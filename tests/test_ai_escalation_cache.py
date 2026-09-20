"""Test: the AI escalation ladder loads each classifier once, and reloads on change.

``escalate_line`` is called once per unparsed cluster, in a loop, from
``backend/app/main.py``. It used to construct a fresh classifier on every call,
and because ``TfidfClassifier`` loads lazily on first ``predict``, that meant
``joblib.load`` re-unpickled the whole sklearn pipeline per line. Measured over
the ten fixtures in ``test_configs/``: ~1.77 s per unparsed cluster, so
``enterprise_complex`` (18 clusters) took 32.3 s to return 1,462 findings that the
rules engine had produced in about a second. Tier 3 added a second per-line cost —
an HTTP health probe which, on Windows, consumes its entire timeout whenever
nothing is listening, because a closed local port is dropped rather than refused.

Both costs are now paid once. That is a large enough speedup to be worth a test
that notices if it is undone, but the reason these are *tests* rather than a
benchmark is the invalidation: MANUAL_COMMANDS.md Step 8 trains these models,
possibly while the service is up, and a cache that never reloaded would keep
answering "model absent, escalate" until someone restarted the process. The
operator would reasonably conclude that training had failed. So the assertions
below come in pairs — cached, *and* rebuilt when the thing it cached changed.

Everything here runs against injected fakes rather than the real artefacts. These
tests must hold in a cold start with zero models on disk (R7.4) and equally after
Step 8 has been run, so they cannot depend on which is the case.
"""

from __future__ import annotations

import os
import time

import pytest

from backend.ai import escalation


class _FakeTier:
    """A classifier that counts what the ladder does to it.

    ``available`` and ``confidence`` are set per instance by the factory, so one
    fake covers "returns a verdict", "falls through below threshold" and "reports
    itself absent" without three classes.
    """

    def __init__(self, available: bool = True, confidence: float = 0.99) -> None:
        self.available = available
        self.confidence = confidence
        self.availability_probes = 0
        self.predictions = 0

    def is_available(self) -> bool:
        self.availability_probes += 1
        return self.available

    def predict(self, line: str, valid_paths: list[str] | None = None):
        self.predictions += 1
        return "mgmt.ssh.version", self.confidence


class _Recorder:
    """Installs fake tiers and records how many times each was constructed.

    The construction count is the whole point: it is the number of times the real
    code would have hit the disk.
    """

    def __init__(self) -> None:
        self.builds: dict[str, int] = {"tier1": 0, "tier2": 0, "tier3": 0}
        self.instances: dict[str, list[_FakeTier]] = {"tier1": [], "tier2": [], "tier3": []}
        self.signatures: dict[str, object] = {"tier1": "sig-1", "tier2": "sig-2", "tier3": None}
        self._config: dict[str, tuple[bool, float]] = {
            "tier1": (True, 0.99),
            "tier2": (True, 0.99),
            "tier3": (True, 0.99),
        }

    def configure(self, key: str, *, available: bool = True, confidence: float = 0.99) -> None:
        self._config[key] = (available, confidence)

    def _factory(self, key: str):
        def build() -> _FakeTier:
            self.builds[key] += 1
            available, confidence = self._config[key]
            fake = _FakeTier(available=available, confidence=confidence)
            self.instances[key].append(fake)
            return fake

        return build

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        builders = {}
        for key in ("tier1", "tier2", "tier3"):
            def make(key: str = key):
                return escalation._CachedTier(
                    key, self._factory(key), lambda key=key: self.signatures[key]
                )

            builders[key] = make
        monkeypatch.setattr(escalation, "_BUILDERS", builders)

    def latest(self, key: str) -> _FakeTier:
        return self.instances[key][-1]


@pytest.fixture(autouse=True)
def _isolate_cache():
    """The cache is module-global, so leaking it would corrupt unrelated tests.

    Reset on the way in as well as out: an earlier test in the session may have
    populated it with the real classifiers via a ``/simulate`` call.
    """
    escalation.reset_classifier_cache()
    yield
    escalation.reset_classifier_cache()


@pytest.fixture
def rec(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    recorder.install(monkeypatch)
    return recorder


class TestClassifiersAreLoadedOnce:
    """The performance property: N lines must not mean N model loads."""

    def test_repeated_calls_build_tier1_once(self, rec: _Recorder) -> None:
        for _ in range(25):
            escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert rec.builds["tier1"] == 1, (
            f"tier 1 was constructed {rec.builds['tier1']} times for 25 lines — "
            "each construction is a joblib.load of the whole pipeline"
        )

    def test_the_one_instance_is_reused_not_replaced(self, rec: _Recorder) -> None:
        escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        first = rec.latest("tier1")
        for _ in range(9):
            escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert rec.latest("tier1") is first
        assert first.predictions == 10, (
            "the same instance must serve every line, so its own call count is "
            "the line count"
        )

    def test_lower_tiers_are_also_cached_when_the_ladder_falls_through(
        self, rec: _Recorder
    ) -> None:
        """A line no tier can classify walks the whole ladder, every time.

        This is the expensive path and the common one — an abstaining line is by
        definition one the deterministic parser could not handle either.
        """
        rec.configure("tier1", confidence=0.10)   # below TAU_TFIDF
        rec.configure("tier2", confidence=0.10)   # below TAU_SETFIT
        rec.configure("tier3", confidence=0.10)   # below TAU_LLM
        for _ in range(15):
            result = escalation.escalate_line("wholly unknown directive", ["mgmt.ssh.version"])
            assert result.abstained
        assert rec.builds == {"tier1": 1, "tier2": 1, "tier3": 1}

    def test_tier3_is_probed_once_not_per_line(self, rec: _Recorder) -> None:
        """The other half of the old cost.

        ``LLMClassifier.is_available`` is an HTTP GET. On this platform a closed
        local port is dropped rather than refused, so a failed probe costs its
        whole timeout — every line, for as long as llama-server is not running,
        which is the default state.
        """
        rec.configure("tier1", confidence=0.10)
        rec.configure("tier2", confidence=0.10)
        rec.configure("tier3", available=False)
        for _ in range(15):
            escalation.escalate_line("wholly unknown directive", ["mgmt.ssh.version"])
        assert rec.latest("tier3").availability_probes == 1, (
            "tier 3 availability must be cached — 15 lines took 15 probes"
        )


class TestRetrainingTakesEffectWithoutARestart:
    """The safety property, and the reason the cache is signature-keyed.

    Step 8 of MANUAL_COMMANDS.md writes these artefacts. If it runs while the
    service is up — which nothing prevents, and which is the natural thing to do
    after noticing the training queue is full — an unkeyed cache would serve the
    pre-training answer indefinitely.
    """

    def test_a_changed_signature_rebuilds_the_classifier(self, rec: _Recorder) -> None:
        escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert rec.builds["tier1"] == 1

        rec.signatures["tier1"] = "sig-after-training"
        escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert rec.builds["tier1"] == 2, (
            "the artefact changed and the ladder kept the old instance — "
            "retraining would appear to have done nothing"
        )

    def test_a_tier_that_appears_becomes_usable(self, rec: _Recorder) -> None:
        """Absent → trained is the transition that actually matters.

        Before Step 8 the model is missing and every line abstains. Afterwards the
        same line must classify, with no restart in between.
        """
        rec.configure("tier1", available=False)
        rec.configure("tier2", available=False)
        rec.configure("tier3", available=False)
        before = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert before.abstained
        assert before.parser_id == "ai.abstain"

        rec.configure("tier1", available=True, confidence=0.99)
        rec.signatures["tier1"] = "sig-after-training"
        after = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert not after.abstained
        assert after.tier == 1
        assert after.parser_id == "ai.tfidf@sklearn"

    def test_reset_clears_every_tier(self, rec: _Recorder) -> None:
        rec.configure("tier1", confidence=0.10)
        rec.configure("tier2", confidence=0.10)
        rec.configure("tier3", confidence=0.10)
        escalation.escalate_line("unknown", ["mgmt.ssh.version"])
        assert rec.builds == {"tier1": 1, "tier2": 1, "tier3": 1}

        escalation.reset_classifier_cache()
        escalation.escalate_line("unknown", ["mgmt.ssh.version"])
        assert rec.builds == {"tier1": 2, "tier2": 2, "tier3": 2}


class TestFileSignature:
    """Tier 1's artefact is one ``.joblib`` file."""

    def test_absent_artefact_signature_is_none(self, tmp_path) -> None:
        assert escalation._file_signature(tmp_path / "never-created.joblib") is None

    def test_signature_is_stable_across_reads(self, tmp_path) -> None:
        artefact = tmp_path / "model.joblib"
        artefact.write_bytes(b"x" * 512)
        assert escalation._file_signature(artefact) == escalation._file_signature(artefact)

    def test_signature_moves_when_content_changes(self, tmp_path) -> None:
        """Size alone would be enough here; mtime_ns covers a same-size rewrite."""
        artefact = tmp_path / "model.joblib"
        artefact.write_bytes(b"x" * 512)
        before = escalation._file_signature(artefact)
        artefact.write_bytes(b"y" * 1024)
        assert escalation._file_signature(artefact) != before


class TestTreeSignature:
    """Tier 2's artefact is a directory, and that difference is not cosmetic.

    These tests exist because the first version of this cache used one stat for
    both shapes. It passes on ext4 and silently never invalidates on NTFS, which
    is the platform in GLOBAL_RULESET's environment section — so the bug would
    have shipped and shown up as "I ran Step 8 and nothing changed".
    """

    def test_absent_directory_signature_is_none(self, tmp_path) -> None:
        assert escalation._tree_signature(tmp_path / "no-such-model") is None

    def test_a_file_is_not_a_directory(self, tmp_path) -> None:
        """Guards the mixed-up-the-two-helpers mistake directly."""
        artefact = tmp_path / "model.joblib"
        artefact.write_bytes(b"x" * 32)
        assert escalation._tree_signature(artefact) is None

    def test_empty_directory_is_distinguishable_from_absent(self, tmp_path) -> None:
        """A half-finished training run leaves the directory but no weights.

        ``None`` and ``(0, 0, 0)`` must differ, or the cache could not tell
        "never trained" from "training created the directory and then failed" —
        and the second needs to invalidate once the files land.
        """
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        assert escalation._tree_signature(model_dir) == (0, 0, 0)

    def test_signature_is_stable_across_reads(self, tmp_path) -> None:
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        (model_dir / "model_head.pkl").write_bytes(b"weights")
        assert escalation._tree_signature(model_dir) == escalation._tree_signature(model_dir)

    def test_signature_moves_when_a_file_is_added(self, tmp_path) -> None:
        """A model appearing where there was none must invalidate the cache."""
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        before = escalation._tree_signature(model_dir)
        (model_dir / "model_head.pkl").write_bytes(b"weights")
        assert escalation._tree_signature(model_dir) != before

    def test_directory_stat_alone_would_have_missed_a_retrain(self, tmp_path) -> None:
        """Pins the platform behaviour itself, not just our handling of it.

        Without this, the test above looks like an arbitrary preference for one
        implementation. It is not — it is the only one that works here.

        The event pinned is an **in-place overwrite**, because that is what a
        retrain is: ``save_pretrained`` writes into the existing directory, so
        ``model_head.pkl`` is replaced under the same name. The directory entry
        does not change, so the directory's own mtime does not move, so
        ``_file_signature(model_dir)`` is constant across exactly the event the
        cache must notice.

        Deliberately *not* pinned by creating a new file: on NTFS that does move
        the directory mtime, but only outside the ~1 ms window in which both stats
        can land on one clock tick. A test written that way passes alone and fails
        under load, which is how a real platform assumption ends up looking flaky
        and gets deleted. Overwriting is unconditional.

        If a future filesystem starts moving directory mtimes on in-place writes
        this fails, which is the right prompt to re-read ``_tree_signature``'s
        docstring rather than a real breakage.
        """
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        weights = model_dir / "model_head.pkl"
        weights.write_bytes(b"old weights")

        naive_before = escalation._file_signature(model_dir)
        tree_before = escalation._tree_signature(model_dir)

        weights.write_bytes(b"new weights of a different length entirely")

        assert escalation._file_signature(model_dir) == naive_before, (
            "the directory's own mtime moved on an in-place overwrite — the "
            "platform assumption behind _tree_signature has changed; re-read its "
            "docstring"
        )
        # And the implementation we actually use does notice.
        assert escalation._tree_signature(model_dir) != tree_before

    def test_a_directory_has_no_size_to_stat(self, tmp_path) -> None:
        """The other half of why one stat cannot work: ``st_size`` is 0 regardless.

        So a naive signature has only mtime to go on — and the test above shows
        mtime is the field that stands still across a retrain.
        """
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        (model_dir / "model_head.pkl").write_bytes(b"x" * 4096)
        signature = escalation._file_signature(model_dir)
        assert signature is not None
        assert signature[1] == 0

    def test_signature_moves_when_a_file_is_replaced_at_the_same_size(
        self, tmp_path
    ) -> None:
        """Retraining rewrites weights in place; count and total stay put."""
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        weights = model_dir / "model_head.pkl"
        weights.write_bytes(b"a" * 256)
        before = escalation._tree_signature(model_dir)
        os.utime(weights, ns=(before[2] + 10**9, before[2] + 10**9))
        assert escalation._tree_signature(model_dir) != before

    def test_signature_sees_into_subdirectories(self, tmp_path) -> None:
        """A sentence-transformers model keeps weights in ``1_Pooling/`` etc."""
        model_dir = tmp_path / "setfit_model"
        (model_dir / "1_Pooling").mkdir(parents=True)
        before = escalation._tree_signature(model_dir)
        (model_dir / "1_Pooling" / "config.json").write_bytes(b"{}")
        assert escalation._tree_signature(model_dir) != before

    def test_signature_moves_when_a_file_is_removed(self, tmp_path) -> None:
        model_dir = tmp_path / "setfit_model"
        model_dir.mkdir()
        (model_dir / "model_head.pkl").write_bytes(b"weights")
        before = escalation._tree_signature(model_dir)
        (model_dir / "model_head.pkl").unlink()
        assert escalation._tree_signature(model_dir) != before


class TestTier3AvailabilityTtl:
    """Down is cheap to cache and expensive to recheck; up is the reverse."""

    def test_a_negative_verdict_is_held_longer_than_a_positive_one(self) -> None:
        """Asserted as an inequality because the asymmetry is the design.

        Rechecking "up" costs about a millisecond against a live server.
        Rechecking "down" costs HEALTH_PROBE_TIMEOUT_S, and down is the normal
        state before Step 6 has been run. Equal TTLs would tax every upload
        forever to detect a transition that only follows an operator action.
        """
        assert escalation._LLM_DOWN_TTL_S > escalation._LLM_UP_TTL_S

    def test_the_verdict_is_rechecked_once_the_ttl_lapses(
        self, rec: _Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = {"now": 1_000.0}
        monkeypatch.setattr(
            escalation, "time", type("_Clock", (), {"monotonic": lambda: clock["now"]})
        )
        rec.configure("tier1", confidence=0.10)
        rec.configure("tier2", confidence=0.10)
        rec.configure("tier3", available=False)

        escalation.escalate_line("unknown", ["mgmt.ssh.version"])
        escalation.escalate_line("unknown", ["mgmt.ssh.version"])
        assert rec.latest("tier3").availability_probes == 1

        clock["now"] += escalation._LLM_DOWN_TTL_S + 1
        escalation.escalate_line("unknown", ["mgmt.ssh.version"])
        assert rec.latest("tier3").availability_probes == 2, (
            "a down verdict must eventually be rechecked, or starting "
            "llama-server per Step 6 would need a restart to be noticed"
        )


class TestCachingDoesNotChangeVerdicts:
    """Semantics the cache must not have altered."""

    def test_disabled_backend_still_short_circuits(
        self, rec: _Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SENTINEL_AI_BACKEND=none must not even construct a classifier."""
        monkeypatch.setattr(escalation, "SENTINEL_AI_BACKEND", "none")
        result = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert result.abstained
        assert result.tier == -1
        assert result.parser_id == "ai.disabled"
        assert rec.builds == {"tier1": 0, "tier2": 0, "tier3": 0}

    def test_first_tier_over_threshold_wins(self, rec: _Recorder) -> None:
        rec.configure("tier1", confidence=0.99)
        result = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert (result.tier, result.parser_id) == (1, "ai.tfidf@sklearn")
        assert rec.builds["tier2"] == 0, "tier 2 must not be touched after a tier 1 hit"

    def test_escalation_order_is_preserved(self, rec: _Recorder) -> None:
        rec.configure("tier1", confidence=0.10)
        rec.configure("tier2", confidence=0.99)
        result = escalation.escalate_line("ip ssh version 2", ["mgmt.ssh.version"])
        assert (result.tier, result.parser_id) == (2, "ai.setfit@1.1.3")

    def test_tier3_needs_valid_paths(self, rec: _Recorder) -> None:
        """Without the enum there is nothing to constrain the answer to.

        Tier 3's output is only safe because it is checked against the canonical
        path list; with no list, the ladder abstains rather than accepting a
        free-text guess.
        """
        rec.configure("tier1", confidence=0.10)
        rec.configure("tier2", confidence=0.10)
        rec.configure("tier3", confidence=0.99)
        result = escalation.escalate_line("unknown", None)
        assert result.abstained
        assert rec.latest("tier3").predictions == 0


class TestStatusReportingSharesTheProbeCache:
    """The status endpoints must not keep a second, uncached copy of the probe.

    They did. ``backend/app/main.py`` had its own ``_llm_reachable`` — a bare
    ``urlopen`` with ``timeout=1.5`` and no cache — and ``_ai_status`` called it on
    every request. So ``POST /simulate`` and ``GET /health`` each paid a full 1.5 s
    to re-answer a question the cache above already held: measured 1.507, 1.503 and
    1.506 s on three successive calls, against 0.509 s once and then 0.000 s
    through the cache. Removing it took ``/simulate`` from 1.675 s to 0.29 s and
    ``/health`` from 1.5 s to 0.008 s on the same fixture.

    That is worth a test because of *how* the duplicate arose: the careful cache
    was built in ``backend/ai/`` and a second, naive copy of the same probe was
    written in ``backend/app/``, where nothing pointed at the first. Nothing about
    either file's behaviour looked wrong in isolation, and the cost only showed up
    as "the UI feels slow". The assertions below fail if a direct probe comes back,
    because a probe that bypasses the cache never reaches these fakes.
    """

    def test_repeated_status_reads_take_one_probe(self, rec: _Recorder) -> None:
        for _ in range(20):
            escalation.llm_availability()
        assert rec.latest("tier3").availability_probes == 1, (
            f"{rec.latest('tier3').availability_probes} probes for 20 status reads "
            "— each costs HEALTH_PROBE_TIMEOUT_S while Tier 3 is down"
        )

    def test_the_reported_age_is_real_elapsed_time(self, rec: _Recorder) -> None:
        """A constant 0.0 would satisfy a ``>= 0`` assertion and mean nothing.

        The age exists so a UI can distinguish "llama-server is down" from "we
        last looked 28 seconds ago", which are the same badge and different
        actions. That only works if it counts.
        """
        _, first = escalation.llm_availability()
        time.sleep(0.02)
        _, second = escalation.llm_availability()
        assert first >= 0.0
        assert second > first, "the age is not advancing — it is not being measured"

    def test_ai_status_does_not_take_its_own_probe(self, rec: _Recorder) -> None:
        """The regression test for the duplicate, at the API layer that had it."""
        from backend.app.main import _ai_status

        status = _ai_status()
        if status["ai_backend"] == "none":
            pytest.skip("SENTINEL_AI_BACKEND=none short-circuits before any probe")
        for _ in range(5):
            _ai_status()
        assert rec.builds["tier3"] == 1, (
            "status reporting never reached the shared Tier 3 cache — something in "
            "backend/app/ is probing llama-server directly again"
        )
        assert rec.latest("tier3").availability_probes == 1, (
            f"6 status reads took {rec.latest('tier3').availability_probes} probes"
        )

    def test_the_status_payload_carries_the_probe_age(self, rec: _Recorder) -> None:
        from backend.app.main import _ai_status

        status = _ai_status()
        if status["ai_backend"] == "none":
            pytest.skip("SENTINEL_AI_BACKEND=none reports no per-tier freshness")
        assert isinstance(status["tier3_checked_age_s"], float)
        assert status["tier3_checked_age_s"] >= 0.0
