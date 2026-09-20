"""Tier 1 must not answer confidently about input it has no basis for.

Why this file exists
--------------------
``scripts/bench/bench_llm_abstention.py`` was written with a negative control —
ten lines of prose, JSON and shell commands pushed through the escalation ladder
alongside the real unparsed config lines — on the theory that a suggester which
cannot stay silent is worse than no suggester. The control fired immediately:

    "milk, eggs, bread"         -> interface.admin_state  0.928
    "The quick brown fox ..."   -> interface.admin_state  0.897
    "zzzzzzzz qqqq"             -> interface.admin_state  0.929
    "shutdown"                  -> interface.admin_state  0.929

The last line is the diagnosis rather than another symptom. A real config command
scored the *same* as a random string, which means the number was the class prior
and not a reading of the input at all. ``TAU_TFIDF`` is 0.85, so every one of
those cleared the escalation threshold and arrived in the training queue as a
93%-confidence suggestion an operator was invited to approve into the permanent
pattern library.

The tests below are written against behaviour, not against
``PRIOR_EVIDENCE_MARGIN``'s value, so retuning the margin or retraining the model
does not require editing them — but replacing the guard with nothing does.

These skip rather than fail when the model artefact is absent, because a cold
checkout has not run MANUAL_COMMANDS.md Step 8 and "the classifier is not
installed" is a supported state (``tests/test_cold_start.py`` owns it). A skip
here is honest; a pass would not be.
"""

from __future__ import annotations

import pytest

from backend.ai.tfidf_clf import PRIOR_EVIDENCE_MARGIN, TFIDF_MODEL_PATH, TfidfClassifier
from backend.app.config import TAU_TFIDF
from backend.canonical.paths import canonical_paths_sorted

pytestmark = pytest.mark.skipif(
    not TFIDF_MODEL_PATH.exists(),
    reason="tier 1 model absent (MANUAL_COMMANDS.md Step 8 not run) — cold start is covered elsewhere",
)

#: Text with no correct canonical path. Any confident answer here is wrong by
#: construction, which is what makes them usable as a test oracle without a
#: hand-labelled ground truth: we do not need to know the right answer to know
#: that there isn't one.
NOT_CONFIG = [
    "milk, eggs, bread",
    "The quick brown fox jumps over the lazy dog.",
    "git commit -m 'fix the thing'",
    "zzzzzzzz qqqq",
    "lorem ipsum dolor sit amet consectetur",
    "ip address of the nearest coffee shop",
    "<html><body><h1>Not a router</h1></body></html>",
]

#: Lines the shipped model demonstrably does read, used to prove the guard is a
#: filter and not an off switch. Deliberately short of the full class list: the
#: point is that *some* real signal survives, not that all of it does.
#:
#: ``no ip http server`` is in the list at 0.838 — a correct path that does not
#: clear TAU_TFIDF (0.85). It is kept rather than dropped because it separates the
#: two things this file must not confuse: whether the guard *blanked* a prediction,
#: and whether the prediction clears the escalation threshold. It was below τ
#: before the guard existed, so treating it as a regression would be blaming the
#: guard for the model's calibration.
REAL_SIGNAL = [
    ("ip ssh version 2", "mgmt.ssh.version"),
    ("hostname R1", "device.hostname"),
    ("service timestamps log datetime msec", "service.timestamps"),
    ("no ip http server", "mgmt.http.server_enabled"),
]

#: How many of ``REAL_SIGNAL`` must still clear ``TAU_TFIDF`` and reach an
#: operator. Three of four, so the guard cannot quietly become an off switch while
#: every per-line assertion still passes.
MIN_SIGNAL_ABOVE_THRESHOLD = 3


@pytest.fixture(scope="module")
def clf() -> TfidfClassifier:
    """One loaded classifier for the module — loading it costs ~1 s."""
    classifier = TfidfClassifier()
    classifier.load()
    return classifier


class TestPriorCollapse:
    """The specific defect: a class prior escalated as if it were a prediction."""

    @pytest.mark.parametrize("line", NOT_CONFIG)
    def test_non_config_text_never_clears_the_escalation_threshold(
        self, clf: TfidfClassifier, line: str
    ) -> None:
        """Asserted against ``TAU_TFIDF``, which is what actually gates the queue.

        Not asserted as ``path == ""``: that would tie the test to how the guard
        signals abstention. What must hold is that nothing here reaches an
        operator as a suggestion, and ``escalate_line`` decides that by comparing
        the confidence to ``TAU_TFIDF``.
        """
        path, confidence = clf.predict(line)
        assert confidence < TAU_TFIDF, (
            f"{line!r} was suggested as {path!r} at {confidence:.3f}, which clears "
            f"TAU_TFIDF={TAU_TFIDF} and would be offered to an operator for "
            f"approval into the permanent pattern library"
        )

    def test_a_real_command_and_a_random_string_are_not_scored_alike(
        self, clf: TfidfClassifier
    ) -> None:
        """The root cause, stated as a test.

        ``shutdown`` is a genuine ``interface.admin_state`` line and ``zzzzzzzz
        qqqq`` is noise. Before the guard both scored 0.929 — identical to three
        decimal places. Any future model that reproduces that has reproduced the
        bug, whatever its accuracy on a held-out set, because it is reporting a
        prior rather than reading the input.

        Both are expected to abstain now, and that is the correct outcome even
        though ``shutdown`` is real: the model did not identify it. It says
        ``interface.admin_state`` for everything. Losing a suggestion that was
        right by coincidence is the price of not shipping confident nonsense, and
        it costs nothing in practice because ``shutdown`` is claimed by a
        deterministic pattern and never reaches this tier.
        """
        real = clf.predict("shutdown")
        noise = clf.predict("zzzzzzzz qqqq")
        assert real[1] < TAU_TFIDF and noise[1] < TAU_TFIDF, (
            f"real={real} noise={noise}: one of these escalated. If they are also "
            "near-identical, the model is scoring its prior."
        )

    def test_the_guard_blanks_the_path_rather_than_returning_an_untrusted_one(
        self, clf: TfidfClassifier
    ) -> None:
        """A zero-confidence answer must not carry a plausible path.

        The original bug was a value that callers were expected to remember not to
        trust. Returning ``interface.admin_state`` with confidence 0.0 would be the
        same shape again — correct for the one caller that checks, a trap for the
        next one. An empty path fails ``is_canonical_path`` immediately instead.
        """
        path, confidence = clf.predict("milk, eggs, bread")
        assert (path, confidence) == ("", 0.0)
        assert path not in canonical_paths_sorted()


class TestTheGuardIsNotAnOffSwitch:
    """A filter that rejects everything would pass every test above."""

    @pytest.mark.parametrize(("line", "expected"), REAL_SIGNAL)
    def test_lines_the_model_actually_reads_still_come_through(
        self, clf: TfidfClassifier, line: str, expected: str
    ) -> None:
        """Without this, ``return "", 0.0`` unconditionally would be "correct".

        This asserts the guard did not *blank* a real prediction. Whether that
        prediction then clears ``TAU_TFIDF`` is the model's calibration and is
        checked separately below — conflating the two would make a pre-existing
        0.838 read as a regression caused by the guard.
        """
        path, confidence = clf.predict(line)
        assert path == expected, f"{line!r} -> {path!r}, expected {expected!r}"
        assert confidence > 0.0, f"{line!r} was blanked by the prior-collapse guard"

    def test_most_real_signal_still_reaches_an_operator(self, clf: TfidfClassifier) -> None:
        """The guard must not become an off switch at the gate that matters.

        Every assertion above would still pass if the guard dropped all four of
        these below ``TAU_TFIDF``, because they check the path rather than the
        threshold. This checks the threshold, at the population level, since a
        per-line threshold assertion would fail on ``no ip http server`` for a
        reason that predates the guard.
        """
        above = [line for line, _ in REAL_SIGNAL if clf.predict(line)[1] >= TAU_TFIDF]
        assert len(above) >= MIN_SIGNAL_ABOVE_THRESHOLD, (
            f"only {len(above)} of {len(REAL_SIGNAL)} known-good lines clear "
            f"TAU_TFIDF={TAU_TFIDF}: {above}. Tier 1 is now silent on almost "
            "everything, which is safe but makes the tier pointless."
        )

    def test_every_surviving_suggestion_is_a_publishable_path(
        self, clf: TfidfClassifier
    ) -> None:
        """A suggestion outside the schema is worse than a wrong one inside it.

        The training UI would offer the operator a path the parser cannot compile,
        so approving it fails downstream rather than mapping the line badly. The
        model's classes come from parser output so this should hold by
        construction — which is exactly why it is worth asserting: nothing else
        checks that the artefact on disk was trained against the current schema.
        """
        published = set(canonical_paths_sorted())
        unknown = [p for p in clf.known_paths() if p not in published]
        assert not unknown, (
            f"the model can emit {len(unknown)} path(s) the schema does not "
            f"publish: {unknown}. The artefact is stale relative to "
            "backend/canonical/paths.py."
        )


class TestTheMarginItself:
    """The one thing about ``PRIOR_EVIDENCE_MARGIN`` worth pinning."""

    def test_the_margin_is_a_margin_and_not_a_confidence(self) -> None:
        """It must stay small relative to ``TAU_TFIDF``, or it becomes the gate.

        Set to 0.5 it would reject everything; set to 0 it would restore the bug
        exactly. The assertion bounds it well inside both failure modes rather
        than pinning the current value, which is a measurement and may change.
        """
        assert 0.0 < PRIOR_EVIDENCE_MARGIN < TAU_TFIDF / 2
