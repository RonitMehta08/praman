"""AI Escalation Ladder orchestrator.

Processes unparsed config lines top-down through the tiered classifiers.
Stop at the first tier that clears its confidence threshold; escalate only
when confidence is below threshold (SPINE §18.1).

No module under backend/ai/ may write Finding.result to pass or fail.

Why the classifiers are cached here
-----------------------------------
``escalate_line`` is called once per unparsed cluster, and it used to construct a
fresh classifier on every call. Because ``TfidfClassifier`` loads its pipeline
lazily on first ``predict``, a fresh instance meant ``joblib.load`` re-read and
unpickled the whole sklearn pipeline from disk *per line*. Measured on
``test_configs/realistic/enterprise_complex.conf``: 18 unparsed clusters,
``POST /simulate`` taking 32.3 s of which roughly 0.5 s was the parse and the
1,462-finding rule evaluation. Fitting the ten fixtures gave ~1.77 s per cluster,
all of it repeated model loading. Tier 2 had the same shape and Tier 3 would have
been far worse — a fresh ``SetFitModel.from_pretrained`` or a re-probe of
llama-server for every line.

The cache is keyed on a cheap signature of the backing artefact rather than being
a plain memo, for the same reason ``RuntimeState`` fingerprints its directories:
Step 8 of MANUAL_COMMANDS.md trains these models, possibly while the service is
up. A cache with no invalidation would keep answering "model absent, escalate"
until someone remembered to restart, and the operator would conclude that
training had not worked.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from backend.app.config import SENTINEL_AI_BACKEND, TAU_LLM, TAU_SETFIT, TAU_TFIDF
from backend.core_errors import ArtifactMissingError

logger = logging.getLogger(__name__)

#: Distinguishes "never built" from "built when the artefact was absent", which is
#: a real state: signature None is what an absent model reports.
_UNSET = object()

#: How long a llama-server health probe is trusted, split by verdict because the
#: two cost wildly different amounts to re-establish.
#:
#: A *positive* verdict is cheap to recheck — a running server answers /health in
#: about a millisecond — so it expires quickly and a server that has died stops
#: being tried almost at once.
#:
#: A *negative* verdict costs HEALTH_PROBE_TIMEOUT_S every time it is retaken,
#: because a closed local port on Windows is dropped rather than refused (see the
#: note on that constant). Down is also the normal state until MANUAL_COMMANDS.md
#: Step 6 has been run, so a short TTL here would tax every bulk upload forever to
#: detect a transition that only ever follows a deliberate operator action. 30 s
#: is far inside the patience of someone who has just downloaded a 2.5 GB model.
#:
#: Staleness in the positive direction is self-correcting in any case: predict()
#: re-checks availability and raises ArtifactMissingError, which escalates to
#: ABSTAIN — the same answer, one probe later.
_LLM_UP_TTL_S = 5.0
_LLM_DOWN_TTL_S = 30.0


class EscalationResult:
    """Result of processing a line through the escalation ladder."""

    __slots__ = ("abstained", "confidence", "parser_id", "path", "tier")

    def __init__(
        self,
        path: str | None,
        confidence: float,
        tier: int,
        parser_id: str,
        abstained: bool = False,
    ) -> None:
        self.path = path
        self.confidence = confidence
        self.tier = tier
        self.parser_id = parser_id
        self.abstained = abstained


def _file_signature(path: Path) -> tuple[int, int] | None:
    """Fingerprint a single-file artefact (Tier 1's ``.joblib``), or None if absent.

    ``(mtime_ns, size)`` rather than a content hash: the artefact is tens of
    megabytes and this runs once per line, so reading it to decide whether to read
    it would defeat the purpose. Retraining rewrites the file and moves both
    fields.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _tree_signature(root: Path) -> tuple[int, int, int] | None:
    """Fingerprint a directory-shaped artefact (Tier 2's SetFit model), or None.

    Stat'ing the directory itself is not enough, and this is a platform trap
    rather than an oversight. Measured on NTFS:

    * overwriting an existing file **leaves the directory's mtime untouched** —
      the directory entry did not change, only the bytes behind it;
    * creating a *new* file does move it;
    * a directory's ``st_size`` is always 0.

    Those first two together are what make the naive ``_file_signature(model_dir)``
    dangerous rather than merely wrong: it appears to work while a model is being
    added, then goes silently blind at the case that matters. ``save_pretrained``
    writes into the *existing* directory, so a retrain overwrites
    ``model_head.pkl`` in place and the signature returns a constant across it —
    and the cache serves the pre-retrain model forever, which looks exactly like
    "the retrain had no effect".

    So aggregate over the contents instead: ``(file count, total bytes, newest
    mtime)``. Any of the three moving means something was written, removed or
    replaced. Recursive because a sentence-transformers model keeps weights in
    subdirectories (``1_Pooling/``, ``2_Dense/``).

    ``tests/test_ai_escalation_cache.py::TestTreeSignature`` pins each of these
    behaviours, including the platform ones, so a filesystem that differs fails a
    test instead of silently serving stale predictions.

    Costs one ``scandir`` per directory rather than a read, so on a model of a
    handful of files it is tens of microseconds against a ~4 ms per-line budget,
    and it is only reached when Tier 1 falls through.
    """
    if not root.is_dir():
        return None
    count = 0
    total = 0
    newest = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                st = os.stat(os.path.join(dirpath, name))
            except OSError:
                # Raced with a write. Skipping it is safe: the next call sees a
                # different signature and rebuilds, which is the correct response
                # to a directory being written while we look at it.
                continue
            count += 1
            total += st.st_size
            newest = max(newest, st.st_mtime_ns)
    return (count, total, newest)


class _CachedTier:
    """One lazily built classifier, rebuilt when its backing artefact changes.

    Holds the lock across construction deliberately. A concurrent burst of
    requests on a cold cache would otherwise each start their own multi-second
    model load; serialising them means the first pays and the rest wait for a
    result they were going to need anyway.
    """

    __slots__ = ("_factory", "_instance", "_last_sig", "_lock", "_name", "_signature")

    def __init__(
        self,
        name: str,
        factory: Callable[[], Any],
        signature: Callable[[], object],
    ) -> None:
        self._name = name
        self._factory = factory
        self._signature = signature
        self._instance: Any = None
        self._last_sig: object = _UNSET
        self._lock = threading.Lock()

    def get(self) -> Any:
        sig = self._signature()
        with self._lock:
            if self._instance is None or sig != self._last_sig:
                if self._instance is not None:
                    logger.info("%s artefact changed, reloading", self._name)
                self._instance = self._factory()
                self._last_sig = sig
            return self._instance

    def clear(self) -> None:
        with self._lock:
            self._instance = None
            self._last_sig = _UNSET


def _build_tier1() -> _CachedTier:
    from backend.ai.tfidf_clf import TFIDF_MODEL_PATH, TfidfClassifier

    return _CachedTier(
        "Tier 1 (TF-IDF)",
        TfidfClassifier,
        lambda: _file_signature(TFIDF_MODEL_PATH),
    )


def _build_tier2() -> _CachedTier:
    from backend.ai.setfit_clf import SETFIT_MODEL_PATH, SetFitClassifier

    return _CachedTier(
        "Tier 2 (SetFit)",
        SetFitClassifier,
        lambda: _tree_signature(SETFIT_MODEL_PATH),
    )


def _build_tier3() -> _CachedTier:
    from backend.ai.llm_classify import LLMClassifier

    # Tier 3's artefact is a running server, not a file, so there is nothing to
    # stat. Construction is a single f-string, so this cache exists only to give
    # every tier the same shape; the expensive part is the probe, cached below.
    return _CachedTier("Tier 3 (LLM)", LLMClassifier, lambda: None)


#: Built on first use so that importing this module never imports sklearn.
#: ``tests/test_cold_start.py`` depends on each tier reporting its own absence
#: without the others being importable.
_TIERS: dict[str, _CachedTier | None] = {"tier1": None, "tier2": None, "tier3": None}
_TIERS_LOCK = threading.Lock()

_BUILDERS: dict[str, Callable[[], _CachedTier]] = {
    "tier1": _build_tier1,
    "tier2": _build_tier2,
    "tier3": _build_tier3,
}


def _tier(key: str) -> _CachedTier:
    with _TIERS_LOCK:
        cached = _TIERS[key]
        if cached is None:
            cached = _BUILDERS[key]()
            _TIERS[key] = cached
        return cached


#: Availability verdict for Tier 3, as (taken_at, verdict). Separate from the
#: instance cache because ``is_available`` is the expensive part — a TCP connect
#: that on this platform costs its full timeout whenever the server is down — and
#: construction is free.
_llm_available: tuple[float, bool] | None = None
_llm_available_lock = threading.Lock()


def _llm_is_available(clf: Any) -> bool:
    global _llm_available
    now = time.monotonic()
    with _llm_available_lock:
        if _llm_available is not None:
            taken_at, verdict = _llm_available
            ttl = _LLM_UP_TTL_S if verdict else _LLM_DOWN_TTL_S
            if now - taken_at < ttl:
                return verdict
    # Probe outside the lock: it can block for the whole timeout, and a caller
    # that arrives meanwhile should get the stale answer rather than queue behind
    # it. The cost of two concurrent probes is one redundant timeout; the cost of
    # holding the lock is every worker thread stalling on it.
    verdict = clf.is_available()
    with _llm_available_lock:
        _llm_available = (now, verdict)
    return verdict


def llm_availability() -> tuple[bool, float]:
    """Is Tier 3 reachable, and how many seconds ago was that established?

    The public form of the probe, for status reporting. It exists because the API
    layer used to keep its own copy — a bare ``urlopen`` with no cache — and so
    every request that reported AI status paid the full timeout for an answer the
    cache already held: measured 1.507 s per call, on all three of three
    successive calls, against 0.509 s once and then 0.000 s through here. That is
    the whole of ``POST /simulate``'s flat cost, and ``GET /health`` paid it too,
    so a UI polling status kept a threadpool worker blocked for 1.5 s at a time.

    The age is returned rather than hidden because a cached verdict is a claim
    about the past, and the one transition an operator cares about — starting
    llama-server after MANUAL_COMMANDS.md Step 6 — is exactly the one the 30 s
    down-TTL delays. A UI that can say "checked 12 s ago" is honest about that;
    one that shows a bare red badge invites the conclusion that Step 6 failed.
    """
    verdict = _llm_is_available(_tier("tier3").get())
    with _llm_available_lock:
        taken_at = _llm_available[0] if _llm_available is not None else time.monotonic()
    return verdict, max(0.0, time.monotonic() - taken_at)


def reset_classifier_cache() -> None:
    """Drop every cached classifier and the Tier 3 availability verdict.

    For tests that monkeypatch a tier or move a model file, where the stat
    signature would not necessarily change within one run.
    """
    global _llm_available
    with _TIERS_LOCK:
        for tier in _TIERS.values():
            if tier is not None:
                tier.clear()
        for key in _TIERS:
            _TIERS[key] = None
    with _llm_available_lock:
        _llm_available = None


def escalate_line(
    line: str,
    valid_paths: list[str] | None = None,
) -> EscalationResult:
    """Run a single unparsed config line through the AI escalation ladder.

    Tier 0 (deterministic) has already been tried and failed — that's why
    this function is being called. We start at Tier 1.

    Args:
        line: The unparsed config line.
        valid_paths: The build-time canonical path enum for Tier 3.

    Returns:
        EscalationResult with the best classification or ABSTAIN.
    """
    if SENTINEL_AI_BACKEND == "none":
        return EscalationResult(
            path=None, confidence=0.0, tier=-1,
            parser_id="ai.disabled", abstained=True,
        )

    # ── Tier 1: TF-IDF char-ngram ─────────────────────────────────
    try:
        clf = _tier("tier1").get()
        if clf.is_available():
            path, confidence = clf.predict(line)
            if confidence >= TAU_TFIDF:
                return EscalationResult(
                    path=path, confidence=confidence, tier=1,
                    parser_id="ai.tfidf@sklearn",
                )
            logger.debug("Tier 1 below threshold (%.3f < %.3f), escalating", confidence, TAU_TFIDF)
    except ArtifactMissingError:
        logger.debug("Tier 1 model absent, escalating to Tier 2")
    except Exception as e:
        logger.warning("Tier 1 failed: %s", e)

    # ── Tier 2: SetFit few-shot ───────────────────────────────────
    try:
        clf2 = _tier("tier2").get()
        if clf2.is_available():
            path, confidence = clf2.predict(line)
            if confidence >= TAU_SETFIT:
                return EscalationResult(
                    path=path, confidence=confidence, tier=2,
                    parser_id="ai.setfit@1.1.3",
                )
            logger.debug("Tier 2 below threshold (%.3f < %.3f), escalating", confidence, TAU_SETFIT)
    except ArtifactMissingError:
        logger.debug("Tier 2 model absent, escalating to Tier 3")
    except Exception as e:
        logger.warning("Tier 2 failed: %s", e)

    # ── Tier 3: Local LLM ─────────────────────────────────────────
    try:
        clf3 = _tier("tier3").get()
        if _llm_is_available(clf3) and valid_paths:
            path, confidence = clf3.predict(line, valid_paths)
            if confidence >= TAU_LLM:
                return EscalationResult(
                    path=path, confidence=confidence, tier=3,
                    parser_id="ai.llm@qwen3-4b",
                )
    except ArtifactMissingError:
        logger.debug("Tier 3 LLM absent")
    except Exception as e:
        logger.warning("Tier 3 failed: %s", e)

    # ── ABSTAIN ───────────────────────────────────────────────────
    return EscalationResult(
        path=None, confidence=0.0, tier=-1,
        parser_id="ai.abstain", abstained=True,
    )
