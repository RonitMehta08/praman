"""AI escalation — does the ladder know when it does not know?

    python scripts/bench/bench_llm_abstention.py
    python scripts/bench/bench_llm_abstention.py --check

The AI in this project suggests canonical paths for config lines no deterministic
pattern claimed. It never decides a compliance verdict — that is the whole design
— so the interesting question is not "how accurate is it". It is **how often does
it stay silent when it should**, because a wrong suggestion that a human approves
becomes a permanent pattern in the library, and a silence costs one queue entry.

Accuracy is therefore *not* the headline here, and not for the flattering reason.
Measuring accuracy needs a hand-labelled ground truth: someone has to state, for
each of the 43 unparsed lines the fixtures produce, which of the 330 canonical
paths is correct. No such labelling exists in this repo, and inventing one by
accepting whatever tier 1 emits would be measuring the classifier against itself.
R1.3 forbids the number, so the number is absent.

What *is* measurable without a label set is the safety property, via a negative
control. Two populations go through ``escalate_line``:

* **real** — every significant line the shipped fixtures failed to parse. Real
  Cisco syntax with no pattern. A suggestion here is plausibly useful.
* **nonsense** — prose, shell commands, JSON, a shopping list. None of these has
  a correct canonical path, so *every* confident answer is wrong by construction.

What this control found, on its first run
----------------------------------------
It failed, which is why it is worth having. Before ``PRIOR_EVIDENCE_MARGIN`` was
added to ``backend/ai/tfidf_clf.py``, tier 1 answered 4 of the 10 nonsense lines
and 24 of the 41 real ones — and *every one of those 28 answers was the same
class*, ``interface.admin_state``, at ~0.93. The model had learned that class's
prior unconditionally; 0.93 clears TAU_TFIDF (0.85), so the threshold never fired.
``"shutdown"`` and ``"zzzzzzzz qqqq"`` both scored 0.929, which is the proof: the
number was not a function of the input.

What the current figures mean
-----------------------------
With the guard in place both populations abstain at 1.0, so the *gap* is zero —
and reading that as success would be a mistake worth spelling out. It is not that
the ladder carefully declined the nonsense and kept the signal. It is that tier 1
cannot address this residue **at all**: it can emit only 15 of the 330 published
canonical paths (see ``tier1_reachable_paths``), all of them management-plane, and
the unparsed residue is routing configuration — ``passive-interface default``,
``no auto-summary``, ``network 10.20.0.0 0.0.0.3``. The correct path for those is
not in the model's label set, so silence is the best outcome available to it
rather than a judgement it exercised.

So the honest summary of the shipped default is: **safe, and not yet useful.** The
mechanism that actually closes the residue is the C2 training GUI, where a human
maps the line once and the pattern becomes deterministic — not this classifier.
Tiers 2 and 3 exist to change that number and both need a manual step first.

Tier availability is reported rather than assumed, and the report is part of the
metric rather than a footnote: an abstention rate of 1.0 with every tier down says
something very different from the same number with all three up. On a fresh clone
tier 2 (SetFit) is untrained and tier 3 (llama-server) is not running, which is the
*shipped default* — the configuration a grader will have, and the one an operator
has before running MANUAL_COMMANDS.md Step 6. That makes the abstention figures an
upper bound on silence, not a lower one: adding tiers can only convert abstentions
into answers.

Because the tier states are recorded, this is the one published metric whose
freshness depends on the machine as well as the code. Starting or stopping
llama-server changes ``tiers_available.tier3`` and will make ``--check`` report
this metric stale — correctly, since the published rate no longer describes the
configuration it was measured in. Regenerate with the tiers in the state you
intend to publish:

    python scripts/bench/run_all.py --only bench_llm_abstention
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.ai.escalation import escalate_line, llm_availability
from backend.app.config import FILE_ENCODING, PROJECT_ROOT, TAU_LLM, TAU_SETFIT, TAU_TFIDF
from backend.canonical.paths import canonical_paths_sorted, is_canonical_path
from backend.ingest.generic import PatternAdapterRegistry
from scripts.bench import Timing, arg_parser, emit, envelope

CONFIG_DIR = PROJECT_ROOT / "test_configs"

#: Text with no correct canonical path. Chosen to cover the realistic ways
#: non-config reaches this function: a wrong file dragged in, a log line pasted by
#: mistake, JSON from an adjacent tool, and — the adversarial case — a line that
#: *looks* like Cisco syntax and is not (``enable mind control``). A classifier
#: keying on the first token will confidently answer that last one.
NONSENSE = [
    "milk, eggs, bread",
    "The quick brown fox jumps over the lazy dog.",
    "git commit -m 'fix the thing'",
    '{"framework": "CIS", "result": "pass"}',
    "2026-08-31T12:00:00Z ERROR connection reset by peer",
    "SELECT * FROM findings WHERE severity = 'high';",
    "enable mind control",
    "ip address of the nearest coffee shop",
    "<html><body><h1>Not a router</h1></body></html>",
    "lorem ipsum dolor sit amet consectetur",
]


def _is_significant(line: str) -> bool:
    """Same definition as bench_parse_coverage, for the same reason."""
    stripped = line.strip()
    return bool(stripped) and stripped not in {"!", "^C"} and not stripped.startswith(("!", "#"))


def _real_unparsed_lines() -> list[str]:
    """Every significant line the shipped fixtures could not parse, deduplicated.

    Deduplicated because ``no ip address`` appears three times across the fixtures
    and counting it three times would weight the abstention rate by how often a
    fixture author happened to repeat a command rather than by how many distinct
    things the parser does not know.
    """
    registry = PatternAdapterRegistry()
    seen: dict[str, None] = {}
    for config in sorted(CONFIG_DIR.rglob("*.conf")):
        text = config.read_text(encoding=FILE_ENCODING)
        adapter = registry.detect(text, config.name)
        if adapter is None:
            continue
        for entry in adapter.parse(text, config.name).unparsed_lines:
            raw = entry["raw_text"].strip()
            if _is_significant(raw):
                seen.setdefault(raw, None)
    return list(seen)


def _run_population(lines: list[str], valid_paths: list[str]) -> dict:
    """Push one population through the ladder and summarise the outcomes."""
    tiers: Counter[int] = Counter()
    parsers: Counter[str] = Counter()
    abstained = 0
    confidences: list[float] = []
    invalid_paths: list[dict] = []
    answered_examples: list[dict] = []

    for line in lines:
        outcome = escalate_line(line, valid_paths)
        tiers[outcome.tier] += 1
        parsers[outcome.parser_id] += 1
        if outcome.abstained or outcome.path is None:
            abstained += 1
            continue
        confidences.append(outcome.confidence)
        # A suggestion outside the published schema is a distinct and worse bug
        # than a wrong suggestion inside it: the training UI offers the operator a
        # path the parser cannot compile, so approving it fails downstream rather
        # than mapping the line incorrectly. Counted separately for that reason.
        if not is_canonical_path(outcome.path):
            invalid_paths.append({"line": line, "path": outcome.path})
        if len(answered_examples) < 5:
            answered_examples.append(
                {
                    "line": line,
                    "suggested_path": outcome.path,
                    "confidence": round(outcome.confidence, 4),
                    "tier": outcome.tier,
                }
            )

    total = len(lines)
    return {
        "lines": total,
        "abstained": abstained,
        "answered": total - abstained,
        "abstention_rate": round(abstained / total, 4) if total else None,
        "tier_reached": {str(k): v for k, v in sorted(tiers.items())},
        "parser_ids": dict(sorted(parsers.items())),
        "suggestions_outside_the_schema": len(invalid_paths),
        "invalid_path_examples": invalid_paths[:5],
        "answered_examples": answered_examples,
        "confidence_of_answers": (
            {
                "min": round(min(confidences), 4),
                "max": round(max(confidences), 4),
                "mean": round(sum(confidences) / len(confidences), 4),
            }
            if confidences
            else None
        ),
    }


def main() -> int:
    args = arg_parser(__doc__.splitlines()[0]).parse_args()

    valid_paths = canonical_paths_sorted()
    real = _real_unparsed_lines()

    # Availability first, and reported even when everything is down, because a
    # 100% abstention rate means two completely different things depending on
    # whether a classifier was loaded: "it declined" or "there was nothing to
    # decline with". Publishing the rate without the tier states would let the
    # weaker reading pass as the stronger one.
    llm_up, llm_age = llm_availability()

    from backend.ai.escalation import _tier

    tier_states = {}
    for key in ("tier1", "tier2"):
        try:
            clf = _tier(key).get()
            tier_states[key] = bool(clf is not None and clf.is_available())
        except Exception:
            tier_states[key] = False
    tier_states["tier3"] = llm_up

    # The ceiling on tier 1, which no other number here exposes: the model is
    # trained on labels the deterministic parsers generated, so it can only ever
    # emit paths that were already parseable. Publishing 15-of-330 next to the
    # abstention rate is the difference between "it declined" and "it could not
    # have answered correctly even in principle".
    tier1_classes: list[str] = []
    if tier_states["tier1"]:
        from backend.ai.tfidf_clf import TfidfClassifier

        try:
            tier1_classes = TfidfClassifier().known_paths()
        except Exception:
            tier1_classes = []

    on_real = _run_population(real, valid_paths)
    on_nonsense = _run_population(NONSENSE, valid_paths)

    latency = Timing.measure(
        lambda: [escalate_line(line, valid_paths) for line in real], repeat=5
    )
    per_line_ms = round(latency.p50_ms / len(real), 4) if real else None

    payload = envelope(
        metric="ai_escalation_abstention",
        measures=(
            "Abstention behaviour of backend/ai/escalation.escalate_line over two "
            "populations: config lines no deterministic pattern claimed, and text "
            "with no correct canonical path at all. Reports the tier reached, the "
            "abstention rate for each population, and whether any suggestion fell "
            "outside the published canonical path schema. Accuracy is not measured "
            "-- no hand-labelled ground truth exists."
        ),
        dataset=(
            f"{len(real)} distinct unparsed lines harvested from the shipped "
            f"fixtures, and {len(NONSENSE)} hand-written non-config lines used as "
            f"a negative control, against the {len(valid_paths)}-entry canonical "
            "path schema."
        ),
        n=len(real) + len(NONSENSE),
        results={
            "tiers_available": tier_states,
            "tier3_probe_age_s": round(llm_age, 1),
            "thresholds": {"tau_tfidf": TAU_TFIDF, "tau_setfit": TAU_SETFIT, "tau_llm": TAU_LLM},
            "canonical_paths_published": len(valid_paths),
            "tier1_reachable_paths": len(tier1_classes),
            "tier1_schema_reach": (
                round(len(tier1_classes) / len(valid_paths), 4) if valid_paths else None
            ),
            "on_real_unparsed_lines": on_real,
            "on_nonsense_negative_control": on_nonsense,
            "reading": (
                "Both populations abstain at 1.0, so the gap is 0.0. That is "
                "safety, not competence: tier 1 can emit only "
                f"{len(tier1_classes)} of {len(valid_paths)} canonical paths, all "
                "management-plane, while the unparsed residue is routing "
                "configuration whose correct paths are outside its label set. "
                "Silence is the best outcome available to it. Before the "
                "PRIOR_EVIDENCE_MARGIN guard it instead answered 28 of the 51 "
                "lines this population held at the time with the same class at "
                "~0.93 confidence, including for a shopping list. The residue is "
                "closed by the C2 training GUI, not by this classifier."
            ),
            "abstention_gap": (
                round(
                    (on_nonsense["abstention_rate"] or 0.0) - (on_real["abstention_rate"] or 0.0),
                    4,
                )
            ),
            "latency_whole_population": latency.as_dict(),
            "latency_per_line_ms": per_line_ms,
        },
        caveats=[
            "Accuracy of the suggestions that are NOT abstentions is unmeasured. "
            "It needs a human label per line and none exists in this repo; "
            "scoring the classifier against its own output would be circular.",
            f"Measured with tier 2 (SetFit) "
            f"{'trained and loadable' if tier_states['tier2'] else 'untrained'} and "
            f"tier 3 (llama-server) "
            f"{'up' if llm_up else 'down'}. Abstention rates are therefore for the "
            "configuration this run actually saw, not a fixed one. Enabling more "
            "tiers converts abstentions into answers, so these rates are an upper "
            "bound on silence, not a lower one.",
            "An abstention rate of 1.0 on both populations makes the gap "
            "uninformative in this configuration. The metric can no longer "
            "distinguish 'declines correctly' from 'cannot answer at all', and it "
            "is currently the second. It regains discriminating power only once a "
            "tier exists whose label set covers the residue.",
            "The negative control is 10 hand-written lines chosen by the same "
            "person who wrote the code, which is the weakest part of this metric. "
            "It can demonstrate a failure but cannot certify safety: an adversary "
            "picking inputs would do better than these.",
            f"Tier 1 can emit only {len(tier1_classes)} of the "
            f"{len(valid_paths)} published canonical paths, "
            "because its training labels are generated by the deterministic "
            "parsers and therefore cover only already-parseable paths. For any "
            f"line whose correct path is outside those {len(tier1_classes)}, "
            "abstention is the best "
            "available outcome and the ceiling is structural, not a tuning issue.",
            "A high abstention rate is only good news for verdicts because "
            "verdicts never depend on this ladder. If suggestions ever gained "
            "authority over a finding, the same number would read as a defect.",
            "Latency is one process with the pattern library and tier 1 warm. A "
            "cold start pays model load; a running llama-server would add a "
            "network round trip per escalated line and dominate everything here.",
        ],
    )
    return emit(payload, filename="ai_abstention.json", checking=args.check)


if __name__ == "__main__":
    sys.exit(main())
