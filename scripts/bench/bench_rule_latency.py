"""Rule-engine latency and control coverage — the deterministic core.

    python scripts/bench/bench_rule_latency.py
    python scripts/bench/bench_rule_latency.py --check

Two numbers live here because they are the two halves of the same claim, and
publishing either alone is misleading.

**Latency** answers "can this run against an estate". It is measured on already
parsed facts, with catalogs and rule packs warm, because that is the operation
that repeats per device — a figure that folded in the one-time 1 s catalog load
would describe a cold process rather than the tenth device in a batch.

**Coverage** answers "how much of the loaded corpus can it decide", and it is the
number this project is most exposed on: 103 rules against 3,366 loaded controls is
3.1%, which sounds bad and is the honest figure. R9.4 says publish it anyway. It
is also the wrong denominator to judge the tool by on its own, so the breakdown
below reports coverage three ways — against every loaded control, against the
controls of the two directly-evaluated frameworks, and against the specific
benchmark the shipped rules target. The third is 71 of 90 CIS controls, and the
distance between 3.1% and 79% is entirely a statement about how many catalogs are
loaded for context versus how many are targeted.

Publishing all three is the point. Quoting only 79% would be selective; quoting
only 3.1% would imply the tool cannot decide anything, which the 372 verdicts on
ten fixtures disprove.

**Governance reach** is the fourth figure, and it exists because the first three
say nothing about NIST 800-53 or ISO 27001. Those two are never evaluated
directly — they are projected from the technical findings by
``backend/rules/projection.py`` — so "rules per control" is meaningless for them
and the only meaningful question is how many of their controls the crosswalk ever
lands a verdict on. Every device gets a finding for all 1,014 current NIST
controls; the overwhelming majority are ``notchecked``, and reporting the emitted
count as coverage would be a straightforward lie.

The denominator that a reader actually wants there is the MODERATE baseline, and
it is the one number in this file that cannot be produced from the repository:
the baselines are allocated by SP 800-53B, published separately from the
SP 800-53 catalog that *is* on disk. Rather than estimate it, the metric reports
the full-catalog reach, the base/enhancement composition of that denominator, and
a stated reason the baseline-scoped figure is absent. See
``backend/frameworks/baseline.py`` and ``MANUAL_COMMANDS.md`` Step 16.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.canonical.findings import Result
from backend.frameworks.baseline import (
    baseline_source,
    catalog_composition,
    scope_to_baseline,
)
from backend.ingest.generic import PatternAdapterRegistry
from backend.rules.evaluator import RulesEvaluator
from backend.rules.projection import DIRECT_FRAMEWORKS
from scripts.bench import Timing, arg_parser, emit, envelope

CONFIG_DIR = PROJECT_ROOT / "test_configs"
BIGGEST = CONFIG_DIR / "realistic" / "enterprise_complex.conf"

#: The baseline SP 800-53 names as the default scope for a moderate-impact
#: system, and the one a network-device audit is realistically judged against.
DEFAULT_BASELINE = "moderate"

#: SP 800-53B allocates baselines for SP 800-53 and nothing else. ISO 27001 has
#: no impact tiers, so scoping its controls to MODERATE would be applying one
#: publication's scoping to another publication's controls — the same
#: crosswalk-as-equivalence error NIST's own OLIR guidance warns against.
BASELINED_FRAMEWORK = "NIST_800_53"


def _baseline_view(all_ids: set[str], hit: set[str]) -> dict[str, object] | str:
    """The MODERATE-scoped view of one framework's reach, or why there isn't one.

    A string return is not an error path. When SP 800-53B is not on disk there is
    no defensible baseline denominator, and saying so in the field where the
    number would have gone is the only rendering that cannot be misread — an
    omitted key reads as "not measured", and falling back to the full catalog
    under a ``moderate`` label reads as a measurement that was never made.
    """
    scoped_all = scope_to_baseline(all_ids, DEFAULT_BASELINE)
    if scoped_all is None:
        return (
            "not on disk: SP 800-53B allocates the baselines and is published "
            "separately from the SP 800-53 catalog. Run MANUAL_COMMANDS.md "
            "Step 16. Until then the only honest denominator is the full "
            "catalog, which is what reach_of_emitted uses."
        )
    scoped_hit = hit & scoped_all
    return {
        "source": baseline_source(),
        "controls_in_baseline": len(scoped_all),
        "controls_decided": len(scoped_hit),
        "reach_of_baseline": (
            round(len(scoped_hit) / len(scoped_all), 4) if scoped_all else None
        ),
    }


def _governance_reach(
    emitted: dict[str, set[str]], reached: dict[str, set[str]]
) -> dict[str, object]:
    """Per-framework reach of the crosswalk projection, scoped where possible.

    ``emitted`` is every governance control the run produced a finding for;
    ``reached`` is the subset that got a pass or a fail. The ratio of the two is
    the number §3.4 of the roadmap is about, and it is reported against the full
    catalog *and*, when SP 800-53B is on disk, against the MODERATE baseline.
    """
    rows: dict[str, object] = {}
    for framework in sorted(emitted):
        all_ids, hit = emitted[framework], reached.get(framework, set())
        row: dict[str, object] = {
            "controls_emitted": len(all_ids),
            "controls_decided": len(hit),
            "reach_of_emitted": round(len(hit) / len(all_ids), 4) if all_ids else None,
            "composition": catalog_composition(sorted(all_ids)),
        }
        if framework == BASELINED_FRAMEWORK:
            row[f"{DEFAULT_BASELINE}_baseline"] = _baseline_view(all_ids, hit)
        rows[framework] = row
    return rows


def main() -> int:
    args = arg_parser(__doc__.splitlines()[0]).parse_args()

    registry, evaluator = PatternAdapterRegistry(), RulesEvaluator()

    # Latency on the largest fixture, facts pre-parsed. Both the full run (all
    # four frameworks, governance projection on) and the direct-only run are
    # timed, because the projection is a measurable share of the cost and a
    # reader should be able to see which they are paying for.
    text = BIGGEST.read_text(encoding=FILE_ENCODING)
    adapter = registry.detect(text, BIGGEST.name)
    facts = adapter.parse(text, BIGGEST.name).facts
    vendor, os_family = adapter.pack.vendor, adapter.pack.os_family

    full = Timing.measure(
        lambda: evaluator.evaluate(facts, vendor, os_family), repeat=20
    )
    direct_only = Timing.measure(
        lambda: evaluator.evaluate(
            facts,
            vendor,
            os_family,
            frameworks=sorted(DIRECT_FRAMEWORKS),
            project_governance=False,
        ),
        repeat=20,
    )

    # Coverage, three denominators.
    catalog_controls: Counter[str] = Counter()
    for catalog in evaluator.catalogs:
        catalog_controls[catalog.framework] += len(catalog.controls)
    controls_total = sum(catalog_controls.values())
    controls_direct = sum(catalog_controls[f] for f in DIRECT_FRAMEWORKS)

    # Which benchmarks the shipped rules actually target, and how much of each.
    targeted: dict[str, set[str]] = {}
    for rule in evaluator.rules:
        targeted.setdefault(rule.catalog.catalog_id, set()).add(rule.catalog.control_id)
    per_benchmark = []
    for catalog in evaluator.catalogs:
        hit = targeted.get(catalog.catalog_id, set())
        if not hit:
            continue
        per_benchmark.append(
            {
                "catalog_id": catalog.catalog_id,
                "benchmark": catalog.benchmark,
                "framework": catalog.framework,
                "controls_in_catalog": len(catalog.controls),
                "controls_with_a_rule": len(hit),
                "coverage": round(len(hit) / len(catalog.controls), 4),
            }
        )
    per_benchmark.sort(key=lambda row: (-row["controls_with_a_rule"], row["catalog_id"]))

    # Verdict throughput across the whole fixture set: how many controls the
    # engine actually *decided*, which is the number that makes coverage real.
    decided = Counter()
    per_fixture_ms = []
    # Governance reach, collected in the same pass: which NIST/ISO controls the
    # crosswalk projection ever reaches with a pass or a fail, as opposed to the
    # full catalog it emits as notchecked. These are two very different
    # denominators and only one of them is a statement about the tool.
    emitted: dict[str, set[str]] = {}
    reached: dict[str, set[str]] = {}
    for config in sorted(CONFIG_DIR.rglob("*.conf")):
        config_text = config.read_text(encoding=FILE_ENCODING)
        config_adapter = registry.detect(config_text, config.name)
        if config_adapter is None:
            continue
        config_facts = config_adapter.parse(config_text, config.name).facts
        one = Timing.measure(
            lambda f=config_facts, a=config_adapter: evaluator.evaluate(
                f, a.pack.vendor, a.pack.os_family
            ),
            repeat=3,
            warmup=0,
        )
        per_fixture_ms.append({"fixture": config.name, "p50_ms": one.p50_ms})
        for finding in evaluator.evaluate(
            config_facts,
            config_adapter.pack.vendor,
            config_adapter.pack.os_family,
            frameworks=sorted(DIRECT_FRAMEWORKS),
            project_governance=False,
        ):
            decided[finding.result.value] += 1
        for finding in evaluator.evaluate(
            config_facts, config_adapter.pack.vendor, config_adapter.pack.os_family
        ):
            if finding.framework in DIRECT_FRAMEWORKS:
                continue
            emitted.setdefault(finding.framework, set()).add(finding.control_id)
            if finding.result.value in (Result.PASS.value, Result.FAIL.value):
                reached.setdefault(finding.framework, set()).add(finding.control_id)

    verdicts = decided[Result.PASS.value] + decided[Result.FAIL.value]
    governance = _governance_reach(emitted, reached)

    payload = envelope(
        metric="rule_latency_and_coverage",
        measures=(
            "Wall-clock latency of one RulesEvaluator.evaluate() call over "
            "pre-parsed facts with catalogs and rule packs warm, plus the share "
            "of loaded controls a deterministic rule can decide, reported against "
            "three denominators."
        ),
        dataset=(
            f"Latency: {BIGGEST.name}, the largest shipped fixture. Coverage: all "
            f"{len(evaluator.catalogs)} built catalogs and all "
            f"{len(evaluator.rules)} shipped mapping rules. Verdict counts: every "
            "fixture under test_configs/, direct frameworks only, governance "
            "projection off. Governance reach: the same fixtures with the "
            "projection on, counting distinct NIST and ISO controls."
        ),
        n=full.n,
        results={
            "rules_loaded": len(evaluator.rules),
            "catalogs_loaded": len(evaluator.catalogs),
            "controls_total": controls_total,
            "controls_by_framework": dict(sorted(catalog_controls.items())),
            "coverage_of_all_loaded_controls": round(len(evaluator.rules) / controls_total, 4),
            "coverage_of_direct_framework_controls": round(
                len(evaluator.rules) / controls_direct, 4
            ),
            "coverage_per_targeted_benchmark": per_benchmark,
            "latency_all_frameworks": full.as_dict(),
            "latency_direct_only": direct_only.as_dict(),
            "latency_per_fixture": per_fixture_ms,
            "verdicts_across_fixtures": {
                "pass": decided[Result.PASS.value],
                "fail": decided[Result.FAIL.value],
                "decided": verdicts,
                "notchecked": decided[Result.NOTCHECKED.value],
                "notapplicable": decided[Result.NOTAPPLICABLE.value],
                "unknown": decided[Result.UNKNOWN.value],
            },
            "governance_reach": governance,
        },
        caveats=[
            "3.1% coverage of all loaded controls is the honest headline and the "
            "least useful of the three figures: 42 catalogs are loaded so that a "
            "control id can be resolved and cited, not because rules were "
            "attempted for all of them. Per-benchmark coverage is what says how "
            "complete the targeted work is.",
            "governance_reach counts distinct controls across the whole fixture "
            "set, not per device. No single device reaches that many, and the "
            "figure describes what the shipped crosswalk can reach at all.",
            "The MODERATE-baseline denominator is the one a reader actually "
            "wants and the one that cannot be produced from the repository: "
            "SP 800-53B is a separate publication and is not vendored. Absent "
            "it, no baseline-scoped percentage is published rather than a "
            "plausible one being estimated.",
            "Latency is single-threaded on one machine with warm caches. It is a "
            "lower bound for a cold process, where catalog and pattern load "
            "dominates by roughly an order of magnitude.",
            "No estate-scale measurement: the largest input measured is one "
            "config file. Throughput across a thousand devices is not claimed, "
            "and the per-device figure should not be multiplied to guess it, "
            "because database writes and PDF generation are not in this number.",
            "The governance projection is included in latency_all_frameworks but "
            "produces no verdict of its own: every NIST or ISO pass and fail in "
            "governance_reach is derived arithmetic over a CIS or DISA result "
            "that was already counted in verdicts_across_fixtures. Adding the "
            "two together would count the same evidence twice.",
        ],
    )
    return emit(payload, filename="rule_latency.json", checking=args.check)


if __name__ == "__main__":
    sys.exit(main())
