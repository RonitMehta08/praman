"""Print, publish and gate the rule → MITRE ATT&CK join.

The threat tier was built and dead: `backend/threat/enrichment.py` reads
`finding["references"]["attack"]`, and nothing in the shipped corpus writes that
key, because no publisher ships a control → technique crosswalk for
network-device benchmarks. `data/frameworks/attack/canonical_map.yaml` supplies
the missing association as PRAMAN's own editorial judgement, and this script is
where that judgement is made inspectable instead of merely asserted.

    python scripts/attack_coverage.py             # human-readable join
    python scripts/attack_coverage.py --json      # the same as JSON
    python scripts/attack_coverage.py --write     # refresh the published metric
    python scripts/attack_coverage.py --check     # exit 1 on a dead prefix or drift

**What `--check` fails on, and why those two things.**

*A dead prefix.* A prefix in the YAML that matches no rule's referenced paths is
a coverage claim with nothing behind it — it reads in review as though a family
is mapped when the join produces nothing. The first draft of the mapping had
three: `snmp.engine_id`, which no rule reads, and `mgmt.ssh.ciphers` and
`mgmt.ssh.macs`, which were simply misspelt plurals of real paths. All three
would have been invisible without this gate, and each would have quietly shrunk
the join.

*Drift in the published number.* `reports/metrics/attack_coverage.json` is cited
in prose, and a metric cited in prose that nothing regenerates is a metric that
goes stale the moment the rule pack grows.

**What it deliberately does not fail on.** Unmapped paths. 100% is the wrong
target here: the logging, accounting and time families are unmapped on purpose,
because a device that does not log is not thereby exposed to a technique, it is
exposed to the technique going unnoticed — the argument is in the YAML header.
A gate demanding full coverage would be a standing incentive to file those under
T1602, which is exactly the dishonest mapping the header rules out. So they are
*listed* in the output, where a reader can disagree with the judgement, and not
counted against it.

Runs without the 53.8 MB bundle. Technique names and mitigations are empty then,
the join itself is unaffected — it is a property of the rule pack, not of ATT&CK
— and the header says which of the two inputs was missing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING
from backend.rules.loader import load_all_rules
from backend.threat.mapping import (
    coverage_report,
    load_canonical_map,
    mitigations_for,
    rationale_for_paths,
)

ROOT = Path(__file__).resolve().parent.parent
METRIC_PATH = ROOT / "reports" / "metrics" / "attack_coverage.json"

#: Keys compared by ``--check``. Deliberately not the whole payload: the report
#: carries the ATT&CK bundle label, and re-running after a bundle upgrade should
#: not read as drift in the mapping.
TRACKED = ("rules_total", "rules_mapped", "paths_total", "paths_mapped", "dead_prefixes")


def _render(report: dict, verbose: bool) -> str:
    """Human-readable rendering of the join."""
    lines: list[str] = []
    lines.append("Rule → ATT&CK join")
    lines.append("=" * 60)

    if not report["map_loaded"]:
        lines.append("canonical_map.yaml did not load — nothing is mapped.")
        return "\n".join(lines)

    lines.append(f"mapping    : {report['authored_by']}")
    lines.append(f"bundle     : {report['attack_bundle']}" + (
        "" if report["bundle_loaded"] else "  (NOT PRESENT — names and mitigations omitted)"
    ))
    pct = 100.0 * report["rules_mapped"] / report["rules_total"] if report["rules_total"] else 0.0
    lines.append(
        f"rules      : {report['rules_mapped']} of {report['rules_total']} mapped ({pct:.1f}%)"
    )
    lines.append(
        f"paths      : {report['paths_mapped']} of {report['paths_total']} mapped"
    )
    lines.append("")

    for tid, info in report["techniques"].items():
        flag = "  [DEPRECATED IN BUNDLE]" if info.get("deprecated") else ""
        name = info["name"] or "(name unavailable — bundle absent)"
        lines.append(f"{tid:<12} {name}{flag}")
        lines.append(f"{'':<12} {info['rules']} rules")
        mitigations = info["mitigations"]
        lines.append(
            f"{'':<12} mitigations: "
            + (", ".join(mitigations) if mitigations else "none related by the publisher")
        )
        lines.append("")

    if report["dead_prefixes"]:
        lines.append("DEAD PREFIXES — mapped, but matching no rule:")
        for prefix in report["dead_prefixes"]:
            lines.append(f"  {prefix}")
        lines.append("")

    lines.append(
        f"unmapped paths: {len(report['unmapped_paths'])} "
        "(logging, accounting and time are unmapped by design — see the YAML header)"
    )
    if verbose:
        for path in report["unmapped_paths"]:
            lines.append(f"  {path}")

    return "\n".join(lines)


def _explain(paths: list[str]) -> str:
    """Show which techniques a set of paths implies, and PRAMAN's argument for each."""
    rationale = rationale_for_paths(set(paths))
    if not rationale:
        return f"{', '.join(paths)} → no technique mapped"

    lines = [f"{', '.join(paths)} →"]
    for tid, why in sorted(rationale.items()):
        mitigations = ", ".join(m["id"] for m in mitigations_for(tid)) or "none"
        lines.append(f"  {tid}")
        lines.append(f"    PRAMAN's rationale (editorial): {why}")
        lines.append(f"    publisher mitigations: {mitigations}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit JSON instead of prose")
    parser.add_argument("--write", action="store_true", help="refresh the published metric")
    parser.add_argument("--check", action="store_true", help="exit 1 on a dead prefix or drift")
    parser.add_argument("--verbose", action="store_true", help="list every unmapped path")
    parser.add_argument(
        "--explain",
        nargs="+",
        metavar="PATH",
        help="show the techniques one or more canonical paths imply, with the rationale",
    )
    args = parser.parse_args()

    if args.explain:
        print(_explain(args.explain))
        return 0

    doc = load_canonical_map()
    if not doc:
        print("canonical_map.yaml did not load — nothing to report.", file=sys.stderr)
        return 1

    report = coverage_report(load_all_rules())

    if args.write:
        METRIC_PATH.parent.mkdir(parents=True, exist_ok=True)
        METRIC_PATH.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding=FILE_ENCODING
        )
        print(f"wrote {METRIC_PATH}")
        return 0

    if args.check:
        problems: list[str] = []
        for prefix in report["dead_prefixes"]:
            problems.append(f"DEAD PREFIX {prefix} — mapped in canonical_map.yaml, matches no rule")
        if not METRIC_PATH.exists():
            problems.append(f"STALE {METRIC_PATH.name} does not exist")
        else:
            published = json.loads(METRIC_PATH.read_text(encoding=FILE_ENCODING))
            for key in TRACKED:
                if published.get(key) != report[key]:
                    problems.append(
                        f"STALE {METRIC_PATH.name}: {key} is "
                        f"{published.get(key)!r}, measured {report[key]!r}"
                    )
        for line in problems:
            print(line)
        if problems:
            print("Regenerate with: python scripts/attack_coverage.py --write")
            return 1
        print(
            f"OK {report['rules_mapped']} of {report['rules_total']} rules mapped, "
            f"0 dead prefixes, published metric current."
        )
        return 0

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render(report, args.verbose))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
