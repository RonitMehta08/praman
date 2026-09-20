"""Parse coverage — how much of a real config the tool actually understands.

    python scripts/bench/bench_parse_coverage.py
    python scripts/bench/bench_parse_coverage.py --check

This is the metric most likely to be quoted and most easily faked, so it is worth
being precise about what "coverage" means here. Three different denominators are
plausible and they give wildly different answers:

1. **Lines matched / total lines.** Flattering and close to meaningless: banner
   text, comments and blank lines inflate it, and a pack that matched nothing but
   ``!`` separators would score well.
2. **Lines matched / semantically significant lines.** What is reported below.
   Comments, blanks and separators are excluded, so the denominator is lines that
   carry configuration.
3. **Facts extracted / facts a human would extract.** The number a reader
   probably wants, and unmeasurable without a hand-labelled ground truth for
   every fixture. Not claimed.

Both (1) and (2) are written out, because publishing only (2) invites the
suspicion that the denominator was chosen to flatter, and the gap between them is
itself informative — it says how much of a device configuration is prose. That
gap is also vendor-dependent: a Cisco config is a third comments and ``!``
separators, a Junos one almost none, so the two numbers converge on Junos and
diverge on IOS.

The unparsed lines are also grouped by first token, which is the actionable half:
"92% coverage" tells an operator nothing, and "the 8% is 14 distinct commands,
mostly ``crypto pki certificate`` blocks" tells them what to teach next.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.ingest.generic import PatternAdapterRegistry
from scripts.bench import Timing, arg_parser, emit, envelope

CONFIG_DIR = PROJECT_ROOT / "test_configs"

#: A line carries configuration unless it is one of these. ``!`` is Cisco's
#: separator and appears hundreds of times in a real config; counting it as a
#: line the parser "failed to understand" would understate coverage as badly as
#: counting it as a success would overstate it.
#: Public because ``scripts/fixture_report.py`` publishes a table beside this
#: bench's numbers, and the two disagreeing about what counts as a line is how a
#: fixture with 85 unparsed comments reads as a parser failure.
def is_significant(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and stripped not in {"!", "^C"} and not stripped.startswith(("!", "#"))


def measure_one(registry: PatternAdapterRegistry, config: Path) -> dict:
    """Coverage for a single fixture."""
    text = config.read_text(encoding=FILE_ENCODING)
    adapter = registry.detect(text, config.name)
    if adapter is None:
        return {"fixture": config.name, "detected": False}

    result = adapter.parse(text, config.name)
    lines = text.splitlines()
    significant = [line for line in lines if is_significant(line)]
    unparsed = [entry["raw_text"] for entry in result.unparsed_lines]
    unparsed_significant = [line for line in unparsed if is_significant(line)]

    return {
        "fixture": config.name,
        "detected": True,
        "vendor": adapter.pack.vendor,
        "lines_total": len(lines),
        "lines_significant": len(significant),
        "lines_unparsed": len(unparsed_significant),
        "facts_extracted": len(result.facts),
        "coverage_of_significant": (
            round(1 - len(unparsed_significant) / len(significant), 4) if significant else None
        ),
        "coverage_of_all_lines": (
            round(1 - len(unparsed_significant) / len(lines), 4) if lines else None
        ),
    }


def main() -> int:
    parser = arg_parser(__doc__.splitlines()[0])
    args = parser.parse_args()

    registry = PatternAdapterRegistry()
    configs = sorted(CONFIG_DIR.rglob("*.conf"))
    per_fixture = [measure_one(registry, config) for config in configs]
    parsed = [row for row in per_fixture if row["detected"]]

    significant = sum(row["lines_significant"] for row in parsed)
    unparsed = sum(row["lines_unparsed"] for row in parsed)
    all_lines = sum(row["lines_total"] for row in parsed)

    # What the residue actually is, keyed by first token. Grouped rather than
    # listed because the same unmapped command recurs across an estate, and a
    # flat list of 300 lines reads as a bigger problem than 14 commands.
    residue: Counter[str] = Counter()
    for config in configs:
        text = config.read_text(encoding=FILE_ENCODING)
        adapter = registry.detect(text, config.name)
        if adapter is None:
            continue
        for entry in adapter.parse(text, config.name).unparsed_lines:
            if is_significant(entry["raw_text"]):
                residue[" ".join(entry["raw_text"].strip().split()[:2])] += 1

    biggest = registry.detect(
        (CONFIG_DIR / "realistic" / "enterprise_complex.conf").read_text(encoding=FILE_ENCODING),
        "enterprise_complex.conf",
    )
    biggest_text = (CONFIG_DIR / "realistic" / "enterprise_complex.conf").read_text(
        encoding=FILE_ENCODING
    )
    timing = Timing.measure(
        lambda: biggest.parse(biggest_text, "enterprise_complex.conf"), repeat=20
    )

    #: Which packs this run actually exercised, read back off the results rather
    #: than off the patterns directory: a pack that ships but that no fixture
    #: triggers has not been measured, and claiming it here would be exactly the
    #: overstatement the caveats are meant to prevent.
    vendors = sorted({row["vendor"] for row in parsed if row.get("vendor")})

    payload = envelope(
        metric="parse_coverage",
        measures=(
            "Share of semantically significant configuration lines claimed by a "
            "deterministic pattern, across every shipped fixture. A line is "
            "significant unless it is blank, a comment, or a Cisco '!' separator. "
            "Also reports parse latency for the largest fixture."
        ),
        dataset=(
            f"{len(configs)} fixtures under test_configs/ (realistic, "
            "compliance_extremes, malformed). No held-out split: these are "
            "hand-written fixtures, not a sample from a population, so a split "
            "would imply a generalisation claim the dataset cannot support."
        ),
        n=significant,
        results={
            "fixtures": len(configs),
            "fixtures_detected": len(parsed),
            "vendors_measured": vendors,
            "lines_significant": significant,
            "lines_unparsed": unparsed,
            "lines_total": all_lines,
            "coverage_of_significant": round(1 - unparsed / significant, 4) if significant else None,
            "coverage_of_all_lines": round(1 - unparsed / all_lines, 4) if all_lines else None,
            "facts_extracted": sum(row["facts_extracted"] for row in parsed),
            "distinct_unmapped_commands": len(residue),
            "top_unmapped": [
                {"command": command, "occurrences": count} for command, count in residue.most_common(10)
            ],
            "parse_latency_largest_fixture": timing.as_dict(),
            "per_fixture": per_fixture,
        },
        caveats=[
            "Coverage is measured against the fixtures shipped with the project, "
            "which were written alongside the pattern pack. It is an upper bound "
            "on what a genuinely unseen config from the same vendor would score, "
            "and says nothing about a vendor with no pack.",
            "'Understood' means a pattern claimed the line, not that the facts "
            "extracted from it are the facts a human would have extracted. "
            "Correctness of extraction is asserted by tests/test_rules_mapping.py "
            "on specific controls, not measured as a rate here.",
            # Derived, not written down. This sentence used to read "One vendor
            # pack (cisco_ios) ships, so this is a single-vendor number" and it
            # stayed there for six packs after it stopped being true, quietly
            # under-claiming the one capability the whole pattern-pack design
            # exists to deliver. A caveat that can rot into a falsehood is worse
            # than no caveat, so it now counts the packs it actually measured.
            f"Measured across {len(vendors)} vendor pack(s) — {', '.join(vendors)} — "
            f"so the aggregate is a weighted average over uneven per-vendor "
            f"fixture counts, not {len(vendors)} independent results. Read "
            "per_fixture for the vendor breakdown before quoting the total.",
            "Parse latency excludes pattern-library load, which is paid once per "
            "process and dominates a single-file run.",
        ],
    )
    return emit(payload, filename="parse_coverage.json", checking=args.check)


if __name__ == "__main__":
    sys.exit(main())
