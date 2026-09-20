"""Measured-coverage probe for a pattern pack + fixture pair.

Authoring a vendor pack by inspection does not work: the gaps are the lines you did
not think of, and they are invisible until the parser reports them. This runs the
real PatternAdapter over a real fixture and prints the three numbers that decide
whether the pack is done — fact count, unparsed count, coverage — followed by every
unparsed line so the next iteration has a worklist rather than a hunch.

Usage:
    .venv/Scripts/python.exe scripts/pack_probe.py <vendor> [fixture.conf]

With no fixture it uses the only .conf in test_configs/multivendor whose detection
score for <vendor> is highest, which is also a check that detection works.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ingest.generic import PatternAdapterRegistry
from backend.ingest.patterns import PatternLibrary

ROOT = Path(__file__).resolve().parent.parent
PATTERNS = ROOT / "data" / "ingest" / "patterns"
CONFIGS = ROOT / "test_configs"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    vendor = sys.argv[1]

    library = PatternLibrary(PATTERNS)
    packs = library.packs()
    if vendor not in packs:
        print(f"no pack named {vendor}; have {sorted(packs)}")
        return 1

    print("── packs loaded ────────────────────────────────────────")
    for name, pack in sorted(packs.items()):
        print(f"  {name:<16} patterns: {pack.pattern_count():<4} paths: {len(pack.referenced_paths())}")

    registry = PatternAdapterRegistry(library)

    if len(sys.argv) > 2:
        fixture = Path(sys.argv[2])
        if not fixture.is_absolute():
            fixture = ROOT / fixture
    else:
        best, best_score = None, -1
        for candidate in sorted(CONFIGS.rglob("*.conf")):
            text = candidate.read_text(encoding="utf-8", errors="replace")
            score = registry.for_vendor(vendor).detection_score(text, candidate.name)
            if score > best_score:
                best, best_score = candidate, score
        fixture = best
    if fixture is None or not fixture.exists():
        print("no fixture found")
        return 1

    raw = fixture.read_text(encoding="utf-8", errors="replace")
    print(f"\n── {fixture.relative_to(ROOT)} ──────────────────────")

    scores = {
        name: registry.for_vendor(name).detection_score(raw, fixture.name)
        for name in sorted(packs)
    }
    print(f"  detection: {scores}")
    winner = max(scores, key=lambda k: scores[k])
    verdict = "OK" if winner == vendor else f"WRONG (picked {winner})"
    print(f"  winner: {winner}  → {verdict}")

    adapter = registry.for_vendor(vendor)
    result = adapter.parse(raw, source_file=fixture.name)

    total = len([line for line in raw.splitlines() if line.strip()])
    unparsed = list(result.unparsed_lines)
    covered = total - len(unparsed)
    print(
        f"\n  facts: {len(result.facts)}  unparsed: {len(unparsed)}  "
        f"lines: {total}  coverage: {covered / total * 100:.1f}%"
    )
    device = result.device
    print(
        f"  device: {device.hostname} {device.vendor} {device.os_version} "
        f"hw={getattr(device, 'hardware', None)}"
    )

    if unparsed:
        print("\n── unparsed ────────────────────────────────────────────")
        for line in unparsed:
            print(f"  L{line['line_number']:<4} [{line.get('block', '')}] {line['raw_text']}")

    paths = sorted({fact.path for fact in result.facts})
    print(f"\n── {len(paths)} distinct paths ───────────────────────────")
    for path in paths:
        print(f"  {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
