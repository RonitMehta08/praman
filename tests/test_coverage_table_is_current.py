"""The per-pack coverage table in `docs/GAPS.md` must match the shipped packs.

That table is the one a reader consults before quoting any single coverage
number — `GAPS.md` says so in the sentence above it — and it was the last
published figure in the project with no gate behind it. It had already drifted
two ways:

* `CIS Juniper OS` read **46 of 172**; the pack maps **47**.
* Two whole packs were missing rows — `Cisco NX OS Switch NDM v3r6` (39 of 42)
  and `Juniper Router NDM v3r2` (34 of 49) — so the table showed 11 of the 13
  mapped benchmarks, and a reader counting DISA packs per vendor got the wrong
  answer about which vendors reach NIST and ISO at all.

Neither is a large error. Both are the kind that a test count, a path count and
an endpoint count each already have a gate for, and the argument for those gates
is not that the number is important — it is that nothing about a stale figure
looks wrong.

How a row is joined to a pack
-----------------------------
Not by title. The table writes reader-facing shorthand — `DISA STIG IOS Router
NDM v3r8` — while the catalog object carries the publisher's full title, `Cisco
IOS Router NDM Security Technical Implementation Guide`. Normalising one into
the other would mean encoding the abbreviations a human chose, and it would
break the next time someone shortens a title differently.

So the join key is `(vendor, controls in the benchmark)`. The denominator is not
a measurement of this project at all — it is how many controls the publisher's
document contains — so it identifies the document, and a row cannot bind to the
wrong pack unless two of a vendor's benchmarks happen to have the same length.
`test_the_join_key_is_unambiguous` asserts they do not, so that assumption fails
loudly rather than silently mis-binding a row.

The cost is that a typo in a denominator reports as a missing row *and* a
phantom row rather than as one wrong number. That is a legible failure, and the
corrected row is printed either way.

Why assert rather than generate
-------------------------------
`scripts/fixture_report.py` regenerates the table in `test_configs/README.md`,
which is pure measurement. This table is not: each row carries a benchmark
*version* that only the publisher document names, and the prose around it argues
about why two of the percentages must not be compared. A generator would either
lose that or have to be taught to preserve it. So this asserts the numbers and
prints the corrected row when it fails.
"""

from __future__ import annotations

import re
from collections import defaultdict

import pytest

from backend.app.config import PROJECT_ROOT
from backend.rules.evaluator import RulesEvaluator

GAPS = PROJECT_ROOT / "docs" / "GAPS.md"

#: The table lives under this heading and ends at the next one.
_HEADING = "### Vendors"

#: ``| `cisco_ios` | CIS Cisco IOS 15 v4.1.1 | 71 | 90 | 78.9% |``
_ROW_RE = re.compile(
    r"^\|\s*`([a-z0-9_]+)`\s*\|\s*(.+?)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([\d.]+)%\s*\|$"
)


@pytest.fixture(scope="module")
def evaluator() -> RulesEvaluator:
    """A full engine over the built catalogs and the shipped mapping packs."""
    return RulesEvaluator()


@pytest.fixture(scope="module")
def measured(evaluator: RulesEvaluator) -> dict[tuple[str, int], tuple[int, str]]:
    """``(vendor, controls in benchmark)`` → (controls a rule decides, title).

    Keyed on the catalog's own ``vendors`` list rather than on anything parsed
    out of the document, so a pack that changes vendor cannot keep its old row.
    Catalogs with no pack behind them are deliberately absent: `GAPS.md` names
    those in prose instead, because a 0% row reads as a measurement of this tool
    rather than as "not started".
    """
    mapped: dict[str, set[str]] = defaultdict(set)
    for rule in evaluator.rules:
        if rule.enabled:
            mapped[rule.catalog.catalog_id].add(rule.catalog.control_id)

    out: dict[tuple[str, int], tuple[int, str]] = {}
    for catalog in evaluator.catalogs:
        hit = len(mapped.get(catalog.catalog_id, set()))
        if not hit:
            continue
        for vendor in catalog.vendors:
            out[(vendor, len(catalog.controls))] = (hit, catalog.benchmark)
    return out


def _published() -> dict[tuple[str, int], tuple[int, float, int, str]]:
    """Parse the table into ``(vendor, total)`` → (hit, pct, line number, label)."""
    lines = GAPS.read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == _HEADING), None)
    assert start is not None, f"{GAPS.name} no longer contains a '{_HEADING}' heading"

    rows: dict[tuple[str, int], tuple[int, float, int, str]] = {}
    for offset, line in enumerate(lines[start + 1 :], start=start + 2):
        if line.startswith(("### ", "## ")):
            break
        match = _ROW_RE.match(line.strip())
        if match:
            vendor, label, hit, total, pct = match.groups()
            rows[(vendor, int(total))] = (int(hit), float(pct), offset, label)
    assert rows, "the vendor coverage table parsed to zero rows -- the format changed"
    return rows


def test_the_join_key_is_unambiguous(evaluator: RulesEvaluator) -> None:
    """No vendor may have two *mapped* benchmarks of the same length.

    The whole join rests on this. It is scoped to mapped packs on purpose: many
    unmapped STIG catalogs share a control count with a mapped one (an IOS switch
    NDM and the IOS router NDM are both 35), but an unmapped catalog has no row
    and cannot be mis-bound to one. What must stay unique is the set the table
    actually describes. If it ever stops holding, the right fix is to key on the
    catalog id and put it in the table — not to let a row bind to whichever pack
    the dict happened to keep.
    """
    mapped_ids = {
        rule.catalog.catalog_id for rule in evaluator.rules if rule.enabled
    }
    seen: dict[tuple[str, int], list[str]] = defaultdict(list)
    for catalog in evaluator.catalogs:
        if catalog.catalog_id not in mapped_ids:
            continue
        for vendor in catalog.vendors:
            seen[(vendor, len(catalog.controls))].append(catalog.catalog_id)

    collisions = {key: ids for key, ids in seen.items() if len(ids) > 1}
    assert not collisions, (
        f"two mapped benchmarks for the same vendor have the same control count, "
        f"so a row in the docs/GAPS.md table can no longer be joined to one pack: "
        f"{collisions}"
    )


def test_every_mapped_pack_has_a_row(measured) -> None:
    """A pack with no row is invisible to the reader the table exists for."""
    published = _published()
    missing = [
        f"  | `{vendor}` | {title} | {hit} | {total} | "
        f"{round(100.0 * hit / total, 1)}% |"
        for (vendor, total), (hit, title) in sorted(measured.items())
        if (vendor, total) not in published
    ]
    assert not missing, (
        "these mapped packs have no row in the docs/GAPS.md vendor table:\n"
        + "\n".join(missing)
        + "\n\nAdd them, replacing the publisher's full title with the shorthand "
        "the rest of the table uses, and keeping the benchmark version. A pack "
        "shipping without a row means a reader counting DISA packs per vendor "
        "gets the wrong answer about which vendors reach NIST and ISO at all."
    )


def test_no_row_describes_a_pack_that_is_not_shipped(measured) -> None:
    """The dangerous direction: a row for coverage that no longer exists."""
    phantom = [
        f"  {GAPS.name}:{lineno} claims {vendor} / {label} ({total} controls)"
        for (vendor, total), (_, _, lineno, label) in sorted(_published().items())
        if (vendor, total) not in measured
    ]
    assert not phantom, (
        "the vendor coverage table claims a pack the engine does not load:\n"
        + "\n".join(phantom)
        + "\n\nEither the pack was removed and the row was not, or the row's "
        "denominator no longer matches the number of controls in that "
        "publisher's document."
    )


def test_every_published_coverage_figure_is_current(measured) -> None:
    """The automated count and the percentage, recomputed from the loaded packs."""
    stale = []
    for (vendor, total), (hit, pct, lineno, label) in sorted(_published().items()):
        actual = measured.get((vendor, total))
        if actual is None:
            continue  # reported by test_no_row_describes_a_pack_that_is_not_shipped
        want_hit, _ = actual
        want_pct = round(100.0 * want_hit / total, 1) if total else 0.0
        if hit != want_hit or abs(pct - want_pct) > 0.05:
            stale.append(
                f"  {GAPS.name}:{lineno} says {hit} of {total} ({pct}%); "
                f"correct row is:\n"
                f"    | `{vendor}` | {label} | {want_hit} | {total} | {want_pct}% |"
            )

    assert not stale, (
        "the per-pack coverage table in docs/GAPS.md has drifted from the "
        "shipped packs:\n" + "\n".join(stale)
    )


def test_the_table_accounts_for_every_loaded_rule(evaluator: RulesEvaluator) -> None:
    """The rows must sum to the rule pack, so no coverage hides outside the table.

    This is the check the other three cannot make between them: each of those
    compares rows that exist, and none notices a control decided by a rule whose
    catalog is reachable from no vendor in the table at all. The published
    headline is "454 automated controls", and this asserts the table a reader is
    pointed at adds up to exactly that number.
    """
    published = sum(hit for hit, _, _, _ in _published().values())
    decided = {
        (rule.catalog.catalog_id, rule.catalog.control_id)
        for rule in evaluator.rules
        if rule.enabled
    }
    assert published == len(decided), (
        f"the coverage table's rows sum to {published} automated controls, but the "
        f"engine decides {len(decided)}. A control counted in the headline figure "
        f"is not attributed to any vendor in the table a reader is told to consult."
    )
