"""Enforce the limits that are stated as limits, and ratchet down the one that is not met.

Two different kinds of rule live here, and conflating them is why neither was
being checked.

**Document budgets** are fixed project conventions: an
architecture document of **max 2 pages**, a demo video of **max 2 minutes**, a
technical presentation of **max 5 content slides**. They are cheap to check
automatically. Exceeding one fails.

**File length** (§145, "every file ≤500 lines; split before that") is a house
style rule that this repository does not currently meet — 29 files are over, one
of them by nearly 1,400 lines. A gate that simply fails on all 29 gets deleted or
skipped within a week, and then nothing is checked at all. So this is a
**ratchet** instead: every over-limit file is recorded in :data:`LINE_BUDGET` at
its current length, and the check fails if a recorded file *grows*, if a new file
crosses 500, or if a budget entry has become stale. The debt cannot get worse and
every entry that gets paid off is deleted permanently.

    python scripts/check_deliverable_limits.py           # report
    python scripts/check_deliverable_limits.py --check    # exit 1 on any violation
    python scripts/check_deliverable_limits.py --lower    # record shrinkage only

``--lower`` deliberately cannot raise a budget or add an entry. If it could, the
ratchet would be a log of what happened rather than a constraint on what may: the
fix for "this file grew" would be to run the tool, which is not a fix. A genuine
new over-limit file has to be argued for in a diff, by hand, with a reason.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT

MAX_LINES = 500
SOURCE_ROOTS = ("backend", "frontend", "scripts", "tests")
SOURCE_SUFFIXES = frozenset({".py", ".js"})
SKIP_DIRS = frozenset({"__pycache__", "node_modules", ".pytest_cache", ".ruff_cache"})

PRESENTATION = PROJECT_ROOT / "docs" / "PRESENTATION.md"
ARCHITECTURE_PDF = PROJECT_ROOT / "docs" / "ARCHITECTURE.pdf"
SCRIPT = PROJECT_ROOT / "docs" / "SCRIPT.md"

#: The project presentation budget is five content slides plus a title slide.
#: The title is counted separately — a title slide
#: carries no technical content and does not consume that budget. So the
#: limit is applied to content slides and the title is named explicitly rather
#: than silently subtracted, so the counting convention is visible in a diff.
MAX_CONTENT_SLIDES = 5
TITLE_SLIDE = 1
_SLIDE_RE = re.compile(r"^## Slide (\d+) — (.+?)\s*$", re.MULTILINE)

ARCHITECTURE_MAX_PAGES = 2

#: ``docs/SCRIPT.md`` states its own target window and its own word/second
#: arithmetic. Both are parsed out and re-derived rather than restated here: a
#: speaking rate written into this file would be an invented constant (R1.1), and
#: the document is the thing that has to be right.
_TARGET_RE = re.compile(r"\*\*Target:\s*(\d+):(\d{2})\s*[–-]\s*(\d+):(\d{2})\.\*\*")
_CLAIM_RE = re.compile(r"~(\d+)\s+words\s*≈\s*\*\*(\d+)\s+seconds\*\*")

#: Every file over :data:`MAX_LINES`, at the length it had when the ratchet was
#: installed. Lower an entry when the file shrinks; delete it when the file
#: reaches the limit. Nothing may be added here by a tool.
LINE_BUDGET = {
    "backend/app/main.py": 1912,
    "backend/report/render.py": 1303,
    "tests/test_api_surface.py": 1064,
    "frontend/js/charts.js": 1020,
    "backend/report/charts.py": 880,
    "tests/test_report_render.py": 861,
    "tests/test_ledger_standalone_verify.py": 849,
    "tests/test_ledger_chain.py": 829,
    "backend/ingest/cisco_ios.py": 817,
    "backend/ingest/generic.py": 552,
    "backend/ingest/patterns.py": 750,
    "backend/frameworks/cis/extract.py": 749,
    "tests/test_remediation_engine.py": 688,
    "tests/test_rules_mapping.py": 660,
    "tests/test_mapping_store.py": 654,
    "tests/test_pattern_packs.py": 649,
    "tests/test_report_charts.py": 649,
    "tests/test_redaction.py": 636,
    "tests/test_frontend_contract.py": 524,
    "tests/test_rules_eval.py": 627,
    "frontend/js/views/training.js": 610,
    "backend/app/auth.py": 606,
    "backend/ingest/redact.py": 604,
    "tests/test_auth.py": 604,
    "backend/ledger/verify.py": 567,
    "backend/rules/evaluator.py": 521,
    "tests/test_ai_escalation_cache.py": 518,
    "frontend/js/findings.js": 505,
}


@dataclass(frozen=True)
class Violation:
    """One limit that is not met, with enough detail to act without re-measuring."""

    subject: str
    detail: str


def measure_sources() -> dict[str, int]:
    """Line counts for every source file, keyed by project-relative POSIX path."""
    counts: dict[str, int] = {}
    for root in SOURCE_ROOTS:
        base = PROJECT_ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if (
                path.is_file()
                and path.suffix in SOURCE_SUFFIXES
                and not SKIP_DIRS.intersection(path.parts)
            ):
                relative = path.relative_to(PROJECT_ROOT).as_posix()
                counts[relative] = len(path.read_text(encoding=FILE_ENCODING).splitlines())
    return counts


def check_line_budget(counts: dict[str, int]) -> list[Violation]:
    """The ratchet: nothing may grow, nothing new may cross, nothing may go stale.

    The stale case matters as much as the other two. A budget entry for a file
    that has since been split reads as a live exemption, so the next person to
    touch that file believes there is room; and it quietly restores the ceiling
    the split was meant to remove.
    """
    violations: list[Violation] = []

    for path, lines in sorted(counts.items()):
        if lines <= MAX_LINES:
            continue
        recorded = LINE_BUDGET.get(path)
        if recorded is None:
            violations.append(
                Violation(
                    path,
                    f"{lines} lines, over the {MAX_LINES}-line limit, and not in "
                    f"LINE_BUDGET. Split it, or add the entry by hand with the "
                    f"reason in the commit message — no tool will add it for you.",
                )
            )
        elif lines > recorded:
            violations.append(
                Violation(
                    path,
                    f"grew from {recorded} to {lines} lines. It was already over "
                    f"the {MAX_LINES}-line limit; the budget exists so it cannot "
                    f"get further from it.",
                )
            )

    for path, recorded in sorted(LINE_BUDGET.items()):
        lines = counts.get(path)
        if lines is None:
            violations.append(
                Violation(path, f"is in LINE_BUDGET at {recorded} lines but no longer exists.")
            )
        elif lines <= MAX_LINES:
            violations.append(
                Violation(
                    path,
                    f"is now {lines} lines, at or under the limit. Delete its "
                    f"LINE_BUDGET entry — a paid-off entry left in place hands the "
                    f"ceiling back.",
                )
            )
    return violations


def check_presentation() -> list[Violation]:
    """R10.3: at most five content slides, numbered contiguously from the title."""
    if not PRESENTATION.exists():
        return [Violation(PRESENTATION.name, "is missing; R10.3 requires a technical presentation.")]
    numbers = [int(n) for n, _ in _SLIDE_RE.findall(PRESENTATION.read_text(encoding=FILE_ENCODING))]
    if not numbers:
        return [
            Violation(
                PRESENTATION.name,
                "has no `## Slide N — ...` headings, so the slide count cannot be "
                "checked. The limit is the easiest deliverable point to lose.",
            )
        ]
    violations: list[Violation] = []
    if numbers != list(range(1, len(numbers) + 1)):
        violations.append(
            Violation(PRESENTATION.name, f"slide numbering is {numbers}, not 1..{len(numbers)}.")
        )
    content = len(numbers) - TITLE_SLIDE
    if content > MAX_CONTENT_SLIDES:
        violations.append(
            Violation(
                PRESENTATION.name,
                f"has {content} content slides plus a title ({len(numbers)} total). "
                f"R10.3 allows {MAX_CONTENT_SLIDES}.",
            )
        )
    return violations


def check_architecture() -> list[Violation]:
    """R10.3: exactly two pages, measured on the rendered PDF.

    This was vacuous until ``scripts/build_architecture_pdf.py`` existed, because
    page count is a property of a rendered document and there is no honest way to
    derive it from the Markdown — a words-per-page constant would be invented
    (R1.1), and a gate built on an invented constant fails for reasons nobody
    caused. Now the artefact exists, so absence of the PDF is itself the
    violation: R10.3 lists it as a deliverable, and "not built" is not a pass.

    ``pypdfium2`` is the reader because it is the PDF library this project
    already pins (``requirements.lock.txt``). The builder's own ``--check`` is
    what verifies the PDF still *matches* ``ARCHITECTURE.md``; this only counts
    pages, so the two checks fail for distinguishable reasons.
    """
    if not ARCHITECTURE_PDF.exists():
        return [
            Violation(
                ARCHITECTURE_PDF.name,
                "has not been built. R10.3 lists it as a deliverable; build it with "
                "python scripts/build_architecture_pdf.py",
            )
        ]
    try:
        import pypdfium2
    except ImportError:  # pragma: no cover - pinned in requirements.lock.txt
        return [
            Violation(
                ARCHITECTURE_PDF.name,
                "exists but pypdfium2 is not installed, so its page count is unchecked.",
            )
        ]
    document = pypdfium2.PdfDocument(str(ARCHITECTURE_PDF))
    try:
        pages = len(document)
    finally:
        document.close()
    if pages != ARCHITECTURE_MAX_PAGES:
        return [
            Violation(
                ARCHITECTURE_PDF.name,
                f"is {pages} pages. R10.3 says exactly {ARCHITECTURE_MAX_PAGES}.",
            )
        ]
    return []


def check_script() -> list[Violation]:
    """``docs/SCRIPT.md`` must be internally consistent and inside its own window.

    Everything is derived from the document: its stated target window, its stated
    word count, and its stated duration. The word count is re-counted from the
    quoted block, and the duration is re-derived at the rate the document's own
    two figures imply. Nothing is compared against a number chosen here.
    """
    if not SCRIPT.exists():
        return []
    text = SCRIPT.read_text(encoding=FILE_ENCODING)
    claim = _CLAIM_RE.search(text)
    target = _TARGET_RE.search(text)
    if claim is None or target is None:
        return [
            Violation(
                SCRIPT.name,
                "no longer states both a target window and a words/seconds "
                "estimate, so its timing cannot be re-derived.",
            )
        ]
    claimed_words, claimed_seconds = int(claim.group(1)), int(claim.group(2))
    low = int(target.group(1)) * 60 + int(target.group(2))
    high = int(target.group(3)) * 60 + int(target.group(4))

    spoken = text.split("## THE SCRIPT (speak this)", 1)
    violations: list[Violation] = []
    if len(spoken) == 2:
        body = spoken[1].split("\n---", 1)[0]
        words = len(re.findall(r"[A-Za-z0-9][\w'\-.]*", re.sub(r"\*\*\[.*?\]\*\*", "", body)))
        drift = abs(words - claimed_words) / claimed_words
        if drift > 0.15:
            violations.append(
                Violation(
                    SCRIPT.name,
                    f"claims ~{claimed_words} words but the spoken block is "
                    f"{words}. The stated duration is derived from that number, "
                    f"so the timing claim no longer follows from the script.",
                )
            )
    if not low <= claimed_seconds <= high:
        violations.append(
            Violation(
                SCRIPT.name,
                f"targets {low}-{high}s but its own estimate is {claimed_seconds}s.",
            )
        )
    return violations


def collect() -> list[Violation]:
    """Every limit, in the order a reader should care about them."""
    return [
        *check_presentation(),
        *check_architecture(),
        *check_script(),
        *check_line_budget(measure_sources()),
    ]


def _lower(counts: dict[str, int]) -> list[str]:
    """Rewrite budget entries downward in place. Never upward, never new."""
    source = Path(__file__).read_text(encoding=FILE_ENCODING)
    changed: list[str] = []
    for path, recorded in LINE_BUDGET.items():
        lines = counts.get(path)
        if lines is None or lines >= recorded:
            continue
        old, new = f'    "{path}": {recorded},', f'    "{path}": {lines},'
        if old not in source:
            continue
        source = source.replace(old, new, 1)
        changed.append(f"{path}: {recorded} -> {lines}")
    if changed:
        Path(__file__).write_text(source, encoding=FILE_ENCODING)
    return changed


def _report(violations: list[Violation]) -> None:
    for violation in violations:
        print(f"OVER {violation.subject} {violation.detail}")
    over = sum(1 for path, lines in measure_sources().items() if lines > MAX_LINES)
    print(
        f"{len(violations)} violations. "
        f"{over} files over {MAX_LINES} lines ({len(LINE_BUDGET)} budgeted), "
        f"{sum(LINE_BUDGET.values()) - MAX_LINES * len(LINE_BUDGET)} lines of debt."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="exit 1 on any violation")
    group.add_argument("--lower", action="store_true", help="record shrinkage; never growth")
    args = parser.parse_args()

    if args.lower:
        changed = _lower(measure_sources())
        print("\n".join(changed) if changed else "no budget entry shrank")
        return 0

    violations = collect()
    _report(violations)
    return 1 if (violations and args.check) else 0


if __name__ == "__main__":
    raise SystemExit(main())
