"""Deliverable limits are checked here because a limit nobody measures is a wish.

``GLOBAL_RULESET.md`` §247 lists overrunning a stated deliverable limit as "the
cheapest possible way to lose points", and it is right: two pages, two minutes,
five slides are not judgement calls, and being over is discovered by a grader
rather than by the team. Every one of them is a counting problem, so every one of
them belongs in the suite.

The line-length rule is different in kind and is treated differently. This
repository does not meet it — 29 files are over 500 lines — and a gate that goes
red on all 29 from the day it lands is a gate people learn to skip, which leaves
the *growth* unchecked as well. So the assertion here is monotonic: the recorded
debt may shrink and may not grow. That is a weaker claim than "we comply", and it
is the one that is actually true.
"""

from __future__ import annotations

import subprocess
import sys

from backend.app.config import PROJECT_ROOT
from scripts.check_deliverable_limits import (
    LINE_BUDGET,
    MAX_CONTENT_SLIDES,
    MAX_LINES,
    check_architecture,
    check_line_budget,
    check_presentation,
    check_script,
    measure_sources,
)


def test_the_presentation_is_within_five_content_slides() -> None:
    """R10.3. The title slide is excluded, and the exclusion is argued, not assumed.

    The SIH template's own instruction slide asks for six including the title,
    which is the same deliverable counted differently. The script names that
    reconciliation in a constant so that "we allow one more than the rule says"
    shows up in a diff rather than in a grader's notes.
    """
    violations = check_presentation()
    assert not violations, "\n".join(f"{v.subject}: {v.detail}" for v in violations)


def test_the_architecture_pdf_is_exactly_two_pages() -> None:
    """R10.3, and no longer vacuous.

    This test asserted nothing until ``scripts/build_architecture_pdf.py`` existed,
    because the page count is a property of a rendered document and predicting it
    from Markdown needs a words-per-page constant that R1.1 forbids inventing. The
    builder produced the artefact, so the limit is now measured on the PDF and a
    missing PDF is itself the failure — "not built" was never a pass for something
    R10.3 lists as a deliverable.
    """
    violations = check_architecture()
    assert not violations, "\n".join(f"{v.subject}: {v.detail}" for v in violations)


def test_the_architecture_pdf_still_matches_the_markdown() -> None:
    """A committed binary is the one artefact that can go stale in silence.

    Page count and content are checked separately and on purpose. A PDF rebuilt
    from a rewritten ``ARCHITECTURE.md`` can land on two pages while saying
    something else entirely, and the page-count gate would pass it. The builder's
    ``--check`` re-renders and diffs *extracted text* — never bytes, because a PDF
    embeds its creation time and no two runs are byte-identical.
    """
    proc = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "scripts" / "build_architecture_pdf.py"), "--check"],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, (
        "docs/ARCHITECTURE.pdf no longer matches docs/ARCHITECTURE.md.\n\n"
        f"{proc.stdout}\n{proc.stderr}\n"
        "Rebuild with:\n    .venv/Scripts/python.exe scripts/build_architecture_pdf.py"
    )


def test_the_speaking_script_still_implies_its_own_duration() -> None:
    """``docs/SCRIPT.md`` states a word count and derives seconds from it.

    Edit the script and the word count moves while the derived duration does not,
    because the duration is prose. That is the whole failure: a two-minute limit
    is enforced against a number that stopped describing the words underneath it
    three revisions ago. Everything compared here is read out of the document, so
    nothing in the suite is asserting a speaking rate of its own choosing.
    """
    violations = check_script()
    assert not violations, "\n".join(f"{v.subject}: {v.detail}" for v in violations)


def test_no_oversized_file_grew_and_no_new_one_appeared() -> None:
    """The ratchet. Debt may be paid down; it may not be taken on.

    Three ways to fail, and the third is the one that gets overlooked: a budget
    entry for a file that has since been split reads as a live exemption, so the
    next person to touch it believes there is room, and the ceiling the split
    removed quietly comes back.
    """
    violations = check_line_budget(measure_sources())
    assert not violations, "\n".join(f"{v.subject}: {v.detail}" for v in violations)


def test_the_budget_is_exactly_the_set_of_files_that_are_over() -> None:
    """Stated separately from the ratchet because it is a different claim.

    ``check_line_budget`` reports drift as violations; this asserts the two sets
    are equal, so a bug in that function cannot make both sides agree on a set
    that excludes something. The published debt figure is read off ``LINE_BUDGET``
    and would otherwise be a number with no relationship to the tree.
    """
    over = {path for path, lines in measure_sources().items() if lines > MAX_LINES}
    assert over == set(LINE_BUDGET), (
        f"untracked and over: {sorted(over - set(LINE_BUDGET))}\n"
        f"tracked but no longer over: {sorted(set(LINE_BUDGET) - over)}"
    )


def test_every_budget_entry_is_actually_over_the_limit() -> None:
    """A budget is a list of exceptions; an entry at or under the limit is not one.

    Guards the direction ``--lower`` could get wrong: it rewrites entries in place
    by string substitution, and an off-by-one there would silently record a
    compliant file as a permanent exception.
    """
    wrong = {path: lines for path, lines in LINE_BUDGET.items() if lines <= MAX_LINES}
    assert not wrong, f"budget entries at or under {MAX_LINES} lines: {wrong}"
    assert MAX_CONTENT_SLIDES == 5, "R10.3 says five content slides; this is not tunable."
