"""Test: the MANUAL_COMMANDS.md contract — every cited step must exist.

``MASTER_PROMPT.md`` §32 point 6 and ``GLOBAL_RULESET.md`` R2.2 make one promise
to the operator: when a heavy artifact is absent, the code says so by **naming
the step that produces it**. That promise is only worth having if the step is
real. A message reading "run Step 8c" when the file has no Step 8c is worse than
a bare traceback, because the operator goes looking, finds nothing, and stops
believing the next message too.

That is not hypothetical. Tier 2's loader, its trainer and one metrics test all
cited "Step 8c" for weeks while ``MANUAL_COMMANDS.md`` contained only 8a and 8b,
and nothing detected it — the citation is prose inside a string literal, so no
import, type check or lint pass can see it. This module is the mechanical
detector, which is the only kind that survives the next person adding a step
citation in a hurry.

Three things are asserted, in increasing strictness:

1. Every ``Step N`` cited anywhere in the tree names a declared step.
2. Every declared step carries all six required fields.
3. Every ``ArtifactMissingError`` message cites at least one step.

None of them look at what a step *says*. They check that the pointer resolves,
which is the part that rots silently.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The project includes the runbook so a standalone GitHub clone can resolve it.
MANUAL_COMMANDS = PROJECT_ROOT / "MANUAL_COMMANDS.md"

#: The six fields every step must carry, verbatim as the file writes them.
#: ``Est. time`` and ``Est. disk`` are load-bearing rather than decorative: they
#: are what lets the operator decide whether to start a step now, and R2.2 makes
#: them mandatory for exactly that reason.
REQUIRED_FIELDS = (
    "**Purpose.**",
    "**Command**",
    "**Est. time**",
    "**Est. disk**",
    "**Verify.**",
    "**Undo.**",
)

#: Where a step citation may appear. Docs and the frontend are included because a
#: dangling step number misleads a reader from a slide exactly as well as from a
#: stack trace.
SEARCH_ROOTS = ("backend", "scripts", "tests", "frontend", "docs", "rules", "configs")

SEARCH_SUFFIXES = (".py", ".md", ".js", ".css", ".yaml", ".yml", ".json", ".html")

#: Directories that are not source. ``.venv`` matters most — site-packages is
#: full of unrelated prose and scanning it turns a 200 ms test into a minute.
SKIP_DIR_PARTS = frozenset(
    {".venv", ".venv-remediation", ".venv-dev-ccp2", "__pycache__", "node_modules",
     ".git", "_source", "checkpoints", "setfit_checkpoints"}
)

#: A citation. Deliberately case-sensitive and deliberately requires the word:
#: matching a bare number would hit every version string in the tree.
_CITATION = re.compile(r"\bStep (\d+[a-z]?)\b")

#: A top-level step: ``## Step 4 — Framework corpora``.
_STEP_HEADING = re.compile(r"(?m)^## Step (\d+[a-z]?)\b")

#: A sub-step declared as its own heading: ``### 4a — ALREADY ON DISK``.
_SUBSTEP_HEADING = re.compile(r"(?m)^#{3,}\s*(\d+[a-z])\b")

#: A sub-step declared inside a command block: ``# --- 8a: TF-IDF ... ---``.
#: This form exists because 8a and 8b are two commands in one fenced block, and
#: splitting them into headings would have implied two independent steps.
_SUBSTEP_COMMENT = re.compile(r"#\s*-{2,}\s*(\d+[a-z])\s*:")


def _manual_commands_text() -> str:
    if not MANUAL_COMMANDS.is_file():
        pytest.fail(
            f"MANUAL_COMMANDS.md not found at {MANUAL_COMMANDS}. Every "
            "ArtifactMissingError in this project points at a step in that file; "
            "without it those messages are unactionable."
        )
    return MANUAL_COMMANDS.read_text(encoding="utf-8")


def declared_steps(text: str) -> set[str]:
    """Every step identifier the file actually defines.

    All three declaration forms count. The test is about whether an operator
    following a citation lands somewhere, not about which markup got used.
    """
    return (
        set(_STEP_HEADING.findall(text))
        | set(_SUBSTEP_HEADING.findall(text))
        | set(_SUBSTEP_COMMENT.findall(text))
    )


def _source_files() -> list[Path]:
    files: list[Path] = []
    for root in SEARCH_ROOTS:
        base = PROJECT_ROOT / root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.suffix.lower() not in SEARCH_SUFFIXES:
                continue
            if SKIP_DIR_PARTS.intersection(path.parts):
                continue
            files.append(path)
    for name in ("README.md", "pyproject.toml"):
        candidate = PROJECT_ROOT / name
        if candidate.is_file():
            files.append(candidate)
    return files


def test_manual_commands_declares_steps_at_all() -> None:
    """Guard the guard.

    Every assertion below is of the form "the cited step is in this set". A
    regex that silently stopped matching — a heading style change, a stray
    non-breaking space — would empty the set and turn the other tests into
    permanent passes that check nothing. Failing here instead makes that
    unmissable.
    """
    steps = declared_steps(_manual_commands_text())
    assert len(steps) >= 10, (
        f"only {len(steps)} steps parsed out of MANUAL_COMMANDS.md ({sorted(steps)}). "
        "The heading format probably changed; fix the regexes in this module "
        "rather than the file, because every other test here trusts this set."
    )
    # The three steps the ArtifactMissingError contract in the file's own
    # preamble names by example, one per declaration form.
    for expected in ("1", "7", "8a"):
        assert expected in steps, f"Step {expected} is no longer declared"


def test_every_cited_step_exists() -> None:
    """A ``Step N`` citation anywhere in the tree must resolve.

    This is the test that would have caught Tier 2's dangling Step 8c on the day
    it was written.
    """
    steps = declared_steps(_manual_commands_text())
    dangling: dict[str, list[str]] = {}

    for path in _source_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover - defensive
            continue
        for cited in set(_CITATION.findall(text)):
            if cited in steps:
                continue
            rel = path.relative_to(PROJECT_ROOT).as_posix()
            dangling.setdefault(cited, []).append(rel)

    assert not dangling, (
        "these files cite MANUAL_COMMANDS.md steps that do not exist:\n"
        + "\n".join(
            f"  Step {step}: {', '.join(sorted(files))}"
            for step, files in sorted(dangling.items())
        )
        + f"\ndeclared steps: {', '.join(sorted(steps))}\n"
        "Either write the step (with all six fields — see "
        "test_every_step_declares_all_six_fields) or correct the citation. Do "
        "not renumber an existing step to close this: GLOBAL_RULESET.md R1.4 "
        "forbids it, because the operator's notes and half this codebase's error "
        "messages point at the current numbers."
    )


def test_every_step_declares_all_six_fields() -> None:
    """A step missing ``Est. disk`` is a step the operator cannot plan around.

    Checked on top-level ``## Step`` sections only. Sub-steps share their
    parent's fields by design — Step 4's four sub-steps are one acquisition with
    four sources, and asking each to restate the parent's Undo block would make
    the file longer and less accurate, not safer.
    """
    text = _manual_commands_text()
    sections = re.split(r"(?m)^## Step (\d+[a-z]?)\b", text)
    assert len(sections) > 1, "no '## Step' sections found"

    incomplete: dict[str, list[str]] = {}
    for index in range(1, len(sections), 2):
        step, body = sections[index], sections[index + 1]
        missing = [field for field in REQUIRED_FIELDS if field not in body]
        if missing:
            incomplete[step] = missing

    assert not incomplete, (
        "these steps are missing required fields:\n"
        + "\n".join(f"  Step {s}: {', '.join(m)}" for s, m in sorted(incomplete.items()))
        + "\nGLOBAL_RULESET.md R2.2 requires all six: "
        + ", ".join(REQUIRED_FIELDS)
    )


def test_every_artifact_missing_error_cites_a_step() -> None:
    """``ArtifactMissingError`` exists to hand over an instruction, not a fact.

    ``backend/core_errors.py`` states the requirement in the class docstring —
    "The message MUST name the exact MANUAL_COMMANDS.md step" — and a docstring
    is not enforcement. The messages are multi-line implicit-concatenation
    literals, so this reads a window after the raise rather than trying to parse
    the string: crude, but it cannot be fooled by reformatting.
    """
    window_lines = 8
    offenders: list[str] = []

    for path in (PROJECT_ROOT / "backend").rglob("*.py"):
        if SKIP_DIR_PARTS.intersection(path.parts):
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            if "raise ArtifactMissingError(" not in line:
                continue
            window = "\n".join(lines[number : number + window_lines])
            if not _CITATION.search(window):
                rel = path.relative_to(PROJECT_ROOT).as_posix()
                offenders.append(f"{rel}:{number + 1}")

    assert not offenders, (
        "these ArtifactMissingError raises do not name a MANUAL_COMMANDS.md "
        f"step within {window_lines} lines:\n  " + "\n  ".join(offenders) + "\n"
        "An operator who gets one of these learns that something is missing and "
        "not what to run. Add 'Run Step N in MANUAL_COMMANDS.md.' to the message."
    )
