"""Test: Repo contract — asserts every path in the frozen tree exists.

Gate for P0: verifies that the SPINE §5 repository layout is correctly
scaffolded before any code is written.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Every directory that MUST exist per SPINE §Repository layout
REQUIRED_DIRS = [
    "backend/app",
    "backend/ingest",
    "backend/canonical",
    "backend/canonical/schema",
    "backend/rules",
    "backend/frameworks",
    "backend/ai",
    "backend/remediation",
    "backend/report",
    "backend/report/assets",
    "backend/ledger",
    "backend/db",
    "backend/threat",
    "frontend",
    "rules",
    "data/frameworks",
    "data/corpus",
    "data/models",
    "data/index",
    "data/labels",
    "scripts/bench",
    "tests",
    "docs",
]

# Files that MUST exist
REQUIRED_FILES = [
    "pyproject.toml",
    ".gitignore",
    "backend/app/config.py",
    "backend/canonical/models.py",
    "backend/canonical/findings.py",
    "backend/core_errors.py",
    "backend/ingest/base.py",
    "backend/ingest/redact.py",
    "backend/ingest/cisco_ios.py",
    "backend/rules/evaluator.py",
    "backend/db/connection.py",
    "backend/ledger/chain.py",
    "backend/app/main.py",
]


def test_required_directories_exist() -> None:
    """Every directory in the frozen tree MUST exist.

    During Step 11's cold-start gate, data/models and data/index are
    intentionally renamed to .bak.  We detect that and exclude them so
    the suite stays green without masking real structural regressions.
    """
    # Directories intentionally hidden during cold-start (Step 11)
    cold_start_hidden = set()
    for d in ("data/models", "data/index"):
        leaf = d.split("/")[-1]
        # Two backup conventions have been used by the cold-start step over time.
        # Both are accepted; the previous version of this loop built a mangled
        # third name (`data\_models`) that was never a path and never read.
        if any((PROJECT_ROOT / name).is_dir() for name in (f"data/_{leaf}.bak", f"data/{leaf}.bak")):
            cold_start_hidden.add(d)

    missing = []
    for d in REQUIRED_DIRS:
        if d in cold_start_hidden:
            continue
        if not (PROJECT_ROOT / d).is_dir():
            missing.append(d)
    assert not missing, f"Missing directories: {missing}"


def test_required_files_exist() -> None:
    """Every file in the frozen tree MUST exist."""
    missing = []
    for f in REQUIRED_FILES:
        if not (PROJECT_ROOT / f).is_file():
            missing.append(f)
    assert not missing, f"Missing files: {missing}"


def test_gitignore_excludes_models() -> None:
    """The .gitignore MUST exclude model files and private data."""
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "*.gguf" in gitignore
    assert "data/models" in gitignore or "data/models/" in gitignore
    assert "data/index" in gitignore or "data/index/" in gitignore
    assert "node_modules" in gitignore or "node_modules/" in gitignore
    assert ".venv" in gitignore or ".venv/" in gitignore


def test_gitignore_excludes_the_operator_database_and_trainer_checkpoints() -> None:
    """Two paths that were committed once, and would be again by accident.

    Both are asserted here rather than left to review because both arrive through
    a *routine* command rather than a deliberate one. `data/praman.db` holds
    whatever devices the last person audited, so a `git commit -a` after a real
    audit publishes customer configurations; it was tracked until the entry below
    was added. `checkpoints/` is 260 MB of SetFit optimiser state that appears
    wherever the trainer was launched from, because
    `TrainingArguments.output_dir` defaults to a *relative* string.

    A missing line in either case is silent — `git status` simply stops
    mentioning the file — which is why the guard is a test and not a comment.
    """
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "data/praman.db" in gitignore
    assert "checkpoints/" in gitignore


def test_the_operator_database_is_not_tracked() -> None:
    """The ignore rule is necessary but not sufficient.

    `.gitignore` has no effect on a path git is already tracking, which is
    exactly the state this repository was in: the entry could be added and the
    17 MB database would keep diffing on every ingest. So ask git, not the
    ignore file.

    Skipped rather than failed when git is unavailable or this is not a
    checkout — a source tarball is a legitimate way to receive the project, and a
    test that cannot run is not the same as a contract that is broken.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "data/praman.db"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        pytest.skip(f"git unavailable: {exc}")

    assert proc.returncode != 0, (
        "data/praman.db is tracked in git. It holds the devices from the last "
        "audit, so a routine `git commit -a` publishes them. Fix with "
        "`git rm --cached praman/data/praman.db` — the file stays on disk."
    )


def test_pyproject_toml_has_ruff_config() -> None:
    """pyproject.toml must configure ruff with line-length 100."""
    toml_text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "line-length = 100" in toml_text
    assert 'target-version = "py310"' in toml_text
