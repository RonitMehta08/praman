"""Mapping pack loader — schema-validated, hot-reloadable, fails loudly.

Rules live in ``rules/mappings/**/*.yaml`` as data. Loading them happens in two
passes on purpose:

1. **JSON Schema** (``schemas/rule.schema.json``) checks structure and rejects
   unknown keys. A typo like ``oprator: gte`` is caught here with the file, the
   line-adjacent JSON pointer, and the list of keys that were allowed - rather
   than being silently ignored and turning a real check into a wrong verdict.
2. **Pydantic** builds the ``Rule`` object and checks semantics the schema cannot
   express, chiefly that every canonical path is in the vocabulary.

The canonical-path enum is injected into the schema at load time from
``canonical_paths.schema.json``, so the two files can never drift.

Hot reload (PS 26155 C2, GLOBAL_RULESET R3.6): ``RulePackLoader`` stamps a
fingerprint over the pack's paths, sizes and mtimes. ``reload_if_changed()``
re-reads only when that fingerprint moves, so the running process picks up a new
mapping without a redeploy and without re-parsing YAML on every request.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from backend.app.config import FILE_ENCODING, PROJECT_ROOT, RULES_DIR
from backend.canonical.paths import canonical_paths_sorted
from backend.core_errors import RuleValidationError
from backend.rules.models import Rule

RULE_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "rule.schema.json"
MAPPINGS_DIR = RULES_DIR / "mappings"


def _load_rule_schema() -> dict[str, Any]:
    """Load the rule schema with the canonical path enum injected."""
    schema: dict[str, Any] = json.loads(RULE_SCHEMA_PATH.read_text(encoding=FILE_ENCODING))
    schema["$defs"]["canonicalPath"]["enum"] = list(canonical_paths_sorted())
    return schema


def _validator() -> Any:
    """Build a jsonschema validator, or None when jsonschema is unavailable.

    jsonschema is a hard dependency of the project. If it is missing the loader
    still works via pydantic, but says so instead of pretending the structural
    pass ran.
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError:  # pragma: no cover - dependency is installed
        return None
    return Draft202012Validator(_load_rule_schema())


def _iter_documents(path: Path) -> list[dict[str, Any]]:
    """Read one YAML file into a list of rule mappings.

    Accepts three shapes so a pack author can pick whichever reads best:
    a top-level list, a ``rules:`` key, or multiple ``---`` documents.
    """
    text = path.read_text(encoding=FILE_ENCODING)
    documents: list[dict[str, Any]] = []
    for document in yaml.safe_load_all(text):
        if document is None:
            continue
        if isinstance(document, list):
            documents.extend(d for d in document if isinstance(d, dict))
        elif isinstance(document, dict) and isinstance(document.get("rules"), list):
            documents.extend(d for d in document["rules"] if isinstance(d, dict))
        elif isinstance(document, dict):
            documents.append(document)
    return documents


def load_rules_from_file(path: Path, validator: Any = None) -> list[Rule]:
    """Load and validate every rule in one mapping pack file.

    Raises:
        RuleValidationError: With the file name and every problem found, so one
            run surfaces all the errors instead of one per re-run.
    """
    if validator is None:
        validator = _validator()

    problems: list[str] = []
    rules: list[Rule] = []

    try:
        documents = _iter_documents(path)
    except yaml.YAMLError as exc:
        raise RuleValidationError(f"{path.name}: not valid YAML: {exc}") from exc

    for position, raw in enumerate(documents, start=1):
        label = raw.get("id") or f"document #{position}"
        structural_errors = 0
        if validator is not None:
            for error in sorted(validator.iter_errors(raw), key=lambda e: list(e.path)):
                pointer = "/".join(str(p) for p in error.path) or "(root)"
                problems.append(f"{path.name} [{label}] at {pointer}: {error.message}")
                structural_errors += 1
        if structural_errors:
            # Structure is already wrong; pydantic would only repeat it.
            continue
        try:
            rules.append(Rule.model_validate(raw))
        except Exception as exc:
            problems.append(f"{path.name} [{label}]: {_first_line(exc)}")

    if problems:
        raise RuleValidationError(
            f"{len(problems)} problem(s) in mapping pack:\n  " + "\n  ".join(problems[:25])
            + (f"\n  … and {len(problems) - 25} more" if len(problems) > 25 else "")
        )
    return rules


def _first_line(exc: Exception) -> str:
    """Compress a pydantic ValidationError into one readable line."""
    text = str(exc).replace("\n", " ")
    return text[:400]


def load_all_rules(mappings_dir: Path | None = None) -> list[Rule]:
    """Load every mapping pack, rejecting duplicate rule ids.

    Args:
        mappings_dir: Directory to scan; ``rules/mappings`` when omitted.

    Returns:
        Rules in deterministic id order.
    """
    directory = mappings_dir or MAPPINGS_DIR
    if not directory.exists():
        return []

    validator = _validator()
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    duplicates: list[str] = []

    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        for rule in load_rules_from_file(path, validator):
            previous = seen.get(rule.id)
            if previous:
                duplicates.append(f"'{rule.id}' in {path.name} and {previous}")
                continue
            seen[rule.id] = path.name
            rules.append(rule)

    if duplicates:
        raise RuleValidationError(
            "duplicate rule ids across mapping packs:\n  " + "\n  ".join(duplicates)
        )
    return sorted(rules, key=lambda r: r.id)


class RulePackLoader:
    """Caches loaded rules and re-reads them only when the pack changes on disk."""

    def __init__(self, mappings_dir: Path | None = None) -> None:
        self.directory = mappings_dir or MAPPINGS_DIR
        self._rules: list[Rule] = []
        self._fingerprint: tuple = ()
        self.version = 0

    def _current_fingerprint(self) -> tuple:
        """Fingerprint the pack from paths, sizes and mtimes."""
        if not self.directory.exists():
            return ()
        entries = []
        for path in sorted(self.directory.rglob("*.y*ml")):
            stat = path.stat()
            entries.append((str(path), stat.st_size, int(stat.st_mtime_ns)))
        return tuple(entries)

    def rules(self) -> list[Rule]:
        """Return the cached rules, loading them on first use."""
        if not self._fingerprint:
            self.reload_if_changed()
        return self._rules

    def reload_if_changed(self) -> bool:
        """Re-read the pack when it has changed. Returns True when it reloaded."""
        fingerprint = self._current_fingerprint()
        if fingerprint == self._fingerprint and self._rules:
            return False
        self._rules = load_all_rules(self.directory)
        self._fingerprint = fingerprint
        self.version += 1
        return True
