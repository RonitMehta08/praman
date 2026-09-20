"""Canonical path vocabulary — loaded from the schema, not duplicated in code.

``canonical_paths.schema.json`` is the single source of truth for the set of
legal ``CanonicalFact.path`` values. Everything that needs the vocabulary reads
it from here:

* parsers, so a typo becomes a test failure instead of a silently-dropped fact;
* the rule loader, so a rule cannot reference a path no parser can produce;
* ``scripts/emit_gbnf.py``, so grammar-constrained decoding restricts the LLM to
  paths that actually exist (GLOBAL_RULESET R5.2).

Keeping one list in one file is what makes the three consumers provably
consistent — see ``tests/test_canonical_schema.py``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema" / "canonical_paths.schema.json"


@lru_cache(maxsize=1)
def canonical_paths() -> frozenset[str]:
    """Return every legal CanonicalFact.path value."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return frozenset(schema["enum"])


@lru_cache(maxsize=1)
def canonical_paths_sorted() -> tuple[str, ...]:
    """Return the vocabulary in deterministic order (grammar and UI use this)."""
    return tuple(sorted(canonical_paths()))


def is_canonical_path(path: str) -> bool:
    """True when ``path`` is part of the canonical vocabulary."""
    return path in canonical_paths()


@lru_cache(maxsize=1)
def path_families() -> dict[str, tuple[str, ...]]:
    """Group the vocabulary by first segment, for UI grouping and coverage stats."""
    families: dict[str, list[str]] = {}
    for path in canonical_paths_sorted():
        families.setdefault(path.split(".", 1)[0], []).append(path)
    return {family: tuple(paths) for family, paths in sorted(families.items())}
