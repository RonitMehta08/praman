"""Emit the Canonical JSON Schema, and verify the canonical path vocabulary.

Run:
    .venv/Scripts/python.exe -m scripts.emit_canonical_schema           # write + verify
    .venv/Scripts/python.exe -m scripts.emit_canonical_schema --check   # verify only

Two files live in ``backend/canonical/schema/`` and they are maintained in
opposite directions, which is the whole point of this script:

``canonical.schema.json`` is **generated**. It is the pydantic models rendered as
JSON Schema, so regenerating it is the only correct way to change it.

``canonical_paths.schema.json`` is **authored**. It is the canonical vocabulary,
and it is deliberately *not* derived from the pattern packs or the rule packs —
deriving it would make its own validation vacuous. ``patterns._check_path`` and
``rules.models`` reject any path outside this enum precisely so that a typo in a
pack ("mgmt.ssh.verison") is a loud startup failure rather than a fact silently
dropped on the floor. If the enum were generated from the packs, the typo would
become a new legal path and the check would protect nothing.

So this script verifies that file instead of writing it: every path the packs and
rules reference must already be in the enum. Adding a canonical path is an
authoring decision — edit the schema, then teach a parser to emit it.

Before this rewrite the script wrote ``canonical_paths.schema.json`` from a
70-entry seed list hardcoded below its docstring, while the authored file had
grown to 312. Running it as documented would have deleted 242 paths and broken
every pattern pack and rule pack that referenced one — a landmine in a file whose
own docstring invited the run. Nothing imported the seed list.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.canonical.findings import AuditRecord, Finding, Result
from backend.canonical.models import CanonicalFact, Device
from backend.canonical.paths import SCHEMA_PATH as PATHS_SCHEMA_PATH
from backend.canonical.paths import canonical_paths

SCHEMA_DIR = PROJECT_ROOT / "backend" / "canonical" / "schema"
MAIN_SCHEMA_PATH = SCHEMA_DIR / "canonical.schema.json"


def build_main_schema() -> dict:
    """The canonical model as JSON Schema, straight from the pydantic models."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "PRAMAN Canonical Model",
        "description": "The vendor-neutral Security Baseline Model.",
        "definitions": {
            "Device": Device.model_json_schema(),
            "CanonicalFact": CanonicalFact.model_json_schema(),
            "Finding": Finding.model_json_schema(),
            "AuditRecord": AuditRecord.model_json_schema(),
            "Result": {
                "type": "string",
                "enum": [r.value for r in Result],
            },
        },
    }


def _render(schema: dict) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


# ── The authored vocabulary ──────────────────────────────────────────────


def paths_used_by_packs() -> dict[str, set[str]]:
    """Every canonical path each pattern pack can emit, keyed by vendor."""
    from backend.ingest.patterns import PatternLibrary

    library = PatternLibrary()
    library.reload_if_changed()
    return {
        vendor: set(pack.referenced_paths())
        for vendor, pack in library.packs().items()
    }


def paths_used_by_rules() -> dict[str, set[str]]:
    """Every canonical path each rule reads, keyed by rule id.

    Covers both the condition tree and the applicability gate: a rule that only
    runs when ``device.os_version`` is present is reading that path just as much
    as one that asserts on it.
    """
    from backend.rules.loader import RulePackLoader

    loader = RulePackLoader()
    loader.reload_if_changed()
    used: dict[str, set[str]] = {}
    for rule in loader.rules():
        paths = set(rule.referenced_paths())
        paths |= set(rule.applies_to.requires_paths or ())
        used[rule.id] = paths
    return used


def verify_paths_schema() -> list[str]:
    """Return a list of problems with the authored path vocabulary; empty is good."""
    problems: list[str] = []

    raw = json.loads(PATHS_SCHEMA_PATH.read_text(encoding="utf-8"))
    enum = raw.get("enum")
    if not isinstance(enum, list) or not enum:
        return [f"{PATHS_SCHEMA_PATH.name} has no non-empty `enum` array"]

    # Sorted and unique. Both are load-bearing: `canonical_paths_sorted()` feeds
    # the LLM grammar and the training GUI's picker, and a duplicate would make
    # the grammar's alternation ambiguous for no reason.
    if len(enum) != len(set(enum)):
        duplicates = sorted({p for p in enum if enum.count(p) > 1})
        problems.append(f"duplicate paths in the enum: {duplicates}")
    if enum != sorted(enum):
        problems.append("the enum is not in sorted order (deterministic output matters)")

    vocabulary = canonical_paths()

    for vendor, used in sorted(paths_used_by_packs().items()):
        for path in sorted(used - vocabulary):
            problems.append(
                f"pattern pack '{vendor}' emits '{path}', which is not in the "
                f"vocabulary — add it to {PATHS_SCHEMA_PATH.name}"
            )

    for rule_id, used in sorted(paths_used_by_rules().items()):
        for path in sorted(used - vocabulary):
            problems.append(
                f"rule '{rule_id}' reads '{path}', which is not in the vocabulary "
                f"— add it to {PATHS_SCHEMA_PATH.name}"
            )

    return problems


def report_unused() -> None:
    """Print the authored paths nothing emits yet.

    Not a failure. A path is often authored before the parser that fills it, and
    the count is a useful read on how much of the vocabulary is live — the
    automation-coverage figure in the UI is the same story told per control.
    """
    emitted: set[str] = set()
    for used in paths_used_by_packs().values():
        emitted |= used
    read: set[str] = set()
    for used in paths_used_by_rules().values():
        read |= used

    vocabulary = canonical_paths()
    print(
        f"[paths] {len(vocabulary)} authored | {len(emitted)} emitted by a pack "
        f"| {len(read)} read by a rule | {len(vocabulary - emitted)} awaiting a parser"
    )
    orphans = sorted(read - emitted)
    if orphans:
        # A rule reading a path no pack emits is not broken — it renders
        # INDETERMINATE, which is the honest verdict. But it is worth naming,
        # because it is indistinguishable from a typo at a glance.
        print(f"[paths] read by a rule but emitted by no pack ({len(orphans)}):")
        for path in orphans:
            print(f"          {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify only; write nothing and fail if the generated schema is stale",
    )
    args = parser.parse_args(argv)

    failed = False

    generated = _render(build_main_schema())
    if args.check:
        on_disk = (
            MAIN_SCHEMA_PATH.read_text(encoding="utf-8")
            if MAIN_SCHEMA_PATH.exists()
            else ""
        )
        if on_disk != generated:
            print(
                f"[FAIL] {MAIN_SCHEMA_PATH.relative_to(PROJECT_ROOT)} is stale — "
                "the pydantic models have changed. Re-run without --check.",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"[ok]   {MAIN_SCHEMA_PATH.relative_to(PROJECT_ROOT)} is up to date")
    else:
        SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
        # `newline="\n"` deliberately: without it Windows writes CRLF and the
        # generated artefact differs byte-for-byte depending on which machine ran
        # the generator, which turns a no-op regeneration into a whole-file diff.
        MAIN_SCHEMA_PATH.write_text(generated, encoding="utf-8", newline="\n")
        print(
            f"[emit] {MAIN_SCHEMA_PATH.relative_to(PROJECT_ROOT)} "
            f"({MAIN_SCHEMA_PATH.stat().st_size:,} bytes)"
        )

    problems = verify_paths_schema()
    if problems:
        print(
            f"[FAIL] {PATHS_SCHEMA_PATH.relative_to(PROJECT_ROOT)}: "
            f"{len(problems)} problem(s)",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"         {problem}", file=sys.stderr)
        failed = True
    else:
        print(
            f"[ok]   {PATHS_SCHEMA_PATH.relative_to(PROJECT_ROOT)} covers every path "
            "the packs and rules reference"
        )

    report_unused()
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
