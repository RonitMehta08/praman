"""Collect every verification marker in the repository into one register.

``GLOBAL_RULESET.md`` R1.5 gives three markers for text that is not fully
established, and §236 makes one of them a release gate: no ``UNVERIFIED`` and no
unresolved ``TODO`` ``(verify)`` may reach a shipped path. Nothing enforced that,
and nothing published the register, so the roadmap's count of the markers was
hand-counted once and went stale the moment work continued.

    python scripts/collect_unverified.py           # print the register
    python scripts/collect_unverified.py --write    # rewrite the register + JSON
    python scripts/collect_unverified.py --check    # exit 1 if stale or blocking

Two outcomes, deliberately separated:

* **Blocking.** A marker inside a *shipped* root — code, pattern packs, mapping
  packs, the frontend — is a defect, because that text reaches an operator
  through the UI, a finding rationale or the signed PDF. Exit code 1.
* **Register.** The same marker in a document is a *disclosure*, which is what
  R1.5 asks for. It is published rather than punished, and ``--check`` fails only
  when the published register no longer matches the repository.

``ASSUMPTION:`` never blocks anywhere. R1.5 defines it as a decision taken in the
absence of data, which is a permanent property of that decision rather than an
open task, so a shipped rule pack is exactly where one belongs — see the weak-SSH
-cipher list in the DISA NX-OS pack, whose rationale says so in the report the
auditor reads.

This file excludes itself from the scan, and so does its test. Both have to name
all three markers in order to look for them, so scanning them would report the
vocabulary as debt; the cost is that a genuine marker written into either is
invisible, which is recorded here rather than left for someone to discover. The
same problem in ``docs/GAPS.md`` is solved the opposite way — the prose that names
the markers is *generated* into the block below the sentinels, so the existing
blanking already covers it and the published rationale cannot drift from the
``SHIPPED_ROOTS`` and ``ALLOWLIST`` it describes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT

WORKSPACE_ROOT = PROJECT_ROOT.parent
SELF = Path(__file__).resolve()

#: The two files whose subject is the marker vocabulary itself. Excluded whole,
#: by name, because each must write all three markers in order to search for or
#: assert on them — and a scanner that reports its own source as debt is not
#: measuring the repository, it is measuring itself.
SELF_EXCLUDED = frozenset(
    {SELF, (PROJECT_ROOT / "tests" / "test_unverified_register.py").resolve()}
)

REGISTER_JSON = PROJECT_ROOT / "reports" / "metrics" / "unverified.json"
GAPS = PROJECT_ROOT / "docs" / "GAPS.md"
BEGIN = "<!-- BEGIN GENERATED: unverified-register -->"
END = "<!-- END GENERATED: unverified-register -->"
_GENERATED_RE = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)

#: Built from fragments on purpose: written whole, they would be findings in this
#: file the moment anything else scanned it.
TODO_MARKER = "TODO" + "(verify)"
ASSUMPTION_MARKER = "ASSUMPTION" + ":"
UNVERIFIED_MARKER = "UN" + "VERIFIED"

MARKERS = {
    TODO_MARKER: re.compile(re.escape(TODO_MARKER)),
    ASSUMPTION_MARKER: re.compile(re.escape(ASSUMPTION_MARKER)),
    UNVERIFIED_MARKER: re.compile(re.escape(UNVERIFIED_MARKER)),
}

#: Markers here are a defect: this text is reachable by an operator at runtime.
SHIPPED_ROOTS = (
    PROJECT_ROOT / "backend",
    PROJECT_ROOT / "frontend",
    PROJECT_ROOT / "rules",
    PROJECT_ROOT / "data" / "ingest",
)

#: Markers here are a disclosure: published in the register, never blocking.
DOCUMENTED_ROOTS = (
    PROJECT_ROOT / "docs",
    PROJECT_ROOT / "scripts",
    PROJECT_ROOT / "tests",
    PROJECT_ROOT / "test_configs",
    PROJECT_ROOT / "README.md",
    PROJECT_ROOT / "guide.md",
    WORKSPACE_ROOT / "MANUAL_COMMANDS.md",
    WORKSPACE_ROOT / "slides_content.md",
)

#: ``data/frameworks/`` is publisher content and ``data/models/`` is weights.
#: Neither is ours to mark up, and a CIS control whose own text says "assumption"
#: is not a claim PRAMAN made.
SKIP_DIRS = frozenset(
    {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache", ".ruff_cache"}
)
SUFFIXES = frozenset({".py", ".js", ".css", ".html", ".yaml", ".yml", ".json", ".md"})

#: Only ``ASSUMPTION:`` is exempt by kind. Anything else in a shipped root must be
#: listed here with the reason it is not a defect, and the reason is checked
#: against the file — an allowlist that outlives its subject is worse than none.
NON_BLOCKING = {
    "MARKER_KIND": ASSUMPTION_MARKER,
}

@dataclass(frozen=True)
class Allowed:
    """One deliberate use of a blocking marker inside a shipped root."""

    path: str
    marker: str
    reason: str


ALLOWLIST = (
    Allowed(
        path="praman/backend/frameworks/cis/extract.py",
        marker=UNVERIFIED_MARKER,
        reason=(
            "Sentinel *value*, not a note to self. When a CIS section number is "
            "unreadable in the PDF text layer, the extractor records the string "
            "rather than inventing a number (R1.7). Removing it would mean "
            "guessing, so the marker is the correct behaviour and the register "
            "exists partly to keep it legible."
        ),
    ),
)


@dataclass(frozen=True)
class Hit:
    """One marker occurrence, located and quoted."""

    file: str
    line: int
    marker: str
    text: str


def _candidate_files(root: Path) -> list[Path]:
    """Every scannable file under ``root``; ``root`` itself when it is a file."""
    if root.is_file():
        return [root]
    if not root.exists():
        return []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in SUFFIXES
        and not SKIP_DIRS.intersection(path.parts)
    )


def _scan(path: Path) -> list[Hit]:
    """Locate every marker in one file. Undecodable bytes are reported, not raised.

    The generated register is blanked before scanning, not skipped: writing the
    table into ``GAPS.md`` puts every marker string it quotes back into a scanned
    document, so the second run counted 36 more markers than the first and the
    third would have counted more again. Blanking keeps the line numbering of
    everything after the block intact.
    """
    if path.resolve() in SELF_EXCLUDED:
        return []
    try:
        text = path.read_text(encoding=FILE_ENCODING)
    except (UnicodeDecodeError, OSError):
        return []
    text = _GENERATED_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    relative = path.resolve().relative_to(WORKSPACE_ROOT).as_posix()
    hits: list[Hit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for marker, pattern in MARKERS.items():
            if pattern.search(line):
                hits.append(Hit(relative, lineno, marker, line.strip()[:160]))
    return hits


def collect() -> tuple[list[Hit], list[Hit], list[str]]:
    """Return ``(blocking, register, allowlist_errors)`` for the whole repository.

    A hit is blocking when it sits in a shipped root, is not an ``ASSUMPTION:``,
    and is not covered by :data:`ALLOWLIST`. Everything else is register-only,
    including every hit in a document — a disclosure is what R1.5 asked for.
    """
    allowed_files = {entry.path: entry for entry in ALLOWLIST}
    blocking: list[Hit] = []
    register: list[Hit] = []

    for root in SHIPPED_ROOTS:
        for path in _candidate_files(root):
            for hit in _scan(path):
                entry = allowed_files.get(hit.file)
                exempt = hit.marker == NON_BLOCKING["MARKER_KIND"] or (
                    entry is not None and entry.marker == hit.marker
                )
                (register if exempt else blocking).append(hit)

    for root in DOCUMENTED_ROOTS:
        for path in _candidate_files(root):
            register.extend(_scan(path))

    errors = [
        f"allowlist entry {entry.path} no longer contains {entry.marker}; "
        "delete the entry rather than leaving it to authorise nothing"
        for entry in ALLOWLIST
        if not any(
            hit.file == entry.path and hit.marker == entry.marker
            for hit in register + blocking
        )
    ]
    return blocking, sorted(register, key=lambda h: (h.file, h.line)), errors


def _counts(hits: list[Hit]) -> dict[str, int]:
    return {marker: sum(1 for hit in hits if hit.marker == marker) for marker in MARKERS}


def build_payload(blocking: list[Hit], register: list[Hit]) -> dict[str, object]:
    """The JSON published under ``reports/metrics/``."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "counts": _counts(register + blocking),
        "blocking": [asdict(hit) for hit in blocking],
        "register": [asdict(hit) for hit in register],
        "allowlisted": [asdict(entry) for entry in ALLOWLIST],
    }


def render_register(register: list[Hit]) -> str:
    """The markdown block that lives in ``docs/GAPS.md`` between the sentinels.

    The rationale is generated with the table rather than hand-written above it,
    for two reasons. It names the shipped roots and quotes each allowlist reason,
    and hand-written prose about a list drifts from the list — the roots grew by
    one (``data/ingest/``) between the first draft and the first run, and nothing
    would have caught the paragraph still claiming three. And prose that spells
    the markers out is itself matched by the scanner, so generating it puts it
    inside the block that :func:`_scan` already blanks, instead of adding a second
    exclusion mechanism that a future author could park a real marker inside.
    """
    roots = ", ".join(
        f"`{root.relative_to(PROJECT_ROOT).as_posix()}/`" for root in SHIPPED_ROOTS
    )
    lines = [
        BEGIN,
        "",
        f"Regenerated by `scripts/collect_unverified.py`, which separates two things "
        f"that look identical in a grep. A marker in a **shipped** root — {roots} — "
        f"is a defect, because that text reaches an operator through the UI, a "
        f"finding rationale or the signed PDF; it fails `--check` and never appears "
        f"below. The same marker in a **document** is a disclosure, which is what "
        f"R1.5 asked for, so it is published rather than punished.",
        "",
        f"**{len(register)} disclosed, 0 blocking.** `{ASSUMPTION_MARKER}` is exempt "
        f"from blocking everywhere, including shipped roots: R1.5 defines it as a "
        f"decision taken in the absence of data, which is a permanent property of "
        f"that decision rather than an open task — a rule pack whose rationale tells "
        f"the auditor which way it resolved an ambiguity is doing the right thing.",
        "",
    ]
    for entry in ALLOWLIST:
        lines.extend(
            [
                f"One exemption is granted by name rather than by kind: "
                f"`{entry.path}` / `{entry.marker}`. {entry.reason}",
                "",
            ]
        )
    lines.extend(
        [
            "| File | Line | Marker | Text |",
            "|---|--:|---|---|",
        ]
    )
    for hit in register:
        text = hit.text.replace("|", "\\|")
        lines.append(f"| `{hit.file}` | {hit.line} | `{hit.marker}` | {text} |")
    lines.extend(["", END])
    return "\n".join(lines)


def _replace_block(document: Path, block: str) -> bool:
    """Swap the sentinel block in ``document``. Returns True when it changed."""
    text = document.read_text(encoding=FILE_ENCODING)
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(
            f"{document.name} has no {BEGIN} / {END} sentinels. Add them where the "
            "register belongs; this script will not guess a location."
        )
    updated = pattern.sub(lambda _: block, text)
    if updated == text:
        return False
    document.write_text(updated, encoding=FILE_ENCODING)
    return True


def _report(blocking: list[Hit], register: list[Hit], errors: list[str]) -> None:
    for hit in blocking:
        print(f"BLOCKING {hit.file}:{hit.line} [{hit.marker}] {hit.text}")
    for error in errors:
        print(f"ALLOWLIST {error}")
    counts = _counts(register + blocking)
    summary = ", ".join(f"{count} {marker}" for marker, count in counts.items())
    print(f"{len(register)} disclosed, {len(blocking)} blocking ({summary}).")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="rewrite the register and JSON")
    group.add_argument("--check", action="store_true", help="exit 1 if stale or blocking")
    args = parser.parse_args()

    blocking, register, errors = collect()
    block = render_register(register)
    payload = build_payload(blocking, register)

    if args.write:
        changed = _replace_block(GAPS, block)
        REGISTER_JSON.parent.mkdir(parents=True, exist_ok=True)
        REGISTER_JSON.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding=FILE_ENCODING
        )
        print(f"{'rewrote' if changed else 'unchanged'} {GAPS.name}; wrote {REGISTER_JSON.name}")
        _report(blocking, register, errors)
        return 1 if blocking or errors else 0

    if args.check:
        stale: list[str] = []
        if not REGISTER_JSON.exists():
            stale.append(f"{REGISTER_JSON.name} does not exist")
        else:
            published = json.loads(REGISTER_JSON.read_text(encoding=FILE_ENCODING))
            for key in ("counts", "blocking", "register", "allowlisted"):
                if published.get(key) != payload[key]:
                    stale.append(f"{REGISTER_JSON.name}: {key} has drifted")
        if BEGIN in GAPS.read_text(encoding=FILE_ENCODING):
            if block not in GAPS.read_text(encoding=FILE_ENCODING):
                stale.append(f"{GAPS.name}: the register block no longer matches")
        else:
            stale.append(f"{GAPS.name}: the register sentinels are missing")
        for line in stale:
            print(f"STALE {line}")
        _report(blocking, register, errors)
        if stale:
            print("Regenerate with: python scripts/collect_unverified.py --write")
        return 1 if stale or blocking or errors else 0

    print(block)
    _report(blocking, register, errors)
    return 1 if blocking or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
