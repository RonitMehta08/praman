"""Check that the Windows build selection excludes local/private artifacts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = (
    "backend",
    "frontend/index.html",
    "rules",
    "schemas",
    "data/ingest/patterns",
    "data/models/classifier",
    "data/frameworks/catalog",
    "data/frameworks/crosswalk",
    "data/frameworks/cis",
    "data/frameworks/oscal/sp80053.json",
    "deploy/windows_components.json",
)
FORBIDDEN_PARTS = {
    "praman.db",
    "praman.db-wal",
    "praman.db-shm",
    "private",
    "lora",
    "_source",
}
FORBIDDEN_SUFFIXES = {".gguf", ".pfx", ".p12", ".pem", ".key"}


def _is_forbidden_file(path: Path) -> bool:
    """Reject secrets while allowing certifi's public CA trust bundle."""
    if path.name.lower() == "cacert.pem" and "certifi" in {part.lower() for part in path.parts}:
        return False
    return (
        any(part.lower() in {part.lower() for part in FORBIDDEN_PARTS} for part in path.parts)
        or path.suffix.lower() in FORBIDDEN_SUFFIXES
    )


def source_check() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        print("Missing Windows package inputs:", file=sys.stderr)
        for path in missing:
            print(f"  {path}", file=sys.stderr)
        return 1

    selected_roots = (
        ROOT / "frontend",
        ROOT / "rules",
        ROOT / "schemas",
        ROOT / "data" / "ingest",
        ROOT / "data" / "labels",
        ROOT / "data" / "models" / "classifier",
        ROOT / "data" / "frameworks" / "catalog",
        ROOT / "data" / "frameworks" / "crosswalk",
        ROOT / "data" / "frameworks" / "cis",
        ROOT / "data" / "frameworks" / "iso",
        ROOT / "data" / "frameworks" / "oscal",
        ROOT / "data" / "frameworks" / "attack" / "canonical_map.yaml",
        ROOT / "data" / "frameworks" / "stig" / "_extracted",
        ROOT / "data" / "frameworks" / "stig" / "U_CCI_List",
    )
    offenders: list[Path] = []
    for selected_root in selected_roots:
        paths = [selected_root] if selected_root.is_file() else selected_root.rglob("*")
        for path in paths:
            if not path.is_file():
                continue
            if selected_root == ROOT / "data" / "frameworks" / "cis" and path.suffix.lower() != ".json":
                continue
            if _is_forbidden_file(path):
                offenders.append(path)
    if offenders:
        print("Forbidden artifact selected by the Windows package:", file=sys.stderr)
        for path in offenders:
            print(f"  {path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    print("Windows package input check passed.")
    return 0


def dist_check(dist: Path) -> int:
    if not dist.is_dir():
        print(f"PyInstaller output not found: {dist}", file=sys.stderr)
        return 1
    offenders = [
        path
        for path in dist.rglob("*")
        if path.is_file()
        and _is_forbidden_file(path)
    ]
    if offenders:
        print("Forbidden artifact found in PyInstaller output:", file=sys.stderr)
        for path in offenders:
            print(f"  {path}", file=sys.stderr)
        return 1
    print(f"PyInstaller output check passed: {dist}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args()
    result = source_check()
    if result or args.dist is None:
        return result
    return dist_check(args.dist)


if __name__ == "__main__":
    raise SystemExit(main())
