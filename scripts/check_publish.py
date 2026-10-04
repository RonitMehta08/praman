"""Check the Git index for private files, oversized blobs and credential tokens.

Run after staging and before committing: ``python scripts/check_publish.py``.
Only paths and reasons are printed, never credential values. Published framework
documents contain configuration examples, so the content scan targets explicit
credential formats rather than every occurrence of the word "password".
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_GITHUB_BYTES = 100 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{60,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{80,}"),
)
PRIVATE_PARTS = frozenset({
    ".venv", ".venv-remediation", ".venv-dev-ccp2", ".venv-py314-backup",
    "__pycache__", "node_modules", "checkpoints", ".cache", ".pytest_cache",
    ".ruff_cache", "_config2spec", "_batfish", "_hierconfig",
})
PRIVATE_SUFFIXES = frozenset({
    ".db", ".sqlite", ".sqlite3", ".key", ".pem", ".pfx", ".p12", ".pyc", ".gguf",
})


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=PROJECT_ROOT)


def main() -> int:
    """Inspect exactly the bytes staged for the next commit."""
    entries = _git("ls-files", "--stage", "-z").split(b"\0")
    errors: list[str] = []
    count = 0
    total = 0
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, blob, stage = metadata.decode("ascii").split()
        name = raw_path.decode("utf-8")
        path = PurePosixPath(name)
        count += 1
        if stage != "0" or mode == "160000":
            errors.append(f"{name}: unresolved merge or nested repository")
            continue
        if (
            PRIVATE_PARTS.intersection(path.parts)
            or path.suffix in PRIVATE_SUFFIXES
            or name.startswith(("data/private/", "out/", "vendor/"))
            or (path.name.startswith(".env") and not path.name.endswith(".example"))
            or re.search(r"\.(?:db|sqlite3?)-(?:wal|shm)$|\.db\.bak-", name)
        ):
            errors.append(f"{name}: private or generated file is tracked")
        size = int(_git("cat-file", "-s", blob))
        total += size
        if size > MAX_GITHUB_BYTES:
            errors.append(f"{name}: exceeds GitHub's 100 MiB file limit")
        # Binary model blobs and publisher ZIPs cannot be scanned as source text.
        if size <= 2 * 1024 * 1024 and path.suffix not in {
            ".zip", ".pdf", ".xlsx", ".pkl", ".joblib", ".npz", ".safetensors",
        }:
            content = _git("cat-file", "blob", blob)
            if any(pattern.search(content) for pattern in SECRET_PATTERNS):
                errors.append(f"{name}: credential-shaped content detected")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print(f"Publish check passed: {count} tracked files, {total / (1024 * 1024):.1f} MiB.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
