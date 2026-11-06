"""Verified optional-component installer for the Windows appliance.

The core installer intentionally contains no unpinned multi-gigabyte downloads.
This module accepts a component manifest entry plus a SHA-256 digest, downloads
to a temporary file, verifies it, and only then moves it into the per-user data
directory. It never executes a downloaded file.

Examples::

    PRAMAN.exe --components list
    PRAMAN.exe --components status
    PRAMAN.exe --components install attack --url URL --sha256 DIGEST

The shipped manifest leaves URLs and digests blank because upstream publisher
locations and release bytes must be reviewed and pinned for each product release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def _manifest_path() -> Path:
    bundled = _project_root() / "deploy" / "windows_components.json"
    if bundled.is_file():
        return bundled
    return Path(__file__).with_name("windows_components.json")


def _user_data_dir() -> Path:
    configured = os.environ.get("PRAMAN_USER_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    return Path(local_appdata) / "PRAMAN" if local_appdata else Path.home() / "AppData/Local/PRAMAN"


def load_manifest() -> dict[str, dict[str, Any]]:
    with _manifest_path().open(encoding="utf-8") as handle:
        payload = json.load(handle)
    components = payload.get("components")
    if not isinstance(components, dict):
        raise ValueError("windows component manifest has no components object")
    return components


def _safe_destination(relative_path: str) -> Path:
    root = _user_data_dir().resolve()
    destination = (root / relative_path).resolve()
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"component destination escapes the PRAMAN data directory: {relative_path}") from exc
    return destination


def _parse_digest(value: str) -> str:
    digest = value.strip().lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("sha256 must be exactly 64 hexadecimal characters")
    return digest


def _download_verified(url: str, destination: Path, digest: str, max_bytes: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    hasher = hashlib.sha256()
    total = 0
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "PRAMAN-component-installer/1"},
        )
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=".praman-download-",
                suffix=".part",
                dir=destination.parent,
                delete=False,
            ) as output,
        ):
            temporary = Path(output.name)
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"download exceeds the manifest limit of {max_bytes:,} bytes"
                    )
                hasher.update(chunk)
                output.write(chunk)

        actual = hasher.hexdigest()
        if actual != digest:
            raise ValueError(f"SHA-256 mismatch: expected {digest}, received {actual}")
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def list_components() -> int:
    for name, component in load_manifest().items():
        destination = _safe_destination(str(component["relative_path"]))
        state = "installed" if destination.is_file() else "not installed"
        print(f"{name}: {state} — {component['display_name']}")
    return 0


def status_components() -> int:
    return list_components()


def install_component(name: str, url: str | None, sha256: str | None) -> int:
    components = load_manifest()
    if name not in components:
        print(f"Unknown component: {name}. Use 'list' to see available components.", file=sys.stderr)
        return 2

    component = components[name]
    url = (url or str(component.get("url", ""))).strip()
    sha256 = (sha256 or str(component.get("sha256", ""))).strip()
    if not url or not sha256:
        print(
            f"{name} is not configured for automatic download in this release. "
            "Provide an approved URL and its pinned SHA-256 digest.",
            file=sys.stderr,
        )
        return 2

    try:
        digest = _parse_digest(sha256)
        destination = _safe_destination(str(component["relative_path"]))
        max_bytes = int(component.get("max_bytes", 0))
        if max_bytes <= 0:
            raise ValueError("component manifest must define a positive max_bytes")
        print(f"Downloading {component['display_name']}...")
        _download_verified(url, destination, digest, max_bytes)
    except (OSError, ValueError, TimeoutError, urllib.error.URLError) as exc:
        print(f"Component installation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Installed {name} at {destination}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage optional PRAMAN components")
    parser.add_argument("command", choices=("list", "status", "install"))
    parser.add_argument("name", nargs="?")
    parser.add_argument("--url")
    parser.add_argument("--sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {"list", "status"}:
        return list_components()
    if not args.name:
        print("install requires a component name", file=sys.stderr)
        return 2
    return install_component(args.name, args.url, args.sha256)


if __name__ == "__main__":
    raise SystemExit(main())
