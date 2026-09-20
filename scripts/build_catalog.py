"""Build the normalised control catalog and crosswalks from on-disk artefacts.

Reads the benchmark artefacts downloaded by MANUAL_COMMANDS.md and writes:

    data/frameworks/catalog/<catalog_id>.json    one per benchmark
    data/frameworks/crosswalk/cci_to_nist_800_53.json
    data/frameworks/crosswalk/nist_800_53_to_iso_27001.json

Offline and idempotent. No network access; no model inference. Re-run it after
adding a benchmark zip or editing data/frameworks/scope.yaml.

Usage:
    python scripts/build_catalog.py             # build everything
    python scripts/build_catalog.py --no-extract  # skip nested-zip extraction
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from backend.app.config import FILE_ENCODING, FRAMEWORKS_DIR
from backend.frameworks.catalog import ControlCatalog, write_catalog
from backend.frameworks.cis_catalog import parse_cis_json
from backend.frameworks.crosswalk import (
    build_cci_to_nist,
    build_nist_to_iso,
    resolve_iso_from_nist,
    write_crosswalk,
)
from backend.frameworks.iso_catalog import build_iso_catalog
from backend.frameworks.oscal import parse_oscal_catalog
from backend.frameworks.xccdf import find_xccdf_files, parse_xccdf

SCOPE_PATH = FRAMEWORKS_DIR / "scope.yaml"
STIG_DIR = FRAMEWORKS_DIR / "stig"
CIS_DIR = FRAMEWORKS_DIR / "cis"
EXTRACT_DIR = STIG_DIR / "_extracted"
ISO_DIR = FRAMEWORKS_DIR / "iso"
OSCAL_DIR = FRAMEWORKS_DIR / "oscal"


def load_scope() -> dict:
    """Load the benchmark applicability scope table."""
    if not SCOPE_PATH.exists():
        return {"patterns": [], "stig_library_include": []}
    return yaml.safe_load(SCOPE_PATH.read_text(encoding=FILE_ENCODING)) or {}


def normalise_for_match(text: str) -> str:
    """Fold punctuation to spaces so titles and filenames match one pattern.

    DISA writes the same product as "Cisco NX OS Switch" in <title> and
    "U_Cisco_NX-OS_Switch" in the filename; both fold to "cisco nx os switch".
    """
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def resolve_scope(name: str, patterns: list[dict]) -> tuple[list[str], list[str]]:
    """Return (vendors, os_families) for a benchmark name via the scope table."""
    haystack = normalise_for_match(name)
    for entry in patterns:
        needle = normalise_for_match(str(entry.get("match", "")))
        if needle and needle in haystack:
            return list(entry.get("vendors") or []), list(entry.get("os_families") or [])
    return [], []


def is_excluded(name: str, excludes: list[str]) -> bool:
    """Return True when a benchmark is outside the problem statement's scope."""
    haystack = normalise_for_match(name)
    return any(
        normalise_for_match(token) in haystack for token in excludes if str(token).strip()
    )


def release_rank(version: str) -> tuple[int, int]:
    """Rank a DISA release token so V3R7 sorts above V3R6 and V2R9."""
    match = re.match(r"V(\d+)R(\d+)", version.upper())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def extract_library_stigs(include: list[str]) -> int:
    """Extract selected network-device STIG zips out of the SRG-STIG libraries.

    Each nested zip is a few megabytes; only names matching `include` are
    extracted so the working set stays small.
    """
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    extracted = 0
    for library in sorted(STIG_DIR.glob("U_SRG-STIG_Library_*")):
        if not library.is_dir():
            continue
        for inner in sorted(library.glob("*.zip")):
            if not any(token.lower() in inner.name.lower() for token in include):
                continue
            target = EXTRACT_DIR / inner.stem
            if target.exists():
                continue
            try:
                with zipfile.ZipFile(inner) as archive:
                    for member in archive.namelist():
                        if member.endswith("/") or ".." in member:
                            continue
                        if not member.lower().endswith(("-xccdf.xml", ".xml")):
                            continue
                        destination = target / Path(member).name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(member) as src, destination.open("wb") as dst:
                            shutil.copyfileobj(src, dst, length=1 << 20)
                extracted += 1
            except zipfile.BadZipFile:
                print(f"  ! skipped unreadable archive: {inner.name}")
    return extracted


def build_stig_catalogs(
    patterns: list[dict], excludes: list[str]
) -> tuple[list[ControlCatalog], list[str]]:
    """Parse Manual STIG XCCDF files, keeping only the newest release of each.

    DISA ships the same benchmark at several releases (a standalone download plus
    one or more library snapshots). Auditing against all of them would count the
    same requirement two or three times, so releases are collapsed per benchmark
    title and the highest VxRy wins.

    Returns:
        (catalogs, superseded) where superseded names the releases dropped, so
        the build reports what it discarded instead of hiding it.
    """
    best: dict[str, ControlCatalog] = {}
    superseded: list[str] = []

    for xml_path in find_xccdf_files(STIG_DIR):
        try:
            preview = parse_xccdf(xml_path)
        except Exception as exc:
            print(f"  ! {xml_path.name}: {exc}")
            continue
        if not preview.controls:
            continue
        if is_excluded(f"{preview.benchmark} {xml_path.name}", excludes):
            continue

        vendors, os_families = resolve_scope(
            f"{preview.benchmark} {xml_path.name}", patterns
        )
        catalog = parse_xccdf(xml_path, vendors=vendors, os_families=os_families)
        key = normalise_for_match(catalog.benchmark)
        incumbent = best.get(key)
        if incumbent is None:
            best[key] = catalog
            continue
        if release_rank(catalog.benchmark_version) > release_rank(
            incumbent.benchmark_version
        ):
            superseded.append(f"{incumbent.benchmark} {incumbent.benchmark_version}")
            best[key] = catalog
        else:
            superseded.append(f"{catalog.benchmark} {catalog.benchmark_version}")

    return list(best.values()), superseded


def build_cis_catalogs(patterns: list[dict]) -> list[ControlCatalog]:
    """Parse every extracted CIS Benchmark JSON into catalogs."""
    catalogs: list[ControlCatalog] = []
    for json_path in sorted(CIS_DIR.glob("*.json")):
        vendors, os_families = resolve_scope(json_path.stem, patterns)
        catalogs.append(
            parse_cis_json(json_path, vendors=vendors, os_families=os_families)
        )
    return catalogs


def enrich_with_crosswalks(catalogs: list[ControlCatalog]) -> dict[str, int]:
    """Resolve CCI to NIST 800-53 to ISO 27001 references on every control."""
    from backend.frameworks.crosswalk import load_crosswalk

    cci_map = load_crosswalk("cci_to_nist_800_53")
    stats = {"nist_resolved": 0, "iso_resolved": 0}
    for catalog in catalogs:
        for control in catalog.controls:
            # A NIST control is its own 800-53 reference; that is what lets the
            # ISO crosswalk resolve for the NIST catalog too.
            if catalog.framework == "NIST_800_53" and not control.nist_800_53:
                control.nist_800_53 = [control.control_id]
            if control.cci and not control.nist_800_53:
                resolved: set[str] = set()
                for cci in control.cci:
                    resolved.update(cci_map.get(cci, []))
                control.nist_800_53 = sorted(resolved)
                if control.nist_800_53:
                    stats["nist_resolved"] += 1
            if control.nist_800_53 and not control.iso_27001:
                control.iso_27001 = resolve_iso_from_nist(control.nist_800_53)
                if control.iso_27001:
                    stats["iso_resolved"] += 1
    return stats


def list_catalogs() -> int:
    """Print the inventory of already-built catalogs, and how many are automated.

    Read-only: it loads ``frameworks/catalog/*.json`` and the shipped mapping
    packs rather than re-extracting the publisher zips, so it is safe to run any
    time you need the numbers quoted in docs/GAPS.md or a report footer.

    The automated column is the point of the command. A catalog inventory on its
    own overstates what the tool assesses — a framework can be fully ingested and
    have no rules at all — so the two figures are printed side by side and never
    separately.
    """
    from backend.rules.evaluator import RulesEvaluator

    evaluator = RulesEvaluator()
    if not evaluator.catalogs:
        print(
            "no catalogs found. Build them first:\n"
            "  python scripts/build_catalog.py",
            file=sys.stderr,
        )
        return 1

    automated: dict[str, set[str]] = {}
    for rule in evaluator.rules:
        automated.setdefault(rule.catalog.catalog_id, set()).add(rule.catalog.control_id)

    print(f"{'framework':<14} {'catalog':<62} {'controls':>8} {'automated':>10}")
    print("-" * 98)
    by_framework: dict[str, list[int]] = {}
    for catalog in sorted(evaluator.catalogs, key=lambda c: (c.framework, c.catalog_id)):
        covered = len(automated.get(catalog.catalog_id, ()))
        bucket = by_framework.setdefault(catalog.framework, [0, 0, 0])
        bucket[0] += 1
        bucket[1] += len(catalog.controls)
        bucket[2] += covered
        flag = f"{covered:>10}" if covered else f"{'—':>10}"
        print(
            f"{catalog.framework:<14} {catalog.catalog_id[:62]:<62} "
            f"{len(catalog.controls):>8} {flag}"
        )

    print("\n── By framework ────────────────────────────────────────────")
    totals = [0, 0, 0]
    for framework in sorted(by_framework):
        count, controls, covered = by_framework[framework]
        totals = [t + v for t, v in zip(totals, (count, controls, covered), strict=True)]
        share = f"{100.0 * covered / controls:.1f}%" if controls else "—"
        print(
            f"  {framework:<14} {count:>3} catalogs  {controls:>5} controls  "
            f"{covered:>4} automated ({share})"
        )
    share = f"{100.0 * totals[2] / totals[1]:.1f}%" if totals[1] else "—"
    print(
        f"\n  {totals[0]} catalogs, {totals[1]} controls normalised, "
        f"{totals[2]} automated ({share}). Unautomated controls are reported as "
        "'notchecked' and excluded from the compliance score — see docs/GAPS.md."
    )
    return 0


def main() -> int:
    """Build catalogs and crosswalks; print a coverage summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-extract", action="store_true", help="skip nested-zip extraction"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the inventory of already-built catalogs and exit; builds nothing",
    )
    args = parser.parse_args()

    if args.list:
        return list_catalogs()

    scope = load_scope()
    patterns = scope.get("patterns", [])

    print("── Crosswalks ──────────────────────────────────────────────")
    cci_xml = next(STIG_DIR.glob("U_CCI_List/*.xml"), None)
    if cci_xml:
        cci_map = build_cci_to_nist(cci_xml)
        write_crosswalk("cci_to_nist_800_53", cci_map)
        print(f"  CCI -> NIST 800-53 : {len(cci_map)} CCIs mapped")
    else:
        print("  ! U_CCI_List.xml not found — STIG findings will carry no 800-53 refs")

    olir = next(ISO_DIR.glob("*OLIR*.xlsx"), None)
    iso_map: dict[str, list[str]] = {}
    if olir:
        iso_map = build_nist_to_iso(olir)
        write_crosswalk("nist_800_53_to_iso_27001", iso_map)
        print(f"  NIST 800-53 -> ISO : {len(iso_map)} controls mapped")
    else:
        print("  ! OLIR workbook not found — ISO references will be empty")

    if not args.no_extract:
        print("\n── Extracting network-device STIGs from library zips ───────")
        count = extract_library_stigs(scope.get("stig_library_include", []))
        print(f"  extracted {count} new STIG package(s)")

    print("\n── Catalogs ────────────────────────────────────────────────")
    stig_catalogs, superseded = build_stig_catalogs(patterns, scope.get("exclude", []))
    catalogs = stig_catalogs + build_cis_catalogs(patterns)

    oscal_json = next(OSCAL_DIR.glob("sp80053*.json"), None)
    if oscal_json:
        catalogs.append(parse_oscal_catalog(oscal_json))
    else:
        print("  ! OSCAL sp80053.json not found — no NIST 800-53 catalog built")

    if iso_map:
        catalogs.append(build_iso_catalog(iso_map, source_document=olir.name))

    stats = enrich_with_crosswalks(catalogs)

    # Remove catalogs from a previous build so a narrowed scope actually shrinks.
    catalog_dir = FRAMEWORKS_DIR / "catalog"
    keep = {f"{c.catalog_id}.json" for c in catalogs}
    for stale in sorted(catalog_dir.glob("*.json")) if catalog_dir.exists() else []:
        if stale.name not in keep:
            stale.unlink()

    total_controls = 0
    for catalog in sorted(catalogs, key=lambda c: c.catalog_id):
        write_catalog(catalog)
        total_controls += len(catalog.controls)
        scope_text = ",".join(catalog.vendors) or "vendor-neutral"
        print(
            f"  {catalog.catalog_id[:58]:58s} "
            f"{len(catalog.controls):4d}  [{scope_text}]"
        )

    if superseded:
        print(f"\n  superseded releases dropped ({len(superseded)}):")
        for name in sorted(set(superseded)):
            print(f"    - {name}")

    by_framework: dict[str, list[int]] = {}
    for catalog in catalogs:
        bucket = by_framework.setdefault(catalog.framework, [0, 0])
        bucket[0] += 1
        bucket[1] += len(catalog.controls)

    print("\n── Coverage by framework ───────────────────────────────────")
    for framework in sorted(by_framework):
        count, controls = by_framework[framework]
        print(f"  {framework:16s} {count:3d} catalogs  {controls:5d} controls")

    print(
        f"\n  {len(catalogs)} catalogs, {total_controls} controls total; "
        f"{stats['nist_resolved']} controls gained 800-53 refs, "
        f"{stats['iso_resolved']} gained ISO refs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
