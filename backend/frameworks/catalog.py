"""The normalised control catalog — one entry per published benchmark control.

A ControlCatalog is *evidence about what a framework requires*. It carries no
verdict logic. The rules engine joins a catalog against a mapping pack
(rules/mappings/*.yaml) to decide which controls are machine-checkable; controls
with no mapping are reported as XCCDF ``notchecked`` rather than dropped.

Catalogs are built by scripts/build_catalog.py and cached as JSON under
data/frameworks/catalog/. They are pure data: adding a benchmark never requires
a code change (capability C5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.app.config import FILE_ENCODING, FRAMEWORKS_DIR

CATALOG_DIR = FRAMEWORKS_DIR / "catalog"


class CatalogControl(BaseModel):
    """One control as published by its framework. All text is verbatim.

    control_id is the framework-native identifier and is never rewritten:
    ``V-215807`` for DISA STIG, ``1.1.1`` for CIS, ``ac-2`` for NIST 800-53,
    ``A.5.15`` for ISO/IEC 27001:2022.
    """

    model_config = ConfigDict(extra="forbid")

    control_id: str
    title: str
    severity: str | None = None  # from XCCDF @severity; None when source omits it
    discussion: str = ""  # XCCDF description / CIS description+rationale
    check_text: str = ""  # how the publisher says to audit it
    fix_text: str = ""  # publisher's own remediation text — never LLM-authored
    # --- source-specific identifiers, all optional ---
    stig_id: str | None = None  # e.g. CISC-ND-000010 (XCCDF <version>)
    legacy_ids: list[str] = []  # e.g. ["SV-105327", "V-96189"]
    cci: list[str] = []  # e.g. ["CCI-000054"]
    nist_800_53: list[str] = []  # resolved via the CCI crosswalk
    iso_27001: list[str] = []  # resolved via the NIST/ISO OLIR crosswalk
    profile: str | None = None  # CIS "Level 1" / "Level 2"
    automated: bool | None = None  # CIS "automated" flag; None when unknown
    default_value: str = ""
    impact: str = ""


class ControlCatalog(BaseModel):
    """All controls from one published benchmark, plus its applicability scope."""

    model_config = ConfigDict(extra="forbid")

    catalog_id: str  # stable slug, e.g. "disa_stig_cisco_iosxe_ndm_v3r7"
    framework: str  # CIS | NIST_800_53 | DISA_STIG | ISO_27001
    benchmark: str  # verbatim publisher title
    benchmark_version: str  # verbatim, e.g. "V3R7", "v4.1.1"
    source_document: str  # filename the catalog was extracted from
    source_url: str = ""
    # Which devices this benchmark governs. Empty list means "all devices".
    vendors: list[str] = []
    os_families: list[str] = []
    controls: list[CatalogControl] = []

    def by_id(self) -> dict[str, CatalogControl]:
        """Index controls by control_id for O(1) mapping joins."""
        return {c.control_id: c for c in self.controls}

    def applies_to(self, vendor: str, os_family: str) -> bool:
        """Return True when this benchmark governs the given device.

        An empty vendors/os_families list means the benchmark is vendor-neutral
        (true for NIST 800-53 and ISO 27001), so it applies everywhere.
        """
        if self.vendors and vendor not in self.vendors:
            return False
        return not (self.os_families and os_family not in self.os_families)


def load_catalogs(catalog_dir: Path | None = None) -> list[ControlCatalog]:
    """Load every built catalog from disk, sorted by catalog_id.

    Returns an empty list when no catalog has been built yet; callers degrade to
    the hand-authored seed rule packs rather than failing.
    """
    base = catalog_dir or CATALOG_DIR
    if not base.exists():
        return []
    catalogs: list[ControlCatalog] = []
    for path in sorted(base.glob("*.json")):
        raw: dict[str, Any] = json.loads(path.read_text(encoding=FILE_ENCODING))
        catalogs.append(ControlCatalog.model_validate(raw))
    return catalogs


def write_catalog(catalog: ControlCatalog, catalog_dir: Path | None = None) -> Path:
    """Persist a catalog as deterministic, sorted JSON."""
    base = catalog_dir or CATALOG_DIR
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{catalog.catalog_id}.json"
    payload = catalog.model_dump(mode="json")
    out.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding=FILE_ENCODING,
    )
    return out
