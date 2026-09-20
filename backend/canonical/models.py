"""PRAMAN Canonical Model — the vendor-neutral Security Baseline Model.

Field names are FROZEN (SPINE). Do not add, drop, or rename any field.
This file is the ONE seam in the system: vendor parsers write to it,
framework rules read from it, and nothing else crosses the boundary.

Python 3.10.11 — do NOT use enum.StrEnum (3.11+).
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict


class Vendor(str, Enum):
    """Canonical vendor enum = netmiko device_type vocabulary (SPINE).

    Extend by adding a parser under backend/ingest/ — NEVER by editing a rule.
    """

    cisco_ios = "cisco_ios"
    cisco_xe = "cisco_xe"
    cisco_nxos = "cisco_nxos"
    cisco_xr = "cisco_xr"
    cisco_asa = "cisco_asa"
    juniper_junos = "juniper_junos"
    paloalto_panos = "paloalto_panos"
    fortinet = "fortinet"
    arista_eos = "arista_eos"


class OsFamily(str, Enum):
    """os_family enum (SPINE)."""

    ios = "ios"
    iosxe = "iosxe"
    nxos = "nxos"
    iosxr = "iosxr"
    asa = "asa"
    junos = "junos"
    panos = "panos"
    fortios = "fortios"
    eos = "eos"


class CanonicalFact(BaseModel):
    """One per evaluated leaf. Carries provenance ALWAYS (SPINE).

    The mandatory six-field provenance:
    - source_file: which uploaded config the fact came from
    - line_start: first line number of the evidence span (1-indexed)
    - line_end: last line number of the evidence span (>= line_start)
    - raw_text: verbatim offending/relevant config line(s), never paraphrased
    - parser_id: which parser produced it, pinned (e.g. "netutils.cisco_ios@1.18.0")
    - confidence: 1.0 for deterministic parse; <1.0 ONLY when AI-classified
    """

    model_config = ConfigDict(extra="forbid")

    path: str  # dotted canonical field path, e.g. "mgmt.ssh.version"
    value: Any  # normalised value (bool | str | int | list)
    present: bool  # was the underlying config line found at all
    # --- the mandatory six-field provenance ---
    source_file: str
    line_start: int
    line_end: int
    raw_text: str  # verbatim offending/relevant config line(s)
    parser_id: str  # e.g. "netutils.cisco_ios@1.18.0"
    confidence: float  # 1.0 for deterministic parse; <1.0 only when AI-classified


class Device(BaseModel):
    """One device record, produced by a vendor parser from config + show-version.

    serials and hardware are list[str] because ntc-templates returns lists
    (stacked chassis / virtual chassis expose multiple serial numbers).
    Keep serials=[] / hardware=[] when nothing was parsed — never None, never "".
    """

    model_config = ConfigDict(extra="forbid")

    device_id: str  # stable slug, e.g. "core-sw-01"
    vendor: Vendor  # canonical vendor enum (str value on the wire)
    os_family: OsFamily
    hostname: str | None = None
    serials: list[str]  # LISTS — ntc-templates returns lists / stacked chassis
    hardware: list[str]  # e.g. ["WS-C2960-24TT-L"]
    os_version: str | None = None  # e.g. "15.0(2)SE11" — from show version parse
    source_file: str
    config_hash: str  # "sha256:<hex>" over the normalised config bytes
    ingested_at: str  # ISO-8601 UTC


# --- Mapping helpers ---

VENDOR_TO_OS_FAMILY: dict[Vendor, OsFamily] = {
    Vendor.cisco_ios: OsFamily.ios,
    Vendor.cisco_xe: OsFamily.iosxe,
    Vendor.cisco_nxos: OsFamily.nxos,
    Vendor.cisco_xr: OsFamily.iosxr,
    Vendor.cisco_asa: OsFamily.asa,
    Vendor.juniper_junos: OsFamily.junos,
    Vendor.paloalto_panos: OsFamily.panos,
    Vendor.fortinet: OsFamily.fortios,
    Vendor.arista_eos: OsFamily.eos,
}


def compute_config_hash(raw_bytes: bytes) -> str:
    """Compute sha256 hash over NFKC-normalised config bytes (SPINE)."""
    normalised = unicodedata.normalize("NFKC", raw_bytes.decode("utf-8"))
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
