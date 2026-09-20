"""OSCAL reader — NIST SP 800-53 Rev 5 catalog to ControlCatalog.

NIST publishes SP 800-53 as an OSCAL JSON catalog. Controls are grouped by
family (``ac``, ``au``, …) and each control carries a title plus ``parts`` holding
the control statement and supplemental guidance. Control enhancements appear as
nested ``controls`` (``ac-2.1``) and are ingested as first-class controls.

Two documented transformations are applied; nothing else is altered:

* Control identifiers are upper-cased and zero-padded to the project-wide
  canonical form (``ac-2.1`` becomes ``AC-02(01)``) so they join the CCI and OLIR
  crosswalks. The original OSCAL id is preserved in ``legacy_ids``.
* OSCAL organisation-defined-parameter placeholders
  (``{{ insert: param, ac-1_prm_1 }}``) are rewritten to ``[assignment:
  ac-1_prm_1]`` so the prose renders in a PDF. The parameter name is kept.

NIST 800-53 states requirements, not device commands, so ``fix_text`` stays empty:
the remediation for a NIST control is whichever vendor-specific STIG or CIS
control implements it, resolved through the crosswalk.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from backend.app.config import FILE_ENCODING
from backend.frameworks.catalog import CatalogControl, ControlCatalog
from backend.frameworks.crosswalk import normalise_control_id

_PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^}]+?)\s*\}\}")


def _resolve_placeholders(prose: str) -> str:
    """Rewrite OSCAL parameter moustaches into readable assignment markers."""
    return _PARAM_RE.sub(lambda m: f"[assignment: {m.group(1)}]", prose)


def _collect_prose(part: dict[str, Any], depth: int = 0) -> list[str]:
    """Recursively flatten an OSCAL part tree into indented prose lines."""
    lines: list[str] = []
    label = ""
    for prop in part.get("props", []):
        if prop.get("name") == "label":
            label = str(prop.get("value", "")).strip()
            break
    prose = _resolve_placeholders(str(part.get("prose", "")).strip())
    if prose:
        prefix = "  " * depth + (f"{label} " if label else "")
        lines.append(f"{prefix}{prose}")
    for child in part.get("parts", []):
        lines.extend(_collect_prose(child, depth + 1))
    return lines


def _part_text(control: dict[str, Any], name: str) -> str:
    """Flatten the named top-level part of a control."""
    for part in control.get("parts", []):
        if part.get("name") == name:
            return "\n".join(_collect_prose(part)).strip()
    return ""


def _withdrawn(control: dict[str, Any]) -> bool:
    """True when NIST has withdrawn the control (status prop)."""
    return any(
        prop.get("name") == "status" and prop.get("value") == "withdrawn"
        for prop in control.get("props", [])
    )


def _flatten_controls(
    controls: list[dict[str, Any]], out: list[CatalogControl]
) -> None:
    """Walk a control list, emitting each control and its enhancements."""
    for control in controls:
        oscal_id = str(control.get("id", "")).strip()
        if not oscal_id:
            continue
        if not _withdrawn(control):
            canonical = normalise_control_id(oscal_id.replace(".", "(") + ")") or None
            # normalise_control_id handles "ac-2(1)"; OSCAL writes "ac-2.1".
            if "." in oscal_id:
                family_number, enhancement = oscal_id.rsplit(".", 1)
                canonical = normalise_control_id(f"{family_number}({enhancement})")
            else:
                canonical = normalise_control_id(oscal_id)
            statement = _part_text(control, "statement")
            guidance = _part_text(control, "guidance")
            out.append(
                CatalogControl(
                    control_id=canonical or oscal_id.upper(),
                    title=str(control.get("title", "")).strip(),
                    severity=None,
                    discussion="\n\n".join(p for p in (statement, guidance) if p),
                    check_text=_part_text(control, "assessment-objective"),
                    fix_text="",
                    legacy_ids=[oscal_id],
                )
            )
        _flatten_controls(control.get("controls", []), out)


def parse_oscal_catalog(path: Path) -> ControlCatalog:
    """Parse the NIST OSCAL SP 800-53 catalog JSON into a ControlCatalog.

    Args:
        path: Path to ``data/frameworks/oscal/sp80053.json``.

    Returns:
        A vendor-neutral ControlCatalog containing every non-withdrawn control
        and control enhancement, with canonical ``AC-02(01)`` identifiers.
    """
    raw: dict[str, Any] = json.loads(path.read_text(encoding=FILE_ENCODING))
    catalog = raw.get("catalog", raw)
    metadata = catalog.get("metadata", {})
    version = str(metadata.get("version", "unknown"))

    controls: list[CatalogControl] = []
    for group in catalog.get("groups", []):
        _flatten_controls(group.get("controls", []), controls)

    return ControlCatalog(
        catalog_id=f"nist_800_53_rev5_{version.replace('.', '_')}",
        framework="NIST_800_53",
        benchmark="NIST SP 800-53 Revision 5",
        benchmark_version=f"Rev {version}",
        source_document=path.name,
        source_url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        vendors=[],
        os_families=[],
        controls=controls,
    )
