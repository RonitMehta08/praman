"""CIS Benchmark reader — extracted CIS JSON to ControlCatalog.

MANUAL_COMMANDS.md extracts each CIS Benchmark PDF into a JSON document with one
entry per recommendation. This module normalises those entries into the shared
catalog shape. The CIS ``section`` number is the control_id and is preserved
verbatim, as are the audit and remediation blocks.

CIS Benchmarks do not publish a severity, so ``severity`` stays None here. The
mapping pack assigns severity deliberately when it automates a control; findings
for unmapped controls carry no severity claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from backend.app.config import FILE_ENCODING
from backend.frameworks.catalog import CatalogControl, ControlCatalog


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def parse_cis_json(
    path: Path,
    *,
    vendors: list[str] | None = None,
    os_families: list[str] | None = None,
) -> ControlCatalog:
    """Parse one extracted CIS Benchmark JSON file into a ControlCatalog.

    Args:
        path: Path to a ``data/frameworks/cis/*.json`` document.
        vendors: Canonical vendor enum values this benchmark governs.
        os_families: Canonical os_family values this benchmark governs.

    Returns:
        A ControlCatalog with one CatalogControl per CIS recommendation.
    """
    raw: dict[str, Any] = json.loads(path.read_text(encoding=FILE_ENCODING))
    benchmark = raw.get("benchmark", path.stem)
    version = raw.get("benchmark_version", "unknown")

    controls: list[CatalogControl] = []
    for entry in raw.get("controls", []):
        section = str(entry.get("section") or "").strip()
        if not section:
            continue
        description = (entry.get("description") or "").strip()
        rationale = (entry.get("rationale") or "").strip()
        discussion = "\n\n".join(part for part in (description, rationale) if part)
        controls.append(
            CatalogControl(
                control_id=section,
                title=(entry.get("title") or "").strip(),
                severity=None,
                discussion=discussion,
                check_text=(entry.get("audit") or "").strip(),
                fix_text=(entry.get("remediation") or "").strip(),
                profile=entry.get("profile"),
                automated=entry.get("automated"),
                default_value=(entry.get("default_value") or "").strip(),
                impact=(entry.get("impact") or "").strip(),
            )
        )

    return ControlCatalog(
        catalog_id=f"cis_{_slugify(benchmark)}_{_slugify(version)}",
        framework="CIS",
        benchmark=f"CIS {benchmark}",
        benchmark_version=version,
        source_document=raw.get("source_document", path.name),
        source_url=raw.get("source_url", ""),
        vendors=sorted(vendors or []),
        os_families=sorted(os_families or []),
        controls=controls,
    )
