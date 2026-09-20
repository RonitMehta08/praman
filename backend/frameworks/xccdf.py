"""XCCDF 1.1 Manual STIG parser — DISA benchmark XML to ControlCatalog.

DISA publishes each STIG as an XCCDF 1.1 ``Benchmark`` whose ``Group`` elements
carry the V-ID and whose nested ``Rule`` carries the severity, the STIG ID
(``<version>``), the CCI identifiers, the check text and the fix text.

Everything this module emits is copied verbatim from the XML. The one piece of
processing is unwrapping DISA's pseudo-XML ``<VulnDiscussion>`` block, which
arrives as escaped text inside ``<description>``.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from backend.frameworks.catalog import CatalogControl, ControlCatalog

_XCCDF_NS = {
    "x11": "http://checklists.nist.gov/xccdf/1.1",
    "x12": "http://checklists.nist.gov/xccdf/1.2",
}
_CCI_SYSTEM = "http://cyber.mil/cci"
_LEGACY_SYSTEM = "http://cyber.mil/legacy"

# DISA embeds several pseudo-tags in <description>; we keep only the discussion.
_VULN_DISCUSSION_RE = re.compile(
    r"<VulnDiscussion>(?P<body>.*?)</VulnDiscussion>", re.DOTALL
)
# "U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml" -> "V3R7"
_RELEASE_RE = re.compile(r"_(V\d+R\d+)_", re.IGNORECASE)


def _parse_xml(path: Path) -> ElementTree.Element:
    """Parse local benchmark XML, preferring defusedxml when it is installed.

    These files are operator-downloaded DISA artefacts read at build time, never
    request-path input. defusedxml is used when present so the hardened path is
    the default once the optional dependency is installed.
    """
    try:  # pragma: no cover - depends on optional dependency
        from defusedxml.ElementTree import parse as safe_parse

        return safe_parse(str(path)).getroot()
    except ImportError:
        return ElementTree.parse(str(path)).getroot()


def _ns_for(root: ElementTree.Element) -> dict[str, str]:
    """Return the namespace map matching the document's XCCDF version."""
    if root.tag.startswith(f"{{{_XCCDF_NS['x12']}}}"):
        return {"x": _XCCDF_NS["x12"]}
    return {"x": _XCCDF_NS["x11"]}


def _text(element: ElementTree.Element | None) -> str:
    """Flatten an element's text content, collapsing whitespace runs."""
    if element is None:
        return ""
    joined = "".join(element.itertext())
    return re.sub(r"[ \t]+\n", "\n", joined).strip()


def _discussion(raw_description: str) -> str:
    """Pull the VulnDiscussion body out of DISA's escaped pseudo-XML."""
    match = _VULN_DISCUSSION_RE.search(raw_description)
    if match:
        return match.group("body").strip()
    return raw_description.strip()


def _release_from_filename(path: Path, fallback: str) -> str:
    """Extract the VxRy release token from a DISA filename."""
    match = _RELEASE_RE.search(path.name)
    return match.group(1).upper() if match else fallback


def _slugify(text: str) -> str:
    """Lowercase alphanumeric slug used for catalog_id."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def parse_xccdf(
    path: Path,
    *,
    vendors: list[str] | None = None,
    os_families: list[str] | None = None,
    catalog_id: str | None = None,
) -> ControlCatalog:
    """Parse one Manual STIG XCCDF file into a ControlCatalog.

    Args:
        path: Path to the ``*-xccdf.xml`` file.
        vendors: Canonical vendor enum values this benchmark governs.
        os_families: Canonical os_family values this benchmark governs.
        catalog_id: Override the derived catalog slug.

    Returns:
        A ControlCatalog whose controls preserve DISA's V-IDs, severities,
        CCI identifiers, check text and fix text verbatim.
    """
    root = _parse_xml(path)
    namespaces = _ns_for(root)

    title = _text(root.find("x:title", namespaces)) or path.stem
    plain_version = _text(root.find("x:version", namespaces))
    release = _release_from_filename(path, plain_version or "unknown")

    controls: list[CatalogControl] = []
    for group in root.findall("x:Group", namespaces):
        rule = group.find("x:Rule", namespaces)
        if rule is None:
            continue
        control_id = group.get("id") or rule.get("id") or ""
        if not control_id:
            continue

        cci: list[str] = []
        legacy: list[str] = []
        for ident in rule.findall("x:ident", namespaces):
            system = ident.get("system") or ""
            value = (ident.text or "").strip()
            if not value:
                continue
            if system == _CCI_SYSTEM:
                cci.append(value)
            elif system == _LEGACY_SYSTEM:
                legacy.append(value)

        check_element = rule.find("x:check/x:check-content", namespaces)
        if check_element is None:
            check_element = rule.find("x:check", namespaces)

        controls.append(
            CatalogControl(
                control_id=control_id,
                title=_text(rule.find("x:title", namespaces)),
                severity=rule.get("severity"),
                discussion=_discussion(_text(rule.find("x:description", namespaces))),
                check_text=_text(check_element),
                fix_text=_text(rule.find("x:fixtext", namespaces)),
                stig_id=_text(rule.find("x:version", namespaces)) or None,
                legacy_ids=sorted(legacy),
                cci=sorted(set(cci)),
            )
        )

    slug = catalog_id or f"disa_stig_{_slugify(title)}_{release.lower()}"
    return ControlCatalog(
        catalog_id=slug,
        framework="DISA_STIG",
        benchmark=title,
        benchmark_version=release,
        source_document=path.name,
        vendors=sorted(vendors or []),
        os_families=sorted(os_families or []),
        controls=controls,
    )


def find_xccdf_files(stig_root: Path) -> list[Path]:
    """Locate every Manual STIG XCCDF file beneath a STIG download directory."""
    return sorted(stig_root.rglob("*Manual-xccdf.xml"))
