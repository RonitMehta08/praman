"""ISO/IEC 27001:2022 catalog — derived from the NIST OLIR crosswalk.

PRAMAN ships no copy of ISO/IEC 27001:2022. The standard is sold by ISO and its
Annex A control titles are copyright ISO/IEC, so they are not redistributable and
are **not** present in any on-disk artefact: the NIST OLIR workbook names 121
distinct ISO elements and leaves every "Reference Document Element Description"
cell empty (verified: 643 relationship rows, 0 with descriptions).

Rather than invent titles, this module builds the ISO catalog from the element
identifiers the OLIR does publish. Each control carries:

* ``control_id`` — the real OLIR element identifier (``A.8.20``, ``5.2``).
* ``title`` — the citation, not the text (``ISO/IEC 27001:2022 A.8.20``).
* ``discussion`` — the list of NIST SP 800-53 controls OLIR relates to this
  element, which is the substantive, redistributable content, plus a note
  explaining why the ISO wording is absent.

ISO compliance is therefore reported as a *projection*: an ISO element's result
is rolled up from the technical findings (STIG / CIS) whose controls crosswalk to
it. See ``backend/rules/projection.py``. That is how the element earns a verdict
without PRAMAN ever asserting what the element says.
"""

from __future__ import annotations

from backend.frameworks.catalog import CatalogControl, ControlCatalog

_COPYRIGHT_NOTE = (
    "ISO/IEC 27001:2022 control text is copyright ISO/IEC and is not "
    "redistributed with this tool. Consult the purchased standard for the "
    "control wording. The relationship below is from the NIST OLIR crosswalk."
)

# Annex A theme names come from the clause numbering of ISO/IEC 27001:2022 and
# are structural, not control text. Clause-numbered elements (no "A." prefix)
# belong to the management-system clauses rather than Annex A.
_ANNEX_THEMES = {
    "5": "Annex A.5 — Organizational controls",
    "6": "Annex A.6 — People controls",
    "7": "Annex A.7 — Physical controls",
    "8": "Annex A.8 — Technological controls",
}


def _theme_for(element: str) -> str:
    """Return the Annex A theme for an element, or the clause designation."""
    if not element.upper().startswith("A."):
        return "ISO/IEC 27001:2022 management system clause"
    parts = element.split(".")
    if len(parts) >= 2:
        return _ANNEX_THEMES.get(parts[1], "Annex A")
    return "Annex A"


def _sort_key(element: str) -> tuple[int, tuple[int, ...], str]:
    """Sort A.5.1 before A.5.15 before A.6.1, clauses first."""
    is_annex = 1 if element.upper().startswith("A.") else 0
    numeric = element[2:] if is_annex else element
    parts: list[int] = []
    for chunk in numeric.split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return (is_annex, tuple(parts), element)


def build_iso_catalog(
    nist_to_iso: dict[str, list[str]], *, source_document: str
) -> ControlCatalog:
    """Build the ISO/IEC 27001:2022 catalog from the NIST-to-ISO crosswalk.

    Args:
        nist_to_iso: Mapping of canonical NIST control id to ISO element ids, as
            produced by ``crosswalk.build_nist_to_iso``.
        source_document: Filename of the OLIR workbook, recorded as provenance.

    Returns:
        A vendor-neutral ControlCatalog with one control per distinct ISO element
        named by the crosswalk. Empty when the crosswalk has not been built.
    """
    inverted: dict[str, set[str]] = {}
    for nist_control, elements in nist_to_iso.items():
        for element in elements:
            inverted.setdefault(element, set()).add(nist_control)

    controls: list[CatalogControl] = []
    for element in sorted(inverted, key=_sort_key):
        related = sorted(inverted[element])
        controls.append(
            CatalogControl(
                control_id=element,
                title=f"ISO/IEC 27001:2022 {element}",
                severity=None,
                discussion=(
                    f"{_theme_for(element)}.\n\n"
                    f"Related NIST SP 800-53 Rev 5 controls: {', '.join(related)}.\n\n"
                    f"{_COPYRIGHT_NOTE}"
                ),
                check_text=(
                    "Satisfied indirectly: verdict is rolled up from the technical "
                    "controls that crosswalk to this element."
                ),
                fix_text="",
                nist_800_53=related,
                iso_27001=[element],
            )
        )

    return ControlCatalog(
        catalog_id="iso_27001_2022_olir",
        framework="ISO_27001",
        benchmark="ISO/IEC 27001:2022",
        benchmark_version="2022",
        source_document=source_document,
        source_url="https://csrc.nist.gov/projects/olir/informative-reference-catalog",
        vendors=[],
        os_families=[],
        controls=controls,
    )
