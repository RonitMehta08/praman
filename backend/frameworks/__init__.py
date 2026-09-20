"""Framework catalog ingest — turns published benchmarks into a normalised catalog.

This package reads the authoritative benchmark artefacts that were downloaded by
MANUAL_COMMANDS.md (DISA XCCDF XML, CIS extracted JSON, the DISA CCI list, the
NIST/ISO OLIR crosswalk) and emits one normalised ControlCatalog per benchmark.

Nothing in this package invents a control ID, a title, a severity, or a fix.
Every field is copied verbatim from the source artefact; when a source does not
carry a field, the catalog leaves it None rather than guessing.
"""

from __future__ import annotations

from backend.frameworks.catalog import CatalogControl, ControlCatalog, load_catalogs

__all__ = ["CatalogControl", "ControlCatalog", "load_catalogs"]
