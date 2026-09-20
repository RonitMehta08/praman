"""Machine-readable exports — OSCAL Assessment Results and SARIF.

The PDF report is for a person; these two are for a system. They answer different
questions and are deliberately fed from different places:

* :func:`to_oscal_ar` renders a **committed ledger record** into an OSCAL v1.2.3
  Assessment Results document, carrying the record hash, Merkle root and signature
  so a GRC platform holds everything it needs to ask PRAMAN's verifier whether the
  assessment it is displaying is the one that was signed. Every id derives from the
  record hash, so re-exporting one audit is byte-identical forever.
* :func:`to_sarif` renders a **simulation** into a SARIF v2.1.0 log for a CI gate,
  attaching each result to the configuration line that produced it. It carries no
  timestamps and no ledger identity, which keeps it a pure function of the config
  bytes and preserves ``/simulate``'s documented idempotence.

Both refuse to emit a schema-invalid document, raising
:class:`backend.core_errors.ExportError` instead. A platform rejecting a malformed
compliance document is a good outcome; one silently ingesting it is not.
"""

from __future__ import annotations

from backend.export.oscal import (
    AUDIT_FIELDS,
    OSCAL_AR_SCHEMA_ID,
    OSCAL_AR_SCHEMA_URL,
    OSCAL_VERSION,
    to_oscal_ar,
)
from backend.export.sarif import (
    DEVICE_FIELDS,
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    to_sarif,
)

__all__ = [
    "AUDIT_FIELDS",
    "DEVICE_FIELDS",
    "OSCAL_AR_SCHEMA_ID",
    "OSCAL_AR_SCHEMA_URL",
    "OSCAL_VERSION",
    "SARIF_SCHEMA_URL",
    "SARIF_VERSION",
    "to_oscal_ar",
    "to_sarif",
]
