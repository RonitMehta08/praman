"""The XCCDF result enum → OSCAL Assessment Results mapping, and nothing else.

Separated from the document builder because this table *is* the argument. Every
other file in this package is plumbing; the nine rows below decide what PRAMAN
claims about a device, and they are the rows a reviewer should be able to read
without also reading a JSON assembler.

**Two documented departures from the project spec's §13.2 mapping table.**

1. §13.2 says a ``notapplicable`` result should carry
   ``implementation-status: not-applicable``. In OSCAL that field lives on
   ``finding-target``, and ``finding-target`` has ``required: ["type",
   "target-id", "status"]`` — so there is no way to attach an
   implementation-status without also asserting an Objective Status, and the only
   two states are ``satisfied`` and ``not-satisfied``. Emitting either would
   fabricate a verdict for a control nobody decided. So a non-decided result
   produces **no finding element at all**; it produces an observation whose
   ``props`` carry ``praman-result`` and, for ``notapplicable``, a
   ``praman-implementation-status`` property. The information survives; the
   fabricated verdict does not.
2. §13.1's example finding target is ``ac-6.1_obj`` — NIST's OSCAL catalog
   convention of a control objective id derived from a control id. CIS 1.1.4 and
   DISA V-215668 have no ``_obj`` twin in any published catalog, so appending one
   would invent an identifier. ``target-id`` is the control id, tokenised only
   where NCName requires it (see :mod:`backend.export.ids`), and each finding's
   ``target.remarks`` says that these benchmarks define one testable objective per
   control, which is why the two ids coincide.

Both departures serve the rule the rest of the project follows: absence of
evidence never renders as a verdict.

Every enum value here was read out of ``oscal_assessment-results_schema.json``
from the OSCAL ``v1.2.3`` release, not from memory.
"""

from __future__ import annotations

import re
from typing import Any

from backend.canonical.findings import Finding, Result
from backend.core_errors import ExportError
from backend.export.ids import PRAMAN_NS

#: The three results that produce an Objective Status, with the exact
#: ``(state, reason)`` pair each maps to. ``state`` and ``reason`` are both schema
#: enums (``satisfied|not-satisfied`` and ``pass|fail|other``) and both verified.
#: ``error`` is here on purpose: an evaluation that could not complete has *not*
#: established the objective, and ``not-satisfied``/``other`` is the direction
#: that never turns missing evidence into a pass.
OBJECTIVE_STATUS: dict[str, tuple[str, str]] = {
    Result.PASS.value: ("satisfied", "pass"),
    Result.FAIL.value: ("not-satisfied", "fail"),
    Result.FIXED.value: ("satisfied", "pass"),
    Result.ERROR.value: ("not-satisfied", "other"),
}

#: ``risk-status`` for the results that carry a risk. Enum verified: ``open``,
#: ``investigating``, ``remediating``, ``deviation-requested``,
#: ``deviation-approved``, ``closed``. Only ``fail`` and ``fixed`` produce one — a
#: passing control has no risk to track, and a risk record for one would make a
#: GRC dashboard's open-risk count meaningless.
RISK_STATUS: dict[str, str] = {
    Result.FAIL.value: "open",
    Result.FIXED.value: "closed",
}

#: ``implementation-status`` for the one non-decided result that has a real one,
#: carried as a PRAMAN property rather than the OSCAL field — departure 1.
IMPLEMENTATION_STATUS: dict[str, str] = {
    Result.NOTAPPLICABLE.value: "not-applicable",
}

#: Why each non-decided result produced no verdict, in the words a reader of the
#: exported document needs. Keyed by every XCCDF value that is not in
#: :data:`OBJECTIVE_STATUS`, so adding a tenth result value fails the
#: completeness test in ``tests/test_export_oscal.py`` rather than exporting as a
#: silent blank.
NO_VERDICT_REMARK: dict[str, str] = {
    Result.UNKNOWN.value: (
        "No verdict: the configuration contained a line no pattern pack "
        "recognised, so the control's inputs were not established. This feeds "
        "PRAMAN's operator training queue."
    ),
    Result.NOTCHECKED.value: (
        "No verdict: the control is in scope for this benchmark and PRAMAN has no "
        "deterministic rule for it. Reported rather than dropped, so the coverage "
        "figure cannot be improved by declining to check something."
    ),
    Result.NOTSELECTED.value: (
        "No verdict: the control is outside the selected baseline scope for this "
        "assessment."
    ),
    Result.NOTAPPLICABLE.value: (
        "No verdict: the control does not apply to this platform or configuration."
    ),
    Result.INFORMATIONAL.value: (
        "No verdict: the control is informational and defines nothing to satisfy."
    ),
}

#: A subset check for OSCAL's ``DateTimeWithTimezoneDatatype``. The schema's own
#: pattern also validates leap years and the exact set of real UTC offsets; this
#: enforces the part that actually goes wrong in practice — a naive timestamp with
#: no timezone at all, which the schema rejects outright.
_DATETIME_TZ = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def as_finding(item: Finding | dict[str, Any]) -> Finding:
    """A `Finding`, whether the caller had a model or a database row projection.

    ``backend.db.connection.finding_from_row`` returns a dict because the Merkle
    root was computed over dicts; the exporters want the model's typed enum.
    """
    return item if isinstance(item, Finding) else Finding.model_validate(item)


def result_value(finding: Finding) -> str:
    """`finding`'s result as a string, refusing anything outside the XCCDF enum."""
    value = finding.result.value if isinstance(finding.result, Result) else str(finding.result)
    if value not in OBJECTIVE_STATUS and value not in NO_VERDICT_REMARK:
        raise ExportError(
            f"finding for control '{finding.control_id}' has result '{value}', "
            "which is outside the XCCDF 9-value enum. Every result must map to "
            "either an OSCAL Objective Status or a documented no-verdict "
            "observation; refusing to guess."
        )
    return value


def require_timestamp(value: str, field: str) -> str:
    """`value` if OSCAL would accept it as a timestamp, else a loud failure."""
    if not _DATETIME_TZ.match(value or ""):
        raise ExportError(
            f"{field} is '{value}', which OSCAL's DateTimeWithTimezoneDatatype "
            "rejects — it requires a timezone. Emitting it would produce a "
            "document a GRC platform accepts and then misdates."
        )
    return value


def prop(name: str, value: str) -> dict[str, str]:
    """One OSCAL property. ``required: ["name", "value"]``, both verified."""
    return {"name": name, "ns": PRAMAN_NS, "value": value}
