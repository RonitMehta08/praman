"""PRAMAN Findings and AuditRecord models.

Finding: one per (control × device).
AuditRecord: immutable, one per committed audit — the ledger row.

Field names are FROZEN (SPINE). Result uses the XCCDF 9-value enum ONLY.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict

from backend.canonical.models import CanonicalFact


class Result(str, Enum):
    """XCCDF 9-value result enum — the ONLY allowed Finding.result values (SPINE).

    pass/fail come only from the deterministic rules engine.
    unknown feeds the training GUI when a line was unparsed.
    Never invent a boolean; never invent a 10th value.
    """

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOTAPPLICABLE = "notapplicable"
    NOTCHECKED = "notchecked"
    NOTSELECTED = "notselected"
    INFORMATIONAL = "informational"
    FIXED = "fixed"


class Framework(str, Enum):
    """The four supported compliance frameworks (SPINE)."""

    CIS = "CIS"
    NIST_800_53 = "NIST_800_53"
    DISA_STIG = "DISA_STIG"
    ISO_27001 = "ISO_27001"


class Finding(BaseModel):
    """One per (control × device).

    result is set ONLY by the deterministic rules engine.
    rationale may be LLM-drafted prose but NEVER changes result.
    remediation_ref is an id into backend/remediation/ — never free-form CLI.
    """

    model_config = ConfigDict(extra="forbid")

    control_id: str  # framework-native id, verbatim (e.g. "V-215823", "ac-3", "1.1.4")
    framework: str  # CIS | NIST_800_53 | DISA_STIG | ISO_27001
    benchmark: str  # e.g. "CIS Cisco IOS 15", "Cisco IOS XE Router NDM STIG"
    benchmark_version: str  # e.g. "v4.1.1", "V3R7" — REQUIRED
    title: str
    result: Result  # XCCDF 9-value enum ONLY
    severity: str  # high | medium | low (STIG: high=CAT I, medium=CAT II, low=CAT III)
    evidence: list[CanonicalFact]  # what was observed
    rationale: str  # plain-English, may be LLM-drafted; NEVER changes result
    remediation_ref: str | None = None  # id into the remediation module
    references: dict[str, Any] = {}  # {"nist_800_53": ["AC-3"], "cci": ["CCI-000213"]}


class AuditRecord(BaseModel):
    """Immutable, one per committed audit.

    The model is frozen=True — no mutation after construction.
    Fields seq, prev_hash, record_hash, merkle_root, signature form the
    tamper-evident hash chain.

    ``actor`` is inside the record rather than in a side table, and that
    placement is the entire point. It is listed in
    ``backend.ledger.chain.RECORD_HASH_FIELDS``, so it is covered by
    ``record_hash`` and therefore by the Ed25519 signature over it: rewriting who
    ran an audit breaks the same chain that rewriting a verdict breaks, and the
    standalone verifier reports it. An ``audit_actors`` table alongside the ledger
    would have been editable without breaking anything, which is another way of
    saying it would not have been evidence. ``docs/SECURITY.md`` §1 puts it as a
    ledger that proves what was decided but not who decided it being only half an
    audit trail.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: str
    device_id: str
    config_hash: str  # binds the record to exact bytes audited
    created_at: str
    actor: str  # the operator who committed it — see below
    findings: list[Finding]
    summary: dict[str, Any]  # counts by result and severity
    seq: int  # position in the append-only ledger
    prev_hash: str  # hash of previous AuditRecord's canonical bytes ("" for genesis)
    record_hash: str  # sha256 over RECORD_HASH_FIELDS (see backend/ledger/chain.py)
    merkle_root: str  # Merkle root over findings (backend/ledger/chain.py, in-repo)
    signature: str  # Ed25519 over record_hash (cryptography)


#: Results whose severity represents actual risk. The severity of a control that
#: *passed* is the severity it would have had — counting it as risk inflates the
#: total by every control the device got right, which reads as the opposite of
#: what happened. Kept identical to ``_SEVERITY_IS_RISK`` in backend/report/render.py.
SEVERITY_IS_RISK = frozenset({"fail", "error"})


def build_summary(findings: list[Finding]) -> dict[str, Any]:
    """Build the summary dict with counts by result and severity.

    ``by_severity`` counts **every** finding, including passes and the
    ``notchecked`` majority. That is the right shape for "how is this catalog
    weighted" and the wrong shape for "how bad is this device" — charting it
    labels the severity of things that passed as though it were risk, which on
    the shipped estate turns 372 failures into 16,082 apparent findings.

    ``by_severity_failing`` is the one a risk chart wants, so callers do not have
    to know that distinction to get it right. Both are published because the
    ledger record is hashed over this dict and is read back years later: dropping
    the broad count to avoid the mistake would break every historical record's
    hash, and leaving only the broad count is what caused the mistake.
    """
    by_result: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_severity_failing: dict[str, int] = {}
    for f in findings:
        result_val = f.result.value if isinstance(f.result, Result) else f.result
        by_result[result_val] = by_result.get(result_val, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        if result_val in SEVERITY_IS_RISK:
            by_severity_failing[f.severity] = by_severity_failing.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_result": by_result,
        "by_severity": by_severity,
        "by_severity_failing": by_severity_failing,
    }
