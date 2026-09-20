"""Per-finding OSCAL elements: observation, finding, risk.

One PRAMAN finding becomes up to three OSCAL objects, and which ones it becomes
is decided entirely by :mod:`backend.export.oscal_mapping`. This module knows the
*shape* of each object — its required members, read from the ``v1.2.3`` schema —
and nothing about compliance semantics.

Every builder takes the same ``key``: a per-(audit, control) string the caller
composes from the ledger record hash and the control id. All three ids derive from
it, so a finding, its observation and its risk are linked by construction rather
than by a lookup that could go wrong, and re-exporting one audit reproduces every
id exactly.
"""

from __future__ import annotations

from typing import Any

from backend.canonical.findings import Finding
from backend.export.ids import deterministic_uuid, oscal_token
from backend.export.oscal_mapping import (
    IMPLEMENTATION_STATUS,
    NO_VERDICT_REMARK,
    OBJECTIVE_STATUS,
    RISK_STATUS,
    prop,
)


def evidence_text(finding: Finding) -> str:
    """The finding's evidence as one Markdown block, provenance included.

    ``observation.description`` is a MarkupMultiline, so the config line, its file
    and its line span can travel together. Without the line numbers the export
    would say what was wrong and not where, which is the difference between
    evidence and an assertion.
    """
    if not finding.evidence:
        return "No canonical facts were recorded for this control."
    lines = []
    for fact in finding.evidence:
        span = (
            f"{fact.line_start}"
            if fact.line_start == fact.line_end
            else f"{fact.line_start}-{fact.line_end}"
        )
        lines.append(
            f"- `{fact.path}` = `{fact.value!r}` "
            f"(present={fact.present}, {fact.source_file}:{span}, "
            f"parser={fact.parser_id}, confidence={fact.confidence})\n"
            f"  ```\n  {fact.raw_text}\n  ```"
        )
    return "\n".join(lines)


def observation(finding: Finding, value: str, collected: str, key: str) -> dict[str, Any]:
    """One observation. ``required: ["uuid", "description", "methods", "collected"]``.

    ``methods: ["TEST"]`` is the NIST 800-53A assessment method for reading a
    configuration and comparing it against a requirement. ``subjects`` is
    deliberately absent: a ``subject-reference`` requires a ``subject-uuid``, and
    PRAMAN declares no ``local-definitions.inventory-items`` for a device, so every
    subject reference would dangle. The device is identified in ``metadata.props``
    and in each result's description instead — an absent optional member beats a
    reference that resolves to nothing.
    """
    props = [
        prop("praman-control-id", finding.control_id),
        prop("praman-result", value),
        prop("praman-severity", finding.severity),
        prop("praman-framework", finding.framework),
        prop("praman-benchmark", f"{finding.benchmark} {finding.benchmark_version}"),
    ]
    implementation = IMPLEMENTATION_STATUS.get(value)
    if implementation:
        props.append(prop("praman-implementation-status", implementation))
    # The publishers' own crosswalk ids — CCI, NIST 800-53 — are what let a GRC
    # platform join this observation to a control it already tracks.
    for name, refs in sorted(finding.references.items()):
        if isinstance(refs, list) and refs:
            props.append(prop(f"praman-reference-{name}", ", ".join(str(r) for r in refs)))
    out: dict[str, Any] = {
        "uuid": deterministic_uuid("observation", key),
        "title": f"{finding.control_id} — {finding.title}",
        "description": f"{finding.rationale}\n\n{evidence_text(finding)}",
        "props": props,
        "methods": ["TEST"],
        "collected": collected,
    }
    remark = NO_VERDICT_REMARK.get(value)
    if remark:
        out["remarks"] = remark
    return out


def finding_element(
    finding: Finding, value: str, key: str, observation_uuid: str
) -> dict[str, Any]:
    """One AR finding. ``required: ["uuid", "title", "description", "target"]``.

    Only ever called for a result in :data:`OBJECTIVE_STATUS`. A control without a
    verdict gets an observation and no finding — see the mapping module's
    departure 1.
    """
    state, reason = OBJECTIVE_STATUS[value]
    token, adjusted = oscal_token(finding.control_id, finding.framework)
    target: dict[str, Any] = {
        "type": "objective-id",
        "target-id": token,
        "title": finding.title,
        "status": {"state": state, "reason": reason},
        "remarks": (
            f"{finding.benchmark} {finding.benchmark_version} defines one testable "
            f"objective per control, so the objective id is the control id. XCCDF "
            f"result: {value}."
            + (
                f" The published id is '{finding.control_id}'; the token above is "
                "prefixed because OSCAL's TokenDatatype forbids a leading digit."
                if adjusted
                else ""
            )
        ),
    }
    props = [prop("praman-control-id", finding.control_id), prop("praman-result", value)]
    if finding.remediation_ref:
        props.append(prop("praman-remediation-ref", finding.remediation_ref))
    out: dict[str, Any] = {
        "uuid": deterministic_uuid("finding", key),
        "title": f"{finding.control_id} — {finding.title}",
        "description": finding.rationale,
        "props": props,
        "target": target,
        "related-observations": [{"observation-uuid": observation_uuid}],
    }
    if value in RISK_STATUS:
        out["related-risks"] = [{"risk-uuid": deterministic_uuid("risk", key)}]
    return out


def risk(finding: Finding, value: str, key: str, observation_uuid: str) -> dict[str, Any]:
    """One risk. ``required: ["uuid", "title", "description", "statement", "status"]``."""
    return {
        "uuid": deterministic_uuid("risk", key),
        "title": f"{finding.control_id} — {finding.title}",
        "description": finding.rationale,
        "statement": (
            f"The device does not satisfy {finding.control_id} of "
            f"{finding.benchmark} {finding.benchmark_version}, a "
            f"{finding.severity}-severity control."
        ),
        "props": [
            prop("praman-severity", finding.severity),
            prop("praman-control-id", finding.control_id),
        ],
        "status": RISK_STATUS[value],
        "related-observations": [{"observation-uuid": observation_uuid}],
    }
