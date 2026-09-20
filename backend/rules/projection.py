"""Framework projection — NIST 800-53 and ISO 27001 verdicts from technical findings.

A router configuration cannot be audited *directly* against NIST SP 800-53 or
ISO/IEC 27001. Those catalogs state organisational requirements ("the
organization employs automated mechanisms to enforce access restrictions"), not
device commands. What is auditable is the technical benchmark - a CIS
recommendation or a DISA STIG rule - which cites the higher-level control it
implements. DISA publishes that citation as a CCI, and NIST publishes the
800-53-to-27001 relationship in the OLIR workbook.

So PRAMAN evaluates the technical frameworks and *projects* onto the governance
ones. An 800-53 control's verdict on a device is the roll-up of the STIG and CIS
findings that implement it:

* any contributing finding fails  -> ``fail`` (severity = worst contributor)
* all contributing findings pass  -> ``pass``
* contributors exist but none was decided -> ``unknown``
* no automated contributor at all -> ``notchecked``

Every projected finding cites its contributors by benchmark and control id, so
the auditor can always trace an 800-53 failure back to the exact configuration
line that caused it. Nothing here invents a verdict: the projection is arithmetic
over verdicts the deterministic engine already produced.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.canonical.findings import Finding, Result
from backend.frameworks.catalog import ControlCatalog

# Frameworks evaluated directly against the canonical model.
DIRECT_FRAMEWORKS = frozenset({"CIS", "DISA_STIG"})

# Frameworks derived from the direct ones through the published crosswalks.
PROJECTED_FRAMEWORKS = frozenset({"NIST_800_53", "ISO_27001"})

# Worst-first, so folding contributor severities keeps the highest.
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class _Contribution:
    """The technical findings that decide one governance control."""

    results: list[Result] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    evidence_count: int = 0


def _reference_key(framework: str) -> str:
    """Which Finding.references key carries this framework's control ids."""
    return "nist_800_53" if framework == "NIST_800_53" else "iso_27001"


def _roll_up(contribution: _Contribution) -> Result:
    """Fold contributor verdicts into one governance verdict."""
    results = contribution.results
    if not results:
        return Result.NOTCHECKED
    if Result.FAIL in results:
        return Result.FAIL
    if Result.PASS in results:
        return Result.PASS
    if Result.ERROR in results:
        return Result.ERROR
    if Result.UNKNOWN in results:
        return Result.UNKNOWN
    if all(r is Result.NOTAPPLICABLE for r in results):
        return Result.NOTAPPLICABLE
    return Result.NOTCHECKED


def _worst_severity(severities: list[str]) -> str:
    """Return the highest-ranked severity among the contributors."""
    if not severities:
        return "unknown"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


def project_framework(
    technical_findings: list[Finding],
    catalog: ControlCatalog,
    *,
    include_notchecked: bool = True,
) -> list[Finding]:
    """Project technical findings onto one governance catalog.

    Args:
        technical_findings: Findings from the directly-evaluated frameworks.
        catalog: The NIST 800-53 or ISO 27001 catalog supplying control titles.
        include_notchecked: Emit governance controls that no technical control
            implements. Keeping them is what makes the coverage figure checkable.

    Returns:
        One Finding per catalog control, in catalog order.
    """
    key = _reference_key(catalog.framework)
    contributions: dict[str, _Contribution] = {}

    for finding in technical_findings:
        if finding.framework in PROJECTED_FRAMEWORKS:
            continue  # never project a projection
        if finding.result is Result.NOTCHECKED:
            continue  # an unimplemented technical control decides nothing
        for control_id in finding.references.get(key, []) or []:
            contribution = contributions.setdefault(control_id, _Contribution())
            contribution.results.append(finding.result)
            contribution.citations.append(
                f"{finding.benchmark} {finding.benchmark_version} "
                f"{finding.control_id} ({finding.result.value})"
            )
            if finding.result is Result.FAIL:
                contribution.severities.append(finding.severity)
            contribution.evidence_count += len(finding.evidence)

    projected: list[Finding] = []
    for control in catalog.controls:
        contribution = contributions.get(control.control_id)
        if contribution is None:
            if not include_notchecked:
                continue
            projected.append(
                Finding(
                    control_id=control.control_id,
                    framework=catalog.framework,
                    benchmark=catalog.benchmark,
                    benchmark_version=catalog.benchmark_version,
                    title=control.title,
                    result=Result.NOTCHECKED,
                    severity="unknown",
                    evidence=[],
                    rationale=(
                        "No automated technical control on this device maps to this "
                        "control through the published crosswalk, so it requires "
                        "manual assessment."
                    ),
                    remediation_ref=None,
                    references={
                        "catalog_id": catalog.catalog_id,
                        "source_document": catalog.source_document,
                        "derivation": "crosswalk projection",
                    },
                )
            )
            continue

        result = _roll_up(contribution)
        failing = [c for c in contribution.citations if c.endswith("(fail)")]
        summary = (
            f"{len(failing)} of {len(contribution.citations)} implementing technical "
            f"control(s) fail on this device."
            if failing
            else f"All {len(contribution.citations)} implementing technical control(s) "
            f"pass on this device."
        )
        projected.append(
            Finding(
                control_id=control.control_id,
                framework=catalog.framework,
                benchmark=catalog.benchmark,
                benchmark_version=catalog.benchmark_version,
                title=control.title,
                result=result,
                severity=_worst_severity(contribution.severities),
                evidence=[],
                rationale=(
                    f"{summary} Verdict derived from the technical findings listed in "
                    f"references.implemented_by; this control is not evaluated "
                    f"directly against the configuration."
                ),
                remediation_ref=None,
                references={
                    "catalog_id": catalog.catalog_id,
                    "source_document": catalog.source_document,
                    "derivation": "crosswalk projection",
                    "implemented_by": sorted(contribution.citations),
                    "failing_contributors": sorted(failing),
                },
            )
        )
    return projected


def project_all(
    technical_findings: list[Finding],
    catalogs: list[ControlCatalog],
    *,
    frameworks: list[str] | None = None,
    include_notchecked: bool = True,
) -> list[Finding]:
    """Project onto every governance catalog present in ``catalogs``."""
    wanted = set(frameworks) if frameworks else set(PROJECTED_FRAMEWORKS)
    projected: list[Finding] = []
    for catalog in sorted(catalogs, key=lambda c: c.catalog_id):
        if catalog.framework in PROJECTED_FRAMEWORKS and catalog.framework in wanted:
            projected.extend(
                project_framework(
                    technical_findings, catalog, include_notchecked=include_notchecked
                )
            )
    return projected
