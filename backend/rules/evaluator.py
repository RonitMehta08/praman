"""Rules engine — joins the control catalog to the canonical model.

The engine evaluates a *catalog*, not a rule file. For each control the publisher
published, exactly one of four things happens:

* a mapping pack automates it and the condition decides ``pass`` / ``fail``;
* a mapping pack automates it but the config carries no evidence -> ``unknown``;
* the control is out of scope for this device's vendor -> ``notapplicable``;
* nothing automates it yet -> ``notchecked``.

That last case is the honest one that hand-written rule files quietly skipped. A
benchmark with 180 controls and 40 automated checks is 40 checks and 140
``notchecked``, and the compliance score is computed over the automated subset
only. Dropping the other 140 would inflate the score; scoring them as passes
would be a lie. ``notchecked`` is the XCCDF value that means exactly "no check
was performed", so it is the one used.

Every human-readable string on a Finding - title, severity, discussion,
official remediation, CCI and 800-53 references - is copied from the catalog,
which was parsed from the publisher's own document. The engine writes no prose of
its own (GLOBAL_RULESET R1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from backend.canonical.findings import Finding, Result
from backend.canonical.models import CanonicalFact
from backend.core_errors import RuleValidationError
from backend.frameworks.catalog import CatalogControl, ControlCatalog, load_catalogs
from backend.rules.conditions import Outcome, evaluate_condition
from backend.rules.facts import FactIndex
from backend.rules.models import Rule

# Severity assumed when neither the publisher nor the mapping pack states one.
# "unknown" is deliberately not a severity word: it renders as its own chip so a
# reader cannot mistake an unrated control for a low-risk one.
DEFAULT_SEVERITY = "unknown"

# STIG CAT levels to the shared severity vocabulary. DISA already publishes
# high/medium/low in @severity, so this only normalises the CAT spellings.
_SEVERITY_ALIASES = {
    "cat i": "high",
    "cat ii": "medium",
    "cat iii": "low",
    "critical": "high",
    "important": "medium",
    "informational": "low",
}


def normalise_severity(raw: str | None) -> str:
    """Fold publisher severity spellings into high / medium / low."""
    if not raw:
        return DEFAULT_SEVERITY
    lowered = raw.strip().lower()
    return _SEVERITY_ALIASES.get(lowered, lowered)


@dataclass(frozen=True)
class DeviceContext:
    """The device attributes that decide which controls apply."""

    vendor: str
    os_family: str
    os_version: str | None = None
    device_id: str = ""


@dataclass(frozen=True)
class EvaluationStats:
    """What the engine did, so the UI can explain the score instead of asserting it."""

    catalogs_selected: int
    catalogs_skipped: int
    controls_total: int
    controls_automated: int
    rules_loaded: int
    rules_inapplicable: int

    @property
    def automation_coverage(self) -> float:
        """Fraction of in-scope controls that have an automated check."""
        if not self.controls_total:
            return 0.0
        return self.controls_automated / self.controls_total


class RulesEvaluator:
    """Evaluates a device's canonical facts against every applicable catalog."""

    def __init__(
        self,
        catalogs: list[ControlCatalog] | None = None,
        rules: list[Rule] | None = None,
        *,
        catalog_dir: Path | None = None,
        rules_dir: Path | None = None,
    ) -> None:
        """Load catalogs and mapping packs.

        Args:
            catalogs: Pre-loaded catalogs; loaded from disk when omitted.
            rules: Pre-loaded rules; loaded from disk when omitted.
            catalog_dir: Override for the catalog directory (tests).
            rules_dir: Override for the mapping pack directory (tests).
        """
        from backend.rules.loader import load_all_rules

        self.catalogs = catalogs if catalogs is not None else load_catalogs(catalog_dir)
        self.rules = rules if rules is not None else load_all_rules(rules_dir)
        self._validate_rule_targets()
        self._by_control: dict[tuple[str, str], list[Rule]] = {}
        for rule in self.rules:
            if rule.enabled:
                key = (rule.catalog.catalog_id, rule.catalog.control_id)
                self._by_control.setdefault(key, []).append(rule)
        self.last_stats: EvaluationStats | None = None

    def _validate_rule_targets(self) -> None:
        """Reject a mapping pack that points at a control no catalog publishes.

        Catching this at load time rather than at audit time is what stops a
        typo'd control id from silently producing zero findings.
        """
        known: dict[str, set[str]] = {
            catalog.catalog_id: {c.control_id for c in catalog.controls}
            for catalog in self.catalogs
        }
        problems: list[str] = []
        for rule in self.rules:
            controls = known.get(rule.catalog.catalog_id)
            if controls is None:
                problems.append(
                    f"rule '{rule.id}' targets unknown catalog "
                    f"'{rule.catalog.catalog_id}'"
                )
            elif rule.catalog.control_id not in controls:
                problems.append(
                    f"rule '{rule.id}' targets control "
                    f"'{rule.catalog.control_id}' which is not in catalog "
                    f"'{rule.catalog.catalog_id}'"
                )
        if problems:
            raise RuleValidationError(
                "mapping pack does not match the built catalog:\n  "
                + "\n  ".join(problems[:20])
                + (f"\n  … and {len(problems) - 20} more" if len(problems) > 20 else "")
                + "\nRe-run: python scripts/build_catalog.py"
            )

    def applicable_catalogs(self, context: DeviceContext) -> list[ControlCatalog]:
        """Return the catalogs that govern this device, in deterministic order."""
        selected = [
            catalog
            for catalog in self.catalogs
            if catalog.applies_to(context.vendor, context.os_family)
        ]
        return sorted(selected, key=lambda c: (c.framework, c.catalog_id))

    def evaluate(
        self,
        facts: list[CanonicalFact],
        device_vendor: str,
        device_os_family: str,
        *,
        os_version: str | None = None,
        frameworks: list[str] | None = None,
        include_notchecked: bool = True,
        project_governance: bool = True,
    ) -> list[Finding]:
        """Evaluate one device and return findings for every requested framework.

        The technical frameworks (CIS, DISA STIG) are evaluated directly against
        the canonical facts. The governance frameworks (NIST 800-53, ISO 27001)
        are projected from those results through the published crosswalks, because
        a configuration file cannot answer an organisational control directly -
        see ``backend/rules/projection.py``.

        Args:
            facts: The device's canonical facts.
            device_vendor: Canonical Vendor value, e.g. ``cisco_ios``.
            device_os_family: Canonical OsFamily value, e.g. ``ios``.
            os_version: Parsed OS version, used by version-scoped rules.
            frameworks: Restrict to these frameworks; all four when omitted.
            include_notchecked: Emit a ``notchecked`` Finding for catalog controls
                with no automated check. Turning this off makes the audit smaller
                but also makes the coverage figure unverifiable, so it defaults on.
            project_governance: Include the projected NIST/ISO findings.

        Returns:
            Findings sorted by framework, benchmark, then control id.
        """
        from backend.rules.projection import (
            DIRECT_FRAMEWORKS,
            PROJECTED_FRAMEWORKS,
            project_all,
        )

        context = DeviceContext(
            vendor=device_vendor, os_family=device_os_family, os_version=os_version
        )
        index = FactIndex(facts)
        wanted = set(frameworks) if frameworks else None

        findings: list[Finding] = []
        selected = 0
        automated = 0
        inapplicable_rules = 0
        total_controls = 0

        for catalog in self.applicable_catalogs(context):
            if catalog.framework not in DIRECT_FRAMEWORKS:
                continue
            if wanted is not None and catalog.framework not in wanted:
                continue
            selected += 1
            for control in catalog.controls:
                total_controls += 1
                rules = self._by_control.get((catalog.catalog_id, control.control_id), [])
                usable = [
                    rule
                    for rule in rules
                    if rule.applies_to.covers(
                        context.vendor, context.os_family, context.os_version
                    )
                ]
                inapplicable_rules += len(rules) - len(usable)

                if not usable:
                    if include_notchecked:
                        findings.append(
                            self._notchecked_finding(catalog, control, bool(rules))
                        )
                    continue

                automated += 1
                findings.append(self._evaluate_control(catalog, control, usable, index))

        if project_governance:
            governance = [f for f in PROJECTED_FRAMEWORKS if wanted is None or f in wanted]
            if governance:
                findings.extend(
                    project_all(
                        findings,
                        self.catalogs,
                        frameworks=governance,
                        include_notchecked=include_notchecked,
                    )
                )

        self.last_stats = EvaluationStats(
            catalogs_selected=selected,
            catalogs_skipped=len(self.catalogs) - selected,
            controls_total=total_controls,
            controls_automated=automated,
            rules_loaded=len(self.rules),
            rules_inapplicable=inapplicable_rules,
        )
        findings.sort(key=lambda f: (f.framework, f.benchmark, _control_sort_key(f.control_id)))
        return findings

    def _evaluate_control(
        self,
        catalog: ControlCatalog,
        control: CatalogControl,
        rules: list[Rule],
        index: FactIndex,
    ) -> Finding:
        """Evaluate every rule mapped to one control and fold the outcomes.

        A control with several mapped checks is compliant only when all of them
        pass; one failure fails the control. This mirrors how a benchmark states
        a control with several requirements.
        """
        outcomes = [(rule, self._outcome_for(rule, index)) for rule in rules]

        failing = [(r, o) for r, o in outcomes if o.result is Result.FAIL]
        errored = [(r, o) for r, o in outcomes if o.result is Result.ERROR]
        unknown = [(r, o) for r, o in outcomes if o.result is Result.UNKNOWN]

        if failing:
            result = Result.FAIL
            chosen = failing
        elif errored:
            result = Result.ERROR
            chosen = errored
        elif unknown:
            result = Result.UNKNOWN
            chosen = unknown
        elif all(o.result is Result.NOTAPPLICABLE for _, o in outcomes):
            result = Result.NOTAPPLICABLE
            chosen = outcomes
        else:
            result = Result.PASS
            chosen = outcomes

        evidence: list[CanonicalFact] = []
        seen: set[tuple[str, int, str]] = set()
        for _, outcome in chosen:
            for fact in outcome.evidence:
                key = (fact.path, fact.line_start, fact.raw_text)
                if key not in seen:
                    seen.add(key)
                    evidence.append(fact)

        rule = chosen[0][0]
        severity = normalise_severity(rule.severity_override or control.severity)
        rationale = self._build_rationale(result, chosen, control)

        return Finding(
            control_id=control.control_id,
            framework=catalog.framework,
            benchmark=catalog.benchmark,
            benchmark_version=catalog.benchmark_version,
            title=control.title,
            result=result,
            severity=severity,
            evidence=evidence,
            rationale=rationale,
            remediation_ref=rule.remediation_ref,
            references=_references(catalog, control, [r for r, _ in outcomes]),
        )

    @staticmethod
    def _outcome_for(rule: Rule, index: FactIndex) -> Outcome:
        """Evaluate one rule, honouring its ``requires_paths`` precondition.

        Many benchmark controls are conditional on a feature being in use: "set
        'authentication mode md5'" is a finding on a router running EIGRP and
        meaningless on one that is not. Expressing that inside the condition
        (``any_of[count eigrp.process eq 0, …]``) makes the inapplicable case come
        back as PASS, which credits the device for a control it was never
        subject to and inflates the compliance score. ``requires_paths`` states
        the precondition outside the verdict, so a device the control does not
        reach is reported ``notapplicable`` and excluded from the ratio.

        The paths must be *observed*, not merely defaulted: a pack-level default
        is the parser saying "this feature is off", which is exactly the case
        that should not satisfy a precondition of "this feature is in use".
        """
        for path in rule.applies_to.requires_paths:
            if not any(fact.present for fact in index.get(path)):
                return Outcome(
                    Result.NOTAPPLICABLE,
                    detail=(
                        f"'{path}' is not configured on this device, so the control "
                        "does not apply"
                    ),
                )
        return evaluate_condition(rule.condition, index)

    @staticmethod
    def _build_rationale(
        result: Result, chosen: list, control: CatalogControl
    ) -> str:
        """Compose the rationale from the outcome detail and the mapping note.

        Deterministic string assembly, not generated prose: the reader is told
        what was observed and which canonical check stood in for the control.
        """
        details = "; ".join(o.detail for _, o in chosen if o.detail)
        notes = "; ".join(r.mapping_rationale for r, _ in chosen if r.mapping_rationale)
        parts = []
        if details:
            parts.append(details)
        if notes:
            parts.append(f"Check basis: {notes}")
        if result is Result.UNKNOWN:
            parts.append(
                "The configuration contains no evidence for this control, so "
                "compliance cannot be determined from the config alone."
            )
        return " ".join(parts) or control.title

    @staticmethod
    def _notchecked_finding(
        catalog: ControlCatalog, control: CatalogControl, had_scoped_out_rule: bool
    ) -> Finding:
        """Emit the honest placeholder for a control with no automated check."""
        reason = (
            "A check exists for this control but is scoped to a different "
            "platform, so it was not run on this device."
            if had_scoped_out_rule
            else "No automated check is mapped to this control yet. It requires "
            "manual review against the benchmark's check text."
        )
        return Finding(
            control_id=control.control_id,
            framework=catalog.framework,
            benchmark=catalog.benchmark,
            benchmark_version=catalog.benchmark_version,
            title=control.title,
            result=Result.NOTCHECKED,
            severity=normalise_severity(control.severity),
            evidence=[],
            rationale=reason,
            remediation_ref=None,
            references=_references(catalog, control, []),
        )


def _references(
    catalog: ControlCatalog, control: CatalogControl, rules: list[Rule]
) -> dict:
    """Assemble the cross-framework references carried on a finding."""
    references: dict = {}
    if control.cci:
        references["cci"] = control.cci
    if control.nist_800_53:
        references["nist_800_53"] = control.nist_800_53
    if control.iso_27001:
        references["iso_27001"] = control.iso_27001
    if control.stig_id:
        references["stig_id"] = control.stig_id
    if control.legacy_ids:
        references["legacy_ids"] = control.legacy_ids
    if control.profile:
        references["profile"] = control.profile
    references["catalog_id"] = catalog.catalog_id
    references["source_document"] = catalog.source_document
    if rules:
        references["rule_ids"] = sorted(rule.id for rule in rules)
    return references


def _control_sort_key(control_id: str) -> tuple:
    """Sort control ids naturally: V-215807 before V-215810, 1.2 before 1.10.

    Every segment becomes a same-shaped triple so the key is a *total* order.
    The obvious version — ``int(p) if p.isdigit() else p.lower()`` — raises
    ``TypeError: '<' not supported between instances of 'str' and 'int'`` the
    moment one benchmark mixes ``5.1`` with ``A.5.1``, which ISO 27001 does. The
    failure is not in the sort key that gets compared most often; it is in the
    one pair of ids that happen to differ in the first segment's type, so it hides
    until a particular framework combination is evaluated in one pass.
    """
    parts = _SEGMENT.split(control_id)
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part.lower())
        for part in parts
        if part
    )


#: Split an id into alternating text and digit runs, keeping both.
_SEGMENT = re.compile(r"(\d+)")


def result_value(finding: Finding | dict) -> str:
    """The ``result`` of a finding, whether it arrived as a model or a dict.

    Findings cross three boundaries in this system as three different shapes: a
    :class:`Finding` in the evaluator, a row dict out of SQLite, and JSON on the
    wire. One accessor keeps every consumer reading the same field rather than
    each re-deriving it — and re-deriving it is how a report ends up scoring
    ``Result.PASS`` and ``"pass"`` as two different outcomes.
    """
    raw = finding.get("result") if isinstance(finding, dict) else finding.result
    return raw.value if isinstance(raw, Result) else str(raw)


SCORE_BASIS = (
    "score = pass / (pass + fail) over automated checks; notchecked, "
    "notapplicable and unknown are excluded from the ratio"
)
"""The one sentence that defines the score. Printed wherever the score is."""


def score_from_counts(counts: dict[str, int]) -> float:
    """The score, from result counts alone.

    Split out from :func:`compute_compliance_score` for the one caller that has
    counts but not findings: a historical ledger row stores its ``summary`` and
    not the findings behind it, and re-reading every past audit's findings to
    plot a trend would be a table scan per point. The arithmetic must be the same
    arithmetic, so it lives in one place.
    """
    passed = int(counts.get("pass", 0) or 0)
    failed = int(counts.get("fail", 0) or 0)
    denominator = passed + failed
    return round(100.0 * passed / denominator, 1) if denominator else 0.0


def compute_compliance_score(findings: list[Finding] | list[dict]) -> dict:
    """Compute the PRAMAN compliance score and the counts that justify it.

    The score is ``pass / (pass + fail)`` over automated findings only. Controls
    that were never checked, are inapplicable, or could not be determined are
    excluded from the ratio and reported separately, because folding them in
    either direction would misstate the posture.

    Accepts findings as models or as dicts. The PDF renderer and the API both
    receive dicts, and a second implementation of the score for their benefit is
    exactly the sort of drift R9.1 exists to prevent: the number on the cover of
    a report has to be the number the engine computed.
    """
    counts: dict[str, int] = {}
    for finding in findings:
        value = result_value(finding)
        counts[value] = counts.get(value, 0) + 1

    passed = counts.get("pass", 0)
    failed = counts.get("fail", 0)

    return {
        "score": score_from_counts(counts),
        "scored_controls": passed + failed,
        "passed": passed,
        "failed": failed,
        "unknown": counts.get("unknown", 0),
        "error": counts.get("error", 0),
        "notchecked": counts.get("notchecked", 0),
        "notapplicable": counts.get("notapplicable", 0),
        "total_controls": len(findings),
        "by_result": counts,
        "basis": SCORE_BASIS,
    }
