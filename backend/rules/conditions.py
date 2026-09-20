"""Condition evaluation — pure, deterministic, no model in the path.

Every function here is a pure function of ``(condition, FactIndex)``. Same inputs
give the same ``Outcome`` byte-for-byte, which is what
``tests/test_simulate_idempotent.py`` proves. No network, no clock, no LLM
(GLOBAL_RULESET R4.1).

The tri-state contract, in one place:

* ``pass`` - the condition was decided and satisfied.
* ``fail`` - the condition was decided and violated.
* ``unknown`` - the parser produced no evidence at the path, and the rule did not
  declare what absence means. This is *not* a pass. Reporting it as one is the
  single most dangerous failure mode a compliance tool can have (R4.2).
* ``error`` - the condition itself is malformed (bad regex, non-numeric
  comparison against a string). The rule is at fault, not the device, and the
  message says which so it can be fixed rather than silently swallowed.

Evidence is a list of the facts that decided the outcome - the failing ones when
the outcome is a failure, so the report cites the offending line and not an
arbitrary first match.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from backend.canonical.findings import Result
from backend.canonical.models import CanonicalFact
from backend.rules.facts import FactIndex
from backend.rules.models import (
    AllOf,
    AnyOf,
    Condition,
    CountCondition,
    ForEachCondition,
    LeafCondition,
    NoneOf,
    OnMissing,
    Operator,
    PresenceCondition,
)

_MISSING_TO_RESULT: dict[OnMissing, Result] = {
    OnMissing.unknown: Result.UNKNOWN,
    OnMissing.fail: Result.FAIL,
    OnMissing.pass_: Result.PASS,
    OnMissing.notapplicable: Result.NOTAPPLICABLE,
}

# Regexes are compiled once per pattern for the life of the process; a rule pack
# reuses the same handful of patterns across thousands of facts.
_REGEX_CACHE: dict[tuple[str, bool], re.Pattern[str]] = {}


class Outcome:
    """The result of evaluating one condition, with the evidence that decided it."""

    __slots__ = ("detail", "evidence", "result")

    def __init__(
        self,
        result: Result,
        evidence: Iterable[CanonicalFact] = (),
        detail: str = "",
    ) -> None:
        self.result = result
        self.evidence: list[CanonicalFact] = list(evidence)
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Outcome({self.result.value}, {len(self.evidence)} evidence, {self.detail!r})"


class ConditionError(Exception):
    """A condition cannot be evaluated because the rule is malformed."""


def _compile(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    """Compile and cache a rule regex, reporting a bad pattern as a rule fault."""
    key = (pattern, case_sensitive)
    compiled = _REGEX_CACHE.get(key)
    if compiled is None:
        try:
            compiled = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise ConditionError(f"invalid regex {pattern!r}: {exc}") from exc
        _REGEX_CACHE[key] = compiled
    return compiled


def _normalise(value: Any, case_sensitive: bool) -> Any:
    """Fold string case when the condition asked for case-insensitive matching."""
    if case_sensitive:
        return value
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, (list, tuple)):
        return [v.lower() if isinstance(v, str) else v for v in value]
    return value


def _as_number(value: Any, operator: Operator) -> float:
    """Coerce a value for an ordered comparison, or say why it cannot be."""
    if isinstance(value, bool):
        raise ConditionError(
            f"operator '{operator.value}' needs a number but got a boolean; "
            "use 'eq' for boolean settings"
        )
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError as exc:
            raise ConditionError(
                f"operator '{operator.value}' needs a number but got {value!r}"
            ) from exc
    raise ConditionError(
        f"operator '{operator.value}' needs a number but got {type(value).__name__}"
    )


def _as_set(value: Any) -> set[Any]:
    """Coerce a value to a set for the set-algebra operators."""
    if isinstance(value, (list, tuple, set, frozenset)):
        return set(value)
    if isinstance(value, str):
        return {token for token in re.split(r"[,\s]+", value.strip()) if token}
    return {value}


def compare(actual: Any, operator: Operator, expected: Any, case_sensitive: bool) -> bool:
    """Apply one operator. Raises ConditionError when the rule is malformed."""
    left = _normalise(actual, case_sensitive)
    right = _normalise(expected, case_sensitive)

    if operator is Operator.eq:
        return bool(left == right)
    if operator is Operator.ne:
        return bool(left != right)
    if operator in (Operator.gt, Operator.gte, Operator.lt, Operator.lte):
        a, b = _as_number(left, operator), _as_number(right, operator)
        if operator is Operator.gt:
            return a > b
        if operator is Operator.gte:
            return a >= b
        if operator is Operator.lt:
            return a < b
        return a <= b
    if operator is Operator.in_:
        return left in _as_set(right)
    if operator is Operator.not_in:
        return left not in _as_set(right)
    if operator is Operator.contains:
        if isinstance(left, str):
            return str(right) in left
        return right in _as_set(left)
    if operator is Operator.not_contains:
        if isinstance(left, str):
            return str(right) not in left
        return right not in _as_set(left)
    if operator is Operator.regex_match:
        return bool(_compile(str(expected), case_sensitive).search(str(actual)))
    if operator is Operator.regex_not_match:
        return not _compile(str(expected), case_sensitive).search(str(actual))
    if operator is Operator.subset_of:
        return _as_set(left) <= _as_set(right)
    if operator is Operator.superset_of:
        return _as_set(left) >= _as_set(right)
    if operator is Operator.disjoint_from:
        return _as_set(left).isdisjoint(_as_set(right))
    raise ConditionError(f"unsupported operator {operator!r}")


def _evaluate_leaf(condition: LeafCondition, index: FactIndex) -> Outcome:
    """Compare the facts at one path against the expected value."""
    facts = index.get(condition.path)
    if not facts:
        return Outcome(
            _MISSING_TO_RESULT[condition.on_missing],
            detail=f"no evidence at '{condition.path}'",
        )

    satisfied: list[CanonicalFact] = []
    violating: list[CanonicalFact] = []
    for fact in facts:
        if compare(fact.value, condition.operator, condition.expected, condition.case_sensitive):
            satisfied.append(fact)
        else:
            violating.append(fact)

    expectation = f"{condition.path} {condition.operator.value} {condition.expected!r}"
    if condition.quantifier == "any":
        if satisfied:
            return Outcome(Result.PASS, satisfied[:1], f"{expectation} satisfied")
        return Outcome(Result.FAIL, violating, f"no fact satisfies {expectation}")

    if violating:
        return Outcome(Result.FAIL, violating, f"{len(violating)} fact(s) violate {expectation}")
    return Outcome(Result.PASS, satisfied, f"{expectation} satisfied")


def _evaluate_presence(condition: PresenceCondition, index: FactIndex) -> Outcome:
    """Decide a condition that only cares whether the path was observed."""
    facts = index.get(condition.path)
    if condition.must_be_present:
        if facts:
            return Outcome(Result.PASS, facts[:1], f"'{condition.path}' is configured")
        return Outcome(Result.FAIL, detail=f"'{condition.path}' is not configured")
    if facts:
        return Outcome(
            Result.FAIL, facts, f"'{condition.path}' is configured but must not be"
        )
    return Outcome(Result.PASS, detail=f"'{condition.path}' is absent as required")


def _evaluate_count(condition: CountCondition, index: FactIndex) -> Outcome:
    """Compare the number of facts at a path against a threshold."""
    facts = index.get(condition.path)
    actual = len(facts)
    ok = compare(actual, condition.operator, condition.expected, True)
    detail = (
        f"{actual} fact(s) at '{condition.path}', "
        f"expected {condition.operator.value} {condition.expected}"
    )
    return Outcome(Result.PASS if ok else Result.FAIL, facts, detail)


def _evaluate_for_each(condition: ForEachCondition, index: FactIndex) -> Outcome:
    """Evaluate the sub-condition once per configuration block."""
    blocks = index.blocks(condition.block)
    if condition.skip_block_regex:
        pattern = _compile(condition.skip_block_regex, False)
        blocks = [block for block in blocks if not pattern.search(block.label)]
    if not blocks:
        return Outcome(
            _MISSING_TO_RESULT[condition.on_no_blocks],
            detail=f"no '{condition.block}' blocks in this configuration",
        )

    failing_evidence: list[CanonicalFact] = []
    failing_labels: list[str] = []
    unknown_labels: list[str] = []
    for block in blocks:
        sub_index = FactIndex(block.facts)
        outcome = evaluate_condition(condition.condition, sub_index)
        if outcome.result is Result.FAIL:
            failing_labels.append(block.label)
            failing_evidence.extend(outcome.evidence or [block.anchor])
        elif outcome.result in (Result.UNKNOWN, Result.ERROR):
            unknown_labels.append(block.label)

    if failing_labels:
        return Outcome(
            Result.FAIL,
            failing_evidence,
            f"{len(failing_labels)} of {len(blocks)} block(s) violate the condition: "
            + ", ".join(failing_labels[:8])
            + ("…" if len(failing_labels) > 8 else ""),
        )
    if unknown_labels:
        return Outcome(
            Result.UNKNOWN,
            detail=f"{len(unknown_labels)} of {len(blocks)} block(s) lack evidence",
        )
    return Outcome(
        Result.PASS,
        [block.anchor for block in blocks],
        f"all {len(blocks)} block(s) satisfy the condition",
    )


def _combine(outcomes: list[Outcome], mode: str) -> Outcome:
    """Fold sub-outcomes for all_of / any_of / none_of.

    UNKNOWN is contagious in ``all_of``: if one component of a conjunction cannot
    be determined, the conjunction cannot be either, unless another component
    already fails outright - a definite failure is still a failure.
    """
    if any(o.result is Result.ERROR for o in outcomes):
        errored = [o for o in outcomes if o.result is Result.ERROR]
        return Outcome(Result.ERROR, detail="; ".join(o.detail for o in errored))

    failures = [o for o in outcomes if o.result is Result.FAIL]
    passes = [o for o in outcomes if o.result is Result.PASS]
    unknowns = [o for o in outcomes if o.result is Result.UNKNOWN]
    inapplicable = [o for o in outcomes if o.result is Result.NOTAPPLICABLE]

    if mode == "all_of":
        if failures:
            evidence = [f for o in failures for f in o.evidence]
            return Outcome(Result.FAIL, evidence, "; ".join(o.detail for o in failures))
        if unknowns:
            return Outcome(Result.UNKNOWN, detail="; ".join(o.detail for o in unknowns))
        if not passes and inapplicable:
            return Outcome(Result.NOTAPPLICABLE, detail="every component is inapplicable")
        return Outcome(
            Result.PASS,
            [f for o in passes for f in o.evidence],
            "; ".join(o.detail for o in passes),
        )

    if mode == "any_of":
        if passes:
            return Outcome(
                Result.PASS, passes[0].evidence, f"satisfied by: {passes[0].detail}"
            )
        if unknowns:
            return Outcome(Result.UNKNOWN, detail="; ".join(o.detail for o in unknowns))
        if failures:
            evidence = [f for o in failures for f in o.evidence]
            return Outcome(
                Result.FAIL,
                evidence,
                "no alternative is satisfied: " + "; ".join(o.detail for o in failures),
            )
        return Outcome(Result.NOTAPPLICABLE, detail="every alternative is inapplicable")

    # none_of
    if passes:
        evidence = [f for o in passes for f in o.evidence]
        return Outcome(
            Result.FAIL,
            evidence,
            "prohibited configuration present: " + "; ".join(o.detail for o in passes),
        )
    if unknowns:
        return Outcome(Result.UNKNOWN, detail="; ".join(o.detail for o in unknowns))
    return Outcome(Result.PASS, detail="no prohibited configuration found")


def evaluate_condition(condition: Condition, index: FactIndex) -> Outcome:
    """Evaluate any condition against one device's facts.

    A malformed rule yields ``Result.ERROR`` carrying the reason, rather than an
    exception that would abort the whole audit or a swallowed failure that would
    look like a pass.
    """
    try:
        if isinstance(condition, LeafCondition):
            return _evaluate_leaf(condition, index)
        if isinstance(condition, PresenceCondition):
            return _evaluate_presence(condition, index)
        if isinstance(condition, CountCondition):
            return _evaluate_count(condition, index)
        if isinstance(condition, ForEachCondition):
            return _evaluate_for_each(condition, index)
        if isinstance(condition, AllOf):
            return _combine(
                [evaluate_condition(c, index) for c in condition.conditions], "all_of"
            )
        if isinstance(condition, AnyOf):
            return _combine(
                [evaluate_condition(c, index) for c in condition.conditions], "any_of"
            )
        if isinstance(condition, NoneOf):
            return _combine(
                [evaluate_condition(c, index) for c in condition.conditions], "none_of"
            )
    except ConditionError as exc:
        return Outcome(Result.ERROR, detail=str(exc))
    return Outcome(Result.ERROR, detail=f"unsupported condition type {type(condition).__name__}")
