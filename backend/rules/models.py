"""Rule model — rules are data, this module only gives that data a shape.

A rule is a *mapping*, not a control. It says "this canonical-model condition
decides benchmark X control Y for these vendors". Everything a human reads in the
report - title, severity, discussion, check text, official remediation - comes
from the control catalog built from the publisher's own document
(``backend/frameworks/``). A rule that carried its own title could disagree with
the benchmark it claims to implement, so ``Rule`` has no title field:
``RulesEvaluator`` resolves it through ``catalog_ref`` at load time.

Three things separate this from the seed rules it replaces:

* ``applies_to`` — a rule is scoped to the vendors and OS families whose
  benchmark it came from. Running a Cisco IOS 15 CIS check against a Junos config
  produced a meaningless verdict before; now it produces ``notapplicable``.
* Compound conditions — ``all_of`` / ``any_of`` / ``none_of`` / ``for_each`` /
  ``count``, so a control that needs two settings together stops needing two
  rules that each half-report it.
* Tri-state is explicit per condition. ``on_missing`` states what the absence of
  evidence means for *this* control; the default is ``unknown``, never ``pass``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.canonical.models import OsFamily, Vendor
from backend.canonical.paths import is_canonical_path


class Operator(str, Enum):
    """Comparison operators available to a leaf condition."""

    eq = "eq"
    ne = "ne"
    gt = "gt"
    gte = "gte"
    lt = "lt"
    lte = "lte"
    in_ = "in"
    not_in = "not_in"
    contains = "contains"
    not_contains = "not_contains"
    regex_match = "regex_match"
    regex_not_match = "regex_not_match"
    subset_of = "subset_of"
    superset_of = "superset_of"
    disjoint_from = "disjoint_from"


class OnMissing(str, Enum):
    """What the absence of any fact at the condition's path means.

    ``unknown`` is the default and the only safe default: a parser that produced
    nothing has told us nothing. ``fail`` is correct when the benchmark requires
    a setting to be present - a missing ``login banner`` *is* a finding. ``pass``
    is correct only for controls satisfied by absence, and even then prefer
    ``none_of`` which says so structurally.
    """

    unknown = "unknown"
    fail = "fail"
    pass_ = "pass"
    notapplicable = "notapplicable"


class Applicability(BaseModel):
    """Which devices a rule may be evaluated against.

    Empty ``vendors`` means vendor-neutral, which is correct for the DISA SRGs.
    Anything else restricts the rule; a device outside the scope yields
    ``notapplicable`` rather than a guess.
    """

    model_config = ConfigDict(extra="forbid")

    vendors: list[Vendor] = Field(default_factory=list)
    os_families: list[OsFamily] = Field(default_factory=list)
    os_version_regex: str | None = None
    # Canonical paths that must have been *observed* on the device for the rule
    # to apply at all. This is how a feature-conditional control ("set EIGRP
    # authentication") reports notapplicable on a device not running the feature
    # instead of passing it. Enforced in RulesEvaluator._outcome_for.
    requires_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_requires_paths(self) -> Applicability:
        """Reject a non-canonical precondition path.

        A typo here is silent and total: no fact ever appears at a misspelled
        path, so every rule carrying it reports notapplicable on every device and
        the control quietly stops being audited. Failing at load time is the only
        way that mistake gets noticed.
        """
        unknown = [p for p in self.requires_paths if not is_canonical_path(p)]
        if unknown:
            raise ValueError(
                f"requires_paths contains non-canonical path(s): {unknown}. A "
                "misspelled precondition silently disables the rule on every "
                "device, so it is rejected here."
            )
        return self

    def covers(self, vendor: str, os_family: str, os_version: str | None) -> bool:
        """True when this rule may be evaluated against the given device."""
        if self.vendors and vendor not in {v.value for v in self.vendors}:
            return False
        if self.os_families and os_family not in {o.value for o in self.os_families}:
            return False
        if self.os_version_regex:
            import re

            if not os_version or not re.search(self.os_version_regex, os_version):
                return False
        return True


class LeafCondition(BaseModel):
    """Compare the value(s) at one canonical path against an expected value."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["fact_check"] = "fact_check"
    path: str
    operator: Operator = Operator.eq
    expected: Any = None
    on_missing: OnMissing = OnMissing.unknown
    # When a path holds several facts (many VTY lines, many ACL entries), decide
    # whether every one must satisfy the comparison or only one of them.
    quantifier: Literal["all", "any"] = "all"
    case_sensitive: bool = True

    @model_validator(mode="after")
    def _validate_path(self) -> LeafCondition:
        if not is_canonical_path(self.path):
            raise ValueError(
                f"'{self.path}' is not in the canonical path vocabulary. "
                "Add it to backend/canonical/schema/canonical_paths.schema.json "
                "and emit it from a parser first."
            )
        return self


class PresenceCondition(BaseModel):
    """Assert that a path has, or has not, been observed at all."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["presence"] = "presence"
    path: str
    must_be_present: bool = True

    @model_validator(mode="after")
    def _validate_path(self) -> PresenceCondition:
        if not is_canonical_path(self.path):
            raise ValueError(f"'{self.path}' is not in the canonical path vocabulary.")
        return self


class CountCondition(BaseModel):
    """Compare how many facts exist at a path against a threshold."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["count"] = "count"
    path: str
    operator: Operator = Operator.gte
    expected: int = 1

    @model_validator(mode="after")
    def _validate_path(self) -> CountCondition:
        if not is_canonical_path(self.path):
            raise ValueError(f"'{self.path}' is not in the canonical path vocabulary.")
        return self


class ForEachCondition(BaseModel):
    """Evaluate a condition once per configuration block.

    ``block`` names the canonical path a block's anchor fact is emitted at -
    ``interface.name``, ``line.vty.id``, ``acl.name``. Which paths qualify is
    decided by the pattern pack that declared the block, not by a list in Python;
    see ``rules.facts.is_block_anchor``. The rule fails when any block fails, and
    the evidence names the offending blocks only - which is what makes
    per-interface remediation possible.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["for_each"] = "for_each"
    block: str
    condition: Condition
    # Blocks whose anchor text matches this regex are skipped (loopbacks, Null0).
    skip_block_regex: str | None = None
    on_no_blocks: OnMissing = OnMissing.notapplicable


class AllOf(BaseModel):
    """Every sub-condition must pass."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["all_of"] = "all_of"
    conditions: list[Condition] = Field(min_length=1)


class AnyOf(BaseModel):
    """At least one sub-condition must pass."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["any_of"] = "any_of"
    conditions: list[Condition] = Field(min_length=1)


class NoneOf(BaseModel):
    """No sub-condition may pass — the structural form of "must not be configured"."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["none_of"] = "none_of"
    conditions: list[Condition] = Field(min_length=1)


Condition = Union[
    LeafCondition,
    PresenceCondition,
    CountCondition,
    ForEachCondition,
    AllOf,
    AnyOf,
    NoneOf,
]

ForEachCondition.model_rebuild()
AllOf.model_rebuild()
AnyOf.model_rebuild()
NoneOf.model_rebuild()


class CatalogRef(BaseModel):
    """Points a rule at the catalog control it automates.

    This is the anti-fabrication seam: the rule supplies the check, the catalog
    supplies every word the auditor reads.
    """

    model_config = ConfigDict(extra="forbid")

    catalog_id: str
    control_id: str


class Rule(BaseModel):
    """One automated check against one catalog control."""

    model_config = ConfigDict(extra="forbid")

    id: str
    catalog: CatalogRef
    condition: Condition = Field(discriminator="type")
    applies_to: Applicability = Field(default_factory=Applicability)
    # Overrides the catalog severity. Only set it where the publisher supplies
    # none (CIS) — never to disagree with a publisher that does.
    severity_override: str | None = None
    # Names a remediation template in backend/remediation/. Absent means the
    # catalog's own fix_text is the remediation.
    remediation_ref: str | None = None
    # Free-text note about the mapping decision, shown in the report as the
    # reason this canonical check stands in for the control.
    mapping_rationale: str = ""
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True

    def referenced_paths(self) -> set[str]:
        """Every canonical path this rule reads, for coverage reporting."""
        return _collect_paths(self.condition)


def _collect_paths(condition: Condition) -> set[str]:
    """Walk a condition tree collecting every canonical path it reads."""
    if isinstance(condition, (LeafCondition, PresenceCondition, CountCondition)):
        return {condition.path}
    if isinstance(condition, ForEachCondition):
        return {condition.block} | _collect_paths(condition.condition)
    paths: set[str] = set()
    for child in condition.conditions:
        paths |= _collect_paths(child)
    return paths
