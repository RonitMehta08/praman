"""Mapping-pack invariants — the tests that make a rule pack safe to edit.

A mapping pack is hand-authored YAML that decides whether a real device is
reported compliant, so the properties the rest of the system assumes about it
cannot live in a reviewer's head. Each test here corresponds to a defect class
that was found by inspection once and must never be found by inspection again.

The two headline tests are the compliance poles, and they are the only tests in
the suite that can catch a *wrong verdict* rather than a crash:

* ``fully_hardened.conf`` satisfies the published remediation text for every
  control the engine claims to automate, so every FAIL it produces is a false
  positive. False positives are what end an auditor's trust in a tool. The one
  documented exception is ``PLATFORM_PERMANENT_FINDINGS`` below.
* ``fully_noncompliant.conf`` violates all of them, so every PASS it produces is
  a false negative. False negatives outrank false positives in this project's
  policy, because a missed finding leaves a device exposed while the report says
  it is fine.

Both poles are evaluated against *every* direct framework, not just CIS. A pole
test that covered one pack while another shipped unguarded would be the more
dangerous state of the two: it reads as coverage while the newest and least
reviewed rules are the ones nobody is checking for wrong verdicts.

A ``notapplicable`` on either pole is a third kind of failure worth naming: it
means the fixture did not manage to express the control's applicable case at all,
so the rule is untested in that direction. Both poles therefore assert zero
notapplicable rather than merely "no wrong verdicts".

This module deliberately does not assert exact scores for the realistic
fixtures. A score is a function of the fixture and the pack together, so pinning
it would make every legitimate new rule a test failure; the poles pin correctness
and ``test_every_control_is_exercised_in_both_directions`` pins coverage.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import pytest

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.canonical.findings import SEVERITY_IS_RISK, Result, build_summary
from backend.ingest.generic import PatternAdapterRegistry
from backend.ingest.patterns import PATTERNS_DIR, load_pattern_pack
from backend.rules.evaluator import RulesEvaluator, compute_compliance_score
from backend.rules.loader import load_all_rules
from backend.rules.models import Rule

CONFIG_DIR = PROJECT_ROOT / "test_configs"
HARDENED = CONFIG_DIR / "compliance_extremes" / "fully_hardened.conf"
NONCOMPLIANT = CONFIG_DIR / "compliance_extremes" / "fully_noncompliant.conf"

#: The severity words a rule may claim. Anything else renders as its own chip in
#: the report and silently drops out of the severity distribution chart.
VALID_SEVERITIES = frozenset({"high", "medium", "low"})

#: Controls a correctly hardened device *cannot* pass, because the publisher says
#: so. Each entry is a documented platform limitation quoted from the control's
#: own check text — not a rule this project has failed to satisfy, and not a
#: waiver. The hardened pole is allowed exactly these failures and no others.
#:
#: Keeping them here rather than deleting the rule is the point: DISA words the
#: control as a permanent finding for this platform, so the honest report says
#: "fail, and here is why it can never pass" instead of quietly omitting it. A
#: rule that vanished would leave a reader unable to tell the difference between
#: a control that passed and a control nobody checked.
PLATFORM_PERMANENT_FINDINGS: dict[str, str] = {
    "V-215698": (
        "Cisco IOS is limited to MD5 for NTP authentication, and incurs a "
        "permanent finding as it is not FIPS compliant. — DISA check text, "
        "CISC-ND-001150"
    ),
}

#: The frameworks evaluated directly against canonical facts. NIST and ISO are
#: projections of these results (backend/rules/projection.py), so asserting them
#: at the poles would test the crosswalk twice and the rules not at all.
DIRECT = ["CIS", "DISA_STIG"]


@pytest.fixture(scope="module")
def rules() -> list[Rule]:
    """Every mapping pack under ``rules/mappings/``."""
    return load_all_rules()


@pytest.fixture(scope="module")
def evaluator() -> RulesEvaluator:
    """A full engine over the built catalogs and the shipped mapping packs.

    Constructing it is itself an assertion: ``RulesEvaluator.__init__`` rejects a
    pack that targets a catalog or control id no publisher document contains.
    """
    return RulesEvaluator()


@pytest.fixture(scope="module")
def registry() -> PatternAdapterRegistry:
    return PatternAdapterRegistry()


def _evaluate(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator, config: Path
) -> list:
    """Parse one fixture and evaluate it against every direct framework."""
    text = config.read_text(encoding=FILE_ENCODING)
    adapter = registry.detect(text, config.name)
    assert adapter is not None, f"no pattern pack detects {config.name}"
    result = adapter.parse(text, config.name)
    return evaluator.evaluate(
        result.facts,
        adapter.pack.vendor,
        adapter.pack.os_family,
        frameworks=DIRECT,
        project_governance=False,
    )


def _describe(findings: list, wanted: set[Result]) -> str:
    """Render the offending findings with their rationale, for the failure message."""
    lines = []
    for finding in findings:
        if finding.result in wanted:
            lines.append(
                f"  {finding.control_id} [{finding.result.value}] {finding.title}\n"
                f"      {finding.rationale.split('Check basis')[0].strip()[:200]}"
            )
    return "\n".join(lines)


# ── Load-time invariants ──────────────────────────────────────────────


def test_mapping_packs_exist(rules: list[Rule]) -> None:
    """A green suite with zero rules would prove nothing at all.

    This is the test that would have caught the state this project was in before
    the packs were written: every catalog loaded, every fixture parsed, the whole
    suite green, and not one automated finding produced.
    """
    assert rules, (
        "no mapping packs found under rules/mappings/. Without them the engine "
        "reports every control as 'notchecked' and produces no findings at all."
    )


def test_rule_ids_are_unique(rules: list[Rule]) -> None:
    """Two rules sharing an id make the second impossible to disable or trace."""
    counts: dict[str, int] = defaultdict(int)
    for rule in rules:
        counts[rule.id] += 1
    duplicates = sorted(rule_id for rule_id, n in counts.items() if n > 1)
    assert not duplicates, f"duplicate rule ids: {duplicates}"


def test_every_rule_reads_a_path_its_pack_can_emit(rules: list[Rule]) -> None:
    """A rule may only read canonical paths some pattern pack actually produces.

    The loader already rejects a path outside the vocabulary. This is the next
    failure along: a path that is *in* the vocabulary but that no pack emits. Such
    a rule can only ever return its ``on_missing`` value, so it reports the same
    verdict for every device on earth - a guaranteed false positive or false
    negative depending on which way ``on_missing`` points, and one that no amount
    of fixture authoring can reveal.
    """
    emitted: set[str] = set()
    for pack_file in sorted(PATTERNS_DIR.glob("*.yaml")):
        emitted |= set(load_pattern_pack(pack_file).referenced_paths())

    problems: list[str] = []
    for rule in rules:
        for path in sorted(rule.referenced_paths() - emitted):
            problems.append(f"{rule.id} reads '{path}'")
    assert not problems, (
        f"{len(problems)} rule/path pair(s) reference a canonical path no pattern "
        "pack emits, so the rule's verdict is fixed at its on_missing value:\n  "
        + "\n  ".join(problems[:20])
    )


def test_severity_overrides_use_the_shared_vocabulary(rules: list[Rule]) -> None:
    """An unrecognised severity word drops the finding out of the severity chart."""
    problems = [
        f"{rule.id}: '{rule.severity_override}'"
        for rule in rules
        if rule.severity_override
        and rule.severity_override.lower() not in VALID_SEVERITIES
    ]
    assert not problems, (
        "severity_override must be high, medium or low: " + "; ".join(problems)
    )


def test_every_rule_states_its_mapping_rationale(rules: list[Rule]) -> None:
    """A mapping with no stated basis cannot be reviewed or defended.

    The rationale is what the report prints as the reason this canonical check
    stands in for the published control, so an empty one is a finding the reader
    has to take on faith.
    """
    silent = sorted(rule.id for rule in rules if not rule.mapping_rationale.strip())
    assert not silent, f"{len(silent)} rule(s) carry no mapping_rationale: {silent}"


def test_cis_rules_override_severity(rules: list[Rule]) -> None:
    """CIS publishes no severity, so a CIS rule that does not set one is unrated.

    Without the override the finding renders with severity 'unknown', which is
    correct but useless: the severity distribution chart collapses to a single bar
    and a reader cannot triage the failures.
    """
    unrated = sorted(
        rule.id
        for rule in rules
        if rule.catalog.catalog_id.startswith("cis_") and not rule.severity_override
    )
    assert not unrated, (
        f"{len(unrated)} CIS rule(s) set no severity_override: {unrated}"
    )


def test_disa_rules_do_not_override_severity(rules: list[Rule]) -> None:
    """DISA publishes a CAT rating, so a rule that sets one is overwriting it.

    The mirror of the CIS test above, and the reason the two packs are written
    differently. ``evaluator.py`` resolves severity as
    ``rule.severity_override or control.severity``, so an override on a DISA rule
    silently replaces the publisher's own CAT I/II/III rating with this project's
    opinion of it. An auditor comparing the report against the STIG would find a
    severity that appears in no DISA document and no way to tell where it came
    from — the substitution this project exists to avoid.
    """
    overriding = sorted(
        f"{rule.id}: '{rule.severity_override}'"
        for rule in rules
        if rule.catalog.catalog_id.startswith("disa_stig_") and rule.severity_override
    )
    assert not overriding, (
        f"{len(overriding)} DISA rule(s) override the publisher's severity: "
        + "; ".join(overriding)
    )


def test_disa_rules_inherit_the_published_remediation(rules: list[Rule]) -> None:
    """A DISA rule must not name a hand-authored playbook entry.

    ``resolve_remediation`` prefers the catalog's own ``fix_text`` and extracts
    the CLI from it, so the remediation an operator is shown is the publisher's
    command sequence with the device's real hostname substituted in. Naming a
    ``remediation_ref`` replaces that with text an auditor cannot trace to any
    document. The playbook exists to *add* verification, rollback and risk notes
    to published fix text, not to stand in for it.
    """
    with_ref = sorted(
        f"{rule.id} -> {rule.remediation_ref}"
        for rule in rules
        if rule.catalog.catalog_id.startswith("disa_stig_") and rule.remediation_ref
    )
    assert not with_ref, (
        f"{len(with_ref)} DISA rule(s) point at a hand-authored remediation "
        "instead of the published fix text: " + "; ".join(with_ref)
    )


# ── The compliance poles ──────────────────────────────────────────────


def test_hardened_config_passes_every_automated_control(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """The false-positive detector. See the module docstring."""
    findings = _evaluate(registry, evaluator, HARDENED)
    wrong = {Result.FAIL, Result.ERROR, Result.UNKNOWN, Result.NOTAPPLICABLE}
    offenders = [
        f
        for f in findings
        if f.result in wrong and f.control_id not in PLATFORM_PERMANENT_FINDINGS
    ]

    assert not offenders, (
        f"{HARDENED.name} satisfies the published remediation for every automated "
        f"control, so these {len(offenders)} result(s) are rule defects, not "
        "device findings:\n" + _describe(findings, wrong)
    )
    score = compute_compliance_score(findings)
    assert score["passed"] > 0
    assert score["failed"] == len(PLATFORM_PERMANENT_FINDINGS)


def test_permanent_findings_are_real_and_still_failing(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """Every documented exception must still be a live, failing control.

    The exception list is the one place a FAIL on the hardened pole is tolerated,
    so it is also the easiest place for a stale entry to hide a real regression:
    a control that was renumbered, or a rule that was deleted, would silently
    widen the allowance. Asserting each entry still fails keeps the list honest,
    and asserting the rationale is non-empty keeps it reviewable.
    """
    by_id = {f.control_id: f for f in _evaluate(registry, evaluator, HARDENED)}

    for control_id, reason in PLATFORM_PERMANENT_FINDINGS.items():
        finding = by_id.get(control_id)
        assert finding is not None, (
            f"{control_id} is listed as a permanent platform finding but the "
            "engine no longer evaluates it — the control was renumbered or its "
            "rule was removed. Delete the entry or fix the mapping."
        )
        assert finding.result is Result.FAIL, (
            f"{control_id} is listed as a permanent platform finding but now "
            f"reports '{finding.result.value}'. If the platform gained a "
            "compliant option, remove it from PLATFORM_PERMANENT_FINDINGS."
        )
        assert reason.strip(), f"{control_id}: no reason recorded"


def test_noncompliant_config_fails_every_automated_control(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """The false-negative detector. See the module docstring."""
    findings = _evaluate(registry, evaluator, NONCOMPLIANT)
    wrong = {Result.PASS, Result.ERROR, Result.UNKNOWN, Result.NOTAPPLICABLE}
    offenders = [f for f in findings if f.result in wrong]

    assert not offenders, (
        f"{NONCOMPLIANT.name} violates every automated control, so these "
        f"{len(offenders)} result(s) are missed findings:\n"
        + _describe(findings, wrong)
    )
    score = compute_compliance_score(findings)
    assert score["score"] == 0.0
    assert score["failed"] == score["scored_controls"] > 0


def test_the_two_poles_cover_the_same_control_set(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """Both poles must automate the identical controls.

    If the hardened fixture reaches a control the violating one does not, that
    control is only ever tested in the passing direction and a rule that can
    never fail would go unnoticed. Asserting set equality is what keeps the two
    fixtures honest as the pack grows.
    """
    def automated(config: Path) -> set[str]:
        return {
            f.control_id
            for f in _evaluate(registry, evaluator, config)
            if f.result is not Result.NOTCHECKED
        }

    hardened, violating = automated(HARDENED), automated(NONCOMPLIANT)
    assert hardened == violating, (
        "only in fully_hardened: "
        f"{sorted(hardened - violating)}; only in fully_noncompliant: "
        f"{sorted(violating - hardened)}"
    )


# ── Coverage across the whole fixture taxonomy ────────────────────────


#: What uniquely identifies a control across the whole catalog set. CIS numbering
#: restarts at 1.1.1 in every benchmark, so ``control_id`` alone is not a key —
#: see ``test_every_control_is_exercised_in_both_directions`` for what merging
#: them silently cost.
ControlKey = tuple[str, str, str]


def test_every_control_is_exercised_in_both_directions(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """Every automated control must be exercised; pole vendors in both directions.

    The per-rule positive-and-negative discipline, asserted over the shipped
    corpus rather than per rule file. A control that only ever passes hides a rule
    that cannot detect its violation; a control that only ever fails hides a rule
    that a compliant device cannot satisfy. Either one is a wrong verdict waiting
    for a real device.

    The bar is deliberately two-tier, and the reason is worth stating because the
    weaker tier is a real weakening. Exercising *both* directions requires two
    fixtures per platform — one that satisfies every control and one that violates
    every control — and ``compliance_extremes/`` supplies that pair for Cisco IOS,
    Arista EOS and PAN-OS. When cisco_ios was the sole mapped vendor, a single
    universal bar was both correct and satisfiable. Four vendors still have no
    pair, and the same bar would demand eight more pole fixtures; the alternative
    to writing them is not "relax the test" but "ship four vendors with no
    coverage assertion at all". So:

    * **Pole vendors** — those with fixtures under ``compliance_extremes/`` — are
      held to the original bar: every control both passes and fails somewhere.
    * **Every other vendor** is held to the bar its corpus can support: each
      automated control must be reached in *at least one* direction. That still
      catches the regression this test exists for — a rule that stopped firing,
      or one whose path a pack no longer emits, produces `notchecked` everywhere
      and surfaces here immediately.

    Adding a hardened/violating pair for another vendor promotes it to the strong
    tier automatically; nothing here is hardcoded to a vendor name.

    Coverage is keyed on ``(framework, benchmark, control_id)`` rather than on
    ``control_id``, and that is load-bearing rather than tidy. CIS numbering
    restarts at 1.1.1 in every benchmark, so 38 of the control ids reached by this
    corpus name a *different* control in each of two to four benchmarks — CIS 1.2.1
    exists in the IOS, ASA, NX-OS and PAN-OS packs and means something different in
    each. Keying on the bare id merged them, with two consequences that both hid
    behind a green run: 26 Cisco IOS controls silently dropped out of the strong
    tier when the multi-vendor packs landed, because a number they shared with
    another vendor made ``vendor_of`` look multi-vendor; and the pass/fail
    directions were unioned across benchmarks, so CIS ASA 1.2.1 passing on the ASA
    fixture could satisfy the bar for CIS IOS 1.2.1, which no fixture ever passed.
    A control credited with coverage it does not have is worse than one honestly
    reported as uncovered.
    """
    seen: dict[ControlKey, set[str]] = defaultdict(set)
    vendor_of: dict[ControlKey, set[str]] = defaultdict(set)
    pole_vendors: set[str] = set()

    for config in sorted(CONFIG_DIR.rglob("*.conf")):
        text = config.read_text(encoding=FILE_ENCODING)
        adapter = registry.detect(text, config.name)
        assert adapter is not None, f"no pattern pack detects {config.name}"
        if config.parent.name == "compliance_extremes":
            pole_vendors.add(adapter.pack.vendor)
        for finding in _evaluate(registry, evaluator, config):
            if finding.result is not Result.NOTCHECKED:
                key = (finding.framework, finding.benchmark, finding.control_id)
                seen[key].add(finding.result.value)
                vendor_of[key].add(adapter.pack.vendor)

    assert seen, "no fixture produced an automated finding"
    assert pole_vendors, (
        "no fixture under compliance_extremes/ was recognised, so no vendor is "
        "held to the both-directions bar"
    )

    # A permanent platform finding is exempt from the passing direction only: no
    # configuration can make it pass, which is the documented verdict. It is still
    # held to the failing direction, so a rule that stopped detecting anything at
    # all would surface here rather than being covered by the exemption.
    strong = {k for k, v in vendor_of.items() if v <= pole_vendors}
    never_passes = sorted(
        k for k in strong if "pass" not in seen[k] and k[2] not in PLATFORM_PERMANENT_FINDINGS
    )
    never_fails = sorted(k for k in strong if "fail" not in seen[k])

    def _name(keys: list[ControlKey]) -> list[str]:
        return [f"{b} {c}" for _, b, c in keys]

    assert not never_passes and not never_fails, (
        f"of {len(strong)} controls on pole vendors {sorted(pole_vendors)}, "
        f"{len(never_passes)} never pass on any fixture ({_name(never_passes)}) and "
        f"{len(never_fails)} never fail on any fixture ({_name(never_fails)}). Add a "
        "fixture that exercises the missing direction, or fix the rule that "
        "cannot reach it."
    )


def test_realistic_fixtures_land_between_the_poles(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """A realistic config must score strictly between 0 and 100.

    Not a quality bar - a sanity check on the fixtures themselves. A "partially
    compliant" fixture that scores 0 or 100 has stopped being partially
    compliant, usually because a pattern pack edit changed what it parses, and
    the demo built on it would mislead.
    """
    directory = CONFIG_DIR / "realistic"
    configs = sorted(directory.rglob("*.conf"))
    assert configs, f"no fixtures in {directory}"

    problems = []
    for config in configs:
        score = compute_compliance_score(_evaluate(registry, evaluator, config))
        if not 0.0 < score["score"] < 100.0:
            problems.append(f"{config.name}: {score['score']}%")
    assert not problems, "realistic fixtures at a pole: " + "; ".join(problems)


def test_scores_are_deterministic(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """The same bytes must produce the same verdicts, twice in a row.

    Determinism in the verdict path is what makes a signed report re-verifiable
    (GLOBAL_RULESET R3.2). Set iteration in the evaluator is the usual way this
    breaks, and it breaks silently.
    """
    for config in (HARDENED, NONCOMPLIANT):
        first = _evaluate(registry, evaluator, config)
        second = _evaluate(registry, evaluator, config)
        signature = [
            (f.control_id, f.result.value, f.severity, len(f.evidence)) for f in first
        ]
        assert signature == [
            (f.control_id, f.result.value, f.severity, len(f.evidence)) for f in second
        ]


def test_notchecked_controls_are_reported_not_dropped(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """Unmapped controls must appear as ``notchecked``, never vanish.

    Dropping them would inflate the automation-coverage figure from "71 of 90
    controls" to "71 of 71", which is the single easiest way for a compliance tool
    to overstate what it verified. The unmapped set is documented in docs/GAPS.md.
    """
    findings = _evaluate(registry, evaluator, HARDENED)
    notchecked = [f for f in findings if f.result is Result.NOTCHECKED]

    assert notchecked, (
        "every control in the catalog is mapped, or notchecked findings are being "
        "dropped. If the pack really is complete, delete this test and say so."
    )
    for finding in notchecked:
        assert finding.rationale.strip(), (
            f"{finding.control_id}: a notchecked finding with no explanation tells "
            "the reader nothing about why no check ran"
        )
        assert not finding.evidence, (
            f"{finding.control_id}: a control that was not checked cannot cite "
            "evidence"
        )


def test_automation_coverage_is_reported_and_plausible(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """``EvaluationStats`` must explain the score rather than assert it.

    The lower bound is a floor against silent regression: if a mapping pack stops
    loading, coverage collapses and every control reports notchecked while the
    suite otherwise stays green.

    The floor is deliberately far below current coverage. Across all six catalogs
    that apply to a Cisco IOS device the denominator is dominated by the DISA
    router and switch STIGs, most of whose controls a configuration file cannot
    decide at all — they call for interface topology, ACL semantics or an
    external certificate feed. Raising this bound to just under today's figure
    would turn every honestly-unmappable control into a test failure and create
    pressure to paper one over with a rule that always passes, which is the exact
    failure this suite exists to prevent. Coverage is reported by
    scripts/coverage_report.py and reviewed there, not pinned here.
    """
    _evaluate(registry, evaluator, HARDENED)
    stats = evaluator.last_stats
    assert stats is not None
    assert stats.controls_total > 0
    assert stats.controls_automated > 0
    assert 0.1 < stats.automation_coverage <= 1.0, (
        f"automation coverage is {stats.automation_coverage:.1%} "
        f"({stats.controls_automated}/{stats.controls_total} controls); a mapping "
        "pack has probably stopped loading"
    )


def test_every_direct_framework_produces_a_verdict(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """Each direct framework must decide at least one control on each pole.

    A framework with a built catalog but no mapping pack reports every control as
    notchecked. That is honest, but it is indistinguishable at a glance from a
    framework that is working, and the dashboard still renders its tile. This
    test is what makes the difference visible: it is the one that would have
    failed for DISA STIG, NIST and ISO for as long as the CIS pack was the only
    pack shipped.
    """
    for pole in (HARDENED, NONCOMPLIANT):
        decided: dict[str, int] = defaultdict(int)
        for finding in _evaluate(registry, evaluator, pole):
            if finding.result is not Result.NOTCHECKED:
                decided[finding.framework] += 1

        silent = sorted(set(DIRECT) - set(decided))
        assert not silent, (
            f"{pole.name}: {silent} produced no automated verdict at all. A "
            "framework whose catalog is built but whose mapping pack is missing "
            "reports 100% notchecked while still appearing in the report."
        )


def test_the_published_fixture_table_is_not_stale() -> None:
    """``test_configs/README.md`` must match what the fixtures actually score.

    The table is generated by ``scripts/fixture_report.py``, and every published
    claim about this project's coverage is read off it. A stale table is worse
    than no table: it reports numbers that were true of some earlier pattern pack
    against fixtures that have since changed, with nothing marking it as history.

    This assertion belongs in the suite rather than in CI because there is no CI —
    ``--check`` only protects the numbers if something runs it, and pytest is the
    thing that runs.

    ``DIRECT_FRAMEWORKS`` in the script and ``DIRECT`` here are asserted equal for
    the same reason the frameworks are evaluated at all: when the script scored
    CIS only, the generated table looked complete while silently omitting a whole
    mapping pack.
    """
    from scripts.fixture_report import BEGIN, DIRECT_FRAMEWORKS, END, README
    from scripts.fixture_report import measure_all as measure_fixtures
    from scripts.fixture_report import render as render_table

    assert DIRECT_FRAMEWORKS == DIRECT, (
        f"scripts/fixture_report.py evaluates {DIRECT_FRAMEWORKS} but this suite "
        f"evaluates {DIRECT}. The published table and the tests behind it have to "
        "agree about which frameworks count, or one of them is measuring a "
        "project that does not exist."
    )

    published = re.search(
        re.escape(BEGIN) + r".*?" + re.escape(END),
        README.read_text(encoding="utf-8"),
        re.S,
    )
    assert published is not None, f"{README.name} has lost its generated-table markers"
    assert published.group(0) == render_table(*measure_fixtures()), (
        f"{README.name} no longer matches the fixtures. Regenerate it:\n"
        "  python scripts/fixture_report.py --write\n"
        "then re-read the hand-written prose around the block, which explains "
        "numbers that have just moved."
    )


def test_summary_separates_failing_severity_from_all_severity(
    registry: PatternAdapterRegistry, evaluator: RulesEvaluator
) -> None:
    """``by_severity`` counts every finding; ``by_severity_failing`` counts risk.

    Conflating the two is a mistake with a large blast radius and no loud
    symptom: the dashboard charted ``by_severity`` as "failing controls" and
    reported 16,082 of them on an estate with 372 failures, which reads as a
    catastrophically insecure estate rather than as a charting bug.

    Asserted on a real fixture rather than a hand-built list because the gap only
    opens when ``notchecked`` dominates, which is exactly the shape a real
    catalog produces and a three-finding unit test does not.
    """
    findings = _evaluate(
        registry, evaluator, CONFIG_DIR / "compliance_extremes" / "fully_noncompliant.conf"
    )
    summary = build_summary(findings)

    failing = sum(1 for f in findings if f.result.value in SEVERITY_IS_RISK)
    assert failing > 0, "the fixture must fail something for this test to mean anything"
    assert sum(summary["by_severity_failing"].values()) == failing, (
        "by_severity_failing must total the failing findings and nothing else"
    )
    assert sum(summary["by_severity"].values()) == summary["total"]
    assert failing < summary["total"], (
        "this fixture no longer has any non-failing findings, so it cannot detect "
        "the two counts being conflated -- pick a fixture with notchecked controls"
    )
