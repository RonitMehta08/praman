"""Rules evaluator semantics, and the decoupling boundary gate.

These are unit tests over synthetic catalogs and hand-built facts, deliberately
independent of the shipped mapping packs. The pack tests in
``test_rules_mapping.py`` prove that the *rules we ship* produce the right
verdicts; these prove the *engine* does, so a semantics regression is localised
to one of the two files instead of showing up as a mystery score change.

Every test here names the wrong verdict it prevents. That is the only kind of
failure that matters in a compliance engine: a crash gets noticed, a plausible
wrong answer gets published.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from backend.canonical.findings import Result
from backend.canonical.models import CanonicalFact
from backend.frameworks.catalog import CatalogControl, ControlCatalog
from backend.rules.evaluator import RulesEvaluator
from backend.rules.models import Rule

CATALOG_ID = "test_catalog_v1"


def _fact(
    path: str,
    value: object,
    *,
    present: bool = True,
    line: int = 1,
    raw_text: str = "test line",
) -> CanonicalFact:
    """A canonical fact with complete six-field provenance."""
    return CanonicalFact(
        path=path,
        value=value,
        present=present,
        source_file="test.conf",
        line_start=line,
        line_end=line,
        raw_text=raw_text,
        parser_id="test@0.0.0",
        confidence=1.0,
    )


def _catalog(*control_ids: str) -> ControlCatalog:
    """A synthetic catalog publishing the given control ids.

    The evaluator refuses to load a rule aimed at a control no catalog
    publishes, so a unit test has to supply one. That refusal is itself tested
    below in ``test_rule_targeting_an_unpublished_control_is_rejected``.
    """
    return ControlCatalog(
        catalog_id=CATALOG_ID,
        framework="DISA_STIG",
        benchmark="Synthetic Test Benchmark",
        benchmark_version="V1R0",
        source_document="tests/test_rules_eval.py",
        vendors=["cisco_ios"],
        os_families=["ios"],
        controls=[
            CatalogControl(
                control_id=cid,
                title=f"Synthetic control {cid}",
                severity="high",
                check_text="Synthetic.",
                fix_text="Synthetic.",
            )
            for cid in control_ids
        ],
    )


def _rule(condition: dict, *, control_id: str = "TEST-001", **overrides: object) -> Rule:
    """A rule wrapping one condition, scoped to cisco_ios/ios.

    No ``title`` here: a rule carries no prose of its own. The title, discussion
    and fix text all come from the catalog control it points at, which is what
    stops a mapping pack from quietly restating — or contradicting — the
    publisher's wording. ``Rule`` forbids extra keys, so an attempt to add one
    fails at load.
    """
    payload: dict = {
        "id": f"test-{control_id.lower()}",
        "catalog": {"catalog_id": CATALOG_ID, "control_id": control_id},
        "applies_to": {"vendors": ["cisco_ios"], "os_families": ["ios"]},
        "mapping_rationale": "Synthetic rule used only by the evaluator unit tests.",
        "condition": condition,
    }
    payload.update(overrides)
    return Rule.model_validate(payload)


def _verdict(condition: dict, facts: list[CanonicalFact], **rule_kwargs: object) -> Result:
    """Evaluate one condition against one fact set and return the single result."""
    rule = _rule(condition, **rule_kwargs)
    evaluator = RulesEvaluator(catalogs=[_catalog(rule.catalog.control_id)], rules=[rule])
    findings = evaluator.evaluate(facts, "cisco_ios", "ios", include_notchecked=False)
    assert len(findings) == 1, f"expected one finding, got {len(findings)}"
    return findings[0].result


def _leaf(path: str, operator: str, expected: object, **kwargs: object) -> dict:
    return {
        "type": "fact_check",
        "path": path,
        "operator": operator,
        "expected": expected,
        **kwargs,
    }


# ── The tri-state rule: absence of evidence is never a pass ────────────


class TestAbsenceOfEvidence:
    """The single most important property in the engine.

    A compliance tool that renders "I did not find the insecure setting" as PASS
    will certify an empty file as hardened. Every branch that can encounter a
    missing fact is tested here.
    """

    def test_missing_fact_defaults_to_unknown(self) -> None:
        assert _verdict(_leaf("mgmt.ssh.version", "eq", 2), []) is Result.UNKNOWN

    def test_missing_fact_never_defaults_to_pass(self) -> None:
        """The default must not be pass, whatever else it is.

        Asserted separately from the test above so that a deliberate change of
        the default to ``fail`` or ``notapplicable`` does not silently also make
        ``pass`` acceptable.
        """
        assert _verdict(_leaf("mgmt.ssh.version", "eq", 2), []) is not Result.PASS

    @pytest.mark.parametrize(
        ("on_missing", "expected"),
        [
            ("unknown", Result.UNKNOWN),
            ("fail", Result.FAIL),
            ("notapplicable", Result.NOTAPPLICABLE),
            ("pass", Result.PASS),
        ],
    )
    def test_on_missing_is_honoured(self, on_missing: str, expected: Result) -> None:
        """``on_missing`` is the rule author's explicit choice, including 'pass'.

        ``pass`` is permitted because some controls are genuinely satisfied by
        absence — a directive that must not appear at all. It is opt-in per rule
        precisely so that it can never happen by accident.
        """
        condition = _leaf("mgmt.ssh.version", "eq", 2, on_missing=on_missing)
        assert _verdict(condition, []) is expected

    def test_a_fact_marked_absent_is_still_a_fact(self) -> None:
        """``present=False`` records an observed absence, not a missing fact.

        This is how ``no ip proxy-arp`` and pack-level defaults are represented.
        The distinction matters: a fact whose value is ``False`` must be compared
        against the expectation, not routed to ``on_missing``. Routing it to
        ``on_missing`` would make every default-backed rule return the same
        verdict for every device.
        """
        condition = _leaf("interface.proxy_arp", "eq", False, on_missing="fail")
        facts = [_fact("interface.proxy_arp", False, present=False, line=0)]
        assert _verdict(condition, facts) is Result.PASS


# ── Operators ─────────────────────────────────────────────────────────


class TestOperators:
    @pytest.mark.parametrize(
        ("path", "operator", "expected", "value", "result"),
        [
            ("mgmt.ssh.version", "eq", 2, 2, Result.PASS),
            ("mgmt.ssh.version", "eq", 2, 1, Result.FAIL),
            ("snmp.community", "ne", "private", "s3cret", Result.PASS),
            ("snmp.community", "ne", "private", "private", Result.FAIL),
            ("mgmt.enable_secret.hash_type", "gte", 8, 9, Result.PASS),
            ("mgmt.enable_secret.hash_type", "gte", 8, 8, Result.PASS),
            ("mgmt.enable_secret.hash_type", "gte", 8, 5, Result.FAIL),
            ("line.vty.exec_timeout", "gt", 0, 300, Result.PASS),
            ("line.vty.exec_timeout", "gt", 0, 0, Result.FAIL),
            ("line.vty.exec_timeout", "lte", 600, 600, Result.PASS),
            ("line.vty.exec_timeout", "lte", 600, 601, Result.FAIL),
            ("mgmt.ssh.maxretries", "lt", 10, 9, Result.PASS),
            ("logging.console", "in", ["critical", "alerts"], "critical", Result.PASS),
            ("logging.console", "in", ["critical", "alerts"], "debugging", Result.FAIL),
            ("line.console.login_auth", "not_in", ["none", "line", "local"], "MGMT", Result.PASS),
            ("line.console.login_auth", "not_in", ["none", "line", "local"], "local", Result.FAIL),
            ("snmp.v3_priv", "regex_match", "^aes", "aes-128", Result.PASS),
            ("snmp.v3_priv", "regex_match", "^aes", "des", Result.FAIL),
            ("snmp.community", "regex_not_match", "^(public|private)$", "s3cret", Result.PASS),
            ("snmp.community", "regex_not_match", "^(public|private)$", "public", Result.FAIL),
        ],
    )
    def test_scalar_operator(
        self, path: str, operator: str, expected: object, value: object, result: Result
    ) -> None:
        """Each operator on a real canonical path.

        The paths are the ones the shipped rules actually use, not placeholders:
        ``Rule`` validates every path against the canonical vocabulary at load,
        so a test using a made-up path would not even construct — which is the
        behaviour that stops a typo'd path from reaching production as a rule
        that can never match anything.
        """
        condition = _leaf(path, operator, expected)
        assert _verdict(condition, [_fact(path, value)]) is result

    @pytest.mark.parametrize(
        ("operator", "expected", "value", "result"),
        [
            ("subset_of", ["ssh", "none"], ["ssh"], Result.PASS),
            ("subset_of", ["ssh", "none"], ["telnet", "ssh"], Result.FAIL),
            ("superset_of", ["ssh"], ["ssh", "none"], Result.PASS),
            ("superset_of", ["ssh"], ["telnet"], Result.FAIL),
            ("disjoint_from", ["telnet"], ["ssh"], Result.PASS),
            ("disjoint_from", ["telnet"], ["telnet", "ssh"], Result.FAIL),
        ],
    )
    def test_set_operator(
        self, operator: str, expected: list, value: list, result: Result
    ) -> None:
        """Set operators are what make ``transport input`` checkable.

        ``transport input`` is a *set* of permitted protocols, so ``eq`` against
        a single value would fail a compliant line that also permits ``none``,
        and ``contains`` would pass a line permitting both telnet and ssh.
        """
        condition = _leaf("line.vty.transport_input", operator, expected)
        assert _verdict(condition, [_fact("line.vty.transport_input", value)]) is result

    def test_case_sensitivity_is_opt_out(self) -> None:
        """Comparisons are case-sensitive unless the rule says otherwise.

        IOS keywords are case-insensitive in practice, so a rule comparing them
        must say so. Defaulting to insensitive would be wrong the other way: a
        community string or key differing only in case is a different secret.
        """
        sensitive = _leaf("snmp.community", "ne", "public")
        insensitive = _leaf("snmp.community", "ne", "public", case_sensitive=False)
        facts = [_fact("snmp.community", "PUBLIC")]
        assert _verdict(sensitive, facts) is Result.PASS
        assert _verdict(insensitive, facts) is Result.FAIL


# ── Quantifiers ───────────────────────────────────────────────────────


class TestQuantifiers:
    """How a rule handles a path carrying several facts.

    The default is ``all``, which is the safe direction: with ``any``, one
    correctly configured user or interface would vouch for every other one.
    """

    def test_all_requires_every_fact_to_satisfy(self) -> None:
        condition = _leaf("mgmt.local_user.secret", "eq", True, quantifier="all")
        facts = [
            _fact("mgmt.local_user.secret", True, line=10),
            _fact("mgmt.local_user.secret", True, line=11),
        ]
        assert _verdict(condition, facts) is Result.PASS

    def test_all_fails_when_one_fact_does_not(self) -> None:
        """One user with a cleartext password fails the control for the device."""
        condition = _leaf("mgmt.local_user.secret", "eq", True, quantifier="all")
        facts = [
            _fact("mgmt.local_user.secret", True, line=10),
            _fact("mgmt.local_user.secret", False, line=11),
        ]
        assert _verdict(condition, facts) is Result.FAIL

    def test_all_is_the_default_quantifier(self) -> None:
        condition = _leaf("mgmt.local_user.secret", "eq", True)
        facts = [
            _fact("mgmt.local_user.secret", True, line=10),
            _fact("mgmt.local_user.secret", False, line=11),
        ]
        assert _verdict(condition, facts) is Result.FAIL

    def test_any_passes_on_a_single_satisfying_fact(self) -> None:
        """``any`` expresses "at least one X exists", e.g. a loopback interface."""
        condition = _leaf(
            "interface.name", "regex_match", "^loopback", quantifier="any", case_sensitive=False
        )
        facts = [
            _fact("interface.name", "GigabitEthernet0/0", line=10),
            _fact("interface.name", "Loopback0", line=20),
        ]
        assert _verdict(condition, facts) is Result.PASS

    def test_any_fails_when_no_fact_satisfies(self) -> None:
        condition = _leaf(
            "interface.name", "regex_match", "^loopback", quantifier="any", case_sensitive=False
        )
        facts = [_fact("interface.name", "GigabitEthernet0/0", line=10)]
        assert _verdict(condition, facts) is Result.FAIL


# ── Boolean folding ───────────────────────────────────────────────────


class TestBooleanFolding:
    """How ``all_of`` / ``any_of`` / ``none_of`` combine a tri-state.

    Two-valued logic is the trap here: with pass/fail only, folding is obvious.
    With ``unknown`` in the mix, a careless ``any_of`` can swallow a real failure
    — which is exactly the CIS 1.5.8 defect this engine shipped once and now
    guards against.
    """

    def test_all_of_passes_only_when_every_branch_passes(self) -> None:
        condition = {
            "type": "all_of",
            "conditions": [
                _leaf("line.vty.exec_timeout", "lte", 600),
                _leaf("line.vty.exec_timeout", "gt", 0),
            ],
        }
        assert _verdict(condition, [_fact("line.vty.exec_timeout", 300)]) is Result.PASS

    def test_all_of_catches_the_never_time_out_setting(self) -> None:
        """``exec-timeout 0 0`` means never time out, and must not pass.

        A bare ``lte 600`` would pass the least secure setting IOS offers, so
        every timeout rule is bounded at both ends. This is the regression test
        for that convention.
        """
        condition = {
            "type": "all_of",
            "conditions": [
                _leaf("line.vty.exec_timeout", "lte", 600),
                _leaf("line.vty.exec_timeout", "gt", 0),
            ],
        }
        assert _verdict(condition, [_fact("line.vty.exec_timeout", 0)]) is Result.FAIL

    def test_any_of_passes_when_one_branch_passes(self) -> None:
        condition = {
            "type": "any_of",
            "conditions": [
                _leaf("snmp.enabled", "eq", False),
                _leaf("snmp.traps", "eq", True, on_missing="fail"),
            ],
        }
        assert _verdict(condition, [_fact("snmp.enabled", False)]) is Result.PASS

    def test_any_of_fails_when_every_branch_decides_fail(self) -> None:
        """The CIS 1.5.8 regression.

        SNMP enabled and no traps directive is the violation. Before the leaf
        carried ``on_missing: fail`` the fold was ``any_of[fail, unknown]``,
        which reported ``unknown`` — excluding a real finding from the score
        instead of counting it.
        """
        condition = {
            "type": "any_of",
            "conditions": [
                _leaf("snmp.enabled", "eq", False),
                _leaf("snmp.traps", "eq", True, on_missing="fail"),
            ],
        }
        assert _verdict(condition, [_fact("snmp.enabled", True)]) is Result.FAIL

    def test_any_of_does_not_let_unknown_mask_a_failure(self) -> None:
        """An undecidable branch must not upgrade a decided failure.

        Whatever the fold returns here it must not be ``pass``: nothing passed.
        The result is allowed to be ``unknown`` (evidence was genuinely missing)
        or ``fail``, and the test pins only the property that matters.
        """
        condition = {
            "type": "any_of",
            "conditions": [
                _leaf("snmp.enabled", "eq", False),
                _leaf("snmp.traps", "eq", True),
            ],
        }
        assert _verdict(condition, [_fact("snmp.enabled", True)]) is not Result.PASS

    def test_none_of_passes_when_no_branch_passes(self) -> None:
        condition = {
            "type": "none_of",
            "conditions": [_leaf("service.finger", "eq", True)],
        }
        assert _verdict(condition, [_fact("service.finger", False)]) is Result.PASS

    def test_none_of_fails_when_a_branch_passes(self) -> None:
        condition = {
            "type": "none_of",
            "conditions": [_leaf("service.finger", "eq", True)],
        }
        assert _verdict(condition, [_fact("service.finger", True)]) is Result.FAIL


# ── Presence ──────────────────────────────────────────────────────────


class TestPresence:
    def test_presence_passes_when_the_path_has_a_fact(self) -> None:
        condition = {"type": "presence", "path": "mgmt.exec_banner"}
        assert _verdict(condition, [_fact("mgmt.exec_banner", True)]) is Result.PASS

    def test_presence_fails_when_the_path_is_empty(self) -> None:
        condition = {"type": "presence", "path": "mgmt.exec_banner"}
        assert _verdict(condition, []) is Result.FAIL

    def test_presence_is_satisfied_by_a_defaulted_fact(self) -> None:
        """Documented hazard, asserted so it stays documented.

        A pack-level default *is* a fact, so ``presence`` on a defaulted path
        passes for every device ever parsed. That is why the mapping pack's
        convention is to use ``fact_check … eq true|false`` on defaulted paths
        and never ``presence``. This test exists to prove the hazard is real
        rather than theoretical — if it ever starts failing, the convention can
        be relaxed.
        """
        condition = {"type": "presence", "path": "service.password_encryption"}
        defaulted = _fact("service.password_encryption", False, present=False, line=0)
        assert _verdict(condition, [defaulted]) is Result.PASS


# ── Applicability ─────────────────────────────────────────────────────


class TestApplicability:
    def test_rule_for_another_vendor_is_not_evaluated(self) -> None:
        """A junos rule must not decide anything about an IOS device.

        Applicability is declared, not inferred, and it is constructed through
        validation rather than assigned after the fact — assigning to
        ``applies_to.vendors`` would bypass the coercion the model performs and
        test a state no loaded rule can be in.
        """
        rule = _rule(
            _leaf("mgmt.ssh.version", "eq", 2),
            applies_to={"vendors": ["juniper_junos"], "os_families": ["junos"]},
        )
        evaluator = RulesEvaluator(catalogs=[_catalog("TEST-001")], rules=[rule])
        findings = evaluator.evaluate(
            [_fact("mgmt.ssh.version", 1)], "cisco_ios", "ios", include_notchecked=False
        )
        assert not findings, "a junos rule must not be evaluated against an IOS device"

    def test_requires_paths_reports_notapplicable_not_pass(self) -> None:
        """A router not running EIGRP is not applicable to the EIGRP control.

        Expressing "the feature is absent" as a satisfied condition would return
        PASS and credit the device for a control it was never subject to, and
        that PASS would count in the compliance score. ``notapplicable`` is
        excluded from the ratio instead.
        """
        condition = _leaf("routing.eigrp.auth", "eq", "md5", on_missing="fail")
        result = _verdict(
            condition,
            [_fact("interface.name", "GigabitEthernet0/0")],
            applies_to={
                "vendors": ["cisco_ios"],
                "os_families": ["ios"],
                "requires_paths": ["routing.eigrp.process"],
            },
        )
        assert result is Result.NOTAPPLICABLE

    def test_requires_paths_evaluates_when_the_feature_is_present(self) -> None:
        """With the feature configured, the rule must decide normally.

        The mirror of the test above, and the one that catches a
        ``requires_paths`` implementation that suppresses the rule outright — a
        bug that would silently disable every feature-conditional control.
        """
        condition = _leaf("routing.eigrp.auth", "eq", "md5", on_missing="fail")
        result = _verdict(
            condition,
            [_fact("routing.eigrp.process", 100)],
            applies_to={
                "vendors": ["cisco_ios"],
                "os_families": ["ios"],
                "requires_paths": ["routing.eigrp.process"],
            },
        )
        assert result is Result.FAIL


# ── Engine contracts ──────────────────────────────────────────────────


class TestEngineContracts:
    def test_rule_targeting_an_unpublished_control_is_rejected(self) -> None:
        """A typo in a control id must fail loudly at load, not silently at run.

        Without this check the rule would be dropped or attached to nothing, and
        the control would report ``notchecked`` — indistinguishable from a
        control that was deliberately left unautomated.
        """
        rule = _rule(_leaf("mgmt.ssh.version", "eq", 2), control_id="TEST-NOPE")
        with pytest.raises(Exception) as excinfo:
            RulesEvaluator(catalogs=[_catalog("TEST-001")], rules=[rule])
        assert "TEST-NOPE" in str(excinfo.value)

    def test_finding_carries_evidence_with_line_numbers(self) -> None:
        """A finding without a locatable line is not actionable.

        An auditor has to be able to open the config at the offending line;
        "SSH version is wrong" without a line number is a claim, not evidence.
        """
        rule = _rule(_leaf("mgmt.ssh.version", "eq", 2))
        evaluator = RulesEvaluator(catalogs=[_catalog("TEST-001")], rules=[rule])
        findings = evaluator.evaluate(
            [_fact("mgmt.ssh.version", 1, line=42, raw_text="ip ssh version 1")],
            "cisco_ios",
            "ios",
            include_notchecked=False,
        )
        evidence = findings[0].evidence
        assert evidence, "a decided finding must cite the facts it decided on"
        assert any(getattr(e, "line_start", None) == 42 for e in evidence)

    def test_severity_override_wins_over_the_catalog(self) -> None:
        """The rule's severity, when set, is what the report shows."""
        rule = _rule(_leaf("mgmt.ssh.version", "eq", 2), severity_override="low")
        evaluator = RulesEvaluator(catalogs=[_catalog("TEST-001")], rules=[rule])
        findings = evaluator.evaluate(
            [_fact("mgmt.ssh.version", 1)], "cisco_ios", "ios", include_notchecked=False
        )
        assert findings[0].severity == "low"

    def test_unmapped_control_is_reported_as_notchecked(self) -> None:
        """A control with no rule appears, so coverage cannot be overstated."""
        rule = _rule(_leaf("mgmt.ssh.version", "eq", 2), control_id="TEST-001")
        evaluator = RulesEvaluator(
            catalogs=[_catalog("TEST-001", "TEST-002")], rules=[rule]
        )
        findings = evaluator.evaluate([], "cisco_ios", "ios", include_notchecked=True)
        by_control = {f.control_id: f.result for f in findings}
        assert by_control["TEST-002"] is Result.NOTCHECKED

    def test_evaluation_is_deterministic(self) -> None:
        """Same facts, same order, twice — the signed report depends on it."""
        rule = _rule(_leaf("mgmt.ssh.version", "eq", 2))
        evaluator = RulesEvaluator(catalogs=[_catalog("TEST-001")], rules=[rule])
        facts = [_fact("mgmt.ssh.version", 1)]
        first = evaluator.evaluate(facts, "cisco_ios", "ios")
        second = evaluator.evaluate(facts, "cisco_ios", "ios")
        assert [(f.control_id, f.result) for f in first] == [
            (f.control_id, f.result) for f in second
        ]


class TestDecouplingBoundary:
    """The decoupling boundary grep gate (SPINE §4).

    The canonical model is the only contract between parsing and evaluation. If a
    vendor regex leaks into a rule, that rule stops being portable to another
    vendor; if a control id leaks into a parser, the parser starts serving one
    framework. Either one collapses the vendor-agnostic property the whole
    architecture is built on, and both are invisible in a passing test suite
    unless something greps for them.
    """

    PROJECT_ROOT = Path(__file__).resolve().parent.parent

    # Vendor-specific tokens that MUST NOT appear in rule files
    VENDOR_TOKENS = [
        r"\bcisco\b",
        r"\bios\b",
        r"\bjunos\b",
        r"\bfortios\b",
        r"\bpanos\b",
        r"\barista\b",
        r"\bnxos\b",
    ]

    # Control ID patterns that MUST NOT appear in parser files
    CONTROL_ID_PATTERNS = [
        r"V-\d{6}",
        r"CISC-\w+-\d+",
        r"CCI-\d{6}",
    ]

    def test_no_vendor_regex_in_rules(self) -> None:
        """No vendor token should appear in YAML rule files."""
        rules_dir = self.PROJECT_ROOT / "rules"
        if not rules_dir.exists():
            pytest.skip("rules/ directory not found")

        violations = []
        for yaml_file in rules_dir.rglob("*.yaml"):
            content = yaml_file.read_text(encoding="utf-8").lower()
            for token in self.VENDOR_TOKENS:
                # Allow vendor tokens only in file paths and benchmark names
                # Check condition blocks specifically
                lines = content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    if ("condition:" in line or "pattern:" in line) and re.search(
                        token, line, re.IGNORECASE
                    ):
                        violations.append(
                            f"{yaml_file.name}:{line_num} — vendor token '{token}' in condition"
                        )
        assert not violations, f"Vendor regex in rules/: {violations}"

    def test_no_control_id_in_parsers(self) -> None:
        """No control ID should appear in parser code."""
        ingest_dir = self.PROJECT_ROOT / "backend" / "ingest"
        if not ingest_dir.exists():
            pytest.skip("backend/ingest/ directory not found")

        violations = []
        for py_file in ingest_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for pattern in self.CONTROL_ID_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    violations.append(
                        f"{py_file.name} — control ID(s) found: {matches}"
                    )
        assert not violations, f"Control IDs in backend/ingest/: {violations}"
