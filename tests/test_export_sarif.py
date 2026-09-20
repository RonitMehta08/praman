"""Test: the SARIF v2.1.0 export — the audit as a CI gate artifact.

Four claims, each of which the suite would otherwise not notice breaking.

**Purity.** ``/simulate`` is documented as idempotent, and this export is the one
place that promise could quietly break: a single ``datetime.now()`` in an
``invocations`` block would make every CI run diff against the last one, and the
document would still be perfectly valid SARIF. :class:`TestPurity` walks the whole
document looking for anything that smells like a clock.

**The omission is arithmetic, not editorial.** ``notchecked``, ``notselected`` and
``notapplicable`` are counted and not emitted, which is a defensible decision only
as long as the counts add up in public. :class:`TestOmissionBookkeeping` asserts
that they do, for every result value.

**Absent facts.** Most PRAMAN findings rest on a line the config never contained,
and ``_absent_fact`` gives those ``line_start=0``. SARIF's ``region.startLine``
carries ``minimum: 1``, so emitting a region for them would make the document
invalid — for the majority of real findings, not an edge case.
:class:`TestLocations` pins the guard.

**Vendor-correct remediation, or none.** ``get_commands_for_vendor`` falls back to
the ``cisco_ios`` list for an unrecognised vendor. Help text is the one place that
fallback is dangerous, because a reader in a hurry pastes it into a FortiGate.

Structural assertions cite the ``required`` lists and enums read out of the OASIS
``sarif-schema-2.1.0.json``. The schema is not vendored; full validation against
the publisher's file is ``scripts/check_export_conformance.py``, run as a
documented manual step (MANUAL_COMMANDS.md Step 14) because it needs that download.
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from backend.canonical.findings import Finding, Result
from backend.canonical.models import CanonicalFact
from backend.core_errors import ExportError
from backend.export.oscal_mapping import result_value
from backend.export.sarif import (
    DEVICE_FIELDS,
    OMITTED_RESULTS,
    RESULT_KIND,
    SARIF_VERSION,
    SEVERITY_LEVEL,
    to_sarif,
)

#: ``result.kind`` enum, verbatim from the OASIS schema.
KIND_ENUM = {"notApplicable", "pass", "fail", "review", "open", "informational"}

#: ``result.level`` enum, verbatim from the OASIS schema.
LEVEL_ENUM = {"none", "note", "warning", "error"}

#: ``runAutomationDetails.guid`` pattern, verbatim from the OASIS schema. Wider
#: than OSCAL's — versions 1-5 — but ``uuid5`` has to land inside it all the same.
GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

#: Anything that looks like a date or a clock reading. Deliberately loose.
TIMESTAMP_SHAPED = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}")

DEVICE = {
    "device_id": "core-rtr-01",
    "vendor": "cisco_ios",
    "os_family": "ios",
    "os_version": "15.7(3)M",
    "hostname": "core-rtr-01.example.test",
    "config_hash": "sha256:" + "3" * 64,
    "source_file": "core-rtr-01.conf",
}


def fact(
    *,
    path: str = "mgmt.ssh.version",
    line_start: int = 42,
    line_end: int = 42,
    raw_text: str = "ip ssh version 2",
    present: bool = True,
    source_file: str = "core-rtr-01.conf",
) -> CanonicalFact:
    return CanonicalFact(
        path=path,
        value=2,
        present=present,
        source_file=source_file,
        line_start=line_start,
        line_end=line_end,
        raw_text=raw_text,
        parser_id="cisco_ios",
        confidence=1.0,
    )


def make_finding(
    result: Result | str = Result.FAIL,
    *,
    control_id: str = "V-215844",
    framework: str = "DISA_STIG",
    benchmark: str = "Cisco IOS Router NDM STIG",
    benchmark_version: str = "V3R7",
    severity: str = "high",
    evidence: list[CanonicalFact] | None = None,
    remediation_ref: str | None = "stig-ndm-v215844-remediation",
) -> Finding:
    return Finding(
        control_id=control_id,
        framework=framework,
        benchmark=benchmark,
        benchmark_version=benchmark_version,
        title="SSH must be version 2",
        result=result if isinstance(result, Result) else Result(result),
        severity=severity,
        evidence=[fact()] if evidence is None else evidence,
        rationale="The device negotiates SSH version 2 only.",
        remediation_ref=remediation_ref,
        references={"cci": ["CCI-000068"]},
    )


def run_of(findings: list[Finding], device: dict | None = None) -> dict:
    """The single run in a SARIF log for `findings`."""
    return to_sarif(device or DEVICE, findings)["runs"][0]


def walk(node, path: str = ""):
    """Every ``(json_pointer, value)`` leaf in `node`."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}/{index}")
    else:
        yield path, node


class TestEveryResultValueIsHandled:
    def test_the_map_covers_the_whole_enum(self) -> None:
        assert set(RESULT_KIND) == {r.value for r in Result}, (
            "RESULT_KIND must name every XCCDF value. A missing one would take "
            "SARIF's default kind, which is 'fail' — the worst possible guess."
        )

    def test_every_mapped_kind_is_in_sarifs_enum(self) -> None:
        assert set(RESULT_KIND.values()) <= KIND_ENUM

    def test_severity_levels_are_in_sarifs_enum(self) -> None:
        assert set(SEVERITY_LEVEL.values()) <= LEVEL_ENUM

    def test_the_omitted_three_are_all_no_verdict_results(self) -> None:
        """Nothing that carries a verdict may be omitted from a gate's input."""
        assert set(OMITTED_RESULTS) == {"notchecked", "notselected", "notapplicable"}
        assert Result.FAIL.value not in OMITTED_RESULTS
        assert Result.PASS.value not in OMITTED_RESULTS

    @pytest.mark.parametrize("value", [r.value for r in Result])
    def test_each_value_either_emits_one_result_or_is_counted(self, value: str) -> None:
        run = run_of([make_finding(value)])
        if value in OMITTED_RESULTS:
            assert run["results"] == []
            assert run["properties"]["pramanResultsOmittedTotal"] == 1
        else:
            assert len(run["results"]) == 1
            assert run["results"][0]["kind"] == RESULT_KIND[value]
            assert run["properties"]["pramanResultsOmittedTotal"] == 0

    @pytest.mark.parametrize("value", [r.value for r in Result])
    def test_level_is_set_only_for_a_failure(self, value: str) -> None:
        """A pass shown at 'error' severity trains reviewers to ignore the column."""
        run = run_of([make_finding(value)])
        for result in run["results"]:
            if result["kind"] == "fail":
                assert result["level"] == "error"
            else:
                assert "level" not in result

    @pytest.mark.parametrize(
        ("severity", "level"), [("high", "error"), ("medium", "warning"), ("low", "note")]
    )
    def test_severity_drives_the_failure_level(self, severity: str, level: str) -> None:
        run = run_of([make_finding(Result.FAIL, severity=severity)])
        assert run["results"][0]["level"] == level

    def test_an_unrecognised_severity_falls_back_to_the_schema_default(self) -> None:
        run = run_of([make_finding(Result.FAIL, severity="moderate")])
        assert run["results"][0]["level"] == "warning"


class TestOmissionBookkeeping:
    def test_the_counts_sum_to_the_findings_total(self) -> None:
        findings = [make_finding(r.value, control_id=f"V-{index:06d}") for index, r in enumerate(Result)]
        run = run_of(findings)
        properties = run["properties"]
        assert sum(properties["pramanResultCounts"].values()) == len(findings)
        assert properties["pramanFindingsTotal"] == len(findings)

    def test_emitted_plus_omitted_equals_the_total(self) -> None:
        findings = [make_finding(r.value, control_id=f"V-{index:06d}") for index, r in enumerate(Result)]
        run = run_of(findings)
        properties = run["properties"]
        assert (
            len(run["results"]) + properties["pramanResultsOmittedTotal"]
            == properties["pramanFindingsTotal"]
        )

    def test_the_omitted_breakdown_names_all_three(self) -> None:
        run = run_of([make_finding(r.value, control_id=f"V-{i:06d}") for i, r in enumerate(Result)])
        assert set(run["properties"]["pramanResultsOmitted"]) == set(OMITTED_RESULTS)
        assert run["properties"]["pramanResultsOmitted"] == {
            "notchecked": 1,
            "notselected": 1,
            "notapplicable": 1,
        }

    def test_the_rationale_is_published_not_just_implied(self) -> None:
        run = run_of([make_finding(Result.NOTCHECKED)])
        assert "pramanResultCounts sums to pramanFindingsTotal" in (
            run["properties"]["pramanOmissionRationale"]
        )

    def test_an_omitted_result_contributes_no_rule_descriptor(self) -> None:
        """A rule nothing reports against is clutter in a viewer's rule list."""
        run = run_of([make_finding(Result.NOTCHECKED)])
        assert run["tool"]["driver"]["rules"] == []
        assert run["results"] == []


class TestPurity:
    """The output must be a pure function of the configuration."""

    def test_two_exports_are_byte_identical(self) -> None:
        findings = [make_finding(Result.FAIL), make_finding(Result.PASS, control_id="V-215845")]
        assert json.dumps(to_sarif(DEVICE, findings)) == json.dumps(to_sarif(DEVICE, findings))

    def test_finding_order_does_not_change_the_output(self) -> None:
        """Rule-load order must not leak into the document."""
        first = make_finding(Result.FAIL, control_id="V-000001")
        second = make_finding(Result.PASS, control_id="V-000002")
        assert json.dumps(to_sarif(DEVICE, [first, second])) == json.dumps(
            to_sarif(DEVICE, [second, first])
        )

    def test_no_value_in_the_document_looks_like_a_timestamp(self) -> None:
        document = to_sarif(DEVICE, [make_finding(Result.FAIL)])
        offenders = [
            (pointer, value)
            for pointer, value in walk(document)
            if isinstance(value, str) and TIMESTAMP_SHAPED.search(value)
        ]
        assert offenders == [], (
            f"a timestamp reached the SARIF output at {offenders[:1]}. That breaks "
            "the guarantee that identical config bytes produce identical bytes, and "
            "turns every CI run into a diff."
        )

    def test_no_invocation_or_column_declaration(self) -> None:
        run = run_of([make_finding()])
        assert "invocations" not in run
        assert "columnKind" not in run

    def test_the_run_guid_is_a_valid_sarif_guid(self) -> None:
        run = run_of([make_finding()])
        assert GUID_PATTERN.match(run["automationDetails"]["guid"])

    def test_an_edited_config_gets_a_new_run_guid(self) -> None:
        other = dict(DEVICE, config_hash="sha256:" + "4" * 64)
        assert (
            run_of([make_finding()])["automationDetails"]["guid"]
            != run_of([make_finding()], other)["automationDetails"]["guid"]
        )

    def test_dict_findings_and_model_findings_agree(self) -> None:
        finding = make_finding()
        assert json.dumps(to_sarif(DEVICE, [finding])) == json.dumps(
            to_sarif(DEVICE, [finding.model_dump(mode="json")])
        )


class TestFingerprints:
    """A fingerprint identifies a problem, not a version of a file."""

    def test_the_fingerprint_survives_a_config_edit(self) -> None:
        """Otherwise every unrelated edit mints a fresh alert and loses its history."""
        edited = dict(DEVICE, config_hash="sha256:" + "7" * 64)
        first = run_of([make_finding()])["results"][0]["partialFingerprints"]
        second = run_of([make_finding()], edited)["results"][0]["partialFingerprints"]
        assert first == second

    def test_different_controls_get_different_fingerprints(self) -> None:
        run = run_of([make_finding(control_id="V-000001"), make_finding(control_id="V-000002")])
        prints = [r["partialFingerprints"] for r in run["results"]]
        assert prints[0] != prints[1]

    def test_different_devices_get_different_fingerprints(self) -> None:
        other = dict(DEVICE, device_id="edge-rtr-09")
        assert (
            run_of([make_finding()])["results"][0]["partialFingerprints"]
            != run_of([make_finding()], other)["results"][0]["partialFingerprints"]
        )

    def test_the_key_is_versioned(self) -> None:
        """So a change to what the hash covers can ship without re-identifying alerts."""
        prints = run_of([make_finding()])["results"][0]["partialFingerprints"]
        assert list(prints) == ["pramanControlFingerprint/v1"]


class TestLocations:
    def test_a_real_line_span_becomes_a_region_with_a_snippet(self) -> None:
        location = run_of([make_finding()])["results"][0]["locations"][0]
        region = location["physicalLocation"]["region"]
        assert region["startLine"] == 42
        assert region["endLine"] == 42
        assert region["snippet"] == {"text": "ip ssh version 2"}

    def test_an_absent_fact_gets_no_region(self) -> None:
        """``_absent_fact`` uses line 0, and ``region.startLine`` has minimum 1."""
        absent = fact(line_start=0, line_end=0, present=False, raw_text="<not configured>")
        location = run_of([make_finding(evidence=[absent])])["results"][0]["locations"][0]
        assert "region" not in location["physicalLocation"]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "core-rtr-01.conf"

    def test_a_finding_with_no_evidence_still_has_a_location(self) -> None:
        result = run_of([make_finding(evidence=[])])["results"][0]
        location = result["locations"][0]
        assert location["physicalLocation"]["artifactLocation"] == {
            "uri": "core-rtr-01.conf",
            "index": 0,
        }
        assert "absence of a configuration line" in location["message"]["text"]

    def test_the_artifact_index_is_set_only_for_the_analysed_file(self) -> None:
        """An index into ``run.artifacts`` that points at the wrong file is worse
        than no index at all."""
        elsewhere = fact(source_file="some-other-device.conf")
        location = run_of([make_finding(evidence=[elsewhere])])["results"][0]["locations"][0]
        assert "index" not in location["physicalLocation"]["artifactLocation"]

    def test_a_reversed_line_span_drops_the_end_line(self) -> None:
        weird = fact(line_start=42, line_end=7)
        region = run_of([make_finding(evidence=[weird])])["results"][0]["locations"][0][
            "physicalLocation"
        ]["region"]
        assert region["startLine"] == 42
        assert "endLine" not in region

    def test_the_analysed_config_is_declared_as_the_analysis_target(self) -> None:
        artifact = run_of([make_finding()])["artifacts"][0]
        assert artifact["roles"] == ["analysisTarget"]
        assert artifact["location"] == {"uri": "core-rtr-01.conf"}
        assert artifact["properties"]["pramanConfigHash"] == DEVICE["config_hash"]
        assert "hashes" not in artifact


class TestRuleDescriptors:
    def test_rule_index_points_at_the_matching_descriptor(self) -> None:
        run = run_of(
            [
                make_finding(Result.FAIL, control_id="V-000001"),
                make_finding(Result.PASS, control_id="V-000002"),
            ]
        )
        for result in run["results"]:
            assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]

    def test_the_rule_id_is_namespaced_by_framework(self) -> None:
        """A bare '1.1.4' is ambiguous across frameworks; the verbatim id is kept."""
        run = run_of([make_finding(Result.FAIL, control_id="1.1.4", framework="CIS")])
        rule = run["tool"]["driver"]["rules"][0]
        assert rule["id"] == "CIS/1.1.4"
        assert rule["properties"]["pramanControlId"] == "1.1.4"

    def test_two_benchmarks_sharing_a_rule_id_are_both_named(self) -> None:
        run = run_of(
            [
                make_finding(Result.FAIL, control_id="1.1.4", framework="CIS", benchmark="A"),
                make_finding(Result.PASS, control_id="1.1.4", framework="CIS", benchmark="B"),
            ]
        )
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert run["tool"]["driver"]["rules"][0]["properties"]["pramanBenchmarks"] == [
            "A V3R7",
            "B V3R7",
        ]

    def test_help_text_carries_the_vendors_own_commands(self) -> None:
        rule = run_of([make_finding()])["tool"]["driver"]["rules"][0]
        assert "ip ssh version 2" in rule["help"]["text"]
        assert "Risk of applying this change: low" in rule["help"]["text"]

    def test_help_text_never_offers_another_vendors_syntax(self) -> None:
        """The one place ``get_commands_for_vendor``'s cisco_ios fallback would harm."""
        fortigate = dict(DEVICE, vendor="fortinet")
        rule = run_of([make_finding()], fortigate)["tool"]["driver"]["rules"][0]
        assert "ip ssh version 2" not in rule["help"]["text"]
        assert "no fortinet command sequence recorded" in rule["help"]["text"]

    def test_a_control_with_no_playbook_entry_gets_no_help(self) -> None:
        rule = run_of([make_finding(remediation_ref=None)])["tool"]["driver"]["rules"][0]
        assert "help" not in rule
        assert "helpUri" not in rule

    def test_remediation_is_never_offered_as_an_applicable_fix(self) -> None:
        """``result.fixes`` would let a viewer offer one-click reconfiguration."""
        document = to_sarif(DEVICE, [make_finding()])
        assert not [pointer for pointer, _ in walk(document) if "/fixes/" in pointer]

    def test_the_default_configuration_carries_the_rules_severity(self) -> None:
        rule = run_of([make_finding(severity="medium")])["tool"]["driver"]["rules"][0]
        assert rule["defaultConfiguration"] == {"level": "warning"}


class TestDocumentStructure:
    def test_the_root_declares_the_only_version_the_schema_accepts(self) -> None:
        document = to_sarif(DEVICE, [make_finding()])
        assert document["version"] == SARIF_VERSION == "2.1.0"
        assert document["$schema"].endswith("sarif-schema-2.1.0.json")
        assert set(document) == {"$schema", "version", "runs"}

    def test_the_driver_names_itself_and_its_version(self) -> None:
        driver = run_of([make_finding()])["tool"]["driver"]
        assert driver["name"] == "PRAMAN"
        assert driver["version"] == driver["semanticVersion"]
        assert "informationUri" not in driver

    def test_the_automation_id_identifies_the_device_and_the_mode(self) -> None:
        details = run_of([make_finding()])["automationDetails"]
        assert details["id"] == "praman/simulate/core-rtr-01"
        assert "No ledger record was written" in details["description"]["text"]

    def test_an_audit_with_no_findings_is_a_valid_empty_run(self) -> None:
        """A config no rule applied to is an outcome, not an error."""
        run = run_of([])
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
        assert run["properties"]["pramanFindingsTotal"] == 0

    def test_the_device_context_reaches_the_run_properties(self) -> None:
        properties = run_of([make_finding()])["properties"]
        assert properties["pramanVendor"] == "cisco_ios"
        assert properties["pramanOsFamily"] == "ios"
        assert properties["pramanOsVersion"] == "15.7(3)M"

    @pytest.mark.parametrize("field", DEVICE_FIELDS)
    def test_a_missing_device_field_names_itself(self, field: str) -> None:
        partial = {k: v for k, v in DEVICE.items() if k != field}
        with pytest.raises(ExportError, match=field):
            to_sarif(partial, [make_finding()])

    def test_a_rogue_result_string_is_rejected_at_the_model_boundary(self) -> None:
        """A dict row carrying a non-XCCDF result never reaches the exporter."""
        rogue = make_finding().model_dump(mode="json")
        rogue["result"] = "compliant"
        with pytest.raises(ValidationError, match="notchecked"):
            to_sarif(DEVICE, [rogue])

    def test_a_result_the_tables_do_not_cover_is_refused(self) -> None:
        """The guard behind that one: a tenth enum value must not export silently.

        Called directly because it is unreachable through ``to_sarif`` — Pydantic
        rejects an out-of-enum string first, and ``Finding.result`` is typed. What it
        protects against is a future ``Result`` member added without updating
        ``OBJECTIVE_STATUS`` or ``NO_VERDICT_REMARK``, which the completeness test
        above catches at the table level and this catches at the call site.
        """
        with pytest.raises(ExportError, match="XCCDF 9-value enum"):
            result_value(SimpleNamespace(result="compliant", control_id="V-215844"))

    def test_every_custom_property_key_is_namespaced(self) -> None:
        """``propertyBag`` is open, so unprefixed keys would collide with a consumer's."""
        document = to_sarif(DEVICE, [make_finding()])
        for pointer, _ in walk(document):
            parts = pointer.split("/")
            if "properties" in parts:
                key = parts[parts.index("properties") + 1]
                if not key.isdigit():
                    assert key.startswith("praman"), f"{pointer} is not namespaced"
