"""Test: the OSCAL Assessment Results export — the document that leaves the building.

Three claims are worth testing here, and they are not the obvious "does it produce
JSON" one.

**Completeness over the XCCDF enum.** A ninth result value that no branch handles
would export as a silently absent verdict — the single worst failure mode for a
compliance document, because the recipient cannot tell a missing control from a
passing one. :class:`TestEveryResultValueIsHandled` walks
``Result`` itself rather than a hand-written list, so adding a tenth value breaks
this file instead of shipping a blank.

**Determinism.** Every id in the document is a version-5 UUID over the ledger
record hash. If that ever regresses to ``uuid4``, a GRC platform ingesting the same
signed audit twice sees two unrelated assessments. Nothing else in the suite would
notice, because both documents would be individually valid.

**Refusal.** ``ExportError`` exists so that a document which would misrepresent an
audit is never emitted at all. Each refusal has a test, because the tempting
"fix" for every one of them is a default value that quietly invents a fact.

Structural conformance is asserted against the ``required`` lists read out of
``oscal_assessment-results_schema.json`` v1.2.3. The schema itself is not vendored:
it is 152 KB of third-party JSON, and the useful assertions are the handful of
requirements this exporter can actually violate. Full validation against the
publisher's file is ``scripts/check_export_conformance.py``, run as a documented
manual step (MANUAL_COMMANDS.md Step 14) because it needs that download.
"""

from __future__ import annotations

import json
import re

import pytest

from backend.canonical.findings import Finding, Result
from backend.canonical.models import CanonicalFact
from backend.core_errors import ExportError
from backend.export.ids import oscal_token
from backend.export.oscal import AUDIT_FIELDS, OSCAL_VERSION, to_oscal_ar
from backend.export.oscal_mapping import NO_VERDICT_REMARK, OBJECTIVE_STATUS, RISK_STATUS

#: OSCAL's own ``UUIDDatatype`` pattern, verbatim from the v1.2.3 schema. The
#: ``[45]`` and ``[89ABab]`` classes are the whole point: they are why ``uuid5``
#: is usable here and why a hand-rolled hex digest would not be.
UUID_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
)

RECORD = {
    "audit_id": "AUD-20260909-0001",
    "device_id": "core-rtr-01",
    "config_hash": "sha256:" + "3" * 64,
    "created_at": "2026-09-09T04:15:00+00:00",
    "actor": "auditor@example.test",
    "seq": 18,
    "prev_hash": "b" * 64,
    "record_hash": "c" * 64,
    "merkle_root": "d" * 64,
    "signature": "e" * 128,
}

DEVICE = {
    "device_id": "core-rtr-01",
    "vendor": "cisco_ios",
    "os_family": "ios",
    "os_version": "15.7(3)M",
    "hostname": "core-rtr-01.example.test",
}


def make_finding(
    result: Result | str = Result.FAIL,
    *,
    control_id: str = "V-215844",
    framework: str = "DISA_STIG",
    benchmark: str = "Cisco IOS Router NDM STIG",
    benchmark_version: str = "V3R7",
    severity: str = "high",
    evidence: bool = True,
) -> Finding:
    """One finding, with real evidence unless a test needs the empty case."""
    facts = (
        [
            CanonicalFact(
                path="mgmt.ssh.version",
                value=2,
                present=True,
                source_file="core-rtr-01.conf",
                line_start=42,
                line_end=42,
                raw_text="ip ssh version 2",
                parser_id="cisco_ios",
                confidence=1.0,
            )
        ]
        if evidence
        else []
    )
    return Finding(
        control_id=control_id,
        framework=framework,
        benchmark=benchmark,
        benchmark_version=benchmark_version,
        title="SSH must be version 2",
        result=result if isinstance(result, Result) else Result(result),
        severity=severity,
        evidence=facts,
        rationale="The device negotiates SSH version 2 only.",
        remediation_ref="stig-ndm-v215844-remediation",
        references={"cci": ["CCI-000068"], "nist_800_53": ["AC-17"]},
    )


def all_elements(document: dict) -> list[dict]:
    """Every observation, finding and risk in `document`, flattened."""
    out: list[dict] = []
    for result in document["assessment-results"]["results"]:
        out += result["observations"]
        out += result.get("findings", [])
        out += result.get("risks", [])
    return out


class TestEveryResultValueIsHandled:
    """The nine-value enum, walked from the enum rather than from a list."""

    def test_every_result_value_maps_somewhere(self) -> None:
        """No value falls between the decided table and the no-verdict table."""
        for value in Result:
            assert (value.value in OBJECTIVE_STATUS) or (value.value in NO_VERDICT_REMARK), (
                f"Result.{value.name} maps to neither an OSCAL Objective Status nor "
                "a documented no-verdict remark. A value with no branch exports as "
                "an absent verdict, which a recipient reads as a pass."
            )

    def test_no_value_is_in_both_tables(self) -> None:
        """A decided result must not also carry a 'no verdict' remark."""
        assert not set(OBJECTIVE_STATUS) & set(NO_VERDICT_REMARK)

    @pytest.mark.parametrize("value", [r.value for r in Result])
    def test_each_value_exports_exactly_one_observation(self, value: str) -> None:
        document = to_oscal_ar(RECORD, [make_finding(value)], DEVICE)
        result = document["assessment-results"]["results"][0]
        assert len(result["observations"]) == 1
        assert result["observations"][0]["props"][1] == {
            "name": "praman-result",
            "ns": "urn:praman:oscal",
            "value": value,
        }

    @pytest.mark.parametrize("value", [r.value for r in Result])
    def test_finding_element_exists_only_for_a_decided_result(self, value: str) -> None:
        """The §13.2 departure, asserted: no verdict means no finding element."""
        result = to_oscal_ar(RECORD, [make_finding(value)], DEVICE)["assessment-results"][
            "results"
        ][0]
        emitted = result.get("findings", [])
        if value in OBJECTIVE_STATUS:
            assert len(emitted) == 1
            state, reason = OBJECTIVE_STATUS[value]
            assert emitted[0]["target"]["status"] == {"state": state, "reason": reason}
        else:
            assert emitted == [], (
                f"result '{value}' produced an OSCAL finding element. "
                "finding-target.status has only satisfied/not-satisfied, so emitting "
                "one here would fabricate a verdict nobody reached."
            )

    @pytest.mark.parametrize("value", [r.value for r in Result])
    def test_risk_exists_only_for_fail_and_fixed(self, value: str) -> None:
        result = to_oscal_ar(RECORD, [make_finding(value)], DEVICE)["assessment-results"][
            "results"
        ][0]
        risks = result.get("risks", [])
        assert len(risks) == (1 if value in RISK_STATUS else 0)
        if risks:
            assert risks[0]["status"] == RISK_STATUS[value]

    def test_notapplicable_carries_its_implementation_status(self) -> None:
        """The information §13.2 wanted survives — as a property, not a verdict."""
        result = to_oscal_ar(
            RECORD, [make_finding(Result.NOTAPPLICABLE)], DEVICE
        )["assessment-results"]["results"][0]
        props = {p["name"]: p["value"] for p in result["observations"][0]["props"]}
        assert props["praman-implementation-status"] == "not-applicable"
        assert "remarks" in result["observations"][0]


class TestDeterminism:
    """Re-exporting one ledger record must reproduce the same bytes."""

    def test_two_exports_of_one_record_are_byte_identical(self) -> None:
        findings = [make_finding(Result.FAIL), make_finding(Result.PASS, control_id="V-215845")]
        first = json.dumps(to_oscal_ar(RECORD, findings, DEVICE), sort_keys=False)
        second = json.dumps(to_oscal_ar(RECORD, findings, DEVICE), sort_keys=False)
        assert first == second

    def test_a_different_record_produces_different_ids(self) -> None:
        """Two audits of the same control must not collide into one assessment."""
        other = dict(RECORD, record_hash="9" * 64, audit_id="AUD-20260909-0002")
        first = to_oscal_ar(RECORD, [make_finding()], DEVICE)
        second = to_oscal_ar(other, [make_finding()], DEVICE)
        assert first["assessment-results"]["uuid"] != second["assessment-results"]["uuid"]

    def test_dict_findings_and_model_findings_agree(self) -> None:
        """``finding_from_row`` projections must export identically to models."""
        finding = make_finding()
        as_dict = finding.model_dump(mode="json")
        assert json.dumps(to_oscal_ar(RECORD, [finding], DEVICE)) == json.dumps(
            to_oscal_ar(RECORD, [as_dict], DEVICE)
        )

    def test_every_uuid_satisfies_oscals_own_pattern(self) -> None:
        document = to_oscal_ar(
            RECORD,
            [make_finding(value) for value in (Result.PASS, Result.FAIL, Result.NOTCHECKED)],
            DEVICE,
        )
        uuids = [document["assessment-results"]["uuid"]]
        uuids += [r["uuid"] for r in document["assessment-results"]["results"]]
        uuids += [element["uuid"] for element in all_elements(document)]
        uuids += [r["uuid"] for r in document["assessment-results"]["back-matter"]["resources"]]
        assert uuids
        for value in uuids:
            assert UUID_PATTERN.match(value), f"'{value}' is not an OSCAL UUIDDatatype"


class TestRefusals:
    """Every case where emitting something would be worse than emitting nothing."""

    @pytest.mark.parametrize("field", AUDIT_FIELDS)
    def test_a_missing_ledger_field_names_itself(self, field: str) -> None:
        partial = {k: v for k, v in RECORD.items() if k != field}
        with pytest.raises(ExportError, match=field):
            to_oscal_ar(partial, [make_finding()], DEVICE)

    def test_an_audit_with_no_findings_is_refused(self) -> None:
        with pytest.raises(ExportError, match="no findings"):
            to_oscal_ar(RECORD, [], DEVICE)

    @pytest.mark.parametrize(
        "timestamp", ["2026-09-09T04:15:00", "2026-09-09 04:15:00+00:00", "", "2026-09-09"]
    )
    def test_a_timestamp_oscal_would_reject_is_refused(self, timestamp: str) -> None:
        with pytest.raises(ExportError, match="DateTimeWithTimezone"):
            to_oscal_ar(dict(RECORD, created_at=timestamp), [make_finding()], DEVICE)

    def test_a_timestamp_with_an_offset_is_accepted(self) -> None:
        """A non-UTC offset is valid OSCAL and must not be rejected as a side effect."""
        document = to_oscal_ar(
            dict(RECORD, created_at="2026-09-09T09:45:00+05:30"), [make_finding()], DEVICE
        )
        assert document["assessment-results"]["metadata"]["last-modified"].endswith("+05:30")


class TestControlIdentifiers:
    """A publisher's id is never rewritten, only ever accompanied."""

    def test_a_cis_numeric_id_is_prefixed_not_rewritten(self) -> None:
        token, adjusted = oscal_token("1.1.4", "CIS")
        assert (token, adjusted) == ("cis-1.1.4", True)

    def test_a_disa_id_passes_through_untouched(self) -> None:
        assert oscal_token("V-215844", "DISA_STIG") == ("V-215844", False)

    def test_the_verbatim_id_travels_beside_an_adjusted_token(self) -> None:
        finding = make_finding(
            Result.FAIL, control_id="1.1.4", framework="CIS", benchmark="CIS Cisco IOS 15"
        )
        result = to_oscal_ar(RECORD, [finding], DEVICE)["assessment-results"]["results"][0]
        target = result["findings"][0]["target"]
        assert target["target-id"] == "cis-1.1.4"
        assert "TokenDatatype" in target["remarks"]
        props = {p["name"]: p["value"] for p in result["findings"][0]["props"]}
        assert props["praman-control-id"] == "1.1.4"
        selection = result["reviewed-controls"]["control-selections"][0]
        assert selection["include-controls"] == [{"control-id": "cis-1.1.4"}]


class TestDocumentStructure:
    """The ``required`` lists this exporter is capable of violating."""

    def test_metadata_carries_the_four_required_members(self) -> None:
        metadata = to_oscal_ar(RECORD, [make_finding()], DEVICE)["assessment-results"][
            "metadata"
        ]
        assert set(metadata) >= {"title", "last-modified", "version", "oscal-version"}
        assert metadata["oscal-version"] == OSCAL_VERSION
        assert metadata["version"] == RECORD["audit_id"]

    def test_import_ap_resolves_to_a_back_matter_resource(self) -> None:
        """The required href must not dangle — an air-gapped reader cannot fetch it."""
        results = to_oscal_ar(RECORD, [make_finding()], DEVICE)["assessment-results"]
        href = results["import-ap"]["href"]
        assert href.startswith("#")
        resources = {r["uuid"] for r in results["back-matter"]["resources"]}
        assert href[1:] in resources

    def test_the_ledger_identity_is_published_in_metadata(self) -> None:
        """Without these a recipient cannot re-verify what it was handed."""
        props = {
            p["name"]: p["value"]
            for p in to_oscal_ar(RECORD, [make_finding()], DEVICE)["assessment-results"][
                "metadata"
            ]["props"]
        }
        assert props["praman-record-hash"] == RECORD["record_hash"]
        assert props["praman-merkle-root"] == RECORD["merkle_root"]
        assert props["praman-signature"] == RECORD["signature"]
        assert props["praman-ledger-seq"] == "18"
        assert props["praman-actor"] == RECORD["actor"]

    def test_an_unsigned_record_says_unsigned(self) -> None:
        props = {
            p["name"]: p["value"]
            for p in to_oscal_ar(dict(RECORD, signature=""), [make_finding()], DEVICE)[
                "assessment-results"
            ]["metadata"]["props"]
        }
        assert props["praman-signature"] == "unsigned"

    def test_one_result_per_benchmark(self) -> None:
        """A control id only means something inside its own catalog."""
        findings = [
            make_finding(Result.FAIL),
            make_finding(Result.PASS, control_id="V-215845"),
            make_finding(
                Result.FAIL,
                control_id="1.1.4",
                framework="CIS",
                benchmark="CIS Cisco IOS 15",
                benchmark_version="v4.1.1",
            ),
        ]
        results = to_oscal_ar(RECORD, findings, DEVICE)["assessment-results"]["results"]
        assert len(results) == 2
        titles = sorted(r["title"] for r in results)
        assert titles == ["CIS Cisco IOS 15 v4.1.1", "Cisco IOS Router NDM STIG V3R7"]

    def test_reviewed_controls_includes_undecided_controls(self) -> None:
        """Coverage must not be improvable by declining to check something."""
        findings = [
            make_finding(Result.PASS),
            make_finding(Result.NOTCHECKED, control_id="V-215845"),
            make_finding(Result.NOTCHECKED, control_id="V-215846"),
        ]
        result = to_oscal_ar(RECORD, findings, DEVICE)["assessment-results"]["results"][0]
        selection = result["reviewed-controls"]["control-selections"][0]
        assert len(selection["include-controls"]) == 3
        props = {p["name"]: p["value"] for p in result["props"]}
        assert props["praman-controls-reviewed"] == "3"
        assert props["praman-controls-decided"] == "1"
        assert props["praman-count-notchecked"] == "2"

    def test_observations_and_findings_are_cross_referenced(self) -> None:
        result = to_oscal_ar(RECORD, [make_finding(Result.FAIL)], DEVICE)[
            "assessment-results"
        ]["results"][0]
        finding = result["findings"][0]
        assert finding["related-observations"] == [
            {"observation-uuid": result["observations"][0]["uuid"]}
        ]
        assert finding["related-risks"] == [{"risk-uuid": result["risks"][0]["uuid"]}]
        assert result["risks"][0]["related-observations"] == [
            {"observation-uuid": result["observations"][0]["uuid"]}
        ]

    def test_evidence_carries_file_and_line_numbers(self) -> None:
        """Evidence without provenance is an assertion, not evidence."""
        observation = to_oscal_ar(RECORD, [make_finding()], DEVICE)["assessment-results"][
            "results"
        ][0]["observations"][0]
        assert "core-rtr-01.conf:42" in observation["description"]
        assert "ip ssh version 2" in observation["description"]

    def test_a_finding_with_no_evidence_says_so(self) -> None:
        observation = to_oscal_ar(RECORD, [make_finding(evidence=False)], DEVICE)[
            "assessment-results"
        ]["results"][0]["observations"][0]
        assert "No canonical facts" in observation["description"]

    def test_the_device_identity_reaches_the_document(self) -> None:
        props = {
            p["name"]: p["value"]
            for p in to_oscal_ar(RECORD, [make_finding()], DEVICE)["assessment-results"][
                "metadata"
            ]["props"]
        }
        assert props["praman-device-vendor"] == "cisco_ios"
        assert props["praman-device-os-version"] == "15.7(3)M"

    def test_a_missing_device_row_is_not_fatal(self) -> None:
        """The device table is a convenience; the ledger record is the source."""
        document = to_oscal_ar(RECORD, [make_finding()], None)
        assert document["assessment-results"]["results"][0]["description"].startswith(
            "PRAMAN evaluated device 'core-rtr-01' against"
        )
