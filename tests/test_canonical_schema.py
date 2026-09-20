"""Test: Canonical Model schema contract.

Gate for P1: validates round-trip serialisation, the XCCDF 9-value enum,
and JSON Schema emission.
"""

from __future__ import annotations

import pytest

from backend.canonical.findings import Finding, Result, build_summary
from backend.canonical.models import (
    CanonicalFact,
    Device,
    OsFamily,
    Vendor,
    compute_config_hash,
)


def _sample_fact() -> CanonicalFact:
    return CanonicalFact(
        path="mgmt.ssh.version",
        value=2,
        present=True,
        source_file="test.conf",
        line_start=10,
        line_end=10,
        raw_text="ip ssh version 2",
        parser_id="test@0.0.0",
        confidence=1.0,
    )


def _sample_device() -> Device:
    return Device(
        device_id="test-sw-01",
        vendor=Vendor.cisco_ios,
        os_family=OsFamily.ios,
        hostname="test-sw-01",
        serials=["FOC1234X5YZ"],
        hardware=["WS-C2960-24TT-L"],
        os_version="15.0(2)SE11",
        source_file="test.conf",
        config_hash="sha256:abc123",
        ingested_at="2026-01-01T00:00:00+00:00",
    )


def _sample_finding() -> Finding:
    return Finding(
        control_id="V-215844",
        framework="DISA_STIG",
        benchmark="Cisco IOS XE Router NDM STIG",
        benchmark_version="V3R7",
        title="SSH version 2 required",
        result=Result.PASS,
        severity="high",
        evidence=[_sample_fact()],
        rationale="SSH v2 is configured.",
        remediation_ref=None,
        references={"nist_800_53": ["AC-17(2)"]},
    )


class TestCanonicalFact:
    def test_round_trip_json(self) -> None:
        fact = _sample_fact()
        json_str = fact.model_dump_json()
        restored = CanonicalFact.model_validate_json(json_str)
        assert restored == fact

    def test_provenance_fields_all_present(self) -> None:
        fact = _sample_fact()
        d = fact.model_dump()
        for field in ("source_file", "line_start", "line_end", "raw_text", "parser_id", "confidence"):
            assert field in d, f"Missing provenance field: {field}"

    def test_confidence_1_for_deterministic(self) -> None:
        fact = _sample_fact()
        assert fact.confidence == 1.0


class TestDevice:
    def test_serials_is_list(self) -> None:
        device = _sample_device()
        assert isinstance(device.serials, list)

    def test_hardware_is_list(self) -> None:
        device = _sample_device()
        assert isinstance(device.hardware, list)

    def test_round_trip_json(self) -> None:
        device = _sample_device()
        json_str = device.model_dump_json()
        restored = Device.model_validate_json(json_str)
        assert restored.device_id == device.device_id
        assert restored.serials == device.serials
        assert restored.hardware == device.hardware


class TestResult:
    def test_exactly_9_values(self) -> None:
        """The XCCDF enum has exactly 9 values — never a 10th."""
        assert len(Result) == 9

    def test_all_expected_values_present(self) -> None:
        expected = {
            "pass", "fail", "error", "unknown",
            "notapplicable", "notchecked", "notselected",
            "informational", "fixed",
        }
        actual = {r.value for r in Result}
        assert actual == expected

    def test_rejects_10th_value(self) -> None:
        """Must reject any value outside the XCCDF 9-value enum."""
        with pytest.raises(ValueError):
            Result("custom_result")

    def test_rejects_boolean(self) -> None:
        """Never invent a boolean — use the enum."""
        with pytest.raises(ValueError):
            Result("true")
        with pytest.raises(ValueError):
            Result("false")


class TestFinding:
    def test_round_trip(self) -> None:
        finding = _sample_finding()
        json_str = finding.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert restored.control_id == finding.control_id
        assert restored.result == finding.result

    def test_result_is_enum(self) -> None:
        finding = _sample_finding()
        assert isinstance(finding.result, Result)


class TestBuildSummary:
    def test_counts_by_result(self) -> None:
        findings = [_sample_finding()]
        summary = build_summary(findings)
        assert summary["total"] == 1
        assert summary["by_result"]["pass"] == 1


class TestConfigHash:
    def test_deterministic(self) -> None:
        data = b"hostname test-sw-01"
        h1 = compute_config_hash(data)
        h2 = compute_config_hash(data)
        assert h1 == h2

    def test_starts_with_sha256(self) -> None:
        h = compute_config_hash(b"test")
        assert h.startswith("sha256:")


class TestCanonicalVocabulary:
    """The authored path enum must cover everything the packs and rules use.

    ``canonical_paths.schema.json`` is authored, not generated — deriving it from
    the packs would make ``patterns._check_path`` vacuous, since a typo in a pack
    would become a new legal path. So the direction of the check is: the packs and
    rules may only reference what the schema already declares.

    This is the same check ``scripts/emit_canonical_schema.py --check`` performs.
    It lives here as well so that adding a pattern for an undeclared path fails
    the suite, rather than waiting for someone to remember the script.
    """

    def test_every_pack_and_rule_path_is_declared(self) -> None:
        from scripts.emit_canonical_schema import verify_paths_schema

        problems = verify_paths_schema()
        assert not problems, "canonical vocabulary problems:\n  " + "\n  ".join(problems)

    def test_generated_schema_is_not_stale(self) -> None:
        """``canonical.schema.json`` must match the pydantic models.

        The opposite direction from the enum: this file *is* generated, so a model
        change that nobody regenerated leaves a schema on disk that describes the
        previous release. Anything consuming it — the LLM's structured output, an
        external validator — would be checking against the wrong contract.
        """
        from scripts.emit_canonical_schema import (
            MAIN_SCHEMA_PATH,
            _render,
            build_main_schema,
        )

        assert MAIN_SCHEMA_PATH.exists(), f"{MAIN_SCHEMA_PATH.name} has not been emitted"
        # Read as text so the comparison is line-ending agnostic; the generator
        # pins LF on write, but a checkout could still normalise it.
        assert MAIN_SCHEMA_PATH.read_text(encoding="utf-8") == _render(build_main_schema()), (
            f"{MAIN_SCHEMA_PATH.name} is stale — run "
            "`python -m scripts.emit_canonical_schema`"
        )

    def test_vocabulary_enum_is_sorted_and_unique(self) -> None:
        """Deterministic order and no duplicates.

        ``canonical_paths_sorted()`` feeds the training GUI's picker and the GBNF
        grammar for tier 3. A duplicate would make the grammar's alternation
        ambiguous, and an unsorted enum makes every regeneration a noisy diff.
        """
        import json

        from backend.canonical.paths import SCHEMA_PATH

        enum = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["enum"]
        assert enum == sorted(enum)
        assert len(enum) == len(set(enum))
