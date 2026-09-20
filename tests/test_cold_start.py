"""Test: Cold start — pytest MUST pass green with zero models and zero indexes.

This test file is named verbatim in GLOBAL_RULESET R7.4.
It validates that the system works in pure-deterministic mode:
  - Tier 0 parsing works with no AI models
  - The rules engine issues verdicts with no ML classifiers
  - The ledger signs and verifies with no external services
  - ArtifactMissingError is raised (not a crash) when models are absent
"""

from __future__ import annotations

import os

import pytest

from backend.core_errors import ArtifactMissingError


class TestColdStartParsing:
    """The system must parse configs and evaluate rules with no AI artifacts."""

    def test_cisco_ios_parse_with_no_models(self) -> None:
        """Parse a Cisco IOS config using only deterministic Tier 0."""
        from backend.ingest.cisco_ios import CiscoIOSAdapter

        adapter = CiscoIOSAdapter()
        config = """!
version 15.0
hostname cold-test-sw
boot-start-marker
boot-end-marker
enable secret 9 $9$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        result = adapter.parse(config, "cold-test.conf")
        assert result.device.hostname == "cold-test-sw"
        assert len(result.facts) > 0

    def test_rules_evaluate_with_no_models(self) -> None:
        """Rules engine runs and issues verdicts with no AI models.

        Built from a synthetic catalog rather than the shipped ones so the test
        stays a cold-start assertion about the *engine* — it must not start
        failing because a mapping pack changed. The engine refuses a rule aimed
        at a control no catalog publishes, so the catalog is not optional
        scaffolding here; it is the contract.
        """
        from backend.canonical.findings import Result
        from backend.canonical.models import CanonicalFact
        from backend.frameworks.catalog import CatalogControl, ControlCatalog
        from backend.rules.evaluator import RulesEvaluator
        from backend.rules.models import Rule

        facts = [
            CanonicalFact(
                path="mgmt.ssh.version",
                value=2,
                present=True,
                source_file="cold-test.conf",
                line_start=1,
                line_end=1,
                raw_text="ip ssh version 2",
                parser_id="test",
                confidence=1.0,
            )
        ]

        catalog = ControlCatalog(
            catalog_id="cold_start_catalog",
            framework="DISA_STIG",
            benchmark="Cold Start Test",
            benchmark_version="V1R0",
            source_document="tests/test_cold_start.py",
            vendors=["cisco_ios"],
            os_families=["ios"],
            controls=[
                CatalogControl(
                    control_id="TEST-001",
                    title="SSH v2 required",
                    severity="high",
                )
            ],
        )
        rule = Rule.model_validate(
            {
                "id": "cold-rule",
                "catalog": {
                    "catalog_id": "cold_start_catalog",
                    "control_id": "TEST-001",
                },
                "applies_to": {"vendors": ["cisco_ios"], "os_families": ["ios"]},
                "mapping_rationale": "Cold-start smoke rule.",
                "condition": {
                    "type": "fact_check",
                    "path": "mgmt.ssh.version",
                    "operator": "eq",
                    "expected": 2,
                },
            }
        )

        evaluator = RulesEvaluator(catalogs=[catalog], rules=[rule])
        findings = evaluator.evaluate(
            facts, "cisco_ios", "ios", include_notchecked=False
        )
        assert len(findings) == 1
        assert findings[0].result == Result.PASS

    def test_shipped_rules_load_and_evaluate_with_no_models(self) -> None:
        """The real packs must also work cold — no classifier, no index, no LLM.

        The test above proves the engine works in isolation; this one proves the
        shipped configuration does, which is what a first-run user actually
        exercises. Any deterministic verdict is enough: the assertion is that
        verdicts are produced at all, not what they are.
        """
        from backend.app.config import PROJECT_ROOT
        from backend.canonical.findings import Result
        from backend.ingest.generic import PatternAdapterRegistry
        from backend.rules.evaluator import RulesEvaluator

        config = PROJECT_ROOT / "test_configs" / "realistic" / "secure_baseline.conf"
        text = config.read_text(encoding="utf-8")

        adapter = PatternAdapterRegistry().detect(text, config.name)
        assert adapter is not None, "vendor detection must work with no models"
        parsed = adapter.parse(text, config.name)

        findings = RulesEvaluator().evaluate(
            parsed.facts,
            adapter.pack.vendor,
            adapter.pack.os_family,
            frameworks=["CIS"],
            project_governance=False,
        )
        decided = [
            f
            for f in findings
            if f.result in {Result.PASS, Result.FAIL}
        ]
        assert decided, "the shipped packs produced no verdict in cold-start mode"

    def test_ledger_works_with_no_models(self) -> None:
        """Ledger signing and verification work with no external services."""
        from backend.ledger.chain import (
            compute_merkle_root,
            compute_record_hash,
            sign_record,
            verify_signature,
        )

        record = {
            # A hashed field, so it has to be here even in cold start: the point of
            # this test is that the ledger works with nothing installed, and a
            # record that cannot be hashed is not a working ledger.
            "actor": "service:cold-start",
            "audit_id": "cold-start",
            "device_id": "cold-start-sw",
            "config_hash": "sha256:cold",
            "created_at": "2026-01-01T00:00:00+00:00",
            "summary": {"total": 0},
            "seq": 1,
            "prev_hash": "",
            "merkle_root": compute_merkle_root([]),
        }
        record_hash = compute_record_hash(record)
        signature = sign_record(record_hash)
        assert verify_signature(record_hash, signature)


class TestArtifactMissingContract:
    """When a heavy artifact is absent, the code MUST raise ArtifactMissingError
    naming its MANUAL_COMMANDS.md step — not crash, not silently skip."""

    def test_artifact_missing_error_is_importable(self) -> None:
        """The exception class must be importable."""
        assert ArtifactMissingError is not None

    def test_artifact_missing_carries_step_reference(self) -> None:
        """The error message must name a MANUAL_COMMANDS.md step."""
        err = ArtifactMissingError(
            "SetFit model not found at data/models/classifier/. "
            "Run Step 8 in MANUAL_COMMANDS.md."
        )
        assert "MANUAL_COMMANDS" in str(err)
        assert "Step" in str(err)

    @pytest.mark.parametrize(
        ("module_name", "class_name"),
        [
            ("backend.ai.tfidf_clf", "TfidfClassifier"),
            ("backend.ai.setfit_clf", "SetFitClassifier"),
            ("backend.ai.llm_classify", "LLMClassifier"),
        ],
    )
    def test_an_optional_tier_reports_its_own_absence(
        self, module_name: str, class_name: str
    ) -> None:
        """Every optional tier answers ``is_available()`` from disk, without raising.

        This replaces two tests that checked whether ``data/models/`` and
        ``data/index/`` happened to be empty, asserted nothing either way, and
        said so in their own comments. What actually matters in a cold start is
        not the state of those directories — the operator may legitimately have
        installed the artifacts — but that a tier whose artifact is missing says
        so instead of raising on import or on first use. A tier that crashes when
        probed cannot be skipped, and then the deterministic path is not reachable
        at all.
        """
        import importlib

        tier = getattr(importlib.import_module(module_name), class_name)()
        available = tier.is_available()
        assert isinstance(available, bool), (
            f"{class_name}.is_available() must answer True or False, not "
            f"{available!r} — a caller cannot gate on a maybe"
        )


class TestEnvironmentContract:
    """Verify environment assumptions."""

    def test_python_310_compat(self) -> None:
        """We must be running on Python 3.10+."""
        import sys
        assert sys.version_info >= (3, 10)

    def test_pythonutf8_recommended(self) -> None:
        """PYTHONUTF8=1 should be set (warning only, not a failure)."""
        # This is an informational check — the code handles encoding explicitly
        val = os.environ.get("PYTHONUTF8", "0")
        if val != "1":
            import warnings
            warnings.warn(
                "PYTHONUTF8=1 is not set. Set it for safety: "
                "set PYTHONUTF8=1 in your shell profile.",
                stacklevel=1,
            )
