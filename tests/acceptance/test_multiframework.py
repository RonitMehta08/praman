"""Acceptance test: Multi-framework evaluation — capability C3.

One Canonical Model evaluated against all four rule packs, each
Finding.framework set, Finding.result restricted to the XCCDF enum.
"""

from __future__ import annotations

from backend.app.main import app

# The XCCDF 9-value result enum (SPINE)
XCCDF_RESULTS = {
    "pass", "fail", "error", "unknown", "notapplicable",
    "notchecked", "notselected", "informational", "fixed",
}


class TestMultiFramework:
    """C3: Multi-framework deterministic engine (CIS + NIST 800-53 + DISA STIG + ISO 27001)."""

    def _simulate(self, config: str) -> dict:
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.post(
            "/simulate",
            json={"config_text": config, "source_file": "multifw.conf"},
        )
        assert resp.status_code == 200
        return resp.json()

    def test_findings_have_valid_frameworks(self) -> None:
        """Each finding's framework must be one of the four required frameworks."""
        config = """\
!
version 15.0
hostname multifw-test
boot-start-marker
boot-end-marker
enable secret 5 $1$test$hash
ip ssh version 2
aaa new-model
aaa authentication login default local
no ip http server
line vty 0 4
 transport input ssh
 exec-timeout 10 0
banner login ^
WARNING: Unauthorized access
^
snmp-server community public RO
logging host 10.0.0.1
ntp server 10.0.0.50
end
"""
        data = self._simulate(config)
        findings = data["findings"]

        # Must have findings (rules are loaded)
        assert len(findings) > 0, "No findings returned — check rules/ directory has YAML files"

        valid_frameworks = {"CIS", "NIST_800_53", "DISA_STIG", "ISO_27001"}
        frameworks_seen = set()

        for f in findings:
            assert f["framework"] in valid_frameworks, (
                f"Finding {f['control_id']} has invalid framework '{f['framework']}'"
            )
            frameworks_seen.add(f["framework"])

        # We should see at least 2 distinct frameworks (CIS + DISA_STIG at minimum)
        assert len(frameworks_seen) >= 2, (
            f"Only {frameworks_seen} seen — need at least 2 frameworks with rules"
        )

    def test_all_results_are_xccdf_enum(self) -> None:
        """Every Finding.result must be in the XCCDF 9-value enum."""
        config = """\
!
version 15.0
hostname xccdf-enum-test
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        data = self._simulate(config)
        findings = data["findings"]

        for f in findings:
            result = f["result"]
            if isinstance(result, dict):
                result = result.get("value", str(result))
            result_lower = str(result).lower()
            assert result_lower in XCCDF_RESULTS, (
                f"Finding {f['control_id']}: result '{result}' is not in XCCDF enum"
            )

    def test_findings_have_required_fields(self) -> None:
        """Each finding must have control_id, framework, title, result, severity."""
        config = """\
!
version 15.0
hostname fields-test
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        data = self._simulate(config)

        required_keys = {"control_id", "framework", "title", "result", "severity"}
        for f in data["findings"]:
            missing = required_keys - set(f.keys())
            assert not missing, (
                f"Finding {f.get('control_id', '?')} missing keys: {missing}"
            )

    def test_summary_has_by_result_breakdown(self) -> None:
        """Summary must include by_result with pass/fail/unknown counts."""
        config = """\
!
version 15.0
hostname summary-test
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        data = self._simulate(config)
        summary = data["summary"]

        assert "by_result" in summary
        assert "total" in summary
        assert summary["total"] > 0
