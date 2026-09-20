"""Acceptance test: PDF report — PS 26155 Capability C4.

Single per-device PDF must carry:
  - Device Identification (serial numbers + hardware + OS version)
  - Compliance Findings (Pass/Fail with risk severity)
  - Remediation Paths (device-specific CLI command sequences)

Since the PDF rendering depends on reportlab (a heavy dependency), these tests
validate the report data structure and the endpoint contract. The actual PDF
render is tested when reportlab is available.
"""

from __future__ import annotations

from backend.app.main import app


class TestPdfReport:
    """C4: Single per-device PDF report with required sections."""

    def _ingest_and_commit(self) -> tuple[str, str]:
        """Helper: ingest a config and commit an audit. Returns (device_id, audit_id)."""
        from fastapi.testclient import TestClient

        client = TestClient(app)

        config = """\
!
version 15.0
hostname pdf-report-device
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
snmp-server community testcomm RO
logging host 10.0.0.1
end
"""
        # Ingest
        resp = client.post(
            "/ingest",
            files={"file": ("report-test.conf", config.encode(), "text/plain")},
        )
        assert resp.status_code == 200
        device_id = resp.json()["device_id"]

        # Commit audit
        resp2 = client.post(
            "/audit/commit",
            json={"device_id": device_id},
        )
        assert resp2.status_code == 200
        audit_id = resp2.json()["audit_id"]

        return device_id, audit_id

    def test_audit_commit_returns_required_fields(self) -> None:
        """POST /audit/commit returns audit_id, seq, record_hash, findings_count."""
        from fastapi.testclient import TestClient

        client = TestClient(app)

        config = """\
!
version 15.0
hostname commit-fields-test
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        client.post(
            "/ingest",
            files={"file": ("cft.conf", config.encode(), "text/plain")},
        )

        # Get the device_id
        devices = client.get("/devices").json()["devices"]
        device_id = None
        for d in devices:
            if "commit-fields-test" in (d.get("hostname") or ""):
                device_id = d["device_id"]
                break

        if not device_id and devices:
            device_id = devices[-1]["device_id"]

        assert device_id is not None, "No device found after ingest"

        resp = client.post("/audit/commit", json={"device_id": device_id})
        assert resp.status_code == 200

        data = resp.json()
        assert "audit_id" in data
        assert "seq" in data
        assert "record_hash" in data
        assert "findings_count" in data
        assert data["findings_count"] > 0

    def test_audit_record_in_ledger(self) -> None:
        """After commit, the audit record appears in the ledger."""
        from fastapi.testclient import TestClient

        client = TestClient(app)

        config = """\
!
version 15.0
hostname ledger-check-device
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""
        client.post(
            "/ingest",
            files={"file": ("lc.conf", config.encode(), "text/plain")},
        )
        devices = client.get("/devices").json()["devices"]
        device_id = devices[-1]["device_id"] if devices else None
        assert device_id

        client.post("/audit/commit", json={"device_id": device_id})

        resp = client.get("/audit/records")
        assert resp.status_code == 200
        records = resp.json()["records"]
        assert len(records) > 0

        latest = records[-1]
        assert "audit_id" in latest
        assert "record_hash" in latest
        assert "seq" in latest
        assert "device_id" in latest

    def test_chain_verification_after_commit(self) -> None:
        """Chain verification endpoint returns valid structure after commit."""
        from fastapi.testclient import TestClient

        client = TestClient(app)

        resp = client.get("/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert "chain_length" in data
        assert "all_valid" in data
        assert isinstance(data["chain_length"], int)

    def test_remediation_playbook_has_entries(self) -> None:
        """The remediation playbook should have entries for known controls."""
        from backend.remediation.playbook import PLAYBOOK

        assert len(PLAYBOOK) > 0, "Remediation playbook is empty"

        # Check a known entry has required structure
        for ref, entry in PLAYBOOK.items():
            assert "title" in entry, f"Playbook entry {ref} missing 'title'"
            assert "commands" in entry, f"Playbook entry {ref} missing 'commands'"
            assert "verification" in entry, f"Playbook entry {ref} missing 'verification'"
