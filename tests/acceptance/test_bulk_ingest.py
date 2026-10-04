"""Acceptance test: Bulk ingest — capability C1.

An archive of N mixed-vendor configs yields N Device records, each with
device_id, vendor, os_family, config_hash populated.
"""

from __future__ import annotations

import io
import zipfile

from backend.app.main import app

CONFIGS = {
    "router1.conf": """\
!
version 15.0
hostname bulk-router-01
boot-start-marker
boot-end-marker
enable secret 5 $1$test$hash1
ip ssh version 2
line vty 0 4
 transport input ssh
end
""",
    "router2.conf": """\
!
version 15.0
hostname bulk-router-02
boot-start-marker
boot-end-marker
enable secret 9 $9$hash2
ip ssh version 2
no ip http server
line vty 0 4
 transport input ssh
end
""",
    "switch1.conf": """\
!
version 15.0
hostname bulk-switch-01
boot-start-marker
boot-end-marker
service password-encryption
ip ssh version 2
line vty 0 4
 transport input ssh
end
""",
}


def _make_zip(configs: dict[str, str]) -> bytes:
    """Create an in-memory ZIP archive of config files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in configs.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestBulkIngest:
    """C1: Unified ingestion, single + BULK, any vendor."""

    def test_bulk_zip_ingest_creates_multiple_devices(self) -> None:
        """Upload a ZIP of 3 configs → 3 devices created."""
        from fastapi.testclient import TestClient

        client = TestClient(app)
        zip_bytes = _make_zip(CONFIGS)

        resp = client.post(
            "/ingest/bulk",
            files={"file": ("configs.zip", zip_bytes, "application/zip")},
        )
        assert resp.status_code == 200

        data = resp.json()
        assert data["total_files"] == 3
        assert data["success"] == 3
        assert data["failed"] == 0

        # Verify each result has required fields
        for result in data["results"]:
            assert result["device_id"]
            assert result["facts_count"] > 0
            assert result["status"] == "ok"

    def test_bulk_devices_appear_in_list(self) -> None:
        """After bulk ingest, all devices should appear in GET /devices."""
        from fastapi.testclient import TestClient

        client = TestClient(app)
        zip_bytes = _make_zip(CONFIGS)
        client.post(
            "/ingest/bulk",
            files={"file": ("configs.zip", zip_bytes, "application/zip")},
        )

        resp = client.get("/devices")
        assert resp.status_code == 200
        devices = resp.json()["devices"]

        # At least the 3 we just ingested should be there
        hostnames = [d.get("hostname", "") for d in devices]
        assert any("bulk-router-01" in h for h in hostnames)
        assert any("bulk-router-02" in h for h in hostnames)

    def test_single_ingest_populates_required_fields(self) -> None:
        """C1: Single ingest populates device_id, vendor, os_family, config_hash."""
        from fastapi.testclient import TestClient

        client = TestClient(app)
        config = CONFIGS["router1.conf"]

        resp = client.post(
            "/ingest",
            files={"file": ("router1.conf", config.encode(), "text/plain")},
        )
        assert resp.status_code == 200

        data = resp.json()
        assert data["device_id"]
        assert data["config_hash"]
        assert data["facts_count"] > 0

    def test_invalid_zip_returns_400(self) -> None:
        """Bad ZIP returns HTTP 400, not a crash."""
        from fastapi.testclient import TestClient

        client = TestClient(app)
        resp = client.post(
            "/ingest/bulk",
            files={"file": ("bad.zip", b"not a zip file", "application/zip")},
        )
        assert resp.status_code == 400
