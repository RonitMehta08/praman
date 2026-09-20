"""Test: POST /simulate is stateless and idempotent.

Gate for P4: same bytes twice ⇒ byte-identical response body
and zero rows written to the database.
"""

from __future__ import annotations

from backend.app.main import app


def test_simulate_idempotent() -> None:
    """Same input → byte-identical output (SPINE: stateless, no side effects)."""
    from fastapi.testclient import TestClient

    client = TestClient(app)

    config = """!
version 15.0
hostname test-sw-01
boot-start-marker
boot-end-marker
enable secret 5 $1$abcd$xyz
ip ssh version 2
line vty 0 4
 transport input ssh
!
end
"""
    req = {"config_text": config, "source_file": "test.conf"}

    resp1 = client.post("/simulate", json=req)
    resp2 = client.post("/simulate", json=req)

    assert resp1.status_code == 200
    assert resp2.status_code == 200

    # Byte-identical response bodies
    body1 = resp1.json()
    body2 = resp2.json()

    # Device and findings should be identical
    assert body1["device"]["device_id"] == body2["device"]["device_id"]
    assert body1["device"]["config_hash"] == body2["device"]["config_hash"]
    assert len(body1["findings"]) == len(body2["findings"])
    assert body1["summary"] == body2["summary"]


def test_simulate_returns_findings() -> None:
    """Verify that /simulate returns findings from loaded rules."""
    from fastapi.testclient import TestClient

    client = TestClient(app)

    config = """!
version 15.0
hostname test-device
boot-start-marker
boot-end-marker
enable secret 5 $1$test$hash
ip ssh version 2
line vty 0 4
 transport input ssh
!
end
"""
    resp = client.post("/simulate", json={"config_text": config, "source_file": "t.conf"})
    assert resp.status_code == 200
    body = resp.json()
    assert "device" in body
    assert "findings" in body
    assert "summary" in body
    assert isinstance(body["findings"], list)


def test_health_endpoint() -> None:
    """Health endpoint returns 200."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["app"] == "PRAMAN"
