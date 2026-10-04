"""Registration must produce real, role-gated sessions, not just a users row."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from backend.app import config
from backend.app.auth import COOKIE_NAME, current_principal, verify_password
from backend.app.main import app
from backend.app.state import STATE

PASSWORD = "judge-demo-passphrase"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SIGNUP_ENABLED", True)
    monkeypatch.setattr(STATE, "db_path", tmp_path / "signup.db")
    saved = app.dependency_overrides.pop(current_principal, None)
    STATE.learned.invalidate()
    try:
        with TestClient(app) as instance:
            yield instance
    finally:
        if saved is not None:
            app.dependency_overrides[current_principal] = saved
        STATE.learned.invalidate()


def register(client, username="judge.test", role="approver", password=PASSWORD):
    return client.post("/auth/signup", json={
        "username": username, "role": role, "password": password,
    })


@pytest.mark.parametrize("role", ["viewer", "auditor", "approver"])
def test_signup_from_empty_database_signs_in_with_chosen_permissions(client, role):
    response = register(client, role=role)
    assert response.status_code == 201, response.text
    session = response.json()
    assert session["username"] == "judge.test"
    assert session["role"] == role
    cookie = response.headers["set-cookie"].lower()
    assert COOKIE_NAME in cookie and "httponly" in cookie and "samesite=strict" in cookie
    headers = {"Authorization": f"Bearer {session['token']}"}
    identity = client.get("/auth/whoami", headers=headers).json()
    assert identity["role"] == role
    assert identity["may_ingest"] == (role != "viewer")
    assert identity["may_commit"] == (role == "approver")
    assert client.get("/devices", headers=headers).status_code == 200
    refused = client.post("/audit/commit", headers=headers, json={"device_id": "missing"})
    assert refused.status_code == (404 if role == "approver" else 403)

    conn = STATE.connect()
    try:
        user = conn.execute("SELECT * FROM users WHERE username = 'judge.test'").fetchone()
        assert user["password_hash"] != PASSWORD
        assert verify_password(PASSWORD, user["password_hash"])
        logged = conn.execute(
            "SELECT actor FROM access_log WHERE path = '/auth/signup'"
        ).fetchone()
        assert logged["actor"] == "judge.test"
    finally:
        conn.close()

    # The new account can log in again, and logout revokes the signup token.
    assert client.post("/auth/login", json={
        "username": "judge.test", "password": PASSWORD,
    }).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 200
    assert client.get("/auth/whoami", headers=headers).status_code == 401


def test_signup_cookie_allows_download_style_get_but_not_state_changes(client):
    assert register(client).status_code == 201
    assert client.get("/devices").status_code == 200
    assert client.post("/audit/commit", json={"device_id": "missing"}).status_code == 401


def test_duplicate_username_cannot_replace_password_or_role(client):
    assert register(client, role="viewer").status_code == 201
    assert register(client, role="approver", password="replacement-password").status_code == 409
    response = client.post("/auth/login", json={"username": "judge.test", "password": PASSWORD})
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"


def test_concurrent_signups_claim_a_username_once(client):
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: register(client), range(2)))
    assert sorted(response.status_code for response in responses) == [201, 409]


@pytest.mark.parametrize("changes,status", [
    ({"username": "service:judge"}, 400),
    ({"username": "Judge Name"}, 400),
    ({"username": "../judge"}, 400),
    ({"username": "ab"}, 422),
    ({"role": "admin"}, 422),
    ({"password": "short"}, 422),
    ({"password": "x" * 513}, 422),
])
def test_invalid_registration_creates_no_account(client, changes, status):
    payload = {"username": "judge.test", "role": "approver", "password": PASSWORD} | changes
    response = client.post("/auth/signup", json=payload)
    assert response.status_code == status, response.text
    conn = STATE.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    finally:
        conn.close()


def test_signup_policy_and_disabled_registration_agree(client, monkeypatch):
    options = client.get("/auth/options").json()
    assert options["signup_enabled"]
    assert options["roles"] == ["viewer", "auditor", "approver"]
    monkeypatch.setattr(config, "SIGNUP_ENABLED", False)
    options = client.get("/auth/options").json()
    assert not options["signup_enabled"]
    assert options["roles"] == []
    assert register(client).status_code == 403
