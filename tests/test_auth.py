"""Test: the authentication gate, for real — no dependency override in sight.

Every other module in this suite runs behind ``conftest.authenticated_operator``,
which overrides ``current_principal`` and hands each test an approver. That is the
right trade for 1,100 tests about parsing and rules, and it means those tests
prove nothing at all about the gate itself: an override that always succeeds looks
identical to a gate that never refuses.

So this module drops the override and exercises the refusals — 401 with no
credential, 403 with the wrong role, 429 after repeated guessing, and the three
ways a live token stops working (logout, expiry, a disabled account).

Two of the assertions here are structural rather than behavioural, and they are
the ones that keep working when somebody adds a route next month:

* ``test_every_route_is_either_gated_or_deliberately_open`` reads the
  application's own dependency tree. A new endpoint with no gate fails the suite,
  which is the only mechanism that survives the author who forgets.
* ``test_one_override_covers_every_gate`` asserts that every gate resolves the
  *same* ``current_principal`` dependency. That is what makes the conftest
  override honest: if a route ever authenticated some other way, the rest of the
  suite would be testing a seam that route does not use, and nobody would notice.

Offline: no models, no network. Accounts are created with a deliberately low
PBKDF2 iteration count — see :data:`_CHEAP_ITERATIONS`.
"""

from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.auth import (
    COOKIE_NAME,
    LOGIN_FAILURE_THRESHOLD,
    MIN_PASSWORD_LENGTH,
    REQUIRE_APPROVER,
    REQUIRE_AUDITOR,
    REQUIRE_VIEWER,
    ROLE_APPROVER,
    ROLE_AUDITOR,
    ROLE_VIEWER,
    Principal,
    RequireRole,
    clear_login_failures,
    create_user,
    current_principal,
    disable_user,
    hash_password,
    known_actors,
    open_session,
    verify_password,
)
from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.app.main import app
from backend.app.state import STATE
from tests.conftest import walk_routes

FIXTURE = PROJECT_ROOT / "test_configs" / "realistic" / "secure_baseline.conf"

#: PBKDF2 rounds for the accounts below. The shipped default is 600,000 and takes
#: 0.209 s; this module logs in a dozen times, and paying 0.4 s per login to test
#: ``hashlib`` rather than the gate would make the suite slower for no assertion.
#: The iteration count is stored inside each hash, so a cheap fixture hash and a
#: real one verify through the same code path.
_CHEAP_ITERATIONS = 1_000

_PASSWORD = "praman-test-passphrase"

#: Routes that answer without a credential, and why each one has to.
#:
#: * ``/health`` — a liveness probe that required a token would report a healthy
#:   service as down whenever the token expired.
#: * ``POST /auth/login`` — the door. It cannot be behind itself.
#: * ``/`` and ``/{asset:path}`` — the login page and the JavaScript that draws
#:   it. Gating them would serve a 401 to a browser that has no way to display
#:   one, so the operator would see a blank page instead of a password prompt.
#:
#: There is no unauthenticated route that reads a device, a finding or the ledger.
# Signup/options must be reachable before authentication. They disclose no
# device data and registration can be disabled by deployment configuration.
_OPEN_ROUTES = {"/health", "/auth/login", "/auth/signup", "/auth/options", "/", "/{asset:path}"}


def _operator(username: str, role: str, password: str = _PASSWORD) -> None:
    """Create (or reset) one operator with a cheap password hash."""
    conn = STATE.connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, role, password_hash, created_at) "
            "VALUES (?, ?, ?, (SELECT COALESCE(MIN(created_at), '2026-01-01T00:00:00+00:00') "
            "FROM users WHERE username = ?))",
            (
                username,
                role,
                hash_password(password, iterations=_CHEAP_ITERATIONS),
                username,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture(scope="module", autouse=True)
def operators(authenticated_operator: Principal) -> None:
    """One account per role, plus three the destructive tests consume.

    Depends on the suite-wide fixture so the isolated database exists and already
    holds ``service:pytest``; these rows are added beside it.
    """
    _operator("auth.viewer", ROLE_VIEWER)
    _operator("auth.auditor", ROLE_AUDITOR)
    _operator("auth.approver", ROLE_APPROVER)
    _operator("auth.throttled", ROLE_VIEWER)
    _operator("auth.demoted", ROLE_APPROVER)
    _operator("auth.departed", ROLE_VIEWER)


@pytest.fixture
def client(operators: None) -> Iterator[TestClient]:
    """A client with the suite's dependency override removed.

    Restored afterwards, and restored in a ``finally``: leaving it popped would
    401 every remaining test in the session, and the failure would be attributed
    to whichever module happened to run next.
    """
    saved = app.dependency_overrides.pop(current_principal, None)
    try:
        with TestClient(app) as instance:
            yield instance
    finally:
        if saved is not None:
            app.dependency_overrides[current_principal] = saved


def _login(client: TestClient, username: str, password: str = _PASSWORD) -> str:
    response = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _dependency_calls(dependant: object) -> list[object]:
    """Every dependency callable a route resolves, including nested ones."""
    found: list[object] = []
    for sub in getattr(dependant, "dependencies", []):
        found.append(sub.call)
        found.extend(_dependency_calls(sub))
    return found


# ─── The gate, read off the application itself ─────────────────────────


def test_every_route_is_either_gated_or_deliberately_open() -> None:
    """A route with no role gate must be one of the four listed open ones.

    Read from ``app.routes`` rather than a hand-written inventory, because the
    failure this catches is somebody adding an endpoint and not thinking about
    authorisation — exactly the person who would not update an inventory.
    """
    ungated = []
    for path, route in walk_routes(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue  # FastAPI's own /docs, /redoc, /openapi.json
        gates = [c for c in _dependency_calls(dependant) if isinstance(c, RequireRole)]
        if gates:
            continue
        if path in _OPEN_ROUTES:
            continue
        ungated.append(f"{sorted(route.methods)} {path}")

    assert not ungated, (
        f"routes with no role gate: {ungated}. Add Depends(REQUIRE_VIEWER) or "
        "higher, or add the path to _OPEN_ROUTES with a comment saying why an "
        "unauthenticated caller may have it. Every route this project added since "
        "identity exists reads devices, findings or the ledger."
    )


def test_one_override_covers_every_gate() -> None:
    """Every gate resolves the same ``current_principal``, so there is one seam.

    ``RequireRole`` is a callable instance for this reason: a
    ``require_role("approver")`` factory would hand FastAPI a new function object
    per route, ``app.dependency_overrides`` is keyed by that object, and the
    conftest override would silently miss one. This assertion is what stops that
    regression from being invisible.
    """
    missing = []
    for path, route in walk_routes(app.routes):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        calls = _dependency_calls(dependant)
        if any(isinstance(c, RequireRole) for c in calls) and current_principal not in calls:
            missing.append(path)
    assert not missing, (
        f"gated routes that do not resolve current_principal: {missing}. The rest "
        "of the suite overrides that one dependency, so these routes are running "
        "unauthenticated in every other test file."
    )


@pytest.mark.parametrize(
    ("path", "gate"),
    [
        ("/audit/commit", REQUIRE_APPROVER),
        ("/training/map", REQUIRE_APPROVER),
        ("/training/retire", REQUIRE_APPROVER),
        ("/audit/access", REQUIRE_APPROVER),
        ("/ingest", REQUIRE_AUDITOR),
        ("/simulate", REQUIRE_AUDITOR),
        ("/devices", REQUIRE_VIEWER),
        ("/audit/verify", REQUIRE_VIEWER),
    ],
)
def test_the_dangerous_routes_are_gated_at_the_level_they_claim(
    path: str, gate: RequireRole
) -> None:
    """Pin the role, not just the presence of a gate.

    The previous test would pass if ``/audit/commit`` were readable by a viewer.
    These eight are the routes where the level is the control: committing writes
    evidence, ``/training/map`` teaches the parser something every later audit
    trusts, and ``/audit/access`` is the map of who is investigating what.
    """
    route = next(r for r in app.routes if getattr(r, "path", None) == path)
    assert gate in _dependency_calls(route.dependant), (
        f"{path} is not behind {gate.minimum}"
    )


# ─── Refusals ──────────────────────────────────────────────────────────


def test_an_unauthenticated_read_is_refused_and_says_how_to_authenticate(
    client: TestClient,
) -> None:
    response = client.get("/devices")
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer", (
        "a 401 without WWW-Authenticate tells a client it failed but not with what"
    )
    assert "/auth/login" in response.json()["detail"]


def test_a_forged_token_is_refused(client: TestClient) -> None:
    """A random string must not resolve, and the refusal must not be a 500."""
    response = client.get("/devices", headers=_auth(secrets.token_urlsafe(32)))
    assert response.status_code == 401
    assert "revoked" in response.json()["detail"]


def test_a_viewer_may_read_but_not_commit(client: TestClient) -> None:
    """PRAMAN's role separation, at its narrowest point.

    A viewer is refused before the handler runs, so the 403 arrives whether or not
    the device exists — which is why a nonexistent id is used here. A 404 would
    mean the gate let the request through and leaked the estate's contents to
    somebody who may not commit.
    """
    token = _login(client, "auth.viewer")
    assert client.get("/devices", headers=_auth(token)).status_code == 200

    response = client.post(
        "/audit/commit", json={"device_id": "no-such-device"}, headers=_auth(token)
    )
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert "viewer" in detail and "approver" in detail, (
        "a 403 that does not say which role is required sends the operator to the "
        f"source code: {detail!r}"
    )


def test_an_auditor_may_ingest_but_only_an_approver_commits(client: TestClient) -> None:
    """The full separation of duties, end to end, including who the ledger names.

    One account uploads and simulates; a second turns the result into signed
    evidence; the record says which one. That last part is the reason ``actor`` is
    a hashed field rather than a column in a side table — see
    ``backend/ledger/chain.py``.
    """
    auditor = _login(client, "auth.auditor")
    approver = _login(client, "auth.approver")
    config = FIXTURE.read_text(encoding=FILE_ENCODING)

    ingest = client.post(
        "/ingest",
        files={"file": ("auth-roles.conf", config, "text/plain")},
        headers=_auth(auditor),
    )
    assert ingest.status_code == 200, ingest.text
    device_id = ingest.json()["device_id"]

    refused = client.post(
        "/audit/commit", json={"device_id": device_id}, headers=_auth(auditor)
    )
    assert refused.status_code == 403, "an auditor committed to the ledger"

    committed = client.post(
        "/audit/commit", json={"device_id": device_id}, headers=_auth(approver)
    )
    assert committed.status_code == 200, committed.text
    assert committed.json()["actor"] == "auth.approver", (
        "the ledger record does not name the operator who authorised it"
    )

    verify = client.get("/audit/verify", headers=_auth(approver)).json()
    mine = [
        r
        for r in verify["results"]
        if r["record_hash"] == committed.json()["record_hash"]
    ]
    assert len(mine) == 1
    assert mine[0]["actor_valid"] is True, mine[0]["detail"]


# ─── How a live token stops working ────────────────────────────────────


def test_logout_revokes_the_token_server_side(client: TestClient) -> None:
    """A client that throws a token away has not ended the session.

    Anyone who captured the token still holds a live credential, so revocation
    has to happen in the database. The unauthenticated attempt is asserted first
    because a logout route that answered 200 to a stranger would be a way to
    revoke somebody else's session by guessing.
    """
    assert client.post("/auth/logout").status_code == 401

    token = _login(client, "auth.viewer")
    assert client.get("/devices", headers=_auth(token)).status_code == 200

    logout = client.post("/auth/logout", headers=_auth(token))
    assert logout.status_code == 200, logout.text
    assert logout.json()["revoked"] is True

    after = client.get("/devices", headers=_auth(token))
    assert after.status_code == 401, "the token still works after logging out"


def test_an_expired_session_is_refused(client: TestClient) -> None:
    """The 12-hour TTL is enforced on read, not only at issue.

    Backdated through the public ``open_session`` rather than by forging a token
    hash, so the test cannot pass while disagreeing with how tokens are actually
    stored.
    """
    principal = Principal(username="auth.viewer", role=ROLE_VIEWER)
    conn = STATE.connect()
    try:
        token, _ = open_session(conn, principal)
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE username = ? AND revoked_at IS NULL",
            ("2020-01-01T00:00:00+00:00", principal.username),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.get("/devices", headers=_auth(token))
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]


def test_disabling_an_operator_kills_the_session_and_keeps_the_row(
    client: TestClient,
) -> None:
    """Departure must end access without rewriting history.

    ``disable_user`` is not a DELETE, and this asserts both halves: the live token
    stops working, and the name still resolves in ``known_actors`` — otherwise
    every audit the departed assessor ever committed would start failing
    ``actor_valid`` the day they left.
    """
    token = _login(client, "auth.departed")
    assert client.get("/devices", headers=_auth(token)).status_code == 200

    conn = STATE.connect()
    try:
        disable_user(conn, "auth.departed")
        actors = known_actors(conn)
    finally:
        conn.close()

    assert client.get("/devices", headers=_auth(token)).status_code == 401
    assert client.post(
        "/auth/login", json={"username": "auth.departed", "password": _PASSWORD}
    ).status_code == 401
    clear_login_failures("auth.departed")
    assert "auth.departed" in actors, (
        "the row was removed, so the ledger records this operator committed now "
        "name an actor the deployment does not recognise"
    )


def test_a_demotion_takes_effect_on_the_next_request(client: TestClient) -> None:
    """The role is read from ``users`` per request, not frozen into the session.

    The row is updated directly here rather than through ``set_role``, which also
    revokes the operator's sessions: revocation would produce a 401 and prove
    nothing about where the role is read from. Both behaviours are wanted — this
    one is the backstop for the case where a session survives.
    """
    token = _login(client, "auth.demoted")
    assert client.get("/auth/whoami", headers=_auth(token)).json()["may_commit"] is True

    conn = STATE.connect()
    try:
        conn.execute(
            "UPDATE users SET role = ? WHERE username = ?", (ROLE_VIEWER, "auth.demoted")
        )
        conn.commit()
    finally:
        conn.close()

    whoami = client.get("/auth/whoami", headers=_auth(token)).json()
    assert whoami["role"] == ROLE_VIEWER
    assert whoami["may_commit"] is False
    assert client.post(
        "/audit/commit", json={"device_id": "no-such-device"}, headers=_auth(token)
    ).status_code == 403


# ─── The cookie, and why it is not a second credential ─────────────────


def test_the_cookie_authorises_a_read_and_never_a_write(client: TestClient) -> None:
    """The whole CSRF defence, in one test.

    The cookie exists so a browser navigation can fetch ``report.pdf``, which
    cannot carry an ``Authorization`` header. Because it is honoured on GET and
    HEAD only, a cross-site form post carrying it authorises nothing — so there is
    no anti-CSRF token that somebody could forget to check. If this test ever
    fails on the POST line, the application has acquired a CSRF vulnerability, not
    a convenience.
    """
    _login(client, "auth.approver")  # the response sets the cookie on the client
    assert COOKIE_NAME in client.cookies

    assert client.get("/devices").status_code == 200, (
        "the cookie was refused on a read, so a PDF download link cannot work"
    )
    assert client.head("/devices").status_code in {200, 405}

    write = client.post("/audit/commit", json={"device_id": "no-such-device"})
    assert write.status_code == 401, (
        "the session cookie authorised a state-changing request: any page on the "
        "internet can now commit to this operator's ledger by submitting a form"
    )


# ─── Throttling and the bootstrap refusal ──────────────────────────────


def test_repeated_guessing_locks_the_account_and_refuses_the_right_password(
    client: TestClient,
) -> None:
    """The lockout has to outrank a correct password, or it is not a lockout.

    In-process and per-username — a speed bump on top of the KDF, not the
    request-rate limiter ``docs/SECURITY.md`` §4 still lists as missing. The
    counter is cleared at the end because it lives in a module-level dict, and a
    later test logging in as this name would otherwise inherit the lockout.
    """
    try:
        for attempt in range(LOGIN_FAILURE_THRESHOLD):
            response = client.post(
                "/auth/login",
                json={"username": "auth.throttled", "password": "wrong-password-here"},
            )
            assert response.status_code == 401, f"attempt {attempt}: {response.text}"

        locked = client.post(
            "/auth/login", json={"username": "auth.throttled", "password": _PASSWORD}
        )
        assert locked.status_code == 429, locked.text
        assert int(locked.headers["Retry-After"]) > 0
        assert "auth.throttled" in locked.json()["detail"]
    finally:
        clear_login_failures("auth.throttled")

    assert _login(client, "auth.throttled"), "clearing the counter did not restore login"


def test_with_no_operators_every_route_says_how_to_create_the_first(
    tmp_path: Path,
) -> None:
    """The bootstrap refusal — no default account, no open bootstrap route.

    Pointed at an empty database rather than deleting rows from the shared one,
    because the shared one is what every other module in the session is using.
    Both answers name ``scripts/manage_users.py`` and the MANUAL_COMMANDS.md step,
    since "401" with no explanation on a fresh install looks like a broken build
    and the usual next move is to go looking for the default password.
    """
    saved_path = STATE.db_path
    saved_override = app.dependency_overrides.pop(current_principal, None)
    STATE.db_path = tmp_path / "empty.db"
    STATE.learned.invalidate()
    try:
        with TestClient(app) as fresh:
            gated = fresh.get("/devices")
            assert gated.status_code == 401
            assert "manage_users.py" in gated.json()["detail"]
            assert "Step 13" in gated.json()["detail"]

            login = fresh.post(
                "/auth/login", json={"username": "anybody", "password": "any password"}
            )
            assert login.status_code == 503, login.text
            assert "/auth/signup" in login.json()["detail"]

            assert fresh.get("/health").status_code == 200, (
                "an empty deployment must still report its own liveness"
            )
    finally:
        STATE.db_path = saved_path
        STATE.learned.invalidate()
        if saved_override is not None:
            app.dependency_overrides[current_principal] = saved_override


# ─── Password storage ──────────────────────────────────────────────────


class TestPasswordStorage:
    """The KDF, and the three malformed inputs a stored hash can be."""

    def test_a_password_round_trips_and_a_wrong_one_does_not(self) -> None:
        encoded = hash_password(_PASSWORD, iterations=_CHEAP_ITERATIONS)
        assert verify_password(_PASSWORD, encoded) is True
        assert verify_password(_PASSWORD + "x", encoded) is False

    def test_the_stored_hash_does_not_contain_the_password(self) -> None:
        encoded = hash_password(_PASSWORD, iterations=_CHEAP_ITERATIONS)
        assert _PASSWORD not in encoded
        assert encoded.startswith("pbkdf2_sha256$")

    def test_the_same_password_hashes_differently_every_time(self) -> None:
        """Per-user salt: without it, two operators sharing a password are visibly
        sharing a password, and one rainbow table covers the estate."""
        first = hash_password(_PASSWORD, iterations=_CHEAP_ITERATIONS)
        second = hash_password(_PASSWORD, iterations=_CHEAP_ITERATIONS)
        assert first != second

    @pytest.mark.parametrize(
        "stored", ["", "not-a-hash", "pbkdf2_sha256$1000$$", "argon2$1$abc$def"]
    )
    def test_a_malformed_stored_hash_never_matches(self, stored: str) -> None:
        """Including the empty string, which is what a service account holds.

        "This row cannot authenticate" is the correct answer for it, and the bug
        this pins is the one that always goes the other way: an empty expected
        digest compared against an empty derivation, matching anything.
        """
        assert verify_password("anything at all", stored) is False
        assert verify_password("", stored) is False

    def test_a_short_password_is_refused_at_the_hash(self) -> None:
        """Enforced in ``hash_password`` rather than in each caller, so the CLI,
        the login route and a future admin UI cannot disagree about the floor."""
        with pytest.raises(ValueError, match="at least"):
            hash_password("x" * (MIN_PASSWORD_LENGTH - 1))

    def test_a_human_operator_cannot_be_created_without_a_password(self) -> None:
        """``password=None`` is for ``service:`` principals only.

        A human account that cannot log in is a mistake, and one that can log in
        with an empty password is worse. The ``service:`` case is asserted by
        ``tests/conftest.py`` existing at all — the suite's own principal is one.
        """
        conn = STATE.connect()
        try:
            with pytest.raises(ValueError, match="service:"):
                create_user(conn, "auth.nopassword", ROLE_VIEWER, None)
        finally:
            conn.close()

    def test_a_name_the_ledger_could_not_render_is_refused(self) -> None:
        """Usernames end up in hashed records, PDFs and the access log."""
        conn = STATE.connect()
        try:
            for bad in ("Ab", "has space", "UPPER", "x" * 80, ""):
                with pytest.raises(ValueError):
                    create_user(conn, bad, ROLE_AUDITOR, _PASSWORD)
            with pytest.raises(ValueError, match="unknown role"):
                create_user(conn, "auth.badrole", "administrator", _PASSWORD)
        except sqlite3.Error:  # pragma: no cover - the insert must never run
            raise
        finally:
            conn.close()
