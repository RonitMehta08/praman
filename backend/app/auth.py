"""Operator identity: authentication, authorisation, and the actor in the ledger.

Why this module exists is stated most precisely by ``docs/SECURITY.md`` §1:

    a ledger that proves *what* was decided but not *who* decided it is only half
    an audit trail.

So identity is not a login screen bolted to the side. ``actor`` is a field inside
:class:`~backend.canonical.findings.AuditRecord`, which puts it inside
``RECORD_HASH_FIELDS``, which puts it under the record hash and the Ed25519
signature. Rewriting who ran an audit therefore breaks the same chain that
rewriting a verdict breaks, and the standalone verifier reports it.

Three design decisions worth stating, because each one is a place a reviewer
would otherwise assume the easy thing was done:

**No password is compiled into anything.** There is no default account, no
``admin/admin``, no bootstrap endpoint. The first operator is created out of band
with ``python scripts/manage_users.py add`` — which requires filesystem access to
the deployment, a far stronger authentication of the act of taking privilege than
any open HTTP path could be. Until an operator exists, every protected route
answers 401 and says so. SECURITY.md §1 argues a hardcoded credential is worse
than visible absence; an open bootstrap route is the same mistake wearing a
different hat.

**Passwords are PBKDF2-HMAC-SHA256, 600,000 iterations, per-user salt.** stdlib
``hashlib``, no new dependency on an air-gapped machine, and the KDF is
FIPS-approved — which matters for a tool whose own rule packs fail devices for
non-FIPS algorithms. Measured 0.209 s per derivation on the development machine:
slow enough to make online guessing pointless, fast enough that a login is not
noticeable.

**The session cookie is accepted on GET only.** The bearer token is the real
credential; the cookie exists solely so the browser can follow a download link
(``/devices/{id}/report.pdf``, ``/training/export``), because a navigation cannot
carry an ``Authorization`` header. Restricting it to safe methods means the cookie
can never authorise a state change, so CSRF has nothing to forge and the design
needs no anti-CSRF token to remember to check. Putting the token in the query
string was the alternative, and it would have written live credentials into the
access log this same change introduces.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request

from backend.canonical.models import utc_now_iso

# ─── Roles ─────────────────────────────────────────────────────────────

#: Read the estate: findings, reports, the ledger, the training queue.
ROLE_VIEWER = "viewer"
#: Viewer, plus hand the system a configuration — ``/ingest``, ``/simulate``.
ROLE_AUDITOR = "auditor"
#: Auditor, plus the two operations that are irreversible or authoritative:
#: committing an audit to the ledger, and teaching the parser a mapping.
ROLE_APPROVER = "approver"

#: Ordered, so authorisation is a comparison rather than a set of membership
#: tables that can disagree with each other. Deliberately monotonic: there is no
#: role that may commit an audit but not read one.
ROLE_RANK: dict[str, int] = {ROLE_VIEWER: 0, ROLE_AUDITOR: 1, ROLE_APPROVER: 2}

ROLES: tuple[str, ...] = (ROLE_VIEWER, ROLE_AUDITOR, ROLE_APPROVER)

# ─── Names ─────────────────────────────────────────────────────────────

#: What a username may be. Lowercase and punctuation-poor because this string
#: ends up inside a hashed ledger record, in PDF reports and in the access log;
#: a name that renders differently in two of those places is a name that makes
#: an audit trail arguable.
#:
#: ``service:`` is a reserved prefix for non-interactive principals — the reseed
#: script, the offline CLI. They hold a row (so the verifier can recognise their
#: records) and no password (so they cannot log in over HTTP).
USERNAME_RE = re.compile(r"^(service:)?[a-z0-9][a-z0-9._-]{2,55}$")

SERVICE_PREFIX = "service:"

#: The actor recorded by ``scripts/reset_ledger.py``. Named here rather than in
#: the script so the verifier's own tests can refer to the same constant.
SERVICE_RESEED = "service:reset-ledger"
#: The actor recorded by ``backend/cli.py`` for an offline, unpersisted audit.
SERVICE_CLI = "service:offline-cli"

# ─── Passwords ─────────────────────────────────────────────────────────

PASSWORD_ALGORITHM = "pbkdf2_sha256"
#: OWASP's current PBKDF2-HMAC-SHA256 recommendation. Stored *inside* each hash
#: so raising it later does not invalidate existing passwords.
PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
#: Short enough not to be a nuisance, long enough that a dictionary is useless.
#: Enforced here rather than in the CLI so every caller gets the same floor.
MIN_PASSWORD_LENGTH = 12

# ─── Sessions ──────────────────────────────────────────────────────────

#: One working day. A stolen token is only useful while it is live, and an
#: assessor's laptop that is open for a week should still ask again.
SESSION_TTL_SECONDS = 12 * 60 * 60
_TOKEN_BYTES = 32
COOKIE_NAME = "praman_session"
_BEARER_PREFIX = "bearer "

#: Methods on which the session cookie is honoured. See the module docstring:
#: this is the whole CSRF defence, and it works because it is a whitelist of
#: methods that cannot change state rather than a list of paths that are safe
#: today.
COOKIE_SAFE_METHODS = frozenset({"GET", "HEAD"})

# ─── Login throttling ──────────────────────────────────────────────────

LOGIN_FAILURE_THRESHOLD = 10
LOGIN_LOCKOUT_SECONDS = 900

#: Consecutive failures per username: ``{username: (count, first_failure_time)}``.
#:
#: In-process on purpose, and honestly limited: a restart clears it and a second
#: worker has its own copy. It is a speed bump on top of a 0.2 s KDF, not the
#: rate limiter ``docs/SECURITY.md`` §4 still lists as missing. Storing it in
#: SQLite would let an unauthenticated caller grow the database by guessing.
_login_failures: dict[str, tuple[int, float]] = {}


@dataclass(frozen=True)
class Principal:
    """An authenticated operator. Frozen: a handler may read it, never edit it."""

    username: str
    role: str

    @property
    def is_service(self) -> bool:
        return self.username.startswith(SERVICE_PREFIX)

    def may(self, minimum: str) -> bool:
        """Whether this principal satisfies ``minimum``."""
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[minimum]


# ─── Password hashing ──────────────────────────────────────────────────


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Encode a password as ``pbkdf2_sha256$<iterations>$<salt>$<derived>``.

    Raises:
        ValueError: If the password is shorter than :data:`MIN_PASSWORD_LENGTH`.
            Refused here, at the only place that can enforce it, rather than in
            whichever caller remembers to check.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"a password must be at least {MIN_PASSWORD_LENGTH} characters; "
            f"this one is {len(password)}"
        )
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        (
            PASSWORD_ALGORITHM,
            str(iterations),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(derived).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of ``password`` against a stored hash.

    An empty or malformed stored hash returns False rather than raising: a
    service account holds ``''`` on purpose, and "this row cannot authenticate"
    is the correct answer for it, not an error the caller has to special-case.
    """
    parts = encoded.split("$")
    if len(parts) != 4 or parts[0] != PASSWORD_ALGORITHM:
        return False
    try:
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2], validate=True)
        expected = base64.b64decode(parts[3], validate=True)
    except (ValueError, TypeError):
        return False
    if iterations < 1 or not salt or not expected:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived, expected)


# ─── User store ────────────────────────────────────────────────────────


def validate_username(username: str) -> str:
    """Raise ``ValueError`` unless ``username`` is a usable operator name.

    Public because ``scripts/manage_users.py`` calls it *before* prompting for a
    password: a name this would reject should not cost the operator a typed
    passphrase, and a second copy of the rule in the script would be a rule that
    drifts.
    """
    if not USERNAME_RE.match(username):
        raise ValueError(
            f"'{username}' is not a usable operator name. Lowercase letters, "
            "digits, dot, underscore and hyphen, 3–56 characters, optionally "
            f"prefixed '{SERVICE_PREFIX}' for a non-interactive principal."
        )
    return username


def _validate_role(role: str) -> str:
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role '{role}'; expected one of {', '.join(ROLES)}")
    return role


def create_user(
    conn: sqlite3.Connection,
    username: str,
    role: str,
    password: str | None,
) -> None:
    """Insert an operator. ``password=None`` creates a login-disabled principal.

    Raises:
        ValueError: On a bad name, an unknown role, a weak password, or a name
            that is already taken.
    """
    validate_username(username)
    _validate_role(role)
    if password is None:
        if not username.startswith(SERVICE_PREFIX):
            raise ValueError(
                f"only a '{SERVICE_PREFIX}' principal may be created without a "
                "password; a human operator who cannot log in is a mistake, not "
                "a configuration"
            )
        encoded = ""
    else:
        encoded = hash_password(password)
    try:
        conn.execute(
            "INSERT INTO users (username, role, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, role, encoded, utc_now_iso()),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"operator '{username}' already exists") from exc
    conn.commit()


def ensure_service_account(
    conn: sqlite3.Connection, username: str, role: str = ROLE_APPROVER
) -> Principal:
    """Return a service principal, creating its row if absent. Idempotent.

    Used by the entry points that commit audits without a human at a keyboard —
    ``scripts/reset_ledger.py`` and the offline CLI. The row matters even though
    it can never log in: the verifier's ``actor_valid`` check asks whether the
    recorded actor is a principal this deployment knows about, and a reseeded
    ledger whose every record named an unknown actor would report itself broken.
    """
    row = conn.execute(
        "SELECT role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        create_user(conn, username, role, None)
        return Principal(username=username, role=role)
    return Principal(username=username, role=row["role"])


def set_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    """Replace an operator's password and revoke their live sessions.

    The revocation is the point: a password change that leaves old tokens
    working does not end the access it was meant to end.
    """
    encoded = hash_password(password)
    cursor = conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?", (encoded, username)
    )
    if cursor.rowcount == 0:
        raise ValueError(f"no operator named '{username}'")
    revoke_sessions_for(conn, username)
    conn.commit()


def set_role(conn: sqlite3.Connection, username: str, role: str) -> None:
    """Change an operator's role and revoke their live sessions.

    Sessions are revoked for the same reason a password change revokes them: a
    demotion that leaves a live approver token in circulation has not demoted
    anybody. Roles are resolved per request from the ``users`` row, so this is
    belt and braces — kept because the cost is one statement.
    """
    _validate_role(role)
    cursor = conn.execute(
        "UPDATE users SET role = ? WHERE username = ?", (role, username)
    )
    if cursor.rowcount == 0:
        raise ValueError(f"no operator named '{username}'")
    revoke_sessions_for(conn, username)
    conn.commit()


def disable_user(conn: sqlite3.Connection, username: str) -> None:
    """Stop an operator logging in, keeping the row.

    Deliberately not a DELETE. The ledger's ``actor`` names this row, and the
    verifier checks that the name resolves; deleting a departed assessor would
    turn every audit they ever committed into a record the verifier calls
    invalid. An audit trail that degrades when staff leave is not an audit trail.
    """
    cursor = conn.execute(
        "UPDATE users SET disabled_at = ? WHERE username = ? AND disabled_at IS NULL",
        (utc_now_iso(), username),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"no enabled operator named '{username}'")
    revoke_sessions_for(conn, username)
    conn.commit()


def enable_user(conn: sqlite3.Connection, username: str) -> None:
    """Undo :func:`disable_user`. No session comes back with it.

    Symmetric with disabling because the asymmetric version — disable in the CLI,
    re-enable by editing SQLite — is how an operator locked out by a typo ends up
    with somebody running ``UPDATE users`` by hand against the file that holds the
    ledger. Old tokens stay revoked: the account is usable again, the credentials
    that were in circulation while it was disabled are not.
    """
    cursor = conn.execute(
        "UPDATE users SET disabled_at = NULL WHERE username = ? AND disabled_at IS NOT NULL",
        (username,),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"no disabled operator named '{username}'")
    conn.commit()


def list_users(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every operator, enabled or not. Never returns a password hash."""
    rows = conn.execute(
        "SELECT username, role, created_at, disabled_at, "
        "       (password_hash <> '') AS can_log_in "
        "FROM users ORDER BY username"
    ).fetchall()
    return [dict(row) for row in rows]


def known_actors(conn: sqlite3.Connection) -> set[str]:
    """Every principal name this deployment recognises, disabled ones included."""
    return {row["username"] for row in conn.execute("SELECT username FROM users")}


def user_count(conn: sqlite3.Connection) -> int:
    """How many operators exist. Zero means nobody can use the API yet."""
    return int(conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"])


# ─── Login throttling ──────────────────────────────────────────────────


def lockout_remaining(username: str) -> int:
    """Seconds until ``username`` may attempt a login again. 0 when it may now."""
    entry = _login_failures.get(username)
    if entry is None:
        return 0
    count, first = entry
    if count < LOGIN_FAILURE_THRESHOLD:
        return 0
    elapsed = time.monotonic() - first
    if elapsed >= LOGIN_LOCKOUT_SECONDS:
        _login_failures.pop(username, None)
        return 0
    return int(LOGIN_LOCKOUT_SECONDS - elapsed)


def note_login_failure(username: str) -> None:
    count, first = _login_failures.get(username, (0, time.monotonic()))
    _login_failures[username] = (count + 1, first)


def clear_login_failures(username: str) -> None:
    _login_failures.pop(username, None)


# ─── Authentication ────────────────────────────────────────────────────


def authenticate(
    conn: sqlite3.Connection, username: str, password: str
) -> Principal | None:
    """Check a credential. Returns the principal, or None for any failure.

    One return value for "no such operator", "wrong password" and "disabled" is
    intentional: three distinguishable answers hand an attacker a user
    enumeration oracle, and the operator at the keyboard cannot act on the
    difference anyway.
    """
    row = conn.execute(
        "SELECT username, role, password_hash, disabled_at FROM users "
        "WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        # Still spend the KDF time. Returning immediately makes "unknown user"
        # measurably faster than "wrong password", which is the enumeration
        # oracle the single return value above was chosen to avoid.
        hash_password("x" * MIN_PASSWORD_LENGTH, iterations=PBKDF2_ITERATIONS)
        return None
    if row["disabled_at"] is not None:
        return None
    if not verify_password(password, row["password_hash"] or ""):
        return None
    return Principal(username=row["username"], role=row["role"])


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def open_session(conn: sqlite3.Connection, principal: Principal) -> tuple[str, str]:
    """Mint a bearer token for ``principal``. Returns ``(token, expires_at)``.

    Only the token's SHA-256 is stored. The token itself is high-entropy random,
    so a digest is enough to recognise it and a database read yields nothing an
    attacker can present — which matters because the same file holds the
    configurations the tool has already sorted by exploitability.
    """
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token_hash, username, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (_token_digest(token), principal.username, now.isoformat(), expires_at),
    )
    conn.commit()
    return token, expires_at


def resolve_session(conn: sqlite3.Connection, token: str) -> Principal | None:
    """The principal behind a bearer token, or None if it is not usable now.

    The role comes from the ``users`` row rather than from the session, so a
    demotion takes effect on the next request instead of at the next login.
    """
    if not token:
        return None
    row = conn.execute(
        "SELECT s.username, s.expires_at, s.revoked_at, u.role, u.disabled_at "
        "FROM sessions s JOIN users u ON u.username = s.username "
        "WHERE s.token_hash = ?",
        (_token_digest(token),),
    ).fetchone()
    if row is None or row["revoked_at"] is not None or row["disabled_at"] is not None:
        return None
    try:
        expires = datetime.fromisoformat(row["expires_at"])
    except ValueError:
        return None
    if expires <= datetime.now(timezone.utc):
        return None
    return Principal(username=row["username"], role=row["role"])


def close_session(conn: sqlite3.Connection, token: str) -> bool:
    """Revoke one token. True when a live session was actually ended."""
    cursor = conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (utc_now_iso(), _token_digest(token)),
    )
    conn.commit()
    return cursor.rowcount > 0


def revoke_sessions_for(conn: sqlite3.Connection, username: str) -> int:
    """Revoke every live session of one operator. Returns how many."""
    cursor = conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE username = ? AND revoked_at IS NULL",
        (utc_now_iso(), username),
    )
    return cursor.rowcount


# ─── FastAPI wiring ────────────────────────────────────────────────────


def bearer_token(request: Request) -> str:
    """The credential on this request, header first, cookie second.

    The cookie is only read on a safe method — see :data:`COOKIE_SAFE_METHODS`
    and the module docstring.
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith(_BEARER_PREFIX):
        return header[len(_BEARER_PREFIX):].strip()
    if request.method.upper() in COOKIE_SAFE_METHODS:
        return request.cookies.get(COOKIE_NAME, "") or ""
    return ""


def _unauthenticated(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def current_principal(request: Request) -> Principal:
    """The authenticated operator, or 401.

    This is the single dependency every protected route resolves, which is what
    makes ``tests/test_auth.py`` able to assert coverage by walking the route
    table instead of trusting a list somebody maintains by hand. It is also the
    one seam the test suite overrides, so the other 1,100-odd tests can exercise
    business logic without each one performing a login.
    """
    from backend.app.state import STATE

    token = bearer_token(request)
    conn = STATE.connect()
    try:
        if user_count(conn) == 0:
            raise _unauthenticated(
                "no operator accounts exist, so nothing can be authorised. "
                "Create the first one with 'python scripts/manage_users.py add "
                "--username <name> --role approver' (MANUAL_COMMANDS.md Step 13)."
            )
        if not token:
            raise _unauthenticated(
                "this endpoint requires an authenticated operator. POST "
                "/auth/login and send the token as 'Authorization: Bearer <token>'."
            )
        principal = resolve_session(conn, token)
    finally:
        conn.close()

    if principal is None:
        raise _unauthenticated(
            "the session token is unknown, expired or revoked — log in again."
        )
    request.state.principal = principal
    return principal


class RequireRole:
    """Dependency asserting a minimum role.

    A callable *instance* rather than a closure-returning factory on purpose.
    ``Depends(require_role("approver"))`` would hand FastAPI a new function
    object per route, and ``app.dependency_overrides`` is keyed by that object —
    so the test suite would have to override nineteen separate dependencies and
    would silently miss the twentieth. An instance delegates to the shared
    :func:`current_principal`, which FastAPI resolves as a sub-dependency and
    therefore honours a single override of it, so there is exactly one seam.
    """

    def __init__(self, minimum: str) -> None:
        self.minimum = _validate_role(minimum)

    def __call__(
        self,
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> Principal:
        # Re-stated here rather than relied on from current_principal, because
        # under a test override current_principal never runs and the access-log
        # middleware would have no actor to record.
        request.state.principal = principal
        if not principal.may(self.minimum):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"role '{principal.role}' cannot do this; '{self.minimum}' or "
                    "higher is required. Roles: viewer reads, auditor uploads, "
                    "approver commits to the ledger and teaches mappings."
                ),
            )
        return principal


#: The three role gates, as singletons.
#:
#: Module-level so every route shares one object per role. Building them inline
#: at each decorator would work, but these get imported by
#: ``tests/test_auth.py``, which walks the app's dependency tree and asserts that
#: every non-open route sits behind one of exactly these three.
REQUIRE_VIEWER = RequireRole(ROLE_VIEWER)
REQUIRE_AUDITOR = RequireRole(ROLE_AUDITOR)
REQUIRE_APPROVER = RequireRole(ROLE_APPROVER)
