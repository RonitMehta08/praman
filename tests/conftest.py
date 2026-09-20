"""Pytest conftest — shared fixtures and sys.path injection.

Ensures the project root is on sys.path so tests can import ``backend.*``
without installing the package, keeps the test suite out of the operator's
database, and gives every test an authenticated identity to act as.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Ensure project root is on sys.path for imports
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session", autouse=True)
def isolated_database(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Point the whole suite at a throwaway database.

    Without this, the acceptance tests ingest devices and append audit records to
    ``data/praman.db`` — the real ledger. That is wrong twice over: a test run
    silently grows the operator's append-only chain with fixture devices, and the
    tests themselves become order-dependent on whatever an earlier run left
    behind.

    Session-scoped rather than per-test because the acceptance tests are
    deliberately sequential: one ingests a device, the next commits an audit for
    it, a third verifies the chain. Isolating each test would break that chain
    while proving nothing extra — the unit tests that need a private database
    already make their own.
    """
    from backend.app.state import STATE

    db_path = tmp_path_factory.mktemp("praman-db") / "test.db"
    STATE.db_path = db_path
    STATE.learned.invalidate()
    return db_path


#: The operator every test acts as, unless it overrides the fixture below.
#:
#: Named as a service principal because it is one: nothing logs in as it, the
#: dependency override hands it out directly. ``scripts/manage_users.py`` would
#: refuse to create a *human* account with no password, and a test suite whose
#: fixture identity could log in over HTTP would be a credential shipped in the
#: repository.
TEST_OPERATOR = "service:pytest"


@pytest.fixture(scope="session", autouse=True)
def authenticated_operator(isolated_database: Path):
    """Act as an approver for the whole suite, and be a real row while doing it.

    Every route except ``/health``, ``POST /auth/login`` and the static assets now
    requires an authenticated principal. Without this fixture all 1,100-odd
    existing tests would 401, and the alternative — logging in inside each test —
    would spend a 0.2 s key derivation per case to prove something one test
    already proves.

    Two things are deliberate. First, the override is on ``current_principal``
    alone: the role gates are ordinary callers of it, so they still *run*, and a
    route accidentally left behind ``REQUIRE_APPROVER`` when it should be readable
    by a viewer is still catchable. ``tests/test_auth.py`` drops this override to
    exercise the 401 and 403 paths for real.

    Second, the operator is inserted into ``users`` rather than merely asserted.
    ``actor`` is now a hashed field of every ledger record and ``/audit/verify``
    resolves it against that table, so a fixture identity with no row would leave
    the fifth check permanently unchecked across the suite — the new link would be
    covered by nothing, which is the failure mode the ledger code keeps warning
    about.
    """
    from backend.app.auth import ROLE_APPROVER, Principal, current_principal, ensure_service_account
    from backend.app.main import app
    from backend.app.state import STATE

    conn = STATE.connect()
    try:
        ensure_service_account(conn, TEST_OPERATOR, ROLE_APPROVER)
    finally:
        conn.close()

    principal = Principal(username=TEST_OPERATOR, role=ROLE_APPROVER)
    app.dependency_overrides[current_principal] = lambda: principal
    yield principal
    app.dependency_overrides.pop(current_principal, None)


def walk_routes(routes, prefix: str = "") -> list[tuple[str, object]]:
    """Every HTTP route the app answers on, as ``(path, route)``, flattened.

    ``app.routes`` is not a flat list of endpoints. A router mounted with
    ``include_router`` — ``backend/app/routes_export.py`` is the first one — is
    held behind a lazy wrapper that has no ``path``, no ``methods`` and no
    ``dependant``. Three separate tests read the route table to enforce a rule
    over *every* route: that each one is behind a role gate
    (``test_auth.test_every_route_is_either_gated_or_deliberately_open``), that
    each gate resolves the single overridable ``current_principal``
    (``test_auth.test_one_override_covers_every_gate``), and that each one is
    called by name in the API surface test. All three filtered on ``methods``
    being present, so all three would have skipped that wrapper — and skipping is
    silent. An inventory that under-reports its input passes forever.

    Shared from ``conftest`` rather than copied into each module for the same
    reason: three copies of this traversal is three chances for one of them to
    stop descending.
    """
    found: list[tuple[str, object]] = []
    for route in routes:
        nested = getattr(route, "original_router", None)
        if nested is not None:
            context = getattr(route, "include_context", None)
            found += walk_routes(
                nested.routes, prefix + (getattr(context, "prefix", "") or "")
            )
            continue
        path = getattr(route, "path", None)
        if path and getattr(route, "methods", None):
            found.append((prefix + path, route))
    return found
