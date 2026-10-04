"""Optionally create the first hosted-demo operator from environment secrets.

Offline installations should use ``scripts/manage_users.py`` interactively. A
managed web host usually has no useful interactive shell during its first boot,
so this small, opt-in bootstrap lets the start command create exactly one human
operator when the database has no users yet.

The password is read from the process environment and is never printed. If the
database already contains an operator, the command is a no-op: it cannot reset a
password or create a second account from deployment variables. Leaving the
variables unset is also safe and leaves the normal "create an operator" 503
message in place.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> int:
    """Create the configured first account, or intentionally do nothing."""
    username = os.environ.get("PRAMAN_BOOTSTRAP_USERNAME", "").strip()
    password = os.environ.get("PRAMAN_BOOTSTRAP_PASSWORD", "")
    role = os.environ.get("PRAMAN_BOOTSTRAP_ROLE", "approver").strip() or "approver"

    if not username and not password:
        print("Hosted bootstrap not configured; keeping the database account-free.")
        return 0
    if not username or not password:
        print(
            "PRAMAN_BOOTSTRAP_USERNAME and PRAMAN_BOOTSTRAP_PASSWORD must be set "
            "together, or both must be omitted.",
            file=sys.stderr,
        )
        return 2

    from backend.app.auth import create_user, user_count
    from backend.app.state import STATE

    conn = STATE.connect()
    try:
        if user_count(conn):
            print("Hosted bootstrap skipped; the database already has an operator.")
            return 0
        create_user(conn, username, role, password)
    except ValueError as exc:
        print(f"Hosted bootstrap failed: {exc}", file=sys.stderr)
        return 2
    finally:
        conn.close()

    print(f"Created the initial PRAMAN operator '{username}' with role '{role}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
