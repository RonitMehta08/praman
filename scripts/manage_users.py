"""Create and manage operator accounts. The only way an account comes into being.

Why this is a script and not an endpoint
----------------------------------------
There is no default account, no ``admin/admin``, and no HTTP route that creates
the first operator. Until one exists, every protected route answers 401 and says
to run this file. That is deliberate, and the reasoning is worth stating because
the alternative looks more convenient:

* A **hardcoded credential** is worse than visible absence — ``docs/SECURITY.md``
  §1 argues it, and this tool's own rule packs fail devices for exactly that.
* An **open bootstrap route** is the same mistake wearing a different hat. Whoever
  reaches the appliance first becomes an approver, and on an air-gapped assessment
  laptop "first" often means "somebody else on the hotel wifi".
* Running this script requires **filesystem access to the deployment**, which is
  strictly stronger authentication of the act of taking privilege than any
  password an HTTP endpoint could check.

Passwords are never taken as an argument. ``--password`` on a command line lands
in shell history, in ``ps`` output and in PowerShell's transcript; this reads from
a prompt that does not echo, or from stdin with ``--password-stdin``.

What it does
------------
    python scripts/manage_users.py list
    python scripts/manage_users.py add     --username asha.n --role approver
    python scripts/manage_users.py passwd  --username asha.n
    python scripts/manage_users.py role    --username asha.n --role viewer
    python scripts/manage_users.py disable --username asha.n
    python scripts/manage_users.py enable  --username asha.n

    # provisioning, password from a secret store rather than a prompt
    Get-Content secret.txt | python scripts/manage_users.py add \
        --username asha.n --role auditor --password-stdin

Roles are ordered: ``viewer`` reads, ``auditor`` uploads and simulates,
``approver`` commits to the ledger and teaches the parser. Only ``approver`` can
turn a simulation into signed evidence, and the record says which approver did —
``actor`` is a hashed field, so that attribution is covered by the same signature
as the verdicts.

Deleting an account is deliberately not offered. The ledger's ``actor`` names the
row and the verifier resolves it, so removing a departed assessor would turn every
audit they ever committed into a record the verifier calls invalid. ``disable``
ends the access and keeps the history.

Not heavy: no download, no model, no GPU. Under a second per command, of which
0.2 s is the PBKDF2 derivation. MANUAL_COMMANDS.md Step 13.
"""

from __future__ import annotations

import argparse
import getpass
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_DB = PROJECT_ROOT / "data" / "praman.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    """Open the database with the schema present.

    ``init_database`` is called rather than assumed, so creating the first
    operator also works on a checkout that has not run Step 12 yet — the account
    is what the UI needs before it can show anything, and requiring a seeded
    ledger first would be a circular instruction.
    """
    from backend.db.connection import get_connection, init_database

    conn = get_connection(db_path)
    init_database(conn)
    return conn


def _read_password(confirm: bool, from_stdin: bool = False) -> str:
    """A password from a non-echoing prompt, or from stdin when asked for.

    ``--password-stdin`` exists because the obvious alternative — infer it from
    ``sys.stdin.isatty()`` — is wrong on the platform this ships on. On Windows,
    ``NUL`` and MSYS's ``/dev/null`` are *character devices*, so ``isatty()``
    answers ``True`` for a redirect that has no input in it at all, and the
    inferred prompt then blocks on a console read forever. A provisioning script
    that hangs is worse than one that fails, so the mode is declared rather than
    guessed. (An ordinary pipe does report ``False``, and is still accepted
    without the flag, because that case cannot hang.)

    The stdin path reads exactly one line and skips the confirmation: a pipeline
    cannot mistype twice differently. It is also why there is no ``--password``
    flag — argv lands in ``Get-History``, in ``ps``, and in PowerShell's
    transcript, whereas a pipe from a secret store does not.
    """
    from backend.app.auth import MIN_PASSWORD_LENGTH

    if from_stdin or not sys.stdin.isatty():
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            raise ValueError(
                "no password on stdin. With --password-stdin the password must "
                "arrive as one line: type it and press Enter, or pipe it in."
            )
        return password

    print(
        f"Password must be at least {MIN_PASSWORD_LENGTH} characters. It is stored "
        "as PBKDF2-HMAC-SHA256 (600,000 iterations, per-user salt) and cannot be "
        "read back."
    )
    password = getpass.getpass("password: ")
    if confirm and getpass.getpass("repeat:   ") != password:
        raise ValueError("the two entries do not match")
    return password


def cmd_list(conn: sqlite3.Connection, _args: argparse.Namespace) -> int:
    from backend.app.auth import list_users

    users = list_users(conn)
    if not users:
        print(
            "no operators yet. Every protected route is answering 401 until you "
            "create one:\n  python scripts/manage_users.py add --username <name> "
            "--role approver"
        )
        return 0

    print(f"{'username':<24} {'role':<9} {'login':<6} {'created':<32} state")
    for user in users:
        state = "disabled" if user["disabled_at"] else "active"
        login = "yes" if user["can_log_in"] else "no"
        print(
            f"{user['username']:<24} {user['role']:<9} {login:<6} "
            f"{user['created_at']:<32} {state}"
        )
    print(
        f"\n{len(users)} operator(s). 'login: no' is a service principal — it holds "
        "a row so the ledger verifier recognises its records, and no password so "
        "nothing can authenticate as it over HTTP."
    )
    return 0


def cmd_add(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    from backend.app.auth import SERVICE_PREFIX, create_user, validate_username

    # Both checks happen before the prompt, so a name or a flag the store would
    # reject anyway never costs the operator a typed passphrase.
    validate_username(args.username)

    is_service = args.username.startswith(SERVICE_PREFIX)
    if is_service != args.no_password:
        # Both directions are refused, and the second is the one worth explaining:
        # a ``service:`` principal *with* a password would be a login nobody
        # rotates, sitting in the ledger's actor field under a name that reads like
        # an unattended process. The prefix means "cannot authenticate over HTTP";
        # letting it hold a credential would make that name a lie.
        wrong = (
            f"'{args.username}' is a service principal, so it must be created with "
            "--no-password. A service name that can log in is a shared credential "
            "wearing a name that says it is not one."
            if is_service
            else f"--no-password is only for a '{SERVICE_PREFIX}' principal. A human "
            "operator who cannot log in is a mistake, not a configuration."
        )
        print(f"error: {wrong}", file=sys.stderr)
        return 2

    if is_service:
        create_user(conn, args.username, args.role, None)
        print(f"created service principal {args.username} ({args.role}), no password")
        return 0

    create_user(conn, args.username, args.role, _read_password(True, args.password_stdin))
    print(f"created {args.username} ({args.role})")
    if args.role == "approver":
        print(
            "  This account can commit audits to the ledger. Every record it "
            "writes names it in a hashed, signed field."
        )
    return 0


def cmd_passwd(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    from backend.app.auth import known_actors, set_password

    # Before the prompt, for the same reason as in ``cmd_add``: a name that is not
    # there should not cost a typed passphrase. ``set_password`` refuses it too —
    # this check is the courtesy, that one is the guarantee.
    if args.username not in known_actors(conn):
        raise ValueError(
            f"no operator named '{args.username}'. 'list' shows every name, "
            "disabled ones included."
        )

    set_password(conn, args.username, _read_password(True, args.password_stdin))
    print(
        f"password changed for {args.username}; live sessions revoked (a password "
        "change that left old tokens working would not have ended the access)"
    )
    return 0


def cmd_role(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    from backend.app.auth import set_role

    set_role(conn, args.username, args.role)
    print(f"{args.username} is now {args.role}; live sessions revoked")
    return 0


def cmd_disable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    from backend.app.auth import disable_user

    disable_user(conn, args.username)
    print(
        f"{args.username} disabled; live sessions revoked. The row is kept on "
        "purpose: the ledger names this operator, and deleting the row would make "
        "every audit they committed report an unknown actor."
    )
    return 0


def cmd_enable(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    from backend.app.auth import enable_user

    enable_user(conn, args.username)
    print(f"{args.username} enabled. Old tokens stay revoked — they must log in again.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    from backend.app.auth import ROLES

    parser = argparse.ArgumentParser(
        prog="python scripts/manage_users.py",
        description=(
            "Create and manage PRAMAN operator accounts. There is no default "
            "account and no HTTP route that creates one; this script is the only "
            "way, because running it proves filesystem access to the deployment."
        ),
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="path to praman.db")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="every operator, enabled or not")

    #: ``--password-stdin`` on both commands that need a password. Declaring the
    #: mode beats inferring it: see ``_read_password``.
    stdin_help = (
        "read the password as one line from stdin instead of prompting, for "
        "provisioning. Never pass a password on the command line — there is no "
        "flag for it, because argv is recorded by the shell"
    )

    add = sub.add_parser("add", help="create an operator (prompts for a password)")
    add.add_argument("--username", required=True)
    add.add_argument("--role", required=True, choices=ROLES)
    add.add_argument(
        "--no-password",
        action="store_true",
        help="create a 'service:' principal that cannot log in over HTTP",
    )
    add.add_argument("--password-stdin", action="store_true", help=stdin_help)

    passwd = sub.add_parser("passwd", help="change a password and revoke sessions")
    passwd.add_argument("--username", required=True)
    passwd.add_argument("--password-stdin", action="store_true", help=stdin_help)

    role = sub.add_parser("role", help="change a role and revoke sessions")
    role.add_argument("--username", required=True)
    role.add_argument("--role", required=True, choices=ROLES)

    disable = sub.add_parser("disable", help="end access, keep the row and the history")
    disable.add_argument("--username", required=True)

    enable = sub.add_parser("enable", help="undo disable; old tokens stay revoked")
    enable.add_argument("--username", required=True)

    return parser


#: Subcommand → handler. A dict rather than ``set_defaults(func=…)`` so the set of
#: commands is one readable list next to the parser that declares them.
_HANDLERS = {
    "list": cmd_list,
    "add": cmd_add,
    "passwd": cmd_passwd,
    "role": cmd_role,
    "disable": cmd_disable,
    "enable": cmd_enable,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    db_path = Path(args.db).resolve()

    conn = _connect(db_path)
    try:
        return _HANDLERS[args.command](conn, args)
    except ValueError as exc:
        # Every refusal in backend/app/auth.py is a ValueError carrying a message
        # written for the person at the keyboard — a weak password, a name the
        # ledger could not render, an account that is already taken. Printing it
        # beats a traceback that buries the same sentence under a stack.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ncancelled; nothing was changed", file=sys.stderr)
        return 130
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
