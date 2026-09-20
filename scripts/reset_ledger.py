"""Seed or reset the demo ledger: re-ingest the shipped fixtures.

Why this exists
---------------
Two jobs, one code path, because they are the same job.

**Seeding a fresh checkout.** ``data/praman.db`` is *not* in git — a 17 MB binary
that changes on every ingest is the worst thing to version, it diffs as noise, it
carries whatever the last developer happened to audit, and it would let a device
configuration reach a public repository by accident. So a clone has no database at
all, and this script is what makes one. Run with no ``--yes`` it changes nothing;
run with ``--yes`` against a missing file it goes straight to the reseed.

**Resetting an existing one.** The database that used to be tracked accumulated
its contents *before* ``tests/conftest.py`` grew the ``isolated_database``
fixture, so every row in it was residue from a test run against the operator's
real ledger, and two of its tables actively carried a fixed bug forward:

* ``mapping_store`` held six "approved" mappings whose templates contain
  ``*** REDACTED ***`` — the old three-token replacement string. They were taught
  from text mangled by the pre-parse redaction filter, all six claim the same
  canonical path, and none of them can ever match again: the token is now a
  single field, and redaction runs *after* the parse, so the training queue never
  sees a redacted ``enable secret`` line at all. They are the bug's fossil record
  filed as institutional knowledge.
* ``audit_records`` held records predating the current record-hash and Merkle
  definitions. All of them fail verification, and a ledger that fails on healthy
  data cannot report unhealthy data — the operator learns to ignore the red
  crosses.

Either way the useful state is not "what is in the database", it is "the fixtures
in ``test_configs/``". This script makes the second the first.

What it does, in order
----------------------
1. Inventories the database and names, per table, why its rows are going.
   Skipped when there is no database yet — there is nothing to account for.
2. Copies the file to ``praman.db.bak-<utc>`` — the whole operation is one
   ``Move-Item`` away from being undone, which is what makes it safe to run.
   Also skipped on a fresh seed, for the same reason.
3. Clears the six device-scoped tables and reclaims the space.
4. Re-ingests every fixture through the real ``/ingest`` and ``/audit/commit``
   routes, so hashes, facts, findings and ledger records are all written by the
   same code path an operator's upload uses — not by a shortcut that could agree
   with itself while disagreeing with production.
5. Verifies the result with ``backend/ledger/verify.py``, the standalone verifier
   that imports nothing from ``backend/``.

Without ``--yes`` it stops after step 1 and changes nothing.

    python scripts/reset_ledger.py
    python scripts/reset_ledger.py --yes

Runtime is a few seconds: measured 0.8 s for the first fixture (loading catalogs
and rule packs) and ~0.12 s each for the rest, plus the backup copy and a VACUUM.
No download, no model, no GPU. MANUAL_COMMANDS.md Step 12.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only, so the annotation resolves for a checker without pulling
    # FastAPI into a CLI that usually does not reseed anything. The runtime
    # import stays inside ``_reseed`` for the same reason.
    from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_DB = PROJECT_ROOT / "data" / "praman.db"
FIXTURE_DIR = PROJECT_ROOT / "test_configs"

#: The legacy replacement token. Its presence in a row is direct evidence that
#: the row was written before the redaction fix — see the module docstring.
LEGACY_REDACTION_TOKEN = "*** REDACTED ***"

#: Tables cleared by a reset, and why. Order matters: children before parents, so
#: the foreign keys hold at every intermediate point even under
#: ``PRAGMA foreign_keys = ON``.
PURGED_TABLES: tuple[tuple[str, str], ...] = (
    ("findings", "verdicts belong to an audit; a reseed recomputes them"),
    ("audit_records", "ledger rows predating the current hash definitions"),
    ("canonical_facts", "facts belong to a device; a reseed re-parses them"),
    ("training_queue", "unparsed lines from probe devices, carrying the old token"),
    ("mapping_store", "taught mappings learned from text the old filter mangled"),
    ("devices", "probe devices: demo.conf, cv.conf, cft.conf, lc.conf, …"),
)


def _count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.OperationalError:
        return -1


def _legacy_token_rows(conn: sqlite3.Connection) -> list[str]:
    """Rows still carrying ``*** REDACTED ***``, as evidence rather than a count."""
    found: list[str] = []
    probes = (
        ("mapping_store", "drain3_template"),
        ("training_queue", "raw_text"),
        ("canonical_facts", "raw_text"),
    )
    for table, column in probes:
        try:
            rows = conn.execute(
                f"SELECT {column} FROM {table} WHERE {column} LIKE ?",
                (f"%{LEGACY_REDACTION_TOKEN}%",),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        for (value,) in rows:
            found.append(f"{table}.{column}: {value[:64]}")
    return found


def inventory(db_path: Path) -> dict[str, int]:
    """Print what is in the database and why each table is going. No writes."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        counts = {table: _count(conn, table) for table, _ in PURGED_TABLES}
        print(f"database: {db_path}")
        print(f"size:     {db_path.stat().st_size:,} bytes\n")
        for table, reason in PURGED_TABLES:
            n = counts[table]
            shown = "absent" if n < 0 else f"{n:>6} rows"
            print(f"  {table:<16} {shown}   {reason}")

        legacy = _legacy_token_rows(conn)
        if legacy:
            print(
                f"\n  {len(legacy)} row(s) still carry the pre-fix "
                f"'{LEGACY_REDACTION_TOKEN}' token:"
            )
            for line in legacy[:8]:
                print(f"    {line}")
            if len(legacy) > 8:
                print(f"    … and {len(legacy) - 8} more")
        return counts
    finally:
        conn.close()


def back_up(db_path: Path) -> Path:
    """Copy the database beside itself with a UTC timestamp. Returns the copy."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = db_path.with_name(f"{db_path.name}.bak-{stamp}")
    shutil.copy2(db_path, backup)
    return backup


def purge(db_path: Path, keep_mappings: bool) -> dict[str, int]:
    """Delete every row from the purged tables. Returns rows deleted per table."""
    from backend.db.connection import (
        create_append_only_triggers,
        drop_append_only_triggers,
    )

    deleted: dict[str, int] = {}
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        # ``audit_records`` carries append-only triggers that abort any DELETE —
        # which is the point of them, and this script is the one caller entitled to
        # disarm them. Doing it explicitly here (rather than never installing them)
        # keeps the guarantee true for every other code path, and the timestamped
        # backup taken above is what makes the exception accountable.
        drop_append_only_triggers(conn)
        for table, _reason in PURGED_TABLES:
            if keep_mappings and table == "mapping_store":
                continue
            try:
                deleted[table] = conn.execute(f"DELETE FROM {table}").rowcount
            except sqlite3.OperationalError as exc:
                print(f"  WARNING: could not clear {table}: {exc}")
        # AUTOINCREMENT counters survive a DELETE, so a reseeded database would
        # start its findings at id 6249. Harmless, but it makes the ids look like
        # they have history the database no longer holds.
        conn.execute("DELETE FROM sqlite_sequence")
        create_append_only_triggers(conn)
        conn.commit()
    finally:
        conn.close()

    # VACUUM has to run outside a transaction, hence its own connection.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("VACUUM")
    finally:
        conn.close()
    return deleted


def reseed(fixtures: list[Path], db_path: Path) -> tuple[list[dict], list[str]]:
    """Ingest and commit every fixture through the real routes.

    Returns ``(committed records, failures)``. Uses ``TestClient`` rather than a
    live HTTP server so the script needs no port and no separate process, but the
    request path through FastAPI is the same one a browser upload takes.

    ``STATE.db_path`` is pointed at ``db_path`` first. Without that the app would
    write to its configured default while this script had just purged whatever
    ``--db`` named — so a non-default ``--db`` would empty one database and seed
    another, and the verifier at the end would be reading a file nothing had
    written to.

    **Identity.** ``/ingest`` and ``/audit/commit`` now require an authenticated
    operator, and ``actor`` is a hashed field of every ledger record, so this
    script has to name itself. It does so as ``service:reset-ledger`` — a service
    principal, created here if absent — rather than by logging in as a human:

    * There is no human to log in as. This entry point authenticates whoever has
      filesystem access to the deployment, which is strictly more privilege than a
      password grants, and writing an operator's name into a signed record they
      were not present for would be a false attribution.
    * A reviewer who finds ``service:reset-ledger`` in a record knows exactly what
      it is worth: demo data, reproducible from ``test_configs/``, not an
      assessment anybody signed off.

    The row is created because ``actor_valid`` resolves the recorded name against
    the ``users`` table — a reseeded ledger whose every record named an unknown
    actor would report itself as broken, which is the opposite of what a freshly
    seeded database should say.
    """
    from fastapi.testclient import TestClient

    from backend.app.auth import (
        ROLE_APPROVER,
        SERVICE_RESEED,
        current_principal,
        ensure_service_account,
    )
    from backend.app.main import app
    from backend.app.state import STATE

    STATE.db_path = db_path
    STATE.learned.invalidate()

    conn = STATE.connect()
    try:
        principal = ensure_service_account(conn, SERVICE_RESEED, ROLE_APPROVER)
    finally:
        conn.close()
    # An override rather than a login: a ``service:`` account holds no password, on
    # purpose, so that nothing can authenticate as it over HTTP. The gate itself is
    # unchanged and still runs — the role check below is the real one — but the
    # credential comes from the fact that this code is executing on the host.
    app.dependency_overrides[current_principal] = lambda: principal
    try:
        return _reseed_with(TestClient(app), fixtures)
    finally:
        app.dependency_overrides.pop(current_principal, None)


def _reseed_with(
    client: TestClient, fixtures: list[Path]
) -> tuple[list[dict], list[str]]:
    """Drive ``/ingest`` then ``/audit/commit`` for each fixture, in order."""
    committed: list[dict] = []
    failures: list[str] = []

    for path in fixtures:
        started = time.perf_counter()
        payload = path.read_bytes()
        response = client.post(
            "/ingest", files={"file": (path.name, payload, "text/plain")}
        )
        if response.status_code != 200:
            failures.append(f"{path.name}: ingest returned {response.status_code}")
            print(f"  {path.name:<34} INGEST FAILED {response.status_code}")
            continue
        ingested = response.json()
        device_id = ingested["device_id"]

        response = client.post("/audit/commit", json={"device_id": device_id})
        if response.status_code != 200:
            failures.append(f"{path.name}: commit returned {response.status_code}")
            print(f"  {path.name:<34} COMMIT FAILED {response.status_code}")
            continue
        record = response.json()
        committed.append(record)
        elapsed = time.perf_counter() - started
        print(
            f"  {path.name:<34} seq={record['seq']:<3} "
            f"findings={record['findings_count']:<5} {elapsed:5.2f}s"
        )

    return committed, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python scripts/reset_ledger.py",
        description=(
            "Seed a fresh data/praman.db from the shipped fixtures, or purge an "
            "existing one and reseed it. Inspects only unless --yes is given."
        ),
    )
    parser.add_argument("--db", default=str(DEFAULT_DB), help="path to praman.db")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="actually do it: back up, purge, reseed, verify",
    )
    parser.add_argument(
        "--keep-mappings",
        action="store_true",
        help=(
            "leave mapping_store alone. Only useful if you have taught mappings "
            "worth keeping — the ones shipped in the demo database are not"
        ),
    )
    args = parser.parse_args(argv)

    db_path = Path(args.db).resolve()
    # A missing database is the fresh-clone case, not an error: ``data/praman.db``
    # is gitignored, so this is the *only* way a checkout gets one. Distinguishing
    # it here rather than failing keeps one script for seeding and reseeding, so
    # the seeded state and the reset state cannot drift apart.
    fresh = not db_path.is_file()
    if fresh:
        print(f"no database at {db_path} — this is the fresh-checkout seed path.")
        print(
            "  data/praman.db is gitignored on purpose (a 17 MB binary that "
            "changes on every ingest, and a place a real config could leak).\n"
        )
        counts: dict[str, int] = {}
    else:
        counts = inventory(db_path)

    fixtures = sorted(FIXTURE_DIR.rglob("*.conf"))
    if not fixtures:
        print(f"\nno fixtures under {FIXTURE_DIR} — nothing to reseed with", file=sys.stderr)
        return 2
    print(f"\nreseed source: {len(fixtures)} fixture(s) under {FIXTURE_DIR}")

    if not args.yes:
        if fresh:
            print(
                "\nDRY RUN — nothing was changed. Re-run with --yes to create the "
                f"database and seed it from the {len(fixtures)} fixture(s) above."
            )
            return 0
        total = sum(n for n in counts.values() if n > 0)
        print(
            f"\nDRY RUN — nothing was changed. Re-run with --yes to back up the "
            f"database, drop {total:,} row(s), and reseed from the fixtures above."
        )
        return 0

    if fresh:
        from backend.db.connection import get_connection, init_database

        conn = get_connection(db_path)
        try:
            init_database(conn)
        finally:
            conn.close()
        print(f"created:  {db_path} (schema, migrations, append-only triggers)\n")
    else:
        backup = back_up(db_path)
        print(f"\nbackup:   {backup}")
        print("          restore with:  Move-Item -Force "
              f"{backup.name} {db_path.name}\n")

        deleted = purge(db_path, keep_mappings=args.keep_mappings)
        print("purged:   " + ", ".join(f"{table} {n}" for table, n in deleted.items()))
        if args.keep_mappings:
            print("          mapping_store left alone (--keep-mappings)")

    print("\nreseeding:")
    committed, failures = reseed(fixtures, db_path)

    print(f"\ncommitted {len(committed)} audit(s) from {len(fixtures)} fixture(s)")
    if failures:
        print("failures:")
        for line in failures:
            print(f"  {line}")

    print("\nverifying with the standalone verifier:\n")
    from backend.ledger.verify import EXIT_VERIFIED
    from backend.ledger.verify import main as verify_main

    verify_exit = verify_main([str(db_path)])

    if failures:
        return 1
    if verify_exit != EXIT_VERIFIED:
        print(
            "\nThe reseeded ledger does not fully verify. That is a bug in the "
            "commit path, not in this script — restore the backup and report it."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
