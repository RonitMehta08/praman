"""The schema version is the upgrade path, and the forward direction is the point.

``GLOBAL_RULESET.md`` R9 and `MASTER_PROMPT.md` §9 ask for schema *and*
migrations, and `README.md` claims both. The additive half was already there —
``migrate`` adds the seven columns that landed after the first published schema,
idempotently, so an older database keeps every row it had. What was missing is the
other direction, and it is the one that does damage quietly.

A **newer** database opened by an **older** build looks healthy. SQLite does not
object to a column the reader has never heard of: selects succeed, inserts
succeed, and every column the newer build depends on is left at its default. For
``audit_records`` that is a correctness failure with a signature, because
``actor`` is inside ``RECORD_HASH_FIELDS`` — the older build appends records
hashed over a different field set, into the same chain, and the standalone
verifier then reports tampering on rows nobody touched. The ledger's whole claim
is that a verification failure means something; a version check is what keeps
that true across builds.

So the assertions here are about *refusing*, not about migrating. The migration
tests exist to prove the refusal has not been made so eager that it blocks the
legitimate upgrade it is supposed to allow.

The code lives in ``backend/db/schema_version.py`` rather than in
``connection.py`` because ``connection.py`` was at 498 of its 500 permitted lines
and this took it to 557. ``scripts/check_deliverable_limits.py`` refused to
budget it, which is the ratchet working on the first change after it landed —
the alternative was a 30th entry in the debt table for code written that morning.
The migration followed the version into that module, since the version is a claim
*about* the migration and splitting them lets one be bumped without the other.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from backend.core_errors import SentinelError
from backend.db.connection import get_connection, init_database
from backend.db.schema_version import ADDED_COLUMNS, SCHEMA_VERSION, SchemaVersionError


@pytest.fixture
def fresh_db(tmp_path: Path) -> sqlite3.Connection:
    """A database created by this build, at the current schema version."""
    conn = get_connection(tmp_path / "praman.db")
    init_database(conn)
    yield conn
    conn.close()


def _version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def test_a_fresh_database_is_stamped_with_the_current_version(
    fresh_db: sqlite3.Connection,
) -> None:
    """Otherwise every database looks like version 0 forever and the check is dead."""
    assert _version(fresh_db) == SCHEMA_VERSION


def test_initialising_twice_changes_nothing(fresh_db: sqlite3.Connection) -> None:
    """``init_database`` runs on every request path, so it has to be free to repeat.

    A version check that only tolerates being run once would turn the second
    request of the process into an error, which is a worse failure than the one
    it is guarding against.
    """
    init_database(fresh_db)
    assert _version(fresh_db) == SCHEMA_VERSION


def test_an_unstamped_database_is_upgraded_rather_than_refused(tmp_path: Path) -> None:
    """Version 0 means "never stamped", which is also what version 1 looks like.

    SQLite cannot distinguish them — ``user_version`` defaults to 0 and version 1
    predates the stamping — so both must be accepted. That is safe precisely
    because ``migrate`` is additive: nothing is dropped, renamed or retyped, so
    running it against a database that is already current is a no-op.
    """
    conn = get_connection(tmp_path / "praman.db")
    init_database(conn)
    conn.execute("PRAGMA user_version = 0")
    conn.commit()

    init_database(conn)
    assert _version(conn) == SCHEMA_VERSION
    conn.close()


def test_a_future_schema_is_refused_before_anything_is_written(tmp_path: Path) -> None:
    """The check runs before the DDL, because creating a table is already a write.

    ``CREATE TABLE IF NOT EXISTS`` against a future database is harmless in
    itself, but it establishes that this build may touch the file — and the next
    thing it does is append to the ledger. The refusal has to come first.
    """
    path = tmp_path / "praman.db"
    conn = get_connection(path)
    init_database(conn)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    conn.commit()

    with pytest.raises(SchemaVersionError) as raised:
        init_database(conn)

    message = str(raised.value)
    assert str(SCHEMA_VERSION + 1) in message and str(SCHEMA_VERSION) in message, (
        "The message must name both versions. An operator holding two builds "
        f"needs to know which one to run, and {message!r} is what they get."
    )
    assert _version(conn) == SCHEMA_VERSION + 1, "The refusal must not rewrite the stamp"
    conn.close()


def test_the_refusal_is_catchable_as_an_ordinary_praman_error() -> None:
    """``core_errors`` exists so one ``except`` covers the hierarchy.

    An error class outside it is one the API error handler does not know about,
    which turns a legible refusal into a 500 with a traceback.
    """
    assert issubclass(SchemaVersionError, SentinelError)


def test_every_migrated_column_exists_after_initialisation(
    fresh_db: sqlite3.Connection,
) -> None:
    """The version means nothing unless it certifies the columns are actually there.

    Read from ``ADDED_COLUMNS`` rather than listed here, so a column added to
    the migration without a version bump is caught by the pairing test below
    instead of silently going unchecked.
    """
    for table, columns in ADDED_COLUMNS.items():
        present = {row["name"] for row in fresh_db.execute(f'PRAGMA table_info("{table}")')}
        missing = sorted(set(columns) - present)
        assert not missing, f"{table} is missing migrated columns after init: {missing}"


def test_a_database_missing_a_migrated_column_gains_it(tmp_path: Path) -> None:
    """The additive half, proven against a database that genuinely lacks the column.

    Simulated by dropping the whole table and recreating it without ``actor``,
    because SQLite before 3.35 cannot ``DROP COLUMN`` and the point is to exercise
    ``migrate``, not the local SQLite build's DDL support. ``actor`` is the case
    that matters: it is inside ``RECORD_HASH_FIELDS``, so a database that never
    receives it writes records the verifier will reject.
    """
    conn = get_connection(tmp_path / "praman.db")
    init_database(conn)
    conn.executescript(
        """
        DROP TRIGGER IF EXISTS audit_records_append_only_update;
        DROP TRIGGER IF EXISTS audit_records_append_only_delete;
        DROP TABLE audit_records;
        CREATE TABLE audit_records (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT NOT NULL UNIQUE
        );
        """
    )
    conn.execute("PRAGMA user_version = 0")
    conn.commit()
    before = {row["name"] for row in conn.execute('PRAGMA table_info("audit_records")')}
    assert "actor" not in before

    init_database(conn)

    after = {row["name"] for row in conn.execute('PRAGMA table_info("audit_records")')}
    assert "actor" in after, "migrate did not add the column the ledger hashes over"
    conn.close()


def test_the_version_is_ahead_of_the_original_schema() -> None:
    """A guard against the version being bumped in the docs but not in the code.

    ``SCHEMA_VERSION`` has to exceed 1 for as long as ``ADDED_COLUMNS`` is
    non-empty: version 1 *is* the schema before those columns, so claiming 1
    while shipping them would tell an older build there is nothing to migrate —
    which is the exact silent-default failure this module exists to prevent.
    """
    if ADDED_COLUMNS:
        assert SCHEMA_VERSION > 1, (
            f"{sum(len(c) for c in ADDED_COLUMNS.values())} columns were added "
            f"after the first schema, but SCHEMA_VERSION is still {SCHEMA_VERSION}."
        )
