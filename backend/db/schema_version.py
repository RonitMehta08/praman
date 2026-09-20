"""Schema versioning and the migration the version certifies.

Migrating *forward* is the easy half, and :func:`migrate` does it: the columns
that landed after the first published schema are added idempotently and
additively, so a database written by an older build keeps every row it had. That
direction is loud when it goes wrong — a missing column raises ``no such column``
immediately.

The other direction does not. A **newer** database opened by an **older** build
looks perfectly healthy, because SQLite does not object to a column the reader
has never heard of. Selects succeed, inserts succeed, and every column the newer
build relies on is quietly left at its default.

For ``audit_records`` that is not cosmetic. ``actor`` is inside
``RECORD_HASH_FIELDS``, so the older build appends records hashed over a
different field set, interleaved into the same chain as records that were not,
and ``scripts/verify_ledger.py`` subsequently reports corruption on rows nobody
tampered with. The ledger's entire claim is that a verification failure means
something. That is what a version check protects, and it is why the check refuses
rather than warns.

Kept in its own module because ``connection.py`` was at 498 of its 500 permitted
lines (``GLOBAL_RULESET.md`` §145) and this pushed it to 557 —
``scripts/check_deliverable_limits.py`` caught it, which is the ratchet doing
exactly what it was written for on the first change after it landed. The
migration moved across with it rather than staying behind, because the version is
a *claim about* the migration: bump one without the other and the stamp starts
lying. Keeping them in one file is what makes that mistake visible in a diff.
"""

from __future__ import annotations

import sqlite3

from backend.core_errors import SentinelError

#: Bumped whenever :data:`ADDED_COLUMNS` or the DDL in ``connection.py`` gains
#: something a previous build did not write. Stored in SQLite's own ``PRAGMA
#: user_version``, a four-byte field in the database header — no table to create,
#: and it travels with the file when someone copies it off a machine.
#:
#: Version 1 was the schema as first published. Version 2 is that schema plus the
#: seven columns in :data:`ADDED_COLUMNS` and the two indexes :func:`migrate`
#: creates.
SCHEMA_VERSION = 2

#: Columns added after the first schema was published. ``CREATE TABLE IF NOT
#: EXISTS`` is a no-op on an existing database, so a new column in the DDL in
#: ``connection.py`` would only reach a database created from scratch — and every
#: developer who had already run an ingest would get "no such column" instead.
ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "training_queue": {
        # Which platform the line came from. A template is only meaningful for
        # the dialect that produced it: `set system services ssh` is a Junos
        # command and teaching it against a Cisco pack would never match.
        "vendor": "TEXT NOT NULL DEFAULT ''",
        "first_seen_at": "TEXT NOT NULL DEFAULT ''",
        "block": "TEXT NOT NULL DEFAULT ''",
    },
    "mapping_store": {
        "vendor": "TEXT NOT NULL DEFAULT '*'",
        # Which masked operand in the template carries the value.
        "value_index": "INTEGER NOT NULL DEFAULT 0",
        "status": "TEXT NOT NULL DEFAULT 'approved'",
    },
    "audit_records": {
        # Who committed this audit. Unlike every other column added here, this
        # one is inside RECORD_HASH_FIELDS, so adding it changes the hash
        # definition and every record written before it fails its own integrity
        # check — correctly, since their hashes were computed over a different
        # field set. The default '' is what lets the ALTER succeed on rows that
        # already exist; re-seeding them is MANUAL_COMMANDS.md Step 12, and
        # scripts/reset_ledger.py exists for exactly this.
        "actor": "TEXT NOT NULL DEFAULT ''",
    },
}


class SchemaVersionError(SentinelError):
    """The database was written by a build that knows more than this one does."""


def migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after a database may already have been created.

    Idempotent and additive only: nothing is dropped, renamed or retyped, so a
    database written by an older build keeps every row it had. Called from
    ``init_database``, which every request path already invokes.
    """
    for table, columns in ADDED_COLUMNS.items():
        existing = {
            row["name"] for row in conn.execute(f'PRAGMA table_info("{table}")')
        }
        if not existing:
            continue  # table absent entirely; the DDL will have made it
        for name, declaration in columns.items():
            if name not in existing:
                conn.execute(f'ALTER TABLE "{table}" ADD COLUMN {name} {declaration}')
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tq_template ON training_queue(template_id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ms_vendor ON mapping_store(vendor)"
    )


def check_schema_version(conn: sqlite3.Connection) -> int:
    """Refuse a future schema; return the version found. Writes nothing.

    A brand-new file reports 0, which is indistinguishable from a version-1
    database — SQLite cannot tell "never stamped" from "stamped zero", and
    version 1 predates the stamping. Both are accepted, which is safe precisely
    because the migration is additive and idempotent: running it against a
    database that is already current does nothing.
    """
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version > SCHEMA_VERSION:
        raise SchemaVersionError(
            f"This database is at schema version {version}; this build understands "
            f"{SCHEMA_VERSION}. It was written by a newer PRAMAN, and opening it "
            f"anyway would append ledger records hashed over a stale field set to a "
            f"chain the newer build has already extended — which the verifier would "
            f"later report as tampering. Upgrade PRAMAN, or point DATABASE_PATH at "
            f"a different file."
        )
    return version


def stamp_schema_version(conn: sqlite3.Connection) -> None:
    """Record the current version. Call only *after* a successful migration.

    A version written before the columns exist tells the next build there is
    nothing to do, which converts a recoverable half-migrated database into a
    permanently broken one. ``PRAGMA`` accepts no bound parameters, hence the
    interpolation — of an ``int`` literal defined in this module, never of input.
    """
    conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
