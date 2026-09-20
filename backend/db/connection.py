"""SQLite database connection and schema management.

Uses WAL mode, JSON1, and FTS5 extensions. Zero-infra: no external database
server required. Version checking and stamping live in ``db/schema_version.py``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.app.config import DATABASE_PATH
from backend.db.schema_version import check_schema_version, migrate, stamp_schema_version


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Create or open a SQLite database connection with WAL mode."""
    path = db_path or DATABASE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_database(conn: sqlite3.Connection) -> None:
    """Create tables if absent, migrate, then stamp the schema version.

    The version check runs before any DDL: creating a table against a database
    from a newer build is already a write, and the point is that this build has
    no business writing to that file at all. See ``db/schema_version.py``.
    """
    check_schema_version(conn)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            vendor TEXT NOT NULL,
            os_family TEXT NOT NULL,
            hostname TEXT,
            serials TEXT NOT NULL DEFAULT '[]',  -- JSON array
            hardware TEXT NOT NULL DEFAULT '[]',  -- JSON array
            os_version TEXT,
            source_file TEXT NOT NULL,
            config_hash TEXT NOT NULL,
            ingested_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS canonical_facts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            path TEXT NOT NULL,
            value TEXT,  -- JSON-encoded
            present INTEGER NOT NULL DEFAULT 1,
            source_file TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            raw_text TEXT NOT NULL,
            parser_id TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            framework TEXT NOT NULL,
            benchmark TEXT NOT NULL,
            benchmark_version TEXT NOT NULL,
            title TEXT NOT NULL,
            result TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT NOT NULL DEFAULT '[]',  -- JSON array
            rationale TEXT NOT NULL DEFAULT '',
            remediation_ref TEXT,
            "references" TEXT NOT NULL DEFAULT '{}',  -- JSON object
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        );

        CREATE TABLE IF NOT EXISTS audit_records (
            audit_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            config_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',  -- who committed it; inside record_hash
            summary TEXT NOT NULL DEFAULT '{}',  -- JSON
            seq INTEGER NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL DEFAULT '',
            record_hash TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            signature TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        );

        -- Operators. No row is created by this DDL: there is no default account
        -- and no bootstrap endpoint, so an unconfigured deployment authorises
        -- nothing rather than authorising whoever knows the shipped password.
        -- The first operator is created with scripts/manage_users.py, which
        -- requires filesystem access to the deployment.
        --
        -- Rows are disabled, never deleted. audit_records.actor names this table
        -- and the standalone verifier checks that the name resolves; deleting a
        -- departed assessor would turn every audit they committed into a record
        -- the verifier calls invalid.
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            role TEXT NOT NULL,  -- viewer | auditor | approver
            password_hash TEXT NOT NULL DEFAULT '',  -- '' = cannot log in (service)
            created_at TEXT NOT NULL,
            disabled_at TEXT  -- NULL while active
        );

        -- Live bearer tokens. Only the SHA-256 of each token is stored, so a
        -- reader of this file gains nothing presentable — which matters because
        -- the same file holds the device configurations the tool has ranked by
        -- exploitability.
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            FOREIGN KEY (username) REFERENCES users(username)
        );

        -- Every request that reached a protected route, reads included.
        -- docs/PRODUCTION-ROADMAP.md §1.4 names the gap this closes: the ledger
        -- recorded writes and nothing recorded reads, so "who looked at the
        -- unredacted configuration of the core router" had no answer at all.
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',  -- '' when the request was unauthenticated
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            client TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS training_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            raw_text TEXT NOT NULL,
            source_file TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            template_id TEXT,
            drain3_template TEXT,
            cluster_size INTEGER DEFAULT 1,
            mapped_path TEXT,  -- NULL until admin maps it
            admin_id TEXT,
            mapped_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending'  -- pending | mapped | skipped
        );

        CREATE TABLE IF NOT EXISTS mapping_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            drain3_template TEXT NOT NULL UNIQUE,
            canonical_path TEXT NOT NULL,
            admin_id TEXT NOT NULL,
            note TEXT DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
        CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id);
        CREATE INDEX IF NOT EXISTS idx_findings_framework ON findings(framework);
        CREATE INDEX IF NOT EXISTS idx_facts_device ON canonical_facts(device_id);
        CREATE INDEX IF NOT EXISTS idx_facts_path ON canonical_facts(path);
        CREATE INDEX IF NOT EXISTS idx_tq_status ON training_queue(status);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
        CREATE INDEX IF NOT EXISTS idx_access_log_at ON access_log(at);
        CREATE INDEX IF NOT EXISTS idx_access_log_actor ON access_log(actor);
        """
    )
    migrate(conn)
    create_append_only_triggers(conn)
    stamp_schema_version(conn)  # last, and only once the migration has succeeded
    conn.commit()


#: Storage-layer enforcement of the append-only claim on ``audit_records``.
#:
#: The hash chain makes tampering *detectable*; these make the ordinary kinds of
#: it *impossible*. Both matter, and they fail differently: a stray ``UPDATE`` in
#: a migration script or a support engineer "fixing" a timestamp is caught here,
#: at the statement, with a message saying why — rather than surfacing weeks later
#: as an unexplained verification failure nobody can attribute.
#:
#: This is not a defence against an attacker holding the database file. Anyone who
#: can write to it can also ``DROP TRIGGER``. That attacker is the hash chain's
#: job, and the chain still detects them — which is why the layers are worth
#: having separately. ``tests/test_ledger_standalone_verify.py`` drops these on
#: purpose to play that attacker.
_APPEND_ONLY_TRIGGERS = (
    # The RAISE messages are single long literals on purpose: SQL has no
    # adjacent-literal concatenation, so wrapping one across two lines makes it a
    # syntax error rather than a shorter line.
    """
    CREATE TRIGGER IF NOT EXISTS audit_records_append_only_update
    BEFORE UPDATE ON audit_records
    BEGIN
        SELECT RAISE(ABORT, 'audit_records is append-only: a committed audit record cannot be modified. Commit a new audit instead.');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_records_append_only_delete
    BEFORE DELETE ON audit_records
    BEGIN
        SELECT RAISE(ABORT, 'audit_records is append-only: a committed audit record cannot be deleted. To re-seed the ledger, run scripts/reset_ledger.py.');
    END
    """,
)

_APPEND_ONLY_TRIGGER_NAMES = (
    "audit_records_append_only_update",
    "audit_records_append_only_delete",
)


def create_append_only_triggers(conn: sqlite3.Connection) -> None:
    """Install the ``audit_records`` append-only triggers. Idempotent."""
    for statement in _APPEND_ONLY_TRIGGERS:
        conn.execute(statement)


def drop_append_only_triggers(conn: sqlite3.Connection) -> None:
    """Remove the append-only triggers.

    Deliberately explicit and deliberately ugly to call: the only legitimate
    reasons to disarm the ledger are re-seeding it after a hash-definition change
    (``scripts/reset_ledger.py``) and a test proving the hash chain catches what
    the triggers cannot. Anything else should be committing a new audit.
    """
    for name in _APPEND_ONLY_TRIGGER_NAMES:
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")


def store_device(conn: sqlite3.Connection, device_data: dict[str, Any]) -> None:
    """Insert or replace a device record."""
    conn.execute(
        """
        INSERT OR REPLACE INTO devices
        (device_id, vendor, os_family, hostname, serials, hardware,
         os_version, source_file, config_hash, ingested_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_data["device_id"],
            device_data["vendor"],
            device_data["os_family"],
            device_data.get("hostname"),
            json.dumps(device_data.get("serials", [])),
            json.dumps(device_data.get("hardware", [])),
            device_data.get("os_version"),
            device_data["source_file"],
            device_data["config_hash"],
            device_data["ingested_at"],
        ),
    )
    conn.commit()


def store_facts(
    conn: sqlite3.Connection,
    device_id: str,
    facts: list[dict[str, Any]],
) -> None:
    """Insert canonical facts for a device (replaces existing)."""
    conn.execute("DELETE FROM canonical_facts WHERE device_id = ?", (device_id,))
    for fact in facts:
        conn.execute(
            """
            INSERT INTO canonical_facts
            (device_id, path, value, present, source_file,
             line_start, line_end, raw_text, parser_id, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                fact["path"],
                json.dumps(fact["value"]),
                1 if fact["present"] else 0,
                fact["source_file"],
                fact["line_start"],
                fact["line_end"],
                fact["raw_text"],
                fact["parser_id"],
                fact["confidence"],
            ),
        )
    conn.commit()


def store_findings(
    conn: sqlite3.Connection,
    audit_id: str,
    device_id: str,
    findings: list[dict[str, Any]],
) -> None:
    """Insert findings for an audit."""
    for f in findings:
        conn.execute(
            """
            INSERT INTO findings
            (audit_id, device_id, control_id, framework, benchmark,
             benchmark_version, title, result, severity, evidence,
             rationale, remediation_ref, "references")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                device_id,
                f["control_id"],
                f["framework"],
                f["benchmark"],
                f["benchmark_version"],
                f["title"],
                f["result"],
                f["severity"],
                json.dumps(f.get("evidence", []), default=str),
                f.get("rationale", ""),
                f.get("remediation_ref"),
                json.dumps(f.get("references", {})),
            ),
        )
    conn.commit()


#: The fields of a :class:`~backend.canonical.findings.Finding`, in model order.
#: Named here rather than imported so the storage layer does not depend on the
#: model layer; ``tests/test_ledger_chain.py`` asserts the two agree, which is
#: what keeps this from drifting when a field is added.
FINDING_FIELDS = (
    "control_id",
    "framework",
    "benchmark",
    "benchmark_version",
    "title",
    "result",
    "severity",
    "evidence",
    "rationale",
    "remediation_ref",
    "references",
)

#: Columns of the findings table holding JSON, and what an empty one decodes to.
_FINDING_JSON_COLUMNS = {"evidence": "[]", "references": "{}"}


def finding_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """A findings row as the finding dict it was stored from.

    The exact inverse of :func:`store_findings`, and it has to be exact. The
    Merkle root in the ledger was computed over ``Finding.model_dump(mode="json")``,
    so a projection that kept the table's own ``id``, ``audit_id`` and
    ``device_id`` columns, or that left ``evidence`` as a JSON string, would
    recompute a different root and report a healthy audit as tampered with. Both
    the report route and the ledger verifier read findings through here so there
    is only one projection to get right.
    """
    item = dict(row)
    projected: dict[str, Any] = {}
    for name in FINDING_FIELDS:
        value = item.get(name)
        if name in _FINDING_JSON_COLUMNS and isinstance(value, str):
            value = json.loads(value or _FINDING_JSON_COLUMNS[name])
        elif name in _FINDING_JSON_COLUMNS and value is None:
            value = json.loads(_FINDING_JSON_COLUMNS[name])
        projected[name] = value
    return projected


def get_latest_seq(conn: sqlite3.Connection) -> int:
    """Return the latest seq number from the audit ledger, or 0 if empty."""
    row = conn.execute(
        "SELECT MAX(seq) as max_seq FROM audit_records"
    ).fetchone()
    return row["max_seq"] if row and row["max_seq"] is not None else 0


def get_prev_hash(conn: sqlite3.Connection) -> str:
    """Return the record_hash of the latest audit record, or '' for genesis."""
    row = conn.execute(
        "SELECT record_hash FROM audit_records ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    return row["record_hash"] if row else ""


def record_access(
    conn: sqlite3.Connection,
    *,
    actor: str,
    method: str,
    path: str,
    status: int,
    duration_ms: int,
    client: str,
) -> None:
    """Append one line to the read/write access log.

    Deliberately best-effort at the call site: a failure to log must not fail the
    request that was already served. It is not best-effort about *what* it logs —
    the actor, the path and the status are recorded for reads as well as writes,
    which is the whole point. ``docs/PRODUCTION-ROADMAP.md`` §1.4:

        Reads are not logged at all. Downloading every device's findings leaves
        no trace.

    The query string is deliberately excluded by the caller. It carries filter
    parameters of no forensic value and, on a URL somebody hand-assembled, could
    carry a credential — writing that here would put live tokens in the table
    this change added to make access reviewable.
    """
    conn.execute(
        "INSERT INTO access_log (at, actor, method, path, status, duration_ms, client) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            _utc_now(),
            actor,
            method,
            path,
            int(status),
            max(0, int(duration_ms)),
            client,
        ),
    )
    conn.commit()


def _utc_now() -> str:
    """Local import-free timestamp.

    ``backend.canonical.models.utc_now_iso`` is the project's one timestamp
    function, but importing it here would make the storage layer depend on the
    model layer — the same coupling ``FINDING_FIELDS`` above is written out by
    hand to avoid.
    """
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
