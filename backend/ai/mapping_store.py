"""The training module's persistence layer — capability C2.

PRAMAN provides a GUI-based training module where an admin can teach the
system a new vendor format without redeploying the backend. This module is the
half of that which survives a restart. The flow it implements:

1. An ingest leaves lines no pattern claimed.
   :func:`~backend.ai.mapping_queue.queue_unparsed` clusters them by template
   and writes one row per template into ``training_queue``.
2. The operator opens the queue, picks a template and names the canonical path
   the value belongs to. :func:`upsert_mapping` validates and stores it.
3. :func:`load_mappings` compiles stored mappings back into
   :class:`~backend.ingest.patterns.LinePattern` objects, and
   :class:`LearnedPatternProvider` hands them to the parser registry.

Step 3 is what makes it hot: ``PatternAdapterRegistry`` asks the provider for
learned patterns every time it builds an adapter, so the mapping taught in step 2
is live on the very next parse — same process, no redeploy, no reload endpoint to
remember to call.

Two safety properties are worth stating because they are the difference between a
training module and a foot-gun:

* **A taught mapping cannot override a shipped one.** ``PatternAdapter`` tries
  its pack's patterns first and the learned ones only on lines nothing claimed,
  so no mapping typed in a browser can change the meaning of a line a vetted
  pack already understands.
* **A taught fact is labelled.** Facts from learned patterns carry a
  ``<pack>+taught`` ``parser_id``, so a verdict resting on operator-supplied
  parsing is distinguishable on the report from one resting on a shipped pack.

The store is deliberately *not* authoritative for shipped behaviour. It is an
operator's working surface; the durable form of a mapping is a pattern pack under
``data/ingest/patterns/``. :func:`export_pack_patterns` renders approved mappings
as pack YAML so a template that proved itself in the field can be promoted into
a reviewed pack and dropped from the store.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.ai.templates import (
    build_learned_pattern,
    mine_template,
    template_id,
    wildcard_count,
)
from backend.canonical.paths import canonical_paths_sorted, is_canonical_path
from backend.ingest.patterns import LinePattern

#: A mapping with this vendor applies to every pack. Used when the caller did not
#: say which platform the template came from — the pre-existing ``/training/map``
#: contract has no vendor field, and refusing those requests would break it.
ANY_VENDOR = "*"

#: Mapping lifecycle. Only ``approved`` mappings are compiled into patterns, so
#: a store that later grows a review workflow can queue proposals as ``pending``
#: without them silently affecting verdicts in the meantime.
STATUS_APPROVED = "approved"
STATUS_RETIRED = "retired"


def utc_stamp() -> str:
    """UTC timestamp, second resolution, for the store's audit columns."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Mappings
# --------------------------------------------------------------------------- #


class MappingError(ValueError):
    """A proposed mapping was rejected. The message is shown to the operator."""


def upsert_mapping(
    conn: sqlite3.Connection,
    *,
    template: str,
    canonical_path: str,
    admin_id: str,
    note: str = "",
    vendor: str = ANY_VENDOR,
    value_index: int = 0,
) -> dict[str, Any]:
    """Store one taught mapping, replacing any earlier one for the template.

    Args:
        template: A template, or a raw example line. Raw lines are masked with
            :func:`~backend.ai.templates.mine_template` first, so an operator can
            paste the line they are looking at instead of composing ``<*>``
            tokens by hand — and a template pasted back in is unchanged by the
            masking, which makes the two inputs interchangeable.
        canonical_path: Where the value belongs. Must be a path the canonical
            schema publishes.
        admin_id: Who taught it. This function trusts its caller; the HTTP path
            (``POST /training/map``) passes the authenticated operator and ignores
            the ``admin_id`` the client sent, so over the API the name is not
            self-declared. A direct caller — a test, a migration — can still put
            anything here, which is correct: the authority lives at the boundary
            that has a request to authenticate.
        note: The operator's justification, carried onto the report.
        vendor: Which pack this applies to, or ``*`` for all.
        value_index: Which masked operand carries the value.

    Returns:
        The stored row as a dict, including the ``version`` it now has.

    Raises:
        MappingError: The path is not canonical, the template is empty, or the
            operand index does not exist. All three are operator errors that
            must fail loudly at teach time: a mapping accepted here becomes a
            parser, and a parser that emits a non-canonical path would be
            rejected by the rules engine much later, with no trail back to the
            person who typed it.

    The uniqueness key is the template alone, not (vendor, template). Two packs
    that spell a command identically mean the same thing by it, and a store that
    let ``ip ssh version <*>`` mean one path on IOS and another on NX-OS would be
    a source of contradictions nobody could debug.
    """
    normalised = mine_template(template)
    if not normalised:
        raise MappingError("the template is empty")
    if not is_canonical_path(canonical_path):
        raise MappingError(
            f"'{canonical_path}' is not a canonical path. "
            f"The schema publishes {len(canonical_paths_sorted())} paths; "
            "pick one of those or add the new path to "
            "schema/canonical_paths.schema.json first."
        )
    try:
        # Compiling now, before the row exists, is what keeps load_mappings from
        # having to cope with a row it cannot turn into a pattern.
        build_learned_pattern(normalised, canonical_path, value_index)
    except ValueError as exc:
        raise MappingError(str(exc)) from exc

    now = utc_stamp()
    conn.execute(
        """
        INSERT INTO mapping_store
        (drain3_template, canonical_path, admin_id, note, vendor, value_index,
         status, version, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(drain3_template) DO UPDATE SET
            canonical_path = excluded.canonical_path,
            admin_id       = excluded.admin_id,
            note           = excluded.note,
            vendor         = excluded.vendor,
            value_index    = excluded.value_index,
            status         = excluded.status,
            version        = mapping_store.version + 1,
            updated_at     = excluded.updated_at
        """,
        (
            normalised,
            canonical_path,
            admin_id,
            note,
            vendor or ANY_VENDOR,
            int(value_index),
            STATUS_APPROVED,
            now,
            now,
        ),
    )
    tid = template_id(normalised)
    conn.execute(
        """
        UPDATE training_queue
        SET status = 'mapped', mapped_path = ?, admin_id = ?, mapped_at = ?
        WHERE template_id = ? AND status = 'pending'
        """,
        (canonical_path, admin_id, now, tid),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM mapping_store WHERE drain3_template = ?", (normalised,)
    ).fetchone()
    return _mapping_row(row)


def retire_mapping(conn: sqlite3.Connection, template: str) -> bool:
    """Withdraw a mapping without deleting the record of it having existed.

    Returns True when a mapping changed state. Retiring rather than deleting
    matters for the same reason the ledger is append-only: a verdict on a past
    audit was reached with this mapping in force, and an operator asking "why did
    this device pass in March" needs the mapping to still be findable.
    """
    normalised = mine_template(template)
    cursor = conn.execute(
        "UPDATE mapping_store SET status = ?, updated_at = ?"
        " WHERE drain3_template = ? AND status != ?",
        (STATUS_RETIRED, utc_stamp(), normalised, STATUS_RETIRED),
    )
    conn.commit()
    return cursor.rowcount > 0


def list_mappings(
    conn: sqlite3.Connection,
    *,
    vendor: str | None = None,
    include_retired: bool = False,
) -> list[dict[str, Any]]:
    """All stored mappings, newest first, for the training screen's table."""
    clauses: list[str] = []
    params: list[Any] = []
    if not include_retired:
        clauses.append("status = ?")
        params.append(STATUS_APPROVED)
    if vendor:
        clauses.append("vendor IN (?, ?)")
        params.extend([vendor, ANY_VENDOR])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM mapping_store {where} ORDER BY updated_at DESC, id DESC",
        params,
    ).fetchall()
    return [_mapping_row(row) for row in rows]


def _mapping_row(row: sqlite3.Row | None) -> dict[str, Any]:
    """Project a stored row into the shape the API and UI use."""
    if row is None:
        return {}
    keys = row.keys()
    template = row["drain3_template"]
    return {
        "template": template,
        "template_id": template_id(template),
        "canonical_path": row["canonical_path"],
        "admin_id": row["admin_id"],
        "note": row["note"] or "",
        "vendor": row["vendor"] if "vendor" in keys else ANY_VENDOR,
        "value_index": int(row["value_index"]) if "value_index" in keys else 0,
        "status": row["status"] if "status" in keys else STATUS_APPROVED,
        "version": int(row["version"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "operands": wildcard_count(template),
    }


# --------------------------------------------------------------------------- #
# Compilation into patterns
# --------------------------------------------------------------------------- #

#: The cache key :class:`LearnedPatternProvider` reads off the table:
#: ``(rows, summed versions, approved rows, highest id, newest updated_at)``.
#: Named because the ordering is load-bearing — see the class docstring for what
#: each term catches and why a shorter tuple missed a retirement.
_Fingerprint = tuple[int, int, int, int, str]


@dataclass
class LoadResult:
    """Compiled patterns plus the rows that could not be compiled.

    Skipped rows are returned rather than logged and forgotten. A mapping that
    stopped compiling — because the canonical path it names was removed from the
    schema, say — is a silent loss of parsing coverage, which is exactly the
    failure mode this project treats as unacceptable. The API surfaces the list
    so the training screen can show "3 mappings are not in force, and why".
    """

    patterns: list[LinePattern] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)


def load_mappings(conn: sqlite3.Connection, vendor: str) -> LoadResult:
    """Compile every approved mapping that applies to ``vendor``.

    Ordered by ``updated_at`` so the newest mapping is tried last; with distinct
    templates the order is immaterial, and pinning it keeps parses reproducible.
    """
    rows = conn.execute(
        """
        SELECT drain3_template, canonical_path, value_index
        FROM mapping_store
        WHERE status = ? AND vendor IN (?, ?)
        ORDER BY updated_at ASC, id ASC
        """,
        (STATUS_APPROVED, vendor, ANY_VENDOR),
    ).fetchall()

    result = LoadResult()
    for row in rows:
        template = row["drain3_template"]
        path = row["canonical_path"]
        try:
            if not is_canonical_path(path):
                raise ValueError(
                    f"'{path}' is no longer a canonical path; the mapping is "
                    "not in force. Re-map the template or restore the path."
                )
            result.patterns.append(
                build_learned_pattern(
                    template, path, int(row["value_index"] or 0)
                )
            )
        except (ValueError, KeyError) as exc:
            result.skipped.append(
                {
                    "template": template,
                    "canonical_path": path,
                    "reason": str(exc),
                }
            )
    return result


class LearnedPatternProvider:
    """Caching ``vendor -> list[LinePattern]`` callable for the parser registry.

    ``PatternAdapterRegistry`` asks for learned patterns on every ``detect()``
    and every ``for_vendor()``, which is once or more per request. Recompiling a
    few hundred regexes each time would be wasteful, and holding them forever
    would defeat the point of a training module, so the cache is keyed on a
    cheap fingerprint of the table. Every write this module performs must move
    the fingerprint, or the operator's change is accepted by the store and
    ignored by the parser until something unrelated happens to invalidate the
    cache — a failure with no error message at either end.

    Getting that right takes more than a row count and a timestamp, which is
    what the first version used. Retirement is an ``UPDATE``, so it moves
    neither the count nor the highest id, and :func:`_now` has second
    resolution, so a retirement in the same second as the insert it withdraws
    moves nothing at all: a mapping the operator has just disabled keeps
    producing facts. The two clock-free terms below close that:

    * ``SUM(version)`` — ``upsert_mapping`` increments ``version`` on conflict,
      so any edit to an existing mapping moves it even when nothing else about
      the table's shape changes.
    * the approved-row count — moves on retirement, and back again when an
      upsert restores a retired template to approved.

    ``MAX(updated_at)`` is kept as a fifth term. It adds nothing the others do
    not already cover for writes made through this module, and is there for
    writes made around it: a migration, a restore, an operator with a SQLite
    shell.

    The fingerprint is read under a lock and the compiled result cached per
    vendor. Instances are safe to share across threads, which uvicorn's default
    worker and FastAPI's ``TestClient`` both need.
    """

    def __init__(
        self,
        conn_factory: Callable[[], sqlite3.Connection] | None = None,
    ) -> None:
        self._conn_factory = conn_factory
        self._lock = threading.Lock()
        self._fingerprint: _Fingerprint | None = None
        self._cache: dict[str, LoadResult] = {}

    def _connect(self) -> sqlite3.Connection:
        if self._conn_factory is not None:
            return self._conn_factory()
        from backend.db.connection import get_connection, init_database

        conn = get_connection()
        init_database(conn)
        return conn

    def __call__(self, vendor: str) -> list[LinePattern]:
        """Return taught patterns for one vendor. Never raises."""
        return self.load(vendor).patterns

    def load(self, vendor: str) -> LoadResult:
        """Return patterns and skipped rows, refreshing the cache if stale."""
        return self.load_many([vendor])[vendor]

    def load_many(self, vendors: Sequence[str]) -> dict[str, LoadResult]:
        """Load several vendors through **one** connection and one freshness check.

        Detection scores an upload against every installed pattern pack, so it
        asks this store once per vendor. Answering each question independently
        meant reconnecting and re-running the schema DDL to answer seven
        questions about the same instant — 53% of the time to parse a config.
        See ``docs/GAPS.md`` §6 for the measurement.

        Batching changes no semantics: the fingerprint is still read on every
        sweep, so a mapping taught a moment ago is still in force on the next
        parse. It is read once per sweep instead of once per vendor, which is the
        only number that was ever wrong.
        """
        try:
            conn = self._connect()
        except sqlite3.Error:
            # No database yet is a normal cold start, not an error: there are
            # no taught mappings, so there are no learned patterns.
            return {vendor: LoadResult() for vendor in vendors}
        try:
            fingerprint = self._read_fingerprint(conn)
            with self._lock:
                if fingerprint != self._fingerprint:
                    self._fingerprint = fingerprint
                    self._cache.clear()
                out = {v: self._cache[v] for v in vendors if v in self._cache}
            for vendor in vendors:
                if vendor in out:
                    continue
                loaded = load_mappings(conn, vendor)
                out[vendor] = loaded
                with self._lock:
                    if fingerprint == self._fingerprint:
                        self._cache[vendor] = loaded
            return out
        except sqlite3.Error:
            return {vendor: LoadResult() for vendor in vendors}
        finally:
            conn.close()

    @staticmethod
    def _read_fingerprint(conn: sqlite3.Connection) -> _Fingerprint:
        row = conn.execute(
            "SELECT COUNT(*) AS n,"
            " COALESCE(SUM(version), 0) AS versions,"
            " COUNT(CASE WHEN status = ? THEN 1 END) AS approved,"
            " COALESCE(MAX(id), 0) AS max_id,"
            " COALESCE(MAX(updated_at), '') AS ts"
            " FROM mapping_store",
            (STATUS_APPROVED,),
        ).fetchone()
        return (
            int(row["n"]),
            int(row["versions"]),
            int(row["approved"]),
            int(row["max_id"]),
            str(row["ts"]),
        )

    def invalidate(self) -> None:
        """Drop the cache. Not needed for correctness; used by tests."""
        with self._lock:
            self._fingerprint = None
            self._cache.clear()


# --------------------------------------------------------------------------- #
# Promotion out of the store
# --------------------------------------------------------------------------- #


def export_pack_patterns(mappings: Iterable[dict[str, Any]]) -> str:
    """Render taught mappings as pattern-pack YAML, ready to paste into a pack.

    The store is a working surface; a pack is the reviewed artefact. Without a
    path out of the store, an estate's real parsing knowledge accumulates in a
    SQLite table that no one reviews and no one ships — so promotion is a
    first-class operation, even though it is only string formatting.

    Emits the ``patterns:`` list only; the caller pastes it under an existing
    pack's key so the pack's own detector and metadata stay hand-authored.
    """
    from backend.ai.templates import template_to_regex

    lines: list[str] = ["patterns:"]
    for mapping in mappings:
        template = mapping["template"]
        index = int(mapping.get("value_index", 0) or 0)
        regex = template_to_regex(template, index)
        note = str(mapping.get("note") or "").replace('"', "'")
        lines.extend(
            [
                f"  - id: {mapping['template_id']}",
                f"    regex: {_yaml_single_quoted(regex)}",
                f"    path: {mapping['canonical_path']}",
                # An exported pattern must declare its type: 'auto' exists only
                # because the training GUI has no field for it, and a reviewed
                # pack has an author who can say. 'str' is the safe default to
                # hand-correct, since a wrong widening is visible in review.
                f"    value: {'str' if wildcard_count(template) else 'true'}",
                f'    note: "taught by {mapping.get("admin_id", "operator")}'
                f'{": " + note if note else ""}"',
            ]
        )
    return "\n".join(lines) + "\n"


def _yaml_single_quoted(text: str) -> str:
    """Quote a regex for YAML without backslash mangling.

    Single-quoted YAML scalars have exactly one escape - a doubled quote - so a
    regex full of ``\\S`` and ``\\s`` survives verbatim. Double quotes would
    require escaping every backslash, and an exported pattern that silently lost
    one would be a pack that loads and matches nothing.
    """
    return "'" + text.replace("'", "''") + "'"
