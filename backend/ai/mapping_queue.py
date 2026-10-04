"""The training queue — what an ingest could not parse, as a work list.

Split out of :mod:`backend.ai.mapping_store`, which had grown to hold two
different things: the queue of templates *awaiting* a human decision, and the
store of decisions already made. They share a database and nothing else. The
queue is written by ingest and read by the operator's screen; the store is read
on every parse. Keeping them apart makes that difference visible, and keeps the
hot module small.

The dependency runs one way — this module imports the store's vocabulary
(:data:`~backend.ai.mapping_store.ANY_VENDOR`, the status constants) because a
queue row's ``mapped``/``pending`` status is a statement about what the store
already contains. The store never imports this module.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from typing import Any

from backend.ai.mapping_store import ANY_VENDOR, STATUS_APPROVED, utc_stamp
from backend.ai.templates import (
    TemplateCluster,
    cluster_lines,
    template_id,
    wildcard_count,
)


def queue_unparsed(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    vendor: str,
    source_file: str,
    unparsed_lines: Sequence[dict[str, Any]],
) -> list[TemplateCluster]:
    """Record a device's unparsed lines as training work.

    Args:
        conn: An open connection to an initialised database.
        device_id: The device the lines came from.
        vendor: The pack that parsed the rest of the file. A template is only
            meaningful for the dialect that produced it, so the queue keeps it.
        source_file: Filename as uploaded, for the operator's provenance.
        unparsed_lines: ``ParseResult.unparsed_lines``.

    Returns:
        The clusters written, in file order, so a caller can show the operator
        what this upload added without a second query.

    One row per *template* per device, not one per line: the whole point of
    clustering is that ``logging host <*>`` seen 400 times is one decision. The
    device's own pending rows are cleared first, so re-ingesting a corrected
    config does not leave the queue describing a file that no longer exists.
    Rows already mapped are left alone — they are the audit trail of what was
    taught and why.
    """
    clusters = cluster_lines(list(unparsed_lines))
    conn.execute(
        "DELETE FROM training_queue WHERE device_id = ? AND status = 'pending'",
        (device_id,),
    )
    if not clusters:
        conn.commit()
        return []

    known = _approved_template_ids(conn, vendor)
    now = utc_stamp()
    for cluster in clusters:
        example = cluster.example
        line_no = int(example.get("line_number") or 0)
        conn.execute(
            """
            INSERT INTO training_queue
            (device_id, vendor, raw_text, source_file, line_start, line_end,
             template_id, drain3_template, cluster_size, block, status,
             first_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                vendor,
                str(example.get("raw_text", "")).strip(),
                source_file,
                line_no,
                line_no,
                cluster.template_id,
                cluster.template,
                cluster.cluster_size,
                str(example.get("block") or ""),
                # A template that is already taught is not work. It can still
                # appear here when the mapping was added after this device was
                # ingested; recording it as mapped keeps the queue honest
                # without pretending the line was never unparsed.
                "mapped" if cluster.template_id in known else "pending",
                now,
            ),
        )
    conn.commit()
    return clusters


def _approved_template_ids(conn: sqlite3.Connection, vendor: str) -> set[str]:
    """Template ids that already have an approved mapping for this vendor."""
    rows = conn.execute(
        """
        SELECT drain3_template FROM mapping_store
        WHERE status = ? AND vendor IN (?, ?)
        """,
        (STATUS_APPROVED, vendor, ANY_VENDOR),
    ).fetchall()
    return {template_id(row["drain3_template"]) for row in rows}


def pending_queue(
    conn: sqlite3.Connection,
    *,
    vendor: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return the training queue, one entry per template, busiest first.

    Aggregated across devices: a template unparsed on 40 devices is one entry
    with ``devices: 40``, because it is one decision for the operator. Ordered by
    total occurrences so the mapping that unblocks the most facts is on top —
    the queue is a work list, and the cheapest useful ordering is by impact.
    """
    clauses = ["status = 'pending'"]
    params: list[Any] = []
    if vendor:
        clauses.append("vendor = ?")
        params.append(vendor)
    params.append(int(limit))
    rows = conn.execute(
        f"""
        SELECT
            template_id,
            drain3_template,
            MIN(vendor)               AS vendor,
            SUM(cluster_size)         AS occurrences,
            COUNT(DISTINCT device_id) AS devices,
            MIN(raw_text)             AS example,
            MIN(source_file)          AS source_file,
            MIN(line_start)           AS line_start,
            MIN(block)                AS block,
            MIN(id)                   AS first_id
        FROM training_queue
        WHERE {' AND '.join(clauses)}
        GROUP BY template_id
        ORDER BY occurrences DESC, first_id ASC
        LIMIT ?
        """,
        params,
    ).fetchall()
    return [
        {
            "template_id": row["template_id"],
            "template": row["drain3_template"],
            "vendor": row["vendor"] or "",
            "occurrences": int(row["occurrences"] or 0),
            "devices": int(row["devices"] or 0),
            "example": row["example"],
            "source_file": row["source_file"],
            "line_start": int(row["line_start"] or 0),
            "block": row["block"] or "",
            "operands": wildcard_count(row["drain3_template"] or ""),
        }
        for row in rows
    ]


def queue_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Queue sizes by status, for the dashboard's badge."""
    rows = conn.execute(
        "SELECT status, COUNT(DISTINCT template_id) AS n FROM training_queue"
        " GROUP BY status"
    ).fetchall()
    counts = {row["status"]: int(row["n"]) for row in rows}
    counts.setdefault("pending", 0)
    counts.setdefault("mapped", 0)
    return counts
