"""Mapping store — the C2 training module's durable half.

PRAMAN provides a GUI where an admin teaches the system a new vendor format
without redeploying the backend. These tests cover the part of that promise that
has to survive a restart, and the two safety properties that make a
teach-at-runtime feature something other than a foot-gun:

* **Validation happens at teach time, not at parse time.** A mapping naming a
  non-canonical path, or an operand the template does not have, must be refused
  while the operator is still looking at the screen. Accepted-then-broken is the
  worst outcome available: the mapping appears to work, produces nothing, and the
  queue entry it was meant to clear stays open forever.

* **Withdrawal is not deletion.** A verdict in a committed audit was reached with
  some mapping in force. Deleting the mapping makes "why did this device pass in
  March" unanswerable, so retirement is a status change and the row stays.

The migration tests are here rather than beside the schema because this is the
module whose columns the migration adds. ``CREATE TABLE IF NOT EXISTS`` is a no-op
on a database that already exists, so without the migration every developer who
had run an ingest before this feature landed would get ``no such column: vendor``
instead of a training queue.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from backend.ai.mapping_queue import pending_queue, queue_counts, queue_unparsed
from backend.ai.mapping_store import (
    ANY_VENDOR,
    STATUS_APPROVED,
    STATUS_RETIRED,
    LearnedPatternProvider,
    MappingError,
    export_pack_patterns,
    list_mappings,
    load_mappings,
    retire_mapping,
    upsert_mapping,
)
from backend.ai.templates import template_id
from backend.db.connection import get_connection, init_database

VENDOR = "cisco_ios"

#: Two canonical paths used throughout. Chosen because one takes a value and the
#: other is a bare presence flag, which are the two shapes a mapping can have.
PATH_VALUE = "logging.remote_syslog"
PATH_FLAG = "service.tcp_keepalives_in"


@pytest.fixture()
def conn(tmp_path: Path):
    """A private, initialised database per test.

    Per-test rather than per-session: these tests assert on absolute row counts
    and on the ``version`` counter, both of which leak across tests that share a
    store.
    """
    connection = get_connection(tmp_path / "store.db")
    init_database(connection)
    yield connection
    connection.close()


def _unparsed(*entries: tuple[int, str]) -> list[dict]:
    """Build ``ParseResult.unparsed_lines``-shaped entries."""
    return [
        {"line_number": number, "raw_text": text, "block": ""}
        for number, text in entries
    ]


# ── Schema migration ──────────────────────────────────────────────────


def test_init_database_is_idempotent(tmp_path: Path) -> None:
    """Running init twice must not fail and must not change the schema.

    Every request path calls ``init_database``, so "twice" is the normal case, not
    an edge one.
    """
    path = tmp_path / "twice.db"
    first = get_connection(path)
    init_database(first)
    before = _schema(first)
    init_database(first)
    init_database(first)
    assert _schema(first) == before
    first.close()


def test_migration_upgrades_a_database_written_before_the_feature(
    tmp_path: Path,
) -> None:
    """The case ``CREATE TABLE IF NOT EXISTS`` cannot handle.

    A developer who ran an ingest against an earlier build has a
    ``training_queue`` with no ``vendor`` column. The DDL will not touch it, so
    without an additive migration the training screen fails with ``no such
    column`` and the fix looks like "delete your database" — which throws away the
    ledger.

    The pre-existing row is asserted to survive, because a migration that
    preserves the schema but loses the data has solved nothing.
    """
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE training_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            raw_text TEXT NOT NULL,
            source_file TEXT NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            template_id TEXT,
            drain3_template TEXT,
            cluster_size INTEGER DEFAULT 1,
            mapped_path TEXT,
            admin_id TEXT,
            mapped_at TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE TABLE mapping_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            drain3_template TEXT NOT NULL UNIQUE,
            canonical_path TEXT NOT NULL,
            admin_id TEXT NOT NULL,
            note TEXT DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO mapping_store
            (drain3_template, canonical_path, admin_id, created_at, updated_at)
            VALUES ('old-command <*>', 'logging.remote_syslog', 'legacy@praman',
                    '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
        """
    )
    legacy.commit()
    legacy.close()

    upgraded = get_connection(path)
    init_database(upgraded)

    queue_columns = {r["name"] for r in upgraded.execute("PRAGMA table_info(training_queue)")}
    store_columns = {r["name"] for r in upgraded.execute("PRAGMA table_info(mapping_store)")}
    assert {"vendor", "first_seen_at", "block"} <= queue_columns
    assert {"vendor", "value_index", "status"} <= store_columns

    # The row written by the old build is still there, and readable through the
    # new projection — which is what `_mapping_row`'s key-presence checks are for.
    survivors = list_mappings(upgraded)
    assert [m["template"] for m in survivors] == ["old-command <*>"]
    assert survivors[0]["vendor"] == ANY_VENDOR, "back-filled default"
    assert survivors[0]["status"] == STATUS_APPROVED
    upgraded.close()


def _schema(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    """(table, column) pairs, as a comparable snapshot."""
    tables = [
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    ]
    return {
        (table, row["name"])
        for table in tables
        for row in connection.execute(f'PRAGMA table_info("{table}")')
    }


# ── Queue ─────────────────────────────────────────────────────────────


def test_queue_writes_one_row_per_template_not_per_line(conn) -> None:
    """The property that makes the queue a work list rather than a log.

    Three ``logging host`` lines are one decision. A queue that listed all three
    would list 1,200 rows for a 400-device estate and be abandoned.
    """
    clusters = queue_unparsed(
        conn,
        device_id="dev-1",
        vendor=VENDOR,
        source_file="r1.conf",
        unparsed_lines=_unparsed(
            (10, "logging host 10.0.0.1"),
            (11, "logging host 10.0.0.2"),
            (12, "custom-widget enable"),
            (13, "logging host 192.168.4.9"),
        ),
    )
    assert len(clusters) == 2

    queue = pending_queue(conn)
    assert [entry["template"] for entry in queue] == [
        "logging host <*>",
        "custom-widget enable",
    ], "busiest template first"
    assert queue[0]["occurrences"] == 3
    assert queue[0]["devices"] == 1
    assert queue[0]["operands"] == 1
    assert queue[0]["example"] == "logging host 10.0.0.1"
    assert queue[0]["source_file"] == "r1.conf"
    assert queue[0]["line_start"] == 10


def test_queue_aggregates_the_same_template_across_devices(conn) -> None:
    """One template unparsed on 40 devices is one queue entry, not 40.

    Aggregation is what lets the operator see impact: ``devices: 40`` is the
    argument for spending a minute on this template rather than another.
    """
    for index in range(3):
        queue_unparsed(
            conn,
            device_id=f"dev-{index}",
            vendor=VENDOR,
            source_file=f"r{index}.conf",
            unparsed_lines=_unparsed((5, f"logging host 10.0.0.{index}")),
        )

    queue = pending_queue(conn)
    assert len(queue) == 1
    assert queue[0]["devices"] == 3
    assert queue[0]["occurrences"] == 3


def test_re_ingesting_a_device_replaces_its_pending_rows(conn) -> None:
    """A corrected upload must not leave the queue describing the old file.

    Without the clear, an operator who fixes a config and re-uploads it sees the
    lines they just removed still sitting in the queue, and teaching them produces
    mappings for commands no device runs.
    """
    queue_unparsed(
        conn,
        device_id="dev-1",
        vendor=VENDOR,
        source_file="r1.conf",
        unparsed_lines=_unparsed((10, "old-command 1"), (11, "logging host 10.0.0.1")),
    )
    queue_unparsed(
        conn,
        device_id="dev-1",
        vendor=VENDOR,
        source_file="r1.conf",
        unparsed_lines=_unparsed((10, "logging host 10.0.0.1")),
    )

    assert [entry["template"] for entry in pending_queue(conn)] == [
        "logging host <*>"
    ]


def test_a_template_already_taught_is_queued_as_mapped(conn) -> None:
    """Teaching first and ingesting second must not reopen the decision.

    The row is still written — the line genuinely was unparsed by the pack, and
    hiding that would make the coverage figure a fiction — but it is written
    ``mapped``, so it is history rather than work.
    """
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="admin@praman",
        vendor=VENDOR,
    )
    queue_unparsed(
        conn,
        device_id="dev-1",
        vendor=VENDOR,
        source_file="r1.conf",
        unparsed_lines=_unparsed((10, "logging host 10.0.0.1")),
    )

    assert pending_queue(conn) == []
    assert queue_counts(conn)["mapped"] == 1


def test_teaching_clears_the_matching_queue_rows(conn) -> None:
    """The queue entry a mapping answers must close, on every device.

    Both directions of the join are exercised by this test and the one above: map
    then ingest, and ingest then map.
    """
    for index in range(2):
        queue_unparsed(
            conn,
            device_id=f"dev-{index}",
            vendor=VENDOR,
            source_file=f"r{index}.conf",
            unparsed_lines=_unparsed((7, f"logging host 10.0.0.{index}")),
        )
    assert queue_counts(conn)["pending"] == 1

    upsert_mapping(
        conn,
        template="logging host 10.0.0.1",
        canonical_path=PATH_VALUE,
        admin_id="admin@praman",
        vendor=VENDOR,
    )

    assert pending_queue(conn) == []
    rows = conn.execute(
        "SELECT status, mapped_path, admin_id FROM training_queue"
    ).fetchall()
    assert {row["status"] for row in rows} == {"mapped"}
    assert {row["mapped_path"] for row in rows} == {PATH_VALUE}
    assert {row["admin_id"] for row in rows} == {"admin@praman"}


# ── Teaching: validation ──────────────────────────────────────────────


def test_a_raw_line_and_its_template_are_interchangeable_input(conn) -> None:
    """The operator may paste the line they are looking at.

    Composing ``<*>`` tokens by hand is an invitation to typo the very thing the
    mapping is keyed on. Masking the input means the GUI can accept either form,
    and a template pasted back in is unchanged by masking — which is why the two
    produce one row rather than two.
    """
    first = upsert_mapping(
        conn,
        template="logging host 10.0.0.1",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
    )
    second = upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
    )

    assert first["template"] == second["template"] == "logging host <*>"
    assert second["version"] == 2, "an update, not a second row"
    assert len(list_mappings(conn)) == 1


def test_a_non_canonical_path_is_refused(conn) -> None:
    """The canonical model is the only contract, enforced where it is cheap.

    A mapping emitting an unpublished path would be rejected far downstream by the
    rules engine, with no trail back to the operator who typed it. Refusing here
    puts the error in front of the person who can fix it.
    """
    with pytest.raises(MappingError, match="not a canonical path"):
        upsert_mapping(
            conn,
            template="logging host <*>",
            canonical_path="logging.hosts",  # plausible, and not in the schema
            admin_id="a@praman",
        )
    assert list_mappings(conn) == [], "nothing was written"


def test_an_operand_the_template_lacks_is_refused(conn) -> None:
    """Compile before insert, so an uncompilable row cannot exist.

    If this were checked lazily, ``load_mappings`` would have to cope with rows it
    cannot turn into patterns on every parse, forever.
    """
    with pytest.raises(MappingError, match="value_index"):
        upsert_mapping(
            conn,
            template="logging host <*>",
            canonical_path=PATH_VALUE,
            admin_id="a@praman",
            value_index=4,
        )
    assert list_mappings(conn) == []


def test_an_empty_template_is_refused(conn) -> None:
    """Whitespace is not a command."""
    with pytest.raises(MappingError, match="empty"):
        upsert_mapping(
            conn, template="   ", canonical_path=PATH_VALUE, admin_id="a@praman"
        )


# ── Compilation and hot reload ────────────────────────────────────────


def test_load_mappings_compiles_an_approved_mapping(conn) -> None:
    """A stored mapping becomes a pattern that matches real config text."""
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    result = load_mappings(conn, VENDOR)

    assert result.skipped == []
    assert len(result.patterns) == 1
    pattern = result.patterns[0]
    assert pattern.id == template_id("logging host <*>")
    assert pattern.emits[0].path == PATH_VALUE

    match = pattern.regex.match("logging  host 192.168.4.9")
    assert match, "whitespace runs in the config must not defeat the mapping"
    assert match.group("value") == "192.168.4.9"
    assert not pattern.regex.match("logging host 10.0.0.1 transport tcp")


def test_a_vendor_scoped_mapping_does_not_leak_to_other_vendors(conn) -> None:
    """``set system services ssh`` means nothing to a Cisco pack.

    Scoping is per mapping because the two cases are both real: a command spelled
    identically on every platform (``*``), and one that is a specific dialect's.
    """
    upsert_mapping(
        conn,
        template="cisco-only-command <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    upsert_mapping(
        conn,
        template="universal-command <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=ANY_VENDOR,
    )

    for_cisco = {p.id for p in load_mappings(conn, VENDOR).patterns}
    for_junos = {p.id for p in load_mappings(conn, "juniper_junos").patterns}

    assert template_id("cisco-only-command <*>") in for_cisco
    assert template_id("universal-command <*>") in for_cisco
    assert for_junos == {template_id("universal-command <*>")}


def test_retiring_a_mapping_withdraws_it_without_erasing_it(conn) -> None:
    """The append-only argument, applied to mappings.

    A retired mapping stops producing facts immediately and stays findable, so a
    past audit's verdict can still be explained.
    """
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    assert retire_mapping(conn, "logging host <*>") is True

    assert load_mappings(conn, VENDOR).patterns == []
    assert list_mappings(conn) == []
    retired = list_mappings(conn, include_retired=True)
    assert [m["status"] for m in retired] == [STATUS_RETIRED]
    assert retired[0]["admin_id"] == "a@praman", "who taught it is still recorded"


def test_retiring_an_unknown_mapping_reports_no_change(conn) -> None:
    """Idempotent, and honest about having done nothing."""
    assert retire_mapping(conn, "never-taught <*>") is False


def test_a_mapping_whose_path_left_the_schema_is_skipped_not_silent(conn) -> None:
    """Coverage may be lost, but never quietly.

    The path is written directly to bypass the teach-time validation, which is the
    only way this state arises: the mapping was valid when taught and the schema
    changed under it. What must not happen is the parse silently losing a pattern.
    """
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    conn.execute(
        "UPDATE mapping_store SET canonical_path = 'logging.was_removed'"
    )
    conn.commit()

    result = load_mappings(conn, VENDOR)
    assert result.patterns == []
    assert len(result.skipped) == 1
    assert result.skipped[0]["canonical_path"] == "logging.was_removed"
    assert "no longer a canonical path" in result.skipped[0]["reason"]


def test_provider_sees_a_new_mapping_without_being_invalidated(conn, tmp_path) -> None:
    """The hot half of C2: taught in one request, in force on the next.

    The provider caches compiled patterns, so the question is whether its
    fingerprint notices a write. If it does not, the operator's mapping appears
    to be accepted and does nothing until the process restarts — which is exactly
    a redeploy that would break the runtime-training contract.

    All three writes happen inside one second, which is deliberate: the store's
    timestamps have second resolution, so a fingerprint leaning on
    ``MAX(updated_at)`` to notice an in-place ``UPDATE`` sees nothing here. That
    is not a contrived race — retiring a mapping immediately after teaching it is
    what an operator does when they realise they typed the wrong path — and the
    symptom is a mapping the UI reports as retired that is still producing facts.
    """
    provider = LearnedPatternProvider(lambda: get_connection(tmp_path / "store.db"))
    assert provider(VENDOR) == [], "cold start: nothing taught"

    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    after_insert = provider(VENDOR)
    assert len(after_insert) == 1, "cache did not notice the insert"

    # An edit in place: same template, corrected path. Row count, highest id and
    # second-resolution timestamp are all unchanged; `version` is not.
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_FLAG,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    after_edit = provider(VENDOR)
    assert len(after_edit) == 1
    assert after_edit[0].emits[0].path == PATH_FLAG, "cache served the stale path"

    retire_mapping(conn, "logging host <*>")
    assert provider(VENDOR) == [], "cache did not notice the retirement"


def test_provider_survives_a_missing_database(tmp_path) -> None:
    """No database is a cold start, not an error.

    The provider is called from the parser registry on every detect. Raising there
    would turn "you have not ingested anything yet" into a failed upload.
    """
    provider = LearnedPatternProvider(
        lambda: get_connection(tmp_path / "nonexistent" / "store.db")
    )
    assert provider(VENDOR) == []
    assert provider.load(VENDOR).skipped == []


def test_a_flag_mapping_needs_no_operand(conn) -> None:
    """A command with no operand asserts presence.

    ``service tcp-keepalives-in`` has nothing to capture; the fact is that the line
    is there. Getting this wrong would make every bare-command mapping impossible
    to teach.
    """
    upsert_mapping(
        conn,
        template="service tcp-keepalives-in",
        canonical_path=PATH_FLAG,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    pattern = load_mappings(conn, VENDOR).patterns[0]
    assert pattern.regex.match("service tcp-keepalives-in")
    assert not pattern.regex.match("no service tcp-keepalives-in")


# ── Promotion out of the store ────────────────────────────────────────


def test_exported_yaml_loads_as_a_pattern_pack(conn, tmp_path: Path) -> None:
    """The promotion path has to produce a pack the loader accepts.

    Asserted by actually loading the export rather than by eyeballing the string.
    An export that looks right and fails to load would leave the field's real
    parsing knowledge stranded in a SQLite table nobody reviews or ships — and the
    failure would surface as "the pack matches nothing", not as a parse error.
    """
    from backend.ingest.patterns import load_pattern_pack

    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="ronit",
        note='observed on 12 devices; operator said "ship it"',
        vendor=VENDOR,
    )
    upsert_mapping(
        conn,
        template="service tcp-keepalives-in",
        canonical_path=PATH_FLAG,
        admin_id="ronit",
        vendor=VENDOR,
    )

    exported = export_pack_patterns(list_mappings(conn))

    # Wrapped in the minimum a pack needs, since the export is the patterns list
    # only by design: a pack's detector stays hand-authored.
    pack_file = tmp_path / f"{VENDOR}.yaml"
    pack_file.write_text(
        "vendor: cisco_ios\n"
        "os_family: ios\n"
        "parser_id: exported@1\n"
        "detect:\n"
        "  min_hits: 1\n"
        "  markers: ['hostname ']\n" + exported,
        encoding="utf-8",
    )
    pack = load_pattern_pack(pack_file)

    assert pack.pattern_count() == 2
    assert {
        emission.path for pattern in pack.patterns for emission in pattern.emits
    } == {PATH_VALUE, PATH_FLAG}

    # The regex survived YAML quoting. A backslash lost in transit would produce a
    # pack that loads cleanly and matches nothing.
    logging_pattern = next(
        p for p in pack.patterns if p.emits[0].path == PATH_VALUE
    )
    assert logging_pattern.regex.match("logging host 10.0.0.1")


def test_export_declares_a_type_rather_than_inheriting_auto(conn) -> None:
    """``auto`` must not escape into a reviewed artefact.

    ``auto`` exists because the training GUI has no field for a type. A pack has an
    author who can say, and ``tests/test_pattern_packs.py`` refuses ``auto`` in
    shipped packs — so the export has to declare something concrete or promotion
    would produce a pack that fails its own test suite.
    """
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="ronit",
    )
    exported = export_pack_patterns(list_mappings(conn))
    assert "auto" not in exported
    assert "value: str" in exported
