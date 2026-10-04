"""One database sweep per parse, not one per installed pattern pack.

A profile of ``parse_config`` found that every parse opened seven SQLite
connections — one per pack — and re-ran the schema DDL on each, to answer seven
questions about the same instant: detection scores an upload against every pack,
and each pack's learned-mapping lookup reconnected to re-read the same freshness
fingerprint. That was 53% of parse time and **156 ms to 22.5 ms per config** once
fixed. ``docs/GAPS.md`` §6 records the measurement and the negative result it
also settled, that a ``ProcessPoolExecutor`` over archive members was contending
on that same SQLite file.

These tests exist because the regression would otherwise be invisible. Every
individual call was correct and cheap-looking; only the *number* of them was
wrong, so no functional assertion anywhere in the suite would have moved. Both
halves are pinned: that the store can answer a whole sweep at once, and that the
registry actually asks it that way.

The freshness property is pinned alongside the speed one on purpose — a batch
that bought its speed by caching across sweeps would break C2's promise that a
mapping taught in one request is in force on the next, and would do it quietly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.ai.mapping_store import (
    LearnedPatternProvider,
    LoadResult,
    retire_mapping,
    upsert_mapping,
)
from backend.db.connection import get_connection, init_database
from backend.ingest.generic import PatternAdapterRegistry
from backend.ingest.patterns import PatternLibrary

VENDOR = "cisco_ios"
PATH_VALUE = "logging.remote_syslog"
PATH_FLAG = "service.tcp_keepalives_in"


@pytest.fixture()
def conn(tmp_path: Path):
    """A private, initialised database per test."""
    connection = get_connection(tmp_path / "store.db")
    init_database(connection)
    yield connection
    connection.close()


@pytest.fixture(scope="module")
def library() -> PatternLibrary:
    """The on-disk pattern packs, loaded once for the module."""
    return PatternLibrary()


def test_one_sweep_asks_the_database_once_not_once_per_vendor(conn, tmp_path) -> None:
    """Detection asks about every installed pack; that must be one connection.

    This is a performance property, but it is tested like a correctness one
    because it was worth roughly a 7x difference in the time to parse a
    configuration — 156 ms down to 22 ms measured — and because the cost was
    invisible: each call was correct and cheap-looking on its own, and only the
    *number* of them was wrong. A profile found it; nothing in the suite would
    have.

    It also explains a negative result recorded in ``docs/GAPS.md`` §6: with seven
    connections per parse, four worker processes contending on one SQLite file
    made a ``ProcessPoolExecutor`` no faster than serial parsing.
    """
    opened = 0

    def factory():
        nonlocal opened
        opened += 1
        return get_connection(tmp_path / "store.db")

    provider = LearnedPatternProvider(factory)
    vendors = ["cisco_ios", "cisco_asa", "cisco_nxos", "arista_eos", "juniper_junos"]
    provider.load_many(vendors)
    assert opened == 1, f"{len(vendors)} vendors cost {opened} connections"


def test_a_bulk_sweep_still_notices_a_mapping_taught_a_moment_ago(conn, tmp_path) -> None:
    """Batching must not buy speed with staleness.

    The whole point of the fingerprint is that a mapping taught in one request is
    in force on the next (C2's promise of no redeploy). A batch that read the
    fingerprint once and then cached across sweeps would break that quietly, so
    the freshness check is per sweep, and this is what says so.
    """
    provider = LearnedPatternProvider(lambda: get_connection(tmp_path / "store.db"))
    assert provider.load_many([VENDOR])[VENDOR].patterns == []

    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    assert len(provider.load_many([VENDOR])[VENDOR].patterns) == 1

    retire_mapping(conn, "logging host <*>")
    assert provider.load_many([VENDOR])[VENDOR].patterns == []


def test_a_bulk_sweep_answers_every_vendor_it_was_asked_about(conn, tmp_path) -> None:
    """A missing key would silently drop a pack's taught patterns.

    The caller builds one adapter per pack from this dict. A vendor absent from
    the result reads as "nothing taught for it", which is the same shape as the
    true answer and so would never raise.
    """
    provider = LearnedPatternProvider(lambda: get_connection(tmp_path / "store.db"))
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    asked = [VENDOR, "arista_eos", "fortinet"]
    result = provider.load_many(asked)
    assert sorted(result) == sorted(asked)
    assert len(result[VENDOR].patterns) == 1
    assert result["fortinet"].patterns == []


def test_the_single_vendor_form_still_works(conn, tmp_path) -> None:
    """``load`` is kept because a one-vendor question is still a real question.

    The training GUI asks about one vendor at a time, and tests inject a plain
    callable with no database at all.
    """
    provider = LearnedPatternProvider(lambda: get_connection(tmp_path / "store.db"))
    upsert_mapping(
        conn,
        template="logging host <*>",
        canonical_path=PATH_VALUE,
        admin_id="a@praman",
        vendor=VENDOR,
    )
    assert len(provider.load(VENDOR).patterns) == 1
    assert len(provider(VENDOR)) == 1


def test_detection_asks_the_learned_store_once_for_all_vendors(
    library: PatternLibrary,
) -> None:
    """The registry must take the store's bulk path when the store offers one.

    ``LearnedPatternProvider.load_many`` exists to answer one question per parse
    instead of one per installed pack, and
    ``tests/test_mapping_store.py`` proves the store honours that. This is the
    other half: that the caller actually uses it. Without this test the store
    could keep its fast path while the registry quietly went back to asking
    per-vendor, which is a ~7x parse regression that no functional test would
    notice, because every individual answer stays correct.
    """
    calls: list[list[str]] = []

    class BulkProvider:
        def load_many(self, vendors):
            calls.append(list(vendors))
            return {vendor: LoadResult() for vendor in vendors}

        def __call__(self, vendor):  # pragma: no cover - must not be reached
            raise AssertionError("registry fell back to the per-vendor path")

    registry = PatternAdapterRegistry(library)
    registry.set_learned_provider(BulkProvider())
    adapters = registry.adapters()

    assert len(calls) == 1, f"one sweep asked the store {len(calls)} times"
    assert sorted(calls[0]) == sorted(a.pack.vendor for a in adapters)


def test_a_plain_callable_provider_still_works(library: PatternLibrary) -> None:
    """The per-vendor path is the documented contract for injected providers.

    Tests and the CLI hand the registry a bare callable with no database behind
    it; the bulk path is an optimisation the real store opts into, not a new
    requirement on everyone who supplies patterns.
    """
    asked: list[str] = []
    registry = PatternAdapterRegistry(library)
    registry.set_learned_provider(lambda vendor: asked.append(vendor) or [])
    adapters = registry.adapters()

    assert sorted(asked) == sorted(a.pack.vendor for a in adapters)
