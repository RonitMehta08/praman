"""Test: ledger chain integrity — one test per link, plus a real round trip.

The ledger's claim is that an audit cannot be altered after the fact undetected.
That rests on four links::

    findings → merkle_root → record_hash → signature

so there is a tamper test per link here, each altering exactly one thing and
asserting that exactly that flag goes false. A single "something failed"
assertion is not enough: the version of this file that only checked
``not all(all_valid)`` passed for years while ``hash_valid`` was false on every
record in the database, healthy or not.

:class:`TestTheActorCheck` covers the fifth thing ``verify_chain`` reports, which
is not a link in that chain: ``actor`` is a hashed field, so the four links above
already prove it was not edited, and what the fifth check adds is whether the name
resolves to an operator the deployment issued. It is therefore the one check that
can go from valid to unknown without anybody touching the ledger — hand it a
different roster and the answer changes — which is why its unchecked state is
``None`` rather than ``False``.

The last class is the one that would have caught that. Every test above it builds
a record in memory and verifies the same dict, so the writer and the reader are
the same code path and can never disagree. The bug lived exactly in the gap
between them — the commit path hashed a dict holding the findings list, the
verifier hashed a SQLite row that structurally cannot hold one. Crossing that
boundary needs the real routes.
"""

from __future__ import annotations

import copy
import sqlite3
from pathlib import Path

import pytest

from backend.canonical.findings import Finding
from backend.core_errors import LedgerIntegrityError
from backend.db.connection import (
    FINDING_FIELDS,
    create_append_only_triggers,
    drop_append_only_triggers,
)
from backend.ledger.chain import (
    RECORD_HASH_FIELDS,
    compute_merkle_root,
    compute_record_hash,
    sign_record,
    verify_chain,
    verify_signature,
)

SAMPLE_FINDINGS = [
    {"control_id": "V-215844", "result": "pass", "severity": "high"},
    {"control_id": "V-215823", "result": "fail", "severity": "high"},
]

#: The operator every sample record names, and the roster it resolves against.
#:
#: A service principal rather than a person's name because nothing here logs in;
#: what matters to :func:`verify_chain` is only whether the hashed ``actor``
#: appears in the roster it was handed.
SAMPLE_ACTOR = "service:ledger-test"
KNOWN_ACTORS = {SAMPLE_ACTOR}


def _sample_record(seq: int, prev_hash: str = "") -> dict:
    """One ledger record, holding exactly the fields a real row holds.

    Deliberately no ``findings`` key: the findings are not a column of
    ``audit_records`` and so cannot be part of what the record hash covers. They
    reach the record through ``merkle_root`` instead, and reach the verifier
    through its ``findings_by_audit`` argument.
    """
    record = {
        "actor": SAMPLE_ACTOR,
        "audit_id": f"audit-{seq}",
        "device_id": "test-sw-01",
        "config_hash": "sha256:abc123",
        "created_at": "2026-01-01T00:00:00+00:00",
        "summary": {"total": 2, "by_result": {"pass": 1, "fail": 1}},
        "seq": seq,
        "prev_hash": prev_hash,
        "merkle_root": compute_merkle_root(SAMPLE_FINDINGS),
    }
    record["record_hash"] = compute_record_hash(record)
    record["signature"] = sign_record(record["record_hash"])
    return record


def _two_record_chain() -> tuple[list[dict], dict[str, list[dict]]]:
    """A sound two-record ledger and the findings behind it."""
    first = _sample_record(seq=1, prev_hash="")
    second = _sample_record(seq=2, prev_hash=first["record_hash"])
    findings_by_audit = {
        first["audit_id"]: copy.deepcopy(SAMPLE_FINDINGS),
        second["audit_id"]: copy.deepcopy(SAMPLE_FINDINGS),
    }
    return [first, second], findings_by_audit


class TestLedgerChain:
    def test_genesis_prev_hash_empty(self) -> None:
        """Genesis record has prev_hash == '' (SPINE)."""
        record = _sample_record(seq=1, prev_hash="")
        assert record["prev_hash"] == ""

    def test_chain_linkage(self) -> None:
        """Each record links to the previous via prev_hash."""
        records, _ = _two_record_chain()
        assert records[1]["prev_hash"] == records[0]["record_hash"]

    def test_seq_contiguous(self) -> None:
        """Seq numbers must be contiguous."""
        records, _ = _two_record_chain()
        assert records[1]["seq"] == records[0]["seq"] + 1

    def test_a_sound_chain_verifies_on_every_link(self) -> None:
        """All five flags true, not merely ``all_valid``.

        Asserting the flags individually is the point. ``all_valid`` can be true
        while a link was never checked, and a link reported sound without being
        checked is the failure this module exists to prevent.

        Both optional inputs are supplied — the findings and the operator roster —
        because this is the one test that asserts the *fully* verified sentence,
        and that sentence must only be reachable when nothing was skipped.
        """
        records, findings = _two_record_chain()
        for entry in verify_chain(records, findings, KNOWN_ACTORS):
            assert entry["hash_valid"], entry["detail"]
            assert entry["chain_valid"], entry["detail"]
            assert entry["signature_valid"], entry["detail"]
            assert entry["merkle_valid"], entry["detail"]
            assert entry["actor_valid"], entry["detail"]
            assert entry["actor"] == SAMPLE_ACTOR
            assert entry["all_valid"]
            assert entry["detail"] == (
                "all five links verify: findings, record hash, chain link, "
                "signature and actor"
            )


class TestTamperDetection:
    """One altered thing per test, and exactly one flag is expected to notice."""

    def test_an_altered_verdict_breaks_the_merkle_root(self) -> None:
        """Flipping one finding's result is caught — and only by the Merkle root.

        The verdicts are not in the record hash directly, so this is the *only*
        link that covers the substance of the audit. If it is not checked, the
        one alteration an auditor most cares about is invisible.
        """
        records, findings = _two_record_chain()
        findings[records[0]["audit_id"]][0]["result"] = "fail"  # was "pass"

        first, second = verify_chain(records, findings)
        assert first["merkle_valid"] is False
        assert first["all_valid"] is False
        assert "a verdict has been altered" in first["detail"]
        # The other links are untouched, and the later record is unaffected: the
        # findings hang off their own record, not off the chain.
        assert first["hash_valid"] and first["chain_valid"] and first["signature_valid"]
        assert second["all_valid"]

    def test_a_removed_finding_breaks_the_merkle_root(self) -> None:
        """Deleting a failure — the tamper with the clearest motive."""
        records, findings = _two_record_chain()
        del findings[records[0]["audit_id"]][1]  # the one that said "fail"

        assert verify_chain(records, findings)[0]["merkle_valid"] is False

    def test_an_altered_summary_breaks_the_record_hash(self) -> None:
        """A hashed field of the row itself, so ``hash_valid`` is what notices."""
        records, findings = _two_record_chain()
        records[0]["summary"] = {"total": 2, "by_result": {"pass": 2, "fail": 0}}

        first, second = verify_chain(records, findings)
        assert first["hash_valid"] is False
        assert first["all_valid"] is False
        assert "a hashed field was altered" in first["detail"]
        # merkle_valid stays true: the findings on disk were not touched, which is
        # precisely how a doctored summary would look.
        assert first["merkle_valid"] is True
        assert second["all_valid"]

    def test_a_spliced_out_record_breaks_the_chain(self) -> None:
        """Removing a middle record orphans its successor's prev_hash."""
        first = _sample_record(seq=1, prev_hash="")
        second = _sample_record(seq=2, prev_hash=first["record_hash"])
        third = _sample_record(seq=3, prev_hash=second["record_hash"])
        findings = {
            record["audit_id"]: copy.deepcopy(SAMPLE_FINDINGS)
            for record in (first, third)
        }

        surviving, orphaned = verify_chain([first, third], findings)
        assert surviving["all_valid"]
        assert orphaned["chain_valid"] is False
        assert orphaned["all_valid"] is False
        assert "a record between them was removed" in orphaned["detail"]

    def test_a_forged_record_hash_breaks_the_signature(self) -> None:
        """Rewriting the row and its hash together still fails without the key."""
        records, findings = _two_record_chain()
        records[0]["device_id"] = "some-other-device"
        records[0]["record_hash"] = compute_record_hash(records[0])

        first = verify_chain(records, findings)[0]
        # The hash now matches the doctored fields, so hash_valid alone is fooled.
        assert first["hash_valid"] is True
        assert first["signature_valid"] is False
        assert first["all_valid"] is False
        assert "signature over the record hash does not verify" in first["detail"]

    def test_a_non_empty_genesis_prev_hash_is_reported_as_such(self) -> None:
        """A ledger that does not begin at the beginning."""
        record = _sample_record(seq=1, prev_hash="deadbeef")
        entry = verify_chain([record], {record["audit_id"]: SAMPLE_FINDINGS})[0]
        assert entry["chain_valid"] is False
        assert "does not begin where it claims to" in entry["detail"]


class TestUncheckedLinksAreNotReportedAsSound:
    def test_withholding_findings_reports_merkle_valid_as_none(self) -> None:
        """Not ``True``. The distinction is the whole point of the tri-state."""
        records, _ = _two_record_chain()
        for entry in verify_chain(records):
            assert entry["merkle_valid"] is None
            assert "so merkle_root was not recomputed" in entry["detail"]

    def test_all_valid_does_not_claim_an_unchecked_link(self) -> None:
        """``all_valid`` covers what was checked, and says so in ``detail``.

        It stays true — the three links that *were* checked all passed — but the
        detail sentence names the one that was not, so a caller reading only
        ``all_valid`` is not silently told the findings were verified.
        """
        records, _ = _two_record_chain()
        entry = verify_chain(records)[0]
        assert entry["all_valid"] is True
        assert "the findings were not supplied" in entry["detail"]


class TestTheActorCheck:
    """The fifth thing reported, and the only one that is not a link.

    ``actor`` is inside the record hash, so these tests are not about detecting an
    edit — ``hash_valid`` already does that. They are about resolution: whether the
    name in the record belongs to somebody this deployment issued. That question
    has three answers, and the tri-state is what keeps the third from being
    mistaken for the second.
    """

    def test_a_known_actor_resolves(self) -> None:
        records, findings = _two_record_chain()
        entry = verify_chain(records, findings, KNOWN_ACTORS)[0]
        assert entry["actor"] == SAMPLE_ACTOR
        assert entry["actor_valid"] is True

    def test_an_unknown_actor_is_named_in_the_detail(self) -> None:
        """The name matters in the message: it is the lead an auditor follows.

        A record can reach this state without the ledger being touched at all —
        deleting the operator's row is enough — which is why the sentence blames
        the roster rather than the record.
        """
        records, findings = _two_record_chain()
        entry = verify_chain(records, findings, {"service:somebody-else"})[0]
        assert entry["actor_valid"] is False
        assert entry["all_valid"] is False
        assert SAMPLE_ACTOR in entry["detail"]
        assert "this deployment ever issued" in entry["detail"]

    def test_an_empty_actor_points_at_the_re_seed_instead(self) -> None:
        """Two failures, two messages.

        A record with no actor predates identity; a record with an actor nobody
        recognises is a different event with a different response. Collapsing them
        into "unknown operator" would send a reader looking for a person who was
        never there — and the action that fixes it is Step 12, not an HR question.
        """
        record = _sample_record(seq=1)
        record["actor"] = ""
        record["record_hash"] = compute_record_hash(record)
        record["signature"] = sign_record(record["record_hash"])

        entry = verify_chain([record], {record["audit_id"]: SAMPLE_FINDINGS}, KNOWN_ACTORS)[0]
        assert entry["hash_valid"] is True, "the row itself is sound; only the actor is absent"
        assert entry["actor_valid"] is False
        assert "predates operator identity" in entry["detail"]
        assert "Step 12" in entry["detail"]

    def test_no_roster_leaves_the_actor_unresolved_not_invalid(self) -> None:
        """``None``, and ``all_valid`` does not silently count it.

        This is the state every existing caller that has not been taught about
        operators is in, so reporting it as ``False`` would paint a sound ledger
        red on the strength of an argument nobody passed.
        """
        records, findings = _two_record_chain()
        entry = verify_chain(records, findings)[0]
        assert entry["actor_valid"] is None
        assert entry["all_valid"] is True
        assert "the actor was not resolved" in entry["detail"]

    def test_an_empty_roster_is_the_same_as_no_roster(self) -> None:
        """A deployment with no ``users`` table yields ``set()``.

        ``verify_chain`` is handed ``actors or None`` by ``/audit/verify`` for
        exactly this reason; asserting it here means the route's guard is not the
        only thing standing between an empty table and a red ledger.
        """
        records, findings = _two_record_chain()
        entry = verify_chain(records, findings, set())[0]
        assert entry["actor_valid"] is None

    def test_editing_the_actor_breaks_the_record_hash(self) -> None:
        """The reason ``actor`` is a hashed field rather than a side table.

        Without this, an attacker who could not forge a record could still change
        *who* it says decided — which is the attribution the whole change exists to
        make evidence. ``hash_valid`` is what notices, and it notices before the
        actor is ever resolved.
        """
        records, findings = _two_record_chain()
        records[0]["actor"] = "service:somebody-else"

        entry = verify_chain(records, findings, {"service:somebody-else", SAMPLE_ACTOR})[0]
        assert entry["hash_valid"] is False
        assert entry["all_valid"] is False
        assert "a hashed field was altered" in entry["detail"]


class TestRecordHash:
    def test_deterministic(self) -> None:
        record = _sample_record(seq=1)
        assert compute_record_hash(record) == compute_record_hash(record)

    def test_excludes_self(self) -> None:
        """``record_hash`` and ``signature`` cannot contribute to the hash.

        They are written after it is computed, so folding them in would make the
        hash unrecomputable from the stored row.
        """
        record = _sample_record(seq=1)
        without = {
            name: value
            for name, value in record.items()
            if name not in {"record_hash", "signature"}
        }
        assert compute_record_hash(without) == record["record_hash"]

    def test_findings_do_not_contribute(self) -> None:
        """The defect this module was rewritten for, pinned as a test.

        The commit path used to hand over a dict that also carried the findings
        list. The verifier reads a row from ``audit_records``, which has no such
        column. If an extra key can change the hash, those two paths disagree on
        every record and the check fails on healthy data — at which point it can
        no longer detect unhealthy data either.
        """
        record = _sample_record(seq=1)
        with_findings = dict(record, findings=copy.deepcopy(SAMPLE_FINDINGS))
        assert compute_record_hash(with_findings) == record["record_hash"]

    def test_every_hashed_field_actually_changes_the_hash(self) -> None:
        """No field is in the list decoratively.

        A field named in :data:`RECORD_HASH_FIELDS` but ignored in practice would
        be a hole exactly the size of that field: alter it and nothing notices.
        """
        # Type-appropriate replacements — a string in `seq` or `summary` would
        # test the parsing of a malformed row rather than the coverage of a sound
        # one, which is what the two tests below are for.
        altered_values: dict[str, object] = {
            "seq": 999,
            "summary": {"total": 0, "by_result": {}},
        }
        record = _sample_record(seq=1)
        baseline = compute_record_hash(record)
        for name in RECORD_HASH_FIELDS:
            altered = dict(record)
            altered[name] = altered_values.get(name, "tampered")
            assert compute_record_hash(altered) != baseline, (
                f"{name} is listed as hashed but changing it did not change the hash"
            )

    def test_a_missing_field_raises_rather_than_hashing_around_it(self) -> None:
        """Silence here is what produced two hashes for one record."""
        record = _sample_record(seq=1)
        del record["merkle_root"]
        with pytest.raises(LedgerIntegrityError, match="merkle_root"):
            compute_record_hash(record)

    def test_an_unparseable_summary_is_a_finding_not_a_crash(self) -> None:
        """A verifier that raises on tampered input reports nothing about the rest.

        ``LedgerIntegrityError`` is caught by :func:`verify_chain` and turned into
        ``hash_valid: False`` with an explanation; a raw ``JSONDecodeError`` would
        escape as a 500 from ``/audit/verify`` and take the other records' verdicts
        down with it.
        """
        record = _sample_record(seq=1)
        record["summary"] = "not json at all"
        with pytest.raises(LedgerIntegrityError, match="not JSON"):
            compute_record_hash(record)

        entry = verify_chain([record], {record["audit_id"]: SAMPLE_FINDINGS})[0]
        assert entry["hash_valid"] is False
        assert entry["all_valid"] is False
        assert "not JSON" in entry["detail"]

    def test_a_string_summary_hashes_the_same_as_a_dict_one(self) -> None:
        """SQLite hands back JSON text; the commit path holds a dict.

        Both must reach the same hash or the round trip breaks in a second,
        independent way from the findings-key mismatch.
        """
        import json

        record = _sample_record(seq=1)
        from_sqlite = dict(record, summary=json.dumps(record["summary"]))
        assert compute_record_hash(from_sqlite) == record["record_hash"]


class TestMerkleRoot:
    def test_empty_findings(self) -> None:
        root = compute_merkle_root([])
        assert isinstance(root, str)
        assert len(root) > 0

    def test_deterministic(self) -> None:
        findings = [{"id": 1}, {"id": 2}]
        assert compute_merkle_root(findings) == compute_merkle_root(findings)

    def test_order_matters(self) -> None:
        f1 = [{"id": 1}, {"id": 2}]
        f2 = [{"id": 2}, {"id": 1}]
        assert compute_merkle_root(f1) != compute_merkle_root(f2)


class TestSignature:
    def test_sign_and_verify(self) -> None:
        """Sign a hash and verify it."""
        record_hash = _sample_record(seq=1)["record_hash"]
        assert verify_signature(record_hash, sign_record(record_hash))

    def test_wrong_hash_fails(self) -> None:
        """Verifying with a different hash must fail."""
        signature = sign_record(_sample_record(seq=1)["record_hash"])
        assert not verify_signature("wrong_hash", signature)


class TestStoredFindingsProjection:
    def test_finding_fields_match_the_model(self) -> None:
        """``FINDING_FIELDS`` is a hand-copy of the model, so it needs a guard.

        The Merkle root is computed over ``Finding.model_dump(mode="json")``. Add
        a field to the model without adding it here and the projection read back
        for verification would be missing it, so every audit committed before the
        change would report as tampered with.
        """
        assert tuple(Finding.model_fields) == FINDING_FIELDS


class TestLedgerRoundTripThroughTheApi:
    """The write/read boundary, which every test above deliberately does not cross.

    Nothing in-memory can catch a disagreement between the commit path and the
    verifier, because in-memory tests *are* one path. This is the test whose
    absence let ``hash_valid`` be false on all 13 records of the development
    ledger while the suite stayed green.
    """

    CONFIG = """\
!
version 15.0
hostname ledger-roundtrip-device
enable secret 5 $1$test$hash
ip ssh version 2
aaa new-model
no ip http server
line vty 0 4
 transport input ssh
 exec-timeout 10 0
logging host 10.0.0.1
end
"""

    def _commit_one_audit(self) -> tuple[object, dict]:
        from fastapi.testclient import TestClient

        from backend.app.main import app

        client = TestClient(app)
        ingest = client.post(
            "/ingest",
            files={
                "file": ("ledger-roundtrip.conf", self.CONFIG.encode(), "text/plain")
            },
        )
        assert ingest.status_code == 200, ingest.text
        commit = client.post(
            "/audit/commit", json={"device_id": ingest.json()["device_id"]}
        )
        assert commit.status_code == 200, commit.text
        return client, commit.json()

    def test_a_committed_audit_verifies_on_all_five_checks(self) -> None:
        """Ingest, commit, verify — through the routes, against real SQLite.

        The actor is asserted here rather than only in ``tests/test_auth.py``
        because this is the only test that crosses every boundary the field has to
        survive: the authenticated request, the hashed record, the SQLite column,
        and the roster ``/audit/verify`` resolves it against. A name that reached
        the response but not the hash, or the hash but not the ``users`` table,
        would pass a narrower test and fail this one.
        """
        client, committed = self._commit_one_audit()

        from tests.conftest import TEST_OPERATOR

        assert committed["actor"] == TEST_OPERATOR, (
            "the commit response names a different operator than the one that "
            "authenticated, so the response and the ledger disagree about who acted"
        )

        verify = client.get("/audit/verify")
        assert verify.status_code == 200
        entries = {entry["seq"]: entry for entry in verify.json()["results"]}
        entry = entries[committed["seq"]]

        assert entry["record_hash"] == committed["record_hash"]
        assert entry["hash_valid"] is True, entry["detail"]
        assert entry["chain_valid"] is True, entry["detail"]
        assert entry["signature_valid"] is True, entry["detail"]
        assert entry["merkle_valid"] is True, entry["detail"]
        assert entry["actor"] == TEST_OPERATOR, entry["detail"]
        assert entry["actor_valid"] is True, entry["detail"]
        assert entry["all_valid"] is True, entry["detail"]

    def test_the_verifier_recomputes_the_merkle_root_from_stored_findings(self) -> None:
        """``merkle_valid`` is a real check over the findings table, not a copy.

        Reporting the root as valid by comparing the record to itself would pass
        this endpoint on any database, tampered or not.
        """
        _client, committed = self._commit_one_audit()

        from backend.app.state import STATE
        from backend.db.connection import finding_from_row

        conn = STATE.connect()
        try:
            rows = conn.execute(
                "SELECT * FROM findings WHERE audit_id = ? ORDER BY id",
                (committed["audit_id"],),
            ).fetchall()
        finally:
            conn.close()

        assert rows, "the commit stored no findings, so nothing was verified"
        stored = [finding_from_row(row) for row in rows]
        assert compute_merkle_root(stored) == committed["merkle_root"]

    def test_altering_a_stored_finding_is_detected_end_to_end(self) -> None:
        """The claim the ledger is for, exercised against the database.

        An UPDATE straight to SQLite is what an attacker with file access does;
        it leaves the ledger row untouched, so only the recomputed Merkle root
        can notice.
        """
        client, committed = self._commit_one_audit()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            row = conn.execute(
                "SELECT id, result FROM findings WHERE audit_id = ? AND result = 'fail'"
                " ORDER BY id LIMIT 1",
                (committed["audit_id"],),
            ).fetchone()
            assert row is not None, "fixture produced no failure to hide"
            conn.execute(
                "UPDATE findings SET result = 'pass' WHERE id = ?", (row["id"],)
            )
            conn.commit()

            verify = client.get("/audit/verify")
            entry = next(
                item
                for item in verify.json()["results"]
                if item["seq"] == committed["seq"]
            )
            assert entry["merkle_valid"] is False
            assert entry["all_valid"] is False
            assert "a verdict has been altered" in entry["detail"]
            # The row itself was not touched, so its own hash still checks out —
            # which is exactly why the Merkle link cannot be skipped.
            assert entry["hash_valid"] is True
            assert entry["signature_valid"] is True
        finally:
            # Leave the shared ledger sound for whatever runs next.
            conn.execute(
                "UPDATE findings SET result = ? WHERE id = ?", (row["result"], row["id"])
            )
            conn.commit()
            conn.close()


class TestAppendOnlyEnforcement:
    """``audit_records`` refuses UPDATE and DELETE at the storage layer.

    The hash chain makes tampering detectable. These triggers make the *casual*
    kinds impossible — a migration script with a stray UPDATE, an operator
    correcting a timestamp by hand, an ORM helpfully re-saving a row. Those fail
    here, at the statement, with a message that says why, instead of surfacing
    later as an unexplained verification failure with no author.

    They are not a defence against an attacker holding the file: anyone who can
    write to the database can drop a trigger, which is what
    ``test_the_chain_still_catches_an_attacker_who_drops_the_triggers`` does. The
    two layers fail in different circumstances, which is the whole reason to have
    both.
    """

    def _committed_seq(self) -> tuple[object, dict]:
        return TestLedgerRoundTripThroughTheApi()._commit_one_audit()

    def test_a_committed_record_cannot_be_updated(self) -> None:
        _client, committed = self._committed_seq()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(
                    "UPDATE audit_records SET created_at = '1999-01-01T00:00:00Z'"
                    " WHERE audit_id = ?",
                    (committed["audit_id"],),
                )
        finally:
            conn.close()

    def test_a_committed_record_cannot_be_deleted(self) -> None:
        _client, committed = self._committed_seq()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(
                    "DELETE FROM audit_records WHERE audit_id = ?",
                    (committed["audit_id"],),
                )
        finally:
            conn.close()

    def test_the_abort_message_names_the_way_out(self) -> None:
        """A refusal that does not say what to do instead gets worked around.

        An operator who hits this needs to know the answer is "commit a new audit"
        or "run the reset script" — otherwise the next step is DROP TRIGGER, and
        the guarantee is gone for good rather than for one statement.
        """
        _client, committed = self._committed_seq()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            with pytest.raises(sqlite3.IntegrityError) as update_exc:
                conn.execute(
                    "UPDATE audit_records SET seq = -1 WHERE audit_id = ?",
                    (committed["audit_id"],),
                )
            assert "Commit a new audit" in str(update_exc.value)

            with pytest.raises(sqlite3.IntegrityError) as delete_exc:
                conn.execute("DELETE FROM audit_records")
            assert "reset_ledger.py" in str(delete_exc.value)
        finally:
            conn.close()

    def test_inserting_a_new_record_is_still_allowed(self) -> None:
        """Append-only means append. A commit after a commit must work."""
        _client, first = self._committed_seq()
        _client2, second = self._committed_seq()
        assert second["seq"] == first["seq"] + 1
        assert second["prev_hash"] == first["record_hash"]

    def test_the_triggers_exist_on_a_freshly_initialised_database(
        self, tmp_path: Path
    ) -> None:
        """A new database is protected without anyone remembering to ask.

        ``init_database`` installs them, so the guarantee holds for a first-run
        deployment and not only for databases that happened to pass through the
        reset script.
        """
        from backend.db.connection import get_connection, init_database

        conn = get_connection(tmp_path / "fresh.db")
        try:
            init_database(conn)
            names = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                )
            }
            assert "audit_records_append_only_update" in names
            assert "audit_records_append_only_delete" in names
        finally:
            conn.close()

    def test_init_database_is_idempotent_with_the_triggers_present(
        self, tmp_path: Path
    ) -> None:
        """Every request path calls ``init_database``. It must not raise the second
        time — ``CREATE TRIGGER`` without ``IF NOT EXISTS`` would break every
        request after the first."""
        from backend.db.connection import get_connection, init_database

        conn = get_connection(tmp_path / "twice.db")
        try:
            init_database(conn)
            init_database(conn)
        finally:
            conn.close()

    def test_the_chain_still_catches_an_attacker_who_drops_the_triggers(self) -> None:
        """The layer below the triggers, exercised by defeating the triggers.

        This is the honest statement of the threat model: file-level write access
        beats the storage guard, and the hash chain is what remains. If this test
        ever passes because the UPDATE was refused, the assertion has stopped
        testing the chain — hence the explicit drop.
        """
        client, committed = self._committed_seq()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            original = conn.execute(
                "SELECT config_hash FROM audit_records WHERE audit_id = ?",
                (committed["audit_id"],),
            ).fetchone()["config_hash"]
            drop_append_only_triggers(conn)
            conn.execute(
                "UPDATE audit_records SET config_hash = 'sha256:tampered'"
                " WHERE audit_id = ?",
                (committed["audit_id"],),
            )
            conn.commit()

            verify = client.get("/audit/verify")
            entry = next(
                item
                for item in verify.json()["results"]
                if item["seq"] == committed["seq"]
            )
            assert entry["hash_valid"] is False
            assert entry["all_valid"] is False
        finally:
            # Put the row back before re-arming, or every later test in the
            # session inherits a ledger this one broke. The drop is repeated
            # because the /audit/verify request above went through
            # ``init_database`` and re-armed the triggers underneath us — see
            # ``test_a_dropped_trigger_is_reinstalled_by_the_next_request``.
            drop_append_only_triggers(conn)
            conn.execute(
                "UPDATE audit_records SET config_hash = ? WHERE audit_id = ?",
                (original, committed["audit_id"]),
            )
            create_append_only_triggers(conn)
            conn.commit()
            conn.close()

    def test_a_dropped_trigger_is_reinstalled_by_the_next_request(self) -> None:
        """An attacker's DROP TRIGGER does not stay dropped.

        Every request path calls ``init_database``, which creates the triggers if
        absent. So the window opened by dropping them closes at the next request
        rather than staying open for the life of the database — which is why the
        test above has to drop them a second time to clean up after itself.

        This is a real property, not a lucky accident, and it is worth pinning: if
        trigger creation ever moves out of ``init_database`` into a one-time
        migration, this fails and says so.
        """
        client, _committed = self._committed_seq()

        from backend.app.state import STATE

        conn = STATE.connect()
        try:
            drop_append_only_triggers(conn)
            conn.commit()
            assert self._trigger_names(conn) == set()
        finally:
            conn.close()

        assert client.get("/audit/verify").status_code == 200

        conn = STATE.connect()
        try:
            assert self._trigger_names(conn) == {
                "audit_records_append_only_update",
                "audit_records_append_only_delete",
            }
        finally:
            conn.close()

    @staticmethod
    def _trigger_names(conn: sqlite3.Connection) -> set[str]:
        return {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                " AND name LIKE 'audit_records_append_only%'"
            )
        }
