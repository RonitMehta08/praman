"""Test: the standalone offline ledger verifier.

``backend/ledger/verify.py`` exists so a third party can check the audit chain
without running our code, which means it deliberately duplicates four constants
and three hash definitions from ``backend/``. Duplication that nothing checks is
how a verifier starts disagreeing with the writer and reporting healthy records
as tampered with — a verifier that cries wolf is worse than none, because the
operator learns to close it.

So this file is mostly coupling tests. :class:`TestTheHandCopiesMatch` imports
both sides and asserts they are the same; :class:`TestIndependence` asserts the
duplication is still *necessary* by reading the module's own source and refusing
any import from ``backend``. Between them, either the copies agree or a test
fails.

The rest is what the previous version of that module could not have passed. It
hashed every column of the row except two, while the writer hashes an explicit
nine; those coincide today only because ``audit_records`` happens to have
exactly those nine other columns. And it checked three of the four links,
omitting the Merkle root — the only one that covers the verdicts, so every
pass/fail in the ledger could have been rewritten and it would still have printed
a clean bill of health.

There are now five things checked, not four. The fifth — ``actor_valid`` — is not
a link in the hash chain: the ``actor`` is a hashed field, so the chain already
covers it, and what the fifth check adds is whether the name resolves against the
deployment's operator roster. Because the roster is an *input*, every test below
that asserts a fully verified ledger has to supply one, which is the honest shape
of the claim: a ledger file alone cannot tell you its operators were real.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from backend.db import connection as db_connection
from backend.db.connection import drop_append_only_triggers
from backend.ledger import chain, verify

#: The operator every in-memory sample record names, and the roster that resolves
#: it. Passed explicitly at every call site rather than defaulted, because "which
#: operators exist" is knowledge the verifier gets from outside the ledger.
SAMPLE_ACTOR = "service:standalone-test"
KNOWN_ACTORS = {SAMPLE_ACTOR}

SAMPLE_FINDINGS: list[dict] = [
    {
        "control_id": "1.1.1",
        "framework": "CIS",
        "benchmark": "CIS Cisco IOS 15 Benchmark",
        "benchmark_version": "4.1.1",
        "title": "Enable AAA",
        "result": "pass",
        "severity": "high",
        "evidence": [{"path": "aaa.new_model", "value": True}],
        "rationale": "aaa new-model is present",
        "remediation_ref": None,
        "references": {},
    },
    {
        "control_id": "1.1.2",
        "framework": "CIS",
        "benchmark": "CIS Cisco IOS 15 Benchmark",
        "benchmark_version": "4.1.1",
        "title": "Disable HTTP server",
        "result": "fail",
        "severity": "medium",
        "evidence": [],
        "rationale": "ip http server is enabled",
        "remediation_ref": "cis-1.1.2",
        "references": {"cci": ["CCI-000366"]},
    },
]


def _sample_record(seq: int = 1, prev_hash: str = "") -> dict:
    """A ledger row as SQLite would hand it back, signed and self-consistent."""
    record = {
        "actor": SAMPLE_ACTOR,
        "audit_id": f"audit-{seq}",
        "device_id": "rtr-01",
        "config_hash": "sha256:" + "ab" * 32,
        "created_at": "2026-08-30T12:00:00+00:00",
        "summary": {"total": 2, "by_result": {"pass": 1, "fail": 1}},
        "seq": seq,
        "prev_hash": prev_hash,
        "merkle_root": chain.compute_merkle_root(SAMPLE_FINDINGS),
    }
    record["record_hash"] = chain.compute_record_hash(record)
    record["signature"] = chain.sign_record(record["record_hash"])
    return record


@pytest.fixture
def pub_key() -> bytes:
    from backend.ledger.chain import VERIFY_KEY_PATH, generate_signing_keys

    if not VERIFY_KEY_PATH.exists():
        generate_signing_keys()
    return VERIFY_KEY_PATH.read_bytes()


class TestTheHandCopiesMatch:
    """Every constant and hash the verifier restates must equal the original.

    These are the tests that make the §8 independence affordable. Without them
    the module is a second implementation nobody diffs.
    """

    def test_record_hash_fields(self) -> None:
        assert verify.RECORD_HASH_FIELDS == chain.RECORD_HASH_FIELDS

    def test_finding_fields(self) -> None:
        # Set equality, not tuple: the JSON is key-sorted, so field *order* cannot
        # change a hash, but a field appearing in one list and not the other can.
        assert set(verify.FINDING_FIELDS) == set(db_connection.FINDING_FIELDS)

    def test_finding_json_columns(self) -> None:
        assert verify.FINDING_JSON_COLUMNS == db_connection._FINDING_JSON_COLUMNS

    def test_merkle_tags_and_empty_preimage(self) -> None:
        assert verify.LEAF_TAG == chain._LEAF_TAG
        assert verify.NODE_TAG == chain._NODE_TAG
        assert verify.EMPTY_MERKLE_PREIMAGE == chain._EMPTY_MERKLE_PREIMAGE

    def test_record_hash_agrees(self) -> None:
        record = _sample_record()
        assert verify.compute_record_hash(record) == chain.compute_record_hash(record)

    def test_record_hash_agrees_on_a_sqlite_row(self) -> None:
        """SQLite stores ``summary`` as text; both sides must normalise it."""
        record = _sample_record()
        as_row = dict(record, summary=json.dumps(record["summary"]))
        assert verify.compute_record_hash(as_row) == record["record_hash"]

    @pytest.mark.parametrize("count", [0, 1, 2, 3, 5, 8, 17])
    def test_merkle_root_agrees(self, count: int) -> None:
        findings = [{"control_id": f"1.{i}", "result": "pass"} for i in range(count)]
        assert verify.compute_merkle_root(findings) == chain.compute_merkle_root(findings)

    def test_finding_projection_agrees(self) -> None:
        row = {
            "id": 7,
            "audit_id": "audit-1",
            "device_id": "rtr-01",
            "control_id": "1.1.1",
            "framework": "CIS",
            "benchmark": "b",
            "benchmark_version": "1",
            "title": "t",
            "result": "pass",
            "severity": "high",
            "evidence": '[{"path": "aaa.new_model"}]',
            "rationale": "r",
            "remediation_ref": None,
            "references": None,
        }
        assert verify.project_finding(row) == db_connection.finding_from_row(row)


class TestIndependence:
    """GLOBAL_RULESET §8: the verifier imports nothing from the application.

    Asserted by reading the source rather than by inspecting ``sys.modules``,
    because an import that only fires inside a function would not show up there —
    and the point of §8 is that the *file* can be handed to a third party.
    """

    def test_no_backend_import_in_the_source(self) -> None:
        source = Path(verify.__file__).read_text(encoding="utf-8")
        offenders = [
            line.strip()
            for line in source.splitlines()
            if line.lstrip().startswith(("import backend", "from backend"))
        ]
        assert not offenders, (
            "backend/ledger/verify.py must not import from backend/ — a verifier "
            f"that calls the code it verifies proves nothing. Found: {offenders}"
        )

    def test_the_module_body_only_needs_the_standard_library(self) -> None:
        """``cryptography`` is imported lazily, inside the signature check.

        So the record-hash, chain-link and Merkle checks run on a bare Python
        install with nothing pip-installed at all. That is the difference between
        "verifiable by a third party" and "verifiable by a third party who first
        reproduces our environment".
        """
        source = Path(verify.__file__).read_text(encoding="utf-8")
        header = source.split("# --- Hashing", 1)[0]
        assert "import cryptography" not in header
        assert "from cryptography" not in header


class TestMerkleStructure:
    """Properties the tree must have, asserted against both implementations."""

    @pytest.fixture(params=["chain", "standalone"])
    def root(self, request: pytest.FixtureRequest):
        return (
            chain.compute_merkle_root
            if request.param == "chain"
            else verify.compute_merkle_root
        )

    def test_appending_a_duplicate_of_the_last_finding_changes_the_root(self, root) -> None:
        """The malleability the previous implementation had.

        It padded an odd level by duplicating the final node, which makes
        ``[a, b, c]`` and ``[a, b, c, c]`` hash identically — so a committed audit
        could have its last verdict duplicated without invalidating the ledger.
        Promoting the unpaired node instead removes the whole class.
        """
        three = [{"id": 1}, {"id": 2}, {"id": 3}]
        assert root(three) != root([*three, three[-1]])

    def test_a_single_finding_is_not_its_own_leaf_hash(self, root) -> None:
        """Domain separation, observed rather than asserted about the constant.

        With one finding the root *is* the leaf, so this pins the leaf tag: an
        untagged leaf is plain ``sha256(json)``, which a reader could confuse with
        an internal node.
        """
        import hashlib

        finding = {"id": 1}
        untagged = hashlib.sha256(
            json.dumps(finding, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert root([finding]) != untagged

    def test_the_input_list_is_not_mutated(self, root) -> None:
        """The old tree appended to the list it was given."""
        findings = [{"id": 1}, {"id": 2}, {"id": 3}]
        before = json.dumps(findings)
        root(findings)
        assert json.dumps(findings) == before

    def test_order_matters(self, root) -> None:
        assert root([{"id": 1}, {"id": 2}]) != root([{"id": 2}, {"id": 1}])

    def test_a_non_json_finding_raises_rather_than_stringifying(self, root) -> None:
        """``default=str`` would let two callers agree by accident.

        ``Result.PASS`` and ``"pass"`` are the same audit to a reader and
        different bytes to sha256, so a root computed over enum objects cannot be
        reproduced from the emitted JSON. Raising is what makes that a bug report
        instead of an unverifiable ledger record.
        """
        with pytest.raises(TypeError):
            root([{"result": object()}])


class TestUncheckedIsNotValid:
    """A link that was not checked must never be reported as sound."""

    def test_no_public_key_leaves_the_signature_unchecked(self) -> None:
        ok, results = verify.verify_chain_standalone(
            [_sample_record()],
            {"audit-1": SAMPLE_FINDINGS},
            pub_key=None,
            known_actors=KNOWN_ACTORS,
        )
        assert results[0]["signature_valid"] is None
        assert results[0]["hash_valid"] is True
        assert results[0]["merkle_valid"] is True
        assert results[0]["actor_valid"] is True
        assert results[0]["all_valid"] is False
        assert ok is False
        assert "signature was not checked" in results[0]["detail"]

    def test_no_findings_leaves_the_merkle_root_unchecked(self, pub_key: bytes) -> None:
        ok, results = verify.verify_chain_standalone(
            [_sample_record()],
            findings_by_audit=None,
            pub_key=pub_key,
            known_actors=KNOWN_ACTORS,
        )
        assert results[0]["merkle_valid"] is None
        assert results[0]["all_valid"] is False
        assert ok is False
        assert "merkle_root was not checked" in results[0]["detail"]

    def test_no_operator_roster_leaves_the_actor_unresolved(self, pub_key: bytes) -> None:
        """The link that can go unchecked without anything being missing from the file.

        A ledger export carries its own findings and can be handed a public key, so
        those two gaps are the reader's to close. The operator roster is not in the
        ledger at all — which is why an unresolved actor has to read as a gap in the
        verification rather than as a fault in the record.
        """
        ok, results = verify.verify_chain_standalone(
            [_sample_record()], {"audit-1": SAMPLE_FINDINGS}, pub_key, known_actors=None
        )
        assert results[0]["hash_valid"] is True
        assert results[0]["signature_valid"] is True
        assert results[0]["merkle_valid"] is True
        assert results[0]["actor_valid"] is None
        assert results[0]["actor"] == SAMPLE_ACTOR, (
            "the actor must still be reported even when it cannot be resolved: it "
            "is the name a reader takes to the deployment's own user list"
        )
        assert results[0]["all_valid"] is False
        assert ok is False
        assert "actor was not checked" in results[0]["detail"]

    def test_an_empty_roster_reads_the_same_as_no_roster(self, pub_key: bytes) -> None:
        """``load_known_actors`` returns ``set()`` for a database with no users.

        Treating that as "nobody is a known operator" would report every record in
        an older ledger as committed by a stranger — a false accusation produced by
        a missing table.
        """
        _ok, results = verify.verify_chain_standalone(
            [_sample_record()], {"audit-1": SAMPLE_FINDINGS}, pub_key, known_actors=set()
        )
        assert results[0]["actor_valid"] is None

    def test_an_empty_ledger_is_not_a_verified_ledger(self, pub_key: bytes) -> None:
        """``all([])`` is True, which is the wrong answer to "is this sound?".

        An empty or truncated ``audit_records`` table is the shape a wiped ledger
        has, and reporting it as verified is how a wipe passes review.
        """
        ok, results = verify.verify_chain_standalone([], {}, pub_key, KNOWN_ACTORS)
        assert results == []
        assert ok is False

    def test_a_missing_hashed_field_is_reported_not_raised(self, pub_key: bytes) -> None:
        # The findings are supplied so the Merkle link passes: _detail reports the
        # most serious break first, and an altered verdict outranks an unhashable
        # row, so passing {} here would hide the note this test is about.
        record = _sample_record()
        del record["config_hash"]
        ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, pub_key, KNOWN_ACTORS
        )
        assert ok is False
        assert results[0]["hash_valid"] is False
        assert results[0]["merkle_valid"] is True
        assert "missing hashed field(s): config_hash" in results[0]["detail"]

    def test_a_missing_actor_is_a_missing_hashed_field(self) -> None:
        """A row from before identity cannot be hashed at all, and says so.

        This is the state every record in a ledger written by an older build is in.
        The verifier's job there is to name the reason rather than to report a
        mismatch: "the record hash does not match" would send an operator hunting
        for a tamper, when the answer is a re-seed.
        """
        record = _sample_record()
        del record["actor"]
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, None, KNOWN_ACTORS
        )
        assert results[0]["hash_valid"] is False
        assert "missing hashed field(s): actor" in results[0]["detail"]


class TestTamperDetection:
    """One test per link, each altering exactly one thing."""

    def test_a_sound_ledger_verifies_on_all_five_checks(self, pub_key: bytes) -> None:
        first = _sample_record(seq=1)
        second = _sample_record(seq=2, prev_hash=first["record_hash"])
        findings = {"audit-1": SAMPLE_FINDINGS, "audit-2": SAMPLE_FINDINGS}
        ok, results = verify.verify_chain_standalone(
            [first, second], findings, pub_key, KNOWN_ACTORS
        )
        assert ok is True, results
        assert all(r["all_valid"] for r in results)
        assert results[0]["detail"].startswith("all five links verify")

    def test_an_altered_verdict_breaks_the_merkle_root_only(self, pub_key: bytes) -> None:
        record = _sample_record()
        tampered = [dict(SAMPLE_FINDINGS[0], result="pass"), dict(SAMPLE_FINDINGS[1], result="pass")]
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": tampered}, pub_key, KNOWN_ACTORS
        )
        entry = results[0]
        assert entry["merkle_valid"] is False
        assert entry["hash_valid"] is True
        assert entry["chain_valid"] is True
        assert entry["signature_valid"] is True
        assert entry["actor_valid"] is True
        assert "a verdict has been altered" in entry["detail"]

    def test_an_altered_summary_breaks_the_record_hash(self, pub_key: bytes) -> None:
        record = _sample_record()
        record["summary"] = {"total": 2, "by_result": {"pass": 2, "fail": 0}}
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, pub_key, KNOWN_ACTORS
        )
        assert results[0]["hash_valid"] is False
        assert "not the hash of this record's fields" in results[0]["detail"]

    def test_a_removed_record_breaks_the_chain_link(self, pub_key: bytes) -> None:
        first = _sample_record(seq=1)
        second = _sample_record(seq=2, prev_hash=first["record_hash"])
        third = _sample_record(seq=3, prev_hash=second["record_hash"])
        findings = {f"audit-{i}": SAMPLE_FINDINGS for i in (1, 2, 3)}
        _ok, results = verify.verify_chain_standalone(
            [first, third], findings, pub_key, KNOWN_ACTORS
        )
        assert results[0]["chain_valid"] is True
        assert results[1]["chain_valid"] is False
        assert "a record between them was removed" in results[1]["detail"]

    def test_a_non_empty_genesis_prev_hash_is_detected(self, pub_key: bytes) -> None:
        record = _sample_record(seq=1, prev_hash="deadbeef")
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, pub_key, KNOWN_ACTORS
        )
        assert results[0]["chain_valid"] is False
        assert "does not begin where it claims to" in results[0]["detail"]

    def test_a_forged_signature_is_detected(self, pub_key: bytes) -> None:
        record = _sample_record()
        record["signature"] = "00" * 64
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, pub_key, KNOWN_ACTORS
        )
        assert results[0]["signature_valid"] is False
        assert results[0]["hash_valid"] is True
        assert "does not verify against" in results[0]["detail"]

    def test_an_actor_the_deployment_never_issued_is_detected(self, pub_key: bytes) -> None:
        """Four links intact, and the record is still not sound.

        The signature proves the record was written by something holding the
        signing key. It says nothing about whether the operator it names exists,
        and a record naming ``service:audit-bot`` on a deployment that never had
        such an account is either a stale export or an attribution nobody can
        answer for.
        """
        record = _sample_record()
        _ok, results = verify.verify_chain_standalone(
            [record], {"audit-1": SAMPLE_FINDINGS}, pub_key, {"someone.else"}
        )
        entry = results[0]
        assert entry["hash_valid"] is True
        assert entry["chain_valid"] is True
        assert entry["signature_valid"] is True
        assert entry["merkle_valid"] is True
        assert entry["actor_valid"] is False
        assert entry["all_valid"] is False
        assert SAMPLE_ACTOR in entry["detail"]


class TestAgainstARealDatabase:
    """Ingest, commit, then verify the resulting file with the standalone module.

    Every test above builds a record in memory, so the writer and the reader are
    the same process and can never disagree about a column name or a JSON
    encoding. The original defect lived exactly in that gap. This class crosses
    it: the only thing shared with the application is the ``.db`` file on disk.
    """

    CONFIG = """\
!
version 15.2
hostname standalone-verify-rtr
enable secret 5 $1$abcd$hashedvalue
snmp-server community S3cretC0mmunity RO
ip ssh version 2
aaa new-model
no ip http server
line vty 0 4
 transport input ssh
 exec-timeout 10 0
logging host 10.0.0.1
end
"""

    @pytest.fixture
    def committed_db(self, tmp_path: Path):
        """A private database holding exactly two committed audits."""
        from fastapi.testclient import TestClient

        from backend.app.auth import ensure_service_account
        from backend.app.main import app
        from backend.app.state import STATE
        from tests.conftest import TEST_OPERATOR

        previous = STATE.db_path
        STATE.db_path = tmp_path / "standalone.db"
        STATE.learned.invalidate()
        try:
            client = TestClient(app)
            # The suite's principal is a dependency override, so it exists in every
            # request but only has a ``users`` row in the session database. This one
            # is private, and an operator row is part of what a real deployment
            # hands the verifier — without it the actor in these records would
            # resolve against nothing and the end-to-end test below could only ever
            # report "incomplete".
            conn = STATE.connect()
            try:
                ensure_service_account(conn, TEST_OPERATOR)
            finally:
                conn.close()

            ingest = client.post(
                "/ingest",
                files={"file": ("standalone.conf", self.CONFIG.encode(), "text/plain")},
            )
            assert ingest.status_code == 200, ingest.text
            device_id = ingest.json()["device_id"]
            committed = []
            for _ in range(2):
                response = client.post("/audit/commit", json={"device_id": device_id})
                assert response.status_code == 200, response.text
                committed.append(response.json())
            yield STATE.db_path, committed
        finally:
            STATE.db_path = previous
            STATE.learned.invalidate()

    def test_the_ledger_verifies_end_to_end(self, committed_db, pub_key: bytes) -> None:
        db_path, committed = committed_db
        records, findings = verify.load_sqlite(db_path)
        actors = verify.load_known_actors(db_path)

        assert len(records) == 2
        assert [r["seq"] for r in records] == [1, 2]
        assert findings, "no findings were read, so the Merkle root proves nothing"
        assert actors, "no operators were read, so the actor proves nothing"

        ok, results = verify.verify_chain_standalone(records, findings, pub_key, actors)
        assert ok is True, [r["detail"] for r in results if not r["all_valid"]]
        assert [r["record_hash"] for r in results] == [
            c["record_hash"] for c in committed
        ]
        assert all(r["actor"] in actors for r in results), (
            "a committed record names an operator the same database does not hold"
        )

    def test_the_operator_roster_comes_from_the_ledger_file_itself(
        self, committed_db, tmp_path: Path
    ) -> None:
        """``load_known_actors`` reads the roster the same way it reads the records.

        Two properties matter and neither is obvious. A database with no ``users``
        table must yield ``set()`` rather than raising — that is an older ledger,
        not a corrupt one. And the read must be read-only, because a verifier that
        can write to the evidence is not a verifier.
        """
        db_path, _committed = committed_db
        from tests.conftest import TEST_OPERATOR

        assert TEST_OPERATOR in verify.load_known_actors(db_path)

        bare = tmp_path / "no-users.db"
        conn = sqlite3.connect(bare)
        try:
            conn.execute("CREATE TABLE audit_records (seq INTEGER)")
            conn.commit()
        finally:
            conn.close()
        assert verify.load_known_actors(bare) == set()

        before = db_path.read_bytes()
        verify.load_known_actors(db_path)
        assert db_path.read_bytes() == before

    def test_it_agrees_with_the_writers_own_verifier(self, committed_db, pub_key: bytes) -> None:
        """Same verdicts from both implementations, per record and per link.

        This is the assertion the old module would have failed the moment
        ``audit_records`` gained a column.
        """
        db_path, _committed = committed_db
        records, findings = verify.load_sqlite(db_path)
        actors = verify.load_known_actors(db_path)

        _ok, standalone = verify.verify_chain_standalone(records, findings, pub_key, actors)
        parsed = [
            dict(r, summary=json.loads(r["summary"]) if isinstance(r["summary"], str) else r["summary"])
            for r in records
        ]
        internal = chain.verify_chain(parsed, findings, actors)

        links = (
            "hash_valid",
            "chain_valid",
            "signature_valid",
            "merkle_valid",
            "actor_valid",
            "actor",
            "all_valid",
        )
        for mine, theirs in zip(standalone, internal, strict=True):
            assert mine["seq"] == theirs["seq"]
            assert {k: mine[k] for k in links} == {k: theirs[k] for k in links}

    def test_the_two_implementations_agree_on_an_unknown_actor(
        self, committed_db, pub_key: bytes
    ) -> None:
        """The divergence the tri-state invites, pinned.

        ``verify_chain`` and ``verify_chain_standalone`` decide independently what
        an empty roster means, and if one reads it as "unchecked" while the other
        reads it as "unknown operator", ``/audit/verify`` and the offline verifier
        report different things about the same file. That is worse than either
        answer, because the operator cannot tell which one to believe.
        """
        db_path, _committed = committed_db
        records, findings = verify.load_sqlite(db_path)
        parsed = [
            dict(r, summary=json.loads(r["summary"]) if isinstance(r["summary"], str) else r["summary"])
            for r in records
        ]

        for roster in (None, set(), {"nobody-here"}):
            _ok, standalone = verify.verify_chain_standalone(
                records, findings, pub_key, roster
            )
            internal = chain.verify_chain(parsed, findings, roster)
            assert [r["actor_valid"] for r in standalone] == [
                r["actor_valid"] for r in internal
            ], f"the two verifiers disagree about actor_valid for roster {roster!r}"

    def test_an_update_straight_to_sqlite_is_caught(self, committed_db, pub_key: bytes) -> None:
        """What an attacker with file access actually does.

        Flipping a FAIL to a PASS in the findings table leaves the ledger row
        untouched, so three of the four links still verify. The Merkle root is the
        only thing standing between that edit and a clean report — which is why
        the previous verifier, that omitted it, could not make the ledger's
        central claim.
        """
        db_path, _committed = committed_db

        conn = sqlite3.connect(db_path)
        try:
            altered = conn.execute(
                "UPDATE findings SET result = 'pass' WHERE result = 'fail'"
            ).rowcount
            conn.commit()
        finally:
            conn.close()
        assert altered > 0, "the fixture produced no FAIL to flip"

        records, findings = verify.load_sqlite(db_path)
        actors = verify.load_known_actors(db_path)
        ok, results = verify.verify_chain_standalone(records, findings, pub_key, actors)
        assert ok is False
        assert all(r["merkle_valid"] is False for r in results)
        assert all(r["hash_valid"] is True for r in results)
        assert all(r["signature_valid"] is True for r in results)
        assert all(r["actor_valid"] is True for r in results)

    def test_no_credential_reaches_the_verifier_surface(self, committed_db, pub_key: bytes) -> None:
        """The fixture's community string must not be in what we read back.

        Redaction runs on ingest, so this is a check on the *storage* boundary
        rather than on the response — an offline verifier reads the findings
        table directly, including every ``evidence`` entry's raw provenance line.
        """
        db_path, _committed = committed_db
        _records, findings = verify.load_sqlite(db_path)
        blob = json.dumps(findings)
        assert "S3cretC0mmunity" not in blob

    def test_the_cli_exit_codes_distinguish_broken_from_unchecked(
        self, committed_db, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """0 verified, 1 broken, 2 incomplete, 3 unreadable — all four reachable."""
        db_path, _committed = committed_db
        from backend.ledger.chain import VERIFY_KEY_PATH

        assert verify.main([str(db_path), str(VERIFY_KEY_PATH)]) == verify.EXIT_VERIFIED

        missing_key = tmp_path / "absent.pub"
        assert verify.main([str(db_path), str(missing_key)]) == verify.EXIT_INCOMPLETE

        assert verify.main([str(tmp_path / "nope.db")]) == verify.EXIT_UNREADABLE

        conn = sqlite3.connect(db_path)
        try:
            # Play the attacker who holds the file. The append-only triggers would
            # abort this UPDATE, so drop them first — which is precisely the threat
            # model the hash chain exists for: anyone able to write to the database
            # can also disarm its triggers, and the chain must still catch them.
            # If this DROP ever stops being necessary, the triggers have gone
            # missing from init_database and the storage-layer guard is gone.
            drop_append_only_triggers(conn)
            conn.execute("UPDATE audit_records SET config_hash = 'sha256:tampered'")
            conn.commit()
        finally:
            conn.close()
        assert verify.main([str(db_path), str(VERIFY_KEY_PATH)]) == verify.EXIT_INVALID
        assert "FAILED" in capsys.readouterr().out


class TestJsonInput:
    """The CLI's ``findings.json`` must be independently verifiable.

    ``backend/cli.py`` writes an offline audit with a Merkle root over its
    findings. If the emitted JSON cannot be checked against that root, the record
    it embeds is decoration. This is also the regression test for the CLI's
    ``model_dump()`` → ``model_dump(mode="json")`` fix: a bare dump left the
    enums as objects, so the committed root was over ``"Result.PASS"`` and no
    reader of the file could reproduce it.

    The roster is passed explicitly in both tests below because a JSON export
    genuinely does not contain one — ``main()`` says so in as many words and
    returns ``EXIT_INCOMPLETE``. A reader who has the deployment's operator list
    can close that gap; a reader who does not cannot, and the verifier must not
    pretend otherwise.
    """

    def test_a_cli_report_verifies(self, tmp_path: Path, pub_key: bytes) -> None:
        record = _sample_record()
        payload = {
            "device": {"device_id": "rtr-01"},
            "findings": SAMPLE_FINDINGS,
            "summary": record["summary"],
            "source_file": "rtr-01.conf",
            "audit_record": {k: v for k, v in record.items() if k != "findings"},
        }
        path = tmp_path / "findings.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        records, findings = verify.load_json(path)
        assert records[0]["actor"] == SAMPLE_ACTOR, (
            "the emitted record carries no actor, so the offline door commits "
            "audits nobody can be held to"
        )
        ok, results = verify.verify_chain_standalone(
            records, findings, pub_key, KNOWN_ACTORS
        )
        assert len(records) == 1
        assert ok is True, results[0]["detail"]

    def test_a_list_of_records_verifies(self, tmp_path: Path, pub_key: bytes) -> None:
        first = _sample_record(seq=1)
        second = _sample_record(seq=2, prev_hash=first["record_hash"])
        path = tmp_path / "ledger.json"
        path.write_text(
            json.dumps(
                [
                    dict(first, findings=SAMPLE_FINDINGS),
                    dict(second, findings=SAMPLE_FINDINGS),
                ]
            ),
            encoding="utf-8",
        )
        records, findings = verify.load_json(path)
        ok, _results = verify.verify_chain_standalone(
            records, findings, pub_key, KNOWN_ACTORS
        )
        assert ok is True

    def test_a_json_export_alone_is_reported_as_incomplete(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Exit 2, and the reason printed — not exit 0 with a silent gap.

        A JSON export is a file, not a deployment: it carries the findings and the
        record but nothing that says which operators ever existed. Returning
        "verified" here would make the fifth check meaningless for the one input
        where it cannot be performed.
        """
        record = _sample_record()
        path = tmp_path / "ledger.json"
        path.write_text(
            json.dumps([dict(record, findings=SAMPLE_FINDINGS)]), encoding="utf-8"
        )
        from backend.ledger.chain import VERIFY_KEY_PATH, generate_signing_keys

        if not VERIFY_KEY_PATH.exists():
            generate_signing_keys()

        assert verify.main([str(path), str(VERIFY_KEY_PATH)]) == verify.EXIT_INCOMPLETE
        out = capsys.readouterr().out
        assert "actors NOT resolved" in out
        assert "INCOMPLETE" in out

    def test_an_unreadable_shape_is_named(self, tmp_path: Path) -> None:
        path = tmp_path / "wrong.json"
        path.write_text('"just a string"', encoding="utf-8")
        with pytest.raises(verify.LedgerFormatError):
            verify.load_json(path)


class TestSqliteInput:
    def test_a_database_without_an_audit_records_table_is_named(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.db"
        sqlite3.connect(path).close()
        with pytest.raises(verify.LedgerFormatError, match="no audit_records table"):
            verify.load_sqlite(path)

    def test_a_missing_findings_table_leaves_the_root_unchecked(self, tmp_path: Path) -> None:
        """``{}`` would claim every audit committed zero findings.

        And zero findings has a *valid* Merkle root — the empty preimage — so the
        wrong answer here is not "unknown", it is "verified".
        """
        path = tmp_path / "records-only.db"
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                "CREATE TABLE audit_records (audit_id TEXT, device_id TEXT, "
                "config_hash TEXT, created_at TEXT, actor TEXT, summary TEXT, "
                "seq INTEGER, prev_hash TEXT, record_hash TEXT, merkle_root TEXT, "
                "signature TEXT)"
            )
            record = _sample_record()
            conn.execute(
                "INSERT INTO audit_records VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record["audit_id"], record["device_id"], record["config_hash"],
                    record["created_at"], record["actor"], json.dumps(record["summary"]),
                    record["seq"], record["prev_hash"], record["record_hash"],
                    record["merkle_root"], record["signature"],
                ),
            )
            conn.commit()
        finally:
            conn.close()

        records, findings = verify.load_sqlite(path)
        assert findings == {}
        _ok, results = verify.verify_chain_standalone(
            records, findings or None, None, KNOWN_ACTORS
        )
        assert results[0]["merkle_valid"] is None
        assert results[0]["all_valid"] is False

    def test_the_database_is_opened_read_only(self, tmp_path: Path) -> None:
        """A verifier must not be able to modify the evidence it is examining."""
        path = tmp_path / "ro.db"
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE audit_records (seq INTEGER)")
            conn.commit()
        finally:
            conn.close()

        source = Path(verify.__file__).read_text(encoding="utf-8")
        assert "mode=ro" in source

        before = path.read_bytes()
        verify.load_sqlite(path)
        assert path.read_bytes() == before
