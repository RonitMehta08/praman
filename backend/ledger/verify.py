"""Standalone offline ledger verifier.

This module imports NOTHING from ``backend/`` (GLOBAL_RULESET §8). A third party
can verify the audit chain without trusting our code, which is the entire point:
a verifier that calls into the thing it is verifying proves only that the thing
agrees with itself.

    python -m backend.ledger.verify data/praman.db
    python -m backend.ledger.verify out/audit/findings.json

Why this file is not a thin wrapper
-----------------------------------
The independence has a cost that has to be paid explicitly. Every constant below
is a *hand copy* of one in ``backend/``, so this module can drift from the code
that writes the ledger and start reporting healthy records as tampered with —
which is worse than no verifier, because it teaches the operator to ignore it.
``tests/test_ledger_standalone_verify.py`` imports both sides and asserts they
agree, so the drift fails a test instead of a demo.

It had already drifted. The previous version hashed *every* column of the row
except ``record_hash`` and ``signature``, while the writer hashes an explicit
nine-field list. Those two happened to coincide, because ``audit_records``
happened to have exactly those other columns — so the verifier was correct by
accident, and one added column would have silently broken it. That prediction has
since been paid off: ``actor`` was added, and it landed in both lists because both
are explicit. It also checked three of the four links, omitting the Merkle root:
the only link that covers the *verdicts*. A ledger can pass a three-link check
with every pass/fail in it rewritten.

What it reports, and what it refuses to claim
---------------------------------------------
Four independent links, and ``None`` — never ``True`` — for one it could not
check::

    findings → merkle_root → record_hash → signature

plus a fifth check that is not a link in that chain: ``actor_valid`` asks whether
the hashed operator name resolves to somebody this deployment issued. The chain
already stops an actor being *edited*; only the operator list can say the name
means anything, and a record committed as ``""`` — by a build from before
identity existed — is not a signed statement about who did anything.

A missing public key means the signature is *unchecked*, not valid. An absent
findings table means the Merkle root is *unrecomputed*, not sound. An absent
``users`` table means the actor is *unresolved*, not bogus. The exit code
is 0 only when every link of every record was checked and passed; a ledger whose
records verify but whose signatures could not be checked exits 2, so a CI job
cannot mistake "we did not look" for "we looked and it was fine".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

# --- Hand copies of the writer's definitions. Guarded by a test. ---

#: Mirrors ``backend.ledger.chain.RECORD_HASH_FIELDS``.
#:
#: ``findings`` is absent on purpose: they are committed by ``merkle_root``,
#: which is a column, so the record hash stays recomputable from the row alone.
#: ``actor`` is present on purpose: identity that is not hashed is not evidence.
RECORD_HASH_FIELDS = (
    "actor",
    "audit_id",
    "config_hash",
    "created_at",
    "device_id",
    "merkle_root",
    "prev_hash",
    "seq",
    "summary",
)

#: Mirrors ``backend.db.connection.FINDING_FIELDS`` — the projection the Merkle
#: root was computed over. Order is irrelevant (the JSON is key-sorted); the
#: *set* is not. Keeping the table's own ``id``/``audit_id``/``device_id``
#: columns, or leaving a JSON column as text, yields a different root.
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

#: Mirrors ``backend.db.connection._FINDING_JSON_COLUMNS``.
FINDING_JSON_COLUMNS = {"evidence": "[]", "references": "{}"}

#: Mirrors the tags and empty-tree preimage in ``backend.ledger.chain``.
LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
EMPTY_MERKLE_PREIMAGE = b"praman.merkle.empty.v1"

#: Default location of the published verification key, relative to the ledger.
DEFAULT_PUB_KEY_RELATIVE = Path("private") / "ed25519_verify.pub"


class LedgerFormatError(Exception):
    """The input is not a ledger this verifier can read."""


# --- Hashing ---------------------------------------------------------------


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_record_hash(record: dict[str, Any]) -> str:
    """sha256 over :data:`RECORD_HASH_FIELDS` of one ledger row.

    Raises:
        LedgerFormatError: If a hashed field is absent, or ``summary`` is not
            JSON. A hash over a missing field is not a weaker hash, it is a
            different one, and returning it silently would report every record as
            tampered with for a reason that has nothing to do with tampering.
    """
    missing = [name for name in RECORD_HASH_FIELDS if name not in record]
    if missing:
        raise LedgerFormatError(
            "record is missing hashed field(s): " + ", ".join(missing)
        )
    hashable = {name: record[name] for name in RECORD_HASH_FIELDS}
    if isinstance(hashable["summary"], str):
        try:
            hashable["summary"] = json.loads(hashable["summary"] or "{}")
        except json.JSONDecodeError as exc:
            raise LedgerFormatError(f"summary is not JSON ({exc.msg})") from exc
    return hashlib.sha256(_canonical_json(hashable)).hexdigest()


def compute_merkle_root(findings: list[dict[str, Any]]) -> str:
    """Merkle root over the findings, tagged leaves and promoted odd nodes.

    See ``backend.ledger.chain.compute_merkle_root`` for why the tags and the
    promotion are there rather than the textbook duplicate-the-last-leaf.
    """
    if not findings:
        return hashlib.sha256(EMPTY_MERKLE_PREIMAGE).hexdigest()

    level = [hashlib.sha256(LEAF_TAG + _canonical_json(f)).digest() for f in findings]
    while len(level) > 1:
        level = [
            hashlib.sha256(NODE_TAG + level[i] + level[i + 1]).digest()
            if i + 1 < len(level)
            else level[i]
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def project_finding(row: dict[str, Any]) -> dict[str, Any]:
    """A findings row as the dict the Merkle root was computed over."""
    projected: dict[str, Any] = {}
    for name in FINDING_FIELDS:
        value = row.get(name)
        if name in FINDING_JSON_COLUMNS:
            if isinstance(value, str):
                value = json.loads(value or FINDING_JSON_COLUMNS[name])
            elif value is None:
                value = json.loads(FINDING_JSON_COLUMNS[name])
        projected[name] = value
    return projected


def _verify_ed25519(record_hash: str, signature_hex: str, pub_key: bytes) -> bool:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        load_pem_public_key(pub_key).verify(
            bytes.fromhex(signature_hex), record_hash.encode("utf-8")
        )
        return True
    except Exception:
        # Deliberately broad: a malformed signature, a wrong key and a bad
        # signature are all "this does not verify" to a verifier. The distinction
        # that matters — *not checked* — is carried by pub_key being None, one
        # level up, and never reaches here.
        return False


# --- Verification ---------------------------------------------------------


def verify_chain_standalone(
    records: list[dict[str, Any]],
    findings_by_audit: dict[str, list[dict[str, Any]]] | None = None,
    pub_key: bytes | None = None,
    known_actors: set[str] | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Verify every link of every record.

    Args:
        records: Ledger rows, oldest first. ``summary`` may be a dict or the raw
            JSON text SQLite stores.
        findings_by_audit: Projected findings keyed by ``audit_id``. Omit and
            ``merkle_valid`` is ``None``.
        pub_key: PEM bytes of the published verification key. Omit and
            ``signature_valid`` is ``None``.
        known_actors: Every operator name the deployment issued, disabled ones
            included. Omit — or pass an empty set, which is what a ledger with no
            ``users`` table yields — and ``actor_valid`` is ``None``.

    Returns:
        ``(fully_verified, results)``. ``fully_verified`` is True only when every
        link of every record was *checked* and passed — an unchecked link makes it
        False, because the caller asked whether the ledger is sound and the honest
        answer to "I did not look" is not yes.
    """
    results: list[dict[str, Any]] = []

    for i, record in enumerate(records):
        stored_hash = record.get("record_hash", "")
        stored_prev = record.get("prev_hash", "")

        try:
            hash_valid: bool = compute_record_hash(record) == stored_hash
            note = ""
        except LedgerFormatError as exc:
            hash_valid = False
            note = str(exc)

        if i == 0:
            chain_valid = stored_prev == ""
        else:
            chain_valid = stored_prev == records[i - 1].get("record_hash", "")

        signature_valid: bool | None = None
        if pub_key is not None:
            signature_valid = _verify_ed25519(
                stored_hash, record.get("signature", ""), pub_key
            )

        merkle_valid: bool | None = None
        if findings_by_audit is not None:
            found = findings_by_audit.get(record.get("audit_id", ""), [])
            merkle_valid = compute_merkle_root(found) == record.get("merkle_root", "")

        actor = record.get("actor", "") or ""
        actor_valid: bool | None = None
        if known_actors:
            # Bool first: an empty actor is a record from before identity
            # existed, and reporting that as "unknown operator" would send the
            # reader looking for a person who was never there.
            actor_valid = bool(actor) and actor in known_actors

        links = [hash_valid, chain_valid, signature_valid, merkle_valid, actor_valid]
        results.append(
            {
                "seq": record.get("seq", -1),
                "record_hash": stored_hash,
                "hash_valid": hash_valid,
                "chain_valid": chain_valid,
                "signature_valid": signature_valid,
                "merkle_valid": merkle_valid,
                "actor_valid": actor_valid,
                "actor": actor,
                "all_valid": all(link is True for link in links),
                "detail": _detail(
                    hash_valid=hash_valid,
                    chain_valid=chain_valid,
                    signature_valid=signature_valid,
                    merkle_valid=merkle_valid,
                    actor_valid=actor_valid,
                    actor=actor,
                    note=note,
                    is_genesis=i == 0,
                ),
            }
        )

    fully_verified = all(r["all_valid"] for r in results) if results else False
    return fully_verified, results


def _detail(
    *,
    hash_valid: bool,
    chain_valid: bool,
    signature_valid: bool | None,
    merkle_valid: bool | None,
    actor_valid: bool | None,
    actor: str,
    note: str,
    is_genesis: bool,
) -> str:
    """One sentence naming what broke, in the order a reader should care."""
    if not chain_valid:
        return (
            "prev_hash is not empty on the first record, so the ledger does not "
            "begin where it claims to"
            if is_genesis
            else "prev_hash does not match the preceding record: the ledger has "
            "been reordered, or a record between them was removed"
        )
    if merkle_valid is False:
        return (
            "the findings do not hash to the committed Merkle root: a verdict has "
            "been altered, added or removed since this audit was committed"
        )
    if not hash_valid:
        if note:
            return f"{note}, so the record hash could not be recomputed"
        return (
            "the stored record hash is not the hash of this record's fields: a "
            "hashed field was altered after the audit was committed, or the "
            "record predates the current hash definition"
        )
    if signature_valid is False:
        return (
            "the Ed25519 signature over the record hash does not verify against "
            "the published public key"
        )
    if actor_valid is False:
        return (
            "the record names no actor, so it predates operator identity — "
            "re-seed the ledger (MANUAL_COMMANDS.md Step 12)"
            if not actor
            else f"the record was committed by '{actor}', who is not an operator "
            "this deployment ever issued"
        )
    unchecked = [
        name
        for name, value in (
            ("merkle_root", merkle_valid),
            ("signature", signature_valid),
            ("actor", actor_valid),
        )
        if value is None
    ]
    if unchecked:
        return (
            "the ledger row is internally consistent; "
            + " and ".join(unchecked)
            + (" was" if len(unchecked) == 1 else " were")
            + " not checked, so this record is not fully verified"
        )
    return (
        "all five links verify: findings, record hash, chain link, signature and actor"
    )


# --- Input ---------------------------------------------------------------


def load_sqlite(path: Path) -> tuple[list[dict], dict[str, list[dict]]]:
    """Read records and their projected findings from a PRAMAN database."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute("SELECT * FROM audit_records ORDER BY seq").fetchall()
        except sqlite3.OperationalError as exc:
            raise LedgerFormatError(f"no audit_records table in {path} ({exc})") from exc
        records = [dict(r) for r in rows]

        findings_by_audit: dict[str, list[dict]] = {}
        try:
            finding_rows = conn.execute(
                "SELECT * FROM findings ORDER BY audit_id, id"
            ).fetchall()
        except sqlite3.OperationalError:
            # No findings table: the Merkle root stays unrecomputed and every
            # record reports merkle_valid=None. Returning {} instead would claim
            # every audit committed zero findings.
            return records, {}
        for row in finding_rows:
            item = dict(row)
            findings_by_audit.setdefault(item.get("audit_id", ""), []).append(
                project_finding(item)
            )
        return records, findings_by_audit
    finally:
        conn.close()


def load_known_actors(path: Path) -> set[str]:
    """Every operator name a PRAMAN database has issued, disabled ones included.

    Returns an empty set when there is no ``users`` table — a ledger from a build
    that predates identity, or a bare export. The caller turns that into
    ``actor_valid=None``: "there is nobody to check against" is not the same
    finding as "this actor is unknown", and conflating them would paint an old but
    otherwise sound ledger entirely red.

    Disabled operators are included deliberately. Their audits are still valid
    audits; an audit trail that degrades when staff leave is not an audit trail.
    """
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        try:
            rows = conn.execute("SELECT username FROM users").fetchall()
        except sqlite3.OperationalError:
            return set()
        return {row[0] for row in rows}
    finally:
        conn.close()


def load_json(path: Path) -> tuple[list[dict], dict[str, list[dict]]]:
    """Read a ledger from JSON.

    Three shapes are accepted, because three things in this project emit one:
    a list of records; a single record dict; and the ``findings.json`` the CLI
    writes, which holds the row under ``audit_record`` and the findings beside it.
    """
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, list):
        records = payload
        findings_by_audit = {
            r["audit_id"]: r["findings"]
            for r in records
            if isinstance(r, dict) and "audit_id" in r and "findings" in r
        }
        return records, findings_by_audit or {}

    if not isinstance(payload, dict):
        raise LedgerFormatError(f"{path} is neither a record, a list nor a report")

    if "audit_record" in payload:
        record = dict(payload["audit_record"])
        findings = payload.get("findings")
        by_audit = (
            {record.get("audit_id", ""): findings} if isinstance(findings, list) else {}
        )
        return [record], by_audit

    findings = payload.pop("findings", None)
    by_audit = (
        {payload.get("audit_id", ""): findings} if isinstance(findings, list) else {}
    )
    return [payload], by_audit


def _load_pub_key(explicit: str | None, ledger_path: Path) -> tuple[bytes | None, str]:
    """Return (PEM bytes, note). ``None`` means the signature cannot be checked."""
    if explicit:
        candidate = Path(explicit)
        if not candidate.is_file():
            return None, f"public key not found at {candidate}"
        return candidate.read_bytes(), f"public key: {candidate}"
    candidate = ledger_path.parent / DEFAULT_PUB_KEY_RELATIVE
    if candidate.is_file():
        return candidate.read_bytes(), f"public key: {candidate}"
    return None, (
        f"no public key given and none at {candidate} — signatures NOT checked"
    )


# --- CLI -----------------------------------------------------------------

#: Exit codes, distinct on purpose. See the module docstring.
EXIT_VERIFIED = 0
EXIT_INVALID = 1
EXIT_INCOMPLETE = 2
EXIT_UNREADABLE = 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.ledger.verify",
        description=(
            "Verify a PRAMAN audit ledger offline. Imports nothing from the "
            "application it verifies."
        ),
    )
    parser.add_argument("ledger", help="path to praman.db or a findings/record JSON")
    parser.add_argument(
        "pub_key",
        nargs="?",
        help="Ed25519 public key PEM (default: <ledger dir>/private/ed25519_verify.pub)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the per-record report as JSON"
    )
    args = parser.parse_args(argv)

    path = Path(args.ledger)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return EXIT_UNREADABLE

    try:
        if path.suffix == ".json":
            records, findings_by_audit = load_json(path)
            known_actors: set[str] = set()
            actor_note = (
                "a JSON export carries no operator list — actors NOT resolved"
            )
        else:
            records, findings_by_audit = load_sqlite(path)
            known_actors = load_known_actors(path)
            actor_note = (
                f"operators: {len(known_actors)} known"
                if known_actors
                else "no users table — actors NOT resolved"
            )
    except (LedgerFormatError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return EXIT_UNREADABLE

    pub_key, key_note = _load_pub_key(args.pub_key, path)
    fully_verified, results = verify_chain_standalone(
        records, findings_by_audit or None, pub_key, known_actors or None
    )

    if args.json:
        print(json.dumps({"fully_verified": fully_verified, "records": results}, indent=2))
    else:
        print(f"ledger: {path}")
        print(f"{key_note}")
        print(f"{actor_note}\n")
        if not records:
            print("  the ledger is empty — there is nothing to verify")
        for r in results:
            flag = "OK  " if r["all_valid"] else "FAIL"
            print(
                f"  [{flag}] seq={r['seq']:<4} merkle={_flag(r['merkle_valid'])} "
                f"hash={_flag(r['hash_valid'])} chain={_flag(r['chain_valid'])} "
                f"sig={_flag(r['signature_valid'])} actor={_flag(r['actor_valid'])} "
                f"{r['actor'] or '-'}"
            )
            if not r["all_valid"]:
                print(f"          {r['detail']}")
        print()

    if not records:
        return EXIT_INCOMPLETE
    if any(
        False
        in (
            r["hash_valid"],
            r["chain_valid"],
            r["merkle_valid"],
            r["signature_valid"],
            r["actor_valid"],
        )
        for r in results
    ):
        print(f"FAILED: {len(records)} record(s) read, at least one link is broken.")
        return EXIT_INVALID
    if not fully_verified:
        print(f"INCOMPLETE: {len(records)} record(s) consistent, but not every link was checked.")
        return EXIT_INCOMPLETE
    print(f"VERIFIED: {len(records)} record(s), all five checks, no gaps.")
    return EXIT_VERIFIED


def _flag(value: bool | None) -> str:
    return "?" if value is None else ("y" if value else "n")


if __name__ == "__main__":
    sys.exit(main())
