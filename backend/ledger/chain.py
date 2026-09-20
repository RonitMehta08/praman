"""Tamper-evident ledger — hash chain + Merkle root + Ed25519 signing.

The ledger's claim is that an audit cannot be altered after the fact without the
alteration being detectable. That claim rests on a chain with four links:

    findings → merkle_root → record_hash → signature

and, across records, ``record_hash`` → the next record's ``prev_hash``, which
binds the records into an order. A verifier that checks three of those links
proves nothing about the fourth, so :func:`verify_chain` checks all four and
says explicitly when it could not.

There is a fifth check that is not a link in that chain. ``actor`` — the operator
who committed the audit — is a hashed field, so the chain already protects it
from being *edited*; what the chain cannot say is whether the name means
anything. ``actor_valid`` resolves it against the deployment's operator list, and
so catches a record committed under an identity that was never issued, and an
empty actor left behind by a build that predates identity.

Dependencies:
  - cryptography >= 50.0.0 (Ed25519)

The Merkle root is computed in-repo and deliberately depends on nothing
optional — see :func:`compute_merkle_root`. ``pymerkle`` is still in the
lockfile; nothing imports it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.app.config import DATA_DIR
from backend.core_errors import LedgerIntegrityError

# --- Key paths ---
KEYS_DIR = DATA_DIR / "private"
SIGNING_KEY_PATH = KEYS_DIR / "ed25519_signing.key"
VERIFY_KEY_PATH = KEYS_DIR / "ed25519_verify.pub"

#: The fields the record hash covers.
#:
#: Hashing an explicit list, rather than whatever keys the caller's dict happens
#: to carry, is the whole fix for a defect that made this module's central claim
#: false. The commit path passed a dict that also held the full findings list; the
#: verifier read a row back from SQLite, where findings live in their own table
#: and cannot be a column; so the two hashed different inputs and *every* record
#: in the ledger failed its own integrity check — 13 of 13 on the development
#: database. A check that fails on healthy data cannot detect unhealthy data: a
#: genuinely altered record looked exactly like a sound one.
#:
#: ``findings`` is deliberately absent. The findings are committed by
#: ``merkle_root``, which *is* in this list, so they are covered transitively —
#: and unlike the findings list, ``merkle_root`` is a column in the ledger row, so
#: the hash can still be recomputed from the row alone. That is what makes
#: offline verification possible at all.
#:
#: ``actor`` is present for the mirror-image reason. Identity has to be *inside*
#: the hash or it is not evidence: a name in a side table can be edited without
#: breaking anything, so a ledger carrying it there would prove what was decided
#: and merely assert who decided it. Adding it changed this tuple, which changed
#: every record's hash — which is what ``MANUAL_COMMANDS.md`` Step 12 and
#: ``scripts/reset_ledger.py`` exist for, and why identity was added in the same
#: change as authentication rather than after it.
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


def compute_record_hash(record_data: dict[str, Any]) -> str:
    """sha256 over the ledger row's canonical JSON.

    Only :data:`RECORD_HASH_FIELDS` contribute; extra keys are ignored rather
    than folded in, so the commit path and the verifier cannot disagree about a
    record's hash merely because one of them has the findings in hand and the
    other does not.

    ``summary`` is normalised before hashing. SQLite stores it as a JSON string
    and the commit path holds it as a dict, and those two canonicalise
    differently — a second way for the same record to hash to two values.

    Args:
        record_data: An audit record, or a row read back from ``audit_records``.

    Returns:
        Hex sha256 of the canonical JSON (sorted keys, no whitespace).

    Raises:
        LedgerIntegrityError: If a hashed field is absent, or if ``summary`` holds
            text that is not JSON. A hash computed over a missing field is not a
            weaker hash, it is a *different* one, and returning it silently is how
            this function came to disagree with itself in the first place.
    """
    missing = [name for name in RECORD_HASH_FIELDS if name not in record_data]
    if missing:
        raise LedgerIntegrityError(
            "cannot hash an audit record without " + ", ".join(missing)
        )
    hashable: dict[str, Any] = {name: record_data[name] for name in RECORD_HASH_FIELDS}
    if isinstance(hashable["summary"], str):
        try:
            hashable["summary"] = json.loads(hashable["summary"] or "{}")
        except json.JSONDecodeError as exc:
            # Raised, not propagated as a JSONDecodeError, because the caller is
            # a verifier: an unparseable summary column is a finding about the
            # record, not a bug in the verifier. Letting the decode error escape
            # turns "this record was tampered with" into a 500 from
            # ``/audit/verify``, which reports nothing about the other records.
            raise LedgerIntegrityError(
                f"the summary field is not JSON ({exc.msg})"
            ) from exc
    canonical_json = json.dumps(hashable, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


#: Domain-separation tags for the Merkle tree, and the empty-tree preimage.
#:
#: A leaf and an internal node must be drawn from different spaces. Without a
#: tag they are both "sha256 of some bytes", and a root cannot distinguish *these
#: two findings* from *this one finding whose text happens to be two
#: concatenated digests*. One byte fixes it (RFC 6962 §2.1).
_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"
_EMPTY_MERKLE_PREIMAGE = b"praman.merkle.empty.v1"


def compute_merkle_root(findings: list[dict[str, Any]]) -> str:
    """Merkle root over the findings — the link that commits the verdicts.

    The definition lives here and nowhere else, because it is a *hash
    definition*: a root that depends on which optional packages happen to be
    importable is not a commitment, it is a coincidence. This function used to
    try ``from pymerkle import MerkleTree`` and fall back to an in-repo tree on
    ``ImportError``. pymerkle 6.1.0 — the pinned version — has no ``MerkleTree``
    symbol at all; it is ``InmemoryTree`` since v6. So the import always failed,
    the fallback always ran, every root in the ledger is the in-repo one, and
    three docstrings described a code path that has never executed. Worse, the
    ``except ImportError`` catches a *missing symbol* as readily as a missing
    package, so an environment that did supply a ``MerkleTree`` would have
    silently changed the root definition partway through an append-only ledger.
    The branch is gone; the in-repo tree is the definition.

    Two details are not the obvious choices, and both are deliberate:

    * Leaves are tagged ``0x00`` and internal nodes ``0x01`` — see
      :data:`_LEAF_TAG`.
    * An unpaired node at the end of a level is **promoted** to the next level
      unchanged, not duplicated. Duplicating it, which the previous version did,
      makes ``[a, b, c]`` and ``[a, b, c, c]`` hash to the same root — so a
      duplicate of the final finding could be appended to a committed audit
      without invalidating the ledger. That is the whole point of the structure,
      and it was the one property it did not have.

    ``json.dumps`` is called without ``default=str`` on purpose. A hash
    definition that silently stringifies whatever it cannot serialise lets two
    callers agree by accident: ``Result.PASS`` and ``"pass"`` are the same audit
    to a reader and different bytes to sha256. Callers pass
    ``model_dump(mode="json")``, whose output is JSON-native, so anything that
    raises here is a caller that would otherwise have committed an unreproducible
    root.

    Args:
        findings: Finding dicts, in the order they were produced. Not mutated.

    Returns:
        Hex sha256 of the tree root, or of :data:`_EMPTY_MERKLE_PREIMAGE` when
        there are no findings.
    """
    if not findings:
        return hashlib.sha256(_EMPTY_MERKLE_PREIMAGE).hexdigest()

    level = [
        hashlib.sha256(
            _LEAF_TAG
            + json.dumps(f, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).digest()
        for f in findings
    ]
    while len(level) > 1:
        level = [
            hashlib.sha256(_NODE_TAG + level[i] + level[i + 1]).digest()
            if i + 1 < len(level)
            else level[i]
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def generate_signing_keys() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 key pair and save to disk.

    Returns (private_key_bytes, public_key_bytes).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    SIGNING_KEY_PATH.write_bytes(private_bytes)
    VERIFY_KEY_PATH.write_bytes(public_bytes)

    return private_bytes, public_bytes


def sign_record(record_hash: str) -> str:
    """Sign a record_hash using the Ed25519 private key.

    Returns the hex-encoded signature.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if not SIGNING_KEY_PATH.exists():
        generate_signing_keys()

    key_bytes = SIGNING_KEY_PATH.read_bytes()
    private_key = load_pem_private_key(key_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise LedgerIntegrityError("Signing key is not Ed25519")

    signature = private_key.sign(record_hash.encode("utf-8"))
    return signature.hex()


def verify_signature(record_hash: str, signature_hex: str) -> bool:
    """Verify an Ed25519 signature against a record_hash.

    Returns True if valid, False otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    if not VERIFY_KEY_PATH.exists():
        return False

    key_bytes = VERIFY_KEY_PATH.read_bytes()
    public_key = load_pem_public_key(key_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        return False

    try:
        public_key.verify(bytes.fromhex(signature_hex), record_hash.encode("utf-8"))
        return True
    except Exception:
        return False


def verify_chain(
    records: list[dict[str, Any]],
    findings_by_audit: dict[str, list[dict[str, Any]]] | None = None,
    known_actors: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Verify every link in the ledger's integrity chain.

    Five things are checked per record, and each one can fail on its own:

    * ``merkle_valid`` — the findings hash to the committed ``merkle_root``. This
      is the only link that covers the *content* of the audit; without it an
      altered verdict is invisible, because the verdicts are not in the record
      hash directly.
    * ``hash_valid`` — the record's own fields hash to the stored
      ``record_hash``. Catches an altered summary, timestamp, device id or actor.
    * ``chain_valid`` — ``prev_hash`` matches the previous record's hash. Catches
      a removed, reordered or spliced record.
    * ``signature_valid`` — the Ed25519 signature over the record hash verifies.
      Catches a record forged wholesale by someone without the key.
    * ``actor_valid`` — the recorded ``actor`` is a principal this deployment
      knows. Catches a record committed under an identity that was never issued,
      and an empty actor left by a build that predates identity.

    Args:
        records: Ledger rows, oldest first, ``summary`` already parsed to a dict.
        findings_by_audit: The findings behind each record, keyed by ``audit_id``.
            Omit it and ``merkle_valid`` is reported as ``None`` — *not* as True.
            An unchecked link reported as sound is precisely the failure this
            module exists to prevent, so ``None`` also keeps ``all_valid`` from
            claiming more than was checked.
        known_actors: Every principal name the deployment recognises, disabled
            ones included. Omit it — or pass an empty set, which is what a
            database with no ``users`` table yields — and ``actor_valid`` is
            ``None`` on the same terms.

    Returns:
        One dict per record: ``seq``, ``record_hash``, the five flags,
        ``all_valid``, and a ``detail`` sentence naming what is wrong.
    """
    results = []

    for i, record in enumerate(records):
        stored_hash = record["record_hash"]
        stored_prev = record["prev_hash"]

        try:
            hash_valid = compute_record_hash(record) == stored_hash
            hash_note = ""
        except LedgerIntegrityError as exc:
            hash_valid = False
            hash_note = str(exc)

        chain_valid = (
            stored_prev == "" if i == 0 else stored_prev == records[i - 1]["record_hash"]
        )
        signature_valid = verify_signature(stored_hash, record["signature"])

        merkle_valid: bool | None = None
        if findings_by_audit is not None:
            findings = findings_by_audit.get(record["audit_id"], [])
            merkle_valid = compute_merkle_root(findings) == record["merkle_root"]

        actor = record.get("actor", "")
        actor_valid: bool | None = None
        if known_actors:
            # Truthiness, not ``is not None``: an empty set is what a database with
            # no ``users`` table yields, and treating that as "nobody is known"
            # would report every record as committed by an unknown operator. It
            # also keeps this function's answer identical to the standalone
            # verifier's, which is checked by tests/test_ledger_standalone_verify.py.
            actor_valid = bool(actor) and actor in known_actors

        checked = [hash_valid, chain_valid, signature_valid]
        if merkle_valid is not None:
            checked.append(merkle_valid)
        if actor_valid is not None:
            checked.append(actor_valid)

        results.append(
            {
                "seq": record["seq"],
                "record_hash": stored_hash,
                "hash_valid": hash_valid,
                "chain_valid": chain_valid,
                "signature_valid": signature_valid,
                "merkle_valid": merkle_valid,
                "actor_valid": actor_valid,
                "actor": actor,
                "all_valid": all(checked),
                "detail": _verification_detail(
                    hash_valid=hash_valid,
                    chain_valid=chain_valid,
                    signature_valid=signature_valid,
                    merkle_valid=merkle_valid,
                    actor_valid=actor_valid,
                    actor=actor,
                    hash_note=hash_note,
                    is_genesis=i == 0,
                ),
            }
        )

    return results


def _verification_detail(
    *,
    hash_valid: bool,
    chain_valid: bool,
    signature_valid: bool,
    merkle_valid: bool | None,
    actor_valid: bool | None,
    actor: str,
    hash_note: str,
    is_genesis: bool,
) -> str:
    """One sentence naming what failed, in the order a reader should care about.

    A red cross with no explanation sends an operator to the source code. Each
    branch says which link broke and what that implies about the ledger, because
    "chain_valid is false" and "a record was removed from the ledger" are the
    same fact told to two different audiences.
    """
    if not chain_valid:
        return (
            "prev_hash is not empty on the genesis record, so the ledger does not "
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
        if hash_note:
            return f"{hash_note}, so the record hash could not be recomputed"
        return (
            "the stored record hash is not the hash of this record's fields: a "
            "hashed field was altered after the audit was committed, or the "
            "record predates the current hash definition"
        )
    if not signature_valid:
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
    # Each unchecked link names the *input* that was missing, not just the flag.
    # "merkle_root was not checked" tells the reader which box is grey; "the
    # findings were not supplied" tells them what to pass to turn it green.
    unchecked = [
        reason
        for reason, value in (
            (
                "the findings were not supplied, so merkle_root was not recomputed",
                merkle_valid,
            ),
            (
                "no operator roster was supplied, so the actor was not resolved",
                actor_valid,
            ),
        )
        if value is None
    ]
    if unchecked:
        return "the ledger row verifies, but " + "; and ".join(unchecked)
    return (
        "all five links verify: findings, record hash, chain link, signature and actor"
    )
