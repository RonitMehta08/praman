"""Validate PRAMAN's OSCAL and SARIF exports against the publishers' own JSON Schemas.

This is not a pytest test, and the two schema files are the reason. They are
third-party JSON — 152 KB from NIST, 116 KB from OASIS — redistributed under the
publishers' terms, and a copy vendored into this repository would be a claim
about their content that nobody ever re-checks. So they are downloaded
(``MANUAL_COMMANDS.md`` Step 14) and this script is what reads them.

``tests/test_export_oscal.py`` and ``tests/test_export_sarif.py`` do assert
structure, but against the ``required`` lists transcribed out of these schemas.
That catches a missing field. It cannot catch a field whose *value* violates a
``pattern``, an ``enum`` or a ``minimum`` that the transcription left behind —
and the one bug this pair of exporters was most likely to have was exactly that
shape (SARIF's ``region.startLine`` has ``minimum: 1``; PRAMAN's absent-fact
evidence carries ``line_start=0``). So the suite holds the shape and this script
runs every keyword the publisher actually wrote, over four fixtures picked to sit
at opposite ends of the compliance range.

    python scripts/check_export_conformance.py
    python scripts/check_export_conformance.py --schema-dir some/other/dir
    python scripts/check_export_conformance.py --config test_configs/realistic/vlan1_unused.conf

Exit codes are distinct on purpose, because the three failures mean different
things and want different readers:

  0  both documents validate for every config, and re-export is byte-identical
  1  a document is invalid — PRAMAN's exporter is wrong; the printed path says where
  2  a schema file is absent — run Step 14; **nothing was checked**
  3  a schema file is present but is not the pinned one — the *pin* needs review
     before its verdict means anything, so no validation is attempted

Exit 2 and exit 3 are separated from exit 1 because both of them mean "this
script established nothing", and a check that cannot distinguish "passed" from
"did not run" is the failure mode `docs/PRODUCTION-ROADMAP.md` §5.3 was written
about.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.app.services import evaluate_facts, parse_config
from backend.core_errors import ArtifactMissingError
from backend.export import (
    AUDIT_FIELDS,
    OSCAL_AR_SCHEMA_ID,
    OSCAL_AR_SCHEMA_URL,
    SARIF_SCHEMA_URL,
    to_oscal_ar,
    to_sarif,
)
from backend.ingest.decode import normalise


@dataclass(frozen=True)
class SchemaSpec:
    """A publisher's schema file: where it comes from, and how to know it is that one."""

    label: str
    filename: str
    url: str
    sha256: str
    size: int
    #: The ``$id`` the file declares, when it is worth asserting. See the SARIF note.
    declared_id: str | None


class SchemaPinError(Exception):
    """The file on disk is readable but is not the one the pin identifies.

    Its own exception, and its own exit code, because it is neither "the export is
    wrong" nor "the schema is missing" — it is "this script established nothing,
    and the reason is upstream". Collapsing it into either of the others would let
    a re-released schema read as a PRAMAN bug, or as a pass.
    """


#: The exact publisher files this script's verdict was established against.
#:
#: Pinned for the same reason ``scripts/verify_sources.py`` pins catalog digests:
#: "the export validates against the schema" is only a claim if the schema is
#: identified. Both digests and both byte counts were measured on the downloaded
#: files, not read off a release page.
SCHEMAS = (
    SchemaSpec(
        label="OSCAL",
        filename="oscal-ar-1.2.3.json",
        url=OSCAL_AR_SCHEMA_URL,
        sha256="4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c",
        size=152214,
        declared_id=OSCAL_AR_SCHEMA_ID,
    ),
    SchemaSpec(
        label="SARIF",
        filename="sarif-2.1.0.json",
        url=SARIF_SCHEMA_URL,
        sha256="ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25",
        size=115632,
        # Deliberately not asserted. The file OASIS serves from docs.oasis-open.org
        # declares `$id` as the raw.githubusercontent.com copy, so it does not match
        # the URL it was fetched from. That is upstream's inconsistency, not a wrong
        # download — the digest above is what identifies this file.
        declared_id=None,
    ),
)

#: Default location. Gitignored, because these are the publishers' files.
DEFAULT_SCHEMA_DIR = PROJECT_ROOT / "data" / "schemas"

#: Four fixtures, chosen for spread rather than count: one config that passes
#: almost everything, one that fails almost everything, the largest real-world
#: one, and one with a single conspicuous violation. A schema keyword that only
#: bites on failures — or only on passes — is caught by having both ends.
DEFAULT_CONFIGS = (
    "test_configs/compliance_extremes/fully_hardened.conf",
    "test_configs/compliance_extremes/fully_noncompliant.conf",
    "test_configs/realistic/enterprise_complex.conf",
    "test_configs/realistic/telnet_exposed.conf",
)

#: A frozen instant, so two runs of this script produce the same OSCAL document.
#: OSCAL requires a timezone offset (``DateTimeWithTimezoneDatatype``); that
#: requirement is precisely what the ``pattern`` keyword here is being asked to
#: confirm, so the value is written out in full rather than formatted.
SYNTHETIC_TIMESTAMP = "2026-09-09T05:58:00+00:00"

#: Obviously-not-real placeholders. A committed record's hashes come off the
#: ledger; this script never commits anything, so it must supply its own — and
#: they are written as repeated characters so that no reader of the output can
#: mistake one for a chain hash. What a real record does is asserted end-to-end
#: in ``tests/test_api_export.py::test_the_oscal_document_carries_the_committed_record_hash``.
SYNTHETIC_RECORD_HASH = "f" * 64
SYNTHETIC_MERKLE_ROOT = "a" * 64

#: How many schema errors to print per document. All of them are counted; the
#: first few are what a reader needs, and an invalid document can produce
#: thousands of cascading errors from one bad field.
ERRORS_SHOWN = 5


def pythonise_patterns(node: object) -> object:
    """Rewrite XSD ``\\p{...}`` character classes to Python-``re`` equivalents.

    OSCAL's patterns are written for XSD/ECMA regex, where ``\\p{L}`` means "any
    letter". Python's ``re`` cannot compile that, and ``jsonschema`` reacts by
    *skipping* the keyword — which would quietly turn every OSCAL ``pattern``
    into a no-op and leave this script reporting a pass it never checked.

    ``[^\\W\\d_]`` is the standard Unicode-aware stand-in for ``\\p{L}`` on a
    ``str`` pattern: not a letter-class, but the complement of non-word,
    non-digit, non-underscore, which over Unicode text is the same set. So the
    keyword stays enforced rather than being dropped.
    """
    if isinstance(node, dict):
        rewritten: dict[str, object] = {}
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                value = (
                    value.replace("\\p{L}", "[^\\W\\d_]")
                    .replace("\\p{Nd}", "\\d")
                    .replace("\\p{N}", "\\d")
                )
            rewritten[key] = pythonise_patterns(value)
        return rewritten
    if isinstance(node, list):
        return [pythonise_patterns(item) for item in node]
    return node


def load_schema(spec: SchemaSpec, schema_dir: Path) -> dict:
    """Read one pinned schema, or refuse in a way that says which failure it was."""
    path = schema_dir / spec.filename
    if not path.is_file():
        raise ArtifactMissingError(
            f"{spec.label} schema not found at {path}. Run Step 14 in "
            f"MANUAL_COMMANDS.md (downloads {spec.url}), then re-run this command."
        )

    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != spec.sha256:
        raise SchemaPinError(
            f"{spec.label} schema at {path} is not the pinned file.\n"
            f"       expected sha256 {spec.sha256} ({spec.size} bytes)\n"
            f"       found    sha256 {digest} ({len(raw)} bytes)\n"
            f"       The publisher may have re-released it. Investigate the upstream\n"
            f"       change and update SCHEMAS in this file before trusting a verdict;\n"
            f"       a schema this script cannot identify makes 'valid' meaningless."
        )

    schema = json.loads(raw.decode("utf-8"))
    if spec.declared_id is not None and schema.get("$id") != spec.declared_id:
        raise SchemaPinError(
            f"{spec.label} schema declares $id {schema.get('$id')!r}, "
            f"expected {spec.declared_id!r}."
        )
    return schema


def build_validator(schema: dict) -> jsonschema.protocols.Validator:
    """A validator for the draft the schema itself names.

    ``validator_for`` reads ``$schema`` rather than assuming a draft. Both files
    are draft-07 today; hard-coding ``Draft7Validator`` would silently keep
    validating under the wrong rules if either publisher moved.

    The schema is checked against its own metaschema first. An unparseable
    pattern or a malformed subschema would otherwise surface as "the document is
    valid", because ``jsonschema`` skips keywords it cannot evaluate.
    """
    prepared = pythonise_patterns(schema)
    validator_cls = jsonschema.validators.validator_for(prepared)
    validator_cls.check_schema(prepared)
    return validator_cls(prepared)


def report_errors(validator: jsonschema.protocols.Validator, document: dict, label: str) -> int:
    """Print up to :data:`ERRORS_SHOWN` schema errors; return the total count."""
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    for error in errors[:ERRORS_SHOWN]:
        location = "/".join(str(part) for part in error.absolute_path)
        print(f"  {label} INVALID at /{location}: {error.message[:220]}")
    if len(errors) > ERRORS_SHOWN:
        print(f"  {label} … and {len(errors) - ERRORS_SHOWN} more")
    return len(errors)


def synthetic_record(device: dict) -> dict:
    """A ledger record shaped like a committed one, for a script that commits nothing.

    Built from :data:`backend.export.AUDIT_FIELDS` rather than a literal, so a new
    required field on the real record makes this fail here instead of producing a
    document that validates only because it was assembled by hand.
    """
    record = {
        "audit_id": "AUD-CONFORMANCE-0001",
        "device_id": device["device_id"],
        "config_hash": device["config_hash"],
        "created_at": SYNTHETIC_TIMESTAMP,
        "actor": "conformance-check",
        "seq": 1,
        "prev_hash": None,
        "record_hash": SYNTHETIC_RECORD_HASH,
        "merkle_root": SYNTHETIC_MERKLE_ROOT,
        "signature": "",
    }
    missing = [field for field in AUDIT_FIELDS if field not in record]
    if missing:
        raise SystemExit(
            f"[bug] AUDIT_FIELDS gained {missing}; add them to synthetic_record() "
            f"in scripts/check_export_conformance.py."
        )
    return record


def check_one_config(path: Path, oscal: object, sarif: object) -> int:
    """Export one config both ways and validate both documents. Returns error count."""
    result = parse_config(normalise(path.read_text(encoding=FILE_ENCODING)), path.name)
    _, findings = evaluate_facts(
        result.facts,
        result.device.vendor.value,
        result.device.os_family.value,
        os_version=result.device.os_version,
    )
    device = result.device.model_dump(mode="json")
    errors = 0

    document = to_sarif(device, findings)
    errors += report_errors(sarif, document, "SARIF")
    if json.dumps(to_sarif(device, findings)) != json.dumps(document):
        print("  SARIF NOT REPRODUCIBLE: two exports of one config differ")
        errors += 1
    run = document["runs"][0]
    counts = run["properties"]["pramanResultCounts"]
    total = run["properties"]["pramanFindingsTotal"]
    omitted = run["properties"]["pramanResultsOmittedTotal"]
    if sum(counts.values()) != total or len(run["results"]) + omitted != total:
        print(
            f"  SARIF ARITHMETIC: counts={sum(counts.values())} results={len(run['results'])} "
            f"omitted={omitted} total={total} — a finding was dropped without being counted"
        )
        errors += 1
    print(
        f"  SARIF ok   findings={len(findings):4d} results={len(run['results']):4d} "
        f"rules={len(run['tool']['driver']['rules']):4d} omitted={omitted:4d}"
    )

    ar = to_oscal_ar(synthetic_record(device), findings, device)
    errors += report_errors(oscal, ar, "OSCAL")
    if json.dumps(to_oscal_ar(synthetic_record(device), findings, device)) != json.dumps(ar):
        print("  OSCAL NOT REPRODUCIBLE: two exports of one record differ")
        errors += 1
    results = ar["assessment-results"]["results"]
    print(
        f"  OSCAL ok   results={len(results):4d} "
        f"observations={sum(len(r['observations']) for r in results):4d} "
        f"findings={sum(len(r.get('findings', [])) for r in results):4d} "
        f"risks={sum(len(r.get('risks', [])) for r in results):4d}"
    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate OSCAL and SARIF exports against the publishers' JSON Schemas."
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=DEFAULT_SCHEMA_DIR,
        help=f"directory holding the two downloaded schemas (default: {DEFAULT_SCHEMA_DIR})",
    )
    parser.add_argument(
        "--config",
        action="append",
        dest="configs",
        metavar="PATH",
        help="config to export (repeatable). Defaults to the four spread fixtures.",
    )
    args = parser.parse_args(argv)

    try:
        schemas = {spec.label: load_schema(spec, args.schema_dir) for spec in SCHEMAS}
    except ArtifactMissingError as exc:
        print(f"[missing] {exc}", file=sys.stderr)
        return 2
    except SchemaPinError as exc:
        print(f"[pin] {exc}", file=sys.stderr)
        return 3

    oscal = build_validator(schemas["OSCAL"])
    sarif = build_validator(schemas["SARIF"])

    paths = [Path(c) for c in (args.configs or DEFAULT_CONFIGS)]
    absent = [p for p in paths if not p.is_file()]
    if absent:
        print(f"[missing] no such config: {', '.join(str(p) for p in absent)}", file=sys.stderr)
        return 2

    errors = 0
    for path in paths:
        print(f"\n{path}")
        errors += check_one_config(path, oscal, sarif)

    if errors:
        print(f"\n{errors} schema error(s). The exporter is wrong, not the schema.")
        return 1
    print(
        f"\nBoth documents validate against the publishers' schemas for all "
        f"{len(paths)} config(s), and both re-export byte-identically."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
