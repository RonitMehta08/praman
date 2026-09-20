"""PRAMAN CLI — command-line audit entry point.

Usage:
    python -m backend.cli audit --config PATH --framework FRAMEWORK --out DIR

Runs a deterministic (no-AI) compliance audit on a single config file.
Outputs findings as JSON and PDF (if ReportLab is available) to the --out dir.

Designed to work in cold-start mode: no models, no index, no AI artifacts.

Detection and parsing go through ``PatternAdapterRegistry`` — the same registry
``backend/app/main.py`` uses. Until this was fixed the CLI held its own list of
two hardcoded adapter classes, which meant the project's central claim about
vendor onboarding was false through this door: dropping in
``data/ingest/patterns/arista_eos.yaml`` onboarded the vendor for the API and
left the CLI unable to read an Arista config at all. Two registries is one
registry too many for a tool whose selling point is that adding a vendor takes no
code change.

``findings.json`` gains one optional key, ``threat_appendix``, when
``FEATURE_THREAT_ENRICHMENT`` is on and at least one failing control maps to a
technique. It sits beside ``findings`` rather than inside them because the audit
record's Merkle root is computed over the findings alone — see
``backend/threat/appendix.py`` for why that placement is a constraint and not a
layout choice.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from backend.app.auth import SERVICE_CLI
from backend.app.config import FILE_ENCODING
from backend.canonical.findings import Finding, Framework, Result, build_summary
from backend.canonical.models import utc_now_iso
from backend.core_errors import ParseError
from backend.ingest.base import ParseResult
from backend.ingest.decode import decode_config_file
from backend.ingest.generic import PatternAdapterRegistry
from backend.ingest.redact import redact_parse_result
from backend.ledger.chain import compute_merkle_root, compute_record_hash, sign_record
from backend.rules.evaluator import RulesEvaluator
from backend.threat.appendix import appendix_for_findings

#: Every framework the engine knows, as the ``Framework`` enum spells them.
#: Derived rather than restated: the old hardcoded list offered ``STIG``, which is
#: not a value the enum has, so ``--framework STIG`` wrote findings carrying a
#: framework name nothing downstream could match.
FRAMEWORK_CHOICES = [f.value for f in Framework]

#: Built once at module import, like the API's ``STATE``. Loading the pattern
#: packs is the expensive part and a CLI run needs them exactly once.
_REGISTRY = PatternAdapterRegistry()


def _detect_and_parse(raw_text: str, source_file: str) -> ParseResult:
    """Run vendor detection and parse through the shared pattern registry."""
    adapter = _REGISTRY.detect(raw_text, source_file)
    if adapter is None:
        raise ParseError(
            f"no pattern pack recognised '{source_file}'. Loaded vendors: "
            f"{', '.join(sorted(_REGISTRY.library.packs())) or 'none'}. Add "
            "data/ingest/patterns/<vendor>.yaml to onboard a new platform — no "
            "code change is required."
        )
    return adapter.parse(raw_text, source_file)


def cmd_audit(args: argparse.Namespace) -> int:
    """Execute a deterministic audit on a single config file.

    Returns:
        0 on success, 1 on failure.
    """
    config_path = Path(args.config)
    if not config_path.is_file():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Bytes, not read_text: the encoding decision belongs to one module, and a
    # per-call-site `encoding=` argument is exactly how the CLI and the API came
    # to disagree about a BOM. See backend/ingest/decode.py.
    normalised = decode_config_file(config_path)

    # ── Parse ──────────────────────────────────────────────────────
    # Parse the config as written, then redact the result. Redacting the text
    # first shifted every whitespace-delimited field after a secret and silently
    # destroyed the rest of the line's facts — see backend/ingest/redact.py.
    try:
        result = redact_parse_result(_detect_and_parse(normalised, config_path.name))
    except ParseError as exc:
        # R1.7: a config we cannot parse must NOT produce a clean pass or
        # empty report — report an explicit parse-failure finding.
        print(f"PARSE ERROR: {exc}", file=sys.stderr)
        error_finding = Finding(
            control_id="PARSE-ERROR",
            framework=args.framework,
            benchmark="N/A",
            benchmark_version="N/A",
            title="Configuration could not be parsed",
            result=Result.ERROR,
            severity="high",
            evidence=[],
            rationale=str(exc),
        )
        findings_dicts = [error_finding.model_dump(mode="json")]
        summary = build_summary([error_finding])
        _write_outputs(out_dir, {}, findings_dicts, summary, config_path.name)
        print(f"Audit complete (PARSE FAILURE). 1 error finding written to {out_dir}")
        return 1

    # ── Rules ─────────────────────────────────────────────────────
    # Constructed with no arguments so it loads catalogs *and* mapping packs from
    # disk. Passing load_all_rules() positionally bound the rule list to the
    # `catalogs` parameter, which made every rule look like it targeted an
    # unpublished catalog and raised on construction — this entry point could not
    # be imported, let alone run, and nothing imported it to notice.
    evaluator = RulesEvaluator()
    # ``frameworks`` is passed, which it was not before: ``--framework`` was
    # required, validated, and then dropped on the floor, so every run evaluated
    # all four frameworks and the flag changed nothing but the two synthetic
    # findings below. A required flag that does not affect the output is worse
    # than no flag — it reads as a filter that was applied.
    findings = evaluator.evaluate(
        result.facts,
        result.device.vendor.value,
        result.device.os_family.value,
        os_version=result.device.os_version,
        frameworks=[args.framework],
    )

    if not findings and not evaluator.rules:
        # No rules loaded — issue a notchecked finding so the report is
        # never silently empty (R1.7).
        findings = [
            Finding(
                control_id="NO-RULES",
                framework=args.framework,
                benchmark="N/A",
                benchmark_version="N/A",
                title="No rule packs loaded — cannot produce compliance verdicts",
                result=Result.NOTCHECKED,
                severity="high",
                evidence=[],
                rationale=(
                    "The rules/ directory contained no YAML rule packs. "
                    "Load framework-specific rules (Steps 4b/4c in MANUAL_COMMANDS.md) "
                    "to produce pass/fail verdicts."
                ),
            )
        ]

    # ``mode="json"`` is load-bearing, not stylistic. A bare model_dump leaves the
    # Result and Framework enums as enum objects, which serialise as
    # "Result.PASS" rather than "pass" — so the Merkle root below was computed
    # over bytes that no reader of the emitted findings.json could reproduce, and
    # the record's own findings would have looked tampered with. The API commits
    # findings the same way; the two entry points must not disagree about what a
    # finding *is*.
    findings_dicts = [f.model_dump(mode="json") for f in findings]
    summary = build_summary(findings)
    device_dict = result.device.model_dump(mode="json")

    # ── Ledger record (offline, not persisted to DB) ──────────────
    #
    # ``actor`` is a hashed field of every record, so the offline door has to name
    # itself too. It names a *service* principal rather than the operating-system
    # user because that is the honest answer: this entry point authenticates
    # nobody, and writing ``os.getlogin()`` into a signed record would dress an
    # unauthenticated string up as an identity. A reviewer reading
    # ``service:offline-cli`` in a record knows exactly how much the name is
    # worth — the file was produced by whoever had shell access to the host.
    audit_id = str(uuid.uuid4())
    merkle_root = compute_merkle_root(findings_dicts)
    record_data = {
        "actor": SERVICE_CLI,
        "audit_id": audit_id,
        "device_id": result.device.device_id,
        "config_hash": result.device.config_hash,
        "created_at": utc_now_iso(),
        "findings": findings_dicts,
        "summary": summary,
        "seq": 0,
        "prev_hash": "",
        "merkle_root": merkle_root,
    }
    record_hash = compute_record_hash(record_data)
    signature = sign_record(record_hash)

    audit_record = {
        **record_data,
        "record_hash": record_hash,
        "signature": signature,
    }

    # ── Threat appendix (context, never a verdict) ────────────────
    #
    # Computed *after* the record is sealed, and deliberately so: the Merkle root
    # above is over ``findings_dicts``, and the appendix is a sibling key in the
    # report envelope rather than a field on any finding. So with
    # ``FEATURE_THREAT_ENRICHMENT`` off the envelope loses one key and the record,
    # root and signature are byte-identical — which is what P12 asks for, and is
    # asserted in tests/test_threat_appendix.py rather than merely claimed here.
    # The flag is checked inside ``appendix_for_findings``, so this door cannot
    # disagree with any other about when the tier is on.
    threat_appendix = (
        appendix_for_findings(findings_dicts, evaluator.rules, evaluator.catalogs) or None
    )

    _write_outputs(
        out_dir,
        device_dict,
        findings_dicts,
        summary,
        config_path.name,
        audit_record,
        threat_appendix,
    )

    # ── Summary ───────────────────────────────────────────────────
    total = summary["total"]
    by_result = summary.get("by_result", {})
    print(f"Audit complete: {total} finding(s)")
    for r_name, r_count in sorted(by_result.items()):
        print(f"  {r_name.upper():20s} {r_count}")
    print(f"Output written to {out_dir}")
    return 0


def _write_outputs(
    out_dir: Path,
    device_dict: dict,
    findings_dicts: list[dict],
    summary: dict,
    source_name: str,
    audit_record: dict | None = None,
    threat_appendix: dict | None = None,
) -> None:
    """Write JSON findings and optionally a PDF report to the output dir."""
    # JSON output — always available
    json_path = out_dir / "findings.json"
    report_payload = {
        "device": device_dict,
        "findings": findings_dicts,
        "summary": summary,
        "source_file": source_name,
    }
    if audit_record:
        # Remove the heavy findings list from the record stored in JSON
        record_meta = {k: v for k, v in audit_record.items() if k != "findings"}
        report_payload["audit_record"] = record_meta
    if threat_appendix:
        # Absent rather than empty when there is nothing to say. An empty
        # appendix in the envelope reads as "we looked and found no exposure",
        # which is a claim; a missing key reads as "not produced", which is true.
        report_payload["threat_appendix"] = threat_appendix

    json_path.write_text(
        json.dumps(report_payload, indent=2, default=str),
        encoding=FILE_ENCODING,
    )

    # PDF output — best-effort
    if audit_record and device_dict:
        try:
            from backend.report.render import render_pdf

            pdf_bytes = render_pdf(device_dict, findings_dicts, summary, audit_record)
            pdf_path = out_dir / "report.pdf"
            pdf_path.write_bytes(pdf_bytes)
        except Exception as exc:
            print(f"WARNING: PDF generation failed ({exc}), JSON output is still valid.")


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="praman-cli",
        description="PRAMAN — deterministic network compliance auditor CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # audit sub-command
    audit_parser = subparsers.add_parser(
        "audit",
        help="Run a deterministic compliance audit on a config file",
    )
    audit_parser.add_argument(
        "--config",
        required=True,
        help="Path to the network device configuration file",
    )
    audit_parser.add_argument(
        "--framework",
        required=True,
        choices=FRAMEWORK_CHOICES,
        help="Compliance framework to audit against",
    )
    audit_parser.add_argument(
        "--out",
        required=True,
        help="Output directory for findings JSON and PDF report",
    )

    args = parser.parse_args()

    if args.command == "audit":
        return cmd_audit(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
