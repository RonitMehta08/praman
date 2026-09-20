"""OSCAL Assessment Results (AR) document assembly — the machine-readable output.

An AR document is built from a *committed* ledger record, never from a simulation,
for the same reason the PDF is: the document that leaves the building has to
correspond to something a recipient can re-verify. Every id in it derives from the
record hash, so exporting ledger record ``seq=18`` twice produces byte-identical
JSON, and exporting it again next year still does.

The compliance semantics live in :mod:`backend.export.oscal_mapping`; the shape of
each element lives in :mod:`backend.export.oscal_elements`. This module only
assembles them into a document.

Written with stdlib ``json`` only — the caller serialises the dict this returns.
``compliance-trestle`` is the obvious alternative and is deliberately not used: it
hard-pins ``jinja2==3.1.6`` and ``cryptography`` bounds that fight the FastAPI +
ReportLab + Ed25519 stack this project already has. If OSCAL object validation is
wanted, install trestle in a separate virtualenv and point it at the output file.

Every property name, enum and ``required`` list cited here was read out of
``oscal_assessment-results_schema.json`` from the OSCAL ``v1.2.3`` release
(published 2026-08-07, 152,214 bytes), which is why the notes cite specific
requirements rather than describing them loosely.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from backend.canonical.findings import Finding
from backend.core_errors import ExportError
from backend.export.ids import deterministic_uuid, oscal_token
from backend.export.oscal_elements import finding_element, observation, risk
from backend.export.oscal_mapping import (
    OBJECTIVE_STATUS,
    RISK_STATUS,
    as_finding,
    prop,
    require_timestamp,
    result_value,
)

#: The OSCAL release whose schema the field names, enums and required-lists in
#: this package were read from. Goes into ``metadata.oscal-version``.
OSCAL_VERSION = "1.2.3"

#: The ``$id`` of that schema, used as the document's ``$schema`` directive. The
#: root schema declares ``$schema`` as a ``json-schema-directive``, so this member
#: is allowed rather than tolerated.
OSCAL_AR_SCHEMA_ID = "http://csrc.nist.gov/ns/oscal/1.2.3/oscal-ar-schema.json"

#: Where the schema itself came from, recorded in the document so a reviewer can
#: re-check the mapping instead of taking this package's word for it.
OSCAL_AR_SCHEMA_URL = (
    "https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/"
    "oscal_assessment-results_schema.json"
)

#: Audit-record columns the exporter reads. Checked up front so a missing column
#: names itself instead of surfacing as a KeyError three frames down.
AUDIT_FIELDS = (
    "audit_id",
    "device_id",
    "config_hash",
    "created_at",
    "actor",
    "seq",
    "record_hash",
    "merkle_root",
    "signature",
)


def _result(
    group: tuple[str, str, str],
    findings: list[Finding],
    *,
    record: dict[str, Any],
    device_label: str,
) -> dict[str, Any]:
    """One AR result per (framework, benchmark, benchmark_version).

    One result per benchmark rather than one for the whole audit, because
    ``reviewed-controls`` names a control id and a control id only means something
    inside a catalog. A single result carrying CIS ``1.1.4`` and DISA ``V-215668``
    side by side would be asking a consumer to guess which catalog each belongs to.
    """
    framework, benchmark, benchmark_version = group
    collected = require_timestamp(record["created_at"], "audit record created_at")
    observations: list[dict[str, Any]] = []
    ar_findings: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    tokens: dict[str, None] = {}
    counts: dict[str, int] = {}

    for finding in findings:
        value = result_value(finding)
        counts[value] = counts.get(value, 0) + 1
        # Keyed on the record hash so two audits of one control get different
        # uuids, and on the control id so re-exporting one audit gets the same
        # ones. Both halves matter: the first keeps a GRC platform from merging
        # distinct assessments, the second keeps it from duplicating one.
        key = "\x1f".join((record["record_hash"], framework, benchmark, finding.control_id))
        element = observation(finding, value, collected, key)
        observations.append(element)
        token, _ = oscal_token(finding.control_id, framework)
        tokens[token] = None
        if value in OBJECTIVE_STATUS:
            ar_findings.append(finding_element(finding, value, key, element["uuid"]))
        if value in RISK_STATUS:
            risks.append(risk(finding, value, key, element["uuid"]))

    decided = sum(counts.get(value, 0) for value in OBJECTIVE_STATUS)
    props = [
        prop("praman-framework", framework),
        prop("praman-benchmark", benchmark),
        prop("praman-benchmark-version", benchmark_version),
        prop("praman-device-id", record["device_id"]),
        prop("praman-controls-reviewed", str(len(tokens))),
        prop("praman-controls-decided", str(decided)),
    ]
    props += [prop(f"praman-count-{value}", str(counts[value])) for value in sorted(counts)]

    result: dict[str, Any] = {
        "uuid": deterministic_uuid("result", record["record_hash"], framework, benchmark),
        "title": f"{benchmark} {benchmark_version}",
        "description": (
            f"PRAMAN evaluated {device_label} against {benchmark} "
            f"{benchmark_version} ({framework}). {decided} of {len(tokens)} reviewed "
            f"controls were decided by a deterministic rule; the rest are reported "
            f"as observations carrying the reason they were not decided."
        ),
        "start": collected,
        "props": props,
        "reviewed-controls": {
            "description": (
                f"Every control of {benchmark} {benchmark_version} that PRAMAN "
                f"loaded for this device, decided or not. A control PRAMAN could "
                f"not decide is still a control it reviewed."
            ),
            "control-selections": [
                {
                    "description": f"{benchmark} {benchmark_version}",
                    "include-controls": [{"control-id": token} for token in sorted(tokens)],
                }
            ],
        },
        "observations": observations,
    }
    # ``minItems`` is 1 on each of these, so an empty array is a schema violation
    # rather than an empty list. A benchmark where nothing was decided is a real
    # state — every control notchecked — and it has to export cleanly.
    if ar_findings:
        result["findings"] = ar_findings
    if risks:
        result["risks"] = risks
    return result


def _metadata_props(record: dict[str, Any], device: dict[str, Any] | None) -> list[dict[str, str]]:
    """Ledger and device identity as OSCAL properties.

    Carrying ``record_hash``, ``merkle_root`` and ``signature`` is the whole reason
    this export is interesting rather than merely convenient: a GRC platform that
    ingests it holds the values needed to ask PRAMAN's own verifier whether the
    assessment it is displaying is the one that was signed.
    """
    props = [
        prop("praman-audit-id", record["audit_id"]),
        prop("praman-device-id", record["device_id"]),
        prop("praman-config-hash", record["config_hash"]),
        prop("praman-actor", record["actor"]),
        prop("praman-ledger-seq", str(record["seq"])),
        prop("praman-record-hash", record["record_hash"]),
        prop("praman-merkle-root", record["merkle_root"]),
        # An unsigned record is a supported state — no signing key present — and
        # it has to read as unsigned rather than as an empty string a consumer
        # might treat as "not checked".
        prop("praman-signature", record["signature"] or "unsigned"),
        prop("praman-oscal-schema", OSCAL_AR_SCHEMA_URL),
    ]
    if record.get("prev_hash") is not None:
        props.append(prop("praman-prev-hash", record["prev_hash"] or "genesis"))
    for name in ("vendor", "os_family", "os_version", "hostname"):
        value = (device or {}).get(name)
        if value:
            props.append(prop(f"praman-device-{name.replace('_', '-')}", str(value)))
    return props


def _plan_resource(record: dict[str, Any], plan_uuid: str) -> dict[str, Any]:
    """The back-matter resource ``import-ap`` points at.

    ``import-ap`` is required and there is no external assessment plan: PRAMAN's
    plan is the YAML rule packs it shipped with. Pointing the required href at a
    resource that says exactly that is the honest form. Inventing a plan document,
    or pointing at a URL that would 404 on an air-gapped machine, is not.
    """
    return {
        "uuid": plan_uuid,
        "title": "PRAMAN rule packs (in place of an assessment plan)",
        "description": (
            "PRAMAN has no OSCAL assessment plan document. What was assessed is "
            "fixed by the YAML mapping packs under `rules/mappings/` and the "
            "pattern packs under `data/ingest/patterns/`, both of which ship with "
            "the tool and are versioned with it. The set of controls actually "
            "reviewed is enumerated per result in `reviewed-controls`, which is the "
            "same information an assessment plan would have carried."
        ),
        "props": [
            prop("praman-record-hash", record["record_hash"]),
            prop("praman-audit-id", record["audit_id"]),
        ],
    }


def to_oscal_ar(
    record: dict[str, Any],
    findings: Sequence[Finding | dict[str, Any]],
    device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An OSCAL Assessment Results document for one committed audit.

    `record` is an ``audit_records`` row (``dict(row)`` of a ``sqlite3.Row`` is
    fine); `findings` are that audit's findings, as models or as
    ``finding_from_row`` projections; `device` is the optional ``devices`` row,
    used only to label the assessment and to publish the device's identity.

    Raises :class:`ExportError` rather than emitting a schema-invalid document —
    for a missing ledger column, an audit with no findings, or a timestamp OSCAL
    would reject. A GRC platform refusing a malformed document is a good outcome;
    one silently ingesting a malformed document is not.
    """
    missing = [field for field in AUDIT_FIELDS if field not in record]
    if missing:
        raise ExportError(
            "audit record is missing " + ", ".join(missing) + ". The OSCAL export "
            "reads the ledger fields directly, so a partial row would produce a "
            "document that looks verifiable and is not."
        )
    typed = [as_finding(item) for item in findings]
    if not typed:
        raise ExportError(
            f"audit '{record['audit_id']}' has no findings. OSCAL requires at least "
            "one result and a result requires at least one reviewed control, so "
            "there is no valid document to emit for an empty audit."
        )

    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in typed:
        grouped.setdefault(
            (finding.framework, finding.benchmark, finding.benchmark_version), []
        ).append(finding)

    device_id = record["device_id"]
    hostname = (device or {}).get("hostname")
    device_label = f"device '{device_id}'"
    if hostname and hostname != device_id:
        device_label = f"device '{device_id}' (hostname {hostname})"

    plan_uuid = deterministic_uuid("assessment-plan-absent", record["record_hash"])
    return {
        "$schema": OSCAL_AR_SCHEMA_ID,
        "assessment-results": {
            "uuid": deterministic_uuid("assessment-results", record["record_hash"]),
            "metadata": {
                "title": f"PRAMAN compliance assessment — {device_id}",
                "last-modified": require_timestamp(
                    record["created_at"], "audit record created_at"
                ),
                # OSCAL's ``version`` is the version of *this document*. The audit
                # id is exactly that: one audit, one document, and a re-export
                # produces the same bytes.
                "version": record["audit_id"],
                "oscal-version": OSCAL_VERSION,
                "props": _metadata_props(record, device),
            },
            "import-ap": {
                "href": f"#{plan_uuid}",
                "remarks": (
                    "No external OSCAL assessment plan. See the referenced "
                    "back-matter resource."
                ),
            },
            "results": [
                _result(group, grouped[group], record=record, device_label=device_label)
                for group in sorted(grouped)
            ],
            "back-matter": {"resources": [_plan_resource(record, plan_uuid)]},
        },
    }
