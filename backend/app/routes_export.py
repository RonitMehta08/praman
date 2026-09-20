"""Machine-readable export routes — OSCAL Assessment Results and SARIF.

Two endpoints, deliberately fed from opposite ends of the system, because they
answer to different audiences:

* ``GET /devices/{id}/oscal.json`` renders a **committed ledger record**. It is
  the same rule as ``report.pdf``: a document that leaves the building must cite
  a record an outside party can re-verify, so this route refuses when the device
  has no committed audit rather than quietly exporting a simulation.
* ``POST /simulate/sarif`` renders a **simulation**. A CI gate has to run before
  anything is committed — that is the entire point of shifting left — so
  demanding a ledger record here would make the endpoint useless. It writes
  nothing and carries no ledger identity, which is exactly why its output is not
  evidence.

Why this is a separate router
-----------------------------
``main.py`` is already far over the project's 500-line file limit, and these
routes need nothing from it except the shared parse/evaluate funnel, which now
lives in ``backend/app/services.py``. Importing that module rather than ``main``
is what keeps this file free of a circular import: ``main`` mounts this router,
so anything here that reached back into ``main`` at module scope would deadlock
the import graph.

It must be mounted **before** ``main``'s static-asset catch-all, which is
declared last so that no file under ``frontend/`` can shadow an API route.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from backend.app.auth import REQUIRE_AUDITOR, REQUIRE_VIEWER
from backend.app.services import evaluate_facts, parse_config
from backend.app.services import require_device as _require_device
from backend.app.state import STATE
from backend.db.connection import finding_from_row
from backend.export import OSCAL_VERSION, SARIF_VERSION, to_oscal_ar, to_sarif
from backend.ingest.decode import normalise

router = APIRouter()


class SarifRequest(BaseModel):
    """The body ``POST /simulate/sarif`` accepts.

    Deliberately the same shape as ``/simulate``'s ``SimulateRequest``: the two
    endpoints run the identical pipeline over the identical input and differ only
    in how they serialise the answer, so a client that can call one can call the
    other by changing the path. It is declared here rather than imported so this
    router does not import the application module that mounts it;
    ``tests/test_api_export.py`` asserts the two models stay field-for-field
    identical, which is the drift risk that duplication would otherwise carry.
    """

    config_text: str
    source_file: str = "inline.conf"


def _stem(device: dict, device_id: str) -> str:
    """A filename stem an operator will recognise: hostname, else the device id."""
    return str(device.get("hostname") or device_id)


@router.get("/devices/{device_id}/oscal.json", dependencies=[Depends(REQUIRE_VIEWER)])
async def device_oscal_ar(
    device_id: str,
    audit_id: str | None = Query(
        None, description="A specific committed audit; the latest when omitted."
    ),
) -> Response:
    """The per-device audit as an OSCAL v1.2.3 Assessment Results document.

    Rendered from a committed audit for the same reason the PDF is: the document
    carries the record hash, Merkle root and signature, so the recipient can hand
    those three values back to PRAMAN's verifier and establish that the
    assessment it is displaying is the one that was signed. A document exported
    from a simulation would carry none of that and could not be distinguished
    from one that could.

    Served compact rather than indented — unlike the SARIF log, which a human
    reads in a diff, this is ingested by a GRC platform, and the observations of
    a full audit run to thousands of objects.

    Every identifier in the document is a version-5 UUID over the record hash, so
    re-exporting one audit produces byte-identical output forever. A platform that
    ingests the same audit twice sees one assessment, not two.
    """
    conn = STATE.connect()
    try:
        device_row = _require_device(conn, device_id)
        if audit_id:
            audit = conn.execute(
                "SELECT * FROM audit_records WHERE audit_id = ? AND device_id = ?",
                (audit_id, device_id),
            ).fetchone()
        else:
            audit = conn.execute(
                "SELECT * FROM audit_records WHERE device_id = ?"
                " ORDER BY seq DESC LIMIT 1",
                (device_id,),
            ).fetchone()
        if audit is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"device '{device_id}' has no committed audit"
                    + (f" with audit_id '{audit_id}'" if audit_id else "")
                    + ". An OSCAL Assessment Results document cites a ledger "
                    'record, so commit first: POST /audit/commit {"device_id": "'
                    + device_id
                    + '"}'
                ),
            )
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE audit_id = ? ORDER BY id",
            (audit["audit_id"],),
        ).fetchall()
    finally:
        conn.close()

    if not finding_rows:
        raise HTTPException(
            status_code=409,
            detail=(
                f"audit '{audit['audit_id']}' has no stored findings, so there is "
                "nothing to assess. An Assessment Results document with an empty "
                "results array asserts that a review happened and found nothing, "
                "which is not what occurred."
            ),
        )

    # Projected through the same function the ledger verifier uses, so the
    # exported findings are byte-for-byte the ones the committed Merkle root was
    # computed over. That is what makes the record hash in the document's
    # metadata checkable rather than decorative.
    findings = [finding_from_row(row) for row in finding_rows]
    document = to_oscal_ar(dict(audit), findings, dict(device_row))
    stem = _stem(dict(device_row), device_id)
    return Response(
        content=json.dumps(document, ensure_ascii=False),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="praman-{stem}-seq{audit["seq"]}.oscal.json"'
            ),
            "X-PRAMAN-OSCAL-Version": OSCAL_VERSION,
            "X-PRAMAN-Record-Hash": audit["record_hash"],
            "X-PRAMAN-Audit-Id": audit["audit_id"],
        },
    )


@router.post("/simulate/sarif", dependencies=[Depends(REQUIRE_AUDITOR)])
async def simulate_sarif(req: SarifRequest) -> Response:
    """The same simulation as ``POST /simulate``, serialised as a SARIF v2.1.0 log.

    This is the CI-gate shape of PRAMAN: a pipeline posts a candidate
    configuration, gets back a SARIF log, and the platform annotates the offending
    line of the config file in the pull request. Nothing is written, so a gate can
    run on every push without filling the ledger with records for configurations
    that were never deployed.

    Served indented, because this artefact gets committed, diffed and read by
    people as often as it is uploaded. The log carries no timestamps at all, so
    two runs over the same bytes produce the same file and a diff shows only what
    actually changed — see ``backend/export/sarif.py`` for why that mattered
    enough to leave out fields the schema permits.

    The response media type is ``application/json``. ``application/sarif+json``
    appears in the wild but is not an IANA-registered type, and a CI runner that
    strictly matches on it is rarer than one that chokes on an unknown type.
    """
    result = parse_config(normalise(req.config_text), req.source_file)
    _, findings = evaluate_facts(
        result.facts,
        result.device.vendor.value,
        result.device.os_family.value,
        os_version=result.device.os_version,
    )
    device = result.device.model_dump(mode="json")
    document = to_sarif(device, findings)
    stem = _stem(device, device["device_id"])
    return Response(
        content=json.dumps(document, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="praman-{stem}.sarif"',
            "X-PRAMAN-SARIF-Version": SARIF_VERSION,
            "X-PRAMAN-Config-Hash": device["config_hash"],
        },
    )
