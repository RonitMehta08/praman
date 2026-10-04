"""PRAMAN FastAPI application — the HTTP surface over the deterministic core.

Two operations are the spine, and the distinction between them is an invariant,
not a convenience:

* ``POST /simulate`` — stateless, idempotent, no side effects. Callable without
  limit. Nothing it does can be cited later as evidence.
* ``POST /audit/commit`` — writes exactly one immutable ``AuditRecord`` to the
  hash-chained ledger. This is the operation that produces evidence.

Everything else serves one of PRAMAN's five capabilities:

* C1 ingestion — ``/ingest`` (single) and ``/ingest/bulk`` (archive).
* C2 training — ``/training/queue``, ``/training/map``, ``/training/mappings``,
  ``/training/export``. A mapping taught here applies to the next parse in the
  same process: the pattern registry asks the mapping store for taught patterns
  on every parse, so there is no redeploy and no reload button to forget.
* C3 frameworks — ``/simulate`` and ``/audit/commit`` evaluate CIS and DISA STIG
  against the canonical model and project NIST 800-53 and ISO 27001 by roll-up.
* C4 actionable output — ``/devices/{id}``, ``/devices/{id}/findings`` and the
  signed ``/devices/{id}/report.pdf``.
* C5 scalability — ``/vendors`` and ``/health`` report what is loaded;
  ``/canonical/paths`` is the vocabulary both the UI and the training GUI bind
  to. New vendors and standards arrive as data files, so they show up here
  without a code change.

Handlers do no analysis of their own. They decode, delegate, and serialise; the
verdict logic lives in ``backend/rules`` and is reachable identically from
``backend/cli.py``, which is what keeps the API from becoming a second, subtly
different implementation of the audit.

Who may do what
---------------
Every route below except ``/health``, the public login/signup/options routes and static assets
sits behind a role gate — see ``backend/app/auth.py``. Three roles, ordered:

* ``viewer`` reads the estate: devices, findings, reports, the ledger.
* ``auditor`` adds ``/ingest`` and ``/simulate`` — handing the system a config.
* ``approver`` adds the two authoritative acts: committing an audit to the ledger,
  and teaching the parser a mapping. Both change what future audits will say.

The gate is not only about refusing strangers. ``POST /audit/commit`` records the
authenticated operator as ``actor`` *inside* the hashed ledger record, so who
decided is evidence on the same terms as what was decided. And every request that
reaches a gated route is appended to ``access_log``, reads included: downloading
every device's findings used to leave no trace at all.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from backend.ai.mapping_queue import pending_queue, queue_counts, queue_unparsed
from backend.ai.mapping_store import (
    ANY_VENDOR,
    MappingError,
    export_pack_patterns,
    list_mappings,
    retire_mapping,
    upsert_mapping,
)
from backend.ai.templates import cluster_lines
from backend.app.auth import (
    COOKIE_NAME,
    REQUIRE_APPROVER,
    REQUIRE_AUDITOR,
    REQUIRE_VIEWER,
    ROLE_APPROVER,
    ROLE_AUDITOR,
    SESSION_TTL_SECONDS,
    Principal,
    authenticate,
    bearer_token,
    clear_login_failures,
    close_session,
    known_actors,
    lockout_remaining,
    note_login_failure,
    open_session,
    user_count,
)
from backend.app.bulk import ArchiveRejectedError, open_archive, read_members
from backend.app.config import (
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    MAX_UPLOAD_BYTES,
    SIGNING_PFX_PASSPHRASE,
    SIGNING_PFX_PATH,
    SIGNING_TSA_URL,
)
from backend.app.routes_export import router as export_router
from backend.app.routes_jobs import router as jobs_router
from backend.app.routes_signup import router as signup_router
from backend.app.services import evaluate_facts, parse_config, require_device
from backend.app.state import STATE
from backend.canonical.findings import build_summary
from backend.canonical.models import CanonicalFact, utc_now_iso
from backend.canonical.paths import canonical_paths_sorted, path_families
from backend.core_errors import ExportError, ParseError
from backend.db.connection import (
    finding_from_row,
    get_latest_seq,
    get_prev_hash,
    record_access,
    store_device,
    store_facts,
    store_findings,
)
from backend.ingest.base import ParseResult
from backend.ingest.decode import decode_config, normalise
from backend.jobs import QUEUE, Job
from backend.ledger.chain import compute_merkle_root, compute_record_hash, sign_record
from backend.rules.evaluator import compute_compliance_score, score_from_counts
from backend.rules.projection import DIRECT_FRAMEWORKS

# ─── App setup ─────────────────────────────────────────────────────────

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
)

# The UI is served from this same origin, so no cross-origin request is needed
# for normal use. Credentials are disabled outright: `allow_credentials=True`
# alongside a wildcard origin is the combination that lets any page on the
# internet make authenticated calls to a service running on the operator's
# laptop. Localhost origins are allowed so a separately-served dev frontend
# works without reopening that hole.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


#: Paths whose requests are not written to ``access_log``.
#:
#: Static assets, and ``/health``. Logging the assets would put a line in the
#: table for every stylesheet and ES module the login page pulls, and ``/health``
#: is polled by whatever is watching the process — between them they bury the one
#: line that matters, who fetched which device's findings, under thousands that do
#: not. ``.pdf`` is deliberately absent from the suffix list: a report download is
#: exactly the read this log exists to record.
_UNLOGGED_SUFFIXES = frozenset(
    {".js", ".mjs", ".css", ".html", ".svg", ".png", ".ico", ".woff", ".woff2", ".map"}
)
_UNLOGGED_PATHS = frozenset(
    {"/", "/health", "/openapi.json", "/docs", "/redoc", "/favicon.ico"}
)


def _is_logged_path(path: str) -> bool:
    """Whether a request to ``path`` belongs in the access log."""
    if path in _UNLOGGED_PATHS:
        return False
    dot = path.rfind(".")
    slash = path.rfind("/")
    suffix = path[dot:].lower() if dot > slash else ""
    return suffix not in _UNLOGGED_SUFFIXES


@app.middleware("http")
async def _access_log_middleware(request: Request, call_next):
    """Append every API request to ``access_log``, reads included.

    ``docs/PRODUCTION-ROADMAP.md`` §1.4 names the gap:

        Reads are not logged at all. Downloading every device's findings leaves
        no trace.

    The actor is read from ``request.state`` *after* the handler has run, because
    that is the only point at which authentication has happened. An
    unauthenticated request is still logged, with an empty actor — a burst of
    those is the signature of somebody probing the appliance, and dropping them
    would hide the attempts while keeping the successes.

    Logging failures are swallowed on purpose. The response has already been
    produced; turning a full ``access_log`` table into a 500 would deny service
    to protect an audit trail, which is the wrong trade for a tool whose job is
    to be available when somebody needs an answer about a firewall.
    """
    started = time.perf_counter()
    response = await call_next(request)
    path = request.url.path
    if not _is_logged_path(path):
        return response

    principal: Principal | None = getattr(request.state, "principal", None)
    duration_ms = int((time.perf_counter() - started) * 1000)
    try:
        conn = STATE.connect()
        try:
            record_access(
                conn,
                actor=principal.username if principal else "",
                method=request.method,
                path=path,
                status=response.status_code,
                duration_ms=duration_ms,
                client=request.client.host if request.client else "",
            )
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return response


@app.exception_handler(ParseError)
async def _parse_error_handler(_request, exc: ParseError) -> JSONResponse:
    """A file the system cannot parse is a bad request, not a server fault.

    Returned as 400 with the parser's own message, which names the loaded
    vendors and the file to add. A 500 here would tell the operator that PRAMAN
    is broken when the truth is that their file is a Word document.
    """
    return JSONResponse(
        status_code=400, content={"detail": str(exc), "error": "ParseError"}
    )


@app.exception_handler(MappingError)
async def _mapping_error_handler(_request, exc: MappingError) -> JSONResponse:
    """A rejected mapping is operator input to correct, not a failure to hide."""
    return JSONResponse(
        status_code=400, content={"detail": str(exc), "error": "MappingError"}
    )


@app.exception_handler(ExportError)
async def _export_error_handler(_request, exc: ExportError) -> JSONResponse:
    """An export PRAMAN refuses to emit is a 500, not a 400.

    The input to both exporters is PRAMAN's own data — a committed ledger record,
    or facts this process just parsed. So a refusal never means the caller sent
    something wrong; it means a stored record is missing a field or carries a
    timestamp OSCAL would reject, and the caller can do nothing about it. The
    message is passed through unaltered because it names the offending field, and
    that is the only thing that makes the row findable.

    Emitting a partial document with the bad field defaulted would be worse than
    this error: the recipient would have no way to tell it apart from a good one.
    """
    return JSONResponse(
        status_code=500, content={"detail": str(exc), "error": "ExportError"}
    )


# ─── Helpers ───────────────────────────────────────────────────────────


def _decode_config(raw: bytes) -> str:
    """Decode configuration bytes. See ``backend/ingest/decode.py`` for the policy.

    Kept as a one-line alias rather than replacing the call sites, because the
    upload path and the CLI must not be able to drift apart again: there is now
    one implementation, and this name is what the routes below already read as.
    """
    return decode_config(raw)


async def _read_upload(file: UploadFile, limit: int = MAX_UPLOAD_BYTES) -> bytes:
    """Read an upload in chunks, refusing one that exceeds the limit.

    Chunked rather than ``await file.read()``: the unbounded version decides how
    much memory to allocate based on what the client sent, which is the whole
    problem. Refusing at the limit means a 2 GB upload costs one chunk of RAM
    and a 413, not a dead process.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"upload exceeds the {limit // (1024 * 1024)} MB limit. "
                    "Split the archive, or raise MAX_UPLOAD_BYTES in "
                    "backend/app/config.py if this is a legitimate estate size."
                ),
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _store_parse(conn, result: ParseResult, source_file: str) -> int:
    """Persist a parse: the device, its facts, and its unparsed lines.

    Queuing the unparsed lines here rather than in a separate step is what makes
    the training module self-feeding. Before this, ``training_queue`` was written
    by nothing, so the training GUI had an empty list to show no
    matter how many unrecognised commands the estate contained.
    """
    device_dict = result.device.model_dump(mode="json")
    store_device(conn, device_dict)
    store_facts(
        conn,
        result.device.device_id,
        [f.model_dump(mode="json") for f in result.facts],
    )
    clusters = queue_unparsed(
        conn,
        device_id=result.device.device_id,
        vendor=result.device.vendor.value,
        source_file=source_file,
        unparsed_lines=result.unparsed_lines,
    )
    return len(clusters)


def _ai_status() -> dict[str, Any]:
    """Report which escalation tiers can actually run right now.

    Availability is reported per tier from the artefacts on disk, not from a
    version constant, because the whole point of the cold-start contract is that
    the system runs with none of them. A tier that is absent must read as absent
    in the UI rather than as a green badge that means nothing.
    """
    from backend.ai.escalation import llm_availability
    from backend.ai.readiness import classifier_readiness
    from backend.app.config import LLM_HOST, LLM_PORT, MODELS_DIR, SENTINEL_AI_BACKEND

    if SENTINEL_AI_BACKEND == "none":
        return {
            "ai_backend": "none",
            "tiers": {
                "tier0_deterministic": True,
                "tier1_tfidf": False,
                "tier2_setfit": False,
                "tier3_llm": False,
            },
            "note": "SENTINEL_AI_BACKEND=none — deterministic parsing only.",
        }

    readiness = classifier_readiness()
    llm_up, llm_checked_age_s = (
        (False, 0.0) if SENTINEL_AI_BACKEND == "classifiers" else llm_availability()
    )
    tiers = {
        "tier0_deterministic": True,
        # Readiness checks both packaged artefacts and inference dependencies.
        # A model directory without SetFit installed cannot be a green badge.
        "tier1_tfidf": readiness["tier1_tfidf"]["ready"],
        "tier2_setfit": readiness["tier2_setfit"]["ready"],
        "tier3_llm": llm_up,
    }
    # "Not installed" and "installed but not running" are different sentences
    # because they are different actions: one is a 2.4 GB download, the other is
    # starting a process that is already on disk. Reporting a downloaded model as
    # missing sends the operator back to a step they already completed, which is
    # how a correct availability check still produces a wrong instruction.
    absent = [name for name, ready in tiers.items() if not ready and name != "tier3_llm"]
    # Each absent tier names the step that builds *it*, not one shared "see
    # MANUAL_COMMANDS.md". The generic pointer is what sent operators to Step 1
    # for packages Step 1 does not install, and to Step 8 for a model Step 8a
    # does not write.
    steps = {"tier1_tfidf": "Step 8a", "tier2_setfit": "Step 8c"}
    absent = [f"{name} ({steps[name]})" if name in steps else name for name in absent]
    weights_present = any(MODELS_DIR.glob("*.gguf"))
    if SENTINEL_AI_BACKEND == "classifiers":
        tier3_note = " Tier 3 is disabled in the CPU classifier profile."
    elif tiers["tier3_llm"]:
        tier3_note = ""
    elif weights_present:
        tier3_note = (
            f" Tier 3 weights are present but llama-server is not answering on "
            f"{LLM_HOST}:{LLM_PORT} — start it (MANUAL_COMMANDS.md Step 6)."
        )
    else:
        tier3_note = " tier3_llm has no weights on disk — see MANUAL_COMMANDS.md."

    return {
        "ai_backend": SENTINEL_AI_BACKEND,
        "tiers": tiers,
        "classifier_readiness": readiness,
        # Only Tier 3's answer can be stale. Reported so the UI can distinguish "llama-server
        # is down" from "we last looked 28 seconds ago", which are the same badge
        # and different actions.
        "tier3_checked_age_s": round(llm_checked_age_s, 1),
        "tier3_weights_present": weights_present,
        "note": (
            "Verdicts never depend on these tiers; they only suggest canonical "
            "paths for lines no pattern claimed."
            + (f" Not ready: {', '.join(absent)} — check classifier_readiness for missing files/dependencies." if absent else "")
            + tier3_note
        ),
    }


def _classify_unparsed(result: ParseResult) -> list[dict[str, Any]]:
    """Suggest a canonical path for each cluster of unparsed lines.

    Clustered, not per line: an estate produces the same unmapped command on
    hundreds of devices, and a suggestion list with 400 identical rows is a list
    nobody reads. One row per template, ordered by how many lines it stands for.

    The valid-path list is passed down because the LLM tier is gated on it — it
    performs grammar-constrained decoding into the real canonical-path enum, and
    without the enum it cannot run at all. Omitting it, as the previous version
    did, made Tier 3 permanently unreachable while the UI showed it as ready.
    """
    if not result.unparsed_lines:
        return []

    from backend.ai.escalation import escalate_line

    valid_paths = canonical_paths_sorted()
    suggestions: list[dict[str, Any]] = []
    for cluster in cluster_lines(list(result.unparsed_lines)):
        example = str(cluster.example.get("raw_text", "")).strip()
        if not example:
            continue
        escalation = escalate_line(example, valid_paths=valid_paths)
        suggestions.append(
            {
                "line": example,
                "template": cluster.template,
                "template_id": cluster.template_id,
                "occurrences": cluster.cluster_size,
                "line_number": cluster.example.get("line_number", 0),
                "block": cluster.example.get("block") or "",
                "suggested_path": escalation.path,
                "confidence": round(escalation.confidence, 4),
                "tier": escalation.tier,
                "parser_id": escalation.parser_id,
                "abstained": escalation.abstained,
            }
        )
    suggestions.sort(key=lambda item: (-item["occurrences"], item["line_number"]))
    return suggestions


def _facts_for_device(conn, device_id: str) -> list[CanonicalFact]:
    """Rehydrate a device's stored facts into canonical objects."""
    rows = conn.execute(
        "SELECT * FROM canonical_facts WHERE device_id = ? ORDER BY id",
        (device_id,),
    ).fetchall()
    return [
        CanonicalFact(
            path=row["path"],
            value=json.loads(row["value"]) if row["value"] else None,
            present=bool(row["present"]),
            source_file=row["source_file"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            raw_text=row["raw_text"],
            parser_id=row["parser_id"],
            confidence=row["confidence"],
        )
        for row in rows
    ]


# ─── Request/Response models ──────────────────────────────────────────


class SimulateRequest(BaseModel):
    config_text: str
    source_file: str = "inline.conf"


class SimulateResponse(BaseModel):
    device: dict[str, Any]
    findings: list[dict[str, Any]]
    summary: dict[str, Any]
    unparsed_count: int
    ai_classifications: list[dict[str, Any]] = []
    ai_status: dict[str, Any] = {}
    #: PRAMAN compliance score over selected, applicable, decided controls.
    score: dict[str, Any] = {}
    #: Catalogue/rule selection counts — how much of the standard was in scope.
    stats: dict[str, Any] = {}
    #: Facts that came from operator-taught patterns rather than shipped packs.
    taught_facts: int = 0


class IngestResponse(BaseModel):
    device_id: str
    config_hash: str
    facts_count: int
    message: str
    vendor: str = ""
    unparsed_count: int = 0
    queued_templates: int = 0


class CommitRequest(BaseModel):
    device_id: str


class CommitResponse(BaseModel):
    audit_id: str
    seq: int
    record_hash: str
    findings_count: int
    merkle_root: str = ""
    prev_hash: str = ""
    #: The operator the ledger now attributes this audit to. Echoed back so the
    #: UI can show who it recorded rather than who the browser thinks is logged
    #: in — the server's answer is the one that was hashed.
    actor: str = ""


class MapRequest(BaseModel):
    """One taught mapping.

    ``drain3_template`` keeps its name for compatibility with the existing
    clients and tests, but it accepts a raw example line just as happily: the
    store masks whatever it is given, and masking a template is a no-op. That is
    the difference between an operator pasting the line they are looking at and
    an operator hand-composing ``<*>`` tokens.
    """

    drain3_template: str = Field(..., min_length=1)
    canonical_path: str = Field(..., min_length=1)
    #: Accepted and **ignored**. Who taught a mapping is now the authenticated
    #: operator, not a string the client chose: a self-declared name sitting next
    #: to a real identity system is a spoof waiting to be used, and a mapping
    #: changes what every future audit of that platform will say. Kept on the
    #: model so existing clients that still send it get a 200 rather than a 422
    #: they cannot act on.
    admin_id: str = ""
    note: str = ""
    #: Which pack the mapping applies to. ``*`` means every pack.
    vendor: str = ANY_VENDOR
    #: Which masked operand in the template carries the value.
    value_index: int = 0


class RetireRequest(BaseModel):
    drain3_template: str = Field(..., min_length=1)


# ─── Meta endpoints ────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Liveness plus what is actually loaded.

    The version block is not decoration: it is how an operator confirms that a
    pattern pack they dropped in, or a mapping they taught, is in force — the
    counters move when a hot reload happens, which makes the reload observable
    rather than a claim in a README.
    """
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "description": APP_DESCRIPTION,
        "runtime": STATE.versions(),
        "ai": _ai_status(),
    }


@app.get("/vendors", dependencies=[Depends(REQUIRE_VIEWER)])
async def list_vendors() -> JSONResponse:
    """Vendors the loaded pattern packs can parse (C5)."""
    STATE.registry.library.reload_if_changed()
    packs = STATE.registry.library.packs()
    return JSONResponse(
        content={
            "vendors": [
                {
                    "vendor": pack.vendor,
                    "os_family": pack.os_family,
                    "parser_id": pack.parser_id,
                    "patterns": pack.pattern_count(),
                    "canonical_paths": len(pack.referenced_paths()),
                    "description": getattr(pack, "description", "") or "",
                }
                for pack in sorted(packs.values(), key=lambda p: p.vendor)
            ],
            "count": len(packs),
        }
    )


@app.get("/frameworks", dependencies=[Depends(REQUIRE_VIEWER)])
async def list_frameworks(vendor: str = "", os_family: str = "") -> JSONResponse:
    """The compliance corpus: what is ingested, and how much of it is automated (C3, C5).

    ``/vendors`` answers "what can you parse". This answers "what can you *assess*",
    and the two are different questions — a vendor with a pattern pack and no
    mapping pack parses cleanly and scores nothing.

    Every catalog reports ``controls`` and ``automated`` together and neither is
    ever returned without the other. That is the same rule
    ``scripts/build_catalog.py --list`` follows, for the same reason: a catalog
    inventory on its own overstates what the tool assesses, because a framework can
    be fully normalised and carry no rules at all. A client that renders only
    ``controls`` would be reporting 3,366 controls of coverage for 301 controls of
    checking.

    ``evaluation`` distinguishes the two kinds of framework. A *direct* framework
    has rules of its own. A *projected* one (NIST 800-53, ISO 27001) is rolled up
    from the cross-references its direct contributors carry, so its automated count
    is structurally zero here and its real coverage is a property of the device
    rather than of the catalog — ask ``/devices/{id}`` for that.

    ``?vendor=`` and ``?os_family=`` narrow the inventory to the catalogs that apply
    to one platform, which is the question an operator actually has: not "what
    frameworks do you support" but "what will you check on *this* box".
    """
    evaluator = STATE.evaluator()

    automated: dict[str, set[str]] = {}
    for rule in evaluator.rules:
        automated.setdefault(rule.catalog.catalog_id, set()).add(rule.catalog.control_id)

    catalogs = evaluator.catalogs
    if vendor or os_family:
        # A catalog with no vendor list is publisher material that names no
        # platform, so it cannot be claimed for one; `applies_to` decides, not this
        # route, so the filter agrees with what the evaluator would actually run.
        catalogs = [c for c in catalogs if c.applies_to(vendor, os_family)]

    grouped: dict[str, list[dict[str, Any]]] = {}
    for catalog in sorted(catalogs, key=lambda c: (c.framework, c.catalog_id)):
        covered = len(automated.get(catalog.catalog_id, ()))
        total = len(catalog.controls)
        grouped.setdefault(catalog.framework, []).append(
            {
                "catalog_id": catalog.catalog_id,
                "benchmark": catalog.benchmark,
                "benchmark_version": catalog.benchmark_version,
                "vendors": list(catalog.vendors),
                "os_families": list(catalog.os_families),
                "controls": total,
                "automated": covered,
                # A zero *numerator* is a real measurement and is reported as 0.0:
                # "none of this catalog's 47 controls is automated" is a fact about
                # the tool, and hiding it behind an em dash would be the flattering
                # direction. That is the opposite of a device's compliance score,
                # where a zero *denominator* means nothing was decided and 0.0%
                # would be a verdict the evidence does not support. `None` here is
                # only for the degenerate empty catalog, which no built catalog is.
                "coverage_pct": round(100.0 * covered / total, 1) if total else None,
                "source_document": catalog.source_document,
                "source_url": catalog.source_url,
            }
        )

    frameworks: list[dict[str, Any]] = []
    for name in sorted(grouped):
        entries = grouped[name]
        controls = sum(e["controls"] for e in entries)
        covered = sum(e["automated"] for e in entries)
        frameworks.append(
            {
                "framework": name,
                "evaluation": "direct" if name in DIRECT_FRAMEWORKS else "projected",
                "catalogs": len(entries),
                "controls": controls,
                "automated": covered,
                "coverage_pct": round(100.0 * covered / controls, 1) if controls else None,
                "benchmarks": entries,
            }
        )

    controls_total = sum(f["controls"] for f in frameworks)
    automated_total = sum(f["automated"] for f in frameworks)
    return JSONResponse(
        content={
            "frameworks": frameworks,
            "totals": {
                "frameworks": len(frameworks),
                "catalogs": sum(f["catalogs"] for f in frameworks),
                "controls": controls_total,
                "automated": automated_total,
                "coverage_pct": (
                    round(100.0 * automated_total / controls_total, 1)
                    if controls_total
                    else None
                ),
            },
            "filter": {"vendor": vendor, "os_family": os_family},
            "note": (
                "Unautomated controls are reported as 'notchecked' with a reason and "
                "excluded from the compliance score in both directions, so they can "
                "never flatter a device. Per-control reasoning is in docs/GAPS.md."
            ),
        }
    )


@app.get("/canonical/paths", dependencies=[Depends(REQUIRE_VIEWER)])
async def list_canonical_paths() -> JSONResponse:
    """The canonical vocabulary, grouped by family.

    The training GUI binds its path picker to this rather than to a hardcoded
    list, so a path added to the schema is selectable immediately — and a path
    that is *not* in the schema cannot be chosen, which is what keeps a taught
    mapping from emitting a fact no rule can ever read.
    """
    families = path_families()
    return JSONResponse(
        content={
            "paths": canonical_paths_sorted(),
            "count": len(canonical_paths_sorted()),
            "families": {
                family: sorted(members) for family, members in sorted(families.items())
            },
        }
    )


# ─── C1: ingestion ─────────────────────────────────────────────────────


@app.post(
    "/simulate",
    response_model=SimulateResponse,
    dependencies=[Depends(REQUIRE_AUDITOR)],
)
async def simulate(req: SimulateRequest) -> SimulateResponse:
    """Parse, evaluate, and return findings without writing anything.

    Idempotent by construction: the same bytes produce the same device id, the
    same facts, the same verdicts, and the same score, because every step from
    parse to verdict is a pure function of the configuration and the loaded
    rules. Nothing here touches the ledger — that is ``/audit/commit``.
    """
    result = parse_config(normalise(req.config_text), req.source_file)
    evaluator, findings = evaluate_facts(
        result.facts,
        result.device.vendor.value,
        result.device.os_family.value,
        os_version=result.device.os_version,
    )
    stats = evaluator.last_stats
    return SimulateResponse(
        device=result.device.model_dump(mode="json"),
        findings=[f.model_dump(mode="json") for f in findings],
        summary=build_summary(findings),
        unparsed_count=len(result.unparsed_lines),
        ai_classifications=_classify_unparsed(result),
        ai_status=_ai_status(),
        score=compute_compliance_score(findings),
        stats=(
            {
                "catalogs_selected": stats.catalogs_selected,
                "catalogs_skipped": stats.catalogs_skipped,
                "controls_total": stats.controls_total,
                "controls_automated": stats.controls_automated,
                "rules_loaded": stats.rules_loaded,
                "rules_inapplicable": stats.rules_inapplicable,
                "automation_coverage": round(stats.automation_coverage, 4),
            }
            if stats
            else {}
        ),
        taught_facts=sum(1 for f in result.facts if f.parser_id.endswith("+taught")),
    )


@app.post(
    "/ingest",
    response_model=IngestResponse,
    dependencies=[Depends(REQUIRE_AUDITOR)],
)
async def ingest_file(file: UploadFile = File(...)) -> IngestResponse:
    """Ingest one configuration file and persist its canonical facts."""
    raw = await _read_upload(file)
    filename = file.filename or "upload.conf"
    result = parse_config(_decode_config(raw), filename)

    conn = STATE.connect()
    try:
        queued = _store_parse(conn, result, filename)
    finally:
        conn.close()

    return IngestResponse(
        device_id=result.device.device_id,
        config_hash=result.device.config_hash,
        facts_count=len(result.facts),
        vendor=result.device.vendor.value,
        unparsed_count=len(result.unparsed_lines),
        queued_templates=queued,
        message=(
            f"Ingested {filename} as device '{result.device.device_id}' "
            f"({len(result.facts)} facts, {len(result.unparsed_lines)} lines "
            f"unrecognised across {queued} templates)"
        ),
    )


@app.post("/ingest/bulk", dependencies=[Depends(REQUIRE_AUDITOR)])
async def ingest_bulk(
    file: UploadFile = File(...),
    background: bool = Query(
        False,
        description=(
            "Return 202 and a job_id immediately instead of holding the request "
            "open. Poll GET /jobs/{job_id} for progress."
        ),
    ),
) -> JSONResponse:
    """Ingest a ZIP archive of configurations — the estate-scale path (C1).

    The archive is treated as hostile input, because an auditor is handed
    archives by people and processes they do not control. Enforced before any
    member is read: total upload size, member count, per-member uncompressed
    size, and total uncompressed size. Directory traversal in member names is
    rejected outright even though nothing is written to disk, since the name is
    stored as provenance and rendered in the UI.

    One member failing does not fail the archive. A 400-device upload where two
    files are Word documents should ingest 398 devices and say which two failed —
    an all-or-nothing bulk import is a bulk import that never completes.

    ``background=true`` runs the same walk on the job queue and returns a
    ``job_id`` at once. It is opt-in rather than the default because changing the
    shape of an existing route's response is how you break every client that
    already calls it; the archive ceilings (2,000 members, 512 MB expanded) are
    nonetheless far wider than a synchronous request can carry, so the async mode
    is the one a real estate should use. Validation happens *before* the 202, so
    a malformed archive still fails fast with a 400 rather than succeeding into a
    job that immediately dies.
    """
    raw = await _read_upload(file)
    try:
        archive, members = open_archive(raw)
    except ArchiveRejectedError as err:
        raise HTTPException(status_code=err.status_code, detail=err.detail) from err

    if background:
        job = QUEUE.submit(
            "ingest_bulk",
            lambda job: _run_bulk_ingest(job, archive, members),
            label=file.filename or "archive.zip",
            total=len(members),
        )
        return JSONResponse(status_code=202, content=job.as_dict(include_items=False))

    job = Job(job_id="", kind="ingest_bulk", total=len(members))
    with archive:
        _run_bulk_ingest(job, archive, members)
    return JSONResponse(
        content={
            "total_files": len(job.results) + len(job.errors),
            "success": len(job.results),
            "failed": len(job.errors),
            "results": job.results,
            "errors": job.errors,
        }
    )


def _run_bulk_ingest(
    job: Job, archive: zipfile.ZipFile, members: list[zipfile.ZipInfo]
) -> None:
    """Parse and store every member, recording progress on ``job``.

    Runs on the request thread in synchronous mode and on the queue's worker
    thread otherwise, which is why it opens its own connection: a SQLite
    connection belongs to the thread that created it.
    """
    conn = STATE.connect()
    try:
        for outcome in read_members(archive, members, _decode_config):
            job.raise_if_cancelled()
            if outcome.error is not None:
                job.errors.append(
                    {"file": outcome.name, "status": "failed", "error": outcome.error}
                )
            else:
                try:
                    parsed = parse_config(outcome.text, outcome.name)
                    queued = _store_parse(conn, parsed, outcome.name)
                    job.results.append(
                        {
                            "file": outcome.name,
                            "device_id": parsed.device.device_id,
                            "hostname": parsed.device.hostname,
                            "vendor": parsed.device.vendor.value,
                            "facts_count": len(parsed.facts),
                            "unparsed_count": len(parsed.unparsed_lines),
                            "queued_templates": queued,
                            "status": "ok",
                        }
                    )
                except Exception as exc:
                    job.errors.append(
                        {
                            "file": outcome.name,
                            "status": "failed",
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
            job.done += 1
    finally:
        conn.close()
        if job.job_id:
            # The async path owns the archive handle; the synchronous path holds
            # it in a `with` block that is still open around this call.
            archive.close()


# ─── C3/C4: audit and reports ──────────────────────────────────────────


@app.post("/audit/commit", response_model=CommitResponse)
async def audit_commit(
    req: CommitRequest,
    principal: Principal = Depends(REQUIRE_APPROVER),
) -> CommitResponse:
    """Write one immutable ``AuditRecord`` to the hash-chained ledger.

    The record binds the verdicts to ``config_hash``, so "these findings came
    from those exact bytes" is checkable later without trusting this process.
    ``prev_hash`` chains it to its predecessor and the Ed25519 signature covers
    the record hash: tampering with any earlier record invalidates every record
    after it, which is what ``/audit/verify`` detects.

    It also records **who** committed it. ``actor`` is a hashed field, so the
    identity is covered by the record hash and the signature on exactly the same
    terms as the verdicts — see ``backend/canonical/findings.py``. This is the one
    route where the role gate is load-bearing beyond access control: an auditor
    may upload and simulate all day, but only an approver can turn a simulation
    into evidence, and the evidence says which approver did.
    """
    conn = STATE.connect()
    try:
        device_row = require_device(conn, req.device_id)
        facts = _facts_for_device(conn, req.device_id)
        _, findings = evaluate_facts(
            facts,
            device_row["vendor"],
            device_row["os_family"],
            os_version=device_row["os_version"],
        )

        audit_id = str(uuid.uuid4())
        findings_dicts = [f.model_dump(mode="json") for f in findings]
        summary = build_summary(findings)
        seq = get_latest_seq(conn) + 1
        prev_hash = get_prev_hash(conn)
        merkle_root = compute_merkle_root(findings_dicts)

        # Exactly the columns of the ledger row, and no more. The findings are
        # bound in by ``merkle_root``; putting the list itself here would mean
        # hashing a key that the verifier — which reads the row back from SQLite,
        # where the findings live in their own table — can never see.
        #
        # ``actor`` is the authenticated operator, not a value the client sent.
        # A request-supplied identity would let anyone with an auditor token
        # commit an audit under the assessor's name, which is worse than no
        # identity at all: it produces a signed, hash-chained record attributing
        # a decision to somebody who never made it.
        record = {
            "audit_id": audit_id,
            "device_id": req.device_id,
            "config_hash": device_row["config_hash"],
            "created_at": utc_now_iso(),
            "actor": principal.username,
            "summary": summary,
            "seq": seq,
            "prev_hash": prev_hash,
            "merkle_root": merkle_root,
        }
        record_hash = compute_record_hash(record)
        signature = sign_record(record_hash)

        conn.execute(
            """
            INSERT INTO audit_records
            (audit_id, device_id, config_hash, created_at, actor, summary,
             seq, prev_hash, record_hash, merkle_root, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                req.device_id,
                device_row["config_hash"],
                record["created_at"],
                principal.username,
                json.dumps(summary),
                seq,
                prev_hash,
                record_hash,
                merkle_root,
                signature,
            ),
        )
        store_findings(conn, audit_id, req.device_id, findings_dicts)
        conn.commit()
    finally:
        conn.close()

    return CommitResponse(
        audit_id=audit_id,
        seq=seq,
        record_hash=record_hash,
        findings_count=len(findings),
        merkle_root=merkle_root,
        prev_hash=prev_hash,
        actor=principal.username,
    )


@app.get("/devices", dependencies=[Depends(REQUIRE_VIEWER)])
async def list_devices() -> JSONResponse:
    """Every ingested device, with its latest audit if it has one."""
    conn = STATE.connect()
    try:
        rows = conn.execute(
            """
            SELECT d.*,
                   (SELECT audit_id FROM audit_records a
                     WHERE a.device_id = d.device_id
                     ORDER BY seq DESC LIMIT 1) AS latest_audit_id,
                   (SELECT seq FROM audit_records a
                     WHERE a.device_id = d.device_id
                     ORDER BY seq DESC LIMIT 1) AS latest_seq,
                   (SELECT COUNT(*) FROM canonical_facts f
                     WHERE f.device_id = d.device_id) AS facts_count
            FROM devices d ORDER BY d.device_id
            """
        ).fetchall()
    finally:
        conn.close()
    devices = []
    for row in rows:
        item = dict(row)
        for key in ("serials", "hardware"):
            if isinstance(item.get(key), str):
                item[key] = json.loads(item[key] or "[]")
        devices.append(item)
    return JSONResponse(content={"devices": devices, "count": len(devices)})


@app.get("/devices/{device_id}", dependencies=[Depends(REQUIRE_VIEWER)])
async def get_device(device_id: str) -> JSONResponse:
    """One device: identity, facts with provenance, and current verdicts.

    Verdicts are recomputed from the stored facts rather than read from the
    findings table, so this endpoint reflects the rules as they are *now*. That
    is the right answer for an operator asking "where do I stand", and the wrong
    answer for an auditor asking "what did we conclude in March" — which is what
    the ledger and ``/audit/records`` are for.
    """
    conn = STATE.connect()
    try:
        row = require_device(conn, device_id)
        facts = _facts_for_device(conn, device_id)
        _, findings = evaluate_facts(
            facts, row["vendor"], row["os_family"], os_version=row["os_version"]
        )
        audits = conn.execute(
            "SELECT audit_id, seq, created_at, actor, record_hash, merkle_root, summary"
            " FROM audit_records WHERE device_id = ? ORDER BY seq DESC",
            (device_id,),
        ).fetchall()
    finally:
        conn.close()

    device = dict(row)
    for key in ("serials", "hardware"):
        if isinstance(device.get(key), str):
            device[key] = json.loads(device[key] or "[]")
    history = []
    for audit in audits:
        item = dict(audit)
        if isinstance(item.get("summary"), str):
            item["summary"] = json.loads(item["summary"] or "{}")
        history.append(item)

    return JSONResponse(
        content={
            "device": device,
            "facts": [f.model_dump(mode="json") for f in facts],
            "findings": [f.model_dump(mode="json") for f in findings],
            "summary": build_summary(findings),
            "score": compute_compliance_score(findings),
            "audits": history,
            "taught_facts": [
                f.model_dump(mode="json")
                for f in facts
                if f.parser_id.endswith("+taught")
            ],
        }
    )


@app.get("/devices/{device_id}/report.pdf", dependencies=[Depends(REQUIRE_VIEWER)])
async def device_report_pdf(
    device_id: str,
    audit_id: str | None = Query(
        None, description="A specific committed audit; the latest when omitted."
    ),
) -> Response:
    """The per-device compliance report as a signed PDF (C4).

    Rendered from a *committed* audit, never from a simulation. A PDF is the
    artefact that leaves the building and gets attached to an email, so it must
    correspond to a ledger record that can be verified independently — if it
    could be produced from a simulation, the document and the evidence would be
    two different things.

    The signing outcome is reported in the ``X-PRAMAN-Signature`` header rather
    than hidden, so an unsigned report is visibly unsigned. The attach outcome is
    reported the same way in ``X-PRAMAN-Evidence``.
    """
    from backend.report.attach import attach_evidence
    from backend.report.render import render_pdf
    from backend.report.sign import sign_pdf

    conn = STATE.connect()
    try:
        device_row = require_device(conn, device_id)
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
                    + ". A report must cite a ledger record, so commit first: "
                    'POST /audit/commit {"device_id": "' + device_id + '"}'
                ),
            )
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE audit_id = ? ORDER BY id",
            (audit["audit_id"],),
        ).fetchall()
        # Earlier audits of this device, so the report can show a trend rather
        # than a single point. Bounded to the records at or before the one being
        # rendered: a report about seq 3 that plotted seq 7 would describe a
        # device state that postdates the document.
        history_rows = conn.execute(
            "SELECT seq, summary FROM audit_records WHERE device_id = ? AND seq <= ?"
            " ORDER BY seq",
            (device_id, audit["seq"]),
        ).fetchall()
        # The facts the verdicts were read from, embedded alongside them so the
        # PDF is checkable rather than merely readable. Ordered by path, not by
        # insertion, so two reports over one device produce identical bytes.
        fact_rows = conn.execute(
            "SELECT * FROM canonical_facts WHERE device_id = ?"
            " ORDER BY path, line_start",
            (device_id,),
        ).fetchall()
    finally:
        conn.close()

    # Projected through the same function the ledger verifier uses, so the
    # findings attached to the PDF are byte-for-byte the findings the committed
    # Merkle root was computed over. That is what lets a recipient check the
    # attachment against the ledger instead of taking the report's word for it.
    findings = [finding_from_row(row) for row in finding_rows]

    facts = []
    for row in fact_rows:
        item = dict(row)
        item.pop("id", None)
        item["value"] = json.loads(item["value"]) if item.get("value") else None
        item["present"] = bool(item.get("present"))
        facts.append(item)

    device = dict(device_row)
    for key in ("serials", "hardware"):
        if isinstance(device.get(key), str):
            device[key] = json.loads(device[key] or "[]")

    record = dict(audit)
    if isinstance(record.get("summary"), str):
        record["summary"] = json.loads(record["summary"] or "{}")

    # ``(seq, score)`` for the trend chart, computed with the engine's own
    # arithmetic from each stored summary. A past audit's findings are not
    # re-read: the ledger row already carries the counts, and re-deriving them
    # would be a table scan per plotted point.
    history: list[tuple[int, float]] = []
    for row in history_rows:
        stored = row["summary"]
        if isinstance(stored, str):
            stored = json.loads(stored or "{}")
        counts = (stored or {}).get("by_result") or stored or {}
        if isinstance(counts, dict):
            history.append((int(row["seq"]), score_from_counts(counts)))

    # render → attach → sign, in that order. Signing is an incremental update, so
    # anything attached after it would fall outside the byte range the signature
    # covers.
    pdf = render_pdf(
        device,
        findings,
        record.get("summary") or {},
        record,
        history=history,
    )
    evidence = attach_evidence(pdf, findings, facts)
    signed = sign_pdf(
        evidence.pdf,
        pfx_path=SIGNING_PFX_PATH,
        passphrase=SIGNING_PFX_PASSPHRASE,
        tsa_url=SIGNING_TSA_URL,
    )
    stem = device.get("hostname") or device_id
    return Response(
        content=signed.pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="praman-{stem}-seq{audit["seq"]}.pdf"'
            ),
            "X-PRAMAN-Signature": signed.header_value,
            "X-PRAMAN-Evidence": evidence.header_value,
            "X-PRAMAN-Record-Hash": record["record_hash"],
            "X-PRAMAN-Audit-Id": record["audit_id"],
        },
    )


#: Severity order for the remediation plan — worst first, unknown last.
#: An operator reading a fix list top-to-bottom should be closing the high-risk
#: gaps first, and ``control_id`` order would interleave them arbitrarily.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "unknown": 3}


@app.get("/devices/{device_id}/remediation", dependencies=[Depends(REQUIRE_VIEWER)])
async def device_remediation(
    device_id: str,
    audit_id: str | None = Query(
        None,
        description=(
            "A committed audit to take the verdicts from; the latest when omitted."
        ),
    ),
    control_id: str | None = Query(
        None, description="Narrow the plan to one control."
    ),
    results: str = Query(
        "fail",
        description=(
            "Comma-separated XCCDF results to include, or 'all'. Defaults to "
            "'fail' — the set that needs fixing."
        ),
    ),
) -> JSONResponse:
    """The device-specific remediation plan (C4).

    C4 asks for "device-specific step-by-step remediation CLI", and until this
    route existed the only place it appeared was inside the PDF: the UI could
    show an operator that a control failed and had no way to show them what to
    type. That is the half of the capability that matters operationally.

    Each entry is resolved by :func:`~backend.remediation.engine.resolve_remediation`
    from the publisher's own fix text — never generated (R3) — with the prompts
    rebuilt against *this* device's hostname. ``kind`` is the tri-state that keeps
    it honest: ``cli`` when commands were extracted, ``manual`` when the publisher
    wrote prose only, ``none`` when neither source has anything. A blank block is
    never returned as if there were nothing to do.

    The plan is not folded into ``/devices/{device_id}`` because that response
    already carries every finding — 1,462 on the shipped sample — and resolving
    remediation for all of them would mean 1,462 catalog lookups and a payload an
    order of magnitude larger, to answer a question about the 23 that failed.
    """
    from backend.canonical.findings import Result
    from backend.remediation.engine import resolve_remediation

    wanted: set[str] | None
    if results.strip().lower() == "all":
        wanted = None
    else:
        valid = {item.value for item in Result}
        wanted = {token.strip().lower() for token in results.split(",") if token.strip()}
        unknown = sorted(wanted - valid)
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown result value(s): {', '.join(unknown)}. Valid values are "
                    f"{', '.join(sorted(valid))}, or 'all'."
                ),
            )

    conn = STATE.connect()
    try:
        device_row = require_device(conn, device_id)
        if audit_id:
            audit = conn.execute(
                "SELECT audit_id, seq, created_at FROM audit_records"
                " WHERE audit_id = ? AND device_id = ?",
                (audit_id, device_id),
            ).fetchone()
            if audit is None:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"device '{device_id}' has no committed audit with audit_id "
                        f"'{audit_id}'"
                    ),
                )
        else:
            audit = conn.execute(
                "SELECT audit_id, seq, created_at FROM audit_records"
                " WHERE device_id = ? ORDER BY seq DESC LIMIT 1",
                (device_id,),
            ).fetchone()

        if audit is not None:
            # The committed verdicts, projected exactly as the ledger verifier and
            # the PDF read them, so a plan and a report about the same audit name
            # the same controls.
            rows = conn.execute(
                "SELECT * FROM findings WHERE audit_id = ? ORDER BY id",
                (audit["audit_id"],),
            ).fetchall()
            findings = [finding_from_row(row) for row in rows]
            basis = (
                f"the committed verdicts of audit {audit['audit_id']} (seq "
                f"{audit['seq']})"
            )
        else:
            # No commit yet. Re-evaluating the stored facts is the right fallback:
            # an operator who has just uploaded a config wants the fix list now,
            # and remediation text comes from the catalogs, not from the ledger,
            # so nothing here needs a signature to be true. The basis says which
            # it was, because "current rules" and "what we committed in March" are
            # different answers.
            facts = _facts_for_device(conn, device_id)
            _evaluator, evaluated = evaluate_facts(
                facts,
                device_row["vendor"],
                device_row["os_family"],
                os_version=device_row["os_version"],
            )
            findings = [f.model_dump(mode="json") for f in evaluated]
            basis = (
                "verdicts recomputed from the stored facts — this device has no "
                "committed audit, so there is nothing in the ledger to cite"
            )
    finally:
        conn.close()

    device = dict(device_row)
    for key in ("serials", "hardware"):
        if isinstance(device.get(key), str):
            device[key] = json.loads(device[key] or "[]")

    selected = [
        finding
        for finding in findings
        if (wanted is None or str(finding.get("result") or "").lower() in wanted)
        and (control_id is None or finding.get("control_id") == control_id)
    ]
    selected.sort(
        key=lambda f: (
            _SEVERITY_RANK.get(str(f.get("severity") or "unknown").lower(), 3),
            str(f.get("framework") or ""),
            str(f.get("control_id") or ""),
        )
    )

    plan: list[dict[str, Any]] = []
    for finding in selected:
        fix = resolve_remediation(finding, device)
        plan.append(
            {
                "control_id": fix.control_id,
                "framework": finding.get("framework"),
                "benchmark": finding.get("benchmark"),
                "benchmark_version": finding.get("benchmark_version"),
                "title": finding.get("title"),
                "result": finding.get("result"),
                "severity": finding.get("severity"),
                "kind": fix.kind,
                "guidance": fix.guidance,
                "source": fix.source,
                "verification": fix.verification,
                "rollback": fix.rollback,
                "risk": fix.risk,
                "notes": list(fix.notes),
                "is_actionable": fix.is_actionable,
                "requires_substitution": fix.requires_substitution,
                "steps": [
                    {
                        "mode": step.mode,
                        "command": step.command,
                        "prompt": step.prompt,
                        "placeholders": list(step.placeholders),
                        "is_runnable": step.is_runnable,
                    }
                    for step in fix.steps
                ],
            }
        )

    steps_total = sum(len(entry["steps"]) for entry in plan)
    return JSONResponse(
        content={
            "device_id": device_id,
            "hostname": device.get("hostname"),
            "vendor": device.get("vendor"),
            "audit_id": audit["audit_id"] if audit is not None else None,
            "seq": audit["seq"] if audit is not None else None,
            "created_at": audit["created_at"] if audit is not None else None,
            "basis": basis,
            "counts": {
                "controls": len(plan),
                "cli": sum(1 for e in plan if e["kind"] == "cli"),
                "manual": sum(1 for e in plan if e["kind"] == "manual"),
                "none": sum(1 for e in plan if e["kind"] == "none"),
                "requires_substitution": sum(
                    1 for e in plan if e["requires_substitution"]
                ),
                "commands": steps_total,
                "commands_runnable": sum(
                    1 for e in plan for s in e["steps"] if s["is_runnable"]
                ),
            },
            "plan": plan,
        }
    )


@app.get("/audit/records", dependencies=[Depends(REQUIRE_VIEWER)])
async def list_audit_records() -> JSONResponse:
    """The ledger, oldest first."""
    conn = STATE.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_records ORDER BY seq"
        ).fetchall()
    finally:
        conn.close()
    records = []
    for row in rows:
        item = dict(row)
        if isinstance(item.get("summary"), str):
            item["summary"] = json.loads(item["summary"] or "{}")
        records.append(item)
    return JSONResponse(content={"records": records, "count": len(records)})


@app.get("/audit/verify", dependencies=[Depends(REQUIRE_VIEWER)])
async def verify_chain_endpoint() -> JSONResponse:
    """Re-verify the whole ledger: Merkle roots, record hashes, links, signatures.

    The findings behind every record are loaded and their Merkle roots
    recomputed. Verifying the ledger rows alone would leave the one link that
    covers the actual verdicts unchecked, and report the result as sound.

    The operator list is loaded too, so ``actor_valid`` is a real check rather
    than a ``None``. A record whose actor is empty predates identity and shows up
    here as the reason to run ``MANUAL_COMMANDS.md`` Step 12.
    """
    from backend.ledger.chain import verify_chain

    conn = STATE.connect()
    try:
        rows = conn.execute("SELECT * FROM audit_records ORDER BY seq").fetchall()
        finding_rows = conn.execute("SELECT * FROM findings ORDER BY audit_id, id").fetchall()
        actors = known_actors(conn)
    finally:
        conn.close()

    records = []
    for row in rows:
        item = dict(row)
        if isinstance(item.get("summary"), str):
            item["summary"] = json.loads(item["summary"] or "{}")
        records.append(item)

    findings_by_audit: dict[str, list[dict[str, Any]]] = {}
    for row in finding_rows:
        findings_by_audit.setdefault(row["audit_id"], []).append(finding_from_row(row))

    verification = verify_chain(records, findings_by_audit, actors or None)
    return JSONResponse(
        content={
            "chain_length": len(records),
            "all_valid": all(entry["all_valid"] for entry in verification),
            "results": verification,
        }
    )


@app.get("/audit/access", dependencies=[Depends(REQUIRE_APPROVER)])
async def list_access_log(
    limit: int = Query(200, ge=1, le=2000),
    actor: str | None = Query(None, description="Filter to one operator."),
) -> JSONResponse:
    """The access log, newest first — who read or wrote what, and when.

    Approver-only. The log answers "who looked at the core router's findings",
    which means it is itself a map of who is investigating what; handing it to
    every viewer would make the surveillance mutual and the reviewer's work
    visible to the reviewed.

    An access log nobody can read is a table, not a control, which is why this
    route exists rather than leaving operators to open the database by hand.
    """
    conn = STATE.connect()
    try:
        if actor:
            rows = conn.execute(
                "SELECT * FROM access_log WHERE actor = ? ORDER BY id DESC LIMIT ?",
                (actor, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM access_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM access_log").fetchone()["n"]
    finally:
        conn.close()
    return JSONResponse(
        content={
            "entries": [dict(row) for row in rows],
            "count": len(rows),
            "total": total,
        }
    )


# ─── Identity ──────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=512)


class LoginResponse(BaseModel):
    token: str
    username: str
    role: str
    expires_at: str


@app.post("/auth/login", response_model=LoginResponse)
async def auth_login(req: LoginRequest, response: Response) -> LoginResponse:
    """Exchange a password for a bearer token.

    Login attempts have a per-username lockout. The lockout is
    per-username and in-process — see ``backend/app/auth.py``; on top of a
    0.2 s key derivation it makes online guessing pointless, and it is not the
    request-rate limiter ``docs/SECURITY.md`` still lists as missing.

    The response also sets an ``HttpOnly; SameSite=Strict`` cookie, which the
    server accepts on GET and HEAD only. That is not a second credential so much
    as a way for the browser to follow a download link: a navigation to
    ``/devices/{id}/report.pdf`` cannot carry an ``Authorization`` header. Because
    the cookie is refused on every state-changing method, it cannot be used to
    forge one, so there is no CSRF token to forget to check. The obvious
    alternative — a token in the query string — would have written live
    credentials into ``access_log``.
    """
    locked = lockout_remaining(req.username)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=(
                f"too many failed attempts for '{req.username}'. Try again in "
                f"{locked} seconds, or ask an administrator to reset the password."
            ),
            headers={"Retry-After": str(locked)},
        )

    conn = STATE.connect()
    try:
        if user_count(conn) == 0:
            raise HTTPException(
                status_code=503,
                detail=(
                    "no operator accounts exist yet. Create the first one on the "
                    "server with 'python scripts/manage_users.py add --username "
                    "<name> --role approver' (MANUAL_COMMANDS.md Step 13). There "
                    "is no default password. If signup is enabled, use Create an "
                    "account on the login screen or POST /auth/signup."
                ),
            )
        principal = authenticate(conn, req.username, req.password)
        if principal is None:
            note_login_failure(req.username)
            # One message for unknown user, wrong password and disabled account:
            # three distinguishable answers hand an attacker a user-enumeration
            # oracle, and the operator at the keyboard cannot act on the
            # difference anyway.
            raise HTTPException(status_code=401, detail="invalid credentials")
        clear_login_failures(req.username)
        token, expires_at = open_session(conn, principal)
    finally:
        conn.close()

    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return LoginResponse(
        token=token,
        username=principal.username,
        role=principal.role,
        expires_at=expires_at,
    )


@app.post("/auth/logout", dependencies=[Depends(REQUIRE_VIEWER)])
async def auth_logout(request: Request, response: Response) -> JSONResponse:
    """Revoke the token on this request.

    Server-side revocation, not just a cleared cookie: a token the client throws
    away is still a live credential to anyone who captured it.
    """
    token = bearer_token(request)
    conn = STATE.connect()
    try:
        revoked = close_session(conn, token)
    finally:
        conn.close()
    response.delete_cookie(COOKIE_NAME, path="/")
    return JSONResponse(content={"status": "ok", "revoked": revoked})


@app.get("/auth/whoami")
async def auth_whoami(
    principal: Principal = Depends(REQUIRE_VIEWER),
) -> JSONResponse:
    """Who the server thinks you are, and what that lets you do.

    The frontend calls this on load to decide whether to show the login overlay,
    and to grey out the controls a viewer cannot use. The permissions are computed
    from the role here rather than in JavaScript so the UI cannot disagree with
    the server about what is allowed — a greyed-out button is a courtesy, the
    403 is the control.
    """
    return JSONResponse(
        content={
            "username": principal.username,
            "role": principal.role,
            "may_ingest": principal.may(ROLE_AUDITOR),
            "may_commit": principal.may(ROLE_APPROVER),
        }
    )


# ─── C2: training module ───────────────────────────────────────────────


@app.get("/training/queue", dependencies=[Depends(REQUIRE_VIEWER)])
async def training_queue(
    vendor: str | None = Query(None, description="Filter to one vendor."),
    limit: int = Query(200, ge=1, le=1000),
) -> JSONResponse:
    """Templates awaiting a mapping, busiest first.

    One entry per template across the whole estate, not one per line: mapping
    ``logging host <*>`` once resolves it on every device that has it, so
    presenting it once is what makes the queue finite work rather than an
    inbox that grows with the fleet.
    """
    conn = STATE.connect()
    try:
        items = pending_queue(conn, vendor=vendor, limit=limit)
        counts = queue_counts(conn)
    finally:
        conn.close()
    return JSONResponse(
        content={"queue": items, "count": len(items), "counts": counts}
    )


@app.post("/training/map")
async def training_map(
    req: MapRequest,
    principal: Principal = Depends(REQUIRE_APPROVER),
) -> JSONResponse:
    """Teach the parser one line format — no redeploy, no restart (C2).

    The mapping is data. It is validated here (the path must exist in the
    canonical schema, the template must compile, the operand must exist) and
    stored; the pattern registry picks it up on the next parse because it
    fingerprints the mapping table. So the round trip an admin experiences is:
    upload a config, see the unrecognised line, map it, re-upload, and the fact
    is there — in one running process.

    Approver, not auditor. A mapping is not an observation about one device: it
    changes how every future config of that platform is read, so a wrong one
    manufactures confidently wrong facts fleet-wide. ``admin_id`` on the request
    is ignored in favour of the authenticated operator.
    """
    conn = STATE.connect()
    try:
        stored = upsert_mapping(
            conn,
            template=req.drain3_template,
            canonical_path=req.canonical_path,
            admin_id=principal.username,
            note=req.note,
            vendor=req.vendor or ANY_VENDOR,
            value_index=req.value_index,
        )
        counts = queue_counts(conn)
    except MappingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        conn.close()

    # Not required for correctness — the provider notices the table moved on its
    # own — but dropping the cache here means the very next request cannot be
    # served from a snapshot taken microseconds before this write.
    STATE.learned.invalidate()

    return JSONResponse(
        content={
            "status": "ok",
            "message": (
                f"Mapped template '{stored['template']}' → "
                f"'{stored['canonical_path']}'. In force now; no redeploy."
            ),
            "admin_id": principal.username,
            "mapping": stored,
            "queue_counts": counts,
        }
    )


@app.get("/training/mappings", dependencies=[Depends(REQUIRE_VIEWER)])
async def training_mappings(
    vendor: str | None = Query(None),
    include_retired: bool = Query(False),
) -> JSONResponse:
    """Every taught mapping, and any that are not currently in force.

    ``not_in_force`` is surfaced rather than logged: a mapping that stopped
    compiling is silent loss of parsing coverage, and the operator who taught it
    is the only person who can fix it.
    """
    conn = STATE.connect()
    try:
        mappings = list_mappings(
            conn, vendor=vendor, include_retired=include_retired
        )
    finally:
        conn.close()
    status = STATE.learned_status(vendor or ANY_VENDOR)
    return JSONResponse(
        content={
            "mappings": mappings,
            "count": len(mappings),
            "in_force": len(status.patterns),
            "not_in_force": status.skipped,
        }
    )


@app.post("/training/retire", dependencies=[Depends(REQUIRE_APPROVER)])
async def training_retire(req: RetireRequest) -> JSONResponse:
    """Withdraw a mapping, keeping the record that it once applied.

    Approver, for the same reason as ``/training/map``: retiring a mapping
    silently removes parsing coverage, and the facts it used to produce simply
    stop appearing.
    """
    conn = STATE.connect()
    try:
        changed = retire_mapping(conn, req.drain3_template)
    finally:
        conn.close()
    STATE.learned.invalidate()
    if not changed:
        raise HTTPException(
            status_code=404,
            detail=(
                f"no active mapping for '{req.drain3_template}'. It may already "
                "be retired; GET /training/mappings?include_retired=true"
            ),
        )
    return JSONResponse(content={"status": "ok", "retired": req.drain3_template})


@app.get("/training/export", dependencies=[Depends(REQUIRE_VIEWER)])
async def training_export(vendor: str | None = Query(None)) -> Response:
    """Render taught mappings as pattern-pack YAML for review and promotion.

    The store is an operator's working surface; a pack under
    ``data/ingest/patterns/`` is the reviewed artefact that ships. Without this,
    an estate's real parsing knowledge accumulates in a SQLite table nobody
    reviews — so promotion is a first-class operation.
    """
    conn = STATE.connect()
    try:
        mappings = list_mappings(conn, vendor=vendor)
    finally:
        conn.close()
    body = export_pack_patterns(mappings) if mappings else "patterns: []\n"
    return Response(
        content=body,
        media_type="text/yaml; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="taught-{vendor or "all"}.yaml"'
            )
        },
    )


# ─── Machine-readable exports ──────────────────────────────────────────
#
# OSCAL Assessment Results and SARIF live in their own router because main.py is
# already far over the 500-line file limit and they need nothing from it beyond
# the shared parse/evaluate funnel in backend/app/services.py. Mounted here,
# above the static handler below, so no asset name can shadow either route.

app.include_router(export_router)
app.include_router(jobs_router)
app.include_router(signup_router)


# ─── Static frontend ───────────────────────────────────────────────────
#
# Declared last so no asset name can shadow an API route. Only files that exist
# under frontend/ are served, and only by name — there is no SPA catch-all,
# because a fallback that returns index.html for every unknown path turns an API
# typo into a silent 200 with HTML in it.

_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
_ASSET_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".map": "application/json",
}

if _FRONTEND_DIR.is_dir():

    @app.get("/", include_in_schema=False)
    async def serve_index() -> Response:
        return _serve_asset("index.html")

    @app.get("/{asset:path}", include_in_schema=False)
    async def serve_asset(asset: str) -> Response:
        return _serve_asset(asset)


def _serve_asset(asset: str) -> Response:
    """Return one file from the frontend directory, or 404.

    The resolved path is checked to be inside the frontend directory, which is
    what stops ``GET /../../data/private/ed25519_signing.key`` from being a
    key disclosure. Checking after resolution rather than pattern-matching the
    request string is deliberate: encodings and symlinks defeat string checks.
    """
    candidate = (_FRONTEND_DIR / asset).resolve()
    try:
        candidate.relative_to(_FRONTEND_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="not found") from None
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail=f"no such asset: {asset}")
    media_type = _ASSET_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
    return Response(
        content=candidate.read_bytes(),
        media_type=media_type,
        # No-cache on the UI: an operator who reloads after an upgrade must not
        # get last week's JavaScript talking to this week's API.
        headers={"Cache-Control": "no-cache"},
    )
