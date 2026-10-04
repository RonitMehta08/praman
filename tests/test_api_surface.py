"""Test: every HTTP route is exercised, and the hostile ones are exercised twice.

This module exists because an endpoint with no test is a feature the project
claims and nobody checks. Before it was written, five routes had **zero**
coverage anywhere in the suite — ``GET /vendors``, ``GET /canonical/paths``,
``GET /training/mappings``, ``POST /training/retire`` and
``GET /training/export`` — and three of those five are the C2 training module,
the capability PRAMAN makes the centrepiece. A demo would have been the first
thing to run them. (The training round trip has since moved to its own file,
``tests/test_api_training.py``; the inventory below still refuses to let it go
uncovered.)

Two things are asserted here that are not asserted anywhere else:

* **Route inventory.** ``test_every_declared_route_is_covered_here`` reads the
  application's own route table and fails if a route exists that this module
  never calls. Adding an endpoint therefore fails the suite until it is tested,
  which is the only mechanism that keeps a coverage claim true a month from now.
  A hand-maintained list would have drifted the first time somebody added a
  route in a hurry — the same drift that produced the five uncovered routes.

* **Refusals.** Size limits, traversal guards and malformed input are checked for
  the *refusal*, not just for "not a 500". An endpoint that accepts a zip bomb
  and dies of memory exhaustion and an endpoint that returns 413 both fail to
  produce a report; only one of them is a security control. The limits
  themselves live in ``backend/app/config.py`` and are read from there rather
  than duplicated, so raising a limit does not require editing a test to match.

Offline: no models, no network, no signing key required. The database is the
session-scoped throwaway from ``conftest.isolated_database``.
"""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.app.auth import COOKIE_NAME, clear_login_failures, hash_password
from backend.app.config import (
    FILE_ENCODING,
    MAX_ARCHIVE_MEMBERS,
    MAX_MEMBER_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    PROJECT_ROOT,
)
from backend.app.main import _SEVERITY_RANK, app
from backend.app.state import STATE
from backend.canonical.models import utc_now_iso
from backend.canonical.paths import canonical_paths_sorted
from backend.ledger.chain import VERIFY_KEY_PATH
from backend.rules.projection import DIRECT_FRAMEWORKS
from tests.conftest import TEST_OPERATOR, walk_routes

FIXTURE = PROJECT_ROOT / "test_configs" / "realistic" / "secure_baseline.conf"

#: Severity labels worst-first, derived from the application's own rank map
#: rather than restated. A hand-written copy would let the test keep passing
#: while the route's ordering changed underneath it — which is the only thing
#: the ordering assertion exists to catch.
_SEVERITY_ORDER = sorted(_SEVERITY_RANK, key=_SEVERITY_RANK.__getitem__)

#: The machine-readable export routes, tested in ``tests/test_api_export.py``.
#:
#: Listed rather than called here because what needs asserting about them is not
#: "the route answers" but *which source of truth it reads*: the OSCAL route must
#: refuse a device with no committed audit, and the SARIF route must not require
#: one. Those are four screens of assertions about ledger-versus-simulation, and
#: they belong beside the exporters' own tests. Naming exactly two paths keeps the
#: inventory a real gate — a third export route would still fail it.
EXPORT_ROUTES = {"/devices/{device_id}/oscal.json", "/simulate/sarif"}

#: The three ``/jobs`` routes, for the same reason and with the same limit. What
#: can break about them is not "the route answers" but the queue semantics
#: underneath: cancellation stops at an item boundary and keeps finished work,
#: "already finished" is a 409 and not a 404, and a job that has aged out of the
#: bounded in-memory history 404s with a message saying where the data went.
#: ``tests/test_job_queue.py`` asserts all of that against a real archive, twice
#: — once through the queue directly and once through ``POST /ingest/bulk
#: ?background=true``. Naming exactly three paths keeps this a gate: a fourth
#: job route would still fail it.
JOB_ROUTES = {"/jobs", "/jobs/{job_id}", "/jobs/{job_id}/cancel"}

#: The five ``/training`` routes, tested in ``tests/test_api_training.py``. Same
#: reason once more: the C2 loop is one *ordered* workflow — teach, list, export,
#: retire, retire again — and the thing worth proving is that the same mapping is
#: visible at each stage. Held here it read like a set of independent surface
#: checks that happened to run in order. Naming exactly five paths keeps this a
#: gate: a sixth training route would still fail it.
TRAINING_ROUTES = {
    "/training/queue",
    "/training/map",
    "/training/mappings",
    "/training/retire",
    "/training/export",
}

#: Routes that exist but are deliberately not called by name below.
#:
#: * The static asset catch-all is tested by pattern (index, a real asset, a
#:   traversal attempt) rather than by path; listing ``/{asset:path}`` as
#:   "covered" because one asset was fetched would be the misleading version.
#: * ``/docs``, ``/redoc`` and ``/docs/oauth2-redirect`` are declared by FastAPI,
#:   not by this project. ``test_openapi_schema_renders`` covers the thing that
#:   can actually break about them — a response model that no longer matches its
#:   endpoint — without asserting anything about somebody else's HTML.
ROUTES_COVERED_BY_PATTERN = {
    "/{asset:path}",
    "/",
    "/docs",
    "/redoc",
    "/docs/oauth2-redirect",
} | EXPORT_ROUTES | JOB_ROUTES | TRAINING_ROUTES


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding=FILE_ENCODING)


@pytest.fixture(scope="module")
def ingested(client: TestClient, config_text: str) -> str:
    """Ingest one device and return its id, for the routes that need one."""
    response = client.post(
        "/ingest",
        files={"file": ("api-surface.conf", config_text, "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["device_id"]


@pytest.fixture(scope="module")
def committed(client: TestClient, ingested: str) -> dict[str, str]:
    """Commit one audit for the ingested device and return the ledger record.

    Module-scoped and ordered after ``ingested`` because the report route returns
    409 until a device has a committed audit — signing a PDF over verdicts that
    were never written to the ledger would be a report nobody can later check,
    so the route refuses rather than obliging.
    """
    response = client.post("/audit/commit", json={"device_id": ingested})
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["record_hash"]
    assert record["audit_id"]
    return record


def _zip(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buf.getvalue()


def _bomb(name: str, *, declared_bytes: int) -> bytes:
    """A tiny archive whose central directory lies about how big it expands to.

    ``zipfile`` writes the local header at ``writestr`` time and the central
    directory at close, from ``filelist`` — so overwriting ``file_size`` in
    between produces exactly the mismatch a crafted archive carries, and
    ``infolist()`` on the reading side reports the lie.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, "hostname bomb\n")
        archive.filelist[0].file_size = declared_bytes
    return buf.getvalue()


# ─── The route inventory ───────────────────────────────────────────────


def test_every_declared_route_is_covered_here() -> None:
    """A route the app declares must be called by name in this module.

    Read off ``app.routes`` rather than a hand-written list, because a list is a
    thing somebody has to remember to update and this assertion is specifically
    about what happens when they do not. Walked through
    ``conftest.walk_routes`` so a router mounted with ``include_router`` is
    descended into rather than skipped — see that function for why skipping is
    the dangerous failure here.
    """
    declared = {
        path
        for path, _ in walk_routes(app.routes)
        if not path.startswith("/openapi")
    }
    source = Path(__file__).read_text(encoding=FILE_ENCODING)

    uncovered = sorted(
        path
        for path in declared - ROUTES_COVERED_BY_PATTERN
        # A parameterised path is covered if its literal prefix appears; the
        # request in the test carries a real id where the template has a brace.
        if path.split("{")[0].rstrip("/") not in source
    )
    assert not uncovered, (
        f"routes with no test in this module: {uncovered}. Add one, or add the "
        "path to ROUTES_COVERED_BY_PATTERN with a comment saying how it is "
        "covered instead. An endpoint nobody calls in the suite is a feature "
        "this project claims and does not check."
    )


def test_the_inventory_sees_routes_behind_an_included_router() -> None:
    """The inventory above is only a gate if it can see a mounted router.

    Asserted directly, because the way :func:`conftest.walk_routes` fails is by
    returning *fewer* paths — and a coverage check that under-reports its input
    passes quietly forever.
    """
    declared = {path for path, _ in walk_routes(app.routes)}
    missing = sorted((EXPORT_ROUTES | JOB_ROUTES | TRAINING_ROUTES) - declared)
    assert not missing, (
        f"a mounted router is invisible to the route inventory: {missing}. "
        "Every 'every route must ...' assertion in the suite walks this same "
        "function, so a router it cannot see is a router nothing checks."
    )


def test_openapi_schema_renders() -> None:
    """The schema must build.

    Cheap, and it fails loudly on a response model that no longer matches its
    endpoint — which is otherwise only discovered by whoever opens /docs during
    a demo.
    """
    schema = app.openapi()
    assert schema["info"]["title"]
    assert schema["paths"], "no documented paths"


# ─── Meta endpoints ────────────────────────────────────────────────────


def test_health_reports_what_is_loaded(client: TestClient) -> None:
    """``/health`` must answer "which rules and packs are in force", not just "ok".

    A liveness probe that returns a bare ``ok`` cannot distinguish a process
    serving the packs an operator just installed from one that failed to reload
    them, and that distinction is the entire premise of C2.
    """
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["description"]
    runtime = body["runtime"]
    assert runtime["pattern_packs"] >= 1
    assert runtime["rules_loaded"] >= 1
    assert runtime["catalogs_loaded"] >= 1
    assert runtime["controls_total"] > runtime["rules_loaded"], (
        "more rules than controls means a control is mapped more than once, or "
        "the catalogs failed to load — either way the coverage figure is wrong"
    )
    assert runtime["pattern_library_version"] and runtime["rule_pack_version"], (
        "the version fields are how an operator confirms a hot reload happened; "
        "empty ones make the reload a claim rather than an observation"
    )
    assert "ai" in body


def test_vendors_lists_every_loaded_pattern_pack(client: TestClient) -> None:
    """C5's claim is checkable: the API says which platforms it can parse.

    Each entry carries its pattern and canonical-path counts because "we support
    vendor X" is not a useful answer on its own — a pack with four patterns and a
    pack with four hundred both satisfy a bare vendor list.
    """
    body = client.get("/vendors").json()
    assert body["count"] == len(body["vendors"]) >= 1

    vendors = {entry["vendor"] for entry in body["vendors"]}
    assert "cisco_ios" in vendors, f"cisco_ios pack not loaded; got {vendors}"

    for entry in body["vendors"]:
        assert entry["parser_id"], f"{entry['vendor']}: no parser_id"
        assert entry["patterns"] > 0, f"{entry['vendor']}: a pack with no patterns"
        assert entry["canonical_paths"] > 0, (
            f"{entry['vendor']}: a pack that emits no canonical path parses text "
            "into nothing a rule can read"
        )

    ordered = [entry["vendor"] for entry in body["vendors"]]
    assert ordered == sorted(ordered), "vendor order must be stable for the UI"


def test_frameworks_never_reports_a_control_count_without_an_automated_count(
    client: TestClient,
) -> None:
    """C3's breadth is discoverable, and it cannot be quoted misleadingly.

    ``/vendors`` says what parses; this says what is *assessed*, and the two differ —
    a vendor with a pattern pack and no mapping pack parses cleanly and scores
    nothing. The assertion that matters is structural rather than numeric: every
    level of the response carries ``controls`` and ``automated`` together, so a
    client cannot render one without the other. Without that, this route would
    happily support "PRAMAN covers 3,366 controls", which is true of the corpus and
    false of the tool by a factor of eleven.

    The totals are also checked against the evaluator directly rather than against
    literals. Hardcoding 301 here would turn every new mapping pack into a failing
    test, and the thing worth protecting is the invariant, not the number.
    """
    body = client.get("/frameworks").json()
    evaluator = STATE.evaluator()

    expected_automated = len(
        {(r.catalog.catalog_id, r.catalog.control_id) for r in evaluator.rules}
    )
    expected_controls = sum(len(c.controls) for c in evaluator.catalogs)
    assert body["totals"]["catalogs"] == len(evaluator.catalogs)
    assert body["totals"]["controls"] == expected_controls
    assert body["totals"]["automated"] == expected_automated

    # The pair must survive at every level, because a UI binds to whichever one it
    # finds and a missing key is rendered as absent, not as an error.
    for framework in body["frameworks"]:
        assert {"controls", "automated"} <= framework.keys(), framework["framework"]
        assert framework["evaluation"] in {"direct", "projected"}
        rolled = sum(b["automated"] for b in framework["benchmarks"])
        assert rolled == framework["automated"], (
            f"{framework['framework']}: per-benchmark automated counts sum to "
            f"{rolled} but the framework reports {framework['automated']}"
        )
        for benchmark in framework["benchmarks"]:
            assert {"controls", "automated"} <= benchmark.keys(), benchmark["catalog_id"]
            assert benchmark["automated"] <= benchmark["controls"], (
                f"{benchmark['catalog_id']}: more automated controls than the "
                "catalog contains, so a rule points at a control_id the catalog "
                "does not define"
            )

    # A projected framework must report zero of its own, or the distinction between
    # direct and projected has stopped meaning anything.
    projected = [f for f in body["frameworks"] if f["evaluation"] == "projected"]
    assert projected, "no projected framework loaded, so this assertion proves nothing"
    for framework in projected:
        assert framework["automated"] == 0, (
            f"{framework['framework']} is projected but claims "
            f"{framework['automated']} rules of its own"
        )

    direct = {f["framework"] for f in body["frameworks"] if f["evaluation"] == "direct"}
    assert direct == set(DIRECT_FRAMEWORKS) & {
        c.framework for c in evaluator.catalogs
    }, f"direct/projected split disagrees with the projection module: {direct}"


def test_frameworks_vendor_filter_narrows_to_what_applies_to_that_platform(
    client: TestClient,
) -> None:
    """The useful question is "what will you check on *this* box", not "what do you support".

    Filtering is delegated to ``ControlCatalog.applies_to`` rather than reimplemented
    in the route, so this test's job is to prove the filter is actually wired and
    actually narrows — a filter that silently ignored its arguments would return the
    full corpus and look perfectly healthy.
    """
    everything = client.get("/frameworks").json()
    asa = client.get("/frameworks", params={"vendor": "cisco_asa", "os_family": "asa"}).json()

    assert asa["filter"] == {"vendor": "cisco_asa", "os_family": "asa"}
    assert 0 < asa["totals"]["catalogs"] < everything["totals"]["catalogs"], (
        "the ASA filter returned either nothing or everything; in both cases it is "
        "not filtering"
    )

    named = {
        b["catalog_id"] for f in asa["frameworks"] for b in f["benchmarks"]
    }
    assert any("asa" in cid for cid in named), f"no ASA catalog survived the filter: {named}"
    assert not any("juniper" in cid or "fortinet" in cid for cid in named), (
        f"a non-ASA vendor's catalog was returned for an ASA query: {named}"
    )

    # The ASA has a CIS mapping pack, so this must be a real score rather than a
    # wall of zeroes — that regression is exactly what shipped once already.
    cis = next((f for f in asa["frameworks"] if f["framework"] == "CIS"), None)
    assert cis is not None and cis["automated"] > 0, (
        "the ASA reports no automated CIS controls, so either the mapping pack "
        "stopped loading or the filter dropped it"
    )


def test_canonical_paths_matches_the_schema_on_disk(client: TestClient) -> None:
    """The training GUI's path picker is bound to this route.

    If it could return a path the schema does not declare, an operator could
    teach a mapping that emits a fact no rule will ever read — and the mapping
    would look successful. So the assertion is equality with the authored enum,
    not a subset.
    """
    body = client.get("/canonical/paths").json()
    assert body["paths"] == list(canonical_paths_sorted())
    assert body["count"] == len(body["paths"])

    # Families are what the picker groups by; every path must land in exactly one.
    grouped = [path for members in body["families"].values() for path in members]
    assert sorted(grouped) == sorted(body["paths"])
    assert "logging" in body["families"]


# ─── C1: ingestion ─────────────────────────────────────────────────────


def test_simulate_writes_nothing_and_reports_coverage(
    client: TestClient, config_text: str
) -> None:
    """``/simulate`` is the dry run: same verdicts, no ledger, no device row."""
    before = client.get("/devices").json()["count"]
    body = client.post(
        "/simulate", json={"config_text": config_text, "source_file": "dry-run.conf"}
    ).json()

    assert body["device"]["vendor"] == "cisco_ios"
    assert body["findings"], "a config that parses must produce findings"
    assert body["score"]["scored_controls"] > 0
    assert body["stats"]["controls_automated"] > 0
    assert client.get("/devices").json()["count"] == before, (
        "/simulate persisted a device; the dry-run path must not write"
    )


def test_simulate_rejects_text_no_pack_recognises(client: TestClient) -> None:
    """An unrecognised file must name the loaded vendors, not just refuse.

    "No parser could handle this" gives an operator nothing to do. The vendor
    list turns it into a decision: add a pack, or check the file is a config.
    """
    response = client.post(
        "/simulate",
        json={"config_text": "Dear Sir,\n\nPlease find attached.\n", "source_file": "x.doc"},
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "cisco_ios" in detail, f"refusal names no loaded vendor: {detail}"


def test_simulate_rejects_a_missing_field(client: TestClient) -> None:
    """Malformed input is a 422 from the schema, never a 500 from the parser."""
    assert client.post("/simulate", json={"source_file": "x.conf"}).status_code == 422


def test_ingest_persists_and_is_idempotent(client: TestClient, config_text: str) -> None:
    """The same bytes must produce the same device id and not a second device."""
    files = {"file": ("idem.conf", config_text, "text/plain")}
    first = client.post("/ingest", files=files).json()
    before = client.get("/devices").json()["count"]
    second = client.post(
        "/ingest", files={"file": ("idem.conf", config_text, "text/plain")}
    ).json()

    assert first["device_id"] == second["device_id"]
    assert first["config_hash"] == second["config_hash"]
    assert first["facts_count"] > 0
    assert client.get("/devices").json()["count"] == before, (
        "re-ingesting identical bytes created a second device; the config hash "
        "is the identity, so this would double-count a device in the estate"
    )


def test_ingest_decodes_a_non_utf8_config(client: TestClient) -> None:
    """A cp1252 smart quote in a description must not fail the upload.

    Configurations are pasted and mailed by people who never think about
    encoding. A tool that returns 500 on a stray 0x92 byte is a tool that gets
    worked around. The payload is assembled as bytes rather than encoded from a
    ``str``, because 0x92 is a *byte* cp1252 assigns a character to — the
    codepoint U+0092 it decodes to has no cp1252 encoding, so round-tripping
    through ``str.encode`` would fail in the test rather than in the endpoint.
    """
    raw = (
        b"version 15.7\nhostname enc-test\n"
        b"interface GigabitEthernet0/0\n description Bob\x92s uplink\n"
        b"ip ssh version 2\nline vty 0 4\n transport input ssh\nend\n"
    )
    with pytest.raises(UnicodeDecodeError):
        raw.decode("utf-8")

    response = client.post("/ingest", files={"file": ("cp1252.conf", raw, "text/plain")})
    assert response.status_code == 200, response.text
    assert response.json()["facts_count"] > 0


def test_bulk_ingest_reports_per_member_outcomes(client: TestClient, config_text: str) -> None:
    """One bad member must not fail the archive.

    A 400-device upload with two Word documents in it should ingest 398 and name
    the two. An all-or-nothing bulk import is a bulk import that never completes
    on a real estate.
    """
    payload = _zip(
        {
            "site-a/router.conf": config_text,
            "site-b/notes.txt": "these are meeting notes, not a configuration",
        }
    )
    body = client.post(
        "/ingest/bulk", files={"file": ("estate.zip", payload, "application/zip")}
    ).json()

    assert body["total_files"] == 2
    assert body["success"] == 1
    assert body["failed"] == 1
    assert body["errors"][0]["file"] == "site-b/notes.txt"
    assert body["errors"][0]["error"], "a failed member with no reason is not actionable"


def test_bulk_ingest_rejects_a_non_zip(client: TestClient) -> None:
    assert (
        client.post(
            "/ingest/bulk", files={"file": ("x.zip", b"not a zip at all", "application/zip")}
        ).status_code
        == 400
    )


# ─── Hostile input ─────────────────────────────────────────────────────


class TestArchiveGuards:
    """The archive limits, exercised as refusals rather than as documentation.

    An auditor is handed archives by people and processes they do not control, so
    every one of these is reachable by an attacker who can get a file in front of
    the tool. The limits are imported from config rather than restated, so raising
    one does not silently turn a guard test into a no-op.
    """

    def test_a_zip_bomb_is_refused_before_it_is_expanded(self, client: TestClient) -> None:
        """The declared total is refused without reading a single member.

        The archive is a genuine bomb rather than a monkeypatched constant: its
        central directory declares 600 MB while 127 bytes go over the wire,
        which is what a crafted archive actually looks like. Building it that way
        matters, because it is the only version that proves the guard fires on
        the *header* — fabricating 512 MB of real data would pass the same
        assertion while proving the opposite, that the refusal costs as much
        memory as the attack.

        Note the assertion is on the *status*: an endpoint that expands the bomb
        and dies of memory exhaustion also "does not return a report", and only
        one of the two is a security control.
        """
        payload = _bomb("bomb.conf", declared_bytes=MAX_TOTAL_UNCOMPRESSED_BYTES + 1)
        assert len(payload) < 4096, "the fixture must be small on the wire to be a bomb"

        response = client.post(
            "/ingest/bulk", files={"file": ("bomb.zip", payload, "application/zip")}
        )
        assert response.status_code == 413, response.text
        assert "zip-bomb" in response.json()["detail"]

    def test_a_member_above_the_per_file_limit_is_refused(self, client: TestClient) -> None:
        """The per-member ceiling, which is a different guard from the total.

        A single member can sit under the 512 MB total and still be far too large
        to parse, so this one is refused per file and reported in ``errors``
        rather than rejecting the whole archive: one oversized member in a batch
        of real configs must not cost the operator the other members.

        The member is really that big, because the read path is deliberately not
        willing to trust ``file_size`` here — it reads with its own ceiling, so a
        lie in the header would be caught by the wrong assertion.
        """
        payload = _zip({"huge.conf": "A" * (MAX_MEMBER_BYTES + 1)})
        response = client.post(
            "/ingest/bulk", files={"file": ("huge.zip", payload, "application/zip")}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["success"] == 0
        assert body["failed"] == 1
        assert "limit" in body["errors"][0]["error"]

    def test_too_many_members_is_refused(self, client: TestClient) -> None:
        payload = _zip({f"d{i}.conf": "hostname x\n" for i in range(MAX_ARCHIVE_MEMBERS + 1)})
        response = client.post(
            "/ingest/bulk", files={"file": ("many.zip", payload, "application/zip")}
        )
        assert response.status_code == 413
        assert str(MAX_ARCHIVE_MEMBERS) in response.json()["detail"]

    @pytest.mark.parametrize(
        "name",
        [
            "../../etc/passwd.conf",
            "/absolute/path.conf",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts.conf",
            "C:\\secrets.conf",
        ],
    )
    def test_traversal_in_a_member_name_is_rejected(
        self, client: TestClient, name: str, config_text: str
    ) -> None:
        """Nothing is written to disk, and the name is still rejected.

        The member name is stored as provenance and rendered in the UI, so a name
        that reads as a path outside the tree is a finding attributed to a file
        that does not exist — and it is one code change away from being a write.
        """
        payload = _zip({name: config_text})
        body = client.post(
            "/ingest/bulk", files={"file": ("evil.zip", payload, "application/zip")}
        ).json()
        assert body["success"] == 0, f"{name} was ingested"
        assert body["failed"] == 1
        assert "traversal" in body["errors"][0]["error"].lower()


class TestStaticAssetGuards:
    """The frontend is served by name, and only from inside ``frontend/``."""

    def test_index_is_served(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert response.headers["cache-control"] == "no-cache", (
            "a cached UI means an operator who reloads after an upgrade gets last "
            "week's JavaScript talking to this week's API"
        )

    @pytest.mark.parametrize(
        ("asset", "marker"),
        [
            ("../backend/app/main.py", "from fastapi"),
            ("../../GLOBAL_RULESET.md", "R2.1"),
            ("../data/praman.db", "SQLite format"),
            ("..%2f..%2fpyproject.toml", "[project]"),
        ],
    )
    def test_escaping_the_frontend_directory_is_a_404(
        self, client: TestClient, asset: str, marker: str
    ) -> None:
        """The resolved path is checked, so encodings do not help.

        This is the route that would otherwise serve
        ``data/private/ed25519_signing.key`` to anyone who asked for it by
        relative path.

        The second assertion is against a marker from *inside* each file rather
        than against the requested name, because the 404 body deliberately echoes
        what was asked for — so ``"main.py" not in response.text`` would fail on a
        correct refusal and pass on a leak of any file whose path happens not to
        appear in its own contents. A content marker cannot be satisfied by the
        error message.
        """
        response = client.get(f"/{asset}")
        assert response.status_code == 404, (
            f"GET /{asset} returned {response.status_code}; the static route "
            "escaped the frontend directory"
        )
        assert marker not in response.text, (
            f"GET /{asset} returned the file's own contents"
        )

    def test_an_unknown_asset_is_a_404_not_an_index_fallback(
        self, client: TestClient
    ) -> None:
        """No SPA catch-all.

        A fallback that returns index.html for every unknown path turns an API
        typo into a 200 with HTML in it, which a client then tries to parse as
        JSON — the failure surfaces three layers away from its cause.
        """
        response = client.get("/definitely-not-an-asset.js")
        assert response.status_code == 404
        assert "<html" not in response.text.lower()


# ─── C3/C4: audit, devices, reports ────────────────────────────────────


def test_devices_list_and_detail_agree(client: TestClient, ingested: str) -> None:
    listed = client.get("/devices").json()
    assert listed["count"] == len(listed["devices"]) >= 1
    assert ingested in {device["device_id"] for device in listed["devices"]}

    detail = client.get(f"/devices/{ingested}").json()
    assert detail["device"]["device_id"] == ingested
    assert detail["findings"], "a device with no findings is a device with no audit"
    assert detail["score"]["scored_controls"] > 0


def test_unknown_device_is_a_404(client: TestClient) -> None:
    assert client.get("/devices/sha256:0000000000000000").status_code == 404


def test_audit_commit_then_verify(client: TestClient, committed: dict[str, str]) -> None:
    """Committing appends one record, and the chain still verifies afterwards.

    Verification is asserted *after* the append rather than at rest: a ledger
    that only verifies before you write to it is not an append-only ledger.

    The append itself happens in the ``committed`` fixture, because the report
    and remediation routes need the same record and committing twice would leave
    this test asserting a count it did not produce.

    The five checks are asserted individually rather than through the top-level
    roll-up, because a roll-up is one ``and`` away from hiding a link that stopped
    being checked. ``signature_valid`` is the exception, and is only required
    where a verify key exists: on a host without one the design is to report the
    chain as intact and unsigned, so demanding a signature here would fail the
    test on exactly the degraded deployment it is meant to describe.
    """
    records = client.get("/audit/records").json()
    assert records["count"] >= 1
    assert committed["record_hash"] in {r["record_hash"] for r in records["records"]}

    assert committed["actor"] == TEST_OPERATOR, (
        "the commit response does not name who committed it. ``actor`` is a hashed "
        "field, so the ledger row itself is accountable; a response that omits it "
        "leaves the UI unable to show the operator what it just signed in their name"
    )

    verify = client.get("/audit/verify").json()
    assert verify["chain_length"] >= records["count"]

    mine = [r for r in verify["results"] if r["record_hash"] == committed["record_hash"]]
    assert len(mine) == 1, "the record just committed is not in the verification report"
    assert mine[0]["actor"] == TEST_OPERATOR
    assert mine[0]["actor_valid"] is True, (
        "the route did not resolve the actor against the operator roster. Unresolved "
        f"is reported as None, not False, so this is: {mine[0]['detail']}"
    )

    for result in verify["results"]:
        where = f"seq {result['seq']}"
        assert result["hash_valid"] is True, f"{where}: record hash does not match"
        assert result["chain_valid"] is True, f"{where}: prev_hash link is broken"
        assert result["merkle_valid"] is True, f"{where}: findings do not match merkle_root"
        assert result["detail"], f"{where}: a verdict with no explanation"
        if VERIFY_KEY_PATH.exists():
            assert result["signature_valid"] is True, f"{where}: signature does not verify"
            assert result["all_valid"] is True, f"{where}: {result['detail']}"
        where = f"seq {result['seq']}"
        assert result["hash_valid"] is True, f"{where}: record hash does not match"
        assert result["chain_valid"] is True, f"{where}: prev_hash link is broken"
        assert result["merkle_valid"] is True, f"{where}: findings do not match merkle_root"
        assert result["detail"], f"{where}: a verdict with no explanation"
        if VERIFY_KEY_PATH.exists():
            assert result["signature_valid"] is True, f"{where}: signature does not verify"
            assert result["all_valid"] is True, f"{where}: {result['detail']}"


def test_report_pdf_carries_its_provenance_headers(
    client: TestClient, ingested: str, committed: dict[str, str]
) -> None:
    """The PDF is the C4 deliverable, and it must say how trustworthy it is.

    ``X-PRAMAN-Signature`` and ``X-PRAMAN-Evidence`` are the honest-degradation
    surface: on a host with no signing key the report is still produced and the
    header says it is unsigned. Asserting the headers exist — rather than
    asserting they say "signed" — is the point, because pinning them to the happy
    value would make the test fail on exactly the deployment the design is for.
    """
    response = client.get(f"/devices/{ingested}/report.pdf")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-"), "response is not a PDF"

    for header in ("X-PRAMAN-Signature", "X-PRAMAN-Evidence", "X-PRAMAN-Record-Hash"):
        assert response.headers.get(header), f"{header} missing from the report response"
    assert response.headers["X-PRAMAN-Record-Hash"] == committed["record_hash"], (
        "the report cites a different record than the one just committed, so the "
        "hash an auditor checks would not be the hash the ledger holds"
    )


def test_report_pdf_refuses_a_device_with_no_committed_audit(
    client: TestClient, config_text: str
) -> None:
    """409, not a PDF built on the fly.

    A report is the artefact somebody files, so it has to be reproducible from
    the ledger. Rendering one from uncommitted verdicts would produce a document
    whose ``X-PRAMAN-Record-Hash`` matches nothing — indistinguishable from a
    real report at the point where it matters.

    Only the hostname line is rewritten, because ``device_id`` is the slugified
    hostname: a copy that differs anywhere else would land on the same device row
    and inherit the commit this test needs to be missing.
    """
    other = config_text.replace("hostname secure-gw-01", "hostname uncommitted-gw-09", 1)
    assert other != config_text, "the fixture's hostname line has changed"

    device_id = client.post(
        "/ingest",
        files={"file": ("uncommitted.conf", other, "text/plain")},
    ).json()["device_id"]
    assert device_id == "uncommitted-gw-09"

    response = client.get(f"/devices/{device_id}/report.pdf")
    assert response.status_code == 409, response.text
    assert "commit" in response.json()["detail"].lower(), (
        "a 409 that does not name the next action leaves the operator guessing"
    )


def test_remediation_is_ordered_and_cites_a_source(
    client: TestClient, ingested: str, committed: dict[str, str]
) -> None:
    """C4 asks for *actionable* intelligence, so the CLI has to come from somewhere.

    Kept deliberately thin — ``tests/test_api_remediation.py`` covers this route's
    behaviour in depth. What is asserted here is the part that belongs to the API
    surface: that the counts describe the plan they are attached to, that severity
    order is worst-first, and that ``kind`` is never a blank block dressed up as
    a fix.
    """
    body = client.get(f"/devices/{ingested}/remediation").json()
    assert body["audit_id"] == committed["audit_id"], (
        "the plan cites a different audit than the latest commit"
    )
    assert body["basis"], "a plan that does not say what it was computed from"

    plan = body["plan"]
    counts = body["counts"]
    assert counts["controls"] == len(plan)
    assert counts["commands"] == sum(len(entry["steps"]) for entry in plan)
    assert counts["cli"] + counts["manual"] + counts["none"] == len(plan), (
        "kind is a tri-state that must partition the plan; a fourth value means "
        "an entry is neither actionable nor honestly marked unactionable"
    )
    if not plan:
        pytest.skip("this fixture has no failing controls to remediate")

    ranks = [_SEVERITY_ORDER.index(entry["severity"] or "unknown") for entry in plan]
    assert ranks == sorted(ranks), (
        "the plan is not worst-first, so an operator working top-down closes "
        "low-severity gaps before high ones"
    )

    for entry in plan:
        assert entry["control_id"]
        assert entry["kind"] in {"cli", "manual", "none"}
        if entry["kind"] == "cli":
            assert entry["steps"], f"{entry['control_id']}: kind=cli with no steps"
            assert entry["source"], f"{entry['control_id']}: no cited source"
            for step in entry["steps"]:
                assert step["command"] or step["prompt"], (
                    f"{entry['control_id']}: a step with neither a command nor a prompt"
                )


# ─── Identity, authorisation and the access log ────────────────────────
#
# The 401/403/429 paths live in ``tests/test_auth.py``, which drops the conftest
# override that gives every test in this module an approver. What is asserted here
# is only what belongs to the API surface: that the routes exist, answer in the
# documented shape, and refuse the inputs they say they refuse.


def test_whoami_reports_the_role_and_derives_the_permissions(client: TestClient) -> None:
    """The frontend greys out controls from this response, so it must not guess.

    ``may_ingest`` and ``may_commit`` are computed from the role by the server
    rather than by JavaScript, because a UI that disagrees with the gate either
    hides a button that would have worked or offers one that returns 403.
    """
    body = client.get("/auth/whoami").json()
    assert body["username"] == TEST_OPERATOR
    assert body["role"] == "approver"
    assert body["may_ingest"] is True
    assert body["may_commit"] is True


def test_login_refuses_a_service_account_that_has_no_password(client: TestClient) -> None:
    """The suite's own principal must not be a usable credential.

    ``service:`` accounts are created with an empty ``password_hash`` so that
    nothing can log in as them, and this asserts the empty hash is treated as
    "never matches" rather than as "matches anything" — the direction that bug
    always goes. It also means the fixture identity in ``tests/conftest.py`` is
    not a password shipped in the repository.
    """
    response = client.post(
        "/auth/login", json={"username": TEST_OPERATOR, "password": "any password at all"}
    )
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "invalid credentials", (
        "the message must not distinguish a passwordless account from a wrong "
        "password, or it becomes an enumeration oracle"
    )
    assert COOKIE_NAME not in response.cookies

    # Leave no throttle residue: the counter is process-wide, and a later test
    # logging in as this name would otherwise inherit the failure.
    clear_login_failures(TEST_OPERATOR)


def test_login_issues_a_token_and_an_httponly_cookie(client: TestClient) -> None:
    """The happy path, including the two flags that make the cookie safe to set.

    The cookie exists so a browser can follow a download link — a navigation to
    ``report.pdf`` cannot carry an ``Authorization`` header. It is only accepted on
    GET and HEAD (asserted in ``tests/test_auth.py``), so ``SameSite=Strict`` and
    ``HttpOnly`` are what keep it from being a second, weaker credential.

    A low iteration count is used for the fixture password only. The default is
    600,000 and is what ``scripts/manage_users.py`` writes; paying 0.2 s twice here
    would test ``hashlib`` rather than this route.
    """
    username, password = "surface.login", "correct horse battery"
    conn = STATE.connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, role, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, "viewer", hash_password(password, iterations=1_000), utc_now_iso()),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.post(
        "/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["username"] == username
    assert body["role"] == "viewer"
    assert len(body["token"]) >= 32, "a short session token is a guessable one"
    # Parsed rather than string-compared: ``open_session`` writes
    # ``datetime.isoformat()`` and a lexicographic test would quietly start
    # passing for the wrong reason if either format grew or lost a field.
    assert datetime.fromisoformat(body["expires_at"]) > datetime.now(timezone.utc), (
        "the session expired before it was issued"
    )

    cookie = response.headers["set-cookie"].lower()
    assert COOKIE_NAME in cookie
    assert "httponly" in cookie, "a token readable by JavaScript is a token XSS can steal"
    assert "samesite=strict" in cookie

    conn = STATE.connect()
    try:
        stored = conn.execute(
            "SELECT token_hash FROM sessions WHERE username = ?", (username,)
        ).fetchall()
    finally:
        conn.close()
    assert stored, "the session was never persisted, so it cannot be revoked"
    assert all(row["token_hash"] != body["token"] for row in stored), (
        "the raw token is in the database: anyone who can read the file that holds "
        "the configurations can also authenticate as this operator"
    )


def test_login_rejects_an_unknown_operator(client: TestClient) -> None:
    response = client.post(
        "/auth/login", json={"username": "nobody.here", "password": "not a password"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid credentials"
    clear_login_failures("nobody.here")


def test_login_validates_before_it_authenticates(client: TestClient) -> None:
    """422 on a malformed body, not a 401 that spends a key derivation on it."""
    for body in ({"username": "", "password": "x" * 12}, {"username": "someone"}):
        assert client.post("/auth/login", json=body).status_code == 422


def test_logout_is_idempotent_and_says_what_it_did(client: TestClient) -> None:
    """No token on the request means nothing to revoke — 200 with ``revoked`` false.

    The dependency override in ``tests/conftest.py`` authenticates this client
    without a session, which is exactly the shape of a logout arriving with a
    cookie the server has already revoked. Answering 200 is deliberate: a logout
    that errors leaves the operator unsure whether they are still signed in.
    ``tests/test_auth.py`` asserts the other half — that a real token stops working
    afterwards.
    """
    body = client.post("/auth/logout").json()
    assert body["status"] == "ok"
    assert body["revoked"] is False


def test_the_access_log_records_a_read_and_is_readable(client: TestClient) -> None:
    """Reads are logged too, which is the point of having the table at all.

    Downloading every device's findings used to leave no trace. The route is
    approver-only for a reason worth restating: the log answers "who looked at the
    core router", so handing it to every viewer would make the reviewer's work
    visible to the reviewed.
    """
    probe = client.get("/devices")
    assert probe.status_code == 200

    body = client.get("/audit/access", params={"limit": 50}).json()
    assert body["count"] == len(body["entries"]) <= 50
    assert body["total"] >= body["count"]

    mine = [entry for entry in body["entries"] if entry["path"] == "/devices"]
    assert mine, "a gated read left no entry in the access log"
    entry = mine[0]
    assert entry["actor"] == TEST_OPERATOR, (
        "the log records no actor, so it cannot answer the question it exists for"
    )
    assert entry["method"] == "GET"
    assert entry["status"] == 200
    assert entry["duration_ms"] >= 0
    assert entry["at"], "an access-log entry with no timestamp"

    filtered = client.get(
        "/audit/access", params={"actor": TEST_OPERATOR, "limit": 5}
    ).json()
    assert filtered["count"] <= 5
    assert {e["actor"] for e in filtered["entries"]} <= {TEST_OPERATOR}

    assert client.get("/audit/access", params={"limit": 0}).status_code == 422
    assert client.get("/audit/access", params={"limit": 9999}).status_code == 422


def test_static_assets_are_not_written_to_the_access_log(client: TestClient) -> None:
    """A log flooded by ``app.css`` buries the one line that matters.

    ``/health`` is excluded for the same reason: liveness polling would be most of
    the table. The exclusion is by suffix and by exact path, never by prefix, so a
    route cannot accidentally become invisible by living under one.
    """
    before = client.get("/audit/access", params={"limit": 1}).json()["total"]
    assert client.get("/health").status_code == 200
    assert client.get("/app.css").status_code in {200, 404}
    after = client.get("/audit/access", params={"limit": 1}).json()["total"]

    # The two /audit/access reads above are themselves logged; the point is that
    # the health check and the stylesheet are not.
    assert after - before <= 2, (
        "an unlogged path was logged: the access log is now mostly noise"
    )


# ─── The shape of a refusal ────────────────────────────────────────────


def test_error_responses_are_json_not_html(client: TestClient) -> None:
    """Every refusal above must be machine-readable.

    The frontend renders ``detail`` directly, so an HTML error page becomes a
    blank toast — the operator sees that something failed and not what.
    """
    for response in (
        client.get("/devices/sha256:0000000000000000"),
        client.post("/simulate", json={"config_text": "hello", "source_file": "a.conf"}),
        client.post("/training/retire", json={"drain3_template": "never taught"}),
    ):
        assert response.status_code >= 400
        assert "application/json" in response.headers["content-type"]
        payload: dict[str, Any] = json.loads(response.text)
        assert payload.get("detail"), f"{response.url}: error with no detail field"
