"""Test: the export routes are wired to the right source of truth.

``tests/test_export_oscal.py`` and ``tests/test_export_sarif.py`` prove the two
documents are correct given their inputs. Nothing there says where those inputs
come from — and that is the whole design decision these two endpoints embody:

* ``GET /devices/{id}/oscal.json`` reads a **committed ledger record**. It must
  refuse a device with no audit rather than fall back to re-simulating, because
  the record hash and signature in the document's metadata are the only reason a
  recipient can check what it was handed. A route that quietly served a
  simulation would emit a document that *looks* verifiable and is not.
* ``POST /simulate/sarif`` reads a **simulation** and must not require a
  committed audit, because a CI gate runs before anything is committed. If it
  demanded a ledger record the endpoint would be useless for its only purpose.

So the assertions here are about provenance, refusal and role, not about JSON
shape. Three of them are worth naming:

``TestRequestParity`` compares ``SarifRequest`` field-for-field with
``SimulateRequest``. The duplication is deliberate — it is what keeps the export
router free of a circular import back into ``main`` — and this is the gate that
makes it safe.

``test_the_oscal_document_carries_the_committed_record_hash`` is the provenance
check. It compares the hash in the exported document against the one
``POST /audit/commit`` returned, which no amount of re-simulation could produce.

``test_two_requests_over_one_config_return_identical_bytes`` closes the purity
claim end-to-end. The exporter's own tests assert it over a dict; this asserts it
over the wire, where a middleware or a JSON encoder could still inject a
timestamp.

Offline: no models, no network, no signing key. The database is the
session-scoped throwaway from ``conftest.isolated_database``.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.app.auth import (
    ROLE_AUDITOR,
    ROLE_VIEWER,
    Principal,
    current_principal,
)
from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.app.main import SimulateRequest, app
from backend.app.routes_export import SarifRequest
from backend.export import OSCAL_VERSION, SARIF_VERSION

FIXTURE = PROJECT_ROOT / "test_configs" / "realistic" / "secure_baseline.conf"


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding=FILE_ENCODING)


@pytest.fixture(scope="module")
def ingested(client: TestClient, config_text: str) -> str:
    """A device in the database with no committed audit yet."""
    response = client.post(
        "/ingest", files={"file": ("api-export.conf", config_text, "text/plain")}
    )
    assert response.status_code == 200, response.text
    return response.json()["device_id"]


@pytest.fixture(scope="module")
def committed(client: TestClient, ingested: str) -> dict:
    """The ledger record the OSCAL route is supposed to export.

    Module-scoped and ordered after ``ingested`` so that
    ``test_oscal_is_refused_before_the_audit_is_committed`` can run against the
    device *before* this fixture is ever requested — the refusal is the more
    important half of the behaviour and it is unobservable once a record exists.
    """
    response = client.post("/audit/commit", json={"device_id": ingested})
    assert response.status_code == 200, response.text
    return response.json()


def as_role(role: str):
    """Swap the suite-wide approver for a lower role, then put it back."""
    saved = app.dependency_overrides.get(current_principal)
    app.dependency_overrides[current_principal] = lambda: Principal(
        username=f"service:export.{role}", role=role
    )
    try:
        yield
    finally:
        if saved is None:
            app.dependency_overrides.pop(current_principal, None)
        else:
            app.dependency_overrides[current_principal] = saved


@pytest.fixture
def viewer():
    yield from as_role(ROLE_VIEWER)


@pytest.fixture
def auditor():
    yield from as_role(ROLE_AUDITOR)


class TestRequestParity:
    """``SarifRequest`` duplicates ``SimulateRequest``; this is why that is safe."""

    def test_the_two_bodies_are_field_for_field_identical(self) -> None:
        """A field added to one and not the other is the drift this catches.

        Compared through Pydantic's own ``model_fields`` rather than by reading
        the source, so a changed default or a changed annotation fails too — not
        only a renamed field.
        """
        simulate = {
            name: (field.annotation, field.default, field.is_required())
            for name, field in SimulateRequest.model_fields.items()
        }
        sarif = {
            name: (field.annotation, field.default, field.is_required())
            for name, field in SarifRequest.model_fields.items()
        }
        assert sarif == simulate, (
            "SarifRequest has drifted from SimulateRequest. The duplication exists "
            "only to keep backend/app/routes_export.py from importing the module "
            "that mounts it; the two endpoints run the same pipeline over the same "
            "input, so a client must be able to switch paths and nothing else."
        )

    def test_both_endpoints_accept_a_body_with_the_default_source_file(
        self, client: TestClient, config_text: str
    ) -> None:
        """Parity asserted over HTTP too, since the models could agree and the
        routes still disagree about what they read out of them."""
        body = {"config_text": config_text}
        assert client.post("/simulate", json=body).status_code == 200
        assert client.post("/simulate/sarif", json=body).status_code == 200


class TestSarifRoute:
    """``POST /simulate/sarif`` — the CI gate shape."""

    def test_a_simulation_needs_no_committed_audit(
        self, client: TestClient, config_text: str
    ) -> None:
        """The point of the endpoint: it answers before anything is committed."""
        response = client.post(
            "/simulate/sarif",
            json={"config_text": config_text, "source_file": "candidate.conf"},
        )
        assert response.status_code == 200, response.text
        document = response.json()
        assert document["version"] == SARIF_VERSION
        assert len(document["runs"]) == 1

    def test_the_response_is_a_downloadable_sarif_file(
        self, client: TestClient, config_text: str
    ) -> None:
        """A CI runner uploads a file; the filename is part of the interface."""
        response = client.post(
            "/simulate/sarif", json={"config_text": config_text}
        )
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-praman-sarif-version"] == SARIF_VERSION
        assert ".sarif" in response.headers["content-disposition"]
        assert response.headers["x-praman-config-hash"].startswith("sha256:")

    def test_two_requests_over_one_config_return_identical_bytes(
        self, client: TestClient, config_text: str
    ) -> None:
        """Purity, asserted over the wire rather than over the dict.

        ``sarif.py`` omits every timestamp field the schema permits so that a
        committed log diffs cleanly. That guarantee is only worth anything if
        nothing between the exporter and the socket adds one back.
        """
        body = {"config_text": config_text, "source_file": "candidate.conf"}
        first = client.post("/simulate/sarif", json=body).content
        second = client.post("/simulate/sarif", json=body).content
        assert first == second

    def test_the_sarif_log_accounts_for_every_finding_simulate_reports(
        self, client: TestClient, config_text: str
    ) -> None:
        """The two endpoints must be the same audit, not two similar ones.

        SARIF omits ``notchecked``/``notselected``/``notapplicable`` results so a
        CI annotator is not flooded, and publishes the omission as arithmetic.
        Checking that arithmetic against ``/simulate``'s own finding count is what
        proves the omission is bookkeeping rather than a second pipeline that
        happens to produce fewer verdicts.
        """
        body = {"config_text": config_text, "source_file": "candidate.conf"}
        findings = client.post("/simulate", json=body).json()["findings"]
        run = client.post("/simulate/sarif", json=body).json()["runs"][0]

        properties = run["properties"]
        assert properties["pramanFindingsTotal"] == len(findings)
        assert sum(properties["pramanResultCounts"].values()) == len(findings)
        assert (
            len(run["results"]) + properties["pramanResultsOmittedTotal"]
            == len(findings)
        )

    def test_an_unparseable_config_is_a_400_not_a_500(self, client: TestClient) -> None:
        """The router is mounted, so ``main``'s exception handlers must reach it.

        ``ParseError`` is handled by an ``@app.exception_handler`` declared in
        ``main``. Handlers are registered on the application, not on the router,
        but that is worth an assertion rather than an assumption: if it were the
        other way round every bad upload to this endpoint would be a 500.
        """
        response = client.post(
            "/simulate/sarif",
            json={"config_text": "not a configuration\n", "source_file": "x.docx"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "ParseError"

    def test_a_viewer_may_not_simulate(self, client: TestClient, viewer) -> None:
        """Handing PRAMAN a configuration is an auditor's act, here as at
        ``/simulate``. A read-only role that could post arbitrary text would be
        able to spend the estate's CPU on demand."""
        response = client.post("/simulate/sarif", json={"config_text": "x"})
        assert response.status_code == 403


class TestOscalRoute:
    """``GET /devices/{id}/oscal.json`` — the document that leaves the building."""

    def test_an_unknown_device_is_404(self, client: TestClient) -> None:
        response = client.get("/devices/no-such-device/oscal.json")
        assert response.status_code == 404
        assert "no-such-device" in response.json()["detail"]

    def test_oscal_is_refused_before_the_audit_is_committed(
        self, client: TestClient, ingested: str
    ) -> None:
        """409, naming the operation that fixes it.

        This is the assertion that distinguishes the OSCAL route from the SARIF
        one. Falling back to a simulation here would produce a document whose
        metadata claimed a ledger identity it did not have.
        """
        response = client.get(f"/devices/{ingested}/oscal.json")
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "has no committed audit" in detail
        assert "POST /audit/commit" in detail

    def test_a_committed_audit_exports(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        response = client.get(f"/devices/{ingested}/oscal.json")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-praman-oscal-version"] == OSCAL_VERSION
        assert f"seq{committed['seq']}.oscal.json" in (
            response.headers["content-disposition"]
        )
        document = response.json()
        assert document["assessment-results"]["metadata"]["version"] == (
            committed["audit_id"]
        )

    def test_the_oscal_document_carries_the_committed_record_hash(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        """Provenance: a value only the ledger could have produced.

        A re-simulation would reproduce every verdict in the document and none of
        this. It is what a recipient hands back to ``/audit/verify``.
        """
        response = client.get(f"/devices/{ingested}/oscal.json")
        assert response.headers["x-praman-record-hash"] == committed["record_hash"]
        props = {
            prop["name"]: prop["value"]
            for prop in response.json()["assessment-results"]["metadata"]["props"]
        }
        assert props["praman-record-hash"] == committed["record_hash"]
        assert props["praman-ledger-seq"] == str(committed["seq"])
        assert props["praman-device-id"] == ingested

    def test_every_stored_finding_becomes_an_observation(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        """Coverage must not be improvable by dropping rows on the way out.

        One observation per stored finding, counted against the ledger record's
        own ``findings_count`` rather than against a re-read of the table.
        """
        results = client.get(f"/devices/{ingested}/oscal.json").json()[
            "assessment-results"
        ]["results"]
        observations = sum(len(result["observations"]) for result in results)
        assert observations == committed["findings_count"]

    def test_the_named_audit_is_the_one_exported(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        response = client.get(
            f"/devices/{ingested}/oscal.json",
            params={"audit_id": committed["audit_id"]},
        )
        assert response.status_code == 200
        assert response.headers["x-praman-audit-id"] == committed["audit_id"]

    def test_an_audit_id_this_device_does_not_have_is_refused(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        """Not 404, and not the latest audit instead.

        Silently substituting the newest record for a requested one is the bug
        that makes a GRC platform display the wrong assessment while every id in
        it validates.
        """
        response = client.get(
            f"/devices/{ingested}/oscal.json", params={"audit_id": "AUD-not-real"}
        )
        assert response.status_code == 409
        assert "AUD-not-real" in response.json()["detail"]

    def test_two_exports_of_one_audit_return_identical_bytes(
        self, client: TestClient, ingested: str, committed: dict
    ) -> None:
        """Determinism over HTTP: one audit is one assessment, forever."""
        first = client.get(f"/devices/{ingested}/oscal.json").content
        second = client.get(f"/devices/{ingested}/oscal.json").content
        assert first == second
        assert json.loads(first)["assessment-results"]["uuid"]

    def test_an_auditor_may_read_an_export(
        self, client: TestClient, ingested: str, committed: dict, auditor
    ) -> None:
        """Gated at ``viewer``, so every role at or above it can read.

        Asserted with an auditor rather than a viewer because the suite's default
        principal is an approver: without this, the gate could have been
        ``REQUIRE_APPROVER`` by mistake and nothing would have said so.
        """
        assert client.get(f"/devices/{ingested}/oscal.json").status_code == 200
