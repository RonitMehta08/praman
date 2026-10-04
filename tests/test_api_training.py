"""Test: the C2 training module, end to end over HTTP.

Split out of :mod:`tests.test_api_surface`, which had grown past a thousand lines
holding two different questions. That file asks whether the API *surface* is the
one the project claims — every route reachable, every refusal machine-readable,
every hostile input refused. This one asks whether one workflow *works*: an
operator teaches a mapping, sees it in force, exports it as a reviewable pattern
pack, and retires it.

The distinction matters for how the tests are written. A surface test is
independent by construction — any order, any subset. The round trip below is
deliberately ordered, because the thing worth proving is that the *same* mapping
is visible at each stage. Keeping the two kinds in one file made the ordered one
look like an accident.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app.config import FILE_ENCODING, PROJECT_ROOT
from backend.app.main import app

FIXTURE = PROJECT_ROOT / "test_configs" / "realistic" / "secure_baseline.conf"


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding=FILE_ENCODING)


@pytest.fixture(scope="module")
def ingested(client: TestClient, config_text: str) -> str:
    """Ingest one device and return its id, so the queue has something in it."""
    response = client.post(
        "/ingest",
        files={"file": ("api-training.conf", config_text, "text/plain")},
    )
    assert response.status_code == 200, response.text
    return response.json()["device_id"]


class TestTrainingRoundTrip:
    """Teach, list, export, retire — the whole C2 loop against a live process.

    Ordered deliberately: the mapping taught in the first test is the one the
    later ones list, export and retire. Splitting them into independent tests
    would need four mappings and would stop proving that the *same* mapping is
    visible at each stage, which is the only thing an operator cares about.
    """

    TEMPLATE = "logging api-surface-probe <*>"
    PATH = "logging.origin_id"

    def test_the_queue_is_reachable_and_shaped(self, client: TestClient, ingested: str) -> None:
        body = client.get("/training/queue").json()
        assert body["count"] == len(body["queue"])
        assert "counts" in body
        for item in body["queue"]:
            assert item["template"], "a queue entry with no template is unmappable"

    def test_teaching_a_mapping_takes_effect_without_a_restart(
        self, client: TestClient
    ) -> None:
        response = client.post(
            "/training/map",
            json={
                "drain3_template": self.TEMPLATE,
                "canonical_path": self.PATH,
                "admin_id": "test-api-training",
                "note": "written by tests/test_api_training.py",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "ok"
        assert body["mapping"]["canonical_path"] == self.PATH
        assert "no redeploy" in body["message"]

    def test_a_mapping_to_an_undeclared_path_is_refused(self, client: TestClient) -> None:
        """The canonical vocabulary is a closed set, and the API enforces it.

        Without this the training GUI is a way to write facts no rule can read,
        and the operator gets a success message for work that changed nothing.
        """
        response = client.post(
            "/training/map",
            json={
                "drain3_template": "logging bogus <*>",
                "canonical_path": "logging.not_a_real_path",
                "admin_id": "test-api-training",
            },
        )
        assert response.status_code == 400
        assert "logging.not_a_real_path" in response.json()["detail"]

    def test_the_taught_mapping_is_listed_as_in_force(self, client: TestClient) -> None:
        body = client.get("/training/mappings").json()
        assert body["count"] == len(body["mappings"])
        mine = [m for m in body["mappings"] if m["template"] == self.TEMPLATE]
        assert mine, f"{self.TEMPLATE} was taught but is not listed"
        assert mine[0]["canonical_path"] == self.PATH
        assert body["in_force"] >= 1
        # not_in_force is surfaced rather than logged: a mapping that stopped
        # compiling is silent loss of parsing coverage.
        assert isinstance(body["not_in_force"], list)

    def test_export_renders_a_pattern_pack_fragment(self, client: TestClient) -> None:
        """The store is a working surface; a pack is the reviewed artefact.

        The export is parsed as YAML rather than string-matched, because "it
        contains the path" would also pass for output no pack loader could read.
        """
        import yaml

        response = client.get("/training/export")
        assert response.status_code == 200
        assert "text/yaml" in response.headers["content-type"]
        assert "attachment" in response.headers["content-disposition"]

        parsed = yaml.safe_load(response.text)
        patterns = parsed["patterns"] or []
        assert self.PATH in {p["path"] for p in patterns}, (
            f"the taught mapping is not in the export:\n{response.text[:400]}"
        )
        for pattern in patterns:
            assert pattern["id"] and pattern["regex"] and pattern["path"]

    def test_retiring_the_mapping_removes_it_from_force(self, client: TestClient) -> None:
        response = client.post(
            "/training/retire", json={"drain3_template": self.TEMPLATE}
        )
        assert response.status_code == 200, response.text
        assert response.json()["retired"] == self.TEMPLATE

        active = client.get("/training/mappings").json()["mappings"]
        assert self.TEMPLATE not in {m["template"] for m in active}

        # The record survives retirement. A compliance tool that forgets a
        # mapping once applied cannot explain a verdict it produced last month.
        history = client.get("/training/mappings?include_retired=true").json()["mappings"]
        assert self.TEMPLATE in {m["template"] for m in history}

    def test_retiring_it_twice_is_a_404_that_says_so(self, client: TestClient) -> None:
        response = client.post(
            "/training/retire", json={"drain3_template": self.TEMPLATE}
        )
        assert response.status_code == 404
        assert "include_retired" in response.json()["detail"], (
            "the 404 must point at the query that shows the retired record, or "
            "the operator concludes their mapping was lost"
        )


def test_training_map_rejects_an_empty_template(client: TestClient) -> None:
    response = client.post(
        "/training/map",
        json={"drain3_template": "", "canonical_path": "logging.on", "admin_id": "x"},
    )
    assert response.status_code == 422
