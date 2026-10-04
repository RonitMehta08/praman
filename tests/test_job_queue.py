"""The in-process job queue, and the async mode it gives ``/ingest/bulk``.

MASTER_PROMPT §9.3 asks for this because the archive ceilings — 2,000 members,
512 MB expanded — are already wider than a synchronous HTTP request can carry.
The tests below are about the properties that make a background job *safe* to
offer rather than the happy path, because the happy path is the easy half:

* a bad archive still fails fast, before a 202 promises a job that cannot run;
* cancelling stops at an item boundary and does not discard completed work;
* a worker that raises marks its own job failed and does not kill the drain
  thread, so one bad job cannot silently end background processing for the
  process;
* the retention cap actually evicts, since an unbounded dict in a server that
  runs for weeks is a leak that only shows up in production.

The synchronous path is exercised by ``tests/acceptance/test_bulk_ingest.py``;
what matters here is that both modes walk the *same* code, which is why
``backend/app/bulk.py`` exists at all.
"""

from __future__ import annotations

import io
import threading
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.jobs import Job, JobQueue, JobState

CONFIG = """\
!
version 15.0
hostname job-router-{n}
boot-start-marker
boot-end-marker
enable secret 5 $1$test$hash{n}
ip ssh version 2
line vty 0 4
 transport input ssh
end
"""


def _archive(count: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in range(count):
            zf.writestr(f"router{n}.conf", CONFIG.format(n=n))
    return buf.getvalue()


class TestJobQueueMechanics:
    """The queue on its own, with trivial work, so failures point at the queue."""

    def test_a_submitted_job_runs_and_reports_its_result(self) -> None:
        queue = JobQueue()
        job = queue.submit("demo", lambda j: j.results.append({"ok": True}), total=1)
        assert queue.wait_idle(10.0)
        assert job.state is JobState.SUCCEEDED
        assert job.results == [{"ok": True}]
        assert job.started_at and job.finished_at

    def test_a_job_that_raises_fails_itself_and_not_the_queue(self) -> None:
        """One bad job must not end background processing for the process.

        This is the failure that would be invisible: the drain thread dies, every
        later submission sits at ``queued`` forever, and nothing logs a reason
        that points at the first job.
        """
        queue = JobQueue()
        bad = queue.submit("demo", lambda j: (_ for _ in ()).throw(RuntimeError("boom")))
        assert queue.wait_idle(10.0)
        assert bad.state is JobState.FAILED
        assert "RuntimeError: boom" in (bad.error or "")

        good = queue.submit("demo", lambda j: j.results.append({"ok": True}))
        assert queue.wait_idle(10.0)
        assert good.state is JobState.SUCCEEDED, "the drain thread did not survive"

    def test_cancelling_stops_at_an_item_boundary_and_keeps_finished_work(self) -> None:
        """Cancellation is cooperative, and what was done stays done."""
        queue = JobQueue()
        started = threading.Event()

        def work(job: Job) -> None:
            for i in range(100):
                job.raise_if_cancelled()
                job.results.append({"i": i})
                job.done += 1
                started.set()
                time.sleep(0.01)

        job = queue.submit("demo", work, total=100)
        assert started.wait(10.0)
        assert queue.cancel(job.job_id)
        assert queue.wait_idle(10.0)

        assert job.state is JobState.CANCELLED
        assert job.results, "a cancelled job discarded work it had already completed"
        assert len(job.results) < 100, "cancellation did not actually stop the job"
        assert job.done == len(job.results)

    def test_cancelling_a_finished_job_is_refused_rather_than_ignored(self) -> None:
        queue = JobQueue()
        job = queue.submit("demo", lambda j: None)
        assert queue.wait_idle(10.0)
        assert queue.cancel(job.job_id) is False
        assert queue.cancel("no-such-job") is False

    def test_finished_jobs_are_evicted_past_the_retention_cap(self) -> None:
        """An unbounded history is a slow leak in a server that runs for weeks."""
        queue = JobQueue(retention=3)
        jobs = [queue.submit("demo", lambda j: None) for _ in range(10)]
        assert queue.wait_idle(10.0)
        # Submit once more so the eviction pass runs after the last one finished.
        queue.submit("demo", lambda j: None)
        assert queue.wait_idle(10.0)
        assert len(queue.list()) <= 4
        assert queue.get(jobs[0].job_id) is None, "the oldest job was never evicted"

    def test_the_list_is_newest_first(self) -> None:
        queue = JobQueue()
        first = queue.submit("demo", lambda j: None, label="first")
        second = queue.submit("demo", lambda j: None, label="second")
        assert queue.wait_idle(10.0)
        assert [j.job_id for j in queue.list()][:2] == [second.job_id, first.job_id]

    def test_the_list_view_omits_per_item_results(self) -> None:
        """A 2,000-member job carries 2,000 rows; the list must not return them."""
        queue = JobQueue()
        job = queue.submit("demo", lambda j: j.results.extend([{"i": i} for i in range(50)]))
        assert queue.wait_idle(10.0)
        assert "results" not in job.as_dict(include_items=False)
        assert len(job.as_dict()["results"]) == 50


class TestBulkIngestInBackground:
    """The route, end to end, through the real queue."""

    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(app)

    def _drain(self, client: TestClient, job_id: str, timeout: float = 60.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            body = client.get(f"/jobs/{job_id}").json()
            if body["state"] in ("succeeded", "failed", "cancelled"):
                return body
            time.sleep(0.05)
        raise AssertionError(f"job {job_id} did not finish within {timeout}s")

    def test_background_returns_202_with_a_job_id_and_then_ingests(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/ingest/bulk?background=true",
            files={"file": ("estate.zip", _archive(4), "application/zip")},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["job_id"] and body["total"] == 4
        assert body["label"] == "estate.zip"

        done = self._drain(client, body["job_id"])
        assert done["state"] == "succeeded"
        assert done["succeeded"] == 4 and done["failed"] == 0
        assert done["done"] == 4
        assert {r["hostname"] for r in done["results"]} == {
            f"job-router-{n}" for n in range(4)
        }

    def test_both_modes_agree_on_what_the_archive_contained(
        self, client: TestClient
    ) -> None:
        """The two modes share one walk; this is what says so.

        If they ever diverge, a bulk import would mean something different
        depending on a query parameter, which is the reason ``backend/app/bulk.py``
        was extracted rather than the async path being written beside the old one.
        """
        archive = _archive(3)
        sync = client.post(
            "/ingest/bulk", files={"file": ("a.zip", archive, "application/zip")}
        ).json()
        started = client.post(
            "/ingest/bulk?background=true",
            files={"file": ("a.zip", archive, "application/zip")},
        ).json()
        asyn = self._drain(client, started["job_id"])

        assert sync["success"] == asyn["succeeded"]
        assert sync["failed"] == asyn["failed"]
        assert [r["hostname"] for r in sync["results"]] == [
            r["hostname"] for r in asyn["results"]
        ]

    def test_a_malformed_archive_fails_before_a_job_is_promised(
        self, client: TestClient
    ) -> None:
        """Validation happens before the 202, not inside a job that dies at once.

        A 202 says "this will be processed". Returning one for an archive that is
        not a ZIP would turn an immediate, legible 400 into a job the operator has
        to poll in order to discover the same thing.
        """
        resp = client.post(
            "/ingest/bulk?background=true",
            files={"file": ("nope.zip", b"this is not a zip", "application/zip")},
        )
        assert resp.status_code == 400
        assert "not a valid ZIP archive" in resp.json()["detail"]

    def test_an_unknown_job_is_a_404_that_says_where_the_data_went(
        self, client: TestClient
    ) -> None:
        """Job state is in-memory; the 404 must not read as "your upload vanished"."""
        resp = client.get("/jobs/deadbeef")
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert "in-memory" in detail and "database" in detail

    def test_cancelling_a_finished_job_is_a_409_not_a_404(
        self, client: TestClient
    ) -> None:
        """"Too late" and "never existed" are different answers to the operator."""
        started = client.post(
            "/ingest/bulk?background=true",
            files={"file": ("a.zip", _archive(1), "application/zip")},
        ).json()
        self._drain(client, started["job_id"])

        resp = client.post(f"/jobs/{started['job_id']}/cancel")
        assert resp.status_code == 409
        assert "already finished" in resp.json()["detail"]
        assert client.post("/jobs/deadbeef/cancel").status_code == 404

    def test_the_job_appears_in_the_list(self, client: TestClient) -> None:
        started = client.post(
            "/ingest/bulk?background=true",
            files={"file": ("listed.zip", _archive(1), "application/zip")},
        ).json()
        self._drain(client, started["job_id"])

        listed = client.get("/jobs").json()["jobs"]
        mine = [j for j in listed if j["job_id"] == started["job_id"]]
        assert mine, "a completed job is missing from GET /jobs"
        assert "results" not in mine[0]

    def test_the_default_is_still_synchronous(self, client: TestClient) -> None:
        """Changing an existing route's response shape breaks every caller.

        ``background`` is opt-in for that reason alone, and this test is what
        stops a later "the async path is better, make it the default" from
        shipping without the version bump that would need.
        """
        resp = client.post(
            "/ingest/bulk", files={"file": ("a.zip", _archive(2), "application/zip")}
        )
        assert resp.status_code == 200
        assert set(resp.json()) == {
            "total_files",
            "success",
            "failed",
            "results",
            "errors",
        }
