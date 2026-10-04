"""Job routes — polling and cancelling background work.

Split from ``backend/app/main.py`` for the same reason
``backend/app/routes_export.py`` was: that file is the project's largest
file-length debt, and a self-contained group of routes over a single module has
no reason to live in it.

These three read and steer :data:`backend.jobs.QUEUE`; the work itself is
submitted from the route that creates it (today only ``POST /ingest/bulk``), so
nothing here knows what a job does.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from backend.app.auth import REQUIRE_AUDITOR
from backend.jobs import QUEUE

router = APIRouter()


@router.get("/jobs", dependencies=[Depends(REQUIRE_AUDITOR)])
async def list_jobs() -> dict[str, Any]:
    """Every job this process knows about, newest first, without their item lists.

    Item lists are omitted here on purpose: a 2,000-member ingest carries 2,000
    result rows, and returning them for every job in the history would turn
    "what is running" into a multi-megabyte response. Fetch one job for those.
    """
    return {"jobs": [job.as_dict(include_items=False) for job in QUEUE.list()]}


@router.get("/jobs/{job_id}", dependencies=[Depends(REQUIRE_AUDITOR)])
async def get_job(job_id: str) -> dict[str, Any]:
    """One job with its per-item results, which accumulate while it runs.

    Polling this mid-run is the intended use: the results list grows as devices
    are committed, so a client can show them appearing rather than waiting for a
    single response at the end.
    """
    job = QUEUE.get(job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"no job {job_id}. Job state is in-memory and bounded — a "
                "restart or 64 later jobs will have dropped it. What the job "
                "produced is in the database either way."
            ),
        )
    return job.as_dict()


@router.post("/jobs/{job_id}/cancel", dependencies=[Depends(REQUIRE_AUDITOR)])
async def cancel_job(job_id: str) -> dict[str, Any]:
    """Ask a running job to stop at its next item boundary.

    Cancellation is cooperative and does not roll anything back: members already
    ingested stay ingested, and the job reports how many those were. There is no
    way to interrupt a thread mid-item in Python, and a cancel that left a
    half-written device behind would be worse than one that stops cleanly a
    moment later.

    "Already finished" and "never existed" are different answers, so they get
    different codes: an operator who clicked cancel a moment too late should not
    be told their job never existed.
    """
    if not QUEUE.cancel(job_id):
        job = QUEUE.get(job_id)
        raise HTTPException(
            status_code=404 if job is None else 409,
            detail=(
                f"no job {job_id}"
                if job is None
                else f"job {job_id} already finished as {job.state.value}"
            ),
        )
    job = QUEUE.get(job_id)
    return job.as_dict(include_items=False) if job else {"job_id": job_id}
