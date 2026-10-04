"""An in-process job queue for work too long to hold an HTTP request open.

MASTER_PROMPT §9.3 specifies this, and ``/ingest/bulk`` is why it is needed: the
archive ceilings are 2,000 members and 512 MB expanded, so the guard rails are
already wider than a synchronous request can carry. A 2,000-device estate parses
in minutes, not milliseconds, and a client that must hold a connection open for
that has no way to show progress, no way to cancel, and no way to survive a
proxy's idle timeout.

Three design choices are worth stating, because each had a more obvious
alternative that is wrong here.

**One worker thread, not a pool.** The queue serialises jobs rather than running
them concurrently. Every job in this system writes to the same SQLite file, and
SQLite in WAL mode takes one writer at a time — concurrent bulk ingests would
spend their parallelism blocking on the write lock and then surface it to the
operator as ``database is locked``. Serial execution makes the bound explicit and
the failure mode absent. The FastAPI event loop stays responsive because the work
is off it, which is the property that actually mattered.

**In-memory state, deliberately.** A job record is progress reporting, not
evidence. Everything a job *produces* — devices, facts, audit records — is
committed to SQLite as it goes, so a crash mid-job loses the progress bar and
nothing else; the members already ingested stay ingested. Persisting job rows
would add a schema, a migration and a rehydration path to make a transient
display survive, and would invite the reading that an interrupted job is
resumable, which it is not. :data:`RETENTION` bounds the dict so a long-lived
server cannot grow one entry per upload forever.

**Cooperative cancellation.** :meth:`JobQueue.cancel` sets a flag the worker
checks between items. There is no way to interrupt a thread mid-item in Python
and the alternatives — a process the parent can kill, or a signal — would make
the partial-write question much harder to answer than "the item boundary is the
only place we stop". A cancelled job's completed items remain committed, and the
job says how many those were.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from queue import Empty, Queue
from typing import Any

LOGGER = logging.getLogger(__name__)

#: How many finished jobs to keep. A browser polls for a few seconds after a job
#: ends and then stops caring; anything older is only useful for "what did I run
#: this session", which 64 covers. The cap exists because an unbounded dict in a
#: server that runs for weeks is a slow leak, not because 64 is special.
RETENTION = 64


class JobState(str, Enum):
    """Where a job is. ``str`` so it serialises without a custom encoder."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED)


class JobCancelledError(Exception):
    """Raised inside a worker when the operator cancelled the job."""


@dataclass
class Job:
    """One unit of background work and everything a poller needs to see.

    ``results`` and ``errors`` accumulate *during* the run rather than being
    returned at the end, which is what lets a client show a device appearing in
    the list before the archive finishes. It is also what makes cancellation
    honest: the work already done is visible and committed, not discarded.
    """

    job_id: str
    kind: str
    total: int = 0
    done: int = 0
    state: JobState = JobState.QUEUED
    #: Set when ``state`` is FAILED — the job itself broke, as opposed to an
    #: individual item failing, which lands in ``errors`` and is not fatal.
    error: str | None = None
    results: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    started_at: str | None = None
    finished_at: str | None = None
    #: Free-form label shown beside the progress bar, e.g. the archive filename.
    label: str = ""
    _cancelled: threading.Event = field(default_factory=threading.Event, repr=False)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _now()

    @property
    def cancelling(self) -> bool:
        return self._cancelled.is_set()

    def raise_if_cancelled(self) -> None:
        """Call between items. The worker's only cancellation point."""
        if self._cancelled.is_set():
            raise JobCancelledError()

    def as_dict(self, *, include_items: bool = True) -> dict[str, Any]:
        """Serialise for the API.

        ``include_items=False`` exists for the list endpoint: a 2,000-member job
        carries 2,000 result rows, and returning all of them for every job in the
        history turns "what is running" into a multi-megabyte response.
        """
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "kind": self.kind,
            "label": self.label,
            "state": self.state.value,
            "total": self.total,
            "done": self.done,
            "succeeded": len(self.results),
            "failed": len(self.errors),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
        }
        if include_items:
            payload["results"] = list(self.results)
            payload["errors"] = list(self.errors)
        return payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobQueue:
    """A FIFO queue drained by one background thread.

    The thread is started lazily on the first submission rather than at import,
    so importing this module — which the test suite does hundreds of times — does
    not spawn anything. It is a daemon thread: a queued job must never keep the
    interpreter alive at shutdown, because the alternative is a server that
    appears to hang when you stop it.
    """

    def __init__(self, *, retention: int = RETENTION) -> None:
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._pending: Queue[tuple[Job, Callable[[Job], None]]] = Queue()
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        self._retention = retention
        #: Set while nothing is queued or running, so a caller can wait for the
        #: queue to drain without polling. Gated on :attr:`_outstanding` rather
        #: than on "the pending queue looks empty", because the worker can finish
        #: one job while a submitter is between two ``put`` calls, and a waiter
        #: woken in that window would see a drained queue that is not.
        self._outstanding = 0
        self._idle = threading.Event()
        self._idle.set()

    # ── submission ────────────────────────────────────────────────────

    def submit(
        self,
        kind: str,
        work: Callable[[Job], None],
        *,
        label: str = "",
        total: int = 0,
    ) -> Job:
        """Queue ``work`` and return its :class:`Job` immediately.

        ``work`` receives the job and is expected to mutate ``done``, ``results``
        and ``errors`` as it goes, and to call
        :meth:`Job.raise_if_cancelled` between items.
        """
        job = Job(job_id=uuid.uuid4().hex, kind=kind, label=label, total=total)
        with self._lock:
            self._jobs[job.job_id] = job
            self._evict()
            self._outstanding += 1
            self._idle.clear()
            self._ensure_worker()
        self._pending.put((job, work))
        return job

    def _ensure_worker(self) -> None:
        """Start the drain thread if it is not already running. Caller holds the lock."""
        if self._worker is not None and self._worker.is_alive():
            return
        self._worker = threading.Thread(target=self._drain, name="praman-jobs", daemon=True)
        self._worker.start()

    def _evict(self) -> None:
        """Drop the oldest terminal jobs past ``retention``. Caller holds the lock."""
        terminal = [jid for jid, job in self._jobs.items() if job.state.is_terminal]
        for job_id in terminal[: max(0, len(terminal) - self._retention)]:
            del self._jobs[job_id]

    # ── the worker ────────────────────────────────────────────────────

    def _drain(self) -> None:
        while True:
            try:
                job, work = self._pending.get(timeout=30.0)
            except Empty:
                with self._lock:
                    # Exit only if nothing arrived while we were deciding to,
                    # otherwise a submission racing this timeout would be left
                    # with no thread to run it.
                    if self._outstanding == 0:
                        self._worker = None
                        return
                continue
            self._run(job, work)
            self._pending.task_done()
            with self._lock:
                self._outstanding -= 1
                if self._outstanding == 0:
                    self._idle.set()

    def _run(self, job: Job, work: Callable[[Job], None]) -> None:
        if job.cancelling:
            # Cancelled while still queued: it never ran, so there is nothing
            # partially done to report.
            job.state, job.finished_at = JobState.CANCELLED, _now()
            return
        job.state, job.started_at = JobState.RUNNING, _now()
        try:
            work(job)
        except JobCancelledError:
            job.state = JobState.CANCELLED
        except Exception as exc:
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            LOGGER.exception("job %s (%s) failed", job.job_id, job.kind)
        else:
            job.state = JobState.SUCCEEDED
        finally:
            job.finished_at = _now()

    # ── inspection ────────────────────────────────────────────────────

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        """Newest first, which is the order a job list is read in."""
        with self._lock:
            return list(reversed(self._jobs.values()))

    def cancel(self, job_id: str) -> bool:
        """Ask a job to stop. False if it is unknown or already finished."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.state.is_terminal:
                return False
            job._cancelled.set()
            return True

    def wait_idle(self, timeout: float = 30.0) -> bool:
        """Block until the queue drains. For tests and for shutdown, not routes."""
        return self._idle.wait(timeout)

    def __iter__(self) -> Iterator[Job]:
        return iter(self.list())


#: The process-wide queue. One per interpreter, because the whole point is that
#: the work runs in the same process as FastAPI and the only durable state is the
#: SQLite file — see the module docstring.
QUEUE = JobQueue()
