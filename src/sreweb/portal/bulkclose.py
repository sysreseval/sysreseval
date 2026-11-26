"""The projects an instructor closes in one go from the Watch page.

A close lasts (the agent evaluates the project first when its lab asks, then stops its
machines): the request answers at once with a ``CloseJob`` running in the background — the
pattern of ``examprojects.ExamProjects.close()`` —, ``CLOSE_CONCURRENCY`` stops in flight at a
time, each a ``DELETE /v1/projects/{rln}`` on the agent of the project in the name of the
instructor (what the *Close* button of a row does).  The page reads the job back
(``GET /api/watch/close``) and greys the rows it still has to close (``closing()``).  One job
per instructor at a time; a finished one stays readable ``CLOSE_KEEP`` seconds.
"""
import asyncio
import contextlib
import logging
import time
import urllib.parse
from dataclasses import dataclass, field

from .accesslog import iso_time
from .pool import Pool, PoolError
from .relay import Relay
from ..identity import Identity

log = logging.getLogger('sreweb.portal')

CLOSE_TIMEOUT = 900.0           # the stop of one project (the agent's own timeout is 300 s)
CLOSE_CONCURRENCY = 8           # stops in flight at once
CLOSE_KEEP = 300.0              # seconds a finished job stays readable
MAX_PROJECTS = 500              # projects of one job
MAX_ERRORS = 50                 # failures kept with their reason


@dataclass
class CloseJob:
    login: str
    total: int
    started_at: float
    pending: set = field(default_factory=set)           # (host, rln) not closed yet
    closed: int = 0
    failed: list = field(default_factory=list)          # {host, rln, error}
    finished_at: float | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    @property
    def running(self) -> bool:
        return self.finished_at is None

    @property
    def done(self) -> int:
        return self.closed + len(self.failed)

    def to_dict(self) -> dict:
        return {'total': self.total, 'done': self.done, 'closed': self.closed, 'failed': len(self.failed),
                'errors': self.failed[:MAX_ERRORS], 'running': self.running, 'started_at': iso_time(self.started_at),
                'finished_at': iso_time(self.finished_at) if self.finished_at is not None else None}


class BulkClose:
    """*on_closed(host, rln)*: awaited after each project closed (its sharing ends)."""

    def __init__(self, pool: Pool, relay: Relay, *, on_closed=None, clock=time.time):
        self.pool = pool
        self.relay = relay
        self.on_closed = on_closed
        self.clock = clock
        self._jobs: dict[str, CloseJob] = {}            # login -> their job (running, or kept CLOSE_KEEP)

    def closing(self) -> set:
        """The ``(host, rln)`` the running jobs still have to close."""
        return {key for job in self._jobs.values() if job.running for key in job.pending}

    def job_of(self, login: str) -> CloseJob | None:
        job = self._jobs.get(login)
        if job is not None and not job.running and self.clock() - job.finished_at > CLOSE_KEEP:
            del self._jobs[login]
            return None
        return job

    def start(self, identity: Identity, projects: list) -> CloseJob:
        """A job closing *projects* (``(host, rln)`` pairs) for *identity*; 409 while their
        previous job runs.  The projects another job is closing are left to it."""
        running = self._jobs.get(identity.login)
        if running is not None and running.running:
            raise PoolError(409, "your previous close is still running")
        busy = self.closing()
        wanted = [key for key in dict.fromkeys(projects) if key not in busy]
        job = CloseJob(identity.login, len(wanted), self.clock(), pending=set(wanted))
        self._jobs[identity.login] = job
        if not wanted:
            job.finished_at = self.clock()
            return job
        job.task = asyncio.ensure_future(self._run(job, identity, wanted))
        log.info("%s closes %d project(s)", identity.login, len(wanted))
        return job

    async def _run(self, job: CloseJob, identity: Identity, projects: list):
        sem = asyncio.Semaphore(CLOSE_CONCURRENCY)
        try:
            await asyncio.gather(*(self._close_one(job, identity, host, rln, sem) for host, rln in projects),
                                 return_exceptions=True)
        finally:
            job.pending.clear()
            job.finished_at = self.clock()
            log.info("%s: %d project(s) closed, %d not", job.login, job.closed, len(job.failed))

    async def _close_one(self, job: CloseJob, identity: Identity, host_name: str, rln: str, sem: asyncio.Semaphore):
        error = ''
        try:
            async with sem:
                host = self.pool.host(host_name)
                status, body = await self.relay.json(host, identity, 'DELETE',
                                                     f"/projects/{urllib.parse.quote(rln, safe='')}", timeout=CLOSE_TIMEOUT)
            if status >= 400 and status != 404:           # already gone = closed
                error = str(body.get('error') if isinstance(body, dict) else body)[:300] or f"the host answered {status}"
        except PoolError as e:
            error = e.message
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception("closing %s on %s failed", rln, host_name)
            error = str(e) or type(e).__name__
        job.pending.discard((host_name, rln))
        if error:
            job.failed.append({'host': host_name, 'rln': rln, 'error': error})
            return
        job.closed += 1
        if self.on_closed is not None:
            with contextlib.suppress(Exception):
                await self.on_closed(host_name, rln)

    async def shutdown(self):
        """The running jobs cancelled (the stops already sent go on, on their agents)."""
        for job in list(self._jobs.values()):
            if job.task is not None and not job.task.done():
                job.task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await job.task
