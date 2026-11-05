"""The agents' side of the exams: the exam object of every exam project kept in step with the
portal (``PUT /v1/projects/{rln}/exam`` when a student's clock starts or an instructor adjusts
them, ``DELETE …/exam`` when a project is no longer an exam one), the exam projects closed on
request, and their rows for the members table of the Exams page.  The calls to the agents
carry the identity of the instructor who created the exam (the agent wants an instructor)."""
import asyncio
import contextlib
import logging
import time
import urllib.parse
from dataclasses import dataclass, field

from .exams import Exams, Exam, Member, iso_utc, normal_lab
from .pool import Pool, PoolError
from .relay import Relay
from ..identity import Identity, ROLE_INSTRUCTOR, is_valid_login

log = logging.getLogger('sreweb.portal')

RECONCILE_INTERVAL = 5.0        # seconds between two passes over the exam projects
RETRY_DELAY = 15.0              # before an agent call that failed is tried again
CLOSE_TIMEOUT = 900.0           # the stop of a project (the agent's own timeout is 300 s)
CLOSE_CONCURRENCY = 8           # stops of a close job in flight at once (each agent evaluates first)
CLOSE_KEEP = 300.0              # seconds a finished close job stays readable on the exam's detail


@dataclass
class CloseJob:
    """A close of exam projects running in the background (``ExamProjects.close()``): the
    request answers at once with it, the Exams page shows its progress on the detail it polls."""
    exam_id: int
    total: int
    started_at: float
    done: int = 0
    closed: int = 0
    failed: int = 0
    finished_at: float | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    @property
    def running(self) -> bool:
        return self.finished_at is None

    def to_dict(self) -> dict:
        return {'total': self.total, 'done': self.done, 'closed': self.closed, 'failed': self.failed,
                'running': self.running, 'started_at': iso_utc(self.started_at),
                'finished_at': iso_utc(self.finished_at) if self.finished_at is not None else None}


def exam_payload(exam: Exam, member: Member | None, now: float) -> dict:
    """The exam object of an exam project as the agent takes it: the times of the student's
    clock (``null`` until it started), the evaluation period, the portal's time."""
    started = member.started_at if member is not None else None
    end = exam.end_at(member)
    return {'id': str(exam.id), 'title': exam.title,
            'started_at': iso_utc(started) if started is not None else None,
            'end_at': iso_utc(end) if end is not None else None,
            'eval_interval': int(round(exam.eval_interval)), 'now': iso_utc(now)}


def instructor_identity(exam: Exam) -> Identity:
    login = exam.created_by if is_valid_login(exam.created_by) else 'sre-web'
    return Identity(login=login, role=ROLE_INSTRUCTOR)


class ExamProjects:
    def __init__(self, exams: Exams, pool: Pool, relay: Relay, *, clock=time.time):
        self.exams = exams
        self.pool = pool
        self.relay = relay
        self.clock = clock
        self._last_pass = 0.0
        self._retry_at: dict[tuple, float] = {}      # (host, rln) -> not before
        self._warned: set = set()
        self._closing: dict[int, CloseJob] = {}      # exam id -> its close job (running, or kept CLOSE_KEEP)

    @staticmethod
    def _path(rln: str, suffix: str = '') -> str:
        return f"/projects/{urllib.parse.quote(rln, safe='')}{suffix}"

    def _warn_once(self, key, message, *args):
        if key in self._warned:
            return
        self._warned.add(key)
        log.warning(message, *args)

    async def _call(self, exam: Exam, host_name: str, rln: str, method: str, suffix: str = '', *, json=None,
                    timeout: float = 60.0) -> int | None:
        """One call to the agent of *host_name* about *rln*; the status, ``None`` when the host
        is unknown or does not answer (logged once per project)."""
        try:
            host = self.pool.host(host_name)
        except PoolError:
            self._warn_once(('host', host_name), "exam %d: the host %s of %s is unknown", exam.id, host_name, rln)
            return None
        try:
            status, body = await self.relay.json(host, instructor_identity(exam), method, self._path(rln, suffix),
                                                 json=json, timeout=timeout)
        except PoolError as e:
            self._warn_once(('call', host_name, rln), "exam %d: %s %s on %s failed: %s", exam.id, method, suffix or rln,
                            host_name, e.message)
            return None
        self._warned.discard(('call', host_name, rln))
        if status >= 400 and status != 404:
            self._warn_once(('status', host_name, rln, status), "exam %d: %s %s of %s on %s answered %s: %s", exam.id,
                            method, suffix or '', rln, host_name, status,
                            body.get('error') if isinstance(body, dict) else body)
        return status

    # -- the exam objects of the projects -------------------------------------------------------

    async def sync_member(self, exam: Exam, m: Member, now: float | None = None):
        """The agents of the student's exam projects told their exam object when it changed
        (``synced`` records what each one got); the orphans told to drop theirs."""
        now = self.clock() if now is None else now
        payload = exam_payload(exam, m, now)
        wanted = [payload['started_at'], payload['end_at'], payload['eval_interval'], exam.title]
        changed = False
        for lab, p in list(m.projects.items()):
            if p.get('synced') == wanted or self._retry_at.get((p.get('host'), p.get('rln')), 0) > now:
                continue
            status = await self._call(exam, p.get('host', ''), p.get('rln', ''), 'PUT', '/exam', json=payload)
            if status is None or status >= 500:
                self._retry_at[(p.get('host'), p.get('rln'))] = now + RETRY_DELAY
                continue
            if status == 404:
                self._warn_once(('404', p.get('host')), "exam %d: the agent of %s knows no exam objects "
                                "(an older agent?): the project %s runs without one", exam.id, p.get('host'), p.get('rln'))
            p['synced'] = wanted          # an answer, whatever it is: not asked again until it changes
            changed = True
        for orphan in list(m.orphans):
            status = await self._call(exam, orphan.get('host', ''), orphan.get('rln', ''), 'DELETE', '/exam')
            if status is None or status >= 500:
                continue
            m.orphans.remove(orphan)
            changed = True
        if changed:
            await self.exams._persist_member(exam, m)

    async def reconcile(self, now: float | None = None):
        """A tick hook of the registry: every ``RECONCILE_INTERVAL`` seconds, every member of
        every exam synced."""
        now = self.clock() if now is None else now
        if now - self._last_pass < RECONCILE_INTERVAL:
            return
        self._last_pass = now
        for exam in self.exams.listing():
            for m in list(exam.members.values()):
                await self.sync_member(exam, m, now)

    async def release(self, exam: Exam):
        """An exam deleted: its projects become normal projects (best effort)."""
        for m in exam.members.values():
            for p in list(m.projects.values()):
                await self._call(exam, p.get('host', ''), p.get('rln', ''), 'DELETE', '/exam')
            for orphan in list(m.orphans):
                await self._call(exam, orphan.get('host', ''), orphan.get('rln', ''), 'DELETE', '/exam')

    async def close(self, exam: Exam, logins: set) -> CloseJob:
        """The exam projects of the students given closed by a background job (the agents stop
        them, ``CLOSE_CONCURRENCY`` at a time, each within ``CLOSE_TIMEOUT``; a project already
        gone counts as closed): the job, running — a second close of the exam meanwhile gets the
        same one, the selection is not merged — or finished at once when there is nothing to
        close.  ``closing_of()`` reads it afterwards.  A close ran sequentially inside the request
        before, which a reverse proxy cut long before the end of a class."""
        running = self._closing.get(exam.id)
        if running is not None and running.running:
            return running
        pending = [(login, m, lab, p) for login in sorted(logins) if (m := exam.members.get(login)) is not None
                   for lab, p in list(m.projects.items())]
        job = CloseJob(exam_id=exam.id, total=len(pending), started_at=self.clock())
        self._closing[exam.id] = job
        if not pending:
            job.finished_at = self.clock()
            return job
        job.task = asyncio.ensure_future(self._run_close(job, exam, pending))
        return job

    async def _run_close(self, job: CloseJob, exam: Exam, pending: list):
        sem = asyncio.Semaphore(CLOSE_CONCURRENCY)
        touched: dict = {}
        try:
            await asyncio.gather(*(self._close_one(job, exam, login, m, lab, p, sem, touched)
                                   for login, m, lab, p in pending), return_exceptions=True)
            if self.exams.get(exam.id) is exam:     # not deleted meanwhile (DELETE /api/exams/{id}?close=1)
                for m in touched.values():
                    await self.exams._persist_member(exam, m)
        finally:
            job.finished_at = self.clock()

    async def _close_one(self, job: CloseJob, exam: Exam, login: str, m: Member, lab: str, p: dict,
                         sem: asyncio.Semaphore, touched: dict):
        try:
            async with sem:
                status = await self._call(exam, p.get('host', ''), p.get('rln', ''), 'DELETE', timeout=CLOSE_TIMEOUT)
            if status is not None and (status < 400 or status == 404):
                job.closed += 1
                m.projects.pop(lab, None)
                touched[login] = m
            else:
                job.failed += 1
        finally:
            job.done += 1

    def closing_of(self, exam: Exam) -> CloseJob | None:
        """The close job of the exam: running, or finished less than ``CLOSE_KEEP`` seconds ago."""
        job = self._closing.get(exam.id)
        if job is None:
            return None
        if not job.running and self.clock() - job.finished_at > CLOSE_KEEP:
            del self._closing[exam.id]
            return None
        return job

    async def shutdown(self):
        """The portal stops: the running close jobs are cancelled (the stops already sent go on
        at the agents)."""
        for job in list(self._closing.values()):
            if job.task is not None and not job.task.done():
                job.task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await job.task
            if job.finished_at is None:          # a task cancelled before its first step ran no finally
                job.finished_at = self.clock()
        self._closing.clear()

    # -- the members table ----------------------------------------------------------------------

    @staticmethod
    def is_exam_row(exam: Exam, row: dict) -> bool:
        owner = row.get('owner')
        if not isinstance(owner, str):
            return False
        marker = row.get('exam')
        if isinstance(marker, dict) and str(marker.get('id', '')) not in ('', str(exam.id)):
            return False
        return normal_lab(row.get('lab_name')) in exam.lab_names(owner)

    async def rows_of(self, exam: Exam, instructor: Identity) -> dict:
        """The running exam projects of the students, by login, from one listing of the pool."""
        rows = await self.pool.projects_of(instructor, all_projects=True)
        found: dict[str, list] = {}
        for row in rows:
            if self.is_exam_row(exam, row):
                found.setdefault(row['owner'], []).append(
                    {'host': row.get('host'), 'rln': row.get('running_lab_name'), 'lab': normal_lab(row.get('lab_name')),
                     'started_at': row.get('started_at'), 'managed': row.get('managed'),
                     'exam': row.get('exam') if isinstance(row.get('exam'), dict) else None})
        return found
