"""The machines of the exams: ``exam.json`` kept in step on the pool hosts an exam lists.

An exam of the web site may be taken at machines of the pool, with the Qt GUI (``Exam.hosts``):
the agent of each machine then writes the exam file of the host for the portal (``PUT /v1/exam``,
in place of ``sre set-exam``) and removes it (``DELETE /v1/exam``, in place of ``sre del-exam``;
``close=1`` also stops the exam projects of the GUI there).  This module decides, every
``RECONCILE_INTERVAL`` seconds and right after each change of an exam, what every machine should
hold now, and compares it with the ``exam`` its agent told in its last status
(``HostStatus.exam``):

* from ``Exam.lock_at()`` to ``Exam.release_at(host)`` the file is wanted, with the definition
  of ``host_payload()`` (the end-before time and the duration of *that* machine: its extra
  minutes, an *End now*); its ``rev`` is a digest of that definition, so a machine is up to
  date when it reports the same one;
* at ``release_at`` the machine is closed by itself (``Exams.close_hosts``), like one an
  instructor closes: the agent stops the exam projects and removes the file;
* a file of an exam that no longer wants the machine (closed, unselected, start postponed) is
  removed; one of an exam this portal does not know (deleted meanwhile) only when it says the
  exam is not running there.

Nothing is done before the exams are read from the database: every machine would look like it
held the exam of nobody.  The files of another portal (``origin``) and those set by hand are
never touched.  The calls carry the identity of the instructor who created the exam.
"""
import asyncio
import contextlib
import hashlib
import json
import logging
import math
import time

from .examprojects import instructor_identity
from .exams import Exams, Exam, ExamHost, iso_utc, normal_lab, MAX_MINUTES, HOST_SCHEDULED, HOST_CLOSED
from .pool import Pool, PoolError
from .relay import Relay
from ..agent.occupancy import SESSION_PREFIX

log = logging.getLogger('sreweb.portal')

RECONCILE_INTERVAL = 5.0        # seconds between two passes over the machines
RETRY_DELAY = 15.0              # before a call an agent refused or did not answer is tried again
CALL_TIMEOUT = 20.0             # a PUT, a DELETE without close
CLOSE_TIMEOUT = 900.0           # a DELETE with close (the final evaluation, the stops)
KICK_WAIT = 3.0                 # how long a request waits for the pass it asked for
#: Phases of a machine only the live status tells (the others: ``Exam.host_phase``): the file is
#: wanted there and not there yet; its agent refused it (the file of somebody else is there).
HOST_PENDING = 'pending'
HOST_CONFLICT = 'conflict'


def revision(payload: dict) -> str:
    """The digest of a definition: what a machine reports when it holds exactly that one."""
    canonical = json.dumps({k: v for k, v in payload.items() if k not in ('rev', 'now')}, sort_keys=True,
                           separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:16]


def host_payload(exam: Exam, host: ExamHost, origin: str) -> dict:
    """The definition of the exam for one machine, as its agent takes it (``PUT /v1/exam``):
    the end-before time of the machine (its extra minutes, an *End now*), and a duration always
    — the exam's plus the extra minutes, or, for an exam with a window alone, the length of the
    window (the GUI takes 90 minutes when the file has none; the end-before time comes first
    anyway)."""
    end_before = exam.host_end_before(host)
    if exam.duration is not None:
        duration = exam.duration + host.extra_minutes * 60
    elif end_before is not None:
        duration = end_before - exam.start_at()
    else:
        duration = MAX_MINUTES * 60
    payload = {'id': str(exam.id), 'title': ''.join(c for c in exam.title if c.isprintable()), 'origin': origin,
               'labs': [lab.to_dict() for lab in exam.labs],
               'start_after': iso_utc(exam.start_after) if exam.start_after is not None else None,
               'end_before': iso_utc(end_before) if end_before is not None else None,
               'duration': min(MAX_MINUTES, max(1, math.ceil(duration / 60))),
               'eval_interval': max(1, int(round(exam.eval_interval)))}
    payload['rev'] = revision(payload)
    return payload


def file_running(reported: dict, now: float) -> bool:
    """Whether the exam file a machine reports says the exam runs there: started, and neither
    its end-before time nor its duration passed."""
    started = reported.get('started_at')
    if started is None:
        return False
    ends = [end for end in (reported.get('end_before'),
                            started + reported['duration'] * 60 if reported.get('duration') else None)
            if end is not None]
    return not ends or now < min(ends)


class ExamHosts:
    """*origin*: what marks the files of this portal (``ExamStore.origin()``; ``''``: the exams
    are not stored, no machine is ever told).  *exam_projects*: closes the web exam projects a
    student pre-started before sitting at a machine."""

    def __init__(self, exams: Exams, pool: Pool, relay: Relay, *, origin: str = '', exam_projects=None,
                 clock=time.time):
        self.exams = exams
        self.pool = pool
        self.relay = relay
        self.origin = origin
        self.exam_projects = exam_projects
        self.clock = clock
        self._last_pass = 0.0
        self._retry_at: dict[tuple, float] = {}         # (exam id, host) -> not before
        self.errors: dict[tuple, tuple] = {}            # (exam id, host) -> (status, message) of the last refusal
        self._warned: set = set()
        self._closing: dict[tuple, asyncio.Task] = {}   # (exam id, host) -> its DELETE with close, in flight
        self._tasks: set = set()                        # the other background tasks (kept until done)
        self._lock = asyncio.Lock()                     # one pass at a time

    # -- queries --------------------------------------------------------------------------------

    def _warn_once(self, key, message, *args):
        if key not in self._warned:
            self._warned.add(key)
            log.warning(message, *args)

    def ready(self) -> bool:
        return bool(self.origin) and self.exams.loaded

    def held(self, name: str, now: float | None = None) -> bool:
        """``Pool.exam_hold``: an exam keeps the machine for itself now."""
        now = self.clock() if now is None else now
        for exam in self.exams.listing():
            host = exam.hosts.get(name)
            if host is not None and exam.host_held(host, now):
                return True
        return False

    def _reported(self, name: str) -> dict | None:
        """The exam file the machine told last, when it is one of this portal."""
        status = self.pool.status.get(name)
        if status is None or not status.reachable or status.exam is None:
            return None
        return status.exam if status.exam.get('origin') == self.origin and status.exam.get('id') else None

    def on_machine(self, exam: Exam, name: str) -> dict | None:
        """The file of *exam* the machine holds, as it told last; ``None`` when it holds none."""
        reported = self._reported(name)
        return reported if reported is not None and reported['id'] == str(exam.id) else None

    def sessions(self, name: str) -> list:
        """The logins of the local sessions of a machine (its last status)."""
        status = self.pool.status.get(name)
        if status is None or not status.reachable:
            return []
        return sorted(entry[len(SESSION_PREFIX):] for entry in status.occupied_by if entry.startswith(SESSION_PREFIX))

    def session_host(self, exam: Exam, login: str, now: float | None = None) -> str | None:
        """The machine of the exam, locked now, *login* has a local session at."""
        now = self.clock() if now is None else now
        for host in exam.hosts.values():
            if exam.host_wanted(host, now) and login in self.sessions(host.name):
                return host.name
        return None

    # -- the students at the machines -----------------------------------------------------------

    async def mark_local(self, exam: Exam, login: str, host: str, now: float | None = None):
        """A student of the audience sits at a machine of the exam: they take it there; the web
        exam projects their browser pre-started are closed (their clock never started: no agent
        would reap them)."""
        member = await self.exams.set_local(exam, login, host, now)
        if member is not None and member.projects and self.exam_projects is not None:
            self._background(self.exam_projects.close_member(exam, member))

    async def note_request(self, identity, now: float | None = None):
        """A request of a student: when they are logged in at a locked machine of an exam of
        theirs, they take it there (before the 5 s pass sees their session)."""
        if not self.ready() or identity.is_instructor:
            return
        for exam in self.exams.exams_of(identity.login, identity.group):
            host = self.session_host(exam, identity.login, now)
            if host is not None:
                await self.mark_local(exam, identity.login, host, now)

    async def _mark_sessions(self, wanted: dict, now: float):
        for name, (exam, _) in wanted.items():
            if not exam.logins and not exam.groups:
                continue
            for login in self.sessions(name):
                identity = self.exams.presence.identity_of(login)
                if identity is not None and identity.is_instructor:
                    continue
                if exam.includes(login, identity.group if identity is not None else ''):
                    await self.mark_local(exam, login, name, now)

    # -- the calls to the agents ----------------------------------------------------------------

    def _background(self, coro) -> asyncio.Task:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._done)
        return task

    def _done(self, task: asyncio.Task):
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            log.error("exams: a call to the machines failed", exc_info=task.exception())

    async def _bounded(self, coro):
        """*coro* run as a task and awaited ``KICK_WAIT`` seconds at most: an agent slow to
        answer holds neither a request nor the tick of the exams (the phases of the students);
        the task goes on."""
        task = self._background(coro)
        with contextlib.suppress(asyncio.TimeoutError, Exception):
            await asyncio.wait_for(asyncio.shield(task), KICK_WAIT)

    @staticmethod
    def _key(exam_id, name: str) -> tuple:
        """The key of the errors and retries of an exam on a machine: the id as the registry
        holds it (a number), whatever the form a machine reported."""
        text = str(exam_id)
        return (int(text) if text.isdigit() else text, name)

    def _failed(self, key: tuple, status: int, message: str, now: float):
        self.errors[key] = (status, message)
        self._retry_at[key] = now + RETRY_DELAY

    async def _call(self, exam_id, creator: Exam | None, name: str, method: str, *, json_body=None, params=None,
                    timeout: float = CALL_TIMEOUT) -> tuple:
        """One call about the exam file of the machine *name*: ``(status, body)``, the status
        ``None`` when the host is unknown or its agent does not answer."""
        try:
            host = self.pool.host(name)
        except PoolError:
            return None, "unknown host"
        identity = instructor_identity(creator) if creator is not None else instructor_identity(_Nobody)
        try:
            return await self.relay.json(host, identity, method, '/exam', json=json_body, params=params,
                                         timeout=timeout)
        except PoolError as e:
            return None, e.message
        except Exception as e:      # a relay failing in an unexpected way must not stop the pass
            log.exception("exam %s: %s /exam on %s failed", exam_id, method, name)
            return None, str(e) or type(e).__name__

    @staticmethod
    def _error_text(body) -> str:
        return str(body.get('error') or '') if isinstance(body, dict) else str(body or '')

    async def _put(self, exam: Exam, host: ExamHost, payload: dict, now: float):
        key = (exam.id, host.name)
        status, body = await self._call(exam.id, exam, host.name, 'PUT', json_body={**payload, 'now': iso_utc(now)})
        if status == 200 and isinstance(body, dict):
            self.pool.note_exam(host.name, body.get('exam'))
            if self.errors.pop(key, None) is not None or key not in self._warned:
                self._warned.add(key)
                log.info("exam %d: set on the machine %s (rev %s)", exam.id, host.name, payload['rev'])
            self._retry_at.pop(key, None)
            return
        if status is None:
            self._failed(key, 0, f"the agent does not answer: {body}", now)
        elif status == 404:
            self._failed(key, 404, "the agent of this machine is too old: it cannot be given an exam", now)
            self._warn_once(('404', host.name), "exam %d: the agent of %s knows no exam of the host "
                            "(an older agent?): the exam is not set there", exam.id, host.name)
        else:
            message = self._error_text(body) or f"status {status}"
            if self.errors.get(key) != (status, message):
                log.warning("exam %d: the machine %s refused the exam (%s): %s", exam.id, host.name, status, message)
            self._failed(key, status, message, now)

    async def _delete(self, exam_id: str, exam: Exam | None, name: str, close: bool, now: float):
        """The file of the exam *exam_id* taken off a machine (*exam*: the exam when the portal
        still knows it); with *close*, its projects there stopped first."""
        key = self._key(exam_id, name)
        params = {'id': exam_id, 'origin': self.origin}
        if close:
            params['close'] = '1'
        status, body = await self._call(exam_id, exam, name, 'DELETE', params=params,
                                        timeout=CLOSE_TIMEOUT if close else CALL_TIMEOUT)
        now = self.clock()
        if status == 200:
            self.pool.note_exam(name, None)
            self.errors.pop(key, None)
            self._retry_at.pop(key, None)
            closed = body.get('closed') if isinstance(body, dict) else None
            log.info("exam %s: removed from the machine %s%s", exam_id, name,
                     f" ({closed} project(s) closed)" if close else "")
            if exam is not None and self.exams.get(exam.id) is exam:
                await self.exams.host_closed(exam, name)
            return
        if status is None:
            self._failed(key, 0, f"the agent does not answer: {body}", now)
        else:
            message = self._error_text(body) or f"status {status}"
            if self.errors.get(key) != (status, message):
                log.warning("exam %s: the machine %s did not release the exam (%s): %s", exam_id, name, status,
                            message)
            self._failed(key, status, message, now)

    def _close(self, exam_id: str, exam: Exam | None, name: str, now: float):
        """A removal with close, in the background (the stops take minutes): one per machine."""
        key = (exam_id, name)
        running = self._closing.get(key)
        if running is not None and not running.done():
            return
        task = self._closing[key] = asyncio.ensure_future(self._delete(exam_id, exam, name, True, now))
        task.add_done_callback(lambda t, key=key: self._closing.pop(key, None) if self._closing.get(key) is t else None)

    # -- the pass -------------------------------------------------------------------------------

    async def reconcile(self, now: float | None = None):
        """A tick hook of the registry: one pass every ``RECONCILE_INTERVAL`` seconds, unless the
        previous one still waits for an agent."""
        now = self.clock() if now is None else now
        if now - self._last_pass < RECONCILE_INTERVAL or self._lock.locked():
            return
        await self._bounded(self.sync(now))

    async def kick(self):
        """A pass now, after a change of an exam."""
        await self._bounded(self.sync())

    async def sync(self, now: float | None = None):
        """One pass: the machines released, then every reachable machine brought to what it
        should hold (the calls of a pass run together; a removal with close in the background)."""
        if not self.ready():
            return
        async with self._lock:
            now = self.clock() if now is None else now
            self._last_pass = now
            wanted: dict[str, tuple] = {}       # machine -> (exam, record) of the exam that wants it now
            for exam in self.exams.listing():
                released = [h.name for h in exam.hosts.values()
                            if h.closed_at is None and (release := exam.release_at(h)) is not None and now >= release]
                if released:
                    await self.exams.close_hosts(exam.id, released, now)
                for host in exam.hosts.values():
                    if exam.host_wanted(host, now):
                        wanted.setdefault(host.name, (exam, host))
            calls = []
            for name in list(self.pool.hosts):
                status = self.pool.status.get(name)
                if status is None or not status.reachable:
                    continue
                reported = self._reported(name)
                want = wanted.get(name)
                stale = reported is not None and (want is None or reported['id'] != str(want[0].id))
                if stale:
                    call = self._release_call(reported, name, now)
                    if call is not None:
                        calls.append(call)
                elif want is not None:
                    exam, host = want
                    key = (exam.id, name)
                    if not status.exam_known:
                        self.errors[key] = (404, "the agent of this machine is too old: it cannot be given an exam")
                        continue
                    payload = host_payload(exam, host, self.origin)
                    if reported is not None and reported.get('rev') == payload['rev']:
                        self.errors.pop(key, None)
                        self._retry_at.pop(key, None)
                    elif self._retry_at.get(key, 0) <= now:
                        calls.append(self._put(exam, host, payload, now))
                # a close still asked of a machine that holds nothing of that exam is done
                for exam in self.exams.listing():
                    record = exam.hosts.get(name)
                    if record is not None and record.close_pending and (reported is None
                                                                        or reported['id'] != str(exam.id)):
                        await self.exams.host_closed(exam, name)
            if calls:
                await asyncio.gather(*calls, return_exceptions=True)
            await self._mark_sessions(wanted, now)

    def _release_call(self, reported: dict, name: str, now: float):
        """What to do with the file of an exam that does not want the machine now: the
        coroutine of its removal, ``None`` when nothing is to be awaited (a close started in the
        background, a retry not due, an unknown exam still running there)."""
        exam_id = reported['id']
        exam = self.exams.get(exam_id)
        if self._retry_at.get(self._key(exam_id, name), 0) > now:
            return None
        if exam is None:
            # deleted from the portal while the machine was away: its file goes, unless the
            # exam runs there (students at work: an instructor decides)
            if file_running(reported, now):
                self._warn_once(('unknown', exam_id, name), "the machine %s runs the exam %s %r, which this portal "
                                "does not know: left alone (sre del-exam on the machine removes it)", name, exam_id,
                                reported.get('title'))
                return None
            return self._delete(exam_id, None, name, False, now)
        record = exam.hosts.get(name)
        if record is not None and record.close_pending:
            self._close(exam_id, exam, name, now)
            return None
        return self._delete(exam_id, exam, name, False, now)

    async def release(self, exam: Exam, close: bool):
        """An exam deleted: its file taken off the machines that hold it, in the background
        (with *close*: their exam projects stopped).  A machine away now is cleaned by a later
        pass (the file of an exam the portal no longer knows)."""
        for name in list(exam.hosts):
            self.errors.pop((exam.id, name), None)
            self._retry_at.pop((exam.id, name), None)
            if self.on_machine(exam, name) is not None:
                if close:
                    self._close(str(exam.id), exam, name, self.clock())
                else:
                    self._background(self._delete(str(exam.id), exam, name, False, self.clock()))

    async def shutdown(self):
        """The portal stops: the calls in flight are dropped (a close already sent goes on at
        its agent)."""
        tasks = [t for t in list(self._closing.values()) + list(self._tasks) if not t.done()]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._closing.clear()
        self._tasks.clear()

    # -- the machines table ---------------------------------------------------------------------

    def rows_of(self, exam: Exam, project_rows: list, now: float | None = None) -> list:
        """The machines of an exam for its detail: the pool state and the local sessions of
        each, its phase, the clock its file records, its release, what the instructors adjusted,
        the last refusal of its agent, its exam projects (those of the Qt GUI: *project_rows*,
        the listing of the pool, tells them) and the number of web projects running there."""
        now = self.clock() if now is None else now
        labs = {lab.lab for lab in exam.labs}
        rows = []
        for name in sorted(exam.hosts):
            host = exam.hosts[name]
            status = self.pool.status.get(name)
            reachable = bool(status is not None and status.reachable)
            on = self.on_machine(exam, name)
            started = on['started_at'] if on is not None else None
            error = self.errors.get((exam.id, name))
            phase = exam.host_phase(host, now, started)
            if phase not in (HOST_SCHEDULED, HOST_CLOSED) and on is None:
                phase = HOST_CONFLICT if error is not None and error[0] == 409 else HOST_PENDING
            rows.append({
                'name': name, 'state': self.pool.state_of(name) if name in self.pool.hosts else None,
                'reachable': reachable, 'sessions': self.sessions(name), 'phase': phase, 'locked': on is not None,
                'pre_started': bool(on is not None and on.get('pre_started')), 'started_at': started,
                'end_at': exam.host_end_at(host, started), 'release_at': exam.release_at(host),
                'extra_minutes': host.extra_minutes, 'ended_at': host.ended_at, 'closed_at': host.closed_at,
                'closing': host.close_pending, 'error': error[1] if error is not None else '',
                'projects': [{'host': name, 'rln': row.get('running_lab_name'), 'lab': normal_lab(row.get('lab_name')),
                              'owner': row.get('owner'), 'started_at': row.get('started_at')}
                             for row in project_rows
                             if row.get('host') == name and not row.get('managed')
                             and normal_lab(row.get('lab_name')) in labs],
                'web_projects': status.managed_projects if reachable else 0,
            })
        return rows


class _Nobody:
    """The creator of an exam the portal no longer knows (``instructor_identity``)."""
    created_by = ''
