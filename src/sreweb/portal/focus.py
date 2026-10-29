"""Focus: an instructor helping a student brings the student's browser onto the project they
are both looking at, and keeps the two pages in step.

The in-memory registry ``Focuses`` holds one ``Focus`` per instructor and project: the
instructor (``leader``), the host and running lab name of the student's project, the student
(the owner of the running lab name), the ``view`` the two pages share (the active tab, the
terminal sub-tab shown, the question selected: opaque here, published by either page with
``PUT /api/focus/{id}/view`` and pushed to every socket of both pages, the browsers dropping the
echo of their own view) and the sockets of the instructor's page and of the student's pages
(``GET /api/focus/{id}/ws``).  The presence sockets (``presentation.Presence``) tell the
student's pages about the focus (``{"t": "focus", "id", "url", "host", "rln", "instructor"}``
and ``{"t": "focus", "id", "ended": true}``): a page that does not show the project navigates
to it, the project page takes the focus colour and follows the shared view.

A student is in at most one focus at a time: the newest one wins and ``resync()`` pushes the
delta after every change (an older focus still running comes back when the newer one ends,
as for the presentations).  A focus ends when the instructor turns it off, when the
instructor's page has kept no socket open for ``INSTRUCTOR_GRACE`` seconds (a reload survives),
or when the portal shuts down.  Pure like ``presentation.py``: the routes hand it ``Watcher``
objects, the tests fakes.
"""
import asyncio
import contextlib
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable

from .accesslog import iso_time
from .presentation import Presence, Watcher, MAX_VIEW_BYTES
from ..identity import Identity, running_lab_name_owner

log = logging.getLogger('sreweb.portal')

#: Seconds without a focus socket of the instructor's page before the focus ends.
INSTRUCTOR_GRACE = 60.0
TICK = 10.0                   # period of the grace check
#: Close code of a focus socket when the focus is over.
WS_FOCUS_ENDED = 4412


def project_page_url(host: str, rln: str) -> str:
    """The project page of the student, as the browser builds it (``encodeURIComponent``)."""
    return f"/projects/{urllib.parse.quote(host, safe='')}/{urllib.parse.quote(rln, safe='')}"


def check_view(view) -> dict:
    """The shared view: a JSON object of at most ``MAX_VIEW_BYTES``."""
    if not isinstance(view, dict):
        raise ValueError("the view must be a JSON object")
    if len(json.dumps(view, separators=(',', ':')).encode('utf-8')) > MAX_VIEW_BYTES:
        raise ValueError("view too large")
    return view


@dataclass(eq=False)
class Focus:
    id: str
    instructor: Identity            # as at the start
    host: str
    rln: str
    student: str                    # the owner of the running lab name
    started_at: float
    view: dict = field(default_factory=dict)
    instructor_sockets: set = field(default_factory=set)
    student_sockets: set = field(default_factory=set)
    instructor_absent_since: float | None = None    # None while the instructor's page keeps a socket
    last_status: dict | None = None                 # the last status sent to the instructor's page

    def participant(self, identity: Identity | None) -> bool:
        return identity is not None and identity.login in (self.instructor.login, self.student)

    def sockets(self) -> list:
        return [*self.instructor_sockets, *self.student_sockets]

    def to_dict(self) -> dict:
        return {'id': self.id, 'host': self.host, 'rln': self.rln,
                'instructor': {'login': self.instructor.login, 'fullname': self.instructor.fullname},
                'student': self.student, 'view': self.view, 'started_at': iso_time(self.started_at),
                'connected': len(self.student_sockets)}


class Focuses:
    """The running focuses and what the students' browsers were told (``shown``: login -> the
    id of the focus pushed to their pages).  *clock* (``time.time``) dates the starts and the
    instructor's absence (the tests move it)."""

    def __init__(self, presence: Presence, *, clock=time.time, grace: float = INSTRUCTOR_GRACE):
        self.presence = presence
        self.clock = clock
        self.grace = grace
        self._focuses: dict[str, Focus] = {}
        self.shown: dict[str, str] = {}
        self._task: asyncio.Task | None = None

    # -- queries --------------------------------------------------------------------------------

    def get(self, focus_id: str) -> Focus | None:
        return self._focuses.get(focus_id)

    def listing(self) -> list:
        return sorted(self._focuses.values(), key=lambda f: (f.started_at, f.id))

    def for_instructor(self, login: str) -> list:
        return [f for f in self.listing() if f.instructor.login == login]

    def of_student(self, login: str | None) -> Focus | None:
        """The focus the student's browser follows: the newest one on them."""
        candidates = [f for f in self._focuses.values() if f.student == login]
        return max(candidates, key=lambda f: (f.started_at, f.id), default=None)

    def _require(self, focus_id: str) -> Focus:
        f = self._focuses.get(focus_id)
        if f is None:
            raise KeyError(focus_id)
        return f

    # -- life cycle -----------------------------------------------------------------------------

    def _new_id(self) -> str:
        while True:
            new = secrets.token_urlsafe(16)
            if new not in self._focuses:
                return new

    async def start(self, instructor: Identity, host: str, rln: str, view=None) -> Focus:
        """A new focus; an earlier one of the same instructor on the same project is replaced;
        the student's pages are told.  ``ValueError`` on a running lab name without owner, on
        the instructor's own project, or on a bad view."""
        student = running_lab_name_owner(rln)
        if student is None:
            raise ValueError("bad running lab name")
        if student == instructor.login:
            raise ValueError("your own project")
        view = check_view({} if view is None else view)
        for old in [f for f in self._focuses.values()
                    if f.instructor.login == instructor.login and (f.host, f.rln) == (host, rln)]:
            await self.end(old.id, 'replaced')
        now = self.clock()
        f = Focus(self._new_id(), instructor, host, rln, student, now, view=view, instructor_absent_since=now)
        self._focuses[f.id] = f
        log.info("focus %s: %s focuses %s on %s (%s)", f.id, instructor.login, student, rln, host)
        await self.resync({student})
        return f

    async def set_view(self, focus_id: str, view) -> Focus:
        """The shared view, pushed to every socket of both pages (the sender's included: the
        browser drops the echo of what it published)."""
        f = self._require(focus_id)
        f.view = check_view(view)
        message = {'t': 'view', 'view': f.view}
        for watchers in (f.instructor_sockets, f.student_sockets):
            for watcher in list(watchers):
                if not await watcher.send_quietly(message):
                    watchers.discard(watcher)
        return f

    async def end(self, focus_id: str, reason: str = 'requested') -> Focus | None:
        """Over: every socket closed with ``WS_FOCUS_ENDED``, the student's pages told
        (``resync``); idempotent."""
        f = self._focuses.pop(focus_id, None)
        if f is None:
            return None
        log.info("focus %s of %s on %s ended (%s)", f.id, f.instructor.login, f.rln, reason)
        affected = {f.student} | {login for login, shown in self.shown.items() if shown == f.id}
        for watcher in f.sockets():
            await watcher.close_quietly(WS_FOCUS_ENDED, "the focus has ended")
        f.instructor_sockets.clear()
        f.student_sockets.clear()
        await self.resync(affected)
        return f

    def _started_message(self, f: Focus) -> dict:
        return {'t': 'focus', 'id': f.id, 'url': project_page_url(f.host, f.rln), 'host': f.host, 'rln': f.rln,
                'instructor': f.instructor.fullname or f.instructor.login}

    async def resync(self, logins: Iterable[str]):
        """For each login, the focus their browser must follow now (``of_student``) compared
        with the one they were told about (``shown``): the ``ended`` and started pushes of the
        difference, the student sockets of a focus no longer followed closed."""
        for login in set(logins):
            current = self.of_student(login) if self.presence.identity_of(login) is not None else None
            shown = self.shown.get(login)
            if current is not None and current.id == shown:
                continue
            if shown is not None:
                old = self._focuses.get(shown)
                if old is not None:
                    for watcher in list(old.student_sockets):
                        await watcher.close_quietly(WS_FOCUS_ENDED, "the focus has ended")
                    old.student_sockets.clear()
                    await self._notify_instructor(old)
                del self.shown[login]
                await self.presence.push(login, {'t': 'focus', 'id': shown, 'ended': True})
            if current is not None:
                self.shown[login] = current.id
                await self.presence.push(login, self._started_message(current))

    async def tell(self, login: str, watcher: Watcher):
        """The focus *login* follows now, to one new presence socket of theirs when their other
        pages were told already (``resync`` pushes the changes only): a page opened during the
        focus goes to the project like the others."""
        f = self.of_student(login)
        if f is not None and self.shown.get(login) == f.id:
            await watcher.send_quietly(self._started_message(f))

    # -- the sockets of the two pages -------------------------------------------------------------

    def _status_message(self, f: Focus) -> dict:
        return {'t': 'student', 'connected': len(f.student_sockets)}

    async def _notify_instructor(self, f: Focus):
        """Whether the student's page follows, to the instructor's page, when it changed."""
        message = self._status_message(f)
        if message == f.last_status:
            return
        f.last_status = message
        for watcher in list(f.instructor_sockets):
            if not await watcher.send_quietly(message):
                f.instructor_sockets.discard(watcher)

    async def attach_instructor(self, focus_id: str, watcher: Watcher) -> bool:
        """The instructor's page is there: the absence clock stops; the status and the shared
        view are sent at once.  ``False`` when the focus is over."""
        f = self._focuses.get(focus_id)
        if f is None:
            return False
        f.instructor_sockets.add(watcher)
        f.instructor_absent_since = None
        f.last_status = self._status_message(f)
        await watcher.send_quietly(f.last_status)
        await watcher.send_quietly({'t': 'view', 'view': f.view})
        return True

    def detach_instructor(self, focus_id: str, watcher: Watcher):
        f = self._focuses.get(focus_id)
        if f is None:
            return
        f.instructor_sockets.discard(watcher)
        if not f.instructor_sockets:
            f.instructor_absent_since = self.clock()

    async def attach_student(self, focus_id: str, identity: Identity, watcher: Watcher) -> bool:
        """The student's page: it gets the shared view at once, the instructor's page the new
        count.  ``False`` when the focus is over or *identity* is not its student."""
        f = self._focuses.get(focus_id)
        if f is None or identity.login != f.student:
            return False
        f.student_sockets.add(watcher)
        await watcher.send_quietly({'t': 'view', 'view': f.view})
        await self._notify_instructor(f)
        return True

    async def detach_student(self, focus_id: str, watcher: Watcher):
        f = self._focuses.get(focus_id)
        if f is None:
            return
        f.student_sockets.discard(watcher)
        await self._notify_instructor(f)

    # -- the grace of an absent instructor --------------------------------------------------------

    async def tick(self, now: float | None = None):
        """End the focuses whose instructor has been away for the grace period."""
        now = self.clock() if now is None else now
        for f in list(self._focuses.values()):
            if f.instructor_absent_since is not None and now - f.instructor_absent_since >= self.grace:
                await self.end(f.id, 'instructor gone')

    async def shutdown(self):
        for f in list(self._focuses.values()):
            await self.end(f.id, 'shutdown')

    async def _loop(self):
        while True:
            await asyncio.sleep(TICK)
            try:
                await self.tick()
            except Exception:
                log.exception("focuses: tick failed")

    def start_loop(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop_loop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
