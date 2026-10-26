"""Presentations: an instructor shows a project, read-only, on the browsers of chosen students.

Two in-memory registries, both pure (no aiohttp: the routes hand them ``Watcher`` objects
wrapping the WebSockets, the tests hand them fakes):

- ``Presence``: who has a page of the site open.  Every page of a logged-in user keeps one
  WebSocket (``GET /api/presence/ws``) through which the portal pushes the start and the end of
  a presentation; the instructors read it as the list of connected users (``GET /api/presence``).
- ``Presentations``: the running presentations.  One holds the presenter (the identity relayed
  for the spectators, see ``routes.Routes._target``), the host and running lab name of the
  project, the audience (explicit logins and student groups: a student of a listed group who
  connects later is included), the ``view`` the presenter's page publishes (the active tab, the
  open terminals...: opaque here but for ``instructorView``), and the sockets of the presenter's
  page and of the spectators' pages (``GET /api/presentations/{id}/ws``).

A login is in at most one presentation at a time: the newest one that includes them wins, and
``resync()`` recomputes it after every change and pushes the delta to the browsers (so a student
falls back to an older presentation still running when a newer one ends).  A presentation ends
when the presenter asks, when the presenter's page has kept no socket open for
``PRESENTER_GRACE`` seconds (a reload survives), or when the portal shuts down.
"""
import asyncio
import contextlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable

from .accesslog import iso_time
from ..identity import Identity, clean_group, is_valid_login, request_key

log = logging.getLogger('sreweb.portal')

#: Seconds without a presentation socket of the presenter before the presentation ends.
PRESENTER_GRACE = 60.0
TICK = 10.0                   # period of the grace check
MAX_VIEW_BYTES = 8 * 1024     # the serialized view dict
MAX_AUDIENCE = 1000           # logins + groups of one presentation
MAX_PAGE_LENGTH = 200         # the ``?page=`` of a presence socket
#: Close code of a presentation socket when the presentation is over.
WS_PRESENTATION_ENDED = 4411
#: ``request[SPECTATOR_KEY]``: the ``Presentation`` a project call is relayed for (a spectator).
SPECTATOR_KEY = request_key('spectator')


@dataclass(eq=False)
class Watcher:
    """One WebSocket as the registries see it: how to send a JSON message and how to close it."""
    send: Callable[[dict], Awaitable[None]]
    close: Callable[[int, str], Awaitable[None]]

    async def send_quietly(self, message: dict) -> bool:
        try:
            await self.send(message)
            return True
        except Exception:
            return False

    async def close_quietly(self, code: int, reason: str):
        with contextlib.suppress(Exception):
            await self.close(code, reason)


# -- presence ----------------------------------------------------------------------------------

@dataclass(eq=False)
class PresenceSocket:
    identity: Identity
    page: str
    watcher: Watcher
    since: float


class Presence:
    """The presence sockets, by login."""

    def __init__(self, *, clock=time.time):
        self.clock = clock
        self._sockets: dict[str, list[PresenceSocket]] = {}

    def add(self, identity: Identity, page: str, watcher: Watcher) -> PresenceSocket:
        socket = PresenceSocket(identity, page, watcher, self.clock())
        self._sockets.setdefault(identity.login, []).append(socket)
        return socket

    def remove(self, socket: PresenceSocket):
        sockets = self._sockets.get(socket.identity.login)
        if sockets is None:
            return
        with contextlib.suppress(ValueError):
            sockets.remove(socket)
        if not sockets:
            del self._sockets[socket.identity.login]

    def logins(self) -> set:
        return set(self._sockets)

    def identity_of(self, login: str) -> Identity | None:
        """The identity of a connected login as its newest socket gives it (the group may
        change between logins), ``None`` when not connected."""
        sockets = self._sockets.get(login)
        if not sockets:
            return None
        return max(sockets, key=lambda s: s.since).identity

    def logins_of_group(self, group: str) -> set:
        if not group:
            return set()
        return {login for login in self._sockets if (self.identity_of(login) or Identity(login)).group == group}

    def connected(self, exclude_login: str | None = None, *, presentation_of=lambda identity: None) -> list:
        """One row per connected login, sorted: identity fields, the distinct pages open, the
        time of the oldest socket and, through *presentation_of(identity)*, the presentation
        shown to them (``None`` when none)."""
        rows = []
        for login in sorted(self._sockets):
            sockets = self._sockets[login]
            if login == exclude_login or not sockets:
                continue
            identity = self.identity_of(login)
            rows.append({'login': login, 'fullname': identity.fullname, 'group': identity.group, 'role': identity.role,
                         'pages': sorted({s.page for s in sockets if s.page}),
                         'since': iso_time(min(s.since for s in sockets)),
                         'presentation': presentation_of(identity)})
        return rows

    async def push(self, login: str, message: dict):
        """*message* to every socket of *login* (nothing when not connected); a socket that
        cannot be written is forgotten."""
        for socket in list(self._sockets.get(login, ())):
            if not await socket.watcher.send_quietly(message):
                self.remove(socket)


# -- presentations -----------------------------------------------------------------------------

@dataclass(eq=False)
class Presentation:
    id: str
    presenter: Identity              # as at creation (student view): the identity relayed for the spectators
    host: str
    rln: str
    logins: set
    groups: set
    started_at: float
    view: dict = field(default_factory=dict)
    presenter_sockets: set = field(default_factory=set)
    spectator_sockets: dict = field(default_factory=dict)     # login -> set[Watcher]
    presenter_absent_since: float | None = None               # None while a presenter socket is open
    last_audience: dict | None = None                         # the last counts sent to the presenter

    def includes(self, identity: Identity | None) -> bool:
        """Whether *identity* belongs to the audience (by login or by group; never the presenter)."""
        if identity is None or identity.login == self.presenter.login:
            return False
        return identity.login in self.logins or bool(identity.group and identity.group in self.groups)

    def members(self, presence: Presence) -> set:
        """The explicit logins and the connected members of the groups."""
        members = set(self.logins)
        for group in self.groups:
            members |= presence.logins_of_group(group)
        members.discard(self.presenter.login)
        return members

    def connected_count(self) -> int:
        return sum(1 for sockets in self.spectator_sockets.values() if sockets)

    def to_dict(self, presence: Presence | None = None) -> dict:
        members = self.members(presence) if presence is not None else set(self.logins)
        return {'id': self.id, 'host': self.host, 'rln': self.rln,
                'presenter': {'login': self.presenter.login, 'fullname': self.presenter.fullname},
                'audience': {'logins': sorted(self.logins), 'groups': sorted(self.groups)},
                'view': self.view, 'started_at': iso_time(self.started_at),
                'count': len(members), 'connected': self.connected_count()}


def parse_audience(value, presenter_login: str) -> tuple:
    """``(logins, groups)`` from the ``audience`` of a request: ``{"logins": [...], "groups": [...]}``
    (a bare list = logins); valid logins, non-empty groups, the presenter dropped;
    ``ValueError`` otherwise."""
    if isinstance(value, list):
        value = {'logins': value}
    if not isinstance(value, dict):
        raise ValueError("audience must be an object with logins and groups")
    logins = value.get('logins', [])
    groups = value.get('groups', [])
    if not isinstance(logins, list) or not isinstance(groups, list):
        raise ValueError("logins and groups must be lists")
    if len(logins) + len(groups) > MAX_AUDIENCE:
        raise ValueError("audience too large")
    for login in logins:
        if not isinstance(login, str) or not is_valid_login(login):
            raise ValueError(f"invalid login {login!r}")
    cleaned = set()
    for group in groups:
        if not isinstance(group, str) or not clean_group(group) or clean_group(group) != group.strip():
            raise ValueError(f"invalid group {group!r}")
        cleaned.add(group.strip())
    return set(logins) - {presenter_login}, cleaned


def audience_size(audience: tuple) -> int:
    return len(audience[0]) + len(audience[1])


class Presentations:
    """The running presentations and what the browsers were told (``shown``: login -> the id
    of the presentation pushed to its pages).  *clock* (``time.time``) dates the starts and
    the presenter's absence (the tests move it)."""

    def __init__(self, presence: Presence, *, clock=time.time, grace: float = PRESENTER_GRACE):
        self.presence = presence
        self.clock = clock
        self.grace = grace
        self._presentations: dict[str, Presentation] = {}
        self.shown: dict[str, str] = {}
        self._task: asyncio.Task | None = None

    # -- queries --------------------------------------------------------------------------------

    def get(self, presentation_id: str) -> Presentation | None:
        return self._presentations.get(presentation_id)

    def listing(self) -> list:
        return sorted(self._presentations.values(), key=lambda p: (p.started_at, p.id))

    def of_spectator(self, identity: Identity | None) -> Presentation | None:
        """The presentation shown to *identity*: the newest one that includes them."""
        candidates = [p for p in self._presentations.values() if p.includes(identity)]
        return max(candidates, key=lambda p: (p.started_at, p.id), default=None)

    def spectator_of(self, identity: Identity | None, host: str, rln: str) -> Presentation | None:
        p = self.of_spectator(identity)
        return p if p is not None and p.host == host and p.rln == rln else None

    def for_presenter(self, login: str) -> list:
        return [p for p in self.listing() if p.presenter.login == login]

    def presentation_id_of(self, identity: Identity | None) -> str | None:
        p = self.of_spectator(identity)
        return p.id if p is not None else None

    def _require(self, presentation_id: str) -> Presentation:
        p = self._presentations.get(presentation_id)
        if p is None:
            raise KeyError(presentation_id)
        return p

    # -- life cycle -----------------------------------------------------------------------------

    def _new_id(self) -> str:
        while True:
            new = secrets.token_urlsafe(16)
            if new not in self._presentations:
                return new

    async def start(self, presenter: Identity, host: str, rln: str, audience: tuple) -> Presentation:
        """A new presentation; an earlier one of the same presenter on the same project is
        replaced; the connected members are told."""
        for old in [p for p in self._presentations.values()
                    if p.presenter.login == presenter.login and (p.host, p.rln) == (host, rln)]:
            await self.end(old.id, 'replaced')
        now = self.clock()
        logins, groups = audience
        p = Presentation(self._new_id(), presenter, host, rln, set(logins) - {presenter.login}, set(groups), now,
                         presenter_absent_since=now)
        self._presentations[p.id] = p
        log.info("presentation %s: %s presents %s on %s to %d login(s) and %d group(s)", p.id, presenter.login, rln, host,
                 len(p.logins), len(p.groups))
        await self.resync(p.members(self.presence))
        return p

    async def set_audience(self, presentation_id: str, audience: tuple) -> Presentation:
        p = self._require(presentation_id)
        before = p.members(self.presence)
        logins, groups = audience
        p.logins = set(logins) - {p.presenter.login}
        p.groups = set(groups)
        await self.resync(before | p.members(self.presence))
        await self._notify_presenter(p)
        return p

    async def set_view(self, presentation_id: str, view) -> Presentation:
        """The presenter's view: a JSON object of at most ``MAX_VIEW_BYTES``, pushed to every
        spectator socket."""
        p = self._require(presentation_id)
        if not isinstance(view, dict):
            raise ValueError("the view must be a JSON object")
        if len(json.dumps(view, separators=(',', ':')).encode('utf-8')) > MAX_VIEW_BYTES:
            raise ValueError("view too large")
        p.view = view
        message = {'t': 'view', 'view': view}
        for login, watchers in list(p.spectator_sockets.items()):
            for watcher in list(watchers):
                if not await watcher.send_quietly(message):
                    watchers.discard(watcher)
        return p

    async def end(self, presentation_id: str, reason: str = 'requested') -> Presentation | None:
        """Over: every socket closed with ``WS_PRESENTATION_ENDED``, the browsers told
        (``resync``); idempotent."""
        p = self._presentations.pop(presentation_id, None)
        if p is None:
            return None
        log.info("presentation %s of %s on %s ended (%s)", p.id, p.presenter.login, p.rln, reason)
        affected = set(p.spectator_sockets) | {login for login, shown in self.shown.items() if shown == p.id}
        for watchers in list(p.spectator_sockets.values()):
            for watcher in list(watchers):
                await watcher.close_quietly(WS_PRESENTATION_ENDED, "the presentation has ended")
        p.spectator_sockets.clear()
        for watcher in list(p.presenter_sockets):
            await watcher.close_quietly(WS_PRESENTATION_ENDED, "the presentation has ended")
        p.presenter_sockets.clear()
        await self.resync(affected)
        return p

    async def resync(self, logins: Iterable[str]):
        """For each login, the presentation its browser must show now (``of_spectator`` of
        its connected identity) compared with the one it was told about (``shown``): the
        ``ended`` and ``started`` pushes of the difference, the spectator sockets of a
        presentation no longer shown closed."""
        for login in set(logins):
            identity = self.presence.identity_of(login)
            current = self.of_spectator(identity) if identity is not None else None
            shown = self.shown.get(login)
            if current is not None and current.id == shown:
                continue
            if shown is not None:
                old = self._presentations.get(shown)
                if old is not None:
                    for watcher in list(old.spectator_sockets.pop(login, ())):
                        await watcher.close_quietly(WS_PRESENTATION_ENDED, "the presentation has ended")
                    await self._notify_presenter(old)
                del self.shown[login]
                await self.presence.push(login, {'t': 'presentation', 'id': shown, 'ended': True})
            if current is not None:
                self.shown[login] = current.id
                await self.presence.push(login, {'t': 'presentation', 'id': current.id, 'url': f"/present/{current.id}",
                                                 'presenter': current.presenter.fullname or current.presenter.login})
                await self._notify_presenter(current)    # a member of a group connected: the count grew

    # -- the sockets of the presentation page -----------------------------------------------------

    def _audience_message(self, p: Presentation) -> dict:
        return {'t': 'audience', 'count': len(p.members(self.presence)), 'connected': p.connected_count()}

    async def _notify_presenter(self, p: Presentation):
        """The audience counts to the presenter's page, when they changed since the last time."""
        message = self._audience_message(p)
        if message == p.last_audience:
            return
        p.last_audience = message
        for watcher in list(p.presenter_sockets):
            if not await watcher.send_quietly(message):
                p.presenter_sockets.discard(watcher)

    async def attach_presenter(self, presentation_id: str, watcher: Watcher) -> bool:
        """The presenter's page is there: the absence clock stops; the audience counts are
        sent at once.  ``False`` when the presentation is over."""
        p = self._presentations.get(presentation_id)
        if p is None:
            return False
        p.presenter_sockets.add(watcher)
        p.presenter_absent_since = None
        p.last_audience = self._audience_message(p)
        await watcher.send_quietly(p.last_audience)
        return True

    def detach_presenter(self, presentation_id: str, watcher: Watcher):
        p = self._presentations.get(presentation_id)
        if p is None:
            return
        p.presenter_sockets.discard(watcher)
        if not p.presenter_sockets:
            p.presenter_absent_since = self.clock()

    async def attach_spectator(self, presentation_id: str, identity: Identity, watcher: Watcher) -> bool:
        """A spectator's page: it gets the view at once.  ``False`` when the presentation is
        over or *identity* is not in the audience."""
        p = self._presentations.get(presentation_id)
        if p is None or not p.includes(identity):
            return False
        p.spectator_sockets.setdefault(identity.login, set()).add(watcher)
        await watcher.send_quietly({'t': 'view', 'view': p.view})
        await self._notify_presenter(p)
        return True

    async def detach_spectator(self, presentation_id: str, login: str, watcher: Watcher):
        p = self._presentations.get(presentation_id)
        if p is None:
            return
        watchers = p.spectator_sockets.get(login)
        if watchers is not None:
            watchers.discard(watcher)
            if not watchers:
                del p.spectator_sockets[login]
        await self._notify_presenter(p)

    # -- the grace of an absent presenter ---------------------------------------------------------

    async def tick(self, now: float | None = None):
        """End the presentations whose presenter has been away for the grace period."""
        now = self.clock() if now is None else now
        for p in list(self._presentations.values()):
            if p.presenter_absent_since is not None and now - p.presenter_absent_since >= self.grace:
                await self.end(p.id, 'presenter gone')

    async def shutdown(self):
        for p in list(self._presentations.values()):
            await self.end(p.id, 'shutdown')

    async def _loop(self):
        while True:
            await asyncio.sleep(TICK)
            try:
                await self.tick()
            except Exception:
                log.exception("presentations: tick failed")

    def start_loop(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop_loop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
