"""Web conferences: an instructor opens a BigBlueButton room and puts students in it, by login
or by group; every participant's browser shows the BBB client in an iframe (``webconf.js``).

The registry is in memory and pure like ``presentation.Presentations``: the routes hand it the
``Watcher`` sockets of the presence, the calls to the server go through a ``bbb.BbbClient`` (a
fake in the tests).  A ``Room`` holds its owner (the instructor who created it), the audience
(explicit logins and group keys, as the presentations: a department by the group of the
identity, a directory or custom group by the memberships), the instructors who joined it
(``attending``, kept apart from the audience so that an audience edit never evicts them), the
BBB meeting (``meeting_id``, the passwords, the ``create_time`` a join URL must carry) and what
the last poll of ``getMeetingInfo`` said (``participants``, ``running``).

A login is in at most one room at a time: for a student, the newest room including them; for an
instructor, the room they created or joined last (``preferred``) when it still includes them,
else the newest.  ``resync()`` recomputes it after every change and pushes the difference to the
browsers, like the presentations (``shown``: login -> the id pushed); ``tell()`` repeats the current
room to a presence socket that just opened, since ``resync`` pushes the changes only (a second tab
would otherwise get nothing).  The pushes: ``{"t": "webconf", "id", "name", "owner": {"login",
"fullname"}, "role": "moderator" | "viewer", "join_url": "/api/webconfs/<id>/join"}`` and
``{"t": "webconf", "id", "ended": true}``.

The meeting is created on the server when the room is (a refusal or an outage leaves no room);
``join_url_for()`` makes sure it still exists before signing a join URL for an identity (a
meeting nobody joined expires on the server after a few minutes: it is created again, with a new
``create_time``; one that was used and is gone, or that a moderator ended from the client, ends
the room: ``RoomGone``).  ``tick()`` polls ``getMeetingInfo`` of every room every
``poll_interval`` for the participants and for the meetings ended on the server side.  A room
ends when an instructor asks, when the meeting ends on the server after somebody was in it, or
when the portal shuts down (the meetings are then ended on the server, best effort, within
``SHUTDOWN_TIMEOUT``).  A portal restart forgets the rooms: the meetings expire on their own."""
import asyncio
import contextlib
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Iterable

from .accesslog import iso_time
from .bbb import BbbClient, BbbError, BbbUnavailable, MeetingInfo, ROLE_MODERATOR, ROLE_VIEWER
from .groups import KIND_DEPARTMENT, department_member, group_key, parse_group_key
from .presentation import Presence, Watcher
from ..identity import Identity

log = logging.getLogger('sreweb.portal')

MAX_ROOMS = 50                 # rooms at once on the portal
MIN_NAME, MAX_NAME = 2, 64     # the name of a meeting (the API's limits)
MAX_FULLNAME = 255             # the fullName of a join (the API's limit)
MEETING_ID_PREFIX = 'sre-'
PASSWORD_LENGTH = 16
SHUTDOWN_TIMEOUT = 5.0         # seconds given to the ``end`` calls at shutdown
LEFT_PATH = '/webconf/left'    # the logoutURL of the meetings: the page shown after Leave meeting
ROOM_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
ROLE_NAMES = {ROLE_MODERATOR: 'moderator', ROLE_VIEWER: 'viewer'}


class RoomGone(Exception):
    """The room ended while a join was asked (the meeting is gone on the server)."""


class WebconfDisabled(Exception):
    """No ``[bbb]`` section: the rooms cannot be created."""


def check_name(value) -> str:
    """The name of a room as it is kept: a printable string of ``MIN_NAME`` to ``MAX_NAME``
    characters, the whitespace collapsed; ``ValueError`` otherwise."""
    if not isinstance(value, str):
        raise ValueError("the name of the room must be a string")
    name = ' '.join(value.split())
    if not name.isprintable() or not MIN_NAME <= len(name) <= MAX_NAME:
        raise ValueError(f"the name of the room must have {MIN_NAME} to {MAX_NAME} printable characters")
    return name


def _password() -> str:
    return secrets.token_urlsafe(PASSWORD_LENGTH)[:PASSWORD_LENGTH]


@dataclass(eq=False)
class Room:
    id: str
    meeting_id: str
    name: str
    owner: Identity
    logins: set
    groups: set                                      # canonical keys
    created_at: float
    moderator_pw: str
    attendee_pw: str
    logout_url: str = ''
    language: str = 'en'                             # the owner's: the welcome message
    attending: set = field(default_factory=set)      # the instructors who joined (kept across audience edits)
    create_time: int | None = None                   # of the meeting on the server, as the join URLs need it
    present: bool = False                            # the meeting exists on the server (as of the last call)
    served_join: bool = False                        # a join URL was handed out
    seen_joined: bool = False                        # a poll saw somebody in the meeting
    running: bool = False
    participants: dict = field(default_factory=dict)   # userID -> {'fullname', 'role'} of the last poll
    polled_at: float | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    memberships: object = field(default=None, repr=False)    # groups.Memberships

    def includes(self, identity: Identity | None) -> bool:
        """Whether *identity* takes part: the owner, an instructor who joined, an explicit login,
        or a member of one of the groups (a department by the group of the identity, the other
        kinds by the memberships)."""
        if identity is None:
            return False
        if identity.login == self.owner.login or identity.login in self.logins or identity.login in self.attending:
            return True
        if self.memberships is not None:
            return self.memberships.is_member(identity.login, self.groups, department=identity.group)
        return department_member(identity.group, self.groups)

    def members(self, presence: Presence) -> set:
        """The owner, the instructors who joined, the explicit logins and the connected members
        of the groups."""
        members = set(self.logins) | set(self.attending) | {self.owner.login}
        connected = presence.logins()
        for key in self.groups:
            kind, name = parse_group_key(key)
            if kind == KIND_DEPARTMENT:
                members |= presence.logins_of_group(name)
            if self.memberships is not None:
                members |= self.memberships.members_of([key]) & connected
        return members

    def to_dict(self, presence: Presence) -> dict:
        members = self.members(presence)
        connected = []
        for login in sorted(members & presence.logins()):
            identity = presence.identity_of(login)
            connected.append({'login': login, 'fullname': identity.fullname if identity is not None else ''})
        participants = [{'user_id': uid, 'login': uid if uid in members else None, 'fullname': p['fullname'],
                         'role': p['role'], 'member': uid in members} for uid, p in sorted(self.participants.items())]
        return {'id': self.id, 'name': self.name, 'meeting_id': self.meeting_id,
                'owner': {'login': self.owner.login, 'fullname': self.owner.fullname},
                'audience': {'logins': sorted(self.logins), 'groups': sorted(self.groups)},
                'attending': sorted(self.attending), 'created_at': iso_time(self.created_at),
                'count': len(members), 'running': self.running, 'connected': connected, 'participants': participants}


class Webconfs:
    """The rooms and what the browsers were told (``shown``: login -> the id pushed to its
    pages; ``preferred``: login -> the room an instructor created or joined last).  *bbb* is the
    client of the server (``None``: the feature is off, ``enabled`` false); *cfg* the
    ``config.BbbConfig``; *public_url* the URL of the portal as the users type it (the
    ``logoutURL`` of the meetings); *languages* those of the site (the welcome message)."""

    def __init__(self, presence: Presence, bbb: BbbClient | None, *, clock=time.time, memberships=None, cfg=None,
                 public_url: str = '', languages: Iterable[str] = ('en',)):
        self.presence = presence
        self.bbb = bbb
        self.clock = clock
        self.memberships = memberships
        self.cfg = cfg
        self.public_url = public_url
        self.languages = list(languages)
        self.poll_interval = float(cfg.poll_interval) if cfg is not None else 10.0
        self._rooms: dict[str, Room] = {}
        self.shown: dict[str, str] = {}
        self.preferred: dict[str, str] = {}
        self._task: asyncio.Task | None = None
        self._warned: set = set()

    @property
    def enabled(self) -> bool:
        return self.bbb is not None

    def describe(self) -> str:
        """For the startup log."""
        if not self.enabled:
            return "not configured (no [bbb] url and secret)"
        return f"BigBlueButton at {self.bbb.api_url} ({self.bbb.algorithm}), polled every {self.poll_interval:g} s"

    # -- queries --------------------------------------------------------------------------------

    def get(self, room_id: str) -> Room | None:
        return self._rooms.get(room_id)

    def listing(self) -> list:
        return sorted(self._rooms.values(), key=lambda r: (r.created_at, r.id))

    def of_participant(self, identity: Identity | None) -> Room | None:
        """The room shown to *identity*: the one they created or joined last when it still
        includes them, else the newest including them."""
        if identity is None:
            return None
        candidates = [r for r in self._rooms.values() if r.includes(identity)]
        if not candidates:
            return None
        preferred = self.preferred.get(identity.login)
        for room in candidates:
            if room.id == preferred:
                return room
        return max(candidates, key=lambda r: (r.created_at, r.id))

    def webconf_id_of(self, identity: Identity | None) -> str | None:
        room = self.of_participant(identity)
        return room.id if room is not None else None

    @staticmethod
    def role_of(identity: Identity) -> str:
        """An instructor is a moderator of every room, whatever the audience says."""
        return ROLE_MODERATOR if identity.is_instructor else ROLE_VIEWER

    def _require(self, room_id: str) -> Room:
        room = self._rooms.get(room_id)
        if room is None:
            raise KeyError(room_id)
        return room

    # -- life cycle -----------------------------------------------------------------------------

    def _new_id(self) -> str:
        while True:
            new = secrets.token_urlsafe(8)
            if new not in self._rooms:
                return new

    @staticmethod
    def _keys(groups) -> set:
        return {group_key(*parse_group_key(g)) for g in groups}

    def _logout_url(self, room_id: str, request_origin: str) -> str:
        base = (self.public_url or request_origin).rstrip('/')
        return f"{base}{LEFT_PATH}?id={room_id}" if base else ''

    async def start(self, owner: Identity, name, audience: tuple, *, request_origin: str = '') -> Room:
        """A new room of *owner* for *audience* (``(logins, groups)`` of ``parse_audience``): the
        meeting is created on the server first (``BbbError`` / ``BbbUnavailable`` leave no room),
        then the connected members are told.  ``ValueError`` on the name or too many rooms."""
        if not self.enabled:
            raise WebconfDisabled()
        name = check_name(name)
        if len(self._rooms) >= MAX_ROOMS:
            raise ValueError(f"too many rooms ({MAX_ROOMS})")
        logins, groups = audience
        room_id = self._new_id()
        room = Room(room_id, MEETING_ID_PREFIX + secrets.token_hex(8), name, owner, set(logins) - {owner.login},
                    self._keys(groups), self.clock(), _password(), _password(),
                    logout_url=self._logout_url(room_id, request_origin), language=owner.language,
                    memberships=self.memberships)
        await self._create_meeting(room)
        self._rooms[room.id] = room
        self.preferred[owner.login] = room.id
        log.info("webconf %s: %s opens %r for %d login(s) and %d group(s)", room.id, owner.login, room.name,
                 len(room.logins), len(room.groups))
        await self.resync(room.members(self.presence))
        return room

    async def _create_meeting(self, room: Room):
        """The meeting of *room* on the server (again after it expired: a new ``create_time``)."""
        cfg = self.cfg
        answer = await self.bbb.create(
            room.meeting_id, room.name, moderator_pw=room.moderator_pw, attendee_pw=room.attendee_pw,
            welcome=cfg.welcome_for(room.language, self.languages) if cfg is not None else '',
            logout_url=room.logout_url, record=cfg.record if cfg is not None else False,
            duration=cfg.duration_minutes if cfg is not None else 0,
            mute_on_start=cfg.mute_on_start if cfg is not None else False,
            max_participants=cfg.max_participants if cfg is not None else 0,
            meta={'sre-room': room.id, 'sre-owner': room.owner.login})
        room.create_time = answer['create_time']
        room.present = True
        room.seen_joined = False
        room.running = False
        room.participants = {}
        room.polled_at = self.clock()

    async def set_audience(self, room_id: str, audience: tuple) -> Room:
        room = self._require(room_id)
        before = room.members(self.presence)
        logins, groups = audience
        room.logins = set(logins) - {room.owner.login}
        room.groups = self._keys(groups)
        await self.resync(before | room.members(self.presence))
        return room

    async def attend(self, room_id: str, identity: Identity) -> Room:
        """An instructor chooses *room* as the one their browser shows (a member of it from now
        on, whatever the audience)."""
        room = self._require(room_id)
        if identity.login != room.owner.login:
            room.attending.add(identity.login)
        self.preferred[identity.login] = room.id
        await self.resync({identity.login})
        return room

    async def end(self, room_id: str, reason: str = 'requested', *, server: bool = True) -> Room | None:
        """Over: the meeting ended on the server (*server*: not when the server said it is gone
        already), the browsers told; idempotent."""
        room = self._rooms.pop(room_id, None)
        if room is None:
            return None
        for login in [login for login, rid in self.preferred.items() if rid == room_id]:
            del self.preferred[login]
        log.info("webconf %s of %s ended (%s)", room.id, room.owner.login, reason)
        if server and room.create_time is not None and self.bbb is not None:
            try:
                await self.bbb.end(room.meeting_id, room.moderator_pw)
            except (BbbError, BbbUnavailable) as e:
                log.warning("webconf %s: the meeting could not be ended on the server: %s", room.id, e)
        affected = {login for login, shown in self.shown.items() if shown == room_id}
        await self.resync(affected)
        return room

    # -- the join URLs ----------------------------------------------------------------------------

    async def join_url_for(self, identity: Identity, room: Room) -> str:
        """The signed join URL of *identity* for *room*, the meeting made sure to exist first;
        ``RoomGone`` when the meeting ended on the server (the room ends here too);
        ``BbbUnavailable`` / ``BbbError`` as the server answers."""
        async with room.lock:
            if room.id not in self._rooms:
                raise RoomGone()
            now = self.clock()
            fresh = room.present and room.polled_at is not None and now - room.polled_at < self.poll_interval
            if not fresh:
                info = await self.bbb.meeting_info(room.meeting_id)
                alive = await self._apply_info(room, info, now)
                if room.id not in self._rooms:
                    raise RoomGone()
                if not alive:
                    await self._create_meeting(room)     # expired before anybody joined
            room.served_join = True
            role = self.role_of(identity)
            return self.bbb.join_url(room.meeting_id, fullname=(identity.fullname.strip() or identity.login)[:MAX_FULLNAME],
                                     role=role, user_id=identity.login,
                                     password=room.moderator_pw if role == ROLE_MODERATOR else room.attendee_pw,
                                     create_time=room.create_time,
                                     userdata=self.cfg.userdata if self.cfg is not None else None)

    async def _apply_info(self, room: Room, info: MeetingInfo | None, now: float) -> bool:
        """What a ``getMeetingInfo`` answer means for *room*: ``False`` when the meeting is gone
        (the room ended here when somebody had been in it) or ended by a moderator (the room
        ended)."""
        room.polled_at = now
        if info is None:
            room.present = False
            room.running = False
            room.participants = {}
            if room.served_join and room.seen_joined:
                await self.end(room.id, 'ended on the server', server=False)
            return False
        room.present = True
        room.running = info.running
        room.seen_joined = room.seen_joined or info.has_user_joined
        room.participants = {a['user_id']: {'fullname': a['fullname'], 'role': a['role']}
                             for a in info.attendees if a['user_id']}
        if info.has_been_forcibly_ended:
            await self.end(room.id, 'ended by a moderator', server=False)
            return False
        return True

    # -- the pushes -------------------------------------------------------------------------------

    def _started_message(self, room: Room, identity: Identity) -> dict:
        return {'t': 'webconf', 'id': room.id, 'name': room.name,
                'owner': {'login': room.owner.login, 'fullname': room.owner.fullname},
                'role': ROLE_NAMES[self.role_of(identity)], 'join_url': f"/api/webconfs/{room.id}/join"}

    async def resync(self, logins: Iterable[str]):
        """For each login, the room its browser must show now (``of_participant`` of its connected
        identity) compared with the one it was told about (``shown``): the ``ended`` and started
        pushes of the difference."""
        for login in set(logins):
            identity = self.presence.identity_of(login)
            current = self.of_participant(identity) if identity is not None else None
            shown = self.shown.get(login)
            if current is not None and current.id == shown:
                continue
            if shown is not None:
                del self.shown[login]
                await self.presence.push(login, {'t': 'webconf', 'id': shown, 'ended': True})
            if current is not None:
                self.shown[login] = current.id
                await self.presence.push(login, self._started_message(current, identity))

    async def tell(self, login: str, watcher: Watcher):
        """The room *login* is in now, to one new presence socket of theirs when their other
        pages were told already (``resync`` pushes the changes only): called before the
        ``resync`` of a new socket, so that a page gets the room once."""
        identity = self.presence.identity_of(login)
        room = self.of_participant(identity) if identity is not None else None
        if room is not None and self.shown.get(login) == room.id:
            await watcher.send_quietly(self._started_message(room, identity))

    # -- the polls of the server ------------------------------------------------------------------

    async def tick(self, now: float | None = None):
        """``getMeetingInfo`` of every room: the participants, the meetings gone or ended on the
        server.  An unreachable server is warned about once per message and ends the round."""
        if not self.enabled:
            return
        now = self.clock() if now is None else now
        for room in list(self._rooms.values()):
            if room.id not in self._rooms or room.lock.locked():
                continue
            try:
                info = await self.bbb.meeting_info(room.meeting_id)
            except BbbUnavailable as e:
                if str(e) not in self._warned:
                    self._warned.add(str(e))
                    log.warning("webconf: the server does not answer: %s", e)
                return
            except BbbError as e:
                log.warning("webconf %s: getMeetingInfo failed: %s", room.id, e)
                continue
            if self._warned:
                self._warned.clear()
                log.info("webconf: the server answers again")
            await self._apply_info(room, info, now)

    async def shutdown(self):
        """Every room ended (the meetings on the server too, within ``SHUTDOWN_TIMEOUT``)."""
        rooms = list(self._rooms)
        if not rooms:
            return

        async def end_all():
            await asyncio.gather(*(self.end(room_id, 'shutdown') for room_id in rooms), return_exceptions=True)
        try:
            await asyncio.wait_for(end_all(), SHUTDOWN_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("webconf: %d room(s) not ended on the server within %g s", len(self._rooms), SHUTDOWN_TIMEOUT)
            self._rooms.clear()

    async def _loop(self):
        while True:
            await asyncio.sleep(self.poll_interval)
            try:
                await self.tick()
            except Exception:
                log.exception("webconf: tick failed")

    def start_loop(self):
        if self.enabled:
            self._task = asyncio.ensure_future(self._loop())

    async def stop_loop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
