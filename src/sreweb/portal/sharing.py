"""Shared projects: the owner of a running project lets other students work in it with them.

The in-memory registry ``Sharing`` holds, per project (a host and a running lab name):

* the **policy** an instructor set on the Watch page, when one did (``allowed`` / ``forbidden``);
  the projects nobody decided about follow ``[sharing] allowed`` of ``web.toml``
  ("no-by-default": nothing is shared unless allowed, "yes-by-default": everything may be unless
  forbidden);
* its ``Share`` once the owner turned the sharing on: the **audience** that may ask to join
  (every student, or one group of the owner), the **participants** the owner accepted, the
  pending **requests** to join.

A student of the audience asks (``request()``); the owner is told on their presence sockets
(``presentation.Presence``: ``{"t": "share-request", "id", "host", "rln", "lab", "title", "from",
"to"}``) and answers (``accept()`` / ``decline()``); both are told how it ended (``{..., "ended":
true, "reason": accepted | declined | cancelled | expired | stopped}``, with the ``url`` of the
project page when accepted).  A participant stays one until the owner or an instructor removes
them, they leave, the sharing stops, an instructor forbids it, an exam binds one of the two, or
the project closes; they are then told ``{"t": "share", "id", "host", "rln", "owner", "ended":
true, "reason"}``.

**Access.**  ``grant()`` is the one predicate "this login may act on this project now": the
routes ask it on every request of a participant (``Routes._target``), and a relayed WebSocket
holds its ``Grant`` for as long as it is open (``Grant.hold()`` right after the handshake, with
nothing awaited between the check and the registration; ``Grant.release()`` at the end).
Whatever ends a participation revokes its grants: the relay closes those sockets at once.

**Projects gone.**  The portal has no hook on the close of a project: ``reconcile()`` reads the
running lab names the agents report in their status (``pool.HostStatus.project_names``) and
drops what concerns a project a reachable host no longer lists — late rather than early (two
polls, ``GONE_AFTER`` seconds apart, both asked after the entry was made): a running lab name
never comes back, a decision of an instructor dropped by mistake would be lost.  A host whose
agent reports no names (an older one) offers no sharing: ``available()``.

**Kept across a restart** in ``sharing.json`` beside the state file of the pool: the policies and
the shares with their participants (logins and full names; no request, no grant).  The requests
are a matter of two minutes and die with the portal.

Pure like ``focus.py``: no aiohttp, the routes hand it ``Watcher`` objects, the tests fakes.
"""
import asyncio
import contextlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .accesslog import iso_time
from .clients import page_project
from .focus import project_page_url
from .presentation import Presence, Watcher
from ..config import SHARING_NO, SHARING_YES
from ..identity import Identity, is_valid_login, running_lab_name_owner, request_key

log = logging.getLogger('sreweb.portal')

#: The audience of a share: every student, or the key of one group of the owner.
AUDIENCE_ALL = 'all'
POLICY_ALLOWED = 'allowed'
POLICY_FORBIDDEN = 'forbidden'
POLICY_DEFAULT = 'default'
POLICIES = (POLICY_ALLOWED, POLICY_FORBIDDEN, POLICY_DEFAULT)
#: Close code of the relayed sockets of a participant whose participation ended.
WS_SHARE_ENDED = 4413
#: ``request[PARTICIPANT_KEY]``: the ``Grant`` a project call of a participant was let through on.
PARTICIPANT_KEY = request_key('participant')
#: How long the registry remembers that a participation ended: the page of the project, asked
#: again by who was in it, sends them to their projects instead of answering "not your project".
OUT_MEMORY = 3600.0
TICK = 2.0                      # period of the expiry of the requests, the exam check and the reconcile pass
#: A project missing from the statuses of its host this long (and at least ``GONE_POLLS`` of them) is gone.
GONE_AFTER = 20.0
GONE_POLLS = 2
REFUSAL_PAUSE = 30.0            # seconds before a student refused by the owner may ask the same project again
MAX_PENDING = 10                # requests waiting for the owner on one project
MAX_AUDIENCE_LENGTH = 200
MAX_TEXT = 300                  # a lab name, a title, a full name kept in the state file
STATE_VERSION = 1
STATE_FILE_NAME = 'sharing.json'


class SharingRefused(Exception):
    """What the rules refuse; *status* is the HTTP status of the answer."""

    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


class RequestGone(Exception):
    """A request to join that is over (answered, taken back, expired)."""


def state_file_beside(state_file: str) -> str:
    """The file of the shared projects for a pool whose state file is *state_file*: in the same
    directory; '' (not kept) without a state file."""
    return os.path.join(os.path.dirname(os.path.abspath(state_file)), STATE_FILE_NAME) if state_file else ''


def _text(value) -> str:
    return value[:MAX_TEXT] if isinstance(value, str) else ''


@dataclass
class Participant:
    login: str
    fullname: str = ''
    since: float = 0.0
    group: str = ''             # their department as their last request gave it (the exam check; not kept)


@dataclass
class JoinRequest:
    id: str
    identity: Identity
    created_at: float


@dataclass(eq=False)
class Grant:
    """One access of a participant to a shared project: what a request was let through on, and
    what a relayed WebSocket holds while it is open.  ``revoked`` is set when the participation
    ends (``reason``): the relay then closes the socket."""
    share: 'Share'
    login: str
    revoked: asyncio.Event = field(default_factory=asyncio.Event)
    reason: str = ''

    def hold(self) -> bool:
        """The grant kept for an open socket; ``False`` when the participation ended since the
        request was checked (the socket must be closed): nothing is awaited in between."""
        if self.revoked.is_set() or self.share.participants.get(self.login) is None or self.share.ended:
            self.revoke(self.reason or 'removed')
            return False
        self.share.grants.setdefault(self.login, set()).add(self)
        return True

    def release(self):
        held = self.share.grants.get(self.login)
        if held is not None:
            held.discard(self)
            if not held:
                self.share.grants.pop(self.login, None)

    def revoke(self, reason: str):
        self.reason = self.reason or reason
        self.revoked.set()


@dataclass(eq=False)
class Share:
    id: str
    host: str
    rln: str
    owner: str                      # the owner of the running lab name
    owner_fullname: str = ''
    audience: str = AUDIENCE_ALL
    started_at: float = 0.0
    lab_name: str = ''              # of the owner's row of the project, as when the sharing started
    title: str = ''                 # ... in the owner's language
    project_started_at: str = ''
    owner_group: str = ''           # the owner's department as last seen (the exam check; not kept)
    participants: dict = field(default_factory=dict)        # login -> Participant
    requests: dict = field(default_factory=dict)            # id -> JoinRequest
    grants: dict = field(default_factory=dict)              # login -> the grants their open sockets hold
    refused: dict = field(default_factory=dict)             # login -> when the owner last refused them
    ended: bool = False

    @property
    def key(self) -> tuple:
        return self.host, self.rln

    def request_of(self, login: str) -> JoinRequest | None:
        return next((r for r in self.requests.values() if r.identity.login == login), None)

    def includes(self, keys: Iterable[str]) -> bool:
        """Whether a student whose groups are *keys* is in the audience."""
        return self.audience == AUDIENCE_ALL or self.audience in set(keys)

    def to_state(self) -> dict:
        return {'id': self.id, 'host': self.host, 'rln': self.rln, 'owner': self.owner,
                'owner_fullname': self.owner_fullname, 'audience': self.audience, 'started_at': self.started_at,
                'lab_name': self.lab_name, 'title': self.title, 'project_started_at': self.project_started_at,
                'participants': [{'login': p.login, 'fullname': p.fullname, 'since': p.since}
                                 for p in self.participants.values()]}


def share_from_state(entry) -> Share | None:
    """A share of the state file, ``None`` when the entry is not one (it is skipped)."""
    if not isinstance(entry, dict):
        return None
    host, rln, owner = entry.get('host'), entry.get('rln'), entry.get('owner')
    if not isinstance(host, str) or not host or not isinstance(rln, str) or running_lab_name_owner(rln) != owner:
        return None
    audience = entry.get('audience')
    if not isinstance(audience, str) or not audience or len(audience) > MAX_AUDIENCE_LENGTH:
        return None
    started = entry.get('started_at')
    share = Share(id=entry.get('id') if isinstance(entry.get('id'), str) and entry.get('id') else secrets.token_urlsafe(12),
                  host=host, rln=rln, owner=owner, owner_fullname=_text(entry.get('owner_fullname')), audience=audience,
                  started_at=float(started) if isinstance(started, (int, float)) and not isinstance(started, bool) else 0.0,
                  lab_name=_text(entry.get('lab_name')), title=_text(entry.get('title')),
                  project_started_at=_text(entry.get('project_started_at')))
    for row in entry.get('participants') if isinstance(entry.get('participants'), list) else []:
        login = row.get('login') if isinstance(row, dict) else None
        if not isinstance(login, str) or not is_valid_login(login) or login == owner or login in share.participants:
            continue
        since = row.get('since')
        share.participants[login] = Participant(
            login, _text(row.get('fullname')),
            float(since) if isinstance(since, (int, float)) and not isinstance(since, bool) else 0.0)
    return share


@dataclass
class _Sighting:
    """What the reconcile pass knows of one project: when its entry was made, and since when
    the statuses of its host no longer list it (monotonic times, those of ``polled_at``)."""
    made_at: float
    last_poll: float = 0.0
    missing_since: float | None = None
    missing_polls: int = 0


class Sharing:
    """The policies and the shares.  *default*: ``[sharing] allowed``; *bound(login, group)*:
    whether an exam binds a student now; *statuses()*: the last status of every host of the
    pool, by name (``Pool.status``; without it — the registry alone — every host is taken as
    able to share and no project is ever seen gone); *clock* dates what is shown
    (``time.time``), *monotonic* what is compared with the ``polled_at`` of the statuses."""

    def __init__(self, presence: Presence, *, default: str = SHARING_NO, bound: Callable | None = None,
                 statuses: Callable | None = None, state_file: str = '', request_timeout: float = 120.0,
                 max_participants: int = 4, clock=time.time, monotonic=time.monotonic):
        self.presence = presence
        self.default = default
        self.bound = bound if bound is not None else (lambda login, group: False)
        self.statuses = statuses
        self.state_file = state_file
        self.request_timeout = request_timeout
        self.max_participants = max_participants
        self.clock = clock
        self.monotonic = monotonic
        self._policy: dict[tuple, bool] = {}
        self._shares: dict[tuple, Share] = {}
        self._requests: dict[str, Share] = {}        # request id -> its share
        self._sightings: dict[tuple, _Sighting] = {}
        self._out_at: dict[tuple, float] = {}        # (host, rln, login) -> when their participation ended
        self.state_error = ''
        self._task: asyncio.Task | None = None
        self.load_state()

    # -- the policy ---------------------------------------------------------------------------------

    def policy_of(self, host: str, rln: str) -> str:
        decided = self._policy.get((host, rln))
        return POLICY_DEFAULT if decided is None else (POLICY_ALLOWED if decided else POLICY_FORBIDDEN)

    def allowed(self, host: str, rln: str) -> bool:
        decided = self._policy.get((host, rln))
        return self.default == SHARING_YES if decided is None else decided

    def available(self, host: str) -> bool:
        """Whether the projects of *host* can be shared now: its agent answers and knows the
        participants (it reports the names of its projects)."""
        if self.statuses is None:
            return True
        status = self.statuses().get(host)
        return bool(status is not None and status.reachable and status.project_names is not None)

    async def set_policy(self, keys: Iterable[tuple], policy: str) -> int:
        """*policy* for the projects *keys* (``(host, rln)``); a project that is no longer
        allowed has its share ended.  The number of projects whose policy changed."""
        if policy not in POLICIES:
            raise ValueError(f"policy must be one of {', '.join(POLICIES)}")
        changed = 0
        for key in dict.fromkeys(keys):
            before = self._policy.get(key)
            after = None if policy == POLICY_DEFAULT else policy == POLICY_ALLOWED
            if before is after:
                continue
            changed += 1
            if after is None:
                self._policy.pop(key, None)
            else:
                self._policy[key] = after
                self._sighted(key)
            share = self._shares.get(key)
            if share is not None and not self.allowed(*key):
                await self._end(share, 'forbidden')
        if changed:
            self._forget_unwatched()
            self.save_state()
        return changed

    # -- queries --------------------------------------------------------------------------------------

    def get(self, host: str, rln: str) -> Share | None:
        return self._shares.get((host, rln))

    def listing(self) -> list:
        return sorted(self._shares.values(), key=lambda s: (s.started_at, s.id))

    def connected(self, share: Share) -> set:
        """The owner and the participants whose browser shows the page of the project now."""
        users = {share.owner, *share.participants}
        return {socket.identity.login for socket in self.presence.sockets()
                if not socket.away and socket.identity.login in users and page_project(socket.page) == share.key}

    def row(self, host: str, rln: str) -> dict:
        """The sharing of a project for its row of the Watch page."""
        share = self._shares.get((host, rln))
        return {'available': self.available(host), 'allowed': self.allowed(host, rln), 'policy': self.policy_of(host, rln),
                'shared': share is not None, 'audience': share.audience if share is not None else '',
                'participants': len(share.participants) if share is not None else 0,
                'connected': len(self.connected(share) - {share.owner}) if share is not None else 0}

    def describe(self, share: Share, *, requests: bool = False) -> dict:
        """A share for the pages: its users (the owner first), who is on the project now, and
        with *requests* (the owner, an instructor) who waits for an answer."""
        here = self.connected(share)
        view = {'id': share.id, 'host': share.host, 'rln': share.rln, 'audience': share.audience,
                'owner': {'login': share.owner, 'fullname': share.owner_fullname, 'connected': share.owner in here},
                'started_at': iso_time(share.started_at), 'lab_name': share.lab_name, 'title': share.title,
                'project_started_at': share.project_started_at, 'max_participants': self.max_participants,
                'participants': [{'login': p.login, 'fullname': p.fullname, 'since': iso_time(p.since),
                                  'connected': p.login in here}
                                 for p in sorted(share.participants.values(), key=lambda p: (p.since, p.login))]}
        if requests:
            view['requests'] = [{'id': r.id, 'login': r.identity.login, 'fullname': r.identity.fullname,
                                 'since': iso_time(r.created_at)}
                                for r in sorted(share.requests.values(), key=lambda r: (r.created_at, r.id))]
        return view

    def _summary(self, share: Share, request: JoinRequest | None = None) -> dict:
        return {'id': share.id, 'host': share.host, 'rln': share.rln, 'url': project_page_url(share.host, share.rln),
                'owner': {'login': share.owner, 'fullname': share.owner_fullname}, 'audience': share.audience,
                'lab_name': share.lab_name, 'title': share.title, 'project_started_at': share.project_started_at,
                'started_at': iso_time(share.started_at), 'participants': len(share.participants),
                'full': len(share.participants) >= self.max_participants,
                'request': request.id if request is not None else None}

    def listing_for(self, identity: Identity, keys: Iterable[str]) -> dict:
        """The shares of the others as a student sees them: those they take part in
        (``joined``), those they asked to join (``requested``) and those they may ask
        (``joinable``: their audience includes them).  Nothing of a host that cannot be reached."""
        keys = set(keys)
        found = {'joined': [], 'requested': [], 'joinable': []}
        if identity.is_instructor:
            return found
        for share in self.listing():
            if share.owner == identity.login or not self.available(share.host):
                continue
            if identity.login in share.participants:
                found['joined'].append(self._summary(share))
            elif share.includes(keys):
                request = share.request_of(identity.login)
                found['requested' if request is not None else 'joinable'].append(self._summary(share, request))
        return found

    # -- the life of a share ------------------------------------------------------------------------

    def _check_audience(self, audience, own_keys: Iterable[str]) -> str:
        if not isinstance(audience, str) or not audience or len(audience) > MAX_AUDIENCE_LENGTH:
            raise SharingRefused(400, "audience: 'all' or the key of one of your groups is expected")
        if audience != AUDIENCE_ALL and audience not in set(own_keys):
            raise SharingRefused(403, "you do not belong to this group")
        return audience

    async def start(self, owner: Identity, host: str, rln: str, audience, *, own_keys: Iterable[str] = (),
                    row: dict | None = None) -> Share:
        """The owner turns the sharing of their project on, or changes its audience (the
        participants already accepted stay).  *row*: the project as the agent lists it
        (``lab_name``, ``title``, ``started_at``)."""
        if running_lab_name_owner(rln) != owner.login:
            raise SharingRefused(403, "not your project")
        if not self.allowed(host, rln):
            raise SharingRefused(403, "the sharing of this project is not allowed", code='not_allowed')
        if not self.available(host):
            raise SharingRefused(409, "the projects of this host cannot be shared")
        if self.bound(owner.login, owner.group):
            raise SharingRefused(409, "no sharing during an exam")
        audience = self._check_audience(audience, own_keys)
        share = self._shares.get((host, rln))
        if share is None:
            row = row if isinstance(row, dict) else {}
            share = Share(id=secrets.token_urlsafe(12), host=host, rln=rln, owner=owner.login, audience=audience,
                          started_at=self.clock(), lab_name=_text(row.get('lab_name')), title=_text(row.get('title')),
                          project_started_at=_text(row.get('started_at')))
            self._shares[share.key] = share
            self._sighted(share.key)
            log.info("project %s (%s) shared by %s with %s", rln, host, owner.login, audience)
        elif share.audience != audience:
            log.info("project %s (%s): shared with %s (was %s)", rln, host, audience, share.audience)
            share.audience = audience
        share.owner_fullname = owner.fullname or share.owner_fullname
        share.owner_group = owner.group
        self.save_state()
        return share

    async def stop(self, host: str, rln: str, reason: str = 'stopped') -> Share | None:
        """The sharing of a project ends: its participants are out, the requests are over."""
        share = self._shares.get((host, rln))
        if share is not None:
            await self._end(share, reason)
            self._forget_unwatched()
            self.save_state()
        return share

    async def project_closed(self, host: str, rln: str):
        """The project is gone (closed through the portal, or no longer on its host): its share
        and what an instructor decided about it."""
        key = (host, rln)
        share = self._shares.get(key)
        if share is not None:
            await self._end(share, 'closed')
        if share is not None or key in self._policy:
            self._policy.pop(key, None)
            self._forget_unwatched()
            self.save_state()

    async def _end(self, share: Share, reason: str):
        share.ended = True
        self._shares.pop(share.key, None)
        for request in list(share.requests.values()):
            await self._resolve(share, request, 'stopped')
        for login in list(share.participants):
            await self._out(share, login, reason)
        log.info("project %s (%s): no longer shared (%s)", share.rln, share.host, reason)

    async def _out(self, share: Share, login: str, reason: str):
        """A participant is out: their open sockets are cut, their pages told."""
        if share.participants.pop(login, None) is None:
            return
        self._out_at[(share.host, share.rln, login)] = self.clock()
        for grant in list(share.grants.pop(login, ())):
            grant.revoke(reason)
        await self.presence.push(login, {'t': 'share', 'id': share.id, 'host': share.host, 'rln': share.rln,
                                         'owner': {'login': share.owner, 'fullname': share.owner_fullname},
                                         'title': share.title or share.lab_name, 'ended': True, 'reason': reason})

    async def remove(self, host: str, rln: str, login: str, reason: str = 'removed') -> bool:
        """One participant taken out (by the owner or an instructor), or leaving (``left``)."""
        share = self._shares.get((host, rln))
        if share is None or login not in share.participants:
            return False
        await self._out(share, login, reason)
        log.info("project %s (%s): %s is out (%s)", rln, host, login, reason)
        self.save_state()
        return True

    # -- asking to join -------------------------------------------------------------------------------

    def _request_message(self, share: Share, request: JoinRequest) -> dict:
        return {'t': 'share-request', 'id': request.id, 'host': share.host, 'rln': share.rln, 'lab': share.lab_name,
                'title': share.title or share.lab_name,
                'from': {'login': request.identity.login, 'fullname': request.identity.fullname},
                'to': {'login': share.owner, 'fullname': share.owner_fullname}}

    async def _resolve(self, share: Share, request: JoinRequest, reason: str):
        """A request is over: the owner's pages and the requester's are told why."""
        if share.requests.pop(request.id, None) is None:
            return
        self._requests.pop(request.id, None)
        message = {**self._request_message(share, request), 'ended': True, 'reason': reason}
        if reason == 'accepted':
            message['url'] = project_page_url(share.host, share.rln)
        for login in (share.owner, request.identity.login):
            await self.presence.push(login, message)

    async def request(self, identity: Identity, host: str, rln: str, keys: Iterable[str]) -> JoinRequest:
        """A student asks to join; the owner's pages are told.  A project that is not shared and
        one whose audience does not include them are the same refusal."""
        share = self._shares.get((host, rln))
        if share is None or identity.is_instructor or share.owner == identity.login or not share.includes(keys):
            raise SharingRefused(404, "no such shared project")
        if identity.login in share.participants:
            raise SharingRefused(409, "you already take part in this project", code='joined')
        if self.bound(identity.login, identity.group):
            raise SharingRefused(409, "no sharing during an exam")
        pending = share.request_of(identity.login)
        if pending is not None:
            return pending
        now = self.clock()
        wait = share.refused.get(identity.login, -REFUSAL_PAUSE) + REFUSAL_PAUSE - now
        if wait > 0:
            raise SharingRefused(429, "please wait before asking again", retry_after=round(wait))
        if len(share.participants) >= self.max_participants:
            raise SharingRefused(409, "this project takes no more participant", code='full')
        if len(share.requests) >= MAX_PENDING:
            raise SharingRefused(409, "too many requests are waiting on this project")
        if self.presence.identity_of(share.owner) is None:
            raise SharingRefused(409, "the owner of the project is not connected", code='owner_away')
        request = JoinRequest(secrets.token_urlsafe(12), identity, now)
        share.requests[request.id] = request
        self._requests[request.id] = share
        log.info("project %s (%s): %s asks to join", rln, host, identity.login)
        await self.presence.push(share.owner, self._request_message(share, request))
        return request

    def _pending(self, request_id: str) -> tuple:
        share = self._requests.get(request_id)
        request = share.requests.get(request_id) if share is not None else None
        if request is None:
            raise RequestGone(request_id)
        return share, request

    def request_share(self, request_id: str) -> Share | None:
        """The share a pending request is about (``None``: the request is over)."""
        return self._requests.get(request_id)

    async def accept(self, request_id: str, owner: Identity) -> tuple:
        """The owner accepts: the requester is a participant.  ``(share, request)``."""
        share, request = self._pending(request_id)
        if share.owner != owner.login:
            raise PermissionError("only the owner of the project answers")
        login = request.identity.login
        if not self.allowed(share.host, share.rln) or self.bound(share.owner, owner.group) \
                or self.bound(login, request.identity.group):
            await self._resolve(share, request, 'cancelled')
            raise SharingRefused(409, "this project can no longer be shared")
        if len(share.participants) >= self.max_participants:
            raise SharingRefused(409, "this project takes no more participant", code='full')
        share.participants[login] = Participant(login, request.identity.fullname, self.clock(), request.identity.group)
        share.owner_group = owner.group
        share.refused.pop(login, None)
        log.info("project %s (%s): %s accepted by %s", share.rln, share.host, login, owner.login)
        await self._resolve(share, request, 'accepted')
        self.save_state()
        return share, request

    async def decline(self, request_id: str, owner: Identity) -> tuple:
        share, request = self._pending(request_id)
        if share.owner != owner.login:
            raise PermissionError("only the owner of the project answers")
        share.refused[request.identity.login] = self.clock()
        await self._resolve(share, request, 'declined')
        return share, request

    async def cancel(self, request_id: str, identity: Identity) -> tuple:
        """The requester takes the request back (an instructor may too)."""
        share, request = self._pending(request_id)
        if request.identity.login != identity.login and not identity.is_instructor:
            raise PermissionError("not your request")
        await self._resolve(share, request, 'cancelled')
        return share, request

    async def tell(self, identity: Identity, watcher: Watcher):
        """A presence socket that just opened: the requests waiting for this owner (their other
        pages were told when they came)."""
        for share in self.listing():
            if share.owner != identity.login:
                continue
            for request in sorted(share.requests.values(), key=lambda r: (r.created_at, r.id)):
                await watcher.send_quietly(self._request_message(share, request))

    # -- access ---------------------------------------------------------------------------------------

    def grant(self, identity: Identity, host: str, rln: str) -> Grant | None:
        """The access of a participant to the project now, ``None`` when they have none: the
        share exists, they were accepted, the project may still be shared and no exam binds
        them or the owner (the tick then ends what it must)."""
        share = self._shares.get((host, rln))
        if share is None or identity.is_instructor:
            return None
        participant = share.participants.get(identity.login)
        if participant is None or not self.allowed(host, rln):
            return None
        participant.group = identity.group
        participant.fullname = identity.fullname or participant.fullname
        if self.bound(identity.login, identity.group) or self.bound(share.owner, share.owner_group):
            return None
        return Grant(share, identity.login)

    def recently_out(self, login: str, host: str, rln: str) -> bool:
        """Whether *login* took part in the project until less than ``OUT_MEMORY`` seconds ago."""
        at = self._out_at.get((host, rln, login))
        return at is not None and self.clock() - at < OUT_MEMORY

    def seen_owner(self, identity: Identity, host: str, rln: str):
        """The owner made a request on their project: their department as it is now."""
        share = self._shares.get((host, rln))
        if share is not None and share.owner == identity.login:
            share.owner_group = identity.group

    # -- the tick: requests expired, exams, projects gone ------------------------------------------------

    def _sighted(self, key: tuple):
        self._sightings.setdefault(key, _Sighting(self.monotonic()))

    def _forget_unwatched(self):
        for key in [k for k in self._sightings if k not in self._shares and k not in self._policy]:
            del self._sightings[key]

    async def reconcile(self, statuses: dict | None = None):
        """The shares and the policies of the projects that are gone are dropped (see the module
        docstring), and those of a host that left the pool."""
        if statuses is None:
            if self.statuses is None:
                return
            statuses = self.statuses()
        gone = []
        for key in {*self._shares, *self._policy}:
            host, rln = key
            status = statuses.get(host)
            if status is None:
                gone.append(key)                 # the host left the pool: nothing will ever say more
                continue
            sighting = self._sightings.setdefault(key, _Sighting(self.monotonic()))
            polled = status.polled_at
            if not status.reachable or status.project_names is None or polled <= sighting.made_at \
                    or polled <= sighting.last_poll:
                continue                         # nothing new is known: the entry stays
            sighting.last_poll = polled
            if rln in status.project_names:
                sighting.missing_since, sighting.missing_polls = None, 0
                continue
            sighting.missing_polls += 1
            if sighting.missing_since is None:
                sighting.missing_since = polled
            if sighting.missing_polls >= GONE_POLLS and polled - sighting.missing_since >= GONE_AFTER:
                gone.append(key)
        for host, rln in gone:
            log.info("project %s (%s) is gone: its sharing is forgotten", rln, host)
            await self.project_closed(host, rln)

    async def tick(self, now: float | None = None):
        now = self.clock() if now is None else now
        for key in [k for k, at in self._out_at.items() if now - at >= OUT_MEMORY]:
            del self._out_at[key]
        for share in self.listing():
            for request in list(share.requests.values()):
                if now - request.created_at >= self.request_timeout:
                    await self._resolve(share, request, 'expired')
            if self.bound(share.owner, share.owner_group):
                await self.stop(share.host, share.rln, 'exam')
                continue
            for participant in list(share.participants.values()):
                if self.bound(participant.login, participant.group):
                    await self.remove(share.host, share.rln, participant.login, 'exam')
        await self.reconcile()

    async def _loop(self):
        while True:
            await asyncio.sleep(TICK)
            try:
                await self.tick()
            except Exception:
                log.exception("sharing tick failed")

    def start_loop(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop_loop(self):
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    # -- the state file -------------------------------------------------------------------------------

    def _state(self) -> dict:
        return {'version': STATE_VERSION,
                'policies': [{'host': host, 'rln': rln, 'allowed': allowed}
                             for (host, rln), allowed in sorted(self._policy.items())],
                'shares': [share.to_state() for share in self.listing()]}

    def save_state(self):
        if not self.state_file:
            return
        tmp = f"{self.state_file}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self._state(), f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.state_file)
        except OSError as e:
            if self.state_error != str(e):
                log.error("the shared projects cannot be saved in %s: %s", self.state_file, e)
            self.state_error = str(e)
            return
        if self.state_error:
            log.info("the shared projects are saved again in %s", self.state_file)
        self.state_error = ''

    def load_state(self):
        """The policies and the shares of the state file (at construction).  A file that cannot
        be read is set aside, never written over; an entry that is not one is skipped."""
        if not self.state_file or not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict) or data.get('version') != STATE_VERSION:
                raise ValueError("not a state of the shared projects of this version")
        except (OSError, ValueError) as e:
            aside = f"{self.state_file}.unreadable"
            log.error("the state of the shared projects %s cannot be read (%s): kept as %s", self.state_file, e, aside)
            with contextlib.suppress(OSError):
                os.replace(self.state_file, aside)
            return
        for entry in data.get('policies') if isinstance(data.get('policies'), list) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get('allowed'), bool):
                continue
            host, rln = entry.get('host'), entry.get('rln')
            if isinstance(host, str) and host and isinstance(rln, str) and running_lab_name_owner(rln) is not None:
                self._policy[(host, rln)] = entry['allowed']
        for entry in data.get('shares') if isinstance(data.get('shares'), list) else []:
            share = share_from_state(entry)
            if share is not None and share.key not in self._shares and self.allowed(*share.key):
                self._shares[share.key] = share
        for key in {*self._shares, *self._policy}:
            self._sighted(key)
        if self._shares or self._policy:
            log.info("shared projects: %d share(s) and %d decision(s) of the instructors read from %s",
                     len(self._shares), len(self._policy), self.state_file)
