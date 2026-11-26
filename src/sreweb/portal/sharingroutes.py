"""The API of the shared projects (``sharing.py``: the registry and its rules) and what came to
the Watch page with them: the sharing policy of the projects, one or many at a time, and the
bulk close (``bulkclose.py``).

A project route of the portal goes through ``Routes._target``, which knows the owner, the
instructors and the participants.  These routes do not: who asks to join is nobody yet, so each
one has its own gate here, and a project that is not shared answers a student exactly what a
project they are not in the audience of does (404: no way to probe what the others run).

Everything is 404 when the site has no sharing (``WebConfig.sharing_available``: the anonymous
mode), and refused to a student bound by an exam.
"""
import logging

from aiohttp import web

from .accesslog import ACCESS_KEY
from .bulkclose import MAX_PROJECTS
from .groups import parse_group_key
from .pool import PoolError
from .saves import keys_of, group_rows
from .sharing import (Sharing, Share, SharingRefused, RequestGone, AUDIENCE_ALL, POLICIES, POLICY_DEFAULT)
from ..identity import Identity, running_lab_name_owner, is_valid_login

log = logging.getLogger('sreweb.portal')

ROLE_OWNER = 'owner'
ROLE_PARTICIPANT = 'participant'
ROLE_INSTRUCTOR = 'instructor'
NOT_SHARED = "no such shared project"


def _error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({'error': message, 'status': status, **extra}, status=status)


def shareable_row(row: dict) -> bool:
    """Whether a project, as its agent lists it, is one that can be shared at all: started from
    the web site, in standard mode, not an exam project."""
    return bool(row.get('managed', True)) and not row.get('exam') and not row.get('debug_project') \
        and not row.get('instructor_mode')


def guarded(handler):
    """The refusals of the registry as answers."""
    async def wrapped(self, request):
        try:
            return await handler(self, request)
        except SharingRefused as e:
            return _error(e.status, e.message, **e.extra)
        except RequestGone:
            return _error(410, "this request is over")
        except PermissionError as e:
            return _error(403, str(e))
    wrapped.__name__ = handler.__name__
    wrapped.__doc__ = handler.__doc__
    return wrapped


class SharingRoutes:
    """*routes* is the ``Routes`` of the portal, for what every route shares (the identity, the
    exams, the pool, the relay, the memberships)."""

    def __init__(self, routes):
        self.r = routes
        self.cfg = routes.cfg.sharing

    @property
    def sharing(self) -> Sharing:
        return self.r.sharing

    def register(self, router):
        base = '/api/projects/{host}/{rln}/sharing'
        router.add_get(base, self.api_get)
        router.add_put(base, self.api_start)
        router.add_delete(base, self.api_stop)
        router.add_delete(base + '/participants/{login}', self.api_remove)
        router.add_post(base + '/requests', self.api_request)
        router.add_post(base + '/requests/{id}/accept', self.api_accept)
        router.add_post(base + '/requests/{id}/decline', self.api_decline)
        router.add_delete(base + '/requests/{id}', self.api_cancel)
        router.add_get('/api/shares', self.api_shares)
        router.add_post('/api/watch/sharing', self.api_policy)
        router.add_post('/api/watch/close', self.api_close)
        router.add_get('/api/watch/close', self.api_close_status)

    # -- helpers --------------------------------------------------------------------------------

    def _user(self, request) -> Identity:
        if not self.r.cfg.sharing_available:
            raise PoolError(404, "the sharing of projects is not available")
        identity = self.r._require_identity(request)
        if self.r._exam_binding(identity) is not None:
            raise PoolError(403, "no sharing during an exam")
        return identity

    def _project(self, request) -> tuple:
        """``(identity, host, rln, owner)`` of a call about the sharing of a project."""
        identity = self._user(request)
        host = self.r.pool.host(request.match_info['host'])
        rln = request.match_info['rln']
        owner = running_lab_name_owner(rln)
        if owner is None:
            raise PoolError(404, "unknown project")
        return identity, host, rln, owner

    def _role(self, identity: Identity, share: Share | None, owner: str) -> str | None:
        if owner == identity.login:
            return ROLE_OWNER
        if identity.is_instructor:
            return ROLE_INSTRUCTOR
        if share is not None and identity.login in share.participants:
            return ROLE_PARTICIPANT
        return None

    async def _keys(self, identity: Identity) -> list:
        await self.r.memberships.refresh()
        return keys_of(identity, self.r.memberships)

    @staticmethod
    def _log(http_request, /, **fields):
        """Fields added to the line of the connection log of the call (``request`` is one)."""
        logged = http_request.get(ACCESS_KEY)
        if logged is not None:
            logged.update({k: v for k, v in fields.items() if v is not None})

    @staticmethod
    def audience_row(audience: str) -> dict:
        """An audience as the pages show it: everybody, or a group by kind and name."""
        if audience == AUDIENCE_ALL:
            return {'key': AUDIENCE_ALL, 'kind': AUDIENCE_ALL, 'name': ''}
        kind, name = parse_group_key(audience)
        return {'key': audience, 'kind': kind, 'name': name}

    def _view(self, host: str, rln: str, role: str, share: Share | None, keys=()) -> dict:
        sharing = self.sharing
        view = {'available': sharing.available(host), 'allowed': sharing.allowed(host, rln),
                'policy': sharing.policy_of(host, rln), 'shared': share is not None, 'me': role,
                'max_participants': sharing.max_participants}
        if share is not None:
            view.update(sharing.describe(share, requests=role in (ROLE_OWNER, ROLE_INSTRUCTOR)))
            view['audience'] = self.audience_row(share.audience)
        if role == ROLE_OWNER:
            # what the owner may share with: everybody, or one of their groups
            view['audiences'] = [self.audience_row(AUDIENCE_ALL), *group_rows(keys)]
        return view

    def annotate(self, rows: list) -> list:
        """The rows of the Watch page: ``sharing`` (``Sharing.row``; never available for a
        project that cannot be shared at all, nor on a site without sharing) and ``closing``."""
        closing = self.r.bulk_close.closing()
        enabled = self.r.cfg.sharing_available
        for row in rows:
            host, rln = row.get('host', ''), row.get('running_lab_name', '')
            view = self.sharing.row(host, rln)
            view['available'] = bool(enabled and view['available'] and shareable_row(row))
            row['sharing'] = view
            row['closing'] = (host, rln) in closing
        return rows

    # -- one project -----------------------------------------------------------------------------

    @guarded
    async def api_get(self, request):
        """The sharing of a project for its page: the owner, an instructor, a participant."""
        identity, host, rln, owner = self._project(request)
        share = self.sharing.get(host.name, rln)
        role = self._role(identity, share, owner)
        if role is None:
            return _error(404, NOT_SHARED)
        keys = await self._keys(identity) if role == ROLE_OWNER else ()
        return web.json_response(self._view(host.name, rln, role, share, keys))

    async def _owner_row(self, identity: Identity, host, rln: str) -> dict:
        """The project as the agent lists it for its owner; 404 when it does not run."""
        status, rows = await self.r.relay.json(host, identity, 'GET', '/projects')
        if status != 200 or not isinstance(rows, list):
            raise PoolError(502, f"the host {host.name} did not list the projects")
        row = next((r for r in rows if isinstance(r, dict) and r.get('running_lab_name') == rln), None)
        if row is None:
            raise PoolError(404, "unknown project")
        return row

    @guarded
    async def api_start(self, request):
        """The owner shares the project (``{"audience": "all" | <group key>}``), or changes whom
        with."""
        identity, host, rln, owner = self._project(request)
        if owner != identity.login:
            return _error(403, "only the owner of the project shares it")
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "a JSON body is expected")
        audience = body.get('audience') if isinstance(body, dict) else None
        keys = await self._keys(identity)
        row = await self._owner_row(identity, host, rln)
        if not shareable_row(row):
            return _error(409, "this project cannot be shared", code='not_shareable')
        if isinstance(row.get('title'), dict):
            row = dict(row, title='')        # a title by language: the pages name the lab themselves
        share = await self.sharing.start(identity, host.name, rln, audience, own_keys=keys, row=row)
        self._log(request, audience=share.audience)
        return web.json_response(self._view(host.name, rln, ROLE_OWNER, share, keys))

    @guarded
    async def api_stop(self, request):
        """The owner, or an instructor, stops the sharing: the participants are out."""
        identity, host, rln, owner = self._project(request)
        share = self.sharing.get(host.name, rln)
        role = self._role(identity, share, owner)
        if role not in (ROLE_OWNER, ROLE_INSTRUCTOR):
            return _error(404 if role is None else 403, NOT_SHARED if role is None else "only the owner stops the sharing")
        count = len(share.participants) if share is not None else 0
        await self.sharing.stop(host.name, rln)
        self._log(request, count=count, owner=owner if role == ROLE_INSTRUCTOR else None)
        keys = await self._keys(identity) if role == ROLE_OWNER else ()
        return web.json_response(self._view(host.name, rln, role, None, keys))

    @guarded
    async def api_remove(self, request):
        """A participant taken out by the owner or an instructor, or leaving."""
        identity, host, rln, owner = self._project(request)
        login = request.match_info['login']
        share = self.sharing.get(host.name, rln)
        role = self._role(identity, share, owner)
        if role is None or not is_valid_login(login) or share is None or login not in share.participants:
            return _error(404, NOT_SHARED if role is None else "not a participant of this project")
        if role == ROLE_PARTICIPANT and login != identity.login:
            return _error(403, "only the owner takes somebody out")
        leaving = login == identity.login
        await self.sharing.remove(host.name, rln, login, 'left' if leaving else 'removed')
        self._log(request, member=login, reason='left' if leaving else 'removed')
        if leaving:
            return web.json_response({'ok': True})
        keys = await self._keys(identity) if role == ROLE_OWNER else ()
        return web.json_response(self._view(host.name, rln, role, self.sharing.get(host.name, rln), keys))

    # -- asking to join --------------------------------------------------------------------------

    @guarded
    async def api_request(self, request):
        """A student of the audience asks to join: the owner is told and answers."""
        identity, host, rln, owner = self._project(request)
        if not self.sharing.available(host.name):
            return _error(404, NOT_SHARED)
        asked = await self.sharing.request(identity, host.name, rln, await self._keys(identity))
        self._log(request, owner=owner, request=asked.id)
        return web.json_response({'id': asked.id, 'host': host.name, 'rln': rln}, status=201)

    def _request_of(self, request) -> tuple:
        """``(identity, host name, rln, owner, request id)`` of an answer to a request; the
        request must be one of this project (``RequestGone`` otherwise: 410)."""
        identity, host, rln, owner = self._project(request)
        request_id = request.match_info['id']
        share = self.sharing.request_share(request_id)
        if share is None or share.key != (host.name, rln):
            raise RequestGone(request_id)
        return identity, host.name, rln, owner, request_id

    @guarded
    async def api_accept(self, request):
        identity, host, rln, owner, request_id = self._request_of(request)
        share, asked = await self.sharing.accept(request_id, identity)
        self._log(request, member=asked.identity.login, request=request_id)
        return web.json_response(self._view(host, rln, ROLE_OWNER, share, await self._keys(identity)))

    @guarded
    async def api_decline(self, request):
        identity, host, rln, owner, request_id = self._request_of(request)
        share, asked = await self.sharing.decline(request_id, identity)
        self._log(request, member=asked.identity.login, request=request_id)
        return web.json_response(self._view(host, rln, ROLE_OWNER, share, await self._keys(identity)))

    @guarded
    async def api_cancel(self, request):
        identity, host, rln, owner, request_id = self._request_of(request)
        await self.sharing.cancel(request_id, identity)
        self._log(request, owner=owner, request=request_id)
        return web.json_response({'ok': True})

    @guarded
    async def api_shares(self, request):
        """The projects of the others for a student: those they take part in, those they asked
        to join, those they may ask (the *Open a shared lab* dialog, the cards of the Projects
        page).  An instructor has none: they open any project from the Watch page."""
        if not self.r.cfg.sharing_available:
            raise PoolError(404, "the sharing of projects is not available")
        identity = self.r._require_identity(request)
        if identity.is_instructor or self.r._exam_binding(identity) is not None:
            return web.json_response({'joined': [], 'requested': [], 'joinable': []})
        found = self.sharing.listing_for(identity, await self._keys(identity))
        for rows in found.values():
            for row in rows:
                row['audience'] = self.audience_row(row['audience'])
        return web.json_response(found)

    # -- the Watch page: the policy, the bulk close -------------------------------------------------

    def _selection(self, body) -> list:
        """The ``projects`` of a bulk request: ``[{host, rln}]`` → ``(host, rln)`` pairs of known
        hosts; ``ValueError`` on anything else."""
        projects = body.get('projects') if isinstance(body, dict) else None
        if not isinstance(projects, list) or not projects or len(projects) > MAX_PROJECTS:
            raise ValueError(f"projects: a list of 1 to {MAX_PROJECTS} {{host, rln}} is expected")
        keys = []
        for entry in projects:
            host = entry.get('host') if isinstance(entry, dict) else None
            rln = entry.get('rln') if isinstance(entry, dict) else None
            if not isinstance(host, str) or not isinstance(rln, str) or running_lab_name_owner(rln) is None:
                raise ValueError("projects: each entry names a host and a running lab name")
            self.r.pool.host(host)           # 404 on an unknown host
            keys.append((host, rln))
        return list(dict.fromkeys(keys))

    async def _bulk(self, request, *, sharing: bool = False) -> tuple:
        """``(identity, body, projects)`` of a request of the selection bar of the Watch page
        (instructors); *sharing*: 404 on a site without the shared projects."""
        if sharing and not self.r.cfg.sharing_available:
            raise PoolError(404, "the sharing of projects is not available")
        identity = self.r._require_instructor(request)
        try:
            body = await request.json()
        except ValueError:
            raise PoolError(400, "a JSON body is expected")
        try:
            return identity, body, self._selection(body)
        except ValueError as e:
            raise PoolError(400, str(e))

    @guarded
    async def api_policy(self, request):
        """Instructors: the sharing of the projects given allowed, forbidden, or back to the
        default of the site (``{"projects": [{host, rln}], "policy": ...}``).  A project whose
        host cannot share (an older agent, unreachable) is skipped."""
        identity, body, keys = await self._bulk(request, sharing=True)
        policy = body.get('policy')
        if policy not in POLICIES:
            return _error(400, f"policy: one of {', '.join(POLICIES)} is expected")
        able = [key for key in keys if policy == POLICY_DEFAULT or self.sharing.available(key[0])]
        changed = await self.sharing.set_policy(able, policy)
        self._log(request, policy=policy, count=changed, selected=len(keys))
        return web.json_response({'changed': changed, 'skipped': len(keys) - len(able)})

    @guarded
    async def api_close(self, request):
        """Instructors: the projects given closed by a job in the background (202; the page reads
        it back with ``GET``).  409 while the caller's previous job runs."""
        identity, body, keys = await self._bulk(request)
        job = self.r.bulk_close.start(identity, keys)
        self._log(request, count=job.total, selected=len(keys))
        return web.json_response({'job': job.to_dict()}, status=202)

    async def api_close_status(self, request):
        identity = self.r._require_instructor(request)
        job = self.r.bulk_close.job_of(identity.login)
        return web.json_response({'job': job.to_dict() if job is not None else None})
