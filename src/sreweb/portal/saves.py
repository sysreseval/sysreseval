"""The saved projects, portal side (``[saves]`` of web.toml).

A user saves a running project whose lab allows it into the directory the pool hosts share,
restores it later on any of them, and may share it with groups of theirs.  The portal holds no
file and mounts nothing: the agents do every access (``sreweb/agent/saves.py``), any of them
answers about any save.  What the portal brings is what only it knows — who the user is, their
groups, their exam — so every decision about people is taken here:

- who sees a save: its owner, the members of a group it is shared with, every instructor;
- who restores it: the same, as a new project of their own;
- who changes or deletes it: its owner or an instructor;
- how many a user keeps (``max_per_user`` / ``max_per_instructor``), told before the save starts
  so that the page can ask to delete an old one first.

:class:`SaveCatalog` is the list of the saves, asked to one agent and kept ``cache_ttl``.  What
this portal changes is applied to the kept list at once and stays on top of what the agents list
for two minutes: the hosts see the shared directory through their own cache (NFS), and one that
did not write a save may list it late.
"""
import asyncio
import json
import logging
import time
import urllib.parse

import aiohttp
import aiohttp_jinja2
from aiohttp import web

from .. import savestore
from ..agent.runner import RESULT_CREATED
from ..identity import Identity, IDENTITY_KEY, clean_group
from .accesslog import ACCESS_KEY
from .groups import KINDS, group_key, parse_group_key
from .pool import PoolError

log = logging.getLogger('sreweb.portal')

FETCH_TIMEOUT = 30.0            # seconds one agent has to list the saved projects
OVERLAY_TTL = 120.0             # seconds a change made here stays on top of what the agents list
SAVE_TIMEOUT = 960.0            # seconds a save may take on the agent (its own limit is 900 by default)
#: The keys a row of the API has on top of those of a save.
ROW_MINE = 'mine'
ROW_SHARED = 'shared_with_me'
ROW_LAB_TITLE = 'lab_title'
ROW_LAB_KNOWN = 'lab_known'


class SaveCatalog:
    """The saved projects of the shared directory, as one agent lists them."""

    def __init__(self, pool, *, ttl: float, clock=time.monotonic):
        self.pool = pool
        self.ttl = ttl
        self.clock = clock
        self._saves: list | None = None
        self._space: dict = {'free_mb': None, 'total_mb': None}
        self._fetched_at: float | None = None
        self._stale = False
        self._overlay: dict = {}        # (owner, id) -> (kept until, the entry | None for a deleted save)
        self._lock = asyncio.Lock()

    def invalidate(self):
        """Ask an agent again at the next listing (an agent refused something the list allowed)."""
        self._fetched_at = None

    async def load(self, *, refresh: bool = False) -> dict:
        """``{saves, free_mb, total_mb, stale}``.  When no host answers, the last list is given
        again, flagged ``stale``; without any, ``PoolError`` 503."""
        async with self._lock:
            now = self.clock()
            if refresh or self._fetched_at is None or now - self._fetched_at >= self.ttl:
                fetched = await self._fetch()
                if fetched is not None:
                    self._saves, self._space = fetched
                    self._fetched_at, self._stale = now, False
                elif self._saves is None:
                    raise PoolError(503, "no host with the saved projects answers, please retry in a moment",
                                    retry_after=30)
                else:
                    self._stale = True
            return {'saves': self._merged(now), **self._space, 'stale': self._stale}

    async def find(self, owner: str, save_id: str) -> dict:
        """The save as the list has it; 404 when it has none."""
        for entry in (await self.load())['saves']:
            if entry[savestore.KEY_OWNER] == owner and entry[savestore.KEY_ID] == save_id:
                return entry
        raise PoolError(404, "unknown saved project")

    def applied(self, entry: dict):
        """A save made or changed through this portal."""
        entry = coerced(entry)
        if entry is not None:
            self._overlay[(entry[savestore.KEY_OWNER], entry[savestore.KEY_ID])] = (self.clock() + OVERLAY_TTL, entry)

    def removed(self, owner: str, save_id: str):
        """A save deleted through this portal."""
        self._overlay[(owner, save_id)] = (self.clock() + OVERLAY_TTL, None)

    def _merged(self, now: float) -> list:
        self._overlay = {key: kept for key, kept in self._overlay.items() if kept[0] > now}
        by_key = {(e[savestore.KEY_OWNER], e[savestore.KEY_ID]): e for e in self._saves or []}
        for key, (_, entry) in self._overlay.items():
            if entry is None:
                by_key.pop(key, None)
            else:
                by_key[key] = entry
        return sorted(by_key.values(), key=lambda e: (e[savestore.KEY_SAVED_AT], e[savestore.KEY_ID]), reverse=True)

    async def _fetch(self) -> tuple | None:
        """The list of the first host that gives one; ``None`` when none does."""
        for host in self.pool.save_hosts():
            try:
                async with self.pool.session.get(f"{host.url}/v1/saves", headers=self.pool.headers(host),
                                                 timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)) as resp:
                    if resp.status != 200:
                        log.warning("host %s: GET /v1/saves answered %s: %s", host.name, resp.status,
                                    (await resp.text())[:300])
                        continue
                    body = await resp.json()
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("host %s: GET /v1/saves failed: %s", host.name, e or type(e).__name__)
                continue
            if not isinstance(body, dict) or not isinstance(body.get('saves'), list):
                log.warning("host %s: GET /v1/saves answered something else than a list of saves", host.name)
                continue
            saves = [entry for entry in map(coerced, body['saves']) if entry is not None]
            space = {key: body.get(key) if isinstance(body.get(key), int) and not isinstance(body.get(key), bool)
                     else None for key in ('free_mb', 'total_mb')}
            return saves, space
        return None


def coerced(raw) -> dict | None:
    """A save an agent gave, every field of its type; ``None`` for what does not name one."""
    if not isinstance(raw, dict):
        return None
    owner, save_id = raw.get(savestore.KEY_OWNER), raw.get(savestore.KEY_ID)
    if not savestore.valid_owner(owner) or not savestore.valid_id(save_id):
        return None
    return savestore.clean_entry(raw, owner, save_id)


# -- who may do what ----------------------------------------------------------------------------

class SaveRule(PoolError):
    """A refusal of the rules below."""


def canonical(key: str) -> str:
    """A group key in its one form (a bare name is a department)."""
    return group_key(*parse_group_key(key))


def keys_of(identity: Identity, memberships) -> list:
    """The keys of the groups of *identity*: what they may share a save with, and what lets
    them restore a save shared with one of them."""
    return list(dict.fromkeys(canonical(key) for key in memberships.groups_of_identity(identity)))


def via_group(entry: dict, own_keys) -> str | None:
    """The group, as the save names it, that lets a member restore it; ``None``: none of theirs."""
    own = set(own_keys)
    return next((key for key in entry[savestore.KEY_SHARED_WITH] if canonical(key) in own), None)


def may_change(entry: dict, identity: Identity) -> bool:
    return entry[savestore.KEY_OWNER] == identity.login or identity.is_instructor


def may_restore(entry: dict, identity: Identity, own_keys) -> bool:
    if entry[savestore.KEY_EXAM] and not identity.is_instructor:
        return False
    return may_change(entry, identity) or via_group(entry, own_keys) is not None


def visible(saves: list, identity: Identity, own_keys, *, everything: bool = False) -> list:
    """The saves *identity* sees: their own and those shared with a group of theirs; with
    *everything* (an instructor's list of all the saves): every one."""
    if everything and identity.is_instructor:
        return list(saves)
    return [e for e in saves if e[savestore.KEY_OWNER] == identity.login
            or (not e[savestore.KEY_EXAM] and via_group(e, own_keys) is not None)]


def quota_of(identity: Identity, cfg) -> int:
    """How many saves *identity* may keep; 0 = no limit."""
    return cfg.max_per_instructor if identity.is_instructor else cfg.max_per_user


def checked_shares(entry: dict, identity: Identity, wanted, own_keys) -> list:
    """The groups a save is to be shared with, as they are kept (canonical keys, each once).  A
    student adds only groups of theirs — a group already there may stay, and anything may be
    removed —, an instructor any group.  The save of an exam project is never shared."""
    if not isinstance(wanted, list) or not all(isinstance(key, str) for key in wanted):
        raise SaveRule(400, "shared_with must be a list of group keys")
    keys = []
    for raw in wanted:
        kind, name = parse_group_key(raw)
        if kind not in KINDS or not name or clean_group(name) != name:
            raise SaveRule(400, f"bad group {raw!r}")
        key = group_key(kind, name)
        if key not in keys:
            keys.append(key)
    if len(keys) > savestore.MAX_SHARED_WITH:
        raise SaveRule(400, f"a saved project is shared with at most {savestore.MAX_SHARED_WITH} groups")
    if keys and entry[savestore.KEY_EXAM]:
        raise SaveRule(409, "the save of an exam project cannot be shared")
    if not identity.is_instructor:
        allowed = set(own_keys) | {canonical(key) for key in entry[savestore.KEY_SHARED_WITH]}
        refused = [key for key in keys if key not in allowed]
        if refused:
            raise SaveRule(403, f"you do not belong to the group {parse_group_key(refused[0])[1]}")
    return keys


def group_rows(keys) -> list:
    """Group keys as the page lists them: ``{key, kind, name}``."""
    return [{'key': key, 'kind': kind, 'name': name} for key, (kind, name) in ((k, parse_group_key(k)) for k in keys)]


# -- the routes ---------------------------------------------------------------------------------

class SaveRoutes:
    """The page and the API of the saved projects; *routes* is the ``Routes`` of the portal, for
    what every route shares (the identity, the exams, the pool, the relay, the rate limits)."""

    def __init__(self, routes):
        self.r = routes
        self.cfg = routes.cfg.saves
        self.catalog = SaveCatalog(routes.pool, ttl=self.cfg.cache_ttl)
        self._saving: set = set()       # the logins with a save in flight: one at a time each

    def register(self, router):
        router.add_get('/saves', self.page)
        router.add_get('/api/saves', self.api_list)
        router.add_post('/api/projects/{host}/{rln}/save', self.api_save)
        router.add_post('/api/saves/{owner}/{id}/restore', self.api_restore)
        router.add_put('/api/saves/{owner}/{id}', self.api_update)
        router.add_delete('/api/saves/{owner}/{id}', self.api_delete)

    def shown_to(self, identity: Identity | None) -> bool:
        """Whether the pages of *identity* link to the saved projects."""
        return bool(self.cfg.enabled and identity is not None and not identity.anonymous)

    # -- helpers --------------------------------------------------------------------------------

    def _user(self, request) -> Identity:
        """The user of a call about the saved projects: 404 when they are off, never an
        anonymous pseudonym (it lasts as long as its cookie), never a student in an exam (a save
        is work done before, and its comment a message to the others)."""
        if not self.cfg.enabled:
            raise PoolError(404, "saved projects are not enabled")
        identity = self.r._require_identity(request)
        if identity.anonymous:
            raise PoolError(403, "saved projects need a personal account")
        if self.r._exam_binding(identity) is not None:
            raise PoolError(403, "saved projects are not available during an exam")
        return identity

    async def _own_keys(self, identity: Identity) -> list:
        await self.r.memberships.refresh()
        return keys_of(identity, self.r.memberships)

    @staticmethod
    def _saved(request) -> tuple:
        owner, save_id = request.match_info['owner'], request.match_info['id']
        if not savestore.valid_owner(owner) or not savestore.valid_id(save_id):
            raise PoolError(404, "unknown saved project")
        return owner, save_id

    @staticmethod
    def _log(request, **fields):
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(fields)

    @staticmethod
    def _path(owner: str, save_id: str, suffix: str = '') -> str:
        return f"/saves/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(save_id, safe='')}{suffix}"

    async def _ask(self, identity: Identity, method: str, path: str, body=None) -> dict:
        """One JSON call about a save to the first host that answers; the ``save`` it gives back.
        A refusal of the agent is raised as it is, after the kept list is dropped: the agent
        decided on the save as it is now."""
        hosts = self.r.pool.save_hosts(identity)
        if not hosts:
            raise PoolError(503, "no host with the saved projects is available, please retry in a moment",
                            retry_after=30)
        failure = None
        for host in hosts[:3]:
            try:
                status, answer = await self.r.relay.json(host, identity, method, path, json=body,
                                                         timeout=FETCH_TIMEOUT)
            except PoolError as e:
                failure = e
                continue
            if status != 200 or not isinstance(answer, dict):
                self.catalog.invalidate()
                message = answer.get('error') if isinstance(answer, dict) else None
                raise PoolError(status if 400 <= status < 600 else 502, str(message or f"the host answered {status}"))
            return answer.get('save') if isinstance(answer.get('save'), dict) else {}
        raise failure

    async def _rows(self, saves: list, identity: Identity, own_keys) -> list:
        """The saves as the page shows them: whose they are for the user, and their lab (its
        title; whether it still exists, which only says no when a lab list could be read)."""
        labs = await self.r.pool.labs(identity, all_labs=identity.is_instructor)
        titles = {lab['name']: lab.get('title') for lab in labs if lab.get('kind') == 'lab'}
        rows = []
        for entry in saves:
            mine = entry[savestore.KEY_OWNER] == identity.login
            rows.append({**entry, ROW_MINE: mine,
                         ROW_SHARED: not mine and via_group(entry, own_keys) is not None,
                         ROW_LAB_TITLE: titles.get(entry[savestore.KEY_LAB]),
                         ROW_LAB_KNOWN: not titles or entry[savestore.KEY_LAB] in titles})
        return rows

    # -- the page and the list ------------------------------------------------------------------

    async def page(self, request):
        identity = request.get(IDENTITY_KEY)
        if not identity:
            raise web.HTTPFound(self.r._url('/login'))
        if not self.cfg.enabled:
            raise web.HTTPNotFound(text="saved projects are not enabled")
        if identity.anonymous:
            raise web.HTTPForbidden(text="saved projects need a personal account")
        if self.r._exam_binding(identity) is not None:
            raise web.HTTPFound(self.r._url('/projects'))
        return aiohttp_jinja2.render_template('saves.html', request, self.r._page_context(request))

    async def api_list(self, request):
        """The saves of the user and those shared with them; ``?all=1`` (instructors): every
        save.  With the quota of the user, their groups (what they may share with), and the room
        left in the directory."""
        identity = self._user(request)
        everything = request.query.get('all') == '1'
        if everything and not identity.is_instructor:
            raise PoolError(403, "instructors only")
        listing = await self.catalog.load(refresh=request.query.get('refresh') == '1')
        own_keys = await self._own_keys(identity)
        shown = visible(listing['saves'], identity, own_keys, everything=everything)
        mine = sum(1 for entry in listing['saves'] if entry[savestore.KEY_OWNER] == identity.login)
        return web.json_response({
            'saves': await self._rows(shown, identity, own_keys),
            'quota': {'max': quota_of(identity, self.cfg), 'used': mine},
            'my_groups': group_rows(own_keys),
            'free_mb': listing['free_mb'], 'total_mb': listing['total_mb'], 'stale': listing['stale'],
        })

    # -- saving ---------------------------------------------------------------------------------

    async def api_save(self, request):
        """Save a running project as a new saved project of the user.  One save at a time for a
        user, ``[limits] save_interval`` between two; over their quota, a 409 with their saves:
        the page asks which to delete."""
        identity = self._user(request)
        host, rln, target = self.r._target(request)      # the owner, or an instructor; never a spectator
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "a JSON body is expected")
        comment = body.get('comment', '') if isinstance(body, dict) else None
        if not isinstance(comment, str):
            return _error(400, "comment must be a text")
        self._log(request, host=host.name, rln=rln)
        if identity.login in self._saving:
            return _error(409, "a save of yours is already running")
        quota = quota_of(identity, self.cfg)
        if quota:
            saves = (await self.catalog.load())['saves']
            mine = [entry for entry in saves if entry[savestore.KEY_OWNER] == identity.login]
            if len(mine) >= quota:
                return await self._quota_reached(identity, quota, mine)
        key = self.r._limit_key(request, identity)
        wait, previous = self.r.limiter.take_every('save', key, self.r.cfg.limits.save_interval)
        if wait:
            return _error(429, "please wait before saving again", retry_after=round(wait))
        self._saving.add(identity.login)
        saved = False
        try:
            status, answer = await self.r.relay.json(host, target, 'POST', self.r._path(rln, '/save'),
                                                     json={'comment': comment, 'quota': quota}, timeout=SAVE_TIMEOUT)
            answer = answer if isinstance(answer, dict) else {}
            if status == 409 and answer.get('code') == savestore.CODE_QUOTA:
                # the agent counted more than the kept list has (a save made elsewhere a moment ago)
                self.catalog.invalidate()
                saves = (await self.catalog.load())['saves']
                return await self._quota_reached(
                    identity, quota, [e for e in saves if e[savestore.KEY_OWNER] == identity.login])
            if status != 200 or not isinstance(answer.get('save'), dict):
                self._log(request, result='error')
                return web.json_response(answer or {'error': f"the host answered {status}", 'status': status},
                                         status=status if 400 <= status < 600 else 502)
            saved = True
            self.catalog.applied(answer['save'])
            self._log(request, result='saved', save=f"{answer['save'].get(savestore.KEY_OWNER)}/"
                                                    f"{answer['save'].get(savestore.KEY_ID)}",
                      lab=answer['save'].get(savestore.KEY_LAB), size=answer['save'].get(savestore.KEY_SIZE))
            return web.json_response({'ok': True, 'save': answer['save']})
        finally:
            self._saving.discard(identity.login)
            if not saved:
                self.r.limiter.give_back('save', key, previous)

    async def _quota_reached(self, identity: Identity, quota: int, mine: list) -> web.Response:
        rows = await self._rows(mine, identity, [])
        return web.json_response({'error': "the limit of saved projects is reached", 'status': 409,
                                  'code': savestore.CODE_QUOTA, 'quota': quota, 'saves': rows}, status=409)

    # -- restoring ------------------------------------------------------------------------------

    async def api_restore(self, request):
        """Restore a saved project as a new project of the user, on a host that has the saved
        projects: an NDJSON stream like a start, and counted like one."""
        identity = self._user(request)
        owner, save_id = self._saved(request)
        try:
            body = await request.json() if request.can_read_body else {}
        except ValueError:
            return _error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return _error(400, "a JSON object is expected")
        wanted = body.get('host')
        if wanted is not None and not isinstance(wanted, str):
            return _error(400, "host must be a host name")
        wanted = wanted or None
        instructor_mode = bool(body.get('instructor_mode'))
        if (instructor_mode or wanted) and not identity.is_instructor:
            return _error(403, "instructors only")
        self._log(request, restore=f"{owner}/{save_id}", instructor=instructor_mode)
        entry = await self.catalog.find(owner, save_id)
        own_keys = await self._own_keys(identity)
        if not may_restore(entry, identity, own_keys):
            return _error(403, "this saved project is not shared with you")
        lab = entry[savestore.KEY_LAB]
        self._log(request, lab=lab)
        key = self.r._limit_key(request, identity)
        wait, previous = self.r.limiter.take_every('start', key, self.r.cfg.limits.start_interval)
        if wait:
            return _error(429, "please wait before starting another project", retry_after=round(wait))
        started = False
        reservation = None
        try:
            host, reservation = self.r.pool.pick(identity, wanted, lab=lab, need_saves=True)
            self._log(request, host=host.name, placement=reservation.placement)
            payload = {'idle_timeout': self.r._idle_timeout(identity)}
            if instructor_mode:
                payload['instructor_mode'] = True
            if not may_change(entry, identity):
                payload['via'] = via_group(entry, own_keys)

            def on_result(obj: dict):
                nonlocal started
                started = obj.get('status') == RESULT_CREATED
                self._log(request, result=obj.get('status'), rln=obj.get('running_lab_name'))

            return await self.r.relay.forward_ndjson(
                request, host, identity, 'POST', self._path(owner, save_id, '/restore'),
                data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'},
                on_result=on_result)
        finally:
            if reservation is not None:
                self.r.pool.release(reservation)
            if not started:
                self.r.limiter.give_back('start', key, previous)
                self.catalog.invalidate()       # the agent may have refused a save the list still had

    # -- sharing, deleting ----------------------------------------------------------------------

    async def api_update(self, request):
        """Who a saved project is shared with, and its comment."""
        identity = self._user(request)
        owner, save_id = self._saved(request)
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return _error(400, "a JSON object is expected")
        entry = await self.catalog.find(owner, save_id)
        if not may_change(entry, identity):
            return _error(403, "not your saved project")
        changes = {}
        if savestore.KEY_SHARED_WITH in body:
            changes[savestore.KEY_SHARED_WITH] = checked_shares(
                entry, identity, body[savestore.KEY_SHARED_WITH], await self._own_keys(identity))
        if savestore.KEY_COMMENT in body:
            if not isinstance(body[savestore.KEY_COMMENT], str):
                return _error(400, "comment must be a text")
            changes[savestore.KEY_COMMENT] = body[savestore.KEY_COMMENT]
        if not changes:
            return _error(400, "nothing to change")
        self._log(request, save=f"{owner}/{save_id}",
                  **({'groups': changes[savestore.KEY_SHARED_WITH]} if savestore.KEY_SHARED_WITH in changes else {}))
        changed = await self._ask(identity, 'PUT', self._path(owner, save_id), changes)
        self.catalog.applied(changed)
        return web.json_response({'ok': True, 'save': changed})

    async def api_delete(self, request):
        identity = self._user(request)
        owner, save_id = self._saved(request)
        entry = await self.catalog.find(owner, save_id)
        if not may_change(entry, identity):
            return _error(403, "not your saved project")
        self._log(request, save=f"{owner}/{save_id}", lab=entry[savestore.KEY_LAB])
        try:
            await self._ask(identity, 'DELETE', self._path(owner, save_id))
        except PoolError as e:
            if e.status != 404:
                raise                   # 404: already gone (deleted elsewhere): what was asked
        self.catalog.removed(owner, save_id)
        return web.json_response({'ok': True})


def _error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({'error': message, 'status': status, **extra}, status=status)
