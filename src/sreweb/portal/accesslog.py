"""The connection log of the portal (``[access_log]`` of web.toml): one ``key=value`` line per
event, written to a file (daily rotation) and / or to the portal's log (stderr: the journal,
``docker logs``).  A *session* is the requests of one login from one client address, from the
first one to a logout, ``session_timeout`` of inactivity or the shutdown of the portal; its
closing line carries the duration (up to the last request), the number of requests and the
projects used.  The other events are the logins, the starts (the lab, the host, the outcome and
the name of the new project), the project pages (the events WebSocket: open and close, with the
duration), the terminals and the virtual desktops (same), the evaluations, states, stops and
exports, the denied calls (401 / 403 / 429) and the administration calls.  The client address
is the last ``X-Forwarded-For`` entry when the TCP peer is one of ``trusted_proxies`` (the
reverse proxy adds it), the peer address otherwise; the identity never comes from that header.

The middleware derives the events from the canonical route of the request (``EVENTS``); the
handlers add what only they know through ``request[ACCESS_KEY]`` (the lab and the outcome of a
start) or call ``login()`` / ``login_failed()`` (a login request carries no identity yet).
Every value is escaped by ``format_line`` (JSON quoting), so a user agent or a display name
cannot forge a line."""
import asyncio
import ipaddress
import json
import logging
import logging.handlers
import re
import time
from dataclasses import dataclass, field
from datetime import datetime

from aiohttp import web

from ..config import AccessLogConfig, ConfigError, client_allowed
from ..identity import IDENTITY_KEY, Identity, request_key, VIEW_INSTRUCTOR

log = logging.getLogger('sreweb.portal')

#: The logger of the lines (``propagate`` = ``[access_log] journal``).
LOGGER_NAME = 'sreweb.access'
#: The per-request dict of extra fields a handler adds to the line of its event.
ACCESS_KEY = request_key('access')
#: The ``WebSocketResponse`` of a WebSocket route, stored by the relay once prepared: the close
#: code of the close line comes from it, the handler being cancelled when the browser leaves.
WS_KEY = request_key('websocket')
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S%z'

#: ``(method, canonical route)`` -> event.  The WebSocket events log ``<event>_open`` and
#: ``<event>_close``; the others one line after the handler, with its status.
EVENTS = {
    ('POST', '/api/projects'): 'start',
    ('DELETE', '/api/projects/{host}/{rln}'): 'stop',
    ('GET', '/api/projects/{host}/{rln}/events'): 'project',        # the project page, open as long as it is shown
    ('GET', '/api/projects/{host}/{rln}/terminals/{device}'): 'terminal',
    ('GET', '/api/projects/{host}/{rln}/display/ws'): 'display',
    ('POST', '/api/projects/{host}/{rln}/display'): 'display_start',
    ('POST', '/api/projects/{host}/{rln}/eval'): 'eval',
    ('POST', '/api/projects/{host}/{rln}/states/{state}'): 'state',
    ('GET', '/api/projects/{host}/{rln}/export'): 'export',
    ('POST', '/logout'): 'logout',
    ('POST', '/api/logout'): 'logout',
    ('POST', '/api/pool/hosts'): 'admin',
    ('DELETE', '/api/pool/hosts/{name}'): 'admin',
    ('POST', '/api/pool/hosts/{name}/{action}'): 'admin',
}
WS_EVENTS = frozenset({'project', 'terminal', 'display'})
#: Events naming a project the session used.
PROJECT_EVENTS = frozenset({'project', 'terminal', 'display', 'display_start', 'stop', 'eval', 'state', 'export'})
#: The polls of the browser: they keep the session alive but are not counted as requests.
KEEPALIVE = frozenset({('GET', '/api/projects'), ('GET', '/api/watch'), ('POST', '/api/projects/{host}/{rln}/touch')})
#: Routes that neither touch the session nor count ('' = no route: 404 / 405).
IGNORED = frozenset({'', '/static', '/i18n/{lang}.json', '/site/logo'})
#: A failed login is logged as ``login_failed`` by the handler, not as a denied call.
LOGIN_ROUTES = frozenset({('POST', '/login'), ('POST', '/api/login')})
DENIED_STATUSES = frozenset({401, 403, 429})
MAX_USER_AGENT = 200

_BARE_RE = re.compile(r'^[A-Za-z0-9@_.:/+=,-]+$')
_TOKEN_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s"]*)')


def event_for(method: str, canonical: str) -> str | None:
    """The event of a route (``HEAD`` counts as ``GET``), ``None`` for a route without one."""
    return EVENTS.get(('GET' if method == 'HEAD' else method, canonical))


def forwarded_address(remote, xff, trusted_proxies) -> str:
    """The client address to log: the last entry of the ``X-Forwarded-For`` header *xff* when
    *remote* (the TCP peer) belongs to the non-empty *trusted_proxies*, else *remote* (``-``
    when unknown).  An entry that is not an address is ignored (the header is not trusted
    blindly even from the proxy)."""
    peer = str(remote or '')
    if trusted_proxies and xff and client_allowed(peer, trusted_proxies):
        candidate = xff.rsplit(',', 1)[-1].strip()
        try:
            return str(ipaddress.ip_address(candidate.split('%', 1)[0]))
        except ValueError:
            pass
    return peer or '-'


def format_value(value) -> str:
    """A value of a line: ``-`` for nothing, ``0`` / ``1`` for a bool, one decimal for a float,
    a comma-joined list, bare text when it is safe, JSON-quoted otherwise (spaces, quotes,
    control characters)."""
    if value is None or value == '':
        return '-'
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, float):
        return f"{value:.1f}"
    if isinstance(value, (list, tuple)):
        return format_value(','.join(str(v) for v in value))
    if isinstance(value, (set, frozenset)):
        return format_value(sorted(value))
    text = str(value)
    return text if _BARE_RE.match(text) else json.dumps(text, ensure_ascii=False)


def format_line(fields: dict) -> str:
    """``key=value`` pairs in the order given."""
    return ' '.join(f"{key}={format_value(value)}" for key, value in fields.items())


def parse_line(text: str) -> dict:
    """The fields of a line (the inverse of ``format_line``; ``-`` reads as ``''``); a leading
    timestamp (the lines of the file) is given as ``ts``."""
    text = text.strip()
    fields = {}
    start = 0
    m = re.match(r'(\S+)\s+', text)
    if m and '=' not in m.group(1):
        fields['ts'] = m.group(1)
        start = m.end()
    for m in _TOKEN_RE.finditer(text, start):
        key, raw = m.group(1), m.group(2)
        if raw.startswith('"'):
            fields[key] = json.loads(raw)
        else:
            fields[key] = '' if raw == '-' else raw
    return fields


def iso_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).astimezone().strftime(TIME_FORMAT)


@dataclass
class Visit:
    """One session: a login from one client address."""
    login: str
    addr: str
    role: str
    anon: bool
    name: str
    ua: str
    first_seen: float
    last_seen: float
    requests: int = 0
    sockets: int = 0               # the WebSockets open (a session with one never expires)
    projects: list = field(default_factory=list)   # running lab names, in order of first use

    @property
    def key(self) -> tuple:
        return self.login, self.addr

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


class Visits:
    """The open sessions, keyed by ``(login, address)``."""

    def __init__(self):
        self._visits: dict = {}

    def __len__(self) -> int:
        return len(self._visits)

    def get(self, key) -> Visit | None:
        return self._visits.get(key)

    def touch(self, identity: Identity, addr: str, ua: str, now: float, *, count: bool = True) -> tuple:
        """``(visit, new)``: the session of *identity* from *addr*, opened now when there is
        none; *count* adds the request to the session's count."""
        key = (identity.login, addr)
        visit = self._visits.get(key)
        new = visit is None
        if new:
            visit = Visit(login=identity.login, addr=addr, role=identity.role, anon=identity.anonymous,
                          name=identity.fullname, ua=ua, first_seen=now, last_seen=now)
            self._visits[key] = visit
        visit.last_seen = max(visit.last_seen, now)
        if count:
            visit.requests += 1
        return visit, new

    def socket_opened(self, key):
        visit = self._visits.get(key)
        if visit is not None:
            visit.sockets += 1

    def socket_closed(self, key, now: float):
        visit = self._visits.get(key)
        if visit is not None:
            visit.sockets = max(0, visit.sockets - 1)
            visit.last_seen = max(visit.last_seen, now)

    def add_project(self, key, rln):
        visit = self._visits.get(key)
        if visit is not None and rln and rln not in visit.projects:
            visit.projects.append(rln)

    def close(self, key) -> Visit | None:
        return self._visits.pop(key, None)

    def expire(self, now: float, timeout: float) -> list:
        """The sessions idle for *timeout*, removed; a session with an open WebSocket stays."""
        expired = [v for v in self._visits.values() if v.sockets == 0 and now - v.last_seen >= timeout]
        for visit in expired:
            del self._visits[visit.key]
        return expired

    def close_all(self) -> list:
        visits = list(self._visits.values())
        self._visits.clear()
        return visits


class AccessLog:
    """The log itself: the logger and its file, the sessions, the middleware deriving the events
    from the routes, the expiry task.  *clock* (``time.time``) gives the timestamps and the
    durations (the tests move it)."""

    def __init__(self, cfg: AccessLogConfig, trusted_proxies, *, clock=time.time):
        self.cfg = cfg
        self.trusted_proxies = list(trusted_proxies or [])
        self.clock = clock
        self.visits = Visits()
        self.logger = logging.getLogger(LOGGER_NAME)
        self._handler = None
        self._task = None

    # -- the logger -----------------------------------------------------------------------------

    def open(self):
        """Install the handler of the lines (the file when configured): the logger is a
        process-wide singleton, so the handler another instance left is removed first.  A file
        that cannot be opened is a ``ConfigError``."""
        self.close()
        for handler in list(self.logger.handlers):
            if getattr(handler, 'sreweb_access', False):
                self.logger.removeHandler(handler)
                handler.close()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = bool(self.cfg.journal)
        if self.cfg.file:
            try:
                if self.cfg.keep:
                    handler = logging.handlers.TimedRotatingFileHandler(self.cfg.file, when='midnight',
                                                                        backupCount=self.cfg.keep, encoding='utf-8')
                else:
                    handler = logging.handlers.WatchedFileHandler(self.cfg.file, encoding='utf-8')
            except OSError as e:
                raise ConfigError(f"access_log.file: cannot open {self.cfg.file}: {e.strerror or e}") from None
            handler.setFormatter(logging.Formatter('%(asctime)s %(message)s', datefmt=TIME_FORMAT))
        else:
            handler = logging.NullHandler()
        handler.sreweb_access = True
        self.logger.addHandler(handler)
        self._handler = handler

    def close(self):
        if self._handler is not None:
            self.logger.removeHandler(self._handler)
            self._handler.close()
            self._handler = None

    def describe(self) -> str:
        """For the startup message: where the lines go."""
        where = []
        if self.cfg.file:
            where.append(self.cfg.file + (f" (rotated daily, {self.cfg.keep} days kept)" if self.cfg.keep
                                          else " (no rotation)"))
        if self.cfg.journal:
            where.append("the journal")
        return ' and '.join(where) or "nowhere (file and journal both off)"

    def record(self, event: str, **fields):
        self.logger.info(format_line({'event': event, **fields}))

    # -- the sessions ---------------------------------------------------------------------------

    def address(self, request) -> str:
        return forwarded_address(request.remote, request.headers.get('X-Forwarded-For'), self.trusted_proxies)

    def touch(self, request, identity: Identity, *, count: bool = True) -> Visit:
        """The session of this request, opened (and logged) when it is the first one."""
        addr = self.address(request)
        ua = request.headers.get('User-Agent', '')[:MAX_USER_AGENT]
        visit, new = self.visits.touch(identity, addr, ua, self.clock(), count=count)
        if new:
            self.record('session_open', login=visit.login, addr=addr, role=visit.role, anon=visit.anon,
                        name=visit.name, ua=visit.ua)
        return visit

    def login(self, request, identity: Identity, mode: str):
        """A successful login (``mode``: anonymous or ldap); opens the session (the request
        carried no identity when the middleware ran)."""
        self.record('login', login=identity.login, addr=self.address(request), mode=mode, role=identity.role,
                    anon=identity.anonymous, name=identity.fullname)
        self.touch(request, identity)

    def login_failed(self, request, login: str, reason: str):
        self.record('login_failed', login=login, addr=self.address(request), reason=reason)

    def _closed(self, visit: Visit, reason: str):
        self.record('session_close', login=visit.login, addr=visit.addr, reason=reason, since=iso_time(visit.first_seen),
                    duration=round(visit.duration), requests=visit.requests, projects=visit.projects)

    def close_visit(self, key, reason: str):
        visit = self.visits.close(key)
        if visit is not None:
            self._closed(visit, reason)

    def expire(self):
        for visit in self.visits.expire(self.clock(), self.cfg.session_timeout):
            self._closed(visit, 'idle')

    def close_all(self, reason: str = 'shutdown'):
        for visit in self.visits.close_all():
            self._closed(visit, reason)

    # -- the expiry task ------------------------------------------------------------------------

    @property
    def period(self) -> float:
        return max(1.0, min(60.0, self.cfg.session_timeout / 2))

    async def _loop(self):
        while True:
            await asyncio.sleep(self.period)
            try:
                self.expire()
            except Exception:
                log.exception("access log: expiry failed")

    def start(self):
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # -- the middleware -------------------------------------------------------------------------

    @web.middleware
    async def middleware(self, request, handler):
        """After the identity middleware: touches the session of the request, logs the event of
        its route (``EVENTS``) with the status and the duration, the open and close of a
        WebSocket, and the denied calls."""
        canonical = getattr(request.match_info.route.resource, 'canonical', '') or ''
        if canonical in IGNORED:
            return await handler(request)
        method = 'GET' if request.method == 'HEAD' else request.method
        identity = request.get(IDENTITY_KEY)
        key = None
        if identity is not None:
            key = self.touch(request, identity, count=(method, canonical) not in KEEPALIVE).key
        event = event_for(method, canonical)
        fields = {'login': identity.login if identity is not None else '-', 'addr': self.address(request)}
        if event is None:
            return await self._plain(request, handler, fields, denied=(method, canonical) not in LOGIN_ROUTES)
        info = request.match_info
        for name in ('host', 'rln', 'state', 'device'):
            if name in info:
                fields[name] = info[name]
        if event == 'terminal':
            fields['join'] = request.query.get('join') or None
            fields['private'] = request.query.get('private', '') in ('1', 'true')
        if request.query.get('view') == VIEW_INSTRUCTOR:
            fields['view'] = VIEW_INSTRUCTOR
        if event == 'admin':
            fields.update(method=request.method, path=request.path)
        extra = request[ACCESS_KEY] = {}
        if event in WS_EVENTS:
            return await self._websocket(request, handler, event, key, fields)
        t0 = self.clock()
        response = status = None
        try:
            response = await handler(request)
            status = response.status
            return response
        except web.HTTPException as e:
            status = e.status
            raise
        finally:
            fields.update(extra)
            self.record(event, **fields, status=status or 'abort', duration=self.clock() - t0)
            if key is not None and status is not None and status < 400:
                if event in PROJECT_EVENTS:
                    self.visits.add_project(key, fields.get('rln'))
                elif event == 'start':
                    self.visits.add_project(key, extra.get('rln'))
                elif event == 'logout':
                    self.close_visit(key, 'logout')

    async def _plain(self, request, handler, fields: dict, *, denied: bool = True):
        """A route without event: only the denied calls are logged."""
        status = None
        try:
            response = await handler(request)
            status = response.status
            return response
        except web.HTTPException as e:
            status = e.status
            raise
        finally:
            if denied and status in DENIED_STATUSES:
                self.record('denied', **fields, method=request.method, path=request.path, status=status)

    async def _websocket(self, request, handler, event: str, key, fields: dict):
        """A WebSocket route: ``<event>_open`` now, ``<event>_close`` when the handler ends (the
        socket is closed, or the handler cancelled by the browser leaving), with the duration
        and the close code; a refusal before the upgrade (401 / 403 / 404) gives a close line
        with that status instead of a code."""
        self.record(f'{event}_open', **fields)
        self.visits.socket_opened(key)
        t0 = self.clock()
        status = None
        try:
            response = await handler(request)
            status = response.status
            return response
        except web.HTTPException as e:
            status = e.status
            raise
        finally:
            now = self.clock()
            self.visits.socket_closed(key, now)
            ws = request.get(WS_KEY)
            if ws is not None:
                if key is not None:
                    self.visits.add_project(key, fields.get('rln'))
                self.record(f'{event}_close', **fields, duration=now - t0, code=ws.close_code)
            else:
                self.record(f'{event}_close', **fields, duration=now - t0, status=status or 'abort')
