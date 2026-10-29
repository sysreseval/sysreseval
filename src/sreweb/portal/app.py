"""The aiohttp application of the portal: middlewares (session, connection log, CSRF, errors,
security headers), Jinja2 templates, static files, the pool refresh task."""
import logging
import ssl
import urllib.parse
from dataclasses import replace
from pathlib import Path

import aiohttp
import aiohttp_jinja2
import jinja2
from aiohttp import web

from . import session as S
from .accesslog import AccessLog
from .auth_ldap import LdapRoleResolver
from .auth_proxy import identity_from_headers
from .roles import RoleCache
from .manager import PoolManager
from .pool import Pool, PoolError
from .presentation import Presence, Presentations
from .focus import Focuses
from .relay import Relay
from .routes import Routes, json_error, CSP
from ..identity import IDENTITY_KEY, IdentityError, ROLE_INSTRUCTOR, ROLE_STUDENT
from ..config import WebConfig, AUTH_PROXY, client_allowed

log = logging.getLogger('sreweb.portal')
AGENT_CONNECTION_LIMIT = 0        # 0 = unlimited: a relayed WebSocket holds a connection while the page is open

PORTAL_KEY = web.AppKey('portal', object)
#: Proxy mode: how many distinct peers / bad logins are warned about once (then every time).
PROXY_WARNINGS_MAX = 100


class Portal:
    def __init__(self, cfg: WebConfig, *, web_dir: str, localedirs, role_resolver=None, db_connect=None):
        """*role_resolver*: an object with ``resolve(login) -> DirectoryLookup`` (the
        ``LdapRoleResolver`` of ``[auth.ldap]`` by default; the tests inject a fake), used when
        ``cfg.directory_lookups`` (proxy mode with ``ldap_roles`` / ``ldap_groups``, LDAP mode with
        ``attr_group``: the groups of the Watch rows).  *db_connect*: the ``(connect, transient)``
        pair of the connection log's database (``accessdb.connector`` by default; the tests
        inject a fake connection)."""
        self.cfg = cfg
        self.web_dir = Path(web_dir)
        self.localedirs = list(localedirs)
        self.session: aiohttp.ClientSession | None = None
        self.pool: Pool | None = None
        self.manager: PoolManager | None = None
        self.relay: Relay | None = None
        self.routes: Routes | None = None
        self.presence: Presence | None = None
        self.presentations: Presentations | None = None
        self.focuses: Focuses | None = None
        self._proxy_warned: set = set()
        self.access = AccessLog(cfg.access_log, cfg.trusted_proxies, connect=db_connect)
        self._administrators = set(cfg.auth.administrators)    # [auth] administrators: logins (instructors only)
        self.roles: RoleCache | None = None
        if cfg.directory_lookups:
            self.roles = RoleCache(role_resolver or LdapRoleResolver(cfg.auth.ldap), ttl=cfg.auth.proxy.ldap_roles_ttl)

    def make_app(self) -> web.Application:
        self.access.open()     # the log file: a bad path fails here, before the server starts
        app = web.Application(middlewares=[self.identity_middleware, self.access.middleware, self.csrf_middleware,
                                           self.error_middleware],
                              client_max_size=max(1 << 20, self.cfg.limits.max_answer_bytes))
        app[PORTAL_KEY] = self
        aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(str(self.web_dir / 'templates')), autoescape=True)
        # the client session is created at startup, inside the running loop (aiohttp requires it)
        self.pool = Pool(self.cfg.hosts, None, poll_interval=self.cfg.pool.poll_interval,
                         wake_timeout=self.cfg.pool.wake_timeout, state_file=self.cfg.admin.state_file,
                         follow_local_sessions=self.cfg.pool.follow_local_sessions,
                         labs_cache_ttl=self.cfg.pool.labs_cache_ttl)
        self.manager = PoolManager(self.pool, self.cfg.pool)
        self.relay = Relay(self.pool, None)
        self.presence = Presence()
        self.presentations = Presentations(self.presence)
        self.focuses = Focuses(self.presence)
        self.routes = Routes(self.cfg, self.pool, self.relay, localedirs=self.localedirs, manager=self.manager,
                             access=self.access, presentations=self.presentations, roles=self.roles,
                             focuses=self.focuses)
        self.routes.register(app)
        static = self.web_dir / 'static'
        if static.is_dir():
            app.router.add_static('/static/', str(static), name='static')
            app.on_response_prepare.append(self._static_no_cache)
        app.on_startup.append(self._on_startup)
        app.on_shutdown.append(self._on_shutdown)
        app.on_cleanup.append(self._on_cleanup)
        return app

    def client_ssl_context(self):
        """The TLS context of the calls to the agents: their certificates verified against
        ``[pool] ca`` (the system store without it), the portal's client certificate presented
        when ``[pool] client_cert`` is set.  ``None`` keeps aiohttp's defaults."""
        pool = self.cfg.pool
        if not pool.ca and not pool.client_cert:
            return None
        context = ssl.create_default_context(cafile=pool.ca or None)
        if pool.client_cert:
            context.load_cert_chain(pool.client_cert, pool.client_key)
        return context

    async def _on_startup(self, app):
        context = self.client_ssl_context()
        # one session to the agents for the status polls, the project lists and every relayed
        # socket or stream: no connection limit (aiohttp's default is 100), since each open events
        # or terminal socket of a browser holds one connection for as long as the page is open and
        # a full pool starved the 5 s status polls (hosts reported unreachable, starts refused)
        connector = aiohttp.TCPConnector(limit=AGENT_CONNECTION_LIMIT, ssl=context if context is not None else True)
        self.session = aiohttp.ClientSession(connector=connector)
        if context is not None:
            log.info("TLS to the agents: CA %s, client certificate %s", self.cfg.pool.ca or '(system store)',
                     self.cfg.pool.client_cert or '(none)')
        self.pool.session = self.session
        self.relay.session = self.session
        await self.pool.refresh()
        self.pool.start()
        self.manager.start()
        self.access.start()
        self.presentations.start_loop()
        self.focuses.start_loop()

    async def _on_shutdown(self, app):
        # before the connections are torn down: the spectators' browsers get the end of the
        # presentations (their sockets closed, the overlays removed), the students' pages the
        # end of the focuses
        await self.presentations.stop_loop()
        await self.presentations.shutdown()
        await self.focuses.stop_loop()
        await self.focuses.shutdown()

    async def _on_cleanup(self, app):
        # after the in-flight handlers (the WebSockets) are done: their close lines come first
        await self.access.stop()
        self.access.close_all('shutdown')
        self.access.close()
        await self.manager.stop()
        await self.pool.stop()
        await self.session.close()

    @staticmethod
    async def _static_no_cache(request, response):
        """The scripts and style sheets are revalidated on every page load (aiohttp sends an
        ``ETag``, so an unchanged file costs a 304): without it a browser keeps a script for hours
        after ``web/`` is updated and runs it on a page it no longer matches."""
        if request.path.startswith('/static/'):
            response.headers['Cache-Control'] = 'no-cache'

    # -- middlewares ----------------------------------------------------------------------------

    @web.middleware
    async def identity_middleware(self, request, handler):
        if self.cfg.auth.mode == AUTH_PROXY:
            identity = self._proxy_identity(request)
            if identity is not None and self.roles is not None:
                # the directory after the header tests (cached per login): the role of ldap_roles
                # for a user the headers did not make an instructor, the group of attr_group
                # (ldap_roles or ldap_groups) for a user whose header gives none, the administrator
                # tests of [auth.ldap] for an instructor nothing made an administrator yet; the
                # headers win
                proxy, ldap = self.cfg.auth.proxy, self.cfg.auth.ldap
                want_role = proxy.ldap_roles and not identity.is_instructor
                want_group = bool(ldap.attr_group) and not identity.group
                want_admin = (ldap.administrator_tests and identity.is_instructor and not identity.administrator
                              and identity.login not in self._administrators)
                if want_role or want_group or want_admin:
                    found = await self.roles.get(identity.login)
                    instructor = identity.is_instructor or (proxy.ldap_roles and found.role == ROLE_INSTRUCTOR)
                    administrator = identity.administrator or (ldap.administrator_tests and found.administrator)
                    identity = replace(identity, role=ROLE_INSTRUCTOR if instructor else ROLE_STUDENT,
                                       group=identity.group or found.group, administrator=False)
                    identity = identity.with_administrator(administrator)
            request[IDENTITY_KEY] = self._administrator(identity)
        else:
            request[IDENTITY_KEY] = self._administrator(S.decode(request.cookies.get(S.COOKIE_NAME, ''),
                                                                 self.cfg.secret))
        response = await handler(request)
        response.headers.setdefault('Content-Security-Policy', CSP)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        return response

    def _administrator(self, identity):
        """The identity with the administrator flag when its login is one of ``[auth]
        administrators`` (an instructor only: ``with_administrator`` keeps a student out)."""
        if identity is None or identity.administrator or identity.login not in self._administrators:
            return identity
        return identity.with_administrator(True)

    def _proxy_identity(self, request):
        """Proxy mode: the identity of the request headers, from a peer of ``trusted_proxies``
        only; the session cookie is not consulted.  ``None`` (no identity) when the peer is not
        trusted, sends no login header or a bad one, warned once per peer / per message."""
        proxy = self.cfg.auth.proxy
        if not client_allowed(request.remote, self.cfg.trusted_proxies):
            if request.headers.get(proxy.header_login):
                self._warn_once(('peer', request.remote),
                                "proxy mode: identity headers from %s ignored (not in trusted_proxies)", request.remote)
            return None
        language = S.choose_language((request.query.get('lang'), request.cookies.get(S.LANG_COOKIE)),
                                     self.cfg.languages)
        try:
            identity = identity_from_headers(proxy, request.headers, language)
        except IdentityError as e:
            self._warn_once(('login', str(e)), "proxy mode: %s (from %s)", e, request.remote)
            return None
        if identity is None:
            log.debug("proxy mode: no %s header from %s", proxy.header_login, request.remote)
        return identity

    def _warn_once(self, key, message, *args):
        if key in self._proxy_warned:
            return
        if len(self._proxy_warned) < PROXY_WARNINGS_MAX:
            self._proxy_warned.add(key)
        log.warning(message, *args)

    def _same_origin(self, request) -> bool:
        origin = request.headers.get('Origin')
        if not origin:
            return True
        allowed = {request.host}
        if self.cfg.public_url:
            allowed.add(urllib.parse.urlsplit(self.cfg.public_url).netloc)
        return urllib.parse.urlsplit(origin).netloc in allowed

    @web.middleware
    async def csrf_middleware(self, request, handler):
        if request.path.startswith('/api/pool') and request.headers.get('Authorization', '').lower().startswith('bearer '):
            return await handler(request)   # sre-web-tool: the admin token, checked by the handler
        if request.path.startswith('/api/'):
            upgrade = request.headers.get('Upgrade', '').lower() == 'websocket'
            if request.method not in ('GET', 'HEAD', 'OPTIONS') or upgrade:
                if not self._same_origin(request):
                    return json_error(403, "bad origin")
                if not upgrade and request.headers.get(S.CSRF_HEADER) != S.CSRF_VALUE:
                    return json_error(403, f"missing {S.CSRF_HEADER} header")
        elif request.method == 'POST' and not self._same_origin(request):
            raise web.HTTPForbidden(text="bad origin")
        return await handler(request)

    @web.middleware
    async def error_middleware(self, request, handler):
        try:
            return await handler(request)
        except PoolError as e:
            if request.path.startswith('/api/'):
                extra = {'retry_after': e.retry_after} if e.retry_after else {}
                return json_error(e.status, e.message, **extra)
            return web.Response(status=e.status, text=e.message)
        except web.HTTPException:
            raise
        except Exception:
            log.exception("unhandled error on %s %s", request.method, request.path)
            if request.path.startswith('/api/'):
                return json_error(500, "internal error")
            raise
