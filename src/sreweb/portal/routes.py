"""The handlers of the portal: the pages (Jinja2) and the ``/api/...`` endpoints relayed to the
agents (``relay.py``).  Every ``/api`` call needs the session cookie (in proxy mode, the identity
headers of the reverse proxy); the non-GET ones and the WebSockets need the
``X-Requested-With: sre-web`` header (CSRF)."""
import contextlib
import hmac
import json
import logging
import urllib.parse
from dataclasses import replace

import aiohttp_jinja2
from aiohttp import web, WSMsgType

from . import auth_anon, session as S
from .accesslog import AccessLog, ACCESS_KEY, ALL_EVENTS, LOGIN_EVENTS
from .accesshistory import parse_filters, session_filters, session_of_row, session_of_visit, visit_matches, HistoryError
from .auth_ldap import LdapAuthenticator, LdapError
from .pool import Pool, PoolError
from .presentation import (Presence, Presentation, Presentations, Watcher, SPECTATOR_KEY, WS_PRESENTATION_ENDED,
                           MAX_VIEW_BYTES, MAX_EVALUATION_BYTES, MAX_PAGE_LENGTH, parse_audience, audience_size)
from .focus import Focus, Focuses, WS_FOCUS_ENDED
from .ratelimit import RateLimiter
from .relay import Relay
from .roles import complete_owners
from ..agent.runner import RESULT_FLAVOR_FORM, RESULT_FLAVOR_ERROR
from ..config import WebConfig, AUTH_LDAP, AUTH_ANONYMOUS, AUTH_PROXY, host_config_from_dict, ConfigError
from ..identity import Identity, IdentityError, ROLE_INSTRUCTOR, running_lab_name_owner, VIEW_INSTRUCTOR, IDENTITY_KEY

#: Where the institution's logo of ``[site] logo`` is served.
SITE_LOGO_PATH = '/site/logo'
from ..i18n import translator, catalog

log = logging.getLogger('sreweb.portal')

TERMINAL_SUBPROTOCOL = 'sre-term.v1'
DISPLAY_SUBPROTOCOL = 'sre-display.v1'   # the RFB stream of the virtual X desktop (binary frames only)
LANGUAGE_NAMES = {'en': 'English', 'fr': 'Français'}
#: The security policy of every page; the page of a presentation (``/present/{id}``) is shown in
#: an iframe of the student's current page, so it alone allows a same-origin frame ancestor.
CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
CSP_FRAMED = CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self'")
#: ``(method, canonical route)`` of the project calls a spectator of a presentation may make: they
#: are relayed with the presenter's identity (``Routes._target``), read-only by construction (the
#: terminal socket must join a session and gets ``readonly=1``, the display socket ``readonly=1``).
#: The last archived evaluation is not among them: the spectators show the table of the
#: presenter's page, which their presentation socket carries (``Presentations.set_evaluation``).
SPECTATOR_ROUTES = frozenset({
    ('GET', '/api/projects/{host}/{rln}'),
    ('GET', '/api/projects/{host}/{rln}/events'),
    ('GET', '/api/projects/{host}/{rln}/schema.svg'),
    ('GET', '/api/projects/{host}/{rln}/log'),
    ('GET', '/api/projects/{host}/{rln}/terminals/{device}'),
    ('GET', '/api/projects/{host}/{rln}/display'),
    ('GET', '/api/projects/{host}/{rln}/display/ws'),
    ('POST', '/api/projects/{host}/{rln}/touch'),
})


def json_error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({'error': message, 'status': status, **extra}, status=status)


class Routes:
    def __init__(self, cfg: WebConfig, pool: Pool, relay: Relay, *, localedirs, manager=None, access: AccessLog,
                 presentations: Presentations | None = None, roles=None, focuses: Focuses | None = None):
        self.cfg = cfg
        self.pool = pool
        self.roles = roles       # the directory lookups (roles.RoleCache) completing the Watch rows' groups
        self.manager = manager
        self.relay = relay
        self.access = access
        self.presentations = presentations if presentations is not None else Presentations(Presence())
        self.presence = self.presentations.presence
        self.focuses = focuses if focuses is not None else Focuses(self.presence)
        self.localedirs = localedirs
        self.limiter = RateLimiter()
        self.ldap = LdapAuthenticator(cfg.auth.ldap) if cfg.auth.mode == AUTH_LDAP else None

    def register(self, app: web.Application):
        r = app.router
        r.add_get('/', self.index)
        r.add_get('/login', self.login_page)
        r.add_post('/login', self.login_form)
        r.add_post('/logout', self.logout)
        r.add_get('/projects', self.projects_page)
        r.add_get('/open', self.open_page)
        r.add_get('/watch', self.watch_page)
        r.add_get('/pool', self.pool_page)
        r.add_get('/history', self.history_page)
        r.add_get('/projects/{host}/{rln}', self.project_page)
        r.add_get('/i18n/{lang}.json', self.i18n_catalog)
        r.add_get(SITE_LOGO_PATH, self.site_logo)
        r.add_get('/api/me', self.api_me)
        r.add_post('/api/login', self.api_login)
        r.add_post('/api/logout', self.logout)
        r.add_post('/api/language', self.api_language)
        r.add_get('/api/labs', self.api_labs)
        r.add_get('/api/pool', self.api_pool)
        r.add_get('/api/pool/status', self.api_pool_status)
        r.add_post('/api/pool/hosts', self.api_pool_add)
        r.add_delete('/api/pool/hosts/{name}', self.api_pool_remove)
        r.add_post('/api/pool/hosts/{name}/{action}', self.api_pool_action)
        r.add_get('/api/projects', self.api_projects)
        r.add_get('/api/watch', self.api_watch)
        r.add_get('/api/watch/evaluations', self.api_watch_evaluations)
        r.add_get('/api/history', self.api_history)
        r.add_get('/api/history/sessions', self.api_history_sessions)
        r.add_post('/api/projects', self.api_projects_create)
        r.add_get('/api/projects/{host}/{rln}', self.api_project_get)
        r.add_delete('/api/projects/{host}/{rln}', self.api_project_close)
        r.add_get('/api/projects/{host}/{rln}/events', self.api_events)
        r.add_get('/api/projects/{host}/{rln}/schema.svg', self.api_schema)
        r.add_get('/api/projects/{host}/{rln}/schema.pdf', self.api_schema_pdf)
        r.add_put('/api/projects/{host}/{rln}/answers', self.api_answers)
        r.add_post('/api/projects/{host}/{rln}/eval', self.api_eval)
        r.add_get('/api/projects/{host}/{rln}/evaluation', self.api_evaluation)
        r.add_post('/api/projects/{host}/{rln}/states/{state}', self.api_state)
        r.add_get('/api/projects/{host}/{rln}/terminals/{device}', self.api_terminal)
        r.add_get('/api/projects/{host}/{rln}/display', self.api_display)
        r.add_post('/api/projects/{host}/{rln}/display', self.api_display_start)
        r.add_get('/api/projects/{host}/{rln}/display/ws', self.api_display_ws)
        r.add_get('/api/projects/{host}/{rln}/log', self.api_log)
        r.add_post('/api/projects/{host}/{rln}/touch', self.api_touch)
        # presentations: an instructor's project shown read-only on the students' browsers
        r.add_get('/present/{id}', self.present_page)
        r.add_get('/api/presence/ws', self.api_presence_ws)
        r.add_get('/api/presence', self.api_presence)
        r.add_get('/api/presentations', self.api_presentations)
        r.add_post('/api/presentations', self.api_presentation_create)
        r.add_get('/api/presentations/{id}', self.api_presentation_get)
        r.add_put('/api/presentations/{id}/audience', self.api_presentation_audience)
        r.add_put('/api/presentations/{id}/view', self.api_presentation_view)
        r.add_put('/api/presentations/{id}/evaluation', self.api_presentation_evaluation)
        r.add_delete('/api/presentations/{id}', self.api_presentation_delete)
        r.add_get('/api/presentations/{id}/ws', self.api_presentation_ws)
        # focus: an instructor helping a student keeps the student's browser on the project
        r.add_get('/api/focus', self.api_focus_list)
        r.add_post('/api/focus', self.api_focus_create)
        r.add_get('/api/focus/{id}', self.api_focus_get)
        r.add_put('/api/focus/{id}/view', self.api_focus_view)
        r.add_delete('/api/focus/{id}', self.api_focus_delete)
        r.add_get('/api/focus/{id}/ws', self.api_focus_ws)

    # -- helpers --------------------------------------------------------------------------------

    @property
    def proxy_mode(self) -> bool:
        """The reverse proxy authenticates and passes the identity in headers (no login page)."""
        return self.cfg.auth.mode == AUTH_PROXY

    def _secure(self, request) -> bool:
        return self.cfg.public_url.lower().startswith('https://') or request.scheme == 'https'

    def _language(self, request) -> str:
        identity = request.get(IDENTITY_KEY)
        if identity is not None:
            return identity.language
        return S.choose_language((request.query.get('lang'), request.cookies.get(S.LANG_COOKIE)), self.cfg.languages)

    def _translate(self, request):
        return translator(self._language(request), self.localedirs)

    def _page_context(self, request, **extra) -> dict:
        identity = request.get(IDENTITY_KEY)
        language = self._language(request)
        return {
            '_': self._translate(request),
            'identity': identity.to_dict() if identity else None,
            'auth_mode': self.cfg.auth.mode,
            'languages': [(code, LANGUAGE_NAMES.get(code, code)) for code in self.cfg.languages],
            'language': language,
            'instructor': bool(identity and identity.role == ROLE_INSTRUCTOR),
            'administrator': bool(identity and identity.administrator),   # the History link
            'groups': self.cfg.groups_configured,     # the Watch page shows the student groups
            'logout_url': self.cfg.auth.proxy.logout_url if self.proxy_mode else '',
            'site': self._site(language),
            **extra,
        }

    def _site(self, language: str) -> dict:
        """``[site]`` for the header of the pages: the institution's name in *language*, its
        link, and the URL of its logo ('' without one)."""
        site = self.cfg.site
        return {'name': site.name_for(language, self.cfg.languages), 'url': site.url,
                'logo_url': SITE_LOGO_PATH if site.logo else ''}

    def _require_identity(self, request) -> Identity:
        identity = request.get(IDENTITY_KEY)
        if identity is None:
            raise web.HTTPUnauthorized(text=json.dumps({'error': 'not logged in', 'status': 401}),
                                       content_type='application/json')
        return identity

    def _require_instructor(self, request) -> Identity:
        identity = self._require_identity(request)
        if identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "instructors only")
        return identity

    def _require_administrator(self, request) -> Identity:
        identity = self._require_identity(request)
        if not identity.administrator:
            raise PoolError(403, "administrators only")
        return identity

    def _target(self, request) -> tuple:
        """The host and running lab name of a project URL, after the ownership check.  A
        spectator of a presentation of that project gets the presenter's identity (their own
        language) on the read-only routes of ``SPECTATOR_ROUTES``, the instructor view following
        the presenter's; ``request[SPECTATOR_KEY]`` then holds the presentation."""
        identity = self._require_identity(request)
        host = self.pool.host(request.match_info['host'])
        rln = request.match_info['rln']
        owner = running_lab_name_owner(rln)
        if owner is None:
            raise PoolError(404, "unknown project")
        if owner != identity.login and identity.role != ROLE_INSTRUCTOR:
            presentation = self.presentations.spectator_of(identity, host.name, rln)
            canonical = getattr(request.match_info.route.resource, 'canonical', '') or ''
            method = 'GET' if request.method == 'HEAD' else request.method
            if presentation is None or (method, canonical) not in SPECTATOR_ROUTES:
                raise PoolError(403, "not your project")
            request[SPECTATOR_KEY] = presentation
            logged = request.get(ACCESS_KEY)
            if logged is not None:
                logged['spectator'] = True
            presenter = replace(presentation.presenter, language=identity.language)
            if presentation.view.get('instructorView') is True:
                presenter = presenter.with_view(VIEW_INSTRUCTOR)
            return host, rln, presenter
        view = request.query.get('view', '')
        if view == VIEW_INSTRUCTOR and identity.role == ROLE_INSTRUCTOR:
            identity = identity.with_view(VIEW_INSTRUCTOR)
        return host, rln, identity

    def _check_language(self, language: str) -> str:
        return language if language in self.cfg.languages else self.cfg.languages[0]

    # -- pages ----------------------------------------------------------------------------------

    async def index(self, request):
        raise web.HTTPFound('/projects' if request.get(IDENTITY_KEY) else '/login')

    async def login_page(self, request):
        if request.get(IDENTITY_KEY):
            raise web.HTTPFound('/projects')
        return aiohttp_jinja2.render_template('login.html', request,
                                              self._page_context(request, error=request.query.get('error', '')))

    async def _authenticate(self, request, data: dict) -> Identity:
        """The identity of a login request; the outcome goes to the connection log (the
        request carries no identity, so the log's middleware cannot see it)."""
        login = str(data.get('login', '')).strip()
        if self.proxy_mode:
            self.access.login_failed(request, login, 'proxy_mode')
            raise PoolError(403, "the authentication is done by the reverse proxy")
        language = self._check_language(str(data.get('language', '') or self._language(request)))
        if self.cfg.auth.mode == AUTH_ANONYMOUS:
            identity = auth_anon.new_guest(str(data.get('display_name', '')), language)
            self.access.login(request, identity, self.cfg.auth.mode)
            return identity
        # per client address: the one the proxy forwards, else every user shares the proxy's budget
        if not self.limiter.allow_per_minute('login', self.access.address(request), self.cfg.limits.login_per_minute):
            self.access.login_failed(request, login, 'rate_limited')
            raise PoolError(429, "too many login attempts, try again in a minute")
        password = str(data.get('password', ''))
        try:
            identity = await self.ldap.authenticate(login, password, language)
        except LdapError as e:
            log.error("LDAP error: %s", e)
            self.access.login_failed(request, login, 'directory')
            raise PoolError(502, "the directory does not answer")
        if identity is None:
            self.access.login_failed(request, login, 'password')
            raise PoolError(401, "wrong login or password")
        self.access.login(request, identity, self.cfg.auth.mode)
        return identity

    async def login_form(self, request):
        data = await request.post()
        try:
            identity = await self._authenticate(request, dict(data))
        except PoolError as e:
            raise web.HTTPFound('/login?' + urllib.parse.urlencode({'error': e.message}))
        response = web.HTTPFound('/projects')
        S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        raise response

    async def logout(self, request):
        """Clears the session cookie (a stale cookie of a previous mode too); in proxy mode the
        browser is sent to ``logout_url`` (the logout location or handler of the proxy) when
        there is one."""
        target = self.cfg.auth.proxy.logout_url if self.proxy_mode else ''
        if request.path.startswith('/api/'):
            response = web.json_response({'ok': True, 'logout_url': target})
        else:
            response = web.HTTPFound(target or '/login')
        S.clear_cookie(response)
        if isinstance(response, web.HTTPException):
            raise response
        return response

    async def projects_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        return aiohttp_jinja2.render_template('projects.html', request, self._page_context(request))

    async def open_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        return aiohttp_jinja2.render_template('open.html', request, self._page_context(request))

    async def watch_page(self, request):
        """Instructors: every running project of the pool with its last evaluation."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('watch.html', request, self._page_context(request))

    async def pool_page(self, request):
        """Instructors: the hosts of the pool with their state, and the actions of sre-web-tool
        (but add / remove)."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if request[IDENTITY_KEY].role != ROLE_INSTRUCTOR:
            raise web.HTTPForbidden(text="instructors only")
        return aiohttp_jinja2.render_template('pool.html', request, self._page_context(request))

    async def history_page(self, request):
        """Administrators: the connection log, read from its database (``[access_log.database]``;
        the page says so when none is configured).  The event select lists every event but, in
        proxy mode, those of the login page (never logged there)."""
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        if not request[IDENTITY_KEY].administrator:
            raise web.HTTPForbidden(text="administrators only")
        events = [e for e in ALL_EVENTS if not (self.proxy_mode and e in LOGIN_EVENTS)]
        return aiohttp_jinja2.render_template('history.html', request, self._page_context(
            request, history_database=self.access.history is not None, events=events))

    async def project_page(self, request):
        if not request.get(IDENTITY_KEY):
            raise web.HTTPFound('/login')
        host, rln, identity = self._target(request)
        return aiohttp_jinja2.render_template('project.html', request, self._page_context(
            request, host=host.name, rln=rln, api_base=f"/api/projects/{host.name}/{urllib.parse.quote(rln)}"))

    async def i18n_catalog(self, request):
        lang = request.match_info['lang']
        if lang not in self.cfg.languages:
            raise web.HTTPNotFound()
        return web.json_response(catalog(lang, self.localedirs), headers={'Cache-Control': 'max-age=3600'})

    async def site_logo(self, request):
        """The institution's logo (``[site] logo``), next to the SRE logo on every page, the
        login page included: no session needed."""
        if not self.cfg.site.logo:
            raise web.HTTPNotFound()
        return web.FileResponse(self.cfg.site.logo, headers={'Cache-Control': 'max-age=3600'})

    # -- session API ----------------------------------------------------------------------------

    async def api_me(self, request):
        identity = request.get(IDENTITY_KEY)
        return web.json_response({'identity': identity.to_dict() if identity else None, 'auth_mode': self.cfg.auth.mode,
                                  'languages': self.cfg.languages})

    async def api_login(self, request):
        try:
            data = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        identity = await self._authenticate(request, data if isinstance(data, dict) else {})
        response = web.json_response({'identity': identity.to_dict()})
        S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        return response

    async def api_language(self, request):
        identity = self._require_identity(request)
        try:
            data = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        language = self._check_language(str((data or {}).get('language', '')))
        identity = replace(identity, language=language)
        response = web.json_response({'identity': identity.to_dict()})
        S.set_language_cookie(response, language, secure=self._secure(request))
        if not self.proxy_mode:       # the session cookie carries the language; proxy mode has none
            S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        return response

    # -- labs, pool, projects -------------------------------------------------------------------

    async def api_labs(self, request):
        identity = self._require_identity(request)
        return web.json_response(await self.pool.labs(identity))

    # -- the pool: sre-web-tool with the admin token; the listing and the actions (not add /
    # remove) for the instructors too (the Pool page) ---------------------------------------

    def _is_admin(self, request) -> bool:
        """The administration token (``[admin] token`` of web.toml), from the loopback unless
        ``listen_any``; every admin call is logged with its source."""
        token = self.cfg.admin.token
        scheme, _, given = request.headers.get('Authorization', '').partition(' ')
        if not token or scheme.lower() != 'bearer' \
                or not hmac.compare_digest(given.strip().encode('utf-8'), token.encode('utf-8')):
            return False
        if not self.cfg.admin.listen_any and request.remote not in ('127.0.0.1', '::1'):
            log.warning("admin call from %s refused (admin.listen_any is false)", request.remote)
            return False
        log.info("admin %s %s from %s", request.method, request.path, request.remote)
        return True

    def _require_pool_access(self, request) -> Identity | None:
        """The admin token (sre-web-tool) or an instructor's session (the Pool page): ``None``
        for the token, the identity otherwise."""
        if self._is_admin(request):
            return None
        if request.headers.get('Authorization'):
            raise PoolError(401, "bad administration token")
        identity = self._require_identity(request)
        if identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "instructors only")
        return identity

    def _require_admin(self, request):
        if not self._is_admin(request):
            raise PoolError(401, "bad administration token" if request.headers.get('Authorization')
                            else "the administration token is required")

    async def api_pool(self, request):
        self._require_pool_access(request)
        return web.json_response(self.pool.summary())

    async def api_pool_status(self, request):
        self._require_pool_access(request)
        return web.json_response(self.manager.status() if self.manager else {})

    async def api_pool_add(self, request):
        self._require_admin(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        try:
            host = host_config_from_dict(body if isinstance(body, dict) else {}, "host")
        except ConfigError as e:
            return json_error(400, str(e))
        self.pool.add_host(host)
        return web.json_response(self._host_row(host.name), status=201)

    async def api_pool_remove(self, request):
        self._require_admin(request)
        name = request.match_info['name']
        self.pool.remove_host(name, force=request.query.get('force', '') in ('1', 'true'))
        return web.json_response({'ok': True, 'removed': name})

    async def api_pool_action(self, request):
        """``enable`` / ``disable`` / ``wake`` / ``poweroff`` / ``drain`` / ``restart`` a host:
        the commands of sre-web-tool and the buttons of the Pool page (which has no Restart
        button: the tool alone offers it); the answer is the updated row."""
        identity = self._require_pool_access(request)
        name, action = request.match_info['name'], request.match_info['action']
        if action == 'enable':
            self.pool.set_enabled(name, True)
        elif action == 'disable':
            self.pool.set_enabled(name, False)
        elif action == 'wake':
            await self.manager.wake(name, "requested")
        elif action == 'poweroff':
            await self.manager.power_off(name, "requested")
        elif action == 'restart':
            await self.manager.restart(name, "requested")
        elif action == 'drain':
            self.pool.host(name)
            self.pool.runtime[name].drain = True
            log.info("host %s draining: no new project, power off when empty", name)
        else:
            return json_error(404, f"unknown action {action}")
        log.info("pool: %s %s by %s", action, name, identity.login if identity else "the admin token")
        return web.json_response(self._host_row(name))

    def _host_row(self, name: str) -> dict:
        return next((row for row in self.pool.summary() if row['name'] == name), {'name': name})

    async def api_projects(self, request):
        identity = self._require_identity(request)
        return web.json_response(await self.pool.projects_of(identity))

    async def api_watch(self, request):
        """Instructors: every project of every reachable host, with its owner and the summary of
        its last archived evaluation (the agents read their archives); from the directory when
        it is readable, the group of the owners the agents know none for and the full name of
        the owners of the Qt GUI projects (``roles.complete_owners``)."""
        identity = self._require_instructor(request)
        rows = await self.pool.projects_of(identity, all_projects=True)
        if self.roles is not None:
            await complete_owners(rows, self.roles)
        return web.json_response(rows)

    async def api_watch_evaluations(self, request):
        """Instructors: the lab summary of the Watch page, every running project of the lab
        ``?lab=`` on every reachable host with the elements of its last archived evaluation (the
        agents read their archives), the groups and the names completed as for ``/api/watch``."""
        identity = self._require_instructor(request)
        lab = request.query.get('lab', '')
        if not lab:
            return json_error(400, "a lab is expected")
        rows = await self.pool.evaluations_of(identity, lab)
        if self.roles is not None:
            await complete_owners(rows, self.roles)
        return web.json_response(rows)

    async def api_history(self, request):
        """Administrators: a page of the connection log from its database, newest first, with
        the filters of ``accesshistory.parse_filters`` and a cursor for the older pages; the
        call is a ``history`` line of the log carrying the filters asked (``<key>_filter``)."""
        self._require_administrator(request)
        if self.access.history is None:
            return json_error(409, "the connection log has no database ([access_log.database] of web.toml)")
        try:
            filters = parse_filters(request.query)
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update({f'{key}_filter': value for key, value in filters.items() if key != 'limit'})
        try:
            page = await self.access.history.query(filters)
        except HistoryError as e:
            log.warning("access database: a history query failed: %s", e)
            return json_error(503, "the database of the connection log does not answer")
        return web.json_response({**page, 'limit': filters['limit'],
                                  'database': self.access.db.status() if self.access.db is not None else None})

    async def api_history_sessions(self, request):
        """Administrators: the Sessions view of the History page.  ``open``: the sessions still
        open, from the portal's memory (the first page only, newest first); ``rows``: the closed
        ones from the database, one per ``session_close`` line, newest first, with the login /
        address prefixes, the time window (on the closing time) and the cursor of
        ``accesshistory.session_filters``.  Without a database the open sessions alone (no 409:
        who is connected now needs none).  A ``history`` line with ``view=sessions`` (whatever
        the answer) and the filters."""
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged['view'] = 'sessions'
        self._require_administrator(request)
        try:
            filters = session_filters(parse_filters(request.query))
        except ValueError as e:
            return json_error(400, str(e))
        if logged is not None:
            logged.update({f'{key}_filter': value for key, value in filters.items() if key not in ('limit', 'event')})
        open_sessions = []
        if filters.get('before') is None:
            open_sessions = sorted((session_of_visit(v) for v in self.access.visits.all() if visit_matches(v, filters)),
                                   key=lambda s: s['start'], reverse=True)
        page = {'rows': [], 'more': False}
        if self.access.history is not None:
            try:
                page = await self.access.history.query(filters)
            except HistoryError as e:
                log.warning("access database: a history query failed: %s", e)
                return json_error(503, "the database of the connection log does not answer")
            page['rows'] = [session_of_row(row) for row in page['rows']]
        return web.json_response({**page, 'open': open_sessions, 'limit': filters['limit'],
                                  'database': self.access.db.status() if self.access.db is not None else None})

    def _idle_timeout(self, identity: Identity) -> float:
        return self.cfg.pool.idle_timeout_anonymous if identity.anonymous else self.cfg.pool.idle_timeout_authenticated

    async def api_projects_create(self, request):
        identity = self._require_identity(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict) or not isinstance(body.get('lab'), str):
            return json_error(400, "lab is required")
        wanted = body.get('host')             # an instructor's choice ('' = the automatic placement)
        if wanted is not None and not isinstance(wanted, str):
            return json_error(400, "host must be a host name")
        wanted = wanted or None
        logged = request.get(ACCESS_KEY)      # the line of the connection log: the lab, the host, the outcome
        if logged is not None:
            logged.update(lab=body['lab'], instructor=bool(body.get('instructor_mode')))
        if body.get('instructor_mode') and identity.role != ROLE_INSTRUCTOR:
            return json_error(403, "instructors only")
        if wanted and identity.role != ROLE_INSTRUCTOR:
            return json_error(403, "instructors only")
        # The start slot of the user is taken now (two simultaneous starts of one user are refused)
        # and given back unless a start reached the agent and went past the flavor form: the form
        # of a lab with flavor_form_at_startup is fetched by a start that ends on it, and the
        # student's real start, seconds later, must not be refused; a placement refused by the
        # pool, an agent not answering or a relay broken before the result line cost nothing
        # either (the agent's start lock per user and max_projects still bound that user).
        wait, previous = self.limiter.take_every('start', identity.login, self.cfg.limits.start_interval)
        if wait:
            return json_error(429, "please wait before starting another project", retry_after=round(wait))
        started = False
        reservation = None
        try:
            host, reservation = self.pool.pick(identity, wanted)
            if logged is not None:
                logged.update(host=host.name, placement=reservation.placement)
            payload = {'lab': body['lab'], 'idle_timeout': self._idle_timeout(identity)}
            if isinstance(body.get('flavor'), dict):
                payload['flavor_json'] = body['flavor']
            if body.get('instructor_mode'):
                payload['instructor_mode'] = True     # an instructor's own project in instructor mode

            def on_result(obj: dict):
                nonlocal started
                started = obj.get('status') not in (RESULT_FLAVOR_FORM, RESULT_FLAVOR_ERROR)
                if logged is not None:
                    logged.update(result=obj.get('status'), rln=obj.get('running_lab_name'))

            return await self._forward_json(request, host, identity, payload, on_result=on_result)
        finally:
            if reservation is not None:
                self.pool.release(reservation)
            if not started:
                self.limiter.give_back('start', identity.login, previous)

    async def _forward_json(self, request, host, identity, payload: dict, *, on_result=None):
        """Relay a JSON POST that answers an NDJSON stream."""
        return await self.relay.forward_ndjson(request, host, identity, 'POST', '/projects',
                                               data=json.dumps(payload).encode('utf-8'),
                                               headers={'Content-Type': 'application/json'}, on_result=on_result)

    # -- one project -----------------------------------------------------------------------------

    def _path(self, rln: str, suffix: str = '') -> str:
        return f"/projects/{urllib.parse.quote(rln, safe='')}{suffix}"

    async def _relay_json(self, request, method: str, suffix: str = '', *, json_body=None, params=None, timeout=60.0):
        host, rln, identity = self._target(request)
        status, body = await self.relay.json(host, identity, method, self._path(rln, suffix), json=json_body,
                                             params=params, timeout=timeout)
        if status == 204:
            return web.Response(status=204)
        if isinstance(body, dict) and 'host' in body:
            body['host'] = host.name   # as the browser names it, not as the agent calls itself
        return web.json_response(body, status=status)

    async def api_project_get(self, request):
        return await self._relay_json(request, 'GET')

    async def api_project_close(self, request):
        return await self._relay_json(request, 'DELETE', timeout=900)

    async def api_touch(self, request):
        return await self._relay_json(request, 'POST', '/touch')

    async def api_log(self, request):
        return await self._relay_json(request, 'GET', '/log', params={'offset': request.query.get('offset', '0')})

    async def api_schema(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.forward(request, host, identity, 'GET', self._path(rln, '/schema.svg'),
                                        params=dict(request.query))

    async def api_schema_pdf(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.forward(request, host, identity, 'GET', self._path(rln, '/schema.pdf'),
                                        params=dict(request.query))

    async def api_answers(self, request):
        if request.content_length and request.content_length > self.cfg.limits.max_answer_bytes:
            return json_error(413, "answers too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        return await self._relay_json(request, 'PUT', '/answers', json_body=body)

    async def api_evaluation(self, request):
        return await self._relay_json(request, 'GET', '/evaluation')

    async def api_eval(self, request):
        identity = self._require_identity(request)
        wait = self.limiter.allow_every('eval', identity.login, self.cfg.limits.eval_interval)
        if wait:
            return json_error(429, "please wait before evaluating again", retry_after=round(wait))
        return await self._relay_json(request, 'POST', '/eval', timeout=900)

    async def api_state(self, request):
        state = request.match_info['state']
        return await self._relay_json(request, 'POST', f"/states/{urllib.parse.quote(state, safe='')}", timeout=900)

    async def api_events(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.websocket(request, host, identity, self._path(rln, '/events'),
                                          upstream=request.get(SPECTATOR_KEY) is None)

    async def api_display(self, request):
        return await self._relay_json(request, 'GET', '/display')

    async def api_display_start(self, request):
        return await self._relay_json(request, 'POST', '/display', timeout=60)

    async def api_display_ws(self, request):
        host, rln, identity = self._target(request)
        # a spectator: the agent filters the RFB client messages (the handshake and the update
        # requests must still reach it, so the frames of the browser are forwarded)
        params = {'readonly': '1'} if request.get(SPECTATOR_KEY) is not None else None
        return await self.relay.websocket(request, host, identity, self._path(rln, '/display/ws'),
                                          protocols=(DISPLAY_SUBPROTOCOL,), params=params)

    async def api_terminal(self, request):
        host, rln, identity = self._target(request)
        device = request.match_info['device']
        params = {k: request.query[k] for k in ('cols', 'rows', 'join', 'private') if k in request.query}
        spectator = request.get(SPECTATOR_KEY) is not None
        if spectator:
            # a spectator only watches a live terminal of the presenter: the agent attaches a
            # read-only client, and nothing typed in the browser is relayed anyway
            if not params.get('join'):
                raise PoolError(403, "a spectator may only join a terminal")
            params.pop('private', None)
            params['readonly'] = '1'
        return await self.relay.websocket(request, host, identity,
                                          self._path(rln, f"/terminals/{urllib.parse.quote(device, safe='')}"),
                                          protocols=(TERMINAL_SUBPROTOCOL,), params=params, upstream=not spectator)

    # -- presentations ----------------------------------------------------------------------------
    # An instructor's project shown read-only on the browsers of the chosen students: the state
    # lives in ``presentation.py``; here the page of a spectator, the presence sockets of every
    # page, and the API of the presenter's page.

    @staticmethod
    def _watcher(ws: web.WebSocketResponse) -> Watcher:
        async def close(code: int, reason: str):
            await ws.close(code=code, message=reason.encode('utf-8'))
        return Watcher(ws.send_json, close)

    def _presentation(self, request) -> Presentation:
        p = self.presentations.get(request.match_info['id'])
        if p is None:
            raise PoolError(404, "no such presentation")
        return p

    def _presenter_of(self, request) -> tuple:
        """``(identity, presentation)`` of a call reserved to the presenter."""
        identity = self._require_identity(request)
        p = self._presentation(request)
        if identity.login != p.presenter.login:
            raise PoolError(403, "the presenter only")
        return identity, p

    async def present_page(self, request):
        """The project page of a spectator: the same template as ``project_page`` with the
        ``presentation`` context (the browser hides every control and follows the presenter's
        view), shown in an iframe of the student's own page, hence the framing headers."""
        identity = request.get(IDENTITY_KEY)
        if not identity:
            raise web.HTTPFound('/login')
        p = self._presentation(request)
        if not p.includes(identity):
            raise PoolError(403, "not in the audience")
        host = self.pool.host(p.host)
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=p.rln, presenter=p.presenter.login)
        response = aiohttp_jinja2.render_template('project.html', request, self._page_context(
            request, host=host.name, rln=p.rln, api_base=f"/api/projects/{host.name}/{urllib.parse.quote(p.rln)}",
            presentation={'id': p.id, 'presenter': p.presenter.fullname or p.presenter.login}))
        response.headers['Content-Security-Policy'] = CSP_FRAMED
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response

    async def api_presence_ws(self, request):
        """The socket every page of a logged-in user keeps open: the portal pushes the start and
        the end of the presentations the user is in; the frames of the browser are ignored."""
        identity = self._require_identity(request)
        page = request.query.get('page', '')
        if not (page.startswith('/') and len(page) <= MAX_PAGE_LENGTH and page.isprintable()):
            page = ''
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        await ws.prepare(request)
        watcher = self._watcher(ws)
        socket = self.presence.add(identity, page, watcher)
        try:
            await self.presentations.resync({identity.login})    # a presentation already running for them
            await self.focuses.resync({identity.login})          # a focus on them already
            await self.focuses.tell(identity.login, watcher)     # ... their other pages knew of
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            self.presence.remove(socket)
            with contextlib.suppress(Exception):
                await self.presentations.resync({identity.login})
            with contextlib.suppress(Exception):
                await self.focuses.resync({identity.login})
        return ws

    async def api_presence(self, request):
        """Instructors: the connected users (the audience to choose from)."""
        identity = self._require_instructor(request)
        return web.json_response(self.presence.connected(exclude_login=identity.login,
                                                         presentation_of=self.presentations.presentation_id_of))

    async def api_presentations(self, request):
        self._require_instructor(request)
        return web.json_response([p.to_dict(self.presence) for p in self.presentations.listing()])

    async def api_presentation_create(self, request):
        identity = self._require_instructor(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return json_error(400, "a JSON object is expected")
        host = self.pool.host(str(body.get('host', '')))
        rln = body.get('rln')
        if not isinstance(rln, str) or running_lab_name_owner(rln) is None:
            return json_error(400, "bad running lab name")
        try:
            audience = parse_audience(body.get('audience'), identity.login)
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=rln, audience=audience_size(audience))
        p = await self.presentations.start(identity, host.name, rln, audience)
        return web.json_response(p.to_dict(self.presence), status=201)

    async def api_presentation_get(self, request):
        identity = self._require_identity(request)
        p = self._presentation(request)
        if identity.login != p.presenter.login and not p.includes(identity):
            raise PoolError(403, "not in the audience")
        return web.json_response(p.to_dict(self.presence))

    async def api_presentation_audience(self, request):
        identity, p = self._presenter_of(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        try:
            audience = parse_audience((body or {}).get('audience') if isinstance(body, dict) else None, identity.login)
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=p.host, rln=p.rln, audience=audience_size(audience))
        p = await self.presentations.set_audience(p.id, audience)
        return web.json_response(p.to_dict(self.presence))

    async def api_presentation_view(self, request):
        """The presenter's view (the active tab, the open terminals...), pushed to the spectators."""
        identity, p = self._presenter_of(request)
        if request.content_length and request.content_length > MAX_VIEW_BYTES + 64:
            return json_error(413, "view too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        view = body.get('view') if isinstance(body, dict) and 'view' in body else body
        try:
            await self.presentations.set_view(p.id, view)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such presentation")
        return web.Response(status=204)

    async def api_presentation_evaluation(self, request):
        """The table of the presenter's Evaluation tab (header, rows, caption), pushed to the
        spectators as it is and sent to those attaching later."""
        identity, p = self._presenter_of(request)
        if request.content_length and request.content_length > MAX_EVALUATION_BYTES + 64:
            return json_error(413, "evaluation too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        evaluation = body.get('evaluation') if isinstance(body, dict) and 'evaluation' in body else body
        try:
            await self.presentations.set_evaluation(p.id, evaluation)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such presentation")
        return web.Response(status=204)

    async def api_presentation_delete(self, request):
        identity = self._require_identity(request)
        p = self._presentation(request)
        if identity.login != p.presenter.login and identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "the presenter or an instructor only")
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=p.host, rln=p.rln, presenter=p.presenter.login)
        await self.presentations.end(p.id)
        return web.json_response({'ok': True})

    async def api_presentation_ws(self, request):
        """The socket of the presenter's page (the audience counts) and of a spectator's page
        (the view, at once and on every change); closed with ``WS_PRESENTATION_ENDED`` when the
        presentation is over, at once when it already is."""
        identity = self._require_identity(request)
        p = self.presentations.get(request.match_info['id'])
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        if p is None:
            await ws.prepare(request)
            await ws.close(code=WS_PRESENTATION_ENDED, message=b"the presentation has ended")
            return ws
        presenter = identity.login == p.presenter.login
        if not presenter and not p.includes(identity):
            raise PoolError(403, "not in the audience")
        await ws.prepare(request)
        watcher = self._watcher(ws)
        if presenter:
            attached = await self.presentations.attach_presenter(p.id, watcher)
        else:
            attached = await self.presentations.attach_spectator(p.id, identity, watcher)
        if not attached:
            await ws.close(code=WS_PRESENTATION_ENDED, message=b"the presentation has ended")
            return ws
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            if presenter:
                self.presentations.detach_presenter(p.id, watcher)
            else:
                with contextlib.suppress(Exception):
                    await self.presentations.detach_spectator(p.id, identity.login, watcher)
        return ws

    # -- focus: an instructor on a student's project keeps the student's browser on it ---------
    # The registry is ``focus.Focuses``; the student's pages learn of a focus through the
    # presence socket (above), both pages share the view through the focus socket.

    def _focus(self, request) -> Focus:
        f = self.focuses.get(request.match_info['id'])
        if f is None:
            raise PoolError(404, "no such focus")
        return f

    def _focus_participant(self, request) -> tuple:
        """``(identity, focus)`` of a call reserved to the instructor or the student of it."""
        identity = self._require_identity(request)
        f = self._focus(request)
        if not f.participant(identity):
            raise PoolError(403, "the instructor or the student of this focus only")
        return identity, f

    async def api_focus_list(self, request):
        """The focuses of the caller: those they lead (an instructor's project pages resume
        theirs) and the one on them (a student's page)."""
        identity = self._require_identity(request)
        following = self.focuses.of_student(identity.login)
        return web.json_response({'leading': [f.to_dict() for f in self.focuses.for_instructor(identity.login)],
                                  'following': following.to_dict() if following is not None else None})

    async def api_focus_create(self, request):
        identity = self._require_instructor(request)
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        if not isinstance(body, dict):
            return json_error(400, "a JSON object is expected")
        host = self.pool.host(str(body.get('host', '')))
        rln = body.get('rln')
        if not isinstance(rln, str) or running_lab_name_owner(rln) is None:
            return json_error(400, "bad running lab name")
        try:
            f = await self.focuses.start(identity, host.name, rln, body.get('view'))
        except ValueError as e:
            return json_error(400, str(e))
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=host.name, rln=rln, student=f.student)
        return web.json_response(f.to_dict(), status=201)

    async def api_focus_get(self, request):
        _, f = self._focus_participant(request)
        return web.json_response(f.to_dict())

    async def api_focus_view(self, request):
        """The shared view (the active tab, the terminal shown, the question), from either
        page, pushed to both."""
        _, f = self._focus_participant(request)
        if request.content_length and request.content_length > MAX_VIEW_BYTES + 64:
            return json_error(413, "view too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        view = body.get('view') if isinstance(body, dict) and 'view' in body else body
        try:
            await self.focuses.set_view(f.id, view)
        except ValueError as e:
            return json_error(400, str(e))
        except KeyError:
            return json_error(404, "no such focus")
        return web.Response(status=204)

    async def api_focus_delete(self, request):
        identity = self._require_identity(request)
        f = self._focus(request)
        if identity.login != f.instructor.login and identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "the instructor of this focus or an instructor only")
        logged = request.get(ACCESS_KEY)
        if logged is not None:
            logged.update(host=f.host, rln=f.rln, instructor=f.instructor.login, student=f.student)
        await self.focuses.end(f.id)
        return web.json_response({'ok': True})

    async def api_focus_ws(self, request):
        """The socket of the instructor's page (the status of the student's page, the view) and
        of the student's page (the view, at once and on every change); closed with
        ``WS_FOCUS_ENDED`` when the focus is over, at once when it already is."""
        identity = self._require_identity(request)
        f = self.focuses.get(request.match_info['id'])
        ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=4096)
        if f is None:
            await ws.prepare(request)
            await ws.close(code=WS_FOCUS_ENDED, message=b"the focus has ended")
            return ws
        if not f.participant(identity):
            raise PoolError(403, "the instructor or the student of this focus only")
        leader = identity.login == f.instructor.login
        await ws.prepare(request)
        watcher = self._watcher(ws)
        if leader:
            attached = await self.focuses.attach_instructor(f.id, watcher)
        else:
            attached = await self.focuses.attach_student(f.id, identity, watcher)
        if not attached:
            await ws.close(code=WS_FOCUS_ENDED, message=b"the focus has ended")
            return ws
        try:
            async for msg in ws:
                if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                    break
        finally:
            if leader:
                self.focuses.detach_instructor(f.id, watcher)
            else:
                with contextlib.suppress(Exception):
                    await self.focuses.detach_student(f.id, watcher)
        return ws
