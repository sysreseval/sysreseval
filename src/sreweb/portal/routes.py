"""The handlers of the portal: the pages (Jinja2) and the ``/api/...`` endpoints relayed to the
agents (``relay.py``).  Every ``/api`` call needs the session cookie; the non-GET ones and the
WebSockets need the ``X-Requested-With: sre-web`` header (CSRF)."""
import hmac
import json
import logging
import urllib.parse

import aiohttp_jinja2
from aiohttp import web

from . import auth_anon, session as S
from .auth_ldap import LdapAuthenticator, LdapError
from .pool import Pool, PoolError
from .ratelimit import RateLimiter
from .relay import Relay
from ..config import WebConfig, AUTH_LDAP, AUTH_ANONYMOUS, host_config_from_dict, ConfigError
from ..identity import Identity, IdentityError, ROLE_INSTRUCTOR, running_lab_name_owner, VIEW_INSTRUCTOR, IDENTITY_KEY
from ..i18n import translator, catalog

log = logging.getLogger('sreweb.portal')

TERMINAL_SUBPROTOCOL = 'sre-term.v1'
LANGUAGE_NAMES = {'en': 'English', 'fr': 'Français'}


def json_error(status: int, message: str, **extra) -> web.Response:
    return web.json_response({'error': message, 'status': status, **extra}, status=status)


class Routes:
    def __init__(self, cfg: WebConfig, pool: Pool, relay: Relay, *, localedirs, manager=None):
        self.cfg = cfg
        self.pool = pool
        self.manager = manager
        self.relay = relay
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
        r.add_get('/projects/{host}/{rln}', self.project_page)
        r.add_get('/i18n/{lang}.json', self.i18n_catalog)
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
        r.add_post('/api/projects', self.api_projects_create)
        r.add_get('/api/projects/{host}/{rln}', self.api_project_get)
        r.add_delete('/api/projects/{host}/{rln}', self.api_project_close)
        r.add_get('/api/projects/{host}/{rln}/events', self.api_events)
        r.add_get('/api/projects/{host}/{rln}/schema.svg', self.api_schema)
        r.add_put('/api/projects/{host}/{rln}/answers', self.api_answers)
        r.add_post('/api/projects/{host}/{rln}/eval', self.api_eval)
        r.add_post('/api/projects/{host}/{rln}/states/{state}', self.api_state)
        r.add_get('/api/projects/{host}/{rln}/terminals/{device}', self.api_terminal)
        r.add_get('/api/projects/{host}/{rln}/log', self.api_log)
        r.add_post('/api/projects/{host}/{rln}/touch', self.api_touch)
        r.add_get('/api/projects/{host}/{rln}/export', self.api_export)

    # -- helpers --------------------------------------------------------------------------------

    def _secure(self, request) -> bool:
        return self.cfg.public_url.lower().startswith('https://') or request.scheme == 'https'

    def _language(self, request) -> str:
        identity = request.get(IDENTITY_KEY)
        if identity is not None:
            return identity.language
        lang = request.query.get('lang') or request.cookies.get('sreweb_lang', '')
        return lang if lang in self.cfg.languages else self.cfg.languages[0]

    def _translate(self, request):
        return translator(self._language(request), self.localedirs)

    def _page_context(self, request, **extra) -> dict:
        identity = request.get(IDENTITY_KEY)
        return {
            '_': self._translate(request),
            'identity': identity.to_dict() if identity else None,
            'auth_mode': self.cfg.auth.mode,
            'languages': [(code, LANGUAGE_NAMES.get(code, code)) for code in self.cfg.languages],
            'language': self._language(request),
            'instructor': bool(identity and identity.role == ROLE_INSTRUCTOR),
            **extra,
        }

    def _require_identity(self, request) -> Identity:
        identity = request.get(IDENTITY_KEY)
        if identity is None:
            raise web.HTTPUnauthorized(text=json.dumps({'error': 'not logged in', 'status': 401}),
                                       content_type='application/json')
        return identity

    def _target(self, request) -> tuple:
        """The host and running lab name of a project URL, after the ownership check."""
        identity = self._require_identity(request)
        host = self.pool.host(request.match_info['host'])
        rln = request.match_info['rln']
        owner = running_lab_name_owner(rln)
        if owner is None:
            raise PoolError(404, "unknown project")
        if owner != identity.login and identity.role != ROLE_INSTRUCTOR:
            raise PoolError(403, "not your project")
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
        language = self._check_language(str(data.get('language', '') or self._language(request)))
        if self.cfg.auth.mode == AUTH_ANONYMOUS:
            return auth_anon.new_guest(str(data.get('display_name', '')), language)
        if not self.limiter.allow_per_minute('login', request.remote or '', self.cfg.limits.login_per_minute):
            raise PoolError(429, "too many login attempts, try again in a minute")
        login = str(data.get('login', '')).strip()
        password = str(data.get('password', ''))
        try:
            identity = await self.ldap.authenticate(login, password, language)
        except LdapError as e:
            log.error("LDAP error: %s", e)
            raise PoolError(502, "the directory does not answer")
        if identity is None:
            raise PoolError(401, "wrong login or password")
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
        if request.path.startswith('/api/'):
            response = web.json_response({'ok': True})
        else:
            response = web.HTTPFound('/login')
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
        from dataclasses import replace
        identity = replace(identity, language=language)
        response = web.json_response({'identity': identity.to_dict()})
        S.set_cookie(response, identity, self.cfg.secret, secure=self._secure(request))
        return response

    # -- labs, pool, projects -------------------------------------------------------------------

    async def api_labs(self, request):
        identity = self._require_identity(request)
        return web.json_response(await self.pool.labs(identity))

    # -- the pool (instructors, and sre-web pool with the admin token) --------------------------

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

    def _require_pool_access(self, request):
        if self._is_admin(request):
            return
        if request.headers.get('Authorization'):
            raise PoolError(401, "bad administration token")
        if self._require_identity(request).role != ROLE_INSTRUCTOR:
            raise PoolError(403, "instructors only")

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
        self._require_admin(request)
        name, action = request.match_info['name'], request.match_info['action']
        if action == 'enable':
            self.pool.set_enabled(name, True)
        elif action == 'disable':
            self.pool.set_enabled(name, False)
        elif action == 'wake':
            await self.manager.wake(name, "requested")
        elif action == 'poweroff':
            await self.manager.power_off(name, "requested")
        elif action == 'drain':
            self.pool.host(name)
            self.pool.runtime[name].drain = True
            log.info("host %s draining: no new project, power off when empty", name)
        else:
            return json_error(404, f"unknown action {action}")
        return web.json_response(self._host_row(name))

    def _host_row(self, name: str) -> dict:
        return next((row for row in self.pool.summary() if row['name'] == name), {'name': name})

    async def api_projects(self, request):
        identity = self._require_identity(request)
        return web.json_response(await self.pool.projects_of(identity))

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
        wait = self.limiter.allow_every('start', identity.login, self.cfg.limits.start_interval)
        if wait:
            return json_error(429, "please wait before starting another project", retry_after=round(wait))
        host, reservation = self.pool.pick()
        payload = {'lab': body['lab'], 'idle_timeout': self._idle_timeout(identity)}
        if isinstance(body.get('flavor'), dict):
            payload['flavor_json'] = body['flavor']
        try:
            return await self._forward_json(request, host, identity, payload)
        finally:
            self.pool.release(reservation)

    async def _forward_json(self, request, host, identity, payload: dict):
        """Relay a JSON POST that answers an NDJSON stream."""
        return await self.relay.forward_ndjson(request, host, identity, 'POST', '/projects',
                                               data=json.dumps(payload).encode('utf-8'),
                                               headers={'Content-Type': 'application/json'})

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

    async def api_answers(self, request):
        if request.content_length and request.content_length > self.cfg.limits.max_answer_bytes:
            return json_error(413, "answers too large")
        try:
            body = await request.json()
        except ValueError:
            return json_error(400, "a JSON body is expected")
        return await self._relay_json(request, 'PUT', '/answers', json_body=body)

    async def api_eval(self, request):
        identity = self._require_identity(request)
        wait = self.limiter.allow_every('eval', identity.login, self.cfg.limits.eval_interval)
        if wait:
            return json_error(429, "please wait before evaluating again", retry_after=round(wait))
        return await self._relay_json(request, 'POST', '/eval', timeout=900)

    async def api_state(self, request):
        state = request.match_info['state']
        return await self._relay_json(request, 'POST', f"/states/{urllib.parse.quote(state, safe='')}", timeout=900)

    async def api_export(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.forward(request, host, identity, 'GET', self._path(rln, '/export'),
                                        params=dict(request.query))

    async def api_events(self, request):
        host, rln, identity = self._target(request)
        return await self.relay.websocket(request, host, identity, self._path(rln, '/events'))

    async def api_terminal(self, request):
        host, rln, identity = self._target(request)
        device = request.match_info['device']
        params = {k: request.query[k] for k in ('cols', 'rows') if k in request.query}
        return await self.relay.websocket(request, host, identity,
                                          self._path(rln, f"/terminals/{urllib.parse.quote(device, safe='')}"),
                                          protocols=(TERMINAL_SUBPROTOCOL,), params=params)
