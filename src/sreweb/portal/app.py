"""The aiohttp application of the portal: middlewares (session, CSRF, errors, security headers),
Jinja2 templates, static files, the pool refresh task."""
import logging
import ssl
import urllib.parse
from pathlib import Path

import aiohttp
import aiohttp_jinja2
import jinja2
from aiohttp import web

from . import session as S
from .manager import PoolManager
from .pool import Pool, PoolError
from .relay import Relay
from .routes import Routes, json_error
from ..identity import IDENTITY_KEY
from ..config import WebConfig

log = logging.getLogger('sreweb.portal')

PORTAL_KEY = web.AppKey('portal', object)
CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"


class Portal:
    def __init__(self, cfg: WebConfig, *, web_dir: str, localedirs):
        self.cfg = cfg
        self.web_dir = Path(web_dir)
        self.localedirs = list(localedirs)
        self.session: aiohttp.ClientSession | None = None
        self.pool: Pool | None = None
        self.manager: PoolManager | None = None
        self.relay: Relay | None = None
        self.routes: Routes | None = None

    def make_app(self) -> web.Application:
        app = web.Application(middlewares=[self.identity_middleware, self.csrf_middleware, self.error_middleware],
                              client_max_size=max(1 << 20, self.cfg.limits.max_answer_bytes))
        app[PORTAL_KEY] = self
        aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(str(self.web_dir / 'templates')), autoescape=True)
        # the client session is created at startup, inside the running loop (aiohttp requires it)
        self.pool = Pool(self.cfg.hosts, None, poll_interval=self.cfg.pool.poll_interval,
                         wake_timeout=self.cfg.pool.wake_timeout, state_file=self.cfg.admin.state_file)
        self.manager = PoolManager(self.pool, self.cfg.pool)
        self.relay = Relay(self.pool, None)
        self.routes = Routes(self.cfg, self.pool, self.relay, localedirs=self.localedirs, manager=self.manager)
        self.routes.register(app)
        static = self.web_dir / 'static'
        if static.is_dir():
            app.router.add_static('/static/', str(static), name='static')
        app.on_startup.append(self._on_startup)
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
        self.session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context) if context else None)
        if context is not None:
            log.info("TLS to the agents: CA %s, client certificate %s", self.cfg.pool.ca or '(system store)',
                     self.cfg.pool.client_cert or '(none)')
        self.pool.session = self.session
        self.relay.session = self.session
        await self.pool.refresh()
        self.pool.start()
        self.manager.start()

    async def _on_cleanup(self, app):
        await self.manager.stop()
        await self.pool.stop()
        await self.session.close()

    # -- middlewares ----------------------------------------------------------------------------

    @web.middleware
    async def identity_middleware(self, request, handler):
        request[IDENTITY_KEY] = S.decode(request.cookies.get(S.COOKIE_NAME, ''), self.cfg.secret)
        response = await handler(request)
        response.headers.setdefault('Content-Security-Policy', CSP)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        return response

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
            return await handler(request)   # sre-web pool: the admin token, checked by the handler
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
