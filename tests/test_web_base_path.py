"""The portal served under a sub-path (``base_path`` of web.toml: ``https://host/my-sre-server/``
instead of the root of a host name): the application mounted there and nowhere else, the
redirects and the cookies carrying the sub-path, the checks made on the path of a request (CSRF,
JSON errors, static files, the connection log, the routes of a spectator) made on the path of
the application, the paths sent to the browser in JSON left as they are (``base_path.js`` adds
the sub-path), the ``logoutURL`` of a web conference and the URL ``sre-web-tool`` calls.  On the
harness of ``test_web_portal.py``: a real agent on the fake ``sre``, the portal in front."""
import asyncio
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip('aiohttp')
pytest.importorskip('aiohttp_jinja2')

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yarl   # noqa: E402

import test_web_portal as P   # noqa: E402  (the Harness)
import test_web_webconf as WC   # noqa: E402  (the harness with the fake BBB server)
from fake_bbb import FakeBbbServer   # noqa: E402

from sreweb.config import web_config_from_dict   # noqa: E402
from sreweb.portal import session as S   # noqa: E402
from sreweb.portal.basepath import strip_base, route_pattern   # noqa: E402
from sreweb.portal.poolctl import _portal_url   # noqa: E402

SRC = Path(__file__).resolve().parent.parent / 'src'
BASE = '/my-sre-server'
ADMIN = 'a' * 32
CSRF = P.CSRF
run = P.run


class Under:
    """The client of a harness, every path under the sub-path (*base* ``''``: the root)."""

    def __init__(self, h, base: str = BASE):
        self.h = h
        self.base = base

    def get(self, path, **kw):
        return self.h.client.get(self.base + path, **kw)

    def post(self, path, **kw):
        return self.h.client.post(self.base + path, **kw)

    def delete(self, path, **kw):
        return self.h.client.delete(self.base + path, **kw)

    def ws_connect(self, path, **kw):
        return self.h.client.ws_connect(self.base + path, **kw)

    async def start(self, headers=None) -> str:
        """A project started: its running lab name."""
        resp = await self.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**(headers or {}), **CSRF})
        assert resp.status == 200, await resp.text()
        return [json.loads(line) for line in (await resp.text()).splitlines()][-1]['running_lab_name']


def under(tmp_path, **kw):
    """The harness of a portal served under ``BASE``."""
    web_over = {**kw.pop('web_over', {}), 'base_path': BASE}
    return P.Harness(tmp_path, web_over=web_over, **kw)


def request_of(canonical):
    """What ``route_pattern`` reads of a request: the resource of its route (``None`` for the
    route of a 404)."""
    resource = None if canonical is None else types.SimpleNamespace(canonical=canonical)
    return types.SimpleNamespace(match_info=types.SimpleNamespace(route=types.SimpleNamespace(resource=resource)))


class TestHelpers:
    @pytest.mark.parametrize('path, base, expected', [
        ('/sre/api/x', '/sre', '/api/x'), ('/sre', '/sre', '/'), ('/sre/', '/sre', '/'),
        ('/a/b/static/x.css', '/a/b', '/static/x.css'),
        ('/srex/api/x', '/sre', '/srex/api/x'),          # another path, not the sub-path
        ('/api/x', '/sre', '/api/x'), ('/api/x', '', '/api/x'), ('/', '', '/'),
    ])
    def test_strip_base(self, path, base, expected):
        assert strip_base(path, base) == expected

    @pytest.mark.parametrize('canonical, base, expected', [
        ('/sre/api/projects/{host}/{rln}', '/sre', '/api/projects/{host}/{rln}'),
        ('/sre/static', '/sre', '/static'), ('/sre/', '/sre', '/'),
        ('/api/projects', '', '/api/projects'), ('/srex/api', '/sre', '/srex/api'),
        (None, '/sre', ''), (None, '', ''),
    ])
    def test_route_pattern(self, canonical, base, expected):
        assert route_pattern(request_of(canonical), base) == expected


class TestMount:
    def test_the_site_lives_under_the_sub_path_only(self, tmp_path):
        async def go():
            async with under(tmp_path) as h:
                c, root = Under(h), Under(h, '')
                resp = await c.get('/', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login'
                resp = await root.get(BASE, allow_redirects=False)                 # without its slash
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/'
                resp = await c.get('/projects', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login'
                resp = await c.get('/login')
                assert resp.status == 200 and 'anonymous' in await resp.text()
                assert 'default-src' in resp.headers['Content-Security-Policy']
                assert (await (await c.get('/api/me')).json())['identity'] is None
                resp = await c.get('/static/x.css')
                assert resp.status == 200 and resp.headers['Cache-Control'] == 'no-cache'
                # nothing at the root of the host name, nor under a path that only starts alike
                for path in ('/', '/login', '/projects', '/api/me', '/static/x.css', f'{BASE}x/login', f'{BASE}x'):
                    assert (await root.get(path, allow_redirects=False)).status == 404, path
                assert (await root.post('/api/login', json={'display_name': 'x'}, headers=CSRF)).status == 404
        run(go())

    def test_login_cookies_and_logout(self, tmp_path):
        async def go():
            async with under(tmp_path) as h:
                c = Under(h)
                jar = h.client.session.cookie_jar
                site = yarl.URL(f'http://127.0.0.1:{h.client.port}')
                resp = await c.post('/login', data={'display_name': 'Émile', 'language': 'fr'}, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/projects'
                assert resp.cookies[S.COOKIE_NAME]['path'] == BASE
                # the browser sends the session to the site, not to what else the host name serves
                assert S.COOKIE_NAME in jar.filter_cookies(site.with_path(f'{BASE}/api/me'))
                assert S.COOKIE_NAME not in jar.filter_cookies(site.with_path('/other/app'))
                me = (await (await c.get('/api/me')).json())['identity']
                assert me['login'].startswith('guest-') and me['fullname'] == 'Émile'
                resp = await c.get('/login', allow_redirects=False)                # already logged in
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/projects'
                resp = await c.get('/', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/projects'
                assert (await c.get('/projects')).status == 200 and (await c.get('/open')).status == 200
                # the language: both cookies written again, on the same path
                resp = await c.post('/api/language', json={'language': 'en'}, headers=CSRF)
                assert resp.status == 200
                assert resp.cookies[S.LANG_COOKIE]['path'] == BASE and resp.cookies[S.COOKIE_NAME]['path'] == BASE
                assert (await (await c.get('/api/me')).json())['identity']['language'] == 'en'
                # the logout form: the cookie of that path removed
                resp = await c.post('/logout', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login'
                assert resp.cookies[S.COOKIE_NAME]['path'] == BASE and resp.cookies[S.COOKIE_NAME].value == ''
                assert S.COOKIE_NAME not in jar.filter_cookies(site.with_path(f'{BASE}/api/me'))
                assert (await (await c.get('/api/me')).json())['identity'] is None
                assert (await c.get('/api/projects')).status == 401
                # the API login and logout
                resp = await c.post('/api/login', json={'display_name': 'x'}, headers=CSRF)
                assert resp.status == 200 and resp.cookies[S.COOKIE_NAME]['path'] == BASE
                resp = await c.post('/api/logout', headers=CSRF)
                assert resp.status == 200 and await resp.json() == {'ok': True, 'logout_url': ''}
        run(go())

    def test_proxy_mode_and_the_logout_of_the_proxy(self, tmp_path):
        """``logout_url`` is a location of the reverse proxy: followed as it is written."""
        proxy = {**P.PROXY_OVER['auth']['proxy'], 'logout_url': '/apache-logout'}
        over = {**P.PROXY_OVER, 'auth': {'mode': 'proxy', 'proxy': proxy}}

        async def go():
            async with under(tmp_path, auth_mode='proxy', web_over=over) as h:
                c, bob = Under(h), P.who('bob', 'Bob')
                resp = await c.get('/projects', headers=bob)
                assert resp.status == 200 and 'bob' in await resp.text()
                resp = await c.get('/projects', allow_redirects=False)             # no identity header
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login'
                resp = await c.post('/login', data={'login': 'bob'}, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login?error=proxy_mode'
                resp = await c.post('/logout', headers=bob, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/apache-logout'
                resp = await c.post('/api/logout', headers={**bob, **CSRF})
                assert resp.status == 200 and await resp.json() == {'ok': True, 'logout_url': '/apache-logout'}
        run(go())


class TestPathChecks:
    """What the middlewares decide on the path of a request, decided on the path of the
    application."""

    def test_csrf_and_json_errors(self, tmp_path):
        async def go():
            async with under(tmp_path) as h:
                c = Under(h)
                origin = f'http://{h.client.host}:{h.client.port}'
                resp = await c.post('/api/login', json={'display_name': 'x'})
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
                resp = await c.post('/api/login', json={'display_name': 'x'}, headers={**CSRF, 'Origin': 'https://evil.example'})
                assert resp.status == 403 and (await resp.json())['error'] == 'bad origin'
                resp = await c.post('/login', data={'display_name': 'x'}, headers={'Origin': 'https://evil.example'},
                                    allow_redirects=False)
                assert resp.status == 403
                resp = await c.post('/api/login', json={'display_name': 'x'}, headers={**CSRF, 'Origin': origin})
                assert resp.status == 200
                # the errors of the API are JSON, those of a page plain text
                resp = await c.get('/api/projects/nope/x')
                assert resp.status == 404 and 'error' in await resp.json()
                resp = await c.get('/projects/nope/x')
                assert resp.status == 404 and resp.content_type == 'text/plain'
        run(go())

    def test_public_url_names_the_origin(self, tmp_path):
        """The ``Origin`` of a request is checked against the host of ``public_url``, written
        with the sub-path or without."""
        async def go(n, public_url):
            async with under(tmp_path / n, web_over={'public_url': public_url}) as h:
                c = Under(h)
                good = {**CSRF, 'Origin': 'https://sre.example.org'}
                assert (await c.post('/api/login', json={'display_name': 'x'}, headers=good)).status == 200
                bad = {**CSRF, 'Origin': 'https://other.example.org'}
                assert (await c.post('/api/login', json={'display_name': 'x'}, headers=bad)).status == 403
        for n, public_url in enumerate(('https://sre.example.org', f'https://sre.example.org{BASE}/')):
            (tmp_path / str(n)).mkdir()
            run(go(str(n), public_url))

    def test_admin_token(self, tmp_path):
        """``sre-web-tool``: the bearer token passes the CSRF check of ``/api/pool`` there too."""
        over = {'admin': {'token': ADMIN, 'state_file': str(tmp_path / 'pool.json')}}

        async def go():
            async with under(tmp_path, web_over=over) as h:
                c, auth = Under(h), {'Authorization': f'Bearer {ADMIN}'}
                assert (await c.get('/api/pool')).status == 401
                rows = await (await c.get('/api/pool', headers=auth)).json()
                assert [r['name'] for r in rows] == ['a01']
                assert (await c.post('/api/pool/hosts/a01/disable', headers=auth)).status == 200     # no CSRF header
                assert (await c.post('/api/pool/hosts/a01/enable', headers=auth)).status == 200
                resp = await c.post('/api/pool/hosts/a01/disable')
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
        run(go())

    def test_the_tool_calls_the_sub_path(self, tmp_path):
        cfg = web_config_from_dict({'secret': P.SECRET, 'hosts': [], 'listen': '0.0.0.0:8460', 'base_path': BASE})
        assert _portal_url(cfg) == f'http://127.0.0.1:8460{BASE}'
        assert _portal_url(web_config_from_dict({'secret': P.SECRET, 'hosts': []})) == 'http://127.0.0.1:8450'
        over = {'admin': {'token': ADMIN, 'state_file': str(tmp_path / 'pool.json')}}

        async def go():
            async with under(tmp_path, web_over=over) as h:
                env = {**os.environ, 'PYTHONPATH': str(SRC)}

                def cli(url):
                    return subprocess.run([sys.executable, '-m', 'sreweb.tool', '--url', url, '--token', ADMIN, 'list'],
                                          capture_output=True, text=True, env=env, timeout=120)
                loop = asyncio.get_running_loop()
                r = await loop.run_in_executor(None, cli, f'http://127.0.0.1:{h.client.port}{BASE}/')
                assert r.returncode == 0, r.stderr
                assert r.stdout.splitlines()[1].split()[:2] == ['a01', 'up']
                r = await loop.run_in_executor(None, cli, f'http://127.0.0.1:{h.client.port}')
                assert r.returncode == 1 and '404' in r.stderr
        run(go())


class TestConnectionLog:
    @staticmethod
    async def session(tmp_path, base: str) -> list:
        """One session of a student on a portal served under *base*: the lines of its log."""
        over = {'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}
        if base:
            over['base_path'] = base
        log = P.TestAccessLog()
        async with P.Harness(tmp_path, web_over=over) as h:
            c = Under(h, base)
            resp = await c.post('/api/login', json={'display_name': 'Alice', 'language': 'fr'}, headers=CSRF)
            assert resp.status == 200, await resp.text()
            rln = await c.start()
            api = f'/api/projects/a01/{rln}'
            assert (await c.get('/api/projects')).status == 200
            assert (await c.post(f'{api}/touch', headers=CSRF)).status == 204
            assert (await c.get(f'/projects/a01/{rln}')).status == 200
            assert (await c.get('/static/x.css')).status == 200
            ws = await c.ws_connect(f'{api}/events')
            await ws.close()
            await log.wait_event(tmp_path, 'project_close')
            presence = await c.ws_connect('/api/presence/ws?page=/projects')       # ignored, like the static files
            await presence.close()
            assert (await c.post(f'{api}/eval', headers=CSRF)).status == 200
            assert (await c.get('/api/pool')).status == 403                        # denied
            assert (await c.delete(api, headers=CSRF)).status == 200
            assert (await c.post('/api/logout', headers=CSRF)).status == 200
        return log.lines(tmp_path)

    def test_the_same_lines_as_at_the_root(self, tmp_path):
        """The events come from the routes and the lines name paths: both are those of the
        application, so the log of a site under a sub-path reads like any other."""
        lines = {}
        for name, base in (('root', ''), ('sub', BASE)):
            (tmp_path / name).mkdir()
            lines[name] = run(self.session(tmp_path / name, base))
        events = [line['event'] for line in lines['sub']]
        assert events == [line['event'] for line in lines['root']]
        assert events == ['login', 'session_open', 'start', 'project_open', 'project_close', 'eval', 'denied', 'stop',
                          'logout', 'session_close']
        for name in ('root', 'sub'):
            denied = next(line for line in lines[name] if line['event'] == 'denied')
            assert (denied['method'], denied['path'], denied['status']) == ('GET', '/api/pool', '403')
            assert not any(BASE in str(value) for line in lines[name] for value in line.values())

    def test_admin_line(self, tmp_path):
        over = {'admin': {'token': ADMIN, 'state_file': str(tmp_path / 'pool.json')},
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}

        async def go():
            async with under(tmp_path, web_over=over) as h:
                resp = await Under(h).post('/api/pool/hosts/a01/disable', headers={'Authorization': f'Bearer {ADMIN}'})
                assert resp.status == 200
        run(go())
        admin = [line for line in P.TestAccessLog.lines(tmp_path) if line['event'] == 'admin']
        assert [(line['method'], line['path']) for line in admin] == [('POST', '/api/pool/hosts/a01/disable')]


class TestPresentationAndConference:
    def test_spectator_routes_and_the_pushed_url(self, tmp_path):
        """The routes a spectator may use are told by their pattern, and the URL pushed to the
        audience is an application path (``base.js`` adds the sub-path)."""
        async def go():
            async with under(tmp_path, auth_mode='proxy', web_over=P.PROXY_OVER) as h:
                c = Under(h)
                alice, bob, prof = P.who('alice', 'Alice'), P.who('bob', 'Bob'), P.who('prof', 'Pr. Of', groups=P.TEACHERS)
                rln = await c.start(alice)
                api = f'/api/projects/a01/{rln}'
                assert (await c.get(api, headers=bob)).status == 403               # before the presentation
                ws = await c.ws_connect('/api/presence/ws?page=/projects', headers=bob)
                resp = await c.post('/api/presentations', json={'host': 'a01', 'rln': rln, 'audience': ['bob']},
                                    headers={**prof, **CSRF})
                assert resp.status == 201, await resp.text()
                pid = (await resp.json())['id']
                push = await asyncio.wait_for(ws.receive_json(), 5)
                assert (push['t'], push['url']) == ('presentation', f'/present/{pid}')
                data = await (await c.get(api, headers=bob)).json()
                assert data['owner'] == 'alice' and data['running_lab_name'] == rln
                assert (await c.post(f'{api}/touch', headers={**bob, **CSRF})).status == 204
                assert (await c.post(f'{api}/eval', headers={**bob, **CSRF})).status == 403     # not a spectator's route
                assert (await c.get(api, headers=P.who('carol'))).status == 403
                resp = await c.get(f'/present/{pid}', headers=bob)
                assert resp.status == 200 and resp.headers['X-Frame-Options'] == 'SAMEORIGIN'
                assert f'/api/projects/a01/' in await resp.text()                  # api_base: an application path
                assert BASE not in await resp.text()
                resp = await c.get(f'/present/{pid}', allow_redirects=False)       # nobody
                assert resp.status == 302 and resp.headers['Location'] == f'{BASE}/login'
                # a focus names the project page the same way
                await ws.close()
                ws = await c.ws_connect('/api/presence/ws?page=/open', headers=alice)
                resp = await c.post('/api/focus', json={'host': 'a01', 'rln': rln, 'view': {}}, headers={**prof, **CSRF})
                assert resp.status == 201, await resp.text()
                push = await asyncio.wait_for(ws.receive_json(), 5)
                assert push['t'] == 'focus' and push['url'].startswith('/projects/a01/')
                await ws.close()
        run(go())

    @pytest.mark.parametrize('public_url, site', [
        ('https://sre.example.org', f'https://sre.example.org{BASE}'),
        (f'https://sre.example.org{BASE}', f'https://sre.example.org{BASE}'),
        ('', None),                                    # the origin of the request
    ])
    def test_the_meeting_comes_back_to_the_site(self, tmp_path, public_url, site):
        """The ``logoutURL`` of a meeting is the left page of the site, under its sub-path; the
        join URL pushed to the browsers is an application path."""
        async def go():
            fake = await FakeBbbServer().start()
            try:
                async with WC.harness(tmp_path, fake, base_path=BASE, public_url=public_url) as h:
                    c = Under(h)
                    ws = await c.ws_connect('/api/presence/ws?page=/projects', headers=WC.ALICE_H)
                    resp = await c.post('/api/webconfs', json={'name': 'Salle 1', 'audience': {'logins': ['alice']}},
                                        headers={**WC.PROF_H, **CSRF})
                    assert resp.status == 201, await resp.text()
                    room = await resp.json()
                    expected = site or f'http://{h.client.host}:{h.client.port}{BASE}'
                    left = fake.meetings[room['meeting_id']].params['logoutURL']
                    assert left == f"{expected}/webconf/left?id={room['id']}"
                    push = await asyncio.wait_for(ws.receive_json(), 5)
                    assert push['join_url'] == f"/api/webconfs/{room['id']}/join"
                    resp = await c.get(push['join_url'], headers=WC.ALICE_H, allow_redirects=False)
                    assert resp.status == 302 and resp.headers['Location'].startswith(fake.url)
                    resp = await c.get(f"/webconf/left?id={room['id']}")
                    assert resp.status == 200 and room['id'] in await resp.text()
                    await ws.close()
            finally:
                await fake.close()
        run(go())
