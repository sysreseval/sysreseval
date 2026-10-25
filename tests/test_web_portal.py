"""Tests of the portal (sreweb.portal): session cookie, anonymous login, the proxy mode (the
identity in the headers of a trusted reverse proxy), CSRF, ownership, pool placement, rate
limits, and the relay to a real agent running the fake sre of tests/mock_sre.py."""
import asyncio
import json
import stat
import sys
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")
pytest.importorskip('aiohttp_jinja2', reason="aiohttp_jinja2 is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")
from aiohttp.test_utils import TestServer, TestClient  # noqa: E402

from sreweb import identity as ident
from sreweb.agent.app import Agent, TERMINAL_SUBPROTOCOL, DISPLAY_SUBPROTOCOL
from sreweb.config import agent_config_from_dict, web_config_from_dict
from sreweb.identity import Identity
from sreweb.portal import session as S
from sreweb.portal.app import Portal
from sreweb.portal.pool import Pool, PoolError, HostStatus
from sreweb.config import HostConfig

MOCK = Path(__file__).parent / 'mock_sre.py'
MOCK_XVNC = Path(__file__).parent / 'mock_xvnc.py'
TOKEN = 't' * 32
SECRET = 's' * 32
CSRF = {S.CSRF_HEADER: S.CSRF_VALUE}
TEXT_HASH = 'cfc140584d209e6d8ed82f6db72c91a210cb1f2ded6a6b66f81c17e16ac2b857'
TEACHERS = 'cn=teachers,ou=groups,dc=example,dc=org'
# proxy mode: the test client is the trusted peer (TestServer binds 127.0.0.1); web_over replaces the whole auth dict
PROXY_OVER = {'auth': {'mode': 'proxy', 'proxy': {'instructor_groups': [TEACHERS]}},
              'trusted_proxies': ['127.0.0.1', '::1']}

TEMPLATES = {
    'login.html': '<html lang="{{ language }}"><title>Login</title>{{ auth_mode }} {{ error }}'
                  '{% for code, name in languages %}<option>{{ code }}</option>{% endfor %}'
                  '{% if site.logo_url %}<img src="{{ site.logo_url }}">{% endif %}[{{ site.name }}]</html>',
    'projects.html': '<html><title>Projects</title>{{ identity.login }}</html>',
    'open.html': '<html><title>Open</title>{{ identity.login }}</html>',
    'project.html': '<html><title>Project</title>{{ host }} {{ rln }} {{ api_base }} {{ _("Schema") }}</html>',
    'watch.html': '<html><title>Watch</title>{{ identity.login }} {{ instructor }}</html>',
}


def run(coro):
    return asyncio.run(coro)


def who(login, fullname='', email='', groups='') -> dict:
    """The identity headers Apache sets in proxy mode (the defaults of [auth.proxy])."""
    return {'X-Remote-User': login, 'X-Remote-Name': fullname, 'X-Remote-Email': email, 'X-Remote-Groups': groups}


class Harness:
    """A real agent on the fake sre, and a portal whose only host is that agent."""

    def __init__(self, tmp_path, *, auth_mode='anonymous', mock_env=None, web_over=None, hosts=1, agent_over=None,
                 role_resolver=None):
        self.tmp = tmp_path
        self.role_resolver = role_resolver
        self.pub = tmp_path / 'pub'
        (self.pub / 'projects').mkdir(parents=True)
        exe = tmp_path / 'sre'
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" -W ignore "{MOCK}" "$@"\n')
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        env = {'SRE_PUB_DIR': str(self.pub), **(mock_env or {})}
        cfg = agent_config_from_dict({'token': TOKEN, 'sre_exe': str(exe), 'poll_interval': 0.05,
                                      'state_dir': str(tmp_path / 'web-agent'), 'occupied_check': 'never',
                                      **(agent_over or {})},
                                     sre_exe=str(exe), state_dir='')   # never: the sessions of the test host
        self.agent = Agent(cfg, pub_dir=str(self.pub), projects_dir=str(self.pub / 'projects'), localedirs=[],
                           hostname='pool1', extra_env=env, archive_dirs=[str(self.pub / 'archives')])
        self.web_dir = tmp_path / 'web'
        (self.web_dir / 'templates').mkdir(parents=True)
        (self.web_dir / 'static').mkdir()
        (self.web_dir / 'static' / 'x.css').write_text('body {}')
        for name, text in TEMPLATES.items():
            (self.web_dir / 'templates' / name).write_text(text)
        self.auth_mode = auth_mode
        self.web_over = web_over or {}
        self.hosts = hosts
        self.agent_server = None
        self.portal = None
        self.client = None

    async def __aenter__(self):
        self.agent_server = TestServer(self.agent.make_app())
        await self.agent_server.start_server()
        url = f"http://127.0.0.1:{self.agent_server.port}"
        hosts = [{'name': 'a01', 'url': url, 'token': TOKEN, 'max_projects': 3}]
        if self.hosts > 1:
            hosts.append({'name': 'down', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'max_projects': 3})
        cfg = web_config_from_dict({'secret': SECRET, 'auth': {'mode': self.auth_mode},
                                    'pool': {'poll_interval': 0.1}, 'hosts': hosts, **self.web_over})
        self.portal = Portal(cfg, web_dir=str(self.web_dir), localedirs=[], role_resolver=self.role_resolver)
        self.client = TestClient(TestServer(self.portal.make_app()))
        await self.client.start_server()
        return self

    async def __aexit__(self, *exc):
        await self.client.close()
        await self.agent_server.close()

    async def login(self, display_name='Alice', language='fr'):
        resp = await self.client.post('/api/login', json={'display_name': display_name, 'language': language},
                                      headers=CSRF)
        assert resp.status == 200, await resp.text()
        return (await resp.json())['identity']

    async def start(self, lab='sre/dhcp.py', **body) -> dict:
        resp = await self.client.post('/api/projects', json={'lab': lab, **body}, headers=CSRF)
        assert resp.status == 200, await resp.text()
        lines = [json.loads(l) for l in (await resp.text()).splitlines()]
        return lines[-1]


class TestSessionCookie:
    def test_round_trip_and_forgery(self):
        me = Identity(login='alice', fullname='Alice', email='a@x', language='fr', anonymous=True)
        value = S.encode(me, SECRET, now=1000)
        assert S.decode(value, SECRET, now=2000) == me
        assert S.decode(value, 'x' * 32, now=2000) is None          # another secret
        assert S.decode(value[:-2] + 'zz', SECRET, now=2000) is None  # tampered signature
        assert S.decode(value, SECRET, now=1000 + S.MAX_AGE + 1) is None   # expired
        assert S.decode('', SECRET) is None and S.decode('garbage', SECRET) is None
        body, _, sig = value.rpartition('.')
        assert S.decode('eyJ4IjoxfQ.' + sig, SECRET, now=2000) is None   # another payload, same signature


class TestLoginAndPages:
    def test_anonymous_login_pages_and_logout(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.get('/', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/login'
                resp = await h.client.get('/projects', allow_redirects=False)
                assert resp.status == 302
                resp = await h.client.get('/login')
                assert resp.status == 200 and 'anonymous' in await resp.text()
                assert 'default-src' in resp.headers['Content-Security-Policy']
                assert (await h.client.get('/api/me')).status == 200
                assert (await (await h.client.get('/api/me')).json())['identity'] is None
                assert (await h.client.get('/api/projects')).status == 401
                # the HTML form
                resp = await h.client.post('/login', data={'display_name': 'Émile', 'language': 'fr'},
                                           allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/projects'
                assert S.COOKIE_NAME in resp.cookies
                me = (await (await h.client.get('/api/me')).json())['identity']
                assert me['login'].startswith('guest-') and me['fullname'] == 'Émile' and me['anonymous']
                assert me['language'] == 'fr' and me['role'] == 'student'
                resp = await h.client.get('/projects')
                assert resp.status == 200 and me['login'] in await resp.text()
                assert (await h.client.get('/open')).status == 200
                assert (await h.client.get('/static/x.css')).status == 200
                assert (await h.client.get('/i18n/fr.json')).status == 200
                assert (await h.client.get('/i18n/xx.json')).status == 404
                # language change
                resp = await h.client.post('/api/language', json={'language': 'en'}, headers=CSRF)
                assert (await resp.json())['identity']['language'] == 'en'
                resp = await h.client.post('/api/language', json={'language': 'xx'}, headers=CSRF)
                assert (await resp.json())['identity']['language'] == 'en'   # the first configured language
                # logout
                resp = await h.client.post('/api/logout', headers=CSRF)
                assert resp.status == 200
                assert (await (await h.client.get('/api/me')).json())['identity'] is None
        run(go())

    def test_site_logo_and_name(self, tmp_path):
        """[site] of web.toml: the logo is served at /site/logo without any session (the login
        page shows it), the name follows the language of the page; 404 and nothing without."""
        async def go():
            logo = tmp_path / 'logo.jpg'
            logo.write_bytes(b'\xff\xd8\xff\xe0 fake jpeg')
            over = {'languages': ['fr', 'en'],
                    'site': {'logo': str(logo), 'name': {'fr': 'IUT de Démo', 'en': 'Demo Institute'}, 'url': '/about'}}
            async with Harness(tmp_path / 'with', web_over=over) as h:
                resp = await h.client.get('/site/logo')
                assert resp.status == 200 and resp.headers['Content-Type'] == 'image/jpeg'
                assert await resp.read() == logo.read_bytes()
                text = await (await h.client.get('/login')).text()
                assert '<img src="/site/logo">' in text and '[IUT de Démo]' in text
                text = await (await h.client.get('/login?lang=en')).text()
                assert '[Demo Institute]' in text
            async with Harness(tmp_path / 'without') as h:
                assert (await h.client.get('/site/logo')).status == 404
                text = await (await h.client.get('/login')).text()
                assert '<img' not in text and '[]' in text
        run(go())

    def test_each_browser_gets_its_own_guest(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                a = await h.login('A')
                h.client.session.cookie_jar.clear()
                b = await h.login('B')
                assert a['login'] != b['login']
        run(go())

    def test_ldap_mode_without_directory(self, tmp_path):
        async def go():
            over = {'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldap://127.0.0.1:1', 'bind_dn_template': 'uid={login},dc=x',
                                                     'timeout': 1}}}
            async with Harness(tmp_path, auth_mode='ldap', web_over=over) as h:
                resp = await h.client.post('/api/login', json={'login': 'alice', 'password': 'x'}, headers=CSRF)
                assert resp.status in (502, 401)
                resp = await h.client.post('/api/login', json={'login': '../x', 'password': 'x'}, headers=CSRF)
                assert resp.status == 401
                resp = await h.client.post('/login', data={'login': 'alice', 'password': 'x'}, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'].startswith('/login?error=')
        run(go())


class TestCsrf:
    def test_header_and_origin(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.post('/api/login', json={'display_name': 'x'})
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
                resp = await h.client.post('/api/login', json={'display_name': 'x'},
                                           headers={**CSRF, 'Origin': 'https://evil.example'})
                assert resp.status == 403
                resp = await h.client.post('/api/login', json={'display_name': 'x'},
                                           headers={**CSRF, 'Origin': f'http://{h.client.host}:{h.client.port}'})
                assert resp.status == 200
                resp = await h.client.post('/login', data={'display_name': 'x'}, headers={'Origin': 'https://evil.example'},
                                           allow_redirects=False)
                assert resp.status == 403
        run(go())


class TestProjectsThroughThePortal:
    def test_start_open_use_and_close(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                me = await h.login()
                labs = await (await h.client.get('/api/labs')).json()
                assert {l['name'] for l in labs} == {'sre/dhcp.py', 's4/tp_ssh'}
                result = await h.start()
                assert result['status'] == 'created' and result['host'] == 'a01'
                rln = result['running_lab_name']
                assert rln.endswith('@@@' + me['login'])
                projects = await (await h.client.get('/api/projects')).json()
                assert [(p['host'], p['running_lab_name']) for p in projects] == [('a01', rln)]
                base = f'/api/projects/a01/{rln}'
                data = await (await h.client.get(base)).json()
                assert data['project']['title'] == 'TP DHCP' and data['host'] == 'a01'
                resp = await h.client.get(f'/projects/a01/{rln}')
                assert resp.status == 200 and rln in await resp.text()
                # answers, eval, state, touch, log
                resp = await h.client.put(f'{base}/answers', json={'answers': {TEXT_HASH: 'gw'}}, headers=CSRF)
                assert resp.status == 200 and (await resp.json())['answers'][TEXT_HASH] == 'gw'
                resp = await h.client.post(f'{base}/eval', headers=CSRF)
                assert resp.status == 200 and (await resp.json())['rows']
                resp = await h.client.post(f'{base}/eval', headers=CSRF)
                assert resp.status == 429 and (await resp.json())['retry_after'] > 0
                resp = await h.client.post(f'{base}/states/final', headers=CSRF)
                assert resp.status == 200 and (await resp.json())['answers'][TEXT_HASH] == '42'
                assert (await h.client.post(f'{base}/states/nope', headers=CSRF)).status == 403
                assert (await h.client.post(f'{base}/touch', headers=CSRF)).status == 204
                assert (await h.client.get(f'{base}/log')).status == 403
                import shutil
                if shutil.which('neato'):
                    resp = await h.client.get(f'{base}/schema.svg?curved=1')
                    assert resp.status == 200 and resp.content_type == 'image/svg+xml'
                assert (await h.client.get(f'{base}/save')).status == 404   # not offered on the web
                resp = await h.client.get(f'{base}/export?sep=2')
                assert resp.status == 200 and (await resp.read()).startswith(b'PK')
                # websockets through the relay
                ws = await h.client.ws_connect(f'{base}/events')
                await h.client.post(f'{base}/states/final', headers=CSRF)
                msg = await asyncio.wait_for(ws.receive_json(), 5)
                assert msg['t'] == 'answers'
                await ws.close()
                term = await h.client.ws_connect(f'{base}/terminals/m1?cols=90&rows=20', protocols=(TERMINAL_SUBPROTOCOL,))
                assert term.protocol == TERMINAL_SUBPROTOCOL
                assert (await asyncio.wait_for(term.receive_json(), 5))['t'] == 'ready'
                await term.send_bytes(b'echo hi\n')
                out = b''
                async with asyncio.timeout(10):
                    while b'hi' not in out.split(b'echo hi')[-1]:
                        msg = await term.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        out += msg.data
                await term.close()
                assert (await h.client.post('/api/projects/restore', data=b'x', headers=CSRF)).status == 404
                resp = await h.client.delete(base, headers=CSRF)
                assert resp.status == 200
                await asyncio.sleep(0.2)
                assert await (await h.client.get('/api/projects')).json() == []
        run(go())

    def test_ownership_at_the_portal(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                await h.login('A')
                rln = (await h.start())['running_lab_name']
                h.client.session.cookie_jar.clear()
                await h.login('B')
                assert (await h.client.get(f'/api/projects/a01/{rln}')).status == 403
                assert (await h.client.get(f'/projects/a01/{rln}')).status == 403
                assert (await h.client.get('/api/projects/a01/junk')).status == 404
                assert (await h.client.get(f'/api/projects/nohost/{rln}')).status == 404
                assert await (await h.client.get('/api/projects')).json() == []
                assert (await h.client.get('/api/pool')).status == 403
        run(go())

    def test_flavor_form_round_trip(self, tmp_path):
        async def go():
            async with Harness(tmp_path, mock_env={'MOCK_FLAVOR_FORM': 'N: @@{nb:[0-9]+}@@'}) as h:
                await h.login()
                result = await h.start()
                assert result['status'] == 'flavor_form' and result['chunks'][1]['name'] == 'nb'
                h.portal.routes.limiter._last.clear()
                result = await h.start(flavor={'nb': '2'})
                assert result['status'] == 'created'
        run(go())

    def test_pool_full_and_unreachable_host(self, tmp_path):
        async def go():
            async with Harness(tmp_path, hosts=2) as h:
                await h.login()
                await asyncio.sleep(0.3)
                status = h.portal.pool.status
                assert status['a01'].reachable and not status['down'].reachable
                for _ in range(3):
                    h.portal.routes.limiter._last.clear()
                    assert (await h.start())['status'] == 'created'
                    # a poll made after the release of the reservation (a poll started before it and
                    # answered after counts the project twice for one interval)
                    await asyncio.sleep(0.3)
                h.portal.routes.limiter._last.clear()
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers=CSRF)
                assert resp.status == 503
                assert len(await (await h.client.get('/api/projects')).json()) == 3
        run(go())


class TestProxyMode:
    def test_identity_from_the_headers(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                me = who('alice', 'Émile Dupont', 'alice@example.org', f'cn=students,ou=groups,dc=example,dc=org; {TEACHERS}')
                resp = await h.client.get('/api/me', headers=me)
                data = await resp.json()
                assert data['auth_mode'] == 'proxy' and S.COOKIE_NAME not in resp.cookies
                assert data['identity'] == {'login': 'alice', 'fullname': 'Émile Dupont', 'email': 'alice@example.org',
                                            'role': 'instructor', 'language': 'en', 'anonymous': False}
                student = (await (await h.client.get('/api/me', headers=who('bob'))).json())['identity']
                assert student['login'] == 'bob' and student['role'] == 'student' and student['fullname'] == ''
                for path in ('/', '/login'):
                    resp = await h.client.get(path, headers=me, allow_redirects=False)
                    assert resp.status == 302 and resp.headers['Location'] == '/projects'
                resp = await h.client.get('/projects', headers=me)
                assert resp.status == 200 and 'alice' in await resp.text() and not resp.cookies
        run(go())

    def test_without_headers_or_from_an_untrusted_peer(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                assert (await (await h.client.get('/api/me')).json())['identity'] is None
                assert (await h.client.get('/api/projects')).status == 401
                resp = await h.client.get('/', allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/login'
                resp = await h.client.get('/login')
                assert resp.status == 200 and 'proxy' in await resp.text()
                assert not h.portal._proxy_warned
            untrusted = dict(PROXY_OVER, trusted_proxies=['10.0.0.0/8'])
            async with Harness(tmp_path / 'untrusted', web_over=untrusted) as h:
                assert (await (await h.client.get('/api/me', headers=who('alice'))).json())['identity'] is None
                assert (await h.client.get('/api/projects', headers=who('alice'))).status == 401
                assert h.portal._proxy_warned == {('peer', '127.0.0.1')}
        run(go())

    def test_bad_login_and_no_login_endpoints(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                for _ in range(2):
                    assert (await h.client.get('/api/projects', headers=who('../x'))).status == 401
                assert len(h.portal._proxy_warned) == 1
                resp = await h.client.post('/api/login', json={'login': 'alice', 'password': 'x'},
                                           headers={**who('alice'), **CSRF})
                assert resp.status == 403 and 'reverse proxy' in await resp.text()
                resp = await h.client.post('/login', data={'display_name': 'x'}, allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'].startswith('/login?error=')
        run(go())

    def test_language_cookie(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                resp = await h.client.post('/api/language', json={'language': 'fr'}, headers={**who('alice'), **CSRF})
                assert resp.status == 200 and (await resp.json())['identity']['language'] == 'fr'
                assert S.LANG_COOKIE in resp.cookies and S.COOKIE_NAME not in resp.cookies
                me = await (await h.client.get('/api/me', headers=who('alice'))).json()
                assert me['identity']['language'] == 'fr'
                me = await (await h.client.get('/api/me?lang=en', headers=who('alice'))).json()
                assert me['identity']['language'] == 'en'
                resp = await h.client.get('/login')            # no identity: the page in the cookie's language
                assert '<html lang="fr">' in await resp.text()
        run(go())

    def test_logout(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                resp = await h.client.post('/logout', headers=who('alice'), allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/login'
                resp = await h.client.post('/api/logout', headers={**who('alice'), **CSRF})
                assert await resp.json() == {'ok': True, 'logout_url': ''}
            over = dict(PROXY_OVER, auth={'mode': 'proxy', 'proxy': {'logout_url': '/apache-logout'}})
            async with Harness(tmp_path / 'out', web_over=over) as h:
                resp = await h.client.post('/logout', headers=who('alice'), allow_redirects=False)
                assert resp.status == 302 and resp.headers['Location'] == '/apache-logout'
                resp = await h.client.post('/api/logout', headers={**who('alice'), **CSRF})
                assert (await resp.json())['logout_url'] == '/apache-logout'
        run(go())

    def test_stale_session_cookie_is_ignored(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                stale = {S.COOKIE_NAME: S.encode(Identity(login='ghost', anonymous=True), SECRET)}
                assert (await (await h.client.get('/api/me', cookies=stale)).json())['identity'] is None
                me = await (await h.client.get('/api/me', cookies=stale, headers=who('alice'))).json()
                assert me['identity']['login'] == 'alice'
        run(go())

    def test_projects_with_the_proxy_identity(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                alice = who('alice', 'Émile Dupont', 'alice@example.org')
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**alice, **CSRF})
                assert resp.status == 200, await resp.text()
                result = json.loads((await resp.text()).splitlines()[-1])
                assert result['status'] == 'created'
                rln = result['running_lab_name']
                assert rln.endswith('@@@alice')
                base = f'/api/projects/a01/{rln}'
                assert (await h.client.get(base, headers=alice)).status == 200
                resp = await h.client.put(f'{base}/answers', json={'answers': {TEXT_HASH: 'gw'}}, headers={**alice, **CSRF})
                assert resp.status == 200
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert (on_disk['login'], on_disk['fullname'], on_disk['email']) == ('alice', 'Émile Dupont', 'alice@example.org')
                ws = await h.client.ws_connect(f'{base}/events', headers=alice)
                await h.client.post(f'{base}/states/final', headers={**alice, **CSRF})
                assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'answers'
                await ws.close()
                # ownership and the instructor role, at the portal and at the agent
                bob, prof = who('bob'), who('prof', groups=TEACHERS)
                assert (await h.client.get(base, headers=bob)).status == 403
                assert (await h.client.get(f'/projects/a01/{rln}', headers=bob)).status == 403
                assert await (await h.client.get('/api/projects', headers=bob)).json() == []
                assert (await h.client.get('/api/pool', headers=bob)).status == 403
                assert (await h.client.get(base, headers=prof)).status == 200
                assert (await h.client.get('/api/pool', headers=prof)).status == 200
                assert (await h.client.delete(base, headers={**alice, **CSRF})).status == 200
        run(go())


class TestPoolPlacement:
    def test_pick_least_loaded(self):
        hosts = [HostConfig('a', 'http://a', TOKEN, 10), HostConfig('b', 'http://b', TOKEN, 10),
                 HostConfig('c', 'http://c', TOKEN, 10)]
        pool = Pool(hosts, session=None)
        pool.status['a'] = HostStatus(reachable=True, projects=5, load1=1.0)
        pool.status['b'] = HostStatus(reachable=True, projects=2, load1=3.0)
        pool.status['c'] = HostStatus(reachable=True, projects=2, load1=1.0)
        host, reservation = pool.pick()
        assert host.name == 'c' and pool.status['c'].projects == 3
        assert pool.pick()[0].name == 'b'
        # a status polled before the release keeps the reservation, one polled after consumes it
        pool.release(reservation)
        assert pool._consume('c', reservation.released_at - 1) == 1
        assert pool._consume('c', reservation.released_at + 1) == 0
        pool.status['b'] = HostStatus(reachable=True, projects=10)
        pool.status['c'] = HostStatus(reachable=True, projects=10, exam_mode=False)
        pool.status['a'] = HostStatus(reachable=True, projects=1, exam_mode=True)
        with pytest.raises(PoolError) as e:
            pool.pick()
        assert e.value.status == 503


class TestDisplayThroughThePortal:
    """The virtual X desktop: the JSON routes relayed, the RFB WebSocket pumped as it is."""

    @staticmethod
    def display_over(runtime_dir) -> dict:
        script = runtime_dir / 'xvnc'
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{MOCK_XVNC}" "$@"\n')
        script.chmod(0o755)
        return {'display': {'enabled': True, 'user': '', 'xvnc_command': str(script), 'window_manager_command': '',
                            'runtime_dir': str(runtime_dir), 'first_display': 93, 'last_display': 94}}

    def test_display_relayed(self, tmp_path):
        import shutil
        import tempfile
        runtime_dir = Path(tempfile.mkdtemp(prefix='sre-x11-', dir='/tmp'))   # short: an AF_UNIX path

        async def go():
            async with Harness(tmp_path, mock_env={'MOCK_X11': '1'}, agent_over=self.display_over(runtime_dir)) as h:
                await h.login('A')
                rln = (await h.start())['running_lab_name']
                base = f'/api/projects/a01/{rln}'
                project = (await (await h.client.get(base)).json())['project']
                assert project['display'] == {'available': True} and 'display' in project['tabs']
                status = await (await h.client.get(f'{base}/display')).json()
                assert status['available'] is True and status['display'] == 93
                resp = await h.client.post(f'{base}/display', headers=CSRF)
                assert resp.status == 200 and (await resp.json())['running'] is True
                ws = await h.client.ws_connect(f'{base}/display/ws', protocols=(DISPLAY_SUBPROTOCOL,))
                assert ws.protocol == DISPLAY_SUBPROTOCOL
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.BINARY and msg.data == b'RFB 003.008\n'
                await ws.send_bytes(b'\x00\x01\x02')
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.BINARY and msg.data == b'\x00\x01\x02'
                await ws.close()
                h.client.session.cookie_jar.clear()
                await h.login('B')
                assert (await h.client.get(f'{base}/display')).status == 403
                assert (await h.client.post(f'{base}/display', headers=CSRF)).status == 403
                with pytest.raises(aiohttp.WSServerHandshakeError):
                    await h.client.ws_connect(f'{base}/display/ws', protocols=(DISPLAY_SUBPROTOCOL,))
        try:
            run(go())
        finally:
            shutil.rmtree(runtime_dir, ignore_errors=True)


class FakeRoleResolver:
    """The directory of proxy mode's ldap_roles, answering from a dict (or failing)."""

    def __init__(self, roles, fail=False):
        self.roles, self.fail, self.calls = roles, fail, []

    def role_for(self, login):
        self.calls.append(login)
        if self.fail:
            from sreweb.portal.auth_ldap import LdapError
            raise LdapError("directory down")
        return self.roles.get(login, 'student')


class TestInstructorThroughThePortal:
    def test_watch_evaluation_and_instructor_mode(self, tmp_path):
        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=PROXY_OVER) as h:
                alice, bob, prof = who('alice', 'Alice'), who('bob'), who('prof', groups=TEACHERS)
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**alice, **CSRF})
                rln = [json.loads(l) for l in (await resp.text()).splitlines()][-1]['running_lab_name']
                # the watch page and its data: instructors only
                assert (await h.client.get('/watch', headers=bob)).status == 403
                assert (await h.client.get('/api/watch', headers=bob)).status == 403
                assert (await h.client.get('/watch', allow_redirects=False)).status == 302
                page = await h.client.get('/watch', headers=prof)
                assert page.status == 200 and 'prof True' in await page.text()
                rows = await (await h.client.get('/api/watch', headers=prof)).json()
                assert len(rows) == 1 and (rows[0]['host'], rows[0]['owner'], rows[0]['last_eval']) == ('a01', 'alice', None)
                # the instructor's own list stays theirs; the student's list unchanged
                assert await (await h.client.get('/api/projects', headers=prof)).json() == []
                assert [p['running_lab_name'] for p in await (await h.client.get('/api/projects', headers=alice)).json()] == [rln]
                base = f'/api/projects/a01/{rln}'
                assert (await h.client.get(f'{base}/evaluation', headers=alice)).status == 403
                assert (await h.client.get(f'{base}/evaluation', headers=prof)).status == 404
                await h.client.put(f'{base}/answers', json={'answers': {TEXT_HASH: 'gw'}}, headers={**alice, **CSRF})
                assert (await h.client.post(f'{base}/eval', headers={**alice, **CSRF})).status == 200
                rows = await (await h.client.get('/api/watch', headers=prof)).json()
                assert rows[0]['last_eval']['grade'] == 4.5 and rows[0]['fullname'] == 'Alice'
                data = await (await h.client.get(f'{base}/evaluation', headers=prof)).json()
                assert data['mark'] == 18.0 and data['rows'] and data['archive'].endswith('.zst')
                # the instructor evaluates the student's project (privileged on the agent) and reads her answers only
                assert (await h.client.post(f'{base}/eval', headers={**prof, **CSRF})).status == 200
                assert (await h.client.put(f'{base}/answers', json={'answers': {TEXT_HASH: 'x'}},
                                           headers={**prof, **CSRF})).status == 403
                got = await (await h.client.get(base, headers=prof)).json()
                assert got['answers_readonly'] is True and got['owner'] == 'alice'
                # an instructor-mode project of the instructor; refused to a student
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py', 'instructor_mode': True},
                                           headers={**bob, **CSRF})
                assert resp.status == 403
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py', 'instructor_mode': True},
                                           headers={**prof, **CSRF})
                result = [json.loads(l) for l in (await resp.text()).splitlines()][-1]
                assert result['status'] == 'created' and result['running_lab_name'].endswith('@@@prof')
                view = (await (await h.client.get(f"/api/projects/a01/{result['running_lab_name']}?view=instructor",
                                                  headers=prof)).json())['project']
                assert view['instructor_mode'] and view['instructor_view'] and 'Solution' in view['informations_html']
        run(go())

    def test_join_through_the_portal(self, tmp_path):
        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=PROXY_OVER) as h:
                alice, prof = who('alice'), who('prof', groups=TEACHERS)
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**alice, **CSRF})
                rln = [json.loads(l) for l in (await resp.text()).splitlines()][-1]['running_lab_name']
                base = f'/api/projects/a01/{rln}'
                term = await h.client.ws_connect(f'{base}/terminals/m1', headers=alice, protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(term.receive_json(), 5)
                sid = ready['session']
                joined = await h.client.ws_connect(f'{base}/terminals/m1?join={sid}&cols=90&rows=20', headers=prof,
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(joined.receive_json(), 5)
                assert ready['t'] == 'ready' and ready['session'] == sid and ready['clients'] == 2 and ready['joined']
                private = await h.client.ws_connect(f'{base}/terminals/m2?private=1', headers=prof,
                                                    protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(private.receive_json(), 5))['t'] == 'ready'
                listed = (await (await h.client.get(base, headers=alice)).json())['terminals']
                assert [t['id'] for t in listed] == [sid]              # the private one is not hers to see
                for ws in (private, joined, term):
                    await ws.close()
        run(go())

    def test_ldap_roles_in_proxy_mode(self, tmp_path):
        over = {'auth': {'mode': 'proxy', 'proxy': {'ldap_roles': True, 'ldap_roles_ttl': '10m',
                                                     'instructor_header': 'X-Remote-Gid', 'instructor_values': ['2000']},
                         'ldap': {'uri': 'ldaps://ldap.example.org', 'search_base': 'ou=people,dc=example,dc=org'}},
                'trusted_proxies': ['127.0.0.1', '::1']}

        async def go():
            resolver = FakeRoleResolver({'zoe': 'instructor'})
            async with Harness(tmp_path, auth_mode='proxy', web_over=over, role_resolver=resolver) as h:
                me = await (await h.client.get('/api/me', headers=who('zoe'))).json()
                assert me['identity']['role'] == 'instructor'
                await h.client.get('/api/me', headers=who('zoe'))
                assert resolver.calls == ['zoe']                          # cached
                assert (await (await h.client.get('/api/me', headers=who('bob'))).json())['identity']['role'] == 'student'
                # the header test comes first: no lookup for a header-granted role
                me = await (await h.client.get('/api/me', headers={**who('ann'), 'X-Remote-Gid': '2000'})).json()
                assert me['identity']['role'] == 'instructor' and 'ann' not in resolver.calls
            resolver = FakeRoleResolver({'zoe': 'instructor'}, fail=True)
            async with Harness(tmp_path / 'b', auth_mode='proxy', web_over=over, role_resolver=resolver) as h:
                me = await (await h.client.get('/api/me', headers=who('zoe'))).json()
                assert me['identity']['role'] == 'student'              # the site stays up without the directory
                assert (await h.client.get('/projects', headers=who('zoe'))).status == 200
        run(go())
