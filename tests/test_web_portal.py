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
from sreweb.portal.accesslog import parse_line, ALL_EVENTS
from sreweb.portal.ratelimit import RateLimiter
from sreweb.portal.app import Portal
from sreweb.portal.pool import Pool, PoolError, HostStatus
from sreweb.config import HostConfig
from test_agent_api import display_user                      # noqa: E402  (the [display] user as root)

MOCK = Path(__file__).parent / 'mock_sre.py'
MOCK_XVNC = Path(__file__).parent / 'mock_xvnc.py'
TOKEN = 't' * 32
SECRET = 's' * 32
CSRF = {S.CSRF_HEADER: S.CSRF_VALUE}
TEXT_HASH = 'cfc140584d209e6d8ed82f6db72c91a210cb1f2ded6a6b66f81c17e16ac2b857'
TEACHERS = 'cn=teachers,ou=groups,dc=example,dc=org'
# proxy mode: the test client is the trusted peer (TestServer binds 127.0.0.1); web_over replaces the whole auth dict
PROXY_OVER = {'auth': {'mode': 'proxy', 'proxy': {'instructor_groups': [TEACHERS], 'header_group': 'X-Remote-Group'}},
              'trusted_proxies': ['127.0.0.1', '::1']}

TEMPLATES = {
    'login.html': '<html lang="{{ language }}"><title>Login</title>{{ auth_mode }} {{ error }}'
                  '{% for code, name in languages %}<option>{{ code }}</option>{% endfor %}'
                  '{% if site.logo_url %}<img src="{{ site.logo_url }}">{% endif %}[{{ site.name }}]</html>',
    'projects.html': '<html><title>Projects</title>{{ identity.login }}</html>',
    'open.html': '<html><title>Open</title>{{ identity.login }}</html>',
    'project.html': '<html><title>Project</title>{{ host }} {{ rln }} {{ api_base }} {{ _("Schema") }}</html>',
    'watch.html': '<html><title>Watch</title>{{ identity.login }} {{ instructor }} {{ groups }}</html>',
    'pool.html': '<html><title>Pool</title>{{ identity.login }} {{ instructor }}</html>',
    'history.html': '<html><title>History</title>{{ identity.login }} {{ administrator }} {{ history_database }} '
                    '{{ events | length }}</html>',
}


def run(coro):
    return asyncio.run(coro)


def who(login, fullname='', email='', groups='', group='') -> dict:
    """The identity headers Apache sets in proxy mode (the defaults of [auth.proxy], and the
    X-Remote-Group of PROXY_OVER)."""
    return {'X-Remote-User': login, 'X-Remote-Name': fullname, 'X-Remote-Email': email, 'X-Remote-Groups': groups,
            'X-Remote-Group': group}


class Harness:
    """A real agent on the fake sre, and a portal whose only host is that agent."""

    def __init__(self, tmp_path, *, auth_mode='anonymous', mock_env=None, web_over=None, hosts=1, agent_over=None,
                 role_resolver=None, host_over=None, db_connect=None):
        self.tmp = tmp_path
        self.role_resolver = role_resolver
        self.db_connect = db_connect           # the (connect, transient) pair of a fake access database
        self.host_over = host_over or {}       # merged into the [[hosts]] entry of the agent (a01)
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
        # never the unit the test process may run in (a CI runner): a restart needs restart_command here
        self.agent.cgroup_file = str(tmp_path / 'no-cgroup')
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
        hosts = [{'name': 'a01', 'url': url, 'token': TOKEN, 'max_projects': 3, **self.host_over}]
        if self.hosts > 1:
            hosts.append({'name': 'down', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'max_projects': 3})
        cfg = web_config_from_dict({'secret': SECRET, 'auth': {'mode': self.auth_mode},
                                    'pool': {'poll_interval': 0.1}, 'hosts': hosts, **self.web_over})
        self.portal = Portal(cfg, web_dir=str(self.web_dir), localedirs=[], role_resolver=self.role_resolver,
                             db_connect=self.db_connect)
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

    async def start_refused(self, lab='sre/dhcp.py', **body) -> tuple:
        """A start the portal refuses before the relay: (status, the JSON error)."""
        resp = await self.client.post('/api/projects', json={'lab': lab, **body}, headers=CSRF)
        assert resp.status != 200, await resp.text()
        return resp.status, await resp.json()


class TestRateLimiter:
    def test_take_and_give_back(self):
        rl = RateLimiter()
        assert rl.take_every('start', 'a', 30, now=100) == (0.0, None)
        assert rl.take_every('start', 'a', 30, now=110) == (20.0, None)    # refused: nothing to give back
        rl.give_back('start', 'a', None)                                  # the take of 100, undone
        assert rl.allow_every('start', 'a', 30, now=110) == 0
        wait, previous = rl.take_every('start', 'a', 30, now=150)
        assert (wait, previous) == (0.0, 110)
        rl.give_back('start', 'a', previous)                              # back to the stamp of 110
        assert rl.allow_every('start', 'a', 30, now=130) == 10
        assert rl.allow_every('start', 'b', 30, now=130) == 0             # another key


class TestSessionCookie:
    def test_round_trip_and_forgery(self):
        me = Identity(login='alice', fullname='Alice', email='a@x', language='fr', anonymous=True, group='INFO1')
        value = S.encode(me, SECRET, now=1000)
        assert S.decode(value, SECRET, now=2000) == me
        assert S.decode(value, SECRET, now=2000).group == 'INFO1'
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
                resp = await h.client.get('/static/x.css')
                assert resp.status == 200 and resp.headers['Cache-Control'] == 'no-cache'   # revalidated on every load
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
                    resp = await h.client.get(f'{base}/schema.pdf?sep=2&order=reverse')
                    assert resp.status == 200 and resp.content_type == 'application/pdf'
                    assert (await resp.read()).startswith(b'%PDF')
                    assert resp.headers['Content-Disposition'].endswith('_schema.pdf"')   # copied by the relay
                assert (await h.client.get(f'{base}/save')).status == 404     # not offered on the web
                assert (await h.client.get(f'{base}/export')).status == 404   # the Kathara export neither
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
                # the form fetch gave the start slot back: the start with the answers comes at once
                result = await h.start(flavor={'nb': '2'})
                assert result['status'] == 'created'
                status, error = await h.start_refused(flavor={'nb': '2'})   # a real start took the slot
                assert status == 429 and error['retry_after'] > 0
        run(go())

    def test_flavor_refused_gives_the_start_slot_back(self, tmp_path):
        async def go():
            env = {'MOCK_FLAVOR_FORM': 'N: @@{nb:[0-9]+}@@', 'MOCK_FLAVOR_REFUSE': 'too many'}
            async with Harness(tmp_path, mock_env=env) as h:
                await h.login()
                assert (await h.start())['status'] == 'flavor_form'
                assert (await h.start(flavor={'nb': '9'}))['status'] == 'flavor_error'
                assert (await h.start(flavor={'nb': '1'}))['status'] == 'flavor_error'   # corrected at once, not 429
                assert not h.portal.routes.limiter._last                                # no slot kept
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
                # a refused placement gives the start slot back: the retry is refused by the pool again, not 429
                status, error = await h.start_refused()
                assert status == 503 and error['retry_after'] == 60
                assert len(await (await h.client.get('/api/projects')).json()) == 3
        run(go())


class TestAccessLog:
    """The connection log ([access_log]) of a real portal: the lines of a whole session."""

    @staticmethod
    def over(tmp_path, **more) -> dict:
        return {'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False, **more}}

    @staticmethod
    def lines(tmp_path) -> list:
        return [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]

    async def wait_event(self, tmp_path, event: str) -> dict:
        """The WebSocket close lines are written when the server side of the socket ends, a
        moment after the client's close() returns."""
        async with asyncio.timeout(5):
            while True:
                for line in reversed(self.lines(tmp_path)):
                    if line['event'] == event:
                        return line
                await asyncio.sleep(0.02)

    def test_full_flow(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=self.over(tmp_path)) as h:
                me = await h.login('Alice Test')
                rln = (await h.start())['running_lab_name']
                base = f'/api/projects/a01/{rln}'
                assert (await h.client.get('/api/projects')).status == 200            # polls: not counted
                assert (await h.client.post(f'{base}/touch', headers=CSRF)).status == 204
                assert (await h.client.get(f'/projects/a01/{rln}')).status == 200   # counted, no event
                assert (await h.client.get('/static/x.css')).status == 200            # ignored
                ws = await h.client.ws_connect(f'{base}/events')
                await ws.close()
                await self.wait_event(tmp_path, 'project_close')
                term = await h.client.ws_connect(f'{base}/terminals/m1?cols=90&rows=20', protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(term.receive_json(), 5))['t'] == 'ready'
                await term.close()
                await self.wait_event(tmp_path, 'terminal_close')
                assert (await h.client.post(f'{base}/eval', headers=CSRF)).status == 200
                assert (await h.client.post(f'{base}/states/final', headers=CSRF)).status == 200
                assert (await h.client.post(f'{base}/states/nope', headers=CSRF)).status == 403
                assert (await h.client.get('/api/pool')).status == 403                # denied, no event
                assert (await h.client.delete(base, headers=CSRF)).status == 200
                assert (await h.client.post('/api/logout', headers=CSRF)).status == 200
                assert (await h.client.get('/api/projects')).status == 401            # denied, nobody
                return me['login'], rln
        login, rln = run(go())
        lines = self.lines(tmp_path)
        assert [l['event'] for l in lines] == [
            'login', 'session_open', 'start', 'project_open', 'project_close', 'terminal_open', 'terminal_close',
            'eval', 'state', 'state', 'denied', 'stop', 'logout', 'session_close', 'denied']
        for line in lines[:-1]:
            assert line['login'] == login and line['addr'] == '127.0.0.1', line
        assert lines[0]['mode'] == 'anonymous' and lines[0]['anon'] == '1' and lines[0]['name'] == 'Alice Test'
        assert lines[1]['role'] == 'student' and lines[1]['ua'].startswith('Python/')
        start = lines[2]
        assert (start['lab'], start['instructor'], start['host'], start['placement'], start['result'], start['rln'],
                start['status']) == ('sre/dhcp.py', '0', 'a01', 'load', 'created', rln, '200')
        assert float(start['duration']) >= 0
        assert lines[3] == dict(ts=lines[3]['ts'], event='project_open', login=login, addr='127.0.0.1', host='a01', rln=rln)
        assert lines[4]['code'] == '1000' and float(lines[4]['duration']) >= 0
        assert (lines[5]['device'], lines[5]['join'], lines[5]['private']) == ('m1', '', '0')
        assert lines[6]['code'] == '1000' and lines[6]['device'] == 'm1'
        assert (lines[7]['status'], lines[8]['state'], lines[8]['status'], lines[9]['state'], lines[9]['status']) == \
               ('200', 'final', '200', 'nope', '403')
        assert lines[10] == dict(ts=lines[10]['ts'], event='denied', login=login, addr='127.0.0.1', method='GET',
                                 path='/api/pool', status='403')
        assert lines[11]['rln'] == rln and lines[11]['status'] == '200'
        assert lines[12]['status'] == '200'
        close = lines[13]
        # login, start, page, 2 sockets, eval, 2 states, stop, logout; not the polls (projects, pool), the
        # touch, the static file
        assert (close['reason'], close['requests'], close['projects']) == ('logout', '10', rln)
        assert close['since'][:2] == '20' and int(close['duration']) < 60
        assert lines[14] == dict(ts=lines[14]['ts'], event='denied', login='', addr='127.0.0.1', method='GET',
                                 path='/api/projects', status='401')

    def test_shutdown_closes_the_sessions(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=self.over(tmp_path)) as h:
                await h.login('A')
                h.client.session.cookie_jar.clear()
                await h.login('B')
        run(go())
        lines = self.lines(tmp_path)
        assert [l['event'] for l in lines] == ['login', 'session_open', 'login', 'session_open', 'session_close',
                                               'session_close']
        assert {l['reason'] for l in lines[4:]} == {'shutdown'} and {l['requests'] for l in lines[4:]} == {'1'}

    def test_idle_expiry(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=self.over(tmp_path, session_timeout='10m')) as h:
                access = h.portal.access
                assert access.period == 60.0 and access._task is not None
                await h.login('A')
                t0 = access.clock()
                access.clock = lambda: t0 + 700
                access.expire()
                assert [l['event'] for l in self.lines(tmp_path)][-1] == 'session_close'
                # a session with an open WebSocket (the project page) never expires
                h.client.session.cookie_jar.clear()      # else the login of B is a request of A's session
                await h.login('B')
                rln = (await h.start())['running_lab_name']
                ws = await h.client.ws_connect(f'/api/projects/a01/{rln}/events')
                access.clock = lambda: t0 + 1400
                access.expire()
                assert [l['event'] for l in self.lines(tmp_path)][-1] == 'project_open'
                await ws.close()
                await self.wait_event(tmp_path, 'project_close')
                access.expire()                      # active until the socket closed
                assert [l['event'] for l in self.lines(tmp_path)][-1] == 'project_close'
                access.clock = lambda: t0 + 2100
                access.expire()
                return rln
        rln = run(go())
        lines = self.lines(tmp_path)
        assert [l['event'] for l in lines] == ['login', 'session_open', 'session_close', 'login', 'session_open', 'start',
                                               'project_open', 'project_close', 'session_close']
        assert lines[2]['reason'] == 'idle' and int(lines[2]['duration']) < 5
        assert (lines[8]['reason'], lines[8]['duration'], lines[8]['projects'], lines[8]['requests']) == \
               ('idle', '700', rln, '3')

    def test_client_address_behind_a_trusted_proxy(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over={**PROXY_OVER, **self.over(tmp_path)}) as h:
                headers = {**who('alice', 'Alice'), 'X-Forwarded-For': '1.2.3.4, 10.0.1.7'}
                assert (await h.client.get('/api/projects', headers=headers)).status == 200
                assert (await h.client.get('/api/projects', headers=who('alice'))).status == 200   # the peer itself
                resp = await h.client.post('/api/logout', headers={**headers, **CSRF})
                assert resp.status == 200
                assert (await h.client.get('/projects', headers=headers)).status == 200     # proxy mode: a new session
            lines = self.lines(tmp_path)
            assert [(l['event'], l['addr']) for l in lines] == [
                ('session_open', '10.0.1.7'), ('session_open', '127.0.0.1'), ('logout', '10.0.1.7'),
                ('session_close', '10.0.1.7'), ('session_open', '10.0.1.7'),
                ('session_close', '127.0.0.1'), ('session_close', '10.0.1.7')]
            assert lines[0]['name'] == 'Alice' and lines[0]['role'] == 'student' and lines[0]['anon'] == '0'
            assert lines[3]['reason'] == 'logout' and lines[3]['requests'] == '1' and lines[5]['reason'] == 'shutdown'
            # without trusted proxies the header is ignored
            async with Harness(tmp_path / 'anon', web_over=self.over(tmp_path / 'anon')) as h:
                resp = await h.client.post('/api/login', json={'display_name': 'x'},
                                           headers={**CSRF, 'X-Forwarded-For': '10.0.1.7'})
                assert resp.status == 200
            assert [l['addr'] for l in self.lines(tmp_path / 'anon')] == ['127.0.0.1'] * 3
        run(go())

    def test_login_failures(self, tmp_path):
        async def go():
            over = {'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldap://127.0.0.1:1', 'bind_dn_template': 'uid={login},dc=x',
                                                     'timeout': 1}}, **self.over(tmp_path)}
            async with Harness(tmp_path, auth_mode='ldap', web_over=over) as h:
                resp = await h.client.post('/api/login', json={'login': 'alice', 'password': 'x'}, headers=CSRF)
                assert resp.status in (502, 401)
                resp = await h.client.post('/login', data={'login': '../x', 'password': 'x'}, allow_redirects=False)
                assert resp.status == 302
                statuses = set()
                for _ in range(6):
                    resp = await h.client.post('/api/login', json={'login': 'bob', 'password': 'x'}, headers=CSRF)
                    statuses.add(resp.status)
                assert 429 in statuses
            lines = self.lines(tmp_path)
            assert {l['event'] for l in lines} == {'login_failed'}
            assert lines[0]['login'] == 'alice' and lines[0]['reason'] in ('directory', 'password')
            assert lines[1]['login'] == '../x' and lines[1]['reason'] in ('directory', 'password')
            assert lines[-1] == dict(ts=lines[-1]['ts'], event='login_failed', login='bob', addr='127.0.0.1',
                                     reason='rate_limited')
            async with Harness(tmp_path / 'proxy', web_over={**PROXY_OVER, **self.over(tmp_path / 'proxy')}) as h:
                resp = await h.client.post('/api/login', json={'login': 'alice', 'password': 'x'},
                                           headers={**who('alice'), **CSRF})
                assert resp.status == 403
            lines = self.lines(tmp_path / 'proxy')
            assert [(l['event'], l.get('reason'), l['login']) for l in lines] == [
                ('session_open', None, 'alice'), ('login_failed', 'proxy_mode', 'alice'), ('session_close', 'shutdown', 'alice')]
        run(go())


class TestProxyMode:
    def test_identity_from_the_headers(self, tmp_path):
        async def go():
            async with Harness(tmp_path, web_over=PROXY_OVER) as h:
                me = who('alice', 'Émile Dupont', 'alice@example.org', f'cn=students,ou=groups,dc=example,dc=org; {TEACHERS}',
                         group='INFO1')
                resp = await h.client.get('/api/me', headers=me)
                data = await resp.json()
                assert data['auth_mode'] == 'proxy' and S.COOKIE_NAME not in resp.cookies
                assert data['identity'] == {'login': 'alice', 'fullname': 'Émile Dupont', 'email': 'alice@example.org',
                                            'role': 'instructor', 'language': 'en', 'anonymous': False, 'group': 'INFO1',
                                            'administrator': False}
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

    def test_instructors_only_host(self, tmp_path):
        """A host reserved for instructors: no student's project, no lab list for them; an
        instructor is placed there by the automatic rule or by naming it."""
        async def go():
            over = {**PROXY_OVER, 'limits': {'start_interval': 0}}
            async with Harness(tmp_path, web_over=over, hosts=2, host_over={'instructors_only': True}) as h:
                bob, alice = who('bob'), who('alice', 'Alice', '', TEACHERS)
                assert await (await h.client.get('/api/labs', headers=bob)).json() == []
                labs = await (await h.client.get('/api/labs', headers=alice)).json()
                assert {l['name'] for l in labs} == {'sre/dhcp.py', 's4/tp_ssh'}
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**bob, **CSRF})
                assert resp.status == 503 and 'no host' in (await resp.json())['error']
                assert (await resp.json())['retry_after'] == 60
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py', 'host': 'a01'},
                                           headers={**bob, **CSRF})
                assert resp.status == 403
                for host, status, fragment in ((5, 400, 'host name'), ('nope', 404, 'unknown host'),
                                               ('down', 503, 'not available')):
                    resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py', 'host': host},
                                               headers={**alice, **CSRF})
                    assert resp.status == status and fragment in (await resp.json())['error'], host
                for body in ({'lab': 'sre/dhcp.py'}, {'lab': 'sre/dhcp.py', 'host': 'a01'}, {'lab': 'sre/dhcp.py', 'host': ''}):
                    resp = await h.client.post('/api/projects', json=body, headers={**alice, **CSRF})
                    assert resp.status == 200, await resp.text()
                    result = json.loads((await resp.text()).splitlines()[-1])
                    assert result['status'] == 'created' and result['host'] == 'a01', body
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=alice)).json()}
                assert rows['a01']['instructors_only'] is True and rows['down']['instructors_only'] is False
                assert await (await h.client.get('/api/projects', headers=bob)).json() == []
                assert len(await (await h.client.get('/api/projects', headers=alice)).json()) == 3
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
                alice = who('alice', 'Émile Dupont', 'alice@example.org', group='INFO1')
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
                assert (on_disk['login'], on_disk['fullname'], on_disk['email'], on_disk['group']) == \
                    ('alice', 'Émile Dupont', 'alice@example.org', 'INFO1')
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
        return {'display': {'enabled': True, 'user': display_user(runtime_dir), 'xvnc_command': str(script),
                            'window_manager_command': '', 'runtime_dir': str(runtime_dir), 'first_display': 93,
                            'last_display': 94}}

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
    """The directory of proxy mode's ldap_roles, answering from dicts (or failing)."""

    def __init__(self, roles, fail=False, groups=None, administrators=None, fullnames=None):
        self.roles, self.fail, self.calls, self.groups = roles, fail, [], groups or {}
        self.administrators = set(administrators or ())
        self.fullnames = fullnames or {}

    def resolve(self, login):
        from sreweb.portal.auth_ldap import DirectoryLookup, LdapError
        self.calls.append(login)
        if self.fail:
            raise LdapError("directory down")
        return DirectoryLookup(self.roles.get(login, 'student'), self.groups.get(login, ''), login in self.administrators,
                               self.fullnames.get(login, ''))


class TestInstructorThroughThePortal:
    def test_watch_evaluation_and_instructor_mode(self, tmp_path):
        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=PROXY_OVER) as h:
                alice, bob, prof = who('alice', 'Alice', group='INFO1'), who('bob'), who('prof', groups=TEACHERS)
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**alice, **CSRF})
                rln = [json.loads(l) for l in (await resp.text()).splitlines()][-1]['running_lab_name']
                # the watch page and its data: instructors only
                assert (await h.client.get('/watch', headers=bob)).status == 403
                assert (await h.client.get('/api/watch', headers=bob)).status == 403
                assert (await h.client.get('/watch', allow_redirects=False)).status == 302
                page = await h.client.get('/watch', headers=prof)
                assert page.status == 200 and 'prof True True' in await page.text()   # a group source is configured
                rows = await (await h.client.get('/api/watch', headers=prof)).json()
                assert len(rows) == 1 and (rows[0]['host'], rows[0]['owner'], rows[0]['last_eval']) == ('a01', 'alice', None)
                # the owner's name and group from the start, before any answer
                assert (rows[0]['fullname'], rows[0]['group']) == ('Alice', 'INFO1')
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
                # the lab summary: every project of the lab on every host with its last elements
                assert (await h.client.get('/api/watch/evaluations?lab=sre@dhcp.py', headers=bob)).status == 403
                assert (await h.client.get('/api/watch/evaluations', headers=prof)).status == 400
                rows = await (await h.client.get('/api/watch/evaluations?lab=sre@dhcp.py', headers=prof)).json()
                assert [(r['host'], r['owner'], r['group'], r['last_eval']['grade'], len(r['elements'])) for r in rows] == \
                    [('a01', 'alice', 'INFO1', 4.5, 3)]
                assert await (await h.client.get('/api/watch/evaluations?lab=none/x.py', headers=prof)).json() == []
                # the instructor evaluates the student's project (privileged on the agent) and writes
                # her answers (her file, her metadata kept: the Watch page still names her)
                assert (await h.client.post(f'{base}/eval', headers={**prof, **CSRF})).status == 200
                assert (await h.client.put(f'{base}/answers', json={'answers': {TEXT_HASH: 'x'}},
                                           headers={**prof, **CSRF})).status == 200
                got = await (await h.client.get(base, headers=prof)).json()
                assert got['owner'] == 'alice' and got['answers'][TEXT_HASH] == 'x' and 'answers_readonly' not in got
                assert got['fullname'] == 'Alice'   # the student's name in the title of the instructor's page
                assert (await (await h.client.get(base, headers=alice)).json())['answers'][TEXT_HASH] == 'x'
                rows = await (await h.client.get('/api/watch', headers=prof)).json()
                assert (rows[0]['owner'], rows[0]['fullname']) == ('alice', 'Alice')
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
        with_group = {**over, 'auth': {**over['auth'], 'ldap': {**over['auth']['ldap'], 'attr_group': 'departmentNumber'},
                                       'proxy': {**over['auth']['proxy'], 'header_group': 'X-Remote-Group'}}}

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
                assert (await h.client.get('/watch', headers=who('zoe'))).status == 200
                assert 'zoe True False' in await (await h.client.get('/watch', headers=who('zoe'))).text()   # no group source
            # the lookup also reads the group (attr_group): then it runs for a header-made instructor too
            resolver = FakeRoleResolver({'zoe': 'instructor'}, groups={'zoe': 'INFO2', 'ann': 'INFO3', 'bob': 'INFO1'})
            async with Harness(tmp_path / 'g', auth_mode='proxy', web_over=with_group, role_resolver=resolver) as h:
                me = (await (await h.client.get('/api/me', headers=who('zoe'))).json())['identity']
                assert (me['role'], me['group']) == ('instructor', 'INFO2')
                me = (await (await h.client.get('/api/me', headers={**who('ann'), 'X-Remote-Gid': '2000'})).json())['identity']
                assert (me['role'], me['group']) == ('instructor', 'INFO3') and 'ann' in resolver.calls
                me = (await (await h.client.get('/api/me', headers=who('bob', group='HDR'))).json())['identity']
                assert (me['role'], me['group']) == ('student', 'HDR')           # the header's value wins
                assert 'zoe True True' in await (await h.client.get('/watch', headers=who('zoe'))).text()
            resolver = FakeRoleResolver({'zoe': 'instructor'}, fail=True)
            async with Harness(tmp_path / 'b', auth_mode='proxy', web_over=with_group, role_resolver=resolver) as h:
                me = (await (await h.client.get('/api/me', headers=who('zoe'))).json())['identity']
                assert (me['role'], me['group']) == ('student', '')      # the site stays up without the directory
                assert (await h.client.get('/projects', headers=who('zoe'))).status == 200
                me = (await (await h.client.get('/api/me', headers={**who('ann'), 'X-Remote-Gid': '2000'})).json())['identity']
                assert (me['role'], me['group']) == ('instructor', '')   # never demoted by a directory failure
        run(go())

    def test_ldap_groups_in_proxy_mode(self, tmp_path):
        """ldap_groups alone: the directory gives the group (never the role) of a user whose header
        carries none, and the group of the owners the Watch rows lack (the Qt GUI projects)."""
        over = {'auth': {'mode': 'proxy', 'proxy': {'ldap_groups': True, 'header_group': 'X-Remote-Group',
                                                     'instructor_header': 'X-Remote-Gid', 'instructor_values': ['2000']},
                         'ldap': {'uri': 'ldaps://ldap.example.org', 'search_base': 'ou=people,dc=example,dc=org',
                                  'attr_group': 'departmentNumber'}},
                'trusted_proxies': ['127.0.0.1', '::1']}

        async def go():
            resolver = FakeRoleResolver({'zoe': 'instructor'}, groups={'zoe': 'INFO9', 'alice': 'INFO1'},
                                        fullnames={'alice': 'Alice Dupont'})
            async with Harness(tmp_path, auth_mode='proxy', web_over=over, role_resolver=resolver) as h:
                me = (await (await h.client.get('/api/me', headers=who('zoe'))).json())['identity']
                assert (me['role'], me['group']) == ('student', 'INFO9')          # the group, never the role
                zoe = {**who('zoe'), 'X-Remote-Gid': '2000'}
                me = (await (await h.client.get('/api/me', headers=zoe)).json())['identity']
                assert (me['role'], me['group']) == ('instructor', 'INFO9') and resolver.calls == ['zoe']   # cached
                me = (await (await h.client.get('/api/me', headers=who('bob', group='HDR'))).json())['identity']
                assert (me['role'], me['group']) == ('student', 'HDR') and 'bob' not in resolver.calls   # no lookup
                assert 'zoe True True' in await (await h.client.get('/watch', headers=zoe)).text()   # a group source
                # a project of alice, whose header has no group: the directory's goes into the metadata
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**who('alice'), **CSRF})
                rln = [json.loads(l) for l in (await resp.text()).splitlines()][-1]['running_lab_name']
                rows = await (await h.client.get('/api/watch', headers=zoe)).json()
                assert (rows[0]['owner'], rows[0]['group']) == ('alice', 'INFO1')
                # the answers file of a Qt GUI project carries no group: the row gets the directory's
                answers_file = h.pub / 'projects' / rln / 'answers' / 'answers.json'
                answers_file.write_text(json.dumps({'login': 'alice', 'fullname': 'Alice', 'hostname': 'pc1'}))
                rows = await (await h.client.get('/api/watch', headers=zoe)).json()
                assert (rows[0]['fullname'], rows[0]['group']) == ('Alice', 'INFO1')   # a managed project keeps its name
                assert resolver.calls.count('alice') == 1                           # one lookup, cached
                rows = await (await h.client.get('/api/watch/evaluations?lab=sre@dhcp.py', headers=zoe)).json()
                assert (rows[0]['owner'], rows[0]['group'], rows[0]['elements']) == ('alice', 'INFO1', None)
                assert resolver.calls.count('alice') == 1
                # a project of the Qt GUI (not managed by the agent): the directory's full name, not the
                # GECOS one of the answers file, on the Watch rows and in the lab summary
                answers_file.write_text(json.dumps({'login': 'alice', 'fullname': 'alice dupont', 'hostname': 'pc1'}))
                (h.pub / 'web-agent' / f'{rln}.json').unlink(missing_ok=True)
                h.agent.registry.projects[rln].managed = False
                rows = await (await h.client.get('/api/watch', headers=zoe)).json()
                assert (rows[0]['fullname'], rows[0]['group'], rows[0]['managed']) == ('Alice Dupont', 'INFO1', False)
                rows = await (await h.client.get('/api/watch/evaluations?lab=sre@dhcp.py', headers=zoe)).json()
                assert (rows[0]['fullname'], rows[0]['group'], rows[0]['managed']) == ('Alice Dupont', 'INFO1', False)
                assert resolver.calls.count('alice') == 1                           # still the cached lookup
        run(go())

    def test_complete_owners(self):
        """The Watch rows without a group: the directory's group by owner login, one lookup per
        login, nothing for an unknown login, an invalid login or a row with a group.  The rows
        of the projects the agent does not manage (the Qt GUI, whose answers file carries the
        GECOS name): the directory's full name whatever the group; a managed row, a row without
        the key and the owner the directory names not keep theirs."""
        from sreweb.portal.roles import RoleCache, complete_owners
        resolver = FakeRoleResolver({}, groups={'alice': 'INFO1'}, fullnames={'alice': 'Alice Dupont', 'carl': 'Carl'})
        cache = RoleCache(resolver, ttl=600)
        rows = [{'owner': 'alice', 'group': ''}, {'owner': 'alice'}, {'owner': 'bob', 'group': ''},
                {'owner': 'carl', 'group': 'KEEP'}, {'owner': '../x', 'group': ''}, {}]
        assert run(complete_owners(rows, cache)) is rows
        assert [r.get('group') for r in rows] == ['INFO1', 'INFO1', '', 'KEEP', '', None]
        assert all('fullname' not in r for r in rows)                   # managed rows: no name added
        assert sorted(resolver.calls) == ['alice', 'bob']
        rows = [{'owner': 'alice', 'group': '', 'fullname': 'alice dupont', 'managed': False},
                {'owner': 'alice', 'group': 'INFO1', 'fullname': 'alice dupont', 'managed': False},
                {'owner': 'alice', 'group': 'INFO1', 'fullname': 'alice dupont', 'managed': True},
                {'owner': 'alice', 'group': 'INFO1', 'fullname': 'alice dupont'},
                {'owner': 'bob', 'group': '', 'fullname': 'bob', 'managed': False},
                {'owner': 'carl', 'group': 'KEEP', 'fullname': '', 'managed': False}]
        run(complete_owners(rows, cache))
        assert [r['fullname'] for r in rows] == ['Alice Dupont', 'Alice Dupont', 'alice dupont', 'alice dupont',
                                                 'bob', 'Carl']
        assert [r.get('group') for r in rows] == ['INFO1', 'INFO1', 'INFO1', 'INFO1', '', 'KEEP']
        assert sorted(resolver.calls) == ['alice', 'bob', 'carl']        # alice and bob cached, carl looked up once
        failing = RoleCache(FakeRoleResolver({}, fail=True), ttl=600)
        before = [{'owner': 'alice', 'group': ''}, {'owner': 'alice', 'group': 'G', 'fullname': 'alice', 'managed': False}]
        assert run(complete_owners([dict(r) for r in before], failing)) == before


class TestHistory:
    """The administrators (the instructors of [auth] administrators, of the administrator groups of the
    headers or of the directory) and their History page: the guards, the queries on a fake
    database (test_web_accessdb.FakeServer), the history and denied lines."""
    ADMINS = 'cn=sre-admins,ou=groups,dc=example,dc=org'
    DB = {'host': 'db.example.org', 'user': 'sre_web', 'name': 'sre'}

    def test_administrators_by_login_and_by_header_group(self, tmp_path):
        over = {**PROXY_OVER, 'auth': {**PROXY_OVER['auth'], 'administrators': ['root.prof'],
                                       'proxy': {**PROXY_OVER['auth']['proxy'], 'administrator_groups': [self.ADMINS]}}}

        async def me(h, headers) -> dict:
            return (await (await h.client.get('/api/me', headers=headers)).json())['identity']

        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=over) as h:
                bob, prof = who('bob'), who('prof', groups=TEACHERS)
                root = who('root.prof', groups=TEACHERS)
                by_group = who('ann', groups=f'{TEACHERS}; {self.ADMINS}')
                assert (await me(h, root))['administrator'] is True
                assert (await me(h, prof))['administrator'] is False
                assert (await me(h, by_group))['administrator'] is True
                student = await me(h, who('stu', groups=self.ADMINS))             # in the group, not an instructor
                assert student['role'] == 'student' and student['administrator'] is False
                listed = await me(h, who('root.prof'))                            # listed, not an instructor today
                assert listed['role'] == 'student' and listed['administrator'] is False
                # the page and its API: administrators only
                assert (await h.client.get('/history', allow_redirects=False)).status == 302
                assert (await h.client.get('/history', headers=bob)).status == 403
                assert (await h.client.get('/history', headers=prof)).status == 403
                assert (await h.client.get('/api/history', headers=prof)).status == 403
                assert (await h.client.get('/api/history')).status == 401
                page = await h.client.get('/history', headers=root)
                assert page.status == 200 and 'root.prof True False' in await page.text()   # no database configured
                # the event names of the select: without the login events, never logged in proxy mode
                assert f' {len(ALL_EVENTS) - 2}</html>' in await page.text()
                resp = await h.client.get('/api/history', headers=root)
                assert resp.status == 409 and 'access_log.database' in (await resp.json())['error']
                assert (await h.client.get('/watch', headers=by_group)).status == 200
                assert await (await h.client.get('/api/projects', headers=root)).json() == []  # relayed with the header
        run(go())

    def test_administrators_from_the_directory(self, tmp_path):
        """ldap_groups: the roles stay the headers', the administrator tests of [auth.ldap] run for
        the instructors (once per login, cached) and never make a student an administrator."""
        over = {'auth': {'mode': 'proxy', 'proxy': {'ldap_groups': True, 'header_group': 'X-Remote-Group',
                                                     'instructor_header': 'X-Remote-Gid', 'instructor_values': ['2000']},
                         'ldap': {'uri': 'ldaps://ldap.example.org', 'search_base': 'ou=people,dc=example,dc=org',
                                  'attr_group': 'departmentNumber', 'group_search_base': 'ou=groups,dc=example,dc=org',
                                  'administrator_group_filter': '(&(cn=sre-admins)(memberUid={login}))'}},
                'trusted_proxies': ['127.0.0.1', '::1']}

        async def go():
            resolver = FakeRoleResolver({}, groups={'zoe': 'INFO9'}, administrators={'zoe', 'stu'})
            async with Harness(tmp_path, auth_mode='proxy', web_over=over, role_resolver=resolver) as h:
                zoe = {**who('zoe'), 'X-Remote-Gid': '2000'}
                me = (await (await h.client.get('/api/me', headers=zoe)).json())['identity']
                assert (me['role'], me['group'], me['administrator']) == ('instructor', 'INFO9', True)
                await h.client.get('/api/me', headers=zoe)
                assert resolver.calls == ['zoe']                                      # cached
                me = (await (await h.client.get('/api/me', headers=who('stu', group='HDR'))).json())['identity']
                assert (me['role'], me['administrator']) == ('student', False) and 'stu' not in resolver.calls
                prof = {**who('prof', group='HDR'), 'X-Remote-Gid': '2000'}
                me = (await (await h.client.get('/api/me', headers=prof)).json())['identity']
                assert (me['role'], me['administrator']) == ('instructor', False) and 'prof' in resolver.calls
                page = await h.client.get('/history', headers=zoe)
                assert page.status == 200 and 'zoe True False' in await page.text()
                assert (await h.client.get('/history', headers=prof)).status == 403
            resolver = FakeRoleResolver({}, fail=True, administrators={'zoe'})
            async with Harness(tmp_path / 'down', auth_mode='proxy', web_over=over, role_resolver=resolver) as h:
                me = (await (await h.client.get('/api/me', headers=zoe)).json())['identity']
                assert (me['role'], me['administrator']) == ('instructor', False)      # the directory is down
        run(go())

    def test_ldap_mode_keeps_the_login_events(self, tmp_path):
        """An administrator of LDAP mode (the flag in the cookie): every event in the select."""
        over = {'auth': {'mode': 'ldap', 'ldap': {'uri': 'ldaps://ldap.example.org',
                                                    'search_base': 'ou=people,dc=example,dc=org'}}}

        async def go():
            async with Harness(tmp_path, auth_mode='ldap', web_over=over) as h:
                h.client.session.cookie_jar.update_cookies(
                    {S.COOKIE_NAME: S.encode(Identity(login='prof', role='instructor', administrator=True), SECRET)})
                page = await h.client.get('/history')
                assert page.status == 200 and f'prof True False {len(ALL_EVENTS)}</html>' in await page.text()
                me = (await (await h.client.get('/api/me')).json())['identity']
                assert me['administrator'] is True
                h.client.session.cookie_jar.update_cookies(
                    {S.COOKIE_NAME: S.encode(Identity(login='prof', role='instructor'), SECRET)})
                assert (await h.client.get('/history')).status == 403
        run(go())

    def test_history_from_the_database(self, tmp_path):
        import time
        from test_web_accessdb import FakeServer, Down, NAMES
        from sreweb.portal.accessdb import utc_datetime
        server = FakeServer(table_exists=True)
        over = {**PROXY_OVER, 'auth': {**PROXY_OVER['auth'], 'administrators': ['prof']},
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False, 'database': self.DB}}

        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=over, db_connect=(server.connect, (Down,))) as h:
                access = h.portal.access
                assert access.db is not None and 'database sre on db.example.org' in access.describe()
                prof, bob = who('prof', groups=TEACHERS), who('bob')
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers={**bob, **CSRF})
                assert resp.status == 200 and (await resp.text())          # the start line comes after the stream
                assert (await h.client.get('/history', headers=bob)).status == 403
                assert access.db.flush(5)
                events = [row[1] for row in server.committed]
                assert events[:2] == ['session_open', 'start'] and 'denied' in events
                assert server.committed[1][2:5] == ('bob', '127.0.0.1', 'a01') and server.committed[1][6] == 'sre/dhcp.py'
                # the reader answers what the fake server scripts: the three newest rows, as ORDER BY id DESC
                rows = [(i + 1, *row) for i, row in enumerate(server.committed)]
                server.select_names = NAMES
                server.select_rows = rows[::-1][:3]
                page = await (await h.client.get('/api/history?login=bob&event=start,stop&limit=2', headers=prof)).json()
                assert page['limit'] == 2 and page['more'] is True and len(page['rows']) == 2
                assert page['rows'][0]['id'] == rows[-1][0] and isinstance(page['rows'][0]['ts'], float)
                assert page['rows'][0]['details'] and page['database']['connected'] is True
                kind, sql, args = next(s for s in reversed(server.statements) if s[1].startswith('SELECT id'))
                assert "login LIKE %s ESCAPE '!'" in sql and 'event IN (%s, %s)' in sql and args == ['bob%', 'start', 'stop', 3]
                assert (await h.client.get('/api/history?since=yesterday', headers=prof)).status == 400
                assert (await h.client.get('/api/history', headers=bob)).status == 403
                server.down = True                                       # the reader cannot connect
                resp = await h.client.get('/api/history', headers=prof)
                assert resp.status == 503 and 'does not answer' in (await resp.json())['error']
                server.down = False
            # after the cleanup: the shutdown lines reached the database, the history line names the filters
            events = [row[1] for row in server.committed]
            assert events[-1] == 'session_close' and events.count('session_close') == 2 and 'history' in events
            history_row = next(row for row in server.committed if row[1] == 'history')
            assert history_row[2] == 'prof' and json.loads(history_row[9])['login_filter'] == 'bob'
            lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
            history = [l for l in lines if l['event'] == 'history']
            assert history[0]['login'] == 'prof' and history[0]['login_filter'] == 'bob'
            assert history[0]['event_filter'] == 'start,stop' and history[0]['status'] == '200'
            assert history[1]['status'] == '400' and history[-1]['status'] == '503'
            assert any(l['path'] == '/history' and l['login'] == 'bob' for l in lines if l['event'] == 'denied')
            # a student's call of the API: a history line with its status (the route has an event), not denied
            assert any(l['login'] == 'bob' and l['status'] == '403' for l in history)
            assert not any(l['path'] == '/api/history' for l in lines if l['event'] == 'denied')
            assert server.committed[0][0] <= utc_datetime(time.time())          # UTC, not local time
        run(go())

    def test_sessions_from_the_database(self, tmp_path):
        """The Sessions view: the open sessions of the portal's memory on the first page, the
        closed ones from their session_close rows (the fake server scripts them), the login
        prefix and the cursor, the events-only filters ignored, the history line."""
        from datetime import datetime
        from test_web_accessdb import FakeServer, Down, NAMES
        from sreweb.portal.accessdb import epoch
        from sreweb.portal.accesshistory import parse_time
        server = FakeServer(table_exists=True)
        over = {**PROXY_OVER, 'auth': {**PROXY_OVER['auth'], 'administrators': ['prof']},
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False, 'database': self.DB}}
        since = '2026-10-26T09:11:50+0100'
        closed_at = datetime(2026, 10, 26, 8, 42, 40, 500000)          # UTC in the table
        rows = [(9, closed_at, 'session_close', 'alice', '10.0.1.7', '', '', '', '', 1850.0,
                 json.dumps({'role': 'student', 'name': 'Alice Test', 'reason': 'idle', 'since': since, 'requests': 14,
                             'projects': ['1761466323@@@dhcp@@@alice']})),
                (5, datetime(2026, 10, 26, 7, 0, 0), 'session_close', 'bob', '10.0.1.8', '', '', '', '', 60.0,
                 json.dumps({'reason': 'logout', 'since': '2026-10-26T07:59:00+0100', 'requests': 2, 'projects': []}))]

        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=over, db_connect=(server.connect, (Down,))) as h:
                prof, bob = who('prof', 'Prof Essor', groups=TEACHERS), who('bob', 'Bob Test')
                await h.client.get('/api/me', headers=bob)                  # bob's session is open
                server.select_names = NAMES
                server.select_rows = rows
                page = await (await h.client.get('/api/history/sessions', headers=prof)).json()
                assert page['limit'] == 100 and page['more'] is False and page['database']['connected'] is True
                start = parse_time(since)
                assert page['rows'][0] == {'id': 9, 'login': 'alice', 'name': 'Alice Test', 'role': 'student',
                                           'addr': '10.0.1.7', 'start': start, 'end': start + 1850.0,
                                           'closed': epoch(closed_at), 'duration': 1850.0, 'requests': 14,
                                           'projects': ['1761466323@@@dhcp@@@alice'], 'reason': 'idle'}
                assert page['rows'][1]['name'] == '' and page['rows'][1]['reason'] == 'logout'
                # the open sessions, newest first (prof's opened by this very call), the identity of the headers
                assert [(s['login'], s['name'], s['role'], s['reason'], s['closed'], s['sockets']) for s in page['open']] == \
                       [('prof', 'Prof Essor', 'instructor', None, None, 0), ('bob', 'Bob Test', 'student', None, None, 0)]
                assert page['open'][0]['requests'] == 1 and page['open'][0]['projects'] == []
                assert page['open'][0]['start'] <= page['open'][0]['end'] and page['open'][0]['id'] is None
                # the login prefix on both kinds, the limit and the cursor; the events-only filters are ignored
                page = await (await h.client.get('/api/history/sessions?login=b&limit=1&event=start&host=a01&lab=x',
                                                 headers=prof)).json()
                assert [s['login'] for s in page['open']] == ['bob'] and page['more'] is True and len(page['rows']) == 1
                kind, sql, args = next(s for s in reversed(server.statements) if s[1].startswith('SELECT id'))
                assert 'event IN (%s)' in sql and 'host = %s' not in sql and 'lab LIKE' not in sql
                assert args == ['b%', 'session_close', 2]
                page = await (await h.client.get('/api/history/sessions?before=9', headers=prof)).json()
                assert page['open'] == [] and len(page['rows']) == 2
                assert (await h.client.get('/api/history/sessions?since=yesterday', headers=prof)).status == 400
                assert (await h.client.get('/api/history/sessions', headers=bob)).status == 403
                server.down = True
                resp = await h.client.get('/api/history/sessions', headers=prof)
                assert resp.status == 503 and 'does not answer' in (await resp.json())['error']
                server.down = False
            # the history lines carry the view and the filters; the close lines the name and role
            history = [row for row in server.committed if row[1] == 'history']
            assert json.loads(history[0][9])['view'] == 'sessions' and 'login_filter' not in json.loads(history[0][9])
            assert json.loads(history[1][9])['login_filter'] == 'b' and 'event_filter' not in json.loads(history[1][9])
            closes = {row[2]: json.loads(row[9]) for row in server.committed if row[1] == 'session_close'}
            assert closes['bob']['name'] == 'Bob Test' and closes['bob']['role'] == 'student'
            assert closes['prof']['role'] == 'instructor' and closes['prof']['reason'] == 'shutdown'
            lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
            assert [l['view'] for l in lines if l['event'] == 'history'][:2] == ['sessions', 'sessions']
            assert any(l['event'] == 'session_close' and l['name'] == 'Bob Test' and l['role'] == 'student' for l in lines)
        run(go())

    def test_sessions_without_database(self, tmp_path):
        """No database: the Sessions view lists the open sessions alone (no 409: who is connected
        now needs none), the events view keeps its 409."""
        over = {**PROXY_OVER, 'auth': {**PROXY_OVER['auth'], 'administrators': ['prof']}}

        async def go():
            async with Harness(tmp_path, auth_mode='proxy', web_over=over) as h:
                prof = who('prof', 'Prof Essor', groups=TEACHERS)
                assert (await h.client.get('/api/history', headers=prof)).status == 409
                page = await (await h.client.get('/api/history/sessions', headers=prof)).json()
                assert page['rows'] == [] and page['more'] is False and page['database'] is None and page['limit'] == 100
                assert [(s['login'], s['role'], s['name'], s['reason']) for s in page['open']] == \
                       [('prof', 'instructor', 'Prof Essor', None)]
                assert (await h.client.get('/api/history/sessions', headers=who('bob'))).status == 403
                assert (await h.client.get('/api/history/sessions')).status == 401
        run(go())

