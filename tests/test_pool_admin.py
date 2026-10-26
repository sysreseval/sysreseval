"""The administration of the pool: the admin API of the portal (token, loopback, membership kept
in the state file across restarts) and the ``sre-web-tool`` command line on top of it."""
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

import test_web_portal as P   # noqa: E402  (the Harness: a real agent on the fake sre, a portal in front)

SRC = Path(__file__).resolve().parent.parent / 'src'
ADMIN = 'a' * 32
TOKEN = P.TOKEN
CSRF = P.CSRF
QUIET_POOL = {'poll_interval': 0.1, 'min_hosts_up': 0, 'spare_projects': 0}   # no automatic wake


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def run(coro):
    return asyncio.run(coro)


class TestAdminApi:
    def test_token_membership_and_persistence(self, tmp_path):
        state = tmp_path / 'state' / 'pool.json'
        over = {'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL,
                'limits': {'start_interval': 0}}

        async def go():
            async with P.Harness(tmp_path, web_over=over) as h:
                sent = []
                h.portal.manager.wol = lambda mac, broadcast: sent.append((mac, broadcast))
                # nobody: 401; a wrong token: 401
                assert (await h.client.get('/api/pool')).status == 401
                assert (await h.client.get('/api/pool', headers=auth('x' * 32))).status == 401
                rows = await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()
                assert [(r['name'], r['state'], r['source']) for r in rows] == [('a01', 'up', 'config')]
                assert 'token' not in rows[0] and rows[0]['projects'] == 0 and rows[0]['max_projects'] == 3
                status = await (await h.client.get('/api/pool/status', headers=auth(ADMIN))).json()
                assert status['awake'] == 1 and status['spare_projects'] == 3 and status['waking'] == []
                # a student: the listing is for instructors, the actions for the token
                await h.login()
                assert (await h.client.get('/api/pool')).status == 403
                assert (await h.client.post('/api/pool/hosts/a01/disable', headers=CSRF)).status == 401
                # add a host (down, wakeable), replace it, refuse a config name and a bad entry
                body = {'name': 'b02', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'max_projects': 2,
                        'mac': 'AA-BB-CC-DD-EE-FF', 'power': True}
                resp = await h.client.post('/api/pool/hosts', json=body, headers=auth(ADMIN))
                assert resp.status == 201, await resp.text()
                row = await resp.json()
                assert row['source'] == 'added' and row['can_wake'] is True and row['power'] is True
                assert (await h.client.post('/api/pool/hosts', json=body, headers=auth(ADMIN))).status == 201
                assert (await h.client.post('/api/pool/hosts', json={**body, 'name': 'a01'},
                                            headers=auth(ADMIN))).status == 409
                assert (await h.client.post('/api/pool/hosts', json={'name': 'x'}, headers=auth(ADMIN))).status == 400
                assert (await h.client.post('/api/pool/hosts', data='nope', headers=auth(ADMIN))).status == 400
                saved = json.loads(state.read_text())
                assert [a['name'] for a in saved['added']] == ['b02'] and saved['added'][0]['mac'] == 'aa:bb:cc:dd:ee:ff'
                assert oct(state.stat().st_mode & 0o777) == '0o600'
                await asyncio.sleep(0.3)
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()}
                assert rows['b02']['state'] == 'off' and rows['b02']['reachable'] is False
                # disabled: no placement; nothing else to wake automatically (min_hosts_up = 0)
                resp = await h.client.post('/api/pool/hosts/a01/disable', headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['state'] == 'disabled'
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers=CSRF)
                assert resp.status == 503 and 'no host' in (await resp.json())['error']
                # a wake by hand: the host is starting, a start says so
                resp = await h.client.post('/api/pool/hosts/b02/wake', headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['state'] == 'waking'
                assert sent == [('aa:bb:cc:dd:ee:ff', '255.255.255.255')]
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers=CSRF)
                assert resp.status == 503 and (await resp.json())['retry_after'] == 30
                assert 'starting' in (await resp.json())['error']
                resp = await h.client.post('/api/pool/hosts/a01/wake', headers=auth(ADMIN))
                assert resp.status == 409                                # no mac, no wake_command
                # enabled again: the start lands there; remove refused while it holds a project
                assert (await h.client.post('/api/pool/hosts/a01/enable', headers=auth(ADMIN))).status == 200
                result = await h.start()
                assert result['host'] == 'a01'
                resp = await h.client.delete('/api/pool/hosts/a01', headers=auth(ADMIN))
                assert resp.status == 409 and 'drain' in (await resp.json())['error']
                resp = await h.client.post('/api/pool/hosts/a01/poweroff', headers=auth(ADMIN))
                assert resp.status == 403                                # the agent does not allow it
                resp = await h.client.post('/api/pool/hosts/a01/drain', headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['state'] == 'draining'
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers=CSRF)
                assert resp.status == 503
                assert (await h.client.post('/api/pool/hosts/a01/dance', headers=auth(ADMIN))).status == 404
                assert (await h.client.delete('/api/pool/hosts/nope', headers=auth(ADMIN))).status == 404
                # forced removal of a config host, then enable brings it back from the configuration
                resp = await h.client.delete('/api/pool/hosts/a01?force=1', headers=auth(ADMIN))
                assert resp.status == 200
                assert [r['name'] for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()] == ['b02']
                assert json.loads(state.read_text())['removed'] == ['a01']
                resp = await h.client.post('/api/pool/hosts/a01/enable', headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['source'] == 'config'
                assert (await h.client.post('/api/pool/hosts/b02/disable', headers=auth(ADMIN))).status == 200
                saved = json.loads(state.read_text())
                assert saved['removed'] == [] and saved['disabled'] == ['b02']
                # the loopback rule of the token
                routes = h.portal.routes
                fake = types.SimpleNamespace(headers=auth(ADMIN), remote='10.0.0.5', method='GET', path='/api/pool')
                assert routes._is_admin(fake) is False
                routes.cfg.admin.listen_any = True
                assert routes._is_admin(fake) is True
            # a new portal on the same state file: the host added, the one disabled
            async with P.Harness(tmp_path / 'again', web_over=over) as h:
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()}
                assert rows['a01']['state'] == 'up' and rows['a01']['source'] == 'config'
                assert rows['b02']['source'] == 'added' and rows['b02']['state'] == 'disabled'
        run(go())

    def test_no_token_configured(self, tmp_path):
        async def go():
            async with P.Harness(tmp_path, web_over={'pool': QUIET_POOL}) as h:
                assert (await h.client.get('/api/pool', headers=auth(ADMIN))).status == 401
                assert (await h.client.post('/api/pool/hosts/a01/disable', headers=auth(ADMIN))).status == 401
        run(go())

    def test_instructors_only_host(self, tmp_path):
        """`add --instructors-only`: the flag in the answer, in the state file, back after a restart."""
        state = tmp_path / 'state' / 'pool.json'
        over = {'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, web_over=over) as h:
                body = {'name': 'c03', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'max_projects': 2,
                        'instructors_only': True}
                resp = await h.client.post('/api/pool/hosts', json=body, headers=auth(ADMIN))
                assert resp.status == 201, await resp.text()
                assert (await resp.json())['instructors_only'] is True
                resp = await h.client.post('/api/pool/hosts', json={**body, 'instructors_only': 'yes'},
                                           headers=auth(ADMIN))
                assert resp.status == 400 and 'instructors_only' in (await resp.json())['error']
                assert json.loads(state.read_text())['added'][0]['instructors_only'] is True
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()}
                assert rows['a01']['instructors_only'] is False
            async with P.Harness(tmp_path / 'again', web_over=over) as h:
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()}
                assert rows['c03']['instructors_only'] is True and rows['c03']['source'] == 'added'
        run(go())


class TestCli:
    def test_sre_web_tool(self, tmp_path):
        over = {'admin': {'token': ADMIN}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, web_over=over) as h:
                url = f"http://127.0.0.1:{h.client.port}"
                env = {**os.environ, 'PYTHONPATH': str(SRC)}

                def cli(*args, token=ADMIN):
                    return subprocess.run([sys.executable, '-m', 'sreweb.tool', '--url', url,
                                           '--token', token, *args], capture_output=True, text=True, env=env,
                                          timeout=120)
                loop = asyncio.get_running_loop()
                r = await loop.run_in_executor(None, cli, 'list')
                assert r.returncode == 0, r.stderr
                lines = r.stdout.splitlines()
                assert lines[0].split() == ['NAME', 'STATE', 'PROJECTS', 'LOAD', 'TERMINALS', 'OCCUPIED', 'UPTIME',
                                            'SOURCE', 'LAST', 'ERROR']
                assert lines[1].split()[:3] == ['a01', 'up', '0/3'] and lines[1].split()[-1] == 'config'
                r = await loop.run_in_executor(None, lambda: cli('add', 'b02', '--url', 'http://127.0.0.1:9',
                                                                 '--token', TOKEN, '--max-projects', '2', '--json',
                                                                 '--instructors-only'))
                assert r.returncode == 0, r.stderr
                assert json.loads(r.stdout)['state'] == 'off' and json.loads(r.stdout)['source'] == 'added'
                assert json.loads(r.stdout)['instructors_only'] is True
                r = await loop.run_in_executor(None, cli, 'status')
                assert r.returncode == 0 and r.stdout.startswith('spare capacity: 3 project slot(s)')
                assert 'waking: none' in r.stdout
                r = await loop.run_in_executor(None, cli, 'list')
                assert [l.split()[:2] for l in r.stdout.splitlines()[1:]] == [['a01', 'up'], ['b02', 'off']]
                assert 'Cannot connect' in r.stdout.splitlines()[2]     # the last error of the unreachable host
                assert '(instructors)' in r.stdout.splitlines()[2] and '(instructors)' not in r.stdout.splitlines()[1]
                r = await loop.run_in_executor(None, cli, 'disable', 'b02')
                assert r.returncode == 0 and r.stdout.splitlines()[1].split()[:2] == ['b02', 'disabled']
                r = await loop.run_in_executor(None, cli, 'remove', 'b02')
                assert r.returncode == 0 and r.stdout.strip() == 'b02 removed'
                r = await loop.run_in_executor(None, cli, 'wake', 'a01')
                assert r.returncode == 1 and 'no mac' in r.stderr and '(409)' in r.stderr
                r = await loop.run_in_executor(None, lambda: cli('list', token='w' * 32))
                assert r.returncode == 1 and 'bad administration token (401)' in r.stderr
                r = await loop.run_in_executor(None, lambda: subprocess.run(
                    [sys.executable, '-m', 'sreweb.tool', '--url', 'http://127.0.0.1:9', '--token', ADMIN,
                     'list'], capture_output=True, text=True, env=env, timeout=120))
                assert r.returncode == 1 and 'cannot reach the portal' in r.stderr
                # the former `sre-web pool ...` points at the tool
                r = await loop.run_in_executor(None, lambda: subprocess.run(
                    [sys.executable, '-m', 'sreweb.portal', 'pool', 'list'], capture_output=True, text=True,
                    env=env, timeout=120))
                assert r.returncode == 2 and 'sre-web-tool' in r.stderr
        run(go())

    def test_table_cells(self):
        from sreweb.portal.poolctl import table
        rows = [{'name': 'a01', 'state': 'waking', 'waking_for': 12, 'wake_failures': 1, 'reachable': False,
                 'error': 'down', 'source': 'config', 'max_projects': 3},
                {'name': 'b02', 'state': 'up', 'drain': True, 'reachable': True, 'projects': 2, 'max_projects': 3,
                 'load1': 1.234, 'terminals': 4, 'occupied_by': ['session:bob'], 'uptime': 3725, 'source': 'added'},
                {'name': 'c03', 'state': 'off', 'instructors_only': True, 'reachable': False, 'source': 'config',
                 'max_projects': 3}]
        out = table(rows).splitlines()
        assert out[1].split()[:2] == ['a01', 'waking'] and '(12s, 1 failed)' in out[1] and out[1].endswith('down')
        assert out[2].split() == ['b02', 'up', '(drain)', '2/3', '1.23', '4', 'session:bob', '1h02', 'added']
        assert out[3].split()[:3] == ['c03', 'off', '(instructors)']
