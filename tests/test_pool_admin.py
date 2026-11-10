"""The administration of the pool: the admin API of the portal (token, loopback, membership kept
in the state file across restarts) and the ``sre-web-tool`` command line on top of it."""
import asyncio
import json
import os
import subprocess
import sys
import time
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


async def pool_row(h, predicate, name='a01', timeout=10.0) -> dict:
    """The row of host *name* in ``GET /api/pool``, read until *predicate* holds."""
    async with asyncio.timeout(timeout):
        while True:
            rows = await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()
            row = next(r for r in rows if r['name'] == name)
            if predicate(row):
                return row
            await asyncio.sleep(0.05)


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
                # a student: the listing and the actions are for the instructors (TestInstructorPage) and the token
                await h.login()
                assert (await h.client.get('/api/pool')).status == 403
                assert (await h.client.post('/api/pool/hosts/a01/disable', headers=CSRF)).status == 403
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

    def test_restart(self, tmp_path):
        """``restart``: the agent runs its command, the row shows the restart sent, a second one
        and an unreachable host are refused."""
        flag = tmp_path / 'restarted'
        over = {'admin': {'token': ADMIN}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, web_over=over, hosts=2,
                                 agent_over={'restart_command': f'sh -c "touch {flag}"'}) as h:
                resp = await h.client.post('/api/pool/hosts/a01/restart', headers=auth(ADMIN))
                assert resp.status == 200, await resp.text()
                row = await resp.json()
                assert row['restart_sent'] is True and row['restart_allowed'] is True and row['state'] == 'up'
                resp = await h.client.post('/api/pool/hosts/a01/restart', headers=auth(ADMIN))
                assert resp.status == 409 and 'sent' in (await resp.json())['error']
                resp = await h.client.post('/api/pool/hosts/down/restart', headers=auth(ADMIN))
                assert resp.status == 409 and 'not reachable' in (await resp.json())['error']
                for _ in range(40):
                    if flag.exists():
                        break
                    await asyncio.sleep(0.1)
                assert flag.exists()
                # the agent of the tests never restarts: the flag stays until the portal's hold
                rows = {r['name']: r for r in await (await h.client.get('/api/pool', headers=auth(ADMIN))).json()}
                assert rows['a01']['restart_sent'] is True and rows['a01']['restarting'] is True
        run(go())

    def test_preload(self, tmp_path):
        """``preload``: the agent is asked and waits (the row says so at once), the policy gives it
        its turn, it pulls the images; an unreachable host is refused."""
        over = {'admin': {'token': ADMIN}, 'pool': QUIET_POOL}
        log = tmp_path / 'mock.log'
        mock_env = {'MOCK_PRELOAD_IMAGES': json.dumps(['debian:12', 'sysreseval/base:1.0']),
                    'MOCK_PRELOAD_DELAY': '0.6', 'MOCK_SRE_LOG': str(log)}

        async def go():
            async with P.Harness(tmp_path, web_over=over, hosts=2, mock_env=mock_env,
                                 agent_over={'preload': {'paths': [str(tmp_path)]}}) as h:
                assert (await pool_row(h, lambda r: r['reachable']))['preload'] == 'idle'
                await asyncio.sleep(0.4)
                assert not log.exists()                             # nobody asked: nothing is pulled
                resp = await h.client.post('/api/pool/hosts/a01/preload', headers=auth(ADMIN))
                assert resp.status == 200, await resp.text()
                assert (await resp.json())['preload'] == 'pending'
                row = await pool_row(h, lambda r: r['preload'] == 'running' and r['preload_current'] == 2)
                assert (row['preload_total'], row['preload_image'], row['state']) == (2, 'sysreseval/base:1.0', 'up')
                status = await (await h.client.get('/api/pool/status', headers=auth(ADMIN))).json()
                assert (status['max_preloads'], status['preloading'], status['preload_queued']) == (2, ['a01'], 0)
                # asked again meanwhile: the preload in progress goes on, alone
                resp = await h.client.post('/api/pool/hosts/a01/preload', headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['preload'] == 'running'
                row = await pool_row(h, lambda r: r['preload'] != 'running')
                assert (row['preload'], row['preload_current'], row['preload_error']) == ('done', 2, '')
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                assert [c['argv'] for c in calls] == [['preload-images', '--progress', '--', str(tmp_path)]]
                assert calls[0]['user_mode'] is False and calls[0]['env']['LOGNAME'] == 'root'
                resp = await h.client.post('/api/pool/hosts/down/preload', headers=auth(ADMIN))
                assert resp.status == 409 and 'not reachable' in (await resp.json())['error']
                assert (await h.client.post('/api/pool/hosts/nope/preload', headers=auth(ADMIN))).status == 404
        run(go())

    def test_preload_at_the_start_of_the_agents(self, tmp_path):
        """An agent with ``[preload] at_start`` asks when it starts: the portal gives it its turn
        without anybody asking; with ``max_preloads = 0`` it gives none, and refuses a request."""
        agent_over = {'preload': {'at_start': True, 'paths': [str(tmp_path)]}}
        failing = {'MOCK_PRELOAD_IMAGES': json.dumps(['debian:12', '!gone:1'])}

        async def go():
            async with P.Harness(tmp_path, web_over={'admin': {'token': ADMIN}, 'pool': QUIET_POOL},
                                 mock_env=failing, agent_over=agent_over) as h:
                row = await pool_row(h, lambda r: r['preload'] in ('done', 'failed'))
                assert row['preload'] == 'failed' and row['preload_error'] == '1 of 2 image(s) failed to pull: gone:1'
                status = await (await h.client.get('/api/pool/status', headers=auth(ADMIN))).json()
                assert status['preload_failed'] == 1 and status['preloading'] == []
            async with P.Harness(tmp_path / 'none', agent_over=agent_over,
                                 web_over={'admin': {'token': ADMIN}, 'pool': {**QUIET_POOL, 'max_preloads': 0}}) as h:
                assert (await pool_row(h, lambda r: r['reachable']))['preload'] == 'pending'
                await asyncio.sleep(0.5)
                assert (await pool_row(h, lambda r: True))['preload'] == 'pending'
                resp = await h.client.post('/api/pool/hosts/a01/preload', headers=auth(ADMIN))
                assert resp.status == 409 and 'max_preloads' in (await resp.json())['error']
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


class TestInstructorPage:
    def test_page_and_actions(self, tmp_path):
        """The Pool page: the listing and the actions of the route for an instructor's session
        (the CSRF header, no token; ``restart`` too, though the page offers no button for it),
        add / remove for the token only."""
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN}, 'pool': QUIET_POOL, 'limits': {'start_interval': 0}}

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over,
                                 agent_over={'restart_command': 'sh -c true'}) as h:
                sent = []
                h.portal.manager.wol = lambda mac, broadcast: sent.append((mac, broadcast))
                bob, prof = P.who('bob'), P.who('prof', groups=P.TEACHERS)
                body = {'name': 'b02', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'mac': 'aa:bb:cc:dd:ee:ff'}
                assert (await h.client.post('/api/pool/hosts', json=body, headers=auth(ADMIN))).status == 201
                # the page and the status: instructors only
                assert (await h.client.get('/pool', allow_redirects=False)).status == 302
                assert (await h.client.get('/pool', headers=bob)).status == 403
                page = await h.client.get('/pool', headers=prof)
                assert page.status == 200 and 'prof True' in await page.text()
                assert (await h.client.get('/api/pool/status', headers=bob)).status == 403
                status = await (await h.client.get('/api/pool/status', headers=prof)).json()
                assert status['awake'] == 1 and status['waking'] == []
                # the actions: a student 403, the CSRF header required, then the commands of the tool
                a01 = '/api/pool/hosts/a01/'
                assert (await h.client.post(a01 + 'disable', headers={**bob, **CSRF})).status == 403
                resp = await h.client.post(a01 + 'disable', headers=prof)
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
                resp = await h.client.post(a01 + 'disable', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['state'] == 'disabled'
                resp = await h.client.post(a01 + 'enable', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['state'] == 'up'
                resp = await h.client.post(a01 + 'drain', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['state'] == 'draining'
                row = await (await h.client.post(a01 + 'enable', headers={**prof, **CSRF})).json()
                assert row['state'] == 'up' and row['drain'] is False
                resp = await h.client.post('/api/pool/hosts/b02/wake', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['state'] == 'waking'
                assert sent == [('aa:bb:cc:dd:ee:ff', '255.255.255.255')]
                assert (await h.client.post(a01 + 'wake', headers={**prof, **CSRF})).status == 409      # no mac
                assert (await h.client.post(a01 + 'poweroff', headers={**prof, **CSRF})).status == 403  # the agent refuses
                # the preload of the Docker images (the Preload images button of the bar)
                assert (await h.client.post(a01 + 'preload', headers={**bob, **CSRF})).status == 403
                resp = await h.client.post(a01 + 'preload', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['preload'] == 'pending'
                resp = await h.client.post('/api/pool/hosts/b02/preload', headers={**prof, **CSRF})
                assert resp.status == 409 and 'not reachable' in (await resp.json())['error']
                resp = await h.client.post(a01 + 'restart', headers={**prof, **CSRF})
                assert resp.status == 200 and (await resp.json())['restart_sent'] is True
                assert (await h.client.post(a01 + 'restart', headers={**prof, **CSRF})).status == 409   # sent already
                assert (await h.client.post(a01 + 'dance', headers={**prof, **CSRF})).status == 404
                assert (await h.client.post('/api/pool/hosts/nope/enable', headers={**prof, **CSRF})).status == 404
                # add and remove stay with the token
                assert (await h.client.post('/api/pool/hosts', json=body, headers={**prof, **CSRF})).status == 401
                assert (await h.client.delete('/api/pool/hosts/b02', headers={**prof, **CSRF})).status == 401
        run(go())

    def test_actions_are_kept_across_a_restart(self, tmp_path):
        """A host the configuration disables (the DISABLED_ROOMS of make-web-hosts.sh), enabled
        then drained by an instructor on the Pool page: a new portal on the same configuration
        and state file shows it as it was left (it came back disabled until 2026-11-10); once
        the configuration enables the host itself, the entry made by hand is gone."""
        state = tmp_path / 'state' / 'pool.json'
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}
        prof = {**P.who('prof', groups=P.TEACHERS), **CSRF}

        async def row_of(h):
            return (await (await h.client.get('/api/pool', headers=prof)).json())[0]

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={'enabled': False}) as h:
                assert (await row_of(h))['state'] == 'disabled'
                status = await (await h.client.get('/api/pool/status', headers=prof)).json()
                assert status['state_file'] == str(state) and status['state_error'] == ''
                resp = await h.client.post('/api/pool/hosts/a01/enable', headers=prof)
                assert resp.status == 200 and (await resp.json())['state'] == 'up'
                assert json.loads(state.read_text())['enabled'] == ['a01']
                resp = await h.client.post('/api/pool/hosts/a01/drain', headers=prof)
                assert resp.status == 200 and (await resp.json())['state'] == 'draining'
                assert list(json.loads(state.read_text())['drain']) == ['a01']
            async with P.Harness(tmp_path / 'again', auth_mode='proxy', web_over=over,
                                 host_over={'enabled': False}) as h:
                row = await row_of(h)
                assert row['state'] == 'draining' and row['enabled'] is True and row['drain'] is True
                resp = await h.client.post('/api/pool/hosts/a01/enable', headers=prof)       # cancels the drain
                assert resp.status == 200 and (await resp.json())['state'] == 'up'
            async with P.Harness(tmp_path / 'third', auth_mode='proxy', web_over=over,
                                 host_over={'enabled': False}) as h:
                assert (await row_of(h))['state'] == 'up'
                saved = json.loads(state.read_text())
                assert saved['enabled'] == ['a01'] and saved['drain'] == {}
            # the configuration enables the host now: nothing by hand is left in the file
            async with P.Harness(tmp_path / 'edited', auth_mode='proxy', web_over=over) as h:
                assert (await row_of(h))['state'] == 'up'
                assert json.loads(state.read_text())['enabled'] == []
            async with P.Harness(tmp_path / 'back', auth_mode='proxy', web_over=over,
                                 host_over={'enabled': False}) as h:
                assert (await row_of(h))['state'] == 'disabled'
        run(go())

    def test_bulk_actions(self, tmp_path):
        """The bar of the Pool page sends one call per selected host, all at once: the per-host
        route serves them together, each answer being the row of its host, a failure (the wake
        of a host without MAC) leaving the others alone."""
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN}, 'pool': QUIET_POOL, 'limits': {'start_interval': 0}}

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over) as h:
                sent = []
                h.portal.manager.wol = lambda mac, broadcast: sent.append((mac, broadcast))
                prof = {**P.who('prof', groups=P.TEACHERS), **CSRF}
                for name in ('b02', 'b03'):
                    body = {'name': name, 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'mac': f'aa:bb:cc:dd:ee:{name[-2:]}'}
                    assert (await h.client.post('/api/pool/hosts', json=body, headers=auth(ADMIN))).status == 201
                hosts = ['a01', 'b02', 'b03']
                responses = await asyncio.gather(*(h.client.post(f'/api/pool/hosts/{name}/disable', headers=prof)
                                                   for name in hosts))
                rows = [await r.json() for r in responses]
                assert [r.status for r in responses] == [200] * 3
                assert [row['name'] for row in rows] == hosts and all(row['state'] == 'disabled' for row in rows)
                responses = await asyncio.gather(*(h.client.post(f'/api/pool/hosts/{name}/enable', headers=prof)
                                                   for name in hosts))
                assert [(await r.json())['enabled'] for r in responses] == [True] * 3
                # a wake of the three: a01 has no MAC (409), the two others are woken
                responses = await asyncio.gather(*(h.client.post(f'/api/pool/hosts/{name}/wake', headers=prof)
                                                   for name in hosts))
                assert [r.status for r in responses] == [409, 200, 200]
                assert sorted(sent) == [('aa:bb:cc:dd:ee:02', '255.255.255.255'), ('aa:bb:cc:dd:ee:03', '255.255.255.255')]
                summary = {row['name']: row['state'] for row in await (await h.client.get('/api/pool', headers=prof)).json()}
                assert summary == {'a01': 'up', 'b02': 'waking', 'b03': 'waking'}
        run(go())


class TestCli:
    def test_sre_web_tool(self, tmp_path):
        state = tmp_path / 'pool.json'
        over = {'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, web_over=over, agent_over={'restart_command': 'sh -c true'}) as h:
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
                assert 'waking: none' in r.stdout and r.stdout.splitlines()[-1] == f'pool state: {state}'
                assert 'image preloads: 0 running, 0 queued, 0 failed (at most 2 at a time)' in r.stdout
                # the state file cannot be written: said by the status, the pool goes on
                h.portal.pool.state_error = 'Read-only file system'
                r = await loop.run_in_executor(None, cli, 'status')
                assert r.returncode == 0
                assert r.stdout.splitlines()[-1] == f'pool state: NOT SAVED in {state}: Read-only file system'
                h.portal.pool.state_error = ''
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
                # preload: the host waits for its turn to pull the Docker images; every host; the usage
                r = await loop.run_in_executor(None, cli, 'preload', 'a01')
                assert r.returncode == 0, r.stderr
                assert r.stdout.splitlines()[1].split()[:4] == ['a01', 'up', '(preload', 'queued)']
                await pool_row(h, lambda row: row['preload'] == 'done')
                r = await loop.run_in_executor(None, lambda: cli('preload', '--all', '--json'))
                assert r.returncode == 0 and [row['name'] for row in json.loads(r.stdout)] == ['a01']
                await pool_row(h, lambda row: row['preload'] == 'done')
                r = await loop.run_in_executor(None, cli, 'preload', '--failed')
                assert r.returncode == 0 and r.stdout.strip() == 'no host whose preload failed'
                r = await loop.run_in_executor(None, cli, 'preload', 'nope')
                assert r.returncode == 1 and 'nope:' in r.stderr and '(404)' in r.stderr
                for args in (['preload'], ['preload', '--all', 'a01'], ['preload', '--all', '--failed']):
                    r = await loop.run_in_executor(None, lambda: cli(*args))
                    assert r.returncode == 2 and 'give a host name, --all or --failed' in r.stderr, args
                # restart: every reachable host, then the one already sent is refused; the usage
                r = await loop.run_in_executor(None, cli, 'restart', '--all')
                assert r.returncode == 0, r.stderr
                assert r.stdout.splitlines()[1].split()[:3] == ['a01', 'up', '(restart)']
                r = await loop.run_in_executor(None, cli, 'restart', 'a01')
                assert r.returncode == 1 and r.stdout == '' and 'a01: a01: a restart was sent' in r.stderr \
                    and '(409)' in r.stderr
                r = await loop.run_in_executor(None, lambda: cli('restart', '--all', '--json'))
                assert r.returncode == 1 and r.stdout == '' and 'a01:' in r.stderr
                r = await loop.run_in_executor(None, cli, 'restart')
                assert r.returncode == 2 and 'give a host name or --all' in r.stderr
                r = await loop.run_in_executor(None, cli, 'restart', '--all', 'a01')
                assert r.returncode == 2 and 'give a host name or --all' in r.stderr
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
                 'max_projects': 3, 'restart_sent': True}]
        out = table(rows).splitlines()
        assert out[1].split()[:2] == ['a01', 'waking'] and '(12s, 1 failed)' in out[1] and out[1].endswith('down')
        assert out[2].split() == ['b02', 'up', '(drain)', '2/3', '1.23', '4', 'session:bob', '1h02', 'added']
        assert out[3].split()[:4] == ['c03', 'off', '(restart,', 'instructors)']
        # the preload of the Docker images: pulling (image 2 of 5), waiting for its turn, failed
        from sreweb.portal.poolctl import _cell
        for preload, cell in (({'preload': 'running', 'preload_current': 2, 'preload_total': 5}, 'up (preload 2/5)'),
                              ({'preload': 'running', 'preload_total': 0}, 'up (preload)'),
                              ({'preload': 'pending'}, 'up (preload queued)'),
                              ({'preload': 'failed', 'preload_error': 'x'}, 'up (preload failed)'),
                              ({'preload': 'done'}, 'up'), ({'preload': 'idle'}, 'up'), ({'preload': ''}, 'up'), ({}, 'up')):
            assert _cell({'name': 'd04', 'state': 'up', 'reachable': True, **preload}, 'state') == cell, preload
        assert _cell({'state': 'up', 'drain': True, 'preload': 'pending', 'instructors_only': True}, 'state') == \
            'up (drain, preload queued, instructors)'

    def test_preload_hosts(self, capsys):
        """``preload --all``: every reachable host whose agent knows the preload; ``--failed``:
        those whose last preload failed; one POST each, the failures on stderr."""
        from sreweb.portal import poolctl
        rows = [{'name': 'a01', 'reachable': True, 'preload': 'done', 'state': 'up'},
                {'name': 'b02', 'reachable': True, 'preload': 'failed', 'state': 'up'},
                {'name': 'c03', 'reachable': True, 'preload': '', 'state': 'up'},          # an older agent
                {'name': 'd04', 'reachable': False, 'preload': '', 'state': 'off'},
                {'name': 'e05', 'reachable': True, 'preload': 'failed', 'state': 'occupied'}]
        client = types.SimpleNamespace(posts=[])

        def call(method, path):
            if method == 'GET':
                assert path == '/api/pool'
                return rows
            client.posts.append(path)
            name = path.split('/')[4]
            if name == 'e05':
                raise poolctl.CallError("e05 does not answer", 502)
            return {'name': name, 'state': 'up', 'reachable': True, 'preload': 'pending'}
        client.call = call
        assert poolctl.preload_hosts(client, None, failed_only=False, as_json=False) == 1
        assert client.posts == [f'/api/pool/hosts/{n}/preload' for n in ('a01', 'b02', 'e05')]
        captured = capsys.readouterr()
        assert [line.split()[0] for line in captured.out.splitlines()[1:]] == ['a01', 'b02']
        assert 'sre-web-tool: e05: e05 does not answer (502)' in captured.err
        client.posts.clear()
        assert poolctl.preload_hosts(client, None, failed_only=True, as_json=True) == 1
        assert client.posts == ['/api/pool/hosts/b02/preload', '/api/pool/hosts/e05/preload']
        assert [row['name'] for row in json.loads(capsys.readouterr().out)] == ['b02']
        client.posts.clear()
        assert poolctl.preload_hosts(client, ['c03'], failed_only=False, as_json=False) == 0
        assert client.posts == ['/api/pool/hosts/c03/preload']
        capsys.readouterr()
        rows[:] = [rows[2], rows[3]]                            # nobody knows the preload
        assert poolctl.preload_hosts(client, None, failed_only=False, as_json=False) == 1
        assert 'no reachable host whose agent knows the preload' in capsys.readouterr().err
        assert poolctl.preload_hosts(client, None, failed_only=True, as_json=False) == 0
        assert capsys.readouterr().out.strip() == 'no host whose preload failed'

    def test_wait_restarted(self, monkeypatch):
        """``--wait``: a host is back once its agent's uptime is younger than the request; the
        others are reported at the deadline, the rows refreshed."""
        from sreweb.portal import poolctl
        monkeypatch.setattr(poolctl, 'RESTART_POLL', 0.01)
        readings = [[{'name': 'a01', 'reachable': True, 'agent_uptime': 500}, {'name': 'b02', 'reachable': False},
                     {'name': 'c03', 'reachable': True, 'agent_uptime': 500}],
                    [{'name': 'a01', 'reachable': True, 'agent_uptime': 0}, {'name': 'b02', 'reachable': False},
                     {'name': 'c03', 'reachable': True, 'agent_uptime': 501}]]
        client = types.SimpleNamespace(calls=0)

        def call(method, path):
            assert (method, path) == ('GET', '/api/pool')
            client.calls += 1
            return readings[min(client.calls, len(readings)) - 1]
        client.call = call
        sent = time.monotonic() - 2.0      # requests two seconds old (the uptime is rounded to the second)
        rows = [{'name': 'a01', 'state': 'up'}, {'name': 'b02', 'state': 'up'}, {'name': 'c03', 'state': 'up'}]
        failures = poolctl._wait_restarted(client, {'a01': sent, 'b02': sent, 'c03': sent}, 0.2, rows)
        assert sorted(failures) == ['b02: did not come back within 0 s',
                                    'c03: did not restart within 0 s (agent up for 501 s)']
        assert rows[0]['agent_uptime'] == 0 and rows[2]['agent_uptime'] == 501 and client.calls >= 2
