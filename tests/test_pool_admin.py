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

from sreweb.portal.accesslog import parse_line   # noqa: E402
from sreweb.identity import Identity   # noqa: E402
from sreweb.portal.costs import Usage   # noqa: E402
from sreweb.portal.pool import PoolError   # noqa: E402

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

    def test_local_drain(self, tmp_path):
        """A drain asked on the host itself (`sre set-drain` there, here its request file): the
        host drains, Enable cancels it on the agent, and the two actions of the bar let the host
        ask for one or not."""
        from SRE import local_drain
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over,
                                 agent_over={'allow_local_drain': True}) as h:
                bob, prof = P.who('bob'), {**P.who('prof', groups=P.TEACHERS), **CSRF}
                request, boot = local_drain.request_path(str(h.pub)), local_drain.boot_id()
                a01 = '/api/pool/hosts/a01/'

                def ask():
                    local_drain.write_request(request, boot, now=1795104130.0)

                row = await pool_row(h, lambda row: row['local_drain_allowed'] is True)
                assert (row['state'], row['drain'], row['local_drain'], row['local_drain_default']) == \
                    ('up', False, False, True)
                ask()
                row = await pool_row(h, lambda row: row['local_drain'])
                assert (row['state'], row['drain'], row['local_drain_since']) == ('draining', True, 1795104130.0)
                assert h.portal.pool.runtime['a01'].drain is False
                # Enable cancels it: on the agent, the request is gone
                assert (await h.client.post(a01 + 'enable', headers={**bob, **CSRF})).status == 403
                row = await (await h.client.post(a01 + 'enable', headers=prof)).json()
                assert (row['state'], row['drain'], row['local_drain']) == ('up', False, False)
                assert not os.path.exists(request)
                await asyncio.sleep(0.3)                                    # a few polls: it does not come back
                assert (await pool_row(h, lambda row: True))['drain'] is False
                # both drains at once: Enable cancels both
                ask()
                await pool_row(h, lambda row: row['local_drain'])
                assert (await h.client.post(a01 + 'drain', headers=prof)).status == 200
                row = await (await h.client.post(a01 + 'enable', headers=prof)).json()
                assert row['drain'] is False and not os.path.exists(request)
                assert h.portal.pool.runtime['a01'].drain is False
                # forbidden from the page: a request is dropped by the agent, the host stays up
                assert (await h.client.post(a01 + 'forbid-local-drain', headers={**bob, **CSRF})).status == 403
                row = await (await h.client.post(a01 + 'forbid-local-drain', headers=prof)).json()
                assert (row['local_drain_allowed'], row['local_drain_default']) == (False, True)
                ask()
                row = await pool_row(h, lambda row: not os.path.exists(request))
                assert row['drain'] is False and row['state'] == 'up'
                # allowed again (the token of sre-web-tool); forbidding cancels the drain asked
                row = await (await h.client.post(a01 + 'allow-local-drain', headers=auth(ADMIN))).json()
                assert row['local_drain_allowed'] is True
                ask()
                await pool_row(h, lambda row: row['local_drain'])
                row = await (await h.client.post(a01 + 'forbid-local-drain', headers=prof)).json()
                assert (row['state'], row['drain'], row['local_drain_allowed']) == ('up', False, False)
                assert not os.path.exists(request)
                assert (await h.client.post('/api/pool/hosts/nope/allow-local-drain', headers=prof)).status == 404
        run(go())

    def test_drain_of_a_disabled_host(self, tmp_path):
        """A host the portal has disabled (a room of DISABLED_ROOMS) is never powered off, so a
        drain there never ends, unless its agent says ``allow_power_off_when_disabled``: the
        drain asked on the host (`sre set-drain`) and the portal's then both end with the power
        off, the real agent running its command."""
        from SRE import local_drain
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN}, 'pool': QUIET_POOL}
        prof = {**P.who('prof', groups=P.TEACHERS), **CSRF}
        a01 = '/api/pool/hosts/a01/'

        class Off:      # the power off command of the agent, never run for real
            returncode = 0

            async def wait(self):
                return 0

        async def scenario(directory, says: bool, local: bool) -> tuple:
            """One disabled host that drains: its row once the power off was sent (or after a
            while without it), and what its agent ran."""
            agent = {'allow_local_drain': True, 'allow_power_off': True, 'power_off_command': '/usr/bin/true',
                     'allow_power_off_when_disabled': says}
            async with P.Harness(directory, auth_mode='proxy', web_over=over, agent_over=agent,
                                 host_over={'enabled': False, 'power': True}) as h:
                ran = []

                async def spawn(*argv):
                    ran.append(list(argv))
                    return Off()
                h.agent.spawn = spawn
                row = await pool_row(h, lambda row: row['reachable'])
                assert (row['state'], row['power_off_when_disabled_allowed'], row['drain']) == ('disabled', says, False)
                if local:
                    local_drain.write_request(local_drain.request_path(str(h.pub)), local_drain.boot_id())
                    row = await pool_row(h, lambda row: row['local_drain'])
                else:
                    row = await (await h.client.post(a01 + 'drain', headers=prof)).json()
                assert (row['state'], row['drain']) == ('disabled', True)
                if says:
                    row = await pool_row(h, lambda row: row['power_off_sent'])
                    async with asyncio.timeout(10):
                        while not ran:      # the agent runs its command one second after its answer
                            await asyncio.sleep(0.05)
                else:
                    await asyncio.sleep(1.5)        # fifteen polls of the policy
                    row = await pool_row(h, lambda row: True)
                return row, ran

        async def go():
            for local in (True, False):
                where = 'local' if local else 'portal'
                row, ran = await scenario(tmp_path / f'{where}-no', False, local)
                assert (row['state'], row['drain'], row['power_off_sent']) == ('disabled', True, False) and ran == []
                row, ran = await scenario(tmp_path / f'{where}-yes', True, local)
                assert (row['state'], row['drain'], row['power_off_sent']) == ('disabled', True, True)
                assert ran == [['/usr/bin/true']]
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

    def test_priority(self, tmp_path):
        """The priority of a host, group:order: set by an instructor on the Pool page or with the
        token, told by the row (as it is written, and its two numbers), kept in the state file
        and across a restart, in the ``admin`` line of the connection log; what is no priority
        is refused; one integer is that order in group 0; an edit of the configuration wins."""
        state = tmp_path / 'state' / 'pool.json'
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL,
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}
        teacher = P.who('prof', groups=P.TEACHERS)
        bob, prof = {**P.who('bob'), **CSRF}, {**teacher, **CSRF}
        url = '/api/pool/hosts/a01/priority'

        async def priority_of(h):
            return (await (await h.client.get('/api/pool', headers=prof)).json())[0]['priority']

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={'priority': '1:2'}) as h:
                assert await priority_of(h) == '1:2'                # the one of the configuration
                assert (await h.client.post(url, json={'priority': '1:1'}, headers=bob)).status == 403
                resp = await h.client.post(url, json={'priority': '1:1'}, headers=teacher)
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
                resp = await h.client.post(url, json={'priority': '-3:4'}, headers=prof)
                assert resp.status == 200, await resp.text()
                row = await resp.json()
                assert row['name'] == 'a01' and row['priority'] == '-3:4' and row['state'] == 'up'
                assert (row['group'], row['order']) == (-3, 4)
                assert json.loads(state.read_text())['priority'] == {'a01': {'value': '-3:4', 'configured': '1:2'}}
                for body in ({'priority': '1'}, {'priority': True}, {'priority': 1.5}, {'priority': 10000},
                             {'priority': '0:-10000'}, {'priority': '1:'}, {'priority': None}, {'group': 1, 'order': 2},
                             {}, [1], 4):
                    resp = await h.client.post(url, json=body, headers=prof)
                    assert resp.status == 400, body
                    assert 'priority must be "group:order", two integers from -9999 to 9999' \
                        in (await resp.json())['error'], body
                resp = await h.client.post(url, data=b'seven', headers=prof)
                assert resp.status == 400 and 'JSON body' in (await resp.json())['error']
                resp = await h.client.post('/api/pool/hosts/nope/priority', json={'priority': '1:1'}, headers=prof)
                assert resp.status == 404
                assert await priority_of(h) == '-3:4'               # the refused calls changed nothing
                # the token (sre-web-tool priority); the limits are priorities; one integer: that order in group 0
                resp = await h.client.post(url, json={'priority': '9999:-9999'}, headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['priority'] == '9999:-9999'
                resp = await h.client.post(url, json={'priority': 7}, headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())['priority'] == '0:7'
            async with P.Harness(tmp_path / 'again', auth_mode='proxy', web_over=over,
                                 host_over={'priority': '1:2'}) as h:
                assert await priority_of(h) == '0:7'
                assert h.portal.pool.runtime['a01'].priority == (0, 7) and h.portal.pool.hosts['a01'].priority == (1, 2)
            # the configuration gives the host another priority: it is followed, nothing by hand is left
            async with P.Harness(tmp_path / 'edited', auth_mode='proxy', web_over=over,
                                 host_over={'priority': '1:4'}) as h:
                assert await priority_of(h) == '1:4'
                assert json.loads(state.read_text())['priority'] == {}
            lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
            asked = [(l['login'], l['priority'], l['status']) for l in lines
                     if l['event'] == 'admin' and 'priority' in l]
            assert asked == [('prof', '-3:4', '200'), ('', '9999:-9999', '200'), ('', '0:7', '200')]
            refused = [l for l in lines if l['event'] == 'admin' and l['path'] == url and l['status'] == '400']
            assert len(refused) == 12 and all('priority' not in l for l in refused)
        run(go())

    def test_usable_capacity(self, tmp_path):
        """The share of a host its projects may fill, a percentage: set with the token
        (``sre-web-tool usable-capacity``) or by an instructor, told by the row, kept in the
        state file and across a restart, in the ``admin`` line of the connection log; what is
        no percentage is refused; an edit of the configuration wins."""
        state = tmp_path / 'state' / 'pool.json'
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL,
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}
        bob, prof = {**P.who('bob'), **CSRF}, {**P.who('prof', groups=P.TEACHERS), **CSRF}
        url, key = '/api/pool/hosts/a01/usable-capacity', 'total_usable_capacity'

        async def share_of(h):
            return (await (await h.client.get('/api/pool', headers=prof)).json())[0][key]

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over, host_over={key: 80}) as h:
                assert await share_of(h) == 80                      # the one of the configuration
                assert (await h.client.post(url, json={key: 50}, headers=bob)).status == 403
                resp = await h.client.post(url, json={key: 50}, headers=prof)
                assert resp.status == 200, await resp.text()
                row = await resp.json()
                assert row['name'] == 'a01' and row[key] == 50 and row['state'] == 'up'
                assert json.loads(state.read_text())[key] == {'a01': {'value': 50, 'configured': 80}}
                for body in ({key: 0}, {key: 101}, {key: -5}, {key: True}, {key: 12.5}, {key: '50'}, {key: None},
                             {'percent': 50}, {}, [50], 50):
                    resp = await h.client.post(url, json=body, headers=prof)
                    assert resp.status == 400, body
                    assert 'total_usable_capacity must be a percentage, an integer from 1 to 100' \
                        in (await resp.json())['error'], body
                resp = await h.client.post(url, data=b'half', headers=prof)
                assert resp.status == 400 and 'JSON body' in (await resp.json())['error']
                resp = await h.client.post('/api/pool/hosts/nope/usable-capacity', json={key: 50}, headers=prof)
                assert resp.status == 404
                assert await share_of(h) == 50                      # the refused calls changed nothing
                # the token (sre-web-tool usable-capacity); the limits are percentages
                resp = await h.client.post(url, json={key: 1}, headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())[key] == 1
                resp = await h.client.post(url, json={key: 100}, headers=auth(ADMIN))
                assert resp.status == 200 and (await resp.json())[key] == 100
            async with P.Harness(tmp_path / 'again', auth_mode='proxy', web_over=over, host_over={key: 80}) as h:
                assert await share_of(h) == 100
                pool = h.portal.pool
                assert pool.runtime['a01'].total_usable_capacity == 100 and pool.hosts['a01'].total_usable_capacity == 80
            # the configuration gives the host another share: it is followed, nothing by hand is left
            async with P.Harness(tmp_path / 'edited', auth_mode='proxy', web_over=over, host_over={key: 60}) as h:
                assert await share_of(h) == 60
                assert json.loads(state.read_text())[key] == {}
            lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
            asked = [(l['login'], l[key], l['status']) for l in lines if l['event'] == 'admin' and key in l]
            assert asked == [('prof', '50', '200'), ('', '1', '200'), ('', '100', '200')]
            refused = [l for l in lines if l['event'] == 'admin' and l['path'] == url and l['status'] == '400']
            assert len(refused) == 12 and all(key not in l for l in refused)
        run(go())

    def test_reset_settings(self, tmp_path):
        """``POST /api/pool/reset-settings``: the priority and the usable capacity of every
        host back to the values of the configuration, for an instructor (the button of the
        Pool page) or the token (``sre-web-tool reset-settings``).  The rows tell the
        configured values, the state file forgets what was set by hand, the ``admin`` line of
        the connection log counts the hosts."""
        state = tmp_path / 'state' / 'pool.json'
        over = {**P.PROXY_OVER, 'admin': {'token': ADMIN, 'state_file': str(state)}, 'pool': QUIET_POOL,
                'access_log': {'file': str(tmp_path / 'access.log'), 'journal': False}}
        teacher = P.who('prof', groups=P.TEACHERS)
        bob, prof = {**P.who('bob'), **CSRF}, {**teacher, **CSRF}
        url = '/api/pool/reset-settings'

        async def rows(h):
            return {row['name']: row for row in await (await h.client.get('/api/pool', headers=prof)).json()}

        def settings(row):
            return row['priority'], row['total_usable_capacity']

        def configured(row):
            return row['priority_configured'], row['total_usable_capacity_configured']

        async def go():
            async with P.Harness(tmp_path, auth_mode='proxy', web_over=over,
                                 host_over={'priority': '1:2', 'total_usable_capacity': 80}) as h:
                added = {'name': 'b02', 'url': 'http://127.0.0.1:9', 'token': TOKEN, 'priority': '3:0',
                         'total_usable_capacity': 40}
                assert (await h.client.post('/api/pool/hosts', json=added, headers=auth(ADMIN))).status == 201
                seen = await rows(h)
                assert configured(seen['a01']) == settings(seen['a01']) == ('1:2', 80)
                assert configured(seen['b02']) == settings(seen['b02']) == ('3:0', 40)
                # nothing set by hand: nothing to reset
                resp = await h.client.post(url, headers=prof)
                assert resp.status == 200 and await resp.json() == {'reset': []}
                for name, action, body in (('a01', 'priority', {'priority': '0:9'}),
                                           ('a01', 'usable-capacity', {'total_usable_capacity': 10}),
                                           ('b02', 'usable-capacity', {'total_usable_capacity': 100})):
                    resp = await h.client.post(f'/api/pool/hosts/{name}/{action}', json=body, headers=prof)
                    assert resp.status == 200, await resp.text()
                seen = await rows(h)
                assert settings(seen['a01']) == ('0:9', 10) and settings(seen['b02']) == ('3:0', 100)
                assert configured(seen['a01']) == ('1:2', 80) and configured(seen['b02']) == ('3:0', 40)
                saved = json.loads(state.read_text())
                assert set(saved['priority']) == {'a01'} and set(saved['total_usable_capacity']) == {'a01', 'b02'}
                # a student, an instructor's call without the CSRF header: refused, nothing changes
                assert (await h.client.post(url, headers=bob)).status == 403
                resp = await h.client.post(url, headers=teacher)
                assert resp.status == 403 and 'X-Requested-With' in (await resp.json())['error']
                assert settings((await rows(h))['a01']) == ('0:9', 10)
                resp = await h.client.post(url, headers=prof)
                assert resp.status == 200 and await resp.json() == {'reset': ['a01', 'b02']}
                seen = await rows(h)
                assert settings(seen['a01']) == ('1:2', 80)
                assert settings(seen['b02']) == ('3:0', 40)         # the entry it was added with
                saved = json.loads(state.read_text())
                assert saved['priority'] == {} and saved['total_usable_capacity'] == {}
                assert [entry['name'] for entry in saved['added']] == ['b02']
                # the token (sre-web-tool reset-settings)
                resp = await h.client.post('/api/pool/hosts/a01/priority', json={'priority': '5:5'}, headers=auth(ADMIN))
                assert resp.status == 200
                resp = await h.client.post(url, headers=auth(ADMIN))
                assert resp.status == 200 and await resp.json() == {'reset': ['a01']}
                assert settings((await rows(h))['a01']) == ('1:2', 80)
            lines = [parse_line(l) for l in (tmp_path / 'access.log').read_text().splitlines()]
            done = [(l['login'], l['hosts']) for l in lines
                    if l['event'] == 'admin' and l['path'] == url and l['status'] == '200']
            assert done == [('prof', '0'), ('prof', '2'), ('', '1')]
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
                assert lines[0].split() == ['NAME', 'STATE', 'PROJECTS', 'LOAD', 'FREE', 'MEM', 'CPU', 'TERMINALS',
                                            'OCCUPIED', 'UPTIME', 'SOURCE', 'LAST', 'ERROR']
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
                assert 'memory per project: not checked\n' in r.stdout and 'placement' not in r.stdout
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
                # priority: group:order, a negative group too, shown by list for the hosts that have one;
                # one integer is that order in group 0; add --priority
                assert 'priority' not in r.stdout
                r = await loop.run_in_executor(None, cli, 'priority', 'a01', '-2:5')
                assert r.returncode == 0, r.stderr
                assert r.stdout.splitlines()[1].split()[:4] == ['a01', 'up', '(priority', '-2:5)']
                assert json.loads(state.read_text())['priority'] == {'a01': {'value': '-2:5', 'configured': '0:0'}}
                r = await loop.run_in_executor(None, lambda: cli('priority', 'b02', '5', '--json'))
                assert r.returncode == 0 and json.loads(r.stdout)['priority'] == '0:5'
                r = await loop.run_in_executor(None, cli, 'list')
                assert '(priority -2:5)' in r.stdout.splitlines()[1]
                assert '(instructors, priority 0:5)' in r.stdout.splitlines()[2]
                r = await loop.run_in_executor(None, cli, 'priority', 'a01', '-2')
                assert r.returncode == 0 and '(priority 0:-2)' in r.stdout.splitlines()[1], r.stderr
                r = await loop.run_in_executor(None, cli, 'priority', 'a01', '0:0')
                assert r.returncode == 0 and 'priority' not in r.stdout     # the default: not shown
                for bad in ('10000:0', 'high', '1:', '1:2:3'):              # refused by the tool, nothing sent
                    r = await loop.run_in_executor(None, cli, 'priority', 'a01', bad)
                    assert r.returncode == 2 and 'the priority must be "group:order"' in r.stderr, bad
                r = await loop.run_in_executor(None, cli, 'priority', 'nope', '1:1')
                assert r.returncode == 1 and '(404)' in r.stderr
                r = await loop.run_in_executor(None, lambda: cli('add', 'c03', '--url', 'http://127.0.0.1:9',
                                                                 '--token', TOKEN, '--priority', '-4:1', '--json'))
                assert r.returncode == 0 and json.loads(r.stdout)['priority'] == '-4:1', r.stderr
                assert [e['priority'] for e in json.loads(state.read_text())['added']] == ['0:0', '-4:1']
                # usable-capacity: a percentage, shown by list for the hosts that are not at 100; add
                # --total-usable-capacity
                r = await loop.run_in_executor(None, cli, 'list')
                assert 'capacity' not in r.stdout
                r = await loop.run_in_executor(None, cli, 'usable-capacity', 'a01', '50')
                assert r.returncode == 0, r.stderr
                assert r.stdout.splitlines()[1].split()[:4] == ['a01', 'up', '(capacity', '50%)']
                assert json.loads(state.read_text())['total_usable_capacity'] == {'a01': {'value': 50, 'configured': 100}}
                r = await loop.run_in_executor(None, lambda: cli('usable-capacity', 'b02', '25', '--json'))
                assert r.returncode == 0 and json.loads(r.stdout)['total_usable_capacity'] == 25
                r = await loop.run_in_executor(None, cli, 'list')
                assert '(capacity 50%)' in r.stdout.splitlines()[1]
                assert '(instructors, priority 0:5, capacity 25%)' in r.stdout.splitlines()[2]
                r = await loop.run_in_executor(None, cli, 'usable-capacity', 'a01', '100')
                assert r.returncode == 0 and 'capacity' not in r.stdout     # the whole host: not shown
                for bad in ('0', '101', '-5', '12.5', 'half', '50%'):       # refused by the tool, nothing sent
                    r = await loop.run_in_executor(None, cli, 'usable-capacity', 'a01', bad)
                    assert r.returncode == 2 and 'the usable capacity must be a percentage' in r.stderr, bad
                r = await loop.run_in_executor(None, cli, 'usable-capacity', 'nope', '50')
                assert r.returncode == 1 and '(404)' in r.stderr
                r = await loop.run_in_executor(None, lambda: cli('add', 'd04', '--url', 'http://127.0.0.1:9',
                                                                 '--token', TOKEN, '--total-usable-capacity', '40',
                                                                 '--json'))
                assert r.returncode == 0 and json.loads(r.stdout)['total_usable_capacity'] == 40, r.stderr
                assert [e['total_usable_capacity'] for e in json.loads(state.read_text())['added']] == [100, 100, 40]
                r = await loop.run_in_executor(None, cli, 'remove', 'd04')
                assert r.returncode == 0, r.stderr
                # reset-settings: the priority and the usable capacity of every host back to the
                # configuration (b02: 0:5 and 25 % set above, over the 0:0 and 100 it was added with)
                saved = json.loads(state.read_text())
                assert set(saved['priority']) == {'b02'} and set(saved['total_usable_capacity']) == {'b02'}
                r = await loop.run_in_executor(None, cli, 'reset-settings')
                assert r.returncode == 0 and r.stdout.strip() == 'settings reset on 1 host(s): b02', r.stderr
                saved = json.loads(state.read_text())
                assert saved['priority'] == {} and saved['total_usable_capacity'] == {}
                r = await loop.run_in_executor(None, cli, 'list')
                assert 'capacity' not in r.stdout and '(instructors)' in r.stdout.splitlines()[2]
                assert '(priority -4:1)' in r.stdout.splitlines()[3]       # c03: the priority it was added with
                r = await loop.run_in_executor(None, cli, 'reset-settings')
                assert r.returncode == 0 and r.stdout.strip() == 'nothing to reset'
                r = await loop.run_in_executor(None, lambda: cli('reset-settings', '--json'))
                assert r.returncode == 0 and json.loads(r.stdout) == {'reset': []}
                r = await loop.run_in_executor(None, cli, 'remove', 'c03')
                assert r.returncode == 0, r.stderr
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

    def test_free_memory_and_memory_full(self, tmp_path, monkeypatch):
        """The MemAvailable the agent sends reaches the FREE MEM column; with project_memory_mb a
        host whose memory holds no more project is ``(memory full)`` in ``list`` and named by
        ``status``; ``placement``, the key of 0.18 that is no longer used, is read and not told."""
        from sreweb.agent import app as agent_app
        monkeypatch.setattr(agent_app, '_mem_available_mb', lambda path=None: 3000)
        over = {'admin': {'token': ADMIN}, 'pool': {**QUIET_POOL, 'placement': 'pack', 'project_memory_mb': 1000}}

        async def go():
            async with P.Harness(tmp_path, web_over=over) as h:
                url = f"http://127.0.0.1:{h.client.port}"
                env = {**os.environ, 'PYTHONPATH': str(SRC)}

                def cli(*args):
                    return subprocess.run([sys.executable, '-m', 'sreweb.tool', '--url', url, '--token', ADMIN,
                                           *args], capture_output=True, text=True, env=env, timeout=120)
                loop = asyncio.get_running_loop()
                row = await pool_row(h, lambda row: row['mem_available_mb'] == 3000)
                assert row['memory_room'] == 3
                r = await loop.run_in_executor(None, cli, 'list')
                assert r.returncode == 0, r.stderr
                cells = r.stdout.splitlines()[1].split()
                assert cells[:3] == ['a01', 'up', '0/3'] and cells[4] == '2.9G'    # cells[3]: the load of this machine
                r = await loop.run_in_executor(None, cli, 'status')
                assert r.returncode == 0 and 'memory per project: 1000 MiB (memory full: none)\n' in r.stdout
                assert 'placement' not in r.stdout
                h.portal.pool.project_memory_mb = 4000                 # 3000 MiB hold no project of 4000
                r = await loop.run_in_executor(None, cli, 'list')
                assert r.stdout.splitlines()[1].split()[:4] == ['a01', 'up', '(memory', 'full)']
                r = await loop.run_in_executor(None, cli, 'status')
                assert 'memory per project: 4000 MiB (memory full: a01)\n' in r.stdout
                assert 'spare capacity: 0 project slot(s)' in r.stdout   # the elastic pool counts the memory
                with pytest.raises(PoolError) as e:
                    h.portal.pool.pick()
                assert e.value.status == 503 and 'no host' in e.value.message
        run(go())

    def test_costs_of_the_labs(self, tmp_path, monkeypatch):
        """``GET /api/pool/costs`` and ``sre-web-tool costs``: what a project of each lab is
        counted for.  The weights come with the lab list of the agent (the fake sre gives them),
        the measures with its status; the file is beside the state file; ``list`` and ``status``
        show the processors."""
        from sreweb.agent import app as agent_app
        monkeypatch.setattr(agent_app, '_mem_available_mb', lambda path=None: 12000)
        monkeypatch.setattr(agent_app, '_mem_total_mb', lambda path=None: 16000)
        monkeypatch.setattr(agent_app.os, 'cpu_count', lambda: 8)
        state = tmp_path / 'state' / 'pool.json'
        over = {'admin': {'token': ADMIN, 'state_file': str(state)},
                'pool': {**QUIET_POOL, 'weight_memory_mb': 20, 'weight_cpu': 0.01, 'cpu_target': 0.5}}
        weights = {'MOCK_LAB_WEIGHTS': json.dumps({'sre/dhcp.py': 15, 's4/tp_ssh': 4})}

        async def go():
            async with P.Harness(tmp_path, web_over=over, mock_env=weights) as h:
                url = f"http://127.0.0.1:{h.client.port}"
                env = {**os.environ, 'PYTHONPATH': str(SRC)}

                def cli(*args):
                    return subprocess.run([sys.executable, '-m', 'sreweb.tool', '--url', url, '--token', ADMIN,
                                           *args], capture_output=True, text=True, env=env, timeout=120)
                loop = asyncio.get_running_loop()
                assert h.portal.pool.costs_file == str(state.parent / 'pool-costs.json')
                # nothing known yet: the header lines and an empty table
                costs = await (await h.client.get('/api/pool/costs', headers=auth(ADMIN))).json()
                assert costs['labs'] == [] and costs['default'] == {'mem_mb': 512.0, 'cpu': 0.2}
                assert costs['weight_unit'] == {'mem_mb': 20, 'cpu': 0.01} and costs['measured_unit'] is None
                assert (costs['file'], costs['error']) == (str(state.parent / 'pool-costs.json'), '')
                # the lab list of the Open page declares the weights
                await h.portal.pool.labs(Identity(login='alice'))
                costs = await (await h.client.get('/api/pool/costs', headers=auth(ADMIN))).json()
                assert {row['lab']: (row['weight'], row['mem_mb'], row['cpu'], row['source']) for row in costs['labs']} == {
                    's4/tp_ssh': (4, 80.0, 0.04, 'declared'), 'sre/dhcp.py': (15, 300.0, 0.15, 'declared')}
                # three projects of a lab measured on a host: their figures replace the weight
                h.portal.pool.costs.observe(
                    [Usage(name=f'p{i}', lab='sre/dhcp.py', containers=15, mem_mb=400.0 + i, cpu=0.3, settled=True)
                     for i in range(3)], time.time())
                r = await loop.run_in_executor(None, cli, 'costs')
                assert r.returncode == 0, r.stderr
                lines = r.stdout.splitlines()
                assert lines[0] == 'a lab never seen, without weight: 512 MiB, 0.2 core'
                assert lines[1] == 'one unit of weight: 20 MiB, 0.01 core (measured on this pool: 26.7 MiB, 0.02 core)'
                assert lines[2] == f"costs: {state.parent / 'pool-costs.json'}"
                assert lines[3].split() == ['LAB', 'WEIGHT', 'CONTAINERS', 'MEMORY', 'CPU', 'PROJECTS', 'SOURCE']
                assert [line.split() for line in lines[4:]] == [
                    ['s4/tp_ssh', '4', '-', '80M', '0.040', '0', 'declared'],
                    ['sre/dhcp.py', '15', '15', '402M', '0.300', '3', 'measured']]
                r = await loop.run_in_executor(None, cli, 'costs', '--json')
                assert r.returncode == 0 and [row['lab'] for row in json.loads(r.stdout)['labs']] == ['s4/tp_ssh', 'sre/dhcp.py']
                # the processors of the hosts: none counted on an empty host, half of its 8 cores usable
                row = await pool_row(h, lambda row: row['cpus'] == 8)
                assert (row['mem_total_mb'], row['cpu_used'], row['cpu_capacity']) == (16000, 0.0, 4.0)
                r = await loop.run_in_executor(None, cli, 'list')
                assert r.stdout.splitlines()[1].split()[4:6] == ['11.7G', '0.0/4.0']
                r = await loop.run_in_executor(None, cli, 'status')
                assert ('load of a host: 1024 MiB of memory kept free, 50 % of its processors for the projects; '
                        'one unit of weight: 20 MiB, 0.01 core\n') in r.stdout
            # the stop of the portal wrote the costs: a restart finds them again
            saved = json.loads((state.parent / 'pool-costs.json').read_text())
            assert saved['labs']['sre/dhcp.py']['weight'] == 15 and len(saved['labs']['sre/dhcp.py']['samples']) == 3
        run(go())

    def test_capacity_resources(self, tmp_path, monkeypatch):
        """``[pool] capacity = "resources"`` on a real portal and agent: a host whose processors
        hold no more project takes none (503), is ``(cpu full)`` in ``list`` and named by
        ``status``, and is no spare capacity; without the key the same host goes on by its
        number of projects."""
        from sreweb.agent import app as agent_app
        monkeypatch.setattr(agent_app, '_mem_available_mb', lambda path=None: 12000)
        monkeypatch.setattr(agent_app, '_mem_total_mb', lambda path=None: 16000)
        monkeypatch.setattr(agent_app.os, 'cpu_count', lambda: 1)       # 0.3 core for the projects
        pool = {**QUIET_POOL, 'cpu_target': 0.3}

        async def go(directory, capacity, expected):
            over = {'admin': {'token': ADMIN}, 'pool': {**pool, **capacity}}
            async with P.Harness(directory, web_over=over) as h:
                url = f"http://127.0.0.1:{h.client.port}"
                env = {**os.environ, 'PYTHONPATH': str(SRC)}

                def cli(*args):
                    return subprocess.run([sys.executable, '-m', 'sreweb.tool', '--url', url, '--token', ADMIN,
                                           *args], capture_output=True, text=True, env=env, timeout=120)
                loop = asyncio.get_running_loop()
                await h.login()
                await pool_row(h, lambda row: row['cpus'] == 1)
                # an empty host takes a project whatever it costs; a lab never seen: 512 MiB, 0.2 core
                assert (await h.start())['status'] == 'created'
                # the row is asked once a status asked after the end of the start has consumed its
                # reservation: until then the project counts twice (the agent lists it, the
                # reservation holds), in the number of projects and in the load
                async with asyncio.timeout(10):
                    while h.portal.pool._reservations['a01']:
                        await asyncio.sleep(0.02)
                row = await pool_row(h, lambda row: row['projects'] == 1)
                assert row['cpu_used'] == 0.2
                assert (row['cpu_capacity'], row['cpu_room'], row['memory_room']) == expected['rooms']
                h.portal.routes.limiter._last.clear()
                resp = await h.client.post('/api/projects', json={'lab': 'sre/dhcp.py'}, headers=P.CSRF)
                assert resp.status == expected['second_start'], await resp.text()
                if resp.status == 200:
                    await resp.text()
                r = await loop.run_in_executor(None, cli, 'status')
                assert r.returncode == 0, r.stderr
                assert expected['status_line'] in r.stdout.splitlines(), r.stdout
                assert f"spare capacity: {expected['spare']} project slot(s)" in r.stdout
                r = await loop.run_in_executor(None, cli, 'list')
                assert ('(cpu full)' in r.stdout.splitlines()[1]) is expected['flag'], r.stdout
        run(go(tmp_path / 'resources', {'capacity': 'resources'},
               {'rooms': (0.3, 0, 21), 'second_start': 503, 'flag': True, 'spare': 0,
                'status_line': 'capacity: resources (a slot: 512 MiB, 0.2 core; memory full: none; cpu full: a01)'}))
        # the default: the processors are shown, and decide nothing
        run(go(tmp_path / 'projects', {},
               {'rooms': (0.3, None, None), 'second_start': 200, 'flag': False, 'spare': 1,
                'status_line': 'capacity: projects (the number of projects of a host)'}))

    def test_cost_cells(self):
        from sreweb.portal.poolctl import table, cost_rows, cost_lines, COSTS_COLUMNS
        rows = cost_rows([{'lab': 'a.py', 'weight': 2.5, 'containers': None, 'mem_mb': 40.04, 'cpu': 0.025,
                           'samples': 0, 'source': 'declared'},
                          {'lab': 'b.py', 'weight': None, 'containers': 6, 'mem_mb': 1234.5, 'cpu': 1.5,
                           'samples': 12, 'source': 'measured'}, 'junk', {'lab': 'c.py'}])
        out = table(rows, COSTS_COLUMNS).splitlines()
        assert out[1].split() == ['a.py', '2.5', '-', '40M', '0.025', '0', 'declared']
        assert out[2].split() == ['b.py', '-', '6', '1234M', '1.500', '12', 'measured']
        assert out[3].split() == ['c.py', '-', '-', '-', '-', '-']        # an older portal: nothing invented
        assert cost_lines({}) == ['a lab never seen, without weight: ?', 'one unit of weight: ? (nothing measured yet)',
                                  'costs: not kept (no state file)']
        # whatever the portal sends where a number is expected, nothing breaks the table
        assert table(cost_rows([{'lab': 'd.py', 'weight': 'x', 'containers': 15.0, 'mem_mb': None, 'cpu': True,
                                 'samples': 3.0, 'source': 'measured'}]), COSTS_COLUMNS).splitlines()[1].split() == \
            ['d.py', '-', '15', '-', '-', '3', 'measured']
        assert cost_lines({'file': '/x/pool-costs.json', 'error': 'Read-only file system'})[-1] == \
            'costs: NOT SAVED in /x/pool-costs.json: Read-only file system'

    def test_local_drain_commands(self, tmp_path):
        """``sre-web-tool allow-local-drain`` / ``forbid-local-drain``, and the drain a host asked
        for itself in ``list``; ``enable`` cancels it."""
        from SRE import local_drain
        over = {'admin': {'token': ADMIN}, 'pool': QUIET_POOL}

        async def go():
            async with P.Harness(tmp_path, web_over=over) as h:              # agent.toml: forbidden
                url = f"http://127.0.0.1:{h.client.port}"
                env = {**os.environ, 'PYTHONPATH': str(SRC)}
                loop = asyncio.get_running_loop()

                async def cli(*args):
                    return await loop.run_in_executor(None, lambda: subprocess.run(
                        [sys.executable, '-m', 'sreweb.tool', '--url', url, '--token', ADMIN, *args],
                        capture_output=True, text=True, env=env, timeout=120))
                await pool_row(h, lambda row: row['local_drain_allowed'] is False)
                r = await cli('allow-local-drain', 'a01', '--json')
                assert r.returncode == 0, r.stderr
                assert json.loads(r.stdout)['local_drain_allowed'] is True
                local_drain.write_request(local_drain.request_path(str(h.pub)), local_drain.boot_id())
                await pool_row(h, lambda row: row['local_drain'])
                r = await cli('list')
                assert r.returncode == 0 and r.stdout.splitlines()[1].split()[:4] == ['a01', 'draining', '(local', 'drain)']
                r = await cli('enable', 'a01')
                assert r.returncode == 0 and r.stdout.splitlines()[1].split()[:3] == ['a01', 'up', '0/3']
                r = await cli('forbid-local-drain', 'a01', '--json')
                assert r.returncode == 0 and json.loads(r.stdout)['local_drain_allowed'] is False
                r = await cli('forbid-local-drain', 'nope')
                assert r.returncode == 1 and '(404)' in r.stderr
                r = await cli('allow-local-drain')
                assert r.returncode == 2
        run(go())

    def test_table_cells(self):
        from sreweb.portal.poolctl import table
        rows = [{'name': 'a01', 'state': 'waking', 'waking_for': 12, 'wake_failures': 1, 'reachable': False,
                 'error': 'down', 'source': 'config', 'max_projects': 3},
                {'name': 'b02', 'state': 'up', 'drain': True, 'reachable': True, 'projects': 2, 'max_projects': 3,
                 'load1': 1.234, 'mem_available_mb': 12595, 'terminals': 4, 'occupied_by': ['session:bob'],
                 'uptime': 3725, 'source': 'added', 'cpu_used': 3.24, 'cpu_capacity': 11.2},
                {'name': 'c03', 'state': 'off', 'instructors_only': True, 'reachable': False, 'source': 'config',
                 'max_projects': 3, 'restart_sent': True}]
        out = table(rows).splitlines()
        assert out[1].split()[:2] == ['a01', 'waking'] and '(12s, 1 failed)' in out[1] and out[1].endswith('down')
        # CPU: the cores the projects of the host are counted for / those they may use
        assert out[2].split() == ['b02', 'up', '(drain)', '2/3', '1.23', '12.3G', '3.2/11.2', '4', 'session:bob',
                                  '1h02', 'added']
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
        # a drain the host asked for itself (sre set-drain there): told in every state
        assert _cell({'state': 'draining', 'drain': True, 'local_drain': True}, 'state') == 'draining (local drain)'
        assert _cell({'state': 'occupied', 'drain': True, 'local_drain': True}, 'state') == 'occupied (local drain)'
        assert _cell({'state': 'draining', 'drain': True, 'local_drain': False}, 'state') == 'draining'
        # the priority (group:order), when it is not the default; a portal of before the groups tells one integer
        assert _cell({'state': 'up', 'priority': '0:0'}, 'state') == 'up'
        assert _cell({'state': 'off', 'priority': '0:-3'}, 'state') == 'off (priority 0:-3)'
        assert _cell({'state': 'up', 'instructors_only': True, 'priority': '2:12'}, 'state') \
            == 'up (instructors, priority 2:12)'
        assert _cell({'state': 'up', 'priority': 0}, 'state') == 'up'
        assert _cell({'state': 'off', 'priority': -3}, 'state') == 'off (priority -3)'
        # the share of the host its projects may fill, when it is not the whole host (an older portal: nothing)
        assert _cell({'state': 'up', 'total_usable_capacity': 100}, 'state') == 'up'
        assert _cell({'state': 'up', 'total_usable_capacity': 50}, 'state') == 'up (capacity 50%)'
        assert _cell({'state': 'off', 'instructors_only': True, 'priority': '2:12', 'total_usable_capacity': 1},
                     'state') == 'off (instructors, priority 2:12, capacity 1%)'
        # the free memory (an older agent or portal: none) and a host whose memory takes no more project
        assert _cell({'reachable': True, 'mem_available_mb': 2048}, 'mem_available_mb') == '2.0G'
        assert _cell({'reachable': True}, 'mem_available_mb') == '-'
        assert _cell({'reachable': False, 'mem_available_mb': 2048}, 'mem_available_mb') == ''
        assert _cell({'state': 'up', 'reachable': True, 'memory_room': 0}, 'state') == 'up (memory full)'
        assert _cell({'state': 'up', 'reachable': True, 'memory_room': 1}, 'state') == 'up'
        assert _cell({'state': 'up', 'reachable': True, 'memory_room': None}, 'state') == 'up'
        assert _cell({'state': 'off', 'reachable': False, 'memory_room': 0}, 'state') == 'off'

    def test_add_sends_the_priority_only_when_one_is_given(self, capsys):
        """A portal still running older code (synced, not restarted yet) refuses a host entry it
        does not understand: ``add`` without ``--priority`` sends the body it always sent."""
        from sreweb.portal import poolctl
        bodies = []

        def call(method, path, body=None):
            bodies.append((method, path, body))
            return {'name': body['name'], 'state': 'off', 'reachable': False}
        client = types.SimpleNamespace(call=call)
        args = dict(command='add', name='b02', host_url='http://b02', host_token=TOKEN, max_projects=25, mac='',
                    wake_command='', power=False, instructors_only=False, json=False, total_usable_capacity=None)
        assert poolctl._dispatch(client, types.SimpleNamespace(**args, priority=None)) == 0
        assert poolctl._dispatch(client, types.SimpleNamespace(**args, priority=poolctl._priority('1:-3'))) == 0
        assert poolctl._dispatch(client, types.SimpleNamespace(**args, priority=poolctl._priority('0:0'))) == 0
        assert [(method, path) for method, path, _ in bodies] == [('POST', '/api/pool/hosts')] * 3
        assert 'priority' not in bodies[0][2] and bodies[1][2]['priority'] == '1:-3'
        assert bodies[2][2]['priority'] == '0:0'            # given, though the default: sent
        assert poolctl._priority('-7') == '0:-7'            # one integer: that order in group 0
        # the same for the share of the host: sent when given, the default too
        for share in (40, 100):
            assert poolctl._dispatch(client, types.SimpleNamespace(**{**args, 'total_usable_capacity': share},
                                                                 priority=None)) == 0
        assert [body['total_usable_capacity'] for _, _, body in bodies[3:]] == [40, 100]
        assert 'priority' not in bodies[3][2] and poolctl._usable_capacity('100') == 100
        assert set(bodies[0][2]) == {'name', 'url', 'token', 'max_projects', 'mac', 'wake_command', 'power',
                                     'instructors_only'}
        capsys.readouterr()

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
