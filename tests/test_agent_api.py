"""Tests of the HTTP API of the agent (sreweb.agent.app) against the fake sre of tests/mock_sre.py."""
import asyncio
import json
import os
import pwd
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")
from aiohttp.test_utils import TestServer, TestClient  # noqa: E402

from SRE import params
from sreweb.agent.app import Agent, TERMINAL_SUBPROTOCOL, DISPLAY_SUBPROTOCOL, PROBE_DELAY, unit_of_cgroup
from sreweb.agent.display import parse_xauthority, WS_DISPLAY_FAILED
from sreweb.config import agent_config_from_dict
from sreweb.identity import Identity

MOCK = Path(__file__).parent / 'mock_sre.py'
MOCK_XVNC = Path(__file__).parent / 'mock_xvnc.py'
TOKEN = 't' * 32
ALICE = Identity(login='alice', fullname='Alice A', email='a@x.org', language='fr', group='INFO1')
BOB = Identity(login='bob')
PROF = Identity(login='prof', role='instructor', view='instructor')
PROF_NOVIEW = Identity(login='prof', role='instructor')
TEXT_HASH = 'cfc140584d209e6d8ed82f6db72c91a210cb1f2ded6a6b66f81c17e16ac2b857'
FORM_HASH = 'e87736964454b2a575c2eb84df9bcb7440abd31fd2a722c99a0e20a8f2c3b4f2'


def headers(identity=ALICE, token=TOKEN):
    h = {'Authorization': f'Bearer {token}'}
    if identity is not None:
        h.update(identity.headers())
    return h


class Harness:
    """An agent on the fake sre, in a temporary SRE_PUB_DIR, and an aiohttp test client."""

    def __init__(self, tmp_path, mock_env=None, **cfg_over):
        self.pub = tmp_path / 'pub'
        (self.pub / 'projects').mkdir(parents=True, exist_ok=True)   # a second agent on the same host
        exe = tmp_path / 'sre'
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" -W ignore "{MOCK}" "$@"\n')
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
        self.log = tmp_path / 'mock.log'
        env = {'SRE_PUB_DIR': str(self.pub), 'MOCK_SRE_LOG': str(self.log), **(mock_env or {})}
        cfg = agent_config_from_dict({'token': TOKEN, 'sre_exe': str(exe), 'poll_interval': 0.05,
                                      'state_dir': str(tmp_path / 'web-agent'), 'occupied_check': 'never',
                                      **cfg_over},   # never: the login sessions of the test host
                                     sre_exe=str(exe), state_dir=str(tmp_path / 'web-agent'))
        self.agent = Agent(cfg, pub_dir=str(self.pub), projects_dir=str(self.pub / 'projects'), localedirs=[],
                           hostname='pool1', extra_env=env, archive_dirs=[str(self.pub / 'archives')])
        # never the unit the test process may run in (a CI runner): TestRestart gives its own file
        self.agent.cgroup_file = str(tmp_path / 'no-cgroup')
        self.client = None

    async def __aenter__(self):
        self.client = TestClient(TestServer(self.agent.make_app()))
        await self.client.start_server()
        return self

    async def __aexit__(self, *exc):
        await self.client.close()

    def entries(self) -> list:
        """The calls of the fake sre: ``{'argv', 'env'}`` dicts."""
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def calls(self) -> list:
        return [entry['argv'] for entry in self.entries()]

    async def start(self, identity=ALICE, lab='sre/dhcp.py', **body) -> tuple:
        resp = await self.client.post('/v1/projects', json={'lab': lab, **body}, headers=headers(identity))
        assert resp.status == 200, await resp.text()
        lines = [json.loads(l) for l in (await resp.text()).splitlines()]
        return lines, lines[-1]

    async def started(self, identity=ALICE, **body) -> str:
        _, result = await self.start(identity, **body)
        assert result['status'] == 'created', result
        return result['running_lab_name']


def run(coro):
    return asyncio.run(coro)


class TestAuth:
    def test_token_and_identity(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.get('/v1/status')
                assert resp.status == 401
                resp = await h.client.get('/v1/status', headers=headers(token='x' * 32))
                assert resp.status == 401
                # the status is polled by the portal itself: the token alone is enough there
                resp = await h.client.get('/v1/labs', headers=headers(identity=None))
                assert resp.status == 400 and 'X-SRE-Login' in (await resp.json())['error']
                resp = await h.client.get('/v1/labs', headers={**headers(), 'X-SRE-Login': '../x'})
                assert resp.status == 400
                resp = await h.client.get('/v1/status', headers=headers(identity=None))
                data = await resp.json()
                assert resp.status == 200 and data['hostname'] == 'pool1' and data['projects'] == 0
                assert data['sre_version'] == params.sre_version and data['exam_mode'] is False
        run(go())


class TestAllowedClients:
    def test_refused_and_allowed_addresses(self, tmp_path):
        async def go():
            async with Harness(tmp_path, allowed_clients=['10.0.0.0/8']) as h:
                resp = await h.client.get('/v1/status', headers=headers())
                assert resp.status == 403 and 'address' in (await resp.json())['error']
                assert (await h.client.get('/v1/labs', headers=headers())).status == 403
            async with Harness(tmp_path / 'b', allowed_clients=['127.0.0.1', '::1']) as h:
                assert (await h.client.get('/v1/status', headers=headers())).status == 200
        run(go())


class TestOccupancyAndPower:
    def test_status_fields_and_power_off(self, tmp_path):
        async def go():
            async with Harness(tmp_path, allow_power_off=True, power_off_command='/usr/bin/true',
                               occupied_check='sessions') as h:
                calls = []
                import subprocess
                h.agent.run_command = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', '')   # no loginctl, no who
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['occupied'] is False and st['occupied_by'] == [] and st['managed_projects'] == 0
                assert st['power_off_allowed'] is True and 'agent_uptime' in st
                # a local session: occupied, no power off
                h.agent.run_command = lambda argv, **kw: subprocess.CompletedProcess(
                    argv, 0, "     2 1000 alice seat0 tty2\n" if argv[1] == 'list-sessions'
                    else "Name=alice\nSeat=seat0\nTTY=tty2\nClass=user\nRemote=no\nUser=1000\n", '')
                h.agent._occupancy = None
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['occupied'] is True and st['occupied_by'] == ['session:alice']
                resp = await h.client.post('/v1/power/off', headers=headers())
                assert resp.status == 409 and 'occupied' in (await resp.json())['error']
                # nobody, but a project: refused too
                h.agent.run_command = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', '')
                h.agent._occupancy = None
                rln = await h.started()
                resp = await h.client.post('/v1/power/off', headers=headers())
                assert resp.status == 409 and 'project' in (await resp.json())['error']
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['managed_projects'] == 1 and st['local_projects'] == 0
                await h.client.delete(f'/v1/projects/{rln}', headers=headers())
                h.agent._occupancy = None
                resp = await h.client.post('/v1/power/off', headers=headers())
                assert resp.status == 200 and (await resp.json()) == {'ok': True}
            async with Harness(tmp_path / 'b') as h:   # not allowed by default
                assert (await h.client.post('/v1/power/off', headers=headers())).status == 403
        run(go())

    def test_local_projects_count_as_occupied(self, tmp_path):
        async def go():
            async with Harness(tmp_path, occupied_check='projects') as h:
                rln = await h.started()
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['occupied'] is False                      # managed by this agent
                (tmp_path / 'web-agent' / f'{rln}.json').unlink()   # as a Qt-GUI project: not managed
                h.agent.registry.projects[rln].managed = False
                h.agent._occupancy = None
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['occupied'] is True and st['occupied_by'] == ['projects:1'] and st['local_projects'] == 1
        run(go())

    def test_managed_projects_closed_on_shutdown(self, tmp_path):
        async def go():
            async with Harness(tmp_path, close_projects_on_stop='shutdown') as h:
                rln = await h.started()
                h.agent.system_stopping = lambda: False
                await h.agent.close_managed_projects()
                assert (h.pub / 'projects' / rln).exists()           # a plain restart keeps them
                h.agent.system_stopping = lambda: True
                await h.agent.close_managed_projects()
                assert not (h.pub / 'projects' / rln).exists()       # the shutdown closes them
                assert h.calls()[-1] == ['--user', 'stop', rln]
        run(go())


class FakeProc:
    returncode = 0

    async def wait(self):
        return 0


def fake_spawn(spawned: list):
    async def spawn(*argv):
        spawned.append(list(argv))
        return FakeProc()
    return spawn


class TestRestart:
    SERVICE = '0::/system.slice/sre-agent.service\n'
    SCOPE = '0::/user.slice/user-0.slice/session-55.scope\n'

    def test_unit_of_cgroup(self):
        assert unit_of_cgroup(self.SERVICE) == 'sre-agent.service'
        assert unit_of_cgroup('0::/system.slice/system-x.slice/x@1.service\n') == 'x@1.service'
        assert unit_of_cgroup('12:pids:/system.slice/sysreseval-agent.service\n1:name=systemd:/system.slice/'
                              'sysreseval-agent.service\n0::/system.slice/sysreseval-agent.service\n') \
            == 'sysreseval-agent.service'
        assert unit_of_cgroup(self.SCOPE) is None and unit_of_cgroup('0::/docker/abc\n') is None
        assert unit_of_cgroup('') is None and unit_of_cgroup('garbage\n') is None

    def test_refused_outside_systemd(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                (tmp_path / 'cgroup').write_text(self.SCOPE)
                h.agent.cgroup_file = str(tmp_path / 'cgroup')
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['restart_allowed'] is False and st['restarting'] is False
                resp = await h.client.post('/v1/restart', headers=headers())
                assert resp.status == 409 and 'restart_command' in (await resp.json())['error']
                h.agent.cgroup_file = str(tmp_path / 'nope')      # no /proc at all (macOS)
                assert (await h.client.post('/v1/restart', headers=headers())).status == 409
        run(go())

    def test_own_unit_restarted(self, tmp_path):
        """The unit of the cgroup, restarted one second after the answer; a second request
        changes nothing; no new project meanwhile."""
        async def go():
            async with Harness(tmp_path) as h:
                (tmp_path / 'cgroup').write_text(self.SERVICE)
                h.agent.cgroup_file = str(tmp_path / 'cgroup')
                spawned = []
                h.agent.spawn = fake_spawn(spawned)
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['restart_allowed'] is True and st['restarting'] is False
                resp = await h.client.post('/v1/restart', headers=headers())
                assert resp.status == 200 and (await resp.json()) == {'ok': True, 'in_flight': 0}
                assert (await h.client.post('/v1/restart', headers=headers())).status == 200
                st = await (await h.client.get('/v1/status', headers=headers())).json()
                assert st['restarting'] is True and spawned == []
                resp = await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py'}, headers=headers())
                assert resp.status == 503 and 'restarting' in (await resp.json())['error']
                for _ in range(40):
                    if len(spawned) == 2:
                        break
                    await asyncio.sleep(0.1)
                assert spawned == [['systemctl', 'reset-failed', 'sre-agent.service'],
                                   ['systemctl', '--no-block', 'restart', 'sre-agent.service']]
                await asyncio.sleep(0.2)
                assert len(spawned) == 2                    # once, whatever the number of requests
        run(go())

    def test_restart_command(self, tmp_path):
        flag = tmp_path / 'restarted'
        async def go():
            async with Harness(tmp_path, restart_command=f'sh -c "touch {flag}"') as h:
                h.agent.cgroup_file = str(tmp_path / 'nope')
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['restart_allowed'] is True
                assert (await h.client.post('/v1/restart', headers=headers())).status == 200
                for _ in range(40):
                    if flag.exists():
                        break
                    await asyncio.sleep(0.1)
                assert flag.exists()
        run(go())

    def test_deferred_behind_a_start(self, tmp_path):
        """The command waits for the sre commands in flight (a start of a few seconds here);
        a new start is refused meanwhile."""
        async def go():
            async with Harness(tmp_path, mock_env={'MOCK_START_DELAY': '0.4'}) as h:
                (tmp_path / 'cgroup').write_text(self.SERVICE)
                h.agent.cgroup_file = str(tmp_path / 'cgroup')
                spawned = []
                h.agent.spawn = fake_spawn(spawned)
                start = asyncio.ensure_future(h.started())
                await asyncio.sleep(0.5)
                resp = await h.client.post('/v1/restart', headers=headers())
                assert resp.status == 200 and (await resp.json()) == {'ok': True, 'in_flight': 1}
                assert (await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py'}, headers=headers(BOB))).status == 503
                await asyncio.sleep(1.2)
                assert spawned == [] and not start.done()   # deferred: the start goes on
                rln = await start
                assert (h.pub / 'projects' / rln).exists()
                for _ in range(40):
                    if len(spawned) == 2:
                        break
                    await asyncio.sleep(0.1)
                assert len(spawned) == 2
        run(go())

    def test_shutdown_closes_the_project_pages(self, tmp_path):
        """An events WebSocket left open by a browser is closed with 1001 at the stop, instead of
        holding the shutdown for aiohttp's timeout (60 s)."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                url = f"http://127.0.0.1:{h.client.port}/v1/projects/{rln}/events"
                async with aiohttp.ClientSession() as session:    # not closed by the test client itself
                    ws = await session.ws_connect(url, headers=headers())
                    started = time.monotonic()
                    await h.client.close()
                    elapsed = time.monotonic() - started
                    msg = await asyncio.wait_for(ws.receive(), 5)
                    assert msg.type == aiohttp.WSMsgType.CLOSE and msg.data == aiohttp.WSCloseCode.GOING_AWAY
                    await ws.close()
                assert elapsed < 10, elapsed
                assert (h.pub / 'projects' / rln).exists()         # a restart keeps the projects
        run(go())


class TestLabsAndStart:
    def test_labs_cached(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                labs = await (await h.client.get('/v1/labs', headers=headers())).json()
                assert labs[0] == {'name': 'sre/dhcp.py', 'title': {'en': 'DHCP lab', 'fr': 'TP DHCP'}}
                await h.client.get('/v1/labs', headers=headers(BOB))
                assert sum(1 for c in h.calls() if 'list' in c) == 1
        run(go())

    def test_start_streams_events_and_creates_the_project(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                lines, result = await h.start(idle_timeout=7200)
                phases = [(l['phase'], l.get('status')) for l in lines]
                assert phases[0] == ('pull', 'start') and ('deploy', 'end') in phases
                assert ('project', 'created') in phases
                assert result['status'] == 'created' and result['host'] == 'pool1'
                rln = result['running_lab_name']
                assert rln.endswith('@@@sre@dhcp.py@@@alice')
                assert h.calls()[-1] == ['--user', 'start', 'sre/dhcp.py']
                projects = await (await h.client.get('/v1/projects', headers=headers())).json()
                assert [p['running_lab_name'] for p in projects] == [rln] and projects[0]['lab_name'] == 'sre@dhcp.py'
                assert await (await h.client.get('/v1/projects', headers=headers(BOB))).json() == []
                # an instructor lists their own projects; every one of the host with ?all=1
                assert await (await h.client.get('/v1/projects', headers=headers(PROF))).json() == []
                assert len(await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json()) == 1
                assert (await h.client.get('/v1/projects?all=1', headers=headers())).status == 403
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['projects'] == 1
                state = json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert state['idle_timeout'] == 7200.0
        run(go())

    def test_start_with_flavor(self, tmp_path):
        async def go():
            async with Harness(tmp_path, {'MOCK_FLAVOR_FORM': 'Clients: @@{nb:[0-9]+}@@ @@{go::Start}@@'}) as h:
                _, result = await h.start()
                assert result['status'] == 'flavor_form' and result['form'].startswith('Clients:')
                kinds = [c['kind'] for c in result['chunks'] if c['type'] == 'field']
                assert kinds == ['line', 'submit']
                rln = await h.started(flavor_json={'nb': '3', 'go': True})
                assert json.loads((h.pub / 'projects' / rln / '.private' / 'flavor.json').read_text()) == {'nb': '3', 'go': True}
            async with Harness(tmp_path / 'b', {'MOCK_FLAVOR_REFUSE': 'Max 5'}) as h:
                _, result = await h.start(flavor_json={'nb': '9'})
                assert result == {'phase': 'result', 'status': 'flavor_error', 'message': 'Max 5'}
        run(go())

    def test_start_refusals(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.post('/v1/projects', json={'lab': 'nope.py'}, headers=headers())
                assert resp.status == 404
                resp = await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py', 'idle_timeout': 'x'},
                                           headers=headers())
                assert resp.status == 400
                resp = await h.client.post('/v1/projects', data=b'junk', headers=headers())
                assert resp.status == 400
                (h.pub / params.exam_json_name).write_text('{}')
                resp = await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py'}, headers=headers())
                assert resp.status == 409
                assert await (await h.client.get('/v1/labs', headers=headers())).json() == []
            async with Harness(tmp_path / 'f', {'MOCK_FAIL': 'start'}) as h:
                _, result = await h.start()
                assert result['status'] == 'error' and 'mock failure' in result['message']
        run(go())


class TestProject:
    def test_view_answers_and_ownership(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                resp = await h.client.get(f'/v1/projects/{rln}', headers=headers())
                data = await resp.json()
                view = data['project']
                assert resp.status == 200 and view['title'] == 'TP DHCP' and view['lab_name'] == 'sre@dhcp.py'
                assert [m['name'] for m in view['machines']] == ['m1', 'm2']   # probe hidden
                assert [d['name'] for d in view['terminal_devices']] == ['m1', 'm2', 'lan']
                assert view['tabs'] == ['schema', 'informations', 'machines', 'networks', 'questions', 'evaluation',
                                        'terminals', 'apply_config']
                assert data['answers'] == {}
                # ownership
                assert (await h.client.get(f'/v1/projects/{rln}', headers=headers(BOB))).status == 403
                assert (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).status == 200
                assert (await h.client.get('/v1/projects/dhcp', headers=headers())).status == 404
                assert (await h.client.get(f'/v1/projects/{rln[:-1]}', headers=headers())).status == 404
                # answers
                resp = await h.client.put(f'/v1/projects/{rln}/answers',
                                          json={'answers': {TEXT_HASH: 'gw', FORM_HASH: {'ip': '10.0.0.1', 'ok': True}}},
                                          headers=headers())
                data = await resp.json()
                assert resp.status == 200 and data['answers'][TEXT_HASH] == 'gw'
                assert json.loads(data['answers'][FORM_HASH]) == {'ip': '10.0.0.1', 'ok': True}
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert on_disk['login'] == 'alice' and on_disk['hostname'] == 'pool1' and on_disk['language'] == 'fr'
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {'x' * 64: 'a'}},
                                          headers=headers())
                assert resp.status == 400
                # schema
                import shutil
                if shutil.which('neato'):
                    resp = await h.client.get(f'/v1/projects/{rln}/schema.svg?curved=1&sep=2', headers=headers())
                    assert resp.status == 200 and resp.content_type == 'image/svg+xml'
                    assert 'm1' in await resp.text()
                    assert (await h.client.get(f'/v1/projects/{rln}/schema.svg?order=bogus', headers=headers())).status == 400
                # touch and log
                assert (await h.client.post(f'/v1/projects/{rln}/touch', headers=headers())).status == 204
                assert (await h.client.get(f'/v1/projects/{rln}/log', headers=headers())).status == 403
        run(go())

    def test_eval_state_and_close(self, tmp_path):
        async def go():
            async with Harness(tmp_path, {'MOCK_COOLDOWN': '60'}) as h:
                rln = await h.started()
                resp = await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())
                data = await resp.json()
                assert resp.status == 200 and data['result']['grades'] and data['delay_before_self_grade'] == 60
                kinds = [r['kind'] for r in data['rows']]
                assert kinds[0] == 'part_header' and 'mark' in kinds and data['header'][0] == 'Element'
                assert h.calls()[-1] == ['--user', 'eval', '--auto-eval', rln]
                # the cooldown of the CLI
                data = await (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).json()
                assert data['result']['grades'] is None and data['rows'] == [] and 0 < data['delay_before_self_grade'] <= 60
                # a state writes cheat.json, merged into the answers
                resp = await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers())
                data = await resp.json()
                assert resp.status == 200 and data['answers'][TEXT_HASH] == '42'
                assert not (h.pub / 'projects' / rln / 'answers' / 'cheat.json').exists()
                assert (await h.client.post(f'/v1/projects/{rln}/states/initial', headers=headers())).status == 403
                assert (await h.client.post(f'/v1/projects/{rln}/states/nope', headers=headers())).status == 403
                # close: the directory is gone
                resp = await h.client.delete(f'/v1/projects/{rln}', headers=headers())
                assert resp.status == 200 and h.calls()[-1] == ['--user', 'stop', rln]
                assert not (h.pub / 'projects' / rln).exists()
                assert (await h.client.get(f'/v1/projects/{rln}', headers=headers())).status == 404
        run(go())

    def test_self_grade_refused_by_the_lab(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                info_path = h.pub / 'projects' / rln / 'info.json'
                info = json.loads(info_path.read_text())
                info['allow_self_grade'] = False
                info_path.write_text(json.dumps(info))
                os.utime(info_path, (os.path.getmtime(info_path) + 2,) * 2)
                await asyncio.sleep(0.2)   # the registry reloads info.json
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).status == 403
        run(go())

    def test_schema_pdf_and_no_export_save_restore(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                # save, restore and the Kathara export are not offered on the web
                assert (await h.client.get(f'/v1/projects/{rln}/save', headers=headers())).status == 404
                # the URL now matches the {rln} route, which has no POST: 405 (404 when no route matches at all)
                assert (await h.client.post('/v1/projects/restore', data=b'x', headers=headers())).status in (404, 405)
                assert (await h.client.get(f'/v1/projects/{rln}/export?curved=1', headers=headers())).status == 404
                # the schema PDF: the drawing of the Schema tab, rendered by the agent itself (no sre call)
                calls = len(h.calls())
                import shutil
                if shutil.which('neato'):
                    resp = await h.client.get(f'/v1/projects/{rln}/schema.pdf?curved=1&sep=4&order=reverse&icons=0',
                                              headers=headers())
                    blob = await resp.read()
                    assert resp.status == 200 and resp.content_type == 'application/pdf' and blob.startswith(b'%PDF')
                    disposition = resp.headers['Content-Disposition']
                    assert disposition.startswith('attachment; filename="') and disposition.endswith('_schema.pdf"')
                    assert (await h.client.get(f'/v1/projects/{rln}/schema.pdf?order=bogus', headers=headers())).status == 400
                assert len(h.calls()) == calls
                # the lab's export_schema_pdf flag (File → Export Schema to PDF of the GUI)
                info_path = h.pub / 'projects' / rln / 'info.json'
                info = json.loads(info_path.read_text())
                info['export_schema_pdf'] = False
                info_path.write_text(json.dumps(info))
                os.utime(info_path, (os.path.getmtime(info_path) + 2,) * 2)
                await asyncio.sleep(0.2)   # the registry reloads info.json
                assert (await h.client.get(f'/v1/projects/{rln}/schema.pdf', headers=headers())).status == 403
        run(go())


class TestWebSockets:
    def test_events(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                # a state pushes the merged answers to the subscribers
                await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers())
                msg = await asyncio.wait_for(ws.receive_json(), 5)
                assert msg['t'] == 'answers' and msg['answers'][TEXT_HASH] == '42'
                # a stop ends with the removed event
                await h.client.delete(f'/v1/projects/{rln}', headers=headers())
                msg = await asyncio.wait_for(ws.receive_json(), 5)
                assert msg == {'t': 'removed'}
                await ws.close()
        run(go())

    def test_terminal_round_trip(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?cols=100&rows=30',
                                               headers=headers(), protocols=(TERMINAL_SUBPROTOCOL,))
                assert ws.protocol == TERMINAL_SUBPROTOCOL
                assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'ready'
                await ws.send_bytes(b'echo hi\n')
                out = b''
                async with asyncio.timeout(10):
                    while b'hi' not in out.split(b'echo hi')[-1]:
                        msg = await ws.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        out += msg.data
                await ws.send_str(json.dumps({'t': 'resize', 'cols': 120, 'rows': 40}))
                await ws.send_bytes(b'stty size\n')
                async with asyncio.timeout(10):
                    while b'40 120' not in out:
                        msg = await ws.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        out += msg.data
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['terminals'] == 1
                await ws.send_bytes(b'exit\n')
                async with asyncio.timeout(10):
                    while True:
                        msg = await ws.receive()
                        if msg.type == aiohttp.WSMsgType.TEXT and json.loads(msg.data).get('t') == 'exit':
                            break
                        assert msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT), msg
                await ws.close()
                assert [c for c in h.calls() if 'connect' in c] == [['--user', 'connect', rln, 'm1']]
        run(go())

    def test_two_terminals_on_one_device(self, tmp_path):
        """Every Connect of the web opens a new terminal: two live sessions on the same machine."""
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                terms = []
                for _ in range(2):
                    ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                    assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'ready'
                    terms.append(ws)
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['terminals'] == 2
                for n, ws in enumerate(terms):
                    await ws.send_bytes(f'echo MARK{n}\n'.encode())
                    out = b''
                    async with asyncio.timeout(10):
                        while f'MARK{n}'.encode() not in out.split(b'echo MARK')[-1]:
                            msg = await ws.receive()
                            assert msg.type == aiohttp.WSMsgType.BINARY, msg
                            out += msg.data
                await terms[0].close()
                await asyncio.sleep(0.3)
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['terminals'] == 1
                assert [c for c in h.calls() if 'connect' in c] == [['--user', 'connect', rln, 'm1']] * 2
                await terms[1].close()
        run(go())

    def test_terminal_waiting_for_the_user(self, tmp_path):
        """A machine whose startup never ends shows nothing until stdin is readable (Kathara's
        "the user requests the control"): the agent probes it with a newline, on the first
        keystroke and after a few seconds of silence anyway."""
        async def go():
            async with Harness(tmp_path, {'MOCK_CONNECT_WAIT_INPUT': '1'}) as h:
                rln = await h.started()
                # silence: the automatic probe brings the prompt
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                               protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'ready'
                out = b''
                async with asyncio.timeout(PROBE_DELAY + 10):
                    while b'mock$' not in out:
                        msg = await ws.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        out += msg.data
                await ws.send_bytes(b'exit\n')
                await ws.close()
                # a keystroke right away: the probe is immediate and the keystrokes are kept
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                               protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive_json(), 5))['t'] == 'ready'
                t0 = asyncio.get_running_loop().time()
                await ws.send_bytes(b'echo hi\n')
                out = b''
                async with asyncio.timeout(PROBE_DELAY):
                    while b'hi' not in out.split(b'echo hi')[-1]:
                        msg = await ws.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        out += msg.data
                assert asyncio.get_running_loop().time() - t0 < PROBE_DELAY
                await ws.send_bytes(b'exit\n')
                await ws.close()
        run(go())

    def test_terminal_refusals(self, tmp_path):
        async def go():
            async with Harness(tmp_path, terminals_per_device=1) as h:
                rln = await h.started()
                for device, code in (('m2', 4403), ('probe', 4404), ('dmz', 4403), ('nope', 4404)):
                    ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/{device}', headers=headers(),
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                    msg = await asyncio.wait_for(ws.receive_json(), 5)
                    assert msg['t'] == 'error'
                    closing = await ws.receive()
                    assert closing.type == aiohttp.WSMsgType.CLOSE and ws.close_code == code, device
                first = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                  protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(first.receive_json(), 5))['t'] == 'ready'
                second = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                await asyncio.wait_for(second.receive_json(), 5)
                await second.receive()
                assert second.close_code == 4409
                await first.close()
        run(go())


# ---------------------------------------------------------------------------------------------
# the virtual X desktop of a project (sreweb.agent.display on the fake Xvnc of tests/mock_xvnc.py)
# ---------------------------------------------------------------------------------------------

@pytest.fixture
def short_dir():
    """A short runtime directory: an AF_UNIX socket path is limited to about 100 bytes, and
    pytest's tmp_path is longer than that on macOS."""
    d = Path(tempfile.mkdtemp(prefix='sre-x11-', dir='/tmp'))
    yield d
    shutil.rmtree(d, ignore_errors=True)


DISPLAY_USER_AS_ROOT = 'nobody'


def display_user(runtime_dir) -> str:
    """The ``[display] user`` of a test agent: ``''`` (the agent's own account) unless the suite
    runs as root (``make tests`` on an installed tree), where the agent insists on an unprivileged
    account as the service does with ``sreweb-x11``: then ``nobody``, which gets *runtime_dir* (the
    fake X server writes its log there); the test is skipped when that account cannot read the
    fake Xvnc or run the interpreter."""
    if os.geteuid() != 0:
        return ''
    try:
        entry = pwd.getpwnam(DISPLAY_USER_AS_ROOT)
    except KeyError:
        pytest.skip(f"running as root without a '{DISPLAY_USER_AS_ROOT}' account to run the fake Xvnc as")
    for path, bit in ((MOCK_XVNC, stat.S_IROTH), (Path(sys.executable), stat.S_IXOTH)):
        if not os.stat(path).st_mode & bit:
            pytest.skip(f"{path} is not accessible to {DISPLAY_USER_AS_ROOT}: the fake Xvnc cannot run as root")
    os.chown(runtime_dir, entry.pw_uid, entry.pw_gid)
    os.chmod(runtime_dir, 0o755)
    return DISPLAY_USER_AS_ROOT


def display_cfg(runtime_dir, *, fail: str = '', **over) -> dict:
    """The ``[display]`` section of a test agent: the fake X server (through a shell script giving
    it its log file, and ``MOCK_XVNC_FAIL`` when *fail* is set: the agent builds the environment of
    the server itself), no window manager, the user of :func:`display_user`, three display
    numbers."""
    script = Path(runtime_dir) / 'xvnc'
    script.write_text(f'#!/bin/sh\nexport MOCK_XVNC_LOG="{runtime_dir}/xvnc.log"\n'
                      + (f'export MOCK_XVNC_FAIL="{fail}"\n' if fail else '')
                      + f'exec "{sys.executable}" "{MOCK_XVNC}" "$@"\n')
    script.chmod(0o755)
    return {'display': {'enabled': True, 'user': display_user(runtime_dir), 'xvnc_command': str(script),
                        'window_manager_command': '', 'runtime_dir': str(runtime_dir), 'first_display': 90,
                        'last_display': 92, 'start_timeout': 10, **over}}


def x11_env(**over) -> dict:
    return {'MOCK_X11': '1', **over}


def xvnc_runs(runtime_dir) -> list:
    """What the fake X server logged: ``{'argv', 'env', 'pid'}`` per run."""
    log = Path(runtime_dir) / 'xvnc.log'
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


async def until(predicate, timeout=5.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.05)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class TestDisplay:
    def test_start_gets_a_display_and_the_browser_reaches_it(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h:
                rln = await h.started()
                env = [e for e in h.entries() if 'start' in e['argv']][0]['env']
                cookie = env['SRE_XAUTH_COOKIE']
                assert len(cookie) == 32 and int(cookie, 16) >= 0 and env['SRE_X11_DISPLAY'] == '90'
                state = json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                assert state['display'] == {'number': 90, 'cookie': cookie}
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert view['display'] == {'available': True} and view['machines'][0]['x11_host'] is True
                assert view['tabs'].index('display') == view['tabs'].index('terminals') + 1
                # the X server is started right after the project: POST reports it running
                resp = await h.client.post(f'/v1/projects/{rln}/display', headers=headers())
                assert resp.status == 200, await resp.text()
                status = await resp.json()
                assert status == {'available': True, 'running': True, 'display': 90, 'geometry': '1280x800', 'error': ''}
                assert (await (await h.client.get(f'/v1/projects/{rln}/display', headers=headers())).json()) == status
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['displays'] == 1
                xauth = short_dir / 'display' / '90.xauth'
                assert xauth.stat().st_mode & 0o777 == 0o600
                (family, address, number, name, data), = parse_xauthority(xauth.read_bytes())
                assert (family, address, number, name, data.hex()) == (0xFFFF, b'', b'90', b'MIT-MAGIC-COOKIE-1', cookie)
                runs = xvnc_runs(short_dir)
                assert len(runs) == 1
                argv = runs[0]['argv']
                assert argv[0] == ':90' and argv[argv.index('-auth') + 1] == str(xauth)
                assert argv[argv.index('-rfbunixpath') + 1] == str(short_dir / 'display' / '90.sock')
                assert '-listen' in argv and argv[argv.index('-SecurityTypes') + 1] == 'None'
                # the RFB stream: the greeting of the server, then (the fake) echoes the bytes sent
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                assert ws.protocol == DISPLAY_SUBPROTOCOL
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.BINARY and msg.data == b'RFB 003.008\n'
                await ws.send_bytes(b'RFB 003.008\n')
                await ws.send_bytes(bytes(range(256)))
                got = b''
                async with asyncio.timeout(5):
                    while len(got) < 12 + 256:
                        msg = await ws.receive()
                        assert msg.type == aiohttp.WSMsgType.BINARY, msg
                        got += msg.data
                assert got == b'RFB 003.008\n' + bytes(range(256))
                assert len(h.agent.registry.get(rln).display_clients) == 1
                await ws.close()
                await until(lambda: not h.agent.registry.get(rln).display_clients)
                # closing the project ends the X server and removes its files
                pid = runs[0]['pid']
                assert alive(pid)
                resp = await h.client.delete(f'/v1/projects/{rln}', headers=headers())
                assert resp.status == 200
                await until(lambda: h.agent.registry.get(rln) is None)
                await until(lambda: not alive(pid))
                assert not xauth.exists() and not (short_dir / 'display' / '90.sock').exists()
                assert h.agent.displays.running_count() == 0
        run(go())

    def test_lab_without_x11_machine_gets_no_display(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env={}, **display_cfg(short_dir)) as h:
                rln = await h.started()
                env = [e for e in h.entries() if 'start' in e['argv']][0]['env']
                assert env['SRE_X11_DISPLAY'] == '90' and len(env['SRE_XAUTH_COOKIE']) == 32
                assert 'display' not in json.loads((tmp_path / 'web-agent' / f'{rln}.json').read_text())
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert view['display'] == {'available': False} and 'display' not in view['tabs']
                status = await (await h.client.get(f'/v1/projects/{rln}/display', headers=headers())).json()
                assert status['available'] is False and status['display'] is None and status['running'] is False
                assert (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).status == 404
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.CLOSE and msg.data == 4404
                # the number was released: the next project gets it again
                await h.started()
                assert [e['env']['SRE_X11_DISPLAY'] for e in h.entries() if 'start' in e['argv']] == ['90', '90']
                assert xvnc_runs(short_dir) == []
        run(go())

    def test_host_without_displays(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env()) as h:
                rln = await h.started()
                env = [e for e in h.entries() if 'start' in e['argv']][0]['env']
                assert 'SRE_X11_DISPLAY' not in env and 'SRE_XAUTH_COOKIE' not in env
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['project']
                assert view['display'] == {'available': False} and view['machines'][0]['x11_host'] is True
                status = await (await h.client.get(f'/v1/projects/{rln}/display', headers=headers())).json()
                assert status['available'] is False and 'disabled' in status['error']
                assert (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).status == 404
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['displays'] == 0
        run(go())

    def test_other_user_and_exam_mode(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h:
                rln = await h.started()
                for method in (h.client.get, h.client.post):
                    assert (await method(f'/v1/projects/{rln}/display', headers=headers(BOB))).status == 403
                with pytest.raises(aiohttp.WSServerHandshakeError) as e:
                    await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(BOB),
                                              protocols=(DISPLAY_SUBPROTOCOL,))
                assert e.value.status == 403
                (h.pub / params.exam_json_name).write_text('{}')
                assert (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).status == 409
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.CLOSE and msg.data == 4403
        run(go())

    def test_dead_server_is_started_again(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h:
                rln = await h.started()
                assert (await (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).json())['running']
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive(), 5)).data == b'RFB 003.008\n'
                first = xvnc_runs(short_dir)[0]
                os.kill(first['pid'], 15)
                await until(lambda: not alive(first['pid']))
                # the viewer is told, the status says so, POST starts another server
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.CLOSE and msg.data == WS_DISPLAY_FAILED
                await until(lambda: not h.agent.displays.sessions[rln].running)
                status = await (await h.client.get(f'/v1/projects/{rln}/display', headers=headers())).json()
                assert status['running'] is False and 'exited' in status['error']
                status = await (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).json()
                assert status['running'] is True and status['error'] == ''
                runs = xvnc_runs(short_dir)
                assert len(runs) == 2 and runs[1]['pid'] != first['pid'] and runs[1]['argv'][0] == ':90'
                cookie = [e for e in h.entries() if 'start' in e['argv']][0]['env']['SRE_XAUTH_COOKIE']
                records = parse_xauthority((short_dir / 'display' / '90.xauth').read_bytes())
                assert records[0][4].hex() == cookie
        run(go())

    def test_server_failures(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir, fail='early')) as h:
                rln = await h.started()
                resp = await h.client.post(f'/v1/projects/{rln}/display', headers=headers())
                assert resp.status == 503 and 'listening sockets' in (await resp.json())['error']
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws', headers=headers(),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                msg = await asyncio.wait_for(ws.receive(), 5)
                assert msg.type == aiohttp.WSMsgType.CLOSE and msg.data == WS_DISPLAY_FAILED
                assert not (short_dir / 'display' / '90.xauth').exists()
        run(go())

    def test_agent_restart_starts_the_same_display_again(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h:
                rln = await h.started()
                assert (await (await h.client.post(f'/v1/projects/{rln}/display', headers=headers())).json())['running']
                first = xvnc_runs(short_dir)[0]
                cookie = [e for e in h.entries() if 'start' in e['argv']][0]['env']['SRE_XAUTH_COOKIE']
            await until(lambda: not alive(first['pid']))
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h2:
                assert h2.agent.registry.get(rln).display == {'number': 90, 'cookie': cookie}
                status = await (await h2.client.post(f'/v1/projects/{rln}/display', headers=headers())).json()
                assert status['running'] is True and status['display'] == 90
                runs = xvnc_runs(short_dir)
                assert len(runs) == 2 and runs[1]['argv'][0] == ':90'
                assert parse_xauthority((short_dir / 'display' / '90.xauth').read_bytes())[0][4].hex() == cookie
                # a new project of the second agent takes the next free number
                await h2.started()
                assert [e['env']['SRE_X11_DISPLAY'] for e in h2.entries() if 'start' in e['argv']][-1] == '91'
        run(go())


# ---------------------------------------------------------------------------------------------
# the instructor role: every project of the host, privileged actions on a student's project,
# the last archived evaluation, instructor-mode projects, shared and private terminals
# ---------------------------------------------------------------------------------------------

async def receive_event(ws, kind, timeout=5.0) -> dict:
    """The next event of *kind* on an events WebSocket (the others are skipped)."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive_json()
            if msg.get('t') == kind:
                return msg


async def events_of(ws, duration=1.0) -> list:
    """Every event received on *ws* during *duration* seconds."""
    seen = []
    try:
        async with asyncio.timeout(duration):
            while True:
                seen.append(await ws.receive_json())
    except TimeoutError:
        pass
    return seen


async def read_until(ws, needle: bytes, timeout=10.0, after: bytes = b'') -> bytes:
    """The binary frames of a terminal WebSocket until *needle* shows up (after the last
    occurrence of *after*, e.g. the echo of the command typed)."""
    out = b''
    async with asyncio.timeout(timeout):
        while needle not in (out.split(after)[-1] if after else out):
            msg = await ws.receive()
            assert msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT), msg
            if msg.type == aiohttp.WSMsgType.BINARY:
                out += msg.data
    return out


def privileged_call(entry: dict, argv: list, login: str):
    assert entry['argv'] == argv, entry
    assert entry['env']['LOGNAME'] == login and 'SUDO_USER' not in entry['env'] and 'USER_USERNAME' not in entry['env']
    assert entry['user_mode'] is False and entry['username'] == login


class TestInstructor:
    def test_projects_of_everyone_and_the_last_evaluation(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                assert (await h.client.get('/v1/projects?all=1', headers=headers())).status == 403
                rows = await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json()
                assert len(rows) == 1
                row = rows[0]
                # the full name and the group are written at the creation, before any answer
                assert (row['running_lab_name'], row['owner'], row['fullname'], row['group'], row['managed']) == \
                    (rln, 'alice', 'Alice A', 'INFO1', True)
                assert row['last_eval'] is None and row['terminals'] == 0 and row['eval_interval'] == 0
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert (on_disk['login'], on_disk['hostname'], on_disk['group'], on_disk['exam_mode']) == ('alice', 'pool1', 'INFO1', False)
                assert not [k for k in on_disk if len(k) == 64]       # no question entry
                assert (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['answers'] == {}
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'gw'}}, headers=headers())
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).status == 200
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert row['fullname'] == ALICE.fullname and row['group'] == 'INFO1'
                last = row['last_eval']
                assert (last['grade'], last['max_grade'], last['mark'], last['maximum_mark']) == (4.5, 5, 18.0, 20)
                assert (last['errors'], last['warnings'], last['auto_eval_count']) == (0, 0, 1)
                assert last['age_s'] >= 0 and last['archive'].endswith('.zst') and last['eval_date']
                # a second agent instance would see the same archive: the index is read on demand
                assert h.agent.results.scans >= 1
                # the group of the owner's next request wins (the directory changed it)
                from dataclasses import replace
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'gw2'}},
                                   headers=headers(replace(ALICE, group='INFO2')))
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert row['group'] == 'INFO2'
                # the file of an older agent or of the Qt GUI (no metadata): the owner's next page load
                # writes it again, a non-owner's never does; a request without the name or the group
                # (a missing header) keeps the stored values
                answers_file = h.pub / 'projects' / rln / 'answers' / 'answers.json'
                answers_file.write_text(json.dumps({TEXT_HASH: 'gw2'}))
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert (row['fullname'], row['group']) == ('', '')
                assert (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).status == 200
                assert json.loads(answers_file.read_text()) == {TEXT_HASH: 'gw2'}
                page = await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json()
                assert page['answers'] == {TEXT_HASH: 'gw2'}
                on_disk = json.loads(answers_file.read_text())
                assert (on_disk['login'], on_disk['fullname'], on_disk['group'], on_disk['hostname']) == \
                    ('alice', 'Alice A', 'INFO1', 'pool1')
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert (row['fullname'], row['group']) == ('Alice A', 'INFO1')
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'gw3'}},
                                   headers=headers(replace(ALICE, fullname='', group='')))
                on_disk = json.loads(answers_file.read_text())
                assert (on_disk['fullname'], on_disk['group'], on_disk[TEXT_HASH]) == ('Alice A', 'INFO1', 'gw3')
                assert not h.agent.answers.metadata_stale(on_disk, ALICE)
            async with Harness(tmp_path / 'b', {'MOCK_EVAL_ERRORS': '[["ERROR", "m1 down"], ["WARNING", "slow"]]'}) as h:
                rln = await h.started()
                await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())
                last = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]['last_eval']
                assert (last['errors'], last['warnings']) == (1, 1)
        run(go())

    def test_non_owner_actions_run_privileged(self, tmp_path):
        """An instructor on a student's project: sre runs privileged for them (their login, no
        --user): no cooldown, no counter, no answer of the student touched; the owner, instructor
        or not, keeps the student path."""
        async def go():
            async with Harness(tmp_path, {'MOCK_COOLDOWN': '60'}) as h:
                rln = await h.started()
                resp = await h.client.post(f'/v1/projects/{rln}/eval', headers=headers(PROF))
                data = await resp.json()
                assert resp.status == 200 and data['rows'] and data['delay_before_self_grade'] == 0
                privileged_call(h.entries()[-1], ['eval', rln], 'prof')
                assert not (h.pub / 'last_self_grades').exists()      # alice's cooldown untouched
                # alice's own evaluation afterwards is her first one (grades, not the cooldown answer)
                resp = await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())
                assert (await resp.json())['result']['grades'] is not None
                assert h.calls()[-1] == ['--user', 'eval', '--auto-eval', rln]
                # states: privileged too
                assert (await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers(PROF))).status == 200
                privileged_call(h.entries()[-1], ['state', rln, 'final'], 'prof')
                # the answers: the instructor writes in the student's file (no sre call), the
                # student's metadata kept, and every save is pushed to the pages of both
                ws_alice = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                ws_prof = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                resp = await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'x'}},
                                          headers=headers(PROF))
                assert resp.status == 200 and (await resp.json())['answers'][TEXT_HASH] == 'x'
                on_disk = json.loads((h.pub / 'projects' / rln / 'answers' / 'answers.json').read_text())
                assert (on_disk[TEXT_HASH], on_disk['login'], on_disk['fullname'], on_disk['email'],
                        on_disk['group'], on_disk['language'], on_disk['hostname']) == \
                    ('x', 'alice', 'Alice A', 'a@x.org', 'INFO1', 'fr', 'pool1')
                assert (await receive_event(ws_alice, 'answers'))['answers'][TEXT_HASH] == 'x'
                assert (await receive_event(ws_prof, 'answers'))['answers'][TEXT_HASH] == 'x'
                await h.client.put(f'/v1/projects/{rln}/answers', json={'answers': {TEXT_HASH: 'y'}}, headers=headers())
                assert (await receive_event(ws_prof, 'answers'))['answers'][TEXT_HASH] == 'y'
                assert (await receive_event(ws_alice, 'answers'))['answers'][TEXT_HASH] == 'y'
                await ws_alice.close()
                await ws_prof.close()
                privileged_call(h.entries()[-1], ['state', rln, 'final'], 'prof')
                import shutil
                if shutil.which('neato'):   # the schema PDF of a non-owner: rendered by the agent, no sre call
                    resp = await h.client.get(f'/v1/projects/{rln}/schema.pdf', headers=headers(PROF))
                    assert resp.status == 200 and (await resp.read()).startswith(b'%PDF')
                    privileged_call(h.entries()[-1], ['state', rln, 'final'], 'prof')
                data = await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json()
                assert data['owner'] == 'alice' and data['answers'][TEXT_HASH] == 'y' and 'answers_readonly' not in data
                # the student's full name (the answers metadata, kept under the instructor's
                # write): the title of the instructor's page names the student
                assert data['fullname'] == ALICE.fullname
                assert all(d['allow_connection'] for d in data['project']['terminal_devices'])
                own = await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json()
                assert own['answers'][TEXT_HASH] == 'y' and 'answers_readonly' not in own
                assert (own['owner'], own['fullname']) == ('alice', ALICE.fullname)
                assert [d['allow_connection'] for d in own['project']['terminal_devices']] == [True, False, True]
                # the instructor's own project: the student path
                mine = await h.started(PROF_NOVIEW)
                assert mine.endswith('@@@prof')
                await h.client.post(f'/v1/projects/{mine}/eval', headers=headers(PROF_NOVIEW))
                assert h.calls()[-1] == ['--user', 'eval', '--auto-eval', mine]
                assert h.entries()[-1]['env']['SUDO_USER'] == 'prof'
        run(go())

    def test_last_archived_evaluation(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                assert (await h.client.get(f'/v1/projects/{rln}/evaluation', headers=headers())).status == 403
                assert (await h.client.get(f'/v1/projects/{rln}/evaluation', headers=headers(PROF))).status == 404
                await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())
                project = h.agent.registry.require(rln)
                project.last_activity = 0.0
                resp = await h.client.get(f'/v1/projects/{rln}/evaluation', headers=headers(PROF))
                data = await resp.json()
                assert resp.status == 200
                assert project.last_activity == 0.0     # reading the results is not the student's activity
                assert data['header'] == ['Element', 'Grade', 'Max grade']
                assert [r['kind'] for r in data['rows']][-1] == 'mark' and any(r['kind'] == 'total' for r in data['rows'])
                assert (data['grade'], data['max_grade'], data['mark'], data['maximum_mark']) == (4.5, 5, 18.0, 20)
                assert data['errors'] == [] and (data['error_count'], data['warning_count']) == (0, 0)
                assert data['eval_date'] and data['archive'].endswith('.zst')
        run(go())

    def test_lab_evaluations(self, tmp_path):
        """The lab summary of the Watch page: every project of a lab with the elements of its
        last archived evaluation, matched across the students by a language-independent key."""
        async def go():
            async with Harness(tmp_path) as h:
                alice_rln = await h.started()
                bob_rln = await h.started(BOB)
                await h.client.post(f'/v1/projects/{alice_rln}/eval', headers=headers())
                assert (await h.client.get('/v1/evaluations?lab=sre@dhcp.py', headers=headers())).status == 403
                assert (await h.client.get('/v1/evaluations', headers=headers(PROF))).status == 400
                assert await (await h.client.get('/v1/evaluations?lab=other/lab.py', headers=headers(PROF))).json() == []
                for p in h.agent.registry.visible_to(PROF, all_projects=True):
                    p.last_activity = 0.0
                rows = await (await h.client.get('/v1/evaluations?lab=sre@dhcp.py', headers=headers(PROF))).json()
                assert [(r['running_lab_name'], r['owner'], r['fullname'], r['group'], r['managed']) for r in rows] == \
                    [(alice_rln, 'alice', 'Alice A', 'INFO1', True), (bob_rln, 'bob', '', '', True)]
                assert all(p.last_activity == 0.0 for p in h.agent.registry.visible_to(PROF, all_projects=True))   # idle clocks untouched
                alice, bob = rows
                assert (bob['last_eval'], bob['elements'], bob['parts']) == (None, None, None)
                assert alice['last_eval']['grade'] == 4.5 and alice['last_eval']['archive'].endswith('.zst')
                assert [(e['label'], e['grade'], e['max_grade'], e['part'], e['bonus']) for e in alice['elements']] == [
                    ('Default route of m1', 2.0, 2.0, 'Routing', False), ('Address of m2', 1.5, 3.0, 'Routing', False),
                    ('IPv6 route of m1', 1.0, 1.0, None, True)]
                assert len({e['key'] for e in alice['elements']}) == 3
                assert alice['parts'] == [{'title': 'Routing', 'label': 'Routing between lan and dmz'}]
                # the labels in the instructor's language, the keys unchanged
                prof_fr = Identity(login='prof', role='instructor', view='instructor', language='fr')
                rows_fr = await (await h.client.get('/v1/evaluations?lab=sre@dhcp.py', headers=headers(prof_fr))).json()
                assert rows_fr[0]['parts'][0]['label'] == 'Routage entre lan et dmz'
                assert [e['key'] for e in rows_fr[0]['elements']] == [e['key'] for e in alice['elements']]
        run(go())

    def test_periodic_evaluation_of_a_web_project(self, tmp_path):
        """The agent evaluates a project it created every eval_interval_without_exam_mode
        seconds as the Qt GUI does (sre --user eval, no --auto-eval: no cooldown, nothing
        counted), tells the open pages (the `evaluated` event) and the Watch page shows the new
        archive at once.  The registry finds the directory before sre start ends
        (MOCK_START_DELAY), as in production: the project must be armed when it is adopted."""
        async def go():
            async with Harness(tmp_path, {'MOCK_EVAL_INTERVAL': '1', 'MOCK_START_DELAY': '0.3'}) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                await receive_event(ws, 'evaluated', timeout=5)
                entry = h.entries()[-1]
                assert (entry['argv'], entry['user_mode'], entry['username']) == (['--user', 'eval', rln], True, 'alice')
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert row['eval_interval'] == 1 and row['managed'] is True
                first = row['last_eval']
                assert first is not None and first['auto_eval_count'] == 0 and first['grade'] == 4.5
                assert not (h.pub / 'last_self_grades').exists()
                # the next one: a new archive, shown at once
                await receive_event(ws, 'evaluated', timeout=5)
                row = (await (await h.client.get('/v1/projects?all=1', headers=headers(PROF))).json())[0]
                assert row['last_eval']['archive'] != first['archive']
                data = await (await h.client.get(f'/v1/projects/{rln}/evaluation', headers=headers(PROF))).json()
                assert data['archive'] == row['last_eval']['archive']
                await ws.close()
            # the student's own evaluation tells the pages too; one refused by the cooldown does not
            async with Harness(tmp_path / 'b', {'MOCK_COOLDOWN': '60'}) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                assert (await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())).status == 200
                await receive_event(ws, 'evaluated', timeout=5)
                resp = await h.client.post(f'/v1/projects/{rln}/eval', headers=headers())
                assert (await resp.json())['result']['grades'] is None
                assert await events_of(ws, 0.5) == []
                await ws.close()
        run(go())

    def test_instructor_mode_project(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                resp = await h.client.post('/v1/projects', json={'lab': 'sre/dhcp.py', 'instructor_mode': True},
                                           headers=headers())
                assert resp.status == 403
                rln = await h.started(PROF_NOVIEW, instructor_mode=True)
                assert rln.endswith('@@@prof')
                privileged_call([e for e in h.entries() if 'start' in e['argv']][-1],
                                ['start', '--instructor-mode', 'sre/dhcp.py'], 'prof')
                view = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json())['project']
                assert view['instructor_mode'] and view['has_instructor_texts'] and view['instructor_view']
                assert 'Solution' in view['informations_html'] and 'log' in view['tabs']
                plain = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF_NOVIEW))).json())['project']
                assert plain['has_instructor_texts'] and not plain['instructor_view']
                assert 'Solution' not in plain['informations_html'] and 'log' not in plain['tabs']
                # the student view of a plain project never holds the fragment
                other = await h.started()
                view = (await (await h.client.get(f'/v1/projects/{other}', headers=headers(PROF))).json())['project']
                assert not view['has_instructor_texts'] and 'Solution' not in view['informations_html']
        run(go())

    def test_log_reaches_the_allowed_subscribers_only(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started(PROF_NOVIEW, instructor_mode=True)
                shown = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                hidden = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF_NOVIEW))
                await h.client.post(f'/v1/projects/{rln}/states/final', headers=headers(PROF_NOVIEW))
                log_event = await receive_event(shown, 'log')
                assert 'state final' in log_event['data']
                assert [e['t'] for e in await events_of(hidden, 1.0) if e['t'] == 'log'] == []
                await shown.close()
                await hidden.close()
        run(go())


class TestSharedTerminals:
    def test_join_a_session(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                events = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                alice = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                  protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(alice.receive_json(), 5)
                assert ready['t'] == 'ready' and ready['device'] == 'm1' and ready['clients'] == 1 and not ready['joined']
                sid = ready['session']
                listed = (await receive_event(events, 'terminals'))['terminals']
                assert len(listed) == 1 and listed[0]['id'] == sid and listed[0]['created_by'] == 'alice'
                await read_until(alice, b'mock$')
                data = await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json()
                entry = data['terminals'][0]
                assert (entry['id'], entry['device'], entry['created_by'], entry['private'], entry['clients']) == \
                    (sid, 'm1', 'alice', False, 1)
                # the instructor joins: the replay, then the live session shared with alice
                prof = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?join={sid}', headers=headers(PROF),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(prof.receive_json(), 5)
                assert ready['t'] == 'ready' and ready['session'] == sid and ready['clients'] == 2 and ready['joined']
                assert b'mock$' in await read_until(prof, b'mock$')
                assert (await receive_event(events, 'terminals'))['terminals'][0]['clients'] == 2
                await prof.send_bytes(b'echo MARK\n')
                await read_until(alice, b'MARK', after=b'echo MARK')
                await read_until(prof, b'MARK', after=b'echo MARK')
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['terminals'] == 1
                # the instructor leaves: the session stays with alice
                await prof.close()
                assert (await receive_event(events, 'terminals'))['terminals'][0]['clients'] == 1
                await alice.send_bytes(b'echo STILL\n')
                await read_until(alice, b'STILL', after=b'echo STILL')
                await alice.close()
                assert (await receive_event(events, 'terminals'))['terminals'] == []
                await asyncio.sleep(0.2)
                assert (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['terminals'] == []
                assert [c for c in h.calls() if 'connect' in c] == [['--user', 'connect', rln, 'm1']]
                await events.close()
        run(go())

    def test_private_terminals_and_refusals(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()

                async def refused(path, identity, code):
                    ws = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/{path}', headers=headers(identity),
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                    msg = await asyncio.wait_for(ws.receive_json(), 5)
                    assert msg['t'] == 'error', msg
                    closing = await ws.receive()
                    assert closing.type == aiohttp.WSMsgType.CLOSE and ws.close_code == code, (path, ws.close_code)

                await refused('m1?join=nope', ALICE, 4404)
                await refused('m1?private=1', ALICE, 4403)
                # the events sockets of the student and of the instructor: each gets its own list
                alice_events = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers())
                prof_events = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                # a private terminal of the instructor on the closed machine, privileged
                prof = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m2?private=1', headers=headers(PROF),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(prof.receive_json(), 5)
                assert ready['t'] == 'ready'
                pid = ready['session']
                await read_until(prof, b'mock$')          # the fake sre logs its call before the shell
                privileged_call([e for e in h.entries() if 'connect' in e['argv']][-1], ['connect', rln, 'm2'], 'prof')
                assert (await (await h.client.get(f'/v1/projects/{rln}', headers=headers())).json())['terminals'] == []
                mine = (await (await h.client.get(f'/v1/projects/{rln}', headers=headers(PROF))).json())['terminals']
                assert [(t['id'], t['private'], t['created_by']) for t in mine] == [(pid, True, 'prof')]
                # the terminals event hides it from the student too (the focus of an instructor's
                # page follows the sub-tabs by session id: a student's page must never learn of it)
                listed = (await receive_event(prof_events, 'terminals'))['terminals']
                assert [(t['id'], t['private'], t['created_by']) for t in listed] == [(pid, True, 'prof')]
                assert (await receive_event(alice_events, 'terminals'))['terminals'] == []
                await refused(f'm2?join={pid}', ALICE, 4403)
                await refused(f'm1?join={pid}', PROF, 4404)          # the right device is part of the address
                await prof.close()
                await asyncio.sleep(0.2)
                assert (await (await h.client.get('/v1/status', headers=headers())).json())['terminals'] == 0
                assert (await receive_event(prof_events, 'terminals'))['terminals'] == []
                assert (await receive_event(alice_events, 'terminals'))['terminals'] == []
                await alice_events.close()
                await prof_events.close()
            async with Harness(tmp_path / 'b', terminals_per_device=1) as h:
                rln = await h.started()
                alice = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                  protocols=(TERMINAL_SUBPROTOCOL,))
                sid = (await asyncio.wait_for(alice.receive_json(), 5))['session']
                prof = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?join={sid}', headers=headers(PROF),
                                                 protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(prof.receive_json(), 5))['t'] == 'ready'   # a join is not a new terminal
                second = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1', headers=headers(),
                                                   protocols=(TERMINAL_SUBPROTOCOL,))
                await asyncio.wait_for(second.receive_json(), 5)
                await second.receive()
                assert second.close_code == 4409
                await prof.close()
                await alice.close()
        run(go())


# ---------------------------------------------------------------------------------------------
# the read-only clients of the spectators of a presentation: terminals and the display
# ---------------------------------------------------------------------------------------------

async def receive_text(ws, kind, timeout=5.0) -> dict:
    """The next text frame of *kind* on a terminal WebSocket (the binary frames are skipped)."""
    async with asyncio.timeout(timeout):
        while True:
            msg = await ws.receive()
            assert msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT), msg
            if msg.type == aiohttp.WSMsgType.TEXT and json.loads(msg.data).get('t') == kind:
                return json.loads(msg.data)


async def collect_bytes(ws, n: int, timeout=5.0) -> bytes:
    """*n* bytes of binary frames."""
    out = b''
    async with asyncio.timeout(timeout):
        while len(out) < n:
            msg = await ws.receive()
            assert msg.type == aiohttp.WSMsgType.BINARY, msg
            out += msg.data
    return out


class TestReadOnlyClients:
    def test_readonly_terminal_join(self, tmp_path, monkeypatch):
        import sreweb.agent.app as agent_app

        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                events = await h.client.ws_connect(f'/v1/projects/{rln}/events', headers=headers(PROF))
                alice = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?cols=100&rows=30', headers=headers(),
                                                  protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(alice.receive_json(), 5)
                sid = ready['session']
                assert (ready['cols'], ready['rows'], ready['readonly'], ready['viewers']) == (100, 30, False, 0)
                await read_until(alice, b'mock$')
                assert (await receive_event(events, 'terminals'))['terminals'][0]['viewers'] == 0
                # a read-only client needs a session to join
                refused = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?readonly=1', headers=headers(PROF),
                                                    protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(refused.receive_json(), 5))['t'] == 'error'
                await refused.receive()
                assert refused.close_code == 4403
                viewer = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?join={sid}&readonly=1&cols=20&rows=5',
                                                   headers=headers(PROF), protocols=(TERMINAL_SUBPROTOCOL,))
                ready = await asyncio.wait_for(viewer.receive_json(), 5)
                assert ready['readonly'] is True and ready['joined'] and (ready['clients'], ready['viewers']) == (1, 1)
                assert (ready['cols'], ready['rows']) == (100, 30)      # the pty's size, not the viewer's
                await read_until(viewer, b'mock$')
                listed = (await receive_event(events, 'terminals'))['terminals'][0]
                assert (listed['clients'], listed['viewers']) == (1, 1)
                # nothing the viewer sends reaches the shell
                await viewer.send_bytes(b'echo NOPE\n')
                await viewer.send_str(json.dumps({'t': 'input', 'data': 'echo NOPE2\n'}))
                await viewer.send_str(json.dumps({'t': 'resize', 'cols': 10, 'rows': 3}))
                await alice.send_bytes(b'echo STILL\n')
                out = await read_until(alice, b'STILL', after=b'echo STILL')
                assert b'NOPE' not in out
                # the writer's resize is told to the viewer
                await alice.send_str(json.dumps({'t': 'resize', 'cols': 90, 'rows': 25}))
                size = await receive_text(viewer, 'size')
                assert (size['cols'], size['rows']) == (90, 25)
                # the cap of the viewers
                monkeypatch.setattr(agent_app, 'MAX_READONLY_CLIENTS_PER_SESSION', 1)
                second = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?join={sid}&readonly=1',
                                                   headers=headers(PROF), protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(second.receive_json(), 5))['t'] == 'error'
                await second.receive()
                assert second.close_code == 4409
                # the viewer leaves: the session stays; the writer leaves: the session ends for the viewers too
                await viewer.close()
                listed = (await receive_event(events, 'terminals'))['terminals'][0]
                assert (listed['clients'], listed['viewers']) == (1, 0)
                viewer = await h.client.ws_connect(f'/v1/projects/{rln}/terminals/m1?join={sid}&readonly=1',
                                                   headers=headers(PROF), protocols=(TERMINAL_SUBPROTOCOL,))
                assert (await asyncio.wait_for(viewer.receive_json(), 5))['t'] == 'ready'
                assert (await receive_event(events, 'terminals'))['terminals'][0]['viewers'] == 1
                await alice.close()
                assert (await receive_text(viewer, 'exit', timeout=10))['t'] == 'exit'
                await viewer.receive()
                assert viewer.close_code == 1000
                assert (await receive_event(events, 'terminals'))['terminals'] == []
                await events.close()
        run(go())

    def test_readonly_display_stream(self, tmp_path, short_dir):
        async def go():
            async with Harness(tmp_path, mock_env=x11_env(), **display_cfg(short_dir)) as h:
                rln = await h.started()
                ws = await h.client.ws_connect(f'/v1/projects/{rln}/display/ws?readonly=1', headers=headers(PROF),
                                               protocols=(DISPLAY_SUBPROTOCOL,))
                assert (await asyncio.wait_for(ws.receive(), 5)).data == b'RFB 003.008\n'
                handshake = b'RFB 003.008\n\x01\x01'
                await ws.send_bytes(handshake)
                assert await collect_bytes(ws, len(handshake)) == handshake   # the fake server echoes
                key = b'\x04\x01\x00\x00\x00\x00\x00\x61'
                request = b'\x03\x00' + bytes(8)
                pointer = b'\x05\x01\x00\x0a\x00\x14'
                await ws.send_bytes(key + request + pointer)
                assert await collect_bytes(ws, len(request)) == request     # the input never reached the server
                await ws.send_bytes(b'\x07')                                # not an RFB client message
                closing = await asyncio.wait_for(ws.receive(), 5)
                assert closing.type == aiohttp.WSMsgType.CLOSE and ws.close_code == 4403
                await asyncio.sleep(0.1)
                assert h.agent.registry.projects[rln].display_clients == []
        run(go())
