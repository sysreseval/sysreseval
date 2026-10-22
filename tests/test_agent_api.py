"""Tests of the HTTP API of the agent (sreweb.agent.app) against the fake sre of tests/mock_sre.py."""
import asyncio
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest

aiohttp = pytest.importorskip('aiohttp', reason="aiohttp is not installed: the web front-end needs it: run `make venv` (or pip install aiohttp jinja2 aiohttp-jinja2 ldap3 in the venv)")
from aiohttp.test_utils import TestServer, TestClient  # noqa: E402

from SRE import params
from sreweb.agent.app import Agent, TERMINAL_SUBPROTOCOL, DISPLAY_SUBPROTOCOL, PROBE_DELAY
from sreweb.agent.display import parse_xauthority, WS_DISPLAY_FAILED
from sreweb.config import agent_config_from_dict
from sreweb.identity import Identity

MOCK = Path(__file__).parent / 'mock_sre.py'
MOCK_XVNC = Path(__file__).parent / 'mock_xvnc.py'
TOKEN = 't' * 32
ALICE = Identity(login='alice', fullname='Alice A', email='a@x.org', language='fr')
BOB = Identity(login='bob')
PROF = Identity(login='prof', role='instructor', view='instructor')
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
                           hostname='pool1', extra_env=env)
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
                assert len(await (await h.client.get('/v1/projects', headers=headers(PROF))).json()) == 1
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

    def test_export_and_no_save_restore(self, tmp_path):
        async def go():
            async with Harness(tmp_path) as h:
                rln = await h.started()
                # save and restore are not offered on the web
                assert (await h.client.get(f'/v1/projects/{rln}/save', headers=headers())).status == 404
                # the URL now matches the {rln} route, which has no POST: 405 (404 when no route matches at all)
                assert (await h.client.post('/v1/projects/restore', data=b'x', headers=headers())).status in (404, 405)
                resp = await h.client.get(f'/v1/projects/{rln}/export?curved=1&sep=4', headers=headers())
                blob = await resp.read()
                assert resp.status == 200 and blob.startswith(b'PK')
                assert ['--user', 'export', rln, '--curved', '--sep', '4'] in h.calls()
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
                assert (await asyncio.wait_for(ws.receive_json(), 5)) == {'t': 'ready'}
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
                    assert (await asyncio.wait_for(ws.receive_json(), 5)) == {'t': 'ready'}
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
                assert (await asyncio.wait_for(ws.receive_json(), 5)) == {'t': 'ready'}
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
                assert (await asyncio.wait_for(ws.receive_json(), 5)) == {'t': 'ready'}
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
                assert (await asyncio.wait_for(first.receive_json(), 5)) == {'t': 'ready'}
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


def display_cfg(runtime_dir, *, fail: str = '', **over) -> dict:
    """The ``[display]`` section of a test agent: the fake X server (through a shell script giving
    it its log file, and ``MOCK_XVNC_FAIL`` when *fail* is set: the agent builds the environment of
    the server itself), no window manager, no dedicated user, three display numbers."""
    script = Path(runtime_dir) / 'xvnc'
    script.write_text(f'#!/bin/sh\nexport MOCK_XVNC_LOG="{runtime_dir}/xvnc.log"\n'
                      + (f'export MOCK_XVNC_FAIL="{fail}"\n' if fail else '')
                      + f'exec "{sys.executable}" "{MOCK_XVNC}" "$@"\n')
    script.chmod(0o755)
    return {'display': {'enabled': True, 'user': '', 'xvnc_command': str(script), 'window_manager_command': '',
                        'runtime_dir': str(runtime_dir), 'first_display': 90, 'last_display': 92,
                        'start_timeout': 10, **over}}


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
