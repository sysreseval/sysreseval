"""``scripts/web-stress.py`` (the load generator of the web front-end) and ``scripts/web-fake-pool.py``
(a portal + fake agents on the mock sre): the pure helpers, an end-to-end run of the generator on
the in-process harness of ``test_web_portal.py`` in proxy mode, and the fake pool launched for real
with the generator as its command."""
import asyncio
import csv
import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip('aiohttp')

from test_web_portal import Harness, run   # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
STRESS = ROOT / 'scripts' / 'web-stress.py'
FAKE_POOL = ROOT / 'scripts' / 'web-fake-pool.py'

# proxy mode with the production role header (web_over replaces the whole auth dict)
STRESS_OVER = {'auth': {'mode': 'proxy', 'proxy': {'instructor_header': 'X-Remote-Gid', 'instructor_values': ['2000'],
                                                   'header_group': 'X-Remote-Group'}},
               'trusted_proxies': ['127.0.0.1', '::1'],
               'limits': {'start_interval': 0, 'eval_interval': 0}}


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module            # the dataclasses of the script resolve their annotations there
    spec.loader.exec_module(module)
    return module


stress = load_script(STRESS, 'web_stress')


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------------------------

class TestHelpers:
    def test_percentile(self):
        assert stress.percentile([], 50) == 0.0
        assert stress.percentile([3.0], 95) == 3.0
        values = [float(i) for i in range(1, 101)]
        assert stress.percentile(values, 50) == 50.0
        assert stress.percentile(values, 95) == 95.0
        assert stress.percentile(values, 100) == 100.0

    def test_status_ok(self):
        assert stress.status_ok('200') and stress.status_ok('204') and stress.status_ok('ok')
        assert stress.status_ok('created') and stress.status_ok('ws:1000') and stress.status_ok('ws:1001')
        assert not stress.status_ok('503') and not stress.status_ok('error') and not stress.status_ok('ws:4502')
        assert not stress.status_ok('ws:None') and not stress.status_ok('timeout')

    def test_phase_stats(self):
        s = [stress.Sample(0, 'a', 'start', 'created', 2.0), stress.Sample(1, 'b', 'start', '503', 0.1),
             stress.Sample(2, 'a', 'page', '200', 0.01), stress.Sample(3, 'b', 'start', 'created', 4.0)]
        stats = stress.phase_stats(s)
        assert list(stats) == ['page', 'start']           # PHASE_ORDER
        start = stats['start']
        assert (start.count, start.ok, start.errors) == (3, 2, 1)
        assert start.by_status == {'created': 2, '503': 1}
        assert start.max == 4.0 and start.p50 == 2.0

    def test_pool_flips_and_hosts(self):
        rows = lambda a, b: [{'name': 'h1', 'reachable': a}, {'name': 'h2', 'reachable': b}]   # noqa: E731
        samples = [stress.PoolSample(0, rows(True, True)), stress.PoolSample(5, rows(False, True)),
                   stress.PoolSample(10, rows(True, True)), stress.PoolSample(15, rows(True, False))]
        assert stress.pool_flips(samples) == {'h1': 2, 'h2': 1}
        assert stress.pool_flips([]) == {}
        students = [stress.StudentResult('a', host='h1'), stress.StudentResult('b', host='h1'),
                    stress.StudentResult('c', host='h2'), stress.StudentResult('d')]
        assert stress.host_distribution(students) == {'h1': 2, 'h2': 1}

    def test_retry_delay(self):
        opts = stress.Options(portal='http://x', start_retries=2)
        assert stress.retry_delay('start', '503', 10, 1, opts) == 11          # the pool's retry_after
        assert stress.retry_delay('start', '503', 60, 1, opts) == 61
        assert stress.retry_delay('start', '503', 60, 2, opts) is None       # attempts exhausted
        assert stress.retry_delay('start', '429', 7, 1, opts) == 8
        assert stress.retry_delay('start', '502', None, 1, opts) == 5.0
        assert stress.retry_delay('start', 'error', None, 3, opts) is None
        assert stress.retry_delay('start', '404', None, 1, opts) is None
        assert stress.retry_delay('eval', '429', 3, 1, opts) == 4
        assert stress.retry_delay('eval', '409', None, 2, opts) == 5.0
        assert stress.retry_delay('eval', '409', None, 3, opts) is None
        assert stress.retry_delay('answers', '500', None, 1, opts) is None

    def test_login_and_headers(self):
        assert stress.login_of('stress', 7) == 'stress007'
        opts = stress.Options(portal='http://x/')
        assert opts.portal == 'http://x'
        headers = stress.identity_headers(opts, 'stress007')
        assert headers['X-Remote-User'] == 'stress007' and headers['X-Remote-Group'] == 'stress'
        assert 'X-Remote-Gid' not in headers and headers['X-Remote-Email'] == 'stress007@stress.invalid'
        teacher = stress.identity_headers(opts, 'stress-instructor', instructor=True)
        assert teacher['X-Remote-Gid'] == '2000' and 'X-Remote-Group' not in teacher
        with pytest.raises(ValueError):
            stress.Options(portal='http://x', login_prefix='bad prefix')

    def test_pick_terminal_device(self):
        project = {'terminal_devices': [{'name': 'lan', 'kind': 'switch', 'allow_connection': True},
                                        {'name': 'm2', 'kind': 'machine', 'allow_connection': False},
                                        {'name': 'm1', 'kind': 'machine', 'allow_connection': True}]}
        assert stress.pick_terminal_device(project) == 'm1'          # machines before switches
        project['terminal_devices'][2]['allow_connection'] = False
        assert stress.pick_terminal_device(project) == 'lan'
        assert stress.pick_terminal_device({'terminal_devices': []}) is None
        assert stress.pick_terminal_device({}) is None

    def test_answers_payload(self):
        project = {'questions': [
            {'question_hash': 'a' * 32, 'question_type': 1},
            {'question_hash': 'd' * 32, 'question_type': 0},            # display only: no answer
            {'question_hash': 'b' * 32, 'question_type': 2, 'chunks': [
                {'type': 'text', 'html': 'x'},
                {'type': 'field', 'name': 'ip', 'kind': 'line', 'regex': r'[0-9.]+'},
                {'type': 'field', 'name': 'ok', 'kind': 'checkbox'},
                {'type': 'field', 'name': 'mode', 'kind': 'select', 'options': ['easy', 'hard']},
                {'type': 'field', 'name': 'free', 'kind': 'multiline', 'default': 'given'},
                {'type': 'field', 'name': 'go', 'kind': 'submit'}]},
            {'question_type': 1}]
        }
        answers = stress.answers_payload(project, 'stress001', 2)
        assert answers == {'a' * 32: 'answer 2 by stress001',
                           'b' * 32: {'ip': '1', 'ok': True, 'mode': 'easy', 'free': 'given'}}

    def test_report_summary_and_json(self):
        samples = [stress.Sample(0, 'stress001', 'start', 'created', 2.0, 'h1'),
                   stress.Sample(1, 'stress002', 'start', '503', 0.1, 'no host'),
                   stress.Sample(2, 'stress001', 'eval', '200', 1.0), stress.Sample(3, 'stress001', 'me', '200', 0.01)]
        stats = stress.phase_stats(samples)
        probe = stats.pop('me')
        students = [stress.StudentResult('stress001', host='h1', rln='x', completed=True,
                                         checks={'terminal_echo': True}, start_seconds=2.0, start_attempts=1),
                    stress.StudentResult('stress002', failure='start: 503 no host', checks={'lab_listed': True,
                                                                                            'project_listed': False})]
        pool = [stress.PoolSample(0, [{'name': 'h1', 'reachable': True, 'projects': 3, 'load1': 1.5}]),
                stress.PoolSample(5, [{'name': 'h1', 'reachable': False, 'projects': 0, 'load1': None}])]
        report = stress.Report(options={'users': 2, 'lab': 'l', 'ramp': 0, 'hold': 1}, started_at='t', duration=9.5,
                               students=students, phases=stats, pool=pool, pool_flips=stress.pool_flips(pool),
                               hosts={'h1': 1}, probe=probe, instructor={'role_ok': True, 'watch_rows_max': 1,
                                                                          'watch_stress_max': 1, 'errors': 0})
        text = report.summary()
        assert 'students: 1/2 completed, 1 fully ok; failures: start: 503 no host (1)' in text
        assert 'checks failed: project_listed 1' in text
        assert 'start ' in text and 'created=1 503=1' in text
        assert 'hosts: h1=1' in text and 'reachable flips h1×1' in text and 'probe GET /api/me' in text
        assert 'instructor: role ok' in text
        assert report.exit_code == 1
        data = json.loads(json.dumps(report.to_json()))
        assert data['completed'] == 1 and data['ok'] == 1 and data['phases']['start']['by_status'] == {'created': 1,
                                                                                                        '503': 1}
        assert data['students'][1]['failure'] == 'start: 503 no host' and data['pool_flips'] == {'h1': 1}
        students[1].completed, students[1].checks['project_listed'] = True, True
        assert report.exit_code == 0


# ---------------------------------------------------------------------------------------------
# the generator on the in-process harness (a real agent on the fake sre, a real portal)
# ---------------------------------------------------------------------------------------------

def options(h: Harness, tmp_path, **over) -> 'stress.Options':
    base = dict(portal=str(h.client.make_url('')), users=4, ramp=0.0, hold=1.0, browse=0.2, type_pause=0.1,
                answers=1, evals=1, terminal=True, timeout=30.0, events=str(tmp_path / 'events.csv'))
    base.update(over)
    return stress.Options(**base)


class TestEndToEnd:
    def test_four_students(self, tmp_path):
        async def scenario():
            async with Harness(tmp_path, web_over=STRESS_OVER, host_over={'max_projects': 10},
                               agent_over={'max_concurrent_starts': 4}) as h:
                report = await stress.run(options(h, tmp_path, instructor=True, probe=True, watch_interval=0.3,
                                                  admin_token=h.portal.cfg.admin.token or ''))
                assert [s.login for s in report.students] == ['stress001', 'stress002', 'stress003', 'stress004']
                for s in report.students:
                    assert s.completed and not s.failure, s
                    assert s.host == 'a01' and s.rln.endswith('@@@' + s.login)
                    assert all(s.checks.values()), s.checks
                    assert set(s.checks) == {'identity_ok', 'lab_listed', 'own_projects_only', 'project_listed',
                                             'terminal_echo', 'eval_grades', 'events_stayed_open',
                                             'no_unexpected_removed', 'stopped'}
                    assert s.start_attempts == 1 and s.events_received.get('answers', 0) >= 0
                assert report.exit_code == 0
                assert report.phases['start'].by_status == {'created': 4}
                assert report.phases['eval'].by_status == {'200': 4}
                assert report.phases['answers'].by_status == {'200': 4}
                assert report.phases['stop'].by_status == {'200': 4}
                assert report.phases['terminal_cmd'].count == 4 * len(stress.DEFAULT_COMMANDS)
                assert report.hosts == {'a01': 4}
                assert report.probe is not None and report.probe.count >= 1 and 'me' not in report.phases
                assert report.instructor['role_ok'] and report.instructor['watch_stress_max'] >= 1
                assert report.instructor['errors'] == 0
                assert report.phases['watch'].by_status.get('200', 0) >= 1
                # no admin token in the harness: the pool sampler ran only if one was configured
                assert report.pool == [] or all(r['reachable'] for p in report.pool for r in p.rows)
                # nothing left on the pool, the report serialises
                resp = await h.client.get('/api/projects', headers={'X-Remote-User': 'stress001'})
                assert await resp.json() == []
                json.dumps(report.to_json())
                text = report.summary()
                assert 'students: 4/4 completed, 4 fully ok' in text and 'checks failed: none' in text
            with open(tmp_path / 'events.csv', newline='') as f:
                rows = list(csv.DictReader(f))
            starts = [r for r in rows if r['phase'] == 'start']
            assert sorted(r['login'] for r in starts) == ['stress001', 'stress002', 'stress003', 'stress004']
            assert all(r['status'] == 'created' and r['detail'] == 'a01' for r in starts)
        run(scenario())

    def test_keep_then_cleanup(self, tmp_path):
        async def scenario():
            async with Harness(tmp_path, web_over=STRESS_OVER, host_over={'max_projects': 10}) as h:
                report = await stress.run(options(h, tmp_path, users=2, keep=True, terminal=False, answers=0, evals=0))
                assert report.exit_code == 0 and all(s.completed for s in report.students)
                assert all('stopped' not in s.checks for s in report.students)
                instructor = {'X-Remote-User': 'stress-instructor', 'X-Remote-Gid': '2000'}
                rows = await (await h.client.get('/api/watch', headers=instructor)).json()
                assert sorted(r['owner'] for r in rows) == ['stress001', 'stress002']
                assert await stress.cleanup(options(h, tmp_path)) == 0
                assert await (await h.client.get('/api/watch', headers=instructor)).json() == []
        run(scenario())

    def test_untrusted_peer_is_a_setup_error(self, tmp_path):
        async def scenario():
            async with Harness(tmp_path) as h:          # anonymous mode: the headers mean nothing
                with pytest.raises(stress.SetupError):
                    await stress.run(options(h, tmp_path, users=1))
        run(scenario())


# ---------------------------------------------------------------------------------------------
# the fake pool, launched for real
# ---------------------------------------------------------------------------------------------

class TestFakePool:
    def test_two_hosts_and_the_generator(self, tmp_path):
        workdir = tmp_path / 'pool'
        port = free_port()
        report_file = workdir / 'report.json'
        command = ['sh', '-c', f'"$0" "{STRESS}" --portal "$SRE_STRESS_PORTAL" --admin-token "$SRE_STRESS_ADMIN_TOKEN" '
                               f'--users 4 --hold 1 --browse 0.2 --type-pause 0.1 --report "$SRE_STRESS_WORKDIR/report.json"',
                   sys.executable]
        completed = subprocess.run([sys.executable, str(FAKE_POOL), '--hosts', '2', '--max-projects', '3',
                                    '--listen', f'127.0.0.1:{port}', '--start-delay', '0', '--start-interval', '0',
                                    '--eval-interval', '0', '--poll-interval', '0.5', '--workdir', str(workdir),
                                    '--keep-workdir', '--'] + command,
                                   capture_output=True, text=True, timeout=180, env={**os.environ, 'PYTHONPATH': ''})
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert f'portal=http://127.0.0.1:{port}' in completed.stdout
        assert 'students: 4/4 completed, 4 fully ok' in completed.stdout
        report = json.loads(report_file.read_text())
        assert report['ok'] == 4 and set(report['hosts']) <= {'fake01', 'fake02'} and sum(report['hosts'].values()) == 4
        assert report['hosts'] == {'fake01': 2, 'fake02': 2}       # the least loaded host each time
        assert report['pool'] and all(r['reachable'] for p in report['pool'] for r in p['rows'])
        assert (workdir / 'web.toml').is_file() and (workdir / 'fake01' / 'agent.toml').is_file()
        access = (workdir / 'access.log').read_text()
        assert access.count('event=start') == 4 and 'result=created' in access
        assert (workdir / 'fake01' / 'sre.log').is_file() and (workdir / 'portal.log').is_file()
        # the daemons are gone
        for host in ('fake01', 'fake02'):
            assert 'listening on' in (workdir / host / 'agent.log').read_text()
        assert not (workdir / 'fake01' / 'pub' / 'projects').is_dir() or \
            not any((workdir / 'fake01' / 'pub' / 'projects').iterdir())
