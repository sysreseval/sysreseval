"""Tests of sreweb.agent.runner: how the agent spawns `sre --user ...` (a fake sre written here)."""
import asyncio
import json
import os
import stat
import sys
import textwrap

import pytest

from sreweb.agent import runner as R
from sreweb.agent.runner import SreRunner, CommandError, CommandTimeout, FlavorFormNeeded, FlavorError

FAKE = textwrap.dedent('''\
    #!%s
    import json, os, sys, time
    args = sys.argv[1:]
    env = {k: os.environ.get(k) for k in ("LOGNAME", "SUDO_USER", "USER_USERNAME", "SUDO_COMMAND", "SUDO_UID", "LANGUAGE")}
    def ev(**d): print(json.dumps(d), file=sys.stderr, flush=True)
    cmd = [a for a in args if not a.startswith("--")][0] if [a for a in args if not a.startswith("--")] else ""
    if cmd == "env":
        print(json.dumps({"argv": args, "env": env})); sys.exit(0)
    if cmd == "start":
        ev(phase="pull", status="start"); ev(phase="deploy", status="start", total=2)
        print("sre: something odd", file=sys.stderr, flush=True)
        here = os.path.dirname(os.path.abspath(__file__))
        if "--flavor-json" not in args and os.path.exists(os.path.join(here, "form")):
            ev(phase="flavor_form", status="needed", form="Clients: @@{nb:[0-9]+}@@", form_size=[400, 200]); sys.exit(3)
        if "--flavor-json" in args and os.path.exists(os.path.join(here, "refuse")):
            ev(phase="flavor_error", message="Max 5"); sys.exit(4)
        ev(phase="deploy", status="end")
        ev(phase="project", status="created", running_lab_name="20260101000000@@@lab@@@" + str(env["SUDO_USER"]))
        sys.exit(0)
    if cmd == "fail":
        print("sre: boom", file=sys.stderr); sys.exit(1)
    if cmd == "sleep":
        time.sleep(30)
    if cmd == "cat":
        sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(0)
    if cmd == "big":
        sys.stdout.buffer.write(b"x" * (300 * 1024)); print("done", file=sys.stderr); sys.exit(0)
    if cmd == "bigfail":
        sys.stdout.buffer.write(b"y" * 1000); print("sre: late failure", file=sys.stderr); sys.exit(2)
    sys.exit(2)
''')


@pytest.fixture
def fake_sre(tmp_path, monkeypatch):
    exe = tmp_path / 'sre'
    exe.write_text(FAKE % sys.executable)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return str(exe)


def run(coro):
    return asyncio.run(coro)


class TestEnvAndArgv:
    def test_student_env_is_the_sudo_one_without_sudo_command(self):
        env = R.build_env('alice')
        assert env['LOGNAME'] == 'root' and env['SUDO_USER'] == 'alice' and env['USER_USERNAME'] == 'alice'
        assert 'SUDO_COMMAND' not in env and 'SUDO_UID' not in env
        assert env['LANG'] == 'C.UTF-8' and 'PATH' in env and 'TERM' not in env

    def test_privileged_env(self):
        env = R.build_env('prof', privileged=True, lang='fr', term='xterm-256color')
        assert env['LOGNAME'] == 'prof' and 'SUDO_USER' not in env
        assert env['LANGUAGE'] == 'fr' and env['TERM'] == 'xterm-256color'

    def test_argv(self):
        assert R.build_argv('/usr/sbin/sre', ['start', 'sre/dhcp.py']) == ['/usr/sbin/sre', '--user', 'start', 'sre/dhcp.py']
        assert R.build_argv('/usr/sbin/sre', ['exec', 'x'], privileged=True) == ['/usr/sbin/sre', 'exec', 'x']

    def test_parse_stderr_line(self):
        assert R.parse_stderr_line('{"phase": "pull", "status": "start"}\n') == {'phase': 'pull', 'status': 'start'}
        assert R.parse_stderr_line('sre: boom\n') == {'phase': 'message', 'line': 'sre: boom'}
        assert R.parse_stderr_line('{"no": "phase"}') == {'phase': 'message', 'line': '{"no": "phase"}'}
        assert R.parse_stderr_line('{broken') == {'phase': 'message', 'line': '{broken'}
        assert R.last_message('{"phase":"x"}\nsre: a\n\nsre: b\n{"phase":"y"}\n') == 'sre: b'


class TestRun:
    def test_run_passes_the_identity(self, fake_sre):
        result = run(SreRunner(fake_sre).run('alice', ['env']))
        out = json.loads(result.stdout)
        assert out['argv'] == ['--user', 'env'] and out['env']['SUDO_USER'] == 'alice'
        assert out['env']['LOGNAME'] == 'root' and out['env']['SUDO_COMMAND'] is None
        assert result.rc == 0 and result.events == []

    def test_privileged_run(self, fake_sre):
        out = json.loads(run(SreRunner(fake_sre).run('prof', ['env'], privileged=True, lang='fr')).stdout)
        assert out['argv'] == ['env'] and out['env']['LOGNAME'] == 'prof' and out['env']['LANGUAGE'] == 'fr'

    def test_failure(self, fake_sre):
        with pytest.raises(CommandError) as e:
            run(SreRunner(fake_sre).run('alice', ['fail']))
        assert e.value.rc == 1 and e.value.message == 'sre: boom'

    def test_stdin(self, fake_sre):
        assert run(SreRunner(fake_sre).run('alice', ['cat'], stdin=b'abc\x00def')).stdout == b'abc\x00def'

    def test_timeout_kills(self, fake_sre):
        with pytest.raises(CommandTimeout):
            run(SreRunner(fake_sre, timeouts={'sleep': 0.5}).run('alice', ['sleep']))

    def test_missing_executable(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run(SreRunner(str(tmp_path / 'nope')).run('alice', ['list']))


class TestStream:
    async def _start(self, exe, args, user='alice'):
        r = SreRunner(exe)
        s = await r.stream(user, args)
        events = [e async for e in s.events()]
        return s, events

    def test_events_and_created_project(self, fake_sre):
        s, events = run(self._start(fake_sre, ['start', 'lab']))
        assert [e['phase'] for e in events] == ['pull', 'deploy', 'message', 'deploy', 'project']
        assert events[2] == {'phase': 'message', 'line': 'sre: something odd'}
        assert s.result().rc == 0
        assert s.created_running_lab_name() == '20260101000000@@@lab@@@alice'

    def test_flavor_form(self, fake_sre, tmp_path):
        (tmp_path / 'form').touch()   # the runner gives sre a clean environment: a marker file instead
        s, _ = run(self._start(fake_sre, ['start', 'lab']))
        with pytest.raises(FlavorFormNeeded) as e:
            s.result()
        assert e.value.form == 'Clients: @@{nb:[0-9]+}@@' and e.value.form_size == [400, 200]

    def test_flavor_refused(self, fake_sre, tmp_path):
        (tmp_path / 'refuse').touch()
        s, _ = run(self._start(fake_sre, ['start', '--flavor-json', '{"nb": "9"}', 'lab']))
        with pytest.raises(FlavorError, match='Max 5'):
            s.result()

    def test_failure_message(self, fake_sre):
        s, _ = run(self._start(fake_sre, ['fail']))
        with pytest.raises(CommandError, match='boom'):
            s.result()

    def test_stream_timeout(self, fake_sre):
        async def go():
            s = await SreRunner(fake_sre, timeouts={'sleep': 0.5}).stream('alice', ['sleep'])
            async for _ in s.events():
                pass
        with pytest.raises(CommandTimeout):
            run(go())

    def test_start_limits_are_released(self, fake_sre):
        async def go():
            r = SreRunner(fake_sre, max_concurrent_starts=1)
            for _ in range(3):   # a second start would hang if the semaphore leaked
                s = await r.stream('alice', ['start', 'lab'])
                async for _ in s.events():
                    pass
                s.result()
            return r._start_sem._value
        assert run(go()) == 1


class TestStreamStdout:
    def test_chunks(self, fake_sre):
        async def go():
            return b''.join([c async for c in SreRunner(fake_sre).stream_stdout('alice', ['big'])])
        assert run(go()) == b'x' * (300 * 1024)

    def test_late_failure(self, fake_sre):
        async def go():
            chunks = []
            async for c in SreRunner(fake_sre).stream_stdout('alice', ['bigfail']):
                chunks.append(c)
        with pytest.raises(CommandError, match='late failure'):
            run(go())
