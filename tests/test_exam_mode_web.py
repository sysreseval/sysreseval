#!/usr/bin/env python3
"""
End-to-end tests of an exam of the web site taken at a machine of the pool (the Qt GUI there).

test_exam_mode.py feeds sysreseval an exam.json the test writes itself.  Here nothing writes
the file by hand: the **web agent** of the tree does (`PUT` / `DELETE /v1/exam`), on the orders
of the **portal's own code** — the registry of the exams (sreweb.portal.exams), a pool polling
that agent and the reconciler of the machines (sreweb.portal.examhosts), pumped every second as
the tick of the portal does, without its HTTP server nor its database.  sysreseval --debug runs
as a normal user on the same temporary SRE_PUB_DIR and must follow: locked a delay before the
start, waiting → active → ended, the end screen kept until the release, extra minutes granted
meanwhile resuming the exam, End now and Close for the machine, a file set by hand left alone.

The scenarios of test_exam_mode.py have their counterpart here (its scenario → this one): 1
the end by the duration → 6; 2 another project stopped at the pre-start → 12; 3 and 4 the GUI
restarted → 11; 5 the file removed after the end → 1, 4; 6 the end by end-before → 1; 7 and 8
the labs changed → 5, 12; 9 time added after the end → 2.  The others are what only the web
site does: the lock and the release (1, 10), minutes during the exam (7), Start now and a
postponed start (8), a machine unselected and selected again (9), a file set by hand (4), a
student of the audience logged in at the machine (13).

The GUI runs the mock sre-wrapper of test_exam_mode.py (no Docker, no Kathara); the agent runs
the fake sre of the web tests (tests/mock_sre.py) for the lab list and for the close of the
exam (`sre end-exam`, `sre stop`).  Run as root, with debug_mode = True (the GUI then obeys
SRE_PUB_DIR and SRE_WRAPPER), like `make exam-tests`: `make web-exam-tests`.

Usage:
  python3 tests/test_exam_mode_web.py [options] [scenario_numbers...]

Options:
  --user USER           normal user to run sysreseval as (default: current user)
  --lab LAB             lab name (CLI arg form, e.g. _TESTS_/exam_test1.py)
  --lab2 LAB2           second lab, for the scenario adding a lab
  --sysreseval PATH     path to the sysreseval script (default: the one of the tree)
  --keep-tmpdir         keep the temp SRE_PUB_DIR on exit (for debugging)
  scenario_numbers      1-13 (default: all)
"""

import argparse
import asyncio
import json
import os
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

from SRE import params

from test_exam_mode import ExamTestHarness, PASS, FAIL, _current_user

ROOT = Path(__file__).resolve().parents[1]
MOCK_SRE = ROOT / 'tests' / 'mock_sre.py'
MOCK_WRAPPER = ROOT / 'tests' / 'mock_sre_wrapper.py'
AGENT_SCRIPT = ROOT / 'src' / 'sre_agent.py'

TOKEN = 'exam-mode-web-tests-' + 'x' * 28
HOST = 'machine'                # the name of the pool host the agent of the test stands for
ORIGIN = 'exam-mode-web'        # what marks the files of this "portal"
INSTRUCTOR = 'prof'

# ---------------------------------------------------------------------------
# Timing constants (seconds)
# ---------------------------------------------------------------------------

START_IN = 25           # from the creation of the exam to its start
LOCK_LEAD = 12          # the machine is locked that long before the start (host_lead)
EXAM_SECONDS = 40       # from the start to the end-before time
RELEASE = 12            # the file is removed that long after the end-before time (host_release)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def end_gui_of(user: str):
    """The GUI of *user*, for good.  ``ExamTestHarness.stop_sysreseval`` ends what it launched
    (runuser, the shell script of bin/sysreseval), whose python child lives on until the next
    GUI of that user replaces it; the pid file of the GUI (its single-instance lock) names it:
    ended here when it is a ``sysreseval --debug`` (never the GUI of a real session)."""
    try:
        pid = int(Path(f"/tmp/sysreseval-{pwd.getpwnam(user).pw_uid}.pid").read_text().strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (KeyError, OSError, ValueError):
        return
    if b'sysreseval' in cmdline and b'--debug' in cmdline:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# The agent of the machine
# ---------------------------------------------------------------------------

class AgentProcess:
    """The web agent of the tree on the pub dir of the test (``--pub-dir``), the fake sre of
    tests/mock_sre.py behind it: its calls are logged in ``sre_log``."""

    def __init__(self, tmpdir: Path, pub_dir: Path, labs: list):
        self.pub_dir = pub_dir
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.sre_log = tmpdir / 'agent-sre.log'
        self.output = tmpdir / 'agent.log'
        wrapper = tmpdir / 'sre-of-the-agent'
        wrapper.write_text("#!/bin/sh\n"
                           f"MOCK_LAB_LIST='{json.dumps(labs)}' MOCK_SRE_LOG='{self.sre_log}' "
                           f"exec '{sys.executable}' -W ignore '{MOCK_SRE}' \"$@\"\n")
        wrapper.chmod(0o755)
        self.config = tmpdir / 'agent.toml'
        self.config.write_text(f'token = "{TOKEN}"\nlisten = "127.0.0.1:{self.port}"\nsre_exe = "{wrapper}"\n'
                               'poll_interval = 0.5\noccupied_check = "sessions"\n')
        self.config.chmod(0o600)
        # the local login sessions the agent reports (`session:<login>` in its status) are those
        # of this file, one login per line: a `loginctl` and a `who` of the test come first in
        # the PATH of the agent (never the sessions of the host the tests run on)
        self.sessions_file = tmpdir / 'sessions'
        self.sessions_file.write_text('')
        self.bin = tmpdir / 'agent-bin'
        self.bin.mkdir()
        (self.bin / 'loginctl').write_text(
            "#!/bin/sh\n"
            f"SESSIONS='{self.sessions_file}'\n"
            'if [ "$1" = list-sessions ]; then\n'
            '    n=0\n'
            '    while read -r login; do\n'
            '        n=$((n + 1))\n'
            '        [ -n "$login" ] && echo "    $n 1000 $login seat0 tty2"\n'
            '    done < "$SESSIONS"\n'
            '    exit 0\n'
            'fi\n'
            'if [ "$1" = show-session ]; then\n'
            '    printf \'Name=%s\\nSeat=seat0\\nTTY=tty2\\nClass=user\\nRemote=no\\nUser=1000\\n\' '
            '"$(sed -n "${2}p" "$SESSIONS")"\n'
            '    exit 0\n'
            'fi\n'
            'exit 1\n')
        (self.bin / 'who').write_text("#!/bin/sh\nexit 0\n")
        for fake in ('loginctl', 'who'):
            (self.bin / fake).chmod(0o755)
        self._proc: subprocess.Popen | None = None
        self._out = None

    def sessions(self, logins: list):
        """Who is logged in at the keyboard of the machine, as the agent will tell (its
        occupancy is cached five seconds)."""
        self.sessions_file.write_text(''.join(f"{login}\n" for login in logins))

    def start(self, timeout: float = 20.0):
        self._out = open(self.output, 'w')
        env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src'), 'PATH': f"{self.bin}:{os.environ.get('PATH', '')}"}
        self._proc = subprocess.Popen([sys.executable, '-W', 'ignore', str(AGENT_SCRIPT), '--config', str(self.config),
                                       '--pub-dir', str(self.pub_dir)], stdout=self._out, stderr=subprocess.STDOUT,
                                      env=env)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                break
            try:
                request = urllib.request.Request(self.url + '/v1/status', headers={'Authorization': f'Bearer {TOKEN}'})
                with urllib.request.urlopen(request, timeout=2) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                time.sleep(0.2)
        raise RuntimeError(f"the agent did not start:\n{self.tail()}")

    def stop(self):
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None
        if self._out is not None:
            self._out.close()
            self._out = None

    def tail(self, lines: int = 30) -> str:
        try:
            return '\n'.join(self.output.read_text().splitlines()[-lines:])
        except OSError:
            return ''

    def calls(self) -> list:
        """The calls of the fake sre since the log was emptied: ``(argv, login, user mode)``."""
        if not self.sre_log.exists():
            return []
        entries = [json.loads(line) for line in self.sre_log.read_text().splitlines() if line.strip()]
        return [(entry['argv'], entry.get('username'), entry.get('user_mode')) for entry in entries]

    def forget_calls(self):
        self.sre_log.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# The portal's side
# ---------------------------------------------------------------------------

class WebSide:
    """What the portal does for the machines of its exams, with its own code: the registry of
    the exams (no database), the pool polling the agent, the relay and the reconciler, in a
    thread with its own event loop; ``pool.refresh()`` then ``ExamHosts.sync()`` every second."""

    def __init__(self, agent_url: str):
        import aiohttp                                            # the web front-end is needed from here on
        from sreweb.config import ExamsConfig, HostConfig
        from sreweb.identity import Identity
        from sreweb.portal import exams as X
        from sreweb.portal.examhosts import ExamHosts
        from sreweb.portal.pool import Pool
        from sreweb.portal.presentation import Presence
        from sreweb.portal.relay import Relay
        self.X = X
        self.cfg = ExamsConfig()
        self.creator = Identity(login=INSTRUCTOR, role='instructor')
        self.loop = asyncio.new_event_loop()
        self.failures: list = []
        ready = threading.Event()

        async def setup():
            self.session = aiohttp.ClientSession()
            self.pool = Pool([HostConfig(name=HOST, url=agent_url, token=TOKEN, max_projects=5)], self.session,
                             poll_interval=1.0)
            self.relay = Relay(self.pool, self.session)
            self.exams = X.Exams(Presence(), cfg=self.cfg)
            self.hosts = ExamHosts(self.exams, self.pool, self.relay, origin=ORIGIN)
            self._pump = asyncio.ensure_future(self._pump_loop())

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(setup())
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        if not ready.wait(15):
            raise RuntimeError("the portal's side did not start")

    async def _pump_loop(self):
        while True:
            try:
                await self.pool.refresh()
                await self.hosts.sync()
            except Exception:
                self.failures.append(traceback.format_exc())
            await asyncio.sleep(1.0)

    def call(self, coro, timeout: float = 60.0):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    async def _pass(self):
        await self.pool.refresh()
        await self.hosts.sync()

    # -- what an instructor does on the Exams page ------------------------------------------------

    def create(self, **body):
        """A new exam for the machine (the body of ``POST /api/exams``, minutes for the delays)."""
        spec = self.X.parse_exam({'title': 'Partiel', 'hosts': [HOST], **body}, cfg=self.cfg, now=time.time(),
                                 known_hosts={HOST})
        exam = self.call(self.exams.create(self.creator, spec))
        self.call(self._pass())
        return exam

    def adjust(self, exam, minutes: int):
        self.call(self.exams.adjust(exam.id, None, minutes, {HOST}))
        self.call(self._pass())

    def end_now(self, exam):
        self.call(self.exams.end_now(exam.id, None, {HOST}))
        self.call(self._pass())

    def close(self, exam):
        self.call(self.exams.close_hosts(exam.id, [HOST]))
        self.call(self._pass())

    def set_labs(self, exam, labs: list):
        self.call(self.exams.set_labs(exam.id, None, self.X.parse_labs(labs)))
        self.call(self._pass())

    def edit(self, exam, **body):
        """The Edit of the page (the keys of ``PUT /api/exams/{id}``); *Start now* is
        ``edit(exam, start_after=time.time())``."""
        spec = self.X.parse_exam(body, cfg=self.cfg, now=time.time(), current=exam, known_hosts={HOST})
        self.call(self.exams.update(exam.id, spec, resume='end_before' in body or 'duration' in body))
        self.call(self._pass())

    def delete(self, exam, close: bool):
        async def gone():
            await self.hosts.release(exam, close)
            await self.exams.delete(exam.id)
        self.call(gone())

    # -- what the Exams page shows ---------------------------------------------------------------

    def rows(self, exam) -> list:
        """The machines table of the exam."""
        async def rows():
            return self.hosts.rows_of(exam, [])
        return self.call(rows())

    def row(self, exam) -> dict:
        """The row of the machine in the machines table of the exam."""
        return self.rows(exam)[0]

    # -- what a student's browser is told ----------------------------------------------------------

    def binding(self, login: str) -> tuple | None:
        """``(phase, the machine they take the exam at)`` of the exam binding *login* on the web
        site now, ``None`` when none does (``GET /api/exam``)."""
        async def bound():
            found = self.exams.for_login(login, '')
            if found is None:
                return None
            _, member, phase = found
            return phase, member.local if member is not None else ''
        return self.call(bound())

    def start_access(self, login: str, lab: str) -> tuple:
        """``(allowed, reason)`` of a start of *lab* by *login* (``POST /api/projects``)."""
        async def access():
            return self.exams.start_access(login, '', lab)
        return self.call(access())

    def wait_row(self, exam, condition, timeout: float, what: str) -> dict:
        deadline = time.time() + timeout
        row = None
        while time.time() < deadline:
            row = self.row(exam)
            if condition(row):
                return row
            time.sleep(0.5)
        raise AssertionError(f"Timed out waiting for {what}; the machine: {row}")

    def reset(self):
        """Between two scenarios: no exam left, the pool told what the machine holds."""
        async def clear():
            for exam in self.exams.listing():
                await self.exams.delete(exam.id)
            self.hosts.errors.clear()
            self.hosts._retry_at.clear()
            await self.pool.refresh()
        self.call(clear())

    def stop(self):
        async def close():
            self._pump.cancel()
            await self.hosts.shutdown()
            await self.session.close()
        try:
            self.call(close(), timeout=20)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=5)


# ---------------------------------------------------------------------------
# The scenarios
# ---------------------------------------------------------------------------

class Stage:
    """A scenario's world: the GUI harness, the agent, the portal's side."""

    def __init__(self, harness: ExamTestHarness, agent: AgentProcess, web: WebSide):
        self.h = harness
        self.agent = agent
        self.web = web

    def reset(self):
        self.end_gui()
        self.web.reset()
        self.h.clean()
        self.agent.sessions([])
        self.web.call(self.web.pool.refresh())
        self.agent.forget_calls()

    def end_gui(self):
        """The student logs out: the GUI ended for good (``start_sysreseval`` starts the next)."""
        self.h.stop_sysreseval()
        end_gui_of(self.h.user)

    def wait_no_file(self, timeout: float = 20.0, stable: float = 3.0):
        """exam.json gone, and for *stable* seconds: an `end-exam` of the GUI that read the file
        just before the agent removed it writes it back (the portal then removes it again)."""
        path = self.h.pub_dir / params.exam_json_name
        deadline = time.time() + timeout
        gone_since = None
        while time.time() < deadline:
            if path.exists():
                gone_since = None
            elif gone_since is None:
                gone_since = time.time()
            elif time.time() - gone_since >= stable:
                return
            time.sleep(0.2)
        raise AssertionError("exam.json still exists (or keeps coming back) after its removal")

    def other_project(self) -> Path:
        """A project of a lab that is not the exam's, open before the exam (as scenario 2 of
        test_exam_mode.py makes it)."""
        name = f"{time.strftime('%Y%m%d%H%M%S')}@@@other_lab@@@{self.h.user}"
        project = self.h.projects_dir / name
        project.mkdir(parents=True)
        project.chmod(0o777)       # the mock sre-wrapper removes it as the student
        info = project / "info.json"
        info.write_text(json.dumps({"lab_name": "other_lab", "lab_hash": "mock", "title": "Other lab"}))
        info.chmod(0o666)
        return project

    def forget_events(self):
        """The events of the GUI seen so far dropped: ``assert_event`` scans them all, and an
        earlier one of the same kind would answer for the one awaited next."""
        with self.h._events_lock:
            self.h.events.clear()

    def projects(self) -> list:
        return sorted(d.name for d in self.h.projects_dir.iterdir() if d.is_dir())

    def wait_no_project(self, timeout: float = 15.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.projects():
                return
            time.sleep(0.3)
        raise AssertionError(f"projects still there: {self.projects()}")

    def window(self, start_in: float = START_IN, seconds: float = EXAM_SECONDS, **over) -> dict:
        """The body of an exam starting in *start_in* seconds and ending *seconds* later, locked
        LOCK_LEAD before and released RELEASE after."""
        start = time.time() + start_in
        return {'labs': [self.h.lab], 'start_after': start, 'end_before': start + seconds,
                'host_lead': LOCK_LEAD / 60, 'host_release': RELEASE / 60, **over}

    def until_active(self, exam, start_in: float = START_IN) -> dict:
        """From the lock to the running exam: the file written by the agent, the GUI waiting,
        then active with its projects and the start stamped; the content of the file."""
        h = self.h
        h.assert_event("exam_entered", timeout=start_in + 5, msg="exam.json written by the agent")
        h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)
        h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=start_in + 15)
        h.assert_event("tick", lambda e: e.get("start_exam_called") is True, timeout=15)
        h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
        data = h.assert_field_in_exam("started_at", timeout=15)
        assert data[params.exam_web][params.exam_web_id] == str(exam.id), \
            "the commands of the GUI must keep the marker of the web exam"
        return data


def marker_of(data: dict | None) -> dict:
    return (data or {}).get(params.exam_web) or {}


def scenario_1(s: Stage):
    """Locked a delay before the start, waiting → active → ended, the end screen, the release."""
    h, web = s.h, s.web
    h.start_sysreseval()                       # the student's GUI, on a normal workstation
    body = s.window()
    exam = web.create(**body)
    lock_at = body['start_after'] - LOCK_LEAD

    # not before the lock: the machine stays a normal workstation
    time.sleep(3)
    assert h.read_exam_json() is None, "exam.json written before the lock"
    assert web.row(exam)['phase'] == 'scheduled'
    h.assert_event("exam_entered", timeout=START_IN, msg="exam.json written by the agent at the lock")
    assert time.time() >= lock_at - 1.5, "the machine was locked before its time"

    # the file of sre set-exam, plus the marker
    data = h.read_exam_json()
    assert marker_of(data) == {params.exam_web_id: str(exam.id), params.exam_web_title: 'Partiel',
                               params.exam_web_rev: marker_of(data).get(params.exam_web_rev),
                               params.exam_web_origin: ORIGIN}, data
    assert data[params.exam_labs] == [[h.lab, None]] and data[params.exam_record_sessions] is True
    assert data[params.exam_duration] == 1 and params.exam_start_after in data and params.exam_end_before in data

    s.until_active(exam)
    row = web.wait_row(exam, lambda r: r['phase'] == 'active' and r['started_at'], 15,
                       "the portal seeing the clock of the machine")
    assert row['locked'] and row['pre_started'] and abs(row['end_at'] - body['end_before']) < 1.5

    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=EXAM_SECONDS + 20)
    h.assert_field_in_exam("ended_at", timeout=15)
    web.wait_row(exam, lambda r: r['phase'] == 'ended', 10, "the ended machine")
    assert h.read_exam_json() is not None and len(s.projects()) == 1, "the end screen: the file and the project stay"
    assert time.time() < body['end_before'] + RELEASE, "the scenario is late: the release already came"

    # the release: the machine closed by the portal, its project stopped by the agent, then the file
    h.assert_event("exam_exited", timeout=RELEASE + 25)
    h.assert_no_exam_json(timeout=5)
    assert time.time() >= body['end_before'] + RELEASE - 1.5, "released before its time"
    s.wait_no_project()
    web.wait_row(exam, lambda r: r['phase'] == 'closed' and not r['closing'], 15, "the closed machine")
    calls = [argv for argv, login, user_mode in s.agent.calls() if argv[0] in ('end-exam', 'stop')]
    assert [argv[0] for argv in calls] == ['stop'], f"the GUI ended the exam: the agent only stops; got {calls}"


def scenario_2(s: Stage):
    """Minutes granted on the end screen resume the exam; the agent runs the final evaluation."""
    h, web = s.h, s.web
    h.start_sysreseval()
    body = s.window()
    exam = web.create(**body)
    started = s.until_active(exam)[params.exam_started_at]
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=EXAM_SECONDS + 20)
    h.assert_field_in_exam("ended_at", timeout=15)

    # one more minute for that machine, during the release delay
    s.forget_events()
    web.adjust(exam, 1)
    h.assert_event("exam_modified", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=10)
    data = h.read_exam_json()
    assert data[params.exam_started_at] == started, "the machine keeps its clock"
    assert params.exam_ended_at not in data, "the recorded end is dropped: the exam goes on"
    assert data[params.exam_duration] == 2
    row = web.wait_row(exam, lambda r: r['phase'] == 'active', 10, "the machine running again")
    assert row['extra_minutes'] == 1 and abs(row['release_at'] - (body['end_before'] + 60 + RELEASE)) < 1.5
    assert h.read_exam_json() is not None

    # the new end: the GUI ends an exam once only, so no end is recorded this time
    s.forget_events()
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=60 + 20)
    time.sleep(3)
    assert params.exam_ended_at not in (h.read_exam_json() or {})

    # the release: the agent runs the final evaluation itself, then stops the project
    h.assert_event("exam_exited", timeout=RELEASE + 25)
    h.assert_no_exam_json(timeout=5)
    s.wait_no_project()
    calls = [(argv, login, user_mode) for argv, login, user_mode in s.agent.calls() if argv[0] in ('end-exam', 'stop')]
    assert [argv[0] for argv, _, _ in calls] == ['end-exam', 'stop'], calls
    assert all(login == INSTRUCTOR and user_mode is False for _, login, user_mode in calls), calls
    archives = list((h.pub_dir / 'archives').glob('*.zst'))
    assert len(archives) == 1, f"the final evaluation of the agent left {archives}"


def scenario_3(s: Stage):
    """End now, then Close, for the machine during the exam; a closed machine stays closed."""
    h, web = s.h, s.web
    exam = web.create(**s.window(seconds=600))

    # nobody logged in yet: the file as the agent wrote it at the lock — readable by the student
    # who will sit there, owned like the one of sre set-exam (the commands of the GUI rewrite it
    # as that user; the mock wrapper of this harness replaces the file instead, as the student)
    path = h.pub_dir / params.exam_json_name
    deadline = time.time() + START_IN
    while not path.exists() and time.time() < deadline:
        time.sleep(0.2)
    st = path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o644, oct(st.st_mode)
    if os.geteuid() == 0:
        assert (st.st_uid, st.st_gid) == (params.sre_uid, params.docker_gid), (st.st_uid, st.st_gid)

    h.start_sysreseval()                       # the student logs in at the locked machine
    s.until_active(exam)

    web.end_now(exam)
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=10)
    h.assert_field_in_exam("ended_at", timeout=15)
    assert len(s.projects()) == 1

    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    h.assert_no_exam_json(timeout=5)
    s.wait_no_project()
    web.wait_row(exam, lambda r: r['phase'] == 'closed' and not r['closing'], 15, "the closed machine")
    try:
        web.adjust(exam, 5)
    except ValueError as e:
        assert 'closed on the machine' in str(e), e
    else:
        raise AssertionError("minutes were granted to a closed machine")
    time.sleep(4)
    assert h.read_exam_json() is None, "the file came back on a closed machine"


def scenario_4(s: Stage):
    """A machine holding an exam set by hand is refused and left alone, then taken once free."""
    h, web = s.h, s.web
    by_hand = h.make_exam_data(start_in=300, duration=1, labs=[h.lab])      # sre set-exam on the machine
    h.write_exam_json(by_hand)
    h.start_sysreseval()
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    now = time.time()
    exam = web.create(labs=[h.lab], end_before=now + 600, host_release=RELEASE / 60)    # no start time: at once
    row = web.wait_row(exam, lambda r: r['phase'] == 'conflict', 10, "the machine refusing the exam")
    assert 'sre set-exam' in row['error'], row
    time.sleep(4)
    assert h.read_exam_json() == by_hand, "the file set by hand was touched"
    assert h.wait_for_event("exam_modified", timeout=0.5) is None

    # sre del-exam on the machine: the portal tries again (15 s) and the exam starts there
    h.delete_exam_json()
    h.assert_event("exam_exited", timeout=10)
    s.forget_events()
    h.assert_event("exam_entered", timeout=25, msg="the exam of the web site, at the retry")
    assert marker_of(h.read_exam_json()).get(params.exam_web_id) == str(exam.id)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    h.assert_field_in_exam("started_at", timeout=15)

    # the exam deleted with its projects closed
    s.forget_events()
    web.delete(exam, close=True)
    h.assert_event("exam_exited", timeout=20)
    h.assert_no_exam_json(timeout=5)
    s.wait_no_project()


def scenario_5(s: Stage):
    """A lab added for everybody during the exam reaches the machine."""
    h, web = s.h, s.web
    if h.lab2 == h.lab:
        raise AssertionError("this scenario needs a second lab (--lab2)")
    h.start_sysreseval()
    exam = web.create(**s.window(seconds=600))
    s.until_active(exam)

    s.forget_events()
    web.set_labs(exam, [h.lab, h.lab2])
    h.assert_event("exam_modified", timeout=10)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is False, timeout=10)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    data = h.read_exam_json()
    assert data[params.exam_labs] == [[h.lab, None], [h.lab2, None]] and params.exam_started_at in data
    assert len(s.projects()) == 2

    web.close(exam)                            # closed while it runs: the agent ends it first
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()
    calls = [argv[0] for argv, _, _ in s.agent.calls() if argv[0] in ('end-exam', 'stop')]
    assert calls == ['end-exam', 'stop', 'stop'], calls


def scenario_6(s: Stage):
    """A student logging in after the start gets their own clock, which the duration ends."""
    h, web = s.h, s.web
    body = s.window(start_in=15, seconds=600, duration=1)       # a minute each, in a window of ten
    exam = web.create(**body)

    # the start passes with nobody at the machine: locked, never started
    row = web.wait_row(exam, lambda r: r['phase'] == 'starting', 30, "the machine locked, the start passed")
    assert row['locked'] and row['started_at'] is None and not row['pre_started']
    time.sleep(5)
    h.start_sysreseval()                       # the student arrives late
    h.assert_event("exam_entered", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=10)
    assert h.wait_for_event("phase_change", lambda e: e.get("new") == "waiting", timeout=0.5) is None, \
        "no waiting phase once the start passed"
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    data = h.assert_field_in_exam("started_at", timeout=15)
    assert data[params.exam_duration] == 1

    # its own clock: a minute from its own start, long before the end-before time
    row = web.wait_row(exam, lambda r: r['phase'] == 'active' and r['started_at'], 15, "the clock of the machine")
    assert row['started_at'] - body['start_after'] >= 4, "the clock must start when the student arrives"
    assert abs(row['end_at'] - (row['started_at'] + 60)) < 1.5, row
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=60 + 15)
    assert time.time() < body['end_before'] - 300, "ended by the duration, not by the end-before time"
    h.assert_field_in_exam("ended_at", timeout=15)
    row = web.wait_row(exam, lambda r: r['phase'] == 'ended', 10, "the ended machine")

    # the end screen stays until end-before + release (ten minutes away: not waited for here)
    assert abs(row['release_at'] - (body['end_before'] + RELEASE)) < 1.5
    time.sleep(3)
    assert h.read_exam_json() is not None and len(s.projects()) == 1
    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()


def scenario_7(s: Stage):
    """Minutes added, then taken, for the machine during the exam."""
    h, web = s.h, s.web
    h.start_sysreseval()
    exam = web.create(**s.window(seconds=600, duration=2))
    started = s.until_active(exam)[params.exam_started_at]
    row = web.wait_row(exam, lambda r: r['phase'] == 'active' and r['started_at'], 15, "the clock of the machine")
    began = row['started_at']
    assert abs(row['end_at'] - (began + 120)) < 1.5

    s.forget_events()
    web.adjust(exam, 1)
    h.assert_event("exam_modified", timeout=10)
    data = h.read_exam_json()
    assert data[params.exam_duration] == 3 and data[params.exam_started_at] == started
    row = web.wait_row(exam, lambda r: r['extra_minutes'] == 1, 10, "the extra minute")
    assert row['phase'] == 'active' and abs(row['end_at'] - (began + 180)) < 1.5

    # two minutes taken once more than a minute is spent: nothing is left, the exam ends at once
    while time.time() < began + 62:
        time.sleep(0.5)
    s.forget_events()
    web.adjust(exam, -2)
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=10)
    data = h.assert_field_in_exam("ended_at", timeout=15)
    assert data[params.exam_duration] == 1 and data[params.exam_started_at] == started
    row = web.wait_row(exam, lambda r: r['phase'] == 'ended', 10, "the ended machine")
    assert row['extra_minutes'] == -1
    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()


def scenario_8(s: Stage):
    """The start brought forward, postponed, then Start now."""
    h, web = s.h, s.web
    h.start_sysreseval()
    exam = web.create(**s.window(start_in=300, seconds=600))            # in five minutes: not locked
    time.sleep(3)
    assert h.read_exam_json() is None and web.row(exam)['phase'] == 'scheduled'

    # brought forward: the lock comes, the GUI waits (and pre-starts: less than a minute to go)
    now = time.time()
    web.edit(exam, start_after=now + 20, end_before=now + 620)
    h.assert_event("exam_entered", timeout=20)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)
    h.assert_field_in_exam("pre_start_date", timeout=15)
    assert len(s.projects()) == 1

    # postponed beyond the lock: the machine is given back, its project left as a plain one
    s.forget_events()
    s.agent.forget_calls()
    now = time.time()
    web.edit(exam, start_after=now + 300, end_before=now + 900)
    h.assert_event("exam_exited", timeout=15)
    s.wait_no_file()
    assert web.row(exam)['phase'] == 'scheduled' and len(s.projects()) == 1
    assert not [argv for argv, _, _ in s.agent.calls() if argv[0] in ('end-exam', 'stop')]

    # Start now: locked and started at once, no waiting phase, the project of before reused
    s.forget_events()
    web.edit(exam, start_after=time.time())
    h.assert_event("exam_entered", timeout=15)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=10)
    assert h.wait_for_event("phase_change", lambda e: e.get("new") == "waiting", timeout=0.5) is None
    data = h.assert_field_in_exam("started_at", timeout=20)
    assert params.exam_pre_start_date in data and len(s.projects()) == 1

    web.end_now(exam)
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=10)
    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()


def scenario_9(s: Stage):
    """A machine unselected, then selected again (a fresh run); the exam deleted without closing."""
    h, web = s.h, s.web
    h.start_sysreseval()
    exam = web.create(**s.window(seconds=600), audience={'logins': ['alice']})   # the audience keeps it valid
    first = s.until_active(exam)[params.exam_started_at]

    # unselected in Edit: the file alone goes, the project of the GUI stays as a plain one
    s.forget_events()
    s.agent.forget_calls()
    web.edit(exam, hosts=[])
    h.assert_event("exam_exited", timeout=15)
    s.wait_no_file()
    assert web.rows(exam) == [] and len(s.projects()) == 1
    assert not [argv for argv, _, _ in s.agent.calls() if argv[0] in ('end-exam', 'stop')]

    # selected again: a new record, a new file, a new clock
    time.sleep(1.5)
    s.forget_events()
    web.edit(exam, hosts=[HOST])
    h.assert_event("exam_entered", timeout=15)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=15)
    data = h.assert_field_in_exam("started_at", timeout=20)
    assert data[params.exam_started_at] != first and params.exam_ended_at not in data
    assert len(s.projects()) == 1, "the project of the first run serves the second"
    row = web.wait_row(exam, lambda r: r['phase'] == 'active', 15, "the machine running again")
    assert row['closed_at'] is None and row['extra_minutes'] == 0

    # the exam deleted, its projects kept
    s.forget_events()
    web.delete(exam, close=False)
    h.assert_event("exam_exited", timeout=15)
    s.wait_no_file()
    assert len(s.projects()) == 1
    assert not [argv for argv, _, _ in s.agent.calls() if argv[0] in ('end-exam', 'stop')]


def scenario_10(s: Stage):
    """A release delay of 0: the machine is closed at the end, no end screen kept."""
    h, web = s.h, s.web
    h.start_sysreseval()
    body = s.window(host_release=0)
    exam = web.create(**body)
    s.until_active(exam)
    h.assert_event("phase_change", lambda e: e.get("new") == "ended", timeout=EXAM_SECONDS + 20)
    h.assert_event("exam_exited", timeout=15)
    assert time.time() < body['end_before'] + 15, "closed at the end, not a delay after it"
    s.wait_no_file()
    s.wait_no_project()
    web.wait_row(exam, lambda r: r['phase'] == 'closed' and not r['closing'], 15, "the closed machine")
    # the GUI and the agent both end the exam then: whoever came first, the agent stopped last
    calls = [argv[0] for argv, _, _ in s.agent.calls() if argv[0] in ('end-exam', 'stop')]
    assert calls and calls[-1] == 'stop' and calls.count('stop') == 1, calls


def scenario_11(s: Stage):
    """The student logs out and in again, while waiting then during the exam."""
    h, web = s.h, s.web
    h.start_sysreseval()
    exam = web.create(**s.window(start_in=40, seconds=600, host_lead=30 / 60))    # thirty seconds of waiting
    h.assert_event("exam_entered", timeout=25)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    s.end_gui()
    h.start_sysreseval()
    h.assert_event("exam_entered", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=45)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    started = h.assert_field_in_exam("started_at", timeout=15)[params.exam_started_at]
    web.adjust(exam, 1)                        # the portal rewrites the file in between

    s.end_gui()
    h.start_sysreseval()
    h.assert_event("exam_entered", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=10)
    assert h.wait_for_event("phase_change", lambda e: e.get("new") == "waiting", timeout=0.5) is None
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=10)
    # the exam is not started a second time: the clock of the machine is the one of before
    h.assert_event("tick", lambda e: e.get("start_exam_called") is False and e.get("phase") == "active", timeout=10)
    time.sleep(2)
    data = h.read_exam_json()
    assert data[params.exam_started_at] == started and len(s.projects()) == 1
    assert marker_of(data).get(params.exam_web_id) == str(exam.id)

    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()


def scenario_12(s: Stage):
    """A project of another lab is stopped at the pre-start; a lab added while waiting."""
    h, web = s.h, s.web
    if h.lab2 == h.lab:
        raise AssertionError("this scenario needs a second lab (--lab2)")
    h.start_sysreseval()
    other = s.other_project()                  # the student works on something else
    time.sleep(2)
    exam = web.create(**s.window(start_in=45, seconds=600, host_lead=35 / 60))
    h.assert_event("exam_entered", timeout=25)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    # the pre-start of the GUI (less than a minute before the start): the other project goes
    deadline = time.time() + 30
    while other.exists() and time.time() < deadline:
        time.sleep(0.3)
    assert not other.exists(), "the project of another lab was not stopped by pre-start-exam"
    h.assert_field_in_exam("pre_start_date", timeout=15)

    # a second lab for everybody while the machine waits: started before the exam begins
    s.forget_events()
    web.set_labs(exam, [h.lab, h.lab2])
    h.assert_event("exam_modified", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=50)

    def both_labs(event):
        expected = event.get("expected_labs", [])
        return h.lab.replace("/", "@") in expected and h.lab2.replace("/", "@") in expected

    h.assert_event("tick", both_labs, timeout=15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    assert len(s.projects()) == 2
    h.assert_field_in_exam("started_at", timeout=15)

    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()


def scenario_13(s: Stage):
    """Hybrid: a student of the audience logged in at the machine takes the exam there."""
    h, web = s.h, s.web
    s.agent.sessions([h.user])                 # at the keyboard of the machine
    h.start_sysreseval()
    exam = web.create(**s.window(seconds=600), audience={'logins': [h.user, 'alice']})
    s.until_active(exam)

    # the web site binds them without starting anything: they take the exam at the machine
    deadline = time.time() + 20
    while web.binding(h.user) != ('local', HOST) and time.time() < deadline:
        time.sleep(0.5)
    assert web.binding(h.user) == ('local', HOST), web.binding(h.user)
    allowed, reason = web.start_access(h.user, h.lab)
    assert not allowed and f"workstation {HOST}" in reason, reason
    assert web.row(exam)['sessions'] == [h.user]
    # another student of the audience, not at a machine: the web exam, as usual
    assert web.binding('alice') == ('starting', '') and web.start_access('alice', h.lab) == (True, '')

    # the machine closed: the exam is over for the student on the web site too
    web.close(exam)
    h.assert_event("exam_exited", timeout=20)
    s.wait_no_project()
    assert web.binding(h.user) is None and web.binding('alice') == ('starting', '')


SCENARIOS = {
    1: ("Web scenario 1 — lock, waiting → active → ended, release", scenario_1),
    2: ("Web scenario 2 — minutes on the end screen resume the exam", scenario_2),
    3: ("Web scenario 3 — End now and Close for the machine", scenario_3),
    4: ("Web scenario 4 — a file set by hand is refused, then the machine taken", scenario_4),
    5: ("Web scenario 5 — a lab added during the exam", scenario_5),
    6: ("Web scenario 6 — a late student: the clock of the machine, ended by the duration", scenario_6),
    7: ("Web scenario 7 — minutes added then taken during the exam", scenario_7),
    8: ("Web scenario 8 — start brought forward, postponed, Start now", scenario_8),
    9: ("Web scenario 9 — machine unselected and selected again, exam deleted without closing", scenario_9),
    10: ("Web scenario 10 — a release delay of 0", scenario_10),
    11: ("Web scenario 11 — the student logs out and in, waiting then active", scenario_11),
    12: ("Web scenario 12 — another project stopped at the pre-start, a lab added while waiting", scenario_12),
    13: ("Web scenario 13 — hybrid: the student at the machine takes the exam there", scenario_13),
}


def run_scenario(name: str, fn, stage: Stage) -> bool:
    stage.reset()
    print(f"\n=== {name} ===", flush=True)
    try:
        fn(stage)
        if stage.web.failures:
            raise AssertionError("the portal's side failed:\n" + stage.web.failures[-1])
        print(f"[{PASS}] {name}", flush=True)
        return True
    except AssertionError as e:
        print(f"[{FAIL}] {name}")
        print(f"  {e}")
        print(f"  exam.json: {stage.h.read_exam_json()}")
        print(f"  calls of the agent's sre: {stage.agent.calls()}")
        for title, text in (("mock_wrapper.log", _read(stage.h.pub_dir / "mock_wrapper.log")),
                            ("agent", stage.agent.tail())):
            if text:
                print(f"  --- {title} ---")
                print(text)
        return False
    finally:
        stage.web.failures.clear()
        stage.reset()


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ''


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="End-to-end tests of an exam of the web site on a machine")
    parser.add_argument("--user", default=_current_user(), help="normal user to run sysreseval as")
    parser.add_argument("--lab", default="_TESTS_/exam_test1.py", help="lab CLI arg")
    parser.add_argument("--lab2", default="_TESTS_/exam_test2.py", help="second lab (the scenario adding a lab)")
    parser.add_argument("--sysreseval", default=params.sysreseval_exe, help="path to the sysreseval script")
    parser.add_argument("--keep-tmpdir", action="store_true", help="keep the temp SRE_PUB_DIR on exit")
    parser.add_argument("scenarios", nargs="*", type=int, metavar="N", help="scenario numbers to run (default: all)")
    args = parser.parse_args()

    try:
        import aiohttp  # noqa: F401
    except ImportError:
        print("ERROR: aiohttp is not installed: the web front-end needs it (make venv)", file=sys.stderr)
        sys.exit(1)

    tmpdir = Path(tempfile.mkdtemp(prefix="sre_exam_web_test_"))
    tmpdir.chmod(0o755)
    pub_dir = tmpdir / "sre_pub"
    pub_dir.mkdir(mode=0o777)
    pub_dir.chmod(0o777)        # the commands of the GUI (the mock wrapper, as the student) rewrite exam.json there
    projects = pub_dir / "projects"
    projects.mkdir(mode=0o777)
    projects.chmod(0o777)

    print(f"Temp SRE_PUB_DIR: {pub_dir}")
    print(f"User: {args.user}  Lab: {args.lab}  Lab2: {args.lab2}")

    harness = ExamTestHarness(user=args.user, lab=args.lab, lab2=args.lab2, sre_path=params.sre_exe,
                              sysreseval_path=args.sysreseval, pub_dir=pub_dir, mock_wrapper=MOCK_WRAPPER)
    agent = AgentProcess(tmpdir, pub_dir, sorted({args.lab, args.lab2}))
    web = None
    results = {}
    try:
        agent.start()
        web = WebSide(agent.url)
        stage = Stage(harness, agent, web)
        for n in args.scenarios or list(SCENARIOS):
            if n not in SCENARIOS:
                print(f"WARNING: unknown scenario {n}, skipping")
                continue
            name, fn = SCENARIOS[n]
            results[n] = run_scenario(name, fn, stage)
    finally:
        harness.stop_sysreseval()
        end_gui_of(args.user)
        if web is not None:
            web.stop()
        agent.stop()
        if args.keep_tmpdir:
            print(f"\nTemp dir kept at: {tmpdir}")
        else:
            shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n" + "=" * 60)
    passed = sum(1 for ok in results.values() if ok)
    for n, ok in sorted(results.items()):
        print(f"  [{PASS if ok else FAIL}] {SCENARIOS[n][0]}")
    print(f"\n{passed}/{len(results)} passed")
    sys.exit(0 if results and passed == len(results) else 1)


if __name__ == "__main__":
    main()
