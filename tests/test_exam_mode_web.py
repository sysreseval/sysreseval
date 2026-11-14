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
  scenario_numbers      1-5 (default: all)
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
                               'poll_interval = 0.5\noccupied_check = "never"\n')
        self.config.chmod(0o600)
        self._proc: subprocess.Popen | None = None
        self._out = None

    def start(self, timeout: float = 20.0):
        self._out = open(self.output, 'w')
        env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
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

    def delete(self, exam, close: bool):
        async def gone():
            await self.hosts.release(exam, close)
            await self.exams.delete(exam.id)
        self.call(gone())

    # -- what the Exams page shows ---------------------------------------------------------------

    def row(self, exam) -> dict:
        """The row of the machine in the machines table of the exam."""
        async def rows():
            return self.hosts.rows_of(exam, [])
        return self.call(rows())[0]

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
        self.h.stop_sysreseval()
        end_gui_of(self.h.user)
        self.web.reset()
        self.h.clean()
        self.web.call(self.web.pool.refresh())
        self.agent.forget_calls()

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


SCENARIOS = {
    1: ("Web scenario 1 — lock, waiting → active → ended, release", scenario_1),
    2: ("Web scenario 2 — minutes on the end screen resume the exam", scenario_2),
    3: ("Web scenario 3 — End now and Close for the machine", scenario_3),
    4: ("Web scenario 4 — a file set by hand is refused, then the machine taken", scenario_4),
    5: ("Web scenario 5 — a lab added during the exam", scenario_5),
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
