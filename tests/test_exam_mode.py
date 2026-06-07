#!/usr/bin/env python3
"""
Exam-mode integration test runner.

Launches sysreseval --debug as a normal user, feeds it a sequence of exam.json
changes via a temp SRE_PUB_DIR, and verifies the correct sequence of JSON debug
events on stderr.

Usage:
  python3 tests/test_exam_mode.py [options] [scenario_numbers...]

Options:
  --user USER           normal user to run sysreseval as (default: current user)
  --lab LAB             lab name (CLI arg form, e.g. test/example1.py) — must exist in lab_dir
  --lab2 LAB2           second lab for multi-lab scenarios (default: same as --lab)
  --sre PATH            path to sre binary (default: /opt/sre/sbin/sre)
  --sysreseval PATH     path to sysreseval script (default: /opt/sre/bin/sysreseval)
  --keep-tmpdir         keep temp SRE_PUB_DIR on exit (for debugging)
  scenario_numbers      1-9 (default: all)

Examples:
  python3 tests/test_exam_mode.py --user student --lab test/example1.py
  python3 tests/test_exam_mode.py --user student --lab test/example1.py 1 4 8
  python3 tests/test_exam_mode.py --user student --lab test/example1.py --keep-tmpdir 1
"""

import argparse
import datetime
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from SRE import params

# ---------------------------------------------------------------------------
# Timing constants
# ---------------------------------------------------------------------------

WAIT_BEFORE_START = 5        # seconds to wait after write_exam_json before starting sysreseval
START_IN = 20                # seconds from now to start_after when setting up exam
DURATION_MIN = 1             # exam duration in minutes
EVAL_INTERVAL = 60           # seconds between auto-evals
PRE_START_MARGIN = 60        # params.max_duration_between_exam_pre_start_and_start


# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

class ExamTestHarness:
    def __init__(self, user: str, lab: str, lab2: str,
                 sre_path: str, sysreseval_path: str,
                 pub_dir: Path, mock_wrapper: Path):
        self.user = user
        self.lab = lab
        self.lab2 = lab2
        self.sre_path = sre_path
        self.sysreseval_path = sysreseval_path
        self.pub_dir = pub_dir
        self.projects_dir = pub_dir / "projects"
        self.mock_wrapper = mock_wrapper

        self._proc: subprocess.Popen | None = None
        self._stderr_thread: threading.Thread | None = None
        self.events: list[dict] = []
        self._events_lock = threading.Lock()

    # ------------------------------------------------------------------
    # sysreseval process management
    # ------------------------------------------------------------------

    def start_sysreseval(self):
        """Launch sysreseval --debug as self.user."""
        assert self._proc is None, "sysreseval already running"
        self.events = []

        env_pairs = [
            f"SRE_PUB_DIR={self.pub_dir}",
            f"SRE_WRAPPER={self.mock_wrapper}",
            f"MOCK_USERNAME={self.user}",
            "QT_QPA_PLATFORM=offscreen",
        ]
        env_str = " ".join(env_pairs)
        cmd_inner = f"{env_str} {self.sysreseval_path} --debug"

        if self.user == _current_user():
            full_cmd = ["bash", "-c", f"exec {cmd_inner}"]
        else:
            # runuser: switches user from root without a password prompt
            full_cmd = ["runuser", "-u", self.user, "--", "bash", "-c", cmd_inner]

        self._proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

        # Give the process a moment and check it didn't die immediately
        time.sleep(1.5)
        rc = self._proc.poll()
        if rc is not None:
            raise RuntimeError(
                f"sysreseval exited immediately with code {rc}.\n"
                f"Command: {' '.join(full_cmd)}\n"  
                f"Events captured: {self.events}"
            )

    def stop_sysreseval(self, timeout: float = 5.0):
        """Terminate sysreseval and wait for it to exit."""
        if self._proc is None:
            return
        try:
            self._proc.terminate()
        except ProcessLookupError:
            pass
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        self._proc = None
        if self._stderr_thread:
            self._stderr_thread.join(timeout=2.0)
            self._stderr_thread = None

    # Qt offscreen plugin warnings that are harmless and should not pollute output
    _IGNORED_STDERR = (
        "This plugin does not support propagateSizeHints()",
        "This plugin does not support raise()",
        "This plugin does not support setWindowTitle()",
        "This plugin does not support requestActivate()",
    )

    def _read_stderr(self):
        for line in self._proc.stderr:
            line = line.rstrip()
            if not line:
                continue
            if any(s in line for s in self._IGNORED_STDERR):
                continue
            try:
                event = json.loads(line)
                with self._events_lock:
                    self.events.append(event)
            except json.JSONDecodeError:
                # Print non-JSON lines (Python tracebacks, Qt errors, etc.)
                print(f"[sysreseval] {line}", file=sys.stderr, flush=True)

    # ------------------------------------------------------------------
    # exam.json manipulation
    # ------------------------------------------------------------------

    def write_exam_json(self, data: dict):
        path = self.pub_dir / "exam.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=4))
        tmp.chmod(0o666)
        tmp.rename(path)

    def read_exam_json(self) -> dict | None:
        path = self.pub_dir / "exam.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except Exception:
            return None

    def delete_exam_json(self):
        path = self.pub_dir / "exam.json"
        path.unlink(missing_ok=True)

    def clean(self):
        self.delete_exam_json()
        if self.projects_dir.exists():
            for d in self.projects_dir.iterdir():
                if d.is_dir():
                    shutil.rmtree(d)

    # ------------------------------------------------------------------
    # Assertions / polling helpers
    # ------------------------------------------------------------------

    def wait_for_event(self, event_type: str, condition=None,
                       timeout: float = 30.0, poll: float = 0.2) -> dict | None:
        """
        Poll self.events until an event with event_type (and matching condition) appears.
        Returns the matching event, or None on timeout.
        """
        deadline = time.time() + timeout
        checked = 0
        while time.time() < deadline:
            with self._events_lock:
                snapshot = self.events[checked:]
                checked += len(snapshot)
            for ev in snapshot:
                if ev.get("event") == event_type:
                    if condition is None or condition(ev):
                        return ev
            time.sleep(poll)
        return None

    def assert_event(self, event_type: str, condition=None,
                     timeout: float = 30.0, msg: str = "") -> dict:
        ev = self.wait_for_event(event_type, condition, timeout)
        if ev is None:
            desc = f"event={event_type!r}"
            if msg:
                desc += f" ({msg})"
            raise AssertionError(f"Timed out waiting for {desc}")
        return ev

    def assert_phase_seq(self, phases: list, timeout: float = 120.0):
        """
        Assert that phase_change events appear in the given sequence.
        phases is a list of "new" phase values to see in order.
        """
        remaining = list(phases)
        deadline = time.time() + timeout
        checked = 0
        while remaining and time.time() < deadline:
            with self._events_lock:
                snapshot = self.events[checked:]
                checked += len(snapshot)
            for ev in snapshot:
                if ev.get("event") == "phase_change":
                    if ev.get("new") == remaining[0]:
                        remaining.pop(0)
                        if not remaining:
                            break
            time.sleep(0.2)
        if remaining:
            raise AssertionError(
                f"Phase sequence incomplete; still waiting for {remaining!r}\n"
                f"Events seen: {[e for e in self.events if e.get('event') == 'phase_change']}"
            )

    def assert_field_in_exam(self, field: str, timeout: float = 30.0) -> dict:
        """Poll exam.json until field is present; return the exam data."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.read_exam_json()
            if data is not None and field in data:
                return data
            time.sleep(0.5)
        raise AssertionError(f"Field {field!r} never appeared in exam.json within {timeout}s")

    def assert_no_exam_json(self, timeout: float = 10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not (self.pub_dir / "exam.json").exists():
                return
            time.sleep(0.2)
        raise AssertionError("exam.json still exists after expected deletion")

    def make_exam_data(self, start_in: float = START_IN,
                       duration: int = DURATION_MIN,
                       end_before: datetime.datetime | None = None,
                       labs: list | None = None) -> dict:
        """Build an exam.json dict for the current time."""
        now = datetime.datetime.now()
        start_after = now + datetime.timedelta(seconds=start_in)
        data: dict = {
            "start_after": start_after.isoformat(timespec='seconds'),
            "labs": labs if labs is not None else [self.lab],
        }
        if end_before is not None:
            data["end_before"] = end_before.isoformat(timespec='seconds')
        else:
            data["duration"] = duration
        return data

    def _events_snapshot(self) -> list[dict]:
        with self._events_lock:
            return list(self.events)


# ---------------------------------------------------------------------------
# Scenario runners
# ---------------------------------------------------------------------------

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"


def run_scenario(name: str, fn, harness: ExamTestHarness):
    harness.stop_sysreseval()
    harness.clean()
    print(f"\n=== {name} ===")
    try:
        fn(harness)
        print(f"[{PASS}] {name}")
        return True
    except AssertionError as e:
        print(f"[{FAIL}] {name}")
        print(f"  {e}")
        log = harness.pub_dir / "mock_wrapper.log"
        if log.exists():
            print(f"  --- mock_wrapper.log ---")
            print(log.read_text())
        return False
    finally:
        harness.stop_sysreseval()
        harness.clean()


# ------------------------------------------------------------------

def scenario_1(h: ExamTestHarness):
    """waiting → active → ended (with duration)."""
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=START_IN + 15)

    h.assert_event("tick", lambda e: e.get("start_exam_called") is True, timeout=15)

    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)

    h.assert_event("phase_change", lambda e: e.get("new") == "ended",
                   timeout=DURATION_MIN * 60 + 30)

    data = h.assert_field_in_exam("ended_at", timeout=15)
    # ended_at should be present
    assert "ended_at" in data


def scenario_2(h: ExamTestHarness):
    """Non-exam project terminated when exam mode is activated."""
    # Start sysreseval with no exam.json
    h.start_sysreseval()

    # Simulate an open non-exam project by creating its directory (as the GUI would after
    # the user clicks "Open project").
    non_exam_lab = "other_lab"
    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    project_name = f"{ts}@@@{non_exam_lab}@@@{h.user}"
    project_dir = h.projects_dir / project_name
    project_dir.mkdir(parents=True)
    project_dir.chmod(0o777)   # must be writable by student user (mock_sre_wrapper)
    info = {"lab_name": non_exam_lab, "lab_hash": "mock", "title": "Other lab"}
    info_file = project_dir / "info.json"
    info_file.write_text(json.dumps(info))
    info_file.chmod(0o666)

    time.sleep(2)  # let the 1-second poll pick up the project tab

    # Activate exam mode
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)

    h.assert_event("exam_entered", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    # pre-start-exam fires immediately (START_IN < PRE_START_MARGIN) and stops non-exam projects
    deadline = time.time() + 30
    while time.time() < deadline:
        if not project_dir.exists():
            break
        time.sleep(0.5)
    assert not project_dir.exists(), "Non-exam project was not terminated by pre-start-exam"

    # Rest follows scenario 1
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=START_IN + 15)
    h.assert_event("tick", lambda e: e.get("start_exam_called") is True, timeout=15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)
    h.assert_event("phase_change", lambda e: e.get("new") == "ended",
                   timeout=DURATION_MIN * 60 + 30)
    data = h.assert_field_in_exam("ended_at", timeout=15)
    assert "ended_at" in data


def scenario_3(h: ExamTestHarness):
    """Restart sysreseval during active phase."""
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=START_IN + 15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)

    h.stop_sysreseval()

    # Restart — started_at already set in exam.json
    h.start_sysreseval()

    h.assert_event("startup", timeout=5)
    h.assert_event("exam_entered", timeout=5)

    # Should go directly to active, no waiting
    phase_events = []
    deadline = time.time() + 10
    while time.time() < deadline:
        with h._events_lock:
            phase_events = [e for e in h.events if e.get("event") == "phase_change"]
        if any(e.get("new") == "active" for e in phase_events):
            break
        time.sleep(0.2)
    assert any(e.get("new") == "active" for e in phase_events), "Expected phase_change to active"
    assert not any(e.get("new") == "waiting" for e in phase_events), \
        "Should not see waiting phase on restart in active mode"

    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=10)

    # start-exam should NOT be called again (started_at already present)
    h.assert_event("tick",
                   lambda e: e.get("start_exam_called") is False and e.get("phase") == "active",
                   timeout=10)

    h.assert_event("phase_change", lambda e: e.get("new") == "ended",
                   timeout=DURATION_MIN * 60 + 30)


def scenario_4(h: ExamTestHarness):
    """Restart sysreseval during waiting phase."""
    start_in = 60  # longer wait
    data = h.make_exam_data(start_in=start_in, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    h.stop_sysreseval()

    # Still before start_after — restart
    h.start_sysreseval()
    h.assert_event("startup", timeout=5)
    h.assert_event("exam_entered", timeout=5)
    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    # Wait for active
    h.assert_event("phase_change", lambda e: e.get("new") == "active",
                   timeout=start_in + 20)


def scenario_5(h: ExamTestHarness):
    """del-exam after exam completion exits exam mode."""
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "ended",
                   timeout=START_IN + DURATION_MIN * 60 + 30)
    h.assert_field_in_exam("ended_at", timeout=15)

    # Delete exam.json (simulates sre del-exam)
    h.delete_exam_json()

    h.assert_event("exam_exited", timeout=10)
    h.assert_no_exam_json(timeout=5)


def scenario_6(h: ExamTestHarness):
    """end_before instead of duration."""
    now = datetime.datetime.now()
    start_after = now + datetime.timedelta(seconds=START_IN)
    end_before = now + datetime.timedelta(seconds=START_IN + DURATION_MIN * 60 + 10)
    data = {
        "start_after": start_after.isoformat(timespec='seconds'),
        "end_before": end_before.isoformat(timespec='seconds'),
        "labs": [h.lab],
    }
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_phase_seq(["waiting", "active", "ended"],
                       timeout=START_IN + DURATION_MIN * 60 + 30)

    # Confirm "ended" was triggered by end_before
    phase_ev = h.wait_for_event("phase_change", lambda e: e.get("new") == "ended", timeout=5)
    assert phase_ev is not None
    # The tick preceding "ended" should have had a started_at and end_before in past
    tick_evs = [e for e in h._events_snapshot()
                if e.get("event") == "tick" and e.get("phase") == "active"
                and e.get("started_at") is not None]
    assert tick_evs, "Expected tick events with started_at in active phase"


def scenario_7(h: ExamTestHarness):
    """Changing labs during active phase triggers pre-start-exam again."""
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN * 5, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=START_IN + 15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)

    # Add second lab
    current = h.read_exam_json()
    current["labs"] = [h.lab, h.lab2]
    h.write_exam_json(current)

    h.assert_event("exam_modified", timeout=10)

    # projects_ready should go False (lab2 missing), then True after pre-start
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is False, timeout=10)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)


def scenario_8(h: ExamTestHarness):
    """Changing labs during waiting phase."""
    start_in = 60
    data = h.make_exam_data(start_in=start_in, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "waiting", timeout=10)

    # Add second lab while still waiting
    current = h.read_exam_json()
    current["labs"] = [h.lab, h.lab2]
    h.write_exam_json(current)

    h.assert_event("exam_modified", timeout=10)

    # Wait for active and both labs in expected_labs
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=start_in + 15)

    def _both_labs(ev):
        # The GUI converts lab CLI args to internal names by replacing '/' with '@'
        lab1_internal = h.lab.replace("/", "@")
        lab2_internal = h.lab2.replace("/", "@")
        expected = ev.get("expected_labs", [])
        return lab1_internal in expected and lab2_internal in expected

    h.assert_event("tick", _both_labs, timeout=15)
    h.assert_event("projects_ready_change", lambda e: e.get("ready") is True, timeout=30)


def scenario_9(h: ExamTestHarness):
    """Increasing duration during 'ended' phase returns to 'active'."""
    data = h.make_exam_data(start_in=START_IN, duration=DURATION_MIN, labs=[h.lab])
    h.write_exam_json(data)
    time.sleep(WAIT_BEFORE_START)
    h.start_sysreseval()

    h.assert_event("phase_change", lambda e: e.get("new") == "ended",
                   timeout=START_IN + DURATION_MIN * 60 + 30)

    # Now extend duration so started_at + 60min is in the future
    current = h.read_exam_json()
    current["duration"] = 60
    h.write_exam_json(current)

    h.assert_event("exam_modified", timeout=10)
    h.assert_event("phase_change", lambda e: e.get("new") == "active", timeout=10)

    # end_eval should not fire again (already called once).
    # Combine into one condition so assert_event scans past early ticks from the
    # first active phase (where end_eval_called was still False).
    h.assert_event("tick",
                   lambda e: e.get("phase") == "active" and e.get("end_eval_called") is True,
                   timeout=10,
                   msg="end_eval_called should remain True after returning to active")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCENARIOS = {
    1: ("Scenario 1 — waiting → active → ended (duration)", scenario_1),
    2: ("Scenario 2 — non-exam project terminated on exam start", scenario_2),
    3: ("Scenario 3 — restart during active phase", scenario_3),
    4: ("Scenario 4 — restart during waiting phase", scenario_4),
    5: ("Scenario 5 — del-exam after completion", scenario_5),
    6: ("Scenario 6 — end_before instead of duration", scenario_6),
    7: ("Scenario 7 — change labs during active phase", scenario_7),
    8: ("Scenario 8 — change labs during waiting phase", scenario_8),
    9: ("Scenario 9 — increase duration from ended → active", scenario_9),
}


def _current_user() -> str:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def main():
    parser = argparse.ArgumentParser(description="Exam-mode integration tests")
    parser.add_argument("--user", default=_current_user(),
                        help="normal user to run sysreseval as")
    parser.add_argument("--lab", default=None,
                        help="lab CLI arg (e.g. test/example1.py)")
    parser.add_argument("--lab2", default=None,
                        help="second lab for multi-lab scenarios (default: same as --lab)")
    parser.add_argument("--sre", default=params.sre_exe,
                        help="path to sre binary")
    parser.add_argument("--sysreseval", default=params.sysreseval_exe,
                        help="path to sysreseval script")
    parser.add_argument("--keep-tmpdir", action="store_true",
                        help="keep temp SRE_PUB_DIR on exit")
    parser.add_argument("scenarios", nargs="*", type=int, metavar="N",
                        help="scenario numbers to run (default: all)")
    args = parser.parse_args()

    lab_dir = Path(args.sre).parent.parent / "lab"

    # Resolve lab: prefer dedicated exam-test labs, fall back to first available lab
    lab = args.lab
    if lab is None:
        for candidate in ["_TESTS_/exam_test1.py", "_TESTS_/exam_test2.py"]:
            if (lab_dir / candidate).exists():
                lab = candidate
                print(f"Using exam test lab: {lab}")
                break
    if lab is None:
        skip = ["srelab", "__", "_EXAM_", "_OLD_", "_DRAFT_", "_TESTS_"]
        for p in sorted(lab_dir.rglob("*.py")):
            rel = p.relative_to(lab_dir)
            if not any(s in str(rel) for s in skip):
                lab = str(rel)
                print(f"Auto-detected lab: {lab}")
                break
    if lab is None:
        print("ERROR: Could not find a lab; use --lab", file=sys.stderr)
        sys.exit(1)

    # Resolve lab2: prefer the second exam-test lab, fall back to lab
    lab2 = args.lab2
    if lab2 is None:
        candidate2 = "_TESTS_/exam_test2.py"
        if (lab_dir / candidate2).exists() and candidate2 != lab:
            lab2 = candidate2
        else:
            lab2 = lab

    scenarios_to_run = args.scenarios or list(SCENARIOS.keys())

    mock_wrapper = Path(__file__).parent / "mock_sre_wrapper.py"
    if not mock_wrapper.exists():
        print(f"ERROR: mock_sre_wrapper.py not found at {mock_wrapper}", file=sys.stderr)
        sys.exit(1)

    tmpdir = Path(tempfile.mkdtemp(prefix="sre_exam_test_"))
    tmpdir.chmod(0o755)
    pub_dir = tmpdir / "sre_pub"
    pub_dir.mkdir(mode=0o777)
    pub_dir.chmod(0o777)   # override umask so student user can write exam.json
    projects = pub_dir / "projects"
    projects.mkdir(mode=0o777)
    projects.chmod(0o777)  # override umask so student user can create project dirs

    print(f"Temp SRE_PUB_DIR: {pub_dir}")
    print(f"User: {args.user}  Lab: {lab}  Lab2: {lab2}")

    harness = ExamTestHarness(
        user=args.user,
        lab=lab,
        lab2=lab2,
        sre_path=args.sre,
        sysreseval_path=args.sysreseval,
        pub_dir=pub_dir,
        mock_wrapper=mock_wrapper,
    )

    results = {}
    try:
        for n in scenarios_to_run:
            if n not in SCENARIOS:
                print(f"WARNING: unknown scenario {n}, skipping")
                continue
            name, fn = SCENARIOS[n]
            results[n] = run_scenario(name, fn, harness)
    finally:
        harness.stop_sysreseval()
        if args.keep_tmpdir:
            print(f"\nTemp dir kept at: {tmpdir}")
        else:
            shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for n, ok in sorted(results.items()):
        status = PASS if ok else FAIL
        print(f"  [{status}] Scenario {n}: {SCENARIOS[n][0]}")
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
