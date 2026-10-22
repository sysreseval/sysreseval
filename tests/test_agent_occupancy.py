"""Tests of sreweb.agent.occupancy: local sessions through a fake loginctl / who."""
import subprocess

from sreweb.agent import occupancy as O


class FakeRun:
    """A fake subprocess.run answering the loginctl / who calls from a table."""

    def __init__(self, answers: dict, failing=()):
        self.answers = answers
        self.failing = set(failing)
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        key = ' '.join(argv[:3]) if argv[0] == 'loginctl' and argv[1] == 'show-session' else argv[0] if argv[0] == 'who' \
            else ' '.join(argv[:2])
        if argv[0] in self.failing:
            raise OSError('not installed')
        if key not in self.answers:
            return subprocess.CompletedProcess(argv, 1, '', 'no such')
        return subprocess.CompletedProcess(argv, 0, self.answers[key], '')


LIST = "     2 1000 alice seat0 tty2\n     5 1001 bob\n     7 0 root\n"
SESSIONS = {
    'loginctl list-sessions': LIST,
    'loginctl show-session 2': "Name=alice\nSeat=seat0\nTTY=tty2\nClass=user\nRemote=no\nUser=1000\n",
    'loginctl show-session 5': "Name=bob\nSeat=\nTTY=pts/0\nClass=user\nRemote=yes\nUser=1001\n",   # ssh: not local
    'loginctl show-session 7': "Name=root\nSeat=seat0\nTTY=tty1\nClass=user\nRemote=no\nUser=0\n",   # system user
}


def test_loginctl_sessions():
    run = FakeRun(SESSIONS)
    assert O.loginctl_sessions(run) == ['alice']
    assert O.local_sessions(run) == ['alice']


def test_loginctl_absent_falls_back_to_who():
    run = FakeRun({'who': "carol    tty2         2026-10-21 10:00 (:0)\ndave     pts/1        2026-10-21 10:05 (10.0.0.9)\n"},
                  failing={'loginctl'})
    assert O.loginctl_sessions(run) is None
    assert O.local_sessions(run) == ['carol']


def test_who_forms():
    run = FakeRun({'who': "erin     :0           2026-10-21 09:00 (:0)\nfrank    pts/0        2026-10-21 09:00 (:0)\n"
                          "grace    pts/2        2026-10-21 09:00 (host.example)\n"})
    assert O.who_sessions(run) == ['erin', 'frank']


def test_occupancy_modes():
    run = FakeRun(SESSIONS)
    assert O.occupancy('both', 2, run) == (True, ['session:alice', 'projects:2'])
    assert O.occupancy('sessions', 2, run) == (True, ['session:alice'])
    assert O.occupancy('projects', 0, run) == (False, [])
    assert O.occupancy('projects', 1, run) == (True, ['projects:1'])
    assert O.occupancy('never', 3, run) == (False, [])
    assert O.occupancy('both', 0, FakeRun({'loginctl list-sessions': ''}, failing={'who'})) == (False, [])
