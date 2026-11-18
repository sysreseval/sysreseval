"""The Qt GUIs of a machine found among its processes (SRE/procscan.py) and their users as the
web agent reports them (sreweb/agent/localgui.py): the Clients view of the Watch page."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from SRE import procscan
from sreweb.agent import localgui

PYTHON = '/opt/sre/venv/bin/python3'
GUI = [PYTHON, '/opt/sre/bin/../src/sysreseval.py']
BOOT = 1_700_000_000
TICKS = 100
HOST_NS = 'pid:[4026531836]'
CONTAINER_NS = 'pid:[4026532999]'


def fake_proc(root: Path, procs: dict, *, own_ns: str | None = HOST_NS, boot: int | None = BOOT) -> str:
    """A /proc tree: pid → ``{'argv', 'start' (clock ticks since the boot), 'ns', 'comm'}``;
    *argv* ``None`` = a directory without ``cmdline`` (a process that ended), *start* ``None`` =
    no ``stat`` file, *ns* ``None`` = no namespace link.  *own_ns*: the namespace of ``self``."""
    root.mkdir()
    for pid, process in procs.items():
        directory = root / str(pid)
        directory.mkdir()
        if process.get('argv') is not None:
            (directory / 'cmdline').write_bytes(b''.join(arg.encode() + b'\0' for arg in process['argv']))
        if process.get('start') is not None:
            fields = ['S'] + ['0'] * 18 + [str(process['start'])] + ['0'] * 10
            (directory / 'stat').write_text(f"{pid} ({process.get('comm', 'python3')}) {' '.join(fields)}\n")
        if process.get('ns', HOST_NS) is not None:
            (directory / 'ns').mkdir()
            os.symlink(process.get('ns', HOST_NS), directory / 'ns' / 'pid')
    (root / 'self').mkdir()
    if own_ns is not None:
        (root / 'self' / 'ns').mkdir()
        os.symlink(own_ns, root / 'self' / 'ns' / 'pid')
    if boot is not None:
        (root / 'stat').write_text(f"cpu  1 2 3 4\nbtime {boot}\nprocesses 99\n")
    return str(root)


def uids(table: dict):
    """A ``uid_of`` for ``gui_processes``: *table* pid → uid, an ``OSError`` for the others."""
    def uid_of(pid):
        if pid not in table:
            raise FileNotFoundError(pid)
        return table[pid]
    return uid_of


def users(table: dict):
    """A ``pwd.getpwuid``: *table* uid → ``(login, gecos)``; the calls are counted."""
    calls = []

    def lookup(uid):
        calls.append(uid)
        if uid not in table:
            raise KeyError(uid)
        return SimpleNamespace(pw_name=table[uid][0], pw_gecos=table[uid][1])
    lookup.calls = calls
    return lookup


class TestRunsScript:
    @pytest.mark.parametrize('argv', [
        GUI,                                                              # bin/sysreseval
        ['/usr/bin/python3', '/usr/lib/sysreseval/sysreseval.py'],        # the Debian launcher
        ['python3.13', 'src/sysreseval.py', '--debug'],
    ])
    def test_the_gui(self, argv):
        assert procscan.runs_script(argv, procscan.GUI_SCRIPT)

    @pytest.mark.parametrize('argv', [
        ['/bin/bash', '/opt/sre/bin/sysreseval'],                # the wrapper before its exec
        ['vim', 'src/sysreseval.py'],
        ['grep', '-r', 'x', 'sysreseval.py'],
        [PYTHON, '-W', 'ignore', '/opt/sre/src/sre.py', 'list'],
        [PYTHON, '/opt/sre/src/not_sysreseval.py'],
        [PYTHON, '-m', 'sysreseval'],                            # no module given: only the script counts
        [],
    ])
    def test_not_the_gui(self, argv):
        assert not procscan.runs_script(argv, procscan.GUI_SCRIPT)

    def test_module(self):
        assert procscan.runs_script(['python3', '-m', 'sreweb.agent'], 'sre_agent.py', 'sreweb.agent')
        assert not procscan.runs_script(['python3', 'sreweb.agent', '-m'], 'sre_agent.py', 'sreweb.agent')


class TestGuiProcesses:
    def test_found_with_user_and_start_time(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {1: {'argv': ['/sbin/init'], 'start': 1},
                                             4242: {'argv': GUI, 'start': 360_000},
                                             77: {'argv': ['sshd'], 'start': 5}})
        found = procscan.gui_processes(proc, uid_of=uids({4242: 1000}), ticks=TICKS)
        assert found == [{'pid': 4242, 'uid': 1000, 'since': BOOT + 3600.0}]

    def test_the_command_name_may_hold_spaces_and_parentheses(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 200, 'comm': 'py (x) y)'}})
        assert procscan.start_time(proc, 4242, ticks=TICKS) == BOOT + 2.0

    def test_a_process_of_a_container_is_not_a_gui_of_the_machine(self, tmp_path):
        """Root in a lab container can run a script of that name under any uid."""
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 100, 'ns': CONTAINER_NS},
                                             4300: {'argv': GUI, 'start': 100}})
        found = procscan.gui_processes(proc, uid_of=uids({4242: 1000, 4300: 1001}), ticks=TICKS)
        assert [p['pid'] for p in found] == [4300]
        assert not procscan.same_pid_namespace(proc, 4242) and procscan.same_pid_namespace(proc, 4300)

    def test_namespaces_that_cannot_be_read(self, tmp_path):
        """Not root, or a kernel without them: every process counts."""
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 100, 'ns': CONTAINER_NS}}, own_ns=None)
        assert [p['pid'] for p in procscan.gui_processes(proc, uid_of=uids({4242: 1000}))] == [4242]
        proc = fake_proc(tmp_path / 'proc2', {4242: {'argv': GUI, 'start': 100, 'ns': None}})
        assert [p['pid'] for p in procscan.gui_processes(proc, uid_of=uids({4242: 1000}))] == [4242]

    def test_processes_that_ended_meanwhile(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': None}, 4300: {'argv': GUI, 'start': 100},
                                             4400: {'argv': GUI, 'start': 100}})
        assert [p['pid'] for p in procscan.gui_processes(proc, uid_of=uids({4300: 1000}))] == [4300]   # 4400: no owner

    def test_start_time_unknown(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI}})                    # no stat file
        assert procscan.gui_processes(proc, uid_of=uids({4242: 1000})) == [{'pid': 4242, 'uid': 1000, 'since': None}]
        proc = fake_proc(tmp_path / 'proc2', {4242: {'argv': GUI, 'start': 100}}, boot=None)
        assert procscan.gui_processes(proc, uid_of=uids({4242: 1000}))[0]['since'] is None
        assert procscan.boot_time(proc) is None

    def test_the_owner_of_the_process_directory_by_default(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 100}})
        assert procscan.gui_processes(proc)[0]['uid'] == os.stat(tmp_path / 'proc' / '4242').st_uid

    def test_no_proc(self, tmp_path):
        assert procscan.gui_processes(str(tmp_path / 'missing')) == []
        assert procscan.command_lines(str(tmp_path / 'missing')) is None

    def test_command_lines(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {9: {'argv': ['b', 'x y']}, 3: {'argv': []}, 5: {'argv': None}})
        assert procscan.command_lines(proc) == [(3, []), (9, ['b', 'x y'])]


class TestGuiUsers:
    def test_one_entry_per_user_with_the_oldest_start(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {4242: {'argv': GUI, 'start': 500}, 4300: {'argv': GUI, 'start': 200},
                                             5000: {'argv': GUI, 'start': 300}, 6000: {'argv': GUI}})
        lookup = users({1000: ('zoe', 'Zoe Martin,,,'), 1001: ('alice', 'alice dupont'), 1002: ('bob', '')})
        found = localgui.gui_users(proc, user_of=localgui.Users(lookup),
                                   uid_of=uids({4242: 1000, 4300: 1000, 5000: 1001, 6000: 1002}))
        ticks = os.sysconf('SC_CLK_TCK')
        assert found == [{'login': 'alice', 'fullname': 'alice dupont', 'since': BOOT + 300 / ticks},
                         {'login': 'bob', 'fullname': '', 'since': None},
                         {'login': 'zoe', 'fullname': 'Zoe Martin', 'since': BOOT + 200 / ticks}]

    def test_system_accounts_are_left_out(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {10: {'argv': GUI, 'start': 1}, 11: {'argv': GUI, 'start': 1},
                                             12: {'argv': GUI, 'start': 1}})
        lookup = users({0: ('root', 'root'), 999: ('sre', ''), 1000: ('etudiant', 'Etudiant')})
        found = localgui.gui_users(proc, user_of=localgui.Users(lookup), uid_of=uids({10: 0, 11: 999, 12: 1000}))
        assert [user['login'] for user in found] == ['etudiant']
        assert lookup.calls == [1000]

    def test_nobody(self, tmp_path):
        proc = fake_proc(tmp_path / 'proc', {1: {'argv': ['/sbin/init']}})
        assert localgui.gui_users(proc) == [] and localgui.gui_users(str(tmp_path / 'missing')) == []


class TestUsers:
    def test_the_answers_are_kept(self):
        lookup = users({1000: ('zoe', 'Zoe Martin,room 12,,')})
        user_of = localgui.Users(lookup)
        assert user_of(1000) == ('zoe', 'Zoe Martin') and user_of(1000) == ('zoe', 'Zoe Martin')
        assert lookup.calls == [1000]

    def test_an_unknown_uid_is_asked_again(self):
        table = {}
        lookup = users(table)
        user_of = localgui.Users(lookup)
        assert user_of(1234) == ('1234', '')
        table[1234] = ('late', 'Late Comer')
        assert user_of(1234) == ('late', 'Late Comer') and lookup.calls == [1234, 1234]

    def test_the_full_name_is_cleaned_and_capped(self):
        user_of = localgui.Users(users({1000: ('zoe', ' Zoe\x07 Martin ' + 'x' * 300), 1001: ('bob', None)}))
        name = user_of(1000)[1]
        assert name.startswith('Zoe Martin') and len(name) <= localgui.MAX_FULLNAME and '\x07' not in name
        assert user_of(1001) == ('bob', '')
