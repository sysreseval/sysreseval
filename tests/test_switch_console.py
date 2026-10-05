"""Tests for the management console of the managed switches: SRE.switch_console (one command,
allow-list of the student commands, prompt of `sre connect`), and the routing of `sre connect` /
`sre exec` to a switch with the user-mode refusals.  No Docker: Kathara's manager is a stand-in."""
import builtins
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from SRE import params, switch_console
from SRE.lib_sre import Data0, NetScheme0
from SRE.params import SRE
from SRE.switch_console import SwitchConsole, interactive, is_user_command_allowed, print_result
from SRE.command import connect, exec_

RUNNING_LAB = '20260101000000@@@test/test1@@@user'


class FakeLinkCommandError(Exception):
    """Kathara's LinkCommandError: the switch refused a command (status 1000 + errno)."""

    def __init__(self, code, message):
        super().__init__(f"failed: {code} {message}")
        self.code = code
        self.message = message


class FakeKathara:
    def __init__(self):
        self.answers = {}  # command -> output, or an exception to raise
        self.ports = {3: {'vlan': 10, 'tagged_vlans': [], 'active': True, 'endpoints': ['pc1:eth0']},
                      5: {'vlan': 0, 'tagged_vlans': [], 'active': False, 'endpoints': []}}
        self.commands = []
        self.port_queries = 0

    def get_instance(self):
        return self

    def exec_link(self, link_name, command, lab_hash=None):
        self.commands.append((link_name, command, lab_hash))
        answer = self.answers.get(command, '')
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get_link_ports(self, link_name, lab_hash=None):
        self.port_queries += 1
        return self.ports


@pytest.fixture
def kathara(monkeypatch):
    fake = FakeKathara()
    monkeypatch.setattr(switch_console, 'Kathara', fake)
    return fake


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


class Scheme(NetScheme0):
    _machine_specs = {'pc1': {}, 'pc2': {}, 'probe': {'hidden': True}}
    _network_specs = {
        'lan': {'mode': 'managed'},
        'dmz': {'mode': 'switch'},
        'closed': {'mode': 'managed', 'allow_connection': False},
        'hid': {'mode': 'managed'},
        'unused': {'mode': 'managed'},
    }
    _topology = {'lan': ['pc1', 'pc2'], 'dmz': ['pc1', 'pc2'], 'old': ['pc1', 'pc2'],
                 'closed': ['pc1', 'pc2'], 'hid': ['probe']}

    def __init__(self):
        super().__init__(data=MockData(), running_lab_name=RUNNING_LAB)
        self.lab_hash = 'fakehash'


# ---------------------------------------------------------------------------
# SwitchConsole.run()
# ---------------------------------------------------------------------------

class TestSwitchConsole:
    def test_output_and_code_zero(self, kathara):
        kathara.answers['vlan/print'] = 'VLAN 0010'
        assert SwitchConsole(Scheme()).run('lan', 'vlan/print') == ('VLAN 0010', 0)
        assert kathara.commands == [('lan', 'vlan/print', 'fakehash')]

    def test_no_output(self, kathara):
        assert SwitchConsole(Scheme()).run('lan', 'vlan/create 10') == ('', 0)

    def test_switch_error_gives_errno_and_message(self, kathara):
        kathara.answers['vlan/create 10'] = FakeLinkCommandError(1017, 'File exists')
        assert SwitchConsole(Scheme()).run('lan', 'vlan/create 10') == ('File exists', 17)

    def test_other_failure_gives_minus_two(self, kathara):
        kathara.answers['vlan/print'] = PermissionError('You are not allowed to manage collision domain `lan`.')
        output, code = SwitchConsole(Scheme()).run('lan', 'vlan/print')
        assert code == params.switch_cmd_error_code == -2
        assert 'not allowed to manage' in output

    def test_machine_reference_replaced_by_its_port(self, kathara):
        SwitchConsole(Scheme()).run('lan', 'port/setvlan @pc1 20')
        assert kathara.commands == [('lan', 'port/setvlan 3 20', 'fakehash')]

    def test_ports_read_once_per_network(self, kathara):
        console = SwitchConsole(Scheme())
        console.run('lan', 'port/setvlan @pc1 20')
        console.run('lan', 'vlan/addport 30 @pc1')
        assert kathara.port_queries == 1

    def test_ports_not_read_without_reference(self, kathara):
        SwitchConsole(Scheme()).run('lan', 'port/setvlan 3 20')
        assert kathara.port_queries == 0

    def test_references_kept_when_not_resolved(self, kathara):
        SwitchConsole(Scheme()).run('lan', 'port/setvlan @pc1 20', resolve_ports=False)
        assert kathara.commands == [('lan', 'port/setvlan @pc1 20', 'fakehash')]

    @pytest.mark.parametrize('command, message', [
        ('port/setvlan @nobody 20', "'nobody' is not a machine of network 'lan'"),
        ('port/setvlan @probe 20', "'probe' is not a machine of network 'lan'"),
        ('port/setvlan @pc2 20', "no port of switch 'lan' is used by pc2:eth0"),
    ])
    def test_unknown_reference_is_an_error_and_nothing_runs(self, kathara, command, message):
        assert SwitchConsole(Scheme()).run('lan', command) == (message, -2)
        assert kathara.commands == []

    def test_kathara_without_console(self, monkeypatch):
        old = SimpleNamespace(get_instance=lambda: SimpleNamespace())
        monkeypatch.setattr(switch_console, 'Kathara', old)
        output, code = SwitchConsole(Scheme()).run('lan', 'vlan/print')
        assert code == -2
        assert 'no switch console' in output


class TestUserCommands:
    @pytest.mark.parametrize('command', ['help', 'vlan/create 10', '  port/setvlan 3 10 ', 'vlan/print',
                                         'port/allprint', 'hash/print', 'fstp/setfstp 1'])
    def test_allowed(self, command):
        assert is_user_command_allowed(command)

    @pytest.mark.parametrize('command', ['', '   ', 'shutdown', 'load /etc/passwd', 'logout', 'plugin/add /x.so',
                                         'port/remove 3', 'port/create 9', 'port/epclose 3 1', 'debug/add /x',
                                         'port/sethub 1', 'VLAN/CREATE 10', 'vlan/createx 10'])
    def test_refused(self, command):
        assert not is_user_command_allowed(command)

    def test_kathara_refusals_are_not_in_the_list(self):
        assert not {'shutdown', 'load', 'logout'} & set(params.switch_user_commands)


class TestPrintResult:
    def test_output_on_stdout(self, capsys):
        assert print_result('VLAN 0010', 0) == 0
        assert capsys.readouterr() == ('VLAN 0010\n', '')

    def test_nothing_for_an_empty_output(self, capsys):
        assert print_result('', 0) == 0
        assert capsys.readouterr() == ('', '')

    def test_error_on_stderr_with_the_errno_as_status(self, capsys):
        assert print_result('File exists', 17) == 17
        assert capsys.readouterr() == ('', 'error: File exists\n')

    def test_status_one_when_not_run(self, capsys):
        assert print_result('unreachable', -2) == 1
        assert print_result('', -2) == 1
        assert capsys.readouterr().err == 'error: unreachable\nerror -2\n'


# ---------------------------------------------------------------------------
# interactive prompt
# ---------------------------------------------------------------------------

def _session(monkeypatch, lines, restricted, answers=None):
    """Run interactive() on canned input lines; returns the commands that reached the switch."""
    feed = iter(lines)

    def fake_input(prompt):
        assert prompt == 'lan$ '
        item = next(feed, EOFError)
        if item in (EOFError, KeyboardInterrupt):
            raise item()
        return item

    monkeypatch.setattr(builtins, 'input', fake_input)
    ran = []

    def run(command):
        ran.append(command)
        return (answers or {}).get(command, ('', 0))

    interactive('lan', run, restricted)
    return ran


class TestInteractive:
    def test_commands_run_until_end_of_input(self, monkeypatch, capsys):
        ran = _session(monkeypatch, ['vlan/create 10', '', '  vlan/print  '], restricted=False,
                       answers={'vlan/print': ('VLAN 0010', 0)})
        assert ran == ['vlan/create 10', 'vlan/print']
        assert 'VLAN 0010\n' in capsys.readouterr().out

    @pytest.mark.parametrize('word', ['exit', 'quit', 'logout'])
    def test_exit_words_leave_without_reaching_the_switch(self, monkeypatch, word):
        assert _session(monkeypatch, ['vlan/print', word, 'vlan/create 10'], restricted=False) == ['vlan/print']

    def test_interrupt_does_not_leave(self, monkeypatch):
        assert _session(monkeypatch, [KeyboardInterrupt, 'vlan/print'], restricted=False) == ['vlan/print']

    def test_restricted_refuses_commands_outside_the_list(self, monkeypatch, capsys):
        ran = _session(monkeypatch, ['shutdown', 'plugin/add /tmp/x.so', 'port/remove 3', 'vlan/create 10'],
                       restricted=True)
        assert ran == ['vlan/create 10']
        err = capsys.readouterr().err
        assert "error: command 'plugin/add' is not allowed" in err
        assert "error: command 'port/remove' is not allowed" in err

    def test_unrestricted_passes_everything(self, monkeypatch):
        assert _session(monkeypatch, ['port/remove 3'], restricted=False) == ['port/remove 3']

    def test_error_shown_and_session_goes_on(self, monkeypatch, capsys):
        ran = _session(monkeypatch, ['vlan/create 10', 'vlan/print'], restricted=True,
                       answers={'vlan/create 10': ('File exists', 17)})
        assert ran == ['vlan/create 10', 'vlan/print']
        assert 'error: File exists' in capsys.readouterr().err


# ---------------------------------------------------------------------------
# sre connect / sre exec on a switch
# ---------------------------------------------------------------------------

@pytest.fixture
def cli(monkeypatch, kathara, tmp_pub_dir):
    """action_connect / action_exec on a real scheme, privileges and lab loading patched out."""
    scheme = Scheme()
    module_rvlab = SimpleNamespace(record_sessions=False)
    sessions = []
    for module in (connect, exec_):
        monkeypatch.setattr(module, 'resolve_running_lab_name', lambda name: RUNNING_LAB)
        monkeypatch.setattr(module, 'set_all_variables_for_action', lambda running_lab_name: (module_rvlab, scheme))
        monkeypatch.setattr(module, 'drop_privileges_permanently_if_not_needed', lambda ns: None)
        monkeypatch.setattr(module, 'set_sudo_uid_for_username', lambda u: None)
        monkeypatch.setattr(module, 'drop_privileges_temporarily', lambda: None)
        monkeypatch.setattr(module, 'gain_privileges_if_needed', lambda ns: None)
    monkeypatch.setattr(connect, 'interactive',
                        lambda name, run, restricted: sessions.append((name, restricted, run)))
    monkeypatch.delenv('SRE_IN_RECORDER', raising=False)

    def set_args(device, **overrides):
        SRE.args = SimpleNamespace(running_lab='lab', device=device, shell=None, exec_cmd=None,
                                   no_records=False, user=False, debug=False, command=[])
        for key, value in overrides.items():
            setattr(SRE.args, key, value)

    return SimpleNamespace(scheme=scheme, sessions=sessions, set_args=set_args, kathara=kathara,
                           module_rvlab=module_rvlab)


def _quits(capsys, action):
    with pytest.raises(SystemExit) as exc:
        action()
    return exc.value.code, capsys.readouterr()


class TestConnectSwitch:
    def test_privileged_console_is_unrestricted(self, cli):
        cli.set_args('lan')
        connect.action_connect()
        assert [(name, restricted) for name, restricted, _run in cli.sessions] == [('lan', False)]

    def test_student_console_is_restricted(self, cli):
        cli.set_args('lan', user=True)
        connect.action_connect()
        assert [(name, restricted) for name, restricted, _run in cli.sessions] == [('lan', True)]

    def test_student_commands_do_not_resolve_machine_references(self, cli):
        cli.set_args('lan', user=True)
        connect.action_connect()
        cli.sessions[0][2]('port/setvlan @pc1 10')
        assert cli.kathara.commands == [('lan', 'port/setvlan @pc1 10', 'fakehash')]

    def test_privileged_commands_resolve_machine_references(self, cli):
        cli.set_args('lan')
        connect.action_connect()
        cli.sessions[0][2]('port/setvlan @pc1 10')
        assert cli.kathara.commands == [('lan', 'port/setvlan 3 10', 'fakehash')]

    @pytest.mark.parametrize('device, mode', [('dmz', 'switch'), ('old', 'hub')])
    def test_no_console_on_hub_or_plain_switch(self, cli, capsys, device, mode):
        cli.set_args(device)
        code, captured = _quits(capsys, connect.action_connect)
        assert code == 1
        assert f"device {device} is a {mode}: it has no console" in captured.err
        assert cli.sessions == []

    def test_student_refused_when_connection_not_allowed(self, cli, capsys):
        cli.set_args('closed', user=True)
        code, captured = _quits(capsys, connect.action_connect)
        assert code == 1
        assert "connection to device closed is not allowed" in captured.err
        assert cli.sessions == []

    def test_privileged_user_may_use_a_closed_switch(self, cli):
        cli.set_args('closed')
        connect.action_connect()
        assert [name for name, _restricted, _run in cli.sessions] == ['closed']

    def test_network_of_hidden_machines_is_unknown_to_students(self, cli, capsys):
        cli.set_args('hid', user=True)
        _code, captured = _quits(capsys, connect.action_connect)
        assert "device hid is unknown" in captured.err

    def test_network_of_hidden_machines_for_privileged_user(self, cli):
        cli.set_args('hid')
        connect.action_connect()
        assert [name for name, _restricted, _run in cli.sessions] == ['hid']

    @pytest.mark.parametrize('device', ['closed', 'hid'])
    def test_debug_project_lifts_the_student_restrictions(self, cli, device):
        import os
        os.makedirs(params.private_lab_dir(RUNNING_LAB))
        open(params.debug_project_marker_filename(RUNNING_LAB), 'w').close()
        cli.set_args(device, user=True)
        connect.action_connect()
        assert [(name, restricted) for name, restricted, _run in cli.sessions] == [(device, True)]

    def test_network_without_machine_is_unknown(self, cli, capsys):
        cli.set_args('unused')
        _code, captured = _quits(capsys, connect.action_connect)
        assert "device unused is unknown" in captured.err

    def test_unknown_device(self, cli, capsys):
        cli.set_args('nowhere')
        _code, captured = _quits(capsys, connect.action_connect)
        assert "device nowhere is unknown" in captured.err

    def test_shell_option_refused(self, cli, capsys):
        cli.set_args('lan', shell='/bin/sh')
        _code, captured = _quits(capsys, connect.action_connect)
        assert "--shell does not apply to a switch" in captured.err

    def test_exec_option_runs_one_command(self, cli, capsys):
        cli.kathara.answers['vlan/print'] = 'VLAN 0010'
        cli.set_args('lan', exec_cmd=['vlan/print'])
        code, captured = _quits(capsys, connect.action_connect)
        assert (code, captured.out) == (0, 'VLAN 0010\n')
        assert cli.sessions == []

    def test_exec_option_refused_in_user_mode(self, cli, capsys):
        cli.set_args('lan', user=True, exec_cmd=['vlan/print'])
        _code, captured = _quits(capsys, connect.action_connect)
        assert "--exec is not allowed in user mode" in captured.err
        assert cli.kathara.commands == []

    def test_session_recorded_like_a_machine_one(self, cli, monkeypatch, tmp_path):
        recorded = []
        monkeypatch.setattr(connect, 'should_record_sessions', lambda module: True)
        monkeypatch.setattr(params, 'records_dir', lambda name: str(tmp_path / 'records'))
        monkeypatch.setattr(connect, '_exec_recorder',
                            lambda record_dir, device, env, cmd: recorded.append((device, env['SRE_IN_RECORDER'])))
        cli.set_args('lan', user=True)
        connect.action_connect()
        assert recorded == [('lan', '1')]

    def test_machines_still_connect_as_before(self, cli, monkeypatch):
        kathara = MagicMock()
        kathara.get_machine_stats.return_value = iter([SimpleNamespace(status='running')])
        monkeypatch.setattr(connect.Kathara, 'get_instance', staticmethod(lambda: kathara))
        cli.set_args('pc1')
        connect.action_connect()
        assert kathara.connect_tty.call_args.args[0] == 'pc1'
        assert cli.sessions == []


class TestExecSwitch:
    def test_one_command(self, cli, capsys):
        cli.kathara.answers['port/setvlan 3 20'] = ''
        cli.set_args('lan', command=['port/setvlan', '@pc1', '20'])
        code, captured = _quits(capsys, exec_.action_exec)
        assert (code, captured.out, captured.err) == (0, '', '')
        assert cli.kathara.commands == [('lan', 'port/setvlan 3 20', 'fakehash')]

    def test_output_printed(self, cli, capsys):
        cli.kathara.answers['vlan/print'] = 'VLAN 0010'
        cli.set_args('lan', command=['vlan/print'])
        code, captured = _quits(capsys, exec_.action_exec)
        assert (code, captured.out) == (0, 'VLAN 0010\n')

    def test_switch_error_is_the_exit_status(self, cli, capsys):
        cli.kathara.answers['vlan/create 10'] = FakeLinkCommandError(1017, 'File exists')
        cli.set_args('lan', command=['vlan/create', '10'])
        code, captured = _quits(capsys, exec_.action_exec)
        assert (code, captured.err) == (17, 'error: File exists\n')

    def test_no_command(self, cli, capsys):
        cli.set_args('lan', command=[])
        _code, captured = _quits(capsys, exec_.action_exec)
        assert "no command to execute" in captured.err

    def test_not_a_managed_switch(self, cli, capsys):
        cli.set_args('dmz', command=['vlan/print'])
        _code, captured = _quits(capsys, exec_.action_exec)
        assert "device dmz is a switch: it has no console" in captured.err

    def test_refused_in_user_mode(self, cli, capsys):
        cli.set_args('lan', user=True, command=['vlan/print'])
        _code, captured = _quits(capsys, exec_.action_exec)
        assert "exec is not available in user mode" in captured.err
        assert cli.kathara.commands == []
