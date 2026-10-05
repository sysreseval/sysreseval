"""Tests for the types of switch of the networks (hub / switch / managed switch): Network model
and VLAN declarations, Kathara lab built from the scheme, NetScheme.switch_cmd() applied by
do_action_state(), Grade.test_switch() run by run_tests().  No Docker: Kathara's manager is a
stand-in answering exec_link() / get_link_ports()."""
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from SRE import lib_sre, params, switch_console
from SRE.lib_sre import (Data0, Grade0, NetScheme0, Network, _HostCmdOp, _SwitchCmdOp, parse_port_vlans,
                         sre_state)
from SRE.command import state as state_cmd

RUNNING_LAB = '20260101000000@@@test/test1@@@user'
REPO = Path(__file__).parent.parent


class FakeLinkCommandError(Exception):
    """Kathara's LinkCommandError: the switch refused a command (status 1000 + errno)."""

    def __init__(self, code, message):
        super().__init__(f"failed: {code} {message}")
        self.code = code
        self.message = message


class FakeKathara:
    """Stand-in for Kathara's manager: console of the managed switches."""

    def __init__(self, answers=None, ports=None):
        self.answers = answers or {}  # command -> output, or an exception to raise
        self.ports = ports or {}      # get_link_ports() result
        self.commands = []            # [(network, command), ...]
        self.port_queries = 0

    def get_instance(self):
        return self

    def exec_link(self, link_name, command, lab_hash=None):
        self.commands.append((link_name, command))
        answer = self.answers.get(command, '')
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get_link_ports(self, link_name, lab_hash=None):
        self.port_queries += 1
        return self.ports


PORTS = {
    1: {'vlan': 0, 'tagged_vlans': [10, 20], 'active': True, 'endpoints': ['r1:eth0']},
    2: {'vlan': 10, 'tagged_vlans': [], 'active': True, 'endpoints': ['pc1:eth0']},
    4: {'vlan': 20, 'tagged_vlans': [], 'active': True, 'endpoints': ['pc2:eth1']},
}


@pytest.fixture
def kathara(monkeypatch):
    fake = FakeKathara(ports=PORTS)
    monkeypatch.setattr(switch_console, 'Kathara', fake)
    return fake


@dataclass(slots=True)
class MockData(Data0):
    x: int = 0


class SwitchScheme(NetScheme0):
    _machine_specs = {'pc1': {}, 'pc2': {}, 'r1': {}, 'srv': {}, 'probe': {'hidden': True}}
    _network_specs = {
        'lan': {'mode': 'managed', 'vlans': {'pc1': 10, 'pc2': {'vlan': 20, 'trunk': [30]}, 'r1': [20, 10]}},
        'dmz': {'mode': 'switch', 'color': 'yellow'},
        'closed': {'mode': 'managed', 'allow_connection': False},
        'hid': {'mode': 'managed'},
    }
    _topology = {
        'lan': {'r1': 0, 'pc1': 0, 'pc2': 1},
        'dmz': ['r1', 'srv'],
        'old': ['srv', 'pc2'],
        'closed': ['srv', 'pc1'],
        'hid': ['probe'],
    }

    def __init__(self, data=None):
        super().__init__(data=data or MockData(), running_lab_name=RUNNING_LAB)
        self.seen = []

    @sre_state
    def single(self):
        self.host_cmd('echo before')
        self.switch_cmd('lan', 'vlan/create 30')
        self.switch_cmd('lan', 'port/setvlan @pc2 30')
        self.cmd('pc1', 'echo container')
        self.switch_cmd('lan', 'vlan/print', step=2)

    @sre_state
    def failing(self):
        self.switch_cmd('lan', 'vlan/create 10')
        self.switch_cmd('lan', 'vlan/create 20', allow_error=True)

    @sre_state(multi_pass=True)
    def multi(self):
        out, code = self.switch_cmd('lan', 'vlan/print', default_value='?', default_code=9)
        self.seen.append((out, code))
        if code == 0:
            self.switch_cmd('lan', f"vlan/remove {out.split()[-1]}", step=2)

    @sre_state
    def unknown(self):
        self.switch_cmd('dmz', 'vlan/print')


def _scheme_with(network_specs, topology=None, machine_specs=None):
    class _Scheme(NetScheme0):
        _machine_specs = machine_specs or {'m1': {}, 'm2': {}}
        _network_specs = network_specs
        _topology = topology or {'lan': ['m1', 'm2']}

    return _Scheme(data=MockData(), running_lab_name=RUNNING_LAB)


# ---------------------------------------------------------------------------
# Network model
# ---------------------------------------------------------------------------

class TestNetworkModel:
    def test_hub_by_default(self):
        net = Network(name='lan')
        assert net.mode == params.network_mode_hub == 'hub'
        assert not net.is_managed()
        assert net.allow_connection is True
        assert net.vlans == {}

    def test_network_of_the_topology_alone_is_a_hub(self):
        s = SwitchScheme()
        assert s.old.mode == 'hub'

    def test_modes_from_network_specs(self):
        s = SwitchScheme()
        assert (s.lan.mode, s.dmz.mode, s.closed.mode) == ('managed', 'switch', 'managed')
        assert s.lan.is_managed() and not s.dmz.is_managed()
        assert s.dmz.color == 'yellow'

    def test_allow_connection(self):
        s = SwitchScheme()
        assert s.lan.allow_connection is True
        assert s.closed.allow_connection is False

    def test_none_mode_is_the_default(self):
        assert Network(name='lan', mode=None).mode == 'hub'

    @pytest.mark.parametrize('mode', ['router', 'Managed', '', 1])
    def test_invalid_mode(self, mode):
        with pytest.raises(ValueError, match="network 'lan': mode"):
            Network(name='lan', mode=mode)

    @pytest.mark.parametrize('mode', ['hub', 'switch'])
    def test_vlans_need_a_managed_switch(self, mode):
        with pytest.raises(ValueError, match="'vlans' needs 'mode': 'managed'"):
            Network(name='lan', mode=mode, vlans={'m1': 10})

    def test_vlans_on_adapters(self):
        s = SwitchScheme()
        adapters = {m.name: a for m, a in s.lan.net_adapters.items()}
        assert (adapters['pc1'].vlan, adapters['pc1'].tagged_vlans) == (10, [])
        assert (adapters['pc2'].vlan, adapters['pc2'].tagged_vlans) == (20, [30])
        assert (adapters['r1'].vlan, adapters['r1'].tagged_vlans) == (None, [10, 20])

    def test_no_vlan_on_other_adapters(self):
        s = SwitchScheme()
        for net in (s.dmz, s.old, s.closed):
            for adapter in net.net_adapters.values():
                assert (adapter.vlan, adapter.tagged_vlans) == (None, [])

    def test_switch_port_label(self):
        s = SwitchScheme()
        assert s.lan.net_adapters[s.pc2].switch_port_label() == 'pc2:eth1'

    def test_vlans_of_a_machine_outside_the_network(self):
        with pytest.raises(ValueError, match="'vlans' names 'm3'"):
            _scheme_with({'lan': {'mode': 'managed', 'vlans': {'m3': 10}}},
                         topology={'lan': ['m1', 'm2'], 'wan': ['m3']},
                         machine_specs={'m1': {}, 'm2': {}, 'm3': {}})

    def test_vlans_of_an_unknown_machine(self):
        with pytest.raises(ValueError, match="'vlans' names 'nobody'"):
            _scheme_with({'lan': {'mode': 'managed', 'vlans': {'nobody': 10}}})

    def test_bad_vlan_names_network_and_machine(self):
        with pytest.raises(ValueError, match="network 'lan', machine 'm1': VLAN 5000 is invalid"):
            _scheme_with({'lan': {'mode': 'managed', 'vlans': {'m1': 5000}}})

    def test_visible_networks_leave_out_hidden_machines_only(self):
        s = SwitchScheme()
        assert {n.name for n in s.get_visible_networks()} == {'lan', 'dmz', 'old', 'closed'}
        assert {n.name for n in s.get_networks()} == {'lan', 'dmz', 'old', 'closed', 'hid'}


class TestParsePortVlans:
    def test_access_port(self):
        assert parse_port_vlans(10, 'x') == (10, [])

    @pytest.mark.parametrize('spec', [[20, 10], (10, 20), {10, 20}, [10, 20, 10]])
    def test_trunk_port(self, spec):
        assert parse_port_vlans(spec, 'x') == (None, [10, 20])

    def test_native_vlan_and_trunk(self):
        assert parse_port_vlans({'vlan': 1, 'trunk': [30, 20]}, 'x') == (1, [20, 30])
        assert parse_port_vlans({'vlan': 7}, 'x') == (7, [])
        assert parse_port_vlans({'trunk': 30}, 'x') == (None, [30])

    def test_bounds(self):
        assert parse_port_vlans(params.min_vlan_id, 'x') == (1, [])
        assert parse_port_vlans(params.max_vlan_id, 'x') == (4094, [])

    @pytest.mark.parametrize('spec', [0, 4095, -1, '10', 1.5, True, [10, '20'], {'vlan': 0}, {'trunk': [4095]}])
    def test_invalid_vlan(self, spec):
        with pytest.raises(ValueError, match='is invalid'):
            parse_port_vlans(spec, 'x')

    @pytest.mark.parametrize('spec', [[], {}, {'vlan': None}, {'trunk': []}])
    def test_no_vlan(self, spec):
        with pytest.raises(ValueError, match='no VLAN given'):
            parse_port_vlans(spec, 'x')

    def test_untagged_and_tagged(self):
        with pytest.raises(ValueError, match='VLAN 10 cannot be both untagged and tagged'):
            parse_port_vlans({'vlan': 10, 'trunk': [10, 20]}, 'x')

    def test_unknown_key(self):
        with pytest.raises(ValueError, match="unknown key"):
            parse_port_vlans({'vlan': 10, 'tagged': [20]}, 'x')

    def test_where_starts_the_message(self):
        with pytest.raises(ValueError, match="^network 'lan', machine 'pc1': "):
            parse_port_vlans(0, "network 'lan', machine 'pc1'")


# ---------------------------------------------------------------------------
# Kathara lab built from the scheme
# ---------------------------------------------------------------------------

def _new_lab(scheme, monkeypatch):
    """Mock of the Kathara Lab built by get_new_lab_from_scheme(), one link object per name."""
    monkeypatch.delitem(sys.modules, 'srelab', raising=False)
    lab = MagicMock()
    links = {}
    lab.get_or_new_link.side_effect = lambda name: links.setdefault(name, MagicMock(mode=None))
    monkeypatch.setattr(lib_sre, 'Lab', MagicMock(return_value=lab))
    scheme.get_new_lab_from_scheme()
    return lab, links


def _connections(lab):
    """{(machine, network): kwargs} of the connect_machine_to_link() calls."""
    return {(c.args[0], c.args[1]): c.kwargs for c in lab.connect_machine_to_link.call_args_list}


class TestLabFromScheme:
    def test_modes_set_on_non_hub_links_only(self, monkeypatch):
        _lab, links = _new_lab(SwitchScheme(), monkeypatch)
        assert {name: link.mode for name, link in links.items()} == {
            'lan': 'managed', 'dmz': 'switch', 'closed': 'managed', 'hid': 'managed'}

    def test_vlans_passed_to_the_links(self, monkeypatch):
        lab, _ = _new_lab(SwitchScheme(), monkeypatch)
        connections = _connections(lab)
        assert connections[('pc1', 'lan')]['vlan'] == 10
        assert 'tagged_vlans' not in connections[('pc1', 'lan')]
        assert (connections[('pc2', 'lan')]['vlan'], connections[('pc2', 'lan')]['tagged_vlans']) == (20, [30])
        assert connections[('r1', 'lan')]['tagged_vlans'] == [10, 20]
        assert 'vlan' not in connections[('r1', 'lan')]

    def test_interface_numbers_unchanged(self, monkeypatch):
        lab, _ = _new_lab(SwitchScheme(), monkeypatch)
        connections = _connections(lab)
        assert connections[('pc2', 'lan')]['machine_iface_number'] == 1
        assert connections[('r1', 'lan')]['machine_iface_number'] == 0

    def test_nothing_new_for_other_networks(self, monkeypatch):
        lab, _ = _new_lab(SwitchScheme(), monkeypatch)
        for (machine, network), kwargs in _connections(lab).items():
            if network != 'lan':
                assert set(kwargs) == {'machine_iface_number', 'mac_address'}, (machine, network)

    def test_lab_with_hubs_only_makes_the_same_calls_as_before(self, monkeypatch):
        lab, links = _new_lab(_scheme_with({'lan': {'color': 'red'}}), monkeypatch)
        assert links == {}
        lab.get_or_new_link.assert_not_called()
        for kwargs in _connections(lab).values():
            assert set(kwargs) == {'machine_iface_number', 'mac_address'}

    def test_explicit_hub_says_nothing_either(self, monkeypatch):
        lab, links = _new_lab(_scheme_with({'lan': {'mode': 'hub'}}), monkeypatch)
        assert links == {}

    def test_network_without_machine_creates_no_link(self, monkeypatch):
        _lab, links = _new_lab(_scheme_with({'lan': {}, 'unused': {'mode': 'managed'}}), monkeypatch)
        assert links == {}

    def test_kathara_without_switch_modes(self, monkeypatch):
        class OldLink:
            __slots__ = ('name',)

        monkeypatch.delitem(sys.modules, 'srelab', raising=False)
        lab = MagicMock()
        lab.get_or_new_link.side_effect = lambda name: OldLink()
        monkeypatch.setattr(lib_sre, 'Lab', MagicMock(return_value=lab))
        with patch.object(lib_sre, 'error_quit', side_effect=SystemExit) as error_quit:
            with pytest.raises(SystemExit):
                _scheme_with({'lan': {'mode': 'switch'}}).get_new_lab_from_scheme()
        assert "mode 'switch' needs a Kathara with switch modes" in error_quit.call_args.args[0]

    def test_real_kathara_model_accepts_the_lab(self, tmp_path):
        """The lab of tests/labs/switch_test_lab.py built with the real Kathara model (in a
        subprocess: conftest replaces Kathara by a mock in this one)."""
        script = f"""
import importlib.util, json, sys
sys.path[:0] = [{str(REPO / 'src')!r}, {str(REPO / 'lib')!r}]
try:
    from Kathara.types import LinkMode  # noqa: F401
except ImportError:
    sys.exit(77)
spec = importlib.util.spec_from_file_location('srelab', {str(REPO / 'tests' / 'labs' / 'switch_test_lab.py')!r})
module = importlib.util.module_from_spec(spec)
sys.modules['srelab'] = module
spec.loader.exec_module(module)
scheme = module.NetScheme(data=module.Data.generate(), running_lab_name={RUNNING_LAB!r})
lab = scheme.get_new_lab_from_scheme()
lab.check_integrity()
print(json.dumps({{
    'modes': {{name: (link.mode.value if link.mode is not None else None) for name, link in lab.links.items()}},
    'vlans': {{f"{{m.name}}:{{i.link.name}}": [i.vlan, i.tagged_vlans]
              for m in lab.machines.values() for i in m.interfaces.values() if i.has_vlans()}},
}}))
"""
        env = dict(os.environ, SRE_PUB_DIR=str(tmp_path))
        result = subprocess.run([sys.executable, '-W', 'ignore', '-c', script], capture_output=True, text=True,
                                env=env)
        if result.returncode == 77:
            pytest.skip("the installed Kathara has no switch modes")
        assert result.returncode == 0, result.stderr
        out = json.loads(result.stdout.strip().splitlines()[-1])
        assert out['modes'] == {'lan': 'managed', 'dmz': 'switch', 'old': None, 'closed': 'managed',
                                'hid': 'managed'}
        assert out['vlans'] == {'pc1:lan': [10, []], 'pc2:lan': [20, []], 'pc3:lan': [10, []],
                                'r1:lan': [None, [10, 20]]}


# ---------------------------------------------------------------------------
# NetScheme.switch_cmd()
# ---------------------------------------------------------------------------

class TestSwitchCmdRegistration:
    def test_registered_with_the_host_ops_in_order(self, tmp_pub_dir):
        s = SwitchScheme()
        ops, host_ops = s.compute_state_ops('single')
        step1 = host_ops[1]
        assert isinstance(step1[0], _HostCmdOp)
        assert [(op.network, op.command) for op in step1[1:]] == [('lan', 'vlan/create 30'),
                                                                 ('lan', 'port/setvlan @pc2 30')]
        assert all(isinstance(op, _SwitchCmdOp) for op in step1[1:])
        assert [(op.network, op.command) for op in host_ops[2]] == [('lan', 'vlan/print')]
        assert list(ops[1]) == ['pc1']

    def test_placeholder_until_run(self, tmp_pub_dir):
        s = SwitchScheme()
        assert s.switch_cmd('lan', 'vlan/print') == ('', 0)
        assert s.switch_cmd('lan', 'port/print', default_value='x', default_code=3) == ('x', 3)

    def test_recorded_result_returned(self, tmp_pub_dir):
        s = SwitchScheme()
        s.switch_cmd('lan', 'vlan/print')
        s.record_switch_cmd_result(1, 'lan', 'vlan/print', 'VLAN 0010', 0)
        assert s.switch_cmd('lan', 'vlan/print') == ('VLAN 0010', 0)
        assert s.switch_cmd('lan', 'vlan/print', step=2) == ('', 0)

    def test_results_forgotten_with_the_state_results(self, tmp_pub_dir):
        s = SwitchScheme()
        s.record_switch_cmd_result(1, 'lan', 'vlan/print', 'VLAN 0010', 0)
        s.reset_state_results()
        assert s.switch_cmd('lan', 'vlan/print') == ('', 0)

    def test_step_raises_max_step(self, tmp_pub_dir):
        s = SwitchScheme()
        s.switch_cmd('lan', 'vlan/print', step=3)
        assert s.max_step == 3

    def test_allow_error(self, tmp_pub_dir):
        s = SwitchScheme()
        s.switch_cmd('lan', 'vlan/create 20', allow_error=True)
        assert s.is_switch_cmd_error_allowed(1, 'lan', 'vlan/create 20')
        assert not s.is_switch_cmd_error_allowed(1, 'lan', 'vlan/create 10')

    @pytest.mark.parametrize('network', ['dmz', 'old', 'nowhere', 'pc1'])
    def test_only_on_a_managed_switch(self, network, tmp_pub_dir):
        with pytest.raises(ValueError, match="is not a managed switch of this lab"):
            SwitchScheme().switch_cmd(network, 'vlan/print')


def _apply(scheme, state, machines=None):
    lab = MagicMock()
    lab.machines = machines or {}
    with patch.object(state_cmd, 'log_error') as log_error:
        state_cmd.do_action_state(lab=lab, state=state, net_scheme=scheme, project_has_directory=False)
    return [c.args[0] for c in log_error.call_args_list]


class TestSwitchCmdApplied:
    def test_commands_reach_the_console_in_order(self, kathara, tmp_pub_dir):
        _apply(SwitchScheme(), 'single')
        assert kathara.commands == [('lan', 'vlan/create 30'), ('lan', 'port/setvlan 4 30'), ('lan', 'vlan/print')]

    def test_machine_reference_is_its_port(self, kathara, tmp_pub_dir):
        _apply(SwitchScheme(), 'single')
        assert ('lan', 'port/setvlan 4 30') in kathara.commands  # pc2:eth1 is on port 4
        assert kathara.port_queries == 1

    def test_results_recorded_under_the_registered_command(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/print'] = 'VLAN 0030'
        s = SwitchScheme()
        _apply(s, 'single')
        assert s.switch_cmd('lan', 'vlan/print', step=2) == ('VLAN 0030', 0)
        assert s.switch_cmd('lan', 'port/setvlan @pc2 30') == ('', 0)

    def test_switch_commands_run_before_the_containers_of_the_step(self, kathara, tmp_pub_dir):
        order = []
        machine = MagicMock()
        machine.api_object.exec_run.side_effect = lambda *a, **k: (order.append('container'), (0, b''))[1]
        real_exec = kathara.exec_link
        kathara.exec_link = lambda *a, **k: (order.append('switch'), real_exec(*a, **k))[1]
        _apply(SwitchScheme(), 'single', {'pc1': machine})
        assert order[:3] == ['switch', 'switch', 'container']

    def test_error_of_the_switch_gives_its_errno(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/create 10'] = FakeLinkCommandError(1017, 'File exists')
        kathara.answers['vlan/create 20'] = FakeLinkCommandError(1017, 'File exists')
        s = SwitchScheme()
        errors = _apply(s, 'failing')
        assert s.switch_cmd('lan', 'vlan/create 10') == ('File exists', 17)
        assert errors == ['switch cmd error on lan:vlan/create 10 code=17']  # the other one is allowed

    def test_unreachable_console_gives_minus_two(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/create 10'] = RuntimeError('Unable to reach the management console')
        s = SwitchScheme()
        _apply(s, 'failing')
        assert s.switch_cmd('lan', 'vlan/create 10') == ('Unable to reach the management console', -2)

    def test_multi_pass_sees_the_result(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/print'] = 'VLAN 0010\nVLAN 0020'
        s = SwitchScheme()
        _apply(s, 'multi')
        assert s.seen[0] == ('?', 9)
        assert s.seen[-1] == ('VLAN 0010\nVLAN 0020', 0)
        assert kathara.commands == [('lan', 'vlan/print'), ('lan', 'vlan/remove 0020')]

    def test_not_a_managed_switch_stops_the_state(self, kathara, tmp_pub_dir):
        with patch.object(lib_sre, 'error_quit', side_effect=SystemExit) as error_quit:
            with pytest.raises(SystemExit):
                _apply(SwitchScheme(), 'unknown')
        assert "'dmz' is not a managed switch" in error_quit.call_args.args[0]
        assert kathara.commands == []

    def test_operations_log(self, kathara, tmp_pub_dir, monkeypatch):
        kathara.answers['vlan/print'] = 'VLAN 0030'
        kathara.answers['vlan/create 30'] = FakeLinkCommandError(1017, 'File exists')
        os.makedirs(params.private_lab_dir(RUNNING_LAB))
        Path(params.debug_project_marker_filename(RUNNING_LAB)).touch()
        monkeypatch.setattr(os, 'fchown', lambda *a: None)
        _apply(SwitchScheme(), 'single')
        log = Path(params.operations_log_filename(RUNNING_LAB)).read_text()
        assert "step1 - on switch lan : vlan/create 30\n    File exists\n    exit code 17\n" in log
        assert "step1 - on switch lan : port/setvlan @pc2 30\n    exit code 0\n" in log
        assert "step2 - on switch lan : vlan/print\n    VLAN 0030\n    exit code 0\n" in log


# ---------------------------------------------------------------------------
# Grade.test_switch()
# ---------------------------------------------------------------------------

class SwitchGrade(Grade0):
    def grade(self):
        super().grade()
        self.vlans = self.test_switch('lan', 'vlan/print')
        self.port = self.test_switch('lan', 'port/print @pc1', allow_error=True)
        self.later = self.test_switch('lan', 'hash/print', step=2, default_value='none', default_code=5)
        self.host = self.test('pc1', 'hostname')


def _graded(kathara, machines=None):
    scheme = SwitchScheme()
    lab = MagicMock()
    lab.machines = machines or {}
    scheme.get_lab_from_kathara = lambda: lab
    grade = SwitchGrade(scheme)
    grade.run_tests()
    return grade


class TestGradeTestSwitch:
    def test_placeholder_on_registration(self, tmp_pub_dir):
        g = SwitchGrade(SwitchScheme())
        g.grade()
        assert g.vlans == ('', 0)
        assert g.later == ('none', 5)
        assert g.max_step == 2

    def test_only_on_a_managed_switch(self, tmp_pub_dir):
        g = SwitchGrade(SwitchScheme())
        with pytest.raises(ValueError, match="'dmz' is not a managed switch"):
            g.test_switch('dmz', 'vlan/print')

    def test_not_run_through_exetests(self, tmp_pub_dir):
        g = SwitchGrade(SwitchScheme())
        g.grade()
        assert set(g.get_exetests_strings(1)) == {'pc1'}
        assert g.get_exetests_strings(2) == {}

    def test_results_after_run_tests(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/print'] = 'VLAN 0010'
        kathara.answers['hash/print'] = 'Hash: 0001'
        g = _graded(kathara)
        assert g.vlans == ('VLAN 0010', 0)
        assert g.later == ('Hash: 0001', 0)
        assert ('lan', 'port/print 2') in kathara.commands  # pc1:eth0 is on port 2

    def test_each_command_runs_once(self, kathara, tmp_pub_dir):
        _graded(kathara)
        assert sorted(kathara.commands) == [('lan', 'hash/print'), ('lan', 'port/print 2'), ('lan', 'vlan/print')]

    def test_stored_with_the_tests_of_the_machines(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/print'] = 'VLAN 0010'
        g = _graded(kathara)
        assert g.get_tests()[('lan', 1)] == {('vlan/print', 0): ('VLAN 0010', 0), ('port/print @pc1', 0): ('', 0)}
        assert g.get_tests()[('lan', 2)] == {('hash/print', 0): ('', 0)}

    def test_error_reported_unless_allowed(self, kathara, tmp_pub_dir):
        kathara.answers['vlan/print'] = FakeLinkCommandError(1022, 'Invalid argument')
        kathara.answers['port/print 2'] = FakeLinkCommandError(1022, 'Invalid argument')
        g = _graded(kathara)
        assert g.vlans == ('Invalid argument', 22)
        errors = [e for _category, e in g._errors]
        assert errors == ['test error on switch lan:vlan/print code=22']

    def test_archived_results_replayed_without_console(self, kathara, tmp_pub_dir):
        """sre re-eval puts the archived tests back and calls grade(): no command is run."""
        g = SwitchGrade(SwitchScheme())
        g.reset_before_grade()
        g._tests[('lan', 1)] = {('vlan/print', 0): ('VLAN 0042', 0)}
        g.grade()
        assert g.vlans == ('VLAN 0042', 0)
        assert kathara.commands == []
