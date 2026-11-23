"""Offline tests of the save / restore of the DHCP lab (lab/sre/dhcp.py): save() records the DHCP
daemons of the students' machines, restore() (multi_pass) puts the initial configuration back,
relaunches the recorded daemons (servers and relay at step 2, clients at step 3) and removes the
records at its last step.

No Docker: restore() is driven through iter_state_steps() like `sre restore` does, with synthetic
records in the format of state_helpers.record_daemons_cmd().
"""
import datetime
import importlib.util
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.lib_sre import _CmdOp

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))

import state_helpers  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / 'dhcp.py'
_READ = f"cat {state_helpers.SAVED_DAEMONS_FILE} 2>/dev/null; true"
_FORGET = f"rm -f {state_helpers.SAVED_DAEMONS_FILE}"

# Records as the save state writes them (TAB-separated, trailing TAB of /proc/PID/cmdline).
_SRV1_SERVICE = ("proc\tisc-dhcp-server.service\t/usr/sbin/dhcpd\t-4\t-q\t-cf\t/etc/dhcp/dhcpd.conf\t"
                 "-pf\t/run/dhcp-server/dhcpd.pid\teth0\t\n")
_SRV2_BY_HAND = "proc\t-\tdhcpd\t-4\t-cf\t/etc/dhcp/dhcpd.conf\teth0\t\n"
_M0_DHCLIENT = "proc\t-\tdhclient\t-v\teth0\t\n"
_M1_IFUP = ("ifup\teth0\nproc\t-\t/sbin/dhclient\t-4\t-v\t-i\t-pf\t/run/dhclient.eth0.pid\t-lf\t"
            "/var/lib/dhcp/dhclient.eth0.leases\t-I\t-df\t/var/lib/dhcp/dhclient6.eth0.leases\teth0\t\n")
RECORDS = {'srv1': _SRV1_SERVICE, 'srv2': _SRV2_BY_HAND, 'r1': '', 'm0': _M0_DHCLIENT, 'm1': _M1_IFUP,
           'm2': _M1_IFUP, 'm3': '', 'm4': _M1_IFUP}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('dhcp_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _new_ns(lab, data):
    """A fresh NetScheme, as each sre command builds one (remount_proc_sys() registers its command
    once per instance)."""
    name = params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')
    return lab.NetScheme(data, running_lab_name=name)


@pytest.fixture
def ns(lab, data):
    return _new_ns(lab, data)


def _key(op):
    """Comparable form of an op (_FileOp has no __eq__)."""
    if isinstance(op, str):
        return ('cmd', str(op))
    return (type(op).__name__, op.filename, op.content, op.permissions, op.owner)


def _state_ops(ns, name):
    """{(step, machine): [op keys]} registered by one call of the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    return {(step, m): [_key(op) for op in ops] for step in ns._ops for m, ops in ns._ops[step].items()}


def _run_restore(ns, records):
    """Apply restore() as `sre restore` does: {step: {machine: [op keys]}}, the reads of the
    records answered from *records* and every other command with an empty output."""
    applied = {}
    for step, step_ops, _ in ns.iter_state_steps('restore'):
        applied[step] = {m: [_key(op) for op in ops] for m, ops in step_ops.items()}
        for m, ops in step_ops.items():
            for op in ops:
                if isinstance(op, _CmdOp):
                    out = records.get(m, '') if (step == 1 and str(op) == _READ) else ''
                    ns.record_cmd_result(m, step, str(op), op.timeout, out, 0)
    return applied


def _cmds(ops):
    return [c for kind, c, *_ in ops if kind == 'cmd']


def test_save_restore_allowed(lab):
    assert lab.allow_save_restore is True
    assert getattr(lab, 'save_key', None) is None
    assert lab.STUDENT_MACHINES == ['srv1', 'srv2', 'r1', 'm0', 'm1', 'm2', 'm3', 'm4']


def test_lifecycle_states(lab):
    assert lab.NetScheme.is_state_multi_pass('restore') is True
    assert lab.NetScheme.is_state_multi_pass('save') is False
    allowed = {name for name in ('initial', 'save', 'restore', 'final')
               if getattr(getattr(lab.NetScheme, name), '_sre_state_user_allowed', False)}
    assert allowed == set()


def test_save_records_the_student_machines_only(lab, ns):
    ops = _state_ops(ns, 'save')
    record = state_helpers.record_daemons_cmd(lab.SAVED_DAEMONS)
    assert ops == {(1, m): [('cmd', record)] for m in lab.STUDENT_MACHINES}
    assert "pgrep -x 'dhcpd|dhcrelay|dhclient'" in record


def test_initial_unchanged_by_the_refactoring(lab, ns):
    ops = _state_ops(ns, 'initial')
    assert {step for step, _ in ops} == {1}
    assert set(m for _, m in ops) == set(ns.get_machine_names())
    srv0 = _cmds(ops[(1, 'srv0')])
    assert any('unbound -c /etc/unbound/unbound.conf' in c for c in srv0)
    assert any('dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf eth0' in c for c in srv0)
    assert 'mkdir -p /run/network' in _cmds(ops[(1, 'm0')])


def test_restore_step1_is_initial_plus_the_reads(lab, data, ns):
    initial = _state_ops(_new_ns(lab, data), 'initial')
    applied = _run_restore(ns, RECORDS)
    assert set(applied[1]) == {m for _, m in initial}
    for m in ns.get_machine_names():
        expected = initial[(1, m)] + ([('cmd', _READ)] if m in lab.STUDENT_MACHINES else [])
        assert applied[1][m] == expected, m


def test_restore_step2_servers_and_relay(lab, ns):
    applied = _run_restore(ns, RECORDS)
    assert set(applied[2]) == {'srv1', 'srv2', 'r1'}
    wait = state_helpers.WAIT_FOR_SYSTEMD_CMD
    assert _cmds(applied[2]['srv1']) == [wait, 'systemctl stop isc-dhcp-server; pkill -x dhcpd; systemctl reset-failed isc-dhcp-server 2>/dev/null; true',
                                         'systemctl start isc-dhcp-server.service']
    assert _cmds(applied[2]['srv2']) == [wait, 'systemctl stop isc-dhcp-server; pkill -x dhcpd; systemctl reset-failed isc-dhcp-server 2>/dev/null; true',
                                         'setsid -f dhcpd -4 -cf /etc/dhcp/dhcpd.conf eth0 '
                                         '</dev/null >/dev/null 2>&1']
    # not running at the time of the save: only what the boot started is stopped
    assert _cmds(applied[2]['r1']) == [wait, 'systemctl stop isc-dhcp-relay; pkill -x dhcrelay; systemctl reset-failed isc-dhcp-relay 2>/dev/null; true']


def test_restore_step3_clients(ns):
    applied = _run_restore(ns, RECORDS)
    ifup = 'mkdir -p /run/network; setsid -f ifup eth0 </dev/null >/dev/null 2>&1'
    assert _cmds(applied[3]['m0']) == ['setsid -f dhclient -v eth0 </dev/null >/dev/null 2>&1']
    for m in ('m1', 'm2', 'm4'):
        assert _cmds(applied[3][m]) == [ifup], m     # ifup relaunches its own dhclient
    assert 'm3' not in applied[3]
    assert not {'srv1', 'srv2', 'r1'} & set(applied[3])


def test_restore_last_step_removes_the_records(lab, ns):
    applied = _run_restore(ns, RECORDS)
    assert max(applied) == 4
    assert applied[4] == {m: [('cmd', _FORGET)] for m in lab.STUDENT_MACHINES}


def test_restore_without_records(lab, ns):
    """A machine without record (nothing running at the time of the save): nothing relaunched,
    the boot services stopped, the records removed at the last step all the same."""
    applied = _run_restore(ns, {})
    assert sorted(applied) == [1, 2, 3, 4]
    assert applied[3] == {}
    for m in ('srv1', 'srv2', 'r1'):
        assert len(_cmds(applied[2][m])) == 2, m
    assert applied[4] == {m: [('cmd', _FORGET)] for m in lab.STUDENT_MACHINES}
