"""Tests for lib/snmp.py (fixtures captured on Net-SNMP 5.9.3, Debian 12, in sysreseval/monitoring
containers with IPv6 disabled on 2026-11-11: tests/mock_data/snmp/)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from snmp import (  # noqa: E402
    DSK_PATH, GRADER_OPTS, ISOLATE, LA_CONFIG, OID, PR_COUNT, PR_ERROR_FLAG, PR_NAMES, RC_SUFFIX, SNMPD_CONF,
    SNMPD_PERSISTENT, SNMPTRAPD_DROPIN, column_values, conf_communities, conf_trap_sinks, conf_values,
    create_v3_user_cmd, extend_index, extend_oid, get_interface_rate, get_snmpd_conf, is_authentication_failure,
    normalize_mac, normalize_oid, oid_under, parse_marked_lines, parse_rate_sample, parse_snmp_error,
    parse_snmp_output, parse_snmpd_conf, parse_trap_log, rate_sample_cmd, raw, render_snmp_client_conf,
    render_snmpd_conf, render_snmptrapd_conf, render_snmptrapd_dropin, set_snmp_agent, set_snmptrapd_service,
    snmp_auth_args, snmp_get, snmp_result, snmp_set, snmp_walk, snmpd_conf_dump_cmd, snmpd_start_cmd,
    snmpget_cmd, snmpset_cmd, snmptrap_cmd, snmpwalk_cmd, table_rows, trap_log_lines_cmd, trap_log_tail_cmd,
    trap_log_window,
)

MOCK = Path(__file__).parent / 'mock_data' / 'snmp'


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    """Grade mock whose grade.test(machine, command, step=...) dispatches by command."""
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 0))

    grade.test.side_effect = _test
    return grade


# ---------------------------------------------------------------------------
# OIDs and MAC addresses
# ---------------------------------------------------------------------------

class TestOids:
    def test_normalize(self):
        assert normalize_oid('1.3.6.1.2.1.1.5.0') == '.1.3.6.1.2.1.1.5.0'
        assert normalize_oid('.1.3.6.1.2.1.1.5.0.') == '.1.3.6.1.2.1.1.5.0'
        assert normalize_oid(' .1.3 ') == '.1.3'
        assert normalize_oid('SNMPv2-MIB::sysName.0') == ''
        assert normalize_oid('') == '' and normalize_oid(None) == ''

    def test_under(self):
        assert oid_under('.1.3.6.1.2.1.1.5.0', OID['system'])
        assert oid_under('1.3.6.1.2.1.1', '.1.3.6.1.2.1.1')
        assert not oid_under('.1.3.6.1.2.1.11.30.0', OID['system'])   # .1.3.6.1.2.1.11 is not below .1.3.6.1.2.1.1
        assert not oid_under('sysName.0', OID['system'])

    def test_extend_index_matches_the_agent(self):
        # what the agent printed for `extend backup …` and `extend asset …`
        assert extend_index('backup') == '6.98.97.99.107.117.112'
        assert extend_oid('nsExtendOutput1Line', 'asset') == '.1.3.6.1.4.1.8072.1.3.2.3.1.1.5.97.115.115.101.116'
        r = snmp_result(fixture('get_extend_oid.txt'))
        assert r.value(extend_oid('nsExtendOutput1Line', 'backup')) == 'backup OK jobs=37 build=4f2a9c'
        assert r.int(extend_oid('nsExtendResult', 'backup')) == 0
        assert r.value(extend_oid('nsExtendCommand', 'backup')) == '/usr/local/bin/sre-app-status'

    @pytest.mark.parametrize('text', ['CA 9F DC E5 C7 2A ', 'ca:9f:dc:e5:c7:2a', 'CA-9F-DC-E5-C7-2A', 'ca9fdce5c72a',
                                      '"CA 9F DC E5 C7 2A"'])
    def test_mac_forms(self, text):
        assert normalize_mac(text) == 'ca:9f:dc:e5:c7:2a'

    def test_mac_short_bytes_and_garbage(self):
        assert normalize_mac('2:53:4e:a:1b:2c') == '02:53:4e:0a:1b:2c'
        assert normalize_mac('') == '' and normalize_mac('eth1') == '' and normalize_mac('02:53:4e:0a:1b') == ''
        assert normalize_mac('zz:53:4e:0a:1b:2c') == ''


# ---------------------------------------------------------------------------
# client outputs
# ---------------------------------------------------------------------------

class TestOutput:
    def test_every_type(self):
        r = snmp_result(fixture('get_v2c_ok.txt'))
        assert r.ran and r.ok and r.exit_code == 0 and r.error is None
        assert r.value(OID['sysName']) == 'srv1'
        assert r.value('1.3.6.1.2.1.1.6.0') == 'Batiment B, salle 204, baie 3'
        assert r.value(OID['sysContact']) == 'Equipe reseau <noc@corp.lab>'
        assert r.int(OID['ifNumber']) == 2
        assert r.get(OID['hrSystemUptime']).type == 'Timeticks'
        assert r.int(OID['hrSystemUptime']) == 13098921
        assert r.get(OID['sysObjectID']).type == 'OID' and r.value(OID['sysObjectID']) == '.1.3.6.1.4.1.8072.3.2.10'
        assert r.int(OID['snmpEnableAuthenTraps']) == 1
        assert len(r.vars) == 9

    def test_names_when_the_mibs_are_loaded(self):
        variables = parse_snmp_output(fixture('get_mibs_loaded.txt'))
        by_name = {v.oid: v for v in variables}
        assert by_name['SNMPv2-MIB::sysName.0'].value == 'srv1'          # unquoted in that form
        assert by_name['IP-MIB::ipForwarding.0'].value == 'forwarding(1)'
        assert by_name['IP-MIB::ipForwarding.0'].int is None

    def test_exceptions_per_variable(self):
        out = snmp_result(fixture('get_view_out.txt'))
        assert out.ran and out.exit_code == 0 and out.error is None      # a v2c answer, each variable refused
        assert [v.exception for v in out.vars] == ['noSuchObject'] * 3
        assert out.refused and not out.has_value(OID['ipForwarding']) and out.value(OID['ipForwarding']) is None
        mixed = snmp_result(fixture('get_view_mixed.txt'))
        assert mixed.has_value(OID['sysName']) and not mixed.has_value(OID['ipForwarding']) and not mixed.refused
        inst = snmp_result(fixture('get_nosuchinstance.txt'))
        assert [v.exception for v in inst.vars] == ['noSuchInstance', 'noSuchObject']

    def test_view_in(self):
        r = snmp_result(fixture('get_view_in.txt'))
        assert r.value(OID['sysName']) == 'srv1' and r.int(OID['ifNumber']) == 2

    def test_walk_stops_at_the_end_of_the_view(self):
        r = snmp_result(fixture('walk_end_of_view.txt'))
        assert [v.oid for v in r.vars] == [OID['ifNumber']]

    @pytest.mark.parametrize('name, error, code', [
        ('get_timeout.txt', 'timeout', 1),
        ('v3_v2c_public.txt', 'timeout', 1),
        ('v3_wrong_priv.txt', 'timeout', 1),
        ('set_from_probe.txt', 'timeout', 1),
        ('v3_wrong_pass.txt', 'auth_failure', 1),
        ('v3_unknown_user.txt', 'unknown_user', 1),
        ('v3_authnopriv_denied.txt', 'authorization', 2),
        ('v3_noauth_denied.txt', 'authorization', 2),
        ('set_notwritable.txt', 'not_writable', 2),
        ('set_with_ro.txt', 'no_access', 2),
        ('set_wrong_type.txt', 'wrong_type', 2),
        ('get_v1_nosuch.txt', 'no_such_name', 2),
        ('v3_client_defaults_isolated.txt', 'no_security_name', 1),
    ])
    def test_errors(self, name, error, code):
        r = snmp_result(fixture(name))
        assert r.ran and r.error == error and r.exit_code == code
        assert not r.ok and r.refused
        assert r.timed_out == (error == 'timeout')

    def test_v3_ok_and_set_ok(self):
        v3 = snmp_result(fixture('v3_ok.txt'))
        assert v3.ok and v3.value(OID['sysName']) == 'srv2' and v3.int(OID['ifNumber']) == 2
        done = snmp_result(fixture('set_ok.txt'))
        assert done.ok and done.value(OID['sysName']) == 'srv1-prod-07'

    def test_placeholder_is_not_a_run(self):
        r = snmp_result('', 0)
        assert not r.ran and not r.ok and not r.refused and not r.timed_out
        assert r.value(OID['sysName']) is None and not r.has_value(OID['sysName'])

    def test_empty_and_hex_strings(self):
        variables = parse_snmp_output(fixture('walk_ifdescr_physaddr.txt'))
        phys = [v for v in variables if v.oid == OID['ifPhysAddress'] + '.2']
        assert phys and phys[0].type == 'Hex-STRING' and normalize_mac(phys[0].value) == 'ca:9f:dc:e5:c7:2a'
        lo = [v for v in variables if v.oid == OID['ifPhysAddress'] + '.1'][0]
        assert lo.has_value and lo.value == '' and lo.type == ''

    def test_multi_line_values(self):
        text = ('.1.3.6.1.2.1.1.1.0 = STRING: "line one\nline two"\n'
                '.1.3.6.1.2.1.2.2.1.6.3 = Hex-STRING: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF \n'
                '00 11 22 \n'
                '.1.3.6.1.2.1.1.5.0 = STRING: "x: y"\n'
                'Created directory: /var/lib/snmp/cert_indexes\n')
        variables = parse_snmp_output(text)
        assert [v.oid for v in variables] == ['.1.3.6.1.2.1.1.1.0', '.1.3.6.1.2.1.2.2.1.6.3', '.1.3.6.1.2.1.1.5.0']
        assert variables[0].value == 'line one\nline two'
        assert variables[1].value.endswith('EE FF 00 11 22') and variables[1].type == 'Hex-STRING'
        assert variables[2].value == 'x: y' and variables[2].type == 'STRING'

    def test_error_names(self):
        assert parse_snmp_error('') is None and parse_snmp_error(fixture('get_v2c_ok.txt')) is None
        assert parse_snmp_error('snmpget: Unsupported security level (Sub-id not found)') == 'unsupported_level'
        assert parse_snmp_error('snmpget: something new') == 'other'


class TestTables:
    def test_process_table(self):
        r = snmp_result(fixture('walk_prtable.txt'))
        rows = table_rows(r.vars, OID['prEntry'])
        assert sorted(rows) == ['1', '2']
        names = column_values(r.vars, OID['prEntry'], PR_NAMES)
        assert names == {'1': 'rsyslogd', '2': 'nginx'}
        assert rows['1'][PR_COUNT].int == 1 and rows['1'][PR_ERROR_FLAG].int == 0
        assert rows['2'][PR_COUNT].int == 0 and rows['2'][PR_ERROR_FLAG].int == 1

    def test_load_table(self):
        r = snmp_result(fixture('walk_latable.txt'))
        config = column_values(r.vars, OID['laEntry'], LA_CONFIG)
        assert [float(config[i]) for i in ('1', '2', '3')] == [12.0, 10.0, 6.0]

    def test_disk_table_of_an_overlay_root_is_empty(self):
        r = snmp_result(fixture('walk_dsktable_overlay.txt'))
        assert column_values(r.vars, OID['dskEntry'], DSK_PATH) == {}

    def test_extend_walk(self):
        r = snmp_result(fixture('walk_extend.txt'))
        out = column_values(r.vars, '.1.3.6.1.4.1.8072.1.3.2.3.1', 1)
        assert out == {extend_index('backup'): 'backup OK jobs=37 build=4f2a9c'}

    def test_address_table_gives_the_interface_index(self):
        r = snmp_result(fixture('walk_ipaddrtable.txt'))
        assert r.int(OID['ipAdEntIfIndex'] + '.172.18.0.2') == 2


# ---------------------------------------------------------------------------
# snmpd.conf
# ---------------------------------------------------------------------------

CONF = """
# a comment
agentAddress udp:161
sysLocation "Batiment B, salle 204"   # trailing comment
rocommunity ro-secret 10.1.2.0/24
view monitoring included .1.3.6.1.2.1.1
rocommunity vw-secret default -V monitoring
rocommunity sub-secret 10.1.2.5 .1.3.6.1.2.1.2
rwcommunity rw-secret 10.1.2.7
trap2sink 10.1.2.7 tr-secret
informsink udp:10.1.2.8:1162 other
trapsink host3 legacy 2162
authtrapenable 1
"""


class TestConf:
    def test_parse(self):
        conf = parse_snmpd_conf(CONF)
        assert conf[0] == ('agentaddress', ['udp:161'])
        assert conf_values(conf, 'sysLocation') == [['Batiment B, salle 204']]
        assert conf_values(conf, 'authtrapenable') == [['1']]
        assert parse_snmpd_conf('') == [] and parse_snmpd_conf(None) == []

    def test_communities(self):
        entries = conf_communities(parse_snmpd_conf(CONF))
        assert entries == [
            {'community': 'ro-secret', 'source': '10.1.2.0/24', 'view': None, 'oid': None, 'write': False},
            {'community': 'vw-secret', 'source': 'default', 'view': 'monitoring', 'oid': None, 'write': False},
            {'community': 'sub-secret', 'source': '10.1.2.5', 'view': None, 'oid': '.1.3.6.1.2.1.2', 'write': False},
            {'community': 'rw-secret', 'source': '10.1.2.7', 'view': None, 'oid': None, 'write': True},
        ]

    def test_trap_sinks(self):
        sinks = conf_trap_sinks(parse_snmpd_conf(CONF))
        assert sinks == [
            {'kind': 'trap2sink', 'host': '10.1.2.7', 'port': 162, 'community': 'tr-secret'},
            {'kind': 'informsink', 'host': '10.1.2.8', 'port': 1162, 'community': 'other'},
            {'kind': 'trapsink', 'host': 'host3', 'port': 2162, 'community': 'legacy'},
        ]

    def test_render_round_trip(self):
        text = render_snmpd_conf(
            name='rtr-07', location='Local technique', contact='noc <noc@corp.lab>', services=76,
            views=[('monitoring', '.1.3.6.1.2.1.1')],
            communities=[{'community': 'ro', 'source': '10.1.2.0/24'},
                         {'community': 'vw', 'view': 'monitoring'},
                         {'community': 'rw', 'source': '10.1.2.7', 'write': True}],
            v3_users=[('supervision', 'priv')], extends=[('asset', '/bin/echo INV-1')], procs=['nginx'],
            disks=[('/shared', '10%')], load=(12, 10, 6), trap_sinks=[('10.1.2.7', 'tr')], authtrapenable=True,
            extra=['# end'])
        conf = parse_snmpd_conf(text)
        assert text.startswith('agentaddress udp:161\n') and text.endswith('# end\n')
        assert [c['community'] for c in conf_communities(conf)] == ['ro', 'vw', 'rw']
        assert conf_communities(conf)[1] == {'community': 'vw', 'source': 'default', 'view': 'monitoring',
                                             'oid': None, 'write': False}
        assert conf_values(conf, 'rouser') == [['supervision', 'priv']]
        assert conf_values(conf, 'extend') == [['asset', '/bin/echo', 'INV-1']]
        assert conf_values(conf, 'disk') == [['/shared', '10%']] and conf_values(conf, 'load') == [['12', '10', '6']]
        assert conf_trap_sinks(conf) == [{'kind': 'trap2sink', 'host': '10.1.2.7', 'port': 162, 'community': 'tr'}]
        # views are declared before the communities that use them
        assert text.index('view monitoring') < text.index('rocommunity vw')

    def test_other_renderers(self):
        assert render_snmptrapd_conf(['tr-secret']) == 'authCommunity log tr-secret\n'
        client = render_snmp_client_conf('supervision', 'Auth-1', 'Priv-1')
        assert 'defSecurityName supervision\n' in client and 'defAuthType SHA-256\n' in client
        assert 'defPrivPassphrase Priv-1\n' in client and client.startswith('defVersion 3\n')
        dropin = render_snmptrapd_dropin('/var/log/snmptrapd.log')
        assert 'ExecStart=\nExecStart=/usr/sbin/snmptrapd -f -A -Lf /var/log/snmptrapd.log udp:162\n' in dropin
        assert 'User=root' in dropin


# ---------------------------------------------------------------------------
# traps
# ---------------------------------------------------------------------------

class TestTrapLog:
    def test_default_format_records(self):
        records = parse_trap_log(fixture('trap_log_default.txt'))
        assert len(records) == 6                               # the 'NET-SNMP version' line is not one
        assert 'sre-TOKEN-ok-1794427656796087213' in records[0] and '172.18.0.5' in records[0]
        assert not any('sre-TOKEN-bad' in r for r in records)   # dropped: no authCommunity for it
        failures = [r for r in records if is_authentication_failure(r)]
        assert len(failures) == 1 and '[172.18.0.2]' in failures[0]
        assert any('coldStart' in r for r in records) and any('nsNotifyShutdown' in r for r in records)

    def test_custom_format_records(self):
        records = parse_trap_log(fixture('trap_log_custom_format.txt'))
        assert len(records) == 2 and is_authentication_failure(records[1]) and '172.18.0.2' in records[1]

    def test_numeric_and_undated_logs(self):
        text = ('UDP: [10.0.0.9]:1234->[10.0.0.1]:162 .1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.5\n'
                'UDP: [10.0.0.9]:1234->[10.0.0.1]:162 .1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.51\n')
        records = parse_trap_log(text)
        assert [is_authentication_failure(r) for r in records] == [True, False]
        assert parse_trap_log('') == []

    def test_window(self):
        log = fixture('trap_log_default.txt').replace('===RC 0\n', '')
        lines = log.splitlines()
        tail = f'===LINES {len(lines)}\n===TAIL\n' + log + '===RC 0\n'
        assert parse_marked_lines(tail) == len(lines)
        assert len(trap_log_window(tail, 0)) == 6
        # the last four lines only: two records
        window = trap_log_window(tail, len(lines) - 4)
        assert len(window) == 2 and 'netSnmpExampleHeartbeatNotification' in window[0]
        assert trap_log_window(tail, len(lines)) == []
        # unknown count before, or a log shorter than before (rotated): the whole tail
        assert len(trap_log_window(tail, None)) == 6
        assert len(trap_log_window(tail, len(lines) + 50)) == 6

    def test_marked_lines(self):
        assert parse_marked_lines('===LINES 17\n===RC 0\n') == 17
        assert parse_marked_lines('===LINES \n===RC 0\n') == 0      # missing file
        assert parse_marked_lines('') is None

    def test_probe_step_output(self):
        out = fixture('probe_trap_step.txt')
        assert 'rc_ok=0' in out and '===NONCE 1794427656796087213' in out


# ---------------------------------------------------------------------------
# rate samples
# ---------------------------------------------------------------------------

class TestRate:
    def test_sample(self):
        # 5 s at 600 kbit/s with 842-byte frames: 375000 bytes in 445.37 frames
        text = '===RATE 1000000 1000 1794427694000000000 1375000 1445 1794427699000000000\n===RC 0\n'
        sample = parse_rate_sample(text)
        assert sample['bps'] == pytest.approx(600000) and sample['seconds'] == pytest.approx(5)
        assert sample['frame'] == pytest.approx(375000 / 445) and sample['pps'] == pytest.approx(89)

    def test_no_traffic_or_no_run(self):
        assert parse_rate_sample('===RATE 1253 14 1794427694452821331 1253 14 1794427696460618637\n') is None
        assert parse_rate_sample('') is None and parse_rate_sample('cat: /sys/…: No such file\n===RC 1') is None

    def test_command(self):
        cmd = rate_sample_cmd('eth1', 'tx', 5)
        assert '/sys/class/net/eth1/statistics/tx_bytes' in cmd and 'sleep 5' in cmd and cmd.endswith(RC_SUFFIX)
        assert '\n' not in cmd and '@@@' not in cmd

    def test_wrapper(self):
        cmd = rate_sample_cmd('eth1', 'tx', 5)
        grade = make_grade({cmd: ('===RATE 0 0 1000000000 125000 100 6000000000\n===RC 0\n', 0)})
        assert get_interface_rate(grade, 'router', 'eth1')['bps'] == pytest.approx(200000)
        assert get_interface_rate(make_grade({}), 'router', 'eth1') is None


# ---------------------------------------------------------------------------
# command builders
# ---------------------------------------------------------------------------

class TestCommands:
    def test_auth_args(self):
        assert snmp_auth_args('ro-secret') == '-v2c -c ro-secret'
        assert snmp_auth_args('ro secret', version='1') == "-v1 -c 'ro secret'"
        full = snmp_auth_args(user='supervision', auth_pass='Auth-1', priv_pass='Priv-1')
        assert full == '-v3 -u supervision -l authPriv -a SHA-256 -A Auth-1 -x AES -X Priv-1'
        assert snmp_auth_args(user='u', level='authNoPriv', auth_pass='a b') == "-v3 -u u -l authNoPriv -a SHA-256 -A 'a b'"
        assert snmp_auth_args(user='u', level='noAuthNoPriv') == '-v3 -u u -l noAuthNoPriv'
        with pytest.raises(ValueError):
            snmp_auth_args()

    def test_get(self):
        cmd = snmpget_cmd('10.0.0.2', [OID['sysName'], '1.3.6.1.2.1.2.1.0'], community='ro-secret')
        assert cmd == (f"{ISOLATE}snmpget -v2c -c ro-secret {GRADER_OPTS} -t 1 -r 1 10.0.0.2"
                       f" .1.3.6.1.2.1.1.5.0 .1.3.6.1.2.1.2.1.0{RC_SUFFIX}")
        refused = snmpget_cmd('10.0.0.2', OID['sysName'], community='public', retries=0)
        assert ' -r 0 ' in refused
        own = snmpget_cmd('10.0.0.3', OID['sysName'], isolate=False, env='HOME=/root ', user='u', level='noAuthNoPriv')
        assert own.startswith('HOME=/root snmpget -v3 -u u -l noAuthNoPriv')
        # no credential at all: the defaults of the user's snmp.conf are what is tested
        defaults = snmpget_cmd('10.0.0.3', OID['sysName'], isolate=False, env='HOME=/root ')
        assert defaults == f"HOME=/root snmpget {GRADER_OPTS} -t 1 -r 1 10.0.0.3 .1.3.6.1.2.1.1.5.0{RC_SUFFIX}"

    def test_walk_and_set(self):
        assert f' 10.0.0.2 {OID["prTable"]}' in snmpwalk_cmd('10.0.0.2', OID['prTable'], community='c')
        cmd = snmpset_cmd('10.0.0.2', OID['sysName'], 's', 'srv1 prod', community='rw')
        assert " .1.3.6.1.2.1.1.5.0 s 'srv1 prod'" in cmd and cmd.startswith(ISOLATE + 'snmpset -v2c -c rw ')

    def test_trap(self):
        playpen = OID['netSnmpPlaypen']
        cmd = snmptrap_cmd('10.0.0.7', 'tr-secret', playpen + '.0.1', [(playpen + '.1.1', 's', raw('"sre-tok-$N"'))])
        assert cmd == (f"{ISOLATE}snmptrap -v2c -c tr-secret -m '' 10.0.0.7:162 ''"
                       f" {playpen}.0.1 {playpen}.1.1 s \"sre-tok-$N\"")
        quoted = snmptrap_cmd('h', 'c', playpen + '.0.1', [(playpen + '.1.1', 's', 'a b')], port=1162, inform=True)
        assert quoted.endswith("h:1162 '' .1.3.6.1.4.1.8072.9999.9999.0.1 .1.3.6.1.4.1.8072.9999.9999.1.1 s 'a b'")
        assert 'snmpinform' in quoted

    def test_every_command_is_one_stable_line(self):
        commands = [
            snmpget_cmd('h', OID['sysName'], community='c'), snmpwalk_cmd('h', OID['system'], community='c'),
            snmpset_cmd('h', OID['sysName'], 's', 'x', community='c'), rate_sample_cmd('eth0'),
            trap_log_lines_cmd(), trap_log_tail_cmd(), snmpd_conf_dump_cmd(), snmpd_start_cmd(),
            create_v3_user_cmd('u', 'Auth-1234', 'Priv-1234'),
        ]
        for cmd in commands:
            assert '\n' not in cmd and '@@@' not in cmd
        assert snmpget_cmd('h', OID['sysName'], community='c') == snmpget_cmd('h', OID['sysName'], community='c')

    def test_trap_log_commands(self):
        assert trap_log_lines_cmd() == 'echo "===LINES $(wc -l < /var/log/snmptrapd.log 2>/dev/null)"' + RC_SUFFIX
        tail = trap_log_tail_cmd(lines=50, wait=2)
        assert tail.startswith('sleep 2; echo "===LINES ') and 'tail -n 50 /var/log/snmptrapd.log' in tail
        assert "tr -cd '\\11\\12\\15\\40-\\176'" in tail

    def test_create_v3_user(self):
        cmd = create_v3_user_cmd('supervision', 'Auth-1234', 'Priv-1234')
        assert cmd.startswith(f'systemctl stop snmpd; rm -f {SNMPD_PERSISTENT}; printf')
        assert 'createUser supervision SHA-256 "Auth-1234" AES "Priv-1234"' in cmd
        assert cmd.endswith('systemctl start snmpd') and f'chmod 600 {SNMPD_PERSISTENT}' in cmd
        direct = create_v3_user_cmd('u', 'a', 'p', systemd=False, reset=False)
        assert 'systemctl' not in direct and 'rm -f' not in direct and '/usr/sbin/snmpd' in direct

    def test_persistent_file_after_the_start_has_no_clear_secret(self):
        text = fixture('persistent_after_createuser.txt')
        lines = [line for line in text.splitlines() if line and not line.startswith('#')]
        assert any(line.startswith('usmUser ') for line in lines)
        assert not any(line.startswith('createUser') for line in lines) and 'AuthPass-2026' not in text


# ---------------------------------------------------------------------------
# wrappers and state helpers
# ---------------------------------------------------------------------------

class TestWrappers:
    def test_get_walk_set(self):
        get = snmpget_cmd('10.0.0.2', [OID['sysName'], OID['ifNumber']], community='vw-secret')
        walk = snmpwalk_cmd('10.0.0.2', OID['prTable'], community='ro-secret')
        done = snmpset_cmd('10.0.0.2', OID['sysName'], 's', 'srv1-prod-07', community='rw-secret')
        grade = make_grade({get: (fixture('get_view_in.txt'), 0), walk: (fixture('walk_prtable.txt'), 0),
                            done: (fixture('set_ok.txt'), 0)})
        assert snmp_get(grade, 'probe', '10.0.0.2', [OID['sysName'], OID['ifNumber']],
                        community='vw-secret').value(OID['sysName']) == 'srv1'
        assert len(snmp_walk(grade, 'probe', '10.0.0.2', OID['prTable'], community='ro-secret').vars) == 18
        assert snmp_set(grade, 'nms', '10.0.0.2', OID['sysName'], 's', 'srv1-prod-07',
                        community='rw-secret').value(OID['sysName']) == 'srv1-prod-07'
        # every call allows a failure (a refusal is a result to grade) and passes its step
        snmp_get(grade, 'probe', '10.0.0.2', OID['sysName'], step=2, community='c')
        assert grade.test.call_args.kwargs['step'] == 2 and grade.test.call_args.kwargs['allow_error'] is True

    def test_placeholders(self):
        grade = make_grade({})
        assert not snmp_get(grade, 'probe', 'h', OID['sysName'], community='c').ran
        assert get_snmpd_conf(grade, 'srv1') == []

    def test_conf_dump(self):
        grade = make_grade({snmpd_conf_dump_cmd(): ('agentaddress udp:161\nrocommunity ro 10.0.0.0/24\n===RC 0\n', 0)})
        assert get_snmpd_conf(grade, 'srv1') == [('agentaddress', ['udp:161']), ('rocommunity', ['ro', '10.0.0.0/24'])]

    def test_set_snmp_agent_without_systemd(self):
        ns = MagicMock()
        set_snmp_agent(ns, 'router', community='ro-secret', location='Baie 1', contact='noc@corp.lab', name='rtr-07',
                       sources=['10.1.2.0/24'], extends=[('asset', '/bin/echo INV-1')], services=76)
        (machine, path, text), kwargs = ns.file.call_args
        assert (machine, path) == ('router', SNMPD_CONF)
        assert kwargs == {'permissions': 0o640, 'owner': 'root:Debian-snmp', 'step': 1}
        assert 'rocommunity ro-secret 10.1.2.0/24\n' in text and 'sysName     rtr-07\n' in text
        assert 'extend asset /bin/echo INV-1\n' in text and 'sysServices 76\n' in text
        ns.cmd.assert_called_once_with('router', snmpd_start_cmd(), step=1)
        assert 'systemctl' not in snmpd_start_cmd()

    def test_set_snmp_agent_with_systemd_everywhere(self):
        ns = MagicMock()
        set_snmp_agent(ns, 'srv1', community='ro', systemd=True, step=2)
        assert 'rocommunity ro default\n' in ns.file.call_args.args[2]
        ns.cmd.assert_called_once_with('srv1', 'systemctl restart snmpd', step=2)

    def test_set_snmptrapd_service(self):
        ns = MagicMock()
        set_snmptrapd_service(ns, 'nms')
        assert ns.file.call_args.args[:2] == ('nms', SNMPTRAPD_DROPIN)
        commands = [c.args[1] for c in ns.cmd.call_args_list]
        assert commands[0].startswith('mkdir -p ') and 'systemctl mask snmptrapd.socket' in commands[1]
        assert all('\n' not in c for c in commands)


class TestLiveRun:
    """Outputs of an evaluation of the SNMP lab after its `final` state (z04, 2026-11-11: a constant
    bit rate of 960 kbit/s in 1242-byte frames crossing the router)."""

    def test_rate_sample(self):
        sample = parse_rate_sample(fixture('rate_sample.txt'))
        assert sample['bps'] == pytest.approx(970400, rel=0.001) and sample['seconds'] == pytest.approx(5.0, abs=0.05)
        # the grader's own requests cross the router during the sample: more, smaller frames
        assert sample['packets'] == 556 and 1050 < sample['frame'] < 1242

    def test_disk_table_of_a_bind_mount(self):
        r = snmp_result(fixture('walk_dsktable.txt'))
        rows = table_rows(r.vars, OID['dskEntry'])
        assert list(rows) == ['1'] and rows['1'][DSK_PATH].text == '/shared'
        from snmp import DSK_MIN_PERCENT
        assert rows['1'][DSK_MIN_PERCENT].int == 25

    def test_trap_log_window(self):
        tail = fixture('trap_log_tail_final.txt')
        assert parse_marked_lines(tail) == 13
        records = trap_log_window(tail, 7)                   # 7 lines before the evaluation
        assert len(records) == 3
        assert any('sre-41f0584da82c-ok-1794430437883828439' in r for r in records)
        failures = [r for r in records if is_authentication_failure(r)]
        assert len(failures) == 2 and all('[192.168.189.220]' in r and ' srv1 ' in r for r in failures)
        # the probe is not in /etc/hosts and there is no resolver: its name is unknown
        assert any('<UNKNOWN> [UDP: [192.168.95.6]' in r for r in records)
        everything = trap_log_window(tail, None)
        assert len(everything) == 6 and 'coldStart' in everything[0]

    def test_listeners(self):
        from openvpn import parse_ss_listeners
        srv1 = parse_ss_listeners(fixture('ss_ulnp_srv1.txt'))
        assert srv1[161] == {'address': '0.0.0.0', 'processes': ['snmpd']}
        nms = parse_ss_listeners(fixture('ss_ulnp_nms.txt'))
        assert nms[162]['processes'] == ['snmptrapd']

    def test_conf_dump(self):
        grade = make_grade({snmpd_conf_dump_cmd(): (fixture('snmpd_conf_dump_final.txt'), 0)})
        conf = get_snmpd_conf(grade, 'srv1')
        assert conf_trap_sinks(conf) == [{'kind': 'trap2sink', 'host': '192.168.95.36', 'port': 162,
                                          'community': 'tr-10d0e5c0'}]
        assert [c['community'] for c in conf_communities(conf)] == ['ro-a033b1ab', 'vw-64a796fd', 'rw-92dea922']
        assert conf_values(conf, 'disk') == [['/shared', '25%']]


class TestFacts:
    def test_default_agent_fails_without_ipv6(self):
        assert 'Error opening specified endpoint "[::1]"' in fixture('default_start.txt')

    def test_packaged_helper_gives_a_plain_rouser(self):
        text = fixture('create_v3_user_script.txt')
        assert 'rouser helper\n' in text and 'createUser helper SHA-256' in text

    def test_router_extend(self):
        r = snmp_result(fixture('router_extend.txt'))
        assert r.value(extend_oid('nsExtendOutput1Line', 'asset')) == 'INV-482913'
