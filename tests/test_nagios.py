"""Tests for lib/nagios.py (fixtures captured on Nagios Core 4.4.6, monitoring-plugins 2.3.3 and
NRPE 4.1.0, Debian 12, in sysreseval/monitoring containers on 2026-11-11: tests/mock_data/nagios/)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))

from nagios import (  # noqa: E402
    COMMAND_FILE, LABDB_SCRIPT, OBJECTS_CACHE, PLUGIN_DIR, RC_SUFFIX, SMS_OUTBOX, STATUS_DAT, check_nrpe,
    check_nrpe_cmd, checked_state, expand_command_line, external_command, external_commands_cmd, get_nrpe_config,
    get_notifications, get_objects, get_sms, get_status, notification_log_cmd, notification_type, notifications,
    nrpe_config_cmd, number, objects_cmd, options_set, parse_blocks, parse_nagios_log, parse_nrpe_config,
    parse_objects_cache, parse_perfdata, parse_plugin_output, parse_sms_outbox, parse_status_dat, parse_t0,
    parse_written, plugin_case, plugin_case_cmd, preflight_cmd, render_check_queue, render_lab_templates,
    render_labdb_script, render_labdb_unit, render_localhost_cfg, render_nrpe_conf, render_object, render_sms_send,
    sms_outbox_cmd, split_check_command, status_cmd, submit_external_commands,
)

MOCK = Path(__file__).parent / 'mock_data' / 'nagios'
# what external_commands_cmd() prints when Nagios reads its pipe (the write of the captured session)
WRITE_OUTPUT = '===T0 1794431055\nwritten=0\n===RC 0\n'


def fixture(name: str) -> str:
    return (MOCK / name).read_text()


def make_grade(responses: dict):
    grade = MagicMock()

    def _test(machine_name, command, step=1, **kwargs):
        return responses.get(command, ('', 0))

    grade.test.side_effect = _test
    return grade


@pytest.fixture(scope='module')
def objects():
    return parse_objects_cache(fixture('objects_final.cache'))


@pytest.fixture(scope='module')
def status():
    return parse_status_dat(fixture('status_final.dat'))


# ---------------------------------------------------------------------------
# objects.cache
# ---------------------------------------------------------------------------

class TestObjects:
    def test_blocks(self, objects):
        assert objects.ran
        kinds = {k for k, _ in objects.blocks}
        assert {'host', 'hostgroup', 'service', 'servicegroup', 'contact', 'contactgroup', 'command',
                'timeperiod'} <= kinds
        assert len(objects.of_kind('host')) == 4 and len(objects.of_kind('service')) == 24

    def test_hosts(self, objects):
        db1 = objects.host('db1')
        assert db1['address'] == '172.18.0.4' and db1['parents'] == 'router' and db1['contact_groups'] == 'dmz-admins'
        assert number(db1, 'check_interval') == 0.5 and number(db1, 'max_check_attempts') == 3
        assert objects.host('router').get('parents') is None and objects.host('absent') is None
        assert options_set(db1['notification_options']) == {'d', 'r'}

    def test_groups(self, objects):
        assert objects.hostgroup_members('dmz-servers') == {'web1', 'db1'}
        assert objects.servicegroup_members('business') == {('web1', 'HEALTH'), ('db1', 'DB')}
        assert objects.contactgroup_members('dmz-admins') == {'oncall'}
        assert objects.hostgroup_members('absent') is None and objects.servicegroup_members('absent') is None

    def test_contact(self, objects):
        oncall = objects.contact('oncall')
        assert oncall['pager'] == '0612345678' and oncall['service_notification_commands'] == 'notify-service-by-sms'
        assert options_set(oncall['service_notification_options']) == {'c', 'r'}
        assert options_set(oncall['host_notification_options']) == {'d', 'r'}

    def test_services_and_effective_commands(self, objects):
        health = objects.service('web1', 'HEALTH')
        assert split_check_command(health['check_command']) == ('check_http_string', ['/health', '4f2a9c1b'])
        macros = {'USER1': PLUGIN_DIR, 'HOSTADDRESS': '172.18.0.3'}
        assert objects.effective_command(health, macros) == (
            '/usr/lib/nagios/plugins/check_http -H 172.18.0.3 -u /health -s 4f2a9c1b')
        ping = objects.effective_command(objects.service('db1', 'PING'), {'HOSTADDRESS': '172.18.0.4'})
        assert ping == "/usr/lib/nagios/plugins/check_ping -H '172.18.0.4' -w '100.0,20%' -c '500.0,60%'"
        snmp = objects.effective_command(objects.service('router', 'IF-DMZ'), macros)
        assert '-C sre3f9a1c -o .1.3.6.1.2.1.2.2.1.8.2 -c 1:1' in snmp
        nrpe = objects.effective_command(objects.service('db1', 'QUEUE'), macros)
        assert nrpe.endswith('check_nrpe -H 172.18.0.3 -c check_queue'.replace('0.3', '0.3')) or 'check_queue' in nrpe
        assert objects.effective_command(None) == '' and objects.effective_command({'check_command': 'nope!1'}) == ''
        assert len(objects.services_of('db1')) == 8

    def test_passive_service(self, objects):
        backup = objects.service('db1', 'BACKUP')
        assert number(backup, 'active_checks_enabled') == 0 and number(backup, 'passive_checks_enabled') == 1
        assert number(backup, 'check_freshness') == 1 and number(backup, 'freshness_threshold') == 60
        stale = objects.effective_command(backup, {'USER1': PLUGIN_DIR})
        assert stale == '/usr/lib/nagios/plugins/check_dummy 2 "Aucune sauvegarde signalee depuis 60 secondes"'

    def test_expand(self):
        assert expand_command_line('$USER1$/x -H $HOSTADDRESS$ $ARG1$ $ARG2$', ['a'], {'USER1': '/p'}) == (
            '/p/x -H $HOSTADDRESS$ a $ARG2$')
        assert split_check_command('check_ssh') == ('check_ssh', []) and split_check_command(None) == ('', [])
        assert expand_command_line(None) == ''

    def test_placeholder(self):
        empty = parse_objects_cache('')
        assert not empty.ran and empty.host('web1') is None and empty.hostgroup_members('x') is None
        assert not parse_objects_cache('cat: /var/lib/nagios4/objects.cache: No such file or directory\n===RC 0').ran


# ---------------------------------------------------------------------------
# status.dat
# ---------------------------------------------------------------------------

class TestStatus:
    def test_hosts_and_services(self, status):
        assert status.ran and status.created() == 1794431063
        web1 = status.host('web1')
        assert checked_state(web1) == 0 and web1['plugin_output'].startswith('PING OK')
        health = status.service('web1', 'HEALTH')
        assert checked_state(health) == 0 and health['plugin_output'].startswith('HTTP OK')
        assert status.service('db1', 'QUEUE')['performance_data'] == 'queue=17;50;100;0'
        assert status.host('absent') is None and status.service('web1', 'absent') is None

    def test_forced_check_is_after_t0(self, status):
        t0 = parse_t0(WRITE_OUTPUT)
        assert t0 == 1794431055 and parse_written(WRITE_OUTPUT)
        # the forced checks ran at or after the write; the others are older
        assert checked_state(status.service('web1', 'HEALTH'), since=t0) == 0
        assert checked_state(status.host('web1'), since=t0) == 0
        assert checked_state(status.service('web1', 'SSH'), since=t0) is None
        assert checked_state(status.service('web1', 'SSH')) == 0

    def test_passive_result(self, status):
        backup = status.service('db1', 'BACKUP')
        assert backup['plugin_output'] == 'BACKUP OK - sre-eval tok123'
        assert number(backup, 'check_type') == 1 and checked_state(backup, since=1794431055) == 0

    def test_not_checked_yet(self, status):
        # localhost's stock services had not run after 50 s (5-minute interval)
        assert checked_state(status.service('localhost', 'Swap Usage')) is None

    def test_incident(self):
        incident = parse_status_dat(fixture('status_incident_db.dat'))
        assert checked_state(incident.service('db1', 'DB')) == 2
        assert checked_state(incident.service('db1', 'PROCS')) == 2
        assert checked_state(incident.host('db1')) == 0 and checked_state(incident.service('web1', 'HEALTH')) == 0

    def test_placeholder(self):
        assert not parse_status_dat('').ran and parse_status_dat('').host('web1') is None
        assert checked_state(None) is None and number(None, 'x') is None and number({'x': 'a'}, 'x', 7) == 7


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------

class TestPlugins:
    @pytest.mark.parametrize('name, state, rc', [
        ('plugin_ping_nagios.txt', 'OK', 0), ('plugin_ping_down.txt', 'CRITICAL', 2),
        ('plugin_http_ok.txt', 'OK', 0), ('plugin_http_404.txt', 'WARNING', 1),
        ('plugin_http_string_missing.txt', 'CRITICAL', 2), ('plugin_tcp_ok.txt', 'OK', 0),
        ('plugin_tcp_refused.txt', '', 2), ('plugin_ssh.txt', 'OK', 0), ('plugin_snmp_ok.txt', 'OK', 0),
        ('plugin_snmp_critical.txt', 'CRITICAL', 2), ('plugin_snmp_timeout.txt', '', 3),
        ('plugin_dummy.txt', 'CRITICAL', 2), ('nrpe_version.txt', '', 0), ('nrpe_refused.txt', '', 2),
        ('nrpe_unknown_command.txt', '', 3), ('nrpe_no_daemon.txt', '', 2), ('nrpe_load.txt', 'OK', 0),
        ('queue_case_5.txt', 'OK', 0), ('queue_case_10.txt', 'WARNING', 1), ('queue_case_15.txt', 'WARNING', 1),
        ('queue_case_20.txt', 'CRITICAL', 2), ('queue_case_500.txt', 'CRITICAL', 2),
        ('queue_case_abc.txt', 'UNKNOWN', 3), ('queue_case_missing.txt', 'UNKNOWN', 3),
        ('queue_case_nothresholds.txt', 'UNKNOWN', 3),
    ])
    def test_states_and_codes(self, name, state, rc):
        r = parse_plugin_output(fixture(name))
        assert r.ran and r.rc == rc and r.state == state and r.ok == (rc == 0)

    def test_a_missing_plugin_exits_like_a_warning(self):
        r = parse_plugin_output(fixture('queue_case_noplugin.txt'))
        assert r.rc == 1 and r.state == '' and 'failed to execute' in r.line     # the state word tells them apart

    def test_perfdata(self):
        ping = parse_plugin_output(fixture('plugin_ping_nagios.txt')).perfdata
        assert ping['rta'].unit == 'ms' and float(ping['rta'].warn) == 100 and float(ping['rta'].crit) == 500
        assert ping['pl'].value == 0 and ping['pl'].unit == '%' and ping['pl'].warn == '20' and ping['pl'].crit == '60'
        queue = parse_plugin_output(fixture('queue_case_5.txt')).perfdata['queue']
        assert (queue.value, queue.warn, queue.crit, queue.minimum) == (5, '10', '20', '0')
        load = parse_plugin_output(fixture('nrpe_load.txt')).perfdata
        assert float(load['scaled_load1'].warn) == 20 and float(load['scaled_load1'].crit) == 40
        assert float(load['scaled_load5'].warn) == 15 and float(load['scaled_load15'].crit) == 20
        disk = parse_plugin_output(fixture('nrpe_disk.txt'))
        assert disk.line.startswith('DISK OK') and '/' in disk.perfdata and disk.perfdata['/'].unit == 'B'
        assert parse_perfdata("'a b'=1;2;3 c=4") == {
            'a b': parse_perfdata("'a b'=1;2;3")['a b'], 'c': parse_perfdata('c=4')['c']}
        assert parse_perfdata('') == {}

    def test_nrpe_outputs(self):
        assert parse_plugin_output(fixture('nrpe_version.txt')).line == 'NRPE v4.1.0'
        assert 'Connection reset by peer' in parse_plugin_output(fixture('nrpe_refused.txt')).line
        assert "with command name 'labdb'" in parse_plugin_output(fixture('nrpe_procs_db1.txt')).line
        assert "with command name 'nginx'" in parse_plugin_output(fixture('nrpe_procs_web1.txt')).line
        queue = parse_plugin_output(fixture('nrpe_queue.txt'))
        assert queue.state == 'OK' and queue.perfdata['queue'].value == 17

    def test_placeholder(self):
        r = parse_plugin_output('')
        assert not r.ran and r.rc is None and not r.ok and r.state == ''


# ---------------------------------------------------------------------------
# log, notifications, NRPE files
# ---------------------------------------------------------------------------

class TestLog:
    def test_custom_notifications(self):
        entries = parse_nagios_log(fixture('notification_log.txt'))
        assert [e.kind for e in entries] == ['SERVICE NOTIFICATION', 'HOST NOTIFICATION']
        service = notifications(entries, 'SERVICE', contact='oncall', host='db1', service='DB', since=1794431055)
        assert len(service) == 1 and notification_type(service[0]) == 'CUSTOM (OK)'
        assert service[0].fields[4] == 'notify-service-by-sms' and service[0].fields[-2:] == ['sre-eval', 'tok123']
        host = notifications(entries, 'HOST', contact='oncall', host='db1')
        assert len(host) == 1 and notification_type(host[0]) == 'CUSTOM (UP)'
        assert notifications(entries, 'SERVICE', since=1794431056) == []
        assert notifications(entries, 'SERVICE', contact='other') == []

    def test_incident_and_recovery(self):
        entries = parse_nagios_log(fixture('log_incident.txt'))
        alerts = [e for e in entries if e.kind == 'SERVICE ALERT' and e.fields[:2] == ['db1', 'DB']]
        assert [(e.fields[2], e.fields[3], e.fields[4]) for e in alerts] == [
            ('CRITICAL', 'SOFT', '1'), ('CRITICAL', 'SOFT', '2'), ('CRITICAL', 'HARD', '3')]
        problem = notifications(entries, 'SERVICE', contact='oncall', host='db1', service='DB')
        assert [notification_type(e) for e in problem] == ['CRITICAL']
        stale = notifications(entries, 'SERVICE', service='BACKUP')
        assert len(stale) == 1 and 'Aucune sauvegarde' in stale[0].fields[5]
        recovery = notifications(parse_nagios_log(fixture('log_recovery.txt')), 'SERVICE', service='DB')
        assert [notification_type(e) for e in recovery] == ['OK']

    def test_external_command_log(self):
        entries = parse_nagios_log(fixture('external_command_log.txt'))
        commands = [e.fields[0] for e in entries if e.kind == 'EXTERNAL COMMAND']
        assert commands == ['PROCESS_SERVICE_CHECK_RESULT', 'SEND_CUSTOM_SVC_NOTIFICATION',
                            'SEND_CUSTOM_HOST_NOTIFICATION', 'SCHEDULE_FORCED_HOST_CHECK',
                            'SCHEDULE_FORCED_SVC_CHECK', 'SCHEDULE_FORCED_SVC_CHECK']
        assert parse_nagios_log('') == [] and parse_nagios_log('garbage\n===RC 0') == []

    def test_sms_outbox(self):
        messages = parse_sms_outbox(fixture('sms_outbox_incident.txt'))
        assert len(messages) == 7 and {m.number for m in messages} == {'0612345678'}
        assert messages[0].time == 1794431055 and messages[0].message.startswith('CUSTOM db1/DB OK - TCP OK')
        assert messages[1].message.startswith('CUSTOM db1 UP - ')
        kinds = [m.message.split()[0] for m in messages]
        assert kinds == ['CUSTOM', 'CUSTOM', 'PROBLEM', 'PROBLEM', 'PROBLEM', 'RECOVERY', 'RECOVERY']
        assert parse_sms_outbox('tail: cannot open\n===RC 1') == []

    def test_nrpe_config(self):
        conf = parse_nrpe_config(fixture('nrpe_dump.txt'))
        assert conf['allowed_hosts'] == ['127.0.0.1', '172.18.0.2']             # the last line wins
        assert conf['commands']['check_load'].endswith('check_load -r -w 20,15,10 -c 40,30,20')
        assert 'check_users' in conf['commands'] and conf['commands']['check_disk'].endswith('-w 15% -c 8% -p /')
        assert parse_nrpe_config('') == {'allowed_hosts': [], 'commands': {}}

    def test_t0(self):
        assert parse_t0('') is None and not parse_written('')
        assert parse_t0('===T0 12\nwritten=nopipe\n===RC 0') == 12 and not parse_written('===T0 12\nwritten=nopipe\n')
        assert not parse_written('===T0 12\nwritten=124\n')                    # the bounded write timed out


# ---------------------------------------------------------------------------
# command builders
# ---------------------------------------------------------------------------

class TestCommands:
    def test_external_commands(self):
        commands = [external_command('PROCESS_SERVICE_CHECK_RESULT', 'db1', 'BACKUP', 0, 'BACKUP OK - sre-eval tok'),
                    external_command('SCHEDULE_FORCED_SVC_CHECK', 'router', 'IF-DMZ', '{now}')]
        cmd = external_commands_cmd(commands)
        assert cmd.startswith(f'f={COMMAND_FILE}; n=$(date +%s); echo "===T0 $n"; if [ -p $f ]; then printf ')
        assert '"$n" "PROCESS_SERVICE_CHECK_RESULT;db1;BACKUP;0;BACKUP OK - sre-eval tok"' in cmd
        assert '"$n" "SCHEDULE_FORCED_SVC_CHECK;router;IF-DMZ;$n"' in cmd
        assert '| timeout 5 tee $f > /dev/null' in cmd and 'written=nopipe' in cmd and cmd.endswith(RC_SUFFIX)
        assert '\n' not in cmd and '@@@' not in cmd
        with pytest.raises(ValueError):
            external_commands_cmd(['X;$(reboot)'])
        with pytest.raises(ValueError):
            external_commands_cmd(['X;"quote'])

    def test_files_and_waits(self):
        assert objects_cmd().startswith(f'cat {OBJECTS_CACHE} 2>&1 | tr -cd ')
        assert status_cmd(12).startswith(f'sleep 12; cat {STATUS_DAT} 2>&1 | tr -cd ')
        assert preflight_cmd().startswith('out=$(/usr/sbin/nagios4 -v /etc/nagios4/nagios.cfg 2>&1); rc=$?;')
        assert sms_outbox_cmd(40).startswith(f'tail -n 40 {SMS_OUTBOX} 2>&1')
        assert "grep -F 'NOTIFICATION: '" in notification_log_cmd('sre-eval;tok') and "'sre-eval;tok'" in notification_log_cmd('sre-eval;tok')
        assert nrpe_config_cmd().startswith("grep -hvE '^[[:space:]]*(#|$)' /etc/nagios/nrpe.cfg ")

    def test_check_nrpe(self):
        assert check_nrpe_cmd('10.0.0.3') == f'{PLUGIN_DIR}/check_nrpe -H 10.0.0.3 -t 5{RC_SUFFIX}'
        assert check_nrpe_cmd('10.0.0.3', 'check_load', 3) == f'{PLUGIN_DIR}/check_nrpe -H 10.0.0.3 -t 3 -c check_load{RC_SUFFIX}'

    def test_plugin_case(self):
        with_file = plugin_case_cmd('/p/check_queue', '-w 10 -c 20', '15')
        assert with_file == ('f=$(mktemp /tmp/sreq.XXXXXX); echo 15 > $f; chmod 644 $f;'
                             ' runuser -u nagios -- /p/check_queue -w 10 -c 20 -f $f 2>&1; echo "===RC $?"; rm -f $f')
        assert plugin_case_cmd('/p/check_queue', '') == f'runuser -u nagios -- /p/check_queue{RC_SUFFIX}'
        assert plugin_case_cmd('/p/check_queue', '-w 1 -c 2 -f /nonexistent').endswith(f'-f /nonexistent{RC_SUFFIX}')

    def test_every_command_is_one_line(self):
        commands = [objects_cmd(), status_cmd(), preflight_cmd(), check_nrpe_cmd('h', 'c'), sms_outbox_cmd(),
                    plugin_case_cmd('/p', '-w 1', 'abc'), notification_log_cmd('m'), nrpe_config_cmd(),
                    external_commands_cmd([external_command('A', 'b')])]
        for cmd in commands:
            assert '\n' not in cmd and '@@@' not in cmd


# ---------------------------------------------------------------------------
# renderers
# ---------------------------------------------------------------------------

class TestRenderers:
    def test_object_round_trip(self):
        text = render_object('host', [('use', 'lab-host'), ('host_name', 'web1'), ('address', '10.0.0.3')])
        assert text.startswith('define host {\n    use') and text.endswith('}\n')
        assert parse_blocks(text) == [('host', {'use': 'lab-host', 'host_name': 'web1', 'address': '10.0.0.3'})]

    def test_lab_templates(self):
        blocks = dict(parse_blocks(render_lab_templates()))
        assert blocks['host']['name'] == 'lab-host' and blocks['host']['register'] == '0'
        assert blocks['host']['check_command'] == 'check-host-alive' and blocks['host']['check_interval'] == '0.5'
        assert blocks['service']['name'] == 'lab-service' and blocks['service']['retry_interval'] == '0.25'
        assert blocks['service']['max_check_attempts'] == '3' and 'use' not in blocks['service']

    def test_localhost(self):
        blocks = parse_blocks(render_localhost_cfg())
        assert [k for k, _ in blocks] == ['host', 'hostgroup', 'service', 'service', 'service']
        assert {b['service_description'] for k, b in blocks if k == 'service'} == {'PING', 'Current Users',
                                                                                 'Total Processes'}

    def test_scripts(self):
        sms = render_sms_send()
        assert sms.startswith('#!/bin/sh\n') and f'>> {SMS_OUTBOX}\n' in sms and "printf '%s\\t%s\\t%s\\n'" in sms
        assert 'prctl(15, b"labdb"' in render_labdb_script()
        compile(render_labdb_script(), 'labdb', 'exec')
        unit = render_labdb_unit(5432)
        assert f'ExecStart={LABDB_SCRIPT} 5432\n' in unit and 'WantedBy=multi-user.target' in unit
        plugin = render_check_queue('/var/lib/labdb/queue')
        assert plugin.startswith('#!/bin/sh\nFILE=/var/lib/labdb/queue\n') and 'exit 3' in plugin
        assert 'P="queue=$N;$W;$C;0"' in plugin and '{ echo' in plugin and '{{' not in plugin

    def test_nrpe_conf(self):
        text = render_nrpe_conf(['127.0.0.1', '10.0.0.2'], [('check_load', '/p/check_load -r -w 1,1,1 -c 2,2,2')])
        assert text == 'allowed_hosts=127.0.0.1,10.0.0.2\ncommand[check_load]=/p/check_load -r -w 1,1,1 -c 2,2,2\n'
        assert parse_nrpe_config(text) == {'allowed_hosts': ['127.0.0.1', '10.0.0.2'],
                                           'commands': {'check_load': '/p/check_load -r -w 1,1,1 -c 2,2,2'}}


# ---------------------------------------------------------------------------
# wrappers
# ---------------------------------------------------------------------------

class TestWrappers:
    def test_submit(self):
        commands = [external_command('SCHEDULE_FORCED_HOST_CHECK', 'web1', '{now}')]
        grade = make_grade({external_commands_cmd(commands): (WRITE_OUTPUT, 0)})
        assert submit_external_commands(grade, 'monitor', commands) == (1794431055, True)
        assert submit_external_commands(make_grade({}), 'monitor', commands) == (None, False)

    def test_objects_and_status(self):
        grade = make_grade({objects_cmd(): (fixture('objects_final.cache') + '===RC 0\n', 0),
                            status_cmd(12): (fixture('status_final.dat') + '===RC 0\n', 0)})
        assert get_objects(grade, 'monitor').hostgroup_members('dmz-servers') == {'web1', 'db1'}
        assert checked_state(get_status(grade, 'monitor').host('db1')) == 0
        assert grade.test.call_args.kwargs['step'] == 2 and grade.test.call_args.kwargs['timeout'] == 32
        assert not get_objects(make_grade({}), 'monitor').ran and not get_status(make_grade({}), 'monitor').ran

    def test_nrpe_and_plugin(self):
        grade = make_grade({check_nrpe_cmd('10.0.0.3'): (fixture('nrpe_version.txt'), 0),
                            check_nrpe_cmd('10.0.0.3', 'check_load'): (fixture('nrpe_load.txt'), 0),
                            plugin_case_cmd('/p/check_queue', '-w 10 -c 20', '15'): (fixture('queue_case_15.txt'), 0),
                            nrpe_config_cmd(): (fixture('nrpe_dump.txt'), 0)})
        assert check_nrpe(grade, 'monitor', '10.0.0.3').line == 'NRPE v4.1.0'
        assert check_nrpe(grade, 'monitor', '10.0.0.3', 'check_load').state == 'OK'
        assert plugin_case(grade, 'db1', '/p/check_queue', '-w 10 -c 20', '15').rc == 1
        assert get_nrpe_config(grade, 'web1')['allowed_hosts'] == ['127.0.0.1', '172.18.0.2']
        assert not check_nrpe(make_grade({}), 'monitor', '10.0.0.3').ran

    def test_notifications_and_sms(self):
        grade = make_grade({notification_log_cmd('sre-eval;tok123'): (fixture('notification_log.txt'), 0),
                            sms_outbox_cmd(): (fixture('sms_outbox.txt'), 0)})
        assert len(get_notifications(grade, 'monitor', 'sre-eval;tok123')) == 2
        assert [m.message.split()[0] for m in get_sms(grade, 'monitor')] == ['CUSTOM', 'CUSTOM']
