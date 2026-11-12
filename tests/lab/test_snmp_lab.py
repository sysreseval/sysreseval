"""Offline tests of the SNMP lab (lab/sre/_DRAFT_misc/snmp.py): the data, the topology (three init
machines, the router without terminal, two hidden machines, the pinned MAC address), the state ops
(the router's agent and the constant bit rate of `initial`, the whole solution of `final`, every
command on one line), the multi-pass grading contract with synthetic outputs (nothing done: 0,
everything done: 100, each part left out loses its own points, a few scoring details), the
instructor texts, the numbered course, the stripped lab file and the English identifiers.

No Docker: a small model of the agents (communities with their sources and views, the SNMPv3 user,
the trap log) answers the grader's commands in the formats of Net-SNMP 5.9.3 (the fixtures of
tests/mock_data/snmp/ show the real ones).
"""
import datetime
import importlib.util
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from SRE import params
from SRE.common import TranslatedText
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import snmp as sn  # noqa: E402
import traffic  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'snmp.py'
NONCE = "1794427656796087213"
PARTS = {'part1': 14, 'part2': 16, 'part3': 14, 'part4': 18, 'part5': 12, 'part6': 14, 'part7': 12}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('snmp_lab_under_test', _LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def data(lab):
    d = lab.Data.generate()
    d.compute_post_generate()
    return d


def _running_name():
    return params.get_running_lab_name(lab_name=_LAB_PATH.name, instance_start_date=datetime.datetime(2000, 1, 1),
                                       username='check')


def _text(t, lang='fr'):
    return t.resolve(lang) if hasattr(t, 'resolve') else str(t)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    getattr(ns, name)()
    ops = {}
    for step in sorted(ns._ops):
        for machine, op_list in ns._ops[step].items():
            ops.setdefault((step, machine), []).extend(op_list)
    return ops


def _cmds(ops, step, machine):
    return [str(op) for op in ops.get((step, machine), []) if isinstance(op, str)]


def _files(ops, step, machine):
    return {op.filename: (op.content.decode() if isinstance(op.content, bytes) else op.content)
            for op in ops.get((step, machine), []) if not isinstance(op, str)}


# ---------------------------------------------------------------------------
# a model of the lab answering the grader's commands
# ---------------------------------------------------------------------------


@dataclass
class Done:
    """What the student has done (every flag True: the reference solution)."""
    agent: bool = True          # part 2: srv1 listens, read community limited to lan, public removed
    wide_open: bool = False     # part 2 done badly: the read community answers every source
    views: bool = True          # part 3: audit community with its view, write community for nms
    rw_everywhere: bool = False  # part 3 done badly: the write community answers the whole lan
    v3: bool = True             # part 4: SNMPv3 user on srv2, no community
    v3_level: str = 'priv'      # part 4: level required by the rouser line
    v3_clear: bool = False      # part 4 done badly: createUser left in /etc/snmp/snmpd.conf
    client: bool = True         # part 4: root's defaults on nms
    extensions: bool = True     # part 5
    proc_running: bool = True   # part 5: the watched service is started
    trapd: bool = True          # part 6: snmptrapd on nms with authCommunity
    trap_sink: bool = True      # part 6: trap2sink + authtrapenable on srv1


def nothing():
    return Done(agent=False, views=False, v3=False, client=False, extensions=False, proc_running=False,
                trapd=False, trap_sink=False)


def _line(oid, kind, value):
    if kind == 'STRING':
        return f'{oid} = STRING: "{value}"'
    return f'{oid} = {kind}: {value}'


class Scenario:
    def __init__(self, lab, ns, done: Done):
        self.lab, self.ns, self.d, self.done = lab, ns, ns.data, done
        d = self.d
        self.ips = {m: str(getattr(d.ips, m).ip) for m in ('nms', 'probe', 'srv1', 'srv2', 'outsider')}
        self.lan = ('nms', 'probe')
        self.sysname1 = 'srv1'
        self.log_lines = 10 if done.trapd else None      # lines of the trap log before the evaluation

    # -- the objects of an agent ----------------------------------------------------

    def _objects(self, host):
        d, done, lab = self.d, self.done, self.lab
        o = sn.OID
        if host == 'srv1':
            objs = {
                o['sysObjectID']: ('OID', '.1.3.6.1.4.1.8072.3.2.10'),
                o['sysContact']: ('STRING', lab.CONTACT), o['sysName']: ('STRING', self.sysname1),
                o['sysLocation']: ('STRING', d.srv1_location), o['ifNumber']: ('INTEGER', 2),
                o['ipForwarding']: ('INTEGER', 2), o['hrSystemUptime']: ('Timeticks', '(13098921) 1 day, 12:23:09.21'),
                o['snmpEnableAuthenTraps']: ('INTEGER', 1 if done.trap_sink else 2),
                o['memTotalReal']: ('INTEGER', 16000000),
            }
            if done.extensions:
                name = d.extend_name
                objs[sn.extend_oid('nsExtendCommand', name)] = ('STRING', lab.APP_SCRIPT)
                objs[sn.extend_oid('nsExtendOutput1Line', name)] = ('STRING', d.app_status_line)
                objs[sn.extend_oid('nsExtendResult', name)] = ('INTEGER', 0)
                pr, dsk, la = o['prEntry'], o['dskEntry'], o['laEntry']
                running = done.proc_running
                objs.update({f'{pr}.1.1': ('INTEGER', 1), f'{pr}.2.1': ('STRING', d.watched_service),
                             f'{pr}.5.1': ('INTEGER', 1 if running else 0),
                             f'{pr}.100.1': ('INTEGER', 0 if running else 1)})
                objs.update({f'{dsk}.1.1': ('INTEGER', 1), f'{dsk}.2.1': ('STRING', lab.DISK_PATH),
                             f'{dsk}.4.1': ('INTEGER', -1), f'{dsk}.5.1': ('INTEGER', d.disk_min_percent)})
                for i, value in enumerate((d.load1, d.load5, d.load15), 1):
                    objs[f'{la}.3.{i}'] = ('STRING', '0.42')
                    objs[f'{la}.4.{i}'] = ('STRING', f'{value:.2f}')
            return objs
        return {o['sysName']: ('STRING', 'srv2'), o['sysLocation']: ('STRING', d.srv2_location),
                o['ifNumber']: ('INTEGER', 2)}

    def _access(self, host, source, credentials):
        """(readable subtrees or None for everything, may write) or an error output."""
        d, done = self.d, self.done
        timeout = f"Timeout: No Response from {self.ips[host]}.\n===RC 1\n"
        kind = credentials[0]
        if host == 'srv1':
            if not done.agent or kind != 'community':
                return timeout
            community = credentials[1]
            in_lan = source in self.lan
            if community == d.ro_community and (in_lan or done.wide_open):
                return None, False
            if done.views and community == d.view_community and in_lan:
                return (sn.OID['system'], sn.OID['interfaces']), False
            if done.views and community == d.rw_community and (source == 'nms' or (done.rw_everywhere and in_lan)):
                return None, True
            return timeout
        # srv2
        if not done.v3:
            return timeout
        if kind == 'community':
            return timeout
        _, user, level, auth_pass, priv_pass = credentials
        if user != d.v3_user:
            return "snmpget: Unknown user name\n===RC 1\n"
        if level != 'noAuthNoPriv' and auth_pass != d.v3_auth_pass:
            return "snmpget: Authentication failure (incorrect password, community or key)\n===RC 1\n"
        if level == 'authPriv' and priv_pass != d.v3_priv_pass:
            return timeout
        needed = {'noauth': 0, 'auth': 1, 'priv': 2}[done.v3_level]
        if {'noAuthNoPriv': 0, 'authNoPriv': 1, 'authPriv': 2}[level] < needed:
            return "Error in packet\nReason: authorizationError (access denied to that object)\n===RC 2\n"
        return None, False

    def _snmp(self, source, command):
        words = shlex.split(command.split(' 2>&1')[0])
        while '=' in words[0] and not words[0].startswith('snmp'):
            words.pop(0)
        tool, args = words[0], words[1:]
        credentials, i = None, 0
        opts = {}
        rest = []
        while i < len(args):
            a = args[i]
            if a in ('-c', '-u', '-l', '-a', '-A', '-x', '-X', '-m', '-t', '-r'):
                opts[a] = args[i + 1]
                i += 2
            elif a.startswith('-'):
                i += 1
            else:
                rest.append(a)
                i += 1
        host_ip, operands = rest[0], rest[1:]
        host = {v: k for k, v in self.ips.items()}[host_ip]
        if '-c' in opts:
            credentials = ('community', opts['-c'])
        elif '-u' in opts:
            credentials = ('v3', opts['-u'], opts.get('-l', 'authPriv'), opts.get('-A'), opts.get('-X'))
        else:
            # no credential: the defaults of root on nms
            if not (self.done.client and 'HOME=/root' in command):
                return "snmpget: No securityName specified\n===RC 1\n"
            d = self.d
            credentials = ('v3', d.v3_user, 'authPriv', d.v3_auth_pass, d.v3_priv_pass)
        access = self._access(host, source, credentials)
        if isinstance(access, str):
            return access.replace('snmpget:', f'{tool}:')
        subtrees, may_write = access
        objects = self._objects(host)

        def visible(oid):
            return subtrees is None or any(sn.oid_under(oid, s) for s in subtrees)

        if tool == 'snmpset':
            oid, _type, value = operands
            if not may_write:
                return f"Error in packet.\nReason: noAccess\nFailed object: {oid}\n\n===RC 2\n"
            if oid != sn.OID['sysName']:
                return f"Error in packet.\nReason: notWritable (That object does not support modification)\n===RC 2\n"
            self.sysname1 = value
            return _line(oid, 'STRING', value) + "\n===RC 0\n"
        if tool == 'snmpwalk':
            base = operands[0]
            found = sorted((oid for oid in objects if sn.oid_under(oid, base) and visible(oid)),
                           key=lambda x: [int(p) for p in x.strip('.').split('.')])
            if not found:
                return f"{base} = No Such Object available on this agent at this OID\n===RC 0\n"
            return "\n".join(_line(oid, *objects[oid]) for oid in found) + "\n===RC 0\n"
        lines = []
        for oid in operands:
            if oid in objects and visible(oid):
                lines.append(_line(oid, *objects[oid]))
            else:
                lines.append(f"{oid} = No Such Object available on this agent at this OID")
        return "\n".join(lines) + "\n===RC 0\n"

    # -- the trap log of nms ---------------------------------------------------------

    def _trap_tail(self):
        d, done = self.d, self.done
        if not done.trapd:
            return "===LINES \n===TAIL\n===RC 0\n"
        old = [f"2026-11-11 20:00:{i:02d} old line {i}" for i in range(self.log_lines)]
        new = [f"2026-11-11 20:07:36 <UNKNOWN> [UDP: [{self.ips['probe']}]:36553->[{self.ips['nms']}]:162]:",
               "DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1) 0:00:00.01\tSNMPv2-MIB::snmpTrapOID.0 = OID: "
               f"NET-SNMP-MIB::netSnmpPlaypen.0.1\tNET-SNMP-MIB::netSnmpPlaypen.1.1 = STRING: \"sre-{d.probe_token}-ok-{NONCE}\""]
        if done.trap_sink and done.agent:
            new += [f"2026-11-11 20:07:37 srv1.corp.lab [UDP: [{self.ips['srv1']}]:59258->[{self.ips['nms']}]:162]:",
                    "DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1164) 0:00:11.64\tSNMPv2-MIB::snmpTrapOID.0 = OID: "
                    "SNMPv2-MIB::authenticationFailure\tSNMPv2-MIB::snmpTrapEnterprise.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10"]
        lines = old + new
        return f"===LINES {len(lines)}\n===TAIL\n" + "\n".join(lines) + "\n===RC 0\n"

    # -- dispatch ---------------------------------------------------------------------

    def __call__(self, machine, command):
        d, done, lab = self.d, self.done, self.lab
        if command == "ss -ulnpH 2>/dev/null":
            if machine == 'srv1' and done.agent:
                return 'UNCONN 0      0         0.0.0.0:161   0.0.0.0:* users:(("snmpd",pid=741,fd=6))\n', 0
            if machine == 'nms' and done.trapd:
                return 'UNCONN 0      0         0.0.0.0:162   0.0.0.0:* users:(("snmptrapd",pid=718,fd=8))\n', 0
            return "UNCONN 0      0      127.0.0.11:42137 0.0.0.0:*\n", 0
        if command == sn.snmpd_conf_dump_cmd():
            if not done.agent:
                return ("agentaddress 127.0.0.1\nview systemonly included .1.3.6.1.2.1.1\n"
                        "rocommunity public default -V systemonly\n===RC 0\n"), 0
            part = 6 if done.trap_sink else 5 if done.extensions else 3 if done.views else 2
            return self.ns._solution_srv1_conf(part) + "===RC 0\n", 0
        if command == sn.rate_sample_cmd(lab.ROUTER_DMZ_IF, 'tx', lab.RATE_SECONDS):
            octets = d.traffic_kbps * 1000 // 8 * lab.RATE_SECONDS
            packets = octets // d.frame_size()
            return f"===RATE 1000 10 1000000000 {1000 + octets} {10 + packets} 6000000000\n===RC 0\n", 0
        if command == sn.trap_log_lines_cmd():
            return (f"===LINES {self.log_lines}\n===RC 0\n" if done.trapd else "===LINES \n===RC 0\n"), 0
        if command == sn.trap_log_tail_cmd():
            return self._trap_tail(), 0
        if command.startswith("N=$(date +%s%N); "):
            return f"rc_ok=0\n===NONCE {NONCE}\n===RC 0\n", 0
        if command.startswith("grep -rlF -- "):
            if done.v3 and done.v3_clear:
                return "/etc/snmp/snmpd.conf\n===RC 0\n", 0
            return "===RC 1\n", 0
        if re.match(r"^(\S+=\S+ )*snmp(get|walk|set) ", command):
            out = self._snmp(machine, command)
            m = re.search(r"===RC (\d+)", out)
            return out, int(m.group(1)) if m else 0
        return "", 0          # diagnostics


def _simulate(lab, data, tmp_pub_dir, done=None, instructor_mode=False, cheat=True, module=None):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  Every test is registered
    on the first pass and the set never changes (the commands depend on the lab data only)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    lab = module or lab
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    scenario = Scenario(lab, ns, done if done is not None else Done())
    previous, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if previous is None:
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == previous, "the registered tests changed between two passes"
        previous = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = scenario(m, key[0])
        step += 1
    return grade, ns


def _regrade(grade):
    grade.reset_before_grade()
    grade.grade()
    return _by_title(grade)


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


def _by_title(grade):
    return {str(e.title): e for e in grade.get_grade_list()}


def _by_part(grade):
    totals = {}
    for e in grade.get_grade_list():
        key = str(e.grade_part)
        got, maximum = totals.get(key, (0, 0))
        totals[key] = (got + e.grade, maximum + e.max_grade)
    return totals


def _set_answer(grade, field, value):
    for q in grade.get_questions_ordered():
        fields = getattr(q, 'fields', None) or []
        if any(f['name'] == field for f in fields):
            form = json.loads(grade._answers[q.question_hash])
            form[field] = value
            grade._answers[q.question_hash] = json.dumps(form)
            return
    raise AssertionError(f"no form field {field}")


def _all_texts(grade, ns, lang='fr'):
    yield 'informations', _text(ns.informations, lang)
    for q in grade.get_questions_ordered():
        yield f"title:{_text(q.title)}", _text(q.title, lang)
        yield f"description:{_text(q.title)}", _text(q.description, lang)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()
        again = lab.Data.from_json(data.to_json())
        assert again.router_dmz_mac() == data.router_dmz_mac() and again.ro_community == data.ro_community

    def test_values(self, lab, data):
        d = data
        communities = [d.ro_community, d.view_community, d.rw_community, d.trap_community]
        assert len(set(communities)) == 4 and all(re.fullmatch(r'(ro|vw|rw|tr)-[0-9a-f]{8}', c) for c in communities)
        assert 'public' not in communities
        assert re.fullmatch(r'02:53:4e:[0-9a-f:]{8}', d.router_dmz_mac())
        assert len(d.v3_auth_pass) >= 8 and len(d.v3_priv_pass) >= 8 and d.v3_auth_pass != d.v3_priv_pass
        assert d.watched_service in lab.WATCHED_SERVICES and d.extend_name in lab.EXTEND_NAMES
        assert d.app_status_line.startswith(d.extend_name + ' OK ')
        assert d.router_name != 'router' and d.srv1_sysname != 'srv1'
        assert all(text.isascii() for text in (d.router_location, d.srv1_location, d.srv2_location, lab.CONTACT))
        assert len({d.router_location, d.srv1_location, d.srv2_location}) == 3
        assert d.oid_numeric() == sn.normalize_oid(d.oid_numeric()) and '::' in d.oid_name()
        assert d.nets.lan != d.nets.dmz and not d.nets.lan.overlaps(d.nets.dmz)
        assert d.ips.nms in d.nets.lan and d.ips.probe in d.nets.lan and d.ips.router_lan in d.nets.lan
        assert all(getattr(d.ips, m) in d.nets.dmz for m in ('router_dmz', 'srv1', 'srv2', 'outsider'))

    def test_rate_arithmetic(self, lab, data):
        d = data
        assert d.frame_size() == d.traffic_payload + 42
        pps = traffic.cbr_pps(d.traffic_kbps, d.traffic_payload)
        assert pps * d.frame_size() * 8 == pytest.approx(d.traffic_kbps * 1000)
        assert 50 < pps < 320                                    # a rate a Python sender keeps
        assert d.wrap_seconds() == pytest.approx(2 ** 32 * 8 / (d.traffic_kbps * 1000))

    def test_oid_questions(self, lab):
        for name, oid in lab.OID_QUESTIONS:
            assert sn.normalize_oid(oid) == oid and not oid.endswith('.0') and '::' in name
        short = {n.split('::')[1]: o for n, o in lab.OID_QUESTIONS}
        for name in ('ifHCInOctets', 'ifOperStatus'):
            assert sn.OID[name] == short[name]
        for name in ('ipForwarding', 'hrSystemUptime', 'tcpCurrEstab', 'udpInDatagrams', 'snmpInPkts'):
            assert sn.OID[name] == short[name] + '.0'


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'nms', 'router', 'srv1', 'srv2', 'probe', 'outsider'}
        for m in lab.SYSTEMD_MACHINES:
            machine = ns.get_machine(m)
            assert machine.privileged and machine.entrypoint == '/sbin/init' and not machine.hidden
        for m in ('probe', 'outsider'):
            assert ns.get_machine(m).hidden and not ns.get_machine(m).allow_connection
        router = ns.get_machine('router')
        assert not router.allow_connection and not router.hidden and not router.privileged
        assert all(ns.get_machine(m).image == params.sre_docker_image('monitoring') for m in ns.get_machine_names())
        assert {m.name for m in ns.get_visibles_machines()} == {'nms', 'router', 'srv1', 'srv2'}
        assert lab.export_kathara_project is False and lab.shared_path is True

    def test_image_is_written_literally(self):
        # `sre preload-images` reads the file as text
        source = _LAB_PATH.read_text()
        assert source.count('"image": sre_docker_image("monitoring")') >= 3

    def test_networks_and_pinned_mac(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        topology = ns._topology
        assert set(topology) == {'lan', 'dmz'}
        assert set(topology['lan']) == {'router', 'nms', 'probe'}
        assert set(topology['dmz']) == {'router', 'srv1', 'srv2', 'outsider'}
        iface, mac = topology['dmz']['router']
        assert iface == 1 and sn.normalize_mac(str(mac)) == data.router_dmz_mac()
        assert lab.ROUTER_DMZ_IF == f'eth{iface}'
        # every machine reaches the other network through the router
        default = ns.net_config['nms'][0][1][0]
        assert str(default[1]) == str(data.ips.router_lan.ip)
        assert str(ns.net_config['srv1'][0][1][0][1]) == str(data.ips.router_dmz.ip)


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------

class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        d = data
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        for m in ns.get_machine_names():
            files = _files(ops, 1, m)
            assert files['/etc/resolv.conf'] == ''
            hosts = files['/etc/hosts']
            assert f"{d.ips.router_lan.ip}\trouter\t" in hosts and f"{d.ips.srv1.ip}\tsrv1\t" in hosts
            assert str(d.ips.probe.ip) not in hosts and str(d.ips.outsider.ip) not in hosts
        for m in lab.SYSTEMD_MACHINES:
            assert "sysctl -w net.ipv4.ip_forward=0" in _cmds(ops, 1, m)
        assert "sysctl -w net.ipv4.ip_forward=1" in _cmds(ops, 1, 'router')
        # the router's agent: started without systemd, the read community for the lan only
        conf = sn.parse_snmpd_conf(_files(ops, 1, 'router')[sn.SNMPD_CONF])
        assert sn.conf_communities(conf) == [{'community': d.ro_community, 'source': str(d.nets.lan), 'view': None,
                                              'oid': None, 'write': False}]
        assert sn.conf_values(conf, 'sysname') == [[d.router_name]]
        assert sn.conf_values(conf, 'extend') == [[d.router_asset_name, '/bin/echo', d.router_asset_value]]
        assert sn.conf_values(conf, 'agentaddress') == [['udp:161']]
        assert sn.snmpd_start_cmd() in _cmds(ops, 1, 'router')
        assert not any('systemctl' in c for c in _cmds(ops, 1, 'router'))
        # the servers: the Debian file kept, its IPv6 endpoint removed, nothing started
        for m in ('srv1', 'srv2'):
            cmds = _cmds(ops, 1, m)
            assert any('snmpd.conf.dist' in c and "agentaddress 127.0.0.1" in c for c in cmds)
            assert not any('systemctl start' in c or 'systemctl restart' in c for c in cmds)
        script = _files(ops, 1, 'srv1')[lab.APP_SCRIPT]
        assert script == f'#!/bin/sh\necho "{d.app_status_line}"\n'
        # nms: the drop-in of snmptrapd, the daemon not started
        assert sn.SNMPTRAPD_DROPIN in _files(ops, 1, 'nms')
        assert not any('systemctl start' in c or 'systemctl restart' in c for c in _cmds(ops, 1, 'nms'))
        # the constant bit rate: the sink first (step 1), the sender at step 2
        assert traffic.TRAFFIC_GEN_PATH in _files(ops, 1, 'outsider') and traffic.TRAFFIC_GEN_PATH in _files(ops, 1, 'probe')
        import traffic_gen
        sink = [c for c in _cmds(ops, 1, 'outsider') if traffic.TRAFFIC_GEN_PATH in c]
        assert len(sink) == 1 and traffic_gen.decode_spec(sink[0].split()[-1])['listen'][0]['port'] == lab.SINK_PORT
        sender = [c for c in _cmds(ops, 2, 'probe') if traffic.TRAFFIC_GEN_PATH in c]
        job = traffic_gen.decode_spec(sender[0].split()[-1])['jobs'][0]
        assert job['dst'] == str(d.ips.outsider.ip) and job['payload'] == d.traffic_payload
        assert job['pps'] * d.frame_size() * 8 == pytest.approx(d.traffic_kbps * 1000)

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        d = data
        assert set(ops) == {(1, 'srv1'), (1, 'srv2'), (1, 'nms'), (2, 'nms')}
        for (step, m), op_list in ops.items():
            for op in op_list:
                if isinstance(op, str):
                    assert "\n" not in op and "@@@" not in op, (m, op[:60])
        conf = sn.parse_snmpd_conf(_files(ops, 1, 'srv1')[sn.SNMPD_CONF])
        communities = {c['community']: c for c in sn.conf_communities(conf)}
        assert set(communities) == {d.ro_community, d.view_community, d.rw_community}
        assert communities[d.ro_community]['source'] == str(d.nets.lan) and communities[d.ro_community]['view'] is None
        assert communities[d.view_community]['view'] == 'monitoring'
        assert communities[d.rw_community] == {'community': d.rw_community, 'source': str(d.ips.nms.ip), 'view': None,
                                               'oid': None, 'write': True}
        assert sn.conf_values(conf, 'view') == [['monitoring', 'included', sn.OID['system']],
                                                ['monitoring', 'included', sn.OID['interfaces']]]
        assert sn.conf_values(conf, 'extend') == [[d.extend_name, lab.APP_SCRIPT]]
        assert sn.conf_values(conf, 'proc') == [[d.watched_service]]
        assert sn.conf_values(conf, 'disk') == [[lab.DISK_PATH, f'{d.disk_min_percent}%']]
        assert sn.conf_values(conf, 'load') == [[str(d.load1), str(d.load5), str(d.load15)]]
        assert sn.conf_trap_sinks(conf) == [{'kind': 'trap2sink', 'host': str(d.ips.nms.ip), 'port': 162,
                                             'community': d.trap_community}]
        assert sn.conf_values(conf, 'authtrapenable') == [['1']]
        assert 'public' not in _files(ops, 1, 'srv1')[sn.SNMPD_CONF]
        assert any(f"systemctl start {lab.WATCHED_SERVICES[d.watched_service]}" in c for c in _cmds(ops, 1, 'srv1'))
        # srv2: no community, the user created the documented way
        conf2 = sn.parse_snmpd_conf(_files(ops, 1, 'srv2')[sn.SNMPD_CONF])
        assert sn.conf_communities(conf2) == [] and sn.conf_values(conf2, 'rouser') == [[d.v3_user, 'priv']]
        create = [c for c in _cmds(ops, 1, 'srv2') if 'createUser' in c]
        assert len(create) == 1 and f'createUser {d.v3_user} SHA-256 "{d.v3_auth_pass}" AES "{d.v3_priv_pass}"' in create[0]
        assert d.v3_auth_pass not in _files(ops, 1, 'srv2')[sn.SNMPD_CONF]
        # nms
        files = _files(ops, 1, 'nms')
        assert files[sn.SNMPTRAPD_CONF] == f'authCommunity log {d.trap_community}\n'
        assert f'defSecurityName {d.v3_user}\n' in files[sn.SNMP_CLIENT_CONF]
        assert any(c == 'systemctl restart snmptrapd' for c in _cmds(ops, 1, 'nms'))
        setter = _cmds(ops, 2, 'nms')
        assert len(setter) == 1 and f" {sn.OID['sysName']} s {d.srv1_sysname} " in setter[0]

    def test_solution_stages(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        stage2 = sn.parse_snmpd_conf(ns._solution_srv1_conf(2))
        assert [c['community'] for c in sn.conf_communities(stage2)] == [data.ro_community]
        assert sn.conf_values(stage2, 'extend') == [] and sn.conf_trap_sinks(stage2) == []
        stage3 = sn.parse_snmpd_conf(ns._solution_srv1_conf(3))
        assert len(sn.conf_communities(stage3)) == 3 and sn.conf_values(stage3, 'extend') == []
        stage5 = sn.parse_snmpd_conf(ns._solution_srv1_conf(5))
        assert sn.conf_values(stage5, 'extend') and sn.conf_trap_sinks(stage5) == []


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _totals(grade) == (100, 100)
        assert _by_part(grade) == {k: (v, v) for k, v in PARTS.items()}
        assert grade.max_step == 3

    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=nothing(), cheat=False)
        assert _totals(grade) == (0, 100)

    def test_answers_alone(self, lab, data, tmp_pub_dir):
        # the forms filled, nothing configured: the typed answers only
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=nothing())
        parts = _by_part(grade)
        assert parts['part1'] == (14, 14) and parts['part7'] == (12, 12)
        assert parts['part3'] == (3, 14) and parts['part5'] == (1, 12)
        assert parts['part2'] == (0, 16) and parts['part4'] == (0, 18) and parts['part6'] == (0, 14)

    @pytest.mark.parametrize('change, lost', [
        ({'views': False}, {'part3': 11}),
        ({'v3': False, 'client': False}, {'part4': 18}),
        ({'client': False}, {'part4': 2}),
        ({'extensions': False, 'proc_running': False}, {'part5': 11}),
        ({'proc_running': False}, {'part5': 1}),
        ({'trapd': False}, {'part6': 11}),                  # nothing logged: 2 + 4 + 1 + 4
        ({'trap_sink': False}, {'part6': 7}),               # no sink (2), no auth traps (1), none received (4)
        ({'wide_open': True}, {'part2': 3}),                # the read community answers the dmz too
        ({'rw_everywhere': True}, {'part3': 2}),
        ({'v3_level': 'auth'}, {'part4': 3}),               # authNoPriv accepted
        ({'v3_clear': True}, {'part4': 2}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, change, lost):
        done = Done(**change)
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=done)
        parts = _by_part(grade)
        for part, maximum in PARTS.items():
            assert parts[part] == (maximum - lost.get(part, 0), maximum), part

    def test_no_agent_on_srv1(self, lab, data, tmp_pub_dir):
        # parts 3, 5 and 6 need the agent: only what nms does alone remains
        done = Done(agent=False, views=False, extensions=False, proc_running=False, trap_sink=False)
        grade, _ = _simulate(lab, data, tmp_pub_dir, done=done)
        parts = _by_part(grade)
        assert parts['part2'] == (0, 16) and parts['part3'] == (3, 14) and parts['part5'] == (1, 12)
        assert parts['part6'] == (7, 14) and parts['part4'] == (18, 18)

    def test_typed_answers(self, lab, data, tmp_pub_dir):
        d = data
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        # the MAC address and the OIDs in the forms a student types
        _set_answer(grade, 'if_mac', d.router_dmz_mac().upper().replace(':', '-'))
        _set_answer(grade, 'oid_numeric', d.oid_numeric().lstrip('.') + '.0')
        _set_answer(grade, 'sys_location', '  ' + d.router_location.upper() + ' ')
        _set_answer(grade, 'extend_oid', sn.extend_oid('nsExtendOutput1Line', d.extend_name).lstrip('.'))
        elements = _regrade(grade)
        assert all(elements[k].grade == elements[k].max_grade
                   for k in ('answer_if_mac', 'answer_oid_numeric', 'answer_sys_location', 'answer_extend_oid'))
        _set_answer(grade, 'if_mac', '02:53:4e:00:00:00')
        _set_answer(grade, 'if_name', 'eth0')
        _set_answer(grade, 'enterprise', '2021')
        _set_answer(grade, 'set_error', 'noAccess')
        elements = _regrade(grade)
        assert [elements[k].grade for k in ('answer_if_mac', 'answer_if_name', 'answer_enterprise',
                                            'answer_set_error')] == [0, 0, 0, 0]
        assert elements['answer_ro_set_error'].grade == 1

    def test_rate_tolerance(self, lab, data, tmp_pub_dir):
        d = data
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for value, ok in ((d.traffic_kbps * 1.15, True), (d.traffic_kbps * 0.85, True), (d.traffic_kbps * 1.3, False),
                          (d.traffic_kbps * 1000, False), (d.traffic_kbps / 8, False)):
            _set_answer(grade, 'rate_kbps', f"{value:.1f}".replace('.', ','))
            assert (_regrade(grade)['answer_rate'].grade == 5) == ok, value
        _set_answer(grade, 'frame_size', str(d.traffic_payload))            # the payload, not the frame: 42 bytes off
        assert (_regrade(grade)['answer_frame_size'].grade == 3) == (42 <= 0.10 * d.frame_size())
        _set_answer(grade, 'frame_size', str(d.traffic_payload + 28))        # the IP packet: within 10 %
        assert _regrade(grade)['answer_frame_size'].grade == 3
        _set_answer(grade, 'wrap_seconds', str(round(d.wrap_seconds() / 8)))  # bits and bytes mixed up
        assert _regrade(grade)['answer_wrap'].grade == 0
        _set_answer(grade, 'counter_choice', 'c32')
        assert _regrade(grade)['answer_counter_choice'].grade == 0

    def test_typed_answers_are_instructor_scope(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for element in grade.get_grade_list():
            typed = str(element.title).startswith('answer_')
            assert (element.scope == params.EXO_EVAL_SCOPE) == typed, str(element.title)

    def test_cheat_answers_match_the_form_fields(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        cheats = grade.get_cheat_answers('final')
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 4
        for q in forms:
            assert set(json.loads(cheats[q.question_hash])) == {f['name'] for f in q.fields}

    def test_commands_are_single_lines_and_stable(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        tests = grade.get_tests()
        assert {step for _, step in tests} == {1, 2, 3}
        assert {m for m, _ in tests} == {'nms', 'router', 'srv1', 'srv2', 'probe', 'outsider'}
        for (machine, step), cmds in tests.items():
            for command, _timeout in cmds:
                assert "\n" not in command and "@@@" not in command, (machine, command[:60])
        # the trap step: one command, the nonce drawn by the shell of the container
        step2 = [c for c, _ in tests[('probe', 2)]]
        assert len(step2) == 1 and step2[0].startswith('N=$(date +%s%N); ') and f'sre-{data.probe_token}-ok-$N' in step2[0]
        assert f'-c x{data.trap_community}x ' in step2[0] and f'-c sre-wrong-{data.probe_token} ' in step2[0]
        # the line count of the trap log is the first command of nms
        assert next(iter(tests[('nms', 1)]))[0] == sn.trap_log_lines_cmd()
        # refused requests do not retry: the evaluation stays short
        refused = [c for c, _ in tests[('outsider', 1)]]
        assert len(refused) == 1 and ' -r 0 ' in refused[0]


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 8          # the organisation + one per part
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 8 and 'informations' not in with_fragment      # every question has its solution
        student = "\n".join(t for _, t in _all_texts(g0, ns0))
        # what the students need is in the organisation question; the grader's secrets are nowhere
        for value in (data.ro_community, data.view_community, data.rw_community, data.trap_community, data.v3_user,
                      data.v3_auth_pass, data.v3_priv_pass, data.srv1_sysname, data.srv1_location):
            assert value in student
        assert data.probe_token not in student and data.router_asset_value not in student
        assert data.router_dmz_mac() not in student and data.router_name not in student
        assert str(data.traffic_kbps) + ' kbit/s' not in student
        teacher = "\n".join(t for _, t in _all_texts(g1, ns1))
        assert data.router_asset_value in teacher and f"{data.traffic_kbps} kbit/s" in teacher

    def test_texts_are_formatted_and_render(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_][a-z_0-9]*\}(?!\})", re.sub(r"@@\{[^}]*\}@@", "", text)), where
            assert '@@{' not in text or where != 'informations'
            assert '</' not in re.sub(r"```.*?```", "", text, flags=re.S), where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)

    def test_course_is_numbered_and_generic(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        resolved, numbering = resolve_informations(ns1.informations)
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 13)]
        assert [s.number for s in numbering.sections('fr') if s.level == 2] == ['2.1', '2.2', '7.1', '8.1', '8.2']
        informations = _text(resolved)
        assert '@@' not in informations and 'Organisation du TP' not in informations
        # neither the session specifics nor a value of the instance
        for value in (data.ro_community, data.v3_auth_pass, data.srv1_sysname, str(data.ips.srv1.ip), data.router_name):
            assert value not in informations
        assert '## <a id="traps"></a>10. Les notifications : traps et informs' in informations
        assert '(section [10](#traps))' in informations
        # no fenced block inside a list item (it would not render as a block)
        for block in re.finditer(r"^( +)```", _text(ns1.informations), re.M):
            raise AssertionError("indented code fence in the course")
        # the references of the questions resolve to bare section numbers
        for q in g1.get_questions_ordered():
            description = resolve_text(TranslatedText.from_value(q.description, 'fr'), numbering)
            assert '@@ref' not in description.resolve('fr')

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        kinds = {f['name']: f for q in g1.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])}
        assert set(kinds) == {'sys_name', 'sys_location', 'enterprise', 'if_name', 'if_mac', 'oid_numeric',
                              'extend_value', 'set_error', 'ro_set_error', 'extend_oid', 'rate_kbps', 'frame_size',
                              'wrap_seconds', 'counter_choice'}
        assert kinds['set_error']['choices'] == ['noAccess', 'notWritable', 'wrongType', 'authorizationError', 'genErr']
        assert kinds['counter_choice']['choices'] == ['c32', 'hc', 'speed', 'pkts']
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                assert '}' not in m.group(2)

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls == 12 and result.warnings == []
        stripped = tmp_path / 'snmp_stripped.py'
        stripped.write_bytes(result.data)
        assert b'instructor(' not in result.data
        spec = importlib.util.spec_from_file_location('snmp_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True, module=module)
        assert _totals(grade) == (100, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(routeur|serveur|sonde|reseau|communaute|utilisateur|debit|mot|passe|charge|disque)', re.I)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        names = list(lab.NetScheme._machine_specs) + list(ns._topology)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.macs))
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [f['name'] for q in grade.get_questions_ordered() for f in (getattr(q, 'fields', None) or [])]
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
