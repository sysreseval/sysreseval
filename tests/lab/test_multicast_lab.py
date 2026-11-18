"""Offline tests of the multicast lab (lab/sre/_DRAFT_misc/multicast.py).

No Docker and no FRR: a model of the seven sites (``World``) holds what has been configured, as a
set of features (``igmp_r1``, ``querier``, ``msdp_peer``, ``fix3``...), and renders the outputs the
grader reads in the shapes of FRR 9.1.3, iproute2 and the probe (the fixtures of
``tests/mock_data/frr/pim_*``, ``igmp_*``, ``msdp_*``, ``mld_*``, ``tests/mock_data/bridge/`` and
``tests/mock_data/mcast/`` were captured in the lab).  The streams follow from the features as
they did live (PIM-SM needs PIM, the RP on the three routers and IGMP; the snooping bridge floods
until it has a querier; the boundary stops the scoped group...).  Covers the data, the topology,
the state ops, the two-pass grading contract (nothing done: 0; everything: 100 + 6 bonus points;
**each part alone gives exactly its points and everything but one part the rest**; variants) and
the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Address, IPv4Network, IPv6Address, ip_address
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import mcast_probe  # noqa: E402
from mcast import MCAST_PROBE_PATH, group_mac, mac_aliases  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'multicast.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'addressing': set(),
    'igmp': {'igmp_r1', 'igmp_qi', 'h2_v2'},
    'snooping': {'snooping', 'querier', 'snoop_v3', 'fastleave'},
    'asm': {'asm_pim', 'asm_rp_r1', 'asm_rp_r2', 'asm_rp_r3', 'asm_igmp'},
    'ssm': {'ssm_pim', 'ssm_igmp_v3', 'ssm_range'},
    'msdp': {'msdp_peer', 'boundary'},
    'fix': {'fix1', 'fix2', 'fix3', 'fix4'},
    'ipv6': {'v6_pim', 'v6_mld'},
}
POINTS = {'addressing': 10, 'igmp': 14, 'snooping': 14, 'asm': 22, 'ssm': 12, 'msdp': 14, 'fix': 14, 'ipv6': 6}
SOLVE_STATE = {'addressing': 'solve_addressing', 'igmp': 'solve_igmp', 'snooping': 'solve_snooping', 'asm': 'solve_asm',
               'ssm': 'solve_ssm', 'msdp': 'solve_msdp', 'fix': 'solve_fix', 'ipv6': 'solve_v6'}
ALL_FEATURES = set().union(*PARTS.values())
# the elements that grade the answers of the forms
FORM_ELEMENTS = {
    'addressing_mac', 'addressing_alias', 'addressing_scope_a', 'addressing_scope_b', 'addressing_scope_c',
    'addressing_solicited_node', 'addressing_solicited_node_mac', 'igmp_report_v3_destination',
    'igmp_leave_v2_destination', 'igmp_ttl', 'igmp_querier_before', 'igmp_election_rule', 'igmp_ip_option',
    'asm_rpf_interface', 'asm_register', 'asm_register_stop',
}
CHOICE_ELEMENTS = {'addressing_scope_a', 'addressing_scope_b', 'addressing_scope_c', 'igmp_querier_before',
                   'igmp_election_rule', 'igmp_ip_option', 'asm_register', 'asm_register_stop'}


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('multicast_lab_under_test', _LAB_PATH)
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


def _vtysh_commands(command):
    """The configuration lines of a `vtysh -c "configure terminal" -c ... -c "end" -c "write"`."""
    lines = re.findall(r'-c "([^"]*)"', command)
    assert lines[0] == 'configure terminal' and lines[-2:] == ['end', 'write'], command
    return lines[1:-2]


# ---------------------------------------------------------------------------
# a model of the sites: features -> what the grader reads
# ---------------------------------------------------------------------------


class World:
    def __init__(self, lab, ns, features, dead=()):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.f = set(features)
        self.dead = set(dead)                      # hosts whose probe did not run

    # -- streams ---------------------------------------------------------------

    def received(self, host, tag):
        """{group: (count, source)} of what the probe *tag* of *host* got."""
        f, d = self.f, self.d
        snoop_src = str(d.ips.snoop_src.ip)
        if host == 'snoop_h1':
            return {d.g_snoop: (20, snoop_src)}                       # the bridge forwards in every case
        if host == 'snoop_h2':
            return {} if {'snooping', 'querier'} <= f else {d.g_snoop: (20, snoop_src)}
        if host == 'asm_h' and {'asm_pim', 'asm_rp_r1', 'asm_rp_r2', 'asm_rp_r3', 'asm_igmp'} <= f:
            return {d.g_asm: (19, str(d.ips.asm_src.ip))}
        if host == 'ssm_h' and {'ssm_pim', 'ssm_igmp_v3'} <= f:
            return {d.g_ssm: (20, str(d.ips.ssm_src.ip))}
        if host == 'msdp_h' and 'msdp_peer' in f:
            got = {d.g_msdp: (18, str(d.ips.msdp_src.ip))}
            if 'boundary' not in f:
                got[d.g_scoped] = (18, str(d.ips.msdp_src.ip))
            return got
        if host == 'fix_h' and {'fix1', 'fix2', 'fix3', 'fix4'} <= f:
            return {d.g_fix: (19, str(d.ips.fix_src.ip))}
        if host == 'v6_h' and {'v6_pim', 'v6_mld'} <= f:
            return {d.g_v6: (20, str(d.ips6.v6_src.ip))}
        return {}

    def dump(self, host, tag):
        if host in self.dead:
            return {'kind': None, 'uptime': None, 'heartbeat_age': None, 'done': False, 'joins': [], 'watched': [],
                    'igmp': {}, 'groups': {}, 'errors': ["FileNotFoundError: no state"]}
        groups = {}
        for group, (count, source) in self.received(host, tag).items():
            groups[str(group)] = {'count': count, 'sources': {source: count}, 'tokens': {self.d.token: count},
                                  'ttl_min': 14, 'ttl_max': 14, 'first_age': 9.0, 'last_age': 1.5}
        kind = 'sniff' if tag in ('grade_ssm_sniff',) or host == 'snoop_h2' else 'recv'
        return {'kind': kind, 'uptime': 12.0, 'heartbeat_age': 0.5, 'done': False, 'joins': [], 'watched': [],
                'igmp': {'report_v3': 2} if kind == 'sniff' else {}, 'groups': groups, 'errors': []}

    # -- vtysh -------------------------------------------------------------------

    @staticmethod
    def _iface(name, address, **extra):
        return {'name': name, 'state': 'up', 'address': str(address), 'index': 2, 'flagMulticast': True,
                'flagBroadcast': True, 'lanDelayEnabled': True, **extra}

    def _igmp_iface(self, name, address, version=3, querier='local', query_interval=125):
        return self._iface(name, address, upTime='00:01:00', querier=querier, querierIp=str(address), version=version,
                           timerQueryInterval=query_interval, timerQueryResponseIntervalMsec=10000,
                           timerLastMemberQueryMsec=2000, lastMemberQueryCount=2, timerRobustnessVariable=2)

    def _pim_iface(self, name, address, neighbors=0):
        return self._iface(name, address, pimNeighbors=neighbors, pimDesignatedRouter=str(address),
                           pimDesignatedRouterLocal=True)

    @staticmethod
    def _neighbor(name, address):
        return {str(address): {'interface': name, 'neighbor': str(address), 'upTime': '00:01:00',
                               'holdTime': '00:01:30', 'holdTimeMax': 105, 'drPriority': 1}}

    @staticmethod
    def _rp(rp, iface, i_am_rp, group='239.0.0.0/8'):
        return {str(rp): [{'rpAddress': str(rp), 'outboundInterface': iface, 'iAmRP': i_am_rp, 'group': group,
                           'source': 'Static', 'groupType': 'ASM'}]}

    def vtysh(self, machine, command):
        f, d, a, lo, lab = self.f, self.d, self.ns.addr, self.ns.lo, self.lab
        if command == 'show ip igmp interface detail':
            if machine == 'igmp_r1' and 'igmp_r1' in f:
                interval = d.query_interval if 'igmp_qi' in f else 125
                return {'eth0': self._igmp_iface('eth0', a('igmp_r1', 'igmp_lan'), query_interval=interval)}
            if machine == 'asm_r3':
                result = {}
                if 'asm_pim' in f:
                    for n, net in enumerate(('asm_l23', 'asm_l13')):
                        result[f'eth{n}'] = dict(self._igmp_iface(f'eth{n}', a('asm_r3', net), querier='other'),
                                                 mtraceOnly=True)
                if 'asm_igmp' in f:
                    result['eth2'] = self._igmp_iface('eth2', a('asm_r3', 'asm_rx_lan'))
                return result
            if machine == 'ssm_r2' and ({'ssm_igmp_v3', 'ssm_igmp_v2'} & f):
                version = 3 if 'ssm_igmp_v3' in f else 2
                return {'eth1': self._igmp_iface('eth1', a('ssm_r2', 'ssm_rx_lan'), version=version)}
            return {}
        if command == 'show ip pim interface':
            nets = {'asm_r1': ('asm_pim', ['asm_src_lan', 'asm_l12', 'asm_l13']),
                    'ssm_r1': ('ssm_pim', ['ssm_src_lan', 'ssm_link'])}
            if machine in nets:
                feature, names = nets[machine]
                if feature not in f:
                    return {}
                return {f'eth{n}': self._pim_iface(f'eth{n}', a(machine, net)) for n, net in enumerate(names)}
            if machine == 'fix_r1':
                result = {'eth1': self._pim_iface('eth1', a('fix_r1', 'fix_la'), 1 if 'fix2' in f else 0),
                          'lo': self._pim_iface('lo', lo('fix_r1'))}
                if 'fix1' in f:
                    result['eth0'] = self._pim_iface('eth0', a('fix_r1', 'fix_src_lan'))
                return result
            return {}
        if command == 'show ip pim neighbor':
            if machine == 'asm_r2':
                return ({'eth0': self._neighbor('eth0', a('asm_r1', 'asm_l12')),
                         'eth1': self._neighbor('eth1', a('asm_r3', 'asm_l23'))} if 'asm_pim' in f else {})
            if machine == 'asm_r3':
                return ({'eth0': self._neighbor('eth0', a('asm_r2', 'asm_l23')),
                         'eth1': self._neighbor('eth1', a('asm_r1', 'asm_l13')), 'eth2': {}} if 'asm_pim' in f else {})
            if machine == 'ssm_r2':
                return {'eth0': self._neighbor('eth0', a('ssm_r1', 'ssm_link'))} if 'ssm_pim' in f else {}
            if machine == 'fix_r1':
                return {'eth1': self._neighbor('eth1', a('fix_r2', 'fix_la')) if 'fix2' in f else {}, 'lo': {}}
            if machine == 'fix_r2':
                # fix_r1 sends its Hellos on fix_la from the start (its filter only drops what it receives)
                return {'eth0': self._neighbor('eth0', a('fix_r1', 'fix_la')), 'eth2': {}}
            return {}
        if command == 'show ip pim rp-info':
            if machine in ('asm_r1', 'asm_r2', 'asm_r3'):
                if f'asm_rp_{machine[-2:]}' not in f:
                    return {}
                iface = {'asm_r1': 'eth1', 'asm_r2': 'lo', 'asm_r3': 'eth0'}[machine]
                return self._rp(lo('asm_r2'), iface, machine == 'asm_r2')
            if machine == 'fix_r2':
                return self._rp(lo('fix_r1') if 'fix3' in f else a('fix_r1', 'fix_la'), 'eth0', False)
            return {}
        m = re.fullmatch(r'show ip pim group-type (\S+)', command)
        if m:
            group = ip_address(m.group(1))
            ssm = group in lab.SSM_DEFAULT or ('ssm_range' in f and group in lab.SSM_EXTRA)
            return {'groupType': 'SSM' if ssm else 'ASM'}
        if command == 'show ip msdp peer':
            if 'msdp_peer' not in f:
                return {}
            local, peer = (lo('msdp_r1'), lo('msdp_r2')) if machine == 'msdp_r1' else (lo('msdp_r2'), lo('msdp_r1'))
            return {str(peer): {'peer': str(peer), 'local': str(local), 'state': 'established', 'upTime': '00:01:00',
                                'saCount': 2}}
        if command == 'show ip msdp sa':
            if machine != 'msdp_r2' or 'msdp_peer' not in f:
                return {}
            src = str(d.ips.msdp_src.ip)
            return {str(g): {src: {'source': src, 'group': str(g), 'rp': str(lo('msdp_r1')), 'local': 'no',
                                   'sptSetup': 'yes', 'upTime': '00:00:10'}} for g in (d.g_msdp, d.g_scoped)}
        if command == 'show ip igmp groups':
            if machine != 'igmp_r1' or 'igmp_r1' not in f:
                return {'totalGroups': 0, 'watermarkLimit': 0}
            groups = [{'group': str(d.g_igmp1), 'mode': 'EXCLUDE', 'timer': '00:01:20', 'sourcesCount': 1, 'version': 3,
                       'uptime': '00:00:10'},
                      {'group': str(d.g_igmp2), 'timer': '00:01:20', 'sourcesCount': 1,
                       'version': 2 if 'h2_v2' in f else 3, 'uptime': '00:00:10'}]
            return {'totalGroups': 2, 'watermarkLimit': 0,
                    'eth0': dict(self._iface('eth0', a('igmp_r1', 'igmp_lan')), groups=groups)}
        if command == 'show ip mroute':
            if machine != 'asm_r3' or not self.received('asm_h', 'grade_asm'):
                return {}
            src, group = str(d.ips.asm_src.ip), str(d.g_asm)
            return {group: {'*': {'source': '*', 'group': group, 'installed': 1, 'iif': 'eth0', 'flags': 'SC',
                                  'oil': {'pimreg': {}, 'eth2': {}}},
                            src: {'source': src, 'group': group, 'installed': 1, 'iif': 'eth1', 'flags': 'S',
                                  'oil': {'eth2': {}}}}}
        if command == 'show ipv6 pim neighbor':
            return {'eth0': self._neighbor('eth0', 'fe80::9045:f2ff:feb4:161a')} if 'v6_pim' in f else {}
        if command == 'show ipv6 mld interface':
            if 'v6_mld' not in f:
                return {}
            return {'default': {'eth1': {'name': 'eth1', 'address': 'fe80::1', 'state': 'up', 'version': '2',
                                         'querier': True, 'querierIp': 'fe80::1', 'timerQueryIntervalMsec': 125000}}}
        if command == 'show ipv6 mld groups':
            if 'v6_mld' not in f:
                return {'totalGroups': 0, 'watermarkLimit': 0}
            # the receiver of v6_h joins whatever PIM does
            groups = [{'group': 'ff02::16', 'version': 2}, {'group': str(d.g_v6), 'version': 2, 'uptime': '00:00:05'}]
            return {'totalGroups': len(groups), 'watermarkLimit': 0,
                    'eth1': dict(self._iface('eth1', 'fe80::1'), groups=groups)}
        raise AssertionError(f"unexpected vtysh command on {machine}: {command}")

    # -- other commands ------------------------------------------------------------

    def links(self):
        f = self.f
        bridge = {'ifindex': 2, 'ifname': 'br0', 'flags': ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'],
                  'address': '62:a8:14:ae:0b:08',
                  'linkinfo': {'info_kind': 'bridge', 'info_data': {
                      'mcast_snooping': int('snooping' in f), 'mcast_querier': int('querier' in f),
                      'mcast_igmp_version': 3 if 'snoop_v3' in f else 2, 'mcast_query_use_ifaddr': int('querier' in f),
                      'mcast_query_intvl': 12500, 'mcast_membership_intvl': 26000}}}
        ports = [{'ifindex': 10 + n, 'ifname': f'eth{n}', 'master': 'br0', 'flags': ['UP'],
                  'linkinfo': {'info_kind': 'tun', 'info_slave_kind': 'bridge', 'info_slave_data': {
                      'fastleave': 'fastleave' in f and n > 0, 'multicast_router': 1, 'mcast_flood': True}}}
                 for n in range(3)]
        return [{'ifindex': 1, 'ifname': 'lo', 'flags': ['LOOPBACK', 'UP']}, bridge] + ports

    def mdb(self):
        entries = []
        if 'snooping' in self.f:
            entries.append({'index': 2, 'dev': 'br0', 'port': 'eth1', 'grp': str(self.d.g_snoop), 'state': 'temp',
                            'filter_mode': 'exclude', 'protocol': 'kernel', 'flags': []})
        return [{'mdb': entries, 'router': {}}]

    def msdp_r1_config(self):
        lab = self.lab
        lines = ["Building configuration...", "", "Current configuration:", "!", "hostname msdp_r1", "!",
                 "interface eth1", " ip pim"]
        if 'boundary' in self.f:
            lines.append(f" ip multicast boundary oil {lab.SCOPE_PLIST}")
        lines += ["exit", "!"]
        if 'boundary' in self.f:
            lines += [f"ip prefix-list {lab.SCOPE_PLIST} seq 5 deny {lab.SCOPED_RANGE} le 32",
                      f"ip prefix-list {lab.SCOPE_PLIST} seq 10 permit 224.0.0.0/4 le 32", "!"]
        return "\n".join(lines + ["end"]) + "\n"

    def output(self, machine, command):
        if command == 'vtysh -c "show running-config"':
            return (self.msdp_r1_config() if machine == 'msdp_r1' else 'Building configuration...\n'), 0
        if command.startswith(f"python3 {MCAST_PROBE_PATH} "):
            words = command.split()
            mode = words[2]
            if mode in ('recv', 'sniff'):
                mcast_probe._spec(words[3])                # a valid spec
                return '', 0
            if mode == 'send':
                spec = mcast_probe._spec(words[3])
                return ('' if spec.get('background') else json.dumps({'sent': spec['count'], 'errors': []})), 0
            if mode == 'dump':
                return json.dumps({tag: self.dump(machine, tag) for tag in words[3:]}), 0
        m = re.fullmatch(r'vtysh -c "(.*) json"', command)
        if m:
            return json.dumps(self.vtysh(machine, m.group(1)), indent=2) + "\n", 0
        m = re.fullmatch(r'cat /proc/sys/net/ipv4/conf/(\w+)/force_igmp_version', command)
        if m and machine == 'igmp_h2':
            return ('2' if 'h2_v2' in self.f and m.group(1) == 'eth0' else '0') + "\n", 0
        if command == 'ip -j -d link show' and machine == self.lab.SWITCH:
            return json.dumps(self.links()), 0
        if command == f'bridge -j -d mdb show dev {self.lab.BRIDGE}' and machine == self.lab.SWITCH:
            return json.dumps(self.mdb()), 0
        m = re.fullmatch(r'ip -j route get (\S+)', command)
        if m and machine == 'fix_r2':
            via = self.ns.addr('fix_r1', 'fix_la' if 'fix4' in self.f else 'fix_lb')
            dev = 'eth0' if 'fix4' in self.f else 'eth1'
            return json.dumps([{'dst': m.group(1), 'gateway': str(via), 'dev': dev, 'flags': []}]), 0
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES, answers='final', instructor_mode=False, dead=()):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  *answers*: the state whose
    cheat answers fill the forms (None: no answer)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    model = World(lab, ns, features, dead=dead)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            grade._answers = dict(grade.get_cheat_answers(answers) or {}) if answers else {}
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = model.output(m, key[0])
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    """(regular points, bonus points)."""
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _lost(grade):
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _parts(grade):
    """{part key: points earned}."""
    result = {str(p.title): 0 for p in grade.get_grade_parts()}
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return result


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    def test_groups(self, lab):
        for d in [lab.Data.generate() for _ in range(40)]:
            plain = IPv4Network('239.0.0.0/9')
            for name in ('igmp_group', 'snoop_group', 'asm_group', 'msdp_group', 'fix_group', 'g_igmp1', 'g_igmp2',
                         'g_snoop', 'g_asm', 'g_msdp', 'g_fix'):
                group = getattr(d, name)
                assert group in plain and group in lab.RP_RANGE and group not in lab.SCOPED_RANGE, name
            assert d.ssm_group in lab.SSM_DEFAULT and d.g_ssm in lab.SSM_DEFAULT and d.g_ssm_extra in lab.SSM_EXTRA
            assert d.scoped_group in lab.SCOPED_RANGE and d.g_scoped in lab.SCOPED_RANGE
            assert d.v6_group in lab.V6_SSM_RANGE and d.g_v6 in lab.V6_SSM_RANGE and d.v6_group != d.g_v6
            groups = [getattr(d, f.name) for f in d.__dataclass_fields__.values()
                      if isinstance(getattr(d, f.name), IPv4Address)]
            assert len(groups) == len(set(groups))
            # part 1: the mapping drops the high bit of the second octet, and the question has an alias
            assert d.mac_group in IPv4Network('239.128.0.0/10') and len(mac_aliases(d.mac_group)) == 32
            classes = (d.scope_a_class, d.scope_b_class, d.scope_c_class)
            assert len(set(classes)) == 3 and set(classes) <= set(lab.SCOPE_CLASSES)
            from mcast import multicast_scope
            for address, cls in zip((d.scope_a, d.scope_b, d.scope_c), classes):
                assert multicast_scope(address) == cls
            assert d.query_interval in lab.IGMP_QUERY_INTERVALS
            assert 20000 <= d.grade_port <= 29999 and d.token.isalnum()

    def test_addressing(self, lab):
        for d in [lab.Data.generate() for _ in range(40)]:
            site = d.nets.site
            assert site.prefixlen == 16 and site.subnet_of(IPv4Network('10.0.0.0/8')) and site != IPv4Network('10.0.0.0/16')
            for net, (octet, prefix) in lab.NET_PLAN.items():
                network = getattr(d.nets, net)
                assert network.subnet_of(site) and network.prefixlen == prefix
                assert int(str(network.network_address).split('.')[2]) == octet
            for router, nets in lab.ROUTER_IFACES.items():
                for net in nets:
                    if router in lab.V6_MACHINES:
                        assert getattr(d.ips6, f"{router}_{net}").ip in getattr(d.nets6, net)
                    else:
                        assert getattr(d.ips, f"{router}_{net}").ip in getattr(d.nets, net)
            for router in lab.LOOPBACKS:
                assert getattr(d.ips, f"{router}_lo").network.prefixlen == 32
            # igmp_r1 wins the querier election
            assert int(d.ips.igmp_r1_igmp_lan.ip) < int(d.ips.igmp_r2_igmp_lan.ip)
            assert d.ips.ssm_src2.ip in d.nets.ssm_src_lan and d.ips.snoop_sw.ip in d.nets.snoop_lan
            addresses = [ip.ip for ip in vars(d.ips).values()]
            assert len(addresses) == len(set(addresses))


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        machines = set(ns.get_machine_names())
        assert len(machines) == 29 and machines == set(lab.ROUTER_IFACES) | set(lab.HOSTS) | {lab.SWITCH}
        for machine, spec in lab.NetScheme._machine_specs.items():
            assert spec['image'].startswith('sysreseval/routing-frr:')
            assert spec.get('ipv6') is (True if machine in lab.V6_MACHINES else None)
            assert not spec.get('hidden')

    def test_interfaces_follow_the_tables(self, lab):
        for router, nets in lab.ROUTER_IFACES.items():
            for n, net in enumerate(nets):
                assert lab._TOPOLOGY[net][router] == n and lab.iface(router, net) == f"eth{n}"
        for host, (net, _gw) in lab.HOSTS.items():
            if net != 'snoop_lan':
                assert lab._TOPOLOGY[net][host] == 0
        for port, host in lab.SWITCH_PORTS.items():
            network = next(name for name, members in lab._TOPOLOGY.items() if host in members)
            assert lab._TOPOLOGY[network] == {lab.SWITCH: int(port[3:]), host: 0}
        # every machine of a site is only connected to machines of its site
        for network, members in lab._TOPOLOGY.items():
            assert len({lab.site_of(m) for m in members}) == 1, network

    def test_net_config(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config[lab.SWITCH] == [([], [])] * 3
        assert ns.net_config['ssm_src'][0][0] == [data.ips.ssm_src, data.ips.ssm_src2]
        assert ns.net_config['igmp_h1'] == [([data.ips.igmp_h1], [])]
        assert ns.net_config['asm_h'] == [([data.ips.asm_h], [(IPv4Network('0.0.0.0/0'), data.ips.asm_r3_asm_rx_lan.ip)])]
        assert ns.net_config['v6_h'][0][0] == [data.ips6.v6_h]
        assert ns.net_config['v6_r1'][1] == ([data.ips6.v6_r1_v6_link], [])


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        for router in lab.ROUTER_IFACES:
            files = _files(ops, 1, router)
            daemons = files['/etc/frr/daemons']
            assert 'pimd=yes' in daemons and 'staticd' in daemons
            assert ('pim6d=yes' in daemons) is (router in lab.V6_MACHINES)
            assert 'systemctl start frr' in _cmds(ops, 2, router)
        for host in lab.HOSTS:
            assert MCAST_PROBE_PATH in _files(ops, 1, host)
            routed = lab.HOSTS[host][1] is not None
            assert (f"ip route add {lab.MCAST_ROUTE} dev eth0" in _cmds(ops, 1, host)) is (not routed)
        switch = _cmds(ops, 1, lab.SWITCH)
        assert 'ip link add br0 type bridge mcast_snooping 0' in switch and 'ip link set br0 up' in switch
        assert f"ip addr add {data.ips.snoop_sw} dev br0" in switch

    def test_given_configurations_and_faults(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        conf = {r: _files(ops, 1, r)['/etc/frr/frr.conf'] for r in lab.ROUTER_IFACES}
        assert 'interface eth0\n ip igmp\n' in conf['igmp_r2'] and 'ip igmp' not in conf['igmp_r1']
        for r in ('msdp_r1', 'msdp_r2'):
            assert f"ip pim rp {ns.lo(r)} 224.0.0.0/4" in conf[r] and 'ip msdp' not in conf[r]
        assert 'interface msdp' not in conf['msdp_r1']
        # the four faults of the fix site
        assert 'interface eth0' not in conf['fix_r1'] and 'interface eth2' not in conf['fix_r1']
        assert f"ip pim rp {ns.addr('fix_r1', 'fix_la')} 239.0.0.0/8" in conf['fix_r2']
        assert f"ip route {ns.lo('fix_r1')}/32 {ns.addr('fix_r1', 'fix_lb')}" in conf['fix_r2']
        nft = _files(ops, 1, 'fix_r1')[lab.FIX_NFT_FILE]
        assert 'pim' in nft and nft.startswith('#!/usr/sbin/nft -f\nflush ruleset')
        # nothing multicast elsewhere
        for r in ('igmp_r1', 'asm_r1', 'asm_r2', 'asm_r3', 'ssm_r1', 'ssm_r2', 'v6_r1', 'v6_r2'):
            assert 'pim' not in conf[r] and 'igmp' not in conf[r] and 'mld' not in conf[r], r
        assert f"ip route {ns.lo('asm_r2')}/32 {ns.addr('asm_r2', 'asm_l23')}" in conf['asm_r3']
        assert f"ip route {data.nets.asm_src_lan} {ns.addr('asm_r1', 'asm_l13')}" in conf['asm_r3']
        assert f"ipv6 route {data.nets6.v6_src_lan} {ns.addr('v6_r1', 'v6_link')}" in conf['v6_r2']

    def test_solutions_are_vtysh_sessions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        lines = {}
        for (step, machine), op_list in final.items():
            for op in op_list:
                if isinstance(op, str) and op.startswith('vtysh -c "configure terminal"'):
                    lines.setdefault(machine, []).extend(_vtysh_commands(op))
        assert f"ip igmp query-interval {data.query_interval}" in lines['igmp_r1']
        assert f"ip pim rp {ns.lo('asm_r2')} 239.0.0.0/8" in lines['asm_r3'] and 'ip igmp' in lines['asm_r3']
        assert f"ip msdp peer {ns.lo('msdp_r2')} source {ns.lo('msdp_r1')}" in lines['msdp_r1']
        assert f"ip multicast boundary oil {lab.SCOPE_PLIST}" in lines['msdp_r1']
        assert f"ip pim ssm prefix-list {lab.SSM_PLIST}" in lines['ssm_r2'] and 'ipv6 mld' in lines['v6_r2']
        assert f"ip route {ns.lo('fix_r1')}/32 {ns.addr('fix_r1', 'fix_la')}" in lines['fix_r2']
        commands = [str(op) for ops in final.values() for op in ops if isinstance(op, str)]
        assert 'sysctl -w net.ipv4.conf.eth0.force_igmp_version=2' in commands
        assert 'bridge link set dev eth1 fastleave on' in commands
        assert not any('clear ip pim' in c for c in commands)
        assert any(c.startswith('sleep 3') for c in _cmds(final, 2, 'msdp_r1'))

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())

        def configuration(state):
            return sorted(str(op) for (step, _m), ops in _state_ops(ns, state).items() if step == 1 for op in ops
                          if isinstance(op, str) and op != 'true')
        parts = sorted(c for state in SOLVE_STATE.values() for c in configuration(state))
        assert configuration('final') == parts
        states = [n for n in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, n), '_is_sre_state', False)]
        assert set(states) >= set(SOLVE_STATE.values()) | {'initial', 'final'}


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 100
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 61 and len({str(e.title) for e in elements}) == 61

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (100, 6)
        assert _parts(grade) == POINTS

    @pytest.mark.parametrize('part', list(PARTS))
    def test_a_part_alone(self, lab, data, tmp_pub_dir, part):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=PARTS[part], answers=SOLVE_STATE[part])
        assert _parts(grade) == {key: (POINTS[key] if key == part else 0) for key in POINTS}

    @pytest.mark.parametrize('part', list(PARTS))
    def test_everything_but_a_part(self, lab, data, tmp_pub_dir, part):
        features = ALL_FEATURES - PARTS[part]
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=features, answers='final')
        # the answers of the forms stay: the part keeps the points of its forms
        forms = sum(m for t, (_g, m) in _grades(grade).items() if t in FORM_ELEMENTS and t.split('_')[0] == part)
        assert _parts(grade) == {key: (forms if key == part else POINTS[key]) for key in POINTS}
        assert forms == {'addressing': 10, 'igmp': 3, 'asm': 3}.get(part, 0)

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(10):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (100, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == ['v6_neighbor', 'v6_mld', 'v6_mld_group',
                                                                              'v6_stream']
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _totals(answers_only) == (sum(m for t, (_g, m) in _grades(answers_only).items() if t in FORM_ELEMENTS), 0)
        assert _totals(answers_only)[0] == 10 + 3 + 3

    def test_wrong_answers(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(grade) == FORM_ELEMENTS
        assert _totals(grade) == (84, 6)

    def test_other_alias_and_mac_spellings(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        form = next(q for q in grade.get_questions_ordered() if 'adresses multicast' in _text(q.title))
        cheat = dict(grade.get_cheat_answers('final'))
        stored = cheat[form.question_hash]
        answers = dict(json.loads(stored) if isinstance(stored, str) else stored)
        aliases = [str(a) for a in mac_aliases(data.mac_group) if a != data.mac_group]
        answers['mac'] = group_mac(data.mac_group).upper().replace(':', '-')
        for alias, ok in ((aliases[-1], True), (str(data.mac_group), False), ('10.1.2.3', False), ('garbage', False)):
            changed = dict(answers, alias=alias)
            cheat[form.question_hash] = json.dumps(changed) if isinstance(stored, str) else changed
            graded, _ = _simulate_with_answers(lab, data, tmp_pub_dir, cheat)
            assert _grades(graded)['addressing_alias'][0] == (2 if ok else 0), alias
            assert _grades(graded)['addressing_mac'][0] == 2

    def test_snooping_without_querier_still_floods(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'querier'})
        assert _lost(grade) == {'snooping_querier', 'snooping_no_flood'}

    def test_snooping_off_gives_nothing_for_the_stream(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'snooping'})
        assert _lost(grade) == {'snooping_enabled', 'snooping_mdb', 'snooping_member_receives', 'snooping_no_flood'}

    def test_dead_sniffer_never_proves_an_absence(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, dead={'snoop_h2'})
        assert _lost(grade) == {'snooping_no_flood'}
        grade, _ = _simulate(lab, data, tmp_pub_dir, dead={'ssm_h'})
        assert _lost(grade) == {'ssm_stream', 'ssm_source_filter'}

    def test_rp_missing_on_one_router(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'asm_rp_r1'})
        assert _lost(grade) == {'asm_rp_r1', 'asm_stream', 'asm_spt'}

    def test_ssm_with_igmp_v2(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=(ALL_FEATURES - {'ssm_igmp_v3'}) | {'ssm_igmp_v2'})
        assert _lost(grade) == {'ssm_igmp_v3', 'ssm_stream', 'ssm_source_filter'}

    def test_ssm_range_not_extended(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'ssm_range'})
        assert _lost(grade) == {'ssm_range_r1', 'ssm_range_r2'}

    def test_msdp_without_boundary(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'boundary'})
        assert _lost(grade) == {'msdp_boundary_config', 'msdp_boundary_blocks'}

    @pytest.mark.parametrize('fault, element', [('fix1', 'fix_source_lan'), ('fix2', 'fix_pim_filter'),
                                                ('fix3', 'fix_rp_address'), ('fix4', 'fix_rpf_to_rp')])
    def test_one_fault_left(self, lab, data, tmp_pub_dir, fault, element):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {fault})
        assert _lost(grade) == {'fix_stream', element}

    def test_igmp_h2_still_v3(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'h2_v2'})
        assert _lost(grade) == {'igmp_h2_v2', 'igmp_group_v2'}

    def test_default_query_interval(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {'igmp_qi'})
        assert _lost(grade) == {'igmp_query_interval'}

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 4
        for state in ['final'] + list(SOLVE_STATE.values()):
            cheat = grade.get_cheat_answers(state) or {}
            for q in forms:
                if q.question_hash not in cheat:
                    continue
                answers = cheat[q.question_hash]
                answers = json.loads(answers) if isinstance(answers, str) else answers
                assert set(answers) == {field['name'] for field in q.fields}
                for field in q.fields:
                    if 'choices' in field:
                        assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
                    elif 'regex' in field:
                        assert re.fullmatch(field['regex'], answers[field['name']]), field['name']
        assert len(grade.get_cheat_answers('final')) == 4


def _simulate_with_answers(lab, data, tmp_pub_dir, cheat):
    """_simulate() with the answers *cheat* (``{question hash: answers}``)."""
    original = lab.Grade.get_cheat_answers
    try:
        lab.Grade.get_cheat_answers = lambda self, state: cheat
        return _simulate(lab, data, tmp_pub_dir)
    finally:
        lab.Grade.get_cheat_answers = original


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------


def _all_texts(grade, ns):
    texts = [('informations', _text(ns.informations))]
    for q in grade.get_questions_ordered():
        texts.append((_text(q.title), _text(q.description)))
    for e in grade.get_grade_list():
        texts.append((str(e.title), _text(e.description) if e.description else ''))
    return texts


class TestTexts:
    def test_hashes_and_fragments(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        assert [q.question_hash for q in g0.get_questions_ordered()] == [q.question_hash for q in g1.get_questions_ordered()]
        assert len(g1.get_questions_ordered()) == 12
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 11 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            assert '@@{' not in text or where != 'informations'
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'principle', 'addressing', 'host', 'igmp', 'snooping', 'routing', 'pimsm', 'ssm', 'msdp', 'ipv6', 'frr',
            'tools', 'diagnostic']
        assert '@@' not in informations and '(\\*,G)' in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.site), str(data.mac_group), str(data.asm_group), str(data.ips.snoop_sw.ip),
                      'Partie 1', data.token):
            assert value not in informations

    def test_values_of_the_instance_in_the_first_question(self, lab, data, tmp_pub_dir):
        g0, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (f"**{data.query_interval} s**", str(data.asm_group), str(data.ssm_group), str(data.scoped_group),
                      str(data.v6_group), str(data.nets.asm_l13), str(data.nets6.v6_link), str(data.grade_port)):
            assert value in first, value
        # the grading groups and the token are for the instructor only
        for value in (data.token, str(data.g_asm), str(data.g_scoped)):
            assert value not in "\n".join(t for _w, t in _all_texts(g0, _simulate(lab, data, tmp_pub_dir)[1])), value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['mac', 'alias', 'scope_a', 'scope_b', 'scope_c', 'sn', 'sn_mac', 'querier_before', 'rule',
                         'report_v3_dst', 'leave_v2_dst', 'ttl', 'option', 'rpf_iface', 'fhr_message', 'rp_answer',
                         'diagnosis']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 11 and result.warnings == []
        assert b'**Solution.**' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'multicast_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('multicast_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|sonde|panne|groupe|partie|portee|adresse|requete|depart|'
                            r'domaine|frontiere|lien|controle|globale)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.ips6)) + list(vars(data.nets6))
        names += list(lab.SCOPE_CLASSES)
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []
                  for c in field.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'snoop_sw' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.-]+', n)]
        assert not bad, bad
