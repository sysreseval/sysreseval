"""Offline tests of the link aggregation / LLDP lab (lab/sre/_DRAFT_misc/lacp-lldp.py).

No Docker: a model of the five sites (``World``) holds what has been done, as a set of features
(``lldp_on``, ``ab_arp``, ``isl_bonds``...), and renders the outputs the grader reads in the shapes
captured live on s17 (``ip -j -d link`` of bonds, bridges and VLAN interfaces, ``lldpcli -f json0``,
ping, transmit counters).  The behaviours follow what was seen live: a static (balance-xor) server
facing an LACP switch loses its traffic, miimon misses a silent cut while ARP monitoring fails over
in well under a second, a layer2 hash puts every flow on one member, the STP of the isl site blocks
eth2 of the non-root switch.  Covers the data, the topology, the states, the two-pass grading
contract (nothing done: 0; everything: 100 + 6 bonus points; **each part alone gives exactly its
points and everything but one part the rest**) and the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Network
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

from bonding import tx_packets_cmd  # noqa: E402
from bridging import normalize_mac  # noqa: E402
from lldp import LLDP_NEIGHBORS_CMD  # noqa: E402
from pmtu import ip_link_json_cmd  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'lacp-lldp.py'

# what each part configures (the features of the model) and its points
PARTS = {
    'lldp': {'lldp_on', 'lldp_descr', 'lldp_rx_only'},
    'ab': {'ab_bond', 'ab_arp'},
    'lacp': {'lacp_bond', 'lacp_fast', 'lacp_hash'},
    'isl': {'isl_bonds', 'isl_hash'},
    'fix': {'fix_srv', 'fix_member', 'fix_min_links'},
    'bonus': {'bonus_vlan'},
}
POINTS = {'lldp': 18, 'ab': 18, 'lacp': 22, 'isl': 22, 'fix': 20, 'bonus': 6}
SOLVE_STATE = {part: f'solve_{part}' for part in PARTS}
ALL_FEATURES = set().union(*PARTS.values())
FORM_ELEMENTS = {'q_lldp_discovery': 'lldp', 'q_lldp_protocol': 'lldp', 'q_ab': 'ab', 'q_lacpdu': 'lacp',
                 'q_lacp_iperf': 'lacp', 'q_lacp_one_side': 'lacp', 'q_isl_stp': 'isl', 'q_isl_iperf': 'isl',
                 'q_fix': 'fix'}
FORM_POINTS = {'lldp': 8, 'ab': 3, 'lacp': 5, 'isl': 4, 'fix': 3}
CHOICE_ELEMENTS = {'q_ab', 'q_isl_stp', 'q_fix'}
BONUS_ELEMENTS = ['bonus_vlan', 'bonus_ping']
UP = ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP']


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('lacp_lldp_lab_under_test', _LAB_PATH)
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


def _mentions(text, value):
    return re.search(r'(?<![0-9A-Za-z.])' + re.escape(value) + r'(?![0-9A-Za-z])', text) is not None


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
    ns.reset_state_results()
    if hasattr(ns, 'remount_proc_sys_done'):
        del ns.remount_proc_sys_done
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
# the model
# ---------------------------------------------------------------------------


def _iface(name, index, mac, master=None, slave_kind=None, slave_data=None, flags=UP, kind='tun', data=None,
           link=None):
    obj = {'ifindex': index, 'ifname': name, 'flags': list(flags), 'address': normalize_mac(mac), 'operstate': 'UP'}
    if master:
        obj['master'] = master
    if link:
        obj['link'] = link
    info = {'info_kind': kind, 'info_data': data or {}}
    if slave_kind:
        info['info_slave_kind'] = slave_kind
        info['info_slave_data'] = slave_data or {}
    obj['linkinfo'] = info
    return obj


AGG_STATE = ['active', 'short_timeout', 'aggregating', 'in_sync', 'collecting', 'distributing']
ALONE_STATE = ['active', 'short_timeout', 'aggregating', 'defaulted']


def _bond_slave(aggregator, aggregated):
    return {'state': 'ACTIVE', 'mii_status': 'UP', 'ad_aggregator_id': aggregator,
            'ad_actor_oper_port_state': 63 if aggregated else 71,
            'ad_actor_oper_port_state_str': AGG_STATE if aggregated else ALONE_STATE}


def _bond_data(mode, partner='', aggregator=1, num_ports=0, miimon=100, arp_interval=0, targets=(), primary=None,
               rate='fast', policy='layer3+4', min_links=0):
    data = {'mode': mode, 'miimon': miimon, 'arp_interval': arp_interval, 'arp_ip_target': list(targets),
            'xmit_hash_policy': policy, 'ad_lacp_rate': rate, 'ad_lacp_active': 'on', 'min_links': min_links,
            'ad_select': 'stable', 'ad_actor_sys_prio': 65535}
    if primary:
        data['primary'] = primary
    if mode == '802.3ad':
        data['ad_info'] = {'aggregator': aggregator, 'num_ports': num_ports, 'actor_key': 15,
                           'partner_key': 15 if partner else 1, 'partner_mac': partner or '00:00:00:00:00:00'}
    return data


class World:
    def __init__(self, lab, ns, features):
        self.lab, self.ns, self.d, self.f = lab, ns, ns.data, set(features)

    def mac(self, machine, i):
        return normalize_mac(getattr(self.d.macs, f"{machine}_eth{i}"))

    # -- ip -j -d link show --------------------------------------------------------------

    def links(self, m):
        f, d = self.f, self.d
        if m == 'lldp_srv':
            links = [_iface(f'eth{i}', 2 + i, self.mac(m, i)) for i in range(3)]
            if 'bonus_vlan' in f:
                links.append(_iface(f'eth0.{d.mgmt_vlan}', 9, self.mac(m, 0), kind='vlan',
                                    data={'protocol': '802.1Q', 'id': d.mgmt_vlan}, link='eth0'))
            return links
        if m == 'ab_srv':
            if 'ab_bond' not in f:
                return [_iface(f'eth{i}', 2 + i, self.mac(m, i)) for i in range(2)]
            arp = 'ab_arp' in f
            data = _bond_data('active-backup', miimon=0 if arp else 100, arp_interval=200 if arp else 0,
                              targets=[str(d.ips.ab_gw.ip)] if arp else [], primary='eth0')
            return [_iface('bond0', 9, self.mac(m, 0), kind='bond', data=data),
                    _iface('eth0', 2, self.mac(m, 0), 'bond0', 'bond', {'state': 'ACTIVE', 'mii_status': 'UP'}),
                    _iface('eth1', 3, self.mac(m, 0), 'bond0', 'bond', {'state': 'BACKUP', 'mii_status': 'UP'})]
        if m in ('lacp_srv', 'lacp_sw'):
            on = 'lacp_bond' in f
            srv_mac, sw_mac = self.mac('lacp_srv', 0), self.mac('lacp_sw', 0)
            if m == 'lacp_srv':
                if not on:
                    return [_iface(f'eth{i}', 2 + i, self.mac(m, i)) for i in range(2)]
                data = _bond_data('802.3ad', partner=sw_mac, num_ports=2, rate='fast' if 'lacp_fast' in f else 'slow',
                                  policy='layer3+4' if 'lacp_hash' in f else 'layer2')
                return [_iface('bond0', 9, srv_mac, kind='bond', data=data)] + [
                    _iface(f'eth{i}', 2 + i, srv_mac, 'bond0', 'bond', _bond_slave(1, True)) for i in range(2)]
            data = _bond_data('802.3ad', partner=srv_mac if on else '', num_ports=2 if on else 1)
            return [_iface('br0', 8, sw_mac, kind='bridge', data={'stp_state': 0}),
                    _iface('po1', 9, sw_mac, 'br0', 'bridge', {'state': 'forwarding'}, kind='bond', data=data),
                    _iface('eth0', 2, sw_mac, 'po1', 'bond', _bond_slave(1, on)),
                    _iface('eth1', 3, sw_mac, 'po1', 'bond', _bond_slave(1 if on else 2, on)),
                    _iface('eth2', 4, self.mac(m, 2), 'br0', 'bridge', {'state': 'forwarding'})]
        if m in ('isl_sw1', 'isl_sw2'):
            other = 'isl_sw2' if m == 'isl_sw1' else 'isl_sw1'
            br = _iface('br0', 8, min(self.mac(m, i) for i in range(3)), kind='bridge', data={'stp_state': 1})
            eth0 = _iface('eth0', 2, self.mac(m, 0), 'br0', 'bridge', {'state': 'forwarding'})
            if 'isl_bonds' not in f:
                blocked = self.lab.isl_blocked_port(self.d) == f"{m}_eth2"
                return [br, eth0, _iface('eth1', 3, self.mac(m, 1), 'br0', 'bridge', {'state': 'forwarding'}),
                        _iface('eth2', 4, self.mac(m, 2), 'br0', 'bridge',
                               {'state': 'blocking' if blocked else 'forwarding'})]
            data = _bond_data('802.3ad', partner=self.mac(other, 1), num_ports=2,
                              policy='layer3+4' if 'isl_hash' in f else 'layer2')
            return [br, eth0,
                    _iface('bond0', 9, self.mac(m, 1), 'br0', 'bridge', {'state': 'forwarding'}, kind='bond', data=data),
                    _iface('eth1', 3, self.mac(m, 1), 'bond0', 'bond', _bond_slave(1, True)),
                    _iface('eth2', 4, self.mac(m, 1), 'bond0', 'bond', _bond_slave(1, True))]
        if m in ('fix_srv', 'fix_sw'):
            srv_mac, sw_mac = self.mac('fix_srv', 0), self.mac('fix_sw', 0)
            lacp, member = 'fix_srv' in f, 'fix_member' in f
            both = lacp and member
            if m == 'fix_srv':
                if not lacp:
                    data = _bond_data('balance-xor')
                    slaves = [_iface(f'eth{i}', 2 + i, srv_mac, 'bond0', 'bond', {'state': 'ACTIVE', 'mii_status': 'UP'})
                              for i in range(2)]
                else:
                    data = _bond_data('802.3ad', partner=sw_mac, num_ports=2 if both else 1)
                    slaves = [_iface('eth0', 2, srv_mac, 'bond0', 'bond', _bond_slave(1, True)),
                              _iface('eth1', 3, srv_mac, 'bond0', 'bond', _bond_slave(1 if both else 2, both))]
                return [_iface('bond0', 9, srv_mac, kind='bond', data=data)] + slaves
            ports = 2 if both else 1
            min_links = 1 if 'fix_min_links' in f else 3
            carrier = ports >= min_links
            data = _bond_data('802.3ad', partner=srv_mac if lacp else '', num_ports=ports, min_links=min_links)
            po1_flags = UP if carrier else ['NO-CARRIER', 'BROADCAST', 'MULTICAST', 'MASTER', 'UP']
            links = [_iface('br0', 8, sw_mac, kind='bridge', data={'stp_state': 0}),
                     _iface('po1', 9, sw_mac, 'br0', 'bridge', {'state': 'forwarding' if carrier else 'disabled'},
                            flags=po1_flags, kind='bond', data=data),
                     _iface('eth0', 2, sw_mac, 'po1', 'bond', _bond_slave(1, lacp)),
                     _iface('eth2', 4, self.mac(m, 2), 'br0', 'bridge', {'state': 'forwarding'})]
            if member:
                links.append(_iface('eth1', 3, sw_mac, 'po1', 'bond', _bond_slave(1 if both else 2, both)))
            else:
                links.append(_iface('eth1', 3, self.mac(m, 1), flags=['BROADCAST', 'MULTICAST']))
            return links
        raise AssertionError(f"no ip link model for {m}")

    # -- lldpcli -f json0 show neighbors details --------------------------------------------

    def lldp(self, m):
        f, d = self.f, self.d
        sees = 'lldp_on' in f and (m != 'lldp_isp' or 'lldp_rx_only' not in f)
        if not sees:
            return json.dumps({'lldp': [{}]})
        descr = d.srv_descr if 'lldp_descr' in f else 'Debian GNU/Linux 13 (trixie) Linux 6.12'
        entry = {'name': 'eth0', 'via': 'LLDP',
                 'chassis': [{'id': [{'type': 'mac', 'value': self.mac('lldp_srv', 0)}],
                              'name': [{'value': 'lldp_srv'}], 'descr': [{'value': descr}],
                              'capability': [{'type': 'Router', 'enabled': False}]}],
                 'port': [{'id': [{'type': 'mac', 'value': self.mac('lldp_srv', 0)}], 'descr': [{'value': 'eth0'}],
                           'ttl': [{'value': '120'}]}]}
        return json.dumps({'lldp': [{'interface': [entry]}]})

    # -- traffic -----------------------------------------------------------------------------

    def ping_ok(self, src, dest):
        f, d = self.f, self.d
        if src == 'lldp_srv':
            return 'bonus_vlan' in f and dest == str(d.ips.lldp_core1.ip)
        if src == 'ab_srv':
            return 'ab_bond' in f
        if src == 'lacp_srv':
            return 'lacp_bond' in f
        if src in ('isl_pc1', 'isl_pc2'):
            return True                         # one link of the STP bridges already forwards
        if src == 'fix_srv':
            return self.fix_carrier() and 'fix_srv' in f
        raise AssertionError(f"unexpected ping from {src} to {dest}")

    def fix_carrier(self):
        ports = 2 if {'fix_srv', 'fix_member'} <= self.f else 1
        return ports >= (1 if 'fix_min_links' in self.f else 3)

    def tx(self, m, step):
        """Transmit counters: 1000 at step 1, plus the flows at step 3."""
        f = self.f
        if step == 1:
            return {'eth0': 1000, 'eth1': 1000, 'eth2': 1000}
        if m == 'lacp_srv':
            spread = ('lacp_bond' in f, 'lacp_hash' in f)
            added = {(True, True): (33, 33), (True, False): (66, 1)}.get(spread, (0, 0))
            return {'eth0': 1000 + added[0], 'eth1': 1000 + added[1]}
        if m in ('isl_sw1', 'isl_sw2'):
            if 'isl_bonds' in f and 'isl_hash' in f:
                return {'eth1': 1033, 'eth2': 1033}
            return {'eth1': 1066, 'eth2': 1001}   # one member (layer2) or STP blocking eth2
        if m == 'fix_srv':
            if 'fix_srv' not in f:
                return {'eth0': 1033, 'eth1': 1033}               # balance-xor: both, half dropped
            if 'fix_member' in f:
                return {'eth0': 1033, 'eth1': 1033}
            return {'eth0': 1066, 'eth1': 1000}
        raise AssertionError(f"no counters on {m}")

    def delivered(self):
        if not self.fix_carrier():
            return 0
        return 64 if 'fix_srv' in self.f else 31

    # -- every command ---------------------------------------------------------------------

    def output(self, machine, command, step):
        if command == ip_link_json_cmd():
            return json.dumps(self.links(machine)), 0
        if command == LLDP_NEIGHBORS_CMD:
            return self.lldp(machine), 0
        if command.startswith('cat /proc/net/bonding/') or command == 'bridge link':
            return '', 0
        m = re.fullmatch(r'ping -c 2 -w 4 (\S+)', command)
        if m:
            if self.ping_ok(machine, m.group(1)):
                return f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=64 time=1 ms\n", 0
            return "2 packets transmitted, 0 received, 100% packet loss\n", 1
        if command.endswith('ab-cut pulse 6'):
            return 'pulsed\n', 0
        if command.startswith('ping -i 0.1 -c 80'):
            received = 0 if 'ab_bond' not in self.f else (74 if 'ab_arp' in self.f else 20)
            return f"80 packets transmitted, {received} received\n", 0 if received else 1
        if command.startswith('sleep 1; hping3'):
            return '', 0
        if command.startswith('timeout 8 tcpdump'):
            return f"{self.delivered()}\n", 0
        if command.startswith('for i in '):
            ifaces = re.match(r'for i in (.*?); do', command).group(1).split()
            assert command == tx_packets_cmd(ifaces)
            counters = self.tx(machine, step)
            return "".join(f"{i} {counters[i]}\n" for i in ifaces), 0
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES, answers='final', instructor_mode=False):
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
    model = World(lab, ns, features)
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
                    cmds[key] = model.output(m, key[0], s)
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _lost(grade):
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _parts(grade):
    result = {str(p.title): 0 for p in grade.get_grade_parts()}
    for e in grade.get_grade_list():
        result[str(e.grade_part)] += e.grade
    return result


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        again = lab.Data.from_dict(data.to_dict())
        assert again.to_dict() == data.to_dict()

    def test_values(self, lab, data):
        assert data.core1_name != data.core2_name and data.core1_name.startswith(data.dc + '-core-')
        assert re.fullmatch(r'Gi1/0/\d+', data.core1_port) and re.fullmatch(r'Gi2/0/\d+', data.core2_port)
        assert 100 <= data.mgmt_vlan <= 999
        assert data.srv_descr == f"web server rack {data.rack}"
        nets = [getattr(data.nets, n) for n in lab.SITE_NETS]
        assert len({str(n) for n in nets}) == 5 and all(n.prefixlen == 24 and n.is_private for n in nets)
        assert not any(n.overlaps(IPv4Network('172.17.0.0/16')) for n in nets)
        assert str(data.ips.lacp_pc.ip).endswith('.20') and data.ips.ab_gw.ip in data.nets.ab

    def test_fixed_macs(self, lab, data):
        macs = [normalize_mac(getattr(data.macs, key)) for key in set(lab.MAC_KEYS.values())]
        assert len(macs) == 34 == len(set(macs)) and all(mac.startswith('02:53:52:') for mac in macs)

    def test_isl_roles(self, lab, data):
        root, other = lab.isl_roles(data)
        mins = {m: min(int(getattr(data.macs, f'{m}_eth{i}')) for i in range(3)) for m in lab.ISL_SWITCHES}
        assert mins[root] < mins[other]
        assert lab.isl_blocked_port(data) == f'{other}_eth2'


class TestTopology:
    def test_machines(self, lab):
        specs = lab.NetScheme._machine_specs
        assert len(specs) == 18
        assert all(spec['image'] == lab.IMAGE and spec['weight'] == 1 for spec in specs.values())
        assert lab.IMAGE.split('/')[-1].startswith('netdev13:')
        assert {m for m, spec in specs.items() if spec.get('hidden')} == {'lldp_core1', 'lldp_core2', 'lldp_isp'}
        assert all(not spec.get('allow_connection', True) for spec in specs.values() if spec.get('hidden'))

    def test_point_to_point_and_sites(self, lab):
        for net, members in lab._TOPOLOGY.items():
            assert len(members) == 2, net
            assert all(m.split('_')[0] == net.split('_')[0] for m in members), net

    def test_topology_has_fixed_macs(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        topo = ns._topology
        assert topo['lacp_l1']['lacp_sw'] == (0, data.macs.lacp_sw_eth0)
        assert topo['isl_t2']['isl_sw2'] == (2, data.macs.isl_sw2_eth2)


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        core = _files(ops, 1, 'lldp_core1')[lab.LLDP_CONF]
        assert f'hostname {data.core1_name}' in core and f'portidsubtype local {data.core1_port}' in core
        assert f'management pattern {data.ips.lldp_core1.ip}' in core
        assert any(f'type vlan id {data.mgmt_vlan}' in c for c in _cmds(ops, 1, 'lldp_core1'))
        assert 'lldpd' in _cmds(ops, 1, 'lldp_isp')
        # lacp_sw: po1 802.3ad fast layer3+4, eth0 enslaved first, members capped
        sw = _cmds(ops, 1, 'lacp_sw')
        assert any(c.startswith('ip link add po1 type bond mode 802.3ad') and 'lacp_rate fast' in c
                   and 'layer3+4' in c for c in sw)
        assert sw.index('ip link set eth0 master po1') < sw.index('ip link set eth1 master po1')
        assert sum('tbf rate 20mbit' in c for c in sw) == 2
        assert sum('tbf rate 20mbit' in c for c in _cmds(ops, 1, 'lacp_srv')) == 2
        # isl: STP bridges, ports in the order eth0, eth1, eth2
        for m in lab.ISL_SWITCHES:
            cmds = _cmds(ops, 1, m)
            assert 'ip link add br0 type bridge stp_state 1' in cmds
            assert [c for c in cmds if c.endswith('master br0')] == [f'ip link set eth{i} master br0' for i in range(3)]
        # fix: the three faults
        assert any('mode balance-xor' in c for c in _cmds(ops, 1, 'fix_srv'))
        fix_sw = _cmds(ops, 1, 'fix_sw')
        assert any('min_links 3' in c for c in fix_sw) and 'ip link set eth1 master po1' not in fix_sw
        # ab: the cut script and nothing on ab_srv
        assert lab.AB_CUT in _files(ops, 1, 'ab_sw1')
        assert not any('bond' in c for c in _cmds(ops, 1, 'ab_srv'))
        for m in lab.LLDP_SWITCHES:
            assert 'lldpd' in _cmds(ops, 1, m)

    def test_cut_states(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert _cmds(_state_ops(ns, 'ab_cut'), 1, 'ab_sw1') == [f'{lab.AB_CUT} on']
        assert _cmds(_state_ops(ns, 'ab_uncut'), 1, 'ab_sw1') == [f'{lab.AB_CUT} off']
        assert 'table netdev $TABLE' in lab.AB_CUT_SCRIPT
        assert 'hook ingress device "eth0"' in lab.AB_CUT_SCRIPT and 'hook egress device "eth0"' in lab.AB_CUT_SCRIPT

    def test_solutions(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'solve_lldp')
        assert _files(ops, 1, 'lldp_srv')[lab.LLDP_CONF] == ns.lldp_conf()
        assert f'"{data.srv_descr}"' in ns.lldp_conf() and 'ports eth2 lldp status rx-only' in ns.lldp_conf()
        ab = _cmds(_state_ops(ns, 'solve_ab'), 1, 'ab_srv')
        assert any('mode active-backup primary eth0 arp_interval 200' in c and str(data.ips.ab_gw.ip) in c for c in ab)
        isl = _state_ops(ns, 'solve_isl')
        for m in lab.ISL_SWITCHES:
            assert 'ip link set bond0 master br0' in _cmds(isl, 1, m)
            assert any('state forwarding' in c for c in _cmds(isl, 2, m))
        fix = _state_ops(ns, 'solve_fix')
        assert 'ip link set po1 type bond min_links 1' in _cmds(fix, 1, 'fix_sw')
        assert any('mode 802.3ad' in c for c in _cmds(fix, 1, 'fix_srv'))
        bonus = _cmds(_state_ops(ns, 'solve_bonus'), 1, 'lldp_srv')
        assert f'ip link add link eth0 name eth0.{data.mgmt_vlan} type vlan id {data.mgmt_vlan}' in bonus

    def test_final_is_the_union_of_the_parts(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        final = _state_ops(ns, 'final')
        union = {}
        for state in SOLVE_STATE.values():
            for key, op_list in _state_ops(ns, state).items():
                union.setdefault(key, []).extend(str(op) for op in op_list if isinstance(op, str))
        assert {key: [str(op) for op in ops if isinstance(op, str)] for key, ops in final.items()} == {
            key: cmds for key, cmds in union.items()}


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
        assert len({str(e.title) for e in elements}) == len(elements) == 40

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
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - PARTS[part], answers='final')
        # the answers of the forms stay: the part keeps the points of its forms
        assert _parts(grade) == {key: (FORM_POINTS.get(part, 0) if key == part else POINTS[key]) for key in POINTS}

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(10):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (100, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, features=set(), answers=None)[0]) == (0, 0)

    def test_scopes_and_bonus(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        for e in grade.get_grade_list():
            expected = params.EXO_EVAL_SCOPE if str(e.title) in CHOICE_ELEMENTS else params.BOTH_EVAL_SCOPE
            assert e.scope == expected, e.title
        assert [str(e.title) for e in grade.get_grade_list() if e.bonus] == BONUS_ELEMENTS

    def test_answers_only_and_wrong_answers(self, lab, data, tmp_pub_dir):
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, features=set())
        assert _lost(answers_only) == set(_grades(answers_only)) - set(FORM_ELEMENTS)
        assert _totals(answers_only) == (sum(FORM_POINTS.values()), 0) == (23, 0)
        wrong, _ = _simulate(lab, data, tmp_pub_dir, answers=None)
        assert _lost(wrong) == set(FORM_ELEMENTS) and _totals(wrong) == (77, 6)

    @pytest.mark.parametrize('missing, lost', [
        ('lldp_on', {'lldp_seen', 'lldp_descr', 'lldp_rx_only'}),
        ('lldp_descr', {'lldp_descr'}),
        ('lldp_rx_only', {'lldp_rx_only'}),
        ('ab_arp', {'ab_arp', 'ab_failover'}),
        ('ab_bond', {'ab_bond', 'ab_primary', 'ab_arp', 'ab_ping', 'ab_failover'}),
        ('lacp_fast', {'lacp_fast'}),
        ('lacp_hash', {'lacp_hash', 'lacp_spread'}),
        ('lacp_bond', {'lacp_bond', 'lacp_fast', 'lacp_hash', 'lacp_srv_aggregated', 'lacp_sw_aggregated',
                       'lacp_ping', 'lacp_spread'}),
        ('isl_hash', {'isl_hash', 'isl_spread'}),
        ('isl_bonds', {'isl_bond_sw1', 'isl_bond_sw2', 'isl_aggregated_sw1', 'isl_aggregated_sw2', 'isl_bridge',
                       'isl_hash', 'isl_ping', 'isl_spread'}),
        ('fix_srv', {'fix_srv_mode', 'fix_aggregated', 'fix_ping', 'fix_delivery'}),
        ('fix_member', {'fix_sw_member', 'fix_aggregated', 'fix_delivery'}),
        ('fix_min_links', {'fix_min_links', 'fix_aggregated', 'fix_ping', 'fix_delivery'}),
        ('bonus_vlan', {'bonus_vlan', 'bonus_ping'}),
    ])
    def test_one_thing_missing(self, lab, data, tmp_pub_dir, missing, lost):
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=ALL_FEATURES - {missing})
        assert _lost(grade) == lost

    def test_isl_untouched_scores_nothing(self, lab, data, tmp_pub_dir):
        """The pings already work through the STP bridges: they only count once bond0 is a port."""
        grade, _ = _simulate(lab, data, tmp_pub_dir, features=set(), answers=None)
        assert _grades(grade)['isl_ping'] == (0, 2)

    def test_other_answer_spellings(self, lab, data, tmp_pub_dir):
        grade, ns = _simulate(lab, data, tmp_pub_dir)
        cheat = dict(grade.get_cheat_answers('final'))
        forms = {_text(q.title).split('. ', 1)[1]: q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)}

        def regrade(title, **changes):
            q = forms[title]
            stored = cheat[q.question_hash]
            answers = dict(json.loads(stored) if isinstance(stored, str) else stored, **changes)
            changed = dict(cheat, **{q.question_hash: json.dumps(answers) if isinstance(stored, str) else answers})
            return _grades(_simulate_with_answers(lab, data, tmp_pub_dir, changed)[0])

        assert regrade("Le câblage, vu par LLDP", core1_port=data.core1_port.lower())['q_lldp_discovery'][0] == 6
        assert regrade("Le câblage, vu par LLDP", core1_name=data.core2_name)['q_lldp_discovery'][0] == 5
        for ethertype in ('88cc', '0x88CC', '88CC'):
            assert regrade("Le protocole", ethertype=ethertype)['q_lldp_protocol'][0] == 2
        assert regrade("Le protocole", dst='01-80-C2-00-00-0E')['q_lldp_protocol'][0] == 2
        assert regrade("Le protocole", ttl='30', interval='120')['q_lldp_protocol'][0] == 1
        system = normalize_mac(data.macs.lacp_sw_eth0)
        assert regrade("Les LACPDU", system=system.upper().replace(':', '-'))['q_lacpdu'][0] == 3
        assert regrade("Les LACPDU", system=normalize_mac(data.macs.lacp_srv_eth0))['q_lacpdu'][0] == 2
        assert regrade("Débit et panne d'un membre", single='19,5', multi='37.8')['q_lacp_iperf'][0] == 1
        assert regrade("Débit et panne d'un membre", single='19', multi='20')['q_lacp_iperf'][0] == 0
        assert regrade("Débit et panne d'un membre", seconds='90')['q_lacp_one_side'][0] == 0
        assert regrade("STP et agrégat", before='38', after='38')['q_isl_iperf'][0] == 0

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 7
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
        assert len(grade.get_cheat_answers('final')) == 7
        assert grade.get_cheat_answers('solve_bonus') is None


def _simulate_with_answers(lab, data, tmp_pub_dir, cheat):
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
        assert len(g1.get_questions_ordered()) == 14
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 14 and 'informations' not in with_fragment

    def test_texts_are_formatted_and_numbered(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            assert '@@{{' not in text, where
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        from SRE.informations import resolve_informations, resolve_text
        resolved, numbering = resolve_informations(ns1.informations)
        informations = _text(resolved)
        assert [s.tag for s in numbering.sections('fr') if s.level == 1] == [
            'why', 'modes', 'monitoring', 'hashing', 'lacp', 'linux', 'bridge', 'lldp', 'lldpd', 'cheatsheet']
        assert '@@' not in informations
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (data.core1_name, data.core1_port, f"eth0.{data.mgmt_vlan}", str(data.nets.lacp.network_address),
                      'Partie 1', 'lldp_srv', 'fix_sw', 'isl_sw1'):
            assert not _mentions(informations, value), value

    def test_values_of_the_instance_in_the_questions(self, lab, data, tmp_pub_dir):
        g0, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        questions = [_text(q.description) for q in g0.get_questions_ordered()]
        first = questions[0]
        for value in (str(data.nets.ab), f"`{data.ips.lacp_pc.ip}`", f"`{data.ips.isl_pc2.ip}`", '**`bond0`**'):
            assert value in first, value
        everything = "\n".join(questions)
        for value in (f"**`{data.srv_descr}`**", f"`{data.ips.ab_srv}`", f"`{data.nets.lldp_mgmt}`",
                      f"`{data.ips.lldp_srv}`"):
            assert value in everything, value
        # what LLDP must reveal and the faults are for the instructor only
        for value in (data.core1_name, data.core2_name, data.core1_port, str(data.ips.lldp_core1.ip), data.isp_name,
                      f"eth0.{data.mgmt_vlan}", f"VLAN: {data.mgmt_vlan}", 'min_links 3'):
            assert not _mentions(everything, value), value

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        names = []
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices', 'lines'} & field.keys(), field
                names.append(field['name'])
        assert names == ['core1_name', 'core1_port', 'core1_mgmt', 'core2_name', 'core2_port', 'core2_mgmt', 'dst',
                         'ethertype', 'ttl', 'interval', 'miimon_cut', 'why', 'mac', 'dst', 'ethertype', 'system',
                         'priority', 'key', 'interval', 'single', 'multi', 'seconds', 'blocked', 'stp_view', 'before',
                         'after', 'outage', 'no_partner', 'one_port']

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 14 and result.warnings == []
        assert b'**Solution' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'lacp_lldp_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('lacp_lldp_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        kept = module._TRANSLATIONS['en']
        assert len(kept) == len(lab._TRANSLATIONS['en']) - 14
        assert not any(v.lstrip().startswith(('**Solution', '**For the instructor.**')) for v in kept.values())
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_translations(self, lab, data, tmp_pub_dir):
        """The texts are French with every one translated in _TRANSLATIONS['en'] (the markup kept: checked for
        every lab of the directory by test_draft_misc_translations.py)."""
        import ast
        import check_sre_translations as cst
        assert set(lab._TRANSLATIONS) == {'en'} and lab.default_language == 'fr'
        english = lab._TRANSLATIONS['en']
        assert set(english) == cst.get_tr_strings(ast.parse(_LAB_PATH.read_text())) and all(english.values())
        assert sum(v.lstrip().startswith(('**Solution', '**For the instructor.**')) for v in english.values()) == 14
        assert _text(lab.title, 'en') == "LACP and LLDP: link aggregation (bonding) and neighbour discovery"
        assert _text(lab.NetScheme.ab_cut._sre_state_description, 'en').startswith('Part 2: silently cut')
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for q in g1.get_questions_ordered():
            fr, en = _text(q.description, 'fr'), _text(q.description, 'en')
            assert fr != en and has_instructor(fr) and has_instructor(en), _text(q.title)
            assert "{'" not in en and not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", en), _text(q.title)

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements, part keys and form fields are English."""
        french = re.compile(r'(routeur|reseau|panne|partie|adresse|lien|voisin|serveur|commutateur|agregat|'
                            r'depannage|coupure|secours)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.macs))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        names += [c for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []
                  for c in field.get('choices', [])]
        assert 'initial' in names and 'final' in names and 'solve_fix' in names and 'ab_cut' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.:-]+', n)]
        assert bad == []
