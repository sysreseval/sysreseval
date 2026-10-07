"""Offline tests of the IPv6 lab (lab/sre/_DRAFT_misc/ipv6.py): data generation, topology and
expected configuration, state ops, the two-pass grading contract with synthetic outputs (nothing
done: 0, everything done: 100), the instructor texts and the stripped lab file.

No Docker: the outputs of the containers are rendered from the generated data in the format of
the real tools (ip, ip -j, dhclient lease file, dhcpd command line, the probe's JSON).
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

sys.path.insert(0, str(Path(__file__).parent.parent / 'lib'))
sys.path.insert(0, str(Path(__file__).parent.parent / 'src' / 'tools'))

import ipv6  # noqa: E402
import pmtu  # noqa: E402
from net_config import get_net_config_from_topology, net_config_entry_family, render_persistent_net_config_entry  # noqa: E402

_LAB_PATH = Path(__file__).parent.parent / 'lab' / 'sre' / '_DRAFT_misc' / 'ipv6.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('ipv6_lab_under_test', _LAB_PATH)
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


def _gw(g):
    return str(g.ip if hasattr(g, 'ip') else g)


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
# synthetic outputs of the "everything done" project
# ---------------------------------------------------------------------------

def _ip_a(ns, m):
    lines = []
    for i, entry in enumerate(ns.net_config[m]):
        lines.append(f"{i + 2}: eth{i}@if{i + 10}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP")
        if entry:
            for a in entry[0]:
                lines.append(f"    inet {a} brd {a.network.broadcast_address} scope global eth{i}" if a.version == 4
                             else f"    inet6 {a} scope global")
        lines.append(f"    inet6 fe80::53:52ff:fe00:{i + 1}/64 scope link proto kernel_ll")
    return "\n".join(lines) + "\n"


def _ip_route(ns, m, v6):
    lines = []
    for i, entry in enumerate(ns.net_config[m]):
        if not entry:
            continue
        for a in entry[0]:
            if (a.version == 6) == v6:
                lines.append(f"{a.network} dev eth{i} proto kernel metric 256 pref medium" if v6
                             else f"{a.network} dev eth{i} proto kernel scope link src {a.ip}")
        for net, gw in entry[1]:
            if (net.version == 6) == v6:
                dst = 'default' if net.prefixlen == 0 else str(net)
                lines.append(f"{dst} via {gw.ip} dev eth{i}" + (" metric 1024 pref medium" if v6 else ""))
    return "\n".join(lines) + "\n"


def _ip_j_addr(entries):
    return json.dumps([{"ifindex": 2, "ifname": "eth0", "addr_info": [{"family": "inet6", **e} for e in entries]}])


def _probe_json(lab, d):
    ll_r2 = str(ipv6.link_local_from_mac(d.macs.r2_lan3))
    ra = {"src": ll_r2, "hop_limit": 64, "managed": True, "other": True, "router_lifetime": 30,
          "prefixes": [{"prefix": str(d.nets6.lan3), "on_link": True, "autonomous": True, "valid": 86400, "preferred": 14400}],
          "mtu": None, "rdnss": [str(d.ips6.srv.ip)], "dnssl": [lab.DOMAIN], "source_mac": ipv6.mac_str(d.macs.r2_lan3)}

    def reply(msg_type, addresses):
        return {"msg_type": msg_type, "src": "fe80::53:52ff:fe00:5", "server_duid": "00:01:00:01:2e:4f:00:00:02:00:00:00:00:01",
                "addresses": addresses, "dns_servers": [str(d.ips6.srv.ip)], "domain_search": [lab.DOMAIN], "preference": 0}
    pool_addr = str(ipv6.IPv6Address(int(d.ips6.pool_min.ip) + 7))
    lifetimes = {"preferred": d.lease6 * 5 // 8, "valid": d.lease6}
    return json.dumps({"errors": [], "link_local": "fe80::53:52ff:fe00:9", "ra": [ra], "dhcp6": {
        "info": [reply("REPLY", [])],
        "dyn": [reply("ADVERTISE", [{"address": pool_addr, **lifetimes}])],
        "fixe": [reply("ADVERTISE", [{"address": str(d.ips6.pc2_fixe.ip), **lifetimes}])]}})


def _synthetic(lab, ns, machine, command):
    """(output, code) of *command* on *machine* in a project where everything is done."""
    d = ns.data
    n = d.wan_mtu
    tun_mtu = n - lab.TUN_OVERHEAD
    if command == 'ip a':
        return _ip_a(ns, machine), 0
    if command == 'ip route':
        return _ip_route(ns, machine, False), 0
    if command == 'ip -6 route':
        return _ip_route(ns, machine, True), 0
    if command == 'ip link show':
        return "\n".join(f"{i + 2}: eth{i}@if{i + 10}: <UP>" for i in range(len(ns.net_config[machine]))) + "\n", 0
    if command == 'ip -j -6 addr show dev eth0':
        ll = {"prefixlen": 64, "scope": "link", "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
        if machine == 'pc1':
            a = ipv6.slaac_address(d.nets6.lan3, d.macs.pc1)
            return _ip_j_addr([{"local": str(a.ip), "prefixlen": 64, "scope": "global", "dynamic": True, "mngtmpaddr": True,
                                "protocol": "kernel_ra", "valid_life_time": 86000, "preferred_life_time": 14000},
                               {"local": str(ipv6.link_local_from_mac(d.macs.pc1)), **ll}]), 0
        if machine == 'pc2':
            return _ip_j_addr([{"local": str(d.ips6.pc2_fixe.ip), "prefixlen": 128, "scope": "global", "dynamic": True,
                                "valid_life_time": d.lease6, "preferred_life_time": d.lease6 // 2},
                               {"local": str(ipv6.link_local_from_mac(d.macs.pc2)), **ll}]), 0
        mac = d.macs.m1 if machine == 'm1' else d.macs.r1_lan1
        return _ip_j_addr([{"local": str(ipv6.link_local_from_mac(mac)), **ll}]), 0
    if command == 'ip -j -6 route show':
        return json.dumps([{"dst": str(d.nets6.lan3), "dev": "eth0", "protocol": "kernel", "metric": 256},
                           {"dst": "default", "gateway": str(ipv6.link_local_from_mac(d.macs.r2_lan3)), "dev": "eth0",
                            "protocol": "ra", "metric": 1024, "expires": 27}]), 0
    if command == 'cat /proc/sys/net/ipv6/conf/all/forwarding':
        return ('1\n' if machine in lab.ROUTERS6 else '0\n'), 0
    if command == 'cat /etc/network/interfaces':
        return render_persistent_net_config_entry(ns.net_config[machine]), 0
    if command == 'pidof radvd':
        return '123\n', 0
    if command.startswith(f'python3 {ipv6.IPV6_PROBE_PATH}'):
        return _probe_json(lab, d), 0
    if command == 'cat /etc/resolv.conf':
        return f"search {lab.DOMAIN}\nnameserver {d.ips6.srv.ip}\n", 0
    if command.startswith('cat /var/lib/dhcp/dhclient6'):
        return (f'lease6 {{\n  interface "eth0";\n  ia-na 15:7f:62:a1 {{\n    iaaddr {d.ips6.pc2_fixe.ip} {{\n'
                f'      preferred-life 375;\n      max-life {d.lease6};\n    }}\n  }}\n'
                f'  option dhcp6.client-id {ipv6.duid_ll(d.macs.pc2)};\n}}\n'), 0
    if command.startswith('for p in $(pidof dhcpd)'):
        return "/usr/sbin/dhcpd -user dhcpd -group dhcpd -f -6 -pf /run/dhcp-server/dhcpd6.pid -cf /etc/dhcp/dhcpd6.conf eth0 \n", 0
    if command == 'nft list ruleset':
        return pmtu.nft_mss_clamp(lab.CLAMP_TABLE, mss4=pmtu.mss_for(n), mss6=pmtu.mss_for(n, ipv6=True)), 0
    if command == 'ip -j -d link show':
        local = str(d.ips.r1_wan1.ip if machine == 'r1' else d.ips.r2_wan2.ip)
        remote = str(d.ips.r2_wan2.ip if machine == 'r1' else d.ips.r1_wan1.ip)
        return json.dumps([{"ifname": "eth0", "mtu": 1500}, {"ifname": "eth1", "mtu": 1500},
                           {"ifname": "sit1", "mtu": tun_mtu, "flags": ["UP"],
                            "linkinfo": {"info_kind": "sit", "info_data": {"local": local, "remote": remote}}}]), 0
    if command.startswith('ping '):
        return "64 bytes from x: icmp_seq=1 ttl=62 time=0.5 ms\n3 packets transmitted, 3 received\n", 0
    if 'getent ahostsv6 m1' in command:
        return f"{d.ips6.m1.ip}      STREAM m1\n", 0
    if '===V4A' in command:
        flow = json.dumps({"end": {"sum_received": {"bytes": 5_000_000, "bits_per_second": 2e7, "seconds": 2}}})
        return "\n".join(f"==={tag}\n{flow}" for tag in ('V4A', 'V4R', 'V6A', 'V6R')) + "\n", 0
    if '===T6' in command:
        return ("===T6\n2 packets transmitted, 2 received, 0% packet loss\n"
                "===FIT\n2 packets transmitted, 2 received, 0% packet loss\n"
                f"===OVER\nping: local error: message too long, mtu: {tun_mtu}\n1 packets transmitted, 0 received\n"), 0
    return '', 0


def _simulate(lab, data, tmp_pub_dir, instructor_mode=False, everything=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            if everything:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        if everything:
            for (m, s), cmds in grade.get_tests().items():
                if s == step:
                    for key in list(cmds):
                        cmds[key] = _synthetic(lab, ns, m, key[0])
        step += 1
    return grade, ns


def _totals(grade):
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements), sum(e.max_grade for e in elements)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------

class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    def test_prefixes(self, lab, data):
        n6 = data.nets6
        assert n6.site1.prefixlen == 48 and n6.site2.prefixlen == 48 and not n6.site1.overlaps(n6.site2)
        assert n6.lan1.subnet_of(n6.site1) and n6.lan2.subnet_of(n6.site2) and n6.lan3.subnet_of(n6.site2)
        assert n6.lan2 != n6.lan3 and {n6.lan1.prefixlen, n6.wan1.prefixlen, n6.tun.prefixlen} == {64}
        for net in (n6.wan1, n6.wan2, n6.tun):
            assert not net.overlaps(n6.site1) and not net.overlaps(n6.site2)
        assert data.wan_mtu in lab.MTU_CHOICES and data.lease6 in lab.LEASE6_CHOICES

    def test_addresses(self, lab, data):
        i6 = data.ips6
        assert i6.r1_lan1.ip == data.nets6.lan1[1] and i6.r2_lan3.ip == data.nets6.lan3[1]
        assert i6.wan_wan1.ip == data.nets6.wan1[1] and i6.r1_wan1.ip == data.nets6.wan1[2]
        assert i6.pool_min.ip in data.nets6.lan3 and i6.pool_max.ip in data.nets6.lan3
        assert int(i6.pool_max.ip) - int(i6.pool_min.ip) == lab.POOL_SIZE - 1
        for a in (i6.srv, i6.h3, i6.pc2_fixe):
            assert a.ip in data.nets6.lan3 and not (i6.pool_min.ip <= a.ip <= i6.pool_max.ip)
        assert len({i6.srv.ip, i6.h3.ip, i6.pc2_fixe.ip, i6.r2_lan3.ip}) == 4
        assert len({str(data.macs.m1), str(data.macs.r1_lan1), str(data.macs.r2_lan3), str(data.macs.pc1),
                    str(data.macs.pc2), str(data.macs.probe)}) == 6
        assert ipv6.mac_str(data.macs.pc1).startswith(lab.MAC_PREFIX)


class TestNetScheme:
    def test_machines_and_adapters(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert sorted(ns.get_machine_names()) == ['h1', 'h2', 'h3', 'm1', 'm2', 'pc1', 'pc2', 'r1', 'r2', 'srv', 'wan']
        assert sorted(m.name for m in ns.get_visibles_machines()) == ['m1', 'm2', 'pc1', 'pc2', 'r1', 'r2', 'srv', 'wan']
        r2 = ns.get_machine('r2')
        assert sorted((a.network.name, a.interface) for a in r2.net_adapters.values()) == [('lan2', 1), ('lan3', 2), ('wan2', 0)]
        macs = {(a.network.name, a.machine.name): a.mac for net in ns.get_networks() for a in net.net_adapters.values()}
        assert macs[('lan1', 'm1')] == data.macs.m1 and macs[('lan1', 'r1')] == data.macs.r1_lan1
        assert macs[('lan3', 'r2')] == data.macs.r2_lan3 and macs[('lan3', 'pc1')] == data.macs.pc1
        assert macs[('lan3', 'pc2')] == data.macs.pc2 and macs[('lan1', 'h1')] is None
        assert ns.get_machine('srv').privileged and ns.get_machine('srv').image.endswith(':' + params.default_docker_image_version)
        assert 'net.ipv6.conf.default.addr_gen_mode=0' in ns.get_machine('pc1').sysctls
        assert 'net.ipv6.conf.default.accept_ra=0' in ns.get_machine('m1').sysctls
        assert 'net.ipv6.conf.default.accept_ra=0' not in ns.get_machine('pc1').sysctls

    def test_ipv4_entries_match_the_topology(self, lab, data, tmp_pub_dir):
        """The hand-written entries agree with get_net_config_from_topology on the IPv4 family,
        except on wan (aggregate routes are only written for IPv6)."""
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        generated = get_net_config_from_topology(ns, gateway='wan', default_route=None)
        for m, entry in ns.net_config.items():
            if m in lab.AUTO_HOSTS:
                assert entry == [None]
                continue
            got = net_config_entry_family(entry, 4)
            exp = generated[m]
            assert [e[0] for e in got] == [e[0] for e in exp], m
            assert [sorted((str(n), _gw(g)) for n, g in e[1]) for e in got] == \
                   [sorted((str(n), _gw(g)) for n, g in e[1]) for e in exp], m

    def test_initial_state(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        # IPv4 everywhere but pc1 / pc2, IPv6 on the operator and the probes only
        assert any(c.startswith(f'ip addr add {data.ips.m1}') for c in _cmds(ops, 1, 'm1'))
        assert not any(str(data.ips6.m1) in c for c in _cmds(ops, 1, 'm1'))
        assert any(c.startswith(f'ip addr add {data.ips6.wan_wan1}') for c in _cmds(ops, 1, 'wan'))
        assert f'ip route add {data.nets6.site2} via {data.ips6.r2_wan2.ip}' in _cmds(ops, 1, 'wan')
        assert any(c.startswith(f'ip addr add {data.ips6.h3}') for c in _cmds(ops, 1, 'h3'))
        assert _cmds(ops, 1, 'pc1')[0] == 'ip link set eth0 up' and not any('ip addr add' in c for c in _cmds(ops, 1, 'pc1'))
        # forwarding: IPv4 on the routers, IPv6 on wan only; the privileged srv gets plain sysctl
        for m in ('r1', 'wan', 'r2'):
            assert 'sysctl -w net.ipv4.ip_forward=1' in _cmds(ops, 1, m)
        assert 'sysctl -w net.ipv6.conf.all.forwarding=1' in _cmds(ops, 1, 'wan')
        for m in ('r1', 'r2', 'm1', 'srv', 'h1'):
            assert 'sysctl -w net.ipv6.conf.all.forwarding=0' in _cmds(ops, 1, m)
        assert not any(c.startswith('mount') for c in _cmds(ops, 1, 'srv'))
        # router advertisements: ignored by the static machines, used by pc1 / pc2
        for m in ('m1', 'r1', 'wan', 'r2', 'm2', 'srv', 'h1', 'h2', 'h3'):
            assert 'sysctl -w net.ipv6.conf.eth0.accept_ra=0' in _cmds(ops, 1, m), m
        assert 'sysctl -w net.ipv6.conf.eth2.accept_ra=0' in _cmds(ops, 1, 'r2')
        assert {'sysctl -w net.ipv6.conf.eth0.accept_ra=2', 'sysctl -w net.ipv6.conf.eth0.autoconf=1',
                'sysctl -w net.ipv6.conf.eth0.addr_gen_mode=0'} <= set(_cmds(ops, 1, 'pc1'))
        assert {'sysctl -w net.ipv6.conf.eth0.accept_ra=2', 'sysctl -w net.ipv6.conf.eth0.autoconf=0'} <= set(_cmds(ops, 1, 'pc2'))
        assert 'sysctl -w net.ipv6.icmp.echo_ignore_multicast=1' in _cmds(ops, 1, 'h3')
        # operator: MTU and the probes' black hole; probe, DNS, hosts files
        assert f'ip link set dev eth0 mtu {data.wan_mtu}; ip link set dev eth1 mtu {data.wan_mtu}' in _cmds(ops, 1, 'wan')
        assert str(data.ips6.h1.ip) in _files(ops, 1, 'wan')[lab.PROBE_RULES]
        assert ipv6.IPV6_PROBE_PATH in _files(ops, 1, 'h3')
        unbound = _files(ops, 1, 'srv')['/etc/unbound/unbound.conf']
        assert f'IN AAAA {data.ips6.m1.ip}' in unbound and f'IN AAAA {ipv6.slaac_address(data.nets6.lan3, data.macs.pc1).ip}' in unbound
        hosts = _files(ops, 1, 'm1')['/etc/hosts']
        assert f'{data.ips6.m2.ip}' in hosts and 'pc1' not in hosts
        assert 'pc1' in _files(ops, 1, 'pc1')['/etc/hosts'] and _files(ops, 1, 'pc1')['/etc/resolv.conf'] == ''
        assert f'nameserver {data.ips.srv.ip}' in _files(ops, 1, 'm1')['/etc/resolv.conf']
        interfaces = _files(ops, 1, 'r1')['/etc/network/interfaces']
        assert 'inet static' in interfaces and 'inet6' not in interfaces

    def test_final_state(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert f'ip addr add {data.ips6.r2_lan3} dev eth2' in _cmds(ops, 1, 'r2')
        assert f'ip route add ::/0 via {data.ips6.wan_wan2.ip}' in _cmds(ops, 1, 'r2')
        assert 'sysctl -w net.ipv6.conf.all.forwarding=1' in _cmds(ops, 1, 'r1')
        assert 'inet6 static' in _files(ops, 1, 'm1')['/etc/network/interfaces']
        radvd = _files(ops, 1, 'r2')['/etc/radvd.conf']
        assert 'AdvManagedFlag on;' in radvd and 'AdvOtherConfigFlag on;' in radvd and f'RDNSS {data.ips6.srv.ip}' in radvd
        conf = _files(ops, 1, 'srv')[ipv6.DHCPD6_CONF]
        assert f'range6 {data.ips6.pool_min.ip} {data.ips6.pool_max.ip};' in conf
        assert f'host-identifier option dhcp6.client-id {ipv6.duid_ll(data.macs.pc2)};' in conf
        assert f'fixed-address6 {data.ips6.pc2_fixe.ip};' in conf and f'default-lease-time {data.lease6};' in conf
        assert f'systemctl restart {ipv6.DHCPD6_UNIT}' in _cmds(ops, 1, 'srv')
        assert any('nft -f' in c for c in _cmds(ops, 1, 'r1')) and any('type sit' in c for c in _cmds(ops, 1, 'r2'))
        pc1, pc2 = _cmds(ops, 2, 'pc1'), _cmds(ops, 2, 'pc2')
        assert len(pc1) == 1 and 'dhclient -6 -S' in pc1[0] and '>/tmp/dhclient6.log 2>&1' in pc1[0]
        assert len(pc2) == 1 and 'dhclient -6 -D LL' in pc2[0] and 'rm -f /run/dhclient6*.pid /var/lib/dhcp/dhclient6*.leases' in pc2[0]
        assert not any(op for (step, m), op in ops.items() if step > 2)

    def test_user_states(self, lab, data, tmp_pub_dir):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert f'nft -f {lab.TN_RULES}' in _cmds(_state_ops(ns, 'trou_noir'), 1, 'wan')[0]
        assert 'nft delete table inet trou_noir' in _cmds(_state_ops(ns, 'icmp_retabli'), 1, 'wan')[0]
        assert lab.NetScheme.trou_noir._sre_state_user_allowed and not lab.NetScheme.final._sre_state_user_allowed


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------

class TestGrading:
    def test_everything_done_scores_100(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        not_max = [(str(e.title), e.grade, e.max_grade) for e in grade.get_grade_list() if e.grade != e.max_grade]
        assert not_max == []
        assert _totals(grade) == (100, 100)
        parts = {}
        for e in grade.get_grade_list():
            parts[e.grade_part] = parts.get(e.grade_part, 0) + e.max_grade
        assert parts == {'partie1': 12, 'partie2': 23, 'partie3': 16, 'partie4': 24, 'partie5': 15, 'partie6': 10}

    def test_nothing_done_scores_almost_nothing(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=False)
        scored = {str(e.title): e.grade for e in grade.get_grade_list() if e.grade}
        assert scored == {'route_hotes': 1}   # forwarding is off on the hosts from the start

    def test_probe_spec_depends_on_data_only(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, everything=False)
        commands = [cmd for (m, s), cmds in grade.get_tests().items() if m == 'h3' for cmd, _ in cmds]
        probe_cmd = [c for c in commands if c.startswith('python3')]
        assert len(probe_cmd) == 1
        spec = json.loads(__import__('base64').urlsafe_b64decode(probe_cmd[0].split()[-1]))
        assert [q['id'] for q in spec['queries']] == ['info', 'dyn', 'fixe']
        assert spec['queries'][2]['duid'] == ipv6.duid_ll(data.macs.pc2)

    def test_tampering_is_not_rewarded(self, lab, data, tmp_pub_dir):
        """A pc2 address added by hand (no dynamic flag) or outside the pool scores nothing."""
        name = _running_name()
        ns = lab.NetScheme(data=data, running_lab_name=name)
        grade = lab.Grade(net_scheme=ns)
        step = 1
        while True:
            grade.reset_before_grade()
            grade.grade()
            if step > grade.max_step:
                break
            for (m, s), cmds in grade.get_tests().items():
                if s == step:
                    for key in list(cmds):
                        out = _synthetic(lab, ns, m, key[0])
                        if m == 'pc2' and key[0] == 'ip -j -6 addr show dev eth0':
                            out = (_ip_j_addr([{"local": str(data.ips6.pc2_fixe.ip), "prefixlen": 64, "scope": "global",
                                                "valid_life_time": 4294967295, "preferred_life_time": 4294967295}]), 0)
                        cmds[key] = out
            step += 1
        by_title = {str(e.title): e.grade for e in grade.get_grade_list()}
        assert by_title['dhcp6_pc2_adresse'] == 0 and by_title['dhcp6_pc2_fixe'] == 0
        assert by_title['dhcp6_reservation'] == 3


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
        assert len(g1.get_questions_ordered()) == 20
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) >= 15 and 'informations' not in with_fragment

    def test_texts_are_formatted(self, lab, data, tmp_pub_dir):
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        for where, text in _all_texts(g1, ns1):
            assert "{'" not in text, where
            assert not re.search(r"(?<!\{)\{[a-z_0-9]+\}(?!\})", text), where
            assert '@@{' not in text or where != 'informations'
            markdown_to_html(text, show_instructor=True)
            markdown_to_html(text, show_instructor=False)
        informations = _text(ns1.informations)
        for section in ('## 7. La découverte de voisins', '## 9. DHCPv6', '## 12. MTU', '## 17. Plan du TP'):
            assert section in informations

    def test_student_texts_never_show_the_operator_mtu(self, lab, data, tmp_pub_dir):
        """The same project rendered with two MTU values gives the same student texts (the MTU
        is what the students measure); the instructor texts do change."""
        texts = {}
        for mtu in (lab.MTU_CHOICES[0], lab.MTU_CHOICES[-1]):
            variant = lab.Data.from_json(data.to_json())
            variant.wan_mtu = mtu
            for mode in (False, True):
                grade, ns = _simulate(lab, variant, tmp_pub_dir, instructor_mode=mode)
                texts[(mtu, mode)] = [_text(q.description) for q in grade.get_questions_ordered()] + [_text(ns.informations)]
        assert texts[(lab.MTU_CHOICES[0], False)] == texts[(lab.MTU_CHOICES[-1], False)]
        assert texts[(lab.MTU_CHOICES[0], True)] != texts[(lab.MTU_CHOICES[-1], True)]

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields > 30

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        result = strip_source(_LAB_PATH.read_bytes())
        assert result.calls >= 20 and result.warnings == []
        stripped = tmp_path / 'ipv6_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('ipv6_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 100)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())
