"""Offline tests of the network-firewall lab (lab/sre/_DRAFT_misc/nftables-filter2.py): data generation with the
hidden mirror, topology, the ops of the states (echo servers, DNS servers, sshd, mail banners,
resolvers), the multi-pass grading contract with synthetic outputs (nothing done: 0, the reference
solution: 100 + the bonus, one firewall only, variants of the rules, a ban placed too late), the
two phases of the hidden mirror, the texts in both languages, the instructor fragments, the stripped
lab file and the English identifiers.

No Docker: the `nft -j list ruleset` of ext1 and of the router are built from the generated data in
the JSON shape of nftables 1.0.6, and a model of the two firewalls answers the probes as the echo
servers / dig / bash / ping do.  The model gave, before the lab ever ran, the points a workstation
then gave for real on 2026-11-11 (0, 100 + 6, 97 with a drop in output, 98 with one general stateful
rule, a bonus of 3 with the ban rules placed too late); the rulesets captured that day
(tests/mock_data/firewall/nft_json_filter2_*_live.json) are graded as they are by
test_live_captures_get_full_marks.
"""
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from SRE import form_spec, params
from SRE.informations import resolve_informations, resolve_text
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]          # tests/lab/<this file>
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import check_sre_translations  # noqa: E402
import strip_instructor  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'nftables-filter2.py'


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('nftables_filter2_lab_under_test', _LAB_PATH)
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


def _ip(obj):
    return str(obj.ip)


def _state_ops(ns, name):
    """{(step, machine): [ops]} registered by the state method *name*."""
    ns._ops, ns._host_ops = {}, {}
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
            for op in ops.get((step, machine), []) if not isinstance(op, str) and hasattr(op, 'filename')}


# ---------------------------------------------------------------------------
# synthetic rulesets (nft -j list ruleset, nftables 1.0.6 shapes)
# ---------------------------------------------------------------------------


def _match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def _payload(proto, field):
    return {"payload": {"protocol": proto, "field": field}}


def _meta(key):
    return {"meta": {"key": key}}


def _ct(*states):
    return _match({"ct": {"key": "state"}}, list(states) if len(states) > 1 else states[0], "in")


ACCEPT, DROP = {"accept": None}, {"drop": None}
REJECT = {"reject": {"type": "icmpx", "expr": "port-unreachable"}}       # inet table, no ip match in the rule: icmpx


def _ruleset(family, chains, rules, sets=()):
    """chains: [(name, hook or None, policy)], rules: [(chain, expr)], sets: [set object]."""
    objs = [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}},
            {"table": {"family": family, "name": "filter", "handle": 1}}]
    for obj in sets:
        objs.append({"set": dict(obj, family=family, table="filter")})
    for handle, (name, hook, policy) in enumerate(chains, 1):
        chain = {"family": family, "table": "filter", "name": name, "handle": handle}
        if hook:
            chain.update(type="filter", hook=hook, prio=0, policy=policy)
        objs.append({"chain": chain})
    for handle, (chain, expr) in enumerate(rules, 20):
        objs.append({"rule": {"family": family, "table": "filter", "chain": chain, "handle": handle, "expr": expr}})
    return json.dumps({"nftables": objs})


def _host_json(lab, d, family='inet', generic_ct=False, output='reject', policy='drop', by_name=False):
    """ext1 after `final` (or a variant: one general stateful rule, a drop in output, iifname, two ICMP rules)."""
    ext2 = _ip(d.ips.ext2)
    internal = {"prefix": {"addr": str(d.nets.int.network_address), "len": d.nets.int.prefixlen}}
    rules = [('input', [_match(_meta("iifname" if by_name else "iif"), "lo"), ACCEPT])]
    if generic_ct:
        rules.append(('input', [_ct("established", "related"), ACCEPT]))
    else:
        rules += [('input', [_match(_payload("ip", "saddr"), ext2), _match(_payload("udp", "sport"), 53), _ct("established"), ACCEPT]),
                  ('input', [_match(_meta("l4proto"), "tcp"), _ct("established", "related"), ACCEPT])]
    if by_name:
        rules += [('input', [_match(_payload("icmp", "type"), "echo-request"), ACCEPT]),
                  ('input', [_match(_payload("icmp", "type"), "echo-reply"), ACCEPT])]
    else:
        rules.append(('input', [_match(_payload("icmp", "type"), {"set": ["echo-reply", "echo-request"]}), ACCEPT]))
    rules += [('input', [_match(_payload("tcp", "dport"), 80), ACCEPT]),
              ('input', [_match(_payload("ip", "saddr"), internal), _match(_payload("tcp", "dport"), 22), ACCEPT])]
    chains = [('input', 'input', policy)]
    if output:
        chains.append(('output', 'output', 'accept'))
        if by_name:      # one rule: ip daddr != ext2 tcp dport 25 reject
            rules.append(('output', [_match(_payload("ip", "daddr"), ext2, "!="), _match(_payload("tcp", "dport"), 25), REJECT]))
        else:
            rules += [('output', [_match(_payload("ip", "daddr"), ext2), _match(_payload("tcp", "dport"), 25), ACCEPT]),
                      ('output', [_match(_payload("tcp", "dport"), 25), REJECT if output == 'reject' else DROP])]
    return _ruleset(family, chains, rules)


def _iface(key, name):
    return _match(_meta(key), name)


def _router_json(lab, d, family='inet', forward=True, forward_policy='drop', ban='first', by_index=False,
                 set_name=None, banned=()):
    """The router after `final` (or a variant: no forward chain, a forward chain that accepts, the ban rules
    after the stateful rule or missing, iif / oif, a crafted set name, elements in the set)."""
    dmz1, dmz2, ext2, int1 = (_ip(getattr(d.ips, m)) for m in ('dmz1', 'dmz2', 'ext2', 'int1'))
    iif, oif = ('iif', 'oif') if by_index else ('iifname', 'oifname')
    set_name = set_name or lab.BAN_SET
    rules = [('input', [_iface('iif', 'lo'), ACCEPT]),
             ('input', [_match(_meta(iif), {"set": ["eth1", "eth2"]}), _match(_payload("icmp", "type"), "echo-request"), ACCEPT]),
             ('input', [_match(_payload("icmp", "type"), "echo-reply"), ACCEPT]),
             ('input', [_match(_payload("ip", "saddr"), dmz1), _match(_payload("udp", "sport"), 53), _ct("established"), ACCEPT]),
             ('input', [_iface(iif, 'eth0'), _match(_meta("l4proto"), "tcp"), _ct("established", "related"), ACCEPT]),
             ('input', [_iface(iif, 'eth2'), _match(_payload("ip", "saddr"), int1), _match(_payload("tcp", "dport"), 22), ACCEPT])]
    chains, sets = [('input', 'input', 'drop')], []
    if forward:
        chains.append(('forward', 'forward', forward_policy))
        established = ('forward', [_ct("established", "related"), ACCEPT])
        ban_rules = [('forward', [_iface(iif, 'eth0'), _iface(oif, 'eth2'), _match(_payload("ip", "saddr"), "@" + set_name), DROP]),
                     ('forward', [_iface(iif, 'eth0'), _iface(oif, 'eth2'), _match(_payload("tcp", "dport"), 22),
                                  {"set": {"op": "add", "elem": _payload("ip", "saddr"), "set": "@" + set_name}}])]
        flows = [('forward', [_iface(iif, 'eth2'), _iface(oif, 'eth1'), _match(_payload("icmp", "type"), "echo-request"), ACCEPT]),
                 ('forward', [_iface(iif, 'eth2'), _iface(oif, 'eth0'), _match(_payload("ip", "daddr"), ext2),
                              _match(_payload("udp", "dport"), 53), ACCEPT]),
                 ('forward', [_iface(iif, 'eth2'), _iface(oif, 'eth0'), _match(_payload("tcp", "dport"), 80), ACCEPT]),
                 ('forward', [_match(_meta(iif), {"set": ["eth0", "eth2"]}), _iface(oif, 'eth1'), _match(_payload("ip", "daddr"), dmz1),
                              _match(_payload("tcp", "dport"), 80), ACCEPT]),
                 ('forward', [_iface(iif, 'eth1'), _iface(oif, 'eth0'), _match(_payload("ip", "saddr"), dmz2),
                              _match(_payload("udp", "dport"), 53), ACCEPT]),
                 ('forward', [_iface(iif, 'eth2'), _iface(oif, 'eth1'), _match(_payload("ip", "daddr"), dmz2),
                              _match(_payload("udp", "dport"), 53), ACCEPT])]
        if ban == 'first':
            rules += ban_rules + [established] + flows
        elif ban == 'last':
            rules += [established] + flows + ban_rules
        else:
            rules += [established] + flows
        if ban:
            # nftables 1.0.6 lists the `timeout` flag only for a set declared `flags dynamic,timeout`
            ban_set = {"name": set_name, "type": "ipv4_addr", "handle": 9, "size": 65535, "flags": ["timeout"],
                       "timeout": lab.BAN_SECONDS}
            if banned:
                ban_set["elem"] = [{"elem": {"val": address, "expires": 40}} for address in banned]
            sets.append(ban_set)
    return _ruleset(family, chains, rules, sets)


# ---------------------------------------------------------------------------
# a model of the two firewalls, as the probes see them on the hidden clones
# ---------------------------------------------------------------------------

_CURL = re.compile(r"curl -s -m \d+ http://([0-9.]+):(\d+)/")
_DIG = re.compile(r"dig \+time=\d+ \+tries=1 \+short -p 53 @([0-9.]+) (\S+) A")
_TCP = re.compile(r"/dev/tcp/([0-9.]+)/(\d+)")
_PING = re.compile(r"ping -c \d+ -W \d+ ([0-9.]+)")


class Model:
    """host: the reference ruleset of ext1 is loaded (phase 1 only); router / forward: the input and forward
    chains of the router (phase 2 and later); ban: 'first' (the reference), 'last' (after the stateful rule)
    or None; generic_ct: ext1 accepts every reply; output: 'reject', 'drop' or None on ext1."""

    def __init__(self, lab, d, host=True, router=True, forward=True, ban='first', generic_ct=False, output='reject',
                 resolver=None):
        self.lab, self.d = lab, d
        self.host, self.router, self.forward, self.ban = host, router, forward, ban
        self.generic_ct, self.output = generic_ct, output
        self.resolver = resolver
        self.banned = set()
        self.owner = {_ip(getattr(d.ips, m)): m for m in lab.HOSTS}
        self.owner.update({_ip(getattr(d.ips, f"router_{zone}")): 'router' for zone in lab.ZONES})

    def zone(self, machine):
        return self.lab.ZONE_OF.get(machine, 'router')

    def listens(self, machine, port):
        return (port in (80, 8080) or (port == 22 and machine in self.lab.SSH_SERVERS)
                or (port == 25 and machine in self.lab.MAIL_SERVERS))

    def crossing(self, src, dst, step, kind, port=None):
        """True when the forward chain lets a NEW exchange src -> dst through, and its replies back."""
        if 'router' in (src, dst) or self.zone(src) == self.zone(dst):
            return True
        if not (self.forward and step >= self.lab.ROUTER_PROBE_STEP):
            return True
        a, b = self.zone(src), self.zone(dst)
        if self.ban == 'first' and ((a == 'ext' and b == 'int' and src in self.banned)
                                    or (a == 'int' and b == 'ext' and dst in self.banned)):
            return False
        if kind == 'icmp':
            return (a, b) == ('int', 'dmz')
        if kind == 'udp':
            return ((a, b) == ('int', 'ext') and dst == 'ext2') or (src == 'dmz2' and b == 'ext') or (a == 'int' and dst == 'dmz2')
        return ((a, b) == ('int', 'ext') and port == 80) or (a in ('ext', 'int') and dst == 'dmz1' and port == 80)

    def filters(self, machine, step):
        """True when *machine* runs its firewall at *step*."""
        if machine == 'ext1':
            return self.host and step == self.lab.HOST_PROBE_STEP
        if machine == 'router':
            return self.router and step >= self.lab.ROUTER_PROBE_STEP
        return False

    def tcp(self, src, dst, port, step):
        if src == dst:
            return 'open' if self.listens(dst, port) else 'refused'
        if self.filters('ext1', step) and src == 'ext1' and self.output and port == 25 and dst != 'ext2':
            return 'refused' if self.output == 'reject' else 'dropped'
        if (self.forward and step >= self.lab.ROUTER_PROBE_STEP and self.ban and port == 22
                and self.zone(src) == 'ext' and self.zone(dst) == 'int'):
            self.banned.add(src)            # the trap: the packet reached the `add @banned` rule
        if not self.crossing(src, dst, step, 'tcp', port):
            return 'dropped'
        if self.filters(dst, step):
            allowed = ((dst == 'ext1' and (port == 80 or (port == 22 and self.zone(src) == 'int')))
                       or (dst == 'router' and port == 22 and src == 'int1'))
            if not allowed:
                return 'dropped'
        if self.filters(src, step) and src == 'router' and self.zone(dst) != 'ext':
            return 'dropped'                # the router only accepts the TCP replies arriving on eth0
        return 'open' if self.listens(dst, port) else 'refused'

    def dns(self, src, dst, step):
        if dst not in self.lab.DNS_SERVERS or not self.crossing(src, dst, step, 'udp'):
            return False
        if self.filters(dst, step):
            return False                    # a new UDP exchange towards a filtering machine
        if self.filters(src, step):
            return self.generic_ct or dst == {'ext1': 'ext2', 'router': 'dmz1'}[src]
        return True

    def ping(self, src, dst, step):
        if not self.crossing(src, dst, step, 'icmp'):
            return False
        if self.filters(dst, step) and dst == 'router':
            return self.zone(src) in ('dmz', 'int')
        return True

    def __call__(self, machine, command, step):
        lab, d = self.lab, self.d
        src = lab.visible(machine)
        m = _CURL.search(command)
        if m:
            ip, port = m.group(1), int(m.group(2))
            dst = src if ip == '127.0.0.1' else self.owner[ip]
            if self.tcp(src, dst, port, step) != 'open':
                return "", 28
            ttl = 64 if (dst == src or 'router' in (src, dst) or self.zone(src) == self.zone(dst)) else 63
            return f"SERVER={dst}\nSERVER_IP={ip}\nSERVER_PORT={port}\nCLIENT_IP=192.0.2.1\nCLIENT_PORT=40000\nTTL={ttl}\n", 0
        m = _DIG.search(command)
        if m:
            assert m.group(2) == f"{lab.DNS_NAME}.{lab.DOMAIN}"
            if self.dns(src, self.owner[m.group(1)], step):
                return _ip(getattr(d.ips, lab.DNS_NAME)) + "\n", 0
            return f";; communications error to {m.group(1)}#53: timed out\n;; no servers could be reached\n", 9
        m = _TCP.search(command)
        if m:
            verdict = self.tcp(src, self.owner[m.group(1)], int(m.group(2)), step)
            return {"open": "RC=0\n", "refused": "RC=1\n", "dropped": "RC=124\n"}[verdict], 0
        m = _PING.search(command)
        if m:
            ip = m.group(1)
            if self.ping(src, self.owner[ip], step):
                return f"PING {ip} ({ip}) 56(84) bytes of data.\n64 bytes from {ip}: icmp_seq=1 ttl=63 time=0.3 ms\n", 0
            return f"PING {ip} ({ip}) 56(84) bytes of data.\n\n--- {ip} ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", 1
        return None


def _outputs(model, host_json="", router_json=""):
    """The outputs function of _simulate for a model and the JSON of the two rulesets ('' = nothing loaded)."""
    def outputs(lab, ns, machine, command, step):
        listings = {'ext1': host_json, 'router': router_json}
        if command == 'nft -j list ruleset' and machine in listings:
            return listings[machine], 0
        if command == 'nft list ruleset' and machine in listings:
            return ("table inet filter {\n}\n" if listings[machine] else ""), 0
        if command == 'cat /etc/resolv.conf' and machine == 'int1':
            return ns.resolv_conf(model.resolver or lab.RESOLVER['int1']), 0
        probe = model(machine, command, step)
        return probe if probe is not None else ("", 0)
    return outputs


def _done(lab, d, **model_options):
    """Everything done: the reference rulesets, their model, int1 asking dmz2."""
    return _outputs(Model(lab, d, resolver=lab.DMZ_DNS, **model_options), _host_json(lab, d), _router_json(lab, d))


def _simulate(lab, data, tmp_pub_dir, outputs, instructor_mode=False, cheat=True):
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
            if cheat:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            # the transplants are registered once the rulesets are known: commands only join later steps
            for key, cmds in current.items():
                assert cmds >= keys.get(key, set()), "a registered test disappeared between two passes"
                assert key[1] >= step or cmds == keys.get(key, set()), "a test was registered for a step already run"
        keys = current
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = outputs(lab, ns, m, key[0], s)
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    """(points of the regular elements, points of the bonus elements)."""
    elements = grade.get_grade_list()
    return sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus)


def _part(grade, title):
    return sum(e.grade for e in grade.get_grade_list() if str(e.grade_part) == title)


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


def test_data_generation_and_round_trip(lab, data):
    d = data
    nets = [d.nets.ext, d.nets.dmz, d.nets.int]
    assert all(n.prefixlen == 24 for n in nets) and len(set(nets)) == 3
    for machine, zone in lab.ZONE_OF.items():
        net = getattr(d.nets, zone)
        assert getattr(d.ips, machine).ip == net.network_address + lab.HOST_PARTS[machine]
        assert getattr(d.ips, machine).network == net
        assert getattr(d.ips, machine + '_h') == getattr(d.ips, machine)
    for zone in lab.ZONES:
        router = getattr(d.ips, f"router_{zone}")
        assert router.ip == getattr(d.nets, zone).network_address + lab.ROUTER_PARTS[zone]
        assert getattr(d.ips, f"router_h_{zone}_h") == router and getattr(d.nets, zone + '_h') == getattr(d.nets, zone)
    blob = d.to_json()
    again = lab.Data.from_json(blob)
    assert again.to_json() == blob and again.ips.dmz2 == d.ips.dmz2
    assert lab.ip_of(d, 'int1_h') == d.ips.int1 and lab.visible('router_h') == 'router' and lab.clone('ext1') == 'ext1_h'
    for _ in range(5):
        other = lab.Data.generate()
        for zone in lab.ZONES:
            assert not getattr(other.nets, zone).overlaps(lab.IPv4Network("172.17.0.0/16"))


def test_topology_and_machines(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    visible = ['ext1', 'ext2', 'router', 'dmz1', 'dmz2', 'int1', 'int2']
    assert ns.get_machine_names() == visible + [m + '_h' for m in visible]
    nets = {n.name: n for n in ns.get_networks()}
    assert set(nets) == {'ext', 'dmz', 'int', 'ext_h', 'dmz_h', 'int_h'}
    assert all(n.mode == params.default_network_mode for n in nets.values())      # hubs: no network plugin needed
    assert [m.name for m in nets['dmz'].get_machines()] == ['dmz1', 'dmz2', 'router']
    assert [m.name for m in nets['int_h'].get_machines()] == ['int1_h', 'int2_h', 'router_h']
    assert [n.name for n in ns.get_visible_networks()] == ['ext', 'dmz', 'int']
    machines = {m.name: m for m in ns.get_machines()}
    assert all(machines[m].hidden and not machines[m].allow_connection for m in machines if m.endswith('_h'))
    assert not any(machines[m].hidden for m in visible)
    for suffix in ('', '_h'):       # the interfaces of the router: eth0 outside, eth1 the DMZ, eth2 inside
        adapters = machines['router' + suffix].net_adapters
        assert {net.name: a.interface for net, a in adapters.items()} == {'ext' + suffix: 0, 'dmz' + suffix: 1, 'int' + suffix: 2}


def test_initial_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'initial')
    d = data
    for m in ns.get_machine_names():
        name = lab.visible(m)
        cmds, files = _cmds(ops, 1, m), _files(ops, 1, m)
        assert 'nft flush ruleset' in cmds
        assert any(f'sysctl -w net.ipv4.ip_forward={1 if name == "router" else 0}' in c for c in cmds), m
        start = [c for c in cmds if 'sre_server_echo.py' in c and 'python3' in c]
        assert len(start) == 1 and start[0].endswith(f" {name} 80 8080'"), (m, start)
        assert files['/etc/hosts'] == f"127.0.0.1\tlocalhost\n127.0.1.1\t{name}\n"       # names: by DNS only
        resolver = lab.RESOLVER[name]
        address = '127.0.0.1' if resolver is None else _ip(getattr(d.ips, resolver))
        assert files['/etc/resolv.conf'] == f"search lab\nnameserver {address}\noptions timeout:1 attempts:1\n"
        unbound = [c for c in cmds if 'unbound -c' in c]
        assert bool(unbound) == (name in lab.DNS_SERVERS) == ('/etc/unbound/unbound.conf' in files)
        assert ('/usr/local/sbin/sre_tcp_server_25.py' in files) == (name in lab.MAIL_SERVERS)
        if name in lab.MAIL_SERVERS:
            assert files['/var/lib/sre_tcp_server_25.answer'] == f"220 {name}.lab ESMTP\r\n"
        assert (_cmds(ops, 2, m) == ['systemctl start ssh']) == (name in lab.SSH_SERVERS)
    conf = _files(ops, 1, 'dmz2_h')['/etc/unbound/unbound.conf']
    for machine in lab.HOSTS:
        assert f'local-data: "{machine}.lab. IN A {_ip(getattr(d.ips, machine))}"' in conf
    assert f'local-data: "router-dmz.lab. IN A {_ip(d.ips.router_dmz)}"' in conf and 'local-zone: "lab." static' in conf
    assert lab.RESOLVER == {'ext1': 'ext2', 'ext2': None, 'dmz1': None, 'dmz2': None, 'int1': 'ext2', 'int2': 'ext2',
                            'router': 'dmz1'}
    for suffix in ('', '_h'):
        assert f"ip address add {d.ips.ext1} dev eth0" in _cmds(ops, 1, 'ext1' + suffix)
        assert f"ip route add default via {_ip(d.ips.router_dmz)}" in _cmds(ops, 1, 'dmz2' + suffix)
        assert f"ip route add default via {_ip(d.ips.router_int)}" in _cmds(ops, 1, 'int1' + suffix)
        router = _cmds(ops, 1, 'router' + suffix)
        for zone, iface in (('ext', 'eth0'), ('dmz', 'eth1'), ('int', 'eth2')):
            assert f"ip link set {iface} up; ip address add {getattr(d.ips, 'router_' + zone)} dev {iface}" in router


def test_final_ops(lab, data):
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    ops = _state_ops(ns, 'final')
    assert sorted(ops) == [(1, 'ext1'), (1, 'int1'), (1, 'router')]
    host, router = _cmds(ops, 1, 'ext1'), _cmds(ops, 1, 'router')
    assert host[0] == 'nft flush ruleset' and host[1:] == ns.cmds_host() and len(host) == 12
    assert router[0] == 'nft flush ruleset' and router[1:] == ns.cmds_router() and len(router) == 20
    assert all(c.startswith('nft ') for c in host + router)
    text = "\n".join(host + router)
    d = data
    assert f"input ip saddr {_ip(d.ips.ext2)} udp sport 53 ct state established accept" in text
    assert f"input ip saddr {d.nets.int} tcp dport 22 accept" in text
    assert f"output ip daddr {_ip(d.ips.ext2)} tcp dport 25 accept" in text and "output tcp dport 25 reject" in text
    assert "nft 'add rule inet filter input iifname { eth1, eth2 } icmp type echo-request accept'" in text
    assert f"input iifname eth2 ip saddr {_ip(d.ips.int1)} tcp dport 22 accept" in text
    assert "nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'" in text
    assert f"nft 'add rule inet filter forward iifname {{ eth0, eth2 }} oifname eth1 ip daddr {_ip(d.ips.dmz1)} tcp dport 80 accept'" in text
    assert "nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'" in text
    # the two inserts: the drop on the set ends up first, before the rule feeding it
    assert router[-2:] == ["nft 'insert rule inet filter forward iifname eth0 oifname eth2 tcp dport 22 add @banned { ip saddr }'",
                           "nft insert rule inet filter forward iifname eth0 oifname eth2 ip saddr @banned drop"]
    # every brace and every quoted word is inside single quotes: the shell passes them to nft untouched
    for c in host + router:
        assert ('{' in c) == c.startswith("nft '") and '"' not in c
    assert _files(ops, 1, 'int1')['/etc/resolv.conf'].splitlines()[1] == f"nameserver {_ip(d.ips.dmz2)}"


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


def test_grading_nothing_done(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs(Model(lab, data, host=False, router=False, forward=False)), cheat=False)
    grades = _grades(grade)
    assert _totals(grade) == (0, 0), {k: v for k, v in grades.items() if v[0]}
    elements = grade.get_grade_list()
    assert sum(e.max_grade for e in elements if not e.bonus) == 100 and len(elements) == 41
    assert [str(e.title) for e in elements if e.bonus] == ['ban_set', 'ban_rules', 'ban_works', 'q_ban']
    assert sum(e.max_grade for e in elements if e.bonus) == 6
    assert [str(p.title) for p in grade.get_grade_parts()] == [f'part{i}' for i in range(1, 8)]
    tests = grade.get_tests()
    # empty rulesets: the clones are flushed in both phases, nothing is loaded
    for machine in ('ext1_h', 'router_h'):
        for step in (lab.HOST_LOAD_STEP, lab.ROUTER_LOAD_STEP):
            assert [c for c, _ in tests[(machine, step)]] == ['nft flush ruleset']


def test_grading_everything_done(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _done(lab, data))
    grades = _grades(grade)
    short = {k: v for k, v in grades.items() if v[0] != v[1]}
    assert not short, short
    assert _totals(grade) == (100, 6)
    assert [_part(grade, f'part{i}') for i in range(1, 8)] == [5, 20, 12, 13, 20, 30, 6]
    tests = grade.get_tests()
    assert grade.max_step == lab.BAN_STEP == 7
    # phase 1: ext1 loaded, the router open; phase 2: ext1 open, the router loaded, its fed set emptied
    host_load = [c for c, _ in tests[('ext1_h', lab.HOST_LOAD_STEP)]]
    assert host_load[0] == 'nft flush ruleset' and len(host_load) == 2 and 'base64 -d | nft -f -' in host_load[1]
    assert [c for c, _ in tests[('router_h', lab.HOST_LOAD_STEP)]] == ['nft flush ruleset']
    assert [c for c, _ in tests[('ext1_h', lab.ROUTER_LOAD_STEP)]] == ['nft flush ruleset']
    router_load = [c for c, _ in tests[('router_h', lab.ROUTER_LOAD_STEP)]]
    assert router_load[0] == 'nft flush ruleset' and 'base64 -d | nft -f -' in router_load[1]
    assert router_load[2:] == ['nft flush set inet filter banned']
    # nothing but the listings runs on the machines of the students
    visible = {m for (m, s) in tests if not m.endswith('_h')}
    assert visible == {'ext1', 'router', 'int1'} and all(s == 1 for (m, s) in tests if not m.endswith('_h'))
    assert {m for (m, s) in tests if s == lab.HOST_PROBE_STEP} == {'ext1_h', 'ext2_h', 'dmz1_h', 'int1_h', 'int2_h'}
    assert {m for (m, s) in tests if s == lab.ROUTER_PROBE_STEP} == {'router_h', 'ext1_h', 'ext2_h', 'dmz1_h', 'dmz2_h',
                                                                    'int1_h', 'int2_h'}
    assert [(m, len(c)) for (m, s), c in tests.items() if s == lab.TRAP_STEP] == [('ext1_h', 1)]
    assert [(m, len(c)) for (m, s), c in tests.items() if s == lab.BAN_STEP] == [('int2_h', 2)]


def test_one_firewall_at_a_time(lab, data, tmp_pub_dir):
    """The two phases are independent: ext1 alone gives parts 2 to 4, the router alone parts 5 to 7."""
    d = data
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs(Model(lab, d, router=False, forward=False), _host_json(lab, d)),
                         cheat=False)
    assert [_part(grade, f'part{i}') for i in range(1, 8)] == [0, 20, 12, 11, 0, 0, 0], _grades(grade)
    grade, _ = _simulate(lab, data, tmp_pub_dir,
                         _outputs(Model(lab, d, host=False, resolver=lab.DMZ_DNS), "", _router_json(lab, d)), cheat=False)
    assert [_part(grade, f'part{i}') for i in range(1, 8)] == [0, 0, 0, 0, 20, 28, 5], _grades(grade)
    # the input chain of the router without its forward chain: part 5 only, the transit is open
    grade, _ = _simulate(lab, data, tmp_pub_dir,
                         _outputs(Model(lab, d, host=False, forward=False), "", _router_json(lab, d, forward=False)), cheat=False)
    assert [_part(grade, f'part{i}') for i in range(1, 8)] == [0, 0, 0, 0, 20, 0, 0], _grades(grade)


def test_host_variants(lab, data, tmp_pub_dir):
    d = data
    router_json = _router_json(lab, d)
    # one general stateful rule on ext1: every DNS server is answered, the restriction of (c) is lost
    outputs = _outputs(Model(lab, d, generic_ct=True, resolver=lab.DMZ_DNS), _host_json(lab, d, generic_ct=True), router_json)
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    grades = _grades(grade)
    assert grades['host_dns_restricted'] == (1, 3) and grades['host_dns_default'] == (4, 4) and _totals(grade) == (98, 6)
    # a drop in output: blocked, but not rejected
    outputs = _outputs(Model(lab, d, output='drop', resolver=lab.DMZ_DNS), _host_json(lab, d, output='drop'), router_json)
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    grades = _grades(grade)
    assert grades['out_mail_reject'] == (0, 3) and grades['out_mail_blocked'] == (3, 3) and grades['out_rule'] == (2, 2)
    assert _totals(grade) == (97, 6)
    # no output chain: mail goes everywhere
    outputs = _outputs(Model(lab, d, output=None, resolver=lab.DMZ_DNS), _host_json(lab, d, output=None), router_json)
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    assert _part(grade, 'part4') == 2 and _grades(grade)['out_mail_allowed'] == (0, 3)        # the form only
    # other spellings: the ip family, iifname lo, two ICMP rules, one negated reject rule
    outputs = _outputs(Model(lab, d, resolver=lab.DMZ_DNS), _host_json(lab, d, family='ip', by_name=True), router_json)
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    assert _totals(grade) == (100, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    # the same rules under a policy accept: ext1 does not filter, what it lets through does not count
    outputs = _outputs(Model(lab, d, host=False, resolver=lab.DMZ_DNS), _host_json(lab, d, policy='accept'), router_json)
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    grades = _grades(grade)
    assert grades['host_policy_drop'] == (0, 3) and grades['host_tcp_out'] == (0, 4) and grades['host_http_open'] == (0, 4)
    assert _part(grade, 'part2') == 1 and _part(grade, 'part3') == 0          # the DNS rule is still there


def test_router_variants(lab, data, tmp_pub_dir):
    d = data
    host_json = _host_json(lab, d)
    # iif / oif and the ip family
    outputs = _outputs(Model(lab, d, resolver=lab.DMZ_DNS), host_json, _router_json(lab, d, family='ip', by_index=True))
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    assert _totals(grade) == (100, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    # the ban rules after the stateful rule: the replies of ext1 still pass
    outputs = _outputs(Model(lab, d, ban='last', resolver=lab.DMZ_DNS), host_json, _router_json(lab, d, ban='last'))
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs)
    grades = _grades(grade)
    assert grades['ban_set'] == (1, 1) and grades['ban_rules'] == (1, 2) and grades['ban_works'] == (0, 2)
    assert _totals(grade) == (100, 3)
    # no ban at all
    outputs = _outputs(Model(lab, d, ban=None, resolver=lab.DMZ_DNS), host_json, _router_json(lab, d, ban=None))
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs, cheat=False)
    assert _part(grade, 'part7') == 0 and _totals(grade) == (91, 0)
    assert all('flush set' not in c for (m, s), cmds in grade.get_tests().items() for c, _ in cmds)
    # a forward chain that accepts: nothing is filtered, int1 still asks ext2
    outputs = _outputs(Model(lab, d, forward=False), host_json, _router_json(lab, d, forward_policy='accept', ban=None))
    grade, _ = _simulate(lab, data, tmp_pub_dir, outputs, cheat=False)
    grades = _grades(grade)
    assert grades['forward_policy_drop'] == (0, 2) and grades['forward_established'] == (2, 2) and _part(grade, 'part6') == 2


def test_a_ban_in_progress_does_not_reach_the_clone(lab, data, tmp_pub_dir):
    """The set of the real router holds ext2 (the student was testing): the clone starts with an empty set,
    so the model, which knows nothing of that element, is right and the grade is whole."""
    d = data
    router_json = _router_json(lab, d, banned=(_ip(d.ips.ext2),))
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs(Model(lab, d, resolver=lab.DMZ_DNS), _host_json(lab, d), router_json))
    assert _totals(grade) == (100, 6)
    assert [c for c, _ in grade.get_tests()[('router_h', lab.ROUTER_LOAD_STEP)]][-1] == 'nft flush set inet filter banned'
    # a set name that is not a plain identifier never reaches a shell command
    router_json = _router_json(lab, d, set_name='x;reboot')
    grade, _ = _simulate(lab, data, tmp_pub_dir, _outputs(Model(lab, d, resolver=lab.DMZ_DNS), _host_json(lab, d), router_json))
    commands = [c for (m, s), cmds in grade.get_tests().items() for c, _ in cmds]
    assert not any('reboot' in c for c in commands) and not any('flush set' in c for c in commands)


def test_live_captures_get_full_marks(lab, tmp_pub_dir, monkeypatch):
    """The rulesets `final` left on ext1 and on the router of a real project (the router with the address of
    ext1 in its set: a ban in progress), graded with the addresses of that project."""
    captured = [lab.IPv4Network(n) for n in ('172.31.243.0/24', '10.230.6.0/24', '192.168.147.0/24')]
    monkeypatch.setattr(lab, 'random_ipv4networks', lambda **kwargs: captured)
    d = lab.Data.generate()
    d.compute_post_generate()
    assert (_ip(d.ips.ext2), _ip(d.ips.dmz1), _ip(d.ips.int1)) == ('172.31.243.52', '10.230.6.101', '192.168.147.10')
    mock = _REPO / 'tests' / 'mock_data' / 'firewall'
    host_json = (mock / 'nft_json_filter2_host_live.json').read_text()
    router_json = (mock / 'nft_json_filter2_router_live.json').read_text()
    assert '"expires"' in router_json
    grade, ns = _simulate(lab, d, tmp_pub_dir, _outputs(Model(lab, d, resolver=lab.DMZ_DNS), host_json, router_json))
    assert _totals(grade) == (100, 6), {k: v for k, v in _grades(grade).items() if v[0] != v[1]}
    assert [c for c, _ in grade.get_tests()[('router_h', lab.ROUTER_LOAD_STEP)]][-1] == 'nft flush set inet filter banned'
    # the builder of this file gives the same JSON as nft for the reference solution (the handles apart)
    def shape(text):
        objects = json.loads(text)['nftables']
        rules = [(o['rule']['chain'], o['rule']['expr']) for o in objects if 'rule' in o]
        sets = [{k: v for k, v in o['set'].items() if k not in ('handle', 'elem')} for o in objects if 'set' in o]
        chains = [{k: v for k, v in o['chain'].items() if k != 'handle'} for o in objects if 'chain' in o]
        return rules, sets, chains
    assert shape(_host_json(lab, d)) == shape(host_json)
    assert shape(_router_json(lab, d)) == shape(router_json)


def test_form_answers(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _done(lab, data))
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert [[f['name'] for f in q.fields] for q in forms] == [['ttl', 'client_ip', 'resolver', 'ruleset'],
                                                             ['with_drop', 'with_reject'],
                                                             ['stateless_hole', 'reply_state'], ['ban_effect']]
    q1 = forms[0]
    answers = json.loads(grade._answers[q1.question_hash])
    answers.update({"ttl": "TTL=63 ", "client_ip": f"{_ip(data.ips.int1)}/24", "resolver": _ip(data.ips.ext2)})
    grade._answers[q1.question_hash] = json.dumps(answers)
    grade.reset_before_grade()
    grade.grade()
    assert _grades(grade)['q_before'] == (5, 5)
    answers.update({"ttl": "64", "resolver": _ip(data.ips.dmz1), "ruleset": "drop"})
    grade._answers[q1.question_hash] = json.dumps(answers)
    grade.reset_before_grade()
    grade.grade()
    assert _grades(grade)['q_before'] == (1, 5)
    assert lab._same_ip('x', data.ips.int1) is False and lab._is_int('', 63) is False
    assert lab._nameservers("search lab\nnameserver 192.0.2.1\n# nameserver 192.0.2.9\nnameserver\n") == ['192.0.2.1']
    assert lab._blocked('dropped') and lab._blocked('refused') and not lab._blocked('open') and not lab._blocked('error')


def test_cheat_answers_fill_every_form(lab, data, tmp_pub_dir):
    grade, _ = _simulate(lab, data, tmp_pub_dir, _done(lab, data))
    cheat = grade.get_cheat_answers('final')
    forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
    assert len(forms) == 4
    for q in forms:
        answers = cheat[q.question_hash]
        answers = json.loads(answers) if isinstance(answers, str) else answers
        for field in q.fields:
            assert field['name'] in answers, field['name']
            if 'choices' in field:
                assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
            elif 'regex' in field:
                assert re.fullmatch(field['regex'], answers[field['name']]), (field['name'], answers[field['name']])


# ---------------------------------------------------------------------------
# texts
# ---------------------------------------------------------------------------

#: the numbered sections of the course (level 1), in order; the questions refer to eight of them by tag
_TAGS = ['zones', 'hooks', 'ruleset', 'selectors', 'conntrack', 'verdicts', 'logging', 'output', 'forward', 'sets',
         'testing', 'practices', 'cheatsheet']
#: sub-sections the texts refer to (the reading guide, cross-references inside the course)
_SUB_TAGS = ['matrix', 'hook-list', 'three-paths', 'chain-roles', 'families', 'files', 'output-view', 'zone-chains',
             'router-input', 'spoofing', 'dynamic-sets', 'vmaps', 'locate', 'trace']


@pytest.mark.parametrize('lang', ['fr', 'en'])
def test_texts_and_instructor_fragments(lab, data, tmp_pub_dir, lang):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _done(lab, data), instructor_mode=True)
    info = _text(ns.informations, lang)
    assert info.count('\n## ') == len(_TAGS) and 'ct state established,related' in info and '@banned' in info
    for value in (data.nets.ext, data.nets.dmz, data.nets.int, data.ips.ext2.ip):
        assert str(value) not in info                      # instance data belongs to the first question
    # the examples of the course use the documentation ranges, never an address an instance could draw
    assert not re.search(r'\b(10\.\d+|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+\b', info)
    resolved, numbering = resolve_informations(ns.informations)
    course = _text(resolved, lang)
    sections = numbering.sections(lang)
    assert [s.number for s in sections if s.level == 1] == [str(i) for i in range(1, len(_TAGS) + 1)]
    assert [s.tag for s in sections if s.level == 1] == _TAGS
    tags = [s.tag for s in sections]
    assert {s.level for s in sections} == {1, 2} and all(tags) and len(set(tags)) == len(tags)
    assert set(_SUB_TAGS) <= set(tags) and 'iptables' not in tags and 'iptables' not in info
    for hook in ('prerouting', 'input', 'forward', 'output', 'postrouting', 'ingress', 'egress'):
        assert f'**`{hook}`**' in info, hook                # every hook is presented, ingress and egress included
    assert '## <a id="conntrack"></a>5. ' in course and '(#sets)' in course and '@@' not in course
    questions = list(grade.get_questions_ordered())
    assert len(questions) == 8
    resolved_questions = [_text(resolve_text(q.description, numbering), lang) for q in questions]
    assert all('@@ref' not in q and '@@sec' not in q for q in resolved_questions)
    section = 'section' if lang == 'fr' else 'section'
    assert f'({section} 11 ' in resolved_questions[0] and f'({section} 3)' in resolved_questions[0]
    assert f'({section}\n3 ' in resolved_questions[2] and f'({section} 5)' in resolved_questions[2]
    assert f'({section} 6 ' in resolved_questions[4]        # question 4: drop or reject in the output chain
    assert f'({section} 2 ' in resolved_questions[5] and f'({section} 4)' in resolved_questions[5]
    assert f'({section} 9 ' in resolved_questions[6] and f'({section} 11)' in resolved_questions[6]
    assert re.search(rf'{section}\s+10\s', resolved_questions[7])     # question 7: the sets
    assert all(has_instructor(_text(q.description, lang)) for q in questions)
    all_text = info + "".join(_text(q.description, lang) for q in questions)
    assert "{'" not in all_text and not re.search(r"(?<!@@)\{[a-z_0-9]+\}", all_text)
    first = _text(questions[0].description, lang)
    for value in (data.nets.ext, data.nets.dmz, data.nets.int, data.ips.ext1.ip, data.ips.dmz2.ip, data.ips.int2.ip,
                  data.ips.router_ext.ip, data.ips.router_dmz.ip, data.ips.router_int.ip):
        assert str(value) in first
    for cmd in ns.cmds_host() + ns.cmds_router():
        assert cmd in all_text, cmd                        # every command of the solution is in a question text
    for e in grade.get_grade_list():
        desc = _text(e.description, lang)
        assert desc and "{'" not in desc and not re.search(r"\{[a-z_]+\}", desc)
    for part in grade.get_grade_parts():
        assert _text(part.description, lang).startswith('Partie' if lang == 'fr' else 'Part ')
    # the student's view: no instructor fragment, no hidden machine, the ban commands still given
    grade2, ns2 = _simulate(lab, data, tmp_pub_dir, _done(lab, data), instructor_mode=False)
    student_text = _text(ns2.informations, lang) + "".join(_text(q.description, lang) for q in grade2.get_questions_ordered())
    assert not has_instructor(student_text) and 'Solution' not in student_text
    assert '_h`' not in student_text and 'ext1_h' not in student_text and 'router_h' not in student_text
    assert ns2.cmds_router_ban()[1] in student_text and ns2.cmds_router_forward()[3] not in student_text
    html = markdown_to_html(info)
    assert html.count('<table>') == 12 and '<code>nft -f /root/firewall.nft</code>' in html
    assert '```' not in html and html.count('<pre>') == 18      # every fenced block is rendered as code


def test_french_and_english_differ(lab, data, tmp_pub_dir):
    grade, ns = _simulate(lab, data, tmp_pub_dir, _done(lab, data), instructor_mode=True)
    texts = [ns.informations] + [q.description for q in grade.get_questions_ordered()]
    texts += [q.title for q in grade.get_questions_ordered()] + [e.description for e in grade.get_grade_list()]
    for text in texts:
        assert _text(text, 'fr') != _text(text, 'en'), _text(text, 'fr')[:60]
    assert _text(lab.title, 'en') == "Network firewall with nftables: client, server, router and DMZ"
    assert check_sre_translations.check_file(_LAB_PATH) == 0
    # the forms of both languages have the same fields and the same choice values (the answers are stored once)
    with_fields = 0
    for q in grade.get_questions_ordered():
        fields = form_spec.form_fields(_text(q.description, 'fr'))
        assert fields == form_spec.form_fields(_text(q.description, 'en'))
        with_fields += bool(fields)
    assert with_fields == 4


def test_stripped_lab_file(lab):
    source = _LAB_PATH.read_bytes()
    result = strip_instructor.strip_source(source)
    stripped = result.data if hasattr(result, 'data') else result[0]
    warnings = result.warnings if hasattr(result, 'warnings') else result[1]
    assert b'instructor(' not in stripped and not warnings, warnings
    compile(stripped, 'nftables_filter2_stripped', 'exec')
    assert source.count(b'instructor(tr(') == 8
    assert b'Solution' not in stripped and b'Pour l\'enseignant' not in stripped       # their translations are gone too


def test_english_identifiers(lab, data):
    """Machines, networks, states, data fields, grade elements and part keys are English (tr() texts are French)."""
    french = re.compile(r'(routeur|pont|reseau|serveur|sonde|panne|exemple|reponse|commutateur|passerelle|'
                        r'machine_|_machine|exterieur|interne|filtre|regle|journal|parefeu|courrier|banni)', re.I)
    names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY) + list(lab.NetScheme._network_specs)
    names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
    names += list(vars(data.ips)) + list(vars(data.nets))
    ns = lab.NetScheme(data=data, running_lab_name=_running_name())
    grade = lab.Grade(net_scheme=ns)
    grade.reset_before_grade()
    grade.grade()
    names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
    names += [f['name'] for q in grade.get_questions_ordered() for f in getattr(q, 'fields', [])]
    bad = [n for n in names if french.search(n)]
    assert not bad, bad
    own_states = [n for n, v in vars(lab.NetScheme).items() if getattr(v, '_is_sre_state', False)]
    assert sorted(own_states) == ['final', 'initial']       # save / restore are the empty lifecycle states of NetScheme0
