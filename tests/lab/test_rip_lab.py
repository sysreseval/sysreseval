"""Offline tests of the RIP lab (lab/sre/_DRAFT_misc/rip.py).

No Docker and no FRR: a small model of the site (``World``) interprets the FRR configuration the
lab itself writes — the frr.conf files of the ``initial`` state, then the vtysh sessions of the
``final`` state, or a few commands a student would type —, runs the distance-vector algorithm
with the rules of ripd (split horizon, poisoned reverse, output offsets, ECMP, authentication,
redistribution, a rogue speaker believed on any RIP interface) and renders the outputs the
grader reads: ``show ip rip``, ``show ip rip status``, ``ip -j route``, ``ip -j -6 route``, the
pings and the document of the hidden probe.  Covers the data, the topology, the state ops, the
two-pass grading contract (nothing done: 0; the final state: 100 + 6 bonus points; variants) and
the texts.
"""
import datetime
import importlib.util
import json
import re
import sys
from ipaddress import IPv4Address, IPv4Network, ip_address
from pathlib import Path

import pytest

from SRE import params
from SRE.instructor_text import has_instructor, markdown_to_html

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / 'lib'))
sys.path.insert(0, str(_REPO / 'src' / 'tools'))

import rip_probe  # noqa: E402
from frr import parse_kernel_routes, parse_rip_routes, parse_rip_status  # noqa: E402
from rip import RIP_PROBE_PATH, rip_window  # noqa: E402

_LAB_PATH = _REPO / 'lab' / 'sre' / '_DRAFT_misc' / 'rip.py'
DEFAULT = '0.0.0.0/0'
INFINITY = 16


@pytest.fixture(scope='module')
def lab():
    spec = importlib.util.spec_from_file_location('rip_lab_under_test', _LAB_PATH)
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
# a model of the site: FRR configuration -> what the grader reads
# ---------------------------------------------------------------------------


class Router:
    def __init__(self, name, lab, data):
        self.name = name
        self.nets = [net for net, _attr in lab.ROUTER_IFACES[name]]          # index = eth number
        self.ips = {net: getattr(data.ips, attr) for net, attr in lab.ROUTER_IFACES[name]}
        self.rip = False
        self.version2 = False
        self.statements = []            # `network` statements, as written
        self.enabled = set()            # networks RIP runs on
        self.timers = (30, 180, 120)
        self.passive = set()
        self.poisoned = set()
        self.deaf = set()               # `ip rip receive version none`
        self.md5 = set()                # `ip rip authentication mode md5`
        self.chain_of = {}              # network -> key chain name
        self.string_of = {}             # network -> `ip rip authentication string`
        self.key_chains = {}            # name -> {key id: secret}
        self.static = {}                # prefix -> gateway (FRR static routes)
        self.redistribute_static = None
        self.default_originate = False
        self.offsets = {}               # network -> metric added on output
        self.acls = set()
        self.ecmp = False
        self.ripng = set()

    def eth(self, net):
        return f"eth{self.nets.index(net)}"

    def net_of(self, interface):
        return self.nets[int(interface[3:])]

    def key(self, net):
        """(key id, secret) the router signs with on *net*, or None."""
        if net not in self.md5:
            return None
        if net in self.string_of:
            return (1, self.string_of[net])
        keys = self.key_chains.get(self.chain_of.get(net), {})
        return min(keys.items()) if keys else None

    def configure(self, lines):
        """Interpret vtysh configuration lines (the subset the lab and its solutions use)."""
        mode = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith('!') or line.startswith('log file'):
                continue
            words = line.split()
            if line in ('exit', 'end'):
                mode = mode[:-1] if line == 'exit' else []
            elif words[:2] == ['key', 'chain'] and not mode:
                mode = [('chain', words[2])]
                self.key_chains.setdefault(words[2], {})
            elif words[0] == 'key' and mode and mode[-1][0] == 'chain':
                mode = mode + [('key', int(words[1]))]
            elif words[0] == 'key-string' and mode and mode[-1][0] == 'key':
                self.key_chains[mode[0][1]][mode[-1][1]] = words[1]
            elif words[0] == 'interface' and not mode:
                mode = [('interface', self.net_of(words[1]))]
            elif mode and mode[-1][0] == 'interface':
                net = mode[-1][1]
                if line == 'ip rip split-horizon poisoned-reverse':
                    self.poisoned.add(net)
                elif line == 'ip rip authentication mode md5':
                    self.md5.add(net)
                elif words[:4] == ['ip', 'rip', 'authentication', 'key-chain']:
                    self.chain_of[net] = words[4]
                elif words[:4] == ['ip', 'rip', 'authentication', 'string']:
                    self.string_of[net] = words[4]
                elif line == 'ip rip receive version none':
                    self.deaf.add(net)
                else:
                    raise AssertionError(f"{self.name}: unknown interface command {line!r}")
            elif words[:2] == ['ip', 'route'] and not mode:
                self.static[str(IPv4Network(words[2]))] = IPv4Address(words[3])
            elif words[0] == 'access-list' and not mode:
                assert words[2:] == ['permit', 'any'], line
                self.acls.add(words[1])
            elif line == 'router rip' and not mode:
                mode, self.rip = [('rip',)], True
            elif line == 'router ripng' and not mode:
                mode = [('ripng',)]
            elif mode and mode[-1][0] == 'ripng':
                assert words[0] == 'network', line
                self.ripng.add(self.net_of(words[1]))
            elif mode and mode[-1][0] == 'rip':
                self._router_rip(line, words)
            else:
                raise AssertionError(f"{self.name}: unknown command {line!r} in mode {mode}")

    def _router_rip(self, line, words):
        negate = words[0] == 'no'
        if negate:
            words = words[1:]
        if words == ['version', '2']:
            self.version2 = not negate
        elif words[0] == 'network':
            target = words[1]
            if negate:
                self.statements.remove(target)
            elif target not in self.statements:          # a statement given twice is one statement
                self.statements.append(target)
            self.enabled = set()
            for statement in self.statements:
                if statement.startswith('eth'):
                    self.enabled.add(self.net_of(statement))
                else:
                    self.enabled |= {net for net, ip in self.ips.items() if ip.ip in IPv4Network(statement)}
        elif words[:2] == ['timers', 'basic']:
            self.timers = tuple(int(w) for w in words[2:5])
        elif words[0] == 'passive-interface':
            (self.passive.discard if negate else self.passive.add)(self.net_of(words[1]))
        elif words[:2] == ['redistribute', 'static']:
            self.redistribute_static = None if negate else (int(words[3]) if words[2:3] == ['metric'] else 1)
        elif words == ['default-information', 'originate']:
            self.default_originate = not negate
        elif words[0] == 'offset-list':
            acl, direction, metric, interface = words[1:5]
            assert acl in self.acls and direction == 'out', line
            self.offsets[self.net_of(interface)] = int(metric)
        elif words == ['allow-ecmp']:
            self.ecmp = not negate
        else:
            raise AssertionError(f"{self.name}: unknown router rip command {line!r}")


class Path_:
    """One path of a RIP table."""

    def __init__(self, metric, code, sub, net=None, via=None, source=None, nexthop=None, shown=None):
        self.metric, self.code, self.sub = metric, code, sub
        self.net, self.via, self.source, self.nexthop = net, via, source, nexthop
        # metric printed by `show ip rip` when it differs from the announced one: a redistributed
        # route is listed with 1 in the router's own table, `metric M` applies to its updates
        self.shown = metric if shown is None else shown

    def key(self):
        return (self.metric, self.code, self.sub, self.net, self.via)


class World:
    """The four routers, configured from what the lab writes."""

    def __init__(self, lab, ns, final=False):
        self.lab, self.ns, self.d = lab, ns, ns.data
        self.routers = {name: Router(name, lab, ns.data) for name in lab.ROUTER_IFACES}
        self.probe_uptime, self.probe_heartbeat_age, self.probe_answers = 600.0, 0.4, True
        self.rogue = True
        self.unheard = set()            # (router, network): RIP just enabled, no update sent yet
        initial = _state_ops(ns, 'initial')
        for name, router in self.routers.items():
            router.configure(_files(initial, 1, name)['/etc/frr/frr.conf'].splitlines())
        if final:
            ops = _state_ops(ns, 'final')
            for name, router in self.routers.items():
                for command in _cmds(ops, 1, name):
                    router.configure(_vtysh_commands(command))

    def configure(self, router, *lines):
        self.routers[router].configure(lines)
        return self

    # -- addressing -------------------------------------------------------------

    def prefix(self, net):
        return str(getattr(self.d.nets, net))

    def link_up(self, link, sender, receiver):
        """*receiver* accepts on *link* the updates of *sender*."""
        a, b = self.routers[sender], self.routers[receiver]
        if link not in a.enabled or link not in b.enabled or link in a.passive or link in b.deaf:
            return False
        return a.key(link) == b.key(link)

    # -- distance vector --------------------------------------------------------

    def local_paths(self, router):
        r, paths = self.routers[router], {}
        if not r.rip:
            return paths
        for net in r.enabled:
            paths[self.prefix(net)] = [Path_(1, 'C', 'i', net=net)]
        if r.default_originate:
            paths[DEFAULT] = [Path_(1, 'R', 'd')]
        if r.redistribute_static is not None:
            for prefix, gateway in r.static.items():
                paths.setdefault(prefix, [Path_(r.redistribute_static, 'S', 'r', nexthop=str(gateway), shown=1)])
        return paths

    def announcement(self, tables, router, link):
        """{prefix: metric} *router* sends on *link*."""
        r, out = self.routers[router], {}
        for prefix, paths in tables[router].items():
            learned_here = any(p.via is not None and p.net == link for p in paths)
            own_link = paths[0].via is None and paths[0].code == 'C' and prefix == self.prefix(link)
            if learned_here or own_link:
                if link in r.poisoned:
                    out[prefix] = INFINITY
                continue
            out[prefix] = min(INFINITY, paths[0].metric + r.offsets.get(link, 0))
        return out

    def tables(self):
        """{router: {prefix: [Path_]}} at the fixed point."""
        d, lab = self.d, self.lab
        tables = {name: self.local_paths(name) for name in self.routers}
        for _round in range(40):
            new = {}
            for name, router in self.routers.items():
                local = self.local_paths(name)
                candidates = {}
                if router.rip:
                    for link, ends in lab.TRANSIT.items():
                        if name not in ends:
                            continue
                        peer = ends[0] if ends[1] == name else ends[1]
                        if not self.link_up(link, peer, name):
                            continue
                        source = str(self.routers[peer].ips[link].ip)
                        for prefix, metric in self.announcement(tables, peer, link).items():
                            if metric + 1 < INFINITY:
                                candidates.setdefault(prefix, []).append(
                                    Path_(metric + 1, 'R', 'n', net=link, via=peer, source=source, nexthop=source))
                    # the rogue speaker of lan3 is believed on any interface RIP runs on
                    if (self.rogue and name == 'r3' and 'lan3' in router.enabled and 'lan3' not in router.deaf
                            and router.key('lan3') is None):
                        rogue = str(d.ips.intruder.ip)
                        candidates.setdefault(str(d.nets.ghost), []).append(
                            Path_(2, 'R', 'n', net='lan3', via='intruder', source=rogue, nexthop=rogue))
                table = dict(local)
                for prefix, paths in candidates.items():
                    if prefix in local:
                        continue
                    best = min(p.metric for p in paths)
                    kept = [p for p in paths if p.metric == best]
                    table[prefix] = kept if router.ecmp else kept[:1]
                new[name] = table
            if all({p: [x.key() for x in v] for p, v in new[n].items()}
                   == {p: [x.key() for x in v] for p, v in tables[n].items()} for n in new):
                return new
            tables = new
        raise AssertionError("the routing tables do not converge")

    # -- kernel tables ----------------------------------------------------------

    def kernel(self, router, tables):
        """ip -j route of *router* as a list of dicts."""
        r, routes = self.routers[router], []
        for prefix, gateway in r.static.items():
            net = next(n for n, ip in r.ips.items() if gateway in ip.network)
            routes.append({'dst': 'default' if prefix == DEFAULT else prefix, 'gateway': str(gateway),
                           'dev': r.eth(net), 'protocol': 'static', 'metric': 20})
        for net, ip in r.ips.items():
            routes.append({'dst': str(ip.network), 'dev': r.eth(net), 'protocol': 'kernel', 'scope': 'link',
                           'prefsrc': str(ip.ip)})
        known = {route['dst'] for route in routes}
        for prefix, paths in sorted(tables[router].items()):
            learned = [p for p in paths if p.via is not None]
            dst = 'default' if prefix == DEFAULT else prefix
            if not learned or dst in known:
                continue
            if len(learned) == 1:
                routes.append({'dst': dst, 'gateway': learned[0].nexthop, 'dev': r.eth(learned[0].net),
                               'protocol': 'rip', 'metric': 20})
            else:
                routes.append({'dst': dst, 'protocol': 'rip', 'metric': 20, 'nexthops': [
                    {'gateway': p.nexthop, 'dev': r.eth(p.net), 'weight': 1, 'flags': []} for p in learned]})
        return routes

    def ripng_complete(self):
        return all(set(r.nets) - {'wan'} <= r.ripng for r in self.routers.values())

    def kernel6(self, router):
        r, routes = self.routers[router], []
        for net in r.nets:
            if net != 'wan':
                routes.append({'dst': str(getattr(self.d.nets6, net)), 'dev': r.eth(net), 'protocol': 'kernel',
                               'metric': 256, 'pref': 'medium'})
        if self.ripng_complete():
            for net in self.lab.SITE_NETS:
                if net not in r.nets:
                    routes.append({'dst': str(getattr(self.d.nets6, net)), 'gateway': 'fe80::42:acff:fe11:2',
                                   'dev': 'eth1', 'protocol': 'ripng', 'metric': 20, 'pref': 'medium'})
        return routes

    # -- forwarding (the pings) -------------------------------------------------

    def _owner(self, address):
        """(machine, network it sits on) of an IPv4 address the grader pings."""
        d = self.d
        for host, (_router, router_attr) in self.lab.HOST_ROUTER.items():
            if address == getattr(d.ips, host).ip:
                return host, router_attr.split('_')[1]
        if address in d.nets.vmnet:
            return 'vm', None
        if address in self.lab.INTERNET:
            return 'internet', None
        raise AssertionError(f"unknown ping destination {address}")

    def _forward(self, router, address, tables):
        """True when a packet for *address* entering *router* is delivered."""
        owner, lan = self._owner(address)
        for _hop in range(20):
            routes = parse_kernel_routes(json.dumps(self.kernel(router, tables)))
            matches = [p for p in routes if address in IPv4Network(p)]
            if not matches:
                return False
            best = max(matches, key=lambda p: IPv4Network(p).prefixlen)
            gateways = [gw for gw, _dev in routes[best]['nexthops']]
            if gateways == [None]:                                    # connected: delivered on the LAN
                return lan is not None and str(getattr(self.d.nets, lan)) == best
            gateway = IPv4Address(gateways[0])
            if gateway == self.d.ips.hv.ip:
                return owner in ('vm', 'hv')
            if gateway == self.d.ips.isp.ip:
                return owner == 'internet'
            if gateway == self.d.ips.intruder.ip:
                return False
            router = next(name for name, r in self.routers.items() if gateway in [ip.ip for ip in r.ips.values()])
        return False

    def ping(self, src, address, tables):
        """*src* (a host) gets an answer from *address*."""
        if address.version == 6:
            return self.ripng_complete()
        first = self.lab.HOST_ROUTER[src][0]
        if not self._forward(first, address, tables):
            return False
        owner, _lan = self._owner(address)
        back = {'vm': 'r3', 'internet': 'r4'}.get(owner) or self.lab.HOST_ROUTER[owner][0]
        return self._forward(back, getattr(self.d.ips, src).ip, tables)

    # -- outputs ----------------------------------------------------------------

    def show_ip_rip(self, router, tables):
        if not self.routers[router].rip:
            return "% RIP instance not found\n"
        lines = ["Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP", "Sub-codes:",
                 "      (n) - normal, (s) - static, (d) - default, (r) - redistribute,", "      (i) - interface", "",
                 "     Network            Next Hop         Metric From            Tag Time"]
        for prefix, paths in sorted(tables[router].items(), key=lambda item: IPv4Network(item[0])):
            for p in paths:
                head = f"{p.code}({p.sub}) {prefix}".ljust(24)
                if p.via is None:
                    lines.append(f"{head}{p.nexthop or '0.0.0.0':<20} {p.shown:>2} {'self':<15} {0:>3}")
                else:
                    lines.append(f"{head}{p.nexthop:<20} {p.metric:>2} {p.source:<15} {0:>3} 00:11")
        return "\n".join(lines) + "\n"

    def show_ip_rip_status(self, router, tables):
        r = self.routers[router]
        if not r.rip:
            return "% RIP instance not found\n"
        update, timeout, garbage = r.timers
        version = "send version 2, receive version 2 " if r.version2 else "send version 2, receive any version "
        receive = '2' if r.version2 else '1 2'
        lines = ['Routing Protocol is "rip"',
                 f"  Sending updates every {update} seconds with +/-50%, next due in 2 seconds",
                 f"  Timeout after {timeout} seconds, garbage collect after {garbage} seconds",
                 "  Outgoing update filter list for all interface is not set",
                 "  Incoming update filter list for all interface is not set",
                 "  Default redistribution metric is 1",
                 "  Redistributing:" + (" static" if r.redistribute_static is not None else ""),
                 f"  Default version control: {version}",
                 "    Interface        Send  Recv   Key-chain"]
        for net in r.nets:
            if net in r.enabled:
                recv = 'none' if net in r.deaf else receive
                lines.append(f"    {r.eth(net):<17}{'2':<3}   {recv:<3}    {r.chain_of.get(net, '') if net in r.md5 else ''}")
        lines.append("  Routing for Networks:")
        lines += [f"    {statement}" for statement in r.statements]
        if r.passive & r.enabled:
            lines.append("  Passive Interface(s):")
            lines += [f"    {r.eth(net)}" for net in r.nets if net in r.passive and net in r.enabled]
        lines += ["  Routing Information Sources:", "    Gateway          BadPackets BadRoutes  Distance Last Update"]
        sources = sorted({p.source for paths in tables[router].values() for p in paths if p.source},
                         key=IPv4Address)
        lines += [f"    {source:<16} {0:>9} {0:>9} {120:>9}   00:00:03" for source in sources]
        lines.append("  Distance: (default is 120)")
        return "\n".join(lines) + "\n"

    def probe_dump(self, tables):
        """The document of `rip_probe.py dump`."""
        if not self.probe_answers:
            return ''
        interfaces = {}
        for net, interface in self.lab.PROBE_IFACES.items():
            sources = interfaces.setdefault(interface, {})
            for name, r in self.routers.items():
                if net not in r.nets or not r.rip or net not in r.enabled:
                    continue
                if (name, net) in self.unheard:
                    # RIP was just enabled there: one request went out, the first update is due
                    sources[str(r.ips[net].ip)] = {'age': None, 'packets': 0, 'version': None, 'dst': None,
                                                   'auth': None, 'requests': 1, 'unicast': 0, 'entries': {}}
                    continue
                # a passive interface was heard before it became passive: an old record stays
                age = 400.0 if net in r.passive else 2.5
                key = r.key(net)
                if key is None:
                    auth = {'type': 'none'}
                else:
                    auth = {'type': 'md5', 'key_id': key[0], 'auth_len': 20,
                            'valid': key[1] == self.d.key_secret}
                entries = {prefix: {'metric': metric, 'next_hop': '0.0.0.0', 'tag': 0, 'age': age}
                           for prefix, metric in self.announcement(tables, name, net).items()}
                sources[str(r.ips[net].ip)] = {'age': age, 'packets': 40, 'version': 2, 'dst': '224.0.0.9',
                                               'auth': auth, 'requests': 1, 'unicast': 0, 'entries': entries}
            if net == 'lan3' and self.rogue:
                sources[str(self.d.ips.intruder.ip)] = {
                    'age': 0.7, 'packets': 300, 'version': 2, 'dst': '224.0.0.9', 'auth': {'type': 'none'},
                    'requests': 0, 'unicast': 0,
                    'entries': {str(self.d.nets.ghost): {'metric': 1, 'next_hop': '0.0.0.0', 'tag': 0, 'age': 0.7}}}
        return json.dumps({'errors': [], 'uptime': self.probe_uptime, 'heartbeat_age': self.probe_heartbeat_age,
                           'interfaces': interfaces})

    def output(self, machine, command, tables):
        """(stdout, exit code) of *command* on *machine*."""
        if command == f'python3 {RIP_PROBE_PATH} dump':
            assert machine == 'probe'
            return self.probe_dump(tables), 0
        m = re.fullmatch(r'ping -c 2 -w 3 (\S+)', command)
        if m:
            ok = self.ping(machine, ip_address(m.group(1)), tables)
            return (f"64 bytes from {m.group(1)}: icmp_seq=1 ttl=61 time=0.2 ms\n" if ok else ''), (0 if ok else 1)
        assert machine in self.routers, (machine, command)
        if command == 'vtysh -c "show ip rip"':
            return self.show_ip_rip(machine, tables), 0
        if command == 'vtysh -c "show ip rip status"':
            return self.show_ip_rip_status(machine, tables), 0
        if command == 'ip -j route':
            return json.dumps(self.kernel(machine, tables)), 0
        if command == 'ip -j -6 route show':
            return json.dumps(self.kernel6(machine)), 0
        if command in ('vtysh -c "show running-config"', 'vtysh -c "show ip route"'):
            return 'Building configuration...\n', 0
        raise AssertionError(f"unexpected command on {machine}: {command}")


def _simulate(lab, data, tmp_pub_dir, world=None, final=True, instructor_mode=False, answers=True):
    """Multi-pass grade() like run_tests(): returns (grade, net_scheme).  *world*: a function
    ``World -> None`` changing the model after it was configured (the final state when *final*)."""
    name = _running_name()
    marker = Path(params.instructor_mode_marker_filename(name))
    if instructor_mode:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    elif marker.exists():
        marker.unlink()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    model = World(lab, ns, final=final)
    if world is not None:
        world(model)
    tables = model.tables()
    ns = lab.NetScheme(data=data, running_lab_name=name)
    grade = lab.Grade(net_scheme=ns)
    keys, step = None, 1
    while True:
        grade.reset_before_grade()
        grade.grade()
        current = {(m, s): set(cmds) for (m, s), cmds in grade.get_tests().items()}
        if keys is None:
            keys = current
            if answers:
                grade._answers = dict(grade.get_cheat_answers('final') or {})
        else:
            assert current == keys, "the registered tests changed between two passes"
        if step > grade.max_step:
            break
        for (m, s), cmds in grade.get_tests().items():
            if s == step:
                for key in list(cmds):
                    cmds[key] = model.output(m, key[0], tables)
        step += 1
    return grade, ns


def _grades(grade):
    return {str(e.title): (e.grade, e.max_grade) for e in grade.get_grade_list()}


def _totals(grade):
    """(regular points, bonus points)."""
    elements = grade.get_grade_list()
    return (sum(e.grade for e in elements if not e.bonus), sum(e.grade for e in elements if e.bonus))


def _lost(grade):
    """Titles of the elements that are not at their maximum."""
    return {title for title, (got, best) in _grades(grade).items() if got != best}


def _part(grade, key):
    """Points earned in the grade part *key* (``part3``)."""
    title = next(str(p.title) for p in grade.get_grade_parts() if str(p.title) == key)
    return sum(e.grade for e in grade.get_grade_list() if str(e.grade_part) == title)


# what a student types, part by part (the solutions of the instructor texts)
def _part1(w):
    w.configure('r1', 'router rip', f'network {w.d.nets.lan1}', 'exit')


def _part2(w):
    d = w.d
    w.configure('r3', 'router rip', 'version 2', f'network {d.nets.lan3}', f'network {d.nets.l13}',
                f'network {d.nets.l23}', f'network {d.nets.l34}', 'exit')
    w.configure('r4', 'router rip', 'version 2', f'network {d.nets.l14}', f'network {d.nets.l34}', 'exit')
    w.configure('r1', 'router rip', f'network {d.nets.l13}', f'network {d.nets.l14}', 'exit')
    w.configure('r2', 'router rip', f'network {d.nets.l23}', 'exit')


# ---------------------------------------------------------------------------
# data and topology
# ---------------------------------------------------------------------------


class TestData:
    def test_round_trip(self, lab, data):
        assert lab.Data.from_json(data.to_json()).to_json() == data.to_json()
        assert lab.Data.unpack(data.pack()).to_json() == data.to_json()

    def test_values(self, lab):
        for d in [lab.Data.generate() for _ in range(40)]:
            assert (d.update_timer, d.timeout_timer, d.garbage_timer) in lab.TIMER_PRESETS
            assert 5 <= d.update_timer and d.timeout_timer == 3 * d.update_timer
            # the backup link must lose against the ring (metric 3), without reaching infinity
            assert 2 + d.backup_offset > 3 and d.static_metric + d.backup_offset + 2 < INFINITY
            assert 2 <= d.key_id <= 255 and len(d.key_secret) <= 16 and d.key_secret.isalnum()

    def test_addressing(self, lab):
        for d in [lab.Data.generate() for _ in range(40)]:
            site = d.nets.site
            assert site.prefixlen == 16 and site.subnet_of(IPv4Network('10.0.0.0/8'))
            assert site != IPv4Network('10.0.0.0/16')
            for net, octet in lab.SITE_OCTETS.items():
                prefix = getattr(d.nets, net)
                assert prefix.subnet_of(site) and int(str(prefix.network_address).split('.')[2]) == octet
                assert prefix.prefixlen == (24 if net in lab.LANS else 30)
                assert str(getattr(d.nets6, net)).endswith(f":{octet}::/64")
            assert d.nets.vmnet.subnet_of(site) and d.nets.vmnet not in [getattr(d.nets, n) for n in lab.SITE_NETS]
            for outside in (d.nets.wan, d.nets.ghost):
                assert not outside.overlaps(IPv4Network('10.0.0.0/8'))
                assert not outside.overlaps(IPv4Network('172.17.0.0/16')) and outside.is_private
            assert d.ips.vm.ip in d.nets.vmnet and d.ips.intruder.ip in d.nets.lan3
            addresses = [ip.ip for ip in vars(d.ips).values()]
            assert len(addresses) == len(set(addresses))
            for router, ifaces in lab.ROUTER_IFACES.items():
                for net, attr in ifaces:
                    assert getattr(d.ips, attr).ip in getattr(d.nets, net)
                    if net != 'wan':
                        assert str(getattr(d.ips6, attr).ip).endswith(f"::{router[1:]}")
            assert not hasattr(d.ips6, 'r4_wan')
            assert str(d.ips6.pc1.ip).endswith('::100') and d.ips6.hv.ip in d.nets6.lan3


class TestTopology:
    def test_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert set(ns.get_machine_names()) == {'r1', 'r2', 'r3', 'r4', 'pc1', 'pc2', 'hv', 'isp', 'probe', 'intruder'}
        specs = lab.NetScheme._machine_specs
        for router in lab.ROUTER_IFACES:
            assert specs[router]['image'].startswith('sysreseval/frr:')
            assert 'net.ipv6.conf.all.keep_addr_on_down=1' in specs[router]['sysctls']
        for hidden in ('probe', 'intruder'):
            assert specs[hidden] == {'hidden': True, 'allow_connection': False, 'ipv6': False}
        assert specs['isp']['allow_connection'] is False and specs['isp']['ipv6'] is False
        assert lab.ipv6 is True and lab.export_kathara_project is False

    def test_interfaces_follow_the_tables(self, lab):
        for router, ifaces in lab.ROUTER_IFACES.items():
            for n, (net, attr) in enumerate(ifaces):
                assert lab._TOPOLOGY[net][router] == n and attr == f"{router}_{net}"
                assert lab.iface(router, net) == f"eth{n}"
        # the probe listens on every site network, in the order of PROBE_IFACES, and nowhere else
        assert list(lab.PROBE_IFACES) == lab.SITE_NETS
        for net, interface in lab.PROBE_IFACES.items():
            assert f"eth{lab._TOPOLOGY[net]['probe']}" == interface
        assert 'probe' not in lab._TOPOLOGY['wan'] and lab._TOPOLOGY['lan3']['intruder'] == 0
        for link, ends in lab.TRANSIT.items():
            assert set(lab._TOPOLOGY[link]) == set(ends) | {'probe'}
        for lan, router in lab.LANS.items():
            assert lab._TOPOLOGY[lan][router] == 0

    def test_net_config(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        assert ns.net_config['probe'] == [([], [])] * 8                    # up, without any address
        assert ns.net_config['intruder'] == [([data.ips.intruder], [])]
        assert ns.net_config['r4'][2] == ([data.ips.r4_wan], [])           # no IPv6 towards the ISP
        assert ns.net_config['r1'][1] == ([data.ips.r1_l12, data.ips6.r1_l12], [])
        addresses, routes = ns.net_config['pc1'][0]
        assert addresses == [data.ips.pc1, data.ips6.pc1]
        assert [str(net) for net, _gw in routes] == ['0.0.0.0/0', '::/0']
        assert [gw for _net, gw in routes] == [data.ips.r1_lan1.ip, data.ips6.r1_lan1.ip]
        isp_addresses, isp_routes = ns.net_config['isp'][0]
        assert isp_addresses == [data.ips.isp, lab.INTERNET_HOST] and isp_routes == [(data.nets.site, data.ips.r4_wan.ip)]


# ---------------------------------------------------------------------------
# states
# ---------------------------------------------------------------------------


class TestStates:
    def test_initial(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        assert {step for step, _m in ops} == {1, 2}
        # FRR starts at step 2, once the listener is up
        for router in lab.ROUTER_IFACES:
            assert _cmds(ops, 2, router) == ['systemctl start frr']
            files = _files(ops, 1, router)
            assert 'ripd=yes' in files['/etc/frr/daemons'] and 'ripngd=yes' in files['/etc/frr/daemons']
            assert 'ospfd=no' in files['/etc/frr/daemons']
            assert files['/etc/frr/vtysh.conf'] == 'service integrated-vtysh-config\n'
            assert f'sysctl -w net.ipv4.ip_forward=1' in _cmds(ops, 1, router)
        conf = {router: _files(ops, 1, router)['/etc/frr/frr.conf'] for router in lab.ROUTER_IFACES}
        assert f' network {data.nets.l12}\n' in conf['r1'] and str(data.nets.lan1) not in conf['r1']
        assert f' network {data.nets.l12}\n' in conf['r2'] and f' network {data.nets.lan2}\n' in conf['r2']
        assert 'router rip' not in conf['r3'] and 'router rip' not in conf['r4']
        assert f'ip route 0.0.0.0/0 {data.ips.isp.ip}\n' in conf['r4']
        for router in ('r1', 'r2'):
            assert ' version 2\n' in conf[router]
        for host in lab.HOST_ROUTER:
            assert 'sysctl -w net.ipv4.ip_forward=0' in _cmds(ops, 1, host)
            assert 'sysctl -w net.ipv6.conf.all.forwarding=0' in _cmds(ops, 1, host)
        assert f'ip addr add {data.ips.vm} dev lo' in _cmds(ops, 1, 'hv')
        for router in lab.TRANSIT[lab.BACKUP_LINK]:
            assert f'tc qdisc replace dev {lab.iface(router, lab.BACKUP_LINK)} root netem delay 20ms' in _cmds(ops, 1, router)

    def test_hidden_machines(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'initial')
        script = (_REPO / 'lib' / 'rip_probe.py').read_text()
        for hidden in ('probe', 'intruder'):
            assert _files(ops, 1, hidden) == {RIP_PROBE_PATH: script}
            assert 'sysctl -w net.ipv4.ip_forward=0' in _cmds(ops, 1, hidden)
            assert not _cmds(ops, 2, hidden)
        listen = _cmds(ops, 1, 'probe')[-1]
        assert f'python3 {RIP_PROBE_PATH} listen ' in listen
        spec = rip_probe._spec(listen.rstrip("'").split()[-1])
        assert spec == {'interfaces': [f'eth{n}' for n in range(8)], 'keys': {str(data.key_id): data.key_secret}}
        assert [c for c in _cmds(ops, 1, 'probe') if c.startswith('ip ')] == [f'ip link set eth{n} up' for n in range(8)]
        announce = _cmds(ops, 1, 'intruder')[-1]
        assert rip_probe._spec(announce.rstrip("'").split()[-1]) == {
            'source': str(data.ips.intruder.ip), 'interval': lab.GHOST_INTERVAL, 'routes': [[str(data.nets.ghost), 1]]}
        # the rogue announcements must outpace the shortest timeout of `timers basic`
        assert lab.GHOST_INTERVAL < 5
        # nothing a student can read names a hidden machine or what it announces
        for machine in list(lab.ROUTER_IFACES) + list(lab.HOST_ROUTER):
            hosts = _files(ops, 1, machine)['/etc/hosts']
            assert str(data.ips.intruder.ip) not in hosts and 'intruder' not in hosts and 'probe' not in hosts
            assert f"{data.ips.vm.ip}\tvm\n" in hosts and "203.0.113.1\tinternet\n" in hosts
            assert f"{data.ips.r3_l23.ip}\tr3-eth2\n" in hosts and f"{data.ips6.hv.ip}\thv-v6\n" in hosts
        assert '/etc/hosts' not in _files(ops, 1, 'isp')

    def test_final(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        ops = _state_ops(ns, 'final')
        assert set(ops) == {(step, router) for step in (1, 2, 3) for router in lab.ROUTER_IFACES} | {(4, 'r1')}
        for router in lab.ROUTER_IFACES:
            (command,) = _cmds(ops, 1, router)
            lines = _vtysh_commands(command)
            assert lines[:5] == [f'key chain {lab.KEY_CHAIN}', f'key {data.key_id}', f'key-string {data.key_secret}',
                                 'exit', 'exit']
            assert f'timers basic {data.update_timer} {data.timeout_timer} {data.garbage_timer}' in lines
            assert '"' not in ' '.join(lines)
        # the routes are cleared on the four routers at once, twice (a router cleared alone learns
        # the rogue route again from its neighbours); the wait covers a whole window
        for step in (2, 3):
            for router in lab.ROUTER_IFACES:
                assert _cmds(ops, step, router) == ['vtysh -c "clear ip rip"']
        (wait,) = _cmds(ops, 4, 'r1')
        assert int(wait.split()[1]) > rip_window(data.update_timer) and int(wait.split()[1]) < 60
        r3 = _vtysh_commands(_cmds(ops, 1, 'r3')[0])
        assert f'ip route {data.nets.vmnet} {data.ips.hv.ip}' in r3
        assert f'redistribute static metric {data.static_metric}' in r3 and 'ip rip receive version none' in r3
        assert f'offset-list {lab.OFFSET_ACL} out {data.backup_offset} eth1' in r3 and 'allow-ecmp' in r3
        r4 = _vtysh_commands(_cmds(ops, 1, 'r4')[0])
        assert 'default-information originate' in r4 and 'passive-interface eth0' not in r4
        assert not any('eth2' in line for line in r4)                       # nothing on wan
        r1 = _vtysh_commands(_cmds(ops, 1, 'r1')[0])
        assert r1.count('ip rip authentication mode md5') == 3 and 'ip rip split-horizon poisoned-reverse' in r1

    def test_the_model_reads_the_final_state(self, lab, data):
        """The interpreter of the tests understands every command of the reference solution."""
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        world = World(lab, ns, final=True)
        for name, router in world.routers.items():
            assert router.rip and router.version2
            assert router.enabled == set(router.nets) - {'wan'} and router.ripng == router.enabled
            assert router.timers == (data.update_timer, data.timeout_timer, data.garbage_timer)
            for link in router.nets:
                if link in lab.TRANSIT:
                    assert router.key(link) == (data.key_id, data.key_secret)
        assert world.routers['r1'].passive == {'lan1'} and world.routers['r4'].passive == set()
        assert world.routers['r3'].deaf == {'lan3'} and world.routers['r3'].redistribute_static == data.static_metric
        assert world.routers['r1'].offsets == {'l13': data.backup_offset} and world.routers['r3'].ecmp
        assert world.routers['r1'].poisoned == {'l12'} == world.routers['r2'].poisoned
        assert world.routers['r4'].default_originate and world.routers['r4'].static == {DEFAULT: data.ips.isp.ip}


# ---------------------------------------------------------------------------
# the model itself
# ---------------------------------------------------------------------------


class TestModel:
    def test_final_tables(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        world = World(lab, ns, final=True)
        tables = world.tables()
        lan3, vmnet = str(data.nets.lan3), str(data.nets.vmnet)
        # r1 reaches lan3 by the ring, with both next hops
        assert sorted((p.via, p.metric) for p in tables['r1'][lan3]) == [('r2', 3), ('r4', 3)]
        assert [(p.via, p.metric) for p in tables['r2'][vmnet]] == [('r3', data.static_metric + 1)]
        assert [(p.via, p.metric) for p in tables['r2'][DEFAULT]] in ([('r1', 3)], [('r3', 3)])
        assert str(data.nets.ghost) not in tables['r3']
        # what the outputs say is what the parsers of the grader read
        routes = parse_rip_routes(world.show_ip_rip('r1', tables))
        assert [(p['nexthop'], p['metric']) for p in routes[lan3]] in (
            [(str(data.ips.r2_l12.ip), 3), (str(data.ips.r4_l14.ip), 3)],
            [(str(data.ips.r4_l14.ip), 3), (str(data.ips.r2_l12.ip), 3)])
        status = parse_rip_status(world.show_ip_rip_status('r3', tables))
        assert (status['update'], status['timeout'], status['garbage']) == (
            data.update_timer, data.timeout_timer, data.garbage_timer)
        assert status['passive_interfaces'] == ['eth0'] and status['redistribute'] == ['static']
        assert status['interfaces']['eth0']['receive'] == 'none'
        assert status['interfaces']['eth1']['key_chain'] == lab.KEY_CHAIN
        # on the backup link r3 offers lan3 with the offset; on l12 r1 poisons what it got from r2
        assert world.announcement(tables, 'r3', 'l13')[lan3] == 1 + data.backup_offset
        on_l12 = world.announcement(tables, 'r1', 'l12')
        assert on_l12[str(data.nets.lan2)] == INFINITY and on_l12[str(data.nets.l12)] == INFINITY
        assert on_l12[str(data.nets.lan1)] == 1

    def test_initial_tables(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        world = World(lab, ns)
        tables = world.tables()
        assert set(tables['r1']) == {str(data.nets.l12), str(data.nets.lan2)}
        assert set(tables['r2']) == {str(data.nets.l12), str(data.nets.lan2)}
        assert tables['r3'] == {} and tables['r4'] == {}
        assert world.show_ip_rip('r3', tables) == "% RIP instance not found\n"
        assert not world.ping('pc1', data.ips.pc2.ip, tables) and not world.ping('pc2', data.ips.pc1.ip, tables)
        # simple split horizon: nothing about lan2 nor about the link itself goes back to r2
        assert world.announcement(tables, 'r1', 'l12') == {}

    def test_rogue_route_spreads(self, lab, data):
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        world = World(lab, ns)
        _part1(world)
        _part2(world)
        tables = world.tables()
        ghost = str(data.nets.ghost)
        assert [(p.via, p.metric) for p in tables['r3'][ghost]] == [('intruder', 2)]
        assert tables['r1'][ghost][0].metric == 3 and tables['r4'][ghost][0].metric == 3
        # a passive interface still listens
        world.configure('r3', 'router rip', 'passive-interface eth0', 'exit')
        assert ghost in world.tables()['r1']


# ---------------------------------------------------------------------------
# grading
# ---------------------------------------------------------------------------


class TestGrading:
    def test_nothing_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, final=False, answers=False)
        assert {title: got for title, (got, _best) in _grades(grade).items() if got} == {}
        elements = grade.get_grade_list()
        assert sum(e.max_grade for e in elements if not e.bonus) == 100
        assert sum(e.max_grade for e in elements if e.bonus) == 6
        assert len(elements) == 47 and len({str(e.title) for e in elements}) == 47

    def test_everything_done(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        assert _lost(grade) == set()
        assert _totals(grade) == (100, 6)
        assert [_part(grade, f'part{n}') for n in range(1, 10)] == [9, 14, 13, 10, 11, 10, 15, 18, 6]

    def test_scopes(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        elements = grade.get_grade_list()
        exo = [e for e in elements if e.scope == params.EXO_EVAL_SCOPE]
        assert sum(e.max_grade for e in exo) == 23 and all(e.scope == params.BOTH_EVAL_SCOPE for e in elements
                                                           if e not in exo)
        assert [str(e.title) for e in elements if e.bonus] == ['ripng_routes', 'ripng_pings']
        # the answers alone, without any configuration, only give the instructor-only points
        answers_only, _ = _simulate(lab, data, tmp_pub_dir, final=False)
        assert _totals(answers_only) == (23, 0)
        assert _lost(answers_only) == {str(e.title) for e in elements if e not in exo}

    def test_every_data_set(self, lab, tmp_pub_dir):
        for _ in range(12):
            d = lab.Data.generate()
            d.compute_post_generate()
            assert _totals(_simulate(lab, d, tmp_pub_dir)[0]) == (100, 6)
            assert _totals(_simulate(lab, d, tmp_pub_dir, final=False, answers=False)[0]) == (0, 0)

    def test_part_by_part(self, lab, data, tmp_pub_dir):
        """A part does not give the points of the next ones."""
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=_part1, final=False, answers=False)
        assert {t: g for t, (g, _m) in _grades(grade).items() if g} == {
            'discovery_lan1_announced': 2, 'discovery_pings': 2}

        def parts_1_2(w):
            _part1(w)
            _part2(w)
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=parts_1_2, final=False, answers=False)
        assert {t: g for t, (g, _m) in _grades(grade).items() if g} == {
            'discovery_lan1_announced': 2, 'discovery_pings': 2,
            'site_r3': 2, 'site_r4': 2, 'site_tables': 4, 'site_pings': 4}

        def parts_1_2_4(w):
            parts_1_2(w)
            for router in ('r1', 'r2', 'r3'):
                w.configure(router, 'router rip', 'passive-interface eth0', 'exit')
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=parts_1_2_4, final=False, answers=False)
        assert _part(grade, 'part4') == 9 and _part(grade, 'part8') == 0 and _totals(grade) == (16 + 9, 0)

    def test_interface_not_heard_yet_is_not_passive(self, lab, data, tmp_pub_dir):
        """Right after `network lan1` r1 has sent no update on lan1 yet (the first one is due up
        to a period later): that silence is not a passive interface.  Seen on the live lab."""
        def just_enabled(w):
            _part1(w)
            w.unheard.add(('r1', 'lan1'))
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=just_enabled, final=False, answers=False)
        assert _grades(grade)['passive_lan1'] == (0, 3)
        assert {t: g for t, (g, _m) in _grades(grade).items() if g} == {
            'discovery_lan1_announced': 2, 'discovery_pings': 2}

    def test_passive_from_the_start_is_never_heard(self, lab, data, tmp_pub_dir):
        """The final state makes lan1 passive in the session that enables RIP on it: r1 only
        ever sent a request there (as on the live lab), and the element is given."""
        def never_heard(w):
            w.unheard.add(('r1', 'lan1'))
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=never_heard)[0]) == set()

    def test_version_2_is_asked(self, lab, data, tmp_pub_dir):
        def no_version(w):
            _part1(w)
            _part2(w)
            w.configure('r3', 'router rip', 'no version 2', 'exit')
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=no_version, final=False, answers=False)
        assert _grades(grade)['site_r3'] == (0, 2) and _grades(grade)['site_r4'] == (2, 2)

    def test_probe_that_just_started(self, lab, data, tmp_pub_dir):
        """A silence is trusted only when the probe has listened for a whole window."""
        def restarted(w):
            w.probe_uptime = 4.0
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=restarted)
        assert _lost(grade) == {'passive_lan1', 'passive_lan2', 'passive_lan3'}

    def test_dead_probe(self, lab, data, tmp_pub_dir):
        def dead(w):
            w.probe_heartbeat_age = 300.0
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=dead)[0]) == {
            'passive_lan1', 'passive_lan2', 'passive_lan3'}

    def test_silent_probe(self, lab, data, tmp_pub_dir):
        """Without the probe nothing that is graded on the announcements is given."""
        def silent(w):
            w.probe_answers = False
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=silent)[0]) == {
            'convergence_poisoned_reverse', 'passive_lan1', 'passive_lan2', 'passive_lan3',
            'backup_offset_r1', 'backup_offset_r3', 'backup_path_r1', 'backup_path_r3', 'ecmp_r1', 'ecmp_r3',
            'auth_l12', 'auth_l13', 'auth_l14', 'auth_l23', 'auth_l34'}

    def test_passive_forgotten(self, lab, data, tmp_pub_dir):
        def forgotten(w):
            w.configure('r2', 'router rip', 'no passive-interface eth0', 'exit')
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=forgotten)[0]) == {'passive_lan2'}

    def test_lan_removed_instead_of_passive(self, lab, data, tmp_pub_dir):
        """`no network` silences the LAN, but nobody learns it any more."""
        def removed(w):
            w.configure('r2', 'router rip', f'no network {w.d.nets.lan2}', 'exit')
        lost = _lost(_simulate(lab, data, tmp_pub_dir, world=removed)[0])
        assert 'passive_lan2' in lost and 'passive_lan1' not in lost and 'discovery_pings' in lost

    def test_backup_link_out_of_rip(self, lab, data, tmp_pub_dir):
        """Leaving l13 out of RIP also sends the traffic round the ring: not what is asked."""
        def without_l13(w):
            for router in ('r1', 'r3'):
                w.configure(router, 'router rip', f'no network {w.d.nets.l13}', 'exit')
        world_tables = {}

        def capture(w):
            without_l13(w)
            world_tables.update(w.tables())
        lost = _lost(_simulate(lab, data, tmp_pub_dir, world=capture)[0])
        # the tables are those of the reference solution...
        assert sorted(p.via for p in world_tables['r1'][str(data.nets.lan3)]) == ['r2', 'r4']
        # ... but nothing of part 7 is given, nor the authentication of the link; and r2 and r4
        # do not know the network of l13 any more
        assert lost == {'backup_offset_r1', 'backup_offset_r3', 'backup_path_r1', 'backup_path_r3', 'ecmp_r1',
                        'ecmp_r3', 'auth_l13', 'site_tables'}

    def test_no_offset(self, lab, data, tmp_pub_dir):
        def no_offset(w):
            for router in ('r1', 'r3'):
                w.routers[router].offsets.clear()
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=no_offset)[0]) == {
            'backup_offset_r1', 'backup_offset_r3', 'backup_path_r1', 'backup_path_r3', 'ecmp_r1', 'ecmp_r3'}

    def test_no_ecmp(self, lab, data, tmp_pub_dir):
        def no_ecmp(w):
            w.configure('r1', 'router rip', 'no allow-ecmp', 'exit')
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=no_ecmp)[0]) == {'ecmp_r1'}

    def test_poisoned_reverse_on_one_end(self, lab, data, tmp_pub_dir):
        def one_end(w):
            w.routers['r2'].poisoned.clear()
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=one_end)
        assert _lost(grade) == {'convergence_poisoned_reverse'}
        assert _grades(grade)['convergence_poisoned_reverse'] == (2, 4)

    def test_timers_missing_on_one_router(self, lab, data, tmp_pub_dir):
        def default_timers(w):
            w.routers['r4'].timers = (30, 180, 120)
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=default_timers)
        assert _lost(grade) == {'convergence_timers'} and _grades(grade)['convergence_timers'] == (3, 4)

    def test_rogue_still_believed(self, lab, data, tmp_pub_dir):
        def believed(w):
            w.routers['r3'].deaf.clear()
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=believed)[0]) == {'rogue_ignored'}

    def test_rogue_stopped_by_redistribution(self, lab, data, tmp_pub_dir):
        """Another accepted answer: no RIP on lan3, which is announced as a connected network.
        (The model has no `redistribute connected`: lan3 is then unknown elsewhere.)"""
        def no_rip_on_lan3(w):
            w.routers['r3'].deaf.clear()
            w.configure('r3', 'router rip', f'no network {w.d.nets.lan3}', 'exit')
        lost = _lost(_simulate(lab, data, tmp_pub_dir, world=no_rip_on_lan3)[0])
        # the bogus route is gone, but lan3 must still be announced for the points
        assert 'rogue_ignored' in lost and 'passive_lan3' in lost

    def test_authentication_string(self, lab, data, tmp_pub_dir):
        """The right secret without the key chain: the neighbours agree, but the key id is 1."""
        def string(w):
            for router in w.routers.values():
                for net in list(router.md5):
                    router.string_of[net] = w.d.key_secret
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=string)[0]) == {
            'auth_l12', 'auth_l13', 'auth_l14', 'auth_l23', 'auth_l34'}

    def test_another_secret(self, lab, data, tmp_pub_dir):
        def other(w):
            for router in w.routers.values():
                router.key_chains[lab.KEY_CHAIN] = {w.d.key_id: 'anotherSecret'}
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=other)[0]) == {
            'auth_l12', 'auth_l13', 'auth_l14', 'auth_l23', 'auth_l34'}

    def test_authentication_on_one_end(self, lab, data, tmp_pub_dir):
        """r2 without authentication on l23: the two routers reject each other on that link."""
        def one_end(w):
            w.routers['r2'].md5.discard('l23')
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=one_end)
        assert _grades(grade)['auth_l23'] == (1, 2)
        # the site is still connected, but r2 is one hop further from lan3 and from vmnet: the
        # ring no longer offers two equal paths between r1 and r3
        assert _lost(grade) == {'auth_l23', 'ecmp_r1', 'ecmp_r3', 'static_metric'}

    def test_no_authentication(self, lab, data, tmp_pub_dir):
        def none(w):
            for router in w.routers.values():
                router.md5.clear()
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=none)[0]) == {
            'auth_l12', 'auth_l13', 'auth_l14', 'auth_l23', 'auth_l34'}

    def test_no_default_route(self, lab, data, tmp_pub_dir):
        def no_default(w):
            w.configure('r4', 'router rip', 'no default-information originate', 'exit')
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=no_default)[0]) == {'default_routes', 'default_pings'}

    def test_static_route_not_redistributed(self, lab, data, tmp_pub_dir):
        def local_only(w):
            w.configure('r3', 'router rip', 'no redistribute static', 'exit')
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=local_only)[0]) == {
            'static_redistributed', 'static_metric', 'static_pings'}

    def test_static_route_with_the_default_metric(self, lab, data, tmp_pub_dir):
        def metric_1(w):
            w.configure('r3', 'router rip', 'redistribute static', 'exit')
        assert _lost(_simulate(lab, data, tmp_pub_dir, world=metric_1)[0]) == {'static_metric'}

    def test_no_ripng(self, lab, data, tmp_pub_dir):
        def ipv4_only(w):
            w.routers['r2'].ripng.clear()
        grade, _ = _simulate(lab, data, tmp_pub_dir, world=ipv4_only)
        assert _lost(grade) == {'ripng_routes', 'ripng_pings'} and _totals(grade) == (100, 0)

    def test_wrong_answers(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir, answers=False)
        elements = grade.get_grade_list()
        assert _lost(grade) == {str(e.title) for e in elements if e.scope == params.EXO_EVAL_SCOPE}
        assert _totals(grade) == (77, 6)

    def test_cheat_answers_fill_every_form(self, lab, data, tmp_pub_dir):
        grade, _ = _simulate(lab, data, tmp_pub_dir)
        cheat = grade.get_cheat_answers('final')
        forms = [q for q in grade.get_questions_ordered() if getattr(q, 'fields', None)]
        assert len(forms) == 8
        for q in forms:
            answers = cheat[q.question_hash]
            answers = json.loads(answers) if isinstance(answers, str) else answers
            assert set(answers) == {field['name'] for field in q.fields}
            for field in q.fields:
                if 'choices' in field:
                    assert answers[field['name']] in field['choices'], (field['name'], answers[field['name']])
                elif 'regex' in field:
                    assert re.fullmatch(field['regex'], answers[field['name']]), (field['name'], answers[field['name']])


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
        assert len(g1.get_questions_ordered()) == 18
        assert not any(has_instructor(t) for _, t in _all_texts(g0, ns0))
        with_fragment = [w for w, t in _all_texts(g1, ns1) if has_instructor(t)]
        assert len(with_fragment) == 18 and 'informations' not in with_fragment

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
        assert [s.number for s in numbering.sections('fr') if s.level == 1] == [str(i) for i in range(1, 9)]
        assert [s.tag for s in numbering.sections('fr')] == [
            'principle', 'metric', 'messages', 'versions', 'timers', 'loops', 'frr', 'passive', 'redistribution',
            'tuning', 'security', 'ripng', 'diagnostic']
        assert '## <a id="timers"></a>3. Les temporisateurs' in informations
        assert '- [3. Les temporisateurs](#timers)' in informations and '(section [4](#loops))' in informations
        assert '@@' not in informations
        # every reference of a question names a section of the course
        for q in g1.get_questions_ordered():
            description = _text(resolve_text(q.description, numbering))
            assert '@@ref' not in description and '@@sec' not in description, _text(q.title)
        # the course has no summary of the questions and no value of the instance
        for value in (str(data.nets.site), str(data.key_secret), str(data.nets.ghost), 'Partie 1'):
            assert value not in informations

    def test_students_never_read_the_hidden_machines(self, lab, data, tmp_pub_dir):
        g0, ns0 = _simulate(lab, data, tmp_pub_dir, instructor_mode=False)
        student = "\n".join(text for _where, text in _all_texts(g0, ns0))
        for secret in (str(data.ips.intruder.ip), str(data.nets.ghost), 'intruder', 'probe', 'sonde'):
            assert secret not in student, secret
        g1, ns1 = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        instructor = "\n".join(text for _where, text in _all_texts(g1, ns1))
        assert str(data.ips.intruder.ip) in instructor and str(data.nets.ghost) in instructor
        # the values of the instance are in the first question, not in the course
        first = _text(g0.get_questions_ordered()[0].description)
        for value in (data.key_secret, str(data.nets.site), str(data.nets.vmnet), f"**{data.key_id}**"):
            assert value in first

    def test_form_fields_are_well_formed(self, lab, data, tmp_pub_dir):
        g1, _ = _simulate(lab, data, tmp_pub_dir, instructor_mode=True)
        fields = 0
        for q in g1.get_questions_ordered():
            for m in re.finditer(r'@@\{([^:}]+):([^}]*)\}@@', _text(q.description)):
                fields += 1
                assert '}' not in m.group(2)
        assert fields == 8 + 2 + 5 + 1 + 2 + 2 + 3 + 3
        for q in g1.get_questions_ordered():
            for field in getattr(q, 'fields', None) or []:
                assert {'regex', 'choices'} & field.keys(), field

    def test_strip_instructor(self, lab, data, tmp_pub_dir, tmp_path):
        from strip_instructor import strip_source
        source = _LAB_PATH.read_bytes()
        result = strip_source(source)
        assert result.calls == source.count(b'instructor(tr(') == 18 and result.warnings == []
        assert b'Solution' not in result.data and b"Pour l'enseignant" not in result.data
        stripped = tmp_path / 'rip_stripped.py'
        stripped.write_bytes(result.data)
        spec = importlib.util.spec_from_file_location('rip_lab_stripped', stripped)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        grade, _ = _simulate(module, data, tmp_pub_dir, instructor_mode=True)
        assert _totals(grade) == (100, 6)
        assert not any(has_instructor(_text(q.description)) for q in grade.get_questions_ordered())

    def test_english_identifiers(self, lab, data):
        """Machines, networks, states, data fields, grade elements and part keys are English."""
        french = re.compile(r'(routeur|reseau|sonde|intrus|secours|panne|annonce|defaut|statique|cle_|_cle|'
                            r'partie|passif|metrique|temporisateur|boucle)', re.I)
        names = list(lab.NetScheme._machine_specs) + list(lab._TOPOLOGY)
        names += [name for name in dir(lab.NetScheme) if getattr(getattr(lab.NetScheme, name), '_is_sre_state', False)]
        names += [f.name for f in data.__dataclass_fields__.values()]
        names += list(vars(data.ips)) + list(vars(data.nets)) + list(vars(data.ips6)) + list(vars(data.nets6))
        ns = lab.NetScheme(data=data, running_lab_name=_running_name())
        grade = lab.Grade(net_scheme=ns)
        grade.reset_before_grade()
        grade.grade()
        names += [str(e.title) for e in grade.get_grade_list()] + [str(p.title) for p in grade.get_grade_parts()]
        names += [field['name'] for q in grade.get_questions_ordered() for field in getattr(q, 'fields', None) or []]
        assert 'initial' in names and 'final' in names and 'part9' in names and 'rogue_address' in names
        bad = [n for n in names if french.search(n) or not re.fullmatch(r'[a-z0-9_.]+', n)]
        assert not bad, bad
