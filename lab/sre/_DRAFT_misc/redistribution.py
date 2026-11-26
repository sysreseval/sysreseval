"""Route redistribution lab: exchanging routes between RIP, OSPF, BGP, static and connected routes.

IPv4 only, FRR on the ``netdev13`` image.  Eight independent sites, one per part (completing a part
gives all its points whatever the others).  In every site the routing protocols themselves are
given (adjacencies up, RIP running): the students only write the redistribution, its filters, tags,
distances and summaries.

- ``stat``: static, connected, kernel and default routes into OSPF (route-map on the connected
  networks, E1 / E2 metrics, a route added with ``ip route add`` that ``redistribute static``
  misses, ``default-information originate``);
- ``mut``: mutual redistribution RIP <-> OSPF at one border (seed metrics, the border's own
  connected networks);
- ``dual``: the same at two borders: the second border reaches the RIP networks through OSPF
  (distance 110 < 120), a naive redistribution there loops; fixed with tags (deny the routes that
  come back) and ``distance ospf external``;
- ``edge``: OSPF <-> BGP (OSPF into BGP filtered: origin incomplete, MED; the BGP default and one
  partner prefix into OSPF, never the whole table);
- ``fix``: a RIP / OSPF border shipped with four faults (RIP seed metric 15, a prefix-list without
  ``le``, a static route with a wrong next hop, no ``redistribute connected``);
- bonus ``sum`` (``summary-address`` with a tag on an ASBR), ``nssa`` (a stub area turned into an
  NSSA: type 7 LSAs translated to type 5 by the ABR) and ``agg`` (``aggregate-address
  summary-only`` of redistributed routes).

Grading reads ospfd (external LSAs, routes, areas), ripd (``show ip rip``: metrics and tags), bgpd
(the operator's table), the kernel routes and pings.  The states ``solve_<site>`` apply the
reference solution of one part, ``final`` all of them.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List, Optional

from SRE import params
from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from ping import eval_ping
from frr import (
    RIP_ROUTE_PROTOCOLS, get_bgp_routes, get_kernel_routes, get_ospf_external_lsas, get_ospf_info,
    get_ospf_neighbors, get_ospf_nssa_lsas, get_rip_routes, is_ospf_protocol, is_rip_protocol, kernel_route_gateways,
    neighbor_is_full, rip_route_metric,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Redistribution : échanger des routes entre RIP, OSPF, BGP et routes statiques",
           en="Route redistribution: exchanging routes between RIP, OSPF, BGP and static routes")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------

# FRR machines (routers, operators' routers) in ethN order: the network of each interface
ROUTER_IFACES = {
    # part 1: static, connected, kernel and default routes into OSPF
    'stat_asbr': ['stat_lan', 'stat_mgmt', 'stat_l12', 'stat_lgw'],
    'stat_ospf1': ['stat_l12', 'stat_lan2'],
    # part 2: RIP <-> OSPF at one border
    'mut_rip1': ['mut_lan1', 'mut_lrb'],
    'mut_b': ['mut_lrb', 'mut_lbo'],
    'mut_ospf1': ['mut_lbo', 'mut_lan2'],
    # part 3: RIP <-> OSPF at two borders
    'dual_rip1': ['dual_l1b1', 'dual_l1b2', 'dual_l12'],
    'dual_rip2': ['dual_l12', 'dual_l23'],
    'dual_rip3': ['dual_l23', 'dual_lan3'],
    'dual_b1': ['dual_l1b1', 'dual_lb1o'],
    'dual_b2': ['dual_l1b2', 'dual_lb2o'],
    'dual_ospf1': ['dual_lb1o', 'dual_lb2o', 'dual_lano'],
    # part 4: OSPF <-> BGP
    'edge_b': ['edge_l12', 'edge_lisp'],
    'edge_ospf1': ['edge_l12', 'edge_lan1', 'edge_lan2'],
    'edge_isp': ['edge_lisp', 'edge_linet'],
    # part 5: troubleshooting
    'fix_rip1': ['fix_lan1', 'fix_lrb'],
    'fix_b': ['fix_lrb', 'fix_lbo', 'fix_lgw'],
    'fix_ospf1': ['fix_lbo', 'fix_lan2'],
    # bonus: summarisation on an ASBR
    'sum_asbr': ['sum_l12', 'sum_lgw'],
    'sum_ospf1': ['sum_l12'],
    # bonus: NSSA
    'nssa_core': ['nssa_l01'],
    'nssa_abr': ['nssa_l01', 'nssa_l12'],
    'nssa_asbr': ['nssa_l12', 'nssa_lgw'],
    # bonus: BGP aggregation
    'agg_b': ['agg_l12', 'agg_lisp'],
    'agg_ospf1': ['agg_l12'],
    'agg_isp': ['agg_lisp'],
}
# hosts (one interface, eth0): their network and the router of their default route; the gateways
# (``*_gw``: networks on their lo, reached by static routes) are hosts too
HOSTS = {
    'stat_h1': ('stat_lan', 'stat_asbr'),
    'stat_h2': ('stat_lan2', 'stat_ospf1'),
    'stat_gw': ('stat_lgw', 'stat_asbr'),
    'mut_h1': ('mut_lan1', 'mut_rip1'),
    'mut_h2': ('mut_lan2', 'mut_ospf1'),
    'dual_h1': ('dual_lan3', 'dual_rip3'),
    'dual_h2': ('dual_lano', 'dual_ospf1'),
    'edge_h1': ('edge_lan1', 'edge_ospf1'),
    'edge_inet': ('edge_linet', 'edge_isp'),
    'fix_h1': ('fix_lan1', 'fix_rip1'),
    'fix_h2': ('fix_lan2', 'fix_ospf1'),
    'fix_gw': ('fix_lgw', 'fix_b'),
    'sum_gw': ('sum_lgw', 'sum_asbr'),
    'nssa_gw': ('nssa_lgw', 'nssa_asbr'),
}
# point-to-point links (/30): the first machine gets .1, the second .2
LINKS = {
    'stat_l12': ('stat_asbr', 'stat_ospf1'), 'stat_lgw': ('stat_asbr', 'stat_gw'),
    'mut_lrb': ('mut_rip1', 'mut_b'), 'mut_lbo': ('mut_b', 'mut_ospf1'),
    'dual_l1b1': ('dual_rip1', 'dual_b1'), 'dual_l1b2': ('dual_rip1', 'dual_b2'),
    'dual_l12': ('dual_rip1', 'dual_rip2'), 'dual_l23': ('dual_rip2', 'dual_rip3'),
    'dual_lb1o': ('dual_b1', 'dual_ospf1'), 'dual_lb2o': ('dual_b2', 'dual_ospf1'),
    'edge_l12': ('edge_b', 'edge_ospf1'), 'edge_lisp': ('edge_isp', 'edge_b'),
    'fix_lrb': ('fix_rip1', 'fix_b'), 'fix_lbo': ('fix_b', 'fix_ospf1'), 'fix_lgw': ('fix_b', 'fix_gw'),
    'sum_l12': ('sum_asbr', 'sum_ospf1'), 'sum_lgw': ('sum_asbr', 'sum_gw'),
    'nssa_l01': ('nssa_core', 'nssa_abr'), 'nssa_l12': ('nssa_abr', 'nssa_asbr'),
    'nssa_lgw': ('nssa_asbr', 'nssa_gw'),
    'agg_l12': ('agg_b', 'agg_ospf1'), 'agg_lisp': ('agg_isp', 'agg_b'),
}
# broadcast networks (/24): FRR machines get .1, .2... in the order of ROUTER_IFACES, hosts a random address
LANS = [n for n in dict.fromkeys(n for nets in ROUTER_IFACES.values() for n in nets) if n not in LINKS]

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _m, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_m] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

SITE_NUMBER = {'stat': 1, 'mut': 2, 'dual': 3, 'edge': 4, 'fix': 5, 'sum': 6, 'nssa': 7, 'agg': 8}
SITE_COLORS = {'stat': 'lightblue', 'mut': 'palegreen', 'dual': 'khaki', 'edge': 'plum', 'fix': 'lightsalmon',
               'sum': 'lightcyan', 'nssa': 'mistyrose', 'agg': 'wheat'}
ISPS = ('edge_isp', 'agg_isp')
GATEWAYS = ('stat_gw', 'fix_gw', 'sum_gw', 'nssa_gw')
ROUTERS = list(ROUTER_IFACES)

# the networks of each routing domain (what `router ospf` / `router rip` cover at start)
OSPF_NETS = {
    'stat_asbr': ['stat_l12'], 'stat_ospf1': ['stat_l12', 'stat_lan2'],
    'mut_b': ['mut_lbo'], 'mut_ospf1': ['mut_lbo', 'mut_lan2'],
    'dual_b1': ['dual_lb1o'], 'dual_b2': ['dual_lb2o'], 'dual_ospf1': ['dual_lb1o', 'dual_lb2o', 'dual_lano'],
    'edge_b': ['edge_l12'], 'edge_ospf1': ['edge_l12', 'edge_lan1', 'edge_lan2'],
    'fix_b': ['fix_lbo'], 'fix_ospf1': ['fix_lbo', 'fix_lan2'],
    'sum_asbr': ['sum_l12'], 'sum_ospf1': ['sum_l12'],
    'nssa_core': ['nssa_l01'], 'nssa_abr': ['nssa_l01', 'nssa_l12'], 'nssa_asbr': ['nssa_l12'],
    'agg_b': ['agg_l12'], 'agg_ospf1': ['agg_l12'],
}
RIP_NETS = {
    'mut_rip1': ['mut_lan1', 'mut_lrb'], 'mut_b': ['mut_lrb'],
    'dual_rip1': ['dual_l1b1', 'dual_l1b2', 'dual_l12'], 'dual_rip2': ['dual_l12', 'dual_l23'],
    'dual_rip3': ['dual_l23', 'dual_lan3'], 'dual_b1': ['dual_l1b1'], 'dual_b2': ['dual_l1b2'],
    'fix_rip1': ['fix_lan1', 'fix_lrb'], 'fix_b': ['fix_lrb'],
}
BGP_ROUTERS = ('edge_b', 'edge_isp', 'agg_b', 'agg_isp')
# networks of hosts: passive in OSPF / RIP
HOST_NETS = {n for n, _gw in HOSTS.values()} | {'stat_lan', 'edge_lan2'}
NSSA_AREA = 1                       # the area of the nssa site (area 0 elsewhere)

PUBLIC_POOL = IPv4Network("198.18.0.0/15")   # company blocks, partner and "Internet" prefixes
ISP_AS = 65010
RIP_TIMERS = (10, 60, 40)           # update, timeout, garbage (FRR default 30 180 120)
SUM_COUNT = 7                       # static /24 of the sum site: the /21 but its first /24 (see sum_nets())
AGG_COUNT = 4                       # /24 of the agg site (an aligned /22)
# OSPF: cost of an interface of a container (10 Gbit/s, reference 100 Gbit/s)
DEFAULT_COST = 10
# FRR defaults: seed metric of a route redistributed into RIP, into OSPF (type 2), the distances
RIP_DEFAULT_SEED = 1
OSPF_DEFAULT_METRIC = 20
OSPF_DISTANCE, RIP_DISTANCE, KERNEL_DISTANCE = 110, 120, 0
DUAL_EXTERNAL_DISTANCE = 125        # reference solution of the dual site
FIX_SEED = 2                        # reference solution of the fix site
FIX_BAD_SEED = 15
# OSPF MaxAge: an LSA flushed by its router (a route no longer redistributed, the /24 replaced by a
# summary) stays in the databases at this age for some seconds; it no longer counts (seen live)
OSPF_MAX_AGE = 3600
# waits of the reference states: until every expected route is there (or gone), at most
# CONVERGE_MAX s, then SETTLE s (triggered updates, the 5 s aggregation timer of OSPF)
CONVERGE_MAX = 90
SETTLE = 8
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_FRR_DAEMON_NAMES = ('bgpd', 'ospfd', 'ospf6d', 'ripd', 'ripngd', 'isisd', 'pimd', 'pim6d', 'ldpd', 'nhrpd',
                     'eigrpd', 'babeld', 'sharpd', 'pbrd', 'bfdd', 'fabricd', 'vrrpd', 'pathd')
_FRR_DAEMON_OPTIONS = """
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
ospf6d_options=" -A ::1"
ripd_options="   -A 127.0.0.1"
ripngd_options=" -A ::1"
isisd_options="  -A 127.0.0.1"
pimd_options="   -A 127.0.0.1"
pim6d_options="  -A ::1"
ldpd_options="   -A 127.0.0.1"
nhrpd_options="  -A 127.0.0.1"
eigrpd_options=" -A 127.0.0.1"
babeld_options=" -A 127.0.0.1"
sharpd_options=" -A 127.0.0.1"
pbrd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
fabricd_options="-A 127.0.0.1"
vrrpd_options="  -A 127.0.0.1"
pathd_options="  -A 127.0.0.1"
"""
FRR_VTYSH_CONF = "service integrated-vtysh-config\n"


def site_of(machine: str) -> str:
    return machine.split('_', 1)[0]


def iface(machine: str, net: str) -> str:
    """Name of the interface of *machine* on *net* (``eth1``)."""
    return f"eth{ROUTER_IFACES[machine].index(net)}"


def _frr_daemons(enabled: tuple) -> str:
    lines = ["# /etc/frr/daemons -- généré par le TP",
             "# (zebra, mgmtd, staticd et watchfrr démarrent toujours)"]
    lines += [f"{name}={'yes' if name in enabled else 'no'}" for name in _FRR_DAEMON_NAMES]
    return "\n".join(lines) + "\n" + _FRR_DAEMON_OPTIONS


def _distinct(count: int, low: int, high: int, avoid=()) -> List[int]:
    """*count* distinct random integers of [low, high], none of them in *avoid*."""
    values = [v for v in range(low, high + 1) if v not in avoid]
    return random.sample(values, count)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    asn: int = 0              # the company AS (edge and agg sites)
    lan_metric: int = 0       # part 1: external metric (type 2) of the server LAN
    far_metric: int = 0       # part 1: external metric (type 1) of the partner's networks
    mut_metric: int = 0       # part 2: external metric (type 1) of the RIP routes in OSPF
    mut_seed: int = 0         # part 2: seed metric of the OSPF routes in RIP
    tag_rip: int = 0          # part 3: tag of the routes going from RIP into OSPF
    tag_ospf: int = 0         # part 3: tag of the routes going from OSPF into RIP
    edge_metric: int = 0      # part 4: external metric (type 1) of the partner prefix
    tag_sum: int = 0          # bonus sum: tag of the summary

    @classmethod
    def generate(cls):
        data = cls()
        data.asn = random.randint(64512, 64999)
        # the course's examples stay out of these ranges (metrics 1000 / 5000, tags 1 / 2 / 7, seed 8)
        data.lan_metric = random.choice([n for n in range(31, 100) if n % 10])
        data.far_metric, data.mut_metric, data.edge_metric = _distinct(3, 101, 499, avoid=range(100, 500, 100))
        data.mut_seed = random.randint(2, 5)
        data.tag_rip, data.tag_ospf, data.tag_sum = _distinct(3, 101, 999, avoid=range(100, 1000, 100))

        lab = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'),
                                  exclude=[IPv4Network('10.0.0.0/16'), IPv4Network('10.255.0.0/16')])[0]
        data.nets.lab = lab

        def sub(site: str, third: int, prefixlen: int = 24, index: int = 0) -> IPv4Network:
            """A network of *site*: third octet 16N + *third*, the *index*-th /30 of that /24."""
            base = int(lab.network_address) + ((16 * SITE_NUMBER[site] + third) << 8)
            return IPv4Network((base + 4 * index, prefixlen))

        n = data.nets
        # stat: links in .0, then the LANs and the partner's networks
        n.stat_l12, n.stat_lgw = sub('stat', 0, 30, 0), sub('stat', 0, 30, 1)
        n.stat_lan, n.stat_mgmt, n.stat_lan2 = sub('stat', 1), sub('stat', 2), sub('stat', 3)
        n.stat_far1, n.stat_far2, n.stat_far3 = sub('stat', 4), sub('stat', 5), sub('stat', 6)
        # mut / dual / fix: the RIP domain in 16N..16N+3, the OSPF domain from 16N+4
        n.mut_lrb, n.mut_lan1 = sub('mut', 0, 30, 0), sub('mut', 1)
        n.mut_lbo, n.mut_lan2 = sub('mut', 4, 30, 0), sub('mut', 5)
        n.dual_l1b1, n.dual_l1b2 = sub('dual', 0, 30, 0), sub('dual', 0, 30, 1)
        n.dual_l12, n.dual_l23 = sub('dual', 0, 30, 2), sub('dual', 0, 30, 3)
        n.dual_lan3, n.dual_tago = sub('dual', 1), sub('dual', 2)
        n.dual_lb1o, n.dual_lb2o = sub('dual', 4, 30, 0), sub('dual', 4, 30, 1)
        n.dual_lano, n.dual_tagr = sub('dual', 5), sub('dual', 6)
        n.fix_lrb, n.fix_lan1 = sub('fix', 0, 30, 0), sub('fix', 1)
        n.fix_rip_block = sub('fix', 0, 22)
        n.fix_lbo, n.fix_lgw = sub('fix', 4, 30, 0), sub('fix', 4, 30, 1)
        n.fix_lan2, n.fix_srv = sub('fix', 5), sub('fix', 6)
        # edge: links of the company and the operator's link, private
        n.edge_l12, n.edge_lisp = sub('edge', 0, 30, 0), sub('edge', 1, 30, 0)
        # sum: an aligned /21 (16N + 8 .. 16N + 15) of static /24
        n.sum_l12, n.sum_lgw = sub('sum', 0, 30, 0), sub('sum', 0, 30, 1)
        n.sum_block = sub('sum', 8, 21)
        # nssa
        n.nssa_l01, n.nssa_l12, n.nssa_lgw = sub('nssa', 0, 30, 0), sub('nssa', 0, 30, 1), sub('nssa', 0, 30, 2)
        n.nssa_ext1, n.nssa_ext2, n.nssa_coreext = sub('nssa', 1), sub('nssa', 2), sub('nssa', 3)
        # agg
        n.agg_l12, n.agg_lisp = sub('agg', 0, 30, 0), sub('agg', 0, 30, 1)
        # router-ids: one /24 of the lab block, never routed
        n.router_ids = IPv4Network((int(lab.network_address) + (255 << 8), 24))

        # public addresses: the company blocks, the operator's prefixes
        (n.edge_company, n.edge_linet, n.edge_partner, n.edge_inet1, n.edge_inet2, n.agg_company,
         stat_inet_net) = random_ipv4networks([23, 24, 24, 24, 24, 22, 24], from_network=PUBLIC_POOL)
        n.edge_lan1, n.edge_lan2 = list(n.edge_company.subnets(new_prefix=24))
        data.ips.stat_inet = IPv4Interface((int(stat_inet_net.network_address) + random.randint(1, 254), 32))

        for net, (first, second) in LINKS.items():
            network = getattr(n, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for net in LANS:
            network = getattr(n, net)
            members = [m for m, nets in ROUTER_IFACES.items() if net in nets]
            for k, m in enumerate(members):
                setattr(data.ips, f"{m}_{net}", IPv4Interface((int(network.network_address) + 1 + k, 24)))
        for host, (net, _gw) in HOSTS.items():
            if net in LANS:
                network = getattr(n, net)
                setattr(data.ips, host, IPv4Interface((int(network.network_address) + random.randint(10, 250), 24)))
        for k, router in enumerate(ROUTERS):
            setattr(data.ips, f"{router}_rid", IPv4Interface((int(n.router_ids.network_address) + k + 1, 32)))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("netdev13")
        spec['shape'] = 'box'
    if machine in ISPS:
        spec['allow_connection'] = False
    return spec


def _block_lines(lines: List[str], indent_unit: str = " ") -> List[str]:
    """Indent vtysh lines by block (``router``, ``interface``, ``route-map``, ``address-family``):
    what both frr.conf and the solution texts show."""
    out, depth = [], 0
    for line in lines:
        if line in ("exit", "exit-address-family"):
            depth = max(0, depth - 1)
            out.append(indent_unit * depth + line)
            continue
        out.append(indent_unit * depth + line)
        if line.startswith(("router ", "interface ", "route-map ", "address-family ")):
            depth += 1
    return out


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in MACHINES}
    _network_specs = {}
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        default = IPv4Network("0.0.0.0/0")

        self.net_config = {}
        for m, nets in ROUTER_IFACES.items():
            self.net_config[m] = [([getattr(self.data.ips, f"{m}_{net}")], []) for net in nets]
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([self.host_iface(h)], [(default, self.addr(gw, net))])]

        # /etc/hosts, one per site: every interface gets m-ethN (the first one also m)
        self.hosts_by_site: Dict[str, str] = {}
        for site in SITE_NUMBER:
            lines = []
            for m, nets in ROUTER_IFACES.items():
                if site_of(m) != site:
                    continue
                for i, net in enumerate(nets):
                    names = f"{m}-eth{i}" if i else f"{m}\t{m}-eth{i}"
                    lines.append(f"{self.addr(m, net)}\t{names}")
            for h in HOSTS:
                if site_of(h) == site:
                    lines.append(f"{self.host_ip(h)}\t{h}")
            if site == 'stat':
                lines.append(f"{self.data.ips.stat_inet.ip}\tinternet")
            if site == 'edge':
                lines.append(f"{self.first_host(self.net('edge_partner'))}\tpartner")
            self.hosts_by_site[site] = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses -------------------------------------------------------------------

    def addr(self, machine: str, net: str) -> IPv4Address:
        """Address (without prefix) of *machine* on *net*."""
        return getattr(self.data.ips, f"{machine}_{net}").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def rid(self, router: str) -> str:
        """The OSPF / BGP router-id of *router* (given in its configuration)."""
        return str(getattr(self.data.ips, f"{router}_rid").ip)

    def host_iface(self, host: str) -> IPv4Interface:
        net, _gw = HOSTS[host]
        if net in LINKS:
            return getattr(self.data.ips, f"{host}_{net}")
        return getattr(self.data.ips, host)

    def host_ip(self, host: str) -> IPv4Address:
        return self.host_iface(host).ip

    @staticmethod
    def first_host(network: IPv4Network) -> IPv4Address:
        """The .1 of a network (the address a gateway or the operator puts on its lo)."""
        return network.network_address + 1

    def sum_nets(self) -> List[IPv4Network]:
        """The static /24 of the sum site.  Not the first /24 of the /21: its LSA would have the Link
        State ID of the summary, and ospfd 10.3 keeps the route of a /24 whose LSA the summary replaced
        in place (seen live: a stale `N E2 x.y.z.0/24` next to the /21)."""
        return list(self.net('sum_block').subnets(new_prefix=24))[1:1 + SUM_COUNT]

    def agg_nets(self) -> List[IPv4Network]:
        return list(self.net('agg_company').subnets(new_prefix=24))[:AGG_COUNT]

    def fix_wrong_nexthop(self) -> IPv4Address:
        """The next hop of the faulty static route of fix_b: the address of fix_gw + 4 (a typo),
        outside every network of fix_b."""
        return self.addr('fix_gw', 'fix_lgw') + 4

    def lo_addresses(self, m: str) -> List[IPv4Interface]:
        """The addresses `initial` puts on the lo of a gateway or of an operator."""
        n = self.net
        if m == 'stat_gw':
            nets = [n('stat_far1'), n('stat_far2'), n('stat_far3')]
            return [IPv4Interface((self.first_host(x), 24)) for x in nets] + [self.data.ips.stat_inet]
        if m == 'fix_gw':
            nets = [n('fix_srv')]
        elif m == 'sum_gw':
            nets = self.sum_nets()
        elif m == 'nssa_gw':
            nets = [n('nssa_ext1'), n('nssa_ext2')]
        elif m == 'edge_isp':
            nets = [n('edge_partner'), n('edge_inet1'), n('edge_inet2')]
        else:
            return []
        return [IPv4Interface((self.first_host(x), 24)) for x in nets]

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi redistribuer"), tag="principle")
            + tr("""
Un **domaine de routage** est un ensemble de routeurs qui échangent leurs routes avec un même
protocole : un domaine OSPF, un domaine RIP, une session BGP avec un opérateur. Un réseau réel en
contient souvent plusieurs :

- un ancien site encore en RIP raccordé à un cœur OSPF, le temps d'une migration ou après la fusion
  de deux entreprises ;
- des réseaux qui ne parlent aucun protocole de routage : les réseaux directement connectés à un
  routeur (serveurs, administration), les routes statiques vers un partenaire ou un équipement
  simple ;
- la frontière avec un opérateur, en BGP.

Chaque protocole ne connaît que ses propres routes. La **redistribution** fait entrer dans un
**protocole de destination** les routes d'une **source** : un autre protocole, les réseaux
connectés, les routes statiques, les routes du noyau. Le routeur qui la réalise, à cheval sur les
deux, est un **point de redistribution** ; en OSPF on l'appelle **ASBR** (*AS Boundary Router*).
Elle se configure **dans le protocole de destination** :

```
router ospf
 redistribute rip            ! les routes RIP deviennent des routes externes d'OSPF
router rip
 redistribute ospf           ! et les routes OSPF des routes RIP : redistribution mutuelle
```

Une redistribution ne va que dans **un sens** : `redistribute rip` sous `router ospf` fait
connaître les réseaux du domaine RIP au domaine OSPF, pas l'inverse. Pour que les machines des deux
domaines se joignent il faut les deux sens (**redistribution mutuelle**) : sans le retour, les
paquets partent mais les réponses ne reviennent pas.

Dans FRR, chaque démon (`ripd`, `ospfd`, `bgpd`, `staticd`) propose ses meilleures routes à
**zebra**, qui tient la table de routage du routeur (la **RIB**), choisit une route par préfixe
parmi celles qu'on lui propose et l'installe dans le noyau. Une redistribution est un abonnement :
`redistribute rip` dans `ospfd` demande à zebra les routes **choisies** dont la source est RIP. Une
route RIP qui a perdu face à une route d'une autre source (section @@ref:rib@@) n'est donc **pas**
redistribuée.
""")
            + info_subtitle(tr("La distance administrative"), tag="rib")
            + tr("""
Quand plusieurs sources proposent le même préfixe, zebra ne compare pas leurs métriques (un nombre
de sauts RIP et un coût OSPF ne se comparent pas) mais leur **distance administrative**, la
confiance accordée à la source : la plus petite gagne ; à distance égale, la métrique départage.

| source | code dans `show ip route` | distance (FRR) |
|--------|---------------------------|----------------|
| réseau connecté | `C` | 0 |
| route du noyau (`ip route add`) | `K` | 0 |
| route statique de FRR | `S` | 1 |
| eBGP | `B` | 20 |
| OSPF | `O` | 110 |
| IS-IS | `I` | 115 |
| RIP | `R` | 120 |
| iBGP | `B` | 200 |

`show ip route` affiche `[distance/métrique]` : `O>* 192.0.2.0/24 [110/20] via …` ; `>` marque la
route choisie, `*` une route installée dans le noyau. `show ip route 192.0.2.0/24` détaille toutes
les routes connues pour ce préfixe, choisies ou non.

Les distances se règlent dans chaque protocole :

```
router ospf
 distance ospf external 250    ! les routes externes (E1, E2) ; aussi intra-area, inter-area
router rip
 distance 100                  ! toutes les routes RIP
router bgp 64500
 address-family ipv4 unicast
  distance bgp 20 200 200      ! eBGP, iBGP, routes locales
```

FRR n'applique une nouvelle distance qu'aux routes qu'il installe **ensuite** : les routes déjà dans
la RIB gardent l'ancienne. Pour OSPF, `clear ip ospf process` (en mode privilégié, sur le routeur
modifié) recalcule et réinstalle toutes ses routes.
""")
            + info_subtitle(tr("Les métriques"), tag="metrics")
            + tr("""
Chaque protocole a sa métrique : un nombre de sauts de 1 à 15 en RIP (16 = inaccessible), un coût
cumulé en OSPF, l'attribut MED en BGP. Une route redistribuée reçoit donc une **métrique
d'amorçage** (*seed metric*) dans le protocole de destination, choisie par le point de
redistribution ; elle évolue ensuite normalement (RIP ajoute 1 à chaque routeur ; OSPF ajoute ou
non le coût interne).

| destination | métrique par défaut (FRR) | réglages |
|-------------|---------------------------|----------|
| RIP | 1 | `redistribute ospf metric 8`, `default-metric 8`, `set metric` |
| OSPF | 20, externe de type 2 | `redistribute rip metric-type 1 metric 1000`, `default-metric`, `set metric`, `set metric-type` |
| BGP | MED = métrique de la route dans la RIB, origine *incomplete* | `set metric` |

- **RIP** : un routeur ajoute 1 à la métrique qu'il reçoit. Une métrique d'amorçage trop grande
  rend les routes inaccessibles : annoncée à 15, une route arrive à 16 chez le voisin. Une métrique
  trop petite fait croire qu'un réseau est tout proche, ce qui peut attirer le trafic dans un
  détour par l'autre domaine (section @@ref:multipoint@@).
- **OSPF** : une route externe de **type 2** (E2, le défaut) garde sa métrique externe dans tout le
  domaine ; entre deux routes E2 de même métrique, le coût jusqu'à l'ASBR départage. Une route de
  **type 1** (E1) reçoit en plus le coût du chemin jusqu'à l'ASBR, comme une route interne ; elle
  est toujours préférée à une route E2. `show ip ospf route` affiche `N E2 192.0.2.0/24 [10/20]`
  (coût jusqu'à l'ASBR / métrique externe) et `N E1 192.0.2.0/24 [30]` (la somme).
- **BGP** : section @@ref:bgp@@.
""")
            + info_subtitle(tr("Filtrer et marquer : listes de préfixes et route-maps"), tag="policy")
            + tr("""
Redistribuer « tout » est rarement ce qu'on veut. On choisit les routes avec une **route-map**,
attachée à la redistribution : `redistribute connected route-map NOM`.

**Liste de préfixes** (*prefix-list*) : des règles numérotées, examinées dans l'ordre ; la
première qui correspond décide ; un préfixe qu'aucune règle n'accepte est refusé (*deny* implicite
à la fin).

```
ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24   ! les préfixes de 10.1.0.0/16, du /16 au /24
ip prefix-list LANS seq 20 permit 192.0.2.0/24        ! exactement 192.0.2.0/24
```

Sans `ge` ni `le`, une règle ne correspond **qu'au préfixe exact** : `permit 10.1.0.0/16` ne laisse
pas passer `10.1.5.0/24`. `le N` (*less or equal*) accepte aussi les préfixes plus longs jusqu'à
/N, `ge N` impose une longueur minimale.

**Route-map** : des entrées `permit` ou `deny` numérotées, examinées dans l'ordre. Une entrée
contient des conditions `match` (toutes doivent être vraies ; sans condition, l'entrée correspond
toujours) et, pour `permit`, des actions `set`. La première entrée qui correspond décide : la route
est acceptée (et modifiée) ou refusée. Une route qui ne correspond à aucune entrée est **refusée**.

```
route-map RIP-TO-OSPF deny 10
 match tag 7                            ! refuse les routes marquées 7
exit
route-map RIP-TO-OSPF permit 20
 match ip address prefix-list LANS      ! accepte les préfixes de LANS...
 set metric 1000                        ! ...avec la métrique 1000
 set metric-type type-1                 ! en externe de type 1 (OSPF)
 set tag 1                              ! et les marque 1
exit
router ospf
 redistribute rip route-map RIP-TO-OSPF
```

| condition ou action | effet |
|---------------------|-------|
| `match ip address prefix-list L` | le préfixe est accepté par la liste L |
| `match interface ethX` | la route sort par ethX (le réseau connecté de ethX) |
| `match tag N` | la route porte l'étiquette N |
| `set metric N` | la métrique d'amorçage (prime sur `redistribute … metric`) |
| `set metric-type type-1` ou `type-2` | le type de la route externe OSPF |
| `set tag N` | pose l'étiquette N |

Une **étiquette** (*tag*) est un nombre attaché à une route, transporté par le protocole sans être
interprété : 32 bits dans un LSA externe d'OSPF, 16 bits dans une route RIPv2. Une route statique
peut en porter une (`ip route 192.0.2.0/24 10.0.0.1 tag 2`). Zebra garde l'étiquette d'une route
quand il la passe d'un démon à l'autre : on s'en sert pour reconnaître d'où vient une route au
moment de la redistribuer.

`show route-map` affiche les route-maps et le nombre de fois où elles ont été appliquées
(*Invoked*), `show ip prefix-list` les listes de préfixes et leurs compteurs.
""")
            + info_subtitle(tr("Réseaux connectés, routes statiques et routes du noyau"), tag="sources")
            + tr("""
- `redistribute connected` : les réseaux des interfaces du routeur (code `C`), **tous** : ceux des
  interfaces déjà couvertes par le protocole (une route externe de plus, inutile) comme ceux qui
  doivent rester privés. On le filtre presque toujours avec une route-map.
- `redistribute static` : les routes statiques **de FRR** (`ip route …` dans vtysh, gérées par
  `staticd`, code `S`). Une route statique dont le prochain saut n'est joignable par aucune route
  est **inactive** : `show ip route` ne la marque pas comme choisie, elle n'est ni installée ni
  redistribuée.
- `redistribute kernel` : les routes posées directement dans le noyau, par `ip route add` ou par un
  autre logiciel (code `K`). FRR leur donne la distance 0 : une route du noyau l'emporte sur une
  route statique de FRR vers le même préfixe, qui n'est alors ni choisie ni redistribuée. Mieux vaut
  supprimer la route du noyau (`ip route del`) et la déclarer dans FRR, où elle est enregistrée
  avec le reste de la configuration.

Un point de redistribution a ses propres réseaux connectés dans chacun des domaines. Ce sont des
routes `C` de sa RIB, pas des routes RIP ni OSPF : `redistribute rip` ne les emporte pas, même si
RIP est activé sur ces interfaces. Pour que l'autre domaine les connaisse, il faut en plus
`redistribute connected`, filtré sur ces réseaux.
""")
            + info_subtitle(tr("La route par défaut"), tag="default")
            + tr("""
La route par défaut est traitée à part : `redistribute static` ne l'emporte pas, même quand c'est
une route statique de FRR. En OSPF :

```
router ospf
 default-information originate                     ! si le routeur a lui-même une route par défaut
 default-information originate always              ! même sans (gare au trou noir)
 default-information originate metric 5000 metric-type 1
```

Le routeur annonce alors un LSA externe pour `0.0.0.0/0` (type 2, métrique 10 par défaut). Sans
`always`, il ne l'annonce que tant qu'il a une route par défaut active, quelle qu'en soit l'origine
(statique, BGP…) : l'annonce disparaît avec l'accès à l'extérieur, et le trafic part vers un autre
point de sortie s'il y en a un. En RIP : `default-information originate` sous `router rip`.
""")
            + info_subtitle(tr("Redistribuer en plusieurs points"), tag="multipoint")
            + tr("""
Un seul point de redistribution est un point de panne unique : on en met souvent deux. La
redistribution mutuelle en plusieurs points crée alors des problèmes qui n'existent pas avec un
seul.

```
                +----- B1 -----+
   réseau N --- R              O --- réseaux OSPF
                +----- B2 -----+
      domaine RIP          domaine OSPF
```

1. **Chemins sous-optimaux.** B1 redistribue dans OSPF le réseau N, qu'il connaît par RIP. B2
   connaît N par RIP (distance 120) **et** par OSPF, comme route externe venue de B1 (distance 110) :
   il choisit OSPF et envoie le trafic vers N à travers le domaine OSPF jusqu'à B1, alors que R est
   son voisin direct. Et comme la route choisie par B2 n'est plus une route RIP, B2 ne redistribue
   pas N : la redondance attendue n'existe pas.
2. **Boucles par retour des routes** (*route feedback*). Si B2 redistribue aussi OSPF dans RIP, il
   annonce N dans le domaine RIP avec **sa** métrique d'amorçage, qui ne dit rien de la distance
   réelle. Si elle est plus petite que la métrique RIP de N, les routeurs RIP proches de B2
   préfèrent ce chemin : les paquets vers N vont de R à B2, traversent OSPF jusqu'à B1, qui les
   rend à R… une **boucle**, entretenue par les redistributions elles-mêmes.
3. **Oscillations.** Quand les deux points redistribuent la même route au même moment, chacun peut
   préférer celle de l'autre, retirer la sienne, puis la reprendre : la route clignote.

Les remèdes, souvent combinés :

- **marquer et refuser le retour** : toute route qui entre dans OSPF depuis RIP reçoit une
  étiquette (`set tag 1`), et la redistribution d'OSPF dans RIP refuse les routes qui la portent
  (une entrée `deny` avec `match tag 1`) ; de même dans l'autre sens avec une autre étiquette. Une
  route ne repasse jamais la frontière en sens inverse, quel que soit le point de redistribution ;
- **ajuster les distances**, pour que chaque point de redistribution préfère la source d'origine
  d'une route : par exemple une distance des routes externes d'OSPF supérieure à celle de RIP, pour
  qu'une route RIP l'emporte sur la même route revenue par OSPF ;
- **filtrer par préfixes**, quand les plans d'adressage des domaines sont bien séparés.
""")
            + info_subtitle(tr("IGP et BGP"), tag="bgp")
            + tr("""
- **De l'IGP vers BGP.** On annonce ses réseaux à un opérateur avec `network` (le préfixe doit être
  dans la RIB ; origine *IGP*, code `i`) ou en redistribuant l'IGP (`redistribute ospf` sous
  `address-family ipv4 unicast` ; origine *incomplete*, code `?`, et MED = métrique de la route dans
  l'IGP). Le filtre est indispensable : sans lui partent aussi les réseaux d'interconnexion privés et
  tout ce que l'IGP a appris. Dans le choix du meilleur chemin BGP, l'origine `i` est préférée à `?`
  (après la longueur du chemin d'AS).
- **De BGP vers l'IGP.** **Jamais la table complète** : près d'un million de préfixes IPv4 sur
  Internet, que chaque routeur OSPF devrait stocker et recalculer à chaque changement. On donne aux
  routeurs internes une **route par défaut** (`default-information originate`, qui suit la présence
  de la route par défaut apprise de l'opérateur) et, au besoin, quelques préfixes choisis
  (`redistribute bgp route-map …` avec une liste de préfixes).
- La RFC 8212 impose une politique explicite sur chaque session eBGP (`bgp ebgp-requires-policy`,
  actif par défaut dans FRR) : sans route-map en entrée et en sortie, rien n'est échangé.
""")
            + info_subtitle(tr("Résumer à la redistribution"), tag="summary")
            + tr("""
Redistribuer beaucoup de petits réseaux grossit les tables de tout le domaine. S'ils sont
contigus, on les résume au point de redistribution :

- **OSPF** : `summary-address 10.1.0.0/21` (sous `router ospf`, sur l'ASBR) remplace tous les LSA
  externes contenus dans le préfixe par un seul ; `summary-address 10.1.0.0/21 tag 2` marque le
  résumé, `summary-address 10.1.0.0/21 no-advertise` supprime toute annonce. Le résumé remplace les
  routes au bout de quelques secondes (`aggregation timer`, 5 s par défaut). À ne pas confondre avec
  `area N range`, qui résume sur un ABR les routes **inter-aires** et n'agit pas sur les routes
  externes.
- **BGP** : `aggregate-address 10.1.0.0/21` (sous `address-family ipv4 unicast`) annonce le préfixe
  agrégé dès qu'au moins une route plus précise est dans la table BGP ; avec `summary-only`, les
  routes plus précises ne sont plus annoncées (elles restent dans la table, marquées `s`).
""")
            + info_subtitle(tr("Les aires NSSA"), tag="nssa")
            + tr("""
Une aire **stub** n'accepte aucun LSA externe (type 5) : elle ne peut donc pas contenir d'ASBR ; un
routeur d'une aire stub qui redistribue n'annonce rien. L'aire **NSSA** (*Not-So-Stubby Area*, RFC
3101) lève cette limite tout en refusant toujours les routes externes du reste du domaine :

- l'ASBR d'une NSSA décrit ses routes externes dans des **LSA de type 7**, qui ne circulent que
  dans l'aire (`show ip ospf database nssa-external`) ; on parle de routes N1 et N2, l'équivalent
  de E1 et E2, mais FRR les affiche `N E1` et `N E2` dans `show ip ospf route` ;
- l'ABR **traduit** chaque LSA de type 7 en LSA de type 5 pour le reste du domaine : les autres
  aires voient une route externe ordinaire, **annoncée par l'ABR** (*Advertising Router*) ;
- les LSA de type 5 des autres aires n'entrent pas dans la NSSA ; l'ABR peut y injecter une route
  par défaut (`area N nssa default-information-originate`) ; `area N nssa no-summary` refuse en
  plus les routes inter-aires.

Comme `stub`, le type `nssa` est un champ des Hello : **tous** les routeurs de l'aire doivent le
déclarer (`area N nssa` sous `router ospf`), sinon l'adjacence ne se forme pas. Une aire est stub
ou NSSA, pas les deux : on retire l'un (`no area N stub`) avant de déclarer l'autre.
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
**FRRouting** (FRR) est fait de `zebra` (la RIB et l'interface avec le noyau), `staticd` et un
démon par protocole (`ripd`, `ospfd`, `bgpd`). On les configure avec `vtysh` :

```
vtysh                                  # le shell de configuration
configure terminal
 ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24
 route-map RIP-TO-OSPF permit 10
  match ip address prefix-list LANS
  exit
 router ospf
  redistribute rip route-map RIP-TO-OSPF
  exit
 end
write                                  # sauvegarde dans /etc/frr/frr.conf
```

Une ligne s'annule en la préfixant par `no` (`no redistribute rip`). Pour changer les options d'une
redistribution, on retape la commande complète. Une commande isolée depuis le shell :
`vtysh -c "show ip route"`.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ip route [P]` | la RIB : source, `[distance/métrique]`, route choisie `>` |
| `show ip ospf database external [P]` | les LSA de type 5 : *Advertising Router*, *Metric Type*, *Metric*, *External Route Tag* |
| `show ip ospf database nssa-external` | les LSA de type 7 |
| `show ip ospf route` | les routes calculées par OSPF (`N`, `N IA`, `N E1`, `N E2`) |
| `show ip ospf` | router-id, rôle d'ABR ou d'ASBR, type des aires |
| `show ip rip` | la table de RIP : métrique, source, étiquette (*Tag*) ; `R(r)` = redistribuée |
| `show ip rip status` | temporisateurs, interfaces, ligne `Redistributing:` |
| `show bgp ipv4 unicast [P]` | la table BGP : MED (*Metric*), origine (`i`, `?`), `s` = supprimée |
| `show route-map`, `show ip prefix-list` | les filtres et leurs compteurs |
| `traceroute -n IP` | le chemin réellement suivi : dans une boucle, les mêmes routeurs reviennent |

Documentation : [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html),
[RIP](https://docs.frrouting.org/en/latest/ripd.html), [BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
| symptôme | causes à vérifier |
|----------|-------------------|
| la route n'arrive pas dans l'autre domaine | redistribution absente ou configurée dans le mauvais protocole ; route-map qui refuse tout (liste de préfixes sans `le`, route-map inexistante ou réduite à un `deny`) ; route non choisie dans la RIB du point de redistribution (source de distance plus faible, route du noyau, statique inactive) |
| la route arrive dans RIP avec la métrique 16 | métrique d'amorçage de 15 ou plus |
| un réseau d'interconnexion manque | réseau connecté du point de redistribution : `redistribute connected` |
| la route par défaut n'est pas annoncée | `redistribute static` ne la porte pas : `default-information originate` ; pas de route par défaut active sur le routeur |
| les paquets tournent (`traceroute` répète les mêmes routeurs) | redistribution mutuelle en plusieurs points sans étiquettes ni distances adaptées |
| détour par l'autre domaine alors qu'un voisin direct a la route | distance : la route externe d'OSPF (110) bat la route RIP (120) |
| une distance modifiée reste sans effet | elle ne vaut que pour les routes installées ensuite : `clear ip ospf process` |
| des réseaux privés partent chez l'opérateur | redistribution dans BGP sans filtre |
| une route externe n'entre pas dans une aire | aire stub ou NSSA (normal) ; ASBR dans une aire stub : passer l'aire en NSSA |
""")
        )

    # -- FRR configuration at start --------------------------------------------------

    def area_of(self, net: str) -> int:
        return NSSA_AREA if net in ('nssa_l12',) else 0

    def ospf_lines(self, m: str, extra: List[str] = ()) -> List[str]:
        """OSPF of *m* at start: point-to-point links, router-id, its networks, passive host LANs."""
        lines = []
        for net in OSPF_NETS[m]:
            if net in LINKS:
                lines += [f"interface {iface(m, net)}", "ip ospf network point-to-point", "exit"]
        lines += ["router ospf", f"ospf router-id {self.rid(m)}"]
        lines += [f"network {self.net(n)} area {self.area_of(n)}" for n in OSPF_NETS[m]]
        lines += [f"passive-interface {iface(m, n)}" for n in OSPF_NETS[m] if n in HOST_NETS]
        if m in ('nssa_abr', 'nssa_asbr'):
            lines.append(f"area {NSSA_AREA} stub")
        if m == 'agg_ospf1':
            lines.append(f"network {self.net('agg_company')} area 0")
            lines += [f"passive-interface dum{k}" for k in range(AGG_COUNT)]
        return lines + list(extra) + ["exit"]

    def rip_lines(self, m: str, extra: List[str] = ()) -> List[str]:
        """RIP of *m* at start: version 2, the lab's short timers, its networks, passive host LANs."""
        lines = ["router rip", "version 2", "timers basic {} {} {}".format(*RIP_TIMERS)]
        lines += [f"network {self.net(n)}" for n in RIP_NETS[m]]
        lines += [f"passive-interface {iface(m, n)}" for n in RIP_NETS[m] if n in HOST_NETS]
        return lines + list(extra) + ["exit"]

    def bgp_customer_lines(self, m: str, extra_af: List[str] = ()) -> List[str]:
        """BGP of edge_b / agg_b at start: the session with the operator, permit-all policies."""
        site = site_of(m)
        isp = f"{site}_isp"
        peer = self.addr(isp, f"{site}_lisp")
        lines = ["route-map ISP-IN permit 10", "exit", "route-map TO-ISP permit 10", "exit",
                 f"router bgp {self.data.asn}", f"bgp router-id {self.rid(m)}",
                 f"neighbor {peer} remote-as {ISP_AS}", f"neighbor {peer} description operator",
                 "address-family ipv4 unicast", f"neighbor {peer} route-map ISP-IN in",
                 f"neighbor {peer} route-map TO-ISP out"]
        return lines + list(extra_af) + ["exit-address-family", "exit"]

    def bgp_isp_lines(self, isp: str) -> List[str]:
        """BGP of an operator: no RFC 8212 policy, the default route and its prefixes to the customer."""
        site = site_of(isp)
        peer = self.addr(f"{site}_b", f"{site}_lisp")
        lines = [f"router bgp {ISP_AS}", f"bgp router-id {self.rid(isp)}", "no bgp ebgp-requires-policy",
                 f"neighbor {peer} remote-as {self.data.asn}", f"neighbor {peer} description customer",
                 "address-family ipv4 unicast"]
        if isp == 'edge_isp':
            lines += [f"network {self.net(n)}" for n in ('edge_partner', 'edge_inet1', 'edge_inet2', 'edge_linet')]
            lines.append(f"neighbor {peer} default-originate")
        return lines + ["exit-address-family", "exit"]

    def fix_faults(self) -> Dict[str, List[str]]:
        """The four faults of fix_b, by block: the static route, the prefix-list, OSPF, RIP."""
        n = self.net
        return {
            'static': [f"ip route {n('fix_srv')} {self.fix_wrong_nexthop()}"],
            'filter': [f"ip prefix-list RIP-NETS seq 10 permit {n('fix_rip_block')}",
                       "route-map RIP-TO-OSPF permit 10", "match ip address prefix-list RIP-NETS", "exit"],
            'ospf': ["redistribute static", "redistribute rip route-map RIP-TO-OSPF"],
            'rip': [f"redistribute ospf metric {FIX_BAD_SEED}"],
        }

    def _given_lines(self, m: str) -> List[str]:
        """The FRR configuration of *m* at start (statics, filters, then the protocols)."""
        d, n = self.data, self.net
        lines: List[str] = []
        if m == 'dual_ospf1':
            lines.append(f"ip route {n('dual_tagr')} blackhole tag {d.tag_rip}")
        elif m == 'dual_rip2':
            lines.append(f"ip route {n('dual_tago')} blackhole tag {d.tag_ospf}")
        elif m == 'sum_asbr':
            lines += [f"ip route {x} {self.addr('sum_gw', 'sum_lgw')}" for x in self.sum_nets()]
        elif m == 'nssa_core':
            lines.append(f"ip route {n('nssa_coreext')} blackhole")
        elif m == 'nssa_asbr':
            lines += [f"ip route {n(x)} {self.addr('nssa_gw', 'nssa_lgw')}" for x in ('nssa_ext1', 'nssa_ext2')]
        elif m == 'fix_b':
            faults = self.fix_faults()
            lines += faults['static'] + faults['filter']
        elif m == 'agg_b':
            lines += [f"ip prefix-list COMPANY seq 10 permit {n('agg_company')} le 24",
                      "route-map OSPF-TO-BGP permit 10", "match ip address prefix-list COMPANY", "exit"]

        ospf_extra = {
            'dual_ospf1': ["redistribute static"], 'dual_b1': ["redistribute rip"],
            'sum_asbr': ["redistribute static"], 'nssa_core': ["redistribute static"],
            'nssa_asbr': ["redistribute static"], 'fix_b': self.fix_faults()['ospf'],
        }
        rip_extra = {'dual_rip2': ["redistribute static"], 'dual_b1': ["redistribute ospf"],
                     'fix_b': self.fix_faults()['rip']}
        if m in OSPF_NETS:
            lines += self.ospf_lines(m, ospf_extra.get(m, []))
        if m in RIP_NETS:
            lines += self.rip_lines(m, rip_extra.get(m, []))
        if m in ('edge_b', 'agg_b'):
            lines += self.bgp_customer_lines(m, ["redistribute ospf route-map OSPF-TO-BGP"] if m == 'agg_b' else [])
        if m in ISPS:
            lines += self.bgp_isp_lines(m)
        return lines

    def frr_daemons_of(self, m: str) -> tuple:
        return tuple(name for name, table in (('ospfd', OSPF_NETS), ('ripd', RIP_NETS)) if m in table) + \
            (('bgpd',) if m in BGP_ROUTERS else ())

    def _frr_conf(self, m: str) -> str:
        """Initial /etc/frr/frr.conf of *m*."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {m}", "log file /var/log/frr/frr.log", "!"]
        for line in _block_lines(self._given_lines(m)):
            lines.append(line)
            if line == "exit":
                lines.append("!")
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step)

    # -- reference solutions: {machine: [(kind, payload)]}; kinds: sh, vtysh, exec ------------

    def solution_stat(self) -> Dict[str, list]:
        d, n = self.data, self.net
        gw = self.addr('stat_gw', 'stat_lgw')
        return {'stat_asbr': [
            ('sh', f"ip route del {n('stat_far3')} via {gw}"),
            ('vtysh', [f"ip route {n('stat_far1')} {gw}", f"ip route {n('stat_far2')} {gw}",
                       f"ip route {n('stat_far3')} {gw}", f"ip route 0.0.0.0/0 {gw}",
                       f"ip prefix-list SERVERS seq 10 permit {n('stat_lan')}",
                       "route-map CONNECTED permit 10", "match ip address prefix-list SERVERS",
                       f"set metric {d.lan_metric}", "exit",
                       "router ospf", "redistribute connected route-map CONNECTED",
                       f"redistribute static metric-type 1 metric {d.far_metric}",
                       "default-information originate", "exit"])]}

    def solution_mut(self) -> Dict[str, list]:
        d, n = self.data, self.net
        return {'mut_b': [('vtysh', [
            f"ip prefix-list RIP-LINK seq 10 permit {n('mut_lrb')}",
            f"ip prefix-list OSPF-LINK seq 10 permit {n('mut_lbo')}",
            "route-map RIP-LINK permit 10", "match ip address prefix-list RIP-LINK", "exit",
            "route-map OSPF-LINK permit 10", "match ip address prefix-list OSPF-LINK", "exit",
            "router ospf", f"redistribute rip metric-type 1 metric {d.mut_metric}",
            f"redistribute connected metric-type 1 metric {d.mut_metric} route-map RIP-LINK", "exit",
            "router rip", f"redistribute ospf metric {d.mut_seed}",
            f"redistribute connected metric {d.mut_seed} route-map OSPF-LINK", "exit"])]}

    def dual_border_lines(self) -> List[str]:
        d = self.data
        return ["route-map RIP-TO-OSPF deny 10", f"match tag {d.tag_ospf}", "exit",
                "route-map RIP-TO-OSPF permit 20", f"set tag {d.tag_rip}", "exit",
                "route-map OSPF-TO-RIP deny 10", f"match tag {d.tag_rip}", "exit",
                "route-map OSPF-TO-RIP permit 20", f"set tag {d.tag_ospf}", "exit",
                "router ospf", "redistribute rip route-map RIP-TO-OSPF",
                f"distance ospf external {DUAL_EXTERNAL_DISTANCE}", "exit",
                "router rip", "redistribute ospf route-map OSPF-TO-RIP", "exit"]

    def solution_dual(self) -> Dict[str, list]:
        """Both borders; ``clear ip ospf process``: ospfd 10.3 applies a new distance only to the routes
        it installs afterwards (seen live: the E2 route of dual_b2 kept distance 110)."""
        return {b: [('vtysh', self.dual_border_lines()), ('exec', "clear ip ospf process")]
                for b in ('dual_b1', 'dual_b2')}

    def solution_edge(self) -> Dict[str, list]:
        d, n = self.data, self.net
        return {'edge_b': [('vtysh', [
            f"ip prefix-list COMPANY seq 10 permit {n('edge_company')} le 24",
            f"ip prefix-list PARTNER seq 10 permit {n('edge_partner')}",
            "route-map OSPF-TO-BGP permit 10", "match ip address prefix-list COMPANY", "exit",
            "route-map BGP-TO-OSPF permit 10", "match ip address prefix-list PARTNER",
            f"set metric {d.edge_metric}", "set metric-type type-1", "exit",
            f"router bgp {d.asn}", "address-family ipv4 unicast", "redistribute ospf route-map OSPF-TO-BGP",
            "exit-address-family", "exit",
            "router ospf", "default-information originate", "redistribute bgp route-map BGP-TO-OSPF", "exit"])]}

    def solution_fix(self) -> Dict[str, list]:
        n = self.net
        return {'fix_b': [('vtysh', [
            f"no ip route {n('fix_srv')} {self.fix_wrong_nexthop()}",
            f"ip route {n('fix_srv')} {self.addr('fix_gw', 'fix_lgw')}",
            f"no ip prefix-list RIP-NETS seq 10 permit {n('fix_rip_block')}",
            f"ip prefix-list RIP-NETS seq 10 permit {n('fix_rip_block')} le 30",
            "router ospf", "redistribute connected route-map RIP-TO-OSPF", "exit",
            "router rip", "no redistribute ospf", f"redistribute ospf metric {FIX_SEED}", "exit"])]}

    def solution_sum(self) -> Dict[str, list]:
        return {'sum_asbr': [('vtysh', ["router ospf", f"summary-address {self.net('sum_block')} tag {self.data.tag_sum}",
                                        "exit"])]}

    def solution_nssa(self) -> Dict[str, list]:
        lines = ["router ospf", f"no area {NSSA_AREA} stub", f"area {NSSA_AREA} nssa", "exit"]
        return {m: [('vtysh', lines)] for m in ('nssa_abr', 'nssa_asbr')}

    def solution_agg(self) -> Dict[str, list]:
        return {'agg_b': [('vtysh', [f"router bgp {self.data.asn}", "address-family ipv4 unicast",
                                     f"aggregate-address {self.net('agg_company')} summary-only",
                                     "exit-address-family", "exit"])]}

    def solutions(self) -> Dict[str, Dict[str, list]]:
        return {'stat': self.solution_stat(), 'mut': self.solution_mut(), 'dual': self.solution_dual(),
                'edge': self.solution_edge(), 'fix': self.solution_fix(), 'sum': self.solution_sum(),
                'nssa': self.solution_nssa(), 'agg': self.solution_agg()}

    # -- waits of the reference states ------------------------------------------------

    def wait_conditions(self, site: str) -> Dict[str, List[str]]:
        """{observer: [shell conditions]} that hold once the solution of *site* has converged."""
        n, d = self.net, self.data

        def has(prefix, word: str = '.') -> str:
            return f"ip route show {prefix} | grep -q '{word}'"

        def lacks(prefix) -> str:
            return f"! ip route show {prefix} | grep -q ."

        ospf, rip, bgp = 'proto ospf', 'proto rip', 'proto bgp'
        if site == 'stat':
            return {'stat_ospf1': [has(n(x), ospf) for x in ('stat_lan', 'stat_far1', 'stat_far2', 'stat_far3')]
                    + [has('0.0.0.0/0', ospf)]}
        if site == 'mut':
            return {'mut_ospf1': [has(n('mut_lan1'), ospf), has(n('mut_lrb'), ospf)],
                    'mut_rip1': [has(n('mut_lan2'), rip), has(n('mut_lbo'), rip)]}
        if site == 'dual':
            lan3, lano = n('dual_lan3'), n('dual_lano')
            # after `clear ip ospf process` the neighbours keep the borders' former LSAs (untagged) until the
            # restarted ospfd outbids their sequence numbers: wait for both tagged LSAs
            tagged = (f"[ $(vtysh -c 'show ip ospf database external {lan3.network_address}' "
                      f"| grep -c 'External Route Tag: {d.tag_rip}$') -ge 2 ]")
            return {'dual_ospf1': [f"[ $(ip route show {lan3} | grep -c nexthop) -ge 2 ]", lacks(n('dual_tago')), tagged],
                    'dual_b1': [has(lan3, rip)], 'dual_b2': [has(lan3, rip)],
                    'dual_rip1': [lacks(n('dual_tagr')), has(lano, rip),
                                  f"vtysh -c 'show ip rip' | grep -F ' {lano} ' | grep -qw {d.tag_ospf}"]}
        if site == 'edge':
            return {'edge_isp': [has(n('edge_lan1'), bgp), has(n('edge_lan2'), bgp)],
                    'edge_ospf1': [has('0.0.0.0/0', ospf), has(n('edge_partner'), ospf)]}
        if site == 'fix':
            return {'fix_rip1': [has(n('fix_lan2'), rip)],
                    'fix_ospf1': [has(n(x), ospf) for x in ('fix_lan1', 'fix_srv', 'fix_lrb')]}
        if site == 'sum':
            return {'sum_ospf1': [has(n('sum_block'), ospf), lacks(self.sum_nets()[0])]}
        if site == 'nssa':
            return {'nssa_core': [has(n('nssa_ext1'), ospf), has(n('nssa_ext2'), ospf)]}
        if site == 'agg':
            return {'agg_isp': [has(n('agg_company'), bgp), lacks(self.agg_nets()[0])]}
        return {}

    def _wait(self, sites, step: int = 2):
        """Register, on every observer of *sites*, a wait until its conditions hold (at most
        CONVERGE_MAX s), then SETTLE s: the observers wait at the same time."""
        per_machine: Dict[str, List[str]] = {}
        for site in sites:
            for m, conditions in self.wait_conditions(site).items():
                per_machine.setdefault(m, []).extend(conditions)
        for m, conditions in per_machine.items():
            test = " && ".join(conditions)
            self.cmd(m, f"for i in $(seq {CONVERGE_MAX}); do {test} && break; sleep 1; done; sleep {SETTLE}",
                     step=step, timeout=CONVERGE_MAX + SETTLE + 20, allow_error=True)

    def _apply(self, solution: Dict[str, list], step: int = 1):
        for m, items in solution.items():
            for kind, payload in items:
                if kind == 'sh':
                    self.cmd(m, payload, step=step)
                elif kind == 'vtysh':
                    self._vtysh(m, *payload, step=step)
                elif kind == 'exec':
                    self.cmd(m, f'vtysh -c "{payload}"', step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        n = self.net
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_by_site[site_of(m)])
            for address in self.lo_addresses(m):
                self.cmd(m, f"ip addr add {address} dev lo")
        # the partner networks of stat: far3 by a route of the kernel, not of FRR (part 1)
        self.cmd('stat_asbr', f"ip route add {n('stat_far3')} via {self.addr('stat_gw', 'stat_lgw')}")
        # the company networks of agg: dummy interfaces of agg_ospf1
        for k, network in enumerate(self.agg_nets()):
            self.cmd('agg_ospf1', f"ip link add dum{k} type dummy; ip addr add {self.first_host(network)}/24 dev dum{k}; "
                                  f"ip link set dum{k} up")
        for m in ROUTER_IFACES:
            self.file(m, "/etc/frr/daemons", _frr_daemons(self.frr_daemons_of(m)), permissions=0o640,
                      owner="frr:frr", step=2)
            self.file(m, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(m, "/etc/frr/frr.conf", self._frr_conf(m), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(m, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (statiques, connectés, noyau)",
                                                  en="Part 1: solution (static, connected, kernel)"))
    def solve_stat(self):
        self._apply(self.solution_stat())
        self._wait(('stat',))

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (RIP et OSPF, un point)",
                                                  en="Part 2: solution (RIP and OSPF, one point)"))
    def solve_mut(self):
        self._apply(self.solution_mut())
        self._wait(('mut',))

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (deux points, étiquettes)",
                                                  en="Part 3: solution (two points, tags)"))
    def solve_dual(self):
        self._apply(self.solution_dual())
        self._wait(('dual',))

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (OSPF et BGP)",
                                                  en="Part 4: solution (OSPF and BGP)"))
    def solve_edge(self):
        self._apply(self.solution_edge())
        self._wait(('edge',))

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (dépannage)",
                                                  en="Part 5: solution (troubleshooting)"))
    def solve_fix(self):
        self._apply(self.solution_fix())
        self._wait(('fix',))

    @sre_state(user_allowed=False, description=tr("Bonus : solution (résumé sur l'ASBR)",
                                                  en="Bonus: solution (summary on the ASBR)"))
    def solve_sum(self):
        self._apply(self.solution_sum())
        self._wait(('sum',))

    @sre_state(user_allowed=False, description=tr("Bonus : solution (NSSA)", en="Bonus: solution (NSSA)"))
    def solve_nssa(self):
        self._apply(self.solution_nssa())
        self._wait(('nssa',))

    @sre_state(user_allowed=False, description=tr("Bonus : solution (agrégation BGP)",
                                                  en="Bonus: solution (BGP aggregation)"))
    def solve_agg(self):
        self._apply(self.solution_agg())
        self._wait(('agg',))

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part and bonus: every grade element is at its maximum when
        the state returns.  Form questions are filled through cheat_answers."""
        for solution in self.solutions().values():
            self._apply(solution)
        self._wait(tuple(SITE_NUMBER))


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------

# the routers the students configure (their running configuration is kept in each archive)
CONFIGURED = ('stat_asbr', 'mut_b', 'dual_b1', 'dual_b2', 'edge_b', 'fix_b', 'sum_asbr', 'nssa_abr', 'nssa_asbr',
              'agg_b')
BGP_ORIGIN_INCOMPLETE = ('incomplete', '?')


def _norm(s) -> str:
    return " ".join((s or "").strip().lower().rstrip('.').split())


def _int(s):
    try:
        return int(_norm(s).replace(' ', ''))
    except ValueError:
        return None


def _solution_text(solution: Dict[str, list]) -> Dict[str, str]:
    """The reference solution of a part, machine by machine: shell commands, vtysh sessions; one text
    per language (the French one has a space before the colon)."""
    blocks = []
    for m, items in solution.items():
        parts = []
        for kind, payload in items:
            if kind == 'sh':
                parts.append(f"```\n{payload}\n```")
            elif kind == 'exec':
                parts.append(f"```\nvtysh -c \"{payload}\"\n```")
            elif kind == 'vtysh':
                body = ["configure terminal"] + [" " + x for x in _block_lines(payload)] + ["end", "write"]
                parts.append("```\n" + "\n".join(body) + "\n```")
        blocks.append((m, "\n\n".join(parts)))
    return {lang: "\n\n".join(f"`{m}`{colon}\n\n{body}" for m, body in blocks)
            for lang, colon in (('fr', " :"), ('en', ":"))}


def _by_language(text: TranslatedText, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values*; a dict value (a tr() text, the result of
    _solution_text) gives one value per language."""
    return TranslatedText({lang: version.format(**{k: v[lang] if isinstance(v, dict) else v
                                                  for k, v in values.items()})
                           for lang, version in text.items()})


def _join(separator: str, items):
    """``separator.join(items)`` for plain strings and tr() texts (``str.join`` refuses translated texts)."""
    text = ""
    for k, item in enumerate(items):
        text = (text + separator if k else text) + item
    return text


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        addr, net, rid, host_ip, first_host = ns.addr, ns.net, ns.rid, ns.host_ip, ns.first_host

        def alive(entry: Optional[dict]) -> bool:
            """An LSA in use: not being flushed (age MaxAge)."""
            return entry is not None and (entry.get('age') or 0) < OSPF_MAX_AGE

        def lsa(lsas: Dict, prefix, router: str) -> Optional[dict]:
            """The external LSA of *prefix* advertised by *router*, None when absent or being flushed."""
            entry = lsas.get((str(prefix), rid(router)))
            return entry if alive(entry) else None

        def advertised(lsas: Dict, router: str) -> set:
            """The prefixes of every external LSA of *router* that is not being flushed."""
            return {prefix for (prefix, adv), entry in lsas.items() if adv == rid(router) and alive(entry)}

        def external(entry: Optional[dict], metric_type: int, metric: int) -> bool:
            return bool(entry) and entry.get('metric_type') == metric_type and entry.get('metric') == metric

        def route_by(routes: Dict, prefix, check) -> bool:
            """True when the kernel has a route for *prefix* installed by the protocol *check* accepts."""
            entry = routes.get(str(prefix))
            return entry is not None and check(entry['protocol'])

        def gateways(routes: Dict, prefix, protocols=None) -> List[str]:
            return sorted(str(g) for g in kernel_route_gateways(routes, prefix, ospf_only=protocols is None,
                                                                protocols=protocols))

        def company_paths(table: Dict, prefix) -> List[dict]:
            """The paths of *prefix* the operator learned from the company AS."""
            return [p for p in table.get(str(prefix), []) if p.get('as_list')[:1] == [d.asn]]

        def ping(src: str, dest) -> bool:
            return eval_ping(self, src=src, dest=dest, count=3, deadline=5, allow_error=True)

        # ---------------- diagnostics kept in the archive -------------------------
        for m in CONFIGURED:
            self.test(m, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        stat_lsas = get_ospf_external_lsas(self, 'stat_ospf1')
        stat_k = get_kernel_routes(self, 'stat_ospf1', allow_error=True)
        stat_pings = [ping('stat_h2', host_ip('stat_h1')), ping('stat_h2', first_host(net('stat_far1'))),
                      ping('stat_h2', d.ips.stat_inet.ip)]

        mut_lsas = get_ospf_external_lsas(self, 'mut_ospf1')
        mut_k_ospf = get_kernel_routes(self, 'mut_ospf1', allow_error=True)
        mut_rip = get_rip_routes(self, 'mut_rip1', allow_error=True)
        mut_k_rip = get_kernel_routes(self, 'mut_rip1', allow_error=True)
        mut_pings = [ping('mut_h1', host_ip('mut_h2')), ping('mut_h2', host_ip('mut_h1'))]

        dual_lsas = get_ospf_external_lsas(self, 'dual_ospf1')
        dual_rip = get_rip_routes(self, 'dual_rip1', allow_error=True)
        dual_k = {m: get_kernel_routes(self, m, allow_error=True) for m in ('dual_b1', 'dual_b2', 'dual_rip1')}
        dual_pings = [ping('dual_h2', host_ip('dual_h1')), ping('dual_h1', host_ip('dual_h2'))]

        edge_bgp = get_bgp_routes(self, 'edge_isp', allow_error=True)
        edge_lsas = get_ospf_external_lsas(self, 'edge_ospf1')
        edge_k = get_kernel_routes(self, 'edge_ospf1', allow_error=True)
        edge_pings = [ping('edge_h1', host_ip('edge_inet')), ping('edge_h1', first_host(net('edge_partner')))]

        fix_rip = get_rip_routes(self, 'fix_rip1', allow_error=True)
        fix_k_rip = get_kernel_routes(self, 'fix_rip1', allow_error=True)
        fix_lsas = get_ospf_external_lsas(self, 'fix_ospf1')
        fix_k_ospf = get_kernel_routes(self, 'fix_ospf1', allow_error=True)
        fix_pings = [ping('fix_h2', host_ip('fix_h1')), ping('fix_h2', addr('fix_rip1', 'fix_lrb'))]

        sum_lsas = get_ospf_external_lsas(self, 'sum_ospf1')
        sum_ping = ping('sum_ospf1', first_host(ns.sum_nets()[0]))

        nssa_info = {m: get_ospf_info(self, m, allow_error=True) for m in ('nssa_abr', 'nssa_asbr')}
        nssa_nb = get_ospf_neighbors(self, 'nssa_abr', allow_error=True)
        nssa_type7_lsas = get_ospf_nssa_lsas(self, 'nssa_abr')
        nssa_lsas = get_ospf_external_lsas(self, 'nssa_core')
        nssa_k = get_kernel_routes(self, 'nssa_asbr', allow_error=True)

        agg_bgp = get_bgp_routes(self, 'agg_isp', allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        sites = [
            ('stat', tr("1 — routes statiques, connectées et du noyau dans OSPF"),
             tr("`stat_asbr` (à configurer), `stat_ospf1`, `stat_gw`, `stat_h1`, `stat_h2`")),
            ('mut', tr("2 — RIP et OSPF, un point de redistribution"),
             tr("`mut_b` (à configurer), `mut_rip1`, `mut_ospf1`, `mut_h1`, `mut_h2`")),
            ('dual', tr("3 — RIP et OSPF, deux points de redistribution"),
             tr("`dual_b1`, `dual_b2` (à configurer), `dual_rip1` à `dual_rip3`, `dual_ospf1`, `dual_h1`, "
                "`dual_h2`")),
            ('edge', tr("4 — OSPF et BGP"),
             tr("`edge_b` (à configurer), `edge_ospf1`, `edge_h1`, `edge_inet` ; `edge_isp` sans terminal")),
            ('fix', tr("5 — dépannage"),
             tr("`fix_b` (à corriger), `fix_rip1`, `fix_ospf1`, `fix_gw`, `fix_h1`, `fix_h2`")),
            ('sum', tr("bonus — résumé sur un ASBR"), tr("`sum_asbr` (à configurer), `sum_ospf1`, `sum_gw`")),
            ('nssa', tr("bonus — aire NSSA"),
             tr("`nssa_abr`, `nssa_asbr` (à configurer), `nssa_core`, `nssa_gw`")),
            ('agg', tr("bonus — agrégation BGP"),
             tr("`agg_b` (à configurer), `agg_ospf1` ; `agg_isp` sans terminal")),
        ]
        site_rows = _join("\n", ("| " + part + f" | `{site}_*` | " + machines + " |" for site, part, machines in sites))
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + LANS}
        for m, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                members[n].append(f"`{m}` eth{i} (`{addr(m, n)}`)")
        for h, (n, _gw) in HOSTS.items():
            members[n].append(f"`{h}` (`{host_ip(h)}`)")
        rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in list(LINKS) + LANS]
        rows += [
            tr("| `stat_far1` à `stat_far3` | `{far1}`, `{far2}`, `{far3}` | `lo` de `stat_gw` (`.1`) |").format(
                far1=net('stat_far1'), far2=net('stat_far2'), far3=net('stat_far3')),
            tr("| `internet` | `{inet}` | `lo` de `stat_gw` |").format(inet=d.ips.stat_inet.ip),
            tr("| `fix_srv` | `{srv}` | `lo` de `fix_gw` (`.1`) |").format(srv=net('fix_srv')),
            tr("| `sum_block` | `{block}` ({count} /24) | `lo` de `sum_gw` (`.1` de chaque /24) |").format(
                block=net('sum_block'), count=SUM_COUNT),
            tr("| `nssa_ext1`, `nssa_ext2` | `{e1}`, `{e2}` | `lo` de `nssa_gw` (`.1`) |").format(
                e1=net('nssa_ext1'), e2=net('nssa_ext2')),
            tr("| `nssa_coreext` | `{coreext}` | route statique (`blackhole`) de `nssa_core` |").format(
                coreext=net('nssa_coreext')),
            tr("| `edge_partner` | `{partner}` | `lo` de `edge_isp` (`.1`, nom `partner`) |").format(
                partner=net('edge_partner')),
            tr("| `edge_inet1`, `edge_inet2` | `{i1}`, `{i2}` | `lo` de `edge_isp` |").format(
                i1=net('edge_inet1'), i2=net('edge_inet2')),
            tr("| `agg_company` | `{company}` ({count} /24) | interfaces `dum0` à `dum{last}` de "
               "`agg_ospf1` |").format(company=net('agg_company'), count=AGG_COUNT, last=AGG_COUNT - 1),
            tr("| `dual_tagr`, `dual_tago` | `{tagr}`, `{tago}` | routes de test (`blackhole`) de `dual_ospf1` et "
               "`dual_rip2` |").format(tagr=net('dual_tagr'), tago=net('dual_tago')),
        ]
        addressing = _join("\n", rows)
        rid_rows = ", ".join(f"`{m}` `{rid(m)}`" for m in ROUTER_IFACES if m in OSPF_NETS or m in BGP_ROUTERS)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="7da6edddb1ea6810",
            description=_by_language(tr("""
Lisez l'onglet **Informations** : il présente la redistribution (sources, distance administrative,
métriques, route-maps et étiquettes, route par défaut, plusieurs points de redistribution, BGP,
résumés, aires NSSA) et les commandes de FRR utiles.

**Le réseau.** Il est fait de **huit sites indépendants**, un par partie, chacun avec sa couleur
sur le schéma.

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) : configurez-les avec `vtysh` (section
  @@ref:frr@@). Dans chaque site, les protocoles de routage eux-mêmes sont **déjà configurés et
  fonctionnent** (adjacences OSPF établies, RIP actif) : vous n'avez à écrire que la redistribution,
  ses filtres et ses réglages.
- OSPF : une seule aire, l'aire 0 (sauf le site `nssa`) ; les liens entre routeurs sont déclarés
  point à point (`ip ospf network point-to-point`), d'où un coût de 10 par lien et pas d'élection de
  DR. Les réseaux d'hôtes sont passifs.
- RIP : version 2, temporisateurs raccourcis pour le TP (`timers basic {upd} {tmo} {gc}` : une
  mise à jour toutes les {upd} s au lieu de 30).
- Chaque routeur a un router-id fixé dans sa configuration : {rid_rows}.
- Les hôtes et les passerelles (`*_gw`) ont une route par défaut vers leur routeur ; les réseaux
  `stat_far*`, `fix_srv`, `nssa_ext*` et les {sum_count} /24 de `sum_block` sont portés par
  l'interface `lo` des passerelles.
- Les fichiers `/etc/hosts` contiennent les noms : `mut_b-eth1` désigne l'adresse de l'interface
  `eth1` de `mut_b`.
- AS de l'entreprise (sites `edge` et `agg`) : **{asn}** ; opérateur : AS {isp_as}.

**Plan d'adressage.** Les liens entre deux machines sont des /30, les autres réseaux des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Ne modifiez que les routeurs indiqués « à configurer » : les autres sont les références par
  lesquelles l'évaluation regarde le résultat.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).

**Évaluation.** Chaque évaluation lit vos réponses, les bases OSPF (LSA externes, routes), les tables
de RIP et de BGP et les tables de routage des routeurs de référence, et lance des `ping` entre les
hôtes. Après une modification, laissez à RIP le temps d'une mise à jour ({upd} s) avant d'évaluer.
"""), site_rows=site_rows, addressing=addressing, rid_rows=rid_rows, asn=d.asn, isp_as=ISP_AS,
            upd=RIP_TIMERS[0], tmo=RIP_TIMERS[1], gc=RIP_TIMERS[2], sum_count=SUM_COUNT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_stat`, `solve_mut`, `solve_dual`, `solve_edge`, `solve_fix`, `solve_sum`,
`solve_nssa` et `solve_agg` (onglet *Appliquer une configuration*) appliquent la solution d'une
seule partie, attendent que les routes attendues soient en place (au plus {wait} s) et remplissent
ses formulaires. L'état `final` les applique toutes : une évaluation lancée dès son retour donne
tous les points, bonus compris.

Valeurs de cette instance : métriques {lan} (`stat_lan`, E2), {far} (`stat_far*`, E1), {mut} (RIP
vers OSPF sur `mut_b`, E1), amorçage RIP {seed} (`mut_b`), {edge} (préfixe partenaire, E1) ;
étiquettes {trip} (RIP vers OSPF) et {tospf} (OSPF vers RIP) sur le site `dual`, {tsum} pour le
résumé du site `sum`.

Les pannes du site `fix` (sur `fix_b`) : `redistribute ospf metric {bad}` sous `router rip` ;
`RIP-NETS` = `{block}` sans `le` ; route statique vers `{srv}` par `{wrong}` (au lieu de `{gw}`) ;
pas de `redistribute connected` sous `router ospf`. Sur le site `dual`, `dual_b1` redistribue dès
le départ dans les deux sens sans route-map.
""").format(wait=CONVERGE_MAX, lan=d.lan_metric, far=d.far_metric, mut=d.mut_metric, seed=d.mut_seed,
            edge=d.edge_metric, trip=d.tag_rip, tospf=d.tag_ospf, tsum=d.tag_sum, bad=FIX_BAD_SEED,
            block=net('fix_rip_block'), srv=net('fix_srv'), wrong=ns.fix_wrong_nexthop(),
            gw=addr('fix_gw', 'fix_lgw'))),
        )

        # =====================================================================
        # Part 1 — static, connected, kernel and default routes into OSPF (stat)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("stat"),
                                    tr("Partie 1 — routes statiques, connectées et du noyau dans OSPF (site stat)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Annoncer dans OSPF des réseaux qui n'y sont pas"),
            hash="53542be210250bfb",
            description=tr("""
`stat_asbr` et `stat_ospf1` forment un domaine OSPF ; seul le lien `stat_l12` y est déclaré du côté
de `stat_asbr`. `stat_asbr` a en plus trois réseaux qui ne sont pas dans OSPF : `stat_lan` (eth0,
les serveurs, dont `stat_h1`), `stat_mgmt` (eth1, l'administration) et `stat_lgw` (eth3, le lien
vers la passerelle `stat_gw`). Derrière `stat_gw` se trouvent les réseaux d'un partenaire,
`stat_far1` `{far1}`, `stat_far2` `{far2}` et `stat_far3` `{far3}`, ainsi que l'accès à Internet
(l'adresse `internet`, `{inet}`). Un collègue a déjà ajouté une route vers `{far3}` avec
`ip route add`.

Sur `stat_asbr` uniquement :

1. créez dans FRR des routes statiques vers `stat_far1` et `stat_far2` et une route par défaut, par
   `stat_gw` (`{gw}`) ;
2. faites annoncer dans OSPF (sections @@ref:sources@@, @@ref:policy@@ et @@ref:default@@) :
   - `stat_lan` en route externe de **type 2**, métrique **{lan}** ;
   - `stat_far1`, `stat_far2` **et** `stat_far3` en routes externes de **type 1**, métrique
     **{far}** ;
   - la route par défaut ;
   - **et rien d'autre** : ni `stat_mgmt`, ni `stat_lgw`, ni `stat_l12`.

Vérifiez sur `stat_ospf1` (`show ip ospf database external`, `show ip ospf route`, `ip route`), puis
depuis `stat_h2` : `ping` vers `stat_h1`, vers `{far1_host}` et vers `internet`. Pourquoi
`stat_far3` n'apparaît-il pas d'abord ?
""").format(far1=net('stat_far1'), far2=net('stat_far2'), far3=net('stat_far3'), inet=d.ips.stat_inet.ip,
            gw=addr('stat_gw', 'stat_lgw'), lan=d.lan_metric, far=d.far_metric,
            far1_host=first_host(net('stat_far1')))
            + instructor(_by_language(tr("""
**Solution.**

{solution}

La route vers `{far3}` ajoutée par `ip route add` est une route **du noyau** (`K` dans `show ip
route`), pas une route statique de FRR : `redistribute static` ne la voit pas. Une route statique
de FRR vers le même préfixe ne suffit pas tant que la route du noyau existe : distance 0 contre 1,
la route du noyau reste choisie. On la supprime (`ip route del`), ou bien on ajoute
`redistribute kernel metric-type 1 metric {far}`. La route par défaut n'est jamais emportée par
`redistribute static` : `default-information originate` (type 2, métrique 10).

Évaluation (LSA externes vus par `stat_ospf1`) : `stat_lan` (3 : type 2, métrique {lan}),
`stat_filter` (2 : aucun LSA externe de `stat_asbr` pour `stat_mgmt`, `stat_lgw`, `stat_l12`,
compté si `stat_lan` l'est), `stat_far` (4 : `stat_far1`, `stat_far2` en type 1, métrique {far}),
`stat_kernel` (3 : `stat_far3` de même), `stat_default` (3 : route par défaut de `stat_ospf1` par
`stat_asbr`), `stat_ping` (3 : `stat_h2` joint `stat_h1`, `stat_far1`, `internet`).
"""), solution=_solution_text(ns.solution_stat()), far3=net('stat_far3'), far=d.far_metric,
            lan=d.lan_metric)),
        )
        cheat_stat = {'cost_far': str(d.far_metric + DEFAULT_COST), 'dist_ospf': str(OSPF_DISTANCE),
                      'dist_kernel': str(KERNEL_DISTANCE), 'kernel': 'kernel', 'default': 'dio'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site stat"),
            hash="ca5b823095b983b9",
            description=tr("""
- coût de la route de `stat_ospf1` vers `stat_far1` dans `show ip ospf route` : @@{cost_far:[0-9]+}@@
- distance administrative de cette route dans `show ip route` : @@{dist_ospf:[0-9]+}@@
- distance administrative d'une route ajoutée par `ip route add` (FRR) : @@{dist_kernel:[0-9]+}@@
- `redistribute static` n'annonçait pas `stat_far3` parce que :
  @@{kernel:>c'est une route du noyau, pas une route statique de FRR>>>kernel|stat_gw ne répond pas sur cette adresse>>>gw|redistribute static n'emporte que deux routes>>>count|il manque une commande network pour ce préfixe>>>network}@@
- la route par défaut n'est pas annoncée par `redistribute static` parce que :
  @@{default:>la route par défaut ne suit jamais redistribute : il faut default-information originate>>>dio|il faut redistribute kernel>>>kernel|stat_ospf1 la filtre>>>filtered|OSPF ne sait pas transporter de route par défaut>>>never}@@
""")
            + instructor(tr("""
**Solution.** Coût **{cost}** (route E1 : {far} + {dc} pour le lien) ; distance **{dospf}** ;
distance **{dkern}** ; **une route du noyau** ; **default-information originate**.

Évaluation : `stat_q_cost`, `stat_q_dist` (1 chacun ; les deux distances pour le second) et, pour
l'enseignant seulement (choix dans une liste), `stat_q_kernel`, `stat_q_default` (1 chacun).
""").format(cost=d.far_metric + DEFAULT_COST, far=d.far_metric, dc=DEFAULT_COST, dospf=OSPF_DISTANCE,
            dkern=KERNEL_DISTANCE)),
            cheat_answers={"final": cheat_stat, "solve_stat": cheat_stat},
        )
        stat_lan = lsa(stat_lsas, net('stat_lan'), 'stat_asbr')
        stat_lan_ok = external(stat_lan, 2, d.lan_metric)
        stat_leaks = advertised(stat_lsas, 'stat_asbr') & {str(net(x)) for x in ('stat_mgmt', 'stat_lgw', 'stat_l12')}
        stat_far = [external(lsa(stat_lsas, net(x), 'stat_asbr'), 1, d.far_metric)
                    for x in ('stat_far1', 'stat_far2', 'stat_far3')]
        stat_default = (lsa(stat_lsas, '0.0.0.0/0', 'stat_asbr') is not None
                        and gateways(stat_k, '0.0.0.0/0') == [str(addr('stat_asbr', 'stat_l12'))])
        self.add_grade_element(title=no_tr("stat_lan"), max_grade=3, grade_part=part1, grade=3 * int(stat_lan_ok),
                               description=tr("stat_lan annoncé en externe de type 2 avec sa métrique"))
        self.add_grade_element(title=no_tr("stat_filter"), max_grade=2, grade_part=part1,
                               grade=2 * int(stat_lan_ok and not stat_leaks),
                               description=tr("aucun autre réseau connecté de stat_asbr annoncé"))
        self.add_grade_element(title=no_tr("stat_far"), max_grade=4, grade_part=part1, grade=2 * sum(stat_far[:2]),
                               description=tr("stat_far1 et stat_far2 en externes de type 1 avec leur métrique"))
        self.add_grade_element(title=no_tr("stat_kernel"), max_grade=3, grade_part=part1, grade=3 * int(stat_far[2]),
                               description=tr("stat_far3, ajouté par ip route add, annoncé de même"))
        self.add_grade_element(title=no_tr("stat_default"), max_grade=3, grade_part=part1,
                               grade=3 * int(stat_default), description=tr("route par défaut annoncée par stat_asbr"))
        self.add_grade_element(title=no_tr("stat_ping"), max_grade=3, grade_part=part1, grade=sum(stat_pings),
                               description=tr("stat_h2 joint stat_h1, stat_far1 et internet"))
        self.add_grade_element(title=no_tr("stat_q_cost"), max_grade=1, grade_part=part1,
                               grade=int(_int(q1.get('cost_far')) == d.far_metric + DEFAULT_COST),
                               description=tr("coût de la route E1"))
        self.add_grade_element(title=no_tr("stat_q_dist"), max_grade=1, grade_part=part1,
                               grade=int(_int(q1.get('dist_ospf')) == OSPF_DISTANCE
                                         and _int(q1.get('dist_kernel')) == KERNEL_DISTANCE),
                               description=tr("distances d'une route OSPF et d'une route du noyau"))
        self.add_grade_element(title=no_tr("stat_q_kernel"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                               grade=int(_norm(q1.get('kernel')) == 'kernel'),
                               description=tr("pourquoi stat_far3 manquait"))
        self.add_grade_element(title=no_tr("stat_q_default"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                               grade=int(_norm(q1.get('default')) == 'dio'),
                               description=tr("annonce de la route par défaut"))

        # =====================================================================
        # Part 2 — RIP <-> OSPF at one border (mut)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("mut"), tr("Partie 2 — RIP et OSPF, un point de redistribution (site mut)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Redistribution mutuelle entre RIP et OSPF"),
            hash="c61cd8623a93ce62",
            description=tr("""
`mut_rip1` fait partie d'un ancien domaine RIP (son réseau `mut_lan1`, avec `mut_h1`) ; `mut_ospf1`
du domaine OSPF (`mut_lan2`, avec `mut_h2`). `mut_b` est à la frontière : RIP sur `eth0` (lien
`mut_lrb`), OSPF sur `eth1` (lien `mut_lbo`). Les deux protocoles fonctionnent, mais aucune route ne
passe d'un domaine à l'autre.

Sur `mut_b` uniquement, faites que **toutes les adresses** de chaque domaine soient joignables
depuis l'autre (sections @@ref:principle@@, @@ref:metrics@@ et @@ref:sources@@) :

- les routes RIP entrent dans OSPF en externes de **type 1**, métrique **{metric}** ;
- les routes OSPF entrent dans RIP avec la métrique d'amorçage **{seed}** ;
- le lien `mut_lrb` doit être connu dans OSPF et le lien `mut_lbo` dans RIP, avec les mêmes
  métriques, sans rien annoncer d'autre de `mut_b`.

Vérifiez les tables de `mut_rip1` (`show ip rip`, `ip route`) et de `mut_ospf1` (`show ip ospf
route`), puis les `ping` entre `mut_h1` et `mut_h2`.
""").format(metric=d.mut_metric, seed=d.mut_seed)
            + instructor(_by_language(tr("""
**Solution.**

{solution}

`redistribute rip` n'emporte pas `mut_lrb` : c'est un réseau connecté de `mut_b` (route `C`), pas
une route apprise par RIP ; de même `mut_lbo` n'est pas une route OSPF de `mut_b`. D'où les deux
`redistribute connected`, filtrés par une liste de préfixes chacun. `mut_rip1` voit `mut_lan2` à
{seen} ({seed} + 1) ; `mut_ospf1` voit `mut_lan1` en E1 à {cost} ({metric} + {dc}).

Évaluation : `mut_ospf_lan` (4 : LSA de `mut_lan1` par `mut_b`, type 1, métrique {metric}),
`mut_ospf_link` (2 : route OSPF de `mut_ospf1` vers `mut_lrb`), `mut_rip_lan` (4 : métrique {seen}
de `mut_lan2` sur `mut_rip1`), `mut_rip_link` (2 : route RIP de `mut_rip1` vers `mut_lbo`),
`mut_ping` (2 : `ping` dans les deux sens).
"""), solution=_solution_text(ns.solution_mut()), seed=d.mut_seed, seen=d.mut_seed + 1,
            metric=d.mut_metric, cost=d.mut_metric + DEFAULT_COST, dc=DEFAULT_COST)),
        )
        cheat_mut = {'rip_metric': str(d.mut_seed + 1), 'ospf_cost': str(d.mut_metric + DEFAULT_COST),
                     'seed_rip': str(RIP_DEFAULT_SEED), 'seed_ospf': str(OSPF_DEFAULT_METRIC), 'connected': 'connected'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site mut"),
            hash="20ac2342c4b6e66d",
            description=tr("""
- métrique de `mut_lan2` dans `show ip rip` de `mut_rip1` : @@{rip_metric:[0-9]+}@@
- coût de la route de `mut_ospf1` vers `mut_lan1` dans `show ip ospf route` : @@{ospf_cost:[0-9]+}@@
- métrique d'amorçage par défaut de FRR pour une route redistribuée dans RIP : @@{seed_rip:[0-9]+}@@
  et dans OSPF : @@{seed_ospf:[0-9]+}@@
- `redistribute rip` n'annonce pas `mut_lrb` dans OSPF parce que :
  @@{connected:>c'est un réseau connecté de mut_b, pas une route apprise par RIP>>>connected|RIP n'annonce jamais les /30>>>mask|l'horizon partagé (split horizon) le bloque>>>split|OSPF refuse les routes de métrique 1>>>metric}@@
""")
            + instructor(tr("""
**Solution.** **{seen}** ; **{cost}** ; **{srip}** et **{sospf}** ; **un réseau connecté de mut_b**.

Évaluation : `mut_q_rip`, `mut_q_cost`, `mut_q_seed` (1 chacun ; les deux valeurs pour le dernier)
et, pour l'enseignant seulement (choix dans une liste), `mut_q_connected` (1).
""").format(seen=d.mut_seed + 1, cost=d.mut_metric + DEFAULT_COST, srip=RIP_DEFAULT_SEED,
            sospf=OSPF_DEFAULT_METRIC)),
            cheat_answers={"final": cheat_mut, "solve_mut": cheat_mut},
        )
        self.add_grade_element(
            title=no_tr("mut_ospf_lan"), max_grade=4, grade_part=part2,
            grade=4 * int(external(lsa(mut_lsas, net('mut_lan1'), 'mut_b'), 1, d.mut_metric)),
            description=tr("mut_lan1 dans OSPF en externe de type 1 avec sa métrique"))
        self.add_grade_element(title=no_tr("mut_ospf_link"), max_grade=2, grade_part=part2,
                               grade=2 * int(route_by(mut_k_ospf, net('mut_lrb'), is_ospf_protocol)),
                               description=tr("mut_lrb connu dans OSPF"))
        self.add_grade_element(
            title=no_tr("mut_rip_lan"), max_grade=4, grade_part=part2,
            grade=4 * int(rip_route_metric(mut_rip, net('mut_lan2'), learned=True) == d.mut_seed + 1),
            description=tr("mut_lan2 dans RIP avec la métrique d'amorçage demandée"))
        self.add_grade_element(title=no_tr("mut_rip_link"), max_grade=2, grade_part=part2,
                               grade=2 * int(route_by(mut_k_rip, net('mut_lbo'), is_rip_protocol)),
                               description=tr("mut_lbo connu dans RIP"))
        self.add_grade_element(title=no_tr("mut_ping"), max_grade=2, grade_part=part2, grade=sum(mut_pings),
                               description=tr("mut_h1 et mut_h2 se joignent"))
        self.add_grade_element(title=no_tr("mut_q_rip"), max_grade=1, grade_part=part2,
                               grade=int(_int(q2.get('rip_metric')) == d.mut_seed + 1),
                               description=tr("métrique RIP de mut_lan2"))
        self.add_grade_element(title=no_tr("mut_q_cost"), max_grade=1, grade_part=part2,
                               grade=int(_int(q2.get('ospf_cost')) == d.mut_metric + DEFAULT_COST),
                               description=tr("coût OSPF de mut_lan1"))
        self.add_grade_element(title=no_tr("mut_q_seed"), max_grade=1, grade_part=part2,
                               grade=int(_int(q2.get('seed_rip')) == RIP_DEFAULT_SEED
                                         and _int(q2.get('seed_ospf')) == OSPF_DEFAULT_METRIC),
                               description=tr("métriques d'amorçage par défaut"))
        self.add_grade_element(title=no_tr("mut_q_connected"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                               grade=int(_norm(q2.get('connected')) == 'connected'),
                               description=tr("pourquoi mut_lrb manque"))

        # =====================================================================
        # Part 3 — RIP <-> OSPF at two borders: tags and distance (dual)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("dual"),
                                    tr("Partie 3 — RIP et OSPF, deux points de redistribution (site dual)"))
        lan3, lano = net('dual_lan3'), net('dual_lano')
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux points de redistribution : boucles, détours et étiquettes"),
            hash="6e63eb13dc04f0a5",
            description=tr("""
Le domaine RIP (`dual_rip1` — `dual_rip2` — `dual_rip3`, et derrière `dual_rip3` le réseau
`dual_lan3` `{lan3}` avec `dual_h1`) est raccordé au domaine OSPF (`dual_ospf1`, le réseau `dual_lano`
`{lano}` avec `dual_h2`) par **deux** points de redistribution, `dual_b1` et `dual_b2`, voisins RIP de
`dual_rip1` et voisins OSPF de `dual_ospf1`.

- `dual_b1` redistribue déjà dans les deux sens, sans aucun filtre (`redistribute rip` sous
  `router ospf`, `redistribute ospf` sous `router rip`) ;
- `dual_b2` fait tourner RIP et OSPF mais ne redistribue rien ;
- deux routes de test simulent des routes qui ont **déjà franchi la frontière** par un autre
  chemin : `dual_tagr` (`{tagr}`), une route du domaine OSPF qui porte l'étiquette **{trip}** comme si
  elle venait de RIP, et `dual_tago` (`{tago}`), une route du domaine RIP qui porte l'étiquette
  **{tospf}** comme si elle venait d'OSPF.

1. Regardez la route de `dual_b2` vers `dual_lan3` (`show ip route {lan3}`) : par où passe-t-elle,
   et pourquoi (section @@ref:rib@@) ?
2. Pour la redondance, ajoutez sur `dual_b2` la même redistribution que sur `dual_b1`. Lancez
   `traceroute -n {h1}` depuis `dual_h2`, regardez la route de `dual_rip1` vers `dual_lan3` : que
   se passe-t-il (section @@ref:multipoint@@) ?
3. Corrigez sur `dual_b1` **et** `dual_b2` :
   - toute route qui passe de RIP à OSPF reçoit l'étiquette **{trip}**, toute route qui passe
     d'OSPF à RIP l'étiquette **{tospf}** ;
   - une route marquée {tospf} ne passe jamais de RIP à OSPF, une route marquée {trip} jamais
     d'OSPF à RIP ;
   - `dual_b1` et `dual_b2` joignent les réseaux du domaine RIP **par RIP**, directement par
     `dual_rip1` (vérifiez avec `show ip route` que votre réglage s'applique bien aux routes déjà
     en place : section @@ref:rib@@) ;
   - les deux points redistribuent les réseaux RIP dans OSPF (redondance) ; gardez les métriques par
     défaut.
""").format(lan3=lan3, lano=lano, tagr=net('dual_tagr'), tago=net('dual_tago'), trip=d.tag_rip,
            tospf=d.tag_ospf, h1=host_ip('dual_h1'))
            + instructor(_by_language(tr("""
**Solution.** Au départ, `dual_b2` connaît `{lan3}` par RIP (distance {drip}) et par OSPF, en
route externe venue de `dual_b1` (distance {dospf}) : il choisit OSPF et passe par `dual_ospf1`
(`{nh}`), puis `dual_b1`. Avec la redistribution naïve sur `dual_b2`, cette route OSPF (et non RIP)
part dans RIP avec la métrique d'amorçage 1 : `dual_rip1` la reçoit à 2, mieux que les 3 du vrai
chemin par `dual_rip2`. `dual_rip1` envoie alors les paquets vers `{lan3}` à `dual_b2`, qui les
envoie par OSPF à `dual_b1`, qui les rend à `dual_rip1` : boucle (`traceroute` répète
`dual_rip1`, `dual_b2`, `dual_ospf1`, `dual_b1`) jusqu'à l'expiration du TTL.

Sur `dual_b1` et `dual_b2` :

{solution}

Les étiquettes empêchent une route de repasser la frontière en sens inverse (les routes de test le
vérifient) ; la distance {dext} des routes externes d'OSPF, au-dessus de RIP ({drip}), fait choisir à
chaque point la route RIP vers les réseaux RIP, une fois les routes réinstallées par `clear ip ospf
process` (sans lui, `dual_b2` garde sa route OSPF de distance {dospf}). Autre solution acceptée : abaisser sous {dospf} la
distance des seules routes RIP natives (`distance 100 0.0.0.0/0 LISTE` sous `router rip`, avec une
`access-list`).

Évaluation : `dual_redundant` (4 : `dual_ospf1` voit des LSA de `{lan3}` venant de `dual_b1` **et**
de `dual_b2`), `dual_tag_rip` (3 : ces deux LSA portent l'étiquette {trip}), `dual_tag_ospf` (3 :
la route RIP de `dual_rip1` vers `{lano}` porte l'étiquette {tospf}), `dual_paths` (4 : `dual_b1` et
`dual_b2` routent `{lan3}` par RIP via `dual_rip1` ; compté si `dual_redundant` l'est : juste après le
démarrage, avant qu'OSPF converge, `dual_b2` n'a que sa route RIP), `dual_no_return_rip` (2 : `dual_rip1` n'a pas de
route vers `dual_tagr` ; compté si `dual_tag_ospf` l'est), `dual_no_return_ospf` (2 : aucun LSA de
`dual_b1` ou `dual_b2` pour `dual_tago` ; compté si `dual_tag_rip` l'est), `dual_ping` (2 : `ping`
entre `dual_h1` et `dual_h2`, compté si `dual_redundant` l'est : il marche déjà au départ).
"""), lan3=lan3, lano=lano, drip=RIP_DISTANCE, dospf=OSPF_DISTANCE, dext=DUAL_EXTERNAL_DISTANCE,
            nh=addr('dual_ospf1', 'dual_lb2o'), solution=_solution_text({'dual_b1': ns.solution_dual()['dual_b1']}),
            trip=d.tag_rip, tospf=d.tag_ospf)),
        )
        cheat_dual = {'nexthop': str(addr('dual_ospf1', 'dual_lb2o')), 'dist_chosen': str(OSPF_DISTANCE),
                      'dist_rip': str(RIP_DISTANCE), 'loop': 'loop', 'tags': 'return'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site dual"),
            hash="ea33a959ab92b4f8",
            description=tr("""
- avant toute modification, prochain saut de la route de `dual_b2` vers `dual_lan3` : @@{nexthop:[0-9.]+}@@
- distance administrative de cette route : @@{dist_chosen:[0-9]+}@@ et de la route RIP écartée :
  @@{dist_rip:[0-9]+}@@
- avec la même redistribution, sans filtre, sur `dual_b1` et `dual_b2`, un `ping` de `dual_h2` vers
  `dual_h1` :
  @@{loop:>tourne en boucle entre dual_rip1, dual_b2, dual_ospf1 et dual_b1>>>loop|fonctionne, par le chemin le plus court>>>ok|échoue sur dual_rip3, qui n'a pas de route de retour>>>noroute|est refusé par dual_b2>>>filter}@@
- les étiquettes servent à :
  @@{tags:>empêcher une route redistribuée de revenir dans son domaine d'origine par l'autre point>>>return|choisir la métrique d'amorçage>>>metric|accélérer la convergence de RIP>>>speed|authentifier les annonces>>>auth}@@
""")
            + instructor(tr("""
**Solution.** **{nh}** (`dual_ospf1`) ; **{dospf}** et **{drip}** ; **une boucle** ; **empêcher le
retour d'une route dans son domaine d'origine**.

Évaluation : `dual_q_nexthop`, `dual_q_distances` (1 chacun ; les deux valeurs pour le second) et,
pour l'enseignant seulement (choix dans une liste), `dual_q_loop`, `dual_q_tags` (1 chacun).
""").format(nh=addr('dual_ospf1', 'dual_lb2o'), dospf=OSPF_DISTANCE, drip=RIP_DISTANCE)),
            cheat_answers={"final": cheat_dual, "solve_dual": cheat_dual},
        )
        dual_from = {b: lsa(dual_lsas, lan3, b) for b in ('dual_b1', 'dual_b2')}
        dual_redundant = all(dual_from.values())
        dual_tag_rip = dual_redundant and all(e.get('tag') == d.tag_rip for e in dual_from.values())
        lano_paths = [p for p in dual_rip.get(str(lano), []) if p['source'] is not None and p['metric'] < 16]
        dual_tag_ospf = bool(lano_paths) and all(p['tag'] == d.tag_ospf for p in lano_paths)
        dual_paths = all(gateways(dual_k[b], lan3, protocols=RIP_ROUTE_PROTOCOLS) == [str(addr('dual_rip1', link))]
                         for b, link in (('dual_b1', 'dual_l1b1'), ('dual_b2', 'dual_l1b2')))
        tagr_in_rip = (str(net('dual_tagr')) in dual_k['dual_rip1']
                       or rip_route_metric(dual_rip, net('dual_tagr'), learned=True) not in (None, 16))
        tago_back = any(lsa(dual_lsas, net('dual_tago'), b) for b in ('dual_b1', 'dual_b2'))
        self.add_grade_element(title=no_tr("dual_redundant"), max_grade=4, grade_part=part3,
                               grade=4 * int(dual_redundant),
                               description=tr("les réseaux RIP redistribués par les deux points"))
        self.add_grade_element(title=no_tr("dual_tag_rip"), max_grade=3, grade_part=part3, grade=3 * int(dual_tag_rip),
                               description=tr("étiquette des routes passées de RIP à OSPF"))
        self.add_grade_element(title=no_tr("dual_tag_ospf"), max_grade=3, grade_part=part3,
                               grade=3 * int(dual_tag_ospf), description=tr("étiquette des routes passées d'OSPF à RIP"))
        self.add_grade_element(title=no_tr("dual_paths"), max_grade=4, grade_part=part3,
                               grade=4 * int(dual_redundant and dual_paths),
                               description=tr("les deux points joignent dual_lan3 par RIP"))
        self.add_grade_element(title=no_tr("dual_no_return_rip"), max_grade=2, grade_part=part3,
                               grade=2 * int(dual_tag_ospf and not tagr_in_rip),
                               description=tr("une route marquée comme venue de RIP ne retourne pas dans RIP"))
        self.add_grade_element(title=no_tr("dual_no_return_ospf"), max_grade=2, grade_part=part3,
                               grade=2 * int(dual_tag_rip and not tago_back),
                               description=tr("une route marquée comme venue d'OSPF ne retourne pas dans OSPF"))
        self.add_grade_element(title=no_tr("dual_ping"), max_grade=2, grade_part=part3,
                               grade=sum(dual_pings) if dual_redundant else 0,
                               description=tr("dual_h1 et dual_h2 se joignent"))
        self.add_grade_element(title=no_tr("dual_q_nexthop"), max_grade=1, grade_part=part3,
                               grade=int(_norm(q3.get('nexthop')) == str(addr('dual_ospf1', 'dual_lb2o'))),
                               description=tr("prochain saut de dual_b2 au départ"))
        self.add_grade_element(title=no_tr("dual_q_distances"), max_grade=1, grade_part=part3,
                               grade=int(_int(q3.get('dist_chosen')) == OSPF_DISTANCE
                                         and _int(q3.get('dist_rip')) == RIP_DISTANCE),
                               description=tr("distances des deux routes"))
        self.add_grade_element(title=no_tr("dual_q_loop"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                               grade=int(_norm(q3.get('loop')) == 'loop'), description=tr("effet de la redistribution naïve"))
        self.add_grade_element(title=no_tr("dual_q_tags"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                               grade=int(_norm(q3.get('tags')) == 'return'), description=tr("rôle des étiquettes"))

        # =====================================================================
        # Part 4 — OSPF <-> BGP (edge)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("edge"), tr("Partie 4 — OSPF et BGP (site edge)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Entre OSPF et BGP"),
            hash="47fddc7a7ec2eafc",
            description=tr("""
L'entreprise (AS {asn}) a un domaine OSPF : `edge_ospf1` porte ses réseaux publics `edge_lan1`
`{lan1}` (avec `edge_h1`) et `edge_lan2` `{lan2}`, tous deux dans le bloc `{company}`. `edge_b` la relie
en eBGP à son opérateur `edge_isp` (AS {isp_as}), par le lien `edge_lisp`. La session est établie ; les
route-maps `ISP-IN` et `TO-ISP` de `edge_b`, exigées par la RFC 8212, laissent tout passer : le
filtrage vous revient. L'opérateur envoie une route par défaut, le préfixe d'un partenaire
`{partner}` (adresse `partner`, `{partner_host}`) et d'autres préfixes d'Internet.

Sur `edge_b` uniquement (section @@ref:bgp@@) :

1. annoncez à l'opérateur les réseaux de l'entreprise **en redistribuant OSPF dans BGP**, filtré :
   les préfixes du bloc `{company}` et rien d'autre (ni `edge_l12`, ni `edge_lisp`) ;
2. donnez à OSPF la route par défaut apprise de l'opérateur ;
3. redistribuez dans OSPF **le seul préfixe du partenaire**, en externe de type 1 de métrique
   **{metric}** ; aucune autre route BGP.

Vérifiez sur `edge_b` (`show bgp ipv4 unicast`, `show bgp ipv4 unicast neighbors {peer}
advertised-routes`) et sur `edge_ospf1` (`show ip ospf route`), puis `ping` de `edge_h1` vers
`edge_inet` et vers `partner`.
""").format(asn=d.asn, lan1=net('edge_lan1'), lan2=net('edge_lan2'), company=net('edge_company'), isp_as=ISP_AS,
            partner=net('edge_partner'), partner_host=first_host(net('edge_partner')), metric=d.edge_metric,
            peer=addr('edge_isp', 'edge_lisp'))
            + instructor(_by_language(tr("""
**Solution.**

{solution}

L'opérateur reçoit `{lan1}` et `{lan2}` avec l'origine *incomplete* (`?`, redistribution) et le MED
{med} : la métrique OSPF des deux réseaux sur `edge_b` (lien `edge_l12` {dc} + réseau passif {dc}).
`default-information originate` (sans `always`) suit la route par défaut reçue de l'opérateur.
`redistribute bgp` sans filtre ferait entrer dans OSPF tous les préfixes de l'opérateur.

Évaluation (table BGP de `edge_isp`, LSA externes vus par `edge_ospf1`) : `edge_export` (4 : les
deux réseaux reçus de l'AS {asn}), `edge_export_only` (2 : rien d'autre de l'AS {asn} ; compté si
`edge_export` l'est), `edge_origin_med` (2 : origine *incomplete*, MED {med}), `edge_default` (3 :
route par défaut de `edge_ospf1` par `edge_b`), `edge_partner` (3 : LSA du préfixe partenaire,
type 1, métrique {metric}), `edge_partner_only` (2 : aucun autre préfixe de l'opérateur dans OSPF ;
compté si `edge_partner` l'est), `edge_ping` (2 : `edge_h1` joint `edge_inet` et `partner`).
"""), solution=_solution_text(ns.solution_edge()), lan1=net('edge_lan1'), lan2=net('edge_lan2'),
            med=2 * DEFAULT_COST, dc=DEFAULT_COST, asn=d.asn, metric=d.edge_metric)),
        )
        cheat_edge = {'origin': '?', 'med': str(2 * DEFAULT_COST), 'table': 'size', 'network': 'origin'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site edge"),
            hash="c00c2dc999df23d4",
            description=tr("""
- code d'origine BGP (`i`, `e` ou `?`) des réseaux de l'entreprise reçus par l'opérateur : @@{origin:[a-zA-Z?]+}@@
- MED de `edge_lan1` (colonne *Metric* de `show bgp ipv4 unicast` sur `edge_b`) : @@{med:[0-9]+}@@
- on ne redistribue jamais toute la table BGP d'Internet dans OSPF parce que :
  @@{table:>des centaines de milliers de routes satureraient la base et les calculs de chaque routeur OSPF>>>size|BGP l'interdit techniquement>>>forbidden|OSPF n'accepte que 100 routes externes>>>limit|les routes BGP n'ont pas de métrique>>>metric}@@
- `network` et `redistribute` dans BGP diffèrent par :
  @@{network:>l'origine (i pour network, ? pour redistribute) et ce qui est annoncé (un préfixe choisi ou toute une source)>>>origin|rien, ce sont deux syntaxes de la même commande>>>same|network ne fonctionne qu'en iBGP>>>ibgp|redistribute n'est possible que depuis OSPF>>>ospf}@@
""")
            + instructor(tr("""
**Solution.** **?** (*incomplete*) ; **{med}** ; **la taille de la table** ; **l'origine et ce qui
est annoncé**.

Évaluation : `edge_q_origin`, `edge_q_med` (1 chacun) et, pour l'enseignant seulement (choix dans
une liste), `edge_q_table`, `edge_q_network` (1 chacun).
""").format(med=2 * DEFAULT_COST)),
            cheat_answers={"final": cheat_edge, "solve_edge": cheat_edge},
        )
        edge_lans = [company_paths(edge_bgp, net(x)) for x in ('edge_lan1', 'edge_lan2')]
        edge_export = all(edge_lans)
        edge_others = {prefix for prefix in edge_bgp if company_paths(edge_bgp, prefix)} - \
            {str(net('edge_lan1')), str(net('edge_lan2'))}
        edge_origin_med = edge_export and all(str(p.get('origin') or '').lower() in BGP_ORIGIN_INCOMPLETE
                                              and p.get('med') == 2 * DEFAULT_COST for paths in edge_lans for p in paths)
        edge_default = (lsa(edge_lsas, '0.0.0.0/0', 'edge_b') is not None
                        and gateways(edge_k, '0.0.0.0/0') == [str(addr('edge_b', 'edge_l12'))])
        edge_partner = external(lsa(edge_lsas, net('edge_partner'), 'edge_b'), 1, d.edge_metric)
        edge_leaks = advertised(edge_lsas, 'edge_b') & {str(net(x)) for x in ('edge_inet1', 'edge_inet2', 'edge_linet')}
        self.add_grade_element(title=no_tr("edge_export"), max_grade=4, grade_part=part4,
                               grade=2 * sum(bool(x) for x in edge_lans),
                               description=tr("les réseaux de l'entreprise reçus par l'opérateur"))
        self.add_grade_element(title=no_tr("edge_export_only"), max_grade=2, grade_part=part4,
                               grade=2 * int(edge_export and not edge_others),
                               description=tr("rien d'autre envoyé à l'opérateur"))
        self.add_grade_element(title=no_tr("edge_origin_med"), max_grade=2, grade_part=part4,
                               grade=2 * int(edge_origin_med), description=tr("origine incomplete et MED"))
        self.add_grade_element(title=no_tr("edge_default"), max_grade=3, grade_part=part4, grade=3 * int(edge_default),
                               description=tr("route par défaut dans OSPF"))
        self.add_grade_element(title=no_tr("edge_partner"), max_grade=3, grade_part=part4, grade=3 * int(edge_partner),
                               description=tr("préfixe partenaire en externe de type 1 avec sa métrique"))
        self.add_grade_element(title=no_tr("edge_partner_only"), max_grade=2, grade_part=part4,
                               grade=2 * int(edge_partner and not edge_leaks),
                               description=tr("aucune autre route BGP dans OSPF"))
        self.add_grade_element(title=no_tr("edge_ping"), max_grade=2, grade_part=part4, grade=sum(edge_pings),
                               description=tr("edge_h1 joint edge_inet et partner"))
        self.add_grade_element(title=no_tr("edge_q_origin"), max_grade=1, grade_part=part4,
                               grade=int(_norm(q4.get('origin')) in ('?', 'incomplete', 'incomplet')),
                               description=tr("origine des routes redistribuées"))
        self.add_grade_element(title=no_tr("edge_q_med"), max_grade=1, grade_part=part4,
                               grade=int(_int(q4.get('med')) == 2 * DEFAULT_COST), description=tr("MED"))
        self.add_grade_element(title=no_tr("edge_q_table"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                               grade=int(_norm(q4.get('table')) == 'size'),
                               description=tr("pourquoi pas toute la table BGP"))
        self.add_grade_element(title=no_tr("edge_q_network"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                               grade=int(_norm(q4.get('network')) == 'origin'),
                               description=tr("network et redistribute"))

        # =====================================================================
        # Part 5 — troubleshooting (fix)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("fix"), tr("Partie 5 — dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Dépannage d'une redistribution"),
            hash="957844598ca00818",
            description=tr("""
Le site `fix` ressemble au site `mut` : `fix_rip1` dans le domaine RIP (`fix_lan1` avec `fix_h1`),
`fix_b` à la frontière, `fix_ospf1` dans le domaine OSPF (`fix_lan2` avec `fix_h2`), et des serveurs,
`fix_srv` `{srv}`, derrière la passerelle `fix_gw` de `fix_b`. Un administrateur a configuré la
redistribution de `fix_b`, mais presque rien ne marche. Ce qui est attendu :

- les réseaux du domaine RIP (le bloc `{block}`) sont annoncés dans OSPF, ceux d'OSPF dans RIP ;
- les serveurs `fix_srv` sont annoncés dans OSPF, par une route statique de FRR vers `fix_gw`
  (`{gw}`) ;
- le poste de supervision `fix_h2` joint `fix_h1` et **toutes les adresses** de `fix_rip1`.

Trouvez et corrigez les **quatre pannes** de `fix_b`, en corrigeant sa configuration plutôt qu'en la
réécrivant (configuration : `show running-config` ; symptômes : `show ip rip` sur `fix_rip1`, `show ip
ospf route` sur `fix_ospf1`, `show ip route` sur `fix_b`, `show route-map`, `show ip prefix-list` ;
section @@ref:diagnostic@@).
""").format(srv=net('fix_srv'), block=net('fix_rip_block'), gw=addr('fix_gw', 'fix_lgw'))
            + instructor(_by_language(tr("""
**Solution.** Les quatre pannes et leur correction :

1. `redistribute ospf metric {bad}` sous `router rip` : `fix_rip1` reçoit les routes OSPF à 16,
   inaccessibles ;
2. `ip prefix-list RIP-NETS seq 10 permit {block}` sans `le` : la liste ne laisse passer que le
   préfixe `{block}` lui-même, la route-map `RIP-TO-OSPF` refuse tous les réseaux RIP ;
3. `ip route {srv} {wrong}` : prochain saut injoignable (le bon est `{gw}`), la route est inactive
   et n'est pas redistribuée ;
4. pas de `redistribute connected` : le lien `fix_lrb` (l'adresse `{r1}` de `fix_rip1`) est un
   réseau connecté de `fix_b`, inconnu d'OSPF.

{solution}

Évaluation : `fix_seed` (3 : route de `fix_rip1` vers `fix_lan2`, métrique inférieure à 16),
`fix_filter` (3 : LSA de `fix_lan1` par `fix_b` vu de `fix_ospf1`), `fix_static` (3 : LSA de
`fix_srv`), `fix_connected` (3 : route OSPF de `fix_ospf1` vers `fix_lrb`), `fix_ping` (2 : `fix_h2`
joint `fix_h1` et `{r1}`).
"""), bad=FIX_BAD_SEED, block=net('fix_rip_block'), srv=net('fix_srv'), wrong=ns.fix_wrong_nexthop(),
            gw=addr('fix_gw', 'fix_lgw'), r1=addr('fix_rip1', 'fix_lrb'), solution=_solution_text(ns.solution_fix()))),
        )
        cheat_fix = {'metric_before': '16', 'seed': 'infinity', 'plist': 'exact', 'static': 'inactive'}
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Les symptômes du site fix"),
            hash="f0e5caf2fd082f98",
            description=tr("""
- avant correction, métrique de `fix_lan2` dans `show ip rip` de `fix_rip1` : @@{metric_before:[0-9]+}@@
- la première panne de RIP vient de ce que :
  @@{seed:>annoncée avec la métrique 15, une route arrive à 16 chez le voisin : inaccessible>>>infinity|RIP refuse les routes redistribuées depuis OSPF>>>refused|la version 1 de RIP ne transporte pas les masques>>>version|l'horizon partagé (split horizon) bloque la route>>>split}@@
- la liste de préfixes `RIP-NETS` refusait tout parce que :
  @@{plist:>sans le, une règle ne laisse passer que le préfixe exact, ici le /22 lui-même>>>exact|une liste de préfixes ne peut pas servir dans une route-map>>>usage|le numéro de séquence 10 est réservé>>>seq|il manque une règle deny à la fin>>>deny}@@
- la route statique vers `fix_srv` n'était pas redistribuée parce que :
  @@{static:>son prochain saut n'est joignable par aucune route : elle est inactive>>>inactive|une route statique ne se redistribue pas dans OSPF>>>never|fix_gw ne répond pas au ping>>>ping|il faudrait redistribute kernel>>>kernel}@@
""")
            + instructor(tr("""
**Solution.** **16** ; **la métrique 15** ; **le préfixe exact** ; **une route statique inactive**.

Évaluation : `fix_q_metric` (1) et, pour l'enseignant seulement (choix dans une liste), `fix_q_seed`,
`fix_q_filter`, `fix_q_static` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        fix_seed = (rip_route_metric(fix_rip, net('fix_lan2'), learned=True) not in (None, 16)
                    and route_by(fix_k_rip, net('fix_lan2'), is_rip_protocol))
        self.add_grade_element(title=no_tr("fix_seed"), max_grade=3, grade_part=part5, grade=3 * int(fix_seed),
                               description=tr("fix_lan2 accessible dans RIP"))
        self.add_grade_element(title=no_tr("fix_filter"), max_grade=3, grade_part=part5,
                               grade=3 * int(lsa(fix_lsas, net('fix_lan1'), 'fix_b') is not None),
                               description=tr("les réseaux RIP annoncés dans OSPF"))
        self.add_grade_element(title=no_tr("fix_static"), max_grade=3, grade_part=part5,
                               grade=3 * int(lsa(fix_lsas, net('fix_srv'), 'fix_b') is not None),
                               description=tr("fix_srv annoncé dans OSPF"))
        self.add_grade_element(title=no_tr("fix_connected"), max_grade=3, grade_part=part5,
                               grade=3 * int(route_by(fix_k_ospf, net('fix_lrb'), is_ospf_protocol)),
                               description=tr("fix_lrb connu dans OSPF"))
        self.add_grade_element(title=no_tr("fix_ping"), max_grade=2, grade_part=part5, grade=sum(fix_pings),
                               description=tr("fix_h2 joint fix_h1 et fix_rip1"))
        self.add_grade_element(title=no_tr("fix_q_metric"), max_grade=1, grade_part=part5,
                               grade=int(_int(q5.get('metric_before')) == 16),
                               description=tr("métrique avant correction"))
        self.add_grade_element(title=no_tr("fix_q_seed"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(_norm(q5.get('seed')) == 'infinity'), description=tr("panne de la métrique"))
        self.add_grade_element(title=no_tr("fix_q_filter"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(_norm(q5.get('plist')) == 'exact'), description=tr("panne de la liste"))
        self.add_grade_element(title=no_tr("fix_q_static"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(_norm(q5.get('static')) == 'inactive'),
                               description=tr("panne de la route statique"))

        # =====================================================================
        # Bonus — summarisation on an ASBR (sum)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("sum"), tr("Bonus — résumé sur un ASBR (site sum)"))
        sum_nets = ns.sum_nets()
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : résumer les routes externes"),
            hash="2586db95ad9c7549",
            description=tr("""
`sum_asbr` est l'ASBR d'un domaine OSPF : il redistribue des routes statiques vers {count} réseaux
/24 contigus derrière `sum_gw`, de `{first}` à `{last}`, et `sum_ospf1` reçoit {count} LSA externes.
Sur `sum_asbr`, faites qu'OSPF n'annonce plus qu'**un seul préfixe**, `{block}`, marqué de
l'étiquette **{tag}** (section @@ref:summary@@). Vérifiez sur `sum_ospf1`.
""").format(count=SUM_COUNT, first=sum_nets[0], last=sum_nets[-1], block=net('sum_block'), tag=d.tag_sum)
            + instructor(_by_language(tr("""
**Solution.**

{solution}

Évaluation (bonus) : `sum_summary` (3 : LSA de `{block}` par `sum_asbr`, étiquette {tag}),
`sum_specifics` (2 : plus aucun LSA des /24), `sum_ping` (1 : `sum_ospf1` joint `{host}`) ; les deux
comptés si `sum_summary` l'est.
"""), solution=_solution_text(ns.solution_sum()), block=net('sum_block'), tag=d.tag_sum,
            host=first_host(sum_nets[0]))),
        )
        sum_entry = lsa(sum_lsas, net('sum_block'), 'sum_asbr')
        sum_ok = bool(sum_entry) and sum_entry.get('tag') == d.tag_sum
        sum_left = advertised(sum_lsas, 'sum_asbr') & {str(x) for x in sum_nets}
        self.add_grade_element(title=no_tr("sum_summary"), max_grade=3, grade_part=part6, bonus=True,
                               grade=3 * int(sum_ok), description=tr("le résumé, avec son étiquette"))
        self.add_grade_element(title=no_tr("sum_specifics"), max_grade=2, grade_part=part6, bonus=True,
                               grade=2 * int(sum_ok and not sum_left), description=tr("plus aucun /24 annoncé"))
        self.add_grade_element(title=no_tr("sum_ping"), max_grade=1, grade_part=part6, bonus=True,
                               grade=int(sum_ok and sum_ping), description=tr("sum_ospf1 joint un des réseaux résumés"))

        # =====================================================================
        # Bonus — NSSA (nssa)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("nssa"), tr("Bonus — aire NSSA (site nssa)"))
        area = f"0.0.0.{NSSA_AREA}"
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : un ASBR dans une aire qui refuse les routes externes"),
            hash="81ecf15c60153f7c",
            description=tr("""
L'aire {area} de ce domaine (`nssa_abr`, ABR entre l'aire 0 et l'aire {area}, et `nssa_asbr`) est une
aire **stub** : elle ne reçoit pas la route externe `nssa_coreext` (`{coreext}`) que redistribue
`nssa_core`, et c'est voulu. Mais `nssa_asbr` doit faire connaître au reste du domaine les réseaux
`nssa_ext1` `{e1}` et `nssa_ext2` `{e2}`, derrière `nssa_gw` : il a les routes statiques et
`redistribute static`, sans effet. Sur `nssa_abr` et `nssa_asbr`, faites que ces deux réseaux
atteignent `nssa_core`, l'aire {area} refusant toujours les routes externes du reste du domaine
(section @@ref:nssa@@).
""").format(area=NSSA_AREA, coreext=net('nssa_coreext'), e1=net('nssa_ext1'), e2=net('nssa_ext2'))
            + instructor(_by_language(tr("""
**Solution.** Sur `nssa_abr` et `nssa_asbr` :

{solution}

`nssa_abr` reçoit de `nssa_asbr` deux LSA de type 7 (`show ip ospf database nssa-external`) et les
traduit en LSA de type 5, annoncés en son nom (`{rid}`), l'adresse de `nssa_asbr` en *Forward
Address* : `nssa_core` les voit venir de `nssa_abr`, pas de `nssa_asbr`.

Évaluation (bonus) : `nssa_area` (1 : l'aire est NSSA sur les deux routeurs, adjacence `Full`),
`nssa_type7` (2 : LSA de type 7 de `nssa_asbr` pour les deux réseaux dans la base de `nssa_abr`),
`nssa_translated` (2 :
LSA de type 5 des deux réseaux annoncés par `nssa_abr`, vus de `nssa_core`), `nssa_blocked` (1 :
`nssa_asbr` n'a pas de route vers `nssa_coreext` ; compté si `nssa_area` l'est).
"""), solution=_solution_text({'nssa_abr': ns.solution_nssa()['nssa_abr']}), rid=rid('nssa_abr'))),
        )
        nssa_area = (all((nssa_info[m].get('areas', {}).get(area) or {}).get('type') == 'nssa'
                         for m in ('nssa_abr', 'nssa_asbr'))
                     and neighbor_is_full(nssa_nb, neighbor_id=rid('nssa_asbr')))
        nssa_type7 = all(lsa(nssa_type7_lsas, net(x), 'nssa_asbr') is not None for x in ('nssa_ext1', 'nssa_ext2'))
        nssa_translated = all(lsa(nssa_lsas, net(x), 'nssa_abr') is not None for x in ('nssa_ext1', 'nssa_ext2'))
        self.add_grade_element(title=no_tr("nssa_area"), max_grade=1, grade_part=part7, bonus=True,
                               grade=int(nssa_area), description=tr("aire NSSA sur les deux routeurs"))
        self.add_grade_element(title=no_tr("nssa_type7"), max_grade=2, grade_part=part7, bonus=True,
                               grade=2 * int(nssa_type7), description=tr("routes de type 7 sur l'ABR"))
        self.add_grade_element(title=no_tr("nssa_translated"), max_grade=2, grade_part=part7, bonus=True,
                               grade=2 * int(nssa_translated), description=tr("traduction en type 5 par l'ABR"))
        self.add_grade_element(title=no_tr("nssa_blocked"), max_grade=1, grade_part=part7, bonus=True,
                               grade=int(nssa_area and str(net('nssa_coreext')) not in nssa_k),
                               description=tr("les routes externes du domaine restent hors de l'aire"))

        # =====================================================================
        # Bonus — BGP aggregation (agg)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("agg"), tr("Bonus — agrégation BGP (site agg)"))
        agg_nets = ns.agg_nets()
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : agréger les routes redistribuées dans BGP"),
            hash="f3c4255611a454cf",
            description=tr("""
`agg_b` redistribue déjà dans BGP, vers l'opérateur `agg_isp`, les {count} réseaux /24 de l'entreprise
portés par `agg_ospf1` (bloc `{block}`) : l'opérateur reçoit {count} préfixes. Sur `agg_b`, faites
qu'il ne reçoive plus que le préfixe agrégé `{block}` (section @@ref:summary@@).
""").format(count=AGG_COUNT, block=net('agg_company'))
            + instructor(_by_language(tr("""
**Solution.**

{solution}

Les {count} /24 restent dans la table BGP de `agg_b`, marqués `s` (*suppressed*).

Évaluation (bonus) : `agg_aggregate` (4 : `agg_isp` reçoit `{block}` de l'AS {asn}), `agg_specifics`
(2 : il ne reçoit plus aucun des /24 ; compté si `agg_aggregate` l'est).
"""), solution=_solution_text(ns.solution_agg()), count=AGG_COUNT, block=net('agg_company'), asn=d.asn)),
        )
        agg_ok = bool(company_paths(agg_bgp, net('agg_company')))
        agg_left = [x for x in agg_nets if str(x) in agg_bgp]
        self.add_grade_element(title=no_tr("agg_aggregate"), max_grade=4, grade_part=part8, bonus=True,
                               grade=4 * int(agg_ok), description=tr("le préfixe agrégé reçu par l'opérateur"))
        self.add_grade_element(title=no_tr("agg_specifics"), max_grade=2, grade_part=part8, bonus=True,
                               grade=2 * int(agg_ok and not agg_left), description=tr("plus aucun /24 envoyé"))


_TRANSLATIONS = {'en': {
    "Redistribution : échanger des routes entre RIP, OSPF, BGP et routes statiques": "Route redistribution: exchanging routes between RIP, OSPF, BGP and static routes",
    """
**Sommaire**
""": """
**Contents**
""",
    "Pourquoi redistribuer": "Why redistribute",
    """
Un **domaine de routage** est un ensemble de routeurs qui échangent leurs routes avec un même
protocole : un domaine OSPF, un domaine RIP, une session BGP avec un opérateur. Un réseau réel en
contient souvent plusieurs :

- un ancien site encore en RIP raccordé à un cœur OSPF, le temps d'une migration ou après la fusion
  de deux entreprises ;
- des réseaux qui ne parlent aucun protocole de routage : les réseaux directement connectés à un
  routeur (serveurs, administration), les routes statiques vers un partenaire ou un équipement
  simple ;
- la frontière avec un opérateur, en BGP.

Chaque protocole ne connaît que ses propres routes. La **redistribution** fait entrer dans un
**protocole de destination** les routes d'une **source** : un autre protocole, les réseaux
connectés, les routes statiques, les routes du noyau. Le routeur qui la réalise, à cheval sur les
deux, est un **point de redistribution** ; en OSPF on l'appelle **ASBR** (*AS Boundary Router*).
Elle se configure **dans le protocole de destination** :

```
router ospf
 redistribute rip            ! les routes RIP deviennent des routes externes d'OSPF
router rip
 redistribute ospf           ! et les routes OSPF des routes RIP : redistribution mutuelle
```

Une redistribution ne va que dans **un sens** : `redistribute rip` sous `router ospf` fait
connaître les réseaux du domaine RIP au domaine OSPF, pas l'inverse. Pour que les machines des deux
domaines se joignent il faut les deux sens (**redistribution mutuelle**) : sans le retour, les
paquets partent mais les réponses ne reviennent pas.

Dans FRR, chaque démon (`ripd`, `ospfd`, `bgpd`, `staticd`) propose ses meilleures routes à
**zebra**, qui tient la table de routage du routeur (la **RIB**), choisit une route par préfixe
parmi celles qu'on lui propose et l'installe dans le noyau. Une redistribution est un abonnement :
`redistribute rip` dans `ospfd` demande à zebra les routes **choisies** dont la source est RIP. Une
route RIP qui a perdu face à une route d'une autre source (section @@ref:rib@@) n'est donc **pas**
redistribuée.
""": """
A **routing domain** is a set of routers that exchange their routes with the same protocol: an OSPF
domain, a RIP domain, a BGP session with an operator. A real network often contains several of
them:

- an old site still running RIP connected to an OSPF core, for the duration of a migration or after
  the merger of two companies;
- networks that speak no routing protocol at all: the networks directly connected to a router
  (servers, administration), the static routes to a partner or to a simple device;
- the border with an operator, in BGP.

Each protocol only knows its own routes. **Redistribution** brings the routes of a **source** into
a **destination protocol**: another protocol, the connected networks, the static routes, the kernel
routes. The router that does it, straddling both, is a **redistribution point**; in OSPF it is
called an **ASBR** (*AS Boundary Router*). It is configured **in the destination protocol**:

```
router ospf
 redistribute rip            ! the RIP routes become OSPF external routes
router rip
 redistribute ospf           ! and the OSPF routes become RIP routes: mutual redistribution
```

A redistribution only goes **one way**: `redistribute rip` under `router ospf` makes the networks
of the RIP domain known to the OSPF domain, not the reverse. For the machines of the two domains to
reach each other, both directions are needed (**mutual redistribution**): without the way back, the
packets go out but the replies do not come back.

In FRR, each daemon (`ripd`, `ospfd`, `bgpd`, `staticd`) offers its best routes to **zebra**, which
holds the routing table of the router (the **RIB**), chooses one route per prefix among those
offered and installs it in the kernel. A redistribution is a subscription: `redistribute rip` in
`ospfd` asks zebra for the **chosen** routes whose source is RIP. A RIP route that lost against a
route from another source (section @@ref:rib@@) is therefore **not** redistributed.
""",
    "La distance administrative": "The administrative distance",
    """
Quand plusieurs sources proposent le même préfixe, zebra ne compare pas leurs métriques (un nombre
de sauts RIP et un coût OSPF ne se comparent pas) mais leur **distance administrative**, la
confiance accordée à la source : la plus petite gagne ; à distance égale, la métrique départage.

| source | code dans `show ip route` | distance (FRR) |
|--------|---------------------------|----------------|
| réseau connecté | `C` | 0 |
| route du noyau (`ip route add`) | `K` | 0 |
| route statique de FRR | `S` | 1 |
| eBGP | `B` | 20 |
| OSPF | `O` | 110 |
| IS-IS | `I` | 115 |
| RIP | `R` | 120 |
| iBGP | `B` | 200 |

`show ip route` affiche `[distance/métrique]` : `O>* 192.0.2.0/24 [110/20] via …` ; `>` marque la
route choisie, `*` une route installée dans le noyau. `show ip route 192.0.2.0/24` détaille toutes
les routes connues pour ce préfixe, choisies ou non.

Les distances se règlent dans chaque protocole :

```
router ospf
 distance ospf external 250    ! les routes externes (E1, E2) ; aussi intra-area, inter-area
router rip
 distance 100                  ! toutes les routes RIP
router bgp 64500
 address-family ipv4 unicast
  distance bgp 20 200 200      ! eBGP, iBGP, routes locales
```

FRR n'applique une nouvelle distance qu'aux routes qu'il installe **ensuite** : les routes déjà dans
la RIB gardent l'ancienne. Pour OSPF, `clear ip ospf process` (en mode privilégié, sur le routeur
modifié) recalcule et réinstalle toutes ses routes.
""": """
When several sources offer the same prefix, zebra does not compare their metrics (a RIP hop count
and an OSPF cost cannot be compared) but their **administrative distance**, the trust given to the
source: the smallest one wins; at equal distance, the metric decides.

| source | code in `show ip route` | distance (FRR) |
|--------|-------------------------|----------------|
| connected network | `C` | 0 |
| kernel route (`ip route add`) | `K` | 0 |
| FRR static route | `S` | 1 |
| eBGP | `B` | 20 |
| OSPF | `O` | 110 |
| IS-IS | `I` | 115 |
| RIP | `R` | 120 |
| iBGP | `B` | 200 |

`show ip route` displays `[distance/metric]`: `O>* 192.0.2.0/24 [110/20] via …`; `>` marks the
chosen route, `*` a route installed in the kernel. `show ip route 192.0.2.0/24` details all the
routes known for this prefix, chosen or not.

The distances are set in each protocol:

```
router ospf
 distance ospf external 250    ! the external routes (E1, E2); also intra-area, inter-area
router rip
 distance 100                  ! all the RIP routes
router bgp 64500
 address-family ipv4 unicast
  distance bgp 20 200 200      ! eBGP, iBGP, local routes
```

FRR applies a new distance only to the routes it installs **afterwards**: the routes already in the
RIB keep the old one. For OSPF, `clear ip ospf process` (in privileged mode, on the modified router)
recomputes and reinstalls all its routes.
""",
    "Les métriques": "Metrics",
    """
Chaque protocole a sa métrique : un nombre de sauts de 1 à 15 en RIP (16 = inaccessible), un coût
cumulé en OSPF, l'attribut MED en BGP. Une route redistribuée reçoit donc une **métrique
d'amorçage** (*seed metric*) dans le protocole de destination, choisie par le point de
redistribution ; elle évolue ensuite normalement (RIP ajoute 1 à chaque routeur ; OSPF ajoute ou
non le coût interne).

| destination | métrique par défaut (FRR) | réglages |
|-------------|---------------------------|----------|
| RIP | 1 | `redistribute ospf metric 8`, `default-metric 8`, `set metric` |
| OSPF | 20, externe de type 2 | `redistribute rip metric-type 1 metric 1000`, `default-metric`, `set metric`, `set metric-type` |
| BGP | MED = métrique de la route dans la RIB, origine *incomplete* | `set metric` |

- **RIP** : un routeur ajoute 1 à la métrique qu'il reçoit. Une métrique d'amorçage trop grande
  rend les routes inaccessibles : annoncée à 15, une route arrive à 16 chez le voisin. Une métrique
  trop petite fait croire qu'un réseau est tout proche, ce qui peut attirer le trafic dans un
  détour par l'autre domaine (section @@ref:multipoint@@).
- **OSPF** : une route externe de **type 2** (E2, le défaut) garde sa métrique externe dans tout le
  domaine ; entre deux routes E2 de même métrique, le coût jusqu'à l'ASBR départage. Une route de
  **type 1** (E1) reçoit en plus le coût du chemin jusqu'à l'ASBR, comme une route interne ; elle
  est toujours préférée à une route E2. `show ip ospf route` affiche `N E2 192.0.2.0/24 [10/20]`
  (coût jusqu'à l'ASBR / métrique externe) et `N E1 192.0.2.0/24 [30]` (la somme).
- **BGP** : section @@ref:bgp@@.
""": """
Each protocol has its own metric: a hop count from 1 to 15 in RIP (16 = unreachable), a cumulative
cost in OSPF, the MED attribute in BGP. A redistributed route therefore receives a **seed metric**
in the destination protocol, chosen by the redistribution point; it then evolves normally (RIP adds
1 at each router; OSPF adds the internal cost or not).

| destination | default metric (FRR) | settings |
|-------------|----------------------|----------|
| RIP | 1 | `redistribute ospf metric 8`, `default-metric 8`, `set metric` |
| OSPF | 20, external type 2 | `redistribute rip metric-type 1 metric 1000`, `default-metric`, `set metric`, `set metric-type` |
| BGP | MED = metric of the route in the RIB, origin *incomplete* | `set metric` |

- **RIP**: a router adds 1 to the metric it receives. A seed metric that is too large makes the
  routes unreachable: advertised at 15, a route arrives at 16 at the neighbour. A metric that is too
  small makes a network look very close, which can draw the traffic into a detour through the other
  domain (section @@ref:multipoint@@).
- **OSPF**: an external route of **type 2** (E2, the default) keeps its external metric throughout
  the domain; between two E2 routes with the same metric, the cost to the ASBR decides. A route of
  **type 1** (E1) also receives the cost of the path to the ASBR, like an internal route; it is
  always preferred to an E2 route. `show ip ospf route` displays `N E2 192.0.2.0/24 [10/20]` (cost
  to the ASBR / external metric) and `N E1 192.0.2.0/24 [30]` (the sum).
- **BGP**: section @@ref:bgp@@.
""",
    "Filtrer et marquer : listes de préfixes et route-maps": "Filtering and tagging: prefix lists and route-maps",
    """
Redistribuer « tout » est rarement ce qu'on veut. On choisit les routes avec une **route-map**,
attachée à la redistribution : `redistribute connected route-map NOM`.

**Liste de préfixes** (*prefix-list*) : des règles numérotées, examinées dans l'ordre ; la
première qui correspond décide ; un préfixe qu'aucune règle n'accepte est refusé (*deny* implicite
à la fin).

```
ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24   ! les préfixes de 10.1.0.0/16, du /16 au /24
ip prefix-list LANS seq 20 permit 192.0.2.0/24        ! exactement 192.0.2.0/24
```

Sans `ge` ni `le`, une règle ne correspond **qu'au préfixe exact** : `permit 10.1.0.0/16` ne laisse
pas passer `10.1.5.0/24`. `le N` (*less or equal*) accepte aussi les préfixes plus longs jusqu'à
/N, `ge N` impose une longueur minimale.

**Route-map** : des entrées `permit` ou `deny` numérotées, examinées dans l'ordre. Une entrée
contient des conditions `match` (toutes doivent être vraies ; sans condition, l'entrée correspond
toujours) et, pour `permit`, des actions `set`. La première entrée qui correspond décide : la route
est acceptée (et modifiée) ou refusée. Une route qui ne correspond à aucune entrée est **refusée**.

```
route-map RIP-TO-OSPF deny 10
 match tag 7                            ! refuse les routes marquées 7
exit
route-map RIP-TO-OSPF permit 20
 match ip address prefix-list LANS      ! accepte les préfixes de LANS...
 set metric 1000                        ! ...avec la métrique 1000
 set metric-type type-1                 ! en externe de type 1 (OSPF)
 set tag 1                              ! et les marque 1
exit
router ospf
 redistribute rip route-map RIP-TO-OSPF
```

| condition ou action | effet |
|---------------------|-------|
| `match ip address prefix-list L` | le préfixe est accepté par la liste L |
| `match interface ethX` | la route sort par ethX (le réseau connecté de ethX) |
| `match tag N` | la route porte l'étiquette N |
| `set metric N` | la métrique d'amorçage (prime sur `redistribute … metric`) |
| `set metric-type type-1` ou `type-2` | le type de la route externe OSPF |
| `set tag N` | pose l'étiquette N |

Une **étiquette** (*tag*) est un nombre attaché à une route, transporté par le protocole sans être
interprété : 32 bits dans un LSA externe d'OSPF, 16 bits dans une route RIPv2. Une route statique
peut en porter une (`ip route 192.0.2.0/24 10.0.0.1 tag 2`). Zebra garde l'étiquette d'une route
quand il la passe d'un démon à l'autre : on s'en sert pour reconnaître d'où vient une route au
moment de la redistribuer.

`show route-map` affiche les route-maps et le nombre de fois où elles ont été appliquées
(*Invoked*), `show ip prefix-list` les listes de préfixes et leurs compteurs.
""": """
Redistributing "everything" is rarely what you want. The routes are chosen with a **route-map**,
attached to the redistribution: `redistribute connected route-map NAME`.

**Prefix list** (*prefix-list*): numbered rules, examined in order; the first one that matches
decides; a prefix that no rule accepts is refused (implicit *deny* at the end).

```
ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24   ! the prefixes of 10.1.0.0/16, from /16 to /24
ip prefix-list LANS seq 20 permit 192.0.2.0/24        ! exactly 192.0.2.0/24
```

Without `ge` or `le`, a rule matches **only the exact prefix**: `permit 10.1.0.0/16` does not let
`10.1.5.0/24` through. `le N` (*less or equal*) also accepts the longer prefixes up to /N, `ge N`
imposes a minimum length.

**Route-map**: numbered `permit` or `deny` entries, examined in order. An entry contains `match`
conditions (all of them must be true; without a condition, the entry always matches) and, for
`permit`, `set` actions. The first entry that matches decides: the route is accepted (and modified)
or refused. A route that matches no entry is **refused**.

```
route-map RIP-TO-OSPF deny 10
 match tag 7                            ! refuses the routes tagged 7
exit
route-map RIP-TO-OSPF permit 20
 match ip address prefix-list LANS      ! accepts the prefixes of LANS...
 set metric 1000                        ! ...with the metric 1000
 set metric-type type-1                 ! as external type 1 (OSPF)
 set tag 1                              ! and tags them 1
exit
router ospf
 redistribute rip route-map RIP-TO-OSPF
```

| condition or action | effect |
|---------------------|--------|
| `match ip address prefix-list L` | the prefix is accepted by the list L |
| `match interface ethX` | the route goes out through ethX (the connected network of ethX) |
| `match tag N` | the route carries the tag N |
| `set metric N` | the seed metric (takes precedence over `redistribute … metric`) |
| `set metric-type type-1` or `type-2` | the type of the OSPF external route |
| `set tag N` | sets the tag N |

A **tag** is a number attached to a route, carried by the protocol without being interpreted: 32
bits in an OSPF external LSA, 16 bits in a RIPv2 route. A static route can carry one (`ip route
192.0.2.0/24 10.0.0.1 tag 2`). Zebra keeps the tag of a route when it hands it from one daemon to
another: it is used to recognise where a route comes from at the moment it is redistributed.

`show route-map` displays the route-maps and the number of times they have been applied
(*Invoked*), `show ip prefix-list` the prefix lists and their counters.
""",
    "Réseaux connectés, routes statiques et routes du noyau": "Connected networks, static routes and kernel routes",
    """
- `redistribute connected` : les réseaux des interfaces du routeur (code `C`), **tous** : ceux des
  interfaces déjà couvertes par le protocole (une route externe de plus, inutile) comme ceux qui
  doivent rester privés. On le filtre presque toujours avec une route-map.
- `redistribute static` : les routes statiques **de FRR** (`ip route …` dans vtysh, gérées par
  `staticd`, code `S`). Une route statique dont le prochain saut n'est joignable par aucune route
  est **inactive** : `show ip route` ne la marque pas comme choisie, elle n'est ni installée ni
  redistribuée.
- `redistribute kernel` : les routes posées directement dans le noyau, par `ip route add` ou par un
  autre logiciel (code `K`). FRR leur donne la distance 0 : une route du noyau l'emporte sur une
  route statique de FRR vers le même préfixe, qui n'est alors ni choisie ni redistribuée. Mieux vaut
  supprimer la route du noyau (`ip route del`) et la déclarer dans FRR, où elle est enregistrée
  avec le reste de la configuration.

Un point de redistribution a ses propres réseaux connectés dans chacun des domaines. Ce sont des
routes `C` de sa RIB, pas des routes RIP ni OSPF : `redistribute rip` ne les emporte pas, même si
RIP est activé sur ces interfaces. Pour que l'autre domaine les connaisse, il faut en plus
`redistribute connected`, filtré sur ces réseaux.
""": """
- `redistribute connected`: the networks of the router's interfaces (code `C`), **all** of them:
  those of the interfaces already covered by the protocol (one more external route, useless) as
  well as those that must stay private. It is almost always filtered with a route-map.
- `redistribute static`: the static routes **of FRR** (`ip route …` in vtysh, managed by
  `staticd`, code `S`). A static route whose next hop is reachable by no route is **inactive**:
  `show ip route` does not mark it as chosen, it is neither installed nor redistributed.
- `redistribute kernel`: the routes set directly in the kernel, by `ip route add` or by another
  piece of software (code `K`). FRR gives them distance 0: a kernel route wins over an FRR static
  route to the same prefix, which is then neither chosen nor redistributed. It is better to delete
  the kernel route (`ip route del`) and declare it in FRR, where it is saved with the rest of the
  configuration.

A redistribution point has its own connected networks in each of the domains. They are `C` routes
of its RIB, not RIP or OSPF routes: `redistribute rip` does not carry them, even if RIP is enabled
on these interfaces. For the other domain to know them, `redistribute connected` is needed as well,
filtered on these networks.
""",
    "La route par défaut": "The default route",
    """
La route par défaut est traitée à part : `redistribute static` ne l'emporte pas, même quand c'est
une route statique de FRR. En OSPF :

```
router ospf
 default-information originate                     ! si le routeur a lui-même une route par défaut
 default-information originate always              ! même sans (gare au trou noir)
 default-information originate metric 5000 metric-type 1
```

Le routeur annonce alors un LSA externe pour `0.0.0.0/0` (type 2, métrique 10 par défaut). Sans
`always`, il ne l'annonce que tant qu'il a une route par défaut active, quelle qu'en soit l'origine
(statique, BGP…) : l'annonce disparaît avec l'accès à l'extérieur, et le trafic part vers un autre
point de sortie s'il y en a un. En RIP : `default-information originate` sous `router rip`.
""": """
The default route is handled separately: `redistribute static` does not carry it, even when it is
an FRR static route. In OSPF:

```
router ospf
 default-information originate                     ! if the router itself has a default route
 default-information originate always              ! even without one (beware of the black hole)
 default-information originate metric 5000 metric-type 1
```

The router then advertises an external LSA for `0.0.0.0/0` (type 2, metric 10 by default). Without
`always`, it advertises it only as long as it has an active default route, whatever its origin
(static, BGP…): the advertisement disappears with the access to the outside, and the traffic goes
to another exit point if there is one. In RIP: `default-information originate` under `router rip`.
""",
    "Redistribuer en plusieurs points": "Redistributing at several points",
    """
Un seul point de redistribution est un point de panne unique : on en met souvent deux. La
redistribution mutuelle en plusieurs points crée alors des problèmes qui n'existent pas avec un
seul.

```
                +----- B1 -----+
   réseau N --- R              O --- réseaux OSPF
                +----- B2 -----+
      domaine RIP          domaine OSPF
```

1. **Chemins sous-optimaux.** B1 redistribue dans OSPF le réseau N, qu'il connaît par RIP. B2
   connaît N par RIP (distance 120) **et** par OSPF, comme route externe venue de B1 (distance 110) :
   il choisit OSPF et envoie le trafic vers N à travers le domaine OSPF jusqu'à B1, alors que R est
   son voisin direct. Et comme la route choisie par B2 n'est plus une route RIP, B2 ne redistribue
   pas N : la redondance attendue n'existe pas.
2. **Boucles par retour des routes** (*route feedback*). Si B2 redistribue aussi OSPF dans RIP, il
   annonce N dans le domaine RIP avec **sa** métrique d'amorçage, qui ne dit rien de la distance
   réelle. Si elle est plus petite que la métrique RIP de N, les routeurs RIP proches de B2
   préfèrent ce chemin : les paquets vers N vont de R à B2, traversent OSPF jusqu'à B1, qui les
   rend à R… une **boucle**, entretenue par les redistributions elles-mêmes.
3. **Oscillations.** Quand les deux points redistribuent la même route au même moment, chacun peut
   préférer celle de l'autre, retirer la sienne, puis la reprendre : la route clignote.

Les remèdes, souvent combinés :

- **marquer et refuser le retour** : toute route qui entre dans OSPF depuis RIP reçoit une
  étiquette (`set tag 1`), et la redistribution d'OSPF dans RIP refuse les routes qui la portent
  (une entrée `deny` avec `match tag 1`) ; de même dans l'autre sens avec une autre étiquette. Une
  route ne repasse jamais la frontière en sens inverse, quel que soit le point de redistribution ;
- **ajuster les distances**, pour que chaque point de redistribution préfère la source d'origine
  d'une route : par exemple une distance des routes externes d'OSPF supérieure à celle de RIP, pour
  qu'une route RIP l'emporte sur la même route revenue par OSPF ;
- **filtrer par préfixes**, quand les plans d'adressage des domaines sont bien séparés.
""": """
A single redistribution point is a single point of failure: there are often two. Mutual
redistribution at several points then creates problems that do not exist with a single one.

```
                +----- B1 -----+
   network N -- R              O --- OSPF networks
                +----- B2 -----+
      RIP domain           OSPF domain
```

1. **Suboptimal paths.** B1 redistributes into OSPF the network N, which it knows through RIP. B2
   knows N through RIP (distance 120) **and** through OSPF, as an external route coming from B1
   (distance 110): it chooses OSPF and sends the traffic for N across the OSPF domain to B1,
   although R is its direct neighbour. And since the route chosen by B2 is no longer a RIP route, B2
   does not redistribute N: the expected redundancy does not exist.
2. **Loops caused by routes coming back** (*route feedback*). If B2 also redistributes OSPF into
   RIP, it advertises N in the RIP domain with **its** seed metric, which says nothing about the real
   distance. If it is smaller than the RIP metric of N, the RIP routers close to B2 prefer this path:
   the packets for N go from R to B2, cross OSPF to B1, which hands them back to R… a **loop**,
   sustained by the redistributions themselves.
3. **Oscillations.** When both points redistribute the same route at the same time, each of them
   may prefer the other's route, withdraw its own, then take it back: the route flaps.

The remedies, often combined:

- **tag and refuse the way back**: every route that enters OSPF from RIP receives a tag (`set tag
  1`), and the redistribution of OSPF into RIP refuses the routes that carry it (a `deny` entry with
  `match tag 1`); likewise in the other direction with another tag. A route never crosses the
  border back in the opposite direction, whatever the redistribution point;
- **adjust the distances**, so that each redistribution point prefers the original source of a
  route: for example a distance of the OSPF external routes higher than that of RIP, so that a RIP
  route wins over the same route come back through OSPF;
- **filter by prefixes**, when the addressing plans of the domains are well separated.
""",
    "IGP et BGP": "IGP and BGP",
    """
- **De l'IGP vers BGP.** On annonce ses réseaux à un opérateur avec `network` (le préfixe doit être
  dans la RIB ; origine *IGP*, code `i`) ou en redistribuant l'IGP (`redistribute ospf` sous
  `address-family ipv4 unicast` ; origine *incomplete*, code `?`, et MED = métrique de la route dans
  l'IGP). Le filtre est indispensable : sans lui partent aussi les réseaux d'interconnexion privés et
  tout ce que l'IGP a appris. Dans le choix du meilleur chemin BGP, l'origine `i` est préférée à `?`
  (après la longueur du chemin d'AS).
- **De BGP vers l'IGP.** **Jamais la table complète** : près d'un million de préfixes IPv4 sur
  Internet, que chaque routeur OSPF devrait stocker et recalculer à chaque changement. On donne aux
  routeurs internes une **route par défaut** (`default-information originate`, qui suit la présence
  de la route par défaut apprise de l'opérateur) et, au besoin, quelques préfixes choisis
  (`redistribute bgp route-map …` avec une liste de préfixes).
- La RFC 8212 impose une politique explicite sur chaque session eBGP (`bgp ebgp-requires-policy`,
  actif par défaut dans FRR) : sans route-map en entrée et en sortie, rien n'est échangé.
""": """
- **From the IGP into BGP.** You announce your networks to an operator with `network` (the prefix
  must be in the RIB; origin *IGP*, code `i`) or by redistributing the IGP (`redistribute ospf`
  under `address-family ipv4 unicast`; origin *incomplete*, code `?`, and MED = metric of the route
  in the IGP). The filter is essential: without it, the private interconnection networks and
  everything the IGP has learned go out too. In the BGP best path selection, origin `i` is
  preferred to `?` (after the AS path length).
- **From BGP into the IGP.** **Never the full table**: nearly a million IPv4 prefixes on the
  Internet, which every OSPF router would have to store and recompute at each change. The internal
  routers are given a **default route** (`default-information originate`, which follows the
  presence of the default route learned from the operator) and, if needed, a few chosen prefixes
  (`redistribute bgp route-map …` with a prefix list).
- RFC 8212 requires an explicit policy on every eBGP session (`bgp ebgp-requires-policy`, enabled
  by default in FRR): without an inbound and an outbound route-map, nothing is exchanged.
""",
    "Résumer à la redistribution": "Summarising at the redistribution",
    """
Redistribuer beaucoup de petits réseaux grossit les tables de tout le domaine. S'ils sont
contigus, on les résume au point de redistribution :

- **OSPF** : `summary-address 10.1.0.0/21` (sous `router ospf`, sur l'ASBR) remplace tous les LSA
  externes contenus dans le préfixe par un seul ; `summary-address 10.1.0.0/21 tag 2` marque le
  résumé, `summary-address 10.1.0.0/21 no-advertise` supprime toute annonce. Le résumé remplace les
  routes au bout de quelques secondes (`aggregation timer`, 5 s par défaut). À ne pas confondre avec
  `area N range`, qui résume sur un ABR les routes **inter-aires** et n'agit pas sur les routes
  externes.
- **BGP** : `aggregate-address 10.1.0.0/21` (sous `address-family ipv4 unicast`) annonce le préfixe
  agrégé dès qu'au moins une route plus précise est dans la table BGP ; avec `summary-only`, les
  routes plus précises ne sont plus annoncées (elles restent dans la table, marquées `s`).
""": """
Redistributing many small networks enlarges the tables of the whole domain. If they are
contiguous, they are summarised at the redistribution point:

- **OSPF**: `summary-address 10.1.0.0/21` (under `router ospf`, on the ASBR) replaces all the
  external LSAs contained in the prefix by a single one; `summary-address 10.1.0.0/21 tag 2` tags
  the summary, `summary-address 10.1.0.0/21 no-advertise` suppresses any advertisement. The summary
  replaces the routes after a few seconds (`aggregation timer`, 5 s by default). Not to be confused
  with `area N range`, which summarises the **inter-area** routes on an ABR and does not act on the
  external routes.
- **BGP**: `aggregate-address 10.1.0.0/21` (under `address-family ipv4 unicast`) announces the
  aggregate prefix as soon as at least one more specific route is in the BGP table; with
  `summary-only`, the more specific routes are no longer announced (they stay in the table, marked
  `s`).
""",
    "Les aires NSSA": "NSSA areas",
    """
Une aire **stub** n'accepte aucun LSA externe (type 5) : elle ne peut donc pas contenir d'ASBR ; un
routeur d'une aire stub qui redistribue n'annonce rien. L'aire **NSSA** (*Not-So-Stubby Area*, RFC
3101) lève cette limite tout en refusant toujours les routes externes du reste du domaine :

- l'ASBR d'une NSSA décrit ses routes externes dans des **LSA de type 7**, qui ne circulent que
  dans l'aire (`show ip ospf database nssa-external`) ; on parle de routes N1 et N2, l'équivalent
  de E1 et E2, mais FRR les affiche `N E1` et `N E2` dans `show ip ospf route` ;
- l'ABR **traduit** chaque LSA de type 7 en LSA de type 5 pour le reste du domaine : les autres
  aires voient une route externe ordinaire, **annoncée par l'ABR** (*Advertising Router*) ;
- les LSA de type 5 des autres aires n'entrent pas dans la NSSA ; l'ABR peut y injecter une route
  par défaut (`area N nssa default-information-originate`) ; `area N nssa no-summary` refuse en
  plus les routes inter-aires.

Comme `stub`, le type `nssa` est un champ des Hello : **tous** les routeurs de l'aire doivent le
déclarer (`area N nssa` sous `router ospf`), sinon l'adjacence ne se forme pas. Une aire est stub
ou NSSA, pas les deux : on retire l'un (`no area N stub`) avant de déclarer l'autre.
""": """
A **stub** area accepts no external LSA (type 5): it therefore cannot contain an ASBR; a router of
a stub area that redistributes advertises nothing. The **NSSA** area (*Not-So-Stubby Area*, RFC
3101) lifts this limit while still refusing the external routes of the rest of the domain:

- the ASBR of an NSSA describes its external routes in **type 7 LSAs**, which only travel within
  the area (`show ip ospf database nssa-external`); one speaks of N1 and N2 routes, the equivalent
  of E1 and E2, but FRR displays them as `N E1` and `N E2` in `show ip ospf route`;
- the ABR **translates** each type 7 LSA into a type 5 LSA for the rest of the domain: the other
  areas see an ordinary external route, **advertised by the ABR** (*Advertising Router*);
- the type 5 LSAs of the other areas do not enter the NSSA; the ABR can inject a default route
  into it (`area N nssa default-information-originate`); `area N nssa no-summary` also refuses the
  inter-area routes.

Like `stub`, the `nssa` type is a field of the Hellos: **all** the routers of the area must declare
it (`area N nssa` under `router ospf`), otherwise the adjacency does not form. An area is stub or
NSSA, not both: remove one (`no area N stub`) before declaring the other.
""",
    "FRR et vtysh": "FRR and vtysh",
    """
**FRRouting** (FRR) est fait de `zebra` (la RIB et l'interface avec le noyau), `staticd` et un
démon par protocole (`ripd`, `ospfd`, `bgpd`). On les configure avec `vtysh` :

```
vtysh                                  # le shell de configuration
configure terminal
 ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24
 route-map RIP-TO-OSPF permit 10
  match ip address prefix-list LANS
  exit
 router ospf
  redistribute rip route-map RIP-TO-OSPF
  exit
 end
write                                  # sauvegarde dans /etc/frr/frr.conf
```

Une ligne s'annule en la préfixant par `no` (`no redistribute rip`). Pour changer les options d'une
redistribution, on retape la commande complète. Une commande isolée depuis le shell :
`vtysh -c "show ip route"`.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ip route [P]` | la RIB : source, `[distance/métrique]`, route choisie `>` |
| `show ip ospf database external [P]` | les LSA de type 5 : *Advertising Router*, *Metric Type*, *Metric*, *External Route Tag* |
| `show ip ospf database nssa-external` | les LSA de type 7 |
| `show ip ospf route` | les routes calculées par OSPF (`N`, `N IA`, `N E1`, `N E2`) |
| `show ip ospf` | router-id, rôle d'ABR ou d'ASBR, type des aires |
| `show ip rip` | la table de RIP : métrique, source, étiquette (*Tag*) ; `R(r)` = redistribuée |
| `show ip rip status` | temporisateurs, interfaces, ligne `Redistributing:` |
| `show bgp ipv4 unicast [P]` | la table BGP : MED (*Metric*), origine (`i`, `?`), `s` = supprimée |
| `show route-map`, `show ip prefix-list` | les filtres et leurs compteurs |
| `traceroute -n IP` | le chemin réellement suivi : dans une boucle, les mêmes routeurs reviennent |

Documentation : [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html),
[RIP](https://docs.frrouting.org/en/latest/ripd.html), [BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html).
""": """
**FRRouting** (FRR) is made of `zebra` (the RIB and the interface with the kernel), `staticd` and
one daemon per protocol (`ripd`, `ospfd`, `bgpd`). They are configured with `vtysh`:

```
vtysh                                  # the configuration shell
configure terminal
 ip prefix-list LANS seq 10 permit 10.1.0.0/16 le 24
 route-map RIP-TO-OSPF permit 10
  match ip address prefix-list LANS
  exit
 router ospf
  redistribute rip route-map RIP-TO-OSPF
  exit
 end
write                                  # saves to /etc/frr/frr.conf
```

A line is cancelled by prefixing it with `no` (`no redistribute rip`). To change the options of a
redistribution, type the complete command again. A single command from the shell:
`vtysh -c "show ip route"`.

| command | what it shows |
|---------|---------------|
| `show ip route [P]` | the RIB: source, `[distance/metric]`, chosen route `>` |
| `show ip ospf database external [P]` | the type 5 LSAs: *Advertising Router*, *Metric Type*, *Metric*, *External Route Tag* |
| `show ip ospf database nssa-external` | the type 7 LSAs |
| `show ip ospf route` | the routes computed by OSPF (`N`, `N IA`, `N E1`, `N E2`) |
| `show ip ospf` | router-id, ABR or ASBR role, type of the areas |
| `show ip rip` | the RIP table: metric, source, tag (*Tag*); `R(r)` = redistributed |
| `show ip rip status` | timers, interfaces, `Redistributing:` line |
| `show bgp ipv4 unicast [P]` | the BGP table: MED (*Metric*), origin (`i`, `?`), `s` = suppressed |
| `show route-map`, `show ip prefix-list` | the filters and their counters |
| `traceroute -n IP` | the path actually followed: in a loop, the same routers come back |

Documentation: [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html),
[RIP](https://docs.frrouting.org/en/latest/ripd.html), [BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html).
""",
    "Diagnostic": "Troubleshooting",
    """
| symptôme | causes à vérifier |
|----------|-------------------|
| la route n'arrive pas dans l'autre domaine | redistribution absente ou configurée dans le mauvais protocole ; route-map qui refuse tout (liste de préfixes sans `le`, route-map inexistante ou réduite à un `deny`) ; route non choisie dans la RIB du point de redistribution (source de distance plus faible, route du noyau, statique inactive) |
| la route arrive dans RIP avec la métrique 16 | métrique d'amorçage de 15 ou plus |
| un réseau d'interconnexion manque | réseau connecté du point de redistribution : `redistribute connected` |
| la route par défaut n'est pas annoncée | `redistribute static` ne la porte pas : `default-information originate` ; pas de route par défaut active sur le routeur |
| les paquets tournent (`traceroute` répète les mêmes routeurs) | redistribution mutuelle en plusieurs points sans étiquettes ni distances adaptées |
| détour par l'autre domaine alors qu'un voisin direct a la route | distance : la route externe d'OSPF (110) bat la route RIP (120) |
| une distance modifiée reste sans effet | elle ne vaut que pour les routes installées ensuite : `clear ip ospf process` |
| des réseaux privés partent chez l'opérateur | redistribution dans BGP sans filtre |
| une route externe n'entre pas dans une aire | aire stub ou NSSA (normal) ; ASBR dans une aire stub : passer l'aire en NSSA |
""": """
| symptom | causes to check |
|---------|-----------------|
| the route does not reach the other domain | redistribution missing or configured in the wrong protocol; route-map that refuses everything (prefix list without `le`, route-map that does not exist or is reduced to a `deny`); route not chosen in the RIB of the redistribution point (source with a lower distance, kernel route, inactive static route) |
| the route arrives in RIP with metric 16 | seed metric of 15 or more |
| an interconnection network is missing | connected network of the redistribution point: `redistribute connected` |
| the default route is not advertised | `redistribute static` does not carry it: `default-information originate`; no active default route on the router |
| the packets go round in circles (`traceroute` repeats the same routers) | mutual redistribution at several points without suitable tags or distances |
| detour through the other domain although a direct neighbour has the route | distance: the OSPF external route (110) beats the RIP route (120) |
| a modified distance has no effect | it only applies to the routes installed afterwards: `clear ip ospf process` |
| private networks go out to the operator | redistribution into BGP without a filter |
| an external route does not enter an area | stub or NSSA area (normal); ASBR in a stub area: turn the area into an NSSA |
""",
    "Partie 1 : solution (statiques, connectés, noyau)": "Part 1: solution (static, connected, kernel)",
    "Partie 2 : solution (RIP et OSPF, un point)": "Part 2: solution (RIP and OSPF, one point)",
    "Partie 3 : solution (deux points, étiquettes)": "Part 3: solution (two points, tags)",
    "Partie 4 : solution (OSPF et BGP)": "Part 4: solution (OSPF and BGP)",
    "Partie 5 : solution (dépannage)": "Part 5: solution (troubleshooting)",
    "Bonus : solution (résumé sur l'ASBR)": "Bonus: solution (summary on the ASBR)",
    "Bonus : solution (NSSA)": "Bonus: solution (NSSA)",
    "Bonus : solution (agrégation BGP)": "Bonus: solution (BGP aggregation)",
    "1 — routes statiques, connectées et du noyau dans OSPF": "1 — static, connected and kernel routes into OSPF",
    "`stat_asbr` (à configurer), `stat_ospf1`, `stat_gw`, `stat_h1`, `stat_h2`": "`stat_asbr` (to configure), `stat_ospf1`, `stat_gw`, `stat_h1`, `stat_h2`",
    "2 — RIP et OSPF, un point de redistribution": "2 — RIP and OSPF, one redistribution point",
    "`mut_b` (à configurer), `mut_rip1`, `mut_ospf1`, `mut_h1`, `mut_h2`": "`mut_b` (to configure), `mut_rip1`, `mut_ospf1`, `mut_h1`, `mut_h2`",
    "3 — RIP et OSPF, deux points de redistribution": "3 — RIP and OSPF, two redistribution points",
    "`dual_b1`, `dual_b2` (à configurer), `dual_rip1` à `dual_rip3`, `dual_ospf1`, `dual_h1`, `dual_h2`": "`dual_b1`, `dual_b2` (to configure), `dual_rip1` to `dual_rip3`, `dual_ospf1`, `dual_h1`, `dual_h2`",
    "4 — OSPF et BGP": "4 — OSPF and BGP",
    "`edge_b` (à configurer), `edge_ospf1`, `edge_h1`, `edge_inet` ; `edge_isp` sans terminal": "`edge_b` (to configure), `edge_ospf1`, `edge_h1`, `edge_inet`; `edge_isp` without a terminal",
    "5 — dépannage": "5 — troubleshooting",
    "`fix_b` (à corriger), `fix_rip1`, `fix_ospf1`, `fix_gw`, `fix_h1`, `fix_h2`": "`fix_b` (to repair), `fix_rip1`, `fix_ospf1`, `fix_gw`, `fix_h1`, `fix_h2`",
    "bonus — résumé sur un ASBR": "bonus — summary on an ASBR",
    "`sum_asbr` (à configurer), `sum_ospf1`, `sum_gw`": "`sum_asbr` (to configure), `sum_ospf1`, `sum_gw`",
    "bonus — aire NSSA": "bonus — NSSA area",
    "`nssa_abr`, `nssa_asbr` (à configurer), `nssa_core`, `nssa_gw`": "`nssa_abr`, `nssa_asbr` (to configure), `nssa_core`, `nssa_gw`",
    "bonus — agrégation BGP": "bonus — BGP aggregation",
    "`agg_b` (à configurer), `agg_ospf1` ; `agg_isp` sans terminal": "`agg_b` (to configure), `agg_ospf1`; `agg_isp` without a terminal",
    "| `stat_far1` à `stat_far3` | `{far1}`, `{far2}`, `{far3}` | `lo` de `stat_gw` (`.1`) |": "| `stat_far1` to `stat_far3` | `{far1}`, `{far2}`, `{far3}` | `lo` of `stat_gw` (`.1`) |",
    "| `internet` | `{inet}` | `lo` de `stat_gw` |": "| `internet` | `{inet}` | `lo` of `stat_gw` |",
    "| `fix_srv` | `{srv}` | `lo` de `fix_gw` (`.1`) |": "| `fix_srv` | `{srv}` | `lo` of `fix_gw` (`.1`) |",
    "| `sum_block` | `{block}` ({count} /24) | `lo` de `sum_gw` (`.1` de chaque /24) |": "| `sum_block` | `{block}` ({count} /24) | `lo` of `sum_gw` (`.1` of each /24) |",
    "| `nssa_ext1`, `nssa_ext2` | `{e1}`, `{e2}` | `lo` de `nssa_gw` (`.1`) |": "| `nssa_ext1`, `nssa_ext2` | `{e1}`, `{e2}` | `lo` of `nssa_gw` (`.1`) |",
    "| `nssa_coreext` | `{coreext}` | route statique (`blackhole`) de `nssa_core` |": "| `nssa_coreext` | `{coreext}` | static route (`blackhole`) of `nssa_core` |",
    "| `edge_partner` | `{partner}` | `lo` de `edge_isp` (`.1`, nom `partner`) |": "| `edge_partner` | `{partner}` | `lo` of `edge_isp` (`.1`, name `partner`) |",
    "| `edge_inet1`, `edge_inet2` | `{i1}`, `{i2}` | `lo` de `edge_isp` |": "| `edge_inet1`, `edge_inet2` | `{i1}`, `{i2}` | `lo` of `edge_isp` |",
    "| `agg_company` | `{company}` ({count} /24) | interfaces `dum0` à `dum{last}` de `agg_ospf1` |": "| `agg_company` | `{company}` ({count} /24) | interfaces `dum0` to `dum{last}` of `agg_ospf1` |",
    "| `dual_tagr`, `dual_tago` | `{tagr}`, `{tago}` | routes de test (`blackhole`) de `dual_ospf1` et `dual_rip2` |": "| `dual_tagr`, `dual_tago` | `{tagr}`, `{tago}` | test routes (`blackhole`) of `dual_ospf1` and `dual_rip2` |",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente la redistribution (sources, distance administrative,
métriques, route-maps et étiquettes, route par défaut, plusieurs points de redistribution, BGP,
résumés, aires NSSA) et les commandes de FRR utiles.

**Le réseau.** Il est fait de **huit sites indépendants**, un par partie, chacun avec sa couleur
sur le schéma.

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) : configurez-les avec `vtysh` (section
  @@ref:frr@@). Dans chaque site, les protocoles de routage eux-mêmes sont **déjà configurés et
  fonctionnent** (adjacences OSPF établies, RIP actif) : vous n'avez à écrire que la redistribution,
  ses filtres et ses réglages.
- OSPF : une seule aire, l'aire 0 (sauf le site `nssa`) ; les liens entre routeurs sont déclarés
  point à point (`ip ospf network point-to-point`), d'où un coût de 10 par lien et pas d'élection de
  DR. Les réseaux d'hôtes sont passifs.
- RIP : version 2, temporisateurs raccourcis pour le TP (`timers basic {upd} {tmo} {gc}` : une
  mise à jour toutes les {upd} s au lieu de 30).
- Chaque routeur a un router-id fixé dans sa configuration : {rid_rows}.
- Les hôtes et les passerelles (`*_gw`) ont une route par défaut vers leur routeur ; les réseaux
  `stat_far*`, `fix_srv`, `nssa_ext*` et les {sum_count} /24 de `sum_block` sont portés par
  l'interface `lo` des passerelles.
- Les fichiers `/etc/hosts` contiennent les noms : `mut_b-eth1` désigne l'adresse de l'interface
  `eth1` de `mut_b`.
- AS de l'entreprise (sites `edge` et `agg`) : **{asn}** ; opérateur : AS {isp_as}.

**Plan d'adressage.** Les liens entre deux machines sont des /30, les autres réseaux des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Ne modifiez que les routeurs indiqués « à configurer » : les autres sont les références par
  lesquelles l'évaluation regarde le résultat.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).

**Évaluation.** Chaque évaluation lit vos réponses, les bases OSPF (LSA externes, routes), les tables
de RIP et de BGP et les tables de routage des routeurs de référence, et lance des `ping` entre les
hôtes. Après une modification, laissez à RIP le temps d'une mise à jour ({upd} s) avant d'évaluer.
""": """
Read the **Informations** tab: it presents redistribution (sources, administrative distance,
metrics, route-maps and tags, default route, several redistribution points, BGP, summaries, NSSA
areas) and the useful FRR commands.

**The network.** It is made of **eight independent sites**, one per part, each with its own colour
on the diagram.

| part | site | machines |
|------|------|----------|
{site_rows}

- The routers run **FRRouting** (FRR): configure them with `vtysh` (section @@ref:frr@@). In each
  site, the routing protocols themselves are **already configured and working** (OSPF adjacencies
  established, RIP running): you only have to write the redistribution, its filters and its
  settings.
- OSPF: a single area, area 0 (except in the `nssa` site); the links between routers are declared
  point-to-point (`ip ospf network point-to-point`), hence a cost of 10 per link and no DR
  election. The host networks are passive.
- RIP: version 2, timers shortened for the lab (`timers basic {upd} {tmo} {gc}`: an update every
  {upd} s instead of 30).
- Each router has a router-id set in its configuration: {rid_rows}.
- The hosts and the gateways (`*_gw`) have a default route to their router; the networks
  `stat_far*`, `fix_srv`, `nssa_ext*` and the {sum_count} /24 networks of `sum_block` are carried by
  the `lo` interface of the gateways.
- The `/etc/hosts` files contain the names: `mut_b-eth1` stands for the address of the `eth1`
  interface of `mut_b`.
- AS of the company (sites `edge` and `agg`): **{asn}**; operator: AS {isp_as}.

**Addressing plan.** The links between two machines are /30s, the other networks /24s.

| network | prefix | interfaces |
|---------|--------|------------|
{addressing}

**Instructions.**

- The parts are **independent**: do them in any order you like. A completed part gives all its
  points, whatever the state of the others.
- Only modify the routers marked "to configure": the others are the references through which the
  evaluation looks at the result.
- Save the FRR configuration (`write` in `vtysh`).

**Evaluation.** Each evaluation reads your answers, the OSPF databases (external LSAs, routes), the
RIP and BGP tables and the routing tables of the reference routers, and runs `ping`s between the
hosts. After a change, give RIP the time of one update ({upd} s) before evaluating.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_stat`, `solve_mut`, `solve_dual`, `solve_edge`, `solve_fix`, `solve_sum`,
`solve_nssa` et `solve_agg` (onglet *Appliquer une configuration*) appliquent la solution d'une
seule partie, attendent que les routes attendues soient en place (au plus {wait} s) et remplissent
ses formulaires. L'état `final` les applique toutes : une évaluation lancée dès son retour donne
tous les points, bonus compris.

Valeurs de cette instance : métriques {lan} (`stat_lan`, E2), {far} (`stat_far*`, E1), {mut} (RIP
vers OSPF sur `mut_b`, E1), amorçage RIP {seed} (`mut_b`), {edge} (préfixe partenaire, E1) ;
étiquettes {trip} (RIP vers OSPF) et {tospf} (OSPF vers RIP) sur le site `dual`, {tsum} pour le
résumé du site `sum`.

Les pannes du site `fix` (sur `fix_b`) : `redistribute ospf metric {bad}` sous `router rip` ;
`RIP-NETS` = `{block}` sans `le` ; route statique vers `{srv}` par `{wrong}` (au lieu de `{gw}`) ;
pas de `redistribute connected` sous `router ospf`. Sur le site `dual`, `dual_b1` redistribue dès
le départ dans les deux sens sans route-map.
""": """
**For the instructor.** Each question ends with its solution for the values of this instance. The
states `solve_stat`, `solve_mut`, `solve_dual`, `solve_edge`, `solve_fix`, `solve_sum`,
`solve_nssa` and `solve_agg` (*Apply Configuration* tab) apply the solution of a single part, wait
until the expected routes are in place (at most {wait} s) and fill in its forms. The `final` state
applies them all: an evaluation started as soon as it returns gives all the points, bonus included.

Values of this instance: metrics {lan} (`stat_lan`, E2), {far} (`stat_far*`, E1), {mut} (RIP into
OSPF on `mut_b`, E1), RIP seed {seed} (`mut_b`), {edge} (partner prefix, E1); tags {trip} (RIP into
OSPF) and {tospf} (OSPF into RIP) in the `dual` site, {tsum} for the summary of the `sum` site.

The faults of the `fix` site (on `fix_b`): `redistribute ospf metric {bad}` under `router rip`;
`RIP-NETS` = `{block}` without `le`; static route to `{srv}` via `{wrong}` (instead of `{gw}`); no
`redistribute connected` under `router ospf`. In the `dual` site, `dual_b1` redistributes in both
directions from the start, without a route-map.
""",
    "Partie 1 — routes statiques, connectées et du noyau dans OSPF (site stat)": "Part 1 — static, connected and kernel routes into OSPF (site stat)",
    "Annoncer dans OSPF des réseaux qui n'y sont pas": "Advertising networks that are not in OSPF",
    """
`stat_asbr` et `stat_ospf1` forment un domaine OSPF ; seul le lien `stat_l12` y est déclaré du côté
de `stat_asbr`. `stat_asbr` a en plus trois réseaux qui ne sont pas dans OSPF : `stat_lan` (eth0,
les serveurs, dont `stat_h1`), `stat_mgmt` (eth1, l'administration) et `stat_lgw` (eth3, le lien
vers la passerelle `stat_gw`). Derrière `stat_gw` se trouvent les réseaux d'un partenaire,
`stat_far1` `{far1}`, `stat_far2` `{far2}` et `stat_far3` `{far3}`, ainsi que l'accès à Internet
(l'adresse `internet`, `{inet}`). Un collègue a déjà ajouté une route vers `{far3}` avec
`ip route add`.

Sur `stat_asbr` uniquement :

1. créez dans FRR des routes statiques vers `stat_far1` et `stat_far2` et une route par défaut, par
   `stat_gw` (`{gw}`) ;
2. faites annoncer dans OSPF (sections @@ref:sources@@, @@ref:policy@@ et @@ref:default@@) :
   - `stat_lan` en route externe de **type 2**, métrique **{lan}** ;
   - `stat_far1`, `stat_far2` **et** `stat_far3` en routes externes de **type 1**, métrique
     **{far}** ;
   - la route par défaut ;
   - **et rien d'autre** : ni `stat_mgmt`, ni `stat_lgw`, ni `stat_l12`.

Vérifiez sur `stat_ospf1` (`show ip ospf database external`, `show ip ospf route`, `ip route`), puis
depuis `stat_h2` : `ping` vers `stat_h1`, vers `{far1_host}` et vers `internet`. Pourquoi
`stat_far3` n'apparaît-il pas d'abord ?
""": """
`stat_asbr` and `stat_ospf1` form an OSPF domain; only the link `stat_l12` is declared in it on the
`stat_asbr` side. `stat_asbr` also has three networks that are not in OSPF: `stat_lan` (eth0, the
servers, including `stat_h1`), `stat_mgmt` (eth1, the administration) and `stat_lgw` (eth3, the
link to the gateway `stat_gw`). Behind `stat_gw` are the networks of a partner, `stat_far1`
`{far1}`, `stat_far2` `{far2}` and `stat_far3` `{far3}`, as well as the access to the Internet (the
address `internet`, `{inet}`). A colleague has already added a route to `{far3}` with
`ip route add`.

On `stat_asbr` only:

1. create in FRR static routes to `stat_far1` and `stat_far2` and a default route, via `stat_gw`
   (`{gw}`);
2. have OSPF advertise (sections @@ref:sources@@, @@ref:policy@@ and @@ref:default@@):
   - `stat_lan` as an external route of **type 2**, metric **{lan}**;
   - `stat_far1`, `stat_far2` **and** `stat_far3` as external routes of **type 1**, metric
     **{far}**;
   - the default route;
   - **and nothing else**: neither `stat_mgmt`, nor `stat_lgw`, nor `stat_l12`.

Check on `stat_ospf1` (`show ip ospf database external`, `show ip ospf route`, `ip route`), then
from `stat_h2`: `ping` to `stat_h1`, to `{far1_host}` and to `internet`. Why does `stat_far3` not
appear at first?
""",
    """
**Solution.**

{solution}

La route vers `{far3}` ajoutée par `ip route add` est une route **du noyau** (`K` dans `show ip
route`), pas une route statique de FRR : `redistribute static` ne la voit pas. Une route statique
de FRR vers le même préfixe ne suffit pas tant que la route du noyau existe : distance 0 contre 1,
la route du noyau reste choisie. On la supprime (`ip route del`), ou bien on ajoute
`redistribute kernel metric-type 1 metric {far}`. La route par défaut n'est jamais emportée par
`redistribute static` : `default-information originate` (type 2, métrique 10).

Évaluation (LSA externes vus par `stat_ospf1`) : `stat_lan` (3 : type 2, métrique {lan}),
`stat_filter` (2 : aucun LSA externe de `stat_asbr` pour `stat_mgmt`, `stat_lgw`, `stat_l12`,
compté si `stat_lan` l'est), `stat_far` (4 : `stat_far1`, `stat_far2` en type 1, métrique {far}),
`stat_kernel` (3 : `stat_far3` de même), `stat_default` (3 : route par défaut de `stat_ospf1` par
`stat_asbr`), `stat_ping` (3 : `stat_h2` joint `stat_h1`, `stat_far1`, `internet`).
""": """
**Solution.**

{solution}

The route to `{far3}` added by `ip route add` is a **kernel** route (`K` in `show ip route`), not
an FRR static route: `redistribute static` does not see it. An FRR static route to the same prefix
is not enough as long as the kernel route exists: distance 0 against 1, the kernel route stays
chosen. Delete it (`ip route del`), or else add `redistribute kernel metric-type 1 metric {far}`.
The default route is never carried by `redistribute static`: `default-information originate` (type
2, metric 10).

Evaluation (external LSAs seen by `stat_ospf1`): `stat_lan` (3: type 2, metric {lan}),
`stat_filter` (2: no external LSA of `stat_asbr` for `stat_mgmt`, `stat_lgw`, `stat_l12`, counted
if `stat_lan` is), `stat_far` (4: `stat_far1`, `stat_far2` as type 1, metric {far}),
`stat_kernel` (3: `stat_far3` likewise), `stat_default` (3: default route of `stat_ospf1` via
`stat_asbr`), `stat_ping` (3: `stat_h2` reaches `stat_h1`, `stat_far1`, `internet`).
""",
    "Observations sur le site stat": "Observations in the stat site",
    """
- coût de la route de `stat_ospf1` vers `stat_far1` dans `show ip ospf route` : @@{cost_far:[0-9]+}@@
- distance administrative de cette route dans `show ip route` : @@{dist_ospf:[0-9]+}@@
- distance administrative d'une route ajoutée par `ip route add` (FRR) : @@{dist_kernel:[0-9]+}@@
- `redistribute static` n'annonçait pas `stat_far3` parce que :
  @@{kernel:>c'est une route du noyau, pas une route statique de FRR>>>kernel|stat_gw ne répond pas sur cette adresse>>>gw|redistribute static n'emporte que deux routes>>>count|il manque une commande network pour ce préfixe>>>network}@@
- la route par défaut n'est pas annoncée par `redistribute static` parce que :
  @@{default:>la route par défaut ne suit jamais redistribute : il faut default-information originate>>>dio|il faut redistribute kernel>>>kernel|stat_ospf1 la filtre>>>filtered|OSPF ne sait pas transporter de route par défaut>>>never}@@
""": """
- cost of the route of `stat_ospf1` to `stat_far1` in `show ip ospf route`: @@{cost_far:[0-9]+}@@
- administrative distance of this route in `show ip route`: @@{dist_ospf:[0-9]+}@@
- administrative distance of a route added by `ip route add` (FRR): @@{dist_kernel:[0-9]+}@@
- `redistribute static` did not advertise `stat_far3` because:
  @@{kernel:>it is a kernel route, not an FRR static route>>>kernel|stat_gw does not answer on this address>>>gw|redistribute static only carries two routes>>>count|a network command is missing for this prefix>>>network}@@
- the default route is not advertised by `redistribute static` because:
  @@{default:>the default route never follows redistribute: default-information originate is needed>>>dio|redistribute kernel is needed>>>kernel|stat_ospf1 filters it>>>filtered|OSPF cannot carry a default route>>>never}@@
""",
    """
**Solution.** Coût **{cost}** (route E1 : {far} + {dc} pour le lien) ; distance **{dospf}** ;
distance **{dkern}** ; **une route du noyau** ; **default-information originate**.

Évaluation : `stat_q_cost`, `stat_q_dist` (1 chacun ; les deux distances pour le second) et, pour
l'enseignant seulement (choix dans une liste), `stat_q_kernel`, `stat_q_default` (1 chacun).
""": """
**Solution.** Cost **{cost}** (E1 route: {far} + {dc} for the link); distance **{dospf}**;
distance **{dkern}**; **a kernel route**; **default-information originate**.

Evaluation: `stat_q_cost`, `stat_q_dist` (1 each; both distances for the second one) and, for the
instructor only (choice from a list), `stat_q_kernel`, `stat_q_default` (1 each).
""",
    "stat_lan annoncé en externe de type 2 avec sa métrique": "stat_lan advertised as external type 2 with its metric",
    "aucun autre réseau connecté de stat_asbr annoncé": "no other connected network of stat_asbr advertised",
    "stat_far1 et stat_far2 en externes de type 1 avec leur métrique": "stat_far1 and stat_far2 as external type 1 with their metric",
    "stat_far3, ajouté par ip route add, annoncé de même": "stat_far3, added by ip route add, advertised likewise",
    "route par défaut annoncée par stat_asbr": "default route advertised by stat_asbr",
    "stat_h2 joint stat_h1, stat_far1 et internet": "stat_h2 reaches stat_h1, stat_far1 and internet",
    "coût de la route E1": "cost of the E1 route",
    "distances d'une route OSPF et d'une route du noyau": "distances of an OSPF route and of a kernel route",
    "pourquoi stat_far3 manquait": "why stat_far3 was missing",
    "annonce de la route par défaut": "advertisement of the default route",
    "Partie 2 — RIP et OSPF, un point de redistribution (site mut)": "Part 2 — RIP and OSPF, one redistribution point (site mut)",
    "Redistribution mutuelle entre RIP et OSPF": "Mutual redistribution between RIP and OSPF",
    """
`mut_rip1` fait partie d'un ancien domaine RIP (son réseau `mut_lan1`, avec `mut_h1`) ; `mut_ospf1`
du domaine OSPF (`mut_lan2`, avec `mut_h2`). `mut_b` est à la frontière : RIP sur `eth0` (lien
`mut_lrb`), OSPF sur `eth1` (lien `mut_lbo`). Les deux protocoles fonctionnent, mais aucune route ne
passe d'un domaine à l'autre.

Sur `mut_b` uniquement, faites que **toutes les adresses** de chaque domaine soient joignables
depuis l'autre (sections @@ref:principle@@, @@ref:metrics@@ et @@ref:sources@@) :

- les routes RIP entrent dans OSPF en externes de **type 1**, métrique **{metric}** ;
- les routes OSPF entrent dans RIP avec la métrique d'amorçage **{seed}** ;
- le lien `mut_lrb` doit être connu dans OSPF et le lien `mut_lbo` dans RIP, avec les mêmes
  métriques, sans rien annoncer d'autre de `mut_b`.

Vérifiez les tables de `mut_rip1` (`show ip rip`, `ip route`) et de `mut_ospf1` (`show ip ospf
route`), puis les `ping` entre `mut_h1` et `mut_h2`.
""": """
`mut_rip1` belongs to an old RIP domain (its network `mut_lan1`, with `mut_h1`); `mut_ospf1` to
the OSPF domain (`mut_lan2`, with `mut_h2`). `mut_b` is at the border: RIP on `eth0` (link
`mut_lrb`), OSPF on `eth1` (link `mut_lbo`). Both protocols work, but no route goes from one
domain to the other.

On `mut_b` only, make **all the addresses** of each domain reachable from the other (sections
@@ref:principle@@, @@ref:metrics@@ and @@ref:sources@@):

- the RIP routes enter OSPF as external routes of **type 1**, metric **{metric}**;
- the OSPF routes enter RIP with the seed metric **{seed}**;
- the link `mut_lrb` must be known in OSPF and the link `mut_lbo` in RIP, with the same metrics,
  without advertising anything else of `mut_b`.

Check the tables of `mut_rip1` (`show ip rip`, `ip route`) and of `mut_ospf1` (`show ip ospf
route`), then the `ping`s between `mut_h1` and `mut_h2`.
""",
    """
**Solution.**

{solution}

`redistribute rip` n'emporte pas `mut_lrb` : c'est un réseau connecté de `mut_b` (route `C`), pas
une route apprise par RIP ; de même `mut_lbo` n'est pas une route OSPF de `mut_b`. D'où les deux
`redistribute connected`, filtrés par une liste de préfixes chacun. `mut_rip1` voit `mut_lan2` à
{seen} ({seed} + 1) ; `mut_ospf1` voit `mut_lan1` en E1 à {cost} ({metric} + {dc}).

Évaluation : `mut_ospf_lan` (4 : LSA de `mut_lan1` par `mut_b`, type 1, métrique {metric}),
`mut_ospf_link` (2 : route OSPF de `mut_ospf1` vers `mut_lrb`), `mut_rip_lan` (4 : métrique {seen}
de `mut_lan2` sur `mut_rip1`), `mut_rip_link` (2 : route RIP de `mut_rip1` vers `mut_lbo`),
`mut_ping` (2 : `ping` dans les deux sens).
""": """
**Solution.**

{solution}

`redistribute rip` does not carry `mut_lrb`: it is a connected network of `mut_b` (`C` route), not
a route learned through RIP; likewise `mut_lbo` is not an OSPF route of `mut_b`. Hence the two
`redistribute connected`, each filtered by a prefix list. `mut_rip1` sees `mut_lan2` at {seen}
({seed} + 1); `mut_ospf1` sees `mut_lan1` as E1 at {cost} ({metric} + {dc}).

Evaluation: `mut_ospf_lan` (4: LSA of `mut_lan1` by `mut_b`, type 1, metric {metric}),
`mut_ospf_link` (2: OSPF route of `mut_ospf1` to `mut_lrb`), `mut_rip_lan` (4: metric {seen} of
`mut_lan2` on `mut_rip1`), `mut_rip_link` (2: RIP route of `mut_rip1` to `mut_lbo`), `mut_ping`
(2: `ping` in both directions).
""",
    "Observations sur le site mut": "Observations in the mut site",
    """
- métrique de `mut_lan2` dans `show ip rip` de `mut_rip1` : @@{rip_metric:[0-9]+}@@
- coût de la route de `mut_ospf1` vers `mut_lan1` dans `show ip ospf route` : @@{ospf_cost:[0-9]+}@@
- métrique d'amorçage par défaut de FRR pour une route redistribuée dans RIP : @@{seed_rip:[0-9]+}@@
  et dans OSPF : @@{seed_ospf:[0-9]+}@@
- `redistribute rip` n'annonce pas `mut_lrb` dans OSPF parce que :
  @@{connected:>c'est un réseau connecté de mut_b, pas une route apprise par RIP>>>connected|RIP n'annonce jamais les /30>>>mask|l'horizon partagé (split horizon) le bloque>>>split|OSPF refuse les routes de métrique 1>>>metric}@@
""": """
- metric of `mut_lan2` in `show ip rip` of `mut_rip1`: @@{rip_metric:[0-9]+}@@
- cost of the route of `mut_ospf1` to `mut_lan1` in `show ip ospf route`: @@{ospf_cost:[0-9]+}@@
- FRR's default seed metric for a route redistributed into RIP: @@{seed_rip:[0-9]+}@@
  and into OSPF: @@{seed_ospf:[0-9]+}@@
- `redistribute rip` does not advertise `mut_lrb` into OSPF because:
  @@{connected:>it is a connected network of mut_b, not a route learned through RIP>>>connected|RIP never advertises /30 networks>>>mask|split horizon blocks it>>>split|OSPF refuses routes with metric 1>>>metric}@@
""",
    """
**Solution.** **{seen}** ; **{cost}** ; **{srip}** et **{sospf}** ; **un réseau connecté de mut_b**.

Évaluation : `mut_q_rip`, `mut_q_cost`, `mut_q_seed` (1 chacun ; les deux valeurs pour le dernier)
et, pour l'enseignant seulement (choix dans une liste), `mut_q_connected` (1).
""": """
**Solution.** **{seen}**; **{cost}**; **{srip}** and **{sospf}**; **a connected network of mut_b**.

Evaluation: `mut_q_rip`, `mut_q_cost`, `mut_q_seed` (1 each; both values for the last one) and,
for the instructor only (choice from a list), `mut_q_connected` (1).
""",
    "mut_lan1 dans OSPF en externe de type 1 avec sa métrique": "mut_lan1 in OSPF as external type 1 with its metric",
    "mut_lrb connu dans OSPF": "mut_lrb known in OSPF",
    "mut_lan2 dans RIP avec la métrique d'amorçage demandée": "mut_lan2 in RIP with the requested seed metric",
    "mut_lbo connu dans RIP": "mut_lbo known in RIP",
    "mut_h1 et mut_h2 se joignent": "mut_h1 and mut_h2 reach each other",
    "métrique RIP de mut_lan2": "RIP metric of mut_lan2",
    "coût OSPF de mut_lan1": "OSPF cost of mut_lan1",
    "métriques d'amorçage par défaut": "default seed metrics",
    "pourquoi mut_lrb manque": "why mut_lrb is missing",
    "Partie 3 — RIP et OSPF, deux points de redistribution (site dual)": "Part 3 — RIP and OSPF, two redistribution points (site dual)",
    "Deux points de redistribution : boucles, détours et étiquettes": "Two redistribution points: loops, detours and tags",
    """
Le domaine RIP (`dual_rip1` — `dual_rip2` — `dual_rip3`, et derrière `dual_rip3` le réseau
`dual_lan3` `{lan3}` avec `dual_h1`) est raccordé au domaine OSPF (`dual_ospf1`, le réseau `dual_lano`
`{lano}` avec `dual_h2`) par **deux** points de redistribution, `dual_b1` et `dual_b2`, voisins RIP de
`dual_rip1` et voisins OSPF de `dual_ospf1`.

- `dual_b1` redistribue déjà dans les deux sens, sans aucun filtre (`redistribute rip` sous
  `router ospf`, `redistribute ospf` sous `router rip`) ;
- `dual_b2` fait tourner RIP et OSPF mais ne redistribue rien ;
- deux routes de test simulent des routes qui ont **déjà franchi la frontière** par un autre
  chemin : `dual_tagr` (`{tagr}`), une route du domaine OSPF qui porte l'étiquette **{trip}** comme si
  elle venait de RIP, et `dual_tago` (`{tago}`), une route du domaine RIP qui porte l'étiquette
  **{tospf}** comme si elle venait d'OSPF.

1. Regardez la route de `dual_b2` vers `dual_lan3` (`show ip route {lan3}`) : par où passe-t-elle,
   et pourquoi (section @@ref:rib@@) ?
2. Pour la redondance, ajoutez sur `dual_b2` la même redistribution que sur `dual_b1`. Lancez
   `traceroute -n {h1}` depuis `dual_h2`, regardez la route de `dual_rip1` vers `dual_lan3` : que
   se passe-t-il (section @@ref:multipoint@@) ?
3. Corrigez sur `dual_b1` **et** `dual_b2` :
   - toute route qui passe de RIP à OSPF reçoit l'étiquette **{trip}**, toute route qui passe
     d'OSPF à RIP l'étiquette **{tospf}** ;
   - une route marquée {tospf} ne passe jamais de RIP à OSPF, une route marquée {trip} jamais
     d'OSPF à RIP ;
   - `dual_b1` et `dual_b2` joignent les réseaux du domaine RIP **par RIP**, directement par
     `dual_rip1` (vérifiez avec `show ip route` que votre réglage s'applique bien aux routes déjà
     en place : section @@ref:rib@@) ;
   - les deux points redistribuent les réseaux RIP dans OSPF (redondance) ; gardez les métriques par
     défaut.
""": """
The RIP domain (`dual_rip1` — `dual_rip2` — `dual_rip3`, and behind `dual_rip3` the network
`dual_lan3` `{lan3}` with `dual_h1`) is connected to the OSPF domain (`dual_ospf1`, the network
`dual_lano` `{lano}` with `dual_h2`) by **two** redistribution points, `dual_b1` and `dual_b2`, RIP
neighbours of `dual_rip1` and OSPF neighbours of `dual_ospf1`.

- `dual_b1` already redistributes in both directions, without any filter (`redistribute rip` under
  `router ospf`, `redistribute ospf` under `router rip`);
- `dual_b2` runs RIP and OSPF but redistributes nothing;
- two test routes simulate routes that have **already crossed the border** by another path:
  `dual_tagr` (`{tagr}`), a route of the OSPF domain that carries the tag **{trip}** as if it came
  from RIP, and `dual_tago` (`{tago}`), a route of the RIP domain that carries the tag **{tospf}**
  as if it came from OSPF.

1. Look at the route of `dual_b2` to `dual_lan3` (`show ip route {lan3}`): which way does it go,
   and why (section @@ref:rib@@)?
2. For redundancy, add on `dual_b2` the same redistribution as on `dual_b1`. Run
   `traceroute -n {h1}` from `dual_h2` and look at the route of `dual_rip1` to `dual_lan3`: what
   happens (section @@ref:multipoint@@)?
3. Fix on `dual_b1` **and** `dual_b2`:
   - every route that goes from RIP to OSPF receives the tag **{trip}**, every route that goes
     from OSPF to RIP the tag **{tospf}**;
   - a route tagged {tospf} never goes from RIP to OSPF, a route tagged {trip} never from OSPF to
     RIP;
   - `dual_b1` and `dual_b2` reach the networks of the RIP domain **through RIP**, directly via
     `dual_rip1` (check with `show ip route` that your setting really applies to the routes
     already in place: section @@ref:rib@@);
   - both points redistribute the RIP networks into OSPF (redundancy); keep the default metrics.
""",
    """
**Solution.** Au départ, `dual_b2` connaît `{lan3}` par RIP (distance {drip}) et par OSPF, en
route externe venue de `dual_b1` (distance {dospf}) : il choisit OSPF et passe par `dual_ospf1`
(`{nh}`), puis `dual_b1`. Avec la redistribution naïve sur `dual_b2`, cette route OSPF (et non RIP)
part dans RIP avec la métrique d'amorçage 1 : `dual_rip1` la reçoit à 2, mieux que les 3 du vrai
chemin par `dual_rip2`. `dual_rip1` envoie alors les paquets vers `{lan3}` à `dual_b2`, qui les
envoie par OSPF à `dual_b1`, qui les rend à `dual_rip1` : boucle (`traceroute` répète
`dual_rip1`, `dual_b2`, `dual_ospf1`, `dual_b1`) jusqu'à l'expiration du TTL.

Sur `dual_b1` et `dual_b2` :

{solution}

Les étiquettes empêchent une route de repasser la frontière en sens inverse (les routes de test le
vérifient) ; la distance {dext} des routes externes d'OSPF, au-dessus de RIP ({drip}), fait choisir à
chaque point la route RIP vers les réseaux RIP, une fois les routes réinstallées par `clear ip ospf
process` (sans lui, `dual_b2` garde sa route OSPF de distance {dospf}). Autre solution acceptée : abaisser sous {dospf} la
distance des seules routes RIP natives (`distance 100 0.0.0.0/0 LISTE` sous `router rip`, avec une
`access-list`).

Évaluation : `dual_redundant` (4 : `dual_ospf1` voit des LSA de `{lan3}` venant de `dual_b1` **et**
de `dual_b2`), `dual_tag_rip` (3 : ces deux LSA portent l'étiquette {trip}), `dual_tag_ospf` (3 :
la route RIP de `dual_rip1` vers `{lano}` porte l'étiquette {tospf}), `dual_paths` (4 : `dual_b1` et
`dual_b2` routent `{lan3}` par RIP via `dual_rip1` ; compté si `dual_redundant` l'est : juste après le
démarrage, avant qu'OSPF converge, `dual_b2` n'a que sa route RIP), `dual_no_return_rip` (2 : `dual_rip1` n'a pas de
route vers `dual_tagr` ; compté si `dual_tag_ospf` l'est), `dual_no_return_ospf` (2 : aucun LSA de
`dual_b1` ou `dual_b2` pour `dual_tago` ; compté si `dual_tag_rip` l'est), `dual_ping` (2 : `ping`
entre `dual_h1` et `dual_h2`, compté si `dual_redundant` l'est : il marche déjà au départ).
""": """
**Solution.** At the start, `dual_b2` knows `{lan3}` through RIP (distance {drip}) and through
OSPF, as an external route coming from `dual_b1` (distance {dospf}): it chooses OSPF and goes via
`dual_ospf1` (`{nh}`), then `dual_b1`. With the naive redistribution on `dual_b2`, this OSPF (not
RIP) route goes into RIP with the seed metric 1: `dual_rip1` receives it at 2, better than the 3
of the real path via `dual_rip2`. `dual_rip1` then sends the packets for `{lan3}` to `dual_b2`,
which sends them through OSPF to `dual_b1`, which hands them back to `dual_rip1`: a loop
(`traceroute` repeats `dual_rip1`, `dual_b2`, `dual_ospf1`, `dual_b1`) until the TTL expires.

On `dual_b1` and `dual_b2`:

{solution}

The tags prevent a route from crossing the border back in the opposite direction (the test routes
check it); the distance {dext} of the OSPF external routes, above RIP ({drip}), makes each point
choose the RIP route to the RIP networks, once the routes have been reinstalled by `clear ip ospf
process` (without it, `dual_b2` keeps its OSPF route with distance {dospf}). Another accepted
solution: lowering below {dospf} the distance of the native RIP routes only (`distance 100
0.0.0.0/0 LIST` under `router rip`, with an `access-list`).

Evaluation: `dual_redundant` (4: `dual_ospf1` sees LSAs of `{lan3}` coming from `dual_b1` **and**
from `dual_b2`), `dual_tag_rip` (3: these two LSAs carry the tag {trip}), `dual_tag_ospf` (3: the
RIP route of `dual_rip1` to `{lano}` carries the tag {tospf}), `dual_paths` (4: `dual_b1` and
`dual_b2` route `{lan3}` through RIP via `dual_rip1`; counted if `dual_redundant` is: just after
the start, before OSPF converges, `dual_b2` only has its RIP route), `dual_no_return_rip` (2:
`dual_rip1` has no route to `dual_tagr`; counted if `dual_tag_ospf` is), `dual_no_return_ospf` (2:
no LSA of `dual_b1` or `dual_b2` for `dual_tago`; counted if `dual_tag_rip` is), `dual_ping` (2:
`ping` between `dual_h1` and `dual_h2`, counted if `dual_redundant` is: it already works at the
start).
""",
    "Observations sur le site dual": "Observations in the dual site",
    """
- avant toute modification, prochain saut de la route de `dual_b2` vers `dual_lan3` : @@{nexthop:[0-9.]+}@@
- distance administrative de cette route : @@{dist_chosen:[0-9]+}@@ et de la route RIP écartée :
  @@{dist_rip:[0-9]+}@@
- avec la même redistribution, sans filtre, sur `dual_b1` et `dual_b2`, un `ping` de `dual_h2` vers
  `dual_h1` :
  @@{loop:>tourne en boucle entre dual_rip1, dual_b2, dual_ospf1 et dual_b1>>>loop|fonctionne, par le chemin le plus court>>>ok|échoue sur dual_rip3, qui n'a pas de route de retour>>>noroute|est refusé par dual_b2>>>filter}@@
- les étiquettes servent à :
  @@{tags:>empêcher une route redistribuée de revenir dans son domaine d'origine par l'autre point>>>return|choisir la métrique d'amorçage>>>metric|accélérer la convergence de RIP>>>speed|authentifier les annonces>>>auth}@@
""": """
- before any change, next hop of the route of `dual_b2` to `dual_lan3`: @@{nexthop:[0-9.]+}@@
- administrative distance of this route: @@{dist_chosen:[0-9]+}@@ and of the discarded RIP route:
  @@{dist_rip:[0-9]+}@@
- with the same redistribution, without a filter, on `dual_b1` and `dual_b2`, a `ping` from
  `dual_h2` to `dual_h1`:
  @@{loop:>loops between dual_rip1, dual_b2, dual_ospf1 and dual_b1>>>loop|works, by the shortest path>>>ok|fails on dual_rip3, which has no route back>>>noroute|is refused by dual_b2>>>filter}@@
- the tags are used to:
  @@{tags:>prevent a redistributed route from coming back into its original domain through the other point>>>return|choose the seed metric>>>metric|speed up the convergence of RIP>>>speed|authenticate the advertisements>>>auth}@@
""",
    """
**Solution.** **{nh}** (`dual_ospf1`) ; **{dospf}** et **{drip}** ; **une boucle** ; **empêcher le
retour d'une route dans son domaine d'origine**.

Évaluation : `dual_q_nexthop`, `dual_q_distances` (1 chacun ; les deux valeurs pour le second) et,
pour l'enseignant seulement (choix dans une liste), `dual_q_loop`, `dual_q_tags` (1 chacun).
""": """
**Solution.** **{nh}** (`dual_ospf1`); **{dospf}** and **{drip}**; **a loop**; **preventing a
route from coming back into its original domain**.

Evaluation: `dual_q_nexthop`, `dual_q_distances` (1 each; both values for the second one) and, for
the instructor only (choice from a list), `dual_q_loop`, `dual_q_tags` (1 each).
""",
    "les réseaux RIP redistribués par les deux points": "the RIP networks redistributed by both points",
    "étiquette des routes passées de RIP à OSPF": "tag of the routes passed from RIP to OSPF",
    "étiquette des routes passées d'OSPF à RIP": "tag of the routes passed from OSPF to RIP",
    "les deux points joignent dual_lan3 par RIP": "both points reach dual_lan3 through RIP",
    "une route marquée comme venue de RIP ne retourne pas dans RIP": "a route tagged as coming from RIP does not go back into RIP",
    "une route marquée comme venue d'OSPF ne retourne pas dans OSPF": "a route tagged as coming from OSPF does not go back into OSPF",
    "dual_h1 et dual_h2 se joignent": "dual_h1 and dual_h2 reach each other",
    "prochain saut de dual_b2 au départ": "next hop of dual_b2 at the start",
    "distances des deux routes": "distances of the two routes",
    "effet de la redistribution naïve": "effect of the naive redistribution",
    "rôle des étiquettes": "role of the tags",
    "Partie 4 — OSPF et BGP (site edge)": "Part 4 — OSPF and BGP (site edge)",
    "Entre OSPF et BGP": "Between OSPF and BGP",
    """
L'entreprise (AS {asn}) a un domaine OSPF : `edge_ospf1` porte ses réseaux publics `edge_lan1`
`{lan1}` (avec `edge_h1`) et `edge_lan2` `{lan2}`, tous deux dans le bloc `{company}`. `edge_b` la relie
en eBGP à son opérateur `edge_isp` (AS {isp_as}), par le lien `edge_lisp`. La session est établie ; les
route-maps `ISP-IN` et `TO-ISP` de `edge_b`, exigées par la RFC 8212, laissent tout passer : le
filtrage vous revient. L'opérateur envoie une route par défaut, le préfixe d'un partenaire
`{partner}` (adresse `partner`, `{partner_host}`) et d'autres préfixes d'Internet.

Sur `edge_b` uniquement (section @@ref:bgp@@) :

1. annoncez à l'opérateur les réseaux de l'entreprise **en redistribuant OSPF dans BGP**, filtré :
   les préfixes du bloc `{company}` et rien d'autre (ni `edge_l12`, ni `edge_lisp`) ;
2. donnez à OSPF la route par défaut apprise de l'opérateur ;
3. redistribuez dans OSPF **le seul préfixe du partenaire**, en externe de type 1 de métrique
   **{metric}** ; aucune autre route BGP.

Vérifiez sur `edge_b` (`show bgp ipv4 unicast`, `show bgp ipv4 unicast neighbors {peer}
advertised-routes`) et sur `edge_ospf1` (`show ip ospf route`), puis `ping` de `edge_h1` vers
`edge_inet` et vers `partner`.
""": """
The company (AS {asn}) has an OSPF domain: `edge_ospf1` carries its public networks `edge_lan1`
`{lan1}` (with `edge_h1`) and `edge_lan2` `{lan2}`, both in the block `{company}`. `edge_b` connects
it in eBGP to its operator `edge_isp` (AS {isp_as}), through the link `edge_lisp`. The session is
established; the route-maps `ISP-IN` and `TO-ISP` of `edge_b`, required by RFC 8212, let everything
through: the filtering is up to you. The operator sends a default route, the prefix of a partner
`{partner}` (address `partner`, `{partner_host}`) and other Internet prefixes.

On `edge_b` only (section @@ref:bgp@@):

1. announce the networks of the company to the operator **by redistributing OSPF into BGP**,
   filtered: the prefixes of the block `{company}` and nothing else (neither `edge_l12` nor
   `edge_lisp`);
2. give OSPF the default route learned from the operator;
3. redistribute into OSPF **only the prefix of the partner**, as an external route of type 1 with
   metric **{metric}**; no other BGP route.

Check on `edge_b` (`show bgp ipv4 unicast`, `show bgp ipv4 unicast neighbors {peer}
advertised-routes`) and on `edge_ospf1` (`show ip ospf route`), then `ping` from `edge_h1` to
`edge_inet` and to `partner`.
""",
    """
**Solution.**

{solution}

L'opérateur reçoit `{lan1}` et `{lan2}` avec l'origine *incomplete* (`?`, redistribution) et le MED
{med} : la métrique OSPF des deux réseaux sur `edge_b` (lien `edge_l12` {dc} + réseau passif {dc}).
`default-information originate` (sans `always`) suit la route par défaut reçue de l'opérateur.
`redistribute bgp` sans filtre ferait entrer dans OSPF tous les préfixes de l'opérateur.

Évaluation (table BGP de `edge_isp`, LSA externes vus par `edge_ospf1`) : `edge_export` (4 : les
deux réseaux reçus de l'AS {asn}), `edge_export_only` (2 : rien d'autre de l'AS {asn} ; compté si
`edge_export` l'est), `edge_origin_med` (2 : origine *incomplete*, MED {med}), `edge_default` (3 :
route par défaut de `edge_ospf1` par `edge_b`), `edge_partner` (3 : LSA du préfixe partenaire,
type 1, métrique {metric}), `edge_partner_only` (2 : aucun autre préfixe de l'opérateur dans OSPF ;
compté si `edge_partner` l'est), `edge_ping` (2 : `edge_h1` joint `edge_inet` et `partner`).
""": """
**Solution.**

{solution}

The operator receives `{lan1}` and `{lan2}` with the origin *incomplete* (`?`, redistribution) and
the MED {med}: the OSPF metric of the two networks on `edge_b` (link `edge_l12` {dc} + passive
network {dc}). `default-information originate` (without `always`) follows the default route
received from the operator. `redistribute bgp` without a filter would bring all the operator's
prefixes into OSPF.

Evaluation (BGP table of `edge_isp`, external LSAs seen by `edge_ospf1`): `edge_export` (4: the two
networks received from AS {asn}), `edge_export_only` (2: nothing else from AS {asn}; counted if
`edge_export` is), `edge_origin_med` (2: origin *incomplete*, MED {med}), `edge_default` (3:
default route of `edge_ospf1` via `edge_b`), `edge_partner` (3: LSA of the partner prefix, type 1,
metric {metric}), `edge_partner_only` (2: no other prefix of the operator in OSPF; counted if
`edge_partner` is), `edge_ping` (2: `edge_h1` reaches `edge_inet` and `partner`).
""",
    "Observations sur le site edge": "Observations in the edge site",
    """
- code d'origine BGP (`i`, `e` ou `?`) des réseaux de l'entreprise reçus par l'opérateur : @@{origin:[a-zA-Z?]+}@@
- MED de `edge_lan1` (colonne *Metric* de `show bgp ipv4 unicast` sur `edge_b`) : @@{med:[0-9]+}@@
- on ne redistribue jamais toute la table BGP d'Internet dans OSPF parce que :
  @@{table:>des centaines de milliers de routes satureraient la base et les calculs de chaque routeur OSPF>>>size|BGP l'interdit techniquement>>>forbidden|OSPF n'accepte que 100 routes externes>>>limit|les routes BGP n'ont pas de métrique>>>metric}@@
- `network` et `redistribute` dans BGP diffèrent par :
  @@{network:>l'origine (i pour network, ? pour redistribute) et ce qui est annoncé (un préfixe choisi ou toute une source)>>>origin|rien, ce sont deux syntaxes de la même commande>>>same|network ne fonctionne qu'en iBGP>>>ibgp|redistribute n'est possible que depuis OSPF>>>ospf}@@
""": """
- BGP origin code (`i`, `e` or `?`) of the company's networks received by the operator: @@{origin:[a-zA-Z?]+}@@
- MED of `edge_lan1` (*Metric* column of `show bgp ipv4 unicast` on `edge_b`): @@{med:[0-9]+}@@
- the whole BGP table of the Internet is never redistributed into OSPF because:
  @@{table:>hundreds of thousands of routes would overload the database and the computations of every OSPF router>>>size|BGP technically forbids it>>>forbidden|OSPF only accepts 100 external routes>>>limit|BGP routes have no metric>>>metric}@@
- `network` and `redistribute` in BGP differ in:
  @@{network:>the origin (i for network, ? for redistribute) and what is announced (a chosen prefix or a whole source)>>>origin|nothing, they are two syntaxes of the same command>>>same|network only works in iBGP>>>ibgp|redistribute is only possible from OSPF>>>ospf}@@
""",
    """
**Solution.** **?** (*incomplete*) ; **{med}** ; **la taille de la table** ; **l'origine et ce qui
est annoncé**.

Évaluation : `edge_q_origin`, `edge_q_med` (1 chacun) et, pour l'enseignant seulement (choix dans
une liste), `edge_q_table`, `edge_q_network` (1 chacun).
""": """
**Solution.** **?** (*incomplete*); **{med}**; **the size of the table**; **the origin and what is
announced**.

Evaluation: `edge_q_origin`, `edge_q_med` (1 each) and, for the instructor only (choice from a
list), `edge_q_table`, `edge_q_network` (1 each).
""",
    "les réseaux de l'entreprise reçus par l'opérateur": "the company's networks received by the operator",
    "rien d'autre envoyé à l'opérateur": "nothing else sent to the operator",
    "origine incomplete et MED": "origin incomplete and MED",
    "route par défaut dans OSPF": "default route in OSPF",
    "préfixe partenaire en externe de type 1 avec sa métrique": "partner prefix as external type 1 with its metric",
    "aucune autre route BGP dans OSPF": "no other BGP route in OSPF",
    "edge_h1 joint edge_inet et partner": "edge_h1 reaches edge_inet and partner",
    "origine des routes redistribuées": "origin of the redistributed routes",
    "MED": "MED",
    "pourquoi pas toute la table BGP": "why not the whole BGP table",
    "network et redistribute": "network and redistribute",
    "Partie 5 — dépannage (site fix)": "Part 5 — troubleshooting (site fix)",
    "Dépannage d'une redistribution": "Troubleshooting a redistribution",
    """
Le site `fix` ressemble au site `mut` : `fix_rip1` dans le domaine RIP (`fix_lan1` avec `fix_h1`),
`fix_b` à la frontière, `fix_ospf1` dans le domaine OSPF (`fix_lan2` avec `fix_h2`), et des serveurs,
`fix_srv` `{srv}`, derrière la passerelle `fix_gw` de `fix_b`. Un administrateur a configuré la
redistribution de `fix_b`, mais presque rien ne marche. Ce qui est attendu :

- les réseaux du domaine RIP (le bloc `{block}`) sont annoncés dans OSPF, ceux d'OSPF dans RIP ;
- les serveurs `fix_srv` sont annoncés dans OSPF, par une route statique de FRR vers `fix_gw`
  (`{gw}`) ;
- le poste de supervision `fix_h2` joint `fix_h1` et **toutes les adresses** de `fix_rip1`.

Trouvez et corrigez les **quatre pannes** de `fix_b`, en corrigeant sa configuration plutôt qu'en la
réécrivant (configuration : `show running-config` ; symptômes : `show ip rip` sur `fix_rip1`, `show ip
ospf route` sur `fix_ospf1`, `show ip route` sur `fix_b`, `show route-map`, `show ip prefix-list` ;
section @@ref:diagnostic@@).
""": """
The `fix` site looks like the `mut` site: `fix_rip1` in the RIP domain (`fix_lan1` with `fix_h1`),
`fix_b` at the border, `fix_ospf1` in the OSPF domain (`fix_lan2` with `fix_h2`), and servers,
`fix_srv` `{srv}`, behind the gateway `fix_gw` of `fix_b`. An administrator has configured the
redistribution of `fix_b`, but almost nothing works. What is expected:

- the networks of the RIP domain (the block `{block}`) are advertised into OSPF, those of OSPF into
  RIP;
- the servers `fix_srv` are advertised into OSPF, through an FRR static route to `fix_gw`
  (`{gw}`);
- the monitoring host `fix_h2` reaches `fix_h1` and **all the addresses** of `fix_rip1`.

Find and fix the **four faults** of `fix_b`, by correcting its configuration rather than rewriting
it (configuration: `show running-config`; symptoms: `show ip rip` on `fix_rip1`, `show ip ospf
route` on `fix_ospf1`, `show ip route` on `fix_b`, `show route-map`, `show ip prefix-list`;
section @@ref:diagnostic@@).
""",
    """
**Solution.** Les quatre pannes et leur correction :

1. `redistribute ospf metric {bad}` sous `router rip` : `fix_rip1` reçoit les routes OSPF à 16,
   inaccessibles ;
2. `ip prefix-list RIP-NETS seq 10 permit {block}` sans `le` : la liste ne laisse passer que le
   préfixe `{block}` lui-même, la route-map `RIP-TO-OSPF` refuse tous les réseaux RIP ;
3. `ip route {srv} {wrong}` : prochain saut injoignable (le bon est `{gw}`), la route est inactive
   et n'est pas redistribuée ;
4. pas de `redistribute connected` : le lien `fix_lrb` (l'adresse `{r1}` de `fix_rip1`) est un
   réseau connecté de `fix_b`, inconnu d'OSPF.

{solution}

Évaluation : `fix_seed` (3 : route de `fix_rip1` vers `fix_lan2`, métrique inférieure à 16),
`fix_filter` (3 : LSA de `fix_lan1` par `fix_b` vu de `fix_ospf1`), `fix_static` (3 : LSA de
`fix_srv`), `fix_connected` (3 : route OSPF de `fix_ospf1` vers `fix_lrb`), `fix_ping` (2 : `fix_h2`
joint `fix_h1` et `{r1}`).
""": """
**Solution.** The four faults and their fix:

1. `redistribute ospf metric {bad}` under `router rip`: `fix_rip1` receives the OSPF routes at 16,
   unreachable;
2. `ip prefix-list RIP-NETS seq 10 permit {block}` without `le`: the list only lets through the
   prefix `{block}` itself, the route-map `RIP-TO-OSPF` refuses all the RIP networks;
3. `ip route {srv} {wrong}`: unreachable next hop (the right one is `{gw}`), the route is inactive
   and is not redistributed;
4. no `redistribute connected`: the link `fix_lrb` (the address `{r1}` of `fix_rip1`) is a
   connected network of `fix_b`, unknown to OSPF.

{solution}

Evaluation: `fix_seed` (3: route of `fix_rip1` to `fix_lan2`, metric below 16), `fix_filter` (3:
LSA of `fix_lan1` by `fix_b` seen from `fix_ospf1`), `fix_static` (3: LSA of `fix_srv`),
`fix_connected` (3: OSPF route of `fix_ospf1` to `fix_lrb`), `fix_ping` (2: `fix_h2` reaches
`fix_h1` and `{r1}`).
""",
    "Les symptômes du site fix": "The symptoms of the fix site",
    """
- avant correction, métrique de `fix_lan2` dans `show ip rip` de `fix_rip1` : @@{metric_before:[0-9]+}@@
- la première panne de RIP vient de ce que :
  @@{seed:>annoncée avec la métrique 15, une route arrive à 16 chez le voisin : inaccessible>>>infinity|RIP refuse les routes redistribuées depuis OSPF>>>refused|la version 1 de RIP ne transporte pas les masques>>>version|l'horizon partagé (split horizon) bloque la route>>>split}@@
- la liste de préfixes `RIP-NETS` refusait tout parce que :
  @@{plist:>sans le, une règle ne laisse passer que le préfixe exact, ici le /22 lui-même>>>exact|une liste de préfixes ne peut pas servir dans une route-map>>>usage|le numéro de séquence 10 est réservé>>>seq|il manque une règle deny à la fin>>>deny}@@
- la route statique vers `fix_srv` n'était pas redistribuée parce que :
  @@{static:>son prochain saut n'est joignable par aucune route : elle est inactive>>>inactive|une route statique ne se redistribue pas dans OSPF>>>never|fix_gw ne répond pas au ping>>>ping|il faudrait redistribute kernel>>>kernel}@@
""": """
- before the fix, metric of `fix_lan2` in `show ip rip` of `fix_rip1`: @@{metric_before:[0-9]+}@@
- the first RIP fault is caused by the fact that:
  @@{seed:>advertised with metric 15, a route arrives at 16 at the neighbour: unreachable>>>infinity|RIP refuses the routes redistributed from OSPF>>>refused|RIP version 1 does not carry the masks>>>version|split horizon blocks the route>>>split}@@
- the prefix list `RIP-NETS` refused everything because:
  @@{plist:>without le, a rule only lets the exact prefix through, here the /22 itself>>>exact|a prefix list cannot be used in a route-map>>>usage|sequence number 10 is reserved>>>seq|a deny rule is missing at the end>>>deny}@@
- the static route to `fix_srv` was not redistributed because:
  @@{static:>its next hop is reachable by no route: it is inactive>>>inactive|a static route cannot be redistributed into OSPF>>>never|fix_gw does not answer the ping>>>ping|redistribute kernel would be needed>>>kernel}@@
""",
    """
**Solution.** **16** ; **la métrique 15** ; **le préfixe exact** ; **une route statique inactive**.

Évaluation : `fix_q_metric` (1) et, pour l'enseignant seulement (choix dans une liste), `fix_q_seed`,
`fix_q_filter`, `fix_q_static` (1 chacun).
""": """
**Solution.** **16**; **metric 15**; **the exact prefix**; **an inactive static route**.

Evaluation: `fix_q_metric` (1) and, for the instructor only (choice from a list), `fix_q_seed`,
`fix_q_filter`, `fix_q_static` (1 each).
""",
    "fix_lan2 accessible dans RIP": "fix_lan2 reachable in RIP",
    "les réseaux RIP annoncés dans OSPF": "the RIP networks advertised into OSPF",
    "fix_srv annoncé dans OSPF": "fix_srv advertised into OSPF",
    "fix_lrb connu dans OSPF": "fix_lrb known in OSPF",
    "fix_h2 joint fix_h1 et fix_rip1": "fix_h2 reaches fix_h1 and fix_rip1",
    "métrique avant correction": "metric before the fix",
    "panne de la métrique": "fault of the metric",
    "panne de la liste": "fault of the prefix list",
    "panne de la route statique": "fault of the static route",
    "Bonus — résumé sur un ASBR (site sum)": "Bonus — summary on an ASBR (site sum)",
    "Bonus : résumer les routes externes": "Bonus: summarising the external routes",
    """
`sum_asbr` est l'ASBR d'un domaine OSPF : il redistribue des routes statiques vers {count} réseaux
/24 contigus derrière `sum_gw`, de `{first}` à `{last}`, et `sum_ospf1` reçoit {count} LSA externes.
Sur `sum_asbr`, faites qu'OSPF n'annonce plus qu'**un seul préfixe**, `{block}`, marqué de
l'étiquette **{tag}** (section @@ref:summary@@). Vérifiez sur `sum_ospf1`.
""": """
`sum_asbr` is the ASBR of an OSPF domain: it redistributes static routes to {count} contiguous /24
networks behind `sum_gw`, from `{first}` to `{last}`, and `sum_ospf1` receives {count} external
LSAs. On `sum_asbr`, make OSPF advertise **a single prefix** only, `{block}`, marked with the tag
**{tag}** (section @@ref:summary@@). Check on `sum_ospf1`.
""",
    """
**Solution.**

{solution}

Évaluation (bonus) : `sum_summary` (3 : LSA de `{block}` par `sum_asbr`, étiquette {tag}),
`sum_specifics` (2 : plus aucun LSA des /24), `sum_ping` (1 : `sum_ospf1` joint `{host}`) ; les deux
comptés si `sum_summary` l'est.
""": """
**Solution.**

{solution}

Evaluation (bonus): `sum_summary` (3: LSA of `{block}` by `sum_asbr`, tag {tag}), `sum_specifics`
(2: no LSA of the /24 networks any more), `sum_ping` (1: `sum_ospf1` reaches `{host}`); the last
two counted if `sum_summary` is.
""",
    "le résumé, avec son étiquette": "the summary, with its tag",
    "plus aucun /24 annoncé": "no /24 advertised any more",
    "sum_ospf1 joint un des réseaux résumés": "sum_ospf1 reaches one of the summarised networks",
    "Bonus — aire NSSA (site nssa)": "Bonus — NSSA area (site nssa)",
    "Bonus : un ASBR dans une aire qui refuse les routes externes": "Bonus: an ASBR in an area that refuses external routes",
    """
L'aire {area} de ce domaine (`nssa_abr`, ABR entre l'aire 0 et l'aire {area}, et `nssa_asbr`) est une
aire **stub** : elle ne reçoit pas la route externe `nssa_coreext` (`{coreext}`) que redistribue
`nssa_core`, et c'est voulu. Mais `nssa_asbr` doit faire connaître au reste du domaine les réseaux
`nssa_ext1` `{e1}` et `nssa_ext2` `{e2}`, derrière `nssa_gw` : il a les routes statiques et
`redistribute static`, sans effet. Sur `nssa_abr` et `nssa_asbr`, faites que ces deux réseaux
atteignent `nssa_core`, l'aire {area} refusant toujours les routes externes du reste du domaine
(section @@ref:nssa@@).
""": """
Area {area} of this domain (`nssa_abr`, ABR between area 0 and area {area}, and `nssa_asbr`) is a
**stub** area: it does not receive the external route `nssa_coreext` (`{coreext}`) that
`nssa_core` redistributes, and that is intended. But `nssa_asbr` must make the networks
`nssa_ext1` `{e1}` and `nssa_ext2` `{e2}`, behind `nssa_gw`, known to the rest of the domain: it
has the static routes and `redistribute static`, to no effect. On `nssa_abr` and `nssa_asbr`, make
these two networks reach `nssa_core`, area {area} still refusing the external routes of the rest
of the domain (section @@ref:nssa@@).
""",
    """
**Solution.** Sur `nssa_abr` et `nssa_asbr` :

{solution}

`nssa_abr` reçoit de `nssa_asbr` deux LSA de type 7 (`show ip ospf database nssa-external`) et les
traduit en LSA de type 5, annoncés en son nom (`{rid}`), l'adresse de `nssa_asbr` en *Forward
Address* : `nssa_core` les voit venir de `nssa_abr`, pas de `nssa_asbr`.

Évaluation (bonus) : `nssa_area` (1 : l'aire est NSSA sur les deux routeurs, adjacence `Full`),
`nssa_type7` (2 : LSA de type 7 de `nssa_asbr` pour les deux réseaux dans la base de `nssa_abr`),
`nssa_translated` (2 :
LSA de type 5 des deux réseaux annoncés par `nssa_abr`, vus de `nssa_core`), `nssa_blocked` (1 :
`nssa_asbr` n'a pas de route vers `nssa_coreext` ; compté si `nssa_area` l'est).
""": """
**Solution.** On `nssa_abr` and `nssa_asbr`:

{solution}

`nssa_abr` receives from `nssa_asbr` two type 7 LSAs (`show ip ospf database nssa-external`) and
translates them into type 5 LSAs, advertised in its own name (`{rid}`), with the address of
`nssa_asbr` as *Forward Address*: `nssa_core` sees them coming from `nssa_abr`, not from
`nssa_asbr`.

Evaluation (bonus): `nssa_area` (1: the area is NSSA on both routers, adjacency `Full`),
`nssa_type7` (2: type 7 LSAs of `nssa_asbr` for both networks in the database of `nssa_abr`),
`nssa_translated` (2: type 5 LSAs of both networks advertised by `nssa_abr`, seen from
`nssa_core`), `nssa_blocked` (1: `nssa_asbr` has no route to `nssa_coreext`; counted if
`nssa_area` is).
""",
    "aire NSSA sur les deux routeurs": "NSSA area on both routers",
    "routes de type 7 sur l'ABR": "type 7 routes on the ABR",
    "traduction en type 5 par l'ABR": "translation into type 5 by the ABR",
    "les routes externes du domaine restent hors de l'aire": "the external routes of the domain stay out of the area",
    "Bonus — agrégation BGP (site agg)": "Bonus — BGP aggregation (site agg)",
    "Bonus : agréger les routes redistribuées dans BGP": "Bonus: aggregating the routes redistributed into BGP",
    """
`agg_b` redistribue déjà dans BGP, vers l'opérateur `agg_isp`, les {count} réseaux /24 de l'entreprise
portés par `agg_ospf1` (bloc `{block}`) : l'opérateur reçoit {count} préfixes. Sur `agg_b`, faites
qu'il ne reçoive plus que le préfixe agrégé `{block}` (section @@ref:summary@@).
""": """
`agg_b` already redistributes into BGP, towards the operator `agg_isp`, the {count} /24 networks of
the company carried by `agg_ospf1` (block `{block}`): the operator receives {count} prefixes. On
`agg_b`, make it receive only the aggregate prefix `{block}` (section @@ref:summary@@).
""",
    """
**Solution.**

{solution}

Les {count} /24 restent dans la table BGP de `agg_b`, marqués `s` (*suppressed*).

Évaluation (bonus) : `agg_aggregate` (4 : `agg_isp` reçoit `{block}` de l'AS {asn}), `agg_specifics`
(2 : il ne reçoit plus aucun des /24 ; compté si `agg_aggregate` l'est).
""": """
**Solution.**

{solution}

The {count} /24 networks stay in the BGP table of `agg_b`, marked `s` (*suppressed*).

Evaluation (bonus): `agg_aggregate` (4: `agg_isp` receives `{block}` from AS {asn}),
`agg_specifics` (2: it no longer receives any of the /24 networks; counted if `agg_aggregate` is).
""",
    "le préfixe agrégé reçu par l'opérateur": "the aggregate prefix received by the operator",
    "plus aucun /24 envoyé": "no /24 sent any more",
}}
