"""Anycast lab: one DNS service address announced from several sites, by OSPF and by BGP.

IPv4 only.  Nine independent sites, one per part (completing a part gives all its points whatever
the others), each one with its own copy of the service.  The instances are ``routing-frr``
containers ``*_dnsN`` running FRR and unbound; unbound answers ``id.server`` (class CH, type TXT)
with the name of the machine, so ``dig @<service> id.server CH TXT`` tells which instance
answered.

- ``near`` (OSPF): a line of three routers, an instance behind each end; the students announce the
  service address from both servers (address on ``lo``, ospfd, router-id) and observe the nearest
  instance and the ECMP route of the router in the middle;
- ``prim`` (OSPF): two routers, an instance behind each; the students announce the address as an
  external route, type 2, with a larger metric on the backup instance;
- ``hc`` (OSPF): the address is announced; the students write the health check that withdraws it
  when unbound stops answering.  Each evaluation freezes unbound on ``hc_dns1``, then stops it on
  ``hc_dns2``, and follows the routes;
- ``ofix`` (OSPF troubleshooting): the ``near`` design shipped with four faults (duplicate
  router-id = the service address, replies sent from the unicast address, a stale copy of the
  address on a router, a typo in an instance's address);
- ``bgp``: two providers, an instance at each; the students announce the anycast /24 from both;
- ``te`` (BGP): three providers and three instances; the students make one instance a backup
  (AS-path prepending) and another one a local node (``no-export``);
- ``bfix`` (BGP troubleshooting): the ``bgp`` design shipped with four faults;
- ``bfd`` (bonus): BFD between a router and an instance; each evaluation silently cuts the
  instance 4 s and counts the lost pings;
- ``ecmp`` (bonus): per-flow hashing on the ports, so that one client reaches both instances.

Grading reads ospfd / bgpd / bfdd (lib/frr.py), the kernel routes, the identity of the instance
answering real queries (lib/dns.py), ping series (lib/ping.py).  The states ``solve_<part>`` apply
the reference solution of one part, ``final`` all of them.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List, Optional

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from dns import get_dns_identities, get_dns_identity
from ping import get_ping_series
from frr import (
    bfd_detection_time, bgp_best_path, bgp_paths, get_bfd_peers, get_bgp_advertised_routes, get_bgp_prefix,
    get_bgp_routes, get_bgp_summary, get_kernel_routes, get_ospf_external_lsas, get_ospf_info, get_ospf_neighbors,
    get_ospf_routes, kernel_route_gateways, neighbor_is_full,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Anycast : un service annoncé depuis plusieurs sites (OSPF et BGP)",
           en="Anycast: one service announced from several sites (OSPF and BGP)")
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

# FRR machines (routers, operators' routers, instances) in ethN order: the network of each interface
ROUTER_IFACES = {
    'near_r1': ['near_lan1', 'near_l12'],
    'near_r2': ['near_l12', 'near_l23'],
    'near_r3': ['near_lan3', 'near_l23'],
    'near_dns1': ['near_lan1'],
    'near_dns2': ['near_lan3'],
    'prim_r1': ['prim_lan1', 'prim_l12'],
    'prim_r2': ['prim_lan2', 'prim_l12'],
    'prim_dns1': ['prim_lan1'],
    'prim_dns2': ['prim_lan2'],
    'hc_r1': ['hc_lan1', 'hc_l12'],
    'hc_r2': ['hc_lan2', 'hc_l12'],
    'hc_dns1': ['hc_lan1'],
    'hc_dns2': ['hc_lan2'],
    'ofix_r1': ['ofix_lan1', 'ofix_l12'],
    'ofix_r2': ['ofix_l12', 'ofix_l23'],
    'ofix_r3': ['ofix_lan3', 'ofix_l23'],
    'ofix_dns1': ['ofix_lan1'],
    'ofix_dns2': ['ofix_lan3'],
    'bgp_ispa': ['bgp_lana', 'bgp_lab', 'bgp_ld1'],
    'bgp_ispb': ['bgp_lanb', 'bgp_lab', 'bgp_ld2'],
    'bgp_dns1': ['bgp_ld1'],
    'bgp_dns2': ['bgp_ld2'],
    'te_ispa': ['te_lab', 'te_lac', 'te_ld1'],
    'te_ispb': ['te_lanb', 'te_lab', 'te_lbc', 'te_ld2'],
    'te_ispc': ['te_lanc', 'te_lac', 'te_lbc', 'te_ld3'],
    'te_dns1': ['te_ld1'],
    'te_dns2': ['te_ld2'],
    'te_dns3': ['te_ld3'],
    'bfix_ispa': ['bfix_lana', 'bfix_lab', 'bfix_ld1'],
    'bfix_ispb': ['bfix_lanb', 'bfix_lab', 'bfix_ld2'],
    'bfix_dns1': ['bfix_ld1'],
    'bfix_dns2': ['bfix_ld2'],
    'bfd_r1': ['bfd_lan1', 'bfd_lan2'],
    'bfd_dns1': ['bfd_lan1'],
    'bfd_dns2': ['bfd_lan2'],
    'ecmp_r1': ['ecmp_lanc', 'ecmp_lan1', 'ecmp_lan2'],
    'ecmp_dns1': ['ecmp_lan1'],
    'ecmp_dns2': ['ecmp_lan2'],
}
# client hosts (one interface, eth0): their network and the router of their default route
HOSTS = {
    'bgp_ca': ('bgp_lana', 'bgp_ispa'),
    'bgp_cb': ('bgp_lanb', 'bgp_ispb'),
    'te_cb': ('te_lanb', 'te_ispb'),
    'te_cc': ('te_lanc', 'te_ispc'),
    'bfix_ca': ('bfix_lana', 'bfix_ispa'),
    'bfix_cb': ('bfix_lanb', 'bfix_ispb'),
    'ecmp_c1': ('ecmp_lanc', 'ecmp_r1'),
}
# point-to-point links (/30): the first machine gets .1, the second .2
LINKS = {
    'near_l12': ('near_r1', 'near_r2'), 'near_l23': ('near_r2', 'near_r3'),
    'prim_l12': ('prim_r1', 'prim_r2'),
    'hc_l12': ('hc_r1', 'hc_r2'),
    'ofix_l12': ('ofix_r1', 'ofix_r2'), 'ofix_l23': ('ofix_r2', 'ofix_r3'),
    'bgp_lab': ('bgp_ispa', 'bgp_ispb'), 'bgp_ld1': ('bgp_ispa', 'bgp_dns1'), 'bgp_ld2': ('bgp_ispb', 'bgp_dns2'),
    'te_lab': ('te_ispa', 'te_ispb'), 'te_lac': ('te_ispa', 'te_ispc'), 'te_lbc': ('te_ispb', 'te_ispc'),
    'te_ld1': ('te_ispa', 'te_dns1'), 'te_ld2': ('te_ispb', 'te_dns2'), 'te_ld3': ('te_ispc', 'te_dns3'),
    'bfix_lab': ('bfix_ispa', 'bfix_ispb'), 'bfix_ld1': ('bfix_ispa', 'bfix_dns1'),
    'bfix_ld2': ('bfix_ispb', 'bfix_dns2'),
}
# broadcast networks (/24): FRR machines get .1, .2... in the order of ROUTER_IFACES, hosts a random address
LANS = [n for n in dict.fromkeys(n for nets in ROUTER_IFACES.values() for n in nets) if n not in LINKS]

SERVERS = [m for m in ROUTER_IFACES if '_dns' in m]
ROUTERS = [m for m in ROUTER_IFACES if m not in SERVERS]        # OSPF routers and operators' routers
ISPS = [m for m in ROUTERS if '_isp' in m]
OSPF_SITES = ('near', 'prim', 'hc', 'ofix', 'bfd', 'ecmp')
BGP_SITES = ('bgp', 'te', 'bfix')
ISP_AS = {'ispa': 65010, 'ispb': 65020, 'ispc': 65030}

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _m, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_m] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

SITE_NUMBER = {'near': 1, 'prim': 2, 'hc': 3, 'ofix': 4, 'bgp': 5, 'te': 6, 'bfix': 7, 'bfd': 8, 'ecmp': 9}
SITE_COLORS = {'near': 'lightblue', 'prim': 'palegreen', 'hc': 'khaki', 'ofix': 'lightsalmon', 'bgp': 'plum',
               'te': 'lightcyan', 'bfix': 'mistyrose', 'bfd': 'lightgrey', 'ecmp': 'wheat'}
LOOPBACK_OCTET = 15

OSPF_SERVICE_POOL = IPv4Network("172.16.0.0/12")     # the service address of the OSPF sites: x.y.z.53
BGP_SERVICE_POOL = IPv4Network("198.18.0.0/15")      # the anycast /24 of the BGP sites, service at .53
SERVICE_HOST = 53
ISP_FILTER = f"ip prefix-list FROM-ANYCAST seq 10 permit {BGP_SERVICE_POOL} le 24"

# waits of the reference states: on a fresh project the broadcast interfaces of OSPF stay in the
# Waiting state for a dead interval (40 s) before the DR election, so the states wait until every
# router of the site has all its neighbours Full (at most OSPF_CONVERGE_MAX s), then OSPF_SETTLE s
# (SPF, routes); BGP: sessions, then the route-map delay timer (5 s)
OSPF_CONVERGE_MAX = 90
OSPF_SETTLE = 5
BGP_WAIT = 20
# the health check part: wait after freezing / stopping unbound, after thawing / starting it
HC_DOWN_WAIT = 7
HC_UP_WAIT = 8
# the BFD bonus: pings every 50 ms during 6 s from bfd_r1, the instance cut 4 s after 1 s
BFD_PINGS = 120
BFD_INTERVAL = 0.05
BFD_CUT = 4
BFD_MAX_LOST = 30
BFD_MAX_DETECTION = 300
BFD_HELLO, BFD_DEAD = 2, 8
BFD_BACKUP_COST = 100
# the ECMP bonus: queries of ecmp_c1, each from a new source port
ECMP_QUERIES = 16
# OSPF: a loopback address is a host route of cost 0 in the router LSA (checked live)
LOOPBACK_STUB_COST = 0
DEFAULT_COST = 10
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
UNBOUND_DEFAULTS = "ROOT_TRUST_ANCHOR_UPDATE=false\n"
HEALTH_SCRIPT = "/usr/local/sbin/anycast-health"
HEALTH_UNIT = "/etc/systemd/system/anycast-health.service"
# step 1 of each evaluation: an interrupted evaluation may have left unbound frozen or stopped
UNBOUND_RESTORE = "pkill -CONT -x unbound; pgrep -x unbound >/dev/null || systemctl start unbound; true"


def site_of(machine: str) -> str:
    return machine.split('_', 1)[0]


def role_of(machine: str) -> str:
    return machine.split('_', 1)[1]


def iface(machine: str, net: str) -> str:
    """Name of the interface of *machine* on *net* (``eth1``)."""
    return f"eth{ROUTER_IFACES[machine].index(net)}"


def machine_number(machine: str) -> int:
    """1 for ``*_r1`` / ``*_ispa`` / ``*_dns1``, 2 for ``*_r2`` / ``*_ispb``..."""
    role = role_of(machine)
    if role.startswith('isp'):
        return ord(role[3]) - ord('a') + 1
    return int(''.join(c for c in role if c.isdigit()) or 0)


def server_net(server: str) -> str:
    return ROUTER_IFACES[server][0]


def server_gateway(server: str) -> str:
    """The router (or operator's router) on the network of *server*."""
    net = server_net(server)
    return next(m for m in ROUTERS if net in ROUTER_IFACES[m])


def isp_of(server: str) -> str:
    return server_gateway(server)


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


def _frr_daemons(enabled: tuple) -> str:
    lines = ["# /etc/frr/daemons -- généré par le TP",
             "# (zebra, mgmtd, staticd et watchfrr démarrent toujours)"]
    lines += [f"{name}={'yes' if name in enabled else 'no'}" for name in _FRR_DAEMON_NAMES]
    return "\n".join(lines) + "\n" + _FRR_DAEMON_OPTIONS


def unbound_conf(server: str, automatic: bool = True) -> str:
    """/etc/unbound/unbound.conf of an instance: every address, every client, its name as identity."""
    lines = ["# /etc/unbound/unbound.conf -- instance du service anycast (généré par le TP)",
             "server:",
             "    interface: 0.0.0.0"]
    if automatic:
        lines.append("    interface-automatic: yes")
    lines += ["    access-control: 0.0.0.0/0 allow",
              "    do-ip6: no",
              "    hide-identity: no",
              f'    identity: "{server}"',
              f'    nsid: "ascii_{server}"',
              "    verbosity: 1"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    asn: int = 0               # AS of the anycast operator (BGP sites)
    prim_metric1: int = 0      # part 2: external metric of the primary instance
    prim_metric2: int = 0      # part 2: external metric of the backup instance

    @classmethod
    def generate(cls):
        data = cls()
        data.asn = random.randint(64512, 64999)
        data.prim_metric1 = 10 * random.randint(2, 9)
        data.prim_metric2 = 10 * random.randint(15, 50)

        # the service address of the OSPF sites, and its typo (the next /24) for the ofix site
        ospf_block = random_ipv4networks(24, from_network=OSPF_SERVICE_POOL,
                                         exclude=[IPv4Network("172.31.255.0/24")])[0]
        data.ips.service_ospf = IPv4Interface((int(ospf_block.network_address) + SERVICE_HOST, 32))
        data.ips.service_typo = IPv4Interface((int(ospf_block.network_address) + 256 + SERVICE_HOST, 32))
        data.nets.anycast = random_ipv4networks(24, from_network=BGP_SERVICE_POOL)[0]
        data.ips.service_bgp = IPv4Interface((int(data.nets.anycast.network_address) + SERVICE_HOST, 32))

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            links = [n for n in LINKS if site_of(n) == site]
            for k, net in enumerate(links):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            lans = [n for n in LANS if site_of(n) == site]
            for j, net in enumerate(lans):
                setattr(data.nets, net, _subnet(data.nets.instance, base + 1 + j))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET))
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for net in LANS:
            network = getattr(data.nets, net)
            members = [m for m, nets in ROUTER_IFACES.items() if net in nets]
            for k, m in enumerate(members):
                setattr(data.ips, f"{m}_{net}", IPv4Interface((int(network.network_address) + 1 + k, 24)))
        for host, (net, _gw) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, host, IPv4Interface((int(network.network_address) + random.randint(10, 250), 24)))
        for router in ROUTERS:
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + machine_number(router), 32)))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("routing-frr")
    if machine in ROUTERS:
        spec['shape'] = 'box'
    if machine in ISPS:
        spec['allow_connection'] = False
    return spec


def _block_lines(lines: List[str], indent_unit: str = " ") -> List[str]:
    """Indent vtysh lines by block (``router``, ``interface``, ``route-map``, ``bfd``, ``profile``,
    ``address-family``): what both frr.conf and the solution texts show."""
    out, depth = [], 0
    for line in lines:
        if line in ("exit", "exit-address-family"):
            depth = max(0, depth - 1)
            out.append(indent_unit * depth + line)
            continue
        out.append(indent_unit * depth + line)
        if line.startswith(("router ", "interface ", "route-map ", "address-family ", "profile ")) or line == "bfd":
            depth += 1
    return out


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in MACHINES}
    _network_specs = {}
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")

        self.net_config = {}
        for m, nets in ROUTER_IFACES.items():
            routes = [(default, self.addr(server_gateway(m), server_net(m)))] if m in SERVERS else []
            self.net_config[m] = [([getattr(d.ips, f"{m}_{net}")], routes if i == 0 else [])
                                  for i, net in enumerate(nets)]
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(default, self.addr(gw, net))])]

        # /etc/hosts, one per site: every interface gets m-ethN (the first one also m), loopbacks m-lo
        self.hosts_by_site: Dict[str, str] = {}
        for site in SITE_NUMBER:
            lines = []
            for m, nets in ROUTER_IFACES.items():
                if site_of(m) != site:
                    continue
                for i, net in enumerate(nets):
                    names = f"{m}-eth{i}" if i else f"{m}\t{m}-eth{i}"
                    lines.append(f"{self.addr(m, net)}\t{names}")
                if m in ROUTERS:
                    lines.append(f"{self.lo(m)}\t{m}-lo")
            for h in HOSTS:
                if site_of(h) == site:
                    lines.append(f"{getattr(d.ips, h).ip}\t{h}")
            lines.append(f"{self.service(site)}\tanycast")
            self.hosts_by_site[site] = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses -------------------------------------------------------------------

    def addr(self, machine: str, net: str) -> IPv4Address:
        """Address (without prefix) of *machine* on *net*."""
        return getattr(self.data.ips, f"{machine}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def unicast(self, server: str) -> IPv4Address:
        """The unicast address of an instance (its only interface): its router-id too."""
        return self.addr(server, server_net(server))

    def service(self, site: str) -> IPv4Address:
        """The service address of *site*."""
        return (self.data.ips.service_bgp if site in BGP_SITES else self.data.ips.service_ospf).ip

    @property
    def s_ospf(self) -> IPv4Address:
        return self.data.ips.service_ospf.ip

    @property
    def s_bgp(self) -> IPv4Address:
        return self.data.ips.service_bgp.ip

    @property
    def prefix(self) -> IPv4Network:
        return self.data.nets.anycast

    @property
    def typo(self) -> IPv4Address:
        return self.data.ips.service_typo.ip

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("L'anycast"), tag="principle")
            + tr("""
Une adresse IP désigne d'ordinaire **une** interface : c'est l'**unicast**. Le **broadcast**
désigne toutes les machines d'un réseau, le **multicast** tous les membres d'un groupe. L'**anycast**
désigne **n'importe laquelle** d'un ensemble de machines : la même adresse est configurée sur
plusieurs serveurs, à des endroits différents du réseau, et chaque paquet est livré à **un seul**
d'entre eux, celui que le **routage** juge le plus proche.

| mode | destinataires d'un paquet |
|------|---------------------------|
| unicast | une interface |
| broadcast | toutes les machines du réseau local |
| multicast | les membres d'un groupe |
| anycast | **une** des machines qui portent l'adresse, la plus proche |

En IPv4, rien ne distingue une adresse anycast d'une adresse unicast : c'est une adresse unicast
ordinaire, simplement **annoncée depuis plusieurs endroits** par un protocole de routage (OSPF
dans un domaine, BGP sur Internet). Aucun protocole nouveau, aucune modification des clients : le
client envoie ses paquets à une adresse, et les routeurs, qui connaissent plusieurs chemins vers
elle, choisissent comme d'habitude le meilleur. Chaque copie du serveur est une **instance**.
L'architecture est décrite par la RFC 4786 (*Operation of Anycast Services*) et la RFC 7094. IPv6
définit en plus des adresses anycast propres (RFC 4291, par exemple l'adresse *subnet-router*
d'un préfixe), mais en pratique on y fait de l'anycast comme en IPv4.

« Le plus proche » s'entend **au sens du routage** : le plus petit coût OSPF dans un domaine, la
meilleure route BGP (souvent le chemin d'AS le plus court) sur Internet. Ce n'est pas forcément
l'instance la plus proche en kilomètres ni la moins chargée.
""")
            + info_subtitle(tr("Usages"), tag="uses")
            + tr("""
- **DNS** : les 13 noms des serveurs racine (`a` à `m.root-servers.net`) sont servis par plus de
  1900 instances dans le monde ; les résolveurs publics `1.1.1.1`, `8.8.8.8` ou `9.9.9.9` sont des
  adresses anycast ; de nombreux serveurs faisant autorité aussi. Le DNS s'y prête bien : un échange
  est une question et une réponse en UDP.
- **CDN** et grands services web : l'utilisateur est servi par le centre le plus proche.
- **Résistance aux attaques par déni de service** : le trafic d'une attaque se répartit entre les
  instances au lieu de converger sur une seule ; une instance saturée n'affecte que sa région.
- **AS112** (RFC 7534) : des serveurs anycast répondent aux requêtes inverses des adresses privées
  (`10.in-addr.arpa`…) qui fuient sur Internet.
- **Autres** : serveurs NTP, relais 6to4 `192.88.99.1` (abandonné, RFC 7526), point de rendez-vous
  multicast (*anycast RP*, RFC 4610), puits (*sinkhole*) qui attirent un trafic indésirable.

La **passerelle anycast** (*anycast gateway*) d'un réseau EVPN est autre chose : la même adresse
de passerelle (et la même adresse MAC) sur tous les commutateurs d'accès d'un même réseau local,
pour que chaque hôte trouve sa passerelle sur le commutateur où il est branché.
""")
            + info_subtitle(tr("Le service et ses instances"), tag="service")
            + tr("""
Comme deux paquets successifs d'un même client peuvent atteindre deux instances différentes si le
routage change entre-temps, l'anycast convient aux services :

- **sans état** ou à échanges courts : une requête DNS (UDP), une requête NTP ; TCP fonctionne tant
  que les routes sont stables (une connexion qui change d'instance reçoit un `RST`) ;
- dont **toutes les instances donnent la même réponse** : mêmes zones, même contenu.

Chaque instance a donc deux adresses : l'**adresse du service** (anycast), la même partout, et une
**adresse unicast** propre, pour l'administrer, la superviser et lui servir d'identifiant
(router-id). L'adresse du service est posée sur une interface qui ne tombe jamais : `lo` ou une
interface `dummy`, en /32.

Une instance doit **répondre depuis l'adresse que le client a interrogée**. Un serveur UDP qui
écoute sur toutes les adresses (`0.0.0.0`) et laisse le noyau choisir l'adresse source répond
depuis son adresse unicast : le client, qui attend une réponse de l'adresse du service, l'ignore.
`dig` finit par afficher `timed out`, alors que `tcpdump` montre bien la réponse, partie de
l'adresse unicast de l'instance. Les serveurs DNS savent l'éviter : unbound avec
`interface-automatic: yes` (option `IP_PKTINFO` du socket), BIND en ouvrant un socket par adresse.

Pour savoir **quelle instance a répondu**, les serveurs DNS donnent leur nom dans la classe
`CHAOS` (`id.server` ou `hostname.bind`, type TXT, RFC 4892) ou dans l'option EDNS **NSID**
(RFC 5001) :

```
dig @192.0.2.53 id.server CH TXT +short
dig @192.0.2.53 example.org +nsid
```

Dans ce TP, unbound tourne sur chaque instance (`/etc/unbound/unbound.conf`) et donne comme
identité le nom de la machine.
""")
            + info_subtitle(tr("Anycast dans OSPF"), tag="ospf")
            + tr("""
Dans un domaine OSPF, chaque instance annonce l'adresse du service, en /32 :

- le plus simple : l'instance fait elle-même tourner OSPF (FRR, BIRD…) avec son routeur, et
  annonce l'adresse posée sur `lo` comme un réseau OSPF ordinaire (`network 192.0.2.53/32 area 0`).
  Elle apparaît dans la LSA de routeur de l'instance (`show ip ospf database router`), comme un
  lien *stub* ; une adresse de `lo` est annoncée avec le coût **0** ;
- ou bien comme une **route externe** (LSA de type 5), par `redistribute connected` filtré par une
  route-map (section @@ref:external@@) ;
- ou encore par le routeur, avec une route statique vers l'adresse unicast de l'instance,
  redistribuée : simple, mais le routeur n'apprend rien si le serveur tombe.

Chaque routeur calcule ses plus courts chemins comme d'habitude et trouve l'adresse du service
derrière **plusieurs** routeurs : il garde le moins coûteux. Le domaine se partage ainsi en zones
d'attraction, une par instance. Un routeur à **égale distance** de deux instances installe une
route **ECMP** à deux prochains sauts (section @@ref:ecmp@@).

### @@sec:router-id@@ Le piège du router-id

Le router-id identifie un routeur OSPF : il doit être **unique** dans le domaine. Sans
`ospf router-id`, FRR choisit la plus grande adresse des interfaces de bouclage, sinon la plus
grande adresse des autres interfaces. Sur une instance anycast, c'est souvent… l'adresse du
service, **la même sur toutes les instances**. Deux routeurs de même router-id ne forment pas
forcément d'adjacence entre eux, mais leurs LSA portent le même identifiant : chacun reçoit la
LSA de l'autre, la prend pour une version de la sienne, et la réémet avec un numéro de séquence
plus grand ; les deux s'écrasent sans fin, et les routes vers l'une puis l'autre instance
apparaissent et disparaissent. FRR ne le signale pas dans son journal : c'est `show ip ospf database
router ID` qui le montre, avec une LSA dont l'âge repart sans cesse à zéro et dont le contenu change
d'une lecture à l'autre. **Fixez toujours le router-id** d'une instance
à son adresse unicast. Un changement de router-id ne prend effet qu'après
`clear ip ospf process` (FRR le rappelle).
""")
            + info_subtitle(tr("Instance principale et secours : routes externes"), tag="external")
            + tr("""
Annoncer l'adresse comme un lien de l'instance envoie chaque client vers l'instance **la plus
proche**. On peut au contraire vouloir une instance **principale** qui reçoit tout le trafic, et
une instance de **secours** qui ne sert que si la principale disparaît. Les routes externes d'OSPF
le permettent. Une route externe (LSA de type 5, émise par un **ASBR**) porte une métrique et un
type :

| type | coût comparé entre deux ASBR | effet en anycast |
|------|------------------------------|------------------|
| **E2** (`metric-type 2`, défaut de FRR) | la métrique externe **seule** ; à égalité, le coût jusqu'à l'ASBR départage | la plus petite métrique gagne partout : principale / secours |
| **E1** (`metric-type 1`) | métrique externe **+** coût interne jusqu'à l'ASBR | l'instance la plus proche, corrigée par la métrique |

Sur une instance (FRR) :

```
ip prefix-list ANYCAST seq 10 permit 192.0.2.53/32
route-map ANYCAST permit 10
 match ip address prefix-list ANYCAST
 set metric 20
 set metric-type type-2
 exit
router ospf
 redistribute connected route-map ANYCAST
 exit
```

La route-map est indispensable : sans elle, `redistribute connected` annoncerait **tous** les
réseaux connectés de l'instance. `show ip ospf database external` montre les LSA de type 5 (qui les
émet, avec quelle métrique et quel type), `show ip ospf route` les routes choisies : `N E2 …
[20/30]` se lit « coût jusqu'à l'ASBR 20, métrique externe 30 ».
""")
            + info_subtitle(tr("Suivre l'état du service"), tag="health")
            + tr("""
Le routage ne sait rien du service : si unbound s'arrête ou se bloque sur une instance, celle-ci
continue d'annoncer l'adresse et **tous les clients de sa zone d'attraction sont privés de
service** (un *trou noir*), alors que les autres instances fonctionnent. L'annonce doit donc
suivre l'état du service : un **health check** interroge le service régulièrement, **retire
l'adresse** (ou l'annonce) quand il ne répond plus et la remet quand il répond de nouveau.

```
#!/bin/sh
# /usr/local/sbin/anycast-health : n'annoncer le service que s'il répond
while true; do
    if dig +time=1 +tries=1 @127.0.0.1 id.server CH TXT >/dev/null 2>&1; then
        …   # le service répond : l'adresse doit être sur lo (ip addr add, si elle n'y est pas)
    else
        …   # il ne répond pas : retirer l'adresse (ip addr del)
    fi
    sleep 1
done
```

- **Interrogez le service comme un client** (une vraie requête, avec un délai) : un processus
  présent mais figé passe les tests `pidof` ou `systemctl is-active` et ne répond plus.
- **N'interrogez pas l'adresse du service** : une fois l'adresse retirée, la requête part vers une
  autre instance, qui répond ; le script remet l'adresse, la requête suivante échoue de nouveau…
  l'annonce oscille. Interrogez `127.0.0.1` ou l'adresse unicast.
- Le script ne doit pas « réparer » le service (le redémarrer) : c'est un autre rôle.
- Lancez-le pour qu'il tourne en permanence, par exemple comme service systemd :

```
# /etc/systemd/system/anycast-health.service
[Unit]
Description=Anycast health check
After=unbound.service

[Service]
ExecStart=/usr/local/sbin/anycast-health
Restart=always

[Install]
WantedBy=multi-user.target
```

puis `systemctl daemon-reload` et `systemctl enable --now anycast-health` (dans les conteneurs du
TP, `systemctl` est un remplaçant qui lance le processus ; `systemctl status anycast-health` le
montre).

Retirer l'adresse de `lo` suffit : ospfd retire le lien de sa LSA de routeur, les autres routeurs
recalculent leurs routes et choisissent l'instance suivante. Le **délai de bascule** est la somme
de l'intervalle du test, de son délai d'attente, du délai avant la nouvelle LSA (OSPF ne réémet
pas la même LSA plus d'une fois toutes les **5 s**, *MinLSInterval*) et du calcul SPF. En
production, on ajoute de l'hystérésis (plusieurs échecs avant de retirer, plusieurs succès avant de
remettre) pour éviter les oscillations.
""")
            + info_subtitle(tr("Panne d'un serveur : BFD"), tag="bfd")
            + tr("""
Le health check couvre la panne du **service**. Si l'instance entière disparaît sans prévenir
(panne, câble, carte réseau figée), son routeur ne s'en aperçoit qu'à l'expiration du *dead
interval* OSPF (40 s par défaut) : pendant ce temps, il continue de lui envoyer le trafic.
**BFD** (*Bidirectional Forwarding Detection*, RFC 5880) détecte la perte d'un voisin en
quelques centaines de millisecondes : les deux extrémités s'échangent de petits paquets UDP (port
3784) à un rythme rapide, et déclarent la session morte après `detect-multiplier` paquets
manqués. Le temps de détection vaut l'intervalle de réception négocié multiplié par le
multiplicateur du voisin : 100 ms × 3 = 300 ms. OSPF s'abonne à BFD et abandonne aussitôt
l'adjacence.

Avec FRR (démon `bfdd`), sur **les deux** extrémités :

```
bfd
 profile fast
  receive-interval 100
  transmit-interval 100
  detect-multiplier 3
  exit
 exit
interface eth0
 ip ospf bfd
 ip ospf bfd profile fast
 exit
```

`show bfd peers` liste les sessions, leur état et les intervalles négociés.
""")
            + info_subtitle(tr("ECMP et flux"), tag="ecmp")
            + tr("""
Un routeur qui a deux routes de même coût vers l'adresse du service (**ECMP**) répartit le trafic
**par flux** et non par paquet : il calcule une empreinte (*hash*) des en-têtes et l'associe à un
prochain saut. Tous les paquets d'un même flux suivent ainsi le même chemin, ce qui est
indispensable en anycast (une connexion TCP coupée en deux instances ne fonctionne pas). Sous
Linux, `net.ipv4.fib_multipath_hash_policy` choisit les champs du calcul :

| valeur | champs | effet pour un client |
|--------|--------|----------------------|
| `0` (défaut) | adresses source et destination (L3) | toutes ses requêtes vont à la **même** instance |
| `1` | adresses **et ports**, protocole (L4) | chaque flux (port source différent) peut aller à une instance différente |

`sysctl -w net.ipv4.fib_multipath_hash_policy=1` s'applique aussitôt (dans un fichier de
`/etc/sysctl.d/` pour le garder au redémarrage). `ip route get <adresse> ipproto udp sport N dport
53` montre le prochain saut choisi pour un flux donné. Quand une instance disparaît ou revient, les
flux sont redistribués : des connexions TCP en cours peuvent changer d'instance et être coupées.
""")
            + info_subtitle(tr("Anycast entre domaines : BGP"), tag="bgp")
            + tr("""
Sur Internet, chaque site de l'opérateur du service annonce **le même préfixe** en BGP à ses
fournisseurs et à ses pairs. Les autres AS reçoivent plusieurs chemins vers ce préfixe et en
choisissent un avec le processus de décision de BGP (préférence locale, puis **chemin d'AS le plus
court**, origine, MED, eBGP plutôt qu'iBGP, coût IGP jusqu'au prochain saut…).

- **Un /24 au moins** : les opérateurs filtrent les préfixes IPv4 plus longs qu'un /24 (/48 en
  IPv6). On annonce donc un /24 dont l'adresse du service fait partie, et pas le /32 du service.
- **Une route pour `network`** : FRR n'annonce un préfixe déclaré par `network` que si une route
  identique existe dans sa table (`bgp network import-check`) ; sinon le préfixe apparaît sans `*`
  (non valide) dans `show bgp ipv4 unicast`. On crée une route sans issue :
  `ip route 198.51.100.0/24 blackhole`. L'adresse du service, posée sur `lo`, est plus précise et
  reste livrée localement ; les autres adresses du /24 partent à la poubelle.
- **Une politique explicite** : FRR applique la RFC 8212 (`bgp ebgp-requires-policy`) : sans
  route-map (ou prefix-list) en sortie vers un pair eBGP, il ne lui envoie rien ; sans politique
  en entrée, il n'accepte rien. `show bgp summary` affiche alors `(Policy)`. N'annoncez que le
  préfixe du service : une instance n'a pas à transporter le trafic des autres (elle n'est pas un
  AS de transit).
- **Le même AS d'origine** sur tous les sites (le cas le plus courant) : un site ne reçoit jamais
  la route d'un autre site, car tout routeur BGP rejette une route dont le chemin d'AS contient
  son propre AS (détection de boucle). Les sites ne peuvent donc pas se secourir par BGP ; ils
  utilisent leurs adresses unicast pour communiquer. Avec des AS d'origine différents, le préfixe
  a plusieurs origines (*MOAS*) : il faut alors une ROA RPKI pour chacune.
- Une instance qui n'a qu'un fournisseur n'a besoin d'aucune route : une route par défaut vers
  lui suffit ; elle refuse tout en entrée (`route-map DENY-ALL deny 10`).

« Le plus proche » devient « le chemin d'AS le plus court » : un client peut être servi par une
instance lointaine si elle est à moins d'AS que l'instance voisine.
""")
            + info_subtitle(tr("Ingénierie du trafic"), tag="te")
            + tr("""
L'opérateur influence le choix des autres AS par ce qu'il annonce, avec une route-map de sortie :

- **Allonger le chemin d'AS** (*AS-path prepending*) : `set as-path prepend 64500 64500 64500`
  répète son propre AS. Les AS qui ont un chemin plus court préfèrent l'autre site : on en fait
  un site de **secours**, qui ne reçoit le trafic que si les autres disparaissent. À longueur
  égale, d'autres critères départagent (origine, MED, router-id…) : un seul ajout ne suffit pas
  toujours. Un fournisseur qui donne une préférence locale plus forte aux routes de ses clients
  ignore le prepending ; beaucoup proposent des **communautés** pour la faire baisser.
- **Les communautés bien connues** (RFC 1997) : `no-export` (`65535:65281`) demande au voisin
  d'utiliser la route et de la diffuser dans son AS, mais de **ne l'annoncer à aucun pair eBGP** ;
  `no-advertise` interdit même de la diffuser. Les serveurs racine s'en servent pour leurs
  **nœuds locaux** : une instance installée chez un opérateur ou à un point d'échange, annoncée
  avec `no-export`, ne sert que cet opérateur et ses utilisateurs, tandis que les **nœuds
  globaux** sont annoncés à tout Internet.

```
route-map TO-ISP permit 10
 match ip address prefix-list ANYCAST
 set community no-export
 exit
```

FRR envoie les communautés à ses voisins sans réglage particulier. Une modification de route-map
est appliquée aux annonces au bout de quelques secondes (`bgp route-map delay-timer`, 5 s) ;
`clear bgp * soft out` force une nouvelle annonce. `show bgp ipv4 unicast PRÉFIXE` détaille chaque
chemin, avec ses communautés.
""")
            + info_subtitle(tr("FRR : rappels"), tag="frr")
            + tr("""
Les routeurs et les instances font tourner **FRRouting** ; on le configure avec `vtysh`
(`configure terminal`, les commandes, `end`, puis `write` pour enregistrer dans
`/etc/frr/frr.conf`). Une commande se supprime en la préfixant par `no`, et peut être passée depuis
le shell : `vtysh -c "show ip route"`. Les démons actifs sont dans `/etc/frr/daemons`.

OSPF sur une instance (l'adresse du service sur `lo`, l'adresse unicast `10.1.16.2` sur `eth0`) :

```
ip addr add 192.0.2.53/32 dev lo                 # shell
vtysh
configure terminal
 router ospf
  ospf router-id 10.1.16.2
  network 10.1.16.0/24 area 0
  network 192.0.2.53/32 area 0
  exit
 end
write
```

FRR refuse de mélanger les instructions `network` et `ip ospf area` (mode interface) dans un même
processus : choisissez l'une des deux formes.

BGP sur une instance (AS 64500, fournisseur `10.1.80.5` dans l'AS 65010) :

```
configure terminal
 ip route 198.51.100.0/24 blackhole
 ip prefix-list ANYCAST seq 10 permit 198.51.100.0/24
 route-map TO-ISP permit 10
  match ip address prefix-list ANYCAST
  exit
 route-map DENY-ALL deny 10
  exit
 router bgp 64500
  bgp router-id 10.1.80.6
  neighbor 10.1.80.5 remote-as 65010
  address-family ipv4 unicast
   network 198.51.100.0/24
   neighbor 10.1.80.5 route-map DENY-ALL in
   neighbor 10.1.80.5 route-map TO-ISP out
   exit-address-family
  exit
 end
write
```

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ip ospf neighbor` | les adjacences |
| `show ip ospf` | le router-id, ASBR ou non |
| `show ip ospf database router` / `external` | les LSA de routeur (liens *stub*) / de type 5 |
| `show ip ospf route` | les routes d'OSPF, leur coût et leur type |
| `show bgp summary` | les sessions BGP, les préfixes reçus et envoyés, `(Policy)` |
| `show bgp ipv4 unicast [PRÉFIXE]` | la table BGP, le détail des chemins d'un préfixe |
| `show bgp ipv4 unicast neighbors X advertised-routes` | ce qui est annoncé au voisin X |
| `show bfd peers` | les sessions BFD |
| `show ip route` | la table de zebra |

Documentation : [FRR — OSPF](https://docs.frrouting.org/en/latest/ospfd.html),
[BGP](https://docs.frrouting.org/en/latest/bgp.html), [BFD](https://docs.frrouting.org/en/latest/bfd.html).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `dig @ADRESSE id.server CH TXT +short` : quelle instance répond ;
- `ip route get ADRESSE`, `traceroute -n ADRESSE` : le prochain saut choisi, le chemin suivi ;
- `ip -br addr show dev lo` : les adresses de bouclage d'une instance ;
- `tcpdump -ni eth0 port 53` : les requêtes qui arrivent et l'adresse source des réponses ;
- `/var/log/frr/frr.log` : le journal de FRR ;
- `unbound-checkconf` : vérifie la configuration d'unbound ; les conteneurs n'ont pas de syslog :
  pour voir le journal d'unbound, arrêtez-le (`systemctl stop unbound`) et relancez-le au premier
  plan avec `unbound -dd -v` (`-dd` : journal sur la sortie d'erreur).

| symptôme | causes à vérifier |
|----------|-------------------|
| une route vers le service mais pas de réponse | service arrêté ou bloqué sur l'instance choisie (health check), instance parasite qui annonce l'adresse sans service, adresse du service absente de l'instance |
| `dig` sans réponse (`timed out`) alors que `tcpdump` voit passer la réponse | l'instance répond depuis son adresse unicast (serveur UDP sans `IP_PKTINFO`) |
| routes vers le service qui apparaissent et disparaissent | router-id dupliqué, health check qui interroge l'adresse du service |
| une instance n'attire aucun client | adresse mal saisie, réseau non annoncé, adjacence absente, métrique externe |
| préfixe BGP absent chez le fournisseur | `(Policy)` dans `show bgp summary`, préfixe non valide (`network` sans route), préfixe trop long filtré, session non établie |
""")
        )

    # -- FRR configurations -------------------------------------------------------------

    def ospf_router_lines(self, router: str, extra_networks: tuple = ()) -> List[str]:
        """OSPF of a router of an OSPF site: every network in area 0, router-id = loopback."""
        lines = ["router ospf", f"ospf router-id {self.lo(router)}"]
        lines += [f"network {self.net(n)} area 0" for n in ROUTER_IFACES[router]]
        lines += [f"network {self.lo(router)}/32 area 0"]
        lines += [f"network {x}/32 area 0" for x in extra_networks]
        return lines + ["exit"]

    def ospf_server_lines(self, server: str, router_id=None, announce=None) -> List[str]:
        """OSPF of an instance: its network in area 0 and, when *announce* is given, that /32."""
        lines = ["router ospf", f"ospf router-id {router_id or self.unicast(server)}",
                 f"network {self.net(server_net(server))} area 0"]
        if announce is not None:
            lines.append(f"network {announce}/32 area 0")
        return lines + ["exit"]

    def bgp_isp_lines(self, isp: str) -> List[str]:
        """BGP of an operator's router: peers with the other operators of its site (everything
        accepted and sent) and with the instance it connects (only ≤ /24 of 198.18.0.0/15 accepted)."""
        site, d = site_of(isp), self.data
        lines = [ISP_FILTER, "route-map FROM-ANYCAST permit 10", "match ip address prefix-list FROM-ANYCAST", "exit",
                 f"router bgp {ISP_AS[role_of(isp)]}", f"bgp router-id {self.lo(isp)}",
                 "no bgp ebgp-requires-policy", "bgp bestpath compare-routerid"]
        server = None
        for net in ROUTER_IFACES[isp]:
            if net not in LINKS:
                continue
            other = next(m for m in LINKS[net] if m != isp)
            if other in ISPS:
                lines.append(f"neighbor {self.addr(other, net)} remote-as {ISP_AS[role_of(other)]}")
            else:
                server = other
                lines += [f"neighbor {self.addr(other, net)} remote-as {d.asn}",
                          f"neighbor {self.addr(other, net)} description anycast-{other}"]
        lines.append("address-family ipv4 unicast")
        lines += [f"network {self.net(n)}" for n in ROUTER_IFACES[isp] if n in LANS]
        if server:
            lines.append(f"neighbor {self.unicast(server)} route-map FROM-ANYCAST in")
        return lines + ["exit-address-family", "exit"]

    def bgp_server_lines(self, server: str, network=None, prefix_list=None, prepend: int = 0,
                         community: str = None, out_policy: bool = True) -> List[str]:
        """BGP of an instance: announce *network* (default: the anycast /24) to its operator, refuse
        everything in."""
        d = self.data
        isp = isp_of(server)
        peer = self.addr(isp, server_net(server))
        network = network or self.prefix
        prefix_list = prefix_list or network
        rm = [f"ip prefix-list ANYCAST seq 10 permit {prefix_list}", "route-map TO-ISP permit 10",
              "match ip address prefix-list ANYCAST"]
        if prepend:
            rm.append("set as-path prepend " + " ".join([str(d.asn)] * prepend))
        if community:
            rm.append(f"set community {community}")
        lines = rm + ["exit", "route-map DENY-ALL deny 10", "exit",
                      f"router bgp {d.asn}", f"bgp router-id {self.unicast(server)}",
                      f"neighbor {peer} remote-as {ISP_AS[role_of(isp)]}",
                      "address-family ipv4 unicast", f"network {network}",
                      f"neighbor {peer} route-map DENY-ALL in"]
        if out_policy:
            lines.append(f"neighbor {peer} route-map TO-ISP out")
        return lines + ["exit-address-family", "exit"]

    def bfd_lines(self, machine: str, net: str) -> List[str]:
        return ["bfd", "profile fast", "receive-interval 100", "transmit-interval 100", "detect-multiplier 3",
                "exit", "exit", f"interface {iface(machine, net)}", "ip ospf bfd", "ip ospf bfd profile fast", "exit"]

    def _given_lines(self, m: str) -> List[str]:
        """The FRR configuration of *m* at start (``[]`` when the students write it all)."""
        site, d = site_of(m), self.data
        s = self.s_ospf
        if m in ISPS:
            return self.bgp_isp_lines(m)
        if site in OSPF_SITES and m in ROUTERS:
            if m == 'ofix_r2':
                return self.ospf_router_lines(m, extra_networks=(s,))
            lines = self.ospf_router_lines(m)
            if m == 'bfd_r1':
                lines += [f"interface {iface(m, 'bfd_lan1')}", f"ip ospf hello-interval {BFD_HELLO}",
                          f"ip ospf dead-interval {BFD_DEAD}", "exit",
                          f"interface {iface(m, 'bfd_lan2')}", f"ip ospf cost {BFD_BACKUP_COST}", "exit"]
            return lines
        if site == 'near':
            return []
        if site == 'prim':
            return self.ospf_server_lines(m)
        if site in ('hc', 'ecmp'):
            return self.ospf_server_lines(m, announce=s)
        if site == 'bfd':
            lines = self.ospf_server_lines(m, announce=s)
            if m == 'bfd_dns1':
                lines += ["interface eth0", f"ip ospf hello-interval {BFD_HELLO}",
                          f"ip ospf dead-interval {BFD_DEAD}", "exit"]
            return lines
        if site == 'ofix':
            return self.ospf_server_lines(m, router_id=s, announce=self.typo if m == 'ofix_dns1' else s)
        if site == 'te':
            return self.bgp_server_lines(m)
        if m == 'bfix_dns1':
            return self.bgp_server_lines(m, network=f"{self.s_bgp}/32", out_policy=False)
        if m == 'bfix_dns2':
            return self.bgp_server_lines(m)
        return []

    def static_lines(self, m: str) -> List[str]:
        """FRR static routes at start: the blackhole of the anycast /24 on the instances of the te site
        (bfix_dns2 lacks it: a fault)."""
        if site_of(m) == 'te' and m in SERVERS:
            return [f"ip route {self.prefix} blackhole"]
        return []

    def frr_daemons_of(self, m: str) -> tuple:
        site = site_of(m)
        if site in BGP_SITES:
            return ('bgpd',)
        if site == 'bfd':
            return ('ospfd', 'bfdd')
        return ('ospfd',)

    def _frr_conf(self, m: str) -> str:
        """Initial /etc/frr/frr.conf of *m*."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {m}", "log file /var/log/frr/frr.log", "!"]
        statics = self.static_lines(m)
        if statics:
            lines += statics + ["!"]
        for line in _block_lines(self._given_lines(m)):
            lines.append(line)
            if line == "exit":
                lines.append("!")
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step)

    # -- reference solutions: {machine: [(kind, payload)]}; kinds: sh, vtysh, exec, file ------

    def initial_service_address(self, server: str) -> Optional[IPv4Address]:
        """The address an instance has on lo at start."""
        site = site_of(server)
        if site == 'near' or server == 'bfix_dns2':
            return None
        if server == 'ofix_dns1':
            return self.typo
        return self.service(site)

    def solution_near(self) -> Dict[str, list]:
        s = self.s_ospf
        return {m: [('sh', f"ip addr add {s}/32 dev lo"), ('vtysh', self.ospf_server_lines(m, announce=s))]
                for m in ('near_dns1', 'near_dns2')}

    def solution_prim(self) -> Dict[str, list]:
        d, s = self.data, self.s_ospf
        result = {}
        for m, metric in (('prim_dns1', d.prim_metric1), ('prim_dns2', d.prim_metric2)):
            result[m] = [('vtysh', [f"ip prefix-list ANYCAST seq 10 permit {s}/32",
                                    "route-map ANYCAST permit 10", "match ip address prefix-list ANYCAST",
                                    f"set metric {metric}", "set metric-type type-2", "exit",
                                    "router ospf", "redistribute connected route-map ANYCAST", "exit"])]
        return result

    def health_script(self) -> str:
        s = self.s_ospf
        return f"""#!/bin/sh
# {HEALTH_SCRIPT} : n'annoncer l'adresse du service que tant qu'unbound répond
SERVICE={s}
while true; do
    if dig +time=1 +tries=1 @127.0.0.1 id.server CH TXT >/dev/null 2>&1; then
        ip -o addr show dev lo | grep -q " $SERVICE/32" || ip addr add $SERVICE/32 dev lo
    else
        ip addr del $SERVICE/32 dev lo 2>/dev/null
    fi
    sleep 1
done
"""

    @staticmethod
    def health_unit() -> str:
        return f"""[Unit]
Description=Anycast health check
After=unbound.service

[Service]
ExecStart={HEALTH_SCRIPT}
Restart=always

[Install]
WantedBy=multi-user.target
"""

    def solution_hc(self) -> Dict[str, list]:
        return {m: [('file', HEALTH_SCRIPT, self.health_script(), 0o755),
                    ('file', HEALTH_UNIT, self.health_unit(), 0o644),
                    ('sh', "systemctl daemon-reload; systemctl enable anycast-health; systemctl start anycast-health")]
                for m in ('hc_dns1', 'hc_dns2')}

    def solution_ofix(self) -> Dict[str, list]:
        s, typo = self.s_ospf, self.typo
        return {
            'ofix_dns1': [('sh', f"ip addr del {typo}/32 dev lo; ip addr add {s}/32 dev lo"),
                          ('vtysh', ["router ospf", f"ospf router-id {self.unicast('ofix_dns1')}",
                                     f"no network {typo}/32 area 0", f"network {s}/32 area 0", "exit"]),
                          ('exec', "clear ip ospf process")],
            'ofix_dns2': [('sh', "sed -i 's/^    interface: 0.0.0.0$/    interface: 0.0.0.0\\n    "
                                 "interface-automatic: yes/' /etc/unbound/unbound.conf; systemctl restart unbound"),
                          ('vtysh', ["router ospf", f"ospf router-id {self.unicast('ofix_dns2')}", "exit"]),
                          ('exec', "clear ip ospf process")],
            'ofix_r2': [('vtysh', ["router ospf", f"no network {s}/32 area 0", "exit"]),
                        ('sh', f"ip addr del {s}/32 dev lo")],
        }

    def solution_bgp(self) -> Dict[str, list]:
        return {m: [('vtysh', [f"ip route {self.prefix} blackhole"] + self.bgp_server_lines(m))]
                for m in ('bgp_dns1', 'bgp_dns2')}

    def solution_te(self) -> Dict[str, list]:
        d = self.data
        return {
            'te_dns2': [('vtysh', ["route-map TO-ISP permit 10",
                                   "set as-path prepend " + " ".join([str(d.asn)] * 3), "exit"])],
            'te_dns3': [('vtysh', ["route-map TO-ISP permit 10", "set community no-export", "exit"])],
        }

    def solution_bfix(self) -> Dict[str, list]:
        peer1 = self.addr('bfix_ispa', 'bfix_ld1')
        return {
            'bfix_dns1': [('vtysh', [f"ip route {self.prefix} blackhole",
                                     f"no ip prefix-list ANYCAST seq 10 permit {self.s_bgp}/32",
                                     f"ip prefix-list ANYCAST seq 10 permit {self.prefix}",
                                     f"router bgp {self.data.asn}", "address-family ipv4 unicast",
                                     f"no network {self.s_bgp}/32", f"network {self.prefix}",
                                     f"neighbor {peer1} route-map TO-ISP out", "exit-address-family", "exit"])],
            'bfix_dns2': [('vtysh', [f"ip route {self.prefix} blackhole"]),
                          ('sh', f"ip addr add {self.s_bgp}/32 dev lo")],
        }

    def solution_bfd(self) -> Dict[str, list]:
        return {'bfd_r1': [('vtysh', self.bfd_lines('bfd_r1', 'bfd_lan1'))],
                'bfd_dns1': [('vtysh', self.bfd_lines('bfd_dns1', 'bfd_lan1'))]}

    @staticmethod
    def solution_ecmp() -> Dict[str, list]:
        return {'ecmp_r1': [('sh', "sysctl -w net.ipv4.fib_multipath_hash_policy=1"),
                            ('file', "/etc/sysctl.d/90-ecmp.conf", "net.ipv4.fib_multipath_hash_policy = 1\n",
                             0o644)]}

    def _wait_ospf(self, sites: tuple, step: int = 2):
        """Register, on every router of *sites*, a wait until all its OSPF neighbours are Full
        (the routers of a site wait at the same time: the step lasts as long as the slowest)."""
        for r in ROUTERS:
            if site_of(r) not in sites:
                continue
            expected = len({m for net in ROUTER_IFACES[r] for m in ROUTER_IFACES if m != r and net in ROUTER_IFACES[m]})
            self.cmd(r, f"for i in $(seq {OSPF_CONVERGE_MAX}); do "
                        f"[ $(vtysh -c 'show ip ospf neighbor' | grep -c Full) -ge {expected} ] && break; sleep 1; done; "
                        f"sleep {OSPF_SETTLE}", step=step, timeout=OSPF_CONVERGE_MAX + OSPF_SETTLE + 15)

    def _apply(self, solution: Dict[str, list], step: int = 1):
        for m, items in solution.items():
            for item in items:
                kind = item[0]
                if kind == 'sh':
                    self.cmd(m, item[1], step=step)
                elif kind == 'vtysh':
                    self._vtysh(m, *item[1], step=step)
                elif kind == 'exec':
                    self.cmd(m, f'vtysh -c "{item[1]}"', step=step)
                elif kind == 'file':
                    self.file(m, item[1], item[2], permissions=item[3], step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTERS))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_by_site[site_of(m)])
        for r in ROUTERS:
            self.cmd(r, f"ip addr add {self.lo(r)}/32 dev lo")
        for srv in SERVERS:
            address = self.initial_service_address(srv)
            if address is not None:
                self.cmd(srv, f"ip addr add {address}/32 dev lo")
        # the stale copy of the service on a router of the ofix site (a fault)
        self.cmd('ofix_r2', f"ip addr add {self.s_ospf}/32 dev lo")
        for srv in SERVERS:
            self.file(srv, "/etc/default/unbound", UNBOUND_DEFAULTS, step=2)
            self.file(srv, "/etc/unbound/unbound.conf", unbound_conf(srv, automatic=(srv != 'ofix_dns2')), step=2)
            self.cmd(srv, "systemctl start unbound", step=2)
        for m in ROUTER_IFACES:
            self.file(m, "/etc/frr/daemons", _frr_daemons(self.frr_daemons_of(m)), permissions=0o640,
                      owner="frr:frr", step=2)
            self.file(m, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(m, "/etc/frr/frr.conf", self._frr_conf(m), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(m, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (instance la plus proche)"))
    def solve_near(self):
        self._apply(self.solution_near())
        self._wait_ospf(('near',))

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (principale et secours)"))
    def solve_prim(self):
        self._apply(self.solution_prim())
        self._wait_ospf(('prim',))

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (health check)"))
    def solve_hc(self):
        self._apply(self.solution_hc())
        self._wait_ospf(('hc',))

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (dépannage OSPF)"))
    def solve_ofix(self):
        self._apply(self.solution_ofix())
        self._wait_ospf(('ofix',))

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (BGP)"))
    def solve_bgp(self):
        self._apply(self.solution_bgp())
        self.cmd('bgp_ca', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (ingénierie du trafic)"))
    def solve_te(self):
        self._apply(self.solution_te())
        self.cmd('te_cb', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 7 : solution (dépannage BGP)"))
    def solve_bfix(self):
        self._apply(self.solution_bfix())
        self.cmd('bfix_ca', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Bonus : solution (BFD)"))
    def solve_bfd(self):
        self._apply(self.solution_bfd())
        self._wait_ospf(('bfd',))

    @sre_state(user_allowed=False, description=tr("Bonus : solution (ECMP par flux)"))
    def solve_ecmp(self):
        self._apply(self.solution_ecmp())
        self._wait_ospf(('ecmp',))

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns.  Form questions are filled through cheat_answers."""
        for solution in (self.solution_near(), self.solution_prim(), self.solution_hc(), self.solution_ofix(),
                         self.solution_bgp(), self.solution_te(), self.solution_bfix(), self.solution_bfd(),
                         self.solution_ecmp()):
            self._apply(solution)
        self._wait_ospf(OSPF_SITES)
        self.cmd('bgp_ca', f"sleep {BGP_WAIT}", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join((s or "").strip().lower().rstrip('.').split())


def _int(s):
    try:
        return int(_norm(s).replace(' ', ''))
    except ValueError:
        return None


def _solution_text(solution: Dict[str, list]) -> str:
    """The reference solution of a part, machine by machine: shell commands, vtysh sessions,
    files."""
    blocks = []
    for m, items in solution.items():
        parts = []
        for item in items:
            kind = item[0]
            if kind == 'sh':
                parts.append(f"```\n{item[1]}\n```")
            elif kind == 'exec':
                parts.append(f"```\nvtysh -c \"{item[1]}\"\n```")
            elif kind == 'vtysh':
                body = ["configure terminal"] + [" " + x for x in _block_lines(item[1])] + ["end", "write"]
                parts.append("```\n" + "\n".join(body) + "\n```")
            elif kind == 'file':
                parts.append(f"`{item[1]}` :\n\n```\n{item[2].rstrip()}\n```")
        blocks.append(f"`{m}` :\n\n" + "\n\n".join(parts))
    return "\n\n".join(blocks)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        addr, net, unicast, lo = ns.addr, ns.net, ns.unicast, ns.lo
        s_o, s_b, prefix = ns.s_ospf, ns.s_bgp, ns.prefix
        host_o, host_b = f"{s_o}/32", f"{s_b}/32"

        def gws(routes: Dict, prefix_text: str) -> List[str]:
            """The gateways of an OSPF kernel route."""
            return sorted(str(g) for g in kernel_route_gateways(routes, prefix_text))

        def ident(machine: str, server, step: int = 1) -> Optional[str]:
            return get_dns_identity(self, machine, server, step=step)

        # ---------------- diagnostics kept in the archive -------------------------
        for m in ROUTER_IFACES:
            if m not in ISPS:
                self.test(m, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        near_nb = {r: get_ospf_neighbors(self, r, allow_error=True) for r in ('near_r1', 'near_r3')}
        near_info = {m: get_ospf_info(self, m, allow_error=True) for m in ('near_dns1', 'near_dns2')}
        near_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('near_r1', 'near_r2', 'near_r3')}
        near_id = {r: ident(r, s_o) for r in ('near_r1', 'near_r2', 'near_r3')}

        prim_ext = get_ospf_external_lsas(self, 'prim_r2')
        prim_or = get_ospf_routes(self, 'prim_r2', allow_error=True)
        prim_k1 = get_kernel_routes(self, 'prim_r1', allow_error=True)
        prim_id = {r: ident(r, s_o) for r in ('prim_r1', 'prim_r2')}

        ofix_info = {m: get_ospf_info(self, m, allow_error=True) for m in ('ofix_dns1', 'ofix_dns2')}
        ofix_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('ofix_r1', 'ofix_r2', 'ofix_r3')}
        ofix_id = {r: ident(r, s_o) for r in ('ofix_r1', 'ofix_r3')}

        bgp_sum = {i: get_bgp_summary(self, i, allow_error=True) for i in ('bgp_ispa', 'bgp_ispb')}
        bgp_rt = {i: get_bgp_routes(self, i, allow_error=True) for i in ('bgp_ispa', 'bgp_ispb')}
        bgp_adv = {m: get_bgp_advertised_routes(self, m, addr(isp_of(m), server_net(m)), allow_error=True)
                   for m in ('bgp_dns1', 'bgp_dns2')}
        bgp_id = {c: ident(c, s_b) for c in ('bgp_ca', 'bgp_cb')}

        te_rt = {i: get_bgp_routes(self, i, allow_error=True) for i in ('te_ispa', 'te_ispb', 'te_ispc')}
        te_pfx_c = get_bgp_prefix(self, 'te_ispc', prefix, allow_error=True)
        te_id = {c: ident(c, s_b) for c in ('te_cb', 'te_cc')}

        bfix_rt = {i: get_bgp_routes(self, i, allow_error=True) for i in ('bfix_ispa', 'bfix_ispb')}
        bfix_id = {c: ident(c, s_b) for c in ('bfix_ca', 'bfix_cb')}

        bfd_peers = get_bfd_peers(self, 'bfd_r1')
        ecmp_policy, _code = self.test('ecmp_r1', "sysctl -n net.ipv4.fib_multipath_hash_policy", allow_error=True)
        ecmp_ids = get_dns_identities(self, 'ecmp_c1', s_o, count=ECMP_QUERIES)

        # ---------------- the dynamic tests (steps 2 to 7) ------------------------
        # step 1: undo what an interrupted evaluation may have left
        for m in ('hc_dns1', 'hc_dns2'):
            self.test(m, UNBOUND_RESTORE, allow_error=True)
        self.test('bfd_dns1', "tc qdisc del dev eth0 root 2>/dev/null; true", allow_error=True)
        # hc: unbound frozen on hc_dns1, then stopped on hc_dns2
        self.test('hc_dns1', f"pkill -STOP -x unbound; sleep {HC_DOWN_WAIT}", step=2, timeout=HC_DOWN_WAIT + 5,
                  allow_error=True)
        hc_k3 = get_kernel_routes(self, 'hc_r1', step=3, allow_error=True)
        hc_id3 = ident('hc_r1', s_o, step=3)
        self.test('hc_dns1', "pkill -CONT -x unbound", step=4, allow_error=True)
        self.test('hc_dns2', f"systemctl stop unbound; sleep {HC_UP_WAIT}", step=4, timeout=HC_UP_WAIT + 5,
                  allow_error=True)
        hc_k5 = {r: get_kernel_routes(self, r, step=5, allow_error=True) for r in ('hc_r1', 'hc_r2')}
        hc_id5 = {r: ident(r, s_o, step=5) for r in ('hc_r1', 'hc_r2')}
        self.test('hc_dns2', f"systemctl start unbound; sleep {HC_UP_WAIT}", step=6, timeout=HC_UP_WAIT + 5,
                  allow_error=True)
        hc_k7 = get_kernel_routes(self, 'hc_r2', step=7, allow_error=True)
        hc_id7 = ident('hc_r2', s_o, step=7)
        # bfd: bfd_dns1 silent 4 s while bfd_r1 pings the service every 50 ms
        self.test('bfd_dns1', f"sleep 1; tc qdisc add dev eth0 root netem loss 100%; sleep {BFD_CUT}; "
                              f"tc qdisc del dev eth0 root", step=2, timeout=BFD_CUT + 8, allow_error=True)
        bfd_sent, bfd_received = get_ping_series(self, 'bfd_r1', s_o, BFD_PINGS, BFD_INTERVAL, step=2)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('near', "1 — OSPF : l'instance la plus proche", "`near_r1` à `near_r3`, `near_dns1`, `near_dns2`"),
                 ('prim', "2 — OSPF : principale et secours", "`prim_r1`, `prim_r2`, `prim_dns1`, `prim_dns2`"),
                 ('hc', "3 — OSPF : health check", "`hc_r1`, `hc_r2`, `hc_dns1`, `hc_dns2`"),
                 ('ofix', "4 — OSPF : dépannage", "`ofix_r1` à `ofix_r3`, `ofix_dns1`, `ofix_dns2`"),
                 ('bgp', "5 — BGP : un préfixe, deux sites",
                  "`bgp_dns1`, `bgp_dns2`, les clients `bgp_ca`, `bgp_cb` ; `bgp_ispa`, `bgp_ispb` sans terminal"),
                 ('te', "6 — BGP : ingénierie du trafic",
                  "`te_dns1` à `te_dns3`, les clients `te_cb`, `te_cc` ; `te_ispa` à `te_ispc` sans terminal"),
                 ('bfix', "7 — BGP : dépannage",
                  "`bfix_dns1`, `bfix_dns2`, les clients `bfix_ca`, `bfix_cb` ; `bfix_ispa`, `bfix_ispb` sans terminal"),
                 ('bfd', "bonus — BFD", "`bfd_r1`, `bfd_dns1`, `bfd_dns2`"),
                 ('ecmp', "bonus — ECMP par flux", "`ecmp_r1`, `ecmp_dns1`, `ecmp_dns2`, le client `ecmp_c1`")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + LANS}
        for m, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                members[n].append(f"`{m}` eth{i} (`{addr(m, n)}`)")
        for h, (n, _gw) in HOSTS.items():
            members[n].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in list(LINKS) + LANS]
        rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                 + ", ".join(f"`{r}` `{lo(r)}`" for r in ROUTERS if site_of(r) == site) + " |"
                 for site in SITE_NUMBER if any(site_of(r) == site for r in ROUTERS)]
        addressing = "\n".join(rows)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente l'anycast, ses usages, son fonctionnement avec OSPF
puis avec BGP, le suivi de l'état du service, BFD, ECMP, et rappelle la configuration de FRR.

**Le réseau.** Il est fait de **neuf sites indépendants**, un par partie, chacun avec sa couleur
sur le schéma. Chaque site héberge son propre exemplaire du service : un service DNS (unbound)
installé sur plusieurs **instances** `*_dnsN`.

| partie | site | machines |
|--------|------|----------|
{site_rows}

- **Adresse du service** : `{s_o}` dans les sites OSPF (`near`, `prim`, `hc`, `ofix`, `bfd`,
  `ecmp`) ; préfixe anycast `{prefix}` et adresse `{s_b}` dans les sites BGP (`bgp`, `te`,
  `bfix`). Le nom `anycast` la désigne dans les fichiers `/etc/hosts`.
- Sur chaque instance, unbound répond à `dig @ADRESSE id.server CH TXT +short` par le nom de la
  machine (section @@ref:service@@).
- Les routeurs et les instances font tourner **FRRouting** (FRR) : configurez-les avec `vtysh`
  (section @@ref:frr@@). Les routeurs des sites OSPF sont configurés (aire 0, router-id = adresse
  de bouclage) ; les routeurs des opérateurs (`*_isp*`) n'ont pas de terminal.
- Toutes les adresses unicast sont en place ; chaque instance a une route par défaut vers son
  routeur.
- Les fichiers `/etc/hosts` contiennent les noms : `near_r2-eth1` désigne l'adresse de
  l'interface `eth1` de `near_r2`, `near_r2-lo` son adresse de bouclage.
- AS de l'opérateur du service : **{asn}** ; opérateurs A, B, C : AS 65010, 65020, 65030.

**Plan d'adressage.** Les liens entre deux machines sont des /30, les autres réseaux des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).

**Évaluation.** Chaque évaluation lit vos réponses, l'état d'OSPF, de BGP et de BFD, les tables de
routage, et interroge le service depuis les routeurs et les clients pour savoir quelle instance
répond. Elle **perturbe deux sites** pendant une vingtaine de secondes : elle fige puis arrête
unbound sur `hc_dns1` et `hc_dns2` (partie 3) et coupe `bfd_dns1` pendant {cut} s (bonus BFD) ; elle
remet tout en place ensuite.
""").format(site_rows=site_rows, addressing=addressing, s_o=s_o, s_b=s_b, prefix=prefix, asn=d.asn, cut=BFD_CUT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_near`, `solve_prim`, `solve_hc`, `solve_ofix`, `solve_bgp`,
`solve_te`, `solve_bfix`, `solve_bfd` et `solve_ecmp` (onglet *Appliquer une configuration*)
appliquent la solution d'une seule partie et remplissent ses formulaires. L'état `final` les
applique toutes et attend la convergence d'OSPF (toutes les adjacences `Full`, jusqu'à
{wait} s sur un projet qui vient de démarrer) : une évaluation lancée dès son retour donne tous les
points, bonus compris.

Les pannes du site `ofix` : `ospf router-id {s_o}` sur `ofix_dns1` et `ofix_dns2` ; unbound de
`ofix_dns2` sans `interface-automatic` ; `{s_o}/32` sur `lo` de `ofix_r2`, annoncée ; `{typo}` au
lieu de `{s_o}` sur `ofix_dns1`. Celles du site `bfix` : `bfix_dns1` sans route-map de sortie et
annonçant `{s_b}/32` ; `bfix_dns2` sans route `blackhole` pour `{prefix}` et sans `{s_b}` sur `lo`.
""").format(wait=OSPF_CONVERGE_MAX, s_o=s_o, typo=ns.typo, s_b=s_b, prefix=prefix)),
        )

        # =====================================================================
        # Part 1 — the nearest instance (near)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("near"), tr("Partie 1 — OSPF : l'instance la plus proche (site near)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Anycast dans OSPF : l'instance la plus proche"),
            description=tr("""
Les routeurs `near_r1`, `near_r2` et `near_r3` forment une ligne et font tourner OSPF (aire 0).
L'instance `near_dns1` est derrière `near_r1`, l'instance `near_dns2` derrière `near_r3`. Les deux
instances ont unbound, et FRR avec le démon `ospfd`, mais rien de configuré.

1. Sur `near_dns1` et `near_dns2` : posez l'adresse du service `{s}/32` sur `lo`, puis configurez
   OSPF (sections @@ref:ospf@@ et @@ref:frr@@) : **router-id = l'adresse unicast de l'instance**
   (section @@ref:router-id@@), son réseau et l'adresse du service dans l'aire 0.
2. Vérifiez les adjacences, puis, depuis chaque routeur, quelle instance répond
   (`dig @{s} id.server CH TXT +short`) et par quel chemin (`ip route get {s}`, `show ip ospf
   route`).
3. Regardez la route de `near_r2` vers `{s}` : combien de prochains sauts ? Lancez plusieurs fois
   `dig` depuis `near_r2` : est-ce toujours la même instance qui répond ?
""").format(s=s_o)
            + instructor(tr("""
**Solution.**

{solution}

`near_r1` est servi par `near_dns1`, `near_r3` par `near_dns2` ; `near_r2` est à égale distance
(coût {cost} : {dc} jusqu'au routeur voisin, {dc} jusqu'à l'instance, 0 pour une adresse de `lo`) et
sa route a deux prochains sauts. Ses propres requêtes partent toujours vers la même instance
(empreinte calculée sur les adresses : section @@ref:ecmp@@).

Évaluation : `near_adj` (2 : `near_dns1` et `near_dns2` voisins `Full` de leur routeur),
`near_rid` (2 : router-id = adresse unicast), `near_r1`, `near_r3` (3 chacun : route OSPF vers
l'instance voisine et réponse de cette instance), `near_ecmp` (4 : deux prochains sauts sur
`near_r2`), `near_r2` (2 : `near_r2` obtient une réponse).
""").format(solution=_solution_text(ns.solution_near()), cost=2 * DEFAULT_COST + LOOPBACK_STUB_COST,
            dc=DEFAULT_COST)),
        )
        cheat_near = {'cost': str(2 * DEFAULT_COST + LOOPBACK_STUB_COST), 'hops': '2', 'nearest': 'cost',
                      'rid': 'duplicate'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site near"),
            description=tr("""
- coût de la route de `near_r2` vers l'adresse du service (`show ip ospf route`) : @@{cost:[0-9]+}@@
- nombre de prochains sauts de cette route : @@{hops:[0-9]+}@@
- un routeur envoie les paquets destinés à l'adresse du service vers l'instance :
  @@{nearest:>la moins coûteuse au sens d'OSPF>>>cost|la plus proche géographiquement>>>geo|la première configurée>>>first|choisie au hasard pour chaque paquet>>>random}@@
- on fixe le router-id des instances parce que :
  @@{rid:>sinon FRR peut prendre l'adresse du service, la même sur toutes les instances>>>duplicate|le router-id doit être l'adresse annoncée>>>announced|OSPF ne démarre pas sans router-id>>>required|cela accélère la convergence>>>faster}@@
""")
            + instructor(tr("""
**Solution.** Coût **{cost}** ; **2** prochains sauts ; **la moins coûteuse au sens d'OSPF** ;
**sinon FRR peut prendre l'adresse du service** (la plus grande adresse de bouclage), la même sur
toutes les instances : router-id dupliqué.

Évaluation : `near_q_cost`, `near_q_hops` (1 chacun) et, pour l'enseignant seulement (choix dans une
liste), `near_q_nearest`, `near_q_rid` (1 chacun).
""").format(cost=2 * DEFAULT_COST + LOOPBACK_STUB_COST)),
            cheat_answers={"final": cheat_near, "solve_near": cheat_near},
        )
        near_adj = [neighbor_is_full(near_nb['near_r1'], address=unicast('near_dns1')),
                    neighbor_is_full(near_nb['near_r3'], address=unicast('near_dns2'))]
        self.add_grade_element(title=no_tr("near_adj"), max_grade=2, grade_part=part1, grade=sum(near_adj),
                               description=tr("adjacences des instances avec leur routeur"))
        self.add_grade_element(
            title=no_tr("near_rid"), max_grade=2, grade_part=part1,
            grade=sum(int(near_info[m].get('router_id') == str(unicast(m))) for m in ('near_dns1', 'near_dns2')),
            description=tr("router-id des instances = leur adresse unicast"),
        )
        self.add_grade_element(
            title=no_tr("near_r1"), max_grade=3, grade_part=part1,
            grade=3 * int(gws(near_k['near_r1'], host_o) == [str(unicast('near_dns1'))]
                          and near_id['near_r1'] == 'near_dns1'),
            description=tr("near_r1 servi par near_dns1"),
        )
        self.add_grade_element(
            title=no_tr("near_r3"), max_grade=3, grade_part=part1,
            grade=3 * int(gws(near_k['near_r3'], host_o) == [str(unicast('near_dns2'))]
                          and near_id['near_r3'] == 'near_dns2'),
            description=tr("near_r3 servi par near_dns2"),
        )
        self.add_grade_element(
            title=no_tr("near_ecmp"), max_grade=4, grade_part=part1,
            grade=4 * int(gws(near_k['near_r2'], host_o)
                          == sorted([str(addr('near_r1', 'near_l12')), str(addr('near_r3', 'near_l23'))])),
            description=tr("deux prochains sauts de near_r2 vers le service"),
        )
        self.add_grade_element(
            title=no_tr("near_r2"), max_grade=2, grade_part=part1,
            grade=2 * int(near_id['near_r2'] in ('near_dns1', 'near_dns2')),
            description=tr("near_r2 obtient une réponse"),
        )
        self.add_grade_element(title=no_tr("near_q_cost"), max_grade=1, grade_part=part1,
                               grade=int(_int(q1.get('cost')) == int(cheat_near['cost'])),
                               description=tr("coût de la route de near_r2"))
        self.add_grade_element(title=no_tr("near_q_hops"), max_grade=1, grade_part=part1,
                               grade=int(_int(q1.get('hops')) == 2), description=tr("nombre de prochains sauts"))
        self.add_grade_element(title=no_tr("near_q_nearest"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                               grade=int(_norm(q1.get('nearest')) == 'cost'),
                               description=tr("choix de l'instance"))
        self.add_grade_element(title=no_tr("near_q_rid"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                               grade=int(_norm(q1.get('rid')) == 'duplicate'), description=tr("rôle du router-id"))

        # =====================================================================
        # Part 2 — primary and backup instances (prim)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("prim"), tr("Partie 2 — OSPF : principale et secours (site prim)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Instance principale et instance de secours"),
            description=tr("""
Les routeurs `prim_r1` et `prim_r2` sont reliés ; l'instance `prim_dns1` est derrière `prim_r1`,
l'instance `prim_dns2` derrière `prim_r2`. Les instances font déjà tourner OSPF avec leur routeur
(router-id = leur adresse unicast) et portent l'adresse du service `{s}/32` sur `lo`, **sans
l'annoncer**.

On veut que **`prim_dns1` reçoive tout le trafic**, `prim_r2` compris, et que `prim_dns2` ne
serve que de secours. Faites annoncer l'adresse du service par chaque instance comme une **route
externe de type 2** (section @@ref:external@@) : métrique **{m1}** sur `prim_dns1`, **{m2}** sur
`prim_dns2`, et rien d'autre que `{s}/32`.

Vérifiez les LSA de type 5 (`show ip ospf database external`), la route de `prim_r2`
(`show ip ospf route`) et quelle instance répond à `prim_r2`.
""").format(s=s_o, m1=d.prim_metric1, m2=d.prim_metric2)
            + instructor(tr("""
**Solution.**

{solution}

`prim_r2` voit deux LSA de type 5 pour `{s}/32` ; en E2 seule la métrique externe compte : il
prend celle de `prim_dns1` ({m1} < {m2}), à {fwd} de coût (via `prim_r1`), bien que `prim_dns2` soit
plus proche. En E1, avec la même métrique sur les deux instances, il prendrait `prim_dns2`.

Évaluation : `prim_ext1`, `prim_ext2` (3 chacun : LSA de type 5 de l'instance, E2, bonne
métrique), `prim_only` (2 : aucune autre route externe), `prim_r2` (4 : route E2 de `prim_r2` par
`prim_r1` et réponse de `prim_dns1`), `prim_r1` (1 : `prim_r1` servi par `prim_dns1`).
""").format(solution=_solution_text(ns.solution_prim()), s=s_o, m1=d.prim_metric1, m2=d.prim_metric2,
            fwd=2 * DEFAULT_COST)),
        )
        cheat_prim = {'fwd': str(2 * DEFAULT_COST), 'e1': 'dns2', 'e2': 'external'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site prim"),
            description=tr("""
- coût de `prim_r2` jusqu'à l'ASBR `prim_dns1` (`show ip ospf route`, ligne `R`) : @@{fwd:[0-9]+}@@
- avec `metric-type 1` et la **même** métrique sur les deux instances, `prim_r2` serait servi par :
  @@{e1:>prim_dns2>>>dns2|prim_dns1>>>dns1|les deux (ECMP)>>>both|aucune>>>none}@@
- entre deux routes E2, OSPF compare :
  @@{e2:>la métrique externe seule (le coût jusqu'à l'ASBR départage les égalités)>>>external|la métrique externe plus le coût jusqu'à l'ASBR>>>sum|le coût jusqu'à l'ASBR seul>>>internal|le nombre de routeurs traversés>>>hops}@@
""")
            + instructor(tr("""
**Solution.** **{fwd}** ; **`prim_dns2`** (E1 : {dc} + métrique contre {fwd} + métrique) ; **la métrique
externe seule**.

Évaluation : `prim_q_fwd` (1) et, pour l'enseignant seulement, `prim_q_e1`, `prim_q_e2` (1 chacun).
""").format(fwd=2 * DEFAULT_COST, dc=DEFAULT_COST)),
            cheat_answers={"final": cheat_prim, "solve_prim": cheat_prim},
        )
        ext1 = prim_ext.get((host_o, str(unicast('prim_dns1')))) or {}
        ext2 = prim_ext.get((host_o, str(unicast('prim_dns2')))) or {}
        server_ids = {str(unicast('prim_dns1')), str(unicast('prim_dns2'))}
        self.add_grade_element(
            title=no_tr("prim_ext1"), max_grade=3, grade_part=part2,
            grade=3 * int(ext1.get('metric_type') == 2 and ext1.get('metric') == d.prim_metric1),
            description=tr("route externe E2 de prim_dns1"),
        )
        self.add_grade_element(
            title=no_tr("prim_ext2"), max_grade=3, grade_part=part2,
            grade=3 * int(ext2.get('metric_type') == 2 and ext2.get('metric') == d.prim_metric2),
            description=tr("route externe E2 de prim_dns2"),
        )
        self.add_grade_element(
            title=no_tr("prim_only"), max_grade=2, grade_part=part2,
            grade=2 * int(bool(ext1) and bool(ext2)
                          and all(p == host_o for (p, adv) in prim_ext if adv in server_ids)),
            description=tr("seule l'adresse du service est redistribuée"),
        )
        r2_route = prim_or.get(host_o) or {}
        self.add_grade_element(
            title=no_tr("prim_r2"), max_grade=4, grade_part=part2,
            grade=4 * int(r2_route.get('type') == 'E2'
                          and [g for g, _i in r2_route.get('nexthops', [])] == [str(addr('prim_r1', 'prim_l12'))]
                          and prim_id['prim_r2'] == 'prim_dns1'),
            description=tr("prim_r2 servi par prim_dns1"),
        )
        self.add_grade_element(
            title=no_tr("prim_r1"), max_grade=1, grade_part=part2,
            grade=int(gws(prim_k1, host_o) == [str(unicast('prim_dns1'))] and prim_id['prim_r1'] == 'prim_dns1'),
            description=tr("prim_r1 servi par prim_dns1"),
        )
        self.add_grade_element(title=no_tr("prim_q_fwd"), max_grade=1, grade_part=part2,
                               grade=int(_int(q2.get('fwd')) == 2 * DEFAULT_COST),
                               description=tr("coût jusqu'à l'ASBR"))
        self.add_grade_element(title=no_tr("prim_q_e1"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                               grade=int(_norm(q2.get('e1')) == 'dns2'), description=tr("effet d'E1"))
        self.add_grade_element(title=no_tr("prim_q_e2"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                               grade=int(_norm(q2.get('e2')) == 'external'), description=tr("comparaison des E2"))

        # =====================================================================
        # Part 3 — health check (hc)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("hc"), tr("Partie 3 — OSPF : health check (site hc)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Suivre l'état du service"),
            description=tr("""
Les routeurs `hc_r1` et `hc_r2` sont reliés ; l'instance `hc_dns1` est derrière `hc_r1`,
l'instance `hc_dns2` derrière `hc_r2`. Tout est configuré : chaque instance annonce `{s}/32` (sur
`lo`) dans OSPF, `hc_r1` est servi par `hc_dns1` et `hc_r2` par `hc_dns2`.

1. **Le trou noir.** Arrêtez unbound sur `hc_dns1` (`systemctl stop unbound`) : que répond le
   service à `hc_r1` ? Que devient sa route vers `{s}` ? Redémarrez unbound.
2. **Le health check.** Sur `hc_dns1` **et** `hc_dns2`, écrivez le script `{script}` qui,
   **toutes les secondes**, interroge unbound sur l'instance elle-même et retire `{s}/32` de `lo`
   quand il ne répond plus, puis la remet quand il répond de nouveau (section @@ref:health@@). Il
   ne doit pas redémarrer unbound. Faites-le tourner en permanence (service systemd
   `anycast-health`).
3. Recommencez l'expérience du 1 et suivez la bascule depuis `hc_r1` (`ip route get {s}`, `dig`).

**Ce que fait l'évaluation.** Elle **fige** unbound sur `hc_dns1` (`kill -STOP` : le processus
existe mais ne répond plus), attend {down} s, vérifie que `hc_r1` est servi par `hc_dns2`, débloque
unbound puis l'**arrête** sur `hc_dns2`, attend {up} s, vérifie que `hc_r1` est de nouveau servi par
`hc_dns1` et que `hc_r2` l'est aussi, redémarre unbound sur `hc_dns2`, attend {up} s et vérifie que
`hc_r2` est de nouveau servi par `hc_dns2`.
""").format(s=s_o, script=HEALTH_SCRIPT, down=HC_DOWN_WAIT, up=HC_UP_WAIT)
            + instructor(tr("""
**Solution.** Sur les deux instances :

{solution}

Unbound arrêté : `hc_r1` garde sa route vers `hc_dns1`, qui annonce toujours l'adresse, et ne
reçoit plus de réponse (trou noir). Avec le health check, l'adresse disparaît de `lo`, ospfd
retire le lien de sa LSA de routeur, et `hc_r1` passe par `hc_r2` vers `hc_dns2` en 2 à 3 s.

Évaluation : `hc_withdraw1` (3 : `hc_r1` passe par `hc_r2` quand unbound est figé sur `hc_dns1`),
`hc_failover1` (2 : `hc_r1` servi alors par `hc_dns2`), `hc_return1` (2 : retour vers `hc_dns1`
une fois débloqué), `hc_withdraw2` (3 : `hc_r2` passe par `hc_r1` quand unbound est arrêté sur
`hc_dns2`), `hc_failover2` (2), `hc_return2` (2) ; les retours ne comptent qu'après la bascule
correspondante.
""").format(solution=_solution_text({'hc_dns1': ns.solution_hc()['hc_dns1']}))),
        )
        cheat_hc = {'anycast': 'flapping', 'frozen': 'query', 'lsa': '5'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Le health check"),
            description=tr("""
- le script ne doit pas interroger l'adresse du service parce que :
  @@{anycast:>une fois l'adresse retirée, la requête atteint une autre instance qui répond : le script remet l'adresse et l'annonce oscille>>>flapping|unbound n'écoute pas sur cette adresse>>>listen|la requête serait refusée par access-control>>>refused|ce serait plus lent>>>slow}@@
- un unbound figé (processus présent qui ne répond plus) est détecté par :
  @@{frozen:>une vraie requête DNS avec un délai d'attente>>>query|systemctl is-active unbound>>>active|pidof unbound>>>pidof|ss -lun>>>ss}@@
- délai minimal (en secondes) entre deux émissions d'une même LSA par OSPF : @@{lsa:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** L'annonce oscillerait ; **une vraie requête DNS** ; **5** s (*MinLSInterval*).

Évaluation : `hc_q_lsa` (1) et, pour l'enseignant seulement, `hc_q_anycast`, `hc_q_frozen` (1 chacun).
""")),
            cheat_answers={"final": cheat_hc, "solve_hc": cheat_hc},
        )
        via_r2 = [str(addr('hc_r2', 'hc_l12'))]
        via_r1 = [str(addr('hc_r1', 'hc_l12'))]
        withdraw1 = gws(hc_k3, host_o) == via_r2
        withdraw2 = gws(hc_k5['hc_r2'], host_o) == via_r1
        self.add_grade_element(title=no_tr("hc_withdraw1"), max_grade=3, grade_part=part3, grade=3 * int(withdraw1),
                               description=tr("annonce retirée par hc_dns1 (unbound figé)"))
        self.add_grade_element(title=no_tr("hc_failover1"), max_grade=2, grade_part=part3,
                               grade=2 * int(hc_id3 == 'hc_dns2'), description=tr("hc_r1 servi par hc_dns2"))
        self.add_grade_element(
            title=no_tr("hc_return1"), max_grade=2, grade_part=part3,
            grade=2 * int(withdraw1 and gws(hc_k5['hc_r1'], host_o) == [str(unicast('hc_dns1'))]
                          and hc_id5['hc_r1'] == 'hc_dns1'),
            description=tr("retour vers hc_dns1"),
        )
        self.add_grade_element(title=no_tr("hc_withdraw2"), max_grade=3, grade_part=part3, grade=3 * int(withdraw2),
                               description=tr("annonce retirée par hc_dns2 (unbound arrêté)"))
        self.add_grade_element(title=no_tr("hc_failover2"), max_grade=2, grade_part=part3,
                               grade=2 * int(hc_id5['hc_r2'] == 'hc_dns1'), description=tr("hc_r2 servi par hc_dns1"))
        self.add_grade_element(
            title=no_tr("hc_return2"), max_grade=2, grade_part=part3,
            grade=2 * int(withdraw2 and gws(hc_k7, host_o) == [str(unicast('hc_dns2'))] and hc_id7 == 'hc_dns2'),
            description=tr("retour vers hc_dns2"),
        )
        self.add_grade_element(title=no_tr("hc_q_lsa"), max_grade=1, grade_part=part3,
                               grade=int(_int(q3.get('lsa')) == 5), description=tr("MinLSInterval"))
        self.add_grade_element(title=no_tr("hc_q_anycast"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                               grade=int(_norm(q3.get('anycast')) == 'flapping'),
                               description=tr("pourquoi ne pas interroger l'adresse du service"))
        self.add_grade_element(title=no_tr("hc_q_frozen"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                               grade=int(_norm(q3.get('frozen')) == 'query'),
                               description=tr("détection d'un processus figé"))

        # =====================================================================
        # Part 4 — OSPF troubleshooting (ofix)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("ofix"), tr("Partie 4 — OSPF : dépannage (site ofix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Dépannage d'un service anycast dans OSPF"),
            description=tr("""
Le site `ofix` reprend le plan du site `near` : les routeurs `ofix_r1`, `ofix_r2` et `ofix_r3` en
ligne, l'instance `ofix_dns1` derrière `ofix_r1`, l'instance `ofix_dns2` derrière `ofix_r3`, qui
annoncent toutes deux `{s}/32` dans OSPF. Le résultat attendu : `ofix_r1` servi par `ofix_dns1`,
`ofix_r3` par `ofix_dns2`, et `ofix_r2` avec une route à deux prochains sauts vers les deux
instances.

Ce site a été livré avec **quatre pannes**. Trouvez-les et corrigez-les sans changer le plan
(section @@ref:diagnostic@@) : interrogez le service depuis chaque routeur, lisez les routes
(`show ip ospf route`, `show ip ospf database router`), les adresses de `lo`, les router-id, la
configuration d'unbound, les paquets (`tcpdump`) et le journal `/var/log/frr/frr.log`.
""").format(s=s_o)
            + instructor(tr("""
**Solution.**

{solution}

Les pannes : router-id `{s}` (l'adresse du service) sur les deux instances, qui écrasent sans fin
leurs LSA de routeur ; unbound de `ofix_dns2` sans `interface-automatic` (ses réponses partent de
son adresse unicast : `dig` depuis `ofix_r3` finit en `timed out`, `tcpdump` montre la réponse) ;
une copie de `{s}/32` sur `lo` de `ofix_r2`, annoncée (une
instance sans service : `ofix_r2` et ses voisins la choisissent) ; `{typo}` au lieu de `{s}` sur
`ofix_dns1`.

Évaluation : `ofix_rid` (4 : 2 par instance, router-id = adresse unicast), `ofix_address` (3 :
`ofix_dns1` parmi les prochains sauts de `ofix_r1`), `ofix_r1` (2 : `ofix_r1` servi par `ofix_dns1`
seule), `ofix_source` (4 : `ofix_r3` servi par `ofix_dns2`), `ofix_rogue` (3 : `ofix_r2` n'est plus une
instance, route à deux prochains sauts).
""").format(solution=_solution_text(ns.solution_ofix()), s=s_o, typo=ns.typo)),
        )
        cheat_ofix = {'flap': 'rid', 'missing': 'address', 'r3': 'source', 'r2': 'rogue'}
        causes = ("router-id dupliqué>>>rid|adresse du service mal saisie>>>address|réponses envoyées depuis "
                  "l'adresse unicast>>>source|instance parasite sans service>>>rogue|aires OSPF différentes>>>area|"
                  "MTU différentes>>>mtu")
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Les causes des pannes"),
            description=tr("""
- cause des routes vers le service qui changent sans cesse : @@{{flap:>{causes}}}@@
- cause de l'absence de `ofix_dns1` parmi les instances : @@{{missing:>{causes}}}@@
- une fois `ofix_r3` routé vers `ofix_dns2`, cause de ses requêtes sans réponse alors que `tcpdump`
  montre les réponses : @@{{r3:>{causes}}}@@
- cause des requêtes sans réponse depuis `ofix_r2` : @@{{r2:>{causes}}}@@
""").format(causes=causes)
            + instructor(tr("""
**Solution.** Router-id dupliqué ; adresse du service mal saisie ; réponses envoyées depuis
l'adresse unicast ; instance parasite sans service.

Évaluation, pour l'enseignant seulement : `ofix_q_flap`, `ofix_q_missing`, `ofix_q_r3`, `ofix_q_r2` (1
chacun).
""")),
            cheat_answers={"final": cheat_ofix, "solve_ofix": cheat_ofix},
        )
        self.add_grade_element(
            title=no_tr("ofix_rid"), max_grade=4, grade_part=part4,
            grade=2 * sum(int(ofix_info[m].get('router_id') == str(unicast(m))) for m in ('ofix_dns1', 'ofix_dns2')),
            description=tr("router-id des instances"),
        )
        r1_gws = gws(ofix_k['ofix_r1'], host_o)
        self.add_grade_element(
            title=no_tr("ofix_address"), max_grade=3, grade_part=part4,
            grade=3 * int(str(unicast('ofix_dns1')) in r1_gws), description=tr("ofix_dns1 annonce l'adresse du service"),
        )
        self.add_grade_element(
            title=no_tr("ofix_r1"), max_grade=2, grade_part=part4,
            grade=2 * int(r1_gws == [str(unicast('ofix_dns1'))] and ofix_id['ofix_r1'] == 'ofix_dns1'),
            description=tr("ofix_r1 servi par ofix_dns1"),
        )
        self.add_grade_element(
            title=no_tr("ofix_source"), max_grade=4, grade_part=part4,
            grade=4 * int(ofix_id['ofix_r3'] == 'ofix_dns2'), description=tr("ofix_r3 servi par ofix_dns2"),
        )
        self.add_grade_element(
            title=no_tr("ofix_rogue"), max_grade=3, grade_part=part4,
            grade=3 * int(gws(ofix_k['ofix_r2'], host_o)
                          == sorted([str(addr('ofix_r1', 'ofix_l12')), str(addr('ofix_r3', 'ofix_l23'))])),
            description=tr("ofix_r2 n'est plus une instance"),
        )
        for key, title_key, text in (('flap', 'ofix_q_flap', tr("cause des routes instables")),
                                     ('missing', 'ofix_q_missing', tr("cause de l'absence de ofix_dns1")),
                                     ('r3', 'ofix_q_r3', tr("cause de l'échec depuis ofix_r3")),
                                     ('r2', 'ofix_q_r2', tr("cause de l'échec depuis ofix_r2"))):
            self.add_grade_element(title=no_tr(title_key), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                                   grade=int(_norm(q4.get(key)) == cheat_ofix[key]), description=text)

        # =====================================================================
        # Part 5 — BGP: one prefix from two sites (bgp)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("bgp"), tr("Partie 5 — BGP : un préfixe, deux sites (site bgp)"))
        peer_a, peer_b = addr('bgp_ispa', 'bgp_ld1'), addr('bgp_ispb', 'bgp_ld2')
        self.question_dummy(
            section=self.section(0),
            title=tr("Anycast entre domaines : BGP"),
            description=tr("""
Deux opérateurs sont reliés : A (AS 65010, routeur `bgp_ispa`, client `bgp_ca`) et B (AS 65020,
routeur `bgp_ispb`, client `bgp_cb`). L'opérateur du service (AS **{asn}**) a une instance chez
chacun : `bgp_dns1` reliée à `bgp_ispa` ({peer_a}), `bgp_dns2` reliée à `bgp_ispb` ({peer_b}).
Chaque instance porte `{s}/32` sur `lo` et a une route par défaut vers son opérateur. Les
opérateurs sont configurés pour une session BGP avec l'instance qu'ils relient, et n'acceptent de
l'AS {asn} que des préfixes de longueur **24 au plus**.

Sur `bgp_dns1` et `bgp_dns2` (section @@ref:bgp@@) : annoncez le préfixe anycast **`{prefix}`**
(et lui seul) à l'opérateur en BGP, avec la route `blackhole` dont `network` a besoin, une
route-map de sortie, et une route-map d'entrée qui refuse tout. Vérifiez ensuite quelle instance
répond à `bgp_ca` et à `bgp_cb` (`dig @{s} id.server CH TXT +short`).
""").format(asn=d.asn, peer_a=peer_a, peer_b=peer_b, s=s_b, prefix=prefix)
            + instructor(tr("""
**Solution.**

{solution}

Chaque opérateur reçoit deux chemins pour `{prefix}` : `{asn}` (son instance, le plus court) et
`650x0 {asn}` (par l'autre opérateur). `bgp_ca` est servi par `bgp_dns1`, `bgp_cb` par `bgp_dns2`.

Évaluation : `bgp_sessions` (2 : session de chaque instance établie), `bgp_ispa`, `bgp_ispb` (3
chacun : meilleur chemin de l'opérateur = son instance), `bgp_second` (2 : chaque opérateur a aussi
le chemin par l'autre), `bgp_only` (2 : les instances n'annoncent que `{prefix}`), `bgp_ca`, `bgp_cb`
(3 chacun : réponse de l'instance voisine).
""").format(solution=_solution_text(ns.solution_bgp()), prefix=prefix, asn=d.asn)),
        )
        cheat_bgp = {'aspath': f"65020 {d.asn}", 'length': 'filter', 'loop': 'loop'}
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site bgp"),
            description=tr("""
- chemin d'AS du **second** chemin de l'opérateur A vers le préfixe anycast (celui qui passe par
  B ; les AS séparés par des espaces) : @@{aspath:[0-9 ]+}@@
- on annonce un /24 plutôt que le /32 du service parce que :
  @@{length:>les opérateurs filtrent les préfixes plus longs qu'un /24>>>filter|BGP ne sait pas annoncer un /32>>>cannot|cela économise des adresses>>>save|BGP agrège tout seul les /32>>>aggregate}@@
- même sans filtre en entrée, `bgp_dns1` n'apprendrait jamais la route annoncée par `bgp_dns2`
  parce que :
  @@{loop:>son propre AS figure dans le chemin d'AS : détection de boucle>>>loop|l'opérateur A la filtre>>>isp|ebgp-requires-policy l'en empêche>>>policy|les deux instances ont le même router-id>>>rid}@@
""")
            + instructor(tr("""
**Solution.** **`65020 {asn}`** ; les opérateurs filtrent les préfixes plus longs qu'un /24 ;
détection de boucle (l'AS {asn} est dans le chemin).

Évaluation : `bgp_q_aspath` (1) et, pour l'enseignant seulement, `bgp_q_length`, `bgp_q_loop` (1
chacun).
""").format(asn=d.asn)),
            cheat_answers={"final": cheat_bgp, "solve_bgp": cheat_bgp},
        )
        sessions = [bool(((bgp_sum['bgp_ispa'].get('peers') or {}).get(str(unicast('bgp_dns1'))) or {})
                         .get('established')),
                    bool(((bgp_sum['bgp_ispb'].get('peers') or {}).get(str(unicast('bgp_dns2'))) or {})
                         .get('established'))]
        self.add_grade_element(title=no_tr("bgp_sessions"), max_grade=2, grade_part=part5, grade=sum(sessions),
                               description=tr("sessions BGP des instances établies"))
        best_a = bgp_best_path(bgp_rt['bgp_ispa'], prefix)
        best_b = bgp_best_path(bgp_rt['bgp_ispb'], prefix)
        self.add_grade_element(
            title=no_tr("bgp_ispa"), max_grade=3, grade_part=part5,
            grade=3 * int(best_a.get('as_list') == [d.asn] and best_a.get('peer') == str(unicast('bgp_dns1'))),
            description=tr("l'opérateur A passe par bgp_dns1"),
        )
        self.add_grade_element(
            title=no_tr("bgp_ispb"), max_grade=3, grade_part=part5,
            grade=3 * int(best_b.get('as_list') == [d.asn] and best_b.get('peer') == str(unicast('bgp_dns2'))),
            description=tr("l'opérateur B passe par bgp_dns2"),
        )
        second = [any(p['as_list'] == [65020, d.asn] and p['valid'] for p in bgp_paths(bgp_rt['bgp_ispa'], prefix)),
                  any(p['as_list'] == [65010, d.asn] and p['valid'] for p in bgp_paths(bgp_rt['bgp_ispb'], prefix))]
        self.add_grade_element(title=no_tr("bgp_second"), max_grade=2, grade_part=part5, grade=2 * int(all(second)),
                               description=tr("chaque opérateur connaît aussi l'autre instance"))
        self.add_grade_element(
            title=no_tr("bgp_only"), max_grade=2, grade_part=part5,
            grade=2 * int(all(set(bgp_adv[m]) == {str(prefix)} for m in ('bgp_dns1', 'bgp_dns2'))),
            description=tr("seul le préfixe anycast est annoncé"),
        )
        self.add_grade_element(title=no_tr("bgp_ca"), max_grade=3, grade_part=part5,
                               grade=3 * int(bgp_id['bgp_ca'] == 'bgp_dns1'), description=tr("bgp_ca servi par bgp_dns1"))
        self.add_grade_element(title=no_tr("bgp_cb"), max_grade=3, grade_part=part5,
                               grade=3 * int(bgp_id['bgp_cb'] == 'bgp_dns2'), description=tr("bgp_cb servi par bgp_dns2"))
        self.add_grade_element(title=no_tr("bgp_q_aspath"), max_grade=1, grade_part=part5,
                               grade=int(_norm(q5.get('aspath')) == cheat_bgp['aspath']),
                               description=tr("chemin d'AS du second chemin"))
        self.add_grade_element(title=no_tr("bgp_q_length"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(_norm(q5.get('length')) == 'filter'), description=tr("pourquoi un /24"))
        self.add_grade_element(title=no_tr("bgp_q_loop"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(_norm(q5.get('loop')) == 'loop'), description=tr("détection de boucle"))

        # =====================================================================
        # Part 6 — BGP traffic engineering (te)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("te"), tr("Partie 6 — BGP : ingénierie du trafic (site te)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Site de secours et nœud local"),
            description=tr("""
Trois opérateurs sont reliés deux à deux : A (AS 65010, `te_ispa`), B (AS 65020, `te_ispb`, client
`te_cb`) et C (AS 65030, `te_ispc`, client `te_cc`). L'opérateur du service (AS {asn}) a une
instance chez chacun : `te_dns1` chez A, `te_dns2` chez B, `te_dns3` chez C. Les trois annoncent
déjà `{prefix}` de la même façon (route-map de sortie `TO-ISP`) : `te_cb` est servi par
`te_dns2`, et la route de `te_dns3` se propage chez A et B.

On veut que (section @@ref:te@@) :

1. `te_dns2` soit un site de **secours** : ajoutez **trois fois** l'AS {asn} au chemin d'AS de ses
   annonces. `te_cb` doit alors être servi par `te_dns1`, et B garder le chemin par `te_dns2`.
2. `te_dns3` soit un **nœud local** de C : ses annonces portent la communauté `no-export`. C et ses
   clients l'utilisent, mais A et B ne doivent plus apprendre de chemin par C.

Les routeurs des opérateurs n'ont pas de terminal : observez depuis les clients (`dig`,
`traceroute -n {s}`) et sur les instances (`show bgp ipv4 unicast neighbors X advertised-routes`).
""").format(asn=d.asn, prefix=prefix, s=s_b)
            + instructor(tr("""
**Solution.**

{solution}

B reçoit `{asn} {asn} {asn} {asn}` de `te_dns2` (quatre AS) contre `65010 {asn}` par A : il passe par A.
C n'annonce plus la route de `te_dns3` (marquée `no-export`) à A ni à B, mais l'utilise lui-même :
`te_cc` est servi par `te_dns3`. Sans le `no-export`, B aurait deux chemins de deux AS (par A et
par C) départagés par le router-id.

Évaluation : `te_prepend` (3 : B garde le chemin de `te_dns2`, avec au moins trois répétitions de
l'AS), `te_cb` (4 : meilleur chemin de B par A et `te_cb` servi par `te_dns1`), `te_noexport` (3 : la
route de `te_dns3` porte `no-export` chez C), `te_contained` (3 : ni A ni B n'a de chemin par C),
`te_cc` (3 : `te_cc` servi par `te_dns3`, avec `no-export`).
""").format(solution=_solution_text(ns.solution_te()), asn=d.asn)),
        )
        cheat_te = {'aspath': " ".join([str(d.asn)] * 4), 'noexport': 'local', 'tie': 'tie'}
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site te"),
            description=tr("""
- chemin d'AS de la route que `te_ispb` reçoit de `te_dns2` (lisez les annonces de `te_dns2`) :
  @@{aspath:[0-9 ]+}@@
- un opérateur qui reçoit une route marquée `no-export` :
  @@{noexport:>l'utilise et la diffuse dans son AS, mais ne l'annonce à aucun pair eBGP>>>local|la rejette>>>reject|ne l'annonce qu'à ses clients>>>customers|l'annonce avec une préférence basse>>>lowpref}@@
- un seul ajout de l'AS ne suffit pas toujours à faire de `te_dns2` un secours parce que :
  @@{tie:>à longueur de chemin égale, d'autres critères départagent et peuvent garder te_dns2>>>tie|un prepend unique est ignoré>>>ignored|il faut répéter un autre AS que le sien>>>other|il faut un prepend par opérateur>>>each}@@
""")
            + instructor(tr("""
**Solution.** **`{aspath}`** ; elle est utilisée et diffusée dans l'AS mais annoncée à aucun pair
eBGP ; à longueur égale, d'autres critères départagent.

Évaluation : `te_q_aspath` (1) et, pour l'enseignant seulement, `te_q_noexport`, `te_q_tie` (1
chacun).
""").format(aspath=cheat_te['aspath'])),
            cheat_answers={"final": cheat_te, "solve_te": cheat_te},
        )
        dns2_paths = bgp_paths(te_rt['te_ispb'], prefix, peer=str(unicast('te_dns2')))
        prepended = any(len(p['as_list']) >= 4 and set(p['as_list']) == {d.asn} for p in dns2_paths)
        self.add_grade_element(title=no_tr("te_prepend"), max_grade=3, grade_part=part6, grade=3 * int(prepended),
                               description=tr("te_dns2 annonce un chemin allongé"))
        best_tb = bgp_best_path(te_rt['te_ispb'], prefix)
        self.add_grade_element(
            title=no_tr("te_cb"), max_grade=4, grade_part=part6,
            grade=4 * int(prepended and best_tb.get('as_list') == [65010, d.asn] and te_id['te_cb'] == 'te_dns1'),
            description=tr("te_cb servi par te_dns1"),
        )
        dns3_paths = [p for p in te_pfx_c['paths'] if p.get('peer') == str(unicast('te_dns3'))]
        noexport = any(any(c.replace('-', '').replace('_', '').lower() in ('noexport', '65535:65281')
                           for c in p.get('communities', [])) for p in dns3_paths)
        self.add_grade_element(title=no_tr("te_noexport"), max_grade=3, grade_part=part6, grade=3 * int(noexport),
                               description=tr("te_dns3 marque ses annonces no-export"))
        leaked = any(p['as_list'][:1] == [65030] for i in ('te_ispa', 'te_ispb')
                     for p in bgp_paths(te_rt[i], prefix))
        self.add_grade_element(title=no_tr("te_contained"), max_grade=3, grade_part=part6,
                               grade=3 * int(bool(dns3_paths) and not leaked),
                               description=tr("ni A ni B n'apprend de chemin par C"))
        self.add_grade_element(title=no_tr("te_cc"), max_grade=3, grade_part=part6,
                               grade=3 * int(noexport and te_id['te_cc'] == 'te_dns3'),
                               description=tr("te_cc servi par te_dns3"))
        self.add_grade_element(title=no_tr("te_q_aspath"), max_grade=1, grade_part=part6,
                               grade=int(_norm(q6.get('aspath')) == cheat_te['aspath']),
                               description=tr("chemin d'AS allongé"))
        self.add_grade_element(title=no_tr("te_q_noexport"), max_grade=1, grade_part=part6, scope=CHOICE_SCOPE,
                               grade=int(_norm(q6.get('noexport')) == 'local'), description=tr("rôle de no-export"))
        self.add_grade_element(title=no_tr("te_q_tie"), max_grade=1, grade_part=part6, scope=CHOICE_SCOPE,
                               grade=int(_norm(q6.get('tie')) == 'tie'), description=tr("limite du prepending"))

        # =====================================================================
        # Part 7 — BGP troubleshooting (bfix)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("bfix"), tr("Partie 7 — BGP : dépannage (site bfix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Dépannage d'un service anycast en BGP"),
            description=tr("""
Le site `bfix` reprend le plan du site `bgp` : les opérateurs A (`bfix_ispa`, client `bfix_ca`) et
B (`bfix_ispb`, client `bfix_cb`), l'instance `bfix_dns1` chez A, l'instance `bfix_dns2` chez B,
qui devraient annoncer toutes deux `{prefix}` (AS {asn}) pour servir l'adresse `{s}`. Le résultat
attendu : `bfix_ca` servi par `bfix_dns1`, `bfix_cb` par `bfix_dns2`. Les opérateurs n'acceptent
de l'AS {asn} que des préfixes de longueur 24 au plus.

Ce site a été livré avec **quatre pannes**, deux sur chaque instance. Trouvez-les et corrigez-les
(section @@ref:diagnostic@@) : `show bgp summary`, `show bgp ipv4 unicast`, `show bgp ipv4 unicast
neighbors X advertised-routes`, `show running-config`, les adresses de `lo`, et `dig` depuis les
clients.
""").format(prefix=prefix, asn=d.asn, s=s_b)
            + instructor(tr("""
**Solution.**

{solution}

Les pannes : `bfix_dns1` n'a pas de route-map de sortie (`(Policy)` : rien n'est envoyé) et annonce
`{s}/32` (filtré par l'opérateur) au lieu de `{prefix}` ; `bfix_dns2` déclare `network {prefix}` sans
route correspondante (préfixe non valide : rien n'est annoncé) et n'a pas `{s}` sur `lo` (les
requêtes partent dans la route `blackhole`).

Évaluation : `bfix_ispa`, `bfix_ispb` (4 chacun : meilleur chemin de l'opérateur = son instance),
`bfix_ca`, `bfix_cb` (3 chacun : réponse de l'instance voisine).
""").format(solution=_solution_text(ns.solution_bfix()), s=s_b, prefix=prefix)),
        )
        cheat_bfix = {'d1send': 'policy', 'd1isp': 'long', 'd2send': 'importcheck', 'd2answer': 'noaddr'}
        bcauses = ("pas de politique de sortie (ebgp-requires-policy)>>>policy|préfixe trop long, filtré par "
                   "l'opérateur>>>long|network sans route correspondante>>>importcheck|adresse du service absente de "
                   "l'instance>>>noaddr|mauvais numéro d'AS du voisin>>>asn|session non établie>>>session")
        q7 = self.question_form(
            section=self.section(1),
            title=tr("Les causes des pannes"),
            description=tr("""
- cause de l'absence de toute annonce de `bfix_dns1` : @@{{d1send:>{causes}}}@@
- une fois les annonces rétablies, cause du rejet de l'annonce de `bfix_dns1` par l'opérateur A :
  @@{{d1isp:>{causes}}}@@
- cause de l'absence d'annonce de `bfix_dns2`, dont la session est pourtant établie :
  @@{{d2send:>{causes}}}@@
- une fois l'annonce rétablie, cause des requêtes de `bfix_cb` restées sans réponse :
  @@{{d2answer:>{causes}}}@@
""").format(causes=bcauses)
            + instructor(tr("""
**Solution.** Pas de politique de sortie ; préfixe trop long ; `network` sans route
correspondante ; adresse du service absente de l'instance.

Évaluation, pour l'enseignant seulement : `bfix_q_d1send`, `bfix_q_d1isp`, `bfix_q_d2send`,
`bfix_q_d2answer` (1 chacun).
""")),
            cheat_answers={"final": cheat_bfix, "solve_bfix": cheat_bfix},
        )
        best_fa = bgp_best_path(bfix_rt['bfix_ispa'], prefix)
        best_fb = bgp_best_path(bfix_rt['bfix_ispb'], prefix)
        self.add_grade_element(
            title=no_tr("bfix_ispa"), max_grade=4, grade_part=part7,
            grade=4 * int(best_fa.get('as_list') == [d.asn] and best_fa.get('peer') == str(unicast('bfix_dns1'))),
            description=tr("l'opérateur A passe par bfix_dns1"),
        )
        self.add_grade_element(
            title=no_tr("bfix_ispb"), max_grade=4, grade_part=part7,
            grade=4 * int(best_fb.get('as_list') == [d.asn] and best_fb.get('peer') == str(unicast('bfix_dns2'))),
            description=tr("l'opérateur B passe par bfix_dns2"),
        )
        self.add_grade_element(title=no_tr("bfix_ca"), max_grade=3, grade_part=part7,
                               grade=3 * int(bfix_id['bfix_ca'] == 'bfix_dns1'),
                               description=tr("bfix_ca servi par bfix_dns1"))
        self.add_grade_element(title=no_tr("bfix_cb"), max_grade=3, grade_part=part7,
                               grade=3 * int(bfix_id['bfix_cb'] == 'bfix_dns2'),
                               description=tr("bfix_cb servi par bfix_dns2"))
        for key, text in (('d1send', tr("cause du silence de bfix_dns1")),
                          ('d1isp', tr("cause du rejet par l'opérateur A")),
                          ('d2send', tr("cause du silence de bfix_dns2")),
                          ('d2answer', tr("cause des requêtes sans réponse"))):
            self.add_grade_element(title=no_tr(f"bfix_q_{key}"), max_grade=1, grade_part=part7, scope=CHOICE_SCOPE,
                                   grade=int(_norm(q7.get(key)) == cheat_bfix[key]), description=text)

        # =====================================================================
        # Bonus — BFD (bfd)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("bfd"), tr("Bonus — BFD (site bfd)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Panne silencieuse d'une instance : BFD (bonus)"),
            description=tr("""
Le routeur `bfd_r1` relie deux instances qui annoncent `{s}/32` dans OSPF : `bfd_dns1` (coût 10) et
`bfd_dns2` (coût {cost} sur l'interface de `bfd_r1`, une instance de secours). Entre `bfd_r1` et
`bfd_dns1`, les temporisateurs OSPF sont de {hello} s (hello) et {dead} s (dead).

**Ce que fait l'évaluation.** Pendant que `bfd_r1` envoie un `ping` vers `{s}` toutes les 50 ms
pendant 6 s, `bfd_dns1` devient muet pendant {cut} s (plus rien ne sort de son interface : une panne
silencieuse, que `bfd_r1` ne peut pas voir sur son interface). Sans BFD, `bfd_r1` attend la fin du
*dead interval* et perd tous les paquets de la coupure.

Configurez BFD entre `bfd_r1` et `bfd_dns1` (démon `bfdd` déjà activé), avec des intervalles de
**100 ms** et un multiplicateur de **3**, et associez-le à OSPF des deux côtés (section
@@ref:bfd@@). Reproduisez la coupure vous-même pour mesurer la différence :
`tc qdisc add dev eth0 root netem loss 100%` sur `bfd_dns1`, puis `tc qdisc del dev eth0 root`.
""").format(s=s_o, cost=BFD_BACKUP_COST, hello=BFD_HELLO, dead=BFD_DEAD, cut=BFD_CUT)
            + instructor(tr("""
**Solution.**

{solution}

Avec BFD, `bfd_r1` déclare `bfd_dns1` mort en 300 ms, OSPF abandonne l'adjacence et la route passe
par `bfd_dns2` : quelques paquets perdus au lieu de {lost} environ.

Évaluation (bonus) : `bfd_session` (2 : session BFD de `bfd_r1` avec `bfd_dns1` active, détection en
{det} ms au plus), `bfd_failover` (4 : au plus {maxlost} pings perdus sur {pings} pendant la coupure).
""").format(solution=_solution_text(ns.solution_bfd()), lost=int(BFD_CUT / BFD_INTERVAL), det=BFD_MAX_DETECTION,
            maxlost=BFD_MAX_LOST, pings=BFD_PINGS)),
        )
        peer = bfd_peers.get(str(unicast('bfd_dns1'))) or {}
        detection = bfd_detection_time(peer)
        self.add_grade_element(
            title=no_tr("bfd_session"), max_grade=2, grade_part=part8, bonus=True,
            grade=2 * int(bool(peer.get('up')) and detection is not None and detection <= BFD_MAX_DETECTION),
            description=tr("session BFD rapide entre bfd_r1 et bfd_dns1"),
        )
        self.add_grade_element(
            title=no_tr("bfd_failover"), max_grade=4, grade_part=part8, bonus=True,
            grade=4 * int(bfd_sent == BFD_PINGS and bfd_received is not None
                          and bfd_sent - bfd_received <= BFD_MAX_LOST),
            description=tr("bascule rapide pendant la coupure"),
        )

        # =====================================================================
        # Bonus — per-flow ECMP (ecmp)
        # =====================================================================
        part9 = self.add_grade_part(no_tr("ecmp"), tr("Bonus — ECMP par flux (site ecmp)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Répartir les flux d'un client (bonus)"),
            description=tr("""
Le routeur `ecmp_r1` relie deux instances à égale distance, `ecmp_dns1` et `ecmp_dns2`, qui
annoncent `{s}/32` dans OSPF, et le client `ecmp_c1`. La route de `ecmp_r1` vers `{s}` a deux
prochains sauts, mais toutes les requêtes de `ecmp_c1` sont servies par la même instance :
vérifiez-le en lançant plusieurs fois `dig @{s} id.server CH TXT +short` depuis `ecmp_c1`.

Faites en sorte que `ecmp_r1` répartisse **chaque flux** (adresses, protocole et ports) entre les
deux instances (section @@ref:ecmp@@) : les requêtes successives de `ecmp_c1`, qui partent chacune
d'un port source différent, doivent être servies tantôt par l'une, tantôt par l'autre.
""").format(s=s_o)
            + instructor(tr("""
**Solution.**

{solution}

Évaluation (bonus) : `ecmp_policy` (2 : `net.ipv4.fib_multipath_hash_policy` = 1 sur `ecmp_r1`),
`ecmp_spread` (4 : {n} requêtes de `ecmp_c1` servies par les deux instances).
""").format(solution=_solution_text(ns.solution_ecmp()), n=ECMP_QUERIES)),
        )
        self.add_grade_element(title=no_tr("ecmp_policy"), max_grade=2, grade_part=part9, bonus=True,
                               grade=2 * int((ecmp_policy or '').strip() == '1'),
                               description=tr("empreinte ECMP calculée sur les ports"))
        self.add_grade_element(title=no_tr("ecmp_spread"), max_grade=4, grade_part=part9, bonus=True,
                               grade=4 * int({'ecmp_dns1', 'ecmp_dns2'} <= set(ecmp_ids)),
                               description=tr("les requêtes de ecmp_c1 servies par les deux instances"))


_TRANSLATIONS = {}
