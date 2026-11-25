"""IS-IS lab with FRR (isisd, bfdd): IPv6 and multi-topology, segment routing, BFD.

Three independent sites, one per part, and a bonus site (completing a part gives all its points
whatever the others):

- ``mt``: a square of four dual-stack routers with IPv4 IS-IS given; the link ``mt_l14`` carries
  IPv4 only.  The students add IPv6 to IS-IS (single topology: the IPv6 traffic loops between
  ``mt_r1`` and ``mt_r2``), then the IPv6 multi-topology;
- ``sr``: a line of four routers with IS-IS given and MPLS enabled in the kernels; the students
  enable SR-MPLS in IS-IS (SRGB, one router with its own, prefix-SIDs, ``no-php-flag``);
- ``bfd``: a square whose preferred link ``bfd_r1`` – ``bfd_r2`` crosses a bridge of the operator
  (``bfd_sw``, no terminal); the students configure BFD on that link and fast IS-IS hellos on
  another one.  Each evaluation cuts the bridge for a few seconds and measures the outage;
- ``tl`` (bonus): a square with IS-IS and SR given; TI-LFA on ``tl_r1``.

The MPLS modules of the host are loaded by the kernel itself when ``initial`` asks a container for
an ``encap mpls`` route (module autoload, as in the MPLS labs).  Grading reads the running
configurations, the json of vtysh (lib/frr.py), the kernel tables (lib/mpls.py) and real traffic.
The states ``solve_<part>`` apply the reference solution of one part, ``final`` all of them.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv6networks
from net_config import NetConfigEntry, remount_proc_sys, set_ip_forward, set_ipv6_forward, set_net_config_entry
from ping import eval_ping
from frr import (
    bfd_profile_value, get_bfd_peers, get_frr_routes, get_frr_running_config, get_isis_interfaces,
    get_isis_neighbors, get_kernel_routes, is_isis_protocol, isis_adjacency_up, isis_srgb, isis_system_id_from_ipv4,
    parse_frr_config,
)
from mpls import (
    get_kernel_mpls_routes, get_mpls_counters, mpls_counter_delta, mpls_route_is_pop, mpls_route_is_swap,
    trigger_mpls_modules_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("IS-IS : IPv6 multi-topologie, segment routing et BFD",
           en="IS-IS: IPv6 multi-topology, segment routing and BFD")
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

ISIS_NAME = "CORE"

# Router interfaces in ethN order: the network of each.  ``bfd_l12`` is one IP link made of two
# collision domains joined by the bridge bfd_sw (see COLLISION_DOMAINS).
ROUTER_IFACES = {
    'mt_r1': ['mt_lan1', 'mt_l12', 'mt_l14'],
    'mt_r2': ['mt_l12', 'mt_l23'],
    'mt_r3': ['mt_l23', 'mt_l34'],
    'mt_r4': ['mt_lan4', 'mt_l34', 'mt_l14'],
    'sr_r1': ['sr_l12'],
    'sr_r2': ['sr_l12', 'sr_l23'],
    'sr_r3': ['sr_l23', 'sr_l34'],
    'sr_r4': ['sr_l34'],
    'bfd_r1': ['bfd_lan1', 'bfd_l12', 'bfd_l13'],
    'bfd_r2': ['bfd_l12', 'bfd_l24'],
    'bfd_r3': ['bfd_l13', 'bfd_l34'],
    'bfd_r4': ['bfd_lan4', 'bfd_l24', 'bfd_l34'],
    'tl_r1': ['tl_l12', 'tl_l14'],
    'tl_r2': ['tl_l12', 'tl_l23'],
    'tl_r3': ['tl_l23', 'tl_l34'],
    'tl_r4': ['tl_l34', 'tl_l14'],
}
HOSTS = {
    'mt_h1': ('mt_lan1', 'mt_r1'),
    'mt_h4': ('mt_lan4', 'mt_r4'),
    'bfd_h1': ('bfd_lan1', 'bfd_r1'),
    'bfd_h4': ('bfd_lan4', 'bfd_r4'),
}
BRIDGE = 'bfd_sw'
# the collision domain of an interface when it is not named after its IP network
COLLISION_DOMAINS = {('bfd_r1', 'bfd_l12'): 'bfd_l1s', ('bfd_r2', 'bfd_l12'): 'bfd_ls2'}
LINKS = {
    'mt_l12': ('mt_r1', 'mt_r2'), 'mt_l23': ('mt_r2', 'mt_r3'), 'mt_l34': ('mt_r3', 'mt_r4'),
    'mt_l14': ('mt_r1', 'mt_r4'),
    'sr_l12': ('sr_r1', 'sr_r2'), 'sr_l23': ('sr_r2', 'sr_r3'), 'sr_l34': ('sr_r3', 'sr_r4'),
    'bfd_l12': ('bfd_r1', 'bfd_r2'), 'bfd_l13': ('bfd_r1', 'bfd_r3'), 'bfd_l24': ('bfd_r2', 'bfd_r4'),
    'bfd_l34': ('bfd_r3', 'bfd_r4'),
    'tl_l12': ('tl_r1', 'tl_r2'), 'tl_l23': ('tl_r2', 'tl_r3'), 'tl_l34': ('tl_r3', 'tl_r4'),
    'tl_l14': ('tl_r1', 'tl_r4'),
}
LANS = ['mt_lan1', 'mt_lan4', 'bfd_lan1', 'bfd_lan4']
# the networks of the mt site that carry IPv6 (mt_l14 is IPv4 only)
MT_IPV6_NETS = ['mt_lan1', 'mt_lan4', 'mt_l12', 'mt_l23', 'mt_l34']
MT_IPV4_ONLY = 'mt_l14'
# routers configured by the lab, without terminal
OPERATORS = ('tl_r2', 'tl_r3', 'tl_r4', BRIDGE)
MPLS_ROUTERS = [r for r in ROUTER_IFACES if r.startswith(('sr_', 'tl_'))]
BFD_ROUTERS = [r for r in ROUTER_IFACES if r.startswith('bfd_')]


def collision_domain(machine: str, net: str) -> str:
    return COLLISION_DOMAINS.get((machine, net), net)


_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(collision_domain(_r, _n), {})[_r] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
_TOPOLOGY['bfd_l1s'][BRIDGE] = 0
_TOPOLOGY['bfd_ls2'][BRIDGE] = 1
MACHINES = list(ROUTER_IFACES) + list(HOSTS) + [BRIDGE]

SITE_COLORS = {'mt': 'lightblue', 'sr': 'khaki', 'bfd': 'palegreen', 'tl': 'plum'}

# ---------------------------------------------------------------------------
# addressing: one /16 of 10.0.0.0/8 per instance (site s: third octets 16s to 16s + 15, as in the
# IS-IS lab) and, for the mt site, one /48 of fd00::/8 (one /64 per network, loopbacks in the 16th)
# ---------------------------------------------------------------------------

SITE_NUMBER = {'mt': 1, 'sr': 2, 'bfd': 3, 'tl': 4}
LOOPBACK_OCTET = 15

MT_L34_METRIC = 20               # makes the IPv4-only link mt_l14 the shortest way from mt_r2 to mt_r4
BFD_BACKUP_METRIC = 30           # the way through bfd_r3 is the backup of the bfd site
PLATFORM_LABELS = 100000         # given label space (net.mpls.platform_labels) of the sr and tl sites
SRGB_SIZE = 8000
SR_SRGB_BASES = (17000, 18000, 19000, 20000, 21000)
SR_R3_SRGB_BASES = (30000, 40000, 50000)
TL_SRGB_BASE = 16000             # FRR's default SRGB (the given SR of the tl site)
TL_METRICS = {'tl_l12': 10, 'tl_l23': 10, 'tl_l34': 15, 'tl_l14': 10}
BFD_INTERVALS = (100, 150, 200, 250)    # ms (FRR's default, 300, is not shown in the configuration)
BFD_MULTIPLIERS = (3, 4, 5)
BFD_PROFILE = "FAST"
# the failover measure of each evaluation: h1 pings h4 every PING_INTERVAL s while the bridge drops
# everything during CUT_SECONDS; the outage must stay under MAX_OUTAGE s
CUT_SECONDS = 6
PING_INTERVAL = 0.05
PING_COUNT = int((CUT_SECONDS + 2) / PING_INTERVAL)
MAX_OUTAGE = 3.0
CUT_TABLE = "table bridge cut { chain c { type filter hook forward priority 0; policy drop; }; }"
UNCUT_CMD = "nft delete table bridge cut 2>/dev/null; true"
# the reference states wait for the LSPs (FRR regenerates an LSP at most every 30 s) and BFD
CONVERGE_WAIT = 35
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE
# Creation-time sysctls of the dual-stack machines: EUI-64 link-local addresses whatever the host's
SYSCTLS = ('net.ipv6.conf.default.addr_gen_mode=0', 'net.ipv6.conf.default.use_tempaddr=0',
           'net.ipv6.conf.all.use_tempaddr=0')

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : isisd{bfd} activé
# (zebra, mgmtd, staticd et watchfrr démarrent toujours)
bgpd=no
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=yes
pimd=no
pim6d=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd={bfdd}
fabricd=no
vrrpd=no
pathd=no

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


def iface(router: str, net: str) -> str:
    """Name of the interface of *router* on *net* (``eth1``)."""
    return f"eth{ROUTER_IFACES[router].index(net)}"


def router_number(router: str) -> int:
    return int(router.rsplit('_r', 1)[1])


def link_ifaces(router: str) -> List[str]:
    """The interfaces of *router* on point-to-point links."""
    return [f"eth{i}" for i, net in enumerate(ROUTER_IFACES[router]) if net in LINKS]


def frr_daemons(router: str) -> str:
    bfd = router in BFD_ROUTERS
    return FRR_DAEMONS.format(bfd=" et bfdd" if bfd else "", bfdd='yes' if bfd else 'no')


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


def _subnet6(block: IPv6Network, index: int) -> IPv6Network:
    return IPv6Network((int(block.network_address) + (index << 64), 64))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    mt_area: str = ""
    sr_area: str = ""
    sr_srgb: int = 0           # part 2: SRGB base of sr_r1, sr_r2, sr_r4
    sr_srgb_r3: int = 0        # part 2: SRGB base of sr_r3
    sr_index1: int = 0         # part 2: prefix-SID indexes of the loopbacks
    sr_index2: int = 0
    sr_index3: int = 0
    sr_index4: int = 0
    bfd_area: str = ""
    bfd_interval: int = 0      # part 3: BFD receive / transmit interval (ms)
    bfd_multiplier: int = 0    # part 3: BFD detect multiplier
    tl_area: str = ""

    @classmethod
    def generate(cls):
        data = cls()
        # never 49.0001, the area of the course's examples
        data.mt_area, data.sr_area, data.bfd_area, data.tl_area = [f"49.{n:04d}" for n in random.sample(range(2, 10000), 4)]
        data.sr_srgb = random.choice(SR_SRGB_BASES)
        data.sr_srgb_r3 = random.choice(SR_R3_SRGB_BASES)
        data.sr_index1, data.sr_index2, data.sr_index3, data.sr_index4 = random.sample(range(1, 100), 4)
        data.bfd_interval = random.choice(BFD_INTERVALS)
        data.bfd_multiplier = random.choice(BFD_MULTIPLIERS)

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
            router = next(r for r, nets in ROUTER_IFACES.items() if net in nets)
            setattr(data.ips, f"{router}_{net}", IPv4Interface((int(network.network_address) + 1, 24)))
        for host, (net, _gw) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, host, IPv4Interface((int(network.network_address) + random.randint(10, 250), 24)))
        for router in ROUTER_IFACES:
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo",
                    IPv4Interface((int(block.network_address) + router_number(router), 32)))

        # IPv6 of the mt site
        data.nets6.instance = random_ipv6networks(48, from_private_network=True)[0]
        for k, net in enumerate(MT_IPV6_NETS):
            setattr(data.nets6, net, _subnet6(data.nets6.instance, k + 1))
        data.nets6.mt_lo = _subnet6(data.nets6.instance, 0xff)
        for net in MT_IPV6_NETS:
            network = getattr(data.nets6, net)
            members = [r for r, nets in ROUTER_IFACES.items() if net in nets]
            if net in LINKS:
                members = list(LINKS[net])
            for k, router in enumerate(members):
                setattr(data.ips6, f"{router}_{net}", IPv6Interface((int(network.network_address) + 1 + k, 64)))
        for host in ('mt_h1', 'mt_h4'):
            network = getattr(data.nets6, HOSTS[host][0])
            setattr(data.ips6, host, IPv6Interface((int(network.network_address) + random.randint(0x10, 0xfff), 64)))
        for router in ('mt_r1', 'mt_r2', 'mt_r3', 'mt_r4'):
            setattr(data.ips6, f"{router}_lo",
                    IPv6Interface((int(data.nets6.mt_lo.network_address) + router_number(router), 128)))
        return data

    def sr_index(self, router: str) -> int:
        return getattr(self, f"sr_index{router_number(router)}")

    def sr_base(self, router: str) -> int:
        return self.sr_srgb_r3 if router == 'sr_r3' else self.sr_srgb


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("netdev13")
        spec['shape'] = 'box'
    if machine in OPERATORS:
        spec['allow_connection'] = False
    if site_of(machine) == 'mt':
        spec['ipv6'] = True
        spec['sysctls'] = SYSCTLS
    return spec


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in MACHINES}
    _network_specs = {}
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data

        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, nets in ROUTER_IFACES.items():
            entries = []
            for net in nets:
                addresses = [getattr(d.ips, f"{r}_{net}")]
                if net in MT_IPV6_NETS:
                    addresses.append(getattr(d.ips6, f"{r}_{net}"))
                entries.append((addresses, []))
            self.net_config[r] = entries
        for h, (net, gw) in HOSTS.items():
            addresses, routes = [getattr(d.ips, h)], [(IPv4Network("0.0.0.0/0"), self.addr(gw, net))]
            if site_of(h) == 'mt':
                addresses.append(getattr(d.ips6, h))
                routes.append((IPv6Network("::/0"), self.addr6(gw, net)))
            self.net_config[h] = [(addresses, routes)]

        lines = []
        for r, nets in ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{self.addr(r, net)}\t{names}")
                if net in MT_IPV6_NETS:
                    lines.append(f"{self.addr6(r, net)}\t{names}")
            lines.append(f"{self.lo(r)}\t{r}-lo")
            if site_of(r) == 'mt':
                lines.append(f"{self.lo6(r)}\t{r}-lo")
        for h in HOSTS:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
            if site_of(h) == 'mt':
                lines.append(f"{getattr(d.ips6, h).ip}\t{h}")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses and names -------------------------------------------------------

    def addr(self, machine: str, net: str) -> IPv4Address:
        return getattr(self.data.ips, f"{machine}_{net}").ip

    def addr6(self, machine: str, net: str) -> IPv6Address:
        return getattr(self.data.ips6, f"{machine}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def lo6(self, router: str) -> IPv6Address:
        return getattr(self.data.ips6, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def net6(self, name: str) -> IPv6Network:
        return getattr(self.data.nets6, name)

    def sysid(self, router: str) -> str:
        return isis_system_id_from_ipv4(self.lo(router))

    def area_of(self, router: str) -> str:
        return getattr(self.data, f"{site_of(router)}_area")

    def net_title(self, router: str) -> str:
        return f"{self.area_of(router)}.{self.sysid(router)}.00"

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Rappels sur IS-IS"), tag="reminder")
            + tr("""
IS-IS est un protocole de routage à état de liens : chaque routeur (*IS*) décrit ses voisins et ses
préfixes dans des **LSP** inondées à tout le domaine, et calcule ses routes avec l'algorithme SPF.
Il est transporté directement dans les trames Ethernet (pas dans IP) et ses PDU sont des listes de
**TLV** : une fonction nouvelle est un TLV de plus. Un routeur est identifié par son **NET**, par
exemple `49.0001.0100.0003.1002.00` : l'aire `49.0001`, le **system-id** `0100.0003.1002`, le
sélecteur `00`. Dans ce TP, tous les routeurs sont au niveau 2 d'une seule aire par site et les liens
entre routeurs sont point à point (`isis network point-to-point`).

```
router isis CORE
 net 49.0001.0100.0003.1002.00
 is-type level-2-only
interface eth1
 ip router isis CORE
 isis network point-to-point
```

| commande | ce qu'elle montre |
|----------|-------------------|
| `show isis neighbor [detail]` | les adjacences (avec l'état BFD dans `detail`) |
| `show isis interface [detail]` | les interfaces : métrique, temporisateurs |
| `show isis database [detail]` | les LSP et leur contenu (TLV) |
| `show isis route` | les routes IPv4 et IPv6 calculées par IS-IS |
| `show isis topology` | les arbres des plus courts chemins, par famille |
| `show ip route`, `show ipv6 route` | les routes de zebra, avec leurs labels |
""")
            + info_subtitle(tr("IS-IS et IPv6"), tag="ipv6")
            + tr("""
IPv6 n'a pas demandé de nouvelle version d'IS-IS (contrairement à OSPF, remplacé par OSPFv3 pour
IPv6) : quelques TLV de plus suffisent (RFC 5308).

| TLV | contenu |
|-----|---------|
| 129 | protocoles supportés : NLPID `0xCC` (IPv4) et `0x8E` (IPv6) |
| 232 | adresses IPv6 de l'interface (dans les IIH : l'adresse **lien-local**) |
| 236 | préfixes IPv6 (*IPv6 reachability*) |

- Les prochains sauts des routes IPv6 sont les adresses **lien-local** des voisins (`fe80::…`),
  apprises dans les IIH.
- Dans FRR, `ipv6 router isis NOM` sur chaque interface (à côté de `ip router isis NOM`) ; les
  routeurs doivent relayer IPv6 (`net.ipv6.conf.all.forwarding=1`, déjà fait).
- `show isis route` affiche les deux familles ; `ip -6 route` les routes IPv6 installées
  (`proto isis`).
""")
            + info_subtitle(tr("Topologie unique et multi-topologie"), tag="topology")
            + tr("""
Par défaut IS-IS est en **topologie unique** (*single topology*) : un seul graphe sert au calcul
des routes IPv4 et IPv6. Cela suppose que **tous les liens** portent les deux protocoles. Si un lien
ne porte que IPv4, un routeur peut choisir pour IPv6 un chemin qui passe par ce lien : le routeur
suivant, qui ne peut pas l'emprunter, renvoie le paquet par ailleurs, parfois vers celui qui le lui
a envoyé — une **boucle** ou un **trou noir** pour IPv6, alors qu'un autre chemin, plus long,
aurait fonctionné.

La **multi-topologie** (MT, RFC 5120) donne à chaque famille son propre graphe et son propre calcul
SPF. Chaque topologie a un identifiant (MT ID) : 0 pour IPv4 unicast, **2 pour IPv6 unicast**. Les
TLV changent :

| TLV | contenu |
|-----|---------|
| 229 | topologies du routeur (dans les IIH et les LSP) |
| 222 | voisins IS d'une topologie (*MT IS reachability*) |
| 237 | préfixes IPv6 de la topologie IPv6 (*MT IPv6 reachability*) |

Un voisin ne compte dans la topologie IPv6 que si IPv6 fonctionne avec lui sur ce lien : un lien
sans IPv6 disparaît du graphe IPv6 et le calcul IPv6 passe par ailleurs, sans toucher aux routes
IPv4. Dans FRR :

```
router isis CORE
 topology ipv6-unicast
```

à faire sur **tous** les routeurs. `show isis topology` affiche alors deux arbres différents et
`show isis database detail` les TLV `MT`.
""")
            + info_subtitle(tr("Le segment routing avec IS-IS"), tag="sr")
            + tr("""
Le **segment routing** (RFC 8402) est un routage par la source : le routeur d'entrée écrit le
chemin dans le paquet sous forme de **segments**, et le cœur ne garde aucun état par chemin. En
**SR-MPLS**, un segment est un label MPLS, et il n'y a **pas de LDP** : les labels sont annoncés par
l'IGP, ici IS-IS (RFC 8667).

- Chaque routeur réserve un bloc de labels, le **SRGB** (*SR Global Block*), qu'il annonce dans le
  TLV **242** (*Router Capability*), sous-TLV *SR-Capabilities*. FRR prend 16000 à 23999 par défaut.
- Un **prefix-SID** désigne un préfixe, en général l'adresse de bouclage d'un routeur, par un
  **index** unique dans le domaine, annoncé dans le sous-TLV *Prefix-SID* (**3**) du TLV 135 qui
  porte le préfixe.
- Le label à utiliser vers un préfixe est **le SRGB du prochain saut + l'index** : avec le même
  SRGB partout, c'est le même label tout le long du chemin ; un routeur qui a son propre SRGB reçoit
  des labels différents, et son voisin en amont en tient compte.
- Le routeur d'entrée impose le label et l'envoie au prochain saut du plus court chemin ; chaque
  routeur échange le label contre celui du routeur suivant.
- **PHP** : l'avant-dernier routeur retire le label et le dernier n'a plus qu'une recherche IP. Avec
  le drapeau **no-PHP** (`no-php-flag`), il l'échange contre le label du dernier routeur, qui le
  retire lui-même ; avec `explicit-null`, contre le label 0.
- IS-IS annonce aussi des **adjacency-SID** (un label local par voisin, pris dans le SRLB, 15000 à
  15999 dans FRR) qui forcent le passage par un lien précis.

```
router isis CORE
 segment-routing on
 segment-routing global-block 17000 24999
 segment-routing prefix 10.0.31.1/32 index 1
```

`show isis segment-routing node` affiche le SRGB de chaque routeur, `show isis database detail`
les prefix-SID, `show mpls table` et `ip -f mpls route` les labels installés, `ip route` les labels
imposés (`encap mpls 17004`), `tcpdump -nei ethX mpls` les labels qui passent.

### @@sec:mpls-linux@@ MPLS sous Linux

Le noyau commute les labels quand `net.mpls.platform_labels` (taille de la table des labels, 0 par
défaut) est assez grand et que `net.mpls.conf.<interface>.input=1` sur les interfaces qui reçoivent
des paquets étiquetés : c'est déjà fait sur les sites `sr` et `tl`. Un label se lit dans `ip -f mpls
route` : `17004 as to 30004 via inet 10.0.32.6 dev eth1` est un échange, `17004 via inet …` un
retrait vers un voisin, `17004 dev lo` un retrait avant livraison locale.
""")
            + info_subtitle(tr("Détecter les pannes : temporisateurs et BFD"), tag="detection")
            + tr("""
Un routeur IS-IS découvre la panne d'un voisin de deux façons :

- **coupure franche** (l'interface passe *down*) : il le sait immédiatement, retire l'adjacence,
  inonde une nouvelle LSP ; tous recalculent leurs routes en moins d'une seconde ;
- **panne silencieuse** (l'interface reste *up* mais le voisin ne répond plus : un commutateur ou
  un équipement de transmission entre les deux, un processus bloqué) : seule l'absence d'IIH la
  révèle, au bout du *holding time* — **30 s** par défaut dans FRR (un IIH toutes les 3 s,
  multiplicateur 10). Pendant tout ce temps le trafic part vers un voisin qui ne répond plus.

On peut réduire les temporisateurs d'IS-IS (`isis hello-interval 1` et `isis hello-multiplier 3`
en mode interface : 3 s). Ils s'appliquent à l'émission : c'est le voisin qui en profite. Descendre
sous la seconde avec des IIH n'est pas raisonnable : ce sont de grosses trames (remplies jusqu'à la
MTU), traitées par le démon.

Une fois la panne détectée, il faut encore inonder les LSP et recalculer les routes. FRR espace les
générations d'une même LSP de 30 s au plus (`lsp-gen-interval`, mode `router isis`) et les calculs
SPF d'une seconde (`spf-interval`) : un réseau qui doit converger vite règle `lsp-gen-interval 1`,
sans quoi les routeurs voisins de la panne peuvent se renvoyer le trafic le temps que leurs LSP
soient régénérées.

### @@sec:bfd@@ BFD

**BFD** (*Bidirectional Forwarding Detection*, RFC 5880 ; RFC 5881 pour un saut) est un protocole
léger qui ne fait qu'une chose : vérifier, plusieurs fois par seconde, qu'un voisin répond.

- Une **session** BFD relie deux adresses ; elle est demandée par un protocole client (ici IS-IS,
  pour chaque adjacence), qui est prévenu dès qu'elle tombe et retire alors l'adjacence sans
  attendre le *holding time*.
- Les paquets de contrôle voyagent en **UDP**, port **3784** (un saut), par le même chemin que le
  trafic.
- Chaque extrémité annonce l'intervalle minimal auquel elle veut **recevoir** (`receive-interval`)
  et auquel elle peut **émettre** (`transmit-interval`) ; l'intervalle réel dans un sens est le plus
  grand des deux. La session tombe quand rien n'est arrivé pendant **multiplicateur × intervalle**
  (*detection time*) : avec 3 × 300 ms, une panne est vue en 900 ms.
- Le mode *echo* (des paquets que le voisin renvoie sans les traiter) permet des intervalles encore
  plus courts ; il n'est pas utilisé ici.

Dans FRR, `bfdd` (activé dans `/etc/frr/daemons`) gère les sessions, et un **profil** regroupe les
réglages (FRR n'écrit pas dans la configuration les valeurs par défaut : multiplicateur 3,
intervalles de 300 ms) :

```
bfd
 profile FAST
  detect-multiplier 3
  receive-interval 300
  transmit-interval 300
 exit
exit
interface eth1
 isis bfd
 isis bfd profile FAST
```

`show bfd peers` affiche les sessions (`Status: up`) et les intervalles des deux extrémités ;
`show isis neighbor detail` indique `BFD is active, status Up` pour chaque adjacence protégée.
""")
            + info_subtitle(tr("Protection rapide : TI-LFA"), tag="tilfa")
            + tr("""
Après une panne, il faut la détecter, inonder les LSP et recalculer : quelques centaines de
millisecondes au mieux. La **protection rapide** calcule d'avance un chemin de secours pour chaque
destination et l'utilise dès que la panne est vue, avant la reconvergence.

**TI-LFA** (*Topology Independent Loop-Free Alternate*) utilise le segment routing pour qu'un
secours existe quelle que soit la topologie : le routeur protégé calcule le chemin que prendra le
réseau **après** la panne, et pousse la pile de labels qui y mène (un ou plusieurs SID, puis le
prefix-SID de la destination). La protection de **lien** contourne le lien en panne, la protection
de **nœud** (`node-protection`) contourne aussi le routeur voisin. Dans FRR, sur les interfaces à
protéger :

```
interface eth0
 isis fast-reroute ti-lfa level-2 node-protection
```

`show ip route` (json : `backupNexthops`) affiche les prochains sauts de secours avec leurs
labels ; zebra les garde prêts sans les installer dans le noyau. `show isis fast-reroute summary`
compte les destinations protégées.
""")
        )

    # -- configurations --------------------------------------------------------------

    def isis_lines(self, router: str, metrics: Dict[str, int] = None, router_extra: tuple = ()) -> List[str]:
        """vtysh lines of the given IPv4 IS-IS of *router*: level 2 only, links point-to-point (with
        *metrics* on some), host networks and loopback passive."""
        metrics = metrics or {}
        lines = [f"router isis {ISIS_NAME}", f"net {self.net_title(router)}", "is-type level-2-only"]
        lines += list(router_extra) + ["exit"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            lines += [f"interface eth{i}", f"ip router isis {ISIS_NAME}"]
            lines.append("isis network point-to-point" if net in LINKS else "isis passive")
            if net in metrics:
                lines.append(f"isis metric {metrics[net]}")
            lines.append("exit")
        lines += ["interface lo", f"ip router isis {ISIS_NAME}", "isis passive", "exit"]
        return lines

    def _given_lines(self, router: str) -> List[str]:
        site = site_of(router)
        if site == 'mt':
            return self.isis_lines(router, metrics={'mt_l34': MT_L34_METRIC})
        if site == 'sr':
            return self.isis_lines(router)
        if site == 'bfd':
            # LSPs regenerated at once: FRR waits up to 30 s between two generations of an LSP, which
            # would delay the reconvergence after a failure as much
            return self.isis_lines(router, metrics={'bfd_l13': BFD_BACKUP_METRIC, 'bfd_l34': BFD_BACKUP_METRIC},
                                   router_extra=("lsp-gen-interval 1",))
        # tl: IS-IS and segment routing (default SRGB, index N for tl_rN)
        return self.isis_lines(router, metrics=TL_METRICS,
                               router_extra=("segment-routing on",
                                             f"segment-routing prefix {self.lo(router)}/32 index {router_number(router)}"))

    def _frr_conf(self, router: str) -> str:
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {router}", "log file /var/log/frr/frr.log", "!"]
        for line in self._given_lines(router):
            if line == "exit":
                lines += ["exit", "!"]
            elif line.startswith(("router ", "interface ")):
                lines.append(line)
            else:
                lines.append(f" {line}")
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part (texts shown by the instructor solutions) ------

    def solution_ipv6(self) -> Dict[str, List[str]]:
        """Part 1, step 1: IPv6 in IS-IS on every interface that carries IPv6."""
        result = {}
        for r in ('mt_r1', 'mt_r2', 'mt_r3', 'mt_r4'):
            cmds = []
            for i, net in enumerate(ROUTER_IFACES[r]):
                if net in MT_IPV6_NETS:
                    cmds += [f"interface eth{i}", f"ipv6 router isis {ISIS_NAME}", "exit"]
            result[r] = cmds + ["interface lo", f"ipv6 router isis {ISIS_NAME}", "exit"]
        return result

    def solution_topology(self) -> Dict[str, List[str]]:
        """Part 1, step 2: the IPv6 multi-topology on every router."""
        return {r: [f"router isis {ISIS_NAME}", "topology ipv6-unicast", "exit"]
                for r in ('mt_r1', 'mt_r2', 'mt_r3', 'mt_r4')}

    def solution_sr(self) -> Dict[str, List[str]]:
        d = self.data
        result = {}
        for r in ('sr_r1', 'sr_r2', 'sr_r3', 'sr_r4'):
            base = d.sr_base(r)
            prefix = f"segment-routing prefix {self.lo(r)}/32 index {d.sr_index(r)}"
            if r == 'sr_r4':
                prefix += " no-php-flag"
            result[r] = [f"router isis {ISIS_NAME}", "segment-routing on",
                         f"segment-routing global-block {base} {base + SRGB_SIZE - 1}", prefix, "exit"]
        return result

    def solution_bfd(self) -> Dict[str, List[str]]:
        d = self.data
        result = {}
        for r in ('bfd_r1', 'bfd_r2'):
            result[r] = ["bfd", f"profile {BFD_PROFILE}", f"detect-multiplier {d.bfd_multiplier}",
                         f"receive-interval {d.bfd_interval}", f"transmit-interval {d.bfd_interval}", "exit", "exit",
                         f"interface {iface(r, 'bfd_l12')}", "isis bfd", f"isis bfd profile {BFD_PROFILE}", "exit"]
        for r in ('bfd_r3', 'bfd_r4'):
            result[r] = [f"interface {iface(r, 'bfd_l34')}", "isis hello-interval 1", "isis hello-multiplier 3", "exit"]
        return result

    def solution_tilfa(self) -> Dict[str, List[str]]:
        cmds = []
        for name in link_ifaces('tl_r1'):
            cmds += [f"interface {name}", "isis fast-reroute ti-lfa level-2 node-protection", "exit"]
        return {'tl_r1': cmds}

    # -- applying the solutions ----------------------------------------------------

    def _apply(self, solution: Dict[str, List[str]], step: int = 1):
        for r, cmds in solution.items():
            self._vtysh(r, *cmds, step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for h in ('mt_h1', 'mt_h4'):
            set_ipv6_forward(net_scheme=self, machine_name=h, ipv6_forward=False)
        for r in ('mt_r1', 'mt_r4'):
            # mt_l14 carries IPv4 only: no IPv6 at all on its interfaces (no link-local address)
            remount_proc_sys(self, r)
            self.cmd(r, f"sysctl -w net.ipv6.conf.{iface(r, MT_IPV4_ONLY)}.disable_ipv6=1")
        for r in ROUTER_IFACES:
            self.cmd(r, f"ip addr add {getattr(self.data.ips, f'{r}_lo')} dev lo")
            if site_of(r) == 'mt':
                self.cmd(r, f"ip -6 addr add {getattr(self.data.ips6, f'{r}_lo')} dev lo")
        for r in MPLS_ROUTERS:
            remount_proc_sys(self, r)
            # loads mpls_router / mpls_iptunnel on the host (module autoload) and waits for the
            # net.mpls sysctls of this container
            self.cmd(r, trigger_mpls_modules_cmd())
            self.cmd(r, f"sysctl -w net.mpls.platform_labels={PLATFORM_LABELS}", step=2)
            for name in link_ifaces(r):
                self.cmd(r, f"sysctl -w net.mpls.conf.{name}.input=1", step=2)
        self.cmd(BRIDGE, "ip link add br0 type bridge && ip link set eth0 master br0 && ip link set eth1 master br0"
                         " && ip link set br0 up")
        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr", step=2)
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(r, "systemctl start frr", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (IPv6 et multi-topologie)"))
    def solve_mt(self):
        self._apply(self.solution_ipv6())
        self._apply(self.solution_topology(), step=2)
        self.cmd('mt_r1', f"sleep {CONVERGE_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (segment routing)"))
    def solve_sr(self):
        self._apply(self.solution_sr())
        self.cmd('sr_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (BFD)"))
    def solve_bfd(self):
        self.cmd(BRIDGE, UNCUT_CMD)
        self._apply(self.solution_bfd())
        self.cmd('bfd_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Bonus : solution (TI-LFA)"))
    def solve_tilfa(self):
        self._apply(self.solution_tilfa())
        self.cmd('tl_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for the LSPs and BFD).  Form questions are filled through cheat_answers."""
        self.cmd(BRIDGE, UNCUT_CMD)
        self._apply(self.solution_ipv6())
        self._apply(self.solution_sr())
        self._apply(self.solution_bfd())
        self._apply(self.solution_tilfa())
        self._apply(self.solution_topology(), step=2)
        self.cmd('mt_r1', f"sleep {CONVERGE_WAIT}", step=3)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s):
    """The integer of a typed answer (``0x8e`` is read in hexadecimal), None when unreadable."""
    text = _norm(s).replace(' ', '')
    try:
        return int(text, 16) if text.startswith('0x') else int(text)
    except ValueError:
        return None


def _nlpid(s):
    """A typed NLPID: ``0x8E``, ``8E`` (read in hexadecimal) or ``142``."""
    text = _norm(s).replace(' ', '')
    if text.startswith('0x'):
        return _int(text)
    try:
        return int(text, 16) if re.search(r'[a-f]', text) or len(text) == 2 else int(text)
    except ValueError:
        return None


def _running_config(grade: Grade0, router: str) -> Dict:
    """The parsed running configuration of *router*; the empty shape before the results."""
    return get_frr_running_config(grade, router, allow_error=True) or parse_frr_config("")


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    """The reference configuration of a part, as vtysh sessions (one block per router)."""
    blocks = []
    for router, cmds in solution.items():
        body, depth = ["configure terminal"], 1
        for c in cmds:
            if c == "exit":
                depth = max(1, depth - 1)
                body.append(" " * depth + c)
                continue
            body.append(" " * depth + c)
            if c.startswith(("router ", "interface ", "profile ")) or c == "bfd":
                depth += 1
        blocks.append(f"`{router}` :\n\n```\n" + "\n".join(body + ["end", "write"]) + "\n```")
    return "\n\n".join(blocks)


def _ping_outage(output: str, interval: float = PING_INTERVAL):
    """(replies, longest outage in s) of a ``ping -i`` output: the largest gap of icmp_seq."""
    seqs = sorted({int(n) for n in re.findall(r'icmp_seq=(\d+)', output or '')})
    if not seqs:
        return 0, None
    gaps = [b - a - 1 for a, b in zip(seqs, seqs[1:])]
    return len(seqs), max(gaps or [0]) * interval


def _route_via(routes: Dict[str, Dict], prefix, labels: List[int], gateway) -> bool:
    """True when the kernel route of *prefix* pushes *labels* towards *gateway*."""
    entry = routes.get(str(prefix)) or {}
    return any(stack == labels and str(gw) == str(gateway)
               for (gw, _dev), stack in zip(entry.get('nexthops', []), entry.get('labels', [])))


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest) -> bool:
        return eval_ping(self, src=src, dest=dest, count=3, deadline=5, allow_error=True)

    def _burst(self, src: str, dest, source=None) -> bool:
        """Five pings at step 2 (between the two readings of the MPLS counters); True when all
        five come back."""
        option = f" -I {source}" if source else ""
        _out, code = self.test(src, f"ping -c 5 -i 0.2 -w 4{option} {dest}", step=2, allow_error=True)
        return code == 0

    def _counters_delta(self, router: str, ifname: str) -> int:
        """MPLS packets received on *ifname* of *router* between steps 1 and 3."""
        return mpls_counter_delta(get_mpls_counters(self, router, step=1), get_mpls_counters(self, router, step=3),
                                  ifname)

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net, sysid = ns.lo, ns.addr, ns.net, ns.sysid

        def names(router: str) -> List[str]:
            return [router, sysid(router)]

        def isis_route(routes: Dict[str, Dict], prefix) -> Dict:
            entry = routes.get(str(prefix))
            return entry if entry and is_isis_protocol(entry['protocol']) else {}

        def devices(routes: Dict[str, Dict], prefix) -> List[str]:
            return [dev for _gw, dev in isis_route(routes, prefix).get('nexthops', [])]

        def gateways(routes: Dict[str, Dict], prefix) -> List[str]:
            return [str(gw) for gw, _dev in isis_route(routes, prefix).get('nexthops', []) if gw]

        def isis_if(cfg: Dict, router: str, net_name: str) -> Dict:
            return ((cfg.get('interfaces') or {}).get(iface(router, net_name)) or {}).get('isis') or {}

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            if r not in OPERATORS:
                self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        mt = ('mt_r1', 'mt_r2', 'mt_r3', 'mt_r4')
        mt_cfg = {r: _running_config(self, r) for r in mt}
        mt_k6 = {r: get_kernel_routes(self, r, allow_error=True, ipv6=True) for r in ('mt_r1', 'mt_r2', 'mt_r4')}
        mt_k4 = get_kernel_routes(self, 'mt_r1', allow_error=True)
        mt_ping = [self._ping('mt_h1', d.ips6.mt_h4.ip), self._ping('mt_h4', d.ips6.mt_h1.ip)]

        sr = ('sr_r1', 'sr_r2', 'sr_r3', 'sr_r4')
        sr_cfg = {r: _running_config(self, r) for r in sr}
        sr_ilm = {r: get_kernel_mpls_routes(self, r) for r in ('sr_r2', 'sr_r3', 'sr_r4')}
        sr_k = get_kernel_routes(self, 'sr_r1', allow_error=True)
        sr_ping = self._burst('sr_r1', lo('sr_r4'), source=lo('sr_r1'))
        sr_delta = {r: self._counters_delta(r, 'eth0') for r in ('sr_r2', 'sr_r3')}

        bfd_cfg = {r: _running_config(self, r) for r in ('bfd_r1', 'bfd_r2')}
        bfd_peers = {r: get_bfd_peers(self, r) for r in ('bfd_r1', 'bfd_r2')}
        bfd_nb = get_isis_neighbors(self, 'bfd_r1')
        bfd_if = {r: get_isis_interfaces(self, r) for r in ('bfd_r3', 'bfd_r4')}
        # the failover measure: reset any cut left by an interrupted evaluation, then, at step 2,
        # bfd_h1 pings bfd_h4 while the bridge drops everything for CUT_SECONDS
        self.test(BRIDGE, UNCUT_CMD, allow_error=True)
        cut_out, _code = self.test(BRIDGE, f"sleep 1; echo '{CUT_TABLE}' | nft -f - && sleep {CUT_SECONDS}; {UNCUT_CMD}",
                                   step=2, timeout=CUT_SECONDS + 20, allow_error=True)
        ping_out, _code = self.test('bfd_h1', f"ping -i {PING_INTERVAL} -c {PING_COUNT} -W 1 {d.ips.bfd_h4.ip}",
                                    step=2, timeout=CUT_SECONDS + 20, allow_error=True)

        tl_routes = get_frr_routes(self, 'tl_r1')
        tl_cfg = _running_config(self, 'tl_r1')

        # ---------------- texts shared by the questions ---------------------------
        sites = [('mt', "1 — IPv6 et multi-topologie", "`mt_r1` à `mt_r4`, les hôtes `mt_h1` et `mt_h4`"),
                 ('sr', "2 — segment routing", "`sr_r1` à `sr_r4`"),
                 ('bfd', "3 — BFD", "`bfd_r1` à `bfd_r4`, les hôtes `bfd_h1` et `bfd_h4`, le pont `bfd_sw` (sans "
                                    "terminal)"),
                 ('tl', "bonus — TI-LFA", "`tl_r1` (les trois autres routeurs n'ont pas de terminal)")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + LANS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                text = f"`{r}` eth{i} (`{addr(r, n)}`"
                if n in MT_IPV6_NETS:
                    text += f", `{ns.addr6(r, n)}`"
                members[n].append(text + ")")
        for h, (n, _gw) in HOSTS.items():
            text = f"`{h}` (`{getattr(d.ips, h).ip}`"
            if site_of(h) == 'mt':
                text += f", `{getattr(d.ips6, h).ip}`"
            members[n].append(text + ")")
        address_rows = []
        for n in list(LINKS) + LANS:
            prefix = f"`{net(n)}`" + (f", `{ns.net6(n)}`" if n in MT_IPV6_NETS else "")
            address_rows.append(f"| `{n}` | {prefix} | {', '.join(members[n])} |")
        for site in SITE_NUMBER:
            routers = [r for r in ROUTER_IFACES if site_of(r) == site]
            cells = ", ".join(f"`{r}` `{lo(r)}`" + (f" `{ns.lo6(r)}`" if site == 'mt' else "") for r in routers)
            prefix = f"`{net(site + '_lo')}`" + (f", `{ns.net6('mt_lo')}`" if site == 'mt' else "")
            address_rows.append(f"| `{site}_lo` | {prefix} | {cells} |")
        addressing = "\n".join(address_rows)
        i1, i2, i3, i4 = d.sr_index1, d.sr_index2, d.sr_index3, d.sr_index4
        detection = d.bfd_interval * d.bfd_multiplier

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="10e937b8810985ef",
            description=tr("""
Lisez l'onglet **Informations** : il rappelle IS-IS, puis présente IPv6 et la multi-topologie, le
segment routing, BFD et TI-LFA, avec leur configuration dans FRR.

**Le réseau.** Il est fait de **quatre sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) avec `isisd` (et `bfdd` sur le site `bfd`) :
  configurez-les avec `vtysh`. **IS-IS (IPv4) fonctionne déjà partout** : niveau 2, une aire par
  site, liens point à point, interfaces de bouclage annoncées. Le processus s'appelle **`{name}`**.
- Toutes les adresses sont en place ; le site `mt` est en double pile IPv4 / IPv6, sauf le lien
  `mt_l14` (IPv4 seulement). Les modules MPLS du noyau sont chargés et MPLS est activé sur les
  interfaces des routeurs des sites `sr` et `tl`.
- Les fichiers `/etc/hosts` contiennent les noms : `sr_r2-eth1` désigne l'adresse de l'interface
  `eth1` de `sr_r2`, `sr_r2-lo` son adresse de bouclage.

**Plan d'adressage.** Les liens entre routeurs sont des /30 (des /64 en IPv6), les réseaux des
hôtes des /24.

| réseau | préfixes | interfaces |
|--------|----------|------------|
{addressing}

**Valeurs propres à votre instance.**

- Partie 2 : SRGB de `sr_r1`, `sr_r2` et `sr_r4` : **{srgb} à {srgb_end}** ; SRGB de `sr_r3` :
  **{srgb3} à {srgb3_end}** ; index des prefix-SID des interfaces de bouclage : `sr_r1` **{i1}**,
  `sr_r2` **{i2}**, `sr_r3` **{i3}**, `sr_r4` **{i4}**.
- Partie 3 : profil BFD **`{profile}`** : intervalles de réception et d'émission **{interval} ms**,
  multiplicateur **{mult}**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).
- Un nouveau préfixe ou un nouveau SID peut mettre jusqu'à 30 s à être annoncé (FRR espace les
  générations d'une même LSP).

**Évaluation.** Chaque évaluation lit vos réponses, la configuration et l'état d'IS-IS et de BFD,
les tables de routage et de labels, et envoie du trafic. **Sur le site `bfd`, elle coupe le pont
`bfd_sw` pendant {cut} s** (aucune trame ne passe, les interfaces restent actives) et mesure la durée
de la coupure vue par `bfd_h1`, qui envoie un `ping` à `bfd_h4` toutes les {step} s. Elle dure une
quinzaine de secondes.
""").format(site_rows=site_rows, addressing=addressing, name=ISIS_NAME, srgb=d.sr_srgb,
            srgb_end=d.sr_srgb + SRGB_SIZE - 1, srgb3=d.sr_srgb_r3, srgb3_end=d.sr_srgb_r3 + SRGB_SIZE - 1, i1=i1,
            i2=i2, i3=i3, i4=i4, profile=BFD_PROFILE, interval=d.bfd_interval, mult=d.bfd_multiplier,
            cut=CUT_SECONDS, step=PING_INTERVAL)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_mt`, `solve_sr`, `solve_bfd` et `solve_tilfa` (onglet *Appliquer une
configuration*) appliquent la solution d'une seule partie et remplissent ses formulaires. L'état
`final` les applique toutes, attend {wait} s (régénération des LSP, sessions BFD) puis remplit tous
les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.
""").format(wait=CONVERGE_WAIT)),
        )

        # =====================================================================
        # Part 1 — IPv6 and multi-topology (mt)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("mt"), tr("Partie 1 — IPv6 et multi-topologie (site mt)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("IPv6 et multi-topologie"),
            hash="77a09f71ec762177",
            description=tr("""
Les routeurs `mt_r1`, `mt_r2`, `mt_r3` et `mt_r4` forment un carré (liens `mt_l12`, `mt_l23`,
`mt_l34` et `mt_l14`) ; l'hôte `mt_h1` est derrière `mt_r1`, l'hôte `mt_h4` derrière `mt_r4`. IS-IS
route déjà IPv4 ; la métrique de `mt_l34` est {m34}. Le lien `mt_l14` passe par un vieil équipement
qui ne transporte que IPv4 : ses interfaces n'ont pas d'IPv6 du tout (sections @@ref:ipv6@@ et
@@ref:topology@@).

1. Vérifiez que `mt_h1` joint `mt_h4` en IPv4 (`traceroute -n`) mais pas en IPv6.
2. Activez IPv6 dans IS-IS sur les quatre routeurs, sur toutes les interfaces qui ont IPv6 (y
   compris les interfaces de bouclage et les réseaux des hôtes). Regardez les routes IPv6 (`show
   isis route`, `ip -6 route`) de chaque routeur vers `mt_lan4`, puis essayez `ping` et
   `traceroute -n` de `mt_h1` vers l'adresse IPv6 de `mt_h4`. Expliquez ce que vous voyez.
3. Passez les quatre routeurs en **multi-topologie** IPv6, puis regardez à nouveau les routes
   IPv6 et IPv4, `show isis topology`, et le trafic entre les hôtes.
""").format(m34=MT_L34_METRIC)
            + instructor(tr("""
**Solution.** D'abord IPv6 dans IS-IS :

{ipv6}

puis la multi-topologie, sur les quatre routeurs :

{topology}

En topologie unique, `mt_r2` calcule sur un graphe qui contient `mt_l14` : son meilleur chemin vers
`mt_lan4` passe par `mt_r1` puis `mt_l14` (coût 30, contre 40 par `mt_r3`). Mais `mt_r1` ne peut pas
envoyer d'IPv6 sur `mt_l14` (son voisin n'y a pas d'adresse IPv6) : il passe par `mt_r2`. Les paquets
IPv6 tournent entre `mt_r1` et `mt_r2` jusqu'à épuisement de leur *hop limit* (`traceroute` le
montre). En multi-topologie, `mt_l14` n'existe pas dans le graphe IPv6 : `mt_r2` passe par
`mt_r3`, et IPv4 garde le lien direct.

Évaluation : `mt_ipv6_ifaces` (8 : 2 par routeur, IPv6 dans IS-IS sur ses interfaces IPv6),
`mt_prefixes` (4 : routes IPv6 d'IS-IS de `mt_r1` vers `mt_lan4` et `mt_r4-lo`, de `mt_r4` vers
`mt_lan1`), `mt_topology` (4 : un point par routeur), `mt_r2_path` (4 : route IPv6 de `mt_r2` vers
`mt_lan4` par `mt_r3` seulement), `mt_r2_lo` (2 : de même vers `mt_r4-lo`), `mt_ipv4_kept` (2 : IPv4
de `mt_r1` vers `mt_lan4` toujours par `mt_l14`, compté avec la multi-topologie de `mt_r1`),
`mt_ping6` (4).
""").format(ipv6=_vtysh_text(ns.solution_ipv6()), topology=_vtysh_text(ns.solution_topology()))),
        )
        cheat_mt = {'nlpid': '0x8e', 'mt_id': '2', 'tlv_st': '236', 'tlv_mt': '237', 'single': 'loop',
                    'nexthop': 'link_local'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site mt"),
            hash="e24a682ac46a6a68",
            description=tr("""
- NLPID qui annonce IPv6 dans le TLV 129 (en hexadécimal) : @@{nlpid:[0-9a-fA-Fx]+}@@
- identifiant de la topologie IPv6 unicast (MT ID) : @@{mt_id:[0-9]+}@@
- TLV des préfixes IPv6 en topologie unique : @@{tlv_st:[0-9]+}@@  et en multi-topologie :
  @@{tlv_mt:[0-9]+}@@
- en topologie unique, les paquets IPv6 de `mt_h1` vers `mt_h4` :
  @@{single:>tournent entre mt_r1 et mt_r2>>>loop|passent par mt_l14>>>l14|passent par mt_r3>>>r3|sont jetés par mt_h4>>>dropped}@@
- prochain saut des routes IPv6 d'IS-IS :
  @@{nexthop:>l'adresse lien-local du voisin>>>link_local|l'adresse globale du voisin>>>global|l'adresse IPv4 du voisin>>>ipv4}@@
""")
            + instructor(tr("""
**Solution.** **`0x8E`** ; MT ID **2** ; TLV **236** et **237** ; ils **tournent entre `mt_r1` et
`mt_r2`** ; **l'adresse lien-local du voisin**.

Évaluation : `mt_q_nlpid`, `mt_q_mt_id`, `mt_q_tlv_st`, `mt_q_tlv_mt` (1 chacun) et, pour l'enseignant
seulement, `mt_q_single`, `mt_q_nexthop` (1 chacun).
""")),
            cheat_answers={"final": cheat_mt, "solve_mt": cheat_mt},
        )
        v6_ok = []
        for r in mt:
            wanted = [n for n in ROUTER_IFACES[r] if n in MT_IPV6_NETS]
            interfaces = mt_cfg[r].get('interfaces') or {}
            v6_ok.append(all(isis_if(mt_cfg[r], r, n).get('ipv6') == ISIS_NAME for n in wanted)
                         and ((interfaces.get('lo') or {}).get('isis') or {}).get('ipv6') == ISIS_NAME)
        self.add_grade_element(
            title=no_tr("mt_ipv6_ifaces"), max_grade=8, grade_part=part1, grade=2 * sum(v6_ok),
            description=tr("IPv6 dans IS-IS sur les interfaces IPv6"),
        )
        prefixes = [isis_route(mt_k6['mt_r1'], ns.net6('mt_lan4')), isis_route(mt_k6['mt_r1'], f"{ns.lo6('mt_r4')}/128"),
                    isis_route(mt_k6['mt_r4'], ns.net6('mt_lan1'))]
        self.add_grade_element(
            title=no_tr("mt_prefixes"), max_grade=4, grade_part=part1,
            grade=2 * int(bool(prefixes[0]) and bool(prefixes[1])) + 2 * int(bool(prefixes[2])),
            description=tr("préfixes IPv6 appris par IS-IS"),
        )
        topology = [ns_cfg['router_isis']['present'] and 'ipv6-unicast' in ns_cfg['router_isis']['topologies']
                    for ns_cfg in (mt_cfg[r] for r in mt)]
        self.add_grade_element(
            title=no_tr("mt_topology"), max_grade=4, grade_part=part1, grade=sum(topology),
            description=tr("multi-topologie IPv6 sur les quatre routeurs"),
        )
        towards_r3 = [iface('mt_r2', 'mt_l23')]
        self.add_grade_element(
            title=no_tr("mt_r2_path"), max_grade=4, grade_part=part1,
            grade=4 * int(devices(mt_k6['mt_r2'], ns.net6('mt_lan4')) == towards_r3),
            description=tr("IPv6 de mt_r2 vers mt_lan4 par mt_r3"),
        )
        self.add_grade_element(
            title=no_tr("mt_r2_lo"), max_grade=2, grade_part=part1,
            grade=2 * int(devices(mt_k6['mt_r2'], f"{ns.lo6('mt_r4')}/128") == towards_r3),
            description=tr("IPv6 de mt_r2 vers mt_r4-lo par mt_r3"),
        )
        self.add_grade_element(
            title=no_tr("mt_ipv4_kept"), max_grade=2, grade_part=part1,
            grade=2 * int(topology[0] and gateways(mt_k4, net('mt_lan4')) == [str(addr('mt_r4', 'mt_l14'))]),
            description=tr("IPv4 garde le lien mt_l14"),
        )
        self.add_grade_element(
            title=no_tr("mt_ping6"), max_grade=4, grade_part=part1, grade=4 * int(all(mt_ping)),
            description=tr("mt_h1 et mt_h4 se joignent en IPv6"),
        )
        for key, points, label, ok in (
                ('nlpid', 1, tr("NLPID d'IPv6"), _nlpid(q1.get('nlpid')) == 0x8e),
                ('mt_id', 1, tr("MT ID d'IPv6"), _int(q1.get('mt_id')) == 2),
                ('tlv_st', 1, tr("TLV des préfixes IPv6"), _int(q1.get('tlv_st')) == 236),
                ('tlv_mt', 1, tr("TLV des préfixes IPv6 en multi-topologie"), _int(q1.get('tlv_mt')) == 237)):
            self.add_grade_element(title=no_tr(f"mt_q_{key}"), max_grade=points, grade_part=part1,
                                   grade=points * int(ok), description=label)
        self.add_grade_element(
            title=no_tr("mt_q_single"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('single')) == 'loop'), description=tr("effet de la topologie unique"),
        )
        self.add_grade_element(
            title=no_tr("mt_q_nexthop"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('nexthop')) == 'link_local'), description=tr("prochain saut IPv6"),
        )

        # =====================================================================
        # Part 2 — segment routing (sr)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("sr"), tr("Partie 2 — segment routing (site sr)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le segment routing avec IS-IS"),
            hash="8c6b68e545c2c864",
            description=tr("""
Les routeurs `sr_r1`, `sr_r2`, `sr_r3` et `sr_r4` forment une ligne (liens `sr_l12`, `sr_l23`,
`sr_l34`). IS-IS fonctionne et MPLS est activé dans les noyaux ; il n'y a pas de LDP (sections
@@ref:sr@@ et @@ref:mpls-linux@@).

1. Activez le segment routing dans IS-IS sur les quatre routeurs, avec le SRGB et l'index de
   prefix-SID donnés dans l'organisation du TP (`sr_r3` n'a pas le même SRGB que les autres).
2. Observez `show isis segment-routing node`, `show isis database detail`, `show mpls table`,
   `ip -f mpls route` et `ip route` sur chaque routeur. Calculez les labels utilisés de `sr_r1`
   vers `sr_r4`, lien par lien, et comparez.
3. `sr_r4` veut recevoir avec leur label les paquets qui lui sont destinés : annoncez son
   prefix-SID **sans PHP**. Qu'est-ce qui change sur `sr_r3` ?
4. Depuis `sr_r1`, faites un `ping` de l'interface de bouclage de `sr_r4` **depuis sa propre
   interface de bouclage** (`ping -I {lo1} {lo4}`) et regardez les labels sur chaque lien
   (`tcpdump -nei eth0 mpls`).
""").format(lo1=lo('sr_r1'), lo4=lo('sr_r4'))
            + instructor(tr("""
**Solution.**

{solution}

Le label se calcule avec le SRGB du routeur **suivant** : `sr_r1` impose {srgb} + {i4} = **{l_r1}**
pour joindre `sr_r4` ; `sr_r2` l'échange contre {srgb3} + {i4} = **{l_r2}** (le SRGB de `sr_r3`) ;
sans PHP, `sr_r3` l'échange contre {srgb} + {i4} = **{l_r1}** (le SRGB de `sr_r4`), que `sr_r4`
retire (`dev lo`). Avec le PHP, `sr_r3` retirait le label.

Évaluation : `sr_enabled` (4 : un point par routeur), `sr_srgb` (4 : un point par routeur),
`sr_index` (4 : un point par prefix-SID), `sr_r2_swap` (3 : l'échange de `sr_r2`), `sr_no_php` (3 :
l'échange de `sr_r3` (2), le retrait par `sr_r4` (1)), `sr_r1_push` (4 : la route de `sr_r1` vers
`sr_r4`), `sr_ping` (4 : ping entre les interfaces de bouclage, avec des paquets étiquetés reçus par
`sr_r2` et `sr_r3`).
""").format(solution=_vtysh_text(ns.solution_sr()), srgb=d.sr_srgb, srgb3=d.sr_srgb_r3, i4=i4,
            l_r1=d.sr_srgb + i4, l_r2=d.sr_srgb_r3 + i4)),
        )
        cheat_sr = {'push4': str(d.sr_srgb + i4), 'label_l23': str(d.sr_srgb_r3 + i4), 'label_l34': str(d.sr_srgb + i4),
                    'push3': str(d.sr_srgb + i3), 'capability': '242', 'subtlv': '3', 'no_php': 'last_pops'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Les labels du segment routing"),
            hash="d28f3fb8220d4cdd",
            description=tr("""
Calculez-les avant de les observer :

- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r4` : @@{push4:[0-9]+}@@
- label de ces paquets sur le lien `sr_l23` (de `sr_r2` vers `sr_r3`) : @@{label_l23:[0-9]+}@@
- label de ces paquets sur le lien `sr_l34`, une fois le PHP refusé par `sr_r4` :
  @@{label_l34:[0-9]+}@@
- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r3` : @@{push3:[0-9]+}@@
- TLV dans lequel un routeur annonce son SRGB : @@{capability:[0-9]+}@@  et sous-TLV qui porte un
  prefix-SID : @@{subtlv:[0-9]+}@@
- sans PHP :
  @@{no_php:>le dernier routeur reçoit un label et le retire>>>last_pops|l'avant-dernier routeur retire le label>>>penultimate_pops|le premier routeur n'impose plus de label>>>no_push|le label 3 circule jusqu'au dernier routeur>>>implicit_null}@@
""")
            + instructor(tr("""
**Solution.** **{push4}**, **{label_l23}**, **{label_l34}**, **{push3}** (voir la question
précédente) ; TLV **242** (*Router Capability*), sous-TLV **3** ; **le dernier routeur reçoit un label et
le retire**.

Évaluation : `sr_q_push4`, `sr_q_label_l23`, `sr_q_label_l34`, `sr_q_push3`, `sr_q_capability`,
`sr_q_subtlv` (1 chacun) et, pour l'enseignant seulement, `sr_q_no_php` (1).
""").format(**cheat_sr)),
            cheat_answers={"final": cheat_sr, "solve_sr": cheat_sr},
        )
        sr_isis = {r: sr_cfg[r]['router_isis'] for r in sr}
        self.add_grade_element(
            title=no_tr("sr_enabled"), max_grade=4, grade_part=part2,
            grade=sum(int(sr_isis[r]['segment_routing']['enabled']) for r in sr),
            description=tr("segment routing actif sur les quatre routeurs"),
        )
        self.add_grade_element(
            title=no_tr("sr_srgb"), max_grade=4, grade_part=part2,
            grade=sum(int(isis_srgb(sr_isis[r]) == (d.sr_base(r), d.sr_base(r) + SRGB_SIZE - 1)) for r in sr),
            description=tr("SRGB donnés"),
        )
        index_ok = [((sr_isis[r]['segment_routing']['prefixes'] or {}).get(f"{lo(r)}/32") or {}).get('index')
                    == d.sr_index(r) for r in sr]
        self.add_grade_element(
            title=no_tr("sr_index"), max_grade=4, grade_part=part2, grade=sum(index_ok),
            description=tr("prefix-SID des interfaces de bouclage"),
        )
        self.add_grade_element(
            title=no_tr("sr_r2_swap"), max_grade=3, grade_part=part2,
            grade=3 * int(mpls_route_is_swap(sr_ilm['sr_r2'], d.sr_srgb + i4, [d.sr_srgb_r3 + i4], addr('sr_r3', 'sr_l23'))),
            description=tr("sr_r2 : échange vers le SRGB de sr_r3"),
        )
        self.add_grade_element(
            title=no_tr("sr_no_php"), max_grade=3, grade_part=part2,
            grade=2 * int(mpls_route_is_swap(sr_ilm['sr_r3'], d.sr_srgb_r3 + i4, [d.sr_srgb + i4], addr('sr_r4', 'sr_l34')))
            + int(mpls_route_is_pop(sr_ilm['sr_r4'], d.sr_srgb + i4, dev='lo')),
            description=tr("pas de PHP pour sr_r4"),
        )
        self.add_grade_element(
            title=no_tr("sr_r1_push"), max_grade=4, grade_part=part2,
            grade=4 * int(_route_via(sr_k, f"{lo('sr_r4')}/32", [d.sr_srgb + i4], addr('sr_r2', 'sr_l12'))),
            description=tr("sr_r1 : label imposé vers sr_r4"),
        )
        self.add_grade_element(
            title=no_tr("sr_ping"), max_grade=4, grade_part=part2,
            grade=4 * int(sr_ping and all(v >= 5 for v in sr_delta.values())),
            description=tr("ping étiqueté entre les interfaces de bouclage"),
        )
        for key in ('push4', 'label_l23', 'label_l34', 'push3', 'capability', 'subtlv'):
            self.add_grade_element(
                title=no_tr(f"sr_q_{key}"), max_grade=1, grade_part=part2,
                grade=int(_int(q2.get(key)) == int(cheat_sr[key])), description=tr("valeur du segment routing"),
            )
        self.add_grade_element(
            title=no_tr("sr_q_no_php"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('no_php')) == cheat_sr['no_php']), description=tr("effet du drapeau no-PHP"),
        )

        # =====================================================================
        # Part 3 — BFD (bfd)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("bfd"), tr("Partie 3 — BFD (site bfd)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Détecter les pannes avec BFD"),
            hash="abd70fd56495b623",
            description=tr("""
Les routeurs `bfd_r1`, `bfd_r2`, `bfd_r3` et `bfd_r4` forment un carré ; l'hôte `bfd_h1` est derrière
`bfd_r1`, l'hôte `bfd_h4` derrière `bfd_r4`. Le lien `bfd_l12` entre `bfd_r1` et `bfd_r2` passe par
`bfd_sw`, un pont de l'opérateur (sans terminal) : quand il tombe en panne, les interfaces des
routeurs restent actives. Les métriques ({backup} sur `bfd_l13` et `bfd_l34`) font passer le trafic
par `bfd_l12` et `bfd_r2` ; le chemin par `bfd_r3` sert de secours. Les quatre routeurs régénèrent
leurs LSP sans attendre : `lsp-gen-interval 1` est déjà configuré (section @@ref:detection@@).

1. Lancez `ping -i 0.2 bfd_h4` depuis `bfd_h1`, puis une évaluation : elle coupe `bfd_sw` pendant
   {cut} s. Combien de temps le trafic est-il interrompu ? Regardez `show isis neighbor` sur `bfd_r1`
   pendant la coupure : l'adjacence avec `bfd_r2` tombe-t-elle ?
2. Sur `bfd_r1` et `bfd_r2`, créez le profil BFD **`{profile}`** (réception et émission toutes les
   **{interval} ms**, multiplicateur **{mult}**) et protégez avec lui l'adjacence IS-IS du lien
   `bfd_l12` (section @@ref:bfd@@). Vérifiez la session (`show bfd peers`) et `show isis neighbor
   detail`, puis recommencez la mesure.
3. Pour comparer, réglez les temporisateurs d'IS-IS du lien `bfd_l34`, à ses deux extrémités : un
   IIH par seconde, multiplicateur 3. Regardez le temps restant affiché par `show isis neighbor`
   sur `bfd_r3`.
""").format(backup=BFD_BACKUP_METRIC, cut=CUT_SECONDS, profile=BFD_PROFILE, interval=d.bfd_interval,
            mult=d.bfd_multiplier)
            + instructor(tr("""
**Solution.**

{solution}

Sans BFD, la coupure de {cut} s est plus courte que le *holding time* (30 s) : l'adjacence ne tombe
pas et le trafic est perdu pendant toute la coupure. Avec BFD, la session tombe au bout de
{mult} × {interval} = {detection} ms, IS-IS retire l'adjacence et le trafic passe par `bfd_r3` en moins
d'une seconde ; il revient par `bfd_r2` quand l'adjacence se reforme, après la coupure.

Évaluation : `bfd_profile` (2 : le profil de chaque routeur), `bfd_isis` (2 : `isis bfd` sur chaque
interface), `bfd_up` (4 : la session vue de chaque côté), `bfd_timers` (4 : intervalles et
multiplicateur négociés, de chaque côté), `bfd_isis_neighbor` (2 : BFD actif sur l'adjacence vue par
`bfd_r1`), `bfd_failover` (8 : coupure mesurée de moins de {max_outage:g} s, comptée avec la session
BFD), `bfd_hello` (4 : temporisateurs de `bfd_l34`, 2 par extrémité).
""").format(solution=_vtysh_text(ns.solution_bfd()), cut=CUT_SECONDS, mult=d.bfd_multiplier,
            interval=d.bfd_interval, detection=detection, max_outage=MAX_OUTAGE)),
        )
        cheat_bfd = {'port': '3784', 'detection': str(detection), 'hold': '30', 'outage': str(CUT_SECONDS),
                     'fast_hold': '3', 'interface': 'up', 'path': 'r3'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site bfd"),
            hash="2c4b7b65818d3ac1",
            description=tr("""
- port UDP des paquets de contrôle BFD : @@{{port:[0-9]+}}@@
- temps de détection d'une panne par la session BFD de `bfd_r1`, en millisecondes :
  @@{{detection:[0-9]+}}@@
- *holding time* par défaut d'une adjacence IS-IS dans FRR, en secondes : @@{{hold:[0-9]+}}@@
- durée de l'interruption du trafic, en secondes, quand `bfd_sw` est coupé pendant {cut} s, sans
  BFD : @@{{outage:[0-9]+}}@@
- temps restant maximal de l'adjacence avec `bfd_r4` affiché par `bfd_r3`, une fois les
  temporisateurs de `bfd_l34` réglés : @@{{fast_hold:[0-9]+}}@@
- pendant la coupure du pont, l'interface `eth1` de `bfd_r1` est :
  @@{{interface:>active (up)>>>up|inactive (down)>>>down|sans adresse>>>no_address}}@@
- pendant la coupure, avec BFD, le trafic de `bfd_h1` vers `bfd_h4` passe par :
  @@{{path:>bfd_r3>>>r3|bfd_r2>>>r2|nulle part>>>nowhere}}@@
""").format(cut=CUT_SECONDS)
            + instructor(tr("""
**Solution.** **3784** ; **{detection}** ms ({mult} × {interval}) ; **30** s ; **{cut}** s (toute
la coupure : l'adjacence ne tombe pas) ; **3** s ; **active (up)** ; **`bfd_r3`**.

Évaluation : `bfd_q_port`, `bfd_q_detection`, `bfd_q_hold`, `bfd_q_outage`, `bfd_q_fast_hold` (1
chacun) et, pour l'enseignant seulement, `bfd_q_interface`, `bfd_q_path` (1 chacun).
""").format(detection=detection, mult=d.bfd_multiplier, interval=d.bfd_interval, cut=CUT_SECONDS)),
            cheat_answers={"final": cheat_bfd, "solve_bfd": cheat_bfd},
        )

        def profile_ok(router: str) -> bool:
            cfg = bfd_cfg[router]
            name = isis_if(cfg, router, 'bfd_l12').get('bfd_profile')
            profile = cfg['bfd']['profiles'].get(name) if name else None
            return (profile is not None and bfd_profile_value(profile, 'receive_interval') == d.bfd_interval
                    and bfd_profile_value(profile, 'transmit_interval') == d.bfd_interval
                    and bfd_profile_value(profile, 'detect_multiplier') == d.bfd_multiplier)

        def session(router: str, peer: str) -> Dict:
            s = bfd_peers[router].get(str(addr(peer, 'bfd_l12'))) or {}
            return s if s.get('up') and s.get('interface') == iface(router, 'bfd_l12') else {}

        def timers_ok(s: Dict) -> bool:
            return bool(s) and (s.get('receive_interval'), s.get('transmit_interval'), s.get('detect_multiplier')) \
                == (d.bfd_interval, d.bfd_interval, d.bfd_multiplier)

        sessions = {'bfd_r1': session('bfd_r1', 'bfd_r2'), 'bfd_r2': session('bfd_r2', 'bfd_r1')}
        self.add_grade_element(
            title=no_tr("bfd_profile"), max_grade=2, grade_part=part3,
            grade=sum(int(profile_ok(r)) for r in ('bfd_r1', 'bfd_r2')), description=tr("profil BFD"),
        )
        self.add_grade_element(
            title=no_tr("bfd_isis"), max_grade=2, grade_part=part3,
            grade=sum(int(bool(isis_if(bfd_cfg[r], r, 'bfd_l12').get('bfd'))) for r in ('bfd_r1', 'bfd_r2')),
            description=tr("BFD demandé par IS-IS sur bfd_l12"),
        )
        self.add_grade_element(
            title=no_tr("bfd_up"), max_grade=4, grade_part=part3, grade=2 * sum(bool(s) for s in sessions.values()),
            description=tr("session BFD établie"),
        )
        self.add_grade_element(
            title=no_tr("bfd_timers"), max_grade=4, grade_part=part3,
            grade=2 * sum(int(timers_ok(s)) for s in sessions.values()), description=tr("temporisateurs BFD"),
        )
        bfd_neighbor = [n for n in bfd_nb if n['name'] in names('bfd_r2') and n['interface'] == iface('bfd_r1', 'bfd_l12')]
        self.add_grade_element(
            title=no_tr("bfd_isis_neighbor"), max_grade=2, grade_part=part3,
            grade=2 * int(any(n.get('bfd') == 'Up' and n.get('up') for n in bfd_neighbor)),
            description=tr("IS-IS client de la session BFD"),
        )
        replies, outage = _ping_outage(ping_out)
        failover = bool(sessions['bfd_r1']) and replies >= PING_COUNT // 2 and outage is not None \
            and outage < MAX_OUTAGE
        self.add_grade_element(
            title=no_tr("bfd_failover"), max_grade=8, grade_part=part3, grade=8 * int(failover),
            description=tr("trafic rétabli en moins de 3 s après une panne silencieuse"),
        )
        hello = [((bfd_if[r].get(iface(r, 'bfd_l34')) or {}).get('levels', {}).get(2) or {}) for r in ('bfd_r3', 'bfd_r4')]
        self.add_grade_element(
            title=no_tr("bfd_hello"), max_grade=4, grade_part=part3,
            grade=2 * sum(int(h.get('hello_interval') == 1 and h.get('hello_multiplier') == 3) for h in hello),
            description=tr("temporisateurs d'IS-IS de bfd_l34"),
        )
        for key, value in (('port', 3784), ('detection', detection), ('hold', 30), ('outage', CUT_SECONDS),
                           ('fast_hold', 3)):
            self.add_grade_element(
                title=no_tr(f"bfd_q_{key}"), max_grade=1, grade_part=part3, grade=int(_int(q3.get(key)) == value),
                description=tr("valeur de BFD ou d'IS-IS"),
            )
        self.add_grade_element(
            title=no_tr("bfd_q_interface"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('interface')) == 'up'), description=tr("état de l'interface pendant la panne"),
        )
        self.add_grade_element(
            title=no_tr("bfd_q_path"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('path')) == 'r3'), description=tr("chemin de secours"),
        )

        # =====================================================================
        # Bonus — TI-LFA (tl)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("tilfa"), tr("Bonus — TI-LFA (site tl)"))
        r3 = f"{lo('tl_r3')}/32"
        metrics = ", ".join(f"`{n}` {c}" for n, c in TL_METRICS.items())
        self.question_dummy(
            section=self.section(0),
            title=tr("Protection TI-LFA (bonus)"),
            hash="fad4de6865e82fa9",
            description=tr("""
Les routeurs `tl_r1`, `tl_r2`, `tl_r3` et `tl_r4` forment un carré (métriques IS-IS : {metrics}).
IS-IS et le segment routing y fonctionnent (SRGB par défaut, 16000 à 23999 ; l'index du prefix-SID
de `tl_rN` est N). Seul `tl_r1` a un terminal ; il joint `tl_r3` par `tl_r2` (section @@ref:tilfa@@).

1. Regardez la route de `tl_r1` vers l'interface de bouclage de `tl_r3` (`show ip route {r3}`).
2. Activez sur les deux interfaces de `tl_r1` la protection TI-LFA **de nœud** au niveau 2 : le
   secours doit éviter `tl_r2` tout entier.
3. Regardez à nouveau la route : par où passe le secours, avec quels labels ? `show isis
   fast-reroute summary` compte les destinations protégées.
""").format(metrics=metrics, r3=r3)
            + instructor(tr("""
**Solution.**

{solution}

Le secours vers `{r3}` part vers `tl_r4` (`{eth}`) ; sa pile de labels se termine par le prefix-SID
de `tl_r3` (16003). Le calcul est fait d'avance : zebra garde le secours prêt sans l'installer dans le
noyau.

Évaluation (bonus) : `tl_backup` (3 : une route de secours vers `tl_r3`), `tl_node` (1 : protection
de nœud sur les deux interfaces), `tl_repair` (2 : secours par `tl_r4`, pile terminée par le
prefix-SID de `tl_r3`).
""").format(solution=_vtysh_text(ns.solution_tilfa()), r3=r3, eth=iface('tl_r1', 'tl_l14'))),
        )
        backups = (tl_routes.get(r3) or {}).get('backups', [])
        node = all(isis_if(tl_cfg, 'tl_r1', n).get('fast_reroute', {}).get('level-2') == 'node'
                   for n in ROUTER_IFACES['tl_r1'])
        self.add_grade_element(
            title=no_tr("tl_backup"), max_grade=3, grade_part=part4, bonus=True, grade=3 * int(bool(backups)),
            description=tr("route de secours vers tl_r3"),
        )
        self.add_grade_element(
            title=no_tr("tl_node"), max_grade=1, grade_part=part4, bonus=True, grade=int(bool(backups) and node),
            description=tr("protection de nœud"),
        )
        self.add_grade_element(
            title=no_tr("tl_repair"), max_grade=2, grade_part=part4, bonus=True,
            grade=2 * int(any(b['interface'] == iface('tl_r1', 'tl_l14') and b['labels']
                              and b['labels'][-1] == TL_SRGB_BASE + router_number('tl_r3') for b in backups)),
            description=tr("secours par tl_r4 vers le prefix-SID de tl_r3"),
        )


_TRANSLATIONS = {}
