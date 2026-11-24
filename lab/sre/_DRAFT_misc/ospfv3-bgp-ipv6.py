"""IPv6 routing lab with FRR (ospf6d, bgpd): OSPFv3 and BGP over IPv6.

The network is IPv6 only (no IPv4 address anywhere: FRR cannot derive a router-id, the students
set it).  Eight independent sites, one per part (completing a part gives all its points whatever
the others):

- ``o1``: three routers in a triangle and two hosts; OSPFv3 in one area (router-ids, passive LANs,
  a cost that moves the traffic);
- ``o2``: OSPFv3 in two areas: a backbone router that redistributes an outside LAN (ASBR), an ABR
  that summarises area 1 (one /60) and makes it a stub area, an internal router of area 1;
- ``eb``: eBGP / MP-BGP between the students' router (AS 65010) and a given ISP;
- ``ib``: a line of three routers of AS 65020 with OSPFv3 given and the eBGP session of the border
  router given; the students build the iBGP full mesh between loopbacks, with next-hop-self;
- ``po``: AS 65030 with two given ISPs and a given "Internet"; the sessions are given with permit-all
  route-maps; the students set local-preference, AS-path prepend, no transit, bogon filtering;
- ``fix``: a small AS shipped with four faults (MTU mismatch, duplicate router-id, BGP neighbour not
  activated in the IPv6 family, network without route in the RIB);
- ``un`` (bonus): BGP unnumbered on a link without global address;
- ``au`` (bonus): OSPFv3 with the RFC 7166 authentication trailer against a given router.

Every interface has a fixed MAC (EUI-64 link-local addresses known at generation time: the typed
link-local answers have static cheat answers).  Grading reads the json output of vtysh (lib/frr.py),
``ip -j -6 route`` and real pings.  The states ``solve_<part>`` apply the reference solution of one
part, ``final`` all of them.  Facts verified on FRR 9.1.3: memory note frr-ospf6-bgp6-facts; the lab
reaches full marks on the FRR 10.3 of the Debian 13 ``routing-frr`` image too (2026-11-19).
"""
import json
import random
import re
from dataclasses import dataclass
from ipaddress import IPv6Address, IPv6Interface, IPv6Network, ip_network
from typing import Dict, List

import utils
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv6networks, random_mac_address
from net_config import NetConfigEntry, set_net_config_entry, set_ipv6_forward
from ping import eval_ping
from ipv6 import link_local_from_mac, parse_ipv6, same_ipv6
from frr import (
    bgp_best_path, get_bgp_advertised_routes, get_bgp_neighbor, get_bgp_routes, get_bgp_summary,
    get_frr_running_config, get_kernel_routes, get_ospf6_info, get_ospf6_interfaces, get_ospf6_neighbors,
    get_ospf6_routes, is_bgp_protocol, is_ospf_protocol, neighbor_is_full,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("OSPFv3 et BGP : routage IPv6", en="OSPFv3 and BGP: IPv6 routing")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False
ipv6 = True

# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------

# Router interfaces in ethN order: the network of each.  Must match _TOPOLOGY.
ROUTER_IFACES = {
    'o1_r1': ['o1_lan1', 'o1_l12', 'o1_l13'],
    'o1_r2': ['o1_l12', 'o1_l23'],
    'o1_r3': ['o1_lan3', 'o1_l13', 'o1_l23'],
    'o2_r0': ['o2_ext', 'o2_l0'],
    'o2_abr': ['o2_l0', 'o2_l1'],
    'o2_r1': ['o2_l1', 'o2_lan1a', 'o2_lan1b'],
    'eb_r1': ['eb_lan', 'eb_link'],
    'eb_isp': ['eb_link', 'eb_srv_lan'],
    'ib_isp': ['ib_srv_lan', 'ib_link'],
    'ib_r1': ['ib_link', 'ib_l12'],
    'ib_r2': ['ib_l12', 'ib_l23'],
    'ib_r3': ['ib_l23', 'ib_lan'],
    'po_r1': ['po_lan', 'po_la', 'po_lb'],
    'po_ispa': ['po_la', 'po_ia'],
    'po_ispb': ['po_lb', 'po_ib'],
    'po_inet': ['po_ia', 'po_ib', 'po_srv_lan'],
    'fix_r1': ['fix_link', 'fix_l12'],
    'fix_r2': ['fix_l12', 'fix_lan'],
    'fix_isp': ['fix_link', 'fix_srv_lan'],
    'un_r1': ['un_link'],
    'un_r2': ['un_link'],
    'au_r1': ['au_link'],
    'au_r2': ['au_link'],
}
# Hosts (one interface, eth0): their network and the router of their default route
HOSTS = {
    'o1_h1': ('o1_lan1', 'o1_r1'),
    'o1_h3': ('o1_lan3', 'o1_r3'),
    'o2_h1': ('o2_lan1a', 'o2_r1'),
    'o2_srv': ('o2_ext', 'o2_r0'),
    'eb_h': ('eb_lan', 'eb_r1'),
    'eb_srv': ('eb_srv_lan', 'eb_isp'),
    'ib_h': ('ib_lan', 'ib_r3'),
    'ib_srv': ('ib_srv_lan', 'ib_isp'),
    'po_h': ('po_lan', 'po_r1'),
    'po_srv': ('po_srv_lan', 'po_inet'),
    'fix_h': ('fix_lan', 'fix_r2'),
    'fix_srv': ('fix_srv_lan', 'fix_isp'),
}
# routers of the operators and given peers: configured by the lab, no terminal
OPERATORS = ('eb_isp', 'ib_isp', 'po_ispa', 'po_ispb', 'po_inet', 'fix_isp', 'un_r2', 'au_r2')
OSPF6_ROUTERS = ('o1_r1', 'o1_r2', 'o1_r3', 'o2_r0', 'o2_abr', 'o2_r1', 'ib_r1', 'ib_r2', 'ib_r3', 'fix_r1',
                 'fix_r2', 'au_r1', 'au_r2')
BGP_ROUTERS = ('eb_r1', 'eb_isp', 'ib_isp', 'ib_r1', 'ib_r2', 'ib_r3', 'po_r1', 'po_ispa', 'po_ispb', 'po_inet',
               'fix_r1', 'fix_isp', 'un_r1', 'un_r2')

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

SITE_COLORS = {'o1': 'lightblue', 'o2': 'khaki', 'eb': 'palegreen', 'ib': 'lightpink', 'po': 'plum',
               'fix': 'lightsalmon', 'un': 'lightcyan', 'au': 'wheat'}

# ---------------------------------------------------------------------------
# addressing: one /32 of 3fff::/20 (RFC 9637, documentation) per instance; one /48 per AS or
# site (its third group: BLOCKS), one /64 per network (NET6_PLAN: block, subnet number)
# ---------------------------------------------------------------------------

DOC_SPACE = IPv6Network('3fff::/20')
BLOCKS = {
    'o1': 0x100, 'o2': 0x200, 'eb': 0x300, 'eb_isp': 0x310, 'ib': 0x400, 'ib_isp': 0x410,
    'po': 0x500, 'po_ispa': 0x510, 'po_ispb': 0x520, 'po_inet': 0x530, 'fix': 0x600, 'fix_isp': 0x610,
    'un': 0x700, 'au': 0x800,
}
NET6_PLAN = {
    'o1_lan1': ('o1', 0x1), 'o1_lan3': ('o1', 0x3), 'o1_l12': ('o1', 0x12), 'o1_l13': ('o1', 0x13),
    'o1_l23': ('o1', 0x23),
    # area 1 of o2 (l1, lan1a, lan1b) = one /60: o2:10::/60
    'o2_ext': ('o2', 0xe0), 'o2_l0': ('o2', 0x1), 'o2_l1': ('o2', 0x10), 'o2_lan1a': ('o2', 0x11),
    'o2_lan1b': ('o2', 0x12),
    'eb_lan': ('eb', 0x1), 'eb_link': ('eb_isp', 0xc1), 'eb_srv_lan': ('eb_isp', 0x1),
    'ib_lan': ('ib', 0x1), 'ib_l12': ('ib', 0x12), 'ib_l23': ('ib', 0x23), 'ib_link': ('ib_isp', 0xc1),
    'ib_srv_lan': ('ib_isp', 0x1),
    'po_lan': ('po', 0x1), 'po_la': ('po_ispa', 0xc1), 'po_lb': ('po_ispb', 0xc1), 'po_ia': ('po_inet', 0xa),
    'po_ib': ('po_inet', 0xb), 'po_srv_lan': ('po_inet', 0x1),
    'fix_lan': ('fix', 0x1), 'fix_l12': ('fix', 0x12), 'fix_link': ('fix_isp', 0xc1), 'fix_srv_lan': ('fix_isp', 0x1),
    'au_link': ('au', 0x1),
    # un_link: no global address (link-local only: BGP unnumbered)
}
O2_AREA1_SUBNET = 0x10           # o2:10::/60 = the range of area 1
O2_AREA1_PREFIXLEN = 60
LOOPBACK_SUBNET = 0xff           # loopbacks: <block>:ff::<n>/128
LOOPBACKS = {'ib_r1': ('ib', 1), 'ib_r2': ('ib', 2), 'ib_r3': ('ib', 3), 'un_r1': ('un', 1), 'un_r2': ('un', 2)}
# interface identifier of each router on its networks (the ISP side of a customer link is ::1)
ROUTER_IDS6 = {
    'o1_r1': 1, 'o1_r2': 2, 'o1_r3': 3, 'o2_r0': 1, 'o2_abr': 2, 'o2_r1': 3,
    'eb_isp': 1, 'eb_r1': 2, 'ib_isp': 1, 'ib_r1': 2, 'ib_r2': 3, 'ib_r3': 4,
    'po_ispa': 1, 'po_ispb': 1, 'po_inet': 2, 'po_r1': 2, 'fix_isp': 1, 'fix_r1': 2, 'fix_r2': 3,
    'au_r1': 1, 'au_r2': 2,
}
# po_ia / po_ib: the ISP is ::1, po_inet ::2 (ROUTER_IDS6 above)

# router-ids (32 bits, given): <site number>.0.0.<n>
ROUTER_ID = {
    'o1_r1': '1.0.0.1', 'o1_r2': '1.0.0.2', 'o1_r3': '1.0.0.3',
    'o2_r0': '2.0.0.1', 'o2_abr': '2.0.0.2', 'o2_r1': '2.0.0.3',
    'eb_r1': '3.0.0.1', 'eb_isp': '3.0.0.100',
    'ib_r1': '4.0.0.1', 'ib_r2': '4.0.0.2', 'ib_r3': '4.0.0.3', 'ib_isp': '4.0.0.100',
    'po_r1': '5.0.0.1', 'po_ispa': '5.0.0.101', 'po_ispb': '5.0.0.102', 'po_inet': '5.0.0.100',
    'fix_r1': '6.0.0.1', 'fix_r2': '6.0.0.2', 'fix_isp': '6.0.0.100',
    'un_r1': '7.0.0.1', 'un_r2': '7.0.0.2',
    'au_r1': '8.0.0.1', 'au_r2': '8.0.0.2',
}
STUDENT_ROUTERS = [r for r in ROUTER_IFACES if r not in OPERATORS]

AS_OF = {'eb_r1': 65010, 'eb_isp': 65100, 'ib_r1': 65020, 'ib_r2': 65020, 'ib_r3': 65020, 'ib_isp': 65200,
         'po_r1': 65030, 'po_ispa': 65110, 'po_ispb': 65120, 'po_inet': 65000, 'fix_r1': 65040, 'fix_isp': 65300,
         'un_r1': 65050, 'un_r2': 65051}

O1_COSTS = (30, 40, 50)
FIX_MTUS = (1400, 1420, 1450)
AUTH_ALGO = 'hmac-sha-256'
PREPEND_COUNT = 2                 # part 5: po_r1 prepends its AS twice towards ISP B
LOCAL_PREF = 200
BOGON_DOC = IPv6Network('2001:db8::/32')
GLOBAL_UNICAST = IPv6Network('2000::/3')
MAX_ACCEPTED_PREFIXLEN = 48
MAC_PREFIX = "02:53:52"           # locally administered addresses
# Creation-time sysctls (Kathara meta): EUI-64 link-local addresses whatever the host's defaults
SYSCTLS = ('net.ipv6.conf.default.addr_gen_mode=0', 'net.ipv6.conf.default.use_tempaddr=0',
           'net.ipv6.conf.all.use_tempaddr=0')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE
# the reference states wait for the OSPFv3 adjacencies: a broadcast interface stays `Waiting`
# for a Dead interval (40 s) before its DR election
OSPF_WAIT = 50
BGP_WAIT = 15

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP{note}
# (zebra, staticd et watchfrr démarrent toujours)
bgpd={bgpd}
ospfd=no
ospf6d={ospf6d}
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
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
    """Name of the interface of *router* on *net* (``eth2``)."""
    return f"eth{ROUTER_IFACES[router].index(net)}"


def frr_daemons(router: str) -> str:
    ospf6d, bgpd = router in OSPF6_ROUTERS, router in BGP_ROUTERS
    note = " : " + " et ".join(name for name, on in (("ospf6d", ospf6d), ("bgpd", bgpd)) if on) + " activés"
    return FRR_DAEMONS.format(bgpd='yes' if bgpd else 'no', ospf6d='yes' if ospf6d else 'no', note=note)


def _subnet(block: IPv6Network, number: int, prefixlen: int = 64) -> IPv6Network:
    return IPv6Network((int(block.network_address) + (number << (128 - prefixlen)), prefixlen))


def _host(network: IPv6Network, identifier: int) -> IPv6Interface:
    return IPv6Interface((int(network.network_address) + identifier, network.prefixlen))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    o1_cost: int = 0                # part 1: OSPFv3 cost of the link o1_l13 (both ends)
    fix_mtu: int = 0                # part 6: MTU of fix_r2's eth0 (the fault)
    au_key: str = ""                # bonus: key of the OSPFv3 authentication trailer
    au_key_id: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.o1_cost = random.choice(O1_COSTS)
        data.fix_mtu = random.choice(FIX_MTUS)
        data.au_key = utils.random_password(12)     # letters and digits: typed as is in vtysh
        data.au_key_id = random.randint(1, 255)

        data.nets6.instance = random_ipv6networks(32, from_network=DOC_SPACE)[0]
        for name, number in BLOCKS.items():
            setattr(data.nets6, f"as_{name}", _subnet(data.nets6.instance, number, 48))
        for net, (block, number) in NET6_PLAN.items():
            setattr(data.nets6, net, _subnet(getattr(data.nets6, f"as_{block}"), number))
        data.nets6.o2_area1 = _subnet(data.nets6.as_o2, O2_AREA1_SUBNET >> 4, O2_AREA1_PREFIXLEN)
        for router, (block, number) in LOOPBACKS.items():
            loopbacks = _subnet(getattr(data.nets6, f"as_{block}"), LOOPBACK_SUBNET)
            setattr(data.ips6, f"{router}_lo", IPv6Interface((int(loopbacks.network_address) + number, 128)))
        for router, nets in ROUTER_IFACES.items():
            for net in nets:
                if net in NET6_PLAN:
                    setattr(data.ips6, f"{router}_{net}", _host(getattr(data.nets6, net), ROUTER_IDS6[router]))
        for host, (net, _gw) in HOSTS.items():
            setattr(data.ips6, host, _host(getattr(data.nets6, net), 0x100 + random.randint(1, 0xeff)))

        # part 5: what ISP B sends besides real routes (to be filtered by po_r1)
        data.nets6.junk_ula = random_ipv6networks(48, from_private_network=True)[0]
        data.nets6.junk_doc = random_ipv6networks(48, from_network=BOGON_DOC)[0]
        data.nets6.junk_long = _subnet(data.nets6.as_po_ispb, random.randint(0x100, 0xfff))

        # one fixed MAC per interface: the link-local addresses are known in advance
        keys = [f"{m}_{i}" for m in MACHINES for i in range(len(ROUTER_IFACES.get(m, [None])))]
        macs = random_mac_address(prefix=MAC_PREFIX, n=len(keys))
        for key, mac in zip(keys, random.sample(macs, len(macs))):
            setattr(data.macs, key, mac)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'image': sre_docker_image("routing-frr"), 'color': SITE_COLORS[site_of(machine)], 'sysctls': SYSCTLS}
    if machine in ROUTER_IFACES:
        spec['shape'] = 'box'
    if machine in OPERATORS:
        spec['allow_connection'] = False
    return spec


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in MACHINES}
    _network_specs = {}

    @property
    def _topology(self):
        macs = self.data.macs
        return {net: {m: (i, getattr(macs, f"{m}_{i}")) for m, i in members.items()}
                for net, members in _TOPOLOGY.items()}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default6 = IPv6Network("::/0")

        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, nets in ROUTER_IFACES.items():
            self.net_config[r] = [([getattr(d.ips6, f"{r}_{net}")] if net in NET6_PLAN else [], []) for net in nets]
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([getattr(d.ips6, h)], [(default6, getattr(d.ips6, f"{gw}_{net}").ip)])]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX
        lines = []
        for r, nets in ROUTER_IFACES.items():
            named = False
            for i, net in enumerate(nets):
                if net not in NET6_PLAN:
                    continue
                names = f"{r}-eth{i}" if named else f"{r}\t{r}-eth{i}"
                named = True
                lines.append(f"{getattr(d.ips6, f'{r}_{net}').ip}\t{names}")
        for r in LOOPBACKS:
            lines.append(f"{self.lo(r)}\t{r}-lo" + ("" if r not in ('un_r1', 'un_r2') else f"\t{r}"))
        for h in HOSTS:
            lines.append(f"{getattr(d.ips6, h).ip}\t{h}")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses ---------------------------------------------------------------

    def addr(self, router: str, net: str) -> IPv6Address:
        """Global address (without prefix) of *router* on *net*."""
        return getattr(self.data.ips6, f"{router}_{net}").ip

    def lo(self, router: str) -> IPv6Address:
        return getattr(self.data.ips6, f"{router}_lo").ip

    def block(self, name: str) -> IPv6Network:
        """The /48 of an AS or site (``'eb'``, ``'po_ispa'``...)."""
        return getattr(self.data.nets6, f"as_{name}")

    def net(self, name: str) -> IPv6Network:
        return getattr(self.data.nets6, name)

    def ll(self, machine: str, net: str) -> IPv6Address:
        """Link-local address of the interface of *machine* on *net* (EUI-64 of its fixed MAC)."""
        index = ROUTER_IFACES[machine].index(net) if machine in ROUTER_IFACES else 0
        return link_local_from_mac(getattr(self.data.macs, f"{machine}_{index}"))

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("IPv6 et le routage dynamique"), tag="ipv6-routing")
            + tr("""
Les protocoles de routage d'IPv6 reprennent ceux d'IPv4 (OSPF, BGP, RIP, IS-IS), avec quelques
changements qui se voient dès les premières commandes :

- **Les routeurs se parlent en adresses link-local** (`fe80::/10`). Chaque interface en a une,
  construite à partir de son adresse MAC (EUI-64) ou au hasard, toujours présente même sans
  adresse globale. Un routeur OSPFv3 émet ses paquets depuis sa link-local, et le **prochain
  saut** d'une route apprise est une link-local, qui n'a de sens qu'avec l'interface :
  `via fe80::53:52ff:fe12:3456 dev eth1`. Une renumérotation des préfixes globaux ne casse donc
  pas le routage.
- **Le router-id reste un nombre de 32 bits**, écrit comme une adresse IPv4 (`1.0.0.1`), en
  OSPFv3 comme en BGP. Il identifie le routeur, il n'est pas une adresse. FRR le prend d'habitude
  dans les adresses IPv4 du routeur ; sur un routeur **purement IPv6** il n'y en a pas : il faut
  le configurer à la main (`ospf6 router-id`, `bgp router-id`), unique dans le domaine. Sans
  router-id, OSPFv3 ne démarre pas et une session BGP ne s'établit pas.
- **Multicast** : OSPFv3 envoie ses *Hello* à `ff02::5` (*AllSPFRouters*) et le DR et le BDR
  écoutent aussi `ff02::6` (*AllDRouters*), à portée lien.
- Les routeurs doivent relayer les paquets IPv6 : `net.ipv6.conf.all.forwarding=1` (déjà actif
  sur les routeurs du TP).

**Plan d'adressage.** Les adresses du TP sont prises dans `3fff::/20`, le bloc réservé à la
documentation par la RFC 9637 (2024), qui joue ici le rôle de l'espace public : en vrai, il faut
le filtrer comme `2001:db8::/32`. L'usage est d'attribuer un **/48 par site** (ou par
organisation), un **/64 par réseau** (même un lien entre deux routeurs, par simplicité) et un
**/128 par adresse de bouclage**.
""")
            + info_subtitle(tr("OSPFv3"), tag="ospfv3")
            + tr("""
OSPFv3 (RFC 5340) est OSPF pour IPv6 : même algorithme (chaque routeur connaît la carte de sa
zone et calcule les plus courts chemins avec Dijkstra), mêmes zones, mêmes états de voisinage.
Ce qui change :

| | OSPFv2 (IPv4) | OSPFv3 (IPv6) |
|---|---|---|
| transport | IPv4, protocole 89 | IPv6, en-tête suivant 89, source link-local |
| fonctionne | par sous-réseau | par lien (plusieurs préfixes par lien possibles) |
| voisin identifié par | son adresse sur le réseau partagé | son router-id |
| adresses dans les LSA Router / Network | oui | non : des LSA à part portent les préfixes |
| authentification | dans l'en-tête | IPsec ou *trailer* (section @@ref:ospfv3-auth@@) |
| plusieurs instances par lien | non | oui (*Instance ID*) |

**Les LSA.** OSPFv3 sépare la **topologie** (qui est relié à qui) des **préfixes** : un
changement d'adresse ne relance pas le calcul de la topologie.

| type | nom | portée | contenu |
|------|-----|--------|---------|
| 0x2001 | Router-LSA | zone | les liens du routeur (voisins, réseaux de transit), ses bits B (ABR) et E (ASBR) |
| 0x2002 | Network-LSA | zone | émise par le DR : les routeurs attachés au réseau |
| 0x2003 | Inter-Area-Prefix-LSA | zone | émise par un ABR : un préfixe d'une autre zone |
| 0x2004 | Inter-Area-Router-LSA | zone | émise par un ABR : un ASBR d'une autre zone |
| 0x4005 | AS-External-LSA | domaine | émise par un ASBR : une route externe |
| 0x2007 | NSSA-LSA | zone | route externe dans une zone NSSA |
| 0x0008 | Link-LSA | lien | la link-local du routeur et les préfixes qu'il a sur ce lien |
| 0x2009 | Intra-Area-Prefix-LSA | zone | les préfixes d'un routeur ou d'un réseau de transit de la zone |

**Voisinage.** Deux routeurs deviennent voisins s'ils sont d'accord sur la zone, les intervalles
*Hello* / *Dead* (10 s / 40 s par défaut), le type de zone et l'*Instance ID*. Les états
successifs : `Down`, `Init` (j'entends l'autre, il ne m'a pas encore cité), `2-Way` (`Twoway` :
on se voit tous les deux), puis, pour les routeurs qui doivent synchroniser leurs bases,
`ExStart` (négociation de l'échange), `Exchange` (description des bases, paquets DD), `Loading`
(demande des LSA manquantes) et `Full`. Les paquets DD portent le **MTU** de l'interface : un
voisin dont le MTU diffère est refusé et le voisinage reste bloqué en `ExStart` / `Exchange`
(sauf `ipv6 ospf6 mtu-ignore` des deux côtés).

**DR et BDR.** Sur un réseau multipoint (type `BROADCAST`, celui des interfaces Ethernet), les
routeurs élisent un routeur désigné (DR) et un secours (BDR), avec qui seuls ils forment un
voisinage `Full` ; avant l'élection, une interface reste dans l'état `Waiting` pendant un
intervalle *Dead* (40 s). Sur un lien entre deux routeurs, `ipv6 ospf6 network point-to-point`
supprime l'élection et l'attente.

**Coût.** Chaque interface a un coût (par défaut la bande passante de référence divisée par
celle de l'interface : **10** sur les interfaces du TP) ; le coût d'un chemin est la somme des
coûts des interfaces de **sortie** traversées, et chaque routeur calcule ses chemins seul : pour
un trajet symétrique, il faut le même coût aux deux bouts d'un lien.

**Interface passive.** Une interface passive est annoncée (son préfixe est dans les LSA) mais
n'envoie pas de *Hello* : c'est ce qu'on veut sur un réseau d'hôtes, où aucun routeur ne doit
s'inviter.
""")
            + info_subtitle(tr("Zones, ABR, résumés, zones terminales"), level=2, tag="ospfv3-areas")
            + tr("""
Un domaine OSPF se découpe en **zones** autour de la zone **0** (*backbone*) : chaque zone ne
connaît le détail que de sa propre topologie, ce qui limite la taille des bases et le coût des
calculs. Un **ABR** (*Area Border Router*) a des interfaces dans la zone 0 et dans une autre
zone ; il résume chaque zone pour les autres avec des **Inter-Area-Prefix-LSA** (un préfixe et
un coût, sans topologie).

- **Résumé** : `area 1 range 3fff:x:y:10::/60` sur l'ABR remplace, dans les autres zones, tous
  les préfixes de la zone 1 compris dans ce /60 par **une seule** Inter-Area-Prefix-LSA. Pour que
  le résumé marche, le plan d'adressage doit le permettre : tous les réseaux de la zone dans un
  même bloc.
- **Zone terminale** (*stub*) : une zone qui n'a qu'une sortie n'a pas besoin des routes
  externes (AS-External-LSA) : `area 1 stub`, sur **tous** les routeurs de la zone (le type de
  zone fait partie des conditions du voisinage), et l'ABR y injecte à la place une **route par
  défaut** (`::/0`, une Inter-Area-Prefix-LSA). `area 1 stub no-summary` (zone *totally stubby*,
  sur l'ABR) supprime aussi les préfixes des autres zones : il ne reste que la route par défaut.
- **NSSA** : une zone terminale qui a quand même son propre ASBR (NSSA-LSA, traduites en
  AS-External-LSA par l'ABR).
""")
            + info_subtitle(tr("Routes externes"), level=2, tag="ospfv3-external")
            + tr("""
Un routeur qui injecte dans OSPF des routes venues d'ailleurs (réseaux connectés hors OSPF,
routes statiques, BGP) est un **ASBR** (bit E de sa Router-LSA) ; chaque route devient une
**AS-External-LSA**, diffusée dans tout le domaine sauf les zones terminales.

- `redistribute connected` (ou `static`, `kernel`, `bgp`) dans `router ospf6` ;
- type de métrique : **E2** par défaut (le coût externe seul, le même partout), **E1** (coût
  externe + coût interne jusqu'à l'ASBR) avec `metric-type 1` ;
- `default-information originate` annonce une route par défaut externe si le routeur en a une ;
  avec `always`, même sans.

Dans `show ipv6 ospf6 route`, la deuxième colonne donne le type : `IA` (*intra-area*), `IE`
(*inter-area*), `E1`, `E2`.
""")
            + info_subtitle(tr("Authentification"), level=2, tag="ospfv3-auth")
            + tr("""
L'en-tête d'OSPFv3 n'a plus de champ d'authentification : la RFC 5340 comptait sur **IPsec**
(AH ou ESP, RFC 4552), lourd à déployer. La **RFC 7166** ajoute un **trailer d'authentification**
à la fin des paquets OSPFv3 : un identifiant de clé (*key ID*), un numéro de séquence (contre le
rejeu) et un HMAC du paquet (SHA-1, SHA-256, SHA-384, SHA-512) calculé avec une clé partagée.

Avec FRR, sur chaque interface du lien :

```
interface eth0
 ipv6 ospf6 authentication key-id 7 hash-algo hmac-sha-256 key UneCleSecrete
```

(ou `ipv6 ospf6 authentication keychain NOM` avec un trousseau de clés). Un routeur qui exige
le trailer **ignore** les paquets sans trailer ou mal signés : le voisinage ne se forme pas, ou
tombe au bout de l'intervalle *Dead*. `show ipv6 ospf6 interface` montre le type
d'authentification et le nombre de paquets rejetés. La clé est en clair dans la configuration.
""")
            + info_subtitle(tr("OSPFv3 avec FRR"), tag="frr-ospf6")
            + tr("""
Le démon d'OSPFv3 est **`ospf6d`** (activé dans `/etc/frr/daemons` sur les routeurs qui en ont
besoin). On le configure dans `vtysh`, comme le reste de FRR : `configure terminal`, les
commandes, `end`, puis `write` pour enregistrer.

```
router ospf6
 ospf6 router-id 1.0.0.1
 area 1 stub
 area 1 range 3fff:x:y:10::/60
 redistribute connected
 default-information originate always
exit
interface eth0
 ipv6 ospf6 area 0
 ipv6 ospf6 passive
 ipv6 ospf6 cost 40
 ipv6 ospf6 network point-to-point
exit
```

Une interface entre dans OSPFv3 par `ipv6 ospf6 area N` **dans son bloc `interface`** (il n'y a
pas de commande `network` comme en OSPFv2 : OSPFv3 annonce tous les préfixes de l'interface).
**Un changement de router-id ne prend effet qu'après `clear ipv6 ospf6 process`.**

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ipv6 ospf6` | router-id, zones (et leur type), interfaces de chaque zone |
| `show ipv6 ospf6 interface [ethX]` | zone, coût, état (DR, BDR, `Waiting`...), passive, MTU, authentification |
| `show ipv6 ospf6 neighbor` | voisins (par router-id), état, interface |
| `show ipv6 ospf6 database` | la base de LSA (`Rtr`, `Net`, `INP` = Intra-Area-Prefix, `IAP` = Inter-Area-Prefix, `ASE`, `Lnk`) |
| `show ipv6 ospf6 route` | les routes calculées, avec leur type et leur prochain saut |
| `show ipv6 ospf6 border-routers` | les ABR (bit B) et ASBR (bit E) connus |
| `show ipv6 route` | la table de routage de zebra (`O` = OSPFv3, `B` = BGP, `C` = connecté) |

La plupart des `show` acceptent `json` en dernier mot.
""")
            + info_subtitle(tr("BGP multiprotocole"), tag="mpbgp")
            + tr("""
BGP-4 ne transportait que des préfixes IPv4. Les **extensions multiprotocoles** (MP-BGP,
RFC 4760) lui font transporter d'autres familles d'adresses, chacune repérée par un couple
**AFI / SAFI** (*Address Family Identifier* / *Subsequent AFI*) :

| AFI / SAFI | famille |
|-----------|---------|
| 1 / 1 | IPv4 unicast |
| 2 / 1 | IPv6 unicast |
| 1 / 2, 2 / 2 | IPv4, IPv6 multicast (RPF) |
| 1 / 128, 2 / 128 | VPN IPv4, VPN IPv6 (MPLS L3VPN) |
| 25 / 70 | EVPN |

- À l'ouverture de la session, chaque routeur annonce dans son OPEN la capacité
  *Multiprotocol* pour chaque famille qu'il veut échanger ; une famille n'est échangée que si les
  deux l'annoncent.
- Les préfixes d'une autre famille qu'IPv4 voyagent dans l'attribut **MP_REACH_NLRI** (type 14 :
  AFI, SAFI, **prochain saut**, préfixes), leurs retraits dans **MP_UNREACH_NLRI** (type 15) ;
  les champs NLRI et NEXT_HOP de BGP-4 ne servent qu'à IPv4.
- **Le prochain saut IPv6** (RFC 2545) est une adresse globale, suivie de la **link-local** du
  routeur quand le voisin est sur le même lien (32 octets en tout). Le routeur qui reçoit la
  route installe la link-local dans le noyau : `via fe80::… dev eth1`.
- La **famille est indépendante du transport** : une session TCP sur IPv6 peut transporter des
  préfixes IPv4 et inversement.

**Avec FRR**, une famille se configure dans un bloc `address-family`. Par défaut, chaque voisin
est activé en IPv4 unicast seulement : sur un réseau IPv6, on désactive ce défaut avec
`no bgp default ipv4-unicast` et on **active** chaque voisin dans la famille IPv6 :

```
router bgp 65010
 bgp router-id 3.0.0.1
 no bgp default ipv4-unicast
 neighbor 3fff:x:y:c1::1 remote-as 65100
 address-family ipv6 unicast
  network 3fff:x:300::/48
  neighbor 3fff:x:y:c1::1 activate
  neighbor 3fff:x:y:c1::1 route-map ALL in
  neighbor 3fff:x:y:c1::1 route-map ALL out
 exit-address-family
exit
```

Un voisin activé dans **aucune** famille reste `Idle` : la session ne démarre même pas.
""")
            + info_subtitle(tr("eBGP"), level=2, tag="ebgp")
            + tr("""
- La session eBGP se monte en général entre les adresses des deux routeurs sur le lien qui les
  relie (TTL 1 par défaut).
- **RFC 8212** : FRR n'échange rien avec un voisin eBGP tant qu'il n'a pas de politique en
  entrée et en sortie (état `(Policy)` dans `show bgp ipv6 unicast summary`). Une politique
  « tout accepter » suffit : `route-map ALL permit 10`, appliquée en `in` et en `out`.
- **`network P`** annonce le préfixe P **s'il est dans la table de routage** (*import-check*).
  Pour annoncer son /48 alors qu'on n'a que des /64, on installe une route vers le trou noir :
  `ipv6 route 3fff:x:300::/48 blackhole` (les /64, plus précis, restent utilisés pour les
  paquets ; le /48 ne sert qu'aux adresses non attribuées). Un préfixe sans route apparaît dans
  `show bgp ipv6 unicast P` comme `inaccessible, import-check enabled` et n'est pas annoncé.
- On annonce son **agrégat** (/48), pas le détail de ses réseaux.
""")
            + info_subtitle(tr("iBGP"), level=2, tag="ibgp")
            + tr("""
Dans un AS qui a plusieurs routeurs BGP, ceux-ci échangent les routes externes en **iBGP**
(même numéro d'AS des deux côtés). Trois règles en découlent :

- **Pas de relais iBGP → iBGP** : une route apprise d'un voisin iBGP n'est pas réannoncée à un
  autre voisin iBGP (l'AS_PATH ne change pas dans l'AS : rien ne détecterait une boucle). Chaque
  routeur doit donc avoir une session avec **chacun** des autres (**maillage complet** :
  n(n-1)/2 sessions pour n routeurs), ou passer par des **réflecteurs de routes**.
- **Sessions entre adresses de bouclage** : une adresse de bouclage (`/128` sur `lo`) ne tombe
  avec aucune interface ; tant que l'IGP (ici OSPFv3) trouve un chemin, la session tient.
  `neighbor X update-source lo` fait partir la session de la boucle locale. L'IGP doit annoncer
  les adresses de bouclage.
- **Le prochain saut ne change pas en iBGP** : une route apprise en eBGP est transmise en iBGP
  avec le prochain saut d'origine (l'adresse du voisin externe, sur un lien que l'IGP ne connaît
  souvent pas). **`next-hop-self`** sur le routeur de bordure remplace ce prochain saut par sa
  propre adresse (celle de `update-source`, donc sa boucle), que tous les routeurs savent
  joindre.

L'IGP ne transporte que les préfixes internes (liens, boucles, réseaux d'hôtes), jamais la
table Internet : **tout routeur traversé par le trafic vers l'extérieur doit connaître les routes
externes**, donc parler BGP, même s'il n'a aucun voisin externe.
""")
            + info_subtitle(tr("Politiques de routage"), level=2, tag="policies")
            + tr("""
**Choix du meilleur chemin** (pour un même préfixe, FRR compare les chemins dans cet ordre et
s'arrête au premier critère qui les départage) :

1. le plus grand **weight** (local au routeur, propre à FRR / Cisco) ;
2. la plus grande **local-preference** (100 par défaut ; transmise en iBGP, commune à tout l'AS) ;
3. une route d'origine locale (`network`, `redistribute`, agrégat) ;
4. l'**AS_PATH le plus court** ;
5. l'origine (IGP < EGP < incomplete) ;
6. le plus petit **MED** (comparé seulement entre chemins venant du même AS voisin) ;
7. eBGP plutôt qu'iBGP ;
8. le plus petit coût IGP jusqu'au prochain saut ;
9. le chemin le plus ancien, puis le plus petit router-id...

**Leviers.** Pour choisir par où **sort** le trafic, on agit sur les routes **reçues** :
`set local-preference 200` sur celles d'un fournisseur fait préférer ce fournisseur par tout
l'AS. Pour influencer par où le trafic **entre**, on agit sur ses **annonces** : `set as-path
prepend 65030 65030` rallonge l'AS_PATH annoncé à un fournisseur, et le reste de l'Internet
préfère alors l'autre chemin (le MED, lui, ne s'adresse qu'aux routeurs d'un même AS voisin).

**Listes de préfixes IPv6** : `ipv6 prefix-list NOM seq N permit|deny PRÉFIXE [ge X] [le Y]`
(un préfixe correspond s'il est dans PRÉFIXE et si sa longueur est entre `ge` et `le` ; sans
`ge` ni `le`, il doit être exactement PRÉFIXE ; refus implicite à la fin). Une **route-map** est
une suite d'entrées numérotées `permit` / `deny`, chacune avec ses conditions (`match ipv6
address prefix-list NOM`) et ses actions (`set ...`) ; une route qui ne correspond à aucune
entrée est refusée. Une route-map s'applique à un voisin dans sa famille :
`neighbor X route-map NOM in|out`. Après une modification, `clear bgp ipv6 unicast * soft`
(ou `clear bgp ipv6 unicast X soft in|out`) fait réévaluer les routes sans couper la session.

**Filtrer ce qu'on reçoit.** On n'accepte pas les **bogons**, ces préfixes qui n'ont rien à
faire sur l'Internet : adresses uniques locales `fc00::/7`, documentation `2001:db8::/32` (et
`3fff::/20`), link-local `fe80::/10`, multicast `ff00::/8`, et en général tout ce qui n'est pas
dans l'espace unicast global `2000::/3`. On refuse aussi les préfixes **trop longs** : l'usage
est de ne pas accepter plus précis qu'un **/48** en IPv6 (`le 48`), pour limiter la taille de la
table et les détournements par préfixe plus spécifique.

**Ne pas devenir un AS de transit.** Un client relié à deux fournisseurs ne doit annoncer à
chacun que **ses propres préfixes** : s'il réannonce à B les routes apprises de A, B peut faire
passer par lui le trafic destiné à A. Un filtre en sortie qui n'autorise que son /48 l'empêche.
""")
            + info_subtitle(tr("BGP sans adresse (unnumbered)"), level=2, tag="unnumbered")
            + tr("""
Puisque chaque interface IPv6 a une link-local, deux routeurs voisins peuvent monter leur
session BGP **sans aucune adresse globale sur le lien** : c'est le BGP *unnumbered*, très
utilisé dans les centres de données.

```
router bgp 65050
 bgp router-id 7.0.0.1
 no bgp default ipv4-unicast
 neighbor eth0 interface remote-as external
 address-family ipv6 unicast
  neighbor eth0 activate
  ...
```

- `neighbor eth0 interface` : le voisin est désigné par l'interface ; FRR apprend son adresse
  link-local par les annonces de routeur (RA) que zebra active sur cette interface ;
- `remote-as external` (ou `internal`) : n'importe quel AS autre que le sien (ou le même), sans
  avoir à le connaître ;
- la session et les prochains sauts sont des link-local ; dans `show bgp ipv6 unicast summary`,
  le voisin s'appelle `eth0`.

Le même mécanisme permet, avec l'extension *extended next hop* (RFC 8950), d'annoncer des
préfixes **IPv4** avec un prochain saut IPv6 : un cœur de réseau sans aucune adresse IPv4.
""")
            + info_subtitle(tr("BGP avec FRR"), tag="frr-bgp")
            + tr("""
Le démon BGP est **`bgpd`**. Les commandes utiles, dans `vtysh` :

| commande | ce qu'elle montre |
|----------|-------------------|
| `show bgp ipv6 unicast summary` | les voisins actifs en IPv6 : état (`Established`, `Active`, `Idle`...), `(Policy)`, préfixes reçus / envoyés |
| `show bgp summary` | toutes les familles |
| `show bgp neighbors X` | le détail d'une session : familles négociées, temporisateurs, politiques, prochains sauts envoyés |
| `show bgp ipv6 unicast` | la table BGP : `*` valide, `>` meilleur, `i` appris en iBGP, prochain saut, AS_PATH |
| `show bgp ipv6 unicast P` | les chemins de P en détail (prochains sauts global et link-local, attributs, raison du choix) |
| `show bgp ipv6 unicast neighbors X advertised-routes` | ce qui est annoncé à X, après la politique de sortie |
| `show bgp ipv6 unicast neighbors X routes` | ce qui est accepté de X |
| `show ipv6 route` | la table de zebra (`B` = BGP) |

Dans le noyau (`ip -6 route`), les routes de bgpd ont `proto bgp`, celles d'ospf6d `proto ospf` ;
une route BGP apprise d'un voisin direct passe par sa link-local.
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
| symptôme | causes à vérifier |
|----------|-------------------|
| `show ipv6 ospf6` ne montre rien, ou un router-id `0.0.0.0` | `router ospf6` absent, pas de router-id sur un routeur sans IPv4, `ospf6d` non activé |
| aucun voisin OSPFv3 sur une interface | interface hors OSPFv3 (pas de `ipv6 ospf6 area`), passive, zones différentes, intervalles *Hello* / *Dead* différents, zone terminale d'un côté seulement, authentification d'un côté seulement ou clés différentes, **router-id identique** des deux côtés (`Duplicate Router-ID` dans `/var/log/frr/frr.log`) |
| voisin bloqué en `Init` | l'autre n'accepte pas nos *Hello* (authentification, filtre) |
| voisin bloqué en `ExStart` / `Exchange` | **MTU différents** (`MTU mismatch` dans le journal) |
| voisin en `Twoway` depuis moins de 40 s | élection du DR en attente (`Waiting`) : patience |
| route OSPFv3 absente | interface d'origine hors OSPF, zone terminale (pas d'externes), résumé `range` |
| session BGP `Idle` | voisin activé dans aucune famille, `remote-as` faux, router-id absent |
| session BGP `Active` / `Connect` | pas de route vers le voisin, mauvaise adresse, TCP 179 filtré, `update-source` d'un seul côté |
| session `Established` mais `(Policy)` | voisin eBGP sans route-map en entrée et en sortie (RFC 8212) |
| préfixe non annoncé | pas de route exacte dans la RIB (*import-check*), filtre de sortie |
| route BGP présente mais `inaccessible` | prochain saut inconnu de l'IGP (`next-hop-self` manquant) |
| les paquets se perdent au milieu de l'AS | un routeur traversé n'a pas les routes BGP |
""")
            + info_subtitle(tr("Outils"), tag="tools")
            + tr("""
- `ping o1_h3` ou `ping 3fff:…` (la commande `ping` traite IPv4 et IPv6), `ping -I <adresse
  source> <destination>` pour choisir la source (une adresse de bouclage par exemple) ;
- `traceroute -n <destination>` : les routeurs traversés ;
- `ip -6 route`, `ip -6 route get <destination>` (la route choisie : prochain saut et interface) ;
- `ip -6 neigh` (le cache des voisins : link-local et MAC), `ip -6 addr`, `ip link` (MTU) ;
- `tcpdump -ni eth0 ip6 proto 89` (OSPFv3), `tcpdump -ni eth0 tcp port 179` (BGP),
  `tcpdump -ni eth0 icmp6` ;
- les fichiers `/etc/hosts` contiennent les noms des machines et des interfaces des routeurs.
""")
        )

    # -- FRR configuration files -------------------------------------------------

    @staticmethod
    def _bgp_block(router: str, neighbors, networks=(), activate: bool = True) -> List[str]:
        """``router bgp`` of a given router; *neighbors*: ``[(peer, remote_as, description,
        route_map_in, route_map_out)]`` (a peer ``ethN`` is unnumbered)."""
        lines = [f"router bgp {AS_OF[router]}", f" bgp router-id {ROUTER_ID[router]}", " no bgp default ipv4-unicast"]
        for peer, remote_as, description, _in, _out in neighbors:
            if str(peer).startswith('eth'):
                lines.append(f" neighbor {peer} interface remote-as {remote_as}")
            else:
                lines.append(f" neighbor {peer} remote-as {remote_as}")
            if description:
                lines.append(f" neighbor {peer} description {description}")
        lines += [" !", " address-family ipv6 unicast"]
        lines += [f"  network {n}" for n in networks]
        for peer, _as, _description, route_map_in, route_map_out in neighbors:
            if activate:
                lines.append(f"  neighbor {peer} activate")
            if route_map_in:
                lines.append(f"  neighbor {peer} route-map {route_map_in} in")
            if route_map_out:
                lines.append(f"  neighbor {peer} route-map {route_map_out} out")
        return lines + [" exit-address-family", "exit", "!"]

    @staticmethod
    def _ospf6_block(router: str, router_lines=(), interfaces=()) -> List[str]:
        """``router ospf6`` + interface blocks; *interfaces*: ``[(ifname, [statements])]``."""
        lines = ["router ospf6", f" ospf6 router-id {ROUTER_ID[router]}"] + [f" {x}" for x in router_lines] + ["exit", "!"]
        for name, statements in interfaces:
            lines += [f"interface {name}"] + [f" {x}" for x in statements] + ["exit", "!"]
        return lines

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf: empty on the students' routers of o1, o2, eb, un, au; the
        operators and given peers configured; ib and po partly given; fix broken."""
        d = self.data
        a, b = self.addr, self.block
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", "log file /var/log/frr/frr.log", "!"]
        allow_all = ["route-map ALL permit 10", "exit", "!"]
        p2p_area0 = ["ipv6 ospf6 area 0", "ipv6 ospf6 network point-to-point"]
        if router == 'eb_isp':
            lines += [f"ipv6 route {b('eb_isp')} blackhole", "!"] + allow_all
            lines += self._bgp_block(router, [(a('eb_r1', 'eb_link'), AS_OF['eb_r1'], 'CUSTOMER', 'ALL', 'ALL')],
                                     [b('eb_isp')])
        elif router == 'ib_isp':
            lines += [f"ipv6 route {b('ib_isp')} blackhole", "!"] + allow_all
            lines += self._bgp_block(router, [(a('ib_r1', 'ib_link'), AS_OF['ib_r1'], 'CUSTOMER', 'ALL', 'ALL')],
                                     [b('ib_isp')])
        elif router == 'ib_r1':
            lines += [f"ipv6 route {b('ib')} blackhole", "!"] + allow_all
            lines += self._bgp_block(router, [(a('ib_isp', 'ib_link'), AS_OF['ib_isp'], 'ISP', 'ALL', 'ALL')], [b('ib')])
            lines += self._ospf6_block(router, interfaces=[('eth1', p2p_area0), ('lo', ["ipv6 ospf6 area 0"])])
        elif router == 'ib_r2':
            lines += self._ospf6_block(router, interfaces=[('eth0', p2p_area0), ('eth1', p2p_area0),
                                                           ('lo', ["ipv6 ospf6 area 0"])])
        elif router == 'ib_r3':
            lines += self._ospf6_block(router, interfaces=[('eth0', p2p_area0),
                                                           ('eth1', ["ipv6 ospf6 area 0", "ipv6 ospf6 passive"]),
                                                           ('lo', ["ipv6 ospf6 area 0"])])
        elif router == 'po_ispa':
            # ISP A prepends its own AS on every announcement: untouched, po_r1 prefers ISP B
            # towards the Internet and the Internet reaches po through ISP B
            lines += [f"ipv6 route {b('po_ispa')} blackhole", "!"] + allow_all
            lines += ["route-map PREPEND permit 10", f" set as-path prepend {AS_OF['po_ispa']}", "exit", "!"]
            lines += self._bgp_block(router, [(a('po_r1', 'po_la'), AS_OF['po_r1'], 'CUSTOMER', 'ALL', 'PREPEND'),
                                              (a('po_inet', 'po_ia'), AS_OF['po_inet'], 'INTERNET', 'ALL', 'PREPEND')],
                                     [b('po_ispa')])
        elif router == 'po_ispb':
            junk = [d.nets6.junk_ula, d.nets6.junk_doc, d.nets6.junk_long]
            lines += [f"ipv6 route {n} blackhole" for n in [b('po_ispb')] + junk] + ["!"] + allow_all
            lines += self._bgp_block(router, [(a('po_r1', 'po_lb'), AS_OF['po_r1'], 'CUSTOMER', 'ALL', 'ALL'),
                                              (a('po_inet', 'po_ib'), AS_OF['po_inet'], 'INTERNET', 'ALL', 'ALL')],
                                     [b('po_ispb')] + junk)
        elif router == 'po_inet':
            lines += [f"ipv6 route {b('po_inet')} blackhole", "!"] + allow_all
            lines += self._bgp_block(router, [(a('po_ispa', 'po_ia'), AS_OF['po_ispa'], 'ISP-A', 'ALL', 'ALL'),
                                              (a('po_ispb', 'po_ib'), AS_OF['po_ispb'], 'ISP-B', 'ALL', 'ALL')],
                                     [b('po_inet')])
        elif router == 'po_r1':
            lines += [f"ipv6 route {b('po')} blackhole", "!"]
            for name in ('ISPA-IN', 'ISPA-OUT', 'ISPB-IN', 'ISPB-OUT'):
                lines += [f"route-map {name} permit 10", "exit", "!"]
            lines += self._bgp_block(router, [(a('po_ispa', 'po_la'), AS_OF['po_ispa'], 'ISP-A', 'ISPA-IN', 'ISPA-OUT'),
                                              (a('po_ispb', 'po_lb'), AS_OF['po_ispb'], 'ISP-B', 'ISPB-IN', 'ISPB-OUT')],
                                     [b('po')])
        elif router == 'fix_isp':
            lines += [f"ipv6 route {b('fix_isp')} blackhole", "!"] + allow_all
            lines += self._bgp_block(router, [(a('fix_r1', 'fix_link'), AS_OF['fix_r1'], 'CUSTOMER', 'ALL', 'ALL')],
                                     [b('fix_isp')])
        elif router == 'fix_r1':
            # fault 3: the ISP is not activated in the IPv6 family; fault 4: no route for the /48
            lines += allow_all
            lines += self._bgp_block(router, [(a('fix_isp', 'fix_link'), AS_OF['fix_isp'], 'ISP', 'ALL', 'ALL')],
                                     [b('fix')], activate=False)
            lines += self._ospf6_block(router, ["default-information originate always"],
                                       [('eth1', ["ipv6 ospf6 area 0"])])
        elif router == 'fix_r2':
            # fault 2: the router-id of fix_r1 (fault 1, the MTU, is set by initial())
            lines += ["router ospf6", f" ospf6 router-id {ROUTER_ID['fix_r1']}", "exit", "!",
                      "interface eth0", " ipv6 ospf6 area 0", "exit", "!",
                      "interface eth1", " ipv6 ospf6 area 0", " ipv6 ospf6 passive", "exit", "!"]
        elif router == 'un_r2':
            lines += allow_all
            lines += self._bgp_block(router, [('eth0', 'external', None, 'ALL', 'ALL')], [f"{self.lo('un_r2')}/128"])
        elif router == 'au_r2':
            lines += self._ospf6_block(router, interfaces=[('eth0', [
                "ipv6 ospf6 area 0",
                f"ipv6 ospf6 authentication key-id {d.au_key_id} hash-algo {AUTH_ALGO} key {d.au_key}"])])
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part (texts shown by the instructor solutions) ------

    def ospf6_cmds(self, router: str, router_lines=(), interfaces=()) -> List[str]:
        """vtysh commands of an OSPFv3 configuration (see :meth:`_ospf6_block`)."""
        cmds = ["router ospf6", f"ospf6 router-id {ROUTER_ID[router]}", *router_lines, "exit"]
        for name, statements in interfaces:
            cmds += [f"interface {name}", *statements, "exit"]
        return cmds

    def solution_ospf(self) -> Dict[str, List[str]]:
        x = f"ipv6 ospf6 cost {self.data.o1_cost}"
        return {
            'o1_r1': self.ospf6_cmds('o1_r1', interfaces=[('eth0', ["ipv6 ospf6 area 0", "ipv6 ospf6 passive"]),
                                                         ('eth1', ["ipv6 ospf6 area 0"]),
                                                         ('eth2', ["ipv6 ospf6 area 0", x])]),
            'o1_r2': self.ospf6_cmds('o1_r2', interfaces=[('eth0', ["ipv6 ospf6 area 0"]),
                                                         ('eth1', ["ipv6 ospf6 area 0"])]),
            'o1_r3': self.ospf6_cmds('o1_r3', interfaces=[('eth0', ["ipv6 ospf6 area 0", "ipv6 ospf6 passive"]),
                                                         ('eth1', ["ipv6 ospf6 area 0", x]),
                                                         ('eth2', ["ipv6 ospf6 area 0"])]),
        }

    def solution_areas(self) -> Dict[str, List[str]]:
        area1 = self.data.nets6.o2_area1
        return {
            'o2_r0': self.ospf6_cmds('o2_r0', ["redistribute connected"], [('eth1', ["ipv6 ospf6 area 0"])]),
            'o2_abr': self.ospf6_cmds('o2_abr', ["area 1 stub", f"area 1 range {area1}"],
                                      [('eth0', ["ipv6 ospf6 area 0"]), ('eth1', ["ipv6 ospf6 area 1"])]),
            'o2_r1': self.ospf6_cmds('o2_r1', ["area 1 stub"],
                                     [('eth0', ["ipv6 ospf6 area 1"]),
                                      ('eth1', ["ipv6 ospf6 area 1", "ipv6 ospf6 passive"]),
                                      ('eth2', ["ipv6 ospf6 area 1", "ipv6 ospf6 passive"])]),
        }

    def solution_ebgp(self) -> Dict[str, List[str]]:
        isp, mine = self.addr('eb_isp', 'eb_link'), self.block('eb')
        return {'eb_r1': [
            f"ipv6 route {mine} blackhole", "route-map ALL permit 10", "exit",
            f"router bgp {AS_OF['eb_r1']}", f"bgp router-id {ROUTER_ID['eb_r1']}", "no bgp default ipv4-unicast",
            f"neighbor {isp} remote-as {AS_OF['eb_isp']}", "address-family ipv6 unicast", f"network {mine}",
            f"neighbor {isp} activate", f"neighbor {isp} route-map ALL in", f"neighbor {isp} route-map ALL out",
            "exit-address-family", "exit"]}

    def solution_ibgp(self) -> Dict[str, List[str]]:
        result = {}
        routers = ('ib_r1', 'ib_r2', 'ib_r3')
        for r in routers:
            peers = [self.lo(p) for p in routers if p != r]
            cmds = [f"router bgp {AS_OF[r]}"]
            if r != 'ib_r1':
                cmds += [f"bgp router-id {ROUTER_ID[r]}", "no bgp default ipv4-unicast"]
            for p in peers:
                cmds += [f"neighbor {p} remote-as {AS_OF[r]}", f"neighbor {p} update-source lo"]
            cmds.append("address-family ipv6 unicast")
            for p in peers:
                cmds.append(f"neighbor {p} activate")
                if r == 'ib_r1':
                    cmds.append(f"neighbor {p} next-hop-self")
            result[r] = cmds + ["exit-address-family", "exit"]
        return result

    def solution_policy(self) -> Dict[str, List[str]]:
        prepend = " ".join([str(AS_OF['po_r1'])] * PREPEND_COUNT)
        return {'po_r1': [
            f"ipv6 prefix-list BOGONS seq 5 deny {BOGON_DOC} le 128",
            f"ipv6 prefix-list BOGONS seq 10 permit {GLOBAL_UNICAST} le {MAX_ACCEPTED_PREFIXLEN}",
            f"ipv6 prefix-list MINE seq 5 permit {self.block('po')}",
            "route-map ISPA-IN permit 10", "match ipv6 address prefix-list BOGONS",
            f"set local-preference {LOCAL_PREF}", "exit",
            "route-map ISPB-IN permit 10", "match ipv6 address prefix-list BOGONS", "exit",
            "route-map ISPA-OUT permit 10", "match ipv6 address prefix-list MINE", "exit",
            "route-map ISPB-OUT permit 10", "match ipv6 address prefix-list MINE", f"set as-path prepend {prepend}",
            "exit"]}

    def solution_fix(self) -> Dict[str, List[str]]:
        isp = self.addr('fix_isp', 'fix_link')
        return {
            'fix_r2': ["router ospf6", f"ospf6 router-id {ROUTER_ID['fix_r2']}", "exit"],
            'fix_r1': [f"ipv6 route {self.block('fix')} blackhole", f"router bgp {AS_OF['fix_r1']}",
                       "address-family ipv6 unicast", f"neighbor {isp} activate", "exit-address-family", "exit"],
        }

    def solution_unnumbered(self) -> Dict[str, List[str]]:
        return {'un_r1': [
            "route-map ALL permit 10", "exit", f"router bgp {AS_OF['un_r1']}", f"bgp router-id {ROUTER_ID['un_r1']}",
            "no bgp default ipv4-unicast", "neighbor eth0 interface remote-as external", "address-family ipv6 unicast",
            f"network {self.lo('un_r1')}/128", "neighbor eth0 activate", "neighbor eth0 route-map ALL in",
            "neighbor eth0 route-map ALL out", "exit-address-family", "exit"]}

    def solution_auth(self) -> Dict[str, List[str]]:
        d = self.data
        return {'au_r1': self.ospf6_cmds('au_r1', interfaces=[('eth0', [
            "ipv6 ospf6 area 0", f"ipv6 ospf6 authentication key-id {d.au_key_id} hash-algo {AUTH_ALGO} key {d.au_key}"])])}

    def _apply(self, solution: Dict[str, List[str]], step: int = 1):
        for router, cmds in solution.items():
            self._vtysh(router, *cmds, step=step)

    def _apply_fix(self, step: int = 1):
        self.cmd('fix_r2', "ip link set dev eth0 mtu 1500", step=step)
        self._apply(self.solution_fix(), step=step)
        # a new router-id only takes effect after the process is cleared
        self.cmd('fix_r2', 'vtysh -c "clear ipv6 ospf6 process"', step=step)

    def _apply_ibgp(self, step: int = 1):
        """The iBGP solution, each router configured once OSPFv3 gives it the routes to the two
        other loopbacks: a session configured before (``final`` right after the start) fails its
        first connection and FRR only retries after its connect timer (120 s; seen live)."""
        routers = ('ib_r1', 'ib_r2', 'ib_r3')
        solution = self.solution_ibgp()
        for r in routers:
            routes = " && ".join(f"ip -6 route show {self.lo(p)}/128 | grep -q via" for p in routers if p != r)
            self.cmd(r, f"i=0; until {routes}; do i=$((i+1)); [ $i -ge 60 ] && break; sleep 1; done", step=step)
            self._vtysh(r, *solution[r], step=step)

    def _apply_policy(self, step: int = 1):
        self._apply(self.solution_policy(), step=step)
        self.cmd('po_r1', 'vtysh -c "clear bgp ipv6 unicast * soft"', step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for h in HOSTS:
            set_ipv6_forward(net_scheme=self, machine_name=h, ipv6_forward=False)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n127.0.1.1\t{m}\n"
                      + self.hosts_content)
        for r in LOOPBACKS:
            self.cmd(r, f"ip addr add {getattr(d.ips6, f'{r}_lo')} dev lo")
        # fault 1 of the fix site: an MTU that differs from fix_r1's on the link
        self.cmd('fix_r2', f"ip link set dev eth0 mtu {d.fix_mtu}")
        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (OSPFv3, une zone)"))
    def solve_ospf(self):
        self._apply(self.solution_ospf())
        self.cmd('o1_r1', f"sleep {OSPF_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (OSPFv3, plusieurs zones)"))
    def solve_areas(self):
        self._apply(self.solution_areas())
        self.cmd('o2_r0', f"sleep {OSPF_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (eBGP)"))
    def solve_ebgp(self):
        self._apply(self.solution_ebgp())
        self.cmd('eb_r1', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (iBGP)"))
    def solve_ibgp(self):
        self._apply_ibgp()
        self.cmd('ib_r1', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (politiques BGP)"))
    def solve_policy(self):
        self._apply_policy()
        self.cmd('po_r1', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (dépannage)"))
    def solve_fix(self):
        self._apply_fix()
        self.cmd('fix_r1', f"sleep {OSPF_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 7 : solution (BGP unnumbered, bonus)"))
    def solve_unnumbered(self):
        self._apply(self.solution_unnumbered())
        self.cmd('un_r1', f"sleep {BGP_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 8 : solution (authentification OSPFv3, bonus)"))
    def solve_auth(self):
        self._apply(self.solution_auth())
        self.cmd('au_r1', f"sleep {OSPF_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for the OSPFv3 adjacencies and the BGP sessions).  Form questions are
        filled through cheat_answers."""
        for solution in (self.solution_ospf(), self.solution_areas(), self.solution_ebgp(), self.solution_unnumbered(),
                         self.solution_auth()):
            self._apply(solution)
        self._apply_ibgp()
        self._apply_policy()
        self._apply_fix()
        # a broadcast interface waits a Dead interval (40 s) before its DR election
        self.cmd('o1_r1', f"sleep {OSPF_WAIT}", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _ints(s) -> List[int]:
    """The numbers of a typed answer (``'2/1'`` -> ``[2, 1]``, an AS path -> its ASes)."""
    return [int(x) for x in re.findall(r'\d+', str(s or ''))]


def _ipv6_net(answer):
    """The IPv6 prefix of a typed answer, None when unreadable."""
    try:
        network = ip_network(_norm(answer).replace(' ', ''), strict=False)
    except ValueError:
        return None
    return network if network.version == 6 else None


def _same_address(a, b) -> bool:
    """Two IPv6 addresses (strings or objects) are equal; False when one is not an address."""
    pa, pb = parse_ipv6(a), parse_ipv6(b)
    return pa is not None and pa == pb


def _is_link_local(address) -> bool:
    parsed = parse_ipv6(address)
    return parsed is not None and parsed.is_link_local


def _global_addresses(output: str) -> List[str]:
    """Global addresses in ``ip -j -6 addr show dev X`` (``[]`` on the placeholder)."""
    try:
        links = json.loads(output or '[]')
    except ValueError:
        return []
    return [a.get('local') for link in links if isinstance(link, dict)
            for a in link.get('addr_info') or [] if isinstance(a, dict) and a.get('scope') == 'global']


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    """The reference configuration of a part, as vtysh sessions (one block per router)."""
    blocks = []
    for router, cmds in solution.items():
        body = "\n".join(["configure terminal"] + [f" {c}" for c in cmds] + ["end", "write"])
        blocks.append(f"`{router}` :\n\n```\n{body}\n```")
    return "\n\n".join(blocks)


def _kernel_nexthops(routes: Dict[str, Dict], prefix, bgp: bool = False) -> List[tuple]:
    """``[(gateway, dev)]`` of *prefix* in a kernel table when ospf6d (bgpd) installed it."""
    entry = routes.get(str(prefix))
    if not entry:
        return []
    ok = is_bgp_protocol(entry['protocol']) if bgp else is_ospf_protocol(entry['protocol'])
    return entry['nexthops'] if ok else []


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def ping(self, src: str, dest) -> bool:
        return eval_ping(self, src, dest, count=2, deadline=4, allow_error=True)

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        a, lo, b, ll = ns.addr, ns.lo, ns.block, ns.ll

        # ---------------- diagnostics kept in the archive -------------------------
        for r in STUDENT_ROUTERS:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read (all at step 1) ------------------
        o1 = ('o1_r1', 'o1_r2', 'o1_r3')
        o1_info = {r: get_ospf6_info(self, r, allow_error=True) for r in o1}
        o1_nb = {r: get_ospf6_neighbors(self, r, allow_error=True) for r in ('o1_r1', 'o1_r2')}
        o1_if = {r: get_ospf6_interfaces(self, r, allow_error=True) for r in ('o1_r1', 'o1_r3')}
        o1_k = {r: get_kernel_routes(self, r, allow_error=True, ipv6=True) for r in ('o1_r1', 'o1_r3')}
        o1_ping = self.ping('o1_h1', d.ips6.o1_h3.ip)

        o2_nb = {r: get_ospf6_neighbors(self, r, allow_error=True) for r in ('o2_r0', 'o2_r1')}
        o2_info = {r: get_ospf6_info(self, r, allow_error=True) for r in ('o2_abr', 'o2_r1')}
        o2_routes = {r: get_ospf6_routes(self, r, allow_error=True) for r in ('o2_r0', 'o2_abr', 'o2_r1')}
        o2_ping = self.ping('o2_h1', d.ips6.o2_srv.ip)

        eb_cfg = get_frr_running_config(self, 'eb_r1', allow_error=True)
        eb_isp_summary = get_bgp_summary(self, 'eb_isp', allow_error=True, afi='ipv6')
        eb_r1_summary = get_bgp_summary(self, 'eb_r1', allow_error=True, afi='ipv6')
        eb_isp_routes = get_bgp_routes(self, 'eb_isp', allow_error=True, afi='ipv6')
        eb_k = get_kernel_routes(self, 'eb_r1', allow_error=True, ipv6=True)
        eb_ping = self.ping('eb_h', d.ips6.eb_srv.ip)

        ib_pairs = (('ib_r1', 'ib_r2'), ('ib_r1', 'ib_r3'), ('ib_r2', 'ib_r3'))
        ib_nb = {(x, y): get_bgp_neighbor(self, x, lo(y), allow_error=True, afi='ipv6') for x, y in ib_pairs}
        ib_r3_routes = get_bgp_routes(self, 'ib_r3', allow_error=True, afi='ipv6')
        ib_k2 = get_kernel_routes(self, 'ib_r2', allow_error=True, ipv6=True)
        ib_ping = self.ping('ib_h', d.ips6.ib_srv.ip)

        po_r1_routes = get_bgp_routes(self, 'po_r1', allow_error=True, afi='ipv6')
        po_inet_routes = get_bgp_routes(self, 'po_inet', allow_error=True, afi='ipv6')
        po_adv = {isp: get_bgp_advertised_routes(self, 'po_r1', a(isp, link), allow_error=True, afi='ipv6')
                  for isp, link in (('po_ispa', 'po_la'), ('po_ispb', 'po_lb'))}

        fix_info = {r: get_ospf6_info(self, r, allow_error=True) for r in ('fix_r1', 'fix_r2')}
        fix_if = {'fix_r1': get_ospf6_interfaces(self, 'fix_r1', allow_error=True).get('eth1') or {},
                  'fix_r2': get_ospf6_interfaces(self, 'fix_r2', allow_error=True).get('eth0') or {}}
        fix_nb = get_ospf6_neighbors(self, 'fix_r1', allow_error=True)
        fix_r1_routes = get_bgp_routes(self, 'fix_r1', allow_error=True, afi='ipv6')
        fix_isp_routes = get_bgp_routes(self, 'fix_isp', allow_error=True, afi='ipv6')
        fix_ping = self.ping('fix_h', d.ips6.fix_srv.ip)

        un_summary = get_bgp_summary(self, 'un_r1', allow_error=True, afi='ipv6')
        un_addrs, _ = self.test('un_r1', 'ip -j -6 addr show dev eth0', allow_error=True)
        un_routes = get_bgp_routes(self, 'un_r1', allow_error=True, afi='ipv6')
        un_k = get_kernel_routes(self, 'un_r1', allow_error=True, ipv6=True)
        un_ping, _ = self.test('un_r1', f"ping -c 2 -w 4 -I {lo('un_r1')} {lo('un_r2')}", allow_error=True)

        au_nb = get_ospf6_neighbors(self, 'au_r1', allow_error=True)
        au_if = get_ospf6_interfaces(self, 'au_r1', allow_error=True).get('eth0') or {}

        # ---------------- texts shared by the questions ---------------------------
        sites = [('o1', "1 — OSPFv3, une zone", "`o1_r1`, `o1_r2`, `o1_r3` (triangle), les hôtes `o1_h1` et `o1_h3`"),
                 ('o2', "2 — OSPFv3, plusieurs zones", "`o2_r0` (zone 0), `o2_abr`, `o2_r1` (zone 1), l'hôte `o2_h1`, "
                                                     "le serveur `o2_srv` (réseau extérieur)"),
                 ('eb', "3 — eBGP", "`eb_r1` (AS 65010), le fournisseur `eb_isp`, l'hôte `eb_h`, le serveur `eb_srv`"),
                 ('ib', "4 — iBGP", "`ib_r1`, `ib_r2`, `ib_r3` (AS 65020), le fournisseur `ib_isp`, `ib_h`, `ib_srv`"),
                 ('po', "5 — politiques", "`po_r1` (AS 65030), les fournisseurs `po_ispa` et `po_ispb`, "
                                          "l'Internet `po_inet`, `po_h`, `po_srv`"),
                 ('fix', "6 — dépannage", "`fix_r1`, `fix_r2` (AS 65040), le fournisseur `fix_isp`, `fix_h`, `fix_srv`"),
                 ('un', "7 — BGP unnumbered (bonus)", "`un_r1` (AS 65050), `un_r2` (AS 65051)"),
                 ('au', "8 — authentification OSPFv3 (bonus)", "`au_r1`, `au_r2`")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members = {net: [] for net in NET6_PLAN}
        for r, nets in ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                if net in members:
                    members[net].append(f"`{r}` eth{i} (`::{ROUTER_IDS6[r]:x}`)")
        for h, (net, _gw) in HOSTS.items():
            members[net].append(f"`{h}` (`{getattr(d.ips6, h).ip}`)")
        address_rows = [f"| `{net}` | `{ns.net(net)}` | {', '.join(members[net])} |" for net in NET6_PLAN]
        address_rows.append("| `un_link` | aucune adresse globale | `un_r1` eth0, `un_r2` eth0 |")
        address_rows += [f"| `{r}` lo | `{lo(r)}/128` | `{r}` |" for r in LOOPBACKS]
        addressing = "\n".join(address_rows)
        id_rows = "\n".join(f"| `{r}` | `{ROUTER_ID[r]}` | {AS_OF.get(r, '—')} |" for r in ROUTER_IFACES)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente le routage IPv6 avec OSPFv3 et BGP, et leur
configuration avec FRR.

**Le réseau.** Il est **uniquement IPv6** (aucune adresse IPv4) et fait de **huit sites
indépendants**, un par partie. Chaque site a sa couleur sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) : configurez-les avec `vtysh`. Les démons
  utiles (`ospf6d`, `bgpd`) sont déjà activés.
- Toutes les adresses sont en place, ainsi que la route par défaut des hôtes.
- Les routeurs des fournisseurs et les voisins déjà configurés (`eb_isp`, `ib_isp`, `po_ispa`,
  `po_ispb`, `po_inet`, `fix_isp`, `un_r2`, `au_r2`) n'ont pas de terminal.
- Les fichiers `/etc/hosts` contiennent les noms : `o1_r2-eth1` désigne l'adresse de
  l'interface `eth1` d'`o1_r2`, `ib_r1-lo` l'adresse de bouclage d'`ib_r1`, `o1_h3` l'hôte.

**Plan d'adressage.** Les préfixes de votre instance sont pris dans `{instance}` (un /32 du bloc
de documentation `3fff::/20`) ; le troisième groupe d'un préfixe indique son AS ou son site.
Une interface de routeur a l'identifiant indiqué entre parenthèses dans son réseau.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

Préfixes (/48) des AS et des sites : `o1` `{as_o1}`, `o2` `{as_o2}`, `eb` (AS 65010) `{as_eb}`,
`eb_isp` `{as_eb_isp}`, `ib` (AS 65020) `{as_ib}`, `ib_isp` `{as_ib_isp}`, `po` (AS 65030)
`{as_po}`, ISP A `{as_po_ispa}`, ISP B `{as_po_ispb}`, l'Internet `{as_po_inet}`, `fix`
(AS 65040) `{as_fix}`, `fix_isp` `{as_fix_isp}`.

**Router-id et numéros d'AS** (à utiliser tels quels) :

| routeur | router-id | AS |
|---------|-----------|----|
{id_rows}

**Valeurs propres à votre instance** : coût du lien `o1_l13` (partie 1) : **{o1_cost}** ;
authentification d'`au_r2` (partie 8) : identifiant de clé **{au_key_id}**, clé **`{au_key}`**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie
  terminée rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration des routeurs (`write` dans `vtysh`).
- OSPFv3 n'est pas instantané : sur un réseau Ethernet, un voisinage met **environ 45 s** à
  devenir `Full` (élection du DR) ; une session BGP s'établit en quelques secondes, mais FRR
  n'échange rien avec un voisin eBGP sans politique (RFC 8212).

**Évaluation.** Chaque évaluation lit vos réponses, l'état d'OSPFv3 et de BGP sur les routeurs
(voisins, routes, tables BGP, ce qui est annoncé) et la table de routage du noyau, et fait des
`ping` entre les hôtes de chaque site. Elle dure une dizaine de secondes.
""").format(site_rows=site_rows, addressing=addressing, id_rows=id_rows, instance=d.nets6.instance,
            as_o1=b('o1'), as_o2=b('o2'), as_eb=b('eb'), as_eb_isp=b('eb_isp'), as_ib=b('ib'), as_ib_isp=b('ib_isp'),
            as_po=b('po'), as_po_ispa=b('po_ispa'), as_po_ispb=b('po_ispb'), as_po_inet=b('po_inet'),
            as_fix=b('fix'), as_fix_isp=b('fix_isp'), o1_cost=d.o1_cost, au_key_id=d.au_key_id, au_key=d.au_key)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_ospf`, `solve_areas`, `solve_ebgp`, `solve_ibgp`, `solve_policy`,
`solve_fix`, `solve_unnumbered` et `solve_auth` (onglet *Appliquer une configuration*)
appliquent la solution d'une seule partie et remplissent ses formulaires. L'état `final` les
applique toutes, attend {wait} s (élection des DR d'OSPFv3) puis remplit tous les formulaires :
une évaluation lancée dès son retour donne tous les points, bonus compris.

Les pannes du site `fix` : MTU d'`eth0` d'`fix_r2` à {mtu} (voisinage bloqué en `ExStart`),
router-id d'`fix_r2` égal à celui d'`fix_r1` (`6.0.0.1` : aucun voisin, `Duplicate Router-ID`),
voisin `fix_isp` non activé en IPv6 unicast sur `fix_r1` (`Idle`), `network {fix48}` sans route
dans la RIB (*import-check*). ISP B envoie à `po_r1` trois préfixes à filtrer : `{ula}`, `{doc}`
et `{long}`.
""").format(wait=OSPF_WAIT, mtu=d.fix_mtu, fix48=b('fix'), ula=d.nets6.junk_ula, doc=d.nets6.junk_doc,
            long=d.nets6.junk_long)),
        )

        # =====================================================================
        # Part 1 — OSPFv3 in one area (o1)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("ospf"), tr("Partie 1 — OSPFv3 dans une zone (site o1)"))
        lan1, lan3 = ns.net('o1_lan1'), ns.net('o1_lan3')
        self.question_dummy(
            section=self.section(0),
            title=tr("OSPFv3 dans une zone"),
            description=tr("""
Les trois routeurs `o1_r1`, `o1_r2` et `o1_r3` forment un triangle (liens `o1_l12`, `o1_l13`,
`o1_l23`) ; l'hôte `o1_h1` est sur le réseau `o1_lan1` d'`o1_r1`, l'hôte `o1_h3` sur le réseau
`o1_lan3` d'`o1_r3`. Aucun routeur ne fait encore d'OSPF (sections @@ref:ospfv3@@ et
@@ref:frr-ospf6@@).

1. Sur chaque routeur, configurez OSPFv3 dans la zone 0 sur toutes ses interfaces, avec le
   router-id donné dans l'organisation du TP. Suivez la formation des voisinages
   (`show ipv6 ospf6 neighbor`, `show ipv6 ospf6 interface`) jusqu'à l'état `Full`.
2. Regardez les routes (`show ipv6 ospf6 route`, `ip -6 route`) : quelles sont les adresses des
   prochains sauts ? Vérifiez que `o1_h1` joint `o1_h3`.
3. Les réseaux `o1_lan1` et `o1_lan3` n'ont aucun autre routeur : rendez ces deux interfaces
   **passives**.
4. Donnez au lien `o1_l13` le coût **{cost}**, à ses deux extrémités. Par où passe maintenant le
   trafic d'`o1_h1` vers `o1_h3`, et le retour (`traceroute`) ?
5. Observez la base de données (`show ipv6 ospf6 database`) et les paquets OSPFv3
   (`tcpdump -ni eth1 ip6 proto 89` sur `o1_r1`).
""").format(cost=d.o1_cost)
            + instructor(tr("""
**Solution.**

{solution}

Les prochains sauts sont les adresses link-local des voisins. Avec le coût {cost} sur `o1_l13`,
`o1_r1` joint `o1_lan3` par `o1_r2` (10 + 10 < {cost}) et `o1_r3` joint `o1_lan1` par `o1_r2`.

Évaluation : `o1_router_id_o1_r1`, `o1_router_id_o1_r2`, `o1_router_id_o1_r3` (1 chacun),
`o1_adjacencies` (3 : un point par voisinage `Full`), `o1_passive` (2 : un point par réseau
d'hôtes, dans OSPFv3 et passif), `o1_routes` (2 : routes OSPF des deux réseaux d'hôtes via une
link-local), `o1_cost` (2 : le coût aux deux bouts, puis le chemin par `o1_r2` dans les deux
sens), `o1_ping` (2).
""").format(solution=_vtysh_text(ns.solution_ospf()), cost=d.o1_cost)),
        )
        cheat_o1 = {'nexthop': str(ll('o1_r2', 'o1_l12')), 'hello_group': 'ff02::5', 'lsa': 'intra-area-prefix'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site o1"),
            description=tr("""
- adresse du prochain saut d'`o1_r1` vers `o1_lan3`, une fois le coût en place :
  @@{nexthop:[0-9a-zA-Z:%./]+}@@
- adresse de destination des *Hello* d'OSPFv3 : @@{hello_group:[0-9a-fA-F:]+}@@
- type de LSA qui porte le préfixe d'`o1_lan3` dans la zone :
  @@{lsa:>Router-LSA>>>router|Network-LSA>>>network|Link-LSA>>>link|Intra-Area-Prefix-LSA>>>intra-area-prefix|Inter-Area-Prefix-LSA>>>inter-area-prefix|AS-External-LSA>>>as-external}@@
""")
            + instructor(tr("""
**Solution.** Le prochain saut est la link-local d'`o1_r2` sur `o1_l12` : **`{nexthop}`**. Les
*Hello* vont à **`ff02::5`** (*AllSPFRouters*). Le préfixe d'un réseau d'hôtes est porté par
l'**Intra-Area-Prefix-LSA** d'`o1_r3` (les Router-LSA d'OSPFv3 ne contiennent plus d'adresse).

Évaluation : `o1_q_nexthop`, `o1_q_hello_group` (1 chacun) ; pour l'enseignant seulement :
`o1_q_lsa` (1).
""").format(nexthop=cheat_o1['nexthop'])),
            cheat_answers={"final": cheat_o1, "solve_ospf": cheat_o1},
        )
        for r in o1:
            self.add_grade_element(
                title=no_tr(f"o1_router_id_{r}"), max_grade=1, grade_part=part1,
                grade=int(o1_info[r].get('router_id') == ROUTER_ID[r]), description=tr("router-id OSPFv3 donné"),
            )
        adjacencies = [neighbor_is_full(o1_nb['o1_r1'], interface=iface('o1_r1', 'o1_l12')),
                       neighbor_is_full(o1_nb['o1_r1'], interface=iface('o1_r1', 'o1_l13')),
                       neighbor_is_full(o1_nb['o1_r2'], interface=iface('o1_r2', 'o1_l23'))]
        self.add_grade_element(
            title=no_tr("o1_adjacencies"), max_grade=3, grade_part=part1, grade=sum(adjacencies),
            description=tr("voisinages OSPFv3 Full sur les trois liens"),
        )
        passive = [bool((o1_if[r].get('eth0') or {}).get('enabled')) and (o1_if[r].get('eth0') or {}).get('passive') is True
                   for r in ('o1_r1', 'o1_r3')]
        self.add_grade_element(
            title=no_tr("o1_passive"), max_grade=2, grade_part=part1, grade=sum(passive),
            description=tr("réseaux d'hôtes annoncés, interfaces passives"),
        )
        routes_ok = [bool(nh) and all(_is_link_local(gw) for gw, _dev in nh)
                     for nh in (_kernel_nexthops(o1_k['o1_r1'], lan3), _kernel_nexthops(o1_k['o1_r3'], lan1))]
        self.add_grade_element(
            title=no_tr("o1_routes"), max_grade=2, grade_part=part1, grade=sum(routes_ok),
            description=tr("routes OSPFv3 des réseaux d'hôtes, via une link-local"),
        )
        costs = [(o1_if['o1_r1'].get(iface('o1_r1', 'o1_l13')) or {}).get('cost'),
                 (o1_if['o1_r3'].get(iface('o1_r3', 'o1_l13')) or {}).get('cost')]
        paths = ({dev for _gw, dev in _kernel_nexthops(o1_k['o1_r1'], lan3)} == {iface('o1_r1', 'o1_l12')}
                 and {dev for _gw, dev in _kernel_nexthops(o1_k['o1_r3'], lan1)} == {iface('o1_r3', 'o1_l23')})
        self.add_grade_element(
            title=no_tr("o1_cost"), max_grade=2, grade_part=part1,
            grade=int(costs == [d.o1_cost, d.o1_cost]) + int(costs == [d.o1_cost, d.o1_cost] and paths),
            description=tr("coût du lien o1_l13, chemin par o1_r2"),
        )
        self.add_grade_element(
            title=no_tr("o1_ping"), max_grade=2, grade_part=part1, grade=2 * int(o1_ping),
            description=tr("o1_h1 joint o1_h3"),
        )
        self.add_grade_element(
            title=no_tr("o1_q_nexthop"), max_grade=1, grade_part=part1,
            grade=int(same_ipv6(q1.get('nexthop'), ll('o1_r2', 'o1_l12'))), description=tr("prochain saut link-local"),
        )
        self.add_grade_element(
            title=no_tr("o1_q_hello_group"), max_grade=1, grade_part=part1,
            grade=int(same_ipv6(q1.get('hello_group'), 'ff02::5')), description=tr("groupe des Hello d'OSPFv3"),
        )
        self.add_grade_element(
            title=no_tr("o1_q_lsa"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('lsa')) == cheat_o1['lsa']), description=tr("LSA des préfixes"),
        )

        # =====================================================================
        # Part 2 — OSPFv3 in several areas (o2)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("areas"), tr("Partie 2 — OSPFv3 dans plusieurs zones (site o2)"))
        area1 = d.nets6.o2_area1
        self.question_dummy(
            section=self.section(0),
            title=tr("Zones, résumé, zone terminale, routes externes"),
            description=tr("""
Le site `o2` a deux zones : la **zone 0** entre `o2_r0` et `o2_abr` (lien `o2_l0`), la **zone 1**
entre `o2_abr` et `o2_r1` (lien `o2_l1`) avec les réseaux `o2_lan1a` (l'hôte `o2_h1`) et
`o2_lan1b` d'`o2_r1`. Le réseau `o2_ext` d'`o2_r0` (le serveur `o2_srv`) représente un réseau
extérieur : il ne doit **pas** être dans OSPF (sections @@ref:ospfv3-areas@@ et
@@ref:ospfv3-external@@).

1. Configurez OSPFv3 avec les router-id donnés : `o2_r0` dans la zone 0 sur `o2_l0` seulement,
   `o2_abr` dans les zones 0 et 1, `o2_r1` dans la zone 1 sur ses trois interfaces (ses réseaux
   d'hôtes passifs). Regardez la table d'`o2_r0`.
2. Faites annoncer `o2_ext` par `o2_r0` comme **route externe**, sans mettre son interface dans
   OSPF.
3. **Résumez** la zone 1 : `o2_r0` ne doit plus voir qu'un seul préfixe, le plus long possible,
   pour les trois réseaux de la zone 1.
4. Faites de la zone 1 une **zone terminale** (*stub*). Comparez la table d'`o2_r1` avant et
   après. `o2_h1` doit toujours joindre `o2_srv`.
""")
            + instructor(tr("""
**Solution.**

{solution}

Les trois réseaux de la zone 1 tiennent dans **`{area1}`**. `o2_r0` voit ce /60 (`IE`), `o2_abr`
voit `o2_ext` en `E2` ; dans la zone terminale, `o2_r1` n'a plus de route externe mais une route
par défaut (`::/0`, `IE`) injectée par `o2_abr`.

Évaluation : `o2_adjacencies` (2), `o2_abr` (2 : zones 0 et 1 sur les bonnes interfaces),
`o2_range` (3 : le /60 et aucun des trois /64 dans la table d'`o2_r0`), `o2_external` (2 :
`o2_ext` externe sur `o2_abr`), `o2_stub` (3 : zone terminale des deux côtés, route par défaut,
plus de route externe sur `o2_r1`), `o2_ping` (2).
""").format(solution=_vtysh_text(ns.solution_areas()), area1=area1)),
        )
        cheat_o2 = {'range': str(area1), 'summary_lsa': 'inter-area-prefix', 'stub_gets': 'default'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site o2"),
            description=tr("""
- préfixe qui résume la zone 1 : @@{range:[0-9a-fA-F:/]+}@@
- LSA qui porte ce résumé dans la zone 0 :
  @@{summary_lsa:>Router-LSA>>>router|Intra-Area-Prefix-LSA>>>intra-area-prefix|Inter-Area-Prefix-LSA>>>inter-area-prefix|Inter-Area-Router-LSA>>>inter-area-router|AS-External-LSA>>>as-external}@@
- ce qu'une zone terminale reçoit à la place des routes externes :
  @@{stub_gets:>une route par défaut>>>default|rien>>>nothing|les routes externes résumées>>>summarized|les routes de la zone 0 seulement>>>backbone}@@
""")
            + instructor(tr("""
**Solution.** **`{area1}`** ; une **Inter-Area-Prefix-LSA** émise par `o2_abr` ; une **route par
défaut** (`::/0`).

Évaluation : `o2_q_range` (1) ; pour l'enseignant seulement : `o2_q_summary_lsa`, `o2_q_stub`
(1 chacun).
""").format(area1=area1)),
            cheat_answers={"final": cheat_o2, "solve_areas": cheat_o2},
        )
        self.add_grade_element(
            title=no_tr("o2_adjacencies"), max_grade=2, grade_part=part2,
            grade=int(neighbor_is_full(o2_nb['o2_r0'], interface=iface('o2_r0', 'o2_l0')))
            + int(neighbor_is_full(o2_nb['o2_r1'], interface=iface('o2_r1', 'o2_l1'))),
            description=tr("voisinages OSPFv3 Full dans les deux zones"),
        )
        abr_areas = o2_info['o2_abr'].get('areas') or {}
        self.add_grade_element(
            title=no_tr("o2_abr"), max_grade=2, grade_part=part2,
            grade=2 * int(iface('o2_abr', 'o2_l0') in (abr_areas.get('0.0.0.0') or {}).get('interfaces', [])
                          and iface('o2_abr', 'o2_l1') in (abr_areas.get('0.0.0.1') or {}).get('interfaces', [])),
            description=tr("o2_abr est un ABR entre les zones 0 et 1"),
        )
        r0_routes = o2_routes['o2_r0']
        area1_nets = [ns.net(n) for n in ('o2_l1', 'o2_lan1a', 'o2_lan1b')]
        self.add_grade_element(
            title=no_tr("o2_range"), max_grade=3, grade_part=part2,
            grade=3 * int((r0_routes.get(str(area1)) or {}).get('type') == 'inter-area'
                          and not any(str(n) in r0_routes for n in area1_nets)),
            description=tr("la zone 1 résumée par un /60"),
        )
        self.add_grade_element(
            title=no_tr("o2_external"), max_grade=2, grade_part=part2,
            grade=2 * int(str((o2_routes['o2_abr'].get(str(ns.net('o2_ext'))) or {}).get('type')).startswith('external')),
            description=tr("o2_ext annoncé comme route externe"),
        )
        r1_routes = o2_routes['o2_r1']
        r1_default = (r1_routes.get('::/0') or {}).get('type') == 'inter-area'
        stub_both = bool((abr_areas.get('0.0.0.1') or {}).get('stub')
                         and ((o2_info['o2_r1'].get('areas') or {}).get('0.0.0.1') or {}).get('stub'))
        self.add_grade_element(
            title=no_tr("o2_stub"), max_grade=3, grade_part=part2,
            grade=int(stub_both) + int(r1_default)
            + int(r1_default and not any(str(r['type']).startswith('external') for r in r1_routes.values())),
            description=tr("zone 1 terminale : une route par défaut, aucune route externe"),
        )
        self.add_grade_element(
            title=no_tr("o2_ping"), max_grade=2, grade_part=part2, grade=2 * int(o2_ping),
            description=tr("o2_h1 joint o2_srv"),
        )
        self.add_grade_element(
            title=no_tr("o2_q_range"), max_grade=1, grade_part=part2,
            grade=int(_ipv6_net(q2.get('range')) == area1), description=tr("préfixe du résumé"),
        )
        for field, title_ in (('summary_lsa', 'o2_q_summary_lsa'), ('stub_gets', 'o2_q_stub')):
            self.add_grade_element(
                title=no_tr(title_), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                grade=int(_norm(q2.get(field)) == cheat_o2[field]), description=tr("question de cours sur les zones"),
            )

        # =====================================================================
        # Part 3 — eBGP / MP-BGP (eb)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("ebgp"), tr("Partie 3 — eBGP en IPv6 (site eb)"))
        isp_link = a('eb_isp', 'eb_link')
        self.question_dummy(
            section=self.section(0),
            title=tr("eBGP multiprotocole avec un fournisseur"),
            description=tr("""
Votre AS {as_eb} (`eb_r1`, le réseau `eb_lan` et l'hôte `eb_h`) a reçu le préfixe `{eb48}`. Son
fournisseur `eb_isp` (AS {as_isp}, déjà configuré) vous attend sur le lien `eb_link` : `eb_r1` y
a l'adresse `{r1_link}`, `eb_isp` l'adresse `{isp_link}`. Derrière lui se trouve le serveur
`eb_srv` (`{srv}`). Sections @@ref:mpbgp@@ et @@ref:ebgp@@.

1. Configurez BGP sur `eb_r1` : AS {as_eb}, router-id `{rid}`, le voisin `eb_isp` activé dans la
   **seule** famille IPv6 unicast, une politique « tout accepter » en entrée et en sortie.
2. Annoncez le préfixe `{eb48}` de votre AS (et lui seul).
3. Vérifiez : `show bgp ipv6 unicast summary`, `show bgp ipv6 unicast`, `ip -6 route`, puis
   `ping eb_srv` depuis `eb_h`.
4. Regardez le détail de la route reçue d'`eb_isp` (`show bgp ipv6 unicast <préfixe>`) : quels
   sont ses prochains sauts ? Lequel est installé dans le noyau ?
""").format(as_eb=AS_OF['eb_r1'], eb48=b('eb'), as_isp=AS_OF['eb_isp'], r1_link=a('eb_r1', 'eb_link'),
            isp_link=isp_link, srv=d.ips6.eb_srv.ip, rid=ROUTER_ID['eb_r1'])
            + instructor(tr("""
**Solution.**

{solution}

Sans la route vers le trou noir, le `network` reste `inaccessible, import-check enabled` et
n'est pas annoncé ; sans route-map, la session est `(Policy)`. La route d'`eb_isp` porte deux
prochains sauts : `{isp_link}` (global) et `{isp_ll}` (link-local), et c'est la link-local qui
est installée dans le noyau.

Évaluation : `eb_router_id` (1), `eb_session` (3 : session établie en IPv6 unicast, vue par
`eb_isp`), `eb_policy` (1 : des préfixes reçus, pas de `(Policy)`), `eb_announce` (3 : `eb_isp`
a `{eb48}` avec l'AS_PATH `{as_eb}`), `eb_kernel` (2 : route BGP dans le noyau via une
link-local), `eb_ping` (3).
""").format(solution=_vtysh_text(ns.solution_ebgp()), isp_link=isp_link, isp_ll=ll('eb_isp', 'eb_link'),
            eb48=b('eb'), as_eb=AS_OF['eb_r1'])),
        )
        cheat_eb = {'afi_safi': '2/1', 'attribute': 'mp_reach_nlri', 'nh_global': str(isp_link),
                    'nh_ll': str(ll('eb_isp', 'eb_link'))}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site eb"),
            description=tr("""
- AFI / SAFI de la famille IPv6 unicast (sous la forme `AFI/SAFI`) : @@{afi_safi:[0-9 /]+}@@
- attribut BGP qui transporte les préfixes IPv6 :
  @@{attribute:>NEXT_HOP>>>next_hop|MP_REACH_NLRI>>>mp_reach_nlri|AS_PATH>>>as_path|COMMUNITIES>>>communities|ORIGINATOR_ID>>>originator_id}@@
- prochain saut **global** de la route d'`eb_isp` reçue par `eb_r1` : @@{nh_global:[0-9a-zA-Z:%./]+}@@
- prochain saut **link-local** de cette route : @@{nh_ll:[0-9a-zA-Z:%./]+}@@
""")
            + instructor(tr("""
**Solution.** **2/1** ; **MP_REACH_NLRI** (attribut 14) ; **`{nh_global}`** et **`{nh_ll}`**.

Évaluation : `eb_q_afi_safi`, `eb_q_nh_global`, `eb_q_nh_ll` (1 chacun) ; pour l'enseignant
seulement : `eb_q_attribute` (1).
""").format(nh_global=cheat_eb['nh_global'], nh_ll=cheat_eb['nh_ll'])),
            cheat_answers={"final": cheat_eb, "solve_ebgp": cheat_eb},
        )
        r1_bgp = (eb_cfg.get('router_bgp') or {}) if eb_cfg else {}
        self.add_grade_element(
            title=no_tr("eb_router_id"), max_grade=1, grade_part=part3,
            grade=int(r1_bgp.get('router_id') == ROUTER_ID['eb_r1']), description=tr("router-id BGP donné"),
        )
        isp_peer = (eb_isp_summary.get('peers') or {}).get(str(a('eb_r1', 'eb_link'))) or {}
        self.add_grade_element(
            title=no_tr("eb_session"), max_grade=3, grade_part=part3, grade=3 * int(bool(isp_peer.get('established'))),
            description=tr("session eBGP établie en IPv6 unicast"),
        )
        r1_peer = next((p for ip, p in (eb_r1_summary.get('peers') or {}).items() if _same_address(ip, isp_link)), {})
        self.add_grade_element(
            title=no_tr("eb_policy"), max_grade=1, grade_part=part3,
            grade=int(bool(r1_peer.get('established')) and not r1_peer.get('policy_blocked') and r1_peer.get('pfx_rcd', 0) >= 1),
            description=tr("politique en place : des préfixes reçus"),
        )
        announced = bgp_best_path(eb_isp_routes, b('eb'))
        self.add_grade_element(
            title=no_tr("eb_announce"), max_grade=3, grade_part=part3,
            grade=3 * int(bool(announced.get('valid')) and announced.get('as_list') == [AS_OF['eb_r1']]),
            description=tr("le /48 de l'AS annoncé au fournisseur"),
        )
        eb_nh = _kernel_nexthops(eb_k, b('eb_isp'), bgp=True)
        self.add_grade_element(
            title=no_tr("eb_kernel"), max_grade=2, grade_part=part3,
            grade=2 * int(bool(eb_nh) and all(_is_link_local(gw) for gw, _dev in eb_nh)),
            description=tr("route BGP dans le noyau, via une link-local"),
        )
        self.add_grade_element(
            title=no_tr("eb_ping"), max_grade=3, grade_part=part3, grade=3 * int(eb_ping),
            description=tr("eb_h joint eb_srv"),
        )
        self.add_grade_element(
            title=no_tr("eb_q_afi_safi"), max_grade=1, grade_part=part3, grade=int(_ints(q3.get('afi_safi')) == [2, 1]),
            description=tr("AFI / SAFI d'IPv6 unicast"),
        )
        self.add_grade_element(
            title=no_tr("eb_q_attribute"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('attribute')) == cheat_eb['attribute']), description=tr("attribut MP_REACH_NLRI"),
        )
        self.add_grade_element(
            title=no_tr("eb_q_nh_global"), max_grade=1, grade_part=part3,
            grade=int(same_ipv6(q3.get('nh_global'), isp_link)), description=tr("prochain saut global"),
        )
        self.add_grade_element(
            title=no_tr("eb_q_nh_ll"), max_grade=1, grade_part=part3,
            grade=int(same_ipv6(q3.get('nh_ll'), ll('eb_isp', 'eb_link'))), description=tr("prochain saut link-local"),
        )

        # =====================================================================
        # Part 4 — iBGP (ib)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("ibgp"), tr("Partie 4 — iBGP entre adresses de bouclage (site ib)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("iBGP : maillage complet et next-hop-self"),
            description=tr("""
L'AS {as_ib} a trois routeurs en ligne : `ib_r1` (bordure, relié au fournisseur `ib_isp`, AS
{as_isp}), `ib_r2` et `ib_r3` (le réseau `ib_lan` et l'hôte `ib_h`). OSPFv3 tourne déjà entre
eux et annonce leurs adresses de bouclage (`ib_r1-lo` `{lo1}`, `ib_r2-lo` `{lo2}`, `ib_r3-lo`
`{lo3}`) ; la session eBGP d'`ib_r1` avec `ib_isp` est en place et annonce `{ib48}`. Pourtant
`ib_h` ne joint pas `ib_srv` (`{srv}`). Section @@ref:ibgp@@.

1. Regardez les tables BGP et les tables de routage des trois routeurs : lequel connaît la
   route vers `ib_srv` ?
2. Montez le **maillage complet** iBGP entre les trois routeurs, **entre leurs adresses de
   bouclage**, en IPv6 unicast seulement (router-id donnés). Regardez sur `ib_r3` la route
   reçue : son prochain saut, est-elle utilisable ?
3. Corrigez avec `next-hop-self` sur `ib_r1`, puis vérifiez `ping ib_srv` depuis `ib_h`.
""").format(as_ib=AS_OF['ib_r1'], as_isp=AS_OF['ib_isp'], lo1=lo('ib_r1'), lo2=lo('ib_r2'), lo3=lo('ib_r3'),
            ib48=b('ib'), srv=d.ips6.ib_srv.ip)
            + instructor(tr("""
**Solution.**

{solution}

Sans `next-hop-self`, `ib_r3` reçoit la route de `{isp48}` avec le prochain saut `{nh_before}`
(l'adresse d'`ib_isp` sur `ib_link`, lien qu'OSPFv3 ne connaît pas) : la route est
`inaccessible`. Avec, le prochain saut est la boucle d'`ib_r1` (`{lo1}`), jointe par OSPFv3.
`ib_r2` doit avoir la route aussi : c'est lui qui relaie les paquets d'`ib_r3` vers `ib_r1`.

Évaluation : `ib_session_ib_r1_ib_r2`, `ib_session_ib_r1_ib_r3`, `ib_session_ib_r2_ib_r3`
(1 chacune : session iBGP établie entre les adresses de bouclage, active en IPv6),
`ib_next_hop_self` (3 : sur `ib_r3`, le prochain saut est la boucle d'`ib_r1`), `ib_r2_route`
(2 : route BGP dans le noyau d'`ib_r2`), `ib_ping` (3).
""").format(solution=_vtysh_text(ns.solution_ibgp()), isp48=b('ib_isp'), nh_before=a('ib_isp', 'ib_link'),
            lo1=lo('ib_r1'))),
        )
        cheat_ib = {'why_loopback': 'survives_link_failure', 'nh_before': str(a('ib_isp', 'ib_link')),
                    'why_r2': 'transit_router', 'mesh10': '45'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Questions sur le site ib"),
            description=tr("""
- on monte les sessions iBGP entre adresses de bouclage parce qu'une telle adresse :
  @@{why_loopback:>ne tombe avec aucune interface : la session survit à la panne d'un lien>>>survives_link_failure|accélère l'établissement de la session>>>faster|dispense de la politique de la RFC 8212>>>rfc8212|est imposée par le protocole en iBGP>>>mandatory}@@
- prochain saut de la route d'`ib_isp` vue par `ib_r3` **sans** `next-hop-self` :
  @@{nh_before:[0-9a-zA-Z:%./]+}@@
- `ib_r2`, qui n'a aucun voisin externe, doit parler BGP parce que :
  @@{why_r2:>il est traversé par le trafic vers l'extérieur et OSPFv3 ne transporte pas les routes externes>>>transit_router|il doit annoncer le /48 de l'AS>>>announce|il est le réflecteur de routes de l'AS>>>reflector|la session entre ib_r1 et ib_r3 passe par lui>>>session_path}@@
- nombre de sessions iBGP d'un maillage complet de 10 routeurs : @@{mesh10:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Une adresse de bouclage **ne tombe avec aucune interface** ; **`{nh_before}`** ;
**`ib_r2` est traversé** par le trafic et OSPFv3 ne connaît pas les routes externes ;
10 × 9 / 2 = **45** sessions.

Évaluation : `ib_q_nh_before`, `ib_q_mesh` (1 chacun) ; pour l'enseignant seulement :
`ib_q_why_loopback`, `ib_q_why_r2` (1 chacun).
""").format(nh_before=cheat_ib['nh_before'])),
            cheat_answers={"final": cheat_ib, "solve_ibgp": cheat_ib},
        )
        for x, y in ib_pairs:
            n = ib_nb[(x, y)]
            self.add_grade_element(
                title=no_tr(f"ib_session_{x}_{y}"), max_grade=1, grade_part=part4,
                grade=int(bool(n.get('established')) and n.get('link') == 'internal' and bool(n.get('af'))
                          and _same_address(n.get('local_host'), lo(x)) and _same_address(n.get('foreign_host'), lo(y))),
                description=tr("session iBGP entre adresses de bouclage"),
            )
        r3_best = bgp_best_path(ib_r3_routes, b('ib_isp'))
        self.add_grade_element(
            title=no_tr("ib_next_hop_self"), max_grade=3, grade_part=part4,
            grade=3 * int(bool(r3_best.get('valid')) and _same_address(r3_best.get('nexthop_global'), lo('ib_r1'))),
            description=tr("next-hop-self : prochain saut = boucle d'ib_r1"),
        )
        self.add_grade_element(
            title=no_tr("ib_r2_route"), max_grade=2, grade_part=part4,
            grade=2 * int(bool(_kernel_nexthops(ib_k2, b('ib_isp'), bgp=True))),
            description=tr("ib_r2 a la route externe"),
        )
        self.add_grade_element(
            title=no_tr("ib_ping"), max_grade=3, grade_part=part4, grade=3 * int(ib_ping),
            description=tr("ib_h joint ib_srv"),
        )
        self.add_grade_element(
            title=no_tr("ib_q_nh_before"), max_grade=1, grade_part=part4,
            grade=int(same_ipv6(q4.get('nh_before'), a('ib_isp', 'ib_link'))),
            description=tr("prochain saut sans next-hop-self"),
        )
        self.add_grade_element(
            title=no_tr("ib_q_mesh"), max_grade=1, grade_part=part4, grade=int(_ints(q4.get('mesh10')) == [45]),
            description=tr("taille d'un maillage complet"),
        )
        for field, title_ in (('why_loopback', 'ib_q_why_loopback'), ('why_r2', 'ib_q_why_r2')):
            self.add_grade_element(
                title=no_tr(title_), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                grade=int(_norm(q4.get(field)) == cheat_ib[field]), description=tr("question de cours sur iBGP"),
            )

        # =====================================================================
        # Part 5 — policies (po)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("policy"), tr("Partie 5 — Politiques BGP (site po)"))
        ispa, ispb = a('po_ispa', 'po_la'), a('po_ispb', 'po_lb')
        path_b = [AS_OF['po_ispb']] + [AS_OF['po_r1']] * (1 + PREPEND_COUNT)
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux fournisseurs : préférences, prepend, transit, bogons"),
            description=tr("""
L'AS {as_po} (`po_r1`, le réseau `po_lan` et l'hôte `po_h`, le préfixe `{po48}`) a deux
fournisseurs : `po_ispa` (ISP A, AS {as_a}) et `po_ispb` (ISP B, AS {as_b}), reliés tous deux à
« l'Internet » `po_inet` (AS {as_inet}, le serveur `po_srv`, le préfixe `{inet48}`). Les sessions
de `po_r1` sont en place, avec quatre route-maps vides qui acceptent tout : `ISPA-IN`,
`ISPA-OUT`, `ISPB-IN` et `ISPB-OUT`. Section @@ref:policies@@.

Objectifs, à atteindre en complétant ces route-maps (et des listes de préfixes) :

1. **Trafic sortant par ISP A** : `po_r1` doit préférer les routes d'ISP A, avec une
   local-preference de {lp}. Aujourd'hui il préfère ISP B pour joindre `{inet48}` : pourquoi ?
2. **Trafic entrant par ISP A** : l'Internet doit joindre `{po48}` par ISP A. Annoncez votre
   préfixe à ISP B avec votre numéro d'AS ajouté **deux fois** de plus (prepend).
3. **Pas de transit** : n'annoncez à chaque fournisseur que `{po48}`. Que fait `po_r1`
   aujourd'hui des routes apprises d'ISP A ?
4. **Bogons** : n'acceptez des fournisseurs que des préfixes de `2000::/3` de longueur au plus
   /48, à l'exception de ceux de `2001:db8::/32`. ISP B vous envoie en ce moment des préfixes qui
   ne passent pas ce filtre : lesquels ?

Après chaque modification : `clear bgp ipv6 unicast * soft`, puis `show bgp ipv6 unicast` et
`show bgp ipv6 unicast neighbors <adresse d'un ISP> advertised-routes`.
""").format(as_po=AS_OF['po_r1'], po48=b('po'), as_a=AS_OF['po_ispa'], as_b=AS_OF['po_ispb'],
            as_inet=AS_OF['po_inet'], inet48=b('po_inet'), lp=LOCAL_PREF)
            + instructor(tr("""
**Solution.**

{solution}

ISP A ajoute son AS une fois à toutes ses annonces : sans local-preference, le chemin par ISP B
est plus court. Sans filtre de sortie, `po_r1` réannonce à chaque fournisseur les routes de
l'autre (transit). ISP B envoie `{ula}` (adresses uniques locales), `{doc}` (documentation) et
`{long}` (plus long qu'un /48).

Évaluation : `po_local_pref` (3 : meilleur chemin vers `{inet48}` par ISP A, local-preference
au-dessus de 100), `po_prepend` (3 : `po_inet` passe par ISP A, le chemin par ISP B a l'AS
{as_po} trois fois), `po_no_transit_a`, `po_no_transit_b` (2 chacun : seul `{po48}` est
annoncé), `po_bogons` (3 : aucun des trois préfixes dans la table, `{inet48}` toujours reçu des
deux fournisseurs).
""").format(solution=_vtysh_text(ns.solution_policy()), ula=d.nets6.junk_ula, doc=d.nets6.junk_doc,
            long=d.nets6.junk_long, inet48=b('po_inet'), as_po=AS_OF['po_r1'], po48=b('po'))),
        )
        cheat_po = {'decision': 'local_pref', 'path_b': " ".join(str(x) for x in path_b), 'why_long': 'table_hijack',
                    'med': 'neighbor_as'}
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Questions sur le site po"),
            description=tr("""
- critère examiné **en premier** pour départager deux chemins :
  @@{{decision:>la local-preference>>>local_pref|la longueur de l'AS_PATH>>>as_path|le MED>>>med|le router-id>>>router_id}}@@
- AS_PATH de `{po48}` reçu par `po_inet` **par ISP B**, une fois le prepend en place (numéros
  séparés par des espaces) : @@{{path_b:[0-9 ]+}}@@
- on refuse les préfixes plus longs qu'un /48 :
  @@{{why_long:>pour limiter la taille de la table et les détournements par préfixe plus spécifique>>>table_hijack|parce qu'un /64 n'est pas routable>>>not_routable|parce que BGP ne peut pas transporter un /64>>>bgp_limit|pour économiser la bande passante des sessions>>>bandwidth}}@@
- le MED aurait-il pu remplacer le prepend pour attirer le trafic de l'Internet par ISP A ?
  @@{{med:>non : le MED n'est comparé qu'entre chemins venant d'un même AS voisin>>>neighbor_as|oui, il a le même effet>>>same|oui, mais seulement en iBGP>>>ibgp}}@@
""").format(po48=b('po'))
            + instructor(tr("""
**Solution.** La **local-preference** (avant la longueur de l'AS_PATH) ; **`{path_b}`** ; pour
**limiter la table et les détournements** ; **non**, le MED ne départage que des chemins venant
d'un même AS voisin.

Évaluation : `po_q_path_b` (2) ; pour l'enseignant seulement : `po_q_decision`, `po_q_why_long`,
`po_q_med` (1 chacun).
""").format(path_b=cheat_po['path_b'])),
            cheat_answers={"final": cheat_po, "solve_policy": cheat_po},
        )
        best_out = bgp_best_path(po_r1_routes, b('po_inet'))
        self.add_grade_element(
            title=no_tr("po_local_pref"), max_grade=3, grade_part=part5,
            grade=3 * int(_same_address(best_out.get('peer'), ispa) and (best_out.get('locprf') or 100) > 100),
            description=tr("trafic sortant par ISP A (local-preference)"),
        )
        best_in = bgp_best_path(po_inet_routes, b('po'))
        via_b = [p for p in po_inet_routes.get(str(b('po')), []) if _same_address(p.get('peer'), a('po_ispb', 'po_ib'))]
        self.add_grade_element(
            title=no_tr("po_prepend"), max_grade=3, grade_part=part5,
            grade=3 * int(_same_address(best_in.get('peer'), a('po_ispa', 'po_ia')) and bool(via_b)
                          and all(p['as_list'].count(AS_OF['po_r1']) >= 1 + PREPEND_COUNT for p in via_b)),
            description=tr("trafic entrant par ISP A (prepend vers ISP B)"),
        )
        for isp, label in (('po_ispa', 'a'), ('po_ispb', 'b')):
            self.add_grade_element(
                title=no_tr(f"po_no_transit_{label}"), max_grade=2, grade_part=part5,
                grade=2 * int(set(po_adv[isp]) == {str(b('po'))}),
                description=tr("seul le préfixe de l'AS est annoncé au fournisseur"),
            )
        junk = [d.nets6.junk_ula, d.nets6.junk_doc, d.nets6.junk_long]
        srv_paths = po_r1_routes.get(str(b('po_inet')), [])
        from_both = all(any(_same_address(p.get('peer'), peer) for p in srv_paths) for peer in (ispa, ispb))
        self.add_grade_element(
            title=no_tr("po_bogons"), max_grade=3, grade_part=part5,
            grade=3 * int(from_both and not any(str(n) in po_r1_routes for n in junk)),
            description=tr("bogons et préfixes trop longs refusés"),
        )
        self.add_grade_element(
            title=no_tr("po_q_path_b"), max_grade=2, grade_part=part5, grade=2 * int(_ints(q5.get('path_b')) == path_b),
            description=tr("AS_PATH après le prepend"),
        )
        for field, title_ in (('decision', 'po_q_decision'), ('why_long', 'po_q_why_long'), ('med', 'po_q_med')):
            self.add_grade_element(
                title=no_tr(title_), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                grade=int(_norm(q5.get(field)) == cheat_po[field]), description=tr("question de cours sur les politiques"),
            )

        # =====================================================================
        # Part 6 — troubleshooting (fix)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("fix"), tr("Partie 6 — Dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Quatre pannes"),
            description=tr("""
L'AS {as_fix} a deux routeurs reliés par `fix_l12`, avec OSPFv3 entre eux : `fix_r1` (bordure,
relié au fournisseur `fix_isp`, AS {as_isp}) et `fix_r2` (le réseau `fix_lan` et l'hôte `fix_h`).
`fix_r1` annonce une route par défaut dans OSPFv3 et doit annoncer `{fix48}` à `fix_isp`. Tout
est configuré... mais `fix_h` ne joint pas `fix_srv` (`{srv}`).

**Quatre pannes** se cachent sur `fix_r1` et `fix_r2` (rien n'est à corriger sur `fix_isp`).
Trouvez-les et corrigez-les, en gardant les router-id donnés (`fix_r1` : `{rid1}`, `fix_r2` :
`{rid2}`). Les journaux de FRR (`/var/log/frr/frr.log`) et la section @@ref:diagnostic@@
aident ; une panne peut en cacher une autre.
""").format(as_fix=AS_OF['fix_r1'], as_isp=AS_OF['fix_isp'], fix48=b('fix'), srv=d.ips6.fix_srv.ip,
            rid1=ROUTER_ID['fix_r1'], rid2=ROUTER_ID['fix_r2'])
            + instructor(tr("""
**Solution.** Sur `fix_r2` : `ip link set dev eth0 mtu 1500` (le MTU était {mtu} : voisinage
bloqué en `ExStart`, `MTU mismatch` dans le journal ; `ipv6 ospf6 mtu-ignore` des deux côtés
marche aussi), puis :

{solution}

et `clear ipv6 ospf6 process` sur `fix_r2` (son router-id était celui d'`fix_r1` : aucun voisin,
`Duplicate Router-ID` dans le journal). Sur `fix_r1`, le voisin n'était activé dans aucune
famille (session `Idle`) et `{fix48}` n'avait pas de route dans la RIB (*import-check*).

Évaluation : `fix_mtu` (2 : MTU égaux, ou `mtu-ignore` des deux côtés), `fix_router_id` (2 :
router-id distincts), `fix_adjacency` (2 : voisinage `Full`), `fix_activate` (3 : `fix_r1` reçoit
les routes de `fix_isp`), `fix_network` (2 : `fix_isp` reçoit `{fix48}`), `fix_ping` (3).
""").format(mtu=d.fix_mtu, solution=_vtysh_text(ns.solution_fix()), fix48=b('fix'))),
        )
        cheat_fix = {'mtu_state': 'exstart', 'not_activated': 'idle'}
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Symptômes"),
            description=tr("""
- état d'un voisinage OSPFv3 entre deux interfaces de MTU différents :
  @@{mtu_state:>Init>>>init|2-Way>>>twoway|ExStart / Exchange>>>exstart|Loading>>>loading|Full>>>full}@@
- état d'une session BGP dont le voisin n'est activé dans aucune famille :
  @@{not_activated:>Idle>>>idle|Active>>>active|Established, sans préfixe échangé>>>established|OpenConfirm>>>openconfirm}@@
""")
            + instructor(tr("""
**Solution.** **ExStart / Exchange** ; **Idle**.

Évaluation, pour l'enseignant seulement : `fix_q_mtu_state`, `fix_q_not_activated` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        mtus = [fix_if[r].get('mtu') for r in ('fix_r1', 'fix_r2')]
        ignored = all(fix_if[r].get('mtu_ignore') for r in ('fix_r1', 'fix_r2'))
        self.add_grade_element(
            title=no_tr("fix_mtu"), max_grade=2, grade_part=part6,
            grade=2 * int(None not in mtus and (mtus[0] == mtus[1] or ignored)),
            description=tr("MTU cohérents sur fix_l12"),
        )
        rids = [fix_info[r].get('router_id') for r in ('fix_r1', 'fix_r2')]
        self.add_grade_element(
            title=no_tr("fix_router_id"), max_grade=2, grade_part=part6,
            grade=2 * int(None not in rids and '0.0.0.0' not in rids and rids[0] != rids[1]),
            description=tr("router-id distincts"),
        )
        self.add_grade_element(
            title=no_tr("fix_adjacency"), max_grade=2, grade_part=part6,
            grade=2 * int(neighbor_is_full(fix_nb, interface=iface('fix_r1', 'fix_l12'))),
            description=tr("voisinage OSPFv3 Full"),
        )
        isp_paths = [p for p in fix_r1_routes.get(str(b('fix_isp')), [])
                     if p.get('valid') and _same_address(p.get('peer'), a('fix_isp', 'fix_link'))]
        self.add_grade_element(
            title=no_tr("fix_activate"), max_grade=3, grade_part=part6, grade=3 * int(bool(isp_paths)),
            description=tr("fix_r1 reçoit les routes du fournisseur"),
        )
        fix_announced = bgp_best_path(fix_isp_routes, b('fix'))
        self.add_grade_element(
            title=no_tr("fix_network"), max_grade=2, grade_part=part6,
            grade=2 * int(bool(fix_announced.get('valid')) and fix_announced.get('as_list') == [AS_OF['fix_r1']]),
            description=tr("le /48 de l'AS est annoncé"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=3, grade_part=part6, grade=3 * int(fix_ping),
            description=tr("fix_h joint fix_srv"),
        )
        for field, title_ in (('mtu_state', 'fix_q_mtu_state'), ('not_activated', 'fix_q_not_activated')):
            self.add_grade_element(
                title=no_tr(title_), max_grade=1, grade_part=part6, scope=CHOICE_SCOPE,
                grade=int(_norm(q6.get(field)) == cheat_fix[field]), description=tr("symptôme d'une panne"),
            )

        # =====================================================================
        # Part 7 — BGP unnumbered (un, bonus)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("unnumbered"), tr("Partie 7 — BGP unnumbered (site un, bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("BGP sans adresse globale (bonus)"),
            description=tr("""
`un_r1` (AS {as1}) et `un_r2` (AS {as2}, déjà configuré) sont reliés par `un_link`, un lien
**sans adresse globale** : leurs interfaces n'ont que leur link-local. Chacun a une adresse de
bouclage : `un_r1` `{lo1}`, `un_r2` `{lo2}`. Section @@ref:unnumbered@@.

Configurez sur `un_r1` une session BGP *unnumbered* avec `un_r2` (router-id `{rid}`), en IPv6
unicast, et annoncez l'adresse de bouclage d'`un_r1`. Vérifiez avec
`ping -I {lo1} {lo2}` depuis `un_r1`.
""").format(as1=AS_OF['un_r1'], as2=AS_OF['un_r2'], lo1=lo('un_r1'), lo2=lo('un_r2'), rid=ROUTER_ID['un_r1'])
            + instructor(tr("""
**Solution.**

{solution}

Évaluation (bonus) : `un_session` (1 : session établie avec le voisin `eth0`, sans adresse
globale sur le lien), `un_route` (1 : la boucle d'`un_r2` apprise en BGP, via une link-local),
`un_ping` (1 : ping entre les deux boucles).
""").format(solution=_vtysh_text(ns.solution_unnumbered()))),
        )
        un_peer = next((p for p in (un_summary.get('peers') or {}).values() if p.get('id_type') == 'interface'), {})
        self.add_grade_element(
            title=no_tr("un_session"), max_grade=1, grade_part=part7, bonus=True,
            grade=int(bool(un_peer.get('established')) and not _global_addresses(un_addrs)),
            description=tr("session BGP unnumbered établie"),
        )
        un_best = bgp_best_path(un_routes, f"{lo('un_r2')}/128")
        un_nh = _kernel_nexthops(un_k, f"{lo('un_r2')}/128", bgp=True)
        self.add_grade_element(
            title=no_tr("un_route"), max_grade=1, grade_part=part7, bonus=True,
            grade=int(bool(un_best.get('valid')) and bool(un_nh) and all(_is_link_local(gw) for gw, _dev in un_nh)),
            description=tr("boucle d'un_r2 apprise en BGP"),
        )
        self.add_grade_element(
            title=no_tr("un_ping"), max_grade=1, grade_part=part7, bonus=True,
            grade=int('bytes from' in (un_ping or '')), description=tr("ping entre les boucles"),
        )

        # =====================================================================
        # Part 8 — OSPFv3 authentication (au, bonus)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("auth"), tr("Partie 8 — Authentification OSPFv3 (site au, bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Trailer d'authentification (bonus)"),
            description=tr("""
`au_r2` (déjà configuré) fait OSPFv3 dans la zone 0 sur `au_link` et exige le trailer
d'authentification de la RFC 7166 : identifiant de clé **{key_id}**, algorithme
**HMAC-SHA-256**, clé **`{key}`**. Configurez OSPFv3 sur `au_r1` (router-id `{rid}`, zone 0 sur
`eth0`) pour former un voisinage `Full` avec `au_r2`. Que montre `show ipv6 ospf6 neighbor`
avant que l'authentification soit en place ? Section @@ref:ospfv3-auth@@.
""").format(key_id=d.au_key_id, key=d.au_key, rid=ROUTER_ID['au_r1'])
            + instructor(tr("""
**Solution.**

{solution}

Sans le trailer, `au_r1` voit `au_r2` en `Init` (il reçoit ses *Hello*), et `au_r2` ignore les
siens.

Évaluation (bonus) : `au_adjacency` (2 : voisinage `Full`), `au_auth` (1 : authentification
configurée sur `eth0` d'`au_r1`).
""").format(solution=_vtysh_text(ns.solution_auth()))),
        )
        self.add_grade_element(
            title=no_tr("au_adjacency"), max_grade=2, grade_part=part8, bonus=True,
            grade=2 * int(neighbor_is_full(au_nb, interface='eth0')), description=tr("voisinage authentifié Full"),
        )
        self.add_grade_element(
            title=no_tr("au_auth"), max_grade=1, grade_part=part8, bonus=True,
            grade=int(au_if.get('auth_type') in ('manualkey', 'keychain')),
            description=tr("trailer d'authentification configuré"),
        )


_TRANSLATIONS = {}
