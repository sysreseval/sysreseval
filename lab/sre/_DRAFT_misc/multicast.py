"""IP multicast lab with FRR (pimd, pim6d): IGMP, IGMP snooping, PIM-SM, PIM-SSM, MSDP.

Seven independent sites, one per part (completing a part gives all its points whatever the
others):

- ``igmp``: a LAN with two routers and two hosts.  ``igmp_r2`` runs IGMP from the start (the
  querier); the students enable IGMP on ``igmp_r1`` (lower address: it wins the election), set
  its query interval, force ``igmp_h2`` to IGMPv2;
- ``snoop``: a Linux bridge ``br0`` on ``snoop_sw`` between a source and two hosts, created
  with snooping off; the students enable snooping, the querier, IGMPv3 and fast leave;
- ``asm``: a triangle of routers (first hop ``asm_r1``, RP ``asm_r2`` on its loopback, last
  hop ``asm_r3``); PIM-SM with a static RP, shared tree then shortest-path tree;
- ``ssm``: two routers, a source with two addresses; PIM-SSM with IGMPv3, SSM range extended;
- ``msdp``: two PIM domains given configured, each with its own RP; MSDP peering and a scope
  boundary (239.192.0.0/14) at the border;
- ``fix``: a PIM domain shipped with four faults (no PIM on the source LAN, an nftables rule
  dropping PIM, a wrong RP address, the route to the RP through a link without PIM);
- ``v6`` (bonus): PIMv6 and MLD with pim6d, an SSM group of ff3e::/32.

Unicast routing is given everywhere (FRR static routes written in frr.conf by ``initial``).
Grading runs ``lib/mcast_probe.py`` on the hosts: receivers / sniffers started at step 1, a
burst of datagrams carrying a token sent at step 2, what was received read at step 3, plus the
json output of vtysh (lib/frr.py) and of ``ip`` / ``bridge`` (lib/bridging.py).  The states
``solve_<part>`` apply the reference solution of one part, ``final`` all of them.  Texts are French
(``tr()``) with their English in ``_TRANSLATIONS``, identifiers English.
"""
import json
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network, ip_address
from typing import Dict, List

import utils
from SRE import params
from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s, random_ipv6networks
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, set_ipv6_forward
from ipv6 import ipv6_subnet, solicited_node_multicast
from bridging import bridge_mcast_info, get_ip_links, get_mdb, get_sysctl_int, mdb_ports
from frr import (
    get_frr_running_config, get_igmp_groups, get_igmp_interfaces, get_mld_groups, get_mld_interfaces, get_mroutes,
    get_msdp_peers, get_msdp_sa, get_pim_group_type, get_pim_interfaces, get_pim_neighbors, get_pim_rp_info,
    igmp_enabled, pim_neighbor_on, prefix_list_permits, rp_for_group,
)
from mcast import (
    group_mac, install_mcast_probe, mac_aliases, mcast_recv_cmd, mcast_send_cmd, mcast_sniff_cmd,
    get_mcast_dump, received, normalize_mac,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Multicast IP : IGMP, PIM et MSDP", en="IP multicast: IGMP, PIM and MSDP")
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

# Router interfaces in ethN order: the network of each.  Must match _TOPOLOGY.
ROUTER_IFACES = {
    'igmp_r1': ['igmp_lan'],
    'igmp_r2': ['igmp_lan'],
    'asm_r1': ['asm_src_lan', 'asm_l12', 'asm_l13'],
    'asm_r2': ['asm_l12', 'asm_l23'],
    'asm_r3': ['asm_l23', 'asm_l13', 'asm_rx_lan'],
    'ssm_r1': ['ssm_src_lan', 'ssm_link'],
    'ssm_r2': ['ssm_link', 'ssm_rx_lan'],
    'msdp_r1': ['msdp_src_lan', 'msdp_link'],
    'msdp_r2': ['msdp_link', 'msdp_rx_lan'],
    'fix_r1': ['fix_src_lan', 'fix_la', 'fix_lb'],
    'fix_r2': ['fix_la', 'fix_lb', 'fix_rx_lan'],
    'v6_r1': ['v6_src_lan', 'v6_link'],
    'v6_r2': ['v6_link', 'v6_rx_lan'],
}
# Hosts (one interface, eth0): their network and the router of their default route (None:
# no default route, the igmp and snoop LANs are not routed)
HOSTS = {
    'igmp_h1': ('igmp_lan', None),
    'igmp_h2': ('igmp_lan', None),
    'snoop_src': ('snoop_lan', None),
    'snoop_h1': ('snoop_lan', None),
    'snoop_h2': ('snoop_lan', None),
    'asm_src': ('asm_src_lan', 'asm_r1'),
    'asm_h': ('asm_rx_lan', 'asm_r3'),
    'ssm_src': ('ssm_src_lan', 'ssm_r1'),
    'ssm_h': ('ssm_rx_lan', 'ssm_r2'),
    'msdp_src': ('msdp_src_lan', 'msdp_r1'),
    'msdp_h': ('msdp_rx_lan', 'msdp_r2'),
    'fix_src': ('fix_src_lan', 'fix_r1'),
    'fix_h': ('fix_rx_lan', 'fix_r2'),
    'v6_src': ('v6_src_lan', 'v6_r1'),
    'v6_h': ('v6_rx_lan', 'v6_r2'),
}
SWITCH = 'snoop_sw'
BRIDGE = 'br0'
# the ports of br0 (ethN of snoop_sw) and the host behind each
SWITCH_PORTS = {'eth0': 'snoop_src', 'eth1': 'snoop_h1', 'eth2': 'snoop_h2'}
SOURCES = ['snoop_src', 'asm_src', 'ssm_src', 'msdp_src', 'fix_src', 'v6_src']
V6_MACHINES = ['v6_r1', 'v6_r2', 'v6_src', 'v6_h']

# IPv4 networks: third octet of the /16 of the instance and prefix length.  The snoop LAN is one
# subnet over the three collision domains bridged by br0.
NET_PLAN = {
    'igmp_lan': (10, 24), 'snoop_lan': (20, 24),
    'asm_src_lan': (31, 24), 'asm_l12': (32, 30), 'asm_l13': (33, 30), 'asm_l23': (34, 30), 'asm_rx_lan': (35, 24),
    'ssm_src_lan': (41, 24), 'ssm_link': (42, 30), 'ssm_rx_lan': (43, 24),
    'msdp_src_lan': (51, 24), 'msdp_link': (52, 30), 'msdp_rx_lan': (53, 24),
    'fix_src_lan': (71, 24), 'fix_la': (72, 30), 'fix_lb': (73, 30), 'fix_rx_lan': (74, 24),
}
LOOPBACK_OCTET = 99
# loopback addresses (/32 in the 10.x.99.0/24 block): fourth octet
LOOPBACKS = {'asm_r2': 2, 'msdp_r1': 51, 'msdp_r2': 52, 'fix_r1': 71}
# IPv6 subnets of the ULA /48 (bonus part); a router is ::1 / ::2 on its links, a host ::100
NET6_PLAN = {'v6_src_lan': 0x61, 'v6_link': 0x62, 'v6_rx_lan': 0x63}
V6_HOST_ID = 0x100

SITE_COLORS = {'igmp': 'lightblue', 'snoop': 'khaki', 'asm': 'palegreen', 'ssm': 'lightpink', 'msdp': 'plum',
               'fix': 'lightsalmon', 'v6': 'lightcyan'}

_TOPOLOGY = {
    'igmp_lan': {'igmp_r1': 0, 'igmp_r2': 0, 'igmp_h1': 0, 'igmp_h2': 0},
    'snoop_p0': {'snoop_sw': 0, 'snoop_src': 0},
    'snoop_p1': {'snoop_sw': 1, 'snoop_h1': 0},
    'snoop_p2': {'snoop_sw': 2, 'snoop_h2': 0},
    'asm_src_lan': {'asm_r1': 0, 'asm_src': 0},
    'asm_l12': {'asm_r1': 1, 'asm_r2': 0},
    'asm_l13': {'asm_r1': 2, 'asm_r3': 1},
    'asm_l23': {'asm_r2': 1, 'asm_r3': 0},
    'asm_rx_lan': {'asm_r3': 2, 'asm_h': 0},
    'ssm_src_lan': {'ssm_r1': 0, 'ssm_src': 0},
    'ssm_link': {'ssm_r1': 1, 'ssm_r2': 0},
    'ssm_rx_lan': {'ssm_r2': 1, 'ssm_h': 0},
    'msdp_src_lan': {'msdp_r1': 0, 'msdp_src': 0},
    'msdp_link': {'msdp_r1': 1, 'msdp_r2': 0},
    'msdp_rx_lan': {'msdp_r2': 1, 'msdp_h': 0},
    'fix_src_lan': {'fix_r1': 0, 'fix_src': 0},
    'fix_la': {'fix_r1': 1, 'fix_r2': 0},
    'fix_lb': {'fix_r1': 2, 'fix_r2': 1},
    'fix_rx_lan': {'fix_r2': 2, 'fix_h': 0},
    'v6_src_lan': {'v6_r1': 0, 'v6_src': 0},
    'v6_link': {'v6_r1': 1, 'v6_r2': 0},
    'v6_rx_lan': {'v6_r2': 1, 'v6_h': 0},
}

# group ranges of the lab
RP_RANGE = IPv4Network('239.0.0.0/8')            # the range of the static RPs of the asm and fix sites
# the RPs of the two msdp domains serve every group: FRR 9.1 puts in its periodic SAs the RP of
# 224.0.0.0/4, and 0.0.0.0 without one, which the peer rejects (peer-RPF check; seen live).  FRR
# 10.3 behaves the same: with an RP for 239.0.0.0/8 only, the SA of a source that keeps sending
# leaves the peer's cache when the first one expires (210 s; seen live on 2026-11-19)
MSDP_RP_RANGE = IPv4Network('224.0.0.0/4')
SSM_DEFAULT = IPv4Network('232.0.0.0/8')
SSM_EXTRA = IPv4Network('239.232.0.0/16')        # part 5: added to the SSM range
SCOPED_RANGE = IPv4Network('239.192.0.0/14')     # part 6: organisation-local scope, stopped at the border
V6_SSM_RANGE = IPv6Network('ff3e::/32')
SSM_PLIST = 'SSM-RANGE'
SCOPE_PLIST = 'ORG-SCOPE'
IGMP_QUERY_INTERVALS = (20, 30, 40, 50)
FIX_NFT_FILE = '/etc/nftables.conf'
RECV_DURATION = 30                               # lifetime of the grading receivers (s)
MIN_RECEIVED = 5                                 # datagrams of a burst (of 20) that make a stream "received"
MCAST_ROUTE = IPv4Network('224.0.0.0/4')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE
# part 1: the classes of the dropdown (values of the field; names of mcast.multicast_scope())
SCOPE_CLASSES = ('link-local', 'internetwork-control', 'ssm', 'glop', 'local-scope', 'organization-scope', 'global')

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : pimd est activé{pim6d_note}
# (zebra, staticd et watchfrr démarrent toujours)
bgpd=no
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=yes
pim6d={pim6d}
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
    if router in V6_MACHINES:
        return FRR_DAEMONS.format(pim6d='yes', pim6d_note=", pim6d aussi")
    return FRR_DAEMONS.format(pim6d='no', pim6d_note="")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _random_group(block: IPv4Network, used: set, avoid=()) -> IPv4Address:
    """A random group of *block* (never .0 / .255 in the last octet), not in *used* nor in one
    of the networks of *avoid*; added to *used*."""
    while True:
        address = IPv4Address(int(block.network_address) + random.randrange(block.num_addresses))
        last = int(address) & 0xFF
        if 0 < last < 255 and address not in used and not any(address in net for net in avoid):
            used.add(address)
            return address


def _scope_example(cls: str, used: set) -> IPv4Address:
    """A multicast address of the class *cls* of SCOPE_CLASSES."""
    blocks = {
        'link-local': IPv4Network('224.0.0.0/24'), 'internetwork-control': IPv4Network('224.0.1.0/24'),
        'ssm': SSM_DEFAULT, 'glop': IPv4Network('233.0.0.0/9'), 'local-scope': IPv4Network('239.255.0.0/16'),
        'organization-scope': SCOPED_RANGE, 'global': IPv4Network('224.2.0.0/16'),
    }
    return _random_group(blocks[cls], used)


@dataclass(slots=True)
class Data(Data0):
    token: str = ""                 # payload token of the grading datagrams
    grade_port: int = 0             # UDP port of the grading streams
    query_interval: int = 0         # part 2: `ip igmp query-interval`
    # part 1: addressing
    mac_group: IPv4Address = None
    scope_a: IPv4Address = None
    scope_b: IPv4Address = None
    scope_c: IPv4Address = None
    scope_a_class: str = ""
    scope_b_class: str = ""
    scope_c_class: str = ""
    # groups the students use for their own experiments (instructions) ...
    igmp_group: IPv4Address = None
    snoop_group: IPv4Address = None
    asm_group: IPv4Address = None
    ssm_group: IPv4Address = None
    msdp_group: IPv4Address = None
    scoped_group: IPv4Address = None
    fix_group: IPv4Address = None
    v6_group: IPv6Address = None
    # ... and those of the grading streams (never the same)
    g_igmp1: IPv4Address = None     # joined by igmp_h1 (IGMPv3)
    g_igmp2: IPv4Address = None     # joined by igmp_h2 (IGMPv2 once forced)
    g_snoop: IPv4Address = None
    g_asm: IPv4Address = None
    g_ssm: IPv4Address = None       # 232/8: (S1, G) joined, S1 and S2 send
    g_ssm_extra: IPv4Address = None  # 239.232/16: SSM once the range is extended
    g_msdp: IPv4Address = None      # crosses the border through MSDP
    g_scoped: IPv4Address = None    # 239.192/14: stopped at the border
    g_fix: IPv4Address = None
    g_v6: IPv6Address = None

    @classmethod
    def generate(cls):
        data = cls()
        data.token = utils.random_password(10).lower()
        data.token = ''.join(c for c in data.token if c.isalnum()) or 'sremcast'
        data.grade_port = random.randint(20000, 29999)
        data.query_interval = random.choice(IGMP_QUERY_INTERVALS)

        used = set()
        # part 1: a group whose second octet has its high bit set, so that the mapping drops it
        data.mac_group = _random_group(IPv4Network('239.128.0.0/10'), used)
        classes = random.sample(SCOPE_CLASSES, 3)
        data.scope_a_class, data.scope_b_class, data.scope_c_class = classes
        data.scope_a, data.scope_b, data.scope_c = (_scope_example(c, used) for c in classes)

        plain = IPv4Network('239.0.0.0/9')        # 239.0-127: neither scoped nor the SSM extension
        for name in ('igmp_group', 'snoop_group', 'asm_group', 'msdp_group', 'fix_group',
                     'g_igmp1', 'g_igmp2', 'g_snoop', 'g_asm', 'g_msdp', 'g_fix'):
            setattr(data, name, _random_group(plain, used))
        data.ssm_group = _random_group(SSM_DEFAULT, used)
        data.g_ssm = _random_group(SSM_DEFAULT, used)
        data.g_ssm_extra = _random_group(SSM_EXTRA, used)
        data.scoped_group = _random_group(SCOPED_RANGE, used)
        data.g_scoped = _random_group(SCOPED_RANGE, used)
        data.v6_group = IPv6Address(int(V6_SSM_RANGE.network_address) + random.randint(0x1000, 0xFFFF))
        data.g_v6 = IPv6Address(int(V6_SSM_RANGE.network_address) + (random.randint(1, 0xFFFF) << 16)
                                + random.randint(1, 0xFFFF))

        # The lab is one 10.x.0.0/16; the third octet of a network tells which one it is.
        data.nets.site = random_ipv4networks(masks=[16], from_network=IPv4Network("10.0.0.0/8"),
                                             exclude=[IPv4Network("10.0.0.0/16")])[0]
        blocks = list(data.nets.site.subnets(new_prefix=24))
        for net, (octet, prefix) in NET_PLAN.items():
            setattr(data.nets, net, next(blocks[octet].subnets(new_prefix=prefix)))
        for router, octet in LOOPBACKS.items():
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(blocks[LOOPBACK_OCTET].network_address) + octet, 32)))

        # router interfaces and hosts of each IPv4 network
        members = {net: [] for net in NET_PLAN}
        for router, nets in ROUTER_IFACES.items():
            for net in nets:
                if net in members:
                    members[net].append(f"{router}_{net}")
        for host, (net, _gw) in HOSTS.items():
            if net in members:
                members[net].append(host)
        members['snoop_lan'].append(SWITCH)
        members['ssm_src_lan'].append('ssm_src2')       # the second source address of ssm_src
        for net, names in members.items():
            addresses = random_ipv4s(getattr(data.nets, net), len(names))
            if net == 'igmp_lan':
                # igmp_r1 must win the querier election against igmp_r2: the lowest address
                addresses = sorted(addresses, key=lambda a: int(a.ip))
            for name, address in zip(names, addresses):
                setattr(data.ips, name, address)

        # IPv6 (bonus part): one ULA /48
        data.nets6.site = random_ipv6networks(48, from_private_network=True)[0]
        for net, number in NET6_PLAN.items():
            setattr(data.nets6, net, ipv6_subnet(data.nets6.site, number, 64))
        for router in ('v6_r1', 'v6_r2'):
            for net in ROUTER_IFACES[router]:
                setattr(data.ips6, f"{router}_{net}", _ipv6(getattr(data.nets6, net), int(router[-1])))
        for host in ('v6_src', 'v6_h'):
            setattr(data.ips6, host, _ipv6(getattr(data.nets6, HOSTS[host][0]), V6_HOST_ID + random.randint(1, 0xEFF)))
        return data


def _ipv6(network, identifier: int) -> IPv6Interface:
    return IPv6Interface((int(network.network_address) + identifier, network.prefixlen))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'image': sre_docker_image("netdev13"), 'color': SITE_COLORS[site_of(machine)]}
    if machine in V6_MACHINES:
        spec['ipv6'] = True
    if machine in ROUTER_IFACES:
        spec['shape'] = 'box'
    return spec


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in list(ROUTER_IFACES) + [SWITCH] + list(HOSTS)}
    _network_specs = {}
    # Interface numbers must follow ROUTER_IFACES (ethN = position in the list).
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        default6 = IPv6Network("::/0")

        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, nets in ROUTER_IFACES.items():
            if r in V6_MACHINES:
                self.net_config[r] = [([getattr(d.ips6, f"{r}_{net}")], []) for net in nets]
            else:
                self.net_config[r] = [([getattr(d.ips, f"{r}_{net}")], []) for net in nets]
        for h, (net, gw) in HOSTS.items():
            if h in V6_MACHINES:
                self.net_config[h] = [([getattr(d.ips6, h)], [(default6, getattr(d.ips6, f"{gw}_{net}").ip)])]
            else:
                routes = [(default, getattr(d.ips, f"{gw}_{net}").ip)] if gw else []
                addresses = [getattr(d.ips, h)] + ([d.ips.ssm_src2] if h == 'ssm_src' else [])
                self.net_config[h] = [(addresses, routes)]
        # the ports of the bridge have no address (br0 gets the switch's one, see initial())
        self.net_config[SWITCH] = [([], []) for _port in SWITCH_PORTS]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX
        lines = []
        for r, nets in ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                address = getattr(d.ips6, f"{r}_{net}") if r in V6_MACHINES else getattr(d.ips, f"{r}_{net}")
                lines.append(f"{address.ip}\t{names}")
        for r in LOOPBACKS:
            lines.append(f"{getattr(d.ips, f'{r}_lo').ip}\t{r}-lo")
        for h in HOSTS:
            address = getattr(d.ips6, h) if h in V6_MACHINES else getattr(d.ips, h)
            lines.append(f"{address.ip}\t{h}")
        lines.append(f"{d.ips.ssm_src2.ip}\tssm_src-2")
        lines.append(f"{d.ips.snoop_sw.ip}\t{SWITCH}")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le multicast IP : principes"), tag="principle")
            + tr("""
Il y a trois façons de remettre un datagramme IP :

- l'**unicast** : un émetteur, un destinataire ;
- la **diffusion** (*broadcast*) : tous les hôtes du réseau local, et lui seul (les routeurs ne la
  propagent pas) ;
- le **multicast** (multidiffusion) : un émetteur, un **groupe** de destinataires, qui peuvent
  être sur n'importe quel réseau.

Un groupe est désigné par une **adresse de groupe** (section @@ref:addressing@@). Le modèle du
groupe d'hôtes (RFC 1112) est très simple :

- un hôte qui veut recevoir le trafic d'un groupe le **rejoint** : son noyau le signale aux
  routeurs de son réseau par IGMP (section @@ref:igmp@@) ;
- n'importe qui peut **émettre** vers un groupe, sans en être membre : il suffit d'envoyer un
  datagramme UDP à l'adresse du groupe ;
- les routeurs construisent entre eux un **arbre de distribution** (section @@ref:routing@@) :
  un datagramme est dupliqué seulement là où les chemins vers les membres divergent. Un lien ne
  le transporte qu'une fois, quel que soit le nombre de récepteurs derrière lui.

Le multicast passe par **UDP** : il n'y a ni connexion, ni accusé de réception, ni contrôle de
congestion (une connexion TCP n'a qu'un seul destinataire). Il sert à la télévision sur IP, à la
diffusion de données financières, à la découverte de services (mDNS, SSDP), aux protocoles de
routage (OSPF, RIP, PIM, VRRP), à la diffusion de logiciels ou d'images système et au transport
des VXLAN.

Deux modèles de service coexistent :

- **ASM** (*Any-Source Multicast*) : le récepteur rejoint un groupe **G** et reçoit le trafic de
  toutes ses sources. L'état correspondant dans les routeurs se note **(\\*,G)** ;
- **SSM** (*Source-Specific Multicast*, section @@ref:ssm@@) : le récepteur s'abonne à un
  **canal (S,G)**, c'est-à-dire au groupe G émis par la seule source S.

### @@sec:ttl@@ Le TTL des datagrammes multicast

Chaque routeur décrémente le TTL d'un datagramme multicast comme celui d'un datagramme unicast,
et le jette à 0. Or **une socket multicast émet par défaut avec un TTL de 1** : sans réglage, le
trafic ne quitte pas le réseau local. Une application qui veut traverser n routeurs doit fixer
un TTL supérieur à n (option `IP_MULTICAST_TTL`, `-T` d'`iperf`).

Les groupes de `224.0.0.0/24` (section @@ref:addressing@@) ne sont **jamais** routés, quel que
soit leur TTL : ce sont ceux des protocoles de contrôle d'un lien (OSPF, RIP, PIM, IGMPv3...),
émis d'ailleurs avec un TTL de 1.
""")
            + info_subtitle(tr("L'adressage multicast"), tag="addressing")
            + tr("""
Les adresses IPv4 multicast forment le bloc **224.0.0.0/4** (de 224.0.0.0 à 239.255.255.255, l'ancienne
« classe D » ; registre de l'IANA, RFC 5771) :

| bloc | usage |
|------|-------|
| `224.0.0.0/24` | **lien local** (*link-local*) : protocoles de contrôle d'un réseau, jamais routés |
| `224.0.1.0/24` | contrôle inter-réseaux (*internetwork control*) : routés, par exemple NTP `224.0.1.1` |
| `224.2.0.0/16` et suivants | groupes **globaux** attribués par l'IANA ou ad hoc |
| `232.0.0.0/8` | **SSM** (section @@ref:ssm@@) |
| `233.0.0.0/8` | **GLOP** (RFC 3180) : `233.X.Y.0/24` revient au réseau dont le numéro d'AS (16 bits) s'écrit X×256+Y |
| `239.0.0.0/8` | **portée administrative** (RFC 2365), l'équivalent des adresses privées : un groupe n'y a de sens que dans un domaine |
| `239.255.0.0/16` | dont la **portée locale** (*local scope*) : un site |
| `239.192.0.0/14` | dont la **portée organisation** (*organization-local scope*) |

Quelques groupes bien connus :

| groupe | membres |
|--------|---------|
| `224.0.0.1` | tous les hôtes du lien (*all-systems*) : requêtes générales d'IGMP |
| `224.0.0.2` | tous les routeurs du lien : messages *Leave* d'IGMPv2 |
| `224.0.0.5` / `224.0.0.6` | routeurs OSPF / routeurs désignés OSPF |
| `224.0.0.9` | routeurs RIPv2 |
| `224.0.0.13` | routeurs PIM (*all-PIM-routers*) |
| `224.0.0.18` | routeurs VRRP |
| `224.0.0.22` | routeurs IGMPv3 : destination des rapports d'IGMPv3 |
| `224.0.0.251` | mDNS (Avahi, Bonjour) |

### @@sec:mac@@ De l'adresse de groupe à l'adresse MAC

Sur Ethernet, une trame multicast IPv4 est envoyée à une adresse MAC de groupe : le préfixe
**`01:00:5e`** suivi des **23 bits de poids faible** de l'adresse IP (RFC 1112). Par exemple :

```
groupe IP     239.  1. 2. 3   = 11101111.00000001.00000010.00000011
23 bits bas                            .0000001.00000010.00000011  = 01:02:03
adresse MAC   01:00:5e:01:02:03
```

Une adresse de groupe a 28 bits significatifs (les 4 premiers valent toujours `1110`) : les
**5 bits** qui séparent les 28 des 23 sont perdus. **32 groupes** partagent donc chaque adresse
MAC : `224.1.2.3`, `225.1.2.3`, `239.129.2.3` (le bit de poids fort du deuxième octet est
aussi perdu) et 29 autres donnent toutes `01:00:5e:01:02:03`. La carte réseau, qui filtre les
trames sur leur adresse MAC, laisse passer celles des groupes « cousins » : c'est le noyau qui
fait le tri. Un commutateur qui fait de l'IGMP snooping (section @@ref:snooping@@) sur les adresses
MAC confond aussi ces groupes.

### @@sec:ipv6addr@@ Les adresses IPv6 multicast

En IPv6, la diffusion n'existe plus : tout ce qu'elle faisait passe par le multicast. Les
adresses multicast forment le bloc **`ff00::/8`**. Le deuxième octet porte deux champs de 4 bits :

- les **drapeaux** : `0` pour une adresse permanente attribuée par l'IANA, `1` pour une adresse
  temporaire, `3` pour une adresse dérivée d'un préfixe unicast : `ff3x::/32` est le bloc **SSM** ;
- la **portée** (*scope*), que les routeurs respectent d'eux-mêmes :

| portée | valeur | exemple |
|--------|--------|---------|
| interface | 1 | `ff01::1` |
| lien | 2 | `ff02::1` (tous les nœuds), `ff02::2` (tous les routeurs), `ff02::d` (PIM), `ff02::16` (MLDv2) |
| administration locale | 4 | |
| site | 5 | `ff05::2` |
| organisation | 8 | |
| globale | e | `ff0e::…`, `ff3e::…` |

Chaque adresse unicast d'une interface fait aussi rejoindre le groupe **solicited-node**
`ff02::1:ffXX:XXXX`, formé des **24 derniers bits** de l'adresse : c'est à lui que la découverte
des voisins (NDP) envoie ses sollicitations. L'adresse MAC d'un groupe IPv6 est **`33:33`**
suivi des **32 derniers bits** du groupe (RFC 2464). Par exemple, pour `2001:db8::1:2abc:d123` :

```
solicited-node  ff02::1:ffbc:d123
adresse MAC     33:33:ff:bc:d1:23
```
""")
            + info_subtitle(tr("Côté hôte : émettre et recevoir"), tag="host")
            + tr("""
Pour **recevoir**, une application ouvre une socket UDP liée au port du flux et demande au noyau
de rejoindre le groupe sur une interface (`IP_ADD_MEMBERSHIP` ou `MCAST_JOIN_GROUP` ; pour un
canal SSM, `IP_ADD_SOURCE_MEMBERSHIP` ou `MCAST_JOIN_SOURCE_GROUP`). Le noyau émet aussitôt le
rapport IGMP correspondant (section @@ref:igmp@@) et le répète quand un routeur l'interroge.
Quand la dernière application quitte le groupe, il émet le départ (*leave*).

Pour **émettre**, il suffit d'envoyer un datagramme à l'adresse du groupe. Trois réglages
comptent :

- le **TTL**, de **1 par défaut** (`IP_MULTICAST_TTL`, section @@ref:ttl@@) ;
- l'**interface de sortie** : à défaut de `IP_MULTICAST_IF`, le noyau la choisit dans la table
  de routage, comme pour l'unicast. Un hôte sans route par défaut et sans route vers
  `224.0.0.0/4` ne peut pas émettre (*Network is unreachable*) : `ip route add 224.0.0.0/4 dev
  eth0` lui en donne une ;
- le **bouclage** (`IP_MULTICAST_LOOP`) : l'émetteur reçoit-il lui-même ce qu'il émet ?

Pour observer l'état d'un hôte :

- `ip maddr show dev eth0` : les groupes rejoints par l'interface et leur adresse MAC ;
- `cat /proc/net/igmp` : les mêmes, avec la version d'IGMP utilisée sur chaque interface
  (adresses en hexadécimal, octets dans l'ordre inverse : `010000E0` est `224.0.0.1`) ;
- `ss -ulpn` : les sockets UDP et leur port.

Le noyau choisit seul la version d'IGMP : la plus récente (v3), sauf s'il entend un routeur
plus ancien sur le lien. On peut la forcer : `sysctl -w net.ipv4.conf.eth0.force_igmp_version=2`
(0 : automatique) ; pour MLD, `net.ipv6.conf.eth0.force_mld_version`.
""")
            + info_subtitle(tr("IGMP : l'adhésion aux groupes"), tag="igmp")
            + tr("""
**IGMP** (*Internet Group Management Protocol*) est le dialogue entre les hôtes d'un réseau
local et ses routeurs multicast. Un routeur n'apprend pas *quels* hôtes sont membres d'un
groupe mais seulement *s'il reste au moins un membre* sur chacune de ses interfaces : il ne lui
en faut pas plus pour décider s'il doit y transmettre le trafic du groupe.

### @@sec:igmpmsg@@ Messages et versions

IGMP est transporté directement dans IP (protocole **2**), avec un **TTL de 1** et l'option IP
**Router Alert** (RFC 2113), qui demande à chaque routeur d'examiner le paquet même s'il ne lui
est pas adressé.

| version | nouveautés | rapport (*report*) envoyé à | départ |
|---------|-----------|-----------------------------|--------|
| v1 (RFC 1112) | requête (*query*) et rapport | l'adresse du groupe | silencieux (expiration) |
| v2 (RFC 2236) | message **Leave**, requête spécifique à un groupe, délai de réponse, élection du querier | l'adresse du groupe | *Leave* vers **224.0.0.2** |
| v3 (RFC 3376) | **filtrage des sources** : enregistrements INCLUDE / EXCLUDE, ALLOW / BLOCK | **224.0.0.22** | un rapport de changement d'état |

- La **requête générale** (*general query*) est envoyée à `224.0.0.1` : « quels groupes
  avez-vous ? ». Chaque hôte répond après un délai aléatoire, borné par le *max response time*.
  En v1 et v2, un hôte qui entend un autre membre répondre pour le même groupe se tait.
- La **requête spécifique** (*group-specific query*, envoyée au groupe lui-même) suit un
  *Leave* : « reste-t-il un membre de ce groupe ? ».
- En **v3**, un rapport contient plusieurs **enregistrements de groupe** : `MODE_IS_EXCLUDE`
  { } signifie « toutes les sources », c'est l'adhésion ASM ; `MODE_IS_INCLUDE` {S1} signifie
  « seulement la source S1 », c'est l'abonnement SSM. Un départ est un rapport de changement
  d'état vers `INCLUDE` { }.

### @@sec:querier@@ Le querier

Sur un lien où plusieurs routeurs font IGMP, un seul envoie les requêtes : le **querier**. En v2
et v3, c'est celui qui a la **plus petite adresse IP** sur le lien. Un routeur qui entend une
requête venant d'une adresse plus petite que la sienne cesse d'interroger. Si plus aucune
requête n'est entendue pendant l'*other querier present interval*, il reprend le rôle.

Les autres routeurs continuent d'écouter les rapports : tous connaissent les groupes du lien.
Ne confondez pas le querier avec le **routeur désigné** de PIM (section @@ref:hello@@), élu, lui,
sur la plus grande adresse.

### @@sec:igmptimers@@ Les temporisateurs

| paramètre | défaut | rôle |
|-----------|--------|------|
| *query interval* | 125 s | période des requêtes générales |
| *query response interval* | 10 s | délai maximal de réponse annoncé dans la requête |
| *robustness variable* | 2 | nombre de répétitions d'un message (perte de paquets) |
| *group membership interval* | 2 × 125 + 10 = 260 s | au-delà, un groupe sans rapport est oublié |
| *other querier present interval* | 2 × 125 + 10 / 2 = 255 s | au-delà, un autre routeur devient querier |
| *last member query interval* | 1 s | délai entre les requêtes spécifiques qui suivent un départ |
| *last member query count* | 2 | nombre de ces requêtes |
| *startup query interval* | 125 / 4 s | requêtes rapprochées au démarrage |

Un départ explicite est vite traité : environ 2 × 1 s après le *Leave*, le routeur arrête le
trafic s'il n'a pas eu de réponse. Un hôte qui disparaît sans rien dire n'est oublié qu'au
bout de 260 s.

### @@sec:compat@@ Compatibilité entre versions

Un hôte s'aligne sur le querier : s'il entend une requête v2, il répond en v2. Un routeur v3
qui reçoit un **rapport v2** pour un groupe passe **ce groupe** en mode de compatibilité v2
pendant l'*older host present interval* (260 s par défaut) : `show ip igmp groups` affiche alors
la version 2. Les enregistrements de source sont ignorés pour ce groupe, car un hôte v2 ne sait
pas filtrer les sources.
""")
            + info_subtitle(tr("L'IGMP snooping des commutateurs"), tag="snooping")
            + tr("""
Un commutateur n'apprend une adresse MAC que comme **adresse source** d'une trame. Une adresse
de groupe n'est jamais une adresse source : les trames multicast sont donc **inondées sur tous
les ports**, comme la diffusion. Sur un réseau où passent quelques flux vidéo, tous les postes
reçoivent tout.

L'**IGMP snooping** (RFC 4541) consiste à lire au passage les messages IGMP :

- un **rapport** reçu sur un port inscrit ce port comme membre du groupe dans la **table des
  groupes** (*mdb*, *multicast database*) ; un *Leave*, ou l'absence de réponse aux requêtes,
  l'en retire ;
- une **requête** reçue sur un port le marque comme **port routeur** (*mrouter port*) : c'est
  par là qu'est le routeur multicast, qui doit recevoir tous les groupes ;
- une trame d'un groupe connu n'est plus transmise qu'aux ports membres et aux ports routeurs.
  Les groupes de `224.0.0.0/24` restent inondés.

Le snooping a besoin de **requêtes** pour tenir sa table à jour : sans elles, les hôtes ne
répètent pas leurs rapports. Sur un réseau sans routeur multicast, le commutateur doit envoyer
lui-même les requêtes : c'est sa fonction de **querier**. Le pont de Linux est prudent : **tant
qu'il n'a détecté aucun querier** (le sien ou un autre), il **inonde tout le multicast** sur
tous ses ports, même avec le snooping actif, pour ne priver personne d'un flux.

Le **départ rapide** (*fast leave*) retire un port d'un groupe dès le premier *Leave*, sans
requête spécifique. Ce n'est correct que si le port ne dessert qu'**un seul hôte**.

Avec le pont de Linux (`ip-link(8)`, `bridge(8)`) :

```
ip link set br0 type bridge mcast_snooping 1      # le snooping (actif par défaut à la création)
ip link set br0 type bridge mcast_querier 1       # le pont émet les requêtes
ip link set br0 type bridge mcast_igmp_version 3  # version de ses requêtes (2 par défaut)
ip link set br0 type bridge mcast_query_use_ifaddr 1   # requêtes émises depuis l'adresse de br0
                                                       # (sinon depuis 0.0.0.0)
bridge link set dev eth1 fastleave on             # départ rapide sur un port
ip -d link show br0                               # mcast_snooping, mcast_querier, temporisateurs
bridge -d link show                               # fastleave, mcast_router par port
bridge mdb show                                   # la table des groupes : port, groupe
```

Les temporisateurs du pont s'expriment en **centièmes de seconde** : `mcast_query_interval 12500`
vaut 125 s.
""")
            + info_subtitle(tr("Le routage multicast"), tag="routing")
            + tr("""
Le but du routage multicast est d'amener le trafic d'un groupe sur tous les réseaux où il y a
des membres, sur eux seuls, et sans boucle.

### @@sec:rpf@@ Le contrôle RPF

Un routeur unicast regarde l'adresse de **destination** d'un paquet. Un routeur multicast
regarde d'abord sa **source** : il n'accepte un paquet que s'il arrive par l'interface qu'il
utiliserait lui-même pour **joindre la source**, d'après sa table de routage unicast. C'est le
contrôle **RPF** (*Reverse Path Forwarding*). L'interface en question est l'**interface RPF**
(l'**iif**), le routeur suivant vers la source est le **voisin RPF**. Un paquet qui arrive par
une autre interface est jeté : c'est ce qui empêche les boucles et les doublons.

Conséquence : **le multicast dépend du routage unicast**. Une route absente ou asymétrique vers
la source, ou une route qui passe par un lien sans routage multicast, suffit à bloquer un flux
(section @@ref:diagnostic@@). Sur l'arbre partagé (section @@ref:join@@), le contrôle porte sur
l'adresse du point de rendez-vous au lieu de la source.

### @@sec:trees@@ Les arbres de distribution

- l'**arbre de source**, ou **arbre des plus courts chemins** (*SPT*), noté **(S,G)** : la
  réunion des plus courts chemins de la source S vers chaque membre de G ; un arbre par source ;
- l'**arbre partagé** (*RPT*), noté **(\\*,G)** : un seul arbre par groupe, enraciné en un
  routeur choisi, le **point de rendez-vous** (*RP*), vers lequel toutes les sources envoient.

Dans un routeur, une entrée (S,G) ou (\\*,G) a une **interface d'entrée** (iif) et une **liste
d'interfaces de sortie** (*OIL*, *outgoing interface list*).

### @@sec:modes@@ Mode dense et mode clairsemé

- **Mode dense** (DVMRP, PIM-DM) : le trafic est d'abord **inondé** partout, puis les branches
  sans membres sont **élaguées** (*prune*), et l'inondation recommence toutes les 3 minutes.
  Adapté à un réseau où presque tous les liens ont des membres.
- **Mode clairsemé** (PIM-SM, section @@ref:pimsm@@) : rien ne circule sans une **demande
  explicite** (*join*) remontée des membres. C'est le mode utilisé partout aujourd'hui.

### @@sec:mfc@@ Le plan de transfert du noyau

Le noyau Linux transmet le multicast grâce à son **MFC** (*multicast forwarding cache*) : des
entrées (S,G) ou (\\*,G) avec une interface d'entrée et des interfaces de sortie. Il ne les
calcule pas : **un seul démon** à la fois ouvre la socket de routage multicast et les y
installe. Ce peut être `pimd` de FRR (PIM), ou `smcrouted` pour du routage multicast
**statique** (`smcroutectl add eth0 SOURCE GROUPE eth1`).

```
ip mroute show                 # les entrées du MFC : (S,G) Iif ... Oifs ...
ip -s mroute show              # avec les compteurs de paquets
cat /proc/net/ip_mr_vif        # les interfaces virtuelles multicast
```
""")
            + info_subtitle(tr("PIM-SM"), tag="pimsm")
            + tr("""
**PIM** (*Protocol Independent Multicast* ; RFC 7761 pour PIM-SM) est « indépendant » parce
qu'il n'échange aucune route : il s'appuie sur la table de routage unicast existante, qu'elle
soit statique ou apprise par OSPF ou BGP, pour ses contrôles RPF. Ses messages sont portés par
IP (protocole **103**). Ils sont envoyés à **224.0.0.13** avec un TTL de 1, sauf *Register* et
*Register-Stop*, qui sont unicast.

### @@sec:hello@@ Voisins et routeur désigné

Chaque interface où PIM est actif émet un **Hello** toutes les **30 s** (validité 105 s) : les
routeurs d'un même lien deviennent **voisins PIM**. Un routeur n'accepte les messages *Join* que
d'un voisin.

Sur chaque réseau, un **routeur désigné** (**DR**) est élu : la plus grande priorité, puis la
plus grande adresse. Sur un réseau d'hôtes, c'est le DR qui transforme les rapports IGMP des
récepteurs en messages *Join* et qui enregistre les sources (*Register*).

### @@sec:rp@@ Le point de rendez-vous

Tous les routeurs du domaine doivent associer chaque groupe au **même RP**. Il y a plusieurs
façons de le leur apprendre :

- la configuration **statique** (`ip pim rp ADRESSE GROUPES` sur chaque routeur) ;
- **BSR** (*Bootstrap Router*, RFC 5059) : les candidats RP s'annoncent et un routeur élu
  diffuse la correspondance ;
- **Auto-RP** (propre à Cisco).

On choisit pour adresse du RP celle d'une **interface de bouclage** (*loopback*), joignable par
plusieurs chemins. Avec FRR, PIM doit être activé sur cette interface (`ip pim` sur `lo`). Pour
la redondance, plusieurs RP peuvent partager la même adresse : c'est l'**anycast RP**
(RFC 4610, ou MSDP entre eux, section @@ref:msdp@@).

### @@sec:join@@ L'arbre partagé : Join et Prune

1. Un récepteur rejoint G : le DR de son réseau (le *last-hop router*, **LHR**) crée l'entrée
   **(\\*,G)**, avec ce réseau dans l'OIL.
2. Il envoie un **Join (\\*,G)** à son voisin RPF **vers le RP**. Le voisin crée à son tour
   (\\*,G), avec dans son OIL l'interface par laquelle le *Join* est arrivé, et le transmet vers
   le RP. Le *Join* remonte ainsi de proche en proche jusqu'au RP.
3. Les *Join* sont répétés toutes les **60 s** (validité 210 s). Quand il n'y a plus de membres,
   le routeur envoie un **Prune** et la branche disparaît.

### @@sec:register@@ L'enregistrement des sources

Le RP ne connaît pas encore les sources :

1. Le DR du réseau de la source (le *first-hop router*, **FHR**) reçoit les premiers
   datagrammes. Il les **encapsule** dans des messages **Register** envoyés en **unicast** au
   RP.
2. Le RP les décapsule et les transmet sur l'arbre partagé : les récepteurs reçoivent déjà le
   flux.
3. Le RP envoie un **Join (S,G)** vers la source, pour recevoir le flux en natif.
4. Quand les datagrammes natifs arrivent, le RP envoie au FHR un **Register-Stop** : le FHR cesse
   d'encapsuler. Il le vérifie de temps en temps par un *Register* vide (*null register*).

### @@sec:spt@@ La bascule vers l'arbre des plus courts chemins

Le chemin qui passe par le RP n'est pas forcément le plus court. Dès qu'un LHR reçoit le premier
datagramme d'une source par l'arbre partagé, il envoie un **Join (S,G)** vers la **source**
(son voisin RPF vers S). Le flux arrive alors directement par l'**arbre de source** (SPT).
Le LHR envoie ensuite vers le RP un **Prune (S,G,rpt)** pour ne plus le recevoir aussi par
l'arbre partagé. Cette bascule est immédiate par défaut. Elle se règle avec
`ip pim spt-switchover infinity-and-beyond` pour rester sur l'arbre partagé.

Dans `show ip mroute` de FRR, les drapeaux résument l'état d'une entrée : **S** (*sparse*),
**C** (des membres connectés), **P** (élaguée), **R** (élaguée sur l'arbre partagé), **F**
(le routeur enregistre la source), **T** (le flux suit l'arbre de source). Une entrée (S,G)
d'un routeur sans trafic disparaît après le *keepalive timer* (210 s).

### @@sec:pimtimers@@ Les temporisateurs de PIM

| temporisateur | défaut |
|---------------|--------|
| *Hello* / validité d'un voisin | 30 s / 105 s |
| *Join/Prune* périodique / validité | 60 s / 210 s |
| *keepalive* d'une entrée (S,G) | 210 s |
| suppression des *Register* | 60 s |

Quand deux routeurs pourraient transmettre le même flux sur un même réseau, un message **Assert**
désigne le seul qui le fera : celui qui a la meilleure route vers la source, à égalité la plus
grande adresse.
""")
            + info_subtitle(tr("PIM-SSM et IGMPv3"), tag="ssm")
            + tr("""
En **SSM** (RFC 4607), le récepteur connaît la source qu'il veut écouter et s'abonne au canal
**(S,G)**, avec un rapport IGMPv3 `INCLUDE` {S} (ou MLDv2 en IPv6). Il n'y a alors **ni RP, ni
Register, ni arbre partagé** : le LHR envoie directement un **Join (S,G)** vers la source, et le
flux suit le plus court chemin dès le premier datagramme.

- Le bloc réservé au SSM est **232.0.0.0/8** (**`ff3x::/32`** en IPv6). On peut déclarer d'autres
  groupes SSM, mais **tous les routeurs du domaine** doivent avoir la même liste
  (`ip pim ssm prefix-list LISTE` dans FRR ; la liste remplace alors le bloc par défaut).
- Dans la plage SSM, les routeurs ignorent les *Join* (\\*,G) et les adhésions sans source, comme
  les rapports IGMPv2 : **les récepteurs doivent parler IGMPv3**, avec une application qui sait
  demander une source (`iperf -H`, section @@ref:tools@@).
- Deux sources qui émettent vers le même groupe forment deux canaux distincts. Un récepteur
  abonné à (S1,G) ne reçoit que S1 : le trafic de S2 n'est même pas transmis, faute de *Join*
  (S2,G).

Le SSM est plus simple, plus robuste (pas de RP, qui serait un point unique de défaillance) et
plus sûr (personne ne peut injecter du trafic dans un canal). Il ne convient pas aux applications
où les sources ne sont pas connues d'avance (visioconférence à plusieurs, découverte de services).
""")
            + info_subtitle(tr("Entre domaines : MSDP et portée des groupes"), tag="msdp")
            + tr("""
Chaque domaine (un opérateur, une université) a ses propres RP. Le RP d'un domaine ignore les
sources des autres domaines, puisqu'elles s'enregistrent auprès de leur propre RP.

**MSDP** (*Multicast Source Discovery Protocol*, RFC 3618) relie les RP de domaines différents
par des sessions **TCP** sur le port **639** :

1. Quand un RP apprend une source de son domaine (par un *Register*), il envoie à ses pairs MSDP
   un message **SA** (*Source-Active*) : la source S, le groupe G et l'adresse du RP d'origine.
2. Les pairs propagent les SA de proche en proche, avec un contrôle de type RPF sur le RP
   d'origine pour éviter les boucles, et les gardent en cache. Le SA est répété toutes les
   60 s tant que la source émet.
3. Un RP qui a des récepteurs pour G (une entrée (\\*,G)) envoie un **Join (S,G)** vers la source,
   à travers la frontière : le flux arrive par l'arbre de source inter-domaines. Il faut donc
   que PIM tourne sur les liens entre domaines et que les routes vers les sources soient
   connues.

Avec FRR :

- `ip msdp peer ADRESSE_DU_PAIR source ADRESSE_LOCALE` déclare une session, configurée des deux
  côtés, entre les adresses de bouclage des RP ;
- `show ip msdp peer` affiche l'état des sessions (`established` une fois la connexion faite) ;
- `show ip msdp sa` affiche le cache des SA.

Le pair de plus petite adresse ouvre la connexion TCP : comptez jusqu'à une trentaine de
secondes avant que la session soit établie.

Une particularité de FRR (versions 9 et 10) : un SA porte l'adresse du RP qui l'a émis. Pour le premier SA d'une
nouvelle source, c'est le RP du groupe. Pour les SA répétés toutes les 60 s, c'est le RP de
**224.0.0.0/4** tout entier, ou 0.0.0.0 si aucun RP ne couvre toute la plage, et le pair rejette
alors ces SA. Un RP MSDP de FRR doit donc servir `224.0.0.0/4` (`ip pim rp ADRESSE`, sans plage).

### @@sec:scoping@@ Limiter la portée d'un groupe

Certains groupes ne doivent pas sortir d'un domaine. Il y a deux façons de les y retenir :

- la **portée par le TTL** (*TTL scoping*), ancienne : une application émet avec un TTL faible,
  et les routeurs de bordure refusent les paquets sous un seuil. Elle est imprécise ;
- la **portée administrative** (RFC 2365) : les groupes de `239.0.0.0/8` sont réservés à un
  domaine (`239.255.0.0/16` à un site, `239.192.0.0/14` à une organisation), et les routeurs de
  bordure posent une **frontière** (*boundary*) qui les bloque.

Avec FRR, `ip multicast boundary oil LISTE` sur l'interface de bordure fait ignorer les *Join* et
les rapports IGMP qui y arrivent pour les groupes **refusés** (`deny`) par la liste de préfixes
(`ip prefix-list`) : l'interface n'entre jamais dans l'OIL de ces groupes. La frontière se pose
sur le routeur qui **émettrait** le trafic vers l'extérieur, du côté où arrivent les *Join*.
Les SA de ces groupes, eux, traversent encore la session MSDP, à moins de les filtrer aussi
(`msdp peer ADRESSE sa-filter LISTE in` ou `out`, dans le bloc `router pim`, où `LISTE` est une
`access-list`).

En IPv6, la portée est inscrite dans l'adresse (section @@ref:ipv6addr@@) : les routeurs ne
transmettent pas un groupe au-delà de sa portée.
""")
            + info_subtitle(tr("Le multicast IPv6 : MLD et PIMv6"), tag="ipv6")
            + tr("""
**MLD** (*Multicast Listener Discovery*) est l'IGMP d'IPv6, porté par ICMPv6 (limite de sauts 1,
adresse source lien local, option Router Alert) :

| IPv4 | IPv6 | rapports envoyés à |
|------|------|--------------------|
| IGMPv2 | **MLDv1** (RFC 2710) | l'adresse du groupe ; départ (*Done*) vers `ff02::2` |
| IGMPv3 | **MLDv2** (RFC 3810) | **`ff02::16`** |

Le querier MLD est le routeur de plus petite adresse. Un lien IPv6 compte toujours beaucoup de
groupes, puisque chaque adresse unicast fait rejoindre son groupe *solicited-node* (section
@@ref:ipv6addr@@).

**PIMv6** est le même protocole que PIM, transporté par IPv6. Les *Hello* partent des adresses
lien local vers `ff02::d`, si bien que les voisins PIMv6 apparaissent sous leur adresse
`fe80::…`. Les contrôles RPF utilisent la table de routage IPv6. Le bloc SSM est `ff3x::/32`
(`ff3e::/32` en portée globale).

Avec FRR, PIMv6 est assuré par un démon à part, **`pim6d`**, à activer dans `/etc/frr/daemons`.
Les commandes reprennent celles d'IPv4 :

- configuration : `ipv6 pim` et `ipv6 mld` sur une interface ;
- vérification : `show ipv6 pim neighbor`, `show ipv6 mld interface`, `show ipv6 mld groups`,
  `show ipv6 mld joins`, `show ipv6 mroute`.
""")
            + info_subtitle(tr("PIM, IGMP et MSDP avec FRR"), tag="frr")
            + tr("""
Le démon **`pimd`** de FRR fait PIM-SM, PIM-SSM, IGMP (v2 et v3) et MSDP ; `pim6d` fait PIMv6 et
MLD. Ils sont activés dans `/etc/frr/daemons` et se configurent dans `vtysh`, comme les autres
démons de FRR. N'oubliez pas `write` pour enregistrer la configuration dans
`/etc/frr/frr.conf`.

```
configure terminal
 ip pim rp 10.9.9.9 239.0.0.0/8         ! le RP (statique) des groupes 239.0.0.0/8
 ip prefix-list SSM seq 5 permit 232.0.0.0/8 le 32
 ip pim ssm prefix-list SSM              ! la plage SSM (232.0.0.0/8 sans cette commande)
 ip pim spt-switchover infinity-and-beyond   ! rester sur l'arbre partagé
 ip msdp peer 10.8.8.8 source 10.9.9.9   ! une session MSDP
 interface eth0
  ip pim                                 ! PIM sur l'interface (Hello, Join...)
  ip igmp                                ! IGMP : l'interface dessert des récepteurs
  ip igmp version 3                      ! (3 par défaut)
  ip igmp query-interval 60              ! en secondes (125 par défaut)
  ip igmp last-member-query-interval 10  ! en dixièmes de seconde
  ip igmp join 239.1.1.1                 ! le routeur rejoint lui-même un groupe
  ip multicast boundary oil LISTE        ! frontière de portée administrative
 exit
 interface lo
  ip pim                                 ! sur le RP : l'interface qui porte son adresse
 exit
end
write
```

Depuis FRR 10, les réglages globaux de PIM (`rp`, `ssm`, `spt-switchover`, `msdp peer`…)
appartiennent à un bloc `router pim`, et c'est là que `show running-config` les range :

```
router pim
 rp 10.9.9.9 239.0.0.0/8
 msdp peer 10.8.8.8 source 10.9.9.9
exit
```

Les commandes `ip pim …` et `ip msdp …` du premier niveau, celles de FRR 9 et des documentations
plus anciennes, restent acceptées : FRR les range lui-même dans ce bloc.

| commande | affiche |
|----------|---------|
| `show ip pim interface` | les interfaces PIM, leur nombre de voisins, le DR |
| `show ip pim neighbor` | les voisins PIM |
| `show ip pim rp-info` | le RP de chaque plage de groupes, l'interface RPF vers lui (OIF) |
| `show ip pim group-type A.B.C.D` | ASM ou SSM pour ce groupe |
| `show ip pim upstream` | les entrées (S,G) et (\\*,G), leur état (*Joined*...), le voisin RPF |
| `show ip mroute` | la table multicast : source, groupe, drapeaux, iif, interfaces de sortie |
| `show ip igmp interface [detail]` | IGMP par interface : version, querier, temporisateurs |
| `show ip igmp groups` / `sources` | les groupes (et les sources) appris par IGMP |
| `show ip msdp peer` / `sa` | les sessions MSDP, le cache des SA |

Toutes ces commandes acceptent le suffixe `json`. `clear ip mroute` vide la table multicast.
`clear ip pim interfaces` relance PIM sur les interfaces. Le routeur oublie alors ses voisins
jusqu'à leur prochain *Hello* : ce n'est pas un moyen d'aller plus vite.
""")
            + info_subtitle(tr("Les outils"), tag="tools")
            + tr("""
- **iperf** (la version 2 ; `iperf3` ne fait pas de multicast) :
  - récepteur : `iperf -s -u -B 239.1.1.1 -i 1` rejoint le groupe et affiche chaque seconde ce
    qu'il reçoit ;
  - récepteur SSM : `iperf -s -u -B 232.1.1.1 -H 10.0.0.1 -i 1` s'abonne au canal de la source
    10.0.0.1 ;
  - source : `iperf -c 239.1.1.1 -u -T 16 -t 10 -b 100K` émet pendant 10 s avec un TTL de 16
    (**1 sans `-T`**) ; `-p` change le port (5001 par défaut).
- **ssmping** : `ssmpingd` sur la machine source ; `ssmping SOURCE` sur un récepteur vérifie
  que le canal SSM de la source arrive ; `asmping GROUPE SOURCE` fait de même en ASM.
- **smcroute** : `smcrouted` (le démon), puis `smcroutectl join eth0 239.1.1.1` fait rejoindre un
  groupe sans application. Ses routes statiques (`smcroutectl add …`) ne cohabitent pas avec
  `pimd`, qui tient déjà la table multicast du noyau.
- **tcpdump** : `tcpdump -ni eth0 -v igmp` (versions, enregistrements, option Router Alert),
  `tcpdump -ni eth1 pim`, `tcpdump -ni eth0 ip multicast and udp`, `tcpdump -ni eth0 -e`
  pour les adresses MAC.
- Le noyau : `ip maddr`, `cat /proc/net/igmp`, `ip mroute`, `ip -s mroute` (section
  @@ref:host@@ et @@ref:mfc@@).
""")
            + info_subtitle(tr("Méthode de diagnostic"), tag="diagnostic")
            + tr("""
Un flux multicast qui n'arrive pas se diagnostique **du récepteur vers la source**, routeur par
routeur, en suivant les interfaces RPF :

1. **Le récepteur** a-t-il rejoint le groupe ? (`ip maddr`, `tcpdump igmp` : le rapport part-il ?)
2. **Le LHR** connaît-il le groupe ? (`show ip igmp groups`) A-t-il une entrée (\\*,G) ou (S,G) ?
   (`show ip pim upstream`, `show ip mroute`)
3. Chaque routeur vers le RP ou la source a-t-il un **voisin PIM** sur son interface RPF ? (`show
   ip pim neighbor`, `show ip pim rp-info`, `ip route get SOURCE`)
4. **Le FHR** voit-il la source ? A-t-il une entrée (S,G) avec le drapeau F ?
5. **La source** émet-elle, avec un TTL suffisant, et par la bonne interface ? (`tcpdump` sur le
   réseau de la source)

| symptôme | causes fréquentes |
|----------|-------------------|
| rien n'arrive, même pas sur le réseau de la source | pas de route vers 224.0.0.0/4 sur la source, mauvais groupe ou mauvais port |
| le flux s'arrête au premier routeur | TTL de 1 (le défaut des sockets multicast), PIM absent sur l'interface du réseau de la source |
| pas de voisin PIM sur un lien | `ip pim` oublié d'un côté, filtrage du protocole 103 ou de 224.0.0.13 |
| (\\*,G) sur le LHR mais rien en amont | pas de RP pour ce groupe, RP différent selon les routeurs, RP injoignable, interface RPF vers le RP sans PIM |
| le LHR ne voit pas le groupe | IGMP absent sur l'interface des récepteurs, rapport IGMPv2 pour un groupe SSM |
| quelques datagrammes passent, puis plus rien | bascule vers l'arbre de source impossible : l'interface RPF vers la source n'a pas de voisin PIM |
| un commutateur inonde tout | snooping inactif, ou pas de querier sur le réseau |
| un groupe sort de son domaine | frontière absente ou mal placée, liste de préfixes qui l'autorise |
| la session MSDP reste en `listen` ou `connecting` | adresse source de la session, route vers le pair, TCP 639 filtré |
""")
        )

    # -- addresses ---------------------------------------------------------------

    def addr(self, router: str, net: str):
        """Address (without prefix) of *router* on *net*."""
        if router in V6_MACHINES:
            return getattr(self.data.ips6, f"{router}_{net}").ip
        return getattr(self.data.ips, f"{router}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    # -- FRR configuration files -------------------------------------------------

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf: the static routes of every router, plus what is given
        configured (igmp_r2, the two domains of the msdp site, the broken fix site)."""
        d = self.data
        a = self.addr
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "log file /var/log/frr/frr.log", "!"]
        routes = {
            'asm_r1': [(d.nets.asm_rx_lan, a('asm_r3', 'asm_l13')), (d.nets.asm_l23, a('asm_r2', 'asm_l12')),
                       (self.lo('asm_r2'), a('asm_r2', 'asm_l12'))],
            'asm_r2': [(d.nets.asm_src_lan, a('asm_r1', 'asm_l12')), (d.nets.asm_rx_lan, a('asm_r3', 'asm_l23')),
                       (d.nets.asm_l13, a('asm_r1', 'asm_l12'))],
            'asm_r3': [(d.nets.asm_src_lan, a('asm_r1', 'asm_l13')), (self.lo('asm_r2'), a('asm_r2', 'asm_l23')),
                       (d.nets.asm_l12, a('asm_r2', 'asm_l23'))],
            'ssm_r1': [(d.nets.ssm_rx_lan, a('ssm_r2', 'ssm_link'))],
            'ssm_r2': [(d.nets.ssm_src_lan, a('ssm_r1', 'ssm_link'))],
            'msdp_r1': [(d.nets.msdp_rx_lan, a('msdp_r2', 'msdp_link')), (self.lo('msdp_r2'), a('msdp_r2', 'msdp_link'))],
            'msdp_r2': [(d.nets.msdp_src_lan, a('msdp_r1', 'msdp_link')), (self.lo('msdp_r1'), a('msdp_r1', 'msdp_link'))],
            'fix_r1': [(d.nets.fix_rx_lan, a('fix_r2', 'fix_la'))],
            # fault 4: the route to the RP goes through fix_lb, where PIM does not run
            'fix_r2': [(d.nets.fix_src_lan, a('fix_r1', 'fix_la')), (self.lo('fix_r1'), a('fix_r1', 'fix_lb'))],
        }
        routes6 = {
            'v6_r1': [(d.nets6.v6_rx_lan, a('v6_r2', 'v6_link'))],
            'v6_r2': [(d.nets6.v6_src_lan, a('v6_r1', 'v6_link'))],
        }
        for net, gw in routes.get(router, []):
            prefix = f"{net}/32" if isinstance(net, IPv4Address) else str(net)
            lines.append(f"ip route {prefix} {gw}")
        for net, gw in routes6.get(router, []):
            lines.append(f"ipv6 route {net} {gw}")
        lines.append("!")
        if router == 'igmp_r2':
            lines += ["interface eth0", " ip igmp", "exit", "!"]
        elif router in ('msdp_r1', 'msdp_r2'):
            lines += [f"ip pim rp {self.lo(router)} {MSDP_RP_RANGE}", "!"]
            for name in ['lo'] + [iface(router, net) for net in ROUTER_IFACES[router]]:
                lines += [f"interface {name}", " ip pim"]
                if router == 'msdp_r2' and name == iface(router, 'msdp_rx_lan'):
                    lines.append(" ip igmp")
                lines += ["exit", "!"]
        elif router == 'fix_r1':
            # fault 1: no `ip pim` on eth0 (the source LAN); fix_lb has no PIM on either side
            lines += [f"ip pim rp {self.lo('fix_r1')} {RP_RANGE}", "!",
                      "interface lo", " ip pim", "exit", "!",
                      f"interface {iface('fix_r1', 'fix_la')}", " ip pim", "exit", "!"]
        elif router == 'fix_r2':
            # fault 3: the RP address is the one of fix_r1 on fix_la, not its loopback
            lines += [f"ip pim rp {a('fix_r1', 'fix_la')} {RP_RANGE}", "!",
                      f"interface {iface('fix_r2', 'fix_la')}", " ip pim", "exit", "!",
                      f"interface {iface('fix_r2', 'fix_rx_lan')}", " ip pim", " ip igmp", "exit", "!"]
        return "\n".join(lines) + "\n"

    def _fix_nftables(self, broken: bool) -> str:
        """/etc/nftables.conf of fix_r1: an input filter; fault 2 = the PIM rule."""
        pim_rule = "        ip protocol { gre, pim } counter drop comment \"protocoles non utilisés\"\n" if broken else ""
        return ("#!/usr/sbin/nft -f\n"
                "flush ruleset\n\n"
                "table inet filter {\n"
                "    chain input {\n"
                "        type filter hook input priority filter; policy accept;\n"
                "        tcp dport 23 counter drop comment \"pas de telnet\"\n"
                f"{pim_rule}"
                "    }\n"
                "}\n")

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part ----------------------------------------

    def _solution_igmp(self, step: int = 1):
        d = self.data
        self._vtysh('igmp_r1', "interface eth0", "ip igmp", "ip igmp version 3",
                    f"ip igmp query-interval {d.query_interval}", "exit", step=step)
        self.cmd('igmp_h2', "sysctl -w net.ipv4.conf.eth0.force_igmp_version=2", step=step)

    def _solution_snooping(self, step: int = 1):
        self.cmd(SWITCH, f"ip link set {BRIDGE} type bridge mcast_snooping 1 mcast_querier 1 mcast_igmp_version 3 "
                         "mcast_query_use_ifaddr 1", step=step)
        for port in ('eth1', 'eth2'):
            self.cmd(SWITCH, f"bridge link set dev {port} fastleave on", step=step)

    def _solution_asm(self, step: int = 1):
        rp = self.lo('asm_r2')
        self._vtysh('asm_r1', f"ip pim rp {rp} {RP_RANGE}",
                    *[c for net in ROUTER_IFACES['asm_r1'] for c in (f"interface {iface('asm_r1', net)}", "ip pim", "exit")],
                    step=step)
        self._vtysh('asm_r2', f"ip pim rp {rp} {RP_RANGE}", "interface lo", "ip pim", "exit",
                    *[c for net in ROUTER_IFACES['asm_r2'] for c in (f"interface {iface('asm_r2', net)}", "ip pim", "exit")],
                    step=step)
        self._vtysh('asm_r3', f"ip pim rp {rp} {RP_RANGE}",
                    "interface eth0", "ip pim", "exit", "interface eth1", "ip pim", "exit",
                    "interface eth2", "ip pim", "ip igmp", "exit", step=step)

    def _ssm_range_cmds(self) -> List[str]:
        return [f"ip prefix-list {SSM_PLIST} seq 5 permit {SSM_DEFAULT} le 32",
                f"ip prefix-list {SSM_PLIST} seq 10 permit {SSM_EXTRA} le 32",
                f"ip pim ssm prefix-list {SSM_PLIST}"]

    def _solution_ssm(self, step: int = 1):
        self._vtysh('ssm_r1', *self._ssm_range_cmds(), "interface eth0", "ip pim", "exit",
                    "interface eth1", "ip pim", "exit", step=step)
        self._vtysh('ssm_r2', *self._ssm_range_cmds(), "interface eth0", "ip pim", "exit",
                    "interface eth1", "ip pim", "ip igmp", "ip igmp version 3", "exit", step=step)

    def _solution_msdp(self, step: int = 1):
        r1, r2 = self.lo('msdp_r1'), self.lo('msdp_r2')
        self._vtysh('msdp_r1', f"ip msdp peer {r2} source {r1}",
                    f"ip prefix-list {SCOPE_PLIST} seq 5 deny {SCOPED_RANGE} le 32",
                    f"ip prefix-list {SCOPE_PLIST} seq 10 permit 224.0.0.0/4 le 32",
                    f"interface {iface('msdp_r1', 'msdp_link')}", f"ip multicast boundary oil {SCOPE_PLIST}", "exit",
                    step=step)
        self._vtysh('msdp_r2', f"ip msdp peer {r1} source {r2}", step=step)

    def _solution_fix(self, step: int = 1):
        rp = self.lo('fix_r1')
        self._vtysh('fix_r1', "interface eth0", "ip pim", "exit", step=step)
        self.file('fix_r1', FIX_NFT_FILE, self._fix_nftables(broken=False), permissions=0o755, step=step)
        self.cmd('fix_r1', f"nft -f {FIX_NFT_FILE}", step=step)
        # the `no` commands in sessions of their own: they fail when the fault is already gone
        self._vtysh('fix_r2', f"no ip pim rp {self.addr('fix_r1', 'fix_la')} {RP_RANGE}", step=step, allow_error=True)
        self._vtysh('fix_r2', f"no ip route {rp}/32 {self.addr('fix_r1', 'fix_lb')}", step=step, allow_error=True)
        self._vtysh('fix_r2', f"ip pim rp {rp} {RP_RANGE}", f"ip route {rp}/32 {self.addr('fix_r1', 'fix_la')}",
                    step=step)

    def _solution_v6(self, step: int = 1):
        self._vtysh('v6_r1', "interface eth0", "ipv6 pim", "exit", "interface eth1", "ipv6 pim", "exit", step=step)
        self._vtysh('v6_r2', "interface eth0", "ipv6 pim", "exit",
                    "interface eth1", "ipv6 pim", "ipv6 mld", "exit", step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
        for h in ('v6_src', 'v6_h'):
            set_ipv6_forward(net_scheme=self, machine_name=h, ipv6_forward=False)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)

        # the switch: br0 over its three ports, snooping off (it floods every group)
        self.cmd(SWITCH, f"ip link add {BRIDGE} type bridge mcast_snooping 0")
        for port in SWITCH_PORTS:
            self.cmd(SWITCH, f"ip link set {port} master {BRIDGE}")
        self.cmd(SWITCH, f"ip addr add {d.ips.snoop_sw} dev {BRIDGE}")
        self.cmd(SWITCH, f"ip link set {BRIDGE} up")

        for r in LOOPBACKS:
            self.cmd(r, f"ip addr add {getattr(d.ips, f'{r}_lo')} dev lo")
        # the igmp and snoop LANs have no router: a route for the groups, so that the hosts can emit
        for h, (_net, gw) in HOSTS.items():
            if gw is None:
                self.cmd(h, f"ip route add {MCAST_ROUTE} dev eth0")
        # fault 2 of the fix site: fix_r1 drops PIM
        self.file('fix_r1', FIX_NFT_FILE, self._fix_nftables(broken=True), permissions=0o755)
        self.cmd('fix_r1', f"nft -f {FIX_NFT_FILE}")

        for h in HOSTS:
            install_mcast_probe(self, h)

        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : réponses du formulaire", en="Part 1: form answers"))
    def solve_addressing(self):
        """Part 1 needs no machine: the state only fills its form (cheat_answers)."""
        self.cmd(SWITCH, "true")

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (IGMP)", en="Part 2: solution (IGMP)"))
    def solve_igmp(self):
        self._solution_igmp()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (IGMP snooping)",
                                                  en="Part 3: solution (IGMP snooping)"))
    def solve_snooping(self):
        self._solution_snooping()
        # the bridge counts as having a querier once its query response interval (10 s) is over
        self.cmd(SWITCH, "sleep 12", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (PIM-SM)", en="Part 4: solution (PIM-SM)"))
    def solve_asm(self):
        self._solution_asm()
        self.cmd('asm_r1', "sleep 10", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (PIM-SSM)", en="Part 5: solution (PIM-SSM)"))
    def solve_ssm(self):
        self._solution_ssm()
        self.cmd('ssm_r1', "sleep 10", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (MSDP)", en="Part 6: solution (MSDP)"))
    def solve_msdp(self):
        self._solution_msdp()
        self.cmd('msdp_r1', "sleep 35", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 7 : solution (dépannage)",
                                                  en="Part 7: solution (troubleshooting)"))
    def solve_fix(self):
        self._solution_fix()
        # fix_r1 accepts the Join of fix_r2 once it has heard its next Hello (30 s); `clear ip pim
        # interfaces` on fix_r2 made it worse live (it flushes the neighbours of fix_r2 too)
        self.cmd('fix_r1', "sleep 35", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 8 : solution (IPv6, bonus)",
                                                  en="Part 8: solution (IPv6, bonus)"))
    def solve_v6(self):
        self._solution_v6()
        self.cmd('v6_r1', "sleep 10", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for the PIM neighbours and the MSDP session).  Form questions are filled
        through cheat_answers."""
        self._solution_igmp()
        self._solution_snooping()
        self._solution_asm()
        self._solution_ssm()
        self._solution_msdp()
        self._solution_fix()
        self._solution_v6()
        # the MSDP session (connect retry 30 s), the next Hello of fix_r2 heard by fix_r1 (30 s), the
        # bridge querier (10 s)
        self.cmd('msdp_r1', "sleep 35", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s, default: int = -1) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _address(answer):
    """The IP address (v4 or v6) of a typed answer, None when unreadable."""
    try:
        return ip_address(_norm(answer).split('/')[0])
    except ValueError:
        return None


def _by_language(text: TranslatedText, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values*; a dict value gives one value per language (the
    addressing table, whose second address of ssm_src is labelled in words)."""
    return TranslatedText({lang: version.format(**{k: v[lang] if isinstance(v, dict) else v
                                                  for k, v in values.items()})
                           for lang, version in text.items()})


def _route_dev(output: str):
    """The output interface of ``ip -j route get X`` (None)."""
    try:
        routes = json.loads(output or '[]')
    except ValueError:
        return None
    return routes[0].get('dev') if isinstance(routes, list) and routes and isinstance(routes[0], dict) else None


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        a, lo = ns.addr, ns.lo
        port, token = d.grade_port, d.token
        s1, s2 = d.ips.ssm_src.ip, d.ips.ssm_src2.ip

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- step 1: the receivers and sniffers of the grading streams --
        receivers = {
            'igmp_h1': ('grade_igmp', [d.g_igmp1]),
            'igmp_h2': ('grade_igmp', [d.g_igmp2]),
            'snoop_h1': ('grade_snoop', [d.g_snoop]),
            'asm_h': ('grade_asm', [d.g_asm]),
            'ssm_h': ('grade_ssm', [(d.g_ssm, s1)]),
            'msdp_h': ('grade_msdp', [d.g_msdp, d.g_scoped]),
            'fix_h': ('grade_fix', [d.g_fix]),
            'v6_h': ('grade_v6', [(d.g_v6, d.ips6.v6_src.ip)]),
        }
        sniffers = {'snoop_h2': ('grade_snoop', [d.g_snoop]), 'ssm_h': ('grade_ssm_sniff', [d.g_ssm])}
        for h, (tag, joins) in receivers.items():
            self.test(h, mcast_recv_cmd(tag, port, joins, duration=RECV_DURATION), step=1, allow_error=True)
        for h, (tag, groups) in sniffers.items():
            self.test(h, mcast_sniff_cmd(tag, 'eth0', groups, duration=RECV_DURATION), step=1, allow_error=True)

        # ---------------- step 1: configuration of the routers and of the switch -----
        igmp_if = {r: get_igmp_interfaces(self, r, allow_error=True) for r in ('igmp_r1', 'asm_r3', 'ssm_r2')}
        h2_force = {name: get_sysctl_int(self, 'igmp_h2', f"net.ipv4.conf.{name}.force_igmp_version")
                    for name in ('eth0', 'all')}
        switch_links = get_ip_links(self, SWITCH)
        pim_if = {r: get_pim_interfaces(self, r, allow_error=True) for r in ('asm_r1', 'ssm_r1', 'fix_r1')}
        neighbors = {r: get_pim_neighbors(self, r, allow_error=True)
                     for r in ('asm_r2', 'asm_r3', 'ssm_r2', 'fix_r1', 'fix_r2')}
        rp_info = {r: get_pim_rp_info(self, r, allow_error=True) for r in ('asm_r1', 'asm_r2', 'asm_r3', 'fix_r2')}
        group_type = {r: get_pim_group_type(self, r, d.g_ssm_extra, allow_error=True) for r in ('ssm_r1', 'ssm_r2')}
        msdp_peers = {r: get_msdp_peers(self, r, allow_error=True) for r in ('msdp_r1', 'msdp_r2')}
        msdp_r1_config = get_frr_running_config(self, 'msdp_r1', allow_error=True)
        fix_rp_route, _ = self.test('fix_r2', f"ip -j route get {lo('fix_r1')}", allow_error=True)
        v6_neighbors = get_pim_neighbors(self, 'v6_r2', allow_error=True, ipv6=True)
        mld_if = get_mld_interfaces(self, 'v6_r2', allow_error=True)

        # ---------------- step 2: the bursts (a token, from the sources) ---------------
        def send(machine, group, source=None, background=None):
            self.test(machine, mcast_send_cmd(group, port, token, source=source, iface='eth0', background=background),
                      step=2, timeout=40, allow_error=True)

        send('snoop_src', d.g_snoop)
        send('asm_src', d.g_asm)
        send('ssm_src', d.g_ssm, source=s2, background='grade_ssm_s2')
        send('ssm_src', d.g_ssm, source=s1)
        send('msdp_src', d.g_scoped, background='grade_msdp_scoped')
        send('msdp_src', d.g_msdp)
        send('fix_src', d.g_fix)
        send('v6_src', d.g_v6)

        # ---------------- step 3: what arrived, and the state left by the streams -----
        dump_tags = {'igmp_h1': ['grade_igmp'], 'igmp_h2': ['grade_igmp'], 'snoop_h1': ['grade_snoop'],
                     'snoop_h2': ['grade_snoop'], 'asm_h': ['grade_asm'], 'ssm_h': ['grade_ssm', 'grade_ssm_sniff'],
                     'msdp_h': ['grade_msdp'], 'fix_h': ['grade_fix'], 'v6_h': ['grade_v6']}
        dumps = {h: get_mcast_dump(self, h, tags, step=3) for h, tags in dump_tags.items()}
        igmp_groups = get_igmp_groups(self, 'igmp_r1', step=3, allow_error=True)
        mdb = get_mdb(self, SWITCH, BRIDGE, step=3)
        asm_mroutes = get_mroutes(self, 'asm_r3', step=3, allow_error=True)
        msdp_sa = get_msdp_sa(self, 'msdp_r2', step=3, allow_error=True)
        mld_groups = get_mld_groups(self, 'v6_r2', step=3, allow_error=True)

        def got(host, tag, group, source=None) -> int:
            return received(dumps[host][tag], group, token=token, source=source)

        def streamed(host, tag, group, source=None) -> bool:
            return got(host, tag, group, source) >= MIN_RECEIVED

        # ---------------- texts shared by the questions ---------------------------
        members = {net: [] for net in NET_PLAN}
        for r, nets in ROUTER_IFACES.items():
            for n, net in enumerate(nets):
                if net in members:
                    members[net].append(f"`{r}` eth{n} (`{a(r, net)}`)")
        for h, (net, _gw) in HOSTS.items():
            if net in members:
                members[net].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        members['snoop_lan'].append(f"`{SWITCH}` {BRIDGE} (`{d.ips.snoop_sw.ip}`)")
        other_rows = [f"| `{r}` lo | `{lo(r)}/32` | `{r}` |" for r in LOOPBACKS]
        for net in NET6_PLAN:
            ends = [f"`{r}` eth{ROUTER_IFACES[r].index(net)} (`{a(r, net)}`)" for r in ('v6_r1', 'v6_r2')
                    if net in ROUTER_IFACES[r]]
            ends += [f"`{h}` (`{getattr(d.ips6, h).ip}`)" for h in ('v6_src', 'v6_h') if HOSTS[h][0] == net]
            other_rows.append(f"| `{net}` | `{getattr(d.nets6, net)}` | {', '.join(ends)} |")
        # the second address of ssm_src is labelled in words: one table per language (_by_language)
        second_address = {'fr': f"`ssm_src` (2e adresse `{s2}`)", 'en': f"`ssm_src` (2nd address `{s2}`)"}
        addressing = {
            lang: "\n".join([f"| `{net}` | `{getattr(d.nets, net)}` | "
                             f"{', '.join(members[net] + ([second] if net == 'ssm_src_lan' else []))} |"
                             for net in NET_PLAN] + other_rows)
            for lang, second in second_address.items()
        }

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="e3b5327cf41e1ff7",
            description=_by_language(tr("""
Lisez l'onglet **Informations** : il présente le multicast IP (adresses, IGMP, snooping, routage
multicast, PIM-SM, PIM-SSM, MSDP, IPv6), sa configuration avec FRR et les outils de test.

**Le réseau.** Il est fait de **sept sites indépendants**, un par partie (la partie 1 se fait
sans machine). Chaque site a sa couleur sur le schéma :

| partie | site | machines |
|--------|------|----------|
| 2 — IGMP | `igmp_*` | les routeurs `igmp_r1` et `igmp_r2`, les hôtes `igmp_h1` et `igmp_h2`, sur un même réseau |
| 3 — IGMP snooping | `snoop_*` | le commutateur `snoop_sw` (un pont Linux `br0`), la source `snoop_src`, les hôtes `snoop_h1` et `snoop_h2` |
| 4 — PIM-SM | `asm_*` | la source `asm_src`, les routeurs `asm_r1`, `asm_r2` (le RP), `asm_r3`, le récepteur `asm_h` |
| 5 — PIM-SSM | `ssm_*` | la source `ssm_src` (deux adresses), les routeurs `ssm_r1` et `ssm_r2`, le récepteur `ssm_h` |
| 6 — MSDP | `msdp_*` | la source `msdp_src` et le routeur `msdp_r1` (domaine 1), le routeur `msdp_r2` et le récepteur `msdp_h` (domaine 2) |
| 7 — dépannage | `fix_*` | la source `fix_src`, les routeurs `fix_r1` et `fix_r2` (deux liens entre eux), le récepteur `fix_h` |
| 8 — IPv6 (bonus) | `v6_*` | la source `v6_src`, les routeurs `v6_r1` et `v6_r2`, le récepteur `v6_h` |

- Les routeurs font tourner **FRRouting** (FRR) avec le démon `pimd` (et `pim6d` sur le site
  IPv6) : configurez-les avec `vtysh`.
- Toutes les adresses sont configurées, de même que le **routage unicast** (routes statiques de
  FRR, visibles dans `show running-config`) : vous ne vous occupez que du multicast.
- Les fichiers `/etc/hosts` contiennent les noms des interfaces : `asm_r3-eth1` désigne
  l'adresse de l'interface `eth1` de `asm_r3`, `asm_r2-lo` l'adresse de bouclage de `asm_r2`.
- Les machines disposent d'`iperf` (version 2), de `ssmping` / `asmping`, de `smcroute` et de
  `tcpdump` (section @@ref:tools@@).

**Plan d'adressage.** Le troisième octet d'un préfixe IPv4 rappelle le site (10 : igmp, 20 :
snoop, 3x : asm, 4x : ssm, 5x : msdp, 7x : fix, 99 : les adresses de bouclage).

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- intervalle des requêtes IGMP de `igmp_r1` (partie 2) : **{query_interval} s** ;
- groupes pour vos propres essais : `{igmp_group}` (partie 2), `{snoop_group}` (partie 3),
  `{asm_group}` (partie 4), `{ssm_group}` (partie 5), `{msdp_group}` et, de portée
  organisation, `{scoped_group}` (partie 6), `{fix_group}` (partie 7), `{v6_group}` (partie 8) ;
- adresse du RP du site `asm` : `{asm_rp}` ; RP des domaines du site `msdp` : `{msdp_rp1}`
  (domaine 1) et `{msdp_rp2}` (domaine 2) ; RP du site `fix` : `{fix_rp}` ;
- plage de groupes des RP des sites `asm` et `fix` : `{rp_range}` (ceux du site `msdp` servent
  tout `{msdp_rp_range}`) ; plage SSM ajoutée à la partie 5 : `{ssm_extra}` ;
  plage de portée organisation, arrêtée à la frontière à la partie 6 : `{scoped_range}`.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie
  terminée rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration des routeurs (`write` dans `vtysh`).
- PIM n'est pas instantané : un voisin n'est connu qu'à son premier *Hello* (toutes les 30 s), un
  *Join* perdu n'est répété qu'au bout de 60 s, une session MSDP met une trentaine de secondes
  à s'établir. Après une modification, attendez une minute avant de conclure qu'elle ne marche
  pas.

**Évaluation.** Chaque évaluation lit vos réponses et la configuration des routeurs. Elle
**fait passer de vrais flux** : des récepteurs démarrés sur les hôtes rejoignent des groupes,
puis chaque source émet une vingtaine de datagrammes, et l'évaluation regarde ce qui est arrivé
et par où. Ces flux utilisent leurs propres groupes (tous dans les plages ci-dessus) et le port
UDP {port} ; ils ne gênent pas vos essais. Une évaluation dure une quinzaine de secondes.
"""), addressing=addressing, query_interval=d.query_interval, igmp_group=d.igmp_group,
            snoop_group=d.snoop_group, asm_group=d.asm_group, ssm_group=d.ssm_group, msdp_group=d.msdp_group,
            scoped_group=d.scoped_group, fix_group=d.fix_group, v6_group=d.v6_group, asm_rp=lo('asm_r2'),
            msdp_rp1=lo('msdp_r1'), msdp_rp2=lo('msdp_r2'), fix_rp=lo('fix_r1'), rp_range=RP_RANGE,
            msdp_rp_range=MSDP_RP_RANGE,
            ssm_extra=SSM_EXTRA, scoped_range=SCOPED_RANGE, port=port)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_igmp`, `solve_snooping`, `solve_asm`, `solve_ssm`, `solve_msdp`,
`solve_fix` et `solve_v6` (onglet *Appliquer une configuration*) appliquent la solution d'une
seule partie, et remplissent ses formulaires. L'état `final` les applique toutes, attend
l'établissement de la session MSDP puis remplit tous les formulaires : une évaluation lancée dès
son retour donne tous les points, bonus compris.

L'évaluation démarre à l'étape 1 des récepteurs (`/usr/local/sbin/mcast_probe.py recv`) sur
`igmp_h1`, `igmp_h2`, `snoop_h1`, `asm_h`, `ssm_h`, `msdp_h`, `fix_h` et `v6_h`, et des
écouteurs passifs (`sniff`, qui ne rejoignent rien) sur `snoop_h2` et `ssm_h`. À l'étape 2, les
sources émettent 20 datagrammes (un toutes les 0,4 s, après 2 s) marqués du jeton `{token}`, vers
le port {port}. À l'étape 3, l'évaluation lit ce que chaque récepteur a reçu (un flux compte
pour reçu à partir de {minimum} datagrammes) et l'état des routeurs. Les groupes des flux
d'évaluation : `{g_igmp1}` et `{g_igmp2}` (igmp), `{g_snoop}` (snoop), `{g_asm}` (asm), `{g_ssm}`
et `{g_ssm_extra}` (ssm), `{g_msdp}` et `{g_scoped}` (msdp), `{g_fix}` (fix), `{g_v6}` (v6).
""").format(token=token, port=port, minimum=MIN_RECEIVED, g_igmp1=d.g_igmp1, g_igmp2=d.g_igmp2,
            g_snoop=d.g_snoop, g_asm=d.g_asm, g_ssm=d.g_ssm, g_ssm_extra=d.g_ssm_extra, g_msdp=d.g_msdp,
            g_scoped=d.g_scoped, g_fix=d.g_fix, g_v6=d.g_v6)),
        )

        # =====================================================================
        # Part 1 — addressing
        # =====================================================================
        part1 = self.add_grade_part(no_tr("addressing"), tr("Partie 1 — Les adresses multicast"))
        v6_address = d.ips6.v6_h.ip
        solicited = solicited_node_multicast(v6_address)
        scope_answers = {'scope_a': d.scope_a_class, 'scope_b': d.scope_b_class, 'scope_c': d.scope_c_class}
        aliases = [g for g in mac_aliases(d.mac_group) if g != d.mac_group]
        cheat_addressing = {'mac': group_mac(d.mac_group), 'alias': str(aliases[0]), **scope_answers,
                            'sn': str(solicited), 'sn_mac': group_mac(solicited)}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Les adresses multicast"),
            hash="374d0e4f9a88e6fc",
            description=tr("""
Répondez sans machine, avec la section @@ref:addressing@@ :

- adresse MAC de destination des trames du groupe `{mac_group}` :
  @@{{mac:[0-9a-fA-F:.-]+}}@@
- une **autre** adresse de groupe IPv4 qui donne la même adresse MAC : @@{{alias:[0-9.]+}}@@
- nature des adresses suivantes :
  - `{scope_a}` : @@{{scope_a:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
  - `{scope_b}` : @@{{scope_b:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
  - `{scope_c}` : @@{{scope_c:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
- adresse du groupe *solicited-node* de l'adresse `{v6_address}` (l'hôte `v6_h`) :
  @@{{sn:[0-9a-fA-F:]+}}@@
- adresse MAC des trames envoyées à ce groupe : @@{{sn_mac:[0-9a-fA-F:.-]+}}@@
""").format(mac_group=d.mac_group, scope_a=d.scope_a, scope_b=d.scope_b, scope_c=d.scope_c,
            v6_address=v6_address)
            + instructor(tr("""
**Solution.**

- `{mac_group}` : ses 23 bits de poids faible donnent **`{mac}`** ;
- les 32 groupes de cette adresse MAC sont ceux qui ne diffèrent que par les 5 bits perdus, par
  exemple **`{alias1}`**, `{alias2}` ou `{alias3}` (toute réponse de 224.0.0.0/4 autre que
  `{mac_group}` et de même adresse MAC est acceptée) ;
- `{scope_a}` : **{scope_a_class}** ; `{scope_b}` : **{scope_b_class}** ; `{scope_c}` :
  **{scope_c_class}** ;
- les 24 derniers bits de `{v6_address}` donnent **`{sn}`**, et l'adresse MAC **`{sn_mac}`**.

Évaluation : `addressing_mac` (2), `addressing_alias` (2), `addressing_solicited_node` (2),
`addressing_solicited_node_mac` (1) ; pour l'enseignant seulement (réponses choisies dans une
liste) : `addressing_scope_a`, `addressing_scope_b`, `addressing_scope_c` (1 chacun).
""").format(mac_group=d.mac_group, mac=group_mac(d.mac_group), alias1=aliases[0], alias2=aliases[1],
            alias3=aliases[2], scope_a=d.scope_a, scope_b=d.scope_b, scope_c=d.scope_c,
            scope_a_class=d.scope_a_class, scope_b_class=d.scope_b_class, scope_c_class=d.scope_c_class,
            v6_address=v6_address, sn=solicited, sn_mac=group_mac(solicited))),
            cheat_answers={"final": cheat_addressing, "solve_addressing": cheat_addressing},
        )
        alias = _address(q1.get("alias"))
        self.add_grade_element(
            title=no_tr("addressing_mac"), max_grade=2, grade_part=part1,
            grade=2 * int(normalize_mac(q1.get("mac")) == group_mac(d.mac_group)),
            description=tr("adresse MAC d'un groupe IPv4"),
        )
        self.add_grade_element(
            title=no_tr("addressing_alias"), max_grade=2, grade_part=part1,
            grade=2 * int(alias is not None and alias.version == 4 and alias in MCAST_ROUTE and alias != d.mac_group
                          and group_mac(alias) == group_mac(d.mac_group)),
            description=tr("un autre groupe de même adresse MAC"),
        )
        for field in ('scope_a', 'scope_b', 'scope_c'):
            self.add_grade_element(
                title=no_tr(f"addressing_{field}"), max_grade=1, grade_part=part1,
                grade=int(_norm(q1.get(field)) == scope_answers[field]), scope=CHOICE_SCOPE,
                description=tr("nature d'une adresse multicast"),
            )
        self.add_grade_element(
            title=no_tr("addressing_solicited_node"), max_grade=2, grade_part=part1,
            grade=2 * int(_address(q1.get("sn")) == solicited),
            description=tr("groupe solicited-node d'une adresse IPv6"),
        )
        self.add_grade_element(
            title=no_tr("addressing_solicited_node_mac"), max_grade=1, grade_part=part1,
            grade=int(normalize_mac(q1.get("sn_mac")) == group_mac(solicited)),
            description=tr("adresse MAC d'un groupe IPv6"),
        )

        # =====================================================================
        # Part 2 — IGMP
        # =====================================================================
        part2 = self.add_grade_part(no_tr("igmp"), tr("Partie 2 — IGMP sur le site igmp"))
        r1_lan = igmp_if['igmp_r1'].get('eth0') or {}
        self.question_dummy(
            section=self.section(0),
            title=tr("IGMP : rapports, querier, versions"),
            hash="8649a3489aa0323b",
            description=tr("""
Sur le réseau `igmp_lan`, `igmp_r2` fait déjà tourner IGMP : c'est le querier. `igmp_r1` n'a
encore aucune configuration multicast (sections @@ref:igmp@@ et @@ref:frr@@).

1. Sur `igmp_r2`, lisez `show ip igmp interface` et `show ip igmp groups`. Sur `igmp_h1`,
   lancez `tcpdump -ni eth0 -v igmp`, puis faites rejoindre le groupe `{igmp_group}` à `igmp_h2`
   (`iperf -s -u -B {igmp_group}`, arrêté par Ctrl-C) : observez les rapports et le départ
   (destination, TTL, options IP). Comparez avec `cat /proc/net/igmp` sur `igmp_h2`.
2. Activez IGMP, en **version 3**, sur l'interface `eth0` de `igmp_r1`, avec un intervalle des
   requêtes de **{query_interval} s**. Qui est maintenant le querier du réseau ? Vérifiez-le sur
   les deux routeurs.
3. Forcez `igmp_h2` à utiliser **IGMPv2** sur `eth0` (section @@ref:host@@). Refaites rejoindre
   un groupe à `igmp_h2` en observant le trafic IGMP, puis regardez `show ip igmp groups` sur
   `igmp_r1` (section @@ref:compat@@).
""").format(igmp_group=d.igmp_group, query_interval=d.query_interval)
            + instructor(tr("""
**Solution.** Sur `igmp_r1` :

```
configure terminal
 interface eth0
  ip igmp
  ip igmp version 3
  ip igmp query-interval {query_interval}
 exit
end
write
```

`igmp_r1` (`{r1}`) a une adresse plus petite que `igmp_r2` (`{r2}`) : il devient aussitôt le
querier, et `igmp_r2` passe à `other`. Sur `igmp_h2` :
`sysctl -w net.ipv4.conf.eth0.force_igmp_version=2` (ou `all`). Ses adhésions apparaissent
alors en version 2 dans `show ip igmp groups` de `igmp_r1`, celles d'`igmp_h1` en version 3.

Évaluation : `igmp_enabled` (3 : IGMP sur `eth0` d'`igmp_r1`), `igmp_query_interval` (2),
`igmp_querier` (2 : `igmp_r1` est le querier), `igmp_h2_v2` (2 : la version forcée sur
`igmp_h2`), `igmp_group_v3` (1 : `igmp_r1` connaît le groupe que rejoint `igmp_h1`),
`igmp_group_v2` (1 : celui d'`igmp_h2`, en version 2).
""").format(query_interval=d.query_interval, r1=d.ips.igmp_r1_igmp_lan.ip, r2=d.ips.igmp_r2_igmp_lan.ip)),
        )
        cheat_igmp = {"querier_before": "igmp_r2", "rule": "lowest_address", "report_v3_dst": "224.0.0.22",
                      "leave_v2_dst": "224.0.0.2", "ttl": "1", "option": "router_alert"}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations"),
            hash="3797e6fd61949c18",
            description=tr("""
- querier du réseau avant votre configuration : @@{querier_before:>igmp_r1|igmp_r2}@@ ; le querier
  est le routeur qui a @@{rule:>la plus petite adresse IP>>>lowest_address|la plus grande adresse IP>>>highest_address|la plus grande priorité>>>highest_priority|le plus ancien uptime>>>oldest}@@
- adresse de destination des rapports d'IGMPv3 : @@{report_v3_dst:[0-9.]+}@@
- adresse de destination des messages *Leave* d'IGMPv2 : @@{leave_v2_dst:[0-9.]+}@@
- TTL des messages IGMP : @@{ttl:[0-9]+}@@
- option IP présente dans les messages IGMP :
  @@{option:>Router Alert>>>router_alert|Record Route>>>record_route|Timestamp>>>timestamp|Strict Source Route>>>source_route|aucune>>>none}@@
""")
            + instructor(tr("""
**Solution.** Avant votre configuration, le querier était **`igmp_r2`**, le seul routeur IGMP ; le
querier est le routeur de **plus petite adresse IP**. Rapports d'IGMPv3 vers **224.0.0.22**,
*Leave* d'IGMPv2 vers **224.0.0.2**, **TTL 1**, option **Router Alert**.

Évaluation : `igmp_report_v3_destination`, `igmp_leave_v2_destination`, `igmp_ttl` (0,5 chacun) ;
pour l'enseignant seulement : `igmp_querier_before`, `igmp_election_rule`, `igmp_ip_option` (0,5
chacun).
""")),
            cheat_answers={"final": cheat_igmp, "solve_igmp": cheat_igmp},
        )
        self.add_grade_element(
            title=no_tr("igmp_enabled"), max_grade=3, grade_part=part2,
            grade=3 * int(igmp_enabled(igmp_if['igmp_r1'], 'eth0')),
            description=tr("IGMP sur eth0 d'igmp_r1"),
        )
        self.add_grade_element(
            title=no_tr("igmp_query_interval"), max_grade=2, grade_part=part2,
            grade=2 * int(igmp_enabled(igmp_if['igmp_r1'], 'eth0') and r1_lan.get('query_interval') == d.query_interval),
            description=tr("intervalle des requêtes d'igmp_r1"),
        )
        self.add_grade_element(
            title=no_tr("igmp_querier"), max_grade=2, grade_part=part2,
            grade=2 * int(igmp_enabled(igmp_if['igmp_r1'], 'eth0') and bool(r1_lan.get('querier'))),
            description=tr("igmp_r1 est le querier"),
        )
        self.add_grade_element(
            title=no_tr("igmp_h2_v2"), max_grade=2, grade_part=part2,
            grade=2 * int(2 in (h2_force['eth0'], h2_force['all'])),
            description=tr("igmp_h2 forcé en IGMPv2"),
        )
        r1_groups = igmp_groups.get('eth0', {})
        self.add_grade_element(
            title=no_tr("igmp_group_v3"), max_grade=1, grade_part=part2,
            grade=int((r1_groups.get(str(d.g_igmp1)) or {}).get('version') == 3),
            description=tr("igmp_r1 connaît le groupe d'igmp_h1 (IGMPv3)"),
        )
        self.add_grade_element(
            title=no_tr("igmp_group_v2"), max_grade=1, grade_part=part2,
            grade=int((r1_groups.get(str(d.g_igmp2)) or {}).get('version') == 2),
            description=tr("igmp_r1 connaît le groupe d'igmp_h2, en IGMPv2"),
        )
        for field, value, title_ in (("report_v3_dst", "224.0.0.22", "igmp_report_v3_destination"),
                                     ("leave_v2_dst", "224.0.0.2", "igmp_leave_v2_destination")):
            self.add_grade_element(
                title=no_tr(title_), max_grade=0.5, grade_part=part2,
                grade=0.5 * int(_address(q2.get(field)) == ip_address(value)),
                description=tr("adresse de destination d'un message IGMP"),
            )
        self.add_grade_element(
            title=no_tr("igmp_ttl"), max_grade=0.5, grade_part=part2, grade=0.5 * int(_int(q2.get("ttl")) == 1),
            description=tr("TTL des messages IGMP"),
        )
        for field, title_ in (("querier_before", "igmp_querier_before"), ("rule", "igmp_election_rule"),
                              ("option", "igmp_ip_option")):
            self.add_grade_element(
                title=no_tr(title_), max_grade=0.5, grade_part=part2,
                grade=0.5 * int(_norm(q2.get(field)) == cheat_igmp[field]), scope=CHOICE_SCOPE,
                description=tr("question de cours sur IGMP"),
            )

        # =====================================================================
        # Part 3 — IGMP snooping
        # =====================================================================
        part3 = self.add_grade_part(no_tr("snooping"), tr("Partie 3 — IGMP snooping sur snoop_sw"))
        switch = bridge_mcast_info(switch_links, BRIDGE) or {}
        ports = switch.get('ports') or {}
        self.question_dummy(
            section=self.section(0),
            title=tr("IGMP snooping"),
            hash="7776ba775723413e",
            description=tr("""
`snoop_sw` est un commutateur : un pont Linux `br0` réunit ses ports `eth0` (vers `snoop_src`),
`eth1` (vers `snoop_h1`) et `eth2` (vers `snoop_h2`). Il n'y a pas de routeur multicast sur ce
réseau. Le pont a été créé avec le snooping **désactivé** (section @@ref:snooping@@).

1. Faites rejoindre le groupe `{group}` à `snoop_h1` (`iperf -s -u -B {group} -i 1`), lancez
   `tcpdump -ni eth0 host {group}` sur `snoop_h2`, puis émettez vers ce groupe depuis `snoop_src`
   (`iperf -c {group} -u -T 4 -t 10 -b 50K`). Qui reçoit le flux ?
2. Activez le snooping sur `br0`, sans rien d'autre, et recommencez. Lisez la table des groupes
   (`bridge mdb show`). Qu'est-ce qui a changé ?
3. Faites de `br0` le **querier** du réseau, en **IGMPv3**, avec des requêtes émises depuis son
   adresse (`{switch_ip}`). Après une dizaine de secondes, recommencez : `snoop_h2` ne doit plus
   rien recevoir.
4. Activez le **départ rapide** sur les deux ports des hôtes, `eth1` et `eth2`. Pourquoi ne
   faut-il pas l'activer sur un port qui dessert plusieurs hôtes ?
""").format(group=d.snoop_group, switch_ip=d.ips.snoop_sw.ip)
            + instructor(tr("""
**Solution.** Snooping désactivé, le pont inonde le flux : `snoop_h2` le reçoit aussi. Avec le
snooping seul, `bridge mdb show` contient bien `port eth1 grp {group}`, mais **`snoop_h2` reçoit
toujours le flux** : le pont n'a détecté aucun querier, alors il continue d'inonder. Sur
`snoop_sw` :

```
ip link set br0 type bridge mcast_snooping 1 mcast_querier 1 mcast_igmp_version 3 mcast_query_use_ifaddr 1
bridge link set dev eth1 fastleave on
bridge link set dev eth2 fastleave on
```

Une dizaine de secondes après l'activation du querier (le délai de réponse aux requêtes), seul
`snoop_h1` reçoit le flux. Le départ rapide retire le port dès le premier *Leave* : sur un port
partagé, les autres membres perdraient le flux jusqu'à leur prochain rapport.

Évaluation : `snooping_enabled` (2), `snooping_querier` (2), `snooping_igmp_v3` (1),
`snooping_fast_leave` (2 : `eth1` et `eth2`), `snooping_mdb` (2 : le pont a appris le groupe du
flux d'évaluation sur `eth1`), `snooping_member_receives` (2 : `snoop_h1` le reçoit, le snooping
actif),
`snooping_no_flood` (3 : `snoop_h2` n'en voit aucune trame, compté seulement si `snoop_h1` le
reçoit).
""").format(group=d.snoop_group)),
        )
        # with snooping off the flood delivers the stream too: it only counts once snooping runs
        member_receives = bool(switch.get('snooping')) and streamed('snoop_h1', 'grade_snoop', d.g_snoop)
        flooded = got('snoop_h2', 'grade_snoop', d.g_snoop)
        sniffer_ok = dumps['snoop_h2']['grade_snoop'].ran
        self.add_grade_element(
            title=no_tr("snooping_enabled"), max_grade=2, grade_part=part3,
            grade=2 * int(bool(switch.get('snooping'))), description=tr("snooping actif sur br0"),
        )
        self.add_grade_element(
            title=no_tr("snooping_querier"), max_grade=2, grade_part=part3,
            grade=2 * int(bool(switch.get('querier'))), description=tr("br0 est querier"),
        )
        self.add_grade_element(
            title=no_tr("snooping_igmp_v3"), max_grade=1, grade_part=part3,
            grade=int(switch.get('igmp_version') == 3), description=tr("requêtes de br0 en IGMPv3"),
        )
        self.add_grade_element(
            title=no_tr("snooping_fast_leave"), max_grade=2, grade_part=part3,
            grade=int(bool((ports.get('eth1') or {}).get('fast_leave'))) + int(bool((ports.get('eth2') or {}).get('fast_leave'))),
            description=tr("départ rapide sur eth1 et eth2"),
        )
        self.add_grade_element(
            title=no_tr("snooping_mdb"), max_grade=2, grade_part=part3,
            grade=2 * int(bool(switch.get('snooping')) and 'eth1' in mdb_ports(mdb, d.g_snoop)),
            description=tr("br0 a appris le groupe sur eth1"),
        )
        self.add_grade_element(
            title=no_tr("snooping_member_receives"), max_grade=2, grade_part=part3,
            grade=2 * int(member_receives), description=tr("snoop_h1 reçoit le flux"),
        )
        self.add_grade_element(
            title=no_tr("snooping_no_flood"), max_grade=3, grade_part=part3,
            grade=3 * int(member_receives and sniffer_ok and flooded == 0),
            description=tr("snoop_h2 ne reçoit pas le flux"),
        )

        # =====================================================================
        # Part 4 — PIM-SM
        # =====================================================================
        part4 = self.add_grade_part(no_tr("asm"), tr("Partie 4 — PIM-SM sur le site asm"))
        asm_rp = lo('asm_r2')
        self.question_dummy(
            section=self.section(0),
            title=tr("PIM-SM avec un RP statique"),
            hash="6611b264e2805d8e",
            description=tr("""
Le site `asm` est un triangle de routeurs : `asm_r1` dessert le réseau de la source `asm_src`,
`asm_r3` celui du récepteur `asm_h`, et `asm_r2` sera le **point de rendez-vous** (RP), sur son
adresse de bouclage `{rp}` (sections @@ref:pimsm@@ et @@ref:frr@@). Les routes statiques font
passer le chemin le plus court de `asm_r3` vers la source par le lien direct `asm_l13`, et celui
vers le RP par `asm_l23`.

1. Activez PIM sur **toutes** les interfaces des trois routeurs, y compris celles des réseaux
   d'hôtes, et sur l'interface de bouclage du RP. Vérifiez les voisinages
   (`show ip pim neighbor`).
2. Déclarez `{rp}` comme RP des groupes `{range}` sur les trois routeurs
   (`show ip pim rp-info`).
3. Activez IGMP sur l'interface de `asm_r3` du côté du récepteur.
4. Faites rejoindre `{group}` à `asm_h` (`iperf -s -u -B {group} -i 1`), puis lisez
   `show ip mroute` et `show ip pim upstream` sur les trois routeurs : quelles entrées ont été
   créées, et jusqu'où ?
5. Lancez un `tcpdump -ni eth1 pim` sur `asm_r2`, puis émettez depuis `asm_src`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K`). Suivez les messages PIM, puis relisez les tables
   multicast : par où passe le flux au bout de quelques secondes ?
""").format(rp=asm_rp, range=RP_RANGE, group=d.asm_group)
            + instructor(tr("""
**Solution.** Sur `asm_r1` :

```
configure terminal
 ip pim rp {rp} {range}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
 interface eth2
  ip pim
 exit
end
write
```

Sur `asm_r2`, la même chose avec `interface lo` / `ip pim` en plus (ses interfaces sont `eth0`
et `eth1`). Sur `asm_r3`, la même chose, avec en plus `ip igmp` sur `eth2`.

Quand `asm_h` rejoint le groupe, `asm_r3` crée (\\*,{group}) et envoie un *Join* (\\*,G) vers le RP
par `eth0` (`asm_l23`) : `asm_r2` a aussi une entrée (\\*,G), d'interface d'entrée `lo`. Au premier
datagramme, `asm_r1` (FHR) l'encapsule dans un **Register** vers le RP, qui le décapsule, le
transmet sur l'arbre partagé, envoie un *Join* (S,G) vers la source puis un **Register-Stop**.
Dès réception, `asm_r3` bascule sur l'arbre de source : son entrée (S,G) a pour interface
d'entrée **`eth1`** (`asm_l13`, le lien direct), et `asm_r2` élague (S,G) (drapeaux `SRP`). Le
TTL reçu par `asm_h` passe de 13 (via le RP) à 14.

Évaluation : `asm_neighbors_l12`, `asm_neighbors_l23`, `asm_neighbors_l13` (2 chacun : les
voisinages PIM des trois liens), `asm_source_lan` (1 : PIM sur `eth0` de `asm_r1`), `asm_rp_r1`,
`asm_rp_r2`, `asm_rp_r3` (1 chacun : `{rp}` est le RP du groupe du flux d'évaluation),
`asm_igmp` (2 : IGMP sur `eth2` de `asm_r3`), `asm_stream` (4 : `asm_h` reçoit le flux),
`asm_spt` (3 : l'entrée (S,G) de `asm_r3` arrive par `eth1`).
""").format(rp=asm_rp, range=RP_RANGE, group=d.asm_group)),
        )
        cheat_asm = {"rpf_iface": iface('asm_r3', 'asm_l23'), "fhr_message": "register", "rp_answer": "register-stop"}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations"),
            hash="1907feb1a3ad1625",
            description=tr("""
- interface RPF de `asm_r3` vers le RP (celle de son entrée (\\*,G)) : @@{rpf_iface:[a-z0-9]+}@@
- message PIM qui porte vers le RP les premiers datagrammes de la source :
  @@{fhr_message:>Hello>>>hello|Join>>>join|Register>>>register|Assert>>>assert|Bootstrap>>>bootstrap}@@
- message par lequel le RP fait cesser cet envoi :
  @@{rp_answer:>Prune>>>prune|Register-Stop>>>register-stop|Graft>>>graft|Assert>>>assert}@@
""")
            + instructor(tr("""
**Solution.** Interface RPF vers le RP : **`{rpf}`** (la route statique vers `{rp}` passe par
`asm_l23`). Les premiers datagrammes arrivent au RP dans des **Register**, le RP répond par un
**Register-Stop**.

Évaluation : `asm_rpf_interface` (1) ; pour l'enseignant seulement : `asm_register` (1),
`asm_register_stop` (1).
""").format(rpf=iface('asm_r3', 'asm_l23'), rp=asm_rp)),
            cheat_answers={"final": cheat_asm, "solve_asm": cheat_asm},
        )
        for net, (router, peer) in (('asm_l12', ('asm_r2', 'asm_r1')), ('asm_l23', ('asm_r3', 'asm_r2')),
                                    ('asm_l13', ('asm_r3', 'asm_r1'))):
            self.add_grade_element(
                title=no_tr(f"asm_neighbors_{net.split('_')[1]}"), max_grade=2, grade_part=part4,
                grade=2 * int(pim_neighbor_on(neighbors[router], iface(router, net), a(peer, net))),
                description=tr("voisinage PIM sur un lien du site asm"),
            )
        self.add_grade_element(
            title=no_tr("asm_source_lan"), max_grade=1, grade_part=part4,
            grade=int('eth0' in pim_if['asm_r1']), description=tr("PIM sur le réseau de la source"),
        )
        for r in ('asm_r1', 'asm_r2', 'asm_r3'):
            entry = rp_for_group(rp_info[r], d.g_asm) or {}
            self.add_grade_element(
                title=no_tr(f"asm_rp_{r.split('_')[1]}"), max_grade=1, grade_part=part4,
                grade=int(entry.get('rp') == str(asm_rp)), description=tr("RP du groupe sur un routeur"),
            )
        self.add_grade_element(
            title=no_tr("asm_igmp"), max_grade=2, grade_part=part4,
            grade=2 * int(igmp_enabled(igmp_if['asm_r3'], iface('asm_r3', 'asm_rx_lan'))),
            description=tr("IGMP du côté du récepteur"),
        )
        self.add_grade_element(
            title=no_tr("asm_stream"), max_grade=4, grade_part=part4,
            grade=4 * int(streamed('asm_h', 'grade_asm', d.g_asm)), description=tr("asm_h reçoit le flux"),
        )
        spt_entry = asm_mroutes.get((str(d.ips.asm_src.ip), str(d.g_asm))) or {}
        self.add_grade_element(
            title=no_tr("asm_spt"), max_grade=3, grade_part=part4,
            grade=3 * int(spt_entry.get('iif') == iface('asm_r3', 'asm_l13')),
            description=tr("asm_r3 reçoit le flux par l'arbre de source"),
        )
        self.add_grade_element(
            title=no_tr("asm_rpf_interface"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("rpf_iface")) == cheat_asm["rpf_iface"]), description=tr("interface RPF vers le RP"),
        )
        for field, title_ in (("fhr_message", "asm_register"), ("rp_answer", "asm_register_stop")):
            self.add_grade_element(
                title=no_tr(title_), max_grade=1, grade_part=part4,
                grade=int(_norm(q4.get(field)) == cheat_asm[field]), scope=CHOICE_SCOPE,
                description=tr("message PIM de l'enregistrement d'une source"),
            )

        # =====================================================================
        # Part 5 — PIM-SSM
        # =====================================================================
        part5 = self.add_grade_part(no_tr("ssm"), tr("Partie 5 — PIM-SSM sur le site ssm"))
        self.question_dummy(
            section=self.section(0),
            title=tr("PIM-SSM et IGMPv3"),
            hash="dba2b3694b8c1144",
            description=tr("""
Sur le site `ssm`, la source `ssm_src` a deux adresses : `{s1}` et `{s2}` (sur le même réseau).
Il n'y a pas de RP (section @@ref:ssm@@).

1. Activez PIM sur les interfaces de `ssm_r1` et de `ssm_r2`, et IGMP, en **version 3**, sur
   l'interface de `ssm_r2` du côté de `ssm_h`.
2. Sur `ssm_h`, abonnez-vous au canal ({s1}, `{group}`) : `iperf -s -u -B {group} -H {s1} -i 1`.
   Émettez vers `{group}` depuis `ssm_src`, d'abord depuis `{s1}`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K -B {s1}`), puis en même temps depuis `{s2}`.
   Comparez les tables multicast des deux routeurs et ce qui arrive sur `ssm_h`
   (`tcpdump -ni eth0 host {group}`).
3. Déclarez aussi les groupes `{extra}` comme groupes SSM, sur les deux routeurs, sans perdre
   `{default}` (`show ip pim group-type`).
""").format(s1=s1, s2=s2, group=d.ssm_group, extra=SSM_EXTRA, default=SSM_DEFAULT)
            + instructor(tr("""
**Solution.** Sur `ssm_r1` :

```
configure terminal
 ip prefix-list {plist} seq 5 permit {default} le 32
 ip prefix-list {plist} seq 10 permit {extra} le 32
 ip pim ssm prefix-list {plist}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
end
write
```

Sur `ssm_r2`, la même chose, avec en plus `ip igmp` et `ip igmp version 3` sur `eth1`.
L'abonnement de `ssm_h` est un rapport IGMPv3 `INCLUDE` {{{s1}}} : `ssm_r2` envoie un *Join*
({s1}, G) vers `ssm_r1`, qui ne transmet que ce canal. Le trafic de `{s2}` s'arrête à `ssm_r1`
(entrée ({s2}, G) sans interface de sortie, drapeau `P`) : `ssm_h` n'en voit rien.

Évaluation : `ssm_neighbor` (2 : voisinage PIM entre les deux routeurs), `ssm_source_lan` (1 :
PIM sur `eth0` de `ssm_r1`), `ssm_igmp_v3` (2 : IGMPv3 sur `eth1` de `ssm_r2`), `ssm_stream` (3 :
`ssm_h` reçoit le canal de `{s1}`), `ssm_source_filter` (2 : aucune trame de `{s2}` vers le groupe
sur le réseau de `ssm_h`, compté seulement si le canal de `{s1}` arrive), `ssm_range_r1` et
`ssm_range_r2` (1 chacun : un groupe de `{extra}` est SSM).
""").format(plist=SSM_PLIST, default=SSM_DEFAULT, extra=SSM_EXTRA, s1=s1, s2=s2)),
        )
        ssm_stream = streamed('ssm_h', 'grade_ssm', d.g_ssm, source=s1)
        ssm_r2_rx = igmp_if['ssm_r2'].get(iface('ssm_r2', 'ssm_rx_lan')) or {}
        self.add_grade_element(
            title=no_tr("ssm_neighbor"), max_grade=2, grade_part=part5,
            grade=2 * int(pim_neighbor_on(neighbors['ssm_r2'], iface('ssm_r2', 'ssm_link'), a('ssm_r1', 'ssm_link'))),
            description=tr("voisinage PIM ssm_r1 – ssm_r2"),
        )
        self.add_grade_element(
            title=no_tr("ssm_source_lan"), max_grade=1, grade_part=part5,
            grade=int('eth0' in pim_if['ssm_r1']), description=tr("PIM sur le réseau de la source"),
        )
        self.add_grade_element(
            title=no_tr("ssm_igmp_v3"), max_grade=2, grade_part=part5,
            grade=2 * int(igmp_enabled(igmp_if['ssm_r2'], iface('ssm_r2', 'ssm_rx_lan'))
                          and ssm_r2_rx.get('version') == 3),
            description=tr("IGMPv3 du côté du récepteur"),
        )
        self.add_grade_element(
            title=no_tr("ssm_stream"), max_grade=3, grade_part=part5,
            grade=3 * int(ssm_stream), description=tr("ssm_h reçoit le canal (S1, G)"),
        )
        self.add_grade_element(
            title=no_tr("ssm_source_filter"), max_grade=2, grade_part=part5,
            grade=2 * int(ssm_stream and dumps['ssm_h']['grade_ssm_sniff'].ran
                          and received(dumps['ssm_h']['grade_ssm_sniff'], d.g_ssm, source=s2) == 0),
            description=tr("le trafic de S2 n'atteint pas ssm_h"),
        )
        for r in ('ssm_r1', 'ssm_r2'):
            self.add_grade_element(
                title=no_tr(f"ssm_range_{r.split('_')[1]}"), max_grade=1, grade_part=part5,
                grade=int(group_type[r] == 'SSM'), description=tr("plage SSM étendue"),
            )

        # =====================================================================
        # Part 6 — MSDP and scope boundary
        # =====================================================================
        part6 = self.add_grade_part(no_tr("msdp"), tr("Partie 6 — MSDP et frontière sur le site msdp"))
        rp1, rp2 = lo('msdp_r1'), lo('msdp_r2')
        self.question_dummy(
            section=self.section(0),
            title=tr("MSDP et portée administrative"),
            hash="56d4edf29591ba1d",
            description=tr("""
Le site `msdp` réunit deux domaines PIM, déjà configurés : `msdp_r1` est le RP du domaine 1
(`{rp1}`, celui de la source `msdp_src`), `msdp_r2` celui du domaine 2 (`{rp2}`, celui du
récepteur `msdp_h`), chacun pour tous les groupes (`{all}`). PIM tourne sur le lien entre eux
(section @@ref:msdp@@).

1. Faites rejoindre `{group}` à `msdp_h`, émettez depuis `msdp_src` : le flux n'arrive pas.
   Pourquoi ? Comparez `show ip mroute` sur les deux routeurs.
2. Établissez une session **MSDP** entre les deux RP, entre leurs adresses de bouclage
   (`show ip msdp peer`, puis `show ip msdp sa` pendant que la source émet). Le flux arrive-t-il ?
3. Les groupes de portée organisation (`{scoped}`) ne doivent pas sortir du domaine 1. Posez
   une **frontière** sur l'interface de `msdp_r1` vers `msdp_r2` (section @@ref:scoping@@), puis
   vérifiez avec deux flux simultanés, vers `{group}` et vers `{scoped_group}` : le premier passe,
   le second non.
""").format(rp1=rp1, rp2=rp2, all=MSDP_RP_RANGE, group=d.msdp_group, scoped=SCOPED_RANGE,
            scoped_group=d.scoped_group)
            + instructor(tr("""
**Solution.** Chaque RP ignore les sources de l'autre domaine : `msdp_r2` a l'entrée (\\*,G) de
son récepteur, `msdp_r1` l'entrée (S,G) de sa source, mais personne ne fait le lien. Sur
`msdp_r1` :

```
configure terminal
 ip msdp peer {rp2} source {rp1}
 ip prefix-list {plist} seq 5 deny {scoped} le 32
 ip prefix-list {plist} seq 10 permit 224.0.0.0/4 le 32
 interface {r1_link}
  ip multicast boundary oil {plist}
 exit
end
write
```

Sur `msdp_r2` : `ip msdp peer {rp1} source {rp2}`. Après une trentaine de secondes, la session
est `established`. Dès que la source émet, `msdp_r1` envoie un SA, `msdp_r2` le met en cache
(`SPT y`) et envoie un *Join* (S,G) vers la source : le flux passe. La frontière fait ignorer à
`msdp_r1` les *Join* reçus sur `{r1_link}` pour `{scoped}` : l'entrée (S,G) de ces groupes reste
sans interface de sortie (drapeau `P`), alors que leur SA traverse encore la session.

Évaluation : `msdp_peer_r1`, `msdp_peer_r2` (2 chacun : la session est établie), `msdp_sa` (2 :
`msdp_r2` a reçu le SA du flux d'évaluation), `msdp_stream` (4 : `msdp_h` reçoit le flux),
`msdp_boundary_config` (1 : une frontière sur `{r1_link}` de `msdp_r1`, dont la liste refuse le
groupe de portée organisation du flux d'évaluation), `msdp_boundary_blocks` (3 : `msdp_h` ne reçoit
pas ce groupe, compté seulement si le premier flux passe).
""").format(rp1=rp1, rp2=rp2, plist=SCOPE_PLIST, scoped=SCOPED_RANGE, r1_link=iface('msdp_r1', 'msdp_link'))),
        )
        msdp_stream = streamed('msdp_h', 'grade_msdp', d.g_msdp)
        boundary = (msdp_r1_config.get('interfaces', {}).get(iface('msdp_r1', 'msdp_link')) or {}).get('multicast_boundary')
        boundary_ok = bool(boundary) and prefix_list_permits(msdp_r1_config.get('prefix_lists', {}), boundary,
                                                             d.g_scoped) is False
        for r, peer in (('msdp_r1', rp2), ('msdp_r2', rp1)):
            self.add_grade_element(
                title=no_tr(f"msdp_peer_{r.split('_')[1]}"), max_grade=2, grade_part=part6,
                grade=2 * int(bool((msdp_peers[r].get(str(peer)) or {}).get('established'))),
                description=tr("session MSDP établie"),
            )
        self.add_grade_element(
            title=no_tr("msdp_sa"), max_grade=2, grade_part=part6,
            grade=2 * int((str(d.ips.msdp_src.ip), str(d.g_msdp)) in msdp_sa), description=tr("SA reçu par msdp_r2"),
        )
        self.add_grade_element(
            title=no_tr("msdp_stream"), max_grade=4, grade_part=part6,
            grade=4 * int(msdp_stream), description=tr("msdp_h reçoit le flux de l'autre domaine"),
        )
        self.add_grade_element(
            title=no_tr("msdp_boundary_config"), max_grade=1, grade_part=part6,
            grade=int(boundary_ok), description=tr("frontière sur msdp_r1"),
        )
        self.add_grade_element(
            title=no_tr("msdp_boundary_blocks"), max_grade=3, grade_part=part6,
            grade=3 * int(msdp_stream and got('msdp_h', 'grade_msdp', d.g_scoped) == 0),
            description=tr("le groupe de portée organisation ne sort pas du domaine 1"),
        )

        # =====================================================================
        # Part 7 — troubleshooting
        # =====================================================================
        part7 = self.add_grade_part(no_tr("fix"), tr("Partie 7 — Dépannage sur le site fix"))
        fix_rp = lo('fix_r1')
        self.question_dummy(
            section=self.section(0),
            title=tr("Un domaine PIM en panne"),
            hash="538aa30fd2d2f9d7",
            description=tr("""
Le site `fix` est un domaine PIM-SM complet : `fix_r1` dessert la source `fix_src` et sert de RP
(`{rp}`, son adresse de bouclage, pour les groupes `{range}`), `fix_r2` dessert le récepteur
`fix_h`. Deux liens relient les routeurs : `fix_la` et `fix_lb`. Tout a été configuré par un
collègue... mais `fix_h` ne reçoit pas le flux de `fix_src`.

Trouvez et corrigez **toutes** les pannes : il y en a **quatre**. Ne cassez pas la conception
du site : `{rp}` reste le RP, et le routage unicast peut être modifié s'il le faut. Suivez la
méthode de la section @@ref:diagnostic@@, du récepteur vers la source, et testez avec
`iperf -s -u -B {group} -i 1` sur `fix_h` et `iperf -c {group} -u -T 16 -t 60 -b 50K` sur
`fix_src`.
""").format(rp=fix_rp, range=RP_RANGE, group=d.fix_group)
            + instructor(tr("""
**Solution.** Les quatre pannes :

1. PIM n'est pas activé sur `eth0` de `fix_r1`, l'interface du réseau de la source : `fix_r1` ne
   crée pas d'entrée (S,G) et n'enregistre pas la source. Correction : `interface eth0` /
   `ip pim`.
2. `fix_r1` filtre PIM : la règle `ip protocol {{ gre, pim }} drop` de la chaîne `input` de
   `{nft}` jette les *Hello* et les *Join* de `fix_r2`. `fix_r2` voit `fix_r1` comme voisin, pas
   l'inverse. Correction : retirer `pim` de la règle (ou toute la règle), puis `nft -f {nft}`.
3. `fix_r2` désigne comme RP `{wrong}` (l'adresse de `fix_r1` sur `fix_la`) au lieu de `{rp}` : ses
   *Join* (\\*,G) visent un routeur qui n'est pas le RP. Correction :
   `no ip pim rp {wrong} {range}` puis `ip pim rp {rp} {range}`.
4. La route statique de `fix_r2` vers `{rp}` passe par `fix_lb` (`{lb}`), où PIM n'est pas activé :
   l'interface RPF vers le RP n'a pas de voisin PIM, aucun *Join* ne part. Correction : faire
   passer la route par `fix_la` (`no ip route {rp}/32 {lb}` puis `ip route {rp}/32 {la}`), ou
   activer PIM sur `fix_lb` des deux côtés.

Après les corrections, il faut attendre le *Hello* suivant de `fix_r2` (au plus 30 s) avant que
`fix_r1` le connaisse comme voisin et accepte ses *Join*.

Évaluation : `fix_stream` (6 : `fix_h` reçoit le flux), `fix_source_lan` (2 : panne 1),
`fix_pim_filter` (2 : panne 2, `fix_r1` a `fix_r2` pour voisin PIM), `fix_rp_address` (2 : panne 3,
le RP du groupe sur `fix_r2`), `fix_rpf_to_rp` (2 : panne 4, l'interface de `fix_r2` vers `{rp}`
a un voisin PIM).
""").format(rp=fix_rp, range=RP_RANGE, nft=FIX_NFT_FILE, wrong=a('fix_r1', 'fix_la'), lb=a('fix_r1', 'fix_lb'),
            la=a('fix_r1', 'fix_la'))),
        )
        cheat_fix = {"diagnosis": "1. pas de PIM sur eth0 de fix_r1 ; 2. nftables de fix_r1 jette PIM ; "
                                  "3. mauvais RP sur fix_r2 ; 4. route vers le RP par fix_lb sans PIM"}
        self.question_form(
            section=self.section(1),
            title=tr("Compte rendu"),
            hash="1e743ae13f56ccc3",
            description=tr("""
Décrivez brièvement chaque panne trouvée et sa correction (non noté automatiquement : votre
enseignant le lira).

@@{diagnosis:+6}@@
"""),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        fix_rp_entry = rp_for_group(rp_info['fix_r2'], d.g_fix) or {}
        rpf_dev = _route_dev(fix_rp_route)
        self.add_grade_element(
            title=no_tr("fix_stream"), max_grade=6, grade_part=part7,
            grade=6 * int(streamed('fix_h', 'grade_fix', d.g_fix)), description=tr("fix_h reçoit le flux"),
        )
        self.add_grade_element(
            title=no_tr("fix_source_lan"), max_grade=2, grade_part=part7,
            grade=2 * int('eth0' in pim_if['fix_r1']), description=tr("PIM sur le réseau de la source"),
        )
        self.add_grade_element(
            title=no_tr("fix_pim_filter"), max_grade=2, grade_part=part7,
            grade=2 * int(any(str(addr) in sum(neighbors['fix_r1'].values(), [])
                              for addr in (a('fix_r2', 'fix_la'), a('fix_r2', 'fix_lb')))),
            description=tr("fix_r1 voit fix_r2 comme voisin PIM"),
        )
        self.add_grade_element(
            title=no_tr("fix_rp_address"), max_grade=2, grade_part=part7,
            grade=2 * int(fix_rp_entry.get('rp') == str(fix_rp)), description=tr("le bon RP sur fix_r2"),
        )
        self.add_grade_element(
            title=no_tr("fix_rpf_to_rp"), max_grade=2, grade_part=part7,
            grade=2 * int(bool(rpf_dev) and pim_neighbor_on(neighbors['fix_r2'], rpf_dev)),
            description=tr("interface RPF de fix_r2 vers le RP avec un voisin PIM"),
        )

        # =====================================================================
        # Part 8 — IPv6 (bonus)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("ipv6"), tr("Partie 8 — MLD et PIMv6 (bonus)"))
        v6_src = d.ips6.v6_src.ip
        self.question_dummy(
            section=self.section(0),
            title=tr("Multicast IPv6 : MLD et PIMv6"),
            hash="13d5d72142de2d3b",
            description=tr("""
Le site `v6` est en IPv6 seulement ; le démon `pim6d` tourne sur `v6_r1` et `v6_r2`
(section @@ref:ipv6@@).

1. Activez PIMv6 sur les interfaces des deux routeurs, et MLD sur l'interface de `v6_r2` du côté
   de `v6_h`. Vérifiez le voisinage (`show ipv6 pim neighbor`) : sous quelle adresse apparaît le
   voisin ?
2. Sur `v6_h`, abonnez-vous au canal SSM ({src}, `{group}`) :
   `iperf -s -u -V -B {group} -H {src} -i 1`, puis émettez depuis `v6_src` :
   `iperf -c {group} -u -V -T 16 -t 30 -b 50K`. Lisez `show ipv6 mld groups` et
   `show ipv6 mroute` sur `v6_r2`. Quels autres groupes `v6_r2` connaît-il sur ce réseau, et
   pourquoi ?
""").format(src=v6_src, group=d.v6_group)
            + instructor(tr("""
**Solution.** Sur `v6_r1` : `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim`. Sur
`v6_r2` : `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim` et `ipv6 mld`. Le voisin
PIMv6 apparaît sous son adresse lien local (`fe80::…`). Le groupe est dans `ff3e::/32`, la plage
SSM par défaut de `pim6d` : l'abonnement MLDv2 de `v6_h` fait envoyer un *Join* (S,G) à `v6_r2`.
`show ipv6 mld groups` montre aussi `ff02::2`, `ff02::d`, `ff02::16` et les groupes
*solicited-node* (`ff02::1:ff…`) des adresses des machines du réseau.

Évaluation (bonus) : `v6_neighbor` (2 : voisinage PIMv6), `v6_mld` (1 : MLD sur `eth1` de `v6_r2`),
`v6_mld_group` (1 : `v6_r2` connaît le groupe du flux d'évaluation), `v6_stream` (2 : `v6_h` reçoit
le flux).
""")),
        )
        self.add_grade_element(
            title=no_tr("v6_neighbor"), max_grade=2, grade_part=part8, bonus=True,
            grade=2 * int(pim_neighbor_on(v6_neighbors, iface('v6_r2', 'v6_link'))),
            description=tr("voisinage PIMv6"),
        )
        self.add_grade_element(
            title=no_tr("v6_mld"), max_grade=1, grade_part=part8, bonus=True,
            grade=int(igmp_enabled(mld_if, iface('v6_r2', 'v6_rx_lan'))), description=tr("MLD du côté du récepteur"),
        )
        self.add_grade_element(
            title=no_tr("v6_mld_group"), max_grade=1, grade_part=part8, bonus=True,
            grade=int(str(d.g_v6) in (mld_groups.get(iface('v6_r2', 'v6_rx_lan')) or {})),
            description=tr("v6_r2 connaît le groupe du récepteur"),
        )
        self.add_grade_element(
            title=no_tr("v6_stream"), max_grade=2, grade_part=part8, bonus=True,
            grade=2 * int(streamed('v6_h', 'grade_v6', d.g_v6, source=v6_src)), description=tr("v6_h reçoit le flux"),
        )


_TRANSLATIONS = {'en': {
    "Multicast IP : IGMP, PIM et MSDP": "IP multicast: IGMP, PIM and MSDP",
    """
**Sommaire**
""": """
**Contents**
""",
    "Le multicast IP : principes": "IP multicast: principles",
    """
Il y a trois façons de remettre un datagramme IP :

- l'**unicast** : un émetteur, un destinataire ;
- la **diffusion** (*broadcast*) : tous les hôtes du réseau local, et lui seul (les routeurs ne la
  propagent pas) ;
- le **multicast** (multidiffusion) : un émetteur, un **groupe** de destinataires, qui peuvent
  être sur n'importe quel réseau.

Un groupe est désigné par une **adresse de groupe** (section @@ref:addressing@@). Le modèle du
groupe d'hôtes (RFC 1112) est très simple :

- un hôte qui veut recevoir le trafic d'un groupe le **rejoint** : son noyau le signale aux
  routeurs de son réseau par IGMP (section @@ref:igmp@@) ;
- n'importe qui peut **émettre** vers un groupe, sans en être membre : il suffit d'envoyer un
  datagramme UDP à l'adresse du groupe ;
- les routeurs construisent entre eux un **arbre de distribution** (section @@ref:routing@@) :
  un datagramme est dupliqué seulement là où les chemins vers les membres divergent. Un lien ne
  le transporte qu'une fois, quel que soit le nombre de récepteurs derrière lui.

Le multicast passe par **UDP** : il n'y a ni connexion, ni accusé de réception, ni contrôle de
congestion (une connexion TCP n'a qu'un seul destinataire). Il sert à la télévision sur IP, à la
diffusion de données financières, à la découverte de services (mDNS, SSDP), aux protocoles de
routage (OSPF, RIP, PIM, VRRP), à la diffusion de logiciels ou d'images système et au transport
des VXLAN.

Deux modèles de service coexistent :

- **ASM** (*Any-Source Multicast*) : le récepteur rejoint un groupe **G** et reçoit le trafic de
  toutes ses sources. L'état correspondant dans les routeurs se note **(\\*,G)** ;
- **SSM** (*Source-Specific Multicast*, section @@ref:ssm@@) : le récepteur s'abonne à un
  **canal (S,G)**, c'est-à-dire au groupe G émis par la seule source S.

### @@sec:ttl@@ Le TTL des datagrammes multicast

Chaque routeur décrémente le TTL d'un datagramme multicast comme celui d'un datagramme unicast,
et le jette à 0. Or **une socket multicast émet par défaut avec un TTL de 1** : sans réglage, le
trafic ne quitte pas le réseau local. Une application qui veut traverser n routeurs doit fixer
un TTL supérieur à n (option `IP_MULTICAST_TTL`, `-T` d'`iperf`).

Les groupes de `224.0.0.0/24` (section @@ref:addressing@@) ne sont **jamais** routés, quel que
soit leur TTL : ce sont ceux des protocoles de contrôle d'un lien (OSPF, RIP, PIM, IGMPv3...),
émis d'ailleurs avec un TTL de 1.
""": """
There are three ways of delivering an IP datagram:

- **unicast**: one sender, one recipient;
- **broadcast**: every host of the local network, and that network only (routers do not
  forward it);
- **multicast**: one sender, a **group** of recipients, which may be on any
  network.

A group is designated by a **group address** (section @@ref:addressing@@). The host group
model (RFC 1112) is very simple:

- a host that wants to receive the traffic of a group **joins** it: its kernel reports this to
  the routers of its network with IGMP (section @@ref:igmp@@);
- anyone can **send** to a group without being a member: it is enough to send a UDP
  datagram to the address of the group;
- the routers build a **distribution tree** between them (section @@ref:routing@@): a
  datagram is duplicated only where the paths towards the members diverge. A link carries it
  only once, however many receivers there are behind it.

Multicast runs over **UDP**: there is no connection, no acknowledgement and no congestion
control (a TCP connection has a single recipient). It is used for IP television, the
distribution of financial data, service discovery (mDNS, SSDP), routing protocols
(OSPF, RIP, PIM, VRRP), the distribution of software or system images and the transport
of VXLAN.

Two service models coexist:

- **ASM** (*Any-Source Multicast*): the receiver joins a group **G** and receives the traffic of
  all its sources. The corresponding state in the routers is written **(\\*,G)**;
- **SSM** (*Source-Specific Multicast*, section @@ref:ssm@@): the receiver subscribes to a
  **channel (S,G)**, that is, to group G sent by source S alone.

### @@sec:ttl@@ The TTL of multicast datagrams

Each router decrements the TTL of a multicast datagram as it does that of a unicast datagram,
and discards it at 0. Yet **a multicast socket sends with a TTL of 1 by default**: without a
setting, the traffic does not leave the local network. An application that must cross n
routers has to set a TTL greater than n (option `IP_MULTICAST_TTL`, `-T` of `iperf`).

The groups of `224.0.0.0/24` (section @@ref:addressing@@) are **never** routed, whatever
their TTL: they are those of the control protocols of a link (OSPF, RIP, PIM, IGMPv3...),
which are sent with a TTL of 1 anyway.
""",
    "L'adressage multicast": "Multicast addressing",
    """
Les adresses IPv4 multicast forment le bloc **224.0.0.0/4** (de 224.0.0.0 à 239.255.255.255, l'ancienne
« classe D » ; registre de l'IANA, RFC 5771) :

| bloc | usage |
|------|-------|
| `224.0.0.0/24` | **lien local** (*link-local*) : protocoles de contrôle d'un réseau, jamais routés |
| `224.0.1.0/24` | contrôle inter-réseaux (*internetwork control*) : routés, par exemple NTP `224.0.1.1` |
| `224.2.0.0/16` et suivants | groupes **globaux** attribués par l'IANA ou ad hoc |
| `232.0.0.0/8` | **SSM** (section @@ref:ssm@@) |
| `233.0.0.0/8` | **GLOP** (RFC 3180) : `233.X.Y.0/24` revient au réseau dont le numéro d'AS (16 bits) s'écrit X×256+Y |
| `239.0.0.0/8` | **portée administrative** (RFC 2365), l'équivalent des adresses privées : un groupe n'y a de sens que dans un domaine |
| `239.255.0.0/16` | dont la **portée locale** (*local scope*) : un site |
| `239.192.0.0/14` | dont la **portée organisation** (*organization-local scope*) |

Quelques groupes bien connus :

| groupe | membres |
|--------|---------|
| `224.0.0.1` | tous les hôtes du lien (*all-systems*) : requêtes générales d'IGMP |
| `224.0.0.2` | tous les routeurs du lien : messages *Leave* d'IGMPv2 |
| `224.0.0.5` / `224.0.0.6` | routeurs OSPF / routeurs désignés OSPF |
| `224.0.0.9` | routeurs RIPv2 |
| `224.0.0.13` | routeurs PIM (*all-PIM-routers*) |
| `224.0.0.18` | routeurs VRRP |
| `224.0.0.22` | routeurs IGMPv3 : destination des rapports d'IGMPv3 |
| `224.0.0.251` | mDNS (Avahi, Bonjour) |

### @@sec:mac@@ De l'adresse de groupe à l'adresse MAC

Sur Ethernet, une trame multicast IPv4 est envoyée à une adresse MAC de groupe : le préfixe
**`01:00:5e`** suivi des **23 bits de poids faible** de l'adresse IP (RFC 1112). Par exemple :

```
groupe IP     239.  1. 2. 3   = 11101111.00000001.00000010.00000011
23 bits bas                            .0000001.00000010.00000011  = 01:02:03
adresse MAC   01:00:5e:01:02:03
```

Une adresse de groupe a 28 bits significatifs (les 4 premiers valent toujours `1110`) : les
**5 bits** qui séparent les 28 des 23 sont perdus. **32 groupes** partagent donc chaque adresse
MAC : `224.1.2.3`, `225.1.2.3`, `239.129.2.3` (le bit de poids fort du deuxième octet est
aussi perdu) et 29 autres donnent toutes `01:00:5e:01:02:03`. La carte réseau, qui filtre les
trames sur leur adresse MAC, laisse passer celles des groupes « cousins » : c'est le noyau qui
fait le tri. Un commutateur qui fait de l'IGMP snooping (section @@ref:snooping@@) sur les adresses
MAC confond aussi ces groupes.

### @@sec:ipv6addr@@ Les adresses IPv6 multicast

En IPv6, la diffusion n'existe plus : tout ce qu'elle faisait passe par le multicast. Les
adresses multicast forment le bloc **`ff00::/8`**. Le deuxième octet porte deux champs de 4 bits :

- les **drapeaux** : `0` pour une adresse permanente attribuée par l'IANA, `1` pour une adresse
  temporaire, `3` pour une adresse dérivée d'un préfixe unicast : `ff3x::/32` est le bloc **SSM** ;
- la **portée** (*scope*), que les routeurs respectent d'eux-mêmes :

| portée | valeur | exemple |
|--------|--------|---------|
| interface | 1 | `ff01::1` |
| lien | 2 | `ff02::1` (tous les nœuds), `ff02::2` (tous les routeurs), `ff02::d` (PIM), `ff02::16` (MLDv2) |
| administration locale | 4 | |
| site | 5 | `ff05::2` |
| organisation | 8 | |
| globale | e | `ff0e::…`, `ff3e::…` |

Chaque adresse unicast d'une interface fait aussi rejoindre le groupe **solicited-node**
`ff02::1:ffXX:XXXX`, formé des **24 derniers bits** de l'adresse : c'est à lui que la découverte
des voisins (NDP) envoie ses sollicitations. L'adresse MAC d'un groupe IPv6 est **`33:33`**
suivi des **32 derniers bits** du groupe (RFC 2464). Par exemple, pour `2001:db8::1:2abc:d123` :

```
solicited-node  ff02::1:ffbc:d123
adresse MAC     33:33:ff:bc:d1:23
```
""": """
IPv4 multicast addresses form the block **224.0.0.0/4** (from 224.0.0.0 to 239.255.255.255, the former
"class D"; IANA registry, RFC 5771):

| block | use |
|------|-------|
| `224.0.0.0/24` | **link-local**: control protocols of a network, never routed |
| `224.0.1.0/24` | internetwork control: routed, for example NTP `224.0.1.1` |
| `224.2.0.0/16` and following | **global** groups assigned by the IANA or ad hoc |
| `232.0.0.0/8` | **SSM** (section @@ref:ssm@@) |
| `233.0.0.0/8` | **GLOP** (RFC 3180): `233.X.Y.0/24` belongs to the network whose AS number (16 bits) is X×256+Y |
| `239.0.0.0/8` | **administrative scope** (RFC 2365), the equivalent of private addresses: a group there only makes sense within a domain |
| `239.255.0.0/16` | including the **local scope**: a site |
| `239.192.0.0/14` | including the **organisation-local scope** |

A few well-known groups:

| group | members |
|--------|---------|
| `224.0.0.1` | all the hosts of the link (*all-systems*): IGMP general queries |
| `224.0.0.2` | all the routers of the link: IGMPv2 *Leave* messages |
| `224.0.0.5` / `224.0.0.6` | OSPF routers / OSPF designated routers |
| `224.0.0.9` | RIPv2 routers |
| `224.0.0.13` | PIM routers (*all-PIM-routers*) |
| `224.0.0.18` | VRRP routers |
| `224.0.0.22` | IGMPv3 routers: destination of the IGMPv3 reports |
| `224.0.0.251` | mDNS (Avahi, Bonjour) |

### @@sec:mac@@ From the group address to the MAC address

On Ethernet, an IPv4 multicast frame is sent to a group MAC address: the prefix
**`01:00:5e`** followed by the **23 low-order bits** of the IP address (RFC 1112). For example:

```
IP group      239.  1. 2. 3   = 11101111.00000001.00000010.00000011
low 23 bits                            .0000001.00000010.00000011  = 01:02:03
MAC address   01:00:5e:01:02:03
```

A group address has 28 significant bits (the first 4 are always `1110`): the **5 bits**
between the 28 and the 23 are lost. **32 groups** therefore share each MAC address:
`224.1.2.3`, `225.1.2.3`, `239.129.2.3` (the high-order bit of the second byte is lost too)
and 29 others all give `01:00:5e:01:02:03`. The network card, which filters frames on their
MAC address, lets through those of the "cousin" groups: the kernel does the sorting. A switch
that does IGMP snooping (section @@ref:snooping@@) on MAC addresses also mixes these groups
up.

### @@sec:ipv6addr@@ IPv6 multicast addresses

IPv6 has no broadcast any more: everything broadcast did goes through multicast. Multicast
addresses form the block **`ff00::/8`**. The second byte carries two 4-bit fields:

- the **flags**: `0` for a permanent address assigned by the IANA, `1` for a temporary
  address, `3` for an address derived from a unicast prefix: `ff3x::/32` is the **SSM** block;
- the **scope**, which routers enforce on their own:

| scope | value | example |
|--------|--------|---------|
| interface | 1 | `ff01::1` |
| link | 2 | `ff02::1` (all nodes), `ff02::2` (all routers), `ff02::d` (PIM), `ff02::16` (MLDv2) |
| admin-local | 4 | |
| site | 5 | `ff05::2` |
| organisation | 8 | |
| global | e | `ff0e::…`, `ff3e::…` |

Each unicast address of an interface also makes it join the **solicited-node** group
`ff02::1:ffXX:XXXX`, made of the **last 24 bits** of the address: neighbour discovery (NDP)
sends its solicitations to it. The MAC address of an IPv6 group is **`33:33`** followed by
the **last 32 bits** of the group (RFC 2464). For example, for `2001:db8::1:2abc:d123`:

```
solicited-node  ff02::1:ffbc:d123
MAC address     33:33:ff:bc:d1:23
```
""",
    "Côté hôte : émettre et recevoir": "Host side: sending and receiving",
    """
Pour **recevoir**, une application ouvre une socket UDP liée au port du flux et demande au noyau
de rejoindre le groupe sur une interface (`IP_ADD_MEMBERSHIP` ou `MCAST_JOIN_GROUP` ; pour un
canal SSM, `IP_ADD_SOURCE_MEMBERSHIP` ou `MCAST_JOIN_SOURCE_GROUP`). Le noyau émet aussitôt le
rapport IGMP correspondant (section @@ref:igmp@@) et le répète quand un routeur l'interroge.
Quand la dernière application quitte le groupe, il émet le départ (*leave*).

Pour **émettre**, il suffit d'envoyer un datagramme à l'adresse du groupe. Trois réglages
comptent :

- le **TTL**, de **1 par défaut** (`IP_MULTICAST_TTL`, section @@ref:ttl@@) ;
- l'**interface de sortie** : à défaut de `IP_MULTICAST_IF`, le noyau la choisit dans la table
  de routage, comme pour l'unicast. Un hôte sans route par défaut et sans route vers
  `224.0.0.0/4` ne peut pas émettre (*Network is unreachable*) : `ip route add 224.0.0.0/4 dev
  eth0` lui en donne une ;
- le **bouclage** (`IP_MULTICAST_LOOP`) : l'émetteur reçoit-il lui-même ce qu'il émet ?

Pour observer l'état d'un hôte :

- `ip maddr show dev eth0` : les groupes rejoints par l'interface et leur adresse MAC ;
- `cat /proc/net/igmp` : les mêmes, avec la version d'IGMP utilisée sur chaque interface
  (adresses en hexadécimal, octets dans l'ordre inverse : `010000E0` est `224.0.0.1`) ;
- `ss -ulpn` : les sockets UDP et leur port.

Le noyau choisit seul la version d'IGMP : la plus récente (v3), sauf s'il entend un routeur
plus ancien sur le lien. On peut la forcer : `sysctl -w net.ipv4.conf.eth0.force_igmp_version=2`
(0 : automatique) ; pour MLD, `net.ipv6.conf.eth0.force_mld_version`.
""": """
To **receive**, an application opens a UDP socket bound to the port of the stream and asks the
kernel to join the group on an interface (`IP_ADD_MEMBERSHIP` or `MCAST_JOIN_GROUP`; for an
SSM channel, `IP_ADD_SOURCE_MEMBERSHIP` or `MCAST_JOIN_SOURCE_GROUP`). The kernel immediately
sends the corresponding IGMP report (section @@ref:igmp@@) and repeats it when a router queries
it. When the last application leaves the group, it sends a *leave*.

To **send**, it is enough to send a datagram to the address of the group. Three settings
matter:

- the **TTL**, **1 by default** (`IP_MULTICAST_TTL`, section @@ref:ttl@@);
- the **outgoing interface**: without `IP_MULTICAST_IF`, the kernel picks it from the routing
  table, as for unicast. A host without a default route and without a route to
  `224.0.0.0/4` cannot send (*Network is unreachable*): `ip route add 224.0.0.0/4 dev
  eth0` gives it one;
- **loopback** (`IP_MULTICAST_LOOP`): does the sender itself receive what it sends?

To observe the state of a host:

- `ip maddr show dev eth0`: the groups joined by the interface and their MAC address;
- `cat /proc/net/igmp`: the same, with the IGMP version used on each interface
  (addresses in hexadecimal, bytes in reverse order: `010000E0` is `224.0.0.1`);
- `ss -ulpn`: the UDP sockets and their port.

The kernel chooses the IGMP version on its own: the most recent one (v3), unless it hears an
older router on the link. It can be forced: `sysctl -w net.ipv4.conf.eth0.force_igmp_version=2`
(0: automatic); for MLD, `net.ipv6.conf.eth0.force_mld_version`.
""",
    "IGMP : l'adhésion aux groupes": "IGMP: group membership",
    """
**IGMP** (*Internet Group Management Protocol*) est le dialogue entre les hôtes d'un réseau
local et ses routeurs multicast. Un routeur n'apprend pas *quels* hôtes sont membres d'un
groupe mais seulement *s'il reste au moins un membre* sur chacune de ses interfaces : il ne lui
en faut pas plus pour décider s'il doit y transmettre le trafic du groupe.

### @@sec:igmpmsg@@ Messages et versions

IGMP est transporté directement dans IP (protocole **2**), avec un **TTL de 1** et l'option IP
**Router Alert** (RFC 2113), qui demande à chaque routeur d'examiner le paquet même s'il ne lui
est pas adressé.

| version | nouveautés | rapport (*report*) envoyé à | départ |
|---------|-----------|-----------------------------|--------|
| v1 (RFC 1112) | requête (*query*) et rapport | l'adresse du groupe | silencieux (expiration) |
| v2 (RFC 2236) | message **Leave**, requête spécifique à un groupe, délai de réponse, élection du querier | l'adresse du groupe | *Leave* vers **224.0.0.2** |
| v3 (RFC 3376) | **filtrage des sources** : enregistrements INCLUDE / EXCLUDE, ALLOW / BLOCK | **224.0.0.22** | un rapport de changement d'état |

- La **requête générale** (*general query*) est envoyée à `224.0.0.1` : « quels groupes
  avez-vous ? ». Chaque hôte répond après un délai aléatoire, borné par le *max response time*.
  En v1 et v2, un hôte qui entend un autre membre répondre pour le même groupe se tait.
- La **requête spécifique** (*group-specific query*, envoyée au groupe lui-même) suit un
  *Leave* : « reste-t-il un membre de ce groupe ? ».
- En **v3**, un rapport contient plusieurs **enregistrements de groupe** : `MODE_IS_EXCLUDE`
  { } signifie « toutes les sources », c'est l'adhésion ASM ; `MODE_IS_INCLUDE` {S1} signifie
  « seulement la source S1 », c'est l'abonnement SSM. Un départ est un rapport de changement
  d'état vers `INCLUDE` { }.

### @@sec:querier@@ Le querier

Sur un lien où plusieurs routeurs font IGMP, un seul envoie les requêtes : le **querier**. En v2
et v3, c'est celui qui a la **plus petite adresse IP** sur le lien. Un routeur qui entend une
requête venant d'une adresse plus petite que la sienne cesse d'interroger. Si plus aucune
requête n'est entendue pendant l'*other querier present interval*, il reprend le rôle.

Les autres routeurs continuent d'écouter les rapports : tous connaissent les groupes du lien.
Ne confondez pas le querier avec le **routeur désigné** de PIM (section @@ref:hello@@), élu, lui,
sur la plus grande adresse.

### @@sec:igmptimers@@ Les temporisateurs

| paramètre | défaut | rôle |
|-----------|--------|------|
| *query interval* | 125 s | période des requêtes générales |
| *query response interval* | 10 s | délai maximal de réponse annoncé dans la requête |
| *robustness variable* | 2 | nombre de répétitions d'un message (perte de paquets) |
| *group membership interval* | 2 × 125 + 10 = 260 s | au-delà, un groupe sans rapport est oublié |
| *other querier present interval* | 2 × 125 + 10 / 2 = 255 s | au-delà, un autre routeur devient querier |
| *last member query interval* | 1 s | délai entre les requêtes spécifiques qui suivent un départ |
| *last member query count* | 2 | nombre de ces requêtes |
| *startup query interval* | 125 / 4 s | requêtes rapprochées au démarrage |

Un départ explicite est vite traité : environ 2 × 1 s après le *Leave*, le routeur arrête le
trafic s'il n'a pas eu de réponse. Un hôte qui disparaît sans rien dire n'est oublié qu'au
bout de 260 s.

### @@sec:compat@@ Compatibilité entre versions

Un hôte s'aligne sur le querier : s'il entend une requête v2, il répond en v2. Un routeur v3
qui reçoit un **rapport v2** pour un groupe passe **ce groupe** en mode de compatibilité v2
pendant l'*older host present interval* (260 s par défaut) : `show ip igmp groups` affiche alors
la version 2. Les enregistrements de source sont ignorés pour ce groupe, car un hôte v2 ne sait
pas filtrer les sources.
""": """
**IGMP** (*Internet Group Management Protocol*) is the dialogue between the hosts of a local
network and its multicast routers. A router does not learn *which* hosts are members of a
group, only *whether at least one member remains* on each of its interfaces: it needs nothing
more to decide whether it must forward the traffic of the group there.

### @@sec:igmpmsg@@ Messages and versions

IGMP is carried directly in IP (protocol **2**), with a **TTL of 1** and the IP option
**Router Alert** (RFC 2113), which asks every router to examine the packet even if it is not
addressed to it.

| version | what is new | report sent to | leave |
|---------|-----------|-----------------------------|--------|
| v1 (RFC 1112) | query and report | the group address | silent (expiry) |
| v2 (RFC 2236) | **Leave** message, group-specific query, response delay, querier election | the group address | *Leave* to **224.0.0.2** |
| v3 (RFC 3376) | **source filtering**: INCLUDE / EXCLUDE, ALLOW / BLOCK records | **224.0.0.22** | a state-change report |

- The **general query** is sent to `224.0.0.1`: "which groups do you have?". Each host
  answers after a random delay, bounded by the *max response time*. In v1 and v2, a host that
  hears another member answer for the same group stays silent.
- The **group-specific query** (sent to the group itself) follows a *Leave*: "is there still a
  member of this group?".
- In **v3**, a report holds several **group records**: `MODE_IS_EXCLUDE` { } means "all
  sources", the ASM membership; `MODE_IS_INCLUDE` {S1} means "only source S1", the SSM
  subscription. A leave is a state-change report to `INCLUDE` { }.

### @@sec:querier@@ The querier

On a link where several routers run IGMP, only one sends the queries: the **querier**. In v2
and v3, it is the one with the **lowest IP address** on the link. A router that hears a query
from an address lower than its own stops querying. If no query is heard any more during the
*other querier present interval*, it takes the role back.

The other routers keep listening to the reports: they all know the groups of the link. Do not
confuse the querier with the PIM **designated router** (section @@ref:hello@@), which is
elected on the highest address.

### @@sec:igmptimers@@ The timers

| parameter | default | role |
|-----------|--------|------|
| *query interval* | 125 s | period of the general queries |
| *query response interval* | 10 s | maximum response delay announced in the query |
| *robustness variable* | 2 | number of repetitions of a message (packet loss) |
| *group membership interval* | 2 × 125 + 10 = 260 s | beyond it, a group without a report is forgotten |
| *other querier present interval* | 2 × 125 + 10 / 2 = 255 s | beyond it, another router becomes querier |
| *last member query interval* | 1 s | delay between the specific queries that follow a leave |
| *last member query count* | 2 | number of those queries |
| *startup query interval* | 125 / 4 s | closely spaced queries at startup |

An explicit leave is handled quickly: about 2 × 1 s after the *Leave*, the router stops the
traffic if it has had no answer. A host that disappears without a word is only forgotten after
260 s.

### @@sec:compat@@ Compatibility between versions

A host follows the querier: if it hears a v2 query, it answers in v2. A v3 router that
receives a **v2 report** for a group switches **that group** to v2 compatibility mode for the
*older host present interval* (260 s by default): `show ip igmp groups` then shows version 2.
Source records are ignored for that group, since a v2 host cannot filter sources.
""",
    "L'IGMP snooping des commutateurs": "IGMP snooping in switches",
    """
Un commutateur n'apprend une adresse MAC que comme **adresse source** d'une trame. Une adresse
de groupe n'est jamais une adresse source : les trames multicast sont donc **inondées sur tous
les ports**, comme la diffusion. Sur un réseau où passent quelques flux vidéo, tous les postes
reçoivent tout.

L'**IGMP snooping** (RFC 4541) consiste à lire au passage les messages IGMP :

- un **rapport** reçu sur un port inscrit ce port comme membre du groupe dans la **table des
  groupes** (*mdb*, *multicast database*) ; un *Leave*, ou l'absence de réponse aux requêtes,
  l'en retire ;
- une **requête** reçue sur un port le marque comme **port routeur** (*mrouter port*) : c'est
  par là qu'est le routeur multicast, qui doit recevoir tous les groupes ;
- une trame d'un groupe connu n'est plus transmise qu'aux ports membres et aux ports routeurs.
  Les groupes de `224.0.0.0/24` restent inondés.

Le snooping a besoin de **requêtes** pour tenir sa table à jour : sans elles, les hôtes ne
répètent pas leurs rapports. Sur un réseau sans routeur multicast, le commutateur doit envoyer
lui-même les requêtes : c'est sa fonction de **querier**. Le pont de Linux est prudent : **tant
qu'il n'a détecté aucun querier** (le sien ou un autre), il **inonde tout le multicast** sur
tous ses ports, même avec le snooping actif, pour ne priver personne d'un flux.

Le **départ rapide** (*fast leave*) retire un port d'un groupe dès le premier *Leave*, sans
requête spécifique. Ce n'est correct que si le port ne dessert qu'**un seul hôte**.

Avec le pont de Linux (`ip-link(8)`, `bridge(8)`) :

```
ip link set br0 type bridge mcast_snooping 1      # le snooping (actif par défaut à la création)
ip link set br0 type bridge mcast_querier 1       # le pont émet les requêtes
ip link set br0 type bridge mcast_igmp_version 3  # version de ses requêtes (2 par défaut)
ip link set br0 type bridge mcast_query_use_ifaddr 1   # requêtes émises depuis l'adresse de br0
                                                       # (sinon depuis 0.0.0.0)
bridge link set dev eth1 fastleave on             # départ rapide sur un port
ip -d link show br0                               # mcast_snooping, mcast_querier, temporisateurs
bridge -d link show                               # fastleave, mcast_router par port
bridge mdb show                                   # la table des groupes : port, groupe
```

Les temporisateurs du pont s'expriment en **centièmes de seconde** : `mcast_query_interval 12500`
vaut 125 s.
""": """
A switch learns a MAC address only as the **source address** of a frame. A group address is
never a source address: multicast frames are therefore **flooded on all ports**, like
broadcast. On a network carrying a few video streams, every host receives everything.

**IGMP snooping** (RFC 4541) consists in reading the IGMP messages as they go by:

- a **report** received on a port registers that port as a member of the group in the **group
  table** (*mdb*, *multicast database*); a *Leave*, or no answer to the queries, removes it
  from there;
- a **query** received on a port marks it as a **router port** (*mrouter port*): that is where
  the multicast router is, which must receive every group;
- a frame of a known group is only forwarded to the member ports and the router ports.
  The groups of `224.0.0.0/24` are still flooded.

Snooping needs **queries** to keep its table up to date: without them, the hosts do not
repeat their reports. On a network without a multicast router, the switch must send the
queries itself: this is its **querier** function. The Linux bridge is cautious: **as long as
it has detected no querier** (its own or another one), it **floods all multicast** on all its
ports, even with snooping on, so as not to deprive anyone of a stream.

**Fast leave** removes a port from a group at the first *Leave*, without a group-specific
query. It is only correct if the port serves **a single host**.

With the Linux bridge (`ip-link(8)`, `bridge(8)`):

```
ip link set br0 type bridge mcast_snooping 1      # snooping (on by default at creation)
ip link set br0 type bridge mcast_querier 1       # the bridge sends the queries
ip link set br0 type bridge mcast_igmp_version 3  # version of its queries (2 by default)
ip link set br0 type bridge mcast_query_use_ifaddr 1   # queries sent from the address of br0
                                                       # (otherwise from 0.0.0.0)
bridge link set dev eth1 fastleave on             # fast leave on a port
ip -d link show br0                               # mcast_snooping, mcast_querier, timers
bridge -d link show                               # fastleave, mcast_router per port
bridge mdb show                                   # the group table: port, group
```

The timers of the bridge are expressed in **hundredths of a second**: `mcast_query_interval 12500`
is 125 s.
""",
    "Le routage multicast": "Multicast routing",
    """
Le but du routage multicast est d'amener le trafic d'un groupe sur tous les réseaux où il y a
des membres, sur eux seuls, et sans boucle.

### @@sec:rpf@@ Le contrôle RPF

Un routeur unicast regarde l'adresse de **destination** d'un paquet. Un routeur multicast
regarde d'abord sa **source** : il n'accepte un paquet que s'il arrive par l'interface qu'il
utiliserait lui-même pour **joindre la source**, d'après sa table de routage unicast. C'est le
contrôle **RPF** (*Reverse Path Forwarding*). L'interface en question est l'**interface RPF**
(l'**iif**), le routeur suivant vers la source est le **voisin RPF**. Un paquet qui arrive par
une autre interface est jeté : c'est ce qui empêche les boucles et les doublons.

Conséquence : **le multicast dépend du routage unicast**. Une route absente ou asymétrique vers
la source, ou une route qui passe par un lien sans routage multicast, suffit à bloquer un flux
(section @@ref:diagnostic@@). Sur l'arbre partagé (section @@ref:join@@), le contrôle porte sur
l'adresse du point de rendez-vous au lieu de la source.

### @@sec:trees@@ Les arbres de distribution

- l'**arbre de source**, ou **arbre des plus courts chemins** (*SPT*), noté **(S,G)** : la
  réunion des plus courts chemins de la source S vers chaque membre de G ; un arbre par source ;
- l'**arbre partagé** (*RPT*), noté **(\\*,G)** : un seul arbre par groupe, enraciné en un
  routeur choisi, le **point de rendez-vous** (*RP*), vers lequel toutes les sources envoient.

Dans un routeur, une entrée (S,G) ou (\\*,G) a une **interface d'entrée** (iif) et une **liste
d'interfaces de sortie** (*OIL*, *outgoing interface list*).

### @@sec:modes@@ Mode dense et mode clairsemé

- **Mode dense** (DVMRP, PIM-DM) : le trafic est d'abord **inondé** partout, puis les branches
  sans membres sont **élaguées** (*prune*), et l'inondation recommence toutes les 3 minutes.
  Adapté à un réseau où presque tous les liens ont des membres.
- **Mode clairsemé** (PIM-SM, section @@ref:pimsm@@) : rien ne circule sans une **demande
  explicite** (*join*) remontée des membres. C'est le mode utilisé partout aujourd'hui.

### @@sec:mfc@@ Le plan de transfert du noyau

Le noyau Linux transmet le multicast grâce à son **MFC** (*multicast forwarding cache*) : des
entrées (S,G) ou (\\*,G) avec une interface d'entrée et des interfaces de sortie. Il ne les
calcule pas : **un seul démon** à la fois ouvre la socket de routage multicast et les y
installe. Ce peut être `pimd` de FRR (PIM), ou `smcrouted` pour du routage multicast
**statique** (`smcroutectl add eth0 SOURCE GROUPE eth1`).

```
ip mroute show                 # les entrées du MFC : (S,G) Iif ... Oifs ...
ip -s mroute show              # avec les compteurs de paquets
cat /proc/net/ip_mr_vif        # les interfaces virtuelles multicast
```
""": """
The aim of multicast routing is to bring the traffic of a group to every network where there
are members, to those only, and without loops.

### @@sec:rpf@@ The RPF check

A unicast router looks at the **destination** address of a packet. A multicast router first
looks at its **source**: it accepts a packet only if it arrives on the interface it would itself
use to **reach the source**, according to its unicast routing table. This is the **RPF** check
(*Reverse Path Forwarding*). That interface is the **RPF interface** (the **iif**), the next
router towards the source is the **RPF neighbour**. A packet that arrives on another interface
is discarded: this is what prevents loops and duplicates.

Consequence: **multicast depends on unicast routing**. A missing or asymmetric route to the
source, or a route through a link without multicast routing, is enough to block a stream
(section @@ref:diagnostic@@). On the shared tree (section @@ref:join@@), the check is made on
the address of the rendezvous point instead of the source.

### @@sec:trees@@ Distribution trees

- the **source tree**, or **shortest-path tree** (*SPT*), written **(S,G)**: the union of the
  shortest paths from source S to each member of G; one tree per source;
- the **shared tree** (*RPT*), written **(\\*,G)**: a single tree per group, rooted at a chosen
  router, the **rendezvous point** (*RP*), towards which all the sources send.

In a router, an (S,G) or (\\*,G) entry has an **incoming interface** (iif) and an **outgoing
interface list** (*OIL*).

### @@sec:modes@@ Dense mode and sparse mode

- **Dense mode** (DVMRP, PIM-DM): the traffic is first **flooded** everywhere, then the
  branches without members are **pruned**, and the flooding starts again every 3 minutes.
  Suited to a network where almost every link has members.
- **Sparse mode** (PIM-SM, section @@ref:pimsm@@): nothing flows without an **explicit
  request** (*join*) sent up from the members. This is the mode used everywhere today.

### @@sec:mfc@@ The forwarding plane of the kernel

The Linux kernel forwards multicast with its **MFC** (*multicast forwarding cache*): (S,G) or
(\\*,G) entries with an incoming interface and outgoing interfaces. It does not compute them:
**a single daemon** at a time opens the multicast routing socket and installs them there. It
can be FRR's `pimd` (PIM), or `smcrouted` for **static** multicast routing
(`smcroutectl add eth0 SOURCE GROUP eth1`).

```
ip mroute show                 # the MFC entries: (S,G) Iif ... Oifs ...
ip -s mroute show              # with the packet counters
cat /proc/net/ip_mr_vif        # the multicast virtual interfaces
```
""",
    "PIM-SM": "PIM-SM",
    """
**PIM** (*Protocol Independent Multicast* ; RFC 7761 pour PIM-SM) est « indépendant » parce
qu'il n'échange aucune route : il s'appuie sur la table de routage unicast existante, qu'elle
soit statique ou apprise par OSPF ou BGP, pour ses contrôles RPF. Ses messages sont portés par
IP (protocole **103**). Ils sont envoyés à **224.0.0.13** avec un TTL de 1, sauf *Register* et
*Register-Stop*, qui sont unicast.

### @@sec:hello@@ Voisins et routeur désigné

Chaque interface où PIM est actif émet un **Hello** toutes les **30 s** (validité 105 s) : les
routeurs d'un même lien deviennent **voisins PIM**. Un routeur n'accepte les messages *Join* que
d'un voisin.

Sur chaque réseau, un **routeur désigné** (**DR**) est élu : la plus grande priorité, puis la
plus grande adresse. Sur un réseau d'hôtes, c'est le DR qui transforme les rapports IGMP des
récepteurs en messages *Join* et qui enregistre les sources (*Register*).

### @@sec:rp@@ Le point de rendez-vous

Tous les routeurs du domaine doivent associer chaque groupe au **même RP**. Il y a plusieurs
façons de le leur apprendre :

- la configuration **statique** (`ip pim rp ADRESSE GROUPES` sur chaque routeur) ;
- **BSR** (*Bootstrap Router*, RFC 5059) : les candidats RP s'annoncent et un routeur élu
  diffuse la correspondance ;
- **Auto-RP** (propre à Cisco).

On choisit pour adresse du RP celle d'une **interface de bouclage** (*loopback*), joignable par
plusieurs chemins. Avec FRR, PIM doit être activé sur cette interface (`ip pim` sur `lo`). Pour
la redondance, plusieurs RP peuvent partager la même adresse : c'est l'**anycast RP**
(RFC 4610, ou MSDP entre eux, section @@ref:msdp@@).

### @@sec:join@@ L'arbre partagé : Join et Prune

1. Un récepteur rejoint G : le DR de son réseau (le *last-hop router*, **LHR**) crée l'entrée
   **(\\*,G)**, avec ce réseau dans l'OIL.
2. Il envoie un **Join (\\*,G)** à son voisin RPF **vers le RP**. Le voisin crée à son tour
   (\\*,G), avec dans son OIL l'interface par laquelle le *Join* est arrivé, et le transmet vers
   le RP. Le *Join* remonte ainsi de proche en proche jusqu'au RP.
3. Les *Join* sont répétés toutes les **60 s** (validité 210 s). Quand il n'y a plus de membres,
   le routeur envoie un **Prune** et la branche disparaît.

### @@sec:register@@ L'enregistrement des sources

Le RP ne connaît pas encore les sources :

1. Le DR du réseau de la source (le *first-hop router*, **FHR**) reçoit les premiers
   datagrammes. Il les **encapsule** dans des messages **Register** envoyés en **unicast** au
   RP.
2. Le RP les décapsule et les transmet sur l'arbre partagé : les récepteurs reçoivent déjà le
   flux.
3. Le RP envoie un **Join (S,G)** vers la source, pour recevoir le flux en natif.
4. Quand les datagrammes natifs arrivent, le RP envoie au FHR un **Register-Stop** : le FHR cesse
   d'encapsuler. Il le vérifie de temps en temps par un *Register* vide (*null register*).

### @@sec:spt@@ La bascule vers l'arbre des plus courts chemins

Le chemin qui passe par le RP n'est pas forcément le plus court. Dès qu'un LHR reçoit le premier
datagramme d'une source par l'arbre partagé, il envoie un **Join (S,G)** vers la **source**
(son voisin RPF vers S). Le flux arrive alors directement par l'**arbre de source** (SPT).
Le LHR envoie ensuite vers le RP un **Prune (S,G,rpt)** pour ne plus le recevoir aussi par
l'arbre partagé. Cette bascule est immédiate par défaut. Elle se règle avec
`ip pim spt-switchover infinity-and-beyond` pour rester sur l'arbre partagé.

Dans `show ip mroute` de FRR, les drapeaux résument l'état d'une entrée : **S** (*sparse*),
**C** (des membres connectés), **P** (élaguée), **R** (élaguée sur l'arbre partagé), **F**
(le routeur enregistre la source), **T** (le flux suit l'arbre de source). Une entrée (S,G)
d'un routeur sans trafic disparaît après le *keepalive timer* (210 s).

### @@sec:pimtimers@@ Les temporisateurs de PIM

| temporisateur | défaut |
|---------------|--------|
| *Hello* / validité d'un voisin | 30 s / 105 s |
| *Join/Prune* périodique / validité | 60 s / 210 s |
| *keepalive* d'une entrée (S,G) | 210 s |
| suppression des *Register* | 60 s |

Quand deux routeurs pourraient transmettre le même flux sur un même réseau, un message **Assert**
désigne le seul qui le fera : celui qui a la meilleure route vers la source, à égalité la plus
grande adresse.
""": """
**PIM** (*Protocol Independent Multicast*; RFC 7761 for PIM-SM) is "independent" because it
exchanges no routes: it relies on the existing unicast routing table, whether static or learnt
through OSPF or BGP, for its RPF checks. Its messages are carried by IP (protocol **103**).
They are sent to **224.0.0.13** with a TTL of 1, except *Register* and *Register-Stop*, which
are unicast.

### @@sec:hello@@ Neighbours and designated router

Each interface where PIM is enabled sends a **Hello** every **30 s** (holdtime 105 s): the
routers of a same link become **PIM neighbours**. A router accepts *Join* messages only from a
neighbour.

On each network, a **designated router** (**DR**) is elected: the highest priority, then the
highest address. On a host network, the DR is the one that turns the IGMP reports of the
receivers into *Join* messages and registers the sources (*Register*).

### @@sec:rp@@ The rendezvous point

All the routers of the domain must map each group to the **same RP**. There are several ways
of teaching them:

- **static** configuration (`ip pim rp ADDRESS GROUPS` on every router);
- **BSR** (*Bootstrap Router*, RFC 5059): the candidate RPs announce themselves and an elected
  router distributes the mapping;
- **Auto-RP** (Cisco-specific).

The address chosen for the RP is that of a **loopback interface**, reachable through several
paths. With FRR, PIM must be enabled on that interface (`ip pim` on `lo`). For redundancy,
several RPs can share the same address: this is **anycast RP** (RFC 4610, or MSDP between
them, section @@ref:msdp@@).

### @@sec:join@@ The shared tree: Join and Prune

1. A receiver joins G: the DR of its network (the *last-hop router*, **LHR**) creates the
   **(\\*,G)** entry, with that network in the OIL.
2. It sends a **Join (\\*,G)** to its RPF neighbour **towards the RP**. The neighbour in turn
   creates (\\*,G), with in its OIL the interface on which the *Join* arrived, and passes it on
   towards the RP. The *Join* thus travels hop by hop up to the RP.
3. *Joins* are repeated every **60 s** (holdtime 210 s). When there are no members left, the
   router sends a **Prune** and the branch disappears.

### @@sec:register@@ Registering the sources

The RP does not know the sources yet:

1. The DR of the network of the source (the *first-hop router*, **FHR**) receives the first
   datagrams. It **encapsulates** them in **Register** messages sent in **unicast** to the
   RP.
2. The RP decapsulates them and forwards them on the shared tree: the receivers already get
   the stream.
3. The RP sends a **Join (S,G)** towards the source, to receive the stream natively.
4. When the native datagrams arrive, the RP sends the FHR a **Register-Stop**: the FHR stops
   encapsulating. It checks this from time to time with an empty *Register* (*null register*).

### @@sec:spt@@ Switching over to the shortest-path tree

The path through the RP is not necessarily the shortest. As soon as an LHR receives the first
datagram of a source through the shared tree, it sends a **Join (S,G)** towards the **source**
(its RPF neighbour towards S). The stream then arrives directly through the **source tree**
(SPT). The LHR then sends a **Prune (S,G,rpt)** towards the RP so as not to receive it through
the shared tree as well. This switchover is immediate by default. It can be changed with
`ip pim spt-switchover infinity-and-beyond`, to stay on the shared tree.

In FRR's `show ip mroute`, the flags sum up the state of an entry: **S** (*sparse*),
**C** (connected members), **P** (pruned), **R** (pruned on the shared tree), **F**
(the router registers the source), **T** (the stream follows the source tree). An (S,G) entry
of a router without traffic disappears after the *keepalive timer* (210 s).

### @@sec:pimtimers@@ PIM timers

| timer | default |
|---------------|--------|
| *Hello* / holdtime of a neighbour | 30 s / 105 s |
| periodic *Join/Prune* / holdtime | 60 s / 210 s |
| *keepalive* of an (S,G) entry | 210 s |
| *Register* suppression | 60 s |

When two routers could forward the same stream onto the same network, an **Assert** message
designates the only one that will: the one with the best route to the source, the highest
address on a tie.
""",
    "PIM-SSM et IGMPv3": "PIM-SSM and IGMPv3",
    """
En **SSM** (RFC 4607), le récepteur connaît la source qu'il veut écouter et s'abonne au canal
**(S,G)**, avec un rapport IGMPv3 `INCLUDE` {S} (ou MLDv2 en IPv6). Il n'y a alors **ni RP, ni
Register, ni arbre partagé** : le LHR envoie directement un **Join (S,G)** vers la source, et le
flux suit le plus court chemin dès le premier datagramme.

- Le bloc réservé au SSM est **232.0.0.0/8** (**`ff3x::/32`** en IPv6). On peut déclarer d'autres
  groupes SSM, mais **tous les routeurs du domaine** doivent avoir la même liste
  (`ip pim ssm prefix-list LISTE` dans FRR ; la liste remplace alors le bloc par défaut).
- Dans la plage SSM, les routeurs ignorent les *Join* (\\*,G) et les adhésions sans source, comme
  les rapports IGMPv2 : **les récepteurs doivent parler IGMPv3**, avec une application qui sait
  demander une source (`iperf -H`, section @@ref:tools@@).
- Deux sources qui émettent vers le même groupe forment deux canaux distincts. Un récepteur
  abonné à (S1,G) ne reçoit que S1 : le trafic de S2 n'est même pas transmis, faute de *Join*
  (S2,G).

Le SSM est plus simple, plus robuste (pas de RP, qui serait un point unique de défaillance) et
plus sûr (personne ne peut injecter du trafic dans un canal). Il ne convient pas aux applications
où les sources ne sont pas connues d'avance (visioconférence à plusieurs, découverte de services).
""": """
In **SSM** (RFC 4607), the receiver knows the source it wants to listen to and subscribes to
the channel **(S,G)**, with an IGMPv3 `INCLUDE` {S} report (or MLDv2 in IPv6). There is then
**no RP, no Register and no shared tree**: the LHR sends a **Join (S,G)** directly towards the
source, and the stream follows the shortest path from the first datagram.

- The block reserved for SSM is **232.0.0.0/8** (**`ff3x::/32`** in IPv6). Other SSM groups
  can be declared, but **all the routers of the domain** must have the same list
  (`ip pim ssm prefix-list LIST` in FRR; the list then replaces the default block).
- In the SSM range, routers ignore (\\*,G) *Joins* and memberships without a source, as well as
  IGMPv2 reports: **the receivers must speak IGMPv3**, with an application that can ask for a
  source (`iperf -H`, section @@ref:tools@@).
- Two sources sending to the same group form two distinct channels. A receiver subscribed to
  (S1,G) receives only S1: the traffic of S2 is not even forwarded, for lack of a *Join*
  (S2,G).

SSM is simpler, more robust (no RP, which would be a single point of failure) and safer
(nobody can inject traffic into a channel). It does not suit applications where the sources
are not known in advance (multi-party video conferencing, service discovery).
""",
    "Entre domaines : MSDP et portée des groupes": "Between domains: MSDP and the scope of groups",
    """
Chaque domaine (un opérateur, une université) a ses propres RP. Le RP d'un domaine ignore les
sources des autres domaines, puisqu'elles s'enregistrent auprès de leur propre RP.

**MSDP** (*Multicast Source Discovery Protocol*, RFC 3618) relie les RP de domaines différents
par des sessions **TCP** sur le port **639** :

1. Quand un RP apprend une source de son domaine (par un *Register*), il envoie à ses pairs MSDP
   un message **SA** (*Source-Active*) : la source S, le groupe G et l'adresse du RP d'origine.
2. Les pairs propagent les SA de proche en proche, avec un contrôle de type RPF sur le RP
   d'origine pour éviter les boucles, et les gardent en cache. Le SA est répété toutes les
   60 s tant que la source émet.
3. Un RP qui a des récepteurs pour G (une entrée (\\*,G)) envoie un **Join (S,G)** vers la source,
   à travers la frontière : le flux arrive par l'arbre de source inter-domaines. Il faut donc
   que PIM tourne sur les liens entre domaines et que les routes vers les sources soient
   connues.

Avec FRR :

- `ip msdp peer ADRESSE_DU_PAIR source ADRESSE_LOCALE` déclare une session, configurée des deux
  côtés, entre les adresses de bouclage des RP ;
- `show ip msdp peer` affiche l'état des sessions (`established` une fois la connexion faite) ;
- `show ip msdp sa` affiche le cache des SA.

Le pair de plus petite adresse ouvre la connexion TCP : comptez jusqu'à une trentaine de
secondes avant que la session soit établie.

Une particularité de FRR (versions 9 et 10) : un SA porte l'adresse du RP qui l'a émis. Pour le premier SA d'une
nouvelle source, c'est le RP du groupe. Pour les SA répétés toutes les 60 s, c'est le RP de
**224.0.0.0/4** tout entier, ou 0.0.0.0 si aucun RP ne couvre toute la plage, et le pair rejette
alors ces SA. Un RP MSDP de FRR doit donc servir `224.0.0.0/4` (`ip pim rp ADRESSE`, sans plage).

### @@sec:scoping@@ Limiter la portée d'un groupe

Certains groupes ne doivent pas sortir d'un domaine. Il y a deux façons de les y retenir :

- la **portée par le TTL** (*TTL scoping*), ancienne : une application émet avec un TTL faible,
  et les routeurs de bordure refusent les paquets sous un seuil. Elle est imprécise ;
- la **portée administrative** (RFC 2365) : les groupes de `239.0.0.0/8` sont réservés à un
  domaine (`239.255.0.0/16` à un site, `239.192.0.0/14` à une organisation), et les routeurs de
  bordure posent une **frontière** (*boundary*) qui les bloque.

Avec FRR, `ip multicast boundary oil LISTE` sur l'interface de bordure fait ignorer les *Join* et
les rapports IGMP qui y arrivent pour les groupes **refusés** (`deny`) par la liste de préfixes
(`ip prefix-list`) : l'interface n'entre jamais dans l'OIL de ces groupes. La frontière se pose
sur le routeur qui **émettrait** le trafic vers l'extérieur, du côté où arrivent les *Join*.
Les SA de ces groupes, eux, traversent encore la session MSDP, à moins de les filtrer aussi
(`msdp peer ADRESSE sa-filter LISTE in` ou `out`, dans le bloc `router pim`, où `LISTE` est une
`access-list`).

En IPv6, la portée est inscrite dans l'adresse (section @@ref:ipv6addr@@) : les routeurs ne
transmettent pas un groupe au-delà de sa portée.
""": """
Each domain (an operator, a university) has its own RPs. The RP of a domain does not know the
sources of the other domains, since they register with their own RP.

**MSDP** (*Multicast Source Discovery Protocol*, RFC 3618) links the RPs of different domains
through **TCP** sessions on port **639**:

1. When an RP learns of a source of its domain (through a *Register*), it sends its MSDP peers
   an **SA** (*Source-Active*) message: the source S, the group G and the address of the
   originating RP.
2. The peers propagate the SAs hop by hop, with an RPF-like check on the originating RP to
   avoid loops, and keep them in a cache. The SA is repeated every 60 s as long as the source
   sends.
3. An RP that has receivers for G (a (\\*,G) entry) sends a **Join (S,G)** towards the source,
   across the border: the stream arrives through the inter-domain source tree. PIM must
   therefore run on the links between domains, and the routes to the sources must be
   known.

With FRR:

- `ip msdp peer PEER_ADDRESS source LOCAL_ADDRESS` declares a session, configured on both
  sides, between the loopback addresses of the RPs;
- `show ip msdp peer` shows the state of the sessions (`established` once the connection is
  made);
- `show ip msdp sa` shows the SA cache.

The peer with the lower address opens the TCP connection: allow up to about thirty seconds
before the session is established.

A peculiarity of FRR (versions 9 and 10): an SA carries the address of the RP that sent it. For the first SA of a
new source, it is the RP of the group. For the SAs repeated every 60 s, it is the RP of the
whole of **224.0.0.0/4**, or 0.0.0.0 if no RP covers the whole range, and the peer then
rejects those SAs. An FRR MSDP RP must therefore serve `224.0.0.0/4` (`ip pim rp ADDRESS`,
without a range).

### @@sec:scoping@@ Limiting the scope of a group

Some groups must not leave a domain. There are two ways of keeping them inside:

- **TTL scoping**, the old way: an application sends with a low TTL, and the border routers
  refuse packets below a threshold. It is imprecise;
- **administrative scoping** (RFC 2365): the groups of `239.0.0.0/8` are reserved for a
  domain (`239.255.0.0/16` for a site, `239.192.0.0/14` for an organisation), and the border
  routers set up a **boundary** that blocks them.

With FRR, `ip multicast boundary oil LIST` on the border interface makes the router ignore the
*Joins* and IGMP reports arriving there for the groups **denied** (`deny`) by the prefix list
(`ip prefix-list`): the interface never enters the OIL of those groups. The boundary is placed
on the router that **would send** the traffic outwards, on the side where the *Joins* arrive.
The SAs of those groups, however, still cross the MSDP session, unless they are filtered too
(`msdp peer ADDRESS sa-filter LIST in` or `out`, in the `router pim` block, where `LIST` is an
`access-list`).

In IPv6, the scope is written in the address (section @@ref:ipv6addr@@): routers do not
forward a group beyond its scope.
""",
    "Le multicast IPv6 : MLD et PIMv6": "IPv6 multicast: MLD and PIMv6",
    """
**MLD** (*Multicast Listener Discovery*) est l'IGMP d'IPv6, porté par ICMPv6 (limite de sauts 1,
adresse source lien local, option Router Alert) :

| IPv4 | IPv6 | rapports envoyés à |
|------|------|--------------------|
| IGMPv2 | **MLDv1** (RFC 2710) | l'adresse du groupe ; départ (*Done*) vers `ff02::2` |
| IGMPv3 | **MLDv2** (RFC 3810) | **`ff02::16`** |

Le querier MLD est le routeur de plus petite adresse. Un lien IPv6 compte toujours beaucoup de
groupes, puisque chaque adresse unicast fait rejoindre son groupe *solicited-node* (section
@@ref:ipv6addr@@).

**PIMv6** est le même protocole que PIM, transporté par IPv6. Les *Hello* partent des adresses
lien local vers `ff02::d`, si bien que les voisins PIMv6 apparaissent sous leur adresse
`fe80::…`. Les contrôles RPF utilisent la table de routage IPv6. Le bloc SSM est `ff3x::/32`
(`ff3e::/32` en portée globale).

Avec FRR, PIMv6 est assuré par un démon à part, **`pim6d`**, à activer dans `/etc/frr/daemons`.
Les commandes reprennent celles d'IPv4 :

- configuration : `ipv6 pim` et `ipv6 mld` sur une interface ;
- vérification : `show ipv6 pim neighbor`, `show ipv6 mld interface`, `show ipv6 mld groups`,
  `show ipv6 mld joins`, `show ipv6 mroute`.
""": """
**MLD** (*Multicast Listener Discovery*) is the IGMP of IPv6, carried by ICMPv6 (hop limit 1,
link-local source address, Router Alert option):

| IPv4 | IPv6 | reports sent to |
|------|------|--------------------|
| IGMPv2 | **MLDv1** (RFC 2710) | the group address; leave (*Done*) to `ff02::2` |
| IGMPv3 | **MLDv2** (RFC 3810) | **`ff02::16`** |

The MLD querier is the router with the lowest address. An IPv6 link always has many groups,
since each unicast address makes the interface join its *solicited-node* group (section
@@ref:ipv6addr@@).

**PIMv6** is the same protocol as PIM, carried by IPv6. The *Hellos* leave from the link-local
addresses to `ff02::d`, so PIMv6 neighbours appear under their `fe80::…` address. The RPF
checks use the IPv6 routing table. The SSM block is `ff3x::/32` (`ff3e::/32` with global
scope).

With FRR, PIMv6 is handled by a separate daemon, **`pim6d`**, to be enabled in
`/etc/frr/daemons`. The commands follow those of IPv4:

- configuration: `ipv6 pim` and `ipv6 mld` on an interface;
- checks: `show ipv6 pim neighbor`, `show ipv6 mld interface`, `show ipv6 mld groups`,
  `show ipv6 mld joins`, `show ipv6 mroute`.
""",
    "PIM, IGMP et MSDP avec FRR": "PIM, IGMP and MSDP with FRR",
    """
Le démon **`pimd`** de FRR fait PIM-SM, PIM-SSM, IGMP (v2 et v3) et MSDP ; `pim6d` fait PIMv6 et
MLD. Ils sont activés dans `/etc/frr/daemons` et se configurent dans `vtysh`, comme les autres
démons de FRR. N'oubliez pas `write` pour enregistrer la configuration dans
`/etc/frr/frr.conf`.

```
configure terminal
 ip pim rp 10.9.9.9 239.0.0.0/8         ! le RP (statique) des groupes 239.0.0.0/8
 ip prefix-list SSM seq 5 permit 232.0.0.0/8 le 32
 ip pim ssm prefix-list SSM              ! la plage SSM (232.0.0.0/8 sans cette commande)
 ip pim spt-switchover infinity-and-beyond   ! rester sur l'arbre partagé
 ip msdp peer 10.8.8.8 source 10.9.9.9   ! une session MSDP
 interface eth0
  ip pim                                 ! PIM sur l'interface (Hello, Join...)
  ip igmp                                ! IGMP : l'interface dessert des récepteurs
  ip igmp version 3                      ! (3 par défaut)
  ip igmp query-interval 60              ! en secondes (125 par défaut)
  ip igmp last-member-query-interval 10  ! en dixièmes de seconde
  ip igmp join 239.1.1.1                 ! le routeur rejoint lui-même un groupe
  ip multicast boundary oil LISTE        ! frontière de portée administrative
 exit
 interface lo
  ip pim                                 ! sur le RP : l'interface qui porte son adresse
 exit
end
write
```

Depuis FRR 10, les réglages globaux de PIM (`rp`, `ssm`, `spt-switchover`, `msdp peer`…)
appartiennent à un bloc `router pim`, et c'est là que `show running-config` les range :

```
router pim
 rp 10.9.9.9 239.0.0.0/8
 msdp peer 10.8.8.8 source 10.9.9.9
exit
```

Les commandes `ip pim …` et `ip msdp …` du premier niveau, celles de FRR 9 et des documentations
plus anciennes, restent acceptées : FRR les range lui-même dans ce bloc.

| commande | affiche |
|----------|---------|
| `show ip pim interface` | les interfaces PIM, leur nombre de voisins, le DR |
| `show ip pim neighbor` | les voisins PIM |
| `show ip pim rp-info` | le RP de chaque plage de groupes, l'interface RPF vers lui (OIF) |
| `show ip pim group-type A.B.C.D` | ASM ou SSM pour ce groupe |
| `show ip pim upstream` | les entrées (S,G) et (\\*,G), leur état (*Joined*...), le voisin RPF |
| `show ip mroute` | la table multicast : source, groupe, drapeaux, iif, interfaces de sortie |
| `show ip igmp interface [detail]` | IGMP par interface : version, querier, temporisateurs |
| `show ip igmp groups` / `sources` | les groupes (et les sources) appris par IGMP |
| `show ip msdp peer` / `sa` | les sessions MSDP, le cache des SA |

Toutes ces commandes acceptent le suffixe `json`. `clear ip mroute` vide la table multicast.
`clear ip pim interfaces` relance PIM sur les interfaces. Le routeur oublie alors ses voisins
jusqu'à leur prochain *Hello* : ce n'est pas un moyen d'aller plus vite.
""": """
FRR's **`pimd`** daemon does PIM-SM, PIM-SSM, IGMP (v2 and v3) and MSDP; `pim6d` does PIMv6
and MLD. They are enabled in `/etc/frr/daemons` and configured in `vtysh`, like the other FRR
daemons. Do not forget `write` to save the configuration in `/etc/frr/frr.conf`.

```
configure terminal
 ip pim rp 10.9.9.9 239.0.0.0/8         ! the (static) RP of the groups 239.0.0.0/8
 ip prefix-list SSM seq 5 permit 232.0.0.0/8 le 32
 ip pim ssm prefix-list SSM              ! the SSM range (232.0.0.0/8 without this command)
 ip pim spt-switchover infinity-and-beyond   ! stay on the shared tree
 ip msdp peer 10.8.8.8 source 10.9.9.9   ! an MSDP session
 interface eth0
  ip pim                                 ! PIM on the interface (Hello, Join...)
  ip igmp                                ! IGMP: the interface serves receivers
  ip igmp version 3                      ! (3 by default)
  ip igmp query-interval 60              ! in seconds (125 by default)
  ip igmp last-member-query-interval 10  ! in tenths of a second
  ip igmp join 239.1.1.1                 ! the router itself joins a group
  ip multicast boundary oil LIST         ! administrative scope boundary
 exit
 interface lo
  ip pim                                 ! on the RP: the interface that carries its address
 exit
end
write
```

Since FRR 10, the global PIM settings (`rp`, `ssm`, `spt-switchover`, `msdp peer`…) belong to
a `router pim` block, and that is where `show running-config` puts them:

```
router pim
 rp 10.9.9.9 239.0.0.0/8
 msdp peer 10.8.8.8 source 10.9.9.9
exit
```

The top-level `ip pim …` and `ip msdp …` commands, those of FRR 9 and of older documentation,
are still accepted: FRR moves them into that block itself.

| command | shows |
|----------|---------|
| `show ip pim interface` | the PIM interfaces, their number of neighbours, the DR |
| `show ip pim neighbor` | the PIM neighbours |
| `show ip pim rp-info` | the RP of each group range, the RPF interface towards it (OIF) |
| `show ip pim group-type A.B.C.D` | ASM or SSM for that group |
| `show ip pim upstream` | the (S,G) and (\\*,G) entries, their state (*Joined*...), the RPF neighbour |
| `show ip mroute` | the multicast table: source, group, flags, iif, outgoing interfaces |
| `show ip igmp interface [detail]` | IGMP per interface: version, querier, timers |
| `show ip igmp groups` / `sources` | the groups (and the sources) learnt through IGMP |
| `show ip msdp peer` / `sa` | the MSDP sessions, the SA cache |

All these commands accept the `json` suffix. `clear ip mroute` empties the multicast table.
`clear ip pim interfaces` restarts PIM on the interfaces. The router then forgets its
neighbours until their next *Hello*: it is not a way of going faster.
""",
    "Les outils": "Tools",
    """
- **iperf** (la version 2 ; `iperf3` ne fait pas de multicast) :
  - récepteur : `iperf -s -u -B 239.1.1.1 -i 1` rejoint le groupe et affiche chaque seconde ce
    qu'il reçoit ;
  - récepteur SSM : `iperf -s -u -B 232.1.1.1 -H 10.0.0.1 -i 1` s'abonne au canal de la source
    10.0.0.1 ;
  - source : `iperf -c 239.1.1.1 -u -T 16 -t 10 -b 100K` émet pendant 10 s avec un TTL de 16
    (**1 sans `-T`**) ; `-p` change le port (5001 par défaut).
- **ssmping** : `ssmpingd` sur la machine source ; `ssmping SOURCE` sur un récepteur vérifie
  que le canal SSM de la source arrive ; `asmping GROUPE SOURCE` fait de même en ASM.
- **smcroute** : `smcrouted` (le démon), puis `smcroutectl join eth0 239.1.1.1` fait rejoindre un
  groupe sans application. Ses routes statiques (`smcroutectl add …`) ne cohabitent pas avec
  `pimd`, qui tient déjà la table multicast du noyau.
- **tcpdump** : `tcpdump -ni eth0 -v igmp` (versions, enregistrements, option Router Alert),
  `tcpdump -ni eth1 pim`, `tcpdump -ni eth0 ip multicast and udp`, `tcpdump -ni eth0 -e`
  pour les adresses MAC.
- Le noyau : `ip maddr`, `cat /proc/net/igmp`, `ip mroute`, `ip -s mroute` (section
  @@ref:host@@ et @@ref:mfc@@).
""": """
- **iperf** (version 2; `iperf3` does not do multicast):
  - receiver: `iperf -s -u -B 239.1.1.1 -i 1` joins the group and shows every second what it
    receives;
  - SSM receiver: `iperf -s -u -B 232.1.1.1 -H 10.0.0.1 -i 1` subscribes to the channel of the
    source 10.0.0.1;
  - source: `iperf -c 239.1.1.1 -u -T 16 -t 10 -b 100K` sends for 10 s with a TTL of 16
    (**1 without `-T`**); `-p` changes the port (5001 by default).
- **ssmping**: `ssmpingd` on the source machine; `ssmping SOURCE` on a receiver checks that
  the SSM channel of the source arrives; `asmping GROUP SOURCE` does the same in ASM.
- **smcroute**: `smcrouted` (the daemon), then `smcroutectl join eth0 239.1.1.1` joins a group
  without an application. Its static routes (`smcroutectl add …`) cannot coexist with `pimd`,
  which already holds the multicast table of the kernel.
- **tcpdump**: `tcpdump -ni eth0 -v igmp` (versions, records, Router Alert option),
  `tcpdump -ni eth1 pim`, `tcpdump -ni eth0 ip multicast and udp`, `tcpdump -ni eth0 -e`
  for the MAC addresses.
- The kernel: `ip maddr`, `cat /proc/net/igmp`, `ip mroute`, `ip -s mroute` (sections
  @@ref:host@@ and @@ref:mfc@@).
""",
    "Méthode de diagnostic": "Troubleshooting method",
    """
Un flux multicast qui n'arrive pas se diagnostique **du récepteur vers la source**, routeur par
routeur, en suivant les interfaces RPF :

1. **Le récepteur** a-t-il rejoint le groupe ? (`ip maddr`, `tcpdump igmp` : le rapport part-il ?)
2. **Le LHR** connaît-il le groupe ? (`show ip igmp groups`) A-t-il une entrée (\\*,G) ou (S,G) ?
   (`show ip pim upstream`, `show ip mroute`)
3. Chaque routeur vers le RP ou la source a-t-il un **voisin PIM** sur son interface RPF ? (`show
   ip pim neighbor`, `show ip pim rp-info`, `ip route get SOURCE`)
4. **Le FHR** voit-il la source ? A-t-il une entrée (S,G) avec le drapeau F ?
5. **La source** émet-elle, avec un TTL suffisant, et par la bonne interface ? (`tcpdump` sur le
   réseau de la source)

| symptôme | causes fréquentes |
|----------|-------------------|
| rien n'arrive, même pas sur le réseau de la source | pas de route vers 224.0.0.0/4 sur la source, mauvais groupe ou mauvais port |
| le flux s'arrête au premier routeur | TTL de 1 (le défaut des sockets multicast), PIM absent sur l'interface du réseau de la source |
| pas de voisin PIM sur un lien | `ip pim` oublié d'un côté, filtrage du protocole 103 ou de 224.0.0.13 |
| (\\*,G) sur le LHR mais rien en amont | pas de RP pour ce groupe, RP différent selon les routeurs, RP injoignable, interface RPF vers le RP sans PIM |
| le LHR ne voit pas le groupe | IGMP absent sur l'interface des récepteurs, rapport IGMPv2 pour un groupe SSM |
| quelques datagrammes passent, puis plus rien | bascule vers l'arbre de source impossible : l'interface RPF vers la source n'a pas de voisin PIM |
| un commutateur inonde tout | snooping inactif, ou pas de querier sur le réseau |
| un groupe sort de son domaine | frontière absente ou mal placée, liste de préfixes qui l'autorise |
| la session MSDP reste en `listen` ou `connecting` | adresse source de la session, route vers le pair, TCP 639 filtré |
""": """
A multicast stream that does not arrive is diagnosed **from the receiver towards the source**,
router by router, following the RPF interfaces:

1. Has **the receiver** joined the group? (`ip maddr`, `tcpdump igmp`: does the report go out?)
2. Does **the LHR** know the group? (`show ip igmp groups`) Does it have a (\\*,G) or (S,G)
   entry? (`show ip pim upstream`, `show ip mroute`)
3. Does each router towards the RP or the source have a **PIM neighbour** on its RPF
   interface? (`show ip pim neighbor`, `show ip pim rp-info`, `ip route get SOURCE`)
4. Does **the FHR** see the source? Does it have an (S,G) entry with the F flag?
5. Does **the source** send, with a sufficient TTL, and through the right interface?
   (`tcpdump` on the network of the source)

| symptom | frequent causes |
|----------|-------------------|
| nothing arrives, not even on the network of the source | no route to 224.0.0.0/4 on the source, wrong group or wrong port |
| the stream stops at the first router | TTL of 1 (the default of multicast sockets), no PIM on the interface of the network of the source |
| no PIM neighbour on a link | `ip pim` forgotten on one side, protocol 103 or 224.0.0.13 filtered |
| (\\*,G) on the LHR but nothing upstream | no RP for that group, RP differing between routers, RP unreachable, RPF interface towards the RP without PIM |
| the LHR does not see the group | no IGMP on the interface of the receivers, IGMPv2 report for an SSM group |
| a few datagrams get through, then nothing | the switchover to the source tree fails: the RPF interface towards the source has no PIM neighbour |
| a switch floods everything | snooping off, or no querier on the network |
| a group leaves its domain | boundary missing or misplaced, prefix list that permits it |
| the MSDP session stays in `listen` or `connecting` | source address of the session, route to the peer, TCP 639 filtered |
""",
    "Partie 1 : réponses du formulaire": "Part 1: form answers",
    "Partie 2 : solution (IGMP)": "Part 2: solution (IGMP)",
    "Partie 3 : solution (IGMP snooping)": "Part 3: solution (IGMP snooping)",
    "Partie 4 : solution (PIM-SM)": "Part 4: solution (PIM-SM)",
    "Partie 5 : solution (PIM-SSM)": "Part 5: solution (PIM-SSM)",
    "Partie 6 : solution (MSDP)": "Part 6: solution (MSDP)",
    "Partie 7 : solution (dépannage)": "Part 7: solution (troubleshooting)",
    "Partie 8 : solution (IPv6, bonus)": "Part 8: solution (IPv6, bonus)",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente le multicast IP (adresses, IGMP, snooping, routage
multicast, PIM-SM, PIM-SSM, MSDP, IPv6), sa configuration avec FRR et les outils de test.

**Le réseau.** Il est fait de **sept sites indépendants**, un par partie (la partie 1 se fait
sans machine). Chaque site a sa couleur sur le schéma :

| partie | site | machines |
|--------|------|----------|
| 2 — IGMP | `igmp_*` | les routeurs `igmp_r1` et `igmp_r2`, les hôtes `igmp_h1` et `igmp_h2`, sur un même réseau |
| 3 — IGMP snooping | `snoop_*` | le commutateur `snoop_sw` (un pont Linux `br0`), la source `snoop_src`, les hôtes `snoop_h1` et `snoop_h2` |
| 4 — PIM-SM | `asm_*` | la source `asm_src`, les routeurs `asm_r1`, `asm_r2` (le RP), `asm_r3`, le récepteur `asm_h` |
| 5 — PIM-SSM | `ssm_*` | la source `ssm_src` (deux adresses), les routeurs `ssm_r1` et `ssm_r2`, le récepteur `ssm_h` |
| 6 — MSDP | `msdp_*` | la source `msdp_src` et le routeur `msdp_r1` (domaine 1), le routeur `msdp_r2` et le récepteur `msdp_h` (domaine 2) |
| 7 — dépannage | `fix_*` | la source `fix_src`, les routeurs `fix_r1` et `fix_r2` (deux liens entre eux), le récepteur `fix_h` |
| 8 — IPv6 (bonus) | `v6_*` | la source `v6_src`, les routeurs `v6_r1` et `v6_r2`, le récepteur `v6_h` |

- Les routeurs font tourner **FRRouting** (FRR) avec le démon `pimd` (et `pim6d` sur le site
  IPv6) : configurez-les avec `vtysh`.
- Toutes les adresses sont configurées, de même que le **routage unicast** (routes statiques de
  FRR, visibles dans `show running-config`) : vous ne vous occupez que du multicast.
- Les fichiers `/etc/hosts` contiennent les noms des interfaces : `asm_r3-eth1` désigne
  l'adresse de l'interface `eth1` de `asm_r3`, `asm_r2-lo` l'adresse de bouclage de `asm_r2`.
- Les machines disposent d'`iperf` (version 2), de `ssmping` / `asmping`, de `smcroute` et de
  `tcpdump` (section @@ref:tools@@).

**Plan d'adressage.** Le troisième octet d'un préfixe IPv4 rappelle le site (10 : igmp, 20 :
snoop, 3x : asm, 4x : ssm, 5x : msdp, 7x : fix, 99 : les adresses de bouclage).

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- intervalle des requêtes IGMP de `igmp_r1` (partie 2) : **{query_interval} s** ;
- groupes pour vos propres essais : `{igmp_group}` (partie 2), `{snoop_group}` (partie 3),
  `{asm_group}` (partie 4), `{ssm_group}` (partie 5), `{msdp_group}` et, de portée
  organisation, `{scoped_group}` (partie 6), `{fix_group}` (partie 7), `{v6_group}` (partie 8) ;
- adresse du RP du site `asm` : `{asm_rp}` ; RP des domaines du site `msdp` : `{msdp_rp1}`
  (domaine 1) et `{msdp_rp2}` (domaine 2) ; RP du site `fix` : `{fix_rp}` ;
- plage de groupes des RP des sites `asm` et `fix` : `{rp_range}` (ceux du site `msdp` servent
  tout `{msdp_rp_range}`) ; plage SSM ajoutée à la partie 5 : `{ssm_extra}` ;
  plage de portée organisation, arrêtée à la frontière à la partie 6 : `{scoped_range}`.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie
  terminée rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration des routeurs (`write` dans `vtysh`).
- PIM n'est pas instantané : un voisin n'est connu qu'à son premier *Hello* (toutes les 30 s), un
  *Join* perdu n'est répété qu'au bout de 60 s, une session MSDP met une trentaine de secondes
  à s'établir. Après une modification, attendez une minute avant de conclure qu'elle ne marche
  pas.

**Évaluation.** Chaque évaluation lit vos réponses et la configuration des routeurs. Elle
**fait passer de vrais flux** : des récepteurs démarrés sur les hôtes rejoignent des groupes,
puis chaque source émet une vingtaine de datagrammes, et l'évaluation regarde ce qui est arrivé
et par où. Ces flux utilisent leurs propres groupes (tous dans les plages ci-dessus) et le port
UDP {port} ; ils ne gênent pas vos essais. Une évaluation dure une quinzaine de secondes.
""": """
Read the **Informations** tab: it presents IP multicast (addresses, IGMP, snooping, multicast
routing, PIM-SM, PIM-SSM, MSDP, IPv6), its configuration with FRR and the test tools.

**The network.** It is made of **seven independent sites**, one per part (part 1 is done
without any machine). Each site has its own colour on the diagram:

| part | site | machines |
|--------|------|----------|
| 2 — IGMP | `igmp_*` | the routers `igmp_r1` and `igmp_r2`, the hosts `igmp_h1` and `igmp_h2`, on a single network |
| 3 — IGMP snooping | `snoop_*` | the switch `snoop_sw` (a Linux bridge `br0`), the source `snoop_src`, the hosts `snoop_h1` and `snoop_h2` |
| 4 — PIM-SM | `asm_*` | the source `asm_src`, the routers `asm_r1`, `asm_r2` (the RP), `asm_r3`, the receiver `asm_h` |
| 5 — PIM-SSM | `ssm_*` | the source `ssm_src` (two addresses), the routers `ssm_r1` and `ssm_r2`, the receiver `ssm_h` |
| 6 — MSDP | `msdp_*` | the source `msdp_src` and the router `msdp_r1` (domain 1), the router `msdp_r2` and the receiver `msdp_h` (domain 2) |
| 7 — troubleshooting | `fix_*` | the source `fix_src`, the routers `fix_r1` and `fix_r2` (two links between them), the receiver `fix_h` |
| 8 — IPv6 (bonus) | `v6_*` | the source `v6_src`, the routers `v6_r1` and `v6_r2`, the receiver `v6_h` |

- The routers run **FRRouting** (FRR) with the `pimd` daemon (and `pim6d` on the IPv6
  site): configure them with `vtysh`.
- All the addresses are configured, and so is **unicast routing** (FRR static routes, visible
  in `show running-config`): you only deal with multicast.
- The `/etc/hosts` files contain the names of the interfaces: `asm_r3-eth1` designates the
  address of the `eth1` interface of `asm_r3`, `asm_r2-lo` the loopback address of `asm_r2`.
- The machines have `iperf` (version 2), `ssmping` / `asmping`, `smcroute` and `tcpdump`
  (section @@ref:tools@@).

**Addressing plan.** The third byte of an IPv4 prefix recalls the site (10: igmp, 20:
snoop, 3x: asm, 4x: ssm, 5x: msdp, 7x: fix, 99: the loopback addresses).

| network | prefix | interfaces |
|--------|---------|------------|
{addressing}

**Values specific to your instance.**

- IGMP query interval of `igmp_r1` (part 2): **{query_interval} s**;
- groups for your own experiments: `{igmp_group}` (part 2), `{snoop_group}` (part 3),
  `{asm_group}` (part 4), `{ssm_group}` (part 5), `{msdp_group}` and, with organisation
  scope, `{scoped_group}` (part 6), `{fix_group}` (part 7), `{v6_group}` (part 8);
- address of the RP of the `asm` site: `{asm_rp}`; RPs of the domains of the `msdp` site:
  `{msdp_rp1}` (domain 1) and `{msdp_rp2}` (domain 2); RP of the `fix` site: `{fix_rp}`;
- group range of the RPs of the `asm` and `fix` sites: `{rp_range}` (those of the `msdp` site
  serve the whole of `{msdp_rp_range}`); SSM range added in part 5: `{ssm_extra}`;
  organisation-scope range, stopped at the boundary in part 6: `{scoped_range}`.

**Instructions.**

- The parts are **independent**: do them in any order you like. A completed part gives all its
  points, whatever the state of the others.
- Save the configuration of the routers (`write` in `vtysh`).
- PIM is not instantaneous: a neighbour is only known at its first *Hello* (every 30 s), a
  lost *Join* is only repeated after 60 s, an MSDP session takes about thirty seconds to come
  up. After a change, wait a minute before concluding that it does not work.

**Evaluation.** Each evaluation reads your answers and the configuration of the routers. It
**runs real streams**: receivers started on the hosts join groups, then each source sends
about twenty datagrams, and the evaluation looks at what arrived and through which path. These
streams use their own groups (all in the ranges above) and UDP port {port}; they do not
disturb your experiments. An evaluation takes about fifteen seconds.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_igmp`, `solve_snooping`, `solve_asm`, `solve_ssm`, `solve_msdp`,
`solve_fix` et `solve_v6` (onglet *Appliquer une configuration*) appliquent la solution d'une
seule partie, et remplissent ses formulaires. L'état `final` les applique toutes, attend
l'établissement de la session MSDP puis remplit tous les formulaires : une évaluation lancée dès
son retour donne tous les points, bonus compris.

L'évaluation démarre à l'étape 1 des récepteurs (`/usr/local/sbin/mcast_probe.py recv`) sur
`igmp_h1`, `igmp_h2`, `snoop_h1`, `asm_h`, `ssm_h`, `msdp_h`, `fix_h` et `v6_h`, et des
écouteurs passifs (`sniff`, qui ne rejoignent rien) sur `snoop_h2` et `ssm_h`. À l'étape 2, les
sources émettent 20 datagrammes (un toutes les 0,4 s, après 2 s) marqués du jeton `{token}`, vers
le port {port}. À l'étape 3, l'évaluation lit ce que chaque récepteur a reçu (un flux compte
pour reçu à partir de {minimum} datagrammes) et l'état des routeurs. Les groupes des flux
d'évaluation : `{g_igmp1}` et `{g_igmp2}` (igmp), `{g_snoop}` (snoop), `{g_asm}` (asm), `{g_ssm}`
et `{g_ssm_extra}` (ssm), `{g_msdp}` et `{g_scoped}` (msdp), `{g_fix}` (fix), `{g_v6}` (v6).
""": """
**For the instructor.** Each question ends with its solution for the values of this instance.
The states `solve_igmp`, `solve_snooping`, `solve_asm`, `solve_ssm`, `solve_msdp`, `solve_fix`
and `solve_v6` (the *Apply Configuration* tab) apply the solution of a single part and fill in
its forms. The `final` state applies them all, waits for the MSDP session to be established,
then fills in all the forms: an evaluation started as soon as it returns gives all the points,
bonus included.

At step 1, the evaluation starts receivers (`/usr/local/sbin/mcast_probe.py recv`) on
`igmp_h1`, `igmp_h2`, `snoop_h1`, `asm_h`, `ssm_h`, `msdp_h`, `fix_h` and `v6_h`, and passive
listeners (`sniff`, which join nothing) on `snoop_h2` and `ssm_h`. At step 2, the sources send
20 datagrams (one every 0.4 s, after 2 s) marked with the token `{token}`, to port {port}. At
step 3, the evaluation reads what each receiver has received (a stream counts as received from
{minimum} datagrams) and the state of the routers. The groups of the grading streams:
`{g_igmp1}` and `{g_igmp2}` (igmp), `{g_snoop}` (snoop), `{g_asm}` (asm), `{g_ssm}` and
`{g_ssm_extra}` (ssm), `{g_msdp}` and `{g_scoped}` (msdp), `{g_fix}` (fix), `{g_v6}` (v6).
""",
    "Partie 1 — Les adresses multicast": "Part 1 — Multicast addresses",
    "Les adresses multicast": "Multicast addresses",
    """
Répondez sans machine, avec la section @@ref:addressing@@ :

- adresse MAC de destination des trames du groupe `{mac_group}` :
  @@{{mac:[0-9a-fA-F:.-]+}}@@
- une **autre** adresse de groupe IPv4 qui donne la même adresse MAC : @@{{alias:[0-9.]+}}@@
- nature des adresses suivantes :
  - `{scope_a}` : @@{{scope_a:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
  - `{scope_b}` : @@{{scope_b:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
  - `{scope_c}` : @@{{scope_c:>lien local>>>link-local|contrôle inter-réseaux>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|portée locale (site)>>>local-scope|portée organisation>>>organization-scope|globale>>>global}}@@
- adresse du groupe *solicited-node* de l'adresse `{v6_address}` (l'hôte `v6_h`) :
  @@{{sn:[0-9a-fA-F:]+}}@@
- adresse MAC des trames envoyées à ce groupe : @@{{sn_mac:[0-9a-fA-F:.-]+}}@@
""": """
Answer without any machine, using section @@ref:addressing@@:

- destination MAC address of the frames of the group `{mac_group}`:
  @@{{mac:[0-9a-fA-F:.-]+}}@@
- **another** IPv4 group address that gives the same MAC address: @@{{alias:[0-9.]+}}@@
- type of the following addresses:
  - `{scope_a}`: @@{{scope_a:>link-local>>>link-local|internetwork control>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|local scope (site)>>>local-scope|organisation scope>>>organization-scope|global>>>global}}@@
  - `{scope_b}`: @@{{scope_b:>link-local>>>link-local|internetwork control>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|local scope (site)>>>local-scope|organisation scope>>>organization-scope|global>>>global}}@@
  - `{scope_c}`: @@{{scope_c:>link-local>>>link-local|internetwork control>>>internetwork-control|SSM>>>ssm|GLOP>>>glop|local scope (site)>>>local-scope|organisation scope>>>organization-scope|global>>>global}}@@
- address of the *solicited-node* group of the address `{v6_address}` (the host `v6_h`):
  @@{{sn:[0-9a-fA-F:]+}}@@
- MAC address of the frames sent to that group: @@{{sn_mac:[0-9a-fA-F:.-]+}}@@
""",
    """
**Solution.**

- `{mac_group}` : ses 23 bits de poids faible donnent **`{mac}`** ;
- les 32 groupes de cette adresse MAC sont ceux qui ne diffèrent que par les 5 bits perdus, par
  exemple **`{alias1}`**, `{alias2}` ou `{alias3}` (toute réponse de 224.0.0.0/4 autre que
  `{mac_group}` et de même adresse MAC est acceptée) ;
- `{scope_a}` : **{scope_a_class}** ; `{scope_b}` : **{scope_b_class}** ; `{scope_c}` :
  **{scope_c_class}** ;
- les 24 derniers bits de `{v6_address}` donnent **`{sn}`**, et l'adresse MAC **`{sn_mac}`**.

Évaluation : `addressing_mac` (2), `addressing_alias` (2), `addressing_solicited_node` (2),
`addressing_solicited_node_mac` (1) ; pour l'enseignant seulement (réponses choisies dans une
liste) : `addressing_scope_a`, `addressing_scope_b`, `addressing_scope_c` (1 chacun).
""": """
**Solution.**

- `{mac_group}`: its 23 low-order bits give **`{mac}`**;
- the 32 groups of this MAC address are those that differ only in the 5 lost bits, for
  example **`{alias1}`**, `{alias2}` or `{alias3}` (any answer in 224.0.0.0/4 other than
  `{mac_group}` with the same MAC address is accepted);
- `{scope_a}`: **{scope_a_class}**; `{scope_b}`: **{scope_b_class}**; `{scope_c}`:
  **{scope_c_class}**;
- the last 24 bits of `{v6_address}` give **`{sn}`**, and the MAC address **`{sn_mac}`**.

Grading: `addressing_mac` (2), `addressing_alias` (2), `addressing_solicited_node` (2),
`addressing_solicited_node_mac` (1); for the instructor only (answers picked from a list):
`addressing_scope_a`, `addressing_scope_b`, `addressing_scope_c` (1 each).
""",
    "adresse MAC d'un groupe IPv4": "MAC address of an IPv4 group",
    "un autre groupe de même adresse MAC": "another group with the same MAC address",
    "nature d'une adresse multicast": "type of a multicast address",
    "groupe solicited-node d'une adresse IPv6": "solicited-node group of an IPv6 address",
    "adresse MAC d'un groupe IPv6": "MAC address of an IPv6 group",
    "Partie 2 — IGMP sur le site igmp": "Part 2 — IGMP on the igmp site",
    "IGMP : rapports, querier, versions": "IGMP: reports, querier, versions",
    """
Sur le réseau `igmp_lan`, `igmp_r2` fait déjà tourner IGMP : c'est le querier. `igmp_r1` n'a
encore aucune configuration multicast (sections @@ref:igmp@@ et @@ref:frr@@).

1. Sur `igmp_r2`, lisez `show ip igmp interface` et `show ip igmp groups`. Sur `igmp_h1`,
   lancez `tcpdump -ni eth0 -v igmp`, puis faites rejoindre le groupe `{igmp_group}` à `igmp_h2`
   (`iperf -s -u -B {igmp_group}`, arrêté par Ctrl-C) : observez les rapports et le départ
   (destination, TTL, options IP). Comparez avec `cat /proc/net/igmp` sur `igmp_h2`.
2. Activez IGMP, en **version 3**, sur l'interface `eth0` de `igmp_r1`, avec un intervalle des
   requêtes de **{query_interval} s**. Qui est maintenant le querier du réseau ? Vérifiez-le sur
   les deux routeurs.
3. Forcez `igmp_h2` à utiliser **IGMPv2** sur `eth0` (section @@ref:host@@). Refaites rejoindre
   un groupe à `igmp_h2` en observant le trafic IGMP, puis regardez `show ip igmp groups` sur
   `igmp_r1` (section @@ref:compat@@).
""": """
On the `igmp_lan` network, `igmp_r2` already runs IGMP: it is the querier. `igmp_r1` has no
multicast configuration yet (sections @@ref:igmp@@ and @@ref:frr@@).

1. On `igmp_r2`, read `show ip igmp interface` and `show ip igmp groups`. On `igmp_h1`,
   run `tcpdump -ni eth0 -v igmp`, then make `igmp_h2` join the group `{igmp_group}`
   (`iperf -s -u -B {igmp_group}`, stopped with Ctrl-C): observe the reports and the leave
   (destination, TTL, IP options). Compare with `cat /proc/net/igmp` on `igmp_h2`.
2. Enable IGMP, **version 3**, on the `eth0` interface of `igmp_r1`, with a query interval of
   **{query_interval} s**. Who is the querier of the network now? Check it on both
   routers.
3. Force `igmp_h2` to use **IGMPv2** on `eth0` (section @@ref:host@@). Make `igmp_h2` join a
   group again while watching the IGMP traffic, then look at `show ip igmp groups` on
   `igmp_r1` (section @@ref:compat@@).
""",
    """
**Solution.** Sur `igmp_r1` :

```
configure terminal
 interface eth0
  ip igmp
  ip igmp version 3
  ip igmp query-interval {query_interval}
 exit
end
write
```

`igmp_r1` (`{r1}`) a une adresse plus petite que `igmp_r2` (`{r2}`) : il devient aussitôt le
querier, et `igmp_r2` passe à `other`. Sur `igmp_h2` :
`sysctl -w net.ipv4.conf.eth0.force_igmp_version=2` (ou `all`). Ses adhésions apparaissent
alors en version 2 dans `show ip igmp groups` de `igmp_r1`, celles d'`igmp_h1` en version 3.

Évaluation : `igmp_enabled` (3 : IGMP sur `eth0` d'`igmp_r1`), `igmp_query_interval` (2),
`igmp_querier` (2 : `igmp_r1` est le querier), `igmp_h2_v2` (2 : la version forcée sur
`igmp_h2`), `igmp_group_v3` (1 : `igmp_r1` connaît le groupe que rejoint `igmp_h1`),
`igmp_group_v2` (1 : celui d'`igmp_h2`, en version 2).
""": """
**Solution.** On `igmp_r1`:

```
configure terminal
 interface eth0
  ip igmp
  ip igmp version 3
  ip igmp query-interval {query_interval}
 exit
end
write
```

`igmp_r1` (`{r1}`) has a lower address than `igmp_r2` (`{r2}`): it immediately becomes the
querier, and `igmp_r2` switches to `other`. On `igmp_h2`:
`sysctl -w net.ipv4.conf.eth0.force_igmp_version=2` (or `all`). Its memberships then appear as
version 2 in `show ip igmp groups` of `igmp_r1`, those of `igmp_h1` as version 3.

Grading: `igmp_enabled` (3: IGMP on `eth0` of `igmp_r1`), `igmp_query_interval` (2),
`igmp_querier` (2: `igmp_r1` is the querier), `igmp_h2_v2` (2: the version forced on
`igmp_h2`), `igmp_group_v3` (1: `igmp_r1` knows the group that `igmp_h1` joins),
`igmp_group_v2` (1: that of `igmp_h2`, as version 2).
""",
    "Observations": "Observations",
    """
- querier du réseau avant votre configuration : @@{querier_before:>igmp_r1|igmp_r2}@@ ; le querier
  est le routeur qui a @@{rule:>la plus petite adresse IP>>>lowest_address|la plus grande adresse IP>>>highest_address|la plus grande priorité>>>highest_priority|le plus ancien uptime>>>oldest}@@
- adresse de destination des rapports d'IGMPv3 : @@{report_v3_dst:[0-9.]+}@@
- adresse de destination des messages *Leave* d'IGMPv2 : @@{leave_v2_dst:[0-9.]+}@@
- TTL des messages IGMP : @@{ttl:[0-9]+}@@
- option IP présente dans les messages IGMP :
  @@{option:>Router Alert>>>router_alert|Record Route>>>record_route|Timestamp>>>timestamp|Strict Source Route>>>source_route|aucune>>>none}@@
""": """
- querier of the network before your configuration: @@{querier_before:>igmp_r1|igmp_r2}@@; the querier
  is the router with @@{rule:>the lowest IP address>>>lowest_address|the highest IP address>>>highest_address|the highest priority>>>highest_priority|the longest uptime>>>oldest}@@
- destination address of the IGMPv3 reports: @@{report_v3_dst:[0-9.]+}@@
- destination address of the IGMPv2 *Leave* messages: @@{leave_v2_dst:[0-9.]+}@@
- TTL of the IGMP messages: @@{ttl:[0-9]+}@@
- IP option present in the IGMP messages:
  @@{option:>Router Alert>>>router_alert|Record Route>>>record_route|Timestamp>>>timestamp|Strict Source Route>>>source_route|none>>>none}@@
""",
    """
**Solution.** Avant votre configuration, le querier était **`igmp_r2`**, le seul routeur IGMP ; le
querier est le routeur de **plus petite adresse IP**. Rapports d'IGMPv3 vers **224.0.0.22**,
*Leave* d'IGMPv2 vers **224.0.0.2**, **TTL 1**, option **Router Alert**.

Évaluation : `igmp_report_v3_destination`, `igmp_leave_v2_destination`, `igmp_ttl` (0,5 chacun) ;
pour l'enseignant seulement : `igmp_querier_before`, `igmp_election_rule`, `igmp_ip_option` (0,5
chacun).
""": """
**Solution.** Before your configuration, the querier was **`igmp_r2`**, the only IGMP router; the
querier is the router with the **lowest IP address**. IGMPv3 reports to **224.0.0.22**, IGMPv2
*Leave* to **224.0.0.2**, **TTL 1**, **Router Alert** option.

Grading: `igmp_report_v3_destination`, `igmp_leave_v2_destination`, `igmp_ttl` (0.5 each);
for the instructor only: `igmp_querier_before`, `igmp_election_rule`, `igmp_ip_option` (0.5
each).
""",
    "IGMP sur eth0 d'igmp_r1": "IGMP on eth0 of igmp_r1",
    "intervalle des requêtes d'igmp_r1": "query interval of igmp_r1",
    "igmp_r1 est le querier": "igmp_r1 is the querier",
    "igmp_h2 forcé en IGMPv2": "igmp_h2 forced to IGMPv2",
    "igmp_r1 connaît le groupe d'igmp_h1 (IGMPv3)": "igmp_r1 knows the group of igmp_h1 (IGMPv3)",
    "igmp_r1 connaît le groupe d'igmp_h2, en IGMPv2": "igmp_r1 knows the group of igmp_h2, as IGMPv2",
    "adresse de destination d'un message IGMP": "destination address of an IGMP message",
    "TTL des messages IGMP": "TTL of the IGMP messages",
    "question de cours sur IGMP": "course question on IGMP",
    "Partie 3 — IGMP snooping sur snoop_sw": "Part 3 — IGMP snooping on snoop_sw",
    "IGMP snooping": "IGMP snooping",
    """
`snoop_sw` est un commutateur : un pont Linux `br0` réunit ses ports `eth0` (vers `snoop_src`),
`eth1` (vers `snoop_h1`) et `eth2` (vers `snoop_h2`). Il n'y a pas de routeur multicast sur ce
réseau. Le pont a été créé avec le snooping **désactivé** (section @@ref:snooping@@).

1. Faites rejoindre le groupe `{group}` à `snoop_h1` (`iperf -s -u -B {group} -i 1`), lancez
   `tcpdump -ni eth0 host {group}` sur `snoop_h2`, puis émettez vers ce groupe depuis `snoop_src`
   (`iperf -c {group} -u -T 4 -t 10 -b 50K`). Qui reçoit le flux ?
2. Activez le snooping sur `br0`, sans rien d'autre, et recommencez. Lisez la table des groupes
   (`bridge mdb show`). Qu'est-ce qui a changé ?
3. Faites de `br0` le **querier** du réseau, en **IGMPv3**, avec des requêtes émises depuis son
   adresse (`{switch_ip}`). Après une dizaine de secondes, recommencez : `snoop_h2` ne doit plus
   rien recevoir.
4. Activez le **départ rapide** sur les deux ports des hôtes, `eth1` et `eth2`. Pourquoi ne
   faut-il pas l'activer sur un port qui dessert plusieurs hôtes ?
""": """
`snoop_sw` is a switch: a Linux bridge `br0` joins its ports `eth0` (towards `snoop_src`),
`eth1` (towards `snoop_h1`) and `eth2` (towards `snoop_h2`). There is no multicast router on
this network. The bridge was created with snooping **off** (section @@ref:snooping@@).

1. Make `snoop_h1` join the group `{group}` (`iperf -s -u -B {group} -i 1`), run
   `tcpdump -ni eth0 host {group}` on `snoop_h2`, then send to this group from `snoop_src`
   (`iperf -c {group} -u -T 4 -t 10 -b 50K`). Who receives the stream?
2. Enable snooping on `br0`, nothing else, and try again. Read the group table
   (`bridge mdb show`). What has changed?
3. Make `br0` the **querier** of the network, with **IGMPv3**, with queries sent from its
   address (`{switch_ip}`). After about ten seconds, try again: `snoop_h2` must no longer
   receive anything.
4. Enable **fast leave** on the two ports of the hosts, `eth1` and `eth2`. Why must it not be
   enabled on a port that serves several hosts?
""",
    """
**Solution.** Snooping désactivé, le pont inonde le flux : `snoop_h2` le reçoit aussi. Avec le
snooping seul, `bridge mdb show` contient bien `port eth1 grp {group}`, mais **`snoop_h2` reçoit
toujours le flux** : le pont n'a détecté aucun querier, alors il continue d'inonder. Sur
`snoop_sw` :

```
ip link set br0 type bridge mcast_snooping 1 mcast_querier 1 mcast_igmp_version 3 mcast_query_use_ifaddr 1
bridge link set dev eth1 fastleave on
bridge link set dev eth2 fastleave on
```

Une dizaine de secondes après l'activation du querier (le délai de réponse aux requêtes), seul
`snoop_h1` reçoit le flux. Le départ rapide retire le port dès le premier *Leave* : sur un port
partagé, les autres membres perdraient le flux jusqu'à leur prochain rapport.

Évaluation : `snooping_enabled` (2), `snooping_querier` (2), `snooping_igmp_v3` (1),
`snooping_fast_leave` (2 : `eth1` et `eth2`), `snooping_mdb` (2 : le pont a appris le groupe du
flux d'évaluation sur `eth1`), `snooping_member_receives` (2 : `snoop_h1` le reçoit, le snooping
actif),
`snooping_no_flood` (3 : `snoop_h2` n'en voit aucune trame, compté seulement si `snoop_h1` le
reçoit).
""": """
**Solution.** With snooping off, the bridge floods the stream: `snoop_h2` receives it too. With
snooping alone, `bridge mdb show` does contain `port eth1 grp {group}`, but **`snoop_h2` still
receives the stream**: the bridge has detected no querier, so it keeps flooding. On
`snoop_sw`:

```
ip link set br0 type bridge mcast_snooping 1 mcast_querier 1 mcast_igmp_version 3 mcast_query_use_ifaddr 1
bridge link set dev eth1 fastleave on
bridge link set dev eth2 fastleave on
```

About ten seconds after the querier is enabled (the response delay of the queries), only
`snoop_h1` receives the stream. Fast leave removes the port at the first *Leave*: on a shared
port, the other members would lose the stream until their next report.

Grading: `snooping_enabled` (2), `snooping_querier` (2), `snooping_igmp_v3` (1),
`snooping_fast_leave` (2: `eth1` and `eth2`), `snooping_mdb` (2: the bridge has learnt the
group of the grading stream on `eth1`), `snooping_member_receives` (2: `snoop_h1` receives it,
with snooping on),
`snooping_no_flood` (3: `snoop_h2` sees no frame of it, counted only if `snoop_h1` receives
it).
""",
    "snooping actif sur br0": "snooping enabled on br0",
    "br0 est querier": "br0 is the querier",
    "requêtes de br0 en IGMPv3": "queries of br0 in IGMPv3",
    "départ rapide sur eth1 et eth2": "fast leave on eth1 and eth2",
    "br0 a appris le groupe sur eth1": "br0 has learnt the group on eth1",
    "snoop_h1 reçoit le flux": "snoop_h1 receives the stream",
    "snoop_h2 ne reçoit pas le flux": "snoop_h2 does not receive the stream",
    "Partie 4 — PIM-SM sur le site asm": "Part 4 — PIM-SM on the asm site",
    "PIM-SM avec un RP statique": "PIM-SM with a static RP",
    """
Le site `asm` est un triangle de routeurs : `asm_r1` dessert le réseau de la source `asm_src`,
`asm_r3` celui du récepteur `asm_h`, et `asm_r2` sera le **point de rendez-vous** (RP), sur son
adresse de bouclage `{rp}` (sections @@ref:pimsm@@ et @@ref:frr@@). Les routes statiques font
passer le chemin le plus court de `asm_r3` vers la source par le lien direct `asm_l13`, et celui
vers le RP par `asm_l23`.

1. Activez PIM sur **toutes** les interfaces des trois routeurs, y compris celles des réseaux
   d'hôtes, et sur l'interface de bouclage du RP. Vérifiez les voisinages
   (`show ip pim neighbor`).
2. Déclarez `{rp}` comme RP des groupes `{range}` sur les trois routeurs
   (`show ip pim rp-info`).
3. Activez IGMP sur l'interface de `asm_r3` du côté du récepteur.
4. Faites rejoindre `{group}` à `asm_h` (`iperf -s -u -B {group} -i 1`), puis lisez
   `show ip mroute` et `show ip pim upstream` sur les trois routeurs : quelles entrées ont été
   créées, et jusqu'où ?
5. Lancez un `tcpdump -ni eth1 pim` sur `asm_r2`, puis émettez depuis `asm_src`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K`). Suivez les messages PIM, puis relisez les tables
   multicast : par où passe le flux au bout de quelques secondes ?
""": """
The `asm` site is a triangle of routers: `asm_r1` serves the network of the source `asm_src`,
`asm_r3` that of the receiver `asm_h`, and `asm_r2` will be the **rendezvous point** (RP), on
its loopback address `{rp}` (sections @@ref:pimsm@@ and @@ref:frr@@). The static routes make
the shortest path from `asm_r3` to the source go through the direct link `asm_l13`, and the
one to the RP through `asm_l23`.

1. Enable PIM on **all** the interfaces of the three routers, including those of the host
   networks, and on the loopback interface of the RP. Check the neighbours
   (`show ip pim neighbor`).
2. Declare `{rp}` as the RP of the groups `{range}` on the three routers
   (`show ip pim rp-info`).
3. Enable IGMP on the interface of `asm_r3` on the receiver's side.
4. Make `asm_h` join `{group}` (`iperf -s -u -B {group} -i 1`), then read `show ip mroute`
   and `show ip pim upstream` on the three routers: which entries have been created, and how
   far?
5. Start a `tcpdump -ni eth1 pim` on `asm_r2`, then send from `asm_src`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K`). Follow the PIM messages, then read the multicast
   tables again: which way does the stream go after a few seconds?
""",
    """
**Solution.** Sur `asm_r1` :

```
configure terminal
 ip pim rp {rp} {range}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
 interface eth2
  ip pim
 exit
end
write
```

Sur `asm_r2`, la même chose avec `interface lo` / `ip pim` en plus (ses interfaces sont `eth0`
et `eth1`). Sur `asm_r3`, la même chose, avec en plus `ip igmp` sur `eth2`.

Quand `asm_h` rejoint le groupe, `asm_r3` crée (\\*,{group}) et envoie un *Join* (\\*,G) vers le RP
par `eth0` (`asm_l23`) : `asm_r2` a aussi une entrée (\\*,G), d'interface d'entrée `lo`. Au premier
datagramme, `asm_r1` (FHR) l'encapsule dans un **Register** vers le RP, qui le décapsule, le
transmet sur l'arbre partagé, envoie un *Join* (S,G) vers la source puis un **Register-Stop**.
Dès réception, `asm_r3` bascule sur l'arbre de source : son entrée (S,G) a pour interface
d'entrée **`eth1`** (`asm_l13`, le lien direct), et `asm_r2` élague (S,G) (drapeaux `SRP`). Le
TTL reçu par `asm_h` passe de 13 (via le RP) à 14.

Évaluation : `asm_neighbors_l12`, `asm_neighbors_l23`, `asm_neighbors_l13` (2 chacun : les
voisinages PIM des trois liens), `asm_source_lan` (1 : PIM sur `eth0` de `asm_r1`), `asm_rp_r1`,
`asm_rp_r2`, `asm_rp_r3` (1 chacun : `{rp}` est le RP du groupe du flux d'évaluation),
`asm_igmp` (2 : IGMP sur `eth2` de `asm_r3`), `asm_stream` (4 : `asm_h` reçoit le flux),
`asm_spt` (3 : l'entrée (S,G) de `asm_r3` arrive par `eth1`).
""": """
**Solution.** On `asm_r1`:

```
configure terminal
 ip pim rp {rp} {range}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
 interface eth2
  ip pim
 exit
end
write
```

On `asm_r2`, the same with `interface lo` / `ip pim` in addition (its interfaces are `eth0` and
`eth1`). On `asm_r3`, the same, with `ip igmp` on `eth2` in addition.

When `asm_h` joins the group, `asm_r3` creates (\\*,{group}) and sends a *Join* (\\*,G) towards
the RP through `eth0` (`asm_l23`): `asm_r2` also has a (\\*,G) entry, with incoming interface
`lo`. At the first datagram, `asm_r1` (FHR) encapsulates it in a **Register** to the RP, which
decapsulates it, forwards it on the shared tree, sends a *Join* (S,G) towards the source, then
a **Register-Stop**. As soon as the stream reaches it, `asm_r3` switches over to the source
tree: its (S,G) entry has **`eth1`** as incoming interface (`asm_l13`, the direct link), and
`asm_r2` prunes (S,G) (flags `SRP`). The TTL received by `asm_h` goes from 13 (via the RP) to
14.

Grading: `asm_neighbors_l12`, `asm_neighbors_l23`, `asm_neighbors_l13` (2 each: the PIM
neighbours of the three links), `asm_source_lan` (1: PIM on `eth0` of `asm_r1`), `asm_rp_r1`,
`asm_rp_r2`, `asm_rp_r3` (1 each: `{rp}` is the RP of the group of the grading stream),
`asm_igmp` (2: IGMP on `eth2` of `asm_r3`), `asm_stream` (4: `asm_h` receives the stream),
`asm_spt` (3: the (S,G) entry of `asm_r3` comes in through `eth1`).
""",
    """
- interface RPF de `asm_r3` vers le RP (celle de son entrée (\\*,G)) : @@{rpf_iface:[a-z0-9]+}@@
- message PIM qui porte vers le RP les premiers datagrammes de la source :
  @@{fhr_message:>Hello>>>hello|Join>>>join|Register>>>register|Assert>>>assert|Bootstrap>>>bootstrap}@@
- message par lequel le RP fait cesser cet envoi :
  @@{rp_answer:>Prune>>>prune|Register-Stop>>>register-stop|Graft>>>graft|Assert>>>assert}@@
""": """
- RPF interface of `asm_r3` towards the RP (that of its (\\*,G) entry): @@{rpf_iface:[a-z0-9]+}@@
- PIM message that carries the first datagrams of the source to the RP:
  @@{fhr_message:>Hello>>>hello|Join>>>join|Register>>>register|Assert>>>assert|Bootstrap>>>bootstrap}@@
- message with which the RP stops this sending:
  @@{rp_answer:>Prune>>>prune|Register-Stop>>>register-stop|Graft>>>graft|Assert>>>assert}@@
""",
    """
**Solution.** Interface RPF vers le RP : **`{rpf}`** (la route statique vers `{rp}` passe par
`asm_l23`). Les premiers datagrammes arrivent au RP dans des **Register**, le RP répond par un
**Register-Stop**.

Évaluation : `asm_rpf_interface` (1) ; pour l'enseignant seulement : `asm_register` (1),
`asm_register_stop` (1).
""": """
**Solution.** RPF interface towards the RP: **`{rpf}`** (the static route to `{rp}` goes through
`asm_l23`). The first datagrams reach the RP in **Register** messages, and the RP answers with a
**Register-Stop**.

Grading: `asm_rpf_interface` (1); for the instructor only: `asm_register` (1),
`asm_register_stop` (1).
""",
    "voisinage PIM sur un lien du site asm": "PIM neighbours on a link of the asm site",
    "PIM sur le réseau de la source": "PIM on the network of the source",
    "RP du groupe sur un routeur": "RP of the group on a router",
    "IGMP du côté du récepteur": "IGMP on the receiver's side",
    "asm_h reçoit le flux": "asm_h receives the stream",
    "asm_r3 reçoit le flux par l'arbre de source": "asm_r3 receives the stream through the source tree",
    "interface RPF vers le RP": "RPF interface towards the RP",
    "message PIM de l'enregistrement d'une source": "PIM message of the registration of a source",
    "Partie 5 — PIM-SSM sur le site ssm": "Part 5 — PIM-SSM on the ssm site",
    """
Sur le site `ssm`, la source `ssm_src` a deux adresses : `{s1}` et `{s2}` (sur le même réseau).
Il n'y a pas de RP (section @@ref:ssm@@).

1. Activez PIM sur les interfaces de `ssm_r1` et de `ssm_r2`, et IGMP, en **version 3**, sur
   l'interface de `ssm_r2` du côté de `ssm_h`.
2. Sur `ssm_h`, abonnez-vous au canal ({s1}, `{group}`) : `iperf -s -u -B {group} -H {s1} -i 1`.
   Émettez vers `{group}` depuis `ssm_src`, d'abord depuis `{s1}`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K -B {s1}`), puis en même temps depuis `{s2}`.
   Comparez les tables multicast des deux routeurs et ce qui arrive sur `ssm_h`
   (`tcpdump -ni eth0 host {group}`).
3. Déclarez aussi les groupes `{extra}` comme groupes SSM, sur les deux routeurs, sans perdre
   `{default}` (`show ip pim group-type`).
""": """
On the `ssm` site, the source `ssm_src` has two addresses: `{s1}` and `{s2}` (on the same
network). There is no RP (section @@ref:ssm@@).

1. Enable PIM on the interfaces of `ssm_r1` and `ssm_r2`, and IGMP, **version 3**, on the
   interface of `ssm_r2` on the side of `ssm_h`.
2. On `ssm_h`, subscribe to the channel ({s1}, `{group}`): `iperf -s -u -B {group} -H {s1} -i 1`.
   Send to `{group}` from `ssm_src`, first from `{s1}`
   (`iperf -c {group} -u -T 16 -t 30 -b 50K -B {s1}`), then from `{s2}` at the same time.
   Compare the multicast tables of the two routers and what arrives on `ssm_h`
   (`tcpdump -ni eth0 host {group}`).
3. Also declare the groups `{extra}` as SSM groups, on both routers, without losing
   `{default}` (`show ip pim group-type`).
""",
    """
**Solution.** Sur `ssm_r1` :

```
configure terminal
 ip prefix-list {plist} seq 5 permit {default} le 32
 ip prefix-list {plist} seq 10 permit {extra} le 32
 ip pim ssm prefix-list {plist}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
end
write
```

Sur `ssm_r2`, la même chose, avec en plus `ip igmp` et `ip igmp version 3` sur `eth1`.
L'abonnement de `ssm_h` est un rapport IGMPv3 `INCLUDE` {{{s1}}} : `ssm_r2` envoie un *Join*
({s1}, G) vers `ssm_r1`, qui ne transmet que ce canal. Le trafic de `{s2}` s'arrête à `ssm_r1`
(entrée ({s2}, G) sans interface de sortie, drapeau `P`) : `ssm_h` n'en voit rien.

Évaluation : `ssm_neighbor` (2 : voisinage PIM entre les deux routeurs), `ssm_source_lan` (1 :
PIM sur `eth0` de `ssm_r1`), `ssm_igmp_v3` (2 : IGMPv3 sur `eth1` de `ssm_r2`), `ssm_stream` (3 :
`ssm_h` reçoit le canal de `{s1}`), `ssm_source_filter` (2 : aucune trame de `{s2}` vers le groupe
sur le réseau de `ssm_h`, compté seulement si le canal de `{s1}` arrive), `ssm_range_r1` et
`ssm_range_r2` (1 chacun : un groupe de `{extra}` est SSM).
""": """
**Solution.** On `ssm_r1`:

```
configure terminal
 ip prefix-list {plist} seq 5 permit {default} le 32
 ip prefix-list {plist} seq 10 permit {extra} le 32
 ip pim ssm prefix-list {plist}
 interface eth0
  ip pim
 exit
 interface eth1
  ip pim
 exit
end
write
```

On `ssm_r2`, the same, with `ip igmp` and `ip igmp version 3` on `eth1` in addition.
The subscription of `ssm_h` is an IGMPv3 `INCLUDE` {{{s1}}} report: `ssm_r2` sends a *Join*
({s1}, G) towards `ssm_r1`, which forwards only that channel. The traffic of `{s2}` stops at
`ssm_r1` (entry ({s2}, G) without an outgoing interface, flag `P`): `ssm_h` sees none of it.

Grading: `ssm_neighbor` (2: PIM neighbours between the two routers), `ssm_source_lan` (1:
PIM on `eth0` of `ssm_r1`), `ssm_igmp_v3` (2: IGMPv3 on `eth1` of `ssm_r2`), `ssm_stream` (3:
`ssm_h` receives the channel of `{s1}`), `ssm_source_filter` (2: no frame from `{s2}` to the
group on the network of `ssm_h`, counted only if the channel of `{s1}` arrives), `ssm_range_r1`
and `ssm_range_r2` (1 each: a group of `{extra}` is SSM).
""",
    "voisinage PIM ssm_r1 – ssm_r2": "PIM neighbours ssm_r1 – ssm_r2",
    "IGMPv3 du côté du récepteur": "IGMPv3 on the receiver's side",
    "ssm_h reçoit le canal (S1, G)": "ssm_h receives the channel (S1, G)",
    "le trafic de S2 n'atteint pas ssm_h": "the traffic of S2 does not reach ssm_h",
    "plage SSM étendue": "extended SSM range",
    "Partie 6 — MSDP et frontière sur le site msdp": "Part 6 — MSDP and boundary on the msdp site",
    "MSDP et portée administrative": "MSDP and administrative scoping",
    """
Le site `msdp` réunit deux domaines PIM, déjà configurés : `msdp_r1` est le RP du domaine 1
(`{rp1}`, celui de la source `msdp_src`), `msdp_r2` celui du domaine 2 (`{rp2}`, celui du
récepteur `msdp_h`), chacun pour tous les groupes (`{all}`). PIM tourne sur le lien entre eux
(section @@ref:msdp@@).

1. Faites rejoindre `{group}` à `msdp_h`, émettez depuis `msdp_src` : le flux n'arrive pas.
   Pourquoi ? Comparez `show ip mroute` sur les deux routeurs.
2. Établissez une session **MSDP** entre les deux RP, entre leurs adresses de bouclage
   (`show ip msdp peer`, puis `show ip msdp sa` pendant que la source émet). Le flux arrive-t-il ?
3. Les groupes de portée organisation (`{scoped}`) ne doivent pas sortir du domaine 1. Posez
   une **frontière** sur l'interface de `msdp_r1` vers `msdp_r2` (section @@ref:scoping@@), puis
   vérifiez avec deux flux simultanés, vers `{group}` et vers `{scoped_group}` : le premier passe,
   le second non.
""": """
The `msdp` site brings together two PIM domains, already configured: `msdp_r1` is the RP of
domain 1 (`{rp1}`, that of the source `msdp_src`), `msdp_r2` that of domain 2 (`{rp2}`, that of
the receiver `msdp_h`), each for all groups (`{all}`). PIM runs on the link between them
(section @@ref:msdp@@).

1. Make `msdp_h` join `{group}`, and send from `msdp_src`: the stream does not arrive.
   Why? Compare `show ip mroute` on the two routers.
2. Set up an **MSDP** session between the two RPs, between their loopback addresses
   (`show ip msdp peer`, then `show ip msdp sa` while the source sends). Does the stream arrive?
3. The organisation-scope groups (`{scoped}`) must not leave domain 1. Set up a **boundary**
   on the interface of `msdp_r1` towards `msdp_r2` (section @@ref:scoping@@), then check with
   two simultaneous streams, to `{group}` and to `{scoped_group}`: the first gets through, the
   second does not.
""",
    """
**Solution.** Chaque RP ignore les sources de l'autre domaine : `msdp_r2` a l'entrée (\\*,G) de
son récepteur, `msdp_r1` l'entrée (S,G) de sa source, mais personne ne fait le lien. Sur
`msdp_r1` :

```
configure terminal
 ip msdp peer {rp2} source {rp1}
 ip prefix-list {plist} seq 5 deny {scoped} le 32
 ip prefix-list {plist} seq 10 permit 224.0.0.0/4 le 32
 interface {r1_link}
  ip multicast boundary oil {plist}
 exit
end
write
```

Sur `msdp_r2` : `ip msdp peer {rp1} source {rp2}`. Après une trentaine de secondes, la session
est `established`. Dès que la source émet, `msdp_r1` envoie un SA, `msdp_r2` le met en cache
(`SPT y`) et envoie un *Join* (S,G) vers la source : le flux passe. La frontière fait ignorer à
`msdp_r1` les *Join* reçus sur `{r1_link}` pour `{scoped}` : l'entrée (S,G) de ces groupes reste
sans interface de sortie (drapeau `P`), alors que leur SA traverse encore la session.

Évaluation : `msdp_peer_r1`, `msdp_peer_r2` (2 chacun : la session est établie), `msdp_sa` (2 :
`msdp_r2` a reçu le SA du flux d'évaluation), `msdp_stream` (4 : `msdp_h` reçoit le flux),
`msdp_boundary_config` (1 : une frontière sur `{r1_link}` de `msdp_r1`, dont la liste refuse le
groupe de portée organisation du flux d'évaluation), `msdp_boundary_blocks` (3 : `msdp_h` ne reçoit
pas ce groupe, compté seulement si le premier flux passe).
""": """
**Solution.** Each RP ignores the sources of the other domain: `msdp_r2` has the (\\*,G) entry
of its receiver, `msdp_r1` the (S,G) entry of its source, but nobody makes the connection. On
`msdp_r1`:

```
configure terminal
 ip msdp peer {rp2} source {rp1}
 ip prefix-list {plist} seq 5 deny {scoped} le 32
 ip prefix-list {plist} seq 10 permit 224.0.0.0/4 le 32
 interface {r1_link}
  ip multicast boundary oil {plist}
 exit
end
write
```

On `msdp_r2`: `ip msdp peer {rp1} source {rp2}`. After about thirty seconds, the session is
`established`. As soon as the source sends, `msdp_r1` sends an SA, `msdp_r2` caches it
(`SPT y`) and sends a *Join* (S,G) towards the source: the stream gets through. The boundary
makes `msdp_r1` ignore the *Joins* received on `{r1_link}` for `{scoped}`: the (S,G) entry of
these groups stays without an outgoing interface (flag `P`), while their SA still crosses the
session.

Grading: `msdp_peer_r1`, `msdp_peer_r2` (2 each: the session is established), `msdp_sa` (2:
`msdp_r2` has received the SA of the grading stream), `msdp_stream` (4: `msdp_h` receives the
stream), `msdp_boundary_config` (1: a boundary on `{r1_link}` of `msdp_r1`, whose list denies
the organisation-scope group of the grading stream), `msdp_boundary_blocks` (3: `msdp_h` does
not receive that group, counted only if the first stream gets through).
""",
    "session MSDP établie": "MSDP session established",
    "SA reçu par msdp_r2": "SA received by msdp_r2",
    "msdp_h reçoit le flux de l'autre domaine": "msdp_h receives the stream of the other domain",
    "frontière sur msdp_r1": "boundary on msdp_r1",
    "le groupe de portée organisation ne sort pas du domaine 1": "the organisation-scope group does not leave domain 1",
    "Partie 7 — Dépannage sur le site fix": "Part 7 — Troubleshooting on the fix site",
    "Un domaine PIM en panne": "A broken PIM domain",
    """
Le site `fix` est un domaine PIM-SM complet : `fix_r1` dessert la source `fix_src` et sert de RP
(`{rp}`, son adresse de bouclage, pour les groupes `{range}`), `fix_r2` dessert le récepteur
`fix_h`. Deux liens relient les routeurs : `fix_la` et `fix_lb`. Tout a été configuré par un
collègue... mais `fix_h` ne reçoit pas le flux de `fix_src`.

Trouvez et corrigez **toutes** les pannes : il y en a **quatre**. Ne cassez pas la conception
du site : `{rp}` reste le RP, et le routage unicast peut être modifié s'il le faut. Suivez la
méthode de la section @@ref:diagnostic@@, du récepteur vers la source, et testez avec
`iperf -s -u -B {group} -i 1` sur `fix_h` et `iperf -c {group} -u -T 16 -t 60 -b 50K` sur
`fix_src`.
""": """
The `fix` site is a complete PIM-SM domain: `fix_r1` serves the source `fix_src` and acts as
the RP (`{rp}`, its loopback address, for the groups `{range}`), `fix_r2` serves the receiver
`fix_h`. Two links connect the routers: `fix_la` and `fix_lb`. Everything was configured by a
colleague... but `fix_h` does not receive the stream of `fix_src`.

Find and fix **all** the faults: there are **four**. Do not break the design of the site:
`{rp}` remains the RP, and unicast routing may be changed if need be. Follow the method of
section @@ref:diagnostic@@, from the receiver towards the source, and test with
`iperf -s -u -B {group} -i 1` on `fix_h` and `iperf -c {group} -u -T 16 -t 60 -b 50K` on
`fix_src`.
""",
    """
**Solution.** Les quatre pannes :

1. PIM n'est pas activé sur `eth0` de `fix_r1`, l'interface du réseau de la source : `fix_r1` ne
   crée pas d'entrée (S,G) et n'enregistre pas la source. Correction : `interface eth0` /
   `ip pim`.
2. `fix_r1` filtre PIM : la règle `ip protocol {{ gre, pim }} drop` de la chaîne `input` de
   `{nft}` jette les *Hello* et les *Join* de `fix_r2`. `fix_r2` voit `fix_r1` comme voisin, pas
   l'inverse. Correction : retirer `pim` de la règle (ou toute la règle), puis `nft -f {nft}`.
3. `fix_r2` désigne comme RP `{wrong}` (l'adresse de `fix_r1` sur `fix_la`) au lieu de `{rp}` : ses
   *Join* (\\*,G) visent un routeur qui n'est pas le RP. Correction :
   `no ip pim rp {wrong} {range}` puis `ip pim rp {rp} {range}`.
4. La route statique de `fix_r2` vers `{rp}` passe par `fix_lb` (`{lb}`), où PIM n'est pas activé :
   l'interface RPF vers le RP n'a pas de voisin PIM, aucun *Join* ne part. Correction : faire
   passer la route par `fix_la` (`no ip route {rp}/32 {lb}` puis `ip route {rp}/32 {la}`), ou
   activer PIM sur `fix_lb` des deux côtés.

Après les corrections, il faut attendre le *Hello* suivant de `fix_r2` (au plus 30 s) avant que
`fix_r1` le connaisse comme voisin et accepte ses *Join*.

Évaluation : `fix_stream` (6 : `fix_h` reçoit le flux), `fix_source_lan` (2 : panne 1),
`fix_pim_filter` (2 : panne 2, `fix_r1` a `fix_r2` pour voisin PIM), `fix_rp_address` (2 : panne 3,
le RP du groupe sur `fix_r2`), `fix_rpf_to_rp` (2 : panne 4, l'interface de `fix_r2` vers `{rp}`
a un voisin PIM).
""": """
**Solution.** The four faults:

1. PIM is not enabled on `eth0` of `fix_r1`, the interface of the network of the source:
   `fix_r1` creates no (S,G) entry and does not register the source. Fix: `interface eth0` /
   `ip pim`.
2. `fix_r1` filters PIM: the rule `ip protocol {{ gre, pim }} drop` of the `input` chain of
   `{nft}` drops the *Hellos* and the *Joins* of `fix_r2`. `fix_r2` sees `fix_r1` as a
   neighbour, not the other way round. Fix: remove `pim` from the rule (or the whole rule),
   then `nft -f {nft}`.
3. `fix_r2` designates `{wrong}` (the address of `fix_r1` on `fix_la`) as the RP instead of
   `{rp}`: its *Joins* (\\*,G) aim at a router that is not the RP. Fix:
   `no ip pim rp {wrong} {range}` then `ip pim rp {rp} {range}`.
4. The static route of `fix_r2` to `{rp}` goes through `fix_lb` (`{lb}`), where PIM is not
   enabled: the RPF interface towards the RP has no PIM neighbour, so no *Join* goes out. Fix:
   make the route go through `fix_la` (`no ip route {rp}/32 {lb}` then `ip route {rp}/32 {la}`),
   or enable PIM on `fix_lb` on both sides.

After the fixes, wait for the next *Hello* of `fix_r2` (30 s at most) before `fix_r1` knows it
as a neighbour and accepts its *Joins*.

Grading: `fix_stream` (6: `fix_h` receives the stream), `fix_source_lan` (2: fault 1),
`fix_pim_filter` (2: fault 2, `fix_r1` has `fix_r2` as a PIM neighbour), `fix_rp_address` (2:
fault 3, the RP of the group on `fix_r2`), `fix_rpf_to_rp` (2: fault 4, the interface of
`fix_r2` towards `{rp}` has a PIM neighbour).
""",
    "Compte rendu": "Report",
    """
Décrivez brièvement chaque panne trouvée et sa correction (non noté automatiquement : votre
enseignant le lira).

@@{diagnosis:+6}@@
""": """
Briefly describe each fault you found and how you fixed it (not graded automatically: your
instructor will read it).

@@{diagnosis:+6}@@
""",
    "fix_h reçoit le flux": "fix_h receives the stream",
    "fix_r1 voit fix_r2 comme voisin PIM": "fix_r1 sees fix_r2 as a PIM neighbour",
    "le bon RP sur fix_r2": "the right RP on fix_r2",
    "interface RPF de fix_r2 vers le RP avec un voisin PIM": "RPF interface of fix_r2 towards the RP with a PIM neighbour",
    "Partie 8 — MLD et PIMv6 (bonus)": "Part 8 — MLD and PIMv6 (bonus)",
    "Multicast IPv6 : MLD et PIMv6": "IPv6 multicast: MLD and PIMv6",
    """
Le site `v6` est en IPv6 seulement ; le démon `pim6d` tourne sur `v6_r1` et `v6_r2`
(section @@ref:ipv6@@).

1. Activez PIMv6 sur les interfaces des deux routeurs, et MLD sur l'interface de `v6_r2` du côté
   de `v6_h`. Vérifiez le voisinage (`show ipv6 pim neighbor`) : sous quelle adresse apparaît le
   voisin ?
2. Sur `v6_h`, abonnez-vous au canal SSM ({src}, `{group}`) :
   `iperf -s -u -V -B {group} -H {src} -i 1`, puis émettez depuis `v6_src` :
   `iperf -c {group} -u -V -T 16 -t 30 -b 50K`. Lisez `show ipv6 mld groups` et
   `show ipv6 mroute` sur `v6_r2`. Quels autres groupes `v6_r2` connaît-il sur ce réseau, et
   pourquoi ?
""": """
The `v6` site is IPv6 only; the `pim6d` daemon runs on `v6_r1` and `v6_r2`
(section @@ref:ipv6@@).

1. Enable PIMv6 on the interfaces of both routers, and MLD on the interface of `v6_r2` on the
   side of `v6_h`. Check the neighbours (`show ipv6 pim neighbor`): under which address does
   the neighbour appear?
2. On `v6_h`, subscribe to the SSM channel ({src}, `{group}`):
   `iperf -s -u -V -B {group} -H {src} -i 1`, then send from `v6_src`:
   `iperf -c {group} -u -V -T 16 -t 30 -b 50K`. Read `show ipv6 mld groups` and
   `show ipv6 mroute` on `v6_r2`. Which other groups does `v6_r2` know on this network, and
   why?
""",
    """
**Solution.** Sur `v6_r1` : `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim`. Sur
`v6_r2` : `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim` et `ipv6 mld`. Le voisin
PIMv6 apparaît sous son adresse lien local (`fe80::…`). Le groupe est dans `ff3e::/32`, la plage
SSM par défaut de `pim6d` : l'abonnement MLDv2 de `v6_h` fait envoyer un *Join* (S,G) à `v6_r2`.
`show ipv6 mld groups` montre aussi `ff02::2`, `ff02::d`, `ff02::16` et les groupes
*solicited-node* (`ff02::1:ff…`) des adresses des machines du réseau.

Évaluation (bonus) : `v6_neighbor` (2 : voisinage PIMv6), `v6_mld` (1 : MLD sur `eth1` de `v6_r2`),
`v6_mld_group` (1 : `v6_r2` connaît le groupe du flux d'évaluation), `v6_stream` (2 : `v6_h` reçoit
le flux).
""": """
**Solution.** On `v6_r1`: `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim`. On
`v6_r2`: `interface eth0` / `ipv6 pim`, `interface eth1` / `ipv6 pim` and `ipv6 mld`. The PIMv6
neighbour appears under its link-local address (`fe80::…`). The group is in `ff3e::/32`, the
default SSM range of `pim6d`: the MLDv2 subscription of `v6_h` makes `v6_r2` send a *Join*
(S,G). `show ipv6 mld groups` also shows `ff02::2`, `ff02::d`, `ff02::16` and the
*solicited-node* groups (`ff02::1:ff…`) of the addresses of the machines of the network.

Grading (bonus): `v6_neighbor` (2: PIMv6 neighbours), `v6_mld` (1: MLD on `eth1` of `v6_r2`),
`v6_mld_group` (1: `v6_r2` knows the group of the grading stream), `v6_stream` (2: `v6_h`
receives the stream).
""",
    "voisinage PIMv6": "PIMv6 neighbours",
    "MLD du côté du récepteur": "MLD on the receiver's side",
    "v6_r2 connaît le groupe du récepteur": "v6_r2 knows the receiver's group",
    "v6_h reçoit le flux": "v6_h receives the stream",
}}
