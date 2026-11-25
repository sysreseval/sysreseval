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
``solve_<part>`` apply the reference solution of one part, ``final`` all of them.
"""
import json
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network, ip_address
from typing import Dict, List

import utils
from SRE import params
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
    spec = {'image': sre_docker_image("routing-frr13"), 'color': SITE_COLORS[site_of(machine)]}
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

    @sre_state(user_allowed=False, description=tr("Partie 1 : réponses du formulaire"))
    def solve_addressing(self):
        """Part 1 needs no machine: the state only fills its form (cheat_answers)."""
        self.cmd(SWITCH, "true")

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (IGMP)"))
    def solve_igmp(self):
        self._solution_igmp()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (IGMP snooping)"))
    def solve_snooping(self):
        self._solution_snooping()
        # the bridge counts as having a querier once its query response interval (10 s) is over
        self.cmd(SWITCH, "sleep 12", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (PIM-SM)"))
    def solve_asm(self):
        self._solution_asm()
        self.cmd('asm_r1', "sleep 10", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (PIM-SSM)"))
    def solve_ssm(self):
        self._solution_ssm()
        self.cmd('ssm_r1', "sleep 10", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (MSDP)"))
    def solve_msdp(self):
        self._solution_msdp()
        self.cmd('msdp_r1', "sleep 35", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 7 : solution (dépannage)"))
    def solve_fix(self):
        self._solution_fix()
        # fix_r1 accepts the Join of fix_r2 once it has heard its next Hello (30 s); `clear ip pim
        # interfaces` on fix_r2 made it worse live (it flushes the neighbours of fix_r2 too)
        self.cmd('fix_r1', "sleep 35", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 8 : solution (IPv6, bonus)"))
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
        members['ssm_src_lan'].append(f"`ssm_src` (2e adresse `{s2}`)")
        rows = [f"| `{net}` | `{getattr(d.nets, net)}` | {', '.join(members[net])} |" for net in NET_PLAN]
        rows += [f"| `{r}` lo | `{lo(r)}/32` | `{r}` |" for r in LOOPBACKS]
        for net in NET6_PLAN:
            ends = [f"`{r}` eth{ROUTER_IFACES[r].index(net)} (`{a(r, net)}`)" for r in ('v6_r1', 'v6_r2')
                    if net in ROUTER_IFACES[r]]
            ends += [f"`{h}` (`{getattr(d.ips6, h).ip}`)" for h in ('v6_src', 'v6_h') if HOSTS[h][0] == net]
            rows.append(f"| `{net}` | `{getattr(d.nets6, net)}` | {', '.join(ends)} |")
        addressing = "\n".join(rows)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
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
""").format(addressing=addressing, query_interval=d.query_interval, igmp_group=d.igmp_group,
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


_TRANSLATIONS = {}
