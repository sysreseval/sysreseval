"""MPLS VPN lab with Linux and FRR (bgpd, ldpd, ospfd): BGP/MPLS L3VPN and segment routing traffic
engineering.

IPv4 only, the provider is AS 65000.  Six independent sites, one per part (completing a part gives
all its points whatever the others):

- ``l3``: two PEs and a P router, OSPF and LDP given; two customers (VRFs) with the same prefixes on
  both PEs: the students create the VRFs, the iBGP VPNv4 session between the loopbacks and the
  VPN export / import of each VRF (RD, RT, VPN label);
- ``ce``: the same core with the VRF and the VPNv4 session given, and two CE routers of one
  customer AS: the students build the eBGP sessions PE-CE inside the VRF (``as-override``);
- ``ex``: three VRFs given with their own route targets; the students change the imports so that
  both customers reach a shared services VRF while staying isolated from each other (extranet);
- ``te``: five routers with OSPF and segment routing given; the students steer the traffic of two
  hosts through a waypoint with a label stack pushed by the ingress router;
- ``fix``: an L3VPN shipped with four faults (route target mismatch, no VPN label, VPNv4 neighbour
  not activated, customer interface outside the VRF);
- ``sv`` (bonus): an L3VPN given over a core without LDP; the students carry it with segment routing.

The MPLS modules of the host are loaded by the kernel itself when ``initial`` asks a container for an
``encap mpls`` route (lib/mpls.py).  Grading reads the json output of vtysh (lib/frr.py), the kernel
tables, the VRF devices (lib/policy_routing.py), the per-interface MPLS counters and real pings.  The
states ``solve_<part>`` apply the reference solution of one part, ``final`` all of them.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import NetConfigEntry, set_net_config_entry, remount_proc_sys
from bridging import get_ip_links
from policy_routing import vrf_devices, vrf_of_port
from frr import (
    get_bgp_routes, get_bgp_summary, get_bgp_vpn_routes, get_bgp_vpn_summary, get_frr_routes, get_frr_running_config,
    get_kernel_routes, get_ospf_sr_database, kernel_route_labels,
)
from mpls import get_mpls_counters, mpls_counter_delta, trigger_mpls_modules_cmd

default_language = 'fr'
tr = make_tr(default_language)

title = tr("MPLS : VPN BGP/MPLS et ingénierie de trafic segment routing",
           en="MPLS: BGP/MPLS VPNs and segment routing traffic engineering")
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

# Router interfaces in ethN order: the network of each.  A PE has its customer interfaces first.
ROUTER_IFACES = {
    'l3_pe1': ['l3_a1_lan', 'l3_b1_lan', 'l3_l1'],
    'l3_p': ['l3_l1', 'l3_l2'],
    'l3_pe2': ['l3_a2_lan', 'l3_b2_lan', 'l3_l2'],
    'ce_pe1': ['ce_link1', 'ce_l1'],
    'ce_p': ['ce_l1', 'ce_l2'],
    'ce_pe2': ['ce_link2', 'ce_l2'],
    'ce_c1': ['ce_link1'],
    'ce_c2': ['ce_link2'],
    'ex_pe1': ['ex_a_lan', 'ex_b_lan', 'ex_l1'],
    'ex_pe2': ['ex_s_lan', 'ex_l1'],
    'te_pe1': ['te_lan1', 'te_l12', 'te_l14'],
    'te_r2': ['te_l12', 'te_l25'],
    'te_r3': ['te_l34', 'te_l35'],
    'te_r4': ['te_l14', 'te_l34'],
    'te_pe5': ['te_lan5', 'te_l25', 'te_l35'],
    'fix_pe1': ['fix_a1_lan', 'fix_l1'],
    'fix_p': ['fix_l1', 'fix_l2'],
    'fix_pe2': ['fix_a2_lan', 'fix_l2'],
    'sv_pe1': ['sv_a1_lan', 'sv_l1'],
    'sv_p': ['sv_l1', 'sv_l2'],
    'sv_pe2': ['sv_a2_lan', 'sv_l2'],
}
# Hosts (one interface, eth0): their network and the router of their default route
HOSTS = {
    'l3_a1': ('l3_a1_lan', 'l3_pe1'), 'l3_b1': ('l3_b1_lan', 'l3_pe1'),
    'l3_a2': ('l3_a2_lan', 'l3_pe2'), 'l3_b2': ('l3_b2_lan', 'l3_pe2'),
    'ex_a': ('ex_a_lan', 'ex_pe1'), 'ex_b': ('ex_b_lan', 'ex_pe1'), 'ex_s': ('ex_s_lan', 'ex_pe2'),
    'te_h1': ('te_lan1', 'te_pe1'), 'te_h5': ('te_lan5', 'te_pe5'),
    'fix_a1': ('fix_a1_lan', 'fix_pe1'), 'fix_a2': ('fix_a2_lan', 'fix_pe2'),
    'sv_a1': ('sv_a1_lan', 'sv_pe1'), 'sv_a2': ('sv_a2_lan', 'sv_pe2'),
}
# provider links (/30): the first router gets .1, the second .2
LINKS = {
    'l3_l1': ('l3_pe1', 'l3_p'), 'l3_l2': ('l3_p', 'l3_pe2'),
    'ce_l1': ('ce_pe1', 'ce_p'), 'ce_l2': ('ce_p', 'ce_pe2'),
    'ex_l1': ('ex_pe1', 'ex_pe2'),
    'te_l12': ('te_pe1', 'te_r2'), 'te_l25': ('te_r2', 'te_pe5'), 'te_l14': ('te_pe1', 'te_r4'),
    'te_l34': ('te_r4', 'te_r3'), 'te_l35': ('te_r3', 'te_pe5'),
    'fix_l1': ('fix_pe1', 'fix_p'), 'fix_l2': ('fix_p', 'fix_pe2'),
    'sv_l1': ('sv_pe1', 'sv_p'), 'sv_l2': ('sv_p', 'sv_pe2'),
}
# PE - CE links (/30, inside the customer's VRF): the PE gets .1
CE_LINKS = {'ce_link1': ('ce_pe1', 'ce_c1'), 'ce_link2': ('ce_pe2', 'ce_c2')}
# customer and host networks (/24): the router gets .1
LANS = ['l3_a1_lan', 'l3_b1_lan', 'l3_a2_lan', 'l3_b2_lan', 'ex_a_lan', 'ex_b_lan', 'ex_s_lan', 'te_lan1',
        'te_lan5', 'fix_a1_lan', 'fix_a2_lan', 'sv_a1_lan', 'sv_a2_lan']
# OSPF costs of the te site (the shortest path between the PEs goes through te_r2)
TE_COSTS = {'te_l12': 10, 'te_l25': 10, 'te_l14': 10, 'te_l34': 10, 'te_l35': 30}
# loopback number of the provider routers
LOOPBACKS = {
    'l3_pe1': 1, 'l3_p': 2, 'l3_pe2': 3, 'ce_pe1': 1, 'ce_p': 2, 'ce_pe2': 3, 'ex_pe1': 1, 'ex_pe2': 2,
    'te_pe1': 1, 'te_r2': 2, 'te_r3': 3, 'te_r4': 4, 'te_pe5': 5, 'fix_pe1': 1, 'fix_p': 2, 'fix_pe2': 3,
    'sv_pe1': 1, 'sv_p': 2, 'sv_pe2': 3,
}
# the customer routers, configured by the lab, without terminal
OPERATORS = ('ce_c1', 'ce_c2')
PROVIDER_ROUTERS = [r for r in ROUTER_IFACES if r not in OPERATORS]
LDP_ROUTERS = [r for r in PROVIDER_ROUTERS if r.startswith(('l3_', 'ce_', 'ex_', 'fix_'))]
PE_ROUTERS = ['l3_pe1', 'l3_pe2', 'ce_pe1', 'ce_pe2', 'ex_pe1', 'ex_pe2', 'fix_pe1', 'fix_pe2', 'sv_pe1',
              'sv_pe2']
BGP_ROUTERS = PE_ROUTERS + list(OPERATORS)

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

SITE_COLORS = {'l3': 'lightblue', 'ce': 'palegreen', 'ex': 'khaki', 'te': 'plum', 'fix': 'lightsalmon',
               'sv': 'lightcyan'}

# ---------------------------------------------------------------------------
# addressing: one /16 of 10.0.0.0/8 per instance for the provider (site s uses the third octets 16s
# to 16s + 15: 16s = the /30 links, 16s + 15 = loopbacks); the customer networks come from
# 172.16.0.0/12 (site s: 172.(16 + s).x.0/24) except the two customers of the l3 site, which share
# one random pair of /24 of 192.168.0.0/16
# ---------------------------------------------------------------------------

SITE_NUMBER = {'l3': 1, 'ce': 2, 'ex': 3, 'te': 4, 'fix': 5, 'sv': 6}
LOOPBACK_OCTET = 15
PROVIDER_AS = 65000
CUSTOMER_AS = 65101
PLATFORM_LABELS = 100000
SRGB_BASE = 16000                 # FRR's default SRGB (te and sv sites)
SRGB_SIZE = 8000
# VRFs: name, kernel table
VRFS = {'l3_pe1': [('CUST_A', 10, 'eth0'), ('CUST_B', 20, 'eth1')],
        'l3_pe2': [('CUST_A', 10, 'eth0'), ('CUST_B', 20, 'eth1')],
        'ce_pe1': [('CUST_C', 30, 'eth0')], 'ce_pe2': [('CUST_C', 30, 'eth0')],
        'ex_pe1': [('CUST_A', 10, 'eth0'), ('CUST_B', 20, 'eth1')], 'ex_pe2': [('SERVICES', 40, 'eth0')],
        'fix_pe1': [('CUST_A', 10, 'eth0')], 'fix_pe2': [('CUST_A', 10, 'eth0')],
        'sv_pe1': [('CUST_A', 10, 'eth0')], 'sv_pe2': [('CUST_A', 10, 'eth0')]}
# the VRFs given at start (the l3 site has none)
GIVEN_VRF_SITES = ('ce', 'ex', 'fix', 'sv')
CONVERGE_WAIT = 25
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP{note}
# (zebra, mgmtd, staticd et watchfrr démarrent toujours)
bgpd={bgpd}
ospfd={ospfd}
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd={ldpd}
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
    return f"eth{ROUTER_IFACES[router].index(net)}"


def core_ifaces(router: str) -> List[str]:
    return [f"eth{i}" for i, net in enumerate(ROUTER_IFACES[router]) if net in LINKS]


def frr_daemons(router: str) -> str:
    on = {'bgpd': router in BGP_ROUTERS, 'ospfd': router in PROVIDER_ROUTERS, 'ldpd': router in LDP_ROUTERS}
    note = " : " + ", ".join(name for name, value in on.items() if value) + " activés"
    return FRR_DAEMONS.format(note=note, **{k: 'yes' if v else 'no' for k, v in on.items()})


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    rt_a: int = 0             # route target / RD numbers (65000:N) of the customer VRFs
    rt_b: int = 0
    rt_c: int = 0
    rt_s: int = 0             # the services VRF of the ex site
    te_index1: int = 0        # prefix-SID indexes of the te routers (te_pe1, te_r2, te_r3, te_r4, te_pe5)
    te_index2: int = 0
    te_index3: int = 0
    te_index4: int = 0
    te_index5: int = 0
    sv_index1: int = 0        # prefix-SID indexes of the sv routers (sv_pe1, sv_p, sv_pe2)
    sv_index2: int = 0
    sv_index3: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.rt_a, data.rt_b, data.rt_c, data.rt_s = random.sample(range(10, 100), 4)
        (data.te_index1, data.te_index2, data.te_index3, data.te_index4,
         data.te_index5) = random.sample(range(1, 100), 5)
        data.sv_index1, data.sv_index2, data.sv_index3 = random.sample(range(1, 100), 3)

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        pair = random_ipv4networks(23, from_network=IPv4Network('192.168.0.0/16'))[0]
        site1, site2 = list(pair.subnets(new_prefix=24))
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            for k, net in enumerate(n for n in LINKS if site_of(n) == site):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET))
            customer = IPv4Network(f"172.{16 + number}.0.0/16")
            lans = [n for n in LANS if site_of(n) == site]
            for j, net in enumerate(lans):
                setattr(data.nets, net, _subnet(customer, 1 + j))
        # the two customers of the l3 site use the same two prefixes
        data.nets.l3_a1_lan = data.nets.l3_b1_lan = site1
        data.nets.l3_a2_lan = data.nets.l3_b2_lan = site2
        # the ce site: the PE - CE links and the networks of the two customer sites
        data.nets.ce_link1 = IPv4Network('172.18.0.0/30')
        data.nets.ce_link2 = IPv4Network('172.18.0.4/30')
        data.nets.ce_site1, data.nets.ce_site2 = random.sample(list(IPv4Network('172.18.0.0/16').subnets(new_prefix=24))[16:], 2)
        for net, (first, second) in list(LINKS.items()) + list(CE_LINKS.items()):
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for router, nets in ROUTER_IFACES.items():
            for net in nets:
                if net in LANS:
                    network = getattr(data.nets, net)
                    setattr(data.ips, f"{router}_{net}", IPv4Interface((int(network.network_address) + 1, 24)))
        # host addresses: the hosts of the two l3 customers never share an address
        a_host, b_host = random.sample(range(10, 250), 2)
        for host, (net, _gw) in HOSTS.items():
            network = getattr(data.nets, net)
            number = a_host if host in ('l3_a1', 'l3_a2') else b_host if host in ('l3_b1', 'l3_b2') \
                else random.randint(10, 250)
            setattr(data.ips, host, IPv4Interface((int(network.network_address) + number, 24)))
        for ce, net in (('ce_c1', 'ce_site1'), ('ce_c2', 'ce_site2')):
            network = getattr(data.nets, net)
            setattr(data.ips, f"{ce}_site", IPv4Interface((int(network.network_address) + 1, 24)))
        for router, number in LOOPBACKS.items():
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + number, 32)))
        return data

    def te_index(self, router: str) -> int:
        return getattr(self, f"te_index{LOOPBACKS[router] if router != 'te_pe5' else 5}")

    def sv_index(self, router: str) -> int:
        return getattr(self, f"sv_index{LOOPBACKS[router]}")


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("routing-frr13")
        spec['shape'] = 'box'
    if machine in OPERATORS:
        spec['allow_connection'] = False
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
            self.net_config[r] = [([getattr(d.ips, f"{r}_{net}")], []) for net in nets]
        for ce, link in (('ce_c1', 'ce_link1'), ('ce_c2', 'ce_link2')):
            self.net_config[ce] = [([getattr(d.ips, f"{ce}_{link}")], [])]
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(IPv4Network("0.0.0.0/0"), self.addr(gw, net))])]

        lines = []
        for r, nets in ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{self.addr(r, net)}\t{names}")
        for r in LOOPBACKS:
            lines.append(f"{self.lo(r)}\t{r}-lo")
        for h in HOSTS:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses ---------------------------------------------------------------

    def addr(self, router: str, net: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def rt(self, number: int) -> str:
        return f"{PROVIDER_AS}:{number}"

    def vrf_rt(self, router: str, vrf: str) -> str:
        d = self.data
        if vrf == 'CUST_C':
            return self.rt(d.rt_c)
        if vrf == 'SERVICES':
            return self.rt(d.rt_s)
        return self.rt(d.rt_a if vrf == 'CUST_A' else d.rt_b)

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le modèle des VPN BGP/MPLS"), tag="l3vpn")
            + tr("""
Un opérateur vend à ses clients un réseau privé entre leurs sites : chaque client croit avoir ses
propres liaisons, alors que tous partagent le même cœur. Le modèle **BGP/MPLS IP VPN** (RFC 4364,
« L3VPN ») le réalise ainsi :

- le routeur du client, **CE** (*Customer Edge*), est relié à un routeur de bordure de l'opérateur,
  **PE** (*Provider Edge*) ; les routeurs du cœur, **P**, ne relient que des routeurs de l'opérateur ;
- chaque PE range les routes de chaque client dans une **VRF** (*Virtual Routing and Forwarding*) :
  une table de routage séparée, à laquelle sont attachées les interfaces vers ce client. Deux
  clients peuvent donc utiliser les mêmes adresses ;
- les PE s'échangent les routes des VRF par **MP-BGP**, dans la famille **VPNv4** ;
- les paquets traversent le cœur avec **deux labels** : celui du sommet les mène au PE de sortie
  (LDP ou segment routing), celui du dessous désigne la VRF de destination.

Les routeurs P ne connaissent ni les clients ni BGP : ils commutent des labels vers les interfaces
de bouclage des PE (un cœur **sans BGP**). Seuls les PE concernés par un client connaissent ses
routes.
""")
            + info_subtitle(tr("Les VRF sous Linux"), tag="vrf-linux")
            + tr("""
Linux réalise une VRF avec une interface de type `vrf` liée à une table de routage ; les interfaces
qu'on lui attache (`master`) y mettent leurs routes connectées :

```
ip link add CUST_A type vrf table 10
ip link set CUST_A up
ip link set eth0 master CUST_A

ip -br link show type vrf
ip route show vrf CUST_A
ping -I CUST_A 192.168.1.10
ip vrf exec CUST_A ping 192.168.1.10
```

Une adresse déjà configurée sur `eth0` est gardée : sa route passe dans la table de la VRF. Une
interface laissée hors de la VRF reste dans la table principale, que la VRF ignore. FRR découvre
les VRF du noyau tout seul (`show vrf`) ; il ne les crée pas.
""")
            + info_subtitle(tr("Route distinguisher et route target"), tag="rd-rt")
            + tr("""
Deux attributs, souvent confondus, servent à des choses différentes :

- le **RD** (*Route Distinguisher*, 8 octets, écrit `AS:nombre` ou `adresse:nombre`) est collé
  devant chaque préfixe exporté : `65000:1:192.168.1.0/24`. Deux clients peuvent ainsi annoncer
  le même préfixe sans que BGP les confonde. Il **ne dit rien** de la VRF qui importera la route ;
- la **RT** (*Route Target*) est une communauté étendue : la VRF qui exporte une route lui en
  attache (ses RT d'**export**), et chaque VRF importe les routes qui portent une de ses RT
  d'**import**. Les RT décrivent donc la topologie du VPN.

Dans le cas simple (un VPN complet entre les sites d'un client), import et export valent la même
RT. Les autres topologies (section @@ref:vpn-topologies@@) jouent sur des listes différentes.
""")
            + info_subtitle(tr("MP-BGP et la famille VPNv4"), tag="vpnv4")
            + tr("""
BGP multiprotocole (RFC 4760) transporte d'autres familles qu'IPv4 : une famille est désignée par
un couple AFI / SAFI, et VPNv4 est **AFI 1 / SAFI 128**. Une route VPNv4 contient le RD, le
préfixe, le **label VPN** choisi par le PE qui l'annonce et ses RT.

- Les PE forment des sessions **iBGP entre leurs interfaces de bouclage** (`update-source lo`),
  activées dans la famille VPNv4 ; dans un grand réseau, des *route reflectors* évitent le maillage
  complet.
- Le **prochain saut** d'une route VPNv4 est l'interface de bouclage du PE qui l'annonce : pour
  l'utiliser, un PE doit avoir un **LSP** vers cette adresse (LDP ou segment routing).
- Un PE n'importe dans une VRF que les routes dont les RT correspondent ; il peut écarter les
  autres dès la réception.
""")
            + info_subtitle(tr("La pile de labels"), tag="label-stack")
            + tr("""
Un paquet d'un site A1 vers un site A2 du même client :

1. le PE d'entrée cherche la destination dans la VRF de A1 : la route VPN donne le PE de sortie
   (prochain saut BGP) et le **label VPN** annoncé par ce PE ;
2. il impose deux labels : en dessous le label VPN, au sommet le **label de transport** vers
   l'interface de bouclage du PE de sortie (le label LDP de son prochain saut, ou le node-SID) ;
3. les routeurs P commutent le label de transport ; l'avant-dernier le retire (PHP) ;
4. le PE de sortie reçoit le label VPN, le retire et cherche la destination dans la VRF qu'il
   désigne.

Un PE peut allouer un label VPN par préfixe, ou **un seul par VRF** (le PE de sortie fait alors une
recherche IP dans la VRF) : c'est ce que fait `label vpn export auto` dans FRR. Sous Linux, ce label
apparaît dans `ip -f mpls route` sous la forme `80 dev CUST_A`, et la route de la VRF du PE
d'entrée sous la forme `encap mpls 16/80`.

Sans LSP vers le PE de sortie, la route VPN peut quand même être installée avec le seul label
VPN : le premier routeur P reçoit alors un label qu'il ne connaît pas et jette le paquet.
""")
            + info_subtitle(tr("L3VPN avec FRR"), tag="l3vpn-frr")
            + tr("""
Sur chaque PE, après avoir créé les VRF dans le noyau :

```
configure terminal
router bgp 65000
 bgp router-id 10.0.15.1
 no bgp default ipv4-unicast
 neighbor 10.0.15.3 remote-as 65000
 neighbor 10.0.15.3 update-source lo
 address-family ipv4 vpn
  neighbor 10.0.15.3 activate
 exit-address-family
exit
router bgp 65000 vrf CUST_A
 address-family ipv4 unicast
  redistribute connected
  label vpn export auto
  rd vpn export 65000:1
  rt vpn both 65000:1
  export vpn
  import vpn
 exit-address-family
exit
end
write
```

- `router bgp 65000` : l'instance principale, qui porte la session VPNv4 ;
- `router bgp 65000 vrf X` : l'instance de la VRF ; `redistribute connected` (ou des sessions
  avec les CE) remplit sa table BGP ;
- `label vpn export auto` (sans label, rien n'est exporté), `rd vpn export`, `rt vpn both`
  (ou `rt vpn import ...` et `rt vpn export ...`, chacun avec une liste), `export vpn` (de la VRF
  vers VPNv4), `import vpn` (de VPNv4 vers la VRF).

| commande | ce qu'elle montre |
|----------|-------------------|
| `show bgp ipv4 vpn summary` | les sessions VPNv4 |
| `show bgp ipv4 vpn` | la table VPNv4, rangée par RD |
| `show bgp vrf X ipv4 unicast` | la table BGP de la VRF |
| `show ip route vrf X` | la table de la VRF vue par zebra, avec les labels |
| `ip route show vrf X`, `ip -f mpls route` | ce que le noyau a vraiment |
""")
            + info_subtitle(tr("Le routage entre PE et CE"), tag="pe-ce")
            + tr("""
Le PE apprend les réseaux d'un site par des routes statiques, les réseaux connectés ou un
protocole de routage avec le CE ; **eBGP** est le plus courant : le client a son propre numéro
d'AS. Sur le PE, la session est déclarée **dans l'instance de la VRF**
(`router bgp 65000 vrf X`, `neighbor <CE> remote-as <AS du client>`).

Souvent, tous les sites d'un client ont le **même AS**. Une route du site 1 arrive au site 2 avec
l'AS path `65000 65101` : le CE du site 2 y voit son propre AS et **refuse** la route (détection
de boucle de BGP). Deux remèdes :

- `neighbor <CE> as-override` sur le PE : il remplace l'AS du client par le sien dans l'AS path
  annoncé (`65000 65000`) ;
- `neighbor <PE> allowas-in` sur le CE : il accepte son propre AS.

Quand un site est relié à deux PE, l'as-override peut créer des boucles : la communauté **SoO**
(*Site of Origin*) marque les routes d'un site pour ne jamais les lui renvoyer. Comme pour toute
session eBGP, FRR n'échange rien sans politique d'entrée et de sortie (RFC 8212 : des route-maps).
""")
            + info_subtitle(tr("Topologies de VPN"), tag="vpn-topologies")
            + tr("""
Les RT d'import et d'export d'une VRF n'ont pas à être égales ; elles dessinent la topologie :

- **VPN complet** : chaque VRF exporte et importe la RT du client ;
- **extranet** (services partagés) : une VRF de services exporte sa propre RT, que les VRF des
  clients importent en plus de la leur ; elle importe les RT des clients. Chaque client joint les
  services, mais pas les autres clients : une route importée dans une VRF n'est **pas ré-exportée**,
  la VRF de services ne fait donc pas de pont entre eux ;
- **hub-and-spoke** : les sites (*spokes*) exportent une RT que seul le site central (*hub*)
  importe, et importent celle du hub : tout le trafic entre sites passe par le hub (un pare-feu,
  par exemple).
""")
            + info_subtitle(tr("Ingénierie de trafic avec le segment routing"), tag="sr-te")
            + tr("""
Avec le segment routing, le routeur d'entrée choisit un chemin en imposant une **liste de
segments** : par exemple le node-SID d'un routeur de passage (*waypoint*), puis le node-SID de la
destination. Le paquet suit le plus court chemin jusqu'au premier, qui le retire, puis le plus court
chemin jusqu'au second. Le cœur ne garde aucun état.

- Chaque label se calcule avec le SRGB (base + index) du routeur qui le lira. Avec le même SRGB
  partout, c'est simplement base + index.
- Le premier label est lu par le **voisin** auquel on envoie le paquet : on n'impose pas le node-SID
  d'un voisin direct, que celui-ci retirerait aussitôt (PHP) ; il suffit de l'envoyer vers lui.
- L'avant-dernier routeur de chaque segment retire son label (PHP) : le dernier routeur reçoit le
  paquet IP.

Avec FRR, une route statique peut imposer une pile de labels (`staticd`) ; avec le noyau, `ip route
... encap mpls 16003/16005` :

```
configure terminal
ip route 10.1.5.0/24 10.0.0.6 label 16003/16005
end
write
```

À plus grande échelle, des **politiques SR-TE** (démon `pathd` de FRR) calculent ces listes et y
dirigent le trafic, par exemple selon une couleur portée par les routes BGP.
""")
            + info_subtitle(tr("Un VPN sur un cœur segment routing"), tag="vpn-over-sr")
            + tr("""
Le label de transport d'un L3VPN peut venir du segment routing au lieu de LDP : c'est le
**node-SID** du PE de sortie. Il suffit d'activer le segment routing dans l'IGP du cœur, avec un
prefix-SID sur l'interface de bouclage de chaque PE ; aucune ligne de la configuration BGP ne
change : le PE d'entrée prend le label de la route vers le prochain saut BGP, quelle que soit son
origine. Le cœur n'a plus besoin de LDP.
""")
            + info_subtitle(tr("Dépannage d'un L3VPN"), tag="l3vpn-debug")
            + tr("""
Le chemin d'une route d'un site à l'autre, étape par étape :

1. la VRF du PE de départ contient-elle le réseau du site (interface attachée à la VRF, réseau
   connecté ou appris du CE) ? (`ip -br link show master X`, `show ip route vrf X`)
2. la route est-elle exportée en VPNv4, avec un label, le bon RD et la bonne RT ? (`show bgp ipv4
   vpn`, `label vpn export`, `export vpn`)
3. la session VPNv4 est-elle établie **et activée** dans la famille ? (`show bgp ipv4 vpn summary`)
4. le PE d'arrivée l'importe-t-il dans la VRF (RT d'import, `import vpn`) ? (`show bgp vrf X ipv4
   unicast`)
5. a-t-il un LSP vers le prochain saut BGP (label de transport) ? (`show ip route vrf X`,
   `ip route show vrf X` : deux labels)
6. dans l'autre sens, les mêmes questions.

| symptôme | cause probable |
|----------|----------------|
| aucune route dans `show bgp ipv4 vpn summary` | voisin non activé dans la famille VPNv4 |
| le PE reçoit la route VPNv4 mais la VRF ne l'a pas | RT d'import différente de la RT d'export |
| la route du site n'apparaît pas dans la table VPNv4 | pas de `label vpn export`, pas d'`export vpn`, ou réseau absent de la VRF |
| un seul label dans `ip route show vrf X` | pas de LSP vers le PE de sortie |
""")
        )

    # -- FRR configuration ---------------------------------------------------------

    def _ospf_lines(self, router: str) -> List[str]:
        lines = ["router ospf", f" ospf router-id {self.lo(router)}", "exit", "!"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            if net not in LINKS:
                continue
            statements = [" ip ospf area 0", " ip ospf network point-to-point"]
            if net in TE_COSTS:
                statements.append(f" ip ospf cost {TE_COSTS[net]}")
            lines += [f"interface eth{i}"] + statements + ["exit", "!"]
        if router.startswith('te_'):
            # the host networks of the te site are announced (passive)
            for i, net in enumerate(ROUTER_IFACES[router]):
                if net in LANS:
                    lines += [f"interface eth{i}", " ip ospf area 0", " ip ospf passive", "exit", "!"]
        lines += ["interface lo", " ip ospf area 0", "exit", "!"]
        return lines

    def _ldp_lines(self, router: str, interfaces=None) -> List[str]:
        lo = self.lo(router)
        lines = ["mpls ldp", f" router-id {lo}", " !", " address-family ipv4", f"  discovery transport-address {lo}"]
        lines += [f"  interface {name}" for name in (core_ifaces(router) if interfaces is None else interfaces)]
        return lines + [" exit-address-family", " !", "exit", "!"]

    def _sr_lines(self, router: str, index: int) -> List[str]:
        return ["router ospf", " capability opaque", " segment-routing on",
                f" segment-routing global-block {SRGB_BASE} {SRGB_BASE + SRGB_SIZE - 1}",
                f" segment-routing prefix {self.lo(router)}/32 index {index}", "exit", "!"]

    def peer_pe(self, pe: str) -> str:
        site = site_of(pe)
        return f"{site}_pe2" if pe.endswith('pe1') else f"{site}_pe1"

    def vpnv4_lines(self, pe: str, activate: bool = True) -> List[str]:
        """The iBGP session of a PE with the other PE of its site, between loopbacks, VPNv4 only."""
        peer = self.lo(self.peer_pe(pe))
        lines = [f"router bgp {PROVIDER_AS}", f" bgp router-id {self.lo(pe)}", " no bgp default ipv4-unicast",
                 f" neighbor {peer} remote-as {PROVIDER_AS}", f" neighbor {peer} update-source lo", " !",
                 " address-family ipv4 vpn"]
        if activate:
            lines.append(f"  neighbor {peer} activate")
        return lines + [" exit-address-family", "exit", "!"]

    def vrf_bgp_lines(self, pe: str, vrf: str, import_rts: List[str] = None, label: bool = True,
                      redistribute: bool = True, extra: List[str] = ()) -> List[str]:
        """``router bgp 65000 vrf X``: VPN export / import of the VRF (RD = RT = the number of the
        customer)."""
        rt = self.vrf_rt(pe, vrf)
        lines = [f"router bgp {PROVIDER_AS} vrf {vrf}", f" bgp router-id {self.lo(pe)}", *extra, " !",
                 " address-family ipv4 unicast"]
        if redistribute:
            lines.append("  redistribute connected")
        if label:
            lines.append("  label vpn export auto")
        lines.append(f"  rd vpn export {rt}")
        if import_rts is None:
            lines.append(f"  rt vpn both {rt}")
        else:
            lines += [f"  rt vpn import {' '.join(import_rts)}", f"  rt vpn export {rt}"]
        lines += ["  export vpn", "  import vpn", " exit-address-family", "exit", "!"]
        return lines

    def _frr_conf(self, router: str) -> str:
        d = self.data
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", "log file /var/log/frr/frr.log", "!"]
        site = site_of(router)
        if router in OPERATORS:
            link = 'ce_link1' if router == 'ce_c1' else 'ce_link2'
            site_net = self.net('ce_site1' if router == 'ce_c1' else 'ce_site2')
            pe = self.addr(CE_LINKS[link][0], link)
            lines += ["route-map ALL permit 10", "exit", "!",
                      f"router bgp {CUSTOMER_AS}", f" bgp router-id {getattr(d.ips, f'{router}_{link}').ip}",
                      f" neighbor {pe} remote-as {PROVIDER_AS}", " !", " address-family ipv4 unicast",
                      f"  network {site_net}", f"  neighbor {pe} route-map ALL in",
                      f"  neighbor {pe} route-map ALL out", " exit-address-family", "exit", "!"]
            return "\n".join(lines) + "\n"
        lines += self._ospf_lines(router)
        if router in LDP_ROUTERS:
            lines += self._ldp_lines(router)
        if site == 'te':
            lines += self._sr_lines(router, d.te_index(router))
        if router not in PE_ROUTERS or site == 'l3':
            return "\n".join(lines) + "\n"
        # the PEs of the sites with given VRFs
        if site == 'fix':
            # fault 3: the VPNv4 neighbour of fix_pe2 is not activated
            lines += self.vpnv4_lines(router, activate=(router != 'fix_pe2'))
            if router == 'fix_pe1':
                # fault 2: no VPN label, the routes of the VRF are not exported
                lines += self.vrf_bgp_lines(router, 'CUST_A', label=False)
            else:
                # fault 1: the import route target of fix_pe2 is the wrong one
                lines += self.vrf_bgp_lines(router, 'CUST_A', import_rts=[self.rt(d.rt_b)])
        else:
            lines += self.vpnv4_lines(router)
            for vrf, _table, _ifname in VRFS[router]:
                lines += self.vrf_bgp_lines(router, vrf, redistribute=(site != 'ce'))
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    @staticmethod
    def vrf_cmds(router: str, vrfs=None) -> List[str]:
        """The shell commands that create the VRF devices of *router* and enslave their interfaces."""
        cmds = []
        for vrf, table, ifname in (VRFS[router] if vrfs is None else vrfs):
            cmds += [f"ip link add {vrf} type vrf table {table}", f"ip link set {vrf} up",
                     f"ip link set {ifname} master {vrf}"]
        return cmds

    # -- reference solutions -------------------------------------------------------

    @staticmethod
    def _flat(lines: List[str]) -> List[str]:
        """vtysh commands from configuration lines (indentation, ``!`` and blank lines dropped)."""
        return [x.strip() for x in lines if x.strip() and x.strip() != '!']

    def solution_l3(self) -> Dict[str, Dict[str, List[str]]]:
        """{router: {'sh': [...], 'vtysh': [...]}} of part 1."""
        result = {}
        for pe in ('l3_pe1', 'l3_pe2'):
            vtysh = self._flat(self.vpnv4_lines(pe))
            for vrf, _table, _ifname in VRFS[pe]:
                vtysh += self._flat(self.vrf_bgp_lines(pe, vrf))
            result[pe] = {'sh': self.vrf_cmds(pe), 'vtysh': vtysh}
        return result

    def solution_ce(self) -> Dict[str, List[str]]:
        result = {}
        for pe, link, ce in (('ce_pe1', 'ce_link1', 'ce_c1'), ('ce_pe2', 'ce_link2', 'ce_c2')):
            ce_addr = self.addr(ce, link)
            result[pe] = ["route-map ALL permit 10", "exit", f"router bgp {PROVIDER_AS} vrf CUST_C",
                          f"neighbor {ce_addr} remote-as {CUSTOMER_AS}", "address-family ipv4 unicast",
                          f"neighbor {ce_addr} activate", f"neighbor {ce_addr} as-override",
                          f"neighbor {ce_addr} route-map ALL in", f"neighbor {ce_addr} route-map ALL out",
                          "exit-address-family", "exit"]
        return result

    def solution_ex(self) -> Dict[str, List[str]]:
        d = self.data
        a, b, s = self.rt(d.rt_a), self.rt(d.rt_b), self.rt(d.rt_s)
        return {
            'ex_pe1': [f"router bgp {PROVIDER_AS} vrf CUST_A", "address-family ipv4 unicast", f"rt vpn import {a} {s}",
                       "exit-address-family", "exit",
                       f"router bgp {PROVIDER_AS} vrf CUST_B", "address-family ipv4 unicast", f"rt vpn import {b} {s}",
                       "exit-address-family", "exit"],
            'ex_pe2': [f"router bgp {PROVIDER_AS} vrf SERVICES", "address-family ipv4 unicast",
                       f"rt vpn import {s} {a} {b}", "exit-address-family", "exit"],
        }

    def te_stack_out(self) -> List[int]:
        """The labels te_pe1 pushes towards te_lan5: the node-SID of the waypoint te_r3, then the
        node-SID of te_pe5."""
        d = self.data
        return [SRGB_BASE + d.te_index('te_r3'), SRGB_BASE + d.te_index('te_pe5')]

    def te_stack_back(self) -> List[int]:
        """The label te_pe5 pushes towards te_lan1 through te_r3 (its neighbour: the node-SID of
        te_r3 itself would be popped at once)."""
        return [SRGB_BASE + self.data.te_index('te_pe1')]

    def solution_te(self) -> Dict[str, List[str]]:
        out = "/".join(str(x) for x in self.te_stack_out())
        back = "/".join(str(x) for x in self.te_stack_back())
        return {'te_pe1': [f"ip route {self.net('te_lan5')} {self.addr('te_r4', 'te_l14')} label {out}"],
                'te_pe5': [f"ip route {self.net('te_lan1')} {self.addr('te_r3', 'te_l35')} label {back}"]}

    def solution_fix(self) -> Dict[str, Dict[str, List[str]]]:
        d = self.data
        a = self.rt(d.rt_a)
        peer1 = self.lo('fix_pe1')
        return {
            'fix_pe1': {'sh': [], 'vtysh': [f"router bgp {PROVIDER_AS} vrf CUST_A", "address-family ipv4 unicast",
                                            "label vpn export auto", "exit-address-family", "exit"]},
            'fix_pe2': {'sh': ["ip link set eth0 master CUST_A"],
                        'vtysh': [f"router bgp {PROVIDER_AS}", "address-family ipv4 vpn", f"neighbor {peer1} activate",
                                  "exit-address-family", "exit",
                                  f"router bgp {PROVIDER_AS} vrf CUST_A", "address-family ipv4 unicast",
                                  f"no rt vpn import {self.rt(d.rt_b)}", f"rt vpn import {a}",
                                  "exit-address-family", "exit"]},
        }

    def solution_sv(self) -> Dict[str, List[str]]:
        d = self.data
        return {r: ["router ospf", "capability opaque", "segment-routing on",
                    f"segment-routing global-block {SRGB_BASE} {SRGB_BASE + SRGB_SIZE - 1}",
                    f"segment-routing prefix {self.lo(r)}/32 index {d.sv_index(r)}", "exit"]
                for r in ('sv_pe1', 'sv_p', 'sv_pe2')}

    # -- applying the solutions ----------------------------------------------------

    def _apply_mixed(self, solution: Dict[str, Dict[str, List[str]]], step: int = 1):
        for r, parts in solution.items():
            for c in parts['sh']:
                self.cmd(r, c, step=step)
            self._vtysh(r, *parts['vtysh'], step=step)

    def _apply(self, solution: Dict[str, List[str]], step: int = 1):
        for r, cmds in solution.items():
            self._vtysh(r, *cmds, step=step)

    def _apply_fix(self, step: int = 1):
        self._apply_mixed(self.solution_fix(), step=step)
        # the interface entered the VRF after the VRF instance of bgpd: redistribute it again
        self.cmd('fix_pe2', 'vtysh -c "clear bgp vrf CUST_A ipv4 unicast * soft"', step=step, allow_error=True)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for ce in OPERATORS:
            self.cmd(ce, "ip link add lan0 type dummy")
            self.cmd(ce, f"ip addr add {getattr(d.ips, f'{ce}_site')} dev lan0")
            self.cmd(ce, "ip link set lan0 up")
        for r in PROVIDER_ROUTERS:
            remount_proc_sys(self, r)
            self.cmd(r, trigger_mpls_modules_cmd())
        for r in LOOPBACKS:
            self.cmd(r, f"ip addr add {getattr(d.ips, f'{r}_lo')} dev lo")
        for r in PE_ROUTERS:
            if site_of(r) in GIVEN_VRF_SITES:
                vrfs = VRFS[r]
                if r == 'fix_pe2':
                    # fault 4: the VRF exists, the customer interface is not in it
                    self.cmd(r, "ip link add CUST_A type vrf table 10")
                    self.cmd(r, "ip link set CUST_A up")
                    vrfs = []
                for c in self.vrf_cmds(r, vrfs):
                    self.cmd(r, c)
        for r in ROUTER_IFACES:
            if r in PROVIDER_ROUTERS:
                self.cmd(r, f"sysctl -w net.mpls.platform_labels={PLATFORM_LABELS}", step=2)
                for name in core_ifaces(r):
                    self.cmd(r, f"sysctl -w net.mpls.conf.{name}.input=1", step=2)
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (L3VPN)"))
    def solve_l3(self):
        self._apply_mixed(self.solution_l3())
        self.cmd('l3_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (eBGP entre PE et CE)"))
    def solve_ce(self):
        self._apply(self.solution_ce())
        self.cmd('ce_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (extranet)"))
    def solve_ex(self):
        self._apply(self.solution_ex())
        self.cmd('ex_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (ingénierie de trafic)"))
    def solve_te(self):
        self._apply(self.solution_te())
        self.cmd('te_pe1', "sleep 3", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (dépannage)"))
    def solve_fix(self):
        self._apply_fix()
        self.cmd('fix_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 6 : solution (VPN sur segment routing, bonus)"))
    def solve_sv(self):
        self._apply(self.solution_sv())
        self.cmd('sv_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        self._apply_mixed(self.solution_l3())
        self._apply(self.solution_ce())
        self._apply(self.solution_ex())
        self._apply(self.solution_te())
        self._apply_fix()
        self._apply(self.solution_sv())
        self.cmd('l3_pe1', f"sleep {CONVERGE_WAIT}", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s):
    try:
        return int(_norm(s).replace(' ', ''))
    except ValueError:
        return None


def _labels(s) -> List[int]:
    """A typed label stack: ``16007/16025``, ``16007 16025``, ``[16007, 16025]``."""
    return [int(x) for x in re.findall(r'\d+', str(s or ''))]


def _rts(s) -> List[str]:
    """The route targets of a typed answer, in a canonical order."""
    return sorted(set(re.findall(r'\d+:\d+', str(s or ''))))


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    blocks = []
    for router, cmds in solution.items():
        body = "\n".join(["configure terminal"] + [f" {c}" for c in cmds] + ["end", "write"])
        blocks.append(f"`{router}` :\n\n```\n{body}\n```")
    return "\n\n".join(blocks)


def _mixed_text(solution: Dict[str, Dict[str, List[str]]]) -> str:
    blocks = []
    for router, parts in solution.items():
        text = f"`{router}` :\n\n"
        if parts['sh']:
            text += "```\n" + "\n".join(parts['sh']) + "\n```\n\n"
        text += "```\n" + "\n".join(["configure terminal"] + [f" {c}" for c in parts['vtysh']] + ["end", "write"]) + "\n```"
        blocks.append(text)
    return "\n\n".join(blocks)


def _route_via(routes: Dict[str, Dict], prefix, labels: List[int], gateway) -> bool:
    entry = routes.get(str(prefix)) or {}
    return any(stack == labels and str(gw) == str(gateway)
               for (gw, _dev), stack in zip(entry.get('nexthops', []), entry.get('labels', [])))


def _stack_of(routes: Dict[str, Dict], prefix) -> List[int]:
    stacks = kernel_route_labels(routes, prefix)
    return stacks[0] if stacks else []


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest, source=None, count: int = 3) -> bool:
        option = f" -I {source}" if source else ""
        _out, code = self.test(src, f"ping -c {count} -i 0.2 -w 3{option} {dest}", allow_error=True)
        return code == 0

    def _burst(self, src: str, dest) -> bool:
        _out, code = self.test(src, f"ping -c 5 -i 0.2 -w 4 {dest}", step=2, allow_error=True)
        return code == 0

    def _counters_delta(self, router: str, ifname: str) -> int:
        return mpls_counter_delta(get_mpls_counters(self, router, step=1), get_mpls_counters(self, router, step=3),
                                  ifname)

    @staticmethod
    def _established(summary: Dict, peer) -> bool:
        return bool(((summary.get('peers') or {}).get(str(peer)) or {}).get('established'))

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net, rt = ns.lo, ns.addr, ns.net, ns.rt
        ip = lambda host: getattr(d.ips, host).ip   # noqa: E731

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        l3 = ('l3_pe1', 'l3_pe2')
        l3_vrfs = {r: vrf_devices(get_ip_links(self, r)) for r in l3}
        l3_vpn_sum = get_bgp_vpn_summary(self, 'l3_pe1')
        l3_vpn = {r: get_bgp_vpn_routes(self, r) for r in l3}
        l3_k = {(r, v): get_kernel_routes(self, r, allow_error=True, vrf=v) for r in l3 for v in ('CUST_A', 'CUST_B')}
        l3_ping_a = self._ping('l3_a1', ip('l3_a2'))
        l3_ping_b = self._ping('l3_b1', ip('l3_b2'))
        l3_cross = self._ping('l3_a1', ip('l3_b2'), count=2)

        ce_sum = {r: get_bgp_summary(self, r, allow_error=True, vrf='CUST_C') for r in ('ce_pe1', 'ce_pe2')}
        ce_routes = {r: get_bgp_routes(self, r, allow_error=True) for r in ('ce_c1', 'ce_c2')}
        ce_ping = self._ping('ce_c1', d.ips.ce_c2_site.ip, source=d.ips.ce_c1_site.ip)

        ex_rib = {('ex_pe1', 'CUST_A'): get_frr_routes(self, 'ex_pe1', vrf='CUST_A'),
                  ('ex_pe1', 'CUST_B'): get_frr_routes(self, 'ex_pe1', vrf='CUST_B'),
                  ('ex_pe2', 'SERVICES'): get_frr_routes(self, 'ex_pe2', vrf='SERVICES')}
        ex_a_s = self._ping('ex_a', ip('ex_s'))
        ex_b_s = self._ping('ex_b', ip('ex_s'))
        ex_a_b = self._ping('ex_a', ip('ex_b'), count=2)

        te_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('te_pe1', 'te_pe5')}
        te_ping = self._burst('te_h1', ip('te_h5'))
        te_delta = {name: self._counters_delta('te_r3', name) for name in ('eth0', 'eth1')}

        fix_cfg = {r: get_frr_running_config(self, r, allow_error=True) for r in ('fix_pe1', 'fix_pe2')}
        fix_vrfs = vrf_devices(get_ip_links(self, 'fix_pe2'))
        fix_vpn_sum = get_bgp_vpn_summary(self, 'fix_pe2')
        fix_ping = self._burst('fix_a1', ip('fix_a2'))
        fix_delta = self._counters_delta('fix_p', 'eth0')

        sv = ('sv_pe1', 'sv_p', 'sv_pe2')
        sv_db = {r: get_ospf_sr_database(self, r) for r in sv}
        sv_k = get_kernel_routes(self, 'sv_pe1', allow_error=True, vrf='CUST_A')
        sv_ping = self._ping('sv_a1', ip('sv_a2'))

        # ---------------- texts shared by the questions ---------------------------
        sites = [('l3', "1 — L3VPN", "`l3_pe1`, `l3_p`, `l3_pe2`, les hôtes `l3_a1`, `l3_a2` (client A), `l3_b1`, "
                                     "`l3_b2` (client B)"),
                 ('ce', "2 — eBGP entre PE et CE", "`ce_pe1`, `ce_p`, `ce_pe2`, les CE `ce_c1` et `ce_c2` (sans terminal)"),
                 ('ex', "3 — extranet", "`ex_pe1`, `ex_pe2`, les hôtes `ex_a`, `ex_b`, `ex_s`"),
                 ('te', "4 — ingénierie de trafic", "`te_pe1`, `te_r2`, `te_r3`, `te_r4`, `te_pe5`, les hôtes `te_h1`, "
                                                    "`te_h5`"),
                 ('fix', "5 — dépannage", "`fix_pe1`, `fix_p`, `fix_pe2`, les hôtes `fix_a1`, `fix_a2`"),
                 ('sv', "6 — VPN sur segment routing (bonus)", "`sv_pe1`, `sv_p`, `sv_pe2`, les hôtes `sv_a1`, `sv_a2`")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + list(CE_LINKS) + LANS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                members[n].append(f"`{r}` eth{i} (`{addr(r, n)}`)")
        for h, (n, _gw) in HOSTS.items():
            members[n].append(f"`{h}` (`{ip(h)}`)")
        address_rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in list(LINKS) + list(CE_LINKS) + LANS]
        address_rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                         + ", ".join(f"`{r}` `{lo(r)}/32`" for r in LOOPBACKS if site_of(r) == site) + " |"
                         for site in SITE_NUMBER]
        address_rows += [f"| `ce_site1` | `{net('ce_site1')}` | `ce_c1` lan0 (`{d.ips.ce_c1_site.ip}`) |",
                         f"| `ce_site2` | `{net('ce_site2')}` | `ce_c2` lan0 (`{d.ips.ce_c2_site.ip}`) |"]
        addressing = "\n".join(address_rows)
        te_idx = ", ".join(f"`{r}` **{d.te_index(r)}**" for r in ('te_pe1', 'te_r2', 'te_r3', 'te_r4', 'te_pe5'))
        sv_idx = ", ".join(f"`{r}` **{d.sv_index(r)}**" for r in sv)
        te_costs = ", ".join(f"`{n}` {c}" for n, c in TE_COSTS.items())

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="9255c04097daaa37",
            description=tr("""
Lisez l'onglet **Informations** : il présente les VPN BGP/MPLS et l'ingénierie de trafic avec le
segment routing, et leur mise en œuvre avec Linux et FRR. Le TP suppose connus MPLS, LDP et le
segment routing (TP « MPLS : commutation de labels, LDP et segment routing »).

**Le réseau.** Il est fait de **six sites indépendants**, un par partie. L'opérateur est l'AS
**{pas}** ; chaque site a sa couleur sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) : configurez-les avec `vtysh`. Dans chaque site,
  **OSPF fonctionne** entre les routeurs de l'opérateur (interfaces de bouclage annoncées), ainsi
  que **LDP** sur les sites `l3`, `ce`, `ex` et `fix` ; `bgpd` est activé sur les PE et les CE.
- MPLS est activé dans les noyaux des routeurs de l'opérateur (table des labels et entrée MPLS des
  interfaces du cœur).
- Les VRF des sites `ce`, `ex`, `fix` et `sv` existent déjà, avec leur session VPNv4 ; celles du
  site `l3` sont à créer. Les CE `ce_c1` et `ce_c2` (AS **{cas}**) sont configurés et n'ont pas de
  terminal.
- Les fichiers `/etc/hosts` contiennent les noms : `l3_p-eth1` désigne l'adresse de l'interface
  `eth1` de `l3_p`, `l3_pe2-lo` l'adresse de bouclage de `l3_pe2`.

**Plan d'adressage.** Les liens de l'opérateur sont des /30, les réseaux des clients des /24 ; les
clients A et B du site `l3` utilisent **les mêmes préfixes**.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- VRF et RD / RT (RD = RT) : `CUST_A` **{rt_a}** (table 10), `CUST_B` **{rt_b}** (table 20),
  `CUST_C` **{rt_c}** (table 30), `SERVICES` **{rt_s}** (table 40).
- Partie 4 : coûts OSPF {te_costs} ; SRGB 16000 à 23999 ; index des prefix-SID : {te_idx}.
- Partie 6 : index des prefix-SID : {sv_idx}.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`). Les commandes `ip` ne sont pas
  enregistrées : ne redémarrez pas les machines.
- Une session BGP s'établit en quelques secondes ; une route VPN met quelques secondes de plus à
  arriver dans la VRF distante.

**Évaluation.** Chaque évaluation lit vos réponses, les VRF, l'état de BGP (VPNv4, VRF), les tables
des VRF et du noyau, puis envoie des `ping` en comptant les paquets étiquetés reçus par certains
routeurs. Elle dure une quinzaine de secondes.
""").format(site_rows=site_rows, addressing=addressing, pas=PROVIDER_AS, cas=CUSTOMER_AS, rt_a=rt(d.rt_a),
            rt_b=rt(d.rt_b), rt_c=rt(d.rt_c), rt_s=rt(d.rt_s), te_costs=te_costs, te_idx=te_idx, sv_idx=sv_idx)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_l3`, `solve_ce`, `solve_ex`, `solve_te`, `solve_fix` et `solve_sv`
(onglet *Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes, attend {wait} s (sessions BGP, routes VPN) puis
remplit tous les formulaires : une évaluation lancée dès son retour donne tous les points, bonus
compris.

Les pannes du site `fix` : RT d'import de `CUST_A` sur `fix_pe2` égale à {wrong} au lieu de
{rt_a}, pas de `label vpn export` dans `CUST_A` sur `fix_pe1` (ses routes ne sont pas exportées),
voisin `fix_pe1` non activé dans la famille VPNv4 sur `fix_pe2`, `eth0` de `fix_pe2` hors de la VRF
`CUST_A`. Sur le site `sv`, sans LDP, la route VPN est installée avec le seul label VPN : `sv_p`
jette les paquets.
""").format(wait=CONVERGE_WAIT, wrong=rt(d.rt_b), rt_a=rt(d.rt_a))),
        )

        # =====================================================================
        # Part 1 — L3VPN (l3)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("l3vpn"), tr("Partie 1 — un L3VPN pour deux clients (site l3)"))
        site1, site2 = net('l3_a1_lan'), net('l3_a2_lan')
        self.question_dummy(
            section=self.section(0),
            title=tr("Un L3VPN pour deux clients"),
            hash="e5cfcfaf6d05635d",
            description=tr("""
`l3_pe1` et `l3_pe2` sont reliés par `l3_p` ; OSPF et LDP y fonctionnent. Chaque PE a deux
interfaces vers des clients : `eth0` vers le client **A** (`l3_a1`, `l3_a2`), `eth1` vers le client
**B** (`l3_b1`, `l3_b2`). Les deux clients utilisent les mêmes préfixes : `{site1}` pour leur site
1, `{site2}` pour leur site 2 ; les adresses sont déjà en place (sections @@ref:l3vpn@@ à
@@ref:l3vpn-frr@@).

1. Sur chaque PE, créez les VRF `CUST_A` (table 10, `eth0`) et `CUST_B` (table 20, `eth1`).
   Regardez `ip route show vrf CUST_A` : où sont passées les routes connectées ?
2. Établissez la session iBGP entre `l3_pe1` et `l3_pe2`, entre leurs interfaces de bouclage, dans
   la seule famille VPNv4.
3. Dans chaque VRF, exportez les réseaux connectés en VPNv4 et importez ceux de l'autre PE, avec
   le RD et la RT donnés (section @@ref:rd-rt@@).
4. Vérifiez que `l3_a1` joint `l3_a2` et que `l3_b1` joint `l3_b2`, mais que `l3_a1` ne joint pas
   l'adresse de `l3_b2`. Regardez la table VPNv4 (`show bgp ipv4 vpn`), la table de chaque VRF, et
   les labels sur `l3_p` (`tcpdump -nei eth0 mpls`).
""").format(site1=site1, site2=site2)
            + instructor(tr("""
**Solution.**

{solution}

La table VPNv4 contient deux fois chaque préfixe, sous deux RD. La route du site distant, dans la
VRF, impose deux labels : le label LDP du prochain saut vers l'interface de bouclage de l'autre PE
et le label VPN de la VRF (`encap mpls X/Y`) ; sur `l3_p`, les paquets portent les deux labels.

Évaluation : `l3_vrfs` (4 : un point par VRF et par PE, interface attachée), `l3_vpnv4` (3 : la
session VPNv4), `l3_export` (4 : un point par VRF et par PE dont la route arrive à l'autre PE sous
son RD), `l3_vrf_routes` (4 : un point par VRF et par PE dont le noyau a la route du site distant
avec deux labels), `l3_ping` (4 : 2 par client), `l3_isolation` (2 : `l3_a1` ne joint pas `l3_b2`) ;
`l3_q_stack` (1) ; pour l'enseignant seulement : `l3_q_rd`, `l3_q_rt` (1 chacun).
""").format(solution=_mixed_text(ns.solution_l3()))),
        )
        cheat_l3 = {'stack': '2', 'rd': 'rd', 'rt': 'rt'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site l3"),
            hash="946de76e777cc661",
            description=tr("""
- nombre de labels portés par les paquets de `l3_a1` vers `l3_a2` sur le lien `l3_l1` :
  @@{stack:[0-9]+}@@
- ce qui distingue, dans la table VPNv4, les préfixes identiques des deux clients :
  @@{rd:>le route distinguisher>>>rd|la route target>>>rt|le label VPN>>>label|le prochain saut>>>nexthop}@@
- ce qui décide dans quelle VRF une route VPNv4 est importée :
  @@{rt:>la route target>>>rt|le route distinguisher>>>rd|le label VPN>>>label|le nom de la VRF>>>name}@@
""")
            + instructor(tr("""
**Solution.** **2** (transport puis VPN) ; le **RD** ; la **RT**.

Évaluation : `l3_q_stack` (1) ; pour l'enseignant seulement : `l3_q_rd`, `l3_q_rt` (1 chacun).
""")),
            cheat_answers={"final": cheat_l3, "solve_l3": cheat_l3},
        )
        vrf_ok = [vrf_of_port(l3_vrfs[r], ifname) == vrf and l3_vrfs[r][vrf]['up'] and l3_vrfs[r][vrf]['table'] == table
                  for r in l3 for vrf, table, ifname in VRFS[r] if vrf in l3_vrfs[r]]
        self.add_grade_element(
            title=no_tr("l3_vrfs"), max_grade=4, grade_part=part1, grade=sum(vrf_ok),
            description=tr("VRF des deux clients sur les deux PE"),
        )
        self.add_grade_element(
            title=no_tr("l3_vpnv4"), max_grade=3, grade_part=part1,
            grade=3 * int(self._established(l3_vpn_sum, lo('l3_pe2'))), description=tr("session VPNv4 entre les PE"),
        )
        exported = []
        for src, dst, prefix in (('l3_pe1', 'l3_pe2', site1), ('l3_pe2', 'l3_pe1', site2)):
            for number in (d.rt_a, d.rt_b):
                paths = (l3_vpn[dst].get(rt(number)) or {}).get(str(prefix), [])
                exported.append(any(p['path_from'] == 'internal' and p['nexthop'] == str(lo(src)) for p in paths))
        self.add_grade_element(
            title=no_tr("l3_export"), max_grade=4, grade_part=part1, grade=sum(exported),
            description=tr("routes des VRF échangées en VPNv4 sous leur RD"),
        )
        vrf_routes = [len(_stack_of(l3_k[(r, v)], site2 if r == 'l3_pe1' else site1)) == 2
                      for r in l3 for v in ('CUST_A', 'CUST_B')]
        self.add_grade_element(
            title=no_tr("l3_vrf_routes"), max_grade=4, grade_part=part1, grade=sum(vrf_routes),
            description=tr("routes du site distant avec deux labels"),
        )
        self.add_grade_element(
            title=no_tr("l3_ping"), max_grade=4, grade_part=part1, grade=2 * int(l3_ping_a) + 2 * int(l3_ping_b),
            description=tr("chaque client joint son autre site"),
        )
        self.add_grade_element(
            title=no_tr("l3_isolation"), max_grade=2, grade_part=part1, grade=2 * int(l3_ping_a and not l3_cross),
            description=tr("le client A ne joint pas le client B"),
        )
        self.add_grade_element(
            title=no_tr("l3_q_stack"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('stack')) == 2),
            description=tr("profondeur de la pile"),
        )
        self.add_grade_element(
            title=no_tr("l3_q_rd"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('rd')) == 'rd'), description=tr("rôle du RD"),
        )
        self.add_grade_element(
            title=no_tr("l3_q_rt"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('rt')) == 'rt'), description=tr("rôle de la RT"),
        )

        # =====================================================================
        # Part 2 — PE-CE eBGP (ce)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("pe_ce"), tr("Partie 2 — eBGP entre PE et CE (site ce)"))
        ce_site1, ce_site2 = net('ce_site1'), net('ce_site2')
        self.question_dummy(
            section=self.section(0),
            title=tr("eBGP entre PE et CE"),
            hash="1de53a126e0ec8bc",
            description=tr("""
Le client C a deux sites : `ce_c1` (réseau `{s1}`) derrière `ce_pe1`, `ce_c2` (réseau `{s2}`)
derrière `ce_pe2`. Les deux CE sont dans l'AS **{cas}** ; chacun annonce son réseau en eBGP à son PE
(déjà configuré de son côté, avec des route-maps qui laissent tout passer). La VRF `CUST_C` et la
session VPNv4 entre les PE sont en place (section @@ref:pe-ce@@).

1. Sur chaque PE, établissez la session eBGP avec son CE dans l'instance BGP de la VRF `CUST_C`,
   avec une politique d'entrée et de sortie qui laisse tout passer.
2. Regardez la table BGP de la VRF, puis la table VPNv4 de l'autre PE. Le réseau du site 1 arrive-t-il
   chez `ce_c2` ? Pourquoi (`show bgp neighbors` sur le PE, *AS path*) ?
3. Corrigez sur les PE, sans toucher aux CE, pour que les deux sites se joignent.
""").format(s1=ce_site1, s2=ce_site2, cas=CUSTOMER_AS)
            + instructor(tr("""
**Solution.**

{solution}

Sans `as-override`, la route du site 1 arrive à `ce_c2` avec l'AS path `{pas} {cas}` : `ce_c2` y
voit son propre AS et la rejette. Avec, l'AS path devient `{pas} {pas}`.

Évaluation : `ce_sessions` (6 : 3 par session eBGP établie dans la VRF), `ce_routes` (4 : 2 par CE
qui a la route de l'autre site avec l'AS path `{pas} {pas}`), `ce_ping` (4) ; `ce_q_aspath` (2) ;
pour l'enseignant seulement : `ce_q_loop`, `ce_q_core` (1 chacun).
""").format(solution=_vtysh_text(ns.solution_ce()), pas=PROVIDER_AS, cas=CUSTOMER_AS)),
        )
        cheat_ce = {'aspath': f"{PROVIDER_AS} {PROVIDER_AS}", 'loop': 'own_as', 'core': 'none'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site ce"),
            hash="de024b377630cd4e",
            description=tr("""
- AS path de la route du réseau du site 1 dans la table BGP de `ce_c2` : @@{aspath:[0-9 ]+}@@
- sans correction, `ce_c2` refuse cette route parce que :
  @@{loop:>son propre AS est dans l'AS path>>>own_as|le prochain saut est injoignable>>>nexthop|elle n'a pas de RT>>>no_rt|la session n'a pas de politique>>>policy}@@
- ce que `ce_p` sait des réseaux du client C :
  @@{core:>rien : il ne commute que des labels vers les PE>>>none|il les apprend par OSPF>>>ospf|il les apprend par BGP>>>bgp|il les apprend par LDP>>>ldp}@@
""")
            + instructor(tr("""
**Solution.** **`{aspath}`** ; son propre AS est dans l'AS path ; rien : le cœur est sans BGP.

Évaluation : `ce_q_aspath` (2) ; pour l'enseignant seulement : `ce_q_loop`, `ce_q_core` (1 chacun).
""").format(aspath=cheat_ce['aspath'])),
            cheat_answers={"final": cheat_ce, "solve_ce": cheat_ce},
        )
        self.add_grade_element(
            title=no_tr("ce_sessions"), max_grade=6, grade_part=part2,
            grade=3 * int(self._established(ce_sum['ce_pe1'], addr('ce_c1', 'ce_link1')))
            + 3 * int(self._established(ce_sum['ce_pe2'], addr('ce_c2', 'ce_link2'))),
            description=tr("sessions eBGP PE - CE dans la VRF"),
        )
        overridden = [any(p['best'] and p['as_list'] == [PROVIDER_AS, PROVIDER_AS] for p in ce_routes[ce].get(str(prefix), []))
                      for ce, prefix in (('ce_c2', ce_site1), ('ce_c1', ce_site2))]
        self.add_grade_element(
            title=no_tr("ce_routes"), max_grade=4, grade_part=part2, grade=2 * sum(overridden),
            description=tr("chaque CE a la route de l'autre site"),
        )
        self.add_grade_element(
            title=no_tr("ce_ping"), max_grade=4, grade_part=part2, grade=4 * int(ce_ping),
            description=tr("les deux sites du client C se joignent"),
        )
        self.add_grade_element(
            title=no_tr("ce_q_aspath"), max_grade=2, grade_part=part2,
            grade=2 * int(_labels(q2.get('aspath')) == [PROVIDER_AS, PROVIDER_AS]), description=tr("AS path vu par ce_c2"),
        )
        self.add_grade_element(
            title=no_tr("ce_q_loop"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('loop')) == 'own_as'), description=tr("détection de boucle"),
        )
        self.add_grade_element(
            title=no_tr("ce_q_core"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('core')) == 'none'), description=tr("cœur sans BGP"),
        )

        # =====================================================================
        # Part 3 — extranet (ex)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("extranet"), tr("Partie 3 — un extranet (site ex)"))
        lan_a, lan_b, lan_s = net('ex_a_lan'), net('ex_b_lan'), net('ex_s_lan')
        self.question_dummy(
            section=self.section(0),
            title=tr("Des services partagés entre deux clients"),
            hash="94dec6be74915226",
            description=tr("""
Sur `ex_pe1`, la VRF `CUST_A` (l'hôte `ex_a`) et la VRF `CUST_B` (l'hôte `ex_b`) ; sur `ex_pe2`, la
VRF `SERVICES` (le serveur `ex_s`). Chaque VRF exporte et importe pour l'instant sa seule RT :
`CUST_A` **{a}**, `CUST_B` **{b}**, `SERVICES` **{s}** ; personne ne joint personne (section
@@ref:vpn-topologies@@).

1. Modifiez les RT **d'import** pour que `ex_a` et `ex_b` joignent tous deux `ex_s`, sans se
   joindre entre eux. Ne changez ni les RD ni les RT d'export.
2. Regardez la table de chaque VRF. Pourquoi `CUST_A` ne reçoit-elle pas les routes de `CUST_B` par
   l'intermédiaire de `SERVICES` ?
""").format(a=rt(d.rt_a), b=rt(d.rt_b), s=rt(d.rt_s))
            + instructor(tr("""
**Solution.**

{solution}

Une route importée dans une VRF n'est pas ré-exportée : `SERVICES` connaît les deux clients, mais
ne fait pas de pont entre eux.

Évaluation : `ex_routes` (6 : `CUST_A` a `SERVICES`, puis n'a pas `CUST_B` ; de même pour `CUST_B` ;
`SERVICES` a les deux clients), `ex_ping` (6 : `ex_a` et `ex_b` joignent `ex_s`, puis `ex_a` ne joint
pas `ex_b`) ; `ex_q_services`, `ex_q_cust_a` (2 chacun) ; pour l'enseignant seulement :
`ex_q_reexport`, `ex_q_hub` (1 chacun).
""").format(solution=_vtysh_text(ns.solution_ex()))),
        )
        cheat_ex = {'services': f"{rt(d.rt_s)} {rt(d.rt_a)} {rt(d.rt_b)}", 'cust_a': f"{rt(d.rt_a)} {rt(d.rt_s)}",
                    'reexport': 'no', 'hub': 'hub'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Les route targets de l'extranet"),
            hash="0716843292a000b5",
            description=tr("""
- RT importées par la VRF `SERVICES` (séparées par des espaces) : @@{services:[0-9: ]+}@@
- RT importées par la VRF `CUST_A` : @@{cust_a:[0-9: ]+}@@
- une route importée dans une VRF est-elle exportée à nouveau vers les autres PE ?
  @@{reexport:>non>>>no|oui, avec la RT de la VRF qui l'importe>>>yes|oui, avec sa RT d'origine>>>origin}@@
- la topologie où tous les sites ne joignent qu'un site central :
  @@{hub:>hub-and-spoke>>>hub|extranet>>>extranet|VPN complet>>>full|VPN de niveau 2>>>l2}@@
""")
            + instructor(tr("""
**Solution.** **`{services}`** ; **`{cust_a}`** (dans n'importe quel ordre) ; non ; hub-and-spoke.

Évaluation : `ex_q_services`, `ex_q_cust_a` (2 chacun) ; pour l'enseignant seulement :
`ex_q_reexport`, `ex_q_hub` (1 chacun).
""").format(**cheat_ex)),
            cheat_answers={"final": cheat_ex, "solve_ex": cheat_ex},
        )
        a_rib, b_rib, s_rib = (ex_rib[('ex_pe1', 'CUST_A')], ex_rib[('ex_pe1', 'CUST_B')],
                               ex_rib[('ex_pe2', 'SERVICES')])
        routes_ok = [str(lan_s) in a_rib, str(lan_s) in a_rib and str(lan_b) not in a_rib,
                     str(lan_s) in b_rib, str(lan_s) in b_rib and str(lan_a) not in b_rib,
                     str(lan_a) in s_rib, str(lan_b) in s_rib]
        self.add_grade_element(
            title=no_tr("ex_routes"), max_grade=6, grade_part=part3, grade=sum(routes_ok),
            description=tr("tables des trois VRF"),
        )
        self.add_grade_element(
            title=no_tr("ex_ping"), max_grade=6, grade_part=part3,
            grade=2 * int(ex_a_s) + 2 * int(ex_b_s) + 2 * int(ex_a_s and not ex_a_b),
            description=tr("les clients joignent les services, pas l'autre client"),
        )
        self.add_grade_element(
            title=no_tr("ex_q_services"), max_grade=2, grade_part=part3,
            grade=2 * int(_rts(q3.get('services')) == _rts(cheat_ex['services'])), description=tr("RT de SERVICES"),
        )
        self.add_grade_element(
            title=no_tr("ex_q_cust_a"), max_grade=2, grade_part=part3,
            grade=2 * int(_rts(q3.get('cust_a')) == _rts(cheat_ex['cust_a'])), description=tr("RT de CUST_A"),
        )
        self.add_grade_element(
            title=no_tr("ex_q_reexport"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('reexport')) == 'no'), description=tr("pas de ré-export"),
        )
        self.add_grade_element(
            title=no_tr("ex_q_hub"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('hub')) == 'hub'), description=tr("hub-and-spoke"),
        )

        # =====================================================================
        # Part 4 — SR traffic engineering (te)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("sr_te"), tr("Partie 4 — ingénierie de trafic avec le segment routing (site te)"))
        out, back = ns.te_stack_out(), ns.te_stack_back()
        self.question_dummy(
            section=self.section(0),
            title=tr("Faire passer le trafic par un routeur choisi"),
            hash="a7b3b627e5d3b228",
            description=tr("""
Le site `te` forme deux chemins entre `te_pe1` (l'hôte `te_h1`) et `te_pe5` (l'hôte `te_h5`) : par
`te_r2`, le plus court, et par `te_r4` puis `te_r3`. OSPF et le segment routing y fonctionnent (coûts
et index dans l'organisation du TP) ; les réseaux des hôtes sont annoncés dans OSPF, sans SID
(section @@ref:sr-te@@).

1. Vérifiez le chemin actuel entre les hôtes (`traceroute`, les tables).
2. Sur `te_pe1`, faites passer le trafic vers le réseau de `te_h5` par **`te_r3`** avec une pile
   de labels : le node-SID de `te_r3`, puis celui de `te_pe5`. Vers quel voisin l'envoyer ? Que se
   passerait-il avec le seul node-SID de `te_pe5` envoyé vers `te_r4` ?
3. Sur `te_pe5`, faites passer le retour vers le réseau de `te_h1` par `te_r3` lui aussi, avec la
   pile la plus courte possible.
4. Vérifiez avec `tcpdump -nei ethX mpls` sur `te_r3` et `te_r2`.
""")
            + instructor(tr("""
**Solution.**

{solution}

Envoyé vers `te_r4` avec le seul node-SID de `te_pe5`, le paquet repartirait par `te_pe1` (le plus
court chemin de `te_r4` vers `te_pe5` passe par `te_pe1` et `te_r2`). Au retour, `te_r3` est voisin
de `te_pe5` : il suffit de lui envoyer le paquet avec le node-SID de `te_pe1` ({back}).

Évaluation : `te_out` (4 : la route de `te_pe1`), `te_back` (4 : la route de `te_pe5`), `te_ping`
(2 : ping entre les hôtes, la route d'aller en place), `te_waypoint` (6 : 3 par sens, des paquets
étiquetés reçus par `te_r3` pendant le ping) ; `te_q_out` (2), `te_q_back`, `te_q_l34` (1 chacun).
""").format(solution=_vtysh_text(ns.solution_te()), back=back[0])),
        )
        cheat_te = {'out': "/".join(str(x) for x in out), 'back': str(back[0]), 'l34': str(out[1])}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Les labels du chemin choisi"),
            hash="83e725d8718f0c80",
            description=tr("""
- pile de labels imposée par `te_pe1` vers le réseau de `te_h5` (sommet d'abord, séparés par
  `/`) : @@{out:[0-9/ ]+}@@
- label imposé par `te_pe5` vers le réseau de `te_h1` : @@{back:[0-9]+}@@
- label des paquets de `te_h1` vers `te_h5` sur le lien `te_l34` : @@{l34:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **`{out}`** ; **{back}** ; **{l34}** (`te_r4` a retiré le node-SID de `te_r3`, son
voisin : PHP).

Évaluation : `te_q_out` (2), `te_q_back`, `te_q_l34` (1 chacun).
""").format(**cheat_te)),
            cheat_answers={"final": cheat_te, "solve_te": cheat_te},
        )
        out_ok = _route_via(te_k['te_pe1'], net('te_lan5'), out, addr('te_r4', 'te_l14'))
        self.add_grade_element(
            title=no_tr("te_out"), max_grade=4, grade_part=part4, grade=4 * int(out_ok),
            description=tr("te_pe1 : pile de labels par te_r3"),
        )
        self.add_grade_element(
            title=no_tr("te_back"), max_grade=4, grade_part=part4,
            grade=4 * int(_route_via(te_k['te_pe5'], net('te_lan1'), back, addr('te_r3', 'te_l35'))),
            description=tr("te_pe5 : retour par te_r3"),
        )
        self.add_grade_element(
            title=no_tr("te_ping"), max_grade=2, grade_part=part4, grade=2 * int(te_ping and out_ok),
            description=tr("les hôtes se joignent par le chemin choisi"),
        )
        self.add_grade_element(
            title=no_tr("te_waypoint"), max_grade=6, grade_part=part4,
            grade=sum(3 * int(te_ping and te_delta[name] >= 5) for name in ('eth0', 'eth1')),
            description=tr("te_r3 reçoit le trafic dans les deux sens"),
        )
        self.add_grade_element(
            title=no_tr("te_q_out"), max_grade=2, grade_part=part4, grade=2 * int(_labels(q4.get('out')) == out),
            description=tr("pile de te_pe1"),
        )
        self.add_grade_element(
            title=no_tr("te_q_back"), max_grade=1, grade_part=part4, grade=int(_labels(q4.get('back')) == back),
            description=tr("label de te_pe5"),
        )
        self.add_grade_element(
            title=no_tr("te_q_l34"), max_grade=1, grade_part=part4, grade=int(_labels(q4.get('l34')) == [out[1]]),
            description=tr("label sur te_l34"),
        )

        # =====================================================================
        # Part 5 — troubleshooting (fix)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("fix"), tr("Partie 5 — dépannage d'un L3VPN (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un L3VPN en panne"),
            hash="8c9fad869c693b45",
            description=tr("""
Le site `fix` est un L3VPN pour un client A : `fix_a1` derrière `fix_pe1`, `fix_a2` derrière
`fix_pe2`, `fix_p` au cœur ; OSPF, LDP, la VRF `CUST_A` (RD et RT {a}) et la session VPNv4 sont
configurés. Pourtant `fix_a1` ne joint pas `fix_a2` : **quatre pannes** ont été glissées dans la
configuration des PE (section @@ref:l3vpn-debug@@).

Trouvez et corrigez chaque panne sans tout reconfigurer : suivez le chemin d'une route d'un site à
l'autre, dans les deux sens.
""").format(a=rt(d.rt_a))
            + instructor(tr("""
**Solution.**

{solution}

Évaluation : `fix_rt` (3 : RT d'import de `fix_pe2`), `fix_label` (3 : label VPN sur `fix_pe1`),
`fix_activate` (3 : session VPNv4 activée et établie sur `fix_pe2`), `fix_interface` (3 : `eth0` de
`fix_pe2` dans la VRF), `fix_ping` (4), `fix_labelled` (2 : `fix_p` reçoit des paquets étiquetés
pendant le ping) ; pour l'enseignant seulement : `fix_q_label`, `fix_q_interface` (1 chacun).
""").format(solution=_mixed_text(ns.solution_fix()))),
        )
        cheat_fix = {'label': 'not_exported', 'interface': 'main_table'}
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Ce que montraient les pannes"),
            hash="6fffbf8eddac0353",
            description=tr("""
- sans `label vpn export`, FRR :
  @@{label:>n'exporte pas les routes de la VRF>>>not_exported|les exporte avec le label 3>>>implicit|les exporte avec le label de transport>>>transport|les exporte sans RT>>>no_rt}@@
- le réseau d'une interface laissée hors de la VRF est :
  @@{interface:>dans la table principale du PE, que la VRF ignore>>>main_table|dans la VRF, sans label>>>no_label|annoncé en VPNv4 sous le RD 0:0>>>rd_zero|perdu>>>lost}@@
""")
            + instructor(tr("""
**Solution.** Il n'exporte pas les routes de la VRF ; dans la table principale du PE, que la VRF
ignore.

Évaluation, pour l'enseignant seulement : `fix_q_label`, `fix_q_interface` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        vrf1 = ((fix_cfg['fix_pe1'].get('router_bgp_vrfs') or {}).get('CUST_A') or {}).get('vpn') or {}
        vrf2 = ((fix_cfg['fix_pe2'].get('router_bgp_vrfs') or {}).get('CUST_A') or {}).get('vpn') or {}
        self.add_grade_element(
            title=no_tr("fix_rt"), max_grade=3, grade_part=part5, grade=3 * int(rt(d.rt_a) in vrf2.get('rt_import', [])),
            description=tr("RT d'import de fix_pe2"),
        )
        self.add_grade_element(
            title=no_tr("fix_label"), max_grade=3, grade_part=part5, grade=3 * int(bool(vrf1.get('label'))),
            description=tr("label VPN exporté par fix_pe1"),
        )
        self.add_grade_element(
            title=no_tr("fix_activate"), max_grade=3, grade_part=part5,
            grade=3 * int(self._established(fix_vpn_sum, lo('fix_pe1'))), description=tr("session VPNv4 de fix_pe2"),
        )
        self.add_grade_element(
            title=no_tr("fix_interface"), max_grade=3, grade_part=part5,
            grade=3 * int(vrf_of_port(fix_vrfs, 'eth0') == 'CUST_A'), description=tr("eth0 de fix_pe2 dans la VRF"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=4, grade_part=part5, grade=4 * int(fix_ping),
            description=tr("fix_a1 joint fix_a2"),
        )
        self.add_grade_element(
            title=no_tr("fix_labelled"), max_grade=2, grade_part=part5, grade=2 * int(fix_ping and fix_delta >= 5),
            description=tr("trafic étiqueté dans le cœur"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_label"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
            grade=int(_norm(q5.get('label')) == 'not_exported'), description=tr("routes sans label VPN"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_interface"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
            grade=int(_norm(q5.get('interface')) == 'main_table'), description=tr("interface hors de la VRF"),
        )

        # =====================================================================
        # Part 6 — VPN over segment routing (sv, bonus)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("vpn_sr"), tr("Partie 6 — un VPN sur segment routing (site sv, bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un VPN sur un cœur segment routing (bonus)"),
            hash="3cb8526f7735d75f",
            description=tr("""
Le site `sv` est un L3VPN déjà configuré (`sv_a1` derrière `sv_pe1`, `sv_a2` derrière `sv_pe2`,
`sv_p` au cœur, VRF `CUST_A`, session VPNv4), mais son cœur n'a **pas de LDP** : `sv_a1` ne joint
pas `sv_a2` (section @@ref:vpn-over-sr@@).

1. Regardez la route de `sv_a2` dans la VRF de `sv_pe1` (`ip route show vrf CUST_A`) : combien de
   labels ? Que fait `sv_p` du paquet ?
2. Activez le segment routing dans OSPF sur les trois routeurs (SRGB 16000 à 23999, index donnés
   dans l'organisation du TP), sans toucher à BGP. Regardez à nouveau la route.
""")
            + instructor(tr("""
**Solution.**

{solution}

Avant : la route impose le seul label VPN, que `sv_p` ne connaît pas (il jette le paquet). Après :
deux labels, le node-SID de `sv_pe2` ({sid}) au sommet.

Évaluation (bonus) : `sv_sr` (2 : segment routing sur les trois routeurs, avec les index donnés),
`sv_stack` (2 : deux labels, le node-SID de `sv_pe2` au sommet), `sv_ping` (2).
""").format(solution=_vtysh_text(ns.solution_sv()), sid=SRGB_BASE + d.sv_index('sv_pe2'))),
        )
        sr_ok = all(((sv_db[r].get(str(lo(r))) or {}).get('prefixes', {}).get(f"{lo(r)}/32") or {}).get('index')
                    == d.sv_index(r) for r in sv)
        stack = _stack_of(sv_k, net('sv_a2_lan'))
        self.add_grade_element(
            title=no_tr("sv_sr"), max_grade=2, grade_part=part6, bonus=True, grade=2 * int(sr_ok),
            description=tr("segment routing dans le cœur"),
        )
        self.add_grade_element(
            title=no_tr("sv_stack"), max_grade=2, grade_part=part6, bonus=True,
            grade=2 * int(len(stack) == 2 and stack[0] == SRGB_BASE + d.sv_index('sv_pe2')),
            description=tr("label de transport du segment routing"),
        )
        self.add_grade_element(
            title=no_tr("sv_ping"), max_grade=2, grade_part=part6, bonus=True, grade=2 * int(sv_ping),
            description=tr("sv_a1 joint sv_a2"),
        )


_TRANSLATIONS = {}
