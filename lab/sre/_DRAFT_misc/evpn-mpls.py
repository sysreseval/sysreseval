"""EVPN and MPLS lab with Linux and FRR (bgpd, ospfd, ldpd): interconnecting data centres over an
operator's BGP/MPLS L3VPN.

IPv4 only, the operator is AS 65000.  Four independent sites, one per part (completing a part gives
all its points whatever the others):

- ``stretch``: two data centres (one VTEP each, AS 65101 and 65102) are two sites of an operator
  L3VPN (OSPF, LDP, VPNv4, PE-CE eBGP given); the students build the multihop eBGP EVPN session
  between the VTEPs through the VPN, then raise the MTU so that 1500-byte packets cross the VXLAN
  and MPLS encapsulations without fragmentation;
- ``gateway``: a leaf with symmetric IRB (VRF, L3VNI, type-5 subnets given) and a border leaf that is
  also a PE of the operator; the students make the border re-originate the EVPN routes of the data
  centre into VPNv4 and the VPNv4 routes of a remote site into EVPN type-5 routes;
- ``fix``: a stretch over an L3VPN shipped with four faults (no ``ebgp-multihop``, no outbound
  route-map, a VTEP loopback not announced to its PE, MPLS input off on a P router interface);
- ``aggregate`` (bonus): a working gateway that leaks the /32 host routes of the data centre into the
  VPN; the students keep only the subnets with a ``route-map vpn export``.

The MPLS modules of the host are loaded by the kernel itself when ``initial`` asks a container for
an ``encap mpls`` route (lib/mpls.py), the VXLAN ones when a container creates a VXLAN device.
Grading reads the EVPN and VPNv4 json of vtysh (lib/frr.py), the VXLAN devices and forwarding
databases (lib/vxlan.py), the VRF tables, the MPLS counters, the fragmentation counters of the PEs and
real pings.  The states ``solve_<part>`` apply the reference solution of one part, ``final`` all of
them.  Facts checked live: ``.claude/rules/lib-vxlan.md``, ``.claude/rules/lib-mpls.md``.
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
from frr import (
    evpn_routes, get_bgp_evpn_routes, get_bgp_evpn_summary, get_bgp_vpn_routes, get_bgp_vpn_summary,
    get_frr_running_config, get_kernel_routes, kernel_route_labels,
)
from mpls import get_mpls_counters, get_mpls_sysctls, mpls_counter_delta, trigger_mpls_modules_cmd
from vxlan import (
    VXLAN_PORT, bridge_cmds, df_ping_cmd, frag_delta, get_frag_creates, l3vni_cmds, vxlan_cmds,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("EVPN et MPLS : interconnexion de data centres", en="EVPN and MPLS: data centre interconnection")
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

# Router interfaces in ethN order.  A PE has its customer interface first.
ROUTER_IFACES = {
    'st_dc1': ['st_c1', 'st_lan1'],
    'st_pe1': ['st_c1', 'st_l1'],
    'st_p': ['st_l1', 'st_l2'],
    'st_pe2': ['st_c2', 'st_l2'],
    'st_dc2': ['st_c2', 'st_lan2'],
    'gw_leaf': ['gw_u1', 'gw_lan1'],
    'gw_border': ['gw_u1', 'gw_l1'],
    'gw_p': ['gw_l1', 'gw_l2'],
    'gw_pe': ['gw_lan2', 'gw_l2'],
    'fix_dc1': ['fix_c1', 'fix_lan1'],
    'fix_pe1': ['fix_c1', 'fix_l1'],
    'fix_p': ['fix_l1', 'fix_l2'],
    'fix_pe2': ['fix_c2', 'fix_l2'],
    'fix_dc2': ['fix_c2', 'fix_lan2'],
    'ag_leaf': ['ag_u1', 'ag_lan1'],
    'ag_border': ['ag_u1', 'ag_l1'],
    'ag_p': ['ag_l1', 'ag_l2'],
    'ag_pe': ['ag_lan2', 'ag_l2'],
}
# Hosts (eth0): their LAN, their subnet, the address key of their default gateway (None: none)
HOSTS = {
    'st_h1': ('st_lan1', 'st_net', None), 'st_h2': ('st_lan2', 'st_net', None),
    'gw_h1': ('gw_lan1', 'gw_net', 'gw_leaf_gw'), 'gw_h2': ('gw_lan2', 'gw_remote_net', 'gw_pe_gw'),
    'fix_h1': ('fix_lan1', 'fix_net', None), 'fix_h2': ('fix_lan2', 'fix_net', None),
    'ag_h1': ('ag_lan1', 'ag_net', 'ag_leaf_gw'), 'ag_h2': ('ag_lan2', 'ag_remote_net', 'ag_pe_gw'),
}
# /30 links: the first router gets .1, the second .2
LINKS = {
    'st_c1': ('st_pe1', 'st_dc1'), 'st_l1': ('st_pe1', 'st_p'), 'st_l2': ('st_p', 'st_pe2'), 'st_c2': ('st_pe2', 'st_dc2'),
    'gw_u1': ('gw_border', 'gw_leaf'), 'gw_l1': ('gw_border', 'gw_p'), 'gw_l2': ('gw_p', 'gw_pe'),
    'fix_c1': ('fix_pe1', 'fix_dc1'), 'fix_l1': ('fix_pe1', 'fix_p'), 'fix_l2': ('fix_p', 'fix_pe2'),
    'fix_c2': ('fix_pe2', 'fix_dc2'),
    'ag_u1': ('ag_border', 'ag_leaf'), 'ag_l1': ('ag_border', 'ag_p'), 'ag_l2': ('ag_p', 'ag_pe'),
}
CORE_LINKS = ('st_l1', 'st_l2', 'gw_l1', 'gw_l2', 'fix_l1', 'fix_l2', 'ag_l1', 'ag_l2')   # OSPF, LDP, MPLS input
CE_LINKS = ('st_c1', 'st_c2', 'fix_c1', 'fix_c2')                                       # in the VRF DCI of the PE
DC_LINKS = ('gw_u1', 'ag_u1')                                                           # OSPF, no MPLS
LOOPBACKS = {
    'st_pe1': 1, 'st_p': 2, 'st_pe2': 3, 'st_dc1': 11, 'st_dc2': 12,
    'gw_border': 1, 'gw_p': 2, 'gw_pe': 3, 'gw_leaf': 11,
    'fix_pe1': 1, 'fix_p': 2, 'fix_pe2': 3, 'fix_dc1': 11, 'fix_dc2': 12,
    'ag_border': 1, 'ag_p': 2, 'ag_pe': 3, 'ag_leaf': 11,
}
STRETCH_SITES = ('st', 'fix')
GATEWAY_SITES = ('gw', 'ag')
DC_AS = {'dc1': 65101, 'dc2': 65102}
MPLS_ROUTERS = [r for r in ROUTER_IFACES if any(n in CORE_LINKS for n in ROUTER_IFACES[r])]
OSPF_ROUTERS = MPLS_ROUTERS + ['gw_leaf', 'ag_leaf']
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _s, _g) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0

SITE_COLORS = {'st': 'lightblue', 'gw': 'khaki', 'fix': 'lightsalmon', 'ag': 'lightcyan'}
SITE_NUMBER = {'st': 1, 'gw': 2, 'fix': 3, 'ag': 4}
LOOPBACK_OCTET = 15
PROVIDER_AS = 65000
PLATFORM_LABELS = 100000
VRF_DCI, VRF_DCI_TABLE = 'DCI', 10
VRF, VRF_TABLE = 'TENANT', 100
MTU_SOLUTION = 1600          # >= 1500 + 50 (VXLAN) + 8 (two labels)
EBGP_MULTIHOP = 5
CONVERGE_WAIT = 15
OSPF_WAIT = 50               # an MTU change resets the OSPF adjacencies of the interface
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


def role_of(machine: str) -> str:
    return machine.split('_', 1)[1]


def iface(router: str, net: str) -> str:
    return f"eth{ROUTER_IFACES[router].index(net)}"


def core_ifaces(router: str) -> List[str]:
    return [f"eth{i}" for i, net in enumerate(ROUTER_IFACES[router]) if net in CORE_LINKS]


def frr_daemons(router: str) -> str:
    on = {'bgpd': role_of(router) != 'p', 'ospfd': router in OSPF_ROUTERS, 'ldpd': router in MPLS_ROUTERS}
    note = " : " + ", ".join(name for name, value in on.items() if value) + " activés"
    return FRR_DAEMONS.format(note=note, **{k: 'yes' if v else 'no' for k, v in on.items()})


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


def vx(vni: int) -> str:
    return f"vxlan{vni}"


def br(vni: int) -> str:
    return f"br{vni}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    st_vni: int = 0           # the stretched VNI of the st and fix sites
    fix_vni: int = 0
    gw_vni: int = 0           # the layer-2 VNI and the L3VNI of the gateway sites
    gw_l3vni: int = 0
    ag_vni: int = 0
    ag_l3vni: int = 0
    rt_dci: int = 0           # route targets (65000:N) of the operator VRFs
    rt_tenant: int = 0
    rd_pe: int = 0            # RD numbers (65000:N) of the gateway sites: the PE, the border
    rd_border: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.st_vni, data.fix_vni, data.gw_vni, data.ag_vni = random.sample(range(1000, 10000), 4)
        data.gw_l3vni, data.ag_l3vni = random.sample(range(10000, 16000), 2)
        data.rt_dci, data.rt_tenant, data.rd_pe, data.rd_border = random.sample(range(10, 100), 4)

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        (data.nets.st_net, data.nets.gw_net, data.nets.gw_remote_net, data.nets.fix_net, data.nets.ag_net,
         data.nets.ag_remote_net) = random_ipv4networks([24] * 6, from_network=IPv4Network('192.168.0.0/16'))
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            for k, net in enumerate(n for n in LINKS if site_of(n) == site):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET))
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for router, number in LOOPBACKS.items():
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + number, 32)))
        for subnet in sorted({s for _n, s, _g in HOSTS.values()}):
            network = getattr(data.nets, subnet)
            hosts = [h for h, (_n, s, _g) in HOSTS.items() if s == subnet]
            for host, number in zip(hosts, random.sample(range(10, 250), len(hosts))):
                setattr(data.ips, host, IPv4Interface((int(network.network_address) + number, 24)))
        for site in GATEWAY_SITES:
            for key, subnet in ((f"{site}_leaf_gw", f"{site}_net"), (f"{site}_pe_gw", f"{site}_remote_net")):
                network = getattr(data.nets, subnet)
                setattr(data.ips, key, IPv4Interface((int(network.network_address) + 1, 24)))
        return data

    def vni(self, site: str) -> int:
        return getattr(self, f"{site}_vni")

    def l3vni(self, site: str) -> int:
        return getattr(self, f"{site}_l3vni")


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("routing-frr")
        spec['shape'] = 'box'
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
            entry = []
            for net in nets:
                if net in LINKS:
                    entry.append(([getattr(d.ips, f"{r}_{net}")], []))
                elif role_of(r) == 'pe':
                    # the customer interface of a gateway site PE: the gateway of the remote host
                    entry.append(([getattr(d.ips, f"{site_of(r)}_pe_gw")], []))
                else:
                    entry.append(([], []))
            self.net_config[r] = entry
        for h, (_net, _subnet, gw) in HOSTS.items():
            routes = [(IPv4Network("0.0.0.0/0"), getattr(d.ips, gw).ip)] if gw else []
            self.net_config[h] = [([getattr(d.ips, h)], routes)]

        lines = []
        for r, nets in ROUTER_IFACES.items():
            first = True
            for i, net in enumerate(nets):
                if net not in LINKS:
                    continue
                names = f"{r}\t{r}-eth{i}" if first else f"{r}-eth{i}"
                first = False
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

    def host_ip(self, host: str) -> IPv4Address:
        return getattr(self.data.ips, host).ip

    @staticmethod
    def rt(number: int) -> str:
        return f"{PROVIDER_AS}:{number}"

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Interconnecter des data centres"), tag="dci")
            + tr("""
Une entreprise ou un hébergeur exploite souvent plusieurs data centres : pour la redondance, pour
rapprocher les services des utilisateurs. L'**interconnexion de data centres** (DCI, *Data Centre
Interconnect*) doit transporter :

- du **niveau 2** : un même VNI (un même sous-réseau) de part et d'autre, pour déplacer une machine
  virtuelle d'un site à l'autre sans changer son adresse, ou pour un cluster qui exige un segment
  commun ;
- du **niveau 3** : les sous-réseaux d'un client (une VRF) joignables depuis ses autres sites,
  y compris des sites qui ne sont pas des data centres (agences, sièges).

Entre les sites, le transport est souvent le réseau d'un **opérateur**, et ce réseau est un cœur
**MPLS** qui vend des VPN de niveau 3 (L3VPN BGP/MPLS) ou de niveau 2.

| solution | ce qui traverse l'opérateur | plan de données |
|----------|-----------------------------|-----------------|
| fibre noire, longueur d'onde | les trames, telles quelles | celui du data centre |
| VXLAN au-dessus d'un L3VPN | des paquets IP entre VTEP (UDP 4789), étiquetés dans le cœur | VXLAN puis MPLS |
| EVPN-MPLS (RFC 7432) | des trames étiquetées : un label par segment (EVI) au lieu d'un VNI | MPLS |
| VPLS, pseudowires (RFC 4761, 4762, 4448) | des trames étiquetées, émulation d'un commutateur ou d'un câble | MPLS |
| passerelle EVPN ↔ L3VPN | des paquets IP du client, dans le VPN | VXLAN dans le data centre, MPLS chez l'opérateur |

EVPN décrit les deux plans de données, VXLAN et MPLS, avec le même plan de contrôle BGP (les mêmes
types de route). Le noyau Linux sait commuter des labels pour IP (routes `encap mpls`, table des
labels), mais **pas pour des trames Ethernet** : ni EVPN-MPLS, ni VPLS, ni pseudowires. Ce TP réalise
donc les deux solutions qui reposent sur VXLAN : un VNI étendu au-dessus d'un L3VPN (section
@@ref:vxlan-over-l3vpn@@), et une passerelle EVPN ↔ L3VPN (section @@ref:gateway@@).
""")
            + info_subtitle(tr("Rappels : VXLAN, EVPN, L3VPN"), tag="reminders")
            + tr("""
- **VXLAN** (RFC 7348) transporte une trame Ethernet dans UDP (port 4789) entre deux **VTEP** ; le
  **VNI** (24 bits) désigne le segment. Linux : une interface `vxlan` (`id`, `local`, `dstport 4789`,
  `nolearning` avec EVPN) dans un pont avec les interfaces des hôtes.
- **EVPN** (RFC 7432, 8365) annonce par MP-BGP, famille **L2VPN EVPN**, les VNI de chaque VTEP (type 3 :
  la liste d'inondation), les adresses MAC et IP des hôtes (type 2) et des préfixes (type 5). Avec FRR :
  `advertise-all-vni` dans `address-family l2vpn evpn`. RT automatique d'un VNI : `AS:VNI`.
- **IRB symétrique** : les sous-réseaux d'un client forment une VRF ; entre VTEP, les paquets routés
  utilisent le **L3VNI** de la VRF (`vrf X` / ` vni N` dans FRR, une interface `vxlan` et un pont dans
  la VRF), avec la *router MAC* de chaque VTEP.
- **L3VPN BGP/MPLS** (RFC 4364) : chaque PE range les routes d'un client dans une VRF ; les PE les
  échangent en **VPNv4** (RD, RT, label VPN) ; un paquet traverse le cœur avec deux labels, le label
  de transport vers le PE de sortie (LDP) et le label VPN qui désigne la VRF. Le CE parle IP (ici eBGP)
  avec son PE.
""")
            + info_subtitle(tr("VXLAN au-dessus d'un L3VPN"), tag="vxlan-over-l3vpn")
            + tr("""
Les deux data centres sont deux **sites d'un même L3VPN** : chaque VTEP est un CE, qui annonce son
interface de bouclage à son PE par eBGP. Pour le VPN, les paquets VXLAN ne sont que des paquets IP
entre deux adresses de bouclage de clients. Sur le lien entre le PE d'entrée et le routeur P :

```
| Ethernet | label LDP | label VPN | IPv4 VTEP -> VTEP | UDP 4789 | VXLAN (VNI) | trame de l'hôte |
| 14       | 4         | 4         | 20                | 8        | 8           | 14 + IP         |
```

- Le cœur ne voit ni le VNI, ni les adresses MAC : il commute des labels vers le PE de sortie. Le
  PE ne voit qu'un paquet IP de client.
- Le plan de contrôle EVPN des VTEP passe lui aussi dans le VPN : une session BGP entre les deux
  interfaces de bouclage, que le VPN transporte comme le reste.
- L'opérateur ne sait rien d'EVPN : ajouter un VNI ne change rien chez lui.
""")
            + info_subtitle(tr("Une session EVPN entre deux AS"), tag="ebgp-evpn")
            + tr("""
Chaque data centre a son propre AS : la session EVPN entre les VTEP est une session **eBGP**, entre
deux adresses qui ne sont pas sur le même lien. Trois points à régler :

- **`ebgp-multihop`** : par défaut, FRR n'établit une session eBGP qu'avec un voisin directement
  connecté, et envoie ses paquets avec un TTL de 1 ; `neighbor X ebgp-multihop 5` lève les deux ;
- **`update-source lo`** : la session part de l'interface de bouclage, que l'autre VTEP connaît ;
- **une politique d'entrée et de sortie** : la RFC 8212 s'applique aussi à la famille L2VPN EVPN :
  sans route-map, FRR établit la session mais n'échange rien (`(Policy)` dans `show bgp l2vpn evpn
  summary`).

```
configure terminal
route-map ALL permit 10
exit
router bgp 65101
 neighbor 10.0.31.12 remote-as 65102
 neighbor 10.0.31.12 ebgp-multihop 5
 neighbor 10.0.31.12 update-source lo
 address-family l2vpn evpn
  neighbor 10.0.31.12 activate
  neighbor 10.0.31.12 route-map ALL in
  neighbor 10.0.31.12 route-map ALL out
  advertise-all-vni
 exit-address-family
exit
end
write
```

La RT automatique d'un VNI vaut `AS:VNI` : les deux VTEP exportent donc des RT différentes
(`65101:100` et `65102:100`). FRR importe tout de même les routes : pour une RT automatique, il ne
compare que la partie VNI. Avec des RT fixées à la main (bloc `vni N` / `route-target`), il faut
qu'elles correspondent.

Avec `no bgp default ipv4-unicast`, le voisin n'est actif que dans la famille EVPN : le VTEP n'échange
pas de routes IPv4 avec l'autre data centre par cette session (le VPN s'en charge).
""")
            + info_subtitle(tr("La MTU de bout en bout"), tag="mtu")
            + tr("""
Une trame dont le paquet IP fait 1500 octets donne un paquet VXLAN de **1550** octets, puis, dans le
cœur, **1558** octets avec ses deux labels. Ce qui arrive sur des liens à 1500 octets :

- le **VTEP** répond à l'hôte par un ICMP *fragmentation needed* (l'hôte garde une PMTU de 1450
  pendant une dizaine de minutes : `ip route flush cache` pour l'oublier) ;
- le **PE** fragmente le paquet VXLAN (son bit DF n'est pas mis) **avant** de l'étiqueter ; les
  fragments sont réassemblés par le VTEP d'arrivée ;
- le **routeur P** ne fragmente pas un paquet étiqueté : il le **jette** si son lien de sortie est trop
  petit.

Pour transporter sans fragmentation les paquets de 1500 octets des hôtes : au moins 1550 sur les
liens VTEP – PE (dans les deux sens), au moins 1558 sur les liens du cœur. En pratique, l'opérateur
offre une MTU de 9000 (ou 1600) dans son cœur et sur les accès de ses clients data centre.

```
ip link set eth0 mtu 1600                  # sur les deux extrémités de chaque lien
ping -M do -s 1472 <dest>                  # depuis un hôte : 1500 octets avec DF
nstat -az IpFragCreates                    # les fragments créés par un PE
ip -s -s link show eth0                    # erreurs et paquets perdus d'une interface
```

OSPF compare la MTU des deux extrémités d'un lien : changer la MTU d'une interface relance ses
adjacences (plusieurs dizaines de secondes), et elles restent bloquées tant que les deux extrémités
diffèrent.
""")
            + info_subtitle(tr("La passerelle EVPN ↔ L3VPN"), tag="gateway")
            + tr("""
Le client a, dans le data centre, une VRF en IRB symétrique (L3VNI, routes de type 2 et 5) ; ailleurs,
il a des sites reliés par le L3VPN de l'opérateur. Un routeur de bordure, à la fois *border leaf* de
la fabrique et **PE** de l'opérateur, relie les deux mondes dans **la même VRF** :

- il importe les routes EVPN de la VRF (routes de type 5 des sous-réseaux, routes MAC/IP des hôtes)
  et les **exporte en VPNv4**, avec son RD, ses RT VPN et un label VPN ;
- il importe les routes VPNv4 de la VRF et les **ré-annonce en EVPN** comme routes de **type 5**, avec
  sa propre adresse de VTEP comme prochain saut et le L3VNI.

Ces routes sont **ré-originées** : la route qui sort a d'autres RD et RT que celle qui est entrée, un
autre prochain saut (la passerelle elle-même), une autre encapsulation (VNI ou label). Le plan de
données suit :

```
hôte DC -- leaf ==(VXLAN, L3VNI)==> passerelle ==(MPLS : LDP + label VPN)==> PE distant -- site
```

La passerelle termine les deux tunnels : elle décapsule le paquet VXLAN, cherche la destination dans
la VRF, et l'étiquette vers le PE distant ; dans l'autre sens, elle retire le label VPN, cherche dans
la VRF et encapsule en VXLAN vers le leaf.

Avec FRR, sur la passerelle, tout tient dans l'instance BGP de la VRF :

```
configure terminal
router bgp 65000 vrf TENANT
 bgp router-id 10.0.47.1
 address-family ipv4 unicast
  label vpn export auto
  rd vpn export 65000:1
  rt vpn both 65000:500
  export vpn
  import vpn
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
exit
end
write
```

plus, dans l'instance principale, la session VPNv4 avec les autres PE (voisin activé dans
`address-family ipv4 vpn`). FRR ré-exporte en VPNv4 une route importée d'EVPN, et en EVPN une route
importée de VPNv4 ; il ne ré-exporte jamais en VPNv4 une route importée de VPNv4.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show bgp vrf TENANT ipv4 unicast` | la table BGP de la VRF : routes d'EVPN et routes du VPN |
| `show bgp ipv4 vpn` | ce qui part et arrive en VPNv4 |
| `show bgp l2vpn evpn route type prefix` | les routes de type 5, dont celles que la passerelle ré-origine |
| `ip route show vrf TENANT` | sur la passerelle : `encap mpls X/Y` vers le site distant, `dev brL3 onlink` vers le data centre |
""")
            + info_subtitle(tr("Ce qui fuit vers le VPN"), tag="leak")
            + tr("""
Une VRF en IRB symétrique contient, en plus des sous-réseaux (type 5), **une route /32 par hôte**
connu (les routes MAC/IP de type 2). La passerelle les exporte toutes en VPNv4 : les PE de l'opérateur
reçoivent une route par machine du data centre, et une mise à jour à chaque fois qu'un hôte apparaît
ou que son entrée ARP vieillit chez son leaf.

On ne garde vers le VPN que les préfixes utiles avec une **route-map d'export** :

```
configure terminal
ip prefix-list NO-HOST seq 5 deny 0.0.0.0/0 ge 32
ip prefix-list NO-HOST seq 10 permit 0.0.0.0/0 le 32
route-map VPN-OUT permit 10
 match ip address prefix-list NO-HOST
exit
router bgp 65000 vrf TENANT
 address-family ipv4 unicast
  route-map vpn export VPN-OUT
 exit-address-family
exit
end
write
```

`aggregate-address … summary-only` ne suffit pas ici : il cache les routes plus spécifiques aux
voisins BGP de la VRF, mais pas à l'export VPN.
""")
            + info_subtitle(tr("Dépannage"), tag="debug")
            + tr("""
Pour un VNI étendu au-dessus d'un L3VPN, de bas en haut :

1. chaque VTEP annonce-t-il son interface de bouclage à son PE, et le PE l'exporte-t-il dans le VPN
   (`show bgp vrf DCI ipv4 unicast`, `show bgp ipv4 vpn`) ?
2. les deux interfaces de bouclage se joignent-elles (`ping -I lo`, `traceroute`) ? Sinon, le VPN :
   labels des routes de la VRF (`ip route show vrf DCI`), LDP, entrée MPLS des interfaces du cœur
   (`sysctl net.mpls.conf.ethX.input`, compteurs `ip -s link`, `ip stats show group afstats subgroup
   mpls`) ;
3. la session EVPN est-elle établie (`ebgp-multihop`, `update-source`), et échange-t-elle des routes
   (politique d'entrée et de sortie) ?
4. les routes de type 3 et 2 arrivent-elles, et sont-elles installées dans le noyau (`bridge fdb show
   dev vxlanN`) ?
5. les petits paquets passent mais pas les gros : la MTU d'un lien.

| symptôme | cause probable |
|----------|----------------|
| session EVPN `Active` alors que les interfaces de bouclage se joignent | pas d'`ebgp-multihop` |
| session établie, `(Policy)` | pas de route-map d'entrée ou de sortie |
| un VTEP n'a pas de route vers l'autre | interface de bouclage non annoncée au PE, ou route non exportée par le PE |
| les routes sont là, les paquets se perdent dans le cœur | entrée MPLS désactivée, LSP absent |

Après une correction, une session BGP qui attendait peut mettre jusqu'à deux minutes à réessayer :
`clear bgp *` la relance aussitôt.
""")
        )

    # -- FRR configuration ---------------------------------------------------------

    def _ospf_lines(self, router: str) -> List[str]:
        lines = ["router ospf", f" ospf router-id {self.lo(router)}", "exit", "!"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            if net in CORE_LINKS or net in DC_LINKS:
                lines += [f"interface eth{i}", " ip ospf area 0", " ip ospf network point-to-point", "exit", "!"]
        return lines + ["interface lo", " ip ospf area 0", "exit", "!"]

    def _ldp_lines(self, router: str) -> List[str]:
        lo = self.lo(router)
        lines = ["mpls ldp", f" router-id {lo}", " !", " address-family ipv4", f"  discovery transport-address {lo}"]
        lines += [f"  interface {name}" for name in core_ifaces(router)]
        return lines + [" exit-address-family", " !", "exit", "!"]

    def vpnv4_lines(self, pe: str, peer: str, activate: bool = True, header: bool = True) -> List[str]:
        """The iBGP VPNv4 session of a PE with *peer*, between loopbacks."""
        lines = [f"router bgp {PROVIDER_AS}"]
        if header:
            lines += [f" bgp router-id {self.lo(pe)}", " no bgp default ipv4-unicast"]
        lines += [f" neighbor {self.lo(peer)} remote-as {PROVIDER_AS}", f" neighbor {self.lo(peer)} update-source lo",
                  " !", " address-family ipv4 vpn"]
        if activate:
            lines.append(f"  neighbor {self.lo(peer)} activate")
        return lines + [" exit-address-family", "exit", "!"]

    def dci_vrf_lines(self, pe: str, export_label: bool = True) -> List[str]:
        """The VRF DCI of a PE of a stretch site: eBGP with the VTEP of its data centre."""
        site = site_of(pe)
        dc = f"{site}_dc1" if pe.endswith('pe1') else f"{site}_dc2"
        link = f"{site}_c1" if pe.endswith('pe1') else f"{site}_c2"
        ce = self.addr(dc, link)
        rt = self.rt(self.data.rt_dci)
        lines = [f"router bgp {PROVIDER_AS} vrf {VRF_DCI}", f" bgp router-id {self.lo(pe)}",
                 f" neighbor {ce} remote-as {DC_AS[role_of(dc)]}", " !", " address-family ipv4 unicast",
                 f"  neighbor {ce} route-map ALL in", f"  neighbor {ce} route-map ALL out"]
        if export_label:
            lines.append("  label vpn export auto")
        lines += [f"  rd vpn export {rt}", f"  rt vpn both {rt}", "  export vpn", "  import vpn",
                  " exit-address-family", "exit", "!"]
        return lines

    def dc_lines(self, dc: str, announce_lo: bool = True) -> List[str]:
        """A VTEP of a stretch site: eBGP with its PE, its loopback announced."""
        site = site_of(dc)
        pe, link = (f"{site}_pe1", f"{site}_c1") if dc.endswith('dc1') else (f"{site}_pe2", f"{site}_c2")
        pe_addr = self.addr(pe, link)
        lines = [f"router bgp {DC_AS[role_of(dc)]}", f" bgp router-id {self.lo(dc)}", " no bgp default ipv4-unicast",
                 f" neighbor {pe_addr} remote-as {PROVIDER_AS}", " !", " address-family ipv4 unicast"]
        if announce_lo:
            lines.append(f"  network {self.lo(dc)}/32")
        lines += [f"  neighbor {pe_addr} activate", f"  neighbor {pe_addr} route-map ALL in",
                  f"  neighbor {pe_addr} route-map ALL out", " exit-address-family", "exit", "!"]
        return lines

    def evpn_dc_lines(self, dc: str, multihop: bool = True, policy_out: bool = True) -> List[str]:
        """The multihop eBGP EVPN session of a VTEP with the other VTEP of its site."""
        site = site_of(dc)
        other = f"{site}_dc2" if dc.endswith('dc1') else f"{site}_dc1"
        peer = self.lo(other)
        lines = [f"router bgp {DC_AS[role_of(dc)]}", f" neighbor {peer} remote-as {DC_AS[role_of(other)]}"]
        if multihop:
            lines.append(f" neighbor {peer} ebgp-multihop {EBGP_MULTIHOP}")
        lines += [f" neighbor {peer} update-source lo", " !", " address-family l2vpn evpn",
                  f"  neighbor {peer} activate", f"  neighbor {peer} route-map ALL in"]
        if policy_out:
            lines.append(f"  neighbor {peer} route-map ALL out")
        return lines + ["  advertise-all-vni", " exit-address-family", "exit", "!"]

    def evpn_ibgp_lines(self, router: str, peer: str, header: bool = True) -> List[str]:
        """The iBGP EVPN session between the leaf and the border of a gateway site."""
        lines = [f"router bgp {PROVIDER_AS}"]
        if header:
            lines += [f" bgp router-id {self.lo(router)}", " no bgp default ipv4-unicast"]
        lines += [f" neighbor {self.lo(peer)} remote-as {PROVIDER_AS}", f" neighbor {self.lo(peer)} update-source lo",
                  " !", " address-family l2vpn evpn", f"  neighbor {self.lo(peer)} activate", "  advertise-all-vni",
                  " exit-address-family", "exit", "!"]
        return lines

    def vrf_vni_lines(self, site: str) -> List[str]:
        return [f"vrf {VRF}", f" vni {self.data.l3vni(site)}", "exit-vrf", "!"]

    def leaf_vrf_lines(self, leaf: str) -> List[str]:
        """The leaf of a gateway site: its subnet as a type-5 route."""
        return [f"router bgp {PROVIDER_AS} vrf {VRF}", f" bgp router-id {self.lo(leaf)}", " !",
                " address-family ipv4 unicast", "  redistribute connected", " exit-address-family", " !",
                " address-family l2vpn evpn", "  advertise ipv4 unicast", " exit-address-family", "exit", "!"]

    def pe_vrf_lines(self, pe: str) -> List[str]:
        """The VRF TENANT of the PE of a gateway site (the remote site of the customer)."""
        d = self.data
        return [f"router bgp {PROVIDER_AS} vrf {VRF}", f" bgp router-id {self.lo(pe)}", " !",
                " address-family ipv4 unicast", "  redistribute connected", "  label vpn export auto",
                f"  rd vpn export {self.rt(d.rd_pe)}", f"  rt vpn both {self.rt(d.rt_tenant)}", "  export vpn",
                "  import vpn", " exit-address-family", "exit", "!"]

    def border_vrf_lines(self, border: str) -> List[str]:
        """The gateway: VPN export / import of the VRF and type-5 routes of what it imports."""
        d = self.data
        return [f"router bgp {PROVIDER_AS} vrf {VRF}", f" bgp router-id {self.lo(border)}", " !",
                " address-family ipv4 unicast", "  label vpn export auto", f"  rd vpn export {self.rt(d.rd_border)}",
                f"  rt vpn both {self.rt(d.rt_tenant)}", "  export vpn", "  import vpn", " exit-address-family", " !",
                " address-family l2vpn evpn", "  advertise ipv4 unicast", " exit-address-family", "exit", "!"]

    @staticmethod
    def route_map_all() -> List[str]:
        return ["route-map ALL permit 10", "exit", "!"]

    def _frr_conf(self, router: str) -> str:
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", "log file /var/log/frr/frr.log", "!"]
        site, role = site_of(router), role_of(router)
        if site in GATEWAY_SITES and role in ('leaf', 'border'):
            lines += self.vrf_vni_lines(site)
        if router in OSPF_ROUTERS:
            lines += self._ospf_lines(router)
        if router in MPLS_ROUTERS:
            lines += self._ldp_lines(router)
        if site in STRETCH_SITES:
            if role in ('pe1', 'pe2'):
                other = f"{site}_pe2" if role == 'pe1' else f"{site}_pe1"
                lines += self.route_map_all() + self.vpnv4_lines(router, other)
                lines += self.dci_vrf_lines(router)
            elif role in ('dc1', 'dc2'):
                lines += self.route_map_all()
                # fault 3 (fix site): fix_dc2 does not announce its loopback
                lines += self.dc_lines(router, announce_lo=(router != 'fix_dc2'))
                if site == 'fix':
                    # fault 1: no ebgp-multihop on fix_dc1; fault 2: no outbound route-map on fix_dc2
                    lines += self.evpn_dc_lines(router, multihop=(router != 'fix_dc1'), policy_out=(router != 'fix_dc2'))
        else:
            if role == 'leaf':
                lines += self.evpn_ibgp_lines(router, f"{site}_border") + self.leaf_vrf_lines(router)
            elif role == 'border':
                lines += self.evpn_ibgp_lines(router, f"{site}_leaf")
                if site == 'ag':
                    lines += self.vpnv4_lines(router, f"{site}_pe", header=False) + self.border_vrf_lines(router)
            elif role == 'pe':
                lines += self.vpnv4_lines(router, f"{site}_border") + self.pe_vrf_lines(router)
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    @staticmethod
    def _flat(lines: List[str]) -> List[str]:
        return [x.strip() for x in lines if x.strip() and x.strip() != '!']

    @staticmethod
    def wait_route_cmd(dest, vrf: str = None, seconds: int = 90) -> str:
        """Wait until the kernel has a route to *dest* (in *vrf*): the IGP, LDP and the VPN have
        converged (a BGP session configured before retries only after its connect timer)."""
        where = f" vrf {vrf}" if vrf else ""
        return (f"i=0; while ! ip route get {dest}{where} 2>/dev/null | grep -q ' via ' && [ $i -lt {seconds} ]; "
                f"do sleep 1; i=$((i+1)); done")

    # -- reference solutions -------------------------------------------------------

    def solution_stretch(self) -> Dict[str, Dict[str, List[str]]]:
        result = {}
        for dc in ('st_dc1', 'st_dc2'):
            result[dc] = {'sh': [f"ip link set eth0 mtu {MTU_SOLUTION}"], 'vtysh': self._flat(self.evpn_dc_lines(dc))}
        for r in ('st_pe1', 'st_p', 'st_pe2'):
            result[r] = {'sh': [f"ip link set eth{i} mtu {MTU_SOLUTION}" for i in range(2)], 'vtysh': []}
        return result

    def solution_gateway(self) -> Dict[str, Dict[str, List[str]]]:
        vtysh = self._flat(self.vpnv4_lines('gw_border', 'gw_pe', header=False)) + self._flat(self.border_vrf_lines('gw_border'))
        return {'gw_border': {'sh': [], 'vtysh': vtysh}}

    def solution_fix(self) -> Dict[str, Dict[str, List[str]]]:
        dc1, dc2 = self.lo('fix_dc1'), self.lo('fix_dc2')
        return {
            'fix_dc1': {'sh': [], 'vtysh': [f"router bgp {DC_AS['dc1']}", f"neighbor {dc2} ebgp-multihop {EBGP_MULTIHOP}",
                                            "exit"]},
            'fix_dc2': {'sh': [], 'vtysh': [f"router bgp {DC_AS['dc2']}", "address-family ipv4 unicast",
                                            f"network {dc2}/32", "exit-address-family", "address-family l2vpn evpn",
                                            f"neighbor {dc1} route-map ALL out", "exit-address-family", "exit"]},
            'fix_p': {'sh': [f"sysctl -w net.mpls.conf.{iface('fix_p', 'fix_l2')}.input=1"], 'vtysh': []},
        }

    def solution_aggregate(self) -> Dict[str, List[str]]:
        return {'ag_border': ["ip prefix-list NO-HOST seq 5 deny 0.0.0.0/0 ge 32",
                              "ip prefix-list NO-HOST seq 10 permit 0.0.0.0/0 le 32",
                              "route-map VPN-OUT permit 10", "match ip address prefix-list NO-HOST", "exit",
                              f"router bgp {PROVIDER_AS} vrf {VRF}", "address-family ipv4 unicast",
                              "route-map vpn export VPN-OUT", "exit-address-family", "exit"]}

    # -- applying the solutions ----------------------------------------------------

    def _apply_mixed(self, solution: Dict[str, Dict[str, List[str]]], step: int = 1):
        for r, parts in solution.items():
            for c in parts['sh']:
                self.cmd(r, c, step=step)
            if parts['vtysh']:
                self._vtysh(r, *parts['vtysh'], step=step)

    def _apply_stretch(self, step: int = 1):
        # the EVPN session first (the VTEPs reach each other through the VPN), then the MTU
        for dc in ('st_dc1', 'st_dc2'):
            other = 'st_dc2' if dc == 'st_dc1' else 'st_dc1'
            self.cmd(dc, self.wait_route_cmd(self.lo(other)), step=step, timeout=120)
            self._vtysh(dc, *self._flat(self.evpn_dc_lines(dc)), step=step)
        for r, parts in self.solution_stretch().items():
            for c in parts['sh']:
                self.cmd(r, c, step=step + 1)

    def _apply_gateway(self, step: int = 1):
        self.cmd('gw_border', self.wait_route_cmd(self.lo('gw_pe')), step=step, timeout=120)
        self._apply_mixed(self.solution_gateway(), step=step)

    def _apply_fix(self, step: int = 1):
        self._apply_mixed(self.solution_fix(), step=step)
        for dc, other in (('fix_dc1', 'fix_dc2'), ('fix_dc2', 'fix_dc1')):
            self.cmd(dc, self.wait_route_cmd(self.lo(other)), step=step + 1, timeout=120)
            self.cmd(dc, 'vtysh -c "clear bgp *"', step=step + 1, allow_error=True)

    def _apply_aggregate(self, step: int = 1):
        for r, cmds in self.solution_aggregate().items():
            self._vtysh(r, *cmds, step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for r in LOOPBACKS:
            self.cmd(r, f"ip addr add {getattr(d.ips, f'{r}_lo')} dev lo")
        for r in MPLS_ROUTERS:
            remount_proc_sys(self, r)
            self.cmd(r, trigger_mpls_modules_cmd())
        # the VRFs of the PEs
        for site in STRETCH_SITES:
            for pe in (f"{site}_pe1", f"{site}_pe2"):
                for c in (f"ip link add {VRF_DCI} type vrf table {VRF_DCI_TABLE}", f"ip link set {VRF_DCI} up",
                          f"ip link set eth0 master {VRF_DCI}"):
                    self.cmd(pe, c)
        for site in GATEWAY_SITES:
            pe = f"{site}_pe"
            for c in (f"ip link add {VRF} type vrf table {VRF_TABLE}", f"ip link set {VRF} up", f"ip link set eth0 master {VRF}"):
                self.cmd(pe, c)
        # the VTEPs of the stretch sites: the VXLAN device of the stretched VNI and its bridge
        for site in STRETCH_SITES:
            vni = d.vni(site)
            for dc in (f"{site}_dc1", f"{site}_dc2"):
                for c in vxlan_cmds(vx(vni), vni, local=self.lo(dc), learning=False) + bridge_cmds(br(vni), ['eth1', vx(vni)]):
                    self.cmd(dc, c)
        # the gateway sites: symmetric IRB on the leaf (L2VNI with its gateway, L3VNI), the L3VNI
        # of the border
        for site in GATEWAY_SITES:
            vni, l3 = d.vni(site), d.l3vni(site)
            leaf, border = f"{site}_leaf", f"{site}_border"
            cmds = (l3vni_cmds(VRF, VRF_TABLE, l3, self.lo(leaf), vxlan=vx(l3), bridge=br(l3))
                    + vxlan_cmds(vx(vni), vni, local=self.lo(leaf), learning=False)
                    + bridge_cmds(br(vni), ['eth1', vx(vni)], address=getattr(d.ips, f"{site}_leaf_gw"), vrf=VRF))
            for c in cmds:
                self.cmd(leaf, c)
            for c in l3vni_cmds(VRF, VRF_TABLE, l3, self.lo(border), vxlan=vx(l3), bridge=br(l3)):
                self.cmd(border, c)
        for r in MPLS_ROUTERS:
            self.cmd(r, f"sysctl -w net.mpls.platform_labels={PLATFORM_LABELS}", step=2)
            for name in core_ifaces(r):
                # fault 4 (fix site): MPLS input off on the interface of fix_p towards fix_pe2
                value = 0 if (r == 'fix_p' and name == iface('fix_p', 'fix_l2')) else 1
                self.cmd(r, f"sysctl -w net.mpls.conf.{name}.input={value}", step=2)
        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (VNI étendu au-dessus du L3VPN)"))
    def solve_stretch(self):
        self._apply_stretch()
        self.cmd('st_p', f"sleep {OSPF_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (passerelle EVPN - L3VPN)"))
    def solve_gateway(self):
        self._apply_gateway()
        self.cmd('gw_border', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (dépannage)"))
    def solve_fix(self):
        self._apply_fix()
        self.cmd('fix_dc1', f"sleep {CONVERGE_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (routes exportées vers le VPN, bonus)"))
    def solve_aggregate(self):
        self._apply_aggregate()
        self.cmd('ag_border', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        self._apply_stretch()
        self._apply_gateway()
        self._apply_fix()
        self._apply_aggregate()
        self.cmd('st_p', f"sleep {OSPF_WAIT}", step=3)


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


def _rt(s) -> str:
    found = re.findall(r'\d+:\d+', str(s or ''))
    return found[0] if found else ''


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
        if parts['vtysh']:
            text += "```\n" + "\n".join(["configure terminal"] + [f" {c}" for c in parts['vtysh']]
                                        + ["end", "write"]) + "\n```"
        blocks.append(text.rstrip())
    return "\n\n".join(blocks)


def _vpn_paths(vpn: Dict[str, Dict[str, list]], prefix, nexthop=None) -> List[dict]:
    """The VPNv4 paths of *prefix* under any RD (with *nexthop* when given)."""
    paths = []
    for routes in (vpn or {}).values():
        for p in routes.get(str(prefix), []):
            if nexthop is None or p.get('nexthop') == str(nexthop):
                paths.append(p)
    return paths


def _host_routes(vpn: Dict[str, Dict[str, list]], network: IPv4Network, nexthop) -> List[str]:
    """The /32 VPNv4 prefixes inside *network* announced by *nexthop*."""
    found = []
    for routes in (vpn or {}).values():
        for prefix, paths in routes.items():
            try:
                net = IPv4Network(prefix)
            except ValueError:
                continue
            if net.prefixlen == 32 and net.subnet_of(network) and any(p.get('nexthop') == str(nexthop) for p in paths):
                found.append(prefix)
    return found


def _route_via(routes: Dict[str, dict], prefix, gateway) -> bool:
    entry = routes.get(str(prefix)) or {}
    return any(str(gw) == str(gateway) for gw, _dev in entry.get('nexthops', []))


def _stack_of(routes: Dict[str, dict], prefix) -> List[int]:
    stacks = kernel_route_labels(routes, prefix)
    return stacks[0] if stacks else []


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest, count: int = 3, step: int = 1) -> bool:
        _out, code = self.test(src, f"ping -c {count} -i 0.2 -w 4 {dest}", step=step, allow_error=True)
        return code == 0

    def _burst(self, src: str, dest) -> bool:
        _out, code = self.test(src, f"ping -c 5 -i 0.2 -w 4 {dest}", step=2, allow_error=True)
        return code == 0

    def _counters_delta(self, router: str, ifname: str) -> int:
        return mpls_counter_delta(get_mpls_counters(self, router, step=1), get_mpls_counters(self, router, step=3),
                                  ifname)

    def _mac(self, host: str) -> str:
        out, code = self.test(host, "cat /sys/class/net/eth0/address", allow_error=True)
        return out.strip().lower() if code == 0 else ''

    @staticmethod
    def _established(summary: Dict, peer) -> bool:
        p = (summary.get('peers') or {}).get(str(peer)) or {}
        return bool(p.get('established')) and not p.get('policy_blocked')

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net, rt = ns.lo, ns.addr, ns.net, ns.rt
        ip = ns.host_ip

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- part 1 --------------------------------------------------
        st_sum = get_bgp_evpn_summary(self, 'st_dc1')
        # read after the ping of step 2: the type-2 routes of the hosts exist once they have sent a frame
        st_routes = {dc: get_bgp_evpn_routes(self, dc, step=3) for dc in ('st_dc1', 'st_dc2')}
        st_mac = {h: self._mac(h) for h in ('st_h1', 'st_h2')}
        st_frag0 = {pe: get_frag_creates(self, pe, step=1) for pe in ('st_pe1', 'st_pe2')}
        st_ping = self._burst('st_h1', ip('st_h2'))
        st_delta = self._counters_delta('st_p', 'eth0')
        st_df = self.test('st_h1', df_ping_cmd(ip('st_h2')), step=2, allow_error=True)[1] == 0
        st_frag1 = {pe: get_frag_creates(self, pe, step=3) for pe in ('st_pe1', 'st_pe2')}

        # ---------------- part 2 --------------------------------------------------
        gw_sum = get_bgp_vpn_summary(self, 'gw_border')
        gw_vpn = get_bgp_vpn_routes(self, 'gw_pe')
        gw_k_pe = get_kernel_routes(self, 'gw_pe', allow_error=True, vrf=VRF)
        gw_routes = get_bgp_evpn_routes(self, 'gw_leaf')
        gw_k_leaf = get_kernel_routes(self, 'gw_leaf', allow_error=True, vrf=VRF)
        gw_k_border = get_kernel_routes(self, 'gw_border', allow_error=True, vrf=VRF)
        gw_ping = self._burst('gw_h1', ip('gw_h2'))
        gw_delta = self._counters_delta('gw_p', 'eth0')

        # ---------------- part 3 --------------------------------------------------
        fix_cfg = {dc: get_frr_running_config(self, dc, allow_error=True) for dc in ('fix_dc1', 'fix_dc2')}
        fix_k = get_kernel_routes(self, 'fix_dc1', allow_error=True)
        fix_sysctl = get_mpls_sysctls(self, 'fix_p')
        fix_sum = get_bgp_evpn_summary(self, 'fix_dc1')
        fix_ping = self._ping('fix_h1', ip('fix_h2'))

        # ---------------- part 4 --------------------------------------------------
        # the host refreshes the ARP entry of its leaf (its MAC+IP route lives while the entry is fresh)
        self.test('ag_h1', f"ping -c 2 -i 0.2 -w 2 {d.ips.ag_leaf_gw.ip}", allow_error=True)
        self.test('ag_pe', "sleep 4", step=2)
        ag_vpn = get_bgp_vpn_routes(self, 'ag_pe', step=2)
        ag_ping = self._ping('ag_h1', ip('ag_h2'), step=2)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('st', "1 — VNI étendu au-dessus d'un L3VPN",
                  "les VTEP `st_dc1` (AS 65101), `st_dc2` (AS 65102), l'opérateur `st_pe1`, `st_p`, `st_pe2`, les "
                  "hôtes `st_h1`, `st_h2`"),
                 ('gw', "2 — passerelle EVPN ↔ L3VPN",
                  "le leaf `gw_leaf`, la passerelle `gw_border`, `gw_p`, `gw_pe`, les hôtes `gw_h1` (data centre), "
                  "`gw_h2` (site distant)"),
                 ('fix', "3 — dépannage", "`fix_dc1`, `fix_dc2`, `fix_pe1`, `fix_p`, `fix_pe2`, les hôtes `fix_h1`, "
                                          "`fix_h2`"),
                 ('ag', "4 — ce qui part vers le VPN (bonus)", "`ag_leaf`, `ag_border`, `ag_p`, `ag_pe`, les hôtes "
                                                              "`ag_h1`, `ag_h2`")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in LINKS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                if n in LINKS:
                    members[n].append(f"`{r}` eth{i} (`{addr(r, n)}`)")
        rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in LINKS]
        rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                 + ", ".join(f"`{r}` `{lo(r)}/32`" for r in LOOPBACKS if site_of(r) == site) + " |"
                 for site in SITE_NUMBER]
        labels = {'st_net': "site 1, VNI étendu", 'gw_net': "site 2, data centre", 'gw_remote_net': "site 2, site distant",
                  'fix_net': "site 3, VNI étendu", 'ag_net': "site 4, data centre", 'ag_remote_net': "site 4, site distant"}
        for subnet, label in labels.items():
            hosts = ", ".join(f"`{h}` (`{ip(h)}`)" for h, (_n, s, _g) in HOSTS.items() if s == subnet)
            gws = {'gw_net': ('gw_leaf', 'gw_leaf_gw'), 'gw_remote_net': ('gw_pe', 'gw_pe_gw'),
                   'ag_net': ('ag_leaf', 'ag_leaf_gw'), 'ag_remote_net': ('ag_pe', 'ag_pe_gw')}
            if subnet in gws:
                router, key = gws[subnet]
                hosts += f", `{router}` (`{getattr(d.ips, key).ip}`, passerelle)"
            rows.append(f"| {label} | `{net(subnet)}` | {hosts} |")
        addressing = "\n".join(rows)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente l'interconnexion de data centres au-dessus d'un réseau
MPLS, avec Linux et FRR. Le TP suppose connus VXLAN et EVPN (TP « VXLAN et EVPN dans un data
centre ») et les VPN BGP/MPLS (TP « VPN MPLS/BGP »).

**Le réseau.** Il est fait de **quatre sites indépendants**, un par partie ; chaque site a sa couleur
sur le schéma. L'opérateur est l'AS **{pas}** :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR) : configurez-les avec `vtysh`. Dans le cœur de
  l'opérateur, **OSPF et LDP fonctionnent** ; MPLS est activé dans les noyaux (table des labels,
  entrée MPLS des interfaces du cœur).
- Sites 1 et 3 : le L3VPN `{dci}` relie les deux data centres ; chaque VTEP annonce son interface de
  bouclage à son PE par eBGP ; l'interface `vxlan` du VNI étendu et son pont existent sur les VTEP.
- Sites 2 et 4 : le leaf est en IRB symétrique (VRF `{vrf}`, L3VNI, passerelle des hôtes, ses
  sous-réseaux annoncés en type 5) ; sa session EVPN avec la passerelle fonctionne ; le PE a la VRF
  `{vrf}` du site distant et sa session VPNv4 avec la passerelle. Tout est dans l'AS {pas}.
- Les fichiers `/etc/hosts` contiennent les noms : `st_p-eth1` désigne l'adresse de l'interface
  `eth1` de `st_p`, `st_dc2-lo` l'adresse de bouclage de `st_dc2`.

**Plan d'adressage.**

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- Partie 1 : VNI **{st_vni}** ; VRF `{dci}` des PE : RD et RT {rt_dci}.
- Partie 2 : VNI du data centre **{gw_vni}**, L3VNI **{gw_l3}** ; VRF `{vrf}` : RT VPN **{rt_t}**, RD du
  PE {rd_pe}, RD à utiliser sur la passerelle **{rd_b}**.
- Partie 3 : VNI **{fix_vni}** ; VRF `{dci}` : RD et RT {rt_dci}.
- Partie 4 : VNI du data centre {ag_vni}, L3VNI {ag_l3} ; RT VPN {rt_t}.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`). Les commandes `ip` et `sysctl` ne sont
  pas enregistrées : ne redémarrez pas les machines.
- Après un changement de MTU, OSPF met plusieurs dizaines de secondes à rétablir ses adjacences ;
  une session BGP qui attendait peut mettre deux minutes à réessayer (`clear bgp *`).

**Évaluation.** Chaque évaluation lit vos réponses, l'état de BGP (EVPN, VPNv4), les tables du noyau,
les compteurs MPLS et de fragmentation, puis envoie des `ping`. Elle dure une vingtaine de secondes.
""").format(site_rows=site_rows, addressing=addressing, pas=PROVIDER_AS, dci=VRF_DCI, vrf=VRF, st_vni=d.st_vni,
            rt_dci=rt(d.rt_dci), gw_vni=d.gw_vni, gw_l3=d.gw_l3vni, rt_t=rt(d.rt_tenant), rd_pe=rt(d.rd_pe),
            rd_b=rt(d.rd_border), fix_vni=d.fix_vni, ag_vni=d.ag_vni, ag_l3=d.ag_l3vni)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_stretch`, `solve_gateway`, `solve_fix` et `solve_aggregate` (onglet
*Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes, attend {wait} s (les adjacences OSPF relancées par
le changement de MTU) puis remplit tous les formulaires : une évaluation lancée dès son retour donne
tous les points, bonus compris.

Les pannes du site `fix` : pas d'`ebgp-multihop` sur `fix_dc1`, pas de route-map de sortie EVPN sur
`fix_dc2`, `fix_dc2` n'annonce pas son interface de bouclage à `fix_pe2`, entrée MPLS désactivée sur
l'interface `{fix_if}` de `fix_p` (vers `fix_pe2`).
""").format(wait=OSPF_WAIT, fix_if=iface('fix_p', 'fix_l2'))),
        )

        # =====================================================================
        # Part 1 — a VNI stretched over an L3VPN (st)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("stretch"), tr("Partie 1 — un VNI étendu au-dessus d'un L3VPN (site st)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Étendre un VNI entre deux data centres"),
            description=tr("""
Les VTEP `st_dc1` (AS 65101) et `st_dc2` (AS 65102) sont deux sites du L3VPN `{dci}` de l'opérateur :
`st_pe1`, `st_p`, `st_pe2`. Chacun annonce son interface de bouclage à son PE, et ces adresses se
joignent déjà à travers le VPN. Chaque VTEP a l'interface `vxlan` du VNI **{vni}** (sans
apprentissage) dans un pont avec `eth1`, vers son hôte (`st_h1`, `st_h2`, sous-réseau `{subnet}`)
(sections @@ref:vxlan-over-l3vpn@@ à @@ref:mtu@@).

1. Établissez une session EVPN entre `st_dc1` et `st_dc2`, entre leurs interfaces de bouclage, avec
   une politique d'entrée et de sortie qui laisse tout passer (une route-map `ALL` existe déjà).
   Vérifiez que `st_h1` joint `st_h2` ; regardez les RT des routes reçues.
2. Regardez les paquets sur le lien `st_l1` (`tcpdump -nei eth0 mpls` sur `st_p`) : combien de labels,
   quels en-têtes ?
3. Faites passer les paquets de 1500 octets des hôtes (`ping -M do -s 1472`) **sans fragmentation**,
   sans changer la MTU des hôtes.
""").format(dci=VRF_DCI, vni=d.st_vni, subnet=net('st_net'))
            + instructor(tr("""
**Solution.**

{solution}

Les deux VTEP exportent des RT automatiques différentes (`65101:{vni}`, `65102:{vni}`) ; FRR importe
tout de même les routes (il ne compare que le VNI). Sur `st_l1`, un paquet porte deux labels (LDP puis
VPN), puis l'en-tête IP des VTEP, UDP 4789, VXLAN et la trame de l'hôte : 58 octets de plus que le
paquet de l'hôte. Avec la MTU du cœur seule à 1500, `st_pe1` fragmente les paquets VXLAN ; avec celle
des VTEP, ils répondent par un ICMP *fragmentation needed*.

Évaluation : `st_session` (4 : session EVPN établie, avec politique), `st_routes` (4 : chaque VTEP a
la route de type 3 de l'autre et l'adresse MAC de l'hôte distant en type 2), `st_ping` (4), `st_mpls`
(2 : `st_p` reçoit des paquets étiquetés pendant le ping), `st_mtu` (6 : ping de 1500 octets avec DF,
sans fragment créé par `st_pe1` ni `st_pe2`) ; `st_q_labels`, `st_q_overhead`, `st_q_rt` (1 chacun) ;
pour l'enseignant seulement : `st_q_import`, `st_q_core`, `st_q_policy` (1 chacun).
""").format(solution=_mixed_text(ns.solution_stretch()), vni=d.st_vni)),
        )
        cheat_st = {'labels': '2', 'overhead': '58', 'rt': f"{DC_AS['dc2']}:{d.st_vni}", 'import': 'vni',
                    'core': 'none', 'policy': 'nothing'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site st"),
            description=tr("""
- nombre de labels des paquets de `st_h1` vers `st_h2` sur le lien `st_l1` : @@{labels:[0-9]+}@@
- octets ajoutés sur ce lien au paquet IP de `st_h1` (VXLAN et labels) : @@{overhead:[0-9]+}@@
- route target des routes EVPN du VNI que `st_dc1` reçoit de `st_dc2` : @@{rt:[0-9: ]+}@@
- `st_dc1` importe ces routes parce que :
  @@{import:>FRR ne compare que le VNI d'une RT automatique>>>vni|les RT sont égales>>>equal|le RD est le même>>>rd|toute route EVPN reçue est importée>>>all}@@
- ce que `st_p` sait du VNI étendu :
  @@{core:>rien : il commute des labels vers le PE de sortie>>>none|il connaît le VNI par EVPN>>>evpn|il apprend les adresses MAC>>>mac|il connaît les adresses des VTEP>>>vtep}@@
- sans route-map sur la session EVPN, les deux VTEP :
  @@{policy:>établissent la session mais n'échangent rien>>>nothing|n'établissent pas la session>>>down|échangent tout>>>all|n'échangent que les routes de type 3>>>type3}@@
""")
            + instructor(tr("""
**Solution.** **2** ; **58** ; **`{rt}`** ; FRR ne compare que le VNI d'une RT automatique ; rien ;
ils établissent la session mais n'échangent rien (RFC 8212).

Évaluation : `st_q_labels`, `st_q_overhead`, `st_q_rt` (1 chacun) ; pour l'enseignant seulement :
`st_q_import`, `st_q_core`, `st_q_policy` (1 chacun).
""").format(rt=cheat_st['rt'])),
            cheat_answers={"final": cheat_st, "solve_stretch": cheat_st},
        )
        routes_ok = [bool(evpn_routes(st_routes['st_dc1'], route_type=3, vtep=lo('st_dc2'))),
                     bool(evpn_routes(st_routes['st_dc2'], route_type=3, vtep=lo('st_dc1'))),
                     bool(st_mac['st_h2']) and bool(evpn_routes(st_routes['st_dc1'], route_type=2, mac=st_mac['st_h2'])),
                     bool(st_mac['st_h1']) and bool(evpn_routes(st_routes['st_dc2'], route_type=2, mac=st_mac['st_h1']))]
        self.add_grade_element(
            title=no_tr("st_session"), max_grade=4, grade_part=part1,
            grade=4 * int(self._established(st_sum, lo('st_dc2'))), description=tr("session EVPN entre les VTEP"),
        )
        self.add_grade_element(
            title=no_tr("st_routes"), max_grade=4, grade_part=part1, grade=sum(routes_ok),
            description=tr("routes de type 3 et 2 échangées"),
        )
        self.add_grade_element(
            title=no_tr("st_ping"), max_grade=4, grade_part=part1, grade=4 * int(st_ping),
            description=tr("st_h1 joint st_h2"),
        )
        self.add_grade_element(
            title=no_tr("st_mpls"), max_grade=2, grade_part=part1, grade=2 * int(st_ping and st_delta >= 5),
            description=tr("trafic étiqueté dans le cœur"),
        )
        no_frag = all(frag_delta(st_frag0[pe], st_frag1[pe]) == 0 for pe in ('st_pe1', 'st_pe2'))
        self.add_grade_element(
            title=no_tr("st_mtu"), max_grade=6, grade_part=part1, grade=6 * int(st_df and no_frag),
            description=tr("paquets de 1500 octets sans fragmentation"),
        )
        self.add_grade_element(
            title=no_tr("st_q_labels"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('labels')) == 2),
            description=tr("labels dans le cœur"),
        )
        self.add_grade_element(
            title=no_tr("st_q_overhead"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('overhead')) == 58),
            description=tr("surcoût VXLAN et MPLS"),
        )
        self.add_grade_element(
            title=no_tr("st_q_rt"), max_grade=1, grade_part=part1, grade=int(_rt(q1.get('rt')) == cheat_st['rt']),
            description=tr("RT automatique de st_dc2"),
        )
        self.add_grade_element(
            title=no_tr("st_q_import"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('import')) == 'vni'), description=tr("import des RT automatiques"),
        )
        self.add_grade_element(
            title=no_tr("st_q_core"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('core')) == 'none'), description=tr("ce que sait le cœur"),
        )
        self.add_grade_element(
            title=no_tr("st_q_policy"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('policy')) == 'nothing'), description=tr("RFC 8212"),
        )

        # =====================================================================
        # Part 2 — EVPN <-> L3VPN gateway (gw)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("gateway"), tr("Partie 2 — une passerelle EVPN ↔ L3VPN (site gw)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Relier la VRF du data centre au VPN de l'opérateur"),
            description=tr("""
Dans le data centre, `gw_leaf` route le sous-réseau `{dc}` de `gw_h1` en IRB symétrique (VRF `{vrf}`,
L3VNI **{l3}**) et l'annonce en type 5 à `gw_border`, son voisin EVPN. `gw_border` est aussi un **PE**
de l'opérateur : OSPF et LDP fonctionnent avec `gw_p` et `gw_pe`, et il a la VRF `{vrf}` avec le même
L3VNI. `gw_pe` a la VRF `{vrf}` du site distant (sous-réseau `{remote}`, hôte `gw_h2`), avec la RT
**{rt_t}**, et attend une session VPNv4 de `gw_border` (section @@ref:gateway@@).

1. Sur `gw_border`, établissez la session VPNv4 avec `gw_pe` (entre interfaces de bouclage).
2. Toujours sur `gw_border`, dans l'instance BGP de la VRF `{vrf}` : exportez la VRF en VPNv4 (label,
   RD **{rd_b}**, RT {rt_t}), importez les routes VPNv4 de cette RT, et annoncez le contenu de la VRF
   en routes de type 5.
3. Vérifiez que `gw_h1` joint `gw_h2`. Regardez la table EVPN de `gw_leaf`, la table VPNv4 de
   `gw_pe`, la table de la VRF sur chacun des trois routeurs (`ip route show vrf {vrf}`), et les
   paquets sur `gw_u1` et `gw_l1`.
""").format(dc=net('gw_net'), vrf=VRF, l3=d.gw_l3vni, remote=net('gw_remote_net'), rt_t=rt(d.rt_tenant),
            rd_b=rt(d.rd_border))
            + instructor(tr("""
**Solution.**

{solution}

`gw_leaf` reçoit le sous-réseau distant en type 5, avec `gw_border` comme prochain saut et le L3VNI ;
`gw_pe` reçoit en VPNv4 le sous-réseau du data centre (et les /32 des hôtes connus), avec `gw_border`
comme prochain saut et le label VPN de la VRF. Sur `gw_u1`, les paquets sont en VXLAN (VNI {l3}) ;
sur `gw_l1`, ils portent deux labels.

Évaluation : `gw_vpnv4` (4 : session VPNv4 établie), `gw_to_vpn` (5 : `gw_pe` a le sous-réseau du data
centre en VPNv4 par `gw_border`, et sa route dans la VRF avec deux labels), `gw_to_evpn` (5 :
`gw_leaf` a le sous-réseau distant en type 5 par `gw_border`, et sa route dans la VRF vers
`gw_border`), `gw_border_routes` (2 : sur `gw_border`, la route du site distant avec deux labels),
`gw_ping` (6), `gw_mpls` (2 : `gw_p` reçoit des paquets étiquetés pendant le ping) ; `gw_q_labels`,
`gw_q_vni` (1 chacun) ; pour l'enseignant seulement : `gw_q_reoriginate`, `gw_q_core` (1 chacun).
""").format(solution=_mixed_text(ns.solution_gateway()), l3=d.gw_l3vni)),
        )
        cheat_gw = {'labels': '2', 'vni': str(d.gw_l3vni), 'reoriginate': 'type5_self', 'core': 'none'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Ce que fait la passerelle"),
            description=tr("""
- nombre de labels des paquets de `gw_h1` vers `gw_h2` sur le lien `gw_l1` : @@{labels:[0-9]+}@@
- VNI des paquets VXLAN de `gw_h1` vers `gw_h2` sur le lien `gw_u1` : @@{vni:[0-9]+}@@
- `gw_border` reçoit en VPNv4 la route du site distant ; il annonce à `gw_leaf` :
  @@{reoriginate:>une route de type 5, avec sa propre adresse de VTEP comme prochain saut>>>type5_self|la route VPNv4 telle quelle>>>vpnv4|une route de type 5 avec gw_pe comme prochain saut>>>type5_pe|une route de type 2>>>type2}@@
- ce que `gw_p` sait des sous-réseaux du client :
  @@{core:>rien : il commute des labels vers les PE>>>none|il les apprend par OSPF>>>ospf|il les apprend en EVPN>>>evpn|il les apprend en VPNv4>>>vpnv4}@@
""")
            + instructor(tr("""
**Solution.** **2** ; **{l3}** (le L3VNI) ; une route de type 5, avec sa propre adresse de VTEP comme
prochain saut ; rien.

Évaluation : `gw_q_labels`, `gw_q_vni` (1 chacun) ; pour l'enseignant seulement : `gw_q_reoriginate`,
`gw_q_core` (1 chacun).
""").format(l3=d.gw_l3vni)),
            cheat_answers={"final": cheat_gw, "solve_gateway": cheat_gw},
        )
        self.add_grade_element(
            title=no_tr("gw_vpnv4"), max_grade=4, grade_part=part2, grade=4 * int(self._established(gw_sum, lo('gw_pe'))),
            description=tr("session VPNv4 de la passerelle"),
        )
        self.add_grade_element(
            title=no_tr("gw_to_vpn"), max_grade=5, grade_part=part2,
            grade=3 * int(bool(_vpn_paths(gw_vpn, net('gw_net'), lo('gw_border'))))
            + 2 * int(len(_stack_of(gw_k_pe, net('gw_net'))) == 2),
            description=tr("routes du data centre exportées en VPNv4"),
        )
        self.add_grade_element(
            title=no_tr("gw_to_evpn"), max_grade=5, grade_part=part2,
            grade=3 * int(bool(evpn_routes(gw_routes, route_type=5, network=net('gw_remote_net'), nexthop=lo('gw_border'))))
            + 2 * int(_route_via(gw_k_leaf, net('gw_remote_net'), lo('gw_border'))),
            description=tr("route du site distant ré-originée en type 5"),
        )
        self.add_grade_element(
            title=no_tr("gw_border_routes"), max_grade=2, grade_part=part2,
            grade=2 * int(len(_stack_of(gw_k_border, net('gw_remote_net'))) == 2),
            description=tr("route du site distant étiquetée sur la passerelle"),
        )
        self.add_grade_element(
            title=no_tr("gw_ping"), max_grade=6, grade_part=part2, grade=6 * int(gw_ping),
            description=tr("gw_h1 joint gw_h2"),
        )
        self.add_grade_element(
            title=no_tr("gw_mpls"), max_grade=2, grade_part=part2, grade=2 * int(gw_ping and gw_delta >= 5),
            description=tr("trafic étiqueté dans le cœur"),
        )
        self.add_grade_element(
            title=no_tr("gw_q_labels"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('labels')) == 2),
            description=tr("labels dans le cœur"),
        )
        self.add_grade_element(
            title=no_tr("gw_q_vni"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('vni')) == d.gw_l3vni),
            description=tr("VNI dans le data centre"),
        )
        self.add_grade_element(
            title=no_tr("gw_q_reoriginate"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('reoriginate')) == 'type5_self'), description=tr("ré-origination"),
        )
        self.add_grade_element(
            title=no_tr("gw_q_core"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('core')) == 'none'), description=tr("ce que sait le cœur"),
        )

        # =====================================================================
        # Part 3 — troubleshooting (fix)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("fix"), tr("Partie 3 — dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une interconnexion en panne"),
            description=tr("""
Le site `fix` reproduit le site 1, une fois la session EVPN configurée : les VTEP `fix_dc1` (AS
65101) et `fix_dc2` (AS 65102), le L3VPN `{dci}` (`fix_pe1`, `fix_p`, `fix_pe2`), le VNI **{vni}** entre
`fix_h1` et `fix_h2` (sous-réseau `{subnet}`). Les MTU sont restées à 1500, ce qui suffit pour des
`ping` ordinaires. Pourtant `fix_h1` ne joint pas `fix_h2` : **quatre pannes** ont été glissées, côté
data centres et côté opérateur (section @@ref:debug@@).

Trouvez et corrigez chaque panne sans tout reconfigurer : vérifiez de bas en haut, des interfaces
de bouclage des VTEP jusqu'aux routes EVPN.
""").format(dci=VRF_DCI, vni=d.fix_vni, subnet=net('fix_net'))
            + instructor(tr("""
**Solution.**

{solution}

puis `clear bgp *` sur les VTEP (la session réessaie sinon au bout de deux minutes).

Évaluation : `fix_multihop` (3 : `ebgp-multihop` sur `fix_dc1`), `fix_policy` (3 : route-map de sortie
EVPN sur `fix_dc2`), `fix_loopback` (3 : `fix_dc1` a une route vers l'interface de bouclage de
`fix_dc2`), `fix_mpls_input` (3 : entrée MPLS de `{fix_if}` sur `fix_p`), `fix_session` (2 : session
EVPN établie, avec politique), `fix_ping` (4) ; pour l'enseignant seulement : `fix_q_multihop`,
`fix_q_input` (1 chacun).
""").format(solution=_mixed_text(ns.solution_fix()), fix_if=iface('fix_p', 'fix_l2'))),
        )
        cheat_fix = {'multihop': 'connected', 'input': 'dropped'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Ce que montraient les pannes"),
            description=tr("""
- sans `ebgp-multihop`, `fix_dc1` :
  @@{multihop:>refuse un voisin eBGP qui n'est pas directement connecté>>>connected|établit la session sans échanger de routes>>>policy|établit la session normalement>>>ok|attend une session iBGP>>>ibgp}@@
- les paquets étiquetés reçus par `fix_p` sur l'interface dont l'entrée MPLS est désactivée sont :
  @@{input:>comptés en réception puis jetés>>>dropped|routés sans leurs labels>>>popped|renvoyés au PE>>>returned|rejetés avec un ICMP>>>icmp}@@
""")
            + instructor(tr("""
**Solution.** Il refuse un voisin eBGP qui n'est pas directement connecté ; comptés en réception puis
jetés (`rx_dropped` des compteurs MPLS).

Évaluation, pour l'enseignant seulement : `fix_q_multihop`, `fix_q_input` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        rb1 = (fix_cfg['fix_dc1'] or {}).get('router_bgp') or {}
        rb2 = (fix_cfg['fix_dc2'] or {}).get('router_bgp') or {}
        n1 = (rb1.get('neighbors') or {}).get(str(lo('fix_dc2'))) or {}
        evpn2 = ((rb2.get('address_families') or {}).get('l2vpn evpn') or {}).get('neighbors') or {}
        self.add_grade_element(
            title=no_tr("fix_multihop"), max_grade=3, grade_part=part3, grade=3 * int(bool(n1.get('ebgp_multihop'))),
            description=tr("ebgp-multihop sur fix_dc1"),
        )
        self.add_grade_element(
            title=no_tr("fix_policy"), max_grade=3, grade_part=part3,
            grade=3 * int(bool((evpn2.get(str(lo('fix_dc1'))) or {}).get('route_map_out'))),
            description=tr("route-map de sortie EVPN sur fix_dc2"),
        )
        self.add_grade_element(
            title=no_tr("fix_loopback"), max_grade=3, grade_part=part3,
            grade=3 * int(f"{lo('fix_dc2')}/32" in fix_k), description=tr("interface de bouclage de fix_dc2 annoncée"),
        )
        self.add_grade_element(
            title=no_tr("fix_mpls_input"), max_grade=3, grade_part=part3,
            grade=3 * int(fix_sysctl.get('input', {}).get(iface('fix_p', 'fix_l2')) == 1),
            description=tr("entrée MPLS de fix_p"),
        )
        self.add_grade_element(
            title=no_tr("fix_session"), max_grade=2, grade_part=part3, grade=2 * int(self._established(fix_sum, lo('fix_dc2'))),
            description=tr("session EVPN établie"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=4, grade_part=part3, grade=4 * int(fix_ping),
            description=tr("fix_h1 joint fix_h2"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_multihop"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('multihop')) == 'connected'), description=tr("eBGP multihop"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_input"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('input')) == 'dropped'), description=tr("entrée MPLS désactivée"),
        )

        # =====================================================================
        # Part 4 — what leaks into the VPN (ag, bonus)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("aggregate"), tr("Partie 4 — ce qui part vers le VPN (site ag, bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Ne pas exporter les routes des hôtes (bonus)"),
            description=tr("""
Le site `ag` est une passerelle complète, comme le site 2 une fois résolu : `ag_h1` (data centre,
`{dc}`) joint `ag_h2` (site distant). Mais `ag_pe` reçoit en VPNv4, en plus du sous-réseau du data
centre, une route /32 par hôte connu de `ag_leaf` (section @@ref:leak@@).

1. Regardez la table VPNv4 de `ag_pe` après un `ping` de `ag_h1` vers sa passerelle.
2. Sur `ag_border`, n'exportez plus vers le VPN que les préfixes plus courts qu'un /32, sans toucher
   à `ag_leaf` ni à `ag_pe`. `ag_h1` doit toujours joindre `ag_h2`.
""").format(dc=net('ag_net'))
            + instructor(tr("""
**Solution.**

{solution}

Évaluation (bonus) : `ag_no_host` (4 : `ag_pe` a le sous-réseau du data centre par `ag_border`, et
aucune route /32 de ce sous-réseau, juste après un `ping` d'`ag_h1` vers sa passerelle), `ag_ping` (2 :
`ag_h1` joint `ag_h2`, les /32 filtrées).
""").format(solution=_vtysh_text(ns.solution_aggregate()))),
        )
        # the subnet is exported from the start: it only counts with the host routes gone
        subnet_ok = bool(_vpn_paths(ag_vpn, net('ag_net'), lo('ag_border')))
        no_host = subnet_ok and not _host_routes(ag_vpn, net('ag_net'), lo('ag_border'))
        self.add_grade_element(
            title=no_tr("ag_no_host"), max_grade=4, grade_part=part4, bonus=True, grade=4 * int(no_host),
            description=tr("le sous-réseau du data centre, sans les routes des hôtes"),
        )
        self.add_grade_element(
            title=no_tr("ag_ping"), max_grade=2, grade_part=part4, bonus=True, grade=2 * int(no_host and ag_ping),
            description=tr("ag_h1 joint ag_h2"),
        )


_TRANSLATIONS = {}
