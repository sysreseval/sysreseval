"""VXLAN and EVPN lab with Linux and FRR (bgpd, ospfd, pimd): VXLAN overlays in a data centre, the
EVPN control plane, routing between VNIs.

IPv4 only, the fabric is AS 65000 and its underlay runs OSPF (given).  Five independent sites, one
per part (completing a part gives all its points whatever the others):

- ``static``: three VTEPs around a router; the students create the VXLAN devices and their bridges,
  the head-end replication flood list, and raise the underlay MTU so that 1500-byte packets cross
  without fragmentation;
- ``evpn_l2``: a spine and three leaves with their VXLAN devices given (two VNIs sharing one
  subnet); the students build the iBGP EVPN sessions with the spine as route reflector;
- ``irb``: two leaves and a border leaf with the layer-2 EVPN given; the students add symmetric IRB
  (VRF, L3VNI), a distributed anycast gateway, ARP suppression and type-5 routes (the subnets of
  the leaves, an external network behind the border);
- ``fix``: a layer-2 EVPN shipped with four faults (wrong VNI, spine neighbour not a route
  reflector client, no ``advertise-all-vni``, VXLAN device outside its bridge);
- ``mcast`` (bonus): flood-and-learn VXLAN with a multicast group over a PIM-SM underlay.

The ``vxlan``, ``vrf`` and ``bridge`` modules of the host are loaded by the kernel itself when a
container creates such a device.  Grading reads the VXLAN devices and forwarding databases of the
kernel (lib/vxlan.py), the EVPN json of vtysh (lib/frr.py), the VRF tables, the fragmentation counter
of the underlay router and real pings.  The states ``solve_<part>`` apply the reference solution of
one part, ``final`` all of them.  Facts checked live: ``.claude/rules/lib-vxlan.md``.
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
from net_config import NetConfigEntry, set_net_config_entry
from openvpn import get_ip_addresses_json
from bridging import addresses_of
from frr import (
    evpn_family, evpn_routes, get_bgp_evpn_routes, get_bgp_evpn_summary, get_evpn_vnis, get_frr_running_config,
    get_kernel_routes, get_mroutes,
)
from vxlan import (
    VXLAN_PORT, bridge_cmds, df_ping_cmd, flood_cmds, flood_list, frag_delta, get_bridge_port_flags, get_fdb_all,
    get_frag_creates, get_ip_links, l3vni_cmds, link_address, link_master, normalize_mac, remote_macs, vxlan_cmds,
    vxlan_devices, vxlan_of_vni,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("VXLAN et EVPN : réseau overlay d'un data centre", en="VXLAN and EVPN: data centre overlay network")
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

# Router interfaces in ethN order: the network of each (underlay links first, then the host LANs).
ROUTER_IFACES = {
    'st_r': ['st_u1', 'st_u2', 'st_u3'],
    'st_vtep1': ['st_u1', 'st_lan1'],
    'st_vtep2': ['st_u2', 'st_lan2'],
    'st_vtep3': ['st_u3', 'st_lan3'],
    'l2_spine': ['l2_u1', 'l2_u2', 'l2_u3'],
    'l2_leaf1': ['l2_u1', 'l2_a1_lan'],
    'l2_leaf2': ['l2_u2', 'l2_a2_lan', 'l2_b2_lan'],
    'l2_leaf3': ['l2_u3', 'l2_b3_lan'],
    'irb_spine': ['irb_u1', 'irb_u2', 'irb_u3'],
    'irb_leaf1': ['irb_u1', 'irb_a1_lan'],
    'irb_leaf2': ['irb_u2', 'irb_a2_lan', 'irb_b2_lan'],
    'irb_border': ['irb_u3', 'irb_x'],
    'fix_spine': ['fix_u1', 'fix_u2'],
    'fix_leaf1': ['fix_u1', 'fix_h1_lan'],
    'fix_leaf2': ['fix_u2', 'fix_h2_lan'],
    'mc_r': ['mc_u1', 'mc_u2', 'mc_u3'],
    'mc_vtep1': ['mc_u1', 'mc_lan1'],
    'mc_vtep2': ['mc_u2', 'mc_lan2'],
    'mc_vtep3': ['mc_u3', 'mc_lan3'],
}
# Hosts (one interface, eth0): their LAN, their subnet and the address key of their default
# gateway (None: no default route)
HOSTS = {
    'st_h1': ('st_lan1', 'st_net', None), 'st_h2': ('st_lan2', 'st_net', None), 'st_h3': ('st_lan3', 'st_net', None),
    'l2_a1': ('l2_a1_lan', 'l2_net', None), 'l2_a2': ('l2_a2_lan', 'l2_net', None),
    'l2_b2': ('l2_b2_lan', 'l2_net', None), 'l2_b3': ('l2_b3_lan', 'l2_net', None),
    'irb_a1': ('irb_a1_lan', 'irb_net_a', 'irb_gw_a'), 'irb_a2': ('irb_a2_lan', 'irb_net_a', 'irb_gw_a'),
    'irb_b2': ('irb_b2_lan', 'irb_net_b', 'irb_gw_b'),
    'fix_h1': ('fix_h1_lan', 'fix_net', None), 'fix_h2': ('fix_h2_lan', 'fix_net', None),
    'mc_h1': ('mc_lan1', 'mc_net', None), 'mc_h2': ('mc_lan2', 'mc_net', None), 'mc_h3': ('mc_lan3', 'mc_net', None),
}
# the external router behind the border leaf (a plain machine: an address on irb_x, a dummy
# interface holding the external network, a default route to the border)
EXTERNAL = 'irb_ext'
# underlay links (/30): the first router gets .1, the second .2; irb_x is the link border - external
# router, inside the VRF of the border
LINKS = {
    'st_u1': ('st_r', 'st_vtep1'), 'st_u2': ('st_r', 'st_vtep2'), 'st_u3': ('st_r', 'st_vtep3'),
    'l2_u1': ('l2_spine', 'l2_leaf1'), 'l2_u2': ('l2_spine', 'l2_leaf2'), 'l2_u3': ('l2_spine', 'l2_leaf3'),
    'irb_u1': ('irb_spine', 'irb_leaf1'), 'irb_u2': ('irb_spine', 'irb_leaf2'), 'irb_u3': ('irb_spine', 'irb_border'),
    'irb_x': ('irb_border', EXTERNAL),
    'fix_u1': ('fix_spine', 'fix_leaf1'), 'fix_u2': ('fix_spine', 'fix_leaf2'),
    'mc_u1': ('mc_r', 'mc_vtep1'), 'mc_u2': ('mc_r', 'mc_vtep2'), 'mc_u3': ('mc_r', 'mc_vtep3'),
}
VRF_LINKS = ('irb_x',)
LOOPBACKS = {
    'st_r': 1, 'st_vtep1': 11, 'st_vtep2': 12, 'st_vtep3': 13,
    'l2_spine': 1, 'l2_leaf1': 11, 'l2_leaf2': 12, 'l2_leaf3': 13,
    'irb_spine': 1, 'irb_leaf1': 11, 'irb_leaf2': 12, 'irb_border': 20,
    'fix_spine': 1, 'fix_leaf1': 11, 'fix_leaf2': 12,
    'mc_r': 1, 'mc_vtep1': 11, 'mc_vtep2': 12, 'mc_vtep3': 13,
}
ST_VTEPS = ['st_vtep1', 'st_vtep2', 'st_vtep3']
MC_VTEPS = ['mc_vtep1', 'mc_vtep2', 'mc_vtep3']
SPINES = {'l2': 'l2_spine', 'irb': 'irb_spine', 'fix': 'fix_spine'}
LEAVES = {'l2': ['l2_leaf1', 'l2_leaf2', 'l2_leaf3'], 'irb': ['irb_leaf1', 'irb_leaf2', 'irb_border'],
          'fix': ['fix_leaf1', 'fix_leaf2']}
BGP_ROUTERS = [SPINES[s] for s in SPINES] + [x for s in LEAVES for x in LEAVES[s]]
MACHINES = list(ROUTER_IFACES) + list(HOSTS) + [EXTERNAL]

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _s, _g) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
_TOPOLOGY.setdefault('irb_x', {})[EXTERNAL] = 0

SITE_COLORS = {'st': 'lightblue', 'l2': 'palegreen', 'irb': 'khaki', 'fix': 'lightsalmon', 'mc': 'lightcyan'}
SITE_NUMBER = {'st': 1, 'l2': 2, 'irb': 3, 'fix': 4, 'mc': 5}
LOOPBACK_OCTET = 15
FABRIC_AS = 65000
VRF = 'TENANT'
VRF_TABLE = 100
MTU_SOLUTION = 1600          # the underlay MTU of the reference solution (>= 1500 + 50)
MC_TTL = 5
CONVERGE_WAIT = 12
OSPF_WAIT = 45               # an MTU change resets the OSPF adjacencies of the interface
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP{note}
# (zebra, mgmtd, staticd et watchfrr démarrent toujours)
bgpd={bgpd}
ospfd={ospfd}
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd={pimd}
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


def frr_daemons(router: str) -> str:
    on = {'bgpd': router in BGP_ROUTERS, 'ospfd': True, 'pimd': router == 'mc_r'}
    note = " : " + ", ".join(name for name, value in on.items() if value) + " activés"
    return FRR_DAEMONS.format(note=note, **{k: 'yes' if v else 'no' for k, v in on.items()})


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


def vx(vni: int) -> str:
    """The name of the VXLAN device of *vni* in the given configurations and the solutions."""
    return f"vxlan{vni}"


def br(vni: int) -> str:
    """The name of the bridge of *vni* in the given configurations and the solutions."""
    return f"br{vni}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    st_vni: int = 0           # the VNI of each part (random per instance)
    l2_vni_a: int = 0
    l2_vni_b: int = 0
    irb_vni_a: int = 0
    irb_vni_b: int = 0
    irb_l3vni: int = 0
    fix_vni: int = 0
    mc_vni: int = 0
    mc_group: str = ''        # the multicast group of the bonus
    gw_mac: str = ''          # the MAC address of the anycast gateway (part 3)

    @classmethod
    def generate(cls):
        data = cls()
        (data.st_vni, data.l2_vni_a, data.l2_vni_b, data.irb_vni_a, data.irb_vni_b, data.fix_vni,
         data.mc_vni) = random.sample(range(1000, 10000), 7)
        data.irb_l3vni = random.randint(10000, 16000)
        data.mc_group = f"239.{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        data.gw_mac = "02:00:5e:{:02x}:{:02x}:01".format(random.randint(0, 255), random.randint(0, 255))

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        (data.nets.st_net, data.nets.l2_net, data.nets.irb_net_a, data.nets.irb_net_b, data.nets.fix_net,
         data.nets.mc_net) = random_ipv4networks([24] * 6, from_network=IPv4Network('192.168.0.0/16'))
        data.nets.irb_ext_net = random_ipv4networks(24, from_network=IPv4Network('172.16.0.0/12'))[0]
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            for k, net in enumerate(n for n in LINKS if site_of(n) == site):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET, 24))
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for router, number in LOOPBACKS.items():
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + number, 32)))
        subnets = sorted({s for _n, s, _g in HOSTS.values()})
        for subnet in subnets:
            network = getattr(data.nets, subnet)
            hosts = [h for h, (_n, s, _g) in HOSTS.items() if s == subnet]
            for host, number in zip(hosts, random.sample(range(10, 250), len(hosts))):
                setattr(data.ips, host, IPv4Interface((int(network.network_address) + number, 24)))
        data.ips.irb_gw_a = IPv4Interface((int(data.nets.irb_net_a.network_address) + 1, 24))
        data.ips.irb_gw_b = IPv4Interface((int(data.nets.irb_net_b.network_address) + 1, 24))
        data.ips.irb_ext_addr = IPv4Interface((int(data.nets.irb_ext_net.network_address) + 1, 24))
        return data

    def leaf_vnis(self, leaf: str) -> List[tuple]:
        """[(vni, host interface)] of the layer-2 VNIs given on a leaf (parts 2, 3, 4)."""
        return {
            'l2_leaf1': [(self.l2_vni_a, 'eth1')],
            'l2_leaf2': [(self.l2_vni_a, 'eth1'), (self.l2_vni_b, 'eth2')],
            'l2_leaf3': [(self.l2_vni_b, 'eth1')],
            'irb_leaf1': [(self.irb_vni_a, 'eth1')],
            'irb_leaf2': [(self.irb_vni_a, 'eth1'), (self.irb_vni_b, 'eth2')],
            'fix_leaf1': [(self.fix_vni, 'eth1')],
            'fix_leaf2': [(self.fix_vni, 'eth1')],
        }.get(leaf, [])


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("routing-frr13")
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
            self.net_config[r] = [([getattr(d.ips, f"{r}_{net}")] if net in LINKS else [], []) for net in nets]
        for h, (_net, _subnet, gw) in HOSTS.items():
            routes = [(IPv4Network("0.0.0.0/0"), getattr(d.ips, gw).ip)] if gw else []
            self.net_config[h] = [([getattr(d.ips, h)], routes)]
        self.net_config[EXTERNAL] = [([getattr(d.ips, f"{EXTERNAL}_irb_x")],
                                      [(IPv4Network("0.0.0.0/0"), self.addr('irb_border', 'irb_x'))])]

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
        lines.append(f"{self.addr(EXTERNAL, 'irb_x')}\t{EXTERNAL}")
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

    def rt(self, vni: int) -> str:
        return f"{FABRIC_AS}:{vni}"

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Overlay et underlay"), tag="overlay")
            + tr("""
Un data centre moderne est une **fabrique IP** : des *leaves* (les commutateurs de bord, qui
reçoivent les serveurs) reliés à des *spines*, tous routés. Ce réseau routé, l'**underlay**, offre de
nombreux chemins de même coût et se passe de spanning tree. Les machines virtuelles et les
conteneurs veulent pourtant souvent partager un réseau de niveau 2 (une même adresse de sous-réseau,
la migration d'une machine d'un serveur à l'autre), et les clients d'un hébergeur veulent leurs
propres réseaux isolés.

On construit donc des réseaux de niveau 2 **virtuels** par-dessus l'underlay : c'est l'**overlay**.
Chaque trame Ethernet est encapsulée dans un paquet IP qui traverse l'underlay. Les équipements qui
encapsulent et décapsulent sont les **VTEP** (*VXLAN Tunnel End Point*) : en général les leaves, ou
l'hyperviseur lui-même.

- un segment de niveau 2 est désigné par un **VNI** (*VXLAN Network Identifier*) de 24 bits : 16
  millions de segments, au lieu des 4094 VLAN de 802.1Q ;
- l'underlay ne connaît que les adresses des VTEP (une interface de bouclage par VTEP, annoncée
  par l'IGP) ; il ignore tout des machines de l'overlay.
""")
            + info_subtitle(tr("L'encapsulation VXLAN"), tag="vxlan-header")
            + tr("""
VXLAN (RFC 7348) transporte la trame Ethernet complète dans un datagramme **UDP**, port de
destination **4789** :

```
| Ethernet ext. | IPv4 ext. | UDP     | VXLAN         | trame Ethernet d'origine     |
| 14 octets     | 20 octets | 8 oct.  | 8 octets      | (en-tête 14 + données)       |
                  VTEP -> VTEP  dport 4789  flags I + VNI
```

- l'en-tête VXLAN (8 octets) porte le drapeau *I* (VNI valide) et le VNI ;
- le **port source UDP** est calculé par un hachage de la trame intérieure : deux flux différents
  prennent des chemins différents dans un underlay à chemins multiples (ECMP) ;
- le surcoût est de **50 octets** (14 + 20 + 8 + 8) : une trame dont le paquet IP fait 1500 octets
  devient un paquet IP de 1550 octets dans l'underlay (section @@ref:mtu@@).

`tcpdump` et `tshark` décodent VXLAN sur le port 4789 : `tcpdump -nei eth0 udp port 4789` montre
l'en-tête extérieur, le VNI puis la trame intérieure.
""")
            + info_subtitle(tr("VXLAN sous Linux"), tag="vxlan-linux")
            + tr("""
Linux réalise un VTEP avec une interface de type `vxlan`, branchée sur un pont (`bridge`) avec les
interfaces des machines du segment :

```
ip link add vxlan100 type vxlan id 100 local 10.0.15.11 dstport 4789
ip link add br100 type bridge
ip link set vxlan100 master br100
ip link set eth1 master br100
ip link set vxlan100 up
ip link set br100 up
ip link set eth1 up
```

- `id` : le VNI ; `local` : l'adresse source des paquets VXLAN (l'interface de bouclage du VTEP) ;
  `dstport 4789` : le port de l'IANA (Linux utilise 8472 par défaut, un reste de l'histoire) ;
- `nolearning` désactive l'apprentissage des adresses MAC dans les paquets reçus (avec EVPN, c'est
  BGP qui les installe) ;
- le VNI d'une interface existante **ne peut pas être changé** : il faut la supprimer et la
  recréer ;
- sans `dev`, l'interface a une MTU de 1500 ; avec `dev eth0`, elle prend celle d'`eth0` moins 50.

| commande | ce qu'elle montre |
|----------|-------------------|
| `ip -d link show vxlan100` | les paramètres : `vxlan id 100 local … dstport 4789 nolearning ttl …` |
| `ip -br link show master br100` | les ports du pont |
| `bridge fdb show dev vxlan100` | la table de l'interface : liste d'inondation (`00:00:00:00:00:00 dst …`) et adresses MAC distantes (`dst` = le VTEP) |
| `bridge fdb show br br100` | toute la table du pont |
""")
            + info_subtitle(tr("Le trafic BUM et l'apprentissage"), tag="bum")
            + tr("""
Un pont doit inonder le trafic **BUM** (*Broadcast, Unknown unicast, Multicast*) : une requête ARP,
une trame vers une adresse MAC qu'il ne connaît pas encore. Un VTEP l'envoie à tous les VTEP qui
portent le même VNI, de deux manières :

- la **réplication en tête de réseau** (*head-end replication*, HER) : le VTEP envoie une copie en
  unicast à chaque VTEP de sa **liste d'inondation**. Sous Linux, cette liste est faite d'entrées
  `00:00:00:00:00:00` de la table de l'interface `vxlan` :

```
bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst 10.0.15.12
bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst 10.0.15.13
```

- un **groupe multicast** par VNI : le VTEP envoie une seule copie au groupe, l'underlay la
  distribue aux VTEP abonnés (section @@ref:mcast-underlay@@).

Dans les deux cas, le VTEP **apprend** l'adresse MAC source des trames qu'il décapsule et l'associe
au VTEP qui les a envoyées (`… dst 10.0.15.12 self`) : les trames suivantes vers cette adresse
partent en unicast vers ce seul VTEP. C'est le modèle *flood and learn* de VXLAN « nu » : il
fonctionne, mais la liste d'inondation est écrite à la main sur chaque VTEP, et toutes les adresses
s'apprennent en inondant. EVPN (section @@ref:evpn@@) remplace les deux par BGP.
""")
            + info_subtitle(tr("La MTU de l'underlay"), tag="mtu")
            + tr("""
Une trame dont le paquet IP fait 1500 octets donne un paquet VXLAN de 1550 octets. Sur des liens à
1500 octets :

- le VTEP refuse d'envoyer un paquet trop grand avec le bit DF : il répond à l'hôte par un ICMP
  *fragmentation needed* (comme un routeur, bien qu'il soit un pont pour l'hôte), et l'hôte garde une
  **PMTU de 1450** pendant une dizaine de minutes (`ip route get <dest>` : `cache … mtu 1450`) ;
- un routeur de l'underlay dont le lien suivant est trop petit **fragmente** le paquet VXLAN (son bit
  DF n'est pas mis) : les fragments sont réassemblés par le VTEP d'arrivée, au prix de performances
  dégradées.

Deux remèdes : **augmenter la MTU de l'underlay** à au moins 1550 sur tous ses liens (les data
centres utilisent 9000, les *jumbo frames*), ou réduire la MTU des hôtes à 1450. Le premier ne
change rien pour les hôtes.

```
ip link set eth0 mtu 1600                  # sur les deux extrémités de chaque lien
ping -M do -s 1472 <dest>                  # un paquet de 1500 octets avec DF
ip route flush cache                       # oublier les PMTU apprises (sur l'hôte)
nstat -az IpFragCreates                    # les fragments créés par un routeur
```

OSPF compare la MTU des deux extrémités d'un lien : tant qu'elles diffèrent, l'adjacence reste
bloquée (état *ExStart*), et changer la MTU d'une interface relance ses adjacences.
""")
            + info_subtitle(tr("EVPN, un plan de contrôle pour VXLAN"), tag="evpn")
            + tr("""
**EVPN** (*Ethernet VPN*, RFC 7432, et RFC 8365 pour VXLAN) annonce par **MP-BGP** ce que VXLAN
devait apprendre en inondant. Les VTEP sont des voisins BGP dans la famille **L2VPN EVPN** (AFI 25 /
SAFI 70) ; chaque route porte un RD, des RT (section @@ref:evpn-rd-rt@@) et la communauté étendue
d'encapsulation VXLAN (`ET:8`). Les types de route :

| type | nom | rôle |
|------|-----|------|
| 1 | *Ethernet Auto-Discovery* | multi-attachement d'un serveur à deux leaves (ESI) |
| 2 | *MAC/IP Advertisement* | une adresse MAC apprise sur un port local, avec son adresse IP si le VTEP la connaît |
| 3 | *Inclusive Multicast Ethernet Tag* | « je porte ce VNI » : construit la liste d'inondation des autres VTEP |
| 4 | *Ethernet Segment* | élection du *designated forwarder* d'un segment multi-attaché |
| 5 | *IP Prefix* | un préfixe IP, pour router entre VNI et vers l'extérieur (section @@ref:type5@@) |

Ce que gagne la fabrique :

- la liste d'inondation de chaque VNI se construit seule (routes de type 3) : ajouter un VTEP ne
  demande de configurer que lui ;
- les adresses MAC distantes sont installées dès leur apprentissage par le leaf local (routes de type
  2), sans inondation : `bridge fdb` les marque `extern_learn` ;
- un leaf qui connaît aussi l'adresse IP d'un hôte peut répondre lui-même aux requêtes ARP (section
  @@ref:arp-suppression@@) et router (section @@ref:irb@@).
""")
            + info_subtitle(tr("RD et RT en EVPN"), tag="evpn-rd-rt")
            + tr("""
Comme pour les VPN BGP/MPLS, chaque VNI a un **RD** (il rend uniques les routes de deux VNI qui
annoncent la même adresse) et des **RT** d'import et d'export (elles décident quel VNI importe une
route). FRR les calcule tout seul :

- **RD automatique** : `adresse-du-routeur:numéro`, où le numéro est un index interne attribué à
  chaque VNI (ni le VNI ni une valeur prévisible) ;
- **RT automatique** : `AS:VNI` ; deux leaves du même AS qui portent le même VNI ont donc la même RT,
  sans rien configurer. Entre deux AS (eBGP), les RT automatiques diffèrent (`65101:100` et
  `65102:100`), et FRR importe tout de même la route : il ne compare que la partie VNI d'une RT
  automatique.

On peut les fixer à la main, VNI par VNI :

```
router bgp 65000
 address-family l2vpn evpn
  vni 100
   rd 10.0.15.11:100
   route-target import 65000:100
   route-target export 65000:100
  exit-vni
```
""")
            + info_subtitle(tr("EVPN avec FRR"), tag="evpn-frr")
            + tr("""
Les interfaces `vxlan` (avec `nolearning`) et leurs ponts existent déjà dans le noyau ; FRR les
découvre. Sur un leaf :

```
configure terminal
router bgp 65000
 bgp router-id 10.0.15.11
 no bgp default ipv4-unicast
 neighbor 10.0.15.1 remote-as 65000
 neighbor 10.0.15.1 update-source lo
 address-family l2vpn evpn
  neighbor 10.0.15.1 activate
  advertise-all-vni
 exit-address-family
exit
end
write
```

- `advertise-all-vni` : annoncer tous les VNI du noyau, et installer dans le noyau ce qu'annoncent
  les autres ; sans lui, BGP échange la famille EVPN mais ignore les VNI ;
- la session part de l'interface de bouclage, que l'IGP de l'underlay annonce.

Les leaves forment des sessions **iBGP** avec les spines. Un routeur iBGP ne transmet pas à un voisin
iBGP ce qu'il a appris d'un autre voisin iBGP : sans maillage complet entre les leaves, le spine doit
être **route reflector**, et chaque leaf son client :

```
router bgp 65000
 bgp router-id 10.0.15.1
 no bgp default ipv4-unicast
 neighbor 10.0.15.11 remote-as 65000
 neighbor 10.0.15.11 update-source lo
 address-family l2vpn evpn
  neighbor 10.0.15.11 activate
  neighbor 10.0.15.11 route-reflector-client
 exit-address-family
exit
```

Le spine ne porte aucun VNI et n'est pas un VTEP : il ne fait que refléter les routes ; les paquets
VXLAN le traversent comme n'importe quel paquet IP.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show bgp l2vpn evpn summary` | les sessions EVPN |
| `show bgp l2vpn evpn route` | la table EVPN, rangée par RD (`[2]:…:[MAC]`, `[3]:…:[VTEP]`, `[5]:…:[préfixe]`) |
| `show bgp l2vpn evpn route type macip` / `multicast` / `prefix` | les routes d'un type |
| `show bgp l2vpn evpn vni` | les VNI de BGP : RD, RT d'import et d'export |
| `show evpn vni` / `show evpn vni detail` | les VNI de zebra et leurs VTEP distants |
| `show evpn mac vni all` | les adresses MAC locales et distantes |
""")
            + info_subtitle(tr("La suppression ARP"), tag="arp-suppression")
            + tr("""
Une route de type 2 peut porter, avec l'adresse MAC, l'**adresse IP** de l'hôte : le leaf l'apprend
dans sa table ARP, quand il a une adresse dans le sous-réseau (une SVI, section @@ref:irb@@). Les
autres leaves connaissent alors le couple IP / MAC de chaque hôte distant, et peuvent **répondre
eux-mêmes** aux requêtes ARP de leurs hôtes au lieu de les inonder dans toute la fabrique :

```
ip link set vxlan100 type bridge_slave neigh_suppress on
bridge -d link show dev vxlan100              # … neigh_suppress on …
show evpn arp-cache vni all                   # (vtysh) les couples IP / MAC connus
```

Le couple IP / MAC d'un hôte suit l'état de la table ARP du leaf : quand l'entrée vieillit (`STALE`),
FRR la marque *inactive* et retire la route MAC/IP correspondante.
""")
            + info_subtitle(tr("Router entre VNI : l'IRB"), tag="irb")
            + tr("""
Pour router entre deux VNI (deux sous-réseaux), le leaf donne une adresse au pont du VNI : c'est la
**SVI** (*Switched Virtual Interface*), passerelle des hôtes du segment. On parle d'**IRB**
(*Integrated Routing and Bridging*). Deux modèles :

- **IRB asymétrique** : le leaf d'entrée route vers le sous-réseau de destination, puis **pont** la
  trame dans le VNI de destination. Chaque leaf doit porter **tous** les VNI de tous les
  sous-réseaux, et apprendre toutes les adresses ;
- **IRB symétrique** : le leaf d'entrée route le paquet vers le **leaf de sortie**, dans un VNI de
  routage propre à la VRF, le **L3VNI** ; le leaf de sortie route une seconde fois vers l'hôte. Chaque
  leaf ne porte que les VNI de ses hôtes, plus le L3VNI.

En IRB symétrique, les sous-réseaux d'un client forment une **VRF** ; le L3VNI est le VNI de cette
VRF entre les VTEP. Chaque VTEP a une **adresse MAC de routeur** (*router MAC*), annoncée dans la
communauté étendue `Rmac` de ses routes ; la trame intérieure d'un paquet routé va de la *router
MAC* du leaf d'entrée à celle du leaf de sortie. Une route de type 2 MAC/IP porte alors **deux VNI**
(celui du segment, puis le L3VNI) et deux RT.
""")
            + info_subtitle(tr("La passerelle anycast distribuée"), tag="anycast-gw")
            + tr("""
Un hôte peut être branché sur n'importe quel leaf, et migrer d'un leaf à l'autre. Pour qu'il garde
sa passerelle, **tous les leaves** qui portent un VNI donnent à sa SVI la **même adresse IP et la
même adresse MAC** : chaque hôte trouve sa passerelle sur son propre leaf, le trafic routé ne
traverse jamais la fabrique pour atteindre une passerelle lointaine, et une migration ne change rien
pour l'hôte.

```
ip link set br100 address 02:00:5e:00:00:01      # la même sur tous les leaves
ip addr add 192.168.10.1/24 dev br100            # la même sur tous les leaves
```

Ces adresses ne sont jamais annoncées comme des hôtes : chaque leaf les considère comme locales.
""")
            + info_subtitle(tr("IRB symétrique sous Linux et FRR"), tag="irb-linux")
            + tr("""
Le noyau d'abord, sur chaque leaf :

```
ip link add TENANT type vrf table 100            # la VRF
ip link set TENANT up
ip link add vxlan4000 type vxlan id 4000 local 10.0.15.11 dstport 4789 nolearning
ip link add br4000 type bridge                   # le L3VNI : interface vxlan + pont, dans la VRF
ip link set br4000 master TENANT
ip link set vxlan4000 master br4000
ip link set vxlan4000 up
ip link set br4000 up
ip link set br100 master TENANT                  # la SVI du VNI 100 dans la VRF
```

Puis FRR, qui associe le L3VNI à la VRF :

```
configure terminal
vrf TENANT
 vni 4000
exit-vrf
end
write
```

Le pont du L3VNI n'a pas d'adresse. Les routes des hôtes distants apparaissent dans la table de la
VRF sous la forme `192.168.20.15 via 10.0.15.12 dev br4000 onlink` : le prochain saut est le VTEP de
sortie, joint par une entrée de voisinage vers sa *router MAC*.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show evpn vni` | le L3VNI (type `L3`) et sa VRF |
| `show vrf vni` | la VRF, son L3VNI et sa *router MAC* |
| `show evpn rmac vni all` | les *router MAC* des VTEP distants |
| `ip route show vrf TENANT`, `ip neigh show vrf TENANT` | ce que le noyau en a fait |
""")
            + info_subtitle(tr("Les routes de type 5"), tag="type5")
            + tr("""
Les routes de type 2 ne décrivent que les hôtes que les leaves ont **déjà vus**. Deux cas ont besoin
de préfixes :

- un **hôte silencieux** : tant qu'il n'a rien émis, aucun leaf ne connaît son adresse et aucune
  route /32 ne mène à lui ; si le leaf d'entrée ne porte pas son VNI, il ne peut même pas le chercher
  par ARP. Chaque leaf annonce donc aussi ses **sous-réseaux** ; le leaf qui les porte fera la
  résolution ARP lui-même ;
- les **réseaux extérieurs** à la fabrique, connus d'un *border leaf* par une route statique ou un
  protocole de routage.

Une route de **type 5** annonce un préfixe d'une VRF, avec le L3VNI et la *router MAC* du VTEP qui
l'annonce. Avec FRR, dans l'instance BGP de la VRF :

```
configure terminal
router bgp 65000 vrf TENANT
 bgp router-id 10.0.15.11
 address-family ipv4 unicast
  redistribute connected               # ou redistribute static, des sessions...
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
exit
end
write
```

L'instance BGP de la VRF n'est pas nécessaire à l'IRB symétrique (les routes de type 2 suffisent) ;
elle l'est pour annoncer des routes de type 5.
""")
            + info_subtitle(tr("Un underlay multicast"), tag="mcast-underlay")
            + tr("""
Au lieu d'une liste d'inondation, chaque VNI peut utiliser un **groupe multicast** : le VTEP envoie
le trafic BUM au groupe, et rejoint ce groupe (IGMP) pour recevoir celui des autres. L'underlay doit
router le multicast, en général avec **PIM-SM** (RP statique, arbre partagé puis arbre des sources) :

```
ip link add vxlan500 type vxlan id 500 group 239.1.1.5 dev eth0 ttl 5 dstport 4789
```

- `group` exige `dev` : l'interface par laquelle le VTEP rejoint le groupe et l'envoie ;
- le **TTL par défaut d'un paquet VXLAN multicast est 1** : il ne franchirait aucun routeur ; `ttl`
  le fixe ;
- un routeur PIM ne prend en charge (enregistrement auprès du RP) que les sources **directement
  connectées** : sans `local`, le VTEP utilise l'adresse de `dev`, sur le lien du routeur. Un VTEP
  qui envoie depuis son interface de bouclage doit faire tourner PIM lui-même.

Les adresses MAC distantes s'apprennent toujours dans les paquets reçus (*flood and learn*) : le
multicast ne remplace que la liste d'inondation. EVPN peut aussi s'en servir pour son trafic BUM
(au lieu de la réplication en tête de réseau).

Sur le routeur (FRR) :

```
configure terminal
ip pim rp 10.0.15.1 239.0.0.0/8
interface lo
 ip pim
exit
interface eth0
 ip pim
 ip igmp
exit
end
write
```

`show ip igmp groups` montre les VTEP abonnés, `show ip mroute` l'entrée `(*,G)` puis une entrée
`(S,G)` par VTEP qui émet.
""")
            + info_subtitle(tr("Dépannage d'une fabrique EVPN"), tag="evpn-debug")
            + tr("""
Le chemin d'une adresse MAC d'un leaf à l'autre, étape par étape :

1. l'interface `vxlan` a-t-elle le bon VNI (`ip -d link show`), est-elle dans le pont du segment,
   avec l'interface de l'hôte (`ip -br link show master brX`) ?
2. la session EVPN du leaf est-elle établie **et activée** dans la famille L2VPN EVPN, le leaf
   annonce-t-il ses VNI (`advertise-all-vni`, `show bgp l2vpn evpn vni`) ?
3. le spine reflète-t-il les routes (`route-reflector-client` pour chaque leaf) ?
4. l'autre leaf a-t-il reçu la route de type 3 du VNI, et le VTEP est-il dans sa liste d'inondation
   (`show evpn vni detail`, `bridge fdb show dev vxlanX`) ?
5. l'adresse MAC de l'hôte est-elle apprise localement, puis annoncée en type 2 (`show evpn mac vni
   all`) ?

| symptôme | cause probable |
|----------|----------------|
| `show bgp l2vpn evpn summary` vide | voisin non activé dans la famille EVPN |
| la session est établie, aucune route de VNI | pas d'`advertise-all-vni` |
| un leaf reçoit les routes de l'autre, pas l'inverse | un leaf n'est pas client du route reflector |
| les routes arrivent mais ne sont pas importées | VNI ou RT différents d'un leaf à l'autre |
| les VTEP se connaissent, l'hôte local n'est pas appris | interface `vxlan` ou de l'hôte hors du pont |
| les petits paquets passent, pas les gros | MTU de l'underlay trop petite |
""")
        )

    # -- FRR configuration ---------------------------------------------------------

    def _ospf_lines(self, router: str) -> List[str]:
        lines = ["router ospf", f" ospf router-id {self.lo(router)}", "exit", "!"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            if net in LINKS and net not in VRF_LINKS:
                lines += [f"interface eth{i}", " ip ospf area 0", " ip ospf network point-to-point", "exit", "!"]
        return lines + ["interface lo", " ip ospf area 0", "exit", "!"]

    def evpn_leaf_lines(self, leaf: str, advertise: bool = True) -> List[str]:
        """The iBGP EVPN session of a leaf with the spine of its site."""
        spine = self.lo(SPINES[site_of(leaf)])
        lines = [f"router bgp {FABRIC_AS}", f" bgp router-id {self.lo(leaf)}", " no bgp default ipv4-unicast",
                 f" neighbor {spine} remote-as {FABRIC_AS}", f" neighbor {spine} update-source lo", " !",
                 " address-family l2vpn evpn", f"  neighbor {spine} activate"]
        if advertise:
            lines.append("  advertise-all-vni")
        return lines + [" exit-address-family", "exit", "!"]

    def evpn_spine_lines(self, site: str, rr_clients: List[str] = None) -> List[str]:
        """The spine of a site: iBGP EVPN with every leaf, route reflector for *rr_clients* (all
        the leaves by default)."""
        spine = SPINES[site]
        leaves = LEAVES[site]
        clients = leaves if rr_clients is None else rr_clients
        lines = [f"router bgp {FABRIC_AS}", f" bgp router-id {self.lo(spine)}", " no bgp default ipv4-unicast"]
        for leaf in leaves:
            lines += [f" neighbor {self.lo(leaf)} remote-as {FABRIC_AS}", f" neighbor {self.lo(leaf)} update-source lo"]
        lines += [" !", " address-family l2vpn evpn"]
        for leaf in leaves:
            lines.append(f"  neighbor {self.lo(leaf)} activate")
            if leaf in clients:
                lines.append(f"  neighbor {self.lo(leaf)} route-reflector-client")
        return lines + [" exit-address-family", "exit", "!"]

    def vrf_vni_lines(self, static: bool = False) -> List[str]:
        """``vrf TENANT`` / `` vni L3VNI`` (+ the static route of the border to the external network)."""
        lines = [f"vrf {VRF}", f" vni {self.data.irb_l3vni}"]
        if static:
            lines.append(f" ip route {self.net('irb_ext_net')} {self.addr(EXTERNAL, 'irb_x')}")
        return lines + ["exit-vrf", "!"]

    def vrf_bgp_lines(self, router: str, redistribute: str) -> List[str]:
        """The BGP instance of the VRF: type-5 routes of what *redistribute* puts in its table."""
        return [f"router bgp {FABRIC_AS} vrf {VRF}", f" bgp router-id {self.lo(router)}", " !",
                " address-family ipv4 unicast", f"  redistribute {redistribute}", " exit-address-family", " !",
                " address-family l2vpn evpn", "  advertise ipv4 unicast", " exit-address-family", "exit", "!"]

    def _frr_conf(self, router: str) -> str:
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", "log file /var/log/frr/frr.log", "!"]
        if router == 'irb_border':
            lines += self.vrf_vni_lines(static=True)
        lines += self._ospf_lines(router)
        if router == 'irb_spine':
            lines += self.evpn_spine_lines('irb')
        elif router in LEAVES['irb']:
            lines += self.evpn_leaf_lines(router)
        elif router == 'fix_spine':
            # fault 2: fix_leaf1 is not a route reflector client
            lines += self.evpn_spine_lines('fix', rr_clients=['fix_leaf2'])
        elif router in LEAVES['fix']:
            # fault 3: no advertise-all-vni on fix_leaf2
            lines += self.evpn_leaf_lines(router, advertise=(router != 'fix_leaf2'))
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    @staticmethod
    def _flat(lines: List[str]) -> List[str]:
        """vtysh commands from configuration lines (indentation, ``!`` and blank lines dropped)."""
        return [x.strip() for x in lines if x.strip() and x.strip() != '!']

    def wait_route_cmd(self, dest, seconds: int = 60) -> str:
        """Wait until the kernel has a route to *dest* through a gateway (the IGP has converged): an
        iBGP session configured before retries only after its connect timer."""
        return (f"i=0; while ! ip route get {dest} 2>/dev/null | grep -q ' via ' && [ $i -lt {seconds} ]; "
                f"do sleep 1; i=$((i+1)); done")

    # -- reference solutions -------------------------------------------------------

    def solution_static(self) -> Dict[str, Dict[str, List[str]]]:
        d = self.data
        vni = d.st_vni
        result = {}
        for v in ST_VTEPS:
            others = [self.lo(o) for o in ST_VTEPS if o != v]
            sh = (vxlan_cmds(vx(vni), vni, local=self.lo(v)) + bridge_cmds(br(vni), ['eth1', vx(vni)])
                  + flood_cmds(vx(vni), others) + [f"ip link set eth0 mtu {MTU_SOLUTION}"])
            result[v] = {'sh': sh, 'vtysh': []}
        result['st_r'] = {'sh': [f"ip link set eth{i} mtu {MTU_SOLUTION}" for i in range(3)], 'vtysh': []}
        return result

    def solution_l2(self) -> Dict[str, List[str]]:
        result = {'l2_spine': self._flat(self.evpn_spine_lines('l2'))}
        for leaf in LEAVES['l2']:
            result[leaf] = self._flat(self.evpn_leaf_lines(leaf))
        return result

    def solution_irb(self) -> Dict[str, Dict[str, List[str]]]:
        d = self.data
        result = {}
        gateways = {d.irb_vni_a: d.ips.irb_gw_a, d.irb_vni_b: d.ips.irb_gw_b}
        for leaf in ('irb_leaf1', 'irb_leaf2'):
            sh = l3vni_cmds(VRF, VRF_TABLE, d.irb_l3vni, self.lo(leaf), vxlan=vx(d.irb_l3vni), bridge=br(d.irb_l3vni))
            for vni, _ifname in d.leaf_vnis(leaf):
                sh += [f"ip link set {br(vni)} address {d.gw_mac}", f"ip addr add {gateways[vni]} dev {br(vni)}",
                       f"ip link set {br(vni)} master {VRF}",
                       f"ip link set {vx(vni)} type bridge_slave neigh_suppress on"]
            vtysh = self._flat(self.vrf_vni_lines()) + self._flat(self.vrf_bgp_lines(leaf, 'connected'))
            result[leaf] = {'sh': sh, 'vtysh': vtysh}
        result['irb_border'] = {'sh': [], 'vtysh': self._flat(self.vrf_bgp_lines('irb_border', 'static'))}
        return result

    def solution_fix(self) -> Dict[str, Dict[str, List[str]]]:
        v = self.data.fix_vni
        return {
            'fix_spine': {'sh': [], 'vtysh': [f"router bgp {FABRIC_AS}", "address-family l2vpn evpn",
                                              f"neighbor {self.lo('fix_leaf1')} route-reflector-client",
                                              "exit-address-family", "exit"]},
            'fix_leaf1': {'sh': [f"ip link set {vx(v)} master {br(v)}"], 'vtysh': []},
            'fix_leaf2': {'sh': [f"ip link del {vx(v)}"] + vxlan_cmds(vx(v), v, local=self.lo('fix_leaf2'), learning=False)
                          + [f"ip link set {vx(v)} master {br(v)}"],
                          'vtysh': [f"router bgp {FABRIC_AS}", "address-family l2vpn evpn", "advertise-all-vni",
                                    "exit-address-family", "exit"]},
        }

    def solution_mcast(self) -> Dict[str, Dict[str, List[str]]]:
        d = self.data
        v = d.mc_vni
        result = {m: {'sh': vxlan_cmds(vx(v), v, group=d.mc_group, dev='eth0', ttl=MC_TTL)
                      + [f"ip link set {vx(v)} master {br(v)}"], 'vtysh': []} for m in MC_VTEPS}
        vtysh = [f"ip pim rp {self.lo('mc_r')} 239.0.0.0/8", "interface lo", "ip pim", "exit"]
        for i in range(3):
            vtysh += [f"interface eth{i}", "ip pim", "ip igmp", "exit"]
        result['mc_r'] = {'sh': [], 'vtysh': vtysh}
        return result

    # -- applying the solutions ----------------------------------------------------

    def _apply_mixed(self, solution: Dict[str, Dict[str, List[str]]], step: int = 1):
        for r, parts in solution.items():
            for c in parts['sh']:
                self.cmd(r, c, step=step)
            if parts['vtysh']:
                self._vtysh(r, *parts['vtysh'], step=step)

    def _apply_l2(self, step: int = 1):
        for r, cmds in self.solution_l2().items():
            target = SPINES['l2'] if r != 'l2_spine' else 'l2_leaf1'
            self.cmd(r, self.wait_route_cmd(self.lo(target)), step=step, timeout=90)
            self._vtysh(r, *cmds, step=step)

    def _apply_static(self, step: int = 1):
        self._apply_mixed(self.solution_static(), step=step)

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
        # the layer-2 VNIs given on the leaves of parts 2 and 3
        for leaf in LEAVES['l2'] + ['irb_leaf1', 'irb_leaf2']:
            for vni, ifname in d.leaf_vnis(leaf):
                for c in vxlan_cmds(vx(vni), vni, local=self.lo(leaf), learning=False) + bridge_cmds(br(vni), [ifname, vx(vni)]):
                    self.cmd(leaf, c)
        # the border leaf: VRF, L3VNI and the link to the external router in the VRF
        for c in l3vni_cmds(VRF, VRF_TABLE, d.irb_l3vni, self.lo('irb_border'), vxlan=vx(d.irb_l3vni),
                            bridge=br(d.irb_l3vni)) + [f"ip link set eth1 master {VRF}"]:
            self.cmd('irb_border', c)
        for c in ("ip link add ext0 type dummy", f"ip addr add {d.ips.irb_ext_addr} dev ext0", "ip link set ext0 up"):
            self.cmd(EXTERNAL, c)
        # part 4: fix_leaf1's VXLAN device outside the bridge (fault 4), fix_leaf2's with the wrong
        # VNI under the right name (fault 1)
        v = d.fix_vni
        for c in vxlan_cmds(vx(v), v, local=self.lo('fix_leaf1'), learning=False) + bridge_cmds(br(v), ['eth1']):
            self.cmd('fix_leaf1', c)
        for c in vxlan_cmds(vx(v), v + 1, local=self.lo('fix_leaf2'), learning=False) + bridge_cmds(br(v), ['eth1', vx(v)]):
            self.cmd('fix_leaf2', c)
        # bonus: the bridges of the VTEPs, without VXLAN device
        for m in MC_VTEPS:
            for c in bridge_cmds(br(d.mc_vni), ['eth1']):
                self.cmd(m, c)
        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (VXLAN statique)"))
    def solve_static(self):
        self._apply_static()
        self.cmd('st_r', f"sleep {OSPF_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (EVPN)"))
    def solve_l2(self):
        self._apply_l2()
        self.cmd('l2_spine', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (IRB symétrique, type 5)"))
    def solve_irb(self):
        self._apply_mixed(self.solution_irb())
        self.cmd('irb_spine', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (dépannage)"))
    def solve_fix(self):
        self._apply_mixed(self.solution_fix())
        self.cmd('fix_spine', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (underlay multicast, bonus)"))
    def solve_mcast(self):
        self._apply_mixed(self.solution_mcast())
        self.cmd('mc_r', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        self._apply_static()
        self._apply_l2()
        self._apply_mixed(self.solution_irb())
        self._apply_mixed(self.solution_fix())
        self._apply_mixed(self.solution_mcast())
        self.cmd('st_r', f"sleep {OSPF_WAIT}", step=2)


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


def _port_ok(links: List[dict], devices: Dict[str, dict], dev: str, host_if: str) -> bool:
    """*dev* exists, is up and sits in the same bridge as the host interface *host_if*."""
    if dev is None or dev not in devices:
        return False
    master = devices[dev]['master']
    return bool(master) and devices[dev]['up'] and link_master(links, host_if) == master


def _route_via(routes: Dict[str, dict], prefix, gateway, dev: str = None) -> bool:
    entry = routes.get(str(prefix)) or {}
    return any(str(gw) == str(gateway) and (dev is None or ifname == dev) for gw, ifname in entry.get('nexthops', []))


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest, count: int = 3, step: int = 1) -> bool:
        _out, code = self.test(src, f"ping -c {count} -i 0.2 -w 3 {dest}", step=step, allow_error=True)
        return code == 0

    def _mac(self, host: str) -> str:
        out, code = self.test(host, "cat /sys/class/net/eth0/address", allow_error=True)
        return normalize_mac(out.strip()) if code == 0 else ''

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net, rt = ns.lo, ns.addr, ns.net, ns.rt
        ip = ns.host_ip

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- part 1: what the elements read ----------------------------
        st_links = {v: get_ip_links(self, v) for v in ST_VTEPS}
        st_fdb = {v: get_fdb_all(self, v) for v in ST_VTEPS}
        st_mac = {h: self._mac(h) for h in ('st_h2', 'st_h3')}
        st_pings = [self._ping('st_h1', ip('st_h2')), self._ping('st_h1', ip('st_h3')),
                    self._ping('st_h2', ip('st_h3'))]
        st_fdb2 = get_fdb_all(self, 'st_vtep1', step=2)
        st_frag0 = get_frag_creates(self, 'st_r', step=1)
        st_df = [self.test(h, df_ping_cmd(ip(dest)), step=2, allow_error=True)[1] == 0
                 for h, dest in (('st_h1', 'st_h2'), ('st_h1', 'st_h3'))]
        st_frag1 = get_frag_creates(self, 'st_r', step=3)

        # ---------------- part 2 ------------------------------------------------------
        l2_sum = get_bgp_evpn_summary(self, 'l2_spine')
        l2_routes = {leaf: get_bgp_evpn_routes(self, leaf) for leaf in LEAVES['l2']}
        l2_vnis = {leaf: get_evpn_vnis(self, leaf) for leaf in LEAVES['l2']}
        l2_mac = {h: self._mac(h) for h in ('l2_a1', 'l2_a2', 'l2_b2', 'l2_b3')}
        l2_ping_a = self._ping('l2_a1', ip('l2_a2'))
        l2_ping_b = self._ping('l2_b2', ip('l2_b3'))
        l2_cross = self._ping('l2_a1', ip('l2_b2'), count=2)
        l2_links = {leaf: get_ip_links(self, leaf, step=2) for leaf in LEAVES['l2']}
        l2_fdb = {leaf: get_fdb_all(self, leaf, step=2) for leaf in LEAVES['l2']}

        # ---------------- part 3 ------------------------------------------------------
        irb_leaves = ('irb_leaf1', 'irb_leaf2')
        irb_vnis = {leaf: get_evpn_vnis(self, leaf) for leaf in irb_leaves}
        irb_links = {leaf: get_ip_links(self, leaf) for leaf in irb_leaves}
        irb_addrs = {leaf: get_ip_addresses_json(self, leaf) for leaf in irb_leaves}
        irb_ports = {leaf: get_bridge_port_flags(self, leaf) for leaf in irb_leaves}
        # the hosts refresh the ARP entries of their leaf (a MAC+IP route lives while the entry is fresh)
        for h, gw in (('irb_a1', d.ips.irb_gw_a), ('irb_a2', d.ips.irb_gw_a), ('irb_b2', d.ips.irb_gw_b)):
            self.test(h, f"ping -c 2 -i 0.2 -w 2 {gw.ip}", allow_error=True)
        irb_routes = {r: get_bgp_evpn_routes(self, r, step=2) for r in ('irb_leaf1', 'irb_border')}
        irb_k = {leaf: get_kernel_routes(self, leaf, step=2, allow_error=True, vrf=VRF) for leaf in irb_leaves}
        irb_ping_b = self.test('irb_a1', f"sleep 2; ping -c 3 -i 0.2 -w 4 {ip('irb_b2')}", step=2,
                               allow_error=True)[1] == 0
        irb_ping_ext = self.test('irb_a1', f"ping -c 3 -i 0.2 -w 4 {d.ips.irb_ext_addr.ip}", step=2,
                                 allow_error=True)[1] == 0

        # ---------------- part 4 ------------------------------------------------------
        fix_links = {leaf: get_ip_links(self, leaf) for leaf in LEAVES['fix']}
        fix_cfg = {r: get_frr_running_config(self, r, allow_error=True) for r in ('fix_spine', 'fix_leaf2')}
        fix_mac = self._mac('fix_h2')
        fix_ping = self._ping('fix_h1', ip('fix_h2'))
        fix_fdb = get_fdb_all(self, 'fix_leaf1', step=2)

        # ---------------- part 5 ------------------------------------------------------
        mc_links = {m: get_ip_links(self, m) for m in MC_VTEPS}
        mc_pings = [self._ping('mc_h1', ip('mc_h2')), self._ping('mc_h1', ip('mc_h3'))]
        mc_routes = get_mroutes(self, 'mc_r', step=2, allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('st', "1 — VXLAN statique", "`st_r`, les VTEP `st_vtep1` à `st_vtep3`, les hôtes `st_h1` à `st_h3`"),
                 ('l2', "2 — EVPN", "`l2_spine`, `l2_leaf1` à `l2_leaf3`, les hôtes `l2_a1`, `l2_a2` (VNI A), "
                                    "`l2_b2`, `l2_b3` (VNI B)"),
                 ('irb', "3 — IRB symétrique, type 5", "`irb_spine`, `irb_leaf1`, `irb_leaf2`, `irb_border`, le "
                                                       "routeur extérieur `irb_ext`, les hôtes `irb_a1`, `irb_a2` "
                                                       "(sous-réseau A), `irb_b2` (sous-réseau B)"),
                 ('fix', "4 — dépannage", "`fix_spine`, `fix_leaf1`, `fix_leaf2`, les hôtes `fix_h1`, `fix_h2`"),
                 ('mc', "5 — underlay multicast (bonus)", "`mc_r`, les VTEP `mc_vtep1` à `mc_vtep3`, les hôtes "
                                                          "`mc_h1` à `mc_h3`")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in LINKS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                if n in LINKS:
                    members[n].append(f"`{r}` eth{i} (`{addr(r, n)}`)")
        members['irb_x'].append(f"`{EXTERNAL}` eth0 (`{addr(EXTERNAL, 'irb_x')}`)")
        rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in LINKS]
        rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                 + ", ".join(f"`{r}` `{lo(r)}/32`" for r in LOOPBACKS if site_of(r) == site) + " |"
                 for site in SITE_NUMBER]
        subnet_names = {'st_net': "site 1", 'l2_net': "site 2 (VNI A et VNI B)", 'irb_net_a': "site 3, sous-réseau A",
                        'irb_net_b': "site 3, sous-réseau B", 'fix_net': "site 4", 'mc_net': "site 5"}
        for subnet, label in subnet_names.items():
            hosts = ", ".join(f"`{h}` (`{ip(h)}`)" for h, (_n, s, _g) in HOSTS.items() if s == subnet)
            rows.append(f"| {label} | `{net(subnet)}` | {hosts} |")
        rows.append(f"| réseau extérieur | `{net('irb_ext_net')}` | `{EXTERNAL}` ext0 (`{d.ips.irb_ext_addr.ip}`) |")
        addressing = "\n".join(rows)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente VXLAN, EVPN et le routage entre VNI, et leur mise en
œuvre avec Linux et FRR. Le TP suppose connus OSPF et BGP (iBGP entre interfaces de bouclage).

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie ; chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs, les spines, les leaves et les VTEP font tourner **FRRouting** (FRR) : configurez-les
  avec `vtysh`. Dans chaque site, l'**underlay fonctionne** : OSPF annonce les liens et les
  interfaces de bouclage (les adresses des VTEP).
- Sur les sites 2 et 3, les interfaces `vxlan` et les ponts des VNI de niveau 2 existent déjà sur les
  leaves (noms `vxlan<VNI>` et `br<VNI>`) ; `bgpd` est activé sur les spines et les leaves des sites 2
  à 4, `pimd` sur `mc_r`.
- Les fichiers `/etc/hosts` contiennent les noms : `st_r-eth1` désigne l'adresse de l'interface
  `eth1` de `st_r`, `st_vtep2-lo` l'adresse de bouclage de `st_vtep2`.
- L'AS de la fabrique est **{asn}** (sites 2 à 4).

**Plan d'adressage.** Les liens de l'underlay sont des /30 ; les hôtes d'un même site partagent un
sous-réseau de niveau 2 (sauf au site 3).

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- Partie 1 : VNI **{st_vni}**.
- Partie 2 : VNI A **{l2_a}** (`l2_leaf1`, `l2_leaf2`), VNI B **{l2_b}** (`l2_leaf2`, `l2_leaf3`).
- Partie 3 : VNI du sous-réseau A **{irb_a}** (`irb_leaf1`, `irb_leaf2`), du sous-réseau B **{irb_b}**
  (`irb_leaf2`) ; VRF `{vrf}` (table {table}), L3VNI **{l3vni}** ; passerelle anycast : `{gw_a}` (A),
  `{gw_b}` (B), adresse MAC `{gw_mac}`.
- Partie 4 : VNI **{fix_vni}**.
- Partie 5 : VNI **{mc_vni}**, groupe **{group}**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`). Les commandes `ip` et `bridge` ne sont
  pas enregistrées : ne redémarrez pas les machines.
- Une session BGP s'établit en quelques secondes ; une route EVPN met quelques secondes de plus à
  arriver dans le noyau des autres leaves.

**Évaluation.** Chaque évaluation lit vos réponses, les interfaces et les tables du noyau, l'état
d'EVPN dans FRR, puis envoie des `ping` (dont des paquets de 1500 octets avec le bit DF). Elle dure
une quinzaine de secondes.
""").format(site_rows=site_rows, addressing=addressing, asn=FABRIC_AS, st_vni=d.st_vni, l2_a=d.l2_vni_a,
            l2_b=d.l2_vni_b, irb_a=d.irb_vni_a, irb_b=d.irb_vni_b, vrf=VRF, table=VRF_TABLE, l3vni=d.irb_l3vni,
            gw_a=d.ips.irb_gw_a, gw_b=d.ips.irb_gw_b, gw_mac=d.gw_mac, fix_vni=d.fix_vni, mc_vni=d.mc_vni,
            group=d.mc_group)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_static`, `solve_l2`, `solve_irb`, `solve_fix` et `solve_mcast` (onglet
*Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes, attend {wait} s (les adjacences OSPF relancées par
le changement de MTU) puis remplit tous les formulaires : une évaluation lancée dès son retour donne
tous les points, bonus compris.

Les pannes du site `fix` : l'interface `{vx}` de `fix_leaf2` a le VNI {wrong} (son nom est juste),
`fix_leaf1` n'est pas client du route reflector sur `fix_spine`, `fix_leaf2` n'a pas
`advertise-all-vni`, l'interface `{vx}` de `fix_leaf1` est hors du pont `{br}`.
""").format(wait=OSPF_WAIT, vx=vx(d.fix_vni), br=br(d.fix_vni), wrong=d.fix_vni + 1)),
        )

        # =====================================================================
        # Part 1 — static VXLAN (st)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("static"), tr("Partie 1 — VXLAN statique (site st)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un segment VXLAN entre trois VTEP"),
            description=tr("""
`st_vtep1`, `st_vtep2` et `st_vtep3` sont reliés par le routeur `st_r` ; OSPF annonce leurs
interfaces de bouclage. Chaque VTEP a, sur `eth1`, un hôte du même sous-réseau `{subnet}` : `st_h1`,
`st_h2`, `st_h3`. Pour l'instant, les hôtes ne se joignent pas (sections @@ref:vxlan-header@@ à
@@ref:mtu@@).

1. Sur chaque VTEP, créez une interface `vxlan` pour le VNI **{vni}** (adresse locale : l'interface de
   bouclage, port UDP de l'IANA) et un pont qui la relie à `eth1`.
2. Donnez à chaque VTEP la liste d'inondation des deux autres (réplication en tête de réseau).
   Vérifiez que les hôtes se joignent ; regardez la table de l'interface `vxlan` de `st_vtep1`, et
   les paquets sur `st_r` (`tcpdump -nei eth0 udp port 4789`).
3. Essayez `ping -M do -s 1472` d'un hôte à l'autre. Que se passe-t-il, et pourquoi ? Faites passer
   ces paquets de 1500 octets **sans fragmentation**, sans changer la MTU des hôtes.
""").format(subnet=net('st_net'), vni=d.st_vni)
            + instructor(tr("""
**Solution.**

{solution}

Sans changement de MTU, le VTEP répond par un ICMP *fragmentation needed* (MTU 1450) : l'hôte refuse
ensuite d'envoyer (`Message too long`) pendant une dizaine de minutes (`ip route flush cache` sur
l'hôte pour l'oublier). Si seule la MTU des VTEP augmente, `st_r` fragmente les paquets VXLAN.

Évaluation : `st_vxlan` (6 : 2 par VTEP, une interface du bon VNI, adresse locale et port 4789, dans
le pont d'`eth1`), `st_flood` (3 : 1 par VTEP dont la liste d'inondation contient exactement les
deux autres), `st_ping` (3 : `st_h1` → `st_h2`, `st_h1` → `st_h3`, `st_h2` → `st_h3`), `st_learn` (2 :
`st_vtep1` a appris l'adresse MAC de `st_h2` et de `st_h3` derrière le bon VTEP), `st_mtu` (3 : ping
de 1500 octets avec DF de `st_h1` vers `st_h2` et `st_h3`, sans fragment créé par `st_r`) ;
`st_q_port`, `st_q_overhead` (1 chacun) ; pour l'enseignant seulement : `st_q_copies` (1).
""").format(solution=_mixed_text(ns.solution_static()))),
        )
        cheat_st = {'port': str(VXLAN_PORT), 'overhead': '50', 'copies': 'two'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site st"),
            description=tr("""
- port UDP de destination des paquets VXLAN : @@{port:[0-9]+}@@
- nombre d'octets que l'encapsulation VXLAN ajoute à un paquet IP (de l'en-tête Ethernet extérieur à
  l'en-tête VXLAN) : @@{overhead:[0-9]+}@@
- nombre de paquets VXLAN que `st_vtep1` envoie pour une requête ARP de `st_h1` :
  @@{copies:>deux, un par VTEP distant>>>two|un seul, en broadcast>>>one|un par lien de st_r>>>three|aucun : st_vtep1 répond lui-même>>>none}@@
""")
            + instructor(tr("""
**Solution.** **4789** ; **50** ; deux, un par VTEP distant.

Évaluation : `st_q_port`, `st_q_overhead` (1 chacun) ; pour l'enseignant seulement : `st_q_copies` (1).
""")),
            cheat_answers={"final": cheat_st, "solve_static": cheat_st},
        )
        vni = d.st_vni
        vxlan_ok, flood_ok = [], []
        for v in ST_VTEPS:
            devices = vxlan_devices(st_links[v])
            dev = vxlan_of_vni(devices, vni)
            good = (dev is not None and _port_ok(st_links[v], devices, dev, 'eth1')
                    and devices[dev]['local'] == str(lo(v)) and devices[dev]['port'] == VXLAN_PORT)
            vxlan_ok.append(good)
            expected = sorted(str(lo(o)) for o in ST_VTEPS if o != v)
            flood_ok.append(dev is not None and flood_list(st_fdb[v], dev) == expected)
        self.add_grade_element(
            title=no_tr("st_vxlan"), max_grade=6, grade_part=part1, grade=2 * sum(vxlan_ok),
            description=tr("interfaces VXLAN et ponts des trois VTEP"),
        )
        self.add_grade_element(
            title=no_tr("st_flood"), max_grade=3, grade_part=part1, grade=sum(flood_ok),
            description=tr("listes d'inondation"),
        )
        self.add_grade_element(
            title=no_tr("st_ping"), max_grade=3, grade_part=part1, grade=sum(st_pings),
            description=tr("les trois hôtes se joignent"),
        )
        dev1 = vxlan_of_vni(vxlan_devices(st_links['st_vtep1']), vni)
        learned = remote_macs(st_fdb2, dev1) if dev1 else {}
        learn_ok = [bool(st_mac[h]) and learned.get(st_mac[h]) == str(lo(vt))
                    for h, vt in (('st_h2', 'st_vtep2'), ('st_h3', 'st_vtep3'))]
        self.add_grade_element(
            title=no_tr("st_learn"), max_grade=2, grade_part=part1, grade=sum(learn_ok),
            description=tr("adresses MAC apprises derrière leur VTEP"),
        )
        delta = frag_delta(st_frag0, st_frag1)
        self.add_grade_element(
            title=no_tr("st_mtu"), max_grade=3, grade_part=part1, grade=3 * int(all(st_df) and delta == 0),
            description=tr("paquets de 1500 octets sans fragmentation"),
        )
        self.add_grade_element(
            title=no_tr("st_q_port"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('port')) == VXLAN_PORT),
            description=tr("port de VXLAN"),
        )
        self.add_grade_element(
            title=no_tr("st_q_overhead"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('overhead')) == 50),
            description=tr("surcoût de l'encapsulation"),
        )
        self.add_grade_element(
            title=no_tr("st_q_copies"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('copies')) == 'two'), description=tr("réplication en tête de réseau"),
        )

        # =====================================================================
        # Part 2 — EVPN (l2)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("evpn_l2"), tr("Partie 2 — EVPN, le plan de contrôle (site l2)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une fabrique EVPN"),
            description=tr("""
`l2_spine` relie `l2_leaf1`, `l2_leaf2` et `l2_leaf3` ; OSPF annonce leurs interfaces de bouclage.
Les leaves portent deux VNI, qui utilisent **le même sous-réseau** `{subnet}` : le VNI A **{a}**
(`l2_a1` derrière `l2_leaf1`, `l2_a2` derrière `l2_leaf2`) et le VNI B **{b}** (`l2_b2` derrière
`l2_leaf2`, `l2_b3` derrière `l2_leaf3`). Leurs interfaces `vxlan` (sans apprentissage) et leurs ponts
existent ; aucune liste d'inondation n'est configurée (sections @@ref:evpn@@ à @@ref:evpn-frr@@).

1. Établissez une session iBGP entre chaque leaf et `l2_spine`, entre interfaces de bouclage, dans la
   seule famille L2VPN EVPN ; les leaves annoncent tous leurs VNI. Faites de `l2_spine` le route
   reflector des leaves.
2. Regardez la table EVPN d'un leaf (`show bgp l2vpn evpn route`) : quelles routes de type 3, de
   type 2 ? Puis la liste d'inondation des interfaces `vxlan` dans le noyau (`bridge fdb show`).
3. Vérifiez que `l2_a1` joint `l2_a2` et que `l2_b2` joint `l2_b3`, mais que `l2_a1` ne joint pas
   l'adresse de `l2_b2`, pourtant dans le même sous-réseau.
""").format(subnet=net('l2_net'), a=d.l2_vni_a, b=d.l2_vni_b)
            + instructor(tr("""
**Solution.**

{solution}

Les routes de type 3 d'un VNI ne viennent que des leaves qui le portent : `l2_leaf1` n'a que
`l2_leaf2` dans sa liste d'inondation du VNI A. Les adresses MAC distantes apparaissent dans le noyau
avec `extern_learn`.

Évaluation : `l2_sessions` (3 : 1 par leaf dont la session EVPN est établie sur le spine), `l2_rr`
(2 : `l2_leaf1` a la route de type 3 de `l2_leaf2` pour le VNI A, `l2_leaf3` celle de `l2_leaf2`
pour le VNI B, reflétées par le spine), `l2_vni` (3 : 1 par leaf dont zebra connaît exactement les
VTEP distants de chaque VNI), `l2_macs` (3 : 1 par leaf dont le noyau a installé les adresses MAC des
hôtes distants de ses VNI), `l2_ping` (4 : 2 par VNI), `l2_isolation` (2 : `l2_a1` ne joint pas
`l2_b2`) ; `l2_q_rt`, `l2_q_type3`, `l2_q_type2` (1 chacun) ; pour l'enseignant seulement :
`l2_q_rr`, `l2_q_rd` (1 chacun).
""").format(solution=_vtysh_text(ns.solution_l2()))),
        )
        cheat_l2 = {'rt': rt(d.l2_vni_a), 'type3': '3', 'type2': '2', 'rr': 'ibgp', 'rd': 'rid_index'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Les routes EVPN"),
            description=tr("""
- route target (automatique) du VNI A : @@{rt:[0-9: ]+}@@
- type des routes qui construisent la liste d'inondation : @@{type3:[0-9]}@@
- type des routes qui annoncent une adresse MAC : @@{type2:[0-9]}@@
- sans route reflector, `l2_leaf1` apprendrait-il les routes de `l2_leaf2` par `l2_spine` ?
  @@{rr:>non : un routeur iBGP ne transmet pas à un voisin iBGP ce qu'il a appris d'un autre voisin iBGP>>>ibgp|oui : le spine transmet toutes les routes>>>yes|non : les RT diffèrent>>>rt|oui, mais sans les routes de type 3>>>type3}@@
- le RD automatique d'un VNI est :
  @@{rd:>l'adresse du routeur suivie d'un numéro interne>>>rid_index|l'AS suivi du VNI>>>as_vni|l'adresse du routeur suivie du VNI>>>rid_vni|le même que la RT>>>rt}@@
""")
            + instructor(tr("""
**Solution.** **`{rt}`** ; **3** ; **2** ; non : un routeur iBGP ne transmet pas à un voisin iBGP ce
qu'il a appris d'un autre voisin iBGP ; l'adresse du routeur suivie d'un numéro interne.

Évaluation : `l2_q_rt`, `l2_q_type3`, `l2_q_type2` (1 chacun) ; pour l'enseignant seulement :
`l2_q_rr`, `l2_q_rd` (1 chacun).
""").format(rt=cheat_l2['rt'])),
            cheat_answers={"final": cheat_l2, "solve_l2": cheat_l2},
        )
        peers = l2_sum.get('peers') or {}
        sessions = [bool((peers.get(str(lo(leaf))) or {}).get('established')) for leaf in LEAVES['l2']]
        self.add_grade_element(
            title=no_tr("l2_sessions"), max_grade=3, grade_part=part2, grade=sum(sessions),
            description=tr("sessions EVPN des leaves sur le spine"),
        )
        reflected = [bool(evpn_routes(l2_routes['l2_leaf1'], route_type=3, vtep=lo('l2_leaf2'), rt=rt(d.l2_vni_a))),
                     bool(evpn_routes(l2_routes['l2_leaf3'], route_type=3, vtep=lo('l2_leaf2'), rt=rt(d.l2_vni_b)))]
        self.add_grade_element(
            title=no_tr("l2_rr"), max_grade=2, grade_part=part2, grade=sum(reflected),
            description=tr("routes reflétées par le spine"),
        )
        expected_remote = {
            'l2_leaf1': {d.l2_vni_a: ['l2_leaf2']},
            'l2_leaf2': {d.l2_vni_a: ['l2_leaf1'], d.l2_vni_b: ['l2_leaf3']},
            'l2_leaf3': {d.l2_vni_b: ['l2_leaf2']},
        }
        vni_ok = [all((l2_vnis[leaf].get(v) or {}).get('remote_vteps') == sorted(str(lo(o)) for o in others)
                      for v, others in expected_remote[leaf].items())
                  for leaf in LEAVES['l2']]
        self.add_grade_element(
            title=no_tr("l2_vni"), max_grade=3, grade_part=part2, grade=sum(vni_ok),
            description=tr("VTEP distants de chaque VNI"),
        )
        expected_macs = {
            'l2_leaf1': [(d.l2_vni_a, 'l2_a2', 'l2_leaf2')],
            'l2_leaf2': [(d.l2_vni_a, 'l2_a1', 'l2_leaf1'), (d.l2_vni_b, 'l2_b3', 'l2_leaf3')],
            'l2_leaf3': [(d.l2_vni_b, 'l2_b2', 'l2_leaf2')],
        }
        macs_ok = []
        for leaf in LEAVES['l2']:
            devices = vxlan_devices(l2_links[leaf])
            good = True
            for v, host, origin in expected_macs[leaf]:
                dev = vxlan_of_vni(devices, v)
                installed = remote_macs(l2_fdb[leaf], dev, extern_only=True) if dev else {}
                good = good and bool(l2_mac[host]) and installed.get(l2_mac[host]) == str(lo(origin))
            macs_ok.append(good)
        self.add_grade_element(
            title=no_tr("l2_macs"), max_grade=3, grade_part=part2, grade=sum(macs_ok),
            description=tr("adresses MAC distantes installées par EVPN"),
        )
        self.add_grade_element(
            title=no_tr("l2_ping"), max_grade=4, grade_part=part2, grade=2 * int(l2_ping_a) + 2 * int(l2_ping_b),
            description=tr("les hôtes de chaque VNI se joignent"),
        )
        self.add_grade_element(
            title=no_tr("l2_isolation"), max_grade=2, grade_part=part2, grade=2 * int(l2_ping_a and not l2_cross),
            description=tr("les deux VNI sont isolés"),
        )
        self.add_grade_element(
            title=no_tr("l2_q_rt"), max_grade=1, grade_part=part2, grade=int(_rt(q2.get('rt')) == rt(d.l2_vni_a)),
            description=tr("RT du VNI A"),
        )
        self.add_grade_element(
            title=no_tr("l2_q_type3"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('type3')) == 3),
            description=tr("routes de type 3"),
        )
        self.add_grade_element(
            title=no_tr("l2_q_type2"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('type2')) == 2),
            description=tr("routes de type 2"),
        )
        self.add_grade_element(
            title=no_tr("l2_q_rr"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('rr')) == 'ibgp'), description=tr("rôle du route reflector"),
        )
        self.add_grade_element(
            title=no_tr("l2_q_rd"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('rd')) == 'rid_index'), description=tr("RD automatique"),
        )

        # =====================================================================
        # Part 3 — symmetric IRB, anycast gateway, type 5 (irb)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("irb"), tr("Partie 3 — routage entre VNI et vers l'extérieur (site irb)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("IRB symétrique, passerelle anycast et routes de type 5"),
            description=tr("""
`irb_spine` est le route reflector de `irb_leaf1`, `irb_leaf2` et du *border leaf* `irb_border` ;
EVPN fonctionne déjà pour les VNI de niveau 2 : le sous-réseau A `{net_a}` (VNI **{a}**, `irb_a1`
derrière `irb_leaf1`, `irb_a2` derrière `irb_leaf2`) et le sous-réseau B `{net_b}` (VNI **{b}**,
`irb_b2` derrière `irb_leaf2` seulement). Les hôtes ont pour passerelle `{gw_a}` (A) ou `{gw_b}` (B),
qui n'existent pas encore. `irb_border` a déjà la VRF `{vrf}`, le L3VNI **{l3}** et une route
statique vers le réseau extérieur `{ext}` de `irb_ext` (sections @@ref:arp-suppression@@ à
@@ref:type5@@).

1. Sur `irb_leaf1` et `irb_leaf2`, créez la VRF `{vrf}` (table {table}) et son L3VNI **{l3}**
   (interface `vxlan`, pont, déclaration dans FRR).
2. Faites des ponts des VNI de niveau 2 les passerelles de leurs hôtes : sur **les deux leaves**, la
   même adresse IP et la même adresse MAC `{gw_mac}`, dans la VRF. Activez la suppression ARP sur les
   interfaces `vxlan` des VNI de niveau 2.
3. Faites annoncer en type 5 les sous-réseaux des leaves (leurs réseaux connectés dans la VRF) et,
   par `irb_border`, le réseau extérieur.
4. Vérifiez que `irb_a1` joint `irb_b2` et l'adresse `{ext_addr}` de `irb_ext`. Regardez les routes
   de la VRF, et les paquets entre les leaves (`tcpdump -nei eth0 udp port 4789` sur `irb_spine`) :
   quel VNI, quelles adresses MAC intérieures ?
""").format(net_a=net('irb_net_a'), net_b=net('irb_net_b'), a=d.irb_vni_a, b=d.irb_vni_b, gw_a=d.ips.irb_gw_a.ip,
            gw_b=d.ips.irb_gw_b.ip, vrf=VRF, table=VRF_TABLE, l3=d.irb_l3vni, ext=net('irb_ext_net'),
            gw_mac=d.gw_mac, ext_addr=d.ips.irb_ext_addr.ip)
            + instructor(tr("""
**Solution.**

{solution}

`irb_leaf1` ne porte pas le VNI du sous-réseau B : il route les paquets vers `irb_leaf2` dans le
L3VNI ({l3}), la trame intérieure allant de sa *router MAC* à celle d'`irb_leaf2`. La route de type
2 d'`irb_b2` porte deux VNI ({b}/{l3}). Sans les routes de type 5 des sous-réseaux, `irb_b2` ne serait
joignable depuis `irb_leaf1` qu'après avoir lui-même émis (hôte silencieux).

Évaluation : `irb_l3vni` (4 : 2 par leaf dont zebra a le L3VNI, de type L3, dans la VRF, état Up),
`irb_gateway` (4 : 2 par leaf dont les ponts des VNI de niveau 2 ont l'adresse IP et l'adresse MAC de
la passerelle, dans la VRF), `irb_suppress` (2 : 1 par leaf, suppression ARP sur ses interfaces
`vxlan` de niveau 2), `irb_macip` (3 : sur `irb_leaf1`, la route MAC/IP d'`irb_b2` avec les deux VNI ;
dans la VRF d'`irb_leaf1`, la route /32 d'`irb_b2` par `irb_leaf2` ; dans la VRF d'`irb_leaf2`, celle
d'`irb_a1` par `irb_leaf1`), `irb_type5` (3 : sur `irb_leaf1`, le réseau extérieur par `irb_border`
et le sous-réseau B par `irb_leaf2` ; sur `irb_border`, le sous-réseau A), `irb_ping` (6 : `irb_a1` →
`irb_b2`, `irb_a1` → `irb_ext`, 3 chacun) ; `irb_q_l3vni` (1) ; pour l'enseignant seulement :
`irb_q_mac`, `irb_q_silent`, `irb_q_sym` (1 chacun).
""").format(solution=_mixed_text(ns.solution_irb()), l3=d.irb_l3vni, b=d.irb_vni_b)),
        )
        cheat_irb = {'l3vni': str(d.irb_l3vni), 'mac': 'rmac', 'silent': 'unreachable', 'sym': 'own'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Le routage dans la fabrique"),
            description=tr("""
- VNI des paquets VXLAN de `irb_a1` vers `irb_b2` entre les deux leaves : @@{l3vni:[0-9]+}@@
- adresse MAC de destination de la trame intérieure de ces paquets :
  @@{mac:>la router MAC d'irb_leaf2>>>rmac|l'adresse MAC d'irb_b2>>>host|l'adresse MAC de la passerelle anycast>>>gw|ff:ff:ff:ff:ff:ff>>>bcast}@@
- sans routes de type 5 pour les sous-réseaux, un hôte du sous-réseau B qui n'a encore rien émis
  est, depuis `irb_a1` :
  @@{silent:>injoignable : aucune route ne mène à lui depuis irb_leaf1>>>unreachable|joignable : irb_leaf1 le cherche par ARP>>>arp|joignable par la passerelle anycast>>>gw|joignable par irb_border>>>border}@@
- en IRB symétrique, un leaf doit porter :
  @@{sym:>les VNI de ses hôtes, plus le L3VNI>>>own|tous les VNI de la fabrique>>>all|seulement le L3VNI>>>l3|un VNI par VTEP distant>>>per_vtep}@@
""")
            + instructor(tr("""
**Solution.** **{l3}** ; la *router MAC* d'`irb_leaf2` ; injoignable : aucune route ne mène à lui
depuis `irb_leaf1` ; les VNI de ses hôtes, plus le L3VNI.

Évaluation : `irb_q_l3vni` (1) ; pour l'enseignant seulement : `irb_q_mac`, `irb_q_silent`,
`irb_q_sym` (1 chacun).
""").format(l3=d.irb_l3vni)),
            cheat_answers={"final": cheat_irb, "solve_irb": cheat_irb},
        )
        gateways = {d.irb_vni_a: d.ips.irb_gw_a, d.irb_vni_b: d.ips.irb_gw_b}
        l3_ok, gw_ok, sup_ok = [], [], []
        for leaf in irb_leaves:
            l3 = irb_vnis[leaf].get(d.irb_l3vni) or {}
            l3_ok.append(l3.get('type') == 'L3' and l3.get('vrf') == VRF and l3.get('state') == 'Up')
            devices = vxlan_devices(irb_links[leaf])
            good_gw, good_sup = True, True
            for v, _ifname in d.leaf_vnis(leaf):
                dev = vxlan_of_vni(devices, v)
                bridge = devices[dev]['master'] if dev else None
                good_gw = good_gw and bool(bridge) and link_master(irb_links[leaf], bridge) == VRF \
                    and normalize_mac(link_address(irb_links[leaf], bridge)) == normalize_mac(d.gw_mac) \
                    and str(gateways[v]) in addresses_of(irb_addrs[leaf], bridge)
                good_sup = good_sup and bool(dev) and bool((irb_ports[leaf].get(dev) or {}).get('neigh_suppress'))
            gw_ok.append(good_gw)
            sup_ok.append(good_sup)
        self.add_grade_element(
            title=no_tr("irb_l3vni"), max_grade=4, grade_part=part3, grade=2 * sum(l3_ok),
            description=tr("VRF et L3VNI des leaves"),
        )
        self.add_grade_element(
            title=no_tr("irb_gateway"), max_grade=4, grade_part=part3, grade=2 * sum(gw_ok),
            description=tr("passerelle anycast sur les deux leaves"),
        )
        self.add_grade_element(
            title=no_tr("irb_suppress"), max_grade=2, grade_part=part3, grade=sum(sup_ok),
            description=tr("suppression ARP"),
        )
        l3_bridge1 = (irb_vnis['irb_leaf1'].get(d.irb_l3vni) or {}).get('svi')
        l3_bridge2 = (irb_vnis['irb_leaf2'].get(d.irb_l3vni) or {}).get('svi')
        macip = evpn_routes(irb_routes['irb_leaf1'], route_type=2, ip=ip('irb_b2'))
        macip_ok = [any(r['vnis'] == [d.irb_vni_b, d.irb_l3vni] for r in macip),
                    bool(l3_bridge1) and _route_via(irb_k['irb_leaf1'], f"{ip('irb_b2')}/32", lo('irb_leaf2'), l3_bridge1),
                    bool(l3_bridge2) and _route_via(irb_k['irb_leaf2'], f"{ip('irb_a1')}/32", lo('irb_leaf1'), l3_bridge2)]
        self.add_grade_element(
            title=no_tr("irb_macip"), max_grade=3, grade_part=part3, grade=sum(macip_ok),
            description=tr("routes MAC/IP et routes des hôtes dans la VRF"),
        )
        type5_ok = [bool(evpn_routes(irb_routes['irb_leaf1'], route_type=5, network=net('irb_ext_net'),
                                     nexthop=lo('irb_border'))),
                    bool(evpn_routes(irb_routes['irb_leaf1'], route_type=5, network=net('irb_net_b'),
                                     nexthop=lo('irb_leaf2'))),
                    bool(evpn_routes(irb_routes['irb_border'], route_type=5, network=net('irb_net_a'), local=False))]
        self.add_grade_element(
            title=no_tr("irb_type5"), max_grade=3, grade_part=part3, grade=sum(type5_ok),
            description=tr("routes de type 5"),
        )
        self.add_grade_element(
            title=no_tr("irb_ping"), max_grade=6, grade_part=part3, grade=3 * int(irb_ping_b) + 3 * int(irb_ping_ext),
            description=tr("routage entre sous-réseaux et vers l'extérieur"),
        )
        self.add_grade_element(
            title=no_tr("irb_q_l3vni"), max_grade=1, grade_part=part3, grade=int(_int(q3.get('l3vni')) == d.irb_l3vni),
            description=tr("VNI des paquets routés"),
        )
        self.add_grade_element(
            title=no_tr("irb_q_mac"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('mac')) == 'rmac'), description=tr("router MAC"),
        )
        self.add_grade_element(
            title=no_tr("irb_q_silent"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('silent')) == 'unreachable'), description=tr("hôte silencieux"),
        )
        self.add_grade_element(
            title=no_tr("irb_q_sym"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('sym')) == 'own'), description=tr("IRB symétrique"),
        )

        # =====================================================================
        # Part 4 — troubleshooting (fix)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("fix"), tr("Partie 4 — dépannage d'une fabrique EVPN (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une fabrique EVPN en panne"),
            description=tr("""
Le site `fix` est une petite fabrique EVPN : `fix_spine`, route reflector de `fix_leaf1` et
`fix_leaf2`, et un VNI **{vni}** (sous-réseau `{subnet}`) qui relie `fix_h1` (derrière `fix_leaf1`) et
`fix_h2` (derrière `fix_leaf2`). OSPF, les sessions EVPN, les interfaces `vxlan` et les ponts sont
configurés. Pourtant `fix_h1` ne joint pas `fix_h2` : **quatre pannes** ont été glissées dans la
configuration (section @@ref:evpn-debug@@).

Trouvez et corrigez chaque panne sans tout reconfigurer : suivez le chemin d'une route EVPN et d'une
trame d'un leaf à l'autre, dans les deux sens.
""").format(vni=d.fix_vni, subnet=net('fix_net'))
            + instructor(tr("""
**Solution.**

{solution}

Évaluation : `fix_vni` (3 : l'interface `vxlan` de `fix_leaf2` a le VNI {vni}, dans le pont
d'`eth1`), `fix_rr` (3 : `fix_leaf1` client du route reflector sur `fix_spine`), `fix_advertise` (3 :
`advertise-all-vni` sur `fix_leaf2`), `fix_bridge` (3 : l'interface `vxlan` de `fix_leaf1` dans le pont
d'`eth1`), `fix_ping` (4), `fix_macs` (2 : `fix_leaf1` a installé l'adresse MAC de `fix_h2` derrière
`fix_leaf2`) ; pour l'enseignant seulement : `fix_q_vni`, `fix_q_rr` (1 chacun).
""").format(solution=_mixed_text(ns.solution_fix()), vni=d.fix_vni)),
        )
        cheat_fix = {'vni': 'recreate', 'rr': 'rr_client'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Ce que montraient les pannes"),
            description=tr("""
- pour corriger le VNI d'une interface `vxlan` :
  @@{vni:>il faut la supprimer et la recréer>>>recreate|ip link set … type vxlan id N suffit>>>set|il faut redémarrer FRR>>>frr|il faut changer le nom de l'interface>>>name}@@
- `fix_leaf2` recevait les routes de `fix_leaf1` :
  @@{rr:>non, tant que fix_leaf1 n'était pas client du route reflector>>>rr_client|oui, dès que la session était établie>>>yes|non, tant que les RT différaient>>>rt|non, tant que l'interface vxlan était hors du pont>>>bridge}@@
""")
            + instructor(tr("""
**Solution.** Il faut la supprimer et la recréer (« Cannot change VNI ») ; non, tant que `fix_leaf1`
n'était pas client du route reflector.

Évaluation, pour l'enseignant seulement : `fix_q_vni`, `fix_q_rr` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        fix_devices = {leaf: vxlan_devices(fix_links[leaf]) for leaf in LEAVES['fix']}
        dev2 = vxlan_of_vni(fix_devices['fix_leaf2'], d.fix_vni)
        dev1 = vxlan_of_vni(fix_devices['fix_leaf1'], d.fix_vni)
        spine_af = evpn_family((fix_cfg['fix_spine'] or {}).get('router_bgp'))
        rr_client = bool((spine_af['neighbors'].get(str(lo('fix_leaf1'))) or {}).get('route_reflector_client'))
        self.add_grade_element(
            title=no_tr("fix_vni"), max_grade=3, grade_part=part4,
            grade=3 * int(_port_ok(fix_links['fix_leaf2'], fix_devices['fix_leaf2'], dev2, 'eth1')),
            description=tr("VNI de fix_leaf2"),
        )
        self.add_grade_element(
            title=no_tr("fix_rr"), max_grade=3, grade_part=part4, grade=3 * int(rr_client),
            description=tr("fix_leaf1 client du route reflector"),
        )
        self.add_grade_element(
            title=no_tr("fix_advertise"), max_grade=3, grade_part=part4,
            grade=3 * int(evpn_family((fix_cfg['fix_leaf2'] or {}).get('router_bgp'))['advertise_all_vni']),
            description=tr("advertise-all-vni sur fix_leaf2"),
        )
        self.add_grade_element(
            title=no_tr("fix_bridge"), max_grade=3, grade_part=part4,
            grade=3 * int(_port_ok(fix_links['fix_leaf1'], fix_devices['fix_leaf1'], dev1, 'eth1')),
            description=tr("interface vxlan de fix_leaf1 dans son pont"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=4, grade_part=part4, grade=4 * int(fix_ping),
            description=tr("fix_h1 joint fix_h2"),
        )
        installed = remote_macs(fix_fdb, dev1, extern_only=True) if dev1 else {}
        self.add_grade_element(
            title=no_tr("fix_macs"), max_grade=2, grade_part=part4,
            grade=2 * int(fix_ping and bool(fix_mac) and installed.get(fix_mac) == str(lo('fix_leaf2'))),
            description=tr("adresse MAC distante installée par EVPN"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_vni"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get('vni')) == 'recreate'), description=tr("changer un VNI"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_rr"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get('rr')) == 'rr_client'), description=tr("client du route reflector"),
        )

        # =====================================================================
        # Part 5 — multicast underlay (mc, bonus)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("mcast"), tr("Partie 5 — un underlay multicast (site mc, bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Inonder par un groupe multicast (bonus)"),
            description=tr("""
`mc_vtep1`, `mc_vtep2` et `mc_vtep3` sont reliés par le routeur `mc_r` (OSPF fonctionne) ; chaque VTEP
a déjà un pont `{br}` avec `eth1`, vers son hôte (`mc_h1` à `mc_h3`, sous-réseau `{subnet}`). Ici, pas
de liste d'inondation : le trafic BUM du VNI **{vni}** doit passer par le groupe **{group}** (section
@@ref:mcast-underlay@@).

1. Sur chaque VTEP, créez l'interface `vxlan` du VNI {vni} avec ce groupe, et branchez-la sur le pont.
2. Sur `mc_r`, activez PIM et IGMP sur les interfaces vers les VTEP, et faites de `mc_r` le RP des
   groupes `239.0.0.0/8`.
3. Vérifiez que les hôtes se joignent ; regardez `show ip mroute` sur `mc_r` et la table des
   interfaces `vxlan`.
""").format(br=br(d.mc_vni), subnet=net('mc_net'), vni=d.mc_vni, group=d.mc_group)
            + instructor(tr("""
**Solution.**

{solution}

Sans `ttl`, les paquets multicast partent avec un TTL de 1 et `mc_r` ne les route pas ; avec `local`
(l'interface de bouclage), `mc_r` ne prend pas en charge une source qui n'est pas directement
connectée.

Évaluation (bonus) : `mc_vxlan` (2 : les trois VTEP ont une interface du VNI {vni} avec le groupe
{group}, un TTL supérieur à 1, dans le pont d'`eth1`), `mc_mroute` (2 : sur `mc_r`, l'entrée `(*,G)` du
groupe vers les trois VTEP, puis une entrée `(S,G)` d'un VTEP), `mc_ping` (2 : `mc_h1` joint `mc_h2` et
`mc_h3`).
""").format(solution=_mixed_text(ns.solution_mcast()), vni=d.mc_vni, group=d.mc_group)),
        )
        mc_ok = []
        for m in MC_VTEPS:
            devices = vxlan_devices(mc_links[m])
            dev = vxlan_of_vni(devices, d.mc_vni)
            mc_ok.append(dev is not None and _port_ok(mc_links[m], devices, dev, 'eth1')
                         and devices[dev]['group'] == d.mc_group and devices[dev]['ttl'] > 1)
        star = mc_routes.get(('*', d.mc_group)) or {}
        sources = {str(addr(m, f"mc_u{i + 1}")) for i, m in enumerate(MC_VTEPS)}
        sg = any(key[1] == d.mc_group and key[0] in sources for key in mc_routes)
        self.add_grade_element(
            title=no_tr("mc_vxlan"), max_grade=2, grade_part=part5, bonus=True, grade=2 * int(all(mc_ok)),
            description=tr("interfaces VXLAN multicast"),
        )
        self.add_grade_element(
            title=no_tr("mc_mroute"), max_grade=2, grade_part=part5, bonus=True,
            grade=int({'eth0', 'eth1', 'eth2'} <= set(star.get('oil') or [])) + int(sg),
            description=tr("routes multicast de mc_r"),
        )
        self.add_grade_element(
            title=no_tr("mc_ping"), max_grade=2, grade_part=part5, bonus=True, grade=2 * int(all(mc_pings)),
            description=tr("les hôtes se joignent"),
        )


_TRANSLATIONS = {}
