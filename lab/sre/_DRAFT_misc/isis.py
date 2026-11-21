"""IS-IS lab with FRR (isisd): the protocol, levels and areas, broadcast networks, authentication.

IPv4 only.  Five independent sites, one per part, and a bonus site (completing a part gives all its
points whatever the others):

- ``bas``: a square of four routers; ``bas_r1`` and ``bas_r2`` run IS-IS (level 2, one area), the
  students configure ``bas_r3`` and ``bas_r4`` (NET built from the loopback, point-to-point links,
  passive interfaces) and observe the protocol;
- ``lvl``: a line of five routers across three areas; the students configure ``lvl_r1`` (level 1)
  and ``lvl_r2`` (level 1-2, circuit types) and observe the ATT bit and the default route;
- ``lan``: three routers on a broadcast network and a fourth one behind; the students make
  ``lan_r3`` the DIS, change a metric (wide metrics) and put ``lan_r1`` in overload;
- ``auth``: ``auth_r2`` (no terminal) signs its hellos and its level 2 LSPs; the students
  configure the passwords on ``auth_r1``;
- ``fix``: a line of four routers shipped with four faults (areas of a level 1 adjacency, network
  types, MTU, overload bit left set);
- ``ext`` (bonus): ``ext_r1`` redistributes its static routes and a default route.

Grading reads the text of ``show isis neighbor detail`` (the json form loses adjacencies of
broadcast circuits) and the json of the interfaces and of the database (lib/frr.py), the running
configuration, the kernel routes and real pings.  The states ``solve_<part>`` apply the reference
solution of one part, ``final`` all of them.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List

import utils
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from ping import eval_ping
from frr import (
    get_frr_running_config, get_isis_database, get_isis_interfaces, get_isis_neighbors, get_kernel_routes,
    is_isis_protocol, isis_adjacency_levels, isis_adjacency_up, isis_lsps_of, isis_system_id_from_ipv4,
    normalize_system_id, parse_frr_config, parse_isis_net,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Routage dynamique : IS-IS", en="Dynamic routing: IS-IS")
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

# Router interfaces in ethN order: the network of each.
ROUTER_IFACES = {
    'bas_r1': ['bas_lan1', 'bas_l12', 'bas_l14'],
    'bas_r2': ['bas_l12', 'bas_l23'],
    'bas_r3': ['bas_l23', 'bas_l34'],
    'bas_r4': ['bas_lan4', 'bas_l34', 'bas_l14'],
    'lvl_r1': ['lvl_lan1', 'lvl_l12'],
    'lvl_r2': ['lvl_l12', 'lvl_l23'],
    'lvl_r3': ['lvl_l23', 'lvl_l34'],
    'lvl_r4': ['lvl_l34', 'lvl_l45'],
    'lvl_r5': ['lvl_lan5', 'lvl_l45'],
    'lan_r1': ['lan_seg', 'lan_l14'],
    'lan_r2': ['lan_lan2', 'lan_seg'],
    'lan_r3': ['lan_seg', 'lan_l34'],
    'lan_r4': ['lan_lan4', 'lan_l14', 'lan_l34'],
    'auth_r1': ['auth_lan1', 'auth_l12'],
    'auth_r2': ['auth_lan2', 'auth_l12'],
    'fix_r1': ['fix_lan1', 'fix_l12'],
    'fix_r2': ['fix_l12', 'fix_l23'],
    'fix_r3': ['fix_l23', 'fix_l34'],
    'fix_r4': ['fix_lan4', 'fix_l34'],
    'ext_r1': ['ext_wan', 'ext_l12'],
    'ext_r2': ['ext_lan2', 'ext_l12'],
}
# Hosts (one interface, eth0): their network and the router of their default route
HOSTS = {
    'bas_h1': ('bas_lan1', 'bas_r1'),
    'bas_h4': ('bas_lan4', 'bas_r4'),
    'lvl_h1': ('lvl_lan1', 'lvl_r1'),
    'lvl_h5': ('lvl_lan5', 'lvl_r5'),
    'lan_h2': ('lan_lan2', 'lan_r2'),
    'lan_h4': ('lan_lan4', 'lan_r4'),
    'auth_h1': ('auth_lan1', 'auth_r1'),
    'auth_h2': ('auth_lan2', 'auth_r2'),
    'fix_h1': ('fix_lan1', 'fix_r1'),
    'fix_h4': ('fix_lan4', 'fix_r4'),
    'ext_h2': ('ext_lan2', 'ext_r2'),
}
# the operator's router of the external networks (bonus site): one interface on ext_wan
ISP = 'ext_isp'
# point-to-point links (/30): the first machine gets .1, the second .2
LINKS = {
    'bas_l12': ('bas_r1', 'bas_r2'), 'bas_l23': ('bas_r2', 'bas_r3'), 'bas_l34': ('bas_r3', 'bas_r4'),
    'bas_l14': ('bas_r1', 'bas_r4'),
    'lvl_l12': ('lvl_r1', 'lvl_r2'), 'lvl_l23': ('lvl_r2', 'lvl_r3'), 'lvl_l34': ('lvl_r3', 'lvl_r4'),
    'lvl_l45': ('lvl_r4', 'lvl_r5'),
    'lan_l14': ('lan_r1', 'lan_r4'), 'lan_l34': ('lan_r3', 'lan_r4'),
    'auth_l12': ('auth_r1', 'auth_r2'),
    'fix_l12': ('fix_r1', 'fix_r2'), 'fix_l23': ('fix_r2', 'fix_r3'), 'fix_l34': ('fix_r3', 'fix_r4'),
    'ext_l12': ('ext_r1', 'ext_r2'), 'ext_wan': ('ext_r1', ISP),
}
# broadcast networks (/24): host networks, and lan_seg where three routers meet
LANS = ['bas_lan1', 'bas_lan4', 'lvl_lan1', 'lvl_lan5', 'lan_seg', 'lan_lan2', 'lan_lan4', 'auth_lan1',
        'auth_lan2', 'fix_lan1', 'fix_lan4', 'ext_lan2']
ROUTER_LAN = 'lan_seg'
# routers configured by the lab, without terminal
OPERATORS = ('auth_r2', ISP)

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
_TOPOLOGY['ext_wan'][ISP] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS) + [ISP]

SITE_COLORS = {'bas': 'lightblue', 'lvl': 'palegreen', 'lan': 'khaki', 'auth': 'plum', 'fix': 'lightsalmon',
               'ext': 'lightgrey'}

# ---------------------------------------------------------------------------
# addressing: one /16 of 10.0.0.0/8 per instance; site s uses the third octets 16s to 16s + 15:
# 16s = the /30 links (link k: offset 4k), 16s + 1 + j = broadcast network j, 16s + 15 = loopbacks
# ---------------------------------------------------------------------------

SITE_NUMBER = {'bas': 1, 'lvl': 2, 'lan': 3, 'auth': 4, 'fix': 5, 'ext': 6}
LOOPBACK_OCTET = 15
# the lvl site puts each level 1 area in its own /22 (third octets 16s + 4 to 16s + 7 for area A,
# 16s + 8 to 16s + 11 for area C: a link, the host network, the loopbacks), so that its L1/L2
# router can announce it in level 2 as one summary
LVL_AREA_BLOCKS = {'a': 4, 'c': 8}
LVL_AREA_MEMBERS = {'a': ('lvl_l12', 'lvl_lan1', ('lvl_r1', 'lvl_r2')),
                    'c': ('lvl_l45', 'lvl_lan5', ('lvl_r4', 'lvl_r5'))}

EXT_PUBLIC = IPv4Network("203.0.113.0/24")     # the "Internet" of the bonus site (TEST-NET-3)
EXT_SERVER = IPv4Address("203.0.113.1")
LAN_R1_PRIORITY = 80             # given priority of lan_r1 on lan_seg: it is the DIS at start
FIX_MTU = 1400                   # the MTU of fix_r4's link to fix_r3 (a fault)
# the reference states wait for the LSPs: FRR regenerates an LSP at most every 30 s
CONVERGE_WAIT = 35
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : isisd activé
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
    """Name of the interface of *router* on *net* (``eth1``)."""
    return f"eth{ROUTER_IFACES[router].index(net)}"


def router_number(router: str) -> int:
    return int(router.rsplit('_r', 1)[1])


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    bas_area: str = ""         # part 1: area of the bas site
    lvl_area_a: str = ""       # part 2: area of lvl_r1 and lvl_r2
    lvl_area_b: str = ""       # part 2: area of lvl_r3 (level 2 only)
    lvl_area_c: str = ""       # part 2: area of lvl_r4 and lvl_r5
    lan_area: str = ""         # part 3
    lan_priority: int = 0      # part 3: priority to give lan_r3 on lan_seg
    lan_metric: int = 0        # part 3: metric of lan_l14 (> 63: wide metrics)
    auth_area: str = ""        # part 4
    auth_hello_key: str = ""   # part 4: hello password (md5) of auth_l12
    auth_domain_key: str = ""  # part 4: domain password (md5)
    fix_area: str = ""         # part 5: the area of the fix site
    fix_wrong_area: str = ""   # part 5: the area configured on fix_r1 (a fault)
    ext_area: str = ""         # bonus

    @classmethod
    def generate(cls):
        data = cls()
        # never 49.0001, the area of the course's examples
        areas = [f"49.{n:04d}" for n in random.sample(range(2, 10000), 9)]
        (data.bas_area, data.lvl_area_a, data.lvl_area_b, data.lvl_area_c, data.lan_area, data.auth_area,
         data.fix_area, data.fix_wrong_area, data.ext_area) = areas
        data.lan_priority = random.randint(90, 126)
        data.lan_metric = random.randint(100, 900)
        data.auth_hello_key = utils.random_password(10)
        data.auth_domain_key = utils.random_password(10)

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
        loopbacks = {}
        for area, offset in LVL_AREA_BLOCKS.items():
            third = 16 * SITE_NUMBER['lvl'] + offset
            link, lan, routers = LVL_AREA_MEMBERS[area]
            setattr(data.nets, f"lvl_area_{area}_block", _subnet(data.nets.instance, third, 22))
            setattr(data.nets, link, _subnet(data.nets.instance, third, 30))
            setattr(data.nets, lan, _subnet(data.nets.instance, third + 1))
            for router in routers:
                loopbacks[router] = _subnet(data.nets.instance, third + 2)
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        for net in LANS:
            network = getattr(data.nets, net)
            routers = [r for r, nets in ROUTER_IFACES.items() if net in nets]
            for k, router in enumerate(routers):
                setattr(data.ips, f"{router}_{net}", IPv4Interface((int(network.network_address) + 1 + k, 24)))
        for host, (net, _gw) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, host, IPv4Interface((int(network.network_address) + random.randint(10, 250), 24)))
        for router in ROUTER_IFACES:
            block = loopbacks.get(router) or getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo",
                    IPv4Interface((int(block.network_address) + router_number(router), 32)))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in ROUTER_IFACES:
        spec['image'] = sre_docker_image("routing-frr")
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
        default = IPv4Network("0.0.0.0/0")

        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, nets in ROUTER_IFACES.items():
            self.net_config[r] = [([getattr(d.ips, f"{r}_{net}")], []) for net in nets]
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(default, self.addr(gw, net))])]
        # the operator only knows the instance's networks behind ext_r1
        self.net_config[ISP] = [([getattr(d.ips, f"{ISP}_ext_wan")],
                                 [(d.nets.instance, self.addr('ext_r1', 'ext_wan'))])]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX; loopbacks rX-lo
        lines = []
        for r, nets in ROUTER_IFACES.items():
            for i, net in enumerate(nets):
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{self.addr(r, net)}\t{names}")
            lines.append(f"{self.lo(r)}\t{r}-lo")
        for h in HOSTS:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
        lines.append(f"{EXT_SERVER}\tinternet")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses and names -------------------------------------------------------

    def addr(self, machine: str, net: str) -> IPv4Address:
        """Address (without prefix) of *machine* on *net*."""
        return getattr(self.data.ips, f"{machine}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def sysid(self, router: str) -> str:
        """The system-id of *router*, made from its loopback address."""
        return isis_system_id_from_ipv4(self.lo(router))

    def net_title(self, router: str, area: str) -> str:
        """The NET of *router* in *area*."""
        return f"{area}.{self.sysid(router)}.00"

    def area_of(self, router: str) -> str:
        """The area of *router* in the reference solution."""
        d = self.data
        site = site_of(router)
        if site == 'lvl':
            return {1: d.lvl_area_a, 2: d.lvl_area_a, 3: d.lvl_area_b}.get(router_number(router), d.lvl_area_c)
        return getattr(d, f"{site}_area")

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Principe d'IS-IS"), tag="principle")
            + tr("""
**IS-IS** (*Intermediate System to Intermediate System*, norme ISO/IEC 10589, étendue à IP par la
RFC 1195) est, comme OSPF, un protocole de routage **intérieur** (IGP) à **état de liens** : chaque
routeur décrit ses voisins et ses préfixes dans des **LSP** (*Link State PDU*), les LSP sont
**inondées** à tous les routeurs, chacun possède la même base de données (LSDB) et calcule ses
routes avec l'algorithme de **Dijkstra** (SPF). Le vocabulaire vient de l'OSI : un routeur est un
**IS** (*Intermediate System*), un hôte un **ES** (*End System*), un paquet une **PDU**.

Deux particularités le distinguent d'OSPF :

- IS-IS **n'est pas transporté par IP** : ses PDU sont posées directement dans des trames Ethernet
  (encapsulation LLC 802.2, SAP `0xFE`, premier octet de la PDU `0x83`), envoyées à des adresses
  MAC multicast. Un routeur IS-IS n'a pas besoin d'adresse IP pour trouver ses voisins, et une
  machine d'un autre réseau ne peut pas lui envoyer de PDU ;
- ses PDU sont des listes de **TLV** (*Type, Length, Value*) : ajouter une fonction (IPv6,
  métriques larges, segment routing…) consiste à définir un TLV, que les routeurs plus anciens
  ignorent. IS-IS n'a pas eu besoin d'une nouvelle version pour IPv6.

Il est très utilisé par les opérateurs (cœurs de réseau, avec MPLS) et dans les centres de données.

| | OSPF (v2) | IS-IS |
|---|---|---|
| transport | IP, protocole 89 | trames de niveau 2 (LLC) |
| identifiant | router-id (32 bits) | system-id (48 bits), dans le NET |
| hiérarchie | aires autour de l'aire 0, ABR à cheval sur deux aires | niveaux 1 et 2, frontière des aires sur les liens |
| réseau à diffusion | DR et BDR, élection non préemptive | DIS, élection préemptive, sans secours |
| métrique par défaut | référence ÷ bande passante | 10 sur toutes les interfaces |
| extensions | nouveaux types de LSA, OSPFv3 pour IPv6 | nouveaux TLV, même protocole pour IPv6 |
| temporisateurs | identiques aux deux extrémités | chacun annonce le délai qu'il impose |
""")
            + info_subtitle(tr("Adresses : le NET"), tag="net")
            + tr("""
Un routeur IS-IS est identifié par son **NET** (*Network Entity Title*), une adresse OSI (NSAP)
écrite en hexadécimal par groupes séparés de points :

```
49.0001.0100.0003.1002.00
\\_____/ \\____________/ \\/
  aire     system-id   NSEL
```

- **l'aire** (*area address*, 1 à 13 octets) : ici `49.0001`. Son premier octet est l'**AFI** ;
  `49` désigne des adresses **privées** (l'équivalent de la RFC 1918), utilisées par presque tous
  les réseaux IS-IS ;
- **le system-id** (6 octets) : l'identifiant **unique** du routeur dans le domaine, l'équivalent
  du router-id d'OSPF ;
- **le NSEL** (1 octet) : toujours `00` pour un routeur.

Une convention répandue fabrique le system-id à partir de l'adresse de l'interface de bouclage :
chaque octet est écrit sur trois chiffres décimaux, puis les douze chiffres sont regroupés par
quatre : `10.0.31.2` → `010.000.031.002` → `0100.0003.1002`.

Un routeur peut avoir jusqu'à trois NET, avec le même system-id et des aires différentes (pour
renuméroter ou fusionner des aires sans coupure). Les commandes de FRR affichent les routeurs par
leur nom (TLV *dynamic hostname*) quand ils l'annoncent, sinon par leur system-id.
""")
            + info_subtitle(tr("PDU, TLV et inondation"), tag="pdus")
            + tr("""
| PDU | rôle |
|-----|------|
| **IIH** (*IS-IS Hello*) | découverte des voisins et maintien des adjacences : sur un réseau à diffusion un type par niveau (L1, L2), sur un lien point à point un seul |
| **LSP** (*Link State PDU*) | description d'un routeur : ses voisins avec la métrique, ses préfixes, ses aires, son nom… Identifiée par son **LSP-ID** : `system-id.pseudo-nœud-fragment`, par exemple `0100.0003.1002.00-00` |
| **CSNP** (*Complete Sequence Numbers PDU*) | la liste de toutes les LSP connues (identifiant, numéro de séquence), pour comparer les bases |
| **PSNP** (*Partial SNP*) | demande d'une LSP manquante, ou accusé de réception d'une LSP sur un lien point à point |

Une LSP porte un numéro de séquence (la plus récente l'emporte) et une durée de vie restante
(1200 s au plus) ; son auteur la rafraîchit avant qu'elle n'expire, et la régénère quand quelque
chose change (FRR attend jusqu'à 30 s entre deux générations d'une même LSP : un nouveau préfixe
peut mettre ce temps à apparaître chez les voisins). `show isis database` affiche la base :
la colonne `ATT/P/OL` donne trois bits de la LSP (sections @@ref:att@@ et @@ref:overload@@).

| TLV | contenu |
|-----|---------|
| 1 | adresses d'aire |
| 10 | authentification |
| 22 | voisins IS avec leur métrique (*extended IS reachability*) |
| 129 | protocoles supportés (NLPID : `0xCC` pour IPv4, `0x8E` pour IPv6) |
| 132 | adresses IPv4 de l'interface |
| 135 | préfixes IPv4 avec leur métrique (*extended IP reachability*) |
| 137 | nom du routeur (*dynamic hostname*) |
| 240 | état de l'adjacence sur un lien point à point (*three-way handshake*) |
""")
            + info_subtitle(tr("Adjacences"), tag="adjacency")
            + tr("""
Chaque interface où IS-IS est actif envoie des **IIH** à une adresse MAC multicast :
`01:80:c2:00:00:14` (IIH de niveau 1 sur un réseau à diffusion), `01:80:c2:00:00:15` (niveau 2),
`09:00:2b:00:00:05` (lien point à point). Deux routeurs forment une **adjacence** quand leurs IIH
sont compatibles : niveaux compatibles, une aire commune pour le niveau 1, même type de réseau,
même authentification, et des IIH qui passent. Sur un lien point à point, l'état passe de `Down` à
`Initializing` (j'entends le voisin) puis `Up` (il m'entend aussi).

### @@sec:timers@@ Temporisateurs

FRR envoie un IIH toutes les **3 s** (`isis hello-interval`) et déclare un voisin mort au bout de
`hello-interval × hello-multiplier` = 3 × 10 = **30 s** sans IIH. Ce délai (*holding time*) est
annoncé dans chaque IIH : c'est le voisin qui l'impose, et les deux extrémités n'ont pas besoin des
mêmes réglages (au contraire d'OSPF). `show isis neighbor` affiche le temps restant.

### @@sec:padding@@ Remplissage des IIH

IS-IS remplit ses IIH jusqu'à la MTU de l'interface (*hello padding* : avec une MTU de 1500, des
trames de 1500 octets). Une interface dont la MTU est plus petite jette ces trames : le routeur qui
a la petite MTU ne voit pas son voisin. Un écart de MTU est ainsi détecté dès la formation de
l'adjacence, avant qu'il ne coupe le trafic. Il apparaît **d'un seul côté** : le routeur qui a la
grande MTU reçoit les IIH (plus petites) de son voisin et l'affiche `Initializing` (ou le garde
`Up` si l'adjacence existait quand la MTU a changé), l'autre ne voit rien. Vérifiez toujours une
adjacence des deux côtés.
""")
            + info_subtitle(tr("Niveaux et aires"), tag="levels")
            + tr("""
Un domaine IS-IS a une hiérarchie à **deux niveaux** :

- le **niveau 1** (L1) : le routage à l'intérieur d'une **aire** ; un routeur L1 ne connaît que
  les routeurs et les préfixes de son aire ;
- le **niveau 2** (L2) : le routage entre les aires, la **dorsale** (*backbone*). L'ensemble des
  routeurs L2 doit être **connexe**.

Chaque routeur a un type (`is-type`) : `level-1`, `level-2-only` ou `level-1-2` (la valeur par
défaut de FRR). Un routeur L1/L2 tient **deux bases**, une par niveau, et fait deux calculs SPF ; il
remplit le rôle de l'ABR d'OSPF. Différence essentielle avec OSPF : **un routeur appartient tout
entier à une aire, la frontière entre les aires passe sur les liens**.

| adjacence | condition |
|-----------|-----------|
| niveau 1 | les deux routeurs font du L1 et ont **au moins une aire en commun** |
| niveau 2 | les deux routeurs font du L2, **quelles que soient leurs aires** |

Un routeur L1 et un routeur L1/L2 d'aires différentes ne forment donc **aucune** adjacence. Sur un
routeur L1/L2, `isis circuit-type level-1 | level-2-only | level-1-2` (mode interface) limite les
niveaux d'une interface : inutile d'envoyer des IIH de niveau 1 à un routeur qui ne fait que du
niveau 2, ou l'inverse.

### @@sec:att@@ Le bit ATT et la route par défaut

Un routeur L1 ne connaît pas les autres aires. Un routeur L1/L2 relié au niveau 2 positionne le
bit **ATT** (*attached*) dans sa LSP de niveau 1 (la norme le demande quand il joint une autre aire ;
FRR le fait dès qu'il a une adjacence de niveau 2). Les routeurs L1 de l'aire installent alors une
**route par défaut** vers le routeur L1/L2 le plus proche, avec pour métrique la distance jusqu'à
lui. C'est l'équivalent d'une aire *totally stubby* d'OSPF, et c'est le fonctionnement normal d'une
aire IS-IS.

Un routeur L1 qui a plusieurs sorties prend la plus proche, pas forcément celle qui mène au
meilleur chemin vers la destination. Pour l'éviter, un routeur L1/L2 peut injecter des préfixes L2
choisis dans le niveau 1 (*route leaking*, RFC 5302, avec un bit *up/down* qui empêche les
boucles) ; FRR ne le propose pas.

### @@sec:l1-to-l2@@ Les préfixes d'une aire au niveau 2

Dans l'autre sens, la norme veut qu'un routeur L1/L2 annonce au niveau 2 les préfixes qu'il a
appris au niveau 1 : le niveau 2 connaît ainsi toutes les aires. **FRR ne le fait pas** : un
routeur L1/L2 n'annonce au niveau 2 que ses propres réseaux, et les réseaux des routeurs de niveau
1 sont injoignables depuis les autres aires. Il faut lui faire annoncer les préfixes de son aire, de
préférence sous la forme d'un **résumé** : une route statique sans issue (`blackhole`) vers un
préfixe qui couvre toute l'aire, redistribuée au niveau 2 (section @@ref:external@@) :

```
ip route 10.0.36.0/22 blackhole
router isis CORE
 redistribute ipv4 static level-2
```

Les routeurs de niveau 2 lui envoient alors tout le trafic destiné à l'aire, et il l'achemine avec
ses routes de niveau 1, plus précises (la route `blackhole` ne sert qu'aux adresses de l'aire qui
n'existent pas). Le plan d'adressage doit s'y prêter : les réseaux d'une aire contigus, dans un
préfixe qui ne contient rien d'autre. Une route statique vers un seul réseau, par le routeur de
niveau 1 qui y mène, convient aussi.
""")
            + info_subtitle(tr("Réseaux à diffusion : le DIS"), tag="dis")
            + tr("""
Sur un réseau à diffusion où se trouvent plusieurs routeurs, IS-IS élit un **DIS** (*Designated
Intermediate System*), un par niveau :

- l'élection se fait sur la **priorité** de l'interface (`isis priority N [level-1 | level-2]`,
  de 0 à 127, **64** par défaut), puis sur l'adresse MAC (SNPA) la plus grande ;
- elle est **préemptive** : un routeur qui arrive avec une meilleure priorité devient DIS aussitôt
  (au contraire du DR d'OSPF), et il n'y a pas de DIS de secours ;
- **tous** les routeurs du réseau forment une adjacence avec tous les autres (pas d'équivalent des
  `DROther` restés en `2-Way` dans OSPF) ;
- le DIS crée un **pseudo-nœud** qui représente le réseau : une LSP dont l'octet de pseudo-nœud du
  LSP-ID n'est pas nul (`r2.4d-00` : le DIS est `r2`), qui liste les routeurs du réseau avec une
  métrique **0**. Chaque routeur du réseau ne déclare qu'un voisin pour ce réseau : le pseudo-nœud ;
- le DIS envoie un **CSNP** toutes les **10 s** : les autres comparent avec leur base et demandent
  par PSNP les LSP qui leur manquent.

Sur un lien qui ne relie que **deux** routeurs, l'élection et le pseudo-nœud ne servent à rien :
`isis network point-to-point` (aux **deux** extrémités) en fait un lien point à point — adjacence
plus rapide, base plus simple. Les deux extrémités doivent avoir le même type de réseau : un IIH
point à point reçu sur une interface à diffusion (ou l'inverse) est ignoré.
""")
            + info_subtitle(tr("Métriques"), tag="metrics")
            + tr("""
Le **coût** d'un chemin est la somme des métriques des interfaces de sortie traversées, plus la
métrique avec laquelle le préfixe de destination est annoncé (10 pour un réseau connecté). FRR
donne la métrique **10** à toute interface, quelle que soit sa vitesse : `isis metric N
[level-1 | level-2]` (mode interface) la change, sur une extrémité seulement — chaque sens d'un lien
a sa métrique.

| style | TLV | métrique d'une interface | métrique d'un chemin |
|-------|-----|--------------------------|----------------------|
| `narrow` (ISO 10589 d'origine) | 2 et 128 | 6 bits : **1 à 63** | 1023 au plus |
| `wide` (RFC 5305) | 22 et 135 | 24 bits : jusqu'à 16 777 215 | 32 bits |

FRR utilise le style **wide** par défaut (`metric-style wide` en mode `router isis` ; `transition`
émet les deux) : il refuse de passer en `narrow` tant qu'une interface a une métrique supérieure à
63. Tous les routeurs d'un domaine doivent comprendre le même style. À coût égal, une route a
plusieurs prochains sauts (ECMP). `show isis route` affiche le coût de chaque route ; dans le noyau
(`ip route`), les routes d'IS-IS portent `proto isis` et une métrique 20 sans rapport avec le coût.
""")
            + info_subtitle(tr("Le bit de surcharge"), tag="overload")
            + tr("""
Un routeur qui positionne le bit **OL** (*overload*) dans sa LSP (`set-overload-bit`, mode
`router isis`) n'est plus utilisé **comme transit** : les autres routeurs calculent leurs chemins
sans passer par lui. Ses propres préfixes (interface de bouclage, réseaux connectés) restent
joignables. On s'en sert pour retirer un routeur du trafic avant une maintenance, ou à son démarrage
le temps que BGP ait convergé (`set-overload-bit on-startup N`). Oublié après la maintenance, il
coupe tous les chemins qui passaient par ce routeur, alors que toutes les adjacences sont `Up`.
""")
            + info_subtitle(tr("Authentification"), tag="auth")
            + tr("""
IS-IS peut signer ses PDU avec un mot de passe, en clair (`clear`, lisible dans les trames) ou avec
**HMAC-MD5** (`md5`, RFC 5304), dans le TLV 10. Trois réglages indépendants :

| réglage (FRR) | mode | protège |
|---------------|------|---------|
| `isis password md5 SECRET` | interface | les **IIH** de l'interface : sans le bon mot de passe, pas d'adjacence |
| `area-password md5 SECRET` | `router isis` | les **LSP, CSNP et PSNP de niveau 1** (toute l'aire) |
| `domain-password md5 SECRET` | `router isis` | les **LSP, CSNP et PSNP de niveau 2** (tout le domaine) |

- Un routeur qui a un mot de passe rejette les PDU qui n'ont pas le bon. Un routeur **sans** mot de
  passe accepte les PDU signées : il voit son voisin (`Initializing`), qui, lui, ne le voit pas.
- Un routeur qui a un `domain-password` rejette les LSP de niveau 2 non signées : l'adjacence peut
  être `Up` des deux côtés alors que les bases ne se synchronisent pas, et des routes manquent.
""")
            + info_subtitle(tr("Routes externes"), tag="external")
            + tr("""
Un routeur IS-IS peut annoncer des routes venues d'ailleurs (routes statiques, réseaux connectés
hors IS-IS, autre protocole) :

```
router isis CORE
 redistribute ipv4 static level-2            # les routes statiques de FRR (« ip route … » dans vtysh)
 redistribute ipv4 connected level-2         # les réseaux connectés qui ne sont pas dans IS-IS
 default-information originate ipv4 level-2  # une route par défaut, s'il en a une
```

Les préfixes redistribués sont annoncés dans le TLV 135 comme les autres (avec la métrique 0 par
défaut, `metric N` pour la changer). `redistribute` n'annonce jamais la route par défaut : c'est le
rôle de `default-information originate` (`always` pour l'annoncer même sans route par défaut).
`redistribute ipv4 static` ne concerne que les routes statiques déclarées dans FRR, pas celles
ajoutées par `ip route add` (des routes du noyau).
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` installe dans le noyau
les routes choisies, `isisd` est le démon d'IS-IS (activé dans `/etc/frr/daemons` sur les routeurs
du TP). On le configure avec **`vtysh`** :

```
vtysh
configure terminal
 router isis CORE                        # le processus IS-IS, nommé CORE
  net 49.0001.0100.0003.1002.00
  is-type level-2-only
  exit
 interface eth1
  ip router isis CORE                    # IS-IS sur cette interface (le nom du processus)
  isis network point-to-point
  exit
 interface lo
  ip router isis CORE
  isis passive                           # annoncée, mais aucun IIH envoyé
  exit
 end
write                                    # sauvegarde dans /etc/frr/frr.conf
```

Une interface **passive** est annoncée dans IS-IS mais n'émet aucun IIH : c'est le réglage de
l'interface de bouclage et des réseaux d'hôtes. Une commande se supprime en la préfixant par `no`.
Une commande peut aussi être passée depuis le shell : `vtysh -c "show isis neighbor"`.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show isis summary` | system-id, NET, compteurs de PDU |
| `show isis interface [detail]` | les interfaces : type, niveaux, métrique, priorité, DIS, temporisateurs |
| `show isis neighbor [detail]` | les adjacences : niveau, état, temps restant, aires, DIS |
| `show isis database [detail]` | la base : les LSP et leurs bits ATT/P/OL, leur contenu avec `detail` |
| `show isis route` | les routes calculées, avec leur coût |
| `show isis topology` | l'arbre des plus courts chemins |
| `show ip route` | les routes de zebra (`I` pour IS-IS, distance 115) |
| `clear isis neighbor` | relance les adjacences |

Documentation : [FRR — IS-IS](https://docs.frrouting.org/en/latest/isisd.html).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `tcpdump -nei ethX isis` : les PDU IS-IS d'une interface (type, system-id, niveau, longueur) ;
- `ip route`, `traceroute -n IP` : les routes installées et le chemin réellement suivi ;
- `/var/log/frr/frr.log` : le journal des démons.

| symptôme | causes à vérifier |
|----------|-------------------|
| aucun voisin | IS-IS pas activé sur l'interface (`ip router isis`), interface passive, niveaux incompatibles, aires différentes pour le niveau 1, types de réseau différents (le journal dit `p2p hello on non p2p circuit`), mot de passe |
| voisin vu d'un seul côté (`Initializing`) | MTU différentes (remplissage des IIH), mot de passe configuré d'un seul côté |
| voisins `Up` mais routes manquantes | préfixe non annoncé (interface hors IS-IS), `domain-password` / `area-password` différents, LSP pas encore régénérée |
| trafic qui contourne un routeur | métriques, bit de surcharge (`OL` dans `show isis database`) |
| un routeur L1 ne joint pas les autres aires | pas de routeur L1/L2 relié au niveau 2 dans l'aire (pas de bit ATT), préfixes de l'aire non annoncés au niveau 2 |
""")
        )

    # -- configurations --------------------------------------------------------------

    def isis_lines(self, router: str, area: str, is_type: str = None, circuit_types: Dict[str, str] = None,
                   broadcast: tuple = (), interfaces: tuple = None, router_extra: tuple = (),
                   iface_extra: Dict[str, List[str]] = None) -> List[str]:
        """vtysh lines of a complete IS-IS configuration of *router* (usable in frr.conf and in a
        vtysh session): ``router isis`` with the NET and the level, then the interfaces — links
        point-to-point (except the networks of *broadcast*), host networks and loopback passive.
        *interfaces* restricts the configured networks (``None``: all of them)."""
        circuit_types = circuit_types or {}
        iface_extra = iface_extra or {}
        lines = [f"router isis {ISIS_NAME}", f"net {self.net_title(router, area)}"]
        if is_type:
            lines.append(f"is-type {is_type}")
        lines += list(router_extra) + ["exit"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            if net == 'ext_wan' or (interfaces is not None and net not in interfaces):
                continue
            name = f"eth{i}"
            lines += [f"interface {name}", f"ip router isis {ISIS_NAME}"]
            if net in LINKS and net not in broadcast:
                lines.append("isis network point-to-point")
            elif net in LANS and net != ROUTER_LAN:
                lines.append("isis passive")
            if net in circuit_types:
                lines.append(f"isis circuit-type {circuit_types[net]}")
            lines += iface_extra.get(name, []) + ["exit"]
        lines += ["interface lo", f"ip router isis {ISIS_NAME}", "isis passive", "exit"]
        return lines

    def _given_lines(self, router: str) -> List[str]:
        """The IS-IS configuration a router has at start (``[]`` for the routers the students
        configure)."""
        d = self.data
        if router in ('bas_r1', 'bas_r2'):
            return self.isis_lines(router, d.bas_area, "level-2-only")
        if router == 'lvl_r3':
            return self.isis_lines(router, d.lvl_area_b, "level-2-only")
        if router == 'lvl_r4':
            return self.isis_lines(router, d.lvl_area_c, "level-1-2",
                                   circuit_types={'lvl_l34': 'level-2-only', 'lvl_l45': 'level-1'},
                                   router_extra=("redistribute ipv4 static level-2",))
        if router == 'lvl_r5':
            return self.isis_lines(router, d.lvl_area_c, "level-1")
        if site_of(router) == 'lan':
            extra = {iface('lan_r1', ROUTER_LAN): [f"isis priority {LAN_R1_PRIORITY}"]} if router == 'lan_r1' else {}
            return self.isis_lines(router, d.lan_area, "level-2-only", iface_extra=extra)
        if router == 'auth_r1':
            return self.isis_lines(router, d.auth_area, "level-2-only")
        if router == 'auth_r2':
            return self.isis_lines(router, d.auth_area, "level-2-only",
                                   router_extra=(f"domain-password md5 {d.auth_domain_key}",),
                                   iface_extra={iface(router, 'auth_l12'): [f"isis password md5 {d.auth_hello_key}"]})
        if router == 'fix_r1':
            return self.isis_lines(router, d.fix_wrong_area, "level-1")
        if router == 'fix_r2':
            return self.isis_lines(router, d.fix_area, "level-1-2", router_extra=("redistribute ipv4 static level-2",))
        if router == 'fix_r3':
            return self.isis_lines(router, d.fix_area, "level-2-only", broadcast=('fix_l23',),
                                   router_extra=("set-overload-bit",))
        if router == 'fix_r4':
            return self.isis_lines(router, d.fix_area, "level-2-only")
        if site_of(router) == 'ext':
            return self.isis_lines(router, d.ext_area, "level-2-only")
        return []

    def static_lines(self, router: str) -> List[str]:
        """The FRR static routes *router* has at start: the external routes of ext_r1, the summary of
        area C announced in level 2 by lvl_r4, the network of fix_h1 announced in level 2 by fix_r2
        (FRR announces in level 2 only the own networks of a level 1-2 router)."""
        if router == 'ext_r1':
            isp = self.addr(ISP, 'ext_wan')
            return [f"ip route {EXT_PUBLIC} {isp}", f"ip route 0.0.0.0/0 {isp}"]
        if router == 'lvl_r4':
            return [f"ip route {self.net('lvl_area_c_block')} blackhole"]
        if router == 'fix_r2':
            return [f"ip route {self.net('fix_lan1')} {self.addr('fix_r1', 'fix_l12')}"]
        return []

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf of *router*."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {router}", "log file /var/log/frr/frr.log", "!"]
        statics = self.static_lines(router)
        if statics:
            lines += statics + ["!"]
        given = self._given_lines(router)
        # frr.conf syntax: one space of indentation inside a block
        for line in given:
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

    def solution_basics(self) -> Dict[str, List[str]]:
        d = self.data
        return {r: self.isis_lines(r, d.bas_area, "level-2-only") for r in ('bas_r3', 'bas_r4')}

    def solution_levels(self) -> Dict[str, List[str]]:
        d = self.data
        return {
            'lvl_r1': self.isis_lines('lvl_r1', d.lvl_area_a, "level-1"),
            'lvl_r2': [f"ip route {self.net('lvl_area_a_block')} blackhole"]
            + self.isis_lines('lvl_r2', d.lvl_area_a, circuit_types={'lvl_l12': 'level-1', 'lvl_l23': 'level-2-only'},
                              router_extra=("redistribute ipv4 static level-2",)),
        }

    def solution_lan(self) -> Dict[str, List[str]]:
        d = self.data
        return {
            'lan_r3': [f"interface {iface('lan_r3', ROUTER_LAN)}", f"isis priority {d.lan_priority}", "exit"],
            'lan_r1': [f"interface {iface('lan_r1', 'lan_l14')}", f"isis metric {d.lan_metric}", "exit",
                       f"router isis {ISIS_NAME}", "set-overload-bit", "exit"],
            'lan_r4': [f"interface {iface('lan_r4', 'lan_l14')}", f"isis metric {d.lan_metric}", "exit"],
        }

    def solution_auth(self) -> Dict[str, List[str]]:
        d = self.data
        return {'auth_r1': [f"interface {iface('auth_r1', 'auth_l12')}", f"isis password md5 {d.auth_hello_key}",
                            "exit", f"router isis {ISIS_NAME}", f"domain-password md5 {d.auth_domain_key}", "exit"]}

    def solution_fix(self) -> Dict[str, List[tuple]]:
        """Shell and vtysh commands of part 5: {router: [(kind, command)]}."""
        d = self.data
        return {
            'fix_r1': [('vtysh', [f"router isis {ISIS_NAME}", f"no net {self.net_title('fix_r1', d.fix_wrong_area)}",
                                  f"net {self.net_title('fix_r1', d.fix_area)}", "exit"])],
            'fix_r3': [('vtysh', [f"interface {iface('fix_r3', 'fix_l23')}", "isis network point-to-point", "exit",
                                  f"router isis {ISIS_NAME}", "no set-overload-bit", "exit"])],
            'fix_r4': [('sh', f"ip link set {iface('fix_r4', 'fix_l34')} mtu 1500")],
        }

    def solution_external(self) -> Dict[str, List[str]]:
        return {'ext_r1': [f"router isis {ISIS_NAME}", "redistribute ipv4 static level-2",
                           "default-information originate ipv4 level-2", "exit"]}

    # -- applying the solutions ----------------------------------------------------

    def _apply_vtysh(self, solution: Dict[str, List[str]], step: int = 1):
        for r, cmds in solution.items():
            self._vtysh(r, *cmds, step=step)

    def _apply_fix(self, step: int = 1):
        for r, items in self.solution_fix().items():
            for kind, cmd in items:
                if kind == 'sh':
                    self.cmd(r, cmd, step=step)
                else:
                    self._vtysh(r, *cmd, step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for r in ROUTER_IFACES:
            self.cmd(r, f"ip addr add {getattr(self.data.ips, f'{r}_lo')} dev lo")
        self.cmd(ISP, f"ip addr add {EXT_SERVER}/32 dev lo")
        self.cmd('fix_r4', f"ip link set {iface('fix_r4', 'fix_l34')} mtu {FIX_MTU}")
        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", FRR_DAEMONS, permissions=0o640, owner="frr:frr", step=2)
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(r, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (premier domaine)"))
    def solve_basics(self):
        self._apply_vtysh(self.solution_basics())
        self.cmd('bas_r3', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (niveaux et aires)"))
    def solve_levels(self):
        self._apply_vtysh(self.solution_levels())
        self.cmd('lvl_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (DIS, métriques, surcharge)"))
    def solve_lan(self):
        self._apply_vtysh(self.solution_lan())
        self.cmd('lan_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (authentification)"))
    def solve_auth(self):
        self._apply_vtysh(self.solution_auth())
        self.cmd('auth_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (dépannage)"))
    def solve_fix(self):
        self._apply_fix()
        self.cmd('fix_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Bonus : solution (routes externes)"))
    def solve_external(self):
        self._apply_vtysh(self.solution_external())
        self.cmd('ext_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for the LSPs).  Form questions are filled through cheat_answers."""
        self._apply_vtysh(self.solution_basics())
        self._apply_vtysh(self.solution_levels())
        self._apply_vtysh(self.solution_lan())
        self._apply_vtysh(self.solution_auth())
        self._apply_fix()
        self._apply_vtysh(self.solution_external())
        self.cmd('bas_r3', f"sleep {CONVERGE_WAIT}", step=2)


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


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    """The reference configuration of a part, as vtysh sessions (one block per router); the lines
    inside a ``router`` / ``interface`` block are indented."""
    blocks = []
    for router, cmds in solution.items():
        body, depth = ["configure terminal"], 1
        for c in cmds:
            if c == "exit":
                depth = max(1, depth - 1)
                body.append(" " * depth + c)
                continue
            body.append(" " * depth + c)
            if c.startswith(("router ", "interface ")):
                depth += 1
        blocks.append(f"`{router}` :\n\n```\n" + "\n".join(body + ["end", "write"]) + "\n```")
    return "\n\n".join(blocks)


def _running_config(grade: Grade0, router: str) -> Dict:
    """The parsed running configuration of *router*; the empty shape before the results (or when
    vtysh fails)."""
    return get_frr_running_config(grade, router, allow_error=True) or parse_frr_config("")


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest) -> bool:
        return eval_ping(self, src=src, dest=dest, count=3, deadline=5, allow_error=True)

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net, sysid = ns.lo, ns.addr, ns.net, ns.sysid

        def names(router: str) -> List[str]:
            """How a neighbour may be shown: its hostname or its system-id."""
            return [router, sysid(router)]

        def isis_route(routes: Dict[str, Dict], prefix) -> Dict:
            entry = routes.get(str(prefix))
            return entry if entry and is_isis_protocol(entry['protocol']) else {}

        def gateways(routes: Dict[str, Dict], prefix) -> List[str]:
            return [str(gw) for gw, _dev in isis_route(routes, prefix).get('nexthops', []) if gw]

        def has_net(cfg: Dict, router: str, area: str) -> bool:
            wanted = ns.net_title(router, area)
            return any((parse_isis_net(x) or {}).get('area') == area.lower()
                       and str(x).lower() == wanted.lower() for x in cfg['router_isis']['nets'])

        def isis_if(cfg: Dict, router: str, net_name: str) -> Dict:
            return ((cfg.get('interfaces') or {}).get(iface(router, net_name)) or {}).get('isis') or {}

        # ---------------- diagnostics kept in the archive -------------------------
        for r in ROUTER_IFACES:
            if r != 'auth_r2':
                self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        bas_nb = {r: get_isis_neighbors(self, r) for r in ('bas_r3', 'bas_r4')}
        bas_cfg = {r: _running_config(self, r) for r in ('bas_r3', 'bas_r4')}
        bas_if = {r: get_isis_interfaces(self, r) for r in ('bas_r3', 'bas_r4')}
        bas_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('bas_r1', 'bas_r2')}
        bas_ping = [self._ping('bas_h1', d.ips.bas_h4.ip), self._ping('bas_h4', d.ips.bas_h1.ip)]

        lvl_nb = {r: get_isis_neighbors(self, r) for r in ('lvl_r1', 'lvl_r2', 'lvl_r3')}
        lvl_cfg = {r: _running_config(self, r) for r in ('lvl_r1', 'lvl_r2')}
        lvl_k = get_kernel_routes(self, 'lvl_r1', allow_error=True)
        lvl_k3 = get_kernel_routes(self, 'lvl_r3', allow_error=True)
        lvl_ping = [self._ping('lvl_h1', d.ips.lvl_h5.ip), self._ping('lvl_h5', d.ips.lvl_h1.ip)]

        lan_if = {r: get_isis_interfaces(self, r) for r in ('lan_r1', 'lan_r3', 'lan_r4')}
        lan_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('lan_r1', 'lan_r2')}
        lan_db = get_isis_database(self, 'lan_r2')
        lan_ping_lo = self._ping('lan_h4', lo('lan_r1'))

        auth_nb = get_isis_neighbors(self, 'auth_r2')
        auth_k = get_kernel_routes(self, 'auth_r2', allow_error=True)
        auth_cfg = _running_config(self, 'auth_r1')
        auth_ping = [self._ping('auth_h1', d.ips.auth_h2.ip), self._ping('auth_h2', d.ips.auth_h1.ip)]

        fix_nb = {r: get_isis_neighbors(self, r) for r in ('fix_r1', 'fix_r2', 'fix_r3', 'fix_r4')}
        fix_db = get_isis_database(self, 'fix_r3')
        fix_ping = [self._ping('fix_h1', d.ips.fix_h4.ip), self._ping('fix_h4', d.ips.fix_h1.ip)]

        ext_k = get_kernel_routes(self, 'ext_r2', allow_error=True)
        ext_ping = self._ping('ext_h2', EXT_SERVER)

        def fix_both(a: str, b: str, link: str, level: int) -> bool:
            return (isis_adjacency_up(fix_nb[a], names(b), iface(a, link), level)
                    and isis_adjacency_up(fix_nb[b], names(a), iface(b, link), level))

        # ---------------- texts shared by the questions ---------------------------
        sites = [('bas', "1 — premier domaine", "`bas_r1` à `bas_r4`, les hôtes `bas_h1` et `bas_h4`"),
                 ('lvl', "2 — niveaux et aires", "`lvl_r1` à `lvl_r5`, les hôtes `lvl_h1` et `lvl_h5`"),
                 ('lan', "3 — DIS, métriques, surcharge", "`lan_r1` à `lan_r4`, les hôtes `lan_h2` et `lan_h4`"),
                 ('auth', "4 — authentification", "`auth_r1`, `auth_r2` (sans terminal), les hôtes `auth_h1` et "
                                                  "`auth_h2`"),
                 ('fix', "5 — dépannage", "`fix_r1` à `fix_r4`, les hôtes `fix_h1` et `fix_h4`"),
                 ('ext', "bonus — routes externes", "`ext_r1`, `ext_r2`, l'hôte `ext_h2`, `ext_isp` (sans terminal)")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + LANS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                members[n].append(f"`{r}` eth{i} (`{addr(r, n)}`)")
        for h, (n, _gw) in HOSTS.items():
            members[n].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        members['ext_wan'].append(f"`{ISP}` (`{addr(ISP, 'ext_wan')}`)")
        address_rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in list(LINKS) + LANS]
        address_rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                         + ", ".join(f"`{r}` `{lo(r)}`" for r in ROUTER_IFACES if site_of(r) == site) + " |"
                         for site in SITE_NUMBER]
        addressing = "\n".join(address_rows)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente IS-IS (NET, PDU, adjacences, niveaux et aires, DIS,
métriques, surcharge, authentification), sa configuration avec FRR et les commandes de diagnostic.

**Le réseau.** Il est fait de **six sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs font tourner **FRRouting** (FRR), avec le démon `isisd` activé : configurez-les avec
  `vtysh`. Le processus IS-IS s'appelle **`{name}`** partout (`router isis {name}`, `ip router isis
  {name}`).
- Toutes les adresses sont en place, y compris les adresses des interfaces de bouclage (`lo`, une
  /32 par routeur), ainsi que la route par défaut des hôtes. Les routeurs n'ont aucune route
  statique : seul IS-IS les renseigne.
- Les fichiers `/etc/hosts` contiennent les noms : `bas_r2-eth1` désigne l'adresse de l'interface
  `eth1` de `bas_r2`, `bas_r2-lo` son adresse de bouclage, `bas_h4` l'hôte.
- **Convention de ce TP** : le system-id de chaque routeur est fabriqué à partir de son adresse de
  bouclage (section @@ref:net@@), et le NSEL vaut `00`.

**Plan d'adressage.** Les liens entre routeurs sont des /30, les réseaux des hôtes (et `lan_seg`)
des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).
- Une adjacence se forme en quelques secondes ; un nouveau préfixe peut mettre jusqu'à 30 s à être
  annoncé (section @@ref:pdus@@).

**Évaluation.** Chaque évaluation lit vos réponses, l'état d'IS-IS sur les routeurs (adjacences,
interfaces, base de données, configuration), les tables de routage, et lance des `ping` entre les
hôtes.
""").format(site_rows=site_rows, addressing=addressing, name=ISIS_NAME)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_basics`, `solve_levels`, `solve_lan`, `solve_auth`, `solve_fix` et
`solve_external` (onglet *Appliquer une configuration*) appliquent la solution d'une seule partie et
remplissent ses formulaires. L'état `final` les applique toutes, attend {wait} s (régénération des
LSP) puis remplit tous les formulaires : une évaluation lancée dès son retour donne tous les points,
bonus compris.

Les pannes du site `fix` : `fix_r1` configuré dans l'aire `{wrong}` au lieu de `{area}` (niveau 1
seulement : aucune adjacence avec `fix_r2`) ; `fix_r3` sans `isis network point-to-point` vers
`fix_r2` ; MTU de {mtu} sur l'interface de `fix_r4` vers `fix_r3` ; `set-overload-bit` laissé sur
`fix_r3`.
""").format(wait=CONVERGE_WAIT, wrong=d.fix_wrong_area, area=d.fix_area, mtu=FIX_MTU)),
        )

        # =====================================================================
        # Part 1 — basics (bas)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("basics"), tr("Partie 1 — premier domaine IS-IS (site bas)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Premier domaine IS-IS"),
            description=tr("""
Les routeurs `bas_r1`, `bas_r2`, `bas_r3` et `bas_r4` forment un carré (liens `bas_l12`,
`bas_l23`, `bas_l34` et `bas_l14`) ; l'hôte `bas_h1` est derrière `bas_r1`, l'hôte `bas_h4` derrière
`bas_r4`. Tout le site est dans l'aire **`{area}`**, au **niveau 2 seulement**.

1. **Découverte.** `bas_r1` et `bas_r2` sont déjà configurés. Sur `bas_r1`, regardez la
   configuration (`show running-config`), puis `show isis summary`, `show isis interface detail`,
   `show isis neighbor detail`, `show isis database` et `show isis route` (sections @@ref:net@@ à
   @@ref:adjacency@@). Observez les trames avec `tcpdump -nei eth1` : adresses, encapsulation,
   longueur.
2. **Configuration.** Configurez IS-IS sur `bas_r3` et `bas_r4` sur le modèle de `bas_r1` : NET
   dans l'aire `{area}` avec le system-id tiré de l'adresse de bouclage, niveau 2 seulement, liens
   entre routeurs en **point à point**, interface de bouclage et réseau de `bas_h4` **passifs**
   (section @@ref:frr@@).
3. Vérifiez les adjacences (des deux côtés), la base de données, les routes de `bas_r2` vers le
   réseau `bas_lan4` (combien de prochains sauts ?), et que `bas_h1` joint `bas_h4`.
""").format(area=d.bas_area)
            + instructor(tr("""
**Solution.**

{solution}

`bas_r2` atteint `bas_lan4` ({lan4}) par deux chemins de même coût, 30 (10 jusqu'à `bas_r1` ou
`bas_r3`, 10 jusqu'à `bas_r4`, 10 pour le préfixe) : sa route a deux prochains sauts.

Évaluation : `bas_adj_r3`, `bas_adj_r4` (2 chacun : les deux adjacences de niveau 2 du routeur),
`bas_net` (2 : le NET de chaque routeur), `bas_level2` (1), `bas_p2p` (2), `bas_passive` (1 :
`lo` des deux routeurs et `eth0` de `bas_r4`), `bas_loopbacks` (1 : `bas_r1` a une route IS-IS vers les
deux adresses de bouclage), `bas_ping` (3), `bas_ecmp` (2 : deux prochains sauts sur `bas_r2`).
""").format(solution=_vtysh_text(ns.solution_basics()), lan4=net('bas_lan4'))),
        )
        cheat_bas = {'sysid': sysid('bas_r3'), 'hold': '30', 'metric': '20', 'afi': '49',
                     'transport': 'llc', 'mac': '09:00:2b:00:00:05'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site bas"),
            description=tr("""
- system-id de `bas_r3` (format `xxxx.xxxx.xxxx`) : @@{sysid:[0-9a-fA-F.]+}@@
- premier octet du NET qui indique une adresse privée : @@{afi:[0-9]+}@@
- délai (en secondes) au bout duquel `bas_r1` déclare `bas_r2` mort s'il ne reçoit plus rien :
  @@{hold:[0-9]+}@@
- coût de la route de `bas_r1` vers le réseau `bas_lan4` (`show isis route`) : @@{metric:[0-9]+}@@
- une PDU IS-IS est transportée dans :
  @@{transport:>une trame Ethernet (LLC), sans IP>>>llc|un paquet IP, protocole 89>>>ip89|un datagramme UDP, port 520>>>udp520|un segment TCP, port 179>>>tcp179}@@
- adresse MAC de destination des IIH sur un lien point à point :
  @@{mac:>09:00:2b:00:00:05>>>09:00:2b:00:00:05|01:80:c2:00:00:14>>>01:80:c2:00:00:14|01:80:c2:00:00:15>>>01:80:c2:00:00:15|ff:ff:ff:ff:ff:ff>>>ff:ff:ff:ff:ff:ff}@@
""")
            + instructor(tr("""
**Solution.** System-id de `bas_r3` : **`{sysid}`** (adresse de bouclage `{lo}`) ; **49** ;
**30** s (IIH toutes les 3 s, multiplicateur 10 : `Expires in` dans `show isis neighbor detail`,
`Holdtime` dans `show isis neighbor`) ; coût **20** (10 jusqu'à `bas_r4` + 10 pour le préfixe) ;
**une trame Ethernet (LLC)** (`tcpdump` : `LLC, dsap OSI (0xfe)`, `OSI NLPID IS-IS (0x83)`) ;
**`09:00:2b:00:00:05`**.

Évaluation : `bas_q_sysid`, `bas_q_afi`, `bas_q_hold`, `bas_q_metric` (1 chacun) et, pour l'enseignant
seulement (choix dans une liste), `bas_q_transport`, `bas_q_mac` (1 chacun).
""").format(sysid=sysid('bas_r3'), lo=lo('bas_r3'))),
            cheat_answers={"final": cheat_bas, "solve_basics": cheat_bas},
        )
        adj_r3 = [isis_adjacency_up(bas_nb['bas_r3'], names('bas_r2'), iface('bas_r3', 'bas_l23'), 2),
                  isis_adjacency_up(bas_nb['bas_r3'], names('bas_r4'), iface('bas_r3', 'bas_l34'), 2)]
        adj_r4 = [isis_adjacency_up(bas_nb['bas_r4'], names('bas_r3'), iface('bas_r4', 'bas_l34'), 2),
                  isis_adjacency_up(bas_nb['bas_r4'], names('bas_r1'), iface('bas_r4', 'bas_l14'), 2)]
        self.add_grade_element(
            title=no_tr("bas_adj_r3"), max_grade=2, grade_part=part1, grade=sum(adj_r3),
            description=tr("adjacences de bas_r3 avec bas_r2 et bas_r4"),
        )
        self.add_grade_element(
            title=no_tr("bas_adj_r4"), max_grade=2, grade_part=part1, grade=sum(adj_r4),
            description=tr("adjacences de bas_r4 avec bas_r3 et bas_r1"),
        )
        self.add_grade_element(
            title=no_tr("bas_net"), max_grade=2, grade_part=part1,
            grade=sum(int(has_net(bas_cfg[r], r, d.bas_area)) for r in ('bas_r3', 'bas_r4')),
            description=tr("NET de bas_r3 et de bas_r4"),
        )
        self.add_grade_element(
            title=no_tr("bas_level2"), max_grade=1, grade_part=part1,
            grade=int(all(bas_cfg[r]['router_isis']['present']
                          and bas_cfg[r]['router_isis']['is_type'] == 'level-2-only' for r in ('bas_r3', 'bas_r4'))),
            description=tr("bas_r3 et bas_r4 au niveau 2 seulement"),
        )
        p2p = [all((bas_if[r].get(iface(r, n)) or {}).get('type') == 'p2p'
                   for n in ROUTER_IFACES[r] if n in LINKS) for r in ('bas_r3', 'bas_r4')]
        self.add_grade_element(
            title=no_tr("bas_p2p"), max_grade=2, grade_part=part1, grade=sum(p2p),
            description=tr("liens point à point sur bas_r3 et bas_r4"),
        )
        passive = [(bas_if['bas_r3'].get('lo') or {}).get('passive'), (bas_if['bas_r4'].get('lo') or {}).get('passive'),
                   (bas_if['bas_r4'].get(iface('bas_r4', 'bas_lan4')) or {}).get('passive')]
        self.add_grade_element(
            title=no_tr("bas_passive"), max_grade=1, grade_part=part1, grade=int(all(passive)),
            description=tr("interfaces passives de bas_r3 et bas_r4"),
        )
        self.add_grade_element(
            title=no_tr("bas_loopbacks"), max_grade=1, grade_part=part1,
            grade=int(all(isis_route(bas_k['bas_r1'], f"{lo(r)}/32") for r in ('bas_r3', 'bas_r4'))),
            description=tr("adresses de bouclage de bas_r3 et bas_r4 annoncées"),
        )
        self.add_grade_element(
            title=no_tr("bas_ping"), max_grade=3, grade_part=part1, grade=3 * int(all(bas_ping)),
            description=tr("bas_h1 et bas_h4 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("bas_ecmp"), max_grade=2, grade_part=part1,
            grade=2 * int(sorted(gateways(bas_k['bas_r2'], net('bas_lan4')))
                          == sorted([str(addr('bas_r1', 'bas_l12')), str(addr('bas_r3', 'bas_l23'))])),
            description=tr("deux chemins de même coût de bas_r2 vers bas_lan4"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_sysid"), max_grade=1, grade_part=part1,
            grade=int(normalize_system_id(q1.get('sysid')) == sysid('bas_r3')), description=tr("system-id de bas_r3"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_afi"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('afi')) == 49),
            description=tr("AFI des adresses privées"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_hold"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('hold')) == 30),
            description=tr("délai de détection d'un voisin"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_metric"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('metric')) == 20),
            description=tr("coût d'une route"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_transport"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('transport')) == cheat_bas['transport']), description=tr("transport d'IS-IS"),
        )
        self.add_grade_element(
            title=no_tr("bas_q_mac"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('mac')) == cheat_bas['mac']), description=tr("adresse MAC des IIH point à point"),
        )

        # =====================================================================
        # Part 2 — levels and areas (lvl)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("levels"), tr("Partie 2 — niveaux et aires (site lvl)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Niveaux et aires"),
            description=tr("""
Les routeurs `lvl_r1` à `lvl_r5` forment une ligne ; l'hôte `lvl_h1` est derrière `lvl_r1`,
l'hôte `lvl_h5` derrière `lvl_r5`. Le site compte trois aires (section @@ref:levels@@) :

| routeur | aire | type | état au départ |
|---------|------|------|----------------|
| `lvl_r1` | `{a}` | niveau 1 | rien de configuré |
| `lvl_r2` | `{a}` | niveaux 1 et 2 | rien de configuré |
| `lvl_r3` | `{b}` | niveau 2 seulement | configuré |
| `lvl_r4` | `{c}` | niveaux 1 et 2 | configuré |
| `lvl_r5` | `{c}` | niveau 1 | configuré |

Les réseaux de l'aire `{a}` sont tous dans `{block_a}`, ceux de l'aire `{c}` dans `{block_c}`.

1. Sur `lvl_r5`, regardez la base de données (`show isis database`), les routes (`show isis route`,
   `ip route`) et les bits `ATT/P/OL` : comment `lvl_r5` joint-il les autres aires ? Sur `lvl_r4`,
   regardez la configuration (`show running-config`) : comment l'aire `{c}` est-elle annoncée au
   niveau 2 (section @@ref:l1-to-l2@@) ?
2. Configurez `lvl_r1` (niveau 1, aire `{a}`) et `lvl_r2` (niveaux 1 et 2, aire `{a}`) : NET tirés
   des adresses de bouclage, liens point à point, interfaces de bouclage et réseau de `lvl_h1`
   passifs. Sur `lvl_r2`, limitez l'interface vers `lvl_r1` au **niveau 1** et l'interface vers
   `lvl_r3` au **niveau 2** (`isis circuit-type`).
3. Comme `lvl_r4` pour l'aire `{c}`, faites annoncer par `lvl_r2` au niveau 2 le résumé de l'aire
   `{a}`.
4. Vérifiez le niveau des adjacences de `lvl_r2`, les deux bases de `lvl_r2`, la table de routage
   de `lvl_r1` (que sait-il de l'aire `{c}` ?), celle de `lvl_r3`, et que `lvl_h1` joint `lvl_h5`.
""").format(a=d.lvl_area_a, b=d.lvl_area_b, c=d.lvl_area_c, block_a=net('lvl_area_a_block'),
            block_c=net('lvl_area_c_block'))
            + instructor(tr("""
**Solution.**

{solution}

`lvl_r1` (niveau 1) n'a, en dehors de son aire, qu'une route par défaut vers `lvl_r2`, installée à
cause du bit ATT de la LSP de niveau 1 de `lvl_r2`. `lvl_r2` et `lvl_r3` forment une adjacence de
niveau 2 bien que leurs aires diffèrent. FRR n'annonce pas au niveau 2 les préfixes appris au niveau
1 : sans le résumé redistribué par `lvl_r2`, `lvl_r3` et `lvl_r4` ne connaissent pas `lvl_lan1`, et
les réponses de `lvl_h5` se perdent.

Évaluation : `lvl_r1_config` (2 : type et NET), `lvl_r2_config` (2 : type et NET), `lvl_adj_l1` (2 :
`lvl_r1` – `lvl_r2` au niveau 1 seulement, vu des deux côtés), `lvl_adj_l2` (2 : `lvl_r2` – `lvl_r3` au
niveau 2 seulement, vu des deux côtés), `lvl_circuit_type` (2), `lvl_summary` (2 : route IS-IS de
`lvl_r3` vers `{block_a}` par `lvl_r2`), `lvl_default` (3 : route par défaut d'IS-IS sur `lvl_r1` vers
`lvl_r2`), `lvl_l1_only` (1 : pas de route précise vers `lvl_lan5` sur `lvl_r1`, compté avec la route
par défaut), `lvl_ping` (3).
""").format(solution=_vtysh_text(ns.solution_levels()), block_a=net('lvl_area_a_block'))),
        )
        cheat_lvl = {'bit': 'att', 'l2_lsps': '3', 'default_metric': '10', 'databases': '2', 'l1_areas': 'no'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site lvl"),
            description=tr("""
- bit de la LSP de niveau 1 de `lvl_r2` qui fait installer à `lvl_r1` une route par défaut :
  @@{bit:>ATT>>>att|P>>>p|OL>>>ol}@@
- nombre de bases de données (une par niveau) que tient `lvl_r2` : @@{databases:[0-9]+}@@
- nombre de LSP dans la base de niveau 2 de `lvl_r2` (aucun pseudo-nœud sur ce site) :
  @@{l2_lsps:[0-9]+}@@
- coût de la route par défaut de `lvl_r1` (`show isis route`) : @@{default_metric:[0-9]+}@@
- deux routeurs de niveau 1 d'aires différentes forment une adjacence :
  @@{l1_areas:>oui>>>yes|non>>>no|seulement sur un lien point à point>>>p2p}@@
""")
            + instructor(tr("""
**Solution.** **ATT** ; **2** bases ; **3** LSP de niveau 2 (`lvl_r2`, `lvl_r3`, `lvl_r4` : les
routeurs de niveau 2) ; coût **10** (la distance jusqu'à `lvl_r2`) ; **non**.

Évaluation : `lvl_q_databases`, `lvl_q_l2_lsps`, `lvl_q_default_metric` (1 chacun) et, pour
l'enseignant seulement, `lvl_q_bit`, `lvl_q_l1_areas` (1 chacun).
""")),
            cheat_answers={"final": cheat_lvl, "solve_levels": cheat_lvl},
        )
        r1c, r2c = lvl_cfg['lvl_r1'], lvl_cfg['lvl_r2']
        self.add_grade_element(
            title=no_tr("lvl_r1_config"), max_grade=2, grade_part=part2,
            grade=int(r1c['router_isis']['present'] and r1c['router_isis']['is_type'] == 'level-1')
            + int(has_net(r1c, 'lvl_r1', d.lvl_area_a)),
            description=tr("type et NET de lvl_r1"),
        )
        self.add_grade_element(
            title=no_tr("lvl_r2_config"), max_grade=2, grade_part=part2,
            grade=int(r2c['router_isis']['present'] and r2c['router_isis']['is_type'] in (None, 'level-1-2'))
            + int(has_net(r2c, 'lvl_r2', d.lvl_area_a)),
            description=tr("type et NET de lvl_r2"),
        )
        l1 = [isis_adjacency_levels(lvl_nb['lvl_r2'], names('lvl_r1'), iface('lvl_r2', 'lvl_l12')) == 1,
              isis_adjacency_levels(lvl_nb['lvl_r1'], names('lvl_r2'), iface('lvl_r1', 'lvl_l12')) == 1]
        self.add_grade_element(
            title=no_tr("lvl_adj_l1"), max_grade=2, grade_part=part2, grade=2 * int(all(l1)),
            description=tr("adjacence de niveau 1 entre lvl_r1 et lvl_r2"),
        )
        l2 = [isis_adjacency_levels(lvl_nb['lvl_r2'], names('lvl_r3'), iface('lvl_r2', 'lvl_l23')) == 2,
              isis_adjacency_levels(lvl_nb['lvl_r3'], names('lvl_r2'), iface('lvl_r3', 'lvl_l23')) == 2]
        self.add_grade_element(
            title=no_tr("lvl_adj_l2"), max_grade=2, grade_part=part2, grade=2 * int(all(l2)),
            description=tr("adjacence de niveau 2 entre lvl_r2 et lvl_r3"),
        )
        self.add_grade_element(
            title=no_tr("lvl_circuit_type"), max_grade=2, grade_part=part2,
            grade=int(isis_if(r2c, 'lvl_r2', 'lvl_l12').get('circuit_type') == 'level-1')
            + int(isis_if(r2c, 'lvl_r2', 'lvl_l23').get('circuit_type') == 'level-2-only'),
            description=tr("niveaux des interfaces de lvl_r2"),
        )
        self.add_grade_element(
            title=no_tr("lvl_summary"), max_grade=2, grade_part=part2,
            grade=2 * int(gateways(lvl_k3, net('lvl_area_a_block')) == [str(addr('lvl_r2', 'lvl_l23'))]),
            description=tr("l'aire de lvl_r1 et lvl_r2 annoncée au niveau 2"),
        )
        default_ok = gateways(lvl_k, "0.0.0.0/0") == [str(addr('lvl_r2', 'lvl_l12'))]
        self.add_grade_element(
            title=no_tr("lvl_default"), max_grade=3, grade_part=part2, grade=3 * int(default_ok),
            description=tr("route par défaut de lvl_r1 vers lvl_r2"),
        )
        self.add_grade_element(
            title=no_tr("lvl_l1_only"), max_grade=1, grade_part=part2,
            grade=int(default_ok and str(net('lvl_lan5')) not in lvl_k),
            description=tr("lvl_r1 ne connaît pas les préfixes des autres aires"),
        )
        self.add_grade_element(
            title=no_tr("lvl_ping"), max_grade=3, grade_part=part2, grade=3 * int(all(lvl_ping)),
            description=tr("lvl_h1 et lvl_h5 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("lvl_q_databases"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('databases')) == 2),
            description=tr("bases d'un routeur L1/L2"),
        )
        self.add_grade_element(
            title=no_tr("lvl_q_l2_lsps"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('l2_lsps')) == 3),
            description=tr("LSP de niveau 2"),
        )
        self.add_grade_element(
            title=no_tr("lvl_q_default_metric"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get('default_metric')) == 10), description=tr("coût de la route par défaut"),
        )
        self.add_grade_element(
            title=no_tr("lvl_q_bit"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('bit')) == 'att'), description=tr("bit ATT"),
        )
        self.add_grade_element(
            title=no_tr("lvl_q_l1_areas"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get('l1_areas')) == 'no'), description=tr("niveau 1 et aires"),
        )

        # =====================================================================
        # Part 3 — DIS, metrics, overload (lan)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("lan"), tr("Partie 3 — DIS, métriques et surcharge (site lan)"))
        seg = ROUTER_LAN
        self.question_dummy(
            section=self.section(0),
            title=tr("DIS, métriques et surcharge"),
            description=tr("""
`lan_r1`, `lan_r2` et `lan_r3` partagent le réseau à diffusion `lan_seg` ; `lan_r4` est relié à
`lan_r1` (lien `lan_l14`) et à `lan_r3` (lien `lan_l34`). L'hôte `lan_h2` est derrière `lan_r2`,
l'hôte `lan_h4` derrière `lan_r4`. IS-IS fonctionne déjà partout (aire `{area}`, niveau 2).

1. **Le DIS** (section @@ref:dis@@). Sur `lan_r2`, trouvez le DIS de `lan_seg` (`show isis
   interface detail`, `show isis neighbor detail`) et le pseudo-nœud dans la base. Faites de
   `lan_r3` le DIS de `lan_seg` en donnant à son interface la priorité **{prio}**. Que devient le
   pseudo-nœud ?
2. **Les métriques** (section @@ref:metrics@@). Combien `lan_r2` a-t-il de chemins vers
   `lan_lan4` ? Donnez au lien `lan_l14` la métrique **{metric}**, à ses **deux** extrémités, puis
   regardez à nouveau les routes de `lan_r1` et de `lan_r2` vers `lan_lan4`.
3. **La surcharge** (section @@ref:overload@@). `lan_r1` doit partir en maintenance : mettez-le en
   surcharge. Vérifiez dans la base de `lan_r2` le bit `OL`, et que `lan_h4` joint encore
   l'adresse de bouclage de `lan_r1`.
""").format(area=d.lan_area, prio=d.lan_priority, metric=d.lan_metric)
            + instructor(tr("""
**Solution.**

{solution}

Au départ `lan_r1` est le DIS (priorité {r1prio}) ; avec la priorité {prio}, `lan_r3` le devient
aussitôt (élection préemptive) : le pseudo-nœud `lan_r1.xx-00` est purgé, `lan_r3.yy-00` le
remplace. Avant le changement de métrique, `lan_r2` a deux chemins de coût 30 vers `lan_lan4` (par
`lan_r1` et par `lan_r3`) ; ensuite, `lan_r1` lui-même passe par `lan_seg` et `lan_r3` (coût 30,
contre {via_l14} par `lan_l14`). La surcharge de `lan_r1` ne change rien à ses propres préfixes.

Évaluation : `lan_dis` (3), `lan_priority` (2), `lan_metric` (2 : une extrémité chacun),
`lan_r1_path` (2 : `lan_r1` vers `lan_lan4` par `lan_r3`), `lan_r2_path` (2 : un seul chemin, par
`lan_r3`), `lan_overload` (3 : bit OL de la LSP de `lan_r1` dans la base de `lan_r2`),
`lan_overload_own` (1 : `lan_h4` joint `lan_r1-lo`, compté avec le bit OL).
""").format(solution=_vtysh_text(ns.solution_lan()), r1prio=LAN_R1_PRIORITY, prio=d.lan_priority,
            via_l14=d.lan_metric + 10)),
        )
        cheat_lan = {'csnp': '10', 'preemptive': 'yes', 'metric': '30', 'narrow': '63', 'pseudonode': '0'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site lan"),
            description=tr("""
- intervalle (en secondes) entre deux CSNP du DIS : @@{csnp:[0-9]+}@@
- un routeur qui arrive avec une meilleure priorité devient DIS sans attendre :
  @@{preemptive:>oui>>>yes|non, il faut relancer IS-IS sur le DIS>>>no|seulement au niveau 1>>>level1}@@
- métrique, dans la LSP du pseudo-nœud, des liens vers les routeurs du réseau : @@{pseudonode:[0-9]+}@@
- coût de la route de `lan_r1` vers `lan_lan4` après le changement de métrique : @@{metric:[0-9]+}@@
- plus grande métrique d'interface possible avec `metric-style narrow` : @@{narrow:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **10** s ; **oui** ; **0** ; **30** (`lan_seg` 10 + `lan_l34` 10 + préfixe 10) ;
**63** (6 bits).

Évaluation : `lan_q_csnp`, `lan_q_pseudonode`, `lan_q_metric`, `lan_q_narrow` (1 chacun) et, pour
l'enseignant seulement, `lan_q_preemptive` (1).
""")),
            cheat_answers={"final": cheat_lan, "solve_lan": cheat_lan},
        )
        r3seg = (lan_if['lan_r3'].get(iface('lan_r3', seg)) or {}).get('levels', {}).get(2) or {}
        self.add_grade_element(
            title=no_tr("lan_dis"), max_grade=3, grade_part=part3, grade=3 * int(r3seg.get('is_dis') is True),
            description=tr("lan_r3 est le DIS de lan_seg"),
        )
        self.add_grade_element(
            title=no_tr("lan_priority"), max_grade=2, grade_part=part3,
            grade=2 * int(r3seg.get('priority') == d.lan_priority), description=tr("priorité de lan_r3"),
        )
        metrics = [((lan_if[r].get(iface(r, 'lan_l14')) or {}).get('levels', {}).get(2) or {}).get('metric')
                   for r in ('lan_r1', 'lan_r4')]
        self.add_grade_element(
            title=no_tr("lan_metric"), max_grade=2, grade_part=part3,
            grade=sum(int(m == d.lan_metric) for m in metrics), description=tr("métrique de lan_l14"),
        )
        r3_on_seg = str(addr('lan_r3', seg))
        self.add_grade_element(
            title=no_tr("lan_r1_path"), max_grade=2, grade_part=part3,
            grade=2 * int(gateways(lan_k['lan_r1'], net('lan_lan4')) == [r3_on_seg]),
            description=tr("lan_r1 joint lan_lan4 par lan_r3"),
        )
        self.add_grade_element(
            title=no_tr("lan_r2_path"), max_grade=2, grade_part=part3,
            grade=2 * int(gateways(lan_k['lan_r2'], net('lan_lan4')) == [r3_on_seg]),
            description=tr("un seul chemin de lan_r2 vers lan_lan4"),
        )
        overload = any(lsp['ol'] for lsp in isis_lsps_of(lan_db, 2, names('lan_r1'), pseudonode=False))
        self.add_grade_element(
            title=no_tr("lan_overload"), max_grade=3, grade_part=part3, grade=3 * int(overload),
            description=tr("lan_r1 en surcharge"),
        )
        self.add_grade_element(
            title=no_tr("lan_overload_own"), max_grade=1, grade_part=part3, grade=int(overload and lan_ping_lo),
            description=tr("lan_r1 reste joignable en surcharge"),
        )
        self.add_grade_element(
            title=no_tr("lan_q_csnp"), max_grade=1, grade_part=part3, grade=int(_int(q3.get('csnp')) == 10),
            description=tr("intervalle des CSNP"),
        )
        self.add_grade_element(
            title=no_tr("lan_q_pseudonode"), max_grade=1, grade_part=part3,
            grade=int(_int(q3.get('pseudonode')) == 0), description=tr("métrique du pseudo-nœud"),
        )
        self.add_grade_element(
            title=no_tr("lan_q_metric"), max_grade=1, grade_part=part3, grade=int(_int(q3.get('metric')) == 30),
            description=tr("coût après le changement de métrique"),
        )
        self.add_grade_element(
            title=no_tr("lan_q_narrow"), max_grade=1, grade_part=part3, grade=int(_int(q3.get('narrow')) == 63),
            description=tr("métrique narrow maximale"),
        )
        self.add_grade_element(
            title=no_tr("lan_q_preemptive"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('preemptive')) == 'yes'), description=tr("élection préemptive"),
        )

        # =====================================================================
        # Part 4 — authentication (auth)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("auth"), tr("Partie 4 — authentification (site auth)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Authentification"),
            description=tr("""
`auth_r1` et `auth_r2` sont reliés par le lien `auth_l12` ; l'hôte `auth_h1` est derrière
`auth_r1`, l'hôte `auth_h2` derrière `auth_r2`. IS-IS est configuré sur les deux routeurs (aire
`{area}`, niveau 2), mais `auth_r2`, géré par une autre équipe (pas de terminal), exige une
authentification (section @@ref:auth@@) :

- les IIH du lien `auth_l12` sont signés avec HMAC-MD5 et le mot de passe **`{hello}`** ;
- les LSP, CSNP et PSNP de niveau 2 sont signées avec HMAC-MD5 et le mot de passe **`{domain}`**.

1. Regardez les voisins de `auth_r1` : que voit-il de `auth_r2` ? Pourquoi `auth_h1` ne joint-il pas
   `auth_h2` ?
2. Configurez l'authentification des IIH sur l'interface de `auth_r1`, puis vérifiez à nouveau le
   voisinage et la base de données de `auth_r1`. Que manque-t-il encore ?
3. Configurez le mot de passe des PDU de niveau 2 et vérifiez que `auth_h1` joint `auth_h2`.
""").format(area=d.auth_area, hello=d.auth_hello_key, domain=d.auth_domain_key)
            + instructor(tr("""
**Solution.**

{solution}

Au départ, `auth_r1` (sans mot de passe) accepte les IIH signés de `auth_r2` et l'affiche
`Initializing`, mais `auth_r2` rejette les IIH non signés de `auth_r1` : il ne le voit pas. Avec le seul
mot de passe des IIH, l'adjacence est `Up` des deux côtés et `auth_r1` apprend les préfixes de
`auth_r2`, mais `auth_r2` rejette les LSP non signées de `auth_r1` : il n'a pas de route vers
`auth_lan1`.

Évaluation : `auth_adj` (4 : l'adjacence vue par `auth_r2`), `auth_lsdb` (3 : `auth_r2` a une route
IS-IS vers `auth_lan1`), `auth_md5` (2 : les deux mots de passe en `md5` sur `auth_r1`), `auth_ping`
(1).
""").format(solution=_vtysh_text(ns.solution_auth()))),
        )
        cheat_auth = {'tlv': '10', 'domain': 'l2_lsp_snp'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site auth"),
            description=tr("""
- numéro du TLV qui porte l'authentification : @@{tlv:[0-9]+}@@
- `domain-password` protège :
  @@{domain:>les LSP, CSNP et PSNP de niveau 2>>>l2_lsp_snp|les IIH de toutes les interfaces>>>iih|les LSP de niveau 1>>>l1_lsp|tout le trafic IP entre les routeurs>>>ip}@@
""")
            + instructor(tr("""
**Solution.** TLV **10** ; **les LSP, CSNP et PSNP de niveau 2**.

Évaluation : `auth_q_tlv` (1) et, pour l'enseignant seulement, `auth_q_domain` (1).
""")),
            cheat_answers={"final": cheat_auth, "solve_auth": cheat_auth},
        )
        self.add_grade_element(
            title=no_tr("auth_adj"), max_grade=4, grade_part=part4,
            grade=4 * int(isis_adjacency_up(auth_nb, names('auth_r1'), iface('auth_r2', 'auth_l12'), 2)),
            description=tr("adjacence vue par auth_r2"),
        )
        self.add_grade_element(
            title=no_tr("auth_lsdb"), max_grade=3, grade_part=part4,
            grade=3 * int(bool(isis_route(auth_k, net('auth_lan1')))),
            description=tr("auth_r2 accepte les LSP de auth_r1"),
        )
        hello_pw = isis_if(auth_cfg, 'auth_r1', 'auth_l12').get('password') or {}
        domain_pw = auth_cfg['router_isis'].get('domain_password') or {}
        self.add_grade_element(
            title=no_tr("auth_md5"), max_grade=2, grade_part=part4,
            grade=int(hello_pw.get('type') == 'md5') + int(domain_pw.get('type') == 'md5'),
            description=tr("mots de passe md5 sur auth_r1"),
        )
        self.add_grade_element(
            title=no_tr("auth_ping"), max_grade=1, grade_part=part4, grade=int(all(auth_ping)),
            description=tr("auth_h1 et auth_h2 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("auth_q_tlv"), max_grade=1, grade_part=part4, grade=int(_int(q4.get('tlv')) == 10),
            description=tr("TLV d'authentification"),
        )
        self.add_grade_element(
            title=no_tr("auth_q_domain"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get('domain')) == cheat_auth['domain']), description=tr("rôle de domain-password"),
        )

        # =====================================================================
        # Part 5 — troubleshooting (fix)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("fix"), tr("Partie 5 — dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Dépannage"),
            description=tr("""
Les routeurs `fix_r1` à `fix_r4` forment une ligne ; l'hôte `fix_h1` est derrière `fix_r1`, l'hôte
`fix_h4` derrière `fix_r4`. Le plan prévu : toute la ligne dans l'aire **`{area}`**, `fix_r1` au
niveau 1, `fix_r2` aux niveaux 1 et 2, `fix_r3` et `fix_r4` au niveau 2, des liens point à point.
`fix_r2` annonce au niveau 2 le réseau de `fix_h1` (une route statique redistribuée, section
@@ref:l1-to-l2@@).

Ce site a été livré avec **quatre pannes** : `fix_h1` ne joint pas `fix_h4`. Trouvez-les et
corrigez-les, sans changer le plan (section @@ref:diagnostic@@). Pour chaque lien, vérifiez
l'adjacence **des deux côtés** (`show isis neighbor`) ; lisez la configuration (`show
running-config`), les interfaces (`show isis interface detail`, `ip link`), la base de données, et le
journal `/var/log/frr/frr.log`.
""").format(area=d.fix_area)
            + instructor(tr("""
**Solution.**

{solution}

`fix_r4` : `{mtu_cmd}` (la MTU revient à 1500). Les pannes : aire `{wrong}` sur `fix_r1`
(niveau 1 : aucune adjacence avec `fix_r2`, d'une autre aire) ; type de réseau à diffusion sur
`fix_r3` vers `fix_r2` (`p2p hello on non p2p circuit` dans le journal) ; MTU de {mtu} sur `fix_r4`
(les IIH de 1500 octets de `fix_r3` sont jetés : `fix_r3` voit `fix_r4` `Initializing`, `fix_r4` ne
voit rien) ;
`set-overload-bit` sur `fix_r3`, routeur de transit (adjacences `Up`, mais aucun chemin ne passe par
lui).

Évaluation : `fix_adj_12`, `fix_adj_23`, `fix_adj_34` (4 chacun : l'adjacence vue des deux côtés),
`fix_overload` (3 : la LSP de `fix_r3` sans bit OL), `fix_ping` (3).
""").format(solution=_vtysh_text({r: c for r, items in ns.solution_fix().items() for kind, c in items
                                  if kind == 'vtysh'}),
            mtu_cmd=ns.solution_fix()['fix_r4'][0][1], wrong=d.fix_wrong_area, mtu=FIX_MTU)),
        )
        cheat_fix = {'f12': 'area', 'f23': 'network', 'f34': 'mtu', 'transit': 'overload'}
        causes = ("aires différentes>>>area|types de réseau différents>>>network|MTU différentes>>>mtu|"
                  "mots de passe différents>>>password|bit de surcharge>>>overload")
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Les causes des pannes"),
            description=tr("""
- cause de l'absence d'adjacence entre `fix_r1` et `fix_r2` : @@{{f12:>{causes}}}@@
- cause de l'absence d'adjacence entre `fix_r2` et `fix_r3` : @@{{f23:>{causes}}}@@
- cause de l'adjacence vue d'un seul côté entre `fix_r3` et `fix_r4` : @@{{f34:>{causes}}}@@
- cause de l'absence de chemin à travers `fix_r3` une fois les adjacences rétablies :
  @@{{transit:>{causes}}}@@
""").format(causes=causes)
            + instructor(tr("""
**Solution.** Aires différentes ; types de réseau différents ; MTU différentes ; bit de surcharge.

Évaluation, pour l'enseignant seulement : `fix_q_12`, `fix_q_23`, `fix_q_34`, `fix_q_transit` (1
chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        self.add_grade_element(
            title=no_tr("fix_adj_12"), max_grade=4, grade_part=part5,
            grade=4 * int(fix_both('fix_r1', 'fix_r2', 'fix_l12', 1)), description=tr("adjacence fix_r1 – fix_r2"),
        )
        self.add_grade_element(
            title=no_tr("fix_adj_23"), max_grade=4, grade_part=part5,
            grade=4 * int(fix_both('fix_r2', 'fix_r3', 'fix_l23', 2)), description=tr("adjacence fix_r2 – fix_r3"),
        )
        self.add_grade_element(
            title=no_tr("fix_adj_34"), max_grade=4, grade_part=part5,
            grade=4 * int(fix_both('fix_r3', 'fix_r4', 'fix_l34', 2)), description=tr("adjacence fix_r3 – fix_r4"),
        )
        own = isis_lsps_of(fix_db, 2, names('fix_r3'), pseudonode=False)
        self.add_grade_element(
            title=no_tr("fix_overload"), max_grade=3, grade_part=part5,
            grade=3 * int(bool(own) and not any(lsp['ol'] for lsp in own)),
            description=tr("fix_r3 n'est plus en surcharge"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=3, grade_part=part5, grade=3 * int(all(fix_ping)),
            description=tr("fix_h1 et fix_h4 se joignent"),
        )
        for key, title_key, text in (('f12', 'fix_q_12', tr("cause de la panne fix_r1 – fix_r2")),
                                     ('f23', 'fix_q_23', tr("cause de la panne fix_r2 – fix_r3")),
                                     ('f34', 'fix_q_34', tr("cause de la panne fix_r3 – fix_r4")),
                                     ('transit', 'fix_q_transit', tr("cause de l'absence de transit"))):
            self.add_grade_element(
                title=no_tr(title_key), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                grade=int(_norm(q5.get(key)) == cheat_fix[key]), description=text,
            )

        # =====================================================================
        # Bonus — external routes (ext)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("external"), tr("Bonus — routes externes (site ext)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Routes externes (bonus)"),
            description=tr("""
`ext_r1` et `ext_r2` forment un petit domaine IS-IS (aire `{area}`, niveau 2) ; l'hôte `ext_h2` est
derrière `ext_r2`. `ext_r1` est aussi relié, par le réseau `ext_wan` (hors IS-IS), au routeur
`ext_isp` d'un fournisseur d'accès, derrière lequel se trouve le serveur `internet` ({server}).
`ext_r1` a deux routes statiques dans FRR : vers `{public}` et une route par défaut, toutes deux
par `ext_isp`.

Faites annoncer par `ext_r1`, au niveau 2, sa route statique vers `{public}` et une route par
défaut (section @@ref:external@@), puis vérifiez les routes de `ext_r2` et que `ext_h2` joint
`internet`.
""").format(area=d.ext_area, server=EXT_SERVER, public=EXT_PUBLIC)
            + instructor(tr("""
**Solution.**

{solution}

`redistribute ipv4 static` n'annonce que `{public}` : la route par défaut demande
`default-information originate`.

Évaluation (bonus) : `ext_static` (2 : route IS-IS de `ext_r2` vers `{public}`), `ext_default`
(2 : route par défaut IS-IS sur `ext_r2`), `ext_ping` (2 : `ext_h2` joint `internet`).
""").format(solution=_vtysh_text(ns.solution_external()), public=EXT_PUBLIC)),
        )
        self.add_grade_element(
            title=no_tr("ext_static"), max_grade=2, grade_part=part6, bonus=True,
            grade=2 * int(gateways(ext_k, EXT_PUBLIC) == [str(addr('ext_r1', 'ext_l12'))]),
            description=tr("route vers le réseau externe annoncée"),
        )
        self.add_grade_element(
            title=no_tr("ext_default"), max_grade=2, grade_part=part6, bonus=True,
            grade=2 * int(gateways(ext_k, "0.0.0.0/0") == [str(addr('ext_r1', 'ext_l12'))]),
            description=tr("route par défaut annoncée"),
        )
        self.add_grade_element(
            title=no_tr("ext_ping"), max_grade=2, grade_part=part6, bonus=True, grade=2 * int(ext_ping),
            description=tr("ext_h2 joint internet"),
        )


_TRANSLATIONS = {}
