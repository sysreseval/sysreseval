"""MPLS lab with Linux and FRR (ldpd, ospfd): label switching, LDP and segment routing.

IPv4 only.  Five independent sites, one per part (completing a part gives all its points whatever
the others):

- ``st``: three routers and two hosts, no routing protocol; the students build an LSP by hand in
  both directions with ``ip -f mpls route`` / ``ip route ... encap mpls`` (push, swap, egress pop,
  penultimate hop popping) after enabling MPLS in the kernel (``net.mpls.*``);
- ``ldp``: a line of four routers with OSPF given; the students configure LDP (router-id and
  transport address on the loopback, core interfaces only), restrict the label allocation to the
  loopbacks and the host networks, and stop the TTL propagation on the edge routers;
- ``sr``: a line of four routers with OSPF given; the students enable SR-MPLS in OSPF (SRGB,
  prefix-SID indexes, a router with its own SRGB, ``no-php-flag``);
- ``fix``: an LDP core shipped with four faults (MPLS input off on one interface, no label space
  on a router, an interface missing from ``mpls ldp``, a transport address outside OSPF);
- ``tl`` (bonus): a square with OSPF and SR given; TI-LFA on ``tl_r1``.

The MPLS modules of the host (``mpls_router``, ``mpls_iptunnel``) are loaded by the kernel itself
when ``initial`` asks a container for an ``encap mpls`` route (module autoload: no host command).
Grading reads the json output of vtysh (lib/frr.py), the kernel tables and the per-interface MPLS
counters (lib/mpls.py) and real pings / traceroutes.  The states ``solve_<part>`` apply the
reference solution of one part, ``final`` all of them.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.common import TranslatedText
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import NetConfigEntry, set_net_config_entry, remount_proc_sys
from frr import (
    get_frr_routes, get_frr_running_config, get_kernel_routes, get_ldp_bindings, get_ldp_discovery,
    get_ldp_neighbors, get_ospf_sr_database, kernel_route_labels,
)
from mpls import (
    get_kernel_mpls_routes, get_mpls_counters, get_mpls_sysctls, mpls_counter_delta, mpls_route_is_pop,
    mpls_route_is_swap, trigger_mpls_modules_cmd,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("MPLS : commutation de labels, LDP et segment routing",
           en="MPLS: label switching, LDP and segment routing")
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

# Router interfaces in ethN order: the network of each.  The edge routers (pe) have their host
# network on eth0 and the core on eth1.
ROUTER_IFACES = {
    'st_pe1': ['st_lan1', 'st_l1'],
    'st_p': ['st_l1', 'st_l2'],
    'st_pe2': ['st_lan2', 'st_l2'],
    'ldp_pe1': ['ldp_lan1', 'ldp_l1'],
    'ldp_p1': ['ldp_l1', 'ldp_l2'],
    'ldp_p2': ['ldp_l2', 'ldp_l3'],
    'ldp_pe2': ['ldp_lan2', 'ldp_l3'],
    'sr_r1': ['sr_l1'],
    'sr_r2': ['sr_l1', 'sr_l2'],
    'sr_r3': ['sr_l2', 'sr_l3'],
    'sr_r4': ['sr_l3'],
    'fix_pe1': ['fix_lan1', 'fix_l1'],
    'fix_p1': ['fix_l1', 'fix_l2'],
    'fix_p2': ['fix_l2', 'fix_l3'],
    'fix_pe2': ['fix_lan2', 'fix_l3'],
    'tl_r1': ['tl_l12', 'tl_l14'],
    'tl_r2': ['tl_l12', 'tl_l23'],
    'tl_r3': ['tl_l23', 'tl_l34'],
    'tl_r4': ['tl_l34', 'tl_l14'],
}
# Hosts (one interface, eth0): their network and the router of their default route
HOSTS = {
    'st_h1': ('st_lan1', 'st_pe1'),
    'st_h2': ('st_lan2', 'st_pe2'),
    'ldp_h1': ('ldp_lan1', 'ldp_pe1'),
    'ldp_h2': ('ldp_lan2', 'ldp_pe2'),
    'fix_h1': ('fix_lan1', 'fix_pe1'),
    'fix_h2': ('fix_lan2', 'fix_pe2'),
}
# point-to-point links (/30): the first router gets .1, the second .2
LINKS = {
    'st_l1': ('st_pe1', 'st_p'), 'st_l2': ('st_p', 'st_pe2'),
    'ldp_l1': ('ldp_pe1', 'ldp_p1'), 'ldp_l2': ('ldp_p1', 'ldp_p2'), 'ldp_l3': ('ldp_p2', 'ldp_pe2'),
    'sr_l1': ('sr_r1', 'sr_r2'), 'sr_l2': ('sr_r2', 'sr_r3'), 'sr_l3': ('sr_r3', 'sr_r4'),
    'fix_l1': ('fix_pe1', 'fix_p1'), 'fix_l2': ('fix_p1', 'fix_p2'), 'fix_l3': ('fix_p2', 'fix_pe2'),
    'tl_l12': ('tl_r1', 'tl_r2'), 'tl_l23': ('tl_r2', 'tl_r3'), 'tl_l34': ('tl_r3', 'tl_r4'),
    'tl_l14': ('tl_r1', 'tl_r4'),
}
LANS = ['st_lan1', 'st_lan2', 'ldp_lan1', 'ldp_lan2', 'fix_lan1', 'fix_lan2']
# loopback number of the routers that have one (the st routers have none)
LOOPBACKS = {
    'ldp_pe1': 1, 'ldp_p1': 2, 'ldp_p2': 3, 'ldp_pe2': 4,
    'sr_r1': 1, 'sr_r2': 2, 'sr_r3': 3, 'sr_r4': 4,
    'fix_pe1': 1, 'fix_p1': 2, 'fix_p2': 3, 'fix_pe2': 4,
    'tl_r1': 1, 'tl_r2': 2, 'tl_r3': 3, 'tl_r4': 4,
}
# routers configured by the lab, without terminal
OPERATORS = ('tl_r2', 'tl_r3', 'tl_r4')
FRR_ROUTERS = [r for r in ROUTER_IFACES if not r.startswith('st_')]
LDP_ROUTERS = [r for r in ROUTER_IFACES if r.startswith(('ldp_', 'fix_'))]

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _r, _nets in ROUTER_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_r] = _i
for _h, (_n, _gw) in HOSTS.items():
    _TOPOLOGY.setdefault(_n, {})[_h] = 0
MACHINES = list(ROUTER_IFACES) + list(HOSTS)

SITE_COLORS = {'st': 'lightblue', 'ldp': 'palegreen', 'sr': 'khaki', 'fix': 'lightsalmon', 'tl': 'plum'}

# ---------------------------------------------------------------------------
# addressing: one /16 of 10.0.0.0/8 per instance; site s uses the third octets 16s to 16s + 15:
# 16s = the /30 links (link k: offset 4k), 16s + 1 + j = host network j, 16s + 15 = loopbacks
# ---------------------------------------------------------------------------

SITE_NUMBER = {'st': 1, 'ldp': 2, 'sr': 3, 'fix': 4, 'tl': 5}
LOOPBACK_OCTET = 15

LABEL_RANGE = (100, 999)          # part 1: the labels of the static LSP
PLATFORM_LABELS = 100000          # given label space (net.mpls.platform_labels) of the LDP/SR sites
SRGB_SIZE = 8000
SR_SRGB_BASES = (17000, 18000, 19000, 20000, 21000)
SR_R3_SRGB_BASES = (30000, 40000, 50000)
TL_SRGB_BASE = 16000              # FRR's default SRGB (the given SR of the tl site)
TL_COSTS = {'tl_l12': 10, 'tl_l23': 10, 'tl_l34': 15, 'tl_l14': 10}
# the reference states wait for LDP / SR to converge
CONVERGE_WAIT = 20
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP{note}
# (zebra, mgmtd, staticd et watchfrr démarrent toujours)
bgpd=no
ospfd=yes
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
    """Name of the interface of *router* on *net* (``eth1``)."""
    return f"eth{ROUTER_IFACES[router].index(net)}"


def core_ifaces(router: str) -> List[str]:
    """The interfaces of *router* on point-to-point links."""
    return [f"eth{i}" for i, net in enumerate(ROUTER_IFACES[router]) if net in LINKS]


def frr_daemons(router: str) -> str:
    ldpd = router in LDP_ROUTERS
    note = " : ospfd" + (" et ldpd activés" if ldpd else " activé")
    return FRR_DAEMONS.format(ldpd='yes' if ldpd else 'no', note=note)


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    st_push: int = 0          # part 1: label pushed by st_pe1 towards st_lan2
    st_swap: int = 0          # part 1: label st_p swaps it to (popped by st_pe2)
    st_back: int = 0          # part 1: label pushed by st_pe2 towards st_lan1 (popped by st_p)
    sr_srgb: int = 0          # part 3: SRGB base of sr_r1, sr_r2, sr_r4
    sr_srgb_r3: int = 0       # part 3: SRGB base of sr_r3
    sr_index1: int = 0        # part 3: prefix-SID indexes of the loopbacks
    sr_index2: int = 0
    sr_index3: int = 0
    sr_index4: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        data.st_push, data.st_swap, data.st_back = random.sample(range(LABEL_RANGE[0], LABEL_RANGE[1] + 1), 3)
        data.sr_srgb = random.choice(SR_SRGB_BASES)
        data.sr_srgb_r3 = random.choice(SR_R3_SRGB_BASES)
        data.sr_index1, data.sr_index2, data.sr_index3, data.sr_index4 = random.sample(range(1, 100), 4)

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
        for router, nets in ROUTER_IFACES.items():
            for net in nets:
                if net in LANS:
                    network = getattr(data.nets, net)
                    setattr(data.ips, f"{router}_{net}", IPv4Interface((int(network.network_address) + 1, 24)))
        for host, (net, _gw) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, host, IPv4Interface((int(network.network_address) + random.randint(10, 250), 24)))
        for router, number in LOOPBACKS.items():
            block = getattr(data.nets, f"{site_of(router)}_lo")
            setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + number, 32)))
        return data

    def sr_index(self, router: str) -> int:
        return getattr(self, f"sr_index{LOOPBACKS[router]}")

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
        for h, (net, gw) in HOSTS.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(IPv4Network("0.0.0.0/0"), self.addr(gw, net))])]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX; loopbacks rX-lo
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
        """Address (without prefix) of *router* on *net*."""
        return getattr(self.data.ips, f"{router}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def peer(self, router: str, link: str) -> str:
        first, second = LINKS[link]
        return second if router == first else first

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi MPLS"), tag="mpls-why")
            + tr("""
Un routeur IP cherche, pour chaque paquet, la route la plus spécifique qui contient l'adresse de
destination. **MPLS** (*MultiProtocol Label Switching*, RFC 3031) sépare le choix du chemin de
l'acheminement :

- le routeur d'**entrée** classe le paquet une seule fois dans une **FEC** (*Forwarding
  Equivalence Class* : par exemple « tous les paquets vers tel préfixe ») et lui colle un
  **label**, un entier court ;
- les routeurs du **cœur** commutent sur ce label (recherche exacte dans une table, sans regarder
  l'en-tête IP) et le remplacent par le label que le routeur suivant attend ;
- le routeur de **sortie** retire le label et rend le paquet à IP.

Vocabulaire : un **LSR** (*Label Switching Router*) commute des labels ; un **LER** (*Label Edge
Router*) est en bordure (entrée ou sortie). Chez un opérateur on parle de routeurs **PE**
(*Provider Edge*), **P** (*Provider*, le cœur) et **CE** (*Customer Edge*, chez le client). Le
chemin suivi par les paquets d'une FEC est un **LSP** (*Label Switched Path*) ; il est
**unidirectionnel** : l'aller et le retour sont deux LSP.

La commutation de labels n'est plus plus rapide qu'une recherche IP. MPLS sert parce que le cœur
n'a plus besoin de connaître les destinations finales : seulement comment joindre les routeurs de
sortie. Cela permet un cœur sans BGP, les **VPN** (L3VPN, L2VPN : une pile de labels), l'**ingénierie
de trafic** (des chemins choisis à l'entrée) et la **protection rapide** (des chemins de secours
calculés d'avance).
""")
            + info_subtitle(tr("L'en-tête MPLS"), tag="mpls-header")
            + tr("""
MPLS ajoute un en-tête de 32 bits (le *shim header*) entre l'en-tête de niveau 2 et le paquet IP :

| champ | bits | rôle |
|-------|------|------|
| Label | 20 | la valeur commutée |
| TC (ex-EXP) | 3 | classe de trafic (qualité de service) |
| S | 1 | *bottom of stack* : 1 sur le dernier label de la pile |
| TTL | 8 | durée de vie, décrémentée à chaque saut comme celle d'IP |

- Sur Ethernet, l'**EtherType** d'une trame MPLS est `0x8847` (`0x8848` pour le multicast MPLS,
  rare).
- Un paquet peut porter une **pile** de labels : plusieurs en-têtes à la suite, le bit S à 1 sur
  le dernier. Un routeur ne regarde que le label du **sommet** de la pile (les VPN et le segment
  routing empilent plusieurs labels).
- Les labels **0 à 15 sont réservés** : 0 *IPv4 Explicit NULL*, 1 *Router Alert*, 2 *IPv6
  Explicit NULL*, 3 *Implicit NULL* (jamais dans un paquet : il est seulement annoncé et signifie
  « retire le label »), 7 *Entropy Label Indicator*, 13 *GAL*, 14 *OAM*. Les labels utilisables
  vont de 16 à 2^20 − 1.
""")
            + info_subtitle(tr("Opérations et tables"), tag="mpls-ops")
            + tr("""
Trois opérations sur le label du sommet :

- **push** (imposition) : ajouter un label, au routeur d'entrée ;
- **swap** : remplacer le label reçu par celui que le routeur suivant a choisi ;
- **pop** (disposition) : retirer le label.

Les tables qui les décrivent :

- **FTN** (*FEC To NHLFE*), au routeur d'entrée : une route IP qui dit « pour ce préfixe, impose
  tel label et envoie à tel voisin » ;
- **ILM** (*Incoming Label Map*), sur chaque LSR : pour chaque label reçu, un **NHLFE** (*Next Hop
  Label Forwarding Entry* : le voisin suivant et l'opération). L'ILM et les NHLFE forment la
  **LFIB** (*Label Forwarding Information Base*), la table d'acheminement ;
- la **LIB** (*Label Information Base*) d'un protocole de distribution contient tous les labels
  appris de tous les voisins, même ceux qui ne servent pas.

Un label n'a qu'une **signification locale** : chaque LSR choisit les labels qu'il **reçoit**, et
son voisin en amont doit utiliser ce choix (allocation par l'aval, *downstream*). Le même LSP
change donc de label à chaque saut.

**PHP** (*Penultimate Hop Popping*) : l'avant-dernier routeur retire le label, pour que le routeur
de sortie ne fasse qu'une recherche (IP) au lieu de deux (label puis IP). Le routeur de sortie le
demande en annonçant le label **implicit-null** (3) pour ses propres préfixes. Avec
**explicit-null** (0), il reçoit un label jusqu'au bout (pour garder la classe TC) et le retire
lui-même. Sans PHP (*ultimate hop popping*), le routeur de sortie reçoit un label ordinaire,
le retire puis consulte sa table IP.
""")
            + info_subtitle(tr("MPLS sous Linux"), tag="mpls-linux")
            + tr("""
Le noyau Linux commute des labels depuis la version 4.1 : modules `mpls_router` (la LFIB) et
`mpls_iptunnel` (l'imposition sur une route IP), déjà chargés pour le TP. Le réglage est propre à
chaque espace de noms réseau, donc à chaque machine :

| sysctl | rôle |
|--------|------|
| `net.mpls.platform_labels` | taille de la table des labels : le noyau accepte les labels 0 à N − 1 ; **0 par défaut** (aucun label accepté) |
| `net.mpls.conf.<interface>.input` | accepter les paquets étiquetés reçus sur l'interface ; **0 par défaut** : ils sont jetés |
| `net.mpls.ip_ttl_propagate` | copier le TTL IP dans le label à l'entrée (1 par défaut), voir section @@ref:mpls-ttl@@ |
| `net.mpls.default_ttl` | TTL du label quand il n'est pas copié (255) |

Un routeur qui **reçoit** des paquets étiquetés a besoin des deux premiers réglages ; un routeur qui
ne fait qu'imposer des labels n'en a pas besoin. Dans les machines du TP, `/proc/sys` est déjà
accessible en écriture.

```
sysctl -w net.mpls.platform_labels=1000
sysctl -w net.mpls.conf.eth1.input=1

# FTN : une route IP qui impose un label (ou une pile : 100/200)
ip route add 10.1.2.0/24 encap mpls 100 via 10.1.0.2 dev eth1

# ILM : échange, retrait vers un voisin (PHP), retrait puis livraison locale
ip -f mpls route add 100 as 200 via inet 10.1.0.6 dev eth2
ip -f mpls route add 300 via inet 10.1.0.1 dev eth1
ip -f mpls route add 200 dev lo

ip -f mpls route show
ip route show
```

`via inet` désigne le voisin par son adresse IPv4. Une entrée sans `as` retire le label ; avec
`dev lo`, le paquet IP est rendu à la machine, qui le route ensuite comme s'il venait d'arriver.

Pour voir passer les labels : `tcpdump -nei eth1 mpls` affiche `MPLS (label 100, tc 0, [S], ttl
63)`. Les compteurs MPLS d'une interface : `ip stats show dev eth1 group afstats subgroup mpls`
(`RX errors` compte entre autres les TTL expirés, `noroute` les labels inconnus).

Les démons de FRR (`ldpd`, `ospfd`) remplissent ces mêmes tables par l'intermédiaire de `zebra` :
leurs entrées apparaissent avec `proto ldp` ou `proto ospf`.
""")
            + info_subtitle(tr("LDP"), tag="ldp")
            + tr("""
Écrire les tables à la main ne passe pas à l'échelle. **LDP** (*Label Distribution Protocol*, RFC
5036) distribue automatiquement des labels pour les **préfixes de la table de routage** : chaque LSP
suit le plus court chemin de l'IGP (OSPF ici).

- **Découverte** : chaque interface où LDP est activé envoie des *Hello* en UDP, port **646**, à
  l'adresse multicast **224.0.0.2** (*all routers*). Deux routeurs qui s'entendent forment une
  **adjacence**.
- **Session** : ils ouvrent ensuite une connexion **TCP 646** entre leurs **adresses de
  transport** (celle qui a l'adresse la plus haute ouvre la connexion). On choisit l'adresse de
  l'interface de bouclage, annoncée dans l'IGP : la session ne dépend alors d'aucune interface
  physique. Une adresse de transport injoignable donne une adjacence sans session.
- Un LSR est identifié par son **LSR-ID** (32 bits, comme un router-id) suivi de l'espace de labels :
  `10.0.15.1:0`.
- **Messages** : *Initialization*, *KeepAlive*, *Address* (les adresses des interfaces du LSR, pour
  relier un prochain saut IP à un voisin LDP), *Label Mapping* (« pour cette FEC, utilise ce
  label »), *Label Withdraw* / *Release*.

Les modes de FRR, comme de la plupart des routeurs :

- *downstream unsolicited* : un routeur annonce ses labels à tous ses voisins sans attendre de
  demande ;
- *independent control* : il les annonce dès qu'il a une route, sans attendre l'aval ;
- *liberal retention* : il garde les labels de tous ses voisins, même de ceux qui ne sont pas son
  prochain saut. Si l'IGP change de chemin, le bon label est déjà là. La LIB contient donc un label
  distant par voisin, et la LFIB seulement celui du prochain saut IGP.

Par défaut LDP alloue un label à **chaque préfixe** de la table, y compris les liens entre routeurs,
qui ne sont la destination de personne : on restreint souvent l'allocation aux interfaces de
bouclage (ou aux routes d'hôte /32), et ici aux réseaux des hôtes.

Tant que la session LDP n'est pas établie sur un lien, l'IGP peut déjà y faire passer le trafic,
qui perd alors ses labels : la **synchronisation LDP-IGP** (RFC 5443) donne au lien un coût
maximal le temps que LDP soit prêt.
""")
            + info_subtitle(tr("LDP avec FRR"), tag="ldp-frr")
            + tr("""
`ldpd` doit être activé dans `/etc/frr/daemons` (c'est fait sur les routeurs du TP). Dans `vtysh` :

```
configure terminal
mpls ldp
 router-id 10.0.15.1
 address-family ipv4
  discovery transport-address 10.0.15.1
  label local allocate for LDP-FEC
  interface eth1
  exit
  interface eth2
  exit
 exit-address-family
exit
access-list LDP-FEC seq 5 permit 10.0.15.0/24
end
write
```

- `router-id` : le LSR-ID ; `discovery transport-address` : l'adresse de transport des sessions
  IPv4 ;
- `interface` : les interfaces où envoyer des *Hello* (seulement celles qui mènent à d'autres
  routeurs) ;
- `label local allocate for LISTE` : n'allouer de label qu'aux préfixes permis par la liste
  d'accès (`label local allocate host-routes` : seulement aux /32) ; `label local advertise
  explicit-null` : annoncer 0 au lieu de 3 pour ses propres préfixes.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show mpls ldp discovery` | les adjacences, par interface |
| `show mpls ldp neighbor` | les sessions (`OPERATIONAL` quand tout va bien) |
| `show mpls ldp binding` | la LIB : label local et label de chaque voisin par préfixe ; `In Use` = celui du prochain saut |
| `show mpls table` | les labels que zebra a installés (la LFIB vue par FRR) |
| `show ip route` | les routes, avec le label qu'elles imposent |
| `ip -f mpls route`, `ip route` | ce que le noyau a vraiment |
""")
            + info_subtitle(tr("TTL et traceroute dans un cœur MPLS"), tag="mpls-ttl")
            + tr("""
À l'entrée, le routeur copie le TTL IP (décrémenté) dans le label : c'est la **propagation du
TTL**. Chaque LSR décrémente le TTL du label ; quand le label est retiré, le paquet IP reprend le
TTL du label. Une boucle dans le cœur finit donc, comme en IP, par l'expiration du TTL.

Un routeur MPLS d'opérateur dont le TTL de label expire fabrique un *ICMP Time Exceeded*, l'envoie
le long du LSP jusqu'à la sortie qui le route vers la source (RFC 3032), et y joint la pile de
labels (extensions ICMP, RFC 4950) : son `traceroute` affiche les labels. **Linux jette le paquet
sans rien répondre** (le compteur `RX errors` de l'interface augmente) : chaque routeur du cœur
apparaît comme une étoile `*`.

Avec `net.mpls.ip_ttl_propagate=0` à l'entrée, le label part avec un TTL de 255 et le TTL IP n'est
plus décrémenté dans le cœur : tout le LSP compte pour un seul saut. Les opérateurs **cachent**
ainsi leur cœur aux `traceroute` des clients. Le retrait du label par le routeur de sortie, sans
PHP, décrémente une fois de plus le TTL : il ajoute une ligne au `traceroute`.
""")
            + info_subtitle(tr("Segment routing"), tag="sr")
            + tr("""
Le **segment routing** (RFC 8402) est un **routage par la source** : le routeur d'entrée écrit le
chemin dans le paquet sous forme d'une liste de **segments** (des instructions), et le cœur ne garde
aucun état par chemin. En **SR-MPLS**, un segment est un label ; il n'y a **plus de LDP** : les
labels sont annoncés par l'**IGP** lui-même (OSPF : LSA opaques, RFC 8665 ; IS-IS : RFC 8667).

- Un **SID** (*Segment Identifier*) désigne un segment. Un **prefix-SID** est global : « va vers ce
  préfixe par le plus court chemin ». Celui d'une interface de bouclage s'appelle **node-SID**. Un
  **adjacency-SID** est local : « sors par ce lien ».
- Chaque routeur réserve un bloc de labels pour les SID globaux, le **SRGB** (*SR Global Block*,
  16000 à 23999 par défaut dans FRR), et un bloc pour les SID locaux, le **SRLB** (15000 à 15999).
- Un prefix-SID est annoncé comme un **index**. Le label qu'utilise un routeur pour joindre le
  préfixe est **la base du SRGB du routeur suivant + l'index** : chaque routeur annonce son SRGB dans
  une LSA *Router Information*. Si tous les routeurs ont le même SRGB, le label reste le même d'un
  bout à l'autre ; sinon il change à chaque saut, comme avec LDP.
- L'avant-dernier routeur retire le label (PHP), sauf si le prefix-SID est annoncé avec le drapeau
  **no-php** : le dernier routeur reçoit alors le label (dans son propre SRGB) et le retire.
- Seuls les préfixes qui ont un SID reçoivent un label : les autres sont acheminés en IP.

Le segment routing permet aussi l'**ingénierie de trafic** sans état dans le cœur (une liste de
segments : passer par tel routeur puis aller à telle destination) et le **TI-LFA** (section
@@ref:tilfa@@). Sa variante **SRv6** code les segments sous forme d'adresses IPv6, dans un en-tête
de routage IPv6 (*Segment Routing Header*).
""")
            + info_subtitle(tr("Segment routing avec FRR"), tag="sr-frr")
            + tr("""
Le segment routing s'active dans OSPF, sur chaque routeur du domaine :

```
configure terminal
router ospf
 capability opaque
 segment-routing on
 segment-routing global-block 16000 23999
 segment-routing prefix 10.0.15.1/32 index 1
exit
end
write
```

- `capability opaque` : les LSA opaques qui portent les informations SR ;
- `segment-routing global-block BAS HAUT` : le SRGB (`local-block` pour le SRLB) ;
- `segment-routing prefix P/32 index N` : le prefix-SID d'un préfixe de la machine (son interface
  de bouclage, qui doit être dans OSPF) ; suivi de `no-php-flag` pour refuser le PHP, ou de
  `explicit-null`.

FRR ajoute de lui-même `router-info area` (la LSA *Router Information*).

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ip ospf database segment-routing` | chaque routeur SR : SRGB, SRLB, ses prefix-SID et adjacency-SID, avec l'opération sur les labels |
| `show mpls table` | les labels installés (type `SR (OSPF)`) |
| `show ip route` | le label imposé par chaque route |
| `ip -f mpls route`, `ip route` | ce que le noyau a vraiment |
""")
            + info_subtitle(tr("Protection : LFA et TI-LFA"), tag="tilfa")
            + tr("""
Quand un lien tombe, l'IGP met de quelques dizaines de millisecondes à quelques secondes à
converger. La **protection rapide** (*Fast ReRoute*) calcule d'avance un **prochain saut de
secours** pour basculer dès que la panne est détectée.

- **LFA** (*Loop-Free Alternate*, RFC 5286) : un voisin dont le plus court chemin vers la
  destination ne repasse pas par nous peut servir de secours sans créer de boucle. Selon la
  topologie, il n'en existe pas toujours.
- **TI-LFA** (*Topology Independent LFA*) : avec le segment routing, le secours suit le chemin
  qu'aura le réseau **après** convergence. Si le voisin choisi renverrait le paquet vers la panne,
  le routeur impose une **liste de réparation** (un node-SID, un adjacency-SID...) qui fait passer
  le paquet au-delà. La couverture est totale.
- Protection **de lien** (éviter le lien) ou **de nœud** (éviter le routeur suivant tout entier).

Dans FRR : `fast-reroute ti-lfa` (ou `fast-reroute ti-lfa node-protection`) sous `router ospf`.
`show ip route` montre la route de secours sur une ligne marquée `b`, avec sa pile de labels
(`backupNexthops` en json). zebra garde les secours pour lui : le noyau des machines du TP ne les
reçoit pas, et le TP n'en observe donc que le calcul.
""")
            + info_subtitle(tr("Dépannage MPLS"), tag="mpls-debug")
            + tr("""
Une méthode : partir du plan de contrôle et descendre vers le plan de données.

1. **IGP** : chaque routeur a-t-il une route vers les interfaces de bouclage (LSR-ID, adresses de
   transport) des autres ? (`show ip ospf neighbor`, `show ip route`)
2. **LDP** : adjacences par interface (`show mpls ldp discovery`), sessions (`show mpls ldp
   neighbor` : `OPERATIONAL`), labels (`show mpls ldp binding`).
3. **Labels installés** : zebra (`show mpls table`) puis le noyau (`ip -f mpls route`). zebra peut
   croire un label installé alors que le noyau l'a refusé ou perdu (table des labels trop petite).
   zebra ne réinstalle ses labels que quand ses LSP changent : `clear mpls ldp neighbor` les fait
   annoncer à nouveau.
4. **Noyau** : `net.mpls.platform_labels`, `net.mpls.conf.<interface>.input`, la MTU (le label
   ajoute 4 octets et Linux ne fragmente pas un paquet étiqueté).
5. **Plan de données** : `tcpdump -nei ethX mpls` sur chaque lien, les compteurs `ip stats show dev
   ethX group afstats subgroup mpls`, `traceroute`.

| symptôme | cause probable |
|----------|----------------|
| adjacence LDP sans session | adresse de transport injoignable (pas dans l'IGP), TCP 646 filtré |
| aucune adjacence sur un lien | interface absente de `mpls ldp`, *Hello* filtrés |
| le voisin en amont envoie des labels, rien ne ressort | `input` à 0 sur l'interface, label absent de la LFIB du noyau |
| `show mpls table` correcte, `ip -f mpls route` vide | `platform_labels` trop petit (ou remis après coup) |
| le trafic passe mais sans label sur une partie du chemin | pas de session LDP avec le prochain saut : le label est retiré trop tôt |
""")
        )

    # -- FRR configuration files -------------------------------------------------

    def _ospf_lines(self, router: str, with_loopback: bool = True) -> List[str]:
        """``router ospf`` + interface blocks of the given OSPF (core links point-to-point,
        host networks passive)."""
        lines = ["router ospf", f" ospf router-id {self.lo(router)}", "exit", "!"]
        for i, net in enumerate(ROUTER_IFACES[router]):
            statements = [" ip ospf area 0"]
            if net in LINKS:
                statements.append(" ip ospf network point-to-point")
                if net in TL_COSTS:
                    statements.append(f" ip ospf cost {TL_COSTS[net]}")
            else:
                statements.append(" ip ospf passive")
            lines += [f"interface eth{i}"] + statements + ["exit", "!"]
        if with_loopback:
            lines += ["interface lo", " ip ospf area 0", "exit", "!"]
        return lines

    def _ldp_lines(self, router: str, interfaces: List[str], transport=None) -> List[str]:
        lo = self.lo(router)
        lines = ["mpls ldp", f" router-id {lo}", " !", " address-family ipv4",
                 f"  discovery transport-address {transport or lo}"]
        lines += [f"  interface {name}" for name in interfaces]
        return lines + [" exit-address-family", " !", "exit", "!"]

    def _sr_lines(self, router: str, base: int, index: int) -> List[str]:
        return ["router ospf", " capability opaque", " segment-routing on",
                f" segment-routing global-block {base} {base + SRGB_SIZE - 1}",
                f" segment-routing prefix {self.lo(router)}/32 index {index}", "exit", "!"]

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf: OSPF on every FRR router; LDP with its faults on the fix
        site; SR on the tl site."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", "log file /var/log/frr/frr.log", "!"]
        site = site_of(router)
        lines += self._ospf_lines(router, with_loopback=(router != 'fix_pe2'))
        if site == 'fix':
            interfaces = core_ifaces(router)
            if router == 'fix_p2':
                interfaces = [x for x in interfaces if x != iface('fix_p2', 'fix_l2')]
            lines += self._ldp_lines(router, interfaces)
        elif site == 'tl':
            lines += self._sr_lines(router, TL_SRGB_BASE, LOOPBACKS[router])
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part (texts shown by the instructor solutions) ------

    def solution_static(self) -> Dict[str, List[str]]:
        """Shell commands of part 1, per router."""
        d = self.data
        p_l1, p_l2 = self.addr('st_p', 'st_l1'), self.addr('st_p', 'st_l2')
        pe1_l1, pe2_l2 = self.addr('st_pe1', 'st_l1'), self.addr('st_pe2', 'st_l2')
        return {
            'st_pe1': [f"ip route add {self.net('st_lan2')} encap mpls {d.st_push} via {p_l1} dev eth1"],
            'st_p': ["sysctl -w net.mpls.platform_labels=1000",
                     "sysctl -w net.mpls.conf.eth0.input=1",
                     "sysctl -w net.mpls.conf.eth1.input=1",
                     f"ip -f mpls route add {d.st_push} as {d.st_swap} via inet {pe2_l2} dev eth1",
                     f"ip -f mpls route add {d.st_back} via inet {pe1_l1} dev eth0"],
            'st_pe2': ["sysctl -w net.mpls.platform_labels=1000",
                       "sysctl -w net.mpls.conf.eth1.input=1",
                       f"ip -f mpls route add {d.st_swap} dev lo",
                       f"ip route add {self.net('st_lan1')} encap mpls {d.st_back} via {p_l2} dev eth1"],
        }

    def ldp_acl(self) -> List[str]:
        """The access-list of the label allocation filter (loopbacks and host networks)."""
        return [f"access-list LDP-FEC seq 5 permit {self.net('ldp_lo')}",
                f"access-list LDP-FEC seq 10 permit {self.net('ldp_lan1')}",
                f"access-list LDP-FEC seq 15 permit {self.net('ldp_lan2')}"]

    def solution_ldp(self) -> Dict[str, List[str]]:
        """vtysh commands of part 2, per router."""
        result = {}
        for r in ('ldp_pe1', 'ldp_p1', 'ldp_p2', 'ldp_pe2'):
            lo = self.lo(r)
            cmds = self.ldp_acl() + ["mpls ldp", f"router-id {lo}", "address-family ipv4",
                                     f"discovery transport-address {lo}", "label local allocate for LDP-FEC"]
            cmds += [f"interface {name}" for name in core_ifaces(r)]
            result[r] = cmds + ["exit", "exit-address-family", "exit"]
        return result

    def solution_ldp_sysctl(self) -> Dict[str, List[str]]:
        return {r: ["sysctl -w net.mpls.ip_ttl_propagate=0"] for r in ('ldp_pe1', 'ldp_pe2')}

    def solution_sr(self) -> Dict[str, List[str]]:
        d = self.data
        result = {}
        for r in ('sr_r1', 'sr_r2', 'sr_r3', 'sr_r4'):
            base = d.sr_base(r)
            prefix = f"segment-routing prefix {self.lo(r)}/32 index {d.sr_index(r)}"
            if r == 'sr_r4':
                prefix += " no-php-flag"
            result[r] = ["router ospf", "capability opaque", "segment-routing on",
                         f"segment-routing global-block {base} {base + SRGB_SIZE - 1}", prefix, "exit"]
        return result

    def solution_fix(self) -> Dict[str, List[str]]:
        """Shell (sysctl) and vtysh commands of part 4: {router: [(kind, command)]}."""
        return {
            'fix_p1': [('sh', "sysctl -w net.mpls.conf.eth0.input=1")],
            'fix_p2': [('sh', f"sysctl -w net.mpls.platform_labels={PLATFORM_LABELS}"),
                       ('vtysh', ["mpls ldp", "address-family ipv4", f"interface {iface('fix_p2', 'fix_l2')}",
                                  "exit", "exit-address-family", "exit"])],
            'fix_pe2': [('vtysh', ["interface lo", "ip ospf area 0", "exit"])],
        }

    def solution_tilfa(self) -> Dict[str, List[str]]:
        return {'tl_r1': ["router ospf", "fast-reroute ti-lfa node-protection", "exit"]}

    # -- applying the solutions ----------------------------------------------------

    def _apply_static(self, step: int = 1):
        for r, cmds in self.solution_static().items():
            for c in cmds:
                self.cmd(r, c, step=step)

    def _apply_ldp(self, step: int = 1):
        for r, cmds in self.solution_ldp().items():
            self._vtysh(r, *cmds, step=step)
        for r, cmds in self.solution_ldp_sysctl().items():
            for c in cmds:
                self.cmd(r, c, step=step)

    def _apply_sr(self, step: int = 1):
        for r, cmds in self.solution_sr().items():
            self._vtysh(r, *cmds, step=step)

    def _apply_fix(self, step: int = 1):
        for r, items in self.solution_fix().items():
            for kind, cmd in items:
                if kind == 'sh':
                    self.cmd(r, cmd, step=step)
                else:
                    self._vtysh(r, *cmd, step=step)
        # zebra installs the labels refused while platform_labels was 0 only when the LSPs change
        self.cmd('fix_p2', 'vtysh -c "clear mpls ldp neighbor"', step=step, allow_error=True)

    def _apply_tilfa(self, step: int = 1):
        for r, cmds in self.solution_tilfa().items():
            self._vtysh(r, *cmds, step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for r in ROUTER_IFACES:
            remount_proc_sys(self, r)
            # loads mpls_router / mpls_iptunnel on the host (module autoload) and waits for the
            # net.mpls sysctls of this container
            self.cmd(r, trigger_mpls_modules_cmd())
        for r in LOOPBACKS:
            self.cmd(r, f"ip addr add {getattr(self.data.ips, f'{r}_lo')} dev lo")
        for r in FRR_ROUTERS:
            labels = 0 if r == 'fix_p2' else PLATFORM_LABELS
            self.cmd(r, f"sysctl -w net.mpls.platform_labels={labels}", step=2)
            for name in core_ifaces(r):
                value = 0 if (r, name) == ('fix_p1', 'eth0') else 1
                self.cmd(r, f"sysctl -w net.mpls.conf.{name}.input={value}", step=2)
            self.file(r, "/etc/frr/daemons", frr_daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (LSP statique)",
                                                  en="Part 1: solution (static LSP)"))
    def solve_static(self):
        self._apply_static()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (LDP)", en="Part 2: solution (LDP)"))
    def solve_ldp(self):
        self._apply_ldp()
        self.cmd('ldp_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (segment routing)",
                                                  en="Part 3: solution (segment routing)"))
    def solve_sr(self):
        self._apply_sr()
        self.cmd('sr_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (dépannage)",
                                                  en="Part 4: solution (troubleshooting)"))
    def solve_fix(self):
        self._apply_fix()
        self.cmd('fix_pe1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (TI-LFA, bonus)",
                                                  en="Part 5: solution (TI-LFA, bonus)"))
    def solve_tilfa(self):
        self._apply_tilfa()
        self.cmd('tl_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for LDP and SR).  Form questions are filled through cheat_answers."""
        self._apply_static()
        self._apply_ldp()
        self._apply_sr()
        self._apply_fix()
        self._apply_tilfa()
        self.cmd('ldp_pe1', f"sleep {CONVERGE_WAIT}", step=2)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s):
    """The integer of a typed answer (``'0x8847'`` is read in hexadecimal), None when unreadable."""
    text = _norm(s).replace(' ', '')
    try:
        return int(text, 16) if text.startswith('0x') else int(text)
    except ValueError:
        return None


def _hex(s):
    """A typed EtherType: ``0x8847``, ``8847`` (read in hexadecimal) or ``34887``."""
    text = _norm(s).replace(' ', '')
    if text.startswith('0x'):
        return _int(text)
    try:
        return int(text, 16) if len(text) == 4 else int(text)
    except ValueError:
        return None


# the header of a router's block in a solution: French typography puts a space before the colon
_ROUTER_HEADER = {'fr': "`{router}` :", 'en': "`{router}`:"}


def _router_blocks(blocks: List[tuple]) -> Dict[str, str]:
    """Blocks ``(router, body)`` as fenced code under a header, one text per language for _by_language()."""
    return {lang: "\n\n".join(header.format(router=router) + f"\n\n```\n{body}\n```" for router, body in blocks)
            for lang, header in _ROUTER_HEADER.items()}


def _vtysh_text(solution: Dict[str, List[str]]) -> Dict[str, str]:
    """The reference configuration of a part, as vtysh sessions (one block per router), one text per
    language."""
    return _router_blocks([(router, "\n".join(["configure terminal"] + [f" {c}" for c in cmds] + ["end", "write"]))
                           for router, cmds in solution.items()])


def _shell_text(solution: Dict[str, List[str]]) -> Dict[str, str]:
    """The shell commands of a part (one block per router), one text per language."""
    return _router_blocks([(router, "\n".join(cmds)) for router, cmds in solution.items()])


def _in_language(value, lang: str) -> str:
    """*value* in *lang*: a tr() text or a ``{language: text}`` dict resolved, a plain value as it is."""
    return TranslatedText(value).resolve(lang) if isinstance(value, dict) else value


def _by_language(text: TranslatedText, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values*; a dict value (a tr() text, the result of _vtysh_text /
    _shell_text, the table of the sites) gives one value per language."""
    return TranslatedText({lang: version.format(**{k: _in_language(v, lang) for k, v in values.items()})
                           for lang, version in text.items()})


def _traceroute_hops(output: str) -> List[str]:
    """The hops of ``traceroute -n -q 1``: one address or ``*`` per line after the header."""
    hops = []
    for line in (output or "").splitlines()[1:]:
        words = line.split()
        if len(words) >= 2 and words[0].isdigit():
            hops.append(words[1])
    return hops


def _route_via(routes: Dict[str, Dict], prefix, labels: List[int], gateway) -> bool:
    """True when the kernel route of *prefix* pushes *labels* towards *gateway*."""
    entry = routes.get(str(prefix)) or {}
    return any(stack == labels and str(gw) == str(gateway)
               for (gw, _dev), stack in zip(entry.get('nexthops', []), entry.get('labels', [])))


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

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

    def _session(self, neighbors: Dict[str, Dict], peer: str) -> bool:
        """True when *neighbors* holds an operational session with *peer*, whatever LSR-ID it uses."""
        ns = self.net_scheme
        addresses = {str(ns.addr(peer, net)) for net in ROUTER_IFACES[peer]}
        if peer in LOOPBACKS:
            addresses.add(str(ns.lo(peer)))
        return any(n.get('operational') and (lsr in addresses or str(n.get('transport_address')) in addresses)
                   for lsr, n in neighbors.items())

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        lo, addr, net = ns.lo, ns.addr, ns.net

        # ---------------- diagnostics kept in the archive -------------------------
        for r in FRR_ROUTERS:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        st_sys = {r: get_mpls_sysctls(self, r) for r in ('st_p', 'st_pe2')}
        st_ilm = {r: get_kernel_mpls_routes(self, r) for r in ('st_p', 'st_pe2')}
        st_k = {r: get_kernel_routes(self, r, allow_error=True) for r in ('st_pe1', 'st_pe2')}
        _out, st_code = self.test('st_h1', f"ping -c 3 -i 0.2 -w 3 {d.ips.st_h2.ip}", allow_error=True)

        ldp = ('ldp_pe1', 'ldp_p1', 'ldp_p2', 'ldp_pe2')
        ldp_nb = {r: get_ldp_neighbors(self, r) for r in ldp}
        ldp_bind = {r: get_ldp_bindings(self, r) for r in ldp}
        ldp_cfg = {r: get_frr_running_config(self, r, allow_error=True) for r in ('ldp_pe1', 'ldp_pe2')}
        ldp_ilm = {r: get_kernel_mpls_routes(self, r) for r in ('ldp_p1', 'ldp_p2')}
        ldp_k = get_kernel_routes(self, 'ldp_pe1', allow_error=True)
        ldp_sys = {r: get_mpls_sysctls(self, r) for r in ('ldp_pe1', 'ldp_pe2')}
        trace_out, _code = self.test('ldp_h1', f"traceroute -n -q 1 -w 1 -m 8 {d.ips.ldp_h2.ip}", allow_error=True)
        ldp_ping = self._burst('ldp_h1', d.ips.ldp_h2.ip)
        ldp_delta = {r: self._counters_delta(r, 'eth0') for r in ('ldp_p1', 'ldp_p2')}

        sr = ('sr_r1', 'sr_r2', 'sr_r3', 'sr_r4')
        sr_db = {r: get_ospf_sr_database(self, r) for r in sr}
        sr_ilm = {r: get_kernel_mpls_routes(self, r) for r in ('sr_r2', 'sr_r3', 'sr_r4')}
        sr_k = get_kernel_routes(self, 'sr_r1', allow_error=True)
        sr_ping = self._burst('sr_r1', lo('sr_r4'), source=lo('sr_r1'))
        sr_delta = {r: self._counters_delta(r, 'eth0') for r in ('sr_r2', 'sr_r3')}

        fix_sys = {r: get_mpls_sysctls(self, r) for r in ('fix_p1', 'fix_p2')}
        fix_ilm = get_kernel_mpls_routes(self, 'fix_p2')
        fix_disc = get_ldp_discovery(self, 'fix_p2')
        fix_nb = get_ldp_neighbors(self, 'fix_p2')
        fix_ping = self._burst('fix_h1', d.ips.fix_h2.ip)
        fix_delta = {r: self._counters_delta(r, 'eth0') for r in ('fix_p1', 'fix_p2')}

        tl_routes = get_frr_routes(self, 'tl_r1')
        tl_cfg = get_frr_running_config(self, 'tl_r1', allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('st', tr("1 — LSP statique"), tr("`st_pe1`, `st_p`, `st_pe2`, les hôtes `st_h1` et `st_h2`")),
                 ('ldp', "2 — LDP", tr("`ldp_pe1`, `ldp_p1`, `ldp_p2`, `ldp_pe2`, les hôtes `ldp_h1` et `ldp_h2`")),
                 ('sr', "3 — segment routing", "`sr_r1`, `sr_r2`, `sr_r3`, `sr_r4`"),
                 ('fix', tr("4 — dépannage"),
                  tr("`fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2`, les hôtes `fix_h1` et `fix_h2`")),
                 ('tl', "5 — TI-LFA (bonus)", tr("`tl_r1` (les trois autres routeurs n'ont pas de terminal)"))]
        # one table per language (the cells that are tr() texts)
        site_rows = TranslatedText({
            lang: "\n".join(f"| {_in_language(part, lang)} | `{site}_*` | {_in_language(machines, lang)} |"
                            for site, part, machines in sites)
            for lang in ('fr', 'en')})
        members: Dict[str, List[str]] = {n: [] for n in list(LINKS) + LANS}
        for r, nets in ROUTER_IFACES.items():
            for i, n in enumerate(nets):
                members[n].append(f"`{r}` eth{i} (`{addr(r, n)}`)")
        for h, (n, _gw) in HOSTS.items():
            members[n].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        address_rows = [f"| `{n}` | `{net(n)}` | {', '.join(members[n])} |" for n in list(LINKS) + LANS]
        address_rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                         + ", ".join(f"`{r}` `{lo(r)}/32`" for r in LOOPBACKS if site_of(r) == site) + " |"
                         for site in ('ldp', 'sr', 'fix', 'tl')]
        addressing = "\n".join(address_rows)
        i1, i2, i3, i4 = d.sr_index1, d.sr_index2, d.sr_index3, d.sr_index4

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="180faf0c3e8ce6b0",
            description=_by_language(tr("""
Lisez l'onglet **Informations** : il présente MPLS, LDP et le segment routing, et leur mise en
œuvre avec Linux et FRR.

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs des sites `ldp`, `sr`, `fix` et `tl` font tourner **FRRouting** (FRR) :
  configurez-les avec `vtysh`. **OSPF y fonctionne déjà** (zone 0, interfaces de bouclage
  annoncées) ; `ldpd` est activé sur les sites `ldp` et `fix`.
- Sur le site `st`, FRR ne tourne pas : tout se fait avec `sysctl` et `ip`.
- Les modules MPLS du noyau sont chargés. Sur les sites `ldp`, `sr`, `fix` et `tl`, la table des
  labels (`net.mpls.platform_labels={labels}`) et l'entrée MPLS des interfaces entre routeurs sont
  déjà réglées (sauf les pannes du site `fix`) ; sur le site `st`, rien ne l'est.
- Toutes les adresses sont en place, ainsi que la route par défaut des hôtes.
- Les fichiers `/etc/hosts` contiennent les noms : `ldp_p1-eth1` désigne l'adresse de l'interface
  `eth1` de `ldp_p1`, `ldp_pe2-lo` l'adresse de bouclage de `ldp_pe2`, `ldp_h2` l'hôte.

**Plan d'adressage.** Les liens entre routeurs sont des /30, les réseaux des hôtes des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- Partie 1 : labels **{push}** (imposé par `st_pe1`), **{swap}** (le label par lequel `st_p`
  le remplace), **{back}** (imposé par `st_pe2` au retour).
- Partie 3 : SRGB de `sr_r1`, `sr_r2` et `sr_r4` : **{srgb} à {srgb_end}** ; SRGB de `sr_r3` :
  **{srgb3} à {srgb3_end}** ; index des prefix-SID des interfaces de bouclage : `sr_r1` **{i1}**,
  `sr_r2` **{i2}**, `sr_r3` **{i3}**, `sr_r4` **{i4}**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`). Les réglages `sysctl` et les commandes
  `ip` ne sont pas enregistrés : ne redémarrez pas les machines.
- Une session LDP s'établit en quelques secondes ; OSPF annonce les informations du segment
  routing aussitôt qu'il est activé.

**Évaluation.** Chaque évaluation lit vos réponses, les réglages MPLS du noyau, ses tables
(`ip -f mpls route`, `ip route`), l'état de LDP, du segment routing et d'OSPF, puis envoie des
`ping` en comptant les paquets étiquetés reçus par les routeurs du cœur. Elle dure une quinzaine de
secondes.
"""), site_rows=site_rows, addressing=addressing, labels=PLATFORM_LABELS, push=d.st_push, swap=d.st_swap,
                back=d.st_back, srgb=d.sr_srgb, srgb_end=d.sr_srgb + SRGB_SIZE - 1, srgb3=d.sr_srgb_r3,
                srgb3_end=d.sr_srgb_r3 + SRGB_SIZE - 1, i1=i1, i2=i2, i3=i3, i4=i4)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_static`, `solve_ldp`, `solve_sr`, `solve_fix` et `solve_tilfa` (onglet
*Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes, attend {wait} s (sessions LDP) puis remplit tous
les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.

Les pannes du site `fix` : `net.mpls.conf.eth0.input=0` sur `fix_p1` (les paquets étiquetés
venant de `fix_pe1` sont jetés), `net.mpls.platform_labels=0` sur `fix_p2` (le noyau n'accepte
aucun label), `eth0` de `fix_p2` absente de `mpls ldp` (pas de session `fix_p1` – `fix_p2`),
interface de bouclage de `fix_pe2` hors d'OSPF alors qu'elle est son adresse de transport
(adjacence sans session avec `fix_p2`).
""").format(wait=CONVERGE_WAIT)),
        )

        # =====================================================================
        # Part 1 — static LSP (st)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("static"), tr("Partie 1 — un LSP construit à la main (site st)"))
        lan1, lan2 = net('st_lan1'), net('st_lan2')
        self.question_dummy(
            section=self.section(0),
            title=tr("Un LSP construit à la main"),
            hash="ada805fe4fefcf1d",
            description=tr("""
Les routeurs `st_pe1`, `st_p` et `st_pe2` forment une ligne (liens `st_l1` et `st_l2`) ; l'hôte
`st_h1` est sur le réseau `st_lan1` de `st_pe1`, l'hôte `st_h2` sur le réseau `st_lan2` de
`st_pe2`. Aucun protocole de routage ne tourne et aucune route n'est en place : `st_pe1` ne connaît
pas `st_lan2`, `st_pe2` ne connaît pas `st_lan1`, et `st_p` ne connaît **aucun** des deux réseaux
d'hôtes. Il ne pourra transporter leurs paquets qu'en commutant des labels (sections
@@ref:mpls-ops@@ et @@ref:mpls-linux@@).

1. Activez MPLS dans le noyau des routeurs qui **reçoivent** des paquets étiquetés : une table de
   labels assez grande (`net.mpls.platform_labels`) et l'entrée MPLS
   (`net.mpls.conf.<interface>.input`) des interfaces où ces paquets arrivent. Lesquels ?
2. **Aller** (`st_h1` vers `st_h2`) : `st_pe1` impose le label **{push}** aux paquets destinés à
   `st_lan2` et les envoie à `st_p` ; `st_p` remplace **{push}** par **{swap}** et les envoie à
   `st_pe2` ; `st_pe2` retire **{swap}** et route le paquet IP vers `st_h2` (retrait par le routeur
   de sortie : `dev lo`).
3. **Retour** (`st_h2` vers `st_h1`) : `st_pe2` impose **{back}** ; `st_p`, avant-dernier
   routeur, le retire (PHP) et donne le paquet IP à `st_pe1`.
4. Vérifiez que `st_h1` joint `st_h2`. Regardez les trames sur `st_p` (`tcpdump -nei eth0 mpls`) :
   EtherType, label, bit S, TTL ; et ses compteurs MPLS (`ip stats show dev eth0 group afstats
   subgroup mpls`).
5. Lancez `traceroute -n st_h2` depuis `st_h1`, puis `traceroute -n st_h1` depuis `st_h2`. Comptez
   les lignes et expliquez les étoiles (section @@ref:mpls-ttl@@).
""").format(push=d.st_push, swap=d.st_swap, back=d.st_back)
            + instructor(_by_language(tr("""
**Solution.**

{solution}

`st_pe1` ne reçoit aucun paquet étiqueté (`st_p` lui rend des paquets IP) : il n'a besoin d'aucun
réglage. Le `traceroute` aller montre cinq lignes : `st_pe1`, deux étoiles (le TTL du label expire
sur `st_p` puis sur `st_pe2`, qui le jettent sans répondre), `st_pe2` (son retrait du label puis sa
décrémentation du TTL IP), `st_h2`. Le retour en montre quatre : `st_pe2`, une étoile (`st_p`),
`st_pe1`, `st_h1`.

Évaluation : `st_platform_labels` (2 : `st_p` et `st_pe2`), `st_input` (3 : `eth0` et `eth1` de
`st_p`, `eth1` de `st_pe2`), `st_push`, `st_swap` (3 chacun), `st_pop` (2), `st_back` (3 : 1 pour
l'imposition sur `st_pe2`, 2 pour le PHP de `st_p`), `st_ping` (3).
"""), solution=_shell_text(ns.solution_static()))),
        )
        cheat_st = {'ethertype': '0x8847', 'max_label': str(2 ** 20 - 1), 'hops': '5'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site st"),
            hash="20784d493fa2f0f6",
            description=tr("""
- EtherType des trames MPLS (en hexadécimal) : @@{ethertype:[0-9a-fA-Fx]+}@@
- plus grande valeur possible d'un label : @@{max_label:[0-9]+}@@
- nombre de lignes de sauts du `traceroute -n st_h2` lancé depuis `st_h1` : @@{hops:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **`0x8847`** ; un label a 20 bits : **1048575** (2^20 − 1) ; **5** lignes (voir
la question précédente).

Évaluation : `st_q_ethertype`, `st_q_max_label`, `st_q_hops` (1 chacun).
""")),
            cheat_answers={"final": cheat_st, "solve_static": cheat_st},
        )
        sysctl_ok = [int((st_sys['st_p'].get('platform_labels') or 0) > max(d.st_push, d.st_back)),
                     int((st_sys['st_pe2'].get('platform_labels') or 0) > d.st_swap)]
        self.add_grade_element(
            title=no_tr("st_platform_labels"), max_grade=2, grade_part=part1, grade=sum(sysctl_ok),
            description=tr("table des labels assez grande sur st_p et st_pe2"),
        )
        inputs = [st_sys['st_p']['input'].get('eth0') == 1, st_sys['st_p']['input'].get('eth1') == 1,
                  st_sys['st_pe2']['input'].get('eth1') == 1]
        self.add_grade_element(
            title=no_tr("st_input"), max_grade=3, grade_part=part1, grade=sum(inputs),
            description=tr("entrée MPLS sur les interfaces qui reçoivent des labels"),
        )
        self.add_grade_element(
            title=no_tr("st_push"), max_grade=3, grade_part=part1,
            grade=3 * int(_route_via(st_k['st_pe1'], lan2, [d.st_push], addr('st_p', 'st_l1'))),
            description=tr("st_pe1 impose le label de l'aller"),
        )
        self.add_grade_element(
            title=no_tr("st_swap"), max_grade=3, grade_part=part1,
            grade=3 * int(mpls_route_is_swap(st_ilm['st_p'], d.st_push, [d.st_swap], addr('st_pe2', 'st_l2'))),
            description=tr("st_p échange le label de l'aller"),
        )
        self.add_grade_element(
            title=no_tr("st_pop"), max_grade=2, grade_part=part1,
            grade=2 * int(mpls_route_is_pop(st_ilm['st_pe2'], d.st_swap)),
            description=tr("st_pe2 retire le label de l'aller"),
        )
        self.add_grade_element(
            title=no_tr("st_back"), max_grade=3, grade_part=part1,
            grade=int(_route_via(st_k['st_pe2'], lan1, [d.st_back], addr('st_p', 'st_l2')))
            + 2 * int(mpls_route_is_pop(st_ilm['st_p'], d.st_back, via=addr('st_pe1', 'st_l1'))),
            description=tr("retour : imposition par st_pe2, PHP sur st_p"),
        )
        self.add_grade_element(
            title=no_tr("st_ping"), max_grade=3, grade_part=part1, grade=3 * int(st_code == 0),
            description=tr("st_h1 joint st_h2"),
        )
        self.add_grade_element(
            title=no_tr("st_q_ethertype"), max_grade=1, grade_part=part1,
            grade=int(_hex(q1.get('ethertype')) == 0x8847), description=tr("EtherType de MPLS"),
        )
        self.add_grade_element(
            title=no_tr("st_q_max_label"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get('max_label')) == 2 ** 20 - 1), description=tr("plus grand label"),
        )
        self.add_grade_element(
            title=no_tr("st_q_hops"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get('hops')) == 5), description=tr("lignes du traceroute"),
        )

        # =====================================================================
        # Part 2 — LDP (ldp)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("ldp"), tr("Partie 2 — LDP (site ldp)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Distribuer les labels avec LDP"),
            hash="392b33d9bc72e5ee",
            description=tr("""
Les routeurs `ldp_pe1`, `ldp_p1`, `ldp_p2` et `ldp_pe2` forment une ligne ; l'hôte `ldp_h1` est
derrière `ldp_pe1`, l'hôte `ldp_h2` derrière `ldp_pe2`. OSPF fonctionne, MPLS est activé dans les
noyaux et `ldpd` tourne, mais LDP n'est pas configuré (sections @@ref:ldp@@ et @@ref:ldp-frr@@).

1. Configurez LDP sur les quatre routeurs : LSR-ID et adresse de transport égaux à l'adresse de
   l'interface de bouclage, LDP seulement sur les interfaces qui mènent à un autre routeur (pas
   sur les réseaux des hôtes). Suivez `show mpls ldp discovery` et `show mpls ldp neighbor`.
2. Observez la LIB (`show mpls ldp binding`), la LFIB (`show mpls table`, `ip -f mpls route`) et
   les routes qui imposent un label (`ip route`). Suivez les labels qu'utilisent les paquets vers
   l'interface de bouclage de `ldp_pe2`, de `ldp_pe1` jusqu'à `ldp_pe2` : que fait `ldp_p2` ?
3. LDP alloue un label à chaque préfixe, même aux liens entre routeurs. Sur les quatre routeurs,
   n'allouez plus de label qu'aux interfaces de bouclage (`{lo_block}`) et aux deux réseaux des
   hôtes, avec une liste d'accès. Vérifiez que les liens ont disparu de la LIB.
4. Lancez `traceroute -n ldp_h2` depuis `ldp_h1` : d'où viennent les étoiles ? Cessez de propager
   le TTL sur les deux routeurs d'entrée, `ldp_pe1` et `ldp_pe2` (section @@ref:mpls-ttl@@), puis
   relancez-le.
""").format(lo_block=net('ldp_lo'))
            + instructor(_by_language(tr("""
**Solution.**

{solution}

Puis, sur `ldp_pe1` et `ldp_pe2` :

```
sysctl -w net.mpls.ip_ttl_propagate=0
```

Vers l'interface de bouclage de `ldp_pe2`, `ldp_pe1` impose le label local de `ldp_p1`, que
`ldp_p1` échange contre le label local de `ldp_p2` ; `ldp_p2` a reçu *implicit-null* (3) de
`ldp_pe2` : il retire le label (PHP). Avant le changement, le `traceroute` montre `ldp_pe1`, deux
étoiles (`ldp_p1`, `ldp_p2` jettent les paquets dont le TTL de label expire), `ldp_pe2`, `ldp_h2` ;
après, seulement `ldp_pe1` et `ldp_h2` : le label part avec un TTL de 255, et `ldp_p2` redonne ce
TTL au paquet IP en retirant le label.

Évaluation : `ldp_sessions` (6 : 2 par session), `ldp_identity` (4 : LSR-ID et adresse de transport
de chaque routeur, vus par un voisin), `ldp_core_only` (2 : LDP absent de l'`eth0` de `ldp_pe1` et
de `ldp_pe2`), `ldp_lfib` (3 : la chaîne des labels vers l'interface de bouclage de `ldp_pe2`),
`ldp_traffic` (3 : ping `ldp_h1` → `ldp_h2` avec des paquets étiquetés reçus par `ldp_p1` et
`ldp_p2`), `ldp_filter` (4 : un point par routeur dont la LIB n'a aucun lien mais toutes les
interfaces de bouclage et les deux réseaux d'hôtes), `ldp_ttl` (3 : le réglage sur les deux
routeurs d'entrée, puis un `traceroute` sans étoile par un LSP).
"""), solution=_vtysh_text(ns.solution_ldp()))),
        )
        cheat_ldp = {'php_label': '3', 'port': '646', 'hops': '2'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site ldp"),
            hash="6d350d4b9509d73f",
            description=tr("""
- valeur du label sortant de `ldp_p2` pour l'interface de bouclage de `ldp_pe2` (un nombre) :
  @@{php_label:[0-9]+}@@
- port TCP des sessions LDP : @@{port:[0-9]+}@@
- nombre de lignes de sauts du `traceroute -n ldp_h2` lancé depuis `ldp_h1`, une fois la
  propagation du TTL coupée sur les routeurs d'entrée : @@{hops:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **3** (*implicit-null* : `ldp_p2` retire le label) ; **646** ; **2** lignes
(`ldp_pe1` puis `ldp_h2`).

Évaluation : `ldp_q_php_label`, `ldp_q_port`, `ldp_q_hops` (1 chacun).
""")),
            cheat_answers={"final": cheat_ldp, "solve_ldp": cheat_ldp},
        )
        pairs = (('ldp_pe1', 'ldp_p1'), ('ldp_p1', 'ldp_p2'), ('ldp_p2', 'ldp_pe2'))
        sessions = [self._session(ldp_nb[a], b) or self._session(ldp_nb[b], a) for a, b in pairs]
        self.add_grade_element(
            title=no_tr("ldp_sessions"), max_grade=6, grade_part=part2, grade=2 * sum(sessions),
            description=tr("trois sessions LDP établies"),
        )
        line_neighbors = {'ldp_pe1': ['ldp_p1'], 'ldp_p1': ['ldp_pe1', 'ldp_p2'], 'ldp_p2': ['ldp_p1', 'ldp_pe2'],
                          'ldp_pe2': ['ldp_p2']}
        identity = [any(str((ldp_nb[n].get(str(lo(r))) or {}).get('transport_address')) == str(lo(r))
                        for n in line_neighbors[r]) for r in ldp]
        self.add_grade_element(
            title=no_tr("ldp_identity"), max_grade=4, grade_part=part2, grade=sum(identity),
            description=tr("LSR-ID et adresse de transport sur l'interface de bouclage"),
        )
        core_only = [sessions[0 if r == 'ldp_pe1' else 2]
                     and 'eth0' not in (ldp_cfg[r].get('mpls_ldp') or {}).get('interfaces', ['eth0'])
                     for r in ('ldp_pe1', 'ldp_pe2')]
        self.add_grade_element(
            title=no_tr("ldp_core_only"), max_grade=2, grade_part=part2, grade=sum(core_only),
            description=tr("pas de LDP sur les réseaux des hôtes"),
        )
        fec = f"{lo('ldp_pe2')}/32"
        l1 = (ldp_bind['ldp_p1'].get(fec) or {}).get('local')
        l2 = (ldp_bind['ldp_p2'].get(fec) or {}).get('local')
        chain = [l1 not in (None, 3) and _route_via(ldp_k, fec, [l1], addr('ldp_p1', 'ldp_l1')),
                 l1 not in (None, 3) and l2 not in (None, 3) and mpls_route_is_swap(ldp_ilm['ldp_p1'], l1, [l2]),
                 l2 not in (None, 3) and mpls_route_is_pop(ldp_ilm['ldp_p2'], l2, via=addr('ldp_pe2', 'ldp_l3'))]
        self.add_grade_element(
            title=no_tr("ldp_lfib"), max_grade=3, grade_part=part2, grade=sum(chain),
            description=tr("labels vers ldp_pe2 : imposition, échange, PHP"),
        )
        self.add_grade_element(
            title=no_tr("ldp_traffic"), max_grade=3, grade_part=part2,
            grade=3 * int(ldp_ping and all(v >= 5 for v in ldp_delta.values())),
            description=tr("ldp_h1 joint ldp_h2 par un LSP"),
        )
        links = {str(net(n)) for n in LINKS if site_of(n) == 'ldp'}
        wanted = {f"{lo(r)}/32" for r in ldp} | {str(net('ldp_lan1')), str(net('ldp_lan2'))}
        filtered = [bool(ldp_bind[r]) and not (set(ldp_bind[r]) & links) and wanted <= set(ldp_bind[r]) for r in ldp]
        self.add_grade_element(
            title=no_tr("ldp_filter"), max_grade=4, grade_part=part2, grade=sum(filtered),
            description=tr("labels seulement pour les interfaces de bouclage et les réseaux des hôtes"),
        )
        hops = _traceroute_hops(trace_out)
        traced = (bool(hops) and hops[-1] == str(d.ips.ldp_h2.ip) and '*' not in hops
                  and any(kernel_route_labels(ldp_k, net('ldp_lan2'))))
        self.add_grade_element(
            title=no_tr("ldp_ttl"), max_grade=3, grade_part=part2,
            grade=int(ldp_sys['ldp_pe1'].get('ip_ttl_propagate') == 0)
            + int(ldp_sys['ldp_pe2'].get('ip_ttl_propagate') == 0) + int(traced),
            description=tr("TTL non propagé sur les routeurs d'entrée"),
        )
        self.add_grade_element(
            title=no_tr("ldp_q_php_label"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get('php_label')) == 3), description=tr("label implicit-null"),
        )
        self.add_grade_element(
            title=no_tr("ldp_q_port"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get('port')) == 646), description=tr("port de LDP"),
        )
        self.add_grade_element(
            title=no_tr("ldp_q_hops"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get('hops')) == 2), description=tr("lignes du traceroute sans propagation"),
        )

        # =====================================================================
        # Part 3 — segment routing (sr)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("sr"), tr("Partie 3 — segment routing (site sr)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le segment routing dans OSPF"),
            hash="63570fff59fead06",
            description=tr("""
Les routeurs `sr_r1`, `sr_r2`, `sr_r3` et `sr_r4` forment une ligne (liens `sr_l1`, `sr_l2`,
`sr_l3`). OSPF fonctionne et MPLS est activé dans les noyaux ; il n'y a pas de LDP (sections
@@ref:sr@@ et @@ref:sr-frr@@).

1. Activez le segment routing dans OSPF sur les quatre routeurs, avec le SRGB et l'index de
   prefix-SID donnés dans l'organisation du TP (`sr_r3` n'a pas le même SRGB que les autres).
2. Observez `show ip ospf database segment-routing`, `show mpls table`, `ip -f mpls route` et
   `ip route` sur chaque routeur. Calculez les labels utilisés de `sr_r1` vers `sr_r4`, lien par
   lien, et comparez.
3. `sr_r4` veut recevoir les paquets qui lui sont destinés avec leur label : annoncez son prefix-SID
   **sans PHP**. Qu'est-ce qui change sur `sr_r3` ?
4. Depuis `sr_r1`, faites un `ping` de l'interface de bouclage de `sr_r4` **depuis sa propre
   interface de bouclage** (`ping -I {lo1} {lo4}`) et regardez les labels sur chaque lien
   (`tcpdump -nei eth0 mpls`).
""").format(lo1=lo('sr_r1'), lo4=lo('sr_r4'))
            + instructor(_by_language(tr("""
**Solution.**

{solution}

Le label se calcule avec le SRGB du routeur **suivant** : `sr_r1` impose {srgb} + {i4} =
**{l_r1}** pour joindre `sr_r4` ; `sr_r2` l'échange contre {srgb3} + {i4} = **{l_r2}** (le SRGB de
`sr_r3`) ; sans PHP, `sr_r3` l'échange contre {srgb} + {i4} = **{l_r1}** (le SRGB de `sr_r4`),
que `sr_r4` retire (`dev lo`). Avec le PHP, `sr_r3` retirait le label. Vers `sr_r3`, `sr_r1`
impose {srgb} + {i3} = **{l_r3}**, que `sr_r2` retire.

Évaluation : `sr_enabled` (4 : un point par routeur présent dans sa propre base SR), `sr_srgb` (3 :
2 pour `sr_r3`, 1 pour les trois autres ensemble), `sr_index` (4 : un point par prefix-SID),
`sr_r2_lfib` (3 : l'échange de `sr_r2`), `sr_r1_ftn` (3 : la route de `sr_r1` vers `sr_r4`),
`sr_ping` (3 : ping entre les interfaces de bouclage, avec des paquets étiquetés reçus par `sr_r2`
et `sr_r3`), `sr_no_php` (2 : l'échange de `sr_r3`, le retrait par `sr_r4`).
"""), solution=_vtysh_text(ns.solution_sr()), srgb=d.sr_srgb, srgb3=d.sr_srgb_r3, i3=i3, i4=i4,
            l_r1=d.sr_srgb + i4, l_r2=d.sr_srgb_r3 + i4, l_r3=d.sr_srgb + i3)),
        )
        cheat_sr = {'push4': str(d.sr_srgb + i4), 'label_l2': str(d.sr_srgb_r3 + i4), 'push3': str(d.sr_srgb + i3),
                    'label_l3': str(d.sr_srgb + i4)}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Les labels du segment routing"),
            hash="ae8f2180cd9fd39b",
            description=tr("""
Calculez-les avant de les observer :

- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r4` :
  @@{push4:[0-9]+}@@
- label de ces paquets sur le lien `sr_l2` (de `sr_r2` vers `sr_r3`) : @@{label_l2:[0-9]+}@@
- label de ces paquets sur le lien `sr_l3` (de `sr_r3` vers `sr_r4`), une fois le PHP refusé par
  `sr_r4` : @@{label_l3:[0-9]+}@@
- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r3` :
  @@{push3:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **{push4}**, **{label_l2}**, **{label_l3}**, **{push3}** (voir la question
précédente).

Évaluation : `sr_q_push4`, `sr_q_label_l2` (2 chacun), `sr_q_label_l3`, `sr_q_push3` (1 chacun).
""").format(**cheat_sr)),
            cheat_answers={"final": cheat_sr, "solve_sr": cheat_sr},
        )
        own = {r: sr_db[r].get(str(lo(r))) or {} for r in sr}
        self.add_grade_element(
            title=no_tr("sr_enabled"), max_grade=4, grade_part=part3, grade=sum(bool(own[r]) for r in sr),
            description=tr("segment routing actif sur les quatre routeurs"),
        )
        srgb_ok = {r: own[r].get('srgb') == (d.sr_base(r), SRGB_SIZE) for r in sr}
        self.add_grade_element(
            title=no_tr("sr_srgb"), max_grade=3, grade_part=part3,
            grade=2 * int(srgb_ok['sr_r3']) + int(srgb_ok['sr_r1'] and srgb_ok['sr_r2'] and srgb_ok['sr_r4']),
            description=tr("SRGB donnés"),
        )
        index_ok = [((own[r].get('prefixes') or {}).get(f"{lo(r)}/32") or {}).get('index') == d.sr_index(r)
                    for r in sr]
        self.add_grade_element(
            title=no_tr("sr_index"), max_grade=4, grade_part=part3, grade=sum(index_ok),
            description=tr("prefix-SID des interfaces de bouclage"),
        )
        self.add_grade_element(
            title=no_tr("sr_r2_lfib"), max_grade=3, grade_part=part3,
            grade=3 * int(mpls_route_is_swap(sr_ilm['sr_r2'], d.sr_srgb + i4, [d.sr_srgb_r3 + i4],
                                             addr('sr_r3', 'sr_l2'))),
            description=tr("sr_r2 : échange vers le SRGB de sr_r3"),
        )
        self.add_grade_element(
            title=no_tr("sr_r1_ftn"), max_grade=3, grade_part=part3,
            grade=3 * int(_route_via(sr_k, f"{lo('sr_r4')}/32", [d.sr_srgb + i4], addr('sr_r2', 'sr_l1'))),
            description=tr("sr_r1 : label imposé vers sr_r4"),
        )
        self.add_grade_element(
            title=no_tr("sr_ping"), max_grade=3, grade_part=part3,
            grade=3 * int(sr_ping and all(v >= 5 for v in sr_delta.values())),
            description=tr("ping étiqueté entre les interfaces de bouclage"),
        )
        self.add_grade_element(
            title=no_tr("sr_no_php"), max_grade=2, grade_part=part3,
            grade=int(mpls_route_is_swap(sr_ilm['sr_r3'], d.sr_srgb_r3 + i4, [d.sr_srgb + i4], addr('sr_r4', 'sr_l3')))
            + int(mpls_route_is_pop(sr_ilm['sr_r4'], d.sr_srgb + i4, dev='lo')),
            description=tr("pas de PHP pour sr_r4"),
        )
        for key, points, label in (('push4', 2, tr("label imposé vers sr_r4")), ('label_l2', 2, tr("label sur sr_l2")),
                                   ('label_l3', 1, tr("label sur sr_l3")), ('push3', 1, tr("label imposé vers sr_r3"))):
            self.add_grade_element(
                title=no_tr(f"sr_q_{key}"), max_grade=points, grade_part=part3,
                grade=points * int(_int(q3.get(key)) == int(cheat_sr[key])), description=label,
            )

        # =====================================================================
        # Part 4 — troubleshooting (fix)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("fix"), tr("Partie 4 — dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un cœur MPLS en panne"),
            hash="27b472fe1b836881",
            description=tr("""
Le site `fix` reprend le site `ldp` : `fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2` en ligne, les hôtes
`fix_h1` et `fix_h2`, OSPF et LDP configurés (sans filtre de labels), MPLS activé dans les noyaux.
Pourtant `fix_h1` ne joint pas `fix_h2` : **quatre pannes** ont été glissées dans la configuration
(section @@ref:mpls-debug@@).

Le site doit fonctionner ainsi : `fix_h1` joint `fix_h2`, les **trois sessions LDP** sont établies et
les paquets entre les hôtes sont **étiquetés de bout en bout** (`fix_p1` et `fix_p2` reçoivent des
paquets étiquetés). Trouvez et corrigez chaque panne sans tout reconfigurer : suivez la méthode du
cours, du plan de contrôle au plan de données.

Attention : quand on agrandit la table des labels d'un routeur après coup, zebra ne réinstalle ses
labels dans le noyau qu'au prochain changement de ses LSP (`clear mpls ldp neighbor`).
""")
            + instructor(_by_language(tr("""
**Solution.**

`fix_p1` (paquets étiquetés jetés à l'entrée d'`eth0`) :

```
sysctl -w net.mpls.conf.eth0.input=1
```

`fix_p2` (aucun label accepté par le noyau : `show mpls table` correcte mais `ip -f mpls route`
vide ; et `eth0` absente de `mpls ldp`, donc pas de session avec `fix_p1`) :

```
sysctl -w net.mpls.platform_labels={labels}
vtysh -c "clear mpls ldp neighbor"
```

{solution_p2}

`fix_pe2` (son adresse de transport, l'interface de bouclage, n'est pas dans OSPF : adjacence avec
`fix_p2` mais pas de session) :

{solution_pe2}

Évaluation : `fix_input` (3), `fix_labels` (3 : 1 pour la table des labels de `fix_p2`, 2 pour des
labels réellement installés dans son noyau), `fix_interface` (3 : 1 pour l'adjacence sur `eth0` de
`fix_p2`, 2 pour la session avec `fix_p1`), `fix_transport` (3 : session `fix_p2` – `fix_pe2`),
`fix_ping` (4), `fix_labelled` (4 : 2 par routeur du cœur qui reçoit des paquets étiquetés pendant
le ping) ; pour l'enseignant seulement : `fix_q_input`, `fix_q_session` (1 chacun).
"""), labels=PLATFORM_LABELS,
            solution_p2=_vtysh_text({'fix_p2': ns.solution_fix()['fix_p2'][1][1]}),
            solution_pe2=_vtysh_text({'fix_pe2': ns.solution_fix()['fix_pe2'][0][1]}))),
        )
        cheat_fix = {'input': 'dropped', 'session': 'hello_only'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Ce que montraient les pannes"),
            hash="1da57ff52b93d397",
            description=tr("""
- un paquet étiqueté qui arrive sur une interface dont `net.mpls.conf.<interface>.input` vaut 0 :
  @@{input:>est jeté>>>dropped|est routé en IP>>>routed|perd son label puis est routé>>>popped|est renvoyé à l'émetteur>>>returned}@@
- avant la correction, entre `fix_p2` et `fix_pe2`, il y avait :
  @@{session:>une adjacence Hello, mais pas de session>>>hello_only|ni adjacence ni session>>>nothing|une session établie sans aucun label>>>no_label|une session refusée faute de mot de passe>>>password}@@
""")
            + instructor(tr("""
**Solution.** Il **est jeté** (compté dans les erreurs de réception de l'interface) ; **une
adjacence Hello, mais pas de session** : `fix_p2` ne peut pas joindre l'adresse de transport de
`fix_pe2`.

Évaluation, pour l'enseignant seulement : `fix_q_input`, `fix_q_session` (1 chacun).
""")),
            cheat_answers={"final": cheat_fix, "solve_fix": cheat_fix},
        )
        self.add_grade_element(
            title=no_tr("fix_input"), max_grade=3, grade_part=part4,
            grade=3 * int(fix_sys['fix_p1']['input'].get('eth0') == 1),
            description=tr("entrée MPLS d'eth0 sur fix_p1"),
        )
        self.add_grade_element(
            title=no_tr("fix_labels"), max_grade=3, grade_part=part4,
            grade=int((fix_sys['fix_p2'].get('platform_labels') or 0) > 0) + 2 * int(bool(fix_ilm)),
            description=tr("labels acceptés et installés sur fix_p2"),
        )
        adjacency = str(lo('fix_p1')) in fix_disc.get('eth0', [])
        self.add_grade_element(
            title=no_tr("fix_interface"), max_grade=3, grade_part=part4,
            grade=int(adjacency) + 2 * int(self._session(fix_nb, 'fix_p1')),
            description=tr("LDP entre fix_p1 et fix_p2"),
        )
        self.add_grade_element(
            title=no_tr("fix_transport"), max_grade=3, grade_part=part4,
            grade=3 * int(self._session(fix_nb, 'fix_pe2')), description=tr("session LDP entre fix_p2 et fix_pe2"),
        )
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=4, grade_part=part4, grade=4 * int(fix_ping),
            description=tr("fix_h1 joint fix_h2"),
        )
        self.add_grade_element(
            title=no_tr("fix_labelled"), max_grade=4, grade_part=part4,
            grade=sum(2 * int(fix_ping and v >= 5) for v in fix_delta.values()),
            description=tr("trafic étiqueté sur tout le chemin"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_input"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get('input')) == cheat_fix['input']), description=tr("paquet reçu avec input à 0"),
        )
        self.add_grade_element(
            title=no_tr("fix_q_session"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get('session')) == cheat_fix['session']), description=tr("adjacence sans session"),
        )

        # =====================================================================
        # Part 5 — TI-LFA (tl, bonus)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("tilfa"), tr("Partie 5 — TI-LFA (site tl, bonus)"))
        r3 = f"{lo('tl_r3')}/32"
        costs = ", ".join(f"`{n}` {c}" for n, c in TL_COSTS.items())
        self.question_dummy(
            section=self.section(0),
            title=tr("Protection TI-LFA (bonus)"),
            hash="a571d3d63d091433",
            description=tr("""
Les routeurs `tl_r1`, `tl_r2`, `tl_r3` et `tl_r4` forment un carré (coûts OSPF : {costs}). OSPF et
le segment routing y fonctionnent (SRGB par défaut, 16000 à 23999 ; l'index du prefix-SID de
`tl_rN` est N). Seul `tl_r1` a un terminal ; il joint `tl_r3` par `tl_r2` (section @@ref:tilfa@@).

1. Regardez la route de `tl_r1` vers l'interface de bouclage de `tl_r3` (`show ip route {r3}`).
2. Activez sur `tl_r1` la protection TI-LFA **de nœud** : le secours doit éviter `tl_r2` tout
   entier.
3. Regardez à nouveau la route : par où passe le secours, avec quelle pile de labels ? Que
   désignent ces labels ?
""").format(costs=costs, r3=r3)
            + instructor(_by_language(tr("""
**Solution.**

{solution}

Le secours vers `{r3}` part vers `tl_r4` (`eth1`) avec une pile de deux labels qui se termine par
le node-SID de `tl_r3` (16003) ; le premier est un adjacency-SID, qui force le passage de `tl_r4`
vers `tl_r3`.

Évaluation (bonus) : `tl_backup` (3 : une route de secours vers `tl_r3`), `tl_node` (1 : protection
de nœud), `tl_repair` (2 : secours par `tl_r4`, pile terminée par le node-SID de `tl_r3`).
"""), solution=_vtysh_text(ns.solution_tilfa()), r3=r3)),
        )
        backups = (tl_routes.get(r3) or {}).get('backups', [])
        self.add_grade_element(
            title=no_tr("tl_backup"), max_grade=3, grade_part=part5, bonus=True, grade=3 * int(bool(backups)),
            description=tr("route de secours vers tl_r3"),
        )
        self.add_grade_element(
            title=no_tr("tl_node"), max_grade=1, grade_part=part5, bonus=True,
            grade=int(bool(backups) and (tl_cfg.get('router_ospf') or {}).get('ti_lfa') == 'node'),
            description=tr("protection de nœud"),
        )
        self.add_grade_element(
            title=no_tr("tl_repair"), max_grade=2, grade_part=part5, bonus=True,
            grade=2 * int(any(b['interface'] == iface('tl_r1', 'tl_l14') and b['labels']
                              and b['labels'][-1] == TL_SRGB_BASE + LOOPBACKS['tl_r3'] for b in backups)),
            description=tr("secours par tl_r4 vers le node-SID de tl_r3"),
        )


_TRANSLATIONS = {'en': {
    "MPLS : commutation de labels, LDP et segment routing": "MPLS: label switching, LDP and segment routing",
    """
**Sommaire**
""": """
**Contents**
""",
    "Pourquoi MPLS": "Why MPLS",
    """
Un routeur IP cherche, pour chaque paquet, la route la plus spécifique qui contient l'adresse de
destination. **MPLS** (*MultiProtocol Label Switching*, RFC 3031) sépare le choix du chemin de
l'acheminement :

- le routeur d'**entrée** classe le paquet une seule fois dans une **FEC** (*Forwarding
  Equivalence Class* : par exemple « tous les paquets vers tel préfixe ») et lui colle un
  **label**, un entier court ;
- les routeurs du **cœur** commutent sur ce label (recherche exacte dans une table, sans regarder
  l'en-tête IP) et le remplacent par le label que le routeur suivant attend ;
- le routeur de **sortie** retire le label et rend le paquet à IP.

Vocabulaire : un **LSR** (*Label Switching Router*) commute des labels ; un **LER** (*Label Edge
Router*) est en bordure (entrée ou sortie). Chez un opérateur on parle de routeurs **PE**
(*Provider Edge*), **P** (*Provider*, le cœur) et **CE** (*Customer Edge*, chez le client). Le
chemin suivi par les paquets d'une FEC est un **LSP** (*Label Switched Path*) ; il est
**unidirectionnel** : l'aller et le retour sont deux LSP.

La commutation de labels n'est plus plus rapide qu'une recherche IP. MPLS sert parce que le cœur
n'a plus besoin de connaître les destinations finales : seulement comment joindre les routeurs de
sortie. Cela permet un cœur sans BGP, les **VPN** (L3VPN, L2VPN : une pile de labels), l'**ingénierie
de trafic** (des chemins choisis à l'entrée) et la **protection rapide** (des chemins de secours
calculés d'avance).
""": """
An IP router looks up, for each packet, the most specific route containing the destination
address. **MPLS** (*MultiProtocol Label Switching*, RFC 3031) separates the choice of the path
from the forwarding:

- the **ingress** router classifies the packet once into a **FEC** (*Forwarding Equivalence
  Class*: for example "every packet towards a given prefix") and attaches a **label** to it, a
  short integer;
- the **core** routers switch on that label (an exact-match lookup in a table, without looking at
  the IP header) and replace it with the label the next router expects;
- the **egress** router removes the label and hands the packet back to IP.

Vocabulary: an **LSR** (*Label Switching Router*) switches labels; an **LER** (*Label Edge
Router*) sits at the edge (ingress or egress). At a service provider one speaks of **PE** routers
(*Provider Edge*), **P** routers (*Provider*, the core) and **CE** routers (*Customer Edge*, at
the customer's site). The path followed by the packets of a FEC is an **LSP** (*Label Switched
Path*); it is **unidirectional**: the forward and the return directions are two LSPs.

Label switching is no longer faster than an IP lookup. MPLS is useful because the core no longer
needs to know the final destinations: only how to reach the egress routers. This allows a core
without BGP, **VPNs** (L3VPN, L2VPN: a stack of labels), **traffic engineering** (paths chosen at
the ingress) and **fast protection** (backup paths computed in advance).
""",
    "L'en-tête MPLS": "The MPLS header",
    """
MPLS ajoute un en-tête de 32 bits (le *shim header*) entre l'en-tête de niveau 2 et le paquet IP :

| champ | bits | rôle |
|-------|------|------|
| Label | 20 | la valeur commutée |
| TC (ex-EXP) | 3 | classe de trafic (qualité de service) |
| S | 1 | *bottom of stack* : 1 sur le dernier label de la pile |
| TTL | 8 | durée de vie, décrémentée à chaque saut comme celle d'IP |

- Sur Ethernet, l'**EtherType** d'une trame MPLS est `0x8847` (`0x8848` pour le multicast MPLS,
  rare).
- Un paquet peut porter une **pile** de labels : plusieurs en-têtes à la suite, le bit S à 1 sur
  le dernier. Un routeur ne regarde que le label du **sommet** de la pile (les VPN et le segment
  routing empilent plusieurs labels).
- Les labels **0 à 15 sont réservés** : 0 *IPv4 Explicit NULL*, 1 *Router Alert*, 2 *IPv6
  Explicit NULL*, 3 *Implicit NULL* (jamais dans un paquet : il est seulement annoncé et signifie
  « retire le label »), 7 *Entropy Label Indicator*, 13 *GAL*, 14 *OAM*. Les labels utilisables
  vont de 16 à 2^20 − 1.
""": """
MPLS adds a 32-bit header (the *shim header*) between the layer 2 header and the IP packet:

| field | bits | role |
|-------|------|------|
| Label | 20 | the switched value |
| TC (formerly EXP) | 3 | traffic class (quality of service) |
| S | 1 | *bottom of stack*: 1 on the last label of the stack |
| TTL | 8 | time to live, decremented at each hop like the IP one |

- On Ethernet, the **EtherType** of an MPLS frame is `0x8847` (`0x8848` for MPLS multicast,
  rare).
- A packet can carry a **stack** of labels: several headers in a row, with the S bit set to 1 on
  the last one. A router only looks at the label at the **top** of the stack (VPNs and segment
  routing stack several labels).
- Labels **0 to 15 are reserved**: 0 *IPv4 Explicit NULL*, 1 *Router Alert*, 2 *IPv6
  Explicit NULL*, 3 *Implicit NULL* (never in a packet: it is only advertised and means
  "remove the label"), 7 *Entropy Label Indicator*, 13 *GAL*, 14 *OAM*. The usable labels
  range from 16 to 2^20 − 1.
""",
    "Opérations et tables": "Operations and tables",
    """
Trois opérations sur le label du sommet :

- **push** (imposition) : ajouter un label, au routeur d'entrée ;
- **swap** : remplacer le label reçu par celui que le routeur suivant a choisi ;
- **pop** (disposition) : retirer le label.

Les tables qui les décrivent :

- **FTN** (*FEC To NHLFE*), au routeur d'entrée : une route IP qui dit « pour ce préfixe, impose
  tel label et envoie à tel voisin » ;
- **ILM** (*Incoming Label Map*), sur chaque LSR : pour chaque label reçu, un **NHLFE** (*Next Hop
  Label Forwarding Entry* : le voisin suivant et l'opération). L'ILM et les NHLFE forment la
  **LFIB** (*Label Forwarding Information Base*), la table d'acheminement ;
- la **LIB** (*Label Information Base*) d'un protocole de distribution contient tous les labels
  appris de tous les voisins, même ceux qui ne servent pas.

Un label n'a qu'une **signification locale** : chaque LSR choisit les labels qu'il **reçoit**, et
son voisin en amont doit utiliser ce choix (allocation par l'aval, *downstream*). Le même LSP
change donc de label à chaque saut.

**PHP** (*Penultimate Hop Popping*) : l'avant-dernier routeur retire le label, pour que le routeur
de sortie ne fasse qu'une recherche (IP) au lieu de deux (label puis IP). Le routeur de sortie le
demande en annonçant le label **implicit-null** (3) pour ses propres préfixes. Avec
**explicit-null** (0), il reçoit un label jusqu'au bout (pour garder la classe TC) et le retire
lui-même. Sans PHP (*ultimate hop popping*), le routeur de sortie reçoit un label ordinaire,
le retire puis consulte sa table IP.
""": """
Three operations on the top label:

- **push** (imposition): add a label, at the ingress router;
- **swap**: replace the received label with the one the next router has chosen;
- **pop** (disposition): remove the label.

The tables that describe them:

- **FTN** (*FEC To NHLFE*), at the ingress router: an IP route that says "for this prefix, push
  this label and send to this neighbour";
- **ILM** (*Incoming Label Map*), on each LSR: for each received label, an **NHLFE** (*Next Hop
  Label Forwarding Entry*: the next neighbour and the operation). The ILM and the NHLFEs make up
  the **LFIB** (*Label Forwarding Information Base*), the forwarding table;
- the **LIB** (*Label Information Base*) of a distribution protocol holds every label learnt from
  every neighbour, even those that are not used.

A label only has **local significance**: each LSR chooses the labels it **receives**, and its
upstream neighbour must use that choice (allocation by the downstream router, *downstream*). The
same LSP therefore changes label at each hop.

**PHP** (*Penultimate Hop Popping*): the penultimate router removes the label, so that the egress
router performs a single lookup (IP) instead of two (label then IP). The egress router asks for it
by advertising the **implicit-null** label (3) for its own prefixes. With **explicit-null** (0),
it receives a label all the way (to keep the TC class) and removes it itself. Without PHP
(*ultimate hop popping*), the egress router receives an ordinary label, removes it and then looks
up its IP table.
""",
    "MPLS sous Linux": "MPLS on Linux",
    """
Le noyau Linux commute des labels depuis la version 4.1 : modules `mpls_router` (la LFIB) et
`mpls_iptunnel` (l'imposition sur une route IP), déjà chargés pour le TP. Le réglage est propre à
chaque espace de noms réseau, donc à chaque machine :

| sysctl | rôle |
|--------|------|
| `net.mpls.platform_labels` | taille de la table des labels : le noyau accepte les labels 0 à N − 1 ; **0 par défaut** (aucun label accepté) |
| `net.mpls.conf.<interface>.input` | accepter les paquets étiquetés reçus sur l'interface ; **0 par défaut** : ils sont jetés |
| `net.mpls.ip_ttl_propagate` | copier le TTL IP dans le label à l'entrée (1 par défaut), voir section @@ref:mpls-ttl@@ |
| `net.mpls.default_ttl` | TTL du label quand il n'est pas copié (255) |

Un routeur qui **reçoit** des paquets étiquetés a besoin des deux premiers réglages ; un routeur qui
ne fait qu'imposer des labels n'en a pas besoin. Dans les machines du TP, `/proc/sys` est déjà
accessible en écriture.

```
sysctl -w net.mpls.platform_labels=1000
sysctl -w net.mpls.conf.eth1.input=1

# FTN : une route IP qui impose un label (ou une pile : 100/200)
ip route add 10.1.2.0/24 encap mpls 100 via 10.1.0.2 dev eth1

# ILM : échange, retrait vers un voisin (PHP), retrait puis livraison locale
ip -f mpls route add 100 as 200 via inet 10.1.0.6 dev eth2
ip -f mpls route add 300 via inet 10.1.0.1 dev eth1
ip -f mpls route add 200 dev lo

ip -f mpls route show
ip route show
```

`via inet` désigne le voisin par son adresse IPv4. Une entrée sans `as` retire le label ; avec
`dev lo`, le paquet IP est rendu à la machine, qui le route ensuite comme s'il venait d'arriver.

Pour voir passer les labels : `tcpdump -nei eth1 mpls` affiche `MPLS (label 100, tc 0, [S], ttl
63)`. Les compteurs MPLS d'une interface : `ip stats show dev eth1 group afstats subgroup mpls`
(`RX errors` compte entre autres les TTL expirés, `noroute` les labels inconnus).

Les démons de FRR (`ldpd`, `ospfd`) remplissent ces mêmes tables par l'intermédiaire de `zebra` :
leurs entrées apparaissent avec `proto ldp` ou `proto ospf`.
""": """
The Linux kernel has switched labels since version 4.1: modules `mpls_router` (the LFIB) and
`mpls_iptunnel` (the imposition on an IP route), already loaded for the lab. The settings belong
to each network namespace, hence to each machine:

| sysctl | role |
|--------|------|
| `net.mpls.platform_labels` | size of the label table: the kernel accepts labels 0 to N − 1; **0 by default** (no label accepted) |
| `net.mpls.conf.<interface>.input` | accept the labelled packets received on the interface; **0 by default**: they are dropped |
| `net.mpls.ip_ttl_propagate` | copy the IP TTL into the label at the ingress (1 by default), see section @@ref:mpls-ttl@@ |
| `net.mpls.default_ttl` | TTL of the label when it is not copied (255) |

A router that **receives** labelled packets needs the first two settings; a router that only
pushes labels does not. In the machines of the lab, `/proc/sys` is already writable.

```
sysctl -w net.mpls.platform_labels=1000
sysctl -w net.mpls.conf.eth1.input=1

# FTN: an IP route that pushes a label (or a stack: 100/200)
ip route add 10.1.2.0/24 encap mpls 100 via 10.1.0.2 dev eth1

# ILM: swap, pop towards a neighbour (PHP), pop then local delivery
ip -f mpls route add 100 as 200 via inet 10.1.0.6 dev eth2
ip -f mpls route add 300 via inet 10.1.0.1 dev eth1
ip -f mpls route add 200 dev lo

ip -f mpls route show
ip route show
```

`via inet` designates the neighbour by its IPv4 address. An entry without `as` removes the label;
with `dev lo`, the IP packet is handed back to the machine, which then routes it as if it had just
arrived.

To watch the labels go by: `tcpdump -nei eth1 mpls` shows `MPLS (label 100, tc 0, [S], ttl
63)`. The MPLS counters of an interface: `ip stats show dev eth1 group afstats subgroup mpls`
(`RX errors` counts, among other things, the expired TTLs, `noroute` the unknown labels).

The FRR daemons (`ldpd`, `ospfd`) fill these same tables through `zebra`: their entries appear
with `proto ldp` or `proto ospf`.
""",
    "LDP": "LDP",
    """
Écrire les tables à la main ne passe pas à l'échelle. **LDP** (*Label Distribution Protocol*, RFC
5036) distribue automatiquement des labels pour les **préfixes de la table de routage** : chaque LSP
suit le plus court chemin de l'IGP (OSPF ici).

- **Découverte** : chaque interface où LDP est activé envoie des *Hello* en UDP, port **646**, à
  l'adresse multicast **224.0.0.2** (*all routers*). Deux routeurs qui s'entendent forment une
  **adjacence**.
- **Session** : ils ouvrent ensuite une connexion **TCP 646** entre leurs **adresses de
  transport** (celle qui a l'adresse la plus haute ouvre la connexion). On choisit l'adresse de
  l'interface de bouclage, annoncée dans l'IGP : la session ne dépend alors d'aucune interface
  physique. Une adresse de transport injoignable donne une adjacence sans session.
- Un LSR est identifié par son **LSR-ID** (32 bits, comme un router-id) suivi de l'espace de labels :
  `10.0.15.1:0`.
- **Messages** : *Initialization*, *KeepAlive*, *Address* (les adresses des interfaces du LSR, pour
  relier un prochain saut IP à un voisin LDP), *Label Mapping* (« pour cette FEC, utilise ce
  label »), *Label Withdraw* / *Release*.

Les modes de FRR, comme de la plupart des routeurs :

- *downstream unsolicited* : un routeur annonce ses labels à tous ses voisins sans attendre de
  demande ;
- *independent control* : il les annonce dès qu'il a une route, sans attendre l'aval ;
- *liberal retention* : il garde les labels de tous ses voisins, même de ceux qui ne sont pas son
  prochain saut. Si l'IGP change de chemin, le bon label est déjà là. La LIB contient donc un label
  distant par voisin, et la LFIB seulement celui du prochain saut IGP.

Par défaut LDP alloue un label à **chaque préfixe** de la table, y compris les liens entre routeurs,
qui ne sont la destination de personne : on restreint souvent l'allocation aux interfaces de
bouclage (ou aux routes d'hôte /32), et ici aux réseaux des hôtes.

Tant que la session LDP n'est pas établie sur un lien, l'IGP peut déjà y faire passer le trafic,
qui perd alors ses labels : la **synchronisation LDP-IGP** (RFC 5443) donne au lien un coût
maximal le temps que LDP soit prêt.
""": """
Writing the tables by hand does not scale. **LDP** (*Label Distribution Protocol*, RFC
5036) automatically distributes labels for the **prefixes of the routing table**: each LSP
follows the shortest path of the IGP (OSPF here).

- **Discovery**: each interface where LDP is enabled sends *Hello* messages over UDP, port
  **646**, to the multicast address **224.0.0.2** (*all routers*). Two routers that hear each
  other form an **adjacency**.
- **Session**: they then open a **TCP 646** connection between their **transport
  addresses** (the router with the higher address opens the connection). The address of the
  loopback interface, advertised in the IGP, is chosen: the session then depends on no physical
  interface. An unreachable transport address gives an adjacency without a session.
- An LSR is identified by its **LSR-ID** (32 bits, like a router-id) followed by the label space:
  `10.0.15.1:0`.
- **Messages**: *Initialization*, *KeepAlive*, *Address* (the addresses of the interfaces of the
  LSR, to map an IP next hop to an LDP neighbour), *Label Mapping* ("for this FEC, use this
  label"), *Label Withdraw* / *Release*.

The modes of FRR, as of most routers:

- *downstream unsolicited*: a router advertises its labels to all its neighbours without waiting
  for a request;
- *independent control*: it advertises them as soon as it has a route, without waiting for the
  downstream router;
- *liberal retention*: it keeps the labels of all its neighbours, even of those that are not its
  next hop. If the IGP changes path, the right label is already there. The LIB therefore holds one
  remote label per neighbour, and the LFIB only the one of the IGP next hop.

By default LDP allocates a label to **every prefix** of the table, including the links between
routers, which are nobody's destination: the allocation is often restricted to the loopback
interfaces (or to the /32 host routes), and here to the host networks as well.

As long as the LDP session is not established on a link, the IGP may already send traffic over
it, which then loses its labels: **LDP-IGP synchronisation** (RFC 5443) gives the link a maximal
cost until LDP is ready.
""",
    "LDP avec FRR": "LDP with FRR",
    """
`ldpd` doit être activé dans `/etc/frr/daemons` (c'est fait sur les routeurs du TP). Dans `vtysh` :

```
configure terminal
mpls ldp
 router-id 10.0.15.1
 address-family ipv4
  discovery transport-address 10.0.15.1
  label local allocate for LDP-FEC
  interface eth1
  exit
  interface eth2
  exit
 exit-address-family
exit
access-list LDP-FEC seq 5 permit 10.0.15.0/24
end
write
```

- `router-id` : le LSR-ID ; `discovery transport-address` : l'adresse de transport des sessions
  IPv4 ;
- `interface` : les interfaces où envoyer des *Hello* (seulement celles qui mènent à d'autres
  routeurs) ;
- `label local allocate for LISTE` : n'allouer de label qu'aux préfixes permis par la liste
  d'accès (`label local allocate host-routes` : seulement aux /32) ; `label local advertise
  explicit-null` : annoncer 0 au lieu de 3 pour ses propres préfixes.

| commande | ce qu'elle montre |
|----------|-------------------|
| `show mpls ldp discovery` | les adjacences, par interface |
| `show mpls ldp neighbor` | les sessions (`OPERATIONAL` quand tout va bien) |
| `show mpls ldp binding` | la LIB : label local et label de chaque voisin par préfixe ; `In Use` = celui du prochain saut |
| `show mpls table` | les labels que zebra a installés (la LFIB vue par FRR) |
| `show ip route` | les routes, avec le label qu'elles imposent |
| `ip -f mpls route`, `ip route` | ce que le noyau a vraiment |
""": """
`ldpd` must be enabled in `/etc/frr/daemons` (this is done on the routers of the lab). In `vtysh`:

```
configure terminal
mpls ldp
 router-id 10.0.15.1
 address-family ipv4
  discovery transport-address 10.0.15.1
  label local allocate for LDP-FEC
  interface eth1
  exit
  interface eth2
  exit
 exit-address-family
exit
access-list LDP-FEC seq 5 permit 10.0.15.0/24
end
write
```

- `router-id`: the LSR-ID; `discovery transport-address`: the transport address of the IPv4
  sessions;
- `interface`: the interfaces on which to send *Hello* messages (only those that lead to other
  routers);
- `label local allocate for LIST`: allocate labels only to the prefixes permitted by the access
  list (`label local allocate host-routes`: only to the /32s); `label local advertise
  explicit-null`: advertise 0 instead of 3 for its own prefixes.

| command | what it shows |
|----------|-------------------|
| `show mpls ldp discovery` | the adjacencies, per interface |
| `show mpls ldp neighbor` | the sessions (`OPERATIONAL` when all is well) |
| `show mpls ldp binding` | the LIB: local label and label of each neighbour per prefix; `In Use` = the one of the next hop |
| `show mpls table` | the labels zebra has installed (the LFIB as FRR sees it) |
| `show ip route` | the routes, with the label they push |
| `ip -f mpls route`, `ip route` | what the kernel really has |
""",
    "TTL et traceroute dans un cœur MPLS": "TTL and traceroute in an MPLS core",
    """
À l'entrée, le routeur copie le TTL IP (décrémenté) dans le label : c'est la **propagation du
TTL**. Chaque LSR décrémente le TTL du label ; quand le label est retiré, le paquet IP reprend le
TTL du label. Une boucle dans le cœur finit donc, comme en IP, par l'expiration du TTL.

Un routeur MPLS d'opérateur dont le TTL de label expire fabrique un *ICMP Time Exceeded*, l'envoie
le long du LSP jusqu'à la sortie qui le route vers la source (RFC 3032), et y joint la pile de
labels (extensions ICMP, RFC 4950) : son `traceroute` affiche les labels. **Linux jette le paquet
sans rien répondre** (le compteur `RX errors` de l'interface augmente) : chaque routeur du cœur
apparaît comme une étoile `*`.

Avec `net.mpls.ip_ttl_propagate=0` à l'entrée, le label part avec un TTL de 255 et le TTL IP n'est
plus décrémenté dans le cœur : tout le LSP compte pour un seul saut. Les opérateurs **cachent**
ainsi leur cœur aux `traceroute` des clients. Le retrait du label par le routeur de sortie, sans
PHP, décrémente une fois de plus le TTL : il ajoute une ligne au `traceroute`.
""": """
At the ingress, the router copies the (decremented) IP TTL into the label: this is **TTL
propagation**. Each LSR decrements the TTL of the label; when the label is removed, the IP packet
takes the TTL of the label back. A loop in the core therefore ends, as in IP, with the expiry of
the TTL.

A carrier MPLS router whose label TTL expires builds an *ICMP Time Exceeded*, sends it along the
LSP to the egress, which routes it back to the source (RFC 3032), and attaches the label stack to
it (ICMP extensions, RFC 4950): its `traceroute` shows the labels. **Linux drops the packet
without any answer** (the `RX errors` counter of the interface grows): each core router appears
as a star `*`.

With `net.mpls.ip_ttl_propagate=0` at the ingress, the label leaves with a TTL of 255 and the IP
TTL is no longer decremented in the core: the whole LSP counts as a single hop. Service providers
thus **hide** their core from the `traceroute` of their customers. The removal of the label by the
egress router, without PHP, decrements the TTL once more: it adds a line to the `traceroute`.
""",
    "Segment routing": "Segment routing",
    """
Le **segment routing** (RFC 8402) est un **routage par la source** : le routeur d'entrée écrit le
chemin dans le paquet sous forme d'une liste de **segments** (des instructions), et le cœur ne garde
aucun état par chemin. En **SR-MPLS**, un segment est un label ; il n'y a **plus de LDP** : les
labels sont annoncés par l'**IGP** lui-même (OSPF : LSA opaques, RFC 8665 ; IS-IS : RFC 8667).

- Un **SID** (*Segment Identifier*) désigne un segment. Un **prefix-SID** est global : « va vers ce
  préfixe par le plus court chemin ». Celui d'une interface de bouclage s'appelle **node-SID**. Un
  **adjacency-SID** est local : « sors par ce lien ».
- Chaque routeur réserve un bloc de labels pour les SID globaux, le **SRGB** (*SR Global Block*,
  16000 à 23999 par défaut dans FRR), et un bloc pour les SID locaux, le **SRLB** (15000 à 15999).
- Un prefix-SID est annoncé comme un **index**. Le label qu'utilise un routeur pour joindre le
  préfixe est **la base du SRGB du routeur suivant + l'index** : chaque routeur annonce son SRGB dans
  une LSA *Router Information*. Si tous les routeurs ont le même SRGB, le label reste le même d'un
  bout à l'autre ; sinon il change à chaque saut, comme avec LDP.
- L'avant-dernier routeur retire le label (PHP), sauf si le prefix-SID est annoncé avec le drapeau
  **no-php** : le dernier routeur reçoit alors le label (dans son propre SRGB) et le retire.
- Seuls les préfixes qui ont un SID reçoivent un label : les autres sont acheminés en IP.

Le segment routing permet aussi l'**ingénierie de trafic** sans état dans le cœur (une liste de
segments : passer par tel routeur puis aller à telle destination) et le **TI-LFA** (section
@@ref:tilfa@@). Sa variante **SRv6** code les segments sous forme d'adresses IPv6, dans un en-tête
de routage IPv6 (*Segment Routing Header*).
""": """
**Segment routing** (RFC 8402) is **source routing**: the ingress router writes the path into
the packet as a list of **segments** (instructions), and the core keeps no per-path state. In
**SR-MPLS**, a segment is a label; there is **no LDP any more**: the labels are advertised by the
**IGP** itself (OSPF: opaque LSAs, RFC 8665; IS-IS: RFC 8667).

- A **SID** (*Segment Identifier*) designates a segment. A **prefix-SID** is global: "go to this
  prefix along the shortest path". The one of a loopback interface is called a **node-SID**. An
  **adjacency-SID** is local: "leave through this link".
- Each router reserves a block of labels for the global SIDs, the **SRGB** (*SR Global Block*,
  16000 to 23999 by default in FRR), and a block for the local SIDs, the **SRLB** (15000 to 15999).
- A prefix-SID is advertised as an **index**. The label a router uses to reach the prefix is
  **the base of the SRGB of the next router + the index**: each router advertises its SRGB in a
  *Router Information* LSA. If all the routers have the same SRGB, the label stays the same from
  end to end; otherwise it changes at each hop, as with LDP.
- The penultimate router removes the label (PHP), unless the prefix-SID is advertised with the
  **no-php** flag: the last router then receives the label (in its own SRGB) and removes it.
- Only the prefixes that have a SID receive a label: the others are forwarded over IP.

Segment routing also allows **traffic engineering** without state in the core (a list of
segments: go through a given router, then go to a given destination) and **TI-LFA** (section
@@ref:tilfa@@). Its variant **SRv6** encodes the segments as IPv6 addresses, in an IPv6 routing
header (*Segment Routing Header*).
""",
    "Segment routing avec FRR": "Segment routing with FRR",
    """
Le segment routing s'active dans OSPF, sur chaque routeur du domaine :

```
configure terminal
router ospf
 capability opaque
 segment-routing on
 segment-routing global-block 16000 23999
 segment-routing prefix 10.0.15.1/32 index 1
exit
end
write
```

- `capability opaque` : les LSA opaques qui portent les informations SR ;
- `segment-routing global-block BAS HAUT` : le SRGB (`local-block` pour le SRLB) ;
- `segment-routing prefix P/32 index N` : le prefix-SID d'un préfixe de la machine (son interface
  de bouclage, qui doit être dans OSPF) ; suivi de `no-php-flag` pour refuser le PHP, ou de
  `explicit-null`.

FRR ajoute de lui-même `router-info area` (la LSA *Router Information*).

| commande | ce qu'elle montre |
|----------|-------------------|
| `show ip ospf database segment-routing` | chaque routeur SR : SRGB, SRLB, ses prefix-SID et adjacency-SID, avec l'opération sur les labels |
| `show mpls table` | les labels installés (type `SR (OSPF)`) |
| `show ip route` | le label imposé par chaque route |
| `ip -f mpls route`, `ip route` | ce que le noyau a vraiment |
""": """
Segment routing is enabled in OSPF, on every router of the domain:

```
configure terminal
router ospf
 capability opaque
 segment-routing on
 segment-routing global-block 16000 23999
 segment-routing prefix 10.0.15.1/32 index 1
exit
end
write
```

- `capability opaque`: the opaque LSAs that carry the SR information;
- `segment-routing global-block LOW HIGH`: the SRGB (`local-block` for the SRLB);
- `segment-routing prefix P/32 index N`: the prefix-SID of a prefix of the machine (its loopback
  interface, which must be in OSPF); followed by `no-php-flag` to refuse PHP, or by
  `explicit-null`.

FRR adds `router-info area` by itself (the *Router Information* LSA).

| command | what it shows |
|----------|-------------------|
| `show ip ospf database segment-routing` | each SR router: SRGB, SRLB, its prefix-SIDs and adjacency-SIDs, with the operation on the labels |
| `show mpls table` | the installed labels (type `SR (OSPF)`) |
| `show ip route` | the label pushed by each route |
| `ip -f mpls route`, `ip route` | what the kernel really has |
""",
    "Protection : LFA et TI-LFA": "Protection: LFA and TI-LFA",
    """
Quand un lien tombe, l'IGP met de quelques dizaines de millisecondes à quelques secondes à
converger. La **protection rapide** (*Fast ReRoute*) calcule d'avance un **prochain saut de
secours** pour basculer dès que la panne est détectée.

- **LFA** (*Loop-Free Alternate*, RFC 5286) : un voisin dont le plus court chemin vers la
  destination ne repasse pas par nous peut servir de secours sans créer de boucle. Selon la
  topologie, il n'en existe pas toujours.
- **TI-LFA** (*Topology Independent LFA*) : avec le segment routing, le secours suit le chemin
  qu'aura le réseau **après** convergence. Si le voisin choisi renverrait le paquet vers la panne,
  le routeur impose une **liste de réparation** (un node-SID, un adjacency-SID...) qui fait passer
  le paquet au-delà. La couverture est totale.
- Protection **de lien** (éviter le lien) ou **de nœud** (éviter le routeur suivant tout entier).

Dans FRR : `fast-reroute ti-lfa` (ou `fast-reroute ti-lfa node-protection`) sous `router ospf`.
`show ip route` montre la route de secours sur une ligne marquée `b`, avec sa pile de labels
(`backupNexthops` en json). zebra garde les secours pour lui : le noyau des machines du TP ne les
reçoit pas, et le TP n'en observe donc que le calcul.
""": """
When a link fails, the IGP takes from a few tens of milliseconds to a few seconds to converge.
**Fast protection** (*Fast ReRoute*) computes a **backup next hop** in advance, to switch over as
soon as the failure is detected.

- **LFA** (*Loop-Free Alternate*, RFC 5286): a neighbour whose shortest path to the destination
  does not come back through us can act as a backup without creating a loop. Depending on the
  topology, there is not always one.
- **TI-LFA** (*Topology Independent LFA*): with segment routing, the backup follows the path the
  network will have **after** convergence. If the chosen neighbour would send the packet back
  towards the failure, the router pushes a **repair list** (a node-SID, an adjacency-SID...) that
  takes the packet beyond it. The coverage is complete.
- **Link** protection (avoid the link) or **node** protection (avoid the whole next router).

In FRR: `fast-reroute ti-lfa` (or `fast-reroute ti-lfa node-protection`) under `router ospf`.
`show ip route` shows the backup route on a line marked `b`, with its label stack
(`backupNexthops` in json). zebra keeps the backups to itself: the kernel of the machines of the
lab does not receive them, so the lab only observes their computation.
""",
    "Dépannage MPLS": "MPLS troubleshooting",
    """
Une méthode : partir du plan de contrôle et descendre vers le plan de données.

1. **IGP** : chaque routeur a-t-il une route vers les interfaces de bouclage (LSR-ID, adresses de
   transport) des autres ? (`show ip ospf neighbor`, `show ip route`)
2. **LDP** : adjacences par interface (`show mpls ldp discovery`), sessions (`show mpls ldp
   neighbor` : `OPERATIONAL`), labels (`show mpls ldp binding`).
3. **Labels installés** : zebra (`show mpls table`) puis le noyau (`ip -f mpls route`). zebra peut
   croire un label installé alors que le noyau l'a refusé ou perdu (table des labels trop petite).
   zebra ne réinstalle ses labels que quand ses LSP changent : `clear mpls ldp neighbor` les fait
   annoncer à nouveau.
4. **Noyau** : `net.mpls.platform_labels`, `net.mpls.conf.<interface>.input`, la MTU (le label
   ajoute 4 octets et Linux ne fragmente pas un paquet étiqueté).
5. **Plan de données** : `tcpdump -nei ethX mpls` sur chaque lien, les compteurs `ip stats show dev
   ethX group afstats subgroup mpls`, `traceroute`.

| symptôme | cause probable |
|----------|----------------|
| adjacence LDP sans session | adresse de transport injoignable (pas dans l'IGP), TCP 646 filtré |
| aucune adjacence sur un lien | interface absente de `mpls ldp`, *Hello* filtrés |
| le voisin en amont envoie des labels, rien ne ressort | `input` à 0 sur l'interface, label absent de la LFIB du noyau |
| `show mpls table` correcte, `ip -f mpls route` vide | `platform_labels` trop petit (ou remis après coup) |
| le trafic passe mais sans label sur une partie du chemin | pas de session LDP avec le prochain saut : le label est retiré trop tôt |
""": """
A method: start from the control plane and work down to the data plane.

1. **IGP**: does each router have a route to the loopback interfaces (LSR-ID, transport
   addresses) of the others? (`show ip ospf neighbor`, `show ip route`)
2. **LDP**: adjacencies per interface (`show mpls ldp discovery`), sessions (`show mpls ldp
   neighbor`: `OPERATIONAL`), labels (`show mpls ldp binding`).
3. **Installed labels**: zebra (`show mpls table`), then the kernel (`ip -f mpls route`). zebra may
   believe a label is installed while the kernel has refused or lost it (label table too small).
   zebra reinstalls its labels only when its LSPs change: `clear mpls ldp neighbor` has them
   advertised again.
4. **Kernel**: `net.mpls.platform_labels`, `net.mpls.conf.<interface>.input`, the MTU (the label
   adds 4 bytes and Linux does not fragment a labelled packet).
5. **Data plane**: `tcpdump -nei ethX mpls` on each link, the counters `ip stats show dev
   ethX group afstats subgroup mpls`, `traceroute`.

| symptom | probable cause |
|----------|----------------|
| LDP adjacency without a session | unreachable transport address (not in the IGP), TCP 646 filtered |
| no adjacency on a link | interface missing from `mpls ldp`, *Hello* messages filtered |
| the upstream neighbour sends labels, nothing comes out | `input` at 0 on the interface, label missing from the LFIB of the kernel |
| `show mpls table` correct, `ip -f mpls route` empty | `platform_labels` too small (or only raised afterwards) |
| the traffic gets through, but without a label on part of the path | no LDP session with the next hop: the label is removed too early |
""",
    "Partie 1 : solution (LSP statique)": "Part 1: solution (static LSP)",
    "Partie 2 : solution (LDP)": "Part 2: solution (LDP)",
    "Partie 3 : solution (segment routing)": "Part 3: solution (segment routing)",
    "Partie 4 : solution (dépannage)": "Part 4: solution (troubleshooting)",
    "Partie 5 : solution (TI-LFA, bonus)": "Part 5: solution (TI-LFA, bonus)",
    "1 — LSP statique": "1 — static LSP",
    "`st_pe1`, `st_p`, `st_pe2`, les hôtes `st_h1` et `st_h2`": "`st_pe1`, `st_p`, `st_pe2`, the hosts `st_h1` and `st_h2`",
    "`ldp_pe1`, `ldp_p1`, `ldp_p2`, `ldp_pe2`, les hôtes `ldp_h1` et `ldp_h2`": "`ldp_pe1`, `ldp_p1`, `ldp_p2`, `ldp_pe2`, the hosts `ldp_h1` and `ldp_h2`",
    "4 — dépannage": "4 — troubleshooting",
    "`fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2`, les hôtes `fix_h1` et `fix_h2`": "`fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2`, the hosts `fix_h1` and `fix_h2`",
    "`tl_r1` (les trois autres routeurs n'ont pas de terminal)": "`tl_r1` (the three other routers have no terminal)",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente MPLS, LDP et le segment routing, et leur mise en
œuvre avec Linux et FRR.

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Les routeurs des sites `ldp`, `sr`, `fix` et `tl` font tourner **FRRouting** (FRR) :
  configurez-les avec `vtysh`. **OSPF y fonctionne déjà** (zone 0, interfaces de bouclage
  annoncées) ; `ldpd` est activé sur les sites `ldp` et `fix`.
- Sur le site `st`, FRR ne tourne pas : tout se fait avec `sysctl` et `ip`.
- Les modules MPLS du noyau sont chargés. Sur les sites `ldp`, `sr`, `fix` et `tl`, la table des
  labels (`net.mpls.platform_labels={labels}`) et l'entrée MPLS des interfaces entre routeurs sont
  déjà réglées (sauf les pannes du site `fix`) ; sur le site `st`, rien ne l'est.
- Toutes les adresses sont en place, ainsi que la route par défaut des hôtes.
- Les fichiers `/etc/hosts` contiennent les noms : `ldp_p1-eth1` désigne l'adresse de l'interface
  `eth1` de `ldp_p1`, `ldp_pe2-lo` l'adresse de bouclage de `ldp_pe2`, `ldp_h2` l'hôte.

**Plan d'adressage.** Les liens entre routeurs sont des /30, les réseaux des hôtes des /24.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Valeurs propres à votre instance.**

- Partie 1 : labels **{push}** (imposé par `st_pe1`), **{swap}** (le label par lequel `st_p`
  le remplace), **{back}** (imposé par `st_pe2` au retour).
- Partie 3 : SRGB de `sr_r1`, `sr_r2` et `sr_r4` : **{srgb} à {srgb_end}** ; SRGB de `sr_r3` :
  **{srgb3} à {srgb3_end}** ; index des prefix-SID des interfaces de bouclage : `sr_r1` **{i1}**,
  `sr_r2` **{i2}**, `sr_r3` **{i3}**, `sr_r4` **{i4}**.

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`). Les réglages `sysctl` et les commandes
  `ip` ne sont pas enregistrés : ne redémarrez pas les machines.
- Une session LDP s'établit en quelques secondes ; OSPF annonce les informations du segment
  routing aussitôt qu'il est activé.

**Évaluation.** Chaque évaluation lit vos réponses, les réglages MPLS du noyau, ses tables
(`ip -f mpls route`, `ip route`), l'état de LDP, du segment routing et d'OSPF, puis envoie des
`ping` en comptant les paquets étiquetés reçus par les routeurs du cœur. Elle dure une quinzaine de
secondes.
""": """
Read the **Informations** tab: it presents MPLS, LDP and segment routing, and how they are
implemented with Linux and FRR.

**The network.** It is made of **five independent sites**, one per part. Each site has its own
colour on the diagram of the *Schema* tab:

| part | site | machines |
|--------|------|----------|
{site_rows}

- The routers of the sites `ldp`, `sr`, `fix` and `tl` run **FRRouting** (FRR):
  configure them with `vtysh`. **OSPF already works there** (area 0, loopback interfaces
  advertised); `ldpd` is enabled on the sites `ldp` and `fix`.
- On the site `st`, FRR does not run: everything is done with `sysctl` and `ip`.
- The MPLS modules of the kernel are loaded. On the sites `ldp`, `sr`, `fix` and `tl`, the label
  table (`net.mpls.platform_labels={labels}`) and the MPLS input of the interfaces between routers
  are already set (except for the faults of the site `fix`); on the site `st`, nothing is.
- All the addresses are in place, as well as the default route of the hosts.
- The `/etc/hosts` files contain the names: `ldp_p1-eth1` designates the address of the interface
  `eth1` of `ldp_p1`, `ldp_pe2-lo` the loopback address of `ldp_pe2`, `ldp_h2` the host.

**Addressing plan.** The links between routers are /30s, the host networks /24s.

| network | prefix | interfaces |
|--------|---------|------------|
{addressing}

**Values specific to your instance.**

- Part 1: labels **{push}** (pushed by `st_pe1`), **{swap}** (the label `st_p` replaces it
  with), **{back}** (pushed by `st_pe2` on the way back).
- Part 3: SRGB of `sr_r1`, `sr_r2` and `sr_r4`: **{srgb} to {srgb_end}**; SRGB of `sr_r3`:
  **{srgb3} to {srgb3_end}**; indexes of the prefix-SIDs of the loopback interfaces: `sr_r1` **{i1}**,
  `sr_r2` **{i2}**, `sr_r3` **{i3}**, `sr_r4` **{i4}**.

**Instructions.**

- The parts are **independent**: do them in any order you like. A completed part gives all its
  points, whatever the state of the others.
- Save the FRR configuration (`write` in `vtysh`). The `sysctl` settings and the `ip` commands
  are not saved: do not restart the machines.
- An LDP session is established within a few seconds; OSPF advertises the segment routing
  information as soon as it is enabled.

**Evaluation.** Each evaluation reads your answers, the MPLS settings of the kernel, its tables
(`ip -f mpls route`, `ip route`), the state of LDP, of segment routing and of OSPF, then sends
`ping`s while counting the labelled packets received by the core routers. It takes about fifteen
seconds.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_static`, `solve_ldp`, `solve_sr`, `solve_fix` et `solve_tilfa` (onglet
*Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes, attend {wait} s (sessions LDP) puis remplit tous
les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.

Les pannes du site `fix` : `net.mpls.conf.eth0.input=0` sur `fix_p1` (les paquets étiquetés
venant de `fix_pe1` sont jetés), `net.mpls.platform_labels=0` sur `fix_p2` (le noyau n'accepte
aucun label), `eth0` de `fix_p2` absente de `mpls ldp` (pas de session `fix_p1` – `fix_p2`),
interface de bouclage de `fix_pe2` hors d'OSPF alors qu'elle est son adresse de transport
(adjacence sans session avec `fix_p2`).
""": """
**For the instructor.** Each question ends with its solution for the values of this instance.
The states `solve_static`, `solve_ldp`, `solve_sr`, `solve_fix` and `solve_tilfa` (*Apply
Configuration* tab) apply the solution of a single part and fill in its forms. The state `final`
applies them all, waits {wait} s (LDP sessions), then fills in all the forms: an evaluation
started as soon as it returns gives every point, bonus included.

The faults of the site `fix`: `net.mpls.conf.eth0.input=0` on `fix_p1` (the labelled packets
coming from `fix_pe1` are dropped), `net.mpls.platform_labels=0` on `fix_p2` (the kernel accepts
no label), `eth0` of `fix_p2` missing from `mpls ldp` (no `fix_p1` – `fix_p2` session), loopback
interface of `fix_pe2` outside OSPF although it is its transport address (adjacency without a
session with `fix_p2`).
""",
    "Partie 1 — un LSP construit à la main (site st)": "Part 1 — an LSP built by hand (site st)",
    "Un LSP construit à la main": "An LSP built by hand",
    """
Les routeurs `st_pe1`, `st_p` et `st_pe2` forment une ligne (liens `st_l1` et `st_l2`) ; l'hôte
`st_h1` est sur le réseau `st_lan1` de `st_pe1`, l'hôte `st_h2` sur le réseau `st_lan2` de
`st_pe2`. Aucun protocole de routage ne tourne et aucune route n'est en place : `st_pe1` ne connaît
pas `st_lan2`, `st_pe2` ne connaît pas `st_lan1`, et `st_p` ne connaît **aucun** des deux réseaux
d'hôtes. Il ne pourra transporter leurs paquets qu'en commutant des labels (sections
@@ref:mpls-ops@@ et @@ref:mpls-linux@@).

1. Activez MPLS dans le noyau des routeurs qui **reçoivent** des paquets étiquetés : une table de
   labels assez grande (`net.mpls.platform_labels`) et l'entrée MPLS
   (`net.mpls.conf.<interface>.input`) des interfaces où ces paquets arrivent. Lesquels ?
2. **Aller** (`st_h1` vers `st_h2`) : `st_pe1` impose le label **{push}** aux paquets destinés à
   `st_lan2` et les envoie à `st_p` ; `st_p` remplace **{push}** par **{swap}** et les envoie à
   `st_pe2` ; `st_pe2` retire **{swap}** et route le paquet IP vers `st_h2` (retrait par le routeur
   de sortie : `dev lo`).
3. **Retour** (`st_h2` vers `st_h1`) : `st_pe2` impose **{back}** ; `st_p`, avant-dernier
   routeur, le retire (PHP) et donne le paquet IP à `st_pe1`.
4. Vérifiez que `st_h1` joint `st_h2`. Regardez les trames sur `st_p` (`tcpdump -nei eth0 mpls`) :
   EtherType, label, bit S, TTL ; et ses compteurs MPLS (`ip stats show dev eth0 group afstats
   subgroup mpls`).
5. Lancez `traceroute -n st_h2` depuis `st_h1`, puis `traceroute -n st_h1` depuis `st_h2`. Comptez
   les lignes et expliquez les étoiles (section @@ref:mpls-ttl@@).
""": """
The routers `st_pe1`, `st_p` and `st_pe2` form a line (links `st_l1` and `st_l2`); the host
`st_h1` is on the network `st_lan1` of `st_pe1`, the host `st_h2` on the network `st_lan2` of
`st_pe2`. No routing protocol runs and no route is in place: `st_pe1` does not know `st_lan2`,
`st_pe2` does not know `st_lan1`, and `st_p` knows **neither** of the two host networks. It can
only carry their packets by switching labels (sections @@ref:mpls-ops@@ and
@@ref:mpls-linux@@).

1. Enable MPLS in the kernel of the routers that **receive** labelled packets: a label table that
   is large enough (`net.mpls.platform_labels`) and the MPLS input
   (`net.mpls.conf.<interface>.input`) of the interfaces where these packets arrive. Which ones?
2. **Forward direction** (`st_h1` to `st_h2`): `st_pe1` pushes the label **{push}** onto the
   packets destined for `st_lan2` and sends them to `st_p`; `st_p` replaces **{push}** with
   **{swap}** and sends them to `st_pe2`; `st_pe2` removes **{swap}** and routes the IP packet to
   `st_h2` (removal by the egress router: `dev lo`).
3. **Return direction** (`st_h2` to `st_h1`): `st_pe2` pushes **{back}**; `st_p`, the penultimate
   router, removes it (PHP) and hands the IP packet to `st_pe1`.
4. Check that `st_h1` reaches `st_h2`. Look at the frames on `st_p` (`tcpdump -nei eth0 mpls`):
   EtherType, label, S bit, TTL; and at its MPLS counters (`ip stats show dev eth0 group afstats
   subgroup mpls`).
5. Run `traceroute -n st_h2` from `st_h1`, then `traceroute -n st_h1` from `st_h2`. Count the
   lines and explain the stars (section @@ref:mpls-ttl@@).
""",
    """
**Solution.**

{solution}

`st_pe1` ne reçoit aucun paquet étiqueté (`st_p` lui rend des paquets IP) : il n'a besoin d'aucun
réglage. Le `traceroute` aller montre cinq lignes : `st_pe1`, deux étoiles (le TTL du label expire
sur `st_p` puis sur `st_pe2`, qui le jettent sans répondre), `st_pe2` (son retrait du label puis sa
décrémentation du TTL IP), `st_h2`. Le retour en montre quatre : `st_pe2`, une étoile (`st_p`),
`st_pe1`, `st_h1`.

Évaluation : `st_platform_labels` (2 : `st_p` et `st_pe2`), `st_input` (3 : `eth0` et `eth1` de
`st_p`, `eth1` de `st_pe2`), `st_push`, `st_swap` (3 chacun), `st_pop` (2), `st_back` (3 : 1 pour
l'imposition sur `st_pe2`, 2 pour le PHP de `st_p`), `st_ping` (3).
""": """
**Solution.**

{solution}

`st_pe1` receives no labelled packet (`st_p` hands it IP packets): it needs no setting. The
forward `traceroute` shows five lines: `st_pe1`, two stars (the label TTL expires on `st_p`, then
on `st_pe2`, which drop the packet without answering), `st_pe2` (its removal of the label, then
its decrement of the IP TTL), `st_h2`. The return one shows four: `st_pe2`, one star (`st_p`),
`st_pe1`, `st_h1`.

Evaluation: `st_platform_labels` (2: `st_p` and `st_pe2`), `st_input` (3: `eth0` and `eth1` of
`st_p`, `eth1` of `st_pe2`), `st_push`, `st_swap` (3 each), `st_pop` (2), `st_back` (3: 1 for
the imposition on `st_pe2`, 2 for the PHP of `st_p`), `st_ping` (3).
""",
    "Observations sur le site st": "Observations on the site st",
    """
- EtherType des trames MPLS (en hexadécimal) : @@{ethertype:[0-9a-fA-Fx]+}@@
- plus grande valeur possible d'un label : @@{max_label:[0-9]+}@@
- nombre de lignes de sauts du `traceroute -n st_h2` lancé depuis `st_h1` : @@{hops:[0-9]+}@@
""": """
- EtherType of the MPLS frames (in hexadecimal): @@{ethertype:[0-9a-fA-Fx]+}@@
- largest possible value of a label: @@{max_label:[0-9]+}@@
- number of hop lines of the `traceroute -n st_h2` run from `st_h1`: @@{hops:[0-9]+}@@
""",
    """
**Solution.** **`0x8847`** ; un label a 20 bits : **1048575** (2^20 − 1) ; **5** lignes (voir
la question précédente).

Évaluation : `st_q_ethertype`, `st_q_max_label`, `st_q_hops` (1 chacun).
""": """
**Solution.** **`0x8847`**; a label has 20 bits: **1048575** (2^20 − 1); **5** lines (see the
previous question).

Evaluation: `st_q_ethertype`, `st_q_max_label`, `st_q_hops` (1 each).
""",
    "table des labels assez grande sur st_p et st_pe2": "label table large enough on st_p and st_pe2",
    "entrée MPLS sur les interfaces qui reçoivent des labels": "MPLS input on the interfaces that receive labels",
    "st_pe1 impose le label de l'aller": "st_pe1 pushes the label of the forward direction",
    "st_p échange le label de l'aller": "st_p swaps the label of the forward direction",
    "st_pe2 retire le label de l'aller": "st_pe2 removes the label of the forward direction",
    "retour : imposition par st_pe2, PHP sur st_p": "return: imposition by st_pe2, PHP on st_p",
    "st_h1 joint st_h2": "st_h1 reaches st_h2",
    "EtherType de MPLS": "EtherType of MPLS",
    "plus grand label": "largest label",
    "lignes du traceroute": "lines of the traceroute",
    "Partie 2 — LDP (site ldp)": "Part 2 — LDP (site ldp)",
    "Distribuer les labels avec LDP": "Distributing the labels with LDP",
    """
Les routeurs `ldp_pe1`, `ldp_p1`, `ldp_p2` et `ldp_pe2` forment une ligne ; l'hôte `ldp_h1` est
derrière `ldp_pe1`, l'hôte `ldp_h2` derrière `ldp_pe2`. OSPF fonctionne, MPLS est activé dans les
noyaux et `ldpd` tourne, mais LDP n'est pas configuré (sections @@ref:ldp@@ et @@ref:ldp-frr@@).

1. Configurez LDP sur les quatre routeurs : LSR-ID et adresse de transport égaux à l'adresse de
   l'interface de bouclage, LDP seulement sur les interfaces qui mènent à un autre routeur (pas
   sur les réseaux des hôtes). Suivez `show mpls ldp discovery` et `show mpls ldp neighbor`.
2. Observez la LIB (`show mpls ldp binding`), la LFIB (`show mpls table`, `ip -f mpls route`) et
   les routes qui imposent un label (`ip route`). Suivez les labels qu'utilisent les paquets vers
   l'interface de bouclage de `ldp_pe2`, de `ldp_pe1` jusqu'à `ldp_pe2` : que fait `ldp_p2` ?
3. LDP alloue un label à chaque préfixe, même aux liens entre routeurs. Sur les quatre routeurs,
   n'allouez plus de label qu'aux interfaces de bouclage (`{lo_block}`) et aux deux réseaux des
   hôtes, avec une liste d'accès. Vérifiez que les liens ont disparu de la LIB.
4. Lancez `traceroute -n ldp_h2` depuis `ldp_h1` : d'où viennent les étoiles ? Cessez de propager
   le TTL sur les deux routeurs d'entrée, `ldp_pe1` et `ldp_pe2` (section @@ref:mpls-ttl@@), puis
   relancez-le.
""": """
The routers `ldp_pe1`, `ldp_p1`, `ldp_p2` and `ldp_pe2` form a line; the host `ldp_h1` is
behind `ldp_pe1`, the host `ldp_h2` behind `ldp_pe2`. OSPF works, MPLS is enabled in the kernels
and `ldpd` runs, but LDP is not configured (sections @@ref:ldp@@ and @@ref:ldp-frr@@).

1. Configure LDP on the four routers: LSR-ID and transport address equal to the address of the
   loopback interface, LDP only on the interfaces that lead to another router (not on the host
   networks). Follow `show mpls ldp discovery` and `show mpls ldp neighbor`.
2. Observe the LIB (`show mpls ldp binding`), the LFIB (`show mpls table`, `ip -f mpls route`) and
   the routes that push a label (`ip route`). Follow the labels used by the packets towards the
   loopback interface of `ldp_pe2`, from `ldp_pe1` to `ldp_pe2`: what does `ldp_p2` do?
3. LDP allocates a label to every prefix, even to the links between routers. On the four routers,
   allocate labels only to the loopback interfaces (`{lo_block}`) and to the two host networks,
   with an access list. Check that the links have disappeared from the LIB.
4. Run `traceroute -n ldp_h2` from `ldp_h1`: where do the stars come from? Stop propagating the
   TTL on the two ingress routers, `ldp_pe1` and `ldp_pe2` (section @@ref:mpls-ttl@@), then run it
   again.
""",
    """
**Solution.**

{solution}

Puis, sur `ldp_pe1` et `ldp_pe2` :

```
sysctl -w net.mpls.ip_ttl_propagate=0
```

Vers l'interface de bouclage de `ldp_pe2`, `ldp_pe1` impose le label local de `ldp_p1`, que
`ldp_p1` échange contre le label local de `ldp_p2` ; `ldp_p2` a reçu *implicit-null* (3) de
`ldp_pe2` : il retire le label (PHP). Avant le changement, le `traceroute` montre `ldp_pe1`, deux
étoiles (`ldp_p1`, `ldp_p2` jettent les paquets dont le TTL de label expire), `ldp_pe2`, `ldp_h2` ;
après, seulement `ldp_pe1` et `ldp_h2` : le label part avec un TTL de 255, et `ldp_p2` redonne ce
TTL au paquet IP en retirant le label.

Évaluation : `ldp_sessions` (6 : 2 par session), `ldp_identity` (4 : LSR-ID et adresse de transport
de chaque routeur, vus par un voisin), `ldp_core_only` (2 : LDP absent de l'`eth0` de `ldp_pe1` et
de `ldp_pe2`), `ldp_lfib` (3 : la chaîne des labels vers l'interface de bouclage de `ldp_pe2`),
`ldp_traffic` (3 : ping `ldp_h1` → `ldp_h2` avec des paquets étiquetés reçus par `ldp_p1` et
`ldp_p2`), `ldp_filter` (4 : un point par routeur dont la LIB n'a aucun lien mais toutes les
interfaces de bouclage et les deux réseaux d'hôtes), `ldp_ttl` (3 : le réglage sur les deux
routeurs d'entrée, puis un `traceroute` sans étoile par un LSP).
""": """
**Solution.**

{solution}

Then, on `ldp_pe1` and `ldp_pe2`:

```
sysctl -w net.mpls.ip_ttl_propagate=0
```

Towards the loopback interface of `ldp_pe2`, `ldp_pe1` pushes the local label of `ldp_p1`, which
`ldp_p1` swaps for the local label of `ldp_p2`; `ldp_p2` has received *implicit-null* (3) from
`ldp_pe2`: it removes the label (PHP). Before the change, the `traceroute` shows `ldp_pe1`, two
stars (`ldp_p1` and `ldp_p2` drop the packets whose label TTL expires), `ldp_pe2`, `ldp_h2`;
afterwards, only `ldp_pe1` and `ldp_h2`: the label leaves with a TTL of 255, and `ldp_p2` gives
that TTL to the IP packet when it removes the label.

Evaluation: `ldp_sessions` (6: 2 per session), `ldp_identity` (4: LSR-ID and transport address of
each router, as seen by a neighbour), `ldp_core_only` (2: no LDP on `eth0` of `ldp_pe1` and of
`ldp_pe2`), `ldp_lfib` (3: the chain of labels towards the loopback interface of `ldp_pe2`),
`ldp_traffic` (3: ping `ldp_h1` → `ldp_h2` with labelled packets received by `ldp_p1` and
`ldp_p2`), `ldp_filter` (4: one point per router whose LIB has no link but all the loopback
interfaces and both host networks), `ldp_ttl` (3: the setting on the two ingress routers, then a
`traceroute` without a star through an LSP).
""",
    "Observations sur le site ldp": "Observations on the site ldp",
    """
- valeur du label sortant de `ldp_p2` pour l'interface de bouclage de `ldp_pe2` (un nombre) :
  @@{php_label:[0-9]+}@@
- port TCP des sessions LDP : @@{port:[0-9]+}@@
- nombre de lignes de sauts du `traceroute -n ldp_h2` lancé depuis `ldp_h1`, une fois la
  propagation du TTL coupée sur les routeurs d'entrée : @@{hops:[0-9]+}@@
""": """
- value of the outgoing label of `ldp_p2` for the loopback interface of `ldp_pe2` (a number):
  @@{php_label:[0-9]+}@@
- TCP port of the LDP sessions: @@{port:[0-9]+}@@
- number of hop lines of the `traceroute -n ldp_h2` run from `ldp_h1`, once the TTL propagation
  is turned off on the ingress routers: @@{hops:[0-9]+}@@
""",
    """
**Solution.** **3** (*implicit-null* : `ldp_p2` retire le label) ; **646** ; **2** lignes
(`ldp_pe1` puis `ldp_h2`).

Évaluation : `ldp_q_php_label`, `ldp_q_port`, `ldp_q_hops` (1 chacun).
""": """
**Solution.** **3** (*implicit-null*: `ldp_p2` removes the label); **646**; **2** lines
(`ldp_pe1`, then `ldp_h2`).

Evaluation: `ldp_q_php_label`, `ldp_q_port`, `ldp_q_hops` (1 each).
""",
    "trois sessions LDP établies": "three LDP sessions established",
    "LSR-ID et adresse de transport sur l'interface de bouclage": "LSR-ID and transport address on the loopback interface",
    "pas de LDP sur les réseaux des hôtes": "no LDP on the host networks",
    "labels vers ldp_pe2 : imposition, échange, PHP": "labels towards ldp_pe2: imposition, swap, PHP",
    "ldp_h1 joint ldp_h2 par un LSP": "ldp_h1 reaches ldp_h2 through an LSP",
    "labels seulement pour les interfaces de bouclage et les réseaux des hôtes": "labels only for the loopback interfaces and the host networks",
    "TTL non propagé sur les routeurs d'entrée": "TTL not propagated on the ingress routers",
    "label implicit-null": "implicit-null label",
    "port de LDP": "LDP port",
    "lignes du traceroute sans propagation": "traceroute lines without propagation",
    "Partie 3 — segment routing (site sr)": "Part 3 — segment routing (site sr)",
    "Le segment routing dans OSPF": "Segment routing in OSPF",
    """
Les routeurs `sr_r1`, `sr_r2`, `sr_r3` et `sr_r4` forment une ligne (liens `sr_l1`, `sr_l2`,
`sr_l3`). OSPF fonctionne et MPLS est activé dans les noyaux ; il n'y a pas de LDP (sections
@@ref:sr@@ et @@ref:sr-frr@@).

1. Activez le segment routing dans OSPF sur les quatre routeurs, avec le SRGB et l'index de
   prefix-SID donnés dans l'organisation du TP (`sr_r3` n'a pas le même SRGB que les autres).
2. Observez `show ip ospf database segment-routing`, `show mpls table`, `ip -f mpls route` et
   `ip route` sur chaque routeur. Calculez les labels utilisés de `sr_r1` vers `sr_r4`, lien par
   lien, et comparez.
3. `sr_r4` veut recevoir les paquets qui lui sont destinés avec leur label : annoncez son prefix-SID
   **sans PHP**. Qu'est-ce qui change sur `sr_r3` ?
4. Depuis `sr_r1`, faites un `ping` de l'interface de bouclage de `sr_r4` **depuis sa propre
   interface de bouclage** (`ping -I {lo1} {lo4}`) et regardez les labels sur chaque lien
   (`tcpdump -nei eth0 mpls`).
""": """
The routers `sr_r1`, `sr_r2`, `sr_r3` and `sr_r4` form a line (links `sr_l1`, `sr_l2`,
`sr_l3`). OSPF works and MPLS is enabled in the kernels; there is no LDP (sections
@@ref:sr@@ and @@ref:sr-frr@@).

1. Enable segment routing in OSPF on the four routers, with the SRGB and the prefix-SID index
   given in *Organisation of the lab* (`sr_r3` does not have the same SRGB as the others).
2. Observe `show ip ospf database segment-routing`, `show mpls table`, `ip -f mpls route` and
   `ip route` on each router. Compute the labels used from `sr_r1` to `sr_r4`, link by link, and
   compare.
3. `sr_r4` wants to receive the packets destined for it with their label: advertise its
   prefix-SID **without PHP**. What changes on `sr_r3`?
4. From `sr_r1`, ping the loopback interface of `sr_r4` **from its own loopback interface**
   (`ping -I {lo1} {lo4}`) and look at the labels on each link (`tcpdump -nei eth0 mpls`).
""",
    """
**Solution.**

{solution}

Le label se calcule avec le SRGB du routeur **suivant** : `sr_r1` impose {srgb} + {i4} =
**{l_r1}** pour joindre `sr_r4` ; `sr_r2` l'échange contre {srgb3} + {i4} = **{l_r2}** (le SRGB de
`sr_r3`) ; sans PHP, `sr_r3` l'échange contre {srgb} + {i4} = **{l_r1}** (le SRGB de `sr_r4`),
que `sr_r4` retire (`dev lo`). Avec le PHP, `sr_r3` retirait le label. Vers `sr_r3`, `sr_r1`
impose {srgb} + {i3} = **{l_r3}**, que `sr_r2` retire.

Évaluation : `sr_enabled` (4 : un point par routeur présent dans sa propre base SR), `sr_srgb` (3 :
2 pour `sr_r3`, 1 pour les trois autres ensemble), `sr_index` (4 : un point par prefix-SID),
`sr_r2_lfib` (3 : l'échange de `sr_r2`), `sr_r1_ftn` (3 : la route de `sr_r1` vers `sr_r4`),
`sr_ping` (3 : ping entre les interfaces de bouclage, avec des paquets étiquetés reçus par `sr_r2`
et `sr_r3`), `sr_no_php` (2 : l'échange de `sr_r3`, le retrait par `sr_r4`).
""": """
**Solution.**

{solution}

The label is computed with the SRGB of the **next** router: `sr_r1` pushes {srgb} + {i4} =
**{l_r1}** to reach `sr_r4`; `sr_r2` swaps it for {srgb3} + {i4} = **{l_r2}** (the SRGB of
`sr_r3`); without PHP, `sr_r3` swaps it for {srgb} + {i4} = **{l_r1}** (the SRGB of `sr_r4`),
which `sr_r4` removes (`dev lo`). With PHP, `sr_r3` removed the label. Towards `sr_r3`, `sr_r1`
pushes {srgb} + {i3} = **{l_r3}**, which `sr_r2` removes.

Evaluation: `sr_enabled` (4: one point per router present in its own SR database), `sr_srgb` (3:
2 for `sr_r3`, 1 for the three others together), `sr_index` (4: one point per prefix-SID),
`sr_r2_lfib` (3: the swap of `sr_r2`), `sr_r1_ftn` (3: the route of `sr_r1` towards `sr_r4`),
`sr_ping` (3: ping between the loopback interfaces, with labelled packets received by `sr_r2`
and `sr_r3`), `sr_no_php` (2: the swap of `sr_r3`, the removal by `sr_r4`).
""",
    "Les labels du segment routing": "The segment routing labels",
    """
Calculez-les avant de les observer :

- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r4` :
  @@{push4:[0-9]+}@@
- label de ces paquets sur le lien `sr_l2` (de `sr_r2` vers `sr_r3`) : @@{label_l2:[0-9]+}@@
- label de ces paquets sur le lien `sr_l3` (de `sr_r3` vers `sr_r4`), une fois le PHP refusé par
  `sr_r4` : @@{label_l3:[0-9]+}@@
- label imposé par `sr_r1` aux paquets vers l'interface de bouclage de `sr_r3` :
  @@{push3:[0-9]+}@@
""": """
Compute them before observing them:

- label pushed by `sr_r1` onto the packets towards the loopback interface of `sr_r4`:
  @@{push4:[0-9]+}@@
- label of these packets on the link `sr_l2` (from `sr_r2` to `sr_r3`): @@{label_l2:[0-9]+}@@
- label of these packets on the link `sr_l3` (from `sr_r3` to `sr_r4`), once PHP is refused by
  `sr_r4`: @@{label_l3:[0-9]+}@@
- label pushed by `sr_r1` onto the packets towards the loopback interface of `sr_r3`:
  @@{push3:[0-9]+}@@
""",
    """
**Solution.** **{push4}**, **{label_l2}**, **{label_l3}**, **{push3}** (voir la question
précédente).

Évaluation : `sr_q_push4`, `sr_q_label_l2` (2 chacun), `sr_q_label_l3`, `sr_q_push3` (1 chacun).
""": """
**Solution.** **{push4}**, **{label_l2}**, **{label_l3}**, **{push3}** (see the previous
question).

Evaluation: `sr_q_push4`, `sr_q_label_l2` (2 each), `sr_q_label_l3`, `sr_q_push3` (1 each).
""",
    "segment routing actif sur les quatre routeurs": "segment routing active on the four routers",
    "SRGB donnés": "given SRGBs",
    "prefix-SID des interfaces de bouclage": "prefix-SIDs of the loopback interfaces",
    "sr_r2 : échange vers le SRGB de sr_r3": "sr_r2: swap towards the SRGB of sr_r3",
    "sr_r1 : label imposé vers sr_r4": "sr_r1: label pushed towards sr_r4",
    "ping étiqueté entre les interfaces de bouclage": "labelled ping between the loopback interfaces",
    "pas de PHP pour sr_r4": "no PHP for sr_r4",
    "label imposé vers sr_r4": "label pushed towards sr_r4",
    "label sur sr_l2": "label on sr_l2",
    "label sur sr_l3": "label on sr_l3",
    "label imposé vers sr_r3": "label pushed towards sr_r3",
    "Partie 4 — dépannage (site fix)": "Part 4 — troubleshooting (site fix)",
    "Un cœur MPLS en panne": "A broken MPLS core",
    """
Le site `fix` reprend le site `ldp` : `fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2` en ligne, les hôtes
`fix_h1` et `fix_h2`, OSPF et LDP configurés (sans filtre de labels), MPLS activé dans les noyaux.
Pourtant `fix_h1` ne joint pas `fix_h2` : **quatre pannes** ont été glissées dans la configuration
(section @@ref:mpls-debug@@).

Le site doit fonctionner ainsi : `fix_h1` joint `fix_h2`, les **trois sessions LDP** sont établies et
les paquets entre les hôtes sont **étiquetés de bout en bout** (`fix_p1` et `fix_p2` reçoivent des
paquets étiquetés). Trouvez et corrigez chaque panne sans tout reconfigurer : suivez la méthode du
cours, du plan de contrôle au plan de données.

Attention : quand on agrandit la table des labels d'un routeur après coup, zebra ne réinstalle ses
labels dans le noyau qu'au prochain changement de ses LSP (`clear mpls ldp neighbor`).
""": """
The site `fix` repeats the site `ldp`: `fix_pe1`, `fix_p1`, `fix_p2`, `fix_pe2` in a line, the
hosts `fix_h1` and `fix_h2`, OSPF and LDP configured (without a label filter), MPLS enabled in the
kernels. Yet `fix_h1` does not reach `fix_h2`: **four faults** have been slipped into the
configuration (section @@ref:mpls-debug@@).

The site must work as follows: `fix_h1` reaches `fix_h2`, the **three LDP sessions** are
established and the packets between the hosts are **labelled from end to end** (`fix_p1` and
`fix_p2` receive labelled packets). Find and fix each fault without reconfiguring everything:
follow the method of the course, from the control plane to the data plane.

Beware: when the label table of a router is enlarged afterwards, zebra reinstalls its labels in
the kernel only at the next change of its LSPs (`clear mpls ldp neighbor`).
""",
    """
**Solution.**

`fix_p1` (paquets étiquetés jetés à l'entrée d'`eth0`) :

```
sysctl -w net.mpls.conf.eth0.input=1
```

`fix_p2` (aucun label accepté par le noyau : `show mpls table` correcte mais `ip -f mpls route`
vide ; et `eth0` absente de `mpls ldp`, donc pas de session avec `fix_p1`) :

```
sysctl -w net.mpls.platform_labels={labels}
vtysh -c "clear mpls ldp neighbor"
```

{solution_p2}

`fix_pe2` (son adresse de transport, l'interface de bouclage, n'est pas dans OSPF : adjacence avec
`fix_p2` mais pas de session) :

{solution_pe2}

Évaluation : `fix_input` (3), `fix_labels` (3 : 1 pour la table des labels de `fix_p2`, 2 pour des
labels réellement installés dans son noyau), `fix_interface` (3 : 1 pour l'adjacence sur `eth0` de
`fix_p2`, 2 pour la session avec `fix_p1`), `fix_transport` (3 : session `fix_p2` – `fix_pe2`),
`fix_ping` (4), `fix_labelled` (4 : 2 par routeur du cœur qui reçoit des paquets étiquetés pendant
le ping) ; pour l'enseignant seulement : `fix_q_input`, `fix_q_session` (1 chacun).
""": """
**Solution.**

`fix_p1` (labelled packets dropped on input on `eth0`):

```
sysctl -w net.mpls.conf.eth0.input=1
```

`fix_p2` (no label accepted by the kernel: `show mpls table` correct but `ip -f mpls route`
empty; and `eth0` missing from `mpls ldp`, hence no session with `fix_p1`):

```
sysctl -w net.mpls.platform_labels={labels}
vtysh -c "clear mpls ldp neighbor"
```

{solution_p2}

`fix_pe2` (its transport address, the loopback interface, is not in OSPF: adjacency with
`fix_p2` but no session):

{solution_pe2}

Evaluation: `fix_input` (3), `fix_labels` (3: 1 for the label table of `fix_p2`, 2 for labels
really installed in its kernel), `fix_interface` (3: 1 for the adjacency on `eth0` of `fix_p2`,
2 for the session with `fix_p1`), `fix_transport` (3: session `fix_p2` – `fix_pe2`),
`fix_ping` (4), `fix_labelled` (4: 2 per core router that receives labelled packets during the
ping); for the instructor only: `fix_q_input`, `fix_q_session` (1 each).
""",
    "Ce que montraient les pannes": "What the faults showed",
    """
- un paquet étiqueté qui arrive sur une interface dont `net.mpls.conf.<interface>.input` vaut 0 :
  @@{input:>est jeté>>>dropped|est routé en IP>>>routed|perd son label puis est routé>>>popped|est renvoyé à l'émetteur>>>returned}@@
- avant la correction, entre `fix_p2` et `fix_pe2`, il y avait :
  @@{session:>une adjacence Hello, mais pas de session>>>hello_only|ni adjacence ni session>>>nothing|une session établie sans aucun label>>>no_label|une session refusée faute de mot de passe>>>password}@@
""": """
- a labelled packet that arrives on an interface whose `net.mpls.conf.<interface>.input` is 0:
  @@{input:>is dropped>>>dropped|is routed over IP>>>routed|loses its label, then is routed>>>popped|is sent back to the sender>>>returned}@@
- before the fix, between `fix_p2` and `fix_pe2`, there was:
  @@{session:>a Hello adjacency, but no session>>>hello_only|neither an adjacency nor a session>>>nothing|a session established without any label>>>no_label|a session refused for lack of a password>>>password}@@
""",
    """
**Solution.** Il **est jeté** (compté dans les erreurs de réception de l'interface) ; **une
adjacence Hello, mais pas de session** : `fix_p2` ne peut pas joindre l'adresse de transport de
`fix_pe2`.

Évaluation, pour l'enseignant seulement : `fix_q_input`, `fix_q_session` (1 chacun).
""": """
**Solution.** It **is dropped** (counted in the receive errors of the interface); **a Hello
adjacency, but no session**: `fix_p2` cannot reach the transport address of `fix_pe2`.

Evaluation, for the instructor only: `fix_q_input`, `fix_q_session` (1 each).
""",
    "entrée MPLS d'eth0 sur fix_p1": "MPLS input of eth0 on fix_p1",
    "labels acceptés et installés sur fix_p2": "labels accepted and installed on fix_p2",
    "LDP entre fix_p1 et fix_p2": "LDP between fix_p1 and fix_p2",
    "session LDP entre fix_p2 et fix_pe2": "LDP session between fix_p2 and fix_pe2",
    "fix_h1 joint fix_h2": "fix_h1 reaches fix_h2",
    "trafic étiqueté sur tout le chemin": "labelled traffic along the whole path",
    "paquet reçu avec input à 0": "packet received with input at 0",
    "adjacence sans session": "adjacency without a session",
    "Partie 5 — TI-LFA (site tl, bonus)": "Part 5 — TI-LFA (site tl, bonus)",
    "Protection TI-LFA (bonus)": "TI-LFA protection (bonus)",
    """
Les routeurs `tl_r1`, `tl_r2`, `tl_r3` et `tl_r4` forment un carré (coûts OSPF : {costs}). OSPF et
le segment routing y fonctionnent (SRGB par défaut, 16000 à 23999 ; l'index du prefix-SID de
`tl_rN` est N). Seul `tl_r1` a un terminal ; il joint `tl_r3` par `tl_r2` (section @@ref:tilfa@@).

1. Regardez la route de `tl_r1` vers l'interface de bouclage de `tl_r3` (`show ip route {r3}`).
2. Activez sur `tl_r1` la protection TI-LFA **de nœud** : le secours doit éviter `tl_r2` tout
   entier.
3. Regardez à nouveau la route : par où passe le secours, avec quelle pile de labels ? Que
   désignent ces labels ?
""": """
The routers `tl_r1`, `tl_r2`, `tl_r3` and `tl_r4` form a square (OSPF costs: {costs}). OSPF and
segment routing work there (default SRGB, 16000 to 23999; the index of the prefix-SID of `tl_rN`
is N). Only `tl_r1` has a terminal; it reaches `tl_r3` through `tl_r2` (section @@ref:tilfa@@).

1. Look at the route of `tl_r1` towards the loopback interface of `tl_r3` (`show ip route {r3}`).
2. Enable **node** TI-LFA protection on `tl_r1`: the backup must avoid `tl_r2` as a whole.
3. Look at the route again: which way does the backup go, with which label stack? What do these
   labels designate?
""",
    """
**Solution.**

{solution}

Le secours vers `{r3}` part vers `tl_r4` (`eth1`) avec une pile de deux labels qui se termine par
le node-SID de `tl_r3` (16003) ; le premier est un adjacency-SID, qui force le passage de `tl_r4`
vers `tl_r3`.

Évaluation (bonus) : `tl_backup` (3 : une route de secours vers `tl_r3`), `tl_node` (1 : protection
de nœud), `tl_repair` (2 : secours par `tl_r4`, pile terminée par le node-SID de `tl_r3`).
""": """
**Solution.**

{solution}

The backup towards `{r3}` leaves towards `tl_r4` (`eth1`) with a stack of two labels that ends
with the node-SID of `tl_r3` (16003); the first one is an adjacency-SID, which forces the path from
`tl_r4` to `tl_r3`.

Evaluation (bonus): `tl_backup` (3: a backup route towards `tl_r3`), `tl_node` (1: node
protection), `tl_repair` (2: backup through `tl_r4`, stack ending with the node-SID of `tl_r3`).
""",
    "route de secours vers tl_r3": "backup route towards tl_r3",
    "protection de nœud": "node protection",
    "secours par tl_r4 vers le node-SID de tl_r3": "backup through tl_r4 towards the node-SID of tl_r3",
}}
