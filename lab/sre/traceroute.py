"""Traceroute and TTL lab (IPv4 only): emulating traceroute with ping, then with UDP datagrams and a
capture behind a firewall, a routing loop, what the TTL of the replies and the source address of
the ICMP errors reveal.

Three independent networks in one project.

Island A (part 1): ``m1`` — ``lan1`` — ``gw`` — ``core1`` — a hidden line of nine routers ``h1`` —
``c12`` — ``h2`` — ... — ``c89`` — ``h9`` (one hub network per link).  ``m1`` is the student's
machine, stripped of every trace tool at start (traceroute, tracepath, mtr, nmap, hping3...:
``traceroute.remove_tools_cmd``); ``gw`` is visible without a terminal.  The name ``target`` of
``m1``'s ``/etc/hosts`` is the ingress address of one router of the line, ``Data.target`` (h5 to
h9: 4 to 8 hidden routers before it, so the length of the path varies between instances although
the topology is fixed); the routes of the ``initial`` state follow the line up to it symmetrically
(every ``Time to live exceeded`` carries the ingress address), the destination router only knows
the way back and the routers after it get no route; one router of the path (``Data.silent``) never
emits ICMP errors.  The student rebuilds the path with ``ping -t`` / ``ping -R`` and types the
addresses in a form: any address of the right router at the right position counts.

Island C (part 2): ``m2`` — ``lan2`` — ``fw`` — ``core2`` — a second hidden line ``k1`` — ``d12`` —
... — ``k5``, ``target2`` being one of k3 to k5 (``Data.target2``).  Same tool removal on ``m2``,
but ``fw`` is a firewall dropping, before the TTL check, the ICMP echo requests of a TTL below
``Data.ttl_min`` and those carrying IP options (``traceroute.nft_ttl_firewall``): ``ping -t`` and
``ping -R`` no longer map the path.  The student sends UDP datagrams of a chosen TTL with
``nc -u -M TTL`` (or sets ``net.ipv4.ip_default_ttl`` / an nftables ``ip ttl set`` rule) and reads
the ICMP errors in a ``tcpdump`` / ``tshark`` capture (``nc`` prints nothing: the kernel does not
report *time exceeded* to a UDP socket).  ``fw`` counts the non-ICMP probes of a small TTL: the evaluation reads
that counter.  No silent router on this island.

Island B (parts 3 and 4): ``inj`` (traceroute available) — ``lan3`` — a triangle of routers ``r1``
(``l12``) ``r2`` (``l23``) ``r3`` (``l31`` back to ``r1``) without any indirect route, and ``srv``
behind ``r3`` on ``lan4`` (visible, no terminal: an HTTP server behind a firewall dropping UDP).
The student builds the loop r1 → r2 → r3 → r1 with default routes and observes it with ``ping -t``,
``traceroute`` and ``tcpdump`` / ``tshark`` (part 3), then reads the reply TTL, ``ping -R`` and the
source addresses of the errors (``icmp_errors_use_inbound_ifaddr``) and sets ``ip_default_ttl`` on
``inj`` (part 4).  The ``final`` state applies the solution of parts 3 and 4, sends the UDP probes
of part 2 from ``m2`` and fills every form.  Every question ends with its solution in an
``instructor()`` block.

Pure helpers (commands, parsers, loop arithmetic, nft texts, scoring of the typed path) are in
``lib/traceroute.py``.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List, Tuple

import tc
import traceroute as trc
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from bridging import get_sysctl_int
from firewall import setup_http_server
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, set_sysctl, eval_net_config
from state_helpers import create_hosts_file

default_language = 'fr'
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("Traceroute et TTL : tracer un chemin, boucles de routage, chemins asymétriques",
           en="Traceroute and TTL: tracing a path, routing loops, asymmetric paths")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True
# The Kathara export would list the hidden routers and their addresses.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False
allow_save_restore = True

DOMAIN = "tp-trace.lan"
HTTP_PORT = 80
SILENT_TABLE = "silent"            # the hidden silent router: no ICMP time exceeded
SILENT_RULES = "/root/silent.nft"
FW_TABLE = "fw"                    # srv: UDP dropped
FW_RULES = "/root/fw.nft"
TTLFW_TABLE = "ttlfw"              # fw: echo requests of a small TTL dropped, other probes counted
TTLFW_RULES = "/root/ttlfw.nft"
PROBE_TTL_LIMIT = 8                # fw counts the probes below this TTL (target2 is at hop 4 to 6)
PROBE_COUNTER = "probes"
PROBE_TTL = 3                      # TTL of the UDP probe sent by the final state
FAR_NETWORK = IPv4Network("203.0.113.0/24")   # the unrouted destination of the loop (TEST-NET-3)
CYCLE = ('r1', 'r2', 'r3')         # the loop, in the imposed direction
ISLAND_B = ('inj', 'r1', 'r2', 'r3', 'srv')
N_ROUTERS = 9                      # the hidden line h1 - c12 - h2 - ... - c89 - h9 (one hub network per link)
TARGET_RANGE = (5, 9)              # `target` is one of h5..h9: 5 to 9 routers (gw included) between m1 and it
N_ROUTERS2 = 5                     # the hidden line of island C: k1 - d12 - ... - d45 - k5
TARGET_RANGE2 = (3, 5)             # `target2` is one of k3..k5: 3 to 5 routers (fw included), hop 4 to 6 < PROBE_TTL_LIMIT
RP_FILTER_OFF = ('net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')


class _Island:
    """A student machine, its visible gateway and a hidden line of routers, one of which is the
    destination: ``host`` — ``lan`` — ``gateway`` — ``core`` — ``<prefix>1`` — ``<link_prefix>12`` —
    ``<prefix>2`` — ... — ``<prefix>n``.  On the host, *target_name* (``target``) resolves to the
    ingress address of the router ``Data.<target_name>``, drawn in *target_range*."""

    def __init__(self, key: str, host: str, gateway: str, prefix: str, target_name: str, lan: str, core: str,
                 link_prefix: str, n_routers: int, target_range: Tuple[int, int]):
        self.key, self.host, self.gateway, self.prefix, self.target_name = key, host, gateway, prefix, target_name
        self.lan, self.core, self.link_prefix = lan, core, link_prefix
        self.n_routers, self.target_range = n_routers, target_range
        self.routers = [f"{prefix}{i}" for i in range(1, n_routers + 1)]

    def targets(self) -> List[str]:
        """The routers an instance may draw as its destination."""
        lo, hi = self.target_range
        return [f"{self.prefix}{i}" for i in range(lo, hi + 1)]

    def path_to(self, target: str) -> List[str]:
        """The hidden routers before *target* on the line, first router first."""
        return [f"{self.prefix}{i}" for i in range(1, int(target[len(self.prefix):]))]

    def topology(self) -> Dict[str, Dict[str, int]]:
        """``{network: {machine: interface index}}``: eth0 of a router towards the gateway, eth1
        towards the next router (the last router has eth0 only)."""
        topology: Dict[str, Dict[str, int]] = {self.lan: {self.host: 0, self.gateway: 0},
                                               self.core: {self.gateway: 1, self.routers[0]: 0}}
        for i in range(1, self.n_routers):
            topology[trc.link_name(i, i + 1, self.link_prefix)] = {f"{self.prefix}{i}": 1, f"{self.prefix}{i + 1}": 0}
        return topology

    def link(self, a: str, b: str) -> str:
        """The network between two consecutive machines of the chain gateway → routers."""
        if self.gateway in (a, b):
            return self.core
        return trc.link_name(int(a[len(self.prefix):]), int(b[len(self.prefix):]), self.link_prefix)


ISLAND_A = _Island('a', 'm1', 'gw', 'h', 'target', 'lan1', 'core1', 'c', N_ROUTERS, TARGET_RANGE)
ISLAND_C = _Island('c', 'm2', 'fw', 'k', 'target2', 'lan2', 'core2', 'd', N_ROUTERS2, TARGET_RANGE2)
HIDDEN_ROUTERS = ISLAND_A.routers
HIDDEN_ROUTERS2 = ISLAND_C.routers
ROUTERS = ['gw'] + HIDDEN_ROUTERS + ['fw'] + HIDDEN_ROUTERS2 + list(CYCLE)


def _build_topology() -> Dict[str, Dict[str, int]]:
    """Islands A and C from their lines, then island B with explicit numbers."""
    topology: Dict[str, Dict[str, int]] = {}
    topology.update(ISLAND_A.topology())
    topology.update(ISLAND_C.topology())
    topology.update({
        'lan3': {'inj': 0, 'r1': 0},
        'l12': {'r1': 1, 'r2': 0},
        'l23': {'r2': 1, 'r3': 0},
        'l31': {'r3': 1, 'r1': 2},
        'lan4': {'r3': 2, 'srv': 0},
    })
    return topology


_TOPOLOGY = _build_topology()
_SPECS = {
    'm1': {'color': 'lightyellow'},
    'gw': {'allow_connection': False, 'color': 'lightgrey'},    # visible, no terminal
    **{h: {'hidden': True} for h in HIDDEN_ROUTERS},
    'm2': {'color': 'lightyellow'},
    'fw': {'allow_connection': False, 'color': 'lightgrey'},    # visible, no terminal: the firewall
    **{k: {'hidden': True} for k in HIDDEN_ROUTERS2},
    'inj': {'color': 'lightyellow'},
    'r1': {'color': 'lightblue', 'sysctls': RP_FILTER_OFF},
    'r2': {'color': 'lightblue', 'sysctls': RP_FILTER_OFF},
    'r3': {'color': 'lightblue', 'sysctls': RP_FILTER_OFF},
    'srv': {'allow_connection': False, 'color': 'lightgrey'},   # visible, no terminal
}


def _machine_networks(machine: str) -> List[Tuple[int, str]]:
    """``[(interface index, network)]`` of a machine, in interface order."""
    return sorted((members[machine], net) for net, members in _TOPOLOGY.items() if machine in members)


_ALL_MACHINES = sorted({m for members in _TOPOLOGY.values() for m in members})
_SINGLE_HOMED = {m for m in _ALL_MACHINES if len(_machine_networks(m)) == 1}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    target: str = ""                                 # the router of island A that `target` names on m1 (h5..h9)
    silent: str = ""                                 # the router of the path that never says "time exceeded"
    target2: str = ""                                # the router of island C that `target2` names on m2 (k3..k5)
    ttl_min: int = 0                                 # fw drops the echo requests below this TTL
    far_address: IPv4Address = IPv4Address("203.0.113.1")   # destination of the loop (no route anywhere)
    ttl_a: int = 0                                   # ping -t values of the loop questions
    ttl_b: int = 0
    inj_ttl: int = 0                                 # ip_default_ttl to set on inj (part 4)

    @classmethod
    def generate(cls):
        data = cls()
        data.target = random.choice(ISLAND_A.targets())
        data.silent = random.choice(ISLAND_A.path_to(data.target)[1:])   # h1, the first hidden hop, always answers
        data.target2 = random.choice(ISLAND_C.targets())
        data.ttl_min = random.randint(12, 40)        # target2 is at hop 6 at most: any TTL >= ttl_min reaches it
        data.far_address = random.choice(list(FAR_NETWORK.hosts()))
        data.ttl_a = random.choice([t for t in range(5, 31) if t % 3 == 2])     # hop ttl_a is r2
        data.ttl_b = random.choice([t for t in range(31, 64) if t % 3 == 0])    # hop ttl_b is r3
        data.inj_ttl = random.randint(8, 60)
        nets = random_ipv4networks(masks=[24] * len(_TOPOLOGY), from_private_network=True,
                                   exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in zip(_TOPOLOGY, nets):
            setattr(data.nets, name, net)
        # ips.m1, ips.gw_lan1, ips.gw_core1, ips.h1_core1, ips.h1_c12, ips.h2_c12, ..., ips.h9 (single-homed),
        # ips.m2, ips.fw_lan2, ips.fw_core2, ips.k1_core2, ips.k1_d12, ..., ips.k5, ips.inj, ips.r1_lan3,
        # ips.r1_l12, ips.r1_l31, ips.r2_l12, ips.r2_l23, ips.r3_l23, ips.r3_l31, ips.r3_lan4, ips.srv
        random_ips_from_topology(data, _TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = _SPECS
    _network_specs = {
        'lan1': {'color': 'lightyellow'},
        'core1': {'shape': 'cloud'},        # what lies behind the gateway is unknown to the student
        'lan2': {'color': 'lightyellow'},
        'core2': {'shape': 'cloud'},
        'lan3': {'color': 'lightyellow'},
        'l12': {'color': 'lightblue'},
        'l23': {'color': 'lightblue'},
        'l31': {'color': 'lightblue'},
        'lan4': {'color': 'lightgrey'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.expected_path: List[str] = ['gw'] + ISLAND_A.path_to(d.target)     # the routers from m1 to target
        self.silent_index: int = self.expected_path.index(d.silent)
        self.expected_path2: List[str] = ['fw'] + ISLAND_C.path_to(d.target2)   # the routers from m2 to target2
        self.expected_paths: Dict[str, List[str]] = {ISLAND_A.key: self.expected_path, ISLAND_C.key: self.expected_path2}
        self.targets: Dict[str, str] = {ISLAND_A.key: d.target, ISLAND_C.key: d.target2}   # the destination routers
        default = IPv4Network("0.0.0.0/0")
        routes: Dict[str, List[Tuple[IPv4Network, IPv4Interface]]] = {m: [] for m in self.get_machine_names()}
        for island in (ISLAND_A, ISLAND_C):
            self._island_routes(island, routes)
        routes['srv'].append((default, self.addr('r3', 'lan4')))
        self.net_config: Dict[str, NetConfigEntry] = {m: self._entries(m, routes[m]) for m in routes}
        # the solution of part 2: the loop r1 -> r2 -> r3 -> r1, entered from inj
        self.net_config_final: Dict[str, NetConfigEntry] = {
            'inj': self._entries('inj', [(default, self.addr('r1', 'lan3'))]),
            'r1': self._entries('r1', [(default, self.addr('r2', 'l12'))]),
            'r2': self._entries('r2', [(default, self.addr('r3', 'l23'))]),
            'r3': self._entries('r3', [(default, self.addr('r1', 'l31'))]),
        }

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
#             + tr("""
# Ce TP étudie le champ **TTL** des paquets IPv4, le message ICMP *time exceeded* qu'il provoque, et
# l'outil **traceroute** qui en tire le chemin suivi par les paquets : son principe, ses variantes,
# ses limites, la façon de l'émuler avec `ping`, et ce que révèlent une **boucle de routage** ou un
# **chemin asymétrique**.
# """)
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le champ TTL"), tag="ttl")
            + tr("""
Chaque paquet IPv4 porte un champ **TTL** (*time to live*, 8 bits) fixé par l'émetteur et
**décrémenté de 1 par chaque routeur** traversé. Un routeur qui reçoit un paquet dont le TTL vaut 1
le **détruit** au lieu de le retransmettre (il tomberait à 0). Sans ce garde-fou un paquet 
pourrait circuler indéfiniment s'il existe une boucle de routage par suite d'une erreur de configuration
(cf section @@ref:loops@@).

La valeur initiale du TTL dépend du système : **64** pour Linux, macOS et les BSD, **128** pour Windows,
**255** pour la plupart des routeurs (Cisco, Juniper). 

Sous Linux elle se lit et se change par
`sysctl net.ipv4.ip_default_ttl`. 

On voit le TTL de chaque paquet capturé avec `tcpdump -n -v` ou avec `tshark -n`
(on peut spécifier les champs à afficher ainsi :

``tshark -n -T fields -e ip.src -e ip.dst -e ip.ttl -e _ws.col.Info``
""")
            + info_subtitle(tr("Le message ICMP time exceeded"), tag="time-exceeded")
            + tr("""
Le routeur qui détruit un paquet au TTL 1 renvoie à **l'émetteur du paquet** un message ICMP *time to live exceeded in transit*
(**type 11, code 0**). Comme toute erreur ICMP, il contient l'en-tête IP du
paquet fautif et les 8 premiers octets de sa charge utile : l'émetteur reconnaît ainsi le paquet
concerné (identifiant et numéro de séquence d'un écho ICMP, ports d'un datagramme UDP ou d'un
segment TCP). La commande `ping` et les analyseurs réseaux `tcpdump` et `tshark` le montrent.

**Adresse source du message TTL exceeded.** Sous Linux, l'erreur ICMP part avec 
l'adresse de l'interface du routeur
**par laquelle elle est émise** si le paramètre `net.ipv4.icmp_errors_use_inbound_ifaddr` vaut `0`.

Avec le paramètre à 1, c'est toujours l'adresse de
l'interface par laquelle le paquet fautif est **arrivé**, ce que font également la plupart des routeurs dédiés.

**limitation du débit par les routeurs** Les routeurs limitent souvent le débit
des erreurs ICMP qu'ils émettent. Une sonde sans réponse n'est pas forcément un routeur muet.

Sous Linux, les paramètres `net.ipv4.icmp_ratelimit` et `icmp_msgs_per_sec` contrôlent cette limitation.
 Dans ce projet la limitation est désactivée.
""")
            + info_subtitle(tr("Le principe de traceroute"), tag="principle")
            + tr("""
`traceroute` exploite ce mécanisme pour **découvrir les routeurs** d'un chemin : il envoie une sonde
avec un **TTL de 1** (le premier routeur la détruit et répond *time exceeded* : son adresse est
connue), puis une sonde avec un TTL de 2, de 3… jusqu'à ce que la **destination elle-même** réponde.
La réponse de la destination dépend de la sonde (section @@ref:methods@@) : *port unreachable*
(ICMP type 3, code 3) pour un datagramme UDP vers un port fermé, *echo reply* pour un écho ICMP,
SYN/ACK ou RST pour un SYN TCP.

Par défaut : trois sondes par saut (`-q 3`), 30 sauts au plus (`-m 30`), 5 s d'attente par sonde
(`-w 5`) et résolution inverse des noms (`-n` pour l'éviter). Chaque ligne donne le numéro du saut,
l'adresse qui a répondu et le temps aller-retour de chaque sonde :

```
traceroute to 10.5.0.9 (10.5.0.9), 30 hops max, 60 byte packets
 1  192.168.30.1  0.215 ms  0.180 ms  0.170 ms
 2  10.1.0.2  0.401 ms * 0.390 ms
 3  * * *
 4  10.5.0.9  0.744 ms  0.700 ms  0.690 ms
```

Ce que traceroute montre, c'est la liste des **adresses** qui ont émis une erreur, pas des
« routeurs » : pour un même routeur, l'adresse dépend de l'interface choisie (section
@@ref:time-exceeded@@). Il ne voit que le chemin **aller** (section @@ref:asymmetry@@), et les
sondes successives peuvent suivre des chemins différents quand un routeur répartit la charge
(*load balancing*) : la liste mélange alors deux chemins.
""")
            + info_subtitle(tr("Lire une sortie de traceroute"), tag="reading")
            + tr("""
- `*` : aucune réponse à la sonde dans le délai. Un saut `* * *` **au milieu** d'une trace qui
  continue est un routeur **muet** (il n'émet pas d'erreur ICMP, ou son erreur est filtrée ou limitée
  en débit) : le chemin fonctionne. Des `*` **jusqu'à la fin** sans que la destination apparaisse :
  les sondes ou les réponses sont filtrées quelque part, ou la destination est injoignable.
- `!H`, `!N` : *host* / *network unreachable* renvoyé par un routeur ; `!X` : *communication
  administratively prohibited*, un pare-feu qui **rejette** au lieu de détruire le paquet (ICMP type 3, code 13) ;
  `!P` : protocole inaccessible. La trace s'arrête à ce saut.
- Une suite d'adresses qui se **répète** (`A B C A B C …`) jusqu'au nombre maximal de sauts : boucle
  de routage (section @@ref:loops@@).
- Les temps : aller-retour de chaque sonde jusqu'à ce saut. Un temps plus grand pour un saut
  intermédiaire que pour la destination n'a rien d'anormal (les routeurs traitent les erreurs ICMP
  avec une priorité basse).

Options utiles : `-n` (pas de noms), `-q 1` (une sonde par saut), `-w 1` (une seconde d'attente),
`-m 8` (8 sauts au plus), `-f 3` (commencer au TTL 3), `-I` / `-T` (section @@ref:methods@@).
""")
            + info_subtitle(tr("Les méthodes : UDP, ICMP, TCP et les pare-feu"), tag="methods")
            + tr("""
`traceroute` peut fonctionner avec n'importe quel type de paquet IP, seul compte le TTL.
Par défaut `traceroute` utilise des paquets UDP mais s'ils sont détruits par un parefeu sur le chemin on
peut utiliser des paquets ICMP ou TCP.           

| méthode | sondes | fin de parcours | remarque |
|---------|--------|-----------------|----------|
| UDP (défaut sous Linux) | datagrammes vers les ports 33434, 33435… (« improbables ») | ICMP *port unreachable* de la destination | souvent filtré par les pare-feu : des `*` à la fin |
| ICMP (`-I` ; `tracert` de Windows) | échos ICMP | *echo reply* | passe là où `ping` passe |
| TCP (`-T`, port 80 par défaut, `-p PORT`) | SYN TCP | SYN/ACK (port ouvert) ou RST (port fermé) | traverse les pare-feu qui laissent passer le service |

Autres outils : `tracepath` (UDP, sans privilèges, affiche aussi le MTU du chemin ; `no reply` pour
un saut muet), `mtr` (ICMP, trace répétée avec statistiques de pertes), `nmap --traceroute`.

**Pare-feu.** Un hôte qui **détruit** (*drop*) les datagrammes UDP ne renvoie jamais le *port
unreachable* : `traceroute` affiche des `*` jusqu'à `-m` alors que la machine répond à `ping` et
sert ses pages web ; `traceroute -I` ou `traceroute -T` l'atteignent. Un pare-feu qui **rejette**
(*reject*) avec *admin prohibited* termine la trace par `!X`. Un routeur qui filtre ses propres
erreurs *time exceeded* apparaît comme un saut muet.
""")
#             + info_subtitle(tr("Émuler traceroute avec ping"), tag="emulation")
#             + tr("""
# `ping` fixe le TTL de ses échos avec `-t` : `ping -n -c 1 -W 1 -t 1 DEST` fait répondre le premier
# routeur (`From ADRESSE icmp_seq=1 Time to live exceeded`), `-t 2` le deuxième, et ainsi de suite
# jusqu'à la réponse de la destination (`64 bytes from DEST`). C'est exactement traceroute en mode
# ICMP, une sonde par saut ; un saut muet donne `1 packets transmitted, 0 received`. Options utiles :
# `-n` (pas de résolution inverse), `-W 1` (une seconde d'attente), `-c 1` (un seul écho).
#
# `ping -R` demande aux routeurs d'**enregistrer leur adresse** dans le paquet (option IP *record
# route*) : la réponse affiche, après `RR:`, l'adresse de l'émetteur, les adresses de **sortie** de
# chaque routeur à l'aller, la destination (deux fois : à l'arrivée, puis comme source de la réponse),
# puis les adresses de sortie au **retour**. L'en-tête IP n'a de place que pour **neuf** adresses et
# beaucoup de routeurs ignorent l'option : c'est un complément, pas un remplaçant.
#
# `tcpdump -n -v -i eth0 icmp` sur un routeur montre les sondes qui le traversent avec leur TTL
# (`ttl N`) et les erreurs qu'il émet (`ICMP time exceeded in-transit`) ; `tshark -n -i eth0 icmp`
# de même (`ttl=N` au bout de la ligne de chaque écho, `Time-to-live exceeded`).
# """)
#             + info_subtitle(tr("Émuler traceroute sans ICMP : UDP, nc et une capture"), tag="emulation-udp")
#             + tr("""
# Le TTL est un champ de l'en-tête **IP** : n'importe quel paquet fait l'affaire, pas seulement un
# écho ICMP. C'est ce que fait `traceroute` lui-même avec ses datagrammes UDP (section
# @@ref:methods@@), et c'est indispensable quand un pare-feu filtre les échos ICMP (ou seulement ceux
# de TTL faible, pour gêner la cartographie de son réseau) tout en laissant passer le reste.
#
# **Envoyer la sonde** : `echo x | nc -u -w 1 -M 3 DEST 33434` envoie un datagramme UDP de TTL 3
# vers un port « improbable » de la destination (`-M` fixe le TTL avec le netcat d'OpenBSD de Debian
# 12 ; `-w 1` fait quitter `nc` après une seconde sans réponse). Sans cette option, on fixe le TTL
# des paquets émis soit pour toute la machine avec `sysctl -w net.ipv4.ip_default_ttl=3` (à remettre
# à 64 ensuite), soit pour les seuls datagrammes concernés avec une règle nftables qui réécrit le
# champ :
#
# ```
# nft add table ip trace
# nft 'add chain ip trace output { type filter hook output priority mangle; }'
# nft add rule ip trace output udp dport 33434 ip ttl set 3
# ```
#
# **Lire la réponse** dans un second terminal : `tcpdump -n -i eth0 icmp` affiche
# `R > M: ICMP time exceeded in-transit` pour le routeur R qui a jeté la sonde, puis, quand le TTL
# suffit pour arriver, `D > M: ICMP D udp port 33434 unreachable` : la destination D est atteinte et
# la trace est finie. `tshark -n -i eth0 icmp` montre la même chose (`Time-to-live exceeded`,
# `Destination unreachable (Port unreachable)`) ; pour le détail d'un message, datagramme cité compris :
# `tcpdump -n -v -i eth0 icmp` ou `tshark -n -i eth0 -O icmp icmp`.
#
# Pourquoi une capture ? Le noyau ne transmet une erreur ICMP à un socket UDP que si elle est
# « dure » (*port unreachable*) ou si le programme a demandé toutes les erreurs (option `IP_RECVERR`,
# ce que fait `traceroute`) : `nc` ne voit pas passer les *time exceeded*, et il se termine sans
# rien dire dans tous les cas (seul son code de retour change, avec `-v`, quand le port est
# inaccessible). Un SYN TCP (`nc -w 1 -M 3 DEST 80`) fonctionne de la même façon, comme
# `traceroute -T`.
# """)
            + info_subtitle(tr("Le TTL des réponses"), tag="reply-ttl")
            + tr("""
Le `ttl=` affiché par `ping` est celui de l'*echo reply* à son arrivée : la destination l'a émis
avec son TTL initial (64, 128 ou 255 : on devine le système), et chaque routeur du **chemin retour**
l'a décrémenté. `ttl=62` depuis une machine Linux : deux routeurs au retour. Comparer ce nombre au
nombre de sauts de traceroute (chemin aller) révèle un chemin asymétrique (section
@@ref:asymmetry@@). Le TTL des paquets **émis** par une machine se change avec
`sysctl -w net.ipv4.ip_default_ttl=N` ; trop petit, ses paquets n'atteignent plus les destinations
lointaines et elle reçoit des *time exceeded* sans les avoir demandés.
""")
            + info_subtitle(tr("Les boucles de routage"), tag="loops")
            + tr("""
Une **boucle** apparaît quand les routes de plusieurs routeurs se renvoient mutuellement un
paquet : `r1` a sa route par défaut vers `r2`, `r2` vers `r3`, `r3` vers `r1`, et un paquet pour
une destination qu'aucun d'eux ne connaît tourne entre eux jusqu'à ce que son TTL tombe à 0. Causes
typiques : routes par défaut « en chaîne » mal pensées, route statique vers un voisin qui renvoie
lui-même vers sa route par défaut, routage dynamique en cours de convergence.

Symptômes : `ping` reçoit *Time to live exceeded* d'un routeur sans qu'on ait touché au TTL,
`traceroute` répète les mêmes adresses jusqu'à `-m`, et la charge des routeurs monte (chaque paquet
est traité des dizaines de fois).

**Arithmétique.** Un paquet émis avec le TTL *T* arrive au saut *k* avec le TTL *T − k + 1* : il est
jeté au saut *T*. Pour une boucle de *n* routeurs entrée par le premier, le saut *k* est le routeur
numéro *((k − 1) mod n) + 1*. Avec *T* = 64 et trois routeurs, 64 = 3 × 21 + 1 : c'est le premier
routeur qui répond, après que le paquet a traversé chacun des deux autres 21 fois. Changer le TTL
(`ping -t`) change le routeur qui répond. `ip route get DEST` sur un routeur montre la route qu'il
applique.
""")
            + info_subtitle(tr("Chemins asymétriques"), tag="asymmetry")
            + tr("""
Rien n'oblige les paquets d'une réponse à reprendre le chemin de la requête : chaque routeur décide
seul, d'après sa table, du prochain saut vers la destination du paquet qu'il traite. Le chemin
retour est donc souvent **différent** de l'aller (politiques de routage, liens de coût différent,
routes par défaut). `traceroute` ne montre que l'**aller** ; pour voir le retour il faut un
traceroute depuis l'autre extrémité (*reverse traceroute*), ou des indices : le `ttl=` des réponses
(section @@ref:reply-ttl@@), les adresses enregistrées par `ping -R`, ou les adresses sources des
erreurs ICMP, qui désignent l'interface par laquelle chaque routeur **retourne** vers l'émetteur
(section @@ref:time-exceeded@@).
""")
#             + info_subtitle(tr("Outils"), tag="tools")
#             + tr("""
# | outil | usage |
# |-------|-------|
# | `ping -n -c 1 -W 1 -t N DEST` | sonde au TTL N : le routeur du saut N répond |
# | `ping -n -c 1 -R DEST` | adresses de sortie enregistrées (neuf au plus, aller puis retour) |
# | `echo x \\| nc -u -w 1 -M N DEST 33434` | sonde UDP de TTL N (sinon `sysctl -w net.ipv4.ip_default_ttl=N` ou une règle `ip ttl set`) |
# | `tcpdump -n -i IFACE icmp`, `tshark -n -i IFACE icmp` | erreurs ICMP reçues : routeur qui répond, fin de parcours |
# | `traceroute -n -q 1 -w 1 -m 8 DEST` | trace UDP ; `-I` ICMP, `-T` TCP (port 80, `-p PORT`) |
# | `tracepath -n DEST`, `mtr -n DEST` | variantes |
# | `tcpdump -n -v -i IFACE icmp`, `tshark -n -i IFACE -O icmp icmp` | TTL des paquets (`ttl N` ; `tshark -n` l'écrit déjà, `ttl=N`, sur la ligne de chaque écho), détail des erreurs ICMP |
# | `ip route`, `ip route get DEST` | table de routage, route choisie pour une destination |
# | `ip route add default via GW`, `ip route replace default via GW`, `ip route del default` | routes |
# | `sysctl net.ipv4.ip_default_ttl`, `sysctl -w net.ipv4.icmp_errors_use_inbound_ifaddr=1` | paramètres du noyau |
# | `nft list ruleset` | règles de filtrage d'une machine |
# """)
            + info_subtitle(tr("Dépannage"), tag="troubleshooting")
            + tr("""
| symptôme | cause probable |
|----------|----------------|
| `ping: connect: Network is unreachable` | pas de route vers la destination sur l'émetteur |
| `From R icmp_seq=1 Destination Net Unreachable` | le routeur R n'a pas de route (ICMP type 3, code 0) |
| `From R icmp_seq=1 Time to live exceeded` sans `-t` | boucle de routage, ou TTL initial trop petit |
| `traceroute` : des `*` jusqu'à la fin | sondes UDP jetées par la destination (essayer `-I`, `-T`), ou chemin coupé |
| `traceroute` : un seul saut `*`, la suite normale | routeur muet (pas d'erreur ICMP) : rien à corriger |
| `traceroute` affiche `!X` | pare-feu qui rejette (*admin prohibited*) |
| `ping -t N` ne reçoit rien, `ping` sans `-t` répond | pare-feu qui jette les échos de TTL faible : sonder avec UDP ou TCP |
| `nc -u` n'affiche rien | normal : le *time exceeded* n'est pas remonté au socket, lire la capture |
| `traceroute` très lent | 5 s × 3 sondes par saut muet : `-q 1 -w 1 -m 8` |
| `ping -R` sans ligne `RR:` | option ignorée par un routeur ou par la destination |
""")
        )

    # -- helpers ---------------------------------------------------------------

    def _island_routes(self, island: _Island, routes: Dict[str, list]):
        """The routes of an island along its hidden path: the host and the gateway forward, each
        router before the destination forward and back to the host's LAN (symmetric: every *time
        exceeded* carries the ingress address), the destination router back only; the routers after
        it get nothing."""
        default = IPv4Network("0.0.0.0/0")
        lan = getattr(self.data.nets, island.lan)
        target = self.targets[island.key]
        chain = self.expected_paths[island.key] + [target]      # the gateway, the routers, the destination
        routes[island.host].append((default, self.addr(island.gateway, island.lan)))
        routes[island.gateway].append((default, self.addr(chain[1], island.core)))
        for k in range(1, len(chain) - 1):
            r, prev, nxt = chain[k], chain[k - 1], chain[k + 1]
            routes[r].append((lan, self.addr(prev, island.link(prev, r))))
            if nxt != target:
                routes[r].append((default, self.addr(nxt, island.link(r, nxt))))
        routes[target].append((default, self.addr(chain[-2], island.link(chain[-2], target))))

    def addr(self, machine: str, net: str) -> IPv4Interface:
        """The address of *machine* on *net* (``data.ips.m`` or ``data.ips.m_net``)."""
        return getattr(self.data.ips, machine if machine in _SINGLE_HOMED else f"{machine}_{net}")

    def _entries(self, machine: str, routes) -> NetConfigEntry:
        """The net_config entry of *machine*: one tuple per interface, each route on the interface
        whose network holds its gateway (``ip route add`` needs that interface up and addressed)."""
        nets = _machine_networks(machine)
        entries = [([self.addr(machine, net)], []) for _, net in nets]
        for dest, via in routes:
            for k, (_, net) in enumerate(nets):
                if via.ip in getattr(self.data.nets, net):
                    entries[k][1].append((dest, via))
                    break
            else:
                raise ValueError(f"{machine}: gateway {via.ip} is on no network of the machine")
        return entries

    def hop_address(self, k: int, island: _Island = ISLAND_A) -> IPv4Interface:
        """The address of the k-th hop of an island (0 = its gateway, ``len(expected_path)`` = the
        destination) on its ingress link: what the student sees in ``Time to live exceeded``."""
        chain = [island.host] + self.expected_paths[island.key] + [self.targets[island.key]]
        return self.addr(chain[k + 1], island.lan if k == 0 else island.link(chain[k], chain[k + 1]))

    def target_address(self, island: _Island = ISLAND_A) -> IPv4Interface:
        """The address ``target`` / ``target2`` names on the host: the ingress address of the
        destination router."""
        return self.hop_address(len(self.expected_paths[island.key]), island)

    # -- states ------------------------------------------------------------------

    def _configure_network(self):
        """Runtime configuration, applied at start and again after a restore (addresses, routes,
        nft tables and daemons do not survive it)."""
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1 and a read-only /proc/sys: routers
            # only, and the remount lets the students run sysctl -w afterwards.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTERS))
        # the silent router of the hidden path
        self.file(d.silent, SILENT_RULES, trc.nft_drop_icmp_types(SILENT_TABLE))
        self.cmd(d.silent, f"nft delete table ip {SILENT_TABLE} 2>/dev/null; nft -f {SILENT_RULES}")
        # fw: no echo request of a small TTL (nor with IP options) towards the hidden graph; the
        # other small-TTL packets are counted
        self.file('fw', TTLFW_RULES, trc.nft_ttl_firewall(TTLFW_TABLE, d.ttl_min, iif='eth0',
                                                          probe_ttl_limit=PROBE_TTL_LIMIT, comment=PROBE_COUNTER))
        self.cmd('fw', f"nft delete table ip {TTLFW_TABLE} 2>/dev/null; nft -f {TTLFW_RULES}")
        # srv: UDP dropped, web server
        self.file('srv', FW_RULES, trc.nft_udp_policy(FW_TABLE, 'drop'))
        self.cmd('srv', f"nft delete table ip {FW_TABLE} 2>/dev/null; nft -f {FW_RULES}")
        setup_http_server(self, 'srv', HTTP_PORT, 'srv')
        # names: m1 / m2 know themselves, their gateway and their target only (nothing of the hidden
        # graphs); island B knows itself
        for island in (ISLAND_A, ISLAND_C):
            host, gateway, target = island.host, island.gateway, island.target_name
            hosts = (f"127.0.0.1\t\tlocalhost\n127.0.1.1\t\t{host}\t\t{host}.{DOMAIN}\n"
                     f"{self.addr(host, island.lan).ip}\t\t{host}\t\t{host}.{DOMAIN}\n"
                     f"{self.addr(gateway, island.lan).ip}\t\t{gateway}\t\t{gateway}.{DOMAIN}\n"
                     f"{self.target_address(island).ip}\t\t{target}\t\t{target}.{DOMAIN}\n")
            self.file(host, '/etc/hosts', hosts)
            # the student machines without any trace tool
            self.cmd(host, trc.remove_tools_cmd())
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=list(ISLAND_B), included=list(ISLAND_B))

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()

    @sre_state(user_allowed=False)
    def restore(self):
        self._configure_network()

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of parts 3 and 4 (idempotent), one UDP probe of part 2 from m2 so that
        the counter of fw is not zero; nothing to configure for part 1 (answers only)."""
        d = self.data
        self.cmd('m2', f"{trc.nc_udp_cmd(self.target_address(ISLAND_C).ip, ttl=PROBE_TTL)}; true", timeout=10)
        for m, entries in self.net_config_final.items():
            for _, routes in entries:
                for dest, via in routes:
                    self.cmd(m, f"ip route replace {dest.compressed} via {via.ip}")
        for r in ('r2', 'r3'):
            set_sysctl(net_scheme=self, machine_name=r, sysctl_config={'net.ipv4.icmp_errors_use_inbound_ifaddr': 1})
        set_sysctl(net_scheme=self, machine_name='inj', sysctl_config={'net.ipv4.ip_default_ttl': d.inj_ttl})


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _int(s, default=None):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _norm(s) -> str:
    return (s or "").strip().lower()


def _is(answer, expected) -> bool:
    """A numeric form answer equals *expected*."""
    return _int(answer) == int(expected)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _hidden_hops_table(self, island: _Island = ISLAND_A) -> str:
        """Markdown rows of the hidden path of an island for the instructor: hop, router, ingress
        address, every address; the last row is the destination router.  The notes are language
        neutral (the rows are formatted into a text of every language): the name of the destination,
        ``*`` for the silent router (what a trace shows at its hop)."""
        d = self.get_data()
        ns = self.net_scheme
        rows = []
        chain = ns.expected_paths[island.key] + [ns.targets[island.key]]
        for k, m in enumerate(chain):
            all_addresses = ", ".join(str(a.ip) for name, a in vars(d.ips).items() if name.split('_')[0] == m)
            note = f" (`{island.target_name}`)" if k == len(chain) - 1 else " (`*`)" if m == d.silent else ""
            rows.append(f"| {k + 1} | `{m}`{note} | `{ns.hop_address(k, island).ip}` | {all_addresses} |")
        return "\n".join(rows)

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        expected = ns.expected_path
        n_routers = len(expected)
        silent_hop = ns.silent_index + 1
        far = str(d.far_address)
        srv = str(d.ips.srv.ip)
        target = str(ns.target_address(ISLAND_A).ip)
        expected2 = ns.expected_path2
        n_routers2 = len(expected2)
        target2 = str(ns.target_address(ISLAND_C).ip)
        addr = ns.addr
        owner = lambda a: trc.address_owner(a, d.ips)   # noqa: E731

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m in ('m1', 'm2'):
            self.test(m, f"for n in {' '.join(trc.TRACE_TOOLS)}; do command -v $n; done; echo END", allow_error=True)
        for m in ('m1', 'm2', 'inj', 'r1', 'r2', 'r3'):
            self.test(m, "ip route show", allow_error=True)
        for m in ('r2', 'srv'):
            self.test(m, "nft list ruleset", allow_error=True)

        # ---------------- live test of island C: the probes counted by fw ------------------
        fw_out, _ = self.test('fw', f"nft list table ip {TTLFW_TABLE}", allow_error=True)
        probes = trc.nft_counter_packets(fw_out, PROBE_COUNTER) or 0

        # ---------------- live tests of island B --------------------------------------------
        route_ok = {m: eval_net_config(grade=self, expected=ns.net_config_final[m], machine_name=m).default_route
                    for m in ns.net_config_final}
        loop_cmd = (f'echo "===T64"; {trc.ping_ttl_cmd(far, 64)} 2>&1; '
                    f'echo "===TB"; {trc.ping_ttl_cmd(far, d.ttl_b)} 2>&1; true')
        loop_out, _ = self.test('inj', loop_cmd, timeout=15, allow_error=True)
        from_64 = owner(trc.error_from(tc.section_text(loop_out, 'T64')) or '')
        from_b = owner(trc.error_from(tc.section_text(loop_out, 'TB')) or '')
        inbound = {r: get_sysctl_int(self, r, 'net.ipv4.icmp_errors_use_inbound_ifaddr') for r in ('r2', 'r3')}
        inj_ttl = get_sysctl_int(self, 'inj', 'net.ipv4.ip_default_ttl')

        # ---------------- texts shared by the questions ---------------------------------
        addressing_b = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan3` | `{lan3}` | `inj` (`{inj}`), `r1` eth0 (`{r1_lan3}`, nom `r1_lan3`) |
| `l12` | `{l12}` | `r1` eth1 (`{r1_l12}`, `r1_l12`), `r2` eth0 (`{r2_l12}`, `r2_l12`) |
| `l23` | `{l23}` | `r2` eth1 (`{r2_l23}`, `r2_l23`), `r3` eth0 (`{r3_l23}`, `r3_l23`) |
| `l31` | `{l31}` | `r3` eth1 (`{r3_l31}`, `r3_l31`), `r1` eth2 (`{r1_l31}`, `r1_l31`) |
| `lan4` | `{lan4}` | `r3` eth2 (`{r3_lan4}`, `r3_lan4`), `srv` (`{srv}`) |
""").format(lan3=d.nets.lan3, l12=d.nets.l12, l23=d.nets.l23, l31=d.nets.l31, lan4=d.nets.lan4, inj=d.ips.inj.ip,
            r1_lan3=addr('r1', 'lan3').ip, r1_l12=addr('r1', 'l12').ip, r2_l12=addr('r2', 'l12').ip,
            r2_l23=addr('r2', 'l23').ip, r3_l23=addr('r3', 'l23').ip, r3_l31=addr('r3', 'l31').ip,
            r1_l31=addr('r1', 'l31').ip, r3_lan4=addr('r3', 'lan4').ip, srv=srv)
        addressing_a = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `gw` (`{gw}`) |
| au-delà de `gw` | inconnu | des routeurs, puis `target` (`{target}`) |
""").format(lan1=d.nets.lan1, m1=d.ips.m1.ip, gw=addr('gw', 'lan1').ip, target=target)
        addressing_c = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan2` | `{lan2}` | `m2` (`{m2}`), `fw` (`{fw}`) |
| au-delà de `fw` | inconnu | des routeurs, puis `target2` (`{target2}`) |
""").format(lan2=d.nets.lan2, m2=d.ips.m2.ip, fw=addr('fw', 'lan2').ip, target2=target2)

        # ---------------- organisation ----------------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
L'onglet **Informations** présente le TTL, le message ICMP *time exceeded*, le principe
et les variantes de traceroute, son émulation avec `ping`, les boucles de routage et les chemins
asymétriques.

Ce TP contient trois réseaux indépendants, décrits au début des parties 1, 2 et 3 (le troisième
sert aussi à la partie 4).

**Conseils.** Utilisez toujours `-n` (pas de résolution inverse) et une attente courte :
`ping -n -c 1 -W 1`, `traceroute -n -q 1 -w 1 -m 8`. L'adresse de destination de la partie 3
n'appartient à aucun réseau de la maquette : c'est voulu.

**Évaluation.** Chaque évaluation lit vos réponses aux formulaires, le compteur de sondes du
pare-feu `fw`, les routes de `inj`, `r1`, `r2`, `r3` et deux paramètres du noyau, puis lance depuis
`inj` deux `ping -t` vers la destination de la partie 3 (quelques secondes). Elle ne modifie rien.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- Chemin caché de `m1` à `target` ({n} routeurs, `gw` compris, puis la cible) ; le routeur **muet**
  est au saut {silent_hop} (`{silent}`) :

| saut | routeur | adresse vue par `ping -t` (entrée) | toutes ses adresses |
|------|---------|------------------------------------|---------------------|
{hops}

- `target` : `{target}`, TTL initial 64 ; `ping target` depuis `m1` répond avec `ttl={reply_ttl}`.
- Chemin caché de `m2` à `target2` ({n2} routeurs, `fw` compris, puis la cible), aucun routeur muet ; `fw` jette
  les échos ICMP de TTL inférieur à **{ttl_min}** et ceux qui portent une option IP, et compte les
  autres paquets de TTL inférieur à {probe_limit} (règle `counter comment "{counter}"`) :

| saut | routeur | adresse vue dans la capture (entrée) | toutes ses adresses |
|------|---------|--------------------------------------|---------------------|
{hops2}

- `target2` : `{target2}` ; `ping target2` répond avec `ttl={reply_ttl2}` ; `ping -t N target2`
  répond pour N ≥ {ttl_min} seulement.
- Partie 3 : destination `{far}`, boucle attendue `r1 → r2 → r3 → r1` ; `ping -t {ttl_a}` → `r2`,
  `ping -t {ttl_b}` → `r3`, TTL 64 → `r1`.
- Partie 4 : TTL à régler sur `inj` : {inj_ttl}.
- L'état `final` (onglet *Appliquer une configuration*) applique la solution des parties 3 et 4
  (routes de la boucle sur `inj`, `r1`, `r2`, `r3`, `icmp_errors_use_inbound_ifaddr=1` sur `r2` et
  `r3`, `ip_default_ttl={inj_ttl}` sur `inj`), envoie depuis `m2` un datagramme UDP de TTL
  {probe_ttl} vers `target2` (le compteur de `fw` n'est plus nul ; après une restauration du projet
  il faut renvoyer une sonde) et remplit tous les formulaires. Rien à configurer pour la partie 1.
- Évaluation : compteur de `fw` ; `ip route` de `inj`, `r1`, `r2`, `r3` ; depuis `inj` : `ping -t 64`
  et `ping -t {ttl_b}` vers `{far}` (adresse source du *time exceeded*) ; `sysctl` sur `r2`, `r3`,
  `inj` ; les formulaires.
""").format(n=n_routers, silent_hop=silent_hop, silent=d.silent, hops=self._hidden_hops_table(), target=target,
            reply_ttl=trc.reply_ttl(n_routers), n2=n_routers2, ttl_min=d.ttl_min, probe_limit=PROBE_TTL_LIMIT,
            counter=PROBE_COUNTER, hops2=self._hidden_hops_table(ISLAND_C), target2=target2,
            reply_ttl2=trc.reply_ttl(n_routers2), probe_ttl=PROBE_TTL,
            far=far, ttl_a=d.ttl_a, ttl_b=d.ttl_b, inj_ttl=d.inj_ttl)),
        )

        # =====================================================================
        # Part 1 — emulating traceroute
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Tracer un chemin sans traceroute"))
        hops = [str(ns.hop_address(k).ip) for k in range(n_routers)]
        q1_answers = {
            "path": "\n".join(hops),
            "routers": str(n_routers), "reply_ttl": str(trc.reply_ttl(n_routers)), "initial_ttl": "64",
            "icmp_type": str(trc.ICMP_TIME_EXCEEDED[0]), "icmp_code": str(trc.ICMP_TIME_EXCEEDED[1]),
            "silent_hop": str(silent_hop),
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Tracer le chemin de m1 à target avec ping"),
            description=tr("""
**Réseau 1 :** votre poste `m1`, son routeur `gw` (visible, **sans terminal**) et, au-delà,
un réseau **que vous ne voyez pas** : plusieurs routeurs puis la machine `target`. Sur `m1`, les
outils de traçage (`traceroute`, `tracepath`, `mtr`, `nmap`, `hping3`…) ont été **retirés** : vous
reconstituerez le chemin avec `ping` et une capture (`tcpdump` ou `tshark`). Adresses et routes sont
en place, `/etc/hosts` de `m1` connaît `gw` et `target`.
""")
            + addressing_a
            + tr("""
Depuis `m1`, découvrez le chemin jusqu'à `target` ({target}) **sans traceroute** : il reste `ping`,
`tcpdump`, `tshark` et les commandes habituelles.

1. Vérifiez que `ping -n -c 1 target` répond et notez le `ttl=` de la réponse.
2. Envoyez des échos de TTL croissant : `ping -n -c 1 -W 1 -t 1 target`, puis `-t 2`, `-t 3`…. 
Chaque message `Time to live exceeded` révèle un routeur ; un TTL
   sans aucune réponse est un routeur **muet** (section @@ref:reading@@) : notez `*` et continuez.
   Arrêtez-vous quand `target` répond elle-même.
3. Observez les messages ICMP reçus avec `tcpdump -n -v -i eth0 icmp` (ou
   `tshark -n -i eth0 -O icmp icmp`) dans un second terminal de `m1` : type, code, adresse source,
   et le paquet cité dans le message.
4. Comparez avec `ping -n -c 1 -R target` : quelles adresses sont
   enregistrées, combien, et pourquoi diffèrent-elles de celles de l'étape 2 ?
5. Déduisez le nombre de routeurs entre `m1` et `target` et expliquez le `ttl=` de l'étape 1.
""").format(target=target)
            + instructor(tr("""
**Solution.** Sur `m1` :

```
ping -n -c 1 target                 # 64 bytes from {target}: icmp_seq=1 ttl={reply_ttl}
ping -n -c 1 -W 1 -t 1 target       # From {gw} icmp_seq=1 Time to live exceeded  (gw)
ping -n -c 1 -W 1 -t 2 target       # From {second} ...                           (saut 2)
...                                 # un TTL sans réponse : le routeur muet du saut {silent_hop}
ping -n -c 1 -W 1 -t {n1} target    # 64 bytes from {target}: la cible répond (saut {n1})
ping -n -c 1 -R target              # RR: adresses de sortie, 9 au plus
```

- Chemin attendu (`gw` compris) : `{path}` ; {n} routeurs ; `target` répond avec
  `ttl=64 − {n} = {reply_ttl}` (chemin retour symétrique). Les messages sont des ICMP type 11, code 0.
- Le saut {silent_hop} ne répond pas (`{silent}` jette ses propres *time exceeded* par une règle
  nftables) : la trace continue au TTL suivant. `ping -R` enregistre quand même son adresse de
  sortie, et une adresse de ce routeur est acceptée à la place de `*`.
- Notation du chemin : toute adresse du bon routeur à la bonne position compte (adresse d'entrée vue
  par `ping -t`, ou adresse de sortie vue par `ping -R`), `*` compte au saut muet ; une adresse de
  trop retire un point.
""").format(target=target, reply_ttl=trc.reply_ttl(n_routers), gw=ns.hop_address(0).ip,
            second=ns.hop_address(1).ip, silent_hop=silent_hop, silent=d.silent, n=n_routers, n1=n_routers + 1,
            path=" → ".join(hops)))
            + tr("""
**Mesures.**

- Chemin de `m1` à `target` : les adresses des routeurs traversés, dans l'ordre, **une adresse par
  ligne**, de `gw` au dernier routeur avant `target` (`*` pour un routeur muet) : @@{path:+8}@@
- Nombre de routeurs traversés (`gw` compris) : @@{routers:[0-9]+}@@
- `ttl=` affiché par `ping -n -c 1 target` : @@{reply_ttl:[0-9]+}@@
- TTL initial des paquets émis par `target` : @@{initial_ttl:>32|64|128|255}@@
- Message ICMP qui révèle chaque routeur : type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Numéro du saut qui ne répond pas (1 = `gw`) : @@{silent_hop:[0-9]+}@@
""")
            + instructor(tr("""
**Réponses.** chemin `{path}` ; `{routers}` routeurs ; `ttl={reply_ttl}` ; TTL initial `{initial_ttl}` ;
ICMP type `{icmp_type}` code `{icmp_code}` ; saut muet `{silent_hop}`.
""").format(**{**q1_answers, "path": " → ".join(hops)})),
            cheat_answers={"final": q1_answers},
        )
        # the endpoints are not hops: a pasted `ping -R` list starts with m1 and ends with the destination,
        # a router of the line (none of its addresses counts)
        path_tokens = [t for t in trc.parse_path_answer(q1.get("path")) if owner(t) not in ('m1', d.target)]
        matched, extra = trc.score_path(path_tokens, expected, d.ips, silent_index=ns.silent_index)
        self.add_grade_element(
            title=no_tr("path"), max_grade=10, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=max(0.0, round(10 * (matched - extra) / n_routers, 2)),
            description=tr("chemin de m1 à target : routeurs dans l'ordre (gw compris)"),
        )
        self.add_grade_element(
            title=no_tr("routers_count"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q1.get("routers"), n_routers)),
            description=tr("nombre de routeurs entre m1 et target"),
        )
        self.add_grade_element(
            title=no_tr("reply_ttl_target"), max_grade=3, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_is(q1.get("reply_ttl"), trc.reply_ttl(n_routers))),
            description=tr("TTL de la réponse de target"),
        )
        self.add_grade_element(
            title=no_tr("initial_ttl"), max_grade=1, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is(q1.get("initial_ttl"), 64)),
            description=tr("TTL initial de target"),
        )
        self.add_grade_element(
            title=no_tr("icmp_time_exceeded"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q1.get("icmp_type"), 11) and _is(q1.get("icmp_code"), 0)),
            description=tr("type et code du message ICMP time exceeded"),
        )
        self.add_grade_element(
            title=no_tr("silent_hop"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q1.get("silent_hop"), silent_hop)),
            description=tr("numéro du saut muet"),
        )

        # =====================================================================
        # Part 2 — emulating traceroute with UDP datagrams behind a firewall
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Tracer un chemin derrière un pare-feu : UDP et capture"))
        hops2 = [str(ns.hop_address(k, ISLAND_C).ip) for k in range(n_routers2)]
        q2_answers = {
            "path2": "\n".join(hops2),
            "routers2": str(n_routers2), "ttl_min": str(d.ttl_min), "reply_ttl2": str(trc.reply_ttl(n_routers2)),
            "last_message": "port_unreachable", "nc_output": "nothing",
        }
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Tracer le chemin de m2 à target2 avec des datagrammes UDP"),
            description=tr("""
**Réseau 2 :** votre poste `m2`, le **pare-feu** `fw` (visible, sans terminal) et, au-delà,
un autre réseau caché : des routeurs puis `target2`. Mêmes outils retirés sur `m2` ; `/etc/hosts`
connaît `fw` et `target2`. `fw` jette les échos ICMP de TTL faible et ceux qui portent une option
IP (*record route*) : la méthode de la partie 1 ne fonctionne donc plus, vous sonderez avec des
**datagrammes UDP** (`nc`) et lirez les réponses dans une **capture** (`tcpdump` ou `tshark`).
""")
            + addressing_c
            + tr("""
Depuis `m2`, découvrez le chemin jusqu'à `target2` ({target2}).

1. Vérifiez que `ping -n -c 1 target2` répond et notez le `ttl=`. Essayez
   `ping -n -c 1 -W 1 -t 1 target2`, `-t 2`… : plus aucune réponse. Trouvez par essais successifs
   (encadrement) le plus petit TTL avec lequel `ping -t N target2` obtient encore une réponse.
2. Ouvrez un second terminal sur `m2` et lancez-y `tcpdump -n -i eth0 icmp` (ou
   `tshark -n -i eth0 icmp`).
3. Dans le premier terminal, envoyez un datagramme UDP de TTL 1 vers un port improbable de
   `target2` : `echo x | nc -u -w 1 -M 1 target2 33434` (`-M` fixe le TTL ; sinon
   `sysctl -w net.ipv4.ip_default_ttl=1` ou une règle nftables `ip ttl set 1`), et lisez dans la
   capture l'adresse qui répond *time exceeded*. Recommencez avec un TTL de 2, 3… jusqu'à ce que
   `target2` réponde elle-même : par quel message ? Qu'affiche `nc` pendant tout cela ?
4. Déduisez le nombre de routeurs entre `m2` et `target2` et expliquez le `ttl=` de l'étape 1.
""").format(target2=target2)
            + instructor(tr("""
**Solution.** Sur `m2`, avec `tcpdump -n -i eth0 icmp` (ou `tshark -n -i eth0 icmp`) dans un second
terminal :

```
ping -n -c 1 target2                    # 64 bytes from {target2}: icmp_seq=1 ttl={reply_ttl2}
ping -n -c 1 -W 1 -t 1 target2          # 0 received : jeté par fw (comme tout TTL < {ttl_min})
ping -n -c 1 -W 1 -t {ttl_min} target2  # répond : {ttl_min} est le plus petit TTL accepté
echo x | nc -u -w 1 -M 1 target2 33434    # capture : {fw} > {m2}: ICMP time exceeded in-transit (fw)
echo x | nc -u -w 1 -M 2 target2 33434    # capture : {second} > {m2}: ICMP time exceeded in-transit
...
echo x | nc -u -w 1 -M {n1} target2 33434    # capture : {target2} > {m2}: ICMP {target2} udp port 33434 unreachable
```

- Avec `tshark`, les mêmes lignes se lisent `{fw} → {m2} ICMP Time-to-live exceeded (Time to live
  exceeded in transit)`, puis `{target2} → {m2} ICMP Destination unreachable (Port unreachable)`.
- Chemin attendu (`fw` compris) : `{path2}` ; {n2} routeurs ; `target2` répond avec
  `ttl=64 − {n2} = {reply_ttl2}` (chemin retour symétrique).
- `fw` jette, avant même de tester le TTL, les échos ICMP entrant par `eth0` avec un TTL inférieur
  à {ttl_min} ou un en-tête IP de plus de 20 octets (`ping -R`) ; les datagrammes UDP passent et les
  *time exceeded* des routeurs cachés aussi. `nc` n'affiche rien : le noyau ne remonte pas
  *time exceeded* à un socket UDP sans `IP_RECVERR`, et `nc` tait aussi le *port unreachable* final
  (avec `-v`, son code de retour passe seulement à 1).
- Évaluation : `fw` compte les paquets entrant par `eth0` avec un TTL inférieur à {probe_limit}
  autres que les échos jetés (règle `counter`) : au moins une sonde doit avoir été envoyée (2 points) ;
  chemin noté comme en partie 1 (toute adresse du bon routeur à la bonne position, une adresse de
  trop retire un point) ; les autres réponses.
""").format(target2=target2, reply_ttl2=trc.reply_ttl(n_routers2), ttl_min=d.ttl_min, fw=ns.hop_address(0, ISLAND_C).ip,
            m2=d.ips.m2.ip, second=ns.hop_address(1, ISLAND_C).ip, n1=n_routers2 + 1, path2=" → ".join(hops2),
            n2=n_routers2, probe_limit=PROBE_TTL_LIMIT))
            + tr("""
**Mesures.**

- Chemin de `m2` à `target2` : les adresses des routeurs traversés, dans l'ordre, **une adresse par
  ligne**, de `fw` au dernier routeur avant `target2` : @@{path2:+6}@@
- Nombre de routeurs traversés (`fw` compris) : @@{routers2:[0-9]+}@@
- Plus petit TTL avec lequel `ping -t N target2` obtient une réponse : @@{ttl_min:[0-9]+}@@
- `ttl=` affiché par `ping -n -c 1 target2` : @@{reply_ttl2:[0-9]+}@@
- Message qui termine la trace UDP dans la capture : @@{last_message:>ICMP target2 udp port 33434 unreachable>>>port_unreachable|ICMP time exceeded in-transit venant de target2>>>time_exceeded|ICMP echo reply>>>echo_reply|aucun : nc affiche la réponse de target2>>>none}@@
- Ce que `nc` affiche quand un routeur répond *time exceeded* : @@{nc_output:>rien>>>nothing|Time to live exceeded>>>ttl|Connection refused>>>refused|Network is unreachable>>>unreachable}@@
""")
            + instructor(tr("""
**Réponses.** chemin `{path2}` ; `{routers2}` routeurs ; TTL minimal `{ttl_min}` ; `ttl={reply_ttl2}` ;
*port unreachable* de `target2` ; `nc` n'affiche rien.
""").format(**{**q2_answers, "path2": " → ".join(hops2)})),
            cheat_answers={"final": q2_answers},
        )
        path_tokens2 = [t for t in trc.parse_path_answer(q2.get("path2")) if owner(t) not in ('m2', d.target2)]
        matched2, extra2 = trc.score_path(path_tokens2, expected2, d.ips)
        self.add_grade_element(
            title=no_tr("probes_fw"), max_grade=2, grade_part=part2,
            grade=2 * int(probes >= 1),
            description=tr("sondes UDP de TTL faible reçues par fw"),
        )
        self.add_grade_element(
            title=no_tr("path2"), max_grade=10, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=max(0.0, round(10 * (matched2 - extra2) / n_routers2, 2)),
            description=tr("chemin de m2 à target2 : routeurs dans l'ordre (fw compris)"),
        )
        self.add_grade_element(
            title=no_tr("routers2_count"), max_grade=2, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q2.get("routers2"), n_routers2)),
            description=tr("nombre de routeurs entre m2 et target2"),
        )
        self.add_grade_element(
            title=no_tr("q_ttl_min"), max_grade=2, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q2.get("ttl_min"), d.ttl_min)),
            description=tr("plus petit TTL accepté par le pare-feu"),
        )
        self.add_grade_element(
            title=no_tr("reply_ttl_target2"), max_grade=1, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is(q2.get("reply_ttl2"), trc.reply_ttl(n_routers2))),
            description=tr("TTL de la réponse de target2"),
        )
        self.add_grade_element(
            title=no_tr("q_last_message"), max_grade=2, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q2.get("last_message")) == "port_unreachable"),
            description=tr("message qui termine la trace UDP"),
        )
        self.add_grade_element(
            title=no_tr("q_nc_output"), max_grade=1, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q2.get("nc_output")) == "nothing"),
            description=tr("nc n'affiche pas les time exceeded"),
        )

        # =====================================================================
        # Part 3 — the routing loop
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Une boucle de routage"))
        passages = trc.loop_passages(trc.DEFAULT_TTL, len(CYCLE), 1)
        q3_answers = {
            "router_64": trc.hop_at(64, CYCLE), "router_a": trc.hop_at(d.ttl_a, CYCLE), "router_b": trc.hop_at(d.ttl_b, CYCLE),
            "visits_r2": str(len(passages)), "ttl_last_r2": str(passages[-1]), "trace_pattern": "cycle",
        }
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Construire et observer une boucle de routage"),
            description=tr("""
**Réseau 3 (parties 3 et 4) :** le poste `inj`, trois routeurs `r1`, `r2`, `r3` reliés en triangle, et
le serveur web `srv` (visible, sans terminal) derrière `r3`. Adresses en place, routage des paquets
activé sur `r1`, `r2`, `r3`, noms dans `/etc/hosts` (`r1_lan3`, `r2_l23`, `srv`…), mais **aucune
route indirecte** : vous les ajouterez. `inj` dispose de `traceroute`.
""")
            + addressing_b
            + tr("""
L'adresse `{far}` n'appartient à aucun réseau de la maquette.

1. Sur `inj` : `ping -n -c 1 {far}`. Expliquez le message. Ajoutez la route par défaut
   (`ip route add default via r1_lan3`) et recommencez : qui répond, et par quel message ICMP ?
2. Construisez la boucle **dans ce sens** : sur `r1` une route par défaut vers `r2`
   (`via r2_l12`), sur `r2` vers `r3` (`via r3_l23`), sur `r3` vers `r1` (`via r1_l31`). Relancez
   `ping -n -c 1 {far}` depuis `inj` : quel routeur répond, et pourquoi lui (section @@ref:loops@@) ?
3. `traceroute -n -q 1 -w 1 -m 12 {far}` depuis `inj`. Puis lancez `tcpdump -n -v -i eth0 icmp`
   (ou `tshark -n -i eth0 icmp`, le `ttl=` au bout de chaque ligne) sur `r2` pendant un
   `ping -n -c 1 {far}` : combien de fois le même paquet passe-t-il, avec quels TTL ?
4. Prédisez puis vérifiez le routeur qui répond à `ping -n -c 1 -t {ttl_a} {far}` et à
   `ping -n -c 1 -t {ttl_b} {far}`.
""").format(far=far, ttl_a=d.ttl_a, ttl_b=d.ttl_b)
            + instructor(tr("""
**Solution.**

```
# inj
ping -n -c 1 {far}                        # ping: connect: Network is unreachable (pas de route)
ip route add default via {r1_lan3}        # r1_lan3
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Destination Net Unreachable (type 3, code 0)
# r1
ip route add default via {r2_l12}         # r2_l12
# r2
ip route add default via {r3_l23}         # r3_l23
# r3
ip route add default via {r1_l31}         # r1_l31
# inj
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Time to live exceeded
traceroute -n -q 1 -w 1 -m 12 {far}       # {r1_lan3}, {r2_l23}, {r3_l31}, {r1_lan3}, ... (12 lignes)
ping -n -c 1 -t {ttl_a} {far}             # From {r2_l23} ... (r2)
ping -n -c 1 -t {ttl_b} {far}             # From {r3_l31} ... (r3)
```

- Le paquet émis avec le TTL *T* est jeté au saut *T* ; le saut *k* est `r1`, `r2`, `r3` selon
  *(k − 1) mod 3* : TTL 64 → `r1` (64 = 3 × 21 + 1), TTL {ttl_a} → `{router_a}`, TTL {ttl_b} →
  `{router_b}`.
- Sur `eth0` de `r2` le paquet de TTL 64 passe **21 fois** (TTL 63, 60, 57, …, 3) ; il repasse
  par `r3` avec le TTL 2 et `r1` le reçoit avec le TTL 1 : jeté, *time exceeded* émis par `r1`.
- Les adresses affichées par traceroute sont `{r1_lan3}` pour `r1` (sa route vers `inj` est
  directe), `{r2_l23}` pour `r2` et `{r3_l31}` pour `r3` : l'interface par laquelle chacun
  **retourne** vers `inj` (route par défaut), pas l'interface d'entrée (partie 4).
- Évaluation : route par défaut de `inj` (2 points), de `r1`, `r2`, `r3` (3 points chacun, le sens
  compte) ; `ping -t 64` et `ping -t {ttl_b}` depuis `inj` doivent recevoir le *time exceeded* de
  `r1` et de `r3` (3 points chacun).
""").format(far=far, r1_lan3=addr('r1', 'lan3').ip, r2_l12=addr('r2', 'l12').ip, r3_l23=addr('r3', 'l23').ip,
            r1_l31=addr('r1', 'l31').ip, r2_l23=addr('r2', 'l23').ip, r3_l31=addr('r3', 'l31').ip,
            ttl_a=d.ttl_a, ttl_b=d.ttl_b, router_a=q3_answers["router_a"], router_b=q3_answers["router_b"]))
            + tr("""
**Observations.**

- Routeur qui répond à `ping {far}` (TTL 64) : @@{{router_64:>r1|r2|r3}}@@
- Routeur qui répond à `ping -t {ttl_a} {far}` : @@{{router_a:>r1|r2|r3}}@@
- Routeur qui répond à `ping -t {ttl_b} {far}` : @@{{router_b:>r1|r2|r3}}@@
- Nombre de passages du paquet de TTL 64 sur `eth0` de `r2` : @@{{visits_r2:[0-9]+}}@@
- TTL de ce paquet à son dernier passage sur `r2` : @@{{ttl_last_r2:[0-9]+}}@@
- Ce qu'affiche `traceroute` vers `{far}` : @@{{trace_pattern:>r1 r2 r3 r1 r2 r3 … jusqu'au nombre maximal de sauts>>>cycle|r1 puis des étoiles>>>r1_stars|des étoiles dès le premier saut>>>stars|un message « réseau inaccessible »>>>unreachable}}@@
""").format(far=far, ttl_a=d.ttl_a, ttl_b=d.ttl_b)
            + instructor(tr("""
**Réponses.** TTL 64 → `{router_64}` ; TTL {ttl_a} → `{router_a}` ; TTL {ttl_b} → `{router_b}` ;
`{visits_r2}` passages sur `r2`, le dernier avec le TTL `{ttl_last_r2}` ; traceroute : la suite
`r1 r2 r3` répétée jusqu'au nombre maximal de sauts.
""").format(ttl_a=d.ttl_a, ttl_b=d.ttl_b, **q3_answers)),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("route_inj"), max_grade=2, grade_part=part3,
            grade=2 * int(route_ok['inj']),
            description=tr("route par défaut de inj vers r1"),
        )
        for r, nxt in zip(CYCLE, CYCLE[1:] + CYCLE[:1]):
            self.add_grade_element(
                title=no_tr(f"route_{r}"), max_grade=3, grade_part=part3,
                grade=3 * int(route_ok[r]),
                description=tr("route par défaut de {r} vers {nxt}").format(r=r, nxt=nxt),
            )
        self.add_grade_element(
            title=no_tr("loop_ttl_64"), max_grade=3, grade_part=part3,
            grade=3 * int(from_64 == trc.hop_at(64, CYCLE)),
            description=tr("ping depuis inj : time exceeded reçu de r1"),
        )
        self.add_grade_element(
            title=no_tr("loop_ttl_b"), max_grade=3, grade_part=part3,
            grade=3 * int(from_b == trc.hop_at(d.ttl_b, CYCLE)),
            description=tr("ping -t {ttl_b} depuis inj : time exceeded reçu de {r}").format(
                ttl_b=d.ttl_b, r=trc.hop_at(d.ttl_b, CYCLE)),
        )
        for key, points, description in (
                ("router_64", 2, tr("routeur qui répond au TTL 64")),
                ("router_a", 2, tr("routeur qui répond au TTL {t}").format(t=d.ttl_a)),
                ("router_b", 2, tr("routeur qui répond au TTL {t}").format(t=d.ttl_b))):
            self.add_grade_element(
                title=no_tr(f"q_{key}"), max_grade=points, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
                grade=points * int(_norm(q3.get(key)) == q3_answers[key]),
                description=description,
            )
        self.add_grade_element(
            title=no_tr("q_visits_r2"), max_grade=3, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_is(q3.get("visits_r2"), len(passages))),
            description=tr("nombre de passages du paquet sur r2"),
        )
        self.add_grade_element(
            title=no_tr("q_ttl_last_r2"), max_grade=2, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_is(q3.get("ttl_last_r2"), passages[-1])),
            description=tr("TTL du dernier passage sur r2"),
        )
        self.add_grade_element(
            title=no_tr("q_trace_pattern"), max_grade=2, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q3.get("trace_pattern")) == "cycle"),
            description=tr("ce que traceroute affiche dans une boucle"),
        )

        # =====================================================================
        # Part 4 — reply TTL, asymmetry, source addresses
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — TTL des réponses, chemin retour et adresses sources"))
        q4_answers = {
            "reply_ttl_srv": str(trc.reply_ttl(2)), "return_routers": "2", "forward_routers": "3", "asym_path": "r3_r1",
            "rr_r3": "eth2", "r2_iface": "eth1", "r2_iface_after": "eth0",
            "min_ttl": str(trc.min_ttl_to_reach(3)), "router_ttl3": "r3", "ttl_seen_r2": str(d.inj_ttl - 1),
        }
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Ce que révèlent le TTL des réponses, ping -R et les adresses sources"),
            description=tr("""
Toujours depuis `inj` vers `srv`, la boucle de la partie 3 en place.

1. `ping -n -c 1 srv` : notez le `ttl=`. Combien de routeurs la réponse a-t-elle traversés ?
   Comparez au nombre de sauts de `traceroute -n -q 1 -w 1 -I srv` et dessinez les deux chemins
   (section @@ref:asymmetry@@).
2. `ping -n -c 1 -R srv` : retrouvez dans la liste `RR:` les adresses de l'aller, celle de `srv`
   et celles du retour.
3. Relisez les adresses des sauts 2 et 3 de `traceroute srv` : à quelle interface de `r2` et de
   `r3` appartiennent-elles ? Pourquoi (section @@ref:time-exceeded@@) ? Passez
   `net.ipv4.icmp_errors_use_inbound_ifaddr` à 1 sur `r2` et sur `r3` (`sysctl -w`) et recommencez.
4. Sur `inj`, fixez le TTL des paquets émis à **{inj_ttl}** (`net.ipv4.ip_default_ttl`). Vérifiez
   avec `tcpdump -n -v -i eth0 icmp` (ou `tshark -n -i eth0 icmp`) sur `r2` pendant un
   `ping -n -c 1 srv`, et observez le `ttl=` de la réponse. Quel est le plus petit TTL initial qui atteint encore `srv` ? Avec un TTL initial
   de 3, qui répond ?
""").format(inj_ttl=d.inj_ttl)
            + instructor(tr("""
**Solution.**

```
# inj
ping -n -c 1 srv                      # 64 bytes from {srv}: icmp_seq=1 ttl=62 : 2 routeurs au retour (r3, r1)
traceroute -n -q 1 -w 1 -I srv        # 4 sauts : r1, r2, r3, srv à l'aller
ping -n -c 1 -R srv                   # RR: {inj} {r1_l12} {r2_l23} {r3_lan4} {srv} {srv} {r3_l31} {r1_lan3} {inj}
# r2 et r3
sysctl -w net.ipv4.icmp_errors_use_inbound_ifaddr=1
# inj
traceroute -n -q 1 -w 1 srv           # saut 2 : {r2_l12} (eth0 de r2), saut 3 : {r3_l23} (eth0 de r3)
sysctl -w net.ipv4.ip_default_ttl={inj_ttl}
ping -n -c 1 srv                      # ttl=62 toujours : c'est le TTL de srv, pas celui de inj
```

- Aller `inj → r1 → r2 → r3 → srv` (3 routeurs) ; retour `srv → r3 → r1 → inj` (2 routeurs : `r3`
  suit sa route par défaut vers `r1`, qui livre directement sur `lan3`) : `ttl=64 − 2 = 62`.
- `ping -R` enregistre l'adresse de **sortie** de chaque routeur : `{r1_l12}` (eth1 de `r1`),
  `{r2_l23}` (eth1 de `r2`), `{r3_lan4}` (eth2 de `r3`), `srv` deux fois, puis le retour `{r3_l31}`
  (eth1 de `r3`), `{r1_lan3}` (eth0 de `r1`) : neuf adresses avec celles de `inj`, la limite de l'option.
- Les *time exceeded* de `r2` et `r3` portent `{r2_l23}` (eth1 de `r2`, vers `r3`) et `{r3_l31}`
  (eth1 de `r3`, vers `r1`) : l'adresse de l'interface par laquelle chacun **retourne** vers `inj`
  (`icmp_errors_use_inbound_ifaddr = 0`). À 1, ce sont les adresses d'entrée `{r2_l12}` et `{r3_l23}`
  (eth0 de chacun).
- Avec `ip_default_ttl={inj_ttl}`, `tcpdump` (ou `tshark`) sur `eth0` de `r2` voit les échos avec le TTL
  {ttl_r2} ({inj_ttl} − 1 : `r1` traversé). `srv` est le saut 4 : un TTL initial de 4 suffit ; avec
  3, le paquet est jeté par `r3` (*time exceeded* de `{r3_l31}`).
- Évaluation : `icmp_errors_use_inbound_ifaddr` lu sur `r2` et `r3` (2 points chacun),
  `ip_default_ttl` de `inj` égal à {inj_ttl} (3 points) ; les formulaires.
""").format(srv=srv, inj=d.ips.inj.ip, r1_l12=addr('r1', 'l12').ip, r2_l23=addr('r2', 'l23').ip,
            r3_lan4=addr('r3', 'lan4').ip, r3_l31=addr('r3', 'l31').ip, r1_lan3=addr('r1', 'lan3').ip,
            r2_l12=addr('r2', 'l12').ip, r3_l23=addr('r3', 'l23').ip, inj_ttl=d.inj_ttl, ttl_r2=d.inj_ttl - 1))
            + tr("""
**Observations.**

- `ttl=` de la réponse de `srv` : @@{{reply_ttl_srv:[0-9]+}}@@
- Routeurs traversés par la réponse (retour) : @@{{return_routers:[0-9]+}}@@ ; par la requête (aller) : @@{{forward_routers:[0-9]+}}@@
- Chemin retour de `srv` à `inj` : @@{{asym_path:>r3 puis r1>>>r3_r1|r3, r2 puis r1>>>r3_r2_r1|r1 seul>>>r1|le même chemin qu'à l'aller>>>same}}@@
- Interface de `r3` enregistrée à l'aller par `ping -R` : @@{{rr_r3:>eth0 (côté r2)>>>eth0|eth1 (côté r1)>>>eth1|eth2 (côté srv)>>>eth2}}@@
- Interface de `r2` dont `traceroute` affiche l'adresse au saut 2, avant le changement de paramètre : @@{{r2_iface:>eth0 (côté r1)>>>eth0|eth1 (côté r3)>>>eth1}}@@ ; après : @@{{r2_iface_after:>eth0 (côté r1)>>>eth0|eth1 (côté r3)>>>eth1}}@@
- Plus petit TTL initial de `inj` qui atteint `srv` : @@{{min_ttl:[0-9]+}}@@
- Avec un TTL initial de 3, le *time exceeded* vient de : @@{{router_ttl3:>r1|r2|r3}}@@
- TTL des échos de `inj` vus sur `eth0` de `r2` après le réglage à {inj_ttl} : @@{{ttl_seen_r2:[0-9]+}}@@
""").format(inj_ttl=d.inj_ttl)
            + instructor(tr("""
**Réponses.** `ttl={reply_ttl_srv}` ; retour `{return_routers}` routeurs, aller `{forward_routers}` ;
retour par `r3` puis `r1` ; `ping -R` : eth2 de `r3` ; saut 2 : eth1 de `r2` avant, eth0 après ;
TTL minimal `{min_ttl}` ; avec 3 : `{router_ttl3}` ; TTL vu sur `r2` : `{ttl_seen_r2}`.
""").format(**q4_answers)),
            cheat_answers={"final": q4_answers},
        )
        for r in ('r2', 'r3'):
            self.add_grade_element(
                title=no_tr(f"inbound_ifaddr_{r}"), max_grade=2, grade_part=part4,
                grade=2 * int(inbound[r] == 1),
                description=tr("icmp_errors_use_inbound_ifaddr à 1 sur {r}").format(r=r),
            )
        self.add_grade_element(
            title=no_tr("inj_default_ttl"), max_grade=3, grade_part=part4,
            grade=3 * int(inj_ttl == d.inj_ttl),
            description=tr("TTL par défaut de inj réglé à {t}").format(t=d.inj_ttl),
        )
        for key, points, description, check in (
                ("reply_ttl_srv", 3, tr("TTL de la réponse de srv"), lambda v: _is(v, trc.reply_ttl(2))),
                ("return_routers", 2, tr("routeurs du chemin retour"), lambda v: _is(v, 2)),
                ("forward_routers", 2, tr("routeurs du chemin aller"), lambda v: _is(v, 3)),
                ("asym_path", 3, tr("chemin retour de srv à inj"), lambda v: v == "r3_r1"),
                ("rr_r3", 2, tr("interface de r3 enregistrée par ping -R"), lambda v: v == "eth2"),
                ("r2_iface", 3, tr("interface de r2 affichée par traceroute"), lambda v: v == "eth1"),
                ("r2_iface_after", 2, tr("interface de r2 affichée avec icmp_errors_use_inbound_ifaddr"), lambda v: v == "eth0"),
                ("min_ttl", 3, tr("plus petit TTL initial qui atteint srv"), lambda v: _is(v, 4)),
                ("router_ttl3", 2, tr("routeur qui répond à un TTL initial de 3"), lambda v: v == "r3"),
                ("ttl_seen_r2", 1, tr("TTL des échos de inj sur r2"), lambda v: _is(v, d.inj_ttl - 1))):
            self.add_grade_element(
                title=no_tr(f"q_{key}"), max_grade=points, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
                grade=points * int(check(_norm(q4.get(key)))),
                description=description,
            )


_TRANSLATIONS = {
    'en': {
        """
**Mesures.**

- Chemin de `m1` à `target` : les adresses des routeurs traversés, dans l'ordre, **une adresse par
  ligne**, de `gw` au dernier routeur avant `target` (`*` pour un routeur muet) : @@{path:+8}@@
- Nombre de routeurs traversés (`gw` compris) : @@{routers:[0-9]+}@@
- `ttl=` affiché par `ping -n -c 1 target` : @@{reply_ttl:[0-9]+}@@
- TTL initial des paquets émis par `target` : @@{initial_ttl:>32|64|128|255}@@
- Message ICMP qui révèle chaque routeur : type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Numéro du saut qui ne répond pas (1 = `gw`) : @@{silent_hop:[0-9]+}@@
""": """
**Measurements.**

- Path from `m1` to `target`: the addresses of the routers crossed, in order, **one address per
  line**, from `gw` to the last router before `target` (`*` for a silent router): @@{path:+8}@@
- Number of routers crossed (`gw` included): @@{routers:[0-9]+}@@
- `ttl=` shown by `ping -n -c 1 target`: @@{reply_ttl:[0-9]+}@@
- Initial TTL of the packets sent by `target`: @@{initial_ttl:>32|64|128|255}@@
- ICMP message that reveals each router: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Number of the hop that does not answer (1 = `gw`): @@{silent_hop:[0-9]+}@@
""",
        """
**Mesures.**

- Chemin de `m2` à `target2` : les adresses des routeurs traversés, dans l'ordre, **une adresse par
  ligne**, de `fw` au dernier routeur avant `target2` : @@{path2:+6}@@
- Nombre de routeurs traversés (`fw` compris) : @@{routers2:[0-9]+}@@
- Plus petit TTL avec lequel `ping -t N target2` obtient une réponse : @@{ttl_min:[0-9]+}@@
- `ttl=` affiché par `ping -n -c 1 target2` : @@{reply_ttl2:[0-9]+}@@
- Message qui termine la trace UDP dans la capture : @@{last_message:>ICMP target2 udp port 33434 unreachable>>>port_unreachable|ICMP time exceeded in-transit venant de target2>>>time_exceeded|ICMP echo reply>>>echo_reply|aucun : nc affiche la réponse de target2>>>none}@@
- Ce que `nc` affiche quand un routeur répond *time exceeded* : @@{nc_output:>rien>>>nothing|Time to live exceeded>>>ttl|Connection refused>>>refused|Network is unreachable>>>unreachable}@@
""": """
**Measurements.**

- Path from `m2` to `target2`: the addresses of the routers crossed, in order, **one address per
  line**, from `fw` to the last router before `target2`: @@{path2:+6}@@
- Number of routers crossed (`fw` included): @@{routers2:[0-9]+}@@
- Smallest TTL with which `ping -t N target2` gets an answer: @@{ttl_min:[0-9]+}@@
- `ttl=` shown by `ping -n -c 1 target2`: @@{reply_ttl2:[0-9]+}@@
- Message that ends the UDP trace in the capture: @@{last_message:>ICMP target2 udp port 33434 unreachable>>>port_unreachable|ICMP time exceeded in-transit from target2>>>time_exceeded|ICMP echo reply>>>echo_reply|none: nc prints the answer of target2>>>none}@@
- What `nc` prints when a router answers *time exceeded*: @@{nc_output:>nothing>>>nothing|Time to live exceeded>>>ttl|Connection refused>>>refused|Network is unreachable>>>unreachable}@@
""",
        """
**Observations.**

- Routeur qui répond à `ping {far}` (TTL 64) : @@{{router_64:>r1|r2|r3}}@@
- Routeur qui répond à `ping -t {ttl_a} {far}` : @@{{router_a:>r1|r2|r3}}@@
- Routeur qui répond à `ping -t {ttl_b} {far}` : @@{{router_b:>r1|r2|r3}}@@
- Nombre de passages du paquet de TTL 64 sur `eth0` de `r2` : @@{{visits_r2:[0-9]+}}@@
- TTL de ce paquet à son dernier passage sur `r2` : @@{{ttl_last_r2:[0-9]+}}@@
- Ce qu'affiche `traceroute` vers `{far}` : @@{{trace_pattern:>r1 r2 r3 r1 r2 r3 … jusqu'au nombre maximal de sauts>>>cycle|r1 puis des étoiles>>>r1_stars|des étoiles dès le premier saut>>>stars|un message « réseau inaccessible »>>>unreachable}}@@
""": """
**Observations.**

- Router that answers `ping {far}` (TTL 64): @@{{router_64:>r1|r2|r3}}@@
- Router that answers `ping -t {ttl_a} {far}`: @@{{router_a:>r1|r2|r3}}@@
- Router that answers `ping -t {ttl_b} {far}`: @@{{router_b:>r1|r2|r3}}@@
- Number of passages of the packet of TTL 64 on `eth0` of `r2`: @@{{visits_r2:[0-9]+}}@@
- TTL of this packet at its last passage on `r2`: @@{{ttl_last_r2:[0-9]+}}@@
- What `traceroute` towards `{far}` shows: @@{{trace_pattern:>r1 r2 r3 r1 r2 r3 … up to the maximum number of hops>>>cycle|r1 then stars>>>r1_stars|stars from the first hop on>>>stars|a “network unreachable” message>>>unreachable}}@@
""",
        """
**Observations.**

- `ttl=` de la réponse de `srv` : @@{{reply_ttl_srv:[0-9]+}}@@
- Routeurs traversés par la réponse (retour) : @@{{return_routers:[0-9]+}}@@ ; par la requête (aller) : @@{{forward_routers:[0-9]+}}@@
- Chemin retour de `srv` à `inj` : @@{{asym_path:>r3 puis r1>>>r3_r1|r3, r2 puis r1>>>r3_r2_r1|r1 seul>>>r1|le même chemin qu'à l'aller>>>same}}@@
- Interface de `r3` enregistrée à l'aller par `ping -R` : @@{{rr_r3:>eth0 (côté r2)>>>eth0|eth1 (côté r1)>>>eth1|eth2 (côté srv)>>>eth2}}@@
- Interface de `r2` dont `traceroute` affiche l'adresse au saut 2, avant le changement de paramètre : @@{{r2_iface:>eth0 (côté r1)>>>eth0|eth1 (côté r3)>>>eth1}}@@ ; après : @@{{r2_iface_after:>eth0 (côté r1)>>>eth0|eth1 (côté r3)>>>eth1}}@@
- Plus petit TTL initial de `inj` qui atteint `srv` : @@{{min_ttl:[0-9]+}}@@
- Avec un TTL initial de 3, le *time exceeded* vient de : @@{{router_ttl3:>r1|r2|r3}}@@
- TTL des échos de `inj` vus sur `eth0` de `r2` après le réglage à {inj_ttl} : @@{{ttl_seen_r2:[0-9]+}}@@
""": """
**Observations.**

- `ttl=` of the reply of `srv`: @@{{reply_ttl_srv:[0-9]+}}@@
- Routers crossed by the reply (return): @@{{return_routers:[0-9]+}}@@; by the request (forward): @@{{forward_routers:[0-9]+}}@@
- Return path from `srv` to `inj`: @@{{asym_path:>r3 then r1>>>r3_r1|r3, r2 then r1>>>r3_r2_r1|r1 alone>>>r1|the same path as on the way out>>>same}}@@
- Interface of `r3` recorded on the way out by `ping -R`: @@{{rr_r3:>eth0 (r2 side)>>>eth0|eth1 (r1 side)>>>eth1|eth2 (srv side)>>>eth2}}@@
- Interface of `r2` whose address `traceroute` shows at hop 2, before the parameter change: @@{{r2_iface:>eth0 (r1 side)>>>eth0|eth1 (r3 side)>>>eth1}}@@; after: @@{{r2_iface_after:>eth0 (r1 side)>>>eth0|eth1 (r3 side)>>>eth1}}@@
- Smallest initial TTL of `inj` that reaches `srv`: @@{{min_ttl:[0-9]+}}@@
- With an initial TTL of 3, the *time exceeded* comes from: @@{{router_ttl3:>r1|r2|r3}}@@
- TTL of the echoes of `inj` seen on `eth0` of `r2` after setting it to {inj_ttl}: @@{{ttl_seen_r2:[0-9]+}}@@
""",
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- Chemin caché de `m1` à `target` ({n} routeurs, `gw` compris, puis la cible) ; le routeur **muet**
  est au saut {silent_hop} (`{silent}`) :

| saut | routeur | adresse vue par `ping -t` (entrée) | toutes ses adresses |
|------|---------|------------------------------------|---------------------|
{hops}

- `target` : `{target}`, TTL initial 64 ; `ping target` depuis `m1` répond avec `ttl={reply_ttl}`.
- Chemin caché de `m2` à `target2` ({n2} routeurs, `fw` compris, puis la cible), aucun routeur muet ; `fw` jette
  les échos ICMP de TTL inférieur à **{ttl_min}** et ceux qui portent une option IP, et compte les
  autres paquets de TTL inférieur à {probe_limit} (règle `counter comment "{counter}"`) :

| saut | routeur | adresse vue dans la capture (entrée) | toutes ses adresses |
|------|---------|--------------------------------------|---------------------|
{hops2}

- `target2` : `{target2}` ; `ping target2` répond avec `ttl={reply_ttl2}` ; `ping -t N target2`
  répond pour N ≥ {ttl_min} seulement.
- Partie 3 : destination `{far}`, boucle attendue `r1 → r2 → r3 → r1` ; `ping -t {ttl_a}` → `r2`,
  `ping -t {ttl_b}` → `r3`, TTL 64 → `r1`.
- Partie 4 : TTL à régler sur `inj` : {inj_ttl}.
- L'état `final` (onglet *Appliquer une configuration*) applique la solution des parties 3 et 4
  (routes de la boucle sur `inj`, `r1`, `r2`, `r3`, `icmp_errors_use_inbound_ifaddr=1` sur `r2` et
  `r3`, `ip_default_ttl={inj_ttl}` sur `inj`), envoie depuis `m2` un datagramme UDP de TTL
  {probe_ttl} vers `target2` (le compteur de `fw` n'est plus nul ; après une restauration du projet
  il faut renvoyer une sonde) et remplit tous les formulaires. Rien à configurer pour la partie 1.
- Évaluation : compteur de `fw` ; `ip route` de `inj`, `r1`, `r2`, `r3` ; depuis `inj` : `ping -t 64`
  et `ping -t {ttl_b}` vers `{far}` (adresse source du *time exceeded*) ; `sysctl` sur `r2`, `r3`,
  `inj` ; les formulaires.
""": """
**For the instructor.** Every question ends with its solution, computed for this project.

- Hidden path from `m1` to `target` ({n} routers, `gw` included, then the target); the **silent**
  router is at hop {silent_hop} (`{silent}`):

| hop | router | address seen by `ping -t` (ingress) | all its addresses |
|------|---------|------------------------------------|---------------------|
{hops}

- `target`: `{target}`, initial TTL 64; `ping target` from `m1` answers with `ttl={reply_ttl}`.
- Hidden path from `m2` to `target2` ({n2} routers, `fw` included, then the target), no silent router; `fw` drops
  the ICMP echoes of a TTL below **{ttl_min}** and those carrying an IP option, and counts the
  other packets of a TTL below {probe_limit} (rule `counter comment "{counter}"`):

| hop | router | address seen in the capture (ingress) | all its addresses |
|------|---------|--------------------------------------|---------------------|
{hops2}

- `target2`: `{target2}`; `ping target2` answers with `ttl={reply_ttl2}`; `ping -t N target2`
  answers for N ≥ {ttl_min} only.
- Part 3: destination `{far}`, expected loop `r1 → r2 → r3 → r1`; `ping -t {ttl_a}` → `r2`,
  `ping -t {ttl_b}` → `r3`, TTL 64 → `r1`.
- Part 4: TTL to set on `inj`: {inj_ttl}.
- The `final` state (*Apply Configuration* tab) applies the solution of parts 3 and 4
  (routes of the loop on `inj`, `r1`, `r2`, `r3`, `icmp_errors_use_inbound_ifaddr=1` on `r2` and
  `r3`, `ip_default_ttl={inj_ttl}` on `inj`), sends a UDP datagram of TTL {probe_ttl} from `m2`
  towards `target2` (the counter of `fw` is no longer zero; after a restore of the project a probe
  must be sent again) and fills every form. Nothing to configure for part 1.
- Evaluation: counter of `fw`; `ip route` of `inj`, `r1`, `r2`, `r3`; from `inj`: `ping -t 64`
  and `ping -t {ttl_b}` towards `{far}` (source address of the *time exceeded*); `sysctl` on `r2`, `r3`,
  `inj`; the forms.
""",
        """
**Réponses.** TTL 64 → `{router_64}` ; TTL {ttl_a} → `{router_a}` ; TTL {ttl_b} → `{router_b}` ;
`{visits_r2}` passages sur `r2`, le dernier avec le TTL `{ttl_last_r2}` ; traceroute : la suite
`r1 r2 r3` répétée jusqu'au nombre maximal de sauts.
""": """
**Answers.** TTL 64 → `{router_64}`; TTL {ttl_a} → `{router_a}`; TTL {ttl_b} → `{router_b}`;
`{visits_r2}` passages on `r2`, the last one with the TTL `{ttl_last_r2}`; traceroute: the sequence
`r1 r2 r3` repeated up to the maximum number of hops.
""",
        """
**Réponses.** `ttl={reply_ttl_srv}` ; retour `{return_routers}` routeurs, aller `{forward_routers}` ;
retour par `r3` puis `r1` ; `ping -R` : eth2 de `r3` ; saut 2 : eth1 de `r2` avant, eth0 après ;
TTL minimal `{min_ttl}` ; avec 3 : `{router_ttl3}` ; TTL vu sur `r2` : `{ttl_seen_r2}`.
""": """
**Answers.** `ttl={reply_ttl_srv}`; return `{return_routers}` routers, forward `{forward_routers}`;
return through `r3` then `r1`; `ping -R`: eth2 of `r3`; hop 2: eth1 of `r2` before, eth0 after;
minimal TTL `{min_ttl}`; with 3: `{router_ttl3}`; TTL seen on `r2`: `{ttl_seen_r2}`.
""",
        """
**Réponses.** chemin `{path2}` ; `{routers2}` routeurs ; TTL minimal `{ttl_min}` ; `ttl={reply_ttl2}` ;
*port unreachable* de `target2` ; `nc` n'affiche rien.
""": """
**Answers.** path `{path2}`; `{routers2}` routers; minimal TTL `{ttl_min}`; `ttl={reply_ttl2}`;
*port unreachable* from `target2`; `nc` prints nothing.
""",
        """
**Réponses.** chemin `{path}` ; `{routers}` routeurs ; `ttl={reply_ttl}` ; TTL initial `{initial_ttl}` ;
ICMP type `{icmp_type}` code `{icmp_code}` ; saut muet `{silent_hop}`.
""": """
**Answers.** path `{path}`; `{routers}` routers; `ttl={reply_ttl}`; initial TTL `{initial_ttl}`;
ICMP type `{icmp_type}` code `{icmp_code}`; silent hop `{silent_hop}`.
""",
        """
**Réseau 1 :** votre poste `m1`, son routeur `gw` (visible, **sans terminal**) et, au-delà,
un réseau **que vous ne voyez pas** : plusieurs routeurs puis la machine `target`. Sur `m1`, les
outils de traçage (`traceroute`, `tracepath`, `mtr`, `nmap`, `hping3`…) ont été **retirés** : vous
reconstituerez le chemin avec `ping` et une capture (`tcpdump` ou `tshark`). Adresses et routes sont
en place, `/etc/hosts` de `m1` connaît `gw` et `target`.
""": """
**Network 1:** your workstation `m1`, its router `gw` (visible, **no terminal**) and, beyond it,
a network **you cannot see**: several routers, then the machine `target`. On `m1`, the
tracing tools (`traceroute`, `tracepath`, `mtr`, `nmap`, `hping3`…) have been **removed**: you
will rebuild the path with `ping` and a capture (`tcpdump` or `tshark`). Addresses and routes are
in place, the `/etc/hosts` of `m1` knows `gw` and `target`.
""",
        """
**Réseau 2 :** votre poste `m2`, le **pare-feu** `fw` (visible, sans terminal) et, au-delà,
un autre réseau caché : des routeurs puis `target2`. Mêmes outils retirés sur `m2` ; `/etc/hosts`
connaît `fw` et `target2`. `fw` jette les échos ICMP de TTL faible et ceux qui portent une option
IP (*record route*) : la méthode de la partie 1 ne fonctionne donc plus, vous sonderez avec des
**datagrammes UDP** (`nc`) et lirez les réponses dans une **capture** (`tcpdump` ou `tshark`).
""": """
**Network 2:** your workstation `m2`, the **firewall** `fw` (visible, no terminal) and, beyond it,
another hidden network: routers, then `target2`. The same tools are removed on `m2`; `/etc/hosts`
knows `fw` and `target2`. `fw` drops the ICMP echoes of a small TTL and those carrying an IP
option (*record route*): the method of part 1 therefore no longer works, you will probe with
**UDP datagrams** (`nc`) and read the answers in a **capture** (`tcpdump` or `tshark`).
""",
        """
**Réseau 3 (parties 3 et 4) :** le poste `inj`, trois routeurs `r1`, `r2`, `r3` reliés en triangle, et
le serveur web `srv` (visible, sans terminal) derrière `r3`. Adresses en place, routage des paquets
activé sur `r1`, `r2`, `r3`, noms dans `/etc/hosts` (`r1_lan3`, `r2_l23`, `srv`…), mais **aucune
route indirecte** : vous les ajouterez. `inj` dispose de `traceroute`.
""": """
**Network 3 (parts 3 and 4):** the workstation `inj`, three routers `r1`, `r2`, `r3` linked in a triangle, and
the web server `srv` (visible, no terminal) behind `r3`. Addresses in place, packet forwarding
enabled on `r1`, `r2`, `r3`, names in `/etc/hosts` (`r1_lan3`, `r2_l23`, `srv`…), but **no
indirect route**: you will add them. `inj` has `traceroute`.
""",
        """
**Solution.**

```
# inj
ping -n -c 1 srv                      # 64 bytes from {srv}: icmp_seq=1 ttl=62 : 2 routeurs au retour (r3, r1)
traceroute -n -q 1 -w 1 -I srv        # 4 sauts : r1, r2, r3, srv à l'aller
ping -n -c 1 -R srv                   # RR: {inj} {r1_l12} {r2_l23} {r3_lan4} {srv} {srv} {r3_l31} {r1_lan3} {inj}
# r2 et r3
sysctl -w net.ipv4.icmp_errors_use_inbound_ifaddr=1
# inj
traceroute -n -q 1 -w 1 srv           # saut 2 : {r2_l12} (eth0 de r2), saut 3 : {r3_l23} (eth0 de r3)
sysctl -w net.ipv4.ip_default_ttl={inj_ttl}
ping -n -c 1 srv                      # ttl=62 toujours : c'est le TTL de srv, pas celui de inj
```

- Aller `inj → r1 → r2 → r3 → srv` (3 routeurs) ; retour `srv → r3 → r1 → inj` (2 routeurs : `r3`
  suit sa route par défaut vers `r1`, qui livre directement sur `lan3`) : `ttl=64 − 2 = 62`.
- `ping -R` enregistre l'adresse de **sortie** de chaque routeur : `{r1_l12}` (eth1 de `r1`),
  `{r2_l23}` (eth1 de `r2`), `{r3_lan4}` (eth2 de `r3`), `srv` deux fois, puis le retour `{r3_l31}`
  (eth1 de `r3`), `{r1_lan3}` (eth0 de `r1`) : neuf adresses avec celles de `inj`, la limite de l'option.
- Les *time exceeded* de `r2` et `r3` portent `{r2_l23}` (eth1 de `r2`, vers `r3`) et `{r3_l31}`
  (eth1 de `r3`, vers `r1`) : l'adresse de l'interface par laquelle chacun **retourne** vers `inj`
  (`icmp_errors_use_inbound_ifaddr = 0`). À 1, ce sont les adresses d'entrée `{r2_l12}` et `{r3_l23}`
  (eth0 de chacun).
- Avec `ip_default_ttl={inj_ttl}`, `tcpdump` (ou `tshark`) sur `eth0` de `r2` voit les échos avec le TTL
  {ttl_r2} ({inj_ttl} − 1 : `r1` traversé). `srv` est le saut 4 : un TTL initial de 4 suffit ; avec
  3, le paquet est jeté par `r3` (*time exceeded* de `{r3_l31}`).
- Évaluation : `icmp_errors_use_inbound_ifaddr` lu sur `r2` et `r3` (2 points chacun),
  `ip_default_ttl` de `inj` égal à {inj_ttl} (3 points) ; les formulaires.
""": """
**Solution.**

```
# inj
ping -n -c 1 srv                      # 64 bytes from {srv}: icmp_seq=1 ttl=62: 2 routers on the way back (r3, r1)
traceroute -n -q 1 -w 1 -I srv        # 4 hops: r1, r2, r3, srv on the way out
ping -n -c 1 -R srv                   # RR: {inj} {r1_l12} {r2_l23} {r3_lan4} {srv} {srv} {r3_l31} {r1_lan3} {inj}
# r2 and r3
sysctl -w net.ipv4.icmp_errors_use_inbound_ifaddr=1
# inj
traceroute -n -q 1 -w 1 srv           # hop 2: {r2_l12} (eth0 of r2), hop 3: {r3_l23} (eth0 of r3)
sysctl -w net.ipv4.ip_default_ttl={inj_ttl}
ping -n -c 1 srv                      # still ttl=62: it is the TTL of srv, not that of inj
```

- Forward `inj → r1 → r2 → r3 → srv` (3 routers); return `srv → r3 → r1 → inj` (2 routers: `r3`
  follows its default route towards `r1`, which delivers directly on `lan3`): `ttl=64 − 2 = 62`.
- `ping -R` records the **egress** address of each router: `{r1_l12}` (eth1 of `r1`),
  `{r2_l23}` (eth1 of `r2`), `{r3_lan4}` (eth2 of `r3`), `srv` twice, then on the way back `{r3_l31}`
  (eth1 of `r3`), `{r1_lan3}` (eth0 of `r1`): nine addresses with those of `inj`, the limit of the option.
- The *time exceeded* errors of `r2` and `r3` carry `{r2_l23}` (eth1 of `r2`, towards `r3`) and `{r3_l31}`
  (eth1 of `r3`, towards `r1`): the address of the interface through which each one **goes back** to `inj`
  (`icmp_errors_use_inbound_ifaddr = 0`). At 1, they are the ingress addresses `{r2_l12}` and `{r3_l23}`
  (eth0 of each).
- With `ip_default_ttl={inj_ttl}`, `tcpdump` (or `tshark`) on `eth0` of `r2` sees the echoes with the TTL
  {ttl_r2} ({inj_ttl} − 1: `r1` crossed). `srv` is hop 4: an initial TTL of 4 is enough; with
  3, the packet is dropped by `r3` (*time exceeded* from `{r3_l31}`).
- Evaluation: `icmp_errors_use_inbound_ifaddr` read on `r2` and `r3` (2 points each),
  `ip_default_ttl` of `inj` equal to {inj_ttl} (3 points); the forms.
""",
        """
**Solution.**

```
# inj
ping -n -c 1 {far}                        # ping: connect: Network is unreachable (pas de route)
ip route add default via {r1_lan3}        # r1_lan3
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Destination Net Unreachable (type 3, code 0)
# r1
ip route add default via {r2_l12}         # r2_l12
# r2
ip route add default via {r3_l23}         # r3_l23
# r3
ip route add default via {r1_l31}         # r1_l31
# inj
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Time to live exceeded
traceroute -n -q 1 -w 1 -m 12 {far}       # {r1_lan3}, {r2_l23}, {r3_l31}, {r1_lan3}, ... (12 lignes)
ping -n -c 1 -t {ttl_a} {far}             # From {r2_l23} ... (r2)
ping -n -c 1 -t {ttl_b} {far}             # From {r3_l31} ... (r3)
```

- Le paquet émis avec le TTL *T* est jeté au saut *T* ; le saut *k* est `r1`, `r2`, `r3` selon
  *(k − 1) mod 3* : TTL 64 → `r1` (64 = 3 × 21 + 1), TTL {ttl_a} → `{router_a}`, TTL {ttl_b} →
  `{router_b}`.
- Sur `eth0` de `r2` le paquet de TTL 64 passe **21 fois** (TTL 63, 60, 57, …, 3) ; il repasse
  par `r3` avec le TTL 2 et `r1` le reçoit avec le TTL 1 : jeté, *time exceeded* émis par `r1`.
- Les adresses affichées par traceroute sont `{r1_lan3}` pour `r1` (sa route vers `inj` est
  directe), `{r2_l23}` pour `r2` et `{r3_l31}` pour `r3` : l'interface par laquelle chacun
  **retourne** vers `inj` (route par défaut), pas l'interface d'entrée (partie 4).
- Évaluation : route par défaut de `inj` (2 points), de `r1`, `r2`, `r3` (3 points chacun, le sens
  compte) ; `ping -t 64` et `ping -t {ttl_b}` depuis `inj` doivent recevoir le *time exceeded* de
  `r1` et de `r3` (3 points chacun).
""": """
**Solution.**

```
# inj
ping -n -c 1 {far}                        # ping: connect: Network is unreachable (no route)
ip route add default via {r1_lan3}        # r1_lan3
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Destination Net Unreachable (type 3, code 0)
# r1
ip route add default via {r2_l12}         # r2_l12
# r2
ip route add default via {r3_l23}         # r3_l23
# r3
ip route add default via {r1_l31}         # r1_l31
# inj
ping -n -c 1 {far}                        # From {r1_lan3} icmp_seq=1 Time to live exceeded
traceroute -n -q 1 -w 1 -m 12 {far}       # {r1_lan3}, {r2_l23}, {r3_l31}, {r1_lan3}, ... (12 lines)
ping -n -c 1 -t {ttl_a} {far}             # From {r2_l23} ... (r2)
ping -n -c 1 -t {ttl_b} {far}             # From {r3_l31} ... (r3)
```

- The packet sent with the TTL *T* is dropped at hop *T*; hop *k* is `r1`, `r2`, `r3` according to
  *(k − 1) mod 3*: TTL 64 → `r1` (64 = 3 × 21 + 1), TTL {ttl_a} → `{router_a}`, TTL {ttl_b} →
  `{router_b}`.
- On `eth0` of `r2` the packet of TTL 64 passes **21 times** (TTL 63, 60, 57, …, 3); it goes
  through `r3` again with the TTL 2 and `r1` receives it with the TTL 1: dropped, *time exceeded* sent by `r1`.
- The addresses shown by traceroute are `{r1_lan3}` for `r1` (its route to `inj` is
  direct), `{r2_l23}` for `r2` and `{r3_l31}` for `r3`: the interface through which each one
  **goes back** to `inj` (default route), not the ingress interface (part 4).
- Evaluation: default route of `inj` (2 points), of `r1`, `r2`, `r3` (3 points each, the direction
  counts); `ping -t 64` and `ping -t {ttl_b}` from `inj` must receive the *time exceeded* of
  `r1` and of `r3` (3 points each).
""",
        """
**Solution.** Sur `m1` :

```
ping -n -c 1 target                 # 64 bytes from {target}: icmp_seq=1 ttl={reply_ttl}
ping -n -c 1 -W 1 -t 1 target       # From {gw} icmp_seq=1 Time to live exceeded  (gw)
ping -n -c 1 -W 1 -t 2 target       # From {second} ...                           (saut 2)
...                                 # un TTL sans réponse : le routeur muet du saut {silent_hop}
ping -n -c 1 -W 1 -t {n1} target    # 64 bytes from {target}: la cible répond (saut {n1})
ping -n -c 1 -R target              # RR: adresses de sortie, 9 au plus
```

- Chemin attendu (`gw` compris) : `{path}` ; {n} routeurs ; `target` répond avec
  `ttl=64 − {n} = {reply_ttl}` (chemin retour symétrique). Les messages sont des ICMP type 11, code 0.
- Le saut {silent_hop} ne répond pas (`{silent}` jette ses propres *time exceeded* par une règle
  nftables) : la trace continue au TTL suivant. `ping -R` enregistre quand même son adresse de
  sortie, et une adresse de ce routeur est acceptée à la place de `*`.
- Notation du chemin : toute adresse du bon routeur à la bonne position compte (adresse d'entrée vue
  par `ping -t`, ou adresse de sortie vue par `ping -R`), `*` compte au saut muet ; une adresse de
  trop retire un point.
""": """
**Solution.** On `m1`:

```
ping -n -c 1 target                 # 64 bytes from {target}: icmp_seq=1 ttl={reply_ttl}
ping -n -c 1 -W 1 -t 1 target       # From {gw} icmp_seq=1 Time to live exceeded  (gw)
ping -n -c 1 -W 1 -t 2 target       # From {second} ...                           (hop 2)
...                                 # a TTL without any answer: the silent router of hop {silent_hop}
ping -n -c 1 -W 1 -t {n1} target    # 64 bytes from {target}: the target answers (hop {n1})
ping -n -c 1 -R target              # RR: egress addresses, 9 at most
```

- Expected path (`gw` included): `{path}`; {n} routers; `target` answers with
  `ttl=64 − {n} = {reply_ttl}` (symmetric return path). The messages are ICMP type 11, code 0.
- Hop {silent_hop} does not answer (`{silent}` drops its own *time exceeded* with an nftables
  rule): the trace goes on at the next TTL. `ping -R` still records its egress
  address, and an address of this router is accepted instead of `*`.
- Grading of the path: any address of the right router at the right position counts (ingress address
  seen by `ping -t`, or egress address seen by `ping -R`), `*` counts at the silent hop; an extra
  address takes one point off.
""",
        """
**Solution.** Sur `m2`, avec `tcpdump -n -i eth0 icmp` (ou `tshark -n -i eth0 icmp`) dans un second
terminal :

```
ping -n -c 1 target2                    # 64 bytes from {target2}: icmp_seq=1 ttl={reply_ttl2}
ping -n -c 1 -W 1 -t 1 target2          # 0 received : jeté par fw (comme tout TTL < {ttl_min})
ping -n -c 1 -W 1 -t {ttl_min} target2  # répond : {ttl_min} est le plus petit TTL accepté
echo x | nc -u -w 1 -M 1 target2 33434    # capture : {fw} > {m2}: ICMP time exceeded in-transit (fw)
echo x | nc -u -w 1 -M 2 target2 33434    # capture : {second} > {m2}: ICMP time exceeded in-transit
...
echo x | nc -u -w 1 -M {n1} target2 33434    # capture : {target2} > {m2}: ICMP {target2} udp port 33434 unreachable
```

- Avec `tshark`, les mêmes lignes se lisent `{fw} → {m2} ICMP Time-to-live exceeded (Time to live
  exceeded in transit)`, puis `{target2} → {m2} ICMP Destination unreachable (Port unreachable)`.
- Chemin attendu (`fw` compris) : `{path2}` ; {n2} routeurs ; `target2` répond avec
  `ttl=64 − {n2} = {reply_ttl2}` (chemin retour symétrique).
- `fw` jette, avant même de tester le TTL, les échos ICMP entrant par `eth0` avec un TTL inférieur
  à {ttl_min} ou un en-tête IP de plus de 20 octets (`ping -R`) ; les datagrammes UDP passent et les
  *time exceeded* des routeurs cachés aussi. `nc` n'affiche rien : le noyau ne remonte pas
  *time exceeded* à un socket UDP sans `IP_RECVERR`, et `nc` tait aussi le *port unreachable* final
  (avec `-v`, son code de retour passe seulement à 1).
- Évaluation : `fw` compte les paquets entrant par `eth0` avec un TTL inférieur à {probe_limit}
  autres que les échos jetés (règle `counter`) : au moins une sonde doit avoir été envoyée (2 points) ;
  chemin noté comme en partie 1 (toute adresse du bon routeur à la bonne position, une adresse de
  trop retire un point) ; les autres réponses.
""": """
**Solution.** On `m2`, with `tcpdump -n -i eth0 icmp` (or `tshark -n -i eth0 icmp`) in a second
terminal:

```
ping -n -c 1 target2                    # 64 bytes from {target2}: icmp_seq=1 ttl={reply_ttl2}
ping -n -c 1 -W 1 -t 1 target2          # 0 received: dropped by fw (like any TTL < {ttl_min})
ping -n -c 1 -W 1 -t {ttl_min} target2  # answers: {ttl_min} is the smallest TTL accepted
echo x | nc -u -w 1 -M 1 target2 33434    # capture: {fw} > {m2}: ICMP time exceeded in-transit (fw)
echo x | nc -u -w 1 -M 2 target2 33434    # capture: {second} > {m2}: ICMP time exceeded in-transit
...
echo x | nc -u -w 1 -M {n1} target2 33434    # capture: {target2} > {m2}: ICMP {target2} udp port 33434 unreachable
```

- With `tshark`, the same lines read `{fw} → {m2} ICMP Time-to-live exceeded (Time to live
  exceeded in transit)`, then `{target2} → {m2} ICMP Destination unreachable (Port unreachable)`.
- Expected path (`fw` included): `{path2}`; {n2} routers; `target2` answers with
  `ttl=64 − {n2} = {reply_ttl2}` (symmetric return path).
- `fw` drops, even before testing the TTL, the ICMP echoes entering through `eth0` with a TTL below
  {ttl_min} or an IP header longer than 20 bytes (`ping -R`); the UDP datagrams pass, and so do the
  *time exceeded* errors of the hidden routers. `nc` prints nothing: the kernel does not pass
  *time exceeded* up to a UDP socket without `IP_RECVERR`, and `nc` keeps the final *port unreachable*
  to itself too (with `-v`, only its exit code changes to 1).
- Evaluation: `fw` counts the packets entering through `eth0` with a TTL below {probe_limit}
  other than the dropped echoes (`counter` rule): at least one probe must have been sent (2 points);
  path graded as in part 1 (any address of the right router at the right position, an extra
  address takes one point off); the other answers.
""",
        """
**Sommaire**
""": """
**Contents**
""",
        """
- `*` : aucune réponse à la sonde dans le délai. Un saut `* * *` **au milieu** d'une trace qui
  continue est un routeur **muet** (il n'émet pas d'erreur ICMP, ou son erreur est filtrée ou limitée
  en débit) : le chemin fonctionne. Des `*` **jusqu'à la fin** sans que la destination apparaisse :
  les sondes ou les réponses sont filtrées quelque part, ou la destination est injoignable.
- `!H`, `!N` : *host* / *network unreachable* renvoyé par un routeur ; `!X` : *communication
  administratively prohibited*, un pare-feu qui **rejette** au lieu de détruire le paquet (ICMP type 3, code 13) ;
  `!P` : protocole inaccessible. La trace s'arrête à ce saut.
- Une suite d'adresses qui se **répète** (`A B C A B C …`) jusqu'au nombre maximal de sauts : boucle
  de routage (section @@ref:loops@@).
- Les temps : aller-retour de chaque sonde jusqu'à ce saut. Un temps plus grand pour un saut
  intermédiaire que pour la destination n'a rien d'anormal (les routeurs traitent les erreurs ICMP
  avec une priorité basse).

Options utiles : `-n` (pas de noms), `-q 1` (une sonde par saut), `-w 1` (une seconde d'attente),
`-m 8` (8 sauts au plus), `-f 3` (commencer au TTL 3), `-I` / `-T` (section @@ref:methods@@).
""": """
- `*`: no answer to the probe in time. A `* * *` hop **in the middle** of a trace that
  goes on is a **silent** router (it sends no ICMP error, or its error is filtered or rate
  limited): the path works. `*` **up to the end** without the destination showing up:
  the probes or the answers are filtered somewhere, or the destination is unreachable.
- `!H`, `!N`: *host* / *network unreachable* sent back by a router; `!X`: *communication
  administratively prohibited*, a firewall that **rejects** the packet instead of discarding it (ICMP type 3, code 13);
  `!P`: protocol unreachable. The trace stops at that hop.
- A sequence of addresses that **repeats** (`A B C A B C …`) up to the maximum number of hops: routing
  loop (section @@ref:loops@@).
- The times: round trip of each probe up to that hop. A longer time for an intermediate
  hop than for the destination is nothing abnormal (routers handle ICMP errors
  with a low priority).

Useful options: `-n` (no names), `-q 1` (one probe per hop), `-w 1` (one second of waiting),
`-m 8` (at most 8 hops), `-f 3` (start at TTL 3), `-I` / `-T` (section @@ref:methods@@).
""",
        """
Chaque paquet IPv4 porte un champ **TTL** (*time to live*, 8 bits) fixé par l'émetteur et
**décrémenté de 1 par chaque routeur** traversé. Un routeur qui reçoit un paquet dont le TTL vaut 1
le **détruit** au lieu de le retransmettre (il tomberait à 0). Sans ce garde-fou un paquet 
pourrait circuler indéfiniment s'il existe une boucle de routage par suite d'une erreur de configuration
(cf section @@ref:loops@@).

La valeur initiale du TTL dépend du système : **64** pour Linux, macOS et les BSD, **128** pour Windows,
**255** pour la plupart des routeurs (Cisco, Juniper). 

Sous Linux elle se lit et se change par
`sysctl net.ipv4.ip_default_ttl`. 

On voit le TTL de chaque paquet capturé avec `tcpdump -n -v` ou avec `tshark -n`
(on peut spécifier les champs à afficher ainsi :

``tshark -n -T fields -e ip.src -e ip.dst -e ip.ttl -e _ws.col.Info``
""": """
Every IPv4 packet carries a **TTL** field (*time to live*, 8 bits) set by the sender and
**decremented by 1 by every router** it crosses. A router that receives a packet whose TTL is 1
**discards** it instead of forwarding it (the TTL would drop to 0). Without this safeguard a packet
could circulate forever when a configuration error creates a routing loop
(see section @@ref:loops@@).

The initial value of the TTL depends on the system: **64** for Linux, macOS and the BSDs, **128** for Windows,
**255** for most routers (Cisco, Juniper).

On Linux it is read and changed with
`sysctl net.ipv4.ip_default_ttl`.

The TTL of every captured packet shows with `tcpdump -n -v` or with `tshark -n`
(the fields to display can be chosen, for instance:

``tshark -n -T fields -e ip.src -e ip.dst -e ip.ttl -e _ws.col.Info``)
""",
        """
Depuis `m1`, découvrez le chemin jusqu'à `target` ({target}) **sans traceroute** : il reste `ping`,
`tcpdump`, `tshark` et les commandes habituelles.

1. Vérifiez que `ping -n -c 1 target` répond et notez le `ttl=` de la réponse.
2. Envoyez des échos de TTL croissant : `ping -n -c 1 -W 1 -t 1 target`, puis `-t 2`, `-t 3`…. 
Chaque message `Time to live exceeded` révèle un routeur ; un TTL
   sans aucune réponse est un routeur **muet** (section @@ref:reading@@) : notez `*` et continuez.
   Arrêtez-vous quand `target` répond elle-même.
3. Observez les messages ICMP reçus avec `tcpdump -n -v -i eth0 icmp` (ou
   `tshark -n -i eth0 -O icmp icmp`) dans un second terminal de `m1` : type, code, adresse source,
   et le paquet cité dans le message.
4. Comparez avec `ping -n -c 1 -R target` : quelles adresses sont
   enregistrées, combien, et pourquoi diffèrent-elles de celles de l'étape 2 ?
5. Déduisez le nombre de routeurs entre `m1` et `target` et expliquez le `ttl=` de l'étape 1.
""": """
From `m1`, discover the path to `target` ({target}) **without traceroute**: you still have `ping`,
`tcpdump`, `tshark` and the usual commands.

1. Check that `ping -n -c 1 target` answers and note the `ttl=` of the reply.
2. Send echoes of increasing TTL: `ping -n -c 1 -W 1 -t 1 target`, then `-t 2`, `-t 3`….
Each `Time to live exceeded` message reveals a router; a TTL
   without any answer is a **silent** router (section @@ref:reading@@): note `*` and go on.
   Stop when `target` answers itself.
3. Watch the ICMP messages received with `tcpdump -n -v -i eth0 icmp` (or
   `tshark -n -i eth0 -O icmp icmp`) in a second terminal of `m1`: type, code, source address,
   and the packet quoted in the message.
4. Compare with `ping -n -c 1 -R target`: which addresses are
   recorded, how many, and why do they differ from those of step 2?
5. Deduce the number of routers between `m1` and `target` and explain the `ttl=` of step 1.
""",
        """
Depuis `m2`, découvrez le chemin jusqu'à `target2` ({target2}).

1. Vérifiez que `ping -n -c 1 target2` répond et notez le `ttl=`. Essayez
   `ping -n -c 1 -W 1 -t 1 target2`, `-t 2`… : plus aucune réponse. Trouvez par essais successifs
   (encadrement) le plus petit TTL avec lequel `ping -t N target2` obtient encore une réponse.
2. Ouvrez un second terminal sur `m2` et lancez-y `tcpdump -n -i eth0 icmp` (ou
   `tshark -n -i eth0 icmp`).
3. Dans le premier terminal, envoyez un datagramme UDP de TTL 1 vers un port improbable de
   `target2` : `echo x | nc -u -w 1 -M 1 target2 33434` (`-M` fixe le TTL ; sinon
   `sysctl -w net.ipv4.ip_default_ttl=1` ou une règle nftables `ip ttl set 1`), et lisez dans la
   capture l'adresse qui répond *time exceeded*. Recommencez avec un TTL de 2, 3… jusqu'à ce que
   `target2` réponde elle-même : par quel message ? Qu'affiche `nc` pendant tout cela ?
4. Déduisez le nombre de routeurs entre `m2` et `target2` et expliquez le `ttl=` de l'étape 1.
""": """
From `m2`, discover the path to `target2` ({target2}).

1. Check that `ping -n -c 1 target2` answers and note the `ttl=`. Try
   `ping -n -c 1 -W 1 -t 1 target2`, `-t 2`…: no answer any more. Find by successive tries
   (bisection) the smallest TTL with which `ping -t N target2` still gets an answer.
2. Open a second terminal on `m2` and run `tcpdump -n -i eth0 icmp` (or
   `tshark -n -i eth0 icmp`) in it.
3. In the first terminal, send a UDP datagram of TTL 1 to an unlikely port of
   `target2`: `echo x | nc -u -w 1 -M 1 target2 33434` (`-M` sets the TTL; otherwise
   `sysctl -w net.ipv4.ip_default_ttl=1` or an nftables rule `ip ttl set 1`), and read in the
   capture the address that answers *time exceeded*. Start again with a TTL of 2, 3… until
   `target2` answers itself: with which message? What does `nc` print all along?
4. Deduce the number of routers between `m2` and `target2` and explain the `ttl=` of step 1.
""",
        """
L'adresse `{far}` n'appartient à aucun réseau de la maquette.

1. Sur `inj` : `ping -n -c 1 {far}`. Expliquez le message. Ajoutez la route par défaut
   (`ip route add default via r1_lan3`) et recommencez : qui répond, et par quel message ICMP ?
2. Construisez la boucle **dans ce sens** : sur `r1` une route par défaut vers `r2`
   (`via r2_l12`), sur `r2` vers `r3` (`via r3_l23`), sur `r3` vers `r1` (`via r1_l31`). Relancez
   `ping -n -c 1 {far}` depuis `inj` : quel routeur répond, et pourquoi lui (section @@ref:loops@@) ?
3. `traceroute -n -q 1 -w 1 -m 12 {far}` depuis `inj`. Puis lancez `tcpdump -n -v -i eth0 icmp`
   (ou `tshark -n -i eth0 icmp`, le `ttl=` au bout de chaque ligne) sur `r2` pendant un
   `ping -n -c 1 {far}` : combien de fois le même paquet passe-t-il, avec quels TTL ?
4. Prédisez puis vérifiez le routeur qui répond à `ping -n -c 1 -t {ttl_a} {far}` et à
   `ping -n -c 1 -t {ttl_b} {far}`.
""": """
The address `{far}` belongs to no network of the lab.

1. On `inj`: `ping -n -c 1 {far}`. Explain the message. Add the default route
   (`ip route add default via r1_lan3`) and start again: who answers, and with which ICMP message?
2. Build the loop **in this direction**: on `r1` a default route towards `r2`
   (`via r2_l12`), on `r2` towards `r3` (`via r3_l23`), on `r3` towards `r1` (`via r1_l31`). Run
   `ping -n -c 1 {far}` from `inj` again: which router answers, and why that one (section @@ref:loops@@)?
3. `traceroute -n -q 1 -w 1 -m 12 {far}` from `inj`. Then run `tcpdump -n -v -i eth0 icmp`
   (or `tshark -n -i eth0 icmp`, the `ttl=` at the end of each line) on `r2` during a
   `ping -n -c 1 {far}`: how many times does the same packet pass, with which TTLs?
4. Predict, then check, the router that answers `ping -n -c 1 -t {ttl_a} {far}` and
   `ping -n -c 1 -t {ttl_b} {far}`.
""",
        """
L'onglet **Informations** présente le TTL, le message ICMP *time exceeded*, le principe
et les variantes de traceroute, son émulation avec `ping`, les boucles de routage et les chemins
asymétriques.

Ce TP contient trois réseaux indépendants, décrits au début des parties 1, 2 et 3 (le troisième
sert aussi à la partie 4).

**Conseils.** Utilisez toujours `-n` (pas de résolution inverse) et une attente courte :
`ping -n -c 1 -W 1`, `traceroute -n -q 1 -w 1 -m 8`. L'adresse de destination de la partie 3
n'appartient à aucun réseau de la maquette : c'est voulu.

**Évaluation.** Chaque évaluation lit vos réponses aux formulaires, le compteur de sondes du
pare-feu `fw`, les routes de `inj`, `r1`, `r2`, `r3` et deux paramètres du noyau, puis lance depuis
`inj` deux `ping -t` vers la destination de la partie 3 (quelques secondes). Elle ne modifie rien.
""": """
The **Informations** tab presents the TTL, the ICMP *time exceeded* message, the principle
and the variants of traceroute, its emulation with `ping`, routing loops and asymmetric
paths.

This lab holds three independent networks, described at the start of parts 1, 2 and 3 (the third
one also serves part 4).

**Tips.** Always use `-n` (no reverse resolution) and a short wait:
`ping -n -c 1 -W 1`, `traceroute -n -q 1 -w 1 -m 8`. The destination address of part 3
belongs to no network of the lab: this is on purpose.

**Evaluation.** Each evaluation reads your answers to the forms, the probe counter of the
firewall `fw`, the routes of `inj`, `r1`, `r2`, `r3` and two kernel parameters, then runs two
`ping -t` from `inj` towards the destination of part 3 (a few seconds). It changes nothing.
""",
        """
Le `ttl=` affiché par `ping` est celui de l'*echo reply* à son arrivée : la destination l'a émis
avec son TTL initial (64, 128 ou 255 : on devine le système), et chaque routeur du **chemin retour**
l'a décrémenté. `ttl=62` depuis une machine Linux : deux routeurs au retour. Comparer ce nombre au
nombre de sauts de traceroute (chemin aller) révèle un chemin asymétrique (section
@@ref:asymmetry@@). Le TTL des paquets **émis** par une machine se change avec
`sysctl -w net.ipv4.ip_default_ttl=N` ; trop petit, ses paquets n'atteignent plus les destinations
lointaines et elle reçoit des *time exceeded* sans les avoir demandés.
""": """
The `ttl=` shown by `ping` is that of the *echo reply* when it arrives: the destination sent it
with its initial TTL (64, 128 or 255: a hint about the system), and every router of the **return path**
decremented it. `ttl=62` from a Linux machine: two routers on the way back. Comparing this number with
the number of hops of traceroute (forward path) reveals an asymmetric path (section
@@ref:asymmetry@@). The TTL of the packets **sent** by a machine is changed with
`sysctl -w net.ipv4.ip_default_ttl=N`; when it is too small, the packets no longer reach distant
destinations and the machine receives *time exceeded* errors it never asked for.
""",
        """
Le routeur qui détruit un paquet au TTL 1 renvoie à **l'émetteur du paquet** un message ICMP *time to live exceeded in transit*
(**type 11, code 0**). Comme toute erreur ICMP, il contient l'en-tête IP du
paquet fautif et les 8 premiers octets de sa charge utile : l'émetteur reconnaît ainsi le paquet
concerné (identifiant et numéro de séquence d'un écho ICMP, ports d'un datagramme UDP ou d'un
segment TCP). La commande `ping` et les analyseurs réseaux `tcpdump` et `tshark` le montrent.

**Adresse source du message TTL exceeded.** Sous Linux, l'erreur ICMP part avec 
l'adresse de l'interface du routeur
**par laquelle elle est émise** si le paramètre `net.ipv4.icmp_errors_use_inbound_ifaddr` vaut `0`.

Avec le paramètre à 1, c'est toujours l'adresse de
l'interface par laquelle le paquet fautif est **arrivé**, ce que font également la plupart des routeurs dédiés.

**limitation du débit par les routeurs** Les routeurs limitent souvent le débit
des erreurs ICMP qu'ils émettent. Une sonde sans réponse n'est pas forcément un routeur muet.

Sous Linux, les paramètres `net.ipv4.icmp_ratelimit` et `icmp_msgs_per_sec` contrôlent cette limitation.
 Dans ce projet la limitation est désactivée.
""": """
The router that discards a packet at TTL 1 sends an ICMP *time to live exceeded in transit* message
(**type 11, code 0**) back to **the sender of the packet**. Like every ICMP error, it holds the IP header of
the offending packet and the first 8 bytes of its payload: this is how the sender recognises the packet
concerned (identifier and sequence number of an ICMP echo, ports of a UDP datagram or of a
TCP segment). The `ping` command and the network analysers `tcpdump` and `tshark` show it.

**Source address of the TTL exceeded message.** On Linux, the ICMP error leaves with
the address of the router's interface
**through which it is sent** when the parameter `net.ipv4.icmp_errors_use_inbound_ifaddr` is `0`.

With the parameter at 1, it is always the address of
the interface through which the offending packet **arrived**, which is also what most dedicated routers do.

**Rate limiting by the routers.** Routers often limit the rate
of the ICMP errors they send. A probe without an answer is not necessarily a silent router.

On Linux, the parameters `net.ipv4.icmp_ratelimit` and `icmp_msgs_per_sec` control this limit.
In this project the limit is disabled.
""",
        """
Rien n'oblige les paquets d'une réponse à reprendre le chemin de la requête : chaque routeur décide
seul, d'après sa table, du prochain saut vers la destination du paquet qu'il traite. Le chemin
retour est donc souvent **différent** de l'aller (politiques de routage, liens de coût différent,
routes par défaut). `traceroute` ne montre que l'**aller** ; pour voir le retour il faut un
traceroute depuis l'autre extrémité (*reverse traceroute*), ou des indices : le `ttl=` des réponses
(section @@ref:reply-ttl@@), les adresses enregistrées par `ping -R`, ou les adresses sources des
erreurs ICMP, qui désignent l'interface par laquelle chaque routeur **retourne** vers l'émetteur
(section @@ref:time-exceeded@@).
""": """
Nothing forces the packets of a reply to take the path of the request back: every router decides
on its own, from its table, the next hop towards the destination of the packet it handles. The return
path is therefore often **different** from the forward one (routing policies, links of different costs,
default routes). `traceroute` only shows the **forward** path; seeing the return path takes a
traceroute from the other end (*reverse traceroute*), or clues: the `ttl=` of the replies
(section @@ref:reply-ttl@@), the addresses recorded by `ping -R`, or the source addresses of the
ICMP errors, which name the interface through which each router **goes back** to the sender
(section @@ref:time-exceeded@@).
""",
        """
Toujours depuis `inj` vers `srv`, la boucle de la partie 3 en place.

1. `ping -n -c 1 srv` : notez le `ttl=`. Combien de routeurs la réponse a-t-elle traversés ?
   Comparez au nombre de sauts de `traceroute -n -q 1 -w 1 -I srv` et dessinez les deux chemins
   (section @@ref:asymmetry@@).
2. `ping -n -c 1 -R srv` : retrouvez dans la liste `RR:` les adresses de l'aller, celle de `srv`
   et celles du retour.
3. Relisez les adresses des sauts 2 et 3 de `traceroute srv` : à quelle interface de `r2` et de
   `r3` appartiennent-elles ? Pourquoi (section @@ref:time-exceeded@@) ? Passez
   `net.ipv4.icmp_errors_use_inbound_ifaddr` à 1 sur `r2` et sur `r3` (`sysctl -w`) et recommencez.
4. Sur `inj`, fixez le TTL des paquets émis à **{inj_ttl}** (`net.ipv4.ip_default_ttl`). Vérifiez
   avec `tcpdump -n -v -i eth0 icmp` (ou `tshark -n -i eth0 icmp`) sur `r2` pendant un
   `ping -n -c 1 srv`, et observez le `ttl=` de la réponse. Quel est le plus petit TTL initial qui atteint encore `srv` ? Avec un TTL initial
   de 3, qui répond ?
""": """
Still from `inj` towards `srv`, with the loop of part 3 in place.

1. `ping -n -c 1 srv`: note the `ttl=`. How many routers did the reply cross?
   Compare with the number of hops of `traceroute -n -q 1 -w 1 -I srv` and draw the two paths
   (section @@ref:asymmetry@@).
2. `ping -n -c 1 -R srv`: find in the `RR:` list the addresses of the forward path, that of `srv`
   and those of the return path.
3. Look again at the addresses of hops 2 and 3 of `traceroute srv`: to which interface of `r2` and of
   `r3` do they belong? Why (section @@ref:time-exceeded@@)? Set
   `net.ipv4.icmp_errors_use_inbound_ifaddr` to 1 on `r2` and on `r3` (`sysctl -w`) and start again.
4. On `inj`, set the TTL of the packets sent to **{inj_ttl}** (`net.ipv4.ip_default_ttl`). Check it
   with `tcpdump -n -v -i eth0 icmp` (or `tshark -n -i eth0 icmp`) on `r2` during a
   `ping -n -c 1 srv`, and watch the `ttl=` of the reply. What is the smallest initial TTL that still reaches `srv`? With an initial TTL
   of 3, who answers?
""",
        """
Une **boucle** apparaît quand les routes de plusieurs routeurs se renvoient mutuellement un
paquet : `r1` a sa route par défaut vers `r2`, `r2` vers `r3`, `r3` vers `r1`, et un paquet pour
une destination qu'aucun d'eux ne connaît tourne entre eux jusqu'à ce que son TTL tombe à 0. Causes
typiques : routes par défaut « en chaîne » mal pensées, route statique vers un voisin qui renvoie
lui-même vers sa route par défaut, routage dynamique en cours de convergence.

Symptômes : `ping` reçoit *Time to live exceeded* d'un routeur sans qu'on ait touché au TTL,
`traceroute` répète les mêmes adresses jusqu'à `-m`, et la charge des routeurs monte (chaque paquet
est traité des dizaines de fois).

**Arithmétique.** Un paquet émis avec le TTL *T* arrive au saut *k* avec le TTL *T − k + 1* : il est
jeté au saut *T*. Pour une boucle de *n* routeurs entrée par le premier, le saut *k* est le routeur
numéro *((k − 1) mod n) + 1*. Avec *T* = 64 et trois routeurs, 64 = 3 × 21 + 1 : c'est le premier
routeur qui répond, après que le paquet a traversé chacun des deux autres 21 fois. Changer le TTL
(`ping -t`) change le routeur qui répond. `ip route get DEST` sur un routeur montre la route qu'il
applique.
""": """
A **loop** appears when the routes of several routers send a packet back and forth between
them: `r1` has its default route towards `r2`, `r2` towards `r3`, `r3` towards `r1`, and a packet for
a destination none of them knows goes round between them until its TTL drops to 0. Typical
causes: badly designed "chained" default routes, a static route towards a neighbour that itself
sends the packet back along its default route, dynamic routing still converging.

Symptoms: `ping` receives *Time to live exceeded* from a router although nobody touched the TTL,
`traceroute` repeats the same addresses up to `-m`, and the load of the routers rises (every packet
is handled dozens of times).

**Arithmetic.** A packet sent with the TTL *T* reaches hop *k* with the TTL *T − k + 1*: it is
dropped at hop *T*. For a loop of *n* routers entered through the first one, hop *k* is router
number *((k − 1) mod n) + 1*. With *T* = 64 and three routers, 64 = 3 × 21 + 1: the first
router answers, after the packet has crossed each of the two others 21 times. Changing the TTL
(`ping -t`) changes the router that answers. `ip route get DEST` on a router shows the route it
applies.
""",
        """
`traceroute` exploite ce mécanisme pour **découvrir les routeurs** d'un chemin : il envoie une sonde
avec un **TTL de 1** (le premier routeur la détruit et répond *time exceeded* : son adresse est
connue), puis une sonde avec un TTL de 2, de 3… jusqu'à ce que la **destination elle-même** réponde.
La réponse de la destination dépend de la sonde (section @@ref:methods@@) : *port unreachable*
(ICMP type 3, code 3) pour un datagramme UDP vers un port fermé, *echo reply* pour un écho ICMP,
SYN/ACK ou RST pour un SYN TCP.

Par défaut : trois sondes par saut (`-q 3`), 30 sauts au plus (`-m 30`), 5 s d'attente par sonde
(`-w 5`) et résolution inverse des noms (`-n` pour l'éviter). Chaque ligne donne le numéro du saut,
l'adresse qui a répondu et le temps aller-retour de chaque sonde :

```
traceroute to 10.5.0.9 (10.5.0.9), 30 hops max, 60 byte packets
 1  192.168.30.1  0.215 ms  0.180 ms  0.170 ms
 2  10.1.0.2  0.401 ms * 0.390 ms
 3  * * *
 4  10.5.0.9  0.744 ms  0.700 ms  0.690 ms
```

Ce que traceroute montre, c'est la liste des **adresses** qui ont émis une erreur, pas des
« routeurs » : pour un même routeur, l'adresse dépend de l'interface choisie (section
@@ref:time-exceeded@@). Il ne voit que le chemin **aller** (section @@ref:asymmetry@@), et les
sondes successives peuvent suivre des chemins différents quand un routeur répartit la charge
(*load balancing*) : la liste mélange alors deux chemins.
""": """
`traceroute` uses this mechanism to **discover the routers** of a path: it sends a probe
with a **TTL of 1** (the first router discards it and answers *time exceeded*: its address is
known), then a probe with a TTL of 2, of 3… until the **destination itself** answers.
The answer of the destination depends on the probe (section @@ref:methods@@): *port unreachable*
(ICMP type 3, code 3) for a UDP datagram to a closed port, *echo reply* for an ICMP echo,
SYN/ACK or RST for a TCP SYN.

By default: three probes per hop (`-q 3`), at most 30 hops (`-m 30`), a 5 s wait per probe
(`-w 5`) and reverse name resolution (`-n` avoids it). Each line gives the hop number,
the address that answered and the round-trip time of each probe:

```
traceroute to 10.5.0.9 (10.5.0.9), 30 hops max, 60 byte packets
 1  192.168.30.1  0.215 ms  0.180 ms  0.170 ms
 2  10.1.0.2  0.401 ms * 0.390 ms
 3  * * *
 4  10.5.0.9  0.744 ms  0.700 ms  0.690 ms
```

What traceroute shows is the list of the **addresses** that sent an error, not a list of
"routers": for one router, the address depends on the interface chosen (section
@@ref:time-exceeded@@). It only sees the **forward** path (section @@ref:asymmetry@@), and
successive probes may follow different paths when a router spreads the load
(*load balancing*): the list then mixes two paths.
""",
        """
`traceroute` peut fonctionner avec n'importe quel type de paquet IP, seul compte le TTL.
Par défaut `traceroute` utilise des paquets UDP mais s'ils sont détruits par un parefeu sur le chemin on
peut utiliser des paquets ICMP ou TCP.           

| méthode | sondes | fin de parcours | remarque |
|---------|--------|-----------------|----------|
| UDP (défaut sous Linux) | datagrammes vers les ports 33434, 33435… (« improbables ») | ICMP *port unreachable* de la destination | souvent filtré par les pare-feu : des `*` à la fin |
| ICMP (`-I` ; `tracert` de Windows) | échos ICMP | *echo reply* | passe là où `ping` passe |
| TCP (`-T`, port 80 par défaut, `-p PORT`) | SYN TCP | SYN/ACK (port ouvert) ou RST (port fermé) | traverse les pare-feu qui laissent passer le service |

Autres outils : `tracepath` (UDP, sans privilèges, affiche aussi le MTU du chemin ; `no reply` pour
un saut muet), `mtr` (ICMP, trace répétée avec statistiques de pertes), `nmap --traceroute`.

**Pare-feu.** Un hôte qui **détruit** (*drop*) les datagrammes UDP ne renvoie jamais le *port
unreachable* : `traceroute` affiche des `*` jusqu'à `-m` alors que la machine répond à `ping` et
sert ses pages web ; `traceroute -I` ou `traceroute -T` l'atteignent. Un pare-feu qui **rejette**
(*reject*) avec *admin prohibited* termine la trace par `!X`. Un routeur qui filtre ses propres
erreurs *time exceeded* apparaît comme un saut muet.
""": """
`traceroute` can work with any kind of IP packet: only the TTL matters.
By default `traceroute` uses UDP packets, but when a firewall on the path drops them, ICMP or TCP
packets can be used instead.

| method | probes | end of the trace | remark |
|---------|--------|-----------------|----------|
| UDP (default on Linux) | datagrams to the ports 33434, 33435… ("unlikely" ones) | ICMP *port unreachable* from the destination | often filtered by firewalls: `*` at the end |
| ICMP (`-I`; `tracert` on Windows) | ICMP echoes | *echo reply* | passes where `ping` passes |
| TCP (`-T`, port 80 by default, `-p PORT`) | TCP SYN | SYN/ACK (open port) or RST (closed port) | crosses the firewalls that let the service through |

Other tools: `tracepath` (UDP, no privileges needed, also shows the MTU of the path; `no reply` for
a silent hop), `mtr` (ICMP, repeated trace with loss statistics), `nmap --traceroute`.

**Firewalls.** A host that **drops** the UDP datagrams never sends back the *port
unreachable*: `traceroute` shows `*` up to `-m` although the machine answers `ping` and
serves its web pages; `traceroute -I` or `traceroute -T` reach it. A firewall that **rejects**
with *admin prohibited* ends the trace with `!X`. A router that filters its own
*time exceeded* errors shows up as a silent hop.
""",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `gw` (`{gw}`) |
| au-delà de `gw` | inconnu | des routeurs, puis `target` (`{target}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `gw` (`{gw}`) |
| beyond `gw` | unknown | routers, then `target` (`{target}`) |
""",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan2` | `{lan2}` | `m2` (`{m2}`), `fw` (`{fw}`) |
| au-delà de `fw` | inconnu | des routeurs, puis `target2` (`{target2}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan2` | `{lan2}` | `m2` (`{m2}`), `fw` (`{fw}`) |
| beyond `fw` | unknown | routers, then `target2` (`{target2}`) |
""",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan3` | `{lan3}` | `inj` (`{inj}`), `r1` eth0 (`{r1_lan3}`, nom `r1_lan3`) |
| `l12` | `{l12}` | `r1` eth1 (`{r1_l12}`, `r1_l12`), `r2` eth0 (`{r2_l12}`, `r2_l12`) |
| `l23` | `{l23}` | `r2` eth1 (`{r2_l23}`, `r2_l23`), `r3` eth0 (`{r3_l23}`, `r3_l23`) |
| `l31` | `{l31}` | `r3` eth1 (`{r3_l31}`, `r3_l31`), `r1` eth2 (`{r1_l31}`, `r1_l31`) |
| `lan4` | `{lan4}` | `r3` eth2 (`{r3_lan4}`, `r3_lan4`), `srv` (`{srv}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan3` | `{lan3}` | `inj` (`{inj}`), `r1` eth0 (`{r1_lan3}`, name `r1_lan3`) |
| `l12` | `{l12}` | `r1` eth1 (`{r1_l12}`, `r1_l12`), `r2` eth0 (`{r2_l12}`, `r2_l12`) |
| `l23` | `{l23}` | `r2` eth1 (`{r2_l23}`, `r2_l23`), `r3` eth0 (`{r3_l23}`, `r3_l23`) |
| `l31` | `{l31}` | `r3` eth1 (`{r3_l31}`, `r3_l31`), `r1` eth2 (`{r1_l31}`, `r1_l31`) |
| `lan4` | `{lan4}` | `r3` eth2 (`{r3_lan4}`, `r3_lan4`), `srv` (`{srv}`) |
""",
        """
| symptôme | cause probable |
|----------|----------------|
| `ping: connect: Network is unreachable` | pas de route vers la destination sur l'émetteur |
| `From R icmp_seq=1 Destination Net Unreachable` | le routeur R n'a pas de route (ICMP type 3, code 0) |
| `From R icmp_seq=1 Time to live exceeded` sans `-t` | boucle de routage, ou TTL initial trop petit |
| `traceroute` : des `*` jusqu'à la fin | sondes UDP jetées par la destination (essayer `-I`, `-T`), ou chemin coupé |
| `traceroute` : un seul saut `*`, la suite normale | routeur muet (pas d'erreur ICMP) : rien à corriger |
| `traceroute` affiche `!X` | pare-feu qui rejette (*admin prohibited*) |
| `ping -t N` ne reçoit rien, `ping` sans `-t` répond | pare-feu qui jette les échos de TTL faible : sonder avec UDP ou TCP |
| `nc -u` n'affiche rien | normal : le *time exceeded* n'est pas remonté au socket, lire la capture |
| `traceroute` très lent | 5 s × 3 sondes par saut muet : `-q 1 -w 1 -m 8` |
| `ping -R` sans ligne `RR:` | option ignorée par un routeur ou par la destination |
""": """
| symptom | likely cause |
|----------|----------------|
| `ping: connect: Network is unreachable` | no route to the destination on the sender |
| `From R icmp_seq=1 Destination Net Unreachable` | router R has no route (ICMP type 3, code 0) |
| `From R icmp_seq=1 Time to live exceeded` without `-t` | routing loop, or initial TTL too small |
| `traceroute`: `*` up to the end | UDP probes dropped by the destination (try `-I`, `-T`), or broken path |
| `traceroute`: a single `*` hop, the rest normal | silent router (no ICMP error): nothing to fix |
| `traceroute` shows `!X` | firewall that rejects (*admin prohibited*) |
| `ping -t N` receives nothing, `ping` without `-t` answers | firewall dropping the echoes of a small TTL: probe with UDP or TCP |
| `nc -u` prints nothing | normal: the *time exceeded* is not passed up to the socket, read the capture |
| `traceroute` very slow | 5 s × 3 probes per silent hop: `-q 1 -w 1 -m 8` |
| `ping -R` without an `RR:` line | option ignored by a router or by the destination |
""",
        'Ce que révèlent le TTL des réponses, ping -R et les adresses sources': 'What the TTL of the replies, ping -R and the source addresses reveal',
        'Chemins asymétriques': 'Asymmetric paths',
        'Construire et observer une boucle de routage': 'Building and watching a routing loop',
        'Dépannage': 'Troubleshooting',
        'Le TTL des réponses': 'The TTL of the replies',
        'Le champ TTL': 'The TTL field',
        'Le message ICMP time exceeded': 'The ICMP time exceeded message',
        'Le principe de traceroute': 'How traceroute works',
        'Les boucles de routage': 'Routing loops',
        'Les méthodes : UDP, ICMP, TCP et les pare-feu': 'The methods: UDP, ICMP, TCP and firewalls',
        'Lire une sortie de traceroute': 'Reading a traceroute output',
        'Organisation du TP': 'Organisation of the lab',
        'Partie 1 — Tracer un chemin sans traceroute': 'Part 1 — Tracing a path without traceroute',
        'Partie 2 — Tracer un chemin derrière un pare-feu : UDP et capture': 'Part 2 — Tracing a path behind a firewall: UDP and capture',
        'Partie 3 — Une boucle de routage': 'Part 3 — A routing loop',
        'Partie 4 — TTL des réponses, chemin retour et adresses sources': 'Part 4 — TTL of the replies, return path and source addresses',
        'TTL de la réponse de srv': 'TTL of the reply of srv',
        'TTL de la réponse de target': 'TTL of the reply of target',
        'TTL de la réponse de target2': 'TTL of the reply of target2',
        'TTL des échos de inj sur r2': 'TTL of the echoes of inj on r2',
        'TTL du dernier passage sur r2': 'TTL of the last passage on r2',
        'TTL initial de target': 'initial TTL of target',
        'TTL par défaut de inj réglé à {t}': 'default TTL of inj set to {t}',
        'Tracer le chemin de m1 à target avec ping': 'Tracing the path from m1 to target with ping',
        'Tracer le chemin de m2 à target2 avec des datagrammes UDP': 'Tracing the path from m2 to target2 with UDP datagrams',
        'Traceroute et TTL : tracer un chemin, boucles de routage, chemins asymétriques': 'Traceroute and TTL: tracing a path, routing loops, asymmetric paths',
        'ce que traceroute affiche dans une boucle': 'what traceroute shows in a loop',
        "chemin de m1 à target : routeurs dans l'ordre (gw compris)": 'path from m1 to target: routers in order (gw included)',
        "chemin de m2 à target2 : routeurs dans l'ordre (fw compris)": 'path from m2 to target2: routers in order (fw included)',
        'chemin retour de srv à inj': 'return path from srv to inj',
        'icmp_errors_use_inbound_ifaddr à 1 sur {r}': 'icmp_errors_use_inbound_ifaddr set to 1 on {r}',
        'interface de r2 affichée avec icmp_errors_use_inbound_ifaddr': 'interface of r2 shown with icmp_errors_use_inbound_ifaddr',
        'interface de r2 affichée par traceroute': 'interface of r2 shown by traceroute',
        'interface de r3 enregistrée par ping -R': 'interface of r3 recorded by ping -R',
        'message qui termine la trace UDP': 'message that ends the UDP trace',
        "nc n'affiche pas les time exceeded": 'nc does not print the time exceeded errors',
        'nombre de passages du paquet sur r2': 'number of passages of the packet on r2',
        'nombre de routeurs entre m1 et target': 'number of routers between m1 and target',
        'nombre de routeurs entre m2 et target2': 'number of routers between m2 and target2',
        'numéro du saut muet': 'number of the silent hop',
        'ping -t {ttl_b} depuis inj : time exceeded reçu de {r}': 'ping -t {ttl_b} from inj: time exceeded received from {r}',
        'ping depuis inj : time exceeded reçu de r1': 'ping from inj: time exceeded received from r1',
        'plus petit TTL accepté par le pare-feu': 'smallest TTL accepted by the firewall',
        'plus petit TTL initial qui atteint srv': 'smallest initial TTL that reaches srv',
        'route par défaut de inj vers r1': 'default route of inj towards r1',
        'route par défaut de {r} vers {nxt}': 'default route of {r} towards {nxt}',
        'routeur qui répond au TTL 64': 'router that answers at TTL 64',
        'routeur qui répond au TTL {t}': 'router that answers at TTL {t}',
        'routeur qui répond à un TTL initial de 3': 'router that answers an initial TTL of 3',
        'routeurs du chemin aller': 'routers of the forward path',
        'routeurs du chemin retour': 'routers of the return path',
        'sondes UDP de TTL faible reçues par fw': 'UDP probes of a small TTL received by fw',
        'type et code du message ICMP time exceeded': 'type and code of the ICMP time exceeded message',
    },
}
