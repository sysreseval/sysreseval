"""Latency lab: the one-way delays of an opaque network, measured in each direction.

Topology: ``gw — ext — m1 — x1 — x — x3 — m3 — l23 — m2 — l12 — m1``: four machines in a ring
(``m1``, ``x``, ``m3``, ``m2``) and the site's gateway ``gw`` on ``m1``.  ``x`` is an operator's
network (a star in the schema, no terminal) that forwards with a different delay in each direction
(``Data.delay_to_m3``: m1 → x → m3, ``Data.delay_to_m1``: m3 → x → m1; one netem per egress
interface of ``x``) and never emits an ICMP message (no echo reply, no time exceeded: an opaque
network).  ``m2`` carries the slow link of the site (``Data.local_delay`` on both of its interfaces,
visible with ``tc qdisc show``).

At start every machine has its addresses and a hosts file but no route and ``ip_forward = 0``,
except ``x``: forwarding, a route to every network of the site, and two **phantom networks** that
nobody owns, ``net1`` routed towards ``m3`` and ``net2`` routed towards ``m1``.

Question 1: the total latency through ``x`` (a ping m1 → m3 once the two routes through ``x`` are
set).  Question 2: the delay of each direction by the **ring method**: the students route ``net1`` in
a circle (m1 via x, m3 via m2, m2 via m1), a packet sent by ``gw`` turns m1 → x → m3 → m2 → m1 → x …
until its TTL expires, tcpdump on ``m1`` shows one pass per turn and the period is A + L; ``net2``
routed the other way round gives B + L; the local ping gw ↔ m3 through m2 (RTT 2 L) gives the
correction.  The packet must come from outside the ring: Linux drops a forwarded packet whose source
is one of its own addresses (martian source, ``accept_local = 0``).  The grader checks the rings with
``ping -t 9`` from ``gw`` (two turns; ``m1`` answers *time exceeded* on the connected link).

The user-allowed state ``reset`` (the only one of the *Apply Configuration* tab of a student) puts
every machine back as ``initial`` left it: routes flushed, addresses set again, forwarding off on
the students' machines, the qdiscs removed then the delays of ``x`` and ``m2`` set again,
``rp_filter`` / ``accept_local`` back to 0, ARP caches emptied; the answers are kept.

``latency_answers_in_self_eval`` (module flag, default True) grades the three measured latencies in the
self-evaluation too; False keeps them for the instructor's evaluation only (``EXO_EVAL_SCOPE``).
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List, Tuple

import tc
import traceroute as trc
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from ips import random_ipv4networks, random_ips_from_topology
from net_config import (NetConfigEntry, set_net_config_entry, set_ip_forward, get_ip_forward, get_routes,
                        remount_proc_sys)
from state_helpers import create_hosts_file
from tcp import netem_cmd, netem_del_cmd

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Latence : mesurer le délai d'un réseau opaque dans chaque sens",
           en="Latency: measuring the delay of an opaque network in each direction")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True        # the `reset` state alone (`final` stays admin-only)
# The three measured latencies (the form answers) are graded in the self-evaluation too (True: a student
# sees at once whether a measurement is within tolerance, OK / FAIL letters) or in the instructor's
# evaluation only (False: the self-evaluation shows the configuration elements alone, 48 of the 100 points)
latency_answers_in_self_eval = True
# The Kathara export would print the startup commands of x, hence its delays.
export_kathara_project = False
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp-latence.lan"
X_DELAY_RANGE = (30, 120)       # ms: the one-way delays of x, one per direction (Data.delay_to_m3 / delay_to_m1)
X_DELAY_MIN_GAP = 20            # ms: the two delays of x differ by at least this
LOCAL_DELAY_RANGE = (15, 30)    # ms: the slow link of m2, on both of its interfaces (Data.local_delay)
TOLERANCE_REL = 0.10            # an answer is accepted within TOLERANCE_REL * expected + TOLERANCE_ABS_MS
TOLERANCE_ABS_MS = 2.0          # (the local delay always exceeds the tolerance: an uncorrected answer fails)
RING_ROUTERS = 4                # routers of one turn of a ring: m1, x, m3, m2
RING_TTL = 2 * RING_ROUTERS + 1  # ping -t of the grader from gw: two full turns, then m1 answers time exceeded
STUDENT_MACHINES = ('gw', 'm1', 'm2', 'm3')
RING_MACHINES = ('m1', 'm2', 'm3')         # the routers of the rings the students configure
PHANTOM_NETS = ('net1', 'net2')            # routed by x towards m3 / towards m1, owned by nobody
OPAQUE_TABLE = "opaque"                    # x: no ICMP message of its own
OPAQUE_RULES = "/root/opaque.nft"
RP_FILTER_OFF = ('net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
# `reset`: every route of the main table (the connected ones come back with the addresses, a blackhole
# route has no interface) and the per-interface sysctls set back to their creation-time value 0
ROUTE_FLUSH_CMD = "ip -4 route flush table main"
RESET_SYSCTLS = ('rp_filter', 'accept_local')

_TOPOLOGY = {
    'ext': {'gw': 0, 'm1': 0},
    'x1': {'m1': 1, 'x': 0},      # x eth0 towards m1: netem delay_to_m1 (direction m3 -> x -> m1)
    'x3': {'x': 1, 'm3': 0},      # x eth1 towards m3: netem delay_to_m3 (direction m1 -> x -> m3)
    'l23': {'m3': 1, 'm2': 0},    # m2 eth0 towards m3: netem local_delay
    'l12': {'m2': 1, 'm1': 2},    # m2 eth1 towards m1: netem local_delay
}
_SPECS = {
    'gw': {'color': 'lightblue', 'sysctls': RP_FILTER_OFF},
    'm1': {'color': 'lightyellow', 'sysctls': RP_FILTER_OFF},
    'm2': {'color': 'lightyellow', 'sysctls': RP_FILTER_OFF},
    'm3': {'color': 'lightyellow', 'sysctls': RP_FILTER_OFF},
    # the operator's network: visible, no terminal, a star in the schema
    'x': {'shape': 'star', 'allow_connection': False, 'color': 'lightgrey', 'sysctls': RP_FILTER_OFF},
}
X_DEV = {'m1': 'eth0', 'm3': 'eth1'}       # interface of x towards each neighbour
M2_DEV = {'m3': 'eth0', 'm1': 'eth1'}      # interface of m2 towards each neighbour
M1_DEV = {'gw': 'eth0', 'x': 'eth1', 'm2': 'eth2'}   # interfaces of m1 (the capture point)


def _machine_networks(machine: str) -> List[Tuple[int, str]]:
    """``[(interface index, network)]`` of a machine, in interface order."""
    return sorted((members[machine], net) for net, members in _TOPOLOGY.items() if machine in members)


_ALL_MACHINES = sorted({m for members in _TOPOLOGY.values() for m in members})
_SINGLE_HOMED = {m for m in _ALL_MACHINES if len(_machine_networks(m)) == 1}


def _draw_delays() -> Tuple[int, int]:
    """Two delays of X_DELAY_RANGE at least X_DELAY_MIN_GAP apart."""
    while True:
        a, b = random.randint(*X_DELAY_RANGE), random.randint(*X_DELAY_RANGE)
        if abs(a - b) >= X_DELAY_MIN_GAP:
            return a, b


def opaque_rules(table: str = OPAQUE_TABLE) -> str:
    """nftables text making a router emit no ICMP message of its own (the output hook only sees
    the locally generated packets: the forwarded ones are untouched)."""
    return (f"table ip {table} {{\n"
            f"\tchain output {{\n"
            f"\t\ttype filter hook output priority 0; policy accept;\n"
            f"\t\tmeta l4proto icmp drop\n"
            f"\t}}\n"
            f"}}\n")


def reset_sysctl_cmd(interfaces: List[str]) -> str:
    """One ``sysctl -w`` setting every RESET_SYSCTLS to 0 on ``all``, ``default`` and *interfaces*
    (``rp_filter`` is the maximum of ``all`` and the interface's own value)."""
    names = ['all', 'default', *interfaces]
    return "sysctl -w " + " ".join(f"net.ipv4.conf.{name}.{sysctl}=0" for sysctl in RESET_SYSCTLS for name in names)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    delay_to_m3: int = 0     # ms: one-way delay of x in the direction m1 -> x -> m3 (its egress towards m3)
    delay_to_m1: int = 0     # ms: one-way delay of x in the direction m3 -> x -> m1 (its egress towards m1)
    local_delay: int = 0     # ms: delay of each interface of m2 (the slow link of the site)

    @classmethod
    def generate(cls):
        data = cls()
        data.delay_to_m3, data.delay_to_m1 = _draw_delays()
        data.local_delay = random.randint(*LOCAL_DELAY_RANGE)
        names = list(_TOPOLOGY) + list(PHANTOM_NETS)
        nets = random_ipv4networks(masks=[24] * len(names), from_private_network=True,
                                   exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in zip(names, nets):
            setattr(data.nets, name, net)
        # ips.gw, ips.m1_ext, ips.m1_x1, ips.m1_l12, ips.x_x1, ips.x_x3, ips.m3_x3, ips.m3_l23,
        # ips.m2_l23, ips.m2_l12 (nobody on net1 / net2)
        random_ips_from_topology(data, _TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = _SPECS
    _network_specs = {
        'ext': {'color': 'lightblue'},
        'x1': {'color': 'lightgrey'},
        'x3': {'color': 'lightgrey'},
        'l23': {'color': 'lightyellow'},
        'l12': {'color': 'lightyellow'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        # addresses only: the students add every route of their machines
        self.net_config: Dict[str, NetConfigEntry] = {
            m: [([self.addr(m, net)], []) for _, net in _machine_networks(m)] for m in _ALL_MACHINES}
        # x: every network of the site by the shortest path, the phantom networks as announced
        self.x_routes: List[Tuple[IPv4Network, IPv4Interface]] = [
            (d.nets.ext, self.addr('m1', 'x1')), (d.nets.l12, self.addr('m1', 'x1')), (d.nets.net2, self.addr('m1', 'x1')),
            (d.nets.l23, self.addr('m3', 'x3')), (d.nets.net1, self.addr('m3', 'x3')),
        ]
        # the reference solution: question 1 (m1 and m3 through x), question 2 (gw, the two rings, the local path)
        self.ring1_routes: Dict[str, Tuple[IPv4Network, IPv4Interface]] = {       # m1 -> x -> m3 -> m2 -> m1
            'm1': (d.nets.net1, self.addr('x', 'x1')),
            'm3': (d.nets.net1, self.addr('m2', 'l23')),
            'm2': (d.nets.net1, self.addr('m1', 'l12')),
        }
        self.ring2_routes: Dict[str, Tuple[IPv4Network, IPv4Interface]] = {       # m1 -> m2 -> m3 -> x -> m1
            'm1': (d.nets.net2, self.addr('m2', 'l12')),
            'm2': (d.nets.net2, self.addr('m3', 'l23')),
            'm3': (d.nets.net2, self.addr('x', 'x3')),
        }
        self.q1_routes: Dict[str, Tuple[IPv4Network, IPv4Interface]] = {
            'm1': (d.nets.x3, self.addr('x', 'x1')),
            'm3': (d.nets.x1, self.addr('x', 'x3')),
        }
        self.local_routes: Dict[str, Tuple[IPv4Network, IPv4Interface]] = {       # gw <-> m3 through m2, never x
            'm1': (d.nets.l23, self.addr('m2', 'l12')),
            'm2': (d.nets.ext, self.addr('m1', 'l12')),
            'm3': (d.nets.ext, self.addr('m2', 'l23')),
        }
        self.gw_route: Tuple[IPv4Network, IPv4Interface] = (default, self.addr('m1', 'ext'))
        self.solution_routes: Dict[str, List[Tuple[IPv4Network, IPv4Interface]]] = {m: [] for m in STUDENT_MACHINES}
        self.solution_routes['gw'].append(self.gw_route)
        for routes in (self.q1_routes, self.ring1_routes, self.ring2_routes, self.local_routes):
            for m, route in routes.items():
                self.solution_routes[m].append(route)

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Latence, RTT et délai aller simple"), tag="latency")
            + tr("""
La **latence** d'un chemin est le temps que met un paquet pour aller de l'émetteur au destinataire :
le **délai aller simple** (*one-way delay*). Il additionne, lien par lien, le temps de **propagation**
(la vitesse du signal : environ 200 000 km/s dans une fibre, soit 5 µs par km), le temps
d'**émission** (taille du paquet divisée par le débit : 12 µs pour 1500 octets à 1 Gbit/s) et, dans
chaque équipement traversé, le temps de traitement et surtout le temps d'**attente en file** quand le
lien de sortie est occupé. La variation de ce délai d'un paquet à l'autre est la **gigue** (*jitter*).
Ordres de grandeur : moins d'une milliseconde dans un réseau local, 10 à 30 ms entre deux villes
d'Europe, 80 à 100 ms pour traverser l'Atlantique, 250 ms d'aller simple par un satellite
géostationnaire (36 000 km d'altitude).

Le **RTT** (*round-trip time*, temps aller-retour) est ce que mesure `ping` : délai aller, temps de
réponse du destinataire et délai retour. Rien n'oblige les deux sens à être égaux
(section @@ref:oneway@@).

Latence et **débit** sont deux grandeurs indépendantes : un lien peut avoir un gros débit et une
grande latence (un satellite à 100 Mbit/s et 500 ms de RTT). Les protocoles faits d'allers-retours
(l'ouverture d'une connexion TCP, une requête DNS, une page web et ses dizaines de requêtes) souffrent
de la latence quel que soit le débit : c'est pourquoi on la mesure.
""")
            + info_subtitle(tr("Mesurer un RTT avec ping"), tag="ping")
            + tr("""
`ping` envoie un **écho ICMP** (type 8, *echo request*) ; le destinataire renvoie une réponse (type 0,
*echo reply*) qui recopie la charge utile. `ping` note l'heure d'émission dans cette charge utile,
la compare à l'heure de réception et affiche le RTT de chaque réponse, puis le résumé
`rtt min/avg/max/mdev` (minimum, moyenne, maximum, écart type, en ms).

```
ping -n -c 10 -i 0.2 DEST      # 10 échos à 0,2 s d'intervalle, sans résolution inverse des noms
ping -n -c 1 -W 5 DEST         # un seul écho, 5 s d'attente de la réponse
ping -n -c 1 -t 5 DEST         # TTL 5 : le cinquième routeur jette le paquet et répond "Time to live exceeded"
```

- Le **premier écho** est plus lent : il déclenche une résolution **ARP** sur chaque lien traversé, et
  les réponses ARP subissent les mêmes files d'attente que les paquets (sur un lien lent, le premier
  écho coûte à peu près le double). Lisez le **minimum** (`min`) de plusieurs échos, ou la moyenne
  sans le premier.
- Chaque routeur traversé décrémente le **TTL** du paquet (64 au départ sous Linux). Celui qui reçoit
  un TTL de 1 jette le paquet et renvoie à l'émetteur un message ICMP *time exceeded* (type 11), que
  `ping` affiche `From ADRESSE icmp_seq=1 Time to live exceeded` : l'adresse est celle de l'interface
  par laquelle le routeur émet l'erreur. `ping` n'affiche pas de temps pour une erreur.
- Une machine qui n'a aucune route vers la destination répond `Network is unreachable` sans rien
  émettre ; une destination qui ne répond pas donne `100% packet loss` après l'attente.
""")
            + info_subtitle(tr("Pourquoi le délai aller simple n'est pas mesurable directement"), tag="oneway")
            + tr("""
Mesurer un délai aller simple, c'est comparer l'heure d'émission, lue sur l'horloge de l'émetteur, à
l'heure de réception, lue sur celle du destinataire : il faut deux horloges **synchronisées** bien
mieux que le délai à mesurer. NTP donne quelques millisecondes à travers Internet, PTP (IEEE 1588)
la microseconde sur un réseau local équipé pour cela ; c'est ainsi que travaillent les sondes de
mesure des opérateurs (OWAMP, RFC 4656). Sans cela, un `ping` ne donne que la **somme** des deux sens.

Or les deux sens diffèrent souvent : chemins aller et retour différents (le routage d'Internet est
largement asymétrique), liaisons dissymétriques (ADSL, satellite avec voie de retour terrestre), file
d'attente pleine dans un sens seulement. La méthode de ce TP contourne le problème sans horloge
distante : elle fait **repasser le même paquet par le même point de mesure**, où une seule horloge
suffit.
""")
            + info_subtitle(tr("La méthode de la boucle"), tag="ring")
            + tr("""
### @@sec@@ Le principe

On choisit un **réseau fantôme**, un préfixe que personne ne possède, et on le route **en cercle** :
chaque routeur de l'anneau envoie ce réseau au routeur suivant. Un paquet destiné à ce réseau,
injecté dans l'anneau depuis l'extérieur, fait le tour, revient au premier routeur, qui le renvoie…
jusqu'à l'expiration de son TTL : le routeur qui reçoit un TTL de 1 le jette et renvoie *time
exceeded* à l'émetteur, s'il a une route vers lui. Sur une machine de l'anneau, une capture montre le
paquet **à chaque tour** : l'intervalle entre deux passages est la **période** de la boucle, la somme
des délais de tous les liens et routeurs de l'anneau **dans le sens de la boucle**. Le même paquet,
la même horloge : aucune synchronisation n'est nécessaire.

Si un seul tronçon de l'anneau est lent dans ce sens, la période vaut son délai plus les petits
délais des autres tronçons. En routant un **second** réseau fantôme en cercle **dans l'autre sens**,
on mesure de la même façon le délai du tronçon dans l'autre sens.

### @@sec@@ Le calcul

Soit A le délai du tronçon lent dans le sens de la première boucle et B dans le sens de la seconde :

- période de la boucle 1 = A + (délais des autres tronçons, dans le sens 1) ;
- période de la boucle 2 = B + (délais des autres tronçons, dans le sens 2).

Les autres tronçons s'estiment avec un `ping` qui emprunte **seulement** ces tronçons, sans le
tronçon lent : son RTT est deux fois le chemin local, donc **délai local ≈ RTT local / 2**. D'où
A ≈ période 1 − RTT local / 2 et B ≈ période 2 − RTT local / 2. Vérification : A + B doit retrouver
le RTT d'un `ping` qui traverse le tronçon lent à l'aller **et** au retour.

### @@sec@@ Les pièges

- Le paquet doit être injecté **depuis l'extérieur** de l'anneau. Linux jette un paquet à router
  dont l'adresse source est l'une de ses propres adresses (*martian source*, paramètre
  `net.ipv4.conf.all.accept_local = 0`) : un `ping` lancé depuis un routeur de l'anneau disparaît dès
  son premier retour sur ce routeur.
- Le **premier tour** est plus long : une résolution ARP à chaque saut. Mesurez à partir du
  deuxième passage, ou lancez un second `ping`.
- Chaque routeur de l'anneau doit avoir le **routage activé** (`ip_forward`) et une route vers le
  réseau fantôme **vers le routeur suivant**. Une route manquante arrête le paquet : *Destination
  unreachable*, ou rien du tout.
- Le TTL limite le nombre de tours : 64 au départ et quatre routeurs par tour font 16 tours ;
  `ping -t` en fait moins. Le routeur qui reçoit un TTL de 1 ne répond *time exceeded* que s'il a une
  route vers l'émetteur, et s'il n'est pas muet.
- Le `ping` local de la correction doit suivre exactement les tronçons locaux de l'anneau et aucun
  autre : vérifiez son chemin (`ip route get`, `traceroute -n`).
""")
            + info_subtitle(tr("Observer les passages avec tcpdump ou tshark"), tag="capture")
            + tr("""
```
tcpdump -n -i eth1 -ttt icmp                      # une interface ; -ttt : délai depuis la ligne précédente
tcpdump -n -i any -tt icmp                        # toutes les interfaces, horodatage absolu (secondes depuis 1970)
tcpdump -n -i eth1 -ttt 'dst net 203.0.113.0/24'  # seulement les paquets vers un réseau donné
tcpdump -n -i eth1 -c 20 -w /shared/boucle.pcap icmp   # 20 paquets dans un fichier, à ouvrir avec Wireshark
tshark -n -i eth1 -t d icmp                       # tshark : -t d = délai depuis le paquet précédent
```

Sur une machine de l'anneau, le paquet d'une boucle **entre** par une interface et **sort** par une
autre à chaque tour : capturer sur **une seule** interface donne une ligne par tour, et avec `-ttt`
chaque ligne affiche directement la période (`00:00:00.123456` : heures, minutes, secondes et
microsecondes depuis la ligne précédente). Avec `-i any`, `tcpdump` ajoute le nom de l'interface et
le sens (`In` / `Out`) devant chaque ligne, et chaque tour apparaît deux fois. Les erreurs ICMP
s'affichent `ICMP time exceeded in-transit` ; `Ctrl-C` arrête la capture et `-c N` l'arrête après N
paquets. Un fichier écrit dans `/shared` se retrouve dans le répertoire partagé du projet.
""")
            + info_subtitle(tr("Rappels de routage statique sous Linux"), tag="routing")
            + tr("""
```
ip route                                   # la table : une route "proto kernel" par interface (réseaux directement connectés)
ip route add RÉSEAU/PRÉFIXE via PROCHAIN_SAUT    # route statique ("replace" pour la remplacer, "del" pour la retirer)
ip route add default via PROCHAIN_SAUT     # la route par défaut (0.0.0.0/0)
ip route get ADRESSE                       # la route que cette machine utiliserait pour ADRESSE
sysctl -w net.ipv4.ip_forward=1            # activer le routage (relais des paquets reçus pour d'autres) ; 0 : simple hôte
cat /proc/sys/net/ipv4/ip_forward          # lire la valeur en cours
traceroute -n -q 1 -w 1 -m 8 DEST          # les routeurs du chemin aller (un routeur muet donne "*")
tc qdisc show                              # les files d'émission des interfaces (un "netem delay" est un lien lent)
```

Le prochain saut d'une route statique doit être une adresse d'un réseau **directement connecté** à
la machine. Une machine sans route par défaut ne joint que ses propres réseaux ; une machine qui
reçoit un paquet pour un autre réseau le jette tant que `ip_forward` vaut 0, même si elle a la
route. Les routes de ce TP sont volatiles : elles disparaissent au redémarrage d'un conteneur, ce
qui n'arrive pas ici.
""")
            + info_subtitle(tr("Outils"), tag="tools")
            + tr("""
| outil | usage |
|-------|-------|
| `ping -n -c N -i 0.2 DEST` | RTT moyen sur N échos (`rtt min/avg/max/mdev`) |
| `ping -n -c 1 -W S DEST` | un écho, S secondes d'attente |
| `ping -n -c 1 -t TTL DEST` | un écho au TTL donné (où s'arrête-t-il ?) |
| `tcpdump -n -i IFACE -ttt icmp` | une ligne par paquet, le délai depuis la précédente |
| `tshark -n -i IFACE -t d icmp` | idem avec tshark |
| `ip route add RÉSEAU via SAUT` / `ip route get ADRESSE` | ajouter une route / voir la route utilisée |
| `sysctl -w net.ipv4.ip_forward=1` | activer le routage |
| `traceroute -n -q 1 -w 1 -m 8 DEST` | le chemin aller |
| `tc qdisc show` | les délais artificiels des interfaces (`netem`) |
""")
        )

    def addr(self, machine: str, net: str) -> IPv4Interface:
        """The address of *machine* on *net* (``data.ips.m`` or ``data.ips.m_net``)."""
        return getattr(self.data.ips, machine if machine in _SINGLE_HOMED else f"{machine}_{net}")

    # -- states ------------------------------------------------------------------

    def _delays(self):
        """The netem delays of x (one per direction) and of the slow link of m2 (idempotent)."""
        d = self.data
        self.cmd('x', netem_cmd(X_DEV['m3'], d.delay_to_m3))
        self.cmd('x', netem_cmd(X_DEV['m1'], d.delay_to_m1))
        for dev in M2_DEV.values():
            self.cmd('m2', netem_cmd(dev, d.local_delay))

    def _initial_config(self):
        """What ``initial`` sets up on every machine.  Idempotent but for ``ip addr add``, which
        fails on an address already set: ``reset`` flushes the addresses first."""
        for m in _ALL_MACHINES:
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            # Kathara starts every container with ip_forward=1: the operator's network only
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'x'))
        for dest, via in self.x_routes:
            self.cmd('x', f"ip route replace {dest.compressed} via {via.ip}")
        # x emits no ICMP message of its own: pinging it, or expiring a TTL on it, reveals nothing
        self.file('x', OPAQUE_RULES, opaque_rules())
        self.cmd('x', f"nft delete table ip {OPAQUE_TABLE} 2>/dev/null; nft -f {OPAQUE_RULES}")
        self._delays()
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN)

    @sre_state(user_allowed=False)
    def initial(self):
        self._initial_config()

    # the descriptions of the states are evaluated at import time, before _TRANSLATIONS: inline English too
    @sre_state(user_allowed=True,
               description=tr("Retour à l'état de départ (routes supprimées, routage désactivé, etc..) - "
                              "vos réponses sont conservées",
                              en="Back to the initial state (routes removed, forwarding off, etc.) - "
                                 "your answers are kept"))
    def reset(self):
        """Back to the initial state, the students' answers apart.  On every machine (x included,
        harmless there): the main routing table flushed (the connected routes too: ``ip addr add``
        of ``_initial_config`` recreates them once the addresses are flushed; a blackhole route has
        no interface, so flushing the addresses alone would not do), every root qdisc removed (the
        delays of ``x`` and ``m2`` come back with ``_initial_config``, a netem a student added
        elsewhere does not), the creation-time sysctls set again, the ARP caches emptied; then the
        whole initial configuration again."""
        for m in _ALL_MACHINES:
            interfaces = [f"eth{i}" for i, _ in _machine_networks(m)]
            self.cmd(m, ROUTE_FLUSH_CMD)
            for dev in interfaces:
                self.cmd(m, f"ip addr flush dev {dev}")
                self.cmd(m, netem_del_cmd(dev))
            remount_proc_sys(self, m)
            self.cmd(m, reset_sysctl_cmd(interfaces))
            self.cmd(m, "ip neigh flush all")
        self._initial_config()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : routes de m1 et m3 par x (question 1), routage sur m1, m2, m3, "
                              "route par défaut de gw, boucles net1 et net2 et chemin local (question 2) ; "
                              "le lien lent de m2 est remis en place",
                              en="Reference solution: routes of m1 and m3 via x (question 1), forwarding on m1, m2, "
                                 "m3, default route of gw, rings net1 and net2 and local path (question 2); "
                                 "the slow link of m2 is set up again"))
    def final(self):
        """Reference solution (idempotent): the routes of both questions, forwarding on the ring
        routers, the slow link of m2 again (a student may have removed its qdiscs)."""
        for m in RING_MACHINES:
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=True)
        for m, routes in self.solution_routes.items():
            for dest, via in routes:
                self.cmd(m, f"ip route replace {dest.compressed} via {via.ip}")
        self._delays()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _float(s, default=None):
    try:
        return float(str(s).strip().replace(',', '.'))
    except (TypeError, ValueError):
        return default


def _approx(value, expected, rel: float = TOLERANCE_REL, abs_margin: float = TOLERANCE_ABS_MS) -> bool:
    """*value* (a number or a form answer) is within ``rel * expected + abs_margin`` of *expected*."""
    v = _float(value)
    return v is not None and abs(v - float(expected)) <= rel * float(expected) + abs_margin


def _has_route(routes: Dict[Tuple[str, int], Tuple[str, str, int]], dest: IPv4Network, via: IPv4Interface) -> bool:
    """A :func:`net_config.get_routes` table holds *dest* via *via*."""
    entry = routes.get((str(dest.network_address), dest.prefixlen))
    return entry is not None and entry[0] == str(via.ip)


def _time_exceeded_from(result: Dict, source: IPv4Interface) -> bool:
    """A :func:`traceroute.parse_ping` result holds a *time exceeded* error sent by *source*."""
    return any(e['from'] == str(source.ip) and trc.TIME_EXCEEDED_MESSAGE in e['message'] for e in result['errors'])


def _fmt(ms: float) -> str:
    """A delay in ms for the texts (``37`` rather than ``37.0``)."""
    return f"{ms:g}"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        addr = ns.addr
        a, b, local = d.delay_to_m3, d.delay_to_m1, d.local_delay
        total = a + b
        period1, period2, local_rtt = a + local, b + local, 2 * local
        net1, net2 = d.nets.net1, d.nets.net2
        target1, target2 = str(net1[1]), str(net2[1])        # any address of a phantom network does
        m3_x3 = str(addr('m3', 'x3').ip)
        # the three measured latencies: in both evaluations, or in the instructor's only (module flag)
        answer_scope = params.BOTH_EVAL_SCOPE if latency_answers_in_self_eval else params.EXO_EVAL_SCOPE

        # ---------------- the configuration of the students' machines -------------------
        routes = {m: get_routes(self, m) for m in STUDENT_MACHINES}
        forward = {m: get_ip_forward(self, m) for m in RING_MACHINES}
        q1_ok = {m: _has_route(routes[m], dest, via) for m, (dest, via) in ns.q1_routes.items()}
        ring1_ok = {m: _has_route(routes[m], dest, via) for m, (dest, via) in ns.ring1_routes.items()}
        ring2_ok = {m: _has_route(routes[m], dest, via) for m, (dest, via) in ns.ring2_routes.items()}
        gw_ok = (_has_route(routes['gw'], *ns.gw_route)
                 or (_has_route(routes['gw'], net1, ns.gw_route[1]) and _has_route(routes['gw'], net2, ns.gw_route[1])))

        # ---------------- live tests -------------------------------------------------------
        # question 1: a ping of m1 towards m3 through x, in both directions (the students' routes); the
        # minimum RTT: the first echo pays an ARP resolution on every link and the ARP replies of x cross
        # its queues too (seen live: 349 ms for a 173 ms RTT), which would spoil the average of a cold cache
        ping_out, _ = self.test('m1', tc.ping_cmd(m3_x3, count=5, interval=0.2), timeout=12, allow_error=True)
        ping = tc.parse_ping(ping_out)
        ping_ok = (ping.get('received') or 0) >= 2 and _approx(ping.get('min'), total)
        # question 2: two turns of each ring from gw, then m1 (router 1, 5, 9 of the ring) answers time exceeded
        loop1 = trc.ping_ttl(self, 'gw', target1, ttl=RING_TTL, wait=3)
        loop2 = trc.ping_ttl(self, 'gw', target2, ttl=RING_TTL, wait=3)
        loop1_ok = _time_exceeded_from(loop1, addr('m1', 'ext'))
        loop2_ok = _time_exceeded_from(loop2, addr('m1', 'ext'))

        # ---------------- texts shared by the questions ---------------------------------
        addressing = tr("""
| réseau | préfixe | machines (nom dans `/etc/hosts`) |
|--------|---------|----------------------------------|
| `ext` | `{ext}` | `gw` (`{gw}`, `gw`), `m1` eth0 (`{m1_ext}`, `m1_ext`) |
| `x1` | `{x1}` | `m1` eth1 (`{m1_x1}`, `m1_x1`), `x` eth0 (`{x_x1}`, `x_x1`) |
| `x3` | `{x3}` | `x` eth1 (`{x_x3}`, `x_x3`), `m3` eth0 (`{m3_x3}`, `m3_x3`) |
| `l23` | `{l23}` | `m3` eth1 (`{m3_l23}`, `m3_l23`), `m2` eth0 (`{m2_l23}`, `m2_l23`) |
| `l12` | `{l12}` | `m2` eth1 (`{m2_l12}`, `m2_l12`), `m1` eth2 (`{m1_l12}`, `m1_l12`) |
| `net1` | `{net1}` | réseau fantôme : personne ; `x` le route vers `m3` |
| `net2` | `{net2}` | réseau fantôme : personne ; `x` le route vers `m1` |
""").format(ext=d.nets.ext, x1=d.nets.x1, x3=d.nets.x3, l23=d.nets.l23, l12=d.nets.l12, net1=net1, net2=net2,
            gw=addr('gw', 'ext').ip, m1_ext=addr('m1', 'ext').ip, m1_x1=addr('m1', 'x1').ip,
            x_x1=addr('x', 'x1').ip, x_x3=addr('x', 'x3').ip, m3_x3=m3_x3, m3_l23=addr('m3', 'l23').ip,
            m2_l23=addr('m2', 'l23').ip, m2_l12=addr('m2', 'l12').ip, m1_l12=addr('m1', 'l12').ip)

        # ---------------- organisation ----------------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente la latence et le RTT, la mesure avec `ping`, la
méthode de la boucle, les captures et les commandes de routage utiles.

**Le réseau.** 

- `x` est le **réseau d'un
opérateur** (une étoile dans le schéma, **sans terminal**) : il route les paquets entre `m1` et `m3`
avec une **latence inconnue, différente dans chaque sens** (m1 → x → m3 et m3 → x → m1), que vous
allez mesurer. Il n'émet aucun message ICMP : il ne répond pas à `ping` et ne signale pas les TTL
expirés. 

Le routage est activé sur `x` et cette machine route `ext` et `l12` par `m1`, `l23`
par `m3`, le réseau fantôme `net1` par `m3` et le réseau fantôme `net2` par `m1`. Ces deux derniers
préfixes n'existent nulle part : ils servent à la question 2.

- Le routeur `m2` est relié à `m1` et à `m3` par des **liaisons lentes** : un délai sur
chacune de ses deux interfaces, visible avec `tc qdisc show` sur `m2` (**ne modifiez pas cela**).

- **Au départ.** Chaque machine a ses adresses (`ip addr`) et un fichier `/etc/hosts` (`ping m3_x3`
résout le nom), mais **aucune route indirecte n'est configurée** et le routage est **désactivé** (`ip_forward = 0`).

""")
            + addressing
            + tr("""
**Revenir à l'état initial.** Par l'onglet *Appliquer une configuration*, vous pouvez remettre toutes les
machines dans leur état de départ : routes supprimées, routage désactivé, files d'attente retirées
puis délais de `m2` et de `x` remis en place, caches ARP vidés. Vos réponses sont conservées.

**Conseils.** Utilisez `-n` partout (pas de résolution inverse des noms) ; `ping -n -c 10 -i 0.2` et sa ligne
`rtt min/avg/max/mdev` (le premier écho, allongé par les résolutions ARP, fausse la moyenne : lisez
`min`) ; une capture `tcpdump` dans un second terminal de la machine observée. Les réponses sont en
**millisecondes** (virgule ou point), avec une tolérance de 10 % + 2 ms.

**Évaluation.** Chaque évaluation lit vos réponses, les routes et `ip_forward` de `gw`, `m1`, `m2` et
`m3`, lance depuis `m1` un `ping` vers `m3` à travers `x` et, depuis `gw`, un `ping -t 9` vers chaque
réseau fantôme : le paquet doit faire deux tours de l'anneau, puis `m1` répondre *time exceeded* à
`gw`. Votre configuration doit être en place au moment de l'évaluation.
""")
            + (tr("L'auto-évaluation note aussi vos trois réponses chiffrées : elle vous dit si une mesure est dans "
                  "la tolérance.\n")
               if latency_answers_in_self_eval else
               tr("L'auto-évaluation ne note pas vos trois réponses chiffrées : seule l'évaluation de l'enseignant "
                  "les prend en compte.\n"))
            + instructor(tr("""
**Pour l'enseignant.** Délais de `x` : **{a} ms** de m1 vers m3 (netem sur eth1 de `x`) et **{b} ms**
de m3 vers m1 (eth0) ; lien lent de `m2` : {local} ms par interface. Valeurs attendues : RTT de la
question 1 ≈ {total} ms ; période de la boucle 1 (`net1`) ≈ {period1} ms et de la boucle 2 (`net2`)
≈ {period2} ms ; RTT du `ping` local gw ↔ m3 par m2 ≈ {local_rtt} ms. Chaque question se termine
par sa solution pour ces valeurs ; l'état `final` (onglet *Appliquer une configuration*) applique
toute la solution et remplit les formulaires.
""").format(a=a, b=b, local=local, total=total, period1=period1, period2=period2, local_rtt=local_rtt)),
        )

        # =====================================================================
        # Partie 1 — Latence totale
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Latence totale à travers x"))
        q1_answers = {"rtt_total": _fmt(total)}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Latence totale à travers x"),
            description=tr("""
1. Sur `m1`, ajoutez une route vers le réseau `x3` (celui de `m3` du côté de `x`) par `x` ; sur
   `m3`, une route vers le réseau `x1` par `x`. Vérifiez chaque route avec `ip route get`.
2. Depuis `m1`, `ping -n -c 10 -i 0.2 m3_x3` : les échos traversent `x` à l'aller (m1 → x → m3) et
   au retour (m3 → x → m1). Relevez le RTT (`min` de la ligne `rtt min/avg/max/mdev` : le premier
   écho est allongé par les résolutions ARP, dont les réponses traversent aussi `x`).
3. Essayez `ping m3_x3` depuis `gw` : que manque-t-il pour que ce ping passe ? Et `ping x_x1` ou
   `ping x_x3` depuis `m1` : pourquoi n'y a-t-il pas de réponse ? (non noté)

- RTT de `m1` vers `m3` à travers `x` (`min`), en ms : @@{rtt_total:[0-9.,]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` : `ip route add {x3} via {x_x1}` ; sur `m3` : `ip route add {x1} via {x_x3}`.
`ping -n -c 10 -i 0.2 {m3_x3}` depuis `m1` donne un RTT minimal de **{total} ms** ({a} + {b}, plus
quelques dixièmes) ; le premier écho dure environ {first} ms, les réponses ARP de `x` traversant
aussi ses files. Le ping depuis `gw` demande une route par défaut sur `gw`, le routage activé sur
`m1` et une route retour vers `ext` sur `m3` (par `x` ou par `m2`) ; `x` ne répond à aucun ping
(table nftables `opaque`).

Évaluation : `route_m1_to_x3`, `route_m3_to_x1` (4 points chacune), `ping_through_x` (6 : un `ping`
de `m1` vers `m3_x3` lancé par l'évaluation reçoit des réponses et son RTT minimal vaut {total} ms à
10 % + 2 ms près : les deux routes passent par `x`) et `answer_rtt_total` (16 : réponse `{total}`
à la même tolérance).
""").format(x1=d.nets.x1, x3=d.nets.x3, x_x1=addr('x', 'x1').ip, x_x3=addr('x', 'x3').ip, m3_x3=m3_x3,
            a=a, b=b, total=total, first=2 * total)),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("route_m1_to_x3"), max_grade=4, grade_part=part1,
            grade=4 * int(q1_ok['m1']),
            description=tr("route de m1 vers le réseau x3 par x"),
        )
        self.add_grade_element(
            title=no_tr("route_m3_to_x1"), max_grade=4, grade_part=part1,
            grade=4 * int(q1_ok['m3']),
            description=tr("route de m3 vers le réseau x1 par x"),
        )
        self.add_grade_element(
            title=no_tr("ping_through_x"), max_grade=6, grade_part=part1,
            grade=6 * int(ping_ok),
            description=tr("un ping de m1 vers m3 traverse x à l'aller et au retour (RTT attendu)"),
        )
        self.add_grade_element(
            title=no_tr("answer_rtt_total"), max_grade=16, grade_part=part1, scope=answer_scope,
            grade=16 * int(_approx(q1.get("rtt_total"), total)),
            description=tr("latence totale à travers x (RTT m1 → m3)"),
        )

        # =====================================================================
        # Partie 2 — Latence de chaque sens
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Latence de x dans chaque sens"))
        q2_answers = {"delay_m1_to_m3": _fmt(a), "delay_m3_to_m1": _fmt(b)}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Latence de x dans chaque sens"),
            description=tr("""
La méthode est décrite dans l'onglet **Informations**, section @@ref:ring@@ (les captures : section
@@ref:capture@@). Les réseaux fantômes `net1` et `net2` du plan d'adressage n'appartiennent à
personne ; `x` route `net1` vers `m3` et `net2` vers `m1`.

1. Activez le routage sur `m1`, `m2` et `m3` (`sysctl -w net.ipv4.ip_forward=1`), donnez à `gw`
   une route par défaut par `m1`, et aux routeurs une route retour vers `ext` qui évite `x` : sur
   `m2` par `m1`, sur `m3` par `m2` (ils pourront ainsi répondre à `gw`).
2. **Boucle 1** (sens m1 → x → m3). Routez `net1` en cercle : sur `m1` par `x`, sur `m3` par `m2`,
   sur `m2` par `m1`.
3. Sur `m1`, lancez `tcpdump -n -i eth1 -ttt icmp` (`eth1` : vers `x`) ; depuis `gw`,
   `ping -n -c 1 -W 5 ADRESSE` vers une adresse quelconque de `net1`. Le paquet fait seize tours
   (TTL 64, quatre routeurs par tour) : la capture montre un passage par tour et l'intervalle entre
   deux passages est la **période** de la boucle. Relevez-la en ignorant le premier intervalle (les
   résolutions ARP) ; après le seizième passage, `m2` jette le paquet et `gw` reçoit son
   *time exceeded*.
4. **Boucle 2** (sens m3 → x → m1). Routez `net2` dans l'autre sens : sur `m1` par `m2`, sur `m2`
   par `m3`, sur `m3` par `x`. Même mesure depuis `gw` vers une adresse de `net2` : sur `m1` le
   paquet sort alors par `eth2` et revient par `eth1` (quinze passages : `x` jette le paquet au
   seizième tour, sans rien dire).
5. **Délais locaux.** Sur `m1`, routez le réseau `l23` par `m2` : le chemin gw → m1 → m2 → m3 évite
   `x` dans les deux sens. Depuis `gw`, `ping -n -c 10 -i 0.2 m3_l23` suit ce chemin à l'aller et
   au retour : le délai d'un sens est la moitié du RTT moyen.
6. Calculez les deux latences de `x` (période − RTT local / 2) et vérifiez que leur somme retrouve
   la latence totale de la question 1. Laissez toutes les routes en place : l'évaluation fait
   tourner les deux boucles.

- Latence de `x` dans le sens m1 → x → m3, en ms : @@{delay_m1_to_m3:[0-9.,]+}@@
- Latence de `x` dans le sens m3 → x → m1, en ms : @@{delay_m3_to_m1:[0-9.,]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1`, `m2` et `m3` : `sysctl -w net.ipv4.ip_forward=1` ; sur `gw` :
`ip route add default via {m1_ext}` ; routes retour : sur `m2`, `ip route add {ext} via {m1_l12}` ;
sur `m3`, `ip route add {ext} via {m2_l23}`.

Boucle 1 (`net1` = `{net1}`) : sur `m1`, `ip route add {net1} via {x_x1}` ; sur `m3`,
`ip route add {net1} via {m2_l23}` ; sur `m2`, `ip route add {net1} via {m1_l12}`.
Boucle 2 (`net2` = `{net2}`) : sur `m1`, `ip route add {net2} via {m2_l12}` ; sur `m2`,
`ip route add {net2} via {m3_l23}` ; sur `m3`, `ip route add {net2} via {x_x3}`.
Chemin local : sur `m1`, `ip route add {l23} via {m2_l12}`.

Mesures attendues : période de la boucle 1 ≈ **{period1} ms** ({a} + {local}), de la boucle 2 ≈
**{period2} ms** ({b} + {local}) ; `ping -n -c 10 -i 0.2 {m3_l23}` depuis `gw` : RTT ≈ {local_rtt} ms
(2 × {local}). D'où A = {period1} − {local} = **{a} ms** (m1 → x → m3) et B = {period2} − {local} =
**{b} ms** (m3 → x → m1) ; A + B = {total} ms, le RTT de la question 1. Une réponse sans la correction
({period1} ou {period2}) est hors tolérance.

Évaluation : `ip_forward_m1`, `_m2`, `_m3` (2 points chacun), `route_gw_via_m1` (4 : route par défaut,
ou `net1` et `net2`, par `m1`), `ring1_routes` et `ring2_routes` (6 chacune, 2 par route),
`ring1_loop` et `ring2_loop` (6 chacune : `ping -t 9` depuis `gw` vers `{target1}` / `{target2}`, deux
tours puis *time exceeded* émis par `m1`, `{m1_ext}`), `answer_delay_m1_to_m3` et `answer_delay_m3_to_m1`
(18 chacune, 10 % + 2 ms de tolérance).
""").format(net1=net1, net2=net2, ext=d.nets.ext, l23=d.nets.l23, m1_ext=addr('m1', 'ext').ip,
            m1_l12=addr('m1', 'l12').ip, m2_l12=addr('m2', 'l12').ip, m2_l23=addr('m2', 'l23').ip,
            m3_l23=addr('m3', 'l23').ip, x_x1=addr('x', 'x1').ip, x_x3=addr('x', 'x3').ip,
            a=a, b=b, local=local, total=total, period1=period1, period2=period2, local_rtt=local_rtt,
            target1=target1, target2=target2)),
            cheat_answers={"final": q2_answers},
        )
        for m in RING_MACHINES:
            self.add_grade_element(
                title=no_tr(f"ip_forward_{m}"), max_grade=2, grade_part=part2,
                grade=2 * int(forward[m]),
                description=tr("routage activé sur {m}").format(m=m),
            )
        self.add_grade_element(
            title=no_tr("route_gw_via_m1"), max_grade=4, grade_part=part2,
            grade=4 * int(gw_ok),
            description=tr("route de gw par m1 (par défaut, ou vers net1 et net2)"),
        )
        self.add_grade_element(
            title=no_tr("ring1_routes"), max_grade=6, grade_part=part2,
            grade=2 * sum(int(ok) for ok in ring1_ok.values()),
            description=tr("boucle 1 : net1 routé par x sur m1, par m2 sur m3, par m1 sur m2"),
        )
        self.add_grade_element(
            title=no_tr("ring1_loop"), max_grade=6, grade_part=part2,
            grade=6 * int(loop1_ok),
            description=tr("boucle 1 : un paquet de gw vers net1 fait deux tours (ping -t 9, time exceeded de m1)"),
        )
        self.add_grade_element(
            title=no_tr("ring2_routes"), max_grade=6, grade_part=part2,
            grade=2 * sum(int(ok) for ok in ring2_ok.values()),
            description=tr("boucle 2 : net2 routé par m2 sur m1, par m3 sur m2, par x sur m3"),
        )
        self.add_grade_element(
            title=no_tr("ring2_loop"), max_grade=6, grade_part=part2,
            grade=6 * int(loop2_ok),
            description=tr("boucle 2 : un paquet de gw vers net2 fait deux tours (ping -t 9, time exceeded de m1)"),
        )
        self.add_grade_element(
            title=no_tr("answer_delay_m1_to_m3"), max_grade=18, grade_part=part2, scope=answer_scope,
            grade=18 * int(_approx(q2.get("delay_m1_to_m3"), a)),
            description=tr("latence de x dans le sens m1 → x → m3"),
        )
        self.add_grade_element(
            title=no_tr("answer_delay_m3_to_m1"), max_grade=18, grade_part=part2, scope=answer_scope,
            grade=18 * int(_approx(q2.get("delay_m3_to_m1"), b)),
            description=tr("latence de x dans le sens m3 → x → m1"),
        )


_TRANSLATIONS = {
    'en': {
        """
### @@sec@@ Le principe

On choisit un **réseau fantôme**, un préfixe que personne ne possède, et on le route **en cercle** :
chaque routeur de l'anneau envoie ce réseau au routeur suivant. Un paquet destiné à ce réseau,
injecté dans l'anneau depuis l'extérieur, fait le tour, revient au premier routeur, qui le renvoie…
jusqu'à l'expiration de son TTL : le routeur qui reçoit un TTL de 1 le jette et renvoie *time
exceeded* à l'émetteur, s'il a une route vers lui. Sur une machine de l'anneau, une capture montre le
paquet **à chaque tour** : l'intervalle entre deux passages est la **période** de la boucle, la somme
des délais de tous les liens et routeurs de l'anneau **dans le sens de la boucle**. Le même paquet,
la même horloge : aucune synchronisation n'est nécessaire.

Si un seul tronçon de l'anneau est lent dans ce sens, la période vaut son délai plus les petits
délais des autres tronçons. En routant un **second** réseau fantôme en cercle **dans l'autre sens**,
on mesure de la même façon le délai du tronçon dans l'autre sens.

### @@sec@@ Le calcul

Soit A le délai du tronçon lent dans le sens de la première boucle et B dans le sens de la seconde :

- période de la boucle 1 = A + (délais des autres tronçons, dans le sens 1) ;
- période de la boucle 2 = B + (délais des autres tronçons, dans le sens 2).

Les autres tronçons s'estiment avec un `ping` qui emprunte **seulement** ces tronçons, sans le
tronçon lent : son RTT est deux fois le chemin local, donc **délai local ≈ RTT local / 2**. D'où
A ≈ période 1 − RTT local / 2 et B ≈ période 2 − RTT local / 2. Vérification : A + B doit retrouver
le RTT d'un `ping` qui traverse le tronçon lent à l'aller **et** au retour.

### @@sec@@ Les pièges

- Le paquet doit être injecté **depuis l'extérieur** de l'anneau. Linux jette un paquet à router
  dont l'adresse source est l'une de ses propres adresses (*martian source*, paramètre
  `net.ipv4.conf.all.accept_local = 0`) : un `ping` lancé depuis un routeur de l'anneau disparaît dès
  son premier retour sur ce routeur.
- Le **premier tour** est plus long : une résolution ARP à chaque saut. Mesurez à partir du
  deuxième passage, ou lancez un second `ping`.
- Chaque routeur de l'anneau doit avoir le **routage activé** (`ip_forward`) et une route vers le
  réseau fantôme **vers le routeur suivant**. Une route manquante arrête le paquet : *Destination
  unreachable*, ou rien du tout.
- Le TTL limite le nombre de tours : 64 au départ et quatre routeurs par tour font 16 tours ;
  `ping -t` en fait moins. Le routeur qui reçoit un TTL de 1 ne répond *time exceeded* que s'il a une
  route vers l'émetteur, et s'il n'est pas muet.
- Le `ping` local de la correction doit suivre exactement les tronçons locaux de l'anneau et aucun
  autre : vérifiez son chemin (`ip route get`, `traceroute -n`).
""": """
### @@sec@@ The principle

One picks a **phantom network**, a prefix nobody owns, and routes it **in a circle**: every router of
the ring sends that network to the next router. A packet for that network, injected into the ring
from outside, goes round, comes back to the first router, which forwards it again… until its TTL
expires: the router that receives a TTL of 1 drops it and sends *time exceeded* back to the sender,
if it has a route to it. On a machine of the ring, a capture shows the packet **at every turn**: the
interval between two passages is the **period** of the ring, the sum of the delays of all the links
and routers of the ring **in the direction of the ring**. The same packet, the same clock: no
synchronisation is needed.

If a single section of the ring is slow in that direction, the period is its delay plus the small
delays of the other sections. By routing a **second** phantom network in a circle **the other way
round**, one measures in the same way the delay of the section in the other direction.

### @@sec@@ The computation

Let A be the delay of the slow section in the direction of the first ring and B in the direction of
the second:

- period of ring 1 = A + (delays of the other sections, in direction 1);
- period of ring 2 = B + (delays of the other sections, in direction 2).

The other sections are estimated with a `ping` that goes through these sections **only**, without
the slow one: its RTT is twice the local path, so **local delay ≈ local RTT / 2**. Hence
A ≈ period 1 − local RTT / 2 and B ≈ period 2 − local RTT / 2. Check: A + B must give back the RTT
of a `ping` crossing the slow section on the way out **and** on the way back.

### @@sec@@ The pitfalls

- The packet must be injected **from outside** the ring. Linux drops a packet to forward whose
  source address is one of its own addresses (*martian source*, parameter
  `net.ipv4.conf.all.accept_local = 0`): a `ping` run from a router of the ring vanishes on its first
  return to that router.
- The **first turn** is longer: an ARP resolution at every hop. Measure from the second passage on,
  or run a second `ping`.
- Every router of the ring must have **forwarding on** (`ip_forward`) and a route to the phantom
  network **towards the next router**. A missing route stops the packet: *Destination unreachable*,
  or nothing at all.
- The TTL limits the number of turns: 64 at the start and four routers per turn make 16 turns;
  `ping -t` makes fewer. The router that receives a TTL of 1 answers *time exceeded* only if it has
  a route to the sender, and if it is not silent.
- The local `ping` of the correction must follow exactly the local sections of the ring and no
  other: check its path (`ip route get`, `traceroute -n`).
""",
        """
**Pour l'enseignant.** Délais de `x` : **{a} ms** de m1 vers m3 (netem sur eth1 de `x`) et **{b} ms**
de m3 vers m1 (eth0) ; lien lent de `m2` : {local} ms par interface. Valeurs attendues : RTT de la
question 1 ≈ {total} ms ; période de la boucle 1 (`net1`) ≈ {period1} ms et de la boucle 2 (`net2`)
≈ {period2} ms ; RTT du `ping` local gw ↔ m3 par m2 ≈ {local_rtt} ms. Chaque question se termine
par sa solution pour ces valeurs ; l'état `final` (onglet *Appliquer une configuration*) applique
toute la solution et remplit les formulaires.
""": """
**For the instructor.** Delays of `x`: **{a} ms** from m1 to m3 (netem on eth1 of `x`) and **{b} ms**
from m3 to m1 (eth0); slow link of `m2`: {local} ms per interface. Expected values: RTT of question 1
≈ {total} ms; period of ring 1 (`net1`) ≈ {period1} ms and of ring 2 (`net2`) ≈ {period2} ms; RTT of the
local `ping` gw ↔ m3 through m2 ≈ {local_rtt} ms. Every question ends with its solution for these
values; the `final` state (*Apply Configuration* tab) applies the whole solution and fills in the forms.
""",
        """
**Revenir à l'état initial.** Par l'onglet *Appliquer une configuration*, vous pouvez remettre toutes les
machines dans leur état de départ : routes supprimées, routage désactivé, files d'attente retirées
puis délais de `m2` et de `x` remis en place, caches ARP vidés. Vos réponses sont conservées.

**Conseils.** Utilisez `-n` partout (pas de résolution inverse des noms) ; `ping -n -c 10 -i 0.2` et sa ligne
`rtt min/avg/max/mdev` (le premier écho, allongé par les résolutions ARP, fausse la moyenne : lisez
`min`) ; une capture `tcpdump` dans un second terminal de la machine observée. Les réponses sont en
**millisecondes** (virgule ou point), avec une tolérance de 10 % + 2 ms.

**Évaluation.** Chaque évaluation lit vos réponses, les routes et `ip_forward` de `gw`, `m1`, `m2` et
`m3`, lance depuis `m1` un `ping` vers `m3` à travers `x` et, depuis `gw`, un `ping -t 9` vers chaque
réseau fantôme : le paquet doit faire deux tours de l'anneau, puis `m1` répondre *time exceeded* à
`gw`. Votre configuration doit être en place au moment de l'évaluation.
""": """
**Back to the initial state.** Through the *Apply Configuration* tab, you can put every machine back
in its starting state: routes removed, forwarding off, queues removed then the delays of `m2` and
`x` set up again, ARP caches emptied. Your answers are kept.

**Advice.** Use `-n` everywhere (no reverse name resolution); `ping -n -c 10 -i 0.2` and its line
`rtt min/avg/max/mdev` (the first echo, lengthened by the ARP resolutions, spoils the average: read
`min`); a `tcpdump` capture in a second terminal of the machine observed. The answers are in
**milliseconds** (comma or point), with a tolerance of 10 % + 2 ms.

**Evaluation.** Every evaluation reads your answers, the routes and `ip_forward` of `gw`, `m1`, `m2`
and `m3`, runs from `m1` a `ping` towards `m3` through `x` and, from `gw`, a `ping -t 9` towards
each phantom network: the packet must go twice round the ring, then `m1` answer *time exceeded* to
`gw`. Your configuration must be in place at the time of the evaluation.
""",
        """
**Solution.** Sur `m1` : `ip route add {x3} via {x_x1}` ; sur `m3` : `ip route add {x1} via {x_x3}`.
`ping -n -c 10 -i 0.2 {m3_x3}` depuis `m1` donne un RTT minimal de **{total} ms** ({a} + {b}, plus
quelques dixièmes) ; le premier écho dure environ {first} ms, les réponses ARP de `x` traversant
aussi ses files. Le ping depuis `gw` demande une route par défaut sur `gw`, le routage activé sur
`m1` et une route retour vers `ext` sur `m3` (par `x` ou par `m2`) ; `x` ne répond à aucun ping
(table nftables `opaque`).

Évaluation : `route_m1_to_x3`, `route_m3_to_x1` (4 points chacune), `ping_through_x` (6 : un `ping`
de `m1` vers `m3_x3` lancé par l'évaluation reçoit des réponses et son RTT minimal vaut {total} ms à
10 % + 2 ms près : les deux routes passent par `x`) et `answer_rtt_total` (16 : réponse `{total}`
à la même tolérance).
""": """
**Solution.** On `m1`: `ip route add {x3} via {x_x1}`; on `m3`: `ip route add {x1} via {x_x3}`.
`ping -n -c 10 -i 0.2 {m3_x3}` from `m1` gives a minimum RTT of **{total} ms** ({a} + {b}, plus a few
tenths); the first echo takes about {first} ms, the ARP replies of `x` crossing its queues too. The ping
from `gw` needs a default route on `gw`, forwarding on `m1` and a return route towards
`ext` on `m3` (via `x` or via `m2`); `x` answers no ping at all (nftables table `opaque`).

Grading: `route_m1_to_x3`, `route_m3_to_x1` (4 points each), `ping_through_x` (6: a `ping` from `m1`
towards `m3_x3` run by the evaluation gets replies and its minimum RTT is {total} ms within 10 % + 2 ms:
both routes go through `x`) and `answer_rtt_total` (16: the answer `{total}` within the same tolerance).
""",
        """
**Solution.** Sur `m1`, `m2` et `m3` : `sysctl -w net.ipv4.ip_forward=1` ; sur `gw` :
`ip route add default via {m1_ext}` ; routes retour : sur `m2`, `ip route add {ext} via {m1_l12}` ;
sur `m3`, `ip route add {ext} via {m2_l23}`.

Boucle 1 (`net1` = `{net1}`) : sur `m1`, `ip route add {net1} via {x_x1}` ; sur `m3`,
`ip route add {net1} via {m2_l23}` ; sur `m2`, `ip route add {net1} via {m1_l12}`.
Boucle 2 (`net2` = `{net2}`) : sur `m1`, `ip route add {net2} via {m2_l12}` ; sur `m2`,
`ip route add {net2} via {m3_l23}` ; sur `m3`, `ip route add {net2} via {x_x3}`.
Chemin local : sur `m1`, `ip route add {l23} via {m2_l12}`.

Mesures attendues : période de la boucle 1 ≈ **{period1} ms** ({a} + {local}), de la boucle 2 ≈
**{period2} ms** ({b} + {local}) ; `ping -n -c 10 -i 0.2 {m3_l23}` depuis `gw` : RTT ≈ {local_rtt} ms
(2 × {local}). D'où A = {period1} − {local} = **{a} ms** (m1 → x → m3) et B = {period2} − {local} =
**{b} ms** (m3 → x → m1) ; A + B = {total} ms, le RTT de la question 1. Une réponse sans la correction
({period1} ou {period2}) est hors tolérance.

Évaluation : `ip_forward_m1`, `_m2`, `_m3` (2 points chacun), `route_gw_via_m1` (4 : route par défaut,
ou `net1` et `net2`, par `m1`), `ring1_routes` et `ring2_routes` (6 chacune, 2 par route),
`ring1_loop` et `ring2_loop` (6 chacune : `ping -t 9` depuis `gw` vers `{target1}` / `{target2}`, deux
tours puis *time exceeded* émis par `m1`, `{m1_ext}`), `answer_delay_m1_to_m3` et `answer_delay_m3_to_m1`
(18 chacune, 10 % + 2 ms de tolérance).
""": """
**Solution.** On `m1`, `m2` and `m3`: `sysctl -w net.ipv4.ip_forward=1`; on `gw`:
`ip route add default via {m1_ext}`; return routes: on `m2`, `ip route add {ext} via {m1_l12}`;
on `m3`, `ip route add {ext} via {m2_l23}`.

Ring 1 (`net1` = `{net1}`): on `m1`, `ip route add {net1} via {x_x1}`; on `m3`,
`ip route add {net1} via {m2_l23}`; on `m2`, `ip route add {net1} via {m1_l12}`.
Ring 2 (`net2` = `{net2}`): on `m1`, `ip route add {net2} via {m2_l12}`; on `m2`,
`ip route add {net2} via {m3_l23}`; on `m3`, `ip route add {net2} via {x_x3}`.
Local path: on `m1`, `ip route add {l23} via {m2_l12}`.

Expected measurements: period of ring 1 ≈ **{period1} ms** ({a} + {local}), of ring 2 ≈
**{period2} ms** ({b} + {local}); `ping -n -c 10 -i 0.2 {m3_l23}` from `gw`: RTT ≈ {local_rtt} ms
(2 × {local}). Hence A = {period1} − {local} = **{a} ms** (m1 → x → m3) and B = {period2} − {local} =
**{b} ms** (m3 → x → m1); A + B = {total} ms, the RTT of question 1. An answer without the correction
({period1} or {period2}) is out of tolerance.

Grading: `ip_forward_m1`, `_m2`, `_m3` (2 points each), `route_gw_via_m1` (4: a default route, or
`net1` and `net2`, via `m1`), `ring1_routes` and `ring2_routes` (6 each, 2 per route), `ring1_loop` and
`ring2_loop` (6 each: `ping -t 9` from `gw` towards `{target1}` / `{target2}`, two turns then *time
exceeded* sent by `m1`, `{m1_ext}`), `answer_delay_m1_to_m3` and `answer_delay_m3_to_m1` (18 each,
10 % + 2 ms of tolerance).
""",
        """
**Sommaire**
""": """
**Contents**
""",
        """
1. Sur `m1`, ajoutez une route vers le réseau `x3` (celui de `m3` du côté de `x`) par `x` ; sur
   `m3`, une route vers le réseau `x1` par `x`. Vérifiez chaque route avec `ip route get`.
2. Depuis `m1`, `ping -n -c 10 -i 0.2 m3_x3` : les échos traversent `x` à l'aller (m1 → x → m3) et
   au retour (m3 → x → m1). Relevez le RTT (`min` de la ligne `rtt min/avg/max/mdev` : le premier
   écho est allongé par les résolutions ARP, dont les réponses traversent aussi `x`).
3. Essayez `ping m3_x3` depuis `gw` : que manque-t-il pour que ce ping passe ? Et `ping x_x1` ou
   `ping x_x3` depuis `m1` : pourquoi n'y a-t-il pas de réponse ? (non noté)

- RTT de `m1` vers `m3` à travers `x` (`min`), en ms : @@{rtt_total:[0-9.,]+}@@
""": """
1. On `m1`, add a route to the network `x3` (the one of `m3` on the side of `x`) via `x`; on `m3`,
   a route to the network `x1` via `x`. Check each route with `ip route get`.
2. From `m1`, `ping -n -c 10 -i 0.2 m3_x3`: the echoes cross `x` on the way out (m1 → x → m3) and
   on the way back (m3 → x → m1). Note the RTT (`min` of the line `rtt min/avg/max/mdev`: the first
   echo is lengthened by the ARP resolutions, whose replies cross `x` too).
3. Try `ping m3_x3` from `gw`: what is missing for this ping to get through? And `ping x_x1` or
   `ping x_x3` from `m1`: why is there no reply? (not graded)

- RTT from `m1` to `m3` through `x` (`min`), in ms: @@{rtt_total:[0-9.,]+}@@
""",
        """
La **latence** d'un chemin est le temps que met un paquet pour aller de l'émetteur au destinataire :
le **délai aller simple** (*one-way delay*). Il additionne, lien par lien, le temps de **propagation**
(la vitesse du signal : environ 200 000 km/s dans une fibre, soit 5 µs par km), le temps
d'**émission** (taille du paquet divisée par le débit : 12 µs pour 1500 octets à 1 Gbit/s) et, dans
chaque équipement traversé, le temps de traitement et surtout le temps d'**attente en file** quand le
lien de sortie est occupé. La variation de ce délai d'un paquet à l'autre est la **gigue** (*jitter*).
Ordres de grandeur : moins d'une milliseconde dans un réseau local, 10 à 30 ms entre deux villes
d'Europe, 80 à 100 ms pour traverser l'Atlantique, 250 ms d'aller simple par un satellite
géostationnaire (36 000 km d'altitude).

Le **RTT** (*round-trip time*, temps aller-retour) est ce que mesure `ping` : délai aller, temps de
réponse du destinataire et délai retour. Rien n'oblige les deux sens à être égaux
(section @@ref:oneway@@).

Latence et **débit** sont deux grandeurs indépendantes : un lien peut avoir un gros débit et une
grande latence (un satellite à 100 Mbit/s et 500 ms de RTT). Les protocoles faits d'allers-retours
(l'ouverture d'une connexion TCP, une requête DNS, une page web et ses dizaines de requêtes) souffrent
de la latence quel que soit le débit : c'est pourquoi on la mesure.
""": """
The **latency** of a path is the time a packet takes to go from the sender to the receiver: the
**one-way delay**. It adds up, link by link, the **propagation** time (the speed of the signal: about
200 000 km/s in a fibre, i.e. 5 µs per km), the **transmission** time (the size of the packet divided
by the bit rate: 12 µs for 1500 bytes at 1 Gbit/s) and, in every device crossed, the processing time
and above all the **queueing** time when the outgoing link is busy. The variation of this delay from
one packet to the next is the **jitter**. Orders of magnitude: less than a millisecond on a local
network, 10 to 30 ms between two European cities, 80 to 100 ms across the Atlantic, 250 ms one way
through a geostationary satellite (36 000 km high).

The **RTT** (*round-trip time*) is what `ping` measures: the forward delay, the response time of the
receiver and the return delay. Nothing forces the two directions to be equal
(section @@ref:oneway@@).

Latency and **bandwidth** are two independent quantities: a link may have a high bit rate and a high
latency (a satellite at 100 Mbit/s with a 500 ms RTT). The protocols made of round trips (the opening
of a TCP connection, a DNS query, a web page and its dozens of requests) suffer from the latency
whatever the bit rate: that is why it is measured.
""",
        """
La méthode est décrite dans l'onglet **Informations**, section @@ref:ring@@ (les captures : section
@@ref:capture@@). Les réseaux fantômes `net1` et `net2` du plan d'adressage n'appartiennent à
personne ; `x` route `net1` vers `m3` et `net2` vers `m1`.

1. Activez le routage sur `m1`, `m2` et `m3` (`sysctl -w net.ipv4.ip_forward=1`), donnez à `gw`
   une route par défaut par `m1`, et aux routeurs une route retour vers `ext` qui évite `x` : sur
   `m2` par `m1`, sur `m3` par `m2` (ils pourront ainsi répondre à `gw`).
2. **Boucle 1** (sens m1 → x → m3). Routez `net1` en cercle : sur `m1` par `x`, sur `m3` par `m2`,
   sur `m2` par `m1`.
3. Sur `m1`, lancez `tcpdump -n -i eth1 -ttt icmp` (`eth1` : vers `x`) ; depuis `gw`,
   `ping -n -c 1 -W 5 ADRESSE` vers une adresse quelconque de `net1`. Le paquet fait seize tours
   (TTL 64, quatre routeurs par tour) : la capture montre un passage par tour et l'intervalle entre
   deux passages est la **période** de la boucle. Relevez-la en ignorant le premier intervalle (les
   résolutions ARP) ; après le seizième passage, `m2` jette le paquet et `gw` reçoit son
   *time exceeded*.
4. **Boucle 2** (sens m3 → x → m1). Routez `net2` dans l'autre sens : sur `m1` par `m2`, sur `m2`
   par `m3`, sur `m3` par `x`. Même mesure depuis `gw` vers une adresse de `net2` : sur `m1` le
   paquet sort alors par `eth2` et revient par `eth1` (quinze passages : `x` jette le paquet au
   seizième tour, sans rien dire).
5. **Délais locaux.** Sur `m1`, routez le réseau `l23` par `m2` : le chemin gw → m1 → m2 → m3 évite
   `x` dans les deux sens. Depuis `gw`, `ping -n -c 10 -i 0.2 m3_l23` suit ce chemin à l'aller et
   au retour : le délai d'un sens est la moitié du RTT moyen.
6. Calculez les deux latences de `x` (période − RTT local / 2) et vérifiez que leur somme retrouve
   la latence totale de la question 1. Laissez toutes les routes en place : l'évaluation fait
   tourner les deux boucles.

- Latence de `x` dans le sens m1 → x → m3, en ms : @@{delay_m1_to_m3:[0-9.,]+}@@
- Latence de `x` dans le sens m3 → x → m1, en ms : @@{delay_m3_to_m1:[0-9.,]+}@@
""": """
The method is described in the **Informations** tab, section @@ref:ring@@ (the captures: section
@@ref:capture@@). The phantom networks `net1` and `net2` of the addressing plan belong to nobody;
`x` routes `net1` towards `m3` and `net2` towards `m1`.

1. Turn forwarding on in `m1`, `m2` and `m3` (`sysctl -w net.ipv4.ip_forward=1`), give `gw` a
   default route via `m1`, and the routers a return route towards `ext` that avoids `x`: on `m2`
   via `m1`, on `m3` via `m2` (so that they can answer `gw`).
2. **Ring 1** (direction m1 → x → m3). Route `net1` in a circle: on `m1` via `x`, on `m3` via `m2`,
   on `m2` via `m1`.
3. On `m1`, run `tcpdump -n -i eth1 -ttt icmp` (`eth1`: towards `x`); from `gw`,
   `ping -n -c 1 -W 5 ADDRESS` towards any address of `net1`. The packet goes round sixteen times
   (TTL 64, four routers per turn): the capture shows one passage per turn and the interval between
   two passages is the **period** of the ring. Note it down, ignoring the first interval (the ARP
   resolutions); after the sixteenth passage, `m2` drops the packet and `gw` receives its
   *time exceeded*.
4. **Ring 2** (direction m3 → x → m1). Route `net2` the other way round: on `m1` via `m2`, on `m2`
   via `m3`, on `m3` via `x`. Same measurement from `gw` towards an address of `net2`: on `m1` the
   packet then goes out by `eth2` and comes back by `eth1` (fifteen passages: `x` drops the packet
   on the sixteenth turn, without a word).
5. **Local delays.** On `m1`, route the network `l23` via `m2`: the path gw → m1 → m2 → m3 avoids
   `x` in both directions. From `gw`, `ping -n -c 10 -i 0.2 m3_l23` follows this path on the way
   out and on the way back: the delay of one direction is half the average RTT.
6. Compute the two latencies of `x` (period − local RTT / 2) and check that their sum gives back
   the total latency of question 1. Leave every route in place: the evaluation runs the two rings.

- Latency of `x` in the direction m1 → x → m3, in ms: @@{delay_m1_to_m3:[0-9.,]+}@@
- Latency of `x` in the direction m3 → x → m1, in ms: @@{delay_m3_to_m1:[0-9.,]+}@@
""",
        """
Lisez l'onglet **Informations** : il présente la latence et le RTT, la mesure avec `ping`, la
méthode de la boucle, les captures et les commandes de routage utiles.

**Le réseau.** 

- `x` est le **réseau d'un
opérateur** (une étoile dans le schéma, **sans terminal**) : il route les paquets entre `m1` et `m3`
avec une **latence inconnue, différente dans chaque sens** (m1 → x → m3 et m3 → x → m1), que vous
allez mesurer. Il n'émet aucun message ICMP : il ne répond pas à `ping` et ne signale pas les TTL
expirés. 

Le routage est activé sur `x` et cette machine route `ext` et `l12` par `m1`, `l23`
par `m3`, le réseau fantôme `net1` par `m3` et le réseau fantôme `net2` par `m1`. Ces deux derniers
préfixes n'existent nulle part : ils servent à la question 2.

- Le routeur `m2` est relié à `m1` et à `m3` par des **liaisons lentes** : un délai sur
chacune de ses deux interfaces, visible avec `tc qdisc show` sur `m2` (**ne modifiez pas cela**).

- **Au départ.** Chaque machine a ses adresses (`ip addr`) et un fichier `/etc/hosts` (`ping m3_x3`
résout le nom), mais **aucune route indirecte n'est configurée** et le routage est **désactivé** (`ip_forward = 0`).

""": """
Read the **Informations** tab: it presents latency and RTT, the measurement with `ping`, the ring
method, the captures and the useful routing commands.

**The network.**

- `x` is the **network of an operator** (a star in the schema, **no terminal**): it forwards the
packets between `m1` and `m3` with an **unknown latency, different in each direction** (m1 → x → m3
and m3 → x → m1), which you are going to measure. It sends no ICMP message: it does not answer
`ping` and does not report the expired TTLs.

Forwarding is on in `x` and that machine routes `ext` and `l12` via `m1`, `l23` via `m3`, the
phantom network `net1` via `m3` and the phantom network `net2` via `m1`. These last two prefixes
exist nowhere: they are used in question 2.

- The router `m2` is linked to `m1` and to `m3` by **slow links**: a delay on each of its two
interfaces, visible with `tc qdisc show` on `m2` (**do not change that**).

- **At the start.** Every machine has its addresses (`ip addr`) and an `/etc/hosts` file (`ping m3_x3`
resolves the name), but **no indirect route is configured** and forwarding is **off** (`ip_forward = 0`).

""",
        """
Mesurer un délai aller simple, c'est comparer l'heure d'émission, lue sur l'horloge de l'émetteur, à
l'heure de réception, lue sur celle du destinataire : il faut deux horloges **synchronisées** bien
mieux que le délai à mesurer. NTP donne quelques millisecondes à travers Internet, PTP (IEEE 1588)
la microseconde sur un réseau local équipé pour cela ; c'est ainsi que travaillent les sondes de
mesure des opérateurs (OWAMP, RFC 4656). Sans cela, un `ping` ne donne que la **somme** des deux sens.

Or les deux sens diffèrent souvent : chemins aller et retour différents (le routage d'Internet est
largement asymétrique), liaisons dissymétriques (ADSL, satellite avec voie de retour terrestre), file
d'attente pleine dans un sens seulement. La méthode de ce TP contourne le problème sans horloge
distante : elle fait **repasser le même paquet par le même point de mesure**, où une seule horloge
suffit.
""": """
Measuring a one-way delay means comparing the sending time, read on the sender's clock, with the
receiving time, read on the receiver's: it takes two clocks **synchronised** far better than the
delay to measure. NTP gives a few milliseconds across the Internet, PTP (IEEE 1588) the microsecond
on a local network equipped for it; this is how the measurement probes of the operators work (OWAMP,
RFC 4656). Without that, a `ping` only gives the **sum** of the two directions.

Yet the two directions often differ: different forward and return paths (the routing of the Internet
is largely asymmetric), asymmetric links (ADSL, a satellite with a terrestrial return channel), a
queue full in one direction only. The method of this lab gets round the problem without any remote
clock: it makes **the same packet go through the same measuring point again**, where a single clock
is enough.
""",
        """
```
ip route                                   # la table : une route "proto kernel" par interface (réseaux directement connectés)
ip route add RÉSEAU/PRÉFIXE via PROCHAIN_SAUT    # route statique ("replace" pour la remplacer, "del" pour la retirer)
ip route add default via PROCHAIN_SAUT     # la route par défaut (0.0.0.0/0)
ip route get ADRESSE                       # la route que cette machine utiliserait pour ADRESSE
sysctl -w net.ipv4.ip_forward=1            # activer le routage (relais des paquets reçus pour d'autres) ; 0 : simple hôte
cat /proc/sys/net/ipv4/ip_forward          # lire la valeur en cours
traceroute -n -q 1 -w 1 -m 8 DEST          # les routeurs du chemin aller (un routeur muet donne "*")
tc qdisc show                              # les files d'émission des interfaces (un "netem delay" est un lien lent)
```

Le prochain saut d'une route statique doit être une adresse d'un réseau **directement connecté** à
la machine. Une machine sans route par défaut ne joint que ses propres réseaux ; une machine qui
reçoit un paquet pour un autre réseau le jette tant que `ip_forward` vaut 0, même si elle a la
route. Les routes de ce TP sont volatiles : elles disparaissent au redémarrage d'un conteneur, ce
qui n'arrive pas ici.
""": """
```
ip route                                   # the table: one "proto kernel" route per interface (directly connected networks)
ip route add NETWORK/PREFIX via NEXT_HOP   # static route ("replace" to replace it, "del" to remove it)
ip route add default via NEXT_HOP          # the default route (0.0.0.0/0)
ip route get ADDRESS                       # the route this machine would use for ADDRESS
sysctl -w net.ipv4.ip_forward=1            # turn forwarding on (relaying the packets received for others); 0: a plain host
cat /proc/sys/net/ipv4/ip_forward          # read the current value
traceroute -n -q 1 -w 1 -m 8 DEST          # the routers of the forward path (a silent router gives "*")
tc qdisc show                              # the transmit queues of the interfaces (a "netem delay" is a slow link)
```

The next hop of a static route must be an address of a network **directly connected** to the
machine. A machine without a default route only reaches its own networks; a machine that receives a
packet for another network drops it as long as `ip_forward` is 0, even if it has the route. The
routes of this lab are volatile: they vanish when a container restarts, which does not happen here.
""",
        """
```
tcpdump -n -i eth1 -ttt icmp                      # une interface ; -ttt : délai depuis la ligne précédente
tcpdump -n -i any -tt icmp                        # toutes les interfaces, horodatage absolu (secondes depuis 1970)
tcpdump -n -i eth1 -ttt 'dst net 203.0.113.0/24'  # seulement les paquets vers un réseau donné
tcpdump -n -i eth1 -c 20 -w /shared/boucle.pcap icmp   # 20 paquets dans un fichier, à ouvrir avec Wireshark
tshark -n -i eth1 -t d icmp                       # tshark : -t d = délai depuis le paquet précédent
```

Sur une machine de l'anneau, le paquet d'une boucle **entre** par une interface et **sort** par une
autre à chaque tour : capturer sur **une seule** interface donne une ligne par tour, et avec `-ttt`
chaque ligne affiche directement la période (`00:00:00.123456` : heures, minutes, secondes et
microsecondes depuis la ligne précédente). Avec `-i any`, `tcpdump` ajoute le nom de l'interface et
le sens (`In` / `Out`) devant chaque ligne, et chaque tour apparaît deux fois. Les erreurs ICMP
s'affichent `ICMP time exceeded in-transit` ; `Ctrl-C` arrête la capture et `-c N` l'arrête après N
paquets. Un fichier écrit dans `/shared` se retrouve dans le répertoire partagé du projet.
""": """
```
tcpdump -n -i eth1 -ttt icmp                      # one interface; -ttt: delay since the previous line
tcpdump -n -i any -tt icmp                        # every interface, absolute timestamp (seconds since 1970)
tcpdump -n -i eth1 -ttt 'dst net 203.0.113.0/24'  # only the packets towards a given network
tcpdump -n -i eth1 -c 20 -w /shared/ring.pcap icmp     # 20 packets into a file, to open with Wireshark
tshark -n -i eth1 -t d icmp                       # tshark: -t d = delay since the previous packet
```

On a machine of the ring, the packet of a ring **comes in** by one interface and **goes out** by
another at every turn: capturing on **one** interface alone gives one line per turn, and with `-ttt`
every line shows the period directly (`00:00:00.123456`: hours, minutes, seconds and microseconds
since the previous line). With `-i any`, `tcpdump` adds the name of the interface and the direction
(`In` / `Out`) in front of every line, and every turn shows up twice. The ICMP errors are printed
`ICMP time exceeded in-transit`; `Ctrl-C` stops the capture and `-c N` stops it after N packets. A
file written in `/shared` lands in the shared directory of the project.
""",
        """
`ping` envoie un **écho ICMP** (type 8, *echo request*) ; le destinataire renvoie une réponse (type 0,
*echo reply*) qui recopie la charge utile. `ping` note l'heure d'émission dans cette charge utile,
la compare à l'heure de réception et affiche le RTT de chaque réponse, puis le résumé
`rtt min/avg/max/mdev` (minimum, moyenne, maximum, écart type, en ms).

```
ping -n -c 10 -i 0.2 DEST      # 10 échos à 0,2 s d'intervalle, sans résolution inverse des noms
ping -n -c 1 -W 5 DEST         # un seul écho, 5 s d'attente de la réponse
ping -n -c 1 -t 5 DEST         # TTL 5 : le cinquième routeur jette le paquet et répond "Time to live exceeded"
```

- Le **premier écho** est plus lent : il déclenche une résolution **ARP** sur chaque lien traversé, et
  les réponses ARP subissent les mêmes files d'attente que les paquets (sur un lien lent, le premier
  écho coûte à peu près le double). Lisez le **minimum** (`min`) de plusieurs échos, ou la moyenne
  sans le premier.
- Chaque routeur traversé décrémente le **TTL** du paquet (64 au départ sous Linux). Celui qui reçoit
  un TTL de 1 jette le paquet et renvoie à l'émetteur un message ICMP *time exceeded* (type 11), que
  `ping` affiche `From ADRESSE icmp_seq=1 Time to live exceeded` : l'adresse est celle de l'interface
  par laquelle le routeur émet l'erreur. `ping` n'affiche pas de temps pour une erreur.
- Une machine qui n'a aucune route vers la destination répond `Network is unreachable` sans rien
  émettre ; une destination qui ne répond pas donne `100% packet loss` après l'attente.
""": """
`ping` sends an **ICMP echo** (type 8, *echo request*); the receiver sends back a reply (type 0,
*echo reply*) that copies the payload. `ping` writes the sending time in that payload, compares it
with the receiving time and prints the RTT of every reply, then the summary
`rtt min/avg/max/mdev` (minimum, average, maximum, standard deviation, in ms).

```
ping -n -c 10 -i 0.2 DEST      # 10 echoes 0.2 s apart, no reverse name resolution
ping -n -c 1 -W 5 DEST         # a single echo, 5 s of wait for the reply
ping -n -c 1 -t 5 DEST         # TTL 5: the fifth router drops the packet and answers "Time to live exceeded"
```

- The **first echo** is slower: it triggers an **ARP** resolution on every link crossed, and the ARP
  replies go through the same queues as the packets (on a slow link, the first echo costs about
  twice as much). Read the **minimum** (`min`) of several echoes, or the average without the first.
- Every router crossed decrements the **TTL** of the packet (64 at the start on Linux). The one that
  receives a TTL of 1 drops the packet and sends back to the sender an ICMP *time exceeded* message
  (type 11), which `ping` prints as `From ADDRESS icmp_seq=1 Time to live exceeded`: the address is
  that of the interface the router sends the error from. `ping` prints no time for an error.
- A machine without any route to the destination answers `Network is unreachable` without sending
  anything; a destination that does not answer gives `100% packet loss` after the wait.
""",
        """
| outil | usage |
|-------|-------|
| `ping -n -c N -i 0.2 DEST` | RTT moyen sur N échos (`rtt min/avg/max/mdev`) |
| `ping -n -c 1 -W S DEST` | un écho, S secondes d'attente |
| `ping -n -c 1 -t TTL DEST` | un écho au TTL donné (où s'arrête-t-il ?) |
| `tcpdump -n -i IFACE -ttt icmp` | une ligne par paquet, le délai depuis la précédente |
| `tshark -n -i IFACE -t d icmp` | idem avec tshark |
| `ip route add RÉSEAU via SAUT` / `ip route get ADRESSE` | ajouter une route / voir la route utilisée |
| `sysctl -w net.ipv4.ip_forward=1` | activer le routage |
| `traceroute -n -q 1 -w 1 -m 8 DEST` | le chemin aller |
| `tc qdisc show` | les délais artificiels des interfaces (`netem`) |
""": """
| tool | use |
|------|-----|
| `ping -n -c N -i 0.2 DEST` | average RTT over N echoes (`rtt min/avg/max/mdev`) |
| `ping -n -c 1 -W S DEST` | one echo, S seconds of wait |
| `ping -n -c 1 -t TTL DEST` | one echo with the given TTL (where does it stop?) |
| `tcpdump -n -i IFACE -ttt icmp` | one line per packet, the delay since the previous one |
| `tshark -n -i IFACE -t d icmp` | the same with tshark |
| `ip route add NETWORK via HOP` / `ip route get ADDRESS` | add a route / see the route used |
| `sysctl -w net.ipv4.ip_forward=1` | turn forwarding on |
| `traceroute -n -q 1 -w 1 -m 8 DEST` | the forward path |
| `tc qdisc show` | the artificial delays of the interfaces (`netem`) |
""",
        """
| réseau | préfixe | machines (nom dans `/etc/hosts`) |
|--------|---------|----------------------------------|
| `ext` | `{ext}` | `gw` (`{gw}`, `gw`), `m1` eth0 (`{m1_ext}`, `m1_ext`) |
| `x1` | `{x1}` | `m1` eth1 (`{m1_x1}`, `m1_x1`), `x` eth0 (`{x_x1}`, `x_x1`) |
| `x3` | `{x3}` | `x` eth1 (`{x_x3}`, `x_x3`), `m3` eth0 (`{m3_x3}`, `m3_x3`) |
| `l23` | `{l23}` | `m3` eth1 (`{m3_l23}`, `m3_l23`), `m2` eth0 (`{m2_l23}`, `m2_l23`) |
| `l12` | `{l12}` | `m2` eth1 (`{m2_l12}`, `m2_l12`), `m1` eth2 (`{m1_l12}`, `m1_l12`) |
| `net1` | `{net1}` | réseau fantôme : personne ; `x` le route vers `m3` |
| `net2` | `{net2}` | réseau fantôme : personne ; `x` le route vers `m1` |
""": """
| network | prefix | machines (name in `/etc/hosts`) |
|---------|--------|---------------------------------|
| `ext` | `{ext}` | `gw` (`{gw}`, `gw`), `m1` eth0 (`{m1_ext}`, `m1_ext`) |
| `x1` | `{x1}` | `m1` eth1 (`{m1_x1}`, `m1_x1`), `x` eth0 (`{x_x1}`, `x_x1`) |
| `x3` | `{x3}` | `x` eth1 (`{x_x3}`, `x_x3`), `m3` eth0 (`{m3_x3}`, `m3_x3`) |
| `l23` | `{l23}` | `m3` eth1 (`{m3_l23}`, `m3_l23`), `m2` eth0 (`{m2_l23}`, `m2_l23`) |
| `l12` | `{l12}` | `m2` eth1 (`{m2_l12}`, `m2_l12`), `m1` eth2 (`{m1_l12}`, `m1_l12`) |
| `net1` | `{net1}` | phantom network: nobody; `x` routes it towards `m3` |
| `net2` | `{net2}` | phantom network: nobody; `x` routes it towards `m1` |
""",
        """L'auto-évaluation ne note pas vos trois réponses chiffrées : seule l'évaluation de l'enseignant les prend en compte.
""": """The self-evaluation does not grade your three numeric answers: only the instructor's evaluation takes them into account.
""",
        """L'auto-évaluation note aussi vos trois réponses chiffrées : elle vous dit si une mesure est dans la tolérance.
""": """The self-evaluation also grades your three numeric answers: it tells you whether a measurement is within the tolerance.
""",
        'La méthode de la boucle': 'The ring method',
        "Latence : mesurer le délai d'un réseau opaque dans chaque sens": 'Latency: measuring the delay of an opaque network in each direction',
        'Latence de x dans chaque sens': 'Latency of x in each direction',
        'Latence totale à travers x': 'Total latency through x',
        'Latence, RTT et délai aller simple': 'Latency, RTT and one-way delay',
        'Mesurer un RTT avec ping': 'Measuring an RTT with ping',
        'Observer les passages avec tcpdump ou tshark': 'Watching the passages with tcpdump or tshark',
        'Organisation du TP': 'Organisation of the lab',
        'Outils': 'Tools',
        'Partie 1 — Latence totale à travers x': 'Part 1 — Total latency through x',
        'Partie 2 — Latence de x dans chaque sens': 'Part 2 — Latency of x in each direction',
        "Pourquoi le délai aller simple n'est pas mesurable directement": 'Why the one-way delay cannot be measured directly',
        'Rappels de routage statique sous Linux': 'Static routing reminders on Linux',
        "Retour à l'état de départ (routes supprimées, routage désactivé, etc..) - vos réponses sont conservées": 'Back to the initial state (routes removed, forwarding off, etc.) - your answers are kept',
        'Solution de référence : routes de m1 et m3 par x (question 1), routage sur m1, m2, m3, route par défaut de gw, boucles net1 et net2 et chemin local (question 2) ; le lien lent de m2 est remis en place': 'Reference solution: routes of m1 and m3 via x (question 1), forwarding on m1, m2, m3, default route of gw, rings net1 and net2 and local path (question 2); the slow link of m2 is set up again',
        'boucle 1 : net1 routé par x sur m1, par m2 sur m3, par m1 sur m2': 'ring 1: net1 routed via x on m1, via m2 on m3, via m1 on m2',
        'boucle 1 : un paquet de gw vers net1 fait deux tours (ping -t 9, time exceeded de m1)': 'ring 1: a packet from gw to net1 goes twice round (ping -t 9, time exceeded from m1)',
        'boucle 2 : net2 routé par m2 sur m1, par m3 sur m2, par x sur m3': 'ring 2: net2 routed via m2 on m1, via m3 on m2, via x on m3',
        'boucle 2 : un paquet de gw vers net2 fait deux tours (ping -t 9, time exceeded de m1)': 'ring 2: a packet from gw to net2 goes twice round (ping -t 9, time exceeded from m1)',
        'latence de x dans le sens m1 → x → m3': 'latency of x in the direction m1 → x → m3',
        'latence de x dans le sens m3 → x → m1': 'latency of x in the direction m3 → x → m1',
        'latence totale à travers x (RTT m1 → m3)': 'total latency through x (RTT m1 → m3)',
        'routage activé sur {m}': 'forwarding enabled on {m}',
        'route de gw par m1 (par défaut, ou vers net1 et net2)': 'route of gw via m1 (default, or towards net1 and net2)',
        'route de m1 vers le réseau x3 par x': 'route from m1 to the network x3 via x',
        'route de m3 vers le réseau x1 par x': 'route from m3 to the network x1 via x',
        "un ping de m1 vers m3 traverse x à l'aller et au retour (RTT attendu)": 'a ping from m1 to m3 crosses x on the way out and on the way back (expected RTT)',
    },
}
