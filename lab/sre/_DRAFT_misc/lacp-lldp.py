"""Link aggregation lab: Linux bonding (active-backup, LACP), aggregates in Linux switches, LLDP.

Five independent sites, one per part, and a bonus on the first one (completing a part gives all
its points whatever the others).  Every link of the schema is a point-to-point Kathara network (a
"cable"):

- ``lldp`` (part 1): the server ``lldp_srv`` is cabled to two core switches ``lldp_core1`` /
  ``lldp_core2`` and to the box of an operator ``lldp_isp``, three hidden machines without terminal
  that run lldpd with names, port IDs and management addresses drawn for the instance; the
  students run lldpd on the server, discover the three boxes, announce a system description and
  stop announcing towards the operator (``rx-only``).  Graded on the far side (the neighbour tables
  of the core switches and of the operator's box) and by forms;
- ``ab`` (part 2): ``ab_srv`` is cabled to two switches ``ab_sw1`` / ``ab_sw2`` (Linux bridges,
  joined by one link), ``ab_gw`` is behind ``ab_sw2``; the students build an active-backup bond
  with ARP monitoring (a VDE link never loses its carrier at the far end, so ``miimon`` cannot see a
  failure beyond the local port).  Each evaluation cuts the port of ``ab_sw1`` towards the server
  for 6 s (``ab-cut pulse``: an nft netdev table, carrier untouched) while ``ab_srv`` pings ``ab_gw``
  every 100 ms; the user states ``ab_cut`` / ``ab_uncut`` let the students make the experiment;
- ``lacp`` (part 3): ``lacp_srv`` has two links to ``lacp_sw``, whose aggregate ``po1`` (802.3ad,
  fast, layer3+4, port of its bridge) is given; ``lacp_pc`` (iperf3 server) is behind it; the
  students build the LACP bond of the server;
- ``isl`` (part 4): two switches ``isl_sw1`` / ``isl_sw2`` joined by two parallel links, both ports
  of their STP bridges (one blocked), ``isl_pc1`` / ``isl_pc2`` (iperf3 server) behind them; the
  students replace the two ports by an LACP aggregate on both switches;
- ``fix`` (part 5): ``fix_srv`` -> ``fix_sw`` -> ``fix_pc``, shipped with three faults: the server in
  balance-xor while the switch speaks LACP, ``eth1`` of the switch outside its aggregate,
  ``min_links 3`` on the aggregate of the switch;
- bonus (site ``lldp``): ``lldp_core1`` announces by LLDP the management VLAN of its port; the
  students create the VLAN interface and reach the management address of the switch.

The member links of the ``lacp`` and ``isl`` sites are capped at 20 Mbit/s by a ``tc`` tbf at both
ends (one flow then gets ~19 Mbit/s, four flows over two links ~38).  Every interface has a fixed
MAC address (``data.macs``): the system MAC of ``lacp_sw`` (a form answer) and the root bridge of
the ``isl`` site (hence the port STP blocks, another one) are known in advance.  Grading reads the
bonds with ``ip -j -d link`` at both ends (lib/bonding.py), the LLDP neighbours with ``lldpcli -f
json0`` (lib/lldp.py), real pings, and the transmit counters of the members around 64 UDP flows
sent by ``hping3`` (each member must carry at least 10 of them).  The states ``solve_<part>`` apply
the reference solution of one part, ``final`` all of them (it waits for STP, about 30 s).  Facts
verified live on s17 (2026-11-21): see lib/bonding.py and lib/lldp.py.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List, Optional

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_mac_address
from net_config import set_ip_forward
from bridging import bridge_info, bridge_ports, get_ip_links, link_master, normalize_mac, port_states, vlan_links
from bonding import (
    bond_info, bond_slaves, get_tx_packets, hping_flows_cmd, lacp_aggregated, lacp_partner_is, packets_delta,
)
from lldp import LLDP_MAC, get_lldp_neighbors, lldp_neighbor

default_language = 'fr'
tr = make_tr(default_language)

title = tr("LACP et LLDP : agrégation de liens (bonding) et découverte des voisins", en="LACP and LLDP: link aggregation (bonding) and neighbour discovery")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
# An evaluation pings, sends 64 UDP flows per aggregate and cuts the port of ab_sw1 for 6 s.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

IMAGE = sre_docker_image("routing-frr13")        # base13 + lldpd (FRR itself is not used)
#: routing-frr weighs 6 by default (FRR daemons running): here no FRR runs
MACHINE = {'image': IMAGE, 'weight': 1}
HIDDEN = {**MACHINE, 'hidden': True, 'allow_connection': False}

BOND = "bond0"            # the aggregates the students create (imposed name)
SW_BOND = "po1"           # the aggregates of the given switches ("port-channel 1")
BRIDGE = "br0"
MAC_PREFIX = "02:53:52"
LINK_RATE = "20mbit"      # each member link of the lacp and isl sites, both ends
CAP_CMD = "tc qdisc replace dev {dev} root tbf rate " + LINK_RATE + " burst 64kb latency 50ms"
ARP_INTERVAL = 200        # ms, asked in part 2 (measured: 6 s cut -> 0.6 s lost)
CUT_SECONDS = 6
PING_COUNT, PING_INTERVAL = 80, 0.1
MAX_LOST = 20             # pings lost during the cut: 2 s (miimon alone loses ~60, arp 1000 ms ~30)
CUT_TABLE = "sre_cut"
AB_CUT = "/usr/local/sbin/ab-cut"
FLOWS, FLOW_PORT, MIN_PER_LINK, MIN_DELIVERED = 64, 20000, 10, 60
HASH_POLICIES = ('layer3+4', 'encap3+4')
PING = "ping -c 2 -w 4"
LLDP_CONF = "/etc/lldpd.d/sre.conf"
LLDP_TTL, LLDP_TX_INTERVAL = 120, 30
LACP_MAC = "01:80:c2:00:00:02"
LACP_KEY, LACP_PRIORITY = 15, 65535
DATACENTRES = ('par', 'lyo', 'lil', 'nan', 'tls', 'bdx', 'mrs', 'stg', 'ren', 'gre')

# Every link is a point-to-point network: {network: {machine: ethN}}.
_TOPOLOGY = {
    # part 1 / bonus: LLDP
    'lldp_l1': {'lldp_srv': 0, 'lldp_core1': 0},
    'lldp_l2': {'lldp_srv': 1, 'lldp_core2': 0},
    'lldp_l3': {'lldp_srv': 2, 'lldp_isp': 0},
    # part 2: active-backup towards two switches
    'ab_l1': {'ab_srv': 0, 'ab_sw1': 0},
    'ab_l2': {'ab_srv': 1, 'ab_sw2': 0},
    'ab_l12': {'ab_sw1': 1, 'ab_sw2': 1},
    'ab_l3': {'ab_sw2': 2, 'ab_gw': 0},
    # part 3: LACP between a server and a switch
    'lacp_l1': {'lacp_srv': 0, 'lacp_sw': 0},
    'lacp_l2': {'lacp_srv': 1, 'lacp_sw': 1},
    'lacp_l3': {'lacp_sw': 2, 'lacp_pc': 0},
    # part 4: aggregate between two switches
    'isl_a1': {'isl_pc1': 0, 'isl_sw1': 0},
    'isl_t1': {'isl_sw1': 1, 'isl_sw2': 1},
    'isl_t2': {'isl_sw1': 2, 'isl_sw2': 2},
    'isl_a2': {'isl_pc2': 0, 'isl_sw2': 0},
    # part 5: troubleshooting
    'fix_l1': {'fix_srv': 0, 'fix_sw': 0},
    'fix_l2': {'fix_srv': 1, 'fix_sw': 1},
    'fix_l3': {'fix_sw': 2, 'fix_pc': 0},
}
#: (machine, network) -> macs.<key>: a fixed MAC address on every interface
MAC_KEYS = {(m, net): f"{m}_eth{i}" for net, members in _TOPOLOGY.items() for m, i in members.items()}
#: the IPv4 network of each site
SITE_NETS = ('lldp_mgmt', 'ab', 'lacp', 'isl', 'fix')
#: ips.<key> -> (network, host part)
HOSTS = {
    'lldp_core1': ('lldp_mgmt', 2), 'lldp_core2': ('lldp_mgmt', 3), 'lldp_srv': ('lldp_mgmt', 10),
    'ab_gw': ('ab', 1), 'ab_srv': ('ab', 10),
    'lacp_srv': ('lacp', 10), 'lacp_pc': ('lacp', 20),
    'isl_pc1': ('isl', 1), 'isl_pc2': ('isl', 2),
    'fix_srv': ('fix', 10), 'fix_pc': ('fix', 20),
}
#: the names written in /etc/hosts (the management addresses of the core switches are not given)
HOST_NAMES = ('ab_gw', 'ab_srv', 'lacp_srv', 'lacp_pc', 'isl_pc1', 'isl_pc2', 'fix_srv', 'fix_pc')
ISL_SWITCHES = ('isl_sw1', 'isl_sw2')
LLDP_SWITCHES = ('ab_sw1', 'ab_sw2', 'lacp_sw', 'isl_sw1', 'isl_sw2', 'fix_sw')
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice.  Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

# The silent cut of part 2, installed on ab_sw1 by `initial`: a dead cable whose carrier stays up at
# both ends.  Every frame entering or leaving the port eth0 of ab_sw1 (towards ab_srv eth0) is
# dropped at the device (netdev ingress and egress hooks), its own STP BPDUs and LLDPDUs included:
# a cut of the forwarded frames only (bridge family) let the BPDUs sent every 2 s reach ab_srv,
# whose bond then took eth0 back (any frame received makes a backup member valid without
# arp_validate) and flapped (seen live: 23 pings of 80 lost instead of 6).
# `pulse N` is what an evaluation runs: a cut of N s, or nothing when a cut is already in place
# (left by the user state ab_cut: the student's experiment is not undone).
AB_CUT_SCRIPT = """#!/bin/sh
# ab-cut on|off|status|pulse SECONDS: silent cut of the port eth0 of ab_sw1 (towards ab_srv eth0).
# Every frame in or out of eth0 is dropped at the device (nft netdev table, ingress and egress
# hooks); the carrier stays up at both ends.
TABLE=""" + CUT_TABLE + """
case "$1" in
on)
    nft list table netdev $TABLE >/dev/null 2>&1 && exit 0
    nft -f - <<EOF
table netdev $TABLE {
    chain in {
        type filter hook ingress device "eth0" priority 0; policy drop;
    }
    chain out {
        type filter hook egress device "eth0" priority 0; policy drop;
    }
}
EOF
    ;;
off)
    nft delete table netdev $TABLE 2>/dev/null
    exit 0
    ;;
status)
    if nft list table netdev $TABLE >/dev/null 2>&1; then echo cut; else echo ok; fi
    ;;
pulse)
    if nft list table netdev $TABLE >/dev/null 2>&1; then
        sleep $(($2 + 2)); echo kept
    else
        sleep 1; "$0" on; sleep "$2"; "$0" off; echo pulsed
    fi
    ;;
*)
    echo "usage: $0 on|off|status|pulse SECONDS" >&2; exit 2
    ;;
esac
"""


def iface(machine: str, network: str) -> str:
    return f"eth{_TOPOLOGY[network][machine]}"


def mac_text(data, key: str) -> str:
    return normalize_mac(getattr(data.macs, key))


def isl_roles(data):
    """``(root, other)`` of the STP of the isl site: equal priorities, so the bridge with the
    lowest bridge MAC (the lowest MAC of its three ports) is the root."""
    def bridge_mac(m):
        return min((getattr(data.macs, f"{m}_eth{i}") for i in range(3)), key=int)
    sw1, sw2 = bridge_mac('isl_sw1'), bridge_mac('isl_sw2')
    return ('isl_sw1', 'isl_sw2') if int(sw1) < int(sw2) else ('isl_sw2', 'isl_sw1')


def isl_blocked_port(data) -> str:
    """The port STP blocks before the aggregate: on the non-root switch, the one facing the port
    of the root with the higher port id.  The ports are enslaved eth0, eth1, eth2 in that order on
    both switches, so the non-root's eth1 is its root port and its eth2 blocks."""
    return f"{isl_roles(data)[1]}_eth2"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    dc: str = ""
    core1_name: str = ""
    core2_name: str = ""
    isp_name: str = ""
    core1_port: str = ""
    core2_port: str = ""
    rack: str = ""
    mgmt_vlan: int = 0

    @classmethod
    def generate(cls):
        dc = random.choice(DATACENTRES)
        n1, n2 = random.sample(range(1, 20), 2)
        k1, k2 = random.sample(range(1, 49), 2)
        data = cls(dc=dc, core1_name=f"{dc}-core-{n1:02d}", core2_name=f"{dc}-core-{n2:02d}",
                   isp_name=f"cpe-{random.randint(1000, 9999)}", core1_port=f"Gi1/0/{k1}", core2_port=f"Gi2/0/{k2}",
                   rack=f"{random.choice('ABCDEFGH')}{random.randint(1, 12)}", mgmt_vlan=random.randint(100, 999))
        nets = random_ipv4networks(masks=[24] * len(SITE_NETS), from_private_network=True,
                                   exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, net in zip(SITE_NETS, nets):
            setattr(data.nets, name, net)
        for key, (net, host) in HOSTS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{network.network_address + host}/{network.prefixlen}"))
        keys = sorted(set(MAC_KEYS.values()))
        for key, mac in zip(keys, random_mac_address(prefix=MAC_PREFIX, n=len(keys))):
            setattr(data.macs, key, mac)
        return data

    @property
    def srv_descr(self) -> str:
        """The system description the students announce from lldp_srv (part 1)."""
        return f"web server rack {self.rack}"


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'lldp_srv': {**MACHINE, 'color': 'lightblue'},
        'lldp_core1': HIDDEN, 'lldp_core2': HIDDEN, 'lldp_isp': HIDDEN,
        'ab_srv': {**MACHINE, 'color': 'lightblue'},
        'ab_sw1': {**MACHINE, 'color': 'lightyellow'}, 'ab_sw2': {**MACHINE, 'color': 'lightyellow'},
        'ab_gw': {**MACHINE, 'color': 'lightgrey'},
        'lacp_srv': {**MACHINE, 'color': 'lightblue'},
        'lacp_sw': {**MACHINE, 'color': 'lightyellow'},
        'lacp_pc': {**MACHINE, 'color': 'lightgrey'},
        'isl_sw1': {**MACHINE, 'color': 'lightyellow'}, 'isl_sw2': {**MACHINE, 'color': 'lightyellow'},
        'isl_pc1': {**MACHINE, 'color': 'lightgrey'}, 'isl_pc2': {**MACHINE, 'color': 'lightgrey'},
        'fix_srv': {**MACHINE, 'color': 'lightblue'},
        'fix_sw': {**MACHINE, 'color': 'lightyellow'},
        'fix_pc': {**MACHINE, 'color': 'lightgrey'},
    }
    _network_specs = {
        **{n: {'color': 'lavender'} for n in _TOPOLOGY if n.startswith('lldp_')},
        **{n: {'color': 'lightcyan'} for n in _TOPOLOGY if n.startswith('ab_')},
        **{n: {'color': 'lemonchiffon'} for n in _TOPOLOGY if n.startswith('lacp_')},
        **{n: {'color': 'mistyrose'} for n in _TOPOLOGY if n.startswith('isl_')},
        **{n: {'color': 'honeydew'} for n in _TOPOLOGY if n.startswith('fix_')},
    }

    @property
    def _topology(self):
        macs = self.data.macs
        return {net: {m: (i, getattr(macs, MAC_KEYS[(m, net)])) for m, i in members.items()}
                for net, members in _TOPOLOGY.items()}

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.informations = self._informations()

    # -- the course ----------------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi agréger des liens"), tag="why")
            + tr("""

Un lien Ethernet est à la fois un **point unique de défaillance** et un **plafond de débit**.
Multiplier les câbles ne suffit pas : entre deux switchs, deux liens parallèles forment une boucle
que STP défait en bloquant l'un d'eux (la redondance est là, le débit non) ; entre un serveur et un
switch, deux interfaces avec deux adresses IP ne font pas un lien plus gros.

L'**agrégation de liens** (*link aggregation*, *LAG*, *port-channel*, *EtherChannel* ; *bonding*
sous Linux) regroupe N liens physiques, les **membres**, en **un lien logique** : une seule adresse
MAC, une seule adresse IP, un seul port pour STP et pour la table MAC des switchs. On y gagne :

- la **tolérance de panne** : la perte d'un membre ne coupe rien, le trafic passe par les autres ;
- le **débit cumulé**, réparti **par flux** (section @@ref:hashing@@) : un seul flux ne dépasse
  jamais le débit d'un membre.

Les membres relient les **deux mêmes équipements** (ou une paire de switchs qui se présentent comme
un seul, section @@ref:bridge@@), avec la même vitesse et le même duplex.
""")
            + info_subtitle(tr("Les modes du bonding Linux"), tag="modes")
            + tr("""

Le pilote `bonding` du noyau propose sept modes (`mode` de `ip link add ... type bond`) :

| mode | nom | principe | côté switch |
|------|-----|----------|-------------|
| 0 | `balance-rr` | les trames partent tour à tour sur chaque membre | agrégat statique ; les segments d'une connexion TCP arrivent dans le désordre |
| 1 | `active-backup` | un seul membre actif, les autres en secours | rien : marche vers **deux switchs différents** |
| 2 | `balance-xor` | le membre de chaque trame est choisi par hachage (`xmit_hash_policy`) | agrégat **statique** (« mode on ») |
| 3 | `broadcast` | chaque trame part sur tous les membres | rare |
| 4 | `802.3ad` | agrégat **négocié par LACP**, répartition par hachage | LACP |
| 5 | `balance-tlb` | émission répartie selon la charge, réception sur un seul membre | rien |
| 6 | `balance-alb` | `balance-tlb` + réception répartie en jouant sur les réponses ARP | rien |

En `active-backup`, `primary eth0` désigne le membre préféré (il reprend la main dès qu'il est de
nouveau valide, `primary_reselect always`). Le bond prend l'adresse MAC de **son premier membre** et
la donne à tous (`fail_over_mac none`) : après une bascule l'adresse ne change pas, et le bond émet
un **ARP gratuit** (`num_grat_arp`) par le nouveau membre pour que les switchs apprennent le nouveau
chemin.
""")
            + info_subtitle(tr("Détecter une panne : miimon ou surveillance ARP"), tag="monitoring")
            + tr("""

Un bond ne peut retirer un membre que s'il le sait en panne. Deux méthodes (exclusives : régler
l'une désactive l'autre) :

- **`miimon N`** : toutes les N ms, le bond regarde la **porteuse** (*carrier*) de chaque membre.
  Il voit un câble débranché ou une interface locale arrêtée, mais **rien au-delà** : un switch
  intermédiaire, un convertisseur de média, une optique qui perd des trames, un port distant mal
  configuré laissent la porteuse allumée. **Dans cette maquette**, les liens sont virtuels et ne
  perdent jamais leur porteuse à l'autre bout : `ip link set eth1 down` d'un côté laisse l'autre
  côté `UP`.
- **`arp_interval N arp_ip_target A.B.C.D`** (jusqu'à 16 cibles) : toutes les N ms, le bond envoie
  une requête ARP vers les cibles ; un membre qui n'a rien reçu pendant `arp_missed_max` (2)
  intervalles est déclaré en panne. C'est **tout le chemin** jusqu'à la cible qui est testé. Pour
  `active-backup` (et `balance-rr` / `balance-xor`), pas pour `802.3ad`. Par défaut
  (`arp_validate none`), **n'importe quelle trame** reçue suffit à juger un membre valide : un
  switch qui continue d'émettre ses propres trames (BPDU, LLDP) sur un lien dont la suite est
  coupée le fait paraître sain ; `arp_validate all` ne retient que le trafic ARP lié aux sondes.
- En `802.3ad`, **LACP** surveille lui-même chaque membre (section @@ref:lacp@@).

Mesuré dans cette maquette, une coupure silencieuse de 6 s du lien actif d'un bond `active-backup`
(un `ping` toutes les 100 ms) : avec `miimon` seul, **tout est perdu** pendant les 6 s ; avec la
surveillance ARP, environ 3 s de perte à 1000 ms, 0,6 s à 200 ms, 0,3 s à 100 ms.
""")
            + info_subtitle(tr("Répartir le trafic : le hachage par flux"), tag="hashing")
            + tr("""

En `balance-xor` et en `802.3ad`, le membre qui émet une trame est choisi par un **hachage** de ses
en-têtes, modulo le nombre de membres. Toutes les trames d'un même flux prennent donc le même
membre (pas de désordre), et **un flux ne dépasse jamais le débit d'un membre** ; N flux se
répartissent statistiquement. La politique `xmit_hash_policy` dit ce qui est haché :

| politique | champs | conséquence |
|-----------|--------|-------------|
| `layer2` (défaut) | adresses MAC et EtherType | tout le trafic entre deux machines (ou vers un routeur) prend le même membre |
| `layer2+3` | MAC + adresses IP | une paire d'adresses IP = un membre |
| `layer3+4` | adresses IP + ports TCP/UDP | les connexions entre deux mêmes machines se répartissent |
| `encap2+3`, `encap3+4` | en-têtes internes d'un tunnel | pour le trafic encapsulé |

Chaque extrémité choisit pour **ses propres émissions** : la politique du serveur décide du sens
serveur → switch, celle du switch du sens switch → serveur.

Mesuré dans cette maquette (deux membres bridés à 20 Mbit/s) : un flux `iperf3` obtient environ
19 Mbit/s, quatre flux (`iperf3 -P 4`) environ 38 Mbit/s. Il arrive que tous les flux tombent sur le
même membre (une chance sur huit avec quatre flux) : recommencez, ou prenez plus de flux.
""")
            + info_subtitle(tr("LACP (IEEE 802.3ad, aujourd'hui 802.1AX)"), tag="lacp")
            + tr("""

Un agrégat **statique** (`balance-xor`, « mode on » des switchs) ne vérifie rien : chaque
extrémité suppose l'autre configurée pareil. Une erreur de câblage (un membre branché sur un autre
switch) ou de configuration (un côté non agrégé) fait disparaître une partie du trafic, sans
message.

**LACP** (*Link Aggregation Control Protocol*) fait échanger des **LACPDU** sur chaque membre :

- trames du groupe *slow protocols*, adresse de destination **`01:80:c2:00:00:02`** (jamais
  relayée par un pont), EtherType **`0x8809`**, sous-type 1 ;
- chaque LACPDU porte les informations de l'**acteur** (l'émetteur) et ce qu'il sait du
  **partenaire** : priorité système + adresse MAC système (l'**identifiant système**), **clé**
  (des membres de même clé peuvent être agrégés ; Linux la déduit de la vitesse et du duplex : 15
  pour les interfaces virtuelles à 10 Gbit/s de cette maquette), priorité et numéro de port, état.

Les bits d'**état** d'un port (`port state` 63 = `0x3f` = les six premiers) :

| bit | nom | signification quand il vaut 1 |
|-----|-----|-------------------------------|
| 0x01 | *Activity* | port **actif** (il émet de lui-même) ; 0 = passif, il ne fait que répondre |
| 0x02 | *Timeout* | délai **court** demandé (*fast*) |
| 0x04 | *Aggregation* | port agrégeable |
| 0x08 | *Synchronization* | port dans le bon agrégat, en accord avec le partenaire |
| 0x10 | *Collecting* | il accepte les trames reçues |
| 0x20 | *Distributing* | il émet des trames de données |
| 0x40 | *Defaulted* | aucune information reçue du partenaire : valeurs par défaut |
| 0x80 | *Expired* | les informations du partenaire ont expiré |

- **Rythme** : *slow*, une LACPDU toutes les 30 s et expiration après 90 s ; *fast*, toutes les
  secondes et expiration après **3 s**. Sous Linux, `lacp_rate fast` demande au partenaire
  d'émettre vite (bit *Timeout* des LACPDU que l'on envoie).
- **Agrégateur** : les membres dont le partenaire a le même identifiant système et la même clé
  rejoignent le même agrégateur ; un membre qui voit un autre partenaire, ou aucun, est placé seul
  dans un autre agrégateur, **inactif** (ses trames reçues sont jetées). Linux garde l'agrégateur
  actif tant qu'il lui reste un port (`ad_select stable`).
- **`min_links N`** : le bond (donc le port du pont au-dessus) n'a de porteuse qu'avec au moins N
  membres actifs, pour basculer le trafic ailleurs quand trop de capacité est perdue ; trop élevé,
  il coupe tout.

Ce que LACP apporte par rapport à un agrégat statique : un membre branché ailleurs (autre
identifiant système) ou une extrémité non agrégée (pas de partenaire) est **écarté**, et une panne
d'un seul côté est détectée par l'absence de LACPDU pendant 3 intervalles.
""")
            + info_subtitle(tr("Configurer et observer sous Linux"), tag="linux")
            + tr("""

```
ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4
ip link set eth0 down ; ip link set eth0 master bond0     # un membre doit être DOWN
ip link set eth1 down ; ip link set eth1 master bond0
ip link set bond0 up
ip address add 192.0.2.10/24 dev bond0
```

- L'adresse IP se met sur le bond, **jamais sur les membres**. Un membre doit être arrêté pour être
  ajouté (`Device can not be enslaved while up`) ; le bond le remet en marche.
- Le **mode** ne change que sans membre : `ip link del bond0` (les membres sont libérés), puis
  recréer. Beaucoup d'options changent à chaud : `ip link set bond0 type bond min_links 1`,
  `arp_interval 200`, `primary eth0`... Retirer un membre : `ip link set eth1 nomaster`.
- **Observer** : `cat /proc/net/bonding/bond0` (mode, membre actif, agrégateur actif : numéro,
  nombre de ports, adresse MAC du partenaire ; pour chaque membre : son agrégateur, les LACPDU de
  l'acteur et du partenaire), `ip -d link show bond0` (toutes les options), `ip -d link show eth0`
  (état du membre), `ip -s link show eth0` (compteurs d'un membre), et les LACPDU elles-mêmes :
  `tcpdump -n -e -vv -i eth0 ether proto 0x8809`.
- En configuration permanente (paquet `ifenslave`), `/etc/network/interfaces` décrit le bond :

```
auto bond0
iface bond0 inet static
    address 192.0.2.10/24
    bond-slaves eth0 eth1
    bond-mode 802.3ad
    bond-miimon 100
    bond-lacp-rate fast
    bond-xmit-hash-policy layer3+4
```

Dans ce TP tout est volatil (commandes `ip`).
""")
            + info_subtitle(tr("Un agrégat dans un switch"), tag="bridge")
            + tr("""

Dans un switch Linux (un pont), l'agrégat est un port comme un autre : `ip link set po1 master
br0` ; ses membres ne sont **pas** des ports du pont. Les LACPDU sont consommées par le bond et
n'atteignent jamais le pont.

**STP ne voit qu'un port** : deux switchs reliés par deux liens parallèles agrégés n'ont plus de
boucle, rien n'est bloqué et les deux liens transportent du trafic ; sans agrégat, STP en bloque un
(il ne garde que le port racine, celui qui reçoit le meilleur BPDU : à coût égal, celui relié au
port de plus petit identifiant de la racine). Un port STP qui vient d'être ajouté met 30 s
(2 × *forward delay*) à transmettre.

**MLAG** (*multi-chassis LAG* : *vPC*, *stack*...) : deux switchs se présentent avec le même
identifiant système LACP, si bien qu'un serveur peut agréger un lien vers chacun et survivre à la
perte d'un switch. Sans MLAG, la redondance vers deux switchs se fait en `active-backup`.
""")
            + info_subtitle(tr("LLDP (IEEE 802.1AB)"), tag="lldp")
            + tr("""

Avec **LLDP** (*Link Layer Discovery Protocol*), chaque équipement annonce périodiquement, sur
chaque port, qui il est ; le voisin garde l'information pendant une durée de vie (**TTL**). Pas de
négociation, pas de réponse : c'est un annuaire des voisins directs (l'équivalent normalisé de CDP,
le protocole de Cisco).

- Trame : destination **`01:80:c2:00:00:0e`** (*nearest bridge* : jamais relayée par un pont, on
  ne voit que son voisin direct), EtherType **`0x88cc`**, une suite de TLV (type, longueur, valeur).
- TLV **obligatoires** : *Chassis ID* (souvent une adresse MAC), *Port ID* (adresse MAC, nom
  d'interface, ou nom local comme `Ethernet1/12`), *TTL* (= intervalle d'émission × multiplicateur :
  **30 s × 4 = 120 s** par défaut), *End*.
- TLV **optionnels** : *Port Description*, *System Name*, *System Description*, *System
  Capabilities* (Bridge, Router, Station... : disponibles et activées), *Management Address*.
- TLV d'**organisation** : IEEE 802.1 (VLAN natif du port, **noms des VLAN** transportés), IEEE
  802.3 (vitesse et duplex, **appartenance à un agrégat** et son identifiant, taille maximale des
  trames), LLDP-MED (téléphones : VLAN voix, alimentation PoE, inventaire).
- Un équipement qui arrête LLDP sur un port envoie une LLDPDU de **TTL 0** (*shutdown*) : le voisin
  l'oublie aussitôt ; sinon le voisin garde l'information jusqu'à la fin du TTL.

Usages : vérifier un câblage (sur quel port de quel switch arrive ce câble ?), découverte
automatique de la topologie par la supervision (LLDP-MIB en SNMP), configuration des téléphones IP.

**Sécurité** : LLDP donne à quiconque est branché le modèle, la version, les noms, les adresses,
les VLAN. On le coupe, ou on le met en **réception seule**, sur les ports tournés vers un réseau
qui n'est pas de confiance (un opérateur, une salle publique), et on ne se fie pas aveuglément à ce
que l'on reçoit (il se falsifie facilement).
""")
            + info_subtitle(tr("lldpd et lldpcli"), tag="lldpd")
            + tr("""

Sous Linux, le démon **`lldpd`** (lancé à la main ici : `lldpd`) et son client **`lldpcli`** :

- **Consulter** : `lldpcli show neighbors` (`details`, `summary`, `ports eth0`), `lldpcli show
  chassis` (ce que l'on annonce), `lldpcli show interfaces`, `lldpcli show statistics`, `lldpcli
  show configuration` ; `-f json0` ou `-f keyvalue` pour un script.
- **Configurer** :
  `lldpcli configure system description "..."`, `configure system hostname X`,
  `configure system ip management pattern 192.0.2.*`,
  `configure ports eth2 lldp status rx-only` (ou `tx-only`, `rx-and-tx`, `disabled`),
  `configure ports eth0 lldp portidsubtype local Ethernet1/1 description "..."`,
  `configure lldp tx-interval 30`, `configure lldp tx-hold 4`.
- **Au démarrage**, lldpd exécute les commandes des fichiers `/etc/lldpd.d/*.conf` (une commande
  `lldpcli` par ligne, sans le mot `lldpcli`) : c'est la façon de démarrer avec la bonne
  configuration.

Constaté dans cette maquette : sur les membres d'un bond, lldpd émet avec une adresse MAC source
spéciale (celle du bond est sur plusieurs ports) et ajoute le TLV d'agrégation ; il annonce les
sous-interfaces VLAN d'un port ; un port passé en `rx-only` cesse d'émettre **sans** LLDPDU de
*shutdown* (le voisin garde l'ancienne information jusqu'à 120 s), alors qu'arrêter lldpd
(`pkill lldpd`) en envoie une sur chaque port qui émettait.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| créer un bond LACP | `ip link add bond0 type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4` |
| créer un bond actif / secours surveillé par ARP | `ip link add bond0 type bond mode active-backup primary eth0 arp_interval 200 arp_ip_target A.B.C.D` |
| ajouter un membre | `ip link set eth0 down ; ip link set eth0 master bond0` |
| retirer un membre | `ip link set eth0 nomaster` |
| changer une option | `ip link set bond0 type bond min_links 1` |
| supprimer le bond | `ip link del bond0` |
| état complet | `cat /proc/net/bonding/bond0` |
| options du bond | `ip -d link show bond0` |
| compteurs d'un membre | `ip -s link show eth0` |
| voir les LACPDU | `tcpdump -n -e -vv -i eth0 ether proto 0x8809` |
| voir les LLDPDU | `tcpdump -n -e -v -i eth0 ether proto 0x88cc` |
| agrégat dans un pont | `ip link set po1 master br0` ; `bridge link` |
| plusieurs flux | `iperf3 -c <serveur> -P 4` |
| démarrer lldpd | `lldpd` ; avec une configuration : fichier `/etc/lldpd.d/*.conf` puis `lldpd` |
| voisins LLDP | `lldpcli show neighbors [details]` |
| sous-interface VLAN | `ip link add link eth0 name eth0.42 type vlan id 42` |
""")
        )

    # -- the reference commands (used by the states and the instructor texts) ------------------

    def lldp_conf(self) -> str:
        """Part 1: the configuration lldpd reads when it starts on lldp_srv."""
        return (f'configure system description "{self.data.srv_descr}"\n'
                f"configure ports {iface('lldp_srv', 'lldp_l3')} lldp status rx-only\n")

    def cmds_lldp(self) -> List[str]:
        return ["pkill -x lldpd; for i in 1 2 3 4 5 6 7 8 9 10; do pgrep -x lldpd >/dev/null || break; sleep 0.3; done",
                "lldpd"]

    def cmds_bonus(self) -> List[str]:
        d = self.data
        sub = f"eth0.{d.mgmt_vlan}"
        return [f"ip link add link eth0 name {sub} type vlan id {d.mgmt_vlan}",
                f"ip address add {d.ips.lldp_srv} dev {sub}", f"ip link set {sub} up"]

    @staticmethod
    def _bond_cmds(options: str, members=('eth0', 'eth1'), address=None, bond: str = BOND) -> List[str]:
        cmds = [f"ip link add {bond} type bond {options}"]
        for member in members:
            cmds += [f"ip link set {member} down", f"ip link set {member} master {bond}"]
        cmds.append(f"ip link set {bond} up")
        if address is not None:
            cmds.append(f"ip address add {address} dev {bond}")
        return cmds

    def cmds_ab(self) -> List[str]:
        d = self.data
        return self._bond_cmds(f"mode active-backup primary eth0 arp_interval {ARP_INTERVAL} "
                               f"arp_ip_target {d.ips.ab_gw.ip}", address=d.ips.ab_srv)

    def cmds_lacp(self) -> List[str]:
        return self._bond_cmds("mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4",
                               address=self.data.ips.lacp_srv)

    def cmds_isl(self) -> List[str]:
        return ([f"ip link set eth1 nomaster", f"ip link set eth2 nomaster"]
                + self._bond_cmds("mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4",
                                  members=('eth1', 'eth2'))
                + [f"ip link set {BOND} master {BRIDGE}"])

    def cmds_fix_srv(self) -> List[str]:
        return [f"ip link del {BOND}"] + self._bond_cmds(
            "mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4", address=self.data.ips.fix_srv)

    def cmds_fix_sw(self) -> List[str]:
        return [f"ip link set {SW_BOND} type bond min_links 1", "ip link set eth1 down",
                f"ip link set eth1 master {SW_BOND}"]

    # -- states --------------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}", ""]
        lines += [f"{getattr(self.data.ips, name).ip}\t{name}" for name in HOST_NAMES]
        return "\n".join(lines) + "\n"

    def _core_conf(self, name: str, port: str, port_descr: str, mgmt) -> str:
        d = self.data
        return (f"configure system hostname {name}\n"
                f'configure system description "Core switch, datacentre {d.dc.upper()}"\n'
                f"configure system ip management pattern {mgmt.ip}\n"
                f'configure ports eth0 lldp portidsubtype local {port} description "{port_descr}"\n')

    def _switch(self, machine: str, ports: List[str], stp: bool = False):
        """A Linux switch: br0 with *ports* (in this order: it fixes the STP port ids)."""
        self.cmd(machine, f"ip link add {BRIDGE} type bridge stp_state {int(stp)}")
        for port in ports:
            self.cmd(machine, f"ip link set {port} master {BRIDGE}")
        self.cmd(machine, f"ip link set {BRIDGE} up")

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write for the students' own sysctl.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
            self.file(m, "/etc/hosts", self.hosts_content(m))
            self.file(m, "/etc/resolv.conf", "")     # no DNS: fail fast
            self.cmd(m, "for i in /sys/class/net/eth*; do ip link set $(basename $i) up; done; true")
        # part 1: the hidden boxes run lldpd with the identity of the instance
        vlan = d.mgmt_vlan
        for m, name, port, mgmt in (('lldp_core1', d.core1_name, d.core1_port, d.ips.lldp_core1),
                                    ('lldp_core2', d.core2_name, d.core2_port, d.ips.lldp_core2)):
            self.cmd(m, f"ip link add link eth0 name eth0.{vlan} type vlan id {vlan} && "
                        f"ip address add {mgmt} dev eth0.{vlan} && ip link set eth0.{vlan} up")
            self.file(m, LLDP_CONF, self._core_conf(name, port, f"server {d.rack}", mgmt))
            self.cmd(m, "lldpd")
        self.file('lldp_isp', LLDP_CONF, f"configure system hostname {d.isp_name}\n"
                                         'configure system description "Operator access router"\n')
        self.cmd('lldp_isp', "lldpd")
        # part 2: two switches, the gateway behind ab_sw2, the silent cut on ab_sw1
        self._switch('ab_sw1', ['eth0', 'eth1'], stp=True)
        self._switch('ab_sw2', ['eth0', 'eth1', 'eth2'], stp=True)
        self.cmd('ab_gw', f"ip address add {d.ips.ab_gw} dev eth0")
        self.file('ab_sw1', AB_CUT, AB_CUT_SCRIPT, permissions=0o755)
        # part 3: the LACP aggregate of lacp_sw (eth0 first: po1 takes its MAC address)
        for c in self._bond_cmds("mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4", bond=SW_BOND):
            self.cmd('lacp_sw', c)
        self._switch('lacp_sw', [SW_BOND, 'eth2'])
        for m in ('lacp_srv', 'lacp_sw'):
            for dev in ('eth0', 'eth1'):
                self.cmd(m, CAP_CMD.format(dev=dev))
        self.cmd('lacp_pc', f"ip address add {d.ips.lacp_pc} dev eth0; iperf3 -s -D")
        # part 4: two STP switches joined by two parallel links (one of them blocked)
        for m in ISL_SWITCHES:
            self._switch(m, ['eth0', 'eth1', 'eth2'], stp=True)
            for dev in ('eth1', 'eth2'):
                self.cmd(m, CAP_CMD.format(dev=dev))
        self.cmd('isl_pc1', f"ip address add {d.ips.isl_pc1} dev eth0")
        self.cmd('isl_pc2', f"ip address add {d.ips.isl_pc2} dev eth0; iperf3 -s -D")
        # part 5: the three faults
        for c in self._bond_cmds("mode balance-xor miimon 100 xmit_hash_policy layer3+4", address=d.ips.fix_srv):
            self.cmd('fix_srv', c)
        for c in self._bond_cmds("mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4 min_links 3",
                                 members=('eth0',), bond=SW_BOND):
            self.cmd('fix_sw', c)
        self.cmd('fix_sw', "ip link set eth1 down")
        self._switch('fix_sw', [SW_BOND, 'eth2'])
        self.cmd('fix_pc', f"ip address add {d.ips.fix_pc} dev eth0; iperf3 -s -D")
        # LLDP on every switch the students can use (a tool for every part)
        for m in LLDP_SWITCHES:
            self.cmd(m, "lldpd")

    @sre_state(user_allowed=True, description=tr("Partie 2 : couper silencieusement le port de ab_sw1 vers ab_srv"))
    def ab_cut(self):
        self.cmd('ab_sw1', f"{AB_CUT} on")

    @sre_state(user_allowed=True, description=tr("Partie 2 : rétablir le port de ab_sw1 vers ab_srv"))
    def ab_uncut(self):
        self.cmd('ab_sw1', f"{AB_CUT} off")

    # The solve helpers can be applied again: they remove what an earlier application or the
    # students left first.
    def _solve_lldp(self):
        self.file('lldp_srv', LLDP_CONF, self.lldp_conf())
        for c in self.cmds_lldp():
            self.cmd('lldp_srv', c)

    def _solve_bonus(self):
        self.cmd('lldp_srv', f"ip link del eth0.{self.data.mgmt_vlan} 2>/dev/null; true")
        for c in self.cmds_bonus():
            self.cmd('lldp_srv', c)

    def _solve_ab(self):
        self.cmd('ab_srv', f"ip link del {BOND} 2>/dev/null; ip address flush dev eth0; ip address flush dev eth1; "
                           "true")
        for c in self.cmds_ab():
            self.cmd('ab_srv', c)

    def _solve_lacp(self):
        self.cmd('lacp_srv', f"ip link del {BOND} 2>/dev/null; ip address flush dev eth0; ip address flush dev eth1; "
                             "true")
        for c in self.cmds_lacp():
            self.cmd('lacp_srv', c)
        self.cmd('lacp_srv', "sleep 4", step=2)          # LACP negotiation

    def _solve_isl(self):
        for m in ISL_SWITCHES:
            self.cmd(m, f"ip link del {BOND} 2>/dev/null; true")
            for c in self.cmds_isl():
                self.cmd(m, c)
            # the new STP port needs 2 x forward delay (30 s)
            self.cmd(m, f"for i in $(seq 45); do bridge link show dev {BOND} | grep -q 'state forwarding' && break; "
                        "sleep 1; done; true", step=2, timeout=60)

    def _solve_fix(self):
        for c in self.cmds_fix_srv():
            self.cmd('fix_srv', c)
        # applied again, eth1 is already a member of po1: `ip link set eth1 down` would stop the
        # member and the enslaving that follows would do nothing (seen live); release it first
        self.cmd('fix_sw', "ip link set eth1 nomaster 2>/dev/null; true")
        for c in self.cmds_fix_sw():
            self.cmd('fix_sw', c)
        self.cmd('fix_srv', "sleep 4", step=2)           # LACP negotiation

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (LLDP)"))
    def solve_lldp(self):
        self._solve_lldp()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (actif / secours)"))
    def solve_ab(self):
        self._solve_ab()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (LACP serveur - switch)"))
    def solve_lacp(self):
        self._solve_lacp()

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (agrégat entre switchs, ~30 s)"))
    def solve_isl(self):
        self._solve_isl()

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (dépannage)"))
    def solve_fix(self):
        self._solve_fix()

    @sre_state(user_allowed=False, description=tr("Bonus : solution (VLAN annoncé par LLDP)"))
    def solve_bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part, bonus included: every grade element is at its
        maximum when the state returns (it waits for the STP of the isl site, about 30 s).  The
        forms are filled through cheat_answers."""
        self._solve_lldp()
        self._solve_bonus()
        self._solve_ab()
        self._solve_lacp()
        self._solve_isl()
        self._solve_fix()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return re.sub(r'\s+', ' ', str(s or '')).strip().lower()


def _number(s) -> Optional[float]:
    m = re.search(r'-?\d+(?:[.,]\d+)?', str(s or ''))
    return float(m.group(0).replace(',', '.')) if m else None


def _is_int(answer, expected: int) -> bool:
    value = _number(answer)
    return value is not None and value == expected


def _same_mac(answer, expected) -> bool:
    return normalize_mac(answer) != '' and normalize_mac(answer) == normalize_mac(expected)


def _hex_is(answer, expected: int) -> bool:
    text = _norm(answer).replace('0x', '')
    try:
        return int(text, 16) == expected
    except ValueError:
        return False


def _lines(commands: List[str]) -> str:
    return "\n".join(commands) + "\n"


def _code(commands: List[str]) -> str:
    """A shell block for a solution text."""
    return "\n```\n" + _lines(commands) + "```\n"


def _received(ping_output: str) -> int:
    m = re.search(r'(\d+) (?:packets )?received', ping_output or '')
    return int(m.group(1)) if m else 0


def _iperf_ok(single, multi) -> bool:
    """Plausible iperf3 figures over members capped at 20 Mbit/s: one flow about 19 Mbit/s, several
    flows clearly more (two members)."""
    one, many = _number(single), _number(multi)
    return one is not None and many is not None and 10 <= one <= 22 and many >= 1.4 * one and many <= 45


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2)]

    def _ping(self, src: str, dest, step: int = 1) -> bool:
        out, _code = self.test(src, f"{PING} {dest}", step=step, allow_error=True)
        return 'bytes from' in (out or '')

    def _spread(self, src: str, dest, counter_machine: str, ifaces) -> Dict[str, Optional[int]]:
        """64 UDP flows from *src* to *dest* at step 2, the transmit counters of *ifaces* on
        *counter_machine* at steps 1 and 3: ``{iface: packets sent meanwhile}``."""
        before = get_tx_packets(self, counter_machine, ifaces, step=1)
        self.test(src, "sleep 1; " + hping_flows_cmd(dest, count=FLOWS, base_port=FLOW_PORT), step=2, timeout=30,
                  allow_error=True)
        after = get_tx_packets(self, counter_machine, ifaces, step=3)
        return packets_delta(before, after)

    def grade(self):
        super().grade()
        d = self.get_data()

        # ---------------- diagnostics kept in the archive ---------------------------------
        for m, bond in (('ab_srv', BOND), ('lacp_srv', BOND), ('lacp_sw', SW_BOND), ('isl_sw1', BOND),
                        ('isl_sw2', BOND), ('fix_srv', BOND), ('fix_sw', SW_BOND)):
            self.test(m, f"cat /proc/net/bonding/{bond}", allow_error=True)
        for m in ISL_SWITCHES:
            self.test(m, "bridge link", allow_error=True)

        # ---------------- every test is registered on every pass ------------------------------
        links = {m: get_ip_links(self, m) for m in ('lldp_srv', 'ab_srv', 'lacp_srv', 'lacp_sw', 'isl_sw1', 'isl_sw2',
                                                     'fix_srv', 'fix_sw')}
        nb = {m: get_lldp_neighbors(self, m) for m in ('lldp_core1', 'lldp_core2', 'lldp_isp')}
        bonus_ping = self._ping('lldp_srv', d.ips.lldp_core1.ip)

        ab_ping = self._ping('ab_srv', d.ips.ab_gw.ip)
        cut_out, _c = self.test('ab_sw1', f"{AB_CUT} pulse {CUT_SECONDS}", step=2, timeout=CUT_SECONDS + 20,
                                allow_error=True)
        failover_out, _c = self.test('ab_srv', f"ping -i {PING_INTERVAL} -c {PING_COUNT} -W 1 {d.ips.ab_gw.ip}",
                                     step=2, timeout=CUT_SECONDS + 20, allow_error=True)

        lacp_ping = self._ping('lacp_srv', d.ips.lacp_pc.ip)
        lacp_delta = self._spread('lacp_srv', d.ips.lacp_pc.ip, 'lacp_srv', ('eth0', 'eth1'))

        isl_ping12 = self._ping('isl_pc1', d.ips.isl_pc2.ip)
        isl_ping21 = self._ping('isl_pc2', d.ips.isl_pc1.ip)
        isl_delta1 = self._spread('isl_pc1', d.ips.isl_pc2.ip, 'isl_sw1', ('eth1', 'eth2'))
        isl_delta2 = self._spread('isl_pc2', d.ips.isl_pc1.ip, 'isl_sw2', ('eth1', 'eth2'))

        fix_ping = self._ping('fix_srv', d.ips.fix_pc.ip)
        delivered_out, _c = self.test(
            'fix_pc', f"timeout 8 tcpdump -n -l -i eth0 -c {FLOWS} 'udp and dst portrange {FLOW_PORT}-"
                      f"{FLOW_PORT + FLOWS - 1}' 2>/dev/null | wc -l", step=2, timeout=20, allow_error=True)
        fix_delta = self._spread('fix_srv', d.ips.fix_pc.ip, 'fix_srv', ('eth0', 'eth1'))

        # ---------------- what the tests say ----------------------------------------------------
        def bond(m, name=BOND):
            return bond_info(links[m], name)

        def spread_ok(delta) -> bool:
            return all((value or 0) >= MIN_PER_LINK for value in delta.values())

        # part 1
        seen = {m: lldp_neighbor(nb[m], interface='eth0', name='lldp_srv') for m in nb}
        cores_see = bool(seen['lldp_core1']) and bool(seen['lldp_core2'])
        descr_ok = all(n is not None and _norm(n.get('descr')) == _norm(d.srv_descr)
                       for n in (seen['lldp_core1'], seen['lldp_core2']))
        rx_only_ok = cores_see and seen['lldp_isp'] is None
        # bonus
        srv_vlans = vlan_links(links['lldp_srv'])
        bonus_vlan = any(v.get('link') == 'eth0' and v.get('id') == d.mgmt_vlan and v.get('up')
                         for v in srv_vlans.values())
        # part 2
        ab = bond('ab_srv')
        ab_is_bond = bool(ab) and ab['mode'] == 'active-backup' and bond_slaves(ab) == ['eth0', 'eth1']
        ab_primary = ab_is_bond and ab.get('primary') == 'eth0'
        ab_arp = ab_is_bond and ab['arp_interval'] > 0 and str(d.ips.ab_gw.ip) in ab['arp_ip_target']
        ab_lost = PING_COUNT - _received(failover_out)
        ab_failover = ab_primary and ab_lost <= MAX_LOST and _received(failover_out) > 0
        # part 3
        srv3, sw3 = bond('lacp_srv'), bond('lacp_sw', SW_BOND)
        lacp_is_bond = bool(srv3) and srv3['mode'] == '802.3ad' and bond_slaves(srv3) == ['eth0', 'eth1']
        lacp_srv_agg = (lacp_is_bond and lacp_aggregated(srv3) == ['eth0', 'eth1']
                        and lacp_partner_is(srv3, [sw3['address'] if sw3 else '']))
        lacp_sw_agg = (lacp_is_bond and bool(sw3) and lacp_aggregated(sw3) == ['eth0', 'eth1']
                       and lacp_partner_is(sw3, [srv3['address']]))
        # part 4
        isl = {m: bond(m) for m in ISL_SWITCHES}
        isl_is_bond = {m: bool(isl[m]) and isl[m]['mode'] == '802.3ad' and bond_slaves(isl[m]) == ['eth1', 'eth2']
                       for m in ISL_SWITCHES}
        other = {'isl_sw1': 'isl_sw2', 'isl_sw2': 'isl_sw1'}
        isl_agg = {m: isl_is_bond[m] and lacp_aggregated(isl[m]) == ['eth1', 'eth2']
                   and lacp_partner_is(isl[m], [isl[other[m]]['address'] if isl[other[m]] else ''])
                   for m in ISL_SWITCHES}
        isl_ports = {m: bridge_ports(links[m]).get(BRIDGE, []) for m in ISL_SWITCHES}
        isl_in_bridge = {m: isl_is_bond[m] and BOND in isl_ports[m] and 'eth1' not in isl_ports[m]
                         and 'eth2' not in isl_ports[m] for m in ISL_SWITCHES}
        isl_forwarding = {m: isl_in_bridge[m]
                          and port_states(bridge_info(links[m], BRIDGE)).get(BOND) == 'forwarding'
                          for m in ISL_SWITCHES}
        isl_hash = {m: isl_is_bond[m] and isl[m].get('xmit_hash_policy') in HASH_POLICIES for m in ISL_SWITCHES}
        both_in_bridge = all(isl_in_bridge.values())
        # part 5
        srv5, sw5 = bond('fix_srv'), bond('fix_sw', SW_BOND)
        fix_srv_lacp = bool(srv5) and srv5['mode'] == '802.3ad' and bond_slaves(srv5) == ['eth0', 'eth1']
        fix_member = link_master(links['fix_sw'], 'eth1') == SW_BOND
        fix_min_links = bool(sw5) and sw5['min_links'] <= 2
        fix_agg = (fix_srv_lacp and bool(sw5) and lacp_aggregated(srv5) == ['eth0', 'eth1']
                   and lacp_aggregated(sw5) == ['eth0', 'eth1'] and lacp_partner_is(srv5, [sw5['address']])
                   and lacp_partner_is(sw5, [srv5['address']]) and sw5['carrier'])
        try:
            delivered = int((delivered_out or '0').strip().splitlines()[-1])
        except (ValueError, IndexError):
            delivered = 0
        fix_delivery = delivered >= MIN_DELIVERED and spread_ok(fix_delta)

        # ---------------- texts -------------------------------------------------------------
        root, non_root = isl_roles(d)
        sites = tr("""
| partie | site | machines | réseau |
|--------|------|----------|--------|
| 1 — LLDP (et bonus) | `lldp_*` | `lldp_srv`, câblé à trois équipements **invisibles** et sans terminal | — (bonus : VLAN d'administration) |
| 2 — actif / secours | `ab_*` | `ab_srv`, les switchs `ab_sw1` et `ab_sw2`, la passerelle `ab_gw` | `{ab}` : `ab_gw` `{ab_gw}`, `ab_srv` `{ab_srv}` |
| 3 — LACP serveur ↔ switch | `lacp_*` | `lacp_srv`, le switch `lacp_sw`, `lacp_pc` | `{lacp}` : `lacp_srv` `{lacp_srv}`, `lacp_pc` `{lacp_pc}` |
| 4 — agrégat entre switchs | `isl_*` | les switchs `isl_sw1` et `isl_sw2`, `isl_pc1` et `isl_pc2` | `{isl}` : `isl_pc1` `{isl_pc1}`, `isl_pc2` `{isl_pc2}` |
| 5 — dépannage | `fix_*` | `fix_srv`, le switch `fix_sw`, `fix_pc` | `{fix}` : `fix_srv` `{fix_srv}`, `fix_pc` `{fix_pc}` |
""").format(ab=d.nets.ab, ab_gw=d.ips.ab_gw.ip, ab_srv=d.ips.ab_srv.ip, lacp=d.nets.lacp, lacp_srv=d.ips.lacp_srv.ip,
            lacp_pc=d.ips.lacp_pc.ip, isl=d.nets.isl, isl_pc1=d.ips.isl_pc1.ip, isl_pc2=d.ips.isl_pc2.ip,
            fix=d.nets.fix, fix_srv=d.ips.fix_srv.ip, fix_pc=d.ips.fix_pc.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="f762d9230429125b",
            description=tr("""
Lisez l'onglet **Informations** : il présente l'agrégation de liens (modes du bonding Linux,
surveillance des membres, répartition par flux, LACP, agrégat dans un switch) et LLDP.

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie, chacun de sa couleur sur
le schéma. Chaque réseau du schéma est **un câble** entre deux machines.
""")
            + sites
            + tr("""
- Les switchs (`ab_sw1`, `ab_sw2`, `lacp_sw`, `isl_sw1`, `isl_sw2`, `fix_sw`) sont des machines
  Linux dont un pont `br0` relie les ports. Ceux des sites `ab`, `lacp` et `fix` sont **déjà
  configurés** : vous pouvez les observer (agrégat `po1`, `/proc/net/bonding/po1`, `bridge link`)
  mais vous n'avez à les modifier qu'en partie 5. `lldpd` tourne sur tous les switchs.
- Les adresses ci-dessus sont dans `/etc/hosts` de toutes les machines, sauf celles des serveurs
  et de l'agrégat, que vous poserez. Il n'y a pas de DNS.
- Les liens membres des sites `lacp` et `isl` sont **bridés à 20 Mbit/s** (`tc qdisc show`, aux
  deux bouts) pour que la répartition du débit se mesure : n'y touchez pas. `lacp_pc` et `isl_pc2`
  font tourner un serveur `iperf3`.
- **Particularité de la maquette** : un lien n'y perd jamais sa porteuse à l'autre bout.
  `ip link set eth1 down` sur une machine laisse l'interface d'en face `UP`.

**Consignes.**

- Le nom des agrégats que vous créez est imposé : **`{bond}`** (sur les serveurs et sur les
  switchs du site `isl`).
- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Toute la configuration est volatile (`ip`, `lldpcli`) : elle ne survit pas au redémarrage d'une
  machine.
- Un port de pont avec STP met **30 s** à transmettre ; LACP s'accorde en quelques secondes ; un
  voisin LLDP apparaît dans les 30 s.

**Évaluation.** Chaque évaluation lit vos réponses, l'état des agrégats aux deux bouts (`ip -d
link`), les voisins LLDP vus **par les équipements d'en face**, lance des `ping`, envoie 64 flux UDP
(`hping3`) à travers chaque agrégat pour compter les paquets de chaque membre, et **coupe pendant
{cut} s le port de `ab_sw1` vers `ab_srv`** (partie 2 : la coupure ne touche que ce câble).
""").format(bond=BOND, cut=CUT_SECONDS)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_lldp`, `solve_ab`, `solve_lacp`, `solve_isl`, `solve_fix` et `solve_bonus`
appliquent la solution d'une seule partie et remplissent ses formulaires ; `final` les applique
toutes (il attend les 30 s de STP du site `isl`) : une évaluation lancée dès son retour donne tous les
points, bonus compris.

Valeurs de cette instance : `lldp_core1` = `{core1}` (port `{port1}`, administration `{mgmt1}`),
`lldp_core2` = `{core2}` (port `{port2}`, administration `{mgmt2}`), VLAN d'administration
**{vlan}**, boîtier opérateur `{isp}` ; description à annoncer : `{descr}`. Racine STP du site `isl` :
`{root}` (plus petite adresse MAC), port bloqué avant l'agrégat : `{blocked}`. Adresse système de
`lacp_sw` (MAC de `po1` = celle de son `eth0`) : `{lacp_sw_mac}`.

Pannes du site `fix` : `fix_srv` en `balance-xor` (statique) face au LACP de `fix_sw` ; `eth1` de
`fix_sw` hors de `po1` (et arrêtée) ; `min_links 3` sur `po1` (deux membres au plus : pas de porteuse,
coupure totale).
""").format(core1=d.core1_name, port1=d.core1_port, mgmt1=d.ips.lldp_core1.ip, core2=d.core2_name,
            port2=d.core2_port, mgmt2=d.ips.lldp_core2.ip, vlan=d.mgmt_vlan, isp=d.isp_name, descr=d.srv_descr,
            root=root, blocked=isl_blocked_port(d).replace('_eth', ' eth'),
            lacp_sw_mac=mac_text(d, 'lacp_sw_eth0'))),
        )

        # =====================================================================
        # Part 1 — LLDP (site lldp)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("lldp"), tr("Partie 1 — LLDP (site lldp)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Qui est au bout de mes câbles ?"),
            hash="9e89413735b85296",
            description=tr("""
Le serveur `lldp_srv` a trois interfaces câblées : `eth0`, `eth1` et `eth2`. Les équipements
d'en face sont **invisibles** sur le schéma et vous n'y avez pas accès : deux switchs de cœur de
réseau (sur `eth0` et `eth1`) et le boîtier d'un opérateur (sur `eth2`). Tous les trois font tourner
LLDP (sections @@ref:lldp@@ et @@ref:lldpd@@).

1. Démarrez `lldpd` sur `lldp_srv` de sorte que :
   - il annonce la description système **`{descr}`** ;
   - il **n'annonce rien** sur `eth2`, tournée vers l'opérateur (réception seule) : vous voulez voir
     ce boîtier, pas vous montrer à lui.

   Le plus simple est d'écrire la configuration dans `/etc/lldpd.d/sre.conf` **avant** de lancer
   `lldpd`. Si vous avez déjà démarré `lldpd` sans cette configuration, l'opérateur vous a vu :
   arrêtez-le (`pkill lldpd` envoie une LLDPDU de *shutdown* qui vous efface chez lui), puis
   relancez-le ; un simple `lldpcli configure ports eth2 lldp status rx-only` le laisserait vous
   garder jusqu'à 120 s.
2. Avec `lldpcli show neighbors`, identifiez les équipements d'en face (attendez jusqu'à 30 s).

L'évaluation interroge les équipements d'en face : les deux switchs doivent vous voir avec cette
description, le boîtier de l'opérateur ne doit pas vous voir.
""").format(descr=d.srv_descr)
            + instructor(tr("""
**Solution.** Fichier `/etc/lldpd.d/sre.conf` sur `lldp_srv` :

```
{conf}```

puis (re)démarrage :
{cmds}
`lldpcli show neighbors` montre `{core1}` sur `eth0`, `{core2}` sur `eth1` et `{isp}` sur `eth2`.
""").format(conf=self.net_scheme.lldp_conf(), cmds=_code(self.net_scheme.cmds_lldp()), core1=d.core1_name, core2=d.core2_name,
            isp=d.isp_name)),
        )
        q_disc_cheat = {"core1_name": d.core1_name, "core1_port": d.core1_port, "core1_mgmt": str(d.ips.lldp_core1.ip),
                        "core2_name": d.core2_name, "core2_port": d.core2_port, "core2_mgmt": str(d.ips.lldp_core2.ip)}
        q_disc = self.question_form(
            section=self.section(1),
            title=tr("Le câblage, vu par LLDP"),
            hash="90567480ac7e417f",
            description=tr("""
Relevez dans `lldpcli show neighbors` ce que les switchs annoncent :

- `eth0` de `lldp_srv` arrive sur le switch @@{core1_name:[A-Za-z0-9._-]+}@@, port @@{core1_port:[A-Za-z0-9/._-]+}@@ ; son adresse d'administration est @@{core1_mgmt:[0-9.]+}@@
- `eth1` de `lldp_srv` arrive sur le switch @@{core2_name:[A-Za-z0-9._-]+}@@, port @@{core2_port:[A-Za-z0-9/._-]+}@@ ; son adresse d'administration est @@{core2_mgmt:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** `{core1}`, port `{port1}`, `{mgmt1}` ; `{core2}`, port `{port2}`, `{mgmt2}` (lignes
`SysName`, `PortID` et `MgmtIP`).
""").format(core1=d.core1_name, port1=d.core1_port, mgmt1=d.ips.lldp_core1.ip, core2=d.core2_name,
            port2=d.core2_port, mgmt2=d.ips.lldp_core2.ip)),
            cheat_answers={"final": q_disc_cheat, "solve_lldp": q_disc_cheat},
        )
        q_proto_cheat = {"dst": LLDP_MAC, "ethertype": "0x88cc", "ttl": str(LLDP_TTL), "interval": str(LLDP_TX_INTERVAL)}
        q_proto = self.question_form(
            section=self.section(1),
            title=tr("Le protocole"),
            hash="df23fa15335b97ef",
            description=tr("""
Capturez une LLDPDU sur `lldp_srv` (`tcpdump -n -e -v -i eth0 ether proto 0x88cc`, jusqu'à 30 s
d'attente) :

- adresse MAC de destination : @@{dst:[0-9A-Fa-f:.-]+}@@
- EtherType : @@{ethertype:(0x)?[0-9A-Fa-f]+}@@
- durée de vie (TTL) annoncée, en secondes : @@{ttl:[0-9]+}@@
- intervalle entre deux LLDPDU d'un même switch, en secondes : @@{interval:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** `{mac}` (*nearest bridge*) ; `0x88cc` ; {ttl} s ; {interval} s (TTL = intervalle × 4).
""").format(mac=LLDP_MAC, ttl=LLDP_TTL, interval=LLDP_TX_INTERVAL)),
            cheat_answers={"final": q_proto_cheat, "solve_lldp": q_proto_cheat},
        )
        self.add_grade_element(
            title=no_tr("lldp_seen"), max_grade=4, grade_part=part1, grade=2 * int(bool(seen['lldp_core1']))
            + 2 * int(bool(seen['lldp_core2'])),
            description=tr("lldpd tourne sur lldp_srv : les deux switchs de cœur le voient"))
        self.add_grade_element(
            title=no_tr("lldp_descr"), max_grade=2, grade_part=part1, grade=2 * int(descr_ok),
            description=tr("la description système demandée est annoncée"))
        self.add_grade_element(
            title=no_tr("lldp_rx_only"), max_grade=4, grade_part=part1, grade=4 * int(rx_only_ok),
            description=tr("le boîtier de l'opérateur ne voit pas lldp_srv (les switchs, si)"))
        disc_ok = [_norm(q_disc.get("core1_name")) == _norm(d.core1_name),
                   _norm(q_disc.get("core1_port")) == _norm(d.core1_port),
                   _norm(q_disc.get("core1_mgmt")) == str(d.ips.lldp_core1.ip),
                   _norm(q_disc.get("core2_name")) == _norm(d.core2_name),
                   _norm(q_disc.get("core2_port")) == _norm(d.core2_port),
                   _norm(q_disc.get("core2_mgmt")) == str(d.ips.lldp_core2.ip)]
        self.add_grade_element(
            title=no_tr("q_lldp_discovery"), max_grade=6, grade_part=part1, grade=sum(disc_ok),
            description=tr("noms, ports et adresses d'administration des deux switchs"))
        proto_ok = [_same_mac(q_proto.get("dst"), LLDP_MAC), _hex_is(q_proto.get("ethertype"), 0x88cc),
                    _is_int(q_proto.get("ttl"), LLDP_TTL), _is_int(q_proto.get("interval"), LLDP_TX_INTERVAL)]
        self.add_grade_element(
            title=no_tr("q_lldp_protocol"), max_grade=2, grade_part=part1, grade=sum(proto_ok) // 2,
            description=tr("destination, EtherType, TTL et intervalle des LLDPDU"))

        # =====================================================================
        # Part 2 — active-backup (site ab)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("ab"), tr("Partie 2 — actif / secours vers deux switchs (site ab)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un serveur relié à deux switchs"),
            hash="ea278096edd63e9b",
            description=tr("""
`ab_srv` est relié par `eth0` au switch `ab_sw1` et par `eth1` au switch `ab_sw2` ; les deux switchs
sont reliés entre eux et la passerelle `ab_gw` (`{gw}`) est derrière `ab_sw2`. Deux switchs
différents sans MLAG : un agrégat LACP est impossible, c'est un travail pour le mode
`active-backup` (sections @@ref:modes@@ et @@ref:monitoring@@).

1. Créez sur `ab_srv` le bond **`{bond}`** en mode `active-backup` avec `eth0` et `eth1`, `eth0`
   préférée (`primary`), surveillé par **`miimon 100`** pour commencer, et donnez-lui l'adresse
   `{srv}`. Vérifiez que `ab_srv` joint `ab_gw` et regardez `/proc/net/bonding/{bond}`.
2. Lancez `ping {gw_name}` sur `ab_srv`, puis appliquez l'état **`ab_cut`** (onglet *Appliquer une
   configuration*) : il coupe le câble `ab_l1` du côté de `ab_sw1` (les trames sont jetées, la
   porteuse reste). Que fait le bond ? Rétablissez avec l'état **`ab_uncut`**.
3. Remplacez `miimon` par la **surveillance ARP** : `arp_interval {arp}` vers la cible `{gw}`
   (`ip link set {bond} type bond miimon 0 arp_interval {arp} arp_ip_target {gw}`), et refaites
   l'expérience : la bascule doit prendre moins d'une seconde, puis le bond revient sur `eth0`.

Chaque évaluation coupe elle-même ce câble pendant {cut} s pendant que `ab_srv` envoie un `ping`
vers `ab_gw` toutes les 100 ms : moins de 2 s de pertes sont tolérées. Une coupure laissée en
place par `ab_cut` n'est pas levée par l'évaluation.
""").format(gw=d.ips.ab_gw.ip, gw_name='ab_gw', bond=BOND, srv=d.ips.ab_srv, arp=ARP_INTERVAL, cut=CUT_SECONDS)
            + instructor(tr("""
**Solution** (directement avec la surveillance ARP) sur `ab_srv` :
{cmds}
Avec `miimon` seul, la coupure ne change rien à la porteuse de `eth0` : le bond reste sur `eth0`
et tout est perdu pendant la coupure (mesuré : 60 `ping` sur 60). Avec `arp_interval {arp}`, les
requêtes ARP vers `ab_gw` restent sans réponse, `eth0` est déclarée en panne après 2 intervalles et
`eth1` prend le relais (mesuré : 0,6 s de perte) ; à la fin de la coupure, `eth0` redevient active
(`primary`).
""").format(cmds=_code(self.net_scheme.cmds_ab()), arp=ARP_INTERVAL)),
        )
        q_ab_cheat = {"miimon_cut": "stays", "why": "carrier", "mac": "same"}
        q_ab = self.question_form(
            section=self.section(1),
            title=tr("Ce que miimon ne voit pas"),
            hash="dc8d096d7a083756",
            description=tr("""
- avec `miimon` seul, pendant la coupure de `ab_cut` : @@{miimon_cut:>le bond reste sur eth0 : tout le trafic est perdu pendant la coupure>>>stays|le bond bascule sur eth1 en moins d'une seconde>>>switches|le bond bascule sans cesse entre eth0 et eth1>>>flaps}@@
- pourquoi ? @@{why:>eth0 garde sa porteuse : miimon ne teste que le lien local, pas le chemin>>>carrier|miimon n'est pas actif par défaut>>>default|la coupure est trop courte pour miimon>>>short}@@
- après une bascule sur `eth1`, l'adresse MAC de `bond0` : @@{mac:>ne change pas : tous les membres portent l'adresse du bond, un ARP gratuit annonce le nouveau chemin aux switchs>>>same|devient celle de eth1 : ab_gw doit refaire une requête ARP>>>eth1|est tirée au hasard>>>random}@@
""")
            + instructor(tr("""
**Solution.** Le bond reste sur `eth0` ; `eth0` garde sa porteuse (seul le lien local est testé) ;
l'adresse MAC ne change pas (ARP gratuit par `eth1`).
""")),
            cheat_answers={"final": q_ab_cheat, "solve_ab": q_ab_cheat},
        )
        self.add_grade_element(
            title=no_tr("ab_bond"), max_grade=3, grade_part=part2, grade=3 * int(ab_is_bond),
            description=tr("bond0 en active-backup avec eth0 et eth1"))
        self.add_grade_element(
            title=no_tr("ab_primary"), max_grade=2, grade_part=part2, grade=2 * int(ab_primary),
            description=tr("eth0 est le membre préféré (primary)"))
        self.add_grade_element(
            title=no_tr("ab_arp"), max_grade=3, grade_part=part2, grade=3 * int(ab_arp),
            description=tr("surveillance ARP vers ab_gw"))
        self.add_grade_element(
            title=no_tr("ab_ping"), max_grade=2, grade_part=part2, grade=2 * int(ab_is_bond and ab_ping),
            description=tr("ab_srv joint ab_gw par bond0"))
        self.add_grade_element(
            title=no_tr("ab_failover"), max_grade=5, grade_part=part2, grade=5 * int(ab_failover),
            description=tr("coupure de 6 s du câble ab_l1 : moins de 2 s de pertes"))
        q_ab_ok = [_norm(q_ab.get("miimon_cut")) == "stays", _norm(q_ab.get("why")) == "carrier",
                   _norm(q_ab.get("mac")) == "same"]
        self.add_grade_element(
            title=no_tr("q_ab"), max_grade=3, grade_part=part2, scope=CHOICE_SCOPE, grade=sum(q_ab_ok),
            description=tr("miimon face à une coupure silencieuse ; adresse MAC après bascule"))

        # =====================================================================
        # Part 3 — LACP between a server and a switch (site lacp)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("lacp"), tr("Partie 3 — LACP entre un serveur et un switch (site lacp)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un agrégat LACP vers un switch"),
            hash="9e97a6bdd5c29509",
            description=tr("""
`lacp_srv` est relié au switch `lacp_sw` par deux câbles (`eth0` et `eth1` des deux côtés). Côté
switch, l'agrégat **`{sw_bond}`** est déjà configuré : mode `802.3ad`, `lacp_rate fast`,
`xmit_hash_policy layer3+4`, port du pont `br0` avec `eth2` (vers `lacp_pc`, `{pc}`). Sections
@@ref:hashing@@, @@ref:lacp@@ et @@ref:linux@@.

1. Créez sur `lacp_srv` le bond **`{bond}`** en mode `802.3ad` avec `eth0` et `eth1`, en demandant
   des LACPDU rapides (`lacp_rate fast`) et une répartition par flux selon les adresses IP **et les
   ports** ; donnez-lui l'adresse `{srv}`. Vérifiez dans `/proc/net/bonding/{bond}` que les deux
   membres sont dans le **même agrégateur** et que le partenaire est bien `lacp_sw`, et que
   `lacp_srv` joint `lacp_pc`.
2. Mesurez le débit vers `lacp_pc` avec un flux (`iperf3 -c lacp_pc`) puis quatre (`iperf3 -c
   lacp_pc -P 4`) : chaque membre est bridé à 20 Mbit/s.
3. Sur `lacp_srv`, arrêtez `eth1` (`ip link set eth1 down`) et observez `/proc/net/bonding/{sw_bond}`
   sur `lacp_sw` pendant quelques secondes ; puis remettez `eth1` en marche.

L'évaluation vérifie l'agrégat aux deux bouts et envoie 64 flux UDP de `lacp_srv` vers `lacp_pc` :
chacun des deux membres doit en transporter au moins {min_link}.
""").format(sw_bond=SW_BOND, pc=d.ips.lacp_pc.ip, bond=BOND, srv=d.ips.lacp_srv, min_link=MIN_PER_LINK)
            + instructor(tr("""
**Solution** sur `lacp_srv` :
{cmds}
Avec la politique par défaut (`layer2`), tout le trafic vers `lacp_pc` prendrait le même membre :
un seul flux comme quatre plafonnent à ~19 Mbit/s. Avec `layer3+4`, quatre flux font ~38 Mbit/s.
`eth1` arrêtée d'un seul côté : `lacp_sw` garde sa porteuse mais ne reçoit plus de LACPDU ; après
3 s (3 × 1 s, `lacp_rate fast`), son `eth1` n'est plus synchronisée et elle quitte l'agrégateur
quelques secondes plus tard (« Number of ports: 1 »). Un agrégat statique, lui, continuerait d'envoyer
la moitié des flux dans le câble mort.
""").format(cmds=_code(self.net_scheme.cmds_lacp()))),
        )
        lacp_sw_mac = mac_text(d, 'lacp_sw_eth0')
        q_lacpdu_cheat = {"dst": LACP_MAC, "ethertype": "0x8809", "system": lacp_sw_mac,
                          "priority": str(LACP_PRIORITY), "key": str(LACP_KEY), "interval": "1"}
        q_lacpdu = self.question_form(
            section=self.section(1),
            title=tr("Les LACPDU"),
            hash="823d57baa4e65288",
            description=tr("""
Capturez une LACPDU **reçue** sur `lacp_srv` (`tcpdump -n -e -vv -i eth0 ether proto 0x8809` : la
source est le switch) :

- adresse MAC de destination : @@{dst:[0-9A-Fa-f:.-]+}@@ ; EtherType : @@{ethertype:(0x)?[0-9A-Fa-f]+}@@
- identifiant système de l'acteur (`lacp_sw`) : adresse MAC @@{system:[0-9A-Fa-f:.-]+}@@, priorité @@{priority:[0-9]+}@@
- clé de l'acteur : @@{key:[0-9]+}@@
- intervalle entre deux LACPDU, en secondes : @@{interval:[0-9]+([.,][0-9]+)?}@@
""")
            + instructor(tr("""
**Solution.** `{dst}` (*slow protocols*) ; `0x8809` ; `{system}` (la MAC de `po1`, celle de `eth0`
de `lacp_sw`, son premier membre), priorité {priority} ; clé {key} (10 Gbit/s, duplex intégral) ;
1 s (`lacp_rate fast` des deux côtés).
""").format(dst=LACP_MAC, system=lacp_sw_mac, priority=LACP_PRIORITY, key=LACP_KEY)),
            cheat_answers={"final": q_lacpdu_cheat, "solve_lacp": q_lacpdu_cheat},
        )
        q_lacp_perf_cheat = {"single": "19", "multi": "38", "seconds": "3"}
        q_lacp_perf = self.question_form(
            section=self.section(1),
            title=tr("Débit et panne d'un membre"),
            hash="407dd809ee404828",
            description=tr("""
- débit d'un flux `iperf3`, en Mbit/s : @@{single:[0-9]+([.,][0-9]+)?}@@ ; de quatre flux (`-P 4`, ligne `SUM` du récepteur) : @@{multi:[0-9]+([.,][0-9]+)?}@@
- `eth1` arrêtée sur `lacp_srv` seulement : au bout de combien de secondes environ `lacp_sw` la déclare-t-il non synchronisée (elle n'a plus de porteuse en panne de son côté) ? @@{seconds:[0-9]+([.,][0-9]+)?}@@
""")
            + instructor(tr("""
**Solution.** ~19 Mbit/s et ~38 Mbit/s (deux membres de 20 Mbit/s ; recommencer si les quatre flux
tombent sur le même membre) ; 3 s (expiration des informations du partenaire en *fast*), avant de la
sortir de l'agrégateur.
""")),
            cheat_answers={"final": q_lacp_perf_cheat, "solve_lacp": q_lacp_perf_cheat},
        )
        self.add_grade_element(
            title=no_tr("lacp_bond"), max_grade=3, grade_part=part3, grade=3 * int(lacp_is_bond),
            description=tr("bond0 en 802.3ad avec eth0 et eth1"))
        self.add_grade_element(
            title=no_tr("lacp_fast"), max_grade=2, grade_part=part3,
            grade=2 * int(lacp_is_bond and srv3.get('lacp_rate') == 'fast'),
            description=tr("LACPDU rapides (lacp_rate fast)"))
        self.add_grade_element(
            title=no_tr("lacp_hash"), max_grade=2, grade_part=part3,
            grade=2 * int(lacp_is_bond and srv3.get('xmit_hash_policy') in HASH_POLICIES),
            description=tr("répartition selon les adresses et les ports (layer3+4)"))
        self.add_grade_element(
            title=no_tr("lacp_srv_aggregated"), max_grade=3, grade_part=part3, grade=3 * int(lacp_srv_agg),
            description=tr("lacp_srv : les deux membres agrégés, partenaire lacp_sw"))
        self.add_grade_element(
            title=no_tr("lacp_sw_aggregated"), max_grade=2, grade_part=part3, grade=2 * int(lacp_sw_agg),
            description=tr("lacp_sw : les deux membres agrégés, partenaire lacp_srv"))
        self.add_grade_element(
            title=no_tr("lacp_ping"), max_grade=2, grade_part=part3, grade=2 * int(lacp_is_bond and lacp_ping),
            description=tr("lacp_srv joint lacp_pc par bond0"))
        self.add_grade_element(
            title=no_tr("lacp_spread"), max_grade=3, grade_part=part3,
            grade=3 * int(lacp_srv_agg and spread_ok(lacp_delta)),
            description=tr("64 flux UDP : les deux membres en transportent"))
        lacpdu_ok = [_same_mac(q_lacpdu.get("dst"), LACP_MAC), _hex_is(q_lacpdu.get("ethertype"), 0x8809),
                     _same_mac(q_lacpdu.get("system"), lacp_sw_mac), _is_int(q_lacpdu.get("priority"), LACP_PRIORITY),
                     _is_int(q_lacpdu.get("key"), LACP_KEY), _is_int(q_lacpdu.get("interval"), 1)]
        self.add_grade_element(
            title=no_tr("q_lacpdu"), max_grade=3, grade_part=part3, grade=sum(lacpdu_ok) // 2,
            description=tr("contenu d'une LACPDU"))
        self.add_grade_element(
            title=no_tr("q_lacp_iperf"), max_grade=1, grade_part=part3,
            grade=int(_iperf_ok(q_lacp_perf.get("single"), q_lacp_perf.get("multi"))),
            description=tr("débit d'un flux et de quatre flux"))
        seconds = _number(q_lacp_perf.get("seconds"))
        self.add_grade_element(
            title=no_tr("q_lacp_one_side"), max_grade=1, grade_part=part3,
            grade=int(seconds is not None and 2 <= seconds <= 6),
            description=tr("détection d'une panne d'un seul côté par LACP"))

        # =====================================================================
        # Part 4 — an aggregate between two switches (site isl)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("isl"), tr("Partie 4 — agrégat entre deux switchs (site isl)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux liens entre deux switchs"),
            hash="d413f162c748b16a",
            description=tr("""
Les switchs `isl_sw1` et `isl_sw2` sont reliés par deux câbles (`eth1` et `eth2` des deux côtés) ;
`isl_pc1` est sur `eth0` de `isl_sw1`, `isl_pc2` (serveur `iperf3`) sur `eth0` de `isl_sw2`. Le pont
`br0` de chaque switch, avec STP, a pour ports `eth0`, `eth1` et `eth2` (section @@ref:bridge@@).

1. Regardez `bridge link` sur les deux switchs : un des deux câbles est bloqué par STP. Mesurez le
   débit de `isl_pc1` vers `isl_pc2` avec quatre flux (`iperf3 -c isl_pc2 -P 4`).
2. Sur **les deux switchs**, remplacez les deux ports `eth1` et `eth2` du pont par un agrégat LACP
   **`{bond}`** (rapide, réparti selon les adresses et les ports), port de `br0`. Attendez les 30 s
   de STP, vérifiez l'agrégat et `bridge link`, puis mesurez de nouveau.

L'évaluation vérifie les deux agrégats, le pont, et envoie 64 flux UDP dans chaque sens : chacun
des deux câbles doit en transporter au moins {min_link} dans chaque sens.
""").format(bond=BOND, min_link=MIN_PER_LINK)
            + instructor(tr("""
**Solution** sur `isl_sw1` **et** sur `isl_sw2` :
{cmds}
Avant : `{root}` est la racine (plus petite adresse MAC à priorité égale) ; `{other}` reçoit les
BPDU de la racine sur `eth1` et `eth2` à coût égal et garde le port relié au port de plus petit
identifiant de la racine (`eth1`, ajouté avant `eth2`) : **`{other}` `eth2`** est bloqué ; un seul
lien sert, quatre flux font ~19 Mbit/s. Après : STP ne voit qu'un port `{bond}` de chaque côté, rien
n'est bloqué, quatre flux font ~38 Mbit/s.
""").format(cmds=_code(self.net_scheme.cmds_isl()), root=root, other=non_root, bond=BOND)),
        )
        blocked_choices = ">isl_sw1 eth1>>>isl_sw1_eth1|isl_sw1 eth2>>>isl_sw1_eth2|isl_sw2 eth1>>>isl_sw2_eth1|" \
                          "isl_sw2 eth2>>>isl_sw2_eth2"
        q_isl_cheat = {"blocked": isl_blocked_port(d), "stp_view": "one_port", "before": "19", "after": "38"}
        q_isl = self.question_form(
            section=self.section(1),
            title=tr("STP et agrégat"),
            hash="34e14a335abc3ce7",
            description=tr("- avant l'agrégat, le port bloqué par STP est : @@{blocked:" + blocked_choices + "}@@\n")
            + tr("""- avec l'agrégat : @@{stp_view:>STP ne voit qu'un port (bond0) entre les deux switchs : rien n'est bloqué, les deux câbles servent>>>one_port|STP voit deux ports et en bloque toujours un>>>two_ports|il faut désactiver STP pour que l'agrégat fonctionne>>>stp_off}@@
- débit de quatre flux de `isl_pc1` vers `isl_pc2`, en Mbit/s, avant l'agrégat : @@{before:[0-9]+([.,][0-9]+)?}@@ ; après : @@{after:[0-9]+([.,][0-9]+)?}@@
""")
            + instructor(tr("""
**Solution.** `{blocked}` ; STP ne voit qu'un port ; ~19 puis ~38 Mbit/s.
""").format(blocked=isl_blocked_port(d).replace('_eth', ' eth'))),
            cheat_answers={"final": q_isl_cheat, "solve_isl": q_isl_cheat},
        )
        for m, n in (('isl_sw1', 1), ('isl_sw2', 2)):
            self.add_grade_element(
                title=no_tr(f"isl_bond_sw{n}"), max_grade=2, grade_part=part4, grade=2 * int(isl_is_bond[m]),
                description=tr("{m} : bond0 en 802.3ad avec eth1 et eth2").format(m=m))
        for m, n in (('isl_sw1', 1), ('isl_sw2', 2)):
            self.add_grade_element(
                title=no_tr(f"isl_aggregated_sw{n}"), max_grade=2, grade_part=part4, grade=2 * int(isl_agg[m]),
                description=tr("{m} : les deux câbles agrégés avec l'autre switch").format(m=m))
        self.add_grade_element(
            title=no_tr("isl_bridge"), max_grade=4, grade_part=part4,
            grade=sum(int(isl_in_bridge[m]) + int(isl_forwarding[m]) for m in ISL_SWITCHES),
            description=tr("bond0 port de br0 à la place de eth1 et eth2, en transmission, sur les deux switchs"))
        self.add_grade_element(
            title=no_tr("isl_hash"), max_grade=2, grade_part=part4, grade=sum(int(v) for v in isl_hash.values()),
            description=tr("répartition selon les adresses et les ports sur les deux switchs"))
        self.add_grade_element(
            title=no_tr("isl_ping"), max_grade=2, grade_part=part4,
            grade=int(both_in_bridge and isl_ping12) + int(both_in_bridge and isl_ping21),
            description=tr("isl_pc1 et isl_pc2 se joignent à travers l'agrégat"))
        self.add_grade_element(
            title=no_tr("isl_spread"), max_grade=2, grade_part=part4,
            grade=int(isl_agg['isl_sw1'] and spread_ok(isl_delta1)) + int(isl_agg['isl_sw2'] and spread_ok(isl_delta2)),
            description=tr("64 flux UDP dans chaque sens : les deux câbles en transportent"))
        q_isl_ok = int(_norm(q_isl.get("blocked")) == isl_blocked_port(d)) + int(_norm(q_isl.get("stp_view")) == "one_port")
        self.add_grade_element(
            title=no_tr("q_isl_stp"), max_grade=2, grade_part=part4, scope=CHOICE_SCOPE, grade=q_isl_ok,
            description=tr("port bloqué par STP avant l'agrégat, vue de STP après"))
        self.add_grade_element(
            title=no_tr("q_isl_iperf"), max_grade=2, grade_part=part4,
            grade=2 * int(_iperf_ok(q_isl.get("before"), q_isl.get("after"))),
            description=tr("débit de quatre flux avant et après l'agrégat"))

        # =====================================================================
        # Part 5 — troubleshooting (site fix)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("fix"), tr("Partie 5 — dépannage (site fix)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un agrégat qui ne marche pas"),
            hash="3f29cd1c012fc5bd",
            description=tr("""
`fix_srv` est relié au switch `fix_sw` par deux câbles (`eth0` et `eth1` des deux côtés) ; `fix_pc`
(`{pc}`) est derrière `fix_sw`. L'agrégat devait être un agrégat LACP de deux membres aux deux bouts
(**`{bond}`** sur `fix_srv`, avec l'adresse `{srv}`, **`{sw_bond}`** sur `fix_sw`, port de `br0`)...
mais `fix_srv` ne joint pas `fix_pc`. **Trois erreurs** de configuration se cachent sur les deux
machines : trouvez-les et corrigez-les (les autres réglages sont bons : `miimon 100`, `lacp_rate
fast`, `layer3+4`). Outils : `ip -d link`, `/proc/net/bonding/*`, `bridge link`, `lldpcli` (qui
tourne sur `fix_sw`), `ping`, `tcpdump`.

L'évaluation vérifie la configuration, l'agrégat aux deux bouts, et envoie 64 flux UDP de `fix_srv`
vers `fix_pc` : ils doivent tous arriver, répartis sur les deux câbles.
""").format(pc=d.ips.fix_pc.ip, bond=BOND, srv=d.ips.fix_srv, sw_bond=SW_BOND)
            + instructor(tr("""
**Solution.** Sur `fix_srv` (le mode ne change qu'en recréant le bond) :
{srv_cmds}
Sur `fix_sw` :
{sw_cmds}
Les symptômes, dans l'ordre où on les rencontre : `po1` sans porteuse (`NO-CARRIER`, port `disabled`
dans `bridge link`) car `min_links 3` avec au plus deux membres : coupure totale ; puis un
partenaire `00:00:00:00:00:00` dans `/proc/net/bonding/po1` (le serveur en `balance-xor` n'envoie pas
de LACPDU) : chaque membre de `po1` est seul dans son agrégateur, les trames reçues hors de
l'agrégateur actif sont jetées, une partie des flux (voire tout, ARP compris) disparaît ; enfin un
agrégateur d'un seul port car `eth1` de `fix_sw` n'est pas membre de `po1`.
""").format(srv_cmds=_code(self.net_scheme.cmds_fix_srv()), sw_cmds=_code(self.net_scheme.cmds_fix_sw()))),
        )
        causes = tr(">min_links trop élevé sur po1 de fix_sw>>>min_links|fix_srv en balance-xor (agrégat statique) au "
                  "lieu de 802.3ad>>>static|eth1 de fix_sw n'est pas membre de po1>>>member|lacp_rate différent aux "
                  "deux bouts>>>rate")
        q_fix_cheat = {"outage": "min_links", "no_partner": "static", "one_port": "member"}
        q_fix = self.question_form(
            section=self.section(1),
            title=tr("Diagnostic"),
            hash="3ba2317ee23f34a3",
            description=tr("Associez chaque symptôme à sa cause :\n\n")
            + tr("- `po1` de `fix_sw` n'a pas de porteuse (`NO-CARRIER`) : @@{outage:") + causes + no_tr("}@@\n")
            + tr("- `/proc/net/bonding/po1` montre un partenaire `00:00:00:00:00:00` : @@{no_partner:") + causes
            + no_tr("}@@\n")
            + tr("- les deux bouts parlent LACP, mais l'agrégateur de `fix_sw` n'a qu'un port : @@{one_port:")
            + causes + no_tr("}@@\n")
            + instructor(tr("""
**Solution.** `min_links` ; `fix_srv` en `balance-xor` ; `eth1` hors de `po1`.
""")),
            cheat_answers={"final": q_fix_cheat, "solve_fix": q_fix_cheat},
        )
        self.add_grade_element(
            title=no_tr("fix_srv_mode"), max_grade=3, grade_part=part5, grade=3 * int(fix_srv_lacp),
            description=tr("fix_srv : bond0 en 802.3ad avec eth0 et eth1"))
        self.add_grade_element(
            title=no_tr("fix_sw_member"), max_grade=3, grade_part=part5, grade=3 * int(fix_member),
            description=tr("fix_sw : eth1 membre de po1"))
        self.add_grade_element(
            title=no_tr("fix_min_links"), max_grade=3, grade_part=part5, grade=3 * int(fix_min_links),
            description=tr("fix_sw : min_links de po1 compatible avec deux membres"))
        self.add_grade_element(
            title=no_tr("fix_aggregated"), max_grade=3, grade_part=part5, grade=3 * int(fix_agg),
            description=tr("agrégat de deux membres aux deux bouts, po1 avec porteuse"))
        self.add_grade_element(
            title=no_tr("fix_ping"), max_grade=2, grade_part=part5, grade=2 * int(fix_ping),
            description=tr("fix_srv joint fix_pc"))
        self.add_grade_element(
            title=no_tr("fix_delivery"), max_grade=3, grade_part=part5, grade=3 * int(fix_delivery),
            description=tr("64 flux UDP : tous arrivent à fix_pc, répartis sur les deux câbles"))
        q_fix_ok = [_norm(q_fix.get("outage")) == "min_links", _norm(q_fix.get("no_partner")) == "static",
                    _norm(q_fix.get("one_port")) == "member"]
        self.add_grade_element(
            title=no_tr("q_fix"), max_grade=3, grade_part=part5, scope=CHOICE_SCOPE, grade=sum(q_fix_ok),
            description=tr("diagnostic : symptômes et causes"))

        # =====================================================================
        # Bonus — the management VLAN announced by LLDP (site lldp)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("bonus"), tr("Bonus — le VLAN annoncé par LLDP (site lldp)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Le VLAN d'administration"),
            hash="ea5c344192d41cd3",
            description=tr("""
L'administration du switch de cœur relié à `eth0` de `lldp_srv` se fait dans un VLAN étiqueté,
transporté par ce câble, que le switch **annonce par LLDP** (`lldpcli show neighbors details`,
ligne `VLAN`). Le réseau d'administration est `{net}` ; votre adresse y est `{srv}`.

Créez sur `lldp_srv` la sous-interface VLAN correspondante (`eth0.<numéro>`) avec cette adresse, et
vérifiez que vous joignez l'adresse d'administration du switch (relevée en partie 1).

L'évaluation vérifie la sous-interface et lance un `ping` vers le switch.
""").format(net=d.nets.lldp_mgmt, srv=d.ips.lldp_srv)
            + instructor(tr("""
**Solution.** Le switch annonce `VLAN: {vlan}` ; sur `lldp_srv` :
{cmds}
puis `ping {mgmt}`.
""").format(vlan=d.mgmt_vlan, cmds=_code(self.net_scheme.cmds_bonus()), mgmt=d.ips.lldp_core1.ip)),
        )
        self.add_grade_element(
            title=no_tr("bonus_vlan"), max_grade=2, grade_part=part6, bonus=True, grade=2 * int(bonus_vlan),
            description=tr("sous-interface du VLAN d'administration sur eth0"))
        self.add_grade_element(
            title=no_tr("bonus_ping"), max_grade=4, grade_part=part6, bonus=True, grade=4 * int(bonus_vlan and bonus_ping),
            description=tr("lldp_srv joint l'adresse d'administration du switch"))


_TRANSLATIONS = {}
