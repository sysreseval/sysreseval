"""Bridge lab (TP6 "Pont réseaux" of the R306 course, converted and extended from the Marionnet
handout): a Linux bridge joining two switches, its transparency (MAC addresses untouched, what a
third machine sees through a switch), its MAC table and ageing time, layer-2 filtering with the
nftables bridge family, an IP address on the bridge, and the spanning tree protocol with two
redundant bridges joining a third switch to the lan.

Topology::

                     ext1
                      |
                 [switch ext]
                      | eth1
                     gw   (routes lan <-> ext; default route of m1..m4, b1 and ext1)
                      | eth0
    m1 ---- [switch s1] ---- eth0 b1 eth1 ---- [switch s2] ---- m2
              |      |                                           |
         eth1 b2   eth1 b3   (part 6: two bridges in parallel)  m3
              |      |
           [switch s3] ---- m4

``b1`` is the students' bridge of the handout (``pont``): its interfaces are down at the start,
the students build ``br0`` on it (parts 1 to 5, STP off).  Part 6 needs nothing of it: ``b2``
and ``b3``, both to be configured by the students, join the switch ``s3`` (``m4``) to ``s1``
twice, a loop that STP must break; ``m4`` is a plain host of the lan (default route via ``gw``),
unreachable until then.  The ports of ``b2`` and ``b3`` are rate-limited (``tc`` tbf) so that a
broadcast storm, if the students bridge without STP, stays bounded: it floods the whole lan
(``s1``, then ``s2`` through ``b1``) but never saturates the host.  The switches are Kathara
``switch`` collision domains (learning switches, so ``m3`` does not see the unicast traffic of
``m2``).  Every machine but the bridges runs the echo server of ``lib/server_echo.py`` (HTTP on
ports 80 and 8080, UDP on ports 530 and 630: it answers with its name and the addresses and
ports of both ends), TCP and UDP flows for the students to capture through the bridges and to
filter by port; nothing is graded on them.  Every interface of the lan has a fixed MAC address
(``data.macs``) so that the answers
typed by the students (MAC of m3, MAC of the bridge), the ports of the MAC table and the root
bridge election of part 6 (equal priorities: the lowest MAC wins) are known in advance; ``b1``
gets the two highest MACs, so that a ``b1`` whose STP a student turned on (it is on ``s1`` too)
can never be elected root.

The addressing is chosen by a startup form (``Flavor``): random private networks (default) or
the networks of the handout (``192.168.1.0/24``, ``10.10.10.0/24`` outside); the host parts are
those of the handout in both cases (``b1`` = ``.110``, ``m4`` = ``.4``).  The ``final`` state
applies the reference solution.  Every question ends with its solution in an instructor-only
block.  Texts are French (``tr()``) with their English in ``_TRANSLATIONS``, identifiers English.

Facts used (iproute2 and kernel sources, confirmed live, see ``lib/bridging.py``): the bridge
timers are in centiseconds, a bridge with STP off floods the BPDUs, a port needs 2 x
forward_delay (30 s) to forward, ``tcpdump -v`` shows the timers of a BPDU, the kernel lowers
the ageing time to 30 s during a topology change, turning STP off (``stp_state 0``) leaves a
blocked port blocking (a port brought up on a bridge without STP forwards at once: that is how
the optional storm of question 8 is started), and a storm in the loop corrupts the MAC table of
``b1`` too (the looped copies of a broadcast of ``m2`` come back through ``s1``).
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, Flavor0, Grade0, NetScheme0, instructor, make_tr, no_tr, sre_state
from firewall import get_ruleset
from SRE.lib_sre import info_subtitle, info_toc
from ips import random_ipv4networks, random_mac_address
from net_config import get_routes, set_ip_forward
from server_echo_helpers import install_echo_server
from bridging import (
    addresses_of, bridge_info, bridge_ports, drop_rules_for, fdb_port_of, get_fdb, get_ip_addresses_json,
    get_ip_links, interface_of_address, link_up, normalize_mac, parse_bridge_rules, port_states,
)

default_language = 'fr'
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("Ponts Ethernet : pont Linux, table MAC, filtrage et STP",
           en="Ethernet bridges: Linux bridge, MAC table, filtering and STP")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
export_kathara_project = True
# An evaluation runs a dozen pings from the students' machines (one of them must fail: 4 s).
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

flavor_form_at_startup = True

BRIDGE = "br0"                 # the name of the bridges the students create (imposed)
DEFAULT_PRIORITY = 32768       # STP default priority
ROOT_PRIORITY = 4096           # part 6c: the priority that makes the other bridge the root
# part 3: ageing time asked for the MAC table of br0.  30 s is also what the kernel applies by itself
# during an STP topology change (2 x forward_delay, restored ~35 s later).
AGEING_SECONDS = 30
FILTER_TABLE = "filter"        # nft bridge family table / chain of the reference solution
FILTER_CHAIN = "forward"
MAC_PREFIX = "02:53:52"        # locally administered addresses ("SR" + random)
DOMAIN = "lab"
STP_HELLO, STP_MAX_AGE, STP_FORWARD_DELAY = 2, 20, 15   # 802.1D defaults (seconds)
PING = "ping -c 2 -w 4"
STP_BRIDGES = ('b2', 'b3')     # the two bridges of part 6, between s3 and s1
#: every machine but the bridges runs an echo server (lib/server_echo.py): HTTP on HTTP_PORTS, UDP on
#: UDP_PORTS, answering with its name and the addresses / ports of both ends (not graded: TCP and
#: UDP flows for the students to capture through the bridges and to filter by port)
SERVER_MACHINES = ('m1', 'm2', 'm3', 'm4', 'gw', 'ext1')
HTTP_PORTS = (80, 8080)
UDP_PORTS = (530, 630)
#: the ports of b2 and b3 are rate-limited: a broadcast storm in the loop of part 6 (two bridges
#: without STP) floods the whole lan but stays harmless for the host, and the students can even
#: observe one
STORM_CAP_RATE = "1mbit"
STORM_CAP = "tc qdisc replace dev {dev} root tbf rate " + STORM_CAP_RATE + " burst 32kbit latency 50ms"
# Measured live with this cap (2026-10-14): 3 000 to 4 000 frames/s on every machine of the lan
# during a storm (figure quoted in the instructor text of question 8; the 2 Mbit/s cap gave about
# the same rate for a higher host load), host load < 2, and the storm stops a few seconds after STP
# is turned back on.

#: the networks of the handout (flavor "fixed"); the host parts below are used in both flavors
FIXED_NETWORKS = {'lan': IPv4Network("192.168.1.0/24"), 'ext': IPv4Network("10.10.10.0/24")}
HOST_PARTS = {'m1': 1, 'm2': 2, 'm3': 3, 'm4': 4, 'b1': 110, 'gw_lan': 254, 'gw_ext': 254, 'ext1': 51}
#: ips.<key> -> network
ADDRESSED = {'m1': 'lan', 'm2': 'lan', 'm3': 'lan', 'm4': 'lan', 'b1': 'lan', 'gw_lan': 'lan', 'gw_ext': 'ext',
             'ext1': 'ext'}
#: (machine, network) -> macs.<key>: the fixed MAC addresses of the lan interfaces
MAC_KEYS = {('m1', 's1'): 'm1', ('gw', 's1'): 'gw_lan', ('b1', 's1'): 'b1_eth0', ('b2', 's1'): 'b2_eth1',
            ('b3', 's1'): 'b3_eth1',
            ('m2', 's2'): 'm2', ('m3', 's2'): 'm3', ('b1', 's2'): 'b1_eth1',
            ('m4', 's3'): 'm4', ('b2', 's3'): 'b2_eth0', ('b3', 's3'): 'b3_eth0'}
B1_MAC_KEYS = ('b1_eth0', 'b1_eth1')   # the two highest MACs of the instance (see Data.generate)
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_TOPOLOGY = {
    's1': {'m1': 0, 'gw': 0, 'b1': 0, 'b2': 1, 'b3': 1},
    's2': {'m2': 0, 'm3': 0, 'b1': 1},
    'ext': {'gw': 1, 'ext1': 0},
    # part 6: the switch of m4, joined to s1 by two bridges in parallel (a loop)
    's3': {'m4': 0, 'b2': 0, 'b3': 0},
}

# ---------------------------------------------------------------------------
# Flavor: the addressing is chosen when the project starts
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Flavor(Flavor0):
    ip_choice: str = "random"

    form_size = (760, 320)
    flavor_form = (
        no_tr("# ") + title + no_tr("\n\n")
        + tr("**Adresses IP des réseaux :**\n", en="**IP addresses of the networks:**\n")
        + tr("@@{ip_choice:>Aléatoires, propres à cette instance>>>random|"
             "Celles du sujet : 192.168.1.0/24 (et 10.10.10.0/24 pour l'extérieur)>>>fixed}@@\n\n",
             en="@@{ip_choice:>Random, specific to this instance>>>random|"
                "Those of the handout: 192.168.1.0/24 (and 10.10.10.0/24 for the outside)>>>fixed}@@\n\n")
        + tr("Les numéros de machine sont les mêmes dans les deux cas (`m1` = `.1`, `b1` = `.110`, `gw` = `.254`...).\n\n",
             en="The machine numbers are the same in both cases (`m1` = `.1`, `b1` = `.110`, `gw` = `.254`...).\n\n")
        # the label of the submit button alone in tr(): the translation checks read a `:Label`
        # spec as a text field whose regex must not change
        + no_tr("@@{name::") + tr("Démarrer le projet", en="Start the project") + no_tr("}@@")
    )


Flavor.random = Flavor(ip_choice="random")
Flavor.fixed = Flavor(ip_choice="fixed")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls, flavor: Flavor = None):
        if flavor is None:
            flavor = Flavor()
        data = cls()
        if getattr(flavor, 'ip_choice', 'random') == "fixed":
            nets = dict(FIXED_NETWORKS)
        else:
            lan, ext = random_ipv4networks(masks=[24, 24], from_private_network=True,
                                           exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
            nets = {'lan': lan, 'ext': ext}
        for name, net in nets.items():
            setattr(data.nets, name, net)
        for key, net in ADDRESSED.items():
            setattr(data.ips, key, IPv4Interface(f"{nets[net].network_address + HOST_PARTS[key]}/{nets[net].prefixlen}"))
        # Fixed MAC addresses of the lan interfaces: the MAC table, the bridge id and the
        # answers typed by the students become predictable.  b1 gets the two highest ones: b1 is
        # on s1 with b2 and b3, so a student turning its STP on must not make it the root (equal
        # priorities: the lowest bridge MAC wins) and spoil the election of part 6.
        keys = sorted(set(MAC_KEYS.values()))
        macs = sorted(random_mac_address(prefix=MAC_PREFIX, n=len(keys)), key=int)
        others = [key for key in keys if key not in B1_MAC_KEYS]
        for key, mac in zip(others, random.sample(macs[:len(others)], len(others))):
            setattr(data.macs, key, mac)
        for key, mac in zip(B1_MAC_KEYS, random.sample(macs[len(others):], len(B1_MAC_KEYS))):
            setattr(data.macs, key, mac)
        return data


def mac_text(mac) -> str:
    """``02:53:52:xx:xx:xx`` of a ``macs`` entry (what the students read in ``ip link``)."""
    return normalize_mac(mac)


def bridge_mac(data, machine: str = 'b1') -> str:
    """The MAC address br0 takes on *machine*: the lowest of its two ports."""
    return mac_text(min(getattr(data.macs, machine + '_eth0'), getattr(data.macs, machine + '_eth1'), key=int))


def stp_roots(data):
    """``(first root, final root)`` of part 6: with equal priorities the bridge with the lowest
    MAC address (lowest bridge id) is elected, then the other one gets ROOT_PRIORITY."""
    b2, b3 = bridge_mac(data, 'b2'), bridge_mac(data, 'b3')
    return ('b2', 'b3') if b2 < b3 else ('b3', 'b2')


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'b1': {'color': 'lightyellow'},
        'gw': {'color': 'lightgreen'},
        'm1': {}, 'm2': {}, 'm3': {},
        'ext1': {'color': 'lightgrey'},
        # part 6: two bridges in parallel between s3 and s1, both to be configured
        'b2': {'color': 'lightyellow'},
        'b3': {'color': 'lightyellow'},
        'm4': {},
    }
    _network_specs = {
        # learning switches: m3 does not see the unicast traffic of m2
        's1': {'mode': 'switch', 'color': 'lightcyan'},
        's2': {'mode': 'switch', 'color': 'lightcyan'},
        'ext': {'mode': 'switch', 'color': 'lightgrey'},
        's3': {'mode': 'switch', 'color': 'mistyrose'},
    }

    @property
    def _topology(self):
        macs = self.data.macs
        topology = {}
        for net, machines in _TOPOLOGY.items():
            topology[net] = {}
            for machine, iface in machines.items():
                key = MAC_KEYS.get((machine, net))
                topology[net][machine] = (iface, getattr(macs, key)) if key else iface
        return topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Rappels : trames, adresses MAC, hubs et switchs"), tag="recap")
            + tr("""

Une **trame Ethernet** porte une adresse MAC de destination, une adresse MAC source (48 bits,
`02:53:52:0a:0b:0c`), un type (`0x0800` IPv4, `0x0806` ARP) et des données. L'adresse
`ff:ff:ff:ff:ff:ff` est la **diffusion** (*broadcast*) : toutes les machines du réseau la
reçoivent (c'est ainsi qu'ARP demande « qui a l'adresse IP X ? »). Une adresse dont le premier
octet est impair (`01:...`, `33:33:...`) est une adresse multicast.

Un **hub** répète chaque trame sur tous ses ports. Un **switch** (commutateur) apprend sur quel
port se trouve chaque adresse MAC source qu'il voit passer (sa **table MAC**) et ne transmet une
trame unicast que sur le port de son destinataire ; les diffusions, les multicasts et les trames
dont le destinataire est encore inconnu sont envoyés sur tous les ports (*flooding*). Toutes les
machines reliées par des hubs et des switchs forment un seul **domaine de diffusion** : un réseau
IP (`192.168.1.0/24`) occupe normalement un domaine de diffusion. Deux switchs reliés par un
câble forment un seul domaine ; deux switchs **non reliés** forment deux domaines, et une
machine de l'un ne peut pas joindre une machine de l'autre, même avec des adresses IP du même
réseau : sa requête ARP n'arrive jamais.
""")
            + info_subtitle(tr("Le pont transparent"), tag="transparent-bridge")
            + tr("""

Un **pont** (*bridge*, IEEE 802.1D) relie deux segments Ethernet au niveau 2 : il reçoit chaque
trame sur un port, la mémorise entièrement (*store and forward*), lit l'adresse source pour
apprendre sur quel port est l'émetteur, puis la réémet sur le port de son destinataire (ou sur
tous les autres ports s'il ne le connaît pas). Un switch n'est rien d'autre qu'un pont à
beaucoup de ports.

Le pont est **transparent** : il ne modifie pas les trames (adresses MAC source et destination
inchangées, pas de champ TTL décrémenté), il n'a pas besoin d'adresse IP et les machines ne
savent pas qu'il existe : dans la table ARP de `m1`, l'adresse IP de `m2` correspond à la vraie
adresse MAC de `m2`, pas à celle du pont. Un **routeur**, au contraire, termine les trames (elles
lui sont adressées) et en émet de nouvelles avec ses propres adresses MAC, relie des réseaux IP
différents et décrémente le TTL. Le prix de la transparence : un pont ajoute un délai (il attend
la trame complète avant de la réémettre) et il **prolonge le domaine de diffusion** (une
tempête de broadcast le traverse).

Les entrées de la table MAC d'un pont ont une durée de vie (*ageing time*, 300 s par défaut) :
une adresse qui n'a plus émis depuis ce délai est oubliée, et les trames qui lui sont destinées
sont de nouveau diffusées sur tous les ports jusqu'à ce qu'elle se manifeste. Une machine
déplacée d'un port à l'autre est réapprise dès qu'elle émet.
""")
            + info_subtitle(tr("Les ponts sous Linux"), tag="linux-bridges")
            + tr("""

Le noyau Linux contient un pont logiciel : une interface virtuelle `brX` à laquelle on rattache
des **ports** (des interfaces physiques, ou virtuelles). Les ports n'ont **pas** d'adresse IP et
doivent être `up` ; le pont lui-même peut porter une adresse IP si la machine doit être
joignable (elle est alors à la fois le switch et une machine branchée dessus).

```
ip link set eth0 up ; ip link set eth1 up        # les ports doivent être actifs
ip link add br0 type bridge                      # crée le pont (STP désactivé par défaut)
ip link set eth0 master br0                      # eth0 devient un port de br0
ip link set eth1 master br0
ip link set br0 up                               # active le pont : il commute
bridge link                                      # les ports de chaque pont et leur état
bridge fdb show br br0                           # la table MAC de br0 (fdb : forwarding database)
ip -d link show br0                              # les paramètres du pont (-d : détails)
ip link set eth1 nomaster                        # retire un port
ip link del br0                                  # supprime le pont
```

(`brctl addbr br0`, `brctl addif br0 eth0`, `brctl show`, `brctl showmacs br0` du paquet
historique `bridge-utils` font la même chose.)

L'adresse MAC du pont est, sauf si on la fixe, **la plus petite des adresses MAC de ses ports**
(`ip link show br0`). Dans `bridge fdb show br br0`, les lignes `permanent` sont les adresses des
ports eux-mêmes ; les autres sont les adresses apprises, avec le port (`dev`) où la machine a été
vue ; `bridge -s fdb show br br0` ajoute le temps écoulé depuis la dernière trame. La durée de
vie des entrées se règle en **centièmes de seconde** : `ip link set br0 type bridge ageing_time
3000` (30 s ; `ip -d link show br0` affiche `ageing_time 3000`). Pour donner une adresse IP à la
machine dans le réseau ponté, l'adresse va sur `br0` (`ip address add 192.168.1.110/24 dev
br0`), jamais sur un port.
""")
            + info_subtitle(tr("Observer un pont"), tag="observing")
            + tr("""

`tcpdump -e -n -i eth0 icmp` (`-e` affiche l'en-tête Ethernet, `-n` évite les résolutions de
noms) sur un port du pont montre les trames **telles qu'elles sont commutées** : les adresses
MAC source et destination sont celles des machines qui dialoguent, le pont n'y apparaît pas. Sur
`br0`, `tcpdump -i br0` voit les trames qui remontent à la machine elle-même (celles qui lui sont
adressées ou diffusées) ; `-p` désactive le mode *promiscuous*. `ip neigh` affiche la table ARP
d'une machine (adresse IP → adresse MAC apprise), `ip neigh flush all` la vide.

Un switch ne livre une trame unicast qu'à son destinataire : une capture sur une troisième
machine du même switch ne voit que les diffusions (ARP) et les trames dont le destinataire n'est
pas encore dans la table du switch. Avec un hub, elle verrait tout.

`ping` affiche pour chaque réponse le temps aller-retour (`time=0.345 ms`) et, à la fin, les
temps minimum / moyen / maximum (`rtt min/avg/max/mdev`) : `ping -c 10` donne une moyenne sur
dix essais.

Pour observer autre chose que des `ping`, chaque machine du TP sauf les ponts (`m1`, `m2`, `m3`,
`m4`, `gw`, `ext1`) sert un petit **serveur de test**, en HTTP sur les ports TCP **80 et 8080**
et en UDP sur les ports **530 et 630** (`ss -tulnp` les liste). Il répond par son nom et par les
adresses et ports des deux bouts de l'échange, tels qu'il les voit :

```
m1:~# curl http://m2/                   # ou curl http://m2:8080/
SERVER=m2
SERVER_IP=192.168.1.2
SERVER_PORT=80
CLIENT_IP=192.168.1.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # un datagramme UDP vers le port 530 (ou 630) : même réponse
```

`TTL=` est celui du paquet reçu : 64 depuis le même réseau, 63 après un routeur, un pont ne le
change pas. Ces échanges se capturent sur un port du pont (`tcpdump -e -n -i eth0 tcp port 80`,
`tcpdump -e -n -i eth0 udp port 530`) et permettent d'essayer les critères de port du filtrage
de niveau 2 (`tcp dport 8080`, `udp dport 530`, section suivante).
""")
            + info_subtitle(tr("Filtrer au niveau 2 : nftables, famille `bridge`"), tag="filtering")
            + tr("""

Les règles de la famille **`bridge`** de nftables s'appliquent aux trames qui traversent un pont
Linux, avant tout routage. Ses hooks : `prerouting` (à l'entrée d'un port), `input` (vers la
machine elle-même), **`forward`** (commutée d'un port vers un autre), `output`, `postrouting`.
Les critères disponibles sont ceux de la trame et de ce qu'elle contient : `ether saddr`,
`ether daddr` (adresses MAC), `ether type` (`ip`, `arp`, `vlan`), `ip saddr`, `ip daddr`,
`ip protocol`, `tcp dport`, `udp dport`, `arp operation`, `iifname` / `oifname` (ports d'entrée
et de sortie). Les verdicts : `accept`, `drop`. Les critères IP se combinent avec les critères
MAC : `ip saddr X` suffit, nftables ajoute lui-même le test « c'est de l'IPv4 ».

```
nft add table bridge filter
nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'
nft add rule bridge filter forward ether saddr 02:53:52:00:00:02 ether daddr 02:53:52:00:00:fe drop
nft add rule bridge filter forward ip saddr 192.168.1.2 ip daddr != 192.168.1.0/24 drop
nft list ruleset                             # vérifier (famille bridge)
nft flush table bridge filter                # vider ; nft delete table bridge filter supprime
```

Une trame bloquée dans `forward` n'est pas commutée : la machine émettrice n'obtient aucune
réponse. Bloquer un seul sens suffit à interdire une communication (ici les requêtes de `m2`,
donc aucune réponse). Les adresses MAC des machines se lisent dans `ip link` sur la machine, dans
`ip neigh` sur ses voisines ou dans `bridge fdb show` sur le pont. Historiquement ce filtrage
était celui d'`ebtables` (chaîne `FORWARD`, syntaxe d'iptables) ; l'`ebtables` de Debian 13 est
une réimplémentation sur nftables, dont les règles apparaissent dans `nft list ruleset`.
""")
            + info_subtitle(tr("Boucles, redondance et STP"), tag="stp")
            + tr("""

Deux ponts entre les mêmes segments forment une **boucle**. Sans précaution, une seule trame de
diffusion tourne indéfiniment, dupliquée à chaque tour (**tempête de diffusion**, *broadcast
storm*) et les tables MAC deviennent instables (la même adresse est vue tour à tour sur les deux
ports) : le réseau s'effondre en quelques secondes. La redondance est pourtant souhaitable (un
pont peut tomber en panne).

Le **STP** (*Spanning Tree Protocol*, IEEE 802.1D) résout le problème : les ponts échangent des
**BPDU** (*Bridge Protocol Data Units*, trames multicast vers `01:80:c2:00:00:00`, une toutes
les deux secondes, *hello time*) et élisent une **racine** : le pont dont l'**identifiant** est
le plus petit, l'identifiant étant la **priorité** (16 bits, 32768 par défaut, écrite en
hexadécimal : `8000.`) suivie de l'adresse MAC du pont. Chaque autre pont garde un seul chemin
vers la racine : son **port racine** (le plus proche de la racine, au coût le plus faible), et
sur chaque segment un seul pont est **désigné** pour y transmettre les trames. Tout port qui
n'est ni racine ni désigné est **bloqué** (*blocking*) : il ne transmet rien, mais écoute les
BPDU, pour se réactiver si un chemin disparaît. L'arbre couvrant ainsi obtenu n'a plus de boucle.

Un port passe par les états *blocking* → *listening* (15 s) → *learning* (15 s) → *forwarding*
(*forward delay*, 15 s par étape) : un pont STP met donc **environ 30 s** à commuter après son
activation, et une reconfiguration prend 30 à 50 s (*max age* 20 s : délai sans BPDU avant de
considérer un chemin perdu). Le **RSTP** (802.1w) converge en quelques secondes et le MSTP
(802.1s) gère un arbre par groupe de VLAN ; le noyau Linux ne fait que le STP classique (`mstpd`
pour les autres).

Sous Linux :

```
ip link set br0 type bridge stp_state 1          # active STP (0 : désactive)
ip link set br0 type bridge priority 4096        # priorité (0 à 65535 ; plus petite = racine)
bridge link                                      # état de chaque port : forwarding, blocking...
ip -d link show br0                              # bridge_id, root_id (l'identifiant de la racine),
                                                 # root_port, hello_time, max_age, forward_delay (centièmes de seconde)
tcpdump -n -v -i eth0 stp                        # les BPDU (-v : les temporisateurs et root-id)
```

Un pont dont STP est désactivé laisse passer les BPDU des autres (il est pour eux un simple
câble) : si un seul pont de la boucle fait du STP, il reçoit ses propres BPDU et bloque lui-même
l'un de ses ports.

Deux ponts de même priorité : le plus petit identifiant est celui dont l'**adresse MAC** est la
plus petite, ce qui fait une racine choisie par le hasard des adresses ; en pratique on fixe la
racine en lui donnant une priorité plus petite (et une priorité de secours au pont suivant).
Dans un pont qui n'est pas la racine, le port racine est celui par lequel les BPDU de la racine
arrivent au meilleur coût ; à coût égal, celui qui reçoit les BPDU du port de la racine au plus
petit **identifiant de port** (le premier port ajouté au pont racine est le port 1).

Après un changement de topologie, les ponts STP vident leur table MAC (c'est le rôle du
drapeau *topology change* des BPDU) ; un switch qui ne fait pas de STP, lui, garde ses entrées
jusqu'à leur expiration : une adresse apprise derrière un port depuis bloqué reste injoignable
jusqu'à ce qu'une trame de diffusion (ARP) venant d'elle lui fasse réapprendre le bon port.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| interfaces, adresses MAC, adresses IP | `ip link`, `ip -br link`, `ip -br address`, `ip -d link show br0` |
| pont | `ip link add br0 type bridge`, `ip link set ethX master br0`, `ip link set br0 up`, `bridge link` |
| table MAC du pont | `bridge fdb show br br0`, `bridge -s fdb show br br0`, `ip link set br0 type bridge ageing_time 3000` |
| table ARP | `ip neigh`, `ip neigh flush all` |
| capture | `tcpdump -e -n -i eth0 icmp`, `tcpdump -n -v -i eth0 stp`, `tshark -i eth0`, `wireshark` |
| latence | `ping -c 10 192.168.1.1` (ligne `rtt min/avg/max`) |
| serveurs de test (TCP 80 et 8080, UDP 530 et 630) | `curl http://m2/`, `curl http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ss -tulnp` |
| filtrage niveau 2 | `nft add table bridge filter`, `nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'`, `nft add rule bridge filter forward ... drop`, `nft list ruleset` |
| adresse sur le pont | `ip address add A.B.C.D/24 dev br0`, `ip route add default via ...` |
| STP | `ip link set br0 type bridge stp_state 1`, `ip link set br0 type bridge priority N`, `bridge link`, `ip -d link show br0` |
""")
        )

    # -- the commands of the reference solution (used by `final` and the instructor texts) ----

    def cmds_bridge(self) -> List[str]:
        """Part 2: br0 on b1 with eth0 and eth1 as ports, STP off as the handout asks."""
        return ["ip link set eth0 up", "ip link set eth1 up", f"ip link add {BRIDGE} type bridge",
                f"ip link set eth0 master {BRIDGE}", f"ip link set eth1 master {BRIDGE}", f"ip link set {BRIDGE} up"]

    def cmds_ageing(self) -> List[str]:
        """Part 3: the ageing time of the MAC table, in centiseconds."""
        return [f"ip link set {BRIDGE} type bridge ageing_time {AGEING_SECONDS * 100}"]

    def cmds_filter(self) -> List[str]:
        """Part 4: m2 cannot reach the exterior any more (frames from m2 to the MAC of gw)."""
        d = self.data
        return [f"nft add table bridge {FILTER_TABLE}",
                f"nft 'add chain bridge {FILTER_TABLE} {FILTER_CHAIN} "
                "{ type filter hook forward priority 0; policy accept; }'",
                f"nft add rule bridge {FILTER_TABLE} {FILTER_CHAIN} ether saddr {mac_text(d.macs.m2)} "
                f"ether daddr {mac_text(d.macs.gw_lan)} drop"]

    def cmds_filter_by_ip(self) -> List[str]:
        """Part 4, the variant by IP addresses shown in the solution."""
        d = self.data
        return [f"nft add rule bridge {FILTER_TABLE} {FILTER_CHAIN} ip saddr {d.ips.m2.ip} ip daddr != {d.nets.lan} drop"]

    def cmds_bridge_address(self) -> List[str]:
        """Part 5: the address of b1 on the bridge and its default route."""
        d = self.data
        return [f"ip address add {d.ips.b1} dev {BRIDGE}", f"ip route replace default via {d.ips.gw_lan.ip}"]

    def cmds_stp_bridge(self) -> List[str]:
        """Part 6a: br0 with STP on b2 and on b3 (STP on before the ports: no storm)."""
        return ["ip link set eth0 up", "ip link set eth1 up", f"ip link add {BRIDGE} type bridge stp_state 1",
                f"ip link set eth0 master {BRIDGE}", f"ip link set eth1 master {BRIDGE}", f"ip link set {BRIDGE} up"]

    def cmds_root(self) -> List[str]:
        """Part 6c: the bridge that was not elected becomes the root."""
        return [f"ip link set {BRIDGE} type bridge priority {ROOT_PRIORITY}"]

    # -- states -----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('m1', d.ips.m1), ('m2', d.ips.m2), ('m3', d.ips.m3), ('m4', d.ips.m4), ('b1', d.ips.b1),
                   ('gw', d.ips.gw_lan), ('gw_ext', d.ips.gw_ext), ('ext1', d.ips.ext1)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{machine}", ""]
        lines += [f"{ip.ip}\t\t{name}.{DOMAIN}\t{name}" for name, ip in entries]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        d = self.data
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write, which the students need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == 'gw'))
        for m in ('m1', 'm2', 'm3', 'm4'):   # m4 (on s3) reaches gw once b2 or b3 forwards (part 6)
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0")
            self.cmd(m, f"ip route add default via {d.ips.gw_lan.ip}")
        self.cmd('gw', f"ip address add {d.ips.gw_lan} dev eth0")
        self.cmd('gw', f"ip link set eth1 up; ip address add {d.ips.gw_ext} dev eth1")
        self.cmd('ext1', f"ip address add {d.ips.ext1} dev eth0")
        self.cmd('ext1', f"ip route add default via {d.ips.gw_ext.ip}")
        for m in ('b1',) + STP_BRIDGES:
            # the handout: the interfaces of the bridge machines are not configured
            self.cmd(m, "ip link set eth0 down; ip link set eth1 down")
        for m in STP_BRIDGES:
            for dev in ('eth0', 'eth1'):
                self.cmd(m, STORM_CAP.format(dev=dev))

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
        for m in SERVER_MACHINES:
            install_echo_server(net_scheme=self, machine=m, ports=HTTP_PORTS, udp_ports=UDP_PORTS)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the six parts, applicable more than once (what an earlier
        application or the students left is removed first).  The ports of the two STP bridges
        need about 30 s to reach the forwarding state."""
        self.cmd('b1', f"ip link del {BRIDGE} 2>/dev/null; nft delete table bridge {FILTER_TABLE} 2>/dev/null; "
                       "ip address flush dev eth0; ip address flush dev eth1; true")
        for c in self.cmds_bridge() + self.cmds_ageing() + self.cmds_filter() + self.cmds_bridge_address():
            self.cmd('b1', c)
        first_root, final_root = stp_roots(self.data)
        for m in STP_BRIDGES:
            self.cmd(m, f"ip link del {BRIDGE} 2>/dev/null; true")
            for c in self.cmds_stp_bridge():
                self.cmd(m, c)
        for c in self.cmds_root():
            self.cmd(final_root, c)

# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _is_int(answer, expected: int) -> bool:
    return _digits(answer) == str(expected)


def _same_mac(answer, expected) -> bool:
    return normalize_mac(answer) != '' and normalize_mac(answer) == normalize_mac(expected)


def _float_in(answer, low: float, high: float) -> bool:
    try:
        value = float((answer or '').strip().replace(',', '.').replace('ms', ''))
    except ValueError:
        return False
    return low < value < high


def _is_priority(answer, expected: int) -> bool:
    """The priority of a bridge id typed in decimal (4096) or as tcpdump / ip print it (1000, 0x1000)."""
    text = _norm(answer).replace('0x', '')
    if text.isdigit() and int(text) == expected:
        return True
    try:
        return int(text, 16) == expected and len(text) == 4
    except ValueError:
        return False


def _lines(commands: List[str]) -> str:
    return "\n".join(commands) + "\n"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()

        # ---------------- diagnostics kept in the archive ---------------------------------
        for c in ("bridge link", "bridge fdb show", f"ip -d link show {BRIDGE}", "nft list ruleset", "ip -br address",
                  "ip route"):
            self.test('b1', c, allow_error=True)
        for m in STP_BRIDGES:
            for c in ("bridge link", f"ip -d link show {BRIDGE}"):
                self.test(m, c, allow_error=True)

        # ---------------- the state of the machines (every test is registered on every pass) --
        links_b1 = get_ip_links(self, 'b1')
        info_b1 = bridge_info(links_b1, BRIDGE)
        links = {m: get_ip_links(self, m) for m in STP_BRIDGES}
        infos = {m: bridge_info(links[m], BRIDGE) for m in STP_BRIDGES}
        states = {m: port_states(infos[m]) for m in STP_BRIDGES}
        first_root, final_root = stp_roots(d)
        addrs_b1 = get_ip_addresses_json(self, 'b1')
        routes_b1 = get_routes(self, 'b1')
        rules = parse_bridge_rules(get_ruleset(self, 'b1'))
        # the MAC table is read at step 2, after the pings of step 1 have crossed the bridge
        fdb = get_fdb(self, 'b1', BRIDGE, step=2)

        def ping(src, dest, flush_arp=False):
            # flush_arp: the switches s1 / s3 keep a stale MAC entry towards a port STP has just
            # blocked until it expires (~100 s); the broadcast ARP request of the pinging machine
            # makes them learn again (and its reply refreshes the other switch)
            prefix = "ip neigh flush all; " if flush_arp else ""
            out, _ = self.test(src, f"{prefix}{PING} {dest.ip}", allow_error=True)
            return 'bytes from' in (out or '')

        p = {
            'm2_m1': ping('m2', d.ips.m1), 'm1_m2': ping('m1', d.ips.m2),
            'm2_ext1': ping('m2', d.ips.ext1), 'm3_ext1': ping('m3', d.ips.ext1),
            'm1_b1': ping('m1', d.ips.b1), 'm2_b1': ping('m2', d.ips.b1), 'm3_b1': ping('m3', d.ips.b1),
            'gw_b1': ping('gw', d.ips.b1), 'b1_ext1': ping('b1', d.ips.ext1),
            'm4_m1': ping('m4', d.ips.m1, flush_arp=True), 'm1_m4': ping('m1', d.ips.m4, flush_arp=True),
            'm4_ext1': ping('m4', d.ips.ext1, flush_arp=True),
        }
        ports_b1 = bridge_ports(links_b1).get(BRIDGE)
        blocking = {m: [port for port, state in states[m].items() if state == 'blocking'] for m in STP_BRIDGES}
        concerned = drop_rules_for(rules, mac=d.macs.m2, ip=d.ips.m2)

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` : les switchs `s1`, `s2` et `s3` | `{lan}` | `m1` (`{m1}`, sur `s1`), `m2` (`{m2}`, sur `s2`), `m3` (`{m3}`, sur `s2`), `m4` (`{m4}`, sur `s3`, partie 6), `gw` eth0 (`{gw_lan}`, sur `s1`, passerelle) ; à venir : `b1` (`{b1}`, sur `br0`) ; `b2` et `b3` sans adresse |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `gw` eth1 (`{gw_ext}`) |
""").format(lan=d.nets.lan, m1=d.ips.m1.ip, m2=d.ips.m2.ip, m3=d.ips.m3.ip, m4=d.ips.m4.ip, gw_lan=d.ips.gw_lan.ip,
            b1=d.ips.b1.ip, ext=d.nets.ext, ext1=d.ips.ext1.ip, gw_ext=d.ips.gw_ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="e509aaa32ad38066",
            description=tr("""
Lisez l'onglet **Informations** : il présente les ponts Ethernet, leur réalisation sous Linux,
la façon de les observer, le filtrage de niveau 2 avec nftables et le protocole STP.

**La maquette** (onglet *Schéma*) est un seul réseau IP, `lan`, réparti sur trois switchs.

- Parties 1 à 5 : les switchs `s1` (avec `m1` et la passerelle `gw`) et `s2` (avec `m2` et
  `m3`) ne sont reliés que par la machine `b1` (`eth0` sur `s1`, `eth1` sur `s2`), dont les
  interfaces ne sont **pas configurées** : vous en ferez un pont. La passerelle `gw` route vers
  le réseau `ext`, « l'extérieur », où se trouve `ext1`.
- Partie 6 : un troisième switch `s3` (avec `m4`) est relié à `s1` par **deux** machines `b2`
  et `b3` (`eth0` sur `s3`, `eth1` sur `s1`), elles aussi non configurées : vous en ferez deux
  ponts en parallèle, une boucle que STP devra défaire. Jusque-là, `m4` est isolée.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses ci-dessus (sauf celle de `b1`, partie 5), la
route par défaut de `m1`, `m2`, `m3`, `m4` et `ext1` vers `gw`, le routage sur `gw`, les noms dans
`/etc/hosts` (`m1`, `m2`, `m3`, `m4`, `b1`, `gw`, `gw_ext`, `ext1`). Il n'y a pas de DNS. Sur
chaque machine sauf les ponts tourne un **serveur de test** HTTP (ports TCP 80 et 8080) et UDP
(ports 530 et 630) qui répond par son nom et par les adresses et ports du serveur et du client
(`curl http://m2/`, `echo bonjour | nc -u -w 1 m2 530` ; section @@ref:observing@@ des
Informations) : de quoi observer et filtrer autre chose que des `ping`.
Les adresses **MAC** ne sont pas données : lisez-les sur les machines (`ip link`, `ip neigh`,
`bridge fdb show`). Par sécurité, les interfaces de `b2` et `b3` sont bridées à {cap} (`tc qdisc
show`) : une tempête de diffusion dans la boucle de la partie 6 inonderait tout le réseau (`s1`,
puis `s2` à travers `b1`) et perturberait les autres parties tant qu'elle dure, mais sans saturer
votre machine.

**Plan du TP.**

1. **Sans pont** : m1 et m2 ne se joignent pas ;
2. **Le pont `br0`** sur b1 : m2 joint m1 et l'extérieur ; transparence (captures, ARP, adresse
   MAC du pont) ; latence avec ou sans pont ;
3. **Table MAC** du pont et durée de vie des entrées ;
4. **Filtrage** : m2 ne doit plus joindre l'extérieur (famille `bridge` de nftables) ;
5. **Adresse IP** sur le pont : b1 joignable et joint l'extérieur ;
6. **Redondance et STP** : un troisième switch `s3` (avec `m4`) relié à `s1` par deux ponts
   `b2` et `b3` en parallèle ; élection de la racine, port bloqué, BPDU, puis changement de
   racine par la priorité.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place (l'évaluation vérifie l'état final de tout) ;
- toute la configuration de ce TP est volatile (`ip`, `nft`) : elle ne survit pas au redémarrage
  d'une machine ;
- le nom des ponts est imposé : **`{bridge}`** sur `b1`, `b2` et `b3` ;
- avec STP actif, un pont met **30 secondes** à commuter : patientez avant de conclure ;
- l'évaluation observe la maquette telle qu'elle tourne (`ip -d link`, `bridge fdb`, `nft list
  ruleset` sur `b1`, l'état STP de `b2` et `b3`, puis des `ping` **depuis vos machines**).
""").format(bridge=BRIDGE, cap=STORM_CAP_RATE.replace('mbit', ' Mbit/s'))
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit
les formulaires : `br0` sur `b1` (ports `eth0` et `eth1`, sans STP), `ageing_time` de 30 s, la table
`bridge filter` et sa règle `drop`, l'adresse `{b1}` sur `br0` avec la route par défaut, puis `br0`
avec STP sur `b2` et `b3` et la priorité {root_priority} sur `{final_root}`. Il est ré-applicable, et il
faut attendre **30 s** après lui (états *listening* puis *learning* des ports STP) avant une évaluation
complète.

Adresses MAC de cette instance : m1 `{mac_m1}`, m2 `{mac_m2}`, m3 `{mac_m3}`, m4 `{mac_m4}`, gw `{mac_gw}`,
b1 eth0 `{mac_b1_eth0}` / eth1 `{mac_b1_eth1}` (donc `br0` = `{mac_br0}` ; `b1` reçoit les deux plus grandes
adresses de l'instance : même avec STP activé par un étudiant, elle ne peut pas être élue racine) ;
b2 eth0 `{mac_b2_eth0}` / eth1 `{mac_b2_eth1}` (`br0` = `{mac_br2}`), b3 eth0 `{mac_b3_eth0}` / eth1
`{mac_b3_eth1}` (`br0` = `{mac_br3}`) : à priorité égale, **`{first_root}`** est élue racine (plus petite
adresse MAC), puis `{final_root}` le devient avec la priorité {root_priority}.

L'évaluation lit `ip -j -d link` sur `b1`, `b2` et `b3` (ponts, ports, états STP, `root_id` /
`bridge_id`, `ageing_time`), `bridge -j fdb show br br0` sur `b1` après les pings, `nft list ruleset`
sur `b1` (famille `bridge` : une règle `drop` concernant `m2`), `ip -j -4 addr` et `ip route` sur `b1`,
puis douze `ping` depuis `m1` à `m4`, `gw` et `b1` (celui de `m2` vers `ext1` doit échouer : 4 s ; ceux
de la partie 6 sont précédés de `ip neigh flush all`). Une évaluation dure une dizaine de secondes. Les
ports de `b2` et `b3` sont bridés par `tc` (tbf {cap}) : deux ponts sans STP font une tempête de
diffusion visible sur tout le réseau mais inoffensive. Les serveurs de test (HTTP 80 / 8080 et UDP
530 / 630 sur toutes les machines sauf les ponts, journal `/var/log/sre_server_echo.log`) ne sont pas
évalués.
""").format(b1=d.ips.b1.ip, root_priority=ROOT_PRIORITY, final_root=final_root, first_root=first_root,
            mac_m1=mac_text(d.macs.m1), mac_m2=mac_text(d.macs.m2), mac_m3=mac_text(d.macs.m3),
            mac_gw=mac_text(d.macs.gw_lan), mac_b1_eth0=mac_text(d.macs.b1_eth0), mac_b1_eth1=mac_text(d.macs.b1_eth1),
            mac_br0=bridge_mac(d), mac_m4=mac_text(d.macs.m4),
            mac_b2_eth0=mac_text(d.macs.b2_eth0), mac_b2_eth1=mac_text(d.macs.b2_eth1), mac_br2=bridge_mac(d, 'b2'),
            mac_b3_eth0=mac_text(d.macs.b3_eth0), mac_b3_eth1=mac_text(d.macs.b3_eth1), mac_br3=bridge_mac(d, 'b3'),
            cap=STORM_CAP_RATE.replace('mbit', ' Mbit/s'))),
        )

        # =====================================================================
        # Part 1 — without a bridge (question 1)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Sans pont (question 1)"))

        q1_answers = {"why": "two_domains", "m2_m3": "same_switch"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Deux switchs sans pont"),
            hash="51083d5d95846312",
            description=tr("""
Les interfaces de la machine `b1` ne sont pas configurées (`ip link` sur `b1` : `eth0` et `eth1`
sont `DOWN`). Vérifiez que `m1` (`{m1}`) et `m2` (`{m2}`) ne peuvent pas communiquer (`ping`),
alors que `m2` et `m3` (`{m3}`) le peuvent, et que `m1` joint `ext1` (`{ext1}`) par `gw`. Pendant
le `ping {m1}` de `m2`, capturez sur `m2` avec `tcpdump -e -n -i eth0` : que fait `m2` ?
""").format(m1=d.ips.m1.ip, m2=d.ips.m2.ip, m3=d.ips.m3.ip, ext1=d.ips.ext1.ip)
            + tr("""
- pourquoi m1 et m2 ne se joignent-elles pas, bien qu'elles aient des adresses du même réseau ? @@{why:>s1 et s2 ne sont reliés par rien : deux domaines de diffusion séparés, la requête ARP de m2 (diffusion) n'arrive jamais à m1>>>two_domains|il manque une route sur m2 vers le réseau de m1>>>route|gw bloque le trafic entre s1 et s2>>>gw_blocks|m1 et m2 sont dans deux réseaux IP différents>>>different_networks}@@
- et m2 et m3 ? @@{m2_m3:>elles se joignent : même switch s2, donc même domaine de diffusion>>>same_switch|elles ne se joignent pas non plus>>>no|elles se joignent grâce à gw>>>via_gw}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer. `m2` émet des requêtes ARP `who-has {m1} tell {m2}` en diffusion
(`ff:ff:ff:ff:ff:ff`) qui ne quittent pas `s2` : `ping` affiche `Destination Host Unreachable`.
`m2` et `m3` sont sur le même switch, `m1` joint `ext1` par `gw` (sur `s1`).

- Réponses : deux domaines de diffusion séparés ; m2 et m3 se joignent (même switch).
- Cette question n'est évaluée que par le formulaire (l'état final de la maquette a un pont).
""").format(m1=d.ips.m1.ip, m2=d.ips.m2.ip)),
            cheat_answers={"final": q1_answers},
        )

        self.add_grade_element(
            title=no_tr("q_no_bridge"), max_grade=4, grade_part=part1, scope=CHOICE_SCOPE,
            grade=3 * int(_norm(q1.get("why")) == "two_domains") + int(_norm(q1.get("m2_m3")) == "same_switch"),
            description=tr("sans pont : deux domaines de diffusion séparés ; m2 et m3 sur le même switch"),
        )

        # =====================================================================
        # Part 2 — the bridge br0 (questions 2 to 4)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le pont br0 (questions 2 à 4)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Le pont br0 sur b1"),
            hash="8989ae1e04f27d30",
            description=tr("""
Sur `b1`, activez les deux interfaces puis créez un pont nommé **`{bridge}`** entre `eth0` et
`eth1` (section @@ref:linux-bridges@@ des Informations), **sans STP** (c'est le réglage par défaut ; avec STP le
pont mettrait 30 s à commuter), et activez-le. Vérifiez qu'à présent `m2` (`{m2}`) joint `m1`
(`{m1}`) et l'extérieur (`ext1`, `{ext1}`), et que `m1` joint `m2`. Regardez `bridge link` et
`ip -d link show {bridge}` sur `b1`.
""").format(bridge=BRIDGE, m1=d.ips.m1.ip, m2=d.ips.m2.ip, ext1=d.ips.ext1.ip)
            + instructor(tr("""
**Solution.** Sur `b1` :

```
{cmds}```

(`brctl addbr br0 ; brctl stp br0 off ; brctl addif br0 eth0 ; brctl addif br0 eth1 ; ip link set br0
up` dans le sujet d'origine.) `b1` ne fait que commuter : aucune adresse IP n'est nécessaire. `ip -d
link show br0` montre `stp_state 0`, `bridge_id 8000.{mac_br0}` (priorité 32768, l'adresse MAC du
pont). L'évaluation vérifie `br0` (type `bridge`, ports `eth0` et `eth1` : `master br0`), les trois
interfaces `up`, et des `ping` de `m2` vers `m1`, de `m1` vers `m2` et de `m3` vers `ext1` (le `ping` de `m2`
vers `ext1` est celui de la partie 4, où il doit échouer).
""").format(cmds=_lines(self.net_scheme.cmds_bridge()), mac_br0=bridge_mac(d))),
        )

        q3_answers = {"src_mac": "m2", "arp": "m2_mac", "m3_sees": "nothing", "br0_mac": bridge_mac(d),
                      "br0_mac_origin": "lowest_port"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Transparence du pont"),
            hash="c804d2e1ad0b5ad2",
            description=tr("""
Depuis `m2`, lancez `ping {m1}` et observez :

- sur `b1`, `tcpdump -e -n -i eth0 icmp` puis `tcpdump -e -n -i eth1 icmp` (les trames telles
  qu'elles entrent et sortent du pont) ;
- sur `m1`, `ip neigh` (sa table ARP) après le ping ;
- sur `m3`, `tcpdump -e -n -i eth0` pendant le ping de `m2` vers `m1` (videz d'abord la table
  ARP de `m2` avec `ip neigh flush all` pour revoir l'échange ARP) ;
- sur `b1`, `ip link show {bridge}` : l'adresse MAC du pont, à comparer à celles de `eth0` et
  `eth1`.
""").format(m1=d.ips.m1.ip, bridge=BRIDGE)
            + tr("""
- adresse MAC **source** des trames ICMP vues sur `eth0` de `b1` (du côté de m1) : @@{src_mac:>celle de m2 : le pont ne modifie pas les trames>>>m2|celle de eth1 de b1 : le pont réémet avec sa propre adresse>>>b1_eth1|celle de eth0 de b1>>>b1_eth0|celle de gw>>>gw}@@
- dans la table ARP de `m1`, l'adresse IP de `m2` correspond à : @@{arp:>l'adresse MAC de m2>>>m2_mac|l'adresse MAC du pont br0>>>bridge_mac|l'adresse MAC de gw>>>gw_mac|rien : m1 n'a pas d'entrée pour m2>>>none}@@
- sur `m3`, pendant le ping de m2 vers m1 : @@{m3_sees:>seulement la requête ARP de m2 (diffusion), pas les trames ICMP : le switch s2 ne les lui transmet pas>>>nothing|toutes les trames ICMP du ping : s2 répète tout>>>all|les trames ICMP aller mais pas les réponses>>>requests_only|la requête ARP et la réponse ARP de m1>>>arp_both}@@
- adresse MAC du pont `br0` : @@{br0_mac:[0-9a-fA-F:-]+}@@
- d'où vient-elle ? @@{br0_mac_origin:>c'est la plus petite des adresses MAC de ses ports>>>lowest_port|c'est une adresse aléatoire sans lien avec les ports>>>random|c'est celle de eth0, le premier port ajouté>>>first_port|c'est celle de la machine m1>>>m1}@@
""")
            + instructor(tr("""
**Solution.** Sur `eth0` comme sur `eth1` de `b1`, les trames ICMP vont de `{mac_m2}` (m2) à
`{mac_m1}` (m1) et retour : le pont les commute sans les modifier. `ip neigh` sur `m1` donne
`{m2} dev eth0 lladdr {mac_m2}`. Sur `m3`, seule la requête ARP de `m2` (diffusion) passe ; la
réponse ARP de `m1` est unicast vers `m2` et les trames ICMP aussi : le switch `s2` les livre au seul
port de `m2`. `br0` a pris l'adresse `{mac_br0}`, la plus petite de `{mac_b1_eth0}` (eth0) et
`{mac_b1_eth1}` (eth1).

- Réponses : celle de m2 ; l'adresse MAC de m2 ; seulement l'ARP ; `{mac_br0}` ; la plus petite des
  adresses de ses ports.
""").format(mac_m2=mac_text(d.macs.m2), mac_m1=mac_text(d.macs.m1), m2=d.ips.m2.ip, mac_br0=bridge_mac(d),
            mac_b1_eth0=mac_text(d.macs.b1_eth0), mac_b1_eth1=mac_text(d.macs.b1_eth1))),
            cheat_answers={"final": q3_answers},
        )

        q4_answers = {"rtt_bridged": "0.5", "rtt_direct": "0.2", "conclusion": "bridge_delay"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Latence avec et sans pont"),
            hash="338cdd86da44c550",
            description=tr("""
Déterminez la durée moyenne du `ping` entre `m2` et `m1` (`{m1}`, à travers le pont) puis entre
`m2` et `m3` (`{m3}`, sur le même switch), sur une dizaine d'essais chacun (`ping -c 10`, ligne
`rtt min/avg/max`). Qu'en concluez-vous ?
""").format(m1=d.ips.m1.ip, m3=d.ips.m3.ip)
            + tr("""
- durée moyenne m2 → m1, en ms : @@{rtt_bridged:[0-9.,]+}@@
- durée moyenne m2 → m3, en ms : @@{rtt_direct:[0-9.,]+}@@
- conclusion : @@{conclusion:>le trajet par le pont est plus long : chaque trame est reçue en entier puis réémise par b1 (store and forward), et traverse un second switch>>>bridge_delay|les deux durées sont identiques : un pont est transparent, donc sans effet sur le délai>>>same|le trajet par le pont est plus court : b1 accélère les trames>>>faster|le trajet par le pont est plus long parce que b1 route les paquets>>>routing}@@
""")
            + instructor(tr("""
**Solution.** Les valeurs dépendent de la machine hôte (quelques dixièmes de milliseconde) ; le
trajet `m2` → `m1` traverse `s2`, le pont `b1` (réception complète de la trame, consultation de la
table MAC, réémission) puis `s1` : il est en moyenne plus long que `m2` → `m3` (un seul switch). Le
formulaire est évalué sur la conclusion et sur la présence de deux mesures plausibles (0 à 1000 ms).
""")),
            cheat_answers={"final": q4_answers},
        )

        self.add_grade_element(
            title=no_tr("bridge_ports"), max_grade=4, grade_part=part2,
            grade=0 if ports_b1 is None else 2 * int('eth0' in ports_b1) + 2 * int('eth1' in ports_b1),
            description=tr("{bridge} est un pont dont eth0 et eth1 sont les ports (sur b1)").format(bridge=BRIDGE),
        )
        self.add_grade_element(
            title=no_tr("bridge_up"), max_grade=2, grade_part=part2,
            grade=2 * int(link_up(links_b1, BRIDGE) and link_up(links_b1, 'eth0') and link_up(links_b1, 'eth1')),
            description=tr("{bridge}, eth0 et eth1 sont actives (up) sur b1").format(bridge=BRIDGE),
        )
        self.add_grade_element(
            title=no_tr("bridged_connectivity"), max_grade=6, grade_part=part2,
            grade=2 * int(p['m2_m1']) + 2 * int(p['m1_m2']) + 2 * int(p['m3_ext1']),
            description=tr("à travers le pont : m2 joint m1, m1 joint m2, m3 joint ext1 (m2 vers ext1 : partie 4)"),
        )
        self.add_grade_element(
            title=no_tr("q_transparency_typed"), max_grade=1, grade_part=part2,
            grade=int(_same_mac(q3.get("br0_mac"), bridge_mac(d))),
            description=tr("transparence : adresse MAC de br0"),
        )
        self.add_grade_element(
            title=no_tr("q_transparency"), max_grade=5, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get("src_mac")) == "m2") + int(_norm(q3.get("arp")) == "m2_mac")
                  + 2 * int(_norm(q3.get("m3_sees")) == "nothing")
                  + int(_norm(q3.get("br0_mac_origin")) == "lowest_port"),
            description=tr("transparence : adresses MAC inchangées, table ARP de m1, ce que voit m3, origine de "
                           "l'adresse MAC de br0"),
        )
        self.add_grade_element(
            title=no_tr("q_latency_typed"), max_grade=2, grade_part=part2,
            grade=int(_float_in(q4.get("rtt_bridged"), 0, 1000)) + int(_float_in(q4.get("rtt_direct"), 0, 1000)),
            description=tr("latence : deux mesures"),
        )
        self.add_grade_element(
            title=no_tr("q_latency"), max_grade=3, grade_part=part2, scope=CHOICE_SCOPE,
            grade=3 * int(_norm(q4.get("conclusion")) == "bridge_delay"),
            description=tr("latence : la conclusion (le pont ajoute un délai)"),
        )

        # =====================================================================
        # Part 3 — the MAC table (question 5)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Table MAC du pont (question 5)"))

        q5_answers = {"port_m1": "eth0", "port_m3": "eth1", "mac_m3": mac_text(d.macs.m3)}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Table MAC et durée de vie des entrées"),
            hash="5242eed1f9d9071b",
            description=tr("""
Après des `ping` de `m2` vers `m1` et de `m3` vers `m1`, affichez la table MAC du pont sur `b1`
(`bridge fdb show br {bridge}` ; `bridge -s fdb show br {bridge}` ajoute l'ancienneté de chaque
entrée). Repérez les adresses apprises (sans `permanent`) et le port où chacune a été vue.

Réglez ensuite la durée de vie des entrées à **{ageing} secondes** (`ageing_time`, en centièmes
de seconde, section @@ref:linux-bridges@@ des Informations), vérifiez-la avec `ip -d link show {bridge}`, puis que
l'entrée de `m3` disparaît {ageing} s après son dernier échange (en l'absence de tout trafic de
`m3`).
""").format(bridge=BRIDGE, ageing=AGEING_SECONDS)
            + tr("""
- port de `br0` sur lequel l'adresse MAC de `m1` est apprise : @@{port_m1:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- port sur lequel celle de `m3` est apprise : @@{port_m3:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- adresse MAC de `m3` : @@{mac_m3:[0-9a-fA-F:-]+}@@
""")
            + instructor(tr("""
**Solution.** `bridge fdb show br br0` donne `{mac_m1} dev eth0 master br0` (m1, côté `s1`),
`{mac_m2} dev eth1 master br0` et `{mac_m3} dev eth1 master br0` (m2 et m3, côté `s2`), ainsi que
`{mac_gw} dev eth0` (gw) s'il a trafiqué ; les lignes `permanent` sont les adresses de `eth0` et `eth1`.
Puis :

```
{cmds}```

`ip -d link show br0` affiche `ageing_time {centi}`. Sans trafic de `m3`, son entrée disparaît
après {ageing} s (`bridge -s fdb show br br0` montre l'ancienneté). Remarque : pendant un changement de
topologie STP (partie 6), le noyau ramène de lui-même la durée de vie à 2 × *forward delay* = 30 s
(`ageing_time 3000` apparaît alors pendant ~35 s même sans réglage), puis restaure la valeur réglée.

- Réponses : eth0 ; eth1 ; `{mac_m3}`.
- L'évaluation relit la table après ses propres pings (m1 sur eth0, m2 et m3 sur eth1) et
  `ageing_time` ({centi} centièmes = {ageing} s).
""").format(mac_m1=mac_text(d.macs.m1), mac_m2=mac_text(d.macs.m2), mac_m3=mac_text(d.macs.m3), mac_gw=mac_text(d.macs.gw_lan),
            cmds=_lines(self.net_scheme.cmds_ageing()), centi=AGEING_SECONDS * 100, ageing=AGEING_SECONDS)),
            cheat_answers={"final": q5_answers},
        )

        self.add_grade_element(
            title=no_tr("q_fdb_typed"), max_grade=2, grade_part=part3,
            grade=2 * int(_same_mac(q5.get("mac_m3"), d.macs.m3)),
            description=tr("table MAC : adresse MAC de m3"),
        )
        self.add_grade_element(
            title=no_tr("q_fdb"), max_grade=2, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q5.get("port_m1")) == "eth0") + int(_norm(q5.get("port_m3")) == "eth1"),
            description=tr("table MAC : port de m1, port de m3"),
        )
        self.add_grade_element(
            title=no_tr("fdb_learned"), max_grade=5, grade_part=part3,
            grade=2 * int(fdb_port_of(fdb, d.macs.m1) == 'eth0') + int(fdb_port_of(fdb, d.macs.m2) == 'eth1')
                  + 2 * int(fdb_port_of(fdb, d.macs.m3) == 'eth1'),
            description=tr("le pont apprend m1 sur eth0, m2 et m3 sur eth1 (table lue après les pings de l'évaluation)"),
        )
        self.add_grade_element(
            title=no_tr("ageing_time"), max_grade=4, grade_part=part3,
            grade=4 * int(bool(info_b1) and info_b1['ageing_time'] == AGEING_SECONDS),
            description=tr("durée de vie des entrées de la table MAC de {bridge} : {ageing} s").format(
                bridge=BRIDGE, ageing=AGEING_SECONDS),
        )

        # =====================================================================
        # Part 4 — layer-2 filtering (question 6)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Filtrage de niveau 2 (question 6)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("m2 ne doit plus joindre l'extérieur"),
            hash="3635e81495b525a6",
            description=tr("""
En utilisant la famille **`bridge`** de nftables et le hook **`forward`** (section @@ref:filtering@@ des
Informations), interdisez à `m2` (`{m2}`) de communiquer avec l'extérieur (`ext1`, `{ext1}`,
au-delà de `gw`), sans toucher aux autres communications : `m1` et `m2` doivent toujours se
joindre, et `m3` ne doit pas être affectée (elle joint toujours `ext1`). Les trames de `m2`
vers l'extérieur ont pour destination l'adresse MAC de `gw` : lisez-la dans `ip neigh` sur `m2`
ou dans la table du pont. Vérifiez avec `ping` depuis `m2`, `m1` et `m3`, et affichez votre
règle avec `nft list ruleset`.
""").format(m2=d.ips.m2.ip, ext1=d.ips.ext1.ip)
            + instructor(tr("""
**Solution.** Sur `b1`, par adresses MAC (m2 `{mac_m2}` → gw `{mac_gw}`) :

```
{cmds}```

ou, par adresses IP (tout ce que m2 envoie hors du réseau local) :

```
{by_ip}```

Les requêtes de `m2` vers `ext1` ne sont plus commutées vers `s1` : `ping` n'a pas de réponse
(100 % de pertes). Les trames de `m2` vers `m1` (autre adresse MAC de destination) passent, celles
de `m3` aussi. L'évaluation vérifie que `m2` ne joint plus `ext1` alors que `m1` et `m3` la joignent
et que `m1` et `m2` se joignent, et cherche dans la famille `bridge` de `nft list ruleset` une règle
`drop` qui mentionne `m2` (`ether saddr` / `ether daddr` ou `ip saddr` / `ip daddr`), de
préférence dans une chaîne du hook `forward`.
""").format(mac_m2=mac_text(d.macs.m2), mac_gw=mac_text(d.macs.gw_lan), cmds=_lines(self.net_scheme.cmds_filter()),
            by_ip=_lines(self.net_scheme.cmds_filter_by_ip()))),
        )

        self.add_grade_element(
            title=no_tr("filter_m2_blocked"), max_grade=5, grade_part=part4,
            grade=5 * int(not p['m2_ext1'] and p['m2_m1']),
            description=tr("m2 ne joint plus ext1 (et joint toujours m1)"),
        )
        self.add_grade_element(
            title=no_tr("filter_others_ok"), max_grade=5, grade_part=part4,
            grade=3 * int(p['m3_ext1']) + int(p['m2_m1']) + int(p['m1_m2']),
            description=tr("m3 joint toujours ext1, m1 et m2 se joignent toujours"),
        )
        self.add_grade_element(
            title=no_tr("filter_rule"), max_grade=4, grade_part=part4,
            grade=2 * int(bool(concerned)) + 2 * int(any(rule['hook'] == 'forward' for rule in concerned)),
            description=tr("une règle drop de la famille bridge concernant m2, dans le hook forward"),
        )

        # =====================================================================
        # Part 5 — an IP address on the bridge (question 7)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Adresse IP sur le pont (question 7)"))

        q7_answers = {"why_br0": "port_frames_to_bridge"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("b1 joignable : une adresse sur br0"),
            hash="5b965e4d571f16fa",
            description=tr("""
Ajoutez l'adresse IP `{b1}` à la machine `b1`, **sur l'interface `{bridge}`**, et vérifiez
qu'elle devient joignable depuis `m1`, `m2`, `m3` et `gw`. Ajoutez aussi à `b1` une route par
défaut vers `gw` (`{gw}`) et vérifiez qu'elle joint `ext1` (`{ext1}`). Pourquoi l'adresse va-t-elle
sur `{bridge}` et non sur `eth0` ou `eth1` ?
""").format(b1=d.ips.b1, bridge=BRIDGE, gw=d.ips.gw_lan.ip, ext1=d.ips.ext1.ip)
            + tr("""
- pourquoi sur `br0` ? @@{why_br0:>eth0 et eth1 sont des ports : les trames qu'ils reçoivent sont remises au pont, qui les commute ; br0 est l'interface de la machine dans le réseau ponté>>>port_frames_to_bridge|parce que eth0 et eth1 n'ont pas d'adresse MAC>>>no_mac|parce qu'une adresse sur eth0 ne serait joignable que depuis s1>>>only_s1|c'est une convention : eth0 fonctionnerait aussi bien>>>convention}@@
""")
            + instructor(tr("""
**Solution.** Sur `b1` :

```
{cmds}```

Une interface devenue port d'un pont ne traite plus les trames qu'elle reçoit : elles sont remises
au pont, qui les commute ou, si leur adresse MAC de destination est celle du pont, les livre à la
pile IP de la machine par `br0`. L'adresse doit donc être sur `br0`, qui répond aux ARP des deux
côtés. L'évaluation vérifie l'adresse sur `br0` (et aucune sur `eth0` / `eth1`), les `ping` de `m1`,
`m2`, `m3` et `gw` vers `{b1}`, la route par défaut et le `ping` de `b1` vers `ext1`.
""").format(cmds=_lines(self.net_scheme.cmds_bridge_address()), b1=d.ips.b1.ip)),
            cheat_answers={"final": q7_answers},
        )

        self.add_grade_element(
            title=no_tr("bridge_address"), max_grade=4, grade_part=part5,
            grade=3 * int(interface_of_address(addrs_b1, d.ips.b1) == BRIDGE)
                  + int(interface_of_address(addrs_b1, d.ips.b1) == BRIDGE and not addresses_of(addrs_b1, 'eth0')
                        and not addresses_of(addrs_b1, 'eth1')),
            description=tr("{b1} sur {bridge} de b1, rien sur eth0 ni eth1").format(b1=d.ips.b1.ip, bridge=BRIDGE),
        )
        self.add_grade_element(
            title=no_tr("bridge_reachable"), max_grade=5, grade_part=part5,
            grade=int(p['m1_b1']) + int(p['m2_b1']) + int(p['m3_b1']) + 2 * int(p['gw_b1']),
            description=tr("b1 ({b1}) est joignable depuis m1, m2, m3 et gw").format(b1=d.ips.b1.ip),
        )
        self.add_grade_element(
            title=no_tr("bridge_default_route"), max_grade=2, grade_part=part5,
            grade=int(routes_b1.get(('0.0.0.0', 0), ('',))[0] == str(d.ips.gw_lan.ip)) + int(p['b1_ext1']),
            description=tr("route par défaut de b1 via gw, b1 joint ext1"),
        )
        self.add_grade_element(
            title=no_tr("q_address_on_bridge"), max_grade=3, grade_part=part5, scope=CHOICE_SCOPE,
            grade=3 * int(_norm(q7.get("why_br0")) == "port_frames_to_bridge"),
            description=tr("pourquoi l'adresse va sur br0 et non sur un port"),
        )

        # =====================================================================
        # Part 6 — STP between s3 and s1 (question 8)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Redondance et STP (question 8)"))

        # the port of the first root that blocks once the other bridge is the root: its root port is
        # the one hearing the lowest port id of the new root (eth0 when enslaved first, as `final`
        # does); the form answer is graded against the live state, this is the cheat answer only
        q8_answers = {"root_bridge": first_root, "why_root": "lowest_mac", "root_priority": str(DEFAULT_PRIORITY),
                      "hello": str(STP_HELLO), "max_age": str(STP_MAX_AGE), "forward_delay": str(STP_FORWARD_DELAY),
                      "blocked_port": f"{first_root}_eth1", "without_stp": "storm"}
        live_blocked = f"{first_root}_{blocking[first_root][0]}" if len(blocking[first_root]) == 1 else None
        q8 = self.question_form(
            section=self.section(0),
            title=tr("Deux ponts en parallèle : boucle et STP"),
            hash="43db0a3f26906627",
            description=tr("""
Le switch `s3` (avec `m4`, `{m4}`) est relié à `s1` par deux machines `b2` et `b3` non configurées,
chacune avec `eth0` sur `s3` et `eth1` sur `s1`. Deux ponts entre les mêmes switchs forment une
**boucle** (`s1` → `b2` → `s3` → `b3` → `s1`) : sans STP, la première trame de diffusion (une
requête ARP, d'où qu'elle vienne sur le réseau) tournerait indéfiniment (section @@ref:stp@@ des Informations).
Jusqu'ici `m4` est isolée ; pontée, elle joint `m1`, `gw` et, par sa route par défaut, `ext1`.

**(a)** Faites de `b2` **et** de `b3` des ponts `{bridge}` entre `eth0` et `eth1`, **avec STP
activé dès la création** (`ip link add {bridge} type bridge stp_state 1`, avant d'ajouter les
ports). Attendez une trentaine de secondes, vérifiez depuis `m4` que `m1` et `ext1` répondent, puis
regardez `bridge link` et `ip -d link show {bridge}` sur les deux ponts : quel pont est la racine
(`root_id` égal à `bridge_id`) et pourquoi ? Sur l'autre pont, un port est *blocking*.

*Facultatif* : les interfaces de `b2` et `b3` sont bridées à {cap}, vous pouvez donc observer
sans danger une tempête. Désactivez STP sur les deux ponts (`stp_state 0`) : rien ne se passe, le
port *blocking* le reste (arrêter STP ne change pas l'état des ports). Sur ce pont, désactivez puis
réactivez ce port (`ip link set eth1 down`, `ip link set eth1 up`) : sans STP, un port qui s'active
commute aussitôt, et la boucle est fermée. Capturez sur `m4` ou sur `m1` avec `tcpdump -e -n -i
eth0` : chaque diffusion du réseau (les requêtes ARP) tourne et se multiplie, `s2` compris à
travers `b1`. Sur `m2`, faites `ip neigh flush all` puis `ping m1` : les copies de sa requête ARP
reviennent par `s1`, `b1` apprend `m2` sur `eth0` (`bridge fdb show`) et `m2` ne joint plus `m1`.
Rétablissez STP (`stp_state 1`) : la tempête cesse en quelques secondes ; attendez 30 s et videz
la table ARP de `m4` (`ip neigh flush all`) avant de refaire un `ping` (voir la remarque du (c)).

**(b)** Sur `m4`, capturez quelques BPDU avec `tcpdump -n -v -i eth0 stp` (`-v` affiche les
temporisateurs et `root-id`) : relevez la priorité de la racine (dans `root-id`, en hexadécimal)
et les trois temporisateurs.

**(c)** Faites de **l'autre pont** la racine en lui donnant une priorité plus petite
(`ip link set {bridge} type bridge priority N`), attendez encore une trentaine de secondes et
vérifiez : `root_id` égal à `bridge_id` sur ce pont, ses deux ports en `forwarding`, un port de
l'ancienne racine *blocking*, `m4` joint toujours `m1` et `ext1`. Si le `ping` échoue juste après
le changement, videz la table ARP de la machine d'où vous le lancez (`ip neigh flush all` sur
`m4`) : les switchs `s1` et `s3` ne participent pas à STP et gardent jusqu'à ~100 s une entrée
périmée vers le port qui vient d'être bloqué (ou vers un pont qui n'a plus de port actif pour
commuter), jusqu'à ce qu'une diffusion de cette machine (sa requête ARP) leur fasse réapprendre
les adresses. Que se passerait-il sans STP ?
""").format(m4=d.ips.m4.ip, bridge=BRIDGE, cap=STORM_CAP_RATE.replace('mbit', ' Mbit/s'))
            + tr("""
- (a) pont élu racine : @@{root_bridge:>b2>>>b2|b3>>>b3}@@
- (a) pourquoi lui ? @@{why_root:>même priorité (32768) sur les deux ponts : l'identifiant le plus petit est celui dont l'adresse MAC est la plus petite>>>lowest_mac|sa priorité est plus petite>>>priority|il a été activé le premier>>>first|son port eth0 a été ajouté le premier>>>first_port}@@
- (b) priorité de la racine lue dans les BPDU (en décimal ou en hexadécimal) : @@{root_priority:[0-9a-fA-Fx]+}@@
- (b) *hello time*, en secondes : @@{hello:[0-9.]+}@@
- (b) *max age*, en secondes : @@{max_age:[0-9.]+}@@
- (b) *forward delay*, en secondes : @@{forward_delay:[0-9.]+}@@
- (c) port *blocking* une fois la nouvelle racine en place : @@{blocked_port:>eth0 de b2>>>b2_eth0|eth1 de b2>>>b2_eth1|eth0 de b3>>>b3_eth0|eth1 de b3>>>b3_eth1|aucun>>>none}@@
- (c) sans STP, avec cette boucle : @@{without_stp:>une tempête de diffusion : chaque trame de diffusion tourne indéfiniment en se multipliant, et les tables MAC deviennent instables>>>storm|rien de particulier : les deux ponts se partagent le trafic>>>load_balance|les trames unicast sont dupliquées mais les diffusions passent normalement>>>unicast_only|le second pont refuse de commuter tant que le premier commute>>>second_waits}@@
""")
            + instructor(tr("""
**Solution.** (a) Sur `b2` et sur `b3` :

```
{cmds}```

Après 30 s, les deux ponts ont la priorité 32768 : la racine est le pont dont l'identifiant
(`8000.` + adresse MAC du pont, la plus petite de ses ports) est le plus petit, ici **`{first_root}`**
(`{mac_first}` contre `{mac_final}` pour `{final_root}`) ; `ip -d link show br0` y donne `root_id` =
`bridge_id` = `8000.{mac_first}`. Sur `{final_root}`, `bridge link` montre `eth0 ... state forwarding`
(port racine : il reçoit les BPDU du port 1 de la racine, sur `s3`) et `eth1 ... state blocking`.

(b) `tcpdump -n -v -i eth0 stp` sur `m4` : `STP 802.1d, Config, Flags [none], bridge-id
8000.{mac_first}.8001, length 35` (`Flags [Topology change]` pendant la demi-minute qui suit un
changement), puis `message-age 0.00s, max-age {max_age}.00s, hello-time {hello}.00s, forwarding-delay
{forward_delay}.00s` et `root-id 8000.{mac_first}, root-pathcost 0`. Priorité de la racine : 0x8000 =
{default_priority} ; hello {hello} s, max age {max_age} s, forward delay {forward_delay} s.

(c) Sur `{final_root}` : `{root}` (toute valeur inférieure à {default_priority} convient). Après 30 s,
`root_id` = `bridge_id` = `1000.{mac_final}` sur `{final_root}`, ses deux ports `forwarding`, et
`{first_root}` bloque son `eth1` (son port racine est `eth0`, qui entend le port 1 de la nouvelle racine
sur `s3` ; ce serait `eth0` si `eth1` de `{final_root}` avait été ajouté le premier). Les switchs `s1` /
`s3` (vde, sans STP) gardent ~100 s l'entrée de `m4` / `m1` vers `{first_root}`, qui ne commute plus :
`ping` échoue jusqu'à une diffusion ARP de la machine qui l'émet (l'évaluation vide la table ARP de `m4`
et de `m1` avant ses pings, un étudiant fait `ip neigh flush all`). Sans STP, la boucle ferait tourner
indéfiniment chaque trame de diffusion du réseau (tempête, bridée ici à {cap} mais visible sur `s1` et
`s2`) et les tables MAC verraient chaque adresse sur les deux ports. Tempête facultative du (a) : arrêter
STP laisse le port bloqué dans cet état, c'est `ip link set eth1 down` / `up` sur ce port qui ferme la
boucle ; mesuré avec la bride à {cap} : 3 000 à 4 000 trames/s sur chaque machine du réseau, `m2` ne joint
plus `m1` (`b1` apprend `m2` sur `eth0`), `m1` joint encore `ext1`, l'évaluation pendant la tempête
perd une vingtaine de points, tout rentre dans l'ordre quelques secondes après `stp_state 1`.

- Réponses : {first_root} ; même priorité, plus petite adresse MAC ; {default_priority} (0x8000) ; {hello} ;
  {max_age} ; {forward_delay} ; eth1 de {first_root} (le port réellement bloqué est accepté) ; tempête.
- L'évaluation lit sur `b2` et `b3` `stp_state`, les ports, `root_id` / `bridge_id` et l'état des ports
  (`{final_root}` racine avec une priorité inférieure à {default_priority} et deux ports `forwarding`,
  `{first_root}` avec un seul port `blocking` et `{final_root}` pour racine), puis `ping` de `m4` vers `m1`
  et `ext1` et de `m1` vers `m4` (précédés de `ip neigh flush all`).
""").format(cmds=_lines(self.net_scheme.cmds_stp_bridge()), first_root=first_root, final_root=final_root,
            mac_first=bridge_mac(d, first_root), mac_final=bridge_mac(d, final_root),
            max_age=STP_MAX_AGE, hello=STP_HELLO, forward_delay=STP_FORWARD_DELAY, default_priority=DEFAULT_PRIORITY,
            root=self.net_scheme.cmds_root()[0], cap=STORM_CAP_RATE.replace('mbit', ' Mbit/s'))),
            cheat_answers={"final": q8_answers},
        )

        def stp_bridge_ok(m):
            ports = bridge_ports(links[m]).get(BRIDGE)
            return int(ports is not None and 'eth0' in ports and 'eth1' in ports) + int(bool(infos[m]) and infos[m]['stp'])

        self.add_grade_element(
            title=no_tr("stp_bridges"), max_grade=4, grade_part=part6,
            grade=sum(stp_bridge_ok(m) for m in STP_BRIDGES),
            description=tr("{bridge} avec les ports eth0 et eth1 et STP actif sur b2 et sur b3").format(bridge=BRIDGE),
        )
        self.add_grade_element(
            title=no_tr("stp_connectivity"), max_grade=4, grade_part=part6,
            grade=int(p['m4_m1']) + int(p['m1_m4']) + 2 * int(p['m4_ext1']),
            description=tr("m4 joint m1 et, par sa route par défaut, ext1 à travers la boucle ; m1 joint m4"),
        )
        self.add_grade_element(
            title=no_tr("q_root_election"), max_grade=3, grade_part=part6, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q8.get("root_bridge")) == first_root) + int(_norm(q8.get("why_root")) == "lowest_mac"),
            description=tr("pont élu racine à priorité égale ({first_root}) et pourquoi (plus petite adresse MAC)").format(
                first_root=first_root),
        )
        self.add_grade_element(
            title=no_tr("q_bpdu"), max_grade=4, grade_part=part6,
            grade=int(_is_priority(q8.get("root_priority"), DEFAULT_PRIORITY))
                  + int(_float_in(q8.get("hello"), STP_HELLO - 0.01, STP_HELLO + 0.01))
                  + int(_float_in(q8.get("max_age"), STP_MAX_AGE - 0.01, STP_MAX_AGE + 0.01))
                  + int(_float_in(q8.get("forward_delay"), STP_FORWARD_DELAY - 0.01, STP_FORWARD_DELAY + 0.01)),
            description=tr("BPDU : priorité de la racine, hello time, max age, forward delay"),
        )
        new_root = infos[final_root]
        self.add_grade_element(
            title=no_tr("new_root"), max_grade=7, grade_part=part6,
            grade=4 * int(bool(new_root) and new_root['stp'] and new_root['is_root']
                          and (new_root['priority'] or DEFAULT_PRIORITY) < DEFAULT_PRIORITY)
                  + 3 * int(states[final_root].get('eth0') == 'forwarding' and states[final_root].get('eth1') == 'forwarding'),
            description=tr("{final_root} est la racine (priorité abaissée, root_id = bridge_id) avec ses deux ports en forwarding").format(
                final_root=final_root),
        )
        old_root = infos[first_root]
        self.add_grade_element(
            title=no_tr("old_root_blocks"), max_grade=5, grade_part=part6,
            grade=3 * int(bool(old_root) and old_root['stp'] and len(states[first_root]) == 2 and len(blocking[first_root]) == 1
                          and 'forwarding' in states[first_root].values())
                  + 2 * int(bool(old_root) and bool(new_root) and old_root['root_id'] == new_root['bridge_id'] and new_root['is_root']),
            description=tr("{first_root} bloque un seul de ses ports et reconnaît {final_root} comme racine").format(
                first_root=first_root, final_root=final_root),
        )
        self.add_grade_element(
            title=no_tr("q_blocked_port"), max_grade=3, grade_part=part6, scope=CHOICE_SCOPE,
            grade=3 * int(live_blocked is not None and _norm(q8.get("blocked_port")) == live_blocked),
            description=tr("le port bloqué une fois la nouvelle racine en place (comparé à l'état réel de {first_root})").format(
                first_root=first_root),
        )
        self.add_grade_element(
            title=no_tr("q_without_stp"), max_grade=2, grade_part=part6, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q8.get("without_stp")) == "storm"),
            description=tr("sans STP : tempête de diffusion"),
        )

_TRANSLATIONS = {'en': {
    "Ponts Ethernet : pont Linux, table MAC, filtrage et STP": "Ethernet bridges: Linux bridge, MAC table, filtering and STP",
    """**Adresses IP des réseaux :**
""": """**IP addresses of the networks:**
""",
    """@@{ip_choice:>Aléatoires, propres à cette instance>>>random|Celles du sujet : 192.168.1.0/24 (et 10.10.10.0/24 pour l'extérieur)>>>fixed}@@

""": """@@{ip_choice:>Random, specific to this instance>>>random|Those of the handout: 192.168.1.0/24 (and 10.10.10.0/24 for the outside)>>>fixed}@@

""",
    """Les numéros de machine sont les mêmes dans les deux cas (`m1` = `.1`, `b1` = `.110`, `gw` = `.254`...).

""": """The machine numbers are the same in both cases (`m1` = `.1`, `b1` = `.110`, `gw` = `.254`...).

""",
    "Démarrer le projet": "Start the project",
    """**Sommaire**
""": """**Contents**
""",
    "Rappels : trames, adresses MAC, hubs et switchs": "Reminders: frames, MAC addresses, hubs and switches",
    """

Une **trame Ethernet** porte une adresse MAC de destination, une adresse MAC source (48 bits,
`02:53:52:0a:0b:0c`), un type (`0x0800` IPv4, `0x0806` ARP) et des données. L'adresse
`ff:ff:ff:ff:ff:ff` est la **diffusion** (*broadcast*) : toutes les machines du réseau la
reçoivent (c'est ainsi qu'ARP demande « qui a l'adresse IP X ? »). Une adresse dont le premier
octet est impair (`01:...`, `33:33:...`) est une adresse multicast.

Un **hub** répète chaque trame sur tous ses ports. Un **switch** (commutateur) apprend sur quel
port se trouve chaque adresse MAC source qu'il voit passer (sa **table MAC**) et ne transmet une
trame unicast que sur le port de son destinataire ; les diffusions, les multicasts et les trames
dont le destinataire est encore inconnu sont envoyés sur tous les ports (*flooding*). Toutes les
machines reliées par des hubs et des switchs forment un seul **domaine de diffusion** : un réseau
IP (`192.168.1.0/24`) occupe normalement un domaine de diffusion. Deux switchs reliés par un
câble forment un seul domaine ; deux switchs **non reliés** forment deux domaines, et une
machine de l'un ne peut pas joindre une machine de l'autre, même avec des adresses IP du même
réseau : sa requête ARP n'arrive jamais.
""": """

An **Ethernet frame** carries a destination MAC address, a source MAC address (48 bits,
`02:53:52:0a:0b:0c`), a type (`0x0800` IPv4, `0x0806` ARP) and data. The address
`ff:ff:ff:ff:ff:ff` is the **broadcast** address: every machine of the network receives it
(that is how ARP asks "who has IP address X?"). An address whose first octet is odd
(`01:...`, `33:33:...`) is a multicast address.

A **hub** repeats every frame on all its ports. A **switch** learns on which port each source
MAC address it sees go by is located (its **MAC table**) and forwards a unicast frame only on
the port of its recipient; broadcasts, multicasts and frames whose recipient is still unknown
are sent on every port (*flooding*). All the machines joined by hubs and switches form a single
**broadcast domain**: an IP network (`192.168.1.0/24`) normally occupies one broadcast domain.
Two switches joined by a cable form a single domain; two switches that are **not joined** form
two domains, and a machine of one cannot reach a machine of the other, even with IP addresses
of the same network: its ARP request never arrives.
""",
    "Le pont transparent": "The transparent bridge",
    """

Un **pont** (*bridge*, IEEE 802.1D) relie deux segments Ethernet au niveau 2 : il reçoit chaque
trame sur un port, la mémorise entièrement (*store and forward*), lit l'adresse source pour
apprendre sur quel port est l'émetteur, puis la réémet sur le port de son destinataire (ou sur
tous les autres ports s'il ne le connaît pas). Un switch n'est rien d'autre qu'un pont à
beaucoup de ports.

Le pont est **transparent** : il ne modifie pas les trames (adresses MAC source et destination
inchangées, pas de champ TTL décrémenté), il n'a pas besoin d'adresse IP et les machines ne
savent pas qu'il existe : dans la table ARP de `m1`, l'adresse IP de `m2` correspond à la vraie
adresse MAC de `m2`, pas à celle du pont. Un **routeur**, au contraire, termine les trames (elles
lui sont adressées) et en émet de nouvelles avec ses propres adresses MAC, relie des réseaux IP
différents et décrémente le TTL. Le prix de la transparence : un pont ajoute un délai (il attend
la trame complète avant de la réémettre) et il **prolonge le domaine de diffusion** (une
tempête de broadcast le traverse).

Les entrées de la table MAC d'un pont ont une durée de vie (*ageing time*, 300 s par défaut) :
une adresse qui n'a plus émis depuis ce délai est oubliée, et les trames qui lui sont destinées
sont de nouveau diffusées sur tous les ports jusqu'à ce qu'elle se manifeste. Une machine
déplacée d'un port à l'autre est réapprise dès qu'elle émet.
""": """

A **bridge** (IEEE 802.1D) joins two Ethernet segments at layer 2: it receives each frame on a
port, stores it entirely (*store and forward*), reads the source address to learn on which port
the sender is, then sends the frame out again on the port of its recipient (or on every other
port if it does not know it). A switch is nothing but a bridge with many ports.

The bridge is **transparent**: it does not modify the frames (source and destination MAC
addresses unchanged, no TTL field decremented), it needs no IP address and the machines do not
know it exists: in the ARP table of `m1`, the IP address of `m2` maps to the real MAC address
of `m2`, not to that of the bridge. A **router**, on the contrary, terminates the frames (they
are addressed to it) and sends new ones with its own MAC addresses, joins different IP networks
and decrements the TTL. The price of transparency: a bridge adds a delay (it waits for the
complete frame before sending it out again) and it **extends the broadcast domain** (a
broadcast storm crosses it).

The entries of the MAC table of a bridge have a lifetime (*ageing time*, 300 s by default): an
address that has sent nothing for that long is forgotten, and the frames addressed to it are
flooded on every port again until it shows up. A machine moved from one port to another is
learned again as soon as it sends.
""",
    "Les ponts sous Linux": "Bridges on Linux",
    """

Le noyau Linux contient un pont logiciel : une interface virtuelle `brX` à laquelle on rattache
des **ports** (des interfaces physiques, ou virtuelles). Les ports n'ont **pas** d'adresse IP et
doivent être `up` ; le pont lui-même peut porter une adresse IP si la machine doit être
joignable (elle est alors à la fois le switch et une machine branchée dessus).

```
ip link set eth0 up ; ip link set eth1 up        # les ports doivent être actifs
ip link add br0 type bridge                      # crée le pont (STP désactivé par défaut)
ip link set eth0 master br0                      # eth0 devient un port de br0
ip link set eth1 master br0
ip link set br0 up                               # active le pont : il commute
bridge link                                      # les ports de chaque pont et leur état
bridge fdb show br br0                           # la table MAC de br0 (fdb : forwarding database)
ip -d link show br0                              # les paramètres du pont (-d : détails)
ip link set eth1 nomaster                        # retire un port
ip link del br0                                  # supprime le pont
```

(`brctl addbr br0`, `brctl addif br0 eth0`, `brctl show`, `brctl showmacs br0` du paquet
historique `bridge-utils` font la même chose.)

L'adresse MAC du pont est, sauf si on la fixe, **la plus petite des adresses MAC de ses ports**
(`ip link show br0`). Dans `bridge fdb show br br0`, les lignes `permanent` sont les adresses des
ports eux-mêmes ; les autres sont les adresses apprises, avec le port (`dev`) où la machine a été
vue ; `bridge -s fdb show br br0` ajoute le temps écoulé depuis la dernière trame. La durée de
vie des entrées se règle en **centièmes de seconde** : `ip link set br0 type bridge ageing_time
3000` (30 s ; `ip -d link show br0` affiche `ageing_time 3000`). Pour donner une adresse IP à la
machine dans le réseau ponté, l'adresse va sur `br0` (`ip address add 192.168.1.110/24 dev
br0`), jamais sur un port.
""": """

The Linux kernel contains a software bridge: a virtual interface `brX` to which **ports**
(physical or virtual interfaces) are attached. The ports have **no** IP address and must be
`up`; the bridge itself may carry an IP address if the machine must be reachable (it is then
both the switch and a machine plugged into it).

```
ip link set eth0 up ; ip link set eth1 up        # the ports must be up
ip link add br0 type bridge                      # creates the bridge (STP off by default)
ip link set eth0 master br0                      # eth0 becomes a port of br0
ip link set eth1 master br0
ip link set br0 up                               # brings the bridge up: it switches
bridge link                                      # the ports of each bridge and their state
bridge fdb show br br0                           # the MAC table of br0 (fdb: forwarding database)
ip -d link show br0                              # the parameters of the bridge (-d: details)
ip link set eth1 nomaster                        # removes a port
ip link del br0                                  # deletes the bridge
```

(`brctl addbr br0`, `brctl addif br0 eth0`, `brctl show`, `brctl showmacs br0` of the legacy
`bridge-utils` package do the same.)

The MAC address of the bridge is, unless it is set by hand, **the lowest of the MAC addresses
of its ports** (`ip link show br0`). In `bridge fdb show br br0`, the `permanent` lines are the
addresses of the ports themselves; the others are the learned addresses, with the port (`dev`)
where the machine was seen; `bridge -s fdb show br br0` adds the time elapsed since the last
frame. The lifetime of the entries is set in **hundredths of a second**: `ip link set br0 type
bridge ageing_time 3000` (30 s; `ip -d link show br0` shows `ageing_time 3000`). To give the
machine an IP address in the bridged network, the address goes on `br0` (`ip address add
192.168.1.110/24 dev br0`), never on a port.
""",
    "Observer un pont": "Observing a bridge",
    """

`tcpdump -e -n -i eth0 icmp` (`-e` affiche l'en-tête Ethernet, `-n` évite les résolutions de
noms) sur un port du pont montre les trames **telles qu'elles sont commutées** : les adresses
MAC source et destination sont celles des machines qui dialoguent, le pont n'y apparaît pas. Sur
`br0`, `tcpdump -i br0` voit les trames qui remontent à la machine elle-même (celles qui lui sont
adressées ou diffusées) ; `-p` désactive le mode *promiscuous*. `ip neigh` affiche la table ARP
d'une machine (adresse IP → adresse MAC apprise), `ip neigh flush all` la vide.

Un switch ne livre une trame unicast qu'à son destinataire : une capture sur une troisième
machine du même switch ne voit que les diffusions (ARP) et les trames dont le destinataire n'est
pas encore dans la table du switch. Avec un hub, elle verrait tout.

`ping` affiche pour chaque réponse le temps aller-retour (`time=0.345 ms`) et, à la fin, les
temps minimum / moyen / maximum (`rtt min/avg/max/mdev`) : `ping -c 10` donne une moyenne sur
dix essais.

Pour observer autre chose que des `ping`, chaque machine du TP sauf les ponts (`m1`, `m2`, `m3`,
`m4`, `gw`, `ext1`) sert un petit **serveur de test**, en HTTP sur les ports TCP **80 et 8080**
et en UDP sur les ports **530 et 630** (`ss -tulnp` les liste). Il répond par son nom et par les
adresses et ports des deux bouts de l'échange, tels qu'il les voit :

```
m1:~# curl http://m2/                   # ou curl http://m2:8080/
SERVER=m2
SERVER_IP=192.168.1.2
SERVER_PORT=80
CLIENT_IP=192.168.1.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # un datagramme UDP vers le port 530 (ou 630) : même réponse
```

`TTL=` est celui du paquet reçu : 64 depuis le même réseau, 63 après un routeur, un pont ne le
change pas. Ces échanges se capturent sur un port du pont (`tcpdump -e -n -i eth0 tcp port 80`,
`tcpdump -e -n -i eth0 udp port 530`) et permettent d'essayer les critères de port du filtrage
de niveau 2 (`tcp dport 8080`, `udp dport 530`, section suivante).
""": """

`tcpdump -e -n -i eth0 icmp` (`-e` shows the Ethernet header, `-n` avoids name resolution) on
a port of the bridge shows the frames **as they are switched**: the source and destination MAC
addresses are those of the machines talking to each other, the bridge does not appear in them.
On `br0`, `tcpdump -i br0` sees the frames that go up to the machine itself (those addressed to
it or broadcast); `-p` turns *promiscuous* mode off. `ip neigh` shows the ARP table of a
machine (IP address → learned MAC address), `ip neigh flush all` empties it.

A switch delivers a unicast frame only to its recipient: a capture on a third machine of the
same switch sees only the broadcasts (ARP) and the frames whose recipient is not in the table
of the switch yet. With a hub, it would see everything.

For each reply, `ping` shows the round-trip time (`time=0.345 ms`) and, at the end, the
minimum / average / maximum times (`rtt min/avg/max/mdev`): `ping -c 10` gives an average over
ten attempts.

To observe something other than `ping`, every machine of the lab except the bridges (`m1`,
`m2`, `m3`, `m4`, `gw`, `ext1`) runs a small **test server**, in HTTP on TCP ports **80 and
8080** and in UDP on ports **530 and 630** (`ss -tulnp` lists them). It answers with its name
and with the addresses and ports of both ends of the exchange, as it sees them:

```
m1:~# curl http://m2/                   # or curl http://m2:8080/
SERVER=m2
SERVER_IP=192.168.1.2
SERVER_PORT=80
CLIENT_IP=192.168.1.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # a UDP datagram to port 530 (or 630): same reply
```

`TTL=` is that of the packet received: 64 from the same network, 63 after a router; a bridge
does not change it. These exchanges can be captured on a port of the bridge (`tcpdump -e -n -i
eth0 tcp port 80`, `tcpdump -e -n -i eth0 udp port 530`) and let you try the port criteria of
layer-2 filtering (`tcp dport 8080`, `udp dport 530`, next section).
""",
    "Filtrer au niveau 2 : nftables, famille `bridge`": "Filtering at layer 2: nftables, `bridge` family",
    """

Les règles de la famille **`bridge`** de nftables s'appliquent aux trames qui traversent un pont
Linux, avant tout routage. Ses hooks : `prerouting` (à l'entrée d'un port), `input` (vers la
machine elle-même), **`forward`** (commutée d'un port vers un autre), `output`, `postrouting`.
Les critères disponibles sont ceux de la trame et de ce qu'elle contient : `ether saddr`,
`ether daddr` (adresses MAC), `ether type` (`ip`, `arp`, `vlan`), `ip saddr`, `ip daddr`,
`ip protocol`, `tcp dport`, `udp dport`, `arp operation`, `iifname` / `oifname` (ports d'entrée
et de sortie). Les verdicts : `accept`, `drop`. Les critères IP se combinent avec les critères
MAC : `ip saddr X` suffit, nftables ajoute lui-même le test « c'est de l'IPv4 ».

```
nft add table bridge filter
nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'
nft add rule bridge filter forward ether saddr 02:53:52:00:00:02 ether daddr 02:53:52:00:00:fe drop
nft add rule bridge filter forward ip saddr 192.168.1.2 ip daddr != 192.168.1.0/24 drop
nft list ruleset                             # vérifier (famille bridge)
nft flush table bridge filter                # vider ; nft delete table bridge filter supprime
```

Une trame bloquée dans `forward` n'est pas commutée : la machine émettrice n'obtient aucune
réponse. Bloquer un seul sens suffit à interdire une communication (ici les requêtes de `m2`,
donc aucune réponse). Les adresses MAC des machines se lisent dans `ip link` sur la machine, dans
`ip neigh` sur ses voisines ou dans `bridge fdb show` sur le pont. Historiquement ce filtrage
était celui d'`ebtables` (chaîne `FORWARD`, syntaxe d'iptables) ; l'`ebtables` de Debian 13 est
une réimplémentation sur nftables, dont les règles apparaissent dans `nft list ruleset`.
""": """

The rules of the **`bridge`** family of nftables apply to the frames that cross a Linux bridge,
before any routing. Its hooks: `prerouting` (on entering a port), `input` (to the machine
itself), **`forward`** (switched from one port to another), `output`, `postrouting`. The
available criteria are those of the frame and of what it contains: `ether saddr`,
`ether daddr` (MAC addresses), `ether type` (`ip`, `arp`, `vlan`), `ip saddr`, `ip daddr`,
`ip protocol`, `tcp dport`, `udp dport`, `arp operation`, `iifname` / `oifname` (input and
output ports). The verdicts: `accept`, `drop`. IP criteria combine with MAC criteria:
`ip saddr X` is enough, nftables adds the "this is IPv4" test by itself.

```
nft add table bridge filter
nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'
nft add rule bridge filter forward ether saddr 02:53:52:00:00:02 ether daddr 02:53:52:00:00:fe drop
nft add rule bridge filter forward ip saddr 192.168.1.2 ip daddr != 192.168.1.0/24 drop
nft list ruleset                             # check (bridge family)
nft flush table bridge filter                # empty it; nft delete table bridge filter deletes it
```

A frame blocked in `forward` is not switched: the sending machine gets no reply. Blocking a
single direction is enough to forbid a communication (here the requests of `m2`, hence no
reply). The MAC addresses of the machines can be read in `ip link` on the machine, in
`ip neigh` on its neighbours or in `bridge fdb show` on the bridge. Historically this filtering
was done by `ebtables` (`FORWARD` chain, iptables syntax); the `ebtables` of Debian 13 is a
reimplementation on top of nftables, whose rules appear in `nft list ruleset`.
""",
    "Boucles, redondance et STP": "Loops, redundancy and STP",
    """

Deux ponts entre les mêmes segments forment une **boucle**. Sans précaution, une seule trame de
diffusion tourne indéfiniment, dupliquée à chaque tour (**tempête de diffusion**, *broadcast
storm*) et les tables MAC deviennent instables (la même adresse est vue tour à tour sur les deux
ports) : le réseau s'effondre en quelques secondes. La redondance est pourtant souhaitable (un
pont peut tomber en panne).

Le **STP** (*Spanning Tree Protocol*, IEEE 802.1D) résout le problème : les ponts échangent des
**BPDU** (*Bridge Protocol Data Units*, trames multicast vers `01:80:c2:00:00:00`, une toutes
les deux secondes, *hello time*) et élisent une **racine** : le pont dont l'**identifiant** est
le plus petit, l'identifiant étant la **priorité** (16 bits, 32768 par défaut, écrite en
hexadécimal : `8000.`) suivie de l'adresse MAC du pont. Chaque autre pont garde un seul chemin
vers la racine : son **port racine** (le plus proche de la racine, au coût le plus faible), et
sur chaque segment un seul pont est **désigné** pour y transmettre les trames. Tout port qui
n'est ni racine ni désigné est **bloqué** (*blocking*) : il ne transmet rien, mais écoute les
BPDU, pour se réactiver si un chemin disparaît. L'arbre couvrant ainsi obtenu n'a plus de boucle.

Un port passe par les états *blocking* → *listening* (15 s) → *learning* (15 s) → *forwarding*
(*forward delay*, 15 s par étape) : un pont STP met donc **environ 30 s** à commuter après son
activation, et une reconfiguration prend 30 à 50 s (*max age* 20 s : délai sans BPDU avant de
considérer un chemin perdu). Le **RSTP** (802.1w) converge en quelques secondes et le MSTP
(802.1s) gère un arbre par groupe de VLAN ; le noyau Linux ne fait que le STP classique (`mstpd`
pour les autres).

Sous Linux :

```
ip link set br0 type bridge stp_state 1          # active STP (0 : désactive)
ip link set br0 type bridge priority 4096        # priorité (0 à 65535 ; plus petite = racine)
bridge link                                      # état de chaque port : forwarding, blocking...
ip -d link show br0                              # bridge_id, root_id (l'identifiant de la racine),
                                                 # root_port, hello_time, max_age, forward_delay (centièmes de seconde)
tcpdump -n -v -i eth0 stp                        # les BPDU (-v : les temporisateurs et root-id)
```

Un pont dont STP est désactivé laisse passer les BPDU des autres (il est pour eux un simple
câble) : si un seul pont de la boucle fait du STP, il reçoit ses propres BPDU et bloque lui-même
l'un de ses ports.

Deux ponts de même priorité : le plus petit identifiant est celui dont l'**adresse MAC** est la
plus petite, ce qui fait une racine choisie par le hasard des adresses ; en pratique on fixe la
racine en lui donnant une priorité plus petite (et une priorité de secours au pont suivant).
Dans un pont qui n'est pas la racine, le port racine est celui par lequel les BPDU de la racine
arrivent au meilleur coût ; à coût égal, celui qui reçoit les BPDU du port de la racine au plus
petit **identifiant de port** (le premier port ajouté au pont racine est le port 1).

Après un changement de topologie, les ponts STP vident leur table MAC (c'est le rôle du
drapeau *topology change* des BPDU) ; un switch qui ne fait pas de STP, lui, garde ses entrées
jusqu'à leur expiration : une adresse apprise derrière un port depuis bloqué reste injoignable
jusqu'à ce qu'une trame de diffusion (ARP) venant d'elle lui fasse réapprendre le bon port.
""": """

Two bridges between the same segments form a **loop**. Without precautions, a single broadcast
frame circulates forever, duplicated on every turn (**broadcast storm**), and the MAC tables
become unstable (the same address is seen alternately on both ports): the network collapses
within seconds. Redundancy is nevertheless desirable (a bridge can fail).

**STP** (*Spanning Tree Protocol*, IEEE 802.1D) solves the problem: the bridges exchange
**BPDUs** (*Bridge Protocol Data Units*, multicast frames to `01:80:c2:00:00:00`, one every two
seconds, the *hello time*) and elect a **root**: the bridge whose **identifier** is the lowest,
the identifier being the **priority** (16 bits, 32768 by default, written in hexadecimal:
`8000.`) followed by the MAC address of the bridge. Every other bridge keeps a single path to
the root: its **root port** (the closest to the root, at the lowest cost), and on each segment
a single bridge is **designated** to forward the frames onto it. Any port that is neither root
nor designated is **blocked** (*blocking*): it forwards nothing, but listens to the BPDUs, so as
to come back into service if a path disappears. The spanning tree thus obtained has no loop
left.

A port goes through the states *blocking* → *listening* (15 s) → *learning* (15 s) →
*forwarding* (*forward delay*, 15 s per stage): an STP bridge therefore takes **about 30 s** to
switch after it is brought up, and a reconfiguration takes 30 to 50 s (*max age* 20 s: the time
without BPDUs before a path is considered lost). **RSTP** (802.1w) converges in a few seconds
and MSTP (802.1s) handles one tree per group of VLANs; the Linux kernel only does classic STP
(`mstpd` for the others).

On Linux:

```
ip link set br0 type bridge stp_state 1          # turns STP on (0: off)
ip link set br0 type bridge priority 4096        # priority (0 to 65535; lower = root)
bridge link                                      # state of each port: forwarding, blocking...
ip -d link show br0                              # bridge_id, root_id (the identifier of the root),
                                                 # root_port, hello_time, max_age, forward_delay (hundredths of a second)
tcpdump -n -v -i eth0 stp                        # the BPDUs (-v: the timers and root-id)
```

A bridge with STP off lets the BPDUs of the others through (for them it is a mere cable): if a
single bridge of the loop runs STP, it receives its own BPDUs and blocks one of its ports
itself.

Two bridges with the same priority: the lowest identifier is the one whose **MAC address** is
the lowest, which leaves the choice of the root to the chance of the addresses; in practice the
root is fixed by giving it a lower priority (and a backup priority to the next bridge). In a
bridge that is not the root, the root port is the one through which the BPDUs of the root
arrive at the best cost; at equal cost, the one that receives the BPDUs from the port of the
root with the lowest **port identifier** (the first port added to the root bridge is port 1).

After a topology change, STP bridges flush their MAC table (that is the role of the *topology
change* flag of the BPDUs); a switch that does not run STP, on the other hand, keeps its
entries until they expire: an address learned behind a port that has since been blocked stays
unreachable until a broadcast frame (ARP) coming from it makes the switch learn the right port
again.
""",
    "Aide-mémoire": "Cheat sheet",
    """

| besoin | commande |
|--------|----------|
| interfaces, adresses MAC, adresses IP | `ip link`, `ip -br link`, `ip -br address`, `ip -d link show br0` |
| pont | `ip link add br0 type bridge`, `ip link set ethX master br0`, `ip link set br0 up`, `bridge link` |
| table MAC du pont | `bridge fdb show br br0`, `bridge -s fdb show br br0`, `ip link set br0 type bridge ageing_time 3000` |
| table ARP | `ip neigh`, `ip neigh flush all` |
| capture | `tcpdump -e -n -i eth0 icmp`, `tcpdump -n -v -i eth0 stp`, `tshark -i eth0`, `wireshark` |
| latence | `ping -c 10 192.168.1.1` (ligne `rtt min/avg/max`) |
| serveurs de test (TCP 80 et 8080, UDP 530 et 630) | `curl http://m2/`, `curl http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ss -tulnp` |
| filtrage niveau 2 | `nft add table bridge filter`, `nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'`, `nft add rule bridge filter forward ... drop`, `nft list ruleset` |
| adresse sur le pont | `ip address add A.B.C.D/24 dev br0`, `ip route add default via ...` |
| STP | `ip link set br0 type bridge stp_state 1`, `ip link set br0 type bridge priority N`, `bridge link`, `ip -d link show br0` |
""": """

| need | command |
|--------|----------|
| interfaces, MAC addresses, IP addresses | `ip link`, `ip -br link`, `ip -br address`, `ip -d link show br0` |
| bridge | `ip link add br0 type bridge`, `ip link set ethX master br0`, `ip link set br0 up`, `bridge link` |
| MAC table of the bridge | `bridge fdb show br br0`, `bridge -s fdb show br br0`, `ip link set br0 type bridge ageing_time 3000` |
| ARP table | `ip neigh`, `ip neigh flush all` |
| capture | `tcpdump -e -n -i eth0 icmp`, `tcpdump -n -v -i eth0 stp`, `tshark -i eth0`, `wireshark` |
| latency | `ping -c 10 192.168.1.1` (line `rtt min/avg/max`) |
| test servers (TCP 80 and 8080, UDP 530 and 630) | `curl http://m2/`, `curl http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ss -tulnp` |
| layer-2 filtering | `nft add table bridge filter`, `nft 'add chain bridge filter forward { type filter hook forward priority 0; policy accept; }'`, `nft add rule bridge filter forward ... drop`, `nft list ruleset` |
| address on the bridge | `ip address add A.B.C.D/24 dev br0`, `ip route add default via ...` |
| STP | `ip link set br0 type bridge stp_state 1`, `ip link set br0 type bridge priority N`, `bridge link`, `ip -d link show br0` |
""",
    """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` : les switchs `s1`, `s2` et `s3` | `{lan}` | `m1` (`{m1}`, sur `s1`), `m2` (`{m2}`, sur `s2`), `m3` (`{m3}`, sur `s2`), `m4` (`{m4}`, sur `s3`, partie 6), `gw` eth0 (`{gw_lan}`, sur `s1`, passerelle) ; à venir : `b1` (`{b1}`, sur `br0`) ; `b2` et `b3` sans adresse |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `gw` eth1 (`{gw_ext}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan`: the switches `s1`, `s2` and `s3` | `{lan}` | `m1` (`{m1}`, on `s1`), `m2` (`{m2}`, on `s2`), `m3` (`{m3}`, on `s2`), `m4` (`{m4}`, on `s3`, part 6), `gw` eth0 (`{gw_lan}`, on `s1`, gateway); to come: `b1` (`{b1}`, on `br0`); `b2` and `b3` without an address |
| `ext` ("the outside") | `{ext}` | `ext1` (`{ext1}`), `gw` eth1 (`{gw_ext}`) |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente les ponts Ethernet, leur réalisation sous Linux,
la façon de les observer, le filtrage de niveau 2 avec nftables et le protocole STP.

**La maquette** (onglet *Schéma*) est un seul réseau IP, `lan`, réparti sur trois switchs.

- Parties 1 à 5 : les switchs `s1` (avec `m1` et la passerelle `gw`) et `s2` (avec `m2` et
  `m3`) ne sont reliés que par la machine `b1` (`eth0` sur `s1`, `eth1` sur `s2`), dont les
  interfaces ne sont **pas configurées** : vous en ferez un pont. La passerelle `gw` route vers
  le réseau `ext`, « l'extérieur », où se trouve `ext1`.
- Partie 6 : un troisième switch `s3` (avec `m4`) est relié à `s1` par **deux** machines `b2`
  et `b3` (`eth0` sur `s3`, `eth1` sur `s1`), elles aussi non configurées : vous en ferez deux
  ponts en parallèle, une boucle que STP devra défaire. Jusque-là, `m4` est isolée.
""": """
Read the **Informations** tab: it presents Ethernet bridges, how they are implemented on Linux,
how to observe them, layer-2 filtering with nftables and the STP protocol.

**The setup** (*Schema* tab) is a single IP network, `lan`, spread over three switches.

- Parts 1 to 5: the switches `s1` (with `m1` and the gateway `gw`) and `s2` (with `m2` and
  `m3`) are joined only by the machine `b1` (`eth0` on `s1`, `eth1` on `s2`), whose
  interfaces are **not configured**: you will turn it into a bridge. The gateway `gw` routes to
  the network `ext`, "the outside", where `ext1` is.
- Part 6: a third switch `s3` (with `m4`) is joined to `s1` by **two** machines `b2` and `b3`
  (`eth0` on `s3`, `eth1` on `s1`), not configured either: you will turn them into two bridges
  in parallel, a loop that STP will have to break. Until then, `m4` is isolated.
""",
    """
Déjà en place (ne pas modifier) : les adresses ci-dessus (sauf celle de `b1`, partie 5), la
route par défaut de `m1`, `m2`, `m3`, `m4` et `ext1` vers `gw`, le routage sur `gw`, les noms dans
`/etc/hosts` (`m1`, `m2`, `m3`, `m4`, `b1`, `gw`, `gw_ext`, `ext1`). Il n'y a pas de DNS. Sur
chaque machine sauf les ponts tourne un **serveur de test** HTTP (ports TCP 80 et 8080) et UDP
(ports 530 et 630) qui répond par son nom et par les adresses et ports du serveur et du client
(`curl http://m2/`, `echo bonjour | nc -u -w 1 m2 530` ; section @@ref:observing@@ des
Informations) : de quoi observer et filtrer autre chose que des `ping`.
Les adresses **MAC** ne sont pas données : lisez-les sur les machines (`ip link`, `ip neigh`,
`bridge fdb show`). Par sécurité, les interfaces de `b2` et `b3` sont bridées à {cap} (`tc qdisc
show`) : une tempête de diffusion dans la boucle de la partie 6 inonderait tout le réseau (`s1`,
puis `s2` à travers `b1`) et perturberait les autres parties tant qu'elle dure, mais sans saturer
votre machine.

**Plan du TP.**

1. **Sans pont** : m1 et m2 ne se joignent pas ;
2. **Le pont `br0`** sur b1 : m2 joint m1 et l'extérieur ; transparence (captures, ARP, adresse
   MAC du pont) ; latence avec ou sans pont ;
3. **Table MAC** du pont et durée de vie des entrées ;
4. **Filtrage** : m2 ne doit plus joindre l'extérieur (famille `bridge` de nftables) ;
5. **Adresse IP** sur le pont : b1 joignable et joint l'extérieur ;
6. **Redondance et STP** : un troisième switch `s3` (avec `m4`) relié à `s1` par deux ponts
   `b2` et `b3` en parallèle ; élection de la racine, port bloqué, BPDU, puis changement de
   racine par la priorité.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place (l'évaluation vérifie l'état final de tout) ;
- toute la configuration de ce TP est volatile (`ip`, `nft`) : elle ne survit pas au redémarrage
  d'une machine ;
- le nom des ponts est imposé : **`{bridge}`** sur `b1`, `b2` et `b3` ;
- avec STP actif, un pont met **30 secondes** à commuter : patientez avant de conclure ;
- l'évaluation observe la maquette telle qu'elle tourne (`ip -d link`, `bridge fdb`, `nft list
  ruleset` sur `b1`, l'état STP de `b2` et `b3`, puis des `ping` **depuis vos machines**).
""": """
Already in place (do not modify): the addresses above (except that of `b1`, part 5), the
default route of `m1`, `m2`, `m3`, `m4` and `ext1` via `gw`, routing on `gw`, the names in
`/etc/hosts` (`m1`, `m2`, `m3`, `m4`, `b1`, `gw`, `gw_ext`, `ext1`). There is no DNS. Every
machine except the bridges runs a **test server** in HTTP (TCP ports 80 and 8080) and in UDP
(ports 530 and 630) that answers with its name and with the addresses and ports of the server
and of the client (`curl http://m2/`, `echo bonjour | nc -u -w 1 m2 530`; section
@@ref:observing@@ of the Informations tab): enough to observe and filter something other than
`ping`.
The **MAC** addresses are not given: read them on the machines (`ip link`, `ip neigh`,
`bridge fdb show`). For safety, the interfaces of `b2` and `b3` are capped at {cap} (`tc qdisc
show`): a broadcast storm in the loop of part 6 would flood the whole network (`s1`, then `s2`
through `b1`) and disrupt the other parts while it lasts, but without saturating your machine.

**Outline of the lab.**

1. **Without a bridge**: m1 and m2 cannot reach each other;
2. **The bridge `br0`** on b1: m2 reaches m1 and the outside; transparency (captures, ARP, MAC
   address of the bridge); latency with and without a bridge;
3. **MAC table** of the bridge and lifetime of its entries;
4. **Filtering**: m2 must no longer reach the outside (`bridge` family of nftables);
5. **IP address** on the bridge: b1 is reachable and reaches the outside;
6. **Redundancy and STP**: a third switch `s3` (with `m4`) joined to `s1` by two bridges
   `b2` and `b3` in parallel; election of the root, blocked port, BPDUs, then change of root
   through the priority.

Rules for the whole lab:

- the questions are to be done **in order** and the configuration of a finished question stays
  in place (the evaluation checks the final state of everything);
- all the configuration of this lab is volatile (`ip`, `nft`): it does not survive a restart of
  a machine;
- the name of the bridges is imposed: **`{bridge}`** on `b1`, `b2` and `b3`;
- with STP on, a bridge takes **30 seconds** to switch: wait before drawing conclusions;
- the evaluation observes the setup as it runs (`ip -d link`, `bridge fdb`, `nft list
  ruleset` on `b1`, the STP state of `b2` and `b3`, then `ping`s **from your machines**).
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit
les formulaires : `br0` sur `b1` (ports `eth0` et `eth1`, sans STP), `ageing_time` de 30 s, la table
`bridge filter` et sa règle `drop`, l'adresse `{b1}` sur `br0` avec la route par défaut, puis `br0`
avec STP sur `b2` et `b3` et la priorité {root_priority} sur `{final_root}`. Il est ré-applicable, et il
faut attendre **30 s** après lui (états *listening* puis *learning* des ports STP) avant une évaluation
complète.

Adresses MAC de cette instance : m1 `{mac_m1}`, m2 `{mac_m2}`, m3 `{mac_m3}`, m4 `{mac_m4}`, gw `{mac_gw}`,
b1 eth0 `{mac_b1_eth0}` / eth1 `{mac_b1_eth1}` (donc `br0` = `{mac_br0}` ; `b1` reçoit les deux plus grandes
adresses de l'instance : même avec STP activé par un étudiant, elle ne peut pas être élue racine) ;
b2 eth0 `{mac_b2_eth0}` / eth1 `{mac_b2_eth1}` (`br0` = `{mac_br2}`), b3 eth0 `{mac_b3_eth0}` / eth1
`{mac_b3_eth1}` (`br0` = `{mac_br3}`) : à priorité égale, **`{first_root}`** est élue racine (plus petite
adresse MAC), puis `{final_root}` le devient avec la priorité {root_priority}.

L'évaluation lit `ip -j -d link` sur `b1`, `b2` et `b3` (ponts, ports, états STP, `root_id` /
`bridge_id`, `ageing_time`), `bridge -j fdb show br br0` sur `b1` après les pings, `nft list ruleset`
sur `b1` (famille `bridge` : une règle `drop` concernant `m2`), `ip -j -4 addr` et `ip route` sur `b1`,
puis douze `ping` depuis `m1` à `m4`, `gw` et `b1` (celui de `m2` vers `ext1` doit échouer : 4 s ; ceux
de la partie 6 sont précédés de `ip neigh flush all`). Une évaluation dure une dizaine de secondes. Les
ports de `b2` et `b3` sont bridés par `tc` (tbf {cap}) : deux ponts sans STP font une tempête de
diffusion visible sur tout le réseau mais inoffensive. Les serveurs de test (HTTP 80 / 8080 et UDP
530 / 630 sur toutes les machines sauf les ponts, journal `/var/log/sre_server_echo.log`) ne sont pas
évalués.
""": """
**For the instructor.** Every question ends with its solution, computed for the addresses of
this project. The `final` state (*Apply Configuration* tab) applies the whole solution and fills
in the forms: `br0` on `b1` (ports `eth0` and `eth1`, without STP), an `ageing_time` of 30 s,
the table `bridge filter` and its `drop` rule, the address `{b1}` on `br0` with the default
route, then `br0` with STP on `b2` and `b3` and the priority {root_priority} on `{final_root}`.
It can be applied again, and you must wait **30 s** after it (*listening* then *learning* states
of the STP ports) before a complete evaluation.

MAC addresses of this instance: m1 `{mac_m1}`, m2 `{mac_m2}`, m3 `{mac_m3}`, m4 `{mac_m4}`, gw `{mac_gw}`,
b1 eth0 `{mac_b1_eth0}` / eth1 `{mac_b1_eth1}` (hence `br0` = `{mac_br0}`; `b1` gets the two highest
addresses of the instance: even with STP turned on by a student, it cannot be elected root);
b2 eth0 `{mac_b2_eth0}` / eth1 `{mac_b2_eth1}` (`br0` = `{mac_br2}`), b3 eth0 `{mac_b3_eth0}` / eth1
`{mac_b3_eth1}` (`br0` = `{mac_br3}`): with equal priorities, **`{first_root}`** is elected root (lowest
MAC address), then `{final_root}` becomes the root with the priority {root_priority}.

The evaluation reads `ip -j -d link` on `b1`, `b2` and `b3` (bridges, ports, STP states, `root_id` /
`bridge_id`, `ageing_time`), `bridge -j fdb show br br0` on `b1` after the pings, `nft list ruleset`
on `b1` (`bridge` family: a `drop` rule concerning `m2`), `ip -j -4 addr` and `ip route` on `b1`,
then twelve `ping`s from the machines `m1` to `m4`, `gw` and `b1` (the one from `m2` to `ext1` must
fail: 4 s; those of part 6 are preceded by `ip neigh flush all`). An evaluation takes about ten
seconds. The ports of `b2` and `b3` are capped by `tc` (tbf {cap}): two bridges without STP make a
broadcast storm visible on the whole network but harmless. The test servers (HTTP 80 / 8080 and
UDP 530 / 630 on every machine except the bridges, log `/var/log/sre_server_echo.log`) are not
graded.
""",
    "Partie 1 — Sans pont (question 1)": "Part 1 — Without a bridge (question 1)",
    "Deux switchs sans pont": "Two switches without a bridge",
    """
Les interfaces de la machine `b1` ne sont pas configurées (`ip link` sur `b1` : `eth0` et `eth1`
sont `DOWN`). Vérifiez que `m1` (`{m1}`) et `m2` (`{m2}`) ne peuvent pas communiquer (`ping`),
alors que `m2` et `m3` (`{m3}`) le peuvent, et que `m1` joint `ext1` (`{ext1}`) par `gw`. Pendant
le `ping {m1}` de `m2`, capturez sur `m2` avec `tcpdump -e -n -i eth0` : que fait `m2` ?
""": """
The interfaces of the machine `b1` are not configured (`ip link` on `b1`: `eth0` and `eth1`
are `DOWN`). Check that `m1` (`{m1}`) and `m2` (`{m2}`) cannot communicate (`ping`), whereas
`m2` and `m3` (`{m3}`) can, and that `m1` reaches `ext1` (`{ext1}`) through `gw`. During the
`ping {m1}` of `m2`, capture on `m2` with `tcpdump -e -n -i eth0`: what does `m2` do?
""",
    """
- pourquoi m1 et m2 ne se joignent-elles pas, bien qu'elles aient des adresses du même réseau ? @@{why:>s1 et s2 ne sont reliés par rien : deux domaines de diffusion séparés, la requête ARP de m2 (diffusion) n'arrive jamais à m1>>>two_domains|il manque une route sur m2 vers le réseau de m1>>>route|gw bloque le trafic entre s1 et s2>>>gw_blocks|m1 et m2 sont dans deux réseaux IP différents>>>different_networks}@@
- et m2 et m3 ? @@{m2_m3:>elles se joignent : même switch s2, donc même domaine de diffusion>>>same_switch|elles ne se joignent pas non plus>>>no|elles se joignent grâce à gw>>>via_gw}@@
""": """
- why do m1 and m2 not reach each other, although they have addresses of the same network? @@{why:>s1 and s2 are joined by nothing: two separate broadcast domains, the ARP request of m2 (a broadcast) never reaches m1>>>two_domains|a route to the network of m1 is missing on m2>>>route|gw blocks the traffic between s1 and s2>>>gw_blocks|m1 and m2 are in two different IP networks>>>different_networks}@@
- and m2 and m3? @@{m2_m3:>they reach each other: same switch s2, hence same broadcast domain>>>same_switch|they do not reach each other either>>>no|they reach each other thanks to gw>>>via_gw}@@
""",
    """
**Solution.** Rien à configurer. `m2` émet des requêtes ARP `who-has {m1} tell {m2}` en diffusion
(`ff:ff:ff:ff:ff:ff`) qui ne quittent pas `s2` : `ping` affiche `Destination Host Unreachable`.
`m2` et `m3` sont sur le même switch, `m1` joint `ext1` par `gw` (sur `s1`).

- Réponses : deux domaines de diffusion séparés ; m2 et m3 se joignent (même switch).
- Cette question n'est évaluée que par le formulaire (l'état final de la maquette a un pont).
""": """
**Solution.** Nothing to configure. `m2` sends ARP requests `who-has {m1} tell {m2}` as broadcasts
(`ff:ff:ff:ff:ff:ff`) that do not leave `s2`: `ping` shows `Destination Host Unreachable`.
`m2` and `m3` are on the same switch, `m1` reaches `ext1` through `gw` (on `s1`).

- Answers: two separate broadcast domains; m2 and m3 reach each other (same switch).
- This question is graded by the form only (the final state of the setup has a bridge).
""",
    "sans pont : deux domaines de diffusion séparés ; m2 et m3 sur le même switch": "without a bridge: two separate broadcast domains; m2 and m3 on the same switch",
    "Partie 2 — Le pont br0 (questions 2 à 4)": "Part 2 — The bridge br0 (questions 2 to 4)",
    "Le pont br0 sur b1": "The bridge br0 on b1",
    """
Sur `b1`, activez les deux interfaces puis créez un pont nommé **`{bridge}`** entre `eth0` et
`eth1` (section @@ref:linux-bridges@@ des Informations), **sans STP** (c'est le réglage par défaut ; avec STP le
pont mettrait 30 s à commuter), et activez-le. Vérifiez qu'à présent `m2` (`{m2}`) joint `m1`
(`{m1}`) et l'extérieur (`ext1`, `{ext1}`), et que `m1` joint `m2`. Regardez `bridge link` et
`ip -d link show {bridge}` sur `b1`.
""": """
On `b1`, bring the two interfaces up, then create a bridge named **`{bridge}`** between `eth0` and
`eth1` (section @@ref:linux-bridges@@ of the Informations tab), **without STP** (the default setting; with STP the
bridge would take 30 s to switch), and bring it up. Check that `m2` (`{m2}`) now reaches `m1`
(`{m1}`) and the outside (`ext1`, `{ext1}`), and that `m1` reaches `m2`. Look at `bridge link` and
`ip -d link show {bridge}` on `b1`.
""",
    """
**Solution.** Sur `b1` :

```
{cmds}```

(`brctl addbr br0 ; brctl stp br0 off ; brctl addif br0 eth0 ; brctl addif br0 eth1 ; ip link set br0
up` dans le sujet d'origine.) `b1` ne fait que commuter : aucune adresse IP n'est nécessaire. `ip -d
link show br0` montre `stp_state 0`, `bridge_id 8000.{mac_br0}` (priorité 32768, l'adresse MAC du
pont). L'évaluation vérifie `br0` (type `bridge`, ports `eth0` et `eth1` : `master br0`), les trois
interfaces `up`, et des `ping` de `m2` vers `m1`, de `m1` vers `m2` et de `m3` vers `ext1` (le `ping` de `m2`
vers `ext1` est celui de la partie 4, où il doit échouer).
""": """
**Solution.** On `b1`:

```
{cmds}```

(`brctl addbr br0 ; brctl stp br0 off ; brctl addif br0 eth0 ; brctl addif br0 eth1 ; ip link set br0
up` in the original handout.) `b1` only switches: no IP address is needed. `ip -d
link show br0` shows `stp_state 0`, `bridge_id 8000.{mac_br0}` (priority 32768, the MAC address of the
bridge). The evaluation checks `br0` (type `bridge`, ports `eth0` and `eth1`: `master br0`), the three
interfaces `up`, and `ping`s from `m2` to `m1`, from `m1` to `m2` and from `m3` to `ext1` (the `ping` from `m2`
to `ext1` is the one of part 4, where it must fail).
""",
    "Transparence du pont": "Transparency of the bridge",
    """
Depuis `m2`, lancez `ping {m1}` et observez :

- sur `b1`, `tcpdump -e -n -i eth0 icmp` puis `tcpdump -e -n -i eth1 icmp` (les trames telles
  qu'elles entrent et sortent du pont) ;
- sur `m1`, `ip neigh` (sa table ARP) après le ping ;
- sur `m3`, `tcpdump -e -n -i eth0` pendant le ping de `m2` vers `m1` (videz d'abord la table
  ARP de `m2` avec `ip neigh flush all` pour revoir l'échange ARP) ;
- sur `b1`, `ip link show {bridge}` : l'adresse MAC du pont, à comparer à celles de `eth0` et
  `eth1`.
""": """
From `m2`, run `ping {m1}` and observe:

- on `b1`, `tcpdump -e -n -i eth0 icmp` then `tcpdump -e -n -i eth1 icmp` (the frames as they
  enter and leave the bridge);
- on `m1`, `ip neigh` (its ARP table) after the ping;
- on `m3`, `tcpdump -e -n -i eth0` during the ping from `m2` to `m1` (first empty the ARP table
  of `m2` with `ip neigh flush all` to see the ARP exchange again);
- on `b1`, `ip link show {bridge}`: the MAC address of the bridge, to compare with those of `eth0` and
  `eth1`.
""",
    """
- adresse MAC **source** des trames ICMP vues sur `eth0` de `b1` (du côté de m1) : @@{src_mac:>celle de m2 : le pont ne modifie pas les trames>>>m2|celle de eth1 de b1 : le pont réémet avec sa propre adresse>>>b1_eth1|celle de eth0 de b1>>>b1_eth0|celle de gw>>>gw}@@
- dans la table ARP de `m1`, l'adresse IP de `m2` correspond à : @@{arp:>l'adresse MAC de m2>>>m2_mac|l'adresse MAC du pont br0>>>bridge_mac|l'adresse MAC de gw>>>gw_mac|rien : m1 n'a pas d'entrée pour m2>>>none}@@
- sur `m3`, pendant le ping de m2 vers m1 : @@{m3_sees:>seulement la requête ARP de m2 (diffusion), pas les trames ICMP : le switch s2 ne les lui transmet pas>>>nothing|toutes les trames ICMP du ping : s2 répète tout>>>all|les trames ICMP aller mais pas les réponses>>>requests_only|la requête ARP et la réponse ARP de m1>>>arp_both}@@
- adresse MAC du pont `br0` : @@{br0_mac:[0-9a-fA-F:-]+}@@
- d'où vient-elle ? @@{br0_mac_origin:>c'est la plus petite des adresses MAC de ses ports>>>lowest_port|c'est une adresse aléatoire sans lien avec les ports>>>random|c'est celle de eth0, le premier port ajouté>>>first_port|c'est celle de la machine m1>>>m1}@@
""": """
- **source** MAC address of the ICMP frames seen on `eth0` of `b1` (the m1 side): @@{src_mac:>that of m2: the bridge does not modify the frames>>>m2|that of eth1 of b1: the bridge sends them out again with its own address>>>b1_eth1|that of eth0 of b1>>>b1_eth0|that of gw>>>gw}@@
- in the ARP table of `m1`, the IP address of `m2` maps to: @@{arp:>the MAC address of m2>>>m2_mac|the MAC address of the bridge br0>>>bridge_mac|the MAC address of gw>>>gw_mac|nothing: m1 has no entry for m2>>>none}@@
- on `m3`, during the ping from m2 to m1: @@{m3_sees:>only the ARP request of m2 (a broadcast), not the ICMP frames: the switch s2 does not forward them to it>>>nothing|all the ICMP frames of the ping: s2 repeats everything>>>all|the outgoing ICMP frames but not the replies>>>requests_only|the ARP request and the ARP reply of m1>>>arp_both}@@
- MAC address of the bridge `br0`: @@{br0_mac:[0-9a-fA-F:-]+}@@
- where does it come from? @@{br0_mac_origin:>it is the lowest of the MAC addresses of its ports>>>lowest_port|it is a random address unrelated to the ports>>>random|it is that of eth0, the first port added>>>first_port|it is that of the machine m1>>>m1}@@
""",
    """
**Solution.** Sur `eth0` comme sur `eth1` de `b1`, les trames ICMP vont de `{mac_m2}` (m2) à
`{mac_m1}` (m1) et retour : le pont les commute sans les modifier. `ip neigh` sur `m1` donne
`{m2} dev eth0 lladdr {mac_m2}`. Sur `m3`, seule la requête ARP de `m2` (diffusion) passe ; la
réponse ARP de `m1` est unicast vers `m2` et les trames ICMP aussi : le switch `s2` les livre au seul
port de `m2`. `br0` a pris l'adresse `{mac_br0}`, la plus petite de `{mac_b1_eth0}` (eth0) et
`{mac_b1_eth1}` (eth1).

- Réponses : celle de m2 ; l'adresse MAC de m2 ; seulement l'ARP ; `{mac_br0}` ; la plus petite des
  adresses de ses ports.
""": """
**Solution.** On `eth0` as on `eth1` of `b1`, the ICMP frames go from `{mac_m2}` (m2) to
`{mac_m1}` (m1) and back: the bridge switches them without modifying them. `ip neigh` on `m1` gives
`{m2} dev eth0 lladdr {mac_m2}`. On `m3`, only the ARP request of `m2` (a broadcast) gets through; the
ARP reply of `m1` is unicast to `m2`, and so are the ICMP frames: the switch `s2` delivers them to the
port of `m2` only. `br0` took the address `{mac_br0}`, the lowest of `{mac_b1_eth0}` (eth0) and
`{mac_b1_eth1}` (eth1).

- Answers: that of m2; the MAC address of m2; only the ARP request; `{mac_br0}`; the lowest of the
  addresses of its ports.
""",
    "Latence avec et sans pont": "Latency with and without a bridge",
    """
Déterminez la durée moyenne du `ping` entre `m2` et `m1` (`{m1}`, à travers le pont) puis entre
`m2` et `m3` (`{m3}`, sur le même switch), sur une dizaine d'essais chacun (`ping -c 10`, ligne
`rtt min/avg/max`). Qu'en concluez-vous ?
""": """
Determine the average time of a `ping` between `m2` and `m1` (`{m1}`, through the bridge), then between
`m2` and `m3` (`{m3}`, on the same switch), over about ten attempts each (`ping -c 10`, line
`rtt min/avg/max`). What do you conclude?
""",
    """
- durée moyenne m2 → m1, en ms : @@{rtt_bridged:[0-9.,]+}@@
- durée moyenne m2 → m3, en ms : @@{rtt_direct:[0-9.,]+}@@
- conclusion : @@{conclusion:>le trajet par le pont est plus long : chaque trame est reçue en entier puis réémise par b1 (store and forward), et traverse un second switch>>>bridge_delay|les deux durées sont identiques : un pont est transparent, donc sans effet sur le délai>>>same|le trajet par le pont est plus court : b1 accélère les trames>>>faster|le trajet par le pont est plus long parce que b1 route les paquets>>>routing}@@
""": """
- average time m2 → m1, in ms: @@{rtt_bridged:[0-9.,]+}@@
- average time m2 → m3, in ms: @@{rtt_direct:[0-9.,]+}@@
- conclusion: @@{conclusion:>the path through the bridge is longer: each frame is received entirely then sent out again by b1 (store and forward), and crosses a second switch>>>bridge_delay|both times are the same: a bridge is transparent, hence has no effect on the delay>>>same|the path through the bridge is shorter: b1 speeds the frames up>>>faster|the path through the bridge is longer because b1 routes the packets>>>routing}@@
""",
    """
**Solution.** Les valeurs dépendent de la machine hôte (quelques dixièmes de milliseconde) ; le
trajet `m2` → `m1` traverse `s2`, le pont `b1` (réception complète de la trame, consultation de la
table MAC, réémission) puis `s1` : il est en moyenne plus long que `m2` → `m3` (un seul switch). Le
formulaire est évalué sur la conclusion et sur la présence de deux mesures plausibles (0 à 1000 ms).
""": """
**Solution.** The values depend on the host machine (a few tenths of a millisecond); the
path `m2` → `m1` crosses `s2`, the bridge `b1` (complete reception of the frame, lookup in the
MAC table, retransmission) then `s1`: on average it is longer than `m2` → `m3` (a single switch). The
form is graded on the conclusion and on the presence of two plausible measurements (0 to 1000 ms).
""",
    "{bridge} est un pont dont eth0 et eth1 sont les ports (sur b1)": "{bridge} is a bridge whose ports are eth0 and eth1 (on b1)",
    "{bridge}, eth0 et eth1 sont actives (up) sur b1": "{bridge}, eth0 and eth1 are up on b1",
    "à travers le pont : m2 joint m1, m1 joint m2, m3 joint ext1 (m2 vers ext1 : partie 4)": "through the bridge: m2 reaches m1, m1 reaches m2, m3 reaches ext1 (m2 to ext1: part 4)",
    "transparence : adresse MAC de br0": "transparency: MAC address of br0",
    "transparence : adresses MAC inchangées, table ARP de m1, ce que voit m3, origine de l'adresse MAC de br0": "transparency: MAC addresses unchanged, ARP table of m1, what m3 sees, origin of the MAC address of br0",
    "latence : deux mesures": "latency: two measurements",
    "latence : la conclusion (le pont ajoute un délai)": "latency: the conclusion (the bridge adds a delay)",
    "Partie 3 — Table MAC du pont (question 5)": "Part 3 — MAC table of the bridge (question 5)",
    "Table MAC et durée de vie des entrées": "MAC table and lifetime of the entries",
    """
Après des `ping` de `m2` vers `m1` et de `m3` vers `m1`, affichez la table MAC du pont sur `b1`
(`bridge fdb show br {bridge}` ; `bridge -s fdb show br {bridge}` ajoute l'ancienneté de chaque
entrée). Repérez les adresses apprises (sans `permanent`) et le port où chacune a été vue.

Réglez ensuite la durée de vie des entrées à **{ageing} secondes** (`ageing_time`, en centièmes
de seconde, section @@ref:linux-bridges@@ des Informations), vérifiez-la avec `ip -d link show {bridge}`, puis que
l'entrée de `m3` disparaît {ageing} s après son dernier échange (en l'absence de tout trafic de
`m3`).
""": """
After `ping`s from `m2` to `m1` and from `m3` to `m1`, display the MAC table of the bridge on `b1`
(`bridge fdb show br {bridge}`; `bridge -s fdb show br {bridge}` adds the age of each
entry). Identify the learned addresses (without `permanent`) and the port where each one was seen.

Then set the lifetime of the entries to **{ageing} seconds** (`ageing_time`, in hundredths
of a second, section @@ref:linux-bridges@@ of the Informations tab), check it with `ip -d link show {bridge}`, then check that
the entry of `m3` disappears {ageing} s after its last exchange (in the absence of any traffic from
`m3`).
""",
    """
- port de `br0` sur lequel l'adresse MAC de `m1` est apprise : @@{port_m1:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- port sur lequel celle de `m3` est apprise : @@{port_m3:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- adresse MAC de `m3` : @@{mac_m3:[0-9a-fA-F:-]+}@@
""": """
- port of `br0` on which the MAC address of `m1` is learned: @@{port_m1:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- port on which that of `m3` is learned: @@{port_m3:>eth0>>>eth0|eth1>>>eth1|br0>>>br0}@@
- MAC address of `m3`: @@{mac_m3:[0-9a-fA-F:-]+}@@
""",
    """
**Solution.** `bridge fdb show br br0` donne `{mac_m1} dev eth0 master br0` (m1, côté `s1`),
`{mac_m2} dev eth1 master br0` et `{mac_m3} dev eth1 master br0` (m2 et m3, côté `s2`), ainsi que
`{mac_gw} dev eth0` (gw) s'il a trafiqué ; les lignes `permanent` sont les adresses de `eth0` et `eth1`.
Puis :

```
{cmds}```

`ip -d link show br0` affiche `ageing_time {centi}`. Sans trafic de `m3`, son entrée disparaît
après {ageing} s (`bridge -s fdb show br br0` montre l'ancienneté). Remarque : pendant un changement de
topologie STP (partie 6), le noyau ramène de lui-même la durée de vie à 2 × *forward delay* = 30 s
(`ageing_time 3000` apparaît alors pendant ~35 s même sans réglage), puis restaure la valeur réglée.

- Réponses : eth0 ; eth1 ; `{mac_m3}`.
- L'évaluation relit la table après ses propres pings (m1 sur eth0, m2 et m3 sur eth1) et
  `ageing_time` ({centi} centièmes = {ageing} s).
""": """
**Solution.** `bridge fdb show br br0` gives `{mac_m1} dev eth0 master br0` (m1, the `s1` side),
`{mac_m2} dev eth1 master br0` and `{mac_m3} dev eth1 master br0` (m2 and m3, the `s2` side), as well as
`{mac_gw} dev eth0` (gw) if it has sent traffic; the `permanent` lines are the addresses of `eth0` and `eth1`.
Then:

```
{cmds}```

`ip -d link show br0` shows `ageing_time {centi}`. Without traffic from `m3`, its entry disappears
after {ageing} s (`bridge -s fdb show br br0` shows the age). Note: during an STP topology
change (part 6), the kernel brings the lifetime down to 2 × *forward delay* = 30 s by itself
(`ageing_time 3000` then appears for ~35 s even without any setting), then restores the configured value.

- Answers: eth0; eth1; `{mac_m3}`.
- The evaluation reads the table again after its own pings (m1 on eth0, m2 and m3 on eth1) and
  `ageing_time` ({centi} hundredths = {ageing} s).
""",
    "table MAC : adresse MAC de m3": "MAC table: MAC address of m3",
    "table MAC : port de m1, port de m3": "MAC table: port of m1, port of m3",
    "le pont apprend m1 sur eth0, m2 et m3 sur eth1 (table lue après les pings de l'évaluation)": "the bridge learns m1 on eth0, m2 and m3 on eth1 (table read after the pings of the evaluation)",
    "durée de vie des entrées de la table MAC de {bridge} : {ageing} s": "lifetime of the entries of the MAC table of {bridge}: {ageing} s",
    "Partie 4 — Filtrage de niveau 2 (question 6)": "Part 4 — Layer-2 filtering (question 6)",
    "m2 ne doit plus joindre l'extérieur": "m2 must no longer reach the outside",
    """
En utilisant la famille **`bridge`** de nftables et le hook **`forward`** (section @@ref:filtering@@ des
Informations), interdisez à `m2` (`{m2}`) de communiquer avec l'extérieur (`ext1`, `{ext1}`,
au-delà de `gw`), sans toucher aux autres communications : `m1` et `m2` doivent toujours se
joindre, et `m3` ne doit pas être affectée (elle joint toujours `ext1`). Les trames de `m2`
vers l'extérieur ont pour destination l'adresse MAC de `gw` : lisez-la dans `ip neigh` sur `m2`
ou dans la table du pont. Vérifiez avec `ping` depuis `m2`, `m1` et `m3`, et affichez votre
règle avec `nft list ruleset`.
""": """
Using the **`bridge`** family of nftables and the **`forward`** hook (section @@ref:filtering@@ of the
Informations tab), forbid `m2` (`{m2}`) to communicate with the outside (`ext1`, `{ext1}`,
beyond `gw`), without touching the other communications: `m1` and `m2` must still reach each
other, and `m3` must not be affected (it still reaches `ext1`). The frames from `m2` to the
outside have the MAC address of `gw` as their destination: read it in `ip neigh` on `m2`
or in the table of the bridge. Check with `ping` from `m2`, `m1` and `m3`, and display your
rule with `nft list ruleset`.
""",
    """
**Solution.** Sur `b1`, par adresses MAC (m2 `{mac_m2}` → gw `{mac_gw}`) :

```
{cmds}```

ou, par adresses IP (tout ce que m2 envoie hors du réseau local) :

```
{by_ip}```

Les requêtes de `m2` vers `ext1` ne sont plus commutées vers `s1` : `ping` n'a pas de réponse
(100 % de pertes). Les trames de `m2` vers `m1` (autre adresse MAC de destination) passent, celles
de `m3` aussi. L'évaluation vérifie que `m2` ne joint plus `ext1` alors que `m1` et `m3` la joignent
et que `m1` et `m2` se joignent, et cherche dans la famille `bridge` de `nft list ruleset` une règle
`drop` qui mentionne `m2` (`ether saddr` / `ether daddr` ou `ip saddr` / `ip daddr`), de
préférence dans une chaîne du hook `forward`.
""": """
**Solution.** On `b1`, by MAC addresses (m2 `{mac_m2}` → gw `{mac_gw}`):

```
{cmds}```

or, by IP addresses (everything m2 sends outside the local network):

```
{by_ip}```

The requests from `m2` to `ext1` are no longer switched to `s1`: `ping` gets no reply
(100% packet loss). The frames from `m2` to `m1` (another destination MAC address) get through, and so do
those of `m3`. The evaluation checks that `m2` no longer reaches `ext1` while `m1` and `m3` reach it
and that `m1` and `m2` reach each other, and looks in the `bridge` family of `nft list ruleset` for a
`drop` rule that mentions `m2` (`ether saddr` / `ether daddr` or `ip saddr` / `ip daddr`),
preferably in a chain of the `forward` hook.
""",
    "m2 ne joint plus ext1 (et joint toujours m1)": "m2 no longer reaches ext1 (and still reaches m1)",
    "m3 joint toujours ext1, m1 et m2 se joignent toujours": "m3 still reaches ext1, m1 and m2 still reach each other",
    "une règle drop de la famille bridge concernant m2, dans le hook forward": "a drop rule of the bridge family concerning m2, in the forward hook",
    "Partie 5 — Adresse IP sur le pont (question 7)": "Part 5 — IP address on the bridge (question 7)",
    "b1 joignable : une adresse sur br0": "b1 reachable: an address on br0",
    """
Ajoutez l'adresse IP `{b1}` à la machine `b1`, **sur l'interface `{bridge}`**, et vérifiez
qu'elle devient joignable depuis `m1`, `m2`, `m3` et `gw`. Ajoutez aussi à `b1` une route par
défaut vers `gw` (`{gw}`) et vérifiez qu'elle joint `ext1` (`{ext1}`). Pourquoi l'adresse va-t-elle
sur `{bridge}` et non sur `eth0` ou `eth1` ?
""": """
Add the IP address `{b1}` to the machine `b1`, **on the interface `{bridge}`**, and check
that it becomes reachable from `m1`, `m2`, `m3` and `gw`. Also add to `b1` a default route
via `gw` (`{gw}`) and check that it reaches `ext1` (`{ext1}`). Why does the address go
on `{bridge}` and not on `eth0` or `eth1`?
""",
    """
- pourquoi sur `br0` ? @@{why_br0:>eth0 et eth1 sont des ports : les trames qu'ils reçoivent sont remises au pont, qui les commute ; br0 est l'interface de la machine dans le réseau ponté>>>port_frames_to_bridge|parce que eth0 et eth1 n'ont pas d'adresse MAC>>>no_mac|parce qu'une adresse sur eth0 ne serait joignable que depuis s1>>>only_s1|c'est une convention : eth0 fonctionnerait aussi bien>>>convention}@@
""": """
- why on `br0`? @@{why_br0:>eth0 and eth1 are ports: the frames they receive are handed to the bridge, which switches them; br0 is the interface of the machine in the bridged network>>>port_frames_to_bridge|because eth0 and eth1 have no MAC address>>>no_mac|because an address on eth0 would only be reachable from s1>>>only_s1|it is a convention: eth0 would work just as well>>>convention}@@
""",
    """
**Solution.** Sur `b1` :

```
{cmds}```

Une interface devenue port d'un pont ne traite plus les trames qu'elle reçoit : elles sont remises
au pont, qui les commute ou, si leur adresse MAC de destination est celle du pont, les livre à la
pile IP de la machine par `br0`. L'adresse doit donc être sur `br0`, qui répond aux ARP des deux
côtés. L'évaluation vérifie l'adresse sur `br0` (et aucune sur `eth0` / `eth1`), les `ping` de `m1`,
`m2`, `m3` et `gw` vers `{b1}`, la route par défaut et le `ping` de `b1` vers `ext1`.
""": """
**Solution.** On `b1`:

```
{cmds}```

An interface that has become a port of a bridge no longer processes the frames it receives: they are handed
to the bridge, which switches them or, if their destination MAC address is that of the bridge, delivers them to
the IP stack of the machine through `br0`. The address must therefore be on `br0`, which answers the ARP requests
from both sides. The evaluation checks the address on `br0` (and none on `eth0` / `eth1`), the `ping`s from `m1`,
`m2`, `m3` and `gw` to `{b1}`, the default route and the `ping` from `b1` to `ext1`.
""",
    "{b1} sur {bridge} de b1, rien sur eth0 ni eth1": "{b1} on {bridge} of b1, nothing on eth0 or eth1",
    "b1 ({b1}) est joignable depuis m1, m2, m3 et gw": "b1 ({b1}) is reachable from m1, m2, m3 and gw",
    "route par défaut de b1 via gw, b1 joint ext1": "default route of b1 via gw, b1 reaches ext1",
    "pourquoi l'adresse va sur br0 et non sur un port": "why the address goes on br0 and not on a port",
    "Partie 6 — Redondance et STP (question 8)": "Part 6 — Redundancy and STP (question 8)",
    "Deux ponts en parallèle : boucle et STP": "Two bridges in parallel: loop and STP",
    """
Le switch `s3` (avec `m4`, `{m4}`) est relié à `s1` par deux machines `b2` et `b3` non configurées,
chacune avec `eth0` sur `s3` et `eth1` sur `s1`. Deux ponts entre les mêmes switchs forment une
**boucle** (`s1` → `b2` → `s3` → `b3` → `s1`) : sans STP, la première trame de diffusion (une
requête ARP, d'où qu'elle vienne sur le réseau) tournerait indéfiniment (section @@ref:stp@@ des Informations).
Jusqu'ici `m4` est isolée ; pontée, elle joint `m1`, `gw` et, par sa route par défaut, `ext1`.

**(a)** Faites de `b2` **et** de `b3` des ponts `{bridge}` entre `eth0` et `eth1`, **avec STP
activé dès la création** (`ip link add {bridge} type bridge stp_state 1`, avant d'ajouter les
ports). Attendez une trentaine de secondes, vérifiez depuis `m4` que `m1` et `ext1` répondent, puis
regardez `bridge link` et `ip -d link show {bridge}` sur les deux ponts : quel pont est la racine
(`root_id` égal à `bridge_id`) et pourquoi ? Sur l'autre pont, un port est *blocking*.

*Facultatif* : les interfaces de `b2` et `b3` sont bridées à {cap}, vous pouvez donc observer
sans danger une tempête. Désactivez STP sur les deux ponts (`stp_state 0`) : rien ne se passe, le
port *blocking* le reste (arrêter STP ne change pas l'état des ports). Sur ce pont, désactivez puis
réactivez ce port (`ip link set eth1 down`, `ip link set eth1 up`) : sans STP, un port qui s'active
commute aussitôt, et la boucle est fermée. Capturez sur `m4` ou sur `m1` avec `tcpdump -e -n -i
eth0` : chaque diffusion du réseau (les requêtes ARP) tourne et se multiplie, `s2` compris à
travers `b1`. Sur `m2`, faites `ip neigh flush all` puis `ping m1` : les copies de sa requête ARP
reviennent par `s1`, `b1` apprend `m2` sur `eth0` (`bridge fdb show`) et `m2` ne joint plus `m1`.
Rétablissez STP (`stp_state 1`) : la tempête cesse en quelques secondes ; attendez 30 s et videz
la table ARP de `m4` (`ip neigh flush all`) avant de refaire un `ping` (voir la remarque du (c)).

**(b)** Sur `m4`, capturez quelques BPDU avec `tcpdump -n -v -i eth0 stp` (`-v` affiche les
temporisateurs et `root-id`) : relevez la priorité de la racine (dans `root-id`, en hexadécimal)
et les trois temporisateurs.

**(c)** Faites de **l'autre pont** la racine en lui donnant une priorité plus petite
(`ip link set {bridge} type bridge priority N`), attendez encore une trentaine de secondes et
vérifiez : `root_id` égal à `bridge_id` sur ce pont, ses deux ports en `forwarding`, un port de
l'ancienne racine *blocking*, `m4` joint toujours `m1` et `ext1`. Si le `ping` échoue juste après
le changement, videz la table ARP de la machine d'où vous le lancez (`ip neigh flush all` sur
`m4`) : les switchs `s1` et `s3` ne participent pas à STP et gardent jusqu'à ~100 s une entrée
périmée vers le port qui vient d'être bloqué (ou vers un pont qui n'a plus de port actif pour
commuter), jusqu'à ce qu'une diffusion de cette machine (sa requête ARP) leur fasse réapprendre
les adresses. Que se passerait-il sans STP ?
""": """
The switch `s3` (with `m4`, `{m4}`) is joined to `s1` by two unconfigured machines `b2` and `b3`,
each with `eth0` on `s3` and `eth1` on `s1`. Two bridges between the same switches form a
**loop** (`s1` → `b2` → `s3` → `b3` → `s1`): without STP, the first broadcast frame (an
ARP request, wherever it comes from on the network) would circulate forever (section @@ref:stp@@ of the Informations tab).
Until now `m4` is isolated; once bridged, it reaches `m1`, `gw` and, through its default route, `ext1`.

**(a)** Turn `b2` **and** `b3` into bridges `{bridge}` between `eth0` and `eth1`, **with STP
on from their creation** (`ip link add {bridge} type bridge stp_state 1`, before adding the
ports). Wait about thirty seconds, check from `m4` that `m1` and `ext1` answer, then
look at `bridge link` and `ip -d link show {bridge}` on both bridges: which bridge is the root
(`root_id` equal to `bridge_id`) and why? On the other bridge, a port is *blocking*.

*Optional*: the interfaces of `b2` and `b3` are capped at {cap}, so you can safely observe
a storm. Turn STP off on both bridges (`stp_state 0`): nothing happens, the *blocking* port
stays blocking (stopping STP does not change the state of the ports). On that bridge, take that
port down and up again (`ip link set eth1 down`, `ip link set eth1 up`): without STP, a port that
comes up forwards at once, and the loop is closed. Capture on `m4` or on `m1` with `tcpdump -e -n -i
eth0`: every broadcast of the network (the ARP requests) circulates and multiplies, `s2` included,
through `b1`. On `m2`, run `ip neigh flush all` then `ping m1`: the copies of its ARP request
come back through `s1`, `b1` learns `m2` on `eth0` (`bridge fdb show`) and `m2` no longer reaches `m1`.
Turn STP back on (`stp_state 1`): the storm stops within a few seconds; wait 30 s and empty
the ARP table of `m4` (`ip neigh flush all`) before pinging again (see the remark in (c)).

**(b)** On `m4`, capture a few BPDUs with `tcpdump -n -v -i eth0 stp` (`-v` shows the
timers and `root-id`): note the priority of the root (in `root-id`, in hexadecimal)
and the three timers.

**(c)** Make **the other bridge** the root by giving it a lower priority
(`ip link set {bridge} type bridge priority N`), wait another thirty seconds or so and
check: `root_id` equal to `bridge_id` on that bridge, both its ports `forwarding`, one port of
the former root *blocking*, `m4` still reaches `m1` and `ext1`. If the `ping` fails right after
the change, empty the ARP table of the machine you run it from (`ip neigh flush all` on
`m4`): the switches `s1` and `s3` take no part in STP and keep, for up to ~100 s, a stale
entry towards the port that has just been blocked (or towards a bridge that no longer has an
active port to switch on), until a broadcast from that machine (its ARP request) makes them
learn the addresses again. What would happen without STP?
""",
    """
- (a) pont élu racine : @@{root_bridge:>b2>>>b2|b3>>>b3}@@
- (a) pourquoi lui ? @@{why_root:>même priorité (32768) sur les deux ponts : l'identifiant le plus petit est celui dont l'adresse MAC est la plus petite>>>lowest_mac|sa priorité est plus petite>>>priority|il a été activé le premier>>>first|son port eth0 a été ajouté le premier>>>first_port}@@
- (b) priorité de la racine lue dans les BPDU (en décimal ou en hexadécimal) : @@{root_priority:[0-9a-fA-Fx]+}@@
- (b) *hello time*, en secondes : @@{hello:[0-9.]+}@@
- (b) *max age*, en secondes : @@{max_age:[0-9.]+}@@
- (b) *forward delay*, en secondes : @@{forward_delay:[0-9.]+}@@
- (c) port *blocking* une fois la nouvelle racine en place : @@{blocked_port:>eth0 de b2>>>b2_eth0|eth1 de b2>>>b2_eth1|eth0 de b3>>>b3_eth0|eth1 de b3>>>b3_eth1|aucun>>>none}@@
- (c) sans STP, avec cette boucle : @@{without_stp:>une tempête de diffusion : chaque trame de diffusion tourne indéfiniment en se multipliant, et les tables MAC deviennent instables>>>storm|rien de particulier : les deux ponts se partagent le trafic>>>load_balance|les trames unicast sont dupliquées mais les diffusions passent normalement>>>unicast_only|le second pont refuse de commuter tant que le premier commute>>>second_waits}@@
""": """
- (a) bridge elected root: @@{root_bridge:>b2>>>b2|b3>>>b3}@@
- (a) why that one? @@{why_root:>same priority (32768) on both bridges: the lowest identifier is the one whose MAC address is the lowest>>>lowest_mac|its priority is lower>>>priority|it was brought up first>>>first|its port eth0 was added first>>>first_port}@@
- (b) priority of the root read in the BPDUs (in decimal or in hexadecimal): @@{root_priority:[0-9a-fA-Fx]+}@@
- (b) *hello time*, in seconds: @@{hello:[0-9.]+}@@
- (b) *max age*, in seconds: @@{max_age:[0-9.]+}@@
- (b) *forward delay*, in seconds: @@{forward_delay:[0-9.]+}@@
- (c) *blocking* port once the new root is in place: @@{blocked_port:>eth0 of b2>>>b2_eth0|eth1 of b2>>>b2_eth1|eth0 of b3>>>b3_eth0|eth1 of b3>>>b3_eth1|none>>>none}@@
- (c) without STP, with this loop: @@{without_stp:>a broadcast storm: each broadcast frame circulates forever, multiplying, and the MAC tables become unstable>>>storm|nothing special: the two bridges share the traffic>>>load_balance|the unicast frames are duplicated but the broadcasts get through normally>>>unicast_only|the second bridge refuses to switch as long as the first one switches>>>second_waits}@@
""",
    """
**Solution.** (a) Sur `b2` et sur `b3` :

```
{cmds}```

Après 30 s, les deux ponts ont la priorité 32768 : la racine est le pont dont l'identifiant
(`8000.` + adresse MAC du pont, la plus petite de ses ports) est le plus petit, ici **`{first_root}`**
(`{mac_first}` contre `{mac_final}` pour `{final_root}`) ; `ip -d link show br0` y donne `root_id` =
`bridge_id` = `8000.{mac_first}`. Sur `{final_root}`, `bridge link` montre `eth0 ... state forwarding`
(port racine : il reçoit les BPDU du port 1 de la racine, sur `s3`) et `eth1 ... state blocking`.

(b) `tcpdump -n -v -i eth0 stp` sur `m4` : `STP 802.1d, Config, Flags [none], bridge-id
8000.{mac_first}.8001, length 35` (`Flags [Topology change]` pendant la demi-minute qui suit un
changement), puis `message-age 0.00s, max-age {max_age}.00s, hello-time {hello}.00s, forwarding-delay
{forward_delay}.00s` et `root-id 8000.{mac_first}, root-pathcost 0`. Priorité de la racine : 0x8000 =
{default_priority} ; hello {hello} s, max age {max_age} s, forward delay {forward_delay} s.

(c) Sur `{final_root}` : `{root}` (toute valeur inférieure à {default_priority} convient). Après 30 s,
`root_id` = `bridge_id` = `1000.{mac_final}` sur `{final_root}`, ses deux ports `forwarding`, et
`{first_root}` bloque son `eth1` (son port racine est `eth0`, qui entend le port 1 de la nouvelle racine
sur `s3` ; ce serait `eth0` si `eth1` de `{final_root}` avait été ajouté le premier). Les switchs `s1` /
`s3` (vde, sans STP) gardent ~100 s l'entrée de `m4` / `m1` vers `{first_root}`, qui ne commute plus :
`ping` échoue jusqu'à une diffusion ARP de la machine qui l'émet (l'évaluation vide la table ARP de `m4`
et de `m1` avant ses pings, un étudiant fait `ip neigh flush all`). Sans STP, la boucle ferait tourner
indéfiniment chaque trame de diffusion du réseau (tempête, bridée ici à {cap} mais visible sur `s1` et
`s2`) et les tables MAC verraient chaque adresse sur les deux ports. Tempête facultative du (a) : arrêter
STP laisse le port bloqué dans cet état, c'est `ip link set eth1 down` / `up` sur ce port qui ferme la
boucle ; mesuré avec la bride à {cap} : 3 000 à 4 000 trames/s sur chaque machine du réseau, `m2` ne joint
plus `m1` (`b1` apprend `m2` sur `eth0`), `m1` joint encore `ext1`, l'évaluation pendant la tempête
perd une vingtaine de points, tout rentre dans l'ordre quelques secondes après `stp_state 1`.

- Réponses : {first_root} ; même priorité, plus petite adresse MAC ; {default_priority} (0x8000) ; {hello} ;
  {max_age} ; {forward_delay} ; eth1 de {first_root} (le port réellement bloqué est accepté) ; tempête.
- L'évaluation lit sur `b2` et `b3` `stp_state`, les ports, `root_id` / `bridge_id` et l'état des ports
  (`{final_root}` racine avec une priorité inférieure à {default_priority} et deux ports `forwarding`,
  `{first_root}` avec un seul port `blocking` et `{final_root}` pour racine), puis `ping` de `m4` vers `m1`
  et `ext1` et de `m1` vers `m4` (précédés de `ip neigh flush all`).
""": """
**Solution.** (a) On `b2` and on `b3`:

```
{cmds}```

After 30 s, both bridges have the priority 32768: the root is the bridge whose identifier
(`8000.` + MAC address of the bridge, the lowest of its ports) is the lowest, here **`{first_root}`**
(`{mac_first}` against `{mac_final}` for `{final_root}`); there, `ip -d link show br0` gives `root_id` =
`bridge_id` = `8000.{mac_first}`. On `{final_root}`, `bridge link` shows `eth0 ... state forwarding`
(root port: it receives the BPDUs of port 1 of the root, on `s3`) and `eth1 ... state blocking`.

(b) `tcpdump -n -v -i eth0 stp` on `m4`: `STP 802.1d, Config, Flags [none], bridge-id
8000.{mac_first}.8001, length 35` (`Flags [Topology change]` during the half-minute that follows a
change), then `message-age 0.00s, max-age {max_age}.00s, hello-time {hello}.00s, forwarding-delay
{forward_delay}.00s` and `root-id 8000.{mac_first}, root-pathcost 0`. Priority of the root: 0x8000 =
{default_priority}; hello {hello} s, max age {max_age} s, forward delay {forward_delay} s.

(c) On `{final_root}`: `{root}` (any value below {default_priority} will do). After 30 s,
`root_id` = `bridge_id` = `1000.{mac_final}` on `{final_root}`, both its ports `forwarding`, and
`{first_root}` blocks its `eth1` (its root port is `eth0`, which hears port 1 of the new root
on `s3`; the blocked port would be `eth0` if `eth1` of `{final_root}` had been added first). The
switches `s1` / `s3` (vde, without STP) keep for ~100 s the entry of `m4` / `m1` towards `{first_root}`,
which no longer switches: `ping` fails until an ARP broadcast from the machine sending it (the evaluation
empties the ARP table of `m4` and of `m1` before its pings, a student runs `ip neigh flush all`). Without
STP, the loop would make every broadcast frame of the network circulate forever (a storm, capped here at
{cap} but visible on `s1` and `s2`) and the MAC tables would see each address on both ports. Optional
storm of (a): stopping STP leaves the blocked port in that state, it is `ip link set eth1 down` / `up` on
that port that closes the loop; measured with the cap at {cap}: 3,000 to 4,000 frames/s on every machine
of the network, `m2` no longer reaches `m1` (`b1` learns `m2` on `eth0`), `m1` still reaches `ext1`, the
evaluation during the storm loses about twenty points, everything is back to normal a few seconds after
`stp_state 1`.

- Answers: {first_root}; same priority, lowest MAC address; {default_priority} (0x8000); {hello};
  {max_age}; {forward_delay}; eth1 of {first_root} (the port actually blocked is accepted); storm.
- On `b2` and `b3`, the evaluation reads `stp_state`, the ports, `root_id` / `bridge_id` and the state of
  the ports (`{final_root}` root with a priority below {default_priority} and two `forwarding` ports,
  `{first_root}` with a single `blocking` port and `{final_root}` as its root), then `ping`s from `m4` to
  `m1` and `ext1` and from `m1` to `m4` (preceded by `ip neigh flush all`).
""",
    "{bridge} avec les ports eth0 et eth1 et STP actif sur b2 et sur b3": "{bridge} with the ports eth0 and eth1 and STP enabled on b2 and on b3",
    "m4 joint m1 et, par sa route par défaut, ext1 à travers la boucle ; m1 joint m4": "m4 reaches m1 and, through its default route, ext1 across the loop; m1 reaches m4",
    "pont élu racine à priorité égale ({first_root}) et pourquoi (plus petite adresse MAC)": "bridge elected root with equal priorities ({first_root}) and why (lowest MAC address)",
    "BPDU : priorité de la racine, hello time, max age, forward delay": "BPDUs: priority of the root, hello time, max age, forward delay",
    "{final_root} est la racine (priorité abaissée, root_id = bridge_id) avec ses deux ports en forwarding": "{final_root} is the root (lowered priority, root_id = bridge_id) with both its ports forwarding",
    "{first_root} bloque un seul de ses ports et reconnaît {final_root} comme racine": "{first_root} blocks a single one of its ports and recognises {final_root} as the root",
    "le port bloqué une fois la nouvelle racine en place (comparé à l'état réel de {first_root})": "the blocked port once the new root is in place (compared with the actual state of {first_root})",
    "sans STP : tempête de diffusion": "without STP: broadcast storm",
}}
