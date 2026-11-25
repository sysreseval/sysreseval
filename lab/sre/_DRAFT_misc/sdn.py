"""SDN lab: Open vSwitch, OpenFlow and controllers.

Four independent sites, one device under configuration per part:

1. ``sw1``: a first Open vSwitch bridge, its ports and their access VLANs (``h11``, ``h12``, ``h13``);
2. ``sw2``: a bridge in ``secure`` mode without controller whose flow table the students write by
   hand with ``ovs-ofctl`` (an access list between ``client2``, ``web2``, ``db2`` and ``admin2``);
3. ``ctl3`` + ``sw3``: a reactive controller (OS-Ken's ``simple_switch_13``) reached over an
   out-of-band control network, the OpenFlow exchange captured with tshark (``h31``, ``h32``);
4. ``ops`` → ``ctl4`` (``ofctl_rest``, no terminal) → ``sw4a`` / ``sw4b`` (no terminal): two
   tenants isolated across a trunk with flows pushed through the REST northbound API;
   bonus: a meter limiting ``guest4`` towards ``srv4`` on ``sw4a``.

Grading: ``ovs-vsctl`` / ``ovs-ofctl`` read on the switches, real traffic between the hosts (ping,
the HTTP echo server of ``lib/server_echo.py``, iperf3) and ``ovs-appctl ofproto/trace`` on
``sw2`` for the packets the access list must drop (a trace cannot be fooled by a filter on a
host).  The state ``final`` applies the reference solution (``solve_<part>`` one part); every
question ends with its solution, shown to the instructor only.

Image: ``sysreseval/sdn13`` (``images/sdn13/Dockerfile``: base13 + Open vSwitch 3.5 + OS-Ken 3.0 and
the applications ``simple_switch_13`` / ``ofctl_rest``) for the switches and controllers; base13
for the hosts.
"""

import random
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s, random_mac_address
from net_config import set_net_config_entry
from ping import eval_ping
from sdn import (
    OPENFLOW_PORT,
    REST_PORT,
    get_flows,
    get_meters,
    get_ovs_state,
    get_trace,
    normalize_decimal_dpid,
    normalize_dpid,
    osken_start_cmd,
    ovs_bridge_cmd,
    ovs_start_cmd,
    rest_cmd,
    table_miss,
    trace_flow,
)
from server_echo_helpers import get_http_echo, install_echo_server
from tc import parse_iperf3

default_language = "fr"
tr = make_tr(default_language)

title = tr("SDN : Open vSwitch, OpenFlow et contrôleurs", en="SDN: Open vSwitch, OpenFlow and controllers")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

SDN = {"image": sre_docker_image("sdn13")}
BRIDGE = "br0"
MAC_PREFIX = "02:53:44"
P1_HOSTS = ("h11", "h12", "h13")
P2_HOSTS = ("client2", "web2", "db2", "admin2")
P3_HOSTS = ("h31", "h32")
P4_HOSTS = ("red1", "blue1", "red2", "blue2")
BONUS_HOSTS = ("guest4", "srv4")
HOSTS = P1_HOSTS + P2_HOSTS + P3_HOSTS + P4_HOSTS + BONUS_HOSTS
SWITCHES = ("sw1", "sw2", "sw3", "sw4a", "sw4b")
# the interface of each switch towards each neighbour (fixed by the topology)
SW1_PORTS = {"h11": "eth0", "h12": "eth1", "h13": "eth2"}
SW2_PORTS = {"client2": "eth0", "web2": "eth1", "db2": "eth2", "admin2": "eth3"}
SW3_PORTS = {"h31": "eth1", "h32": "eth2"}
SW4A_PORTS = {"trunk": "eth1", "red1": "eth2", "blue1": "eth3", "guest4": "eth4", "srv4": "eth5"}
SW4B_PORTS = {"trunk": "eth1", "red2": "eth2", "blue2": "eth3"}
DB_PORT = 5432
SSH_PORT = 22
WEB_PORT = 80
METER_ID = 1
IPERF_SECONDS = 3
# iperf3 sends three times the rate of the meter: without the meter srv4 gets all of it; with it, the rate
# plus at most one second of burst over the test (OVS gives a meter without burst_size a bucket of one
# second of traffic), i.e. at most 1.33 times the rate in 3 s
IPERF_FACTOR = 3
RATE_LOW, RATE_HIGH = 0.5, 1.5
CHOICE_SCOPE = params.EXO_EVAL_SCOPE  # a dropdown answer counts for the instructor only
ACL_FILE = "/root/acl.flows"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    # part 1: the access VLANs
    vlan_a: int = 0
    vlan_b: int = 0
    dpid1: int = 0  # the datapath ID the reference solution gives to br0 of sw1
    # part 2: the OpenFlow port numbers of sw2 (interface -> ofport)
    ofports2: dict = field(default_factory=dict)
    # part 3: the datapath ID of sw3
    dpid3: int = 0
    # part 4: the datapath IDs and port numbers of sw4a / sw4b, the rate of the bonus meter (kbit/s)
    dpid4a: int = 0
    dpid4b: int = 0
    ofports4a: dict = field(default_factory=dict)
    ofports4b: dict = field(default_factory=dict)
    meter_rate: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        # VLAN IDs outside the course examples (10, 20) and the round hundreds
        data.vlan_a, data.vlan_b = random.sample([v for v in range(101, 900) if v % 100], 2)
        data.dpid1 = random.randint(0x10000000, 0xFFFFFFFFFFFF)
        # OpenFlow port numbers outside the course examples (1, 2, 3)
        numbers = random.sample(range(5, 49), len(SW2_PORTS))
        data.ofports2 = dict(zip(SW2_PORTS.values(), numbers))
        data.dpid3 = random.randint(0x10000000, 0xFFFFFFFFFFFF)
        data.dpid4a, data.dpid4b = random.sample(range(1000, 9999), 2)
        data.ofports4a = dict(zip(SW4A_PORTS.values(), random.sample(range(5, 49), len(SW4A_PORTS))))
        data.ofports4b = dict(zip(SW4B_PORTS.values(), random.sample(range(5, 49), len(SW4B_PORTS))))
        data.meter_rate = random.choice([r for r in range(2500, 9501, 500) if r != 5000])
        # addresses
        (data.nets.lan1, data.nets.lan2, data.nets.lan3, data.nets.lan4, data.nets.lan5, data.nets.ctrl3,
         data.nets.ctrl4) = random_ipv4networks(masks=[24] * 7, from_private_network=True,
                                                exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        data.ips.h11, data.ips.h12, data.ips.h13 = random_ipv4s(data.nets.lan1, 3)
        data.ips.client2, data.ips.web2, data.ips.db2, data.ips.admin2 = random_ipv4s(data.nets.lan2, 4)
        data.ips.h31, data.ips.h32 = random_ipv4s(data.nets.lan3, 2)
        data.ips.red1, data.ips.blue1, data.ips.red2, data.ips.blue2 = random_ipv4s(data.nets.lan4, 4)
        data.ips.guest4, data.ips.srv4 = random_ipv4s(data.nets.lan5, 2)
        data.ips.ctl3, data.ips.sw3 = random_ipv4s(data.nets.ctrl3, 2)
        data.ips.ctl4, data.ips.sw4a, data.ips.sw4b, data.ips.ops = random_ipv4s(data.nets.ctrl4, 4)
        for host, mac in zip(HOSTS, random_mac_address(prefix=MAC_PREFIX, n=len(HOSTS))):
            setattr(data.macs, host, mac)
        return data

    # -- derived values ------------------------------------------------------------------------

    def ip(self, name: str) -> str:
        return str(getattr(self.ips, name).ip)

    def mac(self, name: str) -> str:
        return str(getattr(self.macs, name)).replace("-", ":").lower()

    def ofport2(self, host: str) -> int:
        return self.ofports2[SW2_PORTS[host]]

    def ofport4a(self, neighbour: str) -> int:
        return self.ofports4a[SW4A_PORTS[neighbour]]

    def ofport4b(self, neighbour: str) -> int:
        return self.ofports4b[SW4B_PORTS[neighbour]]


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------

_LINKS = {
    # network: {machine: interface}
    "sw1_h11": {"sw1": 0, "h11": 0},
    "sw1_h12": {"sw1": 1, "h12": 0},
    "sw1_h13": {"sw1": 2, "h13": 0},
    "sw2_client2": {"sw2": 0, "client2": 0},
    "sw2_web2": {"sw2": 1, "web2": 0},
    "sw2_db2": {"sw2": 2, "db2": 0},
    "sw2_admin2": {"sw2": 3, "admin2": 0},
    "ctrl3": {"ctl3": 0, "sw3": 0},
    "sw3_h31": {"sw3": 1, "h31": 0},
    "sw3_h32": {"sw3": 2, "h32": 0},
    "ctrl4": {"ctl4": 0, "sw4a": 0, "sw4b": 0, "ops": 0},
    "trunk": {"sw4a": 1, "sw4b": 1},
    "sw4a_red1": {"sw4a": 2, "red1": 0},
    "sw4a_blue1": {"sw4a": 3, "blue1": 0},
    "sw4a_guest4": {"sw4a": 4, "guest4": 0},
    "sw4a_srv4": {"sw4a": 5, "srv4": 0},
    "sw4b_red2": {"sw4b": 2, "red2": 0},
    "sw4b_blue2": {"sw4b": 3, "blue2": 0},
}


class NetScheme(NetScheme0):
    _machine_specs = {
        "sw1": {**SDN, "color": "lightblue"},
        "h11": {"color": "lightgreen"},
        "h12": {"color": "lightgreen"},
        "h13": {"color": "lightgreen"},
        "sw2": {**SDN, "color": "lightblue"},
        "client2": {"color": "lightgreen"},
        "web2": {"color": "lightgreen"},
        "db2": {"color": "lightgreen"},
        "admin2": {"color": "lightgreen"},
        "ctl3": {**SDN, "color": "orange"},
        "sw3": {**SDN, "color": "lightblue"},
        "h31": {"color": "lightgreen"},
        "h32": {"color": "lightgreen"},
        "ctl4": {**SDN, "color": "orange", "allow_connection": False},
        "sw4a": {**SDN, "color": "lightblue", "allow_connection": False},
        "sw4b": {**SDN, "color": "lightblue", "allow_connection": False},
        "ops": {"color": "khaki"},
        "red1": {"color": "lightcoral"},
        "red2": {"color": "lightcoral"},
        "blue1": {"color": "lightskyblue"},
        "blue2": {"color": "lightskyblue"},
        "guest4": {"color": "lightgrey"},
        "srv4": {"color": "lightgrey"},
    }
    _network_specs = {net: {"color": "orange" if net.startswith("ctrl") else "lightgrey"} for net in _LINKS}

    @property
    def _topology(self):
        macs = self.data.macs
        topology = {}
        for net, machines in _LINKS.items():
            topology[net] = {m: ((i, getattr(macs, m)) if m in HOSTS else i) for m, i in machines.items()}
        return topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        self.net_config = {host: [([getattr(d.ips, host)], [])] for host in HOSTS}
        for m in ("ctl3", "sw3", "ctl4", "sw4a", "sw4b", "ops"):
            self.net_config[m] = [([getattr(d.ips, m)], [])]

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi le SDN"), tag="why")
            + tr("""

Un équipement réseau classique fait trois choses :

- le **plan de données** (*data plane*) traite chaque paquet : il cherche dans ses tables (adresses MAC,
  routes, listes d'accès) et transmet, modifie ou jette, à la vitesse du matériel ;
- le **plan de contrôle** (*control plane*) remplit ces tables : apprentissage des adresses MAC, STP,
  OSPF, BGP... ; chaque équipement calcule seul, avec ses voisins, par des protocoles distribués ;
- le **plan de gestion** (*management plane*) : la configuration (CLI, SNMP, fichiers) et la supervision.

Sur un réseau de centaines d'équipements, cette organisation montre ses limites : chaque boîte se
configure à part, dans le langage de son constructeur ; une politique globale (isoler deux clients,
faire passer un flux par un pare-feu) se traduit en dizaines de configurations à garder cohérentes ;
ajouter une fonction attend que les constructeurs l'implémentent.

Le **SDN** (*Software Defined Networking*, réseau défini par logiciel) **sépare le plan de contrôle du
plan de données** :

- les équipements (les *switchs* SDN) ne gardent que le plan de données : des tables de flux que
  d'autres remplissent ;
- un **contrôleur**, logiciel centralisé (logiquement : il peut être réparti sur plusieurs serveurs),
  a la vue de tout le réseau et programme les tables de tous les équipements ;
- les politiques sont écrites par des **applications**, au-dessus du contrôleur, dans un langage de
  programmation ordinaire.

Le réseau devient programmable comme un système informatique : configuration automatisée, réaction
aux événements, fonctions nouvelles sans changer le matériel.
""")
            + info_subtitle(tr("L'architecture"), tag="architecture")
            + tr("""

```
     applications (politique, supervision, pare-feu, équilibrage...)
              │  API nord (northbound) : REST, gRPC, bibliothèques
     ┌────────┴────────┐
     │   contrôleur    │ ── API est-ouest : entre contrôleurs (redondance, fédération)
     └────────┬────────┘
              │  API sud (southbound) : OpenFlow, OVSDB, NETCONF, P4Runtime
     switch   switch   switch    (plan de données)
```

- L'**API sud** (*southbound*) relie le contrôleur aux équipements. **OpenFlow** programme les tables
  de flux ; **OVSDB** (RFC 7047) configure Open vSwitch lui-même (ponts, ports, VLAN) ; **NETCONF**
  et ses modèles YANG configurent les équipements classiques.
- L'**API nord** (*northbound*) est celle que le contrôleur offre aux applications : très souvent une
  API **REST** (HTTP + JSON), parfois une bibliothèque du langage du contrôleur.
- Le réseau qui relie le contrôleur aux switchs est le **réseau de contrôle**. Il est souvent **hors
  bande** (*out-of-band*) : un réseau de gestion séparé, qui ne dépend pas des flux qu'il programme.

Deux façons de remplir les tables :

| mode | principe | avantages / inconvénients |
|------|----------|---------------------------|
| **réactif** | un paquet qui ne correspond à aucune entrée est envoyé au contrôleur, qui décide et installe une entrée pour la suite du flux | s'adapte au trafic ; le premier paquet de chaque flux est lent, le contrôleur est très sollicité et sa perte bloque les nouveaux flux |
| **proactif** | le contrôleur installe à l'avance toutes les entrées nécessaires | aucune latence au premier paquet, le réseau survit à une panne du contrôleur ; les tables doivent tout prévoir |
""")
            + info_subtitle(tr("OpenFlow"), tag="openflow")
            + info_subtitle(tr("Tables et entrées de flux"), level=2, tag="flowtable")
            + tr("""

**OpenFlow** (Open Networking Foundation) est le premier protocole sud du SDN. Un switch OpenFlow a une
ou plusieurs **tables de flux** (*flow tables*), numérotées à partir de 0. Une **entrée** (*flow
entry*) contient :

| champ | rôle |
|-------|------|
| *match* | les champs à comparer : port d'entrée, adresses MAC, type Ethernet, VLAN, adresses IP, protocole, ports TCP/UDP... ; un champ absent est un joker |
| *priority* | 0 à 65535 ; si plusieurs entrées correspondent, **la plus prioritaire gagne** (à priorité égale, le comportement n'est pas défini) |
| *instructions* | les actions à appliquer (*apply-actions*), aller à une autre table (*goto-table*), passer par un compteur de débit (*meter*) |
| *counters* | paquets et octets qui ont correspondu, durée de vie |
| *timeouts* | *idle_timeout* (supprimée après N secondes sans paquet), *hard_timeout* (après N secondes quoi qu'il arrive) ; 0 = jamais |
| *cookie* | une valeur choisie par le contrôleur pour retrouver ses entrées |

Un paquet entre dans la table 0, prend l'entrée qui correspond avec la plus forte priorité, exécute
ses instructions ; un *goto-table* le fait continuer dans une table de numéro supérieur (un
**pipeline**). Un paquet qui ne correspond à rien est **jeté**, sauf s'il existe une entrée **table-miss** :
priorité 0, aucun champ, qui l'envoie en général au contrôleur.

Les actions les plus courantes :

| action | effet |
|--------|-------|
| `output:N` | émettre sur le port OpenFlow numéro N |
| aucune action (`drop`) | jeter |
| `push_vlan` / `set_field:vlan_vid` / `pop_vlan` | ajouter, modifier, retirer une étiquette 802.1Q |
| `set_field:...` | réécrire un champ (adresse MAC, IP, port TCP...) |
| `group:N` | passer par un groupe (voir plus bas) |

Les ports **réservés** : `CONTROLLER` (au contrôleur, dans un PACKET_IN), `FLOOD` (tous les ports
sauf celui d'entrée), `ALL`, `IN_PORT` (renvoyer par le port d'entrée), `LOCAL` (la pile réseau
du switch lui-même) et `NORMAL` (le traitement d'un switch classique, avec apprentissage MAC : une
extension que propose Open vSwitch). Chaque port a un **numéro OpenFlow** (*ofport*) choisi par le
switch, différent du nom de l'interface.

Les champs se combinent avec des **prérequis** : on ne peut comparer une adresse IP que si le type
Ethernet est IPv4 (`eth_type=0x0800`), un port TCP que si le protocole IP est TCP (`ip_proto=6`).
""")
            + info_subtitle(tr("Les messages"), level=2, tag="messages")
            + tr("""

Le switch ouvre une connexion **TCP vers le contrôleur, port 6653** (6633 dans les anciennes
versions), éventuellement chiffrée en TLS. Les messages principaux :

| message | sens | rôle |
|---------|------|------|
| HELLO | les deux | ouverture ; chacun annonce les versions qu'il parle, la plus haute commune est retenue |
| FEATURES_REQUEST / FEATURES_REPLY | contrôleur → switch → | le switch donne son **identifiant de datapath** (*datapath ID*, **dpid**, 64 bits), son nombre de tables, ses capacités |
| ECHO_REQUEST / ECHO_REPLY | les deux | maintien de la connexion |
| **PACKET_IN** | switch → contrôleur | un paquet envoyé au contrôleur (table-miss ou action `output:CONTROLLER`), avec son port d'entrée |
| **FLOW_MOD** | contrôleur → switch | ajouter, modifier ou supprimer des entrées de flux |
| **PACKET_OUT** | contrôleur → switch | émettre un paquet donné par le contrôleur, avec des actions |
| FLOW_REMOVED | switch → contrôleur | une entrée a expiré (si demandé) |
| PORT_STATUS | switch → contrôleur | un port est apparu, a disparu, a changé d'état |
| MULTIPART_REQUEST / REPLY | les deux | statistiques : flux, ports, tables, compteurs de débit, description |
| BARRIER_REQUEST / REPLY | les deux | attendre que les messages précédents soient appliqués |
| ERROR | switch → contrôleur | un message refusé (champ inconnu, prérequis manquant, table pleine...) |

Le champ *version* de l'en-tête vaut `0x01` pour OpenFlow 1.0, `0x04` pour 1.3, `0x06` pour 1.5.
**OpenFlow 1.3** est la version la plus déployée : plusieurs tables, groupes, compteurs de débit,
IPv6, champs extensibles (OXM). Wireshark / tshark décodent OpenFlow (`openflow_v4` pour la 1.3).
""")
            + info_subtitle(tr("Groupes et compteurs de débit"), level=2, tag="groups")
            + tr("""

- Un **groupe** est une liste de *buckets* d'actions. Types : `all` (chaque bucket reçoit une copie :
  diffusion, miroir), `select` (un bucket choisi par hachage : répartition de charge), `indirect` (un
  seul bucket, partagé par plusieurs entrées), `fast-failover` (le premier bucket dont le port est
  vivant : secours sans attendre le contrôleur).
- Un **compteur de débit** (*meter*) mesure le débit des paquets qui passent par lui et applique une
  **bande** au-delà d'un seuil : `drop` (jeter : limitation de débit, *policing*) ou `dscp_remark`
  (déclasser). Débit en kbit/s (`kbps`) ou en paquets par seconde (`pktps`). Une entrée de flux y fait
  passer ses paquets par l'instruction `meter:N`, avant ses actions.
""")
            + info_subtitle(tr("Open vSwitch"), tag="ovs")
            + info_subtitle(tr("Architecture"), level=2, tag="ovsarch")
            + tr("""

**Open vSwitch** (OVS) est un switch logiciel libre, utilisé dans les hyperviseurs, OpenStack,
Kubernetes et la plupart des laboratoires SDN. Trois composants :

| composant | rôle |
|-----------|------|
| `ovsdb-server` | la base de configuration (`/etc/openvswitch/conf.db`) : ponts, ports, interfaces, VLAN, contrôleurs ; protocole OVSDB, port TCP **6640** quand il écoute sur le réseau |
| `ovs-vswitchd` | le démon qui fait le switch : il lit la base, parle **OpenFlow** avec les contrôleurs, tient les tables de flux et programme le datapath |
| le **datapath** | le module `openvswitch` du noyau Linux : le chemin rapide ; il garde un cache des décisions récentes et remonte à `ovs-vswitchd` le premier paquet de chaque nouvelle combinaison (*upcall*) |

Un **pont** (*bridge*) OVS est un switch indépendant avec sa propre table de flux et son propre dpid
(tiré par défaut de l'adresse MAC du pont, fixé par `other-config:datapath-id`). Il a toujours un port
interne du même nom que lui (`LOCAL`).
""")
            + info_subtitle(tr("Les outils"), level=2, tag="ovstools")
            + tr("""

| commande | usage |
|----------|-------|
| `ovs-vsctl show` | la configuration : ponts, ports, contrôleurs (connectés ou non) |
| `ovs-vsctl add-br br0` / `del-br br0` | créer / supprimer un pont |
| `ovs-vsctl add-port br0 eth1` / `del-port br0 eth1` | ajouter / retirer un port |
| `ovs-vsctl set port eth1 tag=10` | port d'**accès** dans le VLAN 10 (`trunks=10,20` : port de trunk limité à ces VLAN) |
| `ovs-vsctl set-controller br0 tcp:192.0.2.1:6653` / `del-controller br0` | contrôleur du pont |
| `ovs-vsctl set-fail-mode br0 secure` | mode de défaillance (voir plus bas) |
| `ovs-vsctl set bridge br0 protocols=OpenFlow13` | versions d'OpenFlow acceptées |
| `ovs-vsctl list interface eth1` | une ligne de la base (ici, `ofport` donne le numéro OpenFlow) |
| `ovs-ofctl -O OpenFlow13 show br0` | dpid et ports avec leurs numéros OpenFlow |
| `ovs-ofctl -O OpenFlow13 dump-flows br0` | les entrées de flux avec leurs compteurs |
| `ovs-ofctl -O OpenFlow13 add-flow br0 "<entrée>"` | ajouter une entrée (`add-flows br0 fichier` : une par ligne) |
| `ovs-ofctl -O OpenFlow13 del-flows br0 ["<match>"]` | supprimer (toutes, ou celles qui correspondent) |
| `ovs-ofctl -O OpenFlow13 replace-flows br0 fichier` | remplacer la table par le contenu d'un fichier |
| `ovs-ofctl -O OpenFlow13 dump-meters br0` | les compteurs de débit |
| `ovs-appctl ofproto/trace br0 "<paquet>"` | **simuler** un paquet : quelles entrées il traverse, ce qu'il devient |
| `ovs-appctl fdb/show br0` | la table MAC apprise par l'action `NORMAL` |
| `ovs-dpctl dump-flows` | le cache du datapath (le chemin rapide) |

`-O OpenFlow13` choisit la version que parle `ovs-ofctl` : elle doit être acceptée par le pont, sinon
la négociation échoue (`version negotiation failed`).
""")
            + info_subtitle(tr("La syntaxe des entrées"), level=2, tag="ovsflows")
            + tr("""

Une entrée s'écrit `champ=valeur,champ=valeur,...,actions=action,action`. Exemples :

```
priority=100,in_port=1,actions=output:2
priority=200,arp,actions=NORMAL
priority=300,tcp,nw_src=192.0.2.10,nw_dst=192.0.2.20,tp_dst=80,actions=output:3
priority=300,icmp,nw_src=192.0.2.10,icmp_type=8,actions=NORMAL
priority=150,in_port=4,dl_dst=02:00:00:00:00:01,actions=mod_vlan_vid:10,output:1
priority=0,actions=drop
```

| écriture | sens |
|----------|------|
| `in_port=N` | port d'entrée (numéro OpenFlow) |
| `dl_src`, `dl_dst`, `dl_type`, `dl_vlan` | adresses MAC, type Ethernet, VLAN |
| `arp`, `ip`, `icmp`, `tcp`, `udp` | raccourcis : `arp` = `dl_type=0x0806`, `tcp` = `dl_type=0x0800,nw_proto=6`... |
| `nw_src`, `nw_dst` | adresses IPv4 (préfixe possible : `nw_src=192.0.2.0/24`) |
| `tp_src`, `tp_dst` | ports TCP / UDP (après `tcp` ou `udp`) |
| `icmp_type` | type ICMP (8 : demande d'écho, 0 : réponse) |
| `priority=N` | priorité (32768 si absente) |
| `idle_timeout=N`, `hard_timeout=N`, `cookie=N` | voir plus haut |
| `actions=output:N`, `NORMAL`, `CONTROLLER`, `FLOOD`, `drop` | actions ; plusieurs, séparées par des virgules, s'appliquent dans l'ordre |
| `actions=meter:1,output:2` | passer par le compteur de débit 1 puis émettre |

**Un filtrage sans état doit autoriser les réponses** : une entrée `tcp,nw_src=A,nw_dst=B,tp_dst=80`
laisse passer la requête, il en faut une autre pour la réponse (`tcp,nw_src=B,nw_dst=A,tp_src=80`).
Et sans ARP autorisé, aucune machine ne trouve l'adresse MAC de l'autre. (OVS sait aussi filtrer
**avec état** grâce au suivi de connexions du noyau : actions `ct(...)`, champ `ct_state`.)

Pour vérifier une politique sans générer de trafic :

```
ovs-appctl ofproto/trace br0 'in_port=1,tcp,dl_src=02:00:00:00:00:01,dl_dst=02:00:00:00:00:02,nw_src=192.0.2.10,nw_dst=192.0.2.20,tcp_dst=80'
```

La dernière ligne, `Datapath actions:`, donne le verdict : `drop`, ou les ports de sortie. Dans
`ofproto/trace`, écrivez les ports avec `tcp_dst` / `udp_dst` : `tp_dst` n'y est accepté qu'après
`tcp`.
""")
            + info_subtitle(tr("Les modes de défaillance"), level=2, tag="failmode")
            + tr("""

Que fait un pont qui n'a pas (ou plus) de contrôleur ?

| `fail-mode` | sans contrôleur |
|-------------|-----------------|
| `standalone` (par défaut) | après quelques secondes sans contrôleur, OVS se comporte en **switch classique** : il ajoute une entrée `NORMAL` (apprentissage MAC) ; un pont neuf sans contrôleur a donc une seule entrée, `priority=0 actions=NORMAL` |
| `secure` | OVS **n'ajoute rien** : seules les entrées installées (par le contrôleur ou à la main) s'appliquent ; elles restent jusqu'à leur expiration, aucun nouveau flux n'est appris |

Le mode `secure` est celui d'un réseau dont le contrôleur décide de tout : une panne du contrôleur
ne doit pas ouvrir le réseau. C'est aussi le mode d'un pont dont on écrit soi-même la table de flux.
""")
            + info_subtitle(tr("Les contrôleurs"), tag="controllers")
            + info_subtitle(tr("Panorama"), level=2, tag="panorama")
            + tr("""

| contrôleur | langage | remarques |
|------------|---------|-----------|
| NOX / POX | C++ / Python | les premiers, pédagogiques |
| **Ryu** → **OS-Ken** | Python | bibliothèque complète d'OpenFlow 1.0 à 1.5 ; Ryu n'est plus maintenu, OpenStack le continue sous le nom OS-Ken (utilisé par Neutron, le réseau d'OpenStack) |
| ONOS | Java | pour les opérateurs : répartition, haute disponibilité, intentions (*intents*) |
| OpenDaylight | Java | projet de la Linux Foundation, nombreux protocoles sud (OpenFlow, NETCONF, BGP-LS...) |
| Faucet | Python (sur Ryu) | switch de production configuré par un fichier YAML |

Dans ce TP, le contrôleur est **OS-Ken**. `osken-manager` charge des applications (des modules
Python) et écoute les switchs sur le port 6653 :

```
osken-manager --log-file /var/log/osken-manager.log os_ken.app.simple_switch_13 &
```

- `os_ken.app.simple_switch_13` : un switch à apprentissage réactif (ci-dessous) ;
- `os_ken.app.ofctl_rest` : une API REST qui traduit des documents JSON en messages OpenFlow
  (port 8080).

(Ces deux applications, présentes dans Ryu, ont été réécrites pour l'image de ce TP : OS-Ken ne les
fournit plus. Leurs URL et leurs documents sont ceux de Ryu.)
""")
            + info_subtitle(tr("Le switch à apprentissage réactif"), level=2, tag="learning")
            + tr("""

L'application `simple_switch_13` fait, par logiciel, ce que fait un switch Ethernet :

1. à la connexion d'un switch (FEATURES_REPLY), elle installe l'entrée **table-miss** : priorité 0,
   aucun champ, action `output:CONTROLLER` ;
2. un paquet inconnu arrive au contrôleur dans un **PACKET_IN** ; l'application apprend
   « adresse MAC source → port d'entrée » pour ce switch ;
3. si l'adresse MAC de destination est connue, elle installe par un **FLOW_MOD** une entrée de
   priorité 1 (`in_port`, `eth_src`, `eth_dst` → `output:port`, expiration après 300 s d'inactivité) :
   les paquets suivants ne passent plus par le contrôleur ;
4. elle renvoie le paquet lui-même par un **PACKET_OUT**, vers le port appris ou en `FLOOD`.

Le contrôleur voit donc passer le premier paquet de chaque conversation, puis plus rien.
""")
            + info_subtitle(tr("L'API REST de ofctl_rest"), level=2, tag="rest")
            + tr("""

| requête | effet |
|---------|-------|
| `GET /stats/switches` | les dpid des switchs connectés (en **décimal**) |
| `GET /stats/desc/<dpid>` | la description du switch |
| `GET /stats/portdesc/<dpid>` | ses ports : numéro OpenFlow (`port_no`), nom, adresse MAC, état |
| `GET /stats/flow/<dpid>` | ses entrées de flux, avec leurs compteurs |
| `POST /stats/flowentry/add` | ajouter une entrée (document JSON ci-dessous) |
| `POST /stats/flowentry/delete` / `delete_strict` | supprimer les entrées qui correspondent / exactement celle-ci |
| `DELETE /stats/flowentry/clear/<dpid>` | vider toutes les tables du switch |
| `POST /stats/meterentry/add` / `modify` / `delete` | les compteurs de débit |
| `GET /stats/meterconfig/<dpid>` | les compteurs de débit du switch |
| `GET /stats/errors/<dpid>` | (propre à ce TP) les derniers messages ERROR du switch |

Le **dpid s'écrit en décimal** dans l'URL et dans le champ `dpid` (le dpid `00000000000000a1` d'OVS est
`161`). Une entrée de flux en JSON utilise les noms d'OpenFlow 1.3 :

```
curl -X POST -d '{"dpid": 161, "priority": 100,
                  "match": {"in_port": 1, "eth_type": 2048, "ipv4_dst": "192.0.2.20"},
                  "actions": [{"type": "OUTPUT", "port": 2}]}' \\
     http://controller:8080/stats/flowentry/add
```

| champ JSON | sens |
|------------|------|
| `in_port`, `eth_src`, `eth_dst`, `eth_type` | port d'entrée, adresses MAC, type Ethernet (2048 = IPv4, 2054 = ARP) |
| `vlan_vid` | VLAN (un entier décimal : le bit « étiquette présente » est ajouté) |
| `ipv4_src`, `ipv4_dst`, `ip_proto` | adresses IPv4, protocole (1 ICMP, 6 TCP, 17 UDP) |
| `tcp_src`, `tcp_dst`, `udp_src`, `udp_dst` | ports |

| action JSON | effet |
|-------------|-------|
| `{"type": "OUTPUT", "port": 2}` | émettre (`"port": "NORMAL"`, `"CONTROLLER"`, `"FLOOD"`... aussi) |
| `{"type": "PUSH_VLAN", "ethertype": 33024}` | ajouter une étiquette 802.1Q (0x8100) |
| `{"type": "SET_FIELD", "field": "vlan_vid", "value": 4106}` | VLAN 10 (4096 + 10 : le bit « présent » à écrire soi-même ici) |
| `{"type": "POP_VLAN"}` | retirer l'étiquette |
| `{"type": "METER", "meter_id": 1}` | passer par le compteur de débit 1 |
| liste vide | jeter |

Un compteur de débit : `{"dpid": 161, "meter_id": 1, "flags": "KBPS", "bands": [{"type": "DROP",
"rate": 1000}]}` sur `/stats/meterentry/add` (1000 kbit/s).

**La requête réussit même si le switch refuse l'entrée** (un prérequis manquant : `ipv4_dst` sans
`eth_type`, `tcp_dst` sans `ip_proto`...) : l'erreur arrive plus tard, du switch, dans un message
ERROR. Vérifiez avec `GET /stats/flow/<dpid>` et `GET /stats/errors/<dpid>`.
""")
            + info_subtitle(tr("Au-delà d'OpenFlow"), tag="beyond")
            + tr("""

- **NETCONF / YANG** (RFC 6241, RFC 7950) : configurer et lire l'état des équipements classiques avec
  des modèles de données standard ; **RESTCONF** en est la version HTTP ; **gNMI** (gRPC) sert aussi à la
  télémétrie en continu (*streaming telemetry*).
- **P4** : un langage pour décrire le plan de données lui-même (quels en-têtes analyser, quelles
  tables) ; **P4Runtime** remplit ses tables. OpenFlow fixe les champs, P4 les laisse définir.
- **Réseaux de data centres et de cloud** : les mêmes idées, avec des tunnels VXLAN entre les
  hyperviseurs ; OpenStack Neutron programme les Open vSwitch des hyperviseurs avec OS-Ken.
- **Réseaux d'intention** (*intent-based networking*) : l'administrateur décrit le résultat voulu, le
  contrôleur en déduit les configurations et vérifie qu'il est atteint.
- **SD-WAN** : les principes du SDN (contrôle centralisé, politiques par application) appliqués aux
  liaisons entre les sites d'une entreprise.
""")
            + info_subtitle(tr("Dans ce TP"), tag="lab")
            + tr("""

- Les switchs sont des conteneurs où tournent `ovsdb-server` et `ovs-vswitchd` (démarrés pour vous).
  Leur datapath est le module `openvswitch` du noyau de la machine hôte, partagé par tous les switchs
  (`ovs-dpctl show` montre celui du conteneur). Ne relancez pas Open vSwitch : si c'est nécessaire,
  `/usr/share/openvswitch/scripts/ovs-ctl restart`.
- Les interfaces `ethN` d'un switch n'ont pas d'adresse IP : ce sont ses ports.
- Pour capturer OpenFlow : `tcpdump -n -i eth0 tcp port 6653`, ou décodé :
  `tshark -i eth0 -f "tcp port 6653" -O openflow_v4` (`-Y openflow_v4.type==10` pour ne garder que les
  PACKET_IN ; les types : 0 HELLO, 5 FEATURES_REQUEST, 6 FEATURES_REPLY, 10 PACKET_IN, 13 PACKET_OUT,
  14 FLOW_MOD).
- Un contrôleur lancé dans un terminal s'arrête avec ce terminal : lancez-le en arrière-plan
  (`setsid -f osken-manager ...`, ou `nohup ... &`).
""")
        )

    # -- helpers ---------------------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        lines = ["127.0.0.1\tlocalhost"]
        for name in HOSTS + ("ctl3", "sw3", "ctl4", "sw4a", "sw4b", "ops"):
            lines.append(f"{d.ip(name)}\t{name}")
        return "\n".join(lines) + "\n"

    def acl_flows(self) -> str:
        """The reference flow table of sw2 (ovs-ofctl syntax)."""
        d = self.data
        c, w, b, a = (d.ip(h) for h in P2_HOSTS)
        return (
            f"priority=500,arp,actions=NORMAL\n"
            f"priority=400,tcp,nw_src={c},nw_dst={w},tp_dst={WEB_PORT},actions=NORMAL\n"
            f"priority=400,tcp,nw_src={w},nw_dst={c},tp_src={WEB_PORT},actions=NORMAL\n"
            f"priority=400,tcp,nw_src={w},nw_dst={b},tp_dst={DB_PORT},actions=NORMAL\n"
            f"priority=400,tcp,nw_src={b},nw_dst={w},tp_src={DB_PORT},actions=NORMAL\n"
            f"priority=400,tcp,nw_src={a},tp_dst={SSH_PORT},actions=NORMAL\n"
            f"priority=400,tcp,nw_dst={a},tp_src={SSH_PORT},actions=NORMAL\n"
            f"priority=400,icmp,nw_src={a},icmp_type=8,actions=NORMAL\n"
            f"priority=400,icmp,nw_dst={a},icmp_type=0,actions=NORMAL\n"
            f"priority=0,actions=drop\n")

    def tenant_flows(self) -> list:
        """The reference flows of part 4 (REST documents): each host's frames go to the trunk;
        what comes from the trunk is delivered by source MAC to the host of the same tenant."""
        d = self.data
        flows = []
        for dpid, local, remote, ofport in ((d.dpid4a, ("red1", "blue1"), ("red2", "blue2"), d.ofport4a),
                                           (d.dpid4b, ("red2", "blue2"), ("red1", "blue1"), d.ofport4b)):
            for here, there in zip(local, remote):
                flows.append({"dpid": dpid, "priority": 100, "match": {"in_port": ofport(here)},
                              "actions": [{"type": "OUTPUT", "port": ofport("trunk")}]})
                flows.append({"dpid": dpid, "priority": 100,
                              "match": {"in_port": ofport("trunk"), "eth_src": d.mac(there)},
                              "actions": [{"type": "OUTPUT", "port": ofport(here)}]})
        return flows

    def meter_doc(self) -> dict:
        d = self.data
        return {"dpid": d.dpid4a, "meter_id": METER_ID, "flags": "KBPS",
                "bands": [{"type": "DROP", "rate": d.meter_rate}]}

    def guest_flows(self) -> list:
        d = self.data
        return [
            {"dpid": d.dpid4a, "priority": 100, "match": {"in_port": d.ofport4a("guest4")},
             "actions": [{"type": "METER", "meter_id": METER_ID}, {"type": "OUTPUT", "port": d.ofport4a("srv4")}]},
            {"dpid": d.dpid4a, "priority": 100, "match": {"in_port": d.ofport4a("srv4")},
             "actions": [{"type": "OUTPUT", "port": d.ofport4a("guest4")}]},
        ]

    # -- states --------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self._machine_specs:
            self.file(m, "/etc/hosts", self.hosts_content())
            self.file(m, "/etc/resolv.conf", "")
        # Open vSwitch on every switch; sw1 gets no bridge (part 1 creates it)
        for sw in SWITCHES:
            self.cmd(sw, ovs_start_cmd(), timeout=60)
        # sw2: a secure bridge without controller nor flow: nothing passes
        ports2 = sorted(d.ofports2.items(), key=lambda item: item[1])
        self.cmd("sw2", ovs_bridge_cmd(BRIDGE, ports2, fail_mode="secure"))
        # sw3: a standalone bridge (a classic switch until part 3), its datapath ID fixed
        self.cmd("sw3", ovs_bridge_cmd(BRIDGE, [(SW3_PORTS["h31"], None), (SW3_PORTS["h32"], None)],
                                       protocols=None, dpid=d.dpid3))
        # ctl4: the REST API, then sw4a / sw4b connected to it, secure, without any flow
        self.cmd("ctl4", osken_start_cmd(["os_ken.app.ofctl_rest"]), timeout=30)
        controller = f"tcp:{d.ip('ctl4')}:{OPENFLOW_PORT}"
        for sw, dpid, ofports in (("sw4a", d.dpid4a, d.ofports4a), ("sw4b", d.dpid4b, d.ofports4b)):
            ports = sorted(ofports.items(), key=lambda item: item[1])
            self.cmd(sw, ovs_bridge_cmd(BRIDGE, ports, fail_mode="secure", dpid=dpid, controller=controller),
                     step=2)
        # the services of part 2 (HTTP echo servers) and of the bonus (iperf3)
        install_echo_server(self, "client2", ports=(SSH_PORT,))
        install_echo_server(self, "web2", ports=(WEB_PORT, SSH_PORT))
        install_echo_server(self, "db2", ports=(DB_PORT, SSH_PORT))
        install_echo_server(self, "admin2", ports=(SSH_PORT,))
        self.cmd("srv4", "iperf3 -s -D")

    # The solve helpers can be applied again.
    def _solve_part1(self):
        d = self.data
        ports = [(SW1_PORTS[h], None) for h in P1_HOSTS]
        tags = {SW1_PORTS["h11"]: d.vlan_a, SW1_PORTS["h12"]: d.vlan_a, SW1_PORTS["h13"]: d.vlan_b}
        self.cmd("sw1", ovs_bridge_cmd(BRIDGE, ports, protocols=None, dpid=d.dpid1, tags=tags))

    def _solve_part2(self):
        self.file("sw2", ACL_FILE, self.acl_flows())
        self.cmd("sw2", f"ovs-ofctl -O OpenFlow13 replace-flows {BRIDGE} {ACL_FILE}")

    def _solve_part3(self):
        d = self.data
        self.cmd("ctl3", osken_start_cmd(["os_ken.app.simple_switch_13"]), timeout=30)
        self.cmd("sw3", f"ovs-vsctl set bridge {BRIDGE} protocols=OpenFlow13 fail-mode=secure -- "
                        f"set-controller {BRIDGE} tcp:{d.ip('ctl3')}:{OPENFLOW_PORT}", step=2)
        self.cmd("sw3", "for i in $(seq 50); do ovs-vsctl --columns=is_connected list controller | grep -q true "
                        "&& break; sleep 0.2; done", step=2, timeout=30)

    def _solve_part4(self):
        d = self.data
        self.cmd("ops", "; ".join(rest_cmd(d.ip("ctl4"), "flowentry/add", f) for f in self.tenant_flows()),
                 timeout=60)

    def _solve_bonus(self):
        d = self.data
        ctl = d.ip("ctl4")
        meter = self.meter_doc()
        # add, or modify when it is already there (a second application of the state)
        self.cmd("ops", f"{rest_cmd(ctl, 'meterentry/add', meter)}; sleep 0.5; "
                        f"{rest_cmd(ctl, 'meterentry/modify', meter)}", timeout=30)
        self.cmd("ops", "; ".join(rest_cmd(ctl, "flowentry/add", f) for f in self.guest_flows()), timeout=30)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (le pont de sw1 et ses VLAN)"))
    def solve_part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (la table de flux de sw2)"))
    def solve_part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (contrôleur réactif sur ctl3, sw3 relié)"))
    def solve_part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (les flux des deux locataires par l'API REST)"))
    def solve_part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False, description=tr("Bonus : solution (compteur de débit de guest4)"))
    def solve_bonus(self):
        self._solve_bonus()

    @sre_state(user_allowed=False,
               description=tr("Solution de référence : toutes les parties et le bonus, formulaires remplis.",
                              en="Reference solution: every part and the bonus, forms filled."))
    def final(self):
        """Reference solution of every part, bonus included; the forms are filled through
        cheat_answers."""
        self._solve_part1()
        self._solve_part2()
        self._solve_part3()
        self._solve_part4()
        self._solve_bonus()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _int_answer(s):
    text = str(s or "").strip()
    return int(text) if text.isdigit() else None


def _served(echo: dict, name: str) -> bool:
    return echo.get("server") == name


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme=net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        d = self.get_data()
        ip, mac = d.ip, d.mac

        # ---------------------------------------------------------------------
        # tests (every one registered unconditionally)
        # ---------------------------------------------------------------------
        # part 1
        st1 = get_ovs_state(self, "sw1")
        ping_h11_h12 = eval_ping(self, "h11", ip("h12"), count=2, deadline=3, allow_error=True)
        ping_h11_h13 = eval_ping(self, "h11", ip("h13"), count=1, deadline=2, allow_error=True)
        ping_h12_h13 = eval_ping(self, "h12", ip("h13"), count=1, deadline=2, allow_error=True)
        # part 2: real traffic for what must pass, traces on sw2 for what must not
        st2 = get_ovs_state(self, "sw2")
        web_from_client = get_http_echo(self, "client2", ip("web2"), WEB_PORT, timeout=4)
        db_from_web = get_http_echo(self, "web2", ip("db2"), DB_PORT, timeout=4)
        ssh_from_admin = {h: get_http_echo(self, "admin2", ip(h), SSH_PORT, timeout=4)
                          for h in ("client2", "web2", "db2")}
        ping_admin_web = eval_ping(self, "admin2", ip("web2"), count=2, deadline=3, allow_error=True)

        def trace2(src, dst, proto, dport=None):
            flow = trace_flow(in_port=d.ofport2(src), proto=proto, eth_src=mac(src), eth_dst=mac(dst),
                              ip_src=ip(src), ip_dst=ip(dst), dport=dport)
            return get_trace(self, "sw2", BRIDGE, flow)

        t_client_web_ssh = trace2("client2", "web2", "tcp", SSH_PORT)
        t_client_db = trace2("client2", "db2", "tcp", DB_PORT)
        t_db_web = trace2("db2", "web2", "tcp", WEB_PORT)
        t_client_web_ping = trace2("client2", "web2", "icmp")
        t_web_client_ssh = trace2("web2", "client2", "tcp", SSH_PORT)
        t_client_web_udp = trace2("client2", "web2", "udp", 9999)
        # part 3: traffic first, then the switch
        ping_h31_h32 = eval_ping(self, "h31", ip("h32"), count=3, deadline=4, allow_error=True)
        st3 = get_ovs_state(self, "sw3", step=2)
        flows3 = get_flows(self, "sw3", BRIDGE, step=2)
        # part 4
        ping_red = eval_ping(self, "red1", ip("red2"), count=2, deadline=3, allow_error=True)
        ping_red_blue1 = eval_ping(self, "red1", ip("blue1"), count=1, deadline=2, allow_error=True)
        ping_red_blue2 = eval_ping(self, "red1", ip("blue2"), count=1, deadline=2, allow_error=True)
        ping_blue = eval_ping(self, "blue1", ip("blue2"), count=2, deadline=3, allow_error=True)
        ping_blue_red1 = eval_ping(self, "blue2", ip("red1"), count=1, deadline=2, allow_error=True)
        ping_blue_red2 = eval_ping(self, "blue2", ip("red2"), count=1, deadline=2, allow_error=True)
        flows4a = get_flows(self, "sw4a", BRIDGE)
        flows4b = get_flows(self, "sw4b", BRIDGE)
        # bonus
        meters4a = get_meters(self, "sw4a", BRIDGE)
        iperf_out, _ = self.test("guest4", f"timeout {IPERF_SECONDS + 8} iperf3 -c {ip('srv4')} -u "
                                           f"-b {IPERF_FACTOR * d.meter_rate}k -t {IPERF_SECONDS} -J --connect-timeout 3000",
                                 timeout=IPERF_SECONDS + 12, allow_error=True)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="ad20192ef835c8ee",
            description=tr("""
Lisez l'onglet **Informations** : il présente le SDN, OpenFlow, Open vSwitch et les contrôleurs. Le TP a
quatre parties indépendantes, chacune sur son propre site ; un bonus termine la quatrième.

**Les sites et les machines** (tous les noms sont dans `/etc/hosts` ; les ports des switchs n'ont pas
d'adresse IP).

| partie | switch(s) | machines (adresse, adresse MAC) |
|--------|-----------|---------------------------------|
| 1 | `sw1` : Open vSwitch démarré, aucun pont | `h11` {h11} {m_h11} (sur `eth0` de `sw1`) ; `h12` {h12} {m_h12} (`eth1`) ; `h13` {h13} {m_h13} (`eth2`) |
| 2 | `sw2` : pont `br0`, mode `secure`, sans contrôleur, table vide | `client2` {client2} {m_client2} (`eth0`) ; `web2` {web2} {m_web2} (`eth1`) ; `db2` {db2} {m_db2} (`eth2`) ; `admin2` {admin2} {m_admin2} (`eth3`) |
| 3 | `sw3` : pont `br0` en mode `standalone` ; réseau de contrôle `ctrl3` ({ctrl3}) : `sw3` {sw3}, contrôleur `ctl3` {ctl3} | `h31` {h31} (`eth1` de `sw3`) ; `h32` {h32} (`eth2`) |
| 4 | `sw4a`, `sw4b` : ponts `br0` en mode `secure`, reliés au contrôleur `ctl4` ; pas de terminal | `red1` {red1} {m_red1} et `blue1` {blue1} {m_blue1} sur `sw4a` ; `red2` {red2} {m_red2} et `blue2` {blue2} {m_blue2} sur `sw4b` ; `sw4a` et `sw4b` reliés par `trunk` |
| 4 | réseau de contrôle `ctrl4` ({ctrl4}) | `ctl4` {ctl4} (OS-Ken avec `ofctl_rest`, port {rest}, pas de terminal) ; `ops` {ops}, votre poste d'administration (`curl`, `jq`) |
| bonus | `sw4a` | `guest4` {guest4} et `srv4` {srv4} (serveur iperf3) |

Les machines d'une partie sont sur le même réseau IP : elles se joignent directement, à travers le
switch.

Le travail et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation) :
l'évaluation lit la configuration et les tables des switchs, fait passer du trafic entre les machines
(ping, requêtes TCP, iperf3) et simule sur `sw2` les paquets que la partie 2 doit refuser
(`ovs-appctl ofproto/trace`).
""").format(h11=ip("h11"), h12=ip("h12"), h13=ip("h13"), m_h11=mac("h11"), m_h12=mac("h12"), m_h13=mac("h13"),
            client2=ip("client2"), web2=ip("web2"), db2=ip("db2"), admin2=ip("admin2"),
            m_client2=mac("client2"), m_web2=mac("web2"), m_db2=mac("db2"), m_admin2=mac("admin2"),
            ctrl3=d.nets.ctrl3, sw3=ip("sw3"), ctl3=ip("ctl3"), h31=ip("h31"), h32=ip("h32"),
            red1=ip("red1"), blue1=ip("blue1"), red2=ip("red2"), blue2=ip("blue2"),
            m_red1=mac("red1"), m_blue1=mac("blue1"), m_red2=mac("red2"), m_blue2=mac("blue2"),
            ctrl4=d.nets.ctrl4, ctl4=ip("ctl4"), rest=REST_PORT, ops=ip("ops"), guest4=ip("guest4"),
            srv4=ip("srv4"))
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part4` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes ; ils remplissent les formulaires.

- `sw2` : numéros OpenFlow {ofports2} ; `sw4a` (dpid {dpid4a}) : {ofports4a} ; `sw4b` (dpid {dpid4b}) :
  {ofports4b}.
- L'évaluation, en deux étapes : `ovs-vsctl list` et `ovs-ofctl dump-flows` / `dump-meters` sur les
  switchs ; ping entre les machines des parties 1, 3, 4 ; requêtes HTTP vers les serveurs d'écho de la
  partie 2 (ports {web}, {db}, {ssh}) ; six `ofproto/trace` sur `sw2` ; iperf3 UDP de `guest4` vers
  `srv4` à {sent} kbit/s.
""").format(ofports2=", ".join(f"`{i}` = {p}" for i, p in sorted(d.ofports2.items())),
            dpid4a=d.dpid4a, ofports4a=", ".join(f"`{i}` = {p}" for i, p in sorted(d.ofports4a.items())),
            dpid4b=d.dpid4b, ofports4b=", ".join(f"`{i}` = {p}" for i, p in sorted(d.ofports4b.items())),
            web=WEB_PORT, db=DB_PORT, ssh=SSH_PORT, sent=IPERF_FACTOR * d.meter_rate)
            ),
        )

        # =====================================================================
        # Partie 1 — un premier pont Open vSwitch
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Un premier pont Open vSwitch"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Créer un pont, ses ports et ses VLAN"),
            hash="5962e5c56acfa9c0",
            description=tr("""
Sections @@ref:ovsarch@@ et @@ref:ovstools@@. Sur `sw1`, Open vSwitch tourne mais n'a aucun pont.

1. Regardez les démons qui tournent (`ps ax | grep ovs`) et la configuration vide (`ovs-vsctl show`).
2. Créez le pont `br0` et ajoutez-lui les trois interfaces `eth0`, `eth1`, `eth2` de `sw1`.
3. Mettez `h11` et `h12` dans le VLAN **{vlan_a}**, `h13` dans le VLAN **{vlan_b}** (ports d'accès).
   `h11` et `h12` doivent se joindre ; `h13` ne doit joindre ni l'un ni l'autre, bien qu'il soit dans
   le même réseau IP.
4. Regardez la table de flux du pont (`ovs-ofctl -O OpenFlow13 dump-flows br0`) et son identifiant
   (`ovs-ofctl -O OpenFlow13 show br0`).
""").format(vlan_a=d.vlan_a, vlan_b=d.vlan_b)
            + instructor(
                tr("""
**Solution.**

```
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 tag={vlan_a}
ovs-vsctl add-port br0 eth1 tag={vlan_a}
ovs-vsctl add-port br0 eth2 tag={vlan_b}
```

La table contient une seule entrée, `priority=0 actions=NORMAL` (pont `standalone` sans contrôleur).
""").format(vlan_a=d.vlan_a, vlan_b=d.vlan_b)
            ),
        )
        bridge1 = st1.bridge_of(SW1_PORTS["h11"])
        sw1_ports = set(SW1_PORTS.values())
        has_ports = bridge1 is not None and all(st1.bridge_of(i) is bridge1 for i in sw1_ports)
        self.add_grade_element(title=no_tr("sw1_bridge"), max_grade=2, grade_part=part1, grade=2 * int(has_ports),
                               description=tr("un pont de sw1 a les trois ports eth0, eth1, eth2"))
        tags_ok = has_ports and all(
            (st1.port_of(SW1_PORTS[h]).tag if st1.port_of(SW1_PORTS[h]) else None) == vlan
            for h, vlan in (("h11", d.vlan_a), ("h12", d.vlan_a), ("h13", d.vlan_b)))
        self.add_grade_element(title=no_tr("sw1_tags"), max_grade=2, grade_part=part1, grade=2 * int(tags_ok),
                               description=tr("les ports d'accès sont dans les bons VLAN"))
        isolated = ping_h11_h12 and not ping_h11_h13 and not ping_h12_h13
        self.add_grade_element(title=no_tr("sw1_vlans"), max_grade=4, grade_part=part1, grade=4 * int(isolated),
                               description=tr("h11 et h12 se joignent, h13 ne joint aucun des deux"))

        live_dpid = bridge1.dpid if bridge1 is not None else None
        q1_answers = {"dpid": f"{d.dpid1:016x}", "config": "ovsdb", "switching": "vswitchd", "action": "normal"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Les composants d'Open vSwitch"),
            hash="f128f7fee8875350",
            description=tr("""
Section @@ref:ovsarch@@ et @@ref:failmode@@.

- l'identifiant de datapath (dpid) de votre pont `br0` : @@{dpid:.+}@@
- le programme qui garde la configuration (ponts, ports, VLAN) : @@{config:>ovs-vswitchd>>>vswitchd|ovsdb-server>>>ovsdb|le module openvswitch du noyau>>>kernel|ovs-ofctl>>>ofctl}@@
- le programme qui parle OpenFlow et tient les tables de flux : @@{switching:>ovsdb-server>>>ovsdb|ovs-vswitchd>>>vswitchd|le module openvswitch du noyau>>>kernel|ovs-vsctl>>>vsctl}@@
- l'action de la seule entrée de la table d'un pont neuf sans contrôleur : @@{action:>drop>>>drop|CONTROLLER>>>controller|NORMAL>>>normal|FLOOD>>>flood}@@
""")
            + instructor(
                tr("""
**Réponses.** Le dpid lu sur le pont (ici `{dpid}` si le pont est celui de la solution ; l'évaluation
compare avec celui de votre pont) ; `ovsdb-server` ; `ovs-vswitchd` ; `NORMAL`.
""").format(dpid=f"{d.dpid1:016x}")
            ),
            cheat_answers={"final": q1_answers, "solve_part1": q1_answers},
        )
        answer_dpid = normalize_dpid(q1.get("dpid"))
        self.add_grade_element(title=no_tr("answer_dpid1"), max_grade=1, grade_part=part1,
                               grade=int(live_dpid is not None and answer_dpid == live_dpid),
                               description=tr("le dpid de br0"))
        for name, expected, text in (("config", "ovsdb", tr("le démon de configuration")),
                                     ("switching", "vswitchd", tr("le démon OpenFlow")),
                                     ("action", "normal", tr("l'action NORMAL"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part1,
                                   scope=CHOICE_SCOPE, grade=int(q1.get(name) == expected), description=text)

        # =====================================================================
        # Partie 2 — une liste d'accès écrite en OpenFlow
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Une liste d'accès en OpenFlow"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Écrire la table de flux de sw2"),
            hash="32a58a16b869d322",
            description=tr("""
Sections @@ref:flowtable@@, @@ref:ovsflows@@ et @@ref:failmode@@. Le pont `br0` de `sw2` est en mode
`secure`, sans contrôleur et sans aucune entrée : rien ne passe. Écrivez vous-même sa table avec
`ovs-ofctl -O OpenFlow13` pour appliquer cette politique :

| de | vers | autorisé |
|----|------|----------|
| toutes les machines | toutes les machines | ARP |
| `client2` | `web2` | TCP {web} (le site web) |
| `web2` | `db2` | TCP {db} (la base de données) |
| `admin2` | toutes les machines | TCP {ssh} (SSH) et ping (demande d'écho) |

Tout le reste est jeté, y compris les réponses aux requêtes qui ne sont pas autorisées. Les serveurs
écoutent déjà (un serveur d'écho HTTP : `curl http://web2:{web}/` répond qui il est et qui vous êtes).

1. Trouvez le numéro OpenFlow de chaque port (`ovs-ofctl -O OpenFlow13 show br0`) : ce ne sont pas
   1, 2, 3, 4.
2. Écrivez les entrées (un fichier et `ovs-ofctl -O OpenFlow13 add-flows br0 fichier` est plus
   commode), sans oublier les réponses.
3. Vérifiez avec du vrai trafic et avec `ovs-appctl ofproto/trace`, et regardez les compteurs des
   entrées (`dump-flows`).
""").format(web=WEB_PORT, db=DB_PORT, ssh=SSH_PORT)
            + instructor(
                tr("""
**Solution.** `/root/acl.flows`, puis `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/acl.flows` :

```
{flows}```

(`actions=NORMAL` laisse OVS trouver le port ; des `output:N` avec les numéros {ofports} conviennent
aussi.)
""").format(flows=self.net_scheme.acl_flows(),
            ofports=", ".join(f"{h} = {d.ofport2(h)}" for h in P2_HOSTS))
            ),
        )
        web_ok = _served(web_from_client, "web2")
        self.add_grade_element(title=no_tr("acl_web"), max_grade=4, grade_part=part2,
                               grade=4 * int(web_ok and t_client_web_ssh.dropped),
                               description=tr("client2 atteint le site web de web2, pas son SSH"))
        db_ok = _served(db_from_web, "db2")
        self.add_grade_element(title=no_tr("acl_db"), max_grade=4, grade_part=part2,
                               grade=4 * int(db_ok and t_client_db.dropped and t_db_web.dropped),
                               description=tr("web2 atteint la base de db2 ; client2 ne l'atteint pas"))
        admin_ok = all(_served(ssh_from_admin[h], h) for h in ssh_from_admin) and ping_admin_web
        self.add_grade_element(title=no_tr("acl_admin"), max_grade=4, grade_part=part2,
                               grade=4 * int(admin_ok and t_client_web_ping.dropped and t_web_client_ssh.dropped),
                               description=tr("admin2 atteint le SSH de tous et les pingue ; les autres non"))
        bridge2 = st2.bridge(BRIDGE)
        still_secure = bridge2 is not None and bridge2.fail_mode == "secure" and not bridge2.controllers
        self.add_grade_element(title=no_tr("acl_default"), max_grade=2, grade_part=part2,
                               grade=2 * int(web_ok and still_secure and t_client_web_udp.dropped),
                               description=tr("le reste est jeté, sw2 toujours en mode secure sans contrôleur"))

        q2_answers = {"ofport": str(d.ofport2("db2")), "priority": "32768", "tie": "undefined"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Numéros de port et priorités"),
            hash="025950e01b10b5dd",
            description=tr("""
Section @@ref:flowtable@@.

- le numéro OpenFlow du port de `sw2` relié à `db2` : @@{ofport:[0-9]+}@@
- la priorité d'une entrée écrite sans `priority=` : @@{priority:[0-9]+}@@
- deux entrées de même priorité correspondent à un paquet ; laquelle s'applique ? @@{tie:>la plus ancienne>>>oldest|la plus récente>>>newest|ce n'est pas défini : à éviter>>>undefined|les deux, l'une après l'autre>>>both}@@
""")
            + instructor(tr("**Réponses.** {ofport} ; 32768 ; ce n'est pas défini.").format(ofport=d.ofport2("db2"))),
            cheat_answers={"final": q2_answers, "solve_part2": q2_answers},
        )
        self.add_grade_element(title=no_tr("answer_ofport"), max_grade=1, grade_part=part2,
                               grade=int(_int_answer(q2.get("ofport")) == d.ofport2("db2")),
                               description=tr("le numéro OpenFlow du port de db2"))
        self.add_grade_element(title=no_tr("answer_priority"), max_grade=1, grade_part=part2,
                               grade=int(_int_answer(q2.get("priority")) == 32768),
                               description=tr("la priorité par défaut"))
        self.add_grade_element(title=no_tr("answer_tie"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                               grade=int(q2.get("tie") == "undefined"), description=tr("deux entrées de même priorité"))

        # =====================================================================
        # Partie 3 — un contrôleur réactif
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Un contrôleur réactif"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Confier sw3 au contrôleur ctl3"),
            hash="c0cb0d98d2e10141",
            description=tr("""
Sections @@ref:messages@@, @@ref:failmode@@ et @@ref:learning@@. Le pont `br0` de `sw3` se comporte pour
l'instant en switch classique (mode `standalone`, action `NORMAL`). Vous allez le confier au contrôleur
OS-Ken de `ctl3`, joint par le réseau de contrôle hors bande `ctrl3`.

1. Sur `ctl3`, lancez en arrière-plan le contrôleur avec l'application `os_ken.app.simple_switch_13`,
   son journal dans `/var/log/osken-manager.log`.
2. Sur `ctl3`, lancez une capture d'OpenFlow sur `eth0` (section @@ref:lab@@).
3. Sur `sw3` : OpenFlow 1.3 seulement, mode `secure`, contrôleur `tcp:{ctl3}:{port}`. Vérifiez avec
   `ovs-vsctl show` (`is_connected: true`).
4. Pinguez `h32` depuis `h31` ; suivez la capture, le journal du contrôleur et la table de `sw3`
   (`dump-flows`) : qui installe quelle entrée, et quand ?
5. Arrêtez le contrôleur un instant : un nouveau flux passe-t-il encore ? (Relancez-le ensuite.)
""").format(ctl3=ip("ctl3"), port=OPENFLOW_PORT)
            + instructor(
                tr("""
**Solution.**

```
# ctl3
setsid -f osken-manager --log-file /var/log/osken-manager.log os_ken.app.simple_switch_13
tshark -i eth0 -f "tcp port {port}" -O openflow_v4
# sw3
ovs-vsctl set bridge br0 protocols=OpenFlow13 fail-mode=secure
ovs-vsctl set-controller br0 tcp:{ctl3}:{port}
```

Après le ping : l'entrée table-miss `priority=0 actions=CONTROLLER:65535` (installée à la connexion),
et deux entrées `priority=1,in_port=...,dl_src=...,dl_dst=... actions=output:...` installées par des
FLOW_MOD après les premiers PACKET_IN. Contrôleur arrêté : les entrées apprises restent (jusqu'à 300 s
d'inactivité), mais un nouveau flux (une autre paire de machines, ou après expiration) est jeté.
""").format(ctl3=ip("ctl3"), port=OPENFLOW_PORT)
            ),
        )
        bridge3 = st3.bridge(BRIDGE)
        targets = {f"tcp:{host}:{OPENFLOW_PORT}" for host in (ip("ctl3"), "ctl3")} | {f"tcp:{ip('ctl3')}", "tcp:ctl3"}
        controller3 = next((c for c in bridge3.controllers if c.target in targets), None) if bridge3 else None
        connected = controller3 is not None and controller3.is_connected
        self.add_grade_element(title=no_tr("sw3_connected"), max_grade=3, grade_part=part3, grade=3 * int(connected),
                               description=tr("sw3 est connecté au contrôleur de ctl3"))
        secure3 = connected and bridge3.fail_mode == "secure"
        self.add_grade_element(title=no_tr("sw3_secure"), max_grade=2, grade_part=part3, grade=2 * int(secure3),
                               description=tr("sw3 est en mode secure"))
        miss = table_miss(flows3)
        miss_ok = connected and miss is not None and "CONTROLLER" in miss.outputs()
        self.add_grade_element(title=no_tr("sw3_table_miss"), max_grade=2, grade_part=part3, grade=2 * int(miss_ok),
                               description=tr("l'entrée table-miss envoie au contrôleur"))
        learned = [f for f in flows3 if f.priority >= 1 and "in_port" in f.match and "dl_dst" in f.match
                   and f.outputs() and "CONTROLLER" not in f.outputs()]
        self.add_grade_element(title=no_tr("sw3_learned"), max_grade=2, grade_part=part3,
                               grade=2 * int(connected and len(learned) >= 2),
                               description=tr("le contrôleur a installé des entrées apprises"))
        self.add_grade_element(title=no_tr("sw3_ping"), max_grade=2, grade_part=part3,
                               grade=2 * int(secure3 and ping_h31_h32),
                               description=tr("h31 et h32 se joignent à travers le contrôleur"))

        q3_answers = {"miss": "packet_in", "install": "flow_mod", "send": "packet_out",
                      "dpid": f"{d.dpid3:016x}", "loss": "known"}
        messages = ("HELLO>>>hello|PACKET_IN>>>packet_in|FLOW_MOD>>>flow_mod|PACKET_OUT>>>packet_out|"
                    "FEATURES_REPLY>>>features_reply")
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Ce que montre la capture"),
            hash="bc9368b74df430b5",
            description=tr("""
Sections @@ref:messages@@ et @@ref:failmode@@.

- le message par lequel `sw3` envoie au contrôleur un paquet qu'aucune entrée n'a pris : @@{{miss:>{messages}}}@@
- le message par lequel le contrôleur installe une entrée : @@{{install:>{messages}}}@@
- le message par lequel le contrôleur fait émettre un paquet : @@{{send:>{messages}}}@@
- le dpid que `sw3` annonce dans son FEATURES_REPLY (16 chiffres hexadécimaux) : @@{{dpid:.+}}@@
- contrôleur arrêté, `sw3` en mode `secure` : @@{{loss:>sw3 redevient un switch classique>>>standalone|les entrées déjà installées restent, aucun nouveau flux n'est appris>>>known|toutes les entrées sont effacées aussitôt>>>flush|sw3 diffuse tout sur tous ses ports>>>flood}}@@
""").format(messages=messages)
            + instructor(tr("**Réponses.** PACKET_IN ; FLOW_MOD ; PACKET_OUT ; `{dpid}` ; les entrées installées "
                            "restent, aucun nouveau flux.").format(dpid=f"{d.dpid3:016x}")),
            cheat_answers={"final": q3_answers, "solve_part3": q3_answers},
        )
        for name, expected, text in (("miss", "packet_in", tr("PACKET_IN")), ("install", "flow_mod", tr("FLOW_MOD")),
                                     ("send", "packet_out", tr("PACKET_OUT")),
                                     ("loss", "known", tr("le mode secure sans contrôleur"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                                   grade=int(q3.get(name) == expected), description=text)
        self.add_grade_element(title=no_tr("answer_dpid3"), max_grade=1, grade_part=part3,
                               grade=int(normalize_dpid(q3.get("dpid")) == d.dpid3),
                               description=tr("le dpid de sw3"))

        # =====================================================================
        # Partie 4 — l'API nord : deux locataires isolés
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — L'API nord : deux locataires"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Isoler deux locataires par l'API REST"),
            hash="80ee8b864ff2f1a4",
            description=tr("""
Section @@ref:rest@@. `sw4a` et `sw4b` sont en mode `secure`, connectés au contrôleur `ctl4` qui n'y a
installé aucune entrée : rien ne passe. Vous n'avez de terminal ni sur les switchs ni sur le
contrôleur : tout se fait depuis `ops`, par l'API REST de `ofctl_rest` (`http://ctl4:{rest}/stats/...`).

Deux locataires partagent le même réseau IP ({lan4}) : **rouge** (`red1` sur `sw4a`, `red2` sur `sw4b`)
et **bleu** (`blue1` sur `sw4a`, `blue2` sur `sw4b`). `red1` et `red2` doivent se joindre, `blue1` et
`blue2` aussi ; un rouge et un bleu ne doivent jamais se joindre (pas même l'ARP), ni sur le même
switch ni à travers le lien `trunk` (`eth1` des deux switchs).

1. Listez les switchs connectés (`curl -s http://ctl4:{rest}/stats/switches`), puis les ports de chacun
   (`/stats/portdesc/<dpid>`, avec `jq`) : quel numéro OpenFlow pour quelle interface ?
2. Choisissez une méthode : par adresses MAC sources (les adresses sont données dans la
   première question), ou en étiquetant le trafic de chaque locataire sur le trunk (un VLAN par
   locataire).
3. Poussez les entrées (`POST /stats/flowentry/add`), vérifiez-les (`/stats/flow/<dpid>`, `/stats/errors/<dpid>`)
   et testez.
""").format(rest=REST_PORT, lan4=d.nets.lan4)
            + instructor(
                tr("""
**Solution** (par adresses MAC : tout ce qu'émet un hôte part vers le trunk ; ce qui arrive du trunk
n'est remis qu'à l'hôte du même locataire, choisi par l'adresse MAC source). Depuis `ops` :

```
{cmds}
```

Variante par VLAN : sur chaque switch, `in_port=<hôte rouge>` → `PUSH_VLAN` + `SET_FIELD vlan_vid
4096+10` + `OUTPUT trunk`, et `in_port=trunk, vlan_vid=10` → `POP_VLAN` + `OUTPUT <hôte rouge>` ; idem
en VLAN 20 pour le bleu.
""").format(cmds="\n".join(rest_cmd("ctl4", "flowentry/add", f) for f in self.net_scheme.tenant_flows()))
            ),
        )
        red_ok = ping_red and not ping_red_blue1 and not ping_red_blue2
        self.add_grade_element(title=no_tr("tenant_red"), max_grade=5, grade_part=part4, grade=5 * int(red_ok),
                               description=tr("red1 joint red2, pas les bleus"))
        blue_ok = ping_blue and not ping_blue_red1 and not ping_blue_red2
        self.add_grade_element(title=no_tr("tenant_blue"), max_grade=5, grade_part=part4, grade=5 * int(blue_ok),
                               description=tr("blue1 joint blue2 ; blue2 ne joint pas les rouges"))
        flows_both = (any(f.priority > 0 for f in flows4a) and any(f.priority > 0 for f in flows4b)
                      and (red_ok or blue_ok))
        self.add_grade_element(title=no_tr("tenant_flows"), max_grade=2, grade_part=part4, grade=2 * int(flows_both),
                               description=tr("des entrées sur les deux switchs, un locataire au moins isolé"))

        q4_answers = {"dpid": str(d.dpid4b), "ofport": str(d.ofport4b("blue2"))}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Ce que dit l'API"),
            hash="69737438b3f55c64",
            description=tr("""
Section @@ref:rest@@.

- le dpid de `sw4b`, tel que l'API l'écrit (en décimal) : @@{dpid:[0-9]+}@@
- le numéro OpenFlow du port de `sw4b` relié à `blue2` : @@{ofport:[0-9]+}@@
""")
            + instructor(tr("**Réponses.** {dpid} (0x{hex:x}) ; {ofport}.").format(dpid=d.dpid4b, hex=d.dpid4b,
                                                                                ofport=d.ofport4b("blue2"))),
            cheat_answers={"final": q4_answers, "solve_part4": q4_answers},
        )
        self.add_grade_element(title=no_tr("answer_dpid4b"), max_grade=2, grade_part=part4,
                               grade=2 * int(normalize_decimal_dpid(q4.get("dpid")) == d.dpid4b),
                               description=tr("le dpid de sw4b en décimal"))
        self.add_grade_element(title=no_tr("answer_ofport4b"), max_grade=1, grade_part=part4,
                               grade=int(_int_answer(q4.get("ofport")) == d.ofport4b("blue2")),
                               description=tr("le numéro OpenFlow du port de blue2"))

        # =====================================================================
        # Bonus — un compteur de débit
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Limiter un invité"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un compteur de débit pour guest4"),
            hash="f535866d38d1856b",
            description=tr("""
Sections @@ref:groups@@ et @@ref:rest@@. Sur `sw4a`, `guest4` (port `eth4`) et `srv4` (port `eth5`) ne
se joignent pas encore. Par l'API REST :

1. créez sur `sw4a` le compteur de débit numéro {meter} qui jette ce qui dépasse **{rate} kbit/s** ;
2. installez les entrées qui relient `guest4` et `srv4`, en faisant passer par ce compteur ce
   qu'envoie `guest4` ;
3. mesurez : `iperf3 -c srv4 -u -b {sent}k` depuis `guest4`.
""").format(meter=METER_ID, rate=d.meter_rate, sent=IPERF_FACTOR * d.meter_rate)
            + instructor(
                tr("""
**Solution.** Depuis `ops` :

```
{meter}
{flows}
```

iperf3 envoie {sent} kbit/s, le serveur en reçoit à peu près {rate} : un peu plus en moyenne sur un test court,
car le compteur, sans `burst_size`, laisse passer d'abord une seconde de trafic d'avance.
""").format(meter=rest_cmd("ctl4", "meterentry/add", self.net_scheme.meter_doc()),
            flows="\n".join(rest_cmd("ctl4", "flowentry/add", f) for f in self.net_scheme.guest_flows()),
            sent=IPERF_FACTOR * d.meter_rate, rate=d.meter_rate)
            ),
        )
        good_meters = [m for m in meters4a.values() if "kbps" in m.flags
                       and any(b.get("type") == "drop" and b.get("rate") == d.meter_rate for b in m.bands)]
        self.add_grade_element(title=no_tr("bonus_meter"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(bool(good_meters)),
                               description=tr("un compteur de débit qui jette au-delà du débit demandé"))
        good_ids = {m.meter_id for m in good_meters}
        guest_port = str(d.ofport4a("guest4"))
        metered = any(f.match.get("in_port") == guest_port and set(f.meter_ids()) & good_ids and f.outputs()
                      for f in flows4a)
        self.add_grade_element(title=no_tr("bonus_flow"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(metered),
                               description=tr("ce qu'envoie guest4 passe par ce compteur"))
        measured = parse_iperf3(iperf_out)
        kbps = (measured["bps"] or 0) / 1000
        self.add_grade_element(title=no_tr("bonus_rate"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(metered and RATE_LOW * d.meter_rate <= kbps <= RATE_HIGH * d.meter_rate),
                               description=tr("le débit reçu par srv4 est limité au débit demandé"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part4` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes ; ils remplissent les formulaires.

- `sw2` : numéros OpenFlow {ofports2} ; `sw4a` (dpid {dpid4a}) : {ofports4a} ; `sw4b` (dpid {dpid4b}) :
  {ofports4b}.
- L'évaluation, en deux étapes : `ovs-vsctl list` et `ovs-ofctl dump-flows` / `dump-meters` sur les
  switchs ; ping entre les machines des parties 1, 3, 4 ; requêtes HTTP vers les serveurs d'écho de la
  partie 2 (ports {web}, {db}, {ssh}) ; six `ofproto/trace` sur `sw2` ; iperf3 UDP de `guest4` vers
  `srv4` à {sent} kbit/s.
""":
            """
**For the instructor.** Each question ends with its solution, computed for the values of this
project. The states `solve_part1` to `solve_part4` and `solve_bonus` apply the solution of one part,
`final` all of them; they fill the forms.

- `sw2`: OpenFlow port numbers {ofports2}; `sw4a` (dpid {dpid4a}): {ofports4a}; `sw4b` (dpid {dpid4b}):
  {ofports4b}.
- The evaluation, in two steps: `ovs-vsctl list` and `ovs-ofctl dump-flows` / `dump-meters` on the
  switches; ping between the machines of parts 1, 3, 4; HTTP requests to the echo servers of part 2
  (ports {web}, {db}, {ssh}); six `ofproto/trace` on `sw2`; iperf3 UDP from `guest4` to `srv4` at
  {sent} kbit/s.
""",
        """
**Solution.**

```
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 tag={vlan_a}
ovs-vsctl add-port br0 eth1 tag={vlan_a}
ovs-vsctl add-port br0 eth2 tag={vlan_b}
```

La table contient une seule entrée, `priority=0 actions=NORMAL` (pont `standalone` sans contrôleur).
""":
            """
**Solution.**

```
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 tag={vlan_a}
ovs-vsctl add-port br0 eth1 tag={vlan_a}
ovs-vsctl add-port br0 eth2 tag={vlan_b}
```

The table holds a single entry, `priority=0 actions=NORMAL` (a `standalone` bridge without controller).
""",
        """
**Réponses.** Le dpid lu sur le pont (ici `{dpid}` si le pont est celui de la solution ; l'évaluation
compare avec celui de votre pont) ; `ovsdb-server` ; `ovs-vswitchd` ; `NORMAL`.
""":
            """
**Answers.** The dpid read on the bridge (here `{dpid}` if the bridge is the one of the solution; the
evaluation compares with the dpid of your bridge); `ovsdb-server`; `ovs-vswitchd`; `NORMAL`.
""",
        """
**Solution.** `/root/acl.flows`, puis `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/acl.flows` :

```
{flows}```

(`actions=NORMAL` laisse OVS trouver le port ; des `output:N` avec les numéros {ofports} conviennent
aussi.)
""":
            """
**Solution.** `/root/acl.flows`, then `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/acl.flows`:

```
{flows}```

(`actions=NORMAL` lets OVS find the port; `output:N` actions with the numbers {ofports} do as
well.)
""",
        """**Réponses.** {ofport} ; 32768 ; ce n'est pas défini.""":
            """**Answers.** {ofport}; 32768; it is not defined.""",
        """
**Solution.**

```
# ctl3
setsid -f osken-manager --log-file /var/log/osken-manager.log os_ken.app.simple_switch_13
tshark -i eth0 -f "tcp port {port}" -O openflow_v4
# sw3
ovs-vsctl set bridge br0 protocols=OpenFlow13 fail-mode=secure
ovs-vsctl set-controller br0 tcp:{ctl3}:{port}
```

Après le ping : l'entrée table-miss `priority=0 actions=CONTROLLER:65535` (installée à la connexion),
et deux entrées `priority=1,in_port=...,dl_src=...,dl_dst=... actions=output:...` installées par des
FLOW_MOD après les premiers PACKET_IN. Contrôleur arrêté : les entrées apprises restent (jusqu'à 300 s
d'inactivité), mais un nouveau flux (une autre paire de machines, ou après expiration) est jeté.
""":
            """
**Solution.**

```
# ctl3
setsid -f osken-manager --log-file /var/log/osken-manager.log os_ken.app.simple_switch_13
tshark -i eth0 -f "tcp port {port}" -O openflow_v4
# sw3
ovs-vsctl set bridge br0 protocols=OpenFlow13 fail-mode=secure
ovs-vsctl set-controller br0 tcp:{ctl3}:{port}
```

After the ping: the table-miss entry `priority=0 actions=CONTROLLER:65535` (installed at the connection),
and two entries `priority=1,in_port=...,dl_src=...,dl_dst=... actions=output:...` installed by FLOW_MOD
messages after the first PACKET_IN. Controller stopped: the learned entries stay (until 300 s without
traffic), but a new flow (another pair of machines, or after the expiry) is dropped.
""",
        """**Réponses.** PACKET_IN ; FLOW_MOD ; PACKET_OUT ; `{dpid}` ; les entrées installées restent, aucun nouveau flux.""":
            """**Answers.** PACKET_IN; FLOW_MOD; PACKET_OUT; `{dpid}`; the installed entries stay, no new flow.""",
        """
**Solution** (par adresses MAC : tout ce qu'émet un hôte part vers le trunk ; ce qui arrive du trunk
n'est remis qu'à l'hôte du même locataire, choisi par l'adresse MAC source). Depuis `ops` :

```
{cmds}
```

Variante par VLAN : sur chaque switch, `in_port=<hôte rouge>` → `PUSH_VLAN` + `SET_FIELD vlan_vid
4096+10` + `OUTPUT trunk`, et `in_port=trunk, vlan_vid=10` → `POP_VLAN` + `OUTPUT <hôte rouge>` ; idem
en VLAN 20 pour le bleu.
""":
            """
**Solution** (by MAC addresses: everything a host sends goes to the trunk; what comes from the trunk
is delivered only to the host of the same tenant, chosen by the source MAC address). From `ops`:

```
{cmds}
```

VLAN variant: on each switch, `in_port=<red host>` → `PUSH_VLAN` + `SET_FIELD vlan_vid 4096+10` +
`OUTPUT trunk`, and `in_port=trunk, vlan_vid=10` → `POP_VLAN` + `OUTPUT <red host>`; the same with
VLAN 20 for blue.
""",
        """**Réponses.** {dpid} (0x{hex:x}) ; {ofport}.""":
            """**Answers.** {dpid} (0x{hex:x}); {ofport}.""",
        """
**Solution.** Depuis `ops` :

```
{meter}
{flows}
```

iperf3 envoie {sent} kbit/s, le serveur en reçoit à peu près {rate} : un peu plus en moyenne sur un test court,
car le compteur, sans `burst_size`, laisse passer d'abord une seconde de trafic d'avance.
""":
            """
**Solution.** From `ops`:

```
{meter}
{flows}
```

iperf3 sends {sent} kbit/s, the server receives about {rate}: a little more on average over a short
test, because the meter, without `burst_size`, first lets one second of traffic through ahead.
""",
    },
}
