"""Open vSwitch lab: the virtual switch of the hypervisors, without controller.

Five independent sites, one subject per part:

1. ``sw1a`` / ``sw1b``: access VLANs, an 802.1Q trunk limited to two VLANs, and internal ports of
   ``sw1a`` that route between the VLANs;
2. ``hv2`` → ``tor2`` (configured by the lab, no terminal): a bond of two links with LACP;
3. ``hv3a`` / ``hv3b`` behind the router ``core3``: two tenants in one subnet, red over VXLAN, blue
   over Geneve, local VLANs mapped to a VNI, the MTU of the underlay;
4. ``fw4``: a stateful firewall written in OpenFlow with the connection tracking of the kernel
   (``ct()``, ``ct_state``) in a two-table pipeline;
5. ``sw5``: a port mirror towards an IDS and the ingress policing of a guest; bonus: HTB queues and
   ``set_queue``.

Grading: ``ovs-vsctl list`` (OVSDB), ``ovs-appctl`` (``bond/show``, ``lacp/show``,
``ofproto/trace``, ``dpctl/dump-conntrack``), ``ovs-ofctl dump-flows`` on the switches, real
traffic between the hosts (ping, the HTTP echo server of ``lib/server_echo.py``, iperf3) and a
capture on the IDS.  The state ``final`` applies the reference solution (``solve_<part>`` one
part); every question ends with its solution, shown to the instructor only.

Image: ``sysreseval/netdev13`` (Open vSwitch 3.5) for the switches and hypervisors; base13 for the
hosts and the router.
"""

import random
from dataclasses import dataclass, field
from ipaddress import IPv4Network

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s, random_mac_address
from net_config import get_ip_addresses, set_net_config_entry
from ping import eval_ping
from sdn import (
    OVS_TABLES_FULL,
    capture_read_cmd,
    capture_start_cmd,
    count_icmp_echo,
    get_bond_show,
    get_conntrack,
    get_flows,
    get_lacp_show,
    get_ovs_state,
    get_trace,
    ovs_bond_cmd,
    ovs_bridge_cmd,
    ovs_internal_port_cmd,
    ovs_mirror_cmd,
    ovs_policing_cmd,
    ovs_qos_cmd,
    ovs_start_cmd,
    ovs_tunnel_cmd,
    trace_flow,
)
from server_echo_helpers import get_http_echo, install_echo_server
from tc import parse_iperf3
from vxlan import df_ping_cmd

default_language = "fr"
tr = make_tr(default_language)

title = tr("Open vSwitch : VLAN, agrégation, tunnels, pare-feu avec état et QoS",
           en="Open vSwitch: VLANs, bonding, tunnels, stateful firewall and QoS")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

#: netdev13 weighs 6 by default (FRR daemons running): no FRR runs here
OVS = {"image": sre_docker_image("netdev13"), "weight": 1}
BRIDGE = "br0"
BRIDGE3 = "br-int"
MAC_PREFIX = "02:4f:56"
# part 1
P1_HOSTS = ("user1a", "srv1a", "user1b", "srv1b")
TRUNK1 = "eth0"
GW_USERS, GW_SERVERS = "gw-users", "gw-servers"
# part 2
P2_HOSTS = ("vm2", "nas2")
BOND = "bond0"
BOND_MEMBERS = ("eth0", "eth1")
# part 3
P3_HOSTS = ("red3a", "blue3a", "red3b", "blue3b")
VXLAN_PORT, GENEVE_PORT = "vxlan-red", "geneve-blue"
UNDERLAY_MTU = 1600
CORE_MTU = 9000
# part 4
P4_HOSTS = ("client4", "web4")
SW4_PORTS = {"client4": "eth0", "web4": "eth1"}
WEB_PORT = 80
CLIENT_PORT = 8080
FW_FILE = "/root/fw.flows"
# part 5
P5_HOSTS = ("h5a", "h5b", "ids5", "guest5", "srv5")
SW5_PORTS = {"h5a": "eth0", "h5b": "eth1", "ids5": "eth2", "guest5": "eth3", "srv5": "eth4"}
MIRROR = "span"
IPERF_GUEST_PORT, IPERF_QUEUE_PORT = 5201, 5202
QOS_MAX_RATE = 30_000_000  # bit/s, the HTB root of srv5's port
QUEUE_ID = 1
IPERF_SECONDS = 3
# iperf3 sends three times the limit: without it the server receives everything; with it, about the limit
IPERF_FACTOR = 3
RATE_LOW, RATE_HIGH = 0.5, 1.5
DF_SIZE = 1472  # an IPv4 packet of 1500 bytes
SPAN_CAPTURE = "span"
MIN_MIRRORED = 4  # of the 8 ICMP packets of the ping h5b -> h5a
MIRROR_PINGS = 4
SYN_ACK = 0x012

HOSTS = P1_HOSTS + P2_HOSTS + P3_HOSTS + P4_HOSTS + P5_HOSTS
SWITCHES = ("sw1a", "sw1b", "hv2", "tor2", "hv3a", "hv3b", "fw4", "sw5")
CHOICE_SCOPE = params.EXO_EVAL_SCOPE  # a dropdown answer counts for the instructor only


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _not_round(low: int, high: int, step: int = 100):
    return [v for v in range(low, high) if v % step]


@dataclass(slots=True)
class Data(Data0):
    # part 1: the two VLANs
    vlan_users: int = 0
    vlan_servers: int = 0
    # part 2: the LACP system ID of tor2
    lacp_sysid: str = ""
    # part 3: the VNIs and the local VLANs of each hypervisor
    vni_red: int = 0
    vni_blue: int = 0
    tag_red_a: int = 0
    tag_blue_a: int = 0
    tag_red_b: int = 0
    tag_blue_b: int = 0
    # parts 4 and 5: the OpenFlow port numbers (interface -> ofport)
    ofports4: dict = field(default_factory=dict)
    ofports5: dict = field(default_factory=dict)
    # part 5 and bonus: the policing rate of guest5 and the rate of queue 1 (kbit/s)
    police_rate: int = 0
    queue_rate: int = 0

    @classmethod
    def generate(cls):
        data = cls()
        # VLAN IDs outside the course examples (10, 20, 30) and the round hundreds
        (data.vlan_users, data.vlan_servers, data.tag_red_a, data.tag_blue_a, data.tag_red_b,
         data.tag_blue_b) = random.sample(_not_round(101, 900), 6)
        data.lacp_sysid = str(random_mac_address(prefix="02:1a", n=1)[0]).replace("-", ":").lower()
        # VNIs outside the course examples (5000, 5001) and the round hundreds
        data.vni_red, data.vni_blue = random.sample(_not_round(1001, 99999), 2)
        data.ofports4 = dict(zip(SW4_PORTS.values(), random.sample(range(5, 49), len(SW4_PORTS))))
        data.ofports5 = dict(zip(SW5_PORTS.values(), random.sample(range(5, 49), len(SW5_PORTS))))
        # rates far below what a VDE link carries (~50 Mbit/s), never the course examples (1000, 5000)
        data.police_rate = random.choice([r for r in range(2000, 9501, 500) if r != 5000])
        data.queue_rate = random.choice([r for r in range(2000, 8001, 500) if r not in (5000, data.police_rate)])
        # addresses
        (data.nets.users1, data.nets.servers1, data.nets.lan2, data.nets.under3a, data.nets.under3b,
         data.nets.tenant3, data.nets.lan4, data.nets.lan5) = random_ipv4networks(
            masks=[24] * 8, from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")])
        data.ips.user1a, data.ips.user1b, data.ips.gw_users = random_ipv4s(data.nets.users1, 3)
        data.ips.srv1a, data.ips.srv1b, data.ips.gw_servers = random_ipv4s(data.nets.servers1, 3)
        data.ips.vm2, data.ips.nas2 = random_ipv4s(data.nets.lan2, 2)
        data.ips.hv3a, data.ips.core3_a = random_ipv4s(data.nets.under3a, 2)
        data.ips.hv3b, data.ips.core3_b = random_ipv4s(data.nets.under3b, 2)
        data.ips.red3a, data.ips.blue3a, data.ips.red3b, data.ips.blue3b = random_ipv4s(data.nets.tenant3, 4)
        data.ips.client4, data.ips.web4 = random_ipv4s(data.nets.lan4, 2)
        data.ips.h5a, data.ips.h5b, data.ips.ids5, data.ips.guest5, data.ips.srv5 = random_ipv4s(data.nets.lan5, 5)
        for host, mac in zip(HOSTS, random_mac_address(prefix=MAC_PREFIX, n=len(HOSTS))):
            setattr(data.macs, host, mac)
        return data

    # -- derived values ------------------------------------------------------------------------

    def ip(self, name: str) -> str:
        return str(getattr(self.ips, name).ip)

    def mac(self, name: str) -> str:
        return str(getattr(self.macs, name)).replace("-", ":").lower()

    def ofport4(self, host: str) -> int:
        return self.ofports4[SW4_PORTS[host]]

    def ofport5(self, host: str) -> int:
        return self.ofports5[SW5_PORTS[host]]

    def tags3(self, hv: str) -> dict:
        """The local VLAN of each tenant on the hypervisor *hv*."""
        if hv == "hv3a":
            return {"red": self.tag_red_a, "blue": self.tag_blue_a}
        return {"red": self.tag_red_b, "blue": self.tag_blue_b}


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------

_LINKS = {
    # network: {machine: interface}
    "trunk1": {"sw1a": 0, "sw1b": 0},
    "sw1a_user1a": {"sw1a": 1, "user1a": 0},
    "sw1a_srv1a": {"sw1a": 2, "srv1a": 0},
    "sw1b_user1b": {"sw1b": 1, "user1b": 0},
    "sw1b_srv1b": {"sw1b": 2, "srv1b": 0},
    "uplink2a": {"hv2": 0, "tor2": 0},
    "uplink2b": {"hv2": 1, "tor2": 1},
    "hv2_vm2": {"hv2": 2, "vm2": 0},
    "tor2_nas2": {"tor2": 2, "nas2": 0},
    "under3a": {"hv3a": 0, "core3": 0},
    "under3b": {"hv3b": 0, "core3": 1},
    "hv3a_red3a": {"hv3a": 1, "red3a": 0},
    "hv3a_blue3a": {"hv3a": 2, "blue3a": 0},
    "hv3b_red3b": {"hv3b": 1, "red3b": 0},
    "hv3b_blue3b": {"hv3b": 2, "blue3b": 0},
    "fw4_client4": {"fw4": 0, "client4": 0},
    "fw4_web4": {"fw4": 1, "web4": 0},
    "sw5_h5a": {"sw5": 0, "h5a": 0},
    "sw5_h5b": {"sw5": 1, "h5b": 0},
    "sw5_ids5": {"sw5": 2, "ids5": 0},
    "sw5_guest5": {"sw5": 3, "guest5": 0},
    "sw5_srv5": {"sw5": 4, "srv5": 0},
}

_TENANT_COLORS = {"red3a": "lightcoral", "red3b": "lightcoral", "blue3a": "lightskyblue", "blue3b": "lightskyblue"}


class NetScheme(NetScheme0):
    _machine_specs = {
        **{sw: {**OVS, "color": "lightblue"} for sw in SWITCHES},
        "tor2": {**OVS, "color": "lightblue", "allow_connection": False},
        "core3": {"color": "orange"},
        **{h: {"color": _TENANT_COLORS.get(h, "lightgreen")} for h in HOSTS},
        "ids5": {"color": "khaki"},
    }
    _network_specs = {net: {"color": "orange" if net.startswith("under") else "lightgrey"} for net in _LINKS}

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
        default = IPv4Network("0.0.0.0/0")
        self.net_config = {}
        for host in P1_HOSTS:
            gw = d.ips.gw_users if host.startswith("user") else d.ips.gw_servers
            self.net_config[host] = [([getattr(d.ips, host)], [(default, gw)])]
        for host in P2_HOSTS + P3_HOSTS + P4_HOSTS + P5_HOSTS:
            self.net_config[host] = [([getattr(d.ips, host)], [])]
        self.net_config["hv3a"] = [([d.ips.hv3a], [(d.nets.under3b, d.ips.core3_a)])]
        self.net_config["hv3b"] = [([d.ips.hv3b], [(d.nets.under3a, d.ips.core3_b)])]
        self.net_config["core3"] = [([d.ips.core3_a], []), ([d.ips.core3_b], [])]

        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Un switch dans chaque hyperviseur"), tag="why")
            + tr("""

Les machines virtuelles d'un hyperviseur (KVM, Xen) et les conteneurs d'un hôte ont besoin d'un réseau :
leurs interfaces virtuelles (`tap`, `veth`) doivent être reliées entre elles et au réseau physique.
Le pont Linux (`bridge`) fait un switch simple ; **Open vSwitch** (OVS) est un switch logiciel complet :

- des **VLAN** 802.1Q, des **agrégats** de liens avec LACP, des **tunnels** (VXLAN, Geneve, GRE) qui
  relient les hyperviseurs à travers un réseau IP ;
- une table de flux **OpenFlow** programmable, du filtrage **avec état** (suivi de connexions du noyau),
  des **miroirs** de ports, de la **qualité de service** ;
- une base de configuration (**OVSDB**) que l'on modifie par des transactions, en local ou à distance.

On le trouve dans les hyperviseurs (libvirt, Proxmox, XenServer), dans OpenStack (Neutron), dans
Kubernetes (OVN-Kubernetes, Antrea) et dans les cartes réseau programmables (*SmartNIC*). Un contrôleur
peut le piloter (SDN), mais il fonctionne très bien seul, en switch classique enrichi : c'est le cas de
ce TP.
""")
            + info_subtitle(tr("L'architecture d'Open vSwitch"), tag="arch")
            + info_subtitle(tr("Les composants"), level=2, tag="components")
            + tr("""

| composant | rôle |
|-----------|------|
| `ovsdb-server` | la base de configuration (`/etc/openvswitch/conf.db`) ; protocole OVSDB (RFC 7047) |
| `ovs-vswitchd` | le démon qui fait le switch : il lit la base, tient les tables de flux, apprend les adresses MAC, négocie LACP, parle OpenFlow |
| le **datapath** | le module `openvswitch` du noyau : le chemin rapide. Il garde un cache des décisions (*megaflows*) et remonte à `ovs-vswitchd` le premier paquet de chaque nouvelle combinaison (*upcall*) |

Un **pont** (*bridge*) est un switch indépendant. Il a toujours un port interne qui porte son nom
(le port `LOCAL` d'OpenFlow). Tous les ponts d'une machine partagent un seul datapath du noyau,
`ovs-system`.
""")
            + info_subtitle(tr("La base OVSDB"), level=2, tag="ovsdb")
            + tr("""

La configuration est faite de **tables** liées entre elles :

```
Open_vSwitch ── Bridge ──┬── Port ── Interface
                         ├── Mirror
                         └── Controller
                Port ── QoS ── Queue
```

- un **port** est ce que voit la logique du switch (VLAN, agrégat, QoS) ; une **interface** est un
  périphérique réseau (type, options, numéro OpenFlow `ofport`). Un port ordinaire a une interface, un
  **agrégat** (*bond*) est un port à plusieurs interfaces ;
- `ovs-vsctl` modifie la base par **transactions** : plusieurs commandes séparées par `--` s'appliquent
  ensemble ou pas du tout ; `--id=@nom` nomme une ligne créée dans la transaction pour la référencer plus
  loin.

| commande | effet |
|----------|-------|
| `ovs-vsctl show` | vue d'ensemble |
| `ovs-vsctl list port eth1` | toutes les colonnes d'une ligne (ici, de la table Port) |
| `ovs-vsctl find interface type=vxlan` | les lignes qui vérifient une condition |
| `ovs-vsctl set port eth1 tag=10` | écrire une colonne ; `other_config:clé=valeur` pour une colonne de type dictionnaire |
| `ovs-vsctl clear port eth1 trunks` / `remove port eth1 trunks 20` | vider une colonne, retirer une valeur |
| `ovs-vsctl get interface eth1 ofport` | lire une colonne |
""")
            + info_subtitle(tr("Les types de ports"), level=2, tag="porttypes")
            + tr("""

| type d'interface | usage |
|------------------|-------|
| (vide) `system` | une interface existante de la machine (`eth1`, un `tap` de machine virtuelle) |
| `internal` | une interface créée par OVS dans la pile réseau de la machine : elle peut porter une adresse IP |
| `patch` | un lien entre deux ponts de la même machine (`options:peer=...`) |
| `vxlan`, `geneve`, `gre` | un tunnel vers une autre machine (`options:remote_ip=...`) |
""")
            + info_subtitle(tr("Les VLAN"), tag="vlan")
            + tr("""

Les colonnes `tag`, `trunks` et `vlan_mode` d'un port :

| configuration | comportement |
|---------------|--------------|
| `tag=10` | port d'**accès** du VLAN 10 : trames non étiquetées, rangées dans le VLAN 10 |
| ni `tag` ni `trunks` | **trunk de tous les VLAN** (trames étiquetées ; les trames non étiquetées sont dans le VLAN 0) |
| `trunks=10,20` | trunk limité à ces VLAN : les autres sont jetés à l'entrée et jamais émis |
| `tag=10 trunks=20,30 vlan_mode=native-untagged` | trunk des VLAN 20 et 30, le VLAN 10 circule **sans étiquette** (VLAN natif) |
| `vlan_mode=native-tagged` | idem, mais le VLAN natif est émis étiqueté |

`vlan_mode` vaut `access`, `trunk`, `native-tagged` ou `native-untagged`. Sans `vlan_mode`, un port qui
a un `tag` est un port d'accès, et son `trunks` est ignoré (avec un avertissement dans le journal
d'`ovs-vswitchd`).

```
ovs-vsctl add-port br0 eth1 tag=10                          # accès
ovs-vsctl add-port br0 eth0 trunks=10,20                    # trunk limité
ovs-vsctl set port eth0 trunks=10,20,30                     # modifier
```

**Router entre les VLAN.** Un port `internal` étiqueté donne à la machine une interface dans ce VLAN ;
avec une adresse IP sur chacune et le routage activé, la machine route entre les VLAN (un *router on a
stick* intégré au switch) :

```
ovs-vsctl add-port br0 vlan10 tag=10 -- set interface vlan10 type=internal
ip addr add 192.0.2.1/24 dev vlan10 ; ip link set vlan10 up
```

(Un **faux pont** fait la même chose : `ovs-vsctl add-br br0-10 br0 10` crée un « pont » `br0-10` qui
n'est qu'un port interne du VLAN 10 de `br0`.)

`ovs-appctl fdb/show br0` affiche la table MAC apprise, avec le VLAN de chaque adresse.
""")
            + info_subtitle(tr("Agrégation de liens"), tag="bond")
            + tr("""

Un **agrégat** (*bond*) réunit plusieurs liens vers le même équipement en un seul port logique : plus de
débit, et la survie à la perte d'un lien. Sans agrégat, deux liens parallèles entre deux switchs font
une **boucle**.

```
ovs-vsctl add-bond br0 bond0 eth0 eth1 bond_mode=balance-slb
```

| `bond_mode` | répartition | exige LACP |
|-------------|-------------|------------|
| `active-backup` | un seul membre actif, les autres en secours | non |
| `balance-slb` | par adresse MAC source et VLAN (le switch d'en face n'a rien à configurer) | non |
| `balance-tcp` | par flux (adresses et ports L3 / L4) | **oui** |

**LACP** (802.1AX, ex-802.3ad) : les deux extrémités échangent des LACPDU (adresse
`01:80:c2:00:00:02`) pour vérifier qu'elles parlent bien du même agrégat et pour détecter un membre
défaillant.

- `lacp=active` (envoie des LACPDU), `passive` (répond seulement), `off` ;
- `other_config:lacp-time=fast` : un LACPDU par seconde (une panne vue en 3 s) au lieu de 30 s (90 s) ;
- `other_config:lacp-system-id`, `lacp-system-priority` : l'identité annoncée (par défaut l'adresse MAC
  du pont) ;
- sans partenaire LACP, un agrégat `lacp=active` est **désactivé** (sauf `other_config:lacp-fallback-ab=true`) :
  aucun trafic plutôt qu'une boucle.

| commande | contenu |
|----------|---------|
| `ovs-appctl bond/show [bond0]` | mode, état LACP (`negotiated`), membres actifs, répartition des flux |
| `ovs-appctl lacp/show [bond0]` | identités et états LACP de l'acteur (soi) et du partenaire, pour chaque membre |

Chaque **membre** d'un agrégat reste une interface avec son propre numéro OpenFlow.
""")
            + info_subtitle(tr("Tunnels et réseaux overlay"), tag="tunnels")
            + info_subtitle(tr("VXLAN, Geneve, GRE"), level=2, tag="encaps")
            + tr("""

Un **réseau overlay** transporte des trames Ethernet entre des machines à travers un réseau IP (le réseau
**sous-jacent**, *underlay*) : deux machines virtuelles de deux hyperviseurs distants sont dans le même
réseau L2, sans VLAN à étendre dans le data centre.

| encapsulation | transport | identifiant | surcoût sur IPv4 |
|---------------|-----------|-------------|------------------|
| **VXLAN** (RFC 7348) | UDP, port **4789** | VNI, 24 bits | 50 octets (Ethernet 14 + IP 20 + UDP 8 + VXLAN 8) |
| **Geneve** (RFC 8926) | UDP, port **6081** | VNI, 24 bits, et des options extensibles | 50 octets + options |
| **GRE** (RFC 2784) | IP, protocole 47 | clé de 32 bits (option) | 42 octets avec clé (Ethernet 14 + IP 20 + GRE 8) |

Dans OVS, un tunnel est un port :

```
ovs-vsctl add-port br-int vx0 -- set interface vx0 type=vxlan \\
          options:remote_ip=198.51.100.2 options:key=5000
```

- `options:remote_ip` : l'autre extrémité (le **VTEP** distant) ; `options:local_ip` : l'adresse
  source (sinon, celle que donne la table de routage) ;
- `options:key` : le VNI (ou la clé GRE) ; `key=flow` : le VNI est choisi par les entrées de flux
  (`set_field:5000->tun_id`) ;
- les paquets encapsulés sont **routés par la machine** (sa table de routage, ses interfaces) : l'interface
  vers le réseau sous-jacent n'est pas dans le pont ;
- le datapath du noyau utilise une interface par type de tunnel, créée par OVS : `vxlan_sys_4789`,
  `genev_sys_6081`, `gre_sys` (visibles avec `ip link`).

Un port de tunnel est un port comme un autre : il peut avoir un `tag`.
""")
            + info_subtitle(tr("La MTU"), level=2, tag="mtu")
            + tr("""

Une trame de 1500 octets de charge utile devient, encapsulée en VXLAN, un paquet IP de 1550 octets. Si
l'interface du réseau sous-jacent a une MTU de 1500, ce paquet ne passe pas : OVS renvoie à la machine
virtuelle un ICMP *fragmentation needed* (MTU 1450), ou le paquet est perdu. Deux solutions :

- **augmenter la MTU du réseau sous-jacent** (≥ 1550, souvent 1600 ou 9000 : les trames géantes,
  *jumbo frames*), sur les interfaces des hyperviseurs **et** de tout le chemin ;
- **réduire la MTU des machines virtuelles** à 1450 (ce que fait OpenStack, par DHCP).

Pour tester : `ping -M do -s 1472 <destination>` (1472 + 8 + 20 = un paquet IP de 1500 octets, sans
fragmentation). Une machine qui a reçu un *fragmentation needed* garde la MTU réduite en cache dix minutes
(`ip route get <destination>` affiche `mtu 1450`) ; `ip route flush cache` l'efface (dans un conteneur,
après `mount -o rw,remount /proc/sys`).
""")
            + info_subtitle(tr("VNI et VLAN locaux : l'exemple d'OpenStack"), level=2, tag="neutron")
            + tr("""

Dans un hyperviseur, chaque réseau de locataire reçoit un **VLAN local**, choisi par cet hyperviseur ;
le réseau est identifié globalement par son **VNI**. Le même réseau peut donc avoir le VLAN 3 sur un
hyperviseur et le VLAN 7 sur un autre : c'est le tunnel qui fait la correspondance VLAN local ↔ VNI.

OpenStack Neutron organise ainsi chaque hyperviseur : un pont `br-int` (les machines virtuelles, dans
leur VLAN local) relié par des ports `patch` à un pont `br-tun` (les tunnels, `key=flow`), dont les
entrées de flux traduisent le VLAN local en VNI à l'émission et le VNI en VLAN local à la réception.
Avec un port de tunnel par réseau, `tag=<VLAN local>` et `options:key=<VNI>` font la même traduction
sans écrire de flux.
""")
            + info_subtitle(tr("Le pipeline OpenFlow d'OVS"), tag="pipeline")
            + tr("""

Chaque pont a des tables de flux numérotées à partir de 0. Un pont sans contrôleur, en mode `standalone`,
n'a qu'une entrée, `priority=0 actions=NORMAL` : le traitement d'un switch classique (apprentissage MAC,
VLAN, agrégats). Les entrées que l'on ajoute passent devant elle si leur priorité est plus forte.

```
ovs-ofctl -O OpenFlow13 add-flow br0 "table=0,priority=100,arp,actions=NORMAL"
ovs-ofctl -O OpenFlow13 add-flows br0 fichier          # une entrée par ligne
ovs-ofctl -O OpenFlow13 replace-flows br0 fichier      # remplacer toute la table
ovs-ofctl -O OpenFlow13 dump-flows br0                 # entrées et compteurs
ovs-ofctl -O OpenFlow13 del-flows br0                  # tout supprimer
```

| écriture | sens |
|----------|------|
| `table=N` | la table de l'entrée (0 si absent) |
| `priority=N` | la plus forte gagne (32768 si absent) |
| `in_port=N`, `dl_src`, `dl_dst` | port d'entrée (numéro OpenFlow), adresses MAC |
| `arp`, `ip`, `icmp`, `tcp`, `udp` | protocoles (`tcp` = IPv4 + TCP...) |
| `nw_src`, `nw_dst`, `tp_src`, `tp_dst` | adresses IPv4, ports TCP / UDP |
| `actions=NORMAL`, `output:N`, `drop` | traitement classique, émettre sur un port, jeter |
| `actions=goto_table:1` / `resubmit(,1)` | continuer dans la table 1 |
| `actions=set_queue:1,NORMAL` | choisir la file d'attente 1 du port de sortie, puis traitement classique |

`ovs-appctl ofproto/trace br0 "in_port=1,tcp,nw_src=...,nw_dst=...,tcp_dst=80"` **simule** un paquet :
les entrées qu'il traverse, table par table, et à la dernière ligne (`Datapath actions:`) son sort :
`drop`, ou les ports de sortie. Dans une trace, les drapeaux TCP s'écrivent exactement
(`tcp_flags=0x012` pour SYN+ACK).
""")
            + info_subtitle(tr("Pare-feu avec état : le suivi de connexions"), tag="conntrack")
            + tr("""

Un filtrage **sans état** juge chaque paquet seul : pour laisser revenir les réponses d'un serveur web,
il faut autoriser tout ce qui vient de son port 80, même un paquet qu'aucun client n'a demandé. Le
**suivi de connexions** du noyau (*conntrack*, celui de netfilter) retient les connexions ouvertes ; OVS
s'en sert avec l'action `ct` et le champ `ct_state` :

- `ct(table=1)` passe le paquet au suivi de connexions, puis le **recircule** (le fait repasser) dans la
  table 1 avec son état ;
- `ct(commit)` **enregistre** la connexion : sans `commit`, le noyau l'oublie et ses paquets suivants
  restent `new` ;
- `ct(zone=N)` : des tables de connexions séparées (un locataire par zone).

| drapeau de `ct_state` | sens |
|-----------------------|------|
| `trk` | le paquet est passé par le suivi de connexions (`-trk` : pas encore) |
| `new` | premier paquet d'une connexion inconnue |
| `est` | paquet d'une connexion enregistrée, **dans un sens ou dans l'autre** |
| `rel` | paquet lié à une connexion enregistrée (un ICMP d'erreur, une connexion de données FTP) |
| `rpl` | paquet dans le sens de la réponse |
| `inv` | paquet invalide (incohérent avec l'état TCP...) |

On écrit `ct_state=+trk+est` (ces drapeaux présents), `ct_state=-trk` (absent). Le schéma habituel :

```
table=0,priority=100,ip,ct_state=-trk,actions=ct(table=1)
table=1,priority=100,ip,ct_state=+trk+est,actions=NORMAL
table=1,priority=100,ip,ct_state=+trk+new,<ce qui est autorisé>,actions=ct(commit),NORMAL
table=1,priority=0,actions=drop
```

L'ARP n'est pas de l'IP : il passe par sa propre entrée. `ovs-appctl dpctl/dump-conntrack` affiche les
connexions suivies ; dans une trace, `--ct-next trk,new` (ou `trk,est`) donne l'état que le suivi de
connexions attribuerait au paquet après `ct()`.
""")
            + info_subtitle(tr("Miroirs de ports"), tag="mirror")
            + tr("""

Un **miroir** (*SPAN*, *port mirroring*) envoie une copie de trafic vers un port d'analyse (une sonde, un
IDS). Une ligne de la table Mirror, référencée par la colonne `mirrors` du pont :

| colonne | sens |
|---------|------|
| `select_src_port` | copier ce qu'**émettent** ces ports vers le switch (ce que le switch reçoit d'eux) |
| `select_dst_port` | copier ce que le switch **émet** vers ces ports |
| `select_all` | tout le trafic du pont |
| `select_vlan` | seulement ces VLAN |
| `output_port` | le port qui reçoit les copies (il ne sert plus au trafic normal) |
| `output_vlan` | à la place d'un port, un VLAN qui transporte les copies vers une sonde distante (*RSPAN*) |

```
ovs-vsctl -- --id=@p get port eth1 -- --id=@o get port eth9 \\
          -- --id=@m create mirror name=m0 select_src_port=@p select_dst_port=@p output_port=@o \\
          -- set bridge br0 mirrors=@m
ovs-vsctl clear bridge br0 mirrors                      # supprimer
```
""")
            + info_subtitle(tr("Qualité de service"), tag="qos")
            + info_subtitle(tr("Limitation à l'entrée"), level=2, tag="policing")
            + tr("""

La **limitation** (*policing*) jette ce qui dépasse un débit, à l'**entrée** du switch : elle porte sur ce
qu'émet la machine reliée au port. Deux colonnes de l'**interface** :

- `ingress_policing_rate` : le débit, en **kbit/s** (0 : pas de limite) ;
- `ingress_policing_burst` : la rafale tolérée, en **kbit** (au moins 10 % du débit est conseillé).

```
ovs-vsctl set interface eth3 ingress_policing_rate=1000 ingress_policing_burst=100
```

OVS l'applique par un filtre `tc` (`tc filter show dev eth3 ingress`). Le TCP s'adapte mal à des pertes
aussi brutales : on mesure plutôt avec un flux UDP (`iperf3 -u -b ...`), dont on lit le débit reçu.
""")
            + info_subtitle(tr("Files d'attente"), level=2, tag="htb")
            + tr("""

À la **sortie** d'un port, une **QoS** répartit le débit entre des **files** (*queues*), en façonnant le
trafic (*shaping*) au lieu de le jeter brutalement. Une ligne de la table QoS, référencée par la colonne
`qos` du **port**, et ses lignes de la table Queue :

- `type=linux-htb` (Hierarchical Token Bucket) : OVS crée les classes `tc` du port (`tc class show dev
  eth4` : la file N est la classe `1:N+1`) ;
- `other_config:max-rate` de la QoS (le débit total) et de chaque file (`max-rate`, `min-rate`) : en
  **bit/s** ;
- la file 0 reçoit le trafic par défaut ; une entrée de flux choisit une autre file avec
  `set_queue:N` avant sa sortie.

```
ovs-vsctl -- set port eth4 qos=@q \\
          -- --id=@q create qos type=linux-htb other_config:max-rate=100000000 queues:0=@q0 queues:1=@q1 \\
          -- --id=@q0 create queue other_config:max-rate=100000000 \\
          -- --id=@q1 create queue other_config:max-rate=1000000
ovs-ofctl -O OpenFlow13 add-flow br0 "priority=100,ip,nw_src=192.0.2.9,actions=set_queue:1,NORMAL"
```

Les lignes QoS et Queue ne disparaissent pas d'elles-mêmes quand plus rien ne les référence :
`ovs-vsctl clear port eth4 qos`, puis `ovs-vsctl --all destroy qos -- --all destroy queue`.
""")
            + info_subtitle(tr("Les outils de diagnostic"), tag="tools")
            + tr("""

| commande | usage |
|----------|-------|
| `ovs-vsctl show`, `list`, `find` | la configuration (OVSDB) |
| `ovs-ofctl -O OpenFlow13 show br0` | les ports et leurs numéros OpenFlow |
| `ovs-ofctl -O OpenFlow13 dump-flows br0` | les entrées de flux et leurs compteurs |
| `ovs-ofctl -O OpenFlow13 dump-ports br0` | les compteurs des ports |
| `ovs-appctl fdb/show br0` | la table MAC (port, VLAN, adresse, âge) |
| `ovs-appctl bond/show`, `lacp/show` | les agrégats |
| `ovs-appctl ofproto/trace br0 "<paquet>"` | simuler un paquet |
| `ovs-appctl dpctl/dump-conntrack` | les connexions suivies |
| `ovs-appctl dpctl/dump-flows` | le cache du datapath (*megaflows*) |
| `ovs-appctl dpif/show` | les ports du datapath, avec leurs numéros |
| `/var/log/openvswitch/ovs-vswitchd.log` | le journal (avertissements, erreurs de configuration) |
""")
            + info_subtitle(tr("Dans ce TP"), tag="lab")
            + tr("""

- Les switchs et les hyperviseurs sont des conteneurs où tournent `ovsdb-server` et `ovs-vswitchd`
  (démarrés pour vous). Leur datapath est le module `openvswitch` du noyau de la machine hôte. Ne relancez
  pas Open vSwitch ; si c'est nécessaire : `/usr/share/openvswitch/scripts/ovs-ctl restart`.
- Les interfaces `ethN` des switchs n'ont pas d'adresse IP : ce sont leurs ports (sauf l'interface vers le
  réseau sous-jacent d'un hyperviseur).
- Les « machines virtuelles » sont des conteneurs reliés aux ports des hyperviseurs.
- Pour capturer : `tcpdump -n -i eth0` (`-e` affiche les adresses MAC et les étiquettes VLAN).
""")
        )

    # -- helpers ---------------------------------------------------------------------------------

    def hosts_content(self) -> str:
        d = self.data
        names = HOSTS + ("hv3a", "hv3b")
        lines = ["127.0.0.1\tlocalhost"] + [f"{d.ip(name)}\t{name}" for name in names]
        lines += [f"{d.ip('core3_a')}\tcore3", f"{d.ip('gw_users')}\t{GW_USERS}", f"{d.ip('gw_servers')}\t{GW_SERVERS}"]
        return "\n".join(lines) + "\n"

    def fw_flows(self) -> str:
        """The reference pipeline of fw4 (ovs-ofctl syntax)."""
        d = self.data
        c, w = d.ip("client4"), d.ip("web4")
        return (
            "table=0,priority=200,arp,actions=NORMAL\n"
            "table=0,priority=100,ip,ct_state=-trk,actions=ct(table=1)\n"
            "table=0,priority=0,actions=drop\n"
            "table=1,priority=200,ct_state=+trk+est,ip,actions=NORMAL\n"
            "table=1,priority=200,ct_state=+trk+rel,ip,actions=NORMAL\n"
            f"table=1,priority=100,ct_state=+trk+new,tcp,nw_src={c},nw_dst={w},tp_dst={WEB_PORT},"
            "actions=ct(commit),NORMAL\n"
            f"table=1,priority=100,ct_state=+trk+new,icmp,nw_src={c},nw_dst={w},actions=ct(commit),NORMAL\n"
            "table=1,priority=0,actions=drop\n")

    def queue_flow(self) -> str:
        return f"priority=100,ip,nw_src={self.data.ip('h5b')},actions=set_queue:{QUEUE_ID},NORMAL"

    def p1_cmds(self, sw: str) -> list:
        """The reference configuration of sw1a / sw1b (ovs-vsctl and ip commands)."""
        d = self.data
        trunks = ",".join(str(v) for v in sorted((d.vlan_users, d.vlan_servers)))
        cmds = [ovs_bridge_cmd(BRIDGE, [(TRUNK1, None), ("eth1", None), ("eth2", None)], protocols=None,
                               tags={"eth1": d.vlan_users, "eth2": d.vlan_servers}),
                f"ovs-vsctl --timeout=5 set port {TRUNK1} trunks={trunks}"]
        if sw == "sw1a":
            for port, vlan, gw in ((GW_USERS, d.vlan_users, d.ips.gw_users),
                                   (GW_SERVERS, d.vlan_servers, d.ips.gw_servers)):
                cmds.append(ovs_internal_port_cmd(BRIDGE, port, tag=vlan))
                cmds.append(f"ip addr replace {gw} dev {port}")
                cmds.append(f"ip link set {port} up")
        return cmds

    def p3_cmds(self, hv: str) -> list:
        d = self.data
        other = d.ip("hv3b" if hv == "hv3a" else "hv3a")
        tags = d.tags3(hv)
        return [ovs_bridge_cmd(BRIDGE3, [("eth1", None), ("eth2", None)], protocols=None,
                               tags={"eth1": tags["red"], "eth2": tags["blue"]}),
                ovs_tunnel_cmd(BRIDGE3, VXLAN_PORT, "vxlan", other, d.vni_red, tag=tags["red"]),
                ovs_tunnel_cmd(BRIDGE3, GENEVE_PORT, "geneve", other, d.vni_blue, tag=tags["blue"]),
                f"ip link set eth0 mtu {UNDERLAY_MTU}"]

    def p5_cmds(self) -> list:
        d = self.data
        return [ovs_mirror_cmd(BRIDGE, MIRROR, [SW5_PORTS["h5a"]], SW5_PORTS["ids5"]),
                ovs_policing_cmd(SW5_PORTS["guest5"], d.police_rate, d.police_rate // 10)]

    def bonus_cmds(self) -> list:
        d = self.data
        return [ovs_qos_cmd(SW5_PORTS["srv5"], QOS_MAX_RATE, {0: QOS_MAX_RATE, QUEUE_ID: d.queue_rate * 1000}),
                f"ovs-ofctl -O OpenFlow13 add-flow {BRIDGE} '{self.queue_flow()}'"]

    # -- states --------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self._machine_specs:
            self.file(m, "/etc/hosts", self.hosts_content())
            self.file(m, "/etc/resolv.conf", "")
        for sw in SWITCHES:
            self.cmd(sw, ovs_start_cmd(), timeout=60)
        # part 2: tor2 is the switch of the data centre (bond + LACP, its own system ID), hv2 has
        # a bridge for its virtual machine only
        self.cmd("tor2", ovs_bridge_cmd(BRIDGE, [("eth2", None)], protocols=None))
        self.cmd("tor2", ovs_bond_cmd(BRIDGE, BOND, BOND_MEMBERS, other_config={"lacp-system-id": d.lacp_sysid}))
        self.cmd("hv2", ovs_bridge_cmd(BRIDGE, [("eth2", None)], protocols=None))
        # part 3: a core that carries jumbo frames
        self.cmd("core3", f"ip link set eth0 mtu {CORE_MTU}; ip link set eth1 mtu {CORE_MTU}")
        # parts 4 and 5: standalone bridges with their ports, the OpenFlow numbers drawn
        self.cmd("fw4", ovs_bridge_cmd(BRIDGE, sorted(d.ofports4.items(), key=lambda item: item[1]), protocols=None))
        self.cmd("sw5", ovs_bridge_cmd(BRIDGE, sorted(d.ofports5.items(), key=lambda item: item[1]), protocols=None))
        install_echo_server(self, "web4", ports=(WEB_PORT,))
        install_echo_server(self, "client4", ports=(CLIENT_PORT,))
        self.cmd("srv5", f"iperf3 -s -D -p {IPERF_GUEST_PORT}; iperf3 -s -D -p {IPERF_QUEUE_PORT}")

    # The solve helpers can be applied again.
    def _solve_part1(self):
        for sw in ("sw1a", "sw1b"):
            for c in self.p1_cmds(sw):
                self.cmd(sw, c)

    def _solve_part2(self):
        self.cmd("hv2", ovs_bond_cmd(BRIDGE, BOND, BOND_MEMBERS))
        self.cmd("hv2", f"for i in $(seq 50); do ovs-appctl bond/show {BOND} | grep -q 'lacp_status: negotiated' "
                        "&& break; sleep 0.2; done", timeout=30)

    def _solve_part3(self):
        for hv in ("hv3a", "hv3b"):
            for c in self.p3_cmds(hv):
                self.cmd(hv, c)

    def _solve_part4(self):
        self.file("fw4", FW_FILE, self.fw_flows())
        self.cmd("fw4", f"ovs-ofctl -O OpenFlow13 replace-flows {BRIDGE} {FW_FILE}")

    def _solve_part5(self):
        for c in self.p5_cmds():
            self.cmd("sw5", c)

    def _solve_bonus(self):
        for c in self.bonus_cmds():
            self.cmd("sw5", c)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (trunk, VLAN et ports internes)"))
    def solve_part1(self):
        self._solve_part1()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (agrégat LACP de hv2)"))
    def solve_part2(self):
        self._solve_part2()

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (tunnels VXLAN et Geneve, MTU)"))
    def solve_part3(self):
        self._solve_part3()

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (pare-feu avec état de fw4)"))
    def solve_part4(self):
        self._solve_part4()

    @sre_state(user_allowed=False, description=tr("Partie 5 : solution (miroir et limitation de guest5)"))
    def solve_part5(self):
        self._solve_part5()

    @sre_state(user_allowed=False, description=tr("Bonus : solution (files d'attente HTB et set_queue)"))
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
        self._solve_part5()
        self._solve_bonus()


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------




def _norm(s) -> str:
    return " ".join(str(s or "").split()).lower()


def _int_answer(s):
    text = str(s or "").strip()
    return int(text) if text.isdigit() else None


def _mac_answer(s) -> str:
    return str(s or "").strip().lower().replace("-", ":")


def _served(echo: dict, name: str) -> bool:
    return echo.get("server") == name


def _kbps(iperf_out: str) -> float:
    return (parse_iperf3(iperf_out)["bps"] or 0) / 1000


def _queue_ids(flow) -> list:
    return [int(a.split(":", 1)[1]) for a in flow.actions
            if a.startswith("set_queue:") and a.split(":", 1)[1].isdigit()]


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
        st1 = {sw: get_ovs_state(self, sw) for sw in ("sw1a", "sw1b")}
        addr1a = get_ip_addresses(self, "sw1a")
        ping_users = eval_ping(self, "user1a", ip("user1b"), count=2, deadline=3, allow_error=True)
        ping_servers = eval_ping(self, "srv1a", ip("srv1b"), count=2, deadline=3, allow_error=True)
        ping_routed1 = eval_ping(self, "user1a", ip("srv1b"), count=2, deadline=3, allow_error=True)
        ping_routed2 = eval_ping(self, "srv1a", ip("user1b"), count=2, deadline=3, allow_error=True)
        # part 2
        st2 = get_ovs_state(self, "hv2")
        bonds2 = get_bond_show(self, "hv2")
        lacp2 = get_lacp_show(self, "hv2")
        ping_bond = eval_ping(self, "vm2", ip("nas2"), count=2, deadline=3, allow_error=True)
        # part 3
        st3 = {hv: get_ovs_state(self, hv) for hv in ("hv3a", "hv3b")}
        ping_red = eval_ping(self, "red3a", ip("red3b"), count=2, deadline=3, allow_error=True)
        ping_blue = eval_ping(self, "blue3a", ip("blue3b"), count=2, deadline=3, allow_error=True)
        leaks = [eval_ping(self, src, ip(dst), count=1, deadline=2, allow_error=True)
                 for src, dst in (("red3a", "blue3a"), ("red3a", "blue3b"), ("blue3b", "red3b"))]
        # the DF bit is on the request only: red3a -> red3b crosses the underlay of hv3a, blue3b -> blue3a that of hv3b
        _, df_code_a = self.test("red3a", df_ping_cmd(ip("red3b"), DF_SIZE), timeout=10, allow_error=True)
        _, df_code_b = self.test("blue3b", df_ping_cmd(ip("blue3a"), DF_SIZE), timeout=10, allow_error=True)
        # part 4: real traffic, then traces with the state the connection tracking would give
        st4 = get_ovs_state(self, "fw4")
        web_from_client = get_http_echo(self, "client4", ip("web4"), WEB_PORT, timeout=4)
        ping_fw = eval_ping(self, "client4", ip("web4"), count=2, deadline=3, allow_error=True)
        client_from_web = get_http_echo(self, "web4", ip("client4"), CLIENT_PORT, timeout=3)
        ping_back = eval_ping(self, "web4", ip("client4"), count=1, deadline=2, allow_error=True)
        t_synack = get_trace(self, "fw4", BRIDGE, trace_flow(
            in_port=d.ofport4("web4"), proto="tcp", eth_src=mac("web4"), eth_dst=mac("client4"), ip_src=ip("web4"),
            ip_dst=ip("client4"), sport=WEB_PORT, dport=40000, tcp_flags=SYN_ACK), ct_next=["trk,new"])
        t_udp = get_trace(self, "fw4", BRIDGE, trace_flow(
            in_port=d.ofport4("client4"), proto="udp", eth_src=mac("client4"), eth_dst=mac("web4"),
            ip_src=ip("client4"), ip_dst=ip("web4"), dport=53), ct_next=["trk,new"])
        conns4 = get_conntrack(self, "fw4", step=2)
        # part 5: a capture on ids5 from step 1 to step 3, the ping h5b -> h5a in step 2; the two iperf3
        # in two steps (they cross the same port of sw5)
        st5 = get_ovs_state(self, "sw5", tables=OVS_TABLES_FULL)
        self.test("ids5", capture_start_cmd(SPAN_CAPTURE, bpf="icmp"), timeout=10, allow_error=True)
        iperf_guest, _ = self.test("guest5", f"timeout {IPERF_SECONDS + 8} iperf3 -c {ip('srv5')} -p {IPERF_GUEST_PORT} "
                                             f"-u -b {IPERF_FACTOR * d.police_rate}k -t {IPERF_SECONDS} -J "
                                             "--connect-timeout 3000",
                                   timeout=IPERF_SECONDS + 12, allow_error=True)
        self.test("h5b", f"ping -n -c {MIRROR_PINGS} -i 0.2 -W 1 {ip('h5a')}", step=2, timeout=10, allow_error=True)
        iperf_queue, _ = self.test("h5b", f"timeout {IPERF_SECONDS + 8} iperf3 -c {ip('srv5')} -p {IPERF_QUEUE_PORT} "
                                          f"-u -b {IPERF_FACTOR * d.queue_rate}k -t {IPERF_SECONDS} -J "
                                          "--connect-timeout 3000",
                                   step=2, timeout=IPERF_SECONDS + 12, allow_error=True)
        span_out, _ = self.test("ids5", capture_read_cmd(SPAN_CAPTURE, "icmp"), step=3, timeout=10, allow_error=True)
        flows5 = get_flows(self, "sw5", BRIDGE)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="7479efd1a258880f",
            description=tr("""
Lisez l'onglet **Informations** : il présente Open vSwitch, sa base de configuration, les VLAN, les
agrégats, les tunnels, le suivi de connexions, les miroirs et la qualité de service. Le TP a cinq parties
indépendantes, chacune sur son propre site, et un bonus à la fin de la cinquième.

| partie | switchs | machines |
|--------|---------|----------|
| 1 | `sw1a`, `sw1b` : Open vSwitch démarré, aucun pont ; reliés par leur `eth0` | sur `sw1a` : `user1a` {user1a} (`eth1`), `srv1a` {srv1a} (`eth2`) ; sur `sw1b` : `user1b` {user1b} (`eth1`), `srv1b` {srv1b} (`eth2`) |
| 2 | `hv2` : pont `br0` avec `vm2` ; `tor2` : switch du data centre, pas de terminal | `vm2` {vm2} (`eth2` de `hv2`) ; `nas2` {nas2} (derrière `tor2`) ; liens `eth0` et `eth1` entre `hv2` et `tor2` |
| 3 | `hv3a` {hv3a}, `hv3b` {hv3b} : Open vSwitch démarré, aucun pont | routeur `core3` entre les deux ; `red3a` {red3a}, `blue3a` {blue3a} sur `hv3a` ; `red3b` {red3b}, `blue3b` {blue3b} sur `hv3b` |
| 4 | `fw4` : pont `br0` en switch classique | `client4` {client4}, `web4` {web4} |
| 5 | `sw5` : pont `br0` en switch classique | `h5a` {h5a} (`eth0`), `h5b` {h5b} (`eth1`), `ids5` {ids5} (`eth2`), `guest5` {guest5} (`eth3`), `srv5` {srv5} (`eth4`) |

Tous les noms sont dans `/etc/hosts`. Les ports des switchs n'ont pas d'adresse IP.

Le travail et le comportement de vos machines sont évalués automatiquement (bouton d'évaluation) :
l'évaluation lit la configuration des switchs (`ovs-vsctl`, `ovs-appctl`, `ovs-ofctl`), fait passer du
trafic entre les machines (ping, requêtes TCP, iperf3), capture sur `ids5` et simule sur `fw4` des paquets
que la partie 4 doit refuser (`ovs-appctl ofproto/trace`).
""").format(user1a=ip("user1a"), srv1a=ip("srv1a"), user1b=ip("user1b"), srv1b=ip("srv1b"), vm2=ip("vm2"),
            nas2=ip("nas2"), hv3a=ip("hv3a"), hv3b=ip("hv3b"), red3a=ip("red3a"), blue3a=ip("blue3a"),
            red3b=ip("red3b"), blue3b=ip("blue3b"), client4=ip("client4"), web4=ip("web4"), h5a=ip("h5a"),
            h5b=ip("h5b"), ids5=ip("ids5"), guest5=ip("guest5"), srv5=ip("srv5"))
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part5` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes ; ils remplissent les formulaires.

- `tor2` : agrégat `bond0` (`eth0`, `eth1`), LACP actif rapide, `balance-tcp`, `lacp-system-id` {sysid}.
- `fw4` : numéros OpenFlow {ofports4} ; `sw5` : {ofports5}.
- L'évaluation, en trois étapes : `ovs-vsctl list`, `bond/show`, `lacp/show`, `dump-flows` sur les switchs ;
  ping entre les machines des parties 1 à 3 (et ping DF de {df} octets dans la partie 3) ; requêtes HTTP
  vers les serveurs d'écho de `web4` (port {web}) et `client4` (port {cport}) ; deux `ofproto/trace
  --ct-next trk,new` et `dpctl/dump-conntrack` sur `fw4` ; une capture ICMP sur `ids5` pendant un ping de
  `h5b` vers `h5a` ; iperf3 UDP de `guest5` vers `srv5` à {gsent} kbit/s et de `h5b` vers `srv5` à {qsent}
  kbit/s.
""").format(sysid=d.lacp_sysid,
            ofports4=", ".join(f"`{i}` = {p}" for i, p in sorted(d.ofports4.items())),
            ofports5=", ".join(f"`{i}` = {p}" for i, p in sorted(d.ofports5.items())),
            df=DF_SIZE, web=WEB_PORT, cport=CLIENT_PORT, gsent=IPERF_FACTOR * d.police_rate,
            qsent=IPERF_FACTOR * d.queue_rate)
            ),
        )

        # =====================================================================
        # Partie 1 — trunk 802.1Q et ports internes
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Trunk 802.1Q et ports internes"))
        vu, vs = d.vlan_users, d.vlan_servers
        self.question_dummy(
            section=self.section(0),
            title=tr("Deux switchs, deux VLAN, un trunk et une passerelle"),
            hash="452555b86985d51f",
            description=tr("""
Sections @@ref:ovsdb@@ et @@ref:vlan@@. Sur `sw1a` et `sw1b`, Open vSwitch tourne mais n'a aucun pont.
Deux VLAN : **users** (VLAN **{vu}**, réseau {users1}) et **servers** (VLAN **{vs}**, réseau {servers1}).

1. Sur chaque switch, créez le pont `br0` avec ses trois interfaces : `eth1` (vers `user1a` / `user1b`)
   dans le VLAN users, `eth2` (vers `srv1a` / `srv1b`) dans le VLAN servers, et `eth0`, le lien entre
   les deux switchs.
2. Faites de `eth0` un trunk qui ne transporte **que** ces deux VLAN. `user1a` doit joindre `user1b`, et
   `srv1a` joindre `srv1b`.
3. Les machines ont pour passerelle {gwu} (VLAN users) et {gws} (VLAN servers). Créez sur `sw1a` les ports
   internes `gw-users` et `gw-servers`, chacun dans son VLAN, avec ces adresses (/24). `sw1a` route déjà
   (`ip_forward` vaut 1) : `user1a` doit joindre `srv1b`.
4. Regardez `ovs-vsctl show`, la ligne du trunk (`ovs-vsctl list port eth0`) et la table MAC
   (`ovs-appctl fdb/show br0`) : dans quel VLAN chaque adresse est-elle apprise ?
""").format(vu=vu, vs=vs, users1=d.nets.users1, servers1=d.nets.servers1, gwu=ip("gw_users"),
            gws=ip("gw_servers"))
            + instructor(
                tr("""
**Solution.**

```
# sw1a et sw1b
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 trunks={trunks}
ovs-vsctl add-port br0 eth1 tag={vu}
ovs-vsctl add-port br0 eth2 tag={vs}
# sw1a seulement
ovs-vsctl add-port br0 gw-users tag={vu} -- set interface gw-users type=internal
ovs-vsctl add-port br0 gw-servers tag={vs} -- set interface gw-servers type=internal
ip addr add {gwu} dev gw-users
ip addr add {gws} dev gw-servers
ip link set gw-users up
ip link set gw-servers up
```

Sur `sw1a`, `fdb/show` montre les adresses de `user1b` et `srv1b` apprises sur le port du trunk, chacune
dans son VLAN.
""").format(trunks=",".join(str(v) for v in sorted((vu, vs))), vu=vu, vs=vs, gwu=d.ips.gw_users,
            gws=d.ips.gw_servers)
            ),
        )
        ports1 = {"eth0", "eth1", "eth2"}
        bridged = {sw: (st.bridge_of("eth0") is not None
                        and all(st.bridge_of(i) is st.bridge_of("eth0") for i in ports1))
                   for sw, st in st1.items()}
        self.add_grade_element(title=no_tr("p1_bridges"), max_grade=2, grade_part=part1,
                               grade=2 * int(all(bridged.values())),
                               description=tr("sw1a et sw1b ont chacun un pont avec eth0, eth1 et eth2"))

        def tag_of(st, iface):
            port = st.port_of(iface)
            return port.tag if port is not None else None

        access_ok = all(bridged.values()) and all(tag_of(st, "eth1") == vu and tag_of(st, "eth2") == vs
                                                  for st in st1.values())
        self.add_grade_element(title=no_tr("p1_access"), max_grade=2, grade_part=part1, grade=2 * int(access_ok),
                               description=tr("les ports d'accès sont dans les bons VLAN"))

        def trunk_ok(st):
            port = st.port_of(TRUNK1)
            return (port is not None and port.tag is None and sorted(port.trunks) == sorted((vu, vs))
                    and port.vlan_mode in (None, "trunk"))

        self.add_grade_element(title=no_tr("p1_trunk"), max_grade=2, grade_part=part1,
                               grade=2 * int(all(bridged.values()) and all(trunk_ok(st) for st in st1.values())),
                               description=tr("eth0 est un trunk limité aux deux VLAN, des deux côtés"))
        self.add_grade_element(title=no_tr("p1_same_vlan"), max_grade=3, grade_part=part1,
                               grade=3 * int(ping_users and ping_servers),
                               description=tr("user1a joint user1b et srv1a joint srv1b à travers le trunk"))

        def gateway_port(vlan, gw):
            for name, iface in st1["sw1a"].interfaces.items():
                if (iface.type == "internal" and tag_of(st1["sw1a"], name) == vlan
                        and any(a == str(gw.ip) and p == gw.network.prefixlen for a, p in addr1a.get(name, []))):
                    return name
            return None

        gateways_ok = (gateway_port(vu, d.ips.gw_users) is not None
                       and gateway_port(vs, d.ips.gw_servers) is not None)
        self.add_grade_element(title=no_tr("p1_gateways"), max_grade=2, grade_part=part1, grade=2 * int(gateways_ok),
                               description=tr("sw1a a un port interne avec l'adresse de la passerelle dans chaque VLAN"))
        self.add_grade_element(title=no_tr("p1_routing"), max_grade=3, grade_part=part1,
                               grade=3 * int(ping_routed1 and ping_routed2),
                               description=tr("user1a joint srv1b et srv1a joint user1b (routage par sw1a)"))

        q1_answers = {"empty": "all", "both": "access", "type": "internal", "local": "65534"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Ports, VLAN et types d'interfaces"),
            hash="d468d5bd856507c2",
            description=tr("""
Sections @@ref:ovsdb@@, @@ref:porttypes@@ et @@ref:vlan@@.

- un port sans `tag` dont la colonne `trunks` est vide : @@{empty:>n'achemine aucun VLAN>>>none|n'achemine que le VLAN 1>>>vlan1|achemine tous les VLAN>>>all|est désactivé>>>disabled}@@
- un port avec `tag=10 trunks=20,30` et sans `vlan_mode` : @@{both:>trunk des VLAN 10, 20 et 30>>>trunk|trunk des VLAN 20 et 30, le VLAN 10 sans étiquette>>>native|port d'accès du VLAN 10, trunks ignoré>>>access|refusé : erreur de configuration>>>error}@@
- le type de l'interface qui donne au switch une adresse IP dans un VLAN : @@{type:>system>>>system|patch>>>patch|internal>>>internal|vxlan>>>vxlan}@@
- le numéro OpenFlow (colonne `ofport`) de l'interface qui porte le nom du pont (`br0`) : @@{local:[0-9]+}@@
""")
            + instructor(tr("**Réponses.** Achemine tous les VLAN ; port d'accès du VLAN 10 (`trunks` ignoré, "
                            "avec un avertissement dans le journal) ; `internal` ; 65534 (le port `LOCAL`).")),
            cheat_answers={"final": q1_answers, "solve_part1": q1_answers},
        )
        for name, expected, text in (("empty", "all", tr("un trunk sans liste")),
                                     ("both", "access", tr("tag et trunks sans vlan_mode")),
                                     ("type", "internal", tr("le type internal"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part1,
                                   scope=CHOICE_SCOPE, grade=int(q1.get(name) == expected), description=text)
        self.add_grade_element(title=no_tr("answer_local"), max_grade=1, grade_part=part1,
                               grade=int(_int_answer(q1.get("local")) == 65534),
                               description=tr("le numéro OpenFlow du port LOCAL"))

        # =====================================================================
        # Partie 2 — agrégat et LACP
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Agrégation de liens et LACP"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Relier l'hyperviseur hv2 par deux liens"),
            hash="f6aef577a9199d8c",
            description=tr("""
Section @@ref:bond@@. `hv2` est un hyperviseur : sa machine virtuelle `vm2` est sur `eth2`, port du pont
`br0`. Il est relié au switch du data centre `tor2` par deux liens, `eth0` et `eth1`, qui ne sont encore
dans aucun pont. `tor2` (pas de terminal : il est géré par l'équipe réseau) attend un agrégat **LACP
actif**, en mode **`balance-tcp`**, avec des LACPDU **rapides** ; `nas2` est derrière lui.

1. Pourquoi ne faut-il pas ajouter `eth0` et `eth1` à `br0` comme deux ports ordinaires ?
2. Créez sur `hv2` l'agrégat `bond0` de `eth0` et `eth1`, configuré comme celui de `tor2`.
3. Vérifiez avec `ovs-appctl bond/show` et `ovs-appctl lacp/show` ; `vm2` doit joindre `nas2`.
4. Coupez un lien (`ip link set eth1 down` sur `hv2`) : que deviennent l'agrégat et un ping en cours ?
   Remettez-le (`ip link set eth1 up`).
""")
            + instructor(
                tr("""
**Solution.**

```
ovs-vsctl add-bond br0 bond0 eth0 eth1 bond_mode=balance-tcp lacp=active other_config:lacp-time=fast
```

Deux ports ordinaires feraient deux chemins parallèles entre `hv2` et `tor2` : une boucle, sans STP. Ici
`tor2`, qui attend LACP, laisse ses liens désactivés tant que la négociation n'a pas eu lieu (rien ne
passe). Lien coupé : le membre passe `disabled`, le trafic continue sur l'autre.
""")
            ),
        )
        bond_port = next((p for b in st2.bridges.values() for p in b.ports.values()
                          if sorted(p.interfaces) == sorted(BOND_MEMBERS)), None)
        bond_ok = bond_port is not None
        self.add_grade_element(title=no_tr("p2_bond"), max_grade=2, grade_part=part2, grade=2 * int(bond_ok),
                               description=tr("un port de hv2 réunit eth0 et eth1"))
        lacp = lacp2.get(bond_port.name) if bond_ok else None
        bond = bonds2.get(bond_port.name) if bond_ok else None
        negotiated = (lacp is not None and lacp.negotiated and bond is not None
                      and all(m in lacp.members and lacp.members[m].aggregated for m in BOND_MEMBERS)
                      and sorted(bond.enabled_members()) == sorted(BOND_MEMBERS))
        self.add_grade_element(title=no_tr("p2_lacp"), max_grade=3, grade_part=part2, grade=3 * int(negotiated),
                               description=tr("LACP est négocié avec tor2 sur les deux liens"))
        self.add_grade_element(title=no_tr("p2_mode"), max_grade=1, grade_part=part2,
                               grade=int(bond_ok and bond_port.bond_mode == "balance-tcp"),
                               description=tr("l'agrégat répartit par flux (balance-tcp)"))
        self.add_grade_element(title=no_tr("p2_fast"), max_grade=1, grade_part=part2,
                               grade=int(bond_ok and bond_port.other_config.get("lacp-time") == "fast"),
                               description=tr("LACP rapide"))
        self.add_grade_element(title=no_tr("p2_ping"), max_grade=2, grade_part=part2, grade=2 * int(ping_bond),
                               description=tr("vm2 joint nas2 à travers l'agrégat"))

        q2_answers = {"partner": d.lacp_sysid, "lacp_mode": "tcp", "ofports": "2"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Ce que disent bond/show et lacp/show"),
            hash="6b600bb5073af86e",
            description=tr("""
Section @@ref:bond@@.

- l'identifiant système LACP (`sys_id`) de `tor2`, le partenaire de votre agrégat : @@{partner:.+}@@
- le mode d'agrégat qui exige LACP : @@{lacp_mode:>active-backup>>>ab|balance-slb>>>slb|balance-tcp>>>tcp}@@
- le nombre de ports OpenFlow (`ovs-ofctl -O OpenFlow13 show br0`) qu'occupe `bond0` : @@{ofports:[0-9]+}@@
""")
            + instructor(tr("**Réponses.** `{sysid}` (`partner sys_id` de `lacp/show`) ; `balance-tcp` ; 2 (un par "
                            "membre).").format(sysid=d.lacp_sysid)),
            cheat_answers={"final": q2_answers, "solve_part2": q2_answers},
        )
        self.add_grade_element(title=no_tr("answer_partner"), max_grade=2, grade_part=part2,
                               grade=2 * int(_mac_answer(q2.get("partner")) == d.lacp_sysid),
                               description=tr("l'identifiant système de tor2"))
        self.add_grade_element(title=no_tr("answer_lacp_mode"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                               grade=int(q2.get("lacp_mode") == "tcp"), description=tr("le mode qui exige LACP"))
        self.add_grade_element(title=no_tr("answer_ofports"), max_grade=1, grade_part=part2,
                               grade=int(_int_answer(q2.get("ofports")) == 2),
                               description=tr("les ports OpenFlow d'un agrégat"))

        # =====================================================================
        # Partie 3 — overlay VXLAN et Geneve
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Overlay VXLAN et Geneve entre hyperviseurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Relier les machines virtuelles de deux hyperviseurs"),
            hash="17304dd789aee3f7",
            description=tr("""
Sections @@ref:tunnels@@ et @@ref:neutron@@. Deux hyperviseurs, `hv3a` ({hv3a}) et `hv3b` ({hv3b}), sont
dans deux réseaux séparés par le routeur `core3` : c'est le réseau sous-jacent. Chacun héberge une machine
du locataire **rouge** (sur `eth1`) et une du locataire **bleu** (sur `eth2`), toutes dans le même réseau
IP {tenant3}.

| locataire | encapsulation | VNI (clé) | VLAN local sur `hv3a` | VLAN local sur `hv3b` |
|-----------|---------------|-----------|-----------------------|-----------------------|
| rouge | VXLAN | {vr} | {rta} | {rtb} |
| bleu | Geneve | {vb} | {bta} | {btb} |

1. Sur chaque hyperviseur, créez le pont `br-int` avec les ports des machines virtuelles, chacun dans
   le VLAN local de son locataire (`eth0`, l'interface vers `core3`, reste hors du pont).
2. Ajoutez les ports de tunnel `vxlan-red` (VXLAN, clé {vr}) et `geneve-blue` (Geneve, clé {vb}) vers
   l'autre hyperviseur, chacun dans le VLAN local de son locataire. Les rouges doivent se joindre, les
   bleus aussi ; un rouge ne doit jamais joindre un bleu.
3. Capturez sur `core3` (`tcpdump -n -i eth0 udp`) pendant un ping : que voyez-vous ?
4. Un paquet de 1500 octets d'une machine virtuelle passe-t-il (`ping -M do -s {df} ...`) ? Le routeur
   `core3` accepte les trames géantes : portez la MTU de `eth0` des deux hyperviseurs à **{mtu}** et
   vérifiez (section @@ref:mtu@@).
""").format(hv3a=ip("hv3a"), hv3b=ip("hv3b"), tenant3=d.nets.tenant3, vr=d.vni_red, vb=d.vni_blue,
            rta=d.tag_red_a, rtb=d.tag_red_b, bta=d.tag_blue_a, btb=d.tag_blue_b, df=DF_SIZE, mtu=UNDERLAY_MTU)
            + instructor(
                tr("""
**Solution.**

```
# hv3a
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rta}
ovs-vsctl add-port br-int eth2 tag={bta}
ovs-vsctl add-port br-int vxlan-red tag={rta} -- set interface vxlan-red type=vxlan options:remote_ip={hv3b} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={bta} -- set interface geneve-blue type=geneve options:remote_ip={hv3b} options:key={vb}
ip link set eth0 mtu {mtu}
# hv3b
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rtb}
ovs-vsctl add-port br-int eth2 tag={btb}
ovs-vsctl add-port br-int vxlan-red tag={rtb} -- set interface vxlan-red type=vxlan options:remote_ip={hv3a} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={btb} -- set interface geneve-blue type=geneve options:remote_ip={hv3a} options:key={vb}
ip link set eth0 mtu {mtu}
```

La capture montre des paquets UDP entre les deux hyperviseurs, port 4789 (VXLAN, `vni {vr}`) et 6081
(Geneve), qui contiennent les trames des machines virtuelles. Avec une MTU de 1500, le ping DF de 1500
octets échoue : l'hyperviseur renvoie un *fragmentation needed* (MTU 1450).
""").format(rta=d.tag_red_a, bta=d.tag_blue_a, rtb=d.tag_red_b, btb=d.tag_blue_b, hv3a=ip("hv3a"),
            hv3b=ip("hv3b"), vr=d.vni_red, vb=d.vni_blue, mtu=UNDERLAY_MTU)
            ),
        )

        def tunnel_ok(hv, iface_type, key):
            remote = ip("hv3b" if hv == "hv3a" else "hv3a")
            return any(i.type == iface_type and i.options.get("remote_ip") == remote
                       and i.options.get("key") == str(key) for i in st3[hv].interfaces.values())

        for hv in ("hv3a", "hv3b"):
            ok = tunnel_ok(hv, "vxlan", d.vni_red) and tunnel_ok(hv, "geneve", d.vni_blue)
            self.add_grade_element(title=no_tr(f"p3_tunnels_{hv[-1]}"), max_grade=2, grade_part=part3,
                                   grade=2 * int(ok),
                                   description=tr("les tunnels VXLAN et Geneve de {hv} : extrémité et clé").format(hv=hv))
        self.add_grade_element(title=no_tr("p3_red"), max_grade=3, grade_part=part3, grade=3 * int(ping_red),
                               description=tr("red3a joint red3b à travers le tunnel"))
        self.add_grade_element(title=no_tr("p3_blue"), max_grade=3, grade_part=part3, grade=3 * int(ping_blue),
                               description=tr("blue3a joint blue3b à travers le tunnel"))
        self.add_grade_element(title=no_tr("p3_isolation"), max_grade=2, grade_part=part3,
                               grade=2 * int((ping_red or ping_blue) and not any(leaks)),
                               description=tr("aucun rouge ne joint un bleu, sur le même hyperviseur ou à travers les tunnels"))
        self.add_grade_element(title=no_tr("p3_mtu"), max_grade=2, grade_part=part3,
                               grade=2 * int(df_code_a == 0 and df_code_b == 0),
                               description=tr("des paquets de 1500 octets passent dans les deux sens (MTU du réseau sous-jacent)"))

        q3_answers = {"vxlan_port": "4789", "geneve_port": "6081", "overhead": "50", "device": "vxlan_sys_4789"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Ce que montre la capture"),
            hash="4a54e7e044de635e",
            description=tr("""
Sections @@ref:encaps@@ et @@ref:mtu@@.

- le port UDP de destination des paquets du locataire rouge, sur `core3` : @@{vxlan_port:[0-9]+}@@
- celui des paquets du locataire bleu : @@{geneve_port:[0-9]+}@@
- le surcoût de l'encapsulation VXLAN sur IPv4, en octets : @@{overhead:[0-9]+}@@
- le nom de l'interface du noyau qu'Open vSwitch a créée sur `hv3a` pour les ports VXLAN (`ip link`) : @@{device:.+}@@
""")
            + instructor(tr("**Réponses.** 4789 ; 6081 ; 50 (14 + 20 + 8 + 8) ; `vxlan_sys_4789`.")),
            cheat_answers={"final": q3_answers, "solve_part3": q3_answers},
        )
        for name, expected, text in (("vxlan_port", 4789, tr("le port de VXLAN")),
                                     ("geneve_port", 6081, tr("le port de Geneve")),
                                     ("overhead", 50, tr("le surcoût de VXLAN"))):
            self.add_grade_element(title=no_tr(f"answer_{name}"), max_grade=1, grade_part=part3,
                                   grade=int(_int_answer(q3.get(name)) == expected), description=text)
        self.add_grade_element(title=no_tr("answer_device"), max_grade=1, grade_part=part3,
                               grade=int(_norm(q3.get("device")) == "vxlan_sys_4789"),
                               description=tr("l'interface VXLAN du noyau"))

        # =====================================================================
        # Partie 4 — pare-feu avec état
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Pare-feu avec état et suivi de connexions"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Un pare-feu avec état sur fw4"),
            hash="592fed1765c4e3ff",
            description=tr("""
Sections @@ref:pipeline@@ et @@ref:conntrack@@. Le pont `br0` de `fw4` relie `client4` ({client4}) et
`web4` ({web4}) ; il se comporte pour l'instant en switch classique (`NORMAL`). `web4` a un site web
(port {web}) et `client4` un service sur le port {cport}. Écrivez avec `ovs-ofctl -O OpenFlow13` une
politique **avec état** :

- l'ARP passe ;
- `client4` peut ouvrir des connexions TCP vers le port {web} de `web4`, et pinguer `web4` ;
- `web4` ne peut **rien** ouvrir vers `client4` (ni connexion TCP, ni ping) : seules passent ses
  réponses à ce qu'a ouvert `client4` ;
- tout le reste est jeté.

Utilisez le suivi de connexions et deux tables : la table 0 confie le trafic IP au suivi de connexions,
qui le fait repasser dans la table 1 ; la table 1 décide selon l'état.

1. Trouvez les numéros OpenFlow des ports (`ovs-ofctl -O OpenFlow13 show br0`).
2. Écrivez la table (un fichier et `replace-flows` sont commodes) ; testez avec du vrai trafic (`curl
   http://web4/` depuis `client4`, `curl http://client4:{cport}/` depuis `web4`) et regardez
   `ovs-appctl dpctl/dump-conntrack`.
3. Simulez avec `ofproto/trace ... --ct-next trk,new` un SYN+ACK qui viendrait du port {web} de `web4`
   sans connexion ouverte : passe-t-il ? Passerait-il avec une règle sans état qui autorise ce qui vient
   du port {web} ?
""").format(client4=ip("client4"), web4=ip("web4"), web=WEB_PORT, cport=CLIENT_PORT)
            + instructor(
                tr("""
**Solution.** `/root/fw.flows`, puis `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/fw.flows` :

```
{flows}```

La trace du SYN+ACK sans connexion se termine par `Datapath actions: drop` (état `new`, aucune entrée ne
l'autorise) ; une règle sans état `tcp,nw_src=web4,tp_src={web},actions=NORMAL` le laisserait passer.
""").format(flows=self.net_scheme.fw_flows(), web=WEB_PORT)
            ),
        )
        # the bridge of a fresh project switches everything (NORMAL): the allowed traffic counts only once
        # the table filters (a UDP flow is dropped)
        filtering = t_udp.dropped
        web_ok = _served(web_from_client, "web4") and filtering
        self.add_grade_element(title=no_tr("p4_web"), max_grade=3, grade_part=part4, grade=3 * int(web_ok),
                               description=tr("client4 atteint le site web de web4, le reste étant filtré"))
        self.add_grade_element(title=no_tr("p4_ping"), max_grade=1, grade_part=part4, grade=int(ping_fw and filtering),
                               description=tr("client4 pingue web4, le reste étant filtré"))
        self.add_grade_element(title=no_tr("p4_reverse"), max_grade=3, grade_part=part4,
                               grade=3 * int(web_ok and not _served(client_from_web, "client4") and not ping_back),
                               description=tr("web4 n'ouvre rien vers client4 (ni TCP, ni ping)"))
        self.add_grade_element(title=no_tr("p4_stateful"), max_grade=2, grade_part=part4,
                               grade=2 * int(web_ok and t_synack.dropped),
                               description=tr("un SYN+ACK de web4 sans connexion ouverte est jeté (trace)"))
        # the connection of this evaluation's request (its source port, as the echo server saw it): an older
        # one stays two minutes in TIME_WAIT
        client_port = web_from_client.get("client_port") or None
        committed = client_port is not None and any(
            c.proto == "tcp" and c.matches(src=ip("client4"), dst=ip("web4"), dport=WEB_PORT, sport=client_port)
            for c in conns4)
        self.add_grade_element(title=no_tr("p4_conntrack"), max_grade=2, grade_part=part4, grade=2 * int(committed),
                               description=tr("la connexion de client4 vers web4 est enregistrée (commit)"))
        ports_kept = st4.bridge_of(SW4_PORTS["client4"]) is not None and \
            st4.bridge_of(SW4_PORTS["client4"]) is st4.bridge_of(SW4_PORTS["web4"])
        self.add_grade_element(title=no_tr("p4_default"), max_grade=1, grade_part=part4,
                               grade=int(web_ok and ports_kept),
                               description=tr("le reste est jeté (trace d'un flux UDP de client4 vers web4)"))

        q4_answers = {"first": "new", "flag": "est", "commit": "commit"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Les états du suivi de connexions"),
            hash="151deea59df57c28",
            description=tr("""
Section @@ref:conntrack@@.

- l'état (`ct_state`) du premier paquet d'une connexion, après `ct()` : @@{first:>-trk>>>untracked|+trk+est>>>est|+trk+new>>>new|+trk+inv>>>inv}@@
- le drapeau que portent ensuite les paquets de la connexion, dans les deux sens : @@{flag:>rpl>>>rpl|new>>>new|rel>>>rel|est>>>est}@@
- l'argument de l'action `ct` qui fait retenir la connexion par le noyau : @@{commit:.+}@@
""")
            + instructor(tr("**Réponses.** `+trk+new` ; `est` (`rpl` ne marque que le sens de la réponse) ; `commit`.")),
            cheat_answers={"final": q4_answers, "solve_part4": q4_answers},
        )
        self.add_grade_element(title=no_tr("answer_first"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                               grade=int(q4.get("first") == "new"), description=tr("l'état du premier paquet"))
        self.add_grade_element(title=no_tr("answer_flag"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                               grade=int(q4.get("flag") == "est"), description=tr("le drapeau est"))
        self.add_grade_element(title=no_tr("answer_commit"), max_grade=1, grade_part=part4,
                               grade=int(_norm(q4.get("commit")) == "commit"), description=tr("l'argument commit"))

        # =====================================================================
        # Partie 5 — miroir et limitation de débit
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Miroir de port et limitation de débit"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Observer h5a, limiter guest5"),
            hash="eacd3ee9203f06d6",
            description=tr("""
Sections @@ref:mirror@@ et @@ref:policing@@. Le pont `br0` de `sw5` est un switch classique.

1. Le poste de sécurité `ids5` (port `eth2`) doit recevoir une copie de tout ce qu'émet et reçoit `h5a`
   (port `eth0`). Créez le miroir, puis vérifiez par une capture sur `ids5` pendant un ping de `h5b` vers
   `h5a`. (Sans miroir, `ids5` ne voit pas ce trafic : le switch connaît les adresses MAC.)
2. L'invité `guest5` (port `eth3`) ne doit pas émettre plus de **{rate} kbit/s** : limitez-le à l'entrée du
   switch, avec une rafale d'un dixième de ce débit. Mesurez avant et après : `iperf3 -c srv5 -p {gport} -u
   -b {sent}k` depuis `guest5` (le débit reçu est à la fin).
""").format(rate=d.police_rate, gport=IPERF_GUEST_PORT, sent=IPERF_FACTOR * d.police_rate)
            + instructor(
                tr("""
**Solution.**

```
ovs-vsctl -- --id=@a get port eth0 -- --id=@ids get port eth2 \\
          -- --id=@m create mirror name=span select_src_port=@a select_dst_port=@a output_port=@ids \\
          -- set bridge br0 mirrors=@m
ovs-vsctl set interface eth3 ingress_policing_rate={rate} ingress_policing_burst={burst}
```

`tcpdump -n -i eth0 icmp` sur `ids5` montre les demandes et les réponses entre `h5b` et `h5a`. iperf3
envoie {sent} kbit/s ; `srv5` en reçoit environ {rate}.
""").format(rate=d.police_rate, burst=d.police_rate // 10, sent=IPERF_FACTOR * d.police_rate)
            ),
        )
        bridge5 = st5.bridge_of(SW5_PORTS["h5a"])
        h5a_port, ids_port = SW5_PORTS["h5a"], SW5_PORTS["ids5"]
        mirror_ok = bridge5 is not None and any(
            m.output_port == ids_port and (m.select_all or (h5a_port in m.select_src_ports
                                                            and h5a_port in m.select_dst_ports))
            for m in bridge5.mirrors)
        self.add_grade_element(title=no_tr("p5_mirror"), max_grade=2, grade_part=part5, grade=2 * int(mirror_ok),
                               description=tr("un miroir copie vers ids5 ce qu'émet et reçoit h5a"))
        mirrored = count_icmp_echo(span_out, ip("h5b"), ip("h5a"))
        self.add_grade_element(title=no_tr("p5_capture"), max_grade=3, grade_part=part5,
                               grade=3 * int(mirrored >= MIN_MIRRORED),
                               description=tr("ids5 voit le ping de h5b vers h5a (capture)"))
        guest = st5.interfaces.get(SW5_PORTS["guest5"])
        policed = guest is not None and guest.ingress_policing_rate == d.police_rate
        self.add_grade_element(title=no_tr("p5_policing"), max_grade=2, grade_part=part5, grade=2 * int(policed),
                               description=tr("l'entrée de guest5 est limitée au débit demandé"))
        guest_kbps = _kbps(iperf_guest)
        self.add_grade_element(title=no_tr("p5_rate"), max_grade=2, grade_part=part5,
                               grade=2 * int(policed and RATE_LOW * d.police_rate <= guest_kbps <= RATE_HIGH * d.police_rate),
                               description=tr("le débit que srv5 reçoit de guest5 est limité (iperf3)"))

        q5_answers = {"policing_unit": "kbps", "qos_unit": "bps"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Les unités de la qualité de service"),
            hash="18cf566d00c22d57",
            description=tr("""
Sections @@ref:policing@@ et @@ref:htb@@.

- l'unité de `ingress_policing_rate` : @@{policing_unit:>bit/s>>>bps|octets/s>>>Bps|kbit/s>>>kbps|paquets/s>>>pps}@@
- l'unité de `other_config:max-rate` d'une QoS ou d'une file : @@{qos_unit:>kbit/s>>>kbps|Mbit/s>>>mbps|bit/s>>>bps|octets/s>>>Bps}@@
""")
            + instructor(tr("**Réponses.** kbit/s ; bit/s.")),
            cheat_answers={"final": q5_answers, "solve_part5": q5_answers},
        )
        self.add_grade_element(title=no_tr("answer_policing_unit"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(q5.get("policing_unit") == "kbps"), description=tr("l'unité de la limitation"))
        self.add_grade_element(title=no_tr("answer_qos_unit"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
                               grade=int(q5.get("qos_unit") == "bps"), description=tr("l'unité d'une QoS"))

        # =====================================================================
        # Bonus — files d'attente HTB
        # =====================================================================
        bonus = self.add_grade_part(no_tr("bonus"), tr("Bonus — Files d'attente HTB"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une file d'attente pour h5b"),
            hash="449bcf99849a0b26",
            description=tr("""
Section @@ref:htb@@. Sur le port de `srv5` (`eth4`) de `sw5`, créez une QoS `linux-htb` de débit maximal
{maxm} Mbit/s avec deux files : la file 0 ({maxm} Mbit/s) et la file {qid}, limitée à **{qrate} kbit/s**.
Faites passer par la file {qid} le trafic IP émis par `h5b` (une entrée de flux avec `set_queue`), le
reste du trafic restant traité en `NORMAL`. Mesurez : `iperf3 -c srv5 -p {qport} -u -b {qsent}k` depuis
`h5b`, puis depuis `h5a`.
""").format(maxm=QOS_MAX_RATE // 1_000_000, qid=QUEUE_ID, qrate=d.queue_rate, qport=IPERF_QUEUE_PORT,
            qsent=IPERF_FACTOR * d.queue_rate)
            + instructor(
                tr("""
**Solution.**

```
ovs-vsctl -- set port eth4 qos=@q \\
          -- --id=@q create qos type=linux-htb other_config:max-rate={maxr} queues:0=@q0 queues:{qid}=@q1 \\
          -- --id=@q0 create queue other_config:max-rate={maxr} \\
          -- --id=@q1 create queue other_config:max-rate={qbps}
ovs-ofctl -O OpenFlow13 add-flow br0 "{flow}"
```

`h5b` est limité à environ {qrate} kbit/s, `h5a` ne l'est pas (file 0).
""").format(maxr=QOS_MAX_RATE, qid=QUEUE_ID, qbps=d.queue_rate * 1000, flow=self.net_scheme.queue_flow(), qrate=d.queue_rate)
            ),
        )
        srv_port = st5.port_of(SW5_PORTS["srv5"])
        qos = srv_port.qos if srv_port is not None else None
        good_queues = sorted(n for n, q in (qos.queues.items() if qos is not None else ())
                             if q.other_config.get("max-rate") == str(d.queue_rate * 1000))
        qos_ok = qos is not None and qos.type == "linux-htb" and bool(good_queues)
        self.add_grade_element(title=no_tr("bonus_qos"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(qos_ok),
                               description=tr("une QoS linux-htb sur le port de srv5, avec une file au débit demandé"))
        h5b_match = {("ipv4_src", ip("h5b")), ("in_port", str(d.ofport5("h5b"))), ("eth_src", mac("h5b"))}
        queued = qos_ok and any(set(_queue_ids(f)) & set(good_queues) and f.outputs()
                                and set(f.fields().items()) & h5b_match for f in flows5)
        self.add_grade_element(title=no_tr("bonus_flow"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(queued),
                               description=tr("une entrée de flux envoie le trafic de h5b dans cette file"))
        queue_kbps = _kbps(iperf_queue)
        self.add_grade_element(title=no_tr("bonus_rate"), max_grade=2, grade_part=bonus, bonus=True,
                               grade=2 * int(queued and RATE_LOW * d.queue_rate <= queue_kbps <= RATE_HIGH * d.queue_rate),
                               description=tr("le débit que srv5 reçoit de h5b est limité (iperf3)"))


_TRANSLATIONS = {
    'en': {
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les valeurs de ce
projet. Les états `solve_part1` à `solve_part5` et `solve_bonus` appliquent la solution d'une partie,
`final` toutes ; ils remplissent les formulaires.

- `tor2` : agrégat `bond0` (`eth0`, `eth1`), LACP actif rapide, `balance-tcp`, `lacp-system-id` {sysid}.
- `fw4` : numéros OpenFlow {ofports4} ; `sw5` : {ofports5}.
- L'évaluation, en trois étapes : `ovs-vsctl list`, `bond/show`, `lacp/show`, `dump-flows` sur les switchs ;
  ping entre les machines des parties 1 à 3 (et ping DF de {df} octets dans la partie 3) ; requêtes HTTP
  vers les serveurs d'écho de `web4` (port {web}) et `client4` (port {cport}) ; deux `ofproto/trace
  --ct-next trk,new` et `dpctl/dump-conntrack` sur `fw4` ; une capture ICMP sur `ids5` pendant un ping de
  `h5b` vers `h5a` ; iperf3 UDP de `guest5` vers `srv5` à {gsent} kbit/s et de `h5b` vers `srv5` à {qsent}
  kbit/s.
""":
            """
**For the instructor.** Each question ends with its solution, computed for the values of this
project. The states `solve_part1` to `solve_part5` and `solve_bonus` apply the solution of one part,
`final` all of them; they fill the forms.

- `tor2`: bond `bond0` (`eth0`, `eth1`), fast active LACP, `balance-tcp`, `lacp-system-id` {sysid}.
- `fw4`: OpenFlow port numbers {ofports4}; `sw5`: {ofports5}.
- The evaluation, in three steps: `ovs-vsctl list`, `bond/show`, `lacp/show`, `dump-flows` on the switches;
  ping between the machines of parts 1 to 3 (and a DF ping of {df} bytes in part 3); HTTP requests to the
  echo servers of `web4` (port {web}) and `client4` (port {cport}); two `ofproto/trace --ct-next trk,new`
  and `dpctl/dump-conntrack` on `fw4`; an ICMP capture on `ids5` during a ping from `h5b` to `h5a`; UDP
  iperf3 from `guest5` to `srv5` at {gsent} kbit/s and from `h5b` to `srv5` at {qsent} kbit/s.
""",
        """
**Solution.**

```
# sw1a et sw1b
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 trunks={trunks}
ovs-vsctl add-port br0 eth1 tag={vu}
ovs-vsctl add-port br0 eth2 tag={vs}
# sw1a seulement
ovs-vsctl add-port br0 gw-users tag={vu} -- set interface gw-users type=internal
ovs-vsctl add-port br0 gw-servers tag={vs} -- set interface gw-servers type=internal
ip addr add {gwu} dev gw-users
ip addr add {gws} dev gw-servers
ip link set gw-users up
ip link set gw-servers up
```

Sur `sw1a`, `fdb/show` montre les adresses de `user1b` et `srv1b` apprises sur le port du trunk, chacune
dans son VLAN.
""":
            """
**Solution.**

```
# sw1a and sw1b
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 trunks={trunks}
ovs-vsctl add-port br0 eth1 tag={vu}
ovs-vsctl add-port br0 eth2 tag={vs}
# sw1a only
ovs-vsctl add-port br0 gw-users tag={vu} -- set interface gw-users type=internal
ovs-vsctl add-port br0 gw-servers tag={vs} -- set interface gw-servers type=internal
ip addr add {gwu} dev gw-users
ip addr add {gws} dev gw-servers
ip link set gw-users up
ip link set gw-servers up
```

On `sw1a`, `fdb/show` shows the addresses of `user1b` and `srv1b` learned on the trunk port, each in its
VLAN.
""",
        """**Réponses.** Achemine tous les VLAN ; port d'accès du VLAN 10 (`trunks` ignoré, avec un avertissement dans le journal) ; `internal` ; 65534 (le port `LOCAL`).""":
            """**Answers.** Carries every VLAN; access port of VLAN 10 (`trunks` ignored, with a warning in the log); `internal`; 65534 (the `LOCAL` port).""",
        """
**Solution.**

```
ovs-vsctl add-bond br0 bond0 eth0 eth1 bond_mode=balance-tcp lacp=active other_config:lacp-time=fast
```

Deux ports ordinaires feraient deux chemins parallèles entre `hv2` et `tor2` : une boucle, sans STP. Ici
`tor2`, qui attend LACP, laisse ses liens désactivés tant que la négociation n'a pas eu lieu (rien ne
passe). Lien coupé : le membre passe `disabled`, le trafic continue sur l'autre.
""":
            """
**Solution.**

```
ovs-vsctl add-bond br0 bond0 eth0 eth1 bond_mode=balance-tcp lacp=active other_config:lacp-time=fast
```

Two ordinary ports would make two parallel paths between `hv2` and `tor2`: a loop, without STP. Here
`tor2`, which expects LACP, keeps its links disabled as long as the negotiation has not happened (nothing
goes through). Link cut: the member becomes `disabled`, the traffic goes on over the other one.
""",
        """**Réponses.** `{sysid}` (`partner sys_id` de `lacp/show`) ; `balance-tcp` ; 2 (un par membre).""":
            """**Answers.** `{sysid}` (`partner sys_id` of `lacp/show`); `balance-tcp`; 2 (one per member).""",
        """
**Solution.**

```
# hv3a
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rta}
ovs-vsctl add-port br-int eth2 tag={bta}
ovs-vsctl add-port br-int vxlan-red tag={rta} -- set interface vxlan-red type=vxlan options:remote_ip={hv3b} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={bta} -- set interface geneve-blue type=geneve options:remote_ip={hv3b} options:key={vb}
ip link set eth0 mtu {mtu}
# hv3b
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rtb}
ovs-vsctl add-port br-int eth2 tag={btb}
ovs-vsctl add-port br-int vxlan-red tag={rtb} -- set interface vxlan-red type=vxlan options:remote_ip={hv3a} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={btb} -- set interface geneve-blue type=geneve options:remote_ip={hv3a} options:key={vb}
ip link set eth0 mtu {mtu}
```

La capture montre des paquets UDP entre les deux hyperviseurs, port 4789 (VXLAN, `vni {vr}`) et 6081
(Geneve), qui contiennent les trames des machines virtuelles. Avec une MTU de 1500, le ping DF de 1500
octets échoue : l'hyperviseur renvoie un *fragmentation needed* (MTU 1450).
""":
            """
**Solution.**

```
# hv3a
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rta}
ovs-vsctl add-port br-int eth2 tag={bta}
ovs-vsctl add-port br-int vxlan-red tag={rta} -- set interface vxlan-red type=vxlan options:remote_ip={hv3b} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={bta} -- set interface geneve-blue type=geneve options:remote_ip={hv3b} options:key={vb}
ip link set eth0 mtu {mtu}
# hv3b
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int eth1 tag={rtb}
ovs-vsctl add-port br-int eth2 tag={btb}
ovs-vsctl add-port br-int vxlan-red tag={rtb} -- set interface vxlan-red type=vxlan options:remote_ip={hv3a} options:key={vr}
ovs-vsctl add-port br-int geneve-blue tag={btb} -- set interface geneve-blue type=geneve options:remote_ip={hv3a} options:key={vb}
ip link set eth0 mtu {mtu}
```

The capture shows UDP packets between the two hypervisors, port 4789 (VXLAN, `vni {vr}`) and 6081
(Geneve), carrying the frames of the virtual machines. With an MTU of 1500, the DF ping of 1500 bytes
fails: the hypervisor sends back a *fragmentation needed* (MTU 1450).
""",
        """**Réponses.** 4789 ; 6081 ; 50 (14 + 20 + 8 + 8) ; `vxlan_sys_4789`.""":
            """**Answers.** 4789; 6081; 50 (14 + 20 + 8 + 8); `vxlan_sys_4789`.""",
        """
**Solution.** `/root/fw.flows`, puis `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/fw.flows` :

```
{flows}```

La trace du SYN+ACK sans connexion se termine par `Datapath actions: drop` (état `new`, aucune entrée ne
l'autorise) ; une règle sans état `tcp,nw_src=web4,tp_src={web},actions=NORMAL` le laisserait passer.
""":
            """
**Solution.** `/root/fw.flows`, then `ovs-ofctl -O OpenFlow13 replace-flows br0 /root/fw.flows`:

```
{flows}```

The trace of the SYN+ACK without connection ends with `Datapath actions: drop` (state `new`, no entry
allows it); a stateless rule `tcp,nw_src=web4,tp_src={web},actions=NORMAL` would let it through.
""",
        """**Réponses.** `+trk+new` ; `est` (`rpl` ne marque que le sens de la réponse) ; `commit`.""":
            """**Answers.** `+trk+new`; `est` (`rpl` marks the reply direction only); `commit`.""",
        """
**Solution.**

```
ovs-vsctl -- --id=@a get port eth0 -- --id=@ids get port eth2 \\
          -- --id=@m create mirror name=span select_src_port=@a select_dst_port=@a output_port=@ids \\
          -- set bridge br0 mirrors=@m
ovs-vsctl set interface eth3 ingress_policing_rate={rate} ingress_policing_burst={burst}
```

`tcpdump -n -i eth0 icmp` sur `ids5` montre les demandes et les réponses entre `h5b` et `h5a`. iperf3
envoie {sent} kbit/s ; `srv5` en reçoit environ {rate}.
""":
            """
**Solution.**

```
ovs-vsctl -- --id=@a get port eth0 -- --id=@ids get port eth2 \\
          -- --id=@m create mirror name=span select_src_port=@a select_dst_port=@a output_port=@ids \\
          -- set bridge br0 mirrors=@m
ovs-vsctl set interface eth3 ingress_policing_rate={rate} ingress_policing_burst={burst}
```

`tcpdump -n -i eth0 icmp` on `ids5` shows the requests and the replies between `h5b` and `h5a`. iperf3
sends {sent} kbit/s; `srv5` receives about {rate}.
""",
        """**Réponses.** kbit/s ; bit/s.""":
            """**Answers.** kbit/s; bit/s.""",
        """
**Solution.**

```
ovs-vsctl -- set port eth4 qos=@q \\
          -- --id=@q create qos type=linux-htb other_config:max-rate={maxr} queues:0=@q0 queues:{qid}=@q1 \\
          -- --id=@q0 create queue other_config:max-rate={maxr} \\
          -- --id=@q1 create queue other_config:max-rate={qbps}
ovs-ofctl -O OpenFlow13 add-flow br0 "{flow}"
```

`h5b` est limité à environ {qrate} kbit/s, `h5a` ne l'est pas (file 0).
""":
            """
**Solution.**

```
ovs-vsctl -- set port eth4 qos=@q \\
          -- --id=@q create qos type=linux-htb other_config:max-rate={maxr} queues:0=@q0 queues:{qid}=@q1 \\
          -- --id=@q0 create queue other_config:max-rate={maxr} \\
          -- --id=@q1 create queue other_config:max-rate={qbps}
ovs-ofctl -O OpenFlow13 add-flow br0 "{flow}"
```

`h5b` is limited to about {qrate} kbit/s, `h5a` is not (queue 0).
""",
    },
}
