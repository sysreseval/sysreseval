"""VLAN lab (TP7 VLAN of the R306 course, converted from the Marionnet handout): 802.1Q
sub-interfaces, Linux bridges extending a VLAN to untagged ports, a router on a stick between
the two VLANs, source NAT, a new machine plugged on a free port of the managed switch, a brouter
(the nftables bridge family diverting some frames to the IP stack) and its effect on the TTL.

Topology (the figure of the handout)::

                     ext2                                                  m1
                      |                                                     | eth1
     [internet] -- switch ext -- eth0 router2 eth1 ---+            eth0     |   eth2
                      |                               |        +--------- b1 ------- m2
                     ext1        eth0 router eth1 -- switch trunk
                                                               | eth0
                                          m3 -- switch odd -- b2 -- switch even -- m4
                                                  |        eth1  eth2      |
                                                 m5                        m6

`trunk` is a managed switch: the ports of `b1`, `b2`, `router` and `router2` are trunks carrying
VLAN 111 (odd machines) and VLAN 222 (even machines) tagged, the untagged frames stay in the
default VLAN of the switch (the `trunk` network); `m7` is plugged on a free port in the default
VLAN.  The odd machines m1, m3, m5 share the `odd` network, the even ones m2, m4, m6 the `even`
network; the bridges `brodd` / `breven` of b1 and b2 (`brimpair` / `brpair` of the handout)
extend the two VLANs to them.  Every machine runs an HTTP echo server on ports 80 and 8080
(`lib/http_echo.py`: the page shows the client address the server sees and the TTL of its SYN),
which the students and the grader use to tell which router a request went through.

The addressing is chosen by a startup form (``Flavor``): random private networks (default) or the
networks of the handout; the host parts are those of the handout in both cases.  The ``final``
state applies the reference solution.  Every question ends with its solution in an
instructor-only block.  Texts are French (``tr()``), identifiers English.

The brouter uses nftables (the image's ebtables 1.8.9 is the nft flavour without the ``broute``
table, and its nftables 1.0.6 has no ``meta broute``): a *bridge* family rule in the prerouting
hook rewriting the destination MAC to the bridge's own one and the packet type to ``host``, so
that the bridge delivers the frame to its IP stack where it is routed (what ``ebtables -j
redirect`` did).  Verified live on 2026-10-09 (Linux 6.12).
"""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, Flavor0, Grade0, NetScheme0, instructor, make_tr, no_tr, sre_state
from firewall import get_ruleset
from ips import random_ipv4networks
from net_config import get_ip_forward, get_routes, set_ip_forward
from state_helpers import create_hosts_file
from switch import get_switch_ports
from vlan import (
    addresses_of, bridge_ports, broute_rules_for, get_http_echo, get_ip_addresses_json, get_ip_links,
    get_mangle_rules, get_sysctl_int, install_http_echo, interface_of_address, parse_broute_rules, ttl_rules,
    vlan_links,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("VLAN, ponts et brouter")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
allow_user_states = True
export_kathara_project = True
# An evaluation runs about twenty pings and HTTP requests from the students' machines.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

flavor_form_at_startup = True

VLAN_ODD = 111
VLAN_EVEN = 222
HTTP_PORTS = (80, 8080)
DOMAIN = "lab"
DEFAULT_TTL = 64
TTL_M5 = 90          # question 9c: the default TTL set on m5
BROUTER_TABLE = "brouter"
BROUTER_CHAIN = "prerouting"

#: the networks of the handout (flavor "fixed"); the host parts below are used in both flavors
FIXED_NETWORKS = {'odd': IPv4Network("192.168.11.0/24"), 'even': IPv4Network("192.168.22.0/24"),
                  'trunk': IPv4Network("10.10.10.0/24"), 'ext': IPv4Network("172.17.1.0/24")}
HOST_PARTS = {'m1': 1, 'm2': 2, 'm3': 3, 'm4': 4, 'm5': 5, 'm6': 6, 'm7': 7, 'b1': 101, 'b2': 102,
              'router': 254, 'router2': 200, 'ext1': 51, 'ext2': 52}
#: (machine, network) pairs that get an address: ips.<m> for a machine with one address,
#: ips.<m>_<net> otherwise (b1_odd / b2_odd are the addresses of the bridges brodd, question 2/4)
ADDRESSED = [('m1', 'odd'), ('m2', 'even'), ('m3', 'odd'), ('m4', 'even'), ('m5', 'odd'), ('m6', 'even'),
             ('m7', 'odd'), ('ext1', 'ext'), ('ext2', 'ext'),
             ('b1', 'trunk'), ('b1', 'odd'), ('b2', 'trunk'), ('b2', 'odd'),
             ('router', 'ext'), ('router', 'trunk'), ('router', 'odd'), ('router', 'even'),
             ('router2', 'ext'), ('router2', 'trunk'), ('router2', 'odd'), ('router2', 'even')]
SINGLE_HOMED = ('m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'ext1', 'ext2')
ODD_MACHINES = ('m1', 'm3', 'm5')
EVEN_MACHINES = ('m2', 'm4', 'm6')

_TOPOLOGY = {
    'ext': {'router': 0, 'router2': 0, 'ext1': 0, 'ext2': 0},
    'trunk': {'router': 1, 'router2': 1, 'b1': 0, 'b2': 0, 'm7': 0},
    # b1 is cabled directly to m1 and m2
    'link1': {'b1': 1, 'm1': 0},
    'link2': {'b1': 2, 'm2': 0},
    # b2 reaches m3 / m5 and m4 / m6 through two switches
    'odd': {'b2': 1, 'm3': 0, 'm5': 0},
    'even': {'b2': 2, 'm4': 0, 'm6': 0},
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
        + tr("**Adresses IP des réseaux :**\n")
        + tr("@@{ip_choice:>Aléatoires, propres à cette instance>>>random|"
             "Celles du sujet : 192.168.11.0/24, 192.168.22.0/24, 10.10.10.0/24, 172.17.1.0/24>>>fixed}@@\n\n")
        + tr("Les numéros de machine sont les mêmes dans les deux cas (`m3` = `.3`, `b1` = `.101`, `router` = `.254`...).\n\n")
        + tr("@@{name::Démarrer le projet}@@")
    )


Flavor.random = Flavor(ip_choice="random")
Flavor.fixed = Flavor(ip_choice="fixed")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _ips_key(machine: str, net: str) -> str:
    return machine if machine in SINGLE_HOMED else f"{machine}_{net}"


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
            ext, trunk, odd, even = random_ipv4networks(
                masks=[24, 24, 24, 24], from_private_network=True,
                exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
            nets = {'odd': odd, 'even': even, 'trunk': trunk, 'ext': ext}
        for name, net in nets.items():
            setattr(data.nets, name, net)
        for machine, net in ADDRESSED:
            setattr(data.ips, _ips_key(machine, net),
                    IPv4Interface(f"{nets[net].network_address + HOST_PARTS[machine]}/{nets[net].prefixlen}"))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = {
        'router': {'color': 'lightgreen'},
        'router2': {'color': 'lightgreen'},
        'b1': {'color': 'lightyellow'},
        'b2': {'color': 'lightyellow'},
        'm1': {}, 'm2': {}, 'm3': {}, 'm4': {}, 'm5': {}, 'm6': {},
        # the "new machine" of question 7: unconfigured, on a free port of the trunk switch
        'm7': {'color': 'lightcyan'},
        'ext1': {'color': 'lightgrey'},
        'ext2': {'color': 'lightgrey'},
    }
    _network_specs = {
        'ext': {'mode': 'switch', 'color': 'lightgrey'},
        # the managed switch: trunk ports for the two bridges and the two routers (VLAN 111 and
        # 222 tagged, the untagged frames in the default VLAN); m7 has no entry: default VLAN
        'trunk': {'mode': 'managed', 'color': 'lightyellow',
                  'vlans': {m: [VLAN_ODD, VLAN_EVEN] for m in ('b1', 'b2', 'router', 'router2')}},
        'odd': {'mode': 'switch', 'color': 'mistyrose'},
        'even': {'mode': 'switch', 'color': 'lightcyan'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("""
**Sommaire**

1. Rappels : hub, switch, domaine de diffusion
2. Les VLAN et l'étiquetage 802.1Q
3. Les VLAN sous Linux : sous-interfaces
4. Les ponts (*bridges*) Linux
5. Routage entre VLAN : le routeur « on a stick »
6. Traduction d'adresses source (NAT)
7. Le switch administrable et sa console
8. Le *brouter* : ponter ou router ?
9. Le TTL
10. Aide-mémoire
11. Plan du TP
""")
            + tr("""
## 1. Rappels : hub, switch, domaine de diffusion

Un **hub** répète chaque trame sur tous ses ports : toutes les machines voient tout le trafic.
Un **switch** (commutateur) apprend, pour chaque port, les adresses MAC des machines qui y sont
branchées (sa *table MAC*, ou table de commutation) et ne transmet une trame que sur le port de
son destinataire ; les trames de diffusion (*broadcast*, `ff:ff:ff:ff:ff:ff`, par exemple les
requêtes ARP) et celles dont le destinataire est inconnu sont envoyées sur tous les ports. Toutes
les machines reliées par des hubs et des switchs forment un seul **domaine de diffusion** : un
réseau IP (un préfixe, `192.168.11.0/24`) occupe normalement un domaine de diffusion. Pour
séparer deux réseaux IP, il faut soit deux switchs physiques, soit... des VLAN.
""")
            + tr("""
## 2. Les VLAN et l'étiquetage 802.1Q

Un **VLAN** (*Virtual LAN*) découpe un switch physique en plusieurs switchs logiques : chaque
port appartient à un VLAN et une trame n'est jamais transmise d'un VLAN à un autre. Deux
machines dans des VLAN différents ne se voient pas, même branchées côte à côte ; pour qu'elles
communiquent il faut un **routeur** (niveau 3), exactement comme entre deux réseaux physiques.
Les VLAN servent à séparer des populations (étudiants / administration / téléphonie), à limiter
les domaines de diffusion, et à déplacer une machine de réseau sans toucher au câblage.

Pour que deux switchs partagent les mêmes VLAN sur un seul câble, chaque trame qui transite sur
ce câble porte une **étiquette** (*tag*) disant à quel VLAN elle appartient : c'est la norme
**IEEE 802.1Q**. L'étiquette fait **4 octets** et s'insère dans l'en-tête Ethernet, entre
l'adresse MAC source et le champ *type* :

| champ | taille | contenu |
|-------|--------|---------|
| TPID (*Tag Protocol Identifier*) | 16 bits | `0x8100` : « cette trame porte une étiquette » (le vrai type suit) |
| PCP (*Priority Code Point*) | 3 bits | priorité 802.1p (0 à 7) |
| DEI (*Drop Eligible Indicator*) | 1 bit | trame jetable en cas de congestion |
| VID (*VLAN Identifier*) | 12 bits | numéro du VLAN, 1 à 4094 (0 = pas de VLAN, étiquette de priorité seule ; 4095 réservé) |

Une trame Ethernet étiquetée peut donc faire 1522 octets au lieu de 1518. Un port de switch est :

- un **port d'accès** (*access*, *untagged*) : la machine branchée ignore les VLAN, elle émet et
  reçoit des trames normales ; le switch affecte ses trames au VLAN du port et retire
  l'étiquette avant de lui livrer une trame ;
- un **port trunk** (*tagged*) : les trames y circulent **avec** leur étiquette, pour un ou
  plusieurs VLAN ; c'est le cas entre deux switchs, ou vers un routeur ou un serveur qui
  gère lui-même les VLAN. Les trames sans étiquette arrivant sur un trunk sont placées dans
  le **VLAN natif** du port (sur le switch de ce TP : le VLAN 0, VLAN par défaut).

Un switch **administrable** (*managed*) est un switch que l'on configure (ports, VLAN, table
MAC...) par une console ; un switch non administrable n'a qu'un seul VLAN.
""")
            + tr("""
## 3. Les VLAN sous Linux : sous-interfaces

Linux sait étiqueter et désétiqueter lui-même (module `8021q`) : une **sous-interface** VLAN
est une interface virtuelle au-dessus d'une interface physique, qui émet des trames étiquetées
d'un VLAN donné et ne reçoit que celles de ce VLAN, désétiquetées. Elle se configure comme une
interface ordinaire (adresse IP, routes, pont...) :

```
ip link add link eth0 name eth0.111 type vlan id 111   # crée eth0.111 (VLAN 111 sur eth0)
ip link set eth0.111 up
ip address add 192.168.11.101/24 dev eth0.111
ip -d link show eth0.111                               # vlan protocol 802.1Q id 111
ip link del eth0.111                                   # supprime la sous-interface
```

Le nom `eth0.111` n'est qu'une convention (c'est l'option `id` qui compte). L'interface
physique `eth0` reste utilisable pour le trafic **non étiqueté** (VLAN natif du port en face).

On observe l'étiquette avec `tcpdump -e` (`-e` affiche l'en-tête Ethernet) : sur `eth0`,
`tcpdump -e -n -i eth0` montre les trames avec `ethertype 802.1Q (0x8100), ... vlan 111, p 0,
ethertype IPv4` ; sur `eth0.111`, les mêmes trames apparaissent sans étiquette. Dans Wireshark,
filtre `vlan` et champ *802.1Q Virtual LAN* ; le module `vlan` de Debian permet aussi la
configuration persistante dans `/etc/network/interfaces` (`iface eth0.111 inet static` avec
`vlan-raw-device eth0`).
""")
            + tr("""
## 4. Les ponts (*bridges*) Linux

Un **pont** Linux est un switch logiciel : une interface virtuelle `brX` à laquelle on rattache
des **ports** (des interfaces physiques ou virtuelles). Les trames reçues sur un port sont
commutées vers les autres selon la table MAC du pont, apprise comme sur un switch (`bridge fdb
show`). Les ports n'ont **pas** d'adresse IP : c'est le pont lui-même qui en porte une, si la
machine doit être joignable (le pont joue alors le rôle du switch *et* d'une machine branchée
dessus).

```
ip link add brpair type bridge           # crée le pont
ip link set eth2 master brpair           # eth2 devient un port du pont
ip link set eth0.222 master brpair       # la sous-interface VLAN aussi
ip link set brpair up                    # (et les ports doivent être up)
bridge link                              # ports de chaque pont, état
bridge fdb show br brpair                # table MAC du pont
ip link set eth2 nomaster                # retire un port
ip link del brpair
```

(`brctl addbr`, `brctl addif`, `brctl show` du paquet `bridge-utils` font la même chose.)

Ponter une **sous-interface VLAN** avec une interface physique **prolonge le VLAN** : les trames
qui entrent sans étiquette par `eth2` ressortent étiquetées 222 par `eth0`, et inversement. La
machine Linux devient ainsi un port d'accès du VLAN 222 pour ce qui est branché sur `eth2` : un
switch d'accès à deux ports, réalisé en logiciel. Si la machine Linux doit elle-même avoir une
adresse dans ce VLAN, l'adresse va sur le **pont** (pas sur `eth0.222`, devenue un simple port).
La configuration persistante (`/etc/network/interfaces`, `bridge_ports eth2 eth0.222`) est
du ressort du paquet `bridge-utils`.
""")
            + tr("""
## 5. Routage entre VLAN : le routeur « on a stick »

Deux VLAN sont deux réseaux IP : pour qu'ils communiquent, un routeur doit avoir une interface
(une adresse) dans chacun. Plutôt qu'un câble par VLAN, un seul port **trunk** suffit : le
routeur crée une sous-interface par VLAN (`eth1.111`, `eth1.222`), chacune avec l'adresse qui
sert de **passerelle par défaut** aux machines du VLAN. C'est le routeur *on a stick*
(« sur un bâton ») : tout le trafic inter-VLAN entre et ressort par le même câble.

```
ip link add link eth1 name eth1.111 type vlan id 111 ; ip address add 192.168.11.254/24 dev eth1.111 ; ip link set eth1.111 up
ip link add link eth1 name eth1.222 type vlan id 222 ; ip address add 192.168.22.254/24 dev eth1.222 ; ip link set eth1.222 up
sysctl -w net.ipv4.ip_forward=1          # activer le routage (volatile ; /etc/sysctl.conf pour le rendre persistant)
```

Sans `ip_forward=1`, un hôte Linux reçoit les paquets destinés à d'autres mais ne les retransmet
pas. Les machines des deux VLAN doivent avoir ce routeur comme route par défaut (`ip route`).
""")
            + tr("""
## 6. Traduction d'adresses source (NAT)

Les réseaux internes utilisent des adresses privées (RFC 1918) que l'extérieur ne sait pas
router. Le routeur de sortie réécrit l'adresse **source** des paquets sortants avec la sienne
(*SNAT*, *masquerade*), note la correspondance dans sa table de suivi de connexions (*conntrack*)
et fait la réécriture inverse sur les réponses. Vu de l'extérieur, tout le trafic semble venir
du routeur.

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE         # iptables (nft en coulisse)
iptables -t nat -S                                            # vérifier
```

ou, en nftables natif :

```
nft add table ip nat
nft 'add chain ip nat postrouting { type nat hook postrouting priority 100; }'
nft add rule ip nat postrouting oifname "eth0" masquerade
nft list ruleset
```

Dans ce TP, chaque machine sert une page web (`curl http://ext1/`, `curl http://ext1:8080/`)
qui affiche l'adresse du client **telle que le serveur la voit** (`CLIENT_IP=`) : derrière un
NAT, c'est l'adresse du routeur qui apparaît, ce qui permet de savoir par quel routeur une
requête est sortie. La page donne aussi le `TTL=` du paquet reçu (partie 9).
""")
            + tr("""
## 7. Le switch administrable et sa console

Le réseau `trunk` est un switch administrable (un `vde_switch`) : onglet **Réseaux**, bouton
*Connecter* (ou onglet **Terminaux**) ouvre sa console. Les commandes utiles :

```
port/print                   ports utilisés : VLAN non étiqueté (untagged_vlan), machine branchée
port/allprint                tous les ports
vlan/print                   VLAN et leurs ports (tagged=1 : port trunk pour ce VLAN)
port/setvlan <port> <vlan>   VLAN non étiqueté (d'accès) d'un port
vlan/create <vlan>           crée un VLAN
vlan/addport <vlan> <port>   ajoute un port étiqueté (trunk) à un VLAN
vlan/delport <vlan> <port>   le retire
hash/print                   table des adresses MAC
help                         liste des commandes
exit                         ferme la console
```

`port/print` décrit chaque port par la machine branchée (`kathara m7:eth0`) : le **numéro de
port** n'est pas prévisible, lisez-le dans cette sortie. Le VLAN `0000` est le VLAN par défaut
du switch (les ports non configurés et les trames non étiquetées des trunks).
""")
            + tr("""
## 8. Le *brouter* : ponter ou router ?

Une machine qui a un pont **et** des adresses IP fait les deux : pour chaque trame reçue sur un
port du pont, elle regarde l'adresse MAC de destination. Si c'est celle du pont (ou d'un de ses
ports), la trame lui est destinée : elle remonte dans la pile IP, où elle est livrée localement
ou **routée** ; sinon elle est **pontée** (commutée) vers un autre port sans que la couche IP
ne la voie. Un *brouter* (*bridge* + *router*) est une machine qui prend cette décision **par
règle** et non seulement d'après l'adresse MAC : telles trames sont pontées, telles autres sont
routées. Les machines branchées derrière lui continuent de croire que leur routeur est celui
qu'elles ont configuré, alors que leurs paquets suivent un autre chemin.

Sous Linux, cette décision se prend avec la famille **bridge** de **nftables** : ses chaînes
s'accrochent sur le trajet des trames **dans le pont**, et son hook `prerouting` est traversé
avant que le pont ne commute la trame. Deux actions y suffisent pour détourner une trame vers
la pile IP :

- `ether daddr set <MAC du pont>` : réécrit l'adresse MAC de destination avec celle du pont
  (lisible par `ip link show brimpair` ou `cat /sys/class/net/brimpair/address`) : le pont livre
  alors la trame à la machine elle-même ;
- `meta pkttype set host` : marque la trame « pour cet hôte » (sinon la pile IP la jette comme
  adressée à quelqu'un d'autre, `PACKET_OTHERHOST`).

```
nft add table bridge brouter
nft 'add chain bridge brouter prerouting { type filter hook prerouting priority -300; policy accept; }'
nft add rule bridge brouter prerouting iifname "eth1" ip saddr 192.168.11.3 \\
    meta pkttype set host ether daddr set $(cat /sys/class/net/brimpair/address)
nft list ruleset                           # voir ; nft flush table bridge brouter pour vider
```

Les critères disponibles : `iifname` (port d'entrée), `ip saddr`, `ip daddr`, `ip protocol`,
`tcp dport`, `udp dport`, `ether saddr`... Un paquet ainsi détourné est ensuite traité comme
n'importe quel paquet reçu : table de routage de la machine (`ip route`), règles `iptables` /
`nft` des familles `ip` / `inet` (il traverse la chaîne `PREROUTING` puis `FORWARD`), et le
routage **décrémente son TTL**. Les réponses, elles, reviennent par le chemin normal (le routeur
qui a fait le NAT connaît le VLAN de la machine) : le pont les commute sans les voir passer par
la couche IP.

Historiquement c'est le rôle de la table `broute` d'`ebtables` (chaîne `BROUTING`, cible `redirect
--redirect-target DROP`, où « DROP » signifie « router ») ; l'`ebtables` de Debian 12 est une
réimplémentation sur nftables sans cette table, et `meta broute set 1` n'existe que dans les
nftables récents (≥ 1.0.7). Le mécanisme ci-dessus est l'équivalent de la cible `redirect`.
""")
            + tr("""
## 9. Le TTL

Le champ **TTL** (*Time To Live*, 8 bits) d'un paquet IPv4 est décrémenté par **chaque routeur**
traversé ; à zéro, le paquet est détruit et un message ICMP *Time exceeded* est renvoyé à
l'émetteur (c'est ce qu'exploite `traceroute`). Il protège le réseau des boucles de routage. Un
**pont** ou un switch ne le touche pas (niveau 2). Linux émet avec un TTL initial de 64
(`sysctl net.ipv4.ip_default_ttl`, à changer par `sysctl -w` ; `sysctl -a` liste tous les
paramètres du noyau) ; Windows 128, les routeurs Cisco 255.

Sur `ext1`, on lit le TTL des paquets reçus avec `tcpdump -n -v -i eth0 tcp` (champ `ttl` de la
première ligne de chaque paquet), `tshark -i eth0 -V` (*Time to Live*) ou Wireshark ; la page
web des machines de ce TP l'affiche aussi (`TTL=`). Un paquet qui a traversé un routeur arrive
avec 63, deux routeurs 62.

Il est possible de réécrire le TTL dans la table `mangle` d'iptables (cible `TTL`, module
`xt_HL`, voir `man iptables-extensions`) :

```
iptables -t mangle -A PREROUTING -s 192.168.11.3 -j TTL --ttl-inc 1    # +1 (aussi --ttl-dec N, --ttl-set N)
iptables -t mangle -S
```

**Augmenter** le TTL est dangereux : un paquet pris dans une boucle de routage ne meurt plus
jamais. On ne le fait que pour masquer un saut (ici, le brouter) et jamais sur un routeur
d'Internet. (nftables sait seulement fixer une valeur : `ip ttl set 64`.)
""")
            + tr("""
## 10. Aide-mémoire

| besoin | commande |
|--------|----------|
| interfaces, adresses | `ip -br address`, `ip -d link show eth0.111` |
| sous-interface VLAN | `ip link add link eth0 name eth0.111 type vlan id 111` |
| pont | `ip link add br0 type bridge`, `ip link set ethX master br0`, `bridge link`, `bridge fdb show` |
| routes | `ip route`, `ip route add default via A.B.C.D`, `ip route replace default via ...` |
| routage | `sysctl -w net.ipv4.ip_forward=1` |
| NAT | `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` |
| capture | `tcpdump -e -n -i eth0`, `tcpdump -n -v -i eth0 tcp`, `tshark -i eth0 -V`, `wireshark` |
| tester un serveur web | `curl http://ext1/`, `curl http://ext1:8080/` (ou `links`) |
| brouter | `nft add table bridge brouter`, `nft add rule bridge brouter prerouting ...`, `nft list ruleset` |
| TTL | `iptables -t mangle -A PREROUTING -s X -j TTL --ttl-inc 1`, `sysctl -w net.ipv4.ip_default_ttl=90` |
| console du switch | onglet *Réseaux* → *Connecter* : `port/print`, `port/setvlan <port> <vlan>`, `vlan/print` |
""")
            + tr("""
## 11. Plan du TP

1. **Vérification** du réseau `trunk` (b1, b2, router) ;
2. **VLAN 111 et 222** sur `eth0` de b1 et b2, capture sur `eth0` et `eth0.111` ;
3. **Pont `breven`** (eth2 + eth0.222) : m2 joint m4 et m6 ;
4. **Pont `brodd`** (eth1 + eth0.111) : m1 joint m3 et m5 ;
5. **Routeur « on a stick »** : `router` relie les deux VLAN ;
6. **NAT source** sur `router` : tout le monde joint ext1 et ext2 ;
7. **Nouvelle machine `m7`** sur un port libre du switch `trunk` ;
8. **Brouter** sur b2 : le trafic de m3 (puis certains flux) sort par `router2` ;
9. **TTL** : effet du brouter, correction, TTL par défaut.

Les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
en place. Les adresses sont celles de votre instance (onglet *Questions*, première question).
Toute la configuration de ce TP est volatile (`ip`, `nft`, `sysctl -w`) : elle ne survit pas à
un redémarrage d'une machine.
""")
        )

    # -- the commands of the reference solution (used by `final` and the instructor texts) ----

    def cmds_vlan(self, machine: str) -> List[str]:
        """Question 2: the two sub-interfaces of b1 / b2, the odd address on eth0.111."""
        d = self.data
        return [f"ip link add link eth0 name eth0.{VLAN_ODD} type vlan id {VLAN_ODD}",
                f"ip link add link eth0 name eth0.{VLAN_EVEN} type vlan id {VLAN_EVEN}",
                f"ip address add {getattr(d.ips, machine + '_odd')} dev eth0.{VLAN_ODD}",
                f"ip link set eth0.{VLAN_ODD} up", f"ip link set eth0.{VLAN_EVEN} up"]

    def cmds_breven(self) -> List[str]:
        """Question 3: the bridge of the even VLAN (on b1 and on b2)."""
        return ["ip link add breven type bridge", "ip link set eth2 master breven",
                f"ip link set eth0.{VLAN_EVEN} master breven", "ip link set breven up"]

    def cmds_brodd(self, machine: str) -> List[str]:
        """Question 4: the bridge of the odd VLAN, the address moved from eth0.111 to it."""
        address = getattr(self.data.ips, machine + '_odd')
        return ["ip link add brodd type bridge", "ip link set eth1 master brodd",
                f"ip link set eth0.{VLAN_ODD} master brodd", "ip link set brodd up",
                f"ip address del {address} dev eth0.{VLAN_ODD}", f"ip address add {address} dev brodd"]

    def cmds_router_vlans(self, machine: str) -> List[str]:
        """Questions 5 and 8b: the sub-interfaces of a router on its trunk port eth1."""
        d = self.data
        return [f"ip link add link eth1 name eth1.{VLAN_ODD} type vlan id {VLAN_ODD}",
                f"ip address add {getattr(d.ips, machine + '_odd')} dev eth1.{VLAN_ODD}",
                f"ip link set eth1.{VLAN_ODD} up",
                f"ip link add link eth1 name eth1.{VLAN_EVEN} type vlan id {VLAN_EVEN}",
                f"ip address add {getattr(d.ips, machine + '_even')} dev eth1.{VLAN_EVEN}",
                f"ip link set eth1.{VLAN_EVEN} up"]

    def cmds_forward_nat(self) -> List[str]:
        """Questions 5-6 and 8a: forwarding and masquerade of a router (eth0 = ext)."""
        return ["sysctl -w net.ipv4.ip_forward=1", "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"]

    def cmds_m7(self) -> List[str]:
        d = self.data
        return [f"ip address add {d.ips.m7} dev eth0", f"ip route add default via {d.ips.router_odd.ip}"]

    def cmds_b2_default_route(self) -> List[str]:
        return [f"ip route replace default via {self.data.ips.router2_trunk.ip}"]

    def cmds_brouter(self) -> List[str]:
        """Question 8c-d: forwarding on b2 and the two diverting rules of the bridge family."""
        d = self.data
        divert = "meta pkttype set host ether daddr set $(cat /sys/class/net/brodd/address)"
        return ["sysctl -w net.ipv4.ip_forward=1",
                f"nft add table bridge {BROUTER_TABLE}",
                f"nft 'add chain bridge {BROUTER_TABLE} {BROUTER_CHAIN} "
                "{ type filter hook prerouting priority -300; policy accept; }'",
                f"nft add rule bridge {BROUTER_TABLE} {BROUTER_CHAIN} iifname \"eth1\" ip saddr {d.ips.m3.ip} {divert}",
                f"nft add rule bridge {BROUTER_TABLE} {BROUTER_CHAIN} iifname \"eth1\" ip daddr {d.ips.ext2.ip} "
                f"tcp dport {HTTP_PORTS[1]} {divert}"]

    def cmds_ttl(self) -> List[str]:
        return [f"iptables -t mangle -A PREROUTING -s {self.data.ips.m3.ip} -j TTL --ttl-inc 1"]

    def cmds_default_ttl(self) -> List[str]:
        return [f"sysctl -w net.ipv4.ip_default_ttl={TTL_M5}"]

    # -- states -----------------------------------------------------------------------------

    def _configure_network(self):
        d = self.data
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write, which the students need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
        for m in ODD_MACHINES + EVEN_MACHINES:
            gateway = d.ips.router_odd if m in ODD_MACHINES else d.ips.router_even
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0")
            self.cmd(m, f"ip route add default via {gateway.ip}")
        for m in ('b1', 'b2'):
            self.cmd(m, f"ip address add {getattr(d.ips, m + '_trunk')} dev eth0")
            self.cmd(m, f"ip route add default via {d.ips.router_trunk.ip}")
            self.cmd(m, "ip link set eth1 up; ip link set eth2 up")
            # the bridge of question 4 is also the return path of the brouter: no reverse-path check
            self.cmd(m, "sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 >/dev/null")
        for m in ('router', 'router2'):
            self.cmd(m, f"ip address add {getattr(d.ips, m + '_ext')} dev eth0")
            self.cmd(m, f"ip address add {getattr(d.ips, m + '_trunk')} dev eth1")
        for m in ('ext1', 'ext2'):
            self.cmd(m, f"ip address add {getattr(d.ips, m)} dev eth0")
        self.cmd('m7', "ip link set eth0 up")

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        # /etc/hosts: m1..m7, ext1, ext2, b1_trunk, b2_trunk, router_ext, router_trunk, router2_*
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=self.get_machine_names())
        for m in self.get_machine_names():
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
            install_http_echo(net_scheme=self, machine=m, name=m, ports=HTTP_PORTS)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the nine questions, applicable more than once (what an earlier
        application or the students left is removed first)."""
        d = self.data
        for m in ('b1', 'b2'):
            self.cmd(m, f"ip link del brodd 2>/dev/null; ip link del breven 2>/dev/null; "
                        f"ip link del eth0.{VLAN_ODD} 2>/dev/null; ip link del eth0.{VLAN_EVEN} 2>/dev/null; true")
            for c in self.cmds_vlan(m) + self.cmds_breven() + self.cmds_brodd(m):
                self.cmd(m, c)
        for m in ('router', 'router2'):
            self.cmd(m, f"ip link del eth1.{VLAN_ODD} 2>/dev/null; ip link del eth1.{VLAN_EVEN} 2>/dev/null; "
                        "iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null; true")
            for c in self.cmds_router_vlans(m) + self.cmds_forward_nat():
                self.cmd(m, c)
        # question 7: m7 on the odd VLAN (the port number of m7 is resolved by the state machinery)
        self.cmd('m7', f"ip address flush dev eth0; ip route flush default 2>/dev/null; true")
        for c in self.cmds_m7():
            self.cmd('m7', c)
        self.switch_cmd('trunk', f"port/setvlan @m7 {VLAN_ODD}")
        # question 8: b2 routes through router2 the frames the rules divert
        self.cmd('b2', f"nft delete table bridge {BROUTER_TABLE} 2>/dev/null; iptables -t mangle -F PREROUTING; true")
        for c in self.cmds_b2_default_route() + self.cmds_brouter() + self.cmds_ttl():
            self.cmd('b2', c)
        for c in self.cmds_default_ttl():
            self.cmd('m5', c)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _is_int(answer, expected: int) -> bool:
    return _digits(answer) == str(expected)


def _has_vlan(links, ifname: str, parent: str, vid: int) -> bool:
    info = vlan_links(links).get(ifname)
    return bool(info) and info['id'] == vid and info['link'] == parent and info['up']


def _bridge_has(links, bridge: str, *ports: str) -> bool:
    members = bridge_ports(links).get(bridge)
    return members is not None and all(p in members for p in ports)


def _client_is(echo: dict, address) -> bool:
    return bool(echo.get('client_ip')) and echo['client_ip'] == str(address.ip)


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
        for m in ('b1', 'b2'):
            for c in ("bridge link", "bridge fdb show", "ip -br address", "ip route"):
                self.test(m, c, allow_error=True)
        for m in ('router', 'router2'):
            for c in ("ip -br address", "ip route", "iptables -t nat -S"):
                self.test(m, c, allow_error=True)

        # ---------------- the state of the machines (every test is registered on every pass) --
        links = {m: get_ip_links(self, m) for m in ('b1', 'b2', 'router', 'router2', 'm7')}
        addrs = {m: get_ip_addresses_json(self, m) for m in ('b1', 'b2', 'router', 'router2', 'm7')}
        routes = {m: get_routes(self, m) for m in ('b2', 'm7')}
        forward = {m: get_ip_forward(self, m) for m in ('router', 'router2', 'b2')}
        ports = get_switch_ports(self, 'trunk', allow_error=True)
        broute = parse_broute_rules(get_ruleset(self, 'b2'))
        mangle = ttl_rules(get_mangle_rules(self, 'b2'))
        default_ttl_m5 = get_sysctl_int(self, 'm5', 'net.ipv4.ip_default_ttl')

        def ping(src, dest):
            out, _ = self.test(src, f"ping -c 2 -w 4 {dest.ip}", allow_error=True)
            return 'bytes from' in (out or '')

        p = {
            'b1_b2_trunk': ping('b1', d.ips.b2_trunk), 'b1_router_trunk': ping('b1', d.ips.router_trunk),
            'b1_b2_odd': ping('b1', d.ips.b2_odd),
            'm2_m4': ping('m2', d.ips.m4), 'm2_m6': ping('m2', d.ips.m6),
            'm1_m3': ping('m1', d.ips.m3), 'm1_m5': ping('m1', d.ips.m5),
            'm1_m2': ping('m1', d.ips.m2), 'm3_m6': ping('m3', d.ips.m6),
            'm7_m1': ping('m7', d.ips.m1), 'm7_m2': ping('m7', d.ips.m2),
            'm3_router2': ping('m3', d.ips.router2_odd), 'm4_router2': ping('m4', d.ips.router2_even),
        }
        http, alt = HTTP_PORTS
        e = {
            'm5_ext1': get_http_echo(self, 'm5', d.ips.ext1, http), 'm2_ext1': get_http_echo(self, 'm2', d.ips.ext1, http),
            'm1_ext2': get_http_echo(self, 'm1', d.ips.ext2, http), 'm7_ext1': get_http_echo(self, 'm7', d.ips.ext1, http),
            'b2_ext1': get_http_echo(self, 'b2', d.ips.ext1, http), 'm3_ext1': get_http_echo(self, 'm3', d.ips.ext1, http),
            'm5_ext2_alt': get_http_echo(self, 'm5', d.ips.ext2, alt), 'm5_ext2': get_http_echo(self, 'm5', d.ips.ext2, http),
            'm5_ext1_alt': get_http_echo(self, 'm5', d.ips.ext1, alt), 'm4_ext2_alt': get_http_echo(self, 'm4', d.ips.ext2, alt),
        }
        r1, r2 = d.ips.router_ext, d.ips.router2_ext
        ttl_m3 = e['m3_ext1'].get('ttl')
        ttl_m5 = e['m5_ext1'].get('ttl')
        m7_port = ports.get('m7', {})

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `trunk` (switch administrable, VLAN par défaut) | `{trunk}` | `b1` eth0 (`{b1_trunk}`), `b2` eth0 (`{b2_trunk}`), `router` eth1 (`{router_trunk}`), `router2` eth1 (`{router2_trunk}`), `m7` eth0 (non configurée) |
| VLAN {vlan_odd} (machines impaires) | `{odd}` | `m1` (`{m1}`), `m3` (`{m3}`), `m5` (`{m5}`) ; à venir : `b1` (`{b1_odd}`), `b2` (`{b2_odd}`), `router` (`{router_odd}`, passerelle), `router2` (`{router2_odd}`), `m7` (`{m7}`) |
| VLAN {vlan_even} (machines paires) | `{even}` | `m2` (`{m2}`), `m4` (`{m4}`), `m6` (`{m6}`) ; à venir : `router` (`{router_even}`, passerelle), `router2` (`{router2_even}`) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `ext2` (`{ext2}`), `router` eth0 (`{router_ext}`), `router2` eth0 (`{router2_ext}`) |
""").format(trunk=d.nets.trunk, b1_trunk=d.ips.b1_trunk.ip, b2_trunk=d.ips.b2_trunk.ip,
            router_trunk=d.ips.router_trunk.ip, router2_trunk=d.ips.router2_trunk.ip, vlan_odd=VLAN_ODD,
            odd=d.nets.odd, m1=d.ips.m1.ip, m3=d.ips.m3.ip, m5=d.ips.m5.ip, b1_odd=d.ips.b1_odd.ip,
            b2_odd=d.ips.b2_odd.ip, router_odd=d.ips.router_odd.ip, router2_odd=d.ips.router2_odd.ip,
            m7=d.ips.m7.ip, vlan_even=VLAN_EVEN, even=d.nets.even, m2=d.ips.m2.ip, m4=d.ips.m4.ip,
            m6=d.ips.m6.ip, router_even=d.ips.router_even.ip, router2_even=d.ips.router2_even.ip,
            ext=d.nets.ext, ext1=d.ips.ext1.ip, ext2=d.ips.ext2.ip, router_ext=d.ips.router_ext.ip,
            router2_ext=d.ips.router2_ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les VLAN et l'étiquetage 802.1Q, les
sous-interfaces et les ponts Linux, le routeur « on a stick », le NAT, la console du switch,
le brouter et le TTL.

**La maquette** (onglet *Schéma*). Le switch administrable `trunk` relie les deux ponts `b1`
et `b2` (eth0), les deux routeurs `router` et `router2` (eth1) et une machine `m7` non encore
configurée. Ses ports vers `b1`, `b2`, `router` et `router2` sont des **trunks** : ils
transportent les VLAN {vlan_odd} et {vlan_even} étiquetés, et les trames non étiquetées
restent dans le VLAN par défaut du switch (le réseau `trunk` ci-dessous). `b1` est câblée
directement à `m1` (eth1) et `m2` (eth2) ; `b2` atteint `m3` et `m5` par le switch `odd`
(eth1), `m4` et `m6` par le switch `even` (eth2). Les machines impaires `m1`, `m3`, `m5`
forment le réseau du VLAN {vlan_odd}, les paires `m2`, `m4`, `m6` celui du VLAN {vlan_even}.
Les deux routeurs ont leur eth0 sur le réseau `ext`, avec les serveurs `ext1` et `ext2`.
""").format(vlan_odd=VLAN_ODD, vlan_even=VLAN_EVEN)
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses ci-dessus (sauf celles marquées *à venir*, que
vous configurerez), la route par défaut des machines `m1` à `m6` vers `router` (`.254`, qui
ne route pas encore), celle de `b1` et `b2` vers `router` sur `trunk`, les noms dans
`/etc/hosts` (`m1`... `m7`, `ext1`, `ext2`, `b1_trunk`, `b2_trunk`, `router_ext`,
`router_trunk`, `router2_ext`, `router2_trunk`). Le routage est **désactivé** partout. Il n'y a
pas de DNS. Sur `b1` et `b2`, seule `eth0` est configurée.

Sur **chaque machine** tourne un serveur web sur les ports TCP **80 et 8080** : `curl
http://ext1/` ou `curl http://ext1:8080/` affiche `SERVER=` (qui répond), `CLIENT_IP=` (l'adresse
du client **vue par le serveur** : derrière un NAT, celle du routeur) et `TTL=` (le TTL du
paquet reçu). Les captures se font avec `tcpdump` (`-e` pour voir les étiquettes 802.1Q),
`tshark` ou `wireshark`. La console du switch `trunk` est dans l'onglet **Réseaux** (bouton
*Connecter*).

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place (l'évaluation vérifie l'état final de tout) ;
- les noms des ponts sont imposés : **`brodd`** (VLAN {vlan_odd}, machines impaires) et
  **`breven`** (VLAN {vlan_even}, machines paires) ; les sous-interfaces s'appellent
  `eth0.{vlan_odd}`, `eth0.{vlan_even}` (sur `b1`, `b2`) et `eth1.{vlan_odd}`, `eth1.{vlan_even}` (sur les routeurs) ;
- l'évaluation observe la maquette telle qu'elle tourne (`ip`, `nft`, `iptables`, la console
  du switch, puis des `ping` et des requêtes web **depuis vos machines** vers `ext1` et `ext2`).
""").format(vlan_odd=VLAN_ODD, vlan_even=VLAN_EVEN)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit
les formulaires : sous-interfaces et ponts de `b1` / `b2`, sous-interfaces et NAT des deux routeurs,
`m7` adressée et son port placé dans le VLAN {vlan_odd} (résolu par le numéro de port réel), route par
défaut de `b2` vers `router2`, la table `bridge brouter` et ses deux règles, la règle `TTL` et le
`ip_default_ttl` de `m5`. Il est ré-applicable (ce qu'il trouve est d'abord supprimé).

L'évaluation lit `ip -d link` / `ip addr` (sous-interfaces, ponts et leurs ports, adresses),
`ip route`, `ip_forward`, `nft list ruleset` et `iptables -t mangle -S` sur `b2`, la console du switch
(`port/allprint`, `vlan/allprint` : VLAN du port de `m7`), puis des `ping` entre les machines et des
`curl` vers les pages de `ext1` / `ext2` depuis `m1`... `m7` et `b2` : `CLIENT_IP` dit par quel
routeur la requête est sortie, `TTL` combien de routeurs elle a traversés. Une évaluation dure
une dizaine de secondes. Le brouter est en nftables (famille `bridge`), voir la section 8 des
Informations : l'`ebtables` de l'image (1.8.9, nft) n'a pas de table `broute`.
""").format(vlan_odd=VLAN_ODD)),
        )

        # =====================================================================
        # Part 1 — VLAN 802.1Q on b1 and b2 (questions 1 and 2)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — VLAN 802.1Q sur b1 et b2 (questions 1 et 2)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Vérification du réseau trunk"),
            description=tr("""
Vérifiez que `b1` (`{b1_trunk}`), `b2` (`{b2_trunk}`) et `router` (`{router_trunk}`) sont
joignables entre elles (`ping`). Sur `b2`, capturez pendant ce temps avec `tcpdump -e -n -i eth0
icmp` : ces trames traversent le switch `trunk` **sans étiquette** (VLAN par défaut des ports
trunk). Ouvrez la console du switch (onglet *Réseaux*) et regardez `port/print` et `vlan/print` :
repérez les ports de `b1`, `b2`, `router`, `router2` (étiquetés `tagged=1` dans les VLAN {vlan_odd}
et {vlan_even}) et celui de `m7`.
""").format(b1_trunk=d.ips.b1_trunk.ip, b2_trunk=d.ips.b2_trunk.ip, router_trunk=d.ips.router_trunk.ip,
            vlan_odd=VLAN_ODD, vlan_even=VLAN_EVEN)
            + instructor(tr("""
**Solution.** Rien à configurer : les trois adresses sont en place à l'ouverture. `vlan/print` montre
le VLAN `0000` (tous les ports, `tagged=0`) et les VLAN `0111` / `0222` avec les quatre ports trunk
`tagged=1` ; `port/print` donne `untagged_vlan=0000` pour chacun, dont celui de `m7`
(`kathara m7:eth0`). L'évaluation fait `ping` depuis `b1` vers `b2` et `router`.
""")),
        )

        q2_answers = {"diff": "tag_on_eth0", "vid": str(VLAN_ODD), "tag_size": "4"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("VLAN {odd} et {even} sur b1 et b2").format(odd=VLAN_ODD, even=VLAN_EVEN),
            description=tr("""
Sur l'interface `eth0` de `b1` et de `b2`, créez les deux sous-interfaces VLAN `eth0.{odd}` et
`eth0.{even}` (section 3 des Informations), attribuez les adresses :

- `{b1_odd}` à `eth0.{odd}` sur `b1`,
- `{b2_odd}` à `eth0.{odd}` sur `b2`.

Montez toutes les interfaces et vérifiez que `b1` et `b2` se joignent **à travers le VLAN
{odd}** (`ping {b2_odd}` depuis `b1`). Pendant ces pings, capturez sur `b1` avec `tcpdump -e -n
-i eth0 icmp`, puis avec `tcpdump -e -n -i eth0.{odd} icmp` (ou Wireshark). Quelle différence y
a-t-il entre les deux captures ?
""").format(odd=VLAN_ODD, even=VLAN_EVEN, b1_odd=d.ips.b1_odd, b2_odd=d.ips.b2_odd)
            + tr("""
- différence entre les deux captures : @@{diff:>sur eth0 chaque trame porte une étiquette 802.1Q (vlan 111) entre l'adresse MAC source et le type ; sur eth0.111 les mêmes trames apparaissent sans étiquette>>>tag_on_eth0|c'est l'inverse : l'étiquette 802.1Q n'apparaît que sur eth0.111>>>tag_on_sub|aucune, les deux captures sont identiques>>>same|sur eth0 on ne voit aucune trame du ping, seulement sur eth0.111>>>nothing_on_eth0}@@
- numéro de VLAN lu dans la capture sur `eth0` (`vlan N`) : @@{vid:[0-9]+}@@
- taille de l'étiquette 802.1Q, en octets (comparez les longueurs des trames) : @@{tag_size:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `b1` (même chose sur `b2` avec `{b2_odd}`) :

```
{cmds}```

`tcpdump -e -n -i eth0 icmp` montre `ethertype 802.1Q (0x8100), length 102: vlan {odd}, p 0,
ethertype IPv4 (0x0800), ...` : sur l'interface physique, chaque trame porte l'étiquette de 4 octets
(102 octets au lieu de 98 pour un ping de 56 octets de données) ; sur `eth0.{odd}` les mêmes trames
sont vues sans étiquette (`ethertype IPv4 (0x0800), length 98`). Le switch `trunk` ne transmet ces
trames qu'aux ports membres du VLAN {odd}.

- Réponses : étiquette sur `eth0` seulement ; VLAN {odd} ; 4 octets.
- L'évaluation vérifie `eth0.{odd}` / `eth0.{even}` (`ip -d link` : `vlan id`), le `ping` de `b1` vers
  `{b2_odd}` et le formulaire.
""").format(cmds=_lines(self.net_scheme.cmds_vlan('b1')), b2_odd=d.ips.b2_odd, odd=VLAN_ODD, even=VLAN_EVEN)),
            cheat_answers={"final": q2_answers},
        )

        self.add_grade_element(
            title=no_tr("trunk_reachable"), max_grade=1, grade_part=part1,
            grade=int(p['b1_b2_trunk'] and p['b1_router_trunk']),
            description=tr("b1 joint b2 et router sur le réseau trunk (trames non étiquetées)"),
        )
        self.add_grade_element(
            title=no_tr("vlan_interfaces"), max_grade=4, grade_part=part1,
            grade=sum(int(_has_vlan(links[m], f"eth0.{vid}", 'eth0', vid))
                      for m in ('b1', 'b2') for vid in (VLAN_ODD, VLAN_EVEN)),
            description=tr("eth0.{odd} et eth0.{even} (type vlan, bons identifiants, up) sur b1 et sur b2").format(
                odd=VLAN_ODD, even=VLAN_EVEN),
        )
        self.add_grade_element(
            title=no_tr("vlan_odd_ping"), max_grade=2, grade_part=part1,
            grade=2 * int(p['b1_b2_odd']),
            description=tr("b1 joint {b2_odd} (b2) à travers le VLAN {odd}").format(b2_odd=d.ips.b2_odd.ip, odd=VLAN_ODD),
        )
        self.add_grade_element(
            title=no_tr("q_capture_tag"), max_grade=5, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=3 * int(_norm(q2.get("diff")) == "tag_on_eth0") + int(_is_int(q2.get("vid"), VLAN_ODD))
                  + int(_is_int(q2.get("tag_size"), 4)),
            description=tr("captures sur eth0 et eth0.{odd} : où est l'étiquette, numéro de VLAN, taille de l'étiquette").format(
                odd=VLAN_ODD),
        )

        # =====================================================================
        # Part 2 — bridges (questions 3 and 4)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Ponts (questions 3 et 4)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Pont breven : m2 joint m4 et m6"),
            description=tr("""
Créez sur chacune des machines `b1` et `b2` un pont nommé **`breven`** (section 4 des
Informations), ajoutez-lui les interfaces `eth2` et `eth0.{even}`, montez toutes les interfaces
(y compris les nouveaux ponts) et vérifiez que `m2` (`{m2}`) peut joindre `m4` (`{m4}`) et
`m6` (`{m6}`). Observez `bridge fdb show br breven` sur `b1` après ces pings.

*Remarque* : les interfaces `eth0.{even}` de `b1` et `b2` n'ont pour l'instant pas d'adresse IP,
et n'en auront pas besoin : `b1` et `b2` ne sont que des switchs pour le VLAN {even}.
""").format(even=VLAN_EVEN, m2=d.ips.m2.ip, m4=d.ips.m4.ip, m6=d.ips.m6.ip)
            + instructor(tr("""
**Solution.** Sur `b1` et sur `b2` :

```
{cmds}```

Les trames de `m2` entrent sans étiquette par `eth2` de `b1`, le pont les commute vers `eth0.{even}`
qui les étiquette {even} sur `eth0` ; le switch `trunk` les livre aux ports trunk, `b2` les
désétiquette sur son `eth0.{even}` et son pont les commute vers `eth2`, donc vers le switch `even`
et `m4` / `m6`. `bridge fdb show` montre les adresses MAC de `m4` et `m6` apprises sur
`eth0.{even}`. L'évaluation vérifie les ports des deux ponts (`ip -d link` : `master breven`) et
les `ping` de `m2` vers `m4` et `m6`.
""").format(cmds=_lines(self.net_scheme.cmds_breven()), even=VLAN_EVEN)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Pont brodd : m1 joint m3 et m5"),
            description=tr("""
Faites la même chose avec des ponts **`brodd`** (interfaces `eth1` et `eth0.{odd}`) pour que
`m1` (`{m1}`) puisse joindre `m3` (`{m3}`) et `m5` (`{m5}`).

N'oubliez pas de **supprimer** sur `b1` et `b2` l'adresse IP de `eth0.{odd}` et de la remettre
ensuite sur `brodd` (`{b1_odd}` sur `b1`, `{b2_odd}` sur `b2`) : une interface devenue port d'un
pont ne doit plus porter d'adresse. Vérifiez que `b1` et `b2` se joignent toujours par le VLAN
{odd}, et que `m1` joint `b2` (`{b2_odd}`).
""").format(odd=VLAN_ODD, m1=d.ips.m1.ip, m3=d.ips.m3.ip, m5=d.ips.m5.ip, b1_odd=d.ips.b1_odd, b2_odd=d.ips.b2_odd)
            + instructor(tr("""
**Solution.** Sur `b1` (sur `b2` avec `{b2_odd}`) :

```
{cmds}```

L'adresse sur le pont fait de `b1` à la fois un switch du VLAN {odd} et une machine de ce VLAN
(c'est le pont qui répond aux ARP). L'évaluation vérifie les ports des ponts `brodd`, que les
adresses `{b1_odd}` / `{b2_odd}` sont sur `brodd` (et non sur `eth0.{odd}`), le `ping` de `b1` vers `b2`
et ceux de `m1` vers `m3` et `m5`.
""").format(cmds=_lines(self.net_scheme.cmds_brodd('b1')), b1_odd=d.ips.b1_odd, b2_odd=d.ips.b2_odd, odd=VLAN_ODD)),
        )

        self.add_grade_element(
            title=no_tr("breven_ports"), max_grade=4, grade_part=part2,
            grade=sum(2 * int(_bridge_has(links[m], 'breven', 'eth2', f"eth0.{VLAN_EVEN}")) for m in ('b1', 'b2')),
            description=tr("pont breven avec les ports eth2 et eth0.{even} sur b1 et sur b2").format(even=VLAN_EVEN),
        )
        self.add_grade_element(
            title=no_tr("even_connectivity"), max_grade=2, grade_part=part2,
            grade=int(p['m2_m4']) + int(p['m2_m6']),
            description=tr("m2 joint m4 et m6 (VLAN {even} prolongé par les ponts)").format(even=VLAN_EVEN),
        )
        self.add_grade_element(
            title=no_tr("brodd_ports"), max_grade=4, grade_part=part2,
            grade=sum(2 * int(_bridge_has(links[m], 'brodd', 'eth1', f"eth0.{VLAN_ODD}")) for m in ('b1', 'b2')),
            description=tr("pont brodd avec les ports eth1 et eth0.{odd} sur b1 et sur b2").format(odd=VLAN_ODD),
        )
        self.add_grade_element(
            title=no_tr("brodd_addresses"), max_grade=4, grade_part=part2,
            grade=sum(2 * int(interface_of_address(addrs[m], getattr(d.ips, m + '_odd')) == 'brodd'
                              and not addresses_of(addrs[m], f"eth0.{VLAN_ODD}")) for m in ('b1', 'b2')),
            description=tr("{b1_odd} sur brodd de b1 et {b2_odd} sur brodd de b2, plus rien sur eth0.{odd}").format(
                b1_odd=d.ips.b1_odd.ip, b2_odd=d.ips.b2_odd.ip, odd=VLAN_ODD),
        )
        self.add_grade_element(
            title=no_tr("odd_connectivity"), max_grade=2, grade_part=part2,
            grade=int(p['m1_m3']) + int(p['m1_m5']),
            description=tr("m1 joint m3 et m5 (VLAN {odd} prolongé par les ponts)").format(odd=VLAN_ODD),
        )

        # =====================================================================
        # Part 3 — router on a stick and NAT (questions 5 and 6)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Routeur « on a stick » et NAT (questions 5 et 6)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("router relie les deux VLAN"),
            description=tr("""
Ajoutez les VLAN {odd} et {even} sur `router` (sous-interfaces `eth1.{odd}` et `eth1.{even}` de
son port trunk `eth1`) et donnez-lui les adresses `{router_odd}` et `{router_even}`, afin que
`router` puisse joindre les machines `m1` à `m6`. Activez le routage sur `router` (de façon
volatile : `sysctl -w net.ipv4.ip_forward=1`) et vérifiez que **toutes** les machines `m1` à `m6`
sont joignables entre elles (par exemple `ping {m2}` depuis `m1`, `ping {m6}` depuis `m3`).
Observez avec `tcpdump -e -n -i eth1` sur `router` l'aller et le retour d'un ping inter-VLAN :
les deux trames passent par le même câble, avec des étiquettes différentes.
""").format(odd=VLAN_ODD, even=VLAN_EVEN, router_odd=d.ips.router_odd, router_even=d.ips.router_even,
            m2=d.ips.m2.ip, m6=d.ips.m6.ip)
            + instructor(tr("""
**Solution.** Sur `router` :

```
{cmds}sysctl -w net.ipv4.ip_forward=1
```

Les machines `m1` à `m6` ont déjà `{router_odd}` / `{router_even}` comme route par défaut. L'évaluation
vérifie les sous-interfaces et leurs adresses, `ip_forward`, et des `ping` de `m1` vers `m2` et de `m3`
vers `m6`.
""").format(cmds=_lines(self.net_scheme.cmds_router_vlans('router')), router_odd=d.ips.router_odd.ip,
            router_even=d.ips.router_even.ip)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("NAT source sur router"),
            description=tr("""
Mettez en place sur `router` la traduction d'adresses source (NAT source, *masquerade*, section 6
des Informations) afin que le trafic provenant des réseaux internes semble provenir de `router`
(`{router_ext}`). Vérifiez que les machines `m1` à `m6` peuvent joindre `ext1` (`{ext1}`) et
`ext2` (`{ext2}`) : `curl http://ext1/` depuis `m5` doit afficher `CLIENT_IP={router_ext}`.
Pourquoi ne pouvaient-elles pas les joindre avant le NAT, alors que `router` routait déjà ?
""").format(router_ext=d.ips.router_ext.ip, ext1=d.ips.ext1.ip, ext2=d.ips.ext2.ip)
            + instructor(tr("""
**Solution.** Sur `router` : `iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` (ou
`nft add table ip nat ; nft 'add chain ip nat postrouting {{ type nat hook postrouting priority 100; }}' ;
nft add rule ip nat postrouting oifname "eth0" masquerade`). Sans NAT, `ext1` recevait les paquets de
`{m5}` mais ne savait pas répondre : il n'a aucune route vers `{odd}` (et aucune route par défaut).
L'évaluation lit `CLIENT_IP` sur `ext1` / `ext2` depuis `m5`, `m2` et `m1` : `{router_ext}`.
""").format(m5=d.ips.m5.ip, odd=d.nets.odd, router_ext=d.ips.router_ext.ip)),
        )

        self.add_grade_element(
            title=no_tr("router_vlan_interfaces"), max_grade=4, grade_part=part3,
            grade=int(_has_vlan(links['router'], f"eth1.{VLAN_ODD}", 'eth1', VLAN_ODD))
                  + int(interface_of_address(addrs['router'], d.ips.router_odd) == f"eth1.{VLAN_ODD}")
                  + int(_has_vlan(links['router'], f"eth1.{VLAN_EVEN}", 'eth1', VLAN_EVEN))
                  + int(interface_of_address(addrs['router'], d.ips.router_even) == f"eth1.{VLAN_EVEN}"),
            description=tr("eth1.{odd} ({router_odd}) et eth1.{even} ({router_even}) sur router").format(
                odd=VLAN_ODD, router_odd=d.ips.router_odd.ip, even=VLAN_EVEN, router_even=d.ips.router_even.ip),
        )
        self.add_grade_element(
            title=no_tr("router_forwarding"), max_grade=2, grade_part=part3,
            grade=2 * int(forward['router']),
            description=tr("routage activé sur router (net.ipv4.ip_forward)"),
        )
        self.add_grade_element(
            title=no_tr("inter_vlan"), max_grade=4, grade_part=part3,
            grade=2 * int(p['m1_m2']) + 2 * int(p['m3_m6']),
            description=tr("m1 joint m2 et m3 joint m6 (routage entre les VLAN par router)"),
        )
        self.add_grade_element(
            title=no_tr("snat_router"), max_grade=6, grade_part=part3,
            grade=2 * int(_client_is(e['m5_ext1'], r1)) + 2 * int(_client_is(e['m2_ext1'], r1))
                  + 2 * int(_client_is(e['m1_ext2'], r1)),
            description=tr("ext1 et ext2 voient les requêtes de m5, m2 et m1 venir de router ({router_ext})").format(
                router_ext=d.ips.router_ext.ip),
        )

        # =====================================================================
        # Part 4 — a new machine on a free port (question 7)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Une nouvelle machine m7 (question 7)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("m7 sur un port libre du switch trunk"),
            description=tr("""
La machine `m7` est branchée sur un port libre du switch `trunk`, dans le VLAN par défaut, et
n'est pas configurée. Donnez-lui l'adresse `{m7}` et la passerelle par défaut de ce réseau
(`{router_odd}`). Elle ne joint encore personne : ses trames, sans étiquette, restent dans le
VLAN par défaut du switch.

Ouvrez la console du switch `trunk` (onglet *Réseaux*), trouvez le numéro du port de `m7` avec
`port/print` (ligne `kathara m7:eth0`) et placez ce port dans le VLAN {odd} :

```
port/setvlan <port> {odd}
```

Vérifiez avec `vlan/print` que le port est bien dans le VLAN {odd} (`tagged=0` : port d'accès),
puis que `m7` peut joindre toutes les autres machines (`m1`, `m2` par `router`, `ext1` par le NAT).
""").format(m7=d.ips.m7, router_odd=d.ips.router_odd.ip, odd=VLAN_ODD)
            + instructor(tr("""
**Solution.** Sur `m7` :

```
{cmds}```

puis sur la console du switch `port/setvlan N {odd}` (N lu dans `port/print` ; l'état `final` écrit
`port/setvlan @m7 {odd}`, le numéro étant résolu par SRE). Le port devient un port d'accès du VLAN
{odd} : le switch étiquette {odd} les trames de `m7` vers les trunks et désétiquette celles qui lui
reviennent. L'évaluation lit le VLAN du port de `m7` sur le switch (`port/allprint`), l'adresse et
la route de `m7`, puis des `ping` vers `m1` et `m2` et `CLIENT_IP` sur `ext1`.
""").format(cmds=_lines(self.net_scheme.cmds_m7()), odd=VLAN_ODD)),
        )

        self.add_grade_element(
            title=no_tr("m7_port_vlan"), max_grade=5, grade_part=part4,
            grade=5 * int(m7_port.get('vlan') == VLAN_ODD and not m7_port.get('tagged_vlans')),
            description=tr("sur le switch trunk, le port de m7 est un port d'accès du VLAN {odd}").format(odd=VLAN_ODD),
        )
        self.add_grade_element(
            title=no_tr("m7_config"), max_grade=2, grade_part=part4,
            grade=int(interface_of_address(addrs['m7'], d.ips.m7) == 'eth0')
                  + int(routes['m7'].get(('0.0.0.0', 0), ('',))[0] == str(d.ips.router_odd.ip)),
            description=tr("m7 : adresse {m7} sur eth0, route par défaut via {router_odd}").format(
                m7=d.ips.m7.ip, router_odd=d.ips.router_odd.ip),
        )
        self.add_grade_element(
            title=no_tr("m7_connectivity"), max_grade=5, grade_part=part4,
            grade=2 * int(p['m7_m1']) + 2 * int(p['m7_m2']) + int(_client_is(e['m7_ext1'], r1)),
            description=tr("m7 joint m1 (même VLAN), m2 (par router) et ext1 (par le NAT de router)"),
        )

        # =====================================================================
        # Part 5 — the brouter (question 8)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Brouter sur b2 (question 8)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Brouter sur b2"),
            description=tr("""
On veut changer la configuration de `b2` afin que le trafic provenant de `m3` sorte vers
l'extérieur par `router2` et non par `router` comme celui de `m5` et des autres machines, **sans
toucher à la configuration de `m3`** (qui garde `router` comme passerelle).

**(a)** Activez le routage sur `router2` et mettez-y en place le NAT source, comme sur `router`.
Changez la **route par défaut de `b2`** pour que le trafic émis par `b2` soit routé par
`router2` (`{router2_trunk}`, sur le réseau `trunk`). Testez avec `curl http://ext1/` depuis `b2`
(`CLIENT_IP={router2_ext}`) et depuis `m3` (toujours `{router_ext}`).

**(b)** Configurez `router2` de la même façon que `router` : sous-interfaces `eth1.{odd}` et
`eth1.{even}` avec les adresses `{router2_odd}` et `{router2_even}`. Vérifiez que `router2` est
joignable depuis `m3` et depuis `m4`.

**(c)** Lisez la section 8 des Informations. Activez le routage sur `b2`, puis ajoutez sur `b2`
une règle nftables (famille `bridge`, hook `prerouting`) pour que les paquets IPv4 provenant de
`m3` (`{m3}`) soient **routés** par `b2` au lieu d'être pontés. Vérifiez par `curl http://ext1/`
que le trafic de `m3` sort maintenant par `router2` (`CLIENT_IP={router2_ext}`) alors que celui
de `m5` sort toujours par `router`. Comment les réponses de `ext1` reviennent-elles à `m3` ?

**(d)** Ajoutez sur `b2` une règle pour que les paquets IPv4 arrivant par l'interface `eth1`, à
destination de `ext2` (`{ext2}`) et utilisant TCP vers le port **8080**, soient eux aussi routés
via `router2`. Vérifiez votre configuration avec `curl` depuis `m5` et depuis `m4` vers les ports
80 et 8080 de `ext1` et de `ext2` : seules les requêtes de `m5` vers `ext2:8080` doivent sortir
par `router2`.
""").format(router2_trunk=d.ips.router2_trunk.ip, router2_ext=d.ips.router2_ext.ip, router_ext=d.ips.router_ext.ip,
            odd=VLAN_ODD, even=VLAN_EVEN, router2_odd=d.ips.router2_odd, router2_even=d.ips.router2_even,
            m3=d.ips.m3.ip, ext2=d.ips.ext2.ip)
            + instructor(tr("""
**Solution.** (a) Sur `router2` : `sysctl -w net.ipv4.ip_forward=1` et
`iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE` ; sur `b2` : `{b2_route}`.

(b) Sur `router2` :

```
{router2}```

(c) et (d) Sur `b2` :

```
{brouter}```

La première règle réécrit l'adresse MAC de destination des trames de `m3` avec celle du pont
`brodd` et les marque `host` : le pont les livre à la pile IP de `b2`, qui les route par sa
route par défaut (`router2`), qui fait le NAT. Les réponses reviennent de `router2` par sa
sous-interface `eth1.{odd}` (il connaît `{odd_net}`) : trames étiquetées {odd} vers `b2`,
désétiquetées sur `eth0.{odd}` et pontées vers `eth1` et `m3` sans passer par la couche IP de
`b2`. Avec la seconde règle, seules les requêtes de `m5` vers `ext2:8080` sortent par
`router2` ; `m4` entre par `eth2` et n'est jamais concernée.

L'évaluation lit `ip_forward` de `router2` et `b2`, la route par défaut de `b2`, les règles de la
famille `bridge` dans `nft list ruleset` (une règle `meta pkttype set host` + `ether daddr set`
couvrant `{m3}`, une autre `ip daddr {ext2} tcp dport 8080`), des `ping` de `m3` / `m4` vers
`router2`, et `CLIENT_IP` sur `ext1` / `ext2` depuis `b2`, `m3`, `m5` (ports 80 et 8080) et `m4`.
""").format(b2_route=self.net_scheme.cmds_b2_default_route()[0], router2=_lines(self.net_scheme.cmds_router_vlans('router2')),
            brouter=_lines(self.net_scheme.cmds_brouter()), odd=VLAN_ODD, odd_net=d.nets.odd, m3=d.ips.m3.ip, ext2=d.ips.ext2.ip)),
        )

        self.add_grade_element(
            title=no_tr("router2_nat"), max_grade=4, grade_part=part5,
            grade=int(forward['router2']) + 3 * int(_client_is(e['b2_ext1'], r2)),
            description=tr("router2 route et masque : ext1 voit les requêtes de b2 venir de {router2_ext}").format(
                router2_ext=d.ips.router2_ext.ip),
        )
        self.add_grade_element(
            title=no_tr("b2_default_route"), max_grade=2, grade_part=part5,
            grade=2 * int(routes['b2'].get(('0.0.0.0', 0), ('',))[0] == str(d.ips.router2_trunk.ip)),
            description=tr("route par défaut de b2 via router2 ({router2_trunk})").format(router2_trunk=d.ips.router2_trunk.ip),
        )
        self.add_grade_element(
            title=no_tr("router2_vlan_interfaces"), max_grade=4, grade_part=part5,
            grade=int(_has_vlan(links['router2'], f"eth1.{VLAN_ODD}", 'eth1', VLAN_ODD) and p['m3_router2'])
                  + int(interface_of_address(addrs['router2'], d.ips.router2_odd) == f"eth1.{VLAN_ODD}")
                  + int(_has_vlan(links['router2'], f"eth1.{VLAN_EVEN}", 'eth1', VLAN_EVEN) and p['m4_router2'])
                  + int(interface_of_address(addrs['router2'], d.ips.router2_even) == f"eth1.{VLAN_EVEN}"),
            description=tr("eth1.{odd} ({router2_odd}) et eth1.{even} ({router2_even}) sur router2, joignables depuis m3 et m4").format(
                odd=VLAN_ODD, router2_odd=d.ips.router2_odd.ip, even=VLAN_EVEN, router2_even=d.ips.router2_even.ip),
        )
        self.add_grade_element(
            title=no_tr("b2_forwarding"), max_grade=1, grade_part=part5,
            grade=int(forward['b2']),
            description=tr("routage activé sur b2"),
        )
        self.add_grade_element(
            title=no_tr("brouter_m3"), max_grade=6, grade_part=part5,
            grade=4 * int(_client_is(e['m3_ext1'], r2)) + 2 * int(_client_is(e['m5_ext1'], r1)),
            description=tr("ext1 voit les requêtes de m3 venir de router2 et celles de m5 de router"),
        )
        self.add_grade_element(
            title=no_tr("brouter_rules"), max_grade=2, grade_part=part5,
            grade=int(bool(broute_rules_for(broute, src=d.ips.m3)))
                  + int(bool(broute_rules_for(broute, dst=d.ips.ext2, dport=HTTP_PORTS[1]))),
            description=tr("règles nftables de la famille bridge sur b2 : paquets de m3, paquets vers ext2 port 8080"),
        )
        self.add_grade_element(
            title=no_tr("brouter_port_8080"), max_grade=9, grade_part=part5,
            grade=4 * int(_client_is(e['m5_ext2_alt'], r2)) + 2 * int(_client_is(e['m5_ext2'], r1))
                  + 2 * int(_client_is(e['m5_ext1_alt'], r1)) + int(_client_is(e['m4_ext2_alt'], r1)),
            description=tr("depuis m5, seul ext2:8080 est joint par router2 (ext2:80 et ext1:8080 par router) ; m4 vers ext2:8080 par router"),
        )

        # =====================================================================
        # Part 6 — the TTL (question 9)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — TTL (question 9)"))

        q9_answers = {"ttl_m5": str(DEFAULT_TTL - 1), "ttl_m3": str(DEFAULT_TTL - 2), "why": "extra_hop",
                      "ttl_m5_after": str(TTL_M5 - 1)}
        q9 = self.question_form(
            section=self.section(0),
            title=tr("Impact du brouter sur le TTL"),
            description=tr("""
**(a)** Lancez sur `ext1` une capture des paquets TCP reçus (`tcpdump -n -v -i eth0 tcp`,
`tshark -i eth0 -V` ou Wireshark) et faites des requêtes `curl http://ext1/` depuis `m3` et
depuis `m5` (la page affiche aussi `TTL=`). Regardez le **TTL** des paquets semblant provenir de
`router` (requêtes de `m5`) et de `router2` (requêtes de `m3`). Que constatez-vous ?
""")
            + tr("""
- TTL des paquets de `m5` arrivant sur `ext1` : @@{ttl_m5:[0-9]+}@@
- TTL des paquets de `m3` arrivant sur `ext1` : @@{ttl_m3:[0-9]+}@@
- pourquoi : @@{why:>b2 route les paquets de m3 au lieu de les ponter : un routeur de plus sur le chemin, qui décrémente le TTL>>>extra_hop|router2 décrémente le TTL de 2>>>router2_twice|le pont brodd décrémente le TTL comme un routeur>>>bridge|m3 émet ses paquets avec un TTL initial plus petit>>>m3_small}@@
""")
            + tr("""
**(b)** Sur `b2`, ajoutez avec `iptables` une règle dans la table `mangle` pour que tous les
paquets qui transitent par `b2` et proviennent de `m3` (`{m3}`) aient leur TTL **augmenté de 1**
(cible `TTL`, voir `man iptables-extensions` et la section 9 des Informations). Vérifiez sur
`ext1` que les paquets provenant de `m3` et ceux provenant de `m5` ont de nouveau le même TTL.
*Remarque* : il est dangereux en général d'augmenter le TTL ainsi (paquets tournant
indéfiniment en cas de boucle) !

**(c)** Sur `m5`, changez par `sysctl -w net.ipv4.ip_default_ttl={ttl_m5}` le TTL des paquets
émis par défaut (`sysctl -a` affiche l'ensemble des paramètres du noyau et leurs valeurs). Quel
est à présent le TTL des paquets arrivant sur `ext1` provenant d'une requête web de `m5` ?
""").format(m3=d.ips.m3.ip, ttl_m5=TTL_M5)
            + tr("""
- TTL des paquets de `m5` arrivant sur `ext1` après ce changement : @@{ttl_m5_after:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** (a) Les paquets de `m5` arrivent avec un TTL de {ttl_m5} (émis à {default}, décrémenté par
`router`), ceux de `m3` avec {ttl_m3} : `b2` les **route** (un saut de plus), puis `router2`. Un pont ne
décrémente pas le TTL. (b) Sur `b2` : `{ttl_rule}` : les paquets de `m3` repartent avec {ttl_m5}
(la chaîne `PREROUTING` de la famille `ip` est traversée après le détournement, puis le routage retire 1).
(c) Sur `m5` : `{default_ttl}` : ses paquets arrivent sur `ext1` avec {ttl_m5_after}.

- Réponses : {ttl_m5} ; {ttl_m3} ; un routeur de plus (b2) ; {ttl_m5_after}.
- L'évaluation lit `TTL=` sur la page de `ext1` pour les requêtes de `m3` ({ttl_m5} avec la règle) et de `m5`
  ({ttl_m5_after}), `iptables -t mangle -S` sur `b2` (une cible `TTL --ttl-inc 1` pour `{m3}`) et
  `net.ipv4.ip_default_ttl` sur `m5` ({ttl_m5_value}).
""").format(ttl_m5=DEFAULT_TTL - 1, default=DEFAULT_TTL, ttl_m3=DEFAULT_TTL - 2, ttl_rule=self.net_scheme.cmds_ttl()[0],
            default_ttl=self.net_scheme.cmds_default_ttl()[0], ttl_m5_after=TTL_M5 - 1, m3=d.ips.m3.ip, ttl_m5_value=TTL_M5)),
            cheat_answers={"final": q9_answers},
        )

        self.add_grade_element(
            title=no_tr("q_ttl_observed"), max_grade=5, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is_int(q9.get("ttl_m5"), DEFAULT_TTL - 1)) + int(_is_int(q9.get("ttl_m3"), DEFAULT_TTL - 2))
                  + 3 * int(_norm(q9.get("why")) == "extra_hop"),
            description=tr("TTL observés sur ext1 ({ttl_m5} depuis m5, {ttl_m3} depuis m3) et leur explication").format(
                ttl_m5=DEFAULT_TTL - 1, ttl_m3=DEFAULT_TTL - 2),
        )
        self.add_grade_element(
            title=no_tr("ttl_increment"), max_grade=6, grade_part=part6,
            grade=4 * int(ttl_m3 == DEFAULT_TTL - 1 and _client_is(e['m3_ext1'], r2))
                  + 2 * int(any(rule['op'] == 'inc' and rule['value'] == 1 and (rule['src'] or '').startswith(str(d.ips.m3.ip))
                                for rule in mangle)),
            description=tr("les paquets de m3 arrivent sur ext1 avec un TTL de {ttl} grâce à une règle TTL --ttl-inc 1 sur b2").format(
                ttl=DEFAULT_TTL - 1),
        )
        self.add_grade_element(
            title=no_tr("default_ttl_m5"), max_grade=4, grade_part=part6,
            grade=2 * int(default_ttl_m5 == TTL_M5) + 2 * int(ttl_m5 == TTL_M5 - 1 and _client_is(e['m5_ext1'], r1)),
            description=tr("net.ipv4.ip_default_ttl = {ttl_m5} sur m5 : ses paquets arrivent sur ext1 avec un TTL de {after}").format(
                ttl_m5=TTL_M5, after=TTL_M5 - 1),
        )
        self.add_grade_element(
            title=no_tr("q_ttl_after"), max_grade=1, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is_int(q9.get("ttl_m5_after"), TTL_M5 - 1)),
            description=tr("TTL des paquets de m5 après le changement de ip_default_ttl ({after})").format(after=TTL_M5 - 1),
        )


_TRANSLATIONS = {}
