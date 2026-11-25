"""Policy routing lab (IPv4): several routing tables and ``ip rule``, two ISPs, packet and connection
marks, multipath routes and VRFs.

Six small sites, one router per part, so that every part is independent of the others:

1. ``r1`` — routing by the source: the guests' LAN leaves by ISP2 (a second table, an ``ip rule from``),
   the staff's LAN by ISP1, both LANs still reach each other;
2. ``r2`` — a multi-homed machine answers by the uplink a request came in by (one table per uplink,
   rules on its own addresses): each ISP drops the packets whose source it did not assign (BCP 38);
3. ``r3`` — routing by a mark: nftables marks a flow, ``ip rule fwmark`` sends it to ISP2; ``r3``
   starts with a strict reverse-path filter, which drops the replies until it is loosened;
4. ``r4`` — a server published on both uplinks (DNAT given): the replies follow the uplink of the
   request thanks to a conntrack mark;
5. ``r5`` — load sharing: a weighted multipath default route;
6. ``r6`` — VRFs: two customers using the same addresses, an ``unreachable`` default route in each
   VRF table, a service of the router reachable from both, route leaking as a bonus.

``r1`` … ``r5`` have ``eth0`` on their LAN, ``eth1`` on the access network of ISP1 (``acc1``) and
``eth2`` on that of ISP2 (``acc2``); they start with a default route by ISP1 and a masquerade on
both uplinks (``/etc/nftables.conf``).  ``isp1`` and ``isp2`` (visible, no terminal) join the access
networks to ``core``, where ``www`` (the server the probes talk to, no terminal) and ``ext`` (a
client the students use to test from the Internet) live.  ``www`` owns a whole prefix (``svc``): the
destinations of the multipath probe.

Grading: no hidden mirror (routing tables, rules, marks and VRFs are not a text that could be
replayed on a clone).  The echo servers of ``lib/server_echo_helpers.py`` answer who they are and
who they see: ``CLIENT_IP`` tells the uplink a flow left by.  A positive probe and its control form
one element (a default route moved to ISP2 scores nothing), every probe checks the address and
port that answered, and what an untouched project would pass is gated behind the positive element
of its part.  The probes of parts 2 and 4 start on ``www``; those of parts 1, 3, 5 and 6 start on
machines the students control: a forged server could fake them, which is acceptable for a guided
lab, not for an exam.

States: ``final`` applies the reference solution and fills the forms (every point, bonus included);
``isp1_down`` / ``isp1_up`` cut and restore ISP1 beyond the access network (the routers' links stay
up).  Texts are French (``tr()``), identifiers English.
"""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, ip_address
from typing import Dict, List

import tc
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from bridging import get_ip_links, link_up
from ips import random_ipv4networks
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, set_sysctl
from policy_routing import (
    MAIN_TABLE, default_nexthops, get_route_tables, leaves_by, parse_spread, spread_cmd, tables_of_mark,
    vrf_devices, vrf_of_port,
)
from server_echo_helpers import install_echo_server, parse_http_echo
from state_helpers import create_hosts_file
from traceroute import parse_ping
from wireguard import get_ip_rules

default_language = 'fr'
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("Routage par politique : ip rule, deux fournisseurs d'accès et VRF",
           en="Policy routing: ip rule, two ISPs and VRFs")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True
export_kathara_project = True
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False
# No save / restore: the work of this lab is kernel state (rules, tables, marks, VRF devices), and a
# restore only brings files back.

DOMAIN = "tp-policy.lan"
HTTP_PORT = 80
BULK_PORT = 8080                   # part 3: the flow sent to ISP2 (a second port of www)
PUB_PORT = 8080                    # part 4: the port r4 forwards to port 80 of web4
# The addresses of the "Internet": never routed (RFC 2544), visibly not private.
INTERNET_RANGE = IPv4Network("198.18.0.0/15")
SITES = (1, 2, 3, 4, 5)
ROUTERS = tuple(f"r{n}" for n in SITES)      # eth0 = LAN, eth1 = ISP1, eth2 = ISP2
VRF_ROUTER = "r6"
ISPS = (1, 2)
UPLINK = {1: "eth1", 2: "eth2"}    # ISP number -> interface of the site routers
STRICT_ROUTER = "r3"               # starts with rp_filter = 1
FORWARDERS = ROUTERS + (VRF_ROUTER, "isp1", "isp2")
# The LANs of each site ({interface number of the router: network}) and their host.
SITE_LANS = {1: {0: "lan1a", 3: "lan1b"}, 2: {0: "lan2"}, 3: {0: "lan3"}, 4: {0: "lan4"}, 5: {0: "lan5"}}
LAN_HOST = {"lan1a": "pc1a", "lan1b": "pc1b", "lan2": "pc2", "lan3": "pc3", "lan4": "web4", "lan5": "pc5"}
# Part 6: two customers with the same two prefixes ({network: (interface of r6, host)}).
VRF_NETS = {"blue_a": (0, "blue1"), "blue_b": (1, "blue2"), "red_a": (2, "red1"), "red_b": (3, "red2")}
MGMT_IF = 4
VRF_SITE = (VRF_ROUTER, "admin") + tuple(host for _, host in VRF_NETS.values())   # no access to the Internet
# Host part of every address: readable in a capture (r3 is .13 on both access networks).
ISP_HOST, GW_HOST, PC_HOST, SERVER_HOST, EXT_HOST = 1, 1, 10, 80, 100
ROUTER_HOST = {n: 10 + n for n in SITES}

# -- the reference solution -------------------------------------------------------------------
TABLE = {1: 101, 2: 102}           # one table per ISP
MARK = 2                           # the mark that leads to the table of ISP2
WEIGHT = {1: 3, 2: 1}              # part 5: ISP1 carries three times as much as ISP2
VRF = {"blue": ("vrf-blue", 10, ("eth0", "eth1")), "red": ("vrf-red", 20, ("eth2", "eth3"))}
# The metric the kernel documentation gives to the default route that closes a VRF table.
VRF_UNREACHABLE_METRIC = 4278198272
SPREAD = 64                        # destinations of the multipath probe (addresses .1 to .64 of svc)

# -- the evaluation ---------------------------------------------------------------------------
PROBE_TIMEOUT = 3                  # seconds a probe waits for an echo page
# The SPREAD pages are asked eight at a time: 2 s when they all answer, 28 s with ISP1 cut (three
# quarters of them time out), measured live on 2026-11-18.
SPREAD_TIMEOUT = 60

CONF_FILE = "/etc/nftables.conf"
CONF_HEADER = "#!/usr/sbin/nft -f\nflush ruleset\n\n"
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_TOPOLOGY = {
    "core": {"isp1": 1, "isp2": 1, "www": 0, "ext": 0},
    "acc1": {"isp1": 0, **{r: 1 for r in ROUTERS}},
    "acc2": {"isp2": 0, **{r: 2 for r in ROUTERS}},
    **{lan: {f"r{n}": eth, LAN_HOST[lan]: 0} for n, lans in SITE_LANS.items() for eth, lan in lans.items()},
    **{net: {VRF_ROUTER: eth, host: 0} for net, (eth, host) in VRF_NETS.items()},
    "mgmt": {VRF_ROUTER: MGMT_IF, "admin": 0},
}
_SPECS = {
    "isp1": {"allow_connection": False, "color": "lightgrey"},     # visible, no terminal
    "isp2": {"allow_connection": False, "color": "lightgrey"},
    "www": {"allow_connection": False, "color": "lightgrey"},
    "ext": {"color": "lightgrey"},
    **{r: {"color": "lightblue"} for r in ROUTERS + (VRF_ROUTER,)},
    **{host: {"color": "lightyellow"} for host in LAN_HOST.values()},
    "web4": {"color": "lightgreen"},
    "blue1": {"color": "lightskyblue"}, "blue2": {"color": "lightskyblue"},
    "red1": {"color": "lightpink"}, "red2": {"color": "lightpink"},
    "admin": {"color": "lightyellow"},
}


def _host_address(net: IPv4Network, host: int) -> IPv4Interface:
    """The address number *host* of *net*, with its prefix length."""
    return IPv4Interface(f"{net.network_address + host}/{net.prefixlen}")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        nets, ips = data.nets, data.ips
        nets.core, nets.acc1, nets.acc2, nets.svc = random_ipv4networks(masks=[24] * 4, from_network=INTERNET_RANGE)
        private = [lan for lans in SITE_LANS.values() for lan in lans.values()] + ["cust_a", "cust_b", "mgmt"]
        drawn = dict(zip(private, random_ipv4networks(
            masks=[24] * len(private), from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])))
        # the two customers of part 6 use the same prefixes
        for colour in VRF:
            drawn[f"{colour}_a"], drawn[f"{colour}_b"] = drawn["cust_a"], drawn["cust_b"]
        for name, net in drawn.items():
            if not name.startswith("cust_"):
                setattr(nets, name, net)

        # the Internet
        ips.isp1_acc1, ips.isp2_acc2 = _host_address(nets.acc1, ISP_HOST), _host_address(nets.acc2, ISP_HOST)
        ips.isp1_core, ips.isp2_core = _host_address(nets.core, 1), _host_address(nets.core, 2)
        ips.www, ips.ext = _host_address(nets.core, SERVER_HOST), _host_address(nets.core, EXT_HOST)
        # the sites: ips.r1_acc1, ips.r1_acc2, ips.r1_lan1a, ips.r1_lan1b, ips.pc1a, ips.pc1b, ips.r2_acc1, ...
        for n in SITES:
            for isp in ISPS:
                setattr(ips, f"r{n}_acc{isp}", _host_address(getattr(nets, f"acc{isp}"), ROUTER_HOST[n]))
            for lan in SITE_LANS[n].values():
                setattr(ips, f"r{n}_{lan}", _host_address(drawn[lan], GW_HOST))
                host = LAN_HOST[lan]
                setattr(ips, host, _host_address(drawn[lan], SERVER_HOST if host == "web4" else PC_HOST))
        # part 6: ips.r6_blue_a == ips.r6_red_a, ips.blue1 == ips.red1, ...
        for net, (_, host) in VRF_NETS.items():
            setattr(ips, f"{VRF_ROUTER}_{net}", _host_address(drawn[net], GW_HOST))
            setattr(ips, host, _host_address(drawn[net], PC_HOST))
        ips.r6_mgmt, ips.admin = _host_address(drawn["mgmt"], GW_HOST), _host_address(drawn["mgmt"], PC_HOST)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = _SPECS
    # The access networks and the core are switches: a capture on a router only shows its own
    # traffic, not that of the four other sites.
    _network_specs = {
        "core": {"mode": "switch", "color": "lightgrey"},
        "acc1": {"mode": "switch", "color": "lightgrey"},
        "acc2": {"mode": "switch", "color": "lightgrey"},
        **{lan: {"color": "lightyellow"} for lan in LAN_HOST},
        "blue_a": {"color": "lightskyblue"}, "blue_b": {"color": "lightskyblue"},
        "red_a": {"color": "lightpink"}, "red_b": {"color": "lightpink"},
        "mgmt": {"color": "lightyellow"},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config: Dict[str, NetConfigEntry] = self.build_net_config()

        # The course: one tr() text per section (the lab itself is presented by the first question).
        # No text is formatted here: the examples use documentation addresses, and their braces
        # (nftables) are literal.
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Une table de routage ne suffit pas toujours"), tag="why")
            + tr("""
Le routage IP classique ne regarde que **l'adresse de destination** d'un paquet : la table de
routage associe une sortie à chaque préfixe, et tous les paquets qui vont au même endroit prennent
le même chemin. Cela ne suffit plus dès que l'on veut :

- faire sortir deux réseaux internes par deux fournisseurs d'accès différents ;
- répondre à une requête par le lien où elle est arrivée, sur une machine qui en a plusieurs ;
- envoyer un type de trafic (sauvegardes, voix) par un lien et le reste par un autre ;
- faire passer tout le trafic d'un poste dans un tunnel (`wg-quick` et strongSwan le font avec
  leurs propres tables) ;
- faire cohabiter sur un routeur plusieurs clients qui utilisent les mêmes adresses.

Linux répond par le **routage par politique** (*policy routing*) : **plusieurs tables de routage**,
et une liste ordonnée de **règles** qui disent, pour chaque paquet, quelles tables consulter. Les
**VRF** en sont une forme plus étanche : une table par groupe d'interfaces.

Les exemples de ce cours utilisent un routeur dont `eth0` et `eth3` sont deux réseaux internes
(`192.168.1.0/24` et `192.168.2.0/24`), `eth1` l'accès au fournisseur A (passerelle `192.0.2.1`,
notre adresse `192.0.2.10`) et `eth2` l'accès au fournisseur B (passerelle `198.51.100.1`, notre
adresse `198.51.100.10`).
""")
            + info_subtitle(tr("Tables et règles"), tag="rpdb")
            + tr("""
### @@sec:tables@@ Les tables de routage

Le noyau gère autant de tables qu'on le souhaite, désignées par un numéro. Trois existent
toujours :

| table | numéro | contenu |
|-------|--------|---------|
| `local` | 255 | les adresses de la machine et les adresses de diffusion ; le noyau la remplit seul |
| `main` | 254 | la table « ordinaire » : celle que `ip route` affiche et modifie quand on ne précise rien |
| `default` | 253 | vide |

```
ip route show table main          # = ip route
ip route show table local
ip route show table 102           # une table que l'on a remplie
ip route show table all           # toutes les tables
ip route add default via 198.51.100.1 dev eth2 table 102
```

Une table **existe dès qu'on y met une route** : il n'y a rien à créer. On peut lui donner un nom
en ajoutant une ligne `102 isp2` au fichier `/etc/iproute2/rt_tables` ; `table isp2` et `table 102`
désignent alors la même table.

### @@sec:rules@@ Les règles

```
# ip rule
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
```

Pour chaque paquet à router, reçu d'une interface ou émis par la machine, le noyau parcourt les
règles **par priorité croissante**. Chaque règle a un **sélecteur** (ici `from all` : tous les
paquets) et une **action** (ici `lookup` : consulter une table). Quand le paquet correspond au
sélecteur, la table est consultée :

- elle contient une route pour la destination : la recherche s'arrête, cette route est utilisée ;
- elle n'en contient pas : le noyau **passe à la règle suivante**.

Avec les trois règles d'origine on retrouve le routage classique : les adresses locales d'abord,
puis la table `main`. Le routage par politique consiste à **insérer des règles entre `local` et
`main`**.

### @@sec:route-get@@ Demander sa décision au noyau

`ip route get` fait faire au noyau la recherche complète, règles comprises, et affiche la route
retenue :

```
ip route get 203.0.113.80                                     # un paquet émis par la machine
ip route get 203.0.113.80 from 192.168.2.10 iif eth3          # un paquet de 192.168.2.10 reçu sur eth3
ip route get 203.0.113.80 from 192.168.2.10 iif eth3 mark 2   # le même, portant la marque 2
```

La réponse donne la passerelle, l'interface de sortie et, quand ce n'est pas `main`, la table qui a
répondu : `203.0.113.80 from 192.168.2.10 via 198.51.100.1 dev eth2 table 102`. C'est **la**
commande de vérification du routage par politique.
""")
            + info_subtitle(tr("Écrire une règle"), tag="selectors")
            + tr("""
### @@sec:rule-syntax@@ Sélecteurs et actions

```
ip rule add [not] SÉLECTEURS ACTION priority N
ip rule del priority N
```

| sélecteur | paquets concernés |
|-----------|-------------------|
| `from 192.168.2.0/24` | adresse source dans ce préfixe |
| `to 203.0.113.0/24` | adresse de destination dans ce préfixe |
| `iif eth3` | reçus par cette interface (`iif lo` : émis par la machine) |
| `oif eth2` | émis par un programme attaché à cette interface |
| `fwmark 2` (ou `fwmark 0x2/0xff`) | portant cette marque (section @@ref:marks@@) |
| `ipproto tcp dport 8080` (et `sport`) | protocole et ports |
| `uidrange 1000-1000` | émis par les programmes de cet utilisateur |
| `tos 0x10` | champ TOS de l'en-tête IP |

Plusieurs sélecteurs dans une règle se combinent par un **et** ; `not` inverse l'ensemble.

| action | effet |
|--------|-------|
| `lookup TABLE` | consulter la table (numéro ou nom) |
| `lookup TABLE suppress_prefixlength 0` | consulter la table **sauf sa route par défaut** |
| `blackhole` | jeter le paquet en silence |
| `unreachable`, `prohibit` | le refuser, avec une erreur ICMP |

### @@sec:priorities@@ Priorités, doublons, suppression

- Donnez toujours une priorité (`priority 1000`, ou `pref 1000`). Sans elle, le noyau donne à la
  nouvelle règle la priorité de la première règle qui suit `local`, moins un : elle passe **devant
  toutes les autres**, et l'ordre des règles dépend de l'ordre des commandes.
- Ajouter deux fois la même règle échoue (`RTNETLINK answers: File exists`).
- `ip rule del priority 1000` supprime une règle par sa priorité. `ip rule flush` les supprime
  **toutes**, celles de `main` et de `default` comprises : à éviter.
- Les règles et les tables ne sont pas enregistrées : elles disparaissent au redémarrage (section
  @@ref:persist@@).

### @@sec:connected@@ Une table doit se suffire : les routes connectées

Une règle `from 192.168.2.0/24 lookup 102` envoie dans la table 102 **tous** les paquets de ce
réseau, quelle que soit leur destination. Si la table 102 ne contient qu'une route par défaut, un
paquet destiné à l'autre réseau du site (`192.168.1.0/24`, directement connecté) n'y trouve que
cette route par défaut… et part chez le fournisseur d'accès. Même piège pour une règle sur une
adresse du routeur : ses réponses à un poste du réseau local partent vers Internet.

Deux remèdes :

1. **recopier dans la table les routes des réseaux du site** :

        ip route add 192.168.1.0/24 dev eth0 table 102
        ip route add 192.168.2.0/24 dev eth3 table 102

2. **consulter d'abord la table `main` privée de sa route par défaut**, par une règle de priorité
   plus petite :

        ip rule add from 192.168.2.0/24 lookup main suppress_prefixlength 0 priority 900

    Les réseaux que connaît `main` sont trouvés là ; seul ce qui aurait suivi sa route par défaut
    continue jusqu'à la règle suivante. C'est la technique de `wg-quick`.
""")
            + info_subtitle(tr("Deux fournisseurs d'accès"), tag="multihoming")
            + tr("""
Un site relié à deux fournisseurs d'accès (FAI) reçoit de chacun **une adresse publique**, prise
dans les adresses de ce fournisseur. Le routeur a deux sorties, mais sa table `main` n'a qu'une
route par défaut.

### @@sec:bcp38@@ Le filtrage à l'entrée des fournisseurs

Un fournisseur **n'accepte de ses clients que les paquets dont l'adresse source est une adresse
qu'il leur a attribuée** (recommandation BCP 38, « filtrage à l'entrée ») : cela empêche
l'usurpation d'adresses. Conséquence pour un site à deux accès : **un paquet doit sortir par le
fournisseur auquel appartient son adresse source**. Un paquet qui porte l'adresse du fournisseur B
et sort par le fournisseur A est jeté, sans message. Vue du site, la panne déroute : la requête
arrive, la réponse part, et le client ne reçoit rien.

### @@sec:own@@ Répondre par où la requête est arrivée

Une requête arrivée par le fournisseur B est adressée à notre adresse chez B ; la réponse a donc
cette adresse pour source… et la table `main` l'envoie chez A. La solution classique : **une table
par accès, et une règle par adresse publique**.

```
ip route add default via 192.0.2.1    dev eth1 table 101      # fournisseur A
ip route add default via 198.51.100.1 dev eth2 table 102      # fournisseur B
ip rule add from 192.0.2.10    lookup 101 priority 1001       # notre adresse chez A
ip rule add from 198.51.100.10 lookup 102 priority 1002       # notre adresse chez B
```

Chaque table reçoit aussi les routes des réseaux du site (section @@ref:connected@@). Ces règles
valent pour **ce que le routeur émet lui-même** : ses réponses, et les connexions qu'un programme
ouvre depuis une adresse choisie (`curl --interface 198.51.100.10`, `ping -I`, `ssh -b`). Une
connexion ouverte sans préciser d'adresse prend l'adresse de l'interface que désigne la table
`main` : elle sort par le fournisseur de la route par défaut.

### @@sec:nat@@ Traduction d'adresses et choix de la sortie

Les postes d'un réseau privé sortent sous l'adresse publique du routeur. Une règle par interface
de sortie suffit :

```
table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth1" masquerade
        oifname "eth2" masquerade
    }
}
```

`masquerade` donne au paquet l'adresse de l'interface par laquelle il sort : il suffit donc de
**choisir la sortie** (par une règle sur le réseau source, par une marque…) pour que l'adresse
source soit celle du bon fournisseur. La traduction a lieu après le routage (`postrouting`) : les
règles `ip rule` voient donc l'adresse **privée** du poste. Deux conséquences :

- la traduction est mémorisée par connexion : une connexion établie garde son adresse publique,
  donc sa sortie. Un changement de règle ne vaut proprement que pour les nouvelles connexions ;
- les réponses à une connexion **entrante** ne sont pas traduites par `masquerade` : elles gardent
  pour source l'adresse à laquelle la requête était adressée.
""")
            + info_subtitle(tr("Router selon une marque"), tag="marks")
            + tr("""
Une règle `ip rule` n'examine que quelques champs. Pour tout autre critère — un ensemble d'adresses
ou de ports tenu à jour, l'état d'une connexion, un quota, une combinaison de conditions — on
laisse le pare-feu **marquer** les paquets, et l'on route selon la marque.

### @@sec:fwmark@@ Marquer avec nftables, router avec `fwmark`

La **marque** (*fwmark*) est un entier de 32 bits que le noyau attache au paquet. Elle n'est pas
dans l'en-tête : elle ne sort jamais de la machine, et vaut 0 par défaut. nftables la pose avec
`meta mark set` ; la règle `fwmark` la lit.

```
table ip mangle {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "eth0" tcp dport 8080 meta mark set 2
    }
}
```

```
nft add table ip mangle
nft 'add chain ip mangle prerouting { type filter hook prerouting priority mangle; }'
nft 'add rule ip mangle prerouting iifname "eth0" tcp dport 8080 meta mark set 2'
ip route add default via 198.51.100.1 dev eth2 table 102
ip rule add fwmark 2 lookup 102 priority 1000
```

Le point d'accroche compte : la marque doit être posée **avant la décision de routage**, donc dans
`prerouting` pour les paquets qui traversent le routeur. Posée dans `forward` ou `postrouting`,
elle arrive trop tard. La priorité `mangle` (-150) place la chaîne après le suivi de connexion
(-200) et avant la traduction de la destination (-100).

`ip rule add fwmark 0x2/0xff …` ne compare que les bits du masque : on peut réserver des bits de
la marque à des usages différents.

### @@sec:output@@ Les paquets émis par le routeur

Un paquet émis par un programme du routeur ne passe pas par `prerouting` : sa route est choisie
au moment de l'émission, puis il traverse le point d'accroche `output`. Pour le rerouter d'après
une marque, il faut une chaîne de **type `route`** :

```
chain output {
    type route hook output priority mangle; policy accept;
    tcp dport 8080 meta mark set 2
}
```

Quand une règle d'une chaîne `route` modifie la marque d'un paquet, le noyau **refait sa recherche
de route**. Dans une chaîne de type `filter` accrochée à `output`, la marque serait posée sans
effet sur la route. Attention : l'adresse source a été choisie **avant** ce second routage, d'après
la première sortie ; il faut un `masquerade` sur la nouvelle interface de sortie pour la corriger.

### @@sec:connmark@@ La marque de connexion

Cas d'école : un serveur interne publié sur les deux accès par une redirection de port (`dnat`).
La requête arrivée par le fournisseur B est traduite et remise au serveur ; sa réponse revient au
routeur avec **l'adresse privée du serveur** pour source, car la traduction inverse n'a lieu qu'à
la sortie, après le routage. Aucune règle `from` ne reconnaît l'accès d'origine, et le paquet ne
porte aucune trace de son arrivée.

Le suivi de connexion, lui, connaît les deux sens. On note donc l'accès d'arrivée dans une
**marque de connexion** (`ct mark`), mémorisée avec la connexion, et on la recopie sur les paquets
du retour :

```
chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth2" ct state new ct mark set 2          # la connexion est arrivée par le fournisseur B
    iifname "eth0" ct mark 2 meta mark set ct mark     # ses réponses reçoivent la marque de paquet 2
}
```

```
ip rule add fwmark 2 lookup 102 priority 1000
```

`meta mark` vit le temps d'un paquet, `ct mark` le temps d'une connexion. `ct mark set meta mark`
enregistre la marque d'un paquet dans sa connexion, `meta mark set ct mark` la restaure.
""")
            + info_subtitle(tr("Le filtrage par chemin inverse"), tag="rpfilter")
            + tr("""
Le **filtrage par chemin inverse** (`rp_filter`) protège contre les adresses usurpées : à la
réception d'un paquet, le noyau cherche la route qu'il utiliserait pour **répondre à son adresse
source**.

| valeur | mode | le paquet est accepté si… |
|--------|------|---------------------------|
| 0 | désactivé | toujours |
| 1 | strict | la route de retour passe **par l'interface d'arrivée** |
| 2 | lâche | une route de retour existe, par n'importe quelle interface |

```
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.eth2.rp_filter
sysctl -w net.ipv4.conf.eth2.rp_filter=2
nstat -az TcpExtIPReversePathFilter          # nombre de paquets jetés par ce filtre
```

Pour chaque interface, le noyau applique **la plus grande** des deux valeurs `all` et `ethN`. Les
paquets sont jetés sans message : seul le compteur `TcpExtIPReversePathFilter` augmente.

Avec plusieurs sorties, le mode strict et le routage par politique s'accordent… ou non :

- **règle sur la source** (`from`) : la recherche inverse prend pour adresse source la destination
  du paquet reçu ; la règle s'y applique et désigne la bonne interface. Le mode strict convient ;
- **règle sur une marque** (`fwmark`) : la recherche inverse se fait **sans marque**, donc par la
  table `main`. Si la réponse d'un flux marqué revient par l'autre accès, le mode strict la jette.
  Deux remèdes : passer l'interface concernée en mode lâche (2), ou activer
  `net.ipv4.conf.all.src_valid_mark=1`. La recherche inverse tient alors compte de la marque du
  paquet reçu : il faut la restaurer sur les réponses (`ct mark`, section @@ref:connmark@@), et la
  table désignée doit connaître les réseaux internes, sans quoi ce sont les paquets marqués venus
  de l'intérieur qui sont jetés.
""")
            + info_subtitle(tr("Plusieurs chemins : partage de charge et secours"), tag="multipath")
            + tr("""
### @@sec:ecmp@@ Une route à plusieurs prochains sauts

```
ip route replace default nexthop via 192.0.2.1 dev eth1 weight 3 nexthop via 198.51.100.1 dev eth2 weight 1
```

Le noyau répartit les **flux** entre les prochains sauts, en proportion des poids. Il ne distribue
pas les paquets un à un : il calcule une empreinte, et une même empreinte donne toujours le même
chemin.

| `net.ipv4.fib_multipath_hash_policy` | empreinte calculée sur |
|--------------------------------------|------------------------|
| 0 (défaut) | les adresses source et destination : un poste atteint toujours une destination donnée par le même accès |
| 1 | les adresses, le protocole et les ports : chaque connexion a son chemin |

Cette constance est indispensable avec la traduction d'adresses : chaque accès traduit avec sa
propre adresse publique, et une connexion qui changerait d'accès changerait d'adresse source. La
répartition n'est donc exacte qu'en moyenne, sur un grand nombre de flux. `ip route` affiche les
prochains sauts et leurs poids ; `ip route get` celui que le noyau retient pour une destination.

Autre forme, un accès principal et un secours : deux routes par défaut de **métriques**
différentes (`ip route add default via 192.0.2.1 metric 100`, puis `via 198.51.100.1 metric 200`).
La plus petite métrique l'emporte tant que sa route existe.

### @@sec:failover@@ Détecter une panne

Le noyau ne retire une route, ou un prochain saut, que si **son interface** tombe. Si la panne est
plus loin (le routeur du fournisseur ne répond plus, ou son réseau est coupé derrière lui),
l'interface reste active et le noyau continue d'envoyer des paquets dans le vide : avec une route
à deux chemins, une partie des destinations devient injoignable.

- `net.ipv4.fib_multipath_use_neigh=1` fait écarter un prochain saut dont le voisin ne répond plus
  (`ip neigh` : `FAILED`). Cela ne couvre que la panne du premier routeur.
- Un vrai secours repose sur une **surveillance active** : un programme interroge régulièrement
  une destination située au-delà de chaque fournisseur, par chaque accès (`ping -I`, avec les
  règles de la section @@ref:own@@), et retire ou rétablit les routes. Un protocole de routage
  dynamique échangé avec le fournisseur (BGP) remplit le même rôle.
""")
            + info_subtitle(tr("Les VRF"), tag="vrf")
            + tr("""
Une **VRF** (*Virtual Routing and Forwarding*) est une table de routage **attachée à un groupe
d'interfaces** : les paquets reçus par ces interfaces sont routés avec cette table. Deux VRF
peuvent contenir les mêmes réseaux sans se gêner : c'est ainsi qu'un opérateur transporte sur un
même routeur plusieurs clients qui ont tous choisi `192.168.1.0/24`, ou que l'on sépare un réseau
d'administration du trafic des utilisateurs. Par rapport aux règles `ip rule`, tout est
automatique : les routes des réseaux connectés et les adresses locales de chaque interface sont
rangées dans la table de sa VRF.

### @@sec:vrf-create@@ Créer une VRF, y placer des interfaces

```
ip link add vrf-blue type vrf table 10      # une VRF est une interface virtuelle, liée à une table
ip link set vrf-blue up
ip link set eth0 master vrf-blue            # eth0 et eth1 appartiennent désormais à la VRF
ip link set eth1 master vrf-blue
ip addr add 192.168.1.1/24 dev eth0         # les adresses se donnent comme d'habitude
```

```
ip -br link show type vrf                   # les VRF
ip link show master vrf-blue                # les interfaces d'une VRF
ip vrf show                                 # les VRF et leurs tables
ip link set eth0 nomaster                   # sortir eth0 de sa VRF
```

Une interface qui n'appartient à aucune VRF est dans la **VRF par défaut** : celle des tables
`local` et `main`.

### @@sec:vrf-tables@@ Tables, règle des VRF, fermeture d'une table

```
ip route show vrf vrf-blue                  # = ip route show table 10
ip route add 10.9.0.0/16 via 192.168.1.254 vrf vrf-blue
```

À la création de la première VRF, le noyau ajoute une règle :

```
1000:   from all lookup [l3mdev-table]
```

Elle fait consulter, pour un paquet reçu par une interface d'une VRF, la table de cette VRF. Mais,
comme pour toute règle, **si cette table n'a pas de route pour la destination, la recherche
continue** avec les règles suivantes, donc avec la table `main` : un paquet d'une VRF peut ainsi
s'échapper vers les réseaux de la VRF par défaut. On **ferme** chaque table par une route par
défaut qui refuse :

```
ip route add unreachable default metric 4278198272 vrf vrf-blue
```

La métrique très élevée laisse la priorité à une vraie route par défaut que l'on ajouterait à la
VRF. L'expéditeur reçoit une erreur ICMP (*Destination Host Unreachable*) au lieu d'un silence.

### @@sec:vrf-tools@@ Travailler dans une VRF

Les commandes lancées sur le routeur utilisent la VRF par défaut : `ping 192.168.1.10` répond
*Network is unreachable* si ce réseau n'existe que dans une VRF. Il faut dire dans quelle VRF
travailler :

```
ping -I vrf-blue 192.168.1.10
curl --interface vrf-blue http://192.168.1.10/
ip route get 192.168.1.10 vrf vrf-blue
ip neigh show vrf vrf-blue
ip vrf exec vrf-blue COMMANDE               # lance une commande quelconque dans la VRF
```

`ip vrf exec` a besoin d'écrire dans `/sys/fs/cgroup` : elle échoue dans un conteneur non
privilégié.

### @@sec:vrf-services@@ Les services du routeur

Un programme qui écoute sur le routeur (`sshd`, un serveur web) est, sauf précaution, dans la VRF
par défaut : il **n'accepte que les connexions arrivées par une interface de cette VRF**. Le noyau
répond bien au `ping` adressé à une adresse d'une VRF, mais une connexion TCP y est refusée. Deux
possibilités :

- lancer le service dans la VRF (`ip vrf exec`, ou un service qui s'attache à l'interface de la
  VRF) ;
- autoriser les ports d'écoute de la VRF par défaut à servir toutes les VRF, avec `sysctl -w
  net.ipv4.tcp_l3mdev_accept=1` (et `udp_l3mdev_accept` pour UDP). Chaque connexion acceptée reste
  attachée à la VRF par laquelle elle est arrivée : les réponses repartent du bon côté, même si
  deux clients ont la même adresse.

### @@sec:vrf-leak@@ Faire communiquer deux VRF : la fuite de routes

Par construction, deux VRF ne se voient pas. Quand il faut une exception (un poste
d'administration, un service commun), on ajoute des routes qui **traversent** : c'est une *fuite
de routes*. Entre la VRF par défaut, où se trouve le réseau `10.0.0.0/24` sur `eth4`, et la VRF
bleue :

```
ip route add 192.168.1.0/24 dev vrf-blue             # table main : ce réseau est derrière la VRF bleue
ip route add 10.0.0.0/24 dev eth4 vrf vrf-blue       # table de la VRF : le chemin du retour
```

La première route envoie le paquet à l'interface `vrf-blue` : il entre dans la VRF, dont la table
connaît la suite. La seconde est le chemin du retour, indispensable dès que la table est fermée.
Les adresses des deux côtés doivent être distinctes : on ne peut pas faire fuir vers un même
réseau deux VRF qui utilisent les mêmes adresses.

**VRF, règles ou espaces de noms ?** Des règles `iif eth0 lookup 10` séparent aussi le trafic qui
traverse le routeur, mais rien n'y est automatique (routes connectées, adresses locales,
services). Un espace de noms réseau (`ip netns`) isole tout — interfaces, tables, pare-feu,
programmes — au prix de liens virtuels entre les espaces. La VRF est l'intermédiaire : une seule
pile réseau, des tables étanches.
""")
            + info_subtitle(tr("Rendre la configuration permanente"), tag="persist")
            + tr("""
Rien de ce qui précède ne survit à un redémarrage. Sur une Debian configurée par
`/etc/network/interfaces`, les routes et les règles d'un accès s'écrivent avec son interface :

```
auto eth2
iface eth2 inet static
    address 198.51.100.10/24
    post-up   ip route add default via 198.51.100.1 dev eth2 table 102
    post-up   ip rule add from 198.51.100.10 lookup 102 priority 1002
    pre-down  ip rule del priority 1002
```

- les noms des tables : `/etc/iproute2/rt_tables`, ou un fichier de `/etc/iproute2/rt_tables.d/` ;
- les règles nftables : `/etc/nftables.conf`, chargé par le service `nftables` ;
- les paramètres du noyau (`rp_filter`, `tcp_l3mdev_accept`…) : un fichier de `/etc/sysctl.d/` ;
- `systemd-networkd` et NetworkManager ont leurs propres mots-clés pour les règles, les tables et
  les VRF.
""")
            + info_subtitle(tr("Vérifier et dépanner"), tag="diag")
            + tr("""
### @@sec:commands@@ Les commandes utiles

| question | commande |
|----------|----------|
| quelles règles, dans quel ordre ? | `ip rule` |
| que contient une table ? toutes les tables ? | `ip route show table 102` ; `ip route show table all` |
| quelle route pour ce paquet ? | `ip route get DEST from SOURCE iif INTERFACE` (et `mark N`) |
| par où sort-il vraiment, sous quelle adresse ? | `tcpdump -n -i eth1 host DEST`, puis `-i eth2` |
| quelles marques sont posées ? | `nft list ruleset` ; ajouter `counter` à une règle pour compter |
| le filtre par chemin inverse jette-t-il ? | `nstat -az TcpExtIPReversePathFilter` |
| quelles VRF, avec quelles interfaces ? | `ip -br link show type vrf` ; `ip link show master vrf-blue` |
| la passerelle répond-elle ? | `ip neigh` |

### @@sec:troubleshooting@@ Symptômes et causes

| symptôme | cause probable |
|----------|----------------|
| la requête sort, rien ne revient jamais | elle sort par un fournisseur avec l'adresse de l'autre (section @@ref:bcp38@@) |
| une requête arrive, la machine répond, le client ne reçoit rien | la réponse suit la route par défaut de `main` : règle `from` absente (section @@ref:own@@) |
| après une règle `from`, les réseaux du site ne se joignent plus | la table ne contient que la route par défaut (section @@ref:connected@@) |
| la marque est posée, la route ne change pas | marque posée après le routage, ou règle `fwmark` absente ou placée après une règle qui répond déjà (section @@ref:fwmark@@) |
| le paquet sort par le bon accès, la réponse revient, la connexion n'aboutit pas | filtre par chemin inverse strict (section @@ref:rpfilter@@) |
| un `ping` en cours ne change pas de chemin après une modification | sa traduction d'adresse est mémorisée : relancer le test (section @@ref:nat@@) |
| le serveur publié répond par un accès, pas par l'autre | ses réponses sont routées avec son adresse privée (section @@ref:connmark@@) |
| dans une VRF, `ping` vers le routeur répond mais pas `curl` | le service est dans la VRF par défaut (section @@ref:vrf-services@@) |
| *Network is unreachable* sur le routeur pour un réseau d'une VRF | commande lancée dans la VRF par défaut (section @@ref:vrf-tools@@) |
| un client d'une VRF atteint un réseau qui n'est pas le sien | table de la VRF non fermée (section @@ref:vrf-tables@@) |
""")
        )

    # -- addresses and routes -------------------------------------------------------------------

    def iface(self, key: str) -> IPv4Interface:
        """An address of the data with its prefix (``r1_acc2``, ``pc1a``, ``www``...)."""
        return getattr(self.data.ips, key)

    def ip(self, key: str):
        """The same address without its prefix."""
        return self.iface(key).ip

    def net(self, key: str) -> IPv4Network:
        return getattr(self.data.nets, key)

    def uplink_ip(self, n: int, isp: int):
        """The public address of the router of site *n* at ISP *isp*."""
        return self.ip(f"r{n}_acc{isp}")

    def isp_gw(self, isp: int):
        """The address of ISP *isp* in its access network: the next hop of the site routers."""
        return self.ip(f"isp{isp}_acc{isp}")

    def lan_ip(self, lan: str):
        """The address of the router of *lan* in that LAN: the gateway of its host."""
        return self.ip(f"r{lan[3]}_{lan}")

    def svc_ip(self, i: int):
        """The destination number *i* of the prefix ``www`` owns."""
        return self.net("svc").network_address + i

    def build_net_config(self) -> Dict[str, NetConfigEntry]:
        """Addresses and routes of the ``initial`` state.  The ISPs and the Internet hosts know the
        public networks only; a site router has a default route by ISP1 alone; ``r6`` gets no
        address on the ports of the customers (the students add them once the ports are in a VRF)."""
        default = IPv4Network("0.0.0.0/0")
        iface, net = self.iface, self.net
        to_access = [(net("acc1"), iface("isp1_core")), (net("acc2"), iface("isp2_core"))]
        to_svc = (net("svc"), iface("www"))
        config: Dict[str, NetConfigEntry] = {
            "isp1": [([iface("isp1_acc1")], []), ([iface("isp1_core")], [to_access[1], to_svc])],
            "isp2": [([iface("isp2_acc2")], []), ([iface("isp2_core")], [to_access[0], to_svc])],
            "www": [([iface("www")], to_access)],
            "ext": [([iface("ext")], to_access + [to_svc])],
        }
        for n in SITES:
            router = f"r{n}"
            entry: NetConfigEntry = [None] * (max(SITE_LANS[n]) + 1 if max(SITE_LANS[n]) > 2 else 3)
            entry[1] = ([iface(f"{router}_acc1")], [(default, iface("isp1_acc1"))])
            entry[2] = ([iface(f"{router}_acc2")], [])
            for eth, lan in SITE_LANS[n].items():
                entry[eth] = ([iface(f"{router}_{lan}")], [])
                config[LAN_HOST[lan]] = [([iface(LAN_HOST[lan])], [(default, iface(f"{router}_{lan}"))])]
            config[router] = entry
        config[VRF_ROUTER] = [([], [])] * len(VRF_NETS) + [([iface("r6_mgmt")], [])]
        for vrf_net, (_, host) in VRF_NETS.items():
            config[host] = [([iface(host)], [(default, iface(f"{VRF_ROUTER}_{vrf_net}"))])]
        config["admin"] = [([iface("admin")], [(default, iface("r6_mgmt"))])]
        return config

    def interfaces(self, machine: str) -> List[str]:
        """The interfaces of *machine*, ``eth0`` first."""
        return [f"eth{i}" for i in range(len(self.net_config[machine]))]

    def rp_filter_sysctls(self, machine: str) -> Dict[str, int]:
        """The reverse-path filter of a router, written on ``all``, ``default`` and every interface
        (the kernel applies the highest of ``all`` and the interface): strict on ``r3``, off
        elsewhere, whatever the host and Kathara left there."""
        value = 1 if machine == STRICT_ROUTER else 0
        scopes = ["all", "default"] + self.interfaces(machine)
        return {f"net.ipv4.conf.{scope}.rp_filter": value for scope in scopes}

    # -- the rules given at start ---------------------------------------------------------------

    def isp_conf(self, isp: int) -> str:
        """The ingress filter of an ISP (BCP 38): what comes in from the access network with a
        source address the ISP did not assign is dropped, before any routing decision."""
        return CONF_HEADER + (
            "table ip bcp38 {\n"
            "    chain prerouting {\n"
            "        type filter hook prerouting priority raw; policy accept;\n"
            f'        iifname "eth0" ip saddr != {self.net(f"acc{isp}")} counter drop\n'
            "    }\n"
            "}\n")

    def nat_table(self, router: str) -> str:
        """The address translation given on a site router: a masquerade on both uplinks, without a
        criterion on the source (the packets of the router itself, rerouted after the choice of
        their source address, are translated too), and on ``r4`` the port forward of both uplinks."""
        lines = ["table ip nat {"]
        if router == "r4":
            lines += ["    chain prerouting {",
                      "        type nat hook prerouting priority dstnat; policy accept;",
                      f'        iifname {{ "eth1", "eth2" }} tcp dport {PUB_PORT} dnat to {self.ip("web4")}:{HTTP_PORT}',
                      "    }"]
        lines += ["    chain postrouting {",
                  "        type nat hook postrouting priority srcnat; policy accept;",
                  '        oifname "eth1" masquerade',
                  '        oifname "eth2" masquerade',
                  "    }",
                  "}"]
        return "\n".join(lines) + "\n"

    def given_conf(self, router: str) -> str:
        """The ``/etc/nftables.conf`` written and loaded on a site router by `initial`."""
        return CONF_HEADER + self.nat_table(router)

    # -- the reference solution (used by `final` and by the instructor texts) -------------------

    def mangle_table(self, router: str, bonus: bool = True) -> str:
        """The marks of the reference solution (``r3``: a flow chosen by its port, forwarded and,
        with *bonus*, emitted by the router; ``r4``: the uplink a connection came in by), ``''``
        elsewhere."""
        if router == "r3":
            chains = {
                "prerouting": ("type filter hook prerouting priority mangle; policy accept;",
                               [f'iifname "eth0" tcp dport {BULK_PORT} meta mark set {MARK}']),
            }
            if bonus:
                chains["output"] = ("type route hook output priority mangle; policy accept;",
                                    [f'oifname "eth1" tcp dport {BULK_PORT} meta mark set {MARK}'])
        elif router == "r4":
            chains = {
                "prerouting": ("type filter hook prerouting priority mangle; policy accept;",
                               [f'iifname "eth2" ct state new ct mark set {MARK}',
                                f'iifname "eth0" ct mark {MARK} meta mark set ct mark']),
            }
        else:
            return ""
        lines = ["table ip mangle {"]
        for name, (declaration, rules) in chains.items():
            lines += [f"    chain {name} {{", f"        {declaration}"]
            lines += [f"        {rule}" for rule in rules]
            lines.append("    }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def reference_conf(self, router: str) -> str:
        """The ``/etc/nftables.conf`` of a site router in the reference solution."""
        mangle = self.mangle_table(router)
        return CONF_HEADER + self.nat_table(router) + ("\n" + mangle if mangle else "")

    def reference_routes(self, router: str) -> List[str]:
        """The ``ip route`` commands of the reference solution on *router* (re-applicable)."""
        n = int(router[1])

        def default(isp: int) -> str:
            return f"ip route replace default via {self.isp_gw(isp)} dev {UPLINK[isp]} table {TABLE[isp]}"

        def lans(isp: int) -> List[str]:
            return [f"ip route replace {self.net(lan)} dev eth{eth} table {TABLE[isp]}"
                    for eth, lan in SITE_LANS[n].items()]

        if router in ("r1", "r3", "r4"):
            return [default(2)] + lans(2)
        if router == "r2":
            return [default(1)] + lans(1) + [default(2)] + lans(2)
        if router == "r5":
            hops = " ".join(f"nexthop via {self.isp_gw(isp)} dev {UPLINK[isp]} weight {WEIGHT[isp]}" for isp in ISPS)
            return [f"ip route replace default {hops}"]
        return []

    def reference_rules(self, router: str) -> List[str]:
        """The selectors and actions of the ``ip rule add`` commands of the reference solution."""
        if router == "r1":
            return [f"from {self.net('lan1b')} lookup {TABLE[2]} priority 1000"]
        if router == "r2":
            return [f"from {self.uplink_ip(2, isp)} lookup {TABLE[isp]} priority {1000 + isp}" for isp in ISPS]
        if router in ("r3", "r4"):
            return [f"fwmark {MARK} lookup {TABLE[2]} priority 1000"]
        return []

    def reference_sysctls(self, router: str) -> Dict[str, int]:
        if router == "r3":
            return {"net.ipv4.conf.eth2.rp_filter": 2}      # loose: the highest of `all` (1) and eth2 (2)
        if router == VRF_ROUTER:
            return {"net.ipv4.tcp_l3mdev_accept": 1}
        return {}

    def vrf_commands(self, leak: bool = True, reapply: bool = False) -> List[str]:
        """The reference solution of part 6 on ``r6``, with or without the bonus: as an
        instructor would type it, or (*reapply*) in the form the `final` state may run twice."""
        add = "replace" if reapply else "add"
        commands = []
        for name, table, ports in VRF.values():
            create = f"ip link add {name} type vrf table {table}"
            commands += [f"ip link show {name} >/dev/null 2>&1 || {create}" if reapply else create,
                         f"ip link set {name} up"]
            commands += [f"ip link set {port} master {name}" for port in ports]
        for net, (eth, _) in VRF_NETS.items():
            commands.append(f"ip addr {add} {self.iface(f'{VRF_ROUTER}_{net}')} dev eth{eth}")
        commands += self.vrf_closing_commands(add)
        if leak:
            commands += self.vrf_leak_commands(add)
        return commands

    @staticmethod
    def vrf_closing_commands(add: str = "add") -> List[str]:
        """The default route that closes the table of each VRF: no fall through to the main table."""
        return [f"ip route {add} unreachable default metric {VRF_UNREACHABLE_METRIC} table {table}"
                for _, table, _ in VRF.values()]

    def vrf_leak_commands(self, add: str = "add") -> List[str]:
        """The bonus of part 6: the main table reaches the blue customer through its VRF device,
        the table of the blue VRF knows the way back to the management network."""
        name, table, _ = VRF["blue"]
        return [f"ip route {add} {self.net('blue_a')} dev {name}",
                f"ip route {add} {self.net('mgmt')} dev eth{MGMT_IF} table {table}"]

    def reference_commands(self, router: str) -> List[str]:
        """The commands of the reference solution on *router*, as an instructor would type them."""
        commands = self.vrf_commands() if router == VRF_ROUTER else list(self.reference_routes(router))
        commands += [f"ip rule add {rule}" for rule in self.reference_rules(router)]
        commands += [f"sysctl -w {name}={value}" for name, value in self.reference_sysctls(router).items()]
        return commands

    # -- states ---------------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, entry in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=entry)
        for m in self.get_machine_names():
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in FORWARDERS))
        for m in FORWARDERS:
            set_sysctl(net_scheme=self, machine_name=m, sysctl_config=self.rp_filter_sysctls(m))

        # www answers on every address of the prefix `svc`
        self.cmd("www", f"ip route replace local {self.net('svc')} dev lo")
        for isp in ISPS:
            self.file(f"isp{isp}", CONF_FILE, self.isp_conf(isp), permissions=0o644)
            self.cmd(f"isp{isp}", f"nft -f {CONF_FILE}")
        for router in ROUTERS:
            self.file(router, CONF_FILE, self.given_conf(router), permissions=0o644)
            self.cmd(router, f"nft -f {CONF_FILE}")

        install_echo_server(self, "www", ports=(HTTP_PORT, BULK_PORT))
        for m in ("pc1a", "r2", "web4", "blue1", "blue2", "red1", "red2", VRF_ROUTER, "admin"):
            install_echo_server(self, m, ports=(HTTP_PORT,))
        internet = [m for m in self.get_machine_names() if m not in VRF_SITE]
        create_hosts_file(self, DOMAIN, machine_list=internet, included=["www", "ext"])

    @sre_state(user_allowed=False)
    def final(self):
        """The reference solution (every point, bonus included); may be applied again."""
        for router in ROUTERS:
            self.file(router, CONF_FILE, self.reference_conf(router), permissions=0o644)
            self.cmd(router, f"nft -f {CONF_FILE}")
            for command in self.reference_routes(router):
                self.cmd(router, command)
            for rule in self.reference_rules(router):
                self.cmd(router, f"ip rule del {rule} 2>/dev/null; ip rule add {rule}")
        for command in self.vrf_commands(reapply=True):
            self.cmd(VRF_ROUTER, command)
        for router in (STRICT_ROUTER, VRF_ROUTER):
            set_sysctl(net_scheme=self, machine_name=router, sysctl_config=self.reference_sysctls(router))

    @sre_state(user_allowed=True,
               description=tr("Panne : le FAI 1 ne répond plus (son lien d'accès est coupé chez lui)"))
    def isp1_down(self):
        self.cmd("isp1", "ip link set eth0 down")

    @sre_state(user_allowed=True, description=tr("Fin de la panne : le FAI 1 est rétabli"))
    def isp1_up(self):
        self.cmd("isp1", "ip link set eth0 up")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _same_ip(answer, expected) -> bool:
    """The address typed by a student (with or without a prefix) is *expected*."""
    try:
        return ip_address(_norm(answer).split("/")[0]) == ip_address(str(expected).split("/")[0])
    except ValueError:
        return False


def _block(lines) -> str:
    """Command lines as the content of a fenced block of an instructor text."""
    return "\n".join(lines) + "\n"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        ns = self.net_scheme
        www = ns.ip("www")
        isp_gw = {isp: ns.isp_gw(isp) for isp in ISPS}
        pub = {(n, isp): ns.uplink_ip(n, isp) for n in SITES for isp in ISPS}    # the public addresses
        lan = {name: ns.net(name) for name in LAN_HOST}
        lan_gw = {name: ns.lan_ip(name) for name in LAN_HOST}
        host = {name: ns.ip(name) for name in list(LAN_HOST.values()) + ["blue1", "blue2", "admin", "ext"]}
        gw_a, gw_b = ns.ip("r6_blue_a"), ns.ip("r6_blue_b")
        cust_a, cust_b, mgmt = ns.net("blue_a"), ns.net("blue_b"), ns.net("mgmt")

        # ---- diagnostics kept in the archive ----
        for router in ROUTERS + (VRF_ROUTER,):
            for command in ("ip -4 -br addr", "ip rule", "ip route show table all", "nft list ruleset"):
                self.test(router, command, allow_error=True)
        for isp in ISPS:
            self.test(f"isp{isp}", "nft list table ip bcp38", allow_error=True)

        # ---- the probes ----
        def echo(src, target, port=HTTP_PORT, source=None):
            """The echo page of *target*:*port* asked from *src* (bound to the address *source*
            when given), parsed; every field is empty when nothing came back.  Each call registers
            its command: none may sit behind an `and` / `or`."""
            bind = f"--interface {source} " if source is not None else ""
            out, code = self.test(src, f"curl -s -m {PROBE_TIMEOUT} {bind}http://{target}:{int(port)}/",
                                  timeout=PROBE_TIMEOUT + 5, allow_error=True)
            return parse_http_echo(out if code == 0 else "")

        def answered(page, server, server_ip, client_ip, port=HTTP_PORT) -> bool:
            """The page comes from the echo server *server*, reached at *server_ip*:*port*, and that
            server saw the client as *client_ip*.  The address and the port that answered are
            checked too: a destination NAT towards another address of the server does not count."""
            return (page["server"] == server and page["server_ip"] == str(server_ip)
                    and page["server_port"] == str(port) and page["client_ip"] == str(client_ip))

        # part 1 (r1): the guests by ISP2, the staff and the router by ISP1, the LANs still joined
        p1_guest = echo("pc1b", www)
        p1_staff = echo("pc1a", www)
        p1_lans = echo("pc1b", host["pc1a"])
        p1_router = echo("r1", www)
        # part 2 (r2): its service asked from the Internet on both public addresses, its own
        # connections bound to the ISP2 address or not, its LAN
        p2_in = {isp: echo("www", pub[2, isp]) for isp in ISPS}
        p2_bound = echo("r2", www, source=pub[2, 2])
        p2_plain = echo("r2", www)
        p2_lan = echo("pc2", pub[2, 2])
        # part 3 (r3): the marked flow, the other one, the same two emitted by the router
        r3_rules = get_ip_rules(self, STRICT_ROUTER)
        r3_tables = get_route_tables(self, STRICT_ROUTER)
        r3_marks = tc.nft_mark_rules(tc.get_nft_rules(self, STRICT_ROUTER))
        p3_bulk = echo("pc3", www, BULK_PORT)
        p3_web = echo("pc3", www)
        p3_own_bulk = echo(STRICT_ROUTER, www, BULK_PORT)
        p3_own_web = echo(STRICT_ROUTER, www)
        # part 4 (r4): the published server asked on both public addresses, its own traffic
        p4_in = {isp: echo("www", pub[4, isp], PUB_PORT) for isp in ISPS}
        p4_out = echo("web4", www)
        # part 5 (r5): the default route and the uplink of SPREAD destinations
        r5_hops = default_nexthops(get_route_tables(self, "r5").get(MAIN_TABLE, []))
        spread_out, _ = self.test("pc5", spread_cmd(ns.svc_ip(1), SPREAD, timeout=PROBE_TIMEOUT),
                                  timeout=SPREAD_TIMEOUT, allow_error=True)
        spread = parse_spread(spread_out)
        # part 6 (r6): the VRF devices, both customers at once, the service of r6, the closed table, the leak
        vrfs = {name: vrf for name, vrf in vrf_devices(get_ip_links(self, VRF_ROUTER)).items() if vrf["up"]}
        p6_path = {colour: echo(f"{colour}1", host["blue2"]) for colour in VRF}
        p6_service = {colour: echo(f"{colour}1", gw_a) for colour in VRF}
        ping_out, _ = self.test("red1", f"ping -n -c 1 -W 1 {host['admin']} 2>&1; true", allow_error=True)
        p6_closed = parse_ping(ping_out)
        p6_leak = echo("admin", host["blue1"])
        # ISP1 cut by the state isp1_down?
        isp1_links = get_ip_links(self, "isp1")

        # ---- what the probes say ----
        # A probe and its control make one element: a default route moved to ISP2 passes the first
        # and fails the second.
        guests_by_isp2 = (answered(p1_guest, "www", www, pub[1, 2]) and answered(p1_staff, "www", www, pub[1, 1]))
        lans_joined = guests_by_isp2 and answered(p1_lans, "pc1a", host["pc1a"], host["pc1b"])
        router_by_isp1 = guests_by_isp2 and answered(p1_router, "www", www, pub[1, 1])

        both_uplinks = all(answered(p2_in[isp], "r2", pub[2, isp], www) for isp in ISPS)
        bound_source = (answered(p2_bound, "www", www, pub[2, 2]) and answered(p2_plain, "www", www, pub[2, 1]))
        lan_kept = both_uplinks and answered(p2_lan, "r2", pub[2, 2], host["pc2"])

        # the marks a prerouting chain sets and a fwmark rule sends to a table leaving by ISP2
        # (the first such rule decides, as in the kernel)
        def routed_marks(hook: str) -> set:
            marks = {m["mark"] for m in r3_marks if m["hook"] == hook and m["mark"]}
            return {mark for mark in marks
                    if leaves_by(r3_tables.get((tables_of_mark(r3_rules, mark) or [""])[0], []), UPLINK[2])}

        mark_routed = bool(routed_marks("prerouting"))
        flows_split = (mark_routed and answered(p3_bulk, "www", www, pub[3, 2], BULK_PORT)
                       and answered(p3_web, "www", www, pub[3, 1]))
        own_split = (flows_split and bool(routed_marks("output"))
                     and answered(p3_own_bulk, "www", www, pub[3, 2], BULK_PORT)
                     and answered(p3_own_web, "www", www, pub[3, 1]))

        published = all(answered(p4_in[isp], "web4", host["web4"], www) for isp in ISPS)
        server_by_isp1 = published and answered(p4_out, "www", www, pub[4, 1])

        hop = {h["dev"]: h for h in r5_hops}
        two_hops = (len(r5_hops) == 2
                    and all(hop.get(UPLINK[isp], {}).get("gateway") == str(isp_gw[isp]) for isp in ISPS))
        weighted = two_hops and hop[UPLINK[1]]["weight"] * WEIGHT[2] == hop[UPLINK[2]]["weight"] * WEIGHT[1]
        spread_targets = {str(ns.svc_ip(i)) for i in range(1, SPREAD + 1)}
        shared = (two_hops and spread["servers"] >= spread_targets
                  and set(spread["clients"]) == {str(pub[5, isp]) for isp in ISPS})

        two_vrfs = len(vrfs) >= 2 and len({vrf["table"] for vrf in vrfs.values()}) == len(vrfs)
        port_vrf = {port: vrf_of_port(vrfs, port) for _, _, ports in VRF.values() for port in ports}
        ports_placed = (None not in port_vrf.values()
                        and all(len({port_vrf[port] for port in ports}) == 1 for _, _, ports in VRF.values())
                        and port_vrf["eth0"] != port_vrf["eth2"])
        customers_routed = ports_placed and all(
            answered(p6_path[colour], f"{colour}2", host["blue2"], host["blue1"]) for colour in VRF)
        service_reached = customers_routed and all(
            answered(p6_service[colour], VRF_ROUTER, gw_a, host["blue1"]) for colour in VRF)
        # an ICMP error sent by the gateway: the table of the red VRF ends with a route that
        # refuses (`unreachable`, `prohibit`), instead of falling through to the main table
        table_closed = customers_routed and p6_closed["received"] == 0 and p6_closed["from"] == str(gw_a)
        leak = customers_routed and table_closed and answered(p6_leak, "blue1", host["blue1"], host["admin"])

        if isp1_links and not link_up(isp1_links, "eth0"):
            self.add_warning(tr("le FAI 1 est coupé (état « isp1_down ») : tout ce qui doit passer par lui échoue, "
                                "dans les parties 1 à 5 ; appliquez l'état « isp1_up » pour le rétablir"))

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        sites = tr("""
| partie | routeur | `eth1` (FAI 1) | `eth2` (FAI 2) | réseau privé (interface, adresse de `rN`) | machine |
|--------|---------|----------------|----------------|-------------------------------------------|---------|
| 1 | **`r1`** | `{a11}` | `{a12}` | `lan1a` : `{lan1a}` (`eth0`, `{g1a}`) — le personnel | `pc1a` (`{pc1a}`) |
|   |          |         |         | `lan1b` : `{lan1b}` (`eth3`, `{g1b}`) — les invités | `pc1b` (`{pc1b}`) |
| 2 | **`r2`** | `{a21}` | `{a22}` | `lan2` : `{lan2}` (`eth0`, `{g2}`) | `pc2` (`{pc2}`) |
| 3 | **`r3`** | `{a31}` | `{a32}` | `lan3` : `{lan3}` (`eth0`, `{g3}`) | `pc3` (`{pc3}`) |
| 4 | **`r4`** | `{a41}` | `{a42}` | `lan4` : `{lan4}` (`eth0`, `{g4}`) | `web4` (`{web4}`) |
| 5 | **`r5`** | `{a51}` | `{a52}` | `lan5` : `{lan5}` (`eth0`, `{g5}`) | `pc5` (`{pc5}`) |

| Internet | adresses |
|----------|----------|
| `isp1` (FAI 1) | `{isp1}` sur `acc1` (`{acc1}`) : **la passerelle du FAI 1** ; `{isp1_core}` sur `core` |
| `isp2` (FAI 2) | `{isp2}` sur `acc2` (`{acc2}`) : **la passerelle du FAI 2** ; `{isp2_core}` sur `core` |
| `www` | `{www}` sur `core` (`{core}`) ; il possède aussi tout le préfixe `{svc}` |
| `ext` | `{ext}` sur `core` |

| site 6 (partie 6) | réseau A | réseau B |
|-------------------|----------|----------|
| client **bleu** | `blue_a` (`eth0` de `r6`) : `{cust_a}`, poste `blue1` (`{blue1}`) | `blue_b` (`eth1`) : `{cust_b}`, poste `blue2` (`{blue2}`) |
| client **rouge** | `red_a` (`eth2`) : `{cust_a}`, poste `red1` (`{blue1}`) | `red_b` (`eth3`) : `{cust_b}`, poste `red2` (`{blue2}`) |
| passerelle attendue sur `r6` | `{gw_a}` | `{gw_b}` |
| administration | `mgmt` (`eth4`) : `{mgmt}`, `r6` (`{r6_mgmt}`), poste `admin` (`{admin}`) | |
""").format(**{f"a{n}{isp}": pub[n, isp] for n in SITES for isp in ISPS},
            **{name: net for name, net in lan.items()},
            g1a=lan_gw["lan1a"], g1b=lan_gw["lan1b"], **{f"g{n}": lan_gw[f"lan{n}"] for n in (2, 3, 4, 5)},
            **host, isp1=isp_gw[1], isp2=isp_gw[2], isp1_core=ns.ip("isp1_core"), isp2_core=ns.ip("isp2_core"),
            acc1=ns.net("acc1"), acc2=ns.net("acc2"), core=ns.net("core"), svc=ns.net("svc"), www=www,
            cust_a=cust_a, cust_b=cust_b, gw_a=gw_a, gw_b=gw_b, mgmt=mgmt, r6_mgmt=ns.ip("r6_mgmt"))

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="456586e318e310f6",
            description=tr("""
Lisez l'onglet **Informations** : il présente le routage par politique sous Linux (plusieurs tables
de routage et les règles `ip rule`, deux fournisseurs d'accès, marques de paquets et de connexions,
filtrage par chemin inverse, routes à plusieurs chemins, VRF) et la façon de vérifier ce que le
noyau décide.

**La maquette** (onglet *Schéma*). **Internet** est fait de deux fournisseurs d'accès (FAI), `isp1`
et `isp2`, reliés au réseau `core` où se trouvent `www`, un serveur d'Internet, et `ext`, le poste
d'un internaute. Cinq petits sites sont abonnés **aux deux FAI** : le routeur `rN` du site N a
**`eth0` sur son réseau privé, `eth1` sur le réseau d'accès du FAI 1 (`acc1`) et `eth2` sur celui du
FAI 2 (`acc2`)**. Un sixième site, sans accès à Internet, sert aux VRF : le routeur `r6`, deux
clients (bleu et rouge) et un poste d'administration.

**Une partie, un site, un routeur.** La partie N du TP se fait sur le routeur `rN`, et sur lui
seul : les six parties sont **indépendantes**. Faites-les dans l'ordre que vous voulez ; ce que
vous configurez sur un routeur ne change rien aux autres parties.
""")
            + sites
            + tr("""
**Déjà en place** (ne pas modifier) :

- les adresses, le routage sur les routeurs, la route par défaut de chaque poste par le routeur de
  son site ;
- sur `r1` … `r5`, **une seule route par défaut, par le FAI 1** : l'accès au FAI 2 est branché et
  adressé, mais rien ne l'emprunte ;
- sur `r1` … `r5`, la traduction d'adresses : `{conf_file}` contient un `masquerade` sur `eth1` et
  un sur `eth2`. Un paquet qui sort par une de ces interfaces prend donc l'adresse publique de
  **cette** interface. `nft -f {conf_file}` recharge ce fichier, **et efface les règles nftables que
  vous auriez ajoutées à la main** (il commence par `flush ruleset`) : vous pouvez y écrire vos
  propres tables pour les conserver ;
- **chaque FAI filtre ce qui entre chez lui** : `isp1` jette tout paquet venant de `acc1` dont
  l'adresse source n'est pas une adresse de `acc1`, et `isp2` fait de même pour `acc2` (section
  @@ref:bcp38@@). Un paquet qui sort par un FAI avec l'adresse publique de l'autre est perdu ;
- le filtrage par chemin inverse (`rp_filter`, section @@ref:rpfilter@@) est **désactivé** sur les
  routeurs, sauf sur **`r3` où il est strict** (valeur 1), comme sur beaucoup de distributions ;
- sur `r6`, les quatre interfaces des clients (`eth0` … `eth3`) sont actives mais **sans adresse**.

**Les serveurs de test** répondent par leur nom et par les adresses des deux bouts de la
connexion, telles qu'ils les voient : `SERVER=`, `SERVER_IP=`, `SERVER_PORT=`, `CLIENT_IP=`,
`CLIENT_PORT=`. Il y en a un sur `www` (ports {http} et {bulk}) et, sur le port {http}, sur `pc1a`,
`r2`, `web4`, `blue1`, `blue2`, `red1`, `red2`, `r6` et `admin`. **`CLIENT_IP` est l'adresse sous
laquelle le serveur voit son client** : quand une machine d'un site interroge `www`, c'est
l'adresse publique de l'interface par laquelle la requête est sortie. Elle dit donc **par quel FAI
la requête est passée**.

**Pour tester.** `curl -s -m 3 http://ADRESSE:PORT/ ; echo "code $?"` affiche la réponse du serveur
puis le code de retour de `curl` : **0** avec une réponse, **7** pour un refus immédiat, **28**
quand le délai de 3 secondes est dépassé. Sur les machines des sites 1 à 5, `www` et `ext` sont des
noms connus (`/etc/hosts`). Chaque `curl` ouvre une nouvelle connexion : c'est ce qu'il faut pour
essayer une règle, car **une connexion déjà suivie garde sa traduction d'adresse** (un `ping` lancé
avant une modification ne change pas de chemin de façon propre ; la commande `conntrack` n'est pas
installée). `tcpdump -n -i eth1` (ou `eth2`) montre ce qui passe par un accès ; les réseaux `acc1`,
`acc2` et `core` sont des commutateurs : un routeur n'y voit que son propre trafic.

**`ext` est le poste d'où tester « depuis Internet »** (parties 2 et 4). Un test lancé depuis un
autre routeur de la maquette ne prouverait rien : `r1` … `r5` sont voisins sur les réseaux d'accès
et se joignent directement, sans traverser un FAI.

**Deux états** (onglet *Appliquer une configuration*) simulent une panne, pour la partie 5 :
`isp1_down` coupe le FAI 1 au-delà du réseau d'accès (les interfaces `eth1` des routeurs restent
actives), `isp1_up` le rétablit. Tant que le FAI 1 est coupé, les autres parties perdent des points.

Règles valables pour tout le TP :

- l'évaluation observe **ce que fait le noyau au moment où elle a lieu** : rien n'a besoin d'être
  enregistré dans un fichier (la section @@ref:persist@@ dit comment on le ferait). Elle lance des
  `curl` depuis les machines de la maquette et lit les réponses des serveurs de test ;
- les numéros (ou les noms) de tables, les priorités des règles et les valeurs des marques sont
  **libres** ; les exemples des questions utilisent les tables 101 et 102 et la marque {mark} ;
- un résultat demandé et ce qui ne doit pas changer sont notés **ensemble** : envoyer tout le
  trafic par le FAI 2 ne rapporte rien ;
- certaines questions ont un **formulaire** : notez-y ce que vous observez. Les valeurs que vous
  tapez comptent dans l'auto-évaluation ; les réponses choisies dans une liste n'y comptent pas,
  elles sont notées avec le reste à la fin du TP.
""").format(conf_file=CONF_FILE, http=HTTP_PORT, bulk=BULK_PORT, mark=MARK)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` applique toute la solution (bonus compris) et remplit les formulaires ; il
est ré-applicable et donne 100/100 plus les 6 points de bonus.

L'évaluation n'utilise pas de copie cachée (des tables, des règles, des marques et des VRF ne se
recopient pas comme un jeu de règles) : elle interroge les serveurs de test avec `curl -s -m
{timeout}` et lit `SERVER`, `SERVER_IP`, `SERVER_PORT` et `CLIENT_IP`. Les sondes des parties 2 et
4 partent de `www`, sans terminal ; celles des parties 1, 3, 5 et 6 partent des postes des sites.
Chaque FAI rejetant les adresses sources qui ne sont pas les siennes, une traduction d'adresse ne
peut pas imiter l'autre accès. Une sonde et son témoin forment un seul élément, et ce qu'un projet
intact réussirait déjà n'est compté qu'avec l'élément principal de sa partie : un projet intact
vaut 0. Chaque partie a son routeur : rien de ce qui est fait dans une partie ne change les points
d'une autre (sauf l'état `isp1_down`, signalé par un avertissement). Les réponses choisies dans
une liste ne comptent que dans l'évaluation finale. Barème : 20 + 14 + 18 + 14 + 12 + 22 = 100,
bonus 3 (partie 3) + 3 (partie 6).
""").format(timeout=PROBE_TIMEOUT)),
        )

        # =====================================================================
        # Part 1 — r1: routing by the source
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Router selon la source"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Router selon la source"),
            hash="fe6d36ba87c23c19",
            description=tr("""
**Site 1** : deux réseaux privés derrière **`r1`**. `lan1a` (`{lan1a}`, sur `eth0`) est celui du
**personnel**, avec le poste `pc1a` (`{pc1a}`) ; `lan1b` (`{lan1b}`, sur `eth3`) est celui des
**invités**, avec le poste `pc1b` (`{pc1b}`). Adresses publiques de `r1` : `{a1}` chez le FAI 1
(`eth1`, passerelle `{g1}`) et `{a2}` chez le FAI 2 (`eth2`, passerelle `{g2}`).

**But** : le trafic des invités sort par le FAI 2 ; celui du personnel, et celui de `r1` lui-même,
continuent de sortir par le FAI 1 ; les deux réseaux du site se joignent toujours. **À lire** :
sections @@ref:rpdb@@ et @@ref:selectors@@ des Informations.
""").format(lan1a=lan["lan1a"], lan1b=lan["lan1b"], pc1a=host["pc1a"], pc1b=host["pc1b"],
            a1=pub[1, 1], a2=pub[1, 2], g1=isp_gw[1], g2=isp_gw[2])
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r1` (état `final`) :

```
{commands}```

Barème de la partie : `source_routing` 10 (les invités par le FAI 2 **et** le personnel par le
FAI 1), `lans_joined` 4, `router_traffic` 2, formulaire `q_rule_priority` 2 et `q_local_table` 2.
""").format(commands=_block(ns.reference_commands("r1")))),
        )

        q11_answers = {"prio_main": "32766", "table_local": "local"}
        q11 = self.question_form(
            section=self.section(1),
            title=tr("Lire la base de règles"),
            hash="8f48aa454b6e6648",
            description=tr("""
Sur `r1`, avant toute modification :

1. `ip rule` affiche la base de règles ; `ip route show table main` et `ip route show table local`
   affichent deux des tables qu'elle fait consulter (section @@ref:tables@@).
2. `ip route get {www} from {pc1b} iif eth3` demande au noyau comment il routerait un paquet de
   `pc1b` reçu sur `eth3` (section @@ref:route-get@@) : par quelle passerelle sortirait-il ?
""").format(www=www, pc1b=host["pc1b"])
            + tr("""
- Priorité de la règle qui fait consulter la table `main` : @@{{prio_main:[0-9]+}}@@
- Table qui contient la route `local {g1a}` (l'adresse de `r1` sur `eth0`) : @@{{table_local:>main|local|default}}@@
""").format(g1a=lan_gw["lan1a"])
            + instructor(tr("""
**Solution.** `ip rule` affiche `0: from all lookup local`, `32766: from all lookup main` et
`32767: from all lookup default`. Les adresses de la machine sont dans la table `local`, consultée
avant toutes les autres ; `ip route get` répond `via {g1} dev eth1` : seule la table `main` contient
une route par défaut, et elle passe par le FAI 1.

- Réponses : `32766` ; `local`.
""").format(g1=isp_gw[1])),
            cheat_answers={"final": q11_answers})

        self.question_dummy(
            section=self.section(1),
            title=tr("Les invités sortent par le FAI 2"),
            hash="eeb746d59e2d83f2",
            description=tr("""
1. Créez une **nouvelle table de routage** (un numéro de votre choix, 102 par exemple ; vous pouvez
   lui donner un nom dans `/etc/iproute2/rt_tables`) contenant une route par défaut par le FAI 2
   (`{g2}`, interface `eth2`).
2. Ajoutez la **règle** qui fait consulter cette table aux paquets dont l'adresse source est dans
   `{lan1b}`.
3. Vérifiez : `ip rule`, `ip route show table 102`, `ip route get {www} from {pc1b} iif eth3`, puis
   lancez `curl -s -m 3 http://www/` sur `pc1b` et sur `pc1a` : la ligne `CLIENT_IP=` doit valoir
   `{a2}` pour `pc1b` et `{a1}` pour `pc1a`.
4. Pourquoi ne suffisait-il pas de remplacer la route par défaut de `r1` par une route vers le
   FAI 2 ?
""").format(g2=isp_gw[2], lan1b=lan["lan1b"], www=www, pc1b=host["pc1b"], a1=pub[1, 1], a2=pub[1, 2])
            + instructor(tr("""
**Solution.** Sur `r1` :

```
ip route add default via {g2} dev eth2 table {table}
ip rule add from {lan1b} lookup {table} priority 1000
```

`ip route get {www} from {pc1b} iif eth3` répond alors `via {g2} dev eth2 table {table}`. Le
`masquerade` de `eth2`, déjà en place, donne aux paquets des invités l'adresse `{a2}` : `www` voit
`CLIENT_IP={a2}` pour `pc1b` et `CLIENT_IP={a1}` pour `pc1a`. Remplacer la route par défaut de la
table `main` enverrait **tout** le site par le FAI 2 : la table `main` ne distingue les paquets que
par leur destination. L'élément `source_routing` exige les deux résultats à la fois.
""").format(g2=isp_gw[2], lan1b=lan["lan1b"], table=TABLE[2], www=www, pc1b=host["pc1b"],
            a1=pub[1, 1], a2=pub[1, 2])))

        self.question_dummy(
            section=self.section(1),
            title=tr("Les réseaux du site restent joignables"),
            hash="9b0969f123da21fc",
            description=tr("""
1. Sur `pc1b`, interrogez le serveur de test de `pc1a` : `curl -s -m 3 http://{pc1a}/`. Si votre
   table ne contient qu'une route par défaut, la requête échoue. Sur `r1`, suivez le paquet avec
   `ip route get {pc1a} from {pc1b} iif eth3` et expliquez (section @@ref:connected@@).
2. Corrigez (la section @@ref:connected@@ présente deux façons de faire), puis vérifiez dans les
   deux sens : le `curl` ci-dessus, et `ping -c 1 {pc1b}` depuis `pc1a`.
3. Vérifiez que le trafic émis par `r1` lui-même sort toujours par le FAI 1 : `curl -s -m 3
   http://www/` sur `r1` doit afficher `CLIENT_IP={a1}`.
""").format(pc1a=host["pc1a"], pc1b=host["pc1b"], a1=pub[1, 1])
            + instructor(tr("""
**Solution.** Avec la seule route par défaut, `ip route get {pc1a} from {pc1b} iif eth3` répond
`via {g2} dev eth2 table {table}` : la règle a envoyé le paquet dans la table {table}, qui ne
connaît pas `{lan1a}` ; il part chez le FAI 2, qui n'a aucune route vers une adresse privée. Il
faut recopier les routes des réseaux du site dans la table :

```
ip route add {lan1a} dev eth0 table {table}
ip route add {lan1b} dev eth3 table {table}
```

ou faire consulter d'abord la table `main` privée de sa route par défaut, par une règle placée
avant : `ip rule add from {lan1b} lookup main suppress_prefixlength 0 priority 900`. Le trafic de
`r1` lui-même n'est pas concerné par la règle (ses adresses sources sont `{a1}` ou `{a2}`, pas des
adresses de `{lan1b}`) : il suit la table `main`.
""").format(pc1a=host["pc1a"], pc1b=host["pc1b"], g2=isp_gw[2], table=TABLE[2], lan1a=lan["lan1a"],
            lan1b=lan["lan1b"], a1=pub[1, 1], a2=pub[1, 2])))

        self.add_grade_element(
            title=no_tr("source_routing"), max_grade=10, grade_part=part1, grade=10 * int(guests_by_isp2),
            description=tr("pc1b (invités) sort par le FAI 2 et pc1a (personnel) par le FAI 1"))
        self.add_grade_element(
            title=no_tr("lans_joined"), max_grade=4, grade_part=part1, grade=4 * int(lans_joined),
            description=tr("pc1b joint toujours pc1a, sans traduction d'adresse"))
        self.add_grade_element(
            title=no_tr("router_traffic"), max_grade=2, grade_part=part1, grade=2 * int(router_by_isp1),
            description=tr("le trafic émis par r1 sort toujours par le FAI 1"))
        self.add_grade_element(
            title=no_tr("q_rule_priority"), max_grade=2, grade_part=part1,
            grade=2 * int(_norm(q11.get("prio_main")) == q11_answers["prio_main"]),
            description=tr("formulaire : priorité de la règle de la table main"))
        self.add_grade_element(
            title=no_tr("q_local_table"), max_grade=2, grade_part=part1, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q11.get("table_local")) == q11_answers["table_local"]),
            description=tr("formulaire : table des adresses locales"))

        # =====================================================================
        # Part 2 — r2: answering by the uplink a request came in by
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Répondre par où la requête est arrivée"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Répondre par où la requête est arrivée"),
            hash="b540823136639119",
            description=tr("""
**Site 2** : **`r2`** héberge lui-même un service (son serveur de test, port {http}) que l'on doit
pouvoir joindre **par ses deux adresses publiques** : `{a1}` chez le FAI 1 (`eth1`, passerelle
`{g1}`) et `{a2}` chez le FAI 2 (`eth2`, passerelle `{g2}`). Derrière lui, le réseau `lan2`
(`{lan2}`, sur `eth0`) et le poste `pc2` (`{pc2}`).

**But** : une requête arrivée par un FAI reçoit sa réponse **par le même FAI** ; une connexion que
`r2` ouvre depuis une de ses adresses publiques sort par le FAI de cette adresse ; le réseau `lan2`
n'y perd rien. **À lire** : section @@ref:multihoming@@ des Informations.
""").format(http=HTTP_PORT, a1=pub[2, 1], a2=pub[2, 2], g1=isp_gw[1], g2=isp_gw[2], lan2=lan["lan2"],
            pc2=host["pc2"])
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r2` (état `final`) :

```
{commands}```

Barème de la partie : `both_uplinks` 7 (le service répond à `www` sur ses deux adresses),
`bound_source` 3, `lan_kept` 2, formulaire `q_reply_path` 2.
""").format(commands=_block(ns.reference_commands("r2")))),
        )

        q21_answers = {"reply_if": "eth1", "dropper": "isp1"}
        q21 = self.question_form(
            section=self.section(1),
            title=tr("Observer la panne"),
            hash="ddee76011cdff17d",
            description=tr("""
1. Sur `ext` : `curl -s -m 3 http://{a1}/` puis `curl -s -m 3 http://{a2}/`. Le premier répond, pas
   le second.
2. Sur `r2`, lancez deux captures dans deux terminaux, `tcpdump -n -i eth1 tcp port {http}` et
   `tcpdump -n -i eth2 tcp port {http}`, puis relancez le second `curl`. Par quelle interface la
   demande de connexion (SYN) arrive-t-elle ? Par laquelle `r2` envoie-t-il sa réponse (SYN-ACK),
   et avec quelle adresse source ?
3. Pourquoi cette réponse n'arrive-t-elle jamais à `ext` (section @@ref:bcp38@@) ?
""").format(a1=pub[2, 1], a2=pub[2, 2], http=HTTP_PORT)
            + tr("""
- Interface par laquelle `r2` envoie sa réponse : @@{reply_if:>eth2|eth1}@@
- Machine qui jette cette réponse : @@{dropper:>www|isp2|isp1|ext}@@
""")
            + instructor(tr("""
**Solution.** Le SYN arrive par `eth2`. Le SYN-ACK part par **`eth1`**, avec l'adresse source
`{a2}` : pour choisir la sortie d'un paquet, `r2` ne consulte que la table `main`, dont la route
par défaut passe par le FAI 1, quelle que soit l'adresse source. **`isp1`** reçoit de son réseau
d'accès un paquet dont la source n'est pas une de ses adresses, et le jette (filtrage à l'entrée) :
`ext` ne reçoit rien et retransmet son SYN.

- Réponses : `eth1` ; `isp1`.
""").format(a2=pub[2, 2])),
            cheat_answers={"final": q21_answers})

        self.question_dummy(
            section=self.section(1),
            title=tr("Une table par accès"),
            hash="a35a78ce2fd6a57e",
            description=tr("""
1. Créez une table de routage par FAI (101 et 102 par exemple), chacune avec une route par défaut
   par la passerelle de son FAI (`{g1}` par `eth1`, `{g2}` par `eth2`).
2. Ajoutez les deux règles qui font consulter à un paquet **la table du FAI auquel appartient son
   adresse source** : `from {a1}` et `from {a2}` (section @@ref:own@@).
3. Vérifiez depuis `ext` que les deux adresses répondent. Puis, sur `r2`, ouvrez une connexion
   depuis l'adresse du FAI 2 : `curl -s -m 3 --interface {a2} http://www/` doit afficher
   `CLIENT_IP={a2}`, et `curl -s -m 3 http://www/` toujours `CLIENT_IP={a1}`.
4. Avant vos règles, le `curl --interface {a2}` aboutissait déjà : sous quelle adresse `www`
   voyait-il `r2`, et pourquoi (section @@ref:nat@@) ?
""").format(g1=isp_gw[1], g2=isp_gw[2], a1=pub[2, 1], a2=pub[2, 2])
            + instructor(tr("""
**Solution.** Sur `r2` :

```
ip route add default via {g1} dev eth1 table {t1}
ip route add default via {g2} dev eth2 table {t2}
ip rule add from {a1} lookup {t1} priority 1001
ip rule add from {a2} lookup {t2} priority 1002
```

La règle `from {a2}` suffit à la panne observée ; l'autre rend la configuration indépendante de la
route par défaut de la table `main`. Avant les règles, la connexion ouverte depuis `{a2}` sortait
par `eth1`, où le `masquerade` remplaçait sa source par `{a1}` : elle aboutissait, mais `www`
voyait `CLIENT_IP={a1}`. Les réponses de `r2` à une requête venue de l'extérieur, elles, ne sont
pas traduites (elles appartiennent à une connexion ouverte par l'autre bout) : elles partaient
avec la source `{a2}` et `isp1` les jetait. L'élément `both_uplinks` exige les deux adresses : une
route par défaut déplacée vers le FAI 2 réparerait l'une en cassant l'autre.
""").format(g1=isp_gw[1], g2=isp_gw[2], a1=pub[2, 1], a2=pub[2, 2], t1=TABLE[1], t2=TABLE[2])))

        self.question_dummy(
            section=self.section(1),
            title=tr("Le réseau local n'y perd rien"),
            hash="df85a099c483554e",
            description=tr("""
1. Sur `pc2`, demandez le service de `r2` à son adresse du FAI 2 : `curl -s -m 3 http://{a2}/`. Si
   vos tables ne contiennent qu'une route par défaut, il n'y a plus de réponse, alors qu'il y en
   avait une avant vos règles. Pourquoi (section @@ref:connected@@) ? `ip route get {pc2} from
   {a2}` sur `r2` donne la réponse.
2. Corrigez, et vérifiez.
""").format(a2=pub[2, 2], pc2=host["pc2"])
            + instructor(tr("""
**Solution.** La réponse de `r2` à `pc2` a pour source `{a2}` : la règle `from {a2}` l'envoie dans
la table {t2}, qui ne connaît que la route par défaut ; elle part chez le FAI 2 au lieu de
retourner dans `lan2`. Chaque table doit contenir les réseaux du site :

```
ip route add {lan2} dev eth0 table {t1}
ip route add {lan2} dev eth0 table {t2}
```
""").format(a2=pub[2, 2], t1=TABLE[1], t2=TABLE[2], lan2=lan["lan2"])))

        self.add_grade_element(
            title=no_tr("both_uplinks"), max_grade=7, grade_part=part2, grade=7 * int(both_uplinks),
            description=tr("le service de r2 répond à www par ses deux adresses publiques"))
        self.add_grade_element(
            title=no_tr("bound_source"), max_grade=3, grade_part=part2, grade=3 * int(bound_source),
            description=tr("une connexion de r2 ouverte depuis son adresse du FAI 2 sort par le FAI 2, les autres "
                           "par le FAI 1"))
        self.add_grade_element(
            title=no_tr("lan_kept"), max_grade=2, grade_part=part2, grade=2 * int(lan_kept),
            description=tr("pc2 joint toujours r2 par son adresse du FAI 2"))
        self.add_grade_element(
            title=no_tr("q_reply_path"), max_grade=2, grade_part=part2, scope=CHOICE_SCOPE,
            grade=sum(int(_norm(q21.get(field)) == answer) for field, answer in q21_answers.items()),
            description=tr("formulaire : par où part la réponse, et qui la jette"))

        # =====================================================================
        # Part 3 — r3: routing by a mark, strict reverse-path filter
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Router selon une marque"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Router selon une marque"),
            hash="a8f9c5d01e3f776a",
            description=tr("""
**Site 3** : le réseau `lan3` (`{lan3}`, sur `eth0`) et le poste `pc3` (`{pc3}`) derrière **`r3`**
(`{a1}` chez le FAI 1, `{a2}` chez le FAI 2 ; passerelles `{g1}` et `{g2}`). `www` offre un second
service sur le port {bulk} : des transferts volumineux.

**But** : les connexions vers le port TCP {bulk} sortent par le FAI 2, tout le reste par le FAI 1.
Le critère est appelé à s'enrichir (listes d'adresses, quotas…) : on **impose** donc de le confier
à nftables, qui pose une **marque** sur les paquets, puis de router selon cette marque. (Une règle
`ip rule add ipproto tcp dport {bulk} …` saurait exprimer ce critère-ci, pas les suivants : elle
n'est pas comptée.) Attention : **`r3` filtre par chemin inverse en mode strict**. **À lire** :
sections @@ref:marks@@ et @@ref:rpfilter@@ des Informations.
""").format(lan3=lan["lan3"], pc3=host["pc3"], a1=pub[3, 1], a2=pub[3, 2], g1=isp_gw[1], g2=isp_gw[2],
            bulk=BULK_PORT)
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r3` (état `final`) : la table ci-dessous
ajoutée à `{conf_file}` (rechargé par `nft -f {conf_file}`), puis les commandes.

```
{table}```

```
{commands}```

Barème de la partie : `mark_routing` 4 (une marque posée dans une chaîne de `prerouting` et une
règle `fwmark` dont la table sort par le FAI 2), `flows_split` 10 (le port {bulk} par le FAI 2
**et** le port {http} par le FAI 1 ; ne compte qu'avec `mark_routing`), formulaire `q_dropper` 2 et
`q_loose_mode` 2 ; bonus `router_flows` 3.
""").format(conf_file=CONF_FILE, table=ns.mangle_table("r3"), commands=_block(ns.reference_commands("r3")),
            bulk=BULK_PORT, http=HTTP_PORT)),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("Marquer, puis router selon la marque"),
            hash="0df17e8fd2ab5a3b",
            description=tr("""
1. Dans une table nftables de votre choix (`ip mangle` par exemple), créez une chaîne de type
   `filter` accrochée à `prerouting` avec la priorité `mangle`, et la règle qui pose la marque
   {mark} sur les paquets TCP à destination du port {bulk} reçus sur `eth0` (section
   @@ref:fwmark@@).
2. Créez la table de routage du FAI 2 (route par défaut via `{g2}`, et le réseau `{lan3}`), puis la
   règle `ip rule` qui y envoie les paquets portant la marque.
3. Vérifiez la décision du noyau : `ip route get {www} from {pc3} iif eth0 mark {mark}` doit
   répondre `dev eth2`.
4. Sur `pc3` : `curl -s -m 3 http://www/` puis `curl -s -m 3 http://www:{bulk}/`. Le premier répond
   (`CLIENT_IP={a1}`) ; le second n'aboutit pas : c'est l'objet de la question suivante.
""").format(mark=MARK, bulk=BULK_PORT, g2=isp_gw[2], lan3=lan["lan3"], www=www, pc3=host["pc3"], a1=pub[3, 1])
            + instructor(tr("""
**Solution.** Sur `r3`, la table nftables (à taper avec `nft add table` / `add chain` / `add rule`,
ou à ajouter à `{conf_file}`) :

```
{table}```

puis :

```
ip route add default via {g2} dev eth2 table {t2}
ip route add {lan3} dev eth0 table {t2}
ip rule add fwmark {mark} lookup {t2} priority 1000
```

`ip route get … mark {mark}` répond `via {g2} dev eth2 table {t2} mark {mark}`. Les SYN vers le port
{bulk} sortent bien par `eth2` avec la source `{a2}`, et `www` répond ; mais `r3` jette la réponse
(question suivante).
""").format(conf_file=CONF_FILE, table=ns.mangle_table("r3", bonus=False), g2=isp_gw[2], lan3=lan["lan3"],
            t2=TABLE[2], mark=MARK, bulk=BULK_PORT, a2=pub[3, 2])))

        q32_answers = {"dropper": "rpf", "loose": "2"}
        q32 = self.question_form(
            section=self.section(1),
            title=tr("Qui jette les réponses ?"),
            hash="55cf6fd7be3a524e",
            description=tr("""
1. Sur `r3`, capturez les deux accès (`tcpdump -n -i eth1 tcp port {bulk}` et `tcpdump -n -i eth2
   tcp port {bulk}`) et relancez sur `pc3` le `curl` vers le port {bulk}. Par où sortent les SYN ?
   Les réponses de `www` reviennent-elles, et par où ?
2. Sur `r3`, affichez le compteur `nstat -az TcpExtIPReversePathFilter` avant et après un `curl`
   (section @@ref:rpfilter@@).
3. Expliquez pourquoi ce filtre laisse passer les réponses de la partie 1 (une règle sur la
   source) et pas celles-ci. Corrigez le réglage de l'interface concernée, **sans toucher au
   filtre des autres interfaces**, et vérifiez sur `pc3` : `CLIENT_IP={a2}` pour le port {bulk},
   `CLIENT_IP={a1}` pour le port {http}.
""").format(bulk=BULK_PORT, http=HTTP_PORT, a1=pub[3, 1], a2=pub[3, 2])
            + tr("""
- Ce qui jette les réponses : @@{dropper:>le FAI 2 (isp2)>>>isp2|le filtrage par chemin inverse de r3>>>rpf|la traduction d'adresses de r3>>>nat|www, qui ne répond pas>>>www}@@
- Valeur de `rp_filter` qui met une interface en mode « lâche » : @@{loose:[0-9]}@@
""")
            + instructor(tr("""
**Solution.** Les SYN sortent par `eth2` (source `{a2}`) et les SYN-ACK de `www` reviennent par
`eth2`, mais `r3` les jette : `TcpExtIPReversePathFilter` augmente à chaque essai. Le filtre strict
cherche la route de retour vers la source du paquet reçu (`{www}`) et exige qu'elle passe par
l'interface d'arrivée. Cette recherche se fait **sans la marque** : elle aboutit à la table `main`,
donc à `eth1`. Dans la partie 1, la recherche inverse porte l'adresse du poste comme adresse
source : la règle `from` s'y applique, et la route de retour passe bien par `eth2`.

```
sysctl -w net.ipv4.conf.eth2.rp_filter=2
```

Le noyau applique la plus grande des valeurs de `all` (1) et de l'interface (2) : `eth2` passe en
mode lâche, `eth0` et `eth1` restent stricts. Autre solution, plus stricte : garder `eth2` à 1,
enregistrer la marque dans la connexion (`ct mark set meta mark`), la restaurer sur les réponses
(`iifname "eth2" meta mark set ct mark`) et activer `net.ipv4.conf.all.src_valid_mark=1`.

- Réponses : le filtrage par chemin inverse de `r3` ; `2`.
""").format(a2=pub[3, 2], www=www)),
            cheat_answers={"final": q32_answers})

        self.question_dummy(
            section=self.section(1),
            title=tr("Bonus — le trafic du routeur lui-même"),
            hash="83696a8b7d9af6ae",
            description=tr("""
Les connexions que `r3` ouvre lui-même vers le port {bulk} (`curl -s -m 3 http://www:{bulk}/` sur
`r3`) sortent encore par le FAI 1 : elles ne traversent pas `prerouting`. Faites-les sortir par le
FAI 2, le reste du trafic de `r3` continuant de sortir par le FAI 1 (section @@ref:output@@). Quel
type de chaîne faut-il, et pourquoi une chaîne de type `filter` accrochée à `output` ne
suffit-elle pas ?
""").format(bulk=BULK_PORT)
            + instructor(tr("""
**Solution.** Une chaîne de type **`route`** accrochée à `output` : quand une de ses règles change
la marque, le noyau refait la recherche de route du paquet. Une chaîne de type `filter` poserait la
marque trop tard, la route étant déjà choisie. La table complète :

```
{table}```

Le paquet a pris l'adresse source `{a1}` avant d'être rerouté : c'est le `masquerade` de `eth2`,
écrit sans critère sur la source, qui lui donne l'adresse `{a2}`. `www` doit voir `CLIENT_IP={a2}`
pour le port {bulk} et `CLIENT_IP={a1}` pour le port {http} (bonus `router_flows`, qui exige une
marque posée dans une chaîne d'`output`).
""").format(table=ns.mangle_table("r3"), a1=pub[3, 1], a2=pub[3, 2], bulk=BULK_PORT, http=HTTP_PORT)))

        self.add_grade_element(
            title=no_tr("mark_routing"), max_grade=4, grade_part=part3, grade=4 * int(mark_routed),
            description=tr("une marque posée en prerouting, et une règle fwmark dont la table sort par le FAI 2"))
        self.add_grade_element(
            title=no_tr("flows_split"), max_grade=10, grade_part=part3, grade=10 * int(flows_split),
            description=tr("pc3 atteint le port {bulk} de www par le FAI 2 et son port {http} par le FAI 1")
            .format(bulk=BULK_PORT, http=HTTP_PORT))
        self.add_grade_element(
            title=no_tr("q_dropper"), max_grade=2, grade_part=part3, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q32.get("dropper")) == q32_answers["dropper"]),
            description=tr("formulaire : ce qui jette les réponses"))
        self.add_grade_element(
            title=no_tr("q_loose_mode"), max_grade=2, grade_part=part3,
            grade=2 * int(_norm(q32.get("loose")) == q32_answers["loose"]),
            description=tr("formulaire : valeur du mode lâche de rp_filter"))
        self.add_grade_element(
            title=no_tr("router_flows"), max_grade=3, grade_part=part3, bonus=True, grade=3 * int(own_split),
            description=tr("bonus : le trafic de r3 vers le port {bulk} sort par le FAI 2, le reste par le FAI 1")
            .format(bulk=BULK_PORT))

        # =====================================================================
        # Part 4 — r4: a server published on both uplinks (connection mark)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Un serveur publié sur deux accès"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Un serveur publié sur deux accès"),
            hash="5b783be17067ab6c",
            description=tr("""
**Site 4** : le serveur `web4` (`{web4}`, port {http}) dans le réseau `lan4` (`{lan4}`, sur
`eth0`), derrière **`r4`** (`{a1}` chez le FAI 1, `{a2}` chez le FAI 2 ; passerelles `{g1}` et
`{g2}`). `r4` **publie déjà ce serveur sur ses deux accès** : son fichier `{conf_file}` contient,
avec les deux `masquerade`, la redirection du port {pub} de `eth1` et de `eth2` vers le port {http}
de `web4` :

```
{nat}```

**But** : le serveur publié répond par les deux adresses publiques de `r4` ; ce que `web4` émet de
lui-même continue de sortir par le FAI 1. **À lire** : section @@ref:connmark@@ des Informations.
""").format(web4=host["web4"], http=HTTP_PORT, lan4=lan["lan4"], a1=pub[4, 1], a2=pub[4, 2], g1=isp_gw[1],
            g2=isp_gw[2], conf_file=CONF_FILE, pub=PUB_PORT, nat=ns.nat_table("r4"))
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r4` (état `final`) : la table ci-dessous
ajoutée à `{conf_file}` (rechargé par `nft -f {conf_file}`), puis les commandes.

```
{table}```

```
{commands}```

Barème de la partie : `published` 9 (`www` obtient `web4` par les deux adresses publiques, le
serveur voyant bien `www` comme client), `server_traffic` 3, formulaire `q_reply_source` 2. Aucune
règle n'est lue : tout mécanisme qui laisse `web4` répondre lui-même à `www` est accepté.
""").format(conf_file=CONF_FILE, table=ns.mangle_table("r4"), commands=_block(ns.reference_commands("r4")))),
        )

        q41_answers = {"reply_source": str(host["web4"])}
        q41 = self.question_form(
            section=self.section(1),
            title=tr("Pourquoi une règle sur la source ne suffit plus"),
            hash="0d07ffafa9ec1522",
            description=tr("""
1. Sur `ext` : `curl -s -m 3 http://{a1}:{pub}/` répond (`SERVER=web4`), `curl -s -m 3
   http://{a2}:{pub}/` ne répond pas.
2. Sur `r4`, capturez le côté du serveur (`tcpdump -n -i eth0 tcp port {http}`) pendant le second
   `curl` : la requête arrive bien à `web4`, qui répond. Quelle est l'adresse source de sa réponse
   au moment où `r4` la reçoit et lui choisit une route ?
3. Capturez ensuite `eth1` et `eth2` (`tcp port {pub}`) : par où la réponse sort-elle, et sous
   quelle adresse source ? Pourquoi une règle `from {a2}`, comme dans la partie 2, serait-elle sans
   effet ici ? Et une règle `from {web4}` ?
""").format(a1=pub[4, 1], a2=pub[4, 2], pub=PUB_PORT, http=HTTP_PORT, web4=host["web4"])
            + tr("""
- Adresse source de la réponse quand `r4` choisit sa route : @@{reply_source:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** La réponse arrive sur `eth0` avec la source `{web4}` : c'est avec cette adresse que
`r4` choisit la route (table `main`, donc le FAI 1). La traduction inverse, qui remet `{a2}` comme
adresse source, n'a lieu qu'**après** le routage, à la sortie : le paquet part par `eth1` avec la
source `{a2}`, et `isp1` le jette. Une règle `from {a2}` ne voit jamais cette adresse ; une règle
`from {web4}` enverrait par le FAI 2 **tout** ce qu'émet `web4`, y compris ses réponses aux
requêtes arrivées par le FAI 1.

- Réponse : `{web4}`.
""").format(web4=host["web4"], a2=pub[4, 2])),
            cheat_answers={"final": q41_answers})

        self.question_dummy(
            section=self.section(1),
            title=tr("Marquer la connexion"),
            hash="80f37056a506da3f",
            description=tr("""
1. Dans une chaîne de `prerouting` de priorité `mangle`, posez une **marque de connexion** (`ct
   mark`) sur les connexions **nouvelles qui arrivent par `eth2`**, puis recopiez cette marque sur
   les paquets de ces connexions **qui reviennent par `eth0`** (`meta mark set ct mark`) : section
   @@ref:connmark@@.
2. Créez la table de routage du FAI 2 et la règle `fwmark`, comme dans la partie 3.
3. Vérifiez depuis `ext` que les deux adresses publiques répondent `SERVER=web4`, puis sur `web4`
   que `curl -s -m 3 http://www/` affiche toujours `CLIENT_IP={a1}`.
""").format(a1=pub[4, 1])
            + instructor(tr("""
**Solution.** La table nftables de `r4` :

```
{table}```

puis :

```
{commands}```

La marque de connexion est posée par le premier paquet arrivé par `eth2` et reste attachée à la
connexion ; chaque réponse de `web4` la retrouve, reçoit la marque de paquet {mark} avant le
routage et suit la table {t2}. Les connexions arrivées par `eth1`, et celles que `web4` ouvre
lui-même, n'ont pas de marque : elles suivent la table `main`.
""").format(table=ns.mangle_table("r4"), commands=_block(ns.reference_commands("r4")), mark=MARK, t2=TABLE[2])))

        self.add_grade_element(
            title=no_tr("published"), max_grade=9, grade_part=part4, grade=9 * int(published),
            description=tr("www obtient web4 par les deux adresses publiques de r4"))
        self.add_grade_element(
            title=no_tr("server_traffic"), max_grade=3, grade_part=part4, grade=3 * int(server_by_isp1),
            description=tr("ce que web4 émet de lui-même sort toujours par le FAI 1"))
        self.add_grade_element(
            title=no_tr("q_reply_source"), max_grade=2, grade_part=part4,
            grade=2 * int(_same_ip(q41.get("reply_source"), host["web4"])),
            description=tr("formulaire : adresse source de la réponse au moment du routage"))

        # =====================================================================
        # Part 5 — r5: load sharing over both uplinks
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Partager la charge entre les deux accès"))
        svc_prefix = str(ns.svc_ip(0)).rsplit(".", 1)[0]

        self.question_dummy(
            section=self.section(0),
            title=tr("Partager la charge entre les deux accès"),
            hash="1f51d8a69c0a4339",
            description=tr("""
**Site 5** : le réseau `lan5` (`{lan5}`, sur `eth0`) et le poste `pc5` (`{pc5}`) derrière **`r5`**
(`{a1}` chez le FAI 1, `{a2}` chez le FAI 2 ; passerelles `{g1}` et `{g2}`). Le serveur de test de
`www` répond aussi sur **toutes les adresses du préfixe `{svc}`** : autant de destinations
différentes.

**But** : utiliser les deux accès à la fois, le FAI 1 (le plus gros débit) recevant **trois fois
plus** de destinations que le FAI 2. **À lire** : section @@ref:multipath@@ des Informations.
""").format(lan5=lan["lan5"], pc5=host["pc5"], a1=pub[5, 1], a2=pub[5, 2], g1=isp_gw[1], g2=isp_gw[2],
            svc=ns.net("svc"))
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r5` (état `final`) :

```
{commands}```

Barème de la partie : `two_nexthops` 4 (la route par défaut de la table `main` a un prochain saut
par FAI), `weights` 3 (poids dans le rapport {w1} pour {w2}), `load_shared` 5 ({n} destinations
`{prefix}.1` … `{prefix}.{n}` interrogées depuis `pc5` : toutes répondent et `www` voit les deux
adresses publiques de `r5` ; ne compte qu'avec `two_nexthops`). La dernière question n'est pas
notée.
""").format(commands=_block(ns.reference_commands("r5")), w1=WEIGHT[1], w2=WEIGHT[2], n=SPREAD,
            prefix=svc_prefix)),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("Une route par défaut à deux chemins"),
            hash="d1a69ce0ed26c269",
            description=tr("""
1. Remplacez la route par défaut de `r5` (table `main`) par une route à **deux prochains sauts** :
   `{g1}` par `eth1` avec le poids {w1}, `{g2}` par `eth2` avec le poids {w2} (section
   @@ref:ecmp@@). Vérifiez avec `ip route`.
2. Sur `pc5`, interrogez seize destinations et comptez les adresses sous lesquelles `www` vous
   voit :

        for i in $(seq 1 16); do curl -s -m 3 http://{prefix}.$i/ | grep CLIENT_IP; done | sort | uniq -c

3. Relancez la boucle : une destination donnée change-t-elle de FAI d'une fois à l'autre ?
   Pourquoi est-ce indispensable ici (pensez à la traduction d'adresses et aux connexions TCP) ?
   Sur quoi le noyau fonde-t-il son choix (`sysctl net.ipv4.fib_multipath_hash_policy`) ?
""").format(g1=isp_gw[1], g2=isp_gw[2], w1=WEIGHT[1], w2=WEIGHT[2], prefix=svc_prefix)
            + instructor(tr("""
**Solution.** Sur `r5` :

```
{commands}```

`ip route` affiche `default` suivi de deux lignes `nexthop via … weight …`. Le noyau choisit le
prochain saut d'après une empreinte calculée sur les adresses source et destination
(`fib_multipath_hash_policy=0`) : une même destination sort toujours par le même FAI, ce qu'il
faut puisque chaque accès traduit avec sa propre adresse publique (une connexion qui changerait
d'accès changerait d'adresse source). La répartition n'est donc exacte qu'en moyenne : sur seize
destinations on observe à peu près douze `CLIENT_IP={a1}` et quatre `CLIENT_IP={a2}`.
""").format(commands=_block(ns.reference_commands("r5")), a1=pub[5, 1], a2=pub[5, 2])))

        self.question_dummy(
            section=self.section(1),
            title=tr("Et si un accès tombe ?"),
            hash="3d3474e96f6485a4",
            description=tr("""
Cette question n'est pas notée.

1. Appliquez l'état `isp1_down` (onglet *Appliquer une configuration*) : le FAI 1 ne répond plus,
   mais l'interface `eth1` de `r5` reste active, comme derrière le boîtier d'un opérateur.
2. Relancez la boucle de la question précédente et comptez les réponses. `ip route` a-t-il
   changé ? Dans quel état `ip neigh` montre-t-il la passerelle du FAI 1 ?
3. Pourquoi le noyau continue-t-il d'envoyer des paquets à une passerelle qui ne répond plus ?
   Qu'apporte `sysctl -w net.ipv4.fib_multipath_use_neigh=1` ? Que faudrait-il pour un vrai secours
   (section @@ref:failover@@) ?
4. Appliquez l'état `isp1_up` avant de continuer : tant que le FAI 1 est coupé, les autres parties
   perdent des points.
""")
            + instructor(tr("""
**Solution.** Les destinations que l'empreinte attribue au FAI 1 (les trois quarts) ne répondent
plus ; les autres continuent. La route n'a pas changé : le noyau ne retire un prochain saut que si
**son interface** tombe, et `eth1` est toujours active. `ip neigh` montre la passerelle `FAILED`.
Avec `fib_multipath_use_neigh=1`, le noyau écarte un prochain saut dont le voisin est en échec :
toutes les destinations passent alors par le FAI 2. Cela ne couvre que la panne du premier routeur,
et au retour du FAI 1 sa passerelle reste `FAILED` tant que rien ne lui est adressé (un `ping` de
la passerelle la fait revenir). Un vrai secours demande une **surveillance** (un `ping` régulier
d'une destination au-delà du FAI, par chaque accès) qui retire ou remet les routes.
""")))

        self.add_grade_element(
            title=no_tr("two_nexthops"), max_grade=4, grade_part=part5, grade=4 * int(two_hops),
            description=tr("la route par défaut de r5 a un prochain saut chez chaque FAI"))
        self.add_grade_element(
            title=no_tr("weights"), max_grade=3, grade_part=part5, grade=3 * int(weighted),
            description=tr("les poids sont dans le rapport {w1} (FAI 1) pour {w2} (FAI 2)")
            .format(w1=WEIGHT[1], w2=WEIGHT[2]))
        self.add_grade_element(
            title=no_tr("load_shared"), max_grade=5, grade_part=part5, grade=5 * int(shared),
            description=tr("{n} destinations répondent à pc5, et les deux accès sont utilisés").format(n=SPREAD))

        # =====================================================================
        # Part 6 — r6: VRFs
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Des tables étanches : les VRF"))
        blue_name, blue_table, _ = VRF["blue"]
        red_name, red_table, _ = VRF["red"]

        self.question_dummy(
            section=self.section(0),
            title=tr("Des tables étanches : les VRF"),
            hash="99b791f246d44035",
            description=tr("""
**Site 6** : **`r6`** relie les réseaux de deux clients qui ne se connaissent pas et qui ont
choisi **les mêmes adresses**. Le client **bleu** : `blue1` (`{h1}`) sur `eth0`, `blue2` (`{h2}`)
sur `eth1`. Le client **rouge** : `red1` (`{h1}`) sur `eth2`, `red2` (`{h2}`) sur `eth3`. Chaque
poste a pour passerelle la première adresse de son réseau : `{gw_a}` pour `{cust_a}`, `{gw_b}` pour
`{cust_b}`. Le poste `admin` (`{admin}`) est sur `eth4` (`{mgmt}`), dans la table de routage
ordinaire de `r6`. Ce site n'a pas d'accès à Internet.

Les interfaces `eth0` … `eth3` de `r6` n'ont pas encore d'adresse : une table de routage ne peut
pas contenir deux fois le même réseau.

**But** : une VRF par client. Chaque client joint ses deux réseaux, sans jamais atteindre l'autre
client ni le réseau d'administration. **À lire** : section @@ref:vrf@@ des Informations.
""").format(h1=host["blue1"], h2=host["blue2"], gw_a=gw_a, gw_b=gw_b, cust_a=cust_a, cust_b=cust_b,
            admin=host["admin"], mgmt=mgmt)
            + instructor(tr("""
**Pour l'enseignant.** La solution de référence sur `r6` (état `final`), bonus compris :

```
{commands}```

Barème de la partie : `vrf_devices` 4 (deux VRF actives, de tables différentes), `vrf_ports` 3
(`eth0` et `eth1` dans l'une, `eth2` et `eth3` dans l'autre ; ni noms ni numéros imposés),
`customers_routed` 7 (`blue1` obtient `blue2` **et** `red1` obtient `red2` ; ne compte qu'avec
`vrf_ports`), `tables_closed` 3, `router_service` 3, formulaire `q_l3mdev_rule` 2 ; bonus
`route_leak` 3.
""").format(commands=_block(ns.reference_commands(VRF_ROUTER)))),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("Deux VRF"),
            hash="692890521c18089c",
            description=tr("""
1. Créez deux VRF, `{blue}` avec la table {blue_table} et `{red}` avec la table {red_table} par
   exemple, et activez-les (section @@ref:vrf-create@@).
2. Placez `eth0` et `eth1` dans la première, `eth2` et `eth3` dans la seconde.
3. Donnez leurs adresses aux quatre interfaces : `{gw_a}/{len_a}` sur `eth0` et sur `eth2`,
   `{gw_b}/{len_b}` sur `eth1` et sur `eth3`.
4. Vérifiez : `ip -br link show type vrf`, `ip route show vrf {blue}`, `ip route show table
   {red_table}`, puis `curl -s -m 3 http://{h2}/` sur `blue1` (réponse `SERVER=blue2`) et sur `red1`
   (`SERVER=red2`).
5. Sur `r6`, `ping -c 1 {h2}` échoue (*Network is unreachable*) alors que `ping -c 1 -I {blue}
   {h2}` répond. Pourquoi (section @@ref:vrf-tools@@) ?
""").format(blue=blue_name, red=red_name, blue_table=blue_table, red_table=red_table, gw_a=gw_a, gw_b=gw_b,
            len_a=cust_a.prefixlen, len_b=cust_b.prefixlen, h2=host["blue2"])
            + instructor(tr("""
**Solution.** Sur `r6` :

```
{commands}```

Les routes des réseaux connectés et les adresses locales de chaque interface sont rangées dans la
table de sa VRF : les deux clients ne se gênent plus. Une commande lancée sur `r6` sans précision
utilise la VRF par défaut (la table `main`), qui ne connaît aucun des réseaux des clients ; `-I
{blue}` attache la commande à la VRF bleue.
""").format(commands=_block(ns.vrf_commands(leak=False)[:-len(VRF)]), blue=blue_name)))

        q62_answers = {"l3mdev_prio": "1000"}
        q62 = self.question_form(
            section=self.section(1),
            title=tr("La règle des VRF"),
            hash="82fdf6d059dd26cb",
            description=tr("""
`ip rule` sur `r6` montre une règle que vous n'avez pas écrite : le noyau l'a ajoutée à la création
de la première VRF (section @@ref:vrf-tables@@). Elle fait consulter à chaque paquet la table de
la VRF de l'interface par laquelle il est arrivé.

- Priorité de cette règle : @@{l3mdev_prio:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** `1000: from all lookup [l3mdev-table]`, entre la table `local` (0) et la table `main`
(32766).

- Réponse : `1000`.
""")),
            cheat_answers={"final": q62_answers})

        self.question_dummy(
            section=self.section(1),
            title=tr("Fermer les tables des VRF"),
            hash="65d4c92a95d5a889",
            description=tr("""
1. Sur `admin`, lancez `tcpdump -n -i eth0 icmp`, puis sur `red1` : `ping -c 1 -W 1 {admin}`.
   `red1` ne reçoit rien… mais `admin` voit arriver la demande d'écho : un paquet du client rouge
   est **sorti de sa VRF**. Que fait le noyau quand la table d'une VRF n'a pas de route pour une
   destination (regardez l'ordre des règles de `ip rule`) ?
2. Fermez chacune des deux tables par une route par défaut `unreachable` (section
   @@ref:vrf-tables@@), puis recommencez : `red1` doit recevoir aussitôt une erreur de sa
   passerelle (*Destination Host Unreachable*), et `admin` ne plus rien voir.
""").format(admin=host["admin"])
            + instructor(tr("""
**Solution.** Après la table de la VRF (règle 1000), la recherche continue avec les règles
suivantes : la table `main` (32766) connaît `{mgmt}`, et le paquet du client rouge est remis à
`admin`. Seule la réponse échoue, `admin` n'ayant pas de chemin de retour vers le client. On ferme
chaque table par une route par défaut qui refuse, de métrique très élevée pour qu'une vraie route
par défaut, le jour venu, lui soit préférée :

```
{commands}```

`red1` reçoit alors `From {gw_a} icmp_seq=1 Destination Host Unreachable` (élément `tables_closed`).
""").format(mgmt=mgmt, commands=_block(ns.vrf_closing_commands()), gw_a=gw_a)))

        self.question_dummy(
            section=self.section(1),
            title=tr("Un service du routeur pour ses clients"),
            hash="4d1f96f947e07faf",
            description=tr("""
1. Sur `blue1` : `ping -c 1 {gw_a}` répond, mais `curl -s -m 3 http://{gw_a}/` (le serveur de test
   de `r6`) échoue. Ce serveur écoute pourtant sur toutes les adresses (`ss -tln` sur `r6`).
2. Expliquez (section @@ref:vrf-services@@) et corrigez par le réglage du noyau qui convient.
   Vérifiez depuis `blue1` et depuis `red1` : `SERVER=r6`.
""").format(gw_a=gw_a)
            + instructor(tr("""
**Solution.** Le serveur de test a été lancé dans la VRF par défaut : son port d'écoute n'accepte
que les connexions arrivées par une interface de cette VRF. Le noyau répond lui-même au `ping`,
mais refuse la connexion TCP arrivée par `eth0`, qui appartient à la VRF bleue.

```
sysctl -w net.ipv4.tcp_l3mdev_accept=1
```

Un port d'écoute de la VRF par défaut accepte alors les connexions de toutes les VRF ; chaque
connexion acceptée reste attachée à la VRF par laquelle elle est arrivée, si bien que les réponses
repartent du bon côté bien que `blue1` et `red1` aient la même adresse.
""")))

        self.question_dummy(
            section=self.section(1),
            title=tr("Bonus — une fuite de routes"),
            hash="dcfc2575413fc245",
            description=tr("""
Le poste `admin` doit pouvoir joindre le client **bleu** (son réseau `{cust_a}`), et lui seul ; le
client rouge reste isolé. Ajoutez les deux routes nécessaires (section @@ref:vrf-leak@@) : dans la
table `main`, la route vers `{cust_a}` **par la VRF bleue** ; dans la table de la VRF bleue, la
route de retour vers `{mgmt}`. Vérifiez : `curl -s -m 3 http://{h1}/` sur `admin` répond
`SERVER=blue1`, et `ping -c 1 -W 1 {admin}` sur `red1` reçoit toujours l'erreur de sa passerelle.
""").format(cust_a=cust_a, mgmt=mgmt, h1=host["blue1"], admin=host["admin"])
            + instructor(tr("""
**Solution.** Sur `r6` :

```
{commands}```

La première route envoie vers l'interface `{blue}` les paquets d'`admin` destinés à `{cust_a}` :
ils entrent dans la VRF bleue, dont la table connaît `eth0`. La seconde donne au client bleu le
chemin du retour, que la route `unreachable` lui refusait. Le client rouge n'a ni l'une ni l'autre
(bonus `route_leak` : `admin` obtient `blue1`, `red1` reste refusé).
""").format(commands=_block(ns.vrf_leak_commands()), blue=blue_name, cust_a=cust_a)))

        self.add_grade_element(
            title=no_tr("vrf_devices"), max_grade=4, grade_part=part6, grade=4 * int(two_vrfs),
            description=tr("deux VRF actives, chacune avec sa table"))
        self.add_grade_element(
            title=no_tr("vrf_ports"), max_grade=3, grade_part=part6, grade=3 * int(ports_placed),
            description=tr("eth0 et eth1 dans une VRF, eth2 et eth3 dans une autre"))
        self.add_grade_element(
            title=no_tr("customers_routed"), max_grade=7, grade_part=part6, grade=7 * int(customers_routed),
            description=tr("blue1 joint blue2 et red1 joint red2, avec les mêmes adresses"))
        self.add_grade_element(
            title=no_tr("tables_closed"), max_grade=3, grade_part=part6, grade=3 * int(table_closed),
            description=tr("red1 est refusé par sa passerelle quand il vise le réseau d'administration"))
        self.add_grade_element(
            title=no_tr("router_service"), max_grade=3, grade_part=part6, grade=3 * int(service_reached),
            description=tr("le service de r6 répond à blue1 et à red1"))
        self.add_grade_element(
            title=no_tr("q_l3mdev_rule"), max_grade=2, grade_part=part6,
            grade=2 * int(_norm(q62.get("l3mdev_prio")) == q62_answers["l3mdev_prio"]),
            description=tr("formulaire : priorité de la règle des VRF"))
        self.add_grade_element(
            title=no_tr("route_leak"), max_grade=3, grade_part=part6, bonus=True, grade=3 * int(leak),
            description=tr("bonus : admin joint blue1, le client rouge reste isolé"))


_TRANSLATIONS = {}
