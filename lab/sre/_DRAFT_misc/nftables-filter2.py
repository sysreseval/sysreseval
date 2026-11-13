"""Network firewall lab (TP3 "Parefeu 2" of the R306 course, converted from the iptables / Marionnet
handout to nftables): a router between three zones (the outside ``ext``, a DMZ ``dmz`` and the
internal network ``int``) and two firewalls written by the students, question after question:

* on ``ext1``, a host firewall: the ``input`` chain of a client (default policy ``drop``, the
  loopback, the replies of its own DNS server only, the TCP connections it opens, pings both
  ways), then of a server (HTTP for everybody, SSH for the internal network only), then the
  ``output`` chain (outgoing mail: ``drop``, ``reject``, one authorised server);
* on ``router``, the ``input`` chain protecting the router itself (pings from the inside zones
  only, its own DNS and TCP requests, SSH from one machine by interface and address) and the
  ``forward`` chain filtering what crosses it (policy ``drop``, the stateful rule, one rule per
  authorised flow between two zones), plus a bonus: a dynamic set with a timeout banning an
  outside machine that tries SSH towards the internal network (the nftables form of the iptables
  ``recent`` module).

Topology::

    ext1 ---+                              +--- dmz1
    ext2 ---+-- [ext] -- eth0 router eth1 -- [dmz] --+--- dmz2
                              eth2
                                |
                              [int] --+--- int1
                                      +--- int2

Every machine runs the echo server of ``lib/server_echo.py`` (HTTP on TCP 80 and 8080); ``ext1``,
``ext2``, ``dmz1`` and ``dmz2`` run a DNS server (unbound, the static zone ``lab.``), ``ext1`` and
``router`` an SSH server, ``ext2``, ``dmz1`` and ``dmz2`` a banner server on TCP 25.  Names are
resolved by DNS only (``/etc/resolv.conf``: ``ext1``, ``int1``, ``int2`` ask ``ext2``, ``router``
asks ``dmz1``), so a firewall that forgets the DNS breaks every command given a name.

Grading uses the "hidden mirror" of ``lib/hidden_mirror.py`` / ``lib/firewall.py`` in two phases,
because the two firewalls would hide each other: the ruleset of ``ext1`` is loaded on its hidden
clone and probed while the clone of the router is open (steps 2 and 3), then the clone of ``ext1``
is flushed, the ruleset of ``router`` is loaded on its clone and probed (steps 4 and 5); steps 6
and 7 trigger the ban of the bonus part and check it.  What a ruleset *says* is read from
``nft -j list ruleset``, what it *does* from the probes.  The ``final`` state applies the reference
solution.  Texts are French (``tr()``) with their English translation in ``_TRANSLATIONS``,
identifiers English.
"""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, ip_address
from typing import List

from SRE import params
from SRE.lib_sre import Data0, Grade0, NetScheme0, instructor, make_tr, no_tr, sre_state
from SRE.lib_sre import info_subtitle, info_toc
from grade_helpers import test_dig
from ips import random_ipv4networks
from net_config import set_ip_forward
from server_echo_helpers import get_http_echo, install_echo_server
from state_helpers import setup_simple_tcp_server
import firewall
import hidden_mirror

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Pare-feu d'un réseau avec nftables : client, serveur, routeur et DMZ",
           en="Network firewall with nftables: client, server, router and DMZ")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
export_kathara_project = True
# An evaluation runs seven steps and waits for the probes the firewalls must block.
eval_interval_without_exam_mode = 180
eval_before_exit = True
record_sessions = False

HOST = 'ext1'                   # the machine whose input and output chains the students write (questions 2 to 4)
ROUTER = 'router'               # the router whose input and forward chains they write (questions 5 to 7)
MIRROR = '_h'                   # suffix of the hidden clones (hidden_mirror.expand_topology)
FAMILY, TABLE = 'inet', 'filter'                    # the table of the reference solution, on both machines
DOMAIN = 'lab'
EXT_IF, DMZ_IF, INT_IF = 'eth0', 'eth1', 'eth2'     # the interfaces of the router, one per zone
HTTP_PORT, ALT_PORT = 80, 8080                      # the echo server of every machine
HTTP_PORTS = (HTTP_PORT, ALT_PORT)
DNS_PORT, SSH_PORT, MAIL_PORT = 53, 22, 25
DNS_SERVERS = ('ext1', 'ext2', 'dmz1', 'dmz2')      # unbound, the static zone DOMAIN
SSH_SERVERS = (HOST, ROUTER)                        # sshd
MAIL_SERVERS = ('ext2', 'dmz1', 'dmz2')             # a banner server on MAIL_PORT
#: the DNS server of /etc/resolv.conf at start (None: the machine itself)
RESOLVER = {'ext1': 'ext2', 'ext2': None, 'dmz1': None, 'dmz2': None, 'int1': 'ext2', 'int2': 'ext2', ROUTER: 'dmz1'}
HOST_DNS = RESOLVER[HOST]       # question 2: the only server whose DNS replies ext1 accepts
MAIL_ALLOWED = 'ext2'           # question 4: the only server ext1 may reach on MAIL_PORT
SSH_ADMIN = 'int1'              # question 5: the only machine allowed on the SSH server of the router
ROUTER_DNS = RESOLVER[ROUTER]   # question 5: the DNS server the router asks
INT_DNS = RESOLVER['int1']      # question 6: the DNS server of the internal machines at start…
DMZ_DNS = 'dmz2'                # … and the one of the DMZ they may ask too (the new resolver of int1)
DMZ_WEB = 'dmz1'                # question 6: the published web server (HTTP_PORT only)
BAN_SET, BAN_SECONDS = 'banned', 60                 # question 7 (bonus): the dynamic set and its timeout
DNS_NAME = 'ext1'               # the name the DNS probes ask (every server knows the whole zone)
HOST_LOAD_STEP, HOST_PROBE_STEP = 2, 3              # the ruleset of ext1 on its clone, then its probes
ROUTER_LOAD_STEP, ROUTER_PROBE_STEP = 4, 5          # the clone of ext1 flushed, the ruleset of the router, its probes
TRAP_STEP, BAN_STEP = 6, 7                          # the SSH attempt that bans its source, then the checks
PROBE_TIMEOUT = 3               # bash /dev/tcp connection timeout: a dropped SYN is declared after that
HTTP_TIMEOUT = 3                # curl -m
DIG_TIMEOUT = 3                 # dig +time=2
HOSTS = ('ext1', 'ext2', 'dmz1', 'dmz2', 'int1', 'int2')   # single-homed machines (the router has router_<zone>)
ZONES = ('ext', 'dmz', 'int')
ZONE_OF = {'ext1': 'ext', 'ext2': 'ext', 'dmz1': 'dmz', 'dmz2': 'dmz', 'int1': 'int', 'int2': 'int'}
ROUTER_IFACES = {'ext': EXT_IF, 'dmz': DMZ_IF, 'int': INT_IF}
#: host part of every address (the handout: ext1 .51, dmz1 .101, int1 .10, the router .254 outside and .1 inside)
HOST_PARTS = {'ext1': 51, 'ext2': 52, 'dmz1': 101, 'dmz2': 102, 'int1': 10, 'int2': 20}
ROUTER_PARTS = {'ext': 254, 'dmz': 1, 'int': 1}

# The visible topology and its hidden mirror (clones ext1_h ... router_h on ext_h / dmz_h / int_h).
_TOPOLOGY = {
    'ext': {'ext1': 0, 'ext2': 0, ROUTER: 0},
    'dmz': {'dmz1': 0, 'dmz2': 0, ROUTER: 1},
    'int': {'int1': 0, 'int2': 0, ROUTER: 2},
}
_SPECS = {
    'ext1': {'color': 'lightblue'}, 'ext2': {'color': 'lightgrey'},
    ROUTER: {'color': 'lightgreen'},
    'dmz1': {'color': 'moccasin'}, 'dmz2': {'color': 'moccasin'},
    'int1': {}, 'int2': {},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS, suffix=MIRROR)


def clone(machine: str) -> str:
    """Name of the hidden clone of *machine*."""
    return machine + MIRROR


def visible(machine: str) -> str:
    """Name of the visible twin of a clone (identity for a visible machine)."""
    return machine[:-len(MIRROR)] if machine.endswith(MIRROR) else machine


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        networks = random_ipv4networks(masks=[24, 24, 24], from_private_network=True,
                                       exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for zone, network in zip(ZONES, networks):
            setattr(data.nets, zone, network)
            setattr(data.ips, f"{ROUTER}_{zone}",
                    IPv4Interface(f"{network.network_address + ROUTER_PARTS[zone]}/{network.prefixlen}"))
        for machine, zone in ZONE_OF.items():
            network = getattr(data.nets, zone)
            setattr(data.ips, machine, IPv4Interface(f"{network.network_address + HOST_PARTS[machine]}/{network.prefixlen}"))
        # the clones get the same subnets and addresses (persisted in data.json)
        hidden_mirror.copy_addressing(data, _TOPOLOGY, suffix=MIRROR)
        return data


def ip_of(data, machine: str) -> IPv4Interface:
    """The address of a single-homed machine or of its clone (the router: ``data.ips.router_<zone>``)."""
    return getattr(data.ips, visible(machine))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS
    _network_specs = {
        'ext': {'color': 'lightgrey'},
        'dmz': {'color': 'moccasin'},
        'int': {'color': 'lightcyan'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Du pare-feu d'une machine au pare-feu d'un réseau"), tag="zones")
            + tr("""

Un **pare-feu** applique une politique aux paquets : les accepter, les détruire ou les refuser.
Sous Linux il s'écrit avec **nftables** (commande **`nft`**) : des règles accrochées aux points
de passage des paquets dans le noyau, que fournit **Netfilter**. Ce cours rappelle d'abord
l'essentiel de nftables, puis traite ce qui fait l'objet de ce TP : filtrer ce qui **sort**
d'une machine et, surtout, ce qui **traverse un routeur**. Les machines du TP ont nftables 1.0.6
(`nft --version`), la version de Debian 12.

**Comment lire ce cours.** Les questions 2 et 3 (le pare-feu d'un poste, puis d'un serveur)
s'appuient sur les sections @@ref:hooks@@ à @@ref:conntrack@@ ; la question 4 (la chaîne
`output`) sur les sections @@ref:verdicts@@ et @@ref:output@@ ; les questions 5 et 6 (le routeur)
sur les sections @@ref:chain-roles@@ et @@ref:forward@@ ; la question 7 sur la
section @@ref:sets@@ (les ensembles). La section @@ref:testing@@ sert tout au long du TP.

### @@sec:two-places@@ Deux places pour un pare-feu

- sur **une machine** qu'il protège (*host firewall*) : il filtre ce qui **entre** dans la
  machine et, plus rarement, ce qui en **sort** (interdire à un poste d'envoyer du courrier
  directement, par exemple) ;
- sur **un routeur** (*network firewall*) : il filtre ce qui **traverse** le routeur, entre des
  **zones** de confiance différentes. Le routeur est lui-même une machine à protéger.

Les deux se complètent. Le pare-feu du routeur protège tout un réseau d'un coup, mais il ne voit
pas ce que les machines d'une même zone échangent entre elles ; celui d'une machine la protège
aussi de ses voisines.

### @@sec:dmz@@ Les zones et la DMZ

Le découpage classique compte trois zones, chacune derrière une interface du routeur :

- l'**extérieur** (Internet) : on n'y maîtrise rien ;
- le **réseau interne** : les postes de travail. Ils ouvrent des connexions vers l'extérieur,
  mais **aucune** connexion ne doit y entrer ;
- la **DMZ** (*zone démilitarisée*) : les serveurs que l'extérieur doit pouvoir joindre (web,
  DNS, courrier). Ils sont **isolés** du réseau interne : un serveur exposé finit par être
  attaqué, et un serveur compromis ne doit pas donner accès aux postes.

### @@sec:matrix@@ La matrice des flux

Une politique de filtrage se résume par une **matrice des flux** : pour chaque couple (zone
source, zone destination), les services autorisés. Tout le reste est interdit :

| de ↓ vers → | extérieur | DMZ | interne |
|-------------|-----------|-----|---------|
| **extérieur** | — | les services publiés (HTTP d'un serveur…) | rien |
| **DMZ** | le strict nécessaire (DNS d'un serveur…) | — | rien |
| **interne** | la navigation (HTTP, DNS) | les services de la DMZ | — |

Chaque case décrit qui a le droit d'**ouvrir** un échange ; les réponses reviennent d'elles-mêmes
(section @@ref:conntrack@@). La règle d'or : **tout ce qui n'est pas explicitement autorisé est
interdit**. On l'obtient avec une politique par défaut `drop` et une règle par flux autorisé,
jamais l'inverse.
""")
            + info_subtitle(tr("Trois chaînes pour trois trajets"), tag="hooks")
            + tr("""

Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Choisir le hook d'une chaîne, c'est choisir **quels
paquets** elle verra.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hook-list@@ Les hooks

- **`prerouting`** : tous les paquets **reçus**, avant la décision de routage (« ce paquet est-il
  pour moi, ou à faire suivre ? ») ;
- **`input`** : les paquets **destinés à la machine** (à l'une de ses adresses, quelle que soit
  l'interface d'arrivée) ;
- **`forward`** : les paquets que la machine **route** : ni émis par elle, ni pour elle ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`postrouting`** : tous les paquets qui **partent**, routés ou émis localement ;
- **`ingress`** et **`egress`** : deux hooks placés au ras d'une interface, que la chaîne nomme
  (`device`). `ingress` voit tout ce que l'interface reçoit, avant `prerouting` (donc avant le
  suivi de connexion et le routage) ; `egress` tout ce qu'elle émet, après `postrouting`.

Le filtrage se fait dans **`input`**, **`forward`** et **`output`** ; `prerouting` et
`postrouting` servent surtout à la traduction d'adresses (NAT), `ingress` à détruire au plus tôt
un trafic indésirable.

### @@sec:three-paths@@ Un paquet, une seule des trois chaînes

| paquet | hooks traversés, dans l'ordre |
|--------|-------------------------------|
| reçu et destiné à la machine | `prerouting`, `input` |
| reçu et routé vers une autre machine | `prerouting`, `forward`, `postrouting` |
| émis par la machine | `output`, `postrouting` |

Un paquet ne passe donc que par **une** des trois chaînes `input`, `forward` et `output`.
Conséquences :

- sur un routeur, `forward` ne protège pas le routeur lui-même (un `ping` *vers* le routeur passe
  par `input`) et `input` ne filtre rien de ce qui le traverse : il faut les deux ;
- un échange a **deux sens**. Sur un poste client, la requête sort par `output` et la réponse
  entre par `input`. À travers un routeur, la requête **et** la réponse passent par `forward`,
  avec les interfaces d'entrée et de sortie inversées ;
- un paquet d'une machine vers elle-même (`127.0.0.1`, ou sa propre adresse) passe par `output`
  puis par `input`, à travers l'interface `lo` : une politique `drop` en `input` casse aussi les
  communications locales ;
- `forward` ne voit des paquets que si le routage est activé (`sysctl net.ipv4.ip_forward`).

### @@sec:chain-roles@@ Ce que protège chaque chaîne

| chaîne | paquets | ce qu'elle protège | politique habituelle |
|--------|---------|--------------------|----------------------|
| `input` | destinés à la machine | les services de la machine, routeur compris | `drop` |
| `forward` | qui traversent le routeur | les machines des zones derrière lui | `drop` |
| `output` | émis par la machine | le reste du réseau, contre la machine elle-même | `accept`, avec quelques interdictions |

### @@sec:families@@ Les familles

Une table appartient à une **famille**, qui fixe les paquets que ses chaînes voient et les hooks
dont elles disposent :

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip`, `ip6` | IPv4, IPv6 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

Pour filtrer, on prend la famille **`inet`** : les mêmes règles valent pour IPv4 et pour IPv6.
ARP n'est pas de l'IP : une chaîne `inet` ne voit ni les requêtes ni les réponses ARP, et une
politique `drop` n'empêche pas une machine de trouver l'adresse MAC de ses voisines.
""")
            + info_subtitle(tr("Tables, chaînes et règles : rappels"), tag="ruleset")
            + tr("""

Un jeu de règles (*ruleset*) est fait de **tables**, qui contiennent des **chaînes**, qui
contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table ni chaîne
prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des chaînes sont
libres ; `filter`, `input` ou `forward` ne sont que des habitudes.

### @@sec:base-chains@@ Tables et chaînes de base

Une **chaîne de base** est accrochée à un hook. Sa déclaration donne son **type**, son **hook**,
sa **priorité** et sa **politique**. Une même table peut porter une chaîne par hook :

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

- le **type** : `filter` pour filtrer ; `nat` pour la traduction d'adresses ; `route` (au hook
  `output`) pour refaire le routage d'un paquet qu'une règle a modifié ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus petite
  valeur à la plus grande. Les valeurs usuelles ont un nom : `raw` (-300), `mangle` (-150),
  `dstnat` (-100), `filter` (0), `security` (50), `srcnat` (100). `nft list ruleset` affiche
  `priority filter` pour 0. Le suivi de connexion opère à la priorité -200 : une chaîne `filter`
  voit des paquets dont l'état est déjà connu ;
- la **politique** : `accept` ou `drop`, le verdict des paquets qu'aucune règle n'a tranchés.
  Sans `policy`, c'est `accept` ; `reject` n'est pas une politique possible.

Les apostrophes protègent du shell les accolades et les points-virgules. Déclarer de nouveau une
chaîne existante, à l'identique mais avec une autre politique, **change sa politique** sans
toucher à ses règles.

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées au
même hook : un paquet les traverse **toutes**, par priorité croissante. **`drop` est définitif** :
le paquet est détruit sur-le-champ. **`accept` ne vaut que pour la chaîne en cours** : le paquet
passe à la chaîne suivante, puis aux hooks suivants, qui peuvent encore le détruire. On ne
« rattrape » donc pas dans une table un paquet qu'une autre a détruit.

### @@sec:regular-chains@@ Les chaînes régulières

Une **chaîne régulière** n'a ni hook, ni type, ni politique (`nft add chain inet filter
int_ext`). Elle ne voit que les paquets qu'une règle lui envoie, par **`jump`** ou par
**`goto`**, depuis une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump`,
l'évaluation **reprend dans la chaîne appelante**, à la règle qui suit le saut ; avec `goto`,
elle n'y revient pas. Ces chaînes servent à structurer un jeu de règles : une chaîne par couple
de zones sur un routeur (section @@ref:zone-chains@@), une chaîne « journaliser puis détruire »
(section @@ref:logging@@).

### @@sec:rules@@ Les règles : l'ordre compte

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des critères
(section @@ref:selectors@@), puis des actions et, le plus souvent, un verdict
(section @@ref:verdicts@@). Dès qu'un critère n'est pas satisfait, le paquet passe à la règle
suivante. Les règles d'une chaîne sont évaluées **dans l'ordre** ; la première règle satisfaite
qui porte un verdict décide, et les suivantes ne sont pas consultées : une règle `accept` placée
après une règle `reject` qui couvre les mêmes paquets ne sert à rien. L'ordre se choisit à
l'ajout :

```
nft add rule inet filter input iif lo accept           # à la FIN de la chaîne
nft insert rule inet filter input iif lo accept        # au DÉBUT
nft -a list ruleset                                    # affiche le numéro (handle) de chaque règle
nft insert rule inet filter input handle 7 …           # avant la règle 7 (add rule … handle 7 : après)
nft replace rule inet filter input handle 7 …          # remplace la règle 7
nft delete rule inet filter input handle 7             # supprime la règle 7
nft flush chain inet filter output                     # vide une chaîne (sa politique reste)
nft delete table inet filter                           # supprime la table et tout son contenu
```

Le **handle** d'une règle est un numéro que le noyau lui attribue et qui ne change plus : ce
n'est pas un numéro de ligne. **Le shell passe avant `nft`** : dès qu'une commande contient des
accolades, un point-virgule, des guillemets ou un `*`, entourez d'apostrophes tout ce qui suit
`nft`.

### @@sec:files@@ Un pare-feu dans un fichier

Dès qu'un pare-feu dépasse quelques règles, on l'écrit dans un **fichier**, dans la syntaxe
qu'affiche `nft list ruleset`, et on le recharge d'un bloc avec `nft -f /root/firewall.nft` :
c'est plus sûr que de retoucher les règles une à une, et l'ordre y est lisible.

```
flush ruleset

define ADMIN = 192.0.2.10

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        # un commentaire : SSH pour la machine d'administration
        ip saddr $ADMIN tcp dport 22 accept
        tcp dport 80 accept
    }
}
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; `nft -c -f /root/firewall.nft` le vérifie sans rien changer ;
- le fichier commence par **`flush ruleset`** : sans cela, le recharger ajouterait ses règles
  une seconde fois, à la suite des premières ;
- `define` nomme une valeur, reprise par `$NOM` ;
- `nft -s list ruleset > /root/firewall.nft` écrit un tel fichier à partir des règles en place
  (ajoutez-lui `flush ruleset` en tête) ;
- les règles tapées avec `nft` sont **volatiles** : elles disparaissent au redémarrage. Sous
  Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage.
""")
            + info_subtitle(tr("Les critères"), tag="selectors")
            + tr("""

Un critère compare un champ du paquet, ou une information que le noyau lui associe, à une
valeur. Les critères d'une règle sont **tous** requis (un **et**) ; pour un **ou**, on utilise un
ensemble de valeurs ou plusieurs règles.

### @@sec:selector-list@@ Les principaux critères

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname eth0` | interface d'**entrée** du paquet (connue dans `input` et `forward`, pas dans `output`) |
| `oif eth1`, `oifname eth1` | interface de **sortie** (connue dans `forward` et `output`, pas dans `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | adresse ou réseau **source** |
| `ip daddr 192.0.2.10` | adresse ou réseau **destination** |
| `meta l4proto tcp`, `ip protocol udp` | protocole de transport (`tcp`, `udp`, `icmp`) ; `meta l4proto` vaut aussi pour IPv6 |
| `tcp dport 80`, `udp dport 53` | port **destination** : le service demandé |
| `tcp sport 80`, `udp sport 53` | port **source** : dans une réponse, le port du serveur |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête et réponse) |
| `ct state established,related`, `ct state new` | état dans le suivi de connexion (section @@ref:conntrack@@) |

**`iif` ou `iifname` ?** `iif lo` compare le numéro (l'index) de l'interface : c'est rapide,
mais l'interface doit exister quand la règle est chargée. `iifname eth0` compare son nom : un
peu plus lent, mais valable pour une interface qui n'existe pas encore. `nft list ruleset`
réaffiche les noms entre guillemets (`iifname "eth0"`).

### @@sec:values@@ Les formes de valeur

| forme | exemples |
|-------|----------|
| une valeur, un réseau | `tcp dport 22`, `ip saddr 192.0.2.0/24` |
| une plage | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| un ensemble | `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }` |
| un ensemble nommé | `ip saddr @admins` (section @@ref:sets@@) |
| la négation | `ip daddr != 192.0.2.10`, `tcp dport != { 80, 8080 }` |

Nommer un champ implique le protocole qui le porte : `tcp dport 80` ne concerne que TCP, `icmp
type echo-request` que ICMP. Dans une table `inet`, `tcp dport 80 accept` vaut pour IPv4 et pour
IPv6, alors qu'un critère `ip …` restreint la règle à IPv4. `nft describe icmp type` liste les
valeurs possibles d'un champ.

### @@sec:direction@@ D'où vient le paquet, où va-t-il

Une règle de pare-feu de réseau dit en général **d'où** vient le paquet et **où** il va, puis
le service :

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

L'interface désigne la **zone**, l'adresse une **machine** de cette zone. Filtrer sur l'adresse
source seule est fragile : une adresse se falsifie (*spoofing*, section @@ref:spoofing@@). Pour
une règle sensible, on exige **l'interface et l'adresse** : `iifname eth2 ip saddr 192.0.2.10
tcp dport 22 accept` n'accepte la machine d'administration que si elle arrive du bon côté.
""")
            + info_subtitle(tr("Le suivi de connexion : filtrer selon le sens"), tag="conntrack")
            + tr("""

Netfilter mémorise les **connexions** en cours (*connection tracking*, ou *conntrack*) : une
connexion TCP, mais aussi un échange UDP (des datagrammes entre les mêmes adresses et les mêmes
ports) ou ICMP (un `echo-request` et son `echo-reply`). Le suivi ne filtre rien : il
**étiquette** chaque paquet d'un **état**, que les règles testent avec `ct state`.

### @@sec:ct-states@@ Les états

- **`new`** : le paquet ouvre un échange, ou appartient à un échange dont on n'a encore vu
  qu'**un seul sens** (le SYN en TCP, la première requête UDP et ses répétitions) ;
- **`established`** : le paquet appartient à un échange dont on a vu des paquets **dans les deux
  sens**. La toute première **réponse** (le SYN-ACK, la réponse d'un serveur DNS, l'`echo-reply`)
  est déjà dans cet état, comme tout ce qui suit, dans un sens et dans l'autre ;
- **`related`** : le paquet n'appartient pas à un échange connu, mais il est **lié** à l'un
  d'eux : une erreur ICMP qui le concerne (*port unreachable*, *time exceeded*…) ;
- **`invalid`** : le paquet ne correspond à rien de connu et ne peut pas ouvrir d'échange ;
- **`untracked`** : le paquet a été soustrait au suivi (règle `notrack`).

Un échange est enregistré par son premier paquet, à condition que le pare-feu l'accepte : un
paquet `new` détruit ne laisse aucune trace. Il est oublié après un temps d'inactivité : 30
secondes pour un échange UDP ou ICMP resté sans suite, 5 jours pour une connexion TCP établie.

### @@sec:stateless@@ Le filtre sans état et sa faille

Un filtre **sans état** ne sait autoriser les réponses qu'à l'aveugle : « tout ce qui vient du
port 80 », « tout l'UDP qui vient du port 53 ». C'est une **faille** : celui qui choisit 80 ou 53
comme port source de ses paquets passe aussi, vers n'importe quel port. Le port source d'un
paquet est choisi par son émetteur ; il ne prouve rien.

### @@sec:stateful-rule@@ La règle à états

Avec le suivi de connexion, on autorise l'**ouverture** d'un échange, dans un seul sens, et les
réponses suivent :

```
nft add rule inet filter forward ct state established,related accept       # en première règle
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

La seconde règle laisse les machines derrière `eth2` ouvrir des connexions vers le port 80 de
celles derrière `eth0` ; les réponses passent par la première. Rien ne permet à une machine
derrière `eth0` d'ouvrir une connexion dans l'autre sens : son premier paquet serait `new`, et
aucune règle ne l'accepte. C'est le **premier paquet** d'un échange qui fixe son sens.

Placée en **tête** de chaîne, la règle à états traite presque tous les paquets (ceux des
échanges en cours) ; les règles suivantes ne voient plus que les ouvertures. `ct state invalid
drop` la complète souvent.

### @@sec:selective-replies@@ N'accepter que certaines réponses

`ct state` se combine avec les autres critères quand on ne veut accepter que **certaines**
réponses :

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

La première n'accepte que les réponses du serveur DNS `192.0.2.53` aux questions que la machine
lui a posées : ce serveur ne peut pas, de lui-même, joindre la machine depuis son port 53. La
seconde accepte tout le trafic retour des connexions TCP que la machine a ouvertes, mais pas les
erreurs ICMP qui les concernent : une erreur ICMP est `related`, mais ce n'est pas un paquet
TCP.
""")
            + info_subtitle(tr("Verdicts : accept, drop, reject"), tag="verdicts")
            + tr("""

### @@sec:verdict-list@@ Les verdicts

- **`accept`** : le paquet passe ; l'évaluation de la chaîne de base s'arrête ;
- **`drop`** : le paquet est détruit **en silence** : l'émetteur attend, réessaie, puis renonce
  (*timeout*) ;
- **`reject`** : le paquet est détruit et l'émetteur est **prévenu** par un message d'erreur :
  l'erreur est immédiate ;
- **`jump chaine`** : évalue la chaîne régulière, et revient si elle ne tranche pas ; **`goto
  chaine`** y va sans retour ; **`return`** quitte la chaîne en cours et reprend dans la chaîne
  appelante.

Une règle sans verdict (`counter`, `log`…) agit, puis laisse le paquet continuer vers la règle
suivante.

### @@sec:reject@@ reject : refuser en prévenant

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | un message ICMP *port unreachable* (`nft list ruleset` affiche la forme complète, `reject with icmp port-unreachable`, ou `icmpx` quand la règle ne dit pas la version d'IP) |
| `reject with tcp reset` | un segment TCP RST : ce que répond une machine sans pare-feu dont le port est fermé (TCP seulement) |
| `reject with icmpx admin-prohibited` | l'erreur « interdit par l'administrateur », en ICMP ou en ICMPv6 selon le paquet |

Côté client, l'erreur est `Connection refused` avec la réponse par défaut ou un RST, `No route to
host` avec `admin-prohibited`.

### @@sec:drop-or-reject@@ Détruire ou refuser ?

Vers l'extérieur on **détruit** : `drop` ne révèle rien à un attaquant, pas même l'existence de
la machine. Pour ses propres utilisateurs on **refuse** souvent : l'erreur est claire et
immédiate, alors qu'un `drop` les fait attendre sans explication.

### @@sec:output-view@@ Dans la chaîne output : ce que voit le programme

Dans la chaîne **`output`**, le paquet est arrêté sur la machine même qui l'émet, et la
différence entre `drop` et `reject` se voit dans le programme :

| programme | avec `drop` | avec `reject` |
|-----------|-------------|---------------|
| une connexion TCP (`nc`, `curl`) | rien ne signale le blocage : le programme attend son délai (`timed out`) | échec immédiat : `Connection refused` |
| `ping` | `100% packet loss`, sans autre message | `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` |

Le message d'erreur d'un `reject` est fabriqué par le noyau et **revient au programme par
l'interface `lo`** : la chaîne `input` doit l'accepter (`iif lo accept`), sinon le programme
attend comme avec `drop`.
""")
            + info_subtitle(tr("Compter et journaliser"), tag="logging")
            + tr("""

### @@sec:counters@@ Compter

**`counter`** compte les paquets et les octets qui atteignent cet endroit de la règle :
`tcp dport 25 counter reject`. `nft list ruleset` affiche alors `counter packets 3 bytes 180` sur
la règle : c'est le moyen le plus simple de savoir **quelle règle** a vu un paquet. Pour compter
ce que la politique d'une chaîne détruit, on termine la chaîne par une règle `counter drop`. Avec
la version de `nft` des machines du TP, le compteur d'une règle ne se remet pas à zéro (`nft
reset counters` ne concerne que les compteurs nommés, déclarés par `nft add counter`) : on
remplace la règle.

### @@sec:log@@ Journaliser

**`log`** produit une ligne par paquet (interface, adresses, protocole, ports). Il existe sous
deux formes :

- `log prefix "fw: "` écrit dans le **journal du noyau**, lu sur une vraie machine avec
  `dmesg -w` ou `journalctl -k -f`. **Dans un conteneur, cette forme ne donne rien** : par défaut
  le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "fw: " group 0` remet les paquets à **nflog**, où un programme vient les lire :
  **`tcpdump -n -i nflog:0`**. C'est la forme à utiliser dans ce TP.

`log` n'est pas un verdict : on le fait suivre d'un `drop` ou d'un `reject`. Pour ne pas remplir
le journal, on le limite : `limit rate 5/minute log prefix "fw: " group 0` journalise cinq
paquets d'un coup au plus, puis un toutes les 12 secondes ; les autres continuent vers la règle
suivante sans être journalisés. L'usage est de réunir les deux dans une chaîne régulière, où
l'on saute en dernière règle des chaînes concernées :

```
nft add chain inet filter logdrop
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "fw: " group 0'
nft add rule inet filter logdrop counter drop
nft add rule inet filter forward jump logdrop
```

Le préfixe contient des guillemets : dans un shell, toute la règle se protège par des
apostrophes.
""")
            + info_subtitle(tr("Filtrer ce qui sort : la chaîne output"), tag="output")
            + tr("""

### @@sec:why-output@@ Pourquoi filtrer la sortie

La chaîne `output` ne protège pas la machine : elle protège **le reste du réseau** contre elle,
et impose une règle d'usage à ses utilisateurs. On s'en sert pour :

- **limiter les dégâts d'une machine compromise** : un poste qui n'a pas à envoyer de courrier
  ne pourra pas servir à envoyer du spam ;
- **imposer un passage obligé** : le courrier par le serveur de l'entreprise, le DNS par son
  résolveur, le web par son mandataire ;
- **cloisonner un serveur** : un serveur web n'a aucune raison d'ouvrir lui-même des connexions
  vers les postes du réseau interne.

La chaîne `output` d'une machine ne voit que ce que **ses propres processus** émettent, quel que
soit l'utilisateur (`root` compris) ; sur un routeur, elle ne voit rien de ce qui le traverse.

### @@sec:output-policies@@ Deux façons de l'écrire

**Tout permettre, sauf…** : politique `accept` et quelques règles d'interdiction. C'est la forme
habituelle sur un poste, et celle de ce TP :

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
nft add rule inet filter output ip daddr 192.0.2.25 tcp dport 25 accept
nft add rule inet filter output tcp dport 25 reject
```

L'**exception précède l'interdiction** : la première règle satisfaite décide. Une seule règle
convient aussi : `ip daddr != 192.0.2.25 tcp dport 25 reject`.

**Tout interdire, sauf…** : politique `drop` et une règle par flux sortant autorisé. C'est la
forme d'un serveur que l'on veut cloisonner. Il faut alors penser à tout ce que la machine émet
sans qu'on le voie : ses **réponses** aux connexions qu'elle sert (`ct state established,related
accept`, en tête, comme en `input`), ses échanges avec elle-même (`oif lo accept`), ses questions
DNS.

### @@sec:output-reject@@ drop ou reject en sortie

En `output`, préférez **`reject`** : celui qui est bloqué est un utilisateur de la machine, et il
vaut mieux qu'il le sache aussitôt (section @@ref:output-view@@). Deux points à retenir :

- le retour du `reject` passe par la chaîne **`input`** de la même machine, par l'interface
  `lo`. Avec une politique `drop` en `input`, il faut `iif lo accept` ou une règle à états
  générale (`ct state established,related accept` : le message d'erreur est `related`). Une
  règle à états limitée à TCP (`meta l4proto tcp ct state …`) ne le laisse pas passer ;
- un `drop` en sortie ressemble, vu du programme, à une panne du réseau ou du serveur distant :
  pensez à regarder aussi la chaîne `output` de la machine quand « rien ne répond ».
""")
            + info_subtitle(tr("Écrire la politique d'un routeur"), tag="forward")
            + tr("""

La chaîne **`forward`** d'un routeur filtre ce qui passe d'une zone à l'autre. Elle voit les
paquets des **deux sens** de chaque échange : la requête, puis la réponse, avec les interfaces
d'entrée et de sortie inversées.

### @@sec:method@@ La méthode

1. **Associer chaque zone à une interface** du routeur (`ip -br address`) et écrire la matrice
   des flux (section @@ref:matrix@@).
2. **Politique `drop`** sur `forward` : plus rien ne traverse.
3. **La règle à états en tête** : `ct state established,related accept`. Elle ne laisse passer
   que les suites d'échanges déjà autorisés, dans les deux sens.
4. **Une règle par flux autorisé**, qui décrit l'**ouverture** de l'échange : zone source
   (`iifname`), zone destination (`oifname`), serveur éventuel (`ip daddr`), service (`tcp dport`,
   `udp dport`, `icmp type echo-request`).
5. **Tester** chaque flux autorisé et **chaque interdiction** voisine (un autre port, un autre
   serveur, l'autre sens).

### @@sec:forward-example@@ Un exemple

L'interne (`eth2`) navigue sur le web de l'extérieur (`eth0`) ; l'extérieur ne joint que le
serveur web de la DMZ (`eth1`) :

```
table inet filter {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept
        iifname "eth0" oifname "eth1" ip daddr 203.0.113.80 tcp dport 80 accept
    }
}
```

Chaque règle se lit comme une case de la matrice : d'où, vers où, quel serveur, quel service.
Ce qui n'est pas écrit est interdit : l'extérieur n'ouvre rien vers l'interne, la DMZ n'ouvre
rien du tout, le port 8080 du serveur reste fermé. Les erreurs ICMP utiles (*port unreachable*,
*time exceeded*…) reviennent par la règle à états, puisqu'elles sont `related` ; un `ping` ne
traverse que si une règle accepte ses `echo-request`.

### @@sec:zone-chains@@ Structurer : une chaîne par couple de zones

Quand les règles se multiplient, on range celles de chaque couple (zone source, zone
destination) dans une **chaîne régulière**, et la chaîne `forward` ne fait plus qu'aiguiller :

```
table inet filter {
    chain int_ext {
        tcp dport 80 accept
        ip daddr 198.51.100.53 udp dport 53 accept
    }
    chain ext_dmz {
        ip daddr 203.0.113.80 tcp dport 80 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" jump int_ext
        iifname "eth0" oifname "eth1" jump ext_dmz
    }
}
```

Un paquet que sa chaîne de zones n'accepte pas revient dans `forward`, à la règle qui suit le
saut, et finit détruit par la politique ; un couple de zones sans chaîne n'a droit à rien.
L'aiguillage peut tenir en une seule règle, avec un dictionnaire de verdicts
(section @@ref:vmaps@@) : `iif . oif vmap { eth2 . eth0 : jump int_ext, eth0 . eth1 : jump
ext_dmz }`.

### @@sec:router-input@@ Protéger le routeur lui-même

Un routeur est aussi une machine : il a ses propres services (SSH pour son administration) et
ses propres besoins (interroger un serveur DNS, répondre aux `ping`). Tout cela passe par ses
chaînes **`input`** et `output`, jamais par `forward` (section @@ref:three-paths@@) : une règle
de `forward` n'a aucun effet sur un paquet destiné au routeur, et inversement. Sa chaîne `input`
ressemble à celle d'un serveur prudent :

- politique `drop` et `iif lo accept` ;
- les réponses à ce que le routeur émet lui-même (règle à états) ;
- les `ping` venus des zones de confiance seulement : le critère est l'**interface d'entrée**,
  `iifname { eth1, eth2 } icmp type echo-request accept` ;
- l'administration depuis **une** machine, désignée par son interface **et** son adresse :
  `iifname eth2 ip saddr 192.0.2.10 tcp dport 22 accept`.

Le routeur répond sur **toutes** ses adresses, quelle que soit l'interface d'arrivée : c'est
`iifname` qui dit de quelle zone vient un paquet, pas l'adresse de destination.

### @@sec:spoofing@@ L'usurpation d'adresse

Rien n'empêche une machine de l'extérieur d'émettre des paquets dont l'adresse source est celle
d'une machine interne (*spoofing*). Une règle qui ne regarde que `ip saddr` les prend pour du
trafic interne. Deux parades :

- **dire la zone par l'interface**, jamais par l'adresse seule : `iifname eth2 ip saddr
  192.0.2.10 …`. On peut aussi détruire d'emblée ce qui est manifestement faux :
  `iifname eth0 ip saddr 192.0.2.0/24 drop` (une adresse interne qui arrive de l'extérieur) ;
- **vérifier le chemin de retour** : la règle `fib saddr . iif oif missing drop` détruit tout
  paquet dont l'adresse source ne serait pas jointe par l'interface d'où il arrive. On la place
  avant tout le reste, au hook `prerouting`, où elle vaut pour `input` et pour `forward` :

```
nft 'add chain inet filter prerouting { type filter hook prerouting priority raw; policy accept; }'
nft add rule inet filter prerouting fib saddr . iif oif missing drop
```

Cette vérification suppose un routage symétrique : chaque réseau n'est joint que par une
interface.

### @@sec:forward-nat@@ Quand le routeur traduit aussi les adresses

Un routeur fait souvent aussi de la traduction d'adresses (NAT), dans des chaînes de type `nat`.
La chaîne `forward` voit un paquet **après** le changement de son adresse de destination (fait
en `prerouting`) et **avant** le changement de son adresse source (fait en `postrouting`) : ses
règles nomment donc l'adresse réelle du serveur interne, et l'adresse d'origine du client.
""")
            + info_subtitle(tr("Les ensembles"), tag="sets")
            + tr("""

Un **ensemble** (*set*) réunit des valeurs d'un même type ; une règle le consulte en une seule
opération, quel que soit le nombre de ses éléments.

### @@sec:anonymous-sets@@ Les ensembles anonymes

Un **ensemble anonyme** s'écrit dans la règle, entre accolades : `tcp dport { 80, 8080 }`,
`iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }`. Une seule règle remplace
plusieurs règles identiques ; son contenu ne change plus, sauf à remplacer la règle.

### @@sec:named-sets@@ Les ensembles nommés

Un **ensemble nommé** est un objet de la table, que plusieurs règles consultent (`@nom`) et
dont on modifie le contenu **sans toucher aux règles** :

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
nft 'delete element inet filter admins { 192.0.2.20 }'
```

Le `type` fixe la nature des éléments : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC),
`inet_service` (port), `inet_proto` (protocole). Les drapeaux (`flags`) fixent son
comportement :

| déclaration | effet |
|-------------|-------|
| `flags interval;` | les éléments peuvent être des réseaux ou des plages (`192.0.2.0/24`) ; sans ce drapeau, des valeurs isolées seulement |
| `flags timeout; timeout 1h;` | les éléments disparaissent d'eux-mêmes après ce délai |
| `flags dynamic;` | les règles peuvent ajouter elles-mêmes des éléments, au passage des paquets |

Un élément peut réunir plusieurs champs, séparés par un point : avec un ensemble de type
`ipv4_addr . inet_service`, la règle `ip saddr . tcp dport @allowed accept` accepte les couples
(adresse, port) qu'il contient.

### @@sec:dynamic-sets@@ Les ensembles alimentés par les règles

Un **ensemble dynamique** est rempli **par les règles elles-mêmes**, au passage des paquets, et
ses éléments peuvent **expirer** :

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

- chaque paquet qui atteint la règle `add @banned { ip saddr }` fait ajouter son adresse source
  à l'ensemble ; l'élément disparaît de lui-même 60 secondes plus tard. `update` au lieu de `add`
  relance le délai à chaque paquet ;
- `add @banned …` n'est pas un verdict : le paquet continue vers la règle suivante ;
- `nft list set inet filter banned` montre les éléments et le temps qui leur reste (`expires
  54s768ms`) ; `nft flush set inet filter banned` vide l'ensemble.

**La place des règles compte.** La règle qui consulte l'ensemble (`ip saddr @banned drop`) ne
coupe les échanges déjà en cours que si elle est placée **avant la règle à états** ; après elle,
elle ne voit plus que les ouvertures. On construit ainsi un bannissement temporaire, une limite
par adresse ou un *port knocking*.

### @@sec:vmaps@@ Les dictionnaires de verdicts

Un **dictionnaire de verdicts** (*verdict map*, `vmap`) associe un verdict à chaque valeur d'un
champ, en une seule consultation :

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 80 : accept, 23 : drop }'
nft 'add rule inet filter forward oifname vmap { eth1 : jump to_dmz, eth2 : jump to_int }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
```

Un paquet dont le champ n'est pas une clé du dictionnaire passe à la règle suivante.
""")
            + info_subtitle(tr("Observer et tester"), tag="testing")
            + tr("""

Tester un pare-feu, c'est vérifier ce qui **doit passer** et ce qui **doit être bloqué**, avec
des délais courts pour ne pas attendre.

### @@sec:test-commands@@ Les commandes de test

| service | commande de test |
|---------|------------------|
| ICMP | `ping -c 2 -W 1 adresse` |
| HTTP (ports 80, 8080) | `curl -m 3 http://adresse/`, `curl -m 3 http://adresse:8080/` |
| DNS (UDP 53) | `dig @serveur nom +time=1 +tries=1` (ou `+short` pour la seule réponse) |
| SSH (TCP 22), courrier (TCP 25), tout port TCP | `nc -v -w 3 adresse 22` (la bannière du serveur s'affiche), `ssh root@adresse` |

Les serveurs web de test répondent par leur nom et par ce qu'ils voient du client :
`SERVER=dmz1`, `CLIENT_IP=…`, `TTL=63` (64 moins un par routeur traversé). Sur un serveur,
`ss -tulnp` liste les ports en écoute : un port fermé répond `Connection refused` même sans
pare-feu.

### @@sec:symptoms@@ Lire le message d'erreur

| symptôme | cause probable |
|----------|----------------|
| `Connection timed out`, `100% packet loss`, après le délai | un paquet est **détruit** (`drop`), à l'aller ou au retour |
| `Connection refused`, immédiat | un `reject`, ou aucun serveur sur ce port |
| `Could not resolve host`, `Temporary failure in name resolution` | le **DNS** ne répond pas : la question ou la réponse est filtrée. Essayez avec l'adresse |
| `ping: sendmsg: Operation not permitted`, avec `Destination Port Unreachable` venant de la machine elle-même | un `reject` dans sa propre chaîne `output` (un `drop` n'y donne que `100% packet loss`) |
| `no servers could be reached` (`dig`) | la question DNS ou sa réponse est détruite |

### @@sec:locate@@ Localiser un blocage sur un routeur

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu : en réception il voit
les paquets **avant** tous les hooks (même ceux que le pare-feu va détruire), en émission
**après** tous les hooks (seulement ceux qui partent vraiment). Sur le routeur, on capture donc
des deux côtés :

```
tcpdump -n -i eth2 icmp or port 80        # côté arrivée : le paquet entre-t-il ?
tcpdump -n -i eth0 icmp or port 80        # côté départ : ressort-il ? la réponse revient-elle ?
```

Un paquet vu à l'arrivée mais pas au départ a été arrêté par le routeur (ou n'a pas de route).
Une requête qui ressort sans que la réponse revienne côté arrivée désigne le **retour** : la
réponse est détruite par le routeur, ou par la machine qui devait répondre.

Les **compteurs** disent ensuite quelle règle a vu le paquet : ajoutez `counter` aux règles
(`… counter accept`) et relisez `nft list chain inet filter forward` après un essai.

### @@sec:trace@@ Suivre un paquet règle par règle

Une règle `meta nftrace set 1`, placée en tête de chaîne, marque les paquets à suivre, et
`nft monitor trace` affiche leur parcours : la chaîne traversée, chaque règle satisfaite et le
verdict final.

```
nft insert rule inet filter forward ip saddr 192.0.2.10 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter forward packet: iif "eth2" ip saddr 192.0.2.10 … tcp dport 8080 …
trace id a95ea7ef inet filter forward rule ip saddr 192.0.2.10 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter forward verdict continue
trace id a95ea7ef inet filter forward policy drop
```

Supprimez la règle de trace quand vous avez fini.

### @@sec:diagnosis@@ Une démarche de diagnostic

1. le message d'erreur du client : délai (`drop`), refus immédiat (`reject`), ou nom non résolu
   (le DNS) ?
2. `nft list ruleset` sur la machine et sur le routeur : est-ce le jeu de règles que vous croyez
   avoir chargé, dans le bon ordre, dans la bonne chaîne (`input` ou `forward`) ?
3. `tcpdump` : où le paquet s'arrête-t-il ? À l'aller, ou au retour ?
4. les compteurs, puis la trace : quelle règle l'a arrêté ?
""")
            + info_subtitle(tr("Bonnes pratiques et pièges"), tag="practices")
            + tr("""

### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input` et en `forward`, une règle
  par flux de la matrice, restreinte à ceux qui en ont besoin (interface, adresse, port) ;
- **la règle à états en tête** : elle traite presque tous les paquets et dispense d'ouvrir quoi
  que ce soit pour les réponses ;
- **une règle décrit une ouverture** : zone source, zone destination, serveur, service. Jamais
  de règle sur le seul port source ;
- **l'interface pour la zone**, l'adresse pour la machine, les deux pour une règle sensible ;
- **le routeur se protège lui-même** : sa chaîne `input` est aussi stricte que celle d'un
  serveur ;
- **tester les interdictions** autant que les autorisations : un pare-feu qui laisse tout
  passer réussit tous les tests « ça marche » ;
- **un fichier, chargé d'un bloc** (section @@ref:files@@), plutôt que des commandes tapées une
  à une.

### @@sec:pitfalls@@ Les pièges

- **oublier le DNS** : une politique `drop` qui ne laisse pas revenir les réponses du serveur
  DNS fait échouer toute commande qui utilise un nom (`Could not resolve host`), alors que le
  service visé est peut-être ouvert. Testez avec l'adresse ;
- **oublier `lo`** : les services locaux se parlent par `127.0.0.1`, et le retour d'un `reject`
  de la chaîne `output` passe par là ;
- **se tromper de chaîne** : `input` pour ce qui est destiné au routeur, `forward` pour ce qui
  le traverse. Une règle juste dans la mauvaise chaîne ne fait rien ;
- **oublier le retour** : sans règle à états, accepter la requête ne suffit pas, la réponse est
  détruite au retour ;
- **l'ordre des règles** : une exception placée après l'interdiction qu'elle devait tempérer
  n'est jamais consultée (`nft insert rule`, ou `handle`) ;
- **se couper l'accès** : sur un routeur administré à distance, une chaîne `input` en `policy
  drop` sans règle pour SSH coupe la session en cours. Chargez un fichier complet, d'un bloc ;
- **`flush ruleset`** efface **toutes** les tables, pas seulement les vôtres, et les règles
  tapées avec `nft` disparaissent au redémarrage.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table et chaînes | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (de même `input`, `output`) |
| règles | `nft add rule inet filter forward …` (fin), `nft insert rule …` (début), `nft insert rule inet filter forward handle N …` (avant la règle N), `nft replace rule inet filter forward handle N …`, `nft delete rule inet filter forward handle N` |
| critères | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts et actions | `accept`, `drop`, `reject`, `jump chaine`, `counter`, `log prefix "…" group 0` (lu avec `tcpdump -n -i nflog:0`) |
| ensembles | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| fichier | `nft -c -f /root/firewall.nft` (vérifier), `nft -f /root/firewall.nft` (charger ; le fichier commence par `flush ruleset`), `nft -s list ruleset > /root/firewall.nft` (sauvegarder) |
| tout effacer | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S nom +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""")
        )

    # -- the commands of the reference solution (used by `final` and the instructor texts) ----

    def cmds_host_input(self) -> List[str]:
        """Question 2: the input chain of the client ext1."""
        d = self.data
        return [f"nft add table {FAMILY} {TABLE}",
                f"nft 'add chain {FAMILY} {TABLE} input {{ type filter hook input priority 0; policy drop; }}'",
                f"nft add rule {FAMILY} {TABLE} input iif lo accept",
                f"nft add rule {FAMILY} {TABLE} input ip saddr {ip_of(d, HOST_DNS).ip} udp sport {DNS_PORT} ct state established accept",
                f"nft add rule {FAMILY} {TABLE} input meta l4proto tcp ct state established,related accept",
                f"nft 'add rule {FAMILY} {TABLE} input icmp type {{ echo-request, echo-reply }} accept'"]

    def cmds_host_server(self) -> List[str]:
        """Question 3: the services of ext1 (HTTP for everybody, SSH for the internal network)."""
        return [f"nft add rule {FAMILY} {TABLE} input tcp dport {HTTP_PORT} accept",
                f"nft add rule {FAMILY} {TABLE} input ip saddr {self.data.nets.int} tcp dport {SSH_PORT} accept"]

    def cmds_host_output(self) -> List[str]:
        """Question 4 (c): the output chain of ext1, mail towards one server only, the rest rejected."""
        return [f"nft 'add chain {FAMILY} {TABLE} output {{ type filter hook output priority 0; policy accept; }}'",
                f"nft add rule {FAMILY} {TABLE} output ip daddr {ip_of(self.data, MAIL_ALLOWED).ip} tcp dport {MAIL_PORT} accept",
                f"nft add rule {FAMILY} {TABLE} output tcp dport {MAIL_PORT} reject"]

    def cmds_host(self) -> List[str]:
        """The whole reference solution of ext1, in question order."""
        return self.cmds_host_input() + self.cmds_host_server() + self.cmds_host_output()

    def cmds_router_input(self) -> List[str]:
        """Question 5: the input chain of the router."""
        d = self.data
        return [f"nft add table {FAMILY} {TABLE}",
                f"nft 'add chain {FAMILY} {TABLE} input {{ type filter hook input priority 0; policy drop; }}'",
                f"nft add rule {FAMILY} {TABLE} input iif lo accept",
                f"nft 'add rule {FAMILY} {TABLE} input iifname {{ {DMZ_IF}, {INT_IF} }} icmp type echo-request accept'",
                f"nft add rule {FAMILY} {TABLE} input icmp type echo-reply accept",
                f"nft add rule {FAMILY} {TABLE} input ip saddr {ip_of(d, ROUTER_DNS).ip} udp sport {DNS_PORT} ct state established accept",
                f"nft add rule {FAMILY} {TABLE} input iifname {EXT_IF} meta l4proto tcp ct state established,related accept",
                f"nft add rule {FAMILY} {TABLE} input iifname {INT_IF} ip saddr {ip_of(d, SSH_ADMIN).ip} tcp dport {SSH_PORT} accept"]

    def cmds_router_forward(self) -> List[str]:
        """Question 6: the forward chain of the router."""
        d = self.data
        rule = f"nft add rule {FAMILY} {TABLE} forward"
        return [f"nft 'add chain {FAMILY} {TABLE} forward {{ type filter hook forward priority 0; policy drop; }}'",
                f"{rule} ct state established,related accept",
                f"{rule} iifname {INT_IF} oifname {DMZ_IF} icmp type echo-request accept",
                f"{rule} iifname {INT_IF} oifname {EXT_IF} ip daddr {ip_of(d, INT_DNS).ip} udp dport {DNS_PORT} accept",
                f"{rule} iifname {INT_IF} oifname {EXT_IF} tcp dport {HTTP_PORT} accept",
                f"nft '{rule[4:]} iifname {{ {EXT_IF}, {INT_IF} }} oifname {DMZ_IF} ip daddr {ip_of(d, DMZ_WEB).ip} tcp dport {HTTP_PORT} accept'",
                f"{rule} iifname {DMZ_IF} oifname {EXT_IF} ip saddr {ip_of(d, DMZ_DNS).ip} udp dport {DNS_PORT} accept",
                f"{rule} iifname {INT_IF} oifname {DMZ_IF} ip daddr {ip_of(d, DMZ_DNS).ip} udp dport {DNS_PORT} accept"]

    def cmds_router_ban(self) -> List[str]:
        """Question 7 (bonus): the dynamic set and its two rules, inserted at the head of forward (the second
        insert puts the drop rule first)."""
        return [f"nft 'add set {FAMILY} {TABLE} {BAN_SET} {{ type ipv4_addr; flags dynamic,timeout; timeout {BAN_SECONDS}s; }}'",
                f"nft 'insert rule {FAMILY} {TABLE} forward iifname {EXT_IF} oifname {INT_IF} tcp dport {SSH_PORT} add @{BAN_SET} {{ ip saddr }}'",
                f"nft insert rule {FAMILY} {TABLE} forward iifname {EXT_IF} oifname {INT_IF} ip saddr @{BAN_SET} drop"]

    def cmds_router(self) -> List[str]:
        """The whole reference solution of the router, in question order."""
        return self.cmds_router_input() + self.cmds_router_forward() + self.cmds_router_ban()

    # -- configuration files ----------------------------------------------------------------

    def unbound_conf(self) -> str:
        """unbound on the DNS servers: the static zone DOMAIN with the names of every machine (the router has
        one name per zone), no recursion: a name outside the zone gets an immediate NXDOMAIN."""
        d = self.data
        lines = ["server:",
                 "    interface: 0.0.0.0",
                 "    access-control: 0.0.0.0/0 allow",
                 '    chroot: ""',
                 '    module-config: "iterator"',
                 '    local-zone: "." static',
                 f'    local-zone: "{DOMAIN}." static']
        for machine in HOSTS:
            lines.append(f'    local-data: "{machine}.{DOMAIN}. IN A {ip_of(d, machine).ip}"')
        for zone in ZONES:
            lines.append(f'    local-data: "{ROUTER}-{zone}.{DOMAIN}. IN A {getattr(d.ips, f"{ROUTER}_{zone}").ip}"')
        return "\n".join(lines) + "\n"

    def resolv_conf(self, server) -> str:
        """/etc/resolv.conf naming the DNS server *server* (a machine name; None: the machine itself); one
        short attempt, so that a filtered DNS fails fast."""
        address = '127.0.0.1' if server is None else ip_of(self.data, server).ip
        return f"search {DOMAIN}\nnameserver {address}\noptions timeout:1 attempts:1\n"

    # -- states -----------------------------------------------------------------------------

    def _configure_network(self):
        """Addresses and routes of the visible machines and of their clones (same values)."""
        d = self.data
        for suffix in ('', MIRROR):
            for machine, zone in ZONE_OF.items():
                self.cmd(machine + suffix, f"ip address add {ip_of(d, machine)} dev eth0")
                self.cmd(machine + suffix, f"ip route add default via {getattr(d.ips, f'{ROUTER}_{zone}').ip}")
            for zone, iface in ROUTER_IFACES.items():
                self.cmd(ROUTER + suffix, f"ip link set {iface} up; ip address add {getattr(d.ips, f'{ROUTER}_{zone}')} dev {iface}")
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write, which the students need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(visible(m) == ROUTER))

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        for m in self.get_machine_names():
            name = visible(m)
            # names are resolved by DNS only: a filtered DNS shows in every command given a name
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{name}\n")
            self.file(m, "/etc/resolv.conf", self.resolv_conf(RESOLVER[name]))
            # the students start from an empty ruleset (Docker's embedded DNS leaves a nat table
            # in every container otherwise); the clones are loaded at each evaluation
            firewall.flush_ruleset(self, m)
            # the echo server (HTTP 80 / 8080); a clone answers with the visible name
            install_echo_server(net_scheme=self, machine=m, name=name, ports=HTTP_PORTS)
            if name in DNS_SERVERS:
                # started directly: `systemctl start unbound` would wait for unbound-anchor without Internet
                self.file(m, "/etc/unbound/unbound.conf", self.unbound_conf())
                self.cmd(m, "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")
            if name in MAIL_SERVERS:
                setup_simple_tcp_server(net_scheme=self, machine=m, port=MAIL_PORT, answer=f"220 {name}.{DOMAIN} ESMTP\r\n")
            if name in SSH_SERVERS:
                # pam_loginuid fails in a container and would refuse every ssh session
                self.cmd(m, "sed -i 's/^session\\s\\+required\\s\\+pam_loginuid.so/session optional pam_loginuid.so/' "
                            "/etc/pam.d/sshd")
                self.cmd(m, "systemctl start ssh", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the seven questions on ext1 and the router, applicable more than once."""
        for machine, commands in ((HOST, self.cmds_host()), (ROUTER, self.cmds_router())):
            self.cmd(machine, "nft flush ruleset")
            for c in commands:
                self.cmd(machine, c)
        # question 6 (h): int1 asks the DNS server of the DMZ
        self.file('int1', "/etc/resolv.conf", self.resolv_conf(DMZ_DNS))


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _is_int(answer, expected: int) -> bool:
    return _digits(answer) == str(expected)


def _same_ip(answer, expected) -> bool:
    """The address typed by a student (with or without a prefix) is *expected* (an interface or address)."""
    try:
        return ip_address(_norm(answer).split('/')[0]) == ip_address(str(expected).split('/')[0])
    except ValueError:
        return False


def _lines(commands: List[str]) -> str:
    return "\n".join(commands) + "\n"


def _blocked(verdict: str) -> bool:
    """A TCP probe that ran and did not get through (dropped or refused)."""
    return verdict in ('dropped', 'refused')


def _nameservers(resolv_conf: str) -> List[str]:
    """The addresses of the `nameserver` lines of a resolv.conf, in order."""
    servers = []
    for line in (resolv_conf or '').splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == 'nameserver':
            servers.append(words[1])
    return servers


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ext1, ext2, dmz1, dmz2, int1, int2 = (ip_of(d, m) for m in HOSTS)
        r_ext, r_dmz, r_int = (getattr(d.ips, f"{ROUTER}_{zone}") for zone in ZONES)
        host_h, router_h = clone(HOST), clone(ROUTER)
        ext2_h, dmz1_h, dmz2_h, int1_h, int2_h = (clone(m) for m in ('ext2', 'dmz1', 'dmz2', 'int1', 'int2'))
        dns_request, dns_answer = f"{DNS_NAME}.{DOMAIN} A", str(ip_of(d, DNS_NAME).ip)

        # The probes: each call registers its command, so none may sit behind an `and` / `or`.
        def dig(src, server, step) -> bool:
            out, _ = test_dig(self, src, server, request=dns_request, timeout=DIG_TIMEOUT, step=step)
            return dns_answer in out.split()

        def http(src, server, port, step, name) -> bool:
            return get_http_echo(self, src, server, port, step=step, timeout=HTTP_TIMEOUT)['server'] == name

        def tcp(src, server, port, step) -> str:
            return firewall.probe_tcp_verdict(self, src, server, port, step=step, connect_timeout=PROBE_TIMEOUT)

        def ping(src, server, step) -> bool:
            return firewall.probe_ping(self, src, server, step=step)

        # ---------------- diagnostics kept in the archive ---------------------------------
        for machine in (HOST, ROUTER):
            for c in ("nft -a list ruleset", "ss -tulnp", "ip -br address"):
                self.test(machine, c, allow_error=True)
        self.test(host_h, "nft list ruleset", step=HOST_PROBE_STEP, allow_error=True)      # the transplanted rulesets
        self.test(router_h, "nft list ruleset", step=ROUTER_PROBE_STEP, allow_error=True)
        resolv_conf, _ = self.test('int1', "cat /etc/resolv.conf", allow_error=True)

        # ---------------- the two rulesets: transplanted in turn, and read as JSON ----------
        # phase 1: ext1 filters, the clone of the router is open
        firewall.transplant_ruleset(self, src=HOST, dst=host_h, apply_step=HOST_LOAD_STEP)
        self.test(router_h, "nft flush ruleset", step=HOST_LOAD_STEP, allow_error=True)
        # phase 2: the router filters, the clone of ext1 is open
        self.test(host_h, "nft flush ruleset", step=ROUTER_LOAD_STEP, allow_error=True)
        firewall.transplant_ruleset(self, src=ROUTER, dst=router_h, apply_step=ROUTER_LOAD_STEP)
        host_rules = firewall.get_nft_json(self, HOST)
        router_rules = firewall.get_nft_json(self, ROUTER)
        router_sets = firewall.get_nft_sets(self, ROUTER)
        # the sets fed by the rules start empty on the clone: an address banned on the real router
        # while the student was testing would otherwise fail the probes of question 6
        for family, table, name in firewall.updated_sets(router_rules):
            self.test(router_h, f"nft flush set {family} {table} {name}", step=ROUTER_LOAD_STEP, allow_error=True)

        host_in = firewall.hook_rules(host_rules, 'input')
        host_out = firewall.hook_rules(host_rules, 'output')
        router_in = firewall.hook_rules(router_rules, 'input')
        forward = firewall.hook_rules(router_rules, 'forward')
        # what a firewall lets through only counts once it filters: an empty ruleset passes everything
        host_filtering = int(firewall.input_policy(host_rules) == 'drop')
        router_filtering = int(firewall.input_policy(router_rules) == 'drop')
        forward_filtering = int(firewall.hook_policy(router_rules, 'forward') == 'drop')
        dns_rules = firewall.find_rules(host_in, 'accept', saddr=ext2, l4proto='udp', ct_state='established')
        mail_rules = (firewall.find_rules(host_out, 'reject', dport=MAIL_PORT)
                      + firewall.find_rules(host_out, 'drop', dport=MAIL_PORT))
        ssh_rules = firewall.find_rules(router_in, 'accept', iif=INT_IF, saddr=int1, dport=SSH_PORT)
        ct_rules = firewall.find_rules(forward, 'accept', ct_state={'established', 'related'})
        ct_rules_partial = firewall.find_rules(forward, 'accept', ct_state='established')
        ct_index = firewall.rule_index(forward, lambda r: r in ct_rules_partial)
        # question 7: the rules of forward feeding a set with source addresses, and the drop on that set
        ban_updates = [u for r in forward for u in firewall.rule_set_updates(r)
                       if u['key'] == 'saddr' and firewall.find_rules([r], dport=SSH_PORT)]
        ban_names = {u['set'] for u in ban_updates}
        ban_timed = (any(u['timeout'] == BAN_SECONDS for u in ban_updates)
                     or any(s['timeout'] == BAN_SECONDS for key, s in router_sets.items() if key[2] in ban_names))
        ban_index = firewall.rule_index(
            forward, lambda r: firewall.rule_verdict(r) == 'drop' and any(
                lookup['key'] == 'saddr' and not lookup['negated'] and lookup['set'] in ban_names
                for lookup in firewall.rule_set_lookups(r)))

        # ---------------- phase 1: the firewall of ext1 (the clone of the router is open) ----
        step = HOST_PROBE_STEP
        lo_ok = http(host_h, '127.0.0.1', HTTP_PORT, step, HOST)
        dns_default = dig(host_h, ext2, step)
        dns_other = dig(host_h, dmz1, step)
        tcp_out_near = http(host_h, ext2, HTTP_PORT, step, 'ext2')
        tcp_out_far = http(host_h, dmz1, ALT_PORT, step, 'dmz1')
        ping_out_near = ping(host_h, ext2, step)
        ping_out_far = ping(host_h, dmz1, step)
        mail_allowed = tcp(host_h, ip_of(d, MAIL_ALLOWED), MAIL_PORT, step)
        mail_other = tcp(host_h, dmz1, MAIL_PORT, step)
        ping_in = ping(ext2_h, ext1, step)
        dns_inbound = dig(ext2_h, ext1, step)
        http_near = tcp(ext2_h, ext1, HTTP_PORT, step)
        alt_near = tcp(ext2_h, ext1, ALT_PORT, step)
        ssh_near = tcp(ext2_h, ext1, SSH_PORT, step)
        http_far = tcp(int1_h, ext1, HTTP_PORT, step)
        ssh_int1 = tcp(int1_h, ext1, SSH_PORT, step)
        ssh_int2 = tcp(int2_h, ext1, SSH_PORT, step)
        ssh_dmz = tcp(dmz1_h, ext1, SSH_PORT, step)

        # ---------------- phase 2: the firewall of the router (the clone of ext1 is open) ----
        step = ROUTER_PROBE_STEP
        r_lo = http(router_h, '127.0.0.1', HTTP_PORT, step, ROUTER)
        r_ping_out_ext = ping(router_h, ext2, step)
        r_ping_out_int = ping(router_h, int1, step)
        r_dns = dig(router_h, ip_of(d, ROUTER_DNS), step)
        r_tcp_out = http(router_h, ext2, HTTP_PORT, step, 'ext2')
        r_ping_int = ping(int1_h, r_int, step)
        r_ping_dmz = ping(dmz1_h, r_dmz, step)
        r_ping_ext = ping(ext2_h, r_ext, step)
        r_ssh_admin = tcp(int1_h, r_int, SSH_PORT, step)
        r_ssh_int2 = tcp(int2_h, r_int, SSH_PORT, step)
        r_ssh_ext = tcp(ext2_h, r_ext, SSH_PORT, step)
        r_ssh_dmz = tcp(dmz1_h, r_dmz, SSH_PORT, step)
        f_ping_int_dmz = ping(int1_h, dmz1, step)
        f_ping_int_ext = ping(int1_h, ext2, step)
        f_ping_dmz_int = ping(dmz1_h, int1, step)
        f_ping_ext_dmz = ping(ext2_h, dmz1, step)
        f_ping_ext_int = ping(host_h, int1, step)
        f_dns_out = dig(int1_h, ip_of(d, INT_DNS), step)
        f_dns_other = dig(int1_h, ext1, step)
        f_http_out = http(int2_h, ext2, HTTP_PORT, step, 'ext2')
        f_alt_out = tcp(int1_h, ext2, ALT_PORT, step)
        f_ext_to_int = tcp(host_h, int1, HTTP_PORT, step)
        f_web_ext = tcp(ext2_h, ip_of(d, DMZ_WEB), HTTP_PORT, step)
        f_web_int = tcp(int1_h, ip_of(d, DMZ_WEB), HTTP_PORT, step)
        f_web_alt = tcp(ext2_h, ip_of(d, DMZ_WEB), ALT_PORT, step)
        f_dmz_other = tcp(host_h, dmz2, HTTP_PORT, step)
        f_dmz_dns_out = dig(dmz2_h, ext2, step)
        f_dmz_dns_other = dig(dmz1_h, ext2, step)
        f_int_dns_dmz = dig(int1_h, ip_of(d, DMZ_DNS), step)
        ban_before = http(int2_h, ext1, HTTP_PORT, step, HOST)
        # question 7: ext1 tries SSH towards the internal network, then int2 asks ext1 and ext2 again
        firewall.probe_tcp_verdict(self, host_h, int2, SSH_PORT, step=TRAP_STEP, connect_timeout=2)
        ban_after = http(int2_h, ext1, HTTP_PORT, BAN_STEP, HOST)
        ban_spared = http(int2_h, ext2, HTTP_PORT, BAN_STEP, 'ext2')

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| zone | réseau | interface de `router` | machines |
|------|--------|-----------------------|----------|
| **extérieur** (`ext`) | `{net_ext}` | `eth0` : `{r_ext}` | **`ext1`** (`{ext1}`), `ext2` (`{ext2}`) |
| **DMZ** (`dmz`) | `{net_dmz}` | `eth1` : `{r_dmz}` | `dmz1` (`{dmz1}`), `dmz2` (`{dmz2}`) |
| **interne** (`int`) | `{net_int}` | `eth2` : `{r_int}` | `int1` (`{int1}`), `int2` (`{int2}`) |
""").format(net_ext=d.nets.ext, net_dmz=d.nets.dmz, net_int=d.nets.int, r_ext=r_ext.ip, r_dmz=r_dmz.ip, r_int=r_int.ip,
            ext1=ext1.ip, ext2=ext2.ip, dmz1=dmz1.ip, dmz2=dmz2.ip, int1=int1.ip, int2=int2.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les zones d'un réseau, les trois chaînes de filtrage
(`input`, `output`, `forward`), le suivi de connexion, la façon d'écrire la politique d'un
routeur, les ensembles et les outils de test.

**La maquette** (onglet *Schéma*) : le routeur `router` relie trois zones. Vous écrivez deux
pare-feux : celui de la machine **`ext1`** (questions 2 à 4), puis celui de **`router`**
(questions 5 à 7). Les autres machines servent de clients et de serveurs pour vos tests.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses, la route par défaut de chaque machine vers
`router`, le routage sur `router`. Les services :

- sur **toutes** les machines, un **serveur web de test** sur les ports TCP **80** et **8080**
  (`curl http://dmz1/`, `curl http://dmz1:8080/`) : il répond par son nom, l'adresse du client tel
  qu'il le voit et le TTL du paquet reçu (section @@ref:testing@@ des Informations) ;
- sur `ext1`, `ext2`, `dmz1` et `dmz2`, un **serveur DNS** (UDP 53) qui connaît les noms
  `ext1.lab`, `ext2.lab`, `dmz1.lab`, `dmz2.lab`, `int1.lab`, `int2.lab` et `router-ext.lab`,
  `router-dmz.lab`, `router-int.lab` ;
- sur `ext1` et `router`, un **serveur SSH** (port 22 ; compte `root`, mot de passe `root`) ;
- sur `ext2`, `dmz1` et `dmz2`, un **faux serveur de courrier** sur le port TCP 25 : il envoie
  une bannière `220 …` puis ferme la connexion (`nc -v -w 3 ext2 25`).

**Les noms passent par le DNS** : `/etc/hosts` ne connaît que la machine elle-même, et
`/etc/resolv.conf` désigne le serveur DNS de chaque machine : `ext2` pour `ext1`, `int1` et
`int2` ; `dmz1` pour `router` ; eux-mêmes pour `ext2`, `dmz1` et `dmz2`. Quand un pare-feu bloque
le DNS, toute commande qui utilise un nom échoue (`Could not resolve host`) : c'est voulu. En cas
de doute, testez avec les adresses du tableau.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place : l'évaluation vérifie le jeu de règles **final** de `ext1` et de `router` (sur
  chacune, une seule table, `inet filter`) ;
- les règles sont volatiles (`nft`) : elles ne survivent pas à un redémarrage. Écrire le
  pare-feu dans un fichier rechargé par `nft -f` (section @@ref:ruleset@@) évite bien des erreurs
  d'ordre ;
- l'évaluation lit le jeu de règles de `ext1` et de `router` (`nft list ruleset`) et le **recopie
  sur des machines cachées identiques**, qu'elle sonde depuis des copies cachées des autres
  machines : seuls comptent **les jeux de règles chargés** (et, à la question 6, le fichier
  `/etc/resolv.conf` de `int1`), pas l'état des serveurs ni ce que vous faites sur les autres
  machines ;
- pour tester sans attendre, utilisez des délais courts : `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `dig … +time=1 +tries=1`, `nc -v -w 3 …`.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) vide les jeux de règles de `ext1` et
de `router`, applique toute la solution, fait de `dmz2` le serveur DNS de `int1` et remplit les
formulaires ; il est ré-applicable et une évaluation lancée juste après donne 100/100, plus les
points de bonus de la question 7.

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) se fait en deux temps, parce
que les deux pare-feux se masqueraient l'un l'autre (après la question 6, `router` ne laisse plus
passer le SSH de `int1` vers `ext1`) :

1. étape 1 : `nft list ruleset` et `nft -j list ruleset` sur `ext1` et `router` ;
2. étapes {load1} et {probe1} : le jeu de règles de `ext1` est chargé sur `{host_h}`, celui de
   `{router_h}` est vidé (routeur ouvert), puis les sondes des questions 2 à 4 ;
3. étapes {load2} et {probe2} : `{host_h}` est vidée, le jeu de règles de `router` est chargé sur
   `{router_h}`, puis les sondes des questions 5 et 6 ;
4. étapes {trap} et {ban} : la question 7 (une tentative SSH de `{host_h}` vers `int2`, puis HTTP
   de `int2` vers `ext1` et `ext2`).

Les sondes : `curl` des serveurs de test, `dig +time=2 +tries=1` (`{name}.{domain}`), `ping -c 1
-W 2`, connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert, `RC=124` détruit,
autre code refusé). Les copies cachées répondent sous les noms visibles. La structure (politiques,
règle à états, ensemble) est lue dans `nft -j list ruleset`. Ce qu'un pare-feu **laisse passer** ne
compte qu'une fois sa politique `drop` en place : un jeu de règles vide laisse tout passer et vaut 0.
Une évaluation dure environ 25 secondes quand tout est en place (les sondes que les pare-feux
doivent détruire attendent leur délai), une ou deux secondes sans pare-feu.
""").format(load1=HOST_LOAD_STEP, probe1=HOST_PROBE_STEP, load2=ROUTER_LOAD_STEP, probe2=ROUTER_PROBE_STEP,
            trap=TRAP_STEP, ban=BAN_STEP, host_h=host_h, router_h=router_h, name=DNS_NAME, domain=DOMAIN,
            timeout=PROBE_TIMEOUT)),
        )

        # =====================================================================
        # Part 1 — before the firewalls (question 1)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Avant les pare-feux (question 1)"))

        q1_answers = {"ttl": "63", "client_ip": str(int1.ip), "resolver": str(ext2.ip), "ruleset": "empty"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Tests avant les pare-feux"),
            description=tr("""
Avant d'installer quoi que ce soit, vérifiez rapidement que :

- il n'y a aucun pare-feu sur `router` ni sur `ext1` (`nft list ruleset`) ;
- les machines se joignent d'une zone à l'autre (`ping -c 2 dmz1` depuis `int1`, `ping -c 2 int2`
  depuis `ext1`…) ;
- depuis `int1`, `int2` et `router`, le serveur web de `dmz1` répond sur ses deux ports
  (`curl http://dmz1/`, `curl http://dmz1:{alt}/`, ou par son adresse `{dmz1}`) ;
- depuis `int1`, `int2` et `router`, les serveurs DNS de `dmz1` et `dmz2` répondent
  (`dig @{dmz1} ext1.lab`, `dig @{dmz2} ext1.lab +short`) ;
- chaque machine a son serveur DNS par défaut (`cat /etc/resolv.conf`).

Lisez les lignes `TTL=` et `CLIENT_IP=` des réponses des serveurs web.
""").format(alt=ALT_PORT, dmz1=dmz1.ip, dmz2=dmz2.ip)
            + tr("""
- `TTL=` dans la réponse de `dmz1` à `int1` : @@{ttl:[0-9]+}@@
- `CLIENT_IP=` dans la réponse de `ext2` à `int1` (`curl http://ext2/`) : @@{client_ip:[0-9.]+}@@
- adresse du serveur DNS par défaut de `ext1` : @@{resolver:[0-9.]+}@@
- `nft list ruleset` sur `router` affiche : @@{ruleset:>rien : aucune table ni règle, tout est accepté>>>empty|une table filter dont les chaînes ont la politique drop>>>drop|les règles installées par Docker>>>docker|une erreur : nft n'est pas installé>>>error}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer. `TTL=63` : la requête de `int1` a traversé un routeur.
`CLIENT_IP={int1}` : `router` route sans traduction d'adresses, `ext2` voit l'adresse réelle de
`int1`. `/etc/resolv.conf` de `ext1` nomme `{ext2}` (`ext2`). `nft list ruleset` n'affiche rien :
aucun filtrage, tout passe.

- Réponses : 63 ; `{int1}` ; `{ext2}` ; rien.
- Cette question n'est évaluée que par le formulaire.
""").format(int1=int1.ip, ext2=ext2.ip)),
            cheat_answers={"final": q1_answers},
        )

        self.add_grade_element(
            title=no_tr("q_before"), max_grade=5, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is_int(q1.get("ttl"), 63)) + int(_same_ip(q1.get("client_ip"), int1))
                  + 2 * int(_same_ip(q1.get("resolver"), ext2)) + int(_norm(q1.get("ruleset")) == "empty"),
            description=tr("avant les pare-feux : TTL à travers le routeur (63), CLIENT_IP vu par ext2, "
                           "serveur DNS de ext1, jeu de règles vide"),
        )

        # =====================================================================
        # Part 2 — ext1, a client: the input chain (question 2)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Pare-feu d'un poste client (question 2)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Pare-feu d'un poste client : les paquets entrants"),
            description=tr("""
Sur **`ext1`**, créez une table `inet filter` et sa chaîne de base **`input`** (section
@@ref:ruleset@@ des Informations), de telle sorte que :

**(a)** les paquets entrants soient détruits par défaut (politique `drop`) ;

**(b)** tout ce qui arrive par l'interface `lo` soit accepté ;

**(c)** `ext1` puisse interroger **son serveur DNS par défaut**, celui de `/etc/resolv.conf`
(`ext2`, `{ext2}`), et lui seul : n'acceptez que les **réponses** UDP de ce serveur, en combinant
l'adresse source, le port source 53 et l'état de la connexion (section @@ref:conntrack@@). Les
réponses d'un autre serveur DNS (`dig @{dmz1} ext1.lab +time=1 +tries=1`) doivent rester bloquées,
et `ext2` ne doit pas pouvoir interroger le serveur DNS de `ext1` ;

**(d)** `ext1` puisse ouvrir des connexions TCP vers n'importe quelle machine (HTTP par exemple) :
n'acceptez que le trafic retour de ces connexions ;

**(e)** `ext1` réponde aux `ping` venus des autres machines et puisse elle-même en émettre.

Testez après chaque règle : `nft list ruleset`, puis depuis `ext1` `curl -m 3 http://ext2/`,
`curl -m 3 http://dmz1:8080/`, `ping -c 2 -W 1 dmz1` ; depuis `ext2`, `ping -c 2 -W 1 ext1`
(accepté) et `curl -m 3 http://ext1/` (bloqué : aucun service n'est encore ouvert). Tant que (c)
n'est pas faite, les noms ne sont plus résolus sur `ext1` : pourquoi ?
""").format(ext2=ext2.ip, dmz1=dmz1.ip)
            + instructor(tr("""
**Solution.** Sur `ext1` :

```
{cmds}```

Après (a), plus rien n'entre, pas même les réponses DNS : `curl http://ext2/` échoue sur `Could not
resolve host` (avec l'adresse, c'est la connexion TCP qui expire). (c) `udp sport 53` et `ip saddr`
désignent le serveur, `ct state established` n'accepte que les réponses à une question posée par
`ext1` : sans ce critère, `ext2` pourrait envoyer n'importe quel datagramme depuis son port 53.
(d) `meta l4proto tcp ct state established,related` : le SYN-ACK et la suite de toute connexion
ouverte par `ext1`. (e) deux types ICMP dans un ensemble anonyme (deux règles conviennent aussi).
Une règle générale `ct state established,related accept` satisferait (d) et les réponses de (e),
mais pas (c) : elle accepterait les réponses de n'importe quel serveur DNS.

- L'évaluation, sur la copie cachée de `ext1` : `curl http://127.0.0.1/`, `dig @{ext2}` (réponse)
  et `dig @{dmz1}` (aucune réponse), HTTP vers `ext2` et vers `dmz1:8080` (à travers le routeur),
  `ping` vers `ext2` et `dmz1` ; depuis la copie de `ext2` : `ping` de `ext1` (réponse), `dig
  @{ext1}` (aucune réponse). Dans `nft -j list ruleset` : la politique `drop` de `input` et une
  règle `accept` avec `ip saddr {ext2}`, UDP et `ct state established`.
""").format(cmds=_lines(self.net_scheme.cmds_host_input()), ext1=ext1.ip, ext2=ext2.ip, dmz1=dmz1.ip)),
        )

        self.add_grade_element(
            title=no_tr("host_policy_drop"), max_grade=3, grade_part=part2,
            grade=3 * host_filtering,
            description=tr("ext1 : une chaîne de base du hook input avec la politique drop"),
        )
        self.add_grade_element(
            title=no_tr("host_loopback"), max_grade=2, grade_part=part2,
            grade=2 * host_filtering * int(lo_ok),
            description=tr("ext1 : curl http://127.0.0.1/ répond (interface lo acceptée)"),
        )
        self.add_grade_element(
            title=no_tr("host_dns_default"), max_grade=4, grade_part=part2,
            grade=4 * host_filtering * int(dns_default),
            description=tr("ext1 obtient les réponses de son serveur DNS par défaut (ext2)"),
        )
        self.add_grade_element(
            title=no_tr("host_dns_restricted"), max_grade=3, grade_part=part2,
            grade=int(not dns_other) + int(not dns_inbound) + int(bool(dns_rules)),
            description=tr("ext1 : pas de réponse d'un autre serveur DNS, ext2 n'interroge pas le DNS de ext1, "
                           "règle sur l'adresse du serveur, UDP et ct state established"),
        )
        self.add_grade_element(
            title=no_tr("host_tcp_out"), max_grade=4, grade_part=part2,
            grade=host_filtering * (2 * int(tcp_out_near) + 2 * int(tcp_out_far)),
            description=tr("ext1 ouvre des connexions TCP (HTTP vers ext2, et vers dmz1 à travers le routeur)"),
        )
        self.add_grade_element(
            title=no_tr("host_ping"), max_grade=4, grade_part=part2,
            grade=host_filtering * (2 * int(ping_in) + int(ping_out_near) + int(ping_out_far)),
            description=tr("ext1 répond aux ping de ext2 et pingue ext2 et dmz1"),
        )

        # =====================================================================
        # Part 3 — ext1, a server (question 3)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Pare-feu d'un serveur (question 3)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Pare-feu d'un serveur : ouvrir des services"),
            description=tr("""
`ext1` est aussi un serveur. Complétez sa chaîne `input` :

**(a)** le serveur web du port **{http}** doit être accessible depuis **toutes** les machines
(celui du port {alt} reste fermé) ;

**(b)** le serveur SSH (port {ssh}) doit être accessible depuis les machines du **réseau interne**
(`{net_int}`) et d'elles seules.

Testez : `curl -m 3 http://ext1/` depuis `ext2` et `int1` (réponse), `curl -m 3 http://ext1:{alt}/`
(délai) ; `nc -v -w 3 ext1 {ssh}` ou `ssh root@ext1` depuis `int1` (la bannière `SSH-2.0-…` ou
l'invite du mot de passe), puis depuis `ext2` et `dmz1` (délai).
""").format(http=HTTP_PORT, alt=ALT_PORT, ssh=SSH_PORT, net_int=d.nets.int)
            + instructor(tr("""
**Solution.** Sur `ext1` :

```
{cmds}```

Les nouvelles connexions vers le port {http} sont acceptées d'où qu'elles viennent ; le port {ssh}
n'est ouvert qu'aux adresses source du réseau interne (`ip saddr` prend une adresse ou un réseau).
`ext1` ne voit que l'adresse source, qu'une machine de son propre réseau peut falsifier ; sur le
routeur, on exigera aussi l'interface d'entrée (question 5).

- L'évaluation ouvre des connexions TCP vers la copie de `ext1` : port {http} depuis `ext2` et
  `int1` (ouvert), port {alt} depuis `ext2` (détruit), port {ssh} depuis `int1` et `int2` (ouvert),
  depuis `ext2` et `dmz1` (détruit). Pendant ces sondes, la copie du routeur n'a aucun pare-feu.
""").format(cmds=_lines(self.net_scheme.cmds_host_server()), http=HTTP_PORT, alt=ALT_PORT, ssh=SSH_PORT)),
        )

        self.add_grade_element(
            title=no_tr("host_http_open"), max_grade=4, grade_part=part3,
            grade=host_filtering * (2 * int(http_near == 'open') + 2 * int(http_far == 'open')),
            description=tr("le port 80 de ext1 est ouvert à ext2 et à int1"),
        )
        self.add_grade_element(
            title=no_tr("host_alt_closed"), max_grade=2, grade_part=part3,
            grade=2 * int(_blocked(alt_near)),
            description=tr("le port 8080 de ext1 reste fermé"),
        )
        self.add_grade_element(
            title=no_tr("host_ssh_internal"), max_grade=3, grade_part=part3,
            grade=host_filtering * (2 * int(ssh_int1 == 'open') + int(ssh_int2 == 'open')),
            description=tr("le port 22 de ext1 est ouvert à int1 et int2"),
        )
        self.add_grade_element(
            title=no_tr("host_ssh_others"), max_grade=3, grade_part=part3,
            grade=2 * int(_blocked(ssh_near)) + int(_blocked(ssh_dmz)),
            description=tr("le port 22 de ext1 est fermé à ext2 et à dmz1"),
        )

        # =====================================================================
        # Part 4 — ext1: the output chain (question 4)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — La chaîne output (question 4)"))

        q4_answers = {"with_drop": "timeout", "with_reject": "refused"}
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Filtrer ce qui sort : la chaîne output"),
            description=tr("""
On veut contrôler le courrier **émis** par `ext1` (port TCP {mail}). Un faux serveur de courrier
écoute sur `ext2`, `dmz1` et `dmz2` : `nc -v -w 5 ext2 {mail}` affiche sa bannière `220 …`.

**(a)** Ajoutez à la table de `ext1` une chaîne de base **`output`** (politique `accept`) et une
règle qui **détruit** les paquets TCP sortant vers le port {mail}. Testez avec `nc -v -w 5 ext2
{mail}` et `nc -v -w 5 dmz1 {mail}` : que voit le programme ?

**(b)** Remplacez `drop` par **`reject`** dans cette règle (`nft -a list ruleset` puis `nft replace
rule …`, ou videz la chaîne) et refaites les tests (section @@ref:verdicts@@ des Informations).

**(c)** Autorisez à présent les connexions vers le port {mail} de **`ext2`** (`{ext2}`) et d'elle
seule ; les autres restent refusées par `reject`. Attention à l'ordre des règles.
""").format(mail=MAIL_PORT, ext2=ext2.ip)
            + tr("""
- avec `drop`, `nc -v -w 5 dmz1 25` : @@{with_drop:>attend puis abandonne au bout du délai : le SYN est détruit avant de quitter ext1, rien ne revient>>>timeout|échoue immédiatement, « Connection refused »>>>refused|affiche la bannière 220>>>works}@@
- avec `reject`, `nc -v -w 5 dmz1 25` : @@{with_reject:>échoue immédiatement, « Connection refused » : le noyau prévient le programme>>>refused|attend puis abandonne au bout du délai>>>timeout|affiche la bannière 220>>>works}@@
""")
            + instructor(tr("""
**Solution.** (a) puis (b), sur `ext1` :

```
{chain}
nft add rule inet filter output tcp dport {mail} drop
nft flush chain inet filter output
nft add rule inet filter output tcp dport {mail} reject
```

Avec `drop`, le SYN est détruit avant de quitter `ext1` : `nc` attend ses 5 secondes (`timed out:
Operation now in progress`). Avec `reject`, le noyau fabrique un message ICMP *port unreachable*
pour le programme, qui échoue aussitôt (`Connection refused`) ; ce message revient par `lo`, que
la règle `iif lo accept` de `input` laisse passer (sans elle, `nc` attendrait comme avec `drop`).
(c) l'exception doit précéder le refus ; après `nft flush chain inet filter output`, la chaîne
devient :

```
{cmds}```

(une seule règle `ip daddr != {ext2} tcp dport {mail} reject` convient aussi.)

- Réponses : délai avec `drop` ; refus immédiat avec `reject`.
- L'évaluation, depuis la copie de `ext1` : connexion TCP vers le port {mail} de `ext2` (ouverte)
  et de `dmz1` (refusée immédiatement ; un simple délai, c'est-à-dire un `drop`, ne donne qu'une
  partie des points), et une règle `reject` ou `drop` sur `tcp dport {mail}` dans une chaîne du
  hook `output`.
""").format(chain=self.net_scheme.cmds_host_output()[0], cmds=_lines(self.net_scheme.cmds_host_output()[1:]),
            mail=MAIL_PORT, ext2=ext2.ip)),
            cheat_answers={"final": q4_answers},
        )

        self.add_grade_element(
            title=no_tr("out_mail_allowed"), max_grade=3, grade_part=part4,
            grade=3 * int(mail_allowed == 'open') * int(_blocked(mail_other)),
            description=tr("ext1 joint le port 25 de ext2, et de ext2 seulement"),
        )
        self.add_grade_element(
            title=no_tr("out_mail_blocked"), max_grade=3, grade_part=part4,
            grade=3 * int(_blocked(mail_other)),
            description=tr("ext1 ne joint pas le port 25 de dmz1"),
        )
        self.add_grade_element(
            title=no_tr("out_mail_reject"), max_grade=3, grade_part=part4,
            grade=3 * int(mail_other == 'refused'),
            description=tr("le refus est immédiat (reject, pas drop)"),
        )
        self.add_grade_element(
            title=no_tr("out_rule"), max_grade=2, grade_part=part4,
            grade=2 * int(bool(mail_rules)),
            description=tr("ext1 : une règle reject ou drop sur tcp dport 25 dans une chaîne du hook output"),
        )
        self.add_grade_element(
            title=no_tr("q_output"), max_grade=2, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q4.get("with_drop")) == "timeout") + int(_norm(q4.get("with_reject")) == "refused"),
            description=tr("drop ou reject dans output : ce que voit le programme"),
        )

        # =====================================================================
        # Part 5 — the router itself: its input chain (question 5)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Protection du routeur (question 5)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Protéger le routeur lui-même"),
            description=tr("""
On passe à **`router`**. Créez-y une table `inet filter` et sa chaîne de base **`input`**, qui
filtre les paquets destinés au routeur lui-même (section @@ref:hooks@@ des Informations), de telle
sorte que :

**(a)** les paquets entrants soient détruits par défaut ;

**(b)** tout ce qui arrive par `lo` soit accepté ;

**(c)** `router` réponde aux `ping` venus de la zone interne et de la DMZ, mais **pas** de
l'extérieur (critère sur l'interface d'entrée) ;

**(d)** `router` puisse pinguer toutes les autres machines ;

**(e)** `router` puisse interroger le serveur DNS de `dmz1` (`{dmz1}`, son serveur par défaut) et
ouvrir des connexions TCP vers les machines de l'extérieur ;

**(f)** on puisse ouvrir une connexion SSH sur `router` **uniquement depuis `int1`** (`{int1}`) :
exigez à la fois l'interface d'entrée et l'adresse source (section @@ref:selectors@@).

Testez chaque point, et son contraire : `ping -c 2 -W 1 {r_int}` depuis `int1`, `ping -c 2 -W 1
{r_ext}` depuis `ext2` ; `nc -v -w 3 {r_int} 22` depuis `int1` puis `int2`. Vérifiez aussi que ces
règles ne changent rien à ce qui **traverse** le routeur : `curl -m 3 http://ext2/` depuis `int1`
fonctionne toujours.
""").format(dmz1=dmz1.ip, int1=int1.ip, r_int=r_int.ip, r_ext=r_ext.ip)
            + instructor(tr("""
**Solution.** Sur `router` :

```
{cmds}```

(c) `iifname {{ eth1, eth2 }}` : les `echo-request` ne sont acceptés que s'ils arrivent par la DMZ
ou la zone interne ; ceux de l'extérieur tombent sur la politique. (d) les `echo-reply` sont
acceptés d'où qu'ils viennent. (e) les réponses DNS de `dmz1` seulement, et le trafic retour TCP
arrivant par `eth0`. (f) `iifname eth2 ip saddr {int1}` : une machine de l'extérieur qui usurperait
l'adresse de `int1` arriverait par `eth0`. Une seule règle `ct state established,related accept`
remplacerait les règles de (d) et (e) : c'est l'usage sur un vrai pare-feu, et elle est acceptée
ici. Ces règles ne concernent que les paquets destinés à `router` : ce qui le traverse passe par
`forward`, encore ouverte.

- L'évaluation, sur la copie cachée de `router` (chargée après les sondes de `ext1`) : `curl
  http://127.0.0.1/`, `ping` vers `ext2` et `int1`, `dig @{dmz1}`, HTTP vers `ext2` ; `ping` du
  routeur depuis `int1` et `dmz1` (réponse), depuis `ext2` (aucune) ; port 22 depuis `int1`
  (ouvert), depuis `int2`, `ext2` et `dmz1` (détruit). Dans `nft -j list ruleset` : la politique
  `drop` de `input` et une règle `accept` avec l'interface `eth2`, `ip saddr {int1}` et `tcp dport
  22`.
""").format(cmds=_lines(self.net_scheme.cmds_router_input()), dmz1=dmz1.ip, int1=int1.ip)),
        )

        self.add_grade_element(
            title=no_tr("router_policy_drop"), max_grade=3, grade_part=part5,
            grade=3 * router_filtering,
            description=tr("router : une chaîne de base du hook input avec la politique drop"),
        )
        self.add_grade_element(
            title=no_tr("router_loopback"), max_grade=1, grade_part=part5,
            grade=router_filtering * int(r_lo),
            description=tr("router : curl http://127.0.0.1/ répond (interface lo acceptée)"),
        )
        self.add_grade_element(
            title=no_tr("router_ping_inside"), max_grade=4, grade_part=part5,
            grade=router_filtering * (2 * int(r_ping_int) + 2 * int(r_ping_dmz)),
            description=tr("router répond aux ping de la zone interne et de la DMZ"),
        )
        self.add_grade_element(
            title=no_tr("router_ping_outside"), max_grade=2, grade_part=part5,
            grade=2 * int(not r_ping_ext),
            description=tr("router ne répond pas aux ping de l'extérieur"),
        )
        self.add_grade_element(
            title=no_tr("router_ping_out"), max_grade=2, grade_part=part5,
            grade=router_filtering * (int(r_ping_out_ext) + int(r_ping_out_int)),
            description=tr("router pingue ext2 et int1"),
        )
        self.add_grade_element(
            title=no_tr("router_dns"), max_grade=2, grade_part=part5,
            grade=2 * router_filtering * int(r_dns),
            description=tr("router obtient les réponses du serveur DNS de dmz1"),
        )
        self.add_grade_element(
            title=no_tr("router_tcp_out"), max_grade=2, grade_part=part5,
            grade=2 * router_filtering * int(r_tcp_out),
            description=tr("router ouvre des connexions TCP vers l'extérieur (HTTP vers ext2)"),
        )
        self.add_grade_element(
            title=no_tr("router_ssh_admin"), max_grade=2, grade_part=part5,
            grade=2 * router_filtering * int(r_ssh_admin == 'open'),
            description=tr("le port 22 de router est ouvert à int1"),
        )
        self.add_grade_element(
            title=no_tr("router_ssh_others"), max_grade=2, grade_part=part5,
            grade=int(_blocked(r_ssh_int2) and _blocked(r_ssh_ext) and _blocked(r_ssh_dmz)) + int(bool(ssh_rules)),
            description=tr("le port 22 de router est fermé à int2, ext2 et dmz1 ; la règle exige l'interface "
                           "eth2 et l'adresse de int1"),
        )

        # =====================================================================
        # Part 6 — the router: its forward chain (question 6)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Pare-feu du routeur (question 6)"))

        q6_answers = {"stateless_hole": "any_port", "reply_state": "established"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Le pare-feu du routeur : filtrer ce qui le traverse"),
            description=tr("""
Il reste à filtrer les paquets qui **traversent** `router`, d'une zone à l'autre : c'est le rôle
de la chaîne **`forward`** (section @@ref:forward@@ des Informations).

**(a)** Vérifiez que les machines des trois zones se joignent encore (`ping`, `curl`).

**(b)** Ajoutez à la table de `router` une chaîne de base `forward` de politique **`drop`** et
vérifiez que plus rien ne traverse le routeur, alors que `router` lui-même joint toujours ses
voisins.

**(c)** Autorisez les machines de la zone interne à pinguer celles de la DMZ, mais pas celles de
l'extérieur. Les machines de la DMZ et de l'extérieur ne doivent pouvoir pinguer personne à travers
le routeur.

**(d)** Autorisez les machines de la zone interne à interroger **leur serveur DNS par défaut**
(`ext2`, `{ext2}`, en UDP), et lui seul à l'extérieur, et à ouvrir des connexions **HTTP** (port
TCP {http}, pas {alt}) vers les machines de l'extérieur.

**(e)** Seules les communications **ouvertes par la zone interne** doivent traverser le routeur
vers elle. Si vous avez laissé revenir les réponses par des règles sans état (`icmp type
echo-reply`, `udp sport 53`, `tcp sport {http}`), remplacez-les par une seule règle à états, en
tête de chaîne (section @@ref:conntrack@@).

**(f)** Autorisez les machines de l'extérieur **et** de la zone interne à interroger le serveur
web de **`dmz1`** (`{dmz1}`) sur le port {http}, et rien d'autre dans la DMZ.

**(g)** Autorisez **`dmz2`** (`{dmz2}`), et elle seule dans la DMZ, à interroger en UDP les
serveurs DNS de l'extérieur.

**(h)** Autorisez les machines de la zone interne à interroger en UDP le serveur DNS de `dmz2`,
puis faites de `dmz2` le serveur DNS par défaut de **`int1`** (`/etc/resolv.conf`) et testez.

Après chaque point, testez ce qui doit passer **et** ce qui doit rester bloqué (un autre port, un
autre serveur, l'autre sens). `tcpdump` sur `router` et des `counter` sur les règles disent où un
paquet s'arrête (section @@ref:testing@@).
""").format(ext2=ext2.ip, dmz1=dmz1.ip, dmz2=dmz2.ip, http=HTTP_PORT, alt=ALT_PORT)
            + tr("""
- pour laisser revenir les réponses HTTP sans suivi de connexion, on écrirait `iifname eth0 oifname eth2 tcp sport 80 accept`. Que permet cette règle à une machine de l'extérieur ? @@{stateless_hole:>d'ouvrir une connexion vers n'importe quel port TCP d'une machine interne, pourvu qu'elle utilise 80 comme port source>>>any_port|rien de plus : seules les réponses à une requête interne ont 80 pour port source>>>nothing|d'interroger le port 80 des machines internes, et lui seul>>>port_80|de traverser le routeur dans les deux sens, sur tous les ports>>>everything}@@
- `ping dmz1` fonctionne depuis `int1`, mais `ping int1` échoue depuis `dmz1`. Quel paquet de `dmz1` la règle à états laisse-t-elle passer vers `int1` ? @@{reply_state:>son echo-reply : il appartient à un échange ouvert par int1 (established)>>>established|son echo-request : il est dans l'état new>>>new|tous ses paquets ICMP : ICMP n'a pas d'état>>>all_icmp|aucun : la réponse passe par la chaîne input>>>none}@@
""")
            + instructor(tr("""
**Solution.** Sur `router` :

```
{cmds}```

(b) la politique `drop` de `forward` coupe tout transit ; `router` joint toujours ses voisins, ses
propres paquets passant par `output` et `input`. (c) seul l'`echo-request` de la zone interne vers
la DMZ est autorisé ; son `echo-reply` revient par la règle à états. (d) le DNS vers `ext2`
seulement, HTTP vers tout l'extérieur sur le port {http}. (e) la règle `ct state
established,related accept`, première de la chaîne, laisse revenir les réponses de tous les flux
autorisés, et elles seules. (f) `iifname {{ eth0, eth2 }}` : `dmz2` est sur le même réseau que
`dmz1` et ne traverse pas le routeur. (g) et (h) : deux règles DNS, l'une par l'adresse source de
`dmz2`, l'autre par son adresse destination. Sur `int1`, `/etc/resolv.conf` devient :

```
{resolv}```

- Réponses : une connexion vers n'importe quel port interne depuis le port source 80 ;
  l'`echo-reply`, `established`.
- L'évaluation, sur les copies cachées (celle de `ext1` n'a plus de pare-feu) : `ping` de `int1`
  vers `dmz1` (réponse) et vers `ext2` (aucune), de `dmz1` vers `int1`, de `ext2` vers `dmz1`, de
  `ext1` vers `int1` (aucune) ; `dig @{ext2}` depuis `int1` (réponse), `dig @{ext1}` depuis `int1`
  (aucune) ; HTTP de `int2` vers `ext2` (réponse), port {alt} de `ext2` depuis `int1` et port
  {http} de `int1` depuis `ext1` (détruits) ; port {http} de `dmz1` depuis `ext2` et `int1`
  (ouvert), port {alt} de `dmz1` et port {http} de `dmz2` depuis l'extérieur (détruits) ; `dig
  @{ext2}` depuis `dmz2` (réponse) et depuis `dmz1` (aucune) ; `dig @{dmz2}` depuis `int1`
  (réponse). Sur `int1`, le premier `nameserver` de `/etc/resolv.conf` doit être `{dmz2}`. Dans
  `nft -j list ruleset` : la politique `drop` de `forward` et une règle `accept` avec `ct state
  established,related`.
""").format(cmds=_lines(self.net_scheme.cmds_router_forward()), resolv=self.net_scheme.resolv_conf(DMZ_DNS),
            ext1=ext1.ip, ext2=ext2.ip, dmz2=dmz2.ip, http=HTTP_PORT, alt=ALT_PORT)),
            cheat_answers={"final": q6_answers},
        )

        self.add_grade_element(
            title=no_tr("forward_policy_drop"), max_grade=2, grade_part=part6,
            grade=2 * forward_filtering,
            description=tr("router : une chaîne de base du hook forward avec la politique drop"),
        )
        self.add_grade_element(
            title=no_tr("forward_established"), max_grade=2, grade_part=part6,
            grade=2 if ct_rules else int(bool(ct_rules_partial)),
            description=tr("forward : une règle accept avec ct state established,related"),
        )
        self.add_grade_element(
            title=no_tr("forward_ping_dmz"), max_grade=3, grade_part=part6,
            grade=3 * forward_filtering * int(f_ping_int_dmz),
            description=tr("int1 pingue dmz1 à travers le routeur"),
        )
        self.add_grade_element(
            title=no_tr("forward_ping_blocked"), max_grade=3, grade_part=part6,
            grade=int(not f_ping_int_ext) + int(not f_ping_dmz_int) + int(not f_ping_ext_dmz and not f_ping_ext_int),
            description=tr("pas de ping de int1 vers ext2, de dmz1 vers int1, de l'extérieur vers la DMZ et la zone interne"),
        )
        self.add_grade_element(
            title=no_tr("forward_dns_out"), max_grade=3, grade_part=part6,
            grade=3 * forward_filtering * int(f_dns_out),
            description=tr("int1 interroge son serveur DNS par défaut (ext2)"),
        )
        self.add_grade_element(
            title=no_tr("forward_http_out"), max_grade=3, grade_part=part6,
            grade=3 * forward_filtering * int(f_http_out),
            description=tr("int2 interroge le serveur web de ext2 (port 80)"),
        )
        self.add_grade_element(
            title=no_tr("forward_initiated_only"), max_grade=3, grade_part=part6,
            grade=int(_blocked(f_ext_to_int)) + int(_blocked(f_alt_out)) + int(not f_dns_other),
            description=tr("rien n'entre dans la zone interne depuis l'extérieur ; vers l'extérieur, ni le port 8080 "
                           "ni un autre serveur DNS que ext2"),
        )
        self.add_grade_element(
            title=no_tr("forward_dmz_web"), max_grade=3, grade_part=part6,
            grade=forward_filtering * (2 * int(f_web_ext == 'open') + int(f_web_int == 'open')),
            description=tr("le port 80 de dmz1 est ouvert à l'extérieur (ext2) et à la zone interne (int1)"),
        )
        self.add_grade_element(
            title=no_tr("forward_dmz_closed"), max_grade=2, grade_part=part6,
            grade=int(_blocked(f_web_alt) and _blocked(f_dmz_other)) + int(not f_dmz_dns_other),
            description=tr("le port 8080 de dmz1 et le port 80 de dmz2 sont fermés à l'extérieur ; dmz1 n'interroge pas "
                           "les serveurs DNS de l'extérieur"),
        )
        self.add_grade_element(
            title=no_tr("forward_dmz_dns_out"), max_grade=2, grade_part=part6,
            grade=2 * forward_filtering * int(f_dmz_dns_out),
            description=tr("dmz2 interroge un serveur DNS de l'extérieur (ext2)"),
        )
        self.add_grade_element(
            title=no_tr("forward_int_dns_dmz"), max_grade=2, grade_part=part6,
            grade=forward_filtering * int(f_int_dns_dmz) + int(_nameservers(resolv_conf)[:1] == [str(dmz2.ip)]),
            description=tr("int1 interroge le serveur DNS de dmz2, devenu son serveur par défaut (/etc/resolv.conf)"),
        )
        self.add_grade_element(
            title=no_tr("q_forward"), max_grade=2, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q6.get("stateless_hole")) == "any_port") + int(_norm(q6.get("reply_state")) == "established"),
            description=tr("filtrage sans état : la faille du port source ; l'état de la réponse à un ping"),
        )

        # =====================================================================
        # Part 7 — bonus: a dynamic set banning a source (question 7)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Bonus : ensemble dynamique (question 7)"))

        q7_answers = {"ban_effect": "ban_source"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Bonus : bannir temporairement une machine"),
            description=tr("""
nftables peut remplir un ensemble **depuis le trafic** et en faire expirer les éléments (section
@@ref:sets@@ des Informations). Sur `router`, sans rien retirer de la question 6 :

```
{cmds}```

Les deux `insert` placent ces règles **en tête** de la chaîne `forward`, la seconde avant la
première. À quoi sert ce dispositif ? Testez-le :

1. depuis `int1`, `curl -m 3 http://{ext1}/` répond ;
2. depuis `ext1`, `nc -v -w 2 {int1} {ssh}` (une tentative de connexion SSH vers la zone interne) ;
3. depuis `int1`, de nouveau `curl -m 3 http://{ext1}/`, puis `curl -m 3 http://{ext2}/` ;
4. sur `router`, `nft list set inet filter {set}` ; attendez une minute et recommencez l'étape 3.
""").format(cmds=_lines(self.net_scheme.cmds_router_ban()), ext1=ext1.ip, ext2=ext2.ip, int1=int1.ip, ssh=SSH_PORT,
            set=BAN_SET)
            + tr("""
- ce dispositif : @@{ban_effect:>détruit pendant 60 s tous les paquets vers la zone interne d'une machine de l'extérieur qui a tenté une connexion SSH vers cette zone, même les réponses aux connexions ouvertes par la zone interne>>>ban_source|interdit définitivement le SSH de l'extérieur vers la zone interne, et rien d'autre>>>ssh_only|limite l'extérieur à une connexion SSH par minute vers la zone interne>>>rate_limit|bannit pendant 60 s la machine interne visée par la tentative>>>ban_target}@@
""")
            + instructor(tr("""
**Solution.** Les trois commandes de l'énoncé. La chaîne `forward` commence alors par la règle
`ip saddr @{set} drop`, puis la règle `tcp dport {ssh} add @{set} {{ ip saddr }}`, puis la règle à
états. Un paquet de l'extérieur vers le port {ssh} d'une machine interne fait ajouter son adresse
source à l'ensemble `{set}` (puis il est détruit par la politique) ; pendant {seconds} secondes,
**tout** paquet de cette adresse vers la zone interne est détruit par la première règle, placée
**avant** la règle à états : même les réponses aux connexions ouvertes par la zone interne (étape
3 : `curl` vers `ext1` expire, vers `ext2` répond). `nft list set inet filter {set}` montre
l'adresse de `ext1` et le temps qui lui reste (`expires …`). C'est l'équivalent du module `recent`
d'iptables (`--set`, puis `--rcheck --seconds 60`). Placées après la règle à états, les deux règles
ne changeraient rien de visible : les nouvelles connexions de l'extérieur vers la zone interne sont
déjà détruites par la politique.

- Réponse : la machine de l'extérieur est bannie 60 s.
- L'évaluation (bonus) : dans `nft -j list ruleset`, un ensemble alimenté par une règle de
  `forward` (`add` ou `update`, `ip saddr`, `tcp dport {ssh}`) dont les éléments expirent après
  {seconds} s, et une règle `drop` sur `ip saddr @…` placée avant la règle à états ; sur les copies
  cachées : HTTP de `int2` vers `ext1` répond, puis `ext1` tente le port {ssh} de `int2`, puis
  HTTP de `int2` vers `ext1` ne répond plus alors que `ext2` répond toujours. L'ensemble de la
  copie est vidé au chargement : un bannissement en cours sur `router` ne fausse pas les autres
  sondes.
""").format(set=BAN_SET, ssh=SSH_PORT, seconds=BAN_SECONDS)),
            cheat_answers={"final": q7_answers},
        )

        self.add_grade_element(
            title=no_tr("ban_set"), max_grade=1, grade_part=part7, bonus=True,
            grade=int(bool(ban_updates) and ban_timed),
            description=tr("un ensemble alimenté par une règle de forward (ip saddr, tcp dport 22), éléments expirant "
                           "après 60 s"),
        )
        self.add_grade_element(
            title=no_tr("ban_rules"), max_grade=2, grade_part=part7, bonus=True,
            grade=int(ban_index is not None) + int(ban_index is not None and (ct_index is None or ban_index < ct_index)),
            description=tr("une règle drop sur ip saddr @ensemble, placée avant la règle à états"),
        )
        self.add_grade_element(
            title=no_tr("ban_works"), max_grade=2, grade_part=part7, bonus=True,
            grade=2 * int(ban_before and not ban_after and ban_spared),
            description=tr("après une tentative SSH de ext1 vers int2, int2 n'obtient plus de réponse de ext1 "
                           "(mais toujours de ext2)"),
        )
        self.add_grade_element(
            title=no_tr("q_ban"), max_grade=1, grade_part=part7, scope=params.EXO_EVAL_SCOPE, bonus=True,
            grade=int(_norm(q7.get("ban_effect")) == "ban_source"),
            description=tr("à quoi sert l'ensemble dynamique"),
        )


_TRANSLATIONS = {
    'en': {
        """

### @@sec:counters@@ Compter

**`counter`** compte les paquets et les octets qui atteignent cet endroit de la règle :
`tcp dport 25 counter reject`. `nft list ruleset` affiche alors `counter packets 3 bytes 180` sur
la règle : c'est le moyen le plus simple de savoir **quelle règle** a vu un paquet. Pour compter
ce que la politique d'une chaîne détruit, on termine la chaîne par une règle `counter drop`. Avec
la version de `nft` des machines du TP, le compteur d'une règle ne se remet pas à zéro (`nft
reset counters` ne concerne que les compteurs nommés, déclarés par `nft add counter`) : on
remplace la règle.

### @@sec:log@@ Journaliser

**`log`** produit une ligne par paquet (interface, adresses, protocole, ports). Il existe sous
deux formes :

- `log prefix "fw: "` écrit dans le **journal du noyau**, lu sur une vraie machine avec
  `dmesg -w` ou `journalctl -k -f`. **Dans un conteneur, cette forme ne donne rien** : par défaut
  le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "fw: " group 0` remet les paquets à **nflog**, où un programme vient les lire :
  **`tcpdump -n -i nflog:0`**. C'est la forme à utiliser dans ce TP.

`log` n'est pas un verdict : on le fait suivre d'un `drop` ou d'un `reject`. Pour ne pas remplir
le journal, on le limite : `limit rate 5/minute log prefix "fw: " group 0` journalise cinq
paquets d'un coup au plus, puis un toutes les 12 secondes ; les autres continuent vers la règle
suivante sans être journalisés. L'usage est de réunir les deux dans une chaîne régulière, où
l'on saute en dernière règle des chaînes concernées :

```
nft add chain inet filter logdrop
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "fw: " group 0'
nft add rule inet filter logdrop counter drop
nft add rule inet filter forward jump logdrop
```

Le préfixe contient des guillemets : dans un shell, toute la règle se protège par des
apostrophes.
""": """

### @@sec:counters@@ Counting

**`counter`** counts the packets and the bytes reaching this place of the rule: `tcp dport 25
counter reject`. `nft list ruleset` then prints `counter packets 3 bytes 180` on the rule: it is
the simplest way to know **which rule** saw a packet. To count what the policy of a chain drops,
end the chain with a `counter drop` rule. With the version of `nft` of the lab machines, the
counter of a rule cannot be reset (`nft reset counters` only concerns named counters, declared
with `nft add counter`): replace the rule.

### @@sec:log@@ Logging

**`log`** produces one line per packet (interface, addresses, protocol, ports). It comes in two
forms:

- `log prefix "fw: "` writes to the **kernel log**, read on a real machine with `dmesg -w` or
  `journalctl -k -f`. **In a container, this form gives nothing**: by default the kernel only
  logs this way the packets of the host machine (setting `net.netfilter.nf_log_all_netns`), and
  its log cannot be read from a container;
- `log prefix "fw: " group 0` hands the packets to **nflog**, where a program comes and reads
  them: **`tcpdump -n -i nflog:0`**. This is the form to use in this lab.

`log` is not a verdict: follow it with a `drop` or a `reject`. So as not to fill the log, limit
it: `limit rate 5/minute log prefix "fw: " group 0` logs five packets in a burst at most, then
one every 12 seconds; the others go on to the next rule without being logged. The usual way is
to put both in a regular chain, jumped to as the last rule of the chains concerned:

```
nft add chain inet filter logdrop
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "fw: " group 0'
nft add rule inet filter logdrop counter drop
nft add rule inet filter forward jump logdrop
```

The prefix holds double quotes: in a shell, the whole rule is protected by single quotes.
""",
        """

### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input` et en `forward`, une règle
  par flux de la matrice, restreinte à ceux qui en ont besoin (interface, adresse, port) ;
- **la règle à états en tête** : elle traite presque tous les paquets et dispense d'ouvrir quoi
  que ce soit pour les réponses ;
- **une règle décrit une ouverture** : zone source, zone destination, serveur, service. Jamais
  de règle sur le seul port source ;
- **l'interface pour la zone**, l'adresse pour la machine, les deux pour une règle sensible ;
- **le routeur se protège lui-même** : sa chaîne `input` est aussi stricte que celle d'un
  serveur ;
- **tester les interdictions** autant que les autorisations : un pare-feu qui laisse tout
  passer réussit tous les tests « ça marche » ;
- **un fichier, chargé d'un bloc** (section @@ref:files@@), plutôt que des commandes tapées une
  à une.

### @@sec:pitfalls@@ Les pièges

- **oublier le DNS** : une politique `drop` qui ne laisse pas revenir les réponses du serveur
  DNS fait échouer toute commande qui utilise un nom (`Could not resolve host`), alors que le
  service visé est peut-être ouvert. Testez avec l'adresse ;
- **oublier `lo`** : les services locaux se parlent par `127.0.0.1`, et le retour d'un `reject`
  de la chaîne `output` passe par là ;
- **se tromper de chaîne** : `input` pour ce qui est destiné au routeur, `forward` pour ce qui
  le traverse. Une règle juste dans la mauvaise chaîne ne fait rien ;
- **oublier le retour** : sans règle à états, accepter la requête ne suffit pas, la réponse est
  détruite au retour ;
- **l'ordre des règles** : une exception placée après l'interdiction qu'elle devait tempérer
  n'est jamais consultée (`nft insert rule`, ou `handle`) ;
- **se couper l'accès** : sur un routeur administré à distance, une chaîne `input` en `policy
  drop` sans règle pour SSH coupe la session en cours. Chargez un fichier complet, d'un bloc ;
- **`flush ruleset`** efface **toutes** les tables, pas seulement les vôtres, et les règles
  tapées avec `nft` disparaissent au redémarrage.
""": """

### @@sec:principles@@ The principles

- **forbid everything, then allow**: policy `drop` in `input` and in `forward`, one rule per
  flow of the matrix, restricted to those who need it (interface, address, port);
- **the stateful rule first**: it handles nearly every packet and saves opening anything for
  the replies;
- **a rule describes an opening**: source zone, destination zone, server, service. Never a rule
  on the source port alone;
- **the interface for the zone**, the address for the machine, both for a sensitive rule;
- **the router protects itself**: its `input` chain is as strict as the one of a server;
- **test the prohibitions** as much as the permissions: a firewall that lets everything through
  passes every "it works" test;
- **one file, loaded in one go** (section @@ref:files@@), rather than commands typed one by one.

### @@sec:pitfalls@@ The pitfalls

- **forgetting the DNS**: a policy `drop` that does not let the replies of the DNS server come
  back makes every command using a name fail (`Could not resolve host`), while the service aimed
  at may well be open. Test with the address;
- **forgetting `lo`**: local services talk to each other over `127.0.0.1`, and the return of a
  `reject` of the `output` chain goes that way;
- **picking the wrong chain**: `input` for what is addressed to the router, `forward` for what
  crosses it. A correct rule in the wrong chain does nothing;
- **forgetting the return**: without a stateful rule, accepting the request is not enough, the
  reply is dropped on its way back;
- **the order of the rules**: an exception placed after the prohibition it was to soften is
  never consulted (`nft insert rule`, or `handle`);
- **locking oneself out**: on a router administered remotely, an `input` chain with `policy
  drop` and no rule for SSH cuts the session in progress. Load a complete file, in one go;
- **`flush ruleset`** erases **all** the tables, not only yours, and the rules typed with `nft`
  are gone after a reboot.
""",
        """

### @@sec:verdict-list@@ Les verdicts

- **`accept`** : le paquet passe ; l'évaluation de la chaîne de base s'arrête ;
- **`drop`** : le paquet est détruit **en silence** : l'émetteur attend, réessaie, puis renonce
  (*timeout*) ;
- **`reject`** : le paquet est détruit et l'émetteur est **prévenu** par un message d'erreur :
  l'erreur est immédiate ;
- **`jump chaine`** : évalue la chaîne régulière, et revient si elle ne tranche pas ; **`goto
  chaine`** y va sans retour ; **`return`** quitte la chaîne en cours et reprend dans la chaîne
  appelante.

Une règle sans verdict (`counter`, `log`…) agit, puis laisse le paquet continuer vers la règle
suivante.

### @@sec:reject@@ reject : refuser en prévenant

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | un message ICMP *port unreachable* (`nft list ruleset` affiche la forme complète, `reject with icmp port-unreachable`, ou `icmpx` quand la règle ne dit pas la version d'IP) |
| `reject with tcp reset` | un segment TCP RST : ce que répond une machine sans pare-feu dont le port est fermé (TCP seulement) |
| `reject with icmpx admin-prohibited` | l'erreur « interdit par l'administrateur », en ICMP ou en ICMPv6 selon le paquet |

Côté client, l'erreur est `Connection refused` avec la réponse par défaut ou un RST, `No route to
host` avec `admin-prohibited`.

### @@sec:drop-or-reject@@ Détruire ou refuser ?

Vers l'extérieur on **détruit** : `drop` ne révèle rien à un attaquant, pas même l'existence de
la machine. Pour ses propres utilisateurs on **refuse** souvent : l'erreur est claire et
immédiate, alors qu'un `drop` les fait attendre sans explication.

### @@sec:output-view@@ Dans la chaîne output : ce que voit le programme

Dans la chaîne **`output`**, le paquet est arrêté sur la machine même qui l'émet, et la
différence entre `drop` et `reject` se voit dans le programme :

| programme | avec `drop` | avec `reject` |
|-----------|-------------|---------------|
| une connexion TCP (`nc`, `curl`) | rien ne signale le blocage : le programme attend son délai (`timed out`) | échec immédiat : `Connection refused` |
| `ping` | `100% packet loss`, sans autre message | `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` |

Le message d'erreur d'un `reject` est fabriqué par le noyau et **revient au programme par
l'interface `lo`** : la chaîne `input` doit l'accepter (`iif lo accept`), sinon le programme
attend comme avec `drop`.
""": """

### @@sec:verdict-list@@ The verdicts

- **`accept`**: the packet goes through; the evaluation of the base chain stops;
- **`drop`**: the packet is destroyed **silently**: the sender waits, retries, then gives up
  (*timeout*);
- **`reject`**: the packet is destroyed and the sender is **told** with an error message: the
  error is immediate;
- **`jump chain`**: evaluates the regular chain, and comes back if it does not decide; **`goto
  chain`** goes there without coming back; **`return`** leaves the current chain and resumes in
  the calling chain.

A rule without a verdict (`counter`, `log`…) acts, then lets the packet go on to the next rule.

### @@sec:reject@@ reject: refusing and saying so

| rule | answer sent to the sender |
|------|---------------------------|
| `reject` | an ICMP *port unreachable* message (`nft list ruleset` prints the full form, `reject with icmp port-unreachable`, or `icmpx` when the rule does not say the IP version) |
| `reject with tcp reset` | a TCP RST segment: what a machine without a firewall answers when the port is closed (TCP only) |
| `reject with icmpx admin-prohibited` | the "administratively prohibited" error, in ICMP or in ICMPv6 according to the packet |

On the client side, the error is `Connection refused` with the default answer or a RST, `No
route to host` with `admin-prohibited`.

### @@sec:drop-or-reject@@ Drop or reject?

Towards the outside, **drop**: `drop` reveals nothing to an attacker, not even that the machine
exists. For one's own users, **reject** is often preferred: the error is clear and immediate,
whereas a `drop` makes them wait without an explanation.

### @@sec:output-view@@ In the output chain: what the program sees

In the **`output`** chain, the packet is stopped on the very machine that sends it, and the
difference between `drop` and `reject` shows in the program:

| program | with `drop` | with `reject` |
|---------|-------------|---------------|
| a TCP connection (`nc`, `curl`) | nothing signals the blockage: the program waits for its timeout (`timed out`) | immediate failure: `Connection refused` |
| `ping` | `100% packet loss`, with no other message | `Destination Port Unreachable` coming from the machine itself, and `ping: sendmsg: Operation not permitted` |

The error message of a `reject` is built by the kernel and **comes back to the program through
the interface `lo`**: the `input` chain must accept it (`iif lo accept`), otherwise the program
waits as with `drop`.
""",
        """

### @@sec:why-output@@ Pourquoi filtrer la sortie

La chaîne `output` ne protège pas la machine : elle protège **le reste du réseau** contre elle,
et impose une règle d'usage à ses utilisateurs. On s'en sert pour :

- **limiter les dégâts d'une machine compromise** : un poste qui n'a pas à envoyer de courrier
  ne pourra pas servir à envoyer du spam ;
- **imposer un passage obligé** : le courrier par le serveur de l'entreprise, le DNS par son
  résolveur, le web par son mandataire ;
- **cloisonner un serveur** : un serveur web n'a aucune raison d'ouvrir lui-même des connexions
  vers les postes du réseau interne.

La chaîne `output` d'une machine ne voit que ce que **ses propres processus** émettent, quel que
soit l'utilisateur (`root` compris) ; sur un routeur, elle ne voit rien de ce qui le traverse.

### @@sec:output-policies@@ Deux façons de l'écrire

**Tout permettre, sauf…** : politique `accept` et quelques règles d'interdiction. C'est la forme
habituelle sur un poste, et celle de ce TP :

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
nft add rule inet filter output ip daddr 192.0.2.25 tcp dport 25 accept
nft add rule inet filter output tcp dport 25 reject
```

L'**exception précède l'interdiction** : la première règle satisfaite décide. Une seule règle
convient aussi : `ip daddr != 192.0.2.25 tcp dport 25 reject`.

**Tout interdire, sauf…** : politique `drop` et une règle par flux sortant autorisé. C'est la
forme d'un serveur que l'on veut cloisonner. Il faut alors penser à tout ce que la machine émet
sans qu'on le voie : ses **réponses** aux connexions qu'elle sert (`ct state established,related
accept`, en tête, comme en `input`), ses échanges avec elle-même (`oif lo accept`), ses questions
DNS.

### @@sec:output-reject@@ drop ou reject en sortie

En `output`, préférez **`reject`** : celui qui est bloqué est un utilisateur de la machine, et il
vaut mieux qu'il le sache aussitôt (section @@ref:output-view@@). Deux points à retenir :

- le retour du `reject` passe par la chaîne **`input`** de la même machine, par l'interface
  `lo`. Avec une politique `drop` en `input`, il faut `iif lo accept` ou une règle à états
  générale (`ct state established,related accept` : le message d'erreur est `related`). Une
  règle à états limitée à TCP (`meta l4proto tcp ct state …`) ne le laisse pas passer ;
- un `drop` en sortie ressemble, vu du programme, à une panne du réseau ou du serveur distant :
  pensez à regarder aussi la chaîne `output` de la machine quand « rien ne répond ».
""": """

### @@sec:why-output@@ Why filter what leaves

The `output` chain does not protect the machine: it protects **the rest of the network** against
it, and imposes a rule of use on its users. It is used to:

- **limit the damage of a compromised machine**: a workstation that has no mail to send cannot
  be used to send spam;
- **impose a mandatory path**: mail through the server of the company, DNS through its
  resolver, the web through its proxy;
- **confine a server**: a web server has no reason to open connections itself to the
  workstations of the internal network.

The `output` chain of a machine only sees what **its own processes** send, whoever the user
(`root` included); on a router, it sees nothing of what crosses it.

### @@sec:output-policies@@ Two ways to write it

**Allow everything, except…**: policy `accept` and a few prohibition rules. This is the usual
form on a workstation, and the one of this lab:

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
nft add rule inet filter output ip daddr 192.0.2.25 tcp dport 25 accept
nft add rule inet filter output tcp dport 25 reject
```

The **exception comes before the prohibition**: the first matching rule decides. A single rule
also does it: `ip daddr != 192.0.2.25 tcp dport 25 reject`.

**Forbid everything, except…**: policy `drop` and one rule per allowed outgoing flow. This is
the form of a server to be confined. Then think of everything the machine sends without anyone
noticing: its **replies** to the connections it serves (`ct state established,related accept`,
at the head, as in `input`), its exchanges with itself (`oif lo accept`), its DNS questions.

### @@sec:output-reject@@ drop or reject on the way out

In `output`, prefer **`reject`**: the one who is blocked is a user of the machine, and it is
better for them to know at once (section @@ref:output-view@@). Two points to remember:

- the return of the `reject` goes through the **`input`** chain of the same machine, over the
  interface `lo`. With a policy `drop` in `input`, it takes `iif lo accept` or a general
  stateful rule (`ct state established,related accept`: the error message is `related`). A
  stateful rule limited to TCP (`meta l4proto tcp ct state …`) does not let it through;
- a `drop` on the way out looks, from the program, like a failure of the network or of the
  remote server: remember to look at the `output` chain of the machine too when "nothing
  answers".
""",
        """

La chaîne **`forward`** d'un routeur filtre ce qui passe d'une zone à l'autre. Elle voit les
paquets des **deux sens** de chaque échange : la requête, puis la réponse, avec les interfaces
d'entrée et de sortie inversées.

### @@sec:method@@ La méthode

1. **Associer chaque zone à une interface** du routeur (`ip -br address`) et écrire la matrice
   des flux (section @@ref:matrix@@).
2. **Politique `drop`** sur `forward` : plus rien ne traverse.
3. **La règle à états en tête** : `ct state established,related accept`. Elle ne laisse passer
   que les suites d'échanges déjà autorisés, dans les deux sens.
4. **Une règle par flux autorisé**, qui décrit l'**ouverture** de l'échange : zone source
   (`iifname`), zone destination (`oifname`), serveur éventuel (`ip daddr`), service (`tcp dport`,
   `udp dport`, `icmp type echo-request`).
5. **Tester** chaque flux autorisé et **chaque interdiction** voisine (un autre port, un autre
   serveur, l'autre sens).

### @@sec:forward-example@@ Un exemple

L'interne (`eth2`) navigue sur le web de l'extérieur (`eth0`) ; l'extérieur ne joint que le
serveur web de la DMZ (`eth1`) :

```
table inet filter {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept
        iifname "eth0" oifname "eth1" ip daddr 203.0.113.80 tcp dport 80 accept
    }
}
```

Chaque règle se lit comme une case de la matrice : d'où, vers où, quel serveur, quel service.
Ce qui n'est pas écrit est interdit : l'extérieur n'ouvre rien vers l'interne, la DMZ n'ouvre
rien du tout, le port 8080 du serveur reste fermé. Les erreurs ICMP utiles (*port unreachable*,
*time exceeded*…) reviennent par la règle à états, puisqu'elles sont `related` ; un `ping` ne
traverse que si une règle accepte ses `echo-request`.

### @@sec:zone-chains@@ Structurer : une chaîne par couple de zones

Quand les règles se multiplient, on range celles de chaque couple (zone source, zone
destination) dans une **chaîne régulière**, et la chaîne `forward` ne fait plus qu'aiguiller :

```
table inet filter {
    chain int_ext {
        tcp dport 80 accept
        ip daddr 198.51.100.53 udp dport 53 accept
    }
    chain ext_dmz {
        ip daddr 203.0.113.80 tcp dport 80 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" jump int_ext
        iifname "eth0" oifname "eth1" jump ext_dmz
    }
}
```

Un paquet que sa chaîne de zones n'accepte pas revient dans `forward`, à la règle qui suit le
saut, et finit détruit par la politique ; un couple de zones sans chaîne n'a droit à rien.
L'aiguillage peut tenir en une seule règle, avec un dictionnaire de verdicts
(section @@ref:vmaps@@) : `iif . oif vmap { eth2 . eth0 : jump int_ext, eth0 . eth1 : jump
ext_dmz }`.

### @@sec:router-input@@ Protéger le routeur lui-même

Un routeur est aussi une machine : il a ses propres services (SSH pour son administration) et
ses propres besoins (interroger un serveur DNS, répondre aux `ping`). Tout cela passe par ses
chaînes **`input`** et `output`, jamais par `forward` (section @@ref:three-paths@@) : une règle
de `forward` n'a aucun effet sur un paquet destiné au routeur, et inversement. Sa chaîne `input`
ressemble à celle d'un serveur prudent :

- politique `drop` et `iif lo accept` ;
- les réponses à ce que le routeur émet lui-même (règle à états) ;
- les `ping` venus des zones de confiance seulement : le critère est l'**interface d'entrée**,
  `iifname { eth1, eth2 } icmp type echo-request accept` ;
- l'administration depuis **une** machine, désignée par son interface **et** son adresse :
  `iifname eth2 ip saddr 192.0.2.10 tcp dport 22 accept`.

Le routeur répond sur **toutes** ses adresses, quelle que soit l'interface d'arrivée : c'est
`iifname` qui dit de quelle zone vient un paquet, pas l'adresse de destination.

### @@sec:spoofing@@ L'usurpation d'adresse

Rien n'empêche une machine de l'extérieur d'émettre des paquets dont l'adresse source est celle
d'une machine interne (*spoofing*). Une règle qui ne regarde que `ip saddr` les prend pour du
trafic interne. Deux parades :

- **dire la zone par l'interface**, jamais par l'adresse seule : `iifname eth2 ip saddr
  192.0.2.10 …`. On peut aussi détruire d'emblée ce qui est manifestement faux :
  `iifname eth0 ip saddr 192.0.2.0/24 drop` (une adresse interne qui arrive de l'extérieur) ;
- **vérifier le chemin de retour** : la règle `fib saddr . iif oif missing drop` détruit tout
  paquet dont l'adresse source ne serait pas jointe par l'interface d'où il arrive. On la place
  avant tout le reste, au hook `prerouting`, où elle vaut pour `input` et pour `forward` :

```
nft 'add chain inet filter prerouting { type filter hook prerouting priority raw; policy accept; }'
nft add rule inet filter prerouting fib saddr . iif oif missing drop
```

Cette vérification suppose un routage symétrique : chaque réseau n'est joint que par une
interface.

### @@sec:forward-nat@@ Quand le routeur traduit aussi les adresses

Un routeur fait souvent aussi de la traduction d'adresses (NAT), dans des chaînes de type `nat`.
La chaîne `forward` voit un paquet **après** le changement de son adresse de destination (fait
en `prerouting`) et **avant** le changement de son adresse source (fait en `postrouting`) : ses
règles nomment donc l'adresse réelle du serveur interne, et l'adresse d'origine du client.
""": """

The **`forward`** chain of a router filters what goes from one zone to another. It sees the
packets of **both directions** of each exchange: the request, then the reply, with the input and
output interfaces swapped.

### @@sec:method@@ The method

1. **Map each zone to an interface** of the router (`ip -br address`) and write the flow matrix
   (section @@ref:matrix@@).
2. **Policy `drop`** on `forward`: nothing crosses any more.
3. **The stateful rule first**: `ct state established,related accept`. It only lets through what
   follows exchanges already allowed, in both directions.
4. **One rule per allowed flow**, describing the **opening** of the exchange: source zone
   (`iifname`), destination zone (`oifname`), the server if any (`ip daddr`), the service (`tcp
   dport`, `udp dport`, `icmp type echo-request`).
5. **Test** each allowed flow and **each neighbouring prohibition** (another port, another
   server, the other direction).

### @@sec:forward-example@@ An example

The internal zone (`eth2`) browses the web of the outside (`eth0`); the outside only reaches the
web server of the DMZ (`eth1`):

```
table inet filter {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept
        iifname "eth0" oifname "eth1" ip daddr 203.0.113.80 tcp dport 80 accept
    }
}
```

Each rule reads like a cell of the matrix: from where, to where, which server, which service.
What is not written is forbidden: the outside opens nothing towards the internal zone, the DMZ
opens nothing at all, port 8080 of the server stays closed. The useful ICMP errors (*port
unreachable*, *time exceeded*…) come back through the stateful rule, since they are `related`; a
`ping` only crosses when a rule accepts its `echo-request` packets.

### @@sec:zone-chains@@ Structuring: one chain per pair of zones

When rules pile up, those of each pair (source zone, destination zone) are put in a **regular
chain**, and the `forward` chain only dispatches:

```
table inet filter {
    chain int_ext {
        tcp dport 80 accept
        ip daddr 198.51.100.53 udp dport 53 accept
    }
    chain ext_dmz {
        ip daddr 203.0.113.80 tcp dport 80 accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" jump int_ext
        iifname "eth0" oifname "eth1" jump ext_dmz
    }
}
```

A packet its zone chain does not accept comes back to `forward`, at the rule following the
jump, and ends up dropped by the policy; a pair of zones without a chain is allowed nothing.
The dispatch can fit in a single rule, with a verdict map (section @@ref:vmaps@@):
`iif . oif vmap { eth2 . eth0 : jump int_ext, eth0 . eth1 : jump ext_dmz }`.

### @@sec:router-input@@ Protecting the router itself

A router is a machine too: it has its own services (SSH for its administration) and its own
needs (asking a DNS server, answering `ping`). All of that goes through its **`input`** and
`output` chains, never through `forward` (section @@ref:three-paths@@): a rule of `forward` has
no effect on a packet addressed to the router, and conversely. Its `input` chain looks like the
one of a careful server:

- policy `drop` and `iif lo accept`;
- the replies to what the router sends itself (stateful rule);
- `ping` from the trusted zones only: the selector is the **input interface**,
  `iifname { eth1, eth2 } icmp type echo-request accept`;
- administration from **one** machine, named by its interface **and** its address:
  `iifname eth2 ip saddr 192.0.2.10 tcp dport 22 accept`.

The router answers on **all** its addresses, whatever the arrival interface: `iifname` is what
tells which zone a packet comes from, not the destination address.

### @@sec:spoofing@@ Address spoofing

Nothing prevents a machine of the outside from sending packets whose source address is the one
of an internal machine (*spoofing*). A rule that only looks at `ip saddr` takes them for
internal traffic. Two defences:

- **name the zone by the interface**, never by the address alone: `iifname eth2 ip saddr
  192.0.2.10 …`. What is obviously false can also be dropped straight away:
  `iifname eth0 ip saddr 192.0.2.0/24 drop` (an internal address arriving from the outside);
- **check the return path**: the rule `fib saddr . iif oif missing drop` drops every packet
  whose source address would not be reached through the interface it arrives from. It is placed
  before everything else, at the `prerouting` hook, where it holds for `input` and for
  `forward`:

```
nft 'add chain inet filter prerouting { type filter hook prerouting priority raw; policy accept; }'
nft add rule inet filter prerouting fib saddr . iif oif missing drop
```

This check assumes symmetric routing: each network is reached through one interface only.

### @@sec:forward-nat@@ When the router also translates addresses

A router often does address translation (NAT) too, in chains of type `nat`. The `forward` chain
sees a packet **after** the change of its destination address (done in `prerouting`) and
**before** the change of its source address (done in `postrouting`): its rules therefore name
the real address of the internal server, and the original address of the client.
""",
        """

Netfilter mémorise les **connexions** en cours (*connection tracking*, ou *conntrack*) : une
connexion TCP, mais aussi un échange UDP (des datagrammes entre les mêmes adresses et les mêmes
ports) ou ICMP (un `echo-request` et son `echo-reply`). Le suivi ne filtre rien : il
**étiquette** chaque paquet d'un **état**, que les règles testent avec `ct state`.

### @@sec:ct-states@@ Les états

- **`new`** : le paquet ouvre un échange, ou appartient à un échange dont on n'a encore vu
  qu'**un seul sens** (le SYN en TCP, la première requête UDP et ses répétitions) ;
- **`established`** : le paquet appartient à un échange dont on a vu des paquets **dans les deux
  sens**. La toute première **réponse** (le SYN-ACK, la réponse d'un serveur DNS, l'`echo-reply`)
  est déjà dans cet état, comme tout ce qui suit, dans un sens et dans l'autre ;
- **`related`** : le paquet n'appartient pas à un échange connu, mais il est **lié** à l'un
  d'eux : une erreur ICMP qui le concerne (*port unreachable*, *time exceeded*…) ;
- **`invalid`** : le paquet ne correspond à rien de connu et ne peut pas ouvrir d'échange ;
- **`untracked`** : le paquet a été soustrait au suivi (règle `notrack`).

Un échange est enregistré par son premier paquet, à condition que le pare-feu l'accepte : un
paquet `new` détruit ne laisse aucune trace. Il est oublié après un temps d'inactivité : 30
secondes pour un échange UDP ou ICMP resté sans suite, 5 jours pour une connexion TCP établie.

### @@sec:stateless@@ Le filtre sans état et sa faille

Un filtre **sans état** ne sait autoriser les réponses qu'à l'aveugle : « tout ce qui vient du
port 80 », « tout l'UDP qui vient du port 53 ». C'est une **faille** : celui qui choisit 80 ou 53
comme port source de ses paquets passe aussi, vers n'importe quel port. Le port source d'un
paquet est choisi par son émetteur ; il ne prouve rien.

### @@sec:stateful-rule@@ La règle à états

Avec le suivi de connexion, on autorise l'**ouverture** d'un échange, dans un seul sens, et les
réponses suivent :

```
nft add rule inet filter forward ct state established,related accept       # en première règle
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

La seconde règle laisse les machines derrière `eth2` ouvrir des connexions vers le port 80 de
celles derrière `eth0` ; les réponses passent par la première. Rien ne permet à une machine
derrière `eth0` d'ouvrir une connexion dans l'autre sens : son premier paquet serait `new`, et
aucune règle ne l'accepte. C'est le **premier paquet** d'un échange qui fixe son sens.

Placée en **tête** de chaîne, la règle à états traite presque tous les paquets (ceux des
échanges en cours) ; les règles suivantes ne voient plus que les ouvertures. `ct state invalid
drop` la complète souvent.

### @@sec:selective-replies@@ N'accepter que certaines réponses

`ct state` se combine avec les autres critères quand on ne veut accepter que **certaines**
réponses :

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

La première n'accepte que les réponses du serveur DNS `192.0.2.53` aux questions que la machine
lui a posées : ce serveur ne peut pas, de lui-même, joindre la machine depuis son port 53. La
seconde accepte tout le trafic retour des connexions TCP que la machine a ouvertes, mais pas les
erreurs ICMP qui les concernent : une erreur ICMP est `related`, mais ce n'est pas un paquet
TCP.
""": """

Netfilter remembers the **connections** in progress (*connection tracking*, or *conntrack*): a
TCP connection, but also a UDP exchange (datagrams between the same addresses and the same
ports) or an ICMP one (an `echo-request` and its `echo-reply`). Tracking filters nothing: it
**labels** each packet with a **state**, which the rules test with `ct state`.

### @@sec:ct-states@@ The states

- **`new`**: the packet opens an exchange, or belongs to an exchange of which only **one
  direction** has been seen so far (the SYN in TCP, the first UDP request and its repetitions);
- **`established`**: the packet belongs to an exchange of which packets have been seen **in both
  directions**. The very first **reply** (the SYN-ACK, the reply of a DNS server, the
  `echo-reply`) is already in this state, like everything that follows, in one direction and in
  the other;
- **`related`**: the packet does not belong to a known exchange, but it is **linked** to one of
  them: an ICMP error about it (*port unreachable*, *time exceeded*…);
- **`invalid`**: the packet matches nothing known and cannot open an exchange;
- **`untracked`**: the packet was taken out of tracking (a `notrack` rule).

An exchange is recorded by its first packet, provided the firewall accepts it: a `new` packet
that is dropped leaves no trace. It is forgotten after some idle time: 30 seconds for a UDP or
ICMP exchange that got no follow-up, 5 days for an established TCP connection.

### @@sec:stateless@@ The stateless filter and its hole

A **stateless** filter can only allow replies blindly: "whatever comes from port 80", "all the
UDP coming from port 53". This is a **hole**: whoever picks 80 or 53 as the source port of their
packets gets through too, to any port. The source port of a packet is chosen by its sender; it
proves nothing.

### @@sec:stateful-rule@@ The stateful rule

With connection tracking, the **opening** of an exchange is allowed, in one direction only, and
the replies follow:

```
nft add rule inet filter forward ct state established,related accept       # as the first rule
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

The second rule lets the machines behind `eth2` open connections to port 80 of those behind
`eth0`; the replies go through the first one. Nothing lets a machine behind `eth0` open a
connection the other way: its first packet would be `new`, and no rule accepts it. The **first
packet** of an exchange is what sets its direction.

Placed at the **head** of the chain, the stateful rule handles nearly every packet (those of the
exchanges in progress); the following rules only see the openings. `ct state invalid drop` often
completes it.

### @@sec:selective-replies@@ Accepting only some replies

`ct state` combines with the other selectors when only **some** replies are to be accepted:

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

The first one only accepts the replies of the DNS server `192.0.2.53` to the questions the
machine asked it: that server cannot, by itself, reach the machine from its port 53. The second
one accepts all the return traffic of the TCP connections the machine opened, but not the ICMP
errors about them: an ICMP error is `related`, but it is not a TCP packet.
""",
        """

Tester un pare-feu, c'est vérifier ce qui **doit passer** et ce qui **doit être bloqué**, avec
des délais courts pour ne pas attendre.

### @@sec:test-commands@@ Les commandes de test

| service | commande de test |
|---------|------------------|
| ICMP | `ping -c 2 -W 1 adresse` |
| HTTP (ports 80, 8080) | `curl -m 3 http://adresse/`, `curl -m 3 http://adresse:8080/` |
| DNS (UDP 53) | `dig @serveur nom +time=1 +tries=1` (ou `+short` pour la seule réponse) |
| SSH (TCP 22), courrier (TCP 25), tout port TCP | `nc -v -w 3 adresse 22` (la bannière du serveur s'affiche), `ssh root@adresse` |

Les serveurs web de test répondent par leur nom et par ce qu'ils voient du client :
`SERVER=dmz1`, `CLIENT_IP=…`, `TTL=63` (64 moins un par routeur traversé). Sur un serveur,
`ss -tulnp` liste les ports en écoute : un port fermé répond `Connection refused` même sans
pare-feu.

### @@sec:symptoms@@ Lire le message d'erreur

| symptôme | cause probable |
|----------|----------------|
| `Connection timed out`, `100% packet loss`, après le délai | un paquet est **détruit** (`drop`), à l'aller ou au retour |
| `Connection refused`, immédiat | un `reject`, ou aucun serveur sur ce port |
| `Could not resolve host`, `Temporary failure in name resolution` | le **DNS** ne répond pas : la question ou la réponse est filtrée. Essayez avec l'adresse |
| `ping: sendmsg: Operation not permitted`, avec `Destination Port Unreachable` venant de la machine elle-même | un `reject` dans sa propre chaîne `output` (un `drop` n'y donne que `100% packet loss`) |
| `no servers could be reached` (`dig`) | la question DNS ou sa réponse est détruite |

### @@sec:locate@@ Localiser un blocage sur un routeur

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu : en réception il voit
les paquets **avant** tous les hooks (même ceux que le pare-feu va détruire), en émission
**après** tous les hooks (seulement ceux qui partent vraiment). Sur le routeur, on capture donc
des deux côtés :

```
tcpdump -n -i eth2 icmp or port 80        # côté arrivée : le paquet entre-t-il ?
tcpdump -n -i eth0 icmp or port 80        # côté départ : ressort-il ? la réponse revient-elle ?
```

Un paquet vu à l'arrivée mais pas au départ a été arrêté par le routeur (ou n'a pas de route).
Une requête qui ressort sans que la réponse revienne côté arrivée désigne le **retour** : la
réponse est détruite par le routeur, ou par la machine qui devait répondre.

Les **compteurs** disent ensuite quelle règle a vu le paquet : ajoutez `counter` aux règles
(`… counter accept`) et relisez `nft list chain inet filter forward` après un essai.

### @@sec:trace@@ Suivre un paquet règle par règle

Une règle `meta nftrace set 1`, placée en tête de chaîne, marque les paquets à suivre, et
`nft monitor trace` affiche leur parcours : la chaîne traversée, chaque règle satisfaite et le
verdict final.

```
nft insert rule inet filter forward ip saddr 192.0.2.10 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter forward packet: iif "eth2" ip saddr 192.0.2.10 … tcp dport 8080 …
trace id a95ea7ef inet filter forward rule ip saddr 192.0.2.10 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter forward verdict continue
trace id a95ea7ef inet filter forward policy drop
```

Supprimez la règle de trace quand vous avez fini.

### @@sec:diagnosis@@ Une démarche de diagnostic

1. le message d'erreur du client : délai (`drop`), refus immédiat (`reject`), ou nom non résolu
   (le DNS) ?
2. `nft list ruleset` sur la machine et sur le routeur : est-ce le jeu de règles que vous croyez
   avoir chargé, dans le bon ordre, dans la bonne chaîne (`input` ou `forward`) ?
3. `tcpdump` : où le paquet s'arrête-t-il ? À l'aller, ou au retour ?
4. les compteurs, puis la trace : quelle règle l'a arrêté ?
""": """

Testing a firewall means checking what **must pass** and what **must be blocked**, with short
timeouts so as not to wait.

### @@sec:test-commands@@ The test commands

| service | test command |
|---------|--------------|
| ICMP | `ping -c 2 -W 1 address` |
| HTTP (ports 80, 8080) | `curl -m 3 http://address/`, `curl -m 3 http://address:8080/` |
| DNS (UDP 53) | `dig @server name +time=1 +tries=1` (or `+short` for the answer alone) |
| SSH (TCP 22), mail (TCP 25), any TCP port | `nc -v -w 3 address 22` (the banner of the server is printed), `ssh root@address` |

The test web servers answer with their name and what they see of the client: `SERVER=dmz1`,
`CLIENT_IP=…`, `TTL=63` (64 minus one per router crossed). On a server, `ss -tulnp` lists the
listening ports: a closed port answers `Connection refused` even without a firewall.

### @@sec:symptoms@@ Reading the error message

| symptom | likely cause |
|---------|--------------|
| `Connection timed out`, `100% packet loss`, after the timeout | a packet is **dropped**, on the way out or on the way back |
| `Connection refused`, at once | a `reject`, or no server on that port |
| `Could not resolve host`, `Temporary failure in name resolution` | the **DNS** does not answer: the question or the reply is filtered. Try with the address |
| `ping: sendmsg: Operation not permitted`, with `Destination Port Unreachable` coming from the machine itself | a `reject` in its own `output` chain (a `drop` there only gives `100% packet loss`) |
| `no servers could be reached` (`dig`) | the DNS question or its reply is dropped |

### @@sec:locate@@ Locating a blockage on a router

`tcpdump` captures **right at the interface**, outside the firewall: on reception it sees the
packets **before** every hook (even those the firewall is about to drop), on transmission
**after** every hook (only those that really leave). On the router, capture on both sides:

```
tcpdump -n -i eth2 icmp or port 80        # arrival side: does the packet come in?
tcpdump -n -i eth0 icmp or port 80        # departure side: does it go out? does the reply come back?
```

A packet seen on arrival but not on departure was stopped by the router (or has no route). A
request that goes out while the reply does not come back on the arrival side points to the
**return**: the reply is dropped by the router, or by the machine that was to answer.

The **counters** then tell which rule saw the packet: add `counter` to the rules (`… counter
accept`) and read `nft list chain inet filter forward` again after a try.

### @@sec:trace@@ Following a packet rule by rule

A rule `meta nftrace set 1`, placed at the head of a chain, marks the packets to follow, and
`nft monitor trace` prints their journey: the chain crossed, each matching rule and the final
verdict.

```
nft insert rule inet filter forward ip saddr 192.0.2.10 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter forward packet: iif "eth2" ip saddr 192.0.2.10 … tcp dport 8080 …
trace id a95ea7ef inet filter forward rule ip saddr 192.0.2.10 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter forward verdict continue
trace id a95ea7ef inet filter forward policy drop
```

Delete the trace rule when you are done.

### @@sec:diagnosis@@ A way to diagnose

1. the error message of the client: timeout (`drop`), immediate refusal (`reject`), or name not
   resolved (the DNS)?
2. `nft list ruleset` on the machine and on the router: is it the ruleset you think you loaded,
   in the right order, in the right chain (`input` or `forward`)?
3. `tcpdump`: where does the packet stop? On the way out, or on the way back?
4. the counters, then the trace: which rule stopped it?
""",
        """

Un **ensemble** (*set*) réunit des valeurs d'un même type ; une règle le consulte en une seule
opération, quel que soit le nombre de ses éléments.

### @@sec:anonymous-sets@@ Les ensembles anonymes

Un **ensemble anonyme** s'écrit dans la règle, entre accolades : `tcp dport { 80, 8080 }`,
`iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }`. Une seule règle remplace
plusieurs règles identiques ; son contenu ne change plus, sauf à remplacer la règle.

### @@sec:named-sets@@ Les ensembles nommés

Un **ensemble nommé** est un objet de la table, que plusieurs règles consultent (`@nom`) et
dont on modifie le contenu **sans toucher aux règles** :

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
nft 'delete element inet filter admins { 192.0.2.20 }'
```

Le `type` fixe la nature des éléments : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC),
`inet_service` (port), `inet_proto` (protocole). Les drapeaux (`flags`) fixent son
comportement :

| déclaration | effet |
|-------------|-------|
| `flags interval;` | les éléments peuvent être des réseaux ou des plages (`192.0.2.0/24`) ; sans ce drapeau, des valeurs isolées seulement |
| `flags timeout; timeout 1h;` | les éléments disparaissent d'eux-mêmes après ce délai |
| `flags dynamic;` | les règles peuvent ajouter elles-mêmes des éléments, au passage des paquets |

Un élément peut réunir plusieurs champs, séparés par un point : avec un ensemble de type
`ipv4_addr . inet_service`, la règle `ip saddr . tcp dport @allowed accept` accepte les couples
(adresse, port) qu'il contient.

### @@sec:dynamic-sets@@ Les ensembles alimentés par les règles

Un **ensemble dynamique** est rempli **par les règles elles-mêmes**, au passage des paquets, et
ses éléments peuvent **expirer** :

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

- chaque paquet qui atteint la règle `add @banned { ip saddr }` fait ajouter son adresse source
  à l'ensemble ; l'élément disparaît de lui-même 60 secondes plus tard. `update` au lieu de `add`
  relance le délai à chaque paquet ;
- `add @banned …` n'est pas un verdict : le paquet continue vers la règle suivante ;
- `nft list set inet filter banned` montre les éléments et le temps qui leur reste (`expires
  54s768ms`) ; `nft flush set inet filter banned` vide l'ensemble.

**La place des règles compte.** La règle qui consulte l'ensemble (`ip saddr @banned drop`) ne
coupe les échanges déjà en cours que si elle est placée **avant la règle à états** ; après elle,
elle ne voit plus que les ouvertures. On construit ainsi un bannissement temporaire, une limite
par adresse ou un *port knocking*.

### @@sec:vmaps@@ Les dictionnaires de verdicts

Un **dictionnaire de verdicts** (*verdict map*, `vmap`) associe un verdict à chaque valeur d'un
champ, en une seule consultation :

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 80 : accept, 23 : drop }'
nft 'add rule inet filter forward oifname vmap { eth1 : jump to_dmz, eth2 : jump to_int }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
```

Un paquet dont le champ n'est pas une clé du dictionnaire passe à la règle suivante.
""": """

A **set** gathers values of one type; a rule looks it up in a single operation, whatever the
number of its elements.

### @@sec:anonymous-sets@@ Anonymous sets

An **anonymous set** is written in the rule, between braces: `tcp dport { 80, 8080 }`,
`iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }`. One rule replaces several
identical ones; its content no longer changes, unless the rule is replaced.

### @@sec:named-sets@@ Named sets

A **named set** is an object of the table, looked up by several rules (`@name`), whose content
is changed **without touching the rules**:

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
nft 'delete element inet filter admins { 192.0.2.20 }'
```

The `type` sets the nature of the elements: `ipv4_addr`, `ipv6_addr`, `ether_addr` (MAC
address), `inet_service` (port), `inet_proto` (protocol). The `flags` set its behaviour:

| declaration | effect |
|-------------|--------|
| `flags interval;` | the elements may be networks or ranges (`192.0.2.0/24`); without this flag, single values only |
| `flags timeout; timeout 1h;` | the elements disappear by themselves after that time |
| `flags dynamic;` | the rules may add elements themselves, as packets go by |

An element may gather several fields, separated by a dot: with a set of type
`ipv4_addr . inet_service`, the rule `ip saddr . tcp dport @allowed accept` accepts the pairs
(address, port) it holds.

### @@sec:dynamic-sets@@ Sets fed by the rules

A **dynamic set** is filled **by the rules themselves**, as packets go by, and its elements can
**expire**:

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

- each packet reaching the rule `add @banned { ip saddr }` gets its source address added to the
  set; the element disappears by itself 60 seconds later. `update` instead of `add` restarts
  the timer at each packet;
- `add @banned …` is not a verdict: the packet goes on to the next rule;
- `nft list set inet filter banned` shows the elements and the time they have left (`expires
  54s768ms`); `nft flush set inet filter banned` empties the set.

**The place of the rules matters.** The rule looking the set up (`ip saddr @banned drop`) only
cuts the exchanges already in progress when it is placed **before the stateful rule**; after
it, it only sees the openings. This is how a temporary ban, a limit per address or *port
knocking* are built.

### @@sec:vmaps@@ Verdict maps

A **verdict map** (`vmap`) associates a verdict with each value of a field, in a single lookup:

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 80 : accept, 23 : drop }'
nft 'add rule inet filter forward oifname vmap { eth1 : jump to_dmz, eth2 : jump to_int }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
```

A packet whose field is not a key of the map goes on to the next rule.
""",
        """

Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Choisir le hook d'une chaîne, c'est choisir **quels
paquets** elle verra.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hook-list@@ Les hooks

- **`prerouting`** : tous les paquets **reçus**, avant la décision de routage (« ce paquet est-il
  pour moi, ou à faire suivre ? ») ;
- **`input`** : les paquets **destinés à la machine** (à l'une de ses adresses, quelle que soit
  l'interface d'arrivée) ;
- **`forward`** : les paquets que la machine **route** : ni émis par elle, ni pour elle ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`postrouting`** : tous les paquets qui **partent**, routés ou émis localement ;
- **`ingress`** et **`egress`** : deux hooks placés au ras d'une interface, que la chaîne nomme
  (`device`). `ingress` voit tout ce que l'interface reçoit, avant `prerouting` (donc avant le
  suivi de connexion et le routage) ; `egress` tout ce qu'elle émet, après `postrouting`.

Le filtrage se fait dans **`input`**, **`forward`** et **`output`** ; `prerouting` et
`postrouting` servent surtout à la traduction d'adresses (NAT), `ingress` à détruire au plus tôt
un trafic indésirable.

### @@sec:three-paths@@ Un paquet, une seule des trois chaînes

| paquet | hooks traversés, dans l'ordre |
|--------|-------------------------------|
| reçu et destiné à la machine | `prerouting`, `input` |
| reçu et routé vers une autre machine | `prerouting`, `forward`, `postrouting` |
| émis par la machine | `output`, `postrouting` |

Un paquet ne passe donc que par **une** des trois chaînes `input`, `forward` et `output`.
Conséquences :

- sur un routeur, `forward` ne protège pas le routeur lui-même (un `ping` *vers* le routeur passe
  par `input`) et `input` ne filtre rien de ce qui le traverse : il faut les deux ;
- un échange a **deux sens**. Sur un poste client, la requête sort par `output` et la réponse
  entre par `input`. À travers un routeur, la requête **et** la réponse passent par `forward`,
  avec les interfaces d'entrée et de sortie inversées ;
- un paquet d'une machine vers elle-même (`127.0.0.1`, ou sa propre adresse) passe par `output`
  puis par `input`, à travers l'interface `lo` : une politique `drop` en `input` casse aussi les
  communications locales ;
- `forward` ne voit des paquets que si le routage est activé (`sysctl net.ipv4.ip_forward`).

### @@sec:chain-roles@@ Ce que protège chaque chaîne

| chaîne | paquets | ce qu'elle protège | politique habituelle |
|--------|---------|--------------------|----------------------|
| `input` | destinés à la machine | les services de la machine, routeur compris | `drop` |
| `forward` | qui traversent le routeur | les machines des zones derrière lui | `drop` |
| `output` | émis par la machine | le reste du réseau, contre la machine elle-même | `accept`, avec quelques interdictions |

### @@sec:families@@ Les familles

Une table appartient à une **famille**, qui fixe les paquets que ses chaînes voient et les hooks
dont elles disposent :

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip`, `ip6` | IPv4, IPv6 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

Pour filtrer, on prend la famille **`inet`** : les mêmes règles valent pour IPv4 et pour IPv6.
ARP n'est pas de l'IP : une chaîne `inet` ne voit ni les requêtes ni les réponses ARP, et une
politique `drop` n'empêche pas une machine de trouver l'adresse MAC de ses voisines.
""": """

A **hook** is a place on the path of a packet in the kernel where Netfilter calls the chains
attached to it. Choosing the hook of a chain is choosing **which packets** it will see.

```
                              +--------- local processes --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (per interface)          (routing)                                               (per interface)
```

### @@sec:hook-list@@ The hooks

- **`prerouting`**: every packet **received**, before the routing decision ("is this packet for
  me, or to be forwarded?");
- **`input`**: the packets **addressed to the machine** (to one of its addresses, whatever the
  arrival interface);
- **`forward`**: the packets the machine **routes**: neither sent by it, nor for it;
- **`output`**: the packets **sent by the processes of the machine**;
- **`postrouting`**: every packet that **leaves**, routed or sent locally;
- **`ingress`** and **`egress`**: two hooks placed right at an interface, which the chain names
  (`device`). `ingress` sees everything the interface receives, before `prerouting` (hence
  before connection tracking and routing); `egress` everything it sends, after `postrouting`.

Filtering is done in **`input`**, **`forward`** and **`output`**; `prerouting` and `postrouting`
are mostly used for address translation (NAT), `ingress` to drop unwanted traffic as early as
possible.

### @@sec:three-paths@@ One packet, only one of the three chains

| packet | hooks crossed, in order |
|--------|-------------------------|
| received and addressed to the machine | `prerouting`, `input` |
| received and routed to another machine | `prerouting`, `forward`, `postrouting` |
| sent by the machine | `output`, `postrouting` |

A packet therefore goes through only **one** of the three chains `input`, `forward` and
`output`. Consequences:

- on a router, `forward` does not protect the router itself (a `ping` *to* the router goes
  through `input`) and `input` filters nothing of what crosses it: both are needed;
- an exchange has **two directions**. On a client, the request leaves through `output` and the
  reply comes in through `input`. Across a router, the request **and** the reply go through
  `forward`, with the input and output interfaces swapped;
- a packet from a machine to itself (`127.0.0.1`, or its own address) goes through `output` then
  through `input`, over the interface `lo`: a policy `drop` in `input` also breaks local
  communications;
- `forward` only sees packets when routing is enabled (`sysctl net.ipv4.ip_forward`).

### @@sec:chain-roles@@ What each chain protects

| chain | packets | what it protects | usual policy |
|-------|---------|------------------|--------------|
| `input` | addressed to the machine | the services of the machine, a router included | `drop` |
| `forward` | crossing the router | the machines of the zones behind it | `drop` |
| `output` | sent by the machine | the rest of the network, against the machine itself | `accept`, with a few prohibitions |

### @@sec:families@@ Families

A table belongs to a **family**, which sets the packets its chains see and the hooks they may
use:

| family | packets seen | hooks |
|--------|--------------|-------|
| `ip`, `ip6` | IPv4, IPv6 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `inet` | IPv4 and IPv6 | the same five, and `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | the frames crossing a Linux bridge | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | everything going through an interface | `ingress`, `egress` |

To filter, take the **`inet`** family: the same rules hold for IPv4 and for IPv6. ARP is not
IP: an `inet` chain sees neither ARP requests nor ARP replies, and a policy `drop` does not
prevent a machine from finding the MAC address of its neighbours.
""",
        """

Un **pare-feu** applique une politique aux paquets : les accepter, les détruire ou les refuser.
Sous Linux il s'écrit avec **nftables** (commande **`nft`**) : des règles accrochées aux points
de passage des paquets dans le noyau, que fournit **Netfilter**. Ce cours rappelle d'abord
l'essentiel de nftables, puis traite ce qui fait l'objet de ce TP : filtrer ce qui **sort**
d'une machine et, surtout, ce qui **traverse un routeur**. Les machines du TP ont nftables 1.0.6
(`nft --version`), la version de Debian 12.

**Comment lire ce cours.** Les questions 2 et 3 (le pare-feu d'un poste, puis d'un serveur)
s'appuient sur les sections @@ref:hooks@@ à @@ref:conntrack@@ ; la question 4 (la chaîne
`output`) sur les sections @@ref:verdicts@@ et @@ref:output@@ ; les questions 5 et 6 (le routeur)
sur les sections @@ref:chain-roles@@ et @@ref:forward@@ ; la question 7 sur la
section @@ref:sets@@ (les ensembles). La section @@ref:testing@@ sert tout au long du TP.

### @@sec:two-places@@ Deux places pour un pare-feu

- sur **une machine** qu'il protège (*host firewall*) : il filtre ce qui **entre** dans la
  machine et, plus rarement, ce qui en **sort** (interdire à un poste d'envoyer du courrier
  directement, par exemple) ;
- sur **un routeur** (*network firewall*) : il filtre ce qui **traverse** le routeur, entre des
  **zones** de confiance différentes. Le routeur est lui-même une machine à protéger.

Les deux se complètent. Le pare-feu du routeur protège tout un réseau d'un coup, mais il ne voit
pas ce que les machines d'une même zone échangent entre elles ; celui d'une machine la protège
aussi de ses voisines.

### @@sec:dmz@@ Les zones et la DMZ

Le découpage classique compte trois zones, chacune derrière une interface du routeur :

- l'**extérieur** (Internet) : on n'y maîtrise rien ;
- le **réseau interne** : les postes de travail. Ils ouvrent des connexions vers l'extérieur,
  mais **aucune** connexion ne doit y entrer ;
- la **DMZ** (*zone démilitarisée*) : les serveurs que l'extérieur doit pouvoir joindre (web,
  DNS, courrier). Ils sont **isolés** du réseau interne : un serveur exposé finit par être
  attaqué, et un serveur compromis ne doit pas donner accès aux postes.

### @@sec:matrix@@ La matrice des flux

Une politique de filtrage se résume par une **matrice des flux** : pour chaque couple (zone
source, zone destination), les services autorisés. Tout le reste est interdit :

| de ↓ vers → | extérieur | DMZ | interne |
|-------------|-----------|-----|---------|
| **extérieur** | — | les services publiés (HTTP d'un serveur…) | rien |
| **DMZ** | le strict nécessaire (DNS d'un serveur…) | — | rien |
| **interne** | la navigation (HTTP, DNS) | les services de la DMZ | — |

Chaque case décrit qui a le droit d'**ouvrir** un échange ; les réponses reviennent d'elles-mêmes
(section @@ref:conntrack@@). La règle d'or : **tout ce qui n'est pas explicitement autorisé est
interdit**. On l'obtient avec une politique par défaut `drop` et une règle par flux autorisé,
jamais l'inverse.
""": """

A **firewall** applies a policy to packets: accept them, drop them or reject them. Under Linux
it is written with **nftables** (the **`nft`** command): rules hooked to the places packets go
through in the kernel, provided by **Netfilter**. This course first recalls the essentials of
nftables, then deals with the subject of this lab: filtering what **leaves** a machine and,
above all, what **crosses a router**. The machines of the lab have nftables 1.0.6
(`nft --version`), the version of Debian 12.

**How to read this course.** Questions 2 and 3 (the firewall of a workstation, then of a server)
rely on sections @@ref:hooks@@ to @@ref:conntrack@@; question 4 (the `output` chain) on
sections @@ref:verdicts@@ and @@ref:output@@; questions 5 and 6 (the router) on
sections @@ref:chain-roles@@ and @@ref:forward@@; question 7 on section @@ref:sets@@ (sets).
Section @@ref:testing@@ is useful throughout the lab.

### @@sec:two-places@@ Two places for a firewall

- on **a machine** it protects (*host firewall*): it filters what **enters** the machine and,
  more rarely, what **leaves** it (forbidding a workstation to send mail directly, for
  instance);
- on **a router** (*network firewall*): it filters what **crosses** the router, between **zones**
  of different trust. The router is itself a machine to protect.

The two complement each other. The firewall of the router protects a whole network at once, but
it does not see what the machines of one zone exchange with each other; the firewall of a
machine also protects it from its neighbours.

### @@sec:dmz@@ Zones and the DMZ

The classic layout has three zones, each one behind an interface of the router:

- the **outside** (the Internet): nothing there is under control;
- the **internal network**: the workstations. They open connections to the outside, but **no**
  connection may come in;
- the **DMZ** (*demilitarised zone*): the servers the outside must reach (web, DNS, mail). They
  are **isolated** from the internal network: an exposed server ends up being attacked, and a
  compromised server must not give access to the workstations.

### @@sec:matrix@@ The flow matrix

A filtering policy is summed up by a **flow matrix**: for each pair (source zone, destination
zone), the services allowed. Everything else is forbidden:

| from ↓ to → | outside | DMZ | internal |
|-------------|---------|-----|----------|
| **outside** | — | the published services (the HTTP of one server…) | nothing |
| **DMZ** | the bare minimum (the DNS of one server…) | — | nothing |
| **internal** | browsing (HTTP, DNS) | the services of the DMZ | — |

Each cell says who may **open** an exchange; the replies come back by themselves
(section @@ref:conntrack@@). The golden rule: **whatever is not explicitly allowed is
forbidden**. It is obtained with a default policy `drop` and one rule per allowed flow, never
the other way round.
""",
        """

Un critère compare un champ du paquet, ou une information que le noyau lui associe, à une
valeur. Les critères d'une règle sont **tous** requis (un **et**) ; pour un **ou**, on utilise un
ensemble de valeurs ou plusieurs règles.

### @@sec:selector-list@@ Les principaux critères

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname eth0` | interface d'**entrée** du paquet (connue dans `input` et `forward`, pas dans `output`) |
| `oif eth1`, `oifname eth1` | interface de **sortie** (connue dans `forward` et `output`, pas dans `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | adresse ou réseau **source** |
| `ip daddr 192.0.2.10` | adresse ou réseau **destination** |
| `meta l4proto tcp`, `ip protocol udp` | protocole de transport (`tcp`, `udp`, `icmp`) ; `meta l4proto` vaut aussi pour IPv6 |
| `tcp dport 80`, `udp dport 53` | port **destination** : le service demandé |
| `tcp sport 80`, `udp sport 53` | port **source** : dans une réponse, le port du serveur |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête et réponse) |
| `ct state established,related`, `ct state new` | état dans le suivi de connexion (section @@ref:conntrack@@) |

**`iif` ou `iifname` ?** `iif lo` compare le numéro (l'index) de l'interface : c'est rapide,
mais l'interface doit exister quand la règle est chargée. `iifname eth0` compare son nom : un
peu plus lent, mais valable pour une interface qui n'existe pas encore. `nft list ruleset`
réaffiche les noms entre guillemets (`iifname "eth0"`).

### @@sec:values@@ Les formes de valeur

| forme | exemples |
|-------|----------|
| une valeur, un réseau | `tcp dport 22`, `ip saddr 192.0.2.0/24` |
| une plage | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| un ensemble | `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }` |
| un ensemble nommé | `ip saddr @admins` (section @@ref:sets@@) |
| la négation | `ip daddr != 192.0.2.10`, `tcp dport != { 80, 8080 }` |

Nommer un champ implique le protocole qui le porte : `tcp dport 80` ne concerne que TCP, `icmp
type echo-request` que ICMP. Dans une table `inet`, `tcp dport 80 accept` vaut pour IPv4 et pour
IPv6, alors qu'un critère `ip …` restreint la règle à IPv4. `nft describe icmp type` liste les
valeurs possibles d'un champ.

### @@sec:direction@@ D'où vient le paquet, où va-t-il

Une règle de pare-feu de réseau dit en général **d'où** vient le paquet et **où** il va, puis
le service :

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

L'interface désigne la **zone**, l'adresse une **machine** de cette zone. Filtrer sur l'adresse
source seule est fragile : une adresse se falsifie (*spoofing*, section @@ref:spoofing@@). Pour
une règle sensible, on exige **l'interface et l'adresse** : `iifname eth2 ip saddr 192.0.2.10
tcp dport 22 accept` n'accepte la machine d'administration que si elle arrive du bon côté.
""": """

A selector compares a field of the packet, or a piece of information the kernel attaches to
it, with a value. The selectors of a rule are **all** required (an **and**); for an **or**, use
a set of values or several rules.

### @@sec:selector-list@@ The main selectors

| selector | meaning |
|----------|---------|
| `iif lo`, `iifname eth0` | **input** interface of the packet (known in `input` and `forward`, not in `output`) |
| `oif eth1`, `oifname eth1` | **output** interface (known in `forward` and `output`, not in `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | **source** address or network |
| `ip daddr 192.0.2.10` | **destination** address or network |
| `meta l4proto tcp`, `ip protocol udp` | transport protocol (`tcp`, `udp`, `icmp`); `meta l4proto` also holds for IPv6 |
| `tcp dport 80`, `udp dport 53` | **destination** port: the service asked for |
| `tcp sport 80`, `udp sport 53` | **source** port: in a reply, the port of the server |
| `icmp type echo-request`, `icmp type echo-reply` | ICMP type (`ping`: request and reply) |
| `ct state established,related`, `ct state new` | state in connection tracking (section @@ref:conntrack@@) |

**`iif` or `iifname`?** `iif lo` compares the number (the index) of the interface: it is fast,
but the interface must exist when the rule is loaded. `iifname eth0` compares its name: a little
slower, but valid for an interface that does not exist yet. `nft list ruleset` prints the names
between double quotes (`iifname "eth0"`).

### @@sec:values@@ The forms of a value

| form | examples |
|------|----------|
| a value, a network | `tcp dport 22`, `ip saddr 192.0.2.0/24` |
| a range | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| a set | `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`, `icmp type { echo-request, echo-reply }` |
| a named set | `ip saddr @admins` (section @@ref:sets@@) |
| negation | `ip daddr != 192.0.2.10`, `tcp dport != { 80, 8080 }` |

Naming a field implies the protocol that carries it: `tcp dport 80` only concerns TCP, `icmp
type echo-request` only ICMP. In an `inet` table, `tcp dport 80 accept` holds for IPv4 and for
IPv6, whereas a selector `ip …` restricts the rule to IPv4. `nft describe icmp type` lists the
possible values of a field.

### @@sec:direction@@ Where the packet comes from, where it goes

A rule of a network firewall generally says **where** the packet comes from and **where** it
goes, then the service:

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

The interface names the **zone**, the address a **machine** of that zone. Filtering on the
source address alone is fragile: an address can be forged (*spoofing*,
section @@ref:spoofing@@). For a sensitive rule, require **the interface and the address**:
`iifname eth2 ip saddr 192.0.2.10 tcp dport 22 accept` only accepts the administration machine
when it arrives from the right side.
""",
        """

Un jeu de règles (*ruleset*) est fait de **tables**, qui contiennent des **chaînes**, qui
contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table ni chaîne
prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des chaînes sont
libres ; `filter`, `input` ou `forward` ne sont que des habitudes.

### @@sec:base-chains@@ Tables et chaînes de base

Une **chaîne de base** est accrochée à un hook. Sa déclaration donne son **type**, son **hook**,
sa **priorité** et sa **politique**. Une même table peut porter une chaîne par hook :

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

- le **type** : `filter` pour filtrer ; `nat` pour la traduction d'adresses ; `route` (au hook
  `output`) pour refaire le routage d'un paquet qu'une règle a modifié ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus petite
  valeur à la plus grande. Les valeurs usuelles ont un nom : `raw` (-300), `mangle` (-150),
  `dstnat` (-100), `filter` (0), `security` (50), `srcnat` (100). `nft list ruleset` affiche
  `priority filter` pour 0. Le suivi de connexion opère à la priorité -200 : une chaîne `filter`
  voit des paquets dont l'état est déjà connu ;
- la **politique** : `accept` ou `drop`, le verdict des paquets qu'aucune règle n'a tranchés.
  Sans `policy`, c'est `accept` ; `reject` n'est pas une politique possible.

Les apostrophes protègent du shell les accolades et les points-virgules. Déclarer de nouveau une
chaîne existante, à l'identique mais avec une autre politique, **change sa politique** sans
toucher à ses règles.

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées au
même hook : un paquet les traverse **toutes**, par priorité croissante. **`drop` est définitif** :
le paquet est détruit sur-le-champ. **`accept` ne vaut que pour la chaîne en cours** : le paquet
passe à la chaîne suivante, puis aux hooks suivants, qui peuvent encore le détruire. On ne
« rattrape » donc pas dans une table un paquet qu'une autre a détruit.

### @@sec:regular-chains@@ Les chaînes régulières

Une **chaîne régulière** n'a ni hook, ni type, ni politique (`nft add chain inet filter
int_ext`). Elle ne voit que les paquets qu'une règle lui envoie, par **`jump`** ou par
**`goto`**, depuis une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump`,
l'évaluation **reprend dans la chaîne appelante**, à la règle qui suit le saut ; avec `goto`,
elle n'y revient pas. Ces chaînes servent à structurer un jeu de règles : une chaîne par couple
de zones sur un routeur (section @@ref:zone-chains@@), une chaîne « journaliser puis détruire »
(section @@ref:logging@@).

### @@sec:rules@@ Les règles : l'ordre compte

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des critères
(section @@ref:selectors@@), puis des actions et, le plus souvent, un verdict
(section @@ref:verdicts@@). Dès qu'un critère n'est pas satisfait, le paquet passe à la règle
suivante. Les règles d'une chaîne sont évaluées **dans l'ordre** ; la première règle satisfaite
qui porte un verdict décide, et les suivantes ne sont pas consultées : une règle `accept` placée
après une règle `reject` qui couvre les mêmes paquets ne sert à rien. L'ordre se choisit à
l'ajout :

```
nft add rule inet filter input iif lo accept           # à la FIN de la chaîne
nft insert rule inet filter input iif lo accept        # au DÉBUT
nft -a list ruleset                                    # affiche le numéro (handle) de chaque règle
nft insert rule inet filter input handle 7 …           # avant la règle 7 (add rule … handle 7 : après)
nft replace rule inet filter input handle 7 …          # remplace la règle 7
nft delete rule inet filter input handle 7             # supprime la règle 7
nft flush chain inet filter output                     # vide une chaîne (sa politique reste)
nft delete table inet filter                           # supprime la table et tout son contenu
```

Le **handle** d'une règle est un numéro que le noyau lui attribue et qui ne change plus : ce
n'est pas un numéro de ligne. **Le shell passe avant `nft`** : dès qu'une commande contient des
accolades, un point-virgule, des guillemets ou un `*`, entourez d'apostrophes tout ce qui suit
`nft`.

### @@sec:files@@ Un pare-feu dans un fichier

Dès qu'un pare-feu dépasse quelques règles, on l'écrit dans un **fichier**, dans la syntaxe
qu'affiche `nft list ruleset`, et on le recharge d'un bloc avec `nft -f /root/firewall.nft` :
c'est plus sûr que de retoucher les règles une à une, et l'ordre y est lisible.

```
flush ruleset

define ADMIN = 192.0.2.10

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        # un commentaire : SSH pour la machine d'administration
        ip saddr $ADMIN tcp dport 22 accept
        tcp dport 80 accept
    }
}
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; `nft -c -f /root/firewall.nft` le vérifie sans rien changer ;
- le fichier commence par **`flush ruleset`** : sans cela, le recharger ajouterait ses règles
  une seconde fois, à la suite des premières ;
- `define` nomme une valeur, reprise par `$NOM` ;
- `nft -s list ruleset > /root/firewall.nft` écrit un tel fichier à partir des règles en place
  (ajoutez-lui `flush ruleset` en tête) ;
- les règles tapées avec `nft` sont **volatiles** : elles disparaissent au redémarrage. Sous
  Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage.
""": """

A ruleset is made of **tables**, which hold **chains**, which hold **rules**. At the start it is
**empty**: nftables has no predefined table nor chain, and without a chain every packet goes
through. The names of tables and chains are free; `filter`, `input` or `forward` are only
habits.

### @@sec:base-chains@@ Tables and base chains

A **base chain** is attached to a hook. Its declaration gives its **type**, its **hook**, its
**priority** and its **policy**. One table can carry one chain per hook:

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

- the **type**: `filter` to filter; `nat` for address translation; `route` (at the `output`
  hook) to route again a packet a rule has modified;
- the **priority**: an integer ordering the chains attached to the same hook, from the lowest
  value to the highest. The usual values have a name: `raw` (-300), `mangle` (-150), `dstnat`
  (-100), `filter` (0), `security` (50), `srcnat` (100). `nft list ruleset` prints `priority
  filter` for 0. Connection tracking works at priority -200: a `filter` chain sees packets whose
  state is already known;
- the **policy**: `accept` or `drop`, the verdict of the packets no rule has settled. Without
  `policy`, it is `accept`; `reject` is not a possible policy.

The single quotes protect the braces and the semicolons from the shell. Declaring an existing
chain again, identically but with another policy, **changes its policy** without touching its
rules.

Several base chains, of the same table or of different tables, may be attached to the same hook:
a packet goes through **all** of them, by increasing priority. **`drop` is final**: the packet
is destroyed at once. **`accept` only holds for the current chain**: the packet goes on to the
next chain, then to the next hooks, which may still drop it. So a packet dropped by one table
cannot be "rescued" by another.

### @@sec:regular-chains@@ Regular chains

A **regular chain** has no hook, no type and no policy (`nft add chain inet filter int_ext`).
It only sees the packets a rule sends to it, with **`jump`** or **`goto`**, from another chain
of the same table. At the end of a chain reached by `jump`, evaluation **resumes in the calling
chain**, at the rule following the jump; with `goto`, it does not come back. These chains give
a ruleset its structure: one chain per pair of zones on a router
(section @@ref:zone-chains@@), a "log then drop" chain (section @@ref:logging@@).

### @@sec:rules@@ Rules: order matters

A **rule** is a sequence of expressions evaluated **from left to right**: selectors
(section @@ref:selectors@@), then actions and, most often, a verdict
(section @@ref:verdicts@@). As soon as a selector does not match, the packet goes on to the next
rule. The rules of a chain are evaluated **in order**; the first matching rule that carries a
verdict decides, and the following ones are not consulted: an `accept` rule placed after a
`reject` rule covering the same packets is useless. The order is chosen when the rule is added:

```
nft add rule inet filter input iif lo accept           # at the END of the chain
nft insert rule inet filter input iif lo accept        # at the BEGINNING
nft -a list ruleset                                    # prints the number (handle) of each rule
nft insert rule inet filter input handle 7 …           # before rule 7 (add rule … handle 7: after)
nft replace rule inet filter input handle 7 …          # replaces rule 7
nft delete rule inet filter input handle 7             # deletes rule 7
nft flush chain inet filter output                     # empties a chain (its policy stays)
nft delete table inet filter                           # deletes the table and all its content
```

The **handle** of a rule is a number the kernel gives it and that never changes afterwards: it
is not a line number. **The shell comes before `nft`**: as soon as a command holds braces, a
semicolon, double quotes or a `*`, put single quotes around everything that follows `nft`.

### @@sec:files@@ A firewall in a file

As soon as a firewall has more than a few rules, write it in a **file**, in the syntax `nft list
ruleset` prints, and reload it in one go with `nft -f /root/firewall.nft`: it is safer than
editing the rules one by one, and the order can be read there.

```
flush ruleset

define ADMIN = 192.0.2.10

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        # a comment: SSH for the administration machine
        ip saddr $ADMIN tcp dport 22 accept
        tcp dport 80 accept
    }
}
```

- loading is **atomic**: the file is applied as a whole or, at the slightest error, not at all;
  `nft -c -f /root/firewall.nft` checks it without changing anything;
- the file starts with **`flush ruleset`**: without it, loading it again would add its rules a
  second time, after the first ones;
- `define` names a value, used again as `$NAME`;
- `nft -s list ruleset > /root/firewall.nft` writes such a file from the rules in place (add
  `flush ruleset` at its top);
- the rules typed with `nft` are **volatile**: they are gone after a reboot. Under Debian, the
  `nftables` service loads `/etc/nftables.conf` at boot.
""",
        """

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table et chaînes | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (de même `input`, `output`) |
| règles | `nft add rule inet filter forward …` (fin), `nft insert rule …` (début), `nft insert rule inet filter forward handle N …` (avant la règle N), `nft replace rule inet filter forward handle N …`, `nft delete rule inet filter forward handle N` |
| critères | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts et actions | `accept`, `drop`, `reject`, `jump chaine`, `counter`, `log prefix "…" group 0` (lu avec `tcpdump -n -i nflog:0`) |
| ensembles | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| fichier | `nft -c -f /root/firewall.nft` (vérifier), `nft -f /root/firewall.nft` (charger ; le fichier commence par `flush ruleset`), `nft -s list ruleset > /root/firewall.nft` (sauvegarder) |
| tout effacer | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S nom +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""": """

| need | command |
|------|---------|
| state of the firewall | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table and chains | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (likewise `input`, `output`) |
| rules | `nft add rule inet filter forward …` (end), `nft insert rule …` (beginning), `nft insert rule inet filter forward handle N …` (before rule N), `nft replace rule inet filter forward handle N …`, `nft delete rule inet filter forward handle N` |
| selectors | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts and actions | `accept`, `drop`, `reject`, `jump chain`, `counter`, `log prefix "…" group 0` (read with `tcpdump -n -i nflog:0`) |
| sets | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| file | `nft -c -f /root/firewall.nft` (check), `nft -f /root/firewall.nft` (load; the file starts with `flush ruleset`), `nft -s list ruleset > /root/firewall.nft` (save) |
| erase everything | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S name +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
| following a packet | `… counter …` then `nft list ruleset`; `meta nftrace set 1` and `nft monitor trace` |
""",
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) vide les jeux de règles de `ext1` et
de `router`, applique toute la solution, fait de `dmz2` le serveur DNS de `int1` et remplit les
formulaires ; il est ré-applicable et une évaluation lancée juste après donne 100/100, plus les
points de bonus de la question 7.

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) se fait en deux temps, parce
que les deux pare-feux se masqueraient l'un l'autre (après la question 6, `router` ne laisse plus
passer le SSH de `int1` vers `ext1`) :

1. étape 1 : `nft list ruleset` et `nft -j list ruleset` sur `ext1` et `router` ;
2. étapes {load1} et {probe1} : le jeu de règles de `ext1` est chargé sur `{host_h}`, celui de
   `{router_h}` est vidé (routeur ouvert), puis les sondes des questions 2 à 4 ;
3. étapes {load2} et {probe2} : `{host_h}` est vidée, le jeu de règles de `router` est chargé sur
   `{router_h}`, puis les sondes des questions 5 et 6 ;
4. étapes {trap} et {ban} : la question 7 (une tentative SSH de `{host_h}` vers `int2`, puis HTTP
   de `int2` vers `ext1` et `ext2`).

Les sondes : `curl` des serveurs de test, `dig +time=2 +tries=1` (`{name}.{domain}`), `ping -c 1
-W 2`, connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert, `RC=124` détruit,
autre code refusé). Les copies cachées répondent sous les noms visibles. La structure (politiques,
règle à états, ensemble) est lue dans `nft -j list ruleset`. Ce qu'un pare-feu **laisse passer** ne
compte qu'une fois sa politique `drop` en place : un jeu de règles vide laisse tout passer et vaut 0.
Une évaluation dure environ 25 secondes quand tout est en place (les sondes que les pare-feux
doivent détruire attendent leur délai), une ou deux secondes sans pare-feu.
""": """
**For the instructor.** Each question ends with its solution, computed for the addresses of this
project. The state `final` (*Apply Configuration* tab) flushes the rulesets of `ext1` and
`router`, applies the whole solution, makes `dmz2` the DNS server of `int1` and fills the forms;
it can be applied again and an evaluation run right after gives 100/100, plus the bonus points
of question 7.

The evaluation (hidden mirror, `lib/hidden_mirror.py` / `lib/firewall.py`) runs in two phases,
because the two firewalls would hide each other (after question 6, `router` no longer lets the
SSH of `int1` through to `ext1`):

1. step 1: `nft list ruleset` and `nft -j list ruleset` on `ext1` and `router`;
2. steps {load1} and {probe1}: the ruleset of `ext1` is loaded on `{host_h}`, the one of
   `{router_h}` is flushed (open router), then the probes of questions 2 to 4;
3. steps {load2} and {probe2}: `{host_h}` is flushed, the ruleset of `router` is loaded on
   `{router_h}`, then the probes of questions 5 and 6;
4. steps {trap} and {ban}: question 7 (an SSH attempt from `{host_h}` to `int2`, then HTTP from
   `int2` to `ext1` and `ext2`).

The probes: `curl` of the test servers, `dig +time=2 +tries=1` (`{name}.{domain}`), `ping -c 1
-W 2`, TCP connections with `bash` (`/dev/tcp`, timeout {timeout} s: `RC=0` open, `RC=124`
dropped, another code refused). The hidden copies answer under the visible names. The structure
(policies, stateful rule, set) is read in `nft -j list ruleset`. What a firewall **lets through**
only counts once its `drop` policy is in place: an empty ruleset passes everything and is worth 0.
An evaluation takes about 25 seconds once everything is in place (the probes the firewalls must
drop wait for their timeout), one or two seconds without a firewall.
""",
        """
**Solution.** (a) puis (b), sur `ext1` :

```
{chain}
nft add rule inet filter output tcp dport {mail} drop
nft flush chain inet filter output
nft add rule inet filter output tcp dport {mail} reject
```

Avec `drop`, le SYN est détruit avant de quitter `ext1` : `nc` attend ses 5 secondes (`timed out:
Operation now in progress`). Avec `reject`, le noyau fabrique un message ICMP *port unreachable*
pour le programme, qui échoue aussitôt (`Connection refused`) ; ce message revient par `lo`, que
la règle `iif lo accept` de `input` laisse passer (sans elle, `nc` attendrait comme avec `drop`).
(c) l'exception doit précéder le refus ; après `nft flush chain inet filter output`, la chaîne
devient :

```
{cmds}```

(une seule règle `ip daddr != {ext2} tcp dport {mail} reject` convient aussi.)

- Réponses : délai avec `drop` ; refus immédiat avec `reject`.
- L'évaluation, depuis la copie de `ext1` : connexion TCP vers le port {mail} de `ext2` (ouverte)
  et de `dmz1` (refusée immédiatement ; un simple délai, c'est-à-dire un `drop`, ne donne qu'une
  partie des points), et une règle `reject` ou `drop` sur `tcp dport {mail}` dans une chaîne du
  hook `output`.
""": """
**Solution.** (a) then (b), on `ext1`:

```
{chain}
nft add rule inet filter output tcp dport {mail} drop
nft flush chain inet filter output
nft add rule inet filter output tcp dport {mail} reject
```

With `drop`, the SYN is dropped before leaving `ext1`: `nc` waits its 5 seconds (`timed out:
Operation now in progress`). With `reject`, the kernel builds an ICMP *port unreachable* message
for the program, which fails at once (`Connection refused`); this message comes back through
`lo`, which the rule `iif lo accept` of `input` lets through (without it, `nc` would wait as with
`drop`). (c) the exception must come before the refusal; after `nft flush chain inet filter
output`, the chain becomes:

```
{cmds}```

(a single rule `ip daddr != {ext2} tcp dport {mail} reject` does as well.)

- Answers: a timeout with `drop`; an immediate refusal with `reject`.
- The evaluation, from the copy of `ext1`: a TCP connection to port {mail} of `ext2` (open) and
  of `dmz1` (refused at once; a mere timeout, that is a `drop`, only gives part of the points),
  and a `reject` or `drop` rule on `tcp dport {mail}` in a chain of the `output` hook.
""",
        """
**Solution.** Les trois commandes de l'énoncé. La chaîne `forward` commence alors par la règle
`ip saddr @{set} drop`, puis la règle `tcp dport {ssh} add @{set} {{ ip saddr }}`, puis la règle à
états. Un paquet de l'extérieur vers le port {ssh} d'une machine interne fait ajouter son adresse
source à l'ensemble `{set}` (puis il est détruit par la politique) ; pendant {seconds} secondes,
**tout** paquet de cette adresse vers la zone interne est détruit par la première règle, placée
**avant** la règle à états : même les réponses aux connexions ouvertes par la zone interne (étape
3 : `curl` vers `ext1` expire, vers `ext2` répond). `nft list set inet filter {set}` montre
l'adresse de `ext1` et le temps qui lui reste (`expires …`). C'est l'équivalent du module `recent`
d'iptables (`--set`, puis `--rcheck --seconds 60`). Placées après la règle à états, les deux règles
ne changeraient rien de visible : les nouvelles connexions de l'extérieur vers la zone interne sont
déjà détruites par la politique.

- Réponse : la machine de l'extérieur est bannie 60 s.
- L'évaluation (bonus) : dans `nft -j list ruleset`, un ensemble alimenté par une règle de
  `forward` (`add` ou `update`, `ip saddr`, `tcp dport {ssh}`) dont les éléments expirent après
  {seconds} s, et une règle `drop` sur `ip saddr @…` placée avant la règle à états ; sur les copies
  cachées : HTTP de `int2` vers `ext1` répond, puis `ext1` tente le port {ssh} de `int2`, puis
  HTTP de `int2` vers `ext1` ne répond plus alors que `ext2` répond toujours. L'ensemble de la
  copie est vidé au chargement : un bannissement en cours sur `router` ne fausse pas les autres
  sondes.
""": """
**Solution.** The three commands of the question. The `forward` chain then starts with the rule
`ip saddr @{set} drop`, then the rule `tcp dport {ssh} add @{set} {{ ip saddr }}`, then the
stateful rule. A packet from the outside to port {ssh} of an internal machine gets its source
address added to the set `{set}` (then it is dropped by the policy); for {seconds} seconds,
**every** packet from that address towards the internal zone is dropped by the first rule, placed
**before** the stateful rule: even the replies to the connections opened by the internal zone
(step 3: `curl` to `ext1` times out, to `ext2` it answers). `nft list set inet filter {set}`
shows the address of `ext1` and the time it has left (`expires …`). This is the equivalent of the
`recent` module of iptables (`--set`, then `--rcheck --seconds 60`). Placed after the stateful
rule, the two rules would change nothing visible: the new connections from the outside to the
internal zone are already dropped by the policy.

- Answer: the machine of the outside is banned for 60 s.
- The evaluation (bonus): in `nft -j list ruleset`, a set fed by a rule of `forward` (`add` or
  `update`, `ip saddr`, `tcp dport {ssh}`) whose elements expire after {seconds} s, and a `drop`
  rule on `ip saddr @…` placed before the stateful rule; on the hidden copies: HTTP from `int2`
  to `ext1` answers, then `ext1` tries port {ssh} of `int2`, then HTTP from `int2` to `ext1` no
  longer answers while `ext2` still does. The set of the copy is flushed when it is loaded: a ban
  in progress on `router` does not spoil the other probes.
""",
        """
**Solution.** Rien à configurer. `TTL=63` : la requête de `int1` a traversé un routeur.
`CLIENT_IP={int1}` : `router` route sans traduction d'adresses, `ext2` voit l'adresse réelle de
`int1`. `/etc/resolv.conf` de `ext1` nomme `{ext2}` (`ext2`). `nft list ruleset` n'affiche rien :
aucun filtrage, tout passe.

- Réponses : 63 ; `{int1}` ; `{ext2}` ; rien.
- Cette question n'est évaluée que par le formulaire.
""": """
**Solution.** Nothing to configure. `TTL=63`: the request of `int1` crossed one router.
`CLIENT_IP={int1}`: `router` routes without address translation, `ext2` sees the real address of
`int1`. `/etc/resolv.conf` of `ext1` names `{ext2}` (`ext2`). `nft list ruleset` prints nothing:
no filtering, everything passes.

- Answers: 63; `{int1}`; `{ext2}`; nothing.
- This question is only graded by the form.
""",
        """
**Solution.** Sur `ext1` :

```
{cmds}```

Après (a), plus rien n'entre, pas même les réponses DNS : `curl http://ext2/` échoue sur `Could not
resolve host` (avec l'adresse, c'est la connexion TCP qui expire). (c) `udp sport 53` et `ip saddr`
désignent le serveur, `ct state established` n'accepte que les réponses à une question posée par
`ext1` : sans ce critère, `ext2` pourrait envoyer n'importe quel datagramme depuis son port 53.
(d) `meta l4proto tcp ct state established,related` : le SYN-ACK et la suite de toute connexion
ouverte par `ext1`. (e) deux types ICMP dans un ensemble anonyme (deux règles conviennent aussi).
Une règle générale `ct state established,related accept` satisferait (d) et les réponses de (e),
mais pas (c) : elle accepterait les réponses de n'importe quel serveur DNS.

- L'évaluation, sur la copie cachée de `ext1` : `curl http://127.0.0.1/`, `dig @{ext2}` (réponse)
  et `dig @{dmz1}` (aucune réponse), HTTP vers `ext2` et vers `dmz1:8080` (à travers le routeur),
  `ping` vers `ext2` et `dmz1` ; depuis la copie de `ext2` : `ping` de `ext1` (réponse), `dig
  @{ext1}` (aucune réponse). Dans `nft -j list ruleset` : la politique `drop` de `input` et une
  règle `accept` avec `ip saddr {ext2}`, UDP et `ct state established`.
""": """
**Solution.** On `ext1`:

```
{cmds}```

After (a), nothing comes in any more, not even the DNS replies: `curl http://ext2/` fails with
`Could not resolve host` (with the address, it is the TCP connection that times out). (c) `udp
sport 53` and `ip saddr` name the server, `ct state established` only accepts the replies to a
question asked by `ext1`: without it, `ext2` could send any datagram from its port 53. (d) `meta
l4proto tcp ct state established,related`: the SYN-ACK and what follows of any connection opened
by `ext1`. (e) two ICMP types in an anonymous set (two rules do as well). A general rule `ct
state established,related accept` would satisfy (d) and the replies of (e), but not (c): it would
accept the replies of any DNS server.

- The evaluation, on the hidden copy of `ext1`: `curl http://127.0.0.1/`, `dig @{ext2}` (an
  answer) and `dig @{dmz1}` (no answer), HTTP to `ext2` and to `dmz1:8080` (across the router),
  `ping` to `ext2` and `dmz1`; from the copy of `ext2`: `ping` of `ext1` (a reply), `dig
  @{ext1}` (no answer). In `nft -j list ruleset`: the `drop` policy of `input` and an `accept`
  rule with `ip saddr {ext2}`, UDP and `ct state established`.
""",
        """
**Solution.** Sur `ext1` :

```
{cmds}```

Les nouvelles connexions vers le port {http} sont acceptées d'où qu'elles viennent ; le port {ssh}
n'est ouvert qu'aux adresses source du réseau interne (`ip saddr` prend une adresse ou un réseau).
`ext1` ne voit que l'adresse source, qu'une machine de son propre réseau peut falsifier ; sur le
routeur, on exigera aussi l'interface d'entrée (question 5).

- L'évaluation ouvre des connexions TCP vers la copie de `ext1` : port {http} depuis `ext2` et
  `int1` (ouvert), port {alt} depuis `ext2` (détruit), port {ssh} depuis `int1` et `int2` (ouvert),
  depuis `ext2` et `dmz1` (détruit). Pendant ces sondes, la copie du routeur n'a aucun pare-feu.
""": """
**Solution.** On `ext1`:

```
{cmds}```

New connections to port {http} are accepted wherever they come from; port {ssh} is only open to
the source addresses of the internal network (`ip saddr` takes an address or a network). `ext1`
only sees the source address, which a machine of its own network can forge; on the router, the
input interface will be required too (question 5).

- The evaluation opens TCP connections to the copy of `ext1`: port {http} from `ext2` and `int1`
  (open), port {alt} from `ext2` (dropped), port {ssh} from `int1` and `int2` (open), from `ext2`
  and `dmz1` (dropped). During these probes, the copy of the router has no firewall.
""",
        """
**Solution.** Sur `router` :

```
{cmds}```

(b) la politique `drop` de `forward` coupe tout transit ; `router` joint toujours ses voisins, ses
propres paquets passant par `output` et `input`. (c) seul l'`echo-request` de la zone interne vers
la DMZ est autorisé ; son `echo-reply` revient par la règle à états. (d) le DNS vers `ext2`
seulement, HTTP vers tout l'extérieur sur le port {http}. (e) la règle `ct state
established,related accept`, première de la chaîne, laisse revenir les réponses de tous les flux
autorisés, et elles seules. (f) `iifname {{ eth0, eth2 }}` : `dmz2` est sur le même réseau que
`dmz1` et ne traverse pas le routeur. (g) et (h) : deux règles DNS, l'une par l'adresse source de
`dmz2`, l'autre par son adresse destination. Sur `int1`, `/etc/resolv.conf` devient :

```
{resolv}```

- Réponses : une connexion vers n'importe quel port interne depuis le port source 80 ;
  l'`echo-reply`, `established`.
- L'évaluation, sur les copies cachées (celle de `ext1` n'a plus de pare-feu) : `ping` de `int1`
  vers `dmz1` (réponse) et vers `ext2` (aucune), de `dmz1` vers `int1`, de `ext2` vers `dmz1`, de
  `ext1` vers `int1` (aucune) ; `dig @{ext2}` depuis `int1` (réponse), `dig @{ext1}` depuis `int1`
  (aucune) ; HTTP de `int2` vers `ext2` (réponse), port {alt} de `ext2` depuis `int1` et port
  {http} de `int1` depuis `ext1` (détruits) ; port {http} de `dmz1` depuis `ext2` et `int1`
  (ouvert), port {alt} de `dmz1` et port {http} de `dmz2` depuis l'extérieur (détruits) ; `dig
  @{ext2}` depuis `dmz2` (réponse) et depuis `dmz1` (aucune) ; `dig @{dmz2}` depuis `int1`
  (réponse). Sur `int1`, le premier `nameserver` de `/etc/resolv.conf` doit être `{dmz2}`. Dans
  `nft -j list ruleset` : la politique `drop` de `forward` et une règle `accept` avec `ct state
  established,related`.
""": """
**Solution.** On `router`:

```
{cmds}```

(b) the `drop` policy of `forward` cuts all transit; `router` still reaches its neighbours, its
own packets going through `output` and `input`. (c) only the `echo-request` from the internal
zone to the DMZ is allowed; its `echo-reply` comes back through the stateful rule. (d) the DNS to
`ext2` only, HTTP to the whole outside on port {http}. (e) the rule `ct state
established,related accept`, first of the chain, lets the replies of every allowed flow come
back, and only them. (f) `iifname {{ eth0, eth2 }}`: `dmz2` is on the same network as `dmz1` and
does not cross the router. (g) and (h): two DNS rules, one by the source address of `dmz2`, the
other by its destination address. On `int1`, `/etc/resolv.conf` becomes:

```
{resolv}```

- Answers: a connection to any internal port from source port 80; the `echo-reply`,
  `established`.
- The evaluation, on the hidden copies (the one of `ext1` has no firewall any more): `ping` from
  `int1` to `dmz1` (a reply) and to `ext2` (none), from `dmz1` to `int1`, from `ext2` to `dmz1`,
  from `ext1` to `int1` (none); `dig @{ext2}` from `int1` (an answer), `dig @{ext1}` from `int1`
  (none); HTTP from `int2` to `ext2` (an answer), port {alt} of `ext2` from `int1` and port
  {http} of `int1` from `ext1` (dropped); port {http} of `dmz1` from `ext2` and `int1` (open),
  port {alt} of `dmz1` and port {http} of `dmz2` from the outside (dropped); `dig @{ext2}` from
  `dmz2` (an answer) and from `dmz1` (none); `dig @{dmz2}` from `int1` (an answer). On `int1`,
  the first `nameserver` of `/etc/resolv.conf` must be `{dmz2}`. In `nft -j list ruleset`: the
  `drop` policy of `forward` and an `accept` rule with `ct state established,related`.
""",
        """
**Solution.** Sur `router` :

```
{cmds}```

(c) `iifname {{ eth1, eth2 }}` : les `echo-request` ne sont acceptés que s'ils arrivent par la DMZ
ou la zone interne ; ceux de l'extérieur tombent sur la politique. (d) les `echo-reply` sont
acceptés d'où qu'ils viennent. (e) les réponses DNS de `dmz1` seulement, et le trafic retour TCP
arrivant par `eth0`. (f) `iifname eth2 ip saddr {int1}` : une machine de l'extérieur qui usurperait
l'adresse de `int1` arriverait par `eth0`. Une seule règle `ct state established,related accept`
remplacerait les règles de (d) et (e) : c'est l'usage sur un vrai pare-feu, et elle est acceptée
ici. Ces règles ne concernent que les paquets destinés à `router` : ce qui le traverse passe par
`forward`, encore ouverte.

- L'évaluation, sur la copie cachée de `router` (chargée après les sondes de `ext1`) : `curl
  http://127.0.0.1/`, `ping` vers `ext2` et `int1`, `dig @{dmz1}`, HTTP vers `ext2` ; `ping` du
  routeur depuis `int1` et `dmz1` (réponse), depuis `ext2` (aucune) ; port 22 depuis `int1`
  (ouvert), depuis `int2`, `ext2` et `dmz1` (détruit). Dans `nft -j list ruleset` : la politique
  `drop` de `input` et une règle `accept` avec l'interface `eth2`, `ip saddr {int1}` et `tcp dport
  22`.
""": """
**Solution.** On `router`:

```
{cmds}```

(c) `iifname {{ eth1, eth2 }}`: the `echo-request` are only accepted when they arrive from the
DMZ or the internal zone; those of the outside fall on the policy. (d) the `echo-reply` are
accepted wherever they come from. (e) the DNS replies of `dmz1` only, and the TCP return traffic
arriving on `eth0`. (f) `iifname eth2 ip saddr {int1}`: a machine of the outside forging the
address of `int1` would arrive on `eth0`. A single rule `ct state established,related accept`
would replace the rules of (d) and (e): this is what a real firewall does, and it is accepted
here. These rules only concern the packets addressed to `router`: what crosses it goes through
`forward`, still open.

- The evaluation, on the hidden copy of `router` (loaded after the probes of `ext1`): `curl
  http://127.0.0.1/`, `ping` to `ext2` and `int1`, `dig @{dmz1}`, HTTP to `ext2`; `ping` of the
  router from `int1` and `dmz1` (a reply), from `ext2` (none); port 22 from `int1` (open), from
  `int2`, `ext2` and `dmz1` (dropped). In `nft -j list ruleset`: the `drop` policy of `input` and
  an `accept` rule with the interface `eth2`, `ip saddr {int1}` and `tcp dport 22`.
""",
        """
- `TTL=` dans la réponse de `dmz1` à `int1` : @@{ttl:[0-9]+}@@
- `CLIENT_IP=` dans la réponse de `ext2` à `int1` (`curl http://ext2/`) : @@{client_ip:[0-9.]+}@@
- adresse du serveur DNS par défaut de `ext1` : @@{resolver:[0-9.]+}@@
- `nft list ruleset` sur `router` affiche : @@{ruleset:>rien : aucune table ni règle, tout est accepté>>>empty|une table filter dont les chaînes ont la politique drop>>>drop|les règles installées par Docker>>>docker|une erreur : nft n'est pas installé>>>error}@@
""": """
- `TTL=` in the answer of `dmz1` to `int1`: @@{ttl:[0-9]+}@@
- `CLIENT_IP=` in the answer of `ext2` to `int1` (`curl http://ext2/`): @@{client_ip:[0-9.]+}@@
- address of the default DNS server of `ext1`: @@{resolver:[0-9.]+}@@
- `nft list ruleset` on `router` prints: @@{ruleset:>nothing: no table nor rule, everything is accepted>>>empty|a filter table whose chains have the drop policy>>>drop|the rules installed by Docker>>>docker|an error: nft is not installed>>>error}@@
""",
        """
- avec `drop`, `nc -v -w 5 dmz1 25` : @@{with_drop:>attend puis abandonne au bout du délai : le SYN est détruit avant de quitter ext1, rien ne revient>>>timeout|échoue immédiatement, « Connection refused »>>>refused|affiche la bannière 220>>>works}@@
- avec `reject`, `nc -v -w 5 dmz1 25` : @@{with_reject:>échoue immédiatement, « Connection refused » : le noyau prévient le programme>>>refused|attend puis abandonne au bout du délai>>>timeout|affiche la bannière 220>>>works}@@
""": """
- with `drop`, `nc -v -w 5 dmz1 25`: @@{with_drop:>waits then gives up after the timeout: the SYN is dropped before leaving ext1, nothing comes back>>>timeout|fails at once, "Connection refused">>>refused|prints the 220 banner>>>works}@@
- with `reject`, `nc -v -w 5 dmz1 25`: @@{with_reject:>fails at once, "Connection refused": the kernel tells the program>>>refused|waits then gives up after the timeout>>>timeout|prints the 220 banner>>>works}@@
""",
        """
- ce dispositif : @@{ban_effect:>détruit pendant 60 s tous les paquets vers la zone interne d'une machine de l'extérieur qui a tenté une connexion SSH vers cette zone, même les réponses aux connexions ouvertes par la zone interne>>>ban_source|interdit définitivement le SSH de l'extérieur vers la zone interne, et rien d'autre>>>ssh_only|limite l'extérieur à une connexion SSH par minute vers la zone interne>>>rate_limit|bannit pendant 60 s la machine interne visée par la tentative>>>ban_target}@@
""": """
- this device: @@{ban_effect:>drops for 60 s every packet towards the internal zone from a machine of the outside that tried an SSH connection to that zone, even the replies to the connections opened by the internal zone>>>ban_source|forbids SSH from the outside to the internal zone for good, and nothing else>>>ssh_only|limits the outside to one SSH connection per minute towards the internal zone>>>rate_limit|bans for 60 s the internal machine the attempt was aimed at>>>ban_target}@@
""",
        """
- pour laisser revenir les réponses HTTP sans suivi de connexion, on écrirait `iifname eth0 oifname eth2 tcp sport 80 accept`. Que permet cette règle à une machine de l'extérieur ? @@{stateless_hole:>d'ouvrir une connexion vers n'importe quel port TCP d'une machine interne, pourvu qu'elle utilise 80 comme port source>>>any_port|rien de plus : seules les réponses à une requête interne ont 80 pour port source>>>nothing|d'interroger le port 80 des machines internes, et lui seul>>>port_80|de traverser le routeur dans les deux sens, sur tous les ports>>>everything}@@
- `ping dmz1` fonctionne depuis `int1`, mais `ping int1` échoue depuis `dmz1`. Quel paquet de `dmz1` la règle à états laisse-t-elle passer vers `int1` ? @@{reply_state:>son echo-reply : il appartient à un échange ouvert par int1 (established)>>>established|son echo-request : il est dans l'état new>>>new|tous ses paquets ICMP : ICMP n'a pas d'état>>>all_icmp|aucun : la réponse passe par la chaîne input>>>none}@@
""": """
- to let the HTTP replies come back without connection tracking, one would write `iifname eth0 oifname eth2 tcp sport 80 accept`. What does this rule allow a machine of the outside to do? @@{stateless_hole:>open a connection to any TCP port of an internal machine, provided it uses 80 as its source port>>>any_port|nothing more: only the replies to an internal request have 80 as their source port>>>nothing|query port 80 of the internal machines, and that port only>>>port_80|cross the router in both directions, on every port>>>everything}@@
- `ping dmz1` works from `int1`, but `ping int1` fails from `dmz1`. Which packet of `dmz1` does the stateful rule let through to `int1`? @@{reply_state:>its echo-reply: it belongs to an exchange opened by int1 (established)>>>established|its echo-request: it is in the new state>>>new|all its ICMP packets: ICMP has no state>>>all_icmp|none: the reply goes through the input chain>>>none}@@
""",
        """
Avant d'installer quoi que ce soit, vérifiez rapidement que :

- il n'y a aucun pare-feu sur `router` ni sur `ext1` (`nft list ruleset`) ;
- les machines se joignent d'une zone à l'autre (`ping -c 2 dmz1` depuis `int1`, `ping -c 2 int2`
  depuis `ext1`…) ;
- depuis `int1`, `int2` et `router`, le serveur web de `dmz1` répond sur ses deux ports
  (`curl http://dmz1/`, `curl http://dmz1:{alt}/`, ou par son adresse `{dmz1}`) ;
- depuis `int1`, `int2` et `router`, les serveurs DNS de `dmz1` et `dmz2` répondent
  (`dig @{dmz1} ext1.lab`, `dig @{dmz2} ext1.lab +short`) ;
- chaque machine a son serveur DNS par défaut (`cat /etc/resolv.conf`).

Lisez les lignes `TTL=` et `CLIENT_IP=` des réponses des serveurs web.
""": """
Before installing anything, quickly check that:

- there is no firewall on `router` nor on `ext1` (`nft list ruleset`);
- the machines reach each other from one zone to another (`ping -c 2 dmz1` from `int1`,
  `ping -c 2 int2` from `ext1`…);
- from `int1`, `int2` and `router`, the web server of `dmz1` answers on both its ports
  (`curl http://dmz1/`, `curl http://dmz1:{alt}/`, or by its address `{dmz1}`);
- from `int1`, `int2` and `router`, the DNS servers of `dmz1` and `dmz2` answer
  (`dig @{dmz1} ext1.lab`, `dig @{dmz2} ext1.lab +short`);
- each machine has its default DNS server (`cat /etc/resolv.conf`).

Read the `TTL=` and `CLIENT_IP=` lines of the answers of the web servers.
""",
        """
Déjà en place (ne pas modifier) : les adresses, la route par défaut de chaque machine vers
`router`, le routage sur `router`. Les services :

- sur **toutes** les machines, un **serveur web de test** sur les ports TCP **80** et **8080**
  (`curl http://dmz1/`, `curl http://dmz1:8080/`) : il répond par son nom, l'adresse du client tel
  qu'il le voit et le TTL du paquet reçu (section @@ref:testing@@ des Informations) ;
- sur `ext1`, `ext2`, `dmz1` et `dmz2`, un **serveur DNS** (UDP 53) qui connaît les noms
  `ext1.lab`, `ext2.lab`, `dmz1.lab`, `dmz2.lab`, `int1.lab`, `int2.lab` et `router-ext.lab`,
  `router-dmz.lab`, `router-int.lab` ;
- sur `ext1` et `router`, un **serveur SSH** (port 22 ; compte `root`, mot de passe `root`) ;
- sur `ext2`, `dmz1` et `dmz2`, un **faux serveur de courrier** sur le port TCP 25 : il envoie
  une bannière `220 …` puis ferme la connexion (`nc -v -w 3 ext2 25`).

**Les noms passent par le DNS** : `/etc/hosts` ne connaît que la machine elle-même, et
`/etc/resolv.conf` désigne le serveur DNS de chaque machine : `ext2` pour `ext1`, `int1` et
`int2` ; `dmz1` pour `router` ; eux-mêmes pour `ext2`, `dmz1` et `dmz2`. Quand un pare-feu bloque
le DNS, toute commande qui utilise un nom échoue (`Could not resolve host`) : c'est voulu. En cas
de doute, testez avec les adresses du tableau.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place : l'évaluation vérifie le jeu de règles **final** de `ext1` et de `router` (sur
  chacune, une seule table, `inet filter`) ;
- les règles sont volatiles (`nft`) : elles ne survivent pas à un redémarrage. Écrire le
  pare-feu dans un fichier rechargé par `nft -f` (section @@ref:ruleset@@) évite bien des erreurs
  d'ordre ;
- l'évaluation lit le jeu de règles de `ext1` et de `router` (`nft list ruleset`) et le **recopie
  sur des machines cachées identiques**, qu'elle sonde depuis des copies cachées des autres
  machines : seuls comptent **les jeux de règles chargés** (et, à la question 6, le fichier
  `/etc/resolv.conf` de `int1`), pas l'état des serveurs ni ce que vous faites sur les autres
  machines ;
- pour tester sans attendre, utilisez des délais courts : `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `dig … +time=1 +tries=1`, `nc -v -w 3 …`.
""": """
Already in place (do not change): the addresses, the default route of each machine via `router`,
routing on `router`. The services:

- on **every** machine, a **test web server** on TCP ports **80** and **8080**
  (`curl http://dmz1/`, `curl http://dmz1:8080/`): it answers with its name, the address of the
  client as it sees it and the TTL of the packet received (section @@ref:testing@@ of the
  Informations);
- on `ext1`, `ext2`, `dmz1` and `dmz2`, a **DNS server** (UDP 53) that knows the names
  `ext1.lab`, `ext2.lab`, `dmz1.lab`, `dmz2.lab`, `int1.lab`, `int2.lab` and `router-ext.lab`,
  `router-dmz.lab`, `router-int.lab`;
- on `ext1` and `router`, an **SSH server** (port 22; account `root`, password `root`);
- on `ext2`, `dmz1` and `dmz2`, a **fake mail server** on TCP port 25: it sends a `220 …` banner
  then closes the connection (`nc -v -w 3 ext2 25`).

**Names go through the DNS**: `/etc/hosts` only knows the machine itself, and `/etc/resolv.conf`
names the DNS server of each machine: `ext2` for `ext1`, `int1` and `int2`; `dmz1` for `router`;
themselves for `ext2`, `dmz1` and `dmz2`. When a firewall blocks the DNS, every command given a
name fails (`Could not resolve host`): this is intended. When in doubt, test with the addresses
of the table.

Rules for the whole lab:

- the questions are to be done **in order** and the configuration of a finished question stays
  in place: the evaluation checks the **final** ruleset of `ext1` and of `router` (on each, one
  table only, `inet filter`);
- the rules are volatile (`nft`): they do not survive a reboot. Writing the firewall in a file
  loaded with `nft -f` (section @@ref:ruleset@@) avoids many ordering mistakes;
- the evaluation reads the ruleset of `ext1` and of `router` (`nft list ruleset`) and **copies it
  onto identical hidden machines**, which it probes from hidden copies of the other machines:
  only **the loaded rulesets** count (and, in question 6, the file `/etc/resolv.conf` of
  `int1`), not the state of the servers nor what you do on the other machines;
- to test without waiting, use short timeouts: `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `dig … +time=1 +tries=1`, `nc -v -w 3 …`.
""",
        """
Il reste à filtrer les paquets qui **traversent** `router`, d'une zone à l'autre : c'est le rôle
de la chaîne **`forward`** (section @@ref:forward@@ des Informations).

**(a)** Vérifiez que les machines des trois zones se joignent encore (`ping`, `curl`).

**(b)** Ajoutez à la table de `router` une chaîne de base `forward` de politique **`drop`** et
vérifiez que plus rien ne traverse le routeur, alors que `router` lui-même joint toujours ses
voisins.

**(c)** Autorisez les machines de la zone interne à pinguer celles de la DMZ, mais pas celles de
l'extérieur. Les machines de la DMZ et de l'extérieur ne doivent pouvoir pinguer personne à travers
le routeur.

**(d)** Autorisez les machines de la zone interne à interroger **leur serveur DNS par défaut**
(`ext2`, `{ext2}`, en UDP), et lui seul à l'extérieur, et à ouvrir des connexions **HTTP** (port
TCP {http}, pas {alt}) vers les machines de l'extérieur.

**(e)** Seules les communications **ouvertes par la zone interne** doivent traverser le routeur
vers elle. Si vous avez laissé revenir les réponses par des règles sans état (`icmp type
echo-reply`, `udp sport 53`, `tcp sport {http}`), remplacez-les par une seule règle à états, en
tête de chaîne (section @@ref:conntrack@@).

**(f)** Autorisez les machines de l'extérieur **et** de la zone interne à interroger le serveur
web de **`dmz1`** (`{dmz1}`) sur le port {http}, et rien d'autre dans la DMZ.

**(g)** Autorisez **`dmz2`** (`{dmz2}`), et elle seule dans la DMZ, à interroger en UDP les
serveurs DNS de l'extérieur.

**(h)** Autorisez les machines de la zone interne à interroger en UDP le serveur DNS de `dmz2`,
puis faites de `dmz2` le serveur DNS par défaut de **`int1`** (`/etc/resolv.conf`) et testez.

Après chaque point, testez ce qui doit passer **et** ce qui doit rester bloqué (un autre port, un
autre serveur, l'autre sens). `tcpdump` sur `router` et des `counter` sur les règles disent où un
paquet s'arrête (section @@ref:testing@@).
""": """
What remains is to filter the packets that **cross** `router`, from one zone to another: this is
the job of the **`forward`** chain (section @@ref:forward@@ of the Informations).

**(a)** Check that the machines of the three zones still reach each other (`ping`, `curl`).

**(b)** Add to the table of `router` a base chain `forward` with the policy **`drop`** and check
that nothing crosses the router any more, while `router` itself still reaches its neighbours.

**(c)** Allow the machines of the internal zone to ping those of the DMZ, but not those of the
outside. The machines of the DMZ and of the outside must not be able to ping anybody across the
router.

**(d)** Allow the machines of the internal zone to query **their default DNS server** (`ext2`,
`{ext2}`, in UDP), and only that one outside, and to open **HTTP** connections (TCP port {http},
not {alt}) to the machines of the outside.

**(e)** Only the communications **opened by the internal zone** may cross the router towards it.
If you let the replies come back with stateless rules (`icmp type echo-reply`, `udp sport 53`,
`tcp sport {http}`), replace them by a single stateful rule, at the head of the chain (section
@@ref:conntrack@@).

**(f)** Allow the machines of the outside **and** of the internal zone to query the web server of
**`dmz1`** (`{dmz1}`) on port {http}, and nothing else in the DMZ.

**(g)** Allow **`dmz2`** (`{dmz2}`), and only it in the DMZ, to query in UDP the DNS servers of
the outside.

**(h)** Allow the machines of the internal zone to query in UDP the DNS server of `dmz2`, then
make `dmz2` the default DNS server of **`int1`** (`/etc/resolv.conf`) and test.

After each point, test what must pass **and** what must stay blocked (another port, another
server, the other direction). `tcpdump` on `router` and `counter` statements on the rules tell
where a packet stops (section @@ref:testing@@).
""",
        """
Lisez l'onglet **Informations** : il présente les zones d'un réseau, les trois chaînes de filtrage
(`input`, `output`, `forward`), le suivi de connexion, la façon d'écrire la politique d'un
routeur, les ensembles et les outils de test.

**La maquette** (onglet *Schéma*) : le routeur `router` relie trois zones. Vous écrivez deux
pare-feux : celui de la machine **`ext1`** (questions 2 à 4), puis celui de **`router`**
(questions 5 à 7). Les autres machines servent de clients et de serveurs pour vos tests.
""": """
Read the **Informations** tab: it presents the zones of a network, the three filtering chains
(`input`, `output`, `forward`), connection tracking, how to write the policy of a router, sets
and the test tools.

**The setup** (*Schema* tab): the router `router` joins three zones. You write two firewalls:
the one of the machine **`ext1`** (questions 2 to 4), then the one of **`router`** (questions 5
to 7). The other machines are clients and servers for your tests.
""",
        """
On passe à **`router`**. Créez-y une table `inet filter` et sa chaîne de base **`input`**, qui
filtre les paquets destinés au routeur lui-même (section @@ref:hooks@@ des Informations), de telle
sorte que :

**(a)** les paquets entrants soient détruits par défaut ;

**(b)** tout ce qui arrive par `lo` soit accepté ;

**(c)** `router` réponde aux `ping` venus de la zone interne et de la DMZ, mais **pas** de
l'extérieur (critère sur l'interface d'entrée) ;

**(d)** `router` puisse pinguer toutes les autres machines ;

**(e)** `router` puisse interroger le serveur DNS de `dmz1` (`{dmz1}`, son serveur par défaut) et
ouvrir des connexions TCP vers les machines de l'extérieur ;

**(f)** on puisse ouvrir une connexion SSH sur `router` **uniquement depuis `int1`** (`{int1}`) :
exigez à la fois l'interface d'entrée et l'adresse source (section @@ref:selectors@@).

Testez chaque point, et son contraire : `ping -c 2 -W 1 {r_int}` depuis `int1`, `ping -c 2 -W 1
{r_ext}` depuis `ext2` ; `nc -v -w 3 {r_int} 22` depuis `int1` puis `int2`. Vérifiez aussi que ces
règles ne changent rien à ce qui **traverse** le routeur : `curl -m 3 http://ext2/` depuis `int1`
fonctionne toujours.
""": """
Now for **`router`**. Create there a table `inet filter` and its base chain **`input`**, which
filters the packets addressed to the router itself (section @@ref:hooks@@ of the Informations),
so that:

**(a)** incoming packets are dropped by default;

**(b)** whatever arrives on `lo` is accepted;

**(c)** `router` answers the `ping` coming from the internal zone and from the DMZ, but **not**
from the outside (a selector on the input interface);

**(d)** `router` can ping every other machine;

**(e)** `router` can query the DNS server of `dmz1` (`{dmz1}`, its default server) and open TCP
connections to the machines of the outside;

**(f)** an SSH connection to `router` can be opened **from `int1` only** (`{int1}`): require both
the input interface and the source address (section @@ref:selectors@@).

Test each point, and its opposite: `ping -c 2 -W 1 {r_int}` from `int1`, `ping -c 2 -W 1 {r_ext}`
from `ext2`; `nc -v -w 3 {r_int} 22` from `int1` then `int2`. Also check that these rules change
nothing to what **crosses** the router: `curl -m 3 http://ext2/` from `int1` still works.
""",
        """
On veut contrôler le courrier **émis** par `ext1` (port TCP {mail}). Un faux serveur de courrier
écoute sur `ext2`, `dmz1` et `dmz2` : `nc -v -w 5 ext2 {mail}` affiche sa bannière `220 …`.

**(a)** Ajoutez à la table de `ext1` une chaîne de base **`output`** (politique `accept`) et une
règle qui **détruit** les paquets TCP sortant vers le port {mail}. Testez avec `nc -v -w 5 ext2
{mail}` et `nc -v -w 5 dmz1 {mail}` : que voit le programme ?

**(b)** Remplacez `drop` par **`reject`** dans cette règle (`nft -a list ruleset` puis `nft replace
rule …`, ou videz la chaîne) et refaites les tests (section @@ref:verdicts@@ des Informations).

**(c)** Autorisez à présent les connexions vers le port {mail} de **`ext2`** (`{ext2}`) et d'elle
seule ; les autres restent refusées par `reject`. Attention à l'ordre des règles.
""": """
The mail **sent** by `ext1` (TCP port {mail}) is to be controlled. A fake mail server listens on
`ext2`, `dmz1` and `dmz2`: `nc -v -w 5 ext2 {mail}` prints its `220 …` banner.

**(a)** Add to the table of `ext1` a base chain **`output`** (policy `accept`) and a rule that
**drops** the TCP packets leaving for port {mail}. Test with `nc -v -w 5 ext2 {mail}` and
`nc -v -w 5 dmz1 {mail}`: what does the program see?

**(b)** Replace `drop` by **`reject`** in this rule (`nft -a list ruleset` then `nft replace
rule …`, or flush the chain) and run the tests again (section @@ref:verdicts@@ of the
Informations).

**(c)** Now allow the connections to port {mail} of **`ext2`** (`{ext2}`) and of it only; the
others stay refused by `reject`. Mind the order of the rules.
""",
        """
Sur **`ext1`**, créez une table `inet filter` et sa chaîne de base **`input`** (section
@@ref:ruleset@@ des Informations), de telle sorte que :

**(a)** les paquets entrants soient détruits par défaut (politique `drop`) ;

**(b)** tout ce qui arrive par l'interface `lo` soit accepté ;

**(c)** `ext1` puisse interroger **son serveur DNS par défaut**, celui de `/etc/resolv.conf`
(`ext2`, `{ext2}`), et lui seul : n'acceptez que les **réponses** UDP de ce serveur, en combinant
l'adresse source, le port source 53 et l'état de la connexion (section @@ref:conntrack@@). Les
réponses d'un autre serveur DNS (`dig @{dmz1} ext1.lab +time=1 +tries=1`) doivent rester bloquées,
et `ext2` ne doit pas pouvoir interroger le serveur DNS de `ext1` ;

**(d)** `ext1` puisse ouvrir des connexions TCP vers n'importe quelle machine (HTTP par exemple) :
n'acceptez que le trafic retour de ces connexions ;

**(e)** `ext1` réponde aux `ping` venus des autres machines et puisse elle-même en émettre.

Testez après chaque règle : `nft list ruleset`, puis depuis `ext1` `curl -m 3 http://ext2/`,
`curl -m 3 http://dmz1:8080/`, `ping -c 2 -W 1 dmz1` ; depuis `ext2`, `ping -c 2 -W 1 ext1`
(accepté) et `curl -m 3 http://ext1/` (bloqué : aucun service n'est encore ouvert). Tant que (c)
n'est pas faite, les noms ne sont plus résolus sur `ext1` : pourquoi ?
""": """
On **`ext1`**, create a table `inet filter` and its base chain **`input`** (section
@@ref:ruleset@@ of the Informations), so that:

**(a)** incoming packets are dropped by default (policy `drop`);

**(b)** whatever arrives on the interface `lo` is accepted;

**(c)** `ext1` can query **its default DNS server**, the one of `/etc/resolv.conf` (`ext2`,
`{ext2}`), and only that one: accept only the UDP **replies** of this server, by combining the
source address, the source port 53 and the state of the connection (section @@ref:conntrack@@).
The replies of another DNS server (`dig @{dmz1} ext1.lab +time=1 +tries=1`) must stay blocked,
and `ext2` must not be able to query the DNS server of `ext1`;

**(d)** `ext1` can open TCP connections to any machine (HTTP for instance): accept only the
return traffic of these connections;

**(e)** `ext1` answers the `ping` of the other machines and can ping them.

Test after each rule: `nft list ruleset`, then from `ext1` `curl -m 3 http://ext2/`,
`curl -m 3 http://dmz1:8080/`, `ping -c 2 -W 1 dmz1`; from `ext2`, `ping -c 2 -W 1 ext1`
(accepted) and `curl -m 3 http://ext1/` (blocked: no service is open yet). Until (c) is done,
names are no longer resolved on `ext1`: why?
""",
        """
`ext1` est aussi un serveur. Complétez sa chaîne `input` :

**(a)** le serveur web du port **{http}** doit être accessible depuis **toutes** les machines
(celui du port {alt} reste fermé) ;

**(b)** le serveur SSH (port {ssh}) doit être accessible depuis les machines du **réseau interne**
(`{net_int}`) et d'elles seules.

Testez : `curl -m 3 http://ext1/` depuis `ext2` et `int1` (réponse), `curl -m 3 http://ext1:{alt}/`
(délai) ; `nc -v -w 3 ext1 {ssh}` ou `ssh root@ext1` depuis `int1` (la bannière `SSH-2.0-…` ou
l'invite du mot de passe), puis depuis `ext2` et `dmz1` (délai).
""": """
`ext1` is also a server. Complete its `input` chain:

**(a)** the web server of port **{http}** must be reachable from **every** machine (the one of
port {alt} stays closed);

**(b)** the SSH server (port {ssh}) must be reachable from the machines of the **internal
network** (`{net_int}`) and from them only.

Test: `curl -m 3 http://ext1/` from `ext2` and `int1` (an answer), `curl -m 3 http://ext1:{alt}/`
(a timeout); `nc -v -w 3 ext1 {ssh}` or `ssh root@ext1` from `int1` (the banner `SSH-2.0-…` or
the password prompt), then from `ext2` and `dmz1` (a timeout).
""",
        """
nftables peut remplir un ensemble **depuis le trafic** et en faire expirer les éléments (section
@@ref:sets@@ des Informations). Sur `router`, sans rien retirer de la question 6 :

```
{cmds}```

Les deux `insert` placent ces règles **en tête** de la chaîne `forward`, la seconde avant la
première. À quoi sert ce dispositif ? Testez-le :

1. depuis `int1`, `curl -m 3 http://{ext1}/` répond ;
2. depuis `ext1`, `nc -v -w 2 {int1} {ssh}` (une tentative de connexion SSH vers la zone interne) ;
3. depuis `int1`, de nouveau `curl -m 3 http://{ext1}/`, puis `curl -m 3 http://{ext2}/` ;
4. sur `router`, `nft list set inet filter {set}` ; attendez une minute et recommencez l'étape 3.
""": """
nftables can fill a set **from the traffic** and make its elements expire (section @@ref:sets@@
of the Informations). On `router`, without removing anything of question 6:

```
{cmds}```

The two `insert` put these rules **at the head** of the `forward` chain, the second one before
the first. What is this device for? Test it:

1. from `int1`, `curl -m 3 http://{ext1}/` answers;
2. from `ext1`, `nc -v -w 2 {int1} {ssh}` (an attempt to open an SSH connection to the internal
   zone);
3. from `int1`, again `curl -m 3 http://{ext1}/`, then `curl -m 3 http://{ext2}/`;
4. on `router`, `nft list set inet filter {set}`; wait one minute and do step 3 again.
""",
        """
| zone | réseau | interface de `router` | machines |
|------|--------|-----------------------|----------|
| **extérieur** (`ext`) | `{net_ext}` | `eth0` : `{r_ext}` | **`ext1`** (`{ext1}`), `ext2` (`{ext2}`) |
| **DMZ** (`dmz`) | `{net_dmz}` | `eth1` : `{r_dmz}` | `dmz1` (`{dmz1}`), `dmz2` (`{dmz2}`) |
| **interne** (`int`) | `{net_int}` | `eth2` : `{r_int}` | `int1` (`{int1}`), `int2` (`{int2}`) |
""": """
| zone | network | interface of `router` | machines |
|------|---------|-----------------------|----------|
| **outside** (`ext`) | `{net_ext}` | `eth0`: `{r_ext}` | **`ext1`** (`{ext1}`), `ext2` (`{ext2}`) |
| **DMZ** (`dmz`) | `{net_dmz}` | `eth1`: `{r_dmz}` | `dmz1` (`{dmz1}`), `dmz2` (`{dmz2}`) |
| **internal** (`int`) | `{net_int}` | `eth2`: `{r_int}` | `int1` (`{int1}`), `int2` (`{int2}`) |
""",
        """**Sommaire**
""": """**Contents**
""",
        'Aide-mémoire': 'Cheat sheet',
        'Bonnes pratiques et pièges': 'Good practices and pitfalls',
        'Bonus : bannir temporairement une machine': 'Bonus: banning a machine for a while',
        'Compter et journaliser': 'Counting and logging',
        "Du pare-feu d'une machine au pare-feu d'un réseau": 'From a host firewall to a network firewall',
        'Filtrer ce qui sort : la chaîne output': 'Filtering what leaves: the output chain',
        'Le pare-feu du routeur : filtrer ce qui le traverse': 'The firewall of the router: filtering what crosses it',
        'Le suivi de connexion : filtrer selon le sens': 'Connection tracking: filtering by direction',
        'Les critères': 'Selectors',
        'Les ensembles': 'Sets',
        'Observer et tester': 'Observing and testing',
        'Organisation du TP': 'Organisation of the lab',
        "Pare-feu d'un poste client : les paquets entrants": 'Firewall of a client: incoming packets',
        "Pare-feu d'un réseau avec nftables : client, serveur, routeur et DMZ": 'Network firewall with nftables: client, server, router and DMZ',
        "Pare-feu d'un serveur : ouvrir des services": 'Firewall of a server: opening services',
        'Partie 1 — Avant les pare-feux (question 1)': 'Part 1 — Before the firewalls (question 1)',
        "Partie 2 — Pare-feu d'un poste client (question 2)": 'Part 2 — Firewall of a client (question 2)',
        "Partie 3 — Pare-feu d'un serveur (question 3)": 'Part 3 — Firewall of a server (question 3)',
        'Partie 4 — La chaîne output (question 4)': 'Part 4 — The output chain (question 4)',
        'Partie 5 — Protection du routeur (question 5)': 'Part 5 — Protecting the router (question 5)',
        'Partie 6 — Pare-feu du routeur (question 6)': 'Part 6 — Firewall of the router (question 6)',
        'Partie 7 — Bonus : ensemble dynamique (question 7)': 'Part 7 — Bonus: dynamic set (question 7)',
        'Protéger le routeur lui-même': 'Protecting the router itself',
        'Tables, chaînes et règles : rappels': 'Tables, chains and rules: a reminder',
        'Tests avant les pare-feux': 'Tests before the firewalls',
        'Trois chaînes pour trois trajets': 'Three chains for three paths',
        'Verdicts : accept, drop, reject': 'Verdicts: accept, drop, reject',
        "après une tentative SSH de ext1 vers int2, int2 n'obtient plus de réponse de ext1 (mais toujours de ext2)": 'after an SSH attempt from ext1 to int2, int2 no longer gets an answer from ext1 (but still from ext2)',
        'avant les pare-feux : TTL à travers le routeur (63), CLIENT_IP vu par ext2, serveur DNS de ext1, jeu de règles vide': 'before the firewalls: TTL across the router (63), CLIENT_IP seen by ext2, DNS server of ext1, empty ruleset',
        "dmz2 interroge un serveur DNS de l'extérieur (ext2)": 'dmz2 queries a DNS server of the outside (ext2)',
        'drop ou reject dans output : ce que voit le programme': 'drop or reject in output: what the program sees',
        'ext1 : curl http://127.0.0.1/ répond (interface lo acceptée)': 'ext1: curl http://127.0.0.1/ answers (interface lo accepted)',
        "ext1 : pas de réponse d'un autre serveur DNS, ext2 n'interroge pas le DNS de ext1, règle sur l'adresse du serveur, UDP et ct state established": 'ext1: no reply from another DNS server, ext2 cannot query the DNS of ext1, a rule on the address of the server, UDP and ct state established',
        'ext1 : une chaîne de base du hook input avec la politique drop': 'ext1: a base chain of the input hook with the drop policy',
        'ext1 : une règle reject ou drop sur tcp dport 25 dans une chaîne du hook output': 'ext1: a reject or drop rule on tcp dport 25 in a chain of the output hook',
        'ext1 joint le port 25 de ext2, et de ext2 seulement': 'ext1 reaches port 25 of ext2, and of ext2 only',
        'ext1 ne joint pas le port 25 de dmz1': 'ext1 does not reach port 25 of dmz1',
        'ext1 obtient les réponses de son serveur DNS par défaut (ext2)': 'ext1 gets the replies of its default DNS server (ext2)',
        'ext1 ouvre des connexions TCP (HTTP vers ext2, et vers dmz1 à travers le routeur)': 'ext1 opens TCP connections (HTTP to ext2, and to dmz1 across the router)',
        'ext1 répond aux ping de ext2 et pingue ext2 et dmz1': 'ext1 answers the pings of ext2 and pings ext2 and dmz1',
        "filtrage sans état : la faille du port source ; l'état de la réponse à un ping": 'stateless filtering: the source port hole; the state of the reply to a ping',
        'forward : une règle accept avec ct state established,related': 'forward: an accept rule with ct state established,related',
        'int1 interroge le serveur DNS de dmz2, devenu son serveur par défaut (/etc/resolv.conf)': 'int1 queries the DNS server of dmz2, now its default server (/etc/resolv.conf)',
        'int1 interroge son serveur DNS par défaut (ext2)': 'int1 queries its default DNS server (ext2)',
        'int1 pingue dmz1 à travers le routeur': 'int1 pings dmz1 across the router',
        'int2 interroge le serveur web de ext2 (port 80)': 'int2 queries the web server of ext2 (port 80)',
        'le port 22 de ext1 est fermé à ext2 et à dmz1': 'port 22 of ext1 is closed to ext2 and dmz1',
        'le port 22 de ext1 est ouvert à int1 et int2': 'port 22 of ext1 is open to int1 and int2',
        "le port 22 de router est fermé à int2, ext2 et dmz1 ; la règle exige l'interface eth2 et l'adresse de int1": 'port 22 of router is closed to int2, ext2 and dmz1; the rule requires the interface eth2 and the address of int1',
        'le port 22 de router est ouvert à int1': 'port 22 of router is open to int1',
        "le port 80 de dmz1 est ouvert à l'extérieur (ext2) et à la zone interne (int1)": 'port 80 of dmz1 is open to the outside (ext2) and to the internal zone (int1)',
        'le port 80 de ext1 est ouvert à ext2 et à int1': 'port 80 of ext1 is open to ext2 and int1',
        "le port 8080 de dmz1 et le port 80 de dmz2 sont fermés à l'extérieur ; dmz1 n'interroge pas les serveurs DNS de l'extérieur": 'port 8080 of dmz1 and port 80 of dmz2 are closed to the outside; dmz1 cannot query the DNS servers of the outside',
        'le port 8080 de ext1 reste fermé': 'port 8080 of ext1 stays closed',
        'le refus est immédiat (reject, pas drop)': 'the refusal is immediate (reject, not drop)',
        "pas de ping de int1 vers ext2, de dmz1 vers int1, de l'extérieur vers la DMZ et la zone interne": 'no ping from int1 to ext2, from dmz1 to int1, from the outside to the DMZ and the internal zone',
        "rien n'entre dans la zone interne depuis l'extérieur ; vers l'extérieur, ni le port 8080 ni un autre serveur DNS que ext2": 'nothing enters the internal zone from the outside; towards the outside, neither port 8080 nor a DNS server other than ext2',
        'router : curl http://127.0.0.1/ répond (interface lo acceptée)': 'router: curl http://127.0.0.1/ answers (interface lo accepted)',
        'router : une chaîne de base du hook forward avec la politique drop': 'router: a base chain of the forward hook with the drop policy',
        'router : une chaîne de base du hook input avec la politique drop': 'router: a base chain of the input hook with the drop policy',
        "router ne répond pas aux ping de l'extérieur": 'router does not answer the pings of the outside',
        'router obtient les réponses du serveur DNS de dmz1': 'router gets the replies of the DNS server of dmz1',
        "router ouvre des connexions TCP vers l'extérieur (HTTP vers ext2)": 'router opens TCP connections to the outside (HTTP to ext2)',
        'router pingue ext2 et int1': 'router pings ext2 and int1',
        'router répond aux ping de la zone interne et de la DMZ': 'router answers the pings of the internal zone and of the DMZ',
        'un ensemble alimenté par une règle de forward (ip saddr, tcp dport 22), éléments expirant après 60 s': 'a set fed by a rule of forward (ip saddr, tcp dport 22), its elements expiring after 60 s',
        'une règle drop sur ip saddr @ensemble, placée avant la règle à états': 'a drop rule on ip saddr @set, placed before the stateful rule',
        "Écrire la politique d'un routeur": 'Writing the policy of a router',
        "à quoi sert l'ensemble dynamique": 'what the dynamic set is for',
    },
}
