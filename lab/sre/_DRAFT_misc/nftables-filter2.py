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

Un **pare-feu** applique une politique aux paquets IP : accepter, détruire ou refuser. Il peut
tourner à deux endroits :

- sur **une machine** qu'il protège (*host firewall*) : il filtre ce qui **entre** dans la machine
  et, plus rarement, ce qui en **sort** (interdire à un poste d'envoyer du courrier directement,
  par exemple) ;
- sur **un routeur** (*network firewall*) : il filtre ce qui **traverse** le routeur, entre des
  **zones** de confiance différentes. Le routeur est lui-même une machine à protéger.

Le découpage classique compte trois zones, chacune derrière une interface du routeur :

- l'**extérieur** (Internet) : on n'y maîtrise rien ;
- le **réseau interne** : les postes de travail. Ils ouvrent des connexions vers l'extérieur,
  mais **aucune** connexion ne doit y entrer ;
- la **DMZ** (*zone démilitarisée*) : les serveurs que l'extérieur doit pouvoir joindre (web,
  DNS, courrier). Ils sont **isolés** du réseau interne : un serveur compromis ne donne pas accès
  aux postes.

Une politique de filtrage se résume par une **matrice des flux** : pour chaque couple (zone
source, zone destination), les services autorisés. Tout le reste est interdit :

| de ↓ vers → | extérieur | DMZ | interne |
|-------------|-----------|-----|---------|
| **extérieur** | — | les services publiés (HTTP d'un serveur…) | rien |
| **DMZ** | le strict nécessaire (DNS d'un serveur…) | — | rien |
| **interne** | la navigation (HTTP, DNS) | les services de la DMZ | — |

La règle d'or : **tout ce qui n'est pas explicitement autorisé est interdit**. On l'obtient avec
une politique par défaut `drop` et une règle par flux autorisé, jamais l'inverse.
""")
            + info_subtitle(tr("Trois chaînes pour trois trajets"), tag="hooks")
            + tr("""

Sous Linux, le filtrage est fait dans le noyau par **Netfilter**, configuré avec la commande
**`nft`** (nftables). Netfilter offre des points d'accrochage (*hooks*) sur le trajet d'un paquet :

```
                                            ┌──────── processus locaux ────────┐
                                            │                                  │
                                          input                             output
                                            │                                  │
  arrivée ──> prerouting ──> [décision de routage] ──> forward ──> postrouting ──> départ
```

- **`input`** : les paquets **destinés à la machine** (à l'une de ses adresses, quelle que soit
  l'interface d'arrivée) ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`forward`** : les paquets que la machine **route** : ni émis par elle, ni pour elle.

Un paquet ne passe que par **une** de ces trois chaînes. Conséquences :

- sur un routeur, `forward` ne protège pas le routeur lui-même (un `ping` *vers* le routeur passe
  par `input`) et `input` ne filtre rien de ce qui le traverse : il faut les deux ;
- un échange a **deux sens**. Sur un poste client, la requête sort par `output` et la réponse
  entre par `input`. À travers un routeur, la requête **et** la réponse passent par `forward`,
  avec les interfaces d'entrée et de sortie inversées ;
- un paquet d'une machine vers elle-même (`127.0.0.1`) passe par `output` puis par `input`, via
  l'interface `lo` : une politique `drop` en `input` casse aussi les communications locales ;
- `forward` ne voit des paquets que si le routage est activé (`sysctl net.ipv4.ip_forward`).
""")
            + info_subtitle(tr("Tables, chaînes et règles : rappels"), tag="ruleset")
            + tr("""

Un jeu de règles (*ruleset*) est fait de **tables** (famille `inet` : IPv4 et IPv6), qui
contiennent des **chaînes**, qui contiennent des **règles**. Une **chaîne de base** est accrochée
à un hook, avec un type, une priorité et une **politique** : le verdict des paquets qu'aucune règle
n'a tranchés. Une même table peut porter une chaîne par hook :

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

(les apostrophes protègent les accolades et les points-virgules du shell.) Refaire `add chain`
sur une chaîne existante avec une autre politique **change sa politique** sans toucher à ses
règles.

Les règles d'une chaîne sont évaluées **dans l'ordre** ; la première qui porte un verdict et dont
tous les critères sont satisfaits décide. L'ordre se choisit à l'ajout :

```
nft add rule inet filter input iif lo accept           # à la FIN de la chaîne
nft insert rule inet filter input iif lo accept        # au DÉBUT
nft -a list ruleset                                    # affiche le numéro (handle) de chaque règle
nft insert rule inet filter input handle 7 …           # avant la règle 7 (add rule … handle 7 : après)
nft replace rule inet filter input handle 7 …          # remplace la règle 7
nft delete rule inet filter input handle 7             # supprime la règle 7
nft flush chain inet filter output                     # vide une chaîne (sa politique reste)
```

Dès qu'un pare-feu dépasse quelques règles, on l'écrit dans un **fichier** que l'on recharge d'un
bloc : c'est plus sûr que de retoucher les règles une à une, et l'ordre y est lisible.

```
# /root/firewall.nft — chargé par : nft -f /root/firewall.nft
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        tcp dport 80 accept
    }
}
```

`nft -f` remplace l'ancien jeu de règles par le nouveau de façon **atomique** : si le fichier
contient une erreur, rien n'est changé. `nft list ruleset > /root/firewall.nft` produit un tel
fichier à partir des règles en place (ajoutez `flush ruleset` en tête).
""")
            + info_subtitle(tr("Les critères"), tag="selectors")
            + tr("""

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname eth0` | interface d'**entrée** du paquet (`iif` : par index, l'interface doit exister ; `iifname` : par nom) |
| `oifname eth1`, `oif eth1` | interface de **sortie** (connue dans `forward` et `output`, pas dans `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | adresse ou réseau **source** |
| `ip daddr 192.0.2.10` | adresse ou réseau **destination** |
| `meta l4proto tcp`, `ip protocol udp` | protocole de transport (`tcp`, `udp`, `icmp`) |
| `tcp dport 80`, `udp dport 53` | port **destination** : le service demandé |
| `tcp sport 80`, `udp sport 53` | port **source** : dans une réponse, le port du serveur |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête et réponse) |
| `ct state established,related`, `ct state new` | état dans le suivi de connexion (section @@ref:conntrack@@) |
| `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }` | un **ensemble** de valeurs (section @@ref:sets@@) |
| `ip daddr != 192.0.2.10` | négation |

Les critères d'une règle sont **tous** requis. `tcp dport` ou `icmp type` impliquent le
protocole. Une règle de pare-feu de réseau dit en général **d'où** vient le paquet et **où** il
va, puis le service :

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

Filtrer sur l'adresse source seule est fragile : une adresse se falsifie (*spoofing*). Pour une
règle sensible, on exige **l'interface et l'adresse** : `iifname eth2 ip saddr 192.0.2.10 tcp
dport 22 accept` n'accepte la machine d'administration que si elle arrive du bon côté.
""")
            + info_subtitle(tr("Le suivi de connexion : filtrer selon le sens"), tag="conntrack")
            + tr("""

Netfilter mémorise les **connexions** en cours (*conntrack*) : une connexion TCP, mais aussi un
échange UDP (une requête et ses réponses entre les mêmes adresses et ports) ou ICMP (un
`echo-request` et son `echo-reply`). Chaque paquet a un **état** :

- **`new`** : il ouvre un nouvel échange (le SYN en TCP, le premier datagramme en UDP) ;
- **`established`** : il appartient à un échange déjà vu dans les deux sens : c'est le cas de
  toutes les **réponses** ;
- **`related`** : il est lié à un échange existant (une erreur ICMP qui le concerne) ;
- **`invalid`** : il n'appartient à rien de connu.

Un filtre **sans état** ne sait autoriser les réponses qu'à l'aveugle : « tout ce qui vient du
port 80 », « tout l'UDP qui vient du port 53 ». C'est une **faille** : celui qui choisit 80 ou 53
comme port source de ses paquets passe aussi. Avec le suivi de connexion, on autorise
l'**ouverture** d'un échange, dans un seul sens, et les réponses suivent :

```
nft add rule inet filter forward ct state established,related accept       # en première règle
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

La seconde règle laisse les machines derrière `eth2` ouvrir des connexions vers le port 80 de
celles derrière `eth0` ; les réponses passent par la première. Rien ne permet à une machine
derrière `eth0` d'ouvrir une connexion dans l'autre sens.

`ct state` se combine avec les autres critères quand on ne veut accepter que **certaines**
réponses :

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

La première n'accepte que les réponses du serveur DNS `192.0.2.53` aux questions que la machine
lui a posées ; la seconde, tout le trafic retour des connexions TCP que la machine a ouvertes.
""")
            + info_subtitle(tr("Verdicts : accept, drop, reject"), tag="verdicts")
            + tr("""

- **`accept`** : le paquet passe ;
- **`drop`** : le paquet est détruit **en silence** : l'émetteur attend, réessaie, puis renonce
  (*timeout*) ;
- **`reject`** : le paquet est refusé et l'émetteur est **prévenu**, par défaut par un message
  ICMP *port unreachable* (`reject with tcp reset` envoie un RST) : l'erreur est immédiate.

Vers l'extérieur on détruit (ne rien révéler) ; pour ses propres utilisateurs on refuse souvent
(l'erreur est claire et immédiate). Dans la chaîne **`output`**, la différence se voit sur la
machine elle-même :

- `drop` : rien ne signale le blocage. La connexion TCP n'aboutit jamais et le programme attend
  son délai ; `ping` annonce simplement `100% packet loss` ;
- `reject` : le programme est prévenu aussitôt : `Connection refused` pour une connexion TCP,
  `Destination Port Unreachable` et `sendmsg: Operation not permitted` pour `ping`. Le message
  d'erreur est fabriqué par le noyau et revient au programme par l'interface `lo` : la chaîne
  `input` doit l'accepter (`iif lo accept`), sinon le programme attend comme avec `drop`.

Deux **actions sans verdict** aident au diagnostic : **`counter`** compte les paquets qui
atteignent la règle (`tcp dport 25 counter reject` ; `nft list ruleset` affiche les compteurs) et
**`log`** les journalise (`log prefix "fw: " group 0`, lus avec `tcpdump -n -i nflog:0`).
""")
            + info_subtitle(tr("Écrire la politique d'un routeur"), tag="forward")
            + tr("""

1. **Associer chaque zone à une interface** du routeur (`ip -br address`) et écrire la matrice
   des flux (section @@ref:zones@@).
2. **Politique `drop`** sur `forward` : plus rien ne traverse.
3. **La règle à états en tête** : `ct state established,related accept`. Elle ne laisse passer
   que les suites d'échanges déjà autorisés.
4. **Une règle par flux autorisé**, qui décrit l'ouverture de l'échange : zone source
   (`iifname`), zone destination (`oifname`), serveur éventuel (`ip daddr`), service (`tcp dport`,
   `udp dport`, `icmp type echo-request`).
5. **Tester** chaque flux autorisé et **chaque interdiction** voisine (un autre port, un autre
   serveur, l'autre sens).

```
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept                      # interne -> web extérieur
        iifname "eth0" oifname "eth1" ip daddr 192.0.2.80 tcp dport 80 accept  # extérieur -> serveur de la DMZ
    }
}
```

Le routeur se protège lui-même par sa chaîne `input` : politique `drop`, `iif lo accept`, les
réponses à ce qu'il émet, et l'administration (SSH) depuis une seule machine. Une règle de
`forward` n'a aucun effet sur un paquet destiné au routeur, et inversement
(section @@ref:hooks@@).
""")
            + info_subtitle(tr("Les ensembles"), tag="sets")
            + tr("""

Un **ensemble anonyme** s'écrit dans la règle : `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`,
`icmp type { echo-request, echo-reply }`. Une seule règle remplace plusieurs règles identiques.

Un **ensemble nommé** est un objet de la table, que plusieurs règles utilisent (`@nom`) et que l'on
modifie sans toucher aux règles :

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
```

Un **ensemble dynamique** est rempli **par les règles elles-mêmes**, au passage des paquets, et
ses éléments peuvent **expirer** :

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

Chaque paquet qui atteint la règle `add @banned { ip saddr }` fait ajouter son adresse source à
l'ensemble ; l'élément disparaît de lui-même 60 secondes plus tard (`update` au lieu de `add`
relance le délai à chaque paquet). `add @banned …` n'est pas un verdict : le paquet continue vers
la règle suivante. `nft list set inet filter banned` montre les éléments et le temps qui leur
reste (`expires 54s768ms`), `nft flush set inet filter banned` vide l'ensemble. On construit ainsi un
bannissement temporaire, une limite par adresse ou un *port knocking*.
""")
            + info_subtitle(tr("Observer et tester"), tag="testing")
            + tr("""

Tester un pare-feu, c'est vérifier ce qui **doit passer** et ce qui **doit être bloqué**, avec
des délais courts pour ne pas attendre :

| service | commande de test |
|---------|------------------|
| ICMP | `ping -c 2 -W 1 adresse` |
| HTTP (ports 80, 8080) | `curl -m 3 http://adresse/`, `curl -m 3 http://adresse:8080/` |
| DNS (UDP 53) | `dig @serveur nom +time=1 +tries=1` (ou `+short` pour la seule réponse) |
| SSH (TCP 22), courrier (TCP 25), tout port TCP | `nc -v -w 3 adresse 22` (la bannière du serveur s'affiche), `ssh root@adresse` |

Les serveurs web de test répondent par leur nom et par ce qu'ils voient du client :
`SERVER=dmz1`, `CLIENT_IP=…`, `TTL=63` (64 moins un par routeur traversé).

Le message d'erreur dit ce qui s'est passé :

| symptôme | cause probable |
|----------|----------------|
| `Connection timed out`, `100% packet loss`, après le délai | un paquet est **détruit** (`drop`), à l'aller ou au retour |
| `Connection refused`, immédiat | un `reject`, ou aucun serveur sur ce port |
| `Could not resolve host`, `Temporary failure in name resolution` | le **DNS** ne répond pas : la question ou la réponse est filtrée. Essayez avec l'adresse |
| `ping: sendmsg: Operation not permitted`, avec `Destination Port Unreachable` venant de la machine elle-même | un `reject` dans sa propre chaîne `output` (un `drop` n'y donne que `100% packet loss`) |
| `no servers could be reached` (`dig`) | la question DNS ou sa réponse est détruite |

Pour **localiser** un blocage : `tcpdump -n -i eth0 icmp or port 80` sur le routeur, côté
arrivée puis côté départ (le paquet entre-t-il ? ressort-il ? la réponse revient-elle ?), et
`nft list ruleset` avec des `counter` sur les règles pour voir laquelle a vu le paquet. Sur le
serveur, `ss -tulnp` liste les ports en écoute : un port fermé répond `Connection refused` même
sans pare-feu.
""")
            + info_subtitle(tr("Pour qui connaît iptables"), tag="iptables")
            + tr("""

| iptables | nftables |
|----------|----------|
| `iptables -L -v -n` | `nft list ruleset` |
| `iptables -P FORWARD DROP` | `policy drop;` dans la déclaration de la chaîne `forward` |
| `iptables -A INPUT -i lo -j ACCEPT` | `nft add rule inet filter input iif lo accept` |
| `iptables -A INPUT -p udp -s A --sport 53 -m state --state ESTABLISHED -j ACCEPT` | `… input ip saddr A udp sport 53 ct state established accept` |
| `iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT` | `… input meta l4proto tcp ct state established,related accept` |
| `iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT` | `… input icmp type echo-request accept` |
| `iptables -A INPUT -p tcp -s R/24 --dport 22 -j ACCEPT` | `… input ip saddr R/24 tcp dport 22 accept` |
| `iptables -A OUTPUT -p tcp --dport 25 -j REJECT` | `… output tcp dport 25 reject` |
| `iptables -A FORWARD -i eth2 -o eth0 -p tcp --dport 80 -j ACCEPT` | `… forward iifname eth2 oifname eth0 tcp dport 80 accept` |
| `iptables -F FORWARD` | `nft flush chain inet filter forward` |
| `-m recent --name L --set`, `-m recent --name L --rcheck --seconds 60` | `add @L { ip saddr }`, `ip saddr @L` avec un ensemble `timeout 60s` |
| `-m string --string toto` | pas d'équivalent dans nftables |
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table et chaînes | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (de même `input`, `output`) |
| règles | `nft add rule inet filter forward …` (fin), `nft insert rule …` (début), `nft insert rule inet filter forward handle N …` (avant la règle N), `nft delete rule inet filter forward handle N` |
| critères | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts | `accept`, `drop`, `reject`, `counter` |
| ensembles | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| fichier | `nft -f /root/firewall.nft` (commençant par `flush ruleset`), `nft list ruleset > /root/firewall.nft` |
| tout effacer | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S nom +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
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

- **`accept`** : le paquet passe ;
- **`drop`** : le paquet est détruit **en silence** : l'émetteur attend, réessaie, puis renonce
  (*timeout*) ;
- **`reject`** : le paquet est refusé et l'émetteur est **prévenu**, par défaut par un message
  ICMP *port unreachable* (`reject with tcp reset` envoie un RST) : l'erreur est immédiate.

Vers l'extérieur on détruit (ne rien révéler) ; pour ses propres utilisateurs on refuse souvent
(l'erreur est claire et immédiate). Dans la chaîne **`output`**, la différence se voit sur la
machine elle-même :

- `drop` : rien ne signale le blocage. La connexion TCP n'aboutit jamais et le programme attend
  son délai ; `ping` annonce simplement `100% packet loss` ;
- `reject` : le programme est prévenu aussitôt : `Connection refused` pour une connexion TCP,
  `Destination Port Unreachable` et `sendmsg: Operation not permitted` pour `ping`. Le message
  d'erreur est fabriqué par le noyau et revient au programme par l'interface `lo` : la chaîne
  `input` doit l'accepter (`iif lo accept`), sinon le programme attend comme avec `drop`.

Deux **actions sans verdict** aident au diagnostic : **`counter`** compte les paquets qui
atteignent la règle (`tcp dport 25 counter reject` ; `nft list ruleset` affiche les compteurs) et
**`log`** les journalise (`log prefix "fw: " group 0`, lus avec `tcpdump -n -i nflog:0`).
""": """

- **`accept`**: the packet goes through;
- **`drop`**: the packet is destroyed **silently**: the sender waits, retries, then gives up
  (*timeout*);
- **`reject`**: the packet is refused and the sender is **told**, by default with an ICMP *port
  unreachable* message (`reject with tcp reset` sends a RST): the error is immediate.

Towards the outside one drops (reveal nothing); for one's own users one often rejects (the error
is clear and immediate). In the **`output`** chain, the difference shows on the machine itself:

- `drop`: nothing reports the blockage. The TCP connection never completes and the program waits
  for its timeout; `ping` merely reports `100% packet loss`;
- `reject`: the program is told at once: `Connection refused` for a TCP connection, `Destination
  Port Unreachable` and `sendmsg: Operation not permitted` for `ping`. The error message is built
  by the kernel and comes back to the program through the interface `lo`: the `input` chain must
  accept it (`iif lo accept`), otherwise the program waits as with `drop`.

Two **statements without a verdict** help diagnosis: **`counter`** counts the packets reaching
the rule (`tcp dport 25 counter reject`; `nft list ruleset` prints the counters) and **`log`**
logs them (`log prefix "fw: " group 0`, read with `tcpdump -n -i nflog:0`).
""",
        """

1. **Associer chaque zone à une interface** du routeur (`ip -br address`) et écrire la matrice
   des flux (section @@ref:zones@@).
2. **Politique `drop`** sur `forward` : plus rien ne traverse.
3. **La règle à états en tête** : `ct state established,related accept`. Elle ne laisse passer
   que les suites d'échanges déjà autorisés.
4. **Une règle par flux autorisé**, qui décrit l'ouverture de l'échange : zone source
   (`iifname`), zone destination (`oifname`), serveur éventuel (`ip daddr`), service (`tcp dport`,
   `udp dport`, `icmp type echo-request`).
5. **Tester** chaque flux autorisé et **chaque interdiction** voisine (un autre port, un autre
   serveur, l'autre sens).

```
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept                      # interne -> web extérieur
        iifname "eth0" oifname "eth1" ip daddr 192.0.2.80 tcp dport 80 accept  # extérieur -> serveur de la DMZ
    }
}
```

Le routeur se protège lui-même par sa chaîne `input` : politique `drop`, `iif lo accept`, les
réponses à ce qu'il émet, et l'administration (SSH) depuis une seule machine. Une règle de
`forward` n'a aucun effet sur un paquet destiné au routeur, et inversement
(section @@ref:hooks@@).
""": """

1. **Map each zone to an interface** of the router (`ip -br address`) and write the flow matrix
   (section @@ref:zones@@).
2. **Policy `drop`** on `forward`: nothing crosses any more.
3. **The stateful rule first**: `ct state established,related accept`. It only lets through what
   follows exchanges already allowed.
4. **One rule per allowed flow**, describing the opening of the exchange: source zone
   (`iifname`), destination zone (`oifname`), the server if any (`ip daddr`), the service (`tcp
   dport`, `udp dport`, `icmp type echo-request`).
5. **Test** each allowed flow and **each neighbouring prohibition** (another port, another
   server, the other direction).

```
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        iifname "eth2" oifname "eth0" tcp dport 80 accept                      # internal -> outside web
        iifname "eth0" oifname "eth1" ip daddr 192.0.2.80 tcp dport 80 accept  # outside -> server of the DMZ
    }
}
```

The router protects itself with its `input` chain: policy `drop`, `iif lo accept`, the replies to
what it sends, and administration (SSH) from one machine only. A rule of `forward` has no effect
on a packet addressed to the router, and conversely (section @@ref:hooks@@).
""",
        """

Netfilter mémorise les **connexions** en cours (*conntrack*) : une connexion TCP, mais aussi un
échange UDP (une requête et ses réponses entre les mêmes adresses et ports) ou ICMP (un
`echo-request` et son `echo-reply`). Chaque paquet a un **état** :

- **`new`** : il ouvre un nouvel échange (le SYN en TCP, le premier datagramme en UDP) ;
- **`established`** : il appartient à un échange déjà vu dans les deux sens : c'est le cas de
  toutes les **réponses** ;
- **`related`** : il est lié à un échange existant (une erreur ICMP qui le concerne) ;
- **`invalid`** : il n'appartient à rien de connu.

Un filtre **sans état** ne sait autoriser les réponses qu'à l'aveugle : « tout ce qui vient du
port 80 », « tout l'UDP qui vient du port 53 ». C'est une **faille** : celui qui choisit 80 ou 53
comme port source de ses paquets passe aussi. Avec le suivi de connexion, on autorise
l'**ouverture** d'un échange, dans un seul sens, et les réponses suivent :

```
nft add rule inet filter forward ct state established,related accept       # en première règle
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

La seconde règle laisse les machines derrière `eth2` ouvrir des connexions vers le port 80 de
celles derrière `eth0` ; les réponses passent par la première. Rien ne permet à une machine
derrière `eth0` d'ouvrir une connexion dans l'autre sens.

`ct state` se combine avec les autres critères quand on ne veut accepter que **certaines**
réponses :

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

La première n'accepte que les réponses du serveur DNS `192.0.2.53` aux questions que la machine
lui a posées ; la seconde, tout le trafic retour des connexions TCP que la machine a ouvertes.
""": """

Netfilter remembers the **connections** in progress (*conntrack*): a TCP connection, but also a
UDP exchange (a request and its replies between the same addresses and ports) or an ICMP one (an
`echo-request` and its `echo-reply`). Each packet has a **state**:

- **`new`**: it opens a new exchange (the SYN in TCP, the first datagram in UDP);
- **`established`**: it belongs to an exchange already seen in both directions: this is the case
  of every **reply**;
- **`related`**: it is linked to an existing exchange (an ICMP error about it);
- **`invalid`**: it belongs to nothing known.

A **stateless** filter can only allow replies blindly: "whatever comes from port 80", "all the
UDP coming from port 53". This is a **hole**: whoever picks 80 or 53 as the source port of their
packets gets through too. With connection tracking, the **opening** of an exchange is allowed, in
one direction only, and the replies follow:

```
nft add rule inet filter forward ct state established,related accept       # as the first rule
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

The second rule lets the machines behind `eth2` open connections to port 80 of those behind
`eth0`; the replies go through the first one. Nothing lets a machine behind `eth0` open a
connection the other way.

`ct state` combines with the other selectors when only **some** replies are to be accepted:

```
nft add rule inet filter input ip saddr 192.0.2.53 udp sport 53 ct state established accept
nft add rule inet filter input meta l4proto tcp ct state established,related accept
```

The first one only accepts the replies of the DNS server `192.0.2.53` to the questions the machine
asked it; the second one, all the return traffic of the TCP connections the machine opened.
""",
        """

Sous Linux, le filtrage est fait dans le noyau par **Netfilter**, configuré avec la commande
**`nft`** (nftables). Netfilter offre des points d'accrochage (*hooks*) sur le trajet d'un paquet :

```
                                            ┌──────── processus locaux ────────┐
                                            │                                  │
                                          input                             output
                                            │                                  │
  arrivée ──> prerouting ──> [décision de routage] ──> forward ──> postrouting ──> départ
```

- **`input`** : les paquets **destinés à la machine** (à l'une de ses adresses, quelle que soit
  l'interface d'arrivée) ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`forward`** : les paquets que la machine **route** : ni émis par elle, ni pour elle.

Un paquet ne passe que par **une** de ces trois chaînes. Conséquences :

- sur un routeur, `forward` ne protège pas le routeur lui-même (un `ping` *vers* le routeur passe
  par `input`) et `input` ne filtre rien de ce qui le traverse : il faut les deux ;
- un échange a **deux sens**. Sur un poste client, la requête sort par `output` et la réponse
  entre par `input`. À travers un routeur, la requête **et** la réponse passent par `forward`,
  avec les interfaces d'entrée et de sortie inversées ;
- un paquet d'une machine vers elle-même (`127.0.0.1`) passe par `output` puis par `input`, via
  l'interface `lo` : une politique `drop` en `input` casse aussi les communications locales ;
- `forward` ne voit des paquets que si le routage est activé (`sysctl net.ipv4.ip_forward`).
""": """

On Linux, filtering is done in the kernel by **Netfilter**, configured with the **`nft`** command
(nftables). Netfilter offers hooks on the path of a packet:

```
                                            ┌───────── local processes ────────┐
                                            │                                  │
                                          input                             output
                                            │                                  │
  arrival ──> prerouting ──> [routing decision] ──> forward ──> postrouting ──> departure
```

- **`input`**: the packets **addressed to the machine** (to one of its addresses, whatever the
  interface they arrive on);
- **`output`**: the packets **sent by the processes of the machine**;
- **`forward`**: the packets the machine **routes**: neither sent by it, nor for it.

A packet goes through **one** of these three chains only. Consequences:

- on a router, `forward` does not protect the router itself (a `ping` *to* the router goes through
  `input`) and `input` filters nothing of what crosses it: both are needed;
- an exchange has **two directions**. On a client, the request leaves through `output` and the
  reply enters through `input`. Across a router, the request **and** the reply go through
  `forward`, with the input and output interfaces swapped;
- a packet from a machine to itself (`127.0.0.1`) goes through `output` then `input`, on the
  interface `lo`: a `drop` policy on `input` also breaks local communications;
- `forward` only sees packets when routing is on (`sysctl net.ipv4.ip_forward`).
""",
        """

Tester un pare-feu, c'est vérifier ce qui **doit passer** et ce qui **doit être bloqué**, avec
des délais courts pour ne pas attendre :

| service | commande de test |
|---------|------------------|
| ICMP | `ping -c 2 -W 1 adresse` |
| HTTP (ports 80, 8080) | `curl -m 3 http://adresse/`, `curl -m 3 http://adresse:8080/` |
| DNS (UDP 53) | `dig @serveur nom +time=1 +tries=1` (ou `+short` pour la seule réponse) |
| SSH (TCP 22), courrier (TCP 25), tout port TCP | `nc -v -w 3 adresse 22` (la bannière du serveur s'affiche), `ssh root@adresse` |

Les serveurs web de test répondent par leur nom et par ce qu'ils voient du client :
`SERVER=dmz1`, `CLIENT_IP=…`, `TTL=63` (64 moins un par routeur traversé).

Le message d'erreur dit ce qui s'est passé :

| symptôme | cause probable |
|----------|----------------|
| `Connection timed out`, `100% packet loss`, après le délai | un paquet est **détruit** (`drop`), à l'aller ou au retour |
| `Connection refused`, immédiat | un `reject`, ou aucun serveur sur ce port |
| `Could not resolve host`, `Temporary failure in name resolution` | le **DNS** ne répond pas : la question ou la réponse est filtrée. Essayez avec l'adresse |
| `ping: sendmsg: Operation not permitted`, avec `Destination Port Unreachable` venant de la machine elle-même | un `reject` dans sa propre chaîne `output` (un `drop` n'y donne que `100% packet loss`) |
| `no servers could be reached` (`dig`) | la question DNS ou sa réponse est détruite |

Pour **localiser** un blocage : `tcpdump -n -i eth0 icmp or port 80` sur le routeur, côté
arrivée puis côté départ (le paquet entre-t-il ? ressort-il ? la réponse revient-elle ?), et
`nft list ruleset` avec des `counter` sur les règles pour voir laquelle a vu le paquet. Sur le
serveur, `ss -tulnp` liste les ports en écoute : un port fermé répond `Connection refused` même
sans pare-feu.
""": """

Testing a firewall means checking what **must pass** and what **must be blocked**, with short
timeouts so as not to wait:

| service | test command |
|---------|--------------|
| ICMP | `ping -c 2 -W 1 address` |
| HTTP (ports 80, 8080) | `curl -m 3 http://address/`, `curl -m 3 http://address:8080/` |
| DNS (UDP 53) | `dig @server name +time=1 +tries=1` (or `+short` for the answer alone) |
| SSH (TCP 22), mail (TCP 25), any TCP port | `nc -v -w 3 address 22` (the banner of the server is printed), `ssh root@address` |

The test web servers answer with their name and what they see of the client: `SERVER=dmz1`,
`CLIENT_IP=…`, `TTL=63` (64 minus one per router crossed).

The error message tells what happened:

| symptom | likely cause |
|---------|--------------|
| `Connection timed out`, `100% packet loss`, after the timeout | a packet is **dropped**, on the way out or on the way back |
| `Connection refused`, at once | a `reject`, or no server on that port |
| `Could not resolve host`, `Temporary failure in name resolution` | the **DNS** does not answer: the question or the reply is filtered. Try with the address |
| `ping: sendmsg: Operation not permitted`, with `Destination Port Unreachable` coming from the machine itself | a `reject` in its own `output` chain (a `drop` there only gives `100% packet loss`) |
| `no servers could be reached` (`dig`) | the DNS question or its reply is dropped |

To **locate** a blockage: `tcpdump -n -i eth0 icmp or port 80` on the router, on the arrival
side then on the departure side (does the packet come in? does it go out? does the reply come
back?), and `nft list ruleset` with `counter` statements on the rules to see which one saw the
packet. On the server, `ss -tulnp` lists the listening ports: a closed port answers `Connection
refused` even without a firewall.
""",
        """

Un **ensemble anonyme** s'écrit dans la règle : `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`,
`icmp type { echo-request, echo-reply }`. Une seule règle remplace plusieurs règles identiques.

Un **ensemble nommé** est un objet de la table, que plusieurs règles utilisent (`@nom`) et que l'on
modifie sans toucher aux règles :

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
```

Un **ensemble dynamique** est rempli **par les règles elles-mêmes**, au passage des paquets, et
ses éléments peuvent **expirer** :

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

Chaque paquet qui atteint la règle `add @banned { ip saddr }` fait ajouter son adresse source à
l'ensemble ; l'élément disparaît de lui-même 60 secondes plus tard (`update` au lieu de `add`
relance le délai à chaque paquet). `add @banned …` n'est pas un verdict : le paquet continue vers
la règle suivante. `nft list set inet filter banned` montre les éléments et le temps qui leur
reste (`expires 54s768ms`), `nft flush set inet filter banned` vide l'ensemble. On construit ainsi un
bannissement temporaire, une limite par adresse ou un *port knocking*.
""": """

An **anonymous set** is written in the rule: `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }`,
`icmp type { echo-request, echo-reply }`. One rule replaces several identical ones.

A **named set** is an object of the table, used by several rules (`@name`) and changed without
touching the rules:

```
nft 'add set inet filter admins { type ipv4_addr; }'
nft 'add element inet filter admins { 192.0.2.10, 192.0.2.20 }'
nft add rule inet filter input ip saddr @admins tcp dport 22 accept
nft list set inet filter admins
```

A **dynamic set** is filled **by the rules themselves**, as packets go by, and its elements can
**expire**:

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'
nft 'add rule inet filter forward tcp dport 23 add @banned { ip saddr }'
nft add rule inet filter forward ip saddr @banned drop
```

Each packet reaching the rule `add @banned { ip saddr }` gets its source address added to the
set; the element disappears by itself 60 seconds later (`update` instead of `add` restarts the
timer at each packet). `add @banned …` is not a verdict: the packet goes on to the next rule.
`nft list set inet filter banned` shows the elements and the time they have left (`expires
54s768ms`), `nft flush set inet filter banned` empties the set. This is how a temporary ban, a limit
per address or *port knocking* are built.
""",
        """

Un **pare-feu** applique une politique aux paquets IP : accepter, détruire ou refuser. Il peut
tourner à deux endroits :

- sur **une machine** qu'il protège (*host firewall*) : il filtre ce qui **entre** dans la machine
  et, plus rarement, ce qui en **sort** (interdire à un poste d'envoyer du courrier directement,
  par exemple) ;
- sur **un routeur** (*network firewall*) : il filtre ce qui **traverse** le routeur, entre des
  **zones** de confiance différentes. Le routeur est lui-même une machine à protéger.

Le découpage classique compte trois zones, chacune derrière une interface du routeur :

- l'**extérieur** (Internet) : on n'y maîtrise rien ;
- le **réseau interne** : les postes de travail. Ils ouvrent des connexions vers l'extérieur,
  mais **aucune** connexion ne doit y entrer ;
- la **DMZ** (*zone démilitarisée*) : les serveurs que l'extérieur doit pouvoir joindre (web,
  DNS, courrier). Ils sont **isolés** du réseau interne : un serveur compromis ne donne pas accès
  aux postes.

Une politique de filtrage se résume par une **matrice des flux** : pour chaque couple (zone
source, zone destination), les services autorisés. Tout le reste est interdit :

| de ↓ vers → | extérieur | DMZ | interne |
|-------------|-----------|-----|---------|
| **extérieur** | — | les services publiés (HTTP d'un serveur…) | rien |
| **DMZ** | le strict nécessaire (DNS d'un serveur…) | — | rien |
| **interne** | la navigation (HTTP, DNS) | les services de la DMZ | — |

La règle d'or : **tout ce qui n'est pas explicitement autorisé est interdit**. On l'obtient avec
une politique par défaut `drop` et une règle par flux autorisé, jamais l'inverse.
""": """

A **firewall** applies a policy to IP packets: accept, drop or reject. It can run in two places:

- on **a machine** it protects (*host firewall*): it filters what **enters** the machine and,
  more rarely, what **leaves** it (forbidding a workstation to send mail directly, for
  instance);
- on **a router** (*network firewall*): it filters what **crosses** the router, between **zones**
  of different trust. The router is itself a machine to protect.

The classic layout has three zones, each one behind an interface of the router:

- the **outside** (the Internet): nothing there is under control;
- the **internal network**: the workstations. They open connections to the outside, but **no**
  connection may come in;
- the **DMZ** (*demilitarised zone*): the servers the outside must reach (web, DNS, mail). They
  are **isolated** from the internal network: a compromised server gives no access to the
  workstations.

A filtering policy is summed up by a **flow matrix**: for each pair (source zone, destination
zone), the services allowed. Everything else is forbidden:

| from ↓ to → | outside | DMZ | internal |
|-------------|---------|-----|----------|
| **outside** | — | the published services (the HTTP of one server…) | nothing |
| **DMZ** | the bare minimum (the DNS of one server…) | — | nothing |
| **internal** | browsing (HTTP, DNS) | the services of the DMZ | — |

The golden rule: **whatever is not explicitly allowed is forbidden**. It is obtained with a
default policy `drop` and one rule per allowed flow, never the other way round.
""",
        """

Un jeu de règles (*ruleset*) est fait de **tables** (famille `inet` : IPv4 et IPv6), qui
contiennent des **chaînes**, qui contiennent des **règles**. Une **chaîne de base** est accrochée
à un hook, avec un type, une priorité et une **politique** : le verdict des paquets qu'aucune règle
n'a tranchés. Une même table peut porter une chaîne par hook :

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

(les apostrophes protègent les accolades et les points-virgules du shell.) Refaire `add chain`
sur une chaîne existante avec une autre politique **change sa politique** sans toucher à ses
règles.

Les règles d'une chaîne sont évaluées **dans l'ordre** ; la première qui porte un verdict et dont
tous les critères sont satisfaits décide. L'ordre se choisit à l'ajout :

```
nft add rule inet filter input iif lo accept           # à la FIN de la chaîne
nft insert rule inet filter input iif lo accept        # au DÉBUT
nft -a list ruleset                                    # affiche le numéro (handle) de chaque règle
nft insert rule inet filter input handle 7 …           # avant la règle 7 (add rule … handle 7 : après)
nft replace rule inet filter input handle 7 …          # remplace la règle 7
nft delete rule inet filter input handle 7             # supprime la règle 7
nft flush chain inet filter output                     # vide une chaîne (sa politique reste)
```

Dès qu'un pare-feu dépasse quelques règles, on l'écrit dans un **fichier** que l'on recharge d'un
bloc : c'est plus sûr que de retoucher les règles une à une, et l'ordre y est lisible.

```
# /root/firewall.nft — chargé par : nft -f /root/firewall.nft
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        tcp dport 80 accept
    }
}
```

`nft -f` remplace l'ancien jeu de règles par le nouveau de façon **atomique** : si le fichier
contient une erreur, rien n'est changé. `nft list ruleset > /root/firewall.nft` produit un tel
fichier à partir des règles en place (ajoutez `flush ruleset` en tête).
""": """

A ruleset is made of **tables** (family `inet`: IPv4 and IPv6), which hold **chains**, which hold
**rules**. A **base chain** is attached to a hook, with a type, a priority and a **policy**: the
verdict of the packets no rule has settled. One table may carry a chain per hook:

```
nft add table inet filter
nft 'add chain inet filter input   { type filter hook input   priority 0; policy drop; }'
nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'
nft 'add chain inet filter output  { type filter hook output  priority 0; policy accept; }'
```

(the single quotes protect the braces and the semicolons from the shell.) Running `add chain`
again on an existing chain with another policy **changes its policy** and leaves its rules alone.

The rules of a chain are evaluated **in order**; the first one that carries a verdict and whose
selectors all match decides. The order is chosen when the rule is added:

```
nft add rule inet filter input iif lo accept           # at the END of the chain
nft insert rule inet filter input iif lo accept        # at the BEGINNING
nft -a list ruleset                                    # shows the number (handle) of each rule
nft insert rule inet filter input handle 7 …           # before rule 7 (add rule … handle 7: after)
nft replace rule inet filter input handle 7 …          # replaces rule 7
nft delete rule inet filter input handle 7             # deletes rule 7
nft flush chain inet filter output                     # empties a chain (its policy stays)
```

As soon as a firewall has more than a few rules, it is written in a **file** loaded in one go:
this is safer than touching the rules one by one, and the order is there to read.

```
# /root/firewall.nft — loaded by: nft -f /root/firewall.nft
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        tcp dport 80 accept
    }
}
```

`nft -f` replaces the old ruleset by the new one **atomically**: if the file holds an error,
nothing is changed. `nft list ruleset > /root/firewall.nft` writes such a file from the rules in
place (add `flush ruleset` at its top).
""",
        """

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table et chaînes | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (de même `input`, `output`) |
| règles | `nft add rule inet filter forward …` (fin), `nft insert rule …` (début), `nft insert rule inet filter forward handle N …` (avant la règle N), `nft delete rule inet filter forward handle N` |
| critères | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts | `accept`, `drop`, `reject`, `counter` |
| ensembles | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| fichier | `nft -f /root/firewall.nft` (commençant par `flush ruleset`), `nft list ruleset > /root/firewall.nft` |
| tout effacer | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S nom +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
""": """

| need | command |
|------|---------|
| state of the firewall | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter forward` |
| table and chains | `nft add table inet filter`, `nft 'add chain inet filter forward { type filter hook forward priority 0; policy drop; }'` (likewise `input`, `output`) |
| rules | `nft add rule inet filter forward …` (end), `nft insert rule …` (beginning), `nft insert rule inet filter forward handle N …` (before rule N), `nft delete rule inet filter forward handle N` |
| selectors | `iif lo`, `iifname eth2`, `oifname eth0`, `ip saddr A`, `ip daddr A`, `tcp dport 80`, `udp sport 53`, `icmp type echo-request`, `ct state established,related` |
| verdicts | `accept`, `drop`, `reject`, `counter` |
| sets | `tcp dport { 80, 8080 }`, `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `ip saddr @banned drop`, `add @banned { ip saddr }`, `nft list set inet filter banned`, `nft flush set inet filter banned` |
| file | `nft -f /root/firewall.nft` (starting with `flush ruleset`), `nft list ruleset > /root/firewall.nft` |
| erase everything | `nft flush chain inet filter forward`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `ping -c 2 -W 1 A`, `curl -m 3 http://A/`, `dig @S name +time=1 +tries=1`, `nc -v -w 3 A 25`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or port 80` |
""",
        """

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname eth0` | interface d'**entrée** du paquet (`iif` : par index, l'interface doit exister ; `iifname` : par nom) |
| `oifname eth1`, `oif eth1` | interface de **sortie** (connue dans `forward` et `output`, pas dans `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | adresse ou réseau **source** |
| `ip daddr 192.0.2.10` | adresse ou réseau **destination** |
| `meta l4proto tcp`, `ip protocol udp` | protocole de transport (`tcp`, `udp`, `icmp`) |
| `tcp dport 80`, `udp dport 53` | port **destination** : le service demandé |
| `tcp sport 80`, `udp sport 53` | port **source** : dans une réponse, le port du serveur |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête et réponse) |
| `ct state established,related`, `ct state new` | état dans le suivi de connexion (section @@ref:conntrack@@) |
| `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }` | un **ensemble** de valeurs (section @@ref:sets@@) |
| `ip daddr != 192.0.2.10` | négation |

Les critères d'une règle sont **tous** requis. `tcp dport` ou `icmp type` impliquent le
protocole. Une règle de pare-feu de réseau dit en général **d'où** vient le paquet et **où** il
va, puis le service :

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

Filtrer sur l'adresse source seule est fragile : une adresse se falsifie (*spoofing*). Pour une
règle sensible, on exige **l'interface et l'adresse** : `iifname eth2 ip saddr 192.0.2.10 tcp
dport 22 accept` n'accepte la machine d'administration que si elle arrive du bon côté.
""": """

| selector | meaning |
|----------|---------|
| `iif lo`, `iifname eth0` | **input** interface of the packet (`iif`: by index, the interface must exist; `iifname`: by name) |
| `oifname eth1`, `oif eth1` | **output** interface (known in `forward` and `output`, not in `input`) |
| `ip saddr 192.0.2.10`, `ip saddr 192.0.2.0/24` | **source** address or network |
| `ip daddr 192.0.2.10` | **destination** address or network |
| `meta l4proto tcp`, `ip protocol udp` | transport protocol (`tcp`, `udp`, `icmp`) |
| `tcp dport 80`, `udp dport 53` | **destination** port: the service asked for |
| `tcp sport 80`, `udp sport 53` | **source** port: in a reply, the port of the server |
| `icmp type echo-request`, `icmp type echo-reply` | ICMP type (`ping`: request and reply) |
| `ct state established,related`, `ct state new` | state in connection tracking (section @@ref:conntrack@@) |
| `tcp dport { 80, 8080 }`, `iifname { eth1, eth2 }` | a **set** of values (section @@ref:sets@@) |
| `ip daddr != 192.0.2.10` | negation |

The selectors of a rule are **all** required. `tcp dport` or `icmp type` imply the protocol. A
rule of a network firewall usually says **where** the packet comes from and **where** it goes,
then the service:

```
nft add rule inet filter forward iifname eth2 oifname eth0 tcp dport 80 accept
```

Filtering on the source address alone is weak: an address can be forged (*spoofing*). A
sensitive rule requires **the interface and the address**: `iifname eth2 ip saddr 192.0.2.10 tcp
dport 22 accept` only accepts the administration machine when it arrives from the right side.
""",
        """

| iptables | nftables |
|----------|----------|
| `iptables -L -v -n` | `nft list ruleset` |
| `iptables -P FORWARD DROP` | `policy drop;` dans la déclaration de la chaîne `forward` |
| `iptables -A INPUT -i lo -j ACCEPT` | `nft add rule inet filter input iif lo accept` |
| `iptables -A INPUT -p udp -s A --sport 53 -m state --state ESTABLISHED -j ACCEPT` | `… input ip saddr A udp sport 53 ct state established accept` |
| `iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT` | `… input meta l4proto tcp ct state established,related accept` |
| `iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT` | `… input icmp type echo-request accept` |
| `iptables -A INPUT -p tcp -s R/24 --dport 22 -j ACCEPT` | `… input ip saddr R/24 tcp dport 22 accept` |
| `iptables -A OUTPUT -p tcp --dport 25 -j REJECT` | `… output tcp dport 25 reject` |
| `iptables -A FORWARD -i eth2 -o eth0 -p tcp --dport 80 -j ACCEPT` | `… forward iifname eth2 oifname eth0 tcp dport 80 accept` |
| `iptables -F FORWARD` | `nft flush chain inet filter forward` |
| `-m recent --name L --set`, `-m recent --name L --rcheck --seconds 60` | `add @L { ip saddr }`, `ip saddr @L` avec un ensemble `timeout 60s` |
| `-m string --string toto` | pas d'équivalent dans nftables |
""": """

| iptables | nftables |
|----------|----------|
| `iptables -L -v -n` | `nft list ruleset` |
| `iptables -P FORWARD DROP` | `policy drop;` in the declaration of the `forward` chain |
| `iptables -A INPUT -i lo -j ACCEPT` | `nft add rule inet filter input iif lo accept` |
| `iptables -A INPUT -p udp -s A --sport 53 -m state --state ESTABLISHED -j ACCEPT` | `… input ip saddr A udp sport 53 ct state established accept` |
| `iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT` | `… input meta l4proto tcp ct state established,related accept` |
| `iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT` | `… input icmp type echo-request accept` |
| `iptables -A INPUT -p tcp -s R/24 --dport 22 -j ACCEPT` | `… input ip saddr R/24 tcp dport 22 accept` |
| `iptables -A OUTPUT -p tcp --dport 25 -j REJECT` | `… output tcp dport 25 reject` |
| `iptables -A FORWARD -i eth2 -o eth0 -p tcp --dport 80 -j ACCEPT` | `… forward iifname eth2 oifname eth0 tcp dport 80 accept` |
| `iptables -F FORWARD` | `nft flush chain inet filter forward` |
| `-m recent --name L --set`, `-m recent --name L --rcheck --seconds 60` | `add @L { ip saddr }`, `ip saddr @L` with a set declared `timeout 60s` |
| `-m string --string toto` | no equivalent in nftables |
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
        'Bonus : bannir temporairement une machine': 'Bonus: banning a machine for a while',
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
        'Pour qui connaît iptables': 'For those who know iptables',
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
