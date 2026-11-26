"""Host firewall lab (TP2 "Parefeux" of the R306 course, converted from the iptables / Marionnet
handout to nftables): the students write, on ``m1``, the ``input`` chain of an nftables ruleset,
question after question: default policy ``drop``, the loopback interface, ICMP echo replies, UDP
from one server, ``drop`` versus ``reject``, the stateful rule (``ct state established,related``),
one open TCP port placed before an earlier ``reject`` (rule order, handles), then a named chain
logging (``limit rate``) and dropping what is left (questions 1 to 9, 100 points).  Questions 10
to 14 (40 points and a bonus of 6) go on with the same ruleset: the ``output`` chain as a
whitelist (policy ``drop``, the stateful rule, one forbidden destination), then the sets: a
blocklist with ``flags interval``, a set of ports looked up by the output chain, a set of
address . port pairs, and a dynamic set banning whoever touches a trap port.

Topology::

    m1 (firewall) ---+                                    +-- ext1
    m2 --------------+-- [switch lan] -- eth0 gw eth1 -- [switch ext] --+-- ext2
    m3 --------------+                    eth2                          +-- ext3
                                           |
                                     [switch guest] -- guest1

``gw`` routes between ``lan``, ``ext`` and ``guest`` (the default route of every host); ``ext1``
plays the "server of the exterior" whose UDP is accepted in question 5 and the client "from
outside" of the probes of questions 1 to 9.  The other machines belong to the later questions,
so that no question undoes what an earlier one grades: ``ext2`` is the destination ``m1`` must not
contact (question 10) and a member of the allowlist (question 13), ``ext3`` and the whole
``guest`` network are blocklisted (question 11).  Every machine runs the echo server of
``lib/server_echo.py`` (HTTP on TCP 80, 8080 and 8888, UDP on 530 and 630: the answer gives the
addresses and ports of both ends and the TTL of the packet), the services the students open or
close.

**No question costs the points of another**: the output whitelist allows what the probes of
questions 1 to 9 emit from ``m1`` (``lo``, ping, TCP 80, UDP 530 / 630, and every reply through
``ct state established,related``, the ICMP error of the ``reject`` of question 6 included: it is
``related``), every later restriction is observed on a machine or a port no earlier question
probes, and every later rule of ``input`` is inserted.  What is graded is the final ruleset: a
*wrong* output chain does cost the earlier probes it breaks.

Grading uses the "hidden mirror" of ``lib/hidden_mirror.py`` / ``lib/firewall.py``: a hidden clone
of the whole topology (``m1_h`` … ``guest1_h`` on ``lan_h`` / ``ext_h`` / ``guest_h``, same
addresses, same echo servers), onto which the live ruleset of ``m1`` (``nft list ruleset``) is
transplanted at each evaluation; the probes then run from and to the clones, where the expected
result is known and the students cannot interfere.  What the ruleset *says* is read from ``nft -j
list ruleset`` of ``m1`` (policy, selectors, verdicts, rule order, ``log`` / ``limit``, sets),
what it *does* from the probes (step 3; steps 4 and 5 for the ban of the bonus question).  The
``final`` state applies the reference solution (140/140 and the bonus).  Texts are French
(``tr()``) with their English in ``_TRANSLATIONS``, identifiers English.
"""
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, ip_address
from typing import List

from SRE import params
from SRE.lib_sre import Data0, Grade0, NetScheme0, instructor, make_tr, no_tr, sre_state
from SRE.lib_sre import info_subtitle, info_toc
from ips import random_ipv4networks
from net_config import set_ip_forward
from server_echo_helpers import get_http_echo, get_udp_echo, install_echo_server
import firewall
import hidden_mirror

default_language = 'fr'
tr = make_tr(default_language)

title = tr("nftables : pare-feu d'une machine", en="nftables: a host firewall")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
# An evaluation waits for the probes the firewall must block (4 s per dropped TCP connection).
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

FIREWALL = 'm1'                 # the machine whose input and output chains the students write
MIRROR = '_h'                   # suffix of the hidden clones (hidden_mirror.expand_topology)
FAMILY, TABLE, CHAIN = 'inet', 'filter', 'input'   # the table and base chain of the reference solution
OUT_CHAIN = 'output'            # question 10: the base chain of the output hook
LOG_CHAIN = 'logdrop'           # question 9: the named chain logging then dropping
LOG_RATE = 5                    # question 9 (d): at most LOG_RATE log messages per minute
LOG_PREFIX = 'input drop: '
NFLOG_GROUP = 0                 # `log group 0`, read with `tcpdump -i nflog:0` (the kernel log is not readable in a container)
OPEN_PORT = 8080                # question 8: the TCP port opened to everybody
CLOSED_PORT = 80                # ... while this one stays closed
SET_PORT = 8888                 # questions 12 and 13: a third HTTP port, opened through sets only
HTTP_PORTS = (CLOSED_PORT, OPEN_PORT, SET_PORT)   # the echo server of every machine: HTTP ports...
UDP_PORTS = (530, 630)          # ... and UDP ports
UDP_PORT = UDP_PORTS[0]         # the UDP port of the probes
UDP_SERVER = 'ext1'             # question 5: the machine whose UDP is accepted
REJECTED = 'm2'                 # question 6: the machine whose packets are rejected (the others are dropped)
# Questions 10 to 14 only use machines and ports that questions 1 to 9 never probe.
FORBIDDEN = 'ext2'              # question 10: the machine m1 must not open anything to
BLOCKED_HOST = 'ext3'           # question 11: the blocklisted address...
BLOCKED_NET = 'guest'           # ... and the blocklisted network,
BLOCKED_NET_HOST = 'guest1'     # ... probed from this machine of it
BLOCK_SET = 'blocklist'         # question 11: the set of the blocklisted addresses (flags interval)
PORT_SET = 'web_ports'          # question 12: the set of the TCP ports m1 may contact
ALLOW_SET = 'allowed'           # question 13: the set of the (address . port) pairs let in
ALLOWED = (('ext2', CLOSED_PORT), ('m3', SET_PORT))   # ... and its pairs (machine, port of m1)
BAN_SET = 'banned'              # question 14 (bonus): the set fed by the trap rule
TRAP_PORT = 23                  # ... whoever opens a connection to this port of m1 is banned
BAN_SECONDS = 60                # ... for that long
BAN_SOURCE, BAN_SPARED = 'ext1', 'm3'   # the clone walking into the trap, and one that does not
DOMAIN = 'lab'
LOAD_STEP = 2                   # the ruleset of m1 is read at step 1 and loaded on its clone at step 2
PROBE_STEP = 3                  # the probes run after the transplant
TRAP_STEP, BAN_STEP = 4, 5      # question 14: the connection to the trap port, then the probes of the ban
PROBE_TIMEOUT = 4               # bash /dev/tcp connection timeout: a dropped SYN is declared after that
OUT_TIMEOUT = 3                 # ... for what m1 itself opens (a local reject is seen with the SYN retransmission, after 1 s)
VISIBLE_MACHINES = ('m1', 'm2', 'm3', 'gw', 'ext1', 'ext2', 'ext3', 'guest1')
HOSTS = ('m1', 'm2', 'm3', 'ext1', 'ext2', 'ext3', 'guest1')   # single-homed machines (gw has gw_lan / gw_ext / gw_guest)

#: ips.<key> -> network, host part (m1 = .1 ... gw = .254 on every side, ext1 = .51 ...)
HOST_PARTS = {'m1': 1, 'm2': 2, 'm3': 3, 'gw_lan': 254, 'gw_ext': 254, 'ext1': 51, 'ext2': 52, 'ext3': 53,
              'gw_guest': 254, 'guest1': 1}
ADDRESSED = {'m1': 'lan', 'm2': 'lan', 'm3': 'lan', 'gw_lan': 'lan', 'gw_ext': 'ext', 'ext1': 'ext', 'ext2': 'ext',
             'ext3': 'ext', 'gw_guest': 'guest', 'guest1': 'guest'}
NETWORKS = ('lan', 'ext', 'guest')

# The visible topology and its hidden mirror (clones m1_h ... guest1_h on lan_h / ext_h / guest_h).
_TOPOLOGY = {
    'lan': {'m1': 0, 'm2': 0, 'm3': 0, 'gw': 0},
    'ext': {'gw': 1, 'ext1': 0, 'ext2': 0, 'ext3': 0},
    'guest': {'gw': 2, 'guest1': 0},
}
_SPECS = {
    'm1': {'color': 'lightblue'},
    'm2': {}, 'm3': {},
    'gw': {'color': 'lightgreen'},
    'ext1': {'color': 'lightgrey'}, 'ext2': {'color': 'lightgrey'}, 'ext3': {'color': 'lightgrey'},
    'guest1': {'color': 'lightyellow'},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS, suffix=MIRROR)
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


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
        networks = random_ipv4networks(masks=[24] * len(NETWORKS), from_private_network=True,
                                       exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        for name, network in zip(NETWORKS, networks):
            setattr(data.nets, name, network)
        for key, net in ADDRESSED.items():
            network = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{network.network_address + HOST_PARTS[key]}/{network.prefixlen}"))
        # the clones get the same subnets and addresses (persisted in data.json)
        hidden_mirror.copy_addressing(data, _TOPOLOGY, suffix=MIRROR)
        return data


def ip_of(data, machine: str) -> IPv4Interface:
    """The address of a single-homed machine or of its clone (``gw``: ``data.ips.gw_lan`` / ``gw_ext`` /
    ``gw_guest``)."""
    return getattr(data.ips, visible(machine))


def allowed_pairs(data) -> List[tuple]:
    """Question 13: the ``(address, port)`` pairs of the allowlist."""
    return [(str(ip_of(data, machine).ip), port) for machine, port in ALLOWED]


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS
    _network_specs = {
        'lan': {'mode': 'switch', 'color': 'lightcyan'},
        'ext': {'mode': 'switch', 'color': 'lightgrey'},
        'guest': {'mode': 'switch', 'color': 'lightyellow'},
        'lan' + MIRROR: {'mode': 'switch'},
        'ext' + MIRROR: {'mode': 'switch'},
        'guest' + MIRROR: {'mode': 'switch'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pare-feu, Netfilter et nftables"), tag="intro")
            + tr("""

Un **pare-feu** (*firewall*) examine les paquets qui **entrent** dans une machine, en **sortent**
ou la **traversent**, et applique à chacun une **politique** : 

- soit le laisser passer (*accept*) ;
- soit le détruire en silence (*drop*) ; 
- soit le refuser en prévenant l'émetteur (*reject*) ;

selon des critères
comme l'interface, les adresses, le protocole, les ports ou l'état de la connexion. Un pare-feu
*de machine* (*host firewall*) protège la machine sur laquelle il tourne : c'est le sujet de ce
TP, qui filtre ce qui **entre** dans `m1`, puis ce qui en **sort**. Un pare-feu *de réseau* tourne
sur un routeur et filtre ce qui le traverse (prochain TP).

Sous Linux, tout se passe **dans le noyau**. **Netfilter** y fournit des points d'accrochage
(*hooks*) sur le trajet des paquets, le suivi de connexion (*conntrack*) et la traduction
d'adresses (NAT). **nftables** exécute, à ces points d'accrochage, les règles que lui confie la
commande **`nft`**. nftables a remplacé `iptables`, `ip6tables`, `arptables` et `ebtables` (c'est
l'outil par défaut depuis Debian 10) : une seule commande et une seule syntaxe pour IPv4, IPv6,
ARP et les ponts, un jeu de règles chargé d'un bloc, des ensembles et des dictionnaires intégrés
au langage. Sur une machine récente, la commande `iptables` n'est plus qu'un traducteur : ses
règles sont des règles nftables, que `nft list ruleset` affiche aussi (section
@@ref:from-iptables@@).

Le vocabulaire, détaillé dans les sections suivantes :

| terme | rôle |
|-------|------|
| famille | les paquets qu'une table voit : `ip` (IPv4), `ip6` (IPv6), `inet` (les deux), `arp`, `bridge`, `netdev` |
| table | un conteneur nommé, dans une famille, de chaînes, d'ensembles et de compteurs |
| chaîne de base | une liste de règles accrochée à un hook, avec une priorité et une politique par défaut |
| chaîne régulière | une liste de règles sans hook, où l'on arrive par un saut (`jump`, `goto`) |
| règle | des critères puis des actions, évalués de gauche à droite |
| verdict | ce que devient le paquet : `accept`, `drop`, `jump`… |
| ensemble, dictionnaire | des valeurs (*set*) ou des associations clé : valeur (*map*) que les règles consultent |

Les machines du TP ont nftables 1.1.3 (`nft --version`), la version de Debian 13 : c'est elle que
ce cours décrit.

**Comment lire ce cours.** Le TP en utilise l'essentiel : les hooks `input` et `output`
(section @@ref:hooks-ip@@), les tables, les chaînes et les règles (section @@ref:structure@@), les
critères (@@ref:selectors@@), les verdicts (@@ref:verdicts@@), le suivi de connexion
(@@ref:conntrack@@), le filtrage de ce qui sort (@@ref:output@@), la commande `nft`
(@@ref:nft-cli@@), la journalisation (@@ref:logging@@), les ensembles (@@ref:sets@@) et les tests
(@@ref:testing@@). Le reste (les hooks `ingress` et `egress`, les dictionnaires, la limitation de
débit, la traduction d'adresses, les bonnes pratiques) complète le tableau : vous en aurez besoin
dans les TP suivants et sur de vraies machines. Si vous connaissez déjà `iptables`, la section
@@ref:from-iptables@@ fait la correspondance entre les deux.
""")
            + info_subtitle(tr("Le trajet d'un paquet : les hooks"), tag="hooks")
            + tr("""

Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Une chaîne de base s'accroche à **un** hook :
choisir le hook, c'est choisir **quels paquets** la chaîne verra, et **à quel moment** de leur
traitement.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hooks-ip@@ Les cinq hooks de la pile IP

- **`prerouting`** : tous les paquets **reçus**, avant la décision de routage (« ce paquet est-il
  pour moi, ou à faire suivre ? ») ; c'est là que l'on change l'adresse de destination (DNAT) ;
- **`input`** : les paquets **destinés à la machine**, juste avant leur remise à un processus
  local ;
- **`forward`** : les paquets qui **traversent** la machine, reçus par une interface et routés
  vers une autre (elle doit faire office de routeur : `net.ipv4.ip_forward=1`) ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`postrouting`** : tous les paquets qui **partent**, routés ou émis localement, juste avant
  d'être confiés à l'interface de sortie ; c'est là que l'on change l'adresse source (SNAT,
  *masquerade*).

Un paquet suit donc l'un de ces trois trajets :

| paquet | hooks traversés, dans l'ordre |
|--------|-------------------------------|
| reçu et destiné à la machine | `prerouting`, `input` |
| reçu et routé vers une autre machine | `prerouting`, `forward`, `postrouting` |
| émis par la machine | `output`, `postrouting` |

Un paquet émis par `m1` vers `m2` passe par `output` puis `postrouting` ; la réponse de `m2`
arrive par `prerouting` puis `input`. Un paquet de `m1` vers elle-même (`127.0.0.1`, ou sa propre
adresse) fait les deux trajets à la suite, à travers l'interface `lo` : `output`, `postrouting`,
puis `prerouting` et `input`. Un pare-feu qui détruit tout en `input` casse donc aussi les
communications locales. Dans ce TP, on travaille dans le hook **`input`** de `m1`, puis dans son
hook **`output`**.

### @@sec:ingress@@ Les hooks ingress et egress

Deux autres hooks sont placés **au ras de l'interface réseau**, en dehors de la pile IP. À la
différence des cinq précédents, ils sont attachés à **une interface**, que la chaîne nomme dans
sa déclaration (`device`) :

- **`ingress`** : tout ce que l'interface **reçoit**, **avant `prerouting`**, donc avant le
  réassemblage des fragments, avant le suivi de connexion et avant le routage. C'est l'endroit
  le moins coûteux pour détruire un trafic indésirable (une inondation de paquets, des adresses
  sources impossibles) : le noyau n'a encore presque rien fait du paquet. En contrepartie,
  l'état de la connexion (`ct state`) n'y est pas encore connu ;
- **`egress`** : tout ce que l'interface **émet**, **après `postrouting`** : le dernier point de
  contrôle avant le départ.

Ces deux hooks appartiennent à la famille **`netdev`**, dont les chaînes voient **toutes les
trames** de l'interface, quel que soit le protocole : IPv4 et IPv6, mais aussi ARP ou les trames
802.1Q. Le hook `ingress` existe aussi dans la famille `inet` (depuis le noyau 5.10), où il ne
voit que les paquets IPv4 et IPv6 ; `egress` (depuis le noyau 5.16) n'existe que dans la famille
`netdev`.

```
nft add table netdev filter
nft 'add chain netdev filter eth0_filter { type filter hook ingress device eth0 priority 0; }'
nft add rule netdev filter eth0_filter ip saddr 198.51.100.0/24 drop
```

### @@sec:families@@ Les hooks de chaque famille

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | les cinq mêmes |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

ARP n'est pas de l'IP : les chaînes des familles `ip`, `ip6` et `inet` ne voient jamais les
requêtes ni les réponses ARP. C'est pourquoi une politique `drop` en `input` n'empêche pas une
machine de trouver l'adresse MAC de ses voisines, ni de répondre à leurs requêtes ARP.
""")
            + info_subtitle(tr("Tables, chaînes, règles"), tag="structure")
            + tr("""

Un jeu de règles nftables (*ruleset*) est organisé en **tables**, qui contiennent des
**chaînes**, qui contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table
ni chaîne prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des chaînes
sont libres ; `filter` et `input` ne sont que des habitudes. Voici ce qu'affiche `nft list
ruleset` pour un petit pare-feu ; c'est aussi la syntaxe d'un fichier de règles
(section @@ref:nft-files@@) :

```
table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                tcp dport 22 accept
        }
}
```

### @@sec:tables@@ Les tables

Une **table** appartient à une **famille** (section @@ref:families@@), qui fixe les paquets que
ses chaînes peuvent voir et les hooks dont elles disposent. Pour filtrer, la famille **`inet`**
est le choix recommandé : les mêmes règles valent pour IPv4 et pour IPv6.

```
nft add table inet filter
```

Une machine peut avoir plusieurs tables. Chacune est un espace de noms indépendant : ses
chaînes, ses ensembles et ses compteurs ne sont connus que de ses propres règles (un saut ne sort
jamais de sa table). Un logiciel qui installe ses propres règles (Docker, par exemple) le fait
dans ses propres tables : travaillez dans la vôtre et ne touchez pas aux siennes.

### @@sec:base-chains@@ Les chaînes de base

Une **chaîne de base** est accrochée à un hook. Sa déclaration donne quatre éléments :

```
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- le **type** : `filter` (dans toutes les familles et à tous les hooks : c'est le type à utiliser
  pour filtrer), `nat` (traduction d'adresses, section @@ref:nat@@) ou `route` (au hook `output` :
  refait le routage d'un paquet émis par la machine quand une règle l'a modifié) ;
- le **hook** (section @@ref:hooks@@) ; pour `ingress` et `egress`, il est suivi de `device` et du
  nom de l'interface ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus petite
  valeur à la plus grande ;
- la **politique** par défaut, `accept` ou `drop` : le verdict appliqué aux paquets qui atteignent
  la fin de la chaîne sans qu'aucune règle n'ait tranché. Sans `policy`, c'est `accept`.

Les apostrophes protègent du shell les accolades et les points-virgules ; `nft list ruleset`
réaffiche la chaîne avec `priority filter`, le nom de la priorité 0.

Avec `policy drop`, *tout ce qui n'est pas explicitement autorisé est interdit* : c'est la bonne
façon de construire un pare-feu. `reject` n'est pas une politique possible : pour refuser par
défaut plutôt que détruire, on termine la chaîne par une règle `reject`.

### @@sec:priorities@@ Priorités et chaînes multiples

Les priorités usuelles ont un nom (dans les familles `ip`, `ip6` et `inet`) :

| nom | valeur | usage |
|-----|--------|-------|
| `raw` | -300 | avant le suivi de connexion |
| `mangle` | -150 | modification des paquets |
| `dstnat` | -100 | traduction de l'adresse de destination (hook `prerouting`) |
| `filter` | 0 | filtrage |
| `security` | 50 | modules de sécurité (SELinux) |
| `srcnat` | 100 | traduction de l'adresse source (hook `postrouting`) |

On écrit `priority filter`, `priority 0` ou une valeur relative (`priority mangle - 5`, soit
-155). Le suivi de connexion est lui-même accroché à `prerouting` et à `output` avec la priorité
-200 : une chaîne de priorité `filter` voit des paquets dont l'état (`ct state`) est déjà connu,
une chaîne de priorité `raw` passe avant lui.

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées
au même hook : un paquet les traverse **toutes**, par priorité croissante, puis continue vers
les hooks suivants de son trajet. Les deux verdicts ne sont pas symétriques :

- **`drop` est définitif** : le paquet est détruit sur-le-champ, plus aucune chaîne ne le voit ;
- **`accept` ne vaut que pour la chaîne de base en cours** : le paquet passe à la chaîne
  suivante, qui peut encore le détruire.

Un paquet n'arrive donc à destination que si **chaque** chaîne de base qu'il traverse
l'accepte, et l'on ne peut pas « rattraper » dans une table un paquet qu'une autre a détruit.

### @@sec:regular-chains@@ Les chaînes régulières

Une **chaîne régulière** (on dit aussi chaîne *nommée*) n'a ni hook, ni type, ni politique :

```
nft add chain inet filter logdrop
```

Elle ne voit que les paquets qu'une règle lui envoie, par **`jump`** ou par **`goto`**, depuis
une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump`, l'évaluation
**reprend dans la chaîne appelante**, à la règle qui suit le saut ; avec `goto`, elle n'y revient
pas (au bout d'une chaîne atteinte par `goto` depuis une chaîne de base, c'est la politique de
celle-ci qui s'applique). Les sauts s'imbriquent sur 16 niveaux au plus, et le noyau refuse un
jeu de règles qui boucle.

Les chaînes régulières servent à **factoriser** (une chaîne « journaliser puis détruire »
appelée de plusieurs endroits) et à **structurer** un grand jeu de règles (une chaîne par
service, par zone ou par interface).

### @@sec:rules@@ Les règles

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des **critères**
(section @@ref:selectors@@), puis des **actions** et, le plus souvent, un **verdict**
(section @@ref:verdicts@@).

```
nft add rule inet filter input ip saddr 192.0.2.0/24 tcp dport 22 counter accept
```

- dès qu'un critère n'est pas satisfait, l'évaluation de la règle s'arrête et le paquet passe à
  la règle suivante ;
- les règles d'une chaîne sont évaluées **dans l'ordre** ; la première règle satisfaite qui porte
  un verdict (`accept`, `drop`, `reject`) décide, et les suivantes ne sont pas consultées.
  **L'ordre des règles fait donc partie de la politique** : une règle `accept` placée après une
  règle `drop` qui couvre les mêmes paquets ne sert à rien ;
- une règle sans verdict (`counter`, `log`…) agit, puis laisse le paquet continuer vers la règle
  suivante ;
- si aucune règle ne tranche, la politique de la chaîne de base s'applique.

L'ordre des mots compte aussi à l'intérieur d'une règle : `tcp dport 22 counter accept` compte
les paquets destinés au port 22, `counter tcp dport 22 accept` tous ceux qui atteignent la règle.

Le noyau attribue à chaque règle un numéro qui ne change plus, son **handle** (`nft -a list
ruleset`) : il sert à insérer, remplacer ou supprimer une règle précise
(section @@ref:nft-edit@@). Une règle peut se terminer par un commentaire :
`comment "ssh des administrateurs"`.
""")
            + info_subtitle(tr("Les critères (sélecteurs)"), tag="selectors")
            + tr("""

Un critère compare un **champ** du paquet, ou une information que le noyau lui associe, à une
**valeur**. Plusieurs critères dans une même règle sont tous requis (un **et**) ; pour un **ou**,
on utilise un ensemble de valeurs ou plusieurs règles.

### @@sec:headers@@ Les en-têtes du paquet

| critère | signification |
|---------|---------------|
| `ip saddr 192.0.2.2`, `ip daddr 192.0.2.0/24` | adresse IPv4 source, destination (une adresse ou un réseau) |
| `ip protocol udp` | protocole transporté par un paquet IPv4 (`tcp`, `udp`, `icmp`…) |
| `ip ttl 1`, `ip length 1500`, `ip dscp ef` | autres champs de l'en-tête IPv4 |
| `ip6 saddr 2001:db8::/32`, `ip6 daddr`, `ip6 hoplimit` | en-tête IPv6 |
| `tcp dport 8080`, `tcp sport 1024-65535` | port TCP destination, source |
| `udp dport 53`, `udp sport 53` | port UDP destination, source |
| `tcp flags syn` | drapeaux TCP (voir la section @@ref:values@@) |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête `echo-request`, réponse `echo-reply`) |
| `icmpv6 type nd-neighbor-solicit` | type ICMPv6 |
| `ether saddr 02:00:00:00:00:01` | adresse MAC source de la trame |
| `ct state established,related` | état de la connexion dans le suivi de connexion (section @@ref:conntrack@@) |

### @@sec:meta@@ Les informations associées au paquet

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | interface d'**entrée** (aux hooks `prerouting`, `input` et `forward`) |
| `oif eth0`, `oifname "eth0"` | interface de **sortie** (aux hooks `forward`, `output` et `postrouting`) |
| `meta l4proto udp` | protocole de niveau 4, en IPv4 comme en IPv6 |
| `meta nfproto ipv4` | version d'IP du paquet (`ipv4`, `ipv6`), utile dans une table `inet` |
| `meta pkttype broadcast` | paquet adressé à la machine (`host`), diffusé (`broadcast`) ou multidiffusé (`multicast`) |
| `meta mark 1` | marque posée sur le paquet par une autre règle (`meta mark set 1`) |
| `meta skuid 1000` | utilisateur propriétaire du processus qui émet le paquet (au hook `output`) |

**`iif` ou `iifname` ?** `iif lo` compare le **numéro** (l'index) de l'interface : c'est rapide,
mais l'interface doit exister quand la règle est chargée, et la règle ne suit pas une interface
supprimée puis recréée. `iifname "eth0"` compare le **nom** : un peu plus lent, mais valable pour
une interface qui n'existe pas encore (un VPN, une connexion à la demande), et le nom peut se
terminer par un joker (`iifname "eth*"`). Pour `lo` et les interfaces permanentes, `iif` convient.

### @@sec:values@@ Les formes de valeur

| forme | exemples |
|-------|----------|
| une valeur | `tcp dport 22`, `ip saddr 192.0.2.2` |
| un réseau | `ip saddr 192.0.2.0/24` |
| une plage | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| un ensemble | `tcp dport { 22, 80, 443 }`, `ip saddr { 192.0.2.2, 198.51.100.0/24 }` |
| un ensemble nommé | `ip saddr @blocklist` (section @@ref:sets@@) |
| la négation | `ip saddr != 192.0.2.2`, `tcp dport != { 22, 80 }` |
| une comparaison | `ip ttl lt 5`, `meta length gt 1000` (`lt` : inférieur à, `gt` : supérieur à) |

Un port peut être donné par le nom de son service (`tcp dport ssh`) ; `nft list ruleset` le
réaffiche en chiffres.

Pour un champ de **drapeaux** comme `tcp flags`, `tcp flags syn` signifie « le drapeau SYN est
positionné », quels que soient les autres : le critère vaut pour le SYN qui ouvre une connexion
comme pour le SYN-ACK qui lui répond. Pour désigner le SYN seul, on précise les drapeaux
examinés : `tcp flags & (fin|syn|rst|ack) == syn` (« parmi FIN, SYN, RST et ACK, seul SYN est
positionné »). `ct state established,related` se lit de la même façon : l'état est `established`
**ou** `related`.

### @@sec:implicit@@ Protocoles implicites et famille inet

Nommer un champ implique le protocole qui le porte : `tcp dport 8080` ne concerne que TCP,
`icmp type echo-reply` que ICMP ; inutile d'ajouter `ip protocol tcp`. Dans une table `inet` :

- `tcp dport 22 accept` vaut pour IPv4 **et** pour IPv6 ;
- un critère `ip …` (`ip saddr`, `ip protocol`…) restreint la règle à IPv4, un critère `ip6 …`
  à IPv6 ;
- `icmp` désigne l'ICMP d'IPv4 ; celui d'IPv6 s'écrit `icmpv6` ;
- `meta l4proto udp` désigne UDP dans les deux versions d'IP, `ip protocol udp` en IPv4 seulement.

`nft describe` donne le type d'un champ et ses valeurs possibles : `nft describe icmp type`,
`nft describe tcp flags`, `nft describe ct state`.
""")
            + info_subtitle(tr("Verdicts et actions"), tag="verdicts")
            + tr("""

### @@sec:verdict-list@@ Les verdicts

- **`accept`** : le paquet passe ; l'évaluation de la chaîne de base s'arrête (il reste soumis
  aux autres chaînes de son trajet, section @@ref:priorities@@) ;
- **`drop`** : le paquet est détruit **sans rien dire** : l'émetteur attend, réessaie, puis
  renonce (délai d'attente, *timeout*) ;
- **`reject`** : le paquet est détruit et l'émetteur est **prévenu** par un message d'erreur
  (section @@ref:reject@@) ;
- **`jump chaine`** : évalue la chaîne régulière, et revient si elle ne tranche pas ; **`goto
  chaine`** y va sans retour (section @@ref:regular-chains@@) ;
- **`return`** : quitte la chaîne en cours et reprend dans la chaîne appelante ; dans une chaîne
  de base, applique la politique ;
- **`continue`** : passe à la règle suivante ; c'est le verdict implicite d'une règle qui n'en
  porte pas ;
- **`queue`** : confie le paquet à un programme (un système de détection d'intrusion, par
  exemple), qui rendra le verdict.

### @@sec:reject@@ reject : refuser en prévenant

Sans précision, `reject` répond par un message ICMP *port unreachable* ; `nft list ruleset`
affiche alors la règle sous sa forme complète (`reject with icmp port-unreachable`, ou `icmpx`
dans une table `inet` quand la règle ne dit pas la version d'IP). On peut choisir la réponse :

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | ICMP *port unreachable* |
| `reject with tcp reset` | un segment TCP RST : ce que répond une machine sans pare-feu dont le port est fermé (TCP seulement) |
| `reject with icmp host-unreachable` | ICMP *host unreachable* ; autres codes : `net-unreachable`, `prot-unreachable`, `admin-prohibited`… |
| `reject with icmpx admin-prohibited` | dans une table `inet` : l'erreur « interdit par l'administrateur » en ICMP ou en ICMPv6, selon le paquet |

Côté client, l'erreur est **immédiate** au lieu d'un long délai : `Connection refused` avec la
réponse par défaut ou un RST, `No route to host` avec `host-unreachable` ou `admin-prohibited`.

### @@sec:statements@@ Les actions sans verdict

Ces actions font leur travail puis laissent le paquet continuer, dans la même règle puis vers la
règle suivante :

| action | effet |
|--------|-------|
| `counter` | compte les paquets et les octets qui atteignent cet endroit de la règle (section @@ref:logging@@) |
| `log` | journalise le paquet (section @@ref:logging@@) |
| `limit rate 5/minute` | ne laisse la règle se poursuivre qu'à ce rythme ; au-delà, le paquet passe à la règle suivante (section @@ref:limits@@) |
| `meta mark set 1` | pose une marque sur le paquet, qu'une autre règle ou le routage (`ip rule`) retrouvera |
| `notrack` | soustrait le paquet au suivi de connexion (dans une chaîne de priorité `raw`) |
| `meta nftrace set 1` | trace le paquet à travers le jeu de règles (section @@ref:testing@@) |

Elles se combinent, dans l'ordre où elles sont écrites : `limit rate 5/minute log prefix "x: "`
journalise au plus cinq paquets par minute ; `counter drop` compte puis détruit.

### @@sec:drop-or-reject@@ Détruire ou refuser ?

`drop` ne révèle rien à un attaquant, pas même l'existence de la machine, et ne coûte rien ;
`reject` est plus agréable pour les utilisateurs légitimes et pour le diagnostic, puisque
l'erreur est immédiate. L'usage : on détruit ce qui vient de l'extérieur, on refuse souvent ce
qui vient de l'intérieur.
""")
            + info_subtitle(tr("Le suivi de connexion : filtrage à états"), tag="conntrack")
            + tr("""

Netfilter mémorise les **connexions** en cours (*connection tracking*, ou *conntrack*) : une
connexion TCP, mais aussi un « échange » UDP (des datagrammes entre les mêmes adresses et les
mêmes ports) ou ICMP (une requête `echo-request` et sa réponse). Le suivi ne filtre rien : il
**étiquette** chaque paquet d'un **état**, que les règles testent avec `ct state`.

### @@sec:ct-states@@ Les états

- **`new`** : le paquet ouvre une connexion, ou appartient à une connexion dont on n'a encore vu
  qu'**un seul sens** (le SYN en TCP, la première requête UDP et ses répétitions) ;
- **`established`** : le paquet appartient à une connexion dont on a vu des paquets **dans les
  deux sens**. La toute première réponse (le SYN-ACK, la réponse d'un serveur UDP,
  l'`echo-reply`) est déjà dans cet état, comme tout ce qui suit, dans un sens et dans l'autre ;
- **`related`** : le paquet n'appartient pas à une connexion connue, mais il est **lié** à l'une
  d'elles : une erreur ICMP qui la concerne (*port unreachable*, *fragmentation needed*, *time
  exceeded*), ou la connexion de données d'un protocole comme FTP (avec un module d'assistance) ;
- **`invalid`** : le paquet ne correspond à rien de connu et ne peut pas ouvrir de connexion
  (segment TCP incohérent ou hors séquence, erreur ICMP sans connexion…) ;
- **`untracked`** : le paquet a été soustrait au suivi par une règle `notrack`.

Une connexion est enregistrée par son premier paquet, à condition que le pare-feu l'accepte : un
paquet `new` détruit ne laisse aucune trace. Elle est oubliée après un temps d'inactivité : 30
secondes pour un échange UDP ou ICMP resté sans suite (120 secondes pour un flux UDP établi), 5
jours pour une connexion TCP établie, bien moins pendant son ouverture et après sa fermeture.

### @@sec:stateful-rule@@ La règle à états

```
nft insert rule inet filter input ct state established,related accept
```

Placée en **première position**, cette règle accepte d'un coup tout le trafic retour des
communications que la machine a elle-même initiées, et la suite des connexions entrantes déjà
acceptées : il ne reste à autoriser explicitement que les **nouvelles** connexions que l'on veut
servir. Comme presque tous les paquets que reçoit une machine appartiennent à une connexion
établie, la plupart ne consultent que cette règle.

Sans elle, il faut ouvrir à l'aveugle tout ce qui ressemble à une réponse (« tout l'UDP venant du
serveur », par exemple), ce qui laisse aussi passer les requêtes de ce serveur vers la machine :
un filtre **sans état** (*stateless*) ne distingue pas le sens d'un échange.

`ct state invalid drop` complète souvent la règle à états ; les deux s'écrivent aussi en une
seule règle, avec un dictionnaire de verdicts (section @@ref:maps@@) :
`ct state vmap { established : accept, related : accept, invalid : drop }`.

### @@sec:ct-table@@ Observer et régler le suivi

`conntrack -L` (paquet `conntrack`, s'il est installé) affiche la table des connexions suivies,
`conntrack -E` les créations et les suppressions en direct. La taille de la table est bornée
(`sysctl net.netfilter.nf_conntrack_max`) : quand elle est pleine, les nouvelles connexions sont
détruites. On soustrait au suivi un trafic très abondant qui n'en a pas besoin avec `notrack`,
dans une chaîne de priorité `raw` aux hooks `prerouting` et `output` ; ses paquets sont alors
`untracked`, et la règle à états ne les accepte pas.
""")
            + info_subtitle(tr("Filtrer ce qui sort : la chaîne output"), tag="output")
            + tr("""

Une chaîne de base accrochée au hook **`output`** voit tous les paquets que **la machine
elle-même** émet : ceux des connexions que ses programmes ouvrent, mais aussi ses **réponses** aux
connexions qu'elle sert et les messages d'erreur que son noyau fabrique. Elle ne voit pas les
paquets qui traversent un routeur (hook `forward`).

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
```

### @@sec:why-output@@ Pourquoi filtrer la sortie

Filtrer `input` protège la machine des autres ; filtrer `output` protège les autres de la
machine, et limite les dégâts si elle est compromise : un programme malveillant qui ne peut ni
appeler son serveur de commande, ni envoyer de courrier, ni explorer le réseau est bien moins
dangereux. C'est aussi le moyen d'imposer une règle d'usage (« ce serveur ne parle qu'à sa base de
données et aux dépôts de mise à jour »). Les critères utiles sont l'adresse et le port de
**destination** (`ip daddr`, `tcp dport`), l'interface de **sortie** (`oif`, `oifname`) et, propre
à ce hook, l'utilisateur du programme qui émet (section @@ref:skuid@@).

### @@sec:output-view@@ Ce que voit le programme

Dans la chaîne `output`, le paquet est arrêté sur la machine même qui l'émet, et la différence
entre `drop` et `reject` se voit dans le programme :

| programme | avec `drop` | avec `reject` |
|-----------|-------------|---------------|
| `curl` | attend son délai : `curl: (28) Connection timed out` | échec immédiat : `curl: (7) Failed to connect … Couldn't connect to server` |
| `nc -v` | attend son délai : `timed out: Operation now in progress` | échec immédiat : `Connection refused` |
| `ping` | `100% packet loss`, sans autre message | `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` |

Avec `drop`, rien ne signale le blocage : vu du programme, il ressemble à une panne du réseau ou
du serveur distant. En `output`, on préfère donc **`reject`** : celui qui est bloqué est un
utilisateur de la machine, autant qu'il le sache aussitôt. Dans les deux cas `tcpdump` ne montre
aucun paquet : il capture après le hook `output` (section @@ref:capture@@).

Le message d'erreur d'un `reject` est fabriqué par le noyau et **revient au programme par
l'interface `lo`** : la chaîne `input` de la machine doit le laisser entrer, par `iif lo accept`
ou par la règle à états (ce message est `related`). Sinon le programme attend, comme avec `drop`.

### @@sec:output-state@@ Les réponses : la règle à états en sortie

Une règle de `output` ne distingue pas, à elle seule, ce que la machine **initie** de ce qu'elle
**répond**. `ip daddr 192.0.2.7 reject` interdit d'ouvrir une connexion vers `192.0.2.7`, mais
rejette aussi les réponses de la machine aux connexions que `192.0.2.7` ouvre vers elle : ses SYN
entrent, les SYN-ACK ne sortent pas, et le service paraît en panne. Comme en `input`, la règle à
états placée **en tête** règle la question :

```
nft insert rule inet filter output ct state established,related accept
```

- `established` : les paquets des connexions déjà acceptées, dans un sens ou dans l'autre, donc
  toutes les réponses de la machine à ce que sa chaîne `input` a laissé entrer ;
- `related` : les messages d'erreur ICMP que la machine émet elle-même à propos d'une connexion,
  par exemple le *port unreachable* d'une règle `reject` de sa chaîne `input`. Sans `related`,
  ces messages ne sortent plus : l'émetteur n'est plus prévenu et attend, comme avec `drop`.

Les règles suivantes ne voient alors que des paquets `new` : ce que la machine initie.

### @@sec:output-policies@@ Interdire quelques destinations, ou tout interdire sauf…

Deux façons d'écrire la chaîne `output` :

- **tout autoriser, sauf…** : politique `accept` et une règle `reject` par destination ou par
  service interdit. C'est la forme d'un poste de travail ;
- **tout interdire, sauf…** : une règle par flux sortant autorisé, et tout le reste est refusé.
  C'est la forme d'un serveur que l'on veut cloisonner. Il faut alors penser à tout ce que la
  machine émet sans qu'on le voie : ses réponses et ses messages d'erreur (la règle à états), ses
  échanges avec elle-même (`oif lo accept` : beaucoup de programmes se parlent par `127.0.0.1`),
  ses requêtes DNS, ses mises à jour.

```
table inet filter {
        chain output {
                type filter hook output priority filter; policy drop;
                ct state established,related accept
                oif "lo" accept
                icmp type echo-request accept
                udp dport 53 accept
                tcp dport { 80, 443 } accept
                reject
        }
}
```

La règle **`reject` finale**, sans critère, prévient les programmes de la machine ; la politique
`drop` n'est plus qu'un filet de sécurité. Pour passer une chaîne existante de `accept` à `drop`
sans rien couper, on ajoute **d'abord** les règles qui autorisent et l'on change la politique
**en dernier** (section @@ref:nft-edit@@).

### @@sec:skuid@@ Filtrer par utilisateur

Au hook `output`, le noyau connaît le programme qui émet le paquet : `meta skuid` compare
l'utilisateur propriétaire de sa prise réseau (*socket*), `meta skgid` son groupe.

```
nft add rule inet filter output meta skuid "www-data" tcp dport 5432 accept
nft add rule inet filter output tcp dport 5432 reject
```

Seul le serveur web (l'utilisateur `www-data`) joint ici la base de données ; les autres
utilisateurs de la machine sont refusés. Ce critère ne concerne que les paquets émis par la
machine elle-même.
""")
            + info_subtitle(tr("La commande nft"), tag="nft-cli")
            + tr("""

### @@sec:nft-list@@ Consulter

```
nft list ruleset                       # tout le jeu de règles (vide au départ)
nft -a list ruleset                    # avec le handle de chaque table, chaîne et règle
nft list tables                        # les tables
nft list table inet filter             # une table
nft list chain inet filter input       # une chaîne
nft -s list ruleset                    # sans les valeurs des compteurs
nft -j list ruleset                    # en JSON
nft describe icmp type                 # le type d'un champ et ses valeurs possibles
nft monitor                            # les modifications du jeu de règles, en direct
```

### @@sec:nft-build@@ Construire

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add chain inet filter logdrop                    # une chaîne régulière (sans hook)
nft add rule inet filter input iif lo accept         # ajoute la règle à la FIN de la chaîne
nft 'add rule inet filter input tcp dport { 80, 8080 } accept'
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'
```

**Le shell passe avant `nft`.** Le point-virgule, les guillemets, les parenthèses, `*`, `|`, `&`,
`<` et `>` ont un sens pour le shell, qui les interprète ou les retire avant que `nft` ne voie la
commande. La règle simple : dès qu'une commande contient autre chose que des mots, des nombres et
des adresses, **entourez d'apostrophes tout ce qui suit `nft`**. Deux autres façons d'échapper
au shell : le mode interactif `nft -i` (on y tape `add rule …` directement, `quit` pour en
sortir) et les fichiers de règles (section @@ref:nft-files@@).

### @@sec:nft-edit@@ Placer, remplacer, supprimer

L'ordre des règles compte (section @@ref:rules@@) : `add rule` ajoute en **fin** de chaîne,
`insert rule` en **tête**. Pour viser un autre endroit, on désigne une règle existante par son
**handle**, que `nft -a list ruleset` affiche en fin de ligne (`# handle 7`) :

```
nft insert rule inet filter input ct state established,related accept   # au DÉBUT de la chaîne
nft insert rule inet filter input handle 7 tcp dport 8080 accept        # AVANT la règle 7
nft add rule inet filter input handle 7 tcp dport 8080 accept           # APRÈS la règle 7
nft replace rule inet filter input handle 7 tcp dport 8443 accept       # À LA PLACE de la règle 7
nft delete rule inet filter input handle 7                              # supprime la règle 7
nft flush chain inet filter input        # vide une chaîne de ses règles ; la chaîne et sa politique restent
nft delete chain inet filter logdrop     # supprime une chaîne vide, vers laquelle plus aucune règle ne saute
nft delete table inet filter             # supprime la table et tout son contenu
nft flush ruleset                        # efface TOUT : toutes les tables de toutes les familles
```

Un handle n'est pas un numéro de ligne : il ne change pas quand on ajoute ou supprime d'autres
règles. Pour changer la **politique** d'une chaîne de base, on la déclare de nouveau, à
l'identique, avec la nouvelle politique (ses règles restent) :
`nft 'add chain inet filter input { type filter hook input priority 0; policy accept; }'`.

Attention : `nft flush chain` laisse la politique en place (une chaîne `policy drop` vidée
détruit tout), et `nft flush ruleset` efface **toutes** les tables, pas seulement les vôtres.

### @@sec:nft-files@@ Les fichiers de règles

Un vrai pare-feu ne se tape pas commande par commande : il s'écrit dans un **fichier**, dans la
syntaxe qu'affiche `nft list ruleset`, et se charge d'un bloc.

```
#!/usr/sbin/nft -f
flush ruleset

define ADMIN = 192.0.2.0/24
define WEB = { 80, 443 }

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                # un commentaire : SSH pour les administrateurs seulement
                ip saddr $ADMIN tcp dport 22 accept
                tcp dport $WEB accept
        }
}
```

```
nft -c -f /etc/nftables.conf      # vérifie le fichier sans rien changer
nft -f /etc/nftables.conf         # le charge
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; à aucun moment la machine ne se retrouve sans règles, ou avec la moitié des
  règles ;
- le fichier commence par **`flush ruleset`** : sans cela, le recharger ajouterait ses règles
  une seconde fois, à la suite des premières ;
- `define` nomme une valeur, reprise par `$NOM` ; `include "/etc/nftables.d/*.nft"` insère
  d'autres fichiers ;
- `nft -s list ruleset > regles.nft` sauvegarde le jeu de règles en place dans un fichier
  rechargeable (ajoutez-lui `flush ruleset` en tête) ;
- sous Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage (`systemctl enable
  nftables`). Les règles tapées avec `nft` sont **volatiles** : elles disparaissent au
  redémarrage.
""")
            + info_subtitle(tr("Journaliser et compter"), tag="logging")
            + tr("""

### @@sec:counters@@ Compter

**`counter`** est le moyen le plus simple de savoir si une règle sert : `nft list ruleset`
affiche sur la règle `counter packets 12 bytes 1008`, le nombre de paquets et d'octets qui l'ont
atteinte.

```
nft add rule inet filter input tcp dport 8080 counter accept
```

Les compteurs des règles se remettent à zéro avec `nft reset rules` (tout le jeu de règles),
`nft reset rules inet filter` (une table) ou `nft reset rules inet filter input` (une chaîne) :
la commande affiche les règles avec leurs compteurs, puis les remet à zéro. On peut aussi
déclarer un **compteur nommé**, que plusieurs règles alimentent et que l'on relit ou remet à
zéro séparément :

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 8080 } counter name "web" accept'
nft list counters                 # les compteurs nommés
nft reset counters                # les affiche, puis les remet à zéro
```

### @@sec:log@@ Journaliser

Pour voir **quels** paquets passent par une règle, **`log`** produit une ligne par paquet
(interface, adresses, protocole, ports). Il existe sous deux formes :

- `log prefix "input drop: "` écrit dans le **journal du noyau**, que l'on lit sur une vraie
  machine avec `dmesg -w`, `journalctl -k -f` ou dans `/var/log/kern.log` ; `level` choisit la
  gravité du message (`log level info prefix "…"`) et `flags all` y ajoute des détails (options
  IP et TCP, numéros de séquence). **Dans un conteneur, cette forme ne donne rien** : par défaut
  le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "input drop: " group 0` remet les paquets à **nflog** (ici au groupe 0), où un
  programme vient les lire : **`tcpdump -n -i nflog:0`**, ou le démon `ulogd`, qui les range dans
  un fichier ou une base de données. C'est la forme à utiliser dans ce TP : elle montre les
  paquets journalisés en direct, sur `m1` elle-même.

**Limiter la journalisation.** Sans limite, une attaque ou une simple boucle de `ping` remplit le
journal. `limit rate 5/minute` placé **devant** `log` borne le nombre de lignes. C'est un seau à
jetons (section @@ref:limits@@) : 5 jetons au départ (la rafale, *burst*, 5 par défaut), puis un
jeton toutes les 12 secondes ; les paquets sans jeton ne sont pas journalisés, mais continuent
vers la règle suivante.

**Les apostrophes.** Le préfixe contient une espace et des guillemets : tapée dans un shell, la
règle entière doit être protégée par des apostrophes (`nft 'add rule inet filter logdrop log
prefix "input drop: " group 0'`), sinon le shell retire les guillemets et `nft` ne comprend plus
la commande.

**Journaliser puis détruire.** `log` n'est pas un verdict : on le fait suivre d'un `drop` (ou
d'un `accept`), dans la même règle ou dans la règle suivante. L'usage est d'écrire une **chaîne
régulière** `logdrop` qui journalise puis détruit, et d'y sauter (`jump logdrop`) en dernière
règle des chaînes concernées, plutôt que de répéter `log` partout.
""")
            + info_subtitle(tr("Ensembles et dictionnaires"), tag="sets")
            + tr("""

Un **ensemble** (*set*) réunit des valeurs d'un même type ; une règle le consulte en une seule
opération, quel que soit le nombre de ses éléments. Une règle qui porte un ensemble de cent
adresses remplace cent règles, et va bien plus vite qu'elles.

### @@sec:anonymous-sets@@ Les ensembles anonymes

Un ensemble **anonyme** s'écrit directement dans la règle, entre accolades ; il ne change plus
ensuite, sauf à remplacer la règle :

```
nft 'add rule inet filter input tcp dport { 22, 80, 443 } accept'
nft 'add rule inet filter input ip saddr { 192.0.2.2, 198.51.100.0/24 } drop'
```

### @@sec:named-sets@@ Les ensembles nommés

Un ensemble **nommé** est un objet de la table : on en modifie le contenu **sans toucher aux
règles** qui le consultent (`@nom`).

```
nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'
nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'
nft insert rule inet filter input ip saddr @blocklist drop
nft list set inet filter blocklist
nft 'delete element inet filter blocklist { 192.0.2.7 }'
nft flush set inet filter blocklist                  # vide l'ensemble
```

La règle d'une liste noire se place **avant** les règles qui acceptent : `nft insert rule` la met
en tête de chaîne. Ajoutée en fin de chaîne, elle ne verrait jamais les paquets qu'une règle
précédente a déjà acceptés.

Le `type` fixe la nature des éléments : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC),
`inet_proto` (protocole), `inet_service` (port), `mark`. Un ensemble de ports s'emploie comme un
ensemble d'adresses : `nft 'add set inet filter web_ports { type inet_service; }'`, puis une règle
`tcp dport @web_ports accept`. Les drapeaux (`flags`) fixent le comportement de l'ensemble :

| déclaration | effet |
|-------------|-------|
| `flags interval;` | les éléments peuvent être des réseaux ou des plages (`192.0.2.0/24`, `8000-8100`) ; sans ce drapeau, des valeurs isolées seulement |
| `flags timeout; timeout 1h;` | les éléments disparaissent d'eux-mêmes après ce délai |
| `flags dynamic;` | les règles peuvent ajouter elles-mêmes des éléments, au passage des paquets |
| `flags constant;` | le contenu ne peut plus changer |

Sans `flags interval`, `nft` refuse d'ajouter un réseau (`Error: You must add 'flags interval' to
your set declaration if you want to add prefix elements`). Les drapeaux d'un ensemble ne se
changent pas après coup : il faut le supprimer et le recréer (`nft delete set inet filter
blocklist`, après avoir supprimé les règles qui le consultent, sinon `Device or resource busy`).

Un élément peut réunir plusieurs champs, séparés par un point (une **concaténation**) :

```
nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'
nft 'add element inet filter allowed { 192.0.2.2 . 22, 192.0.2.3 . 443 }'
nft insert rule inet filter input ip saddr . tcp dport @allowed accept
```

La règle vaut pour un paquet dont **le couple entier** est dans l'ensemble : ici `192.0.2.2` vers
le port 22 et `192.0.2.3` vers le port 443, mais pas `192.0.2.2` vers le port 443. Une seule
règle et un seul ensemble décrivent ainsi « qui a droit à quoi ».

### @@sec:dynamic-sets@@ Les ensembles alimentés par les règles

Avec `flags dynamic`, une règle range dans un ensemble une valeur tirée du paquet qu'elle
examine : `add @nom { … }` ajoute l'élément s'il n'y est pas, `update @nom { … }` fait de même
et remet son délai à zéro. Exemple : quiconque tente une connexion telnet est banni dix
minutes.

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft add rule inet filter input ip saddr @banned drop
nft 'add rule inet filter input tcp dport 23 add @banned { ip saddr } drop'
```

Dans une chaîne qui accepte déjà des services, ces deux règles se placent **en tête** (`nft insert
rule`), sinon une adresse bannie atteint encore les services acceptés avant elles. `nft list set
inet filter banned` montre chaque élément avec le délai qui lui reste (`expires 9m42s`).

### @@sec:maps@@ Les dictionnaires

Un **dictionnaire** (*map*) associe une valeur à chaque clé. Le plus utile dans un filtre est
le **dictionnaire de verdicts** (*verdict map*, `vmap`), qui choisit le verdict d'après un champ
du paquet, en une seule consultation :

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 8080 : accept, 23 : drop }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
nft 'add rule inet filter input iifname vmap { "eth0" : jump from_lan, "eth1" : jump from_wan }'
```

Un paquet dont le champ n'est pas une clé du dictionnaire passe à la règle suivante. Comme un
ensemble, un dictionnaire peut être nommé, et son contenu modifié sans toucher aux règles :

```
nft 'add map inet filter services { type inet_service : verdict; }'
nft 'add element inet filter services { 22 : accept, 8080 : accept }'
nft add rule inet filter input tcp dport vmap @services
```

Les autres dictionnaires fournissent une valeur à une action ; on les rencontre surtout dans la
traduction d'adresses : `dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }` choisit
le serveur d'après le port demandé.
""")
            + info_subtitle(tr("Limiter le trafic"), tag="limits")
            + tr("""

### @@sec:limit-rate@@ limit rate : le seau à jetons

`limit rate` laisse une règle se poursuivre à un rythme donné. C'est un **seau à jetons** :
chaque paquet qui passe consomme un jeton, le seau se remplit au rythme indiqué et contient au
plus la **rafale** (*burst*, 5 paquets par défaut). Un paquet qui ne trouve pas de jeton ne
satisfait pas la règle : il passe à la règle suivante.

| règle | effet |
|-------|-------|
| `icmp type echo-request limit rate 5/second accept` | accepte au plus 5 `ping` par seconde ; le surplus continue dans la chaîne, jusqu'à la politique |
| `limit rate 10/minute burst 20 packets log` | 20 paquets d'un coup au plus, puis un toutes les 6 secondes |
| `limit rate over 100/second drop` | `over` inverse le test : la règle vaut pour ce qui **dépasse** le rythme |
| `limit rate 1 mbytes/second accept` | un débit en octets (`bytes`, `kbytes`, `mbytes`) |

Les unités de temps sont `second`, `minute`, `hour` et `day`.

**Attention à la place de la règle.** Après la règle à états, une règle `limit` ne voit plus que
les paquets qui ouvrent une connexion : elle limite alors le rythme des **nouvelles connexions**,
pas le débit. Pour limiter tous les paquets d'un trafic, on la place avant la règle à états
(`limit rate over … drop`).

### @@sec:limit-per-source@@ Une limite par adresse

Une limite écrite dans une règle est **globale** : un seul client bruyant épuise les jetons de
tous. Pour compter **par adresse source**, on associe la limite aux éléments d'un ensemble
alimenté par la règle (section @@ref:dynamic-sets@@) : chaque adresse y reçoit son propre seau.

```
nft 'add set inet filter clients { type ipv4_addr; flags dynamic,timeout; timeout 1m; }'
nft 'add rule inet filter input tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop'
```

De la même façon, `ct count over 2` vaut quand le nombre de connexions **simultanées** dépasse
2 : avec un autre ensemble déclaré `flags dynamic`, `add @sessions { ip saddr ct count over 2 }
reject` refuse la troisième connexion ouverte en même temps par une même adresse.

### @@sec:quotas@@ Les quotas

Un **quota** compte un volume, et non un rythme. C'est un objet nommé de la table, comme un
compteur ; avec `over`, la règle vaut une fois le volume dépassé :

```
nft 'add quota inet filter guest { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "guest" drop'
```
""")
            + info_subtitle(tr("La traduction d'adresses en bref"), tag="nat")
            + tr("""

La traduction d'adresses (NAT) réécrit l'adresse, et au besoin le port, source ou destination
des paquets qui traversent un routeur. Elle fera l'objet d'un autre TP ; en voici l'essentiel.
Elle se fait dans des chaînes de type **`nat`** :

```
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'
nft add rule ip nat postrouting oif eth0 masquerade                            # ou bien :
nft add rule ip nat postrouting oif eth0 snat to 203.0.113.1
nft add rule ip nat prerouting iif eth0 tcp dport 80 dnat to 192.0.2.10:8080   # ou bien :
nft add rule ip nat prerouting tcp dport 80 redirect to :8080
```

| action | hook | effet |
|--------|------|-------|
| `masquerade` | `postrouting` | remplace l'adresse source par celle de l'interface de sortie (partage d'une adresse publique) |
| `snat to A` | `postrouting` | remplace l'adresse source par l'adresse A |
| `dnat to A:P` | `prerouting` | remplace l'adresse et le port de destination (redirection de port vers un serveur interne) |
| `redirect to :P` | `prerouting` | envoie le paquet vers le port P de la machine elle-même (mandataire transparent) |

- une chaîne `nat` ne voit que le **premier paquet** de chaque connexion : le suivi de connexion
  applique la même traduction aux suivants, et la traduction inverse aux réponses ;
- le filtrage se fait toujours dans les chaînes `filter`. La chaîne `forward` voit un paquet
  **après** le DNAT (fait en `prerouting`) et **avant** le SNAT (fait en `postrouting`) : ses
  règles nomment donc l'adresse réelle du serveur interne et l'adresse d'origine du client ;
- dans une table `inet`, on précise la version d'IP : `dnat ip to 192.0.2.10`.
""")
            + info_subtitle(tr("Observer et tester un pare-feu"), tag="testing")
            + tr("""

Un pare-feu se vérifie des deux côtés : ce qu'il **laisse passer** (ce qui doit marcher marche
encore) et ce qu'il **arrête** (ce qui doit être bloqué l'est vraiment).

### @@sec:test-servers@@ Les serveurs de test du TP

Les machines du TP servent toutes un petit **serveur de test**, en HTTP sur les ports TCP **80,
8080 et 8888** et en UDP sur les ports **530 et 630** (`ss -tulnp` les liste). Il répond par son
nom et par les adresses et ports des deux bouts de l'échange, tels qu'il
les voit, et par le TTL du paquet reçu (64 depuis le même réseau, un de moins par routeur
traversé) :

```
m1:~# curl http://m2/                   # ou curl http://m2:8080/ ; -m 3 pour ne pas attendre plus de 3 s
SERVER=m2
SERVER_IP=192.0.2.2
SERVER_PORT=80
CLIENT_IP=192.0.2.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # un datagramme UDP vers le port 530 (ou 630) : même réponse
```

### @@sec:client-view@@ Ce que voit le client

Le message d'erreur du client dit ce que le pare-feu a fait du paquet :

| ce que le client observe | ce qui s'est passé |
|--------------------------|--------------------|
| `curl: (7) Failed to connect …`, **immédiat** (connexion refusée ; `nc -vz` affiche `Connection refused`) | un `reject` (ou un port fermé, sans pare-feu) |
| `curl: (28) Connection timed out`, **après le délai** (`-m 3`) | un `drop` (ou une machine éteinte) |
| `nc -u -w 1` se termine sans rien afficher | le datagramme, ou sa réponse, a été détruit |
| `ping -c 2 -W 1 m1` : `100% packet loss` | les requêtes, ou les réponses, sont détruites |
| `ping` : `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` | un `reject` dans sa propre chaîne `output` (section @@ref:output-view@@) |

### @@sec:capture@@ Capturer : où se place tcpdump

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu :

- en réception, il voit les paquets **avant** tous les hooks : un paquet que le pare-feu détruit
  en `input` apparaît quand même dans la capture. Voir arriver un paquet ne prouve donc pas
  qu'il a été accepté ;
- en émission, il voit les paquets **après** tous les hooks : un paquet détruit en `output`
  n'apparaît pas.

`tcpdump -n -i eth0 icmp or tcp port 80` sur le client montre ce qu'il reçoit (le message ICMP
*port unreachable* d'un `reject`, ou rien) ; `tcpdump -n -i eth0 'port 80 or port 530'` sur le
serveur montre ce qui lui arrive, que le pare-feu l'accepte ou non.

### @@sec:which-rule@@ Savoir quelle règle a tranché

Les **compteurs** d'abord : ajoutez `counter` aux règles (`… counter accept`, `… counter drop`)
et relisez `nft list ruleset` après un essai : la règle dont le compteur a bougé est celle qui a
vu le paquet. C'est la méthode de diagnostic de base d'un pare-feu.

Pour suivre un paquet règle par règle, on le **trace** : une règle `meta nftrace set 1`, placée
en tête de chaîne, marque les paquets à suivre, et `nft monitor trace` affiche leur parcours.

```
nft insert rule inet filter input ip saddr 192.0.2.3 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.3 ip daddr 192.0.2.1 … tcp dport 8080 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.3 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 8080 accept (verdict accept)
```

Chaque ligne commence par l'identifiant du paquet, la table et la chaîne ; les lignes `rule`
donnent les règles satisfaites et leur verdict, et un paquet qu'aucune règle n'arrête se termine
par la politique de la chaîne (`policy drop`). Supprimez la règle de trace quand vous avez fini.

### @@sec:method@@ Une démarche de diagnostic

1. `nft list ruleset` : est-ce bien le jeu de règles que vous croyez avoir chargé ? Les règles
   sont-elles dans le bon ordre ?
2. le message d'erreur du client : refus immédiat (`reject`) ou délai d'attente (`drop`) ?
3. les compteurs : quelle règle a vu le paquet ? Aucune : il n'arrive pas jusqu'à la chaîne, ou
   la politique l'a détruit ;
4. `tcpdump` des deux côtés : la requête arrive-t-elle ? La réponse repart-elle ? Souvent c'est
   la **réponse** qui est bloquée, pas la requête ;
5. la trace, quand le reste ne suffit pas.
""")
            + info_subtitle(tr("Bonnes pratiques"), tag="practices")
            + tr("""

### @@sec:host-firewall@@ Le pare-feu type d'une machine

Un serveur qui offre SSH à son réseau d'administration et le web à tout le monde :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;

                ct state established,related accept
                ct state invalid drop
                iif "lo" accept

                icmp type echo-request limit rate 5/second accept
                icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
                icmpv6 type echo-request limit rate 5/second accept

                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept

                limit rate 5/minute log prefix "input drop: "
        }
        chain forward {
                type filter hook forward priority filter; policy drop;
        }
        chain output {
                type filter hook output priority filter; policy accept;
        }
}
```

### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input` (et en `forward`), et une
  règle par service réellement offert, restreinte à ceux qui en ont besoin (`ip saddr`). Le hook
  `output` reste souvent ouvert (on fait confiance à la machine elle-même) ; on le filtre sur les
  machines que l'on veut cloisonner (section @@ref:output@@) ;
- **la règle à états en premier** : elle traite presque tous les paquets et dispense d'ouvrir
  quoi que ce soit pour les réponses ;
- **ne jamais oublier `lo`** : beaucoup de services locaux se parlent par `127.0.0.1` ;
- **ne pas bloquer tout ICMP** : les erreurs ICMP (*fragmentation needed*, *port unreachable*,
  *time exceeded*) sont nécessaires au bon fonctionnement d'IP ; la règle à états les accepte,
  puisqu'elles sont `related`. Répondre au `ping`, à un rythme limité, facilite le diagnostic ;
- **en IPv6, autoriser la découverte des voisins** : elle remplace ARP et utilise ICMPv6
  (`nd-neighbor-solicit`, `nd-neighbor-advert`, `nd-router-advert`). Ces messages ne sont pas
  suivis par le suivi de connexion : sans règle explicite, une politique `drop` coupe IPv6 ;
- **journaliser ce qui est détruit**, avec une limite, pour voir les attaques comme ses propres
  erreurs ;
- **un fichier, chargé d'un bloc** (section @@ref:nft-files@@), vérifié d'abord avec `nft -c -f`,
  plutôt que des commandes tapées une à une.

### @@sec:pitfalls@@ Les pièges

- **se couper l'accès** : sur une machine administrée à distance, une chaîne `input` en
  `policy drop` sans règle pour SSH (ni règle à états) coupe la session en cours. Chargez un
  fichier complet, d'un bloc, et gardez un accès de secours ;
- **l'ordre des règles** : une règle placée après un `drop` ou un `reject` qui couvre les mêmes
  paquets n'est jamais consultée (`nft insert rule`, ou `handle`) ;
- **le sens** : filtrer `input` ne limite pas ce que la machine émet, mais détruit les réponses à
  ce qu'elle émet tant qu'il n'y a pas de règle à états ; filtrer `output` arrête aussi les
  réponses de la machine à ce qu'elle sert, tant que sa chaîne `output` n'a pas la sienne ;
- **oublier `lo` en sortie** : avec une politique `drop` en `output`, sans `oif lo accept` les
  programmes de la machine ne se joignent plus par `127.0.0.1` ;
- **le shell** : guillemets, accolades et points-virgules se protègent par des apostrophes
  (section @@ref:nft-build@@) ;
- **`flush ruleset`** efface aussi les tables des autres logiciels (Docker, par exemple). Sur une
  telle machine, on ne remplace que sa propre table : le fichier commence alors par les deux
  lignes `table inet filter` et `delete table inet filter`, au lieu de `flush ruleset` ;
- **les règles volatiles** : ce qui n'est pas dans `/etc/nftables.conf` disparaît au
  redémarrage.
""")
            + info_subtitle(tr("Passer d'iptables à nftables"), tag="from-iptables")
            + tr("""

Beaucoup de documentations, de scripts et de réponses trouvées en ligne sont encore écrits pour
`iptables`, et beaucoup d'administrateurs ont appris avec lui. Cette section aide à passer de
l'un à l'autre : ce qui change dans le modèle, un même pare-feu écrit dans les deux langages, la
correspondance des commandes et des options, la traduction automatique, et la cohabitation des
deux sur une même machine.

### @@sec:ipt-model@@ Ce qui change dans le modèle

| iptables | nftables |
|----------|----------|
| des tables fixes (`filter`, `nat`, `mangle`, `raw`) et des chaînes prédéfinies (`INPUT`, `FORWARD`, `OUTPUT`, `PREROUTING`, `POSTROUTING`), présentes même vides | rien de prédéfini : on crée ses tables et ses chaînes de base, du nom de son choix ; c'est le `hook` qui accroche une chaîne, pas son nom (section @@ref:base-chains@@) |
| l'ordre des tables sur un hook est figé (`raw`, `mangle`, `nat`, `filter`) | les chaînes de base d'un même hook passent par priorité croissante ; les priorités nommées `raw`, `mangle`, `dstnat`, `filter`, `srcnat` reprennent l'ordre d'iptables (section @@ref:priorities@@) |
| une commande par famille : `iptables`, `ip6tables`, `arptables`, `ebtables` | une seule commande ; une table `inet` filtre IPv4 et IPv6 à la fois |
| chaque règle compte ses paquets | une règle ne compte que si on lui ajoute `counter` |
| une règle n'a qu'une cible (`-j`) : journaliser puis détruire demande deux règles | une règle enchaîne plusieurs actions : `counter log prefix "…" drop` |
| des modules d'extension (`-m multiport`, `-m iprange`, `-m recent`) et l'outil séparé `ipset` | les ensembles, les intervalles et les dictionnaires font partie du langage (section @@ref:sets@@) |
| une règle se désigne par son numéro, qui change quand on en ajoute ou en retire d'autres | une règle se désigne par son `handle`, qui ne change pas (section @@ref:nft-edit@@) |
| `iptables-save` et `iptables-restore` emploient un format à part | `nft list ruleset` affiche le format même des fichiers que charge `nft -f` |

Une différence se voit dès le départ : sans aucune règle, iptables a quand même ses chaînes, en
politique `ACCEPT`, que chaque paquet traverse ; un nftables vide n'a aucune chaîne et laisse tout
passer sans rien examiner. Le reste du fonctionnement est le même : le suivi de connexion,
les hooks, et le fait qu'un `accept` ne termine que la chaîne en cours (un paquet accepté dans
la table `mangle` d'iptables peut encore être détruit dans sa table `filter`, comme dans deux
chaînes de base nftables du même hook).

### @@sec:ipt-example@@ Un même pare-feu dans les deux langages

En iptables, une suite de commandes, où chaque option `-m` charge un module :

```
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT
iptables -A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -N logdrop
iptables -A logdrop -m limit --limit 5/minute -j LOG --log-prefix "input drop: "
iptables -A logdrop -j DROP
iptables -A INPUT -j logdrop
```

En nftables, un fichier chargé d'un bloc (section @@ref:nft-files@@) :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                icmp type echo-request limit rate 5/second accept
                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept
                jump logdrop
        }
        chain logdrop {
                limit rate 5/minute log prefix "input drop: "
                drop
        }
}
```

La correspondance est presque mot à mot ; seul `-m multiport` devient un ensemble anonyme. Une
différence de taille, pourtant : faute de règles `ip6tables`, le script iptables laisse **IPv6
entièrement ouvert**, alors que la table `inet` filtre IPv6 aussi. Ses règles qui ne nomment ni
adresse ni type ICMP (`ct state`, `iif "lo"`, `tcp dport`, `jump`) valent pour les deux versions
d'IP ; sur une machine qui a IPv6, il faut y ajouter la découverte des voisins (section
@@ref:principles@@).

### @@sec:ipt-commands@@ Les commandes

| iptables | nftables |
|----------|----------|
| `iptables -L -n -v --line-numbers`, `iptables -S` | `nft -a list ruleset` |
| `iptables -P INPUT DROP` | `policy drop;` dans la déclaration de la chaîne de base (section @@ref:nft-edit@@) |
| `iptables -A INPUT …` | `nft add rule inet filter input …` |
| `iptables -I INPUT …` | `nft insert rule inet filter input …` |
| `iptables -I INPUT 3 …` | `nft insert rule inet filter input handle N …` (N : le handle de la règle qui doit suivre) |
| `iptables -R INPUT 3 …` | `nft replace rule inet filter input handle N …` |
| `iptables -D INPUT 3`, ou `iptables -D INPUT` suivi de la règle | `nft delete rule inet filter input handle N` (par handle seulement) |
| `iptables -N logdrop`, `-j logdrop`, `-g logdrop`, `-j RETURN` | `nft add chain inet filter logdrop`, `jump logdrop`, `goto logdrop`, `return` |
| `iptables -F INPUT`, `iptables -F` | `nft flush chain inet filter input`, `nft flush table inet filter` |
| `iptables -X logdrop` | `nft delete chain inet filter logdrop` |
| `iptables-save > regles`, `iptables-restore < regles` | `nft -s list ruleset > regles`, `nft -f regles` |
| `iptables -t nat …` | une table et des chaînes de type `nat` (section @@ref:nat@@) |

### @@sec:ipt-options@@ Les critères et les cibles

| iptables | nftables |
|----------|----------|
| `-i eth0`, `-o eth0`, `-i eth+` | `iifname "eth0"`, `oifname "eth0"`, `iifname "eth*"` (ou `iif eth0`, voir plus bas) |
| `-s 192.0.2.0/24`, `-d 192.0.2.1` | `ip saddr 192.0.2.0/24`, `ip daddr 192.0.2.1` |
| `! -s 192.0.2.0/24` | `ip saddr != 192.0.2.0/24` |
| `-p udp` | `meta l4proto udp` |
| `-p tcp --dport 22`, `-p tcp --sport 1024:65535` | `tcp dport 22`, `tcp sport 1024-65535` |
| `-p tcp -m multiport --dports 80,443` | `tcp dport { 80, 443 }` |
| `-m iprange --src-range 192.0.2.10-192.0.2.20` | `ip saddr 192.0.2.10-192.0.2.20` |
| `-p icmp --icmp-type echo-request` | `icmp type echo-request` |
| `-m state --state ESTABLISHED,RELATED`, `-m conntrack --ctstate NEW` | `ct state established,related`, `ct state new` |
| `-m mac --mac-source 02:00:00:00:00:01` | `ether saddr 02:00:00:00:00:01` |
| `-m owner --uid-owner www-data` | `meta skuid "www-data"` (section @@ref:skuid@@) |
| `-m comment --comment "SSH"` | `comment "SSH"`, en fin de règle |
| `-m limit --limit 5/minute --limit-burst 10` | `limit rate 5/minute burst 10 packets` |
| `-m hashlimit --hashlimit-name ssh --hashlimit-mode srcip --hashlimit-above 3/minute` | `update @clients { ip saddr limit rate over 3/minute }` (section @@ref:limit-per-source@@) |
| `-m connlimit --connlimit-above 2` | `add @sessions { ip saddr ct count over 2 }` (section @@ref:limit-per-source@@) |
| `-m set --match-set blocklist src`, l'ensemble créé par `ipset create blocklist hash:net` | `ip saddr @blocklist`, l'ensemble déclaré `type ipv4_addr; flags interval;` (section @@ref:named-sets@@) |
| `-m recent --name banned --set`, puis `-m recent --name banned --rcheck --seconds 60 -j DROP` | `add @banned { ip saddr }`, puis `ip saddr @banned drop`, l'ensemble déclaré `flags dynamic,timeout; timeout 60s;` (section @@ref:dynamic-sets@@) |
| `-m mark --mark 1`, `-j MARK --set-mark 1` | `meta mark 1`, `meta mark set 1` |
| `-j ACCEPT`, `-j DROP`, `-j RETURN` | `accept`, `drop`, `return` |
| `-j REJECT`, `-j REJECT --reject-with tcp-reset` | `reject`, `reject with tcp reset` |
| `-j LOG --log-prefix "input drop: "` | `log prefix "input drop: "` (suivi, si besoin, d'un verdict dans la même règle) |
| `-j NFLOG --nflog-group 0` | `log group 0` |
| `-j TRACE`, dans la table `raw` | `meta nftrace set 1` (section @@ref:which-rule@@) |
| `-j MASQUERADE`, `-j SNAT --to-source A`, `-j DNAT --to-destination A:P`, `-j REDIRECT --to-ports P` | `masquerade`, `snat to A`, `dnat to A:P`, `redirect to :P` |

**`iifname` ou `iif` ?** L'option `-i` d'iptables compare le **nom** de l'interface, comme
`iifname`. `iif` compare son **numéro** (son index) : c'est plus rapide, mais l'interface doit
exister quand la règle est chargée, et une interface détruite puis recréée (un tunnel, une
interface `ppp`, celle d'un conteneur) reçoit un autre numéro, que la règle ne suit pas. `iif lo`
convient donc toujours ; pour une interface qui va et vient, on écrit `iifname`.

### @@sec:ipt-translate@@ Traduire automatiquement

Le paquet `iptables` fournit des traducteurs, qui affichent la commande `nft` équivalente sans
rien changer au pare-feu :

```
iptables-translate -A INPUT -i eth0 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
ip6tables-translate …                                    # la même chose pour ip6tables
iptables-restore-translate -f regles.v4 > regles.nft     # tout un fichier écrit par iptables-save
```

La première commande affiche (à la version près) :

```
nft 'add rule ip filter INPUT iifname "eth0" tcp dport 22 ct state new counter accept'
```

La traduction est **littérale** : elle vise la table `ip filter` et la chaîne `INPUT` que crée
`iptables-nft` (voir plus bas), ajoute `counter` à chaque règle, puisque iptables compte tout, et
emploie `iifname`. Certaines extensions n'ont pas de traduction : relisez toujours le résultat.
C'est un point de départ, que l'on réécrit en vrai fichier nftables. Pour convertir un pare-feu :

1. sauvegarder les règles en place : `iptables-save > regles.v4` (et `ip6tables-save >
   regles.v6`) ;
2. les traduire avec `iptables-restore-translate -f regles.v4`, et lire le résultat ;
3. le réécrire en fichier nftables (section @@ref:nft-files@@) : une seule table `inet` pour IPv4
   et IPv6, des noms en minuscules, des ensembles à la place des séries de règles presque
   identiques et des `ipset`, `counter` seulement là où il sert ;
4. vérifier le fichier (`nft -c -f`), le charger, puis retirer les règles d'iptables et le service
   qui les rechargeait au démarrage (`netfilter-persistent` sous Debian), au profit du service
   `nftables`.

### @@sec:ipt-coexist@@ iptables sur une machine nftables

Sur une Debian récente, la commande `iptables` est **`iptables-nft`** : `iptables -V` affiche
`iptables v1.8.11 (nf_tables)`. Elle garde la syntaxe d'iptables, mais écrit des règles nftables,
dans des tables `ip filter`, `ip nat`, `ip6 filter`… aux chaînes `INPUT`, `FORWARD`, `OUTPUT`…,
que `nft list ruleset` affiche à côté des vôtres. C'est ainsi que Docker, par exemple, installe
ses règles. Quelques conséquences :

- ces tables appartiennent à iptables : on les lit avec `nft`, mais on ne les modifie qu'avec
  `iptables`, dont les règles emploient des extensions que seul iptables sait gérer ;
- chaque table est traversée : un paquet que votre table `inet filter` accepte peut encore être
  détruit par la table `ip filter` d'iptables, sur le même hook, et inversement (section
  @@ref:priorities@@) ;
- `nft flush ruleset` efface aussi ces tables (section @@ref:pitfalls@@) ;
- l'ancien moteur, **`iptables-legacy`** (`iptables -V` affiche alors `(legacy)`), n'apparaît
  pas du tout dans `nft list ruleset`, mais ses règles s'appliquent quand même. Ne mélangez pas
  les deux sur une machine : `update-alternatives --config iptables` choisit le moteur que
  désigne la commande `iptables`.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter input` |
| table et chaîne de base | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'` |
| règles | `nft add rule inet filter input …` (fin), `nft insert rule inet filter input …` (début), `nft insert rule inet filter input handle N …` (avant la règle N), `nft add rule inet filter input handle N …` (après), `nft replace rule inet filter input handle N …`, `nft delete rule inet filter input handle N` |
| critères | `iif lo`, `ip saddr A.B.C.D`, `meta l4proto udp`, `tcp dport 8080`, `tcp dport { 80, 8080 }`, `icmp type echo-reply`, `ct state established,related` |
| verdicts et actions | `accept`, `drop`, `reject`, `jump logdrop`, `counter`, `log prefix "…" group 0`, `limit rate 5/minute` |
| chaîne régulière | `nft add chain inet filter logdrop`, `nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'`, `nft add rule inet filter logdrop counter drop`, `nft add rule inet filter input jump logdrop` |
| journal | `tcpdump -n -i nflog:0` (règles `log … group 0`) |
| chaîne output | `nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'`, `nft insert rule inet filter output ct state established,related accept`, `oif lo accept`, `ip daddr A.B.C.D reject`, `tcp dport 80 accept`, une règle `reject` finale, puis la même déclaration de chaîne avec `policy drop` |
| ensemble nommé | `nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'`, `nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'`, `nft insert rule inet filter input ip saddr @blocklist drop`, `nft list set inet filter blocklist`, `nft 'delete element inet filter blocklist { 192.0.2.7 }'` |
| ensemble de ports, de couples | `nft 'add set inet filter web_ports { type inet_service; }'` et `tcp dport @web_ports accept` ; `nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'`, `nft 'add element inet filter allowed { 192.0.2.2 . 22 }'` et `ip saddr . tcp dport @allowed accept` |
| ensemble alimenté par les règles | `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `tcp dport 23 add @banned { ip saddr } drop`, `ip saddr @banned drop` |
| remplacer une règle | `nft -a list chain inet filter output` (son handle), puis `nft replace rule inet filter output handle N …` |
| fichier de règles | `nft -c -f fichier` (vérifier), `nft -f fichier` (charger), `nft -s list ruleset > fichier` (sauvegarder) |
| tout effacer | `nft flush chain inet filter input`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `curl -m 3 http://m2/`, `curl -m 3 http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ping -c 2 -W 1 m2`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or tcp port 80` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""")
        )

    # -- the commands of the reference solution (used by `final` and the instructor texts) ----

    def cmds_policy(self) -> List[str]:
        """Question 2: the table, the input base chain and its drop policy."""
        return [f"nft add table {FAMILY} {TABLE}",
                f"nft 'add chain {FAMILY} {TABLE} {CHAIN} {{ type filter hook input priority 0; policy drop; }}'"]

    def cmds_lo(self) -> List[str]:
        """Question 3: everything coming through the loopback interface."""
        return [f"nft add rule {FAMILY} {TABLE} {CHAIN} iif lo accept"]

    def cmds_icmp(self) -> List[str]:
        """Question 4: the echo replies (m1 pings, nobody pings m1)."""
        return [f"nft add rule {FAMILY} {TABLE} {CHAIN} icmp type echo-reply accept"]

    def cmds_udp_server(self) -> List[str]:
        """Question 5: every UDP datagram coming from the server (stateless: requests too)."""
        return [f"nft add rule {FAMILY} {TABLE} {CHAIN} ip saddr {ip_of(self.data, UDP_SERVER).ip} meta l4proto udp accept"]

    def cmds_reject(self) -> List[str]:
        """Question 6: the packets of m2 are rejected (the others are dropped by the policy)."""
        return [f"nft add rule {FAMILY} {TABLE} {CHAIN} ip saddr {ip_of(self.data, REJECTED).ip} reject"]

    def cmds_established(self) -> List[str]:
        """Question 7: the stateful rule, inserted first."""
        return [f"nft insert rule {FAMILY} {TABLE} {CHAIN} ct state established,related accept"]

    def cmds_open_port(self) -> List[str]:
        """Question 8: the open port, inserted before the reject rule of m2 (here at the top)."""
        return [f"nft insert rule {FAMILY} {TABLE} {CHAIN} tcp dport {OPEN_PORT} accept"]

    def cmds_log(self) -> List[str]:
        """Question 9: the named chain logging (rate-limited, nflog group) then dropping, jumped to last."""
        return [f"nft add chain {FAMILY} {TABLE} {LOG_CHAIN}",
                f"nft 'add rule {FAMILY} {TABLE} {LOG_CHAIN} limit rate {LOG_RATE}/minute log prefix \"{LOG_PREFIX}\" group {NFLOG_GROUP}'",
                f"nft add rule {FAMILY} {TABLE} {LOG_CHAIN} counter drop",
                f"nft add rule {FAMILY} {TABLE} {CHAIN} jump {LOG_CHAIN}"]

    def cmds_output(self) -> List[str]:
        """Question 10: the output chain, in the order of the question: (a) / (b) the chain and the
        destination m1 must not contact, (c) the stateful rule inserted first, (d) what m1 may emit,
        a final reject, and the policy drop last (every intermediate ruleset keeps what questions 1
        to 9 grade)."""
        chain = f"{FAMILY} {TABLE} {OUT_CHAIN}"
        declaration = f"nft 'add chain {chain} {{{{ type filter hook output priority 0; policy {{policy}}; }}}}'"
        return [declaration.format(policy='accept'),
                f"nft add rule {chain} ip daddr {ip_of(self.data, FORBIDDEN).ip} reject",
                f"nft insert rule {chain} ct state established,related accept",
                f"nft add rule {chain} oif lo accept",
                f"nft add rule {chain} icmp type echo-request accept",
                f"nft add rule {chain} tcp dport {CLOSED_PORT} accept",
                f"nft 'add rule {chain} udp dport {{ {UDP_PORTS[0]}, {UDP_PORTS[1]} }} accept'",
                f"nft add rule {chain} reject",
                declaration.format(policy='drop')]

    def cmds_blocklist(self) -> List[str]:
        """Question 11: the named set of the blocklisted addresses (one host, then a whole network)
        and its rule, inserted before the rule opening a port to everybody."""
        d = self.data
        return [f"nft 'add set {FAMILY} {TABLE} {BLOCK_SET} {{ type ipv4_addr; flags interval; }}'",
                f"nft 'add element {FAMILY} {TABLE} {BLOCK_SET} {{ {ip_of(d, BLOCKED_HOST).ip} }}'",
                f"nft insert rule {FAMILY} {TABLE} {CHAIN} ip saddr @{BLOCK_SET} drop",
                f"nft 'add element {FAMILY} {TABLE} {BLOCK_SET} {{ {getattr(d.nets, BLOCKED_NET)} }}'"]

    def cmds_port_set(self) -> List[str]:
        """Question 12: the TCP ports m1 may contact move to a named set (the rule of question 10 is
        replaced: its handle is read from the listing), then one more port is added to the set."""
        chain = f"{FAMILY} {TABLE} {OUT_CHAIN}"
        handle = f"$(nft -a list chain {chain} | awk '/tcp dport {CLOSED_PORT} accept/ {{print $NF}}')"
        return [f"nft 'add set {FAMILY} {TABLE} {PORT_SET} {{ type inet_service; }}'",
                f"nft 'add element {FAMILY} {TABLE} {PORT_SET} {{ {CLOSED_PORT} }}'",
                f"nft replace rule {chain} handle {handle} tcp dport @{PORT_SET} accept",
                f"nft 'add element {FAMILY} {TABLE} {PORT_SET} {{ {SET_PORT} }}'"]

    def cmds_allowed(self) -> List[str]:
        """Question 13: the set of (address . port) pairs and its single rule, inserted (appended, it
        would come after the jump to the logging chain)."""
        pairs = ", ".join(f"{address} . {port}" for address, port in allowed_pairs(self.data))
        return [f"nft 'add set {FAMILY} {TABLE} {ALLOW_SET} {{ type ipv4_addr . inet_service; }}'",
                f"nft 'add element {FAMILY} {TABLE} {ALLOW_SET} {{ {pairs} }}'",
                f"nft insert rule {FAMILY} {TABLE} {CHAIN} ip saddr . tcp dport @{ALLOW_SET} accept"]

    def cmds_ban(self) -> List[str]:
        """Question 14 (bonus): the dynamic set and its two rules, inserted at the head of input (the
        second insert puts the drop rule first)."""
        return [f"nft 'add set {FAMILY} {TABLE} {BAN_SET} {{ type ipv4_addr; flags dynamic,timeout; timeout {BAN_SECONDS}s; }}'",
                f"nft 'insert rule {FAMILY} {TABLE} {CHAIN} tcp dport {TRAP_PORT} add @{BAN_SET} {{ ip saddr }} drop'",
                f"nft insert rule {FAMILY} {TABLE} {CHAIN} ip saddr @{BAN_SET} drop"]

    def cmds_all(self) -> List[str]:
        """The whole reference solution, in question order."""
        return (self.cmds_policy() + self.cmds_lo() + self.cmds_icmp() + self.cmds_udp_server() + self.cmds_reject()
                + self.cmds_established() + self.cmds_open_port() + self.cmds_log()
                + self.cmds_output() + self.cmds_blocklist() + self.cmds_port_set() + self.cmds_allowed()
                + self.cmds_ban())

    # -- states -----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('m1', d.ips.m1), ('m2', d.ips.m2), ('m3', d.ips.m3), ('gw', d.ips.gw_lan), ('gw_ext', d.ips.gw_ext),
                   ('gw_guest', d.ips.gw_guest), ('ext1', d.ips.ext1), ('ext2', d.ips.ext2), ('ext3', d.ips.ext3),
                   ('guest1', d.ips.guest1)]
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{visible(machine)}", ""]
        lines += [f"{ip.ip}\t\t{name}.{DOMAIN}\t{name}" for name, ip in entries]
        return "\n".join(lines) + "\n"

    def _configure_network(self):
        """Addresses and routes of the visible machines and of their clones (same values)."""
        d = self.data
        for suffix in ('', MIRROR):
            for m in ('m1', 'm2', 'm3'):
                self.cmd(m + suffix, f"ip address add {getattr(d.ips, m)} dev eth0")
                self.cmd(m + suffix, f"ip route add default via {d.ips.gw_lan.ip}")
            self.cmd('gw' + suffix, f"ip address add {d.ips.gw_lan} dev eth0")
            self.cmd('gw' + suffix, f"ip link set eth1 up; ip address add {d.ips.gw_ext} dev eth1")
            self.cmd('gw' + suffix, f"ip link set eth2 up; ip address add {d.ips.gw_guest} dev eth2")
            for m in ('ext1', 'ext2', 'ext3'):
                self.cmd(m + suffix, f"ip address add {getattr(d.ips, m)} dev eth0")
                self.cmd(m + suffix, f"ip route add default via {d.ips.gw_ext.ip}")
            self.cmd('guest1' + suffix, f"ip address add {d.ips.guest1} dev eth0")
            self.cmd('guest1' + suffix, f"ip route add default via {d.ips.gw_guest.ip}")
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1; set_ip_forward() also remounts
            # /proc/sys read-write, which the students need for their own `sysctl -w`.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(visible(m) == 'gw'))

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        for m in self.get_machine_names():
            self.file(m, "/etc/hosts", self.hosts_content(m))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
            # the students start from an empty ruleset (Docker's embedded DNS leaves a nat table
            # in every container otherwise); the clone of the firewall is loaded at each evaluation
            firewall.flush_ruleset(self, m)
            # the echo server (HTTP 80 / 8080 / 8888, UDP 530 / 630); a clone answers with the visible name
            install_echo_server(net_scheme=self, machine=m, name=visible(m), ports=HTTP_PORTS, udp_ports=UDP_PORTS)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the fourteen questions on m1, applicable more than once."""
        self.cmd(FIREWALL, "nft flush ruleset")
        for c in self.cmds_all():
            self.cmd(FIREWALL, c)


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


def _set_pairs(nft_set) -> set:
    """The elements of an (address . port) set as ``(address, port)`` pairs, whatever the order of
    the two fields in the type of the set."""
    pairs = set()
    for item in firewall.set_tuples(nft_set):
        ports = [value for value in item if isinstance(value, int)]
        addresses = [value for value in item if isinstance(value, str)]
        if len(item) == 2 and len(ports) == 1 and len(addresses) == 1:
            pairs.add((addresses[0], ports[0]))
    return pairs


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        m1, m2, m3, ext1 = d.ips.m1, d.ips.m2, d.ips.m3, d.ips.ext1
        fw, fw_h = FIREWALL, clone(FIREWALL)
        m2_h, m3_h, ext1_h = clone('m2'), clone('m3'), clone('ext1')
        # the machines of questions 10 to 14
        forbidden, forbidden_h = ip_of(d, FORBIDDEN), clone(FORBIDDEN)
        blocked_host, blocked_host_h = ip_of(d, BLOCKED_HOST), clone(BLOCKED_HOST)
        blocked_net, blocked_net_h = getattr(d.nets, BLOCKED_NET), clone(BLOCKED_NET_HOST)

        # ---------------- diagnostics kept in the archive ---------------------------------
        for c in ("nft -a list ruleset", "ss -tulnp", "ip -br address"):
            self.test(fw, c, allow_error=True)
        clone_listing, _ = self.test(fw_h, "nft list ruleset", step=PROBE_STEP, allow_error=True)   # the transplanted ruleset
        self.test(fw_h, "nft list ruleset", step=BAN_STEP, allow_error=True)                        # ... and its sets after the trap

        # ---------------- the ruleset of m1: transplanted on its clone, and read as JSON ----
        ruleset = firewall.transplant_ruleset(self, src=fw, dst=fw_h, apply_step=LOAD_STEP)
        parsed = firewall.get_nft_json(self, fw)
        sets = firewall.get_nft_sets(self, fw)
        # The sets the rules feed, and those whose elements expire, start empty on the clone: an
        # address banned on m1 while the student was testing would otherwise fail the probes.
        volatile = firewall.updated_sets(parsed)
        volatile += [key for key in firewall.expiring_sets(sets) if key not in volatile]
        for family, table, name in volatile:
            self.test(fw_h, f"nft flush set {family} {table} {name}", step=LOAD_STEP, allow_error=True)
        if ruleset.strip() and not (clone_listing or '').strip():
            # without this the clone would silently stay open and every "blocked" probe would fail
            self.add_warning(f"the ruleset of {fw} was not loaded on its hidden copy {fw_h}: the probes ran without it",
                             step=PROBE_STEP)
        input_chains = firewall.base_chains(parsed, hook='input')
        rules = firewall.hook_rules(parsed, 'input')
        policy = firewall.input_policy(parsed)
        lo_rules = firewall.find_rules(rules, 'accept', iif='lo')
        icmp_rules = firewall.find_rules(rules, 'accept', icmp_type='echo-reply')
        udp_rules = firewall.find_rules(rules, 'accept', saddr=ext1, l4proto='udp')
        reject_rules = firewall.find_rules(rules, 'reject', saddr=m2)
        ct_rules = firewall.find_rules(rules, 'accept', ct_state={'established', 'related'})
        ct_rules_partial = firewall.find_rules(rules, 'accept', ct_state='established')
        open_index = firewall.rule_index(rules, lambda r: bool(firewall.find_rules([r], 'accept', dport=OPEN_PORT, l4proto='tcp')))
        reject_index = firewall.rule_index(rules, lambda r: r in reject_rules)
        # question 9: the named chain (of a table holding an input chain) that logs, the one input
        # jumps to when there are several (a later question may add chains); the jump to it
        log_chain, log_rule, log_chain_drops, jump_rule, jump_last = None, None, False, None, False
        candidates = []
        for base in input_chains:
            base_rules = firewall.chain_rules(parsed, base['family'], base['table'], base['name'])
            targets = {verdict[1] for verdict in map(firewall.rule_verdict, base_rules) if isinstance(verdict, tuple)}
            for user_chain in firewall.user_chains(parsed, family=base['family'], table=base['table']):
                user_rules = firewall.chain_rules(parsed, base['family'], base['table'], user_chain['name'])
                logs = [r for r in user_rules if firewall.rule_log(r) is not None]
                if logs:
                    candidates.append((user_chain['name'] not in targets, base_rules, user_chain, user_rules, logs[0]))
        if candidates:
            _, base_rules, log_chain, log_chain_rules, log_rule = min(candidates, key=lambda c: c[0])
            log_chain_drops = any(firewall.rule_verdict(r) == 'drop' for r in log_chain_rules)
            for position, r in enumerate(base_rules):
                verdict = firewall.rule_verdict(r)
                if isinstance(verdict, tuple) and verdict[1] == log_chain['name']:
                    jump_rule = r
                    # The last rule of input.  A rule of the set questions appended after it by mistake
                    # (it is dead there, and the student then inserts the right one) does not undo
                    # question 9; a rule of questions 2 to 9 placed after the jump still does.
                    jump_last = all(firewall.rule_set_lookups(later) or firewall.rule_set_updates(later)
                                    for later in base_rules[position + 1:])
        log_limit = firewall.rule_limit(log_rule) if log_rule is not None else None

        # questions 10 to 14: the output chain, and the rules looking a named set up
        out_rules = firewall.hook_rules(parsed, 'output')
        out_policy = firewall.hook_policy(parsed, 'output')
        out_ct_rules = firewall.find_rules(out_rules, 'accept', ct_state={'established', 'related'})
        out_ct_rules_partial = firewall.find_rules(out_rules, 'accept', ct_state='established')

        def looked_up(rule, *fields):
            """The named sets *rule* looks up with exactly *fields* (``'saddr'``; ``'saddr', 'dport'``
            in either order), the sets the rules feed left out: entries of ``sets``."""
            found = []
            for lookup in firewall.rule_set_lookups(rule):
                if lookup['negated'] or sorted(key or '' for key in lookup['keys']) != sorted(fields):
                    continue
                if (rule.get('family'), rule.get('table'), lookup['set']) in volatile:
                    continue
                nft_set = firewall.rule_set(sets, rule, lookup['set'])
                if nft_set is not None:
                    found.append(nft_set)
            return found

        # question 11: a rule of input dropping (or sending to a chain) what comes from a set of addresses
        block_index, block_covers = None, False
        for index, rule in enumerate(rules):
            verdict = firewall.rule_verdict(rule)
            if not (verdict in ('drop', 'reject') or isinstance(verdict, tuple)):
                continue
            for nft_set in looked_up(rule, 'saddr'):
                addresses = firewall.set_addresses(nft_set)
                covers = (firewall.addresses_cover(addresses, blocked_host.ip)
                          and firewall.addresses_cover(addresses, blocked_net))
                if block_index is None or (covers and not block_covers):
                    block_index, block_covers = index, covers
        # question 12: a rule of output accepting the TCP destination ports of a set
        port_rule, port_set_full = False, False
        for rule in firewall.find_rules(out_rules, 'accept', l4proto='tcp'):
            for nft_set in looked_up(rule, 'dport'):
                ports = firewall.set_ports(nft_set)
                port_rule = True
                port_set_full = port_set_full or (firewall.ports_cover(ports, CLOSED_PORT)
                                                  and firewall.ports_cover(ports, SET_PORT))
        # question 13: a rule of input accepting the (source address . destination port) pairs of a set
        allow_rule, allow_full = False, False
        for rule in firewall.find_rules(rules, 'accept'):
            for nft_set in looked_up(rule, 'saddr', 'dport'):
                allow_rule = True
                allow_full = allow_full or set(allowed_pairs(d)) <= _set_pairs(nft_set)
        # question 14: the rules of input feeding a set with the sources of the trap port, and the drop on that set
        ban_updates = [update for r in rules for update in firewall.rule_set_updates(r)
                       if update['key'] == 'saddr' and firewall.find_rules([r], dport=TRAP_PORT)]
        ban_names = {update['set'] for update in ban_updates}
        ban_timed = (any(update['timeout'] == BAN_SECONDS for update in ban_updates)
                     or any(s['timeout'] == BAN_SECONDS for key, s in sets.items() if key[2] in ban_names))
        ban_index = firewall.rule_index(
            rules, lambda r: firewall.rule_verdict(r) == 'drop' and any(
                lookup['key'] == 'saddr' and not lookup['negated'] and lookup['set'] in ban_names
                for lookup in firewall.rule_set_lookups(r)))

        # ---------------- the probes, from and to the hidden clones (step 3) ----------------
        lo_echo = get_http_echo(self, fw_h, '127.0.0.1', CLOSED_PORT, step=PROBE_STEP)
        ping_m2 = firewall.probe_ping(self, fw_h, m2, step=PROBE_STEP)
        ping_ext1 = firewall.probe_ping(self, fw_h, ext1, step=PROBE_STEP)
        ping_from_m2 = firewall.probe_ping(self, m2_h, m1, step=PROBE_STEP)
        udp_server = {port: get_udp_echo(self, fw_h, ext1, port, step=PROBE_STEP) for port in UDP_PORTS}
        udp_from_server = get_udp_echo(self, ext1_h, m1, UDP_PORT, step=PROBE_STEP)
        udp_from_m3 = get_udp_echo(self, m3_h, m1, UDP_PORT, step=PROBE_STEP)
        udp_to_m3 = get_udp_echo(self, fw_h, m3, UDP_PORT, step=PROBE_STEP)
        http_to_m2 = get_http_echo(self, fw_h, m2, CLOSED_PORT, step=PROBE_STEP)
        http_to_ext1 = get_http_echo(self, fw_h, ext1, CLOSED_PORT, step=PROBE_STEP)
        verdict_m2 = firewall.probe_tcp_verdict(self, m2_h, m1, CLOSED_PORT, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
        verdict_m3 = firewall.probe_tcp_verdict(self, m3_h, m1, CLOSED_PORT, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
        verdict_ext1 = firewall.probe_tcp_verdict(self, ext1_h, m1, CLOSED_PORT, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
        open_from = {src: firewall.probe_tcp(self, src, m1, OPEN_PORT, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
                     for src in (m2_h, m3_h, ext1_h)}
        # questions 10 and 12: what m1 itself opens (a local reject is seen after the first SYN
        # retransmission, one second: the timeout stays above it)
        lo_other_port = get_http_echo(self, fw_h, '127.0.0.1', OPEN_PORT, step=PROBE_STEP, timeout=OUT_TIMEOUT)
        http_to_m3 = get_http_echo(self, fw_h, m3, CLOSED_PORT, step=PROBE_STEP, timeout=OUT_TIMEOUT)
        http_set_port = get_http_echo(self, fw_h, m3, SET_PORT, step=PROBE_STEP, timeout=OUT_TIMEOUT)
        out_forbidden = firewall.probe_tcp_verdict(self, fw_h, forbidden, CLOSED_PORT, step=PROBE_STEP,
                                                   connect_timeout=OUT_TIMEOUT)
        out_other_port = firewall.probe_tcp_verdict(self, fw_h, m3, OPEN_PORT, step=PROBE_STEP, connect_timeout=OUT_TIMEOUT)
        from_forbidden = firewall.probe_tcp(self, forbidden_h, m1, OPEN_PORT, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
        # question 11: the blocklisted machines, on the port open to everybody
        verdict_blocked_host = firewall.probe_tcp_verdict(self, blocked_host_h, m1, OPEN_PORT, step=PROBE_STEP,
                                                          connect_timeout=PROBE_TIMEOUT)
        verdict_blocked_net = firewall.probe_tcp_verdict(self, blocked_net_h, m1, OPEN_PORT, step=PROBE_STEP,
                                                         connect_timeout=PROBE_TIMEOUT)
        # question 13: the pairs of the allowlist, and two pairs that are not in it
        allowed_in = {(machine, port): firewall.probe_tcp(self, clone(machine), m1, port, step=PROBE_STEP,
                                                          connect_timeout=PROBE_TIMEOUT)
                      for machine, port in ALLOWED}
        (first_machine, first_port), (second_machine, second_port) = ALLOWED
        other_port_in = firewall.probe_tcp(self, clone(first_machine), m1, second_port, step=PROBE_STEP,
                                           connect_timeout=PROBE_TIMEOUT)
        other_machine_in = firewall.probe_tcp(self, ext1_h, m1, second_port, step=PROBE_STEP, connect_timeout=PROBE_TIMEOUT)
        # question 14: one clone walks into the trap (step 4), then asks for the open port again (step 5)
        ban_source_h, ban_spared_h = clone(BAN_SOURCE), clone(BAN_SPARED)
        firewall.probe_tcp_verdict(self, ban_source_h, m1, TRAP_PORT, step=TRAP_STEP, connect_timeout=2)
        ban_before = open_from[ban_source_h]
        ban_after = firewall.probe_tcp(self, ban_source_h, m1, OPEN_PORT, step=BAN_STEP, connect_timeout=PROBE_TIMEOUT)
        ban_spared = firewall.probe_tcp(self, ban_spared_h, m1, OPEN_PORT, step=BAN_STEP, connect_timeout=PROBE_TIMEOUT)
        # what the firewall lets through only counts once it filters: an empty ruleset passes everything
        filtering = int(policy == 'drop')
        out_filtering = int(out_policy == 'drop')

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (switch `lan`) | `{lan}` | **`m1`** (`{m1}`, **le pare-feu à configurer**), `m2` (`{m2}`), `m3` (`{m3}`), `gw` eth0 (`{gw_lan}`, la passerelle) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `ext2` (`{ext2}`), `ext3` (`{ext3}`), `gw` eth1 (`{gw_ext}`) |
| `guest` (le réseau des invités) | `{guest}` | `guest1` (`{guest1}`), `gw` eth2 (`{gw_guest}`) |
""").format(lan=d.nets.lan, m1=m1.ip, m2=m2.ip, m3=m3.ip, gw_lan=d.ips.gw_lan.ip, ext=d.nets.ext, ext1=ext1.ip,
            ext2=d.ips.ext2.ip, ext3=d.ips.ext3.ip, gw_ext=d.ips.gw_ext.ip, guest=d.nets.guest, guest1=d.ips.guest1.ip,
            gw_guest=d.ips.gw_guest.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="26a346e13f23d2cd",
            description=tr("""
Lisez l'onglet **Informations** : il présente les pare-feux, Netfilter et nftables (hooks, tables,
chaînes, règles, critères, verdicts, suivi de connexion), le filtrage de ce qui sort, la commande
`nft`, la journalisation, les ensembles et la façon de tester un pare-feu.

**La maquette** (onglet *Schéma*) : un réseau local `lan` avec trois machines `m1`, `m2`, `m3` et
une passerelle `gw`, qui route vers un réseau `ext`, « l'extérieur », où se trouvent `ext1`, `ext2`
et `ext3`, et vers un réseau `guest`, celui des invités, où se trouve `guest1`. Vous configurez le
pare-feu de **`m1`** et de `m1` seulement : les autres machines servent de clients (et de serveurs)
pour vos tests. Les questions 1 à 9 n'utilisent que `m2`, `m3` et `ext1`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses, la route par défaut de toutes les machines vers
`gw`, le routage sur `gw`, les noms dans `/etc/hosts` (`m1`, `m2`, `m3`, `gw`, `gw_ext`,
`gw_guest`, `ext1`, `ext2`, `ext3`, `guest1`). Il n'y a pas de DNS. Sur **chaque** machine tourne
un **serveur de test** HTTP (ports TCP **80**, **8080** et **8888**) et UDP (ports **530** et
**630**) qui répond par son nom, les adresses et ports des deux bouts et le TTL du paquet reçu
(`curl http://m2/`, `curl http://ext1:8080/`, `echo bonjour | nc -u -w 1 m2 530` ;
section @@ref:testing@@ des Informations). Le jeu de règles nftables de toutes les machines est
vide au départ.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place : l'évaluation vérifie le jeu de règles **final** (une seule table, `inet filter` : sa
  chaîne de base `input`, puis, à partir de la question 10 seulement, sa chaîne `output` ; ne
  filtrez jamais `forward`) ;
- les questions 10 à 14 **complètent** le pare-feu des questions 2 à 9 sans rien en défaire : à la
  fin du TP, tout ce que les questions précédentes demandent doit encore fonctionner ;
- travaillez dans **votre** table, `inet filter`, créée à la main (`nft add table inet filter`)
  ou déclarée dans un fichier (méthode conseillée plus bas) ; les règles tapées avec `nft` sont
  volatiles : elles ne survivent pas à un redémarrage de la machine ;
- l'évaluation lit le jeu de règles de `m1` (`nft list ruleset`) et le **recopie sur une machine
  cachée identique** à `m1` (mêmes adresses, mêmes serveurs de test), qu'elle sonde depuis des
  copies cachées des autres machines : seul ce que dit **le jeu de règles chargé sur `m1`**
  compte, pas l'état de ses serveurs ni ce que vous faites sur les autres machines ;
- pour tester sans attendre, utilisez des délais courts : `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `nc -u -w 1 …`.

**Méthode conseillée : le pare-feu dans un fichier.** Plutôt que de taper les règles une à une,
écrivez le pare-feu de `m1` dans **`/etc/nftables.conf`**, complétez-le de question en question et
rechargez-le d'un bloc (section @@ref:nft-files@@ des Informations) : plus de guillemets pour le
shell, ni de handle à chercher pour placer une règle (on l'écrit à sa place), et des commentaires
(`#`) pour s'y retrouver. Le fichier existe déjà : le paquet Debian y a mis un squelette, une table
`inet filter` aux chaînes vides `input`, `forward` et `output`. Remplacez-le à partir de la
question 2 (la question 1 observe `m1` sans pare-feu) en gardant cette forme :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                # la déclaration de la chaîne de base (question 2), puis ses règles,
                # dans l'ordre où les paquets doivent les rencontrer
        }
        # à partir de la question 10 : chain output { … } ; questions 11 à 14 : les ensembles
}
```

Après chaque modification (`nano /etc/nftables.conf`, ou `vim`) :

```
nft -c -f /etc/nftables.conf      # vérifie sans rien changer ; aucun message : correct
nft -f /etc/nftables.conf         # remplace tout le jeu de règles par celui du fichier
nft -a list ruleset               # ce qui est réellement chargé (avec les handles)
```

- chaque erreur est signalée par le nom du fichier, les numéros de ligne et de colonne, et des
  `^^^` sous le mot fautif. Le chargement est atomique : en cas d'erreur, **rien** ne change et l'ancien
  jeu de règles reste en place ;
- **l'évaluation ne lit pas le fichier**, seulement le jeu de règles chargé sur `m1` : un fichier
  modifié mais pas rechargé ne compte pas, et aucun service ne le charge dans les machines du TP ;
- `flush ruleset` en tête : recharger le fichier remplace tout, sans doublon (aucune autre table
  n'est à garder sur `m1`). Cela remet aussi à zéro les compteurs et vide les ensembles remplis par
  les règles (question 14) ;
- les questions qui font pratiquer une commande (`nft insert rule`, `nft replace rule … handle`,
  `nft add element`, un changement de politique) se font dans le fichier par la modification
  correspondante : la règle écrite à sa place, l'élément ajouté à la liste, la politique changée.
  Essayez la commande si vous voulez, mais reportez **toute** modification dans le fichier : le
  prochain `nft -f` efface ce qu'il ne contient pas ;
- déjà commencé à la main ? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  transforme le jeu de règles en place en fichier.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) vide le jeu de règles de `m1` puis
applique toute la solution et remplit les formulaires ; il est ré-applicable et une évaluation
lancée juste après donne 140/140 et les 6 points de bonus (questions 1 à 9 : 100 points ; questions
10 à 13 : 40 points ; question 14 : bonus). Le fichier `/etc/nftables.conf` n'est qu'une méthode
conseillée aux étudiants : l'évaluation ne le lit pas (seul compte le jeu de règles chargé), et
l'état `final` passe par des commandes `nft`.

**Aucune question n'en pénalise une autre.** La chaîne `output` de la question 10 autorise tout ce
que les sondes des questions 1 à 9 font émettre à `m1` (`lo`, `ping`, TCP {closed}, UDP {udp_port} et
{udp_other}, et toutes ses réponses par la règle à états, message d'erreur du `reject` de la
question 6 compris) ; les restrictions des questions 10 à 14 ne s'observent que sur des machines et
des ports que les questions 1 à 9 ne sondent pas (`ext2`, `ext3`, `guest1`, les ports {set_port} et
{trap}, le port {open} en sortie) ; leurs règles de `input` sont insérées, aucune règle déjà évaluée
n'est réécrite. En revanche c'est le jeu de règles **final** qui est évalué : une chaîne `output`
**fausse** fait perdre les points de ce qu'elle casse réellement (sans `related`, `m2` n'est plus
prévenue du refus de la question 6 ; sans règle à états, le port {open} ne répond plus à personne).

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` sur `m1`
(étape 1), chargé tel quel sur `{fw_h}` après un `nft flush ruleset` (étape 2 ; un jeu de règles
vide laisse la copie sans filtre ; les ensembles alimentés par les règles ou à délai d'expiration y
sont vidés : une adresse bannie sur `m1` pendant vos essais ne fausse rien), puis les sondes
(étape 3) depuis les copies cachées de `m2`, `m3`, `ext1`, `ext2`, `ext3`, `guest1` et depuis
`{fw_h}` elle-même : `curl` des serveurs de test (HTTP {closed} / {open} / {set_port}), `nc -u`
(UDP {udp_port}), `ping`, connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert,
`RC=124` détruit, autre code refusé). La question 14 ajoute une connexion au port {trap} (étape 4)
puis deux sondes (étape 5). Les copies cachées répondent sous les noms visibles (`SERVER=m2`…). La
structure du jeu de règles (politique, critères, verdicts, ordre, `log` / `limit`, ensembles) est
lue dans `nft -j list ruleset` de `m1` : les chaînes de base des hooks `input` et `output`, famille
`inet` ou `ip`. Ce que le pare-feu **laisse passer** (sondes positives) ne compte qu'une fois la
politique `drop` en place : un jeu de règles vide laisse tout passer et vaut 0 ; ce qu'il **arrête**
ne compte que si une sonde témoin passe. Une évaluation dure une vingtaine de secondes (les sondes
que le pare-feu doit détruire attendent {timeout} s). Les machines ne peuvent pas lire le journal du
noyau (pas de `CAP_SYSLOG`) : la question 9 journalise vers nflog (`log … group {group}`,
`tcpdump -n -i nflog:0`), mais toute règle `log` est acceptée.
""").format(fw_h=fw_h, udp_port=UDP_PORT, udp_other=UDP_PORTS[1], timeout=PROBE_TIMEOUT, group=NFLOG_GROUP,
            closed=CLOSED_PORT, open=OPEN_PORT, set_port=SET_PORT, trap=TRAP_PORT)),
        )

        # =====================================================================
        # Part 1 — before the firewall (question 1)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Avant le pare-feu (question 1)"))

        q1_answers = {"ttl_lan": "64", "ttl_ext": "63", "client_ip": str(m1.ip), "ruleset": "empty"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Tests avant le pare-feu"),
            hash="f98bfc4ef14ed62a",
            description=tr("""
Depuis `m1`, vérifiez que tout fonctionne : les serveurs de test de `m2` (`{m2}`), `m3` (`{m3}`)
et `ext1` (`{ext1}`, à travers `gw`) en HTTP (`curl http://m2/`, `curl http://m3:8080/`,
`curl http://ext1/`) et en UDP (`echo bonjour | nc -u -w 1 m2 530`, `echo bonjour | nc -u -w 1
ext1 630`), et les `ping` vers `m2` et `ext1`. Lisez les lignes `TTL=` et `CLIENT_IP=` des
réponses. Faites les mêmes essais depuis `m2` vers `m1` (`curl http://m1/`…). Sur `m1`, affichez
les ports en écoute (`ss -tulnp`) et l'état du pare-feu (`nft list ruleset`).
""").format(m2=m2.ip, m3=m3.ip, ext1=ext1.ip)
            + tr("""
- `TTL=` dans la réponse de `m2` : @@{ttl_lan:[0-9]+}@@
- `TTL=` dans la réponse de `ext1` : @@{ttl_ext:[0-9]+}@@
- `CLIENT_IP=` dans la réponse de `ext1` : @@{client_ip:[0-9.]+}@@
- `nft list ruleset` sur `m1` affiche : @@{ruleset:>rien : aucune table ni règle, tout est accepté>>>empty|une table filter dont la chaîne input a la politique drop>>>drop|les règles installées par Docker>>>docker|une erreur : nft n'est pas installé>>>error}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer. `TTL=64` depuis `m2` (même réseau), `TTL=63` depuis `ext1` (un
routeur traversé, `gw`), `CLIENT_IP={m1}` (pas de traduction d'adresses sur `gw`), et `nft list
ruleset` n'affiche rien : le jeu de règles est vide, tout passe. `ss -tulnp` montre un `python3` en
écoute sur `0.0.0.0:80`, `:8080` (TCP) et `:530`, `:630` (UDP).

- Réponses : 64 ; 63 ; `{m1}` ; rien.
- Cette question n'est évaluée que par le formulaire.
""").format(m1=m1.ip)),
            cheat_answers={"final": q1_answers},
        )

        self.add_grade_element(
            title=no_tr("q_before_typed"), max_grade=4, grade_part=part1,
            grade=int(_is_int(q1.get("ttl_lan"), 64)) + 2 * int(_is_int(q1.get("ttl_ext"), 63))
                  + int(_same_ip(q1.get("client_ip"), m1)),
            description=tr("avant le pare-feu : TTL depuis m2 et ext1, CLIENT_IP vu par ext1"),
        )
        self.add_grade_element(
            title=no_tr("q_before"), max_grade=2, grade_part=part1, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q1.get("ruleset")) == "empty"),
            description=tr("avant le pare-feu : jeu de règles vide"),
        )

        # =====================================================================
        # Part 2 — the default policy (question 2)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Politique par défaut (question 2)"))

        q2_answers = {"why": "replies_dropped"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Politique par défaut"),
            hash="260e3ca2383cb788",
            description=tr("""
Sur `m1`, créez une table **`filter`** de la famille **`inet`** et, dedans, une chaîne de base
**`input`** de type `filter`, accrochée au hook `input`, de priorité 0 et de politique **`drop`**
(section @@ref:structure@@ des Informations). Vérifiez avec `nft list ruleset`, puis que plus rien
n'entre : depuis `m2`, `curl -m 3 http://m1/` et `ping -c 2 -W 1 m1` échouent. Refaites alors les
essais de la question 1 **depuis `m1`** (`curl -m 3 http://m2/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m2`) : ils échouent aussi. Pourquoi ?
""")
            + tr("""
- pourquoi `m1` ne joint-elle plus `m2`, alors que seule la chaîne `input` filtre ? @@{why:>les requêtes de m1 partent (output n'est pas filtré) mais les réponses de m2 arrivent dans input et sont détruites : la connexion n'aboutit pas>>>replies_dropped|la politique drop s'applique à toutes les chaînes, output comprise>>>all_chains|m2 ne reçoit plus les requêtes de m1>>>no_requests|la table inet ne gère pas IPv4>>>inet_ipv6}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`nft list ruleset` affiche la table et la chaîne vide avec `policy drop`. Tout ce qui arrive sur
`m1` est détruit, y compris les **réponses** (SYN-ACK de `m2`, datagrammes UDP de retour, `echo-reply`)
à ce que `m1` émet : les requêtes partent (`output` n'est pas filtré), rien ne revient, `curl` et
`nc` expirent, `ping` perd tout.

- Réponse : les réponses de m2 sont détruites dans input.
- L'évaluation lit `nft -j list ruleset` sur `m1` : une chaîne de base de type `filter` accrochée au
  hook `input` (famille `inet` ou `ip`) avec `policy drop`, de priorité 0.
""").format(cmds=_lines(self.net_scheme.cmds_policy()))),
            cheat_answers={"final": q2_answers},
        )

        self.add_grade_element(
            title=no_tr("policy_drop"), max_grade=4, grade_part=part2,
            grade=4 * int(policy == 'drop'),
            description=tr("une chaîne de base du hook input avec la politique drop"),
        )
        self.add_grade_element(
            title=no_tr("base_chain"), max_grade=2, grade_part=part2,
            grade=2 * int(any(c.get('type') == 'filter' and c.get('prio') == 0 for c in input_chains)),
            description=tr("la chaîne input est de type filter, priorité 0"),
        )
        self.add_grade_element(
            title=no_tr("q_policy"), max_grade=4, grade_part=part2, scope=CHOICE_SCOPE,
            grade=4 * int(_norm(q2.get("why")) == "replies_dropped"),
            description=tr("pourquoi m1 ne joint plus m2 : les réponses sont détruites dans input"),
        )

        # =====================================================================
        # Part 3 — the loopback interface (question 3)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Filtrage par interface (question 3)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrage par interface : la boucle locale"),
            hash="2d39d3b4e7e4d2e2",
            description=tr("""
Sur `m1`, essayez `curl -m 3 http://127.0.0.1/` : le serveur de test de `m1` elle-même ne répond
plus, car les paquets locaux passent par `output` **puis** par `input`, via l'interface `lo`
(section @@ref:hooks@@ des Informations). Ajoutez à la chaîne `input` une règle acceptant tout ce
qui arrive par l'interface **`lo`** (critère `iif`, section @@ref:selectors@@), et vérifiez que
`curl http://127.0.0.1/` et `curl http://localhost:8080/` fonctionnent de nouveau.
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

(`iifname "lo"` convient aussi.) Toute machine avec un pare-feu `policy drop` a cette règle en
tête : sans elle, les services locaux (bases de données, résolveur, X11…) ne se joignent plus.

- L'évaluation cherche dans `input` une règle `accept` dont le critère `iif` ou `iifname` est `lo`,
  et vérifie que `curl http://127.0.0.1/` répond sur la copie cachée de `m1`.
""").format(cmds=_lines(self.net_scheme.cmds_lo()))),
        )

        self.add_grade_element(
            title=no_tr("lo_rule"), max_grade=3, grade_part=part3,
            grade=3 * int(bool(lo_rules)),
            description=tr("une règle accept pour l'interface lo (iif / iifname)"),
        )
        self.add_grade_element(
            title=no_tr("lo_works"), max_grade=5, grade_part=part3,
            grade=5 * filtering * int(lo_echo['server'] == FIREWALL),
            description=tr("sur m1, curl http://127.0.0.1/ répond (serveur local joignable à travers le pare-feu)"),
        )

        # =====================================================================
        # Part 4 — ICMP (question 4)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Filtrage par protocole (question 4)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrage par protocole : ICMP"),
            hash="c82298c274408ed8",
            description=tr("""
Ajoutez à la chaîne `input` de `m1` une règle acceptant les paquets ICMP de type **`echo-reply`**
(les réponses aux `ping`, critère `icmp type` ; `nft describe icmp type` liste les types).
Vérifiez que `m1` peut de nouveau pinguer `m2` (`{m2}`) et `ext1` (`{ext1}`), mais que `m2` ne
peut toujours pas pinguer `m1` : ses requêtes (`echo-request`) sont détruites. Observez-les avec
`tcpdump -n -i eth0 icmp` sur `m1`.
""").format(m2=m2.ip, ext1=ext1.ip)
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`m1` reçoit les réponses à ses propres `ping` ; les `echo-request` de `m2` sont détruits par la
politique (`tcpdump` sur `m1` les voit arriver, sans réponse). Accepter `icmp type echo-request`
rendrait `m1` pingable ; la règle à états de la question 7 acceptera aussi les `echo-reply` (une
réponse est `established`), mais la règle explicite reste.

- L'évaluation : `ping` de la copie de `m1` vers `m2` et `ext1` (réponses), `ping` de la copie de
  `m2` vers `m1` (doit échouer), une règle `accept` avec `icmp type echo-reply`.
""").format(cmds=_lines(self.net_scheme.cmds_icmp()))),
        )

        self.add_grade_element(
            title=no_tr("ping_out"), max_grade=5, grade_part=part4,
            grade=filtering * (3 * int(ping_m2) + 2 * int(ping_ext1)),
            description=tr("m1 pingue m2 et ext1 (les echo-reply entrent)"),
        )
        self.add_grade_element(
            title=no_tr("ping_in_blocked"), max_grade=3, grade_part=part4,
            grade=3 * int(not ping_from_m2),
            description=tr("m2 ne pingue pas m1 (les echo-request sont détruits)"),
        )
        self.add_grade_element(
            title=no_tr("icmp_rule"), max_grade=2, grade_part=part4,
            grade=2 * int(bool(icmp_rules)),
            description=tr("une règle accept avec icmp type echo-reply"),
        )

        # =====================================================================
        # Part 5 — UDP from one source address (question 5)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Filtrage par protocole et adresse source (question 5)"))

        q5_answers = {"ext1_queries": "yes_stateless"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Filtrage par protocole et adresse source : UDP"),
            hash="3282e30672aee614",
            description=tr("""
`ext1` (`{ext1}`) joue le rôle d'un serveur de l'extérieur que `m1` interroge en UDP (comme un
serveur DNS). Ajoutez à la chaîne `input` de `m1` une règle acceptant **tous les paquets UDP venant
de `ext1`** (critères `ip saddr` et `meta l4proto`). Vérifiez que `echo bonjour | nc -u -w 1 ext1
530` (et 630) fonctionne depuis `m1`, alors que `echo bonjour | nc -u -w 1 m2 530` ne fonctionne
toujours pas : la réponse de `m2` est un paquet UDP venant de `m2`. Puis, **depuis `ext1`**, essayez
`echo bonjour | nc -u -w 1 m1 530` : `ext1` obtient-elle une réponse du serveur UDP de `m1` ?
""").format(ext1=ext1.ip)
            + tr("""
- depuis `ext1`, `nc -u m1 530` obtient-il une réponse ? @@{ext1_queries:>oui : la règle accepte tout datagramme UDP venant de ext1, requête ou réponse, elle ne distingue pas le sens de l'échange>>>yes_stateless|non : seules les réponses aux requêtes de m1 passent>>>answers_only|non : ext1 est dans un autre réseau IP, ses paquets sont routés et détruits par gw>>>other_network|oui, mais seulement sur le port 630>>>only_630}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

(`ip protocol udp` convient aussi.) Les réponses du serveur UDP de `ext1` entrent, celles de `m2`
non. Mais le filtre est **sans état** : il accepte aussi les **requêtes** UDP que `ext1` envoie à
`m1` (`nc -u m1 530` depuis `ext1` est servi, `TTL=63`). La règle à états de la question 7 est la
bonne réponse au besoin « recevoir les réponses à mes requêtes » ; celle-ci ouvre plus que voulu.

- Réponse : oui, la règle ne distingue pas le sens.
- L'évaluation : `nc -u` de la copie de `m1` vers `ext1` (ports {p0} et {p1}), de la copie de `ext1`
  vers `m1` (port {p0}, conséquence de la règle sans état), une règle `accept` avec `ip saddr {ext1}`
  et le protocole `udp`.
""").format(cmds=_lines(self.net_scheme.cmds_udp_server()), p0=UDP_PORTS[0], p1=UDP_PORTS[1], ext1=ext1.ip)),
            cheat_answers={"final": q5_answers},
        )

        self.add_grade_element(
            title=no_tr("udp_from_server"), max_grade=4, grade_part=part5,
            grade=filtering * (3 * int(udp_server[UDP_PORTS[0]]['server'] == UDP_SERVER)
                               + int(udp_server[UDP_PORTS[1]]['server'] == UDP_SERVER)),
            description=tr("m1 obtient les réponses UDP de ext1 (ports {p0} et {p1})").format(p0=UDP_PORTS[0], p1=UDP_PORTS[1]),
        )
        self.add_grade_element(
            title=no_tr("udp_server_queries"), max_grade=2, grade_part=part5,
            grade=2 * filtering * int(udp_from_server['server'] == FIREWALL),
            description=tr("ext1 interroge le serveur UDP de m1 (règle sans état : tout l'UDP de ext1 entre)"),
        )
        self.add_grade_element(
            title=no_tr("udp_rule"), max_grade=2, grade_part=part5,
            grade=2 * int(bool(udp_rules)),
            description=tr("une règle accept pour l'UDP venant de ext1 (ip saddr + udp)"),
        )
        self.add_grade_element(
            title=no_tr("q_udp"), max_grade=2, grade_part=part5, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q5.get("ext1_queries")) == "yes_stateless"),
            description=tr("le filtre sans état accepte aussi les requêtes UDP de ext1"),
        )

        # =====================================================================
        # Part 6 — drop versus reject (question 6)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — drop ou reject (question 6)"))

        q6_answers = {"from_m2": "refused", "from_m3": "timeout", "from_m1": "both_fail"}
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Différence entre drop et reject"),
            hash="29afd008751f17ac",
            description=tr("""
Ajoutez à la chaîne `input` de `m1` une règle **rejetant** (`reject`) tous les paquets venant de
`m2` (`{m2}`) ; ceux de `m3` (`{m3}`) restent détruits par la politique `drop`. Comparez, en lisant
les messages d'erreur et le temps de réponse (section @@ref:testing@@ des Informations) :

- depuis `m2` : `curl -m 5 http://m1/` ;
- depuis `m3` : `curl -m 5 http://m1/` ;
- depuis `m1` : `curl -m 5 http://m2/` puis `curl -m 5 http://m3/`.

Pendant l'essai depuis `m2`, capturez sur `m2` avec `tcpdump -n -i eth0 'icmp or tcp port 80'` :
que reçoit `m2` de `m1` ?
""").format(m2=m2.ip, m3=m3.ip)
            + tr("""
- depuis `m2`, `curl http://m1/` : @@{from_m2:>échoue immédiatement, « Connection refused » : m1 répond par une erreur (ICMP port unreachable) au SYN de m2>>>refused|attend puis expire (délai d'attente) : rien ne revient>>>timeout|la page s'affiche>>>works}@@
- depuis `m3`, `curl http://m1/` : @@{from_m3:>attend puis expire (délai d'attente) : le SYN est détruit sans réponse>>>timeout|échoue immédiatement, « Connection refused »>>>refused|la page s'affiche>>>works}@@
- depuis `m1`, vers `m2` et vers `m3` : @@{from_m1:>les deux échouent après le délai : les requêtes partent mais les réponses (SYN-ACK) arrivent dans input, rejetée pour m2 (c'est m2 qui reçoit l'erreur), détruite pour m3>>>both_fail|seule m3 répond>>>only_m3|seule m2 répond>>>only_m2|les deux pages s'affichent : output n'est pas filtré>>>both_work}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

Depuis `m2`, `curl` échoue **aussitôt** : `curl: (7) Failed to connect to m1 port 80 … Couldn't
connect to server` (`nc -v m1 80` : `Connection refused`) ; `tcpdump` sur `m2` montre son SYN puis
`IP {m1} > {m2}: ICMP {m1} tcp port 80 unreachable`
(`reject with tcp reset` donnerait un RST ; `nft list ruleset` affiche la règle sous sa forme complète,
`reject with icmp port-unreachable`). Depuis `m3`, `curl` attend
les 5 s puis `Connection timed out` : le SYN est détruit, `m3` le retransmet, rien ne revient. Depuis
`m1`, les deux `curl` expirent : la requête part, le SYN-ACK de `m2` est rejeté (le message ICMP
part vers `m2`, pas vers le processus `curl`), celui de `m3` est détruit.

- Réponses : refusé immédiatement ; délai d'attente ; les deux échouent après le délai.
- L'évaluation ouvre une connexion TCP vers le port {port} de la copie de `m1` depuis les copies de
  `m2` (refus immédiat attendu) et de `m3` (expiration attendue : {timeout} s), et cherche une règle
  `reject` avec `ip saddr {m2}`. Le port {port} est servi sur la copie : un refus ne peut venir que
  du `reject`.
""").format(cmds=_lines(self.net_scheme.cmds_reject()), m1=m1.ip, m2=m2.ip, port=CLOSED_PORT, timeout=PROBE_TIMEOUT)),
            cheat_answers={"final": q6_answers},
        )

        self.add_grade_element(
            title=no_tr("reject_m2"), max_grade=4, grade_part=part6,
            grade=4 * int(verdict_m2 == 'refused'),
            description=tr("m2 est refusée immédiatement sur le port {port} de m1 (reject)").format(port=CLOSED_PORT),
        )
        self.add_grade_element(
            title=no_tr("drop_m3"), max_grade=3, grade_part=part6,
            grade=3 * int(verdict_m3 == 'dropped'),
            description=tr("m3 n'a aucune réponse du port {port} de m1 (drop)").format(port=CLOSED_PORT),
        )
        self.add_grade_element(
            title=no_tr("reject_rule"), max_grade=2, grade_part=part6,
            grade=2 * int(bool(reject_rules)),
            description=tr("une règle reject pour ip saddr m2"),
        )
        self.add_grade_element(
            title=no_tr("q_reject"), max_grade=3, grade_part=part6, scope=CHOICE_SCOPE,
            grade=int(_norm(q6.get("from_m2")) == "refused") + int(_norm(q6.get("from_m3")) == "timeout")
                  + int(_norm(q6.get("from_m1")) == "both_fail"),
            description=tr("drop ou reject : ce que voient m2, m3 et m1"),
        )

        # =====================================================================
        # Part 7 — connections initiated locally (question 7)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Connexions initiées localement (question 7)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Autoriser les connexions initiées localement"),
            hash="7459c1dff9ea9fce",
            description=tr("""
Insérez **en première position** de la chaîne `input` de `m1` la règle à états
`ct state established,related accept` (`nft insert rule …`, sections @@ref:conntrack@@ et
@@ref:nft-cli@@ des Informations). Vérifiez que `m1` peut de nouveau tout initier : `curl -m 3
http://m2/`, `curl -m 3 http://m3:8080/`, `curl -m 3 http://ext1/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m3` ; mais que `m2` et `m3` ne peuvent toujours rien initier vers `m1`
(`curl -m 5 http://m1/` : refusé pour `m2`, délai pour `m3` ; `echo bonjour | nc -u -w 1 m1 530`
depuis `m3` : pas de réponse). Pourquoi la règle de la question 5 n'est-elle plus nécessaire pour
les réponses de `ext1`, et pourquoi reste-t-elle gênante ?
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`nft list ruleset` la montre en tête. Le suivi de connexion reconnaît les réponses (SYN-ACK, segments
suivants, datagrammes UDP de retour, `echo-reply`) à ce que `m1` a émis : elles sont `established`
et acceptées, quel que soit l'émetteur. Les **nouvelles** connexions vers `m1` (SYN de `m2` ou `m3`,
premier datagramme UDP) ne sont ni `established` ni `related` : refusées pour `m2`, détruites pour `m3`.
La règle de la question 5 est devenue inutile pour les réponses de `ext1` et reste gênante parce
qu'elle accepte aussi ses requêtes ; on la garde pour l'évaluation.

- L'évaluation : depuis la copie de `m1`, HTTP vers `m2` et `ext1` et UDP vers `m3` (réponses
  acceptées), depuis la copie de `m3` UDP vers `m1` (sans réponse), une règle `accept` avec
  `ct state established,related`.
""").format(cmds=_lines(self.net_scheme.cmds_established()))),
        )

        self.add_grade_element(
            title=no_tr("local_tcp"), max_grade=5, grade_part=part7,
            grade=filtering * (3 * int(http_to_m2['server'] == 'm2') + 2 * int(http_to_ext1['server'] == 'ext1')),
            description=tr("m1 initie des connexions TCP vers m2 et ext1 (réponses acceptées)"),
        )
        self.add_grade_element(
            title=no_tr("local_udp"), max_grade=3, grade_part=part7,
            grade=3 * filtering * int(udp_to_m3['server'] == 'm3'),
            description=tr("m1 initie un échange UDP avec m3 (réponse acceptée)"),
        )
        self.add_grade_element(
            title=no_tr("inbound_still_blocked"), max_grade=2, grade_part=part7,
            grade=2 * int(udp_from_m3['server'] == ''),
            description=tr("m3 n'obtient rien du serveur UDP de m1 (nouvelle connexion entrante)"),
        )
        self.add_grade_element(
            title=no_tr("ct_rule"), max_grade=4, grade_part=part7,
            grade=4 if ct_rules else 2 * int(bool(ct_rules_partial)),
            description=tr("une règle accept avec ct state established,related"),
        )

        # =====================================================================
        # Part 8 — one open port (question 8)
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Filtrage par protocole et port (question 8)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrage par protocole et port : ouvrir un service"),
            hash="081281e9d06d1f58",
            description=tr("""
Vérifiez depuis `m1` que son propre serveur de test répond sur les ports 80 et 8080
(`curl http://127.0.0.1/`, `curl http://127.0.0.1:8080/`). Autorisez à présent les connexions TCP
entrantes vers le port **{open}** de `m1`, depuis n'importe où, et vérifiez depuis `m2`, `m3` et
`ext1` que `curl -m 5 http://m1:{open}/` répond alors que `curl -m 5 http://m1/` (port {closed})
échoue toujours.

Attention à **l'ordre des règles** : si la règle du port {open} est ajoutée en fin de chaîne, elle
vient **après** la règle `reject` de la question 6 et `m2` reste refusée. Placez-la avant, avec
`nft insert rule` (en tête) ou `nft -a list ruleset` puis `nft insert rule inet filter input
handle N …` (section @@ref:nft-cli@@ des Informations).
""").format(open=OPEN_PORT, closed=CLOSED_PORT)
            + instructor(tr("""
**Solution.** Sur `m1`, en tête de chaîne :

```
{cmds}```

ou, pour la placer juste avant la règle `reject` (handle lu dans `nft -a list ruleset`) :
`nft insert rule inet filter input handle N tcp dport {open} accept`. Depuis `m2`, `m3` et `ext1`,
le port {open} répond (`SERVER=m1`, `TTL=63` pour `ext1`) ; le port {closed} reste refusé pour `m2`,
sans réponse pour `m3` et `ext1`.

- L'évaluation : connexion TCP vers le port {open} de la copie de `m1` depuis les copies de `m2`,
  `m3` et `ext1` (ouvert), vers le port {closed} depuis `ext1` (détruit), et une règle `accept` avec
  `tcp dport {open}` placée **avant** la règle `reject` de `m2` dans `input`.
""").format(cmds=_lines(self.net_scheme.cmds_open_port()), open=OPEN_PORT, closed=CLOSED_PORT)),
        )

        self.add_grade_element(
            title=no_tr("port_open"), max_grade=12, grade_part=part8,
            grade=filtering * (4 * int(open_from[m2_h]) + 4 * int(open_from[m3_h]) + 4 * int(open_from[ext1_h])),
            description=tr("le port {open} de m1 est ouvert depuis m2, m3 et ext1").format(open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("closed_port_blocked"), max_grade=3, grade_part=part8,
            grade=2 * int(verdict_ext1 != 'open') + int(verdict_ext1 == 'dropped'),
            description=tr("le port {closed} de m1 reste fermé à ext1 (détruit)").format(closed=CLOSED_PORT),
        )
        self.add_grade_element(
            title=no_tr("open_rule_order"), max_grade=3, grade_part=part8,
            grade=int(open_index is not None) + 2 * int(open_index is not None and (reject_index is None or open_index < reject_index)),
            description=tr("une règle accept tcp dport {open}, avant la règle reject de m2").format(open=OPEN_PORT),
        )

        # =====================================================================
        # Part 9 — log and a named chain (question 9)
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — Journal des paquets et chaîne nommée (question 9)"))

        q9_answers = {"where_logs": "nflog"}
        q9 = self.question_form(
            section=self.section(0),
            title=tr("Journal des paquets et chaîne nommée"),
            hash="6a195a54c0888cf1",
            description=tr("""
**(a)** Ajoutez en fin de chaîne `input` une règle qui **journalise** les paquets qui vont être
détruits : `log prefix "input drop: " group {group}` (section @@ref:logging@@ des Informations ; dans le
shell, protégez toute la règle par des apostrophes à cause des guillemets du préfixe). Sur `m1`,
lancez `tcpdump -n -i nflog:{group}` et, depuis `m3`, `curl -m 3 http://m1/` : les SYN détruits
apparaissent. Pourquoi les paquets de `m2` n'y sont-ils pas ?

**(b)** Créez une chaîne nommée **`{chain}`** (sans hook) contenant une règle `log` suivie d'une
règle `drop` (ou `counter drop`).

**(c)** Remplacez la règle `log` de la chaîne `input` par un saut vers `{chain}` (`jump {chain}`),
en **dernière règle** : supprimez l'ancienne avec `nft -a list ruleset` et `nft delete rule inet
filter input handle N`. Vérifiez que les paquets de `m3` sont toujours journalisés puis détruits.

**(d)** Pour que `m1` ne soit pas submergée par les journaux, limitez la journalisation à **{rate}
paquets par minute** (`limit rate {rate}/minute` devant `log`, dans la règle de `{chain}`). Depuis
`m3`, `ping -c 20 -i 0.2 m1` : combien de lignes `tcpdump` affiche-t-il ? Le compteur de la règle
`drop`, lui, compte tout (`nft list ruleset`).
""").format(group=NFLOG_GROUP, chain=LOG_CHAIN, rate=LOG_RATE)
            + tr("""
- où lit-on les paquets journalisés par `log … group 0` ? @@{where_logs:>avec tcpdump -n -i nflog:0 sur m1 (ou le démon ulogd) ; sans group, dans le journal du noyau d'une vraie machine (dmesg, journalctl -k)>>>nflog|dans /var/log/syslog de m3, la machine qui émet>>>syslog_m3|dans la sortie de nft list ruleset, sous la règle log>>>ruleset|nulle part : log ne fait rien sans verdict>>>nowhere}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

(a) `tcpdump -n -i nflog:{group}` affiche chaque SYN de `m3` vers le port 80 (retransmis toutes les
secondes), rien de `m2` : ses paquets sont rejetés par la règle `reject`, placée avant, et
n'atteignent jamais la fin de la chaîne. Sans `group`, `log` vise le journal du noyau : dans un
conteneur il n'y écrit rien par défaut (`net.netfilter.nf_log_all_netns`), et les conteneurs du TP ne
peuvent de toute façon pas le lire (`dmesg` : *Operation not permitted*). (b) et (c) : la chaîne
`{chain}` journalise puis détruit ; `jump {chain}` en dernière règle de `input` ; la politique `drop`
reste en filet de sécurité. (d) `limit rate {rate}/minute` est un seau à jetons : {rate} jetons au
départ (la rafale par défaut), puis un toutes les 12 s ; sur les 20 `echo-request` de `m3`, `tcpdump`
n'affiche que les premiers (une seule ligne si des paquets détruits juste avant ont vidé le seau), le
`counter` de la règle `drop` en compte 20.

- Réponse : avec `tcpdump -n -i nflog:0` (ou dans le journal du noyau d'une vraie machine).
- L'évaluation lit `nft -j list ruleset` : une chaîne nommée de la table contenant `input` avec une
  règle `log` et une règle `drop`, un `jump` (ou `goto`) vers elle en dernière règle de `input`, et
  `limit rate {rate}/minute` dans la règle `log`. Toute forme de `log` est acceptée.
""").format(cmds=_lines(self.net_scheme.cmds_log()), group=NFLOG_GROUP, chain=LOG_CHAIN, rate=LOG_RATE)),
            cheat_answers={"final": q9_answers},
        )

        self.add_grade_element(
            title=no_tr("log_chain"), max_grade=4, grade_part=part9,
            grade=2 * int(log_chain is not None) + 2 * int(log_chain is not None and log_chain_drops),
            description=tr("une chaîne nommée qui journalise (log) puis détruit (drop)"),
        )
        self.add_grade_element(
            title=no_tr("log_jump"), max_grade=3, grade_part=part9,
            grade=2 * int(jump_rule is not None) + int(jump_rule is not None and jump_last),
            description=tr("input saute vers cette chaîne, en dernière règle"),
        )
        self.add_grade_element(
            title=no_tr("log_limit"), max_grade=3, grade_part=part9,
            grade=3 if (log_limit is not None and log_limit['rate'] == LOG_RATE and log_limit['per'] == 'minute')
            else int(log_limit is not None),
            description=tr("la journalisation est limitée à {rate} paquets par minute (limit rate)").format(rate=LOG_RATE),
        )
        self.add_grade_element(
            title=no_tr("q_log"), max_grade=2, grade_part=part9, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q9.get("where_logs")) == "nflog"),
            description=tr("où lire les paquets journalisés (nflog / journal du noyau)"),
        )

        # =====================================================================
        # Part 10 — the output chain (question 10)
        # =====================================================================
        part10 = self.add_grade_part(no_tr("part10"), tr("Partie 10 — Filtrer ce qui sort (question 10)"))

        q10_answers ={"with_drop": "timeout", "with_reject": "refused", "from_forbidden": "synack_rejected"}
        q10 = self.question_form(
            section=self.section(0),
            title=tr("Filtrer ce qui sort : la chaîne output"),
            hash="5f792a319c111434",
            description=tr("""
Jusqu'ici `m1` émet ce qu'elle veut : seule sa chaîne `input` filtre. On contrôle maintenant ce
qu'elle **émet**, dans une chaîne de base accrochée au hook **`output`** (section @@ref:output@@
des Informations). `ext2` (`{forbidden}`) est une machine de l'extérieur vers laquelle `m1` ne doit
rien **initier**.

**(a)** Ajoutez à la table `inet filter` une chaîne de base **`output`** (type `filter`, hook
`output`, priorité 0, politique **`accept`** pour l'instant) et, dedans, une règle qui **détruit**
tout ce que `m1` envoie à `ext2` (critère `ip daddr`). Depuis `m1`, essayez `curl -m 5
http://ext2/` et `ping -c 2 -W 1 ext2` ; avec `tcpdump -n -i eth0 host ext2`, voit-on partir un
paquet ?

**(b)** Remplacez `drop` par **`reject`** dans cette règle (`nft -a list ruleset` puis `nft replace
rule …`, ou `nft flush chain inet filter output` puis ajoutez-la de nouveau), et refaites les deux
essais.

**(c)** Depuis `ext2`, essayez `curl -m 5 http://m1:{open}/` : le port {open}, ouvert à tous depuis
la question 8, ne répond plus à `ext2`. Insérez **en tête** de la chaîne `output` la règle à états
`ct state established,related accept`, et refaites l'essai : `ext2` est de nouveau servie, alors
que `m1` ne peut toujours rien initier vers elle.

**(d)** `m1` ne doit plus émettre que ce qui est prévu. Ajoutez à la fin de la chaîne `output` les
règles qui acceptent :

- tout ce qui sort par l'interface `lo` (`oif lo`) ;
- les `ping` (`icmp type echo-request`) ;
- les connexions TCP vers le port **{closed}** ;
- les datagrammes UDP vers les ports **{udp0}** et **{udp1}** (un ensemble anonyme, `udp dport
  {{ {udp0}, {udp1} }}` : dans le shell, toute la règle entre apostrophes) ;

puis une dernière règle **`reject`** sans critère, pour que les programmes de `m1` soient prévenus
aussitôt de ce qui leur est interdit. **Ensuite seulement**, passez la politique de la chaîne à
**`drop`** : on déclare la chaîne de nouveau, à l'identique, avec `policy drop`.

Vérifiez que **tout ce qui marchait marche encore** : depuis `m1`, `curl http://127.0.0.1:{open}/`,
`ping -c 2 -W 1` vers `m2` et `ext1`, `curl -m 3 http://m2/`, `curl -m 3 http://ext1/`, `echo
bonjour | nc -u -w 1 ext1 {udp0}`, `echo bonjour | nc -u -w 1 m3 {udp0}` ; depuis `m3` et `ext1`,
`curl -m 5 http://m1:{open}/` ; depuis `m2`, `curl -m 5 http://m1/`, toujours refusé aussitôt. Et
que le reste est refusé : depuis `m1`, `curl -m 5 http://m3:{open}/` et `curl -m 5 http://ext2/`.
C'est le jeu de règles final qui est évalué : une chaîne `output` incomplète défait ce que
vérifient les questions précédentes.
""").format(forbidden=forbidden.ip, open=OPEN_PORT, closed=CLOSED_PORT, udp0=UDP_PORTS[0], udp1=UDP_PORTS[1])
            + tr("""
- (a) avec `drop`, depuis `m1`, `curl -m 5 http://ext2/` : @@{with_drop:>attend puis abandonne au bout du délai : le SYN est détruit avant de quitter m1, rien ne signale le blocage>>>timeout|échoue immédiatement : le noyau prévient le programme>>>refused|la page s'affiche>>>works}@@
- (b) avec `reject`, la même commande : @@{with_reject:>échoue immédiatement : le noyau fabrique un message d'erreur pour le programme>>>refused|attend puis abandonne au bout du délai>>>timeout|la page s'affiche>>>works}@@
- (c) avant la règle à états, pourquoi `ext2` n'obtient-elle plus le port 8080 de `m1` ? @@{from_forbidden:>son SYN entre (input accepte le port), mais la réponse de m1, un SYN-ACK adressé à ext2, sort par output où la règle la rejette>>>synack_rejected|la chaîne input rejette maintenant ext2>>>input_rejects|ext2 ne sait plus joindre le réseau de m1>>>no_route}@@
""")
            + instructor(tr("""
**Solution.** (a) puis (b), sur `m1` :

```
{chain}
nft add rule inet filter output ip daddr {forbidden} drop
nft flush chain inet filter output
{reject}
```

Avec `drop`, rien ne sort (`tcpdump` ne montre aucun paquet vers `ext2` : il capture après le hook
`output`) : `curl` attend ses 5 secondes (`curl: (28) Connection timed out`) et `ping` n'affiche que
`100% packet loss`. Avec `reject`, le noyau fabrique un message ICMP *port unreachable* pour le
programme : `curl` échoue aussitôt (`curl: (7) Failed to connect to ext2 port 80 … Couldn't connect
to server` ; `nc -v ext2 80` : `Connection refused`), `ping` affiche `Destination Port Unreachable`
venant de `m1` elle-même et `ping: sendmsg: Operation not permitted`. Ce message revient au
programme par l'interface `lo` : les règles `ct state established,related accept` (il est `related`)
et `iif lo accept` de `input` le laissent entrer.

(c) Le SYN de `ext2` est accepté par `input` (port {open}), mais la réponse de `m1`, un SYN-ACK
adressé à `ext2`, sort par `output` où la règle la rejette : `ext2` attend, puis abandonne. Avec

```
{stateful}
```

les paquets des connexions déjà acceptées sortent avant d'atteindre la règle `ip daddr` : il ne
reste d'interdit que ce que `m1` **initie** vers `ext2`.

(d)

```
{whitelist}```

La règle `reject` finale prévient les programmes de `m1` ; la politique `drop` n'est plus qu'un
filet de sécurité. Dans cet ordre, aucun état intermédiaire ne coupe quoi que ce soit. `related`
laisse aussi sortir les messages d'erreur que `m1` fabrique elle-même, comme le *port unreachable*
du `reject` de la question 6 : avec `ct state established accept` seul, `m2` ne serait plus
prévenue (un délai au lieu du refus immédiat : la question 6 y perd des points). Sans `oif lo
accept`, `curl http://127.0.0.1:{open}/` serait refusé. Sans la règle à états, le port {open} ne
répondrait plus à personne.

- Réponses : délai avec `drop` ; refus immédiat avec `reject` ; le SYN-ACK de `m1` est rejeté dans
  `output`.
- L'évaluation, sur la copie de `m1` : une chaîne de base du hook `output` de politique `drop` et
  sa règle `ct state established,related accept` ; `curl http://127.0.0.1:{open}/` (la règle
  `oif lo`) ; une connexion TCP vers le port {closed} de `ext2` (refusée ; un simple délai,
  c'est-à-dire un `drop`, ne donne qu'une partie des points) alors que `ext1` répond ; depuis la
  copie de `ext2`, le port {open} de `m1` (ouvert) ; une connexion vers le port {open} de `m3`
  (refusée) alors que son port {closed} répond. Une sonde lancée par `bash` ne voit le refus d'un
  `reject` local qu'à la première retransmission du SYN, une seconde plus tard (`curl` et `nc` le
  voient aussitôt) : le délai de ces sondes est de {out_timeout} s.
""").format(chain=self.net_scheme.cmds_output()[0], reject=self.net_scheme.cmds_output()[1],
            stateful=self.net_scheme.cmds_output()[2], whitelist=_lines(self.net_scheme.cmds_output()[3:]),
            forbidden=forbidden.ip, open=OPEN_PORT, closed=CLOSED_PORT, out_timeout=OUT_TIMEOUT)),
            cheat_answers={"final": q10_answers},
        )

        # what m1 must no longer open only counts when the same kind of connection still works elsewhere
        forbidden_blocked = _blocked(out_forbidden) and http_to_ext1['server'] == 'ext1'
        other_port_blocked = _blocked(out_other_port) and http_to_m3['server'] == 'm3'
        self.add_grade_element(
            title=no_tr("out_policy"), max_grade=2, grade_part=part10,
            grade=2 * out_filtering,
            description=tr("une chaîne de base du hook output avec la politique drop"),
        )
        self.add_grade_element(
            title=no_tr("out_ct_rule"), max_grade=2, grade_part=part10,
            grade=2 if out_ct_rules else int(bool(out_ct_rules_partial)),
            description=tr("output : une règle accept avec ct state established,related"),
        )
        self.add_grade_element(
            title=no_tr("out_lo"), max_grade=1, grade_part=part10,
            grade=out_filtering * int(lo_other_port['server'] == FIREWALL),
            description=tr("sur m1, curl http://127.0.0.1:{open}/ répond encore (oif lo accept)").format(open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("out_forbidden"), max_grade=3, grade_part=part10,
            grade=int(forbidden_blocked) * (2 + int(out_forbidden == 'refused')),
            description=tr("m1 n'ouvre pas de connexion vers ext2 (refus immédiat : reject), alors qu'elle joint ext1"),
        )
        self.add_grade_element(
            title=no_tr("out_replies"), max_grade=3, grade_part=part10,
            grade=3 * int(forbidden_blocked and from_forbidden),
            description=tr("ext2 obtient toujours le port {open} de m1 (règle à états avant la règle ip daddr)").format(
                open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("out_whitelist"), max_grade=3, grade_part=part10,
            grade=int(other_port_blocked) * (2 + int(out_other_port == 'refused')),
            description=tr("m1 n'ouvre pas de connexion vers le port {open} de m3 (refus immédiat : reject final), alors "
                           "qu'elle joint son port {closed}").format(open=OPEN_PORT, closed=CLOSED_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_output"), max_grade=2, grade_part=part10, scope=CHOICE_SCOPE,
            grade=int(_norm(q10.get("with_drop")) == "timeout" and _norm(q10.get("with_reject")) == "refused")
                  + int(_norm(q10.get("from_forbidden")) == "synack_rejected"),
            description=tr("drop ou reject dans output : ce que voit le programme ; pourquoi ext2 perdait le port {open}").format(
                open=OPEN_PORT),
        )

        # =====================================================================
        # Part 11 — a named set with intervals: the blocklist (question 11)
        # =====================================================================
        part11 = self.add_grade_part(no_tr("part11"), tr("Partie 11 — Ensemble nommé : une liste noire (question 11)"))

        q11_answers = {"no_interval": "refused", "rule_place": "before_accept"}
        q11 = self.question_form(
            section=self.section(0),
            title=tr("Ensembles nommés : une liste noire"),
            hash="3f46bd4c54bf6d19",
            description=tr("""
`ext3` (`{host}`) et toutes les machines du réseau `guest` (`{net}`, où se trouve `guest1`) ne
doivent plus rien obtenir de `m1`, pas même son port {open}. Plutôt qu'une règle par adresse, on
utilise un **ensemble nommé** (section @@ref:sets@@ des Informations) : une seule règle le
consulte, et l'on en modifie le contenu sans toucher à cette règle.

**(a)** Créez dans la table `inet filter` un ensemble **`{name}`** d'adresses IPv4 (`type
ipv4_addr`) portant le drapeau **`interval`**, qui lui permet de contenir aussi des réseaux, et
ajoutez-y l'adresse de `ext3` (`nft add element`).

**(b)** Ajoutez à la chaîne `input` une règle qui **détruit** ce qui vient d'une adresse de
l'ensemble (`ip saddr @{name} drop`). Où faut-il la placer pour que `ext3` n'atteigne plus le port
{open} ? Vérifiez depuis `ext3` (`curl -m 5 http://m1:{open}/`), puis depuis `ext1` que le port
répond toujours.

**(c)** Sans toucher à la règle, ajoutez à l'ensemble le réseau `guest` **entier** (`{net}`) et
vérifiez depuis `guest1`. Affichez l'ensemble (`nft list set inet filter {name}`) ; retirez puis
remettez un élément (`nft delete element`, `nft add element`).
""").format(host=blocked_host.ip, net=blocked_net, open=OPEN_PORT, name=BLOCK_SET)
            + tr("""
- sans le drapeau `interval`, l'ajout d'un réseau à l'ensemble : @@{no_interval:>est refusé par nft (« You must add 'flags interval' to your set declaration ») : sans ce drapeau, un ensemble ne contient que des valeurs isolées>>>refused|ajoute une à une toutes les adresses du réseau>>>expanded|n'ajoute que l'adresse du réseau>>>network_address}@@
- la règle `ip saddr @blocklist drop` doit être placée : @@{rule_place:>avant la règle qui accepte le port 8080 (nft insert rule) : la première règle satisfaite décide>>>before_accept|en fin de chaîne (nft add rule)>>>at_end|n'importe où : un drop l'emporte toujours sur un accept>>>anywhere}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`nft insert rule` place la règle en tête de chaîne, donc avant `tcp dport {open} accept` ; ajoutée
en fin de chaîne (`nft add rule`), elle viendrait après `jump logdrop` et ne verrait jamais un
paquet. Le contenu de l'ensemble se modifie ensuite sans toucher à la règle (`nft list set inet
filter {name}` affiche `elements = {{ {host}, {net} }}`). Sans `flags interval`, l'ajout du réseau
est refusé : `Error: You must add 'flags interval' to your set declaration if you want to add
prefix elements` ; et les drapeaux ne se changent pas après coup (`nft add set` : *File exists*) :
il faut supprimer la règle, puis l'ensemble (*Device or resource busy* tant qu'une règle le
consulte), et les recréer. Placée en tête, avant la règle à états, la règle détruit aussi les
**réponses** de `ext3` et de `guest1` : `m1` ne peut plus les joindre non plus.

- Réponses : refusé sans `flags interval` ; avant la règle qui accepte le port {open}.
- L'évaluation : dans `input`, une règle `drop` sur `ip saddr @ensemble` placée avant la règle
  `tcp dport {open} accept`, l'ensemble contenant `{host}` et tout `{net}` ; depuis les copies de
  `ext3` et de `guest1`, le port {open} de `m1` ne répond pas, alors qu'il répond à `ext1`.
""").format(cmds=_lines(self.net_scheme.cmds_blocklist()), open=OPEN_PORT, name=BLOCK_SET, host=blocked_host.ip,
            net=blocked_net)),
            cheat_answers={"final": q11_answers},
        )

        # the witness of the blocked probes: the port still answers a machine that is not in the set
        witness_open = open_from[ext1_h]
        self.add_grade_element(
            title=no_tr("blocklist_rule"), max_grade=2, grade_part=part11,
            grade=int(block_index is not None)
                  + int(block_index is not None and open_index is not None and block_index < open_index),
            description=tr("input : une règle drop sur ip saddr @ensemble, avant la règle qui accepte le port {open}").format(
                open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("blocklist_elements"), max_grade=1, grade_part=part11,
            grade=int(block_covers),
            description=tr("l'ensemble contient l'adresse de ext3 et tout le réseau guest (flags interval)"),
        )
        self.add_grade_element(
            title=no_tr("blocklist_host"), max_grade=2, grade_part=part11,
            grade=2 * int(witness_open and _blocked(verdict_blocked_host)),
            description=tr("ext3 n'obtient plus le port {open} de m1, alors que ext1 l'obtient").format(open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("blocklist_net"), max_grade=2, grade_part=part11,
            grade=2 * int(witness_open and _blocked(verdict_blocked_net)),
            description=tr("guest1 n'obtient plus le port {open} de m1, alors que ext1 l'obtient").format(open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_blocklist"), max_grade=2, grade_part=part11, scope=CHOICE_SCOPE,
            grade=int(_norm(q11.get("no_interval")) == "refused") + int(_norm(q11.get("rule_place")) == "before_accept"),
            description=tr("un réseau dans un ensemble (flags interval) ; la place de la règle qui le consulte"),
        )

        # =====================================================================
        # Part 12 — a set of ports looked up by the output chain (question 12)
        # =====================================================================
        part12 = self.add_grade_part(no_tr("part12"), tr("Partie 12 — Ensemble de ports (question 12)"))

        q12_answers = {"rules_changed": "element_only"}
        q12 = self.question_form(
            section=self.section(0),
            title=tr("Un ensemble de ports pour la sortie"),
            hash="0c64c797fab9a9ee",
            description=tr("""
Un ensemble ne contient pas forcément des adresses. Toutes les machines servent aussi leur page de
test sur le port TCP **{set_port}**, que la chaîne `output` de `m1` refuse pour l'instant (depuis
`m1` : `curl -m 5 http://m3:{set_port}/`).

**(a)** Créez un ensemble **`{name}`** de ports (`type inet_service`) contenant le port {closed},
puis **remplacez**, dans la chaîne `output`, la règle `tcp dport {closed} accept` par `tcp dport
@{name} accept` : `nft -a list chain inet filter output` donne le handle de la règle, `nft replace
rule inet filter output handle N …` la remplace sur place (section @@ref:nft-edit@@ des
Informations). Rien ne doit avoir changé : `curl -m 3 http://m3/` répond, `curl -m 5
http://m3:{set_port}/` et `curl -m 5 http://m3:{open}/` sont refusés.

**(b)** Autorisez maintenant le port {set_port} **sans toucher aux règles**, en ajoutant un élément
à l'ensemble. Vérifiez : `curl -m 3 http://m3:{set_port}/` répond, `curl -m 5 http://m3:{open}/`
est toujours refusé.
""").format(set_port=SET_PORT, closed=CLOSED_PORT, open=OPEN_PORT, name=PORT_SET)
            + tr("""
- pour autoriser le port 8888, il a fallu modifier : @@{rules_changed:>seulement le contenu de l'ensemble (nft add element) : la règle qui le consulte n'a pas changé>>>element_only|la règle de la chaîne output, remplacée une seconde fois>>>rule|toute la chaîne output, vidée puis réécrite>>>whole_chain}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

La troisième commande lit elle-même le handle de la règle à remplacer ; à la main : `nft -a list
chain inet filter output` (`tcp dport {closed} accept # handle N`), puis `nft replace rule inet
filter output handle N tcp dport @{name} accept`. La règle garde sa place et son handle. Le port
{set_port} s'ouvre ensuite par `nft add element` seul : `nft list set inet filter {name}` affiche
`elements = {{ {closed}, {set_port} }}`.

- Réponse : seulement le contenu de l'ensemble.
- L'évaluation : dans `output`, une règle `accept` sur `tcp dport @ensemble`, l'ensemble contenant
  les ports {closed} et {set_port} ; depuis la copie de `m1`, `curl http://m3:{set_port}/` répond
  (sous la politique `drop` de `output`). Une règle `tcp dport {closed} accept` restée en place ne
  coûte rien.
""").format(cmds=_lines(self.net_scheme.cmds_port_set()), closed=CLOSED_PORT, set_port=SET_PORT, name=PORT_SET)),
            cheat_answers={"final": q12_answers},
        )

        self.add_grade_element(
            title=no_tr("port_set"), max_grade=2, grade_part=part12,
            grade=int(port_rule) + int(port_rule and port_set_full),
            description=tr("output : une règle accept sur tcp dport @ensemble, l'ensemble contenant les ports {closed} et "
                           "{set_port}").format(closed=CLOSED_PORT, set_port=SET_PORT),
        )
        self.add_grade_element(
            title=no_tr("port_set_works"), max_grade=3, grade_part=part12,
            grade=3 * out_filtering * int(http_set_port['server'] == 'm3'),
            description=tr("m1 joint le port {set_port} de m3 (sous la politique drop de output)").format(set_port=SET_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_port_set"), max_grade=1, grade_part=part12, scope=CHOICE_SCOPE,
            grade=int(_norm(q12.get("rules_changed")) == "element_only"),
            description=tr("un port de plus : seul le contenu de l'ensemble change"),
        )

        # =====================================================================
        # Part 13 — a set of (address . port) pairs: the allowlist (question 13)
        # =====================================================================
        part13 = self.add_grade_part(no_tr("part13"), tr("Partie 13 — Ensemble de couples adresse . port (question 13)"))

        first_address, second_address = (address for address, _ in allowed_pairs(d))
        q13_answers = {"pair_missing": "timeout"}
        q13 = self.question_form(
            section=self.section(0),
            title=tr("Associations adresse . port : une liste blanche"),
            hash="051bad66d25f6604",
            description=tr("""
Le port {first_port} de `m1` n'est ouvert à personne, son port {second_port} non plus. On veut
ouvrir le port {first_port} à `{first}` (`{first_address}`) et le port {second_port} à `{second}`
(`{second_address}`), et rien d'autre, avec **un seul ensemble et une seule règle** : chaque
élément de l'ensemble est un couple *adresse . port* (une concaténation,
section @@ref:named-sets@@ des Informations).

**(a)** Créez l'ensemble **`{name}`** (`type ipv4_addr . inet_service`) et ajoutez-y les deux
couples : `{first_address} . {first_port}` et `{second_address} . {second_port}`.

**(b)** Ajoutez à la chaîne `input` la règle `ip saddr . tcp dport @{name} accept`. Attention à sa
place : ajoutée en fin de chaîne, elle viendrait après `jump logdrop` et ne verrait jamais un
paquet. Vérifiez : depuis `{first}`, `curl -m 3 http://m1/` répond et `curl -m 5
http://m1:{second_port}/` échoue ; depuis `{second}`, `curl -m 3 http://m1:{second_port}/` répond
et `curl -m 5 http://m1/` échoue toujours ; depuis `ext1`, les deux échouent.
""").format(first=first_machine, first_address=first_address, first_port=first_port, second=second_machine,
            second_address=second_address, second_port=second_port, name=ALLOW_SET)
            + tr("""
- depuis `ext2`, `curl -m 5 http://m1:8888/` : @@{pair_missing:>attend puis abandonne : le couple (ext2, 8888) n'est pas dans l'ensemble, seul (ext2, 80) y est ; le paquet finit dans logdrop>>>timeout|la page s'affiche : l'adresse de ext2 est dans l'ensemble>>>works|échoue immédiatement : la règle reject de la question 6 s'applique>>>refused}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`nft insert rule` place la règle en tête ; toute place avant `jump logdrop` convient (`nft insert
rule inet filter input handle N …`, N étant le handle du saut). La règle ne vaut que pour TCP (le
critère `tcp dport`) et pour un couple **entier** : `{first}` obtient le port {first_port} mais pas
le port {second_port}, `{second}` l'inverse, `ext1` aucun des deux. La réponse de `m1` à `{first}`
sort grâce à la règle à états de la chaîne `output` (question 10) : sans elle, la règle `ip daddr`
la rejetterait.

- Réponse : délai, le couple n'est pas dans l'ensemble.
- L'évaluation : dans `input`, une règle `accept` sur `ip saddr . tcp dport @ensemble`, l'ensemble
  contenant les deux couples ; depuis la copie de `{first}`, le port {first_port} de `m1` est
  ouvert et son port {second_port} ne l'est pas ; depuis celle de `{second}`, le port
  {second_port} est ouvert ; depuis celle de `ext1`, il ne l'est pas.
""").format(cmds=_lines(self.net_scheme.cmds_allowed()), first=first_machine, first_port=first_port,
            second=second_machine, second_port=second_port)),
            cheat_answers={"final": q13_answers},
        )

        first_in, second_in = allowed_in[ALLOWED[0]], allowed_in[ALLOWED[1]]
        self.add_grade_element(
            title=no_tr("allowed_set"), max_grade=2, grade_part=part13,
            grade=int(allow_rule) + int(allow_rule and allow_full),
            description=tr("input : une règle accept sur ip saddr . tcp dport @ensemble, l'ensemble contenant les deux couples"),
        )
        self.add_grade_element(
            title=no_tr("allowed_pairs"), max_grade=4, grade_part=part13,
            grade=filtering * (2 * int(first_in) + 2 * int(second_in)),
            description=tr("{first} obtient le port {first_port} de m1, {second} son port {second_port}").format(
                first=first_machine, first_port=first_port, second=second_machine, second_port=second_port),
        )
        self.add_grade_element(
            title=no_tr("allowed_only"), max_grade=2, grade_part=part13,
            grade=filtering * (int(first_in and not other_port_in) + int(second_in and not other_machine_in)),
            description=tr("le port {second_port} de m1 reste fermé à {first} et à ext1 (couples absents de l'ensemble)").format(
                first=first_machine, second_port=second_port),
        )
        self.add_grade_element(
            title=no_tr("q_allowed"), max_grade=1, grade_part=part13, scope=CHOICE_SCOPE,
            grade=int(_norm(q13.get("pair_missing")) == "timeout"),
            description=tr("un couple absent de l'ensemble n'est pas accepté"),
        )

        # =====================================================================
        # Part 14 — bonus: a set fed by the rules, the ban (question 14)
        # =====================================================================
        part14 = self.add_grade_part(no_tr("part14"), tr("Partie 14 — Bonus : ensemble dynamique (question 14)"))

        q14_answers = {"ban_effect": "banned_then_back"}
        q14 = self.question_form(
            section=self.section(0),
            title=tr("Bonus — ensemble dynamique : bannir les curieux"),
            hash="a7b1ad1938916674",
            description=tr("""
Personne n'a de raison de se connecter au port TCP {trap} (telnet) de `m1` : celui qui essaie
explore la machine. On veut le **bannir pendant {seconds} secondes** : pendant ce temps, tout ce
qui vient de son adresse est détruit, même vers le port {open}. Ce sont les règles elles-mêmes qui
alimentent l'ensemble (section @@ref:dynamic-sets@@ des Informations).

**(a)** Créez l'ensemble **`{name}`** : `type ipv4_addr`, drapeaux `dynamic,timeout`, délai
`timeout {seconds}s`.

**(b)** Insérez en tête de la chaîne `input` la règle qui, pour un paquet TCP destiné au port
{trap}, **ajoute son adresse source à l'ensemble** puis le détruit (`tcp dport {trap} add @{name}
{{ ip saddr }} drop` : dans le shell, toute la règle entre apostrophes) ; puis, en tête elle aussi,
la règle qui détruit tout ce qui vient d'une adresse de l'ensemble (`ip saddr @{name} drop`).

**(c)** Depuis `m3` : `curl -m 3 http://m1:{open}/` (répond), `nc -v -w 2 m1 {trap}`, puis de
nouveau `curl -m 5 http://m1:{open}/`. Sur `m1`, `nft list set inet filter {name}` montre l'adresse
de `m3` et le délai qui lui reste (`expires`). Attendez une minute et recommencez.
""").format(trap=TRAP_PORT, seconds=BAN_SECONDS, open=OPEN_PORT, name=BAN_SET)
            + tr("""
- après `nc -v -w 2 m1 23` depuis `m3`, `curl -m 5 http://m1:8080/` depuis `m3` : @@{ban_effect:>échoue pendant 60 secondes, puis répond de nouveau : l'adresse de m3 est dans l'ensemble, d'où elle disparaît toute seule à la fin du délai>>>banned_then_back|répond : seul le port 23 est concerné>>>only_trap|ne répond plus jamais : il faut retirer l'adresse à la main>>>forever}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

Le second `insert` place la règle `ip saddr @{name} drop` devant la première. La tentative de `m3`
sur le port {trap} range son adresse dans l'ensemble (`elements = {{ {m3} expires 57s }}`) ; pendant
{seconds} secondes tout ce qui vient d'elle est détruit, y compris ses réponses aux requêtes de
`m1` (la règle précède la règle à états). `update @{name} {{ ip saddr }}` au lieu de `add`
relancerait le délai à chaque nouvelle tentative ; `nft flush set inet filter {name}` lève tous les
bannissements.

- Réponse : échoue pendant {seconds} secondes, puis répond de nouveau.
- L'évaluation (bonus) : une règle de `input` qui ajoute `ip saddr` à un ensemble pour `tcp dport
  {trap}`, avec un délai de {seconds} s ; une règle `drop` sur `ip saddr @ensemble` placée avant la
  règle qui accepte le port {open} ; puis, sur les copies cachées, `{source}` obtient le port {open}
  (étape {probe_step}), tente le port {trap} (étape {trap_step}), n'obtient plus le port {open}
  alors que `{spared}` l'obtient toujours (étape {ban_step}). L'ensemble est vidé sur la copie
  avant les sondes : un bannissement en cours sur `m1` ne fausse pas l'évaluation.
""").format(cmds=_lines(self.net_scheme.cmds_ban()), name=BAN_SET, trap=TRAP_PORT, seconds=BAN_SECONDS, open=OPEN_PORT,
            m3=m3.ip, source=BAN_SOURCE, spared=BAN_SPARED, probe_step=PROBE_STEP, trap_step=TRAP_STEP,
            ban_step=BAN_STEP)),
            cheat_answers={"final": q14_answers},
        )

        self.add_grade_element(
            title=no_tr("ban_set"), max_grade=1, grade_part=part14, bonus=True,
            grade=int(bool(ban_updates) and ban_timed),
            description=tr("un ensemble alimenté par une règle de input (ip saddr, tcp dport {trap}), éléments expirant "
                           "après {seconds} s").format(trap=TRAP_PORT, seconds=BAN_SECONDS),
        )
        self.add_grade_element(
            title=no_tr("ban_rules"), max_grade=2, grade_part=part14, bonus=True,
            grade=int(ban_index is not None)
                  + int(ban_index is not None and (open_index is None or ban_index < open_index)),
            description=tr("une règle drop sur ip saddr @ensemble, placée avant la règle qui accepte le port {open}").format(
                open=OPEN_PORT),
        )
        self.add_grade_element(
            title=no_tr("ban_works"), max_grade=2, grade_part=part14, bonus=True,
            grade=2 * int(ban_before and not ban_after and ban_spared),
            description=tr("après une tentative sur le port {trap}, {source} n'obtient plus le port {open} de m1 (mais "
                           "{spared} toujours)").format(trap=TRAP_PORT, source=BAN_SOURCE, open=OPEN_PORT, spared=BAN_SPARED),
        )
        self.add_grade_element(
            title=no_tr("q_ban"), max_grade=1, grade_part=part14, scope=CHOICE_SCOPE, bonus=True,
            grade=int(_norm(q14.get("ban_effect")) == "banned_then_back"),
            description=tr("un bannissement temporaire : l'élément expire de lui-même"),
        )


_TRANSLATIONS = {'en': {
    "nftables : pare-feu d'une machine": "nftables: a host firewall",
    """**Sommaire**
""": """**Contents**
""",
    "Pare-feu, Netfilter et nftables": "Firewalls, Netfilter and nftables",
    """

Un **pare-feu** (*firewall*) examine les paquets qui **entrent** dans une machine, en **sortent**
ou la **traversent**, et applique à chacun une **politique** : 

- soit le laisser passer (*accept*) ;
- soit le détruire en silence (*drop*) ; 
- soit le refuser en prévenant l'émetteur (*reject*) ;

selon des critères
comme l'interface, les adresses, le protocole, les ports ou l'état de la connexion. Un pare-feu
*de machine* (*host firewall*) protège la machine sur laquelle il tourne : c'est le sujet de ce
TP, qui filtre ce qui **entre** dans `m1`, puis ce qui en **sort**. Un pare-feu *de réseau* tourne
sur un routeur et filtre ce qui le traverse (prochain TP).

Sous Linux, tout se passe **dans le noyau**. **Netfilter** y fournit des points d'accrochage
(*hooks*) sur le trajet des paquets, le suivi de connexion (*conntrack*) et la traduction
d'adresses (NAT). **nftables** exécute, à ces points d'accrochage, les règles que lui confie la
commande **`nft`**. nftables a remplacé `iptables`, `ip6tables`, `arptables` et `ebtables` (c'est
l'outil par défaut depuis Debian 10) : une seule commande et une seule syntaxe pour IPv4, IPv6,
ARP et les ponts, un jeu de règles chargé d'un bloc, des ensembles et des dictionnaires intégrés
au langage. Sur une machine récente, la commande `iptables` n'est plus qu'un traducteur : ses
règles sont des règles nftables, que `nft list ruleset` affiche aussi (section
@@ref:from-iptables@@).

Le vocabulaire, détaillé dans les sections suivantes :

| terme | rôle |
|-------|------|
| famille | les paquets qu'une table voit : `ip` (IPv4), `ip6` (IPv6), `inet` (les deux), `arp`, `bridge`, `netdev` |
| table | un conteneur nommé, dans une famille, de chaînes, d'ensembles et de compteurs |
| chaîne de base | une liste de règles accrochée à un hook, avec une priorité et une politique par défaut |
| chaîne régulière | une liste de règles sans hook, où l'on arrive par un saut (`jump`, `goto`) |
| règle | des critères puis des actions, évalués de gauche à droite |
| verdict | ce que devient le paquet : `accept`, `drop`, `jump`… |
| ensemble, dictionnaire | des valeurs (*set*) ou des associations clé : valeur (*map*) que les règles consultent |

Les machines du TP ont nftables 1.1.3 (`nft --version`), la version de Debian 13 : c'est elle que
ce cours décrit.

**Comment lire ce cours.** Le TP en utilise l'essentiel : les hooks `input` et `output`
(section @@ref:hooks-ip@@), les tables, les chaînes et les règles (section @@ref:structure@@), les
critères (@@ref:selectors@@), les verdicts (@@ref:verdicts@@), le suivi de connexion
(@@ref:conntrack@@), le filtrage de ce qui sort (@@ref:output@@), la commande `nft`
(@@ref:nft-cli@@), la journalisation (@@ref:logging@@), les ensembles (@@ref:sets@@) et les tests
(@@ref:testing@@). Le reste (les hooks `ingress` et `egress`, les dictionnaires, la limitation de
débit, la traduction d'adresses, les bonnes pratiques) complète le tableau : vous en aurez besoin
dans les TP suivants et sur de vraies machines. Si vous connaissez déjà `iptables`, la section
@@ref:from-iptables@@ fait la correspondance entre les deux.
""": """

A **firewall** examines the packets that **enter** a machine, **leave** it or **cross** it, and
applies a **policy** to each of them:

- either let it through (*accept*);
- or destroy it silently (*drop*);
- or refuse it and notify the sender (*reject*);

according to criteria such as the interface, the addresses, the protocol, the ports or the state
of the connection. A *host firewall* protects the machine it runs on: that is the subject of this
lab, which filters what **enters** `m1`, then what **leaves** it. A *network firewall* runs on a
router and filters what crosses it (next lab).

On Linux, everything happens **in the kernel**. **Netfilter** provides hooks along the path of
the packets, connection tracking (*conntrack*) and network address translation (NAT).
**nftables** runs, at these hooks, the rules handed to it by the **`nft`** command. nftables has
replaced `iptables`, `ip6tables`, `arptables` and `ebtables` (it has been the default tool since
Debian 10): a single command and a single syntax for IPv4, IPv6, ARP and bridges, a ruleset loaded
in one go, sets and maps built into the language. On a recent machine, the `iptables` command is
only a translator: its rules are nftables rules, which `nft list ruleset` shows as well (section
@@ref:from-iptables@@).

The vocabulary, detailed in the following sections:

| term | role |
|-------|------|
| family | the packets a table sees: `ip` (IPv4), `ip6` (IPv6), `inet` (both), `arp`, `bridge`, `netdev` |
| table | a named container, in a family, of chains, sets and counters |
| base chain | a list of rules attached to a hook, with a priority and a default policy |
| regular chain | a list of rules without a hook, reached through a jump (`jump`, `goto`) |
| rule | criteria then actions, evaluated from left to right |
| verdict | what becomes of the packet: `accept`, `drop`, `jump`… |
| set, map | values (*set*) or key: value associations (*map*) that the rules look up |

The machines of the lab have nftables 1.1.3 (`nft --version`), the version of Debian 13: it is the
one this course describes.

**How to read this course.** The lab uses most of it: the `input` and `output` hooks
(section @@ref:hooks-ip@@), tables, chains and rules (section @@ref:structure@@), the
selectors (@@ref:selectors@@), the verdicts (@@ref:verdicts@@), connection tracking
(@@ref:conntrack@@), filtering what leaves (@@ref:output@@), the `nft` command
(@@ref:nft-cli@@), logging (@@ref:logging@@), sets (@@ref:sets@@) and testing
(@@ref:testing@@). The rest (the `ingress` and `egress` hooks, maps, rate limiting, address
translation, good practice) completes the picture: you will need it in the next labs and on real
machines. If you already know `iptables`, section @@ref:from-iptables@@ maps one onto the other.
""",
    "Le trajet d'un paquet : les hooks": "The path of a packet: the hooks",
    """

Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Une chaîne de base s'accroche à **un** hook :
choisir le hook, c'est choisir **quels paquets** la chaîne verra, et **à quel moment** de leur
traitement.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hooks-ip@@ Les cinq hooks de la pile IP

- **`prerouting`** : tous les paquets **reçus**, avant la décision de routage (« ce paquet est-il
  pour moi, ou à faire suivre ? ») ; c'est là que l'on change l'adresse de destination (DNAT) ;
- **`input`** : les paquets **destinés à la machine**, juste avant leur remise à un processus
  local ;
- **`forward`** : les paquets qui **traversent** la machine, reçus par une interface et routés
  vers une autre (elle doit faire office de routeur : `net.ipv4.ip_forward=1`) ;
- **`output`** : les paquets **émis par les processus de la machine** ;
- **`postrouting`** : tous les paquets qui **partent**, routés ou émis localement, juste avant
  d'être confiés à l'interface de sortie ; c'est là que l'on change l'adresse source (SNAT,
  *masquerade*).

Un paquet suit donc l'un de ces trois trajets :

| paquet | hooks traversés, dans l'ordre |
|--------|-------------------------------|
| reçu et destiné à la machine | `prerouting`, `input` |
| reçu et routé vers une autre machine | `prerouting`, `forward`, `postrouting` |
| émis par la machine | `output`, `postrouting` |

Un paquet émis par `m1` vers `m2` passe par `output` puis `postrouting` ; la réponse de `m2`
arrive par `prerouting` puis `input`. Un paquet de `m1` vers elle-même (`127.0.0.1`, ou sa propre
adresse) fait les deux trajets à la suite, à travers l'interface `lo` : `output`, `postrouting`,
puis `prerouting` et `input`. Un pare-feu qui détruit tout en `input` casse donc aussi les
communications locales. Dans ce TP, on travaille dans le hook **`input`** de `m1`, puis dans son
hook **`output`**.

### @@sec:ingress@@ Les hooks ingress et egress

Deux autres hooks sont placés **au ras de l'interface réseau**, en dehors de la pile IP. À la
différence des cinq précédents, ils sont attachés à **une interface**, que la chaîne nomme dans
sa déclaration (`device`) :

- **`ingress`** : tout ce que l'interface **reçoit**, **avant `prerouting`**, donc avant le
  réassemblage des fragments, avant le suivi de connexion et avant le routage. C'est l'endroit
  le moins coûteux pour détruire un trafic indésirable (une inondation de paquets, des adresses
  sources impossibles) : le noyau n'a encore presque rien fait du paquet. En contrepartie,
  l'état de la connexion (`ct state`) n'y est pas encore connu ;
- **`egress`** : tout ce que l'interface **émet**, **après `postrouting`** : le dernier point de
  contrôle avant le départ.

Ces deux hooks appartiennent à la famille **`netdev`**, dont les chaînes voient **toutes les
trames** de l'interface, quel que soit le protocole : IPv4 et IPv6, mais aussi ARP ou les trames
802.1Q. Le hook `ingress` existe aussi dans la famille `inet` (depuis le noyau 5.10), où il ne
voit que les paquets IPv4 et IPv6 ; `egress` (depuis le noyau 5.16) n'existe que dans la famille
`netdev`.

```
nft add table netdev filter
nft 'add chain netdev filter eth0_filter { type filter hook ingress device eth0 priority 0; }'
nft add rule netdev filter eth0_filter ip saddr 198.51.100.0/24 drop
```

### @@sec:families@@ Les hooks de chaque famille

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | les cinq mêmes |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

ARP n'est pas de l'IP : les chaînes des familles `ip`, `ip6` et `inet` ne voient jamais les
requêtes ni les réponses ARP. C'est pourquoi une politique `drop` en `input` n'empêche pas une
machine de trouver l'adresse MAC de ses voisines, ni de répondre à leurs requêtes ARP.
""": """

A **hook** is a place on the path of a packet through the kernel where Netfilter calls the chains
attached to it. A base chain is attached to **one** hook: choosing the hook means choosing
**which packets** the chain will see, and **at what point** of their processing.

```
                              +-------- local processes ---------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (per interface)          (routing)                                               (per interface)
```

### @@sec:hooks-ip@@ The five hooks of the IP stack

- **`prerouting`**: every packet **received**, before the routing decision ("is this packet for
  me, or to be forwarded?"); this is where the destination address is changed (DNAT);
- **`input`**: the packets **addressed to the machine**, just before they are delivered to a local
  process;
- **`forward`**: the packets that **cross** the machine, received on one interface and routed to
  another (the machine must act as a router: `net.ipv4.ip_forward=1`);
- **`output`**: the packets **sent by the processes of the machine**;
- **`postrouting`**: every packet **leaving**, routed or sent locally, just before it is handed to
  the outgoing interface; this is where the source address is changed (SNAT, *masquerade*).

A packet therefore follows one of these three paths:

| packet | hooks crossed, in order |
|--------|-------------------------------|
| received and addressed to the machine | `prerouting`, `input` |
| received and routed to another machine | `prerouting`, `forward`, `postrouting` |
| sent by the machine | `output`, `postrouting` |

A packet sent by `m1` to `m2` goes through `output` then `postrouting`; the reply of `m2` arrives
through `prerouting` then `input`. A packet from `m1` to itself (`127.0.0.1`, or its own address)
makes both journeys one after the other, through the `lo` interface: `output`, `postrouting`, then
`prerouting` and `input`. A firewall that drops everything in `input` therefore also breaks local
communications. In this lab, we work in the **`input`** hook of `m1`, then in its **`output`**
hook.

### @@sec:ingress@@ The ingress and egress hooks

Two other hooks are placed **right at the network interface**, outside the IP stack. Unlike the
five previous ones, they are attached to **one interface**, which the chain names in its
declaration (`device`):

- **`ingress`**: everything the interface **receives**, **before `prerouting`**, hence before
  fragment reassembly, before connection tracking and before routing. It is the cheapest place to
  drop unwanted traffic (a packet flood, impossible source addresses): the kernel has done almost
  nothing with the packet yet. On the other hand, the state of the connection (`ct state`) is not
  known there yet;
- **`egress`**: everything the interface **sends**, **after `postrouting`**: the last checkpoint
  before departure.

These two hooks belong to the **`netdev`** family, whose chains see **every frame** of the
interface, whatever the protocol: IPv4 and IPv6, but also ARP or 802.1Q frames. The `ingress` hook
also exists in the `inet` family (since kernel 5.10), where it only sees IPv4 and IPv6 packets;
`egress` (since kernel 5.16) only exists in the `netdev` family.

```
nft add table netdev filter
nft 'add chain netdev filter eth0_filter { type filter hook ingress device eth0 priority 0; }'
nft add rule netdev filter eth0_filter ip saddr 198.51.100.0/24 drop
```

### @@sec:families@@ The hooks of each family

| family | packets seen | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | the same five |
| `inet` | IPv4 and IPv6 | the same five, and `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | the frames crossing a Linux bridge | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | everything that goes through an interface | `ingress`, `egress` |

ARP is not IP: the chains of the `ip`, `ip6` and `inet` families never see ARP requests or
replies. This is why a `drop` policy in `input` does not prevent a machine from finding the MAC
address of its neighbours, nor from answering their ARP requests.
""",
    "Tables, chaînes, règles": "Tables, chains, rules",
    """

Un jeu de règles nftables (*ruleset*) est organisé en **tables**, qui contiennent des
**chaînes**, qui contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table
ni chaîne prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des chaînes
sont libres ; `filter` et `input` ne sont que des habitudes. Voici ce qu'affiche `nft list
ruleset` pour un petit pare-feu ; c'est aussi la syntaxe d'un fichier de règles
(section @@ref:nft-files@@) :

```
table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                tcp dport 22 accept
        }
}
```

### @@sec:tables@@ Les tables

Une **table** appartient à une **famille** (section @@ref:families@@), qui fixe les paquets que
ses chaînes peuvent voir et les hooks dont elles disposent. Pour filtrer, la famille **`inet`**
est le choix recommandé : les mêmes règles valent pour IPv4 et pour IPv6.

```
nft add table inet filter
```

Une machine peut avoir plusieurs tables. Chacune est un espace de noms indépendant : ses
chaînes, ses ensembles et ses compteurs ne sont connus que de ses propres règles (un saut ne sort
jamais de sa table). Un logiciel qui installe ses propres règles (Docker, par exemple) le fait
dans ses propres tables : travaillez dans la vôtre et ne touchez pas aux siennes.

### @@sec:base-chains@@ Les chaînes de base

Une **chaîne de base** est accrochée à un hook. Sa déclaration donne quatre éléments :

```
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- le **type** : `filter` (dans toutes les familles et à tous les hooks : c'est le type à utiliser
  pour filtrer), `nat` (traduction d'adresses, section @@ref:nat@@) ou `route` (au hook `output` :
  refait le routage d'un paquet émis par la machine quand une règle l'a modifié) ;
- le **hook** (section @@ref:hooks@@) ; pour `ingress` et `egress`, il est suivi de `device` et du
  nom de l'interface ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus petite
  valeur à la plus grande ;
- la **politique** par défaut, `accept` ou `drop` : le verdict appliqué aux paquets qui atteignent
  la fin de la chaîne sans qu'aucune règle n'ait tranché. Sans `policy`, c'est `accept`.

Les apostrophes protègent du shell les accolades et les points-virgules ; `nft list ruleset`
réaffiche la chaîne avec `priority filter`, le nom de la priorité 0.

Avec `policy drop`, *tout ce qui n'est pas explicitement autorisé est interdit* : c'est la bonne
façon de construire un pare-feu. `reject` n'est pas une politique possible : pour refuser par
défaut plutôt que détruire, on termine la chaîne par une règle `reject`.

### @@sec:priorities@@ Priorités et chaînes multiples

Les priorités usuelles ont un nom (dans les familles `ip`, `ip6` et `inet`) :

| nom | valeur | usage |
|-----|--------|-------|
| `raw` | -300 | avant le suivi de connexion |
| `mangle` | -150 | modification des paquets |
| `dstnat` | -100 | traduction de l'adresse de destination (hook `prerouting`) |
| `filter` | 0 | filtrage |
| `security` | 50 | modules de sécurité (SELinux) |
| `srcnat` | 100 | traduction de l'adresse source (hook `postrouting`) |

On écrit `priority filter`, `priority 0` ou une valeur relative (`priority mangle - 5`, soit
-155). Le suivi de connexion est lui-même accroché à `prerouting` et à `output` avec la priorité
-200 : une chaîne de priorité `filter` voit des paquets dont l'état (`ct state`) est déjà connu,
une chaîne de priorité `raw` passe avant lui.

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées
au même hook : un paquet les traverse **toutes**, par priorité croissante, puis continue vers
les hooks suivants de son trajet. Les deux verdicts ne sont pas symétriques :

- **`drop` est définitif** : le paquet est détruit sur-le-champ, plus aucune chaîne ne le voit ;
- **`accept` ne vaut que pour la chaîne de base en cours** : le paquet passe à la chaîne
  suivante, qui peut encore le détruire.

Un paquet n'arrive donc à destination que si **chaque** chaîne de base qu'il traverse
l'accepte, et l'on ne peut pas « rattraper » dans une table un paquet qu'une autre a détruit.

### @@sec:regular-chains@@ Les chaînes régulières

Une **chaîne régulière** (on dit aussi chaîne *nommée*) n'a ni hook, ni type, ni politique :

```
nft add chain inet filter logdrop
```

Elle ne voit que les paquets qu'une règle lui envoie, par **`jump`** ou par **`goto`**, depuis
une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump`, l'évaluation
**reprend dans la chaîne appelante**, à la règle qui suit le saut ; avec `goto`, elle n'y revient
pas (au bout d'une chaîne atteinte par `goto` depuis une chaîne de base, c'est la politique de
celle-ci qui s'applique). Les sauts s'imbriquent sur 16 niveaux au plus, et le noyau refuse un
jeu de règles qui boucle.

Les chaînes régulières servent à **factoriser** (une chaîne « journaliser puis détruire »
appelée de plusieurs endroits) et à **structurer** un grand jeu de règles (une chaîne par
service, par zone ou par interface).

### @@sec:rules@@ Les règles

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des **critères**
(section @@ref:selectors@@), puis des **actions** et, le plus souvent, un **verdict**
(section @@ref:verdicts@@).

```
nft add rule inet filter input ip saddr 192.0.2.0/24 tcp dport 22 counter accept
```

- dès qu'un critère n'est pas satisfait, l'évaluation de la règle s'arrête et le paquet passe à
  la règle suivante ;
- les règles d'une chaîne sont évaluées **dans l'ordre** ; la première règle satisfaite qui porte
  un verdict (`accept`, `drop`, `reject`) décide, et les suivantes ne sont pas consultées.
  **L'ordre des règles fait donc partie de la politique** : une règle `accept` placée après une
  règle `drop` qui couvre les mêmes paquets ne sert à rien ;
- une règle sans verdict (`counter`, `log`…) agit, puis laisse le paquet continuer vers la règle
  suivante ;
- si aucune règle ne tranche, la politique de la chaîne de base s'applique.

L'ordre des mots compte aussi à l'intérieur d'une règle : `tcp dport 22 counter accept` compte
les paquets destinés au port 22, `counter tcp dport 22 accept` tous ceux qui atteignent la règle.

Le noyau attribue à chaque règle un numéro qui ne change plus, son **handle** (`nft -a list
ruleset`) : il sert à insérer, remplacer ou supprimer une règle précise
(section @@ref:nft-edit@@). Une règle peut se terminer par un commentaire :
`comment "ssh des administrateurs"`.
""": """

An nftables ruleset is organised in **tables**, which contain **chains**, which contain
**rules**. At the start it is **empty**: nftables has no predefined table or chain, and without a
chain every packet gets through. The names of the tables and chains are free; `filter` and
`input` are only habits. Here is what `nft list ruleset` shows for a small firewall; it is also
the syntax of a rules file (section @@ref:nft-files@@):

```
table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                tcp dport 22 accept
        }
}
```

### @@sec:tables@@ Tables

A **table** belongs to a **family** (section @@ref:families@@), which sets the packets its chains
can see and the hooks available to them. For filtering, the **`inet`** family is the recommended
choice: the same rules apply to IPv4 and to IPv6.

```
nft add table inet filter
```

A machine can have several tables. Each one is an independent namespace: its chains, sets and
counters are known only to its own rules (a jump never leaves its table). A piece of software that
installs its own rules (Docker, for example) does so in its own tables: work in yours and do not
touch theirs.

### @@sec:base-chains@@ Base chains

A **base chain** is attached to a hook. Its declaration gives four elements:

```
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- the **type**: `filter` (in every family and at every hook: it is the type to use for
  filtering), `nat` (address translation, section @@ref:nat@@) or `route` (at the `output` hook:
  routes again a packet sent by the machine when a rule has modified it);
- the **hook** (section @@ref:hooks@@); for `ingress` and `egress`, it is followed by `device` and
  the name of the interface;
- the **priority**: an integer that orders the chains attached to the same hook, from the smallest
  value to the largest;
- the default **policy**, `accept` or `drop`: the verdict applied to the packets that reach the end
  of the chain without any rule having decided. Without `policy`, it is `accept`.

The single quotes protect the braces and semicolons from the shell; `nft list ruleset` shows the
chain again with `priority filter`, the name of priority 0.

With `policy drop`, *everything that is not explicitly allowed is forbidden*: that is the right
way to build a firewall. `reject` is not a possible policy: to refuse by default rather than
destroy, the chain ends with a `reject` rule.

### @@sec:priorities@@ Priorities and multiple chains

The usual priorities have a name (in the `ip`, `ip6` and `inet` families):

| name | value | use |
|-----|--------|-------|
| `raw` | -300 | before connection tracking |
| `mangle` | -150 | packet modification |
| `dstnat` | -100 | destination address translation (`prerouting` hook) |
| `filter` | 0 | filtering |
| `security` | 50 | security modules (SELinux) |
| `srcnat` | 100 | source address translation (`postrouting` hook) |

One writes `priority filter`, `priority 0` or a relative value (`priority mangle - 5`, that is
-155). Connection tracking is itself attached to `prerouting` and to `output` with priority -200:
a chain of priority `filter` sees packets whose state (`ct state`) is already known, a chain of
priority `raw` comes before it.

Several base chains, of the same table or of different tables, can be attached to the same hook:
a packet crosses **all** of them, by increasing priority, then goes on to the next hooks of its
path. The two verdicts are not symmetrical:

- **`drop` is final**: the packet is destroyed on the spot, no other chain sees it;
- **`accept` only holds for the current base chain**: the packet moves on to the next chain, which
  can still destroy it.

A packet therefore reaches its destination only if **every** base chain it crosses accepts it,
and a packet destroyed by one table cannot be "rescued" in another.

### @@sec:regular-chains@@ Regular chains

A **regular chain** (also called a *named* chain) has no hook, no type and no policy:

```
nft add chain inet filter logdrop
```

It only sees the packets a rule sends to it, through **`jump`** or **`goto`**, from another chain
of the same table. At the end of a chain reached by `jump`, evaluation **resumes in the calling
chain**, at the rule following the jump; with `goto`, it does not come back (at the end of a chain
reached by `goto` from a base chain, the policy of the base chain applies). Jumps nest 16 levels
deep at most, and the kernel refuses a ruleset that loops.

Regular chains are used to **factor out** (a "log then drop" chain called from several places)
and to **structure** a large ruleset (one chain per service, per zone or per interface).

### @@sec:rules@@ Rules

A **rule** is a sequence of expressions evaluated **from left to right**: **selectors**
(section @@ref:selectors@@), then **actions** and, most often, a **verdict**
(section @@ref:verdicts@@).

```
nft add rule inet filter input ip saddr 192.0.2.0/24 tcp dport 22 counter accept
```

- as soon as a selector does not match, the evaluation of the rule stops and the packet moves on
  to the next rule;
- the rules of a chain are evaluated **in order**; the first matching rule that carries a verdict
  (`accept`, `drop`, `reject`) decides, and the following ones are not consulted. **The order of
  the rules is therefore part of the policy**: an `accept` rule placed after a `drop` rule that
  covers the same packets is useless;
- a rule without a verdict (`counter`, `log`…) acts, then lets the packet go on to the next rule;
- if no rule decides, the policy of the base chain applies.

The order of the words also matters inside a rule: `tcp dport 22 counter accept` counts the
packets addressed to port 22, `counter tcp dport 22 accept` all those that reach the rule.

The kernel gives each rule a number that never changes, its **handle** (`nft -a list
ruleset`): it is used to insert, replace or delete a specific rule
(section @@ref:nft-edit@@). A rule can end with a comment:
`comment "ssh for the administrators"`.
""",
    "Les critères (sélecteurs)": "Selectors",
    """

Un critère compare un **champ** du paquet, ou une information que le noyau lui associe, à une
**valeur**. Plusieurs critères dans une même règle sont tous requis (un **et**) ; pour un **ou**,
on utilise un ensemble de valeurs ou plusieurs règles.

### @@sec:headers@@ Les en-têtes du paquet

| critère | signification |
|---------|---------------|
| `ip saddr 192.0.2.2`, `ip daddr 192.0.2.0/24` | adresse IPv4 source, destination (une adresse ou un réseau) |
| `ip protocol udp` | protocole transporté par un paquet IPv4 (`tcp`, `udp`, `icmp`…) |
| `ip ttl 1`, `ip length 1500`, `ip dscp ef` | autres champs de l'en-tête IPv4 |
| `ip6 saddr 2001:db8::/32`, `ip6 daddr`, `ip6 hoplimit` | en-tête IPv6 |
| `tcp dport 8080`, `tcp sport 1024-65535` | port TCP destination, source |
| `udp dport 53`, `udp sport 53` | port UDP destination, source |
| `tcp flags syn` | drapeaux TCP (voir la section @@ref:values@@) |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête `echo-request`, réponse `echo-reply`) |
| `icmpv6 type nd-neighbor-solicit` | type ICMPv6 |
| `ether saddr 02:00:00:00:00:01` | adresse MAC source de la trame |
| `ct state established,related` | état de la connexion dans le suivi de connexion (section @@ref:conntrack@@) |

### @@sec:meta@@ Les informations associées au paquet

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | interface d'**entrée** (aux hooks `prerouting`, `input` et `forward`) |
| `oif eth0`, `oifname "eth0"` | interface de **sortie** (aux hooks `forward`, `output` et `postrouting`) |
| `meta l4proto udp` | protocole de niveau 4, en IPv4 comme en IPv6 |
| `meta nfproto ipv4` | version d'IP du paquet (`ipv4`, `ipv6`), utile dans une table `inet` |
| `meta pkttype broadcast` | paquet adressé à la machine (`host`), diffusé (`broadcast`) ou multidiffusé (`multicast`) |
| `meta mark 1` | marque posée sur le paquet par une autre règle (`meta mark set 1`) |
| `meta skuid 1000` | utilisateur propriétaire du processus qui émet le paquet (au hook `output`) |

**`iif` ou `iifname` ?** `iif lo` compare le **numéro** (l'index) de l'interface : c'est rapide,
mais l'interface doit exister quand la règle est chargée, et la règle ne suit pas une interface
supprimée puis recréée. `iifname "eth0"` compare le **nom** : un peu plus lent, mais valable pour
une interface qui n'existe pas encore (un VPN, une connexion à la demande), et le nom peut se
terminer par un joker (`iifname "eth*"`). Pour `lo` et les interfaces permanentes, `iif` convient.

### @@sec:values@@ Les formes de valeur

| forme | exemples |
|-------|----------|
| une valeur | `tcp dport 22`, `ip saddr 192.0.2.2` |
| un réseau | `ip saddr 192.0.2.0/24` |
| une plage | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| un ensemble | `tcp dport { 22, 80, 443 }`, `ip saddr { 192.0.2.2, 198.51.100.0/24 }` |
| un ensemble nommé | `ip saddr @blocklist` (section @@ref:sets@@) |
| la négation | `ip saddr != 192.0.2.2`, `tcp dport != { 22, 80 }` |
| une comparaison | `ip ttl lt 5`, `meta length gt 1000` (`lt` : inférieur à, `gt` : supérieur à) |

Un port peut être donné par le nom de son service (`tcp dport ssh`) ; `nft list ruleset` le
réaffiche en chiffres.

Pour un champ de **drapeaux** comme `tcp flags`, `tcp flags syn` signifie « le drapeau SYN est
positionné », quels que soient les autres : le critère vaut pour le SYN qui ouvre une connexion
comme pour le SYN-ACK qui lui répond. Pour désigner le SYN seul, on précise les drapeaux
examinés : `tcp flags & (fin|syn|rst|ack) == syn` (« parmi FIN, SYN, RST et ACK, seul SYN est
positionné »). `ct state established,related` se lit de la même façon : l'état est `established`
**ou** `related`.

### @@sec:implicit@@ Protocoles implicites et famille inet

Nommer un champ implique le protocole qui le porte : `tcp dport 8080` ne concerne que TCP,
`icmp type echo-reply` que ICMP ; inutile d'ajouter `ip protocol tcp`. Dans une table `inet` :

- `tcp dport 22 accept` vaut pour IPv4 **et** pour IPv6 ;
- un critère `ip …` (`ip saddr`, `ip protocol`…) restreint la règle à IPv4, un critère `ip6 …`
  à IPv6 ;
- `icmp` désigne l'ICMP d'IPv4 ; celui d'IPv6 s'écrit `icmpv6` ;
- `meta l4proto udp` désigne UDP dans les deux versions d'IP, `ip protocol udp` en IPv4 seulement.

`nft describe` donne le type d'un champ et ses valeurs possibles : `nft describe icmp type`,
`nft describe tcp flags`, `nft describe ct state`.
""": """

A selector compares a **field** of the packet, or a piece of information the kernel associates
with it, with a **value**. Several selectors in the same rule are all required (an **and**); for
an **or**, use a set of values or several rules.

### @@sec:headers@@ The packet headers

| selector | meaning |
|---------|---------------|
| `ip saddr 192.0.2.2`, `ip daddr 192.0.2.0/24` | IPv4 source, destination address (an address or a network) |
| `ip protocol udp` | protocol carried by an IPv4 packet (`tcp`, `udp`, `icmp`…) |
| `ip ttl 1`, `ip length 1500`, `ip dscp ef` | other fields of the IPv4 header |
| `ip6 saddr 2001:db8::/32`, `ip6 daddr`, `ip6 hoplimit` | IPv6 header |
| `tcp dport 8080`, `tcp sport 1024-65535` | TCP destination, source port |
| `udp dport 53`, `udp sport 53` | UDP destination, source port |
| `tcp flags syn` | TCP flags (see section @@ref:values@@) |
| `icmp type echo-request`, `icmp type echo-reply` | ICMP type (`ping`: request `echo-request`, reply `echo-reply`) |
| `icmpv6 type nd-neighbor-solicit` | ICMPv6 type |
| `ether saddr 02:00:00:00:00:01` | source MAC address of the frame |
| `ct state established,related` | state of the connection in connection tracking (section @@ref:conntrack@@) |

### @@sec:meta@@ The information associated with the packet

| selector | meaning |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | **input** interface (at the `prerouting`, `input` and `forward` hooks) |
| `oif eth0`, `oifname "eth0"` | **output** interface (at the `forward`, `output` and `postrouting` hooks) |
| `meta l4proto udp` | layer 4 protocol, in IPv4 as in IPv6 |
| `meta nfproto ipv4` | IP version of the packet (`ipv4`, `ipv6`), useful in an `inet` table |
| `meta pkttype broadcast` | packet addressed to the machine (`host`), broadcast (`broadcast`) or multicast (`multicast`) |
| `meta mark 1` | mark set on the packet by another rule (`meta mark set 1`) |
| `meta skuid 1000` | user owning the process that sends the packet (at the `output` hook) |

**`iif` or `iifname`?** `iif lo` compares the **number** (the index) of the interface: it is fast,
but the interface must exist when the rule is loaded, and the rule does not follow an interface
that is deleted then created again. `iifname "eth0"` compares the **name**: a little slower, but
valid for an interface that does not exist yet (a VPN, an on-demand connection), and the name can
end with a wildcard (`iifname "eth*"`). For `lo` and permanent interfaces, `iif` is fine.

### @@sec:values@@ Forms of value

| form | examples |
|-------|----------|
| a value | `tcp dport 22`, `ip saddr 192.0.2.2` |
| a network | `ip saddr 192.0.2.0/24` |
| a range | `tcp dport 8000-8100`, `ip saddr 192.0.2.10-192.0.2.20` |
| a set | `tcp dport { 22, 80, 443 }`, `ip saddr { 192.0.2.2, 198.51.100.0/24 }` |
| a named set | `ip saddr @blocklist` (section @@ref:sets@@) |
| negation | `ip saddr != 192.0.2.2`, `tcp dport != { 22, 80 }` |
| a comparison | `ip ttl lt 5`, `meta length gt 1000` (`lt`: less than, `gt`: greater than) |

A port can be given by the name of its service (`tcp dport ssh`); `nft list ruleset` shows it
again as a number.

For a **flags** field such as `tcp flags`, `tcp flags syn` means "the SYN flag is set", whatever
the others: the selector matches the SYN that opens a connection as well as the SYN-ACK that
answers it. To designate the SYN alone, specify the flags examined:
`tcp flags & (fin|syn|rst|ack) == syn` ("among FIN, SYN, RST and ACK, only SYN is set").
`ct state established,related` reads the same way: the state is `established` **or** `related`.

### @@sec:implicit@@ Implicit protocols and the inet family

Naming a field implies the protocol that carries it: `tcp dport 8080` only concerns TCP,
`icmp type echo-reply` only ICMP; there is no need to add `ip protocol tcp`. In an `inet` table:

- `tcp dport 22 accept` applies to IPv4 **and** to IPv6;
- an `ip …` selector (`ip saddr`, `ip protocol`…) restricts the rule to IPv4, an `ip6 …` selector
  to IPv6;
- `icmp` designates the ICMP of IPv4; that of IPv6 is written `icmpv6`;
- `meta l4proto udp` designates UDP in both IP versions, `ip protocol udp` in IPv4 only.

`nft describe` gives the type of a field and its possible values: `nft describe icmp type`,
`nft describe tcp flags`, `nft describe ct state`.
""",
    "Verdicts et actions": "Verdicts and actions",
    """

### @@sec:verdict-list@@ Les verdicts

- **`accept`** : le paquet passe ; l'évaluation de la chaîne de base s'arrête (il reste soumis
  aux autres chaînes de son trajet, section @@ref:priorities@@) ;
- **`drop`** : le paquet est détruit **sans rien dire** : l'émetteur attend, réessaie, puis
  renonce (délai d'attente, *timeout*) ;
- **`reject`** : le paquet est détruit et l'émetteur est **prévenu** par un message d'erreur
  (section @@ref:reject@@) ;
- **`jump chaine`** : évalue la chaîne régulière, et revient si elle ne tranche pas ; **`goto
  chaine`** y va sans retour (section @@ref:regular-chains@@) ;
- **`return`** : quitte la chaîne en cours et reprend dans la chaîne appelante ; dans une chaîne
  de base, applique la politique ;
- **`continue`** : passe à la règle suivante ; c'est le verdict implicite d'une règle qui n'en
  porte pas ;
- **`queue`** : confie le paquet à un programme (un système de détection d'intrusion, par
  exemple), qui rendra le verdict.

### @@sec:reject@@ reject : refuser en prévenant

Sans précision, `reject` répond par un message ICMP *port unreachable* ; `nft list ruleset`
affiche alors la règle sous sa forme complète (`reject with icmp port-unreachable`, ou `icmpx`
dans une table `inet` quand la règle ne dit pas la version d'IP). On peut choisir la réponse :

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | ICMP *port unreachable* |
| `reject with tcp reset` | un segment TCP RST : ce que répond une machine sans pare-feu dont le port est fermé (TCP seulement) |
| `reject with icmp host-unreachable` | ICMP *host unreachable* ; autres codes : `net-unreachable`, `prot-unreachable`, `admin-prohibited`… |
| `reject with icmpx admin-prohibited` | dans une table `inet` : l'erreur « interdit par l'administrateur » en ICMP ou en ICMPv6, selon le paquet |

Côté client, l'erreur est **immédiate** au lieu d'un long délai : `Connection refused` avec la
réponse par défaut ou un RST, `No route to host` avec `host-unreachable` ou `admin-prohibited`.

### @@sec:statements@@ Les actions sans verdict

Ces actions font leur travail puis laissent le paquet continuer, dans la même règle puis vers la
règle suivante :

| action | effet |
|--------|-------|
| `counter` | compte les paquets et les octets qui atteignent cet endroit de la règle (section @@ref:logging@@) |
| `log` | journalise le paquet (section @@ref:logging@@) |
| `limit rate 5/minute` | ne laisse la règle se poursuivre qu'à ce rythme ; au-delà, le paquet passe à la règle suivante (section @@ref:limits@@) |
| `meta mark set 1` | pose une marque sur le paquet, qu'une autre règle ou le routage (`ip rule`) retrouvera |
| `notrack` | soustrait le paquet au suivi de connexion (dans une chaîne de priorité `raw`) |
| `meta nftrace set 1` | trace le paquet à travers le jeu de règles (section @@ref:testing@@) |

Elles se combinent, dans l'ordre où elles sont écrites : `limit rate 5/minute log prefix "x: "`
journalise au plus cinq paquets par minute ; `counter drop` compte puis détruit.

### @@sec:drop-or-reject@@ Détruire ou refuser ?

`drop` ne révèle rien à un attaquant, pas même l'existence de la machine, et ne coûte rien ;
`reject` est plus agréable pour les utilisateurs légitimes et pour le diagnostic, puisque
l'erreur est immédiate. L'usage : on détruit ce qui vient de l'extérieur, on refuse souvent ce
qui vient de l'intérieur.
""": """

### @@sec:verdict-list@@ Verdicts

- **`accept`**: the packet gets through; the evaluation of the base chain stops (the packet is
  still subject to the other chains of its path, section @@ref:priorities@@);
- **`drop`**: the packet is destroyed **without a word**: the sender waits, tries again, then
  gives up (*timeout*);
- **`reject`**: the packet is destroyed and the sender is **notified** by an error message
  (section @@ref:reject@@);
- **`jump chain`**: evaluates the regular chain, and comes back if it does not decide; **`goto
  chain`** goes there with no return (section @@ref:regular-chains@@);
- **`return`**: leaves the current chain and resumes in the calling chain; in a base chain,
  applies the policy;
- **`continue`**: moves on to the next rule; it is the implicit verdict of a rule that carries
  none;
- **`queue`**: hands the packet over to a program (an intrusion detection system, for example),
  which will give the verdict.

### @@sec:reject@@ reject: refusing with notice

Without anything more, `reject` answers with an ICMP *port unreachable* message; `nft list
ruleset` then shows the rule in its full form (`reject with icmp port-unreachable`, or `icmpx` in
an `inet` table when the rule does not state the IP version). The answer can be chosen:

| rule | answer sent to the sender |
|-------|------------------------------|
| `reject` | ICMP *port unreachable* |
| `reject with tcp reset` | a TCP RST segment: what a machine without a firewall answers when the port is closed (TCP only) |
| `reject with icmp host-unreachable` | ICMP *host unreachable*; other codes: `net-unreachable`, `prot-unreachable`, `admin-prohibited`… |
| `reject with icmpx admin-prohibited` | in an `inet` table: the "administratively prohibited" error in ICMP or in ICMPv6, depending on the packet |

On the client side, the error is **immediate** instead of a long delay: `Connection refused` with
the default answer or a RST, `No route to host` with `host-unreachable` or `admin-prohibited`.

### @@sec:statements@@ Actions without a verdict

These actions do their job then let the packet go on, in the same rule then to the next rule:

| action | effect |
|--------|-------|
| `counter` | counts the packets and bytes that reach this point of the rule (section @@ref:logging@@) |
| `log` | logs the packet (section @@ref:logging@@) |
| `limit rate 5/minute` | lets the rule go on only at this rate; beyond it, the packet moves on to the next rule (section @@ref:limits@@) |
| `meta mark set 1` | sets a mark on the packet, which another rule or routing (`ip rule`) will find |
| `notrack` | removes the packet from connection tracking (in a chain of priority `raw`) |
| `meta nftrace set 1` | traces the packet through the ruleset (section @@ref:testing@@) |

They combine, in the order in which they are written: `limit rate 5/minute log prefix "x: "`
logs at most five packets per minute; `counter drop` counts then destroys.

### @@sec:drop-or-reject@@ Drop or reject?

`drop` reveals nothing to an attacker, not even the existence of the machine, and costs nothing;
`reject` is more pleasant for legitimate users and for troubleshooting, since the error is
immediate. Common practice: drop what comes from outside, often reject what comes from inside.
""",
    "Le suivi de connexion : filtrage à états": "Connection tracking: stateful filtering",
    """

Netfilter mémorise les **connexions** en cours (*connection tracking*, ou *conntrack*) : une
connexion TCP, mais aussi un « échange » UDP (des datagrammes entre les mêmes adresses et les
mêmes ports) ou ICMP (une requête `echo-request` et sa réponse). Le suivi ne filtre rien : il
**étiquette** chaque paquet d'un **état**, que les règles testent avec `ct state`.

### @@sec:ct-states@@ Les états

- **`new`** : le paquet ouvre une connexion, ou appartient à une connexion dont on n'a encore vu
  qu'**un seul sens** (le SYN en TCP, la première requête UDP et ses répétitions) ;
- **`established`** : le paquet appartient à une connexion dont on a vu des paquets **dans les
  deux sens**. La toute première réponse (le SYN-ACK, la réponse d'un serveur UDP,
  l'`echo-reply`) est déjà dans cet état, comme tout ce qui suit, dans un sens et dans l'autre ;
- **`related`** : le paquet n'appartient pas à une connexion connue, mais il est **lié** à l'une
  d'elles : une erreur ICMP qui la concerne (*port unreachable*, *fragmentation needed*, *time
  exceeded*), ou la connexion de données d'un protocole comme FTP (avec un module d'assistance) ;
- **`invalid`** : le paquet ne correspond à rien de connu et ne peut pas ouvrir de connexion
  (segment TCP incohérent ou hors séquence, erreur ICMP sans connexion…) ;
- **`untracked`** : le paquet a été soustrait au suivi par une règle `notrack`.

Une connexion est enregistrée par son premier paquet, à condition que le pare-feu l'accepte : un
paquet `new` détruit ne laisse aucune trace. Elle est oubliée après un temps d'inactivité : 30
secondes pour un échange UDP ou ICMP resté sans suite (120 secondes pour un flux UDP établi), 5
jours pour une connexion TCP établie, bien moins pendant son ouverture et après sa fermeture.

### @@sec:stateful-rule@@ La règle à états

```
nft insert rule inet filter input ct state established,related accept
```

Placée en **première position**, cette règle accepte d'un coup tout le trafic retour des
communications que la machine a elle-même initiées, et la suite des connexions entrantes déjà
acceptées : il ne reste à autoriser explicitement que les **nouvelles** connexions que l'on veut
servir. Comme presque tous les paquets que reçoit une machine appartiennent à une connexion
établie, la plupart ne consultent que cette règle.

Sans elle, il faut ouvrir à l'aveugle tout ce qui ressemble à une réponse (« tout l'UDP venant du
serveur », par exemple), ce qui laisse aussi passer les requêtes de ce serveur vers la machine :
un filtre **sans état** (*stateless*) ne distingue pas le sens d'un échange.

`ct state invalid drop` complète souvent la règle à états ; les deux s'écrivent aussi en une
seule règle, avec un dictionnaire de verdicts (section @@ref:maps@@) :
`ct state vmap { established : accept, related : accept, invalid : drop }`.

### @@sec:ct-table@@ Observer et régler le suivi

`conntrack -L` (paquet `conntrack`, s'il est installé) affiche la table des connexions suivies,
`conntrack -E` les créations et les suppressions en direct. La taille de la table est bornée
(`sysctl net.netfilter.nf_conntrack_max`) : quand elle est pleine, les nouvelles connexions sont
détruites. On soustrait au suivi un trafic très abondant qui n'en a pas besoin avec `notrack`,
dans une chaîne de priorité `raw` aux hooks `prerouting` et `output` ; ses paquets sont alors
`untracked`, et la règle à états ne les accepte pas.
""": """

Netfilter remembers the ongoing **connections** (*connection tracking*, or *conntrack*): a TCP
connection, but also a UDP "exchange" (datagrams between the same addresses and the same ports)
or an ICMP one (an `echo-request` and its reply). Tracking filters nothing: it **labels** each
packet with a **state**, which the rules test with `ct state`.

### @@sec:ct-states@@ The states

- **`new`**: the packet opens a connection, or belongs to a connection of which only **one
  direction** has been seen so far (the SYN in TCP, the first UDP request and its repetitions);
- **`established`**: the packet belongs to a connection whose packets have been seen **in both
  directions**. The very first reply (the SYN-ACK, the answer of a UDP server, the `echo-reply`)
  is already in this state, like everything that follows, in either direction;
- **`related`**: the packet does not belong to a known connection, but it is **related** to one of
  them: an ICMP error about it (*port unreachable*, *fragmentation needed*, *time exceeded*), or
  the data connection of a protocol such as FTP (with a helper module);
- **`invalid`**: the packet matches nothing known and cannot open a connection (inconsistent or
  out-of-sequence TCP segment, ICMP error without a connection…);
- **`untracked`**: the packet has been removed from tracking by a `notrack` rule.

A connection is recorded by its first packet, provided the firewall accepts it: a `new` packet
that is dropped leaves no trace. It is forgotten after a period of inactivity: 30 seconds for a
UDP or ICMP exchange left unanswered (120 seconds for an established UDP flow), 5 days for an
established TCP connection, much less while it is being opened and after it is closed.

### @@sec:stateful-rule@@ The stateful rule

```
nft insert rule inet filter input ct state established,related accept
```

Placed in **first position**, this rule accepts at once all the return traffic of the
communications the machine itself has initiated, and the rest of the incoming connections already
accepted: all that remains to allow explicitly are the **new** connections one wants to serve.
Since almost all the packets a machine receives belong to an established connection, most of
them only consult this rule.

Without it, one has to open blindly everything that looks like a reply ("all the UDP coming from
the server", for example), which also lets through the requests of that server to the machine: a
**stateless** filter does not tell the direction of an exchange.

`ct state invalid drop` often complements the stateful rule; both can also be written as a single
rule, with a verdict map (section @@ref:maps@@):
`ct state vmap { established : accept, related : accept, invalid : drop }`.

### @@sec:ct-table@@ Observing and tuning tracking

`conntrack -L` (package `conntrack`, if installed) shows the table of tracked connections,
`conntrack -E` the creations and deletions live. The size of the table is bounded
(`sysctl net.netfilter.nf_conntrack_max`): when it is full, new connections are dropped. A very
heavy traffic that does not need tracking is removed from it with `notrack`, in a chain of
priority `raw` at the `prerouting` and `output` hooks; its packets are then `untracked`, and the
stateful rule does not accept them.
""",
    "Filtrer ce qui sort : la chaîne output": "Filtering what leaves: the output chain",
    """

Une chaîne de base accrochée au hook **`output`** voit tous les paquets que **la machine
elle-même** émet : ceux des connexions que ses programmes ouvrent, mais aussi ses **réponses** aux
connexions qu'elle sert et les messages d'erreur que son noyau fabrique. Elle ne voit pas les
paquets qui traversent un routeur (hook `forward`).

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
```

### @@sec:why-output@@ Pourquoi filtrer la sortie

Filtrer `input` protège la machine des autres ; filtrer `output` protège les autres de la
machine, et limite les dégâts si elle est compromise : un programme malveillant qui ne peut ni
appeler son serveur de commande, ni envoyer de courrier, ni explorer le réseau est bien moins
dangereux. C'est aussi le moyen d'imposer une règle d'usage (« ce serveur ne parle qu'à sa base de
données et aux dépôts de mise à jour »). Les critères utiles sont l'adresse et le port de
**destination** (`ip daddr`, `tcp dport`), l'interface de **sortie** (`oif`, `oifname`) et, propre
à ce hook, l'utilisateur du programme qui émet (section @@ref:skuid@@).

### @@sec:output-view@@ Ce que voit le programme

Dans la chaîne `output`, le paquet est arrêté sur la machine même qui l'émet, et la différence
entre `drop` et `reject` se voit dans le programme :

| programme | avec `drop` | avec `reject` |
|-----------|-------------|---------------|
| `curl` | attend son délai : `curl: (28) Connection timed out` | échec immédiat : `curl: (7) Failed to connect … Couldn't connect to server` |
| `nc -v` | attend son délai : `timed out: Operation now in progress` | échec immédiat : `Connection refused` |
| `ping` | `100% packet loss`, sans autre message | `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` |

Avec `drop`, rien ne signale le blocage : vu du programme, il ressemble à une panne du réseau ou
du serveur distant. En `output`, on préfère donc **`reject`** : celui qui est bloqué est un
utilisateur de la machine, autant qu'il le sache aussitôt. Dans les deux cas `tcpdump` ne montre
aucun paquet : il capture après le hook `output` (section @@ref:capture@@).

Le message d'erreur d'un `reject` est fabriqué par le noyau et **revient au programme par
l'interface `lo`** : la chaîne `input` de la machine doit le laisser entrer, par `iif lo accept`
ou par la règle à états (ce message est `related`). Sinon le programme attend, comme avec `drop`.

### @@sec:output-state@@ Les réponses : la règle à états en sortie

Une règle de `output` ne distingue pas, à elle seule, ce que la machine **initie** de ce qu'elle
**répond**. `ip daddr 192.0.2.7 reject` interdit d'ouvrir une connexion vers `192.0.2.7`, mais
rejette aussi les réponses de la machine aux connexions que `192.0.2.7` ouvre vers elle : ses SYN
entrent, les SYN-ACK ne sortent pas, et le service paraît en panne. Comme en `input`, la règle à
états placée **en tête** règle la question :

```
nft insert rule inet filter output ct state established,related accept
```

- `established` : les paquets des connexions déjà acceptées, dans un sens ou dans l'autre, donc
  toutes les réponses de la machine à ce que sa chaîne `input` a laissé entrer ;
- `related` : les messages d'erreur ICMP que la machine émet elle-même à propos d'une connexion,
  par exemple le *port unreachable* d'une règle `reject` de sa chaîne `input`. Sans `related`,
  ces messages ne sortent plus : l'émetteur n'est plus prévenu et attend, comme avec `drop`.

Les règles suivantes ne voient alors que des paquets `new` : ce que la machine initie.

### @@sec:output-policies@@ Interdire quelques destinations, ou tout interdire sauf…

Deux façons d'écrire la chaîne `output` :

- **tout autoriser, sauf…** : politique `accept` et une règle `reject` par destination ou par
  service interdit. C'est la forme d'un poste de travail ;
- **tout interdire, sauf…** : une règle par flux sortant autorisé, et tout le reste est refusé.
  C'est la forme d'un serveur que l'on veut cloisonner. Il faut alors penser à tout ce que la
  machine émet sans qu'on le voie : ses réponses et ses messages d'erreur (la règle à états), ses
  échanges avec elle-même (`oif lo accept` : beaucoup de programmes se parlent par `127.0.0.1`),
  ses requêtes DNS, ses mises à jour.

```
table inet filter {
        chain output {
                type filter hook output priority filter; policy drop;
                ct state established,related accept
                oif "lo" accept
                icmp type echo-request accept
                udp dport 53 accept
                tcp dport { 80, 443 } accept
                reject
        }
}
```

La règle **`reject` finale**, sans critère, prévient les programmes de la machine ; la politique
`drop` n'est plus qu'un filet de sécurité. Pour passer une chaîne existante de `accept` à `drop`
sans rien couper, on ajoute **d'abord** les règles qui autorisent et l'on change la politique
**en dernier** (section @@ref:nft-edit@@).

### @@sec:skuid@@ Filtrer par utilisateur

Au hook `output`, le noyau connaît le programme qui émet le paquet : `meta skuid` compare
l'utilisateur propriétaire de sa prise réseau (*socket*), `meta skgid` son groupe.

```
nft add rule inet filter output meta skuid "www-data" tcp dport 5432 accept
nft add rule inet filter output tcp dport 5432 reject
```

Seul le serveur web (l'utilisateur `www-data`) joint ici la base de données ; les autres
utilisateurs de la machine sont refusés. Ce critère ne concerne que les paquets émis par la
machine elle-même.
""": """

A base chain attached to the **`output`** hook sees all the packets that **the machine itself**
sends: those of the connections its programs open, but also its **replies** to the connections it
serves and the error messages its kernel builds. It does not see the packets that cross a router
(`forward` hook).

```
nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'
```

### @@sec:why-output@@ Why filter what leaves

Filtering `input` protects the machine from the others; filtering `output` protects the others
from the machine, and limits the damage if it is compromised: a malicious program that can neither
call its command server, nor send mail, nor explore the network is much less dangerous. It is
also the way to enforce a rule of use ("this server only talks to its database and to the update
repositories"). The useful selectors are the **destination** address and port (`ip daddr`,
`tcp dport`), the **output** interface (`oif`, `oifname`) and, specific to this hook, the user of
the program that sends (section @@ref:skuid@@).

### @@sec:output-view@@ What the program sees

In the `output` chain, the packet is stopped on the very machine that sends it, and the difference
between `drop` and `reject` shows in the program:

| program | with `drop` | with `reject` |
|-----------|-------------|---------------|
| `curl` | waits for its timeout: `curl: (28) Connection timed out` | immediate failure: `curl: (7) Failed to connect … Couldn't connect to server` |
| `nc -v` | waits for its timeout: `timed out: Operation now in progress` | immediate failure: `Connection refused` |
| `ping` | `100% packet loss`, with no other message | `Destination Port Unreachable` coming from the machine itself, and `ping: sendmsg: Operation not permitted` |

With `drop`, nothing signals the block: seen from the program, it looks like a failure of the
network or of the remote server. In `output`, **`reject`** is therefore preferred: whoever is
blocked is a user of the machine, who may as well know it at once. In both cases `tcpdump` shows
no packet: it captures after the `output` hook (section @@ref:capture@@).

The error message of a `reject` is built by the kernel and **comes back to the program through the
`lo` interface**: the `input` chain of the machine must let it in, through `iif lo accept` or
through the stateful rule (this message is `related`). Otherwise the program waits, as with
`drop`.

### @@sec:output-state@@ Replies: the stateful rule on the way out

A rule of `output` does not, on its own, tell what the machine **initiates** from what it
**answers**. `ip daddr 192.0.2.7 reject` forbids opening a connection to `192.0.2.7`, but also
rejects the replies of the machine to the connections `192.0.2.7` opens to it: its SYNs come in,
the SYN-ACKs do not go out, and the service looks broken. As in `input`, the stateful rule placed
**at the top** settles the matter:

```
nft insert rule inet filter output ct state established,related accept
```

- `established`: the packets of the connections already accepted, in either direction, hence all
  the replies of the machine to what its `input` chain has let in;
- `related`: the ICMP error messages the machine itself sends about a connection, for example the
  *port unreachable* of a `reject` rule of its `input` chain. Without `related`, these messages no
  longer go out: the sender is no longer notified and waits, as with `drop`.

The following rules then only see `new` packets: what the machine initiates.

### @@sec:output-policies@@ Forbidding a few destinations, or forbidding everything except…

Two ways of writing the `output` chain:

- **allow everything, except…**: policy `accept` and one `reject` rule per forbidden destination
  or service. It is the form for a workstation;
- **forbid everything, except…**: one rule per allowed outgoing flow, and everything else is
  refused. It is the form for a server one wants to lock down. One must then think of everything
  the machine sends without one noticing: its replies and its error messages (the stateful rule),
  its exchanges with itself (`oif lo accept`: many programs talk to each other through
  `127.0.0.1`), its DNS queries, its updates.

```
table inet filter {
        chain output {
                type filter hook output priority filter; policy drop;
                ct state established,related accept
                oif "lo" accept
                icmp type echo-request accept
                udp dport 53 accept
                tcp dport { 80, 443 } accept
                reject
        }
}
```

The **final `reject`** rule, without a selector, notifies the programs of the machine; the `drop`
policy is now only a safety net. To switch an existing chain from `accept` to `drop` without
cutting anything, add the rules that allow **first** and change the policy **last**
(section @@ref:nft-edit@@).

### @@sec:skuid@@ Filtering by user

At the `output` hook, the kernel knows the program that sends the packet: `meta skuid` compares
the user owning its network *socket*, `meta skgid` its group.

```
nft add rule inet filter output meta skuid "www-data" tcp dport 5432 accept
nft add rule inet filter output tcp dport 5432 reject
```

Here only the web server (the user `www-data`) reaches the database; the other users of the
machine are refused. This selector only concerns the packets sent by the machine itself.
""",
    "La commande nft": "The nft command",
    """

### @@sec:nft-list@@ Consulter

```
nft list ruleset                       # tout le jeu de règles (vide au départ)
nft -a list ruleset                    # avec le handle de chaque table, chaîne et règle
nft list tables                        # les tables
nft list table inet filter             # une table
nft list chain inet filter input       # une chaîne
nft -s list ruleset                    # sans les valeurs des compteurs
nft -j list ruleset                    # en JSON
nft describe icmp type                 # le type d'un champ et ses valeurs possibles
nft monitor                            # les modifications du jeu de règles, en direct
```

### @@sec:nft-build@@ Construire

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add chain inet filter logdrop                    # une chaîne régulière (sans hook)
nft add rule inet filter input iif lo accept         # ajoute la règle à la FIN de la chaîne
nft 'add rule inet filter input tcp dport { 80, 8080 } accept'
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'
```

**Le shell passe avant `nft`.** Le point-virgule, les guillemets, les parenthèses, `*`, `|`, `&`,
`<` et `>` ont un sens pour le shell, qui les interprète ou les retire avant que `nft` ne voie la
commande. La règle simple : dès qu'une commande contient autre chose que des mots, des nombres et
des adresses, **entourez d'apostrophes tout ce qui suit `nft`**. Deux autres façons d'échapper
au shell : le mode interactif `nft -i` (on y tape `add rule …` directement, `quit` pour en
sortir) et les fichiers de règles (section @@ref:nft-files@@).

### @@sec:nft-edit@@ Placer, remplacer, supprimer

L'ordre des règles compte (section @@ref:rules@@) : `add rule` ajoute en **fin** de chaîne,
`insert rule` en **tête**. Pour viser un autre endroit, on désigne une règle existante par son
**handle**, que `nft -a list ruleset` affiche en fin de ligne (`# handle 7`) :

```
nft insert rule inet filter input ct state established,related accept   # au DÉBUT de la chaîne
nft insert rule inet filter input handle 7 tcp dport 8080 accept        # AVANT la règle 7
nft add rule inet filter input handle 7 tcp dport 8080 accept           # APRÈS la règle 7
nft replace rule inet filter input handle 7 tcp dport 8443 accept       # À LA PLACE de la règle 7
nft delete rule inet filter input handle 7                              # supprime la règle 7
nft flush chain inet filter input        # vide une chaîne de ses règles ; la chaîne et sa politique restent
nft delete chain inet filter logdrop     # supprime une chaîne vide, vers laquelle plus aucune règle ne saute
nft delete table inet filter             # supprime la table et tout son contenu
nft flush ruleset                        # efface TOUT : toutes les tables de toutes les familles
```

Un handle n'est pas un numéro de ligne : il ne change pas quand on ajoute ou supprime d'autres
règles. Pour changer la **politique** d'une chaîne de base, on la déclare de nouveau, à
l'identique, avec la nouvelle politique (ses règles restent) :
`nft 'add chain inet filter input { type filter hook input priority 0; policy accept; }'`.

Attention : `nft flush chain` laisse la politique en place (une chaîne `policy drop` vidée
détruit tout), et `nft flush ruleset` efface **toutes** les tables, pas seulement les vôtres.

### @@sec:nft-files@@ Les fichiers de règles

Un vrai pare-feu ne se tape pas commande par commande : il s'écrit dans un **fichier**, dans la
syntaxe qu'affiche `nft list ruleset`, et se charge d'un bloc.

```
#!/usr/sbin/nft -f
flush ruleset

define ADMIN = 192.0.2.0/24
define WEB = { 80, 443 }

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                # un commentaire : SSH pour les administrateurs seulement
                ip saddr $ADMIN tcp dport 22 accept
                tcp dport $WEB accept
        }
}
```

```
nft -c -f /etc/nftables.conf      # vérifie le fichier sans rien changer
nft -f /etc/nftables.conf         # le charge
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; à aucun moment la machine ne se retrouve sans règles, ou avec la moitié des
  règles ;
- le fichier commence par **`flush ruleset`** : sans cela, le recharger ajouterait ses règles
  une seconde fois, à la suite des premières ;
- `define` nomme une valeur, reprise par `$NOM` ; `include "/etc/nftables.d/*.nft"` insère
  d'autres fichiers ;
- `nft -s list ruleset > regles.nft` sauvegarde le jeu de règles en place dans un fichier
  rechargeable (ajoutez-lui `flush ruleset` en tête) ;
- sous Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage (`systemctl enable
  nftables`). Les règles tapées avec `nft` sont **volatiles** : elles disparaissent au
  redémarrage.
""": """

### @@sec:nft-list@@ Looking

```
nft list ruleset                       # the whole ruleset (empty at the start)
nft -a list ruleset                    # with the handle of each table, chain and rule
nft list tables                        # the tables
nft list table inet filter             # one table
nft list chain inet filter input       # one chain
nft -s list ruleset                    # without the values of the counters
nft -j list ruleset                    # in JSON
nft describe icmp type                 # the type of a field and its possible values
nft monitor                            # the changes to the ruleset, live
```

### @@sec:nft-build@@ Building

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add chain inet filter logdrop                    # a regular chain (no hook)
nft add rule inet filter input iif lo accept         # adds the rule at the END of the chain
nft 'add rule inet filter input tcp dport { 80, 8080 } accept'
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'
```

**The shell comes before `nft`.** The semicolon, quotes, parentheses, `*`, `|`, `&`, `<` and `>`
mean something to the shell, which interprets or removes them before `nft` sees the command. The
simple rule: as soon as a command contains anything other than words, numbers and addresses,
**put single quotes around everything that follows `nft`**. Two other ways of escaping the shell:
the interactive mode `nft -i` (where `add rule …` is typed directly, `quit` to leave it) and rules
files (section @@ref:nft-files@@).

### @@sec:nft-edit@@ Placing, replacing, deleting

The order of the rules matters (section @@ref:rules@@): `add rule` adds at the **end** of the
chain, `insert rule` at the **top**. To aim at another place, designate an existing rule by its
**handle**, which `nft -a list ruleset` shows at the end of the line (`# handle 7`):

```
nft insert rule inet filter input ct state established,related accept   # at the START of the chain
nft insert rule inet filter input handle 7 tcp dport 8080 accept        # BEFORE rule 7
nft add rule inet filter input handle 7 tcp dport 8080 accept           # AFTER rule 7
nft replace rule inet filter input handle 7 tcp dport 8443 accept       # IN PLACE OF rule 7
nft delete rule inet filter input handle 7                              # deletes rule 7
nft flush chain inet filter input        # empties a chain of its rules; the chain and its policy remain
nft delete chain inet filter logdrop     # deletes an empty chain that no rule jumps to any more
nft delete table inet filter             # deletes the table and all its contents
nft flush ruleset                        # erases EVERYTHING: all the tables of all the families
```

A handle is not a line number: it does not change when other rules are added or deleted. To
change the **policy** of a base chain, declare it again, identically, with the new policy (its
rules remain):
`nft 'add chain inet filter input { type filter hook input priority 0; policy accept; }'`.

Beware: `nft flush chain` leaves the policy in place (an emptied `policy drop` chain destroys
everything), and `nft flush ruleset` erases **all** the tables, not only yours.

### @@sec:nft-files@@ Rules files

A real firewall is not typed command by command: it is written in a **file**, in the syntax
`nft list ruleset` shows, and loaded in one go.

```
#!/usr/sbin/nft -f
flush ruleset

define ADMIN = 192.0.2.0/24
define WEB = { 80, 443 }

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                # a comment: SSH for the administrators only
                ip saddr $ADMIN tcp dport 22 accept
                tcp dport $WEB accept
        }
}
```

```
nft -c -f /etc/nftables.conf      # checks the file without changing anything
nft -f /etc/nftables.conf         # loads it
```

- loading is **atomic**: the file is applied entirely or, at the slightest error, not at all; at
  no time is the machine left without rules, or with half of the rules;
- the file starts with **`flush ruleset`**: without it, reloading it would add its rules a second
  time, after the first ones;
- `define` names a value, used again as `$NAME`; `include "/etc/nftables.d/*.nft"` inserts other
  files;
- `nft -s list ruleset > regles.nft` saves the ruleset in place into a file that can be reloaded
  (add `flush ruleset` at its top);
- on Debian, the `nftables` service loads `/etc/nftables.conf` at boot (`systemctl enable
  nftables`). The rules typed with `nft` are **volatile**: they disappear at reboot.
""",
    "Journaliser et compter": "Logging and counting",
    """

### @@sec:counters@@ Compter

**`counter`** est le moyen le plus simple de savoir si une règle sert : `nft list ruleset`
affiche sur la règle `counter packets 12 bytes 1008`, le nombre de paquets et d'octets qui l'ont
atteinte.

```
nft add rule inet filter input tcp dport 8080 counter accept
```

Les compteurs des règles se remettent à zéro avec `nft reset rules` (tout le jeu de règles),
`nft reset rules inet filter` (une table) ou `nft reset rules inet filter input` (une chaîne) :
la commande affiche les règles avec leurs compteurs, puis les remet à zéro. On peut aussi
déclarer un **compteur nommé**, que plusieurs règles alimentent et que l'on relit ou remet à
zéro séparément :

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 8080 } counter name "web" accept'
nft list counters                 # les compteurs nommés
nft reset counters                # les affiche, puis les remet à zéro
```

### @@sec:log@@ Journaliser

Pour voir **quels** paquets passent par une règle, **`log`** produit une ligne par paquet
(interface, adresses, protocole, ports). Il existe sous deux formes :

- `log prefix "input drop: "` écrit dans le **journal du noyau**, que l'on lit sur une vraie
  machine avec `dmesg -w`, `journalctl -k -f` ou dans `/var/log/kern.log` ; `level` choisit la
  gravité du message (`log level info prefix "…"`) et `flags all` y ajoute des détails (options
  IP et TCP, numéros de séquence). **Dans un conteneur, cette forme ne donne rien** : par défaut
  le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "input drop: " group 0` remet les paquets à **nflog** (ici au groupe 0), où un
  programme vient les lire : **`tcpdump -n -i nflog:0`**, ou le démon `ulogd`, qui les range dans
  un fichier ou une base de données. C'est la forme à utiliser dans ce TP : elle montre les
  paquets journalisés en direct, sur `m1` elle-même.

**Limiter la journalisation.** Sans limite, une attaque ou une simple boucle de `ping` remplit le
journal. `limit rate 5/minute` placé **devant** `log` borne le nombre de lignes. C'est un seau à
jetons (section @@ref:limits@@) : 5 jetons au départ (la rafale, *burst*, 5 par défaut), puis un
jeton toutes les 12 secondes ; les paquets sans jeton ne sont pas journalisés, mais continuent
vers la règle suivante.

**Les apostrophes.** Le préfixe contient une espace et des guillemets : tapée dans un shell, la
règle entière doit être protégée par des apostrophes (`nft 'add rule inet filter logdrop log
prefix "input drop: " group 0'`), sinon le shell retire les guillemets et `nft` ne comprend plus
la commande.

**Journaliser puis détruire.** `log` n'est pas un verdict : on le fait suivre d'un `drop` (ou
d'un `accept`), dans la même règle ou dans la règle suivante. L'usage est d'écrire une **chaîne
régulière** `logdrop` qui journalise puis détruit, et d'y sauter (`jump logdrop`) en dernière
règle des chaînes concernées, plutôt que de répéter `log` partout.
""": """

### @@sec:counters@@ Counting

**`counter`** is the simplest way of knowing whether a rule is used: `nft list ruleset` shows on
the rule `counter packets 12 bytes 1008`, the number of packets and bytes that have reached it.

```
nft add rule inet filter input tcp dport 8080 counter accept
```

The counters of the rules are reset with `nft reset rules` (the whole ruleset),
`nft reset rules inet filter` (one table) or `nft reset rules inet filter input` (one chain): the
command shows the rules with their counters, then resets them. One can also declare a **named
counter**, which several rules feed and which is read or reset separately:

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 8080 } counter name "web" accept'
nft list counters                 # the named counters
nft reset counters                # shows them, then resets them
```

### @@sec:log@@ Logging

To see **which** packets go through a rule, **`log`** produces one line per packet (interface,
addresses, protocol, ports). It comes in two forms:

- `log prefix "input drop: "` writes into the **kernel log**, which is read on a real machine with
  `dmesg -w`, `journalctl -k -f` or in `/var/log/kern.log`; `level` chooses the severity of the
  message (`log level info prefix "…"`) and `flags all` adds details to it (IP and TCP options,
  sequence numbers). **In a container, this form gives nothing**: by default the kernel only logs
  this way the packets of the host machine (setting `net.netfilter.nf_log_all_netns`), and its log
  cannot be read from a container;
- `log prefix "input drop: " group 0` hands the packets over to **nflog** (here to group 0), where a
  program comes to read them: **`tcpdump -n -i nflog:0`**, or the `ulogd` daemon, which stores them
  in a file or a database. It is the form to use in this lab: it shows the logged packets live, on
  `m1` itself.

**Limiting logging.** Without a limit, an attack or a mere `ping` loop fills the log.
`limit rate 5/minute` placed **in front of** `log` bounds the number of lines. It is a token
bucket (section @@ref:limits@@): 5 tokens at the start (the *burst*, 5 by default), then one token
every 12 seconds; the packets without a token are not logged, but go on to the next rule.

**The single quotes.** The prefix contains a space and double quotes: typed in a shell, the whole
rule must be protected by single quotes (`nft 'add rule inet filter logdrop log
prefix "input drop: " group 0'`), otherwise the shell removes the double quotes and `nft` no
longer understands the command.

**Log then drop.** `log` is not a verdict: it is followed by a `drop` (or an `accept`), in the
same rule or in the next one. Common practice is to write a **regular chain** `logdrop` that logs
then drops, and to jump to it (`jump logdrop`) as the last rule of the chains concerned, rather
than repeating `log` everywhere.
""",
    "Ensembles et dictionnaires": "Sets and maps",
    """

Un **ensemble** (*set*) réunit des valeurs d'un même type ; une règle le consulte en une seule
opération, quel que soit le nombre de ses éléments. Une règle qui porte un ensemble de cent
adresses remplace cent règles, et va bien plus vite qu'elles.

### @@sec:anonymous-sets@@ Les ensembles anonymes

Un ensemble **anonyme** s'écrit directement dans la règle, entre accolades ; il ne change plus
ensuite, sauf à remplacer la règle :

```
nft 'add rule inet filter input tcp dport { 22, 80, 443 } accept'
nft 'add rule inet filter input ip saddr { 192.0.2.2, 198.51.100.0/24 } drop'
```

### @@sec:named-sets@@ Les ensembles nommés

Un ensemble **nommé** est un objet de la table : on en modifie le contenu **sans toucher aux
règles** qui le consultent (`@nom`).

```
nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'
nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'
nft insert rule inet filter input ip saddr @blocklist drop
nft list set inet filter blocklist
nft 'delete element inet filter blocklist { 192.0.2.7 }'
nft flush set inet filter blocklist                  # vide l'ensemble
```

La règle d'une liste noire se place **avant** les règles qui acceptent : `nft insert rule` la met
en tête de chaîne. Ajoutée en fin de chaîne, elle ne verrait jamais les paquets qu'une règle
précédente a déjà acceptés.

Le `type` fixe la nature des éléments : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC),
`inet_proto` (protocole), `inet_service` (port), `mark`. Un ensemble de ports s'emploie comme un
ensemble d'adresses : `nft 'add set inet filter web_ports { type inet_service; }'`, puis une règle
`tcp dport @web_ports accept`. Les drapeaux (`flags`) fixent le comportement de l'ensemble :

| déclaration | effet |
|-------------|-------|
| `flags interval;` | les éléments peuvent être des réseaux ou des plages (`192.0.2.0/24`, `8000-8100`) ; sans ce drapeau, des valeurs isolées seulement |
| `flags timeout; timeout 1h;` | les éléments disparaissent d'eux-mêmes après ce délai |
| `flags dynamic;` | les règles peuvent ajouter elles-mêmes des éléments, au passage des paquets |
| `flags constant;` | le contenu ne peut plus changer |

Sans `flags interval`, `nft` refuse d'ajouter un réseau (`Error: You must add 'flags interval' to
your set declaration if you want to add prefix elements`). Les drapeaux d'un ensemble ne se
changent pas après coup : il faut le supprimer et le recréer (`nft delete set inet filter
blocklist`, après avoir supprimé les règles qui le consultent, sinon `Device or resource busy`).

Un élément peut réunir plusieurs champs, séparés par un point (une **concaténation**) :

```
nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'
nft 'add element inet filter allowed { 192.0.2.2 . 22, 192.0.2.3 . 443 }'
nft insert rule inet filter input ip saddr . tcp dport @allowed accept
```

La règle vaut pour un paquet dont **le couple entier** est dans l'ensemble : ici `192.0.2.2` vers
le port 22 et `192.0.2.3` vers le port 443, mais pas `192.0.2.2` vers le port 443. Une seule
règle et un seul ensemble décrivent ainsi « qui a droit à quoi ».

### @@sec:dynamic-sets@@ Les ensembles alimentés par les règles

Avec `flags dynamic`, une règle range dans un ensemble une valeur tirée du paquet qu'elle
examine : `add @nom { … }` ajoute l'élément s'il n'y est pas, `update @nom { … }` fait de même
et remet son délai à zéro. Exemple : quiconque tente une connexion telnet est banni dix
minutes.

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft add rule inet filter input ip saddr @banned drop
nft 'add rule inet filter input tcp dport 23 add @banned { ip saddr } drop'
```

Dans une chaîne qui accepte déjà des services, ces deux règles se placent **en tête** (`nft insert
rule`), sinon une adresse bannie atteint encore les services acceptés avant elles. `nft list set
inet filter banned` montre chaque élément avec le délai qui lui reste (`expires 9m42s`).

### @@sec:maps@@ Les dictionnaires

Un **dictionnaire** (*map*) associe une valeur à chaque clé. Le plus utile dans un filtre est
le **dictionnaire de verdicts** (*verdict map*, `vmap`), qui choisit le verdict d'après un champ
du paquet, en une seule consultation :

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 8080 : accept, 23 : drop }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
nft 'add rule inet filter input iifname vmap { "eth0" : jump from_lan, "eth1" : jump from_wan }'
```

Un paquet dont le champ n'est pas une clé du dictionnaire passe à la règle suivante. Comme un
ensemble, un dictionnaire peut être nommé, et son contenu modifié sans toucher aux règles :

```
nft 'add map inet filter services { type inet_service : verdict; }'
nft 'add element inet filter services { 22 : accept, 8080 : accept }'
nft add rule inet filter input tcp dport vmap @services
```

Les autres dictionnaires fournissent une valeur à une action ; on les rencontre surtout dans la
traduction d'adresses : `dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }` choisit
le serveur d'après le port demandé.
""": """

A **set** gathers values of one type; a rule looks it up in a single operation, whatever the
number of its elements. A rule carrying a set of a hundred addresses replaces a hundred rules, and
is much faster than them.

### @@sec:anonymous-sets@@ Anonymous sets

An **anonymous** set is written directly in the rule, between braces; it no longer changes
afterwards, unless the rule is replaced:

```
nft 'add rule inet filter input tcp dport { 22, 80, 443 } accept'
nft 'add rule inet filter input ip saddr { 192.0.2.2, 198.51.100.0/24 } drop'
```

### @@sec:named-sets@@ Named sets

A **named** set is an object of the table: its contents are changed **without touching the
rules** that look it up (`@name`).

```
nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'
nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'
nft insert rule inet filter input ip saddr @blocklist drop
nft list set inet filter blocklist
nft 'delete element inet filter blocklist { 192.0.2.7 }'
nft flush set inet filter blocklist                  # empties the set
```

The rule of a blocklist goes **before** the rules that accept: `nft insert rule` puts it at the
top of the chain. Added at the end of the chain, it would never see the packets an earlier rule
has already accepted.

The `type` sets the nature of the elements: `ipv4_addr`, `ipv6_addr`, `ether_addr` (MAC address),
`inet_proto` (protocol), `inet_service` (port), `mark`. A set of ports is used like a set of
addresses: `nft 'add set inet filter web_ports { type inet_service; }'`, then a rule
`tcp dport @web_ports accept`. The flags (`flags`) set the behaviour of the set:

| declaration | effect |
|-------------|-------|
| `flags interval;` | the elements can be networks or ranges (`192.0.2.0/24`, `8000-8100`); without this flag, single values only |
| `flags timeout; timeout 1h;` | the elements disappear by themselves after this delay |
| `flags dynamic;` | the rules can add elements themselves, as the packets go by |
| `flags constant;` | the contents can no longer change |

Without `flags interval`, `nft` refuses to add a network (`Error: You must add 'flags interval' to
your set declaration if you want to add prefix elements`). The flags of a set cannot be changed
afterwards: it must be deleted and created again (`nft delete set inet filter
blocklist`, after deleting the rules that look it up, otherwise `Device or resource busy`).

An element can combine several fields, separated by a dot (a **concatenation**):

```
nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'
nft 'add element inet filter allowed { 192.0.2.2 . 22, 192.0.2.3 . 443 }'
nft insert rule inet filter input ip saddr . tcp dport @allowed accept
```

The rule matches a packet whose **whole pair** is in the set: here `192.0.2.2` to port 22 and
`192.0.2.3` to port 443, but not `192.0.2.2` to port 443. A single rule and a single set thus
describe "who is allowed what".

### @@sec:dynamic-sets@@ Sets fed by the rules

With `flags dynamic`, a rule stores in a set a value taken from the packet it examines:
`add @name { … }` adds the element if it is not there, `update @name { … }` does the same and
resets its timeout. Example: whoever tries a telnet connection is banned for ten minutes.

```
nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft add rule inet filter input ip saddr @banned drop
nft 'add rule inet filter input tcp dport 23 add @banned { ip saddr } drop'
```

In a chain that already accepts services, these two rules go **at the top** (`nft insert
rule`), otherwise a banned address still reaches the services accepted before them. `nft list set
inet filter banned` shows each element with the time it has left (`expires 9m42s`).

### @@sec:maps@@ Maps

A **map** associates a value with each key. The most useful one in a filter is the **verdict
map** (`vmap`), which chooses the verdict from a field of the packet, in a single lookup:

```
nft 'add rule inet filter input tcp dport vmap { 22 : accept, 8080 : accept, 23 : drop }'
nft 'add rule inet filter input ct state vmap { established : accept, related : accept, invalid : drop }'
nft 'add rule inet filter input iifname vmap { "eth0" : jump from_lan, "eth1" : jump from_wan }'
```

A packet whose field is not a key of the map moves on to the next rule. Like a set, a map can be
named, and its contents changed without touching the rules:

```
nft 'add map inet filter services { type inet_service : verdict; }'
nft 'add element inet filter services { 22 : accept, 8080 : accept }'
nft add rule inet filter input tcp dport vmap @services
```

The other maps provide a value to an action; they are mostly met in address translation:
`dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }` chooses the server from the port
requested.
""",
    "Limiter le trafic": "Limiting traffic",
    """

### @@sec:limit-rate@@ limit rate : le seau à jetons

`limit rate` laisse une règle se poursuivre à un rythme donné. C'est un **seau à jetons** :
chaque paquet qui passe consomme un jeton, le seau se remplit au rythme indiqué et contient au
plus la **rafale** (*burst*, 5 paquets par défaut). Un paquet qui ne trouve pas de jeton ne
satisfait pas la règle : il passe à la règle suivante.

| règle | effet |
|-------|-------|
| `icmp type echo-request limit rate 5/second accept` | accepte au plus 5 `ping` par seconde ; le surplus continue dans la chaîne, jusqu'à la politique |
| `limit rate 10/minute burst 20 packets log` | 20 paquets d'un coup au plus, puis un toutes les 6 secondes |
| `limit rate over 100/second drop` | `over` inverse le test : la règle vaut pour ce qui **dépasse** le rythme |
| `limit rate 1 mbytes/second accept` | un débit en octets (`bytes`, `kbytes`, `mbytes`) |

Les unités de temps sont `second`, `minute`, `hour` et `day`.

**Attention à la place de la règle.** Après la règle à états, une règle `limit` ne voit plus que
les paquets qui ouvrent une connexion : elle limite alors le rythme des **nouvelles connexions**,
pas le débit. Pour limiter tous les paquets d'un trafic, on la place avant la règle à états
(`limit rate over … drop`).

### @@sec:limit-per-source@@ Une limite par adresse

Une limite écrite dans une règle est **globale** : un seul client bruyant épuise les jetons de
tous. Pour compter **par adresse source**, on associe la limite aux éléments d'un ensemble
alimenté par la règle (section @@ref:dynamic-sets@@) : chaque adresse y reçoit son propre seau.

```
nft 'add set inet filter clients { type ipv4_addr; flags dynamic,timeout; timeout 1m; }'
nft 'add rule inet filter input tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop'
```

De la même façon, `ct count over 2` vaut quand le nombre de connexions **simultanées** dépasse
2 : avec un autre ensemble déclaré `flags dynamic`, `add @sessions { ip saddr ct count over 2 }
reject` refuse la troisième connexion ouverte en même temps par une même adresse.

### @@sec:quotas@@ Les quotas

Un **quota** compte un volume, et non un rythme. C'est un objet nommé de la table, comme un
compteur ; avec `over`, la règle vaut une fois le volume dépassé :

```
nft 'add quota inet filter guest { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "guest" drop'
```
""": """

### @@sec:limit-rate@@ limit rate: the token bucket

`limit rate` lets a rule go on at a given rate. It is a **token bucket**: each packet that goes
through uses one token, the bucket fills up at the given rate and holds at most the **burst** (5
packets by default). A packet that finds no token does not match the rule: it moves on to the
next rule.

| rule | effect |
|-------|-------|
| `icmp type echo-request limit rate 5/second accept` | accepts at most 5 `ping` per second; the excess goes on in the chain, down to the policy |
| `limit rate 10/minute burst 20 packets log` | 20 packets at once at most, then one every 6 seconds |
| `limit rate over 100/second drop` | `over` inverts the test: the rule matches what **exceeds** the rate |
| `limit rate 1 mbytes/second accept` | a rate in bytes (`bytes`, `kbytes`, `mbytes`) |

The time units are `second`, `minute`, `hour` and `day`.

**Mind the place of the rule.** After the stateful rule, a `limit` rule only sees the packets that
open a connection: it then limits the rate of **new connections**, not the throughput. To limit
all the packets of a traffic, place it before the stateful rule (`limit rate over … drop`).

### @@sec:limit-per-source@@ A limit per address

A limit written in a rule is **global**: a single noisy client uses up everybody's tokens. To
count **per source address**, the limit is attached to the elements of a set fed by the rule
(section @@ref:dynamic-sets@@): each address gets its own bucket there.

```
nft 'add set inet filter clients { type ipv4_addr; flags dynamic,timeout; timeout 1m; }'
nft 'add rule inet filter input tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop'
```

In the same way, `ct count over 2` matches when the number of **simultaneous** connections
exceeds 2: with another set declared `flags dynamic`, `add @sessions { ip saddr ct count over 2 }
reject` refuses the third connection opened at the same time by one address.

### @@sec:quotas@@ Quotas

A **quota** counts a volume, not a rate. It is a named object of the table, like a counter; with
`over`, the rule matches once the volume is exceeded:

```
nft 'add quota inet filter guest { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "guest" drop'
```
""",
    "La traduction d'adresses en bref": "Address translation in brief",
    """

La traduction d'adresses (NAT) réécrit l'adresse, et au besoin le port, source ou destination
des paquets qui traversent un routeur. Elle fera l'objet d'un autre TP ; en voici l'essentiel.
Elle se fait dans des chaînes de type **`nat`** :

```
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'
nft add rule ip nat postrouting oif eth0 masquerade                            # ou bien :
nft add rule ip nat postrouting oif eth0 snat to 203.0.113.1
nft add rule ip nat prerouting iif eth0 tcp dport 80 dnat to 192.0.2.10:8080   # ou bien :
nft add rule ip nat prerouting tcp dport 80 redirect to :8080
```

| action | hook | effet |
|--------|------|-------|
| `masquerade` | `postrouting` | remplace l'adresse source par celle de l'interface de sortie (partage d'une adresse publique) |
| `snat to A` | `postrouting` | remplace l'adresse source par l'adresse A |
| `dnat to A:P` | `prerouting` | remplace l'adresse et le port de destination (redirection de port vers un serveur interne) |
| `redirect to :P` | `prerouting` | envoie le paquet vers le port P de la machine elle-même (mandataire transparent) |

- une chaîne `nat` ne voit que le **premier paquet** de chaque connexion : le suivi de connexion
  applique la même traduction aux suivants, et la traduction inverse aux réponses ;
- le filtrage se fait toujours dans les chaînes `filter`. La chaîne `forward` voit un paquet
  **après** le DNAT (fait en `prerouting`) et **avant** le SNAT (fait en `postrouting`) : ses
  règles nomment donc l'adresse réelle du serveur interne et l'adresse d'origine du client ;
- dans une table `inet`, on précise la version d'IP : `dnat ip to 192.0.2.10`.
""": """

Network address translation (NAT) rewrites the source or destination address, and if need be the
port, of the packets that cross a router. It will be the subject of another lab; here is the
essential. It is done in chains of type **`nat`**:

```
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; }'
nft add rule ip nat postrouting oif eth0 masquerade                            # or else:
nft add rule ip nat postrouting oif eth0 snat to 203.0.113.1
nft add rule ip nat prerouting iif eth0 tcp dport 80 dnat to 192.0.2.10:8080   # or else:
nft add rule ip nat prerouting tcp dport 80 redirect to :8080
```

| action | hook | effect |
|--------|------|-------|
| `masquerade` | `postrouting` | replaces the source address with that of the outgoing interface (sharing a public address) |
| `snat to A` | `postrouting` | replaces the source address with address A |
| `dnat to A:P` | `prerouting` | replaces the destination address and port (port forwarding to an internal server) |
| `redirect to :P` | `prerouting` | sends the packet to port P of the machine itself (transparent proxy) |

- a `nat` chain only sees the **first packet** of each connection: connection tracking applies the
  same translation to the following ones, and the reverse translation to the replies;
- filtering is still done in the `filter` chains. The `forward` chain sees a packet **after** the
  DNAT (done in `prerouting`) and **before** the SNAT (done in `postrouting`): its rules therefore
  name the real address of the internal server and the original address of the client;
- in an `inet` table, the IP version is specified: `dnat ip to 192.0.2.10`.
""",
    "Observer et tester un pare-feu": "Observing and testing a firewall",
    """

Un pare-feu se vérifie des deux côtés : ce qu'il **laisse passer** (ce qui doit marcher marche
encore) et ce qu'il **arrête** (ce qui doit être bloqué l'est vraiment).

### @@sec:test-servers@@ Les serveurs de test du TP

Les machines du TP servent toutes un petit **serveur de test**, en HTTP sur les ports TCP **80,
8080 et 8888** et en UDP sur les ports **530 et 630** (`ss -tulnp` les liste). Il répond par son
nom et par les adresses et ports des deux bouts de l'échange, tels qu'il
les voit, et par le TTL du paquet reçu (64 depuis le même réseau, un de moins par routeur
traversé) :

```
m1:~# curl http://m2/                   # ou curl http://m2:8080/ ; -m 3 pour ne pas attendre plus de 3 s
SERVER=m2
SERVER_IP=192.0.2.2
SERVER_PORT=80
CLIENT_IP=192.0.2.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # un datagramme UDP vers le port 530 (ou 630) : même réponse
```

### @@sec:client-view@@ Ce que voit le client

Le message d'erreur du client dit ce que le pare-feu a fait du paquet :

| ce que le client observe | ce qui s'est passé |
|--------------------------|--------------------|
| `curl: (7) Failed to connect …`, **immédiat** (connexion refusée ; `nc -vz` affiche `Connection refused`) | un `reject` (ou un port fermé, sans pare-feu) |
| `curl: (28) Connection timed out`, **après le délai** (`-m 3`) | un `drop` (ou une machine éteinte) |
| `nc -u -w 1` se termine sans rien afficher | le datagramme, ou sa réponse, a été détruit |
| `ping -c 2 -W 1 m1` : `100% packet loss` | les requêtes, ou les réponses, sont détruites |
| `ping` : `Destination Port Unreachable` venant de la machine elle-même, et `ping: sendmsg: Operation not permitted` | un `reject` dans sa propre chaîne `output` (section @@ref:output-view@@) |

### @@sec:capture@@ Capturer : où se place tcpdump

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu :

- en réception, il voit les paquets **avant** tous les hooks : un paquet que le pare-feu détruit
  en `input` apparaît quand même dans la capture. Voir arriver un paquet ne prouve donc pas
  qu'il a été accepté ;
- en émission, il voit les paquets **après** tous les hooks : un paquet détruit en `output`
  n'apparaît pas.

`tcpdump -n -i eth0 icmp or tcp port 80` sur le client montre ce qu'il reçoit (le message ICMP
*port unreachable* d'un `reject`, ou rien) ; `tcpdump -n -i eth0 'port 80 or port 530'` sur le
serveur montre ce qui lui arrive, que le pare-feu l'accepte ou non.

### @@sec:which-rule@@ Savoir quelle règle a tranché

Les **compteurs** d'abord : ajoutez `counter` aux règles (`… counter accept`, `… counter drop`)
et relisez `nft list ruleset` après un essai : la règle dont le compteur a bougé est celle qui a
vu le paquet. C'est la méthode de diagnostic de base d'un pare-feu.

Pour suivre un paquet règle par règle, on le **trace** : une règle `meta nftrace set 1`, placée
en tête de chaîne, marque les paquets à suivre, et `nft monitor trace` affiche leur parcours.

```
nft insert rule inet filter input ip saddr 192.0.2.3 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.3 ip daddr 192.0.2.1 … tcp dport 8080 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.3 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 8080 accept (verdict accept)
```

Chaque ligne commence par l'identifiant du paquet, la table et la chaîne ; les lignes `rule`
donnent les règles satisfaites et leur verdict, et un paquet qu'aucune règle n'arrête se termine
par la politique de la chaîne (`policy drop`). Supprimez la règle de trace quand vous avez fini.

### @@sec:method@@ Une démarche de diagnostic

1. `nft list ruleset` : est-ce bien le jeu de règles que vous croyez avoir chargé ? Les règles
   sont-elles dans le bon ordre ?
2. le message d'erreur du client : refus immédiat (`reject`) ou délai d'attente (`drop`) ?
3. les compteurs : quelle règle a vu le paquet ? Aucune : il n'arrive pas jusqu'à la chaîne, ou
   la politique l'a détruit ;
4. `tcpdump` des deux côtés : la requête arrive-t-elle ? La réponse repart-elle ? Souvent c'est
   la **réponse** qui est bloquée, pas la requête ;
5. la trace, quand le reste ne suffit pas.
""": """

A firewall is checked from both sides: what it **lets through** (what must work still works) and
what it **stops** (what must be blocked really is).

### @@sec:test-servers@@ The test servers of the lab

The machines of the lab all serve a small **test server**, in HTTP on TCP ports **80, 8080 and
8888** and in UDP on ports **530 and 630** (`ss -tulnp` lists them). It answers with its name and
with the addresses and ports of both ends of the exchange, as it sees them, and with the TTL of the
packet received (64 from the same network, one less per router crossed):

```
m1:~# curl http://m2/                   # or curl http://m2:8080/; -m 3 so as not to wait more than 3 s
SERVER=m2
SERVER_IP=192.0.2.2
SERVER_PORT=80
CLIENT_IP=192.0.2.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # a UDP datagram to port 530 (or 630): same answer
```

### @@sec:client-view@@ What the client sees

The error message of the client tells what the firewall has done with the packet:

| what the client observes | what happened |
|--------------------------|--------------------|
| `curl: (7) Failed to connect …`, **immediate** (connection refused; `nc -vz` shows `Connection refused`) | a `reject` (or a closed port, without a firewall) |
| `curl: (28) Connection timed out`, **after the timeout** (`-m 3`) | a `drop` (or a machine switched off) |
| `nc -u -w 1` ends without showing anything | the datagram, or its reply, has been destroyed |
| `ping -c 2 -W 1 m1`: `100% packet loss` | the requests, or the replies, are destroyed |
| `ping`: `Destination Port Unreachable` coming from the machine itself, and `ping: sendmsg: Operation not permitted` | a `reject` in its own `output` chain (section @@ref:output-view@@) |

### @@sec:capture@@ Capturing: where tcpdump sits

`tcpdump` captures **right at the interface**, outside the firewall:

- on reception, it sees the packets **before** all the hooks: a packet the firewall destroys in
  `input` still appears in the capture. Seeing a packet arrive therefore does not prove it has
  been accepted;
- on transmission, it sees the packets **after** all the hooks: a packet destroyed in `output`
  does not appear.

`tcpdump -n -i eth0 icmp or tcp port 80` on the client shows what it receives (the ICMP *port
unreachable* message of a `reject`, or nothing); `tcpdump -n -i eth0 'port 80 or port 530'` on the
server shows what reaches it, whether the firewall accepts it or not.

### @@sec:which-rule@@ Finding out which rule decided

The **counters** first: add `counter` to the rules (`… counter accept`, `… counter drop`) and read
`nft list ruleset` again after a try: the rule whose counter has moved is the one that saw the
packet. It is the basic troubleshooting method for a firewall.

To follow a packet rule by rule, **trace** it: a `meta nftrace set 1` rule, placed at the top of
the chain, marks the packets to follow, and `nft monitor trace` shows their path.

```
nft insert rule inet filter input ip saddr 192.0.2.3 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.3 ip daddr 192.0.2.1 … tcp dport 8080 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.3 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 8080 accept (verdict accept)
```

Each line starts with the identifier of the packet, the table and the chain; the `rule` lines give
the matching rules and their verdict, and a packet that no rule stops ends with the policy of the
chain (`policy drop`). Delete the trace rule when you are done.

### @@sec:method@@ A troubleshooting method

1. `nft list ruleset`: is it really the ruleset you think you loaded? Are the rules in the right
   order?
2. the error message of the client: immediate refusal (`reject`) or timeout (`drop`)?
3. the counters: which rule saw the packet? None: it does not reach the chain, or the policy
   destroyed it;
4. `tcpdump` on both sides: does the request arrive? Does the reply leave? Often it is the
   **reply** that is blocked, not the request;
5. the trace, when the rest is not enough.
""",
    "Bonnes pratiques": "Good practice",
    """

### @@sec:host-firewall@@ Le pare-feu type d'une machine

Un serveur qui offre SSH à son réseau d'administration et le web à tout le monde :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;

                ct state established,related accept
                ct state invalid drop
                iif "lo" accept

                icmp type echo-request limit rate 5/second accept
                icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
                icmpv6 type echo-request limit rate 5/second accept

                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept

                limit rate 5/minute log prefix "input drop: "
        }
        chain forward {
                type filter hook forward priority filter; policy drop;
        }
        chain output {
                type filter hook output priority filter; policy accept;
        }
}
```

### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input` (et en `forward`), et une
  règle par service réellement offert, restreinte à ceux qui en ont besoin (`ip saddr`). Le hook
  `output` reste souvent ouvert (on fait confiance à la machine elle-même) ; on le filtre sur les
  machines que l'on veut cloisonner (section @@ref:output@@) ;
- **la règle à états en premier** : elle traite presque tous les paquets et dispense d'ouvrir
  quoi que ce soit pour les réponses ;
- **ne jamais oublier `lo`** : beaucoup de services locaux se parlent par `127.0.0.1` ;
- **ne pas bloquer tout ICMP** : les erreurs ICMP (*fragmentation needed*, *port unreachable*,
  *time exceeded*) sont nécessaires au bon fonctionnement d'IP ; la règle à états les accepte,
  puisqu'elles sont `related`. Répondre au `ping`, à un rythme limité, facilite le diagnostic ;
- **en IPv6, autoriser la découverte des voisins** : elle remplace ARP et utilise ICMPv6
  (`nd-neighbor-solicit`, `nd-neighbor-advert`, `nd-router-advert`). Ces messages ne sont pas
  suivis par le suivi de connexion : sans règle explicite, une politique `drop` coupe IPv6 ;
- **journaliser ce qui est détruit**, avec une limite, pour voir les attaques comme ses propres
  erreurs ;
- **un fichier, chargé d'un bloc** (section @@ref:nft-files@@), vérifié d'abord avec `nft -c -f`,
  plutôt que des commandes tapées une à une.

### @@sec:pitfalls@@ Les pièges

- **se couper l'accès** : sur une machine administrée à distance, une chaîne `input` en
  `policy drop` sans règle pour SSH (ni règle à états) coupe la session en cours. Chargez un
  fichier complet, d'un bloc, et gardez un accès de secours ;
- **l'ordre des règles** : une règle placée après un `drop` ou un `reject` qui couvre les mêmes
  paquets n'est jamais consultée (`nft insert rule`, ou `handle`) ;
- **le sens** : filtrer `input` ne limite pas ce que la machine émet, mais détruit les réponses à
  ce qu'elle émet tant qu'il n'y a pas de règle à états ; filtrer `output` arrête aussi les
  réponses de la machine à ce qu'elle sert, tant que sa chaîne `output` n'a pas la sienne ;
- **oublier `lo` en sortie** : avec une politique `drop` en `output`, sans `oif lo accept` les
  programmes de la machine ne se joignent plus par `127.0.0.1` ;
- **le shell** : guillemets, accolades et points-virgules se protègent par des apostrophes
  (section @@ref:nft-build@@) ;
- **`flush ruleset`** efface aussi les tables des autres logiciels (Docker, par exemple). Sur une
  telle machine, on ne remplace que sa propre table : le fichier commence alors par les deux
  lignes `table inet filter` et `delete table inet filter`, au lieu de `flush ruleset` ;
- **les règles volatiles** : ce qui n'est pas dans `/etc/nftables.conf` disparaît au
  redémarrage.
""": """

### @@sec:host-firewall@@ The typical firewall of a machine

A server that offers SSH to its administration network and the web to everybody:

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;

                ct state established,related accept
                ct state invalid drop
                iif "lo" accept

                icmp type echo-request limit rate 5/second accept
                icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
                icmpv6 type echo-request limit rate 5/second accept

                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept

                limit rate 5/minute log prefix "input drop: "
        }
        chain forward {
                type filter hook forward priority filter; policy drop;
        }
        chain output {
                type filter hook output priority filter; policy accept;
        }
}
```

### @@sec:principles@@ The principles

- **forbid everything, then allow**: policy `drop` in `input` (and in `forward`), and one rule per
  service actually offered, restricted to those who need it (`ip saddr`). The `output` hook often
  stays open (the machine itself is trusted); it is filtered on the machines one wants to lock
  down (section @@ref:output@@);
- **the stateful rule first**: it handles almost every packet and saves opening anything for the
  replies;
- **never forget `lo`**: many local services talk to each other through `127.0.0.1`;
- **do not block all ICMP**: ICMP errors (*fragmentation needed*, *port unreachable*, *time
  exceeded*) are needed for IP to work properly; the stateful rule accepts them, since they are
  `related`. Answering `ping`, at a limited rate, makes troubleshooting easier;
- **in IPv6, allow neighbour discovery**: it replaces ARP and uses ICMPv6 (`nd-neighbor-solicit`,
  `nd-neighbor-advert`, `nd-router-advert`). These messages are not followed by connection
  tracking: without an explicit rule, a `drop` policy cuts IPv6;
- **log what is destroyed**, with a limit, to see attacks as well as one's own mistakes;
- **one file, loaded in one go** (section @@ref:nft-files@@), checked first with `nft -c -f`,
  rather than commands typed one by one.

### @@sec:pitfalls@@ The pitfalls

- **locking yourself out**: on a machine administered remotely, an `input` chain with
  `policy drop` and no rule for SSH (nor a stateful rule) cuts the current session. Load a
  complete file, in one go, and keep an emergency access;
- **the order of the rules**: a rule placed after a `drop` or a `reject` that covers the same
  packets is never consulted (`nft insert rule`, or `handle`);
- **the direction**: filtering `input` does not limit what the machine sends, but destroys the
  replies to what it sends as long as there is no stateful rule; filtering `output` also stops
  the replies of the machine to what it serves, as long as its `output` chain does not have its
  own;
- **forgetting `lo` on the way out**: with a `drop` policy in `output`, without `oif lo accept`
  the programs of the machine no longer reach each other through `127.0.0.1`;
- **the shell**: double quotes, braces and semicolons are protected by single quotes
  (section @@ref:nft-build@@);
- **`flush ruleset`** also erases the tables of other software (Docker, for example). On such a
  machine, only one's own table is replaced: the file then starts with the two lines
  `table inet filter` and `delete table inet filter`, instead of `flush ruleset`;
- **volatile rules**: what is not in `/etc/nftables.conf` disappears at reboot.
""",
    "Passer d'iptables à nftables": "Moving from iptables to nftables",
    """

Beaucoup de documentations, de scripts et de réponses trouvées en ligne sont encore écrits pour
`iptables`, et beaucoup d'administrateurs ont appris avec lui. Cette section aide à passer de
l'un à l'autre : ce qui change dans le modèle, un même pare-feu écrit dans les deux langages, la
correspondance des commandes et des options, la traduction automatique, et la cohabitation des
deux sur une même machine.

### @@sec:ipt-model@@ Ce qui change dans le modèle

| iptables | nftables |
|----------|----------|
| des tables fixes (`filter`, `nat`, `mangle`, `raw`) et des chaînes prédéfinies (`INPUT`, `FORWARD`, `OUTPUT`, `PREROUTING`, `POSTROUTING`), présentes même vides | rien de prédéfini : on crée ses tables et ses chaînes de base, du nom de son choix ; c'est le `hook` qui accroche une chaîne, pas son nom (section @@ref:base-chains@@) |
| l'ordre des tables sur un hook est figé (`raw`, `mangle`, `nat`, `filter`) | les chaînes de base d'un même hook passent par priorité croissante ; les priorités nommées `raw`, `mangle`, `dstnat`, `filter`, `srcnat` reprennent l'ordre d'iptables (section @@ref:priorities@@) |
| une commande par famille : `iptables`, `ip6tables`, `arptables`, `ebtables` | une seule commande ; une table `inet` filtre IPv4 et IPv6 à la fois |
| chaque règle compte ses paquets | une règle ne compte que si on lui ajoute `counter` |
| une règle n'a qu'une cible (`-j`) : journaliser puis détruire demande deux règles | une règle enchaîne plusieurs actions : `counter log prefix "…" drop` |
| des modules d'extension (`-m multiport`, `-m iprange`, `-m recent`) et l'outil séparé `ipset` | les ensembles, les intervalles et les dictionnaires font partie du langage (section @@ref:sets@@) |
| une règle se désigne par son numéro, qui change quand on en ajoute ou en retire d'autres | une règle se désigne par son `handle`, qui ne change pas (section @@ref:nft-edit@@) |
| `iptables-save` et `iptables-restore` emploient un format à part | `nft list ruleset` affiche le format même des fichiers que charge `nft -f` |

Une différence se voit dès le départ : sans aucune règle, iptables a quand même ses chaînes, en
politique `ACCEPT`, que chaque paquet traverse ; un nftables vide n'a aucune chaîne et laisse tout
passer sans rien examiner. Le reste du fonctionnement est le même : le suivi de connexion,
les hooks, et le fait qu'un `accept` ne termine que la chaîne en cours (un paquet accepté dans
la table `mangle` d'iptables peut encore être détruit dans sa table `filter`, comme dans deux
chaînes de base nftables du même hook).

### @@sec:ipt-example@@ Un même pare-feu dans les deux langages

En iptables, une suite de commandes, où chaque option `-m` charge un module :

```
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT
iptables -A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -N logdrop
iptables -A logdrop -m limit --limit 5/minute -j LOG --log-prefix "input drop: "
iptables -A logdrop -j DROP
iptables -A INPUT -j logdrop
```

En nftables, un fichier chargé d'un bloc (section @@ref:nft-files@@) :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                icmp type echo-request limit rate 5/second accept
                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept
                jump logdrop
        }
        chain logdrop {
                limit rate 5/minute log prefix "input drop: "
                drop
        }
}
```

La correspondance est presque mot à mot ; seul `-m multiport` devient un ensemble anonyme. Une
différence de taille, pourtant : faute de règles `ip6tables`, le script iptables laisse **IPv6
entièrement ouvert**, alors que la table `inet` filtre IPv6 aussi. Ses règles qui ne nomment ni
adresse ni type ICMP (`ct state`, `iif "lo"`, `tcp dport`, `jump`) valent pour les deux versions
d'IP ; sur une machine qui a IPv6, il faut y ajouter la découverte des voisins (section
@@ref:principles@@).

### @@sec:ipt-commands@@ Les commandes

| iptables | nftables |
|----------|----------|
| `iptables -L -n -v --line-numbers`, `iptables -S` | `nft -a list ruleset` |
| `iptables -P INPUT DROP` | `policy drop;` dans la déclaration de la chaîne de base (section @@ref:nft-edit@@) |
| `iptables -A INPUT …` | `nft add rule inet filter input …` |
| `iptables -I INPUT …` | `nft insert rule inet filter input …` |
| `iptables -I INPUT 3 …` | `nft insert rule inet filter input handle N …` (N : le handle de la règle qui doit suivre) |
| `iptables -R INPUT 3 …` | `nft replace rule inet filter input handle N …` |
| `iptables -D INPUT 3`, ou `iptables -D INPUT` suivi de la règle | `nft delete rule inet filter input handle N` (par handle seulement) |
| `iptables -N logdrop`, `-j logdrop`, `-g logdrop`, `-j RETURN` | `nft add chain inet filter logdrop`, `jump logdrop`, `goto logdrop`, `return` |
| `iptables -F INPUT`, `iptables -F` | `nft flush chain inet filter input`, `nft flush table inet filter` |
| `iptables -X logdrop` | `nft delete chain inet filter logdrop` |
| `iptables-save > regles`, `iptables-restore < regles` | `nft -s list ruleset > regles`, `nft -f regles` |
| `iptables -t nat …` | une table et des chaînes de type `nat` (section @@ref:nat@@) |

### @@sec:ipt-options@@ Les critères et les cibles

| iptables | nftables |
|----------|----------|
| `-i eth0`, `-o eth0`, `-i eth+` | `iifname "eth0"`, `oifname "eth0"`, `iifname "eth*"` (ou `iif eth0`, voir plus bas) |
| `-s 192.0.2.0/24`, `-d 192.0.2.1` | `ip saddr 192.0.2.0/24`, `ip daddr 192.0.2.1` |
| `! -s 192.0.2.0/24` | `ip saddr != 192.0.2.0/24` |
| `-p udp` | `meta l4proto udp` |
| `-p tcp --dport 22`, `-p tcp --sport 1024:65535` | `tcp dport 22`, `tcp sport 1024-65535` |
| `-p tcp -m multiport --dports 80,443` | `tcp dport { 80, 443 }` |
| `-m iprange --src-range 192.0.2.10-192.0.2.20` | `ip saddr 192.0.2.10-192.0.2.20` |
| `-p icmp --icmp-type echo-request` | `icmp type echo-request` |
| `-m state --state ESTABLISHED,RELATED`, `-m conntrack --ctstate NEW` | `ct state established,related`, `ct state new` |
| `-m mac --mac-source 02:00:00:00:00:01` | `ether saddr 02:00:00:00:00:01` |
| `-m owner --uid-owner www-data` | `meta skuid "www-data"` (section @@ref:skuid@@) |
| `-m comment --comment "SSH"` | `comment "SSH"`, en fin de règle |
| `-m limit --limit 5/minute --limit-burst 10` | `limit rate 5/minute burst 10 packets` |
| `-m hashlimit --hashlimit-name ssh --hashlimit-mode srcip --hashlimit-above 3/minute` | `update @clients { ip saddr limit rate over 3/minute }` (section @@ref:limit-per-source@@) |
| `-m connlimit --connlimit-above 2` | `add @sessions { ip saddr ct count over 2 }` (section @@ref:limit-per-source@@) |
| `-m set --match-set blocklist src`, l'ensemble créé par `ipset create blocklist hash:net` | `ip saddr @blocklist`, l'ensemble déclaré `type ipv4_addr; flags interval;` (section @@ref:named-sets@@) |
| `-m recent --name banned --set`, puis `-m recent --name banned --rcheck --seconds 60 -j DROP` | `add @banned { ip saddr }`, puis `ip saddr @banned drop`, l'ensemble déclaré `flags dynamic,timeout; timeout 60s;` (section @@ref:dynamic-sets@@) |
| `-m mark --mark 1`, `-j MARK --set-mark 1` | `meta mark 1`, `meta mark set 1` |
| `-j ACCEPT`, `-j DROP`, `-j RETURN` | `accept`, `drop`, `return` |
| `-j REJECT`, `-j REJECT --reject-with tcp-reset` | `reject`, `reject with tcp reset` |
| `-j LOG --log-prefix "input drop: "` | `log prefix "input drop: "` (suivi, si besoin, d'un verdict dans la même règle) |
| `-j NFLOG --nflog-group 0` | `log group 0` |
| `-j TRACE`, dans la table `raw` | `meta nftrace set 1` (section @@ref:which-rule@@) |
| `-j MASQUERADE`, `-j SNAT --to-source A`, `-j DNAT --to-destination A:P`, `-j REDIRECT --to-ports P` | `masquerade`, `snat to A`, `dnat to A:P`, `redirect to :P` |

**`iifname` ou `iif` ?** L'option `-i` d'iptables compare le **nom** de l'interface, comme
`iifname`. `iif` compare son **numéro** (son index) : c'est plus rapide, mais l'interface doit
exister quand la règle est chargée, et une interface détruite puis recréée (un tunnel, une
interface `ppp`, celle d'un conteneur) reçoit un autre numéro, que la règle ne suit pas. `iif lo`
convient donc toujours ; pour une interface qui va et vient, on écrit `iifname`.

### @@sec:ipt-translate@@ Traduire automatiquement

Le paquet `iptables` fournit des traducteurs, qui affichent la commande `nft` équivalente sans
rien changer au pare-feu :

```
iptables-translate -A INPUT -i eth0 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
ip6tables-translate …                                    # la même chose pour ip6tables
iptables-restore-translate -f regles.v4 > regles.nft     # tout un fichier écrit par iptables-save
```

La première commande affiche (à la version près) :

```
nft 'add rule ip filter INPUT iifname "eth0" tcp dport 22 ct state new counter accept'
```

La traduction est **littérale** : elle vise la table `ip filter` et la chaîne `INPUT` que crée
`iptables-nft` (voir plus bas), ajoute `counter` à chaque règle, puisque iptables compte tout, et
emploie `iifname`. Certaines extensions n'ont pas de traduction : relisez toujours le résultat.
C'est un point de départ, que l'on réécrit en vrai fichier nftables. Pour convertir un pare-feu :

1. sauvegarder les règles en place : `iptables-save > regles.v4` (et `ip6tables-save >
   regles.v6`) ;
2. les traduire avec `iptables-restore-translate -f regles.v4`, et lire le résultat ;
3. le réécrire en fichier nftables (section @@ref:nft-files@@) : une seule table `inet` pour IPv4
   et IPv6, des noms en minuscules, des ensembles à la place des séries de règles presque
   identiques et des `ipset`, `counter` seulement là où il sert ;
4. vérifier le fichier (`nft -c -f`), le charger, puis retirer les règles d'iptables et le service
   qui les rechargeait au démarrage (`netfilter-persistent` sous Debian), au profit du service
   `nftables`.

### @@sec:ipt-coexist@@ iptables sur une machine nftables

Sur une Debian récente, la commande `iptables` est **`iptables-nft`** : `iptables -V` affiche
`iptables v1.8.11 (nf_tables)`. Elle garde la syntaxe d'iptables, mais écrit des règles nftables,
dans des tables `ip filter`, `ip nat`, `ip6 filter`… aux chaînes `INPUT`, `FORWARD`, `OUTPUT`…,
que `nft list ruleset` affiche à côté des vôtres. C'est ainsi que Docker, par exemple, installe
ses règles. Quelques conséquences :

- ces tables appartiennent à iptables : on les lit avec `nft`, mais on ne les modifie qu'avec
  `iptables`, dont les règles emploient des extensions que seul iptables sait gérer ;
- chaque table est traversée : un paquet que votre table `inet filter` accepte peut encore être
  détruit par la table `ip filter` d'iptables, sur le même hook, et inversement (section
  @@ref:priorities@@) ;
- `nft flush ruleset` efface aussi ces tables (section @@ref:pitfalls@@) ;
- l'ancien moteur, **`iptables-legacy`** (`iptables -V` affiche alors `(legacy)`), n'apparaît
  pas du tout dans `nft list ruleset`, mais ses règles s'appliquent quand même. Ne mélangez pas
  les deux sur une machine : `update-alternatives --config iptables` choisit le moteur que
  désigne la commande `iptables`.
""": """

Many documents, scripts and answers found online are still written for `iptables`, and many
administrators learnt with it. This section helps to move from one to the other: what changes in
the model, the same firewall written in both languages, the correspondence of the commands and
options, automatic translation, and the coexistence of both on one machine.

### @@sec:ipt-model@@ What changes in the model

| iptables | nftables |
|----------|----------|
| fixed tables (`filter`, `nat`, `mangle`, `raw`) and predefined chains (`INPUT`, `FORWARD`, `OUTPUT`, `PREROUTING`, `POSTROUTING`), present even when empty | nothing predefined: you create your own tables and base chains, with the names of your choice; it is the `hook` that attaches a chain, not its name (section @@ref:base-chains@@) |
| the order of the tables on a hook is fixed (`raw`, `mangle`, `nat`, `filter`) | the base chains of one hook are crossed by increasing priority; the named priorities `raw`, `mangle`, `dstnat`, `filter`, `srcnat` follow the order of iptables (section @@ref:priorities@@) |
| one command per family: `iptables`, `ip6tables`, `arptables`, `ebtables` | a single command; an `inet` table filters IPv4 and IPv6 at once |
| every rule counts its packets | a rule only counts if `counter` is added to it |
| a rule has only one target (`-j`): logging then dropping takes two rules | a rule chains several actions: `counter log prefix "…" drop` |
| extension modules (`-m multiport`, `-m iprange`, `-m recent`) and the separate `ipset` tool | sets, intervals and maps are part of the language (section @@ref:sets@@) |
| a rule is designated by its number, which changes when others are added or removed | a rule is designated by its `handle`, which does not change (section @@ref:nft-edit@@) |
| `iptables-save` and `iptables-restore` use a format of their own | `nft list ruleset` shows the very format of the files `nft -f` loads |

One difference shows from the start: without any rule, iptables still has its chains, with policy
`ACCEPT`, which every packet crosses; an empty nftables has no chain and lets everything through
without examining anything. The rest works the same way: connection tracking, the hooks, and the
fact that an `accept` only ends the current chain (a packet accepted in the `mangle` table of
iptables can still be dropped in its `filter` table, as in two nftables base chains of the same
hook).

### @@sec:ipt-example@@ The same firewall in both languages

In iptables, a sequence of commands, where each `-m` option loads a module:

```
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second -j ACCEPT
iptables -A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -N logdrop
iptables -A logdrop -m limit --limit 5/minute -j LOG --log-prefix "input drop: "
iptables -A logdrop -j DROP
iptables -A INPUT -j logdrop
```

In nftables, a file loaded in one go (section @@ref:nft-files@@):

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                ct state established,related accept
                iif "lo" accept
                icmp type echo-request limit rate 5/second accept
                ip saddr 192.0.2.0/24 tcp dport 22 accept
                tcp dport { 80, 443 } accept
                jump logdrop
        }
        chain logdrop {
                limit rate 5/minute log prefix "input drop: "
                drop
        }
}
```

The correspondence is almost word for word; only `-m multiport` becomes an anonymous set. A big
difference, though: lacking `ip6tables` rules, the iptables script leaves **IPv6 wide open**,
whereas the `inet` table filters IPv6 too. Its rules that name neither an address nor an ICMP type
(`ct state`, `iif "lo"`, `tcp dport`, `jump`) apply to both IP versions; on a machine that has
IPv6, neighbour discovery must be added (section @@ref:principles@@).

### @@sec:ipt-commands@@ The commands

| iptables | nftables |
|----------|----------|
| `iptables -L -n -v --line-numbers`, `iptables -S` | `nft -a list ruleset` |
| `iptables -P INPUT DROP` | `policy drop;` in the declaration of the base chain (section @@ref:nft-edit@@) |
| `iptables -A INPUT …` | `nft add rule inet filter input …` |
| `iptables -I INPUT …` | `nft insert rule inet filter input …` |
| `iptables -I INPUT 3 …` | `nft insert rule inet filter input handle N …` (N: the handle of the rule that must follow) |
| `iptables -R INPUT 3 …` | `nft replace rule inet filter input handle N …` |
| `iptables -D INPUT 3`, or `iptables -D INPUT` followed by the rule | `nft delete rule inet filter input handle N` (by handle only) |
| `iptables -N logdrop`, `-j logdrop`, `-g logdrop`, `-j RETURN` | `nft add chain inet filter logdrop`, `jump logdrop`, `goto logdrop`, `return` |
| `iptables -F INPUT`, `iptables -F` | `nft flush chain inet filter input`, `nft flush table inet filter` |
| `iptables -X logdrop` | `nft delete chain inet filter logdrop` |
| `iptables-save > regles`, `iptables-restore < regles` | `nft -s list ruleset > regles`, `nft -f regles` |
| `iptables -t nat …` | a table and chains of type `nat` (section @@ref:nat@@) |

### @@sec:ipt-options@@ Matches and targets

| iptables | nftables |
|----------|----------|
| `-i eth0`, `-o eth0`, `-i eth+` | `iifname "eth0"`, `oifname "eth0"`, `iifname "eth*"` (or `iif eth0`, see below) |
| `-s 192.0.2.0/24`, `-d 192.0.2.1` | `ip saddr 192.0.2.0/24`, `ip daddr 192.0.2.1` |
| `! -s 192.0.2.0/24` | `ip saddr != 192.0.2.0/24` |
| `-p udp` | `meta l4proto udp` |
| `-p tcp --dport 22`, `-p tcp --sport 1024:65535` | `tcp dport 22`, `tcp sport 1024-65535` |
| `-p tcp -m multiport --dports 80,443` | `tcp dport { 80, 443 }` |
| `-m iprange --src-range 192.0.2.10-192.0.2.20` | `ip saddr 192.0.2.10-192.0.2.20` |
| `-p icmp --icmp-type echo-request` | `icmp type echo-request` |
| `-m state --state ESTABLISHED,RELATED`, `-m conntrack --ctstate NEW` | `ct state established,related`, `ct state new` |
| `-m mac --mac-source 02:00:00:00:00:01` | `ether saddr 02:00:00:00:00:01` |
| `-m owner --uid-owner www-data` | `meta skuid "www-data"` (section @@ref:skuid@@) |
| `-m comment --comment "SSH"` | `comment "SSH"`, at the end of the rule |
| `-m limit --limit 5/minute --limit-burst 10` | `limit rate 5/minute burst 10 packets` |
| `-m hashlimit --hashlimit-name ssh --hashlimit-mode srcip --hashlimit-above 3/minute` | `update @clients { ip saddr limit rate over 3/minute }` (section @@ref:limit-per-source@@) |
| `-m connlimit --connlimit-above 2` | `add @sessions { ip saddr ct count over 2 }` (section @@ref:limit-per-source@@) |
| `-m set --match-set blocklist src`, the set created by `ipset create blocklist hash:net` | `ip saddr @blocklist`, the set declared `type ipv4_addr; flags interval;` (section @@ref:named-sets@@) |
| `-m recent --name banned --set`, then `-m recent --name banned --rcheck --seconds 60 -j DROP` | `add @banned { ip saddr }`, then `ip saddr @banned drop`, the set declared `flags dynamic,timeout; timeout 60s;` (section @@ref:dynamic-sets@@) |
| `-m mark --mark 1`, `-j MARK --set-mark 1` | `meta mark 1`, `meta mark set 1` |
| `-j ACCEPT`, `-j DROP`, `-j RETURN` | `accept`, `drop`, `return` |
| `-j REJECT`, `-j REJECT --reject-with tcp-reset` | `reject`, `reject with tcp reset` |
| `-j LOG --log-prefix "input drop: "` | `log prefix "input drop: "` (followed, if need be, by a verdict in the same rule) |
| `-j NFLOG --nflog-group 0` | `log group 0` |
| `-j TRACE`, in the `raw` table | `meta nftrace set 1` (section @@ref:which-rule@@) |
| `-j MASQUERADE`, `-j SNAT --to-source A`, `-j DNAT --to-destination A:P`, `-j REDIRECT --to-ports P` | `masquerade`, `snat to A`, `dnat to A:P`, `redirect to :P` |

**`iifname` or `iif`?** The `-i` option of iptables compares the **name** of the interface, like
`iifname`. `iif` compares its **number** (its index): it is faster, but the interface must exist
when the rule is loaded, and an interface destroyed then created again (a tunnel, a `ppp`
interface, that of a container) gets another number, which the rule does not follow. `iif lo` is
therefore always fine; for an interface that comes and goes, write `iifname`.

### @@sec:ipt-translate@@ Translating automatically

The `iptables` package provides translators, which show the equivalent `nft` command without
changing anything in the firewall:

```
iptables-translate -A INPUT -i eth0 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
ip6tables-translate …                                    # the same for ip6tables
iptables-restore-translate -f regles.v4 > regles.nft     # a whole file written by iptables-save
```

The first command shows (give or take the version):

```
nft 'add rule ip filter INPUT iifname "eth0" tcp dport 22 ct state new counter accept'
```

The translation is **literal**: it targets the `ip filter` table and the `INPUT` chain that
`iptables-nft` creates (see below), adds `counter` to every rule, since iptables counts
everything, and uses `iifname`. Some extensions have no translation: always read the result
again. It is a starting point, to be rewritten into a real nftables file. To convert a firewall:

1. save the rules in place: `iptables-save > regles.v4` (and `ip6tables-save >
   regles.v6`);
2. translate them with `iptables-restore-translate -f regles.v4`, and read the result;
3. rewrite it into an nftables file (section @@ref:nft-files@@): a single `inet` table for IPv4
   and IPv6, lower-case names, sets instead of series of almost identical rules and of `ipset`,
   `counter` only where it is useful;
4. check the file (`nft -c -f`), load it, then remove the iptables rules and the service that
   reloaded them at boot (`netfilter-persistent` on Debian), in favour of the `nftables` service.

### @@sec:ipt-coexist@@ iptables on an nftables machine

On a recent Debian, the `iptables` command is **`iptables-nft`**: `iptables -V` shows
`iptables v1.8.11 (nf_tables)`. It keeps the syntax of iptables, but writes nftables rules, in
tables `ip filter`, `ip nat`, `ip6 filter`… with the chains `INPUT`, `FORWARD`, `OUTPUT`…, which
`nft list ruleset` shows next to yours. This is how Docker, for example, installs its rules. A
few consequences:

- these tables belong to iptables: they are read with `nft`, but only modified with `iptables`,
  whose rules use extensions only iptables knows how to handle;
- every table is crossed: a packet your `inet filter` table accepts can still be dropped by the
  `ip filter` table of iptables, on the same hook, and conversely (section
  @@ref:priorities@@);
- `nft flush ruleset` also erases these tables (section @@ref:pitfalls@@);
- the old engine, **`iptables-legacy`** (`iptables -V` then shows `(legacy)`), does not appear at
  all in `nft list ruleset`, but its rules apply all the same. Do not mix the two on one machine:
  `update-alternatives --config iptables` chooses the engine the `iptables` command designates.
""",
    "Aide-mémoire": "Cheat sheet",
    """

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter input` |
| table et chaîne de base | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'` |
| règles | `nft add rule inet filter input …` (fin), `nft insert rule inet filter input …` (début), `nft insert rule inet filter input handle N …` (avant la règle N), `nft add rule inet filter input handle N …` (après), `nft replace rule inet filter input handle N …`, `nft delete rule inet filter input handle N` |
| critères | `iif lo`, `ip saddr A.B.C.D`, `meta l4proto udp`, `tcp dport 8080`, `tcp dport { 80, 8080 }`, `icmp type echo-reply`, `ct state established,related` |
| verdicts et actions | `accept`, `drop`, `reject`, `jump logdrop`, `counter`, `log prefix "…" group 0`, `limit rate 5/minute` |
| chaîne régulière | `nft add chain inet filter logdrop`, `nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'`, `nft add rule inet filter logdrop counter drop`, `nft add rule inet filter input jump logdrop` |
| journal | `tcpdump -n -i nflog:0` (règles `log … group 0`) |
| chaîne output | `nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'`, `nft insert rule inet filter output ct state established,related accept`, `oif lo accept`, `ip daddr A.B.C.D reject`, `tcp dport 80 accept`, une règle `reject` finale, puis la même déclaration de chaîne avec `policy drop` |
| ensemble nommé | `nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'`, `nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'`, `nft insert rule inet filter input ip saddr @blocklist drop`, `nft list set inet filter blocklist`, `nft 'delete element inet filter blocklist { 192.0.2.7 }'` |
| ensemble de ports, de couples | `nft 'add set inet filter web_ports { type inet_service; }'` et `tcp dport @web_ports accept` ; `nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'`, `nft 'add element inet filter allowed { 192.0.2.2 . 22 }'` et `ip saddr . tcp dport @allowed accept` |
| ensemble alimenté par les règles | `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `tcp dport 23 add @banned { ip saddr } drop`, `ip saddr @banned drop` |
| remplacer une règle | `nft -a list chain inet filter output` (son handle), puis `nft replace rule inet filter output handle N …` |
| fichier de règles | `nft -c -f fichier` (vérifier), `nft -f fichier` (charger), `nft -s list ruleset > fichier` (sauvegarder) |
| tout effacer | `nft flush chain inet filter input`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `curl -m 3 http://m2/`, `curl -m 3 http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ping -c 2 -W 1 m2`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or tcp port 80` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""": """

| need | command |
|--------|----------|
| state of the firewall | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter input` |
| table and base chain | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'` |
| rules | `nft add rule inet filter input …` (end), `nft insert rule inet filter input …` (start), `nft insert rule inet filter input handle N …` (before rule N), `nft add rule inet filter input handle N …` (after), `nft replace rule inet filter input handle N …`, `nft delete rule inet filter input handle N` |
| selectors | `iif lo`, `ip saddr A.B.C.D`, `meta l4proto udp`, `tcp dport 8080`, `tcp dport { 80, 8080 }`, `icmp type echo-reply`, `ct state established,related` |
| verdicts and actions | `accept`, `drop`, `reject`, `jump logdrop`, `counter`, `log prefix "…" group 0`, `limit rate 5/minute` |
| regular chain | `nft add chain inet filter logdrop`, `nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'`, `nft add rule inet filter logdrop counter drop`, `nft add rule inet filter input jump logdrop` |
| log | `tcpdump -n -i nflog:0` (rules `log … group 0`) |
| output chain | `nft 'add chain inet filter output { type filter hook output priority 0; policy accept; }'`, `nft insert rule inet filter output ct state established,related accept`, `oif lo accept`, `ip daddr A.B.C.D reject`, `tcp dport 80 accept`, a final `reject` rule, then the same chain declaration with `policy drop` |
| named set | `nft 'add set inet filter blocklist { type ipv4_addr; flags interval; }'`, `nft 'add element inet filter blocklist { 192.0.2.7, 198.51.100.0/24 }'`, `nft insert rule inet filter input ip saddr @blocklist drop`, `nft list set inet filter blocklist`, `nft 'delete element inet filter blocklist { 192.0.2.7 }'` |
| set of ports, of pairs | `nft 'add set inet filter web_ports { type inet_service; }'` and `tcp dport @web_ports accept`; `nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'`, `nft 'add element inet filter allowed { 192.0.2.2 . 22 }'` and `ip saddr . tcp dport @allowed accept` |
| set fed by the rules | `nft 'add set inet filter banned { type ipv4_addr; flags dynamic,timeout; timeout 60s; }'`, `tcp dport 23 add @banned { ip saddr } drop`, `ip saddr @banned drop` |
| replace a rule | `nft -a list chain inet filter output` (its handle), then `nft replace rule inet filter output handle N …` |
| rules file | `nft -c -f file` (check), `nft -f file` (load), `nft -s list ruleset > file` (save) |
| erase everything | `nft flush chain inet filter input`, `nft delete table inet filter`, `nft flush ruleset` |
| tests | `curl -m 3 http://m2/`, `curl -m 3 http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ping -c 2 -W 1 m2`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or tcp port 80` |
| follow a packet | `… counter …` then `nft list ruleset`; `meta nftrace set 1` and `nft monitor trace` |
""",
    """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (switch `lan`) | `{lan}` | **`m1`** (`{m1}`, **le pare-feu à configurer**), `m2` (`{m2}`), `m3` (`{m3}`), `gw` eth0 (`{gw_lan}`, la passerelle) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `ext2` (`{ext2}`), `ext3` (`{ext3}`), `gw` eth1 (`{gw_ext}`) |
| `guest` (le réseau des invités) | `{guest}` | `guest1` (`{guest1}`), `gw` eth2 (`{gw_guest}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan` (switch `lan`) | `{lan}` | **`m1`** (`{m1}`, **the firewall to configure**), `m2` (`{m2}`), `m3` (`{m3}`), `gw` eth0 (`{gw_lan}`, the gateway) |
| `ext` ("the outside") | `{ext}` | `ext1` (`{ext1}`), `ext2` (`{ext2}`), `ext3` (`{ext3}`), `gw` eth1 (`{gw_ext}`) |
| `guest` (the guest network) | `{guest}` | `guest1` (`{guest1}`), `gw` eth2 (`{gw_guest}`) |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente les pare-feux, Netfilter et nftables (hooks, tables,
chaînes, règles, critères, verdicts, suivi de connexion), le filtrage de ce qui sort, la commande
`nft`, la journalisation, les ensembles et la façon de tester un pare-feu.

**La maquette** (onglet *Schéma*) : un réseau local `lan` avec trois machines `m1`, `m2`, `m3` et
une passerelle `gw`, qui route vers un réseau `ext`, « l'extérieur », où se trouvent `ext1`, `ext2`
et `ext3`, et vers un réseau `guest`, celui des invités, où se trouve `guest1`. Vous configurez le
pare-feu de **`m1`** et de `m1` seulement : les autres machines servent de clients (et de serveurs)
pour vos tests. Les questions 1 à 9 n'utilisent que `m2`, `m3` et `ext1`.
""": """
Read the **Informations** tab: it presents firewalls, Netfilter and nftables (hooks, tables,
chains, rules, selectors, verdicts, connection tracking), filtering what leaves, the `nft`
command, logging, sets and the way to test a firewall.

**The setup** (*Schema* tab): a local network `lan` with three machines `m1`, `m2`, `m3` and a
gateway `gw`, which routes to a network `ext`, "the outside", where `ext1`, `ext2` and `ext3` are,
and to a network `guest`, the guest network, where `guest1` is. You configure the firewall of
**`m1`** and of `m1` only: the other machines act as clients (and servers) for your tests.
Questions 1 to 9 only use `m2`, `m3` and `ext1`.
""",
    """
Déjà en place (ne pas modifier) : les adresses, la route par défaut de toutes les machines vers
`gw`, le routage sur `gw`, les noms dans `/etc/hosts` (`m1`, `m2`, `m3`, `gw`, `gw_ext`,
`gw_guest`, `ext1`, `ext2`, `ext3`, `guest1`). Il n'y a pas de DNS. Sur **chaque** machine tourne
un **serveur de test** HTTP (ports TCP **80**, **8080** et **8888**) et UDP (ports **530** et
**630**) qui répond par son nom, les adresses et ports des deux bouts et le TTL du paquet reçu
(`curl http://m2/`, `curl http://ext1:8080/`, `echo bonjour | nc -u -w 1 m2 530` ;
section @@ref:testing@@ des Informations). Le jeu de règles nftables de toutes les machines est
vide au départ.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place : l'évaluation vérifie le jeu de règles **final** (une seule table, `inet filter` : sa
  chaîne de base `input`, puis, à partir de la question 10 seulement, sa chaîne `output` ; ne
  filtrez jamais `forward`) ;
- les questions 10 à 14 **complètent** le pare-feu des questions 2 à 9 sans rien en défaire : à la
  fin du TP, tout ce que les questions précédentes demandent doit encore fonctionner ;
- travaillez dans **votre** table, `inet filter`, créée à la main (`nft add table inet filter`)
  ou déclarée dans un fichier (méthode conseillée plus bas) ; les règles tapées avec `nft` sont
  volatiles : elles ne survivent pas à un redémarrage de la machine ;
- l'évaluation lit le jeu de règles de `m1` (`nft list ruleset`) et le **recopie sur une machine
  cachée identique** à `m1` (mêmes adresses, mêmes serveurs de test), qu'elle sonde depuis des
  copies cachées des autres machines : seul ce que dit **le jeu de règles chargé sur `m1`**
  compte, pas l'état de ses serveurs ni ce que vous faites sur les autres machines ;
- pour tester sans attendre, utilisez des délais courts : `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `nc -u -w 1 …`.

**Méthode conseillée : le pare-feu dans un fichier.** Plutôt que de taper les règles une à une,
écrivez le pare-feu de `m1` dans **`/etc/nftables.conf`**, complétez-le de question en question et
rechargez-le d'un bloc (section @@ref:nft-files@@ des Informations) : plus de guillemets pour le
shell, ni de handle à chercher pour placer une règle (on l'écrit à sa place), et des commentaires
(`#`) pour s'y retrouver. Le fichier existe déjà : le paquet Debian y a mis un squelette, une table
`inet filter` aux chaînes vides `input`, `forward` et `output`. Remplacez-le à partir de la
question 2 (la question 1 observe `m1` sans pare-feu) en gardant cette forme :

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                # la déclaration de la chaîne de base (question 2), puis ses règles,
                # dans l'ordre où les paquets doivent les rencontrer
        }
        # à partir de la question 10 : chain output { … } ; questions 11 à 14 : les ensembles
}
```

Après chaque modification (`nano /etc/nftables.conf`, ou `vim`) :

```
nft -c -f /etc/nftables.conf      # vérifie sans rien changer ; aucun message : correct
nft -f /etc/nftables.conf         # remplace tout le jeu de règles par celui du fichier
nft -a list ruleset               # ce qui est réellement chargé (avec les handles)
```

- chaque erreur est signalée par le nom du fichier, les numéros de ligne et de colonne, et des
  `^^^` sous le mot fautif. Le chargement est atomique : en cas d'erreur, **rien** ne change et l'ancien
  jeu de règles reste en place ;
- **l'évaluation ne lit pas le fichier**, seulement le jeu de règles chargé sur `m1` : un fichier
  modifié mais pas rechargé ne compte pas, et aucun service ne le charge dans les machines du TP ;
- `flush ruleset` en tête : recharger le fichier remplace tout, sans doublon (aucune autre table
  n'est à garder sur `m1`). Cela remet aussi à zéro les compteurs et vide les ensembles remplis par
  les règles (question 14) ;
- les questions qui font pratiquer une commande (`nft insert rule`, `nft replace rule … handle`,
  `nft add element`, un changement de politique) se font dans le fichier par la modification
  correspondante : la règle écrite à sa place, l'élément ajouté à la liste, la politique changée.
  Essayez la commande si vous voulez, mais reportez **toute** modification dans le fichier : le
  prochain `nft -f` efface ce qu'il ne contient pas ;
- déjà commencé à la main ? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  transforme le jeu de règles en place en fichier.
""": """
Already in place (do not modify): the addresses, the default route of every machine through `gw`,
routing on `gw`, the names in `/etc/hosts` (`m1`, `m2`, `m3`, `gw`, `gw_ext`, `gw_guest`, `ext1`,
`ext2`, `ext3`, `guest1`). There is no DNS. On **every** machine runs an HTTP (TCP ports **80**,
**8080** and **8888**) and UDP (ports **530** and **630**) **test server** that answers with its
name, the addresses and ports of both ends and the TTL of the packet received
(`curl http://m2/`, `curl http://ext1:8080/`, `echo bonjour | nc -u -w 1 m2 530`;
section @@ref:testing@@ of the Informations tab). The nftables ruleset of every machine is empty at
the start.

Rules for the whole lab:

- the questions are to be done **in order** and the configuration of a finished question stays in
  place: the evaluation checks the **final** ruleset (a single table, `inet filter`: its base chain
  `input`, then, from question 10 only, its `output` chain; never filter `forward`);
- questions 10 to 14 **complete** the firewall of questions 2 to 9 without undoing any of it: at
  the end of the lab, everything the earlier questions ask for must still work;
- work in **your** table, `inet filter`, created by hand (`nft add table inet filter`) or declared
  in a file (recommended method below); the rules typed with `nft` are volatile: they do not
  survive a reboot of the machine;
- the evaluation reads the ruleset of `m1` (`nft list ruleset`) and **copies it onto a hidden
  machine identical** to `m1` (same addresses, same test servers), which it probes from hidden
  copies of the other machines: only what **the ruleset loaded on `m1`** says counts, not the
  state of its servers nor what you do on the other machines;
- to test without waiting, use short timeouts: `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `nc -u -w 1 …`.

**Recommended method: the firewall in a file.** Rather than typing the rules one by one, write the
firewall of `m1` in **`/etc/nftables.conf`**, complete it question after question and reload it in
one go (section @@ref:nft-files@@ of the Informations tab): no more quotes for the shell, no handle to
look up to place a rule (you write it in its place), and comments (`#`) to find your way. The file
already exists: the Debian package put a skeleton in it, an `inet filter` table with empty chains
`input`, `forward` and `output`. Replace it from question 2 onwards (question 1 observes `m1`
without a firewall), keeping this form:

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
        chain input {
                # the declaration of the base chain (question 2), then its rules,
                # in the order in which the packets must meet them
        }
        # from question 10: chain output { … }; questions 11 to 14: the sets
}
```

After each change (`nano /etc/nftables.conf`, or `vim`):

```
nft -c -f /etc/nftables.conf      # checks without changing anything; no message: correct
nft -f /etc/nftables.conf         # replaces the whole ruleset with that of the file
nft -a list ruleset               # what is really loaded (with the handles)
```

- each error is reported with the name of the file, the line and column numbers, and `^^^` under
  the faulty word. Loading is atomic: in case of an error, **nothing** changes and the old ruleset
  stays in place;
- **the evaluation does not read the file**, only the ruleset loaded on `m1`: a file modified but
  not reloaded does not count, and no service loads it in the machines of the lab;
- `flush ruleset` at the top: reloading the file replaces everything, without duplicates (no other
  table is to be kept on `m1`). It also resets the counters and empties the sets filled by the
  rules (question 14);
- the questions that practise a command (`nft insert rule`, `nft replace rule … handle`,
  `nft add element`, a change of policy) are done in the file by the matching change: the rule
  written in its place, the element added to the list, the policy changed. Try the command if you
  like, but carry **every** change over into the file: the next `nft -f` erases what it does not
  contain;
- already started by hand? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  turns the ruleset in place into a file.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) vide le jeu de règles de `m1` puis
applique toute la solution et remplit les formulaires ; il est ré-applicable et une évaluation
lancée juste après donne 140/140 et les 6 points de bonus (questions 1 à 9 : 100 points ; questions
10 à 13 : 40 points ; question 14 : bonus). Le fichier `/etc/nftables.conf` n'est qu'une méthode
conseillée aux étudiants : l'évaluation ne le lit pas (seul compte le jeu de règles chargé), et
l'état `final` passe par des commandes `nft`.

**Aucune question n'en pénalise une autre.** La chaîne `output` de la question 10 autorise tout ce
que les sondes des questions 1 à 9 font émettre à `m1` (`lo`, `ping`, TCP {closed}, UDP {udp_port} et
{udp_other}, et toutes ses réponses par la règle à états, message d'erreur du `reject` de la
question 6 compris) ; les restrictions des questions 10 à 14 ne s'observent que sur des machines et
des ports que les questions 1 à 9 ne sondent pas (`ext2`, `ext3`, `guest1`, les ports {set_port} et
{trap}, le port {open} en sortie) ; leurs règles de `input` sont insérées, aucune règle déjà évaluée
n'est réécrite. En revanche c'est le jeu de règles **final** qui est évalué : une chaîne `output`
**fausse** fait perdre les points de ce qu'elle casse réellement (sans `related`, `m2` n'est plus
prévenue du refus de la question 6 ; sans règle à états, le port {open} ne répond plus à personne).

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` sur `m1`
(étape 1), chargé tel quel sur `{fw_h}` après un `nft flush ruleset` (étape 2 ; un jeu de règles
vide laisse la copie sans filtre ; les ensembles alimentés par les règles ou à délai d'expiration y
sont vidés : une adresse bannie sur `m1` pendant vos essais ne fausse rien), puis les sondes
(étape 3) depuis les copies cachées de `m2`, `m3`, `ext1`, `ext2`, `ext3`, `guest1` et depuis
`{fw_h}` elle-même : `curl` des serveurs de test (HTTP {closed} / {open} / {set_port}), `nc -u`
(UDP {udp_port}), `ping`, connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert,
`RC=124` détruit, autre code refusé). La question 14 ajoute une connexion au port {trap} (étape 4)
puis deux sondes (étape 5). Les copies cachées répondent sous les noms visibles (`SERVER=m2`…). La
structure du jeu de règles (politique, critères, verdicts, ordre, `log` / `limit`, ensembles) est
lue dans `nft -j list ruleset` de `m1` : les chaînes de base des hooks `input` et `output`, famille
`inet` ou `ip`. Ce que le pare-feu **laisse passer** (sondes positives) ne compte qu'une fois la
politique `drop` en place : un jeu de règles vide laisse tout passer et vaut 0 ; ce qu'il **arrête**
ne compte que si une sonde témoin passe. Une évaluation dure une vingtaine de secondes (les sondes
que le pare-feu doit détruire attendent {timeout} s). Les machines ne peuvent pas lire le journal du
noyau (pas de `CAP_SYSLOG`) : la question 9 journalise vers nflog (`log … group {group}`,
`tcpdump -n -i nflog:0`), mais toute règle `log` est acceptée.
""": """
**For the instructor.** Each question ends with its solution, computed for the addresses of this
project. The `final` state (*Apply Configuration* tab) empties the ruleset of `m1` then applies
the whole solution and fills in the forms; it can be applied again and an evaluation run right
after gives 140/140 and the 6 bonus points (questions 1 to 9: 100 points; questions 10 to 13: 40
points; question 14: bonus). The file `/etc/nftables.conf` is only a method recommended to the
students: the evaluation does not read it (only the loaded ruleset counts), and the `final` state
goes through `nft` commands.

**No question penalises another.** The `output` chain of question 10 allows everything the probes
of questions 1 to 9 make `m1` send (`lo`, `ping`, TCP {closed}, UDP {udp_port} and {udp_other},
and all its replies through the stateful rule, the error message of the `reject` of question 6
included); the restrictions of questions 10 to 14 are only observed on machines and ports that
questions 1 to 9 do not probe (`ext2`, `ext3`, `guest1`, ports {set_port} and {trap}, port {open}
on the way out); their `input` rules are inserted, no rule already evaluated is rewritten. On the
other hand it is the **final** ruleset that is evaluated: a **wrong** `output` chain loses the
points of what it really breaks (without `related`, `m2` is no longer notified of the refusal of
question 6; without a stateful rule, port {open} no longer answers anybody).

The evaluation (hidden mirror, `lib/hidden_mirror.py` / `lib/firewall.py`): `nft list ruleset` on
`m1` (step 1), loaded as is on `{fw_h}` after an `nft flush ruleset` (step 2; an empty ruleset
leaves the copy without a filter; the sets fed by the rules or with a timeout are emptied there: an
address banned on `m1` during your tries does not skew anything), then the probes (step 3) from
the hidden copies of `m2`, `m3`, `ext1`, `ext2`, `ext3`, `guest1` and from `{fw_h}` itself: `curl`
of the test servers (HTTP {closed} / {open} / {set_port}), `nc -u` (UDP {udp_port}), `ping`, TCP
connections through `bash` (`/dev/tcp`, timeout {timeout} s: `RC=0` open, `RC=124` dropped, any
other code refused). Question 14 adds a connection to port {trap} (step 4) then two probes (step
5). The hidden copies answer under the visible names (`SERVER=m2`…). The structure of the ruleset
(policy, selectors, verdicts, order, `log` / `limit`, sets) is read from `nft -j list ruleset` of
`m1`: the base chains of the `input` and `output` hooks, family `inet` or `ip`. What the firewall
**lets through** (positive probes) only counts once the `drop` policy is in place: an empty ruleset
lets everything through and is worth 0; what it **stops** only counts if a control probe gets
through. An evaluation takes about twenty seconds (the probes the firewall must drop wait
{timeout} s). The machines cannot read the kernel log (no `CAP_SYSLOG`): question 9 logs to nflog
(`log … group {group}`, `tcpdump -n -i nflog:0`), but any `log` rule is accepted.
""",
    "Partie 1 — Avant le pare-feu (question 1)": "Part 1 — Before the firewall (question 1)",
    "Tests avant le pare-feu": "Tests before the firewall",
    """
Depuis `m1`, vérifiez que tout fonctionne : les serveurs de test de `m2` (`{m2}`), `m3` (`{m3}`)
et `ext1` (`{ext1}`, à travers `gw`) en HTTP (`curl http://m2/`, `curl http://m3:8080/`,
`curl http://ext1/`) et en UDP (`echo bonjour | nc -u -w 1 m2 530`, `echo bonjour | nc -u -w 1
ext1 630`), et les `ping` vers `m2` et `ext1`. Lisez les lignes `TTL=` et `CLIENT_IP=` des
réponses. Faites les mêmes essais depuis `m2` vers `m1` (`curl http://m1/`…). Sur `m1`, affichez
les ports en écoute (`ss -tulnp`) et l'état du pare-feu (`nft list ruleset`).
""": """
From `m1`, check that everything works: the test servers of `m2` (`{m2}`), `m3` (`{m3}`) and
`ext1` (`{ext1}`, through `gw`) in HTTP (`curl http://m2/`, `curl http://m3:8080/`,
`curl http://ext1/`) and in UDP (`echo bonjour | nc -u -w 1 m2 530`, `echo bonjour | nc -u -w 1
ext1 630`), and the `ping` to `m2` and `ext1`. Read the `TTL=` and `CLIENT_IP=` lines of the
answers. Do the same tries from `m2` to `m1` (`curl http://m1/`…). On `m1`, show the listening
ports (`ss -tulnp`) and the state of the firewall (`nft list ruleset`).
""",
    """
- `TTL=` dans la réponse de `m2` : @@{ttl_lan:[0-9]+}@@
- `TTL=` dans la réponse de `ext1` : @@{ttl_ext:[0-9]+}@@
- `CLIENT_IP=` dans la réponse de `ext1` : @@{client_ip:[0-9.]+}@@
- `nft list ruleset` sur `m1` affiche : @@{ruleset:>rien : aucune table ni règle, tout est accepté>>>empty|une table filter dont la chaîne input a la politique drop>>>drop|les règles installées par Docker>>>docker|une erreur : nft n'est pas installé>>>error}@@
""": """
- `TTL=` in the answer of `m2`: @@{ttl_lan:[0-9]+}@@
- `TTL=` in the answer of `ext1`: @@{ttl_ext:[0-9]+}@@
- `CLIENT_IP=` in the answer of `ext1`: @@{client_ip:[0-9.]+}@@
- `nft list ruleset` on `m1` shows: @@{ruleset:>nothing: no table or rule, everything is accepted>>>empty|a filter table whose input chain has the drop policy>>>drop|the rules installed by Docker>>>docker|an error: nft is not installed>>>error}@@
""",
    """
**Solution.** Rien à configurer. `TTL=64` depuis `m2` (même réseau), `TTL=63` depuis `ext1` (un
routeur traversé, `gw`), `CLIENT_IP={m1}` (pas de traduction d'adresses sur `gw`), et `nft list
ruleset` n'affiche rien : le jeu de règles est vide, tout passe. `ss -tulnp` montre un `python3` en
écoute sur `0.0.0.0:80`, `:8080` (TCP) et `:530`, `:630` (UDP).

- Réponses : 64 ; 63 ; `{m1}` ; rien.
- Cette question n'est évaluée que par le formulaire.
""": """
**Solution.** Nothing to configure. `TTL=64` from `m2` (same network), `TTL=63` from `ext1` (one
router crossed, `gw`), `CLIENT_IP={m1}` (no address translation on `gw`), and `nft list
ruleset` shows nothing: the ruleset is empty, everything gets through. `ss -tulnp` shows a
`python3` listening on `0.0.0.0:80`, `:8080` (TCP) and `:530`, `:630` (UDP).

- Answers: 64; 63; `{m1}`; nothing.
- This question is only graded through the form.
""",
    "avant le pare-feu : TTL depuis m2 et ext1, CLIENT_IP vu par ext1": "before the firewall: TTL from m2 and ext1, CLIENT_IP seen by ext1",
    "avant le pare-feu : jeu de règles vide": "before the firewall: empty ruleset",
    "Partie 2 — Politique par défaut (question 2)": "Part 2 — Default policy (question 2)",
    "Politique par défaut": "Default policy",
    """
Sur `m1`, créez une table **`filter`** de la famille **`inet`** et, dedans, une chaîne de base
**`input`** de type `filter`, accrochée au hook `input`, de priorité 0 et de politique **`drop`**
(section @@ref:structure@@ des Informations). Vérifiez avec `nft list ruleset`, puis que plus rien
n'entre : depuis `m2`, `curl -m 3 http://m1/` et `ping -c 2 -W 1 m1` échouent. Refaites alors les
essais de la question 1 **depuis `m1`** (`curl -m 3 http://m2/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m2`) : ils échouent aussi. Pourquoi ?
""": """
On `m1`, create a table **`filter`** of the **`inet`** family and, in it, a base chain **`input`**
of type `filter`, attached to the `input` hook, with priority 0 and policy **`drop`** (section
@@ref:structure@@ of the Informations tab). Check with `nft list ruleset`, then that nothing gets in
any more: from `m2`, `curl -m 3 http://m1/` and `ping -c 2 -W 1 m1` fail. Then do the tries of
question 1 again **from `m1`** (`curl -m 3 http://m2/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m2`): they fail too. Why?
""",
    """
- pourquoi `m1` ne joint-elle plus `m2`, alors que seule la chaîne `input` filtre ? @@{why:>les requêtes de m1 partent (output n'est pas filtré) mais les réponses de m2 arrivent dans input et sont détruites : la connexion n'aboutit pas>>>replies_dropped|la politique drop s'applique à toutes les chaînes, output comprise>>>all_chains|m2 ne reçoit plus les requêtes de m1>>>no_requests|la table inet ne gère pas IPv4>>>inet_ipv6}@@
""": """
- why does `m1` no longer reach `m2`, although only the `input` chain filters? @@{why:>the requests of m1 leave (output is not filtered) but the replies of m2 arrive in input and are dropped: the connection does not complete>>>replies_dropped|the drop policy applies to all the chains, output included>>>all_chains|m2 no longer receives the requests of m1>>>no_requests|the inet table does not handle IPv4>>>inet_ipv6}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

`nft list ruleset` affiche la table et la chaîne vide avec `policy drop`. Tout ce qui arrive sur
`m1` est détruit, y compris les **réponses** (SYN-ACK de `m2`, datagrammes UDP de retour, `echo-reply`)
à ce que `m1` émet : les requêtes partent (`output` n'est pas filtré), rien ne revient, `curl` et
`nc` expirent, `ping` perd tout.

- Réponse : les réponses de m2 sont détruites dans input.
- L'évaluation lit `nft -j list ruleset` sur `m1` : une chaîne de base de type `filter` accrochée au
  hook `input` (famille `inet` ou `ip`) avec `policy drop`, de priorité 0.
""": """
**Solution.** On `m1`:

```
{cmds}```

`nft list ruleset` shows the table and the empty chain with `policy drop`. Everything that arrives
on `m1` is dropped, including the **replies** (SYN-ACK of `m2`, return UDP datagrams,
`echo-reply`) to what `m1` sends: the requests leave (`output` is not filtered), nothing comes
back, `curl` and `nc` time out, `ping` loses everything.

- Answer: the replies of m2 are dropped in input.
- The evaluation reads `nft -j list ruleset` on `m1`: a base chain of type `filter` attached to
  the `input` hook (family `inet` or `ip`) with `policy drop`, with priority 0.
""",
    "une chaîne de base du hook input avec la politique drop": "a base chain of the input hook with the drop policy",
    "la chaîne input est de type filter, priorité 0": "the input chain is of type filter, priority 0",
    "pourquoi m1 ne joint plus m2 : les réponses sont détruites dans input": "why m1 no longer reaches m2: the replies are dropped in input",
    "Partie 3 — Filtrage par interface (question 3)": "Part 3 — Filtering by interface (question 3)",
    "Filtrage par interface : la boucle locale": "Filtering by interface: the loopback",
    """
Sur `m1`, essayez `curl -m 3 http://127.0.0.1/` : le serveur de test de `m1` elle-même ne répond
plus, car les paquets locaux passent par `output` **puis** par `input`, via l'interface `lo`
(section @@ref:hooks@@ des Informations). Ajoutez à la chaîne `input` une règle acceptant tout ce
qui arrive par l'interface **`lo`** (critère `iif`, section @@ref:selectors@@), et vérifiez que
`curl http://127.0.0.1/` et `curl http://localhost:8080/` fonctionnent de nouveau.
""": """
On `m1`, try `curl -m 3 http://127.0.0.1/`: the test server of `m1` itself no longer answers,
because local packets go through `output` **then** through `input`, via the `lo` interface
(section @@ref:hooks@@ of the Informations tab). Add to the `input` chain a rule accepting everything
that arrives through the **`lo`** interface (selector `iif`, section @@ref:selectors@@), and check
that `curl http://127.0.0.1/` and `curl http://localhost:8080/` work again.
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

(`iifname "lo"` convient aussi.) Toute machine avec un pare-feu `policy drop` a cette règle en
tête : sans elle, les services locaux (bases de données, résolveur, X11…) ne se joignent plus.

- L'évaluation cherche dans `input` une règle `accept` dont le critère `iif` ou `iifname` est `lo`,
  et vérifie que `curl http://127.0.0.1/` répond sur la copie cachée de `m1`.
""": """
**Solution.** On `m1`:

```
{cmds}```

(`iifname "lo"` works too.) Every machine with a `policy drop` firewall has this rule at the top:
without it, local services (databases, resolver, X11…) can no longer reach each other.

- The evaluation looks in `input` for an `accept` rule whose `iif` or `iifname` selector is `lo`,
  and checks that `curl http://127.0.0.1/` answers on the hidden copy of `m1`.
""",
    "une règle accept pour l'interface lo (iif / iifname)": "an accept rule for the lo interface (iif / iifname)",
    "sur m1, curl http://127.0.0.1/ répond (serveur local joignable à travers le pare-feu)": "on m1, curl http://127.0.0.1/ answers (local server reachable through the firewall)",
    "Partie 4 — Filtrage par protocole (question 4)": "Part 4 — Filtering by protocol (question 4)",
    "Filtrage par protocole : ICMP": "Filtering by protocol: ICMP",
    """
Ajoutez à la chaîne `input` de `m1` une règle acceptant les paquets ICMP de type **`echo-reply`**
(les réponses aux `ping`, critère `icmp type` ; `nft describe icmp type` liste les types).
Vérifiez que `m1` peut de nouveau pinguer `m2` (`{m2}`) et `ext1` (`{ext1}`), mais que `m2` ne
peut toujours pas pinguer `m1` : ses requêtes (`echo-request`) sont détruites. Observez-les avec
`tcpdump -n -i eth0 icmp` sur `m1`.
""": """
Add to the `input` chain of `m1` a rule accepting the ICMP packets of type **`echo-reply`** (the
replies to `ping`, selector `icmp type`; `nft describe icmp type` lists the types). Check that
`m1` can ping `m2` (`{m2}`) and `ext1` (`{ext1}`) again, but that `m2` still cannot ping `m1`: its
requests (`echo-request`) are dropped. Observe them with `tcpdump -n -i eth0 icmp` on `m1`.
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

`m1` reçoit les réponses à ses propres `ping` ; les `echo-request` de `m2` sont détruits par la
politique (`tcpdump` sur `m1` les voit arriver, sans réponse). Accepter `icmp type echo-request`
rendrait `m1` pingable ; la règle à états de la question 7 acceptera aussi les `echo-reply` (une
réponse est `established`), mais la règle explicite reste.

- L'évaluation : `ping` de la copie de `m1` vers `m2` et `ext1` (réponses), `ping` de la copie de
  `m2` vers `m1` (doit échouer), une règle `accept` avec `icmp type echo-reply`.
""": """
**Solution.** On `m1`:

```
{cmds}```

`m1` receives the replies to its own `ping`; the `echo-request` of `m2` are dropped by the policy
(`tcpdump` on `m1` sees them arrive, without a reply). Accepting `icmp type echo-request` would
make `m1` pingable; the stateful rule of question 7 will also accept the `echo-reply` (a reply is
`established`), but the explicit rule stays.

- The evaluation: `ping` from the copy of `m1` to `m2` and `ext1` (replies), `ping` from the copy
  of `m2` to `m1` (must fail), an `accept` rule with `icmp type echo-reply`.
""",
    "m1 pingue m2 et ext1 (les echo-reply entrent)": "m1 pings m2 and ext1 (the echo-reply get in)",
    "m2 ne pingue pas m1 (les echo-request sont détruits)": "m2 does not ping m1 (the echo-request are dropped)",
    "une règle accept avec icmp type echo-reply": "an accept rule with icmp type echo-reply",
    "Partie 5 — Filtrage par protocole et adresse source (question 5)": "Part 5 — Filtering by protocol and source address (question 5)",
    "Filtrage par protocole et adresse source : UDP": "Filtering by protocol and source address: UDP",
    """
`ext1` (`{ext1}`) joue le rôle d'un serveur de l'extérieur que `m1` interroge en UDP (comme un
serveur DNS). Ajoutez à la chaîne `input` de `m1` une règle acceptant **tous les paquets UDP venant
de `ext1`** (critères `ip saddr` et `meta l4proto`). Vérifiez que `echo bonjour | nc -u -w 1 ext1
530` (et 630) fonctionne depuis `m1`, alors que `echo bonjour | nc -u -w 1 m2 530` ne fonctionne
toujours pas : la réponse de `m2` est un paquet UDP venant de `m2`. Puis, **depuis `ext1`**, essayez
`echo bonjour | nc -u -w 1 m1 530` : `ext1` obtient-elle une réponse du serveur UDP de `m1` ?
""": """
`ext1` (`{ext1}`) plays the part of a server of the outside that `m1` queries over UDP (like a DNS
server). Add to the `input` chain of `m1` a rule accepting **all the UDP packets coming from
`ext1`** (selectors `ip saddr` and `meta l4proto`). Check that `echo bonjour | nc -u -w 1 ext1
530` (and 630) works from `m1`, whereas `echo bonjour | nc -u -w 1 m2 530` still does not work:
the reply of `m2` is a UDP packet coming from `m2`. Then, **from `ext1`**, try
`echo bonjour | nc -u -w 1 m1 530`: does `ext1` get an answer from the UDP server of `m1`?
""",
    """
- depuis `ext1`, `nc -u m1 530` obtient-il une réponse ? @@{ext1_queries:>oui : la règle accepte tout datagramme UDP venant de ext1, requête ou réponse, elle ne distingue pas le sens de l'échange>>>yes_stateless|non : seules les réponses aux requêtes de m1 passent>>>answers_only|non : ext1 est dans un autre réseau IP, ses paquets sont routés et détruits par gw>>>other_network|oui, mais seulement sur le port 630>>>only_630}@@
""": """
- from `ext1`, does `nc -u m1 530` get an answer? @@{ext1_queries:>yes: the rule accepts every UDP datagram coming from ext1, request or reply, it does not tell the direction of the exchange>>>yes_stateless|no: only the replies to the requests of m1 get through>>>answers_only|no: ext1 is in another IP network, its packets are routed and dropped by gw>>>other_network|yes, but only on port 630>>>only_630}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

(`ip protocol udp` convient aussi.) Les réponses du serveur UDP de `ext1` entrent, celles de `m2`
non. Mais le filtre est **sans état** : il accepte aussi les **requêtes** UDP que `ext1` envoie à
`m1` (`nc -u m1 530` depuis `ext1` est servi, `TTL=63`). La règle à états de la question 7 est la
bonne réponse au besoin « recevoir les réponses à mes requêtes » ; celle-ci ouvre plus que voulu.

- Réponse : oui, la règle ne distingue pas le sens.
- L'évaluation : `nc -u` de la copie de `m1` vers `ext1` (ports {p0} et {p1}), de la copie de `ext1`
  vers `m1` (port {p0}, conséquence de la règle sans état), une règle `accept` avec `ip saddr {ext1}`
  et le protocole `udp`.
""": """
**Solution.** On `m1`:

```
{cmds}```

(`ip protocol udp` works too.) The replies of the UDP server of `ext1` get in, those of `m2` do
not. But the filter is **stateless**: it also accepts the UDP **requests** `ext1` sends to `m1`
(`nc -u m1 530` from `ext1` is served, `TTL=63`). The stateful rule of question 7 is the right
answer to the need "receive the replies to my requests"; this one opens more than wanted.

- Answer: yes, the rule does not tell the direction.
- The evaluation: `nc -u` from the copy of `m1` to `ext1` (ports {p0} and {p1}), from the copy of
  `ext1` to `m1` (port {p0}, a consequence of the stateless rule), an `accept` rule with
  `ip saddr {ext1}` and the `udp` protocol.
""",
    "m1 obtient les réponses UDP de ext1 (ports {p0} et {p1})": "m1 gets the UDP replies of ext1 (ports {p0} and {p1})",
    "ext1 interroge le serveur UDP de m1 (règle sans état : tout l'UDP de ext1 entre)": "ext1 queries the UDP server of m1 (stateless rule: all the UDP of ext1 gets in)",
    "une règle accept pour l'UDP venant de ext1 (ip saddr + udp)": "an accept rule for the UDP coming from ext1 (ip saddr + udp)",
    "le filtre sans état accepte aussi les requêtes UDP de ext1": "the stateless filter also accepts the UDP requests of ext1",
    "Partie 6 — drop ou reject (question 6)": "Part 6 — drop or reject (question 6)",
    "Différence entre drop et reject": "Difference between drop and reject",
    """
Ajoutez à la chaîne `input` de `m1` une règle **rejetant** (`reject`) tous les paquets venant de
`m2` (`{m2}`) ; ceux de `m3` (`{m3}`) restent détruits par la politique `drop`. Comparez, en lisant
les messages d'erreur et le temps de réponse (section @@ref:testing@@ des Informations) :

- depuis `m2` : `curl -m 5 http://m1/` ;
- depuis `m3` : `curl -m 5 http://m1/` ;
- depuis `m1` : `curl -m 5 http://m2/` puis `curl -m 5 http://m3/`.

Pendant l'essai depuis `m2`, capturez sur `m2` avec `tcpdump -n -i eth0 'icmp or tcp port 80'` :
que reçoit `m2` de `m1` ?
""": """
Add to the `input` chain of `m1` a rule **rejecting** (`reject`) all the packets coming from `m2`
(`{m2}`); those of `m3` (`{m3}`) are still dropped by the `drop` policy. Compare, reading the
error messages and the response time (section @@ref:testing@@ of the Informations tab):

- from `m2`: `curl -m 5 http://m1/`;
- from `m3`: `curl -m 5 http://m1/`;
- from `m1`: `curl -m 5 http://m2/` then `curl -m 5 http://m3/`.

During the try from `m2`, capture on `m2` with `tcpdump -n -i eth0 'icmp or tcp port 80'`: what
does `m2` receive from `m1`?
""",
    """
- depuis `m2`, `curl http://m1/` : @@{from_m2:>échoue immédiatement, « Connection refused » : m1 répond par une erreur (ICMP port unreachable) au SYN de m2>>>refused|attend puis expire (délai d'attente) : rien ne revient>>>timeout|la page s'affiche>>>works}@@
- depuis `m3`, `curl http://m1/` : @@{from_m3:>attend puis expire (délai d'attente) : le SYN est détruit sans réponse>>>timeout|échoue immédiatement, « Connection refused »>>>refused|la page s'affiche>>>works}@@
- depuis `m1`, vers `m2` et vers `m3` : @@{from_m1:>les deux échouent après le délai : les requêtes partent mais les réponses (SYN-ACK) arrivent dans input, rejetée pour m2 (c'est m2 qui reçoit l'erreur), détruite pour m3>>>both_fail|seule m3 répond>>>only_m3|seule m2 répond>>>only_m2|les deux pages s'affichent : output n'est pas filtré>>>both_work}@@
""": """
- from `m2`, `curl http://m1/`: @@{from_m2:>fails immediately, "Connection refused": m1 answers the SYN of m2 with an error (ICMP port unreachable)>>>refused|waits then times out: nothing comes back>>>timeout|the page is shown>>>works}@@
- from `m3`, `curl http://m1/`: @@{from_m3:>waits then times out: the SYN is dropped without an answer>>>timeout|fails immediately, "Connection refused">>>refused|the page is shown>>>works}@@
- from `m1`, to `m2` and to `m3`: @@{from_m1:>both fail after the timeout: the requests leave but the replies (SYN-ACK) arrive in input, rejected for m2 (it is m2 that receives the error), dropped for m3>>>both_fail|only m3 answers>>>only_m3|only m2 answers>>>only_m2|both pages are shown: output is not filtered>>>both_work}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

Depuis `m2`, `curl` échoue **aussitôt** : `curl: (7) Failed to connect to m1 port 80 … Couldn't
connect to server` (`nc -v m1 80` : `Connection refused`) ; `tcpdump` sur `m2` montre son SYN puis
`IP {m1} > {m2}: ICMP {m1} tcp port 80 unreachable`
(`reject with tcp reset` donnerait un RST ; `nft list ruleset` affiche la règle sous sa forme complète,
`reject with icmp port-unreachable`). Depuis `m3`, `curl` attend
les 5 s puis `Connection timed out` : le SYN est détruit, `m3` le retransmet, rien ne revient. Depuis
`m1`, les deux `curl` expirent : la requête part, le SYN-ACK de `m2` est rejeté (le message ICMP
part vers `m2`, pas vers le processus `curl`), celui de `m3` est détruit.

- Réponses : refusé immédiatement ; délai d'attente ; les deux échouent après le délai.
- L'évaluation ouvre une connexion TCP vers le port {port} de la copie de `m1` depuis les copies de
  `m2` (refus immédiat attendu) et de `m3` (expiration attendue : {timeout} s), et cherche une règle
  `reject` avec `ip saddr {m2}`. Le port {port} est servi sur la copie : un refus ne peut venir que
  du `reject`.
""": """
**Solution.** On `m1`:

```
{cmds}```

From `m2`, `curl` fails **at once**: `curl: (7) Failed to connect to m1 port 80 … Couldn't
connect to server` (`nc -v m1 80`: `Connection refused`); `tcpdump` on `m2` shows its SYN then
`IP {m1} > {m2}: ICMP {m1} tcp port 80 unreachable`
(`reject with tcp reset` would give a RST; `nft list ruleset` shows the rule in its full form,
`reject with icmp port-unreachable`). From `m3`, `curl` waits the 5 s then
`Connection timed out`: the SYN is dropped, `m3` retransmits it, nothing comes back. From `m1`,
both `curl` time out: the request leaves, the SYN-ACK of `m2` is rejected (the ICMP message goes
to `m2`, not to the `curl` process), that of `m3` is dropped.

- Answers: refused immediately; timeout; both fail after the timeout.
- The evaluation opens a TCP connection to port {port} of the copy of `m1` from the copies of
  `m2` (immediate refusal expected) and of `m3` (timeout expected: {timeout} s), and looks for a
  `reject` rule with `ip saddr {m2}`. Port {port} is served on the copy: a refusal can only come
  from the `reject`.
""",
    "m2 est refusée immédiatement sur le port {port} de m1 (reject)": "m2 is refused immediately on port {port} of m1 (reject)",
    "m3 n'a aucune réponse du port {port} de m1 (drop)": "m3 gets no answer from port {port} of m1 (drop)",
    "une règle reject pour ip saddr m2": "a reject rule for ip saddr m2",
    "drop ou reject : ce que voient m2, m3 et m1": "drop or reject: what m2, m3 and m1 see",
    "Partie 7 — Connexions initiées localement (question 7)": "Part 7 — Locally initiated connections (question 7)",
    "Autoriser les connexions initiées localement": "Allowing locally initiated connections",
    """
Insérez **en première position** de la chaîne `input` de `m1` la règle à états
`ct state established,related accept` (`nft insert rule …`, sections @@ref:conntrack@@ et
@@ref:nft-cli@@ des Informations). Vérifiez que `m1` peut de nouveau tout initier : `curl -m 3
http://m2/`, `curl -m 3 http://m3:8080/`, `curl -m 3 http://ext1/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m3` ; mais que `m2` et `m3` ne peuvent toujours rien initier vers `m1`
(`curl -m 5 http://m1/` : refusé pour `m2`, délai pour `m3` ; `echo bonjour | nc -u -w 1 m1 530`
depuis `m3` : pas de réponse). Pourquoi la règle de la question 5 n'est-elle plus nécessaire pour
les réponses de `ext1`, et pourquoi reste-t-elle gênante ?
""": """
Insert **in first position** of the `input` chain of `m1` the stateful rule
`ct state established,related accept` (`nft insert rule …`, sections @@ref:conntrack@@ and
@@ref:nft-cli@@ of the Informations tab). Check that `m1` can initiate everything again: `curl -m 3
http://m2/`, `curl -m 3 http://m3:8080/`, `curl -m 3 http://ext1/`, `echo bonjour | nc -u -w 1 m2
530`, `ping -c 2 -W 1 m3`; but that `m2` and `m3` still cannot initiate anything to `m1`
(`curl -m 5 http://m1/`: refused for `m2`, timeout for `m3`; `echo bonjour | nc -u -w 1 m1 530`
from `m3`: no answer). Why is the rule of question 5 no longer needed for the replies of `ext1`,
and why is it still a nuisance?
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

`nft list ruleset` la montre en tête. Le suivi de connexion reconnaît les réponses (SYN-ACK, segments
suivants, datagrammes UDP de retour, `echo-reply`) à ce que `m1` a émis : elles sont `established`
et acceptées, quel que soit l'émetteur. Les **nouvelles** connexions vers `m1` (SYN de `m2` ou `m3`,
premier datagramme UDP) ne sont ni `established` ni `related` : refusées pour `m2`, détruites pour `m3`.
La règle de la question 5 est devenue inutile pour les réponses de `ext1` et reste gênante parce
qu'elle accepte aussi ses requêtes ; on la garde pour l'évaluation.

- L'évaluation : depuis la copie de `m1`, HTTP vers `m2` et `ext1` et UDP vers `m3` (réponses
  acceptées), depuis la copie de `m3` UDP vers `m1` (sans réponse), une règle `accept` avec
  `ct state established,related`.
""": """
**Solution.** On `m1`:

```
{cmds}```

`nft list ruleset` shows it at the top. Connection tracking recognises the replies (SYN-ACK,
following segments, return UDP datagrams, `echo-reply`) to what `m1` has sent: they are
`established` and accepted, whoever the sender. The **new** connections to `m1` (SYN of `m2` or
`m3`, first UDP datagram) are neither `established` nor `related`: refused for `m2`, dropped for
`m3`. The rule of question 5 has become useless for the replies of `ext1` and is still a nuisance
because it also accepts its requests; it is kept for the evaluation.

- The evaluation: from the copy of `m1`, HTTP to `m2` and `ext1` and UDP to `m3` (replies
  accepted), from the copy of `m3` UDP to `m1` (no answer), an `accept` rule with
  `ct state established,related`.
""",
    "m1 initie des connexions TCP vers m2 et ext1 (réponses acceptées)": "m1 initiates TCP connections to m2 and ext1 (replies accepted)",
    "m1 initie un échange UDP avec m3 (réponse acceptée)": "m1 initiates a UDP exchange with m3 (reply accepted)",
    "m3 n'obtient rien du serveur UDP de m1 (nouvelle connexion entrante)": "m3 gets nothing from the UDP server of m1 (new incoming connection)",
    "une règle accept avec ct state established,related": "an accept rule with ct state established,related",
    "Partie 8 — Filtrage par protocole et port (question 8)": "Part 8 — Filtering by protocol and port (question 8)",
    "Filtrage par protocole et port : ouvrir un service": "Filtering by protocol and port: opening a service",
    """
Vérifiez depuis `m1` que son propre serveur de test répond sur les ports 80 et 8080
(`curl http://127.0.0.1/`, `curl http://127.0.0.1:8080/`). Autorisez à présent les connexions TCP
entrantes vers le port **{open}** de `m1`, depuis n'importe où, et vérifiez depuis `m2`, `m3` et
`ext1` que `curl -m 5 http://m1:{open}/` répond alors que `curl -m 5 http://m1/` (port {closed})
échoue toujours.

Attention à **l'ordre des règles** : si la règle du port {open} est ajoutée en fin de chaîne, elle
vient **après** la règle `reject` de la question 6 et `m2` reste refusée. Placez-la avant, avec
`nft insert rule` (en tête) ou `nft -a list ruleset` puis `nft insert rule inet filter input
handle N …` (section @@ref:nft-cli@@ des Informations).
""": """
Check from `m1` that its own test server answers on ports 80 and 8080
(`curl http://127.0.0.1/`, `curl http://127.0.0.1:8080/`). Now allow the incoming TCP connections
to port **{open}** of `m1`, from anywhere, and check from `m2`, `m3` and `ext1` that
`curl -m 5 http://m1:{open}/` answers whereas `curl -m 5 http://m1/` (port {closed}) still fails.

Mind **the order of the rules**: if the rule of port {open} is added at the end of the chain, it
comes **after** the `reject` rule of question 6 and `m2` is still refused. Place it before, with
`nft insert rule` (at the top) or `nft -a list ruleset` then `nft insert rule inet filter input
handle N …` (section @@ref:nft-cli@@ of the Informations tab).
""",
    """
**Solution.** Sur `m1`, en tête de chaîne :

```
{cmds}```

ou, pour la placer juste avant la règle `reject` (handle lu dans `nft -a list ruleset`) :
`nft insert rule inet filter input handle N tcp dport {open} accept`. Depuis `m2`, `m3` et `ext1`,
le port {open} répond (`SERVER=m1`, `TTL=63` pour `ext1`) ; le port {closed} reste refusé pour `m2`,
sans réponse pour `m3` et `ext1`.

- L'évaluation : connexion TCP vers le port {open} de la copie de `m1` depuis les copies de `m2`,
  `m3` et `ext1` (ouvert), vers le port {closed} depuis `ext1` (détruit), et une règle `accept` avec
  `tcp dport {open}` placée **avant** la règle `reject` de `m2` dans `input`.
""": """
**Solution.** On `m1`, at the top of the chain:

```
{cmds}```

or, to place it just before the `reject` rule (handle read in `nft -a list ruleset`):
`nft insert rule inet filter input handle N tcp dport {open} accept`. From `m2`, `m3` and `ext1`,
port {open} answers (`SERVER=m1`, `TTL=63` for `ext1`); port {closed} is still refused for `m2`,
without an answer for `m3` and `ext1`.

- The evaluation: TCP connection to port {open} of the copy of `m1` from the copies of `m2`, `m3`
  and `ext1` (open), to port {closed} from `ext1` (dropped), and an `accept` rule with
  `tcp dport {open}` placed **before** the `reject` rule of `m2` in `input`.
""",
    "le port {open} de m1 est ouvert depuis m2, m3 et ext1": "port {open} of m1 is open from m2, m3 and ext1",
    "le port {closed} de m1 reste fermé à ext1 (détruit)": "port {closed} of m1 stays closed to ext1 (dropped)",
    "une règle accept tcp dport {open}, avant la règle reject de m2": "an accept rule tcp dport {open}, before the reject rule of m2",
    "Partie 9 — Journal des paquets et chaîne nommée (question 9)": "Part 9 — Packet log and named chain (question 9)",
    "Journal des paquets et chaîne nommée": "Packet log and named chain",
    """
**(a)** Ajoutez en fin de chaîne `input` une règle qui **journalise** les paquets qui vont être
détruits : `log prefix "input drop: " group {group}` (section @@ref:logging@@ des Informations ; dans le
shell, protégez toute la règle par des apostrophes à cause des guillemets du préfixe). Sur `m1`,
lancez `tcpdump -n -i nflog:{group}` et, depuis `m3`, `curl -m 3 http://m1/` : les SYN détruits
apparaissent. Pourquoi les paquets de `m2` n'y sont-ils pas ?

**(b)** Créez une chaîne nommée **`{chain}`** (sans hook) contenant une règle `log` suivie d'une
règle `drop` (ou `counter drop`).

**(c)** Remplacez la règle `log` de la chaîne `input` par un saut vers `{chain}` (`jump {chain}`),
en **dernière règle** : supprimez l'ancienne avec `nft -a list ruleset` et `nft delete rule inet
filter input handle N`. Vérifiez que les paquets de `m3` sont toujours journalisés puis détruits.

**(d)** Pour que `m1` ne soit pas submergée par les journaux, limitez la journalisation à **{rate}
paquets par minute** (`limit rate {rate}/minute` devant `log`, dans la règle de `{chain}`). Depuis
`m3`, `ping -c 20 -i 0.2 m1` : combien de lignes `tcpdump` affiche-t-il ? Le compteur de la règle
`drop`, lui, compte tout (`nft list ruleset`).
""": """
**(a)** Add at the end of the `input` chain a rule that **logs** the packets about to be dropped:
`log prefix "input drop: " group {group}` (section @@ref:logging@@ of the Informations tab; in the
shell, protect the whole rule with single quotes because of the double quotes of the prefix). On
`m1`, run `tcpdump -n -i nflog:{group}` and, from `m3`, `curl -m 3 http://m1/`: the dropped SYNs
appear. Why are the packets of `m2` not there?

**(b)** Create a named chain **`{chain}`** (without a hook) containing a `log` rule followed by a
`drop` rule (or `counter drop`).

**(c)** Replace the `log` rule of the `input` chain with a jump to `{chain}` (`jump {chain}`), as
the **last rule**: delete the old one with `nft -a list ruleset` and `nft delete rule inet
filter input handle N`. Check that the packets of `m3` are still logged then dropped.

**(d)** So that `m1` is not flooded by the logs, limit logging to **{rate} packets per minute**
(`limit rate {rate}/minute` in front of `log`, in the rule of `{chain}`). From `m3`,
`ping -c 20 -i 0.2 m1`: how many lines does `tcpdump` show? The counter of the `drop` rule, for
its part, counts everything (`nft list ruleset`).
""",
    """
- où lit-on les paquets journalisés par `log … group 0` ? @@{where_logs:>avec tcpdump -n -i nflog:0 sur m1 (ou le démon ulogd) ; sans group, dans le journal du noyau d'une vraie machine (dmesg, journalctl -k)>>>nflog|dans /var/log/syslog de m3, la machine qui émet>>>syslog_m3|dans la sortie de nft list ruleset, sous la règle log>>>ruleset|nulle part : log ne fait rien sans verdict>>>nowhere}@@
""": """
- where are the packets logged by `log … group 0` read? @@{where_logs:>with tcpdump -n -i nflog:0 on m1 (or the ulogd daemon); without group, in the kernel log of a real machine (dmesg, journalctl -k)>>>nflog|in /var/log/syslog of m3, the machine that sends>>>syslog_m3|in the output of nft list ruleset, under the log rule>>>ruleset|nowhere: log does nothing without a verdict>>>nowhere}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

(a) `tcpdump -n -i nflog:{group}` affiche chaque SYN de `m3` vers le port 80 (retransmis toutes les
secondes), rien de `m2` : ses paquets sont rejetés par la règle `reject`, placée avant, et
n'atteignent jamais la fin de la chaîne. Sans `group`, `log` vise le journal du noyau : dans un
conteneur il n'y écrit rien par défaut (`net.netfilter.nf_log_all_netns`), et les conteneurs du TP ne
peuvent de toute façon pas le lire (`dmesg` : *Operation not permitted*). (b) et (c) : la chaîne
`{chain}` journalise puis détruit ; `jump {chain}` en dernière règle de `input` ; la politique `drop`
reste en filet de sécurité. (d) `limit rate {rate}/minute` est un seau à jetons : {rate} jetons au
départ (la rafale par défaut), puis un toutes les 12 s ; sur les 20 `echo-request` de `m3`, `tcpdump`
n'affiche que les premiers (une seule ligne si des paquets détruits juste avant ont vidé le seau), le
`counter` de la règle `drop` en compte 20.

- Réponse : avec `tcpdump -n -i nflog:0` (ou dans le journal du noyau d'une vraie machine).
- L'évaluation lit `nft -j list ruleset` : une chaîne nommée de la table contenant `input` avec une
  règle `log` et une règle `drop`, un `jump` (ou `goto`) vers elle en dernière règle de `input`, et
  `limit rate {rate}/minute` dans la règle `log`. Toute forme de `log` est acceptée.
""": """
**Solution.** On `m1`:

```
{cmds}```

(a) `tcpdump -n -i nflog:{group}` shows each SYN of `m3` to port 80 (retransmitted every second),
nothing from `m2`: its packets are rejected by the `reject` rule, placed before, and never reach
the end of the chain. Without `group`, `log` targets the kernel log: in a container it writes
nothing there by default (`net.netfilter.nf_log_all_netns`), and the containers of the lab cannot
read it anyway (`dmesg`: *Operation not permitted*). (b) and (c): the `{chain}` chain logs then
drops; `jump {chain}` as the last rule of `input`; the `drop` policy stays as a safety net. (d)
`limit rate {rate}/minute` is a token bucket: {rate} tokens at the start (the default burst), then
one every 12 s; of the 20 `echo-request` of `m3`, `tcpdump` only shows the first ones (a single
line if packets dropped just before have emptied the bucket), the `counter` of the `drop` rule
counts 20 of them.

- Answer: with `tcpdump -n -i nflog:0` (or in the kernel log of a real machine).
- The evaluation reads `nft -j list ruleset`: a named chain of the table containing `input` with a
  `log` rule and a `drop` rule, a `jump` (or `goto`) to it as the last rule of `input`, and
  `limit rate {rate}/minute` in the `log` rule. Any form of `log` is accepted.
""",
    "une chaîne nommée qui journalise (log) puis détruit (drop)": "a named chain that logs (log) then drops (drop)",
    "input saute vers cette chaîne, en dernière règle": "input jumps to this chain, as its last rule",
    "la journalisation est limitée à {rate} paquets par minute (limit rate)": "logging is limited to {rate} packets per minute (limit rate)",
    "où lire les paquets journalisés (nflog / journal du noyau)": "where to read the logged packets (nflog / kernel log)",
    "Partie 10 — Filtrer ce qui sort (question 10)": "Part 10 — Filtering what leaves (question 10)",
    """
Jusqu'ici `m1` émet ce qu'elle veut : seule sa chaîne `input` filtre. On contrôle maintenant ce
qu'elle **émet**, dans une chaîne de base accrochée au hook **`output`** (section @@ref:output@@
des Informations). `ext2` (`{forbidden}`) est une machine de l'extérieur vers laquelle `m1` ne doit
rien **initier**.

**(a)** Ajoutez à la table `inet filter` une chaîne de base **`output`** (type `filter`, hook
`output`, priorité 0, politique **`accept`** pour l'instant) et, dedans, une règle qui **détruit**
tout ce que `m1` envoie à `ext2` (critère `ip daddr`). Depuis `m1`, essayez `curl -m 5
http://ext2/` et `ping -c 2 -W 1 ext2` ; avec `tcpdump -n -i eth0 host ext2`, voit-on partir un
paquet ?

**(b)** Remplacez `drop` par **`reject`** dans cette règle (`nft -a list ruleset` puis `nft replace
rule …`, ou `nft flush chain inet filter output` puis ajoutez-la de nouveau), et refaites les deux
essais.

**(c)** Depuis `ext2`, essayez `curl -m 5 http://m1:{open}/` : le port {open}, ouvert à tous depuis
la question 8, ne répond plus à `ext2`. Insérez **en tête** de la chaîne `output` la règle à états
`ct state established,related accept`, et refaites l'essai : `ext2` est de nouveau servie, alors
que `m1` ne peut toujours rien initier vers elle.

**(d)** `m1` ne doit plus émettre que ce qui est prévu. Ajoutez à la fin de la chaîne `output` les
règles qui acceptent :

- tout ce qui sort par l'interface `lo` (`oif lo`) ;
- les `ping` (`icmp type echo-request`) ;
- les connexions TCP vers le port **{closed}** ;
- les datagrammes UDP vers les ports **{udp0}** et **{udp1}** (un ensemble anonyme, `udp dport
  {{ {udp0}, {udp1} }}` : dans le shell, toute la règle entre apostrophes) ;

puis une dernière règle **`reject`** sans critère, pour que les programmes de `m1` soient prévenus
aussitôt de ce qui leur est interdit. **Ensuite seulement**, passez la politique de la chaîne à
**`drop`** : on déclare la chaîne de nouveau, à l'identique, avec `policy drop`.

Vérifiez que **tout ce qui marchait marche encore** : depuis `m1`, `curl http://127.0.0.1:{open}/`,
`ping -c 2 -W 1` vers `m2` et `ext1`, `curl -m 3 http://m2/`, `curl -m 3 http://ext1/`, `echo
bonjour | nc -u -w 1 ext1 {udp0}`, `echo bonjour | nc -u -w 1 m3 {udp0}` ; depuis `m3` et `ext1`,
`curl -m 5 http://m1:{open}/` ; depuis `m2`, `curl -m 5 http://m1/`, toujours refusé aussitôt. Et
que le reste est refusé : depuis `m1`, `curl -m 5 http://m3:{open}/` et `curl -m 5 http://ext2/`.
C'est le jeu de règles final qui est évalué : une chaîne `output` incomplète défait ce que
vérifient les questions précédentes.
""": """
So far `m1` sends whatever it likes: only its `input` chain filters. We now control what it
**sends**, in a base chain attached to the **`output`** hook (section @@ref:output@@ of the
Informations tab). `ext2` (`{forbidden}`) is a machine of the outside to which `m1` must
**initiate** nothing.

**(a)** Add to the `inet filter` table a base chain **`output`** (type `filter`, hook `output`,
priority 0, policy **`accept`** for now) and, in it, a rule that **drops** everything `m1` sends
to `ext2` (selector `ip daddr`). From `m1`, try `curl -m 5 http://ext2/` and
`ping -c 2 -W 1 ext2`; with `tcpdump -n -i eth0 host ext2`, do you see a packet leave?

**(b)** Replace `drop` with **`reject`** in this rule (`nft -a list ruleset` then `nft replace
rule …`, or `nft flush chain inet filter output` then add it again), and do both tries again.

**(c)** From `ext2`, try `curl -m 5 http://m1:{open}/`: port {open}, open to everybody since
question 8, no longer answers `ext2`. Insert **at the top** of the `output` chain the stateful rule
`ct state established,related accept`, and try again: `ext2` is served again, whereas `m1` still
cannot initiate anything to it.

**(d)** `m1` must now only send what is planned. Add at the end of the `output` chain the rules
that accept:

- everything that leaves through the `lo` interface (`oif lo`);
- the `ping` (`icmp type echo-request`);
- the TCP connections to port **{closed}**;
- the UDP datagrams to ports **{udp0}** and **{udp1}** (an anonymous set, `udp dport
  {{ {udp0}, {udp1} }}`: in the shell, the whole rule between single quotes);

then a last **`reject`** rule without a selector, so that the programs of `m1` are told at once
what is forbidden to them. **Only then**, switch the policy of the chain to **`drop`**: the chain
is declared again, identically, with `policy drop`.

Check that **everything that worked still works**: from `m1`, `curl http://127.0.0.1:{open}/`,
`ping -c 2 -W 1` to `m2` and `ext1`, `curl -m 3 http://m2/`, `curl -m 3 http://ext1/`, `echo
bonjour | nc -u -w 1 ext1 {udp0}`, `echo bonjour | nc -u -w 1 m3 {udp0}`; from `m3` and `ext1`,
`curl -m 5 http://m1:{open}/`; from `m2`, `curl -m 5 http://m1/`, still refused at once. And that
the rest is refused: from `m1`, `curl -m 5 http://m3:{open}/` and `curl -m 5 http://ext2/`. It is
the final ruleset that is evaluated: an incomplete `output` chain undoes what the earlier
questions check.
""",
    """
- (a) avec `drop`, depuis `m1`, `curl -m 5 http://ext2/` : @@{with_drop:>attend puis abandonne au bout du délai : le SYN est détruit avant de quitter m1, rien ne signale le blocage>>>timeout|échoue immédiatement : le noyau prévient le programme>>>refused|la page s'affiche>>>works}@@
- (b) avec `reject`, la même commande : @@{with_reject:>échoue immédiatement : le noyau fabrique un message d'erreur pour le programme>>>refused|attend puis abandonne au bout du délai>>>timeout|la page s'affiche>>>works}@@
- (c) avant la règle à états, pourquoi `ext2` n'obtient-elle plus le port 8080 de `m1` ? @@{from_forbidden:>son SYN entre (input accepte le port), mais la réponse de m1, un SYN-ACK adressé à ext2, sort par output où la règle la rejette>>>synack_rejected|la chaîne input rejette maintenant ext2>>>input_rejects|ext2 ne sait plus joindre le réseau de m1>>>no_route}@@
""": """
- (a) with `drop`, from `m1`, `curl -m 5 http://ext2/`: @@{with_drop:>waits then gives up after the timeout: the SYN is dropped before leaving m1, nothing signals the block>>>timeout|fails immediately: the kernel notifies the program>>>refused|the page is shown>>>works}@@
- (b) with `reject`, the same command: @@{with_reject:>fails immediately: the kernel builds an error message for the program>>>refused|waits then gives up after the timeout>>>timeout|the page is shown>>>works}@@
- (c) before the stateful rule, why does `ext2` no longer get port 8080 of `m1`? @@{from_forbidden:>its SYN gets in (input accepts the port), but the reply of m1, a SYN-ACK addressed to ext2, leaves through output where the rule rejects it>>>synack_rejected|the input chain now rejects ext2>>>input_rejects|ext2 can no longer reach the network of m1>>>no_route}@@
""",
    """
**Solution.** (a) puis (b), sur `m1` :

```
{chain}
nft add rule inet filter output ip daddr {forbidden} drop
nft flush chain inet filter output
{reject}
```

Avec `drop`, rien ne sort (`tcpdump` ne montre aucun paquet vers `ext2` : il capture après le hook
`output`) : `curl` attend ses 5 secondes (`curl: (28) Connection timed out`) et `ping` n'affiche que
`100% packet loss`. Avec `reject`, le noyau fabrique un message ICMP *port unreachable* pour le
programme : `curl` échoue aussitôt (`curl: (7) Failed to connect to ext2 port 80 … Couldn't connect
to server` ; `nc -v ext2 80` : `Connection refused`), `ping` affiche `Destination Port Unreachable`
venant de `m1` elle-même et `ping: sendmsg: Operation not permitted`. Ce message revient au
programme par l'interface `lo` : les règles `ct state established,related accept` (il est `related`)
et `iif lo accept` de `input` le laissent entrer.

(c) Le SYN de `ext2` est accepté par `input` (port {open}), mais la réponse de `m1`, un SYN-ACK
adressé à `ext2`, sort par `output` où la règle la rejette : `ext2` attend, puis abandonne. Avec

```
{stateful}
```

les paquets des connexions déjà acceptées sortent avant d'atteindre la règle `ip daddr` : il ne
reste d'interdit que ce que `m1` **initie** vers `ext2`.

(d)

```
{whitelist}```

La règle `reject` finale prévient les programmes de `m1` ; la politique `drop` n'est plus qu'un
filet de sécurité. Dans cet ordre, aucun état intermédiaire ne coupe quoi que ce soit. `related`
laisse aussi sortir les messages d'erreur que `m1` fabrique elle-même, comme le *port unreachable*
du `reject` de la question 6 : avec `ct state established accept` seul, `m2` ne serait plus
prévenue (un délai au lieu du refus immédiat : la question 6 y perd des points). Sans `oif lo
accept`, `curl http://127.0.0.1:{open}/` serait refusé. Sans la règle à états, le port {open} ne
répondrait plus à personne.

- Réponses : délai avec `drop` ; refus immédiat avec `reject` ; le SYN-ACK de `m1` est rejeté dans
  `output`.
- L'évaluation, sur la copie de `m1` : une chaîne de base du hook `output` de politique `drop` et
  sa règle `ct state established,related accept` ; `curl http://127.0.0.1:{open}/` (la règle
  `oif lo`) ; une connexion TCP vers le port {closed} de `ext2` (refusée ; un simple délai,
  c'est-à-dire un `drop`, ne donne qu'une partie des points) alors que `ext1` répond ; depuis la
  copie de `ext2`, le port {open} de `m1` (ouvert) ; une connexion vers le port {open} de `m3`
  (refusée) alors que son port {closed} répond. Une sonde lancée par `bash` ne voit le refus d'un
  `reject` local qu'à la première retransmission du SYN, une seconde plus tard (`curl` et `nc` le
  voient aussitôt) : le délai de ces sondes est de {out_timeout} s.
""": """
**Solution.** (a) then (b), on `m1`:

```
{chain}
nft add rule inet filter output ip daddr {forbidden} drop
nft flush chain inet filter output
{reject}
```

With `drop`, nothing leaves (`tcpdump` shows no packet to `ext2`: it captures after the `output`
hook): `curl` waits its 5 seconds (`curl: (28) Connection timed out`) and `ping` only shows
`100% packet loss`. With `reject`, the kernel builds an ICMP *port unreachable* message for the
program: `curl` fails at once (`curl: (7) Failed to connect to ext2 port 80 … Couldn't connect
to server`; `nc -v ext2 80`: `Connection refused`), `ping` shows `Destination Port Unreachable`
coming from `m1` itself and `ping: sendmsg: Operation not permitted`. This message comes back to
the program through the `lo` interface: the rules `ct state established,related accept` (it is
`related`) and `iif lo accept` of `input` let it in.

(c) The SYN of `ext2` is accepted by `input` (port {open}), but the reply of `m1`, a SYN-ACK
addressed to `ext2`, leaves through `output` where the rule rejects it: `ext2` waits, then gives
up. With

```
{stateful}
```

the packets of the connections already accepted leave before reaching the `ip daddr` rule: all
that remains forbidden is what `m1` **initiates** to `ext2`.

(d)

```
{whitelist}```

The final `reject` rule notifies the programs of `m1`; the `drop` policy is now only a safety net.
In this order, no intermediate state cuts anything. `related` also lets out the error messages
`m1` builds itself, such as the *port unreachable* of the `reject` of question 6: with
`ct state established accept` alone, `m2` would no longer be notified (a timeout instead of the
immediate refusal: question 6 loses points). Without `oif lo accept`,
`curl http://127.0.0.1:{open}/` would be refused. Without the stateful rule, port {open} would no
longer answer anybody.

- Answers: timeout with `drop`; immediate refusal with `reject`; the SYN-ACK of `m1` is rejected
  in `output`.
- The evaluation, on the copy of `m1`: a base chain of the `output` hook with policy `drop` and
  its rule `ct state established,related accept`; `curl http://127.0.0.1:{open}/` (the `oif lo`
  rule); a TCP connection to port {closed} of `ext2` (refused; a mere timeout, that is a `drop`,
  only gives part of the points) whereas `ext1` answers; from the copy of `ext2`, port {open} of
  `m1` (open); a connection to port {open} of `m3` (refused) whereas its port {closed} answers. A
  probe run by `bash` only sees the refusal of a local `reject` at the first retransmission of the
  SYN, one second later (`curl` and `nc` see it at once): the timeout of these probes is
  {out_timeout} s.
""",
    "une chaîne de base du hook output avec la politique drop": "a base chain of the output hook with the drop policy",
    "output : une règle accept avec ct state established,related": "output: an accept rule with ct state established,related",
    "sur m1, curl http://127.0.0.1:{open}/ répond encore (oif lo accept)": "on m1, curl http://127.0.0.1:{open}/ still answers (oif lo accept)",
    "m1 n'ouvre pas de connexion vers ext2 (refus immédiat : reject), alors qu'elle joint ext1": "m1 opens no connection to ext2 (immediate refusal: reject), whereas it reaches ext1",
    "ext2 obtient toujours le port {open} de m1 (règle à états avant la règle ip daddr)": "ext2 still gets port {open} of m1 (stateful rule before the ip daddr rule)",
    "m1 n'ouvre pas de connexion vers le port {open} de m3 (refus immédiat : reject final), alors qu'elle joint son port {closed}": "m1 opens no connection to port {open} of m3 (immediate refusal: final reject), whereas it reaches its port {closed}",
    "drop ou reject dans output : ce que voit le programme ; pourquoi ext2 perdait le port {open}": "drop or reject in output: what the program sees; why ext2 lost port {open}",
    "Partie 11 — Ensemble nommé : une liste noire (question 11)": "Part 11 — Named set: a blocklist (question 11)",
    "Ensembles nommés : une liste noire": "Named sets: a blocklist",
    """
`ext3` (`{host}`) et toutes les machines du réseau `guest` (`{net}`, où se trouve `guest1`) ne
doivent plus rien obtenir de `m1`, pas même son port {open}. Plutôt qu'une règle par adresse, on
utilise un **ensemble nommé** (section @@ref:sets@@ des Informations) : une seule règle le
consulte, et l'on en modifie le contenu sans toucher à cette règle.

**(a)** Créez dans la table `inet filter` un ensemble **`{name}`** d'adresses IPv4 (`type
ipv4_addr`) portant le drapeau **`interval`**, qui lui permet de contenir aussi des réseaux, et
ajoutez-y l'adresse de `ext3` (`nft add element`).

**(b)** Ajoutez à la chaîne `input` une règle qui **détruit** ce qui vient d'une adresse de
l'ensemble (`ip saddr @{name} drop`). Où faut-il la placer pour que `ext3` n'atteigne plus le port
{open} ? Vérifiez depuis `ext3` (`curl -m 5 http://m1:{open}/`), puis depuis `ext1` que le port
répond toujours.

**(c)** Sans toucher à la règle, ajoutez à l'ensemble le réseau `guest` **entier** (`{net}`) et
vérifiez depuis `guest1`. Affichez l'ensemble (`nft list set inet filter {name}`) ; retirez puis
remettez un élément (`nft delete element`, `nft add element`).
""": """
`ext3` (`{host}`) and all the machines of the `guest` network (`{net}`, where `guest1` is) must no
longer get anything from `m1`, not even its port {open}. Rather than one rule per address, we use
a **named set** (section @@ref:sets@@ of the Informations tab): a single rule looks it up, and its
contents are changed without touching that rule.

**(a)** Create in the `inet filter` table a set **`{name}`** of IPv4 addresses (`type
ipv4_addr`) carrying the **`interval`** flag, which lets it contain networks as well, and add the
address of `ext3` to it (`nft add element`).

**(b)** Add to the `input` chain a rule that **drops** what comes from an address of the set
(`ip saddr @{name} drop`). Where must it be placed so that `ext3` no longer reaches port {open}?
Check from `ext3` (`curl -m 5 http://m1:{open}/`), then from `ext1` that the port still answers.

**(c)** Without touching the rule, add the **whole** `guest` network (`{net}`) to the set and check
from `guest1`. Show the set (`nft list set inet filter {name}`); remove then put back an element
(`nft delete element`, `nft add element`).
""",
    """
- sans le drapeau `interval`, l'ajout d'un réseau à l'ensemble : @@{no_interval:>est refusé par nft (« You must add 'flags interval' to your set declaration ») : sans ce drapeau, un ensemble ne contient que des valeurs isolées>>>refused|ajoute une à une toutes les adresses du réseau>>>expanded|n'ajoute que l'adresse du réseau>>>network_address}@@
- la règle `ip saddr @blocklist drop` doit être placée : @@{rule_place:>avant la règle qui accepte le port 8080 (nft insert rule) : la première règle satisfaite décide>>>before_accept|en fin de chaîne (nft add rule)>>>at_end|n'importe où : un drop l'emporte toujours sur un accept>>>anywhere}@@
""": """
- without the `interval` flag, adding a network to the set: @@{no_interval:>is refused by nft ("You must add 'flags interval' to your set declaration"): without this flag, a set only contains single values>>>refused|adds all the addresses of the network one by one>>>expanded|only adds the network address>>>network_address}@@
- the rule `ip saddr @blocklist drop` must be placed: @@{rule_place:>before the rule that accepts port 8080 (nft insert rule): the first matching rule decides>>>before_accept|at the end of the chain (nft add rule)>>>at_end|anywhere: a drop always wins over an accept>>>anywhere}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

`nft insert rule` place la règle en tête de chaîne, donc avant `tcp dport {open} accept` ; ajoutée
en fin de chaîne (`nft add rule`), elle viendrait après `jump logdrop` et ne verrait jamais un
paquet. Le contenu de l'ensemble se modifie ensuite sans toucher à la règle (`nft list set inet
filter {name}` affiche `elements = {{ {host}, {net} }}`). Sans `flags interval`, l'ajout du réseau
est refusé : `Error: You must add 'flags interval' to your set declaration if you want to add
prefix elements` ; et les drapeaux ne se changent pas après coup (`nft add set` : *File exists*) :
il faut supprimer la règle, puis l'ensemble (*Device or resource busy* tant qu'une règle le
consulte), et les recréer. Placée en tête, avant la règle à états, la règle détruit aussi les
**réponses** de `ext3` et de `guest1` : `m1` ne peut plus les joindre non plus.

- Réponses : refusé sans `flags interval` ; avant la règle qui accepte le port {open}.
- L'évaluation : dans `input`, une règle `drop` sur `ip saddr @ensemble` placée avant la règle
  `tcp dport {open} accept`, l'ensemble contenant `{host}` et tout `{net}` ; depuis les copies de
  `ext3` et de `guest1`, le port {open} de `m1` ne répond pas, alors qu'il répond à `ext1`.
""": """
**Solution.** On `m1`:

```
{cmds}```

`nft insert rule` places the rule at the top of the chain, hence before `tcp dport {open} accept`;
added at the end of the chain (`nft add rule`), it would come after `jump logdrop` and would never
see a packet. The contents of the set are then changed without touching the rule (`nft list set
inet filter {name}` shows `elements = {{ {host}, {net} }}`). Without `flags interval`, adding the
network is refused: `Error: You must add 'flags interval' to your set declaration if you want to
add prefix elements`; and the flags cannot be changed afterwards (`nft add set`: *File exists*):
the rule must be deleted, then the set (*Device or resource busy* as long as a rule looks it up),
and both created again. Placed at the top, before the stateful rule, the rule also drops the
**replies** of `ext3` and `guest1`: `m1` can no longer reach them either.

- Answers: refused without `flags interval`; before the rule that accepts port {open}.
- The evaluation: in `input`, a `drop` rule on `ip saddr @set` placed before the rule
  `tcp dport {open} accept`, the set containing `{host}` and the whole of `{net}`; from the copies
  of `ext3` and `guest1`, port {open} of `m1` does not answer, whereas it answers `ext1`.
""",
    "input : une règle drop sur ip saddr @ensemble, avant la règle qui accepte le port {open}": "input: a drop rule on ip saddr @set, before the rule that accepts port {open}",
    "l'ensemble contient l'adresse de ext3 et tout le réseau guest (flags interval)": "the set contains the address of ext3 and the whole guest network (flags interval)",
    "ext3 n'obtient plus le port {open} de m1, alors que ext1 l'obtient": "ext3 no longer gets port {open} of m1, whereas ext1 gets it",
    "guest1 n'obtient plus le port {open} de m1, alors que ext1 l'obtient": "guest1 no longer gets port {open} of m1, whereas ext1 gets it",
    "un réseau dans un ensemble (flags interval) ; la place de la règle qui le consulte": "a network in a set (flags interval); the place of the rule that looks it up",
    "Partie 12 — Ensemble de ports (question 12)": "Part 12 — Set of ports (question 12)",
    "Un ensemble de ports pour la sortie": "A set of ports for the way out",
    """
Un ensemble ne contient pas forcément des adresses. Toutes les machines servent aussi leur page de
test sur le port TCP **{set_port}**, que la chaîne `output` de `m1` refuse pour l'instant (depuis
`m1` : `curl -m 5 http://m3:{set_port}/`).

**(a)** Créez un ensemble **`{name}`** de ports (`type inet_service`) contenant le port {closed},
puis **remplacez**, dans la chaîne `output`, la règle `tcp dport {closed} accept` par `tcp dport
@{name} accept` : `nft -a list chain inet filter output` donne le handle de la règle, `nft replace
rule inet filter output handle N …` la remplace sur place (section @@ref:nft-edit@@ des
Informations). Rien ne doit avoir changé : `curl -m 3 http://m3/` répond, `curl -m 5
http://m3:{set_port}/` et `curl -m 5 http://m3:{open}/` sont refusés.

**(b)** Autorisez maintenant le port {set_port} **sans toucher aux règles**, en ajoutant un élément
à l'ensemble. Vérifiez : `curl -m 3 http://m3:{set_port}/` répond, `curl -m 5 http://m3:{open}/`
est toujours refusé.
""": """
A set does not necessarily contain addresses. All the machines also serve their test page on TCP
port **{set_port}**, which the `output` chain of `m1` refuses for now (from `m1`:
`curl -m 5 http://m3:{set_port}/`).

**(a)** Create a set **`{name}`** of ports (`type inet_service`) containing port {closed}, then
**replace**, in the `output` chain, the rule `tcp dport {closed} accept` with `tcp dport
@{name} accept`: `nft -a list chain inet filter output` gives the handle of the rule, `nft replace
rule inet filter output handle N …` replaces it in place (section @@ref:nft-edit@@ of the
Informations tab). Nothing must have changed: `curl -m 3 http://m3/` answers, `curl -m 5
http://m3:{set_port}/` and `curl -m 5 http://m3:{open}/` are refused.

**(b)** Now allow port {set_port} **without touching the rules**, by adding an element to the set.
Check: `curl -m 3 http://m3:{set_port}/` answers, `curl -m 5 http://m3:{open}/` is still refused.
""",
    """
- pour autoriser le port 8888, il a fallu modifier : @@{rules_changed:>seulement le contenu de l'ensemble (nft add element) : la règle qui le consulte n'a pas changé>>>element_only|la règle de la chaîne output, remplacée une seconde fois>>>rule|toute la chaîne output, vidée puis réécrite>>>whole_chain}@@
""": """
- to allow port 8888, what had to be modified: @@{rules_changed:>only the contents of the set (nft add element): the rule that looks it up has not changed>>>element_only|the rule of the output chain, replaced a second time>>>rule|the whole output chain, emptied then rewritten>>>whole_chain}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

La troisième commande lit elle-même le handle de la règle à remplacer ; à la main : `nft -a list
chain inet filter output` (`tcp dport {closed} accept # handle N`), puis `nft replace rule inet
filter output handle N tcp dport @{name} accept`. La règle garde sa place et son handle. Le port
{set_port} s'ouvre ensuite par `nft add element` seul : `nft list set inet filter {name}` affiche
`elements = {{ {closed}, {set_port} }}`.

- Réponse : seulement le contenu de l'ensemble.
- L'évaluation : dans `output`, une règle `accept` sur `tcp dport @ensemble`, l'ensemble contenant
  les ports {closed} et {set_port} ; depuis la copie de `m1`, `curl http://m3:{set_port}/` répond
  (sous la politique `drop` de `output`). Une règle `tcp dport {closed} accept` restée en place ne
  coûte rien.
""": """
**Solution.** On `m1`:

```
{cmds}```

The third command reads the handle of the rule to replace by itself; by hand: `nft -a list
chain inet filter output` (`tcp dport {closed} accept # handle N`), then `nft replace rule inet
filter output handle N tcp dport @{name} accept`. The rule keeps its place and its handle. Port
{set_port} is then opened by `nft add element` alone: `nft list set inet filter {name}` shows
`elements = {{ {closed}, {set_port} }}`.

- Answer: only the contents of the set.
- The evaluation: in `output`, an `accept` rule on `tcp dport @set`, the set containing ports
  {closed} and {set_port}; from the copy of `m1`, `curl http://m3:{set_port}/` answers (under the
  `drop` policy of `output`). A `tcp dport {closed} accept` rule left in place costs nothing.
""",
    "output : une règle accept sur tcp dport @ensemble, l'ensemble contenant les ports {closed} et {set_port}": "output: an accept rule on tcp dport @set, the set containing ports {closed} and {set_port}",
    "m1 joint le port {set_port} de m3 (sous la politique drop de output)": "m1 reaches port {set_port} of m3 (under the drop policy of output)",
    "un port de plus : seul le contenu de l'ensemble change": "one more port: only the contents of the set change",
    "Partie 13 — Ensemble de couples adresse . port (question 13)": "Part 13 — Set of address . port pairs (question 13)",
    "Associations adresse . port : une liste blanche": "Address . port pairs: an allowlist",
    """
Le port {first_port} de `m1` n'est ouvert à personne, son port {second_port} non plus. On veut
ouvrir le port {first_port} à `{first}` (`{first_address}`) et le port {second_port} à `{second}`
(`{second_address}`), et rien d'autre, avec **un seul ensemble et une seule règle** : chaque
élément de l'ensemble est un couple *adresse . port* (une concaténation,
section @@ref:named-sets@@ des Informations).

**(a)** Créez l'ensemble **`{name}`** (`type ipv4_addr . inet_service`) et ajoutez-y les deux
couples : `{first_address} . {first_port}` et `{second_address} . {second_port}`.

**(b)** Ajoutez à la chaîne `input` la règle `ip saddr . tcp dport @{name} accept`. Attention à sa
place : ajoutée en fin de chaîne, elle viendrait après `jump logdrop` et ne verrait jamais un
paquet. Vérifiez : depuis `{first}`, `curl -m 3 http://m1/` répond et `curl -m 5
http://m1:{second_port}/` échoue ; depuis `{second}`, `curl -m 3 http://m1:{second_port}/` répond
et `curl -m 5 http://m1/` échoue toujours ; depuis `ext1`, les deux échouent.
""": """
Port {first_port} of `m1` is open to nobody, nor is its port {second_port}. We want to open port
{first_port} to `{first}` (`{first_address}`) and port {second_port} to `{second}`
(`{second_address}`), and nothing else, with **a single set and a single rule**: each element of
the set is an *address . port* pair (a concatenation, section @@ref:named-sets@@ of the
Informations tab).

**(a)** Create the set **`{name}`** (`type ipv4_addr . inet_service`) and add the two pairs to it:
`{first_address} . {first_port}` and `{second_address} . {second_port}`.

**(b)** Add to the `input` chain the rule `ip saddr . tcp dport @{name} accept`. Mind its place:
added at the end of the chain, it would come after `jump logdrop` and would never see a packet.
Check: from `{first}`, `curl -m 3 http://m1/` answers and `curl -m 5
http://m1:{second_port}/` fails; from `{second}`, `curl -m 3 http://m1:{second_port}/` answers and
`curl -m 5 http://m1/` still fails; from `ext1`, both fail.
""",
    """
- depuis `ext2`, `curl -m 5 http://m1:8888/` : @@{pair_missing:>attend puis abandonne : le couple (ext2, 8888) n'est pas dans l'ensemble, seul (ext2, 80) y est ; le paquet finit dans logdrop>>>timeout|la page s'affiche : l'adresse de ext2 est dans l'ensemble>>>works|échoue immédiatement : la règle reject de la question 6 s'applique>>>refused}@@
""": """
- from `ext2`, `curl -m 5 http://m1:8888/`: @@{pair_missing:>waits then gives up: the pair (ext2, 8888) is not in the set, only (ext2, 80) is; the packet ends up in logdrop>>>timeout|the page is shown: the address of ext2 is in the set>>>works|fails immediately: the reject rule of question 6 applies>>>refused}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

`nft insert rule` place la règle en tête ; toute place avant `jump logdrop` convient (`nft insert
rule inet filter input handle N …`, N étant le handle du saut). La règle ne vaut que pour TCP (le
critère `tcp dport`) et pour un couple **entier** : `{first}` obtient le port {first_port} mais pas
le port {second_port}, `{second}` l'inverse, `ext1` aucun des deux. La réponse de `m1` à `{first}`
sort grâce à la règle à états de la chaîne `output` (question 10) : sans elle, la règle `ip daddr`
la rejetterait.

- Réponse : délai, le couple n'est pas dans l'ensemble.
- L'évaluation : dans `input`, une règle `accept` sur `ip saddr . tcp dport @ensemble`, l'ensemble
  contenant les deux couples ; depuis la copie de `{first}`, le port {first_port} de `m1` est
  ouvert et son port {second_port} ne l'est pas ; depuis celle de `{second}`, le port
  {second_port} est ouvert ; depuis celle de `ext1`, il ne l'est pas.
""": """
**Solution.** On `m1`:

```
{cmds}```

`nft insert rule` places the rule at the top; any place before `jump logdrop` will do (`nft insert
rule inet filter input handle N …`, N being the handle of the jump). The rule only applies to TCP
(the `tcp dport` selector) and to a **whole** pair: `{first}` gets port {first_port} but not port
{second_port}, `{second}` the reverse, `ext1` neither. The reply of `m1` to `{first}` leaves thanks
to the stateful rule of the `output` chain (question 10): without it, the `ip daddr` rule would
reject it.

- Answer: timeout, the pair is not in the set.
- The evaluation: in `input`, an `accept` rule on `ip saddr . tcp dport @set`, the set containing
  the two pairs; from the copy of `{first}`, port {first_port} of `m1` is open and its port
  {second_port} is not; from that of `{second}`, port {second_port} is open; from that of `ext1`,
  it is not.
""",
    "input : une règle accept sur ip saddr . tcp dport @ensemble, l'ensemble contenant les deux couples": "input: an accept rule on ip saddr . tcp dport @set, the set containing the two pairs",
    "{first} obtient le port {first_port} de m1, {second} son port {second_port}": "{first} gets port {first_port} of m1, {second} its port {second_port}",
    "le port {second_port} de m1 reste fermé à {first} et à ext1 (couples absents de l'ensemble)": "port {second_port} of m1 stays closed to {first} and to ext1 (pairs not in the set)",
    "un couple absent de l'ensemble n'est pas accepté": "a pair missing from the set is not accepted",
    "Partie 14 — Bonus : ensemble dynamique (question 14)": "Part 14 — Bonus: dynamic set (question 14)",
    "Bonus — ensemble dynamique : bannir les curieux": "Bonus — dynamic set: banning the curious",
    """
Personne n'a de raison de se connecter au port TCP {trap} (telnet) de `m1` : celui qui essaie
explore la machine. On veut le **bannir pendant {seconds} secondes** : pendant ce temps, tout ce
qui vient de son adresse est détruit, même vers le port {open}. Ce sont les règles elles-mêmes qui
alimentent l'ensemble (section @@ref:dynamic-sets@@ des Informations).

**(a)** Créez l'ensemble **`{name}`** : `type ipv4_addr`, drapeaux `dynamic,timeout`, délai
`timeout {seconds}s`.

**(b)** Insérez en tête de la chaîne `input` la règle qui, pour un paquet TCP destiné au port
{trap}, **ajoute son adresse source à l'ensemble** puis le détruit (`tcp dport {trap} add @{name}
{{ ip saddr }} drop` : dans le shell, toute la règle entre apostrophes) ; puis, en tête elle aussi,
la règle qui détruit tout ce qui vient d'une adresse de l'ensemble (`ip saddr @{name} drop`).

**(c)** Depuis `m3` : `curl -m 3 http://m1:{open}/` (répond), `nc -v -w 2 m1 {trap}`, puis de
nouveau `curl -m 5 http://m1:{open}/`. Sur `m1`, `nft list set inet filter {name}` montre l'adresse
de `m3` et le délai qui lui reste (`expires`). Attendez une minute et recommencez.
""": """
Nobody has any reason to connect to TCP port {trap} (telnet) of `m1`: whoever tries is exploring
the machine. We want to **ban them for {seconds} seconds**: during that time, everything coming
from their address is dropped, even to port {open}. It is the rules themselves that feed the set
(section @@ref:dynamic-sets@@ of the Informations tab).

**(a)** Create the set **`{name}`**: `type ipv4_addr`, flags `dynamic,timeout`, timeout
`timeout {seconds}s`.

**(b)** Insert at the top of the `input` chain the rule that, for a TCP packet addressed to port
{trap}, **adds its source address to the set** then drops it (`tcp dport {trap} add @{name}
{{ ip saddr }} drop`: in the shell, the whole rule between single quotes); then, also at the top,
the rule that drops everything coming from an address of the set (`ip saddr @{name} drop`).

**(c)** From `m3`: `curl -m 3 http://m1:{open}/` (answers), `nc -v -w 2 m1 {trap}`, then
`curl -m 5 http://m1:{open}/` again. On `m1`, `nft list set inet filter {name}` shows the address
of `m3` and the time it has left (`expires`). Wait a minute and try again.
""",
    """
- après `nc -v -w 2 m1 23` depuis `m3`, `curl -m 5 http://m1:8080/` depuis `m3` : @@{ban_effect:>échoue pendant 60 secondes, puis répond de nouveau : l'adresse de m3 est dans l'ensemble, d'où elle disparaît toute seule à la fin du délai>>>banned_then_back|répond : seul le port 23 est concerné>>>only_trap|ne répond plus jamais : il faut retirer l'adresse à la main>>>forever}@@
""": """
- after `nc -v -w 2 m1 23` from `m3`, `curl -m 5 http://m1:8080/` from `m3`: @@{ban_effect:>fails for 60 seconds, then answers again: the address of m3 is in the set, from which it disappears by itself at the end of the timeout>>>banned_then_back|answers: only port 23 is concerned>>>only_trap|never answers again: the address must be removed by hand>>>forever}@@
""",
    """
**Solution.** Sur `m1` :

```
{cmds}```

Le second `insert` place la règle `ip saddr @{name} drop` devant la première. La tentative de `m3`
sur le port {trap} range son adresse dans l'ensemble (`elements = {{ {m3} expires 57s }}`) ; pendant
{seconds} secondes tout ce qui vient d'elle est détruit, y compris ses réponses aux requêtes de
`m1` (la règle précède la règle à états). `update @{name} {{ ip saddr }}` au lieu de `add`
relancerait le délai à chaque nouvelle tentative ; `nft flush set inet filter {name}` lève tous les
bannissements.

- Réponse : échoue pendant {seconds} secondes, puis répond de nouveau.
- L'évaluation (bonus) : une règle de `input` qui ajoute `ip saddr` à un ensemble pour `tcp dport
  {trap}`, avec un délai de {seconds} s ; une règle `drop` sur `ip saddr @ensemble` placée avant la
  règle qui accepte le port {open} ; puis, sur les copies cachées, `{source}` obtient le port {open}
  (étape {probe_step}), tente le port {trap} (étape {trap_step}), n'obtient plus le port {open}
  alors que `{spared}` l'obtient toujours (étape {ban_step}). L'ensemble est vidé sur la copie
  avant les sondes : un bannissement en cours sur `m1` ne fausse pas l'évaluation.
""": """
**Solution.** On `m1`:

```
{cmds}```

The second `insert` places the rule `ip saddr @{name} drop` in front of the first one. The attempt
of `m3` on port {trap} stores its address in the set (`elements = {{ {m3} expires 57s }}`); for
{seconds} seconds everything coming from it is dropped, including its replies to the requests of
`m1` (the rule comes before the stateful rule). `update @{name} {{ ip saddr }}` instead of `add`
would restart the timeout at each new attempt; `nft flush set inet filter {name}` lifts all the
bans.

- Answer: fails for {seconds} seconds, then answers again.
- The evaluation (bonus): an `input` rule that adds `ip saddr` to a set for `tcp dport
  {trap}`, with a timeout of {seconds} s; a `drop` rule on `ip saddr @set` placed before the rule
  that accepts port {open}; then, on the hidden copies, `{source}` gets port {open}
  (step {probe_step}), tries port {trap} (step {trap_step}), no longer gets port {open}
  whereas `{spared}` still gets it (step {ban_step}). The set is emptied on the copy before the
  probes: a ban in progress on `m1` does not skew the evaluation.
""",
    "un ensemble alimenté par une règle de input (ip saddr, tcp dport {trap}), éléments expirant après {seconds} s": "a set fed by an input rule (ip saddr, tcp dport {trap}), elements expiring after {seconds} s",
    "une règle drop sur ip saddr @ensemble, placée avant la règle qui accepte le port {open}": "a drop rule on ip saddr @set, placed before the rule that accepts port {open}",
    "après une tentative sur le port {trap}, {source} n'obtient plus le port {open} de m1 (mais {spared} toujours)": "after an attempt on port {trap}, {source} no longer gets port {open} of m1 (but {spared} still does)",
    "un bannissement temporaire : l'élément expire de lui-même": "a temporary ban: the element expires by itself",
}}
