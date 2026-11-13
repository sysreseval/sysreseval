"""Host firewall lab (TP2 "Parefeux" of the R306 course, converted from the iptables / Marionnet
handout to nftables): the students write, on ``m1``, the ``input`` chain of an nftables ruleset,
question after question: default policy ``drop``, the loopback interface, ICMP echo replies, UDP
from one server, ``drop`` versus ``reject``, the stateful rule (``ct state established,related``),
one open TCP port placed before an earlier ``reject`` (rule order, handles), then a named chain
logging (``limit rate``) and dropping what is left.

Topology::

    m1 (firewall) ---+
    m2 --------------+-- [switch lan] -- eth0 gw eth1 -- [switch ext] -- ext1
    m3 --------------+

``gw`` routes between ``lan`` and ``ext`` (the default route of every host); ``ext1`` plays the
"server of the exterior" whose UDP is accepted in question 5 and the client "from outside" of the
other probes.  Every machine runs the echo server of ``lib/server_echo.py`` (HTTP on TCP 80 and
8080, UDP on 530 and 630: the answer gives the addresses and ports of both ends and the TTL of the
packet), the services the students open or close.

Grading uses the "hidden mirror" of ``lib/hidden_mirror.py`` / ``lib/firewall.py``: a hidden clone
of the whole topology (``m1_h`` … ``ext1_h`` on ``lan_h`` / ``ext_h``, same addresses, same echo
servers), onto which the live ruleset of ``m1`` (``nft list ruleset``) is transplanted at each
evaluation; the probes then run from and to the clones, where the expected result is known and the
students cannot interfere.  What the ruleset *says* is read from ``nft -j list ruleset`` of ``m1``
(policy, selectors, verdicts, rule order, ``log`` / ``limit``), what it *does* from the probes.
The ``final`` state applies the reference solution (100/100).  Texts are French (``tr()``),
identifiers English.
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

title = tr("Pare-feu d'une machine avec nftables")
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
# An evaluation waits for the probes the firewall must block (4 s per dropped TCP connection).
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

FIREWALL = 'm1'                 # the machine whose input chain the students write
MIRROR = '_h'                   # suffix of the hidden clones (hidden_mirror.expand_topology)
FAMILY, TABLE, CHAIN = 'inet', 'filter', 'input'   # the table and base chain of the reference solution
LOG_CHAIN = 'logdrop'           # question 9: the named chain logging then dropping
LOG_RATE = 5                    # question 9 (d): at most LOG_RATE log messages per minute
LOG_PREFIX = 'input drop: '
NFLOG_GROUP = 0                 # `log group 0`, read with `tcpdump -i nflog:0` (the kernel log is not readable in a container)
HTTP_PORTS = (80, 8080)         # the echo server of every machine: HTTP ports...
UDP_PORTS = (530, 630)          # ... and UDP ports
OPEN_PORT = 8080                # question 8: the TCP port opened to everybody
CLOSED_PORT = 80                # ... while this one stays closed
UDP_PORT = UDP_PORTS[0]         # the UDP port of the probes
UDP_SERVER = 'ext1'             # question 5: the machine whose UDP is accepted
REJECTED = 'm2'                 # question 6: the machine whose packets are rejected (the others are dropped)
DOMAIN = 'lab'
PROBE_STEP = 3                  # the probes run after the transplant (download at 1, load at 2)
PROBE_TIMEOUT = 4               # bash /dev/tcp connection timeout: a dropped SYN is declared after that
VISIBLE_MACHINES = ('m1', 'm2', 'm3', 'gw', 'ext1')
HOSTS = ('m1', 'm2', 'm3', 'ext1')   # single-homed machines (gw has gw_lan / gw_ext)

#: ips.<key> -> network, host part (m1 = .1 ... gw = .254 on both sides, ext1 = .51)
HOST_PARTS = {'m1': 1, 'm2': 2, 'm3': 3, 'gw_lan': 254, 'gw_ext': 254, 'ext1': 51}
ADDRESSED = {'m1': 'lan', 'm2': 'lan', 'm3': 'lan', 'gw_lan': 'lan', 'gw_ext': 'ext', 'ext1': 'ext'}

# The visible topology and its hidden mirror (clones m1_h ... ext1_h on lan_h / ext_h).
_TOPOLOGY = {
    'lan': {'m1': 0, 'm2': 0, 'm3': 0, 'gw': 0},
    'ext': {'gw': 1, 'ext1': 0},
}
_SPECS = {
    'm1': {'color': 'lightblue'},
    'm2': {}, 'm3': {},
    'gw': {'color': 'lightgreen'},
    'ext1': {'color': 'lightgrey'},
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
        lan, ext = random_ipv4networks(masks=[24, 24], from_private_network=True,
                                       exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        data.nets.lan, data.nets.ext = lan, ext
        for key, net in ADDRESSED.items():
            network = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{network.network_address + HOST_PARTS[key]}/{network.prefixlen}"))
        # the clones get the same subnets and addresses (persisted in data.json)
        hidden_mirror.copy_addressing(data, _TOPOLOGY, suffix=MIRROR)
        return data


def ip_of(data, machine: str) -> IPv4Interface:
    """The address of a single-homed machine or of its clone (``gw``: ``data.ips.gw_lan`` / ``gw_ext``)."""
    return getattr(data.ips, visible(machine))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS
    _network_specs = {
        'lan': {'mode': 'switch', 'color': 'lightcyan'},
        'ext': {'mode': 'switch', 'color': 'lightgrey'},
        'lan' + MIRROR: {'mode': 'switch'},
        'ext' + MIRROR: {'mode': 'switch'},
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
ou la **traversent**, et applique à chacun une **politique** : le laisser passer (*accept*), le
détruire en silence (*drop*) ou le refuser en prévenant l'émetteur (*reject*), selon des critères
comme l'interface, les adresses, le protocole, les ports ou l'état de la connexion. Un pare-feu
*de machine* (*host firewall*) protège la machine sur laquelle il tourne : c'est le sujet de ce
TP, qui ne filtre que ce qui **entre** dans `m1`. Un pare-feu *de réseau* tourne sur un routeur et
filtre ce qui le traverse (prochain TP).

Sous Linux, tout se passe **dans le noyau**. **Netfilter** y fournit des points d'accrochage
(*hooks*) sur le trajet des paquets, le suivi de connexion (*conntrack*) et la traduction
d'adresses (NAT). **nftables** exécute, à ces points d'accrochage, les règles que lui confie la
commande **`nft`**. nftables a remplacé `iptables`, `ip6tables`, `arptables` et `ebtables` (c'est
l'outil par défaut depuis Debian 10) : une seule commande et une seule syntaxe pour IPv4, IPv6,
ARP et les ponts, un jeu de règles chargé d'un bloc, des ensembles et des dictionnaires intégrés
au langage. Sur une machine récente, la commande `iptables` n'est plus qu'un traducteur : ses
règles sont des règles nftables, que `nft list ruleset` affiche aussi.

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

Les machines du TP ont nftables 1.0.6 (`nft --version`), la version de Debian 12 : c'est elle que
ce cours décrit.

**Comment lire ce cours.** Le TP n'en utilise qu'une partie : le hook `input`
(section @@ref:hooks-ip@@), les tables, les chaînes et les règles (section @@ref:structure@@), les
critères (@@ref:selectors@@), les verdicts (@@ref:verdicts@@), le suivi de connexion
(@@ref:conntrack@@), la commande `nft` (@@ref:nft-cli@@), la journalisation (@@ref:logging@@) et
les tests (@@ref:testing@@). Le reste (les hooks `ingress` et `egress`, les ensembles, la
limitation de débit, la traduction d'adresses, les bonnes pratiques) complète le tableau : vous
en aurez besoin dans les TP suivants et sur de vraies machines.
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
communications locales. Dans ce TP, on travaille uniquement dans le hook **`input`** de `m1`.

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

Le compteur d'une règle ne se remet pas à zéro avec la version de `nft` des machines du TP (il
faut remplacer la règle ; `nft reset rules` n'existe qu'à partir de nftables 1.0.7). On peut en
revanche déclarer un **compteur nommé**, que plusieurs règles alimentent et que l'on relit ou
remet à zéro séparément :

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
nft 'add set inet filter blocklist { type ipv4_addr; }'
nft 'add element inet filter blocklist { 192.0.2.7, 192.0.2.99 }'
nft add rule inet filter input ip saddr @blocklist drop
nft list set inet filter blocklist
nft 'delete element inet filter blocklist { 192.0.2.7 }'
```

Le `type` fixe la nature des éléments : `ipv4_addr`, `ipv6_addr`, `ether_addr` (adresse MAC),
`inet_proto` (protocole), `inet_service` (port), `mark`. Les drapeaux (`flags`) en fixent le
comportement :

| déclaration | effet |
|-------------|-------|
| `flags interval;` | les éléments peuvent être des réseaux ou des plages (`192.0.2.0/24`, `8000-8100`) ; sans ce drapeau, des valeurs isolées seulement |
| `flags timeout; timeout 1h;` | les éléments disparaissent d'eux-mêmes après ce délai |
| `flags dynamic;` | les règles peuvent ajouter elles-mêmes des éléments, au passage des paquets |
| `flags constant;` | le contenu ne peut plus changer |

Un élément peut réunir plusieurs champs, séparés par un point (une **concaténation**) :

```
nft 'add set inet filter allowed { type ipv4_addr . inet_service; }'
nft 'add element inet filter allowed { 192.0.2.2 . 22, 192.0.2.3 . 443 }'
nft add rule inet filter input ip saddr . tcp dport @allowed accept
```

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

Les machines du TP (`m1`, `m2`, `m3`, `gw`, `ext1`) servent toutes un petit **serveur de test**,
en HTTP sur les ports TCP **80 et 8080** et en UDP sur les ports **530 et 630** (`ss -tulnp` les
liste). Il répond par son nom et par les adresses et ports des deux bouts de l'échange, tels qu'il
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
  `output` reste en général ouvert : on fait confiance à la machine elle-même ;
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
  ce qu'elle émet tant qu'il n'y a pas de règle à états ;
- **le shell** : guillemets, accolades et points-virgules se protègent par des apostrophes
  (section @@ref:nft-build@@) ;
- **`flush ruleset`** efface aussi les tables des autres logiciels (Docker, par exemple). Sur une
  telle machine, on ne remplace que sa propre table : le fichier commence alors par les deux
  lignes `table inet filter` et `delete table inet filter`, au lieu de `flush ruleset` ;
- **les règles volatiles** : ce qui n'est pas dans `/etc/nftables.conf` disparaît au
  redémarrage.
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
| ensemble nommé | `nft 'add set inet filter blocklist { type ipv4_addr; }'`, `nft 'add element inet filter blocklist { 192.0.2.7 }'`, `nft add rule inet filter input ip saddr @blocklist drop` |
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

    def cmds_all(self) -> List[str]:
        """The whole reference solution, in question order."""
        return (self.cmds_policy() + self.cmds_lo() + self.cmds_icmp() + self.cmds_udp_server() + self.cmds_reject()
                + self.cmds_established() + self.cmds_open_port() + self.cmds_log())

    # -- states -----------------------------------------------------------------------------

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('m1', d.ips.m1), ('m2', d.ips.m2), ('m3', d.ips.m3), ('gw', d.ips.gw_lan), ('gw_ext', d.ips.gw_ext),
                   ('ext1', d.ips.ext1)]
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
            self.cmd('ext1' + suffix, f"ip address add {d.ips.ext1} dev eth0")
            self.cmd('ext1' + suffix, f"ip route add default via {d.ips.gw_ext.ip}")
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
            # the echo server (HTTP 80 / 8080, UDP 530 / 630); a clone answers with the visible name
            install_echo_server(net_scheme=self, machine=m, name=visible(m), ports=HTTP_PORTS, udp_ports=UDP_PORTS)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the nine questions on m1, applicable more than once."""
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

        # ---------------- diagnostics kept in the archive ---------------------------------
        for c in ("nft -a list ruleset", "ss -tulnp", "ip -br address"):
            self.test(fw, c, allow_error=True)
        self.test(fw_h, "nft list ruleset", step=PROBE_STEP, allow_error=True)   # the transplanted ruleset

        # ---------------- the ruleset of m1: transplanted on its clone, and read as JSON ----
        firewall.transplant_ruleset(self, src=fw, dst=fw_h)
        parsed = firewall.get_nft_json(self, fw)
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
        # question 9: the named chain (of a table holding an input chain) that logs; the jump to it
        log_chain, log_rule, log_chain_drops, jump_rule, jump_last = None, None, False, None, False
        for base in input_chains:
            for user_chain in firewall.user_chains(parsed, family=base['family'], table=base['table']):
                chain_rules = firewall.chain_rules(parsed, base['family'], base['table'], user_chain['name'])
                logs = [r for r in chain_rules if firewall.rule_log(r) is not None]
                if logs and log_chain is None:
                    log_chain, log_rule = user_chain, logs[0]
                    log_chain_drops = any(firewall.rule_verdict(r) == 'drop' for r in chain_rules)
        if log_chain is not None:
            for base in input_chains:
                base_rules = firewall.chain_rules(parsed, base['family'], base['table'], base['name'])
                for r in base_rules:
                    verdict = firewall.rule_verdict(r)
                    if isinstance(verdict, tuple) and verdict[1] == log_chain['name'] and base['table'] == log_chain['table']:
                        jump_rule = r
                        jump_last = base_rules[-1] is r
        log_limit = firewall.rule_limit(log_rule) if log_rule is not None else None

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
        # what the firewall lets through only counts once it filters: an empty ruleset passes everything
        filtering = int(policy == 'drop')

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan` (switch `lan`) | `{lan}` | **`m1`** (`{m1}`, **le pare-feu à configurer**), `m2` (`{m2}`), `m3` (`{m3}`), `gw` eth0 (`{gw_lan}`, la passerelle) |
| `ext` (« l'extérieur ») | `{ext}` | `ext1` (`{ext1}`), `gw` eth1 (`{gw_ext}`) |
""").format(lan=d.nets.lan, m1=m1.ip, m2=m2.ip, m3=m3.ip, gw_lan=d.ips.gw_lan.ip, ext=d.nets.ext, ext1=ext1.ip,
            gw_ext=d.ips.gw_ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les pare-feux, Netfilter et nftables (hooks, tables,
chaînes, règles, critères, verdicts, suivi de connexion), la commande `nft`, la journalisation et
la façon de tester un pare-feu.

**La maquette** (onglet *Schéma*) : un réseau local `lan` avec trois machines `m1`, `m2`, `m3` et
une passerelle `gw`, qui route vers un réseau `ext`, « l'extérieur », où se trouve `ext1`. Vous
configurez le pare-feu de **`m1`** et de `m1` seulement : `m2`, `m3` et `ext1` servent de clients
(et de serveurs) pour vos tests.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : les adresses, la route par défaut de `m1`, `m2`, `m3` et `ext1`
vers `gw`, le routage sur `gw`, les noms dans `/etc/hosts` (`m1`, `m2`, `m3`, `gw`, `gw_ext`,
`ext1`). Il n'y a pas de DNS. Sur **chaque** machine tourne un **serveur de test** HTTP (ports TCP
**80** et **8080**) et UDP (ports **530** et **630**) qui répond par son nom, les adresses et
ports des deux bouts et le TTL du paquet reçu (`curl http://m2/`, `curl http://ext1:8080/`,
`echo bonjour | nc -u -w 1 m2 530` ; section @@ref:testing@@ des Informations). Le jeu de règles
nftables de toutes les machines est vide au départ.

Règles valables pour tout le TP :

- les questions sont à faire **dans l'ordre** et la configuration d'une question terminée reste
  en place : l'évaluation vérifie le jeu de règles **final** (une seule table, `inet filter`, avec
  une chaîne de base `input` ; ne filtrez ni `output` ni `forward`) ;
- travaillez dans **votre** table (`nft add table inet filter`) ; les règles sont volatiles
  (`nft`) : elles ne survivent pas à un redémarrage de la machine ;
- l'évaluation lit le jeu de règles de `m1` (`nft list ruleset`) et le **recopie sur une machine
  cachée identique** à `m1` (mêmes adresses, mêmes serveurs de test), qu'elle sonde depuis des
  copies cachées de `m2`, `m3` et `ext1` : seul ce que dit **le jeu de règles chargé sur `m1`**
  compte, pas l'état de ses serveurs ni ce que vous faites sur `m2`, `m3` ou `ext1` ;
- pour tester sans attendre, utilisez des délais courts : `curl -m 3 …`, `ping -c 2 -W 1 …`,
  `nc -u -w 1 …`.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) vide le jeu de règles de `m1` puis
applique toute la solution et remplit les formulaires ; il est ré-applicable et une évaluation
lancée juste après donne 100/100.

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` sur `m1`
(étape 1), chargé tel quel sur `{fw_h}` après un `nft flush ruleset` (étape 2 ; un jeu de règles
vide laisse la copie sans filtre), puis les sondes (étape 3) depuis `{m2_h}`, `{m3_h}`, `{ext1_h}` et
`{fw_h}` elle-même : `curl` des serveurs de test (HTTP 80 / 8080), `nc -u` (UDP {udp_port}), `ping`,
connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert, `RC=124` détruit, autre code
refusé). Les copies cachées répondent sous les noms visibles (`SERVER=m2`…). La structure du jeu de
règles (politique, critères, verdicts, ordre, `log` / `limit`) est lue dans `nft -j list ruleset` de
`m1` : une chaîne de base `filter` du hook `input`, famille `inet` ou `ip`. Ce que le pare-feu
**laisse passer** (sondes positives) ne compte qu'une fois la politique `drop` en place : un jeu de
règles vide laisse tout passer et vaut 0. Une évaluation dure une
dizaine de secondes (les sondes que le pare-feu doit détruire attendent {timeout} s). Les machines ne
peuvent pas lire le journal du noyau (pas de `CAP_SYSLOG`) : la question 9 journalise vers nflog
(`log … group {group}`, `tcpdump -n -i nflog:0`), mais toute règle `log` est acceptée.
""").format(fw_h=fw_h, m2_h=m2_h, m3_h=m3_h, ext1_h=ext1_h, udp_port=UDP_PORT, timeout=PROBE_TIMEOUT,
            group=NFLOG_GROUP)),
        )

        # =====================================================================
        # Part 1 — before the firewall (question 1)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Avant le pare-feu (question 1)"))

        q1_answers = {"ttl_lan": "64", "ttl_ext": "63", "client_ip": str(m1.ip), "ruleset": "empty"}
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Tests avant le pare-feu"),
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
            title=no_tr("q_before"), max_grade=6, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_is_int(q1.get("ttl_lan"), 64)) + 2 * int(_is_int(q1.get("ttl_ext"), 63))
                  + int(_same_ip(q1.get("client_ip"), m1)) + 2 * int(_norm(q1.get("ruleset")) == "empty"),
            description=tr("avant le pare-feu : TTL depuis m2 (64) et ext1 (63), CLIENT_IP vu par ext1, jeu de règles vide"),
        )

        # =====================================================================
        # Part 2 — the default policy (question 2)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Politique par défaut (question 2)"))

        q2_answers = {"why": "replies_dropped"}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Politique par défaut"),
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
            title=no_tr("q_policy"), max_grade=4, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
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
            title=no_tr("q_udp"), max_grade=2, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
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

Depuis `m2`, `curl` échoue **aussitôt** : `curl: (7) Failed to connect to m1 port 80 … Connection
refused` ; `tcpdump` sur `m2` montre son SYN puis `IP {m1} > {m2}: ICMP {m1} tcp port 80 unreachable`
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
            title=no_tr("q_reject"), max_grade=3, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
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
            title=no_tr("q_log"), max_grade=2, grade_part=part9, scope=params.EXO_EVAL_SCOPE,
            grade=2 * int(_norm(q9.get("where_logs")) == "nflog"),
            description=tr("où lire les paquets journalisés (nflog / journal du noyau)"),
        )


_TRANSLATIONS = {}
