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

Un **pare-feu** (*firewall*) examine les paquets IP qui **entrent** dans une machine, en
**sortent** ou la **traversent**, et applique à chacun une **politique** : le laisser passer
(*accept*), le jeter en silence (*drop*) ou le refuser en prévenant l'émetteur (*reject*), selon
des critères comme l'interface d'arrivée, les adresses, le protocole, les ports ou l'état de la
connexion. Un pare-feu *de machine* (*host firewall*) protège la machine sur laquelle il tourne :
c'est le sujet de ce TP, qui ne filtre que ce qui **entre** dans `m1`. Un pare-feu *de réseau*
tourne sur un routeur et filtre ce qui le traverse (prochain TP).

Sous Linux, le filtrage est fait dans le noyau par **Netfilter**. L'outil qui le configure
aujourd'hui est **`nft`**, du projet **nftables**, qui remplace depuis Debian 10 les anciens
`iptables`, `ip6tables`, `arptables` et `ebtables` : une seule commande et une seule syntaxe pour
IPv4, IPv6, ARP et les ponts, un jeu de règles chargé d'un bloc (`nft -f`), des ensembles
(`{ 80, 8080 }`) et des compteurs intégrés. La commande `iptables` existe encore (`iptables-nft`) :
elle traduit ses règles en nftables, et `nft list ruleset` les montre aussi.
""")
            + info_subtitle(tr("Le trajet d'un paquet : les hooks"), tag="hooks")
            + tr("""

Netfilter offre cinq **points d'accrochage** (*hooks*) sur le trajet d'un paquet dans le noyau :

```
                                            ┌──────── processus locaux ────────┐
                                            │                                  │
                                          input                             output
                                            │                                  │
  arrivée ──> prerouting ──> [décision de routage] ──> forward ──> postrouting ──> départ
                               (pour moi ? à router ?)                 ▲
                                                                       │
                                            (les paquets locaux passent aussi par postrouting)
```

- **`input`** : les paquets **destinés à la machine** (après la décision de routage) ;
- **`output`** : les paquets **émis par la machine** ;
- **`forward`** : les paquets qui **traversent** la machine (routeur) ;
- **`prerouting`** / **`postrouting`** : avant / après la décision de routage, sur tous les
  paquets ; c'est là que se fait la traduction d'adresses (NAT).

Un paquet émis par `m1` vers `m2` passe par `output` ; la réponse de `m2` arrive dans `input`.
Un paquet de `m1` vers elle-même (`127.0.0.1`, ou sa propre adresse) passe par `output` **puis**
par `input`, via l'interface `lo` : un pare-feu qui jette tout en `input` casse aussi les
communications locales. Dans ce TP, on travaille uniquement dans le hook **`input`** de `m1`.
""")
            + info_subtitle(tr("Tables, chaînes, règles"), tag="structure")
            + tr("""

Un jeu de règles nftables (*ruleset*) est organisé en **tables**, qui contiennent des
**chaînes**, qui contiennent des **règles**.

Une **table** appartient à une **famille** : `ip` (IPv4), `ip6` (IPv6), **`inet`** (IPv4 et IPv6 à
la fois, le choix recommandé pour un filtre), `arp`, `bridge`, `netdev`. Son nom est libre
(`filter` par habitude). Une machine peut avoir plusieurs tables ; chacune est indépendante.

Une **chaîne de base** est accrochée à un hook et se déclare avec un **type** (`filter`, `nat` ou
`route`), le **hook**, une **priorité** (l'ordre entre les chaînes accrochées au même hook ; `0`,
alias `filter`, pour le filtrage) et une **politique** par défaut :

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

(les apostrophes protègent les accolades et les points-virgules du shell ; `nft list ruleset`
réaffiche la chaîne avec `priority filter`, le nom de la priorité 0.) La **politique**
(`accept` ou `drop`) est le verdict appliqué aux paquets qui atteignent la fin de la chaîne sans
qu'aucune règle n'ait tranché. Avec `policy drop`, *tout ce qui n'est pas explicitement autorisé
est interdit* : c'est la bonne façon de construire un pare-feu.

Une **chaîne nommée** (ou *régulière*) n'a pas de hook : on y arrive par un saut (`jump`, `goto`)
depuis une autre chaîne ; elle sert à regrouper des règles (par exemple « journaliser puis
jeter »).

Une **règle** est une suite de **critères** (section @@ref:selectors@@) suivie d'**actions** et
d'un **verdict** (section @@ref:verdicts@@). Les règles d'une chaîne sont évaluées **dans l'ordre** ;
la première dont tous les critères sont satisfaits et qui porte un verdict décide du sort du
paquet. Une règle sans verdict (`counter`, `log`…) agit puis laisse le paquet continuer vers la
règle suivante.
""")
            + info_subtitle(tr("Les critères (sélecteurs)"), tag="selectors")
            + tr("""

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | interface d'entrée (`iif` par index : l'interface doit exister ; `iifname` par nom) ; `oif` / `oifname` en sortie |
| `ip saddr 192.168.1.2`, `ip saddr 192.168.1.0/24` | adresse IP source (une adresse, un réseau, une plage `192.168.1.10-192.168.1.20`, un ensemble `{ 192.168.1.2, 192.168.1.3 }`) |
| `ip daddr 10.10.10.51` | adresse IP destination |
| `ip protocol udp`, `meta l4proto udp` | protocole de niveau 4 (`tcp`, `udp`, `icmp`) ; `meta l4proto` vaut aussi pour IPv6 dans une table `inet` |
| `tcp dport 8080`, `tcp dport { 80, 8080 }`, `tcp dport 8000-8100` | port TCP destination ; `tcp sport`, `udp dport`, `udp sport` de même |
| `icmp type echo-request`, `icmp type echo-reply` | type ICMP (`ping` : requête `echo-request`, réponse `echo-reply`) |
| `ct state established,related` | état de la connexion dans le suivi de connexions (section @@ref:conntrack@@) |
| `ip saddr != 192.168.1.2` | négation d'un critère |

Mentionner `tcp dport` ou `icmp type` implique le protocole : inutile d'ajouter `ip protocol tcp`.
Plusieurs critères dans une même règle sont tous requis (un **et**).
""")
            + info_subtitle(tr("Verdicts et actions"), tag="verdicts")
            + tr("""

- **`accept`** : le paquet passe (l'évaluation de la chaîne s'arrête) ;
- **`drop`** : le paquet est jeté **sans rien dire** : l'émetteur attend, réessaie, puis renonce
  (délai d'attente, *timeout*) ;
- **`reject`** : le paquet est refusé et l'émetteur est **prévenu** par un message d'erreur, par
  défaut un ICMP *port unreachable* ; `reject with tcp reset` envoie un segment TCP RST (ce que
  fait une machine sans pare-feu dont le port est fermé), `reject with icmp type
  host-unreachable` choisit le message ICMP. Côté client, l'erreur est immédiate (`Connection
  refused`) au lieu d'un long délai ;
- **`jump chaine`** : évalue la chaîne nommée, et revient si elle ne tranche pas ; **`goto
  chaine`** y va sans retour ; **`return`** revient à la chaîne appelante ;
- **`counter`** : compte les paquets et les octets qui atteignent la règle (visible dans `nft list
  ruleset`, remis à zéro par `nft reset counters`) ; **`log`** : journalise le paquet
  (section @@ref:logging@@) ; **`limit rate 5/minute`** : ne laisse la règle agir qu'à ce rythme.

`counter`, `log` et `limit` sont des **actions sans verdict** : le paquet continue vers la règle
suivante. Elles se combinent dans une règle, dans l'ordre où elles sont écrites : `limit rate
5/minute log prefix "x" ` journalise au plus cinq paquets par minute ; `counter drop` compte puis
jette.

Faut-il jeter ou refuser ? `drop` ne révèle rien à un attaquant et ne coûte rien ; `reject` est
plus agréable pour les utilisateurs légitimes et pour le diagnostic. Vers l'extérieur on jette ;
à l'intérieur on refuse souvent.
""")
            + info_subtitle(tr("Le suivi de connexion : filtrage à états"), tag="conntrack")
            + tr("""

Netfilter mémorise les **connexions** en cours (*conntrack*) : une connexion TCP, mais aussi un
« échange » UDP (une requête et ses réponses entre les mêmes adresses et ports) ou ICMP (une
requête `echo-request` et sa réponse). Chaque paquet est alors dans un **état** :

- **`new`** : il ouvre une nouvelle connexion (premier paquet, le SYN en TCP) ;
- **`established`** : il appartient à une connexion déjà vue dans les deux sens, ou dont le
  premier paquet a déjà été accepté : les **réponses** à ce que la machine a émis ;
- **`related`** : il est lié à une connexion existante (une erreur ICMP la concernant, la
  connexion de données de FTP) ;
- **`invalid`** : il n'appartient à rien de connu (segment TCP hors séquence, erreur isolée).

La règle **`ct state established,related accept`**, placée en **première position**, accepte
d'un coup tout le trafic retour des communications que la machine a elle-même initiées : il ne
reste à autoriser explicitement que les **nouvelles** connexions entrantes que l'on veut servir.
Sans elle, il faut ouvrir à l'aveugle tout ce qui ressemble à une réponse (« tout l'UDP venant du
serveur », par exemple), ce qui laisse aussi passer les requêtes de ce serveur vers la machine :
un filtre **sans état** (*stateless*) ne distingue pas le sens d'un échange. `ct state invalid
drop` complète souvent la première règle.
""")
            + info_subtitle(tr("La commande nft"), tag="nft-cli")
            + tr("""

```
nft list ruleset                                   # tout le jeu de règles (vide au départ)
nft -a list ruleset                                # avec le numéro (handle) de chaque règle
nft add table inet filter                          # une table
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept       # ajoute une règle à la FIN de la chaîne
nft insert rule inet filter input ct state established,related accept   # au DÉBUT
nft insert rule inet filter input handle 7 tcp dport 8080 accept        # avant la règle 7
nft add rule inet filter input handle 7 tcp dport 8080 accept           # après la règle 7
nft delete rule inet filter input handle 7         # supprime la règle 7
nft add chain inet filter logdrop                  # une chaîne nommée (sans hook)
nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'  # apostrophes : le shell garderait sinon les guillemets pour lui
nft flush chain inet filter input                  # vide une chaîne (ses règles) ; flush table, flush ruleset
nft delete table inet filter                       # supprime la table et tout son contenu
nft list ruleset > /etc/nftables.conf              # sauvegarde ; nft -f /etc/nftables.conf recharge
```

L'ordre des règles compte (section @@ref:structure@@) : `add rule` ajoute en fin de chaîne, `insert
rule` en tête, et `handle N` (numéro lu avec `nft -a list ruleset`) place une règle avant (`insert`)
ou après (`add`) une règle existante. Sur une vraie machine, le service `nftables` charge
`/etc/nftables.conf` au démarrage (`systemctl enable nftables`) ; un fichier de règles commence par
`flush ruleset` et se charge d'un bloc, sans trou de sécurité pendant la mise à jour. Attention :
`nft flush ruleset` efface **toutes** les tables, pas seulement les vôtres.
""")
            + info_subtitle(tr("Journaliser et compter"), tag="logging")
            + tr("""

**`counter`** est le moyen le plus simple de voir si une règle sert : `nft list ruleset` affiche
`counter packets 12 bytes 1008` sur la règle (`nft -a list ruleset` pour les handles, `nft reset
counters` pour remettre à zéro). Pour voir **quels** paquets passent par une règle, **`log`** envoie
une ligne par paquet (adresses, protocole, ports, interface) :

- `log prefix "input drop: "` écrit dans le **journal du noyau**, lu sur une vraie machine avec
  `dmesg -w`, `journalctl -k -f` ou dans `/var/log/kern.log` (rsyslog). Dans un conteneur, ce
  journal est celui de la machine hôte et n'est pas accessible ;
- `log prefix "input drop: " group 0` envoie les paquets à **nflog** (groupe 0), que l'on lit
  avec **`tcpdump -n -i nflog:0`** (ou le démon `ulogd`) : c'est la forme à utiliser dans ce TP,
  elle montre les paquets journalisés en direct, sur `m1` elle-même ;
- **`limit rate 5/minute`** devant `log` borne le nombre de lignes : sans limite, une attaque ou
  une simple boucle de `ping` remplit le journal. C'est un seau à jetons : 5 jetons au départ (la
  rafale, *burst*, 5 par défaut ; `burst 10 packets` pour en tolérer plus), puis un jeton toutes les
  12 secondes ; les paquets sans jeton ne sont pas journalisés mais continuent vers la règle suivante.

Le préfixe contient une espace et des guillemets : tapée dans un shell, la règle entière doit
être protégée par des apostrophes (`nft 'add rule inet filter logdrop log prefix "input drop: "
group 0'`), sinon le shell retire les guillemets et `nft` ne comprend plus la commande.

`log` n'est pas un verdict : on le fait suivre d'un `drop` (ou d'un `accept`) dans la même règle
ou dans la règle suivante. L'usage est d'écrire une **chaîne nommée** `logdrop` qui journalise
puis jette, et de sauter dedans (`jump logdrop`) en dernière règle des chaînes concernées, plutôt
que de répéter `log` partout.
""")
            + info_subtitle(tr("Observer et tester un pare-feu"), tag="testing")
            + tr("""

Les machines du TP (`m1`, `m2`, `m3`, `gw`, `ext1`) servent toutes un petit **serveur de test**,
en HTTP sur les ports TCP **80 et 8080** et en UDP sur les ports **530 et 630** (`ss -tulnp` les
liste). Il répond par son nom et par les adresses et ports des deux bouts de l'échange, tels qu'il
les voit, et par le TTL du paquet reçu (64 depuis le même réseau, un de moins par routeur
traversé) :

```
m1:~# curl http://m2/                   # ou curl http://m2:8080/ ; -m 3 pour ne pas attendre plus de 3 s
SERVER=m2
SERVER_IP=192.168.1.2
SERVER_PORT=80
CLIENT_IP=192.168.1.1
CLIENT_PORT=47152
TTL=64
m1:~# echo bonjour | nc -u -w 1 m2 530  # un datagramme UDP vers le port 530 (ou 630) : même réponse
```

Pour savoir ce qu'un client voit, lisez le message d'erreur : `curl: (7) Failed to connect …
Connection refused` **immédiat** signale un `reject` (ou un port fermé sans pare-feu) ;
`Connection timed out` **après le délai** signale un `drop` (ou une machine éteinte). `nc -u -w 1`
se termine sans rien afficher quand aucune réponse n'arrive (`drop`, ou le datagramme de réponse
bloqué). `ping -c 2 -W 1 m1` : `100% packet loss` quand les requêtes ou les réponses sont
jetées. `tcpdump -n -i eth0 icmp or tcp port 80` sur le client montre ce qu'il reçoit (le message
ICMP *port unreachable* d'un `reject`, ou rien), `tcpdump -n -i eth0 'port 80 or port 530'` sur le
serveur ce qui lui arrive malgré tout. Enfin `nft list ruleset` avec des `counter` dit quelle
règle a vu les paquets : la méthode de diagnostic de base d'un pare-feu.
""")
            + info_subtitle(tr("Pour qui connaît iptables"), tag="iptables")
            + tr("""

| iptables | nftables |
|----------|----------|
| `iptables -L -v -n` | `nft list ruleset` |
| `iptables -P INPUT DROP` | `policy drop;` dans la déclaration de la chaîne de base |
| `iptables -A INPUT -i lo -j ACCEPT` | `nft add rule inet filter input iif lo accept` |
| `iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT` | `… icmp type echo-reply accept` |
| `iptables -A INPUT -p udp -s 10.10.10.51 -j ACCEPT` | `… ip saddr 10.10.10.51 meta l4proto udp accept` |
| `iptables -A INPUT -s 192.168.1.2 -j REJECT` | `… ip saddr 192.168.1.2 reject` |
| `iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT` | `… ct state established,related accept` |
| `iptables -A INPUT -p tcp --dport 8080 -j ACCEPT` | `… tcp dport 8080 accept` |
| `iptables -I INPUT 1 …` (insérer en tête) | `nft insert rule inet filter input …` |
| `iptables -N logetdrop`, `iptables -A INPUT -j logetdrop` | `nft add chain inet filter logdrop`, `… input jump logdrop` |
| `iptables -A logetdrop -m limit --limit 5/min -j LOG` | `… logdrop limit rate 5/minute log prefix "…" group 0` |
| `iptables -D INPUT 3` | `nft delete rule inet filter input handle N` (`nft -a list ruleset`) |
| `iptables -F` | `nft flush chain inet filter input` |
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""

| besoin | commande |
|--------|----------|
| état du pare-feu | `nft list ruleset`, `nft -a list ruleset` (handles), `nft list chain inet filter input` |
| table et chaîne de base | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'` |
| règles | `nft add rule inet filter input …` (fin), `nft insert rule inet filter input …` (début), `nft insert rule inet filter input handle N …` (avant la règle N), `nft delete rule inet filter input handle N` |
| critères | `iif lo`, `ip saddr A.B.C.D`, `meta l4proto udp`, `tcp dport 8080`, `icmp type echo-reply`, `ct state established,related` |
| verdicts et actions | `accept`, `drop`, `reject`, `jump logdrop`, `counter`, `log prefix "…" group 0`, `limit rate 5/minute` |
| chaîne nommée | `nft add chain inet filter logdrop`, `nft 'add rule inet filter logdrop limit rate 5/minute log prefix "input drop: " group 0'`, `nft add rule inet filter logdrop counter drop`, `nft add rule inet filter input jump logdrop` |
| journal | `tcpdump -n -i nflog:0` (règles `log … group 0`) |
| tout effacer | `nft flush chain inet filter input`, `nft delete table inet filter` |
| tests | `curl -m 3 http://m2/`, `curl -m 3 http://m2:8080/`, `echo bonjour | nc -u -w 1 m2 530`, `ping -c 2 -W 1 m2`, `ss -tulnp`, `tcpdump -n -i eth0 icmp or tcp port 80` |
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
connexions TCP par `bash` (`/dev/tcp`, délai {timeout} s : `RC=0` ouvert, `RC=124` jeté, autre code
refusé). Les copies cachées répondent sous les noms visibles (`SERVER=m2`…). La structure du jeu de
règles (politique, critères, verdicts, ordre, `log` / `limit`) est lue dans `nft -j list ruleset` de
`m1` : une chaîne de base `filter` du hook `input`, famille `inet` ou `ip`. Ce que le pare-feu
**laisse passer** (sondes positives) ne compte qu'une fois la politique `drop` en place : un jeu de
règles vide laisse tout passer et vaut 0. Une évaluation dure une
dizaine de secondes (les sondes que le pare-feu doit jeter attendent {timeout} s). Les machines ne
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
- pourquoi `m1` ne joint-elle plus `m2`, alors que seule la chaîne `input` filtre ? @@{why:>les requêtes de m1 partent (output n'est pas filtré) mais les réponses de m2 arrivent dans input et sont jetées : la connexion n'aboutit pas>>>replies_dropped|la politique drop s'applique à toutes les chaînes, output comprise>>>all_chains|m2 ne reçoit plus les requêtes de m1>>>no_requests|la table inet ne gère pas IPv4>>>inet_ipv6}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`nft list ruleset` affiche la table et la chaîne vide avec `policy drop`. Tout ce qui arrive sur
`m1` est jeté, y compris les **réponses** (SYN-ACK de `m2`, datagrammes UDP de retour, `echo-reply`)
à ce que `m1` émet : les requêtes partent (`output` n'est pas filtré), rien ne revient, `curl` et
`nc` expirent, `ping` perd tout.

- Réponse : les réponses de m2 sont jetées dans input.
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
            description=tr("pourquoi m1 ne joint plus m2 : les réponses sont jetées dans input"),
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
peut toujours pas pinguer `m1` : ses requêtes (`echo-request`) sont jetées. Observez-les avec
`tcpdump -n -i eth0 icmp` sur `m1`.
""").format(m2=m2.ip, ext1=ext1.ip)
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

`m1` reçoit les réponses à ses propres `ping` ; les `echo-request` de `m2` sont jetés par la
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
            description=tr("m2 ne pingue pas m1 (les echo-request sont jetés)"),
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
- depuis `ext1`, `nc -u m1 530` obtient-il une réponse ? @@{ext1_queries:>oui : la règle accepte tout datagramme UDP venant de ext1, requête ou réponse, elle ne distingue pas le sens de l'échange>>>yes_stateless|non : seules les réponses aux requêtes de m1 passent>>>answers_only|non : ext1 est dans un autre réseau IP, ses paquets sont routés et jetés par gw>>>other_network|oui, mais seulement sur le port 630>>>only_630}@@
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
`m2` (`{m2}`) ; ceux de `m3` (`{m3}`) restent jetés par la politique `drop`. Comparez, en lisant
les messages d'erreur et le temps de réponse (section @@ref:testing@@ des Informations) :

- depuis `m2` : `curl -m 5 http://m1/` ;
- depuis `m3` : `curl -m 5 http://m1/` ;
- depuis `m1` : `curl -m 5 http://m2/` puis `curl -m 5 http://m3/`.

Pendant l'essai depuis `m2`, capturez sur `m2` avec `tcpdump -n -i eth0 'icmp or tcp port 80'` :
que reçoit `m2` de `m1` ?
""").format(m2=m2.ip, m3=m3.ip)
            + tr("""
- depuis `m2`, `curl http://m1/` : @@{from_m2:>échoue immédiatement, « Connection refused » : m1 répond par une erreur (ICMP port unreachable) au SYN de m2>>>refused|attend puis expire (délai d'attente) : rien ne revient>>>timeout|la page s'affiche>>>works}@@
- depuis `m3`, `curl http://m1/` : @@{from_m3:>attend puis expire (délai d'attente) : le SYN est jeté sans réponse>>>timeout|échoue immédiatement, « Connection refused »>>>refused|la page s'affiche>>>works}@@
- depuis `m1`, vers `m2` et vers `m3` : @@{from_m1:>les deux échouent après le délai : les requêtes partent mais les réponses (SYN-ACK) arrivent dans input, rejetée pour m2 (c'est m2 qui reçoit l'erreur), jetée pour m3>>>both_fail|seule m3 répond>>>only_m3|seule m2 répond>>>only_m2|les deux pages s'affichent : output n'est pas filtré>>>both_work}@@
""")
            + instructor(tr("""
**Solution.** Sur `m1` :

```
{cmds}```

Depuis `m2`, `curl` échoue **aussitôt** : `curl: (7) Failed to connect to m1 port 80 … Connection
refused` ; `tcpdump` sur `m2` montre son SYN puis `IP {m1} > {m2}: ICMP {m1} tcp port 80 unreachable`
(`reject with tcp reset` donnerait un RST ; `nft list ruleset` affiche la règle sous sa forme complète,
`reject with icmp port-unreachable`). Depuis `m3`, `curl` attend
les 5 s puis `Connection timed out` : le SYN est jeté, `m3` le retransmet, rien ne revient. Depuis
`m1`, les deux `curl` expirent : la requête part, le SYN-ACK de `m2` est rejeté (le message ICMP
part vers `m2`, pas vers le processus `curl`), celui de `m3` est jeté.

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
premier datagramme UDP) ne sont ni `established` ni `related` : refusées pour `m2`, jetées pour `m3`.
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
  `m3` et `ext1` (ouvert), vers le port {closed} depuis `ext1` (jeté), et une règle `accept` avec
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
            description=tr("le port {closed} de m1 reste fermé à ext1 (jeté)").format(closed=CLOSED_PORT),
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
jetés : `log prefix "input drop: " group {group}` (section @@ref:logging@@ des Informations ; dans le
shell, protégez toute la règle par des apostrophes à cause des guillemets du préfixe). Sur `m1`,
lancez `tcpdump -n -i nflog:{group}` et, depuis `m3`, `curl -m 3 http://m1/` : les SYN jetés
apparaissent. Pourquoi les paquets de `m2` n'y sont-ils pas ?

**(b)** Créez une chaîne nommée **`{chain}`** (sans hook) contenant une règle `log` suivie d'une
règle `drop` (ou `counter drop`).

**(c)** Remplacez la règle `log` de la chaîne `input` par un saut vers `{chain}` (`jump {chain}`),
en **dernière règle** : supprimez l'ancienne avec `nft -a list ruleset` et `nft delete rule inet
filter input handle N`. Vérifiez que les paquets de `m3` sont toujours journalisés puis jetés.

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
n'atteignent jamais la fin de la chaîne. Sans `group`, `log` écrit dans le journal du noyau, que les
conteneurs du TP ne peuvent pas lire (`dmesg` : *Operation not permitted*). (b) et (c) : la chaîne
`{chain}` journalise puis jette ; `jump {chain}` en dernière règle de `input` ; la politique `drop`
reste en filet de sécurité. (d) `limit rate {rate}/minute` est un seau à jetons : {rate} jetons au
départ (la rafale par défaut), puis un toutes les 12 s ; sur les 20 `echo-request` de `m3`, `tcpdump`
n'affiche que les premiers (une seule ligne si des paquets jetés juste avant ont vidé le seau), le
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
            description=tr("une chaîne nommée qui journalise (log) puis jette (drop)"),
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
