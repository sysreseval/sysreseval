"""nftables-misc — Aspects avancés de nftables.

Projet « divers » : sur un pare-feu d'hôte `srv`, l'étudiant met en œuvre des
fonctionnalités variées de nftables :
- **ensembles nommés** (*named sets*) : liste noire d'adresses, liste blanche
  d'administrateurs pour SSH ;
- **reject vs drop** : refus explicite (rapide) contre rejet silencieux ;
- **limitation de débit** (`limit rate`) ;
- **compteurs et journalisation** (`counter`, `log`).

Évaluation par « miroir caché » : le ruleset de `srv` est transplanté sur `srv_h`
et sondé depuis plusieurs machines contrôlées (admin / user / bad).
"""

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import List

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from SRE.lib_sre import info_subtitle, info_toc, instructor
from ips import random_ipv4networks, random_ips_from_topology
from net_config import set_net_config_entry, set_ip_forward, get_net_config_from_topology
import firewall
import hidden_mirror

default_language = "fr"
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("nftables : aspects avancés (sets, limit, reject) (misc)",
           en="nftables: advanced features (sets, limit, reject) (misc)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60
eval_before_exit = True

SSH_PORT = 22
HTTP_PORT = 80
REJECT_PORT = 8080   # doit être *rejeté* (refus explicite)
DROP_PORT = 9090     # doit être *détruit* (silencieux, par la politique)

# The declaration of the input chain of the reference solution: the text loaded by `final` and
# quoted in the instructor's solutions.
INPUT_CHAIN = "type filter hook input priority 0; policy drop;"

_TOPOLOGY = {
    # tout le monde sur un seul LAN : srv filtre le trafic entrant par source.
    "net1": ["srv", "admin", "user", "bad"],
}
_SPECS = {
    "srv": {"color": "lightblue"},
    "admin": {"color": "lightgreen"},
    "user": {},
    "bad": {"color": "salmon"},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS)


def render_set(name: str, address) -> List[str]:
    """The lines declaring a named set of IPv4 addresses that holds one address."""
    return [f"set {name} {{", "    type ipv4_addr", f"    elements = {{ {address} }}", "}"]


def render_table(sets: List[List[str]], rules: List[str], other_chains: bool = False) -> str:
    """The ``table inet filter { ... }`` block of an nftables file: the given named sets
    (``render_set``), the input chain with the given rules and, with *other_chains*, the
    accept-all forward and output chains of the reference solution."""
    lines = ["table inet filter {"]
    for block in sets:
        lines += [f"    {line}" for line in block]
    lines += ["    chain input {", f"        {INPUT_CHAIN}"]
    lines += [f"        {rule}" for rule in rules]
    lines.append("    }")
    if other_chains:
        lines += ["    chain forward { type filter hook forward priority 0; policy accept; }",
                  "    chain output  { type filter hook output  priority 0; policy accept; }"]
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        (data.nets.net1,) = random_ipv4networks(
            masks=[24],
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        random_ips_from_topology(data, _TOPOLOGY)
        hidden_mirror.copy_addressing(data, _TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config = get_net_config_from_topology(net_scheme=self, gateway=None)
        self.routers = hidden_mirror.router_machines(self._topology)  # aucun (topo à plat)

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("nftables en bref"), tag="intro")
            + tr("""
Sous Linux, le filtrage des paquets se fait **dans le noyau**. **Netfilter** y fournit des points
d'accrochage (*hooks*) sur le trajet des paquets et le suivi de connexion (*conntrack*) ;
**nftables** exécute, à ces points, les règles que lui confie la commande **`nft`**. Le pare-feu
d'une machine tient en peu de choses : une chaîne `input` de politique `drop`, la règle à états,
puis une règle par service ouvert. Ce TP y ajoute les outils qui rendent un jeu de règles
**court, rapide et modifiable sans le recharger** : les ensembles, les dictionnaires, le choix
entre `reject` et `drop`, la limitation de débit, les compteurs et la journalisation.

| terme | rôle |
|-------|------|
| famille | les paquets qu'une table voit : `ip` (IPv4), `ip6` (IPv6), `inet` (les deux), `arp`, `bridge`, `netdev` |
| table | un conteneur nommé, dans une famille, de chaînes, d'ensembles, de dictionnaires et de compteurs |
| chaîne de base | une liste de règles accrochée à un hook, avec une priorité et une politique par défaut |
| chaîne régulière | une liste de règles sans hook, où l'on arrive par un saut (`jump`, `goto`) |
| règle | des critères puis des actions, évalués de gauche à droite |
| verdict | ce que devient le paquet : `accept`, `drop`, `jump`… |
| ensemble (*set*) | des valeurs d'un même type, que les règles consultent en une seule opération |
| dictionnaire (*map*) | des associations clé : valeur ; la valeur peut être un verdict (*verdict map*) |

Les machines du TP ont nftables 1.1.3 (`nft --version`), la version de Debian 13 : c'est elle que
ce cours décrit.

**Comment lire ce cours.** Les sections @@ref:hooks@@ à @@ref:conntrack@@ rappellent les bases,
et la section @@ref:base@@ donne le **socle** sur lequel s'appuie tout le TP : commencez par
elle. Les questions 1 et 2 utilisent les ensembles nommés (sections @@ref:named-sets@@ et
@@ref:lists@@), la question 3 `reject` et `drop` (section @@ref:reject-drop@@), la question 4 la
limitation de débit, les compteurs et la journalisation (sections @@ref:limit@@ et
@@ref:counters-log@@) ; la section @@ref:testing@@ dit comment vérifier chaque règle. Le reste
(les ensembles alimentés par les règles, les dictionnaires, les quotas, la trace) complète le
tableau : vous en aurez besoin sur de vraies machines.
""")
            + info_subtitle(tr("Le trajet d'un paquet : les hooks"), tag="hooks")
            + tr("""
Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Choisir le hook d'une chaîne, c'est choisir **quels
paquets** elle verra, et **à quel moment** de leur traitement.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hooks-ip@@ Les cinq hooks de la pile IP

| hook | paquets vus |
|------|-------------|
| `prerouting` | tous les paquets **reçus**, avant la décision de routage |
| `input` | les paquets **destinés à la machine** |
| `forward` | les paquets que la machine **route** d'une interface vers une autre |
| `output` | les paquets **émis par les processus de la machine** |
| `postrouting` | tous les paquets qui **partent**, routés ou émis localement |

Un paquet reçu pour la machine traverse `prerouting` puis `input` ; un paquet routé,
`prerouting`, `forward` puis `postrouting` ; un paquet émis, `output` puis `postrouting`. Un
paquet de la machine vers elle-même (`127.0.0.1`, ou sa propre adresse) fait les deux trajets à
la suite, à travers l'interface `lo` : un pare-feu qui détruit tout en `input` casse aussi les
communications locales. Ce TP ne travaille que dans le hook **`input`** de `srv`.

### @@sec:families@@ ingress, egress et les familles

Deux autres hooks sont attachés à **une interface** (`device` dans la déclaration de la
chaîne), en dehors de la pile IP : **`ingress`** voit tout ce que l'interface reçoit, **avant
`prerouting`** (donc avant le suivi de connexion : c'est l'endroit le moins coûteux pour
détruire un trafic indésirable), et **`egress`** tout ce qu'elle émet, **après `postrouting`**.
Les hooks disponibles dépendent de la **famille** de la table :

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | les cinq mêmes |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

ARP n'est pas de l'IP : les chaînes des familles `ip`, `ip6` et `inet` ne voient jamais les
requêtes ni les réponses ARP, et une politique `drop` en `input` n'empêche pas une machine de
trouver l'adresse MAC de ses voisines.
""")
            + info_subtitle(tr("Tables, chaînes, règles"), tag="structure")
            + tr("""
Un jeu de règles nftables (*ruleset*) est organisé en **tables**, qui contiennent des
**chaînes**, qui contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table
ni chaîne prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des
chaînes sont libres ; `filter` et `input` ne sont que des habitudes.

### @@sec:base-chains@@ Tables et chaînes de base

Une **table** appartient à une famille ; pour filtrer, **`inet`** est le choix recommandé (les
mêmes règles valent pour IPv4 et pour IPv6). C'est un espace de noms : ses chaînes, ses
ensembles, ses dictionnaires et ses compteurs ne sont connus que de ses propres règles. Une
**chaîne de base** est accrochée à un hook :

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- le **type** : `filter` pour filtrer, `nat` pour la traduction d'adresses, `route` pour
  refaire le routage d'un paquet émis par la machine ;
- le **hook** ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus
  petite valeur à la plus grande (`0`, ou `filter`, pour le filtrage) ;
- la **politique** par défaut, `accept` ou `drop` : le verdict appliqué aux paquets qui
  atteignent la fin de la chaîne sans qu'aucune règle n'ait tranché. Sans `policy`, c'est
  `accept` ; `reject` n'est pas une politique possible.

Avec `policy drop`, *tout ce qui n'est pas explicitement autorisé est interdit* : c'est la bonne
façon de construire un pare-feu.

### @@sec:priorities@@ Plusieurs chaînes sur un même hook

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées
au même hook : un paquet les traverse **toutes**, par priorité croissante. Les priorités
usuelles ont un nom : `raw` (-300), `mangle` (-150), `dstnat` (-100), `filter` (0), `security`
(50), `srcnat` (100) ; le suivi de connexion opère à la priorité -200, donc avant une chaîne de
priorité `filter`. Les deux verdicts ne sont pas symétriques :

- **`drop` est définitif** : le paquet est détruit sur-le-champ, plus aucune chaîne ne le voit ;
- **`accept` ne vaut que pour la chaîne de base en cours** : le paquet passe à la chaîne
  suivante, qui peut encore le détruire.

### @@sec:regular-chains@@ Chaînes régulières

Une **chaîne régulière** n'a ni hook, ni type, ni politique (`nft add chain inet filter
journal`). Elle ne voit que les paquets qu'une règle lui envoie par **`jump`** ou par **`goto`**
depuis une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump` (ou sur le
verdict `return`), l'évaluation reprend dans la chaîne appelante, à la règle qui suit le saut ;
avec `goto`, elle n'y revient pas. Les sauts s'imbriquent sur 16 niveaux au plus. Ces chaînes
servent à factoriser des règles (« journaliser puis détruire ») et à structurer un grand jeu de
règles (une chaîne par service ou par zone).

### @@sec:rules@@ Règles, critères et verdicts

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des **critères**,
puis des **actions** et, le plus souvent, un **verdict**. Dès qu'un critère n'est pas
satisfait, le paquet passe à la règle suivante. Les règles d'une chaîne sont évaluées **dans
l'ordre** : la première règle satisfaite qui porte un verdict décide, et les suivantes ne sont
pas consultées. L'ordre des règles fait donc partie de la politique.

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | interface d'entrée (`iif` : par son numéro, l'interface doit exister ; `iifname` : par son nom) |
| `ip saddr 192.0.2.13`, `ip daddr 192.0.2.0/24` | adresse IPv4 source, destination (une adresse ou un réseau) |
| `meta l4proto udp`, `ip protocol icmp` | protocole transporté (`meta l4proto` : en IPv4 comme en IPv6) |
| `tcp dport 22`, `udp sport 53` | port TCP ou UDP, destination ou source |
| `icmp type echo-request` | type ICMP |
| `ct state established,related` | état de la connexion (section @@ref:conntrack@@) |

Une valeur peut être une plage (`tcp dport 8000-8100`), un ensemble (`tcp dport { 22, 80 }`,
section @@ref:sets@@) ou être niée (`ip saddr != 192.0.2.13`). Plusieurs critères dans une
règle sont tous requis ; nommer un champ implique son protocole (`tcp dport 22` ne concerne que
TCP).

| verdict ou action | effet |
|-------------------|-------|
| `accept` | le paquet passe ; l'évaluation de la chaîne de base s'arrête |
| `drop` | le paquet est détruit sans rien dire |
| `reject` | le paquet est détruit et l'émetteur prévenu (section @@ref:reject-drop@@) |
| `jump chaine`, `goto chaine`, `return` | saut vers une chaîne régulière, retour |
| `counter`, `log`, `limit rate …` | actions **sans verdict** : la règle se poursuit, puis le paquet passe à la règle suivante (sections @@ref:limit@@ et @@ref:counters-log@@) |

L'ordre des mots compte aussi à l'intérieur d'une règle : `tcp dport 22 counter accept` compte
les paquets destinés au port 22, `counter tcp dport 22 accept` tous ceux qui atteignent la
règle.
""")
            + info_subtitle(tr("Le suivi de connexion et la règle à états"), tag="conntrack")
            + tr("""
Netfilter mémorise les **connexions** en cours (*conntrack*) : une connexion TCP, mais aussi un
« échange » UDP ou ICMP (une requête et sa réponse). Il ne filtre rien : il **étiquette**
chaque paquet d'un **état**, que les règles testent avec `ct state`.

| état | le paquet… |
|------|------------|
| `new` | ouvre une connexion, ou appartient à une connexion dont on n'a encore vu qu'un seul sens (le SYN en TCP) |
| `established` | appartient à une connexion dont on a vu des paquets dans les deux sens ; la toute première réponse (le SYN-ACK, l'`echo-reply`) est déjà dans cet état |
| `related` | est lié à une connexion connue sans lui appartenir : une erreur ICMP qui la concerne, par exemple |
| `invalid` | ne correspond à rien de connu et ne peut pas ouvrir de connexion |
| `untracked` | a été soustrait au suivi par une règle `notrack` |

La **règle à états** `ct state established,related accept`, placée en **première position**,
accepte d'un coup les réponses aux communications que la machine a elle-même initiées et la
suite des connexions entrantes déjà acceptées : il ne reste à décider que du sort des
**nouvelles** connexions. `ct state invalid drop` la complète souvent. Conséquence à retenir
pour la suite : **les règles placées après elle ne voient plus que le premier paquet de chaque
connexion**.
""")
            + info_subtitle(tr("Le socle d'un pare-feu de machine"), tag="base")
            + tr("""
Tout le TP part du même socle : une chaîne `input` de politique `drop`, la règle à états et
l'interface `lo`. Les outils des sections suivantes viennent s'y ajouter. Il y a deux façons de
travailler : écrire un fichier et le charger d'un bloc, ou taper les commandes une à une.

### @@sec:nft-files@@ Un fichier de règles

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # les réponses à ce que la machine a émis, puis les communications locales
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept

        # ... puis ce que l'on ouvre, règle par règle
    }
}
```

```
nft -c -f /etc/nftables.conf      # vérifie le fichier sans rien changer
nft -f /etc/nftables.conf         # le charge
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; à aucun moment la machine ne se retrouve sans règles ;
- le fichier commence par **`flush ruleset`** : l'ancien jeu de règles est remplacé d'un coup.
  Sans cette ligne, recharger le fichier ajouterait ses règles une seconde fois, à la suite des
  premières ;
- `define ADMIN = 192.0.2.13` nomme une valeur, reprise par `$ADMIN` ; `include "fichier"`
  insère un autre fichier ;
- `nft -s list ruleset > fichier` sauvegarde le jeu de règles en place dans un fichier
  rechargeable (ajoutez-lui `flush ruleset` en tête) ;
- sous Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage. Les règles
  tapées avec `nft` sont **volatiles** : elles disparaissent au redémarrage.

### @@sec:nft-commands@@ Les commandes une à une

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept                               # ajoute en FIN de chaîne
nft insert rule inet filter input ct state established,related accept      # insère en TÊTE
```

**Le shell passe avant `nft`.** Le point-virgule, les guillemets, les parenthèses, `*`, `|`,
`&`, `<` et `>` ont un sens pour le shell, qui les interprète ou les retire avant que `nft` ne
voie la commande. La règle simple : dès qu'une commande contient autre chose que des mots, des
nombres et des adresses, **entourez d'apostrophes tout ce qui suit `nft`**.

### @@sec:nft-edit@@ Consulter, placer, supprimer

```
nft list ruleset                                                   # tout le jeu de règles
nft -a list ruleset                                                # avec le handle de chaque règle
nft list chain inet filter input                                   # une chaîne
nft insert rule inet filter input handle 7 tcp dport 80 accept     # AVANT la règle de handle 7
nft add rule inet filter input handle 7 tcp dport 80 accept        # APRÈS la règle 7
nft replace rule inet filter input handle 7 tcp dport 443 accept   # À LA PLACE de la règle 7
nft delete rule inet filter input handle 7                         # supprime la règle 7
nft flush chain inet filter input                                  # vide la chaîne ; sa politique reste
nft delete table inet filter                                       # supprime la table et son contenu
nft flush ruleset                                                  # efface tout
```

Le noyau attribue à chaque règle un numéro qui ne change plus, son **handle**, que `nft -a list
ruleset` affiche en fin de ligne (`# handle 7`) : ce n'est pas un numéro de ligne. Relisez
`nft list ruleset` après chaque ajout : une règle placée après un `accept`, un `drop` ou un
`reject` qui couvre les mêmes paquets n'est jamais consultée.
""")
            + info_subtitle(tr("Les ensembles (sets)"), tag="sets")
            + tr("""
Un **ensemble** (*set*) réunit des valeurs d'un même type. Une règle le consulte en **une seule
opération**, quel que soit le nombre de ses éléments : une règle et un ensemble de mille
adresses remplacent mille règles, et vont bien plus vite qu'elles.

### @@sec:anonymous-sets@@ Ensembles anonymes

Un ensemble **anonyme** s'écrit entre accolades, directement dans la règle :

```
tcp dport { 22, 80, 443 } accept
ip saddr { 192.0.2.13, 198.51.100.0/24 } drop
```

Il est figé : pour le modifier, il faut remplacer la règle.

### @@sec:named-sets@@ Ensembles nommés

Un ensemble **nommé** est un objet de la table, déclaré à part avec le **type** de ses
éléments ; les règles le désignent par `@nom` :

```
table inet filter {
    set liste_noire {
        type ipv4_addr
        elements = { 192.0.2.13, 198.51.100.7 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @liste_noire drop
    }
}
```

Son intérêt : son contenu se **modifie sans toucher aux règles** ni recharger le jeu de règles,
et plusieurs règles peuvent s'en servir.

```
nft 'add set inet filter liste_noire { type ipv4_addr; }'        # crée un ensemble vide
nft 'add element inet filter liste_noire { 203.0.113.9 }'        # ajoute un élément (ou plusieurs)
nft 'delete element inet filter liste_noire { 203.0.113.9 }'     # en retire un
nft 'get element inet filter liste_noire { 203.0.113.9 }'        # l'élément y est-il ?
nft list set inet filter liste_noire                             # affiche son contenu
nft list sets                                                    # tous les ensembles
nft flush set inet filter liste_noire                            # le vide
nft delete set inet filter liste_noire                           # le supprime
```

L'effet est immédiat : l'adresse ajoutée à la liste noire est bloquée au paquet suivant,
l'adresse retirée est débloquée aussitôt. On ne peut supprimer qu'un ensemble qu'aucune règle
ne consulte plus.

### @@sec:set-types@@ Types et options

Le `type` fixe la nature des éléments :

| type | éléments |
|------|----------|
| `ipv4_addr`, `ipv6_addr` | adresses IPv4, adresses IPv6 |
| `ether_addr` | adresses MAC |
| `inet_service` | ports |
| `inet_proto` | protocoles (`tcp`, `udp`, `icmp`…) |
| `mark` | marques de paquets |

À la place du type, `typeof` nomme le champ que l'ensemble servira à comparer, et `nft` en
déduit le type : `typeof ip saddr` vaut `type ipv4_addr`. Les options règlent le comportement
de l'ensemble :

| déclaration | effet |
|-------------|-------|
| `flags interval` | les éléments peuvent être des **réseaux** ou des **plages** (`198.51.100.0/24`, `192.0.2.10-192.0.2.20`, `1000-2000` pour des ports) ; sans ce drapeau, des valeurs isolées seulement |
| `auto-merge` | avec `flags interval` : les éléments voisins ou qui se recouvrent sont fusionnés, au lieu d'être refusés (`conflicting intervals`) |
| `flags timeout`, `timeout 1h` | les éléments **expirent** (section @@ref:set-timeouts@@) |
| `flags dynamic` | les **règles** peuvent ajouter des éléments, au passage des paquets (section @@ref:dynamic-sets@@) |
| `flags constant` | le contenu ne peut plus changer |
| `size 1000` | nombre maximal d'éléments |

Dans un fichier, chaque option occupe une ligne ; sur une ligne de commande, elles se séparent
par des points-virgules et les drapeaux par des virgules (`flags interval,timeout;`).

```
set reseaux_bloques {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 198.51.100.0/24, 192.0.2.10-192.0.2.20 }
}
```

### @@sec:set-timeouts@@ Éléments à durée limitée

Avec `flags timeout`, un élément disparaît de lui-même au bout d'un délai : celui de
l'ensemble (`timeout` dans la déclaration), ou le sien propre, donné à l'ajout. C'est l'outil
d'une liste noire **temporaire**.

```
nft 'add set inet filter punis { type ipv4_addr; flags timeout; timeout 1h; }'
nft 'add element inet filter punis { 203.0.113.9 }'                 # expire au bout d'une heure
nft 'add element inet filter punis { 198.51.100.7 timeout 10m }'    # expire au bout de dix minutes
nft list set inet filter punis                                      # « expires » : le temps restant
```

### @@sec:concatenations@@ Concaténations

Un élément peut réunir plusieurs champs, séparés par un point : « telle adresse **et** tel
port ». Le critère nomme les champs dans le même ordre.

```
nft 'add set inet filter acces { type ipv4_addr . inet_service; }'
nft 'add element inet filter acces { 192.0.2.13 . 22, 192.0.2.14 . 443 }'
nft add rule inet filter input ip saddr . tcp dport @acces accept
```

La même chose avec un ensemble anonyme :
`ip saddr . tcp dport { 192.0.2.13 . 22, 192.0.2.14 . 443 } accept`.

### @@sec:lists@@ Liste noire, liste blanche

- **liste noire** : `ip saddr @liste_noire drop`, placée **avant** les règles qui acceptent (une
  règle `accept` rencontrée d'abord laisserait passer le paquet) ;
- **liste blanche** : `ip saddr @admins tcp dport 22 accept` : le service n'est ouvert qu'aux
  membres de l'ensemble ; les autres sources ne satisfont aucune règle et tombent dans la
  politique `drop`.

Placée après la règle à états, la règle d'une liste noire ne voit que les **nouvelles**
connexions : celles qu'une adresse avait ouvertes avant d'être listée continuent. Placée avant
elle, la règle les coupe aussitôt.
""")
            + info_subtitle(tr("Les ensembles alimentés par les règles"), tag="dynamic-sets")
            + tr("""
Avec `flags dynamic`, ce sont les **règles** qui remplissent l'ensemble, au passage des
paquets, d'une valeur tirée du paquet examiné :

- `add @nom { ip saddr }` range l'adresse source du paquet dans l'ensemble, si elle n'y est pas
  déjà ;
- `update @nom { ip saddr }` fait de même, et **remet à zéro le délai** de l'élément à chaque
  paquet (`add` ne le prolonge pas).

Un tel ensemble se déclare avec un `timeout` : sans lui, il ne ferait que grossir. Exemple :
bannir dix minutes toute machine qui tente une connexion telnet (port 23), qu'aucun utilisateur
légitime n'a de raison de viser.

```
nft 'add set inet filter bannis { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft insert rule inet filter input ip saddr @bannis drop
nft 'add rule inet filter input tcp dport 23 add @bannis { ip saddr } drop'
```

- la règle `ip saddr @bannis drop` est insérée **en tête**, avant la règle à états : un banni
  perd aussi ses connexions en cours ;
- pour qu'un banni ne revienne qu'après dix minutes de **silence**, on prolonge son
  bannissement à chaque paquet qu'il envoie, en écrivant la première règle
  `ip saddr @bannis update @bannis { ip saddr } drop` ;
- `nft list set inet filter bannis` affiche les bannis et le temps qui leur reste ;
  `nft flush set inet filter bannis` lève tous les bannissements, `nft 'delete element inet
  filter bannis { 203.0.113.9 }'` un seul.

Les éléments d'un ensemble alimenté par une règle peuvent aussi porter un **état propre** : une
limite de débit ou un compte de connexions par adresse (section @@ref:limit-per-source@@).
""")
            + info_subtitle(tr("Les dictionnaires (maps)"), tag="maps")
            + tr("""
Un **dictionnaire** (*map*) associe une **valeur** à chaque **clé**. Comme un ensemble, il est
consulté en une seule opération, quel que soit le nombre de ses entrées.

### @@sec:vmaps@@ Dictionnaires de verdicts

Un **dictionnaire de verdicts** (*verdict map*, `vmap`) associe à chaque clé un **verdict**
(`accept`, `drop`, `jump chaine`…) : une seule règle aiguille les paquets, au lieu d'une règle
par cas.

```
tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }
iifname vmap { "eth0" : jump zone_lan, "eth1" : jump zone_wan }
ct state vmap { established : accept, related : accept, invalid : drop }
ip saddr . tcp dport vmap { 192.0.2.13 . 22 : accept, 192.0.2.14 . 443 : accept }
```

Un paquet dont le champ n'est pas une clé du dictionnaire ne satisfait pas la règle : il passe
à la règle suivante. La troisième ligne écrit en une règle le début habituel d'une chaîne (la
règle à états et `ct state invalid drop`) ; la dernière prend pour clé une concaténation
(section @@ref:concatenations@@).

### @@sec:named-maps@@ Dictionnaires nommés

Comme un ensemble, un dictionnaire peut être **nommé** : c'est alors un objet de la table, dont
le contenu se modifie sans toucher aux règles. Son type donne celui de la clé, puis celui de la
valeur.

```
map services {
    type inet_service : verdict
    elements = { 22 : accept, 80 : accept }
}
```

La règle devient `tcp dport vmap @services`, et l'on ouvre ou ferme un port sans la modifier :

```
nft 'add map inet filter services { type inet_service : verdict; }'    # crée un dictionnaire vide
nft 'add element inet filter services { 443 : accept }'                # ajoute une entrée
nft list map inet filter services                                      # affiche son contenu
nft list maps                                                          # tous les dictionnaires
```

### @@sec:data-maps@@ Dictionnaires de valeurs

Les autres dictionnaires fournissent une **valeur** là où une action en attend une (une
adresse, un port). On les rencontre surtout dans la traduction d'adresses :

```
dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }      # le serveur dépend du port visé
```

Nommé, un tel dictionnaire se déclare `type inet_service : ipv4_addr` et la règle s'écrit
`dnat to tcp dport map @nom`.
""")
            + info_subtitle(tr("reject ou drop ?"), tag="reject-drop")
            + tr("""
### @@sec:reject-forms@@ Deux façons de refuser

- **`drop`** : le paquet est détruit **sans réponse**. L'émetteur retransmet, puis renonce à
  l'expiration de son délai d'attente (*timeout*) : le port paraît « filtré » ;
- **`reject`** : le paquet est détruit et l'émetteur **prévenu** aussitôt par un message
  d'erreur. Le client échoue **immédiatement** : le port paraît « fermé ».

```
tcp dport 8080 reject with tcp reset
tcp dport 9090 drop
```

`reject` n'est pas une politique possible pour une chaîne : pour refuser par défaut plutôt que
détruire, on termine la chaîne par une règle `reject`. La réponse se choisit :

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | un message ICMP *port unreachable* |
| `reject with tcp reset` | un segment TCP RST, exactement ce que répond une machine dont le port est fermé (TCP seulement) |
| `reject with icmp admin-prohibited` | le message ICMP choisi ; autres codes : `host-unreachable`, `net-unreachable`, `port-unreachable`… |
| `reject with icmpx admin-prohibited` | dans une table `inet` : l'erreur équivalente en ICMP ou en ICMPv6, selon le paquet |

`nft list ruleset` réaffiche un `reject` sans précision sous sa forme complète (`reject with
icmp port-unreachable`, ou `icmpx` dans une table `inet` quand la règle ne dit pas la version
d'IP).

### @@sec:client-view@@ Ce que voit le client

| le pare-feu… | le client (`curl -m 5`, `nc -vz -w 5`) |
|--------------|----------------------------------------|
| accepte, et un service écoute | la connexion s'ouvre |
| refuse (`reject`) | échoue **immédiatement** (`nc` : `Connection refused` ; `curl` : erreur 7) |
| détruit (`drop`) | attend, puis renonce au bout de son délai (`nc` : `timed out` ; `curl` : erreur 28, `Connection timed out`) |
| accepte, mais aucun service n'écoute | échoue **immédiatement**, de la même façon : la machine répond elle-même par un RST |

La différence se lit donc dans le **délai** : un refus immédiat pour `reject`, une longue
attente pour `drop`. Attention au dernier cas : vu du client, rien ne distingue un port accepté
mais sans service d'un `reject with tcp reset`. Pour savoir ce que fait une règle, il faut
qu'un service écoute sur le port (section @@ref:testing@@).

### @@sec:which@@ Lequel choisir ?

`drop` ne révèle rien, pas même l'existence de la machine, et ne coûte rien : c'est le choix
face à l'extérieur, et celui de la politique par défaut. `reject` évite aux utilisateurs
légitimes d'attendre et facilite le diagnostic : on l'emploie volontiers à l'intérieur.
""")
            + info_subtitle(tr("Limiter le débit"), tag="limit")
            + tr("""
### @@sec:token-bucket@@ limit rate : le seau à jetons

`limit rate` se comporte comme un **critère** : il est satisfait tant que le rythme des paquets
qui atteignent la règle reste **sous** la limite. Au-delà, la règle ne s'applique plus et le
paquet **continue vers la règle suivante** (puis la politique).

```
tcp dport 22 ct state new limit rate 3/minute accept     # les nouvelles connexions SSH : 3 par minute
ip protocol icmp limit rate 1/second accept              # les pings : 1 par seconde
limit rate 5/minute log prefix "refus: "                 # le journal : 5 lignes par minute
```

C'est un **seau à jetons** : chaque paquet qui passe consomme un jeton ; le seau se remplit au
rythme indiqué et contient au plus la **réserve** (*burst*, 5 paquets par défaut). `limit rate
1/second` laisse donc passer 5 paquets d'un coup, puis un par seconde ; `limit rate 3/minute`,
5 d'un coup, puis un toutes les 20 secondes.

| règle | effet |
|-------|-------|
| `limit rate 10/second burst 20 packets accept` | fixe la réserve : 20 paquets d'un coup au plus, puis 10 par seconde |
| `limit rate over 10/second drop` | `over` inverse le test : la règle vaut pour les paquets **en trop** |
| `limit rate 1 mbytes/second accept` | un débit en octets (`bytes`, `kbytes`, `mbytes`) |

Les unités de temps sont `second`, `minute`, `hour` et `day`. Un piège classique : `limit rate
1/second drop` ne détruit qu'**un paquet par seconde** et laisse continuer tout le surplus ;
pour détruire ce qui dépasse, il faut `over`.

### @@sec:limit-place@@ La place de la règle

- combinée à `ct state new`, la limite porte sur les **ouvertures de connexion** (contre les
  attaques par force brute), sans gêner les connexions établies, acceptées plus haut par la
  règle à états ;
- placée **après** la règle à états, une limite ne voit de toute façon que le **premier paquet**
  de chaque connexion : les échos suivants d'un même `ping` (une seule « connexion » pour le
  suivi) sont acceptés avant elle. Elle limite donc le rythme des nouvelles connexions, pas le
  débit ;
- pour limiter **tous** les paquets d'un trafic, on place `limit rate over … drop` **avant** la
  règle à états.

### @@sec:limit-per-source@@ Une limite par adresse

Une limite écrite dans une règle est **globale**, toutes sources confondues : une seule machine
bruyante consomme les jetons de tout le monde. Pour compter **par adresse source**, on attache
la limite aux éléments d'un ensemble alimenté par la règle (section @@ref:dynamic-sets@@) :
chaque adresse y reçoit son propre seau.

```
table inet filter {
    set clients {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1m
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop
        tcp dport 22 accept
    }
}
```

La règle `update` détruit les ouvertures de connexion d'une adresse qui dépasse son rythme ; les
autres continuent vers la règle suivante, qui les accepte.

### @@sec:quotas@@ Connexions simultanées et quotas

**`ct count`** compte les connexions **simultanées**, et non un rythme : `tcp dport 22 ct count
10 accept` accepte tant qu'il n'y en a pas plus de 10, `ct count over 10` vaut au-delà. Par
adresse source, avec un ensemble déclaré `flags dynamic` :
`tcp dport 22 add @sessions { ip saddr ct count over 2 } reject` refuse la troisième connexion
ouverte en même temps par une même adresse.

Un **quota** compte un **volume** : `udp dport 5060 quota until 100 mbytes accept` accepte
jusqu'à 100 Mo, puis ne s'applique plus. Comme un compteur (section @@ref:counters@@), un quota
peut être un objet nommé de la table, que l'on relit et remet à zéro :

```
nft 'add quota inet filter invites { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "invites" drop'
nft list quota inet filter invites
```

Avec `over`, la règle ne vaut qu'une fois le volume dépassé : ici, l'adresse est coupée après
20 Mo.
""")
            + info_subtitle(tr("Compter et journaliser"), tag="counters-log")
            + tr("""
### @@sec:counters@@ Les compteurs

**`counter`** compte les paquets et les octets qui atteignent cet endroit de la règle ;
`nft list ruleset` l'affiche sous la forme `counter packets 12 bytes 1008`. C'est l'outil de
diagnostic de base : il dit si une règle sert, et laquelle a vu passer un paquet. Ce n'est pas
un verdict : `tcp dport 80 counter accept` compte puis accepte ; une règle `counter` sans
verdict compte et laisse continuer.

Les compteurs des règles se remettent à zéro avec `nft reset rules` (tout le jeu de règles),
`nft reset rules inet filter` (une table) ou `nft reset rules inet filter input` (une chaîne) :
la commande affiche les règles avec leurs compteurs, puis les remet à zéro ; ils repartent
aussi de zéro quand on remplace la règle ou que l'on recharge le fichier. On peut aussi
déclarer un **compteur nommé**, objet de la table que plusieurs règles alimentent et que l'on
relit ou remet à zéro séparément :

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 443 } counter name "web" accept'
nft list counters                 # les compteurs nommés
nft reset counters                # les affiche, puis les remet à zéro
```

### @@sec:log@@ La journalisation

**`log`** produit une ligne par paquet (interfaces, adresses, protocole, ports). Il existe sous
deux formes :

- `log prefix "liste noire: "` écrit dans le **journal du noyau**, que l'on lit sur une vraie
  machine avec `dmesg -w`, `journalctl -k -f` ou dans `/var/log/kern.log` ; `level` choisit la
  gravité du message (`log level info prefix "…"`). **Dans un conteneur, cette forme ne donne
  rien** : par défaut le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "liste noire: " group 0` remet les paquets à **nflog** (ici au groupe 0), où un
  programme vient les lire : **`tcpdump -n -i nflog:0`**, ou le démon `ulogd`, qui les range
  dans un fichier. C'est la forme à utiliser dans ce TP : elle montre les paquets journalisés
  en direct, sur `srv` elle-même.

`log` n'est pas un verdict non plus : `ip saddr @liste_noire log prefix "liste noire: " group 0
drop` journalise **puis** détruit. Sans limite, une attaque ou une simple boucle de `ping`
remplit le journal : on place `limit rate 5/minute` **devant** `log`. Attention : un paquet
sans jeton quitte la règle, il n'en atteint donc pas non plus le verdict. On journalise dans
une règle et l'on détruit dans la suivante :

```
ip saddr @liste_noire limit rate 5/minute log prefix "liste noire: " group 0
ip saddr @liste_noire drop
```

Dans un shell, une règle qui contient des guillemets doit être protégée tout entière par des
apostrophes, sinon le shell les retire et `nft` ne comprend plus le préfixe :
`nft 'add rule inet filter input ip saddr @liste_noire log prefix "liste noire: " group 0 drop'`.
""")
            + info_subtitle(tr("Autres outils"), tag="more")
            + tr("""
### @@sec:trace@@ Suivre un paquet : la trace

Quand les compteurs ne suffisent pas, on **trace** un paquet règle par règle : une règle
`meta nftrace set 1`, placée en tête de chaîne, marque les paquets à suivre, et `nft monitor
trace` affiche leur parcours.

```
nft insert rule inet filter input ip saddr 192.0.2.13 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.13 … tcp dport 80 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.13 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 80 accept (verdict accept)
```

Chaque ligne commence par l'identifiant du paquet, la table et la chaîne ; les lignes `rule`
donnent les règles satisfaites et leur verdict, et un paquet qu'aucune règle n'arrête se
termine par la politique de la chaîne (`policy drop`). Supprimez la règle de trace quand vous
avez fini.

### @@sec:monitor@@ Surveiller et vérifier

| commande | usage |
|----------|-------|
| `nft monitor` | affiche en direct les modifications du jeu de règles : règles ajoutées, éléments qui entrent dans un ensemble ou en sortent |
| `nft -c -f fichier` | vérifie un fichier sans rien changer |
| `nft -c -o -f fichier` | propose des simplifications du jeu de règles, sans rien changer |
| `nft describe tcp dport` | donne le type d'un champ (à reprendre dans la déclaration d'un ensemble) et ses valeurs possibles |
| `nft -s list ruleset` | affiche le jeu de règles sans les valeurs des compteurs |
| `nft -j list ruleset` | l'affiche en JSON, pour un programme |

### @@sec:misc-tools@@ meta, fib, flowtables

- **`meta`** donne accès à ce qui entoure le paquet : `meta l4proto` (le protocole de transport,
  en IPv4 comme en IPv6), `meta iifname` / `meta oifname`, `meta mark` (une marque posée par une
  autre règle, `meta mark set 1`, pour le routage avancé ou la qualité de service), `meta skuid`
  (l'utilisateur du processus local qui émet, au hook `output`) ;
- **`fib`** interroge la table de routage : `fib saddr . iif oif missing drop`, au hook
  `prerouting`, détruit les paquets dont l'adresse source n'est pas joignable par l'interface
  d'arrivée (anti-usurpation, *reverse path filtering*) ;
- une **flowtable** accélère le routage des connexions établies, qui ne repassent plus par les
  chaînes : pour un routeur à très haut débit.
""")
            + info_subtitle(tr("Observer et tester"), tag="testing")
            + tr("""
Un pare-feu se vérifie des deux côtés : ce qu'il **laisse passer** (ce qui doit marcher marche
encore) et ce qu'il **arrête** (ce qui doit être bloqué l'est vraiment).

### @@sec:test-ruleset@@ Ce que dit le jeu de règles

`nft list ruleset` (avec les compteurs), `nft -a list ruleset` (avec les *handles*),
`nft list set inet filter NOM` (le contenu d'un ensemble). Après chaque ajout, vérifiez
l'**ordre** des règles : c'est la première cause d'erreur.

### @@sec:test-client@@ Ce que voit un client

- `curl -m 3 http://ADRESSE:PORT/` pour un service HTTP, ou une simple connexion TCP avec
  `nc -vz -w 3 ADRESSE PORT`. Un succès : la règle accepte et un service écoute ; un échec
  **immédiat** (`Connection refused`) : un `reject`, ou un port accepté mais sans service ; une
  **attente** jusqu'au délai (`-m 3`, `-w 3`) : un `drop` ;
- **un service à l'écoute** : `ss -tlnp` liste les ports TCP en écoute. Pour tester une règle
  sur un port où rien n'écoute, lancez un service provisoire, par exemple
  `python3 -m http.server 8080` ;
- **plusieurs sources** : une liste noire ou une liste blanche ne se vérifie qu'en comparant
  ce que voient une machine listée et une machine qui ne l'est pas.

### @@sec:test-limit@@ Vérifier une limite

Avec la règle à états en tête, un `ping -c 10 -i 0.2 ADRESSE` ne montre rien : ses dix échos
forment une seule « connexion » pour le suivi, et seul le premier rencontre la limite
(section @@ref:limit-place@@). Il faut des essais **distincts** :

```
for i in $(seq 12); do ping -c 1 -W 1 ADRESSE >/dev/null && echo ok || echo perdu; done
```

Avec `limit rate 1/second`, les cinq premiers passent (la réserve du seau), puis un sur deux
environ. De même, plusieurs `nc -z -w 2 ADRESSE 22` rapprochés montrent la limite posée sur les
nouvelles connexions SSH.

### @@sec:test-capture@@ Sur le fil

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu : en réception, il voit
les paquets **avant** tous les hooks (un paquet que le pare-feu détruit en `input` apparaît
quand même dans la capture) ; en émission, il les voit **après** tous les hooks.

- `tcpdump -n -i eth0 'tcp port 8080 or icmp'` sur le client montre le RST ou le message ICMP
  d'un `reject`, ou les SYN retransmis sans réponse d'un `drop` ;
- `tcpdump -n -i nflog:0` sur le pare-feu montre les paquets journalisés par `log … group 0`.

### @@sec:test-which-rule@@ Savoir quelle règle a tranché

Ajoutez `counter` aux règles et relisez `nft list ruleset` après un essai : la règle dont le
compteur a bougé est celle qui a vu le paquet. Si aucun compteur ne bouge, le paquet n'arrive
pas jusqu'à la chaîne, ou c'est la politique qui l'a détruit. La trace
(section @@ref:trace@@) donne le détail, règle par règle.
""")
            + info_subtitle(tr("Bonnes pratiques et pièges"), tag="practices")
            + tr("""
### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input`, la règle à états en
  premier, `lo`, puis une règle par service réellement offert ;
- **des ensembles plutôt que des listes de règles** : une règle et un ensemble nommé se lisent
  mieux, vont plus vite, et l'on change la liste sans toucher aux règles ;
- **restreindre par la source** ce qui n'a pas à être public (une liste blanche pour
  l'administration) ;
- **limiter** ce qui peut être abusé (ouvertures de connexion, `ping`, journal), par adresse
  quand un seul client ne doit pas pénaliser les autres ;
- **journaliser ce qui est détruit**, avec une limite, et compter ce qui est accepté : un
  pare-feu que l'on n'observe pas ne se corrige pas ;
- **un fichier, chargé d'un bloc** et vérifié d'abord avec `nft -c -f`, plutôt que des
  commandes tapées une à une.

### @@sec:pitfalls@@ Les pièges

- **l'ordre des règles** : la règle d'une liste noire placée après un `accept` qui couvre les
  mêmes paquets n'est jamais consultée ; une règle `reject` placée après un `drop` plus général
  non plus ;
- **une liste blanche sans règle qui accepte** : `ip saddr != @admins tcp dport 22 drop` seul
  ne laisse entrer personne sous une politique `drop` ;
- **un ensemble anonyme n'est pas un ensemble nommé** : `ip saddr { 192.0.2.13 } drop` bloque
  l'adresse, mais on ne peut plus changer la liste sans remplacer la règle ;
- **`limit` sans `over` devant `drop`** : `limit rate 1/second drop` ne détruit qu'un paquet par
  seconde ;
- **`limit` et `log` devant un verdict** : un paquet sans jeton n'atteint ni le `log` ni le
  verdict de la règle (section @@ref:log@@) ;
- **une action après le verdict** (`accept counter`) : `nft` la refuse, le verdict termine la
  règle ;
- **un port accepté sans service** répond par un RST, comme un `reject with tcp reset` : ne
  concluez rien d'un refus immédiat sans avoir vérifié qu'un service écoute (`ss -tlnp`) ;
- **le shell** : guillemets, accolades et points-virgules se protègent par des apostrophes ;
- **les règles volatiles** : ce qui n'est pas dans `/etc/nftables.conf` disparaît au
  redémarrage, le contenu des ensembles modifié à la main aussi.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""
| besoin | commande ou règle |
|--------|-------------------|
| état | `nft list ruleset`, `nft -a list ruleset` (avec les *handles*), `nft list set inet filter NOM` |
| socle | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'`, `ct state established,related accept`, `iif lo accept` |
| ensemble nommé | `nft 'add set inet filter NOM { type ipv4_addr; }'`, `nft 'add element inet filter NOM { 192.0.2.13 }'`, `nft 'delete element inet filter NOM { 192.0.2.13 }'`, `nft flush set inet filter NOM` |
| utiliser un ensemble | `ip saddr @NOM drop` (liste noire), `ip saddr @NOM tcp dport 22 accept` (liste blanche) |
| options d'un ensemble | `flags interval` (réseaux, plages), `flags timeout` et `timeout 1h` (expiration), `flags dynamic` (alimenté par les règles : `add @NOM { ip saddr }`) |
| dictionnaire de verdicts | `tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }`, `tcp dport vmap @NOM` |
| refuser | `tcp dport 8080 reject with tcp reset`, `reject` (ICMP *port unreachable*), `drop` |
| limiter | `limit rate 3/minute`, `limit rate 10/second burst 20 packets`, `limit rate over 10/second drop`, `ct count over 10` |
| compter, journaliser | `counter`, `log prefix "texte: "`, `log prefix "texte: " group 0` puis `tcpdump -n -i nflog:0` |
| ordre des règles | `nft insert rule inet filter input …` (en tête), `nft insert rule inet filter input handle N …` (avant la règle N), `nft delete rule inet filter input handle N` |
| fichier de règles | `nft -c -f /etc/nftables.conf` (vérifier), `nft -f /etc/nftables.conf` (charger ; le fichier commence par `flush ruleset`) |
| tests | `curl -m 3 http://ADRESSE:PORT/`, `nc -vz -w 3 ADRESSE PORT`, `ping -c 1 -W 1 ADRESSE`, `ss -tlnp`, `tcpdump -n -i eth0 'tcp port 8080 or icmp'` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""")
        )

    # -- the rules of the reference solution (used by `final` and the instructor texts) ------

    def set_blacklist(self) -> List[str]:
        """Question 1: the named set of the banned addresses (bad)."""
        return render_set("liste_noire", self.data.ips.bad.ip)

    def set_admins(self) -> List[str]:
        """Question 2: the named set of the addresses allowed to use SSH (admin)."""
        return render_set("admins", self.data.ips.admin.ip)

    def rules_base(self) -> List[str]:
        """The stateful base of the input chain (whose policy is drop)."""
        return ["ct state established,related accept", "ct state invalid drop", 'iif "lo" accept']

    def rule_blacklist(self) -> str:
        """Question 1 (and the log of question 4): what comes from the blacklist is dropped."""
        return 'ip saddr @liste_noire log prefix "blacklist: " group 0 drop'

    def rule_icmp(self) -> str:
        """Question 4: rate-limited ICMP."""
        return "ip protocol icmp limit rate 1/second accept"

    def rule_ssh(self) -> str:
        """Question 2 (and the limit / counter of question 4): SSH for the members of `admins`."""
        return f"ip saddr @admins tcp dport {SSH_PORT} ct state new limit rate 3/minute counter accept"

    def rule_http(self) -> str:
        """Question 1: HTTP stays open to everybody else."""
        return f"tcp dport {HTTP_PORT} counter accept"

    def rule_reject(self) -> str:
        """Question 3: the rejected port."""
        return f"tcp dport {REJECT_PORT} reject with tcp reset"

    def rule_drop(self) -> str:
        """Question 3: the dropped port."""
        return f"tcp dport {DROP_PORT} drop"

    def reference_conf(self) -> str:
        """The ``/etc/nftables.conf`` of the reference solution (the four questions)."""
        return "#!/usr/sbin/nft -f\nflush ruleset\n" + render_table(
            [self.set_blacklist(), self.set_admins()],
            self.rules_base() + [self.rule_blacklist(), self.rule_icmp(), self.rule_ssh(), self.rule_http(),
                                 self.rule_reject(), self.rule_drop()],
            other_chains=True)

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        firewall.flush_ruleset(self, "srv")
        firewall.flush_ruleset(self, "srv_h")

        # A controlled service on each port of the lab, on srv (the students' hand checks) and on
        # its hidden clone (the probes of the evaluation): the outcome of a connection then tells
        # what the firewall decided, not that nothing was listening.  HTTP is a real HTTP server
        # (curl prints SERVER=srv and the client address), the other ports send one line and close.
        for machine in ("srv", "srv_h"):
            firewall.setup_http_server(self, machine, HTTP_PORT, "srv")
            firewall.setup_banner_server(self, machine, SSH_PORT, "ssh\n")
            firewall.setup_banner_server(self, machine, REJECT_PORT, "rej\n")
            firewall.setup_banner_server(self, machine, DROP_PORT, "drp\n")

    @sre_state(user_allowed=False)
    def final(self):
        """Solution de référence : note maximale."""
        self.file("srv", "/etc/nftables.conf", self.reference_conf(), permissions=0o644)
        self.cmd("srv", "nft -f /etc/nftables.conf")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()

        for m in ("srv", "srv_h", "admin_h", "user_h", "bad_h"):
            for cmd in ("nft list ruleset", "ip -4 addr"):
                self.test(m, cmd, allow_error=True)

        rs = firewall.get_ruleset(self, "srv")
        firewall.transplant_ruleset(self, src="srv", dst="srv_h")

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| machine | adresse | rôle |
|---------|---------|------|
| **`srv`** | `{srv}` | le serveur à protéger : **le pare-feu à configurer** |
| `admin` | `{admin}` | le poste de l'administrateur, seule source autorisée en SSH |
| `user` | `{user}` | un utilisateur ordinaire : accède au HTTP, pas au SSH |
| `bad` | `{bad}` | une machine indésirable, à mettre en liste noire |

Toutes les machines sont sur le même réseau local `net1` (`{net1}`).
""").format(srv=d.ips.srv.ip, admin=d.ips.admin.ip, user=d.ips.user.ip, bad=d.ips.bad.ip, net1=d.nets.net1)

        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="b9e0a39f370bf65b",
            description=tr("""
Lisez l'onglet **Informations** : il rappelle le socle d'un pare-feu de machine (politique `drop`,
filtrage à états) et présente les ensembles nommés, les *maps*, `reject` et `drop`, la limitation
de débit, les compteurs, la journalisation et la façon de tester un jeu de règles.

**La maquette** (onglet *Schéma*) : un seul réseau local, `net1`, avec le serveur **`srv`** et
trois machines qui sont les trois sources de vos tests : **`admin`**, **`user`** et **`bad`**.
Vous configurez le pare-feu de **`srv`**, et de `srv` seulement, dans sa chaîne `input`.
""")
            + addressing
            + tr("""
**Les ports du TP**, tous en TCP sur `srv` : **{ssh}** (SSH, réservé à `admin`), **{http}** (HTTP,
ouvert à tous sauf à la liste noire), **{rej}** (à **rejeter**) et **{drp}** (à **détruire**).

**Déjà en place** (ne pas modifier) : les adresses. Le jeu de règles nftables de `srv` est vide au
départ : tout passe. Sur `srv`, un service écoute sur chacun des ports du TP : un serveur HTTP sur
le port {http} (`curl` affiche `SERVER=srv` et `CLIENT_IP=`, l'adresse du client) et, sur les ports
{ssh}, {rej} et {drp}, un petit service TCP qui envoie une ligne puis ferme la connexion (à tester
avec `nc`). Dans vos commandes, désignez les machines par leurs adresses (tableau ci-dessus).

**Le socle.** Tout le TP se fait sur `srv`, dans une chaîne `input` de politique `drop`, avec un
filtrage à états : commencez par là (section @@ref:base@@ des Informations), puis ajoutez les
règles des questions.

**Plan du TP** :

1. **liste noire** : un ensemble nommé `liste_noire` dont les membres (`bad`) voient tout leur
   trafic détruit, le HTTP restant ouvert aux autres machines ;
2. **liste blanche SSH** : un ensemble nommé `admins` dont les membres (`admin`) ont seuls accès au
   SSH ;
3. **`reject` ou `drop`** : le port {rej} rejeté, le port {drp} détruit ;
4. **limitation de débit, compteurs et journalisation**.

Règles valables pour tout le TP :

- la configuration d'une question terminée reste en place : l'évaluation vérifie le jeu de règles
  **final** de `srv`, avec les quatre questions à la fois ;
- l'**ordre des règles** compte (une règle qui accepte, placée avant celle de la liste noire,
  laisse passer `bad`) : relisez `nft list ruleset` après chaque ajout ;
- l'évaluation lit le jeu de règles **chargé** sur `srv` (`nft list ruleset`), pas un fichier :
  des règles tapées avec `nft` suffisent (elles sont volatiles), mais un fichier rechargé d'un bloc
  est plus sûr (méthode conseillée plus bas) ;
- ce jeu de règles est **recopié sur une machine cachée identique** à `srv` (même adresse), où des
  services écoutent sur les ports {ssh}, {http}, {rej} et {drp}, et que l'évaluation sonde par des
  connexions TCP depuis des copies cachées de `admin`, `user` et `bad` : `bad` ne doit pas
  atteindre le port {http} et `user` doit l'atteindre ; `admin` doit atteindre le port {ssh} et
  `user` non ; depuis `user`, le port {rej} doit être refusé immédiatement et le port {drp} rester
  sans réponse. Elle cherche aussi dans le jeu de règles un ensemble nommé, une limitation de
  débit (`limit`) et un compteur ou une journalisation (`counter`, `log`). Rien n'est acquis sans
  règle : une connexion qui doit aboutir ne compte que si la chaîne `input` a la politique `drop`,
  et une connexion qui doit échouer ne compte que si son témoin aboutit (`bad` bloqué alors que
  `user` atteint le port {http}, `user` sans SSH alors que `admin` l'a, port {drp} détruit alors
  que le port {http} reste ouvert à `user`). Seul compte ce que dit **le jeu de règles chargé sur
  `srv`**, pas l'état de ses services ni ce que vous faites sur les autres machines ;
- pour tester sans attendre, donnez un délai court à vos commandes : `curl -m 3 http://ADRESSE:PORT/`,
  `nc -vz -w 3 ADRESSE PORT` (section @@ref:testing@@ des Informations).
""").format(ssh=SSH_PORT, http=HTTP_PORT, rej=REJECT_PORT, drp=DROP_PORT)
            + tr("""
**Méthode conseillée : le pare-feu dans un fichier.** Plutôt que de taper les règles une à une,
écrivez le pare-feu de `srv` dans **`/etc/nftables.conf`**, complétez-le de question en question et
rechargez-le d'un bloc : plus de guillemets pour le shell, ni de handle à chercher pour placer une
règle (on l'écrit à sa place), et des commentaires (`#`) pour s'y retrouver. Le fichier existe
déjà : le paquet Debian y a mis un squelette, une table `inet filter` aux chaînes vides `input`,
`forward` et `output`. Remplacez-le par le socle de la section @@ref:nft-files@@ des Informations
(`flush ruleset` en tête, puis la table `inet filter` et sa chaîne `input`), puis ajoutez-y les
ensembles et les règles des questions. Après chaque modification (`nano /etc/nftables.conf`, ou
`vim`) :

```
nft -c -f /etc/nftables.conf      # vérifie sans rien changer ; aucun message : correct
nft -f /etc/nftables.conf         # remplace tout le jeu de règles par celui du fichier
nft -a list ruleset               # ce qui est réellement chargé (avec les handles)
```

- chaque erreur est signalée par le nom du fichier, les numéros de ligne et de colonne, et des
  `^^^` sous le mot fautif. Le chargement est atomique : en cas d'erreur, **rien** ne change et
  l'ancien jeu de règles reste en place ;
- **l'évaluation ne lit pas le fichier**, seulement le jeu de règles chargé sur `srv` : un fichier
  modifié mais pas rechargé ne compte pas, et aucun service ne le charge dans les machines du TP ;
- `flush ruleset` en tête : recharger le fichier remplace tout, sans doublon (aucune autre table
  n'est à garder sur `srv`). Cela remet aussi à zéro les compteurs (question 4) ;
- ce que vous changez en ligne de commande (`nft add element`, `nft insert rule`…) n'est pas dans
  le fichier : reportez-y **toute** modification, le prochain `nft -f` efface ce qu'il ne contient
  pas ;
- déjà commencé à la main ? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  transforme le jeu de règles en place en fichier.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution : il écrit
le fichier ci-dessous dans `/etc/nftables.conf` sur `srv` et le charge (`nft -f /etc/nftables.conf`) ;
il est ré-applicable. Ce TP n'a aucun formulaire à remplir.

```
{conf}```

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` et
`nft -j list ruleset` sur `srv` (étape 1) ; le premier est chargé tel quel sur `srv_h` après un
`nft flush ruleset` (étape 2 ; un jeu de règles vide laisse la copie sans filtre), le second donne
la politique de la chaîne `input` ; puis six connexions TCP par `bash` (`/dev/tcp`, délai 4 s :
`RC=0` ouvert, `RC=124` détruit, autre code refusé) à l'étape 3 : `bad_h` et `user_h` vers le port
{http}, `admin_h` et `user_h` vers le port {ssh}, `user_h` vers les ports {rej} et {drp}. Sur `srv_h`
comme sur `srv`, un service écoute sur chacun des quatre ports (un serveur HTTP sur le port {http},
un petit serveur TCP sur les autres ; ceux de `srv` servent aux vérifications à la main et ne sont
pas évalués).

Barème : 14 points, dont 3 pour la seule présence de mots dans le jeu de règles (`set ` ou `@`,
`limit`, `counter` ou `log`). Aucun point sans règle : les connexions qui doivent aboutir
(`blacklist_user_ok`, `whitelist_admin_ssh`) ne comptent qu'avec la politique `drop` sur la chaîne
`input`, celles qui doivent échouer (`blacklist_bad_bloque`, `whitelist_user_ssh_bloque`,
`port_drop`) que si leur témoin aboutit. Un jeu de règles vide vaut 0, une politique `drop` seule
aussi.
""").format(conf=self.net_scheme.reference_conf(), ssh=SSH_PORT, http=HTTP_PORT, rej=REJECT_PORT,
            drp=DROP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Liste noire (ensemble nommé)"),
            hash="413ca79d34b9b10e",
            description=tr("""
Créez un **ensemble nommé** `liste_noire` (`type ipv4_addr`) contenant l'adresse
de **`bad`** ({_arg0}) et **détruisez** tout trafic provenant de ses membres. Les
autres machines gardent un accès HTTP (port {_arg1}) normal à `srv`.
""").format(_arg0=d.ips.bad.ip, _arg1=HTTP_PORT)
            + instructor(tr("""
**Solution.** Sur `srv`, dans `/etc/nftables.conf` : le socle (politique `drop`, règle à états,
`lo`), l'ensemble nommé et sa règle, placée **avant** toute règle qui accepte, puis l'ouverture du
HTTP :

```
{conf}```

à charger par `nft -f /etc/nftables.conf`. Le `log` de la règle est celui de la question 4 :
`ip saddr @liste_noire drop` suffit ici. À chaud, en ligne de commande, une fois le socle en
place : `nft 'add set inet filter liste_noire {{ type ipv4_addr; }}'`,
`nft 'add element inet filter liste_noire {{ {bad} }}'`,
`nft add rule inet filter input ip saddr @liste_noire drop` puis
`nft add rule inet filter input tcp dport {http} accept`.

Vérification : depuis `bad`, `curl -m 3 http://{srv}/` attend 3 secondes sans réponse, et
`ping {srv}` n'obtient rien ; depuis `user` et `admin`, le même `curl` affiche `SERVER=srv` et
l'adresse du client. `nft list set inet filter liste_noire` affiche
l'ensemble ; `nft 'add element inet filter liste_noire {{ {user} }}'` bloque aussitôt `user`, sans
recharger les règles, et `nft 'delete element inet filter liste_noire {{ {user} }}'` le débloque.

Pièges : la règle de la liste noire placée **après** `tcp dport {http} accept` (jamais atteinte par
le HTTP de `bad`) ; un ensemble anonyme (`ip saddr {{ {bad} }} drop`), qui bloque `bad` mais n'est
pas un ensemble nommé ; placée après `ct state established,related accept`, la règle laisse vivre
une connexion que `bad` aurait ouverte avant d'être listée (sans effet sur l'évaluation, qui
n'ouvre que des connexions nouvelles).

Évaluation : `blacklist_bad_bloque` (2 points : depuis la copie cachée de `bad`, une connexion TCP
vers `{srv}:{http}` doit échouer **et** celle de la copie de `user` aboutir), `blacklist_user_ok`
(1 point : depuis la copie de `user`, elle doit aboutir, la chaîne `input` de `srv` ayant la
politique `drop`) et `ensembles_nommes` (1 point : le texte de `nft list ruleset` de `srv` contient
`set ` ou `@`).
""").format(conf=render_table([self.net_scheme.set_blacklist()],
                              self.net_scheme.rules_base() + [self.net_scheme.rule_blacklist(),
                                                              self.net_scheme.rule_http()]),
            bad=d.ips.bad.ip, user=d.ips.user.ip, srv=d.ips.srv.ip, http=HTTP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Liste blanche SSH (ensemble nommé)"),
            hash="298a27408cad4aba",
            description=tr("""
Créez un ensemble nommé `admins` contenant l'adresse de **`admin`** ({_arg0}) et
n'autorisez le **SSH** (port {_arg1}) que depuis les membres de cet ensemble. Le
SSH depuis `user` doit être refusé.
""").format(_arg0=d.ips.admin.ip, _arg1=SSH_PORT)
            + instructor(tr("""
**Solution.** L'ensemble `admins` et la règle qui n'ouvre le SSH qu'à ses membres (`…` : les
autres règles ; le fichier complet est dans *Organisation du TP*) :

```
{conf}```

`limit rate 3/minute` et `counter` sont ceux de la question 4 :
`ip saddr @admins tcp dport {ssh} accept` suffit ici. Aucune règle pour les autres sources : leur
SSH tombe dans la politique `drop`. En ligne de commande :
`nft 'add set inet filter admins {{ type ipv4_addr; }}'`,
`nft 'add element inet filter admins {{ {admin} }}'` puis
`nft add rule inet filter input ip saddr @admins tcp dport {ssh} accept`.

Vérification : `nc -vz -w 3 {srv} {ssh}` réussit depuis `admin` et attend 3 secondes sans réponse
depuis `user` ;
`nft 'add element inet filter admins {{ {user} }}'` ouvre le SSH à `user` sans toucher aux règles.
Avec la limite de la règle de référence, au-delà de cinq connexions rapprochées (la réserve par
défaut), les suivantes depuis `admin` restent elles aussi sans réponse : une nouvelle connexion
toutes les 20 secondes.

Pièges : `tcp dport {ssh} accept` sans `ip saddr @admins` (ouvert à tous) ;
`ip saddr != @admins tcp dport {ssh} drop` seul, sans règle qui accepte (le SSH de `admin` tombe
alors dans la politique) ; la règle placée après un `tcp dport {ssh} drop`.

Évaluation : `whitelist_admin_ssh` (2 points : depuis la copie cachée de `admin`, une connexion TCP
vers `{srv}:{ssh}` doit aboutir, la chaîne `input` de `srv` ayant la politique `drop`) et
`whitelist_user_ssh_bloque` (2 points : depuis la copie de `user`, elle doit échouer, par `drop`
comme par `reject`, **et** celle de la copie de `admin` aboutir).
""").format(conf=render_table([self.net_scheme.set_admins()], ["…", self.net_scheme.rule_ssh(), "…"]),
            admin=d.ips.admin.ip, user=d.ips.user.ip, srv=d.ips.srv.ip, ssh=SSH_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("reject vs drop"),
            hash="c3f5e4a10b0e4446",
            description=tr("""
Faites en sorte que :

- le port **{_arg0}** soit **rejeté** (`reject`) — le client reçoit un refus immédiat ;
- le port **{_arg1}** soit **détruit** (`drop`) — le client n'obtient aucune réponse
  (délai d'attente).
""").format(_arg0=REJECT_PORT, _arg1=DROP_PORT)
            + instructor(tr("""
**Solution.** Deux règles de la chaîne `input` de `srv` (`…` : les autres règles) :

```
{conf}```

`reject with tcp reset` répond au SYN par un RST, comme le ferait un port fermé ; un simple
`reject` (message ICMP *port unreachable*) convient aussi : dans les deux cas le client échoue
immédiatement. La règle `drop` est explicite : sans elle, le port {drp} serait détruit de la même
façon par la politique. En ligne de commande :
`nft add rule inet filter input tcp dport {rej} reject with tcp reset` et
`nft add rule inet filter input tcp dport {drp} drop`.

Vérification : depuis `user`, `curl -m 5 http://{srv}:{rej}/` échoue **aussitôt**
(`Connection refused`) et `curl -m 5 http://{srv}:{drp}/` attend les 5 secondes. Sur `user`,
`tcpdump -n -i eth0 'tcp port {rej} or tcp port {drp}'` montre le RST (`Flags [R.]`) qui répond au
SYN vers le port {rej}, et le SYN vers le port {drp} retransmis sans réponse. Sans aucune règle,
les deux ports répondent : un service écoute sur chacun.

Pièges : les deux règles placées après un `accept` qui couvre ces ports ; la règle `reject` placée
après un `drop` plus général.

Évaluation : `port_reject` (2 points : depuis la copie cachée de `user`, la connexion TCP vers
`{srv}:{rej}` doit être refusée immédiatement) et `port_drop` (2 points : vers `{srv}:{drp}`, elle
doit rester sans réponse pendant 4 s **et** le port {http} rester ouvert à la copie de `user` : une
politique `drop` sans aucune règle ne rapporte rien). Les deux ports sont servis sur la copie : sans
règle, ils seraient ouverts.
""").format(conf=render_table([], ["…", self.net_scheme.rule_reject(), self.net_scheme.rule_drop()]),
            srv=d.ips.srv.ip, rej=REJECT_PORT, drp=DROP_PORT, http=HTTP_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Limitation de débit, compteurs et journalisation"),
            hash="0ec11492f80f849c",
            description=tr("""
Ajoutez :

- une **limitation de débit** (`limit rate`) — par exemple sur les nouvelles
  connexions SSH ou sur l'ICMP ;
- au moins un **compteur** (`counter`) et une règle de **journalisation** (`log`).
""")
            + instructor(tr("""
**Solution.** Dans le jeu de règles de référence, ces fonctions sont portées par les règles des
questions 1 et 2 et par une règle pour l'ICMP (`…` : les autres règles) :

```
{conf}```

- **limitation de débit** : `limit rate 1/second` sur l'ICMP (au-delà, les paquets tombent dans la
  politique `drop`) et `limit rate 3/minute` sur les **nouvelles** connexions SSH des membres de
  `admins` (`ct state new` ; les connexions établies passent par la règle à états) ;
- **compteurs** : `counter` sur les règles du SSH et du HTTP ;
- **journalisation** : `log prefix "blacklist: " group 0` sur la règle de la liste noire.

Vérification : un même `ping` est un seul flux pour le suivi de connexion et seul son premier écho
rencontre la limite (les suivants sont acceptés par la règle à états) : `ping -c 10 -i 0.2 {srv}`
reçoit ses dix réponses. La limite se voit avec des flux distincts : depuis `user`,
`for i in $(seq 12); do ping -c 1 -W 1 {srv} >/dev/null && echo ok || echo perdu; done` affiche cinq
`ok` (la réserve par défaut du seau à jetons), puis un écho sur deux est perdu. De même, depuis
`admin`, cinq connexions SSH rapprochées (`nc -z -w 2 {srv} 22`) aboutissent et les suivantes
restent sans réponse. `nft list ruleset` affiche `counter packets … bytes …` sur les règles du SSH
et du HTTP. Le journal
du noyau n'est pas lisible dans un conteneur (`dmesg` : *Operation not permitted*), d'où
`group 0` : `tcpdump -n -i nflog:0` sur `srv` montre les paquets journalisés pendant que `bad`
tente une connexion.

Pièges : une instruction placée après le verdict (`accept limit rate …`), que `nft` refuse ;
`limit rate 1/second drop`, qui ne détruit qu'au rythme de la limite et laisse le surplus
continuer ; un `log` sans verdict, qui journalise mais ne décide rien ; tapée dans un shell, une
règle qui contient `log prefix "…"` doit être entre apostrophes.

Évaluation : `limitation_debit` (1 point : le texte de `nft list ruleset` de `srv` contient
`limit`) et `compteur_ou_log` (1 point : il contient `counter` ou `log`). Seule la présence des
mots est vérifiée, pas le comportement.
""").format(conf=render_table([], ["…", self.net_scheme.rule_blacklist(), self.net_scheme.rule_icmp(),
                                   self.net_scheme.rule_ssh(), self.net_scheme.rule_http(), "…"]),
            srv=d.ips.srv.ip)),
        )

        # ---- probes, on the hidden copy ----
        # No element is earned without a rule.  With an empty ruleset every connection succeeds:
        # one that must succeed only counts under the drop policy of the input chain.  With a drop
        # policy alone every connection fails: one that must fail only counts when its witness
        # connection succeeds.
        policy_drop = firewall.input_policy(firewall.get_nft_json(self, "srv")) == "drop"
        bad_http = firewall.probe_tcp(self, "bad_h", d.ips.srv, HTTP_PORT)
        user_http = firewall.probe_tcp(self, "user_h", d.ips.srv, HTTP_PORT)
        admin_ssh = firewall.probe_tcp(self, "admin_h", d.ips.srv, SSH_PORT)
        user_ssh = firewall.probe_tcp(self, "user_h", d.ips.srv, SSH_PORT)
        reject_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, REJECT_PORT)
        drop_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, DROP_PORT)

        self.add_grade_element(title=no_tr("blacklist_bad_bloque"), max_grade=2,
            grade=2 * int(not bad_http and user_http),
            description=tr("Liste noire : `bad` est bloqué (HTTP) alors que `user` passe"))
        self.add_grade_element(title=no_tr("blacklist_user_ok"), max_grade=1, grade=int(user_http and policy_drop),
            description=tr("`user` (hors liste noire) accède au HTTP, sous une politique drop"))
        self.add_grade_element(title=no_tr("whitelist_admin_ssh"), max_grade=2,
            grade=2 * int(admin_ssh and policy_drop),
            description=tr("Liste blanche : SSH autorisé depuis `admin`, sous une politique drop"))
        self.add_grade_element(title=no_tr("whitelist_user_ssh_bloque"), max_grade=2,
            grade=2 * int(not user_ssh and admin_ssh),
            description=tr("SSH refusé depuis `user` (hors liste blanche) alors que `admin` passe"))
        self.add_grade_element(title=no_tr("port_reject"), max_grade=2, grade=2 * int(reject_verdict == "refused"),
            description=tr("Port {_arg0} : reject (refus immédiat)").format(_arg0=REJECT_PORT))
        self.add_grade_element(title=no_tr("port_drop"), max_grade=2,
            grade=2 * int(drop_verdict == "dropped" and user_http),
            description=tr("Port {_arg0} : drop (silencieux) alors que le HTTP reste ouvert").format(_arg0=DROP_PORT))
        self.add_grade_element(title=no_tr("ensembles_nommes"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "set ") or firewall.ruleset_mentions(rs, "@")),
            description=tr("Utilisation d'ensembles nommés (set / @)"))
        self.add_grade_element(title=no_tr("limitation_debit"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "limit")),
            description=tr("Présence d'une limitation de débit (limit rate)"))
        self.add_grade_element(title=no_tr("compteur_ou_log"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "counter") or firewall.ruleset_mentions(rs, "log")),
            description=tr("Présence d'un counter et/ou d'un log"))


_TRANSLATIONS = {'en': {
    "nftables : aspects avancés (sets, limit, reject) (misc)": "nftables: advanced features (sets, limit, reject) (misc)",
    """
**Sommaire**
""": """
**Contents**
""",
    "nftables en bref": "nftables in brief",
    """
Sous Linux, le filtrage des paquets se fait **dans le noyau**. **Netfilter** y fournit des points
d'accrochage (*hooks*) sur le trajet des paquets et le suivi de connexion (*conntrack*) ;
**nftables** exécute, à ces points, les règles que lui confie la commande **`nft`**. Le pare-feu
d'une machine tient en peu de choses : une chaîne `input` de politique `drop`, la règle à états,
puis une règle par service ouvert. Ce TP y ajoute les outils qui rendent un jeu de règles
**court, rapide et modifiable sans le recharger** : les ensembles, les dictionnaires, le choix
entre `reject` et `drop`, la limitation de débit, les compteurs et la journalisation.

| terme | rôle |
|-------|------|
| famille | les paquets qu'une table voit : `ip` (IPv4), `ip6` (IPv6), `inet` (les deux), `arp`, `bridge`, `netdev` |
| table | un conteneur nommé, dans une famille, de chaînes, d'ensembles, de dictionnaires et de compteurs |
| chaîne de base | une liste de règles accrochée à un hook, avec une priorité et une politique par défaut |
| chaîne régulière | une liste de règles sans hook, où l'on arrive par un saut (`jump`, `goto`) |
| règle | des critères puis des actions, évalués de gauche à droite |
| verdict | ce que devient le paquet : `accept`, `drop`, `jump`… |
| ensemble (*set*) | des valeurs d'un même type, que les règles consultent en une seule opération |
| dictionnaire (*map*) | des associations clé : valeur ; la valeur peut être un verdict (*verdict map*) |

Les machines du TP ont nftables 1.1.3 (`nft --version`), la version de Debian 13 : c'est elle que
ce cours décrit.

**Comment lire ce cours.** Les sections @@ref:hooks@@ à @@ref:conntrack@@ rappellent les bases,
et la section @@ref:base@@ donne le **socle** sur lequel s'appuie tout le TP : commencez par
elle. Les questions 1 et 2 utilisent les ensembles nommés (sections @@ref:named-sets@@ et
@@ref:lists@@), la question 3 `reject` et `drop` (section @@ref:reject-drop@@), la question 4 la
limitation de débit, les compteurs et la journalisation (sections @@ref:limit@@ et
@@ref:counters-log@@) ; la section @@ref:testing@@ dit comment vérifier chaque règle. Le reste
(les ensembles alimentés par les règles, les dictionnaires, les quotas, la trace) complète le
tableau : vous en aurez besoin sur de vraies machines.
""": """
On Linux, packet filtering is done **in the kernel**. There, **Netfilter** provides attachment
points (*hooks*) along the path of the packets, and connection tracking (*conntrack*); at these
points, **nftables** runs the rules handed to it by the **`nft`** command. The firewall of a
machine boils down to very little: an `input` chain with a `drop` policy, the stateful rule, then
one rule per open service. This lab adds the tools that make a ruleset **short, fast and
modifiable without reloading it**: sets, maps, the choice between `reject` and `drop`, rate
limiting, counters and logging.

| term | role |
|------|------|
| family | the packets a table sees: `ip` (IPv4), `ip6` (IPv6), `inet` (both), `arp`, `bridge`, `netdev` |
| table | a named container, within a family, of chains, sets, maps and counters |
| base chain | a list of rules attached to a hook, with a priority and a default policy |
| regular chain | a list of rules without a hook, reached by a jump (`jump`, `goto`) |
| rule | matches then actions, evaluated from left to right |
| verdict | what becomes of the packet: `accept`, `drop`, `jump`… |
| set | values of the same type, which the rules look up in a single operation |
| map | key: value associations; the value may be a verdict (*verdict map*) |

The machines of the lab run nftables 1.1.3 (`nft --version`), the version of Debian 13: it is the
one this course describes.

**How to read this course.** Sections @@ref:hooks@@ to @@ref:conntrack@@ review the basics, and
section @@ref:base@@ gives the **base** on which the whole lab builds: start with it. Questions 1
and 2 use named sets (sections @@ref:named-sets@@ and @@ref:lists@@), question 3 `reject` and
`drop` (section @@ref:reject-drop@@), question 4 rate limiting, counters and logging (sections
@@ref:limit@@ and @@ref:counters-log@@); section @@ref:testing@@ explains how to check each rule.
The rest (sets fed by the rules, maps, quotas, tracing) completes the picture: you will need it on
real machines.
""",
    "Le trajet d'un paquet : les hooks": "The path of a packet: the hooks",
    """
Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées. Choisir le hook d'une chaîne, c'est choisir **quels
paquets** elle verra, et **à quel moment** de leur traitement.

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (par interface)          (routage)                                               (par interface)
```

### @@sec:hooks-ip@@ Les cinq hooks de la pile IP

| hook | paquets vus |
|------|-------------|
| `prerouting` | tous les paquets **reçus**, avant la décision de routage |
| `input` | les paquets **destinés à la machine** |
| `forward` | les paquets que la machine **route** d'une interface vers une autre |
| `output` | les paquets **émis par les processus de la machine** |
| `postrouting` | tous les paquets qui **partent**, routés ou émis localement |

Un paquet reçu pour la machine traverse `prerouting` puis `input` ; un paquet routé,
`prerouting`, `forward` puis `postrouting` ; un paquet émis, `output` puis `postrouting`. Un
paquet de la machine vers elle-même (`127.0.0.1`, ou sa propre adresse) fait les deux trajets à
la suite, à travers l'interface `lo` : un pare-feu qui détruit tout en `input` casse aussi les
communications locales. Ce TP ne travaille que dans le hook **`input`** de `srv`.

### @@sec:families@@ ingress, egress et les familles

Deux autres hooks sont attachés à **une interface** (`device` dans la déclaration de la
chaîne), en dehors de la pile IP : **`ingress`** voit tout ce que l'interface reçoit, **avant
`prerouting`** (donc avant le suivi de connexion : c'est l'endroit le moins coûteux pour
détruire un trafic indésirable), et **`egress`** tout ce qu'elle émet, **après `postrouting`**.
Les hooks disponibles dépendent de la **famille** de la table :

| famille | paquets vus | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | les cinq mêmes |
| `inet` | IPv4 et IPv6 | les cinq mêmes, et `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | les trames qui traversent un pont (*bridge*) Linux | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | tout ce qui passe par une interface | `ingress`, `egress` |

ARP n'est pas de l'IP : les chaînes des familles `ip`, `ip6` et `inet` ne voient jamais les
requêtes ni les réponses ARP, et une politique `drop` en `input` n'empêche pas une machine de
trouver l'adresse MAC de ses voisines.
""": """
A **hook** is a place on the path of a packet through the kernel where Netfilter calls the chains
attached to it. Choosing the hook of a chain means choosing **which packets** it will see, and **at
what point** of their processing.

```
                              +-------- local processes ---------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
 (per interface)          (routing)                                               (per interface)
```

### @@sec:hooks-ip@@ The five hooks of the IP stack

| hook | packets seen |
|------|-------------|
| `prerouting` | all the packets **received**, before the routing decision |
| `input` | the packets **addressed to the machine** |
| `forward` | the packets the machine **routes** from one interface to another |
| `output` | the packets **sent by the processes of the machine** |
| `postrouting` | all the packets that **leave**, routed or sent locally |

A packet received for the machine goes through `prerouting` then `input`; a routed packet,
`prerouting`, `forward` then `postrouting`; a sent packet, `output` then `postrouting`. A packet
from the machine to itself (`127.0.0.1`, or its own address) takes both paths one after the
other, through the `lo` interface: a firewall that drops everything in `input` also breaks local
communications. This lab only works in the **`input`** hook of `srv`.

### @@sec:families@@ ingress, egress and the families

Two other hooks are attached to **an interface** (`device` in the declaration of the chain),
outside the IP stack: **`ingress`** sees everything the interface receives, **before
`prerouting`** (so before connection tracking: it is the cheapest place to drop unwanted
traffic), and **`egress`** everything it sends, **after `postrouting`**. The hooks available
depend on the **family** of the table:

| family | packets seen | hooks |
|---------|-------------|-------|
| `ip` | IPv4 | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `ip6` | IPv6 | the same five |
| `inet` | IPv4 and IPv6 | the same five, and `ingress` |
| `arp` | ARP | `input`, `output` |
| `bridge` | the frames crossing a Linux bridge | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `netdev` | everything that goes through an interface | `ingress`, `egress` |

ARP is not IP: the chains of the `ip`, `ip6` and `inet` families never see ARP requests or
replies, and a `drop` policy in `input` does not prevent a machine from finding the MAC address of
its neighbours.
""",
    "Tables, chaînes, règles": "Tables, chains, rules",
    """
Un jeu de règles nftables (*ruleset*) est organisé en **tables**, qui contiennent des
**chaînes**, qui contiennent des **règles**. Au départ il est **vide** : nftables n'a ni table
ni chaîne prédéfinie, et sans chaîne tous les paquets passent. Les noms des tables et des
chaînes sont libres ; `filter` et `input` ne sont que des habitudes.

### @@sec:base-chains@@ Tables et chaînes de base

Une **table** appartient à une famille ; pour filtrer, **`inet`** est le choix recommandé (les
mêmes règles valent pour IPv4 et pour IPv6). C'est un espace de noms : ses chaînes, ses
ensembles, ses dictionnaires et ses compteurs ne sont connus que de ses propres règles. Une
**chaîne de base** est accrochée à un hook :

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- le **type** : `filter` pour filtrer, `nat` pour la traduction d'adresses, `route` pour
  refaire le routage d'un paquet émis par la machine ;
- le **hook** ;
- la **priorité** : un entier qui ordonne les chaînes accrochées au même hook, de la plus
  petite valeur à la plus grande (`0`, ou `filter`, pour le filtrage) ;
- la **politique** par défaut, `accept` ou `drop` : le verdict appliqué aux paquets qui
  atteignent la fin de la chaîne sans qu'aucune règle n'ait tranché. Sans `policy`, c'est
  `accept` ; `reject` n'est pas une politique possible.

Avec `policy drop`, *tout ce qui n'est pas explicitement autorisé est interdit* : c'est la bonne
façon de construire un pare-feu.

### @@sec:priorities@@ Plusieurs chaînes sur un même hook

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées
au même hook : un paquet les traverse **toutes**, par priorité croissante. Les priorités
usuelles ont un nom : `raw` (-300), `mangle` (-150), `dstnat` (-100), `filter` (0), `security`
(50), `srcnat` (100) ; le suivi de connexion opère à la priorité -200, donc avant une chaîne de
priorité `filter`. Les deux verdicts ne sont pas symétriques :

- **`drop` est définitif** : le paquet est détruit sur-le-champ, plus aucune chaîne ne le voit ;
- **`accept` ne vaut que pour la chaîne de base en cours** : le paquet passe à la chaîne
  suivante, qui peut encore le détruire.

### @@sec:regular-chains@@ Chaînes régulières

Une **chaîne régulière** n'a ni hook, ni type, ni politique (`nft add chain inet filter
journal`). Elle ne voit que les paquets qu'une règle lui envoie par **`jump`** ou par **`goto`**
depuis une autre chaîne de la même table. À la fin d'une chaîne atteinte par `jump` (ou sur le
verdict `return`), l'évaluation reprend dans la chaîne appelante, à la règle qui suit le saut ;
avec `goto`, elle n'y revient pas. Les sauts s'imbriquent sur 16 niveaux au plus. Ces chaînes
servent à factoriser des règles (« journaliser puis détruire ») et à structurer un grand jeu de
règles (une chaîne par service ou par zone).

### @@sec:rules@@ Règles, critères et verdicts

Une **règle** est une suite d'expressions évaluées **de gauche à droite** : des **critères**,
puis des **actions** et, le plus souvent, un **verdict**. Dès qu'un critère n'est pas
satisfait, le paquet passe à la règle suivante. Les règles d'une chaîne sont évaluées **dans
l'ordre** : la première règle satisfaite qui porte un verdict décide, et les suivantes ne sont
pas consultées. L'ordre des règles fait donc partie de la politique.

| critère | signification |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | interface d'entrée (`iif` : par son numéro, l'interface doit exister ; `iifname` : par son nom) |
| `ip saddr 192.0.2.13`, `ip daddr 192.0.2.0/24` | adresse IPv4 source, destination (une adresse ou un réseau) |
| `meta l4proto udp`, `ip protocol icmp` | protocole transporté (`meta l4proto` : en IPv4 comme en IPv6) |
| `tcp dport 22`, `udp sport 53` | port TCP ou UDP, destination ou source |
| `icmp type echo-request` | type ICMP |
| `ct state established,related` | état de la connexion (section @@ref:conntrack@@) |

Une valeur peut être une plage (`tcp dport 8000-8100`), un ensemble (`tcp dport { 22, 80 }`,
section @@ref:sets@@) ou être niée (`ip saddr != 192.0.2.13`). Plusieurs critères dans une
règle sont tous requis ; nommer un champ implique son protocole (`tcp dport 22` ne concerne que
TCP).

| verdict ou action | effet |
|-------------------|-------|
| `accept` | le paquet passe ; l'évaluation de la chaîne de base s'arrête |
| `drop` | le paquet est détruit sans rien dire |
| `reject` | le paquet est détruit et l'émetteur prévenu (section @@ref:reject-drop@@) |
| `jump chaine`, `goto chaine`, `return` | saut vers une chaîne régulière, retour |
| `counter`, `log`, `limit rate …` | actions **sans verdict** : la règle se poursuit, puis le paquet passe à la règle suivante (sections @@ref:limit@@ et @@ref:counters-log@@) |

L'ordre des mots compte aussi à l'intérieur d'une règle : `tcp dport 22 counter accept` compte
les paquets destinés au port 22, `counter tcp dport 22 accept` tous ceux qui atteignent la
règle.
""": """
An nftables ruleset is organised in **tables**, which contain **chains**, which contain
**rules**. At first it is **empty**: nftables has no predefined table or chain, and without a
chain every packet goes through. The names of the tables and of the chains are free; `filter` and
`input` are mere conventions.

### @@sec:base-chains@@ Tables and base chains

A **table** belongs to a family; for filtering, **`inet`** is the recommended choice (the same
rules apply to IPv4 and to IPv6). It is a namespace: its chains, sets, maps and counters are known
only to its own rules. A **base chain** is attached to a hook:

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
```

- the **type**: `filter` to filter, `nat` for address translation, `route` to redo the routing of
  a packet sent by the machine;
- the **hook**;
- the **priority**: an integer that orders the chains attached to the same hook, from the smallest
  value to the largest (`0`, or `filter`, for filtering);
- the default **policy**, `accept` or `drop`: the verdict applied to the packets that reach the
  end of the chain without any rule having decided. Without `policy`, it is `accept`; `reject` is
  not a possible policy.

With `policy drop`, *everything that is not explicitly allowed is forbidden*: this is the right
way to build a firewall.

### @@sec:priorities@@ Several chains on the same hook

Several base chains, of the same table or of different tables, can be attached to the same hook: a
packet goes through **all** of them, by increasing priority. The usual priorities have a name:
`raw` (-300), `mangle` (-150), `dstnat` (-100), `filter` (0), `security` (50), `srcnat` (100);
connection tracking operates at priority -200, so before a chain of priority `filter`. The two
verdicts are not symmetric:

- **`drop` is final**: the packet is dropped on the spot, no other chain sees it;
- **`accept` only applies to the current base chain**: the packet moves on to the next chain,
  which can still drop it.

### @@sec:regular-chains@@ Regular chains

A **regular chain** has no hook, no type and no policy (`nft add chain inet filter journal`). It
only sees the packets a rule sends to it by **`jump`** or by **`goto`** from another chain of the
same table. At the end of a chain reached by `jump` (or on the `return` verdict), the evaluation
resumes in the calling chain, at the rule that follows the jump; with `goto`, it does not come
back. Jumps nest 16 levels deep at most. These chains serve to factor out rules ("log then
drop") and to structure a large ruleset (one chain per service or per zone).

### @@sec:rules@@ Rules, matches and verdicts

A **rule** is a sequence of expressions evaluated **from left to right**: **matches**, then
**actions** and, most often, a **verdict**. As soon as a match is not satisfied, the packet moves
on to the next rule. The rules of a chain are evaluated **in order**: the first satisfied rule
that carries a verdict decides, and the following ones are not consulted. The order of the rules
is therefore part of the policy.

| match | meaning |
|---------|---------------|
| `iif lo`, `iifname "eth0"` | input interface (`iif`: by its index, the interface must exist; `iifname`: by its name) |
| `ip saddr 192.0.2.13`, `ip daddr 192.0.2.0/24` | source, destination IPv4 address (an address or a network) |
| `meta l4proto udp`, `ip protocol icmp` | transported protocol (`meta l4proto`: in IPv4 as in IPv6) |
| `tcp dport 22`, `udp sport 53` | TCP or UDP port, destination or source |
| `icmp type echo-request` | ICMP type |
| `ct state established,related` | state of the connection (section @@ref:conntrack@@) |

A value can be a range (`tcp dport 8000-8100`), a set (`tcp dport { 22, 80 }`, section
@@ref:sets@@) or be negated (`ip saddr != 192.0.2.13`). Several matches in a rule are all
required; naming a field implies its protocol (`tcp dport 22` only concerns TCP).

| verdict or action | effect |
|-------------------|-------|
| `accept` | the packet goes through; the evaluation of the base chain stops |
| `drop` | the packet is dropped silently |
| `reject` | the packet is dropped and the sender notified (section @@ref:reject-drop@@) |
| `jump chain`, `goto chain`, `return` | jump to a regular chain, return |
| `counter`, `log`, `limit rate …` | actions **without a verdict**: the rule goes on, then the packet moves on to the next rule (sections @@ref:limit@@ and @@ref:counters-log@@) |

The order of the words also matters within a rule: `tcp dport 22 counter accept` counts the
packets addressed to port 22, `counter tcp dport 22 accept` all those that reach the rule.
""",
    "Le suivi de connexion et la règle à états": "Connection tracking and the stateful rule",
    """
Netfilter mémorise les **connexions** en cours (*conntrack*) : une connexion TCP, mais aussi un
« échange » UDP ou ICMP (une requête et sa réponse). Il ne filtre rien : il **étiquette**
chaque paquet d'un **état**, que les règles testent avec `ct state`.

| état | le paquet… |
|------|------------|
| `new` | ouvre une connexion, ou appartient à une connexion dont on n'a encore vu qu'un seul sens (le SYN en TCP) |
| `established` | appartient à une connexion dont on a vu des paquets dans les deux sens ; la toute première réponse (le SYN-ACK, l'`echo-reply`) est déjà dans cet état |
| `related` | est lié à une connexion connue sans lui appartenir : une erreur ICMP qui la concerne, par exemple |
| `invalid` | ne correspond à rien de connu et ne peut pas ouvrir de connexion |
| `untracked` | a été soustrait au suivi par une règle `notrack` |

La **règle à états** `ct state established,related accept`, placée en **première position**,
accepte d'un coup les réponses aux communications que la machine a elle-même initiées et la
suite des connexions entrantes déjà acceptées : il ne reste à décider que du sort des
**nouvelles** connexions. `ct state invalid drop` la complète souvent. Conséquence à retenir
pour la suite : **les règles placées après elle ne voient plus que le premier paquet de chaque
connexion**.
""": """
Netfilter remembers the ongoing **connections** (*conntrack*): a TCP connection, but also a UDP or
ICMP "exchange" (a request and its reply). It filters nothing: it **labels** each packet with a
**state**, which the rules test with `ct state`.

| state | the packet… |
|------|------------|
| `new` | opens a connection, or belongs to a connection of which only one direction has been seen so far (the SYN in TCP) |
| `established` | belongs to a connection with packets seen in both directions; the very first reply (the SYN-ACK, the `echo-reply`) is already in this state |
| `related` | is related to a known connection without belonging to it: an ICMP error about it, for example |
| `invalid` | matches nothing known and cannot open a connection |
| `untracked` | was taken out of tracking by a `notrack` rule |

The **stateful rule** `ct state established,related accept`, placed in **first position**,
accepts in one go the replies to the communications the machine itself initiated and the rest of
the incoming connections already accepted: all that is left to decide is the fate of the **new**
connections. `ct state invalid drop` often complements it. A consequence to remember for what
follows: **the rules placed after it only see the first packet of each connection**.
""",
    "Le socle d'un pare-feu de machine": "The base of a host firewall",
    """
Tout le TP part du même socle : une chaîne `input` de politique `drop`, la règle à états et
l'interface `lo`. Les outils des sections suivantes viennent s'y ajouter. Il y a deux façons de
travailler : écrire un fichier et le charger d'un bloc, ou taper les commandes une à une.

### @@sec:nft-files@@ Un fichier de règles

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # les réponses à ce que la machine a émis, puis les communications locales
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept

        # ... puis ce que l'on ouvre, règle par règle
    }
}
```

```
nft -c -f /etc/nftables.conf      # vérifie le fichier sans rien changer
nft -f /etc/nftables.conf         # le charge
```

- le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur,
  pas du tout ; à aucun moment la machine ne se retrouve sans règles ;
- le fichier commence par **`flush ruleset`** : l'ancien jeu de règles est remplacé d'un coup.
  Sans cette ligne, recharger le fichier ajouterait ses règles une seconde fois, à la suite des
  premières ;
- `define ADMIN = 192.0.2.13` nomme une valeur, reprise par `$ADMIN` ; `include "fichier"`
  insère un autre fichier ;
- `nft -s list ruleset > fichier` sauvegarde le jeu de règles en place dans un fichier
  rechargeable (ajoutez-lui `flush ruleset` en tête) ;
- sous Debian, le service `nftables` charge `/etc/nftables.conf` au démarrage. Les règles
  tapées avec `nft` sont **volatiles** : elles disparaissent au redémarrage.

### @@sec:nft-commands@@ Les commandes une à une

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept                               # ajoute en FIN de chaîne
nft insert rule inet filter input ct state established,related accept      # insère en TÊTE
```

**Le shell passe avant `nft`.** Le point-virgule, les guillemets, les parenthèses, `*`, `|`,
`&`, `<` et `>` ont un sens pour le shell, qui les interprète ou les retire avant que `nft` ne
voie la commande. La règle simple : dès qu'une commande contient autre chose que des mots, des
nombres et des adresses, **entourez d'apostrophes tout ce qui suit `nft`**.

### @@sec:nft-edit@@ Consulter, placer, supprimer

```
nft list ruleset                                                   # tout le jeu de règles
nft -a list ruleset                                                # avec le handle de chaque règle
nft list chain inet filter input                                   # une chaîne
nft insert rule inet filter input handle 7 tcp dport 80 accept     # AVANT la règle de handle 7
nft add rule inet filter input handle 7 tcp dport 80 accept        # APRÈS la règle 7
nft replace rule inet filter input handle 7 tcp dport 443 accept   # À LA PLACE de la règle 7
nft delete rule inet filter input handle 7                         # supprime la règle 7
nft flush chain inet filter input                                  # vide la chaîne ; sa politique reste
nft delete table inet filter                                       # supprime la table et son contenu
nft flush ruleset                                                  # efface tout
```

Le noyau attribue à chaque règle un numéro qui ne change plus, son **handle**, que `nft -a list
ruleset` affiche en fin de ligne (`# handle 7`) : ce n'est pas un numéro de ligne. Relisez
`nft list ruleset` après chaque ajout : une règle placée après un `accept`, un `drop` ou un
`reject` qui couvre les mêmes paquets n'est jamais consultée.
""": """
The whole lab starts from the same base: an `input` chain with a `drop` policy, the stateful rule
and the `lo` interface. The tools of the following sections are added to it. There are two ways to
work: write a file and load it in one go, or type the commands one by one.

### @@sec:nft-files@@ A rules file

```
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # the replies to what the machine sent, then the local communications
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept

        # ... then what we open, rule by rule
    }
}
```

```
nft -c -f /etc/nftables.conf      # checks the file without changing anything
nft -f /etc/nftables.conf         # loads it
```

- loading is **atomic**: the file is applied in full or, at the slightest error, not at all; at
  no moment is the machine left without rules;
- the file starts with **`flush ruleset`**: the old ruleset is replaced in one go. Without this
  line, reloading the file would add its rules a second time, after the first ones;
- `define ADMIN = 192.0.2.13` names a value, used as `$ADMIN`; `include "file"` inserts another
  file;
- `nft -s list ruleset > file` saves the current ruleset to a reloadable file (add `flush
  ruleset` at its head);
- on Debian, the `nftables` service loads `/etc/nftables.conf` at boot. The rules typed with `nft`
  are **volatile**: they disappear at reboot.

### @@sec:nft-commands@@ The commands one by one

```
nft add table inet filter
nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
nft add rule inet filter input iif lo accept                               # appends at the END of the chain
nft insert rule inet filter input ct state established,related accept      # inserts at the HEAD
```

**The shell comes before `nft`.** The semicolon, quotes, parentheses, `*`, `|`, `&`, `<` and `>`
mean something to the shell, which interprets or removes them before `nft` sees the command. The
simple rule: as soon as a command contains anything other than words, numbers and addresses,
**put single quotes around everything that follows `nft`**.

### @@sec:nft-edit@@ Viewing, placing, deleting

```
nft list ruleset                                                   # the whole ruleset
nft -a list ruleset                                                # with the handle of each rule
nft list chain inet filter input                                   # one chain
nft insert rule inet filter input handle 7 tcp dport 80 accept     # BEFORE the rule with handle 7
nft add rule inet filter input handle 7 tcp dport 80 accept        # AFTER rule 7
nft replace rule inet filter input handle 7 tcp dport 443 accept   # IN PLACE OF rule 7
nft delete rule inet filter input handle 7                         # deletes rule 7
nft flush chain inet filter input                                  # empties the chain; its policy stays
nft delete table inet filter                                       # deletes the table and its contents
nft flush ruleset                                                  # erases everything
```

The kernel gives each rule a number that never changes, its **handle**, which `nft -a list
ruleset` shows at the end of the line (`# handle 7`): it is not a line number. Read `nft list
ruleset` again after each addition: a rule placed after an `accept`, a `drop` or a `reject` that
covers the same packets is never consulted.
""",
    "Les ensembles (sets)": "Sets",
    """
Un **ensemble** (*set*) réunit des valeurs d'un même type. Une règle le consulte en **une seule
opération**, quel que soit le nombre de ses éléments : une règle et un ensemble de mille
adresses remplacent mille règles, et vont bien plus vite qu'elles.

### @@sec:anonymous-sets@@ Ensembles anonymes

Un ensemble **anonyme** s'écrit entre accolades, directement dans la règle :

```
tcp dport { 22, 80, 443 } accept
ip saddr { 192.0.2.13, 198.51.100.0/24 } drop
```

Il est figé : pour le modifier, il faut remplacer la règle.

### @@sec:named-sets@@ Ensembles nommés

Un ensemble **nommé** est un objet de la table, déclaré à part avec le **type** de ses
éléments ; les règles le désignent par `@nom` :

```
table inet filter {
    set liste_noire {
        type ipv4_addr
        elements = { 192.0.2.13, 198.51.100.7 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @liste_noire drop
    }
}
```

Son intérêt : son contenu se **modifie sans toucher aux règles** ni recharger le jeu de règles,
et plusieurs règles peuvent s'en servir.

```
nft 'add set inet filter liste_noire { type ipv4_addr; }'        # crée un ensemble vide
nft 'add element inet filter liste_noire { 203.0.113.9 }'        # ajoute un élément (ou plusieurs)
nft 'delete element inet filter liste_noire { 203.0.113.9 }'     # en retire un
nft 'get element inet filter liste_noire { 203.0.113.9 }'        # l'élément y est-il ?
nft list set inet filter liste_noire                             # affiche son contenu
nft list sets                                                    # tous les ensembles
nft flush set inet filter liste_noire                            # le vide
nft delete set inet filter liste_noire                           # le supprime
```

L'effet est immédiat : l'adresse ajoutée à la liste noire est bloquée au paquet suivant,
l'adresse retirée est débloquée aussitôt. On ne peut supprimer qu'un ensemble qu'aucune règle
ne consulte plus.

### @@sec:set-types@@ Types et options

Le `type` fixe la nature des éléments :

| type | éléments |
|------|----------|
| `ipv4_addr`, `ipv6_addr` | adresses IPv4, adresses IPv6 |
| `ether_addr` | adresses MAC |
| `inet_service` | ports |
| `inet_proto` | protocoles (`tcp`, `udp`, `icmp`…) |
| `mark` | marques de paquets |

À la place du type, `typeof` nomme le champ que l'ensemble servira à comparer, et `nft` en
déduit le type : `typeof ip saddr` vaut `type ipv4_addr`. Les options règlent le comportement
de l'ensemble :

| déclaration | effet |
|-------------|-------|
| `flags interval` | les éléments peuvent être des **réseaux** ou des **plages** (`198.51.100.0/24`, `192.0.2.10-192.0.2.20`, `1000-2000` pour des ports) ; sans ce drapeau, des valeurs isolées seulement |
| `auto-merge` | avec `flags interval` : les éléments voisins ou qui se recouvrent sont fusionnés, au lieu d'être refusés (`conflicting intervals`) |
| `flags timeout`, `timeout 1h` | les éléments **expirent** (section @@ref:set-timeouts@@) |
| `flags dynamic` | les **règles** peuvent ajouter des éléments, au passage des paquets (section @@ref:dynamic-sets@@) |
| `flags constant` | le contenu ne peut plus changer |
| `size 1000` | nombre maximal d'éléments |

Dans un fichier, chaque option occupe une ligne ; sur une ligne de commande, elles se séparent
par des points-virgules et les drapeaux par des virgules (`flags interval,timeout;`).

```
set reseaux_bloques {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 198.51.100.0/24, 192.0.2.10-192.0.2.20 }
}
```

### @@sec:set-timeouts@@ Éléments à durée limitée

Avec `flags timeout`, un élément disparaît de lui-même au bout d'un délai : celui de
l'ensemble (`timeout` dans la déclaration), ou le sien propre, donné à l'ajout. C'est l'outil
d'une liste noire **temporaire**.

```
nft 'add set inet filter punis { type ipv4_addr; flags timeout; timeout 1h; }'
nft 'add element inet filter punis { 203.0.113.9 }'                 # expire au bout d'une heure
nft 'add element inet filter punis { 198.51.100.7 timeout 10m }'    # expire au bout de dix minutes
nft list set inet filter punis                                      # « expires » : le temps restant
```

### @@sec:concatenations@@ Concaténations

Un élément peut réunir plusieurs champs, séparés par un point : « telle adresse **et** tel
port ». Le critère nomme les champs dans le même ordre.

```
nft 'add set inet filter acces { type ipv4_addr . inet_service; }'
nft 'add element inet filter acces { 192.0.2.13 . 22, 192.0.2.14 . 443 }'
nft add rule inet filter input ip saddr . tcp dport @acces accept
```

La même chose avec un ensemble anonyme :
`ip saddr . tcp dport { 192.0.2.13 . 22, 192.0.2.14 . 443 } accept`.

### @@sec:lists@@ Liste noire, liste blanche

- **liste noire** : `ip saddr @liste_noire drop`, placée **avant** les règles qui acceptent (une
  règle `accept` rencontrée d'abord laisserait passer le paquet) ;
- **liste blanche** : `ip saddr @admins tcp dport 22 accept` : le service n'est ouvert qu'aux
  membres de l'ensemble ; les autres sources ne satisfont aucune règle et tombent dans la
  politique `drop`.

Placée après la règle à états, la règle d'une liste noire ne voit que les **nouvelles**
connexions : celles qu'une adresse avait ouvertes avant d'être listée continuent. Placée avant
elle, la règle les coupe aussitôt.
""": """
A **set** gathers values of the same type. A rule looks it up in **a single operation**, whatever
the number of its elements: one rule and a set of a thousand addresses replace a thousand rules,
and are much faster than them.

### @@sec:anonymous-sets@@ Anonymous sets

An **anonymous** set is written between braces, directly in the rule:

```
tcp dport { 22, 80, 443 } accept
ip saddr { 192.0.2.13, 198.51.100.0/24 } drop
```

It is frozen: to change it, the rule has to be replaced.

### @@sec:named-sets@@ Named sets

A **named** set is an object of the table, declared separately with the **type** of its
elements; the rules refer to it as `@name`:

```
table inet filter {
    set liste_noire {
        type ipv4_addr
        elements = { 192.0.2.13, 198.51.100.7 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ip saddr @liste_noire drop
    }
}
```

Its advantage: its contents can be **changed without touching the rules** or reloading the
ruleset, and several rules can use it.

```
nft 'add set inet filter liste_noire { type ipv4_addr; }'        # creates an empty set
nft 'add element inet filter liste_noire { 203.0.113.9 }'        # adds an element (or several)
nft 'delete element inet filter liste_noire { 203.0.113.9 }'     # removes one
nft 'get element inet filter liste_noire { 203.0.113.9 }'        # is the element in it?
nft list set inet filter liste_noire                             # shows its contents
nft list sets                                                    # all the sets
nft flush set inet filter liste_noire                            # empties it
nft delete set inet filter liste_noire                           # deletes it
```

The effect is immediate: an address added to the blacklist is blocked at the next packet, an
address removed is unblocked at once. Only a set that no rule looks up any more can be deleted.

### @@sec:set-types@@ Types and options

The `type` sets the nature of the elements:

| type | elements |
|------|----------|
| `ipv4_addr`, `ipv6_addr` | IPv4 addresses, IPv6 addresses |
| `ether_addr` | MAC addresses |
| `inet_service` | ports |
| `inet_proto` | protocols (`tcp`, `udp`, `icmp`…) |
| `mark` | packet marks |

Instead of the type, `typeof` names the field the set will be compared with, and `nft` deduces
the type from it: `typeof ip saddr` means `type ipv4_addr`. The options set the behaviour of the
set:

| declaration | effect |
|-------------|-------|
| `flags interval` | the elements can be **networks** or **ranges** (`198.51.100.0/24`, `192.0.2.10-192.0.2.20`, `1000-2000` for ports); without this flag, single values only |
| `auto-merge` | with `flags interval`: adjacent or overlapping elements are merged, instead of being refused (`conflicting intervals`) |
| `flags timeout`, `timeout 1h` | the elements **expire** (section @@ref:set-timeouts@@) |
| `flags dynamic` | the **rules** can add elements, as the packets go by (section @@ref:dynamic-sets@@) |
| `flags constant` | the contents can no longer change |
| `size 1000` | maximum number of elements |

In a file, each option takes one line; on a command line, they are separated by semicolons and
the flags by commas (`flags interval,timeout;`).

```
set reseaux_bloques {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { 198.51.100.0/24, 192.0.2.10-192.0.2.20 }
}
```

### @@sec:set-timeouts@@ Elements with a limited lifetime

With `flags timeout`, an element disappears by itself after a delay: that of the set (`timeout`
in the declaration), or its own, given when it is added. It is the tool for a **temporary**
blacklist.

```
nft 'add set inet filter punis { type ipv4_addr; flags timeout; timeout 1h; }'
nft 'add element inet filter punis { 203.0.113.9 }'                 # expires after one hour
nft 'add element inet filter punis { 198.51.100.7 timeout 10m }'    # expires after ten minutes
nft list set inet filter punis                                      # "expires": the time left
```

### @@sec:concatenations@@ Concatenations

An element can combine several fields, separated by a dot: "this address **and** this port". The
match names the fields in the same order.

```
nft 'add set inet filter acces { type ipv4_addr . inet_service; }'
nft 'add element inet filter acces { 192.0.2.13 . 22, 192.0.2.14 . 443 }'
nft add rule inet filter input ip saddr . tcp dport @acces accept
```

The same thing with an anonymous set:
`ip saddr . tcp dport { 192.0.2.13 . 22, 192.0.2.14 . 443 } accept`.

### @@sec:lists@@ Blacklist, whitelist

- **blacklist**: `ip saddr @liste_noire drop`, placed **before** the rules that accept (an
  `accept` rule met first would let the packet through);
- **whitelist**: `ip saddr @admins tcp dport 22 accept`: the service is open only to the members
  of the set; the other sources match no rule and fall into the `drop` policy.

Placed after the stateful rule, the rule of a blacklist only sees the **new** connections: those an
address had opened before being listed carry on. Placed before it, the rule cuts them off at once.
""",
    "Les ensembles alimentés par les règles": "Sets fed by the rules",
    """
Avec `flags dynamic`, ce sont les **règles** qui remplissent l'ensemble, au passage des
paquets, d'une valeur tirée du paquet examiné :

- `add @nom { ip saddr }` range l'adresse source du paquet dans l'ensemble, si elle n'y est pas
  déjà ;
- `update @nom { ip saddr }` fait de même, et **remet à zéro le délai** de l'élément à chaque
  paquet (`add` ne le prolonge pas).

Un tel ensemble se déclare avec un `timeout` : sans lui, il ne ferait que grossir. Exemple :
bannir dix minutes toute machine qui tente une connexion telnet (port 23), qu'aucun utilisateur
légitime n'a de raison de viser.

```
nft 'add set inet filter bannis { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft insert rule inet filter input ip saddr @bannis drop
nft 'add rule inet filter input tcp dport 23 add @bannis { ip saddr } drop'
```

- la règle `ip saddr @bannis drop` est insérée **en tête**, avant la règle à états : un banni
  perd aussi ses connexions en cours ;
- pour qu'un banni ne revienne qu'après dix minutes de **silence**, on prolonge son
  bannissement à chaque paquet qu'il envoie, en écrivant la première règle
  `ip saddr @bannis update @bannis { ip saddr } drop` ;
- `nft list set inet filter bannis` affiche les bannis et le temps qui leur reste ;
  `nft flush set inet filter bannis` lève tous les bannissements, `nft 'delete element inet
  filter bannis { 203.0.113.9 }'` un seul.

Les éléments d'un ensemble alimenté par une règle peuvent aussi porter un **état propre** : une
limite de débit ou un compte de connexions par adresse (section @@ref:limit-per-source@@).
""": """
With `flags dynamic`, it is the **rules** that fill the set, as the packets go by, with a value
taken from the packet being examined:

- `add @name { ip saddr }` puts the source address of the packet into the set, if it is not
  already there;
- `update @name { ip saddr }` does the same, and **resets the timeout** of the element at each
  packet (`add` does not extend it).

Such a set is declared with a `timeout`: without it, it would only grow. Example: banning for ten
minutes any machine that attempts a telnet connection (port 23), which no legitimate user has any
reason to target.

```
nft 'add set inet filter bannis { type ipv4_addr; flags dynamic,timeout; timeout 10m; }'
nft insert rule inet filter input ip saddr @bannis drop
nft 'add rule inet filter input tcp dport 23 add @bannis { ip saddr } drop'
```

- the rule `ip saddr @bannis drop` is inserted **at the head**, before the stateful rule: a banned
  machine also loses its ongoing connections;
- for a banned machine to come back only after ten minutes of **silence**, its ban is extended at
  each packet it sends, by writing the first rule
  `ip saddr @bannis update @bannis { ip saddr } drop`;
- `nft list set inet filter bannis` shows the banned addresses and the time they have left;
  `nft flush set inet filter bannis` lifts all the bans, `nft 'delete element inet filter bannis
  { 203.0.113.9 }'` a single one.

The elements of a set fed by a rule can also carry a **state of their own**: a rate limit or a
count of connections per address (section @@ref:limit-per-source@@).
""",
    "Les dictionnaires (maps)": "Maps",
    """
Un **dictionnaire** (*map*) associe une **valeur** à chaque **clé**. Comme un ensemble, il est
consulté en une seule opération, quel que soit le nombre de ses entrées.

### @@sec:vmaps@@ Dictionnaires de verdicts

Un **dictionnaire de verdicts** (*verdict map*, `vmap`) associe à chaque clé un **verdict**
(`accept`, `drop`, `jump chaine`…) : une seule règle aiguille les paquets, au lieu d'une règle
par cas.

```
tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }
iifname vmap { "eth0" : jump zone_lan, "eth1" : jump zone_wan }
ct state vmap { established : accept, related : accept, invalid : drop }
ip saddr . tcp dport vmap { 192.0.2.13 . 22 : accept, 192.0.2.14 . 443 : accept }
```

Un paquet dont le champ n'est pas une clé du dictionnaire ne satisfait pas la règle : il passe
à la règle suivante. La troisième ligne écrit en une règle le début habituel d'une chaîne (la
règle à états et `ct state invalid drop`) ; la dernière prend pour clé une concaténation
(section @@ref:concatenations@@).

### @@sec:named-maps@@ Dictionnaires nommés

Comme un ensemble, un dictionnaire peut être **nommé** : c'est alors un objet de la table, dont
le contenu se modifie sans toucher aux règles. Son type donne celui de la clé, puis celui de la
valeur.

```
map services {
    type inet_service : verdict
    elements = { 22 : accept, 80 : accept }
}
```

La règle devient `tcp dport vmap @services`, et l'on ouvre ou ferme un port sans la modifier :

```
nft 'add map inet filter services { type inet_service : verdict; }'    # crée un dictionnaire vide
nft 'add element inet filter services { 443 : accept }'                # ajoute une entrée
nft list map inet filter services                                      # affiche son contenu
nft list maps                                                          # tous les dictionnaires
```

### @@sec:data-maps@@ Dictionnaires de valeurs

Les autres dictionnaires fournissent une **valeur** là où une action en attend une (une
adresse, un port). On les rencontre surtout dans la traduction d'adresses :

```
dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }      # le serveur dépend du port visé
```

Nommé, un tel dictionnaire se déclare `type inet_service : ipv4_addr` et la règle s'écrit
`dnat to tcp dport map @nom`.
""": """
A **map** associates a **value** with each **key**. Like a set, it is looked up in a single
operation, whatever the number of its entries.

### @@sec:vmaps@@ Verdict maps

A **verdict map** (`vmap`) associates a **verdict** (`accept`, `drop`, `jump chain`…) with each
key: a single rule dispatches the packets, instead of one rule per case.

```
tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }
iifname vmap { "eth0" : jump zone_lan, "eth1" : jump zone_wan }
ct state vmap { established : accept, related : accept, invalid : drop }
ip saddr . tcp dport vmap { 192.0.2.13 . 22 : accept, 192.0.2.14 . 443 : accept }
```

A packet whose field is not a key of the map does not match the rule: it moves on to the next
rule. The third line writes in a single rule the usual start of a chain (the stateful rule and
`ct state invalid drop`); the last one takes a concatenation as its key (section
@@ref:concatenations@@).

### @@sec:named-maps@@ Named maps

Like a set, a map can be **named**: it is then an object of the table, whose contents can be
changed without touching the rules. Its type gives that of the key, then that of the value.

```
map services {
    type inet_service : verdict
    elements = { 22 : accept, 80 : accept }
}
```

The rule becomes `tcp dport vmap @services`, and a port is opened or closed without changing it:

```
nft 'add map inet filter services { type inet_service : verdict; }'    # creates an empty map
nft 'add element inet filter services { 443 : accept }'                # adds an entry
nft list map inet filter services                                      # shows its contents
nft list maps                                                          # all the maps
```

### @@sec:data-maps@@ Data maps

The other maps supply a **value** where an action expects one (an address, a port). They are
mostly met in address translation:

```
dnat to tcp dport map { 80 : 192.0.2.10, 8080 : 192.0.2.11 }      # the server depends on the port targeted
```

Named, such a map is declared `type inet_service : ipv4_addr` and the rule is written
`dnat to tcp dport map @name`.
""",
    "reject ou drop ?": "reject or drop?",
    """
### @@sec:reject-forms@@ Deux façons de refuser

- **`drop`** : le paquet est détruit **sans réponse**. L'émetteur retransmet, puis renonce à
  l'expiration de son délai d'attente (*timeout*) : le port paraît « filtré » ;
- **`reject`** : le paquet est détruit et l'émetteur **prévenu** aussitôt par un message
  d'erreur. Le client échoue **immédiatement** : le port paraît « fermé ».

```
tcp dport 8080 reject with tcp reset
tcp dport 9090 drop
```

`reject` n'est pas une politique possible pour une chaîne : pour refuser par défaut plutôt que
détruire, on termine la chaîne par une règle `reject`. La réponse se choisit :

| règle | réponse envoyée à l'émetteur |
|-------|------------------------------|
| `reject` | un message ICMP *port unreachable* |
| `reject with tcp reset` | un segment TCP RST, exactement ce que répond une machine dont le port est fermé (TCP seulement) |
| `reject with icmp admin-prohibited` | le message ICMP choisi ; autres codes : `host-unreachable`, `net-unreachable`, `port-unreachable`… |
| `reject with icmpx admin-prohibited` | dans une table `inet` : l'erreur équivalente en ICMP ou en ICMPv6, selon le paquet |

`nft list ruleset` réaffiche un `reject` sans précision sous sa forme complète (`reject with
icmp port-unreachable`, ou `icmpx` dans une table `inet` quand la règle ne dit pas la version
d'IP).

### @@sec:client-view@@ Ce que voit le client

| le pare-feu… | le client (`curl -m 5`, `nc -vz -w 5`) |
|--------------|----------------------------------------|
| accepte, et un service écoute | la connexion s'ouvre |
| refuse (`reject`) | échoue **immédiatement** (`nc` : `Connection refused` ; `curl` : erreur 7) |
| détruit (`drop`) | attend, puis renonce au bout de son délai (`nc` : `timed out` ; `curl` : erreur 28, `Connection timed out`) |
| accepte, mais aucun service n'écoute | échoue **immédiatement**, de la même façon : la machine répond elle-même par un RST |

La différence se lit donc dans le **délai** : un refus immédiat pour `reject`, une longue
attente pour `drop`. Attention au dernier cas : vu du client, rien ne distingue un port accepté
mais sans service d'un `reject with tcp reset`. Pour savoir ce que fait une règle, il faut
qu'un service écoute sur le port (section @@ref:testing@@).

### @@sec:which@@ Lequel choisir ?

`drop` ne révèle rien, pas même l'existence de la machine, et ne coûte rien : c'est le choix
face à l'extérieur, et celui de la politique par défaut. `reject` évite aux utilisateurs
légitimes d'attendre et facilite le diagnostic : on l'emploie volontiers à l'intérieur.
""": """
### @@sec:reject-forms@@ Two ways to refuse

- **`drop`**: the packet is dropped **without a reply**. The sender retransmits, then gives up
  when its timeout expires: the port looks "filtered";
- **`reject`**: the packet is dropped and the sender **notified** at once by an error message.
  The client fails **immediately**: the port looks "closed".

```
tcp dport 8080 reject with tcp reset
tcp dport 9090 drop
```

`reject` is not a possible policy for a chain: to refuse by default rather than drop, the chain is
ended with a `reject` rule. The reply can be chosen:

| rule | reply sent to the sender |
|-------|------------------------------|
| `reject` | an ICMP *port unreachable* message |
| `reject with tcp reset` | a TCP RST segment, exactly what a machine whose port is closed replies (TCP only) |
| `reject with icmp admin-prohibited` | the chosen ICMP message; other codes: `host-unreachable`, `net-unreachable`, `port-unreachable`… |
| `reject with icmpx admin-prohibited` | in an `inet` table: the equivalent error in ICMP or in ICMPv6, depending on the packet |

`nft list ruleset` shows a bare `reject` in its full form (`reject with icmp port-unreachable`,
or `icmpx` in an `inet` table when the rule does not say the IP version).

### @@sec:client-view@@ What the client sees

| the firewall… | the client (`curl -m 5`, `nc -vz -w 5`) |
|--------------|----------------------------------------|
| accepts, and a service is listening | the connection opens |
| refuses (`reject`) | fails **immediately** (`nc`: `Connection refused`; `curl`: error 7) |
| drops (`drop`) | waits, then gives up after its timeout (`nc`: `timed out`; `curl`: error 28, `Connection timed out`) |
| accepts, but no service is listening | fails **immediately**, in the same way: the machine itself replies with a RST |

The difference therefore shows in the **delay**: an immediate refusal for `reject`, a long wait for
`drop`. Beware of the last case: seen from the client, nothing distinguishes a port that is
accepted but has no service from a `reject with tcp reset`. To know what a rule does, a service
must be listening on the port (section @@ref:testing@@).

### @@sec:which@@ Which one to choose?

`drop` reveals nothing, not even the existence of the machine, and costs nothing: it is the choice
facing the outside, and that of the default policy. `reject` saves legitimate users from waiting
and makes troubleshooting easier: it is readily used on the inside.
""",
    "Limiter le débit": "Limiting the rate",
    """
### @@sec:token-bucket@@ limit rate : le seau à jetons

`limit rate` se comporte comme un **critère** : il est satisfait tant que le rythme des paquets
qui atteignent la règle reste **sous** la limite. Au-delà, la règle ne s'applique plus et le
paquet **continue vers la règle suivante** (puis la politique).

```
tcp dport 22 ct state new limit rate 3/minute accept     # les nouvelles connexions SSH : 3 par minute
ip protocol icmp limit rate 1/second accept              # les pings : 1 par seconde
limit rate 5/minute log prefix "refus: "                 # le journal : 5 lignes par minute
```

C'est un **seau à jetons** : chaque paquet qui passe consomme un jeton ; le seau se remplit au
rythme indiqué et contient au plus la **réserve** (*burst*, 5 paquets par défaut). `limit rate
1/second` laisse donc passer 5 paquets d'un coup, puis un par seconde ; `limit rate 3/minute`,
5 d'un coup, puis un toutes les 20 secondes.

| règle | effet |
|-------|-------|
| `limit rate 10/second burst 20 packets accept` | fixe la réserve : 20 paquets d'un coup au plus, puis 10 par seconde |
| `limit rate over 10/second drop` | `over` inverse le test : la règle vaut pour les paquets **en trop** |
| `limit rate 1 mbytes/second accept` | un débit en octets (`bytes`, `kbytes`, `mbytes`) |

Les unités de temps sont `second`, `minute`, `hour` et `day`. Un piège classique : `limit rate
1/second drop` ne détruit qu'**un paquet par seconde** et laisse continuer tout le surplus ;
pour détruire ce qui dépasse, il faut `over`.

### @@sec:limit-place@@ La place de la règle

- combinée à `ct state new`, la limite porte sur les **ouvertures de connexion** (contre les
  attaques par force brute), sans gêner les connexions établies, acceptées plus haut par la
  règle à états ;
- placée **après** la règle à états, une limite ne voit de toute façon que le **premier paquet**
  de chaque connexion : les échos suivants d'un même `ping` (une seule « connexion » pour le
  suivi) sont acceptés avant elle. Elle limite donc le rythme des nouvelles connexions, pas le
  débit ;
- pour limiter **tous** les paquets d'un trafic, on place `limit rate over … drop` **avant** la
  règle à états.

### @@sec:limit-per-source@@ Une limite par adresse

Une limite écrite dans une règle est **globale**, toutes sources confondues : une seule machine
bruyante consomme les jetons de tout le monde. Pour compter **par adresse source**, on attache
la limite aux éléments d'un ensemble alimenté par la règle (section @@ref:dynamic-sets@@) :
chaque adresse y reçoit son propre seau.

```
table inet filter {
    set clients {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1m
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop
        tcp dport 22 accept
    }
}
```

La règle `update` détruit les ouvertures de connexion d'une adresse qui dépasse son rythme ; les
autres continuent vers la règle suivante, qui les accepte.

### @@sec:quotas@@ Connexions simultanées et quotas

**`ct count`** compte les connexions **simultanées**, et non un rythme : `tcp dport 22 ct count
10 accept` accepte tant qu'il n'y en a pas plus de 10, `ct count over 10` vaut au-delà. Par
adresse source, avec un ensemble déclaré `flags dynamic` :
`tcp dport 22 add @sessions { ip saddr ct count over 2 } reject` refuse la troisième connexion
ouverte en même temps par une même adresse.

Un **quota** compte un **volume** : `udp dport 5060 quota until 100 mbytes accept` accepte
jusqu'à 100 Mo, puis ne s'applique plus. Comme un compteur (section @@ref:counters@@), un quota
peut être un objet nommé de la table, que l'on relit et remet à zéro :

```
nft 'add quota inet filter invites { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "invites" drop'
nft list quota inet filter invites
```

Avec `over`, la règle ne vaut qu'une fois le volume dépassé : ici, l'adresse est coupée après
20 Mo.
""": """
### @@sec:token-bucket@@ limit rate: the token bucket

`limit rate` behaves like a **match**: it is satisfied as long as the rate of the packets that
reach the rule stays **below** the limit. Beyond it, the rule no longer applies and the packet
**carries on to the next rule** (then the policy).

```
tcp dport 22 ct state new limit rate 3/minute accept     # the new SSH connections: 3 per minute
ip protocol icmp limit rate 1/second accept              # the pings: 1 per second
limit rate 5/minute log prefix "refused: "               # the log: 5 lines per minute
```

It is a **token bucket**: each packet that goes through uses up a token; the bucket refills at the
given rate and holds at most the **burst** (5 packets by default). `limit rate 1/second`
therefore lets 5 packets through at once, then one per second; `limit rate 3/minute`, 5 at once,
then one every 20 seconds.

| rule | effect |
|-------|-------|
| `limit rate 10/second burst 20 packets accept` | sets the burst: 20 packets at once at most, then 10 per second |
| `limit rate over 10/second drop` | `over` inverts the test: the rule applies to the packets **in excess** |
| `limit rate 1 mbytes/second accept` | a rate in bytes (`bytes`, `kbytes`, `mbytes`) |

The time units are `second`, `minute`, `hour` and `day`. A classic trap: `limit rate 1/second
drop` drops only **one packet per second** and lets all the surplus carry on; to drop what
exceeds the limit, you need `over`.

### @@sec:limit-place@@ Where the rule goes

- combined with `ct state new`, the limit applies to the **connection openings** (against
  brute-force attacks), without hindering the established connections, accepted higher up by the
  stateful rule;
- placed **after** the stateful rule, a limit only sees the **first packet** of each connection
  anyway: the following echoes of the same `ping` (a single "connection" for the tracking) are
  accepted before it. It therefore limits the rate of new connections, not the throughput;
- to limit **all** the packets of a flow, put `limit rate over … drop` **before** the stateful
  rule.

### @@sec:limit-per-source@@ A limit per address

A limit written in a rule is **global**, all sources together: a single noisy machine uses up
everyone's tokens. To count **per source address**, the limit is attached to the elements of a set
fed by the rule (section @@ref:dynamic-sets@@): each address gets its own bucket there.

```
table inet filter {
    set clients {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1m
    }
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 ct state new update @clients { ip saddr limit rate over 3/minute } drop
        tcp dport 22 accept
    }
}
```

The `update` rule drops the connection openings of an address that exceeds its rate; the others
carry on to the next rule, which accepts them.

### @@sec:quotas@@ Concurrent connections and quotas

**`ct count`** counts **concurrent** connections, not a rate: `tcp dport 22 ct count 10 accept`
accepts as long as there are no more than 10 of them, `ct count over 10` applies beyond that. Per
source address, with a set declared `flags dynamic`:
`tcp dport 22 add @sessions { ip saddr ct count over 2 } reject` refuses the third connection
opened at the same time by one address.

A **quota** counts a **volume**: `udp dport 5060 quota until 100 mbytes accept` accepts up to
100 MB, then no longer applies. Like a counter (section @@ref:counters@@), a quota can be a named
object of the table, which can be read and reset:

```
nft 'add quota inet filter invites { over 20 mbytes }'
nft 'add rule inet filter input ip saddr 192.0.2.50 quota name "invites" drop'
nft list quota inet filter invites
```

With `over`, the rule only applies once the volume is exceeded: here, the address is cut off after
20 MB.
""",
    "Compter et journaliser": "Counting and logging",
    """
### @@sec:counters@@ Les compteurs

**`counter`** compte les paquets et les octets qui atteignent cet endroit de la règle ;
`nft list ruleset` l'affiche sous la forme `counter packets 12 bytes 1008`. C'est l'outil de
diagnostic de base : il dit si une règle sert, et laquelle a vu passer un paquet. Ce n'est pas
un verdict : `tcp dport 80 counter accept` compte puis accepte ; une règle `counter` sans
verdict compte et laisse continuer.

Les compteurs des règles se remettent à zéro avec `nft reset rules` (tout le jeu de règles),
`nft reset rules inet filter` (une table) ou `nft reset rules inet filter input` (une chaîne) :
la commande affiche les règles avec leurs compteurs, puis les remet à zéro ; ils repartent
aussi de zéro quand on remplace la règle ou que l'on recharge le fichier. On peut aussi
déclarer un **compteur nommé**, objet de la table que plusieurs règles alimentent et que l'on
relit ou remet à zéro séparément :

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 443 } counter name "web" accept'
nft list counters                 # les compteurs nommés
nft reset counters                # les affiche, puis les remet à zéro
```

### @@sec:log@@ La journalisation

**`log`** produit une ligne par paquet (interfaces, adresses, protocole, ports). Il existe sous
deux formes :

- `log prefix "liste noire: "` écrit dans le **journal du noyau**, que l'on lit sur une vraie
  machine avec `dmesg -w`, `journalctl -k -f` ou dans `/var/log/kern.log` ; `level` choisit la
  gravité du message (`log level info prefix "…"`). **Dans un conteneur, cette forme ne donne
  rien** : par défaut le noyau ne journalise ainsi que les paquets de la machine hôte (réglage
  `net.netfilter.nf_log_all_netns`), et son journal n'est pas lisible depuis un conteneur ;
- `log prefix "liste noire: " group 0` remet les paquets à **nflog** (ici au groupe 0), où un
  programme vient les lire : **`tcpdump -n -i nflog:0`**, ou le démon `ulogd`, qui les range
  dans un fichier. C'est la forme à utiliser dans ce TP : elle montre les paquets journalisés
  en direct, sur `srv` elle-même.

`log` n'est pas un verdict non plus : `ip saddr @liste_noire log prefix "liste noire: " group 0
drop` journalise **puis** détruit. Sans limite, une attaque ou une simple boucle de `ping`
remplit le journal : on place `limit rate 5/minute` **devant** `log`. Attention : un paquet
sans jeton quitte la règle, il n'en atteint donc pas non plus le verdict. On journalise dans
une règle et l'on détruit dans la suivante :

```
ip saddr @liste_noire limit rate 5/minute log prefix "liste noire: " group 0
ip saddr @liste_noire drop
```

Dans un shell, une règle qui contient des guillemets doit être protégée tout entière par des
apostrophes, sinon le shell les retire et `nft` ne comprend plus le préfixe :
`nft 'add rule inet filter input ip saddr @liste_noire log prefix "liste noire: " group 0 drop'`.
""": """
### @@sec:counters@@ Counters

**`counter`** counts the packets and the bytes that reach this place in the rule; `nft list
ruleset` shows it as `counter packets 12 bytes 1008`. It is the basic diagnostic tool: it tells
whether a rule is used, and which one saw a packet go by. It is not a verdict: `tcp dport 80
counter accept` counts then accepts; a `counter` rule without a verdict counts and lets the packet
carry on.

The counters of the rules are reset with `nft reset rules` (the whole ruleset),
`nft reset rules inet filter` (a table) or `nft reset rules inet filter input` (a chain): the
command shows the rules with their counters, then resets them; they also start again from zero
when the rule is replaced or the file reloaded. A **named counter** can also be declared, an
object of the table that several rules feed and that is read or reset separately:

```
nft add counter inet filter web
nft 'add rule inet filter input tcp dport { 80, 443 } counter name "web" accept'
nft list counters                 # the named counters
nft reset counters                # shows them, then resets them
```

### @@sec:log@@ Logging

**`log`** produces one line per packet (interfaces, addresses, protocol, ports). It comes in two
forms:

- `log prefix "blacklist: "` writes to the **kernel log**, read on a real machine with `dmesg -w`,
  `journalctl -k -f` or in `/var/log/kern.log`; `level` chooses the severity of the message
  (`log level info prefix "…"`). **In a container, this form gives nothing**: by default the
  kernel only logs this way the packets of the host machine (setting
  `net.netfilter.nf_log_all_netns`), and its log cannot be read from a container;
- `log prefix "blacklist: " group 0` hands the packets over to **nflog** (here to group 0), where a
  program comes to read them: **`tcpdump -n -i nflog:0`**, or the `ulogd` daemon, which stores
  them in a file. It is the form to use in this lab: it shows the logged packets live, on `srv`
  itself.

`log` is not a verdict either: `ip saddr @liste_noire log prefix "blacklist: " group 0 drop` logs
**then** drops. Without a limit, an attack or a mere `ping` loop fills the log: put
`limit rate 5/minute` **in front of** `log`. Beware: a packet without a token leaves the rule, so
it does not reach its verdict either. Log in one rule and drop in the next one:

```
ip saddr @liste_noire limit rate 5/minute log prefix "blacklist: " group 0
ip saddr @liste_noire drop
```

In a shell, a rule that contains quotes must be protected as a whole by single quotes, otherwise
the shell removes them and `nft` no longer understands the prefix:
`nft 'add rule inet filter input ip saddr @liste_noire log prefix "blacklist: " group 0 drop'`.
""",
    "Autres outils": "Other tools",
    """
### @@sec:trace@@ Suivre un paquet : la trace

Quand les compteurs ne suffisent pas, on **trace** un paquet règle par règle : une règle
`meta nftrace set 1`, placée en tête de chaîne, marque les paquets à suivre, et `nft monitor
trace` affiche leur parcours.

```
nft insert rule inet filter input ip saddr 192.0.2.13 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.13 … tcp dport 80 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.13 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 80 accept (verdict accept)
```

Chaque ligne commence par l'identifiant du paquet, la table et la chaîne ; les lignes `rule`
donnent les règles satisfaites et leur verdict, et un paquet qu'aucune règle n'arrête se
termine par la politique de la chaîne (`policy drop`). Supprimez la règle de trace quand vous
avez fini.

### @@sec:monitor@@ Surveiller et vérifier

| commande | usage |
|----------|-------|
| `nft monitor` | affiche en direct les modifications du jeu de règles : règles ajoutées, éléments qui entrent dans un ensemble ou en sortent |
| `nft -c -f fichier` | vérifie un fichier sans rien changer |
| `nft -c -o -f fichier` | propose des simplifications du jeu de règles, sans rien changer |
| `nft describe tcp dport` | donne le type d'un champ (à reprendre dans la déclaration d'un ensemble) et ses valeurs possibles |
| `nft -s list ruleset` | affiche le jeu de règles sans les valeurs des compteurs |
| `nft -j list ruleset` | l'affiche en JSON, pour un programme |

### @@sec:misc-tools@@ meta, fib, flowtables

- **`meta`** donne accès à ce qui entoure le paquet : `meta l4proto` (le protocole de transport,
  en IPv4 comme en IPv6), `meta iifname` / `meta oifname`, `meta mark` (une marque posée par une
  autre règle, `meta mark set 1`, pour le routage avancé ou la qualité de service), `meta skuid`
  (l'utilisateur du processus local qui émet, au hook `output`) ;
- **`fib`** interroge la table de routage : `fib saddr . iif oif missing drop`, au hook
  `prerouting`, détruit les paquets dont l'adresse source n'est pas joignable par l'interface
  d'arrivée (anti-usurpation, *reverse path filtering*) ;
- une **flowtable** accélère le routage des connexions établies, qui ne repassent plus par les
  chaînes : pour un routeur à très haut débit.
""": """
### @@sec:trace@@ Following a packet: tracing

When the counters are not enough, a packet is **traced** rule by rule: a rule
`meta nftrace set 1`, placed at the head of the chain, marks the packets to follow, and
`nft monitor trace` shows their path.

```
nft insert rule inet filter input ip saddr 192.0.2.13 meta nftrace set 1
nft monitor trace
```

```
trace id a95ea7ef inet filter input packet: iif "eth0" ip saddr 192.0.2.13 … tcp dport 80 …
trace id a95ea7ef inet filter input rule ip saddr 192.0.2.13 meta nftrace set 1 (verdict continue)
trace id a95ea7ef inet filter input rule tcp dport 80 accept (verdict accept)
```

Each line starts with the identifier of the packet, the table and the chain; the `rule` lines give
the matched rules and their verdict, and a packet that no rule stops ends with the policy of the
chain (`policy drop`). Delete the trace rule when you are done.

### @@sec:monitor@@ Monitoring and checking

| command | use |
|----------|-------|
| `nft monitor` | shows the changes of the ruleset live: rules added, elements entering or leaving a set |
| `nft -c -f file` | checks a file without changing anything |
| `nft -c -o -f file` | suggests simplifications of the ruleset, without changing anything |
| `nft describe tcp dport` | gives the type of a field (to be used in the declaration of a set) and its possible values |
| `nft -s list ruleset` | shows the ruleset without the values of the counters |
| `nft -j list ruleset` | shows it in JSON, for a program |

### @@sec:misc-tools@@ meta, fib, flowtables

- **`meta`** gives access to what surrounds the packet: `meta l4proto` (the transport protocol,
  in IPv4 as in IPv6), `meta iifname` / `meta oifname`, `meta mark` (a mark set by another rule,
  `meta mark set 1`, for advanced routing or quality of service), `meta skuid` (the user of the
  local process that sends, at the `output` hook);
- **`fib`** queries the routing table: `fib saddr . iif oif missing drop`, at the `prerouting`
  hook, drops the packets whose source address is not reachable through the interface they came
  in by (anti-spoofing, *reverse path filtering*);
- a **flowtable** speeds up the routing of established connections, which no longer go through
  the chains: for a very high-throughput router.
""",
    "Observer et tester": "Observing and testing",
    """
Un pare-feu se vérifie des deux côtés : ce qu'il **laisse passer** (ce qui doit marcher marche
encore) et ce qu'il **arrête** (ce qui doit être bloqué l'est vraiment).

### @@sec:test-ruleset@@ Ce que dit le jeu de règles

`nft list ruleset` (avec les compteurs), `nft -a list ruleset` (avec les *handles*),
`nft list set inet filter NOM` (le contenu d'un ensemble). Après chaque ajout, vérifiez
l'**ordre** des règles : c'est la première cause d'erreur.

### @@sec:test-client@@ Ce que voit un client

- `curl -m 3 http://ADRESSE:PORT/` pour un service HTTP, ou une simple connexion TCP avec
  `nc -vz -w 3 ADRESSE PORT`. Un succès : la règle accepte et un service écoute ; un échec
  **immédiat** (`Connection refused`) : un `reject`, ou un port accepté mais sans service ; une
  **attente** jusqu'au délai (`-m 3`, `-w 3`) : un `drop` ;
- **un service à l'écoute** : `ss -tlnp` liste les ports TCP en écoute. Pour tester une règle
  sur un port où rien n'écoute, lancez un service provisoire, par exemple
  `python3 -m http.server 8080` ;
- **plusieurs sources** : une liste noire ou une liste blanche ne se vérifie qu'en comparant
  ce que voient une machine listée et une machine qui ne l'est pas.

### @@sec:test-limit@@ Vérifier une limite

Avec la règle à états en tête, un `ping -c 10 -i 0.2 ADRESSE` ne montre rien : ses dix échos
forment une seule « connexion » pour le suivi, et seul le premier rencontre la limite
(section @@ref:limit-place@@). Il faut des essais **distincts** :

```
for i in $(seq 12); do ping -c 1 -W 1 ADRESSE >/dev/null && echo ok || echo perdu; done
```

Avec `limit rate 1/second`, les cinq premiers passent (la réserve du seau), puis un sur deux
environ. De même, plusieurs `nc -z -w 2 ADRESSE 22` rapprochés montrent la limite posée sur les
nouvelles connexions SSH.

### @@sec:test-capture@@ Sur le fil

`tcpdump` capture **au ras de l'interface**, à l'extérieur du pare-feu : en réception, il voit
les paquets **avant** tous les hooks (un paquet que le pare-feu détruit en `input` apparaît
quand même dans la capture) ; en émission, il les voit **après** tous les hooks.

- `tcpdump -n -i eth0 'tcp port 8080 or icmp'` sur le client montre le RST ou le message ICMP
  d'un `reject`, ou les SYN retransmis sans réponse d'un `drop` ;
- `tcpdump -n -i nflog:0` sur le pare-feu montre les paquets journalisés par `log … group 0`.

### @@sec:test-which-rule@@ Savoir quelle règle a tranché

Ajoutez `counter` aux règles et relisez `nft list ruleset` après un essai : la règle dont le
compteur a bougé est celle qui a vu le paquet. Si aucun compteur ne bouge, le paquet n'arrive
pas jusqu'à la chaîne, ou c'est la politique qui l'a détruit. La trace
(section @@ref:trace@@) donne le détail, règle par règle.
""": """
A firewall is checked from both sides: what it **lets through** (what must work still works) and
what it **stops** (what must be blocked really is).

### @@sec:test-ruleset@@ What the ruleset says

`nft list ruleset` (with the counters), `nft -a list ruleset` (with the *handles*),
`nft list set inet filter NAME` (the contents of a set). After each addition, check the **order**
of the rules: it is the first cause of errors.

### @@sec:test-client@@ What a client sees

- `curl -m 3 http://ADDRESS:PORT/` for an HTTP service, or a plain TCP connection with
  `nc -vz -w 3 ADDRESS PORT`. A success: the rule accepts and a service is listening; an
  **immediate** failure (`Connection refused`): a `reject`, or a port accepted but without a
  service; a **wait** until the timeout (`-m 3`, `-w 3`): a `drop`;
- **a listening service**: `ss -tlnp` lists the listening TCP ports. To test a rule on a port
  where nothing is listening, start a temporary service, for example
  `python3 -m http.server 8080`;
- **several sources**: a blacklist or a whitelist can only be checked by comparing what a listed
  machine and an unlisted machine see.

### @@sec:test-limit@@ Checking a limit

With the stateful rule at the head, a `ping -c 10 -i 0.2 ADDRESS` shows nothing: its ten echoes
form a single "connection" for the tracking, and only the first one meets the limit
(section @@ref:limit-place@@). You need **distinct** attempts:

```
for i in $(seq 12); do ping -c 1 -W 1 ADDRESS >/dev/null && echo ok || echo lost; done
```

With `limit rate 1/second`, the first five go through (the burst of the bucket), then roughly one
in two. Likewise, several `nc -z -w 2 ADDRESS 22` in quick succession show the limit set on the
new SSH connections.

### @@sec:test-capture@@ On the wire

`tcpdump` captures **right at the interface**, outside the firewall: on reception, it sees the
packets **before** all the hooks (a packet the firewall drops in `input` still appears in the
capture); on sending, it sees them **after** all the hooks.

- `tcpdump -n -i eth0 'tcp port 8080 or icmp'` on the client shows the RST or the ICMP message of
  a `reject`, or the SYNs of a `drop` retransmitted without a reply;
- `tcpdump -n -i nflog:0` on the firewall shows the packets logged by `log … group 0`.

### @@sec:test-which-rule@@ Finding out which rule decided

Add `counter` to the rules and read `nft list ruleset` again after an attempt: the rule whose
counter moved is the one that saw the packet. If no counter moves, the packet does not reach the
chain, or it is the policy that dropped it. Tracing (section @@ref:trace@@) gives the detail, rule
by rule.
""",
    "Bonnes pratiques et pièges": "Good practices and pitfalls",
    """
### @@sec:principles@@ Les principes

- **tout interdire, puis autoriser** : politique `drop` en `input`, la règle à états en
  premier, `lo`, puis une règle par service réellement offert ;
- **des ensembles plutôt que des listes de règles** : une règle et un ensemble nommé se lisent
  mieux, vont plus vite, et l'on change la liste sans toucher aux règles ;
- **restreindre par la source** ce qui n'a pas à être public (une liste blanche pour
  l'administration) ;
- **limiter** ce qui peut être abusé (ouvertures de connexion, `ping`, journal), par adresse
  quand un seul client ne doit pas pénaliser les autres ;
- **journaliser ce qui est détruit**, avec une limite, et compter ce qui est accepté : un
  pare-feu que l'on n'observe pas ne se corrige pas ;
- **un fichier, chargé d'un bloc** et vérifié d'abord avec `nft -c -f`, plutôt que des
  commandes tapées une à une.

### @@sec:pitfalls@@ Les pièges

- **l'ordre des règles** : la règle d'une liste noire placée après un `accept` qui couvre les
  mêmes paquets n'est jamais consultée ; une règle `reject` placée après un `drop` plus général
  non plus ;
- **une liste blanche sans règle qui accepte** : `ip saddr != @admins tcp dport 22 drop` seul
  ne laisse entrer personne sous une politique `drop` ;
- **un ensemble anonyme n'est pas un ensemble nommé** : `ip saddr { 192.0.2.13 } drop` bloque
  l'adresse, mais on ne peut plus changer la liste sans remplacer la règle ;
- **`limit` sans `over` devant `drop`** : `limit rate 1/second drop` ne détruit qu'un paquet par
  seconde ;
- **`limit` et `log` devant un verdict** : un paquet sans jeton n'atteint ni le `log` ni le
  verdict de la règle (section @@ref:log@@) ;
- **une action après le verdict** (`accept counter`) : `nft` la refuse, le verdict termine la
  règle ;
- **un port accepté sans service** répond par un RST, comme un `reject with tcp reset` : ne
  concluez rien d'un refus immédiat sans avoir vérifié qu'un service écoute (`ss -tlnp`) ;
- **le shell** : guillemets, accolades et points-virgules se protègent par des apostrophes ;
- **les règles volatiles** : ce qui n'est pas dans `/etc/nftables.conf` disparaît au
  redémarrage, le contenu des ensembles modifié à la main aussi.
""": """
### @@sec:principles@@ The principles

- **forbid everything, then allow**: a `drop` policy in `input`, the stateful rule first, `lo`,
  then one rule per service actually offered;
- **sets rather than lists of rules**: one rule and a named set read better, run faster, and the
  list can be changed without touching the rules;
- **restrict by source** what has no need to be public (a whitelist for administration);
- **limit** what can be abused (connection openings, `ping`, the log), per address when a single
  client must not penalise the others;
- **log what is dropped**, with a limit, and count what is accepted: a firewall that nobody
  observes does not get fixed;
- **one file, loaded in one go** and checked first with `nft -c -f`, rather than commands typed
  one by one.

### @@sec:pitfalls@@ The pitfalls

- **the order of the rules**: the rule of a blacklist placed after an `accept` that covers the
  same packets is never consulted; nor is a `reject` rule placed after a more general `drop`;
- **a whitelist without a rule that accepts**: `ip saddr != @admins tcp dport 22 drop` alone
  lets nobody in under a `drop` policy;
- **an anonymous set is not a named set**: `ip saddr { 192.0.2.13 } drop` blocks the address,
  but the list can no longer be changed without replacing the rule;
- **`limit` without `over` in front of `drop`**: `limit rate 1/second drop` drops only one packet
  per second;
- **`limit` and `log` in front of a verdict**: a packet without a token reaches neither the `log`
  nor the verdict of the rule (section @@ref:log@@);
- **an action after the verdict** (`accept counter`): `nft` refuses it, the verdict ends the
  rule;
- **a port accepted without a service** replies with a RST, like a `reject with tcp reset`: do not
  conclude anything from an immediate refusal without having checked that a service is listening
  (`ss -tlnp`);
- **the shell**: quotes, braces and semicolons are protected by single quotes;
- **volatile rules**: what is not in `/etc/nftables.conf` disappears at reboot, and so do the
  contents of the sets changed by hand.
""",
    "Aide-mémoire": "Cheat sheet",
    """
| besoin | commande ou règle |
|--------|-------------------|
| état | `nft list ruleset`, `nft -a list ruleset` (avec les *handles*), `nft list set inet filter NOM` |
| socle | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'`, `ct state established,related accept`, `iif lo accept` |
| ensemble nommé | `nft 'add set inet filter NOM { type ipv4_addr; }'`, `nft 'add element inet filter NOM { 192.0.2.13 }'`, `nft 'delete element inet filter NOM { 192.0.2.13 }'`, `nft flush set inet filter NOM` |
| utiliser un ensemble | `ip saddr @NOM drop` (liste noire), `ip saddr @NOM tcp dport 22 accept` (liste blanche) |
| options d'un ensemble | `flags interval` (réseaux, plages), `flags timeout` et `timeout 1h` (expiration), `flags dynamic` (alimenté par les règles : `add @NOM { ip saddr }`) |
| dictionnaire de verdicts | `tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }`, `tcp dport vmap @NOM` |
| refuser | `tcp dport 8080 reject with tcp reset`, `reject` (ICMP *port unreachable*), `drop` |
| limiter | `limit rate 3/minute`, `limit rate 10/second burst 20 packets`, `limit rate over 10/second drop`, `ct count over 10` |
| compter, journaliser | `counter`, `log prefix "texte: "`, `log prefix "texte: " group 0` puis `tcpdump -n -i nflog:0` |
| ordre des règles | `nft insert rule inet filter input …` (en tête), `nft insert rule inet filter input handle N …` (avant la règle N), `nft delete rule inet filter input handle N` |
| fichier de règles | `nft -c -f /etc/nftables.conf` (vérifier), `nft -f /etc/nftables.conf` (charger ; le fichier commence par `flush ruleset`) |
| tests | `curl -m 3 http://ADRESSE:PORT/`, `nc -vz -w 3 ADRESSE PORT`, `ping -c 1 -W 1 ADRESSE`, `ss -tlnp`, `tcpdump -n -i eth0 'tcp port 8080 or icmp'` |
| suivre un paquet | `… counter …` puis `nft list ruleset` ; `meta nftrace set 1` et `nft monitor trace` |
""": """
| need | command or rule |
|--------|-------------------|
| status | `nft list ruleset`, `nft -a list ruleset` (with the *handles*), `nft list set inet filter NAME` |
| base | `nft add table inet filter`, `nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'`, `ct state established,related accept`, `iif lo accept` |
| named set | `nft 'add set inet filter NAME { type ipv4_addr; }'`, `nft 'add element inet filter NAME { 192.0.2.13 }'`, `nft 'delete element inet filter NAME { 192.0.2.13 }'`, `nft flush set inet filter NAME` |
| using a set | `ip saddr @NAME drop` (blacklist), `ip saddr @NAME tcp dport 22 accept` (whitelist) |
| set options | `flags interval` (networks, ranges), `flags timeout` and `timeout 1h` (expiry), `flags dynamic` (fed by the rules: `add @NAME { ip saddr }`) |
| verdict map | `tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }`, `tcp dport vmap @NAME` |
| refusing | `tcp dport 8080 reject with tcp reset`, `reject` (ICMP *port unreachable*), `drop` |
| limiting | `limit rate 3/minute`, `limit rate 10/second burst 20 packets`, `limit rate over 10/second drop`, `ct count over 10` |
| counting, logging | `counter`, `log prefix "text: "`, `log prefix "text: " group 0` then `tcpdump -n -i nflog:0` |
| order of the rules | `nft insert rule inet filter input …` (at the head), `nft insert rule inet filter input handle N …` (before rule N), `nft delete rule inet filter input handle N` |
| rules file | `nft -c -f /etc/nftables.conf` (check), `nft -f /etc/nftables.conf` (load; the file starts with `flush ruleset`) |
| tests | `curl -m 3 http://ADDRESS:PORT/`, `nc -vz -w 3 ADDRESS PORT`, `ping -c 1 -W 1 ADDRESS`, `ss -tlnp`, `tcpdump -n -i eth0 'tcp port 8080 or icmp'` |
| following a packet | `… counter …` then `nft list ruleset`; `meta nftrace set 1` and `nft monitor trace` |
""",
    """
| machine | adresse | rôle |
|---------|---------|------|
| **`srv`** | `{srv}` | le serveur à protéger : **le pare-feu à configurer** |
| `admin` | `{admin}` | le poste de l'administrateur, seule source autorisée en SSH |
| `user` | `{user}` | un utilisateur ordinaire : accède au HTTP, pas au SSH |
| `bad` | `{bad}` | une machine indésirable, à mettre en liste noire |

Toutes les machines sont sur le même réseau local `net1` (`{net1}`).
""": """
| machine | address | role |
|---------|---------|------|
| **`srv`** | `{srv}` | the server to protect: **the firewall to configure** |
| `admin` | `{admin}` | the administrator's host, the only source allowed for SSH |
| `user` | `{user}` | an ordinary user: has access to HTTP, not to SSH |
| `bad` | `{bad}` | an unwanted machine, to be put on the blacklist |

All the machines are on the same local network `net1` (`{net1}`).
""",
    "Organisation du TP": "Lab organisation",
    """
Lisez l'onglet **Informations** : il rappelle le socle d'un pare-feu de machine (politique `drop`,
filtrage à états) et présente les ensembles nommés, les *maps*, `reject` et `drop`, la limitation
de débit, les compteurs, la journalisation et la façon de tester un jeu de règles.

**La maquette** (onglet *Schéma*) : un seul réseau local, `net1`, avec le serveur **`srv`** et
trois machines qui sont les trois sources de vos tests : **`admin`**, **`user`** et **`bad`**.
Vous configurez le pare-feu de **`srv`**, et de `srv` seulement, dans sa chaîne `input`.
""": """
Read the **Informations** tab: it reviews the base of a host firewall (`drop` policy, stateful
filtering) and presents named sets, *maps*, `reject` and `drop`, rate limiting, counters, logging
and how to test a ruleset.

**The topology** (*Schema* tab): a single local network, `net1`, with the server **`srv`** and
three machines that are the three sources of your tests: **`admin`**, **`user`** and **`bad`**.
You configure the firewall of **`srv`**, and of `srv` only, in its `input` chain.
""",
    """
**Les ports du TP**, tous en TCP sur `srv` : **{ssh}** (SSH, réservé à `admin`), **{http}** (HTTP,
ouvert à tous sauf à la liste noire), **{rej}** (à **rejeter**) et **{drp}** (à **détruire**).

**Déjà en place** (ne pas modifier) : les adresses. Le jeu de règles nftables de `srv` est vide au
départ : tout passe. Sur `srv`, un service écoute sur chacun des ports du TP : un serveur HTTP sur
le port {http} (`curl` affiche `SERVER=srv` et `CLIENT_IP=`, l'adresse du client) et, sur les ports
{ssh}, {rej} et {drp}, un petit service TCP qui envoie une ligne puis ferme la connexion (à tester
avec `nc`). Dans vos commandes, désignez les machines par leurs adresses (tableau ci-dessus).

**Le socle.** Tout le TP se fait sur `srv`, dans une chaîne `input` de politique `drop`, avec un
filtrage à états : commencez par là (section @@ref:base@@ des Informations), puis ajoutez les
règles des questions.

**Plan du TP** :

1. **liste noire** : un ensemble nommé `liste_noire` dont les membres (`bad`) voient tout leur
   trafic détruit, le HTTP restant ouvert aux autres machines ;
2. **liste blanche SSH** : un ensemble nommé `admins` dont les membres (`admin`) ont seuls accès au
   SSH ;
3. **`reject` ou `drop`** : le port {rej} rejeté, le port {drp} détruit ;
4. **limitation de débit, compteurs et journalisation**.

Règles valables pour tout le TP :

- la configuration d'une question terminée reste en place : l'évaluation vérifie le jeu de règles
  **final** de `srv`, avec les quatre questions à la fois ;
- l'**ordre des règles** compte (une règle qui accepte, placée avant celle de la liste noire,
  laisse passer `bad`) : relisez `nft list ruleset` après chaque ajout ;
- l'évaluation lit le jeu de règles **chargé** sur `srv` (`nft list ruleset`), pas un fichier :
  des règles tapées avec `nft` suffisent (elles sont volatiles), mais un fichier rechargé d'un bloc
  est plus sûr (méthode conseillée plus bas) ;
- ce jeu de règles est **recopié sur une machine cachée identique** à `srv` (même adresse), où des
  services écoutent sur les ports {ssh}, {http}, {rej} et {drp}, et que l'évaluation sonde par des
  connexions TCP depuis des copies cachées de `admin`, `user` et `bad` : `bad` ne doit pas
  atteindre le port {http} et `user` doit l'atteindre ; `admin` doit atteindre le port {ssh} et
  `user` non ; depuis `user`, le port {rej} doit être refusé immédiatement et le port {drp} rester
  sans réponse. Elle cherche aussi dans le jeu de règles un ensemble nommé, une limitation de
  débit (`limit`) et un compteur ou une journalisation (`counter`, `log`). Rien n'est acquis sans
  règle : une connexion qui doit aboutir ne compte que si la chaîne `input` a la politique `drop`,
  et une connexion qui doit échouer ne compte que si son témoin aboutit (`bad` bloqué alors que
  `user` atteint le port {http}, `user` sans SSH alors que `admin` l'a, port {drp} détruit alors
  que le port {http} reste ouvert à `user`). Seul compte ce que dit **le jeu de règles chargé sur
  `srv`**, pas l'état de ses services ni ce que vous faites sur les autres machines ;
- pour tester sans attendre, donnez un délai court à vos commandes : `curl -m 3 http://ADRESSE:PORT/`,
  `nc -vz -w 3 ADRESSE PORT` (section @@ref:testing@@ des Informations).
""": """
**The ports of the lab**, all TCP on `srv`: **{ssh}** (SSH, reserved for `admin`), **{http}** (HTTP,
open to all except the blacklist), **{rej}** (to be **rejected**) and **{drp}** (to be **dropped**).

**Already in place** (do not change): the addresses. The nftables ruleset of `srv` is empty at the
start: everything goes through. On `srv`, a service listens on each of the ports of the lab: an
HTTP server on port {http} (`curl` prints `SERVER=srv` and `CLIENT_IP=`, the address of the
client) and, on ports {ssh}, {rej} and {drp}, a small TCP service that sends one line then closes
the connection (to be tested with `nc`). In your commands, refer to the machines by their
addresses (table above).

**The base.** The whole lab is done on `srv`, in an `input` chain with a `drop` policy, with
stateful filtering: start there (section @@ref:base@@ of the Informations tab), then add the rules
of the questions.

**Outline of the lab**:

1. **blacklist**: a named set `liste_noire` whose members (`bad`) have all their traffic dropped,
   HTTP staying open to the other machines;
2. **SSH whitelist**: a named set `admins` whose members (`admin`) alone have access to SSH;
3. **`reject` or `drop`**: port {rej} rejected, port {drp} dropped;
4. **rate limiting, counters and logging**.

Rules for the whole lab:

- the configuration of a finished question stays in place: the evaluation checks the **final**
  ruleset of `srv`, with the four questions at once;
- the **order of the rules** matters (a rule that accepts, placed before the blacklist rule, lets
  `bad` through): read `nft list ruleset` again after each addition;
- the evaluation reads the ruleset **loaded** on `srv` (`nft list ruleset`), not a file: rules
  typed with `nft` are enough (they are volatile), but a file reloaded in one go is safer
  (recommended method below);
- this ruleset is **copied onto a hidden machine identical** to `srv` (same address), where
  services listen on ports {ssh}, {http}, {rej} and {drp}, and which the evaluation probes with TCP
  connections from hidden copies of `admin`, `user` and `bad`: `bad` must not reach port {http}
  and `user` must reach it; `admin` must reach port {ssh} and `user` must not; from `user`, port
  {rej} must be refused immediately and port {drp} must stay without a reply. It also looks in the
  ruleset for a named set, a rate limit (`limit`) and a counter or a log (`counter`, `log`).
  Nothing is earned without a rule: a connection that must succeed only counts if the `input`
  chain has the `drop` policy, and a connection that must fail only counts if its control
  succeeds (`bad` blocked while `user` reaches port {http}, `user` without SSH while `admin` has
  it, port {drp} dropped while port {http} stays open to `user`). Only what **the ruleset loaded on
  `srv`** says counts, not the state of its services nor what you do on the other machines;
- to test without waiting, give your commands a short timeout: `curl -m 3 http://ADDRESS:PORT/`,
  `nc -vz -w 3 ADDRESS PORT` (section @@ref:testing@@ of the Informations tab).
""",
    """
**Méthode conseillée : le pare-feu dans un fichier.** Plutôt que de taper les règles une à une,
écrivez le pare-feu de `srv` dans **`/etc/nftables.conf`**, complétez-le de question en question et
rechargez-le d'un bloc : plus de guillemets pour le shell, ni de handle à chercher pour placer une
règle (on l'écrit à sa place), et des commentaires (`#`) pour s'y retrouver. Le fichier existe
déjà : le paquet Debian y a mis un squelette, une table `inet filter` aux chaînes vides `input`,
`forward` et `output`. Remplacez-le par le socle de la section @@ref:nft-files@@ des Informations
(`flush ruleset` en tête, puis la table `inet filter` et sa chaîne `input`), puis ajoutez-y les
ensembles et les règles des questions. Après chaque modification (`nano /etc/nftables.conf`, ou
`vim`) :

```
nft -c -f /etc/nftables.conf      # vérifie sans rien changer ; aucun message : correct
nft -f /etc/nftables.conf         # remplace tout le jeu de règles par celui du fichier
nft -a list ruleset               # ce qui est réellement chargé (avec les handles)
```

- chaque erreur est signalée par le nom du fichier, les numéros de ligne et de colonne, et des
  `^^^` sous le mot fautif. Le chargement est atomique : en cas d'erreur, **rien** ne change et
  l'ancien jeu de règles reste en place ;
- **l'évaluation ne lit pas le fichier**, seulement le jeu de règles chargé sur `srv` : un fichier
  modifié mais pas rechargé ne compte pas, et aucun service ne le charge dans les machines du TP ;
- `flush ruleset` en tête : recharger le fichier remplace tout, sans doublon (aucune autre table
  n'est à garder sur `srv`). Cela remet aussi à zéro les compteurs (question 4) ;
- ce que vous changez en ligne de commande (`nft add element`, `nft insert rule`…) n'est pas dans
  le fichier : reportez-y **toute** modification, le prochain `nft -f` efface ce qu'il ne contient
  pas ;
- déjà commencé à la main ? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  transforme le jeu de règles en place en fichier.
""": """
**Recommended method: the firewall in a file.** Rather than typing the rules one by one, write the
firewall of `srv` in **`/etc/nftables.conf`**, complete it question after question and reload it in
one go: no more quotes for the shell, no handle to look up to place a rule (you write it where it
belongs), and comments (`#`) to find your way around. The file already exists: the Debian package
put a skeleton in it, an `inet filter` table with empty `input`, `forward` and `output` chains.
Replace it with the base of section @@ref:nft-files@@ of the Informations tab (`flush ruleset` at
the head, then the `inet filter` table and its `input` chain), then add the sets and the rules of
the questions to it. After each change (`nano /etc/nftables.conf`, or `vim`):

```
nft -c -f /etc/nftables.conf      # checks without changing anything; no message: correct
nft -f /etc/nftables.conf         # replaces the whole ruleset with that of the file
nft -a list ruleset               # what is really loaded (with the handles)
```

- each error is reported with the name of the file, the line and column numbers, and `^^^` under
  the faulty word. Loading is atomic: in case of error, **nothing** changes and the old ruleset
  stays in place;
- **the evaluation does not read the file**, only the ruleset loaded on `srv`: a file changed but
  not reloaded does not count, and no service loads it in the machines of the lab;
- `flush ruleset` at the head: reloading the file replaces everything, without duplicates (no other
  table needs to be kept on `srv`). It also resets the counters (question 4);
- what you change on the command line (`nft add element`, `nft insert rule`…) is not in the file:
  copy **every** change into it, the next `nft -f` erases what it does not contain;
- already started by hand? `{ echo 'flush ruleset'; nft -s list ruleset; } > /etc/nftables.conf`
  turns the current ruleset into a file.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution : il écrit
le fichier ci-dessous dans `/etc/nftables.conf` sur `srv` et le charge (`nft -f /etc/nftables.conf`) ;
il est ré-applicable. Ce TP n'a aucun formulaire à remplir.

```
{conf}```

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` et
`nft -j list ruleset` sur `srv` (étape 1) ; le premier est chargé tel quel sur `srv_h` après un
`nft flush ruleset` (étape 2 ; un jeu de règles vide laisse la copie sans filtre), le second donne
la politique de la chaîne `input` ; puis six connexions TCP par `bash` (`/dev/tcp`, délai 4 s :
`RC=0` ouvert, `RC=124` détruit, autre code refusé) à l'étape 3 : `bad_h` et `user_h` vers le port
{http}, `admin_h` et `user_h` vers le port {ssh}, `user_h` vers les ports {rej} et {drp}. Sur `srv_h`
comme sur `srv`, un service écoute sur chacun des quatre ports (un serveur HTTP sur le port {http},
un petit serveur TCP sur les autres ; ceux de `srv` servent aux vérifications à la main et ne sont
pas évalués).

Barème : 14 points, dont 3 pour la seule présence de mots dans le jeu de règles (`set ` ou `@`,
`limit`, `counter` ou `log`). Aucun point sans règle : les connexions qui doivent aboutir
(`blacklist_user_ok`, `whitelist_admin_ssh`) ne comptent qu'avec la politique `drop` sur la chaîne
`input`, celles qui doivent échouer (`blacklist_bad_bloque`, `whitelist_user_ssh_bloque`,
`port_drop`) que si leur témoin aboutit. Un jeu de règles vide vaut 0, une politique `drop` seule
aussi.
""": """
**For the instructor.** Each question ends with its solution, computed for the addresses of this
project. The `final` state (*Apply Configuration* tab) applies the whole solution: it writes the
file below to `/etc/nftables.conf` on `srv` and loads it (`nft -f /etc/nftables.conf`); it can be
applied again. This lab has no form to fill in.

```
{conf}```

The evaluation (hidden mirror, `lib/hidden_mirror.py` / `lib/firewall.py`): `nft list ruleset` and
`nft -j list ruleset` on `srv` (step 1); the first one is loaded as is on `srv_h` after an
`nft flush ruleset` (step 2; an empty ruleset leaves the copy without a filter), the second one
gives the policy of the `input` chain; then six TCP connections by `bash` (`/dev/tcp`, timeout 4 s:
`RC=0` open, `RC=124` dropped, any other code refused) at step 3: `bad_h` and `user_h` to port
{http}, `admin_h` and `user_h` to port {ssh}, `user_h` to ports {rej} and {drp}. On `srv_h` as on
`srv`, a service listens on each of the four ports (an HTTP server on port {http}, a small TCP
server on the others; those of `srv` are for the checks by hand and are not graded).

Marking scheme: 14 points, 3 of them for the mere presence of words in the ruleset (`set ` or `@`,
`limit`, `counter` or `log`). No point without a rule: the connections that must succeed
(`blacklist_user_ok`, `whitelist_admin_ssh`) only count with the `drop` policy on the `input`
chain, those that must fail (`blacklist_bad_bloque`, `whitelist_user_ssh_bloque`, `port_drop`) only
if their control succeeds. An empty ruleset is worth 0, and so is a `drop` policy alone.
""",
    "Liste noire (ensemble nommé)": "Blacklist (named set)",
    """
Créez un **ensemble nommé** `liste_noire` (`type ipv4_addr`) contenant l'adresse
de **`bad`** ({_arg0}) et **détruisez** tout trafic provenant de ses membres. Les
autres machines gardent un accès HTTP (port {_arg1}) normal à `srv`.
""": """
Create a **named set** `liste_noire` (`type ipv4_addr`) containing the address
of **`bad`** ({_arg0}) and **drop** all the traffic coming from its members. The
other machines keep normal HTTP access (port {_arg1}) to `srv`.
""",
    """
**Solution.** Sur `srv`, dans `/etc/nftables.conf` : le socle (politique `drop`, règle à états,
`lo`), l'ensemble nommé et sa règle, placée **avant** toute règle qui accepte, puis l'ouverture du
HTTP :

```
{conf}```

à charger par `nft -f /etc/nftables.conf`. Le `log` de la règle est celui de la question 4 :
`ip saddr @liste_noire drop` suffit ici. À chaud, en ligne de commande, une fois le socle en
place : `nft 'add set inet filter liste_noire {{ type ipv4_addr; }}'`,
`nft 'add element inet filter liste_noire {{ {bad} }}'`,
`nft add rule inet filter input ip saddr @liste_noire drop` puis
`nft add rule inet filter input tcp dport {http} accept`.

Vérification : depuis `bad`, `curl -m 3 http://{srv}/` attend 3 secondes sans réponse, et
`ping {srv}` n'obtient rien ; depuis `user` et `admin`, le même `curl` affiche `SERVER=srv` et
l'adresse du client. `nft list set inet filter liste_noire` affiche
l'ensemble ; `nft 'add element inet filter liste_noire {{ {user} }}'` bloque aussitôt `user`, sans
recharger les règles, et `nft 'delete element inet filter liste_noire {{ {user} }}'` le débloque.

Pièges : la règle de la liste noire placée **après** `tcp dport {http} accept` (jamais atteinte par
le HTTP de `bad`) ; un ensemble anonyme (`ip saddr {{ {bad} }} drop`), qui bloque `bad` mais n'est
pas un ensemble nommé ; placée après `ct state established,related accept`, la règle laisse vivre
une connexion que `bad` aurait ouverte avant d'être listée (sans effet sur l'évaluation, qui
n'ouvre que des connexions nouvelles).

Évaluation : `blacklist_bad_bloque` (2 points : depuis la copie cachée de `bad`, une connexion TCP
vers `{srv}:{http}` doit échouer **et** celle de la copie de `user` aboutir), `blacklist_user_ok`
(1 point : depuis la copie de `user`, elle doit aboutir, la chaîne `input` de `srv` ayant la
politique `drop`) et `ensembles_nommes` (1 point : le texte de `nft list ruleset` de `srv` contient
`set ` ou `@`).
""": """
**Solution.** On `srv`, in `/etc/nftables.conf`: the base (`drop` policy, stateful rule, `lo`), the
named set and its rule, placed **before** any rule that accepts, then the opening of HTTP:

```
{conf}```

to be loaded with `nft -f /etc/nftables.conf`. The `log` of the rule is that of question 4:
`ip saddr @liste_noire drop` is enough here. Live, on the command line, once the base is in
place: `nft 'add set inet filter liste_noire {{ type ipv4_addr; }}'`,
`nft 'add element inet filter liste_noire {{ {bad} }}'`,
`nft add rule inet filter input ip saddr @liste_noire drop` then
`nft add rule inet filter input tcp dport {http} accept`.

Check: from `bad`, `curl -m 3 http://{srv}/` waits 3 seconds without a reply, and `ping {srv}`
gets nothing; from `user` and `admin`, the same `curl` prints `SERVER=srv` and the address of the
client. `nft list set inet filter liste_noire` shows the set;
`nft 'add element inet filter liste_noire {{ {user} }}'` blocks `user` at once, without reloading
the rules, and `nft 'delete element inet filter liste_noire {{ {user} }}'` unblocks it.

Pitfalls: the blacklist rule placed **after** `tcp dport {http} accept` (never reached by the HTTP
of `bad`); an anonymous set (`ip saddr {{ {bad} }} drop`), which blocks `bad` but is not a named
set; placed after `ct state established,related accept`, the rule leaves alive a connection that
`bad` opened before being listed (no effect on the evaluation, which only opens new
connections).

Evaluation: `blacklist_bad_bloque` (2 points: from the hidden copy of `bad`, a TCP connection to
`{srv}:{http}` must fail **and** that of the copy of `user` must succeed), `blacklist_user_ok`
(1 point: from the copy of `user`, it must succeed, the `input` chain of `srv` having the `drop`
policy) and `ensembles_nommes` (1 point: the text of `nft list ruleset` of `srv` contains `set `
or `@`).
""",
    "Liste blanche SSH (ensemble nommé)": "SSH whitelist (named set)",
    """
Créez un ensemble nommé `admins` contenant l'adresse de **`admin`** ({_arg0}) et
n'autorisez le **SSH** (port {_arg1}) que depuis les membres de cet ensemble. Le
SSH depuis `user` doit être refusé.
""": """
Create a named set `admins` containing the address of **`admin`** ({_arg0}) and
allow **SSH** (port {_arg1}) only from the members of this set. SSH from `user`
must be refused.
""",
    """
**Solution.** L'ensemble `admins` et la règle qui n'ouvre le SSH qu'à ses membres (`…` : les
autres règles ; le fichier complet est dans *Organisation du TP*) :

```
{conf}```

`limit rate 3/minute` et `counter` sont ceux de la question 4 :
`ip saddr @admins tcp dport {ssh} accept` suffit ici. Aucune règle pour les autres sources : leur
SSH tombe dans la politique `drop`. En ligne de commande :
`nft 'add set inet filter admins {{ type ipv4_addr; }}'`,
`nft 'add element inet filter admins {{ {admin} }}'` puis
`nft add rule inet filter input ip saddr @admins tcp dport {ssh} accept`.

Vérification : `nc -vz -w 3 {srv} {ssh}` réussit depuis `admin` et attend 3 secondes sans réponse
depuis `user` ;
`nft 'add element inet filter admins {{ {user} }}'` ouvre le SSH à `user` sans toucher aux règles.
Avec la limite de la règle de référence, au-delà de cinq connexions rapprochées (la réserve par
défaut), les suivantes depuis `admin` restent elles aussi sans réponse : une nouvelle connexion
toutes les 20 secondes.

Pièges : `tcp dport {ssh} accept` sans `ip saddr @admins` (ouvert à tous) ;
`ip saddr != @admins tcp dport {ssh} drop` seul, sans règle qui accepte (le SSH de `admin` tombe
alors dans la politique) ; la règle placée après un `tcp dport {ssh} drop`.

Évaluation : `whitelist_admin_ssh` (2 points : depuis la copie cachée de `admin`, une connexion TCP
vers `{srv}:{ssh}` doit aboutir, la chaîne `input` de `srv` ayant la politique `drop`) et
`whitelist_user_ssh_bloque` (2 points : depuis la copie de `user`, elle doit échouer, par `drop`
comme par `reject`, **et** celle de la copie de `admin` aboutir).
""": """
**Solution.** The `admins` set and the rule that opens SSH only to its members (`…`: the other
rules; the complete file is in *Lab organisation*):

```
{conf}```

`limit rate 3/minute` and `counter` are those of question 4:
`ip saddr @admins tcp dport {ssh} accept` is enough here. No rule for the other sources: their SSH
falls into the `drop` policy. On the command line:
`nft 'add set inet filter admins {{ type ipv4_addr; }}'`,
`nft 'add element inet filter admins {{ {admin} }}'` then
`nft add rule inet filter input ip saddr @admins tcp dport {ssh} accept`.

Check: `nc -vz -w 3 {srv} {ssh}` succeeds from `admin` and waits 3 seconds without a reply from
`user`; `nft 'add element inet filter admins {{ {user} }}'` opens SSH to `user` without touching
the rules. With the limit of the reference rule, beyond five connections in quick succession (the
default burst), the following ones from `admin` also stay without a reply: one new connection
every 20 seconds.

Pitfalls: `tcp dport {ssh} accept` without `ip saddr @admins` (open to all);
`ip saddr != @admins tcp dport {ssh} drop` alone, without a rule that accepts (the SSH of `admin`
then falls into the policy); the rule placed after a `tcp dport {ssh} drop`.

Evaluation: `whitelist_admin_ssh` (2 points: from the hidden copy of `admin`, a TCP connection to
`{srv}:{ssh}` must succeed, the `input` chain of `srv` having the `drop` policy) and
`whitelist_user_ssh_bloque` (2 points: from the copy of `user`, it must fail, by `drop` as well as
by `reject`, **and** that of the copy of `admin` must succeed).
""",
    "reject vs drop": "reject vs drop",
    """
Faites en sorte que :

- le port **{_arg0}** soit **rejeté** (`reject`) — le client reçoit un refus immédiat ;
- le port **{_arg1}** soit **détruit** (`drop`) — le client n'obtient aucune réponse
  (délai d'attente).
""": """
Make sure that:

- port **{_arg0}** is **rejected** (`reject`) — the client gets an immediate refusal;
- port **{_arg1}** is **dropped** (`drop`) — the client gets no reply
  (timeout).
""",
    """
**Solution.** Deux règles de la chaîne `input` de `srv` (`…` : les autres règles) :

```
{conf}```

`reject with tcp reset` répond au SYN par un RST, comme le ferait un port fermé ; un simple
`reject` (message ICMP *port unreachable*) convient aussi : dans les deux cas le client échoue
immédiatement. La règle `drop` est explicite : sans elle, le port {drp} serait détruit de la même
façon par la politique. En ligne de commande :
`nft add rule inet filter input tcp dport {rej} reject with tcp reset` et
`nft add rule inet filter input tcp dport {drp} drop`.

Vérification : depuis `user`, `curl -m 5 http://{srv}:{rej}/` échoue **aussitôt**
(`Connection refused`) et `curl -m 5 http://{srv}:{drp}/` attend les 5 secondes. Sur `user`,
`tcpdump -n -i eth0 'tcp port {rej} or tcp port {drp}'` montre le RST (`Flags [R.]`) qui répond au
SYN vers le port {rej}, et le SYN vers le port {drp} retransmis sans réponse. Sans aucune règle,
les deux ports répondent : un service écoute sur chacun.

Pièges : les deux règles placées après un `accept` qui couvre ces ports ; la règle `reject` placée
après un `drop` plus général.

Évaluation : `port_reject` (2 points : depuis la copie cachée de `user`, la connexion TCP vers
`{srv}:{rej}` doit être refusée immédiatement) et `port_drop` (2 points : vers `{srv}:{drp}`, elle
doit rester sans réponse pendant 4 s **et** le port {http} rester ouvert à la copie de `user` : une
politique `drop` sans aucune règle ne rapporte rien). Les deux ports sont servis sur la copie : sans
règle, ils seraient ouverts.
""": """
**Solution.** Two rules of the `input` chain of `srv` (`…`: the other rules):

```
{conf}```

`reject with tcp reset` answers the SYN with a RST, as a closed port would; a plain `reject` (ICMP
*port unreachable* message) also works: in both cases the client fails immediately. The `drop`
rule is explicit: without it, port {drp} would be dropped in the same way by the policy. On the
command line: `nft add rule inet filter input tcp dport {rej} reject with tcp reset` and
`nft add rule inet filter input tcp dport {drp} drop`.

Check: from `user`, `curl -m 5 http://{srv}:{rej}/` fails **at once** (`Connection refused`) and
`curl -m 5 http://{srv}:{drp}/` waits the full 5 seconds. On `user`,
`tcpdump -n -i eth0 'tcp port {rej} or tcp port {drp}'` shows the RST (`Flags [R.]`) that answers
the SYN to port {rej}, and the SYN to port {drp} retransmitted without a reply. Without any rule,
both ports answer: a service listens on each of them.

Pitfalls: both rules placed after an `accept` that covers these ports; the `reject` rule placed
after a more general `drop`.

Evaluation: `port_reject` (2 points: from the hidden copy of `user`, the TCP connection to
`{srv}:{rej}` must be refused immediately) and `port_drop` (2 points: to `{srv}:{drp}`, it must
stay without a reply for 4 s **and** port {http} must stay open to the copy of `user`: a `drop`
policy without any rule earns nothing). Both ports are served on the copy: without a rule, they
would be open.
""",
    "Limitation de débit, compteurs et journalisation": "Rate limiting, counters and logging",
    """
Ajoutez :

- une **limitation de débit** (`limit rate`) — par exemple sur les nouvelles
  connexions SSH ou sur l'ICMP ;
- au moins un **compteur** (`counter`) et une règle de **journalisation** (`log`).
""": """
Add:

- a **rate limit** (`limit rate`) — for example on the new SSH
  connections or on ICMP;
- at least one **counter** (`counter`) and one **logging** rule (`log`).
""",
    """
**Solution.** Dans le jeu de règles de référence, ces fonctions sont portées par les règles des
questions 1 et 2 et par une règle pour l'ICMP (`…` : les autres règles) :

```
{conf}```

- **limitation de débit** : `limit rate 1/second` sur l'ICMP (au-delà, les paquets tombent dans la
  politique `drop`) et `limit rate 3/minute` sur les **nouvelles** connexions SSH des membres de
  `admins` (`ct state new` ; les connexions établies passent par la règle à états) ;
- **compteurs** : `counter` sur les règles du SSH et du HTTP ;
- **journalisation** : `log prefix "blacklist: " group 0` sur la règle de la liste noire.

Vérification : un même `ping` est un seul flux pour le suivi de connexion et seul son premier écho
rencontre la limite (les suivants sont acceptés par la règle à états) : `ping -c 10 -i 0.2 {srv}`
reçoit ses dix réponses. La limite se voit avec des flux distincts : depuis `user`,
`for i in $(seq 12); do ping -c 1 -W 1 {srv} >/dev/null && echo ok || echo perdu; done` affiche cinq
`ok` (la réserve par défaut du seau à jetons), puis un écho sur deux est perdu. De même, depuis
`admin`, cinq connexions SSH rapprochées (`nc -z -w 2 {srv} 22`) aboutissent et les suivantes
restent sans réponse. `nft list ruleset` affiche `counter packets … bytes …` sur les règles du SSH
et du HTTP. Le journal
du noyau n'est pas lisible dans un conteneur (`dmesg` : *Operation not permitted*), d'où
`group 0` : `tcpdump -n -i nflog:0` sur `srv` montre les paquets journalisés pendant que `bad`
tente une connexion.

Pièges : une instruction placée après le verdict (`accept limit rate …`), que `nft` refuse ;
`limit rate 1/second drop`, qui ne détruit qu'au rythme de la limite et laisse le surplus
continuer ; un `log` sans verdict, qui journalise mais ne décide rien ; tapée dans un shell, une
règle qui contient `log prefix "…"` doit être entre apostrophes.

Évaluation : `limitation_debit` (1 point : le texte de `nft list ruleset` de `srv` contient
`limit`) et `compteur_ou_log` (1 point : il contient `counter` ou `log`). Seule la présence des
mots est vérifiée, pas le comportement.
""": """
**Solution.** In the reference ruleset, these features are carried by the rules of questions 1 and
2 and by a rule for ICMP (`…`: the other rules):

```
{conf}```

- **rate limiting**: `limit rate 1/second` on ICMP (beyond it, the packets fall into the `drop`
  policy) and `limit rate 3/minute` on the **new** SSH connections of the members of `admins`
  (`ct state new`; the established connections go through the stateful rule);
- **counters**: `counter` on the SSH and HTTP rules;
- **logging**: `log prefix "blacklist: " group 0` on the blacklist rule.

Check: a single `ping` is one flow for connection tracking and only its first echo meets the limit
(the following ones are accepted by the stateful rule): `ping -c 10 -i 0.2 {srv}` gets its ten
replies. The limit shows with distinct flows: from `user`,
`for i in $(seq 12); do ping -c 1 -W 1 {srv} >/dev/null && echo ok || echo lost; done` prints five
`ok` (the default burst of the token bucket), then one echo in two is lost. Likewise, from
`admin`, five SSH connections in quick succession (`nc -z -w 2 {srv} 22`) succeed and the
following ones stay without a reply. `nft list ruleset` shows `counter packets … bytes …` on the
SSH and HTTP rules. The kernel log cannot be read in a container (`dmesg`: *Operation not
permitted*), hence `group 0`: `tcpdump -n -i nflog:0` on `srv` shows the logged packets while `bad`
attempts a connection.

Pitfalls: a statement placed after the verdict (`accept limit rate …`), which `nft` refuses;
`limit rate 1/second drop`, which only drops at the rate of the limit and lets the surplus carry
on; a `log` without a verdict, which logs but decides nothing; typed in a shell, a rule that
contains `log prefix "…"` must be between single quotes.

Evaluation: `limitation_debit` (1 point: the text of `nft list ruleset` of `srv` contains
`limit`) and `compteur_ou_log` (1 point: it contains `counter` or `log`). Only the presence of the
words is checked, not the behaviour.
""",
    "Liste noire : `bad` est bloqué (HTTP) alors que `user` passe": "Blacklist: `bad` is blocked (HTTP) while `user` gets through",
    "`user` (hors liste noire) accède au HTTP, sous une politique drop": "`user` (not on the blacklist) reaches HTTP, under a drop policy",
    "Liste blanche : SSH autorisé depuis `admin`, sous une politique drop": "Whitelist: SSH allowed from `admin`, under a drop policy",
    "SSH refusé depuis `user` (hors liste blanche) alors que `admin` passe": "SSH refused from `user` (not on the whitelist) while `admin` gets through",
    "Port {_arg0} : reject (refus immédiat)": "Port {_arg0}: reject (immediate refusal)",
    "Port {_arg0} : drop (silencieux) alors que le HTTP reste ouvert": "Port {_arg0}: drop (silent) while HTTP stays open",
    "Utilisation d'ensembles nommés (set / @)": "Use of named sets (set / @)",
    "Présence d'une limitation de débit (limit rate)": "Presence of a rate limit (limit rate)",
    "Présence d'un counter et/ou d'un log": "Presence of a counter and/or a log",
}}
