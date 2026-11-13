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

title = no_tr("nftables — aspects avancés (sets, limit, reject) (misc)")
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

Les machines du TP ont nftables 1.0.6 (`nft --version`), la version de Debian 12 : c'est elle que
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

Le compteur d'une règle ne se remet pas à zéro avec la version de `nft` des machines du TP : il
repart de zéro quand on remplace la règle ou que l'on recharge le fichier (`nft reset rules`
n'existe qu'à partir de nftables 1.0.7). On peut en revanche déclarer un **compteur nommé**,
objet de la table que plusieurs règles alimentent et que l'on relit ou remet à zéro
séparément :

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
- l'évaluation lit le jeu de règles **chargé** sur `srv` (`nft list ruleset`), pas un fichier : des
  règles tapées avec `nft` suffisent (elles sont volatiles) ; si vous écrivez `/etc/nftables.conf`,
  chargez-le (`nft -f /etc/nftables.conf`) ;
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


_TRANSLATIONS = {}
