"""nftables-nat — Traduction d'adresses : SNAT, DNAT, répartition de charge, proxy.

Projet NAT : l'étudiant configure sur le routeur `fw` une table `nat` réalisant
- **SNAT / masquerade** : le LAN privé sort vers le « WAN » sous l'adresse de `fw` ;
- **DNAT / redirection de port** : WAN:8080 → serveur interne `web1`:80 ;
- **répartition de charge L4** (nft `numgen`) : WAN:80 → { `web1`, `web2` } ;
- **proxy transparent** (`redirect`) : le HTTP sortant du LAN est intercepté par le
  proxy local de `fw` (port 3128).

Évaluation par « miroir caché » : le ruleset de `fw` est transplanté sur `fw_h`,
et des serveurs HTTP contrôlés (qui renvoient SERVER_IP / CLIENT_IP) permettent
d'*observer* directement l'effet des traductions.
"""

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict, List

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from SRE.lib_sre import info_subtitle, info_toc, instructor
from ips import random_ipv4networks, random_ips_from_topology
from net_config import set_net_config_entry, set_ip_forward, get_net_config_from_topology
import firewall
import hidden_mirror

default_language = "fr"
tr = make_tr(default_language)

title = no_tr("nftables — NAT, répartition de charge et proxy (nat)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60
eval_before_exit = True

PROXY_PORT = 3128     # proxy transparent local sur fw
FWD_PORT = 8080       # WAN:8080 -> web1:80 (redirection de port)
VIP_PORT = 80         # WAN:80  -> web1/web2 (répartition de charge)
NET_SVC_PORT = 9000   # service « Internet » sur ext (pour observer le SNAT)

# The table of the reference solution and its two base chains (name -> declaration): the text
# loaded by `final` and quoted in the instructor's solutions.
NAT_TABLE = "ip nat"
NAT_CHAINS = {
    "prerouting": "type nat hook prerouting priority dstnat; policy accept;",
    "postrouting": "type nat hook postrouting priority srcnat; policy accept;",
}

_TOPOLOGY = {
    "net1": {"fw": 0, "cli": 0, "web1": 0, "web2": 0},   # LAN privé
    "net2": {"fw": 1, "ext": 0},                         # WAN / « Internet »
}
_SPECS = {
    "fw": {"color": "salmon"},
    "cli": {},
    "web1": {"color": "lightgreen"},
    "web2": {"color": "lightgreen"},
    "ext": {"color": "lightgrey"},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS)


def render_table(chains: Dict[str, List[str]]) -> str:
    """The ``table ip nat { ... }`` block of an nftables file holding the given rules
    (``{chain name: [rule, ...]}``, the chains being those of ``NAT_CHAINS``)."""
    lines = [f"table {NAT_TABLE} {{"]
    for name, rules in chains.items():
        lines += [f"    chain {name} {{", f"        {NAT_CHAINS[name]}"]
        lines += [f"        {rule}" for rule in rules]
        lines.append("    }")
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
        data.nets.net1, data.nets.net2 = random_ipv4networks(
            masks=[24, 24],
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
        self.routers = hidden_mirror.router_machines(self._topology)  # fw, fw_h

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("La traduction d'adresses"), tag="nat")
            + tr("""
La **traduction d'adresses** (NAT, *Network Address Translation*) consiste, pour un routeur, à
**réécrire les adresses IP**, et souvent les ports, des paquets qui le traversent.

### @@sec:why@@ Pourquoi traduire

Le NAT est né de la pénurie d'adresses IPv4. Les réseaux internes utilisent des adresses
**privées** (RFC 1918 : `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), que chacun peut
réutiliser chez soi parce qu'elles ne sont pas routées sur Internet. Une machine qui n'a qu'une
adresse privée ne peut donc pas recevoir de réponse d'Internet : le routeur de sortie doit
substituer à son adresse une adresse **publique**, la sienne. La traduction sert aussi à
**publier** un serveur interne derrière l'adresse publique du routeur, à **répartir** des
connexions entre plusieurs serveurs et à **détourner** un trafic vers un mandataire (*proxy*).

### @@sec:vocabulary@@ Le vocabulaire

| terme | ce qui est réécrit | usage |
|-------|--------------------|-------|
| SNAT (*source NAT*) | l'adresse **source**, et au besoin le port source | faire sortir un réseau privé derrière une adresse publique fixe |
| *masquerade* | l'adresse source, remplacée par celle de l'interface de sortie | la même chose, quand l'adresse publique n'est pas connue d'avance |
| DNAT (*destination NAT*) | l'adresse de **destination**, et éventuellement le port | publier un serveur interne, répartir la charge |
| redirection de port (*port forwarding*) | la destination d'une connexion qui vise un port du routeur | « le port 8080 du routeur mène au port 80 du serveur interne » |
| *redirect* | la destination, remplacée par la machine elle-même | remettre un trafic à un proxy local (proxy transparent) |

Quand plusieurs machines sortent derrière **une seule** adresse, le routeur doit parfois changer
aussi le **port source** pour distinguer leurs connexions : on parle de NAPT, ou de PAT (*port
address translation*). C'est ce que fait une box d'accès à Internet.

### @@sec:not-a-firewall@@ Ce que le NAT n'est pas

Le NAT n'est **pas un pare-feu** : il traduit, il ne filtre pas. Un réseau privé n'est
injoignable de l'extérieur que parce que ses adresses n'y sont pas routées ; la vraie protection
est le filtrage (chaîne `forward`, section @@ref:nat-filter@@). Le NAT a aussi un coût : le
serveur ne voit plus la véritable adresse du client, et les protocoles qui transportent des
adresses dans leurs données (FTP, SIP) ne fonctionnent qu'avec des modules d'assistance du noyau
(*helpers*).

**Comment lire ce cours.** La section @@ref:basics@@ résume nftables (hooks, tables, chaînes,
règles, commande `nft`) : parcourez-la si le filtrage avec nftables vous est familier, lisez-la
sinon. Les questions du TP s'appuient sur les sections @@ref:conntrack@@ et @@ref:chains@@
(toutes), @@ref:snat@@ (question 1), @@ref:dnat@@ (question 2), @@ref:load-balancing@@
(question 3), @@ref:redirect@@ (question 4) et @@ref:observe@@ (pour vérifier chaque
traduction). Le reste (traduction et filtrage, sortie du routeur lui-même, *hairpin*, bonnes
pratiques) complète le tableau pour de vrais routeurs.
""")
            + info_subtitle(tr("nftables en bref"), tag="basics")
            + tr("""
Sous Linux, la traduction d'adresses est faite **dans le noyau** par Netfilter, comme le
filtrage, et se configure avec la même commande, **`nft`** (nftables). Cette section résume ce
qu'il faut savoir de nftables pour ce TP. Les machines du TP ont nftables 1.0.6
(`nft --version`), la version de Debian 12.

### @@sec:hooks@@ Le trajet d'un paquet : les hooks

Un **hook** (point d'accrochage) est un endroit du trajet d'un paquet dans le noyau où Netfilter
appelle les chaînes qui s'y sont accrochées :

```
                              +-------- processus locaux --------+
                              ^                                  |
                            input                              output
                              ^                                  v
 --> ingress --> prerouting --+--> forward ----------------------+--> postrouting --> egress -->
                 DNAT     (routage)                                   SNAT
                 redirect                                             masquerade
```

- `prerouting` : tous les paquets **reçus**, avant la décision de routage (« ce paquet est-il
  pour moi, ou à faire suivre ? ») ;
- `input` : les paquets **destinés à la machine** ;
- `forward` : les paquets qui **traversent** la machine, reçus par une interface et routés vers
  une autre (elle doit faire office de routeur : `net.ipv4.ip_forward=1`) ;
- `output` : les paquets **émis par les processus de la machine** ;
- `postrouting` : tous les paquets qui **partent**, routés ou émis localement, juste avant
  d'être confiés à l'interface de sortie.

| paquet | hooks traversés, dans l'ordre |
|--------|-------------------------------|
| reçu et destiné à la machine | `prerouting`, `input` |
| reçu et routé vers une autre machine | `prerouting`, `forward`, `postrouting` |
| émis par la machine | `output`, `postrouting` |

Deux autres hooks sont attachés à une interface, au ras de la carte réseau : `ingress`, avant
`prerouting` (familles `netdev` et `inet`), et `egress`, après `postrouting` (famille `netdev`).
Ils servent à filtrer très tôt ou très tard ; la traduction d'adresses ne s'y fait pas.

### @@sec:structure@@ Tables, chaînes de base et priorités

Un jeu de règles (*ruleset*) est fait de **tables**, qui contiennent des **chaînes**, qui
contiennent des **règles**. Il est vide au départ, et les noms des tables et des chaînes sont
libres.

- une **table** appartient à une **famille**, qui fixe les paquets qu'elle voit : `ip` (IPv4),
  `ip6` (IPv6) ou `inet` (les deux) ; les familles `arp`, `bridge` et `netdev` ne servent pas
  ici ;
- une **chaîne de base** est accrochée à un hook. Sa déclaration donne son **type** (`filter`
  pour filtrer, `nat` pour traduire), son **hook**, sa **priorité** et sa **politique** par
  défaut, le verdict des paquets qu'aucune règle n'a arrêtés (`accept` ou `drop` ; `accept` si
  l'on ne dit rien) ;
- une **chaîne régulière** n'a pas de hook : on y arrive par un saut (`jump`, `goto`) depuis une
  autre chaîne de la même table.

```
nft add table ip nat
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
```

La **priorité** ordonne les chaînes accrochées à un même hook, de la plus petite valeur à la
plus grande. Les valeurs usuelles ont un nom :

| nom | valeur | usage |
|-----|--------|-------|
| `raw` | -300 | avant le suivi de connexion |
| (pas de nom) | -200 | le suivi de connexion lui-même, aux hooks `prerouting` et `output` |
| `mangle` | -150 | modification des paquets |
| `dstnat` | -100 | traduction de la destination (hook `prerouting`) |
| `filter` | 0 | filtrage |
| `security` | 50 | modules de sécurité (SELinux) |
| `srcnat` | 100 | traduction de la source (hook `postrouting`) |

À son arrivée, un paquet passe donc par le suivi de connexion, puis par la traduction de sa
destination, puis par le filtrage ; à son départ, par le filtrage puis par la traduction de sa
source.

Plusieurs chaînes de base, de la même table ou de tables différentes, peuvent être accrochées au
même hook : un paquet les traverse **toutes**. `drop` est définitif (le paquet est détruit, plus
aucune chaîne ne le voit) ; `accept` ne vaut que pour la chaîne de base en cours : le paquet
passe à la suivante, qui peut encore le détruire.

### @@sec:rules@@ Règles et critères

Une **règle** est une suite de **critères** puis d'**actions**, évalués de gauche à droite ; dès
qu'un critère n'est pas satisfait, le paquet passe à la règle suivante. Les règles d'une chaîne
sont évaluées **dans l'ordre**, et la première qui rend un verdict décide : l'ordre des règles
fait partie de la politique.

| critère | signification |
|---------|---------------|
| `iifname "eth1"` | interface d'**entrée** (aux hooks `prerouting`, `input` et `forward`) |
| `oifname "eth1"` | interface de **sortie** (aux hooks `forward`, `output` et `postrouting`) |
| `ip saddr 192.168.1.0/24`, `ip daddr 203.0.113.1` | adresse source, destination (une adresse, un réseau, une plage `A-B`) |
| `tcp dport 8080`, `udp dport 53` | port de destination (`sport` : port source) ; nommer le port implique le protocole |
| `tcp dport { 80, 443 }` | un **ensemble** de valeurs |
| `meta l4proto tcp` | protocole de niveau 4 |
| `ct state established,related` | état de la connexion (section @@ref:ct-states@@) |
| `ct status dnat` | la connexion a subi un DNAT (`ct status snat` : un SNAT) |
| `ip saddr != 192.168.1.0/24` | négation d'un critère |

Les verdicts sont `accept` (le paquet passe), `drop` (il est détruit en silence), `reject` (il
est détruit et l'émetteur est prévenu) et `jump` / `goto` (vers une chaîne régulière). `counter`
(compter) et `log` (journaliser) agissent sans rendre de verdict. Les **traductions** (`snat`,
`masquerade`, `dnat`, `redirect`) sont des actions propres aux chaînes de type `nat`
(section @@ref:chains@@).

### @@sec:ct-states@@ Le suivi de connexion

Netfilter mémorise les **connexions** en cours (*connection tracking*, ou *conntrack*) : une
connexion TCP, mais aussi un échange UDP ou ICMP, reconnus à leurs adresses et à leurs ports.
Chaque paquet reçoit ainsi un **état**, que les règles testent avec `ct state` :

- `new` : le paquet ouvre une connexion, ou appartient à une connexion dont on n'a encore vu
  qu'un seul sens ;
- `established` : le paquet appartient à une connexion dont on a vu des paquets dans les deux
  sens ; la toute première réponse est déjà dans cet état ;
- `related` : le paquet est lié à une connexion connue (une erreur ICMP qui la concerne) ;
- `invalid` : le paquet ne correspond à rien de connu.

Un filtre s'en sert pour distinguer le sens d'un échange : la règle `ct state
established,related accept`, placée en tête d'une chaîne de filtrage, accepte d'un coup toutes
les réponses, et il ne reste à autoriser que les **nouvelles** connexions voulues. La traduction
d'adresses s'en sert plus encore (section @@ref:conntrack@@).

### @@sec:nft-cli@@ La commande nft et les fichiers de règles

```
nft list ruleset                       # tout le jeu de règles (vide au départ)
nft -a list ruleset                    # avec le handle (numéro) de chaque règle
nft list table ip nat                  # une table
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'
nft 'add rule ip nat prerouting iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80'
nft 'insert rule ip nat prerouting iifname "eth0" tcp dport 80 redirect to :3128'
nft delete rule ip nat prerouting handle 7
nft flush chain ip nat prerouting
nft delete table ip nat
nft flush ruleset
```

- `add rule` ajoute la règle en **fin** de chaîne, `insert rule` en **tête** ;
- `delete rule … handle 7` supprime la règle dont `nft -a list ruleset` affiche `# handle 7` ;
  `flush chain` vide une chaîne, `delete table` supprime une table et tout son contenu, `flush
  ruleset` efface **toutes** les tables ;
- **le shell passe avant `nft`** : les points-virgules, les guillemets et les accolades ont un
  sens pour lui. Dès qu'une commande en contient, entourez d'apostrophes tout ce qui suit `nft`.

Sur un vrai routeur, les règles s'écrivent dans un **fichier**, dans la syntaxe qu'affiche `nft
list ruleset` :

```
#!/usr/sbin/nft -f
flush ruleset

table ip nat {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
        }
        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
        }
}
```

```
nft -c -f /etc/nftables.conf      # vérifie le fichier sans rien changer
nft -f /etc/nftables.conf         # le charge
```

Le chargement est **atomique** : le fichier est appliqué en entier ou, à la moindre erreur, pas
du tout. Il commence par `flush ruleset` : sans cela, le recharger ajouterait ses règles une
seconde fois à la suite des premières. `nft -s list ruleset > regles.nft` sauvegarde le jeu de
règles en place (ajoutez `flush ruleset` en tête du fichier). Les règles tapées avec `nft` sont
**volatiles** : elles disparaissent au redémarrage ; sous Debian, le service `nftables` charge
`/etc/nftables.conf` au démarrage.
""")
            + info_subtitle(tr("NAT et suivi de connexion"), tag="conntrack")
            + tr("""
La traduction d'adresses repose entièrement sur le **suivi de connexion**
(section @@ref:ct-states@@) : le noyau ne traduit pas des paquets isolés, il traduit des
**connexions**.

### @@sec:first-packet@@ Une décision par connexion

- la traduction est **décidée une seule fois**, sur le **premier paquet** de la connexion (état
  `new`) : lui seul parcourt les chaînes de type `nat`, et la décision est inscrite dans l'entrée
  de la connexion ;
- les paquets suivants de la connexion sont traduits de la même façon, sans que les règles
  soient consultées ;
- les paquets **de retour** sont traduits **en sens inverse**, automatiquement : on n'écrit
  jamais de règle pour le retour.

### @@sec:tuples@@ Les deux sens d'une connexion

L'entrée d'une connexion contient deux descriptions : le sens **aller** (*original*), tel que
le premier paquet est arrivé, et le sens **retour** (*reply*), tel que les réponses sont
attendues. Sans traduction, la seconde est le miroir de la première ; une traduction la modifie.
La commande `conntrack -L` (paquet `conntrack`, quand il est installé) affiche les connexions
suivies, chacune sur une ligne (coupée en deux ici) : le sens aller, puis le sens retour. Après
un SNAT :

```
tcp  6 431995 ESTABLISHED src=192.168.1.20 dst=198.51.100.7 sport=40312 dport=80
                          src=198.51.100.7 dst=203.0.113.1 sport=80 dport=40312 [ASSURED]
```

le client `192.168.1.20` s'adresse à `198.51.100.7`, dont les réponses sont attendues vers
`203.0.113.1`, l'adresse publique du routeur : le routeur les reconnaît et les rend au client.
Après un DNAT du port 8080 du routeur vers le port 80 du serveur interne `192.168.1.10` :

```
tcp  6 431990 ESTABLISHED src=198.51.100.7 dst=203.0.113.1 sport=51514 dport=8080
                          src=192.168.1.10 dst=198.51.100.7 sport=80 dport=51514 [ASSURED]
```

le client a visé `203.0.113.1:8080`, et les réponses sont attendues de `192.168.1.10:80`.

La traduction inverse se fait au hook symétrique. La réponse à une connexion qui a subi un SNAT
retrouve sa vraie destination en `prerouting`, donc **avant** le routage : le routeur sait alors
vers quelle machine interne la faire suivre. La réponse à une connexion qui a subi un DNAT
retrouve l'adresse publique comme source en `postrouting`, juste avant de partir.

### @@sec:ct-consequences@@ Conséquences pratiques

- modifier ou supprimer une règle ne change rien aux connexions **déjà suivies** : elles gardent
  leur traduction jusqu'à leur fin. Pour essayer une règle, ouvrez une **nouvelle** connexion
  (chaque `curl` en ouvre une) ; `conntrack -F` vide la table des connexions ;
- une règle de traduction ne peut tester que ce que porte le premier paquet : interface,
  adresses, protocole, ports ;
- le compteur (`counter`) d'une règle de traduction avance d'un paquet par **connexion**, pas
  par paquet ;
- un échange UDP ou ICMP est suivi comme une connexion ; son entrée, et sa traduction avec elle,
  disparaît après 30 secondes sans trafic (120 secondes pour un flux UDP établi, 5 jours pour une
  connexion TCP établie).
""")
            + info_subtitle(tr("Les chaînes de type nat"), tag="chains")
            + tr("""
Les règles de traduction se placent dans des chaînes de base de **type `nat`**, et nulle part
ailleurs : `nft` refuse une traduction dans une chaîne de type `filter`. Le type `nat` existe
dans les familles `ip`, `ip6` et `inet`.

### @@sec:nat-hooks@@ Les quatre hooks du type nat

| hook | priorité | traductions permises | paquets concernés |
|------|----------|----------------------|-------------------|
| `prerouting` | `dstnat` (-100) | `dnat`, `redirect` | ce qui **arrive** par une interface |
| `output` | -100 | `dnat`, `redirect` | ce que le routeur **émet lui-même** |
| `postrouting` | `srcnat` (100) | `snat`, `masquerade` | ce qui **part** par une interface |
| `input` | 100 | `snat` | ce qui est **destiné au routeur** (rare) |

- le **DNAT** se fait **avant** la décision de routage : la destination doit être changée avant
  que le noyau décide si le paquet est pour lui ou à faire suivre, et par où l'envoyer ;
- le **SNAT** se fait **après** le routage, juste avant l'émission : l'interface de sortie est
  alors connue, et tout le reste du traitement (le routage, le filtrage) a vu la vraie source ;
- les paquets que le routeur émet lui-même ne passent pas par `prerouting` : un DNAT qui doit
  valoir pour eux s'écrit dans une chaîne `output` (section @@ref:nat-output@@).

`nft` refuse une traduction placée au mauvais hook : un `dnat` ou un `redirect` en
`postrouting`, un `masquerade` en `prerouting`.

### @@sec:nat-table@@ Déclarer la table et ses chaînes

```
table ip nat {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
        }
        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
        }
}
```

soit, en ligne de commande (les apostrophes protègent du shell les accolades et les
points-virgules) :

```
nft add table ip nat
nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
```

Le nom de la table est libre (`nat` par habitude), et l'on ne déclare que les chaînes dont on a
besoin. La politique reste `accept` : une chaîne `nat` traduit, elle ne filtre pas.

### @@sec:nat-rules@@ Les règles d'une chaîne nat

- une chaîne `nat` n'est parcourue que par le **premier paquet** de chaque connexion
  (section @@ref:first-packet@@) ;
- la **première règle** dont tous les critères sont satisfaits et qui porte une traduction
  (`snat`, `masquerade`, `dnat`, `redirect`) décide pour la connexion : les règles suivantes ne
  sont pas consultées. L'ordre des règles compte donc ici aussi ;
- une connexion qui n'en satisfait aucune passe **sans traduction** ;
- une règle `accept` placée avant une traduction en dispense les connexions qu'elle désigne :
  `ip daddr 192.168.0.0/16 accept` avant un `masquerade` laisse leur adresse aux paquets destinés
  à d'autres réseaux privés ;
- le critère d'interface est `iifname` en `prerouting` (par où le paquet est arrivé) et
  `oifname` en `postrouting` (par où il sort) ; `oifname` n'a pas de sens en `prerouting`, le
  routage n'ayant pas encore eu lieu ;
- on ne **filtre** pas dans une chaîne `nat` : elle ne voit qu'un paquet par connexion. Le
  filtrage se fait dans des chaînes de type `filter` (section @@ref:nat-filter@@) ;
- le routeur doit **router** : `sysctl net.ipv4.ip_forward` doit afficher 1.

### @@sec:nat-inet@@ Dans une table inet

Une table de la famille `inet` traduit IPv4 et IPv6 (depuis le noyau 5.2). Quand la traduction
donne une adresse, on précise alors la version d'IP : `dnat ip to 192.168.1.10:80`, `snat ip to
203.0.113.1`. `masquerade` et `redirect`, qui n'en donnent pas, s'écrivent sans changement.
""")
            + info_subtitle(tr("SNAT et masquerade"), tag="snat")
            + tr("""
La traduction de la source s'écrit dans la chaîne `postrouting`. Dans les exemples de ce cours,
le réseau privé est `192.168.1.0/24`, du côté de l'interface `eth0` du routeur, et l'extérieur
du côté de son interface `eth1`, dont l'adresse publique est `203.0.113.1`.

### @@sec:snat-to@@ snat : une adresse fixe

```
chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 192.168.1.0/24 oifname "eth1" snat to 203.0.113.1
}
```

Toute connexion qui vient du réseau privé `192.168.1.0/24` et sort par `eth1` part avec
l'adresse source `203.0.113.1`. Le serveur distant ne voit que cette adresse et lui répond ; le
routeur reconnaît la connexion et rend la réponse à la bonne machine interne.

### @@sec:masquerade@@ masquerade : l'adresse de l'interface de sortie

`masquerade` est un SNAT dont on n'écrit pas l'adresse : le noyau prend celle de l'interface par
laquelle la connexion sort.

```
ip saddr 192.168.1.0/24 oifname "eth1" masquerade
```

| critère | `snat to A` | `masquerade` |
|---------|-------------|--------------|
| adresse source après traduction | l'adresse A, écrite dans la règle | celle de l'interface de sortie |
| à utiliser quand | l'adresse publique est fixe, ou l'interface en porte plusieurs | l'adresse n'est pas connue d'avance (DHCP, PPP…) |
| hook | `postrouting` (et `input`) | `postrouting` seulement |

### @@sec:snat-options@@ Ports, groupes d'adresses et options

- le routeur garde le **port source** quand il le peut ; si ce port sert déjà à une autre
  connexion traduite, il en choisit un autre : c'est ainsi que plusieurs machines partagent une
  seule adresse ;
- `ip protocol tcp snat to 203.0.113.1:1024-65535` et `ip protocol tcp masquerade to
  :1024-65535` restreignent les ports source utilisables (une traduction qui nomme des ports
  exige que la règle dise d'abord le protocole) ;
- `snat to 203.0.113.10-203.0.113.20` répartit les connexions sur un **groupe** d'adresses ;
- des options se placent en fin de règle : `random` ou `fully-random` (ports tirés au hasard),
  `persistent` (un même client garde la même adresse du groupe à chaque connexion). Exemple :
  `masquerade random,persistent`.

### @@sec:snat-scope@@ Restreindre la règle

Restreignez toujours une traduction de source : `ip saddr` du réseau privé, `oifname` de
l'interface extérieure. Un `masquerade` sans critère traduirait aussi ce qui **entre** vers le
réseau interne, dont les serveurs ne verraient plus que l'adresse du routeur ; et il n'y a rien
à traduire entre deux réseaux internes qui se joignent déjà.
""")
            + info_subtitle(tr("DNAT et redirection de port"), tag="dnat")
            + tr("""
La traduction de la destination s'écrit dans la chaîne `prerouting`.

### @@sec:dnat-to@@ dnat : publier un serveur interne

```
chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80
}
```

Une connexion qui arrive par `eth1` sur le port TCP 8080 du routeur est envoyée au port 80 du
serveur interne `192.168.1.10` : c'est la **redirection de port**, qui publie un service
interne derrière l'adresse du routeur.

| règle | effet |
|-------|-------|
| `tcp dport 80 dnat to 192.168.1.10` | change l'adresse de destination ; le port est conservé |
| `tcp dport 8080 dnat to 192.168.1.10:80` | change l'adresse **et** le port |
| `tcp dport 8000-8010 dnat to 192.168.1.10` | toute une plage de ports, conservés tels quels |
| `ip daddr 203.0.113.1 tcp dport 8080 dnat to 192.168.1.10:80` | ne vaut que pour une des adresses du routeur, quelle que soit l'interface d'arrivée |

Une traduction qui nomme un port (`:80`) exige que la règle dise le protocole : `tcp dport …`
le fait. Restreignez la règle à ce que vous publiez (interface ou adresse visée, protocole,
port) : un `dnat` sans critère enverrait au serveur tout ce qui arrive au routeur.

### @@sec:return-path@@ Le chemin du retour

Le serveur interne voit l'adresse **réelle** du client : seule la destination a changé. Sa
réponse doit **repasser par le routeur**, qui lui rend son adresse publique comme source : le
serveur doit donc avoir une route vers le client **par ce routeur** (sa route par défaut, en
général). Sinon la réponse arrive au client avec une adresse source qu'il ne connaît pas, et il
la rejette.

### @@sec:nat-output@@ Les paquets émis par le routeur lui-même

Ce que le routeur émet lui-même ne passe pas par `prerouting` : un `curl` lancé sur le routeur
vers sa propre adresse publique n'est pas traduit par les règles de cette chaîne. Pour que la
redirection vaille aussi pour lui, on la répète dans une chaîne `nat` du hook `output` :

```
nft 'add chain ip nat output { type nat hook output priority -100; policy accept; }'
nft 'add rule ip nat output ip daddr 203.0.113.1 tcp dport 8080 dnat to 192.168.1.10:80'
```

### @@sec:hairpin@@ Le client et le serveur sur le même réseau (hairpin)

Une machine du réseau interne qui s'adresse à l'**adresse publique** du routeur pour joindre le
serveur interne se heurte à deux obstacles :

1. la règle de DNAT doit la concerner : `iifname "eth1"` ne vaut que pour ce qui arrive de
   l'extérieur ; `ip daddr 203.0.113.1`, qui désigne l'adresse visée, vaut pour les deux côtés ;
2. le serveur reçoit un paquet dont la source est une machine de son propre réseau, et lui
   répond **directement**, sans repasser par le routeur. Le client, qui s'est adressé à
   `203.0.113.1`, reçoit une réponse de `192.168.1.10` et la rejette.

Le remède est d'ajouter une traduction de source pour ces connexions-là, afin que le serveur
réponde au routeur (*hairpin NAT*) :

```
chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr 203.0.113.1 tcp dport 8080 dnat to 192.168.1.10:80
}
chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 192.168.1.0/24 ip daddr 192.168.1.10 tcp dport 80 masquerade
}
```

Le serveur ne voit plus alors que l'adresse du routeur pour ces clients internes ; l'autre
solution est de leur faire résoudre le nom du service en l'adresse interne du serveur.
""")
            + info_subtitle(tr("Traduction et filtrage"), tag="nat-filter")
            + tr("""
Sur un vrai routeur, la traduction (chaînes `nat`) et le filtrage (chaînes `filter`)
cohabitent. Dans ce TP, le routeur n'a aucune chaîne de filtrage : tout ce qui est traduit
passe.

### @@sec:what-forward-sees@@ Ce que voit la chaîne forward

Les priorités (section @@ref:structure@@) fixent ce que chaque chaîne voit : le DNAT se fait en
`prerouting`, **avant** le filtrage ; le SNAT en `postrouting`, **après** lui. Une chaîne
`forward` de type `filter` voit donc les paquets **après le DNAT et avant le SNAT** :

| connexion | ce que voit la chaîne `forward` |
|-----------|---------------------------------|
| du réseau interne vers l'extérieur (SNAT) | la source **d'origine** : l'adresse privée du client, pas l'adresse publique du routeur |
| de l'extérieur vers un serveur publié (DNAT) | la destination **réelle** : l'adresse et le port du serveur interne, pas ceux du routeur |

Il en va de même des réponses, puisque la traduction inverse se fait aux hooks symétriques
(section @@ref:tuples@@) : la chaîne `forward` raisonne toujours sur les adresses **internes**.

### @@sec:filter-rules@@ Les règles de filtrage d'un routeur qui traduit

```
table ip filter {
        chain forward {
                type filter hook forward priority filter; policy drop;
                ct state established,related accept
                iifname "eth0" oifname "eth1" accept
                iifname "eth1" ip daddr 192.168.1.10 tcp dport 80 accept
        }
}
```

- la première règle accepte les réponses, dans les deux sens ;
- la deuxième laisse sortir le réseau interne ;
- la troisième ouvre le service publié, par son adresse et son port **internes** : le port 8080
  du routeur n'apparaît pas dans le filtre. On peut aussi écrire `ct status dnat accept`, qui
  accepte toute connexion à laquelle une règle de DNAT s'est appliquée : une seule règle pour
  tous les services publiés.

Une redirection de port demande donc **deux** règles : la traduction, dans une chaîne `nat`, et
l'autorisation, dans la chaîne `forward`. Oublier la seconde est l'erreur la plus courante sur
un routeur dont la politique est `drop`. De même, un trafic remis à un processus du routeur par
`redirect` (section @@ref:redirect@@) arrive dans sa chaîne `input`, avec le port du processus
comme destination : c'est ce port-là que le filtre doit ouvrir.
""")
            + info_subtitle(tr("Dictionnaires et répartition de charge"), tag="load-balancing")
            + tr("""
L'adresse que donne une traduction n'est pas forcément écrite en dur : elle peut être
**calculée**, à partir d'un champ du paquet ou d'un numéro que le noyau fabrique.

### @@sec:nat-maps@@ Un dictionnaire dans une traduction

Un **dictionnaire** (*map*) associe une valeur à chaque clé. Écrit dans une règle de
traduction, il choisit l'adresse d'après un champ du paquet :

```
dnat to tcp dport map { 8080 : 192.168.1.10, 8081 : 192.168.1.11 }
snat to ip saddr map { 192.168.1.0/24 : 203.0.113.1, 192.168.2.0/24 : 203.0.113.2 }
```

La première règle publie deux serveurs en une seule règle : le port 8080 mène au premier, le
port 8081 au second (le port est conservé). La seconde fait sortir deux réseaux privés derrière
deux adresses publiques. Une connexion dont le champ n'est pas une clé du dictionnaire n'est pas
traduite par la règle.

### @@sec:numgen@@ numgen : le tourniquet

Pour **répartir** des connexions entre plusieurs serveurs, la clé du dictionnaire est un numéro
que fabrique `numgen` :

```
iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }
```

| expression | numéros obtenus | répartition |
|------------|-----------------|-------------|
| `numgen inc mod 2` | 0, 1, 0, 1… (un compteur) | un **tourniquet** (*round-robin*) strict |
| `numgen random mod 2` | 0 ou 1, au hasard | équilibrée en moyenne seulement |
| `numgen inc mod 10` avec `{ 0-5 : A, 6-9 : B }` | 0 à 9 | **pondérée** : six connexions sur dix au serveur A |

Avec trois serveurs : `mod 3`, et trois entrées dans le dictionnaire. Les critères de la règle
se placent **avant** `dnat` : le compteur n'avance que pour les connexions qui les satisfont.
Le numéro peut aussi choisir un **port** plutôt qu'une adresse :
`ip protocol tcp dnat to 192.168.1.10 : numgen inc mod 2 map { 0 : 4040, 1 : 4050 }`.

### @@sec:jhash@@ jhash : toujours le même serveur pour un client

`jhash` calcule le numéro à partir de champs du paquet : deux paquets qui ont les mêmes champs
obtiennent le même numéro.

```
iifname "eth1" tcp dport 80 dnat to jhash ip saddr mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }
```

Un même client (une même adresse source) retombe ainsi toujours sur le même serveur : c'est la
**persistance**, utile quand le serveur garde un état de session. `jhash ip saddr . tcp dport`
hache plusieurs champs à la fois.

### @@sec:lb-limits@@ Ce que cette répartition fait, et ne fait pas

- comme toute règle de traduction, celle-ci n'est parcourue que par le **premier paquet** de
  chaque connexion : la répartition se fait **par connexion**, et tous les paquets d'une
  connexion vont au même serveur ;
- le serveur voit l'adresse réelle du client, et sa réponse doit repasser par le routeur
  (section @@ref:return-path@@) ;
- c'est une répartition de niveau 4, **sans surveillance** : le routeur continue d'envoyer des
  connexions à un serveur en panne. Un vrai répartiteur de charge teste ses serveurs et retire
  celui qui ne répond plus.
""")
            + info_subtitle(tr("redirect et proxy transparent"), tag="redirect")
            + tr("""
### @@sec:redirect-to@@ redirect : vers la machine elle-même

**`redirect`** est un DNAT vers **la machine elle-même** : la destination devient l'adresse du
routeur sur l'interface par laquelle le paquet est arrivé, et le port celui que l'on indique.

```
iifname "eth0" tcp dport 80 redirect to :3128
```

Toute connexion HTTP (port 80) qui arrive par `eth0`, **quelle que soit sa destination**, est
remise au processus local qui écoute sur le port 3128. Sans `to`, `redirect` garde le port : il
ne change que l'adresse.

`redirect` se place en `prerouting` (ce qui arrive au routeur) ou en `output` (ce que la machine
émet elle-même). Restreignez-le à l'interface du réseau interne : sans `iifname "eth0"`, la
règle capterait aussi le port 80 du côté extérieur.

### @@sec:transparent-proxy@@ Le proxy transparent

C'est le principe du **proxy transparent** : le client croit parler au serveur distant, sans
aucune configuration de son côté. Le proxy reçoit la requête, retrouve le serveur visé (par
l'en-tête `Host:` de la requête, ou par la destination d'origine, que le suivi de connexion a
gardée), peut filtrer, journaliser ou mettre en cache, puis interroge le vrai serveur à la
place du client. Les portails captifs des réseaux Wi-Fi publics fonctionnent ainsi.

Ses limites : le serveur final voit l'adresse du proxy, pas celle du client ; et HTTPS ne se
laisse pas intercepter ainsi, le proxy n'ayant pas le certificat du serveur visé.
""")
            + info_subtitle(tr("Observer et vérifier une traduction"), tag="observe")
            + tr("""
### @@sec:test-servers@@ Les serveurs de test

Le plus direct est d'interroger avec `curl` un serveur de test qui **répond par ce qu'il voit** :
son nom, l'adresse et le port où la connexion lui est arrivée, l'adresse et le port du client.

```
SERVER=web1                # qui a répondu
SERVER_IP=192.168.1.10     # l'adresse où la connexion est arrivée...
SERVER_PORT=80             # ... et le port
CLIENT_IP=203.0.113.1      # le client, tel que le serveur le voit
CLIENT_PORT=40312
```

| traduction | ce que montre la réponse |
|------------|--------------------------|
| SNAT, `masquerade` | `CLIENT_IP` est l'adresse extérieure du routeur, et non celle du client |
| DNAT | `SERVER`, `SERVER_IP` et `SERVER_PORT` désignent le serveur interne, alors que le client a visé l'adresse et le port du routeur |
| répartition de charge | `SERVER` change d'une requête à l'autre |
| proxy transparent | c'est le proxy qui répond, sous son nom et sur son port |

### @@sec:capture@@ tcpdump, des deux côtés du routeur

`tcpdump` capture au ras de l'interface, à l'extérieur de tous les hooks : ce qu'il montre sur
une interface du routeur est le paquet tel qu'il circule sur le réseau de ce côté-là.

- sur l'interface **extérieure** (`tcpdump -n -i eth1 tcp port 80`), on ne voit que des adresses
  publiques : les paquets sortants **après** le SNAT, les paquets entrants **avant** le DNAT ;
- sur l'interface **intérieure** (`tcpdump -n -i eth0 tcp port 80`), on voit les adresses
  internes : la vraie source des clients, la vraie destination des serveurs.

Comparer les deux captures montre le même paquet **avant** et **après** sa traduction. Une
capture sur le serveur ou sur le client dit ce que chacun reçoit vraiment.

### @@sec:counters@@ Compteurs, connexions suivies, trace

- `nft list ruleset` : le jeu de règles est-il bien celui que vous croyez avoir chargé ?
- avec `counter` dans une règle de traduction (`… counter masquerade`), le compteur avance d'un
  paquet par **connexion** traduite : s'il ne bouge pas, la règle n'a pas été atteinte, ou ses
  critères ne conviennent pas ;
- `conntrack -L` montre la traduction retenue pour chaque connexion (section @@ref:tuples@@) ;
- pour suivre un paquet à travers toutes les chaînes, on le **trace** : une règle `meta nftrace
  set 1`, dans une chaîne de type `filter` accrochée à `prerouting` avec la priorité `raw`,
  marque les paquets à suivre, et `nft monitor trace` affiche les chaînes traversées, les règles
  satisfaites et leur verdict.

```
nft 'add chain ip nat trace_chain { type filter hook prerouting priority raw; }'
nft add rule ip nat trace_chain tcp dport 8080 meta nftrace set 1
nft monitor trace
```

### @@sec:pitfalls@@ Les pièges courants

| symptôme | cause probable |
|----------|----------------|
| rien ne traverse le routeur | le routage est désactivé (`sysctl net.ipv4.ip_forward` affiche 0) |
| la règle `dnat` semble sans effet | elle est testée **du mauvais côté** : une règle `iifname "eth1"` ne concerne ni une requête venue du réseau interne, ni une requête émise par le routeur lui-même (sections @@ref:nat-output@@ et @@ref:hairpin@@) |
| la nouvelle règle ne change rien | la connexion était déjà suivie et garde son ancienne traduction : refaites une requête (chaque `curl` ouvre une nouvelle connexion) |
| une autre règle s'applique à sa place | l'ordre des règles : la première qui convient l'emporte |
| le serveur reçoit la requête, le client n'a pas de réponse | la route de retour du serveur ne passe pas par le routeur (section @@ref:return-path@@) |
| le serveur ne voit plus que l'adresse du routeur | un `masquerade` trop large traduit aussi ce qui entre (section @@ref:snat-scope@@) |
| la traduction se fait, mais la connexion n'aboutit pas | sur un routeur qui filtre, la chaîne `forward` ne l'autorise pas (section @@ref:nat-filter@@) |
| `nft` refuse la règle | une traduction dans une chaîne de type `filter`, ou au mauvais hook (section @@ref:nat-hooks@@) ; des guillemets ou des accolades que le shell a interprétés |
""")
            + info_subtitle(tr("Bonnes pratiques"), tag="practices")
            + tr("""
### @@sec:router-file@@ Le fichier type d'un routeur d'accès

Un routeur qui fait sortir son réseau interne (`eth0`) derrière son adresse extérieure
(`eth1`), publie un serveur web interne et filtre ce qui le traverse :

```
#!/usr/sbin/nft -f
flush ruleset

table ip nat {
        chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
                iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80
        }
        chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr 192.168.1.0/24 oifname "eth1" masquerade
        }
}

table ip filter {
        chain forward {
                type filter hook forward priority filter; policy drop;
                ct state established,related accept
                iifname "eth0" oifname "eth1" accept
                ct status dnat accept
        }
}
```

### @@sec:principles@@ Les principes

- **traduire dans les chaînes `nat`, filtrer dans les chaînes `filter`** : une traduction
  n'autorise rien, et ne protège de rien ;
- **restreindre chaque traduction** : réseau source et interface de sortie pour un SNAT,
  interface ou adresse visée, protocole et port pour un DNAT ;
- **`masquerade`** quand l'adresse extérieure peut changer, **`snat to`** quand elle est fixe ;
- **penser au retour** : la réponse d'un serveur publié doit repasser par le routeur ;
- **penser au filtre** : une redirection de port demande aussi une règle dans `forward`, qui
  nomme l'adresse et le port **internes** ;
- **vérifier ce que voient les deux bouts** (les serveurs de test, `tcpdump`) plutôt que de
  relire seulement les règles ;
- **un fichier, chargé d'un bloc** et vérifié d'abord avec `nft -c -f`, plutôt que des commandes
  tapées une à une : les règles tapées avec `nft` disparaissent au redémarrage.
""")
            + info_subtitle(tr("Aide-mémoire"), tag="cheatsheet")
            + tr("""
| besoin | commande ou règle |
|--------|-------------------|
| état | `nft list ruleset`, `nft list table ip nat`, `nft -a list ruleset` (avec le numéro, *handle*, de chaque règle) |
| table et chaînes | `nft add table ip nat`, `nft 'add chain ip nat prerouting { type nat hook prerouting priority dstnat; policy accept; }'`, `nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'` |
| ajouter une règle | `nft 'add rule ip nat postrouting …'` (en fin de chaîne), `nft 'insert rule ip nat prerouting …'` (en tête) |
| SNAT | `ip saddr 192.168.1.0/24 oifname "eth1" masquerade`, `… snat to 203.0.113.1` |
| redirection de port | `iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80` |
| plusieurs services | `dnat to tcp dport map { 8080 : 192.168.1.10, 8081 : 192.168.1.11 }` |
| répartition de charge | `iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }` |
| proxy transparent | `iifname "eth0" tcp dport 80 redirect to :3128` |
| filtrer ce qui est traduit | chaîne `forward` de type `filter` : `ip daddr 192.168.1.10 tcp dport 80 accept`, ou `ct status dnat accept` |
| supprimer | `nft delete rule ip nat prerouting handle N`, `nft flush chain ip nat prerouting`, `nft delete table ip nat` |
| fichier de règles | `nft -c -f fichier` (vérifier), `nft -f fichier` (charger) ; le fichier commence par `flush ruleset` et se charge d'un bloc |
| tests | `curl -s -m 3 http://ADRESSE:PORT/`, `tcpdump -n -i eth1 tcp port 80`, `sysctl net.ipv4.ip_forward`, `conntrack -L` |
""")
        )

    # -- the rules of the reference solution (used by `final` and the instructor texts) ------
    # fw: eth0 = LAN (net1), eth1 = WAN (net2)

    def rule_masquerade(self) -> str:
        """Question 1: what comes from the LAN and leaves by the WAN interface is masqueraded."""
        return f'ip saddr {self.data.nets.net1} oifname "eth1" masquerade'

    def rule_port_forward(self) -> str:
        """Question 2: WAN:FWD_PORT -> web1:80."""
        return f'iifname "eth1" tcp dport {FWD_PORT} dnat to {self.data.ips.web1.ip}:80'

    def rule_load_balancing(self) -> str:
        """Question 3: WAN:VIP_PORT -> web1 and web2 in turn."""
        d = self.data
        return (f'iifname "eth1" tcp dport {VIP_PORT} dnat to numgen inc mod 2 '
                f'map {{ 0 : {d.ips.web1.ip}, 1 : {d.ips.web2.ip} }}')

    def rule_proxy(self) -> str:
        """Question 4: the HTTP leaving the LAN is handed to the local proxy of fw."""
        return f'iifname "eth0" tcp dport 80 redirect to :{PROXY_PORT}'

    def reference_conf(self) -> str:
        """The ``/etc/nftables.conf`` of the reference solution (the four questions)."""
        return "#!/usr/sbin/nft -f\nflush ruleset\n" + render_table({
            "prerouting": [self.rule_proxy(), self.rule_port_forward(), self.rule_load_balancing()],
            "postrouting": [self.rule_masquerade()],
        })

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        firewall.flush_ruleset(self, "fw")
        firewall.flush_ruleset(self, "fw_h")

        # The controlled HTTP servers: the same ones on the visible machines (the students check
        # their translations by hand with curl) and on their hidden clones (the probes of the
        # evaluation).  A clone answers with the name of the machine it copies.
        for suffix in ("", "_h"):
            firewall.setup_http_server(self, "ext" + suffix, NET_SVC_PORT, "ext")  # the "Internet" service
            firewall.setup_http_server(self, "fw" + suffix, PROXY_PORT, "proxy")   # local transparent proxy
            firewall.setup_http_server(self, "web1" + suffix, 80, "web1")          # backend 1
            firewall.setup_http_server(self, "web2" + suffix, 80, "web2")          # backend 2

    @sre_state(user_allowed=False)
    def final(self):
        """Solution de référence : note maximale."""
        self.file("fw", "/etc/nftables.conf", self.reference_conf(), permissions=0o644)
        self.cmd("fw", "nft -f /etc/nftables.conf")


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

        for m in ("fw", "fw_h", "cli_h", "ext_h"):
            for cmd in ("nft list ruleset", "ip -4 addr", "ip route",
                        "cat /proc/sys/net/ipv4/ip_forward"):
                self.test(m, cmd, allow_error=True)

        rs = firewall.get_ruleset(self, "fw")
        firewall.transplant_ruleset(self, src="fw", dst="fw_h")

        fw_wan_ip = str(d.ips.fw_net2.ip)

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `net1` (le LAN privé) | `{net1}` | **`fw`** eth0 (`{fw_lan}`, **le routeur à configurer**), `cli` (`{cli}`), `web1` (`{web1}`), `web2` (`{web2}`) |
| `net2` (le WAN, « Internet ») | `{net2}` | `fw` eth1 (**`{fw_wan}`**, l'adresse WAN de `fw`), `ext` (`{ext}`) |
""").format(net1=d.nets.net1, net2=d.nets.net2, fw_lan=d.ips.fw_net1.ip, fw_wan=fw_wan_ip, cli=d.ips.cli.ip,
            web1=d.ips.web1.ip, web2=d.ips.web2.ip, ext=d.ips.ext.ip)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente la traduction d'adresses avec nftables (suivi de
connexion, table `nat` et ses chaînes, SNAT et masquerade, DNAT et redirection de port,
répartition de charge, `redirect` et proxy transparent) et la façon de vérifier une traduction.

**La maquette** (onglet *Schéma*) : un réseau privé `net1`, le LAN, avec un client `cli` et deux
serveurs web `web1` et `web2` ; un réseau `net2` qui joue le WAN (« Internet »), où se trouve
`ext` ; entre les deux, le routeur **`fw`**, dont **`eth0` est du côté du LAN** et **`eth1` du côté
du WAN**. Vous configurez la table `nat` de **`fw`**, et de `fw` seulement : `cli`, `web1`, `web2`
et `ext` servent à vos tests.
""")
            + addressing
            + tr("""
**Les ports du TP** : **{svc}**, le service « Internet » de `ext` (question 1) ; **{fwd}**, le port
de `fw` côté WAN à rediriger vers le port 80 de `web1` (question 2) ; **{vip}**, le port de `fw` côté
WAN à répartir entre `web1` et `web2`, qui servent tous deux le port 80 (question 3) ; **{proxy}**,
le port du proxy local de `fw`, vers lequel détourner le HTTP (port 80) qui sort du LAN
(question 4).

**Déjà en place** (ne pas modifier) : les adresses ; le routage sur `fw`
(`net.ipv4.ip_forward=1`) ; sur chaque autre machine, une route vers le réseau d'en face par `fw`
(`cli`, `web1` et `web2` vers `net2`, `ext` vers `net1`) : sans aucune traduction, `cli` joint déjà
`ext`, qui voit alors l'adresse de `cli`. Le jeu de règles nftables de `fw` est vide au départ.
Dans vos commandes, désignez les machines par leurs adresses (tableau ci-dessus).

**Les serveurs de test.** Les serveurs HTTP du TP répondent par leur nom et par les adresses des
deux bouts de la connexion, telles qu'ils les voient (`SERVER=<nom>`, `SERVER_IP=`, `SERVER_PORT=`,
`CLIENT_IP=<adresse vue par le serveur>`, `CLIENT_PORT=`) : utilisez-les avec `curl` pour vérifier
vos traductions (section @@ref:observe@@ des Informations) :

- après le **SNAT**, `CLIENT_IP` devient l'adresse WAN de `fw` ;
- après le **DNAT**, `SERVER` indique quel serveur a réellement répondu ;
- avec la **répartition de charge**, en répétant la requête, `SERVER` alterne ;
- avec le **proxy transparent**, `SERVER` devient celui du proxy (`proxy`), pas la cible.

**Plan du TP.** Quatre traductions à mettre en place sur `fw`, dans l'ordre que vous voulez :

1. **SNAT / masquerade** : le LAN sort vers le WAN sous l'adresse WAN de `fw` ;
2. **redirection de port** : le port {fwd} de `fw`, côté WAN, mène au port 80 de `web1` ;
3. **répartition de charge** : le port {vip} de `fw`, côté WAN, est réparti entre `web1` et `web2` ;
4. **proxy transparent** : le HTTP qui sort du LAN est remis au proxy local de `fw` (port {proxy}).

Règles valables pour tout le TP :

- les quatre traductions doivent être en place **en même temps** : l'évaluation vérifie le jeu de
  règles final de `fw` ;
- l'évaluation lit le jeu de règles **chargé** sur `fw` (`nft list ruleset`), pas un fichier : des
  règles tapées avec `nft` suffisent (elles sont volatiles) ; si vous écrivez `/etc/nftables.conf`,
  chargez-le (`nft -f /etc/nftables.conf`) ;
- ce jeu de règles est **recopié sur une machine cachée identique** à `fw` (mêmes adresses, mêmes
  interfaces `eth0` et `eth1`), entourée de copies cachées de `cli`, `web1`, `web2` et `ext` où
  tournent les mêmes serveurs de test. L'évaluation y refait avec `curl` les requêtes des questions et lit
  les réponses : `CLIENT_IP` vu par `ext` (question 1), le serveur qui répond sur le port {fwd}
  (question 2) puis à huit requêtes sur le port {vip} (question 3 : `web1` et `web2` doivent répondre
  tous les deux), et celui qui répond à `cli` quand il vise le port 80 de `ext` (question 4). Elle
  vérifie aussi la présence d'une règle `masquerade` ou `snat` et d'une règle `dnat` ou `redirect`.
  Seul compte ce que dit **le jeu de règles chargé sur `fw`**, pas ce que vous faites sur les autres
  machines ;
- pour tester sans attendre, donnez un délai court à `curl` : `curl -s -m 3 http://ADRESSE:PORT/`.
""").format(svc=NET_SVC_PORT, fwd=FWD_PORT, vip=VIP_PORT, proxy=PROXY_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution : il écrit
le fichier ci-dessous dans `/etc/nftables.conf` sur `fw` et le charge (`nft -f /etc/nftables.conf`) ;
il est ré-applicable. Ce TP n'a aucun formulaire à remplir.

```
{conf}```

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` sur `fw`
(étape 1), chargé tel quel sur `fw_h` après un `nft flush ruleset` (étape 2 ; un jeu de règles vide
laisse la copie sans traduction), puis onze `curl -s -m 5` (étape 3) : depuis `cli_h` vers
`http://{ext}:{svc}/` (question 1) et `http://{ext}:80/` (question 4), depuis `ext_h` vers
`http://{fw_wan}:{fwd}/` (question 2) et huit fois vers `http://{fw_wan}:{vip}/?probe=N` (question 3).
Les serveurs de test des copies : `ext_h` port {svc} (`SERVER=ext`), `web1_h` et `web2_h` port 80
(`SERVER=web1`, `SERVER=web2`), `fw_h` port {proxy} (`SERVER=proxy`). Les mêmes serveurs tournent sur
`ext`, `web1`, `web2` et `fw` pour les vérifications à la main des étudiants (journal
`/var/log/sre_http_server_PORT.log`) : ils ne sont pas évalués. Barème : 15 points, dont 2 pour
la seule présence des mots `masquerade` / `snat` et `dnat` / `redirect` dans le jeu de règles.
""").format(conf=self.net_scheme.reference_conf(), ext=d.ips.ext.ip, fw_wan=fw_wan_ip, svc=NET_SVC_PORT,
            fwd=FWD_PORT, vip=VIP_PORT, proxy=PROXY_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("SNAT / masquerade"),
            description=tr("""
Faites en sorte que les machines du LAN `net1` accèdent au WAN en étant
**masquées** derrière l'adresse WAN de `fw` (`masquerade` en `postrouting`,
`oifname "eth1"`). Vérification : depuis `cli`, `curl http://{_arg0}:{_arg1}/` ;
le champ `CLIENT_IP` renvoyé par `ext` doit être **{_arg2}** (l'adresse de `fw`).
""").format(_arg0=str(d.ips.ext.ip), _arg1=NET_SVC_PORT, _arg2=fw_wan_ip)
            + instructor(tr("""
**Solution.** Sur `fw`, une table `{table}` avec une chaîne de type `nat` accrochée au hook
`postrouting`, et la règle qui masque ce qui vient du LAN et sort par `eth1` (le WAN) :

```
{conf}```

En ligne de commande : `nft add table {table}`, `nft 'add chain {table} postrouting {{ {decl} }}'`
puis `nft 'add rule {table} postrouting {rule}'`. L'adresse WAN de `fw` étant fixe,
`ip saddr {net1} oifname "eth1" snat to {fw_wan}` convient aussi.

Vérification : depuis `cli`,
`curl -s -m 3 http://{ext}:{svc}/` renvoie `SERVER=ext` et `CLIENT_IP={fw_wan}`. Sans la règle, la
requête aboutit déjà (`ext` a une route vers `net1`), mais avec `CLIENT_IP={cli}`. Sur `ext`,
`tcpdump -n -i eth0 tcp port {svc}` montre des paquets venant de `{fw_wan}` et non de `{cli}`.

Pièges : une chaîne de type `filter` (`nft` y refuse `masquerade`) ; `oifname "eth0"` (le LAN) au
lieu de `"eth1"` ; un `masquerade` sans aucun critère, qui traduit aussi les connexions entrantes
des questions 2 et 3 (`web1` et `web2` ne voient plus alors que `{fw_lan}`, l'adresse LAN de `fw`).

Évaluation : `snat_masquerade` (3 points : depuis la copie cachée de `cli`, `curl` vers
`http://{ext}:{svc}/` doit renvoyer `CLIENT_IP={fw_wan}`) et `regle_masquerade_presente` (1 point :
le texte de `nft list ruleset` de `fw` contient `masquerade` ou `snat`).
""").format(conf=render_table({"postrouting": [self.net_scheme.rule_masquerade()]}), table=NAT_TABLE,
            decl=NAT_CHAINS["postrouting"], rule=self.net_scheme.rule_masquerade(), net1=d.nets.net1,
            fw_wan=fw_wan_ip, fw_lan=d.ips.fw_net1.ip, ext=d.ips.ext.ip, cli=d.ips.cli.ip, svc=NET_SVC_PORT)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Redirection de port (DNAT)"),
            description=tr("""
Publiez le serveur interne `web1` : toute connexion arrivant du WAN sur
**{_arg0}:{_arg1}** doit être redirigée (DNAT) vers **{_arg2}:80**.
""").format(_arg0=fw_wan_ip, _arg1=FWD_PORT, _arg2=str(d.ips.web1.ip))
            + instructor(tr("""
**Solution.** Dans la table `{table}` de `fw`, une chaîne de type `nat` accrochée au hook
`prerouting`, et la règle de DNAT pour ce qui arrive du WAN (`eth1`) :

```
{conf}```

En ligne de commande : `nft 'add chain {table} prerouting {{ {decl} }}'` puis
`nft 'add rule {table} prerouting {rule}'`. Le critère `ip daddr {fw_wan}` à la place de
`iifname "eth1"` convient aussi.

Vérification : depuis `ext`,
`curl -s -m 3 http://{fw_wan}:{fwd}/` renvoie `SERVER=web1`, `SERVER_IP={web1}`, `SERVER_PORT=80` et
`CLIENT_IP={ext}` : le serveur voit le vrai client, seule la destination a changé. La réponse de
`web1` repasse par `fw` (sa route vers `net2`), qui lui rend l'adresse source `{fw_wan}` : aucune
règle pour le retour. Sur `web1`, `tcpdump -n -i eth0 tcp port 80` montre la connexion de `{ext}`
arriver sur le port 80.

Pièges : la règle écrite en `postrouting` (`nft` la refuse : le routage est déjà fait) ;
`iifname "eth0"` ; le test lancé depuis `cli` ou depuis `fw` lui-même, que la règle `iifname "eth1"`
ne concerne pas.

Évaluation : `dnat_port_forward` (3 points : depuis la copie cachée de `ext`, `curl` vers
`http://{fw_wan}:{fwd}/` doit renvoyer `SERVER=web1`) et `regle_dnat_presente` (1 point : le texte de
`nft list ruleset` de `fw` contient `dnat` ou `redirect` ; les règles des questions 3 et 4 le
donnent aussi).
""").format(conf=render_table({"prerouting": [self.net_scheme.rule_port_forward()]}), table=NAT_TABLE,
            decl=NAT_CHAINS["prerouting"], rule=self.net_scheme.rule_port_forward(), fw_wan=fw_wan_ip,
            fwd=FWD_PORT, web1=d.ips.web1.ip, ext=d.ips.ext.ip)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Répartition de charge (numgen)"),
            description=tr("""
Répartissez les connexions arrivant du WAN sur **{_arg0}:{_arg1}** entre les deux
backends **web1** ({_arg2}) et **web2** ({_arg3}), par exemple en tourniquet avec
`dnat to numgen inc mod 2 map {{ ... }}`.
""").format(_arg0=fw_wan_ip, _arg1=VIP_PORT, _arg2=str(d.ips.web1.ip), _arg3=str(d.ips.web2.ip))
            + instructor(tr("""
**Solution.** Dans la chaîne `prerouting` de la table `{table}` de `fw` (celle de la question 2) :

```
{conf}```

En ligne de commande : `nft 'add rule {table} prerouting {rule}'` (les apostrophes évitent que le
shell interprète les accolades et les guillemets). `numgen inc mod 2` est un compteur qui vaut 0, 1,
0, 1… ; la *map* associe 0 à `web1` et 1 à `web2`, et le port ({vip}) est conservé. La règle n'est
parcourue que par le premier paquet de chaque connexion : les connexions alternent, et tous les
paquets d'une connexion vont au même serveur.

Vérification : depuis `ext`, répétez
`curl -s -m 3 http://{fw_wan}:{vip}/` : `SERVER=web1` (`SERVER_IP={web1}`) et `SERVER=web2`
(`SERVER_IP={web2}`) alternent, avec `CLIENT_IP={ext}`.

Variantes et pièges : `numgen random mod 2` convient (les huit requêtes de l'évaluation tombent sur
le même serveur une fois sur 128) ; `jhash ip saddr mod 2` envoie toujours `ext` au même serveur et
ne rapporte que la moitié des points ; cette règle et celle de la question 2 visent des ports
différents ({vip} et {fwd}), celle de la question 4 l'interface `eth0` : leur ordre dans la chaîne
est indifférent.

Évaluation : `load_balancing` (4 points : huit `curl` vers `http://{fw_wan}:{vip}/?probe=N` depuis la
copie cachée de `ext` ; 4 si `web1` **et** `web2` répondent, 2 si un seul des deux répond).
""").format(conf=render_table({"prerouting": [self.net_scheme.rule_load_balancing()]}), table=NAT_TABLE,
            rule=self.net_scheme.rule_load_balancing(), fw_wan=fw_wan_ip, vip=VIP_PORT, fwd=FWD_PORT,
            web1=d.ips.web1.ip, web2=d.ips.web2.ip, ext=d.ips.ext.ip)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("Proxy transparent (redirect)"),
            description=tr("""
Interceptez le HTTP **sortant du LAN** (`iifname "eth0"`, `tcp dport 80`) et
redirigez-le vers le **proxy transparent local** de `fw` (port {_arg0}) avec
`redirect to :{_arg0}`.
""").format(_arg0=PROXY_PORT)
            + instructor(tr("""
**Solution.** Toujours dans la chaîne `prerouting` de la table `{table}` de `fw`, pour ce qui
arrive du LAN (`eth0`) :

```
{conf}```

En ligne de commande : `nft 'add rule {table} prerouting {rule}'`. `redirect` remplace la
destination par l'adresse de `fw` sur l'interface d'arrivée (`{fw_lan}`) et le port par {proxy} : la
connexion est remise au proxy local, quelle que soit l'adresse visée ; `dnat to {fw_lan}:{proxy}`
aurait ici le même effet.

Vérification : depuis `cli`,
`curl -s -m 3 http://{ext}/` renvoie `SERVER=proxy`, `SERVER_IP={fw_lan}`, `SERVER_PORT={proxy}` et
`CLIENT_IP={cli}` : c'est le proxy de `fw` qui a répondu, pas `ext`. Les requêtes de `cli` vers
`web1` ou `web2` restent dans le LAN, ne traversent pas `fw` et ne sont pas interceptées.

Pièges : sans `iifname "eth0"`, la règle capte aussi le port 80 côté WAN si elle précède celle de
la question 3 (c'est alors le proxy qui répond à `ext`) ; `oifname` n'a pas de sens en `prerouting`.

Évaluation : `proxy_transparent` (3 points : depuis la copie cachée de `cli`, `curl` vers
`http://{ext}:80/` doit renvoyer `SERVER=proxy` ; rien n'écoute sur le port 80 de la copie de `ext` :
seule l'interception donne une réponse). Le jeu de règles complet des quatre questions est dans
*Organisation du TP*.
""").format(conf=render_table({"prerouting": [self.net_scheme.rule_proxy()]}), table=NAT_TABLE,
            rule=self.net_scheme.rule_proxy(), fw_lan=d.ips.fw_net1.ip, proxy=PROXY_PORT, ext=d.ips.ext.ip,
            cli=d.ips.cli.ip)),
        )

        # ---- sondes ----
        # 1. SNAT : cli -> ext:9000 ; ext voit CLIENT_IP = adresse WAN de fw
        snat_body, _ = firewall.probe_http(self, "cli_h", d.ips.ext, port=NET_SVC_PORT)
        snat_client = firewall.http_field(snat_body, "CLIENT_IP")
        snat_ok = (snat_client == fw_wan_ip)

        # 2. DNAT port-forward : ext -> fw_wan:8080 ; répond web1
        fwd_body, _ = firewall.probe_http(self, "ext_h", d.ips.fw_net2, port=FWD_PORT)
        fwd_ok = (firewall.http_field(fwd_body, "SERVER") == "web1")

        # 3. Load balancing : ext -> fw_wan:80 répété ; web1 ET web2 répondent
        backends = firewall.probe_http_backends(self, "ext_h", d.ips.fw_net2, port=VIP_PORT, n=8)
        seen = {b for b in backends if b}
        lb_both = ("web1" in seen) and ("web2" in seen)
        lb_any = ("web1" in seen) or ("web2" in seen)

        # 4. Proxy transparent : cli -> ext:80 redirigé vers le proxy local de fw
        proxy_body, _ = firewall.probe_http(self, "cli_h", d.ips.ext, port=80)
        proxy_ok = (firewall.http_field(proxy_body, "SERVER") == "proxy")

        self.add_grade_element(title=no_tr("snat_masquerade"), max_grade=3, grade=3 * int(snat_ok),
            description=tr("SNAT : le LAN sort masqué derrière l'adresse WAN de fw"))
        self.add_grade_element(title=no_tr("dnat_port_forward"), max_grade=3, grade=3 * int(fwd_ok),
            description=tr("DNAT : WAN:{_arg0} redirigé vers web1:80").format(_arg0=FWD_PORT))
        self.add_grade_element(title=no_tr("load_balancing"), max_grade=4,
            grade=(4 if lb_both else (2 if lb_any else 0)),
            description=tr("Répartition de charge WAN:{_arg0} entre web1 et web2").format(_arg0=VIP_PORT))
        self.add_grade_element(title=no_tr("proxy_transparent"), max_grade=3, grade=3 * int(proxy_ok),
            description=tr("Proxy transparent : HTTP du LAN redirigé vers fw:{_arg0}").format(_arg0=PROXY_PORT))
        self.add_grade_element(title=no_tr("regle_masquerade_presente"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "masquerade") or firewall.ruleset_mentions(rs, "snat")),
            description=tr("Présence d'une règle masquerade/snat"))
        self.add_grade_element(title=no_tr("regle_dnat_presente"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "dnat") or firewall.ruleset_mentions(rs, "redirect")),
            description=tr("Présence d'une règle dnat/redirect"))


_TRANSLATIONS = {}
