"""nftables-nat — Traduction d'adresses : six thèmes, un routeur par thème.

Six small sites share one "Internet" (the network ``wan``); the part N of the lab is done on the
router ``rN`` of site N and on that router only, so that every part is independent of the others:

1. ``r1`` — source NAT: ``masquerade`` for a private LAN (nothing answers without it: the Internet
   hosts have no route to the private networks);
2. ``r2`` — static 1:1 NAT: a second public address dedicated to a server (``dnat`` in, ``snat to``
   out, placed before the masquerade that is given);
3. ``r3`` — publishing a server: port forwarding for the Internet, for the router itself (``nat``
   chain of the ``output`` hook) and for the LAN (hairpin NAT);
4. ``r4`` — layer-4 load balancing (``numgen``);
5. ``r5`` — transparent proxy (``redirect``) and an exception placed before it;
6. ``r6`` — NAT is not a firewall: a ``forward`` filter chain next to a NAT that is given.

Every router has ``eth0`` on its LAN and ``eth1`` on the WAN.  ``r2``, ``r5`` and ``r6`` start with
rules already loaded (``/etc/nftables.conf``): what their part must not depend on.

Grading uses the "hidden mirror" of ``lib/hidden_mirror.py`` / ``lib/firewall.py``: the ruleset
loaded on each ``rN`` is transplanted on its hidden clone ``rN_h`` at each evaluation, and the test
HTTP servers (which answer SERVER / SERVER_IP / SERVER_PORT / CLIENT_IP / CLIENT_PORT) are
questioned from the clones of the hosts, so that the effect of each translation is *observed*.  No
NAT statement is parsed: any correct way of writing a rule is accepted.  The clones of the Internet
hosts have a route to every LAN (the visible ones have none), so that no probe needs a translation
for its return path.  The forms (typed observations) are graded from the generated data.  The
``final`` state applies the reference solution (100/100).  Texts are French (``tr()``), identifiers
English.
"""

from dataclasses import dataclass
from ipaddress import IPv4Network, ip_address
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
from SRE.lib_sre import info_subtitle, info_toc, instructor
from ips import random_ipv4networks, random_ipv4s, random_ips_from_topology
from net_config import set_net_config_entry, set_ip_forward, set_sysctl, get_net_config_from_topology
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
# An evaluation loads six rulesets and runs about thirty probes on 36 containers.
eval_interval_without_exam_mode = 120
eval_before_exit = True

SVC_PORT = 9000        # the "Internet" service of ext1 (to observe a source NAT)
FWD_PORT = 8080        # WAN port of r3 (and r6) forwarded to port 80 of the published server
VIP_PORT = 80          # WAN port of r4 shared between web4a and web4b
PROXY_PORT = 3128      # the local proxy of r5
INTRANET_PORT = 8081   # the service of srv6 that is NOT published
LB_REQUESTS = 8        # requests of the load-balancing probe

# The evaluation: the rulesets are read at step 1, loaded on the clones at LOAD_STEP, probed at PROBE_STEP.
LOAD_STEP, PROBE_STEP = 2, 3

# The addresses of the "Internet": never routed (RFC 2544), visibly not private, and not the
# documentation addresses of the examples of the course.
WAN_RANGE = IPv4Network("198.18.0.0/15")

SITES = (1, 2, 3, 4, 5, 6)
ROUTERS = tuple(f"r{n}" for n in SITES)
WAN_HOSTS = ("ext1", "ext2")
# The hosts of each site (site N = part N = router rN); every router: eth0 = its LAN, eth1 = the WAN.
SITE_HOSTS = {
    1: ("pc1",),
    2: ("srv2", "pc2"),
    3: ("web3", "pc3"),
    4: ("web4a", "web4b"),
    5: ("pc5", "admin"),
    6: ("srv6",),
}
HOST_SITE = {host: n for n, hosts in SITE_HOSTS.items() for host in hosts}

_TOPOLOGY = {f"lan{n}": {f"r{n}": 0, **{host: 0 for host in SITE_HOSTS[n]}} for n in SITES}
_TOPOLOGY["wan"] = {**{router: 1 for router in ROUTERS}, **{host: 0 for host in WAN_HOSTS}}

_SPECS = {
    **{router: {"color": "salmon"} for router in ROUTERS},
    **{host: {} for host in HOST_SITE},
    **{host: {"color": "lightgreen"} for host in ("srv2", "web3", "web4a", "web4b", "srv6")},
    **{host: {"color": "lightgrey"} for host in WAN_HOSTS},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS)

# The test HTTP servers (machine, port, name answered in SERVER=), on the visible machines and on
# their clones.
SERVERS = (
    ("ext1", 80, "ext1"), ("ext1", SVC_PORT, "ext1"),
    ("pc1", 80, "pc1"),
    ("srv2", 80, "srv2"),
    ("web3", 80, "web3"),
    ("web4a", 80, "web4a"), ("web4b", 80, "web4b"),
    ("r5", PROXY_PORT, "proxy"),
    ("srv6", 80, "srv6"), ("srv6", INTRANET_PORT, "intranet"),
)

# A Linux router that sends a packet back through the interface it came in by (hairpin) also sends
# an ICMP redirect to the sender: turned off, the captures of part 3 only show the connection.
NO_REDIRECTS = {f"net.ipv4.conf.{scope}.send_redirects": 0 for scope in ("all", "default", "eth0", "eth1")}

# The tables of the reference solution and their base chains ({table: {chain: declaration}}): the
# text loaded by `initial` (the rules given on r2 / r5 / r6) and by `final`, and quoted in the
# instructor's solutions.
NAT_TABLE = "ip nat"
FILTER_TABLE = "ip filter"
CHAINS = {
    NAT_TABLE: {
        "prerouting": "type nat hook prerouting priority dstnat; policy accept;",
        "output": "type nat hook output priority -100; policy accept;",
        "postrouting": "type nat hook postrouting priority srcnat; policy accept;",
    },
    FILTER_TABLE: {
        "forward": "type filter hook forward priority filter; policy drop;",
    },
}
CONF_FILE = "/etc/nftables.conf"
CONF_HEADER = "#!/usr/sbin/nft -f\nflush ruleset\n\n"


def render_tables(tables: Dict[str, Dict[str, List[str]]]) -> str:
    """The ``table … { … }`` blocks of an nftables file holding the given rules
    (``{table: {chain: [rule, ...]}}``, the tables and chains being those of ``CHAINS``)."""
    lines = []
    for table, chains in tables.items():
        lines.append(f"table {table} {{")
        for name, rules in chains.items():
            lines += [f"    chain {name} {{", f"        {CHAINS[table][name]}"]
            lines += [f"        {rule}" for rule in rules]
            lines.append("    }")
        lines.append("}")
    return "\n".join(lines) + "\n"


def nft_chain(table: str, chain: str) -> str:
    """The command line that creates a base chain of ``CHAINS``."""
    return f"nft 'add chain {table} {chain} {{ {CHAINS[table][chain]} }}'"


def nft_rule(table: str, chain: str, rule: str, verb: str = "add") -> str:
    """The command line that adds (``add``: at the end, ``insert``: first) a rule to a chain."""
    return f"nft '{verb} rule {table} {chain} {rule}'"


def visible(machine: str) -> str:
    """The name of the visible machine a clone copies (the name itself for a visible machine)."""
    return machine[:-2] if machine.endswith("_h") else machine


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    @classmethod
    def generate(cls):
        data = cls()
        data.nets.wan = random_ipv4networks(24, from_network=WAN_RANGE)[0]
        lans = random_ipv4networks(
            masks=[24] * len(SITES),
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        for n, lan in zip(SITES, lans):
            setattr(data.nets, f"lan{n}", lan)
        random_ips_from_topology(data, _TOPOLOGY)
        # the second public address of r2 (part 2), in the WAN like the first one
        used = [ip for ip in vars(data.ips).values() if ip.network == data.nets.wan]
        data.ips.r2_public = random_ipv4s(data.nets.wan, 1, exclude_ips=used)[0]
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
        self.routers = sorted(hidden_mirror.router_machines(self._topology))  # r1 … r6 and their clones
        self.net_config = self.build_net_config()

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
injoignable de l'extérieur que parce que ses adresses n'y sont pas routées : une machine placée du
côté extérieur du routeur (chez le fournisseur d'accès, sur le même réseau d'immeuble) qui se
donne une route vers le réseau privé **à travers le routeur** l'atteint sans obstacle, puisque le
routeur fait suivre ce qu'aucune règle n'arrête. La vraie protection est le filtrage (chaîne
`forward`, section @@ref:nat-filter@@). Le NAT a aussi un coût : le
serveur ne voit plus la véritable adresse du client, et les protocoles qui transportent des
adresses dans leurs données (FTP, SIP) ne fonctionnent qu'avec des modules d'assistance du noyau
(*helpers*).

**Comment lire ce cours.** La section @@ref:basics@@ résume nftables (hooks, tables, chaînes,
règles, commande `nft`) : parcourez-la si le filtrage avec nftables vous est familier, lisez-la
sinon. Les sections @@ref:conntrack@@ et @@ref:chains@@ valent pour toutes les traductions ; les
sections @@ref:snat@@ à @@ref:redirect@@ traitent chacune d'un usage (sortir d'un réseau privé,
publier un serveur, filtrer ce qui est traduit, répartir la charge, détourner vers un proxy) ; la
section @@ref:observe@@ dit comment vérifier une traduction, et les deux dernières rassemblent les
bonnes pratiques et les commandes.
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

La priorité s'écrit ici `-100` : nftables 1.0.6 n'accepte le nom `dstnat` qu'au hook
`prerouting`. Le critère est l'adresse visée (`ip daddr`) : un paquet émis par la machine n'a pas
d'interface d'entrée.

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

### @@sec:static-nat@@ NAT statique : une adresse publique pour une machine

Quand le routeur dispose de **plusieurs adresses publiques**, il peut en consacrer une à une
machine interne : c'est le NAT statique, ou « un pour un » (1:1). L'adresse publique `203.0.113.2`,
seconde adresse de l'interface `eth1` du routeur, est ici celle du serveur `192.168.1.10` :

```
chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr 203.0.113.2 dnat to 192.168.1.10
}
chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 192.168.1.10 oifname "eth1" snat to 203.0.113.2
        ip saddr 192.168.1.0/24 oifname "eth1" masquerade
}
```

- **ce qui entre** : tout ce qui est destiné à `203.0.113.2` est envoyé au serveur. La règle n'a
  ni protocole ni port : tous les ports sont concernés, et conservés ;
- **ce qui sort** : les connexions que le serveur ouvre partent sous cette même adresse. `snat
  to` est ici nécessaire : `masquerade` prendrait l'adresse **principale** de l'interface (la
  première, `203.0.113.1`) ;
- **l'ordre** : la règle du serveur précède la règle générale du réseau. Placée après, elle ne
  serait jamais atteinte, la règle `masquerade` convenant déjà aux connexions du serveur
  (section @@ref:nat-rules@@) ;
- le routeur doit **porter** l'adresse (`ip addr add 203.0.113.2/24 dev eth1`) : c'est lui qui
  répond aux requêtes ARP qui la cherchent.

Vu d'Internet, le serveur a alors sa propre adresse publique, dans les deux sens ; le filtrage de
ce qui lui parvient reste l'affaire de la chaîne `forward` (section @@ref:nat-filter@@).
""")
            + info_subtitle(tr("Traduction et filtrage"), tag="nat-filter")
            + tr("""
Sur un vrai routeur, la traduction (chaînes `nat`) et le filtrage (chaînes `filter`)
cohabitent. Un routeur qui traduit sans filtrer fait suivre tout ce qu'il sait router, traduit ou
non : c'est le filtre, et lui seul, qui décide de ce qui passe.

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
| le routeur lui-même | chaîne `nat` du hook `output` (priorité `-100`) : `ip daddr 203.0.113.1 tcp dport 8080 dnat to 192.168.1.10:80` |
| *hairpin* | `ip daddr 203.0.113.1 tcp dport 8080 dnat to 192.168.1.10:80` et, en `postrouting`, `ip saddr 192.168.1.0/24 ip daddr 192.168.1.10 tcp dport 80 masquerade` |
| NAT statique | `ip daddr 203.0.113.2 dnat to 192.168.1.10` et, en `postrouting` avant le `masquerade`, `ip saddr 192.168.1.10 oifname "eth1" snat to 203.0.113.2` |
| plusieurs services | `dnat to tcp dport map { 8080 : 192.168.1.10, 8081 : 192.168.1.11 }` |
| répartition de charge | `iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }` |
| proxy transparent | `iifname "eth0" tcp dport 80 redirect to :3128` |
| filtrer ce qui est traduit | chaîne `forward` de type `filter` : `ip daddr 192.168.1.10 tcp dport 80 accept`, ou `ct status dnat accept` |
| supprimer | `nft delete rule ip nat prerouting handle N`, `nft flush chain ip nat prerouting`, `nft delete table ip nat` |
| fichier de règles | `nft -c -f fichier` (vérifier), `nft -f fichier` (charger) ; le fichier commence par `flush ruleset` et se charge d'un bloc |
| tests | `curl -s -m 3 http://ADRESSE:PORT/`, `tcpdump -n -i eth1 tcp port 80`, `sysctl net.ipv4.ip_forward`, `conntrack -L` |
""")
        )

    # -- addresses and routes -------------------------------------------------------------------

    def build_net_config(self):
        """The addresses of the topology with the routes of a real access network: a default route
        through the router of the site on the LAN hosts, nothing but the connected networks on the
        routers and on the Internet hosts.  Only the hidden clones of the Internet hosts know the
        LANs (through each router): a probe never needs a translation for its return path, and the
        clone of ext2 is the neighbour who added a route.  r2 and its clone carry the second public
        address on eth1, after the first one (which stays the primary address: the one
        ``masquerade`` uses)."""
        d = self.data
        config = get_net_config_from_topology(net_scheme=self, gateway=None)
        default = IPv4Network("0.0.0.0/0")
        lan_routes = [(self.lan(n), self.wan_ip(n)) for n in SITES]
        for machine, entry in config.items():
            name = visible(machine)
            if name in HOST_SITE:
                routes = [(default, self.lan_ip(HOST_SITE[name]))]
            elif name in WAN_HOSTS and machine != name:
                routes = lan_routes
            else:
                routes = []
            for i, interface in enumerate(entry):
                if isinstance(interface, tuple):
                    entry[i] = (list(interface[0]), routes if i == 0 else [])
        for router in ("r2", "r2_h"):
            addresses, routes = config[router][1]
            config[router][1] = (addresses + [d.ips.r2_public], routes)
        return config

    def lan(self, n: int):
        """The private network of site *n*."""
        return getattr(self.data.nets, f"lan{n}")

    def wan_ip(self, n: int):
        """The (first) public address of the router of site *n*."""
        return getattr(self.data.ips, f"r{n}_wan").ip

    def lan_ip(self, n: int):
        """The address of the router of site *n* in its LAN."""
        return getattr(self.data.ips, f"r{n}_lan{n}").ip

    def host_ip(self, name: str):
        return getattr(self.data.ips, name).ip

    # -- the rules of the reference solution (used by `initial`, `final` and the instructor texts) --
    # every router: eth0 = LAN, eth1 = WAN

    def rule_masquerade(self, n: int) -> str:
        """What comes from the LAN of site *n* and leaves by the WAN interface is masqueraded
        (part 1 on r1; given on r2, r5 and r6)."""
        return f'ip saddr {self.lan(n)} oifname "eth1" masquerade'

    def rule_static_in(self) -> str:
        """Part 2: everything sent to the second public address of r2 goes to srv2."""
        return f'ip daddr {self.data.ips.r2_public.ip} dnat to {self.host_ip("srv2")}'

    def rule_static_out(self) -> str:
        """Part 2: srv2 leaves under the second public address (before the masquerade)."""
        return f'ip saddr {self.host_ip("srv2")} oifname "eth1" snat to {self.data.ips.r2_public.ip}'

    def rule_port_forward(self, n: int, by_interface: bool = False) -> str:
        """WAN:FWD_PORT of the router of site *n* -> port 80 of its server (part 3 on r3, by the
        address aimed at so that it also holds for the LAN; given on r6, by the interface)."""
        server = {3: "web3", 6: "srv6"}[n]
        criterion = 'iifname "eth1"' if by_interface else f"ip daddr {self.wan_ip(n)}"
        return f"{criterion} tcp dport {FWD_PORT} dnat to {self.host_ip(server)}:80"

    def rule_hairpin(self) -> str:
        """Part 3: a LAN client sent to web3 by the port forward is masqueraded, so that web3
        answers to r3."""
        return f'ip saddr {self.lan(3)} ip daddr {self.host_ip("web3")} tcp dport 80 masquerade'

    def rule_load_balancing(self) -> str:
        """Part 4: WAN:VIP_PORT of r4 -> web4a and web4b in turn."""
        return (f'iifname "eth1" tcp dport {VIP_PORT} dnat to numgen inc mod 2 '
                f'map {{ 0 : {self.host_ip("web4a")}, 1 : {self.host_ip("web4b")} }}')

    def rule_proxy_exception(self) -> str:
        """Part 5: the HTTP of admin is not handed to the proxy (placed before `rule_proxy`)."""
        return f'iifname "eth0" ip saddr {self.host_ip("admin")} tcp dport 80 accept'

    def rule_proxy(self) -> str:
        """Part 5: the HTTP leaving the LAN is handed to the local proxy of r5."""
        return f'iifname "eth0" tcp dport 80 redirect to :{PROXY_PORT}'

    def rules_forward(self) -> List[str]:
        """Part 6: the forward chain of r6 (policy drop): answers, the LAN going out, what the
        port forward translated."""
        return ["ct state established,related accept",
                'iifname "eth0" oifname "eth1" accept',
                "ct status dnat accept"]

    def given_tables(self, router: str) -> Dict[str, Dict[str, List[str]]]:
        """The rules loaded at start on *router* (r2, r5, r6): what its part relies on."""
        if router in ("r2", "r5"):
            return {NAT_TABLE: {"postrouting": [self.rule_masquerade(int(router[1]))]}}
        if router == "r6":
            return {NAT_TABLE: {"prerouting": [self.rule_port_forward(6, by_interface=True)],
                                "postrouting": [self.rule_masquerade(6)]}}
        return {}

    def reference_tables(self, router: str) -> Dict[str, Dict[str, List[str]]]:
        """The whole ruleset of *router* in the reference solution (given rules included)."""
        if router == "r1":
            return {NAT_TABLE: {"postrouting": [self.rule_masquerade(1)]}}
        if router == "r2":
            return {NAT_TABLE: {"prerouting": [self.rule_static_in()],
                                "postrouting": [self.rule_static_out(), self.rule_masquerade(2)]}}
        if router == "r3":
            return {NAT_TABLE: {"prerouting": [self.rule_port_forward(3)],
                                "output": [self.rule_port_forward(3)],
                                "postrouting": [self.rule_hairpin()]}}
        if router == "r4":
            return {NAT_TABLE: {"prerouting": [self.rule_load_balancing()]}}
        if router == "r5":
            return {NAT_TABLE: {"prerouting": [self.rule_proxy_exception(), self.rule_proxy()],
                                "postrouting": [self.rule_masquerade(5)]}}
        return {**self.given_tables("r6"), FILTER_TABLE: {"forward": self.rules_forward()}}

    def given_conf(self, router: str) -> str:
        """The ``/etc/nftables.conf`` written and loaded on *router* by `initial`."""
        return CONF_HEADER + render_tables(self.given_tables(router))

    def reference_conf(self, router: str) -> str:
        """The ``/etc/nftables.conf`` of *router* in the reference solution."""
        return CONF_HEADER + render_tables(self.reference_tables(router))

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        for router in self.routers:
            set_sysctl(self, router, NO_REDIRECTS)
            firewall.flush_ruleset(self, router)
        # The rules a part relies on without asking for them: on the visible routers only (a clone
        # gets the ruleset of its router at each evaluation).
        for router in ROUTERS:
            if self.given_tables(router):
                self.file(router, CONF_FILE, self.given_conf(router), permissions=0o644)
                self.cmd(router, f"nft -f {CONF_FILE}")

        # The test HTTP servers: the same ones on the visible machines (the students check their
        # translations by hand with curl) and on their hidden clones (the probes of the
        # evaluation).  A clone answers with the name of the machine it copies.
        for suffix in ("", "_h"):
            for machine, port, name in SERVERS:
                firewall.setup_http_server(self, machine + suffix, port, name)

    @sre_state(user_allowed=False)
    def final(self):
        """The reference solution (every point): the file of each router written and loaded."""
        for router in ROUTERS:
            self.file(router, CONF_FILE, self.reference_conf(router), permissions=0o644)
            self.cmd(router, f"nft -f {CONF_FILE}")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _is_int(answer, expected: int) -> bool:
    return ''.join(ch for ch in (answer or '') if ch.isdigit()) == str(expected)


def _same_ip(answer, expected) -> bool:
    """The address typed by a student (with or without a prefix) is *expected* (an interface or address)."""
    try:
        return ip_address(_norm(answer).split('/')[0]) == ip_address(str(expected).split('/')[0])
    except ValueError:
        return False


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        ext1, ext2 = d.ips.ext1.ip, d.ips.ext2.ip
        wan = {n: ns.wan_ip(n) for n in SITES}        # the public address of each router
        gw = {n: ns.lan_ip(n) for n in SITES}         # its address in its LAN
        lan = {n: ns.lan(n) for n in SITES}
        public2 = d.ips.r2_public.ip
        host = {name: ns.host_ip(name) for name in HOST_SITE}

        # ---- diagnostics, and the ruleset of each router loaded on its clone ----
        for router in ROUTERS:
            clone = router + "_h"
            for m in (router, clone):
                for cmd in ("ip -4 addr", "ip route", "cat /proc/sys/net/ipv4/ip_forward"):
                    self.test(m, cmd, allow_error=True)
            firewall.transplant_ruleset(self, src=router, dst=clone, apply_step=LOAD_STEP)
            self.test(clone, "nft list ruleset", step=PROBE_STEP, allow_error=True)

        # ---- the probes, from and to the clones ----
        def http(src, dst, port):
            """The answer of the test server *dst*:*port* asked from the clone *src*.  Each call
            registers its command: none may sit behind an `and` / `or`."""
            body, _ = firewall.probe_http(self, src, dst, port=port, step=PROBE_STEP)
            return body

        field = firewall.http_field

        # part 1 (r1): pc1 goes out; an Internet host that reaches pc1 keeps its address
        p1_out = http("pc1_h", ext1, SVC_PORT)
        p1_in = http("ext2_h", host["pc1"], 80)
        # part 2 (r2): the second public address leads to srv2; srv2 leaves under it, pc2 does not
        p2_in = http("ext2_h", public2, 80)
        p2_out = http("srv2_h", ext1, SVC_PORT)
        p2_other = http("pc2_h", ext1, SVC_PORT)
        # part 3 (r3): the published port from the Internet, from the router, from the LAN
        p3_wan = http("ext2_h", wan[3], FWD_PORT)
        p3_router = http("r3_h", wan[3], FWD_PORT)
        p3_lan = http("pc3_h", wan[3], FWD_PORT)
        # part 4 (r4): who answers LB_REQUESTS requests in a row.  Sent by the clone of ext1, so that a
        # balancing towards dead addresses (eight time-outs) does not delay the probes the clone of
        # ext2 runs for the other parts.
        p4_servers = firewall.probe_http_backends(self, "ext1_h", wan[4], port=VIP_PORT, n=LB_REQUESTS, step=PROBE_STEP)
        # part 5 (r5): the HTTP of pc5 and of admin, and the port 80 of the WAN side
        p5_lan = http("pc5_h", ext1, 80)
        p5_admin = http("admin_h", ext1, 80)
        p5_wan = http("ext2_h", wan[5], 80)
        # part 6 (r6): the neighbour with a route, the LAN going out, the published service
        p6_rules = firewall.get_nft_json(self, "r6")
        p6_service = http("r6_h", host["srv6"], INTRANET_PORT)
        p6_direct = firewall.probe_tcp_verdict(self, "ext2_h", host["srv6"], INTRANET_PORT, step=PROBE_STEP)
        p6_ping = firewall.probe_ping(self, "ext2_h", host["srv6"], step=PROBE_STEP)
        p6_out = http("srv6_h", ext1, SVC_PORT)
        p6_published = http("ext2_h", wan[6], FWD_PORT)

        # ---- what the probes say ----
        masquerade = field(p1_out, "CLIENT_IP") == str(wan[1])
        inbound_kept = field(p1_in, "SERVER") == "pc1" and field(p1_in, "CLIENT_IP") == str(ext2)

        static_in = field(p2_in, "SERVER") == "srv2"
        static_out = field(p2_out, "CLIENT_IP") == str(public2)
        others_kept = field(p2_other, "CLIENT_IP") == str(wan[2])

        port_forward = field(p3_wan, "SERVER") == "web3" and field(p3_wan, "SERVER_PORT") == "80"
        router_itself = field(p3_router, "SERVER") == "web3"
        hairpin = field(p3_lan, "SERVER") == "web3"
        internet_kept = port_forward and field(p3_wan, "CLIENT_IP") == str(ext2)

        answering = {name for name in p4_servers if name in ("web4a", "web4b")}

        redirect = field(p5_lan, "SERVER") == "proxy"
        wan_spared = field(p5_wan, "SERVER") != "proxy"
        admin_spared = field(p5_admin, "SERVER") == "ext1"

        forward_drop = firewall.hook_policy(p6_rules, "forward") == "drop"
        # the negative probes only mean something while the service runs on the clone
        service_up = field(p6_service, "SERVER") == "intranet"
        intrusion_blocked = service_up and p6_direct in ("dropped", "refused") and not p6_ping
        lan_out = field(p6_out, "SERVER") == "ext1"
        published = field(p6_published, "SERVER") == "srv6"

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        sites = tr("""
| partie | routeur : adresse LAN (`eth0`) / WAN (`eth1`) | réseau privé | machines du site |
|--------|-----------------------------------------------|--------------|------------------|
| 1 | **`r1`** : `{g1}` / `{w1}` | `lan1` : `{l1}` | `pc1` (`{pc1}`) |
| 2 | **`r2`** : `{g2}` / `{w2}` et `{public2}` | `lan2` : `{l2}` | `srv2` (`{srv2}`), `pc2` (`{pc2}`) |
| 3 | **`r3`** : `{g3}` / `{w3}` | `lan3` : `{l3}` | `web3` (`{web3}`), `pc3` (`{pc3}`) |
| 4 | **`r4`** : `{g4}` / `{w4}` | `lan4` : `{l4}` | `web4a` (`{web4a}`), `web4b` (`{web4b}`) |
| 5 | **`r5`** : `{g5}` / `{w5}` | `lan5` : `{l5}` | `pc5` (`{pc5}`), `admin` (`{admin}`) |
| 6 | **`r6`** : `{g6}` / `{w6}` | `lan6` : `{l6}` | `srv6` (`{srv6}`) |
| Internet | | `wan` : `{wan}` | `ext1` (`{ext1}`), `ext2` (`{ext2}`) |
""").format(public2=public2, wan=d.nets.wan, ext1=ext1, ext2=ext2, **host,
            **{f"g{n}": gw[n] for n in SITES}, **{f"w{n}": wan[n] for n in SITES},
            **{f"l{n}": lan[n] for n in SITES})

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente la traduction d'adresses avec nftables (suivi de
connexion, chaînes de type `nat`, SNAT et masquerade, DNAT et redirection de port, NAT statique,
*hairpin*, répartition de charge, `redirect` et proxy transparent, traduction et filtrage) et la
façon de vérifier une traduction.

**La maquette** (onglet *Schéma*). Six petits sites sont reliés au réseau `wan`, qui joue
**Internet**. Chaque site a un routeur `rN`, dont **`eth0` est du côté de son réseau privé `lanN`**
et **`eth1` du côté d'Internet**, et une ou deux machines. Sur `wan` se trouvent aussi `ext1`, un
serveur web d'Internet, et `ext2`, le poste d'un internaute.

**Une partie, un site, un routeur.** La partie N du TP se fait sur le routeur `rN`, et sur lui
seul : les six parties sont **indépendantes**. Faites-les dans l'ordre que vous voulez ; ce que
vous configurez sur un routeur ne change rien aux autres parties.
""")
            + sites
            + tr("""
**Déjà en place** (ne pas modifier) : les adresses ; le routage sur les six routeurs
(`net.ipv4.ip_forward=1`) ; sur chaque machine d'un site, une route par défaut par le routeur du
site. **Comme sur le véritable Internet, `ext1` et `ext2` n'ont aucune route vers les réseaux
privés** : ils ne connaissent que `wan`. Le jeu de règles nftables de `r1`, `r3` et `r4` est vide.
Celui de `r2`, `r5` et `r6` contient déjà quelques règles, présentées au début de leur partie et
écrites dans leur fichier `{conf_file}` : si vous les perdez, `nft -f {conf_file}` les recharge
(et efface les vôtres). `r2` porte deux adresses publiques sur `eth1`. Dans vos commandes,
désignez les machines par leurs adresses (tableau ci-dessus).

**Les serveurs de test** répondent par leur nom et par les adresses des deux bouts de la
connexion, telles qu'ils les voient : `SERVER=`, `SERVER_IP=`, `SERVER_PORT=`, `CLIENT_IP=`,
`CLIENT_PORT=` (section @@ref:test-servers@@ des Informations).

| machine | port | nom (`SERVER=`) |
|---------|------|-----------------|
| `ext1` | 80 et {svc} | `ext1` |
| `pc1`, `srv2`, `web3`, `web4a`, `web4b` | 80 | le nom de la machine |
| `r5` | {proxy} | `proxy` : il tient lieu de proxy web |
| `srv6` | 80 | `srv6` |
| `srv6` | {intranet} | `intranet` : un service interne, qui n'est pas publié |

**Pour tester.** `curl -s -m 5 http://ADRESSE:PORT/ ; echo "code $?"` affiche la réponse du
serveur puis le code de retour de `curl` : **0** avec une réponse, **7** pour un échec immédiat
(connexion refusée), **28** quand le délai de 5 secondes est dépassé (aucune réponse). Chaque
`curl` ouvre une nouvelle connexion : c'est ce qu'il faut pour essayer une règle (section
@@ref:ct-consequences@@). `tcpdump -n -i eth0 tcp` (ou `-i eth1`) montre ce qui circule d'un côté
d'un routeur (section @@ref:capture@@) ; les réseaux de la maquette sont des concentrateurs
(*hubs*) : une machine y voit aussi les paquets destinés à ses voisines. La commande `conntrack`
n'est pas installée sur les machines du TP.

Règles valables pour tout le TP :

- configurez les routeurs avec **`nft`** (pas avec `iptables`). L'évaluation lit le jeu de règles
  **chargé** sur chaque routeur (`nft list ruleset`), pas un fichier : des règles tapées avec `nft`
  suffisent ; si vous écrivez `{conf_file}`, chargez-le (`nft -f {conf_file}`) ;
- ce jeu de règles est **recopié sur une copie cachée du routeur**, entourée de copies cachées des
  machines (mêmes adresses, mêmes serveurs de test), où l'évaluation refait avec `curl` les
  requêtes des questions et lit les réponses. Seul compte donc le jeu de règles chargé sur `rN`,
  pas ce que vous faites sur les autres machines ;
- certaines questions ont un **formulaire** : notez-y ce que vous observez. Ces réponses ne
  comptent pas dans l'auto-évaluation ; elles sont notées avec le reste à la fin du TP ;
- une traduction est décidée au premier paquet d'une connexion : après avoir changé une règle,
  refaites une requête.
""").format(conf_file=CONF_FILE, svc=SVC_PORT, proxy=PROXY_PORT, intranet=INTRANET_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet. L'état `final` (onglet *Appliquer une configuration*) applique toute la solution : il écrit
dans `{conf_file}` de chaque routeur le fichier donné au début de sa partie (questions 1 à 6) et le
charge ; il remplit aussi les formulaires. Il est ré-applicable et donne 100/100.

L'évaluation (miroir caché, `lib/hidden_mirror.py` / `lib/firewall.py`) : `nft list ruleset` sur
`r1` … `r6` (étape 1), chargé tel quel sur leurs copies `r1_h` … `r6_h` après un `nft flush ruleset`
(étape 2), puis les sondes (étape 3) : des `curl -s -m 5` depuis les copies cachées des machines,
une connexion TCP et un `ping` pour la partie 6. Les copies de `ext1` et de `ext2` ont, elles, une
route vers chaque réseau privé par le routeur du site : aucune sonde ne dépend d'une traduction
pour son retour, et la copie de `ext2` joue le voisin qui a ajouté une route. Chaque partie a son
routeur : rien de ce qui est fait dans une partie ne change les points d'une autre. Les éléments
`q_…` (formulaires) ne comptent que dans l'évaluation finale. Barème : 15 + 15 + 22 + 12 + 18 + 18
= 100.
""").format(conf_file=CONF_FILE)),
        )

        # =====================================================================
        # Part 1 — r1: masquerade
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Sortir d'un réseau privé : masquerade"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Sortir d'un réseau privé : masquerade"),
            description=tr("""
**Site 1** : `pc1` (`{pc1}`) dans le réseau privé `lan1` (`{lan}`), derrière **`r1`** (`eth0` :
`{gw}`, `eth1` : `{wan}`). Le jeu de règles de `r1` est vide.

**But** : les machines de `lan1` accèdent à Internet sous l'adresse publique de `r1`. **À lire** :
sections @@ref:snat@@, @@ref:chains@@ et @@ref:conntrack@@ des Informations.
""").format(pc1=host["pc1"], lan=lan[1], gw=gw[1], wan=wan[1])
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r1` (état `final`) :

```
{conf}```

Barème de la partie : `masquerade` 6, `masquerade_scope` 3, formulaires `q_without_nat` 2 et
`q_masquerade` 4.
""").format(conf=ns.reference_conf("r1"))),
        )

        q11_answers = {"src_seen": str(host["pc1"]), "outcome": "timeout"}
        q11 = self.question_form(
            section=self.section(1),
            title=tr("Sans traduction"),
            description=tr("""
**(a)** Sur `ext1`, lancez une capture : `tcpdump -n -i eth0 tcp port {svc}`.

**(b)** Sur `pc1`, interrogez le serveur d'Internet :
`curl -s -m 5 http://{ext1}:{svc}/ ; echo "code $?"`.

**(c)** Lisez la capture. Les paquets de `pc1` arrivent-ils à `ext1` ? Sous quelle adresse
source ? `ext1` leur répond-il ? Affichez sa table de routage (`ip route`) : connaît-il un chemin
vers `{lan}` ? C'est la situation de toute machine d'Internet devant une adresse privée (section
@@ref:why@@).
""").format(svc=SVC_PORT, ext1=ext1, lan=lan[1])
            + tr("""
- Adresse source des paquets que reçoit `ext1` : @@{src_seen:[0-9.]+}@@
- Résultat du `curl` lancé sur `pc1` : @@{outcome:>une réponse de ext1 (code 0)>>>answer|un échec immédiat (code 7)>>>refused|aucune réponse, délai dépassé (code 28)>>>timeout}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer. `r1` route le paquet tel quel : la capture de `ext1` montre les
SYN de `{pc1}` vers `{ext1}.{svc}` (`Flags [S]`, répétés après 1 s, 2 s…) et aucune réponse. `ip
route` sur `ext1` n'affiche que `{wan_net}` : `ext1` n'a aucun chemin vers `{lan}` et ne peut pas
répondre à une adresse privée. `curl` attend ses 5 secondes : `code 28`.

- Réponses : `{pc1}` ; aucune réponse, délai dépassé.
- Cette question n'est évaluée que par le formulaire (`q_without_nat`, 1 point par réponse).
""").format(pc1=host["pc1"], ext1=ext1, svc=SVC_PORT, wan_net=d.nets.wan, lan=lan[1])),
            cheat_answers={"final": q11_answers},
        )
        self.add_grade_element(
            title=no_tr("q_without_nat"), max_grade=2, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q11.get("src_seen"), host["pc1"])) + int(_norm(q11.get("outcome")) == "timeout"),
            description=tr("sans traduction : l'adresse privée de pc1 arrive à ext1, qui ne peut pas répondre"),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("La règle masquerade"),
            description=tr("""
Sur **`r1`** :

**(a)** créez une table `ip nat` et, dans cette table, une chaîne de base de type `nat` accrochée
au hook `postrouting` (section @@ref:nat-table@@) ;

**(b)** ajoutez-y la règle qui remplace l'adresse source par celle de `r1` (`masquerade`, section
@@ref:masquerade@@) pour les connexions qui **viennent de `lan1`** (`{lan}`) et qui **sortent par
`eth1`** : ces deux critères font partie de la règle (section @@ref:snat-scope@@) ;

**(c)** vérifiez : `nft list ruleset` sur `r1`, puis sur `pc1` le `curl` de la question
précédente. `ext1` répond maintenant (`code 0`).

Ce qui **entre** dans `lan1` ne doit pas être traduit : l'évaluation vérifie aussi qu'une machine
d'Internet qui atteint `pc1` est vue par `pc1` sous sa propre adresse. Pour l'essayer vous-même :
sur `ext2`, `ip route add {lan} via {wan}` (un voisin de `r1` qui s'ajoute une route vers le
réseau privé), puis `curl -s -m 5 http://{pc1}/` : `CLIENT_IP` doit être `{ext2}`, pas `{gw}`.
""").format(lan=lan[1], wan=wan[1], pc1=host["pc1"], ext2=ext2, gw=gw[1])
            + instructor(tr("""
**Solution.** Sur `r1` :

```
{conf}```

En ligne de commande : `nft add table {table}`, `{chain}` puis `{rule}`. L'adresse publique de
`r1` étant fixe, `ip saddr {lan} oifname "eth1" snat to {wan}` convient aussi.

Vérification : sur `pc1`, `curl -s -m 5 http://{ext1}:{svc}/` renvoie `SERVER=ext1` et
`CLIENT_IP={wan}`.

Pièges : une chaîne de type `filter` (`nft` y refuse `masquerade` : `Error: Could not process
rule: Operation not supported`) ; `oifname "eth0"` (le LAN) au lieu de `"eth1"` ; un `masquerade`
sans aucun critère, qui traduit aussi ce qui entre (`pc1` voit alors `ext2` sous l'adresse
`{gw}`).

- L'évaluation : `masquerade` (6 points : depuis la copie de `pc1`, `curl` vers
  `http://{ext1}:{svc}/` doit renvoyer `CLIENT_IP={wan}`) et `masquerade_scope` (3 points, comptés
  seulement avec le précédent : depuis la copie de `ext2`, qui a une route vers `{lan}`, `curl`
  vers `http://{pc1}/` doit renvoyer `SERVER=pc1` et `CLIENT_IP={ext2}`).
""").format(conf=render_tables(ns.reference_tables("r1")), table=NAT_TABLE,
            chain=nft_chain(NAT_TABLE, "postrouting"),
            rule=nft_rule(NAT_TABLE, "postrouting", ns.rule_masquerade(1)),
            lan=lan[1], wan=wan[1], gw=gw[1], ext1=ext1, ext2=ext2, svc=SVC_PORT, pc1=host["pc1"])),
        )
        self.add_grade_element(
            title=no_tr("masquerade"), max_grade=6, grade_part=part1, grade=6 * int(masquerade),
            description=tr("pc1 sort vers Internet sous l'adresse publique de r1"),
        )
        self.add_grade_element(
            title=no_tr("masquerade_scope"), max_grade=3, grade_part=part1,
            grade=3 * int(masquerade and inbound_kept),
            description=tr("ce qui entre dans lan1 n'est pas traduit (compté avec le masquerade)"),
        )

        q13_answers = {"client_ip": str(wan[1]), "src_lan": str(host["pc1"]), "src_wan": str(wan[1]),
                       "return_rule": "none"}
        q13 = self.question_form(
            section=self.section(1),
            title=tr("Observer la traduction"),
            description=tr("""
**(a)** Sur `pc1`, `curl -s -m 5 http://{ext1}:{svc}/` : lisez `CLIENT_IP=` dans la réponse de
`ext1`.

**(b)** Sur `r1`, capturez des deux côtés du routeur, dans deux terminaux :
`tcpdump -n -i eth0 tcp port {svc}` et `tcpdump -n -i eth1 tcp port {svc}`. Refaites la requête
et comparez, dans les deux captures, le premier paquet de la connexion (`Flags [S]`) : c'est le
même paquet, avant et après sa traduction (section @@ref:capture@@).

**(c)** Les réponses de `ext1` arrivent à l'adresse de `r1` et parviennent pourtant à `pc1`.
Quelle règle avez-vous écrite pour elles (section @@ref:first-packet@@) ?
""").format(ext1=ext1, svc=SVC_PORT)
            + tr("""
- `CLIENT_IP=` dans la réponse de `ext1` : @@{client_ip:[0-9.]+}@@
- Adresse source du premier paquet sur `eth0` de `r1` : @@{src_lan:[0-9.]+}@@
- Adresse source du même paquet sur `eth1` de `r1` : @@{src_wan:[0-9.]+}@@
- Pour les réponses de `ext1`, vous avez écrit : @@{return_rule:>une règle dnat dans une chaîne prerouting>>>dnat|aucune règle : le suivi de connexion les traduit en sens inverse>>>none|une seconde règle masquerade>>>masquerade}@@
""")
            + instructor(tr("""
**Solution.** `CLIENT_IP={wan}` : `ext1` ne voit que l'adresse publique de `r1`. Sur `eth0`, le
SYN va de `{pc1}` à `{ext1}.{svc}` ; sur `eth1`, le même SYN part de `{wan}` (le port source est
conservé quand il est libre). Aucune règle pour le retour : la traduction, décidée au premier
paquet, est inscrite dans l'entrée de la connexion, et les réponses sont traduites en sens inverse
(elles retrouvent `{pc1}` comme destination dès `prerouting`, avant le routage).

- Réponses : `{wan}` ; `{pc1}` ; `{wan}` ; aucune règle.
- Cette question n'est évaluée que par le formulaire (`q_masquerade`, 1 point par réponse).
""").format(wan=wan[1], pc1=host["pc1"], ext1=ext1, svc=SVC_PORT)),
            cheat_answers={"final": q13_answers},
        )
        self.add_grade_element(
            title=no_tr("q_masquerade"), max_grade=4, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q13.get("client_ip"), wan[1])) + int(_same_ip(q13.get("src_lan"), host["pc1"]))
                  + int(_same_ip(q13.get("src_wan"), wan[1])) + int(_norm(q13.get("return_rule")) == "none"),
            description=tr("la traduction observée : ce que voit ext1, le paquet des deux côtés de r1, le retour"),
        )

        # =====================================================================
        # Part 2 — r2: static 1:1 NAT
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — NAT statique : une adresse publique pour un serveur"))

        self.question_dummy(
            section=self.section(0),
            title=tr("NAT statique : une adresse publique pour un serveur"),
            description=tr("""
**Site 2** : `srv2` (`{srv2}`) et `pc2` (`{pc2}`) dans `lan2` (`{lan}`), derrière **`r2`** (`eth0` :
`{gw}`). `r2` a **deux adresses publiques** sur `eth1` : `{wan}`, son adresse principale, et
`{public2}`, réservée à `srv2`. Son jeu de règles fait déjà sortir `lan2` sous l'adresse
principale :

```
{given}```

**But** : `srv2` est joignable d'Internet à l'adresse `{public2}` et sort sous cette même adresse ;
les autres machines de `lan2` continuent de sortir sous l'adresse principale. **À lire** : sections
@@ref:static-nat@@, @@ref:snat-to@@ et @@ref:nat-rules@@ des Informations.
""").format(srv2=host["srv2"], pc2=host["pc2"], lan=lan[2], gw=gw[2], wan=wan[2], public2=public2,
            given=render_tables(ns.given_tables("r2")))
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r2` (état `final`) :

```
{conf}```

Barème de la partie : `static_in` 5, `static_out` 5, `static_scope` 2, formulaire `q_static` 3.
""").format(conf=ns.reference_conf("r2"))),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("Ce qui entre : dnat"),
            description=tr("""
**(a)** L'état de départ : sur `r2`, `ip -4 addr show dev eth1` (les deux adresses) et `nft list
ruleset`. Depuis `ext2`, `curl -s -m 5 http://{public2}/ ; echo "code $?"` : échec immédiat, rien
n'écoute sur le port 80 de `r2`. `ping -c 1 {public2}` aboutit, lui : c'est `r2` qui répond
(`ttl=64`), l'adresse est la sienne.

**(b)** Dans la table `ip nat` de `r2`, créez une chaîne de base de type `nat` accrochée au hook
`prerouting`, et la règle qui envoie à `srv2` (`{srv2}`) **tout ce qui est destiné à
`{public2}`** : critère `ip daddr`, action `dnat to` sans port ni protocole (section
@@ref:dnat-to@@).

**(c)** Vérifiez depuis `ext2` : le même `curl` renvoie `SERVER=srv2`. Le `ping` affiche
maintenant `ttl=63` : c'est `srv2` qui répond, un routeur plus loin.
""").format(public2=public2, srv2=host["srv2"])
            + instructor(tr("""
**Solution.** Sur `r2` : `{chain}` puis `{rule}`, soit dans la table `{table}` :

```
{conf}```

Vérification : depuis `ext2`, `curl -s -m 5 http://{public2}/` renvoie `SERVER=srv2`,
`SERVER_IP={srv2}` et `CLIENT_IP={ext2}`. `r2` répond aux requêtes ARP pour `{public2}`, qui est
une de ses adresses ; la règle n'a ni protocole ni port : tout ce qui vise cette adresse va à
`srv2`, ports conservés.

Pièges : `iifname "eth1"` sans `ip daddr` (tout ce qui arrive d'Internet irait à `srv2`, y compris
ce qui vise `{wan}`) ; la règle écrite dans la chaîne `postrouting`.

- L'évaluation : `static_in` (5 points : depuis la copie de `ext2`, `curl` vers
  `http://{public2}/` doit renvoyer `SERVER=srv2`).
""").format(chain=nft_chain(NAT_TABLE, "prerouting"), rule=nft_rule(NAT_TABLE, "prerouting", ns.rule_static_in()),
            table=NAT_TABLE, conf=render_tables({NAT_TABLE: {"prerouting": [ns.rule_static_in()]}}),
            public2=public2, srv2=host["srv2"], ext2=ext2, wan=wan[2])),
        )
        self.add_grade_element(
            title=no_tr("static_in"), max_grade=5, grade_part=part2, grade=5 * int(static_in),
            description=tr("la seconde adresse publique de r2 mène à srv2"),
        )

        q22_answers = {"client_srv2": str(public2), "client_pc2": str(wan[2]), "appended": "primary"}
        q22 = self.question_form(
            section=self.section(1),
            title=tr("Ce qui sort : snat, et l'ordre des règles"),
            description=tr("""
**(a)** Depuis `srv2`, `curl -s -m 5 http://{ext1}:{svc}/` : sous quelle adresse `ext1` voit-il
`srv2` pour l'instant ? C'est l'effet de la règle `masquerade` déjà en place.

**(b)** Dans la chaîne `postrouting` **existante**, ajoutez la règle qui fait sortir `srv2` sous
son adresse publique : `snat to {public2}` pour ce qui vient de `{srv2}` et sort par `eth1`
(section @@ref:snat-to@@). Dans une chaîne `nat`, **la première règle qui convient décide**
(section @@ref:nat-rules@@) : la vôtre doit être évaluée **avant** la règle `masquerade`. `nft add
rule` l'ajouterait après ; utilisez `nft insert rule`, qui place la règle en tête de la chaîne.

**(c)** Vérifiez l'ordre (`nft list ruleset`), puis refaites la requête depuis `srv2` et depuis
`pc2`.
""").format(ext1=ext1, svc=SVC_PORT, public2=public2, srv2=host["srv2"])
            + tr("""
- `CLIENT_IP=` vu par `ext1` pour une requête de `srv2`, une fois votre règle en place : @@{client_srv2:[0-9.]+}@@
- `CLIENT_IP=` vu par `ext1` pour une requête de `pc2` : @@{client_pc2:[0-9.]+}@@
- Si votre règle `snat` était placée après la règle `masquerade`, `ext1` verrait `srv2` sous : @@{appended:>son adresse privée>>>private|la seconde adresse publique de r2>>>second|l'adresse principale de r2>>>primary}@@
""")
            + instructor(tr("""
**Solution.** Sur `r2` : `{rule}`, ce qui donne la chaîne :

```
{conf}```

Avant la règle, `ext1` voit `srv2` sous `{wan}` (la règle `masquerade` donnée) ; après,
`CLIENT_IP={public2}` pour `srv2` et toujours `CLIENT_IP={wan}` pour `pc2`. Ajoutée avec `nft add
rule`, la règle `snat` viendrait après la règle `masquerade`, qui convient déjà à `srv2` et décide :
elle ne serait jamais atteinte, et `srv2` sortirait encore sous `{wan}`.

Différence entre les deux actions : `snat to` écrit l'adresse dans la règle (ici la seconde
adresse de l'interface) ; `masquerade` prend l'adresse principale de l'interface de sortie.

Pièges : une règle `snat` sans `ip saddr` (toutes les machines de `lan2` sortiraient sous
`{public2}`) ; la règle créée dans une seconde chaîne `postrouting` de priorité plus grande que
celle de la chaîne donnée : elle ne décide pas non plus.

- Réponses : `{public2}` ; `{wan}` ; l'adresse principale de `r2`.
- L'évaluation : `static_out` (5 points : depuis la copie de `srv2`, `curl` vers
  `http://{ext1}:{svc}/` doit renvoyer `CLIENT_IP={public2}`), `static_scope` (2 points, comptés
  avec le précédent : depuis la copie de `pc2`, `CLIENT_IP={wan}`) et le formulaire `q_static`
  (1 point par réponse).
""").format(rule=nft_rule(NAT_TABLE, "postrouting", ns.rule_static_out(), verb="insert"),
            conf=render_tables({NAT_TABLE: {"postrouting": [ns.rule_static_out(), ns.rule_masquerade(2)]}}),
            wan=wan[2], public2=public2, ext1=ext1, svc=SVC_PORT)),
            cheat_answers={"final": q22_answers},
        )
        self.add_grade_element(
            title=no_tr("static_out"), max_grade=5, grade_part=part2, grade=5 * int(static_out),
            description=tr("srv2 sort vers Internet sous la seconde adresse publique de r2"),
        )
        self.add_grade_element(
            title=no_tr("static_scope"), max_grade=2, grade_part=part2, grade=2 * int(static_out and others_kept),
            description=tr("pc2 sort toujours sous l'adresse principale de r2 (compté avec la sortie de srv2)"),
        )
        self.add_grade_element(
            title=no_tr("q_static"), max_grade=3, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q22.get("client_srv2"), public2)) + int(_same_ip(q22.get("client_pc2"), wan[2]))
                  + int(_norm(q22.get("appended")) == "primary"),
            description=tr("NAT statique : les adresses vues par ext1, l'effet de l'ordre des règles"),
        )

        # =====================================================================
        # Part 3 — r3: publishing a server (port forward, the router itself, hairpin)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Publier un serveur : redirection de port"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Publier un serveur : redirection de port"),
            description=tr("""
**Site 3** : le serveur `web3` (`{web3}`) et le poste `pc3` (`{pc3}`) dans `lan3` (`{lan}`),
derrière **`r3`** (`eth0` : `{gw}`, `eth1` : `{wan}`). Le jeu de règles de `r3` est vide.

**But** : le port {fwd} de l'adresse publique de `r3` mène au port 80 de `web3`, pour un client
d'Internet, puis pour `r3` lui-même, puis pour les machines de `lan3`. **À lire** : section
@@ref:dnat@@ des Informations.
""").format(web3=host["web3"], pc3=host["pc3"], lan=lan[3], gw=gw[3], wan=wan[3], fwd=FWD_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r3` (état `final`) :

```
{conf}```

Barème de la partie : `port_forward` 6, `router_itself` 4, `hairpin` 6, `hairpin_scope` 2,
formulaires `q_publish` 2 et `q_hairpin` 2.
""").format(conf=ns.reference_conf("r3"))),
        )

        q31_answers = {"server_ip": str(host["web3"]), "client_ip": str(ext2)}
        q31 = self.question_form(
            section=self.section(1),
            title=tr("Depuis Internet"),
            description=tr("""
**(a)** Depuis `ext2` : `curl -s -m 5 http://{wan}:{fwd}/ ; echo "code $?"`. Échec immédiat : rien
n'écoute sur le port {fwd} de `r3`.

**(b)** Sur `r3`, créez une table `ip nat`, une chaîne de base de type `nat` accrochée au hook
`prerouting` (priorité `dstnat`) et la règle de redirection de port : ce qui **arrive par `eth1`**
sur le port TCP {fwd} est envoyé au **port 80 de `web3`** (`{web3}`) (section @@ref:dnat-to@@).

**(c)** Refaites la requête depuis `ext2` et lisez la réponse. Sur `web3`, `tcpdump -n -i eth0 tcp
port 80` montre la connexion telle qu'elle lui arrive. Par où la réponse de `web3` repart-elle, et
sous quelle adresse source `ext2` la reçoit-il (section @@ref:return-path@@) ?
""").format(wan=wan[3], fwd=FWD_PORT, web3=host["web3"])
            + tr("""
- `SERVER_IP=` dans la réponse reçue par `ext2` : @@{server_ip:[0-9.]+}@@
- `CLIENT_IP=` dans cette réponse : @@{client_ip:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `r3` : `nft add table {table}`, `{chain}` puis `{rule}`, soit :

```
{conf}```

Vérification : depuis `ext2`, `curl -s -m 5 http://{wan}:{fwd}/` renvoie `SERVER=web3`,
`SERVER_IP={web3}`, `SERVER_PORT=80` et `CLIENT_IP={ext2}` : seule la destination a changé, le
serveur voit le vrai client. Sa réponse repart par sa route par défaut, donc par `r3`, qui lui
rend `{wan}` (port {fwd}) comme source : `ext2` n'a besoin d'aucune route vers `{lan}`.

Pièges : la règle écrite dans une chaîne `postrouting` (`nft` refuse `dnat` à ce hook) ;
`iifname "eth0"` ; un `dnat to {web3}` sans port (le port {fwd} serait conservé, et rien n'y
écoute sur `web3`) ; le test lancé depuis `pc3` ou depuis `r3`, que cette règle ne concerne pas
(questions suivantes).

- Réponses : `{web3}` ; `{ext2}`.
- L'évaluation : `port_forward` (6 points : depuis la copie de `ext2`, `curl` vers
  `http://{wan}:{fwd}/` doit renvoyer `SERVER=web3` et `SERVER_PORT=80`) et le formulaire
  `q_publish` (1 point par réponse).
""").format(table=NAT_TABLE, chain=nft_chain(NAT_TABLE, "prerouting"),
            rule=nft_rule(NAT_TABLE, "prerouting", ns.rule_port_forward(3, by_interface=True)),
            conf=render_tables({NAT_TABLE: {"prerouting": [ns.rule_port_forward(3, by_interface=True)]}}),
            wan=wan[3], fwd=FWD_PORT, web3=host["web3"], ext2=ext2, lan=lan[3])),
            cheat_answers={"final": q31_answers},
        )
        self.add_grade_element(
            title=no_tr("port_forward"), max_grade=6, grade_part=part3, grade=6 * int(port_forward),
            description=tr("d'Internet, le port {port} de r3 mène au port 80 de web3").format(port=FWD_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_publish"), max_grade=2, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q31.get("server_ip"), host["web3"])) + int(_same_ip(q31.get("client_ip"), ext2)),
            description=tr("redirection de port : le serveur qui répond et le client qu'il voit"),
        )

        self.question_dummy(
            section=self.section(1),
            title=tr("Depuis le routeur lui-même"),
            description=tr("""
**(a)** Sur `r3` : `curl -s -m 5 http://{wan}:{fwd}/ ; echo "code $?"`. Échec immédiat, alors que
la règle de la question précédente est en place : ce que `r3` émet lui-même ne passe pas par
`prerouting` (section @@ref:nat-output@@).

**(b)** Ajoutez à la table `ip nat` une chaîne de base de type `nat` accrochée au hook
**`output`**, de priorité `-100`, et dans cette chaîne la règle qui redirige vers le port 80 de
`web3` ce qui est destiné au port TCP {fwd} de `{wan}`. Le critère est ici l'adresse visée (`ip
daddr`) : un paquet émis par la machine n'a pas d'interface d'entrée.

**(c)** Refaites le `curl` sur `r3` : `SERVER=web3`. Sous quelle adresse `web3` voit-il `r3` ?
""").format(wan=wan[3], fwd=FWD_PORT)
            + instructor(tr("""
**Solution.** Sur `r3` : `{chain}` puis `{rule}`, soit :

```
{conf}```

Vérification : sur `r3`, `curl -s -m 5 http://{wan}:{fwd}/` renvoie `SERVER=web3` et
`CLIENT_IP={wan}` : `r3` a choisi son adresse source avant la traduction (il s'adressait à
lui-même), le paquet est ensuite routé vers `web3`, dont la réponse revient à `r3`. Aucune règle
`postrouting` n'est nécessaire.

Pièges : la priorité écrite `dstnat`, que nftables 1.0.6 n'accepte pas au hook `output` (`Error:
invalid priority expression value in this context` : écrire `-100`) ; `iifname` dans la règle ;
croire que la chaîne `prerouting` suffit.

- L'évaluation : `router_itself` (4 points : sur la copie de `r3`, `curl` vers
  `http://{wan}:{fwd}/` doit renvoyer `SERVER=web3`).
""").format(chain=nft_chain(NAT_TABLE, "output"), rule=nft_rule(NAT_TABLE, "output", ns.rule_port_forward(3)),
            conf=render_tables({NAT_TABLE: {"output": [ns.rule_port_forward(3)]}}), wan=wan[3], fwd=FWD_PORT)),
        )
        self.add_grade_element(
            title=no_tr("router_itself"), max_grade=4, grade_part=part3, grade=4 * int(router_itself),
            description=tr("r3 lui-même atteint web3 par son adresse publique (chaîne nat du hook output)"),
        )

        q33_answers = {"reply_src": str(host["web3"]), "client_after": str(gw[3])}
        q33 = self.question_form(
            section=self.section(1),
            title=tr("Depuis le réseau interne : hairpin"),
            description=tr("""
`pc3` veut joindre le serveur par son adresse publique, comme tout le monde (section
@@ref:hairpin@@).

**(a)** Depuis `pc3` : `curl -s -m 5 http://{wan}:{fwd}/ ; echo "code $?"`. Échec immédiat (`code
7`) : la règle de la question 3.1 ne vaut que pour ce qui arrive par `eth1`, et le paquet de `pc3`
arrive par `eth0`.

**(b)** Faites en sorte que la redirection vaille quelle que soit l'interface d'arrivée : dans la
chaîne `prerouting`, désignez **l'adresse visée** (`ip daddr {wan}`) au lieu de l'interface, en
remplaçant la règle de la question 3.1 ou en en ajoutant une seconde.

**(c)** Sur `pc3`, lancez `tcpdump -n -i eth0 tcp` dans un second terminal et refaites la requête :
cette fois le délai est dépassé (`code 28`). Dans la capture, `pc3` s'adresse à `{wan}.{fwd}` ; de
quelle adresse vient la réponse qu'il reçoit (`Flags [S.]`), et qu'en fait-il (`Flags [R]`) ? (Le
réseau étant un concentrateur, la capture montre aussi la copie du paquet que `r3` fait suivre à
`web3`.)

**(d)** Obligez `web3` à répondre à `r3` : dans une chaîne de base de type `nat` accrochée au hook
`postrouting`, ajoutez une règle `masquerade` pour les connexions qui **viennent de `lan3`**
(`{lan}`) et **vont au port 80 de `web3`** (`{web3}`). Refaites la requête depuis `pc3` :
`SERVER=web3` ; lisez `CLIENT_IP`. Vérifiez enfin, depuis `ext2`, que `web3` voit toujours un
client d'Internet sous sa vraie adresse.
""").format(wan=wan[3], fwd=FWD_PORT, lan=lan[3], web3=host["web3"])
            + tr("""
- À l'étape (c), adresse source de la réponse `Flags [S.]` que reçoit `pc3` : @@{reply_src:[0-9.]+}@@
- À l'étape (d), `CLIENT_IP=` dans la réponse que reçoit `pc3` : @@{client_after:[0-9.]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `r3`, la règle de redirection désigne l'adresse visée, et une règle
`masquerade` traduit la source des clients internes :

```
{conf}```

En ligne de commande : `nft flush chain {table} prerouting`, `{forward}`, `{chain}` puis
`{hairpin}`.

Les trois étapes vues de `pc3` : (a) le paquet arrive par `eth0`, aucune règle ne lui convient, il
est destiné à `r3` lui-même où rien n'écoute sur le port {fwd} : refus immédiat, `code 7` ; (c) la
destination est traduite, `web3` reçoit un SYN de `{pc3}` et répond **directement** à `pc3`, qui
est dans son réseau : `pc3` reçoit un `Flags [S.]` de `{web3}.80` alors qu'il s'est adressé à
`{wan}.{fwd}`, il le rejette (`Flags [R]`) et `curl` attend en vain, `code 28` ; (d) `web3` voit
`r3` comme client et lui répond : `SERVER=web3`, `CLIENT_IP={gw}`.

Pièges : une règle `masquerade` sans `ip saddr {lan}` (par exemple `oifname "eth0" masquerade`),
qui traduit aussi les clients d'Internet : `web3` ne verrait plus que `{gw}` ; `oifname "eth1"`
par habitude (ces connexions sortent par `eth0`).

- Réponses : `{web3}` ; `{gw}`.
- L'évaluation : `hairpin` (6 points : depuis la copie de `pc3`, `curl` vers
  `http://{wan}:{fwd}/` doit renvoyer `SERVER=web3`), `hairpin_scope` (2 points, comptés avec le
  précédent : la requête de la copie de `ext2` renvoie toujours `CLIENT_IP={ext2}`) et le
  formulaire `q_hairpin` (1 point par réponse).
""").format(conf=render_tables({NAT_TABLE: {"prerouting": [ns.rule_port_forward(3)],
                                            "postrouting": [ns.rule_hairpin()]}}),
            table=NAT_TABLE, forward=nft_rule(NAT_TABLE, "prerouting", ns.rule_port_forward(3)),
            chain=nft_chain(NAT_TABLE, "postrouting"), hairpin=nft_rule(NAT_TABLE, "postrouting", ns.rule_hairpin()),
            fwd=FWD_PORT, pc3=host["pc3"], web3=host["web3"], wan=wan[3], gw=gw[3], lan=lan[3], ext2=ext2)),
            cheat_answers={"final": q33_answers},
        )
        self.add_grade_element(
            title=no_tr("hairpin"), max_grade=6, grade_part=part3, grade=6 * int(hairpin),
            description=tr("une machine de lan3 atteint web3 par l'adresse publique de r3 (hairpin)"),
        )
        self.add_grade_element(
            title=no_tr("hairpin_scope"), max_grade=2, grade_part=part3, grade=2 * int(hairpin and internet_kept),
            description=tr("web3 voit toujours les clients d'Internet sous leur adresse (compté avec le hairpin)"),
        )
        self.add_grade_element(
            title=no_tr("q_hairpin"), max_grade=2, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q33.get("reply_src"), host["web3"])) + int(_same_ip(q33.get("client_after"), gw[3])),
            description=tr("hairpin : d'où vient la réponse sans traduction de source, ce que voit web3 ensuite"),
        )

        # =====================================================================
        # Part 4 — r4: load balancing
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Répartir la charge entre deux serveurs"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Répartir la charge entre deux serveurs"),
            description=tr("""
**Site 4** : deux serveurs web identiques, `web4a` (`{web4a}`) et `web4b` (`{web4b}`), dans `lan4`
(`{lan}`), derrière **`r4`** (`eth0` : `{gw}`, `eth1` : `{wan}`). Le jeu de règles de `r4` est
vide.

**But** : les connexions qui arrivent d'Internet sur le port {vip} de `r4` sont réparties à tour
de rôle entre les deux serveurs. **À lire** : section @@ref:load-balancing@@ des Informations.
""").format(web4a=host["web4a"], web4b=host["web4b"], lan=lan[4], gw=gw[4], wan=wan[4], vip=VIP_PORT)
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r4` (état `final`) :

```
{conf}```

Barème de la partie : `load_balancing` 9, formulaire `q_balancing` 3.
""").format(conf=ns.reference_conf("r4"))),
        )

        q41_answers = {"unit": "connection", "client_ip": str(ext2), "failure": "keeps"}
        q41 = self.question_form(
            section=self.section(1),
            title=tr("Le tourniquet numgen"),
            description=tr("""
**(a)** Sur `r4`, créez une table `ip nat`, une chaîne de base `prerouting` de type `nat`, et une
règle `dnat to numgen inc mod 2 map {{ … }}` pour ce qui arrive par `eth1` sur le port TCP {vip} :
un **tourniquet strict** (`inc`) entre `{web4a}` et `{web4b}` (section @@ref:numgen@@). Entourez
d'apostrophes ce qui suit `nft` : le shell interpréterait les accolades.

**(b)** Depuis `ext2`, envoyez huit requêtes :
`for i in 1 2 3 4 5 6 7 8; do curl -s -m 5 http://{wan}/ | grep SERVER=; done`. `web4a` et `web4b`
doivent alterner.

**(c)** Lisez `CLIENT_IP=` dans une réponse complète de `web4b`. Tous les paquets d'une même
requête vont-ils au même serveur (section @@ref:lb-limits@@) ?

**(d)** Facultatif : remplacez `numgen inc mod 2` par `jhash ip saddr mod 2` et refaites l'étape
(b) depuis `ext2`, puis depuis `ext1` : que constatez-vous (section @@ref:jhash@@) ? **Remettez
ensuite le tourniquet** : l'évaluation envoie huit requêtes d'un même client et attend des
réponses des deux serveurs.
""").format(vip=VIP_PORT, web4a=host["web4a"], web4b=host["web4b"], wan=wan[4])
            + tr("""
- La répartition se fait : @@{unit:>paquet par paquet>>>packet|connexion par connexion>>>connection|octet par octet>>>byte}@@
- `CLIENT_IP=` dans une réponse de `web4b` à `ext2` : @@{client_ip:[0-9.]+}@@
- Si `web4b` tombe en panne, `r4` : @@{failure:>le détecte et envoie tout à web4a>>>detects|renvoie une erreur aux clients>>>error|continue de lui envoyer une connexion sur deux>>>keeps}@@
""")
            + instructor(tr("""
**Solution.** Sur `r4` : `nft add table {table}`, `{chain}` puis `{rule}`, soit :

```
{conf}```

`numgen inc mod 2` est un compteur qui vaut 0, 1, 0, 1… ; le dictionnaire associe 0 à `web4a` et
1 à `web4b`, et le port ({vip}) est conservé. La règle n'est parcourue que par le premier paquet
de chaque connexion : les connexions alternent, tous les paquets d'une connexion vont au même
serveur, et le serveur voit le vrai client (`CLIENT_IP={ext2}`). Rien ne surveille les serveurs :
si l'un s'arrête, une connexion sur deux échoue.

Variantes : `numgen random mod 2` répartit au hasard (les huit requêtes de l'évaluation tombent
sur le même serveur une fois sur 128) ; `jhash ip saddr mod 2` envoie toujours un même client au
même serveur et ne rapporte que 4 points sur 9, comme un simple `dnat to {web4a}`.

- Réponses : connexion par connexion ; `{ext2}` ; continue de lui envoyer une connexion sur deux.
- L'évaluation : `load_balancing` ({n} `curl` vers `http://{wan}/?probe=N` depuis la copie de
  `ext1`, un client d'Internet comme un autre : 9 points si `web4a` **et** `web4b` répondent, 4 si
  un seul des deux répond) et le formulaire `q_balancing` (1 point par réponse).
""").format(table=NAT_TABLE, chain=nft_chain(NAT_TABLE, "prerouting"),
            rule=nft_rule(NAT_TABLE, "prerouting", ns.rule_load_balancing()),
            conf=render_tables(ns.reference_tables("r4")), vip=VIP_PORT, ext2=ext2, web4a=host["web4a"],
            wan=wan[4], n=LB_REQUESTS)),
            cheat_answers={"final": q41_answers},
        )
        self.add_grade_element(
            title=no_tr("load_balancing"), max_grade=9, grade_part=part4,
            grade=(9 if len(answering) == 2 else 4 * len(answering)),
            description=tr("les connexions au port {port} de r4 sont réparties entre web4a et web4b").format(port=VIP_PORT),
        )
        self.add_grade_element(
            title=no_tr("q_balancing"), max_grade=3, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q41.get("unit")) == "connection") + int(_same_ip(q41.get("client_ip"), ext2))
                  + int(_norm(q41.get("failure")) == "keeps"),
            description=tr("répartition de charge : par connexion, sans traduction de source ni surveillance"),
        )

        # =====================================================================
        # Part 5 — r5: transparent proxy and its exception
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Proxy transparent"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Proxy transparent"),
            description=tr("""
**Site 5** : les postes `pc5` (`{pc5}`) et `admin` (`{admin}`) dans `lan5` (`{lan}`), derrière
**`r5`** (`eth0` : `{gw}`, `eth1` : `{wan}`). Sur `r5`, un serveur de test nommé `proxy` écoute sur
le port {proxy} : il tient lieu de proxy web. Le jeu de règles de `r5` fait déjà sortir `lan5`
sous son adresse publique :

```
{given}```

**But** : le HTTP (port 80) que les machines de `lan5` envoient vers Internet est remis au proxy
de `r5`, sans rien configurer sur les postes ; celui du poste `admin` y échappe. **À lire** :
section @@ref:redirect@@ des Informations.
""").format(pc5=host["pc5"], admin=host["admin"], lan=lan[5], gw=gw[5], wan=wan[5], proxy=PROXY_PORT,
            given=render_tables(ns.given_tables("r5")))
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r5` (état `final`) :

```
{conf}```

Barème de la partie : `redirect` 6, `redirect_lan_only` 2, `proxy_exception` 5, formulaires
`q_proxy` 3 et `q_exception` 2.
""").format(conf=ns.reference_conf("r5"))),
        )

        q51_answers = {"client_before": str(wan[5]), "server_ip": str(gw[5]), "server_port": str(PROXY_PORT)}
        q51 = self.question_form(
            section=self.section(1),
            title=tr("Intercepter le HTTP qui sort"),
            description=tr("""
**(a)** Avant de rien changer : depuis `pc5`, `curl -s -m 5 http://{ext1}/`. Qui répond, et sous
quelle adresse `ext1` voit-il `pc5` ?

**(b)** Dans la table `ip nat` de `r5`, créez une chaîne de base de type `nat` accrochée au hook
`prerouting`, et la règle `redirect` qui remet au port {proxy} de `r5` les connexions TCP vers le
port 80 qui **arrivent par `eth0`**, quelle que soit leur destination (section
@@ref:redirect-to@@).

**(c)** Refaites la requête depuis `pc5` et lisez `SERVER=`, `SERVER_IP=` et `SERVER_PORT=` :
`pc5` croit toujours parler à `{ext1}` (section @@ref:transparent-proxy@@). Depuis `ext2`,
`curl -s -m 5 http://{wan}/ ; echo "code $?"` doit échouer (`code 7`) : le proxy n'est pas offert
à Internet.
""").format(ext1=ext1, proxy=PROXY_PORT, wan=wan[5])
            + tr("""
- À l'étape (a), `CLIENT_IP=` dans la réponse de `ext1` : @@{client_before:[0-9.]+}@@
- À l'étape (c), `SERVER_IP=` dans la réponse que reçoit `pc5` : @@{server_ip:[0-9.]+}@@
- À l'étape (c), `SERVER_PORT=` dans cette réponse : @@{server_port:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `r5` : `{chain}` puis `{rule}`, soit dans la table `{table}` :

```
{conf}```

Avant : `SERVER=ext1` et `CLIENT_IP={wan}` (la règle `masquerade` donnée). Après : `SERVER=proxy`,
`SERVER_IP={gw}`, `SERVER_PORT={proxy}`, `CLIENT_IP={pc5}` : `redirect` remplace la destination
par l'adresse de `r5` sur l'interface d'arrivée et le port par {proxy} ; `dnat to {gw}:{proxy}`
aurait ici le même effet.

Pièges : sans `iifname "eth0"`, la règle capte aussi le port 80 du côté d'Internet (`ext2` obtient
alors `SERVER=proxy` en visant `{wan}`) ; `oifname` n'a pas de sens en `prerouting`.

- Réponses : `{wan}` ; `{gw}` ; {proxy}.
- L'évaluation : `redirect` (6 points : depuis la copie de `pc5`, `curl` vers `http://{ext1}/`
  doit renvoyer `SERVER=proxy`), `redirect_lan_only` (2 points, comptés avec le précédent : depuis
  la copie de `ext2`, `curl` vers `http://{wan}/` ne doit pas être servi par le proxy) et le
  formulaire `q_proxy` (1 point par réponse).
""").format(chain=nft_chain(NAT_TABLE, "prerouting"), rule=nft_rule(NAT_TABLE, "prerouting", ns.rule_proxy()),
            table=NAT_TABLE, conf=render_tables({NAT_TABLE: {"prerouting": [ns.rule_proxy()]}}),
            wan=wan[5], gw=gw[5], proxy=PROXY_PORT, pc5=host["pc5"], ext1=ext1)),
            cheat_answers={"final": q51_answers},
        )
        self.add_grade_element(
            title=no_tr("redirect"), max_grade=6, grade_part=part5, grade=6 * int(redirect),
            description=tr("le HTTP qui sort de lan5 est remis au proxy de r5"),
        )
        self.add_grade_element(
            title=no_tr("redirect_lan_only"), max_grade=2, grade_part=part5, grade=2 * int(redirect and wan_spared),
            description=tr("le port 80 du côté d'Internet n'est pas remis au proxy (compté avec la redirection)"),
        )
        self.add_grade_element(
            title=no_tr("q_proxy"), max_grade=3, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q51.get("client_before"), wan[5])) + int(_same_ip(q51.get("server_ip"), gw[5]))
                  + int(_is_int(q51.get("server_port"), PROXY_PORT)),
            description=tr("proxy transparent : qui répond avant et après la redirection"),
        )

        q52_answers = {"admin_server": "ext1", "position": "before"}
        q52 = self.question_form(
            section=self.section(1),
            title=tr("Une exception : l'ordre des règles"),
            description=tr("""
**(a)** Depuis `admin` (`{admin}`), `curl -s -m 5 http://{ext1}/` : le proxy répond, comme à
`pc5`.

**(b)** Le poste `admin` ne doit pas passer par le proxy. Dans une chaîne `nat`, une règle
`accept` dispense de traduction les connexions qu'elle désigne (section @@ref:nat-rules@@), à
condition d'être évaluée avant la règle qui traduit. Ajoutez une règle `accept` pour le HTTP qui
arrive par `eth0` avec l'adresse source `{admin}`, à la bonne place : `nft add rule` ajoute en fin
de chaîne, `nft insert rule` en tête.

**(c)** Vérifiez l'ordre des règles (`nft -a list table ip nat`), puis refaites la requête depuis
`admin` et depuis `pc5`.
""").format(admin=host["admin"], ext1=ext1)
            + tr("""
- Une fois l'exception en place, `SERVER=` dans la réponse que reçoit `admin` : @@{admin_server:[a-z0-9]+}@@
- Par rapport à la règle `redirect`, la règle `accept` doit être placée : @@{position:>après>>>after|avant>>>before|dans une autre chaîne, de type filter>>>filter}@@
""")
            + instructor(tr("""
**Solution.** Sur `r5` : `{rule}`, ce qui donne la chaîne :

```
{conf}```

Depuis `admin` : `SERVER=ext1` et `CLIENT_IP={wan}` (sa connexion, dispensée du `redirect`, sort
par la règle `masquerade`) ; depuis `pc5`, toujours `SERVER=proxy`. `return` à la place de
`accept`, ou le critère `ip saddr != {admin}` dans la règle `redirect`, conviennent aussi.

Piège : la règle ajoutée avec `nft add rule`, donc après le `redirect`, qui a déjà décidé pour
`admin` : elle n'est jamais atteinte.

- Réponses : `ext1` ; avant.
- L'évaluation : `proxy_exception` (5 points, comptés seulement si la redirection fonctionne pour
  `pc5` : depuis la copie de `admin`, `curl` vers `http://{ext1}/` doit renvoyer `SERVER=ext1`) et
  le formulaire `q_exception` (1 point par réponse).
""").format(rule=nft_rule(NAT_TABLE, "prerouting", ns.rule_proxy_exception(), verb="insert"),
            conf=render_tables({NAT_TABLE: {"prerouting": [ns.rule_proxy_exception(), ns.rule_proxy()]}}),
            wan=wan[5], admin=host["admin"], ext1=ext1)),
            cheat_answers={"final": q52_answers},
        )
        self.add_grade_element(
            title=no_tr("proxy_exception"), max_grade=5, grade_part=part5, grade=5 * int(redirect and admin_spared),
            description=tr("le HTTP du poste admin échappe au proxy (compté avec la redirection)"),
        )
        self.add_grade_element(
            title=no_tr("q_exception"), max_grade=2, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q52.get("admin_server")) == "ext1") + int(_norm(q52.get("position")) == "before"),
            description=tr("exception au proxy : qui répond à admin, la place de la règle accept"),
        )

        # =====================================================================
        # Part 6 — r6: NAT is not a firewall
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Le NAT n'est pas un pare-feu"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Le NAT n'est pas un pare-feu"),
            description=tr("""
**Site 6** : le serveur `srv6` (`{srv6}`) dans `lan6` (`{lan}`), derrière **`r6`** (`eth0` : `{gw}`,
`eth1` : `{wan}`). `srv6` a deux services : son site web (port 80), **publié** sur le port {fwd} de
`r6`, et un service interne (port {intranet}, `SERVER=intranet`) qui ne doit pas sortir du site.
Le jeu de règles de `r6` traduit déjà ce qu'il faut :

```
{given}```

**But** : constater que cette traduction ne protège pas `lan6`, puis filtrer ce qui traverse `r6`
sans rien casser de ce qui doit fonctionner. **À lire** : sections @@ref:not-a-firewall@@ et
@@ref:nat-filter@@ des Informations.
""").format(srv6=host["srv6"], lan=lan[6], gw=gw[6], wan=wan[6], fwd=FWD_PORT, intranet=INTRANET_PORT,
            given=render_tables(ns.given_tables("r6")))
            + instructor(tr("""
**Pour l'enseignant.** Le fichier de référence de `r6` (état `final`) :

```
{conf}```

Barème de la partie : `forward_policy` 2, `intrusion_blocked` 5, `lan_out` 3, `published_kept` 4,
formulaires `q_intrusion` 2 et `q_forward` 2.
""").format(conf=ns.reference_conf("r6"))),
        )

        q61_answers = {"intruder_server": "intranet", "nat_protects": "no"}
        q61 = self.question_form(
            section=self.section(1),
            title=tr("Entrer malgré le NAT"),
            description=tr("""
**(a)** Ce qui fonctionne déjà : depuis `ext2`, `curl -s -m 5 http://{wan}:{fwd}/` (le service
publié répond) ; depuis `srv6`, `curl -s -m 5 http://{ext1}:{svc}/` (`srv6` sort sous l'adresse de
`r6`).

**(b)** Jouez le voisin indélicat, celui qui partage avec `r6` le réseau du fournisseur d'accès.
Sur `ext2`, ajoutez une route vers le réseau privé à travers `r6` : `ip route add {lan} via
{wan}`. Puis visez directement l'adresse privée : `curl -s -m 5 http://{srv6}:{intranet}/` et
`ping -c 1 {srv6}`.

**(c)** Qui a répondu ? `r6` est un routeur : il fait suivre ce paquet comme un autre, et aucune
règle de traduction ne s'y oppose (section @@ref:not-a-firewall@@).
""").format(wan=wan[6], fwd=FWD_PORT, ext1=ext1, svc=SVC_PORT, lan=lan[6], srv6=host["srv6"],
            intranet=INTRANET_PORT)
            + tr("""
- À l'étape (b), `SERVER=` dans la réponse que reçoit `ext2` : @@{intruder_server:[a-z0-9]+}@@
- Les règles de traduction de `r6` ont-elles empêché `ext2` d'atteindre le service interne ? @@{nat_protects:>oui>>>yes|non>>>no}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer sur `r6`. Avec la route, `ext2` envoie à `r6` un paquet destiné à
`{srv6}` ; `r6` le route vers `lan6` (aucune règle `nat` ne lui convient, et il n'y a pas de
filtre) ; la réponse de `srv6` appartient à une connexion déjà suivie : la règle `masquerade` ne
la concerne pas, elle repart telle quelle. `curl` renvoie `SERVER=intranet`, `SERVER_IP={srv6}`,
`CLIENT_IP={ext2}`, et le `ping` aboutit. Seul le fait que `{lan}` ne soit pas routé sur Internet
« protégeait » `srv6` ; il suffit d'être du bon côté de `r6` pour s'en affranchir.

- Réponses : `intranet` ; non.
- Cette question n'est évaluée que par le formulaire (`q_intrusion`, 1 point par réponse).
""").format(srv6=host["srv6"], ext2=ext2, lan=lan[6])),
            cheat_answers={"final": q61_answers},
        )
        self.add_grade_element(
            title=no_tr("q_intrusion"), max_grade=2, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=int(_norm(q61.get("intruder_server")) == "intranet") + int(_norm(q61.get("nat_protects")) == "no"),
            description=tr("un voisin qui s'ajoute une route atteint le service interne malgré le NAT"),
        )

        q62_answers = {"forward_daddr": str(host["srv6"]), "forward_dport": "80"}
        q62 = self.question_form(
            section=self.section(1),
            title=tr("Filtrer ce qui traverse le routeur"),
            description=tr("""
Sur `r6`, **sans toucher à la table `ip nat`**, créez une table `ip filter` et une chaîne de base
`forward` de type `filter` (priorité `filter`) dont la **politique est `drop`** (section
@@ref:filter-rules@@), avec les règles qui acceptent :

**(a)** les paquets des connexions déjà établies, ou liées à elles (`ct state`) ;

**(b)** les nouvelles connexions qui **sortent** : entrées par `eth0`, sorties par `eth1` ;

**(c)** le service publié : les connexions que la règle `dnat` a traduites (`ct status dnat`) ou,
ce qui revient au même ici, celles qui vont à l'adresse et au port que la chaîne `forward` **voit**
pour ce service (section @@ref:what-forward-sees@@).

Vérifiez avec de **nouvelles** connexions (une connexion ou un `ping` commencés avant le filtre
restent acceptés, comme « établis ») : depuis `ext2`, `curl -s -m 5 http://{srv6}:{intranet}/` et
`ping -c 1 -W 2 {srv6}` n'aboutissent plus ; `curl -s -m 5 http://{wan}:{fwd}/` répond toujours ;
depuis `srv6`, `curl -s -m 5 http://{ext1}:{svc}/` aussi.
""").format(srv6=host["srv6"], intranet=INTRANET_PORT, wan=wan[6], fwd=FWD_PORT, ext1=ext1, svc=SVC_PORT)
            + tr("""
- Pour une connexion de `ext2` au port publié de `r6`, adresse de destination que voit la chaîne `forward` : @@{forward_daddr:[0-9.]+}@@
- Port de destination qu'elle voit pour cette connexion : @@{forward_dport:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Sur `r6` : `nft add table {table}`, `{chain}` puis les trois règles, soit :

```
{conf}```

La chaîne `forward` voit les paquets après le DNAT (fait en `prerouting`) et avant le SNAT (fait
en `postrouting`) : pour le service publié, la destination `{srv6}`, port 80, et non `{wan}`, port
{fwd}. `iifname "eth1" ip daddr {srv6} tcp dport 80 accept` convient donc à la place de `ct status
dnat accept` (mais laisse aussi passer le voisin qui vise directement `{srv6}:80`).

Pièges : la politique `drop` sans la règle `ct state established,related accept` (plus aucune
réponse ne passe) ; ouvrir le port {fwd} dans le filtre (la chaîne `forward` ne le voit jamais) ;
`nft flush ruleset` ou un fichier qui ne reprend pas la table `ip nat` donnée.

- Réponses : `{srv6}` ; 80.
- L'évaluation : `forward_policy` (2 points : `nft -j list ruleset` de `r6` montre une chaîne de
  base de type `filter` accrochée à `forward` dont la politique est `drop`), `intrusion_blocked`
  (5 points : depuis la copie de `ext2`, qui a la route, la connexion TCP au port {intranet} de
  `{srv6}` et le `ping` échouent, alors que la copie de `r6` joint ce service), puis, comptés
  seulement quand l'intrusion est bloquée, `lan_out` (3 points : depuis la copie de `srv6`, `curl`
  vers `http://{ext1}:{svc}/` répond) et `published_kept` (4 points : depuis la copie de `ext2`,
  `curl` vers `http://{wan}:{fwd}/` renvoie `SERVER=srv6`) ; et le formulaire `q_forward` (1 point
  par réponse).
""").format(table=FILTER_TABLE, chain=nft_chain(FILTER_TABLE, "forward"),
            conf=render_tables({FILTER_TABLE: {"forward": ns.rules_forward()}}), srv6=host["srv6"],
            wan=wan[6], fwd=FWD_PORT, intranet=INTRANET_PORT, ext1=ext1, svc=SVC_PORT)),
            cheat_answers={"final": q62_answers},
        )
        self.add_grade_element(
            title=no_tr("forward_policy"), max_grade=2, grade_part=part6, grade=2 * int(forward_drop),
            description=tr("une chaîne forward de type filter dont la politique est drop"),
        )
        self.add_grade_element(
            title=no_tr("intrusion_blocked"), max_grade=5, grade_part=part6, grade=5 * int(intrusion_blocked),
            description=tr("le voisin qui a une route n'atteint plus le service interne de srv6, ni son ping"),
        )
        self.add_grade_element(
            title=no_tr("lan_out"), max_grade=3, grade_part=part6, grade=3 * int(intrusion_blocked and lan_out),
            description=tr("srv6 accède toujours à Internet (compté une fois l'intrusion bloquée)"),
        )
        self.add_grade_element(
            title=no_tr("published_kept"), max_grade=4, grade_part=part6,
            grade=4 * int(intrusion_blocked and published),
            description=tr("le service publié répond toujours à Internet (compté une fois l'intrusion bloquée)"),
        )
        self.add_grade_element(
            title=no_tr("q_forward"), max_grade=2, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=int(_same_ip(q62.get("forward_daddr"), host["srv6"])) + int(_is_int(q62.get("forward_dport"), 80)),
            description=tr("ce que voit la chaîne forward pour le service publié : l'adresse et le port internes"),
        )


_TRANSLATIONS = {}
