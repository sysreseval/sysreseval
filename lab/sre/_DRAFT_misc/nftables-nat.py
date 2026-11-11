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
**réécrire les adresses IP** (et souvent les ports) des paquets qui le traversent. Elle est née de
la pénurie d'adresses IPv4 : les réseaux internes utilisent des adresses **privées** (RFC 1918 :
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), qui ne sont pas routées sur Internet, et le
routeur de sortie leur substitue son adresse publique. On distingue deux traductions, selon
l'adresse réécrite :

- le **SNAT** (*source NAT*) réécrit l'adresse **source** : tout un réseau privé sort derrière
  **une seule** adresse publique. Le routeur réécrit au besoin le port source pour distinguer les
  connexions de plusieurs machines (NAPT, ou PAT : *port address translation*) : c'est ce que fait
  une box d'accès à Internet ;
- le **DNAT** (*destination NAT*) réécrit l'adresse, et éventuellement le port, de
  **destination** : il sert à **publier** un serveur interne derrière l'adresse publique du routeur
  (redirection de port), à **répartir la charge** entre plusieurs serveurs, ou à détourner un trafic
  vers un **proxy**.

Le NAT n'est pas un pare-feu : il traduit, il ne filtre pas. Un réseau privé n'est injoignable de
l'extérieur que parce que ses adresses n'y sont pas routées ; la vraie protection est le filtrage
(chaîne `forward`). Le NAT a aussi un coût : le serveur ne voit plus la véritable adresse du
client, et les protocoles qui transportent des adresses dans leurs données (FTP, SIP) ne
fonctionnent qu'avec des modules d'assistance du noyau (*helpers*).
""")
            + info_subtitle(tr("NAT et suivi de connexion"), tag="conntrack")
            + tr("""
Sous Linux, le NAT est fait dans le noyau par Netfilter, que l'on configure avec `nft` (nftables)
comme pour le filtrage. Il repose sur le **suivi de connexion** (*conntrack*) : le noyau mémorise
chaque connexion (une connexion TCP, mais aussi un échange UDP ou ICMP) par ses adresses et ses
ports. Trois conséquences :

- la traduction est **décidée une seule fois**, sur le **premier paquet** de la connexion (état
  `new`) : lui seul parcourt les chaînes de type `nat`, et le choix est inscrit dans l'entrée de
  conntrack ;
- les paquets suivants sont traduits de la même façon, et les paquets **de retour** sont traduits
  **en sens inverse**, automatiquement : on n'écrit jamais de règle pour le retour ;
- modifier ou supprimer une règle ne change rien aux connexions **déjà suivies** : elles gardent
  leur traduction jusqu'à leur fin.

La commande `conntrack` (paquet du même nom, quand il est installé) montre cette table :
`conntrack -L` liste les connexions avec, pour chacune, les adresses du sens aller puis celles
attendues au retour ; `conntrack -F` la vide. Après un SNAT, par exemple :

```
tcp  6 431995 ESTABLISHED src=192.168.1.20 dst=198.51.100.7 sport=40312 dport=80 src=198.51.100.7 dst=203.0.113.1 sport=80 dport=40312 [ASSURED]
```

le client `192.168.1.20` s'adresse à `198.51.100.7`, qui répond à `203.0.113.1`, l'adresse
publique du routeur : c'est le routeur qui rend la réponse au client.
""")
            + info_subtitle(tr("La table nat et ses chaînes"), tag="chains")
            + tr("""
Les règles de NAT se placent dans des chaînes de **type `nat`** (et non `filter`), accrochées à
un *hook* du trajet des paquets :

```
  arrivée ──> prerouting ──> [décision de routage] ──> forward ──> postrouting ──> départ
              type nat :                              type filter   type nat :
              DNAT, redirect                                        SNAT, masquerade
```

- **`prerouting`**, priorité `dstnat` (−100) : **avant** la décision de routage. C'est là que se
  fait le **DNAT** : la destination doit être changée avant que le noyau choisisse par où envoyer
  le paquet ;
- **`postrouting`**, priorité `srcnat` (100) : **après** le routage, juste avant l'émission. C'est
  là que se fait le **SNAT** : l'interface de sortie est connue ;
- `output` (priorité −100) permet un DNAT des paquets **émis par le routeur lui-même**, qui ne
  passent pas par `prerouting`.

```
table ip nat {
    chain prerouting  { type nat hook prerouting  priority dstnat; policy accept; }
    chain postrouting { type nat hook postrouting priority srcnat; policy accept; }
}
```

soit, en ligne de commande (les apostrophes protègent les accolades et les points-virgules du
shell) :

```
nft add table ip nat
nft 'add chain ip nat prerouting  { type nat hook prerouting  priority dstnat; policy accept; }'
nft 'add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
```

Le nom de la table est libre (`nat` par habitude) ; la famille `ip` traite IPv4 (`ip6` pour IPv6,
`inet` pour les deux). La politique reste `accept` : une chaîne `nat` traduit, elle ne filtre pas.
Dans une chaîne `nat`, la **première règle** dont tous les critères sont satisfaits et qui porte
une traduction (`snat`, `masquerade`, `dnat`, `redirect`) décide pour la connexion ; les règles
suivantes ne sont pas consultées. Une connexion qui n'en satisfait aucune passe sans traduction.

À retenir :

- le routeur doit **router** : `sysctl net.ipv4.ip_forward` doit afficher 1 ;
- le critère d'interface est `iifname` en `prerouting` (par où le paquet est arrivé) et `oifname`
  en `postrouting` (par où il sort) ; `oifname` n'a pas de sens en `prerouting`, le routage
  n'ayant pas encore eu lieu ;
- le **filtrage** (chaîne `forward` de type `filter`) voit les paquets **après le DNAT** et **avant
  le SNAT** : ses règles portent sur la destination **réelle** (le serveur interne) et sur la
  source **d'origine** ;
- `nft` refuse une traduction placée au mauvais endroit : un `dnat` ou un `redirect` en
  `postrouting`, un `masquerade` en `prerouting`, ou n'importe laquelle dans une chaîne de type
  `filter`.
""")
            + info_subtitle(tr("SNAT et masquerade"), tag="snat")
            + tr("""
Le SNAT s'écrit dans la chaîne `postrouting`, avec l'adresse qui remplace la source :

```
chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 192.168.1.0/24 oifname "eth1" snat to 203.0.113.1
}
```

Tout paquet qui vient du réseau privé `192.168.1.0/24` et sort par `eth1` part avec l'adresse
source `203.0.113.1` ; si le port source est déjà pris par une autre connexion traduite, le noyau
en choisit un autre. Le serveur distant ne voit que `203.0.113.1` et lui répond ; le routeur
retrouve la connexion dans conntrack et rend la réponse à la bonne machine interne.

Quand l'adresse de sortie n'est pas connue d'avance (DHCP, PPP…), on écrit **`masquerade`** : le
noyau prend l'adresse qu'a l'interface de sortie au moment où la connexion s'ouvre.

```
ip saddr 192.168.1.0/24 oifname "eth1" masquerade
```

Le résultat est le même ; `snat to` se justifie quand l'adresse est fixe, ou quand le routeur a
plusieurs adresses sur l'interface. Restreignez toujours la règle (`ip saddr` du réseau privé,
`oifname` de l'interface extérieure) : un `masquerade` sans critère traduirait aussi ce qui
**entre** vers le réseau interne, dont les serveurs ne verraient plus que l'adresse du routeur.
""")
            + info_subtitle(tr("DNAT et redirection de port"), tag="dnat")
            + tr("""
Le DNAT s'écrit dans la chaîne `prerouting`, avec la nouvelle destination :

```
chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80
}
```

Une connexion qui arrive par `eth1` sur le port TCP 8080 du routeur est envoyée au port 80 du
serveur interne `192.168.1.10` : c'est la **redirection de port**, qui publie un service interne
derrière l'adresse du routeur.

- `dnat to 192.168.1.10` change l'adresse de destination ; le port est conservé ;
- `dnat to 192.168.1.10:80` change l'adresse **et** le port ;
- un critère `ip daddr 203.0.113.1` précise l'adresse visée quand le routeur en a plusieurs.

Le serveur interne voit l'adresse **réelle** du client : seule la destination a changé. Sa réponse
doit **repasser par le routeur**, qui lui rend son adresse publique comme source : le serveur doit
donc avoir une route vers le client **par ce routeur** (sa route par défaut, en général). Sinon la
réponse arrive au client avec une adresse source qu'il ne connaît pas, et il la rejette. C'est le
piège d'une machine du réseau interne qui s'adresse à l'adresse publique du routeur : le serveur,
sur le même réseau qu'elle, lui répond directement sans repasser par le routeur (il faudrait
ajouter un SNAT : *hairpin NAT*).
""")
            + info_subtitle(tr("Répartition de charge"), tag="load-balancing")
            + tr("""
La destination d'un DNAT peut être **calculée** : une expression donne un numéro, et une table de
correspondance (*map*) écrite dans la règle associe chaque numéro à un serveur.

```
iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }
```

- `numgen inc mod 2` : un compteur qui vaut 0, 1, 0, 1… : un **tourniquet** (*round-robin*) strict ;
- `numgen random mod 2` : un tirage aléatoire : équilibré en moyenne seulement ;
- `jhash ip saddr mod 2` : un hachage de l'adresse source : un même client retombe toujours sur
  le même serveur (**persistance**), utile quand le serveur garde un état de session.

Avec trois serveurs : `mod 3` et trois entrées dans la *map*. Comme toute règle de NAT, celle-ci
n'est parcourue que par le **premier paquet** de chaque connexion : la répartition se fait **par
connexion**, et tous les paquets d'une connexion vont au même serveur. C'est une répartition de
niveau 4, sans surveillance : le routeur continue d'envoyer des connexions à un serveur en panne
(un vrai répartiteur de charge teste ses serveurs).
""")
            + info_subtitle(tr("redirect et proxy transparent"), tag="redirect")
            + tr("""
**`redirect`** est un DNAT vers **la machine elle-même** : la destination devient l'adresse de
l'interface par laquelle le paquet est arrivé, et le port celui que l'on indique.

```
iifname "eth0" tcp dport 80 redirect to :3128
```

Toute connexion HTTP (port 80) qui arrive par `eth0`, **quelle que soit sa destination**, est
remise au processus local qui écoute sur le port 3128. C'est le principe du **proxy transparent** :
le client croit parler au serveur distant, sans aucune configuration de son côté ; le proxy reçoit
la requête, retrouve le serveur visé (l'en-tête `Host:` de la requête, ou la destination d'origine
que conntrack a gardée), peut filtrer, journaliser ou mettre en cache, puis interroge le vrai
serveur à la place du client. Les portails captifs des réseaux Wi-Fi publics fonctionnent ainsi.

`redirect` se place en `prerouting` (ce qui traverse le routeur) ou en `output` (ce que la machine
émet elle-même). Limites : le serveur final voit l'adresse du proxy, pas celle du client ; et
HTTPS ne se laisse pas intercepter ainsi, le proxy n'ayant pas le certificat du serveur visé.
""")
            + info_subtitle(tr("Observer et vérifier une traduction"), tag="observe")
            + tr("""
Le plus direct est d'interroger avec `curl` un serveur de test qui **répond par ce qu'il voit** :
son nom, l'adresse et le port où la connexion lui est arrivée, l'adresse et le port du client.

```
SERVER=web1                # qui a répondu
SERVER_IP=192.168.1.10     # l'adresse où la connexion est arrivée...
SERVER_PORT=80             # ... et le port
CLIENT_IP=203.0.113.1      # le client, tel que le serveur le voit
CLIENT_PORT=40312
```

- après un **SNAT**, `CLIENT_IP` est l'adresse extérieure du routeur et non celle du client ;
- après un **DNAT**, `SERVER`, `SERVER_IP` et `SERVER_PORT` désignent le serveur interne, alors
  que le client a visé l'adresse et le port du routeur ;
- avec une **répartition de charge**, `SERVER` change d'une requête à l'autre ;
- avec un **proxy transparent**, c'est le proxy qui répond, sous son nom et sur son port.

Autres outils :

- `tcpdump -n -i eth0 tcp port 80` de chaque côté du routeur montre le même paquet **avant** et
  **après** la traduction ;
- `nft list ruleset` ; avec `counter` dans une règle de NAT (`… counter masquerade`), le compteur
  avance d'un paquet par **connexion** traduite ;
- `conntrack -L` (section @@ref:conntrack@@).

Pièges courants : le routage désactivé (`ip_forward` à 0) ; une règle `dnat` testée **du mauvais
côté** (une règle `iifname "eth1"` ne concerne ni une requête venue du réseau interne ni une
requête émise par le routeur lui-même) ; une connexion déjà suivie, qui garde son ancienne
traduction (refaire une requête : chaque `curl` ouvre une nouvelle connexion) ; l'ordre des règles
d'une chaîne, la première qui convient l'emportant ; la route de retour du serveur interne
(section @@ref:dnat@@).
""")
            + info_subtitle(tr("Pour qui connaît iptables"), tag="iptables")
            + tr("""
| iptables | nftables |
|----------|----------|
| `iptables -t nat -L -n -v` | `nft list table ip nat` |
| `iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth1 -j MASQUERADE` | `ip saddr 192.168.1.0/24 oifname "eth1" masquerade` |
| `iptables -t nat -A POSTROUTING -o eth1 -j SNAT --to-source 203.0.113.1` | `oifname "eth1" snat to 203.0.113.1` |
| `iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80` | `iifname "eth1" tcp dport 8080 dnat to 192.168.1.10:80` |
| `iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 3128` | `iifname "eth0" tcp dport 80 redirect to :3128` |
| `-m statistic --mode nth --every 2 --packet 0` (une règle par serveur) | `dnat to numgen inc mod 2 map { … }` (une seule règle) |
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
| répartition de charge | `iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 192.168.1.10, 1 : 192.168.1.11 }` |
| proxy transparent | `iifname "eth0" tcp dport 80 redirect to :3128` |
| supprimer | `nft delete rule ip nat prerouting handle N`, `nft flush chain ip nat prerouting`, `nft delete table ip nat` |
| fichier de règles | `nft -f /etc/nftables.conf` (le fichier commence par `flush ruleset` et se charge d'un bloc) |
| tests | `curl -s -m 3 http://ADRESSE:PORT/`, `tcpdump -n -i eth1 tcp port 80`, `sysctl net.ipv4.ip_forward` |
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
