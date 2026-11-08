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

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
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

        self.informations = no_tr("## ") + title + no_tr("\n") + tr("""
# Cours : nftables au-delà des règles simples

Ce TP suppose acquises les bases (tables, chaînes, sélecteurs, verdicts, filtrage
avec état). On explore ici des fonctionnalités qui font la puissance de nftables.

## 1. Ensembles (*sets*)

Un **ensemble anonyme** est écrit directement dans une règle :

```
tcp dport { 22, 80, 443 } accept
ip saddr { 10.0.0.1, 10.0.0.2 } drop
```

Un **ensemble nommé** est déclaré à part, réutilisable et **modifiable à chaud** :

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

Ajouter / retirer un élément **sans recharger** tout le ruleset :

```
nft add element inet filter liste_noire { 203.0.113.9 }
nft delete element inet filter liste_noire { 192.0.2.13 }
```

Types utiles : `ipv4_addr`, `ipv6_addr`, `inet_service` (ports),
`ether_addr` (MAC). Options (`flags`) :

- `flags interval` : autorise des **plages** (`10.0.0.0/24`, `1000-2000`) ;
- `flags timeout` : chaque élément **expire** automatiquement — idéal pour des
  listes noires temporaires alimentées dynamiquement.

## 2. Maps et *verdict maps*

Une **map** associe une clé à une valeur (adresse, port…) :

```
dnat to ip daddr map { 10.0.0.1 : 192.168.0.10, 10.0.0.2 : 192.168.0.11 }
```

Une **verdict map** associe une clé à un **verdict / un saut** :

```
tcp dport vmap { 22 : accept, 80 : accept, 25 : drop }
iifname vmap { "eth0" : jump zone_lan, "eth1" : jump zone_wan }
```

## 3. `reject` ou `drop` ?

- **`drop`** : le paquet disparaît **sans réponse**. L'émetteur attend puis
  **expire** (*timeout*). C'est furtif : le port paraît « filtré ».
- **`reject`** : le paquet est refusé **avec** une notification immédiate
  (ICMP *port-unreachable* par défaut, ou `reject with tcp reset` pour un
  RST TCP). L'émetteur est prévenu **tout de suite** ; le port paraît « fermé ».

```
tcp dport 8080 reject with tcp reset
tcp dport 9090 drop
```

On utilise souvent `drop` face à l'extérieur (furtivité) et `reject` en interne
(pour un diagnostic rapide).

## 4. Limitation de débit (`limit`)

`limit` laisse passer jusqu'à un certain **débit**, au-delà la règle ne
s'applique plus (le paquet « déborde ») :

```
# n'accepter que 3 nouvelles connexions SSH par minute (anti-brute-force)
tcp dport 22 ct state new limit rate 3/minute accept

# limiter les pings à 1/seconde, détruire le surplus
ip protocol icmp limit rate 1/second accept
```

On peut aussi compter les connexions simultanées :

```
tcp dport 22 ct count over 10 drop
```

## 5. Compteurs, journalisation, `meta`

```
counter                          # compte paquets et octets qui atteignent la règle
tcp dport 22 counter accept
log prefix "DROP input: " limit rate 5/second   # journalise (dans le noyau/syslog)
tcp dport 23 log prefix "telnet: " drop
```

Sélecteurs `meta` utiles : `meta l4proto`, `meta mark`, `meta iifname`,
`meta skuid` (propriétaire local du socket)…
On peut **marquer** un paquet (`meta mark set 0x1`) pour le routage avancé.

## 6. Anti-usurpation (`fib`) et *flowtables* (pour info)

- `fib saddr . iif oif missing drop` détruit les paquets dont l'adresse source
  n'est **pas routable** par l'interface d'arrivée (anti-*spoofing*, uRPF).
- Une **flowtable** décharge (*offload*) le suivi des connexions établies vers un
  chemin rapide, pour de très hauts débits.

## 7. Ce qui est demandé

Voir les questions : sur **`srv`** (chaîne `input`, `policy drop`), mettez en
place une liste noire, une liste blanche SSH, un port *rejeté* et un port
*détruit*, une limitation de débit, ainsi que des compteurs / de la journalisation.
""")

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        firewall.flush_ruleset(self, "srv")
        firewall.flush_ruleset(self, "srv_h")

        # Services contrôlés sur le clone : ainsi le verdict d'une sonde reflète
        # la politique du pare-feu et non l'absence de service.
        firewall.setup_banner_server(self, "srv_h", SSH_PORT, "ssh\n")
        firewall.setup_banner_server(self, "srv_h", HTTP_PORT, "http\n")
        firewall.setup_banner_server(self, "srv_h", REJECT_PORT, "rej\n")
        firewall.setup_banner_server(self, "srv_h", DROP_PORT, "drp\n")

    @sre_state(user_allowed=False)
    def final(self):
        """Solution de référence : note maximale."""
        d = self.data
        conf = f"""#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
    set liste_noire {{
        type ipv4_addr
        elements = {{ {d.ips.bad.ip} }}
    }}
    set admins {{
        type ipv4_addr
        elements = {{ {d.ips.admin.ip} }}
    }}
    chain input {{
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iif "lo" accept
        ip saddr @liste_noire log prefix "blacklist: " drop
        ip protocol icmp limit rate 1/second accept
        ip saddr @admins tcp dport {SSH_PORT} ct state new limit rate 3/minute counter accept
        tcp dport {HTTP_PORT} counter accept
        tcp dport {REJECT_PORT} reject with tcp reset
        tcp dport {DROP_PORT} drop
    }}
    chain forward {{ type filter hook forward priority 0; policy accept; }}
    chain output  {{ type filter hook output  priority 0; policy accept; }}
}}
"""
        self.file("srv", "/etc/nftables.conf", conf, permissions=0o644)
        self.cmd("srv", "nft -f /etc/nftables.conf")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


class Grade(Grade0):
    def grade(self):
        super().grade()
        d = self.get_data()

        for m in ("srv", "srv_h", "admin_h", "user_h", "bad_h"):
            for cmd in ("nft list ruleset", "ip -4 addr"):
                self.test(m, cmd, allow_error=True)

        rs = firewall.get_ruleset(self, "srv")
        firewall.transplant_ruleset(self, src="srv", dst="srv_h")

        self.question_dummy(
            title=tr("Objectif"),
            description=tr("""
Sur **`srv`** (chaîne `input`, `policy drop`, filtrage avec état), toutes les
machines sont sur le même LAN `net1` ({_arg0}). Vous disposez de trois sources :
**`admin`** ({_arg1}), **`user`** ({_arg2}) et **`bad`** ({_arg3}).
""").format(_arg0=d.nets.net1, _arg1=d.ips.admin.ip, _arg2=d.ips.user.ip, _arg3=d.ips.bad.ip),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("1. Liste noire (ensemble nommé)"),
            description=tr("""
Créez un **ensemble nommé** `liste_noire` (`type ipv4_addr`) contenant l'adresse
de **`bad`** ({_arg0}) et **détruisez** tout trafic provenant de ses membres. Les
autres machines gardent un accès HTTP (port {_arg1}) normal à `srv`.
""").format(_arg0=d.ips.bad.ip, _arg1=HTTP_PORT),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("2. Liste blanche SSH (ensemble nommé)"),
            description=tr("""
Créez un ensemble nommé `admins` contenant l'adresse de **`admin`** ({_arg0}) et
n'autorisez le **SSH** (port {_arg1}) que depuis les membres de cet ensemble. Le
SSH depuis `user` doit être refusé.
""").format(_arg0=d.ips.admin.ip, _arg1=SSH_PORT),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("3. reject vs drop"),
            description=tr("""
Faites en sorte que :
- le port **{_arg0}** soit **rejeté** (`reject`) — le client reçoit un refus immédiat ;
- le port **{_arg1}** soit **détruit** (`drop`) — le client n'obtient aucune réponse
  (délai d'attente).
""").format(_arg0=REJECT_PORT, _arg1=DROP_PORT),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("4. Limitation de débit, compteurs et journalisation"),
            description=tr("""
Ajoutez :
- une **limitation de débit** (`limit rate`) — par exemple sur les nouvelles
  connexions SSH ou sur l'ICMP ;
- au moins un **compteur** (`counter`) et une règle de **journalisation** (`log`).
"""),
        )

        # ---- sondes ----
        bad_http = firewall.probe_tcp(self, "bad_h", d.ips.srv, HTTP_PORT)
        user_http = firewall.probe_tcp(self, "user_h", d.ips.srv, HTTP_PORT)
        admin_ssh = firewall.probe_tcp(self, "admin_h", d.ips.srv, SSH_PORT)
        user_ssh = firewall.probe_tcp(self, "user_h", d.ips.srv, SSH_PORT)
        reject_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, REJECT_PORT)
        drop_verdict = firewall.probe_tcp_verdict(self, "user_h", d.ips.srv, DROP_PORT)

        self.add_grade_element(title=no_tr("blacklist_bad_bloque"), max_grade=2, grade=2 * int(not bad_http),
            description=tr("Liste noire : `bad` est bloqué (HTTP)"))
        self.add_grade_element(title=no_tr("blacklist_user_ok"), max_grade=1, grade=int(user_http),
            description=tr("`user` (hors liste noire) accède au HTTP"))
        self.add_grade_element(title=no_tr("whitelist_admin_ssh"), max_grade=2, grade=2 * int(admin_ssh),
            description=tr("Liste blanche : SSH autorisé depuis `admin`"))
        self.add_grade_element(title=no_tr("whitelist_user_ssh_bloque"), max_grade=2, grade=2 * int(not user_ssh),
            description=tr("SSH refusé depuis `user` (hors liste blanche)"))
        self.add_grade_element(title=no_tr("port_reject"), max_grade=2, grade=2 * int(reject_verdict == "refused"),
            description=tr("Port {_arg0} : reject (refus immédiat)").format(_arg0=REJECT_PORT))
        self.add_grade_element(title=no_tr("port_drop"), max_grade=2, grade=2 * int(drop_verdict == "dropped"),
            description=tr("Port {_arg0} : drop (silencieux)").format(_arg0=DROP_PORT))
        self.add_grade_element(title=no_tr("ensembles_nommes"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "set ") or firewall.ruleset_mentions(rs, "@")),
            description=tr("Utilisation d'ensembles nommés (set / @)"))
        self.add_grade_element(title=no_tr("limitation_debit"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "limit")),
            description=tr("Présence d'une limitation de débit (limit rate)"))
        self.add_grade_element(title=no_tr("compteur_ou_log"), max_grade=1,
            grade=int(firewall.ruleset_mentions(rs, "counter") or firewall.ruleset_mentions(rs, "log")),
            description=tr("Présence d'un counter et/ou d'un log"))
