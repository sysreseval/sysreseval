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

from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr
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

        self.informations = no_tr("## ") + title + no_tr("\n") + tr("""
# Cours : le **NAT** avec nftables

Le **NAT** (*Network Address Translation*) réécrit les adresses IP (et/ou ports)
des paquets qui traversent un routeur. Deux grandes familles :

- **SNAT** (*Source NAT*) — on réécrit l'**adresse source**. Usage type : donner
  accès à Internet à tout un LAN privé derrière **une seule** adresse publique.
- **DNAT** (*Destination NAT*) — on réécrit l'**adresse (ou le port) de
  destination**. Usage type : *publier* un service interne, faire de la
  redirection de port, ou répartir la charge.

Le NAT s'appuie **obligatoirement** sur le suivi de connexion (*conntrack*) : la
traduction n'est décidée que sur le **premier** paquet d'une connexion, puis
appliquée automatiquement (dans les deux sens) à tous les paquets suivants.

## 1. La table `nat` et ses chaînes

Contrairement au filtrage, le NAT se fait dans des chaînes de **type `nat`**,
accrochées à deux hooks :

- **`prerouting`** (priorité `dstnat`, soit −100) — **avant** le routage : c'est
  là qu'on fait le **DNAT** (changer la destination *avant* de router) ;
- **`postrouting`** (priorité `srcnat`, soit 100) — **après** le routage : c'est
  là qu'on fait le **SNAT / masquerade**.

```
table ip nat {
    chain prerouting  { type nat hook prerouting  priority dstnat; policy accept; }
    chain postrouting { type nat hook postrouting priority srcnat; policy accept; }
}
```

⚠️ Le routeur doit avoir `net.ipv4.ip_forward=1` (déjà activé dans ce TP).

## 2. SNAT et masquerade

```
# adresse de sortie fixe et connue :
chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 192.168.0.0/24 oifname "eth1" snat to 203.0.113.1
}
```

Quand l'adresse de sortie est **dynamique** (DHCP, PPP…), on utilise
**`masquerade`**, qui prend automatiquement l'adresse de l'interface de sortie :

```
oifname "eth1" masquerade
```

Après masquerade, le serveur distant voit comme adresse **source** l'adresse WAN
du routeur, jamais celle des machines internes.

## 3. DNAT et redirection de port

```
chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    # publier le web interne : WAN:8080 -> 10.0.0.10:80
    iifname "eth1" tcp dport 8080 dnat to 10.0.0.10:80
}
```

- `dnat to <ip>` : change la destination (le port est conservé) ;
- `dnat to <ip>:<port>` : change destination **et** port.

Le serveur interne voit alors l'adresse **réelle** du client (sauf si on ajoute
aussi un SNAT). Le retour est traduit automatiquement par *conntrack*.

## 4. Répartition de charge (*load balancing* L4)

nftables sait répartir les connexions entre plusieurs backends grâce à des
expressions comme **`numgen`** (compteur/aléatoire) ou **`jhash`** (hachage) et à
une *map* :

```
# tourniquet (round-robin) : une connexion sur deux vers chaque backend
iifname "eth1" tcp dport 80 dnat to numgen inc mod 2 map { 0 : 10.0.0.10, 1 : 10.0.0.11 }
```

- `numgen inc mod 2` : compteur incrémental 0,1,0,1… → alternance stricte ;
- `numgen random mod 2` : tirage aléatoire ;
- `jhash ip saddr mod 2` : même client → même backend (persistance de session).

La *map* associe la valeur (0/1) à l'adresse (et éventuellement au port) du backend.

## 5. `redirect` et proxy transparent

**`redirect`** est un DNAT particulier **vers la machine locale** (l'adresse de
l'interface d'entrée) :

```
# intercepter le HTTP sortant du LAN vers un proxy local écoutant sur 3128
iifname "eth0" tcp dport 80 redirect to :3128
```

Le client croit parler au serveur distant ; en réalité un **proxy transparent**
local (sur `fw`, port 3128) reçoit la connexion, peut filtrer/mettre en cache,
puis relayer. C'est le principe des proxys d'entreprise et des portails captifs.

## 6. Observer le NAT

Les serveurs HTTP de ce TP renvoient qui répond et qui demande :

```
SERVER=<nom>   SERVER_IP=<ip>   CLIENT_IP=<ip vue par le serveur>   CLIENT_PORT=…
```

- après **SNAT** : `CLIENT_IP` devient l'adresse WAN de `fw` ;
- après **DNAT** : `SERVER` indique quel backend a réellement répondu ;
- avec la **répartition** : en répétant la requête, `SERVER` alterne ;
- avec le **proxy transparent** : `SERVER` devient celui du proxy, pas la cible.

Outils utiles : `curl -s http://<ip>:<port>/`, `nft list ruleset`,
`conntrack -L` (table des connexions suivies).

## 7. Ce qui est demandé

Voir les questions : configurez la table `nat` de **`fw`** pour réaliser SNAT,
redirection de port, répartition de charge et proxy transparent.
""")

    @sre_state(user_allowed=False)
    def initial(self):
        for m in self.get_machine_names():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=self.net_config[m])
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))

        firewall.flush_ruleset(self, "fw")
        firewall.flush_ruleset(self, "fw_h")

        # Serveurs contrôlés sur les clones cachés.
        firewall.setup_http_server(self, "ext_h", NET_SVC_PORT, "ext")  # service « Internet »
        firewall.setup_http_server(self, "fw_h", PROXY_PORT, "proxy")   # proxy transparent local
        firewall.setup_http_server(self, "web1_h", 80, "web1")          # backend 1
        firewall.setup_http_server(self, "web2_h", 80, "web2")          # backend 2

    @sre_state(user_allowed=False)
    def final(self):
        """Solution de référence : note maximale."""
        d = self.data
        # fw : eth0 = LAN (net1), eth1 = WAN (net2)
        conf = f"""#!/usr/sbin/nft -f
flush ruleset
table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth0" tcp dport 80 redirect to :{PROXY_PORT}
        iifname "eth1" tcp dport {FWD_PORT} dnat to {d.ips.web1.ip}:80
        iifname "eth1" tcp dport {VIP_PORT} dnat to numgen inc mod 2 map {{ 0 : {d.ips.web1.ip}, 1 : {d.ips.web2.ip} }}
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {d.nets.net1} oifname "eth1" masquerade
    }}
}}
"""
        self.file("fw", "/etc/nftables.conf", conf, permissions=0o644)
        self.cmd("fw", "nft -f /etc/nftables.conf")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


class Grade(Grade0):
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

        self.question_dummy(
            title=tr("Objectif"),
            description=tr("""
Configurez la table **`nat`** du routeur **`fw`** (eth0 → LAN `net1` = {_arg0},
eth1 → WAN `net2` = {_arg1} ; adresse WAN de `fw` = **{_arg2}**).

Les serveurs HTTP renvoient `SERVER=<nom>` et `CLIENT_IP=<ip vue>` — utilisez-les
avec `curl` pour vérifier vos traductions.
""").format(_arg0=d.nets.net1, _arg1=d.nets.net2, _arg2=fw_wan_ip),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("1. SNAT / masquerade"),
            description=tr("""
Faites en sorte que les machines du LAN `net1` accèdent au WAN en étant
**masquées** derrière l'adresse WAN de `fw` (`masquerade` en `postrouting`,
`oifname "eth1"`). Vérification : depuis `cli`, `curl http://{_arg0}:{_arg1}/` ;
le champ `CLIENT_IP` renvoyé par `ext` doit être **{_arg2}** (l'adresse de `fw`).
""").format(_arg0=str(d.ips.ext.ip), _arg1=NET_SVC_PORT, _arg2=fw_wan_ip),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("2. Redirection de port (DNAT)"),
            description=tr("""
Publiez le serveur interne `web1` : toute connexion arrivant du WAN sur
**{_arg0}:{_arg1}** doit être redirigée (DNAT) vers **{_arg2}:80**.
""").format(_arg0=fw_wan_ip, _arg1=FWD_PORT, _arg2=str(d.ips.web1.ip)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("3. Répartition de charge (numgen)"),
            description=tr("""
Répartissez les connexions arrivant du WAN sur **{_arg0}:{_arg1}** entre les deux
backends **web1** ({_arg2}) et **web2** ({_arg3}), par exemple en tourniquet avec
`dnat to numgen inc mod 2 map {{ ... }}`.
""").format(_arg0=fw_wan_ip, _arg1=VIP_PORT, _arg2=str(d.ips.web1.ip), _arg3=str(d.ips.web2.ip)),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("4. Proxy transparent (redirect)"),
            description=tr("""
Interceptez le HTTP **sortant du LAN** (`iifname "eth0"`, `tcp dport 80`) et
redirigez-le vers le **proxy transparent local** de `fw` (port {_arg0}) avec
`redirect to :{_arg0}`.
""").format(_arg0=PROXY_PORT),
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
