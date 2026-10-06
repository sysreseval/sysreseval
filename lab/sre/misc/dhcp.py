"""TP DHCP (ISC DHCP : dhclient, dhcpd, dhcrelay).

Trois réseaux reliés par le routeur r1.  lan0 : serveur srv0 pré-configuré (DHCP + DNS) et
client m0 ; lan1 : serveurs srv1 et srv2 à configurer, clients m1 et m2 (adresse fixe) ;
lan2 : clients m3 et m4 (adresse fixe), servis à travers un relais sur r1.
lan3 : serveur srv3, derrière le routeur r2 de lan1 ; r1 ne connaît pas ce réseau, les clients de
lan1 en reçoivent la route de leur serveur DHCP (option 121).
La machine cachée ``sonde`` envoie les requêtes DHCP de test de l'évaluation.
L'état ``final`` applique la solution de référence.
Chaque question se termine par sa solution dans un bloc ``instructor()`` (mode enseignant).
"""

import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor
from SRE.params import sre_docker_image
from dhcp import (
    CLASSLESS_ROUTES_DECLARATION,
    CLASSLESS_ROUTES_OPTION,
    DhcpRelayParameters,
    set_dhcp_relay,
    render_dhcp_relay,
    check_running_dhcp_relay,
    get_dhcpd_interfaces,
    get_dhcp_failover_state,
    get_dhclient_leases,
    install_dhcp_probe,
    dhcp_probe,
    dhcp_probe_query,
    parse_classless_routes,
    render_classless_routes,
)
from ips import (
    random_ipv4networks,
    random_ipv4s,
    random_ipv4s_with_range,
    random_mac_address,
)
from net_config import (
    NetConfigEntry,
    set_net_config_entry,
    set_ip_forward,
    get_persistent_net_config_entry,
)
from ping import eval_ping

default_language = "fr"
tr = make_tr(default_language)

title = tr("DHCP (*Dynamic Host Configuration Protocol*)",
           en="DHCP (*Dynamic Host Configuration Protocol*)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# The Kathara export would reveal srv0's configuration and the grader's probe.
export_kathara_project = False
# Every evaluation sends test DHCP queries that show up in the students' server logs.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp-dhcp.lan"
CLIENTS = ["m0", "m1", "m2", "m3", "m4"]
SERVERS = ["srv1", "srv2"]
SYSTEMD_MACHINES = [
    "srv1",
    "srv2",
    "r1",
]  # real systemd (init image): systemctl, journalctl
# Locally administered prefix of every MAC address chosen by the lab ("SR" in ASCII).
MAC_PREFIX = "02:53:52"
# TEST-NET-1 address, foreign to every lab network: an authoritative server answers
# DHCPNAK to an INIT-REBOOT request for it.
FOREIGN_ADDRESS = "192.0.2.77"
# Lease asked by the second DISCOVER of the probe: above any max-lease-time of the lab.
LONG_LEASE = 4000000
FAILOVER_NAME = "lan2"
INIT_MACHINE = {
    "image": sre_docker_image("init"),
    "privileged": True,
    "entrypoint": "/sbin/init",
}
DHCP_INTERFACES = "auto eth0\niface eth0 inet dhcp\n"
DHCPD_DEFAULTS = 'INTERFACESv4="eth0"\nINTERFACESv6=""\n'  # /etc/default/isc-dhcp-server of srv1 / srv2


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    lease0: int = 0  # part 1: default-lease-time of srv0 (short: renewals are visible)
    default_lease: int = 0  # part 2: default-lease-time of srv1 / srv2
    max_lease: int = 0  # part 2: max-lease-time of srv1 / srv2
    mclt: int = 0  # part 7: failover MCLT (shorter than default_lease)

    @classmethod
    def generate(cls):
        data = cls()
        data.lease0 = random.choice([120, 150, 180, 240])
        # Away from the ISC defaults (43200 / 86400) so that an unconfigured value is detected.
        data.default_lease = random.choice([600, 900, 1200, 1800])
        data.max_lease = random.choice([3600, 5400, 7200])
        data.mclt = random.choice([60, 90, 120])

        (
            data.nets.lan0,
            data.nets.lan1,
            data.nets.lan2,
            data.nets.lan3,
        ) = random_ipv4networks(
            masks=[24, 24, 24, 24],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16")],
        )

        def edges(net: IPv4Network):
            return [
                IPv4Interface(f"{net.network_address}/{net.prefixlen}"),
                IPv4Interface(f"{net.broadcast_address}/{net.prefixlen}"),
            ]

        # Every range holds at least 30 addresses: each evaluation keeps a few of them
        # "offered" to the probe for two minutes on each server.
        (data.ips.pool0_min, data.ips.pool0_max, data.ips.srv0, data.ips.r1_lan0) = (
            random_ipv4s_with_range(
                data.nets.lan0,
                gap=random.randint(30, 60),
                n=2,
                exclude_ips=edges(data.nets.lan0),
            )
        )
        # lan1: range A is served by srv1, range B by srv2 (split scope).  r2 is its second
        # router, towards lan3.
        (
            data.ips.a_min,
            data.ips.a_max,
            data.ips.b_min,
            data.ips.b_max,
            data.ips.r1_lan1,
            data.ips.srv1,
            data.ips.srv2,
            data.ips.m2,
            data.ips.r2_lan1,
        ) = random_ipv4s_with_range(
            data.nets.lan1,
            gap=[random.randint(30, 50), random.randint(30, 50)],
            n=5,
            exclude_ips=edges(data.nets.lan1),
        )
        # lan2: range C, served by srv1 through the relay (then shared with srv2 by failover).
        (data.ips.c_min, data.ips.c_max, data.ips.r1_lan2, data.ips.m4) = (
            random_ipv4s_with_range(
                data.nets.lan2,
                gap=random.randint(30, 60),
                n=2,
                exclude_ips=edges(data.nets.lan2),
            )
        )

        # lan3: only reachable through r2 (part 4: route given to the lan1 clients by option 121).
        data.ips.r2_lan3, data.ips.srv3 = random_ipv4s(data.nets.lan3, 2)

        # m2 / m4: reserved clients; sonde_*: interfaces of the hidden probe; probe / nak:
        # client addresses announced by the probe (dynamic allocation, INIT-REBOOT request).
        (
            data.macs.m2,
            data.macs.m4,
            data.macs.sonde_lan1,
            data.macs.sonde_lan2,
            data.macs.probe,
            data.macs.nak,
        ) = random_mac_address(prefix=MAC_PREFIX, n=6)
        return data


def _mac(eui) -> str:
    """MAC address in the aa:bb:cc:dd:ee:ff form used by ip, tcpdump and dhcpd.conf."""
    return str(eui).replace("-", ":").lower()


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        "srv0": {"allow_connection": False, "color": "lightgrey"},
        "srv1": {**INIT_MACHINE, "color": "lightgreen"},
        "srv2": {**INIT_MACHINE, "color": "lightgreen"},
        "r1": {**INIT_MACHINE, "color": "lightblue"},
        # Pre-configured, like srv0: the second router of lan1 and the server behind it.
        "r2": {"allow_connection": False, "color": "lightgrey"},
        "srv3": {"allow_connection": False, "color": "lightgrey"},
        "m0": {},
        "m1": {},
        "m2": {},
        "m3": {},
        "m4": {},
        # Hidden helper used only by the auto-grader: it sends the test DHCP queries, so that
        # the checks do not depend on machines the students reconfigure.
        "sonde": {"hidden": True},
    }
    _network_specs = {
        "lan0": {"color": "lightgrey"},
        "lan1": {"color": "lightyellow"},
        "lan2": {"color": "lightyellow"},
        "lan3": {"color": "lightgrey"},
    }

    @property
    def _topology(self):
        macs = self.data.macs
        return {
            "lan0": {"r1": 0, "srv0": 0, "m0": 0},
            "lan1": {
                "r1": 1,
                "r2": 0,
                "srv1": 0,
                "srv2": 0,
                "m1": 0,
                "m2": (0, macs.m2),
                "sonde": (0, macs.sonde_lan1),
            },
            "lan2": {
                "r1": 2,
                "m3": 0,
                "m4": (0, macs.m4),
                "sonde": (1, macs.sonde_lan2),
            },
            "lan3": {"r2": 1, "srv3": 0},
        }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")

        # Clients and the probe have no static address (None: interface left unconfigured).
        self.net_config: Dict[str, NetConfigEntry] = {
            "r1": [([d.ips.r1_lan0], []), ([d.ips.r1_lan1], []), ([d.ips.r1_lan2], [])],
            # r1 has no route to lan3 and r2 none to lan0 / lan2: lan3 is for the lan1 machines only
            "r2": [([d.ips.r2_lan1], []), ([d.ips.r2_lan3], [])],
            "srv3": [([d.ips.srv3], [(default, d.ips.r2_lan3.ip)])],
            "srv0": [([d.ips.srv0], [(default, d.ips.r1_lan0.ip)])],
            "srv1": [([d.ips.srv1], [(default, d.ips.r1_lan1.ip)])],
            "srv2": [([d.ips.srv2], [(default, d.ips.r1_lan1.ip)])],
            **{m: [None] for m in CLIENTS},
            "sonde": [None, None],
        }

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ")
            + title
            + no_tr("\n")
            + tr("""
**Sommaire**

1. À quoi sert DHCP
2. L'obtention d'un bail : quatre messages
3. Le format des messages et les options
4. La vie d'un bail
5. Le client : `dhclient` et `ifupdown`
6. Le serveur : `dhcpd`
7. Distribuer d'autres routes
8. Plusieurs serveurs sur un même réseau
9. Le relais DHCP
10. Observation et diagnostic
11. Sécurité
""")
            + tr("""
## 1. À quoi sert DHCP

Pour communiquer en IPv4, une machine a besoin d'au moins quatre informations : son **adresse**,
le **masque** de son réseau, l'adresse du **routeur par défaut** et celle d'un **serveur DNS**.
Les saisir à la main sur chaque poste ne tient plus dès que le parc grandit : fautes de frappe,
adresses attribuées deux fois, postes à reprendre un par un quand le plan d'adressage change,
portables qui passent d'un réseau à l'autre.

**DHCP** automatise cette configuration : la machine qui se connecte demande ses paramètres au
réseau, un serveur les lui fournit. L'administrateur ne gère plus qu'un point central, le
serveur, qui garantit qu'une adresse n'est prêtée qu'à une machine à la fois.

Trois rôles :

| rôle | fonction | logiciel ISC |
|------|----------|--------------|
| **client** | demande une configuration pour une de ses interfaces | `dhclient` |
| **serveur** | détient les adresses à distribuer et les paramètres, tient le registre des baux | `dhcpd` |
| **relais** | fait suivre les demandes d'un réseau sans serveur vers un serveur distant | `dhcrelay` |

Un serveur peut attribuer une adresse de deux façons :

- **adresse dynamique** : l'adresse est prise dans une plage et **prêtée pour une durée
  limitée**, le *bail* ; rendue ou expirée, elle sera attribuée à une autre machine. C'est le
  cas général ;
- **adresse fixe** (*réservation*) : l'administrateur a associé une adresse à une machine
  précise, reconnue par son adresse MAC ; DHCP ne fait que la lui communiquer.

DHCP date de 1993. Il prolonge **BOOTP** (1985), conçu pour démarrer des stations sans disque,
dont il garde le format de message et les ports UDP : c'est pourquoi les outils de capture
parlent de `BOOTP/DHCP`. Textes de référence actuels : RFC 2131 (le protocole, 1997), RFC 2132
(les options, 1997), RFC 3046 (l'option ajoutée par les relais, 2001).
""")
            + tr("""
## 2. L'obtention d'un bail : quatre messages

Une machine qui démarre sans configuration ne connaît ni son adresse, ni son réseau, ni même
l'adresse d'un serveur : elle ne peut que **diffuser** une demande sur son réseau local.
L'échange normal comporte quatre messages (on parle de *DORA* : Discover, Offer, Request, Ack) :

```
   client                                            serveur
     |                                                  |
     |--- DHCPDISCOVER (diffusion) -------------------->|   y a-t-il un serveur ?
     |<--- DHCPOFFER -----------------------------------|   je te propose cette adresse
     |--- DHCPREQUEST (diffusion) --------------------->|   j'accepte l'offre de ce serveur
     |<--- DHCPACK -------------------------------------|   accordé : voici ton bail
     |                                                  |
```

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPDISCOVER` | client | recherche des serveurs DHCP |
| `DHCPOFFER` | serveur | propose une adresse et des paramètres |
| `DHCPREQUEST` | client | accepte **une** offre en nommant le serveur retenu (ou prolonge un bail) |
| `DHCPACK` | serveur | confirme : le bail est accordé, le client configure son interface |

Sans réponse, le client répète son `DHCPDISCOVER` à intervalles de plus en plus longs. Si
plusieurs serveurs répondent, il reçoit plusieurs offres et en retient une, en général la
première. Une adresse proposée reste mise de côté par le serveur pendant deux minutes environ : si
le client ne la confirme pas, elle redevient disponible.

### Transport et adresses

DHCP est transporté par **UDP** : le serveur (comme le relais) écoute sur le port **67**, le
client sur le port **68**. Tant que le client n'a pas d'adresse :

- il émet avec l'adresse source `0.0.0.0` (« pas encore d'adresse ») vers l'adresse de diffusion
  `255.255.255.255`, dans une trame Ethernet destinée à `ff:ff:ff:ff:ff:ff` : toutes les machines
  du réseau local la reçoivent, aucun routeur ne la fait suivre ;
- le serveur lui répond directement (trame envoyée à l'adresse MAC du client, paquet destiné à
  l'adresse qu'il lui propose), ou en diffusion si le client l'a demandé par le drapeau
  *broadcast* du message ;
- le `DHCPREQUEST` est encore **diffusé**, alors que le client sait à quel serveur il s'adresse :
  c'est ainsi que les **autres** serveurs apprennent que leur offre n'est pas retenue.

### Les autres messages

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPNAK` | serveur | refuse un `DHCPREQUEST` (adresse étrangère au réseau, bail expiré et réattribué…) : le client recommence à zéro par un `DHCPDISCOVER` |
| `DHCPDECLINE` | client | signale que l'adresse reçue est déjà utilisée par une autre machine : le serveur la met à l'écart |
| `DHCPRELEASE` | client | rend son adresse avant la fin du bail (arrêt propre de l'interface) |
| `DHCPINFORM` | client | demande seulement des paramètres (DNS, domaine…) pour une adresse qu'il a déjà, configurée à la main |
""")
            + tr("""
## 3. Le format des messages et les options

Tous les messages ont le même format, hérité de BOOTP : des champs fixes, puis une liste
d'**options**.

| champ | contenu | dans `tcpdump -v` |
|-------|---------|-------------------|
| `op` | sens du message : requête (du client) ou réponse (du serveur) | `Request` / `Reply` |
| `xid` | identifiant de transaction, choisi par le client et recopié par le serveur : il relie les réponses à la demande | `xid` |
| `secs` | secondes écoulées depuis que le client cherche une adresse | `secs` |
| `flags` | drapeau *broadcast* : « répondez-moi en diffusion » | `Flags` |
| `ciaddr` | adresse **actuelle** du client, quand il en a déjà une (renouvellement) | `Client-IP` |
| `yiaddr` | *your address* : l'adresse que le serveur attribue au client | `Your-IP` |
| `siaddr` | serveur à contacter pour un démarrage par le réseau | `Server-IP` |
| `giaddr` | adresse du relais qui a fait suivre la demande (nulle sans relais) | `Gateway-IP` |
| `chaddr` | adresse matérielle (MAC) du client | `Client-Ethernet-Address` |
| `hops` | nombre de relais traversés | `hops` |

`tcpdump` n'affiche que les champs non nuls : pas de `Gateway-IP` sans relais, pas de `Your-IP`
dans un message du client.

Tout le reste voyage dans les options, chacune identifiée par un **code**. Le type du message
est lui-même une option (53) ; le client liste les paramètres qu'il souhaite (option 55) et le
serveur lui renvoie ceux qu'il connaît.

| code | nom dans `dhcpd.conf` et dans les fichiers de baux | contenu | dans `tcpdump -v` |
|------|------|---------|-------------------|
| 1 | `subnet-mask` | masque du réseau | `Subnet-Mask` |
| 3 | `routers` | routeur(s) par défaut | `Default-Gateway` |
| 6 | `domain-name-servers` | serveur(s) DNS | `Domain-Name-Server` |
| 12 | `host-name` | nom de la machine | `Hostname` |
| 15 | `domain-name` | domaine DNS, qui complète les noms courts (`ping srv1`) | `Domain-Name` |
| 28 | `broadcast-address` | adresse de diffusion du réseau | `BR` |
| 33 | `static-routes` | routes vers des adresses, sans masque (section 7) | `Static-Route` |
| 42 | `ntp-servers` | serveurs de temps | `NTP` |
| 50 | `dhcp-requested-address` | adresse que le client souhaite obtenir | `Requested-IP` |
| 51 | `dhcp-lease-time` | durée du bail, en secondes | `Lease-Time` |
| 53 | `dhcp-message-type` | type du message (`DHCPDISCOVER`, `DHCPOFFER`…) | `DHCP-Message` |
| 54 | `dhcp-server-identifier` | adresse du serveur qui fait l'offre, ou que le client retient | `Server-ID` |
| 55 | `dhcp-parameter-request-list` | liste des options demandées par le client | `Parameter-Request` |
| 58 | `dhcp-renewal-time` | instant T1 (section 4) | `RN` |
| 59 | `dhcp-rebinding-time` | instant T2 (section 4) | `RB` |
| 61 | `dhcp-client-identifier` | identifiant du client, quand il n'utilise pas son adresse MAC | `Client-ID` |
| 82 | (ajoutée par un relais) | informations sur le point de raccordement du client | `Agent-Information` |
| 121 | `rfc3442-classless-static-routes` (à déclarer) | routes vers des réseaux, en plus de la route par défaut (section 7) | `Classless-Static-Route` |
""")
            + tr("""
## 4. La vie d'un bail

L'adresse n'est pas donnée mais **louée** : le bail a une durée (option 51), au terme de
laquelle le client doit cesser d'utiliser l'adresse s'il n'a pas obtenu de prolongation.

```
  obtention            T1 = 50 %                 T2 = 87,5 %      expiration
  |------------------------|--------------------------|----------------|
  | bail en cours          | renouvellement :         | rattachement : |
  | (rien n'est émis)      | DHCPREQUEST en unicast   | DHCPREQUEST    |
  |                        | au serveur du bail       | diffusé        |
```

- **à T1**, la moitié du bail : le client demande la prolongation par un `DHCPREQUEST` envoyé
  **en unicast au serveur qui a accordé le bail** ; celui-ci répond par un `DHCPACK` et le bail
  repart pour une durée entière. Il n'y a ni `DHCPDISCOVER` ni `DHCPOFFER` ;
- **à T2**, 87,5 % du bail, si ce serveur n'a pas répondu : le client **diffuse** son
  `DHCPREQUEST`, pour que n'importe quel serveur du réseau puisse prolonger le bail ;
- **à l'expiration** : le client retire l'adresse de son interface et reprend tout depuis le
  `DHCPDISCOVER`.

En fonctionnement normal un bail est donc prolongé bien avant son terme et la machine garde la
même adresse indéfiniment : elle ne la perd que si aucun serveur ne lui répond pendant toute la
seconde moitié du bail.

### Libération, redémarrage, changement de réseau

- **Libération** : un client qui s'arrête proprement envoie un `DHCPRELEASE` et le serveur peut
  réattribuer l'adresse aussitôt. Un client éteint brutalement n'envoie rien : son adresse reste
  immobilisée jusqu'à l'expiration du bail.
- **Redémarrage** : un client qui a gardé la trace d'un bail encore valide ne repart pas du
  `DHCPDISCOVER`, il diffuse directement un `DHCPREQUEST` pour son ancienne adresse. Si elle
  convient toujours, le serveur répond `DHCPACK`.
- **Changement de réseau** : si l'adresse redemandée n'appartient pas au réseau où le client se
  trouve maintenant (portable déplacé), un serveur qui **fait autorité** sur ce réseau
  (`authoritative`) répond `DHCPNAK` ; le client abandonne cette adresse et recommence par un
  `DHCPDISCOVER`. Sans ce refus, il attend inutilement avant de s'y résoudre.

### Éviter les doublons

Une adresse de la plage peut être utilisée par une machine configurée à la main, que le serveur
ne connaît pas. Deux garde-fous :

- avant de proposer une adresse dynamique, `dhcpd` lui envoie un `ping` et attend une seconde
  (c'est pourquoi une première offre arrive avec une seconde de retard). Si une machine répond,
  l'adresse est mise à l'écart (*abandonnée*) et le client, qui répète sa demande, s'en voit
  proposer une autre ;
- le client peut vérifier de son côté, par une requête ARP, que personne n'utilise l'adresse
  reçue, et la refuser par un `DHCPDECLINE`.

### Quelle durée de bail ?

| bail court (quelques minutes) | bail long (plusieurs jours) |
|-------------------------------|------------------------------|
| les adresses des machines parties sont vite récupérées : adapté aux réseaux de passage, où il vient plus de machines qu'il n'y a d'adresses | les adresses des machines parties restent immobilisées longtemps |
| un changement de configuration (nouveau serveur DNS…) est vite pris en compte | un changement de configuration met longtemps à atteindre tous les postes |
| beaucoup de trafic DHCP ; une panne du serveur prive vite les postes de leur adresse | peu de trafic ; les postes traversent sans dommage une longue panne du serveur |
""")
            + tr("""
## 5. Le client : dhclient et ifupdown

```
dhclient -v eth0       # demande un bail, configure l'interface, puis reste en arrière-plan
dhclient -r -v eth0    # libère le bail et arrête le client
```

Avec `-v`, `dhclient` affiche le dialogue :

```
DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3
DHCPOFFER of 192.0.2.101 from 192.0.2.2
DHCPREQUEST for 192.0.2.101 on eth0 to 255.255.255.255 port 67
DHCPACK of 192.0.2.101 from 192.0.2.2
bound to 192.0.2.101 -- renewal in 1527 seconds.
```

Le bail obtenu, il configure l'adresse de l'interface, la route par défaut et
`/etc/resolv.conf` (par le script `/sbin/dhclient-script`), puis reste en arrière-plan pour
renouveler le bail. Dans `ip a`, l'adresse est marquée `dynamic` et sa durée de validité
restante est affichée (`valid_lft`).

| fichier | rôle |
|---------|------|
| `/etc/dhcp/dhclient.conf` | réglages du client |
| `/var/lib/dhcp/dhclient.leases` | baux obtenus par un `dhclient` lancé à la main |
| `/var/lib/dhcp/dhclient.eth0.leases` | baux obtenus par `ifup eth0` |

### Le fichier de baux du client

`dhclient` y inscrit chaque bail obtenu ou prolongé ; le dernier bloc est le bail en cours.

```
lease {
  interface "eth0";
  fixed-address 192.0.2.101;                  # l'adresse obtenue
  option subnet-mask 255.255.255.0;
  option routers 192.0.2.1;
  option dhcp-lease-time 3600;                # durée du bail
  option dhcp-message-type 5;                 # 5 = DHCPACK
  option domain-name-servers 192.0.2.53;
  option dhcp-server-identifier 192.0.2.2;    # le serveur qui a accordé le bail
  option domain-name "example.org";
  renew 3 2026/10/07 08:28:11;                # T1
  rebind 3 2026/10/07 08:52:30;               # T2
  expire 3 2026/10/07 09:00:00;               # fin du bail
}
```

Les dates sont en temps universel (UTC), précédées du numéro du jour de la semaine.

### Les réglages du client

| instruction de `dhclient.conf` | effet |
|--------------------------------|-------|
| `request subnet-mask, routers, …;` | options demandées au serveur (option 55) |
| `send dhcp-lease-time 86400;` | valeur envoyée au serveur, ici la durée de bail souhaitée |
| `supersede domain-name "example.org";` | valeur imposée, quelle que soit la réponse du serveur |
| `prepend domain-name-servers 192.0.2.53;` | valeur placée avant celles du serveur |
| `timeout 60;` | secondes de recherche avant d'abandonner (60 par défaut) |

### Configuration persistante : ifupdown

Pour une configuration **persistante** (appliquée à chaque démarrage), on déclare
l'interface dans `/etc/network/interfaces` :

```
auto eth0
iface eth0 inet dhcp
```

puis on l'active avec `ifup eth0` (et on la désactive avec `ifdown eth0`, qui libère le
bail). `ifup` lance son propre `dhclient`, avec son propre fichier de baux
(`/var/lib/dhcp/dhclient.eth0.leases`) : libérez d'abord un bail obtenu à la main
(`dhclient -r eth0`) et n'utilisez ensuite plus que `ifup` / `ifdown`.
""")
            + tr("""
## 6. Le serveur : dhcpd

| fichier | rôle |
|---------|------|
| `/etc/default/isc-dhcp-server` | interfaces d'écoute : `INTERFACESv4="eth0"` |
| `/etc/dhcp/dhcpd.conf` | configuration |
| `/var/lib/dhcp/dhcpd.leases` | baux accordés (écrit par `dhcpd`, à ne pas modifier) |

### Structure de dhcpd.conf

Le fichier contient des **paramètres** et des **déclarations**. Chaque instruction se termine
par `;`, un bloc est délimité par des accolades, un commentaire commence par `#`.

- un **paramètre** règle le comportement du serveur (`default-lease-time 3600;`) ; précédé du mot
  `option`, il désigne une option DHCP envoyée aux clients (`option routers 192.0.2.1;`) ;
- une **déclaration** décrit le réseau et délimite la **portée** des paramètres qu'elle contient :

| déclaration | décrit |
|-------------|--------|
| `subnet … netmask … { }` | un réseau IP |
| `range début fin;` | dans un `subnet` ou un `pool` : la plage des adresses attribuées dynamiquement |
| `pool { }` | dans un `subnet` : une plage soumise à des règles particulières (clients admis, failover) |
| `host nom { }` | une machine particulière : adresse fixe, options qui lui sont propres |
| `group { }` | des déclarations qui partagent les mêmes paramètres |
| `shared-network nom { }` | plusieurs réseaux IP portés par le même réseau physique |
| `class "nom" { }` | une catégorie de clients, reconnus à ce qu'ils envoient |

Un paramètre écrit hors de tout bloc est **global**. Pour un client donné, c'est la valeur de
la portée **la plus précise** qui l'emporte : `host`, puis `class`, `pool`, `subnet`,
`shared-network`, et enfin les paramètres globaux. On écrit donc une seule fois, globalement, ce
qui vaut partout (serveur DNS, domaine, durées de bail) et dans chaque `subnet` ce qui lui est
propre (le routeur).

### Un exemple

```
authoritative;                         # ce serveur fait autorité sur ses réseaux
default-lease-time 3600;               # bail accordé si le client ne demande rien (secondes)
max-lease-time 7200;                   # bail maximal accordé si le client demande plus
option domain-name "example.org";      # options globales : valables pour tous les réseaux
option domain-name-servers 192.0.2.53;

subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.100 192.0.2.150;     # plage des adresses attribuées dynamiquement
    option routers 192.0.2.1;          # option propre à ce réseau
}

host imprimante {                      # adresse fixe (réservation) pour une machine
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.0.2.10;          # en dehors de toute plage dynamique
}
```

`dhcpd` exige une déclaration `subnet` pour le réseau de chaque interface sur laquelle il
écoute, et il en faut une pour chaque réseau qu'il sert. Un serveur `authoritative` répond
`DHCPNAK` à un client qui redemande une adresse étrangère au réseau (machine venant d'un autre
réseau) : sans cela le client attend inutilement.

### Les durées de bail

| paramètre | rôle | sans réglage |
|-----------|------|--------------|
| `default-lease-time` | durée accordée à un client qui ne demande rien | 43200 s (12 h) |
| `max-lease-time` | plafond appliqué à un client qui demande une durée | 86400 s (24 h) |
| `min-lease-time` | plancher : aucun bail plus court n'est accordé | 300 s |

### Les adresses fixes

Une réservation (bloc `host`) identifie le client par son **adresse MAC** (`ip link show eth0`
sur le client) et lui donne toujours la même adresse :

- l'adresse fixe se choisit **en dehors** des plages dynamiques, mais dans le réseau où la machine
  est branchée : la réservation ne s'applique que si le client se présente sur le `subnet` qui
  contient cette adresse ;
- le client reçoit les options de ce `subnet` (le routeur) et les options globales ; on peut en
  ajouter dans le bloc `host` ;
- le nom donné au bloc `host` est libre : c'est l'adresse MAC qui désigne la machine.

### Choisir les clients servis

Par défaut `dhcpd` sert toute machine qui se présente. `deny unknown-clients;`, dans un `subnet`
ou un `pool`, réserve les adresses dynamiques aux machines déclarées par un bloc `host`. Dans ce
TP, ne l'utilisez pas : la sonde de l'évaluation serait ignorée.

### Le registre des baux : dhcpd.leases

`dhcpd` note dans `/var/lib/dhcp/dhcpd.leases` les baux des adresses de ses plages dynamiques,
pour les retrouver après un redémarrage. C'est un journal : chaque changement **ajoute** un bloc,
et pour une adresse donnée c'est le **dernier** bloc qui compte.

```
lease 192.0.2.101 {
  starts 3 2026/10/07 08:00:00;          # début du bail (UTC)
  ends 3 2026/10/07 09:00:00;            # fin du bail
  cltt 3 2026/10/07 08:00:00;            # dernier échange avec le client
  binding state active;                  # état du bail
  next binding state free;               # état qu'il prendra à son terme
  hardware ethernet 00:11:22:33:44:55;   # le client
  client-hostname "portable";
}
```

| état (`binding state`) | signification |
|------------------------|---------------|
| `active` | bail en cours |
| `free` | adresse disponible : bail terminé ou rendu |
| `abandoned` | adresse écartée : elle a répondu au `ping` du serveur, ou un client l'a refusée |
| `backup` | failover : adresse disponible confiée au serveur secondaire |
| `expired`, `released` | failover : états de passage d'un bail terminé ou rendu, avant `free` |

Une offre n'est pas un bail : rien n'est écrit tant que le client n'a pas confirmé par un
`DHCPREQUEST`. La commande `dhcp-lease-list` donne un résumé lisible des baux en cours.

### Lancer et contrôler le serveur

```
dhcpd -t -cf /etc/dhcp/dhcpd.conf      # vérifie la syntaxe sans lancer le serveur
systemctl restart isc-dhcp-server      # à refaire après CHAQUE modification
systemctl status isc-dhcp-server
journalctl -u isc-dhcp-server -f       # journal en continu : une ligne par message DHCP
ps -C dhcpd -o pid,args                # le processus et ses arguments
dhcp-lease-list                        # résumé des baux en cours
```

Le journal montre chaque message reçu ou émis :

```
DHCPDISCOVER from 00:11:22:33:44:55 via eth0
DHCPOFFER on 192.0.2.101 to 00:11:22:33:44:55 (portable) via eth0
DHCPREQUEST for 192.0.2.101 (192.0.2.2) from 00:11:22:33:44:55 (portable) via eth0
DHCPACK on 192.0.2.101 to 00:11:22:33:44:55 (portable) via eth0
```

`via eth0` désigne l'interface par laquelle la demande est arrivée ; dans le `DHCPREQUEST`,
l'adresse entre parenthèses est celle du serveur que le client a retenu.

Si `INTERFACESv4` est vide, le service est déclaré en échec alors qu'un `dhcpd` continue de
tourner sur toutes les interfaces : corrigez le fichier, tuez ce processus (`pkill dhcpd`)
puis relancez le service.
""")
            + tr("""
## 7. Distribuer d'autres routes

L'option `routers` ne donne au client qu'une **route par défaut**. Elle ne suffit plus quand le
réseau a plusieurs routeurs et que le routeur par défaut ne connaît pas tous les réseaux : pour
atteindre ceux-là, le client doit savoir par quel autre routeur passer. Le serveur DHCP peut lui
distribuer ces routes.

| option | code | contenu |
|--------|------|---------|
| `static-routes` | 33 | des routes sans masque, vers des adresses : conçue avant les réseaux sans classe, à éviter |
| routes sans classe (*classless static routes*) | 121 | des routes vers des réseaux de préfixe quelconque (RFC 3442, 2002) : c'est elle qu'on utilise |

### Le codage de l'option 121

L'option est une suite d'octets. Chaque route s'y écrit : la **longueur du préfixe**, puis les
seuls **octets significatifs** de l'adresse du réseau (ceux que couvre le préfixe), puis les
**quatre octets du routeur**.

| route | codage |
|-------|--------|
| `198.51.100.0/24` par `192.0.2.254` | `24, 198,51,100, 192,0,2,254` |
| `172.16.0.0/12` par `192.0.2.254` | `12, 172,16, 192,0,2,254` |
| `10.0.0.0/8` par `192.0.2.254` | `8, 10, 192,0,2,254` |
| route par défaut par `192.0.2.1` | `0, 192,0,2,1` |

### Sur le serveur

`dhcpd` ne connaît pas cette option par son nom : il faut la **déclarer**, une fois et hors de
tout bloc, avant de lui donner une valeur dans le `subnet` concerné.

```
option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;

subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.100 192.0.2.150;
    option routers 192.0.2.1;
    option rfc3442-classless-static-routes 24, 198,51,100, 192,0,2,254, 0, 192,0,2,1;
}
```

Trois règles :

- **un client qui reçoit l'option 121 ignore l'option `routers`** : la route par défaut doit donc
  figurer **aussi** dans l'option 121. On garde `option routers` pour les clients qui ne
  connaissent pas l'option 121 ;
- les routeurs cités doivent être sur le réseau du client : l'option se place dans le `subnet` de
  ce réseau, pas parmi les options globales ;
- `dhcpd` n'envoie l'option qu'aux clients qui la demandent (option 55), ce que fait `dhclient`.

Le nom donné à l'option est libre, puisque seul le code 121 voyage. Celui de l'exemple est le nom
qu'emploie `dhclient`.

### Sur le client

`dhclient` installe les routes reçues **à l'obtention d'un bail**, pas lors d'un simple
renouvellement : après une modification sur le serveur, redemandez un bail (`ifdown eth0` puis
`ifup eth0`).

```
ip route                                             # les routes installées
grep classless /var/lib/dhcp/dhclient.eth0.leases    # l'option reçue
```

Dans le fichier de baux, l'option apparaît telle que le serveur l'a envoyée :

```
  option rfc3442-classless-static-routes 24,198,51,100,192,0,2,254,0,192,0,2,1;
```
""")
            + tr("""
## 8. Plusieurs serveurs sur un même réseau

Un serveur unique est un point de défaillance : s'il tombe, les machines déjà configurées
gardent leur adresse jusqu'à la fin de leur bail, mais les nouvelles n'obtiennent rien. Rien
n'interdit d'avoir plusieurs serveurs DHCP sur un réseau : tous reçoivent le `DHCPDISCOVER`,
tous répondent par un `DHCPOFFER`, et le client choisit (en général la première offre). Deux
façons d'en tirer une **redondance** :

- **plages disjointes** (*split scope*) : les deux serveurs sont indépendants et ne se
  connaissent pas. Ils ne partagent pas leurs baux : leurs plages dynamiques ne doivent
  donc avoir **aucune adresse commune**, tandis que les options et les réservations doivent
  être **identiques** sur les deux ;
- **failover** : les deux serveurs partagent **la même plage** et se synchronisent par une
  connexion TCP.

### Plages disjointes

C'est la solution la plus simple, et elle fonctionne avec n'importe quels serveurs. Ses limites :
chaque serveur ne dispose que de sa part des adresses (si l'un tombe, l'autre doit pouvoir
servir seul toutes les machines), toute modification est à reporter à la main sur les deux, et
une machine peut changer d'adresse en changeant de serveur.

### Failover

La plage est placée dans un `pool` rattaché à une relation `failover peer` déclarée sur les
deux serveurs (l'un `primary`, l'autre `secondary`) :

```
failover peer "lan2" {
    primary;                           # "secondary;" sur l'autre serveur
    address 192.0.2.2;                 # adresse de ce serveur
    port 647;
    peer address 192.0.2.3;            # adresse de l'autre serveur
    peer port 647;
    max-response-delay 30;
    max-unacked-updates 10;
    load balance max seconds 3;
    mclt 120;                          # sur le serveur primaire uniquement
    split 128;                         # sur le serveur primaire uniquement
}

subnet 198.51.100.0 netmask 255.255.255.0 {
    option routers 198.51.100.1;
    pool {
        failover peer "lan2";
        deny dynamic bootp clients;
        range 198.51.100.100 198.51.100.150;
    }
}
```

| paramètre | rôle |
|-----------|------|
| `address`, `port`, `peer address`, `peer port` | les deux extrémités de la connexion TCP entre les serveurs |
| `max-response-delay` | secondes de silence du partenaire avant de considérer la liaison comme coupée |
| `max-unacked-updates` | nombre de mises à jour qui peuvent rester sans accusé de réception du partenaire |
| `split 128` | répartition des clients entre les serveurs : 128 sur 256, soit moitié-moitié |
| `load balance max seconds` | au-delà de cette attente du client (champ `secs`), les deux serveurs lui répondent |
| `mclt` | *Maximum Client Lead Time* : avance maximale d'un bail sur ce que le partenaire en sait |

En fonctionnement normal (`Both servers normal` dans le journal) les serveurs se
répartissent les clients (`split 128` : moitié-moitié) et un seul répond à un client donné ;
si l'un tombe, l'autre sert tout le monde. Tant qu'un bail n'a pas été confirmé par les deux
serveurs, sa durée est limitée au **MCLT** (*Maximum Client Lead Time*) : le premier bail d'un
client est donc court, et c'est en le renouvelant qu'il obtient la durée normale.

Les adresses libres du `pool` sont réparties entre les deux serveurs (`free` pour le primaire,
`backup` pour le secondaire dans `dhcpd.leases`), si bien que chacun peut encore en attribuer
quand il est seul. L'état de la relation est noté dans le journal et dans `dhcpd.leases` :

| état | situation |
|------|-----------|
| `recover`, `recover-done` | démarrage : les serveurs échangent ce qu'ils savent des baux |
| `normal` | les deux serveurs se voient et se synchronisent |
| `communications-interrupted` | le partenaire ne répond plus : chacun continue avec ses propres adresses libres, les baux étant limités au MCLT |
| `partner-down` | le partenaire est déclaré hors service par l'administrateur : le serveur restant reprend toute la plage |

Les deux serveurs doivent déclarer le même `pool`, et leurs horloges doivent être à la même
heure.
""")
            + tr("""
## 9. Le relais DHCP

Une diffusion ne traverse pas un routeur : un client ne peut pas atteindre un serveur situé
sur un autre réseau. Un **agent de relais**, placé sur le routeur, écoute les diffusions des
clients et les retransmet **en unicast** au(x) serveur(s) après avoir inscrit dans le champ
**`giaddr`** du message sa propre adresse sur le réseau du client.

```
   client                relais (routeur)                            serveur
     |                          |                                        |
     |--- DHCPDISCOVER -------->|                                        |
     |    (diffusion)           |--- DHCPDISCOVER ---------------------->|
     |                          |    unicast, giaddr = adresse du relais |
     |                          |<--- DHCPOFFER -------------------------|
     |<--- DHCPOFFER -----------|    envoyé à l'adresse giaddr           |
     |                          |                                        |
     |   puis, par le même chemin : DHCPREQUEST et DHCPACK               |
```

Le serveur :

- choisit le `subnet` (et donc la plage) d'après `giaddr` : il lui faut une déclaration
  `subnet` pour le réseau distant, avec une option `routers` **propre à ce réseau** ;
- répond au relais, à l'adresse `giaddr` (il doit donc avoir une route vers ce réseau) ;
  le relais remet la réponse au client.

Un seul serveur peut ainsi servir tous les réseaux d'un site, sans y avoir d'interface. Les
**renouvellements**, eux, ne passent pas par le relais : le client, qui a désormais une adresse,
écrit directement au serveur, ce qui suppose que le routage fonctionne entre les deux réseaux.
Un relais peut ajouter à la demande l'option 82, qui indique au serveur par où le client est
raccordé. Sur un routeur du commerce la fonction existe sous d'autres noms (`ip helper-address`
chez Cisco).

Le relais de l'ISC se configure dans `/etc/default/isc-dhcp-relay` :

```
SERVERS="192.0.2.2"          # adresse(s) du ou des serveurs, séparées par des espaces
INTERFACES="eth1 eth2"       # interfaces d'écoute
OPTIONS=""
```

`dhcrelay` doit écouter sur l'interface des **clients** et sur celle par laquelle arrivent
les **réponses des serveurs** (sinon les demandes partent mais les réponses sont ignorées).
On peut préciser le rôle de chaque interface avec `INTERFACES=""` et
`OPTIONS="-id eth2 -iu eth1"` (`-id` : côté clients, `-iu` : côté serveurs).

```
systemctl restart isc-dhcp-relay
ps -C dhcrelay -o pid,args             # seule vérification fiable que le relais tourne
dhcrelay -d -i eth1 -i eth2 192.0.2.2  # au premier plan, avec les messages (Ctrl-C pour arrêter)
```

`systemctl` annonce le service actif même quand `dhcrelay` a refusé de démarrer.
""")
            + tr("""
## 10. Observation et diagnostic

### Capturer les échanges

```
tcpdump -n -e -v -i eth0 port 67 or port 68
```

affiche pour chaque message les adresses MAC et IP, puis le contenu DHCP : `Your-IP`
(adresse proposée), `Gateway-IP` (`giaddr`), `Client-Ethernet-Address`, et les options
(`DHCP-Message` donne le type du message). Ouvrez un second terminal sur la machine pour
laisser la capture tourner pendant vos essais. Début d'un message (extrait simplifié) :

```
02:53:52:aa:bb:cc > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 342: (tos 0x10, ttl 128, …)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 02:53:52:aa:bb:cc, length 300, xid 0x6b3f2a1c
          Client-Ethernet-Address 02:53:52:aa:bb:cc
          Vendor-rfc1048 Extensions
            DHCP-Message (53), length 1: Discover
            Hostname (12), length 2: "m0"
            Parameter-Request (55), length 13:
              Subnet-Mask (1), BR (28), Time-Zone (2), Default-Gateway (3), …
```

| ce que l'on cherche | où le lire |
|---------------------|------------|
| adresses MAC source et destination | début de la première ligne (option `-e`) |
| adresses IP et ports | `0.0.0.0.68 > 255.255.255.255.67` : le dernier nombre de chaque côté est le port UDP |
| sens du message | `Request` (venant d'un client) ou `Reply` (venant d'un serveur) |
| type du message | option `DHCP-Message` |
| adresse attribuée | `Your-IP` |
| passage par un relais | `Gateway-IP` |
| serveur qui répond, ou serveur retenu par le client | option `Server-ID` |
| durée du bail | option `Lease-Time` |

### Particularités de la maquette

- le réseau virtuel se comporte comme un **concentrateur** (*hub*) : une capture sur
  n'importe quelle machine montre **toutes** les trames de son réseau, y compris les
  échanges unicast entre d'autres machines (par exemple entre le relais et un serveur) ;
- à chaque évaluation, une sonde émet sur `lan1` et `lan2` quelques requêtes DHCP de test.
  Elles viennent d'adresses MAC commençant par `02:53:52` avec le nom d'hôte `sonde`, ou
  reprennent l'adresse MAC de `m2` ou de `m4`. Vous les verrez dans les journaux et les
  captures ; elles ne sont jamais suivies d'un `DHCPREQUEST`, donc aucun bail n'est
  enregistré.

### Chercher une panne

Suivez le trajet du message, un point à la fois :

1. le client émet-il sa demande ? (capture sur le client)
2. le serveur la reçoit-il ? (capture ou journal sur le serveur)
3. le serveur répond-il ? (journal du serveur)
4. la réponse arrive-t-elle au client ? (capture sur le client)

| symptôme | cause probable | à vérifier |
|----------|----------------|------------|
| `dhclient` répète ses `DHCPDISCOVER` puis affiche `No DHCPOFFERS received` | serveur arrêté ou à l'écoute sur une autre interface ; réseau sans serveur ni relais | `ps -C dhcpd -o pid,args`, journal du serveur |
| le serveur ne démarre pas : `No subnet declaration for eth0`, `Not configured to listen on any interfaces!` | aucun `subnet` pour le réseau de l'interface d'écoute | `dhcpd.conf`, `ip a` |
| le serveur ne démarre pas : erreur avec un numéro de ligne (`semicolon expected`) | faute de syntaxe | `dhcpd -t -cf /etc/dhcp/dhcpd.conf` |
| journal du serveur : `no free leases` | plage épuisée, ou `subnet` sans `range` | `dhcp-lease-list`, `dhcpd.conf` |
| journal du serveur : `unknown network segment` | demande relayée depuis un réseau pour lequel le serveur n'a pas de `subnet` | `Gateway-IP` dans la capture, `dhcpd.conf` |
| le client a une adresse mais ne sort pas de son réseau | option `routers` absente, ou qui n'est pas celle de ce réseau | `ip route` sur le client |
| le client a une adresse mais ne résout aucun nom | option `domain-name-servers` absente | `/etc/resolv.conf` sur le client |
| le client n'a plus de route par défaut depuis que le serveur envoie l'option 121 | l'option 121 ne contient pas la route par défaut : `routers` est alors ignoré | `ip route` sur le client, valeur de l'option |
| une machine réservée reçoit une adresse de la plage dynamique | adresse MAC erronée dans le bloc `host`, ou service non relancé | `ip link show eth0`, journal du serveur |
| à travers un relais : les demandes partent, rien ne revient | le relais n'écoute pas l'interface côté serveur, ou le serveur n'a pas de route vers `giaddr` | `ps -C dhcrelay -o pid,args`, capture sur le réseau du serveur |
| le client reçoit un `DHCPNAK` | il redemande une adresse qui n'est pas de ce réseau, ou qui a été réattribuée | rien : il repart de lui-même en `DHCPDISCOVER` |
""")
            + tr("""
## 11. Sécurité

DHCP ne comporte **aucune authentification** : le client fait confiance au premier serveur qui
lui répond, et le serveur à l'adresse MAC que le client annonce.

- **Serveur pirate** (*rogue DHCP server*) : n'importe quelle machine du réseau peut répondre
  aux `DHCPDISCOVER`. Un routeur domestique branché par erreur distribue de mauvaises adresses ;
  un attaquant s'annonce comme routeur par défaut ou comme serveur DNS, et voit passer ou
  détourne tout le trafic de ses victimes.
- **Épuisement de la plage** (*DHCP starvation*) : un attaquant demande des baux sous des
  milliers d'adresses MAC inventées, jusqu'à vider la plage : les vraies machines n'obtiennent
  plus rien.
- **Usurpation** : en prenant l'adresse MAC d'une machine, on obtient l'adresse qui lui est
  réservée.

La parade se trouve dans les commutateurs. Le **DHCP snooping** n'accepte les messages de
serveur (`DHCPOFFER`, `DHCPACK`) que sur les ports déclarés de confiance, limite le débit des
demandes sur les autres, et retient quelle adresse a été attribuée à quelle machine sur quel
port, ce que d'autres protections réutilisent (contre l'usurpation ARP notamment).
""")
#             + tr("""
# ## 12. Pour aller plus loin
#
# - **DNS dynamique** : le serveur DHCP peut inscrire dans le DNS le nom de chaque machine à
#   laquelle il attribue une adresse (`ddns-update-style`). Ce mécanisme n'est pas utilisé ici.
# - **Démarrage par le réseau** (PXE) : les paramètres `next-server` et `filename` de `dhcpd.conf`
#   indiquent à une machine sans système où télécharger son programme de démarrage.
# - **IPv6** : l'autoconfiguration sans serveur (SLAAC, à partir des annonces des routeurs) suffit
#   souvent. **DHCPv6** (RFC 8415, 2018) est un protocole distinct : ports UDP 546 (client) et 547
#   (serveur), multidiffusion vers `ff02::1:2` au lieu de la diffusion, messages `SOLICIT`,
#   `ADVERTISE`, `REQUEST` et `REPLY`, clients identifiés par un DUID et non par leur adresse MAC.
#   Il ne distribue pas la route par défaut, toujours apprise des annonces des routeurs.
# - **Kea** : ISC DHCP n'est plus développé depuis 2022. Son successeur, Kea, se configure en
#   JSON mais reprend les mêmes notions (réseaux, plages, réservations, relais, haute
#   disponibilité). ISC DHCP reste très répandu et sa configuration illustre directement les
#   mécanismes du protocole.
#
# Documentation : `man dhcpd.conf`, `man dhcp-options`, `man dhcpd.leases`, `man dhclient.conf`,
# `man dhcrelay` ; RFC 2131 et RFC 2132 (1997).
# """)
        )

    # -- configuration files -------------------------------------------------------

    def _unbound_conf(self) -> str:
        """unbound on srv0: serves the static names of the lab (zone DOMAIN)."""
        d = self.data
        names = {
            "srv0": [d.ips.srv0],
            "srv1": [d.ips.srv1],
            "srv2": [d.ips.srv2],
            "r1": [d.ips.r1_lan0, d.ips.r1_lan1, d.ips.r1_lan2],
            "r2": [d.ips.r2_lan1],
            "srv3": [d.ips.srv3],
            "m2": [d.ips.m2],
            "m4": [d.ips.m4],
        }
        lines = [
            "server:",
            "    interface: 0.0.0.0",
            "    access-control: 0.0.0.0/0 allow",
            '    chroot: ""',
            # no DNSSEC validation and no recursion: the lab has no Internet access, any
            # name outside the zone gets an immediate NXDOMAIN instead of a long timeout
            '    module-config: "iterator"',
            '    local-zone: "." static',
            f'    local-zone: "{DOMAIN}." static',
        ]
        for name, ips in names.items():
            for ip in ips:
                lines.append(f'    local-data: "{name}.{DOMAIN}. IN A {ip.ip}"')
        return "\n".join(lines) + "\n"

    def _dhcpd_globals(self, default_lease: int, max_lease: int) -> list:
        return [
            "ddns-update-style none;",
            "authoritative;",
            f"default-lease-time {default_lease};",
            f"max-lease-time {max_lease};",
            f'option domain-name "{DOMAIN}";',
            f"option domain-name-servers {self.data.ips.srv0.ip};",
            "",
        ]

    def _srv0_dhcpd_conf(self) -> str:
        d = self.data
        lines = [
            "# dhcpd.conf de srv0 (généré par le TP)",
            # dhcpd never grants less than min-lease-time (300 s by default)
            "min-lease-time 60;",
        ]
        lines += self._dhcpd_globals(d.lease0, 2 * d.lease0)
        lines += [
            f"subnet {d.nets.lan0.network_address} netmask {d.nets.lan0.netmask} {{",
            f"    range {d.ips.pool0_min.ip} {d.ips.pool0_max.ip};",
            f"    option routers {d.ips.r1_lan0.ip};",
            "}",
        ]
        return "\n".join(lines) + "\n"

    def _solution_host(self, name: str) -> list:
        """`host` declaration reserving the fixed address of m2 / m4."""
        d = self.data
        return [
            f"host {name} {{",
            f"    hardware ethernet {_mac(getattr(d.macs, name))};",
            f"    fixed-address {getattr(d.ips, name).ip};",
            "}",
        ]

    def _solution_lan2_subnet(self, failover: bool) -> list:
        """`subnet` declaration of lan2: a plain range (part 6, srv1 alone), then the same range
        in a failover pool (part 7, both servers)."""
        d = self.data
        if failover:
            body = [
                f"    option routers {d.ips.r1_lan2.ip};",
                "    pool {",
                f'        failover peer "{FAILOVER_NAME}";',
                "        deny dynamic bootp clients;",
                f"        range {d.ips.c_min.ip} {d.ips.c_max.ip};",
                "    }",
            ]
        else:
            body = [
                f"    range {d.ips.c_min.ip} {d.ips.c_max.ip};",
                f"    option routers {d.ips.r1_lan2.ip};",
            ]
        return [
            f"subnet {d.nets.lan2.network_address} netmask {d.nets.lan2.netmask} {{",
            *body,
            "}",
        ]

    def _solution_routes(self) -> list:
        """Routes the lan1 clients receive by option 121 (part 4): lan3 through r2, and the
        default route, which a client no longer takes from `routers` once it gets this option."""
        d = self.data
        return [
            (d.nets.lan3, d.ips.r2_lan1.ip),
            (IPv4Network("0.0.0.0/0"), d.ips.r1_lan1.ip),
        ]

    def _solution_lan1_subnet(self, server: str, routes: bool) -> list:
        """`subnet` declaration of lan1: range A on srv1, range B on srv2 (split scope), with
        the classless static routes from part 4 on."""
        d = self.data
        low, high = (
            (d.ips.a_min, d.ips.a_max) if server == "srv1" else (d.ips.b_min, d.ips.b_max)
        )
        lines = [
            f"subnet {d.nets.lan1.network_address} netmask {d.nets.lan1.netmask} {{",
            f"    range {low.ip} {high.ip};",
            f"    option routers {d.ips.r1_lan1.ip};",
        ]
        if routes:
            value = render_classless_routes(self._solution_routes())
            lines.append(f"    option {CLASSLESS_ROUTES_OPTION} {value};")
        return lines + ["}"]

    def _solution_dhcpd_conf(self, server: str, part: int = 7) -> str:
        """Reference dhcpd.conf of srv1 / srv2 at the end of *part*.  Part 7 is the file the `final`
        state writes: split scope on lan1, failover pool on lan2.  The earlier ones are shown to
        the instructor: lan1 alone (part 2), then with the reservation of m2 (part 3) and the
        classless static routes (parts 4 and 5, srv2 being configured in part 5), then on srv1
        with lan2 and the reservation of m4 (part 6)."""
        d = self.data
        primary = server == "srv1"
        routes = part >= 4
        failover = part >= 7
        lan2 = failover or (primary and part >= 6)
        me, peer = (
            (d.ips.srv1.ip, d.ips.srv2.ip)
            if primary
            else (d.ips.srv2.ip, d.ips.srv1.ip)
        )
        lines = [f"# dhcpd.conf de {server} (solution de référence)"]
        lines += self._dhcpd_globals(d.default_lease, d.max_lease)
        if routes:
            lines += [CLASSLESS_ROUTES_DECLARATION, ""]
        if failover:
            lines += [
                f'failover peer "{FAILOVER_NAME}" {{',
                "    primary;" if primary else "    secondary;",
                f"    address {me};",
                "    port 647;",
                f"    peer address {peer};",
                "    peer port 647;",
                "    max-response-delay 30;",
                "    max-unacked-updates 10;",
                "    load balance max seconds 3;",
            ]
            if primary:
                lines += [f"    mclt {d.mclt};", "    split 128;"]
            lines += ["}", ""]
        lines += self._solution_lan1_subnet(server, routes)
        if lan2:
            lines += ["", *self._solution_lan2_subnet(failover)]
        if part >= 3:
            lines += ["", *self._solution_host("m2")]
        if lan2:
            lines += self._solution_host("m4")
        return "\n".join(lines) + "\n"

    def _solution_relay(self, part: int = 7) -> DhcpRelayParameters:
        """Relay of r1: towards srv1 (part 6), then towards both failover peers (part 7)."""
        d = self.data
        servers = [d.ips.srv1.ip, d.ips.srv2.ip] if part >= 7 else [d.ips.srv1.ip]
        return DhcpRelayParameters(servers=servers, interfaces=["eth1", "eth2"])

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only (r1, r2).
            if m in SYSTEMD_MACHINES:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, f"sysctl -w net.ipv4.ip_forward={int(m == 'r1')}")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m == "r2"))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n")
        for m in ("r1", "srv0", "srv1", "srv2"):
            self.file(
                m, "/etc/resolv.conf", f"search {DOMAIN}\nnameserver {d.ips.srv0.ip}\n"
            )

        # Clients: link up, no address, no resolver (DHCP will provide everything).
        for m in CLIENTS:
            self.cmd(m, "ip link set eth0 up")
            self.file(m, "/etc/resolv.conf", "")
            # ifup keeps its state in /run/network, which only an init system creates.
            self.cmd(m, "mkdir -p /run/network")

        # srv0: DNS for the lab names, DHCP for lan0.  Both daemons are started directly (no
        # init system in this container) with their output dropped so that the commands
        # return.  `systemctl start unbound` would first run unbound-anchor, which waits
        # more than a minute for the Internet before unbound answers.
        self.file("srv0", "/etc/unbound/unbound.conf", self._unbound_conf())
        self.cmd(
            "srv0",
            "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'",
        )
        self.file("srv0", "/etc/dhcp/dhcpd.conf", self._srv0_dhcpd_conf())
        self.cmd(
            "srv0",
            "sh -c 'touch /var/lib/dhcp/dhcpd.leases; "
            "dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf eth0 >/dev/null 2>&1'",
        )

        for iface in ("eth0", "eth1"):
            self.cmd("sonde", f"ip link set {iface} up")
        install_dhcp_probe(net_scheme=self, machine="sonde")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: every grade element reaches its maximum.

        Step 1 configures and restarts dhcpd on srv1 / srv2 (leases wiped, so that the state
        can be re-applied) and the relay on r1; step 2 restarts every client from scratch
        with a persistent configuration.  The failover pair needs a few seconds to reach
        `normal`: wait ~10 s before an evaluation.  Forms are filled through cheat_answers.
        """
        d = self.data
        for srv in SERVERS:
            self.cmd(
                srv,
                "sh -c 'systemctl stop isc-dhcp-server; pkill -x dhcpd; "
                "rm -f /var/run/dhcpd.pid /var/lib/dhcp/dhcpd.leases*; true'",
            )
            self.file(srv, "/etc/default/isc-dhcp-server", DHCPD_DEFAULTS)
            self.file(srv, "/etc/dhcp/dhcpd.conf", self._solution_dhcpd_conf(srv))
            self.cmd(srv, "systemctl restart isc-dhcp-server")
        self.cmd(
            "r1",
            "sh -c 'systemctl stop isc-dhcp-relay; pkill -x dhcrelay; rm -f /var/run/dhcrelay.pid; true'",
        )
        set_dhcp_relay(
            net_scheme=self, machine="r1", relay_params=self._solution_relay()
        )

        for m in CLIENTS:
            self.file(m, "/etc/network/interfaces", DHCP_INTERFACES, step=2)
            self.cmd(
                m,
                "sh -c 'mkdir -p /run/network; ifdown --force eth0 >/dev/null 2>&1; pkill -x dhclient; "
                "rm -f /run/dhclient*.pid /var/lib/dhcp/dhclient*.leases; ip -4 addr flush dev eth0; "
                "timeout 90 ifup eth0 >/tmp/ifup.log 2>&1'",
                step=2,
            )


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _int(s, default: int = -1) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _same_ip(answer, expected) -> bool:
    return _norm(answer) == str(expected)


def _dynamic_addresses(output: str) -> list:
    """Addresses flagged `dynamic` in `ip -4 -o addr show`: set with a lifetime by dhclient."""
    result = []
    for line in output.splitlines():
        m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+/\d+) .*\bdynamic\b", line)
        if m:
            result.append(IPv4Interface(m.group(1)))
    return result


def _in_range(ip, low: IPv4Interface, high: IPv4Interface) -> bool:
    return ip is not None and low.ip <= ip <= high.ip


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        srv_ip = {s: getattr(d.ips, s).ip for s in SERVERS}
        mac_m2, mac_m4 = _mac(d.macs.m2), _mac(d.macs.m4)
        # part 4: what option 121 must give to the lan1 clients
        lan1_routes = self.net_scheme._solution_routes()
        lan3_route, default_route = lan1_routes

        # ---------------- diagnostics kept in the archive -------------------------
        for s in SERVERS:
            for c in (
                "grep -Ev '^[[:space:]]*(#|$)' /etc/dhcp/dhcpd.conf",
                "grep -Ev '^[[:space:]]*(#|$)' /etc/default/isc-dhcp-server",
                "journalctl -u isc-dhcp-server --no-pager -n 40",
            ):
                self.test(s, c, allow_error=True)
        for c in (
            "grep -Ev '^[[:space:]]*(#|$)' /etc/default/isc-dhcp-relay",
            "journalctl -u isc-dhcp-relay --no-pager -n 20",
        ):
            self.test("r1", c, allow_error=True)

        # ---------------- active probe (every call unconditional: two-pass contract) --
        # The spec only depends on the lab data: the command is the same on every pass.
        probe_mac = _mac(d.macs.probe)
        replies = dhcp_probe(
            self,
            "sonde",
            {
                "wait": 2.5,
                "late_wait": 2.0,
                "interfaces": {
                    "eth0": [
                        dhcp_probe_query("dyn", probe_mac, hostname="sonde"),
                        dhcp_probe_query("fixed", mac_m2, hostname="sonde"),
                        dhcp_probe_query(
                            "nak",
                            _mac(d.macs.nak),
                            msg_type="request",
                            requested=FOREIGN_ADDRESS,
                            hostname="sonde",
                        ),
                        # Late queries are sent once 'dyn' has been answered: a second DISCOVER of
                        # the same client is dropped while the first offer is being ping-checked.
                        dhcp_probe_query(
                            "max",
                            probe_mac,
                            lease=LONG_LEASE,
                            late=True,
                            hostname="sonde",
                        ),
                    ],
                    "eth1": [
                        dhcp_probe_query("dyn", probe_mac, hostname="sonde"),
                        dhcp_probe_query("fixed", mac_m4, hostname="sonde"),
                        dhcp_probe_query(
                            "retry", probe_mac, late=True, hostname="sonde"
                        ),
                    ],
                },
            },
        )
        lan1, lan2 = replies.get("eth0", {}), replies.get("eth1", {})

        def answers(
            lan: dict, query: str, server: str, msg_type: str = "OFFER"
        ) -> list:
            """Replies of `server` (by server identifier) to a probe query.  The relay may
            duplicate them on lan1 (same content, giaddr set): all of them are returned."""
            return [
                r
                for r in lan.get(query, [])
                if r.msg_type == msg_type and r.server_id == srv_ip[server]
            ]

        def every(items: list, predicate) -> bool:
            return bool(items) and all(predicate(r) for r in items)

        def lan1_server(server: str, low: IPv4Interface, high: IPv4Interface) -> dict:
            dyn, longest = answers(lan1, "dyn", server), answers(lan1, "max", server)
            # When the address picked for 'dyn' answers the server's ping check (it is in use
            # without a lease), dhcpd abandons it and sends nothing: the late query is then
            # the first offer.  Everything but the default lease time can be read from it.
            offers = dyn + longest
            return {
                "offer": bool(offers),
                "range": every(offers, lambda r: _in_range(r.yiaddr, low, high)),
                "mask_router": every(
                    offers,
                    lambda r: (
                        r.subnet_mask == d.nets.lan1.netmask
                        and r.routers == [d.ips.r1_lan1.ip]
                    ),
                ),
                "dns": every(offers, lambda r: r.dns_servers == [d.ips.srv0.ip]),
                "domain": every(offers, lambda r: _norm(r.domain_name) == DOMAIN),
                "default_lease": every(dyn, lambda r: r.lease_time == d.default_lease),
                "max_lease": every(longest, lambda r: r.lease_time == d.max_lease),
                "nak": bool(answers(lan1, "nak", server, "NAK")),
                "fixed": every(
                    answers(lan1, "fixed", server), lambda r: r.yiaddr == d.ips.m2.ip
                ),
                "route_lan3": every(offers, lambda r: lan3_route in r.classless_routes),
                # exactly one default route in the option, the one of `routers`
                "route_default": every(
                    offers,
                    lambda r: (
                        [gw for net, gw in r.classless_routes if net == default_route[0]]
                        == [default_route[1]]
                    ),
                ),
            }

        srv1 = lan1_server("srv1", d.ips.a_min, d.ips.a_max)
        srv2 = lan1_server("srv2", d.ips.b_min, d.ips.b_max)
        lan2_dyn = {
            s: answers(lan2, "dyn", s) + answers(lan2, "retry", s) for s in SERVERS
        }
        lan2_fixed = {s: answers(lan2, "fixed", s) for s in SERVERS}

        # ---------------- servers and relay ---------------------------------------
        dhcpd_ifaces = {m: get_dhcpd_interfaces(self, m) for m in SERVERS + ["r1"]}
        relay_running, relay = check_running_dhcp_relay(self, "r1")
        failover_state = {s: get_dhcp_failover_state(self, s) for s in SERVERS}
        failover_conf = {
            s: self.test(
                s,
                "grep -c '^[^#]*failover peer' /etc/dhcp/dhcpd.conf",
                allow_error=True,
            )[0]
            for s in SERVERS
        }

        # ---------------- clients -------------------------------------------------
        client = {}
        for m in CLIENTS:
            addr_out, _ = self.test(m, "ip -4 -o addr show dev eth0", allow_error=True)
            route_out, _ = self.test(m, "ip -4 route show", allow_error=True)
            leases = get_dhclient_leases(self, m)
            leased = {lease.get("fixed-address") for lease in leases}
            persistent, _errors = get_persistent_net_config_entry(self, m)
            # obtained by DHCP: lifetime set by dhclient-script and lease recorded by dhclient
            addresses = [
                a.ip for a in _dynamic_addresses(addr_out) if str(a.ip) in leased
            ]
            client[m] = {
                "addresses": addresses,
                "gateways": re.findall(r"^default via (\S+)", route_out, re.MULTILINE),
                "persistent": persistent[:1] == ["dhcp"],
                # routes of the kernel through a router, as (network, router) strings
                "routes": set(
                    re.findall(
                        r"^(\d+\.\d+\.\d+\.\d+/\d+) via (\S+)", route_out, re.MULTILINE
                    )
                ),
                # routes of option 121 in the leases recorded for the current address
                "lease_routes": {
                    route
                    for lease in leases
                    if lease.get("fixed-address") in [str(a) for a in addresses]
                    for route in parse_classless_routes(
                        lease.get(CLASSLESS_ROUTES_OPTION)
                    )
                },
            }

        def has_address(
            m: str, low: IPv4Interface, high: IPv4Interface, gateway: IPv4Interface
        ) -> bool:
            c = client[m]
            return any(_in_range(a, low, high) for a in c["addresses"]) and c[
                "gateways"
            ] == [str(gateway.ip)]

        def has_dhcp_route(m: str) -> bool:
            """The route to lan3 is installed and was given by the lease (not typed by hand)."""
            c = client[m]
            installed = (str(lan3_route[0]), str(lan3_route[1])) in c["routes"]
            return installed and lan3_route in c["lease_routes"]

        def resolves(m: str, name: str, expected: IPv4Interface) -> bool:
            out, _ = self.test(m, f"timeout 5 getent hosts {name}", allow_error=True)
            return str(expected.ip) in out.split()

        def ping(src: str, dest: IPv4Interface) -> bool:
            return eval_ping(
                self, src=src, dest=dest.ip, count=2, deadline=3, allow_error=True
            )

        # The texts of a question are not indented: the first one starts at the margin, so an
        # indented one would be drawn as a code block.
        addressing = no_tr(f"""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan0` | `{d.nets.lan0}` | `srv0` (`{d.ips.srv0.ip}`), `r1` eth0 (`{d.ips.r1_lan0.ip}`), `m0` |
| `lan1` | `{d.nets.lan1}` | `srv1` (`{d.ips.srv1.ip}`), `srv2` (`{d.ips.srv2.ip}`), `r1` eth1 (`{d.ips.r1_lan1.ip}`), `r2` eth0 (`{d.ips.r2_lan1.ip}`), `m1`, `m2` |
| `lan2` | `{d.nets.lan2}` | `r1` eth2 (`{d.ips.r1_lan2.ip}`), `m3`, `m4` |
| `lan3` | `{d.nets.lan3}` | `r2` eth1 (`{d.ips.r2_lan3.ip}`), `srv3` (`{d.ips.srv3.ip}`) |
""")

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente le protocole, les fichiers de configuration et
les commandes utiles. Le serveur `srv0` (réseau `lan0`) est déjà configuré ; `srv1`, `srv2`
et `r1` n'ont aucun service DHCP ; les machines `m0` à `m4` n'ont aucune configuration réseau.

Règles valables pour tout le TP :

- chaque client doit finir avec une configuration **persistante** (`/etc/network/interfaces`)
  activée par `ifup eth0` ;
- après chaque modification d'un fichier de configuration, **relancez le service** et
  vérifiez dans le journal qu'il a bien démarré ;
- l'évaluation interroge les serveurs tels qu'ils tournent au moment où elle est lancée :
  un serveur arrêté pour un essai doit être relancé.
""")
            + tr("""
Ce TP met en œuvre **DHCP** (*Dynamic Host Configuration Protocol*, RFC 2131, 1997) avec les
logiciels de l'**ISC** fournis par Debian : le client `dhclient`, le serveur `dhcpd` (paquet
`isc-dhcp-server`) et le relais `dhcrelay` (paquet `isc-dhcp-relay`).

Le routeur `r1` relie les réseaux `lan0`, `lan1` et `lan2`. Un second routeur, `r2`, relie
`lan1` à `lan3` ; `r1` ne connaît pas `lan3` :
""")
            + addressing
            + tr("""
Le serveur `srv0` est **déjà configuré** : il est serveur DHCP pour `lan0` et serveur DNS du
domaine `tp-dhcp.lan` (vous ne pouvez pas vous y connecter). Le routeur `r2` et le serveur
`srv3` sont eux aussi déjà configurés, et vous ne pouvez pas non plus vous y connecter. Les
serveurs `srv1` et `srv2` et le routeur `r1` ont leur configuration IP statique mais aucun
service DHCP. Les machines `m0` à `m4` n'ont **aucune** configuration réseau : ni adresse, ni
route, ni serveur DNS.

Les noms `srv0` à `srv3`, `r1`, `r2`, `m2` et `m4` ne sont connus que du serveur DNS `srv0` :
un client ne peut donc les utiliser (`ping srv1`) qu'après avoir été configuré par DHCP.
""")
            + tr("""
## Plan du TP

1. client DHCP et observation du protocole (`m0`, serveur `srv0`) ;
2. serveur DHCP sur `srv1` pour `lan1` ;
3. adresse fixe pour `m2` ;
4. routes distribuées par DHCP : accès à `lan3` par `r2` ;
5. second serveur (`srv2`) sur `lan1` ;
6. relais DHCP sur `r1` pour `lan2` ;
7. failover entre `srv1` et `srv2` pour `lan2`.

Les parties sont à faire **dans l'ordre**. Les réponses aux questions, les serveurs et l'état
des clients sont évalués automatiquement (bouton d'évaluation) ; les adresses, plages et
durées demandées sont propres à votre instance du TP.
""")
            + instructor(
                tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour les adresses de ce
projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
  formulaires. Il efface les baux des serveurs et redemande ceux des clients : attendre une
  dizaine de secondes, le temps que le failover passe en état `normal`, avant de lancer une évaluation.
- L'évaluation porte sur le comportement des serveurs : la machine cachée `sonde`, reliée à `lan1` et à
  `lan2`, émet des requêtes de test et l'on note ce que lui répond chaque serveur, reconnu à son
  `dhcp-server-identifier`. La forme des fichiers `dhcpd.conf` est donc libre (seule la partie 7 y
  cherche `failover peer`).
- Sont lus en plus : la ligne de commande des processus `dhcpd` et `dhcrelay`, l'état du failover dans
  `dhcpd.leases`, et sur chaque client l'adresse, la route par défaut, les baux de `dhclient` et
  `/etc/network/interfaces`.
- Un client n'est compté que si son adresse vient de DHCP (marquée `dynamic` dans `ip a` et inscrite
  dans un fichier `/var/lib/dhcp/dhclient*.leases`) et s'il n'a qu'une route par défaut, vers le routeur
  de son réseau : une adresse ajoutée avec `ip addr add` ne rapporte rien.
- Configuration persistante d'un client : `iface eth0 inet dhcp` dans `/etc/network/interfaces` ; un
  fichier de `/etc/network/interfaces.d/` n'est lu que si `/etc/network/interfaces` contient la ligne
  `source /etc/network/interfaces.d/*`.
""")
            ),
        )

        # =====================================================================
        # Partie 1 — Client DHCP
        # =====================================================================
        part1 = self.add_grade_part(
            no_tr("partie1"), tr("Partie 1 — Client DHCP et observation du protocole")
        )
        q1_answers = {
            "server": str(d.ips.srv0.ip),
            "lease": str(d.lease0),
            "router": str(d.ips.r1_lan0.ip),
            "dns": str(d.ips.srv0.ip),
            "domain": DOMAIN,
            "port_server": "67",
            "port_client": "68",
            "disc_src": "0.0.0.0",
            "disc_dst": "255.255.255.255",
            "disc_mac": "ff:ff:ff:ff:ff:ff",
            "msg1": "DHCPDISCOVER",
            "msg2": "DHCPOFFER",
            "msg3": "DHCPREQUEST",
            "msg4": "DHCPACK",
            "release": "DHCPRELEASE",
            "renew_msg": "DHCPREQUEST",
            "renew_dst": "adressé en unicast au serveur",
        }
        # One question for the whole part: the work to do, then the two groups of fields.
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Client DHCP et observation du protocole"),
            description=tr("""
Sur `m0` (réseau `lan0`, serveur `srv0`) :

1. constatez avec `ip a`, `ip route` et `cat /etc/resolv.conf` que rien n'est configuré ;
2. dans un second terminal sur `m0`, lancez la capture
   `tcpdump -n -e -v -i eth0 port 67 or port 68` et laissez-la tourner ;
3. demandez un bail avec `dhclient -v eth0`. Refaites les vérifications du point 1, testez
   `ping srv1`, et lisez le bail enregistré dans `/var/lib/dhcp/dhclient.leases` ;
4. libérez le bail avec `dhclient -r -v eth0` et observez le message émis ;
5. rendez la configuration **persistante** (`/etc/network/interfaces`) et activez-la avec
   `ifup eth0` ;
6. laissez la capture tourner quelques minutes pour observer un **renouvellement** du bail.
""")
            + instructor(
                tr("""
**Solution.** Sur `m0` :

```
dhclient -v eth0       # DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK
dhclient -r -v eth0    # DHCPRELEASE
```

puis, dans `/etc/network/interfaces` :

```
{interfaces}
```

et `ifup eth0`.

- `srv0` donne à `m0` une adresse de `{pool_min}` à `{pool_max}`, la route par défaut `{router}`, le
  serveur DNS `{dns}` et le domaine `{domain}` : `ping srv1` fonctionne alors (nom résolu par `srv0`,
  paquets routés par `r1`).
- Le bail dure {lease} s : un renouvellement (`DHCPREQUEST` puis `DHCPACK`, tous deux en unicast)
  s'observe au plus tard à la moitié du bail, soit au bout de {renewal} s.
""").format(
                    interfaces=DHCP_INTERFACES.strip(),
                    pool_min=d.ips.pool0_min.ip,
                    pool_max=d.ips.pool0_max.ip,
                    router=d.ips.r1_lan0.ip,
                    dns=d.ips.srv0.ip,
                    domain=DOMAIN,
                    lease=d.lease0,
                    renewal=d.lease0 // 2,
                )
            )
            + tr("""
**Le bail obtenu par m0.** D'après le fichier de baux de `m0` :

- adresse IP du serveur DHCP (`dhcp-server-identifier`) : @@{server:[0-9.]+}@@
- durée du bail en secondes : @@{lease:[0-9]+}@@
- routeur par défaut : @@{router:[0-9.]+}@@ ; serveur DNS : @@{dns:[0-9.]+}@@
- nom de domaine : @@{domain:[a-zA-Z0-9.-]+}@@
""")
            + instructor(
                tr("""
**Réponses.**

- serveur DHCP : `{server}` (`srv0`)
- durée du bail : `{lease}` s
- routeur : `{router}` (`r1`) ; serveur DNS : `{dns}` (`srv0`)
- nom de domaine : `{domain}`
""").format(**q1_answers)
            )
            + tr("""
**Les messages DHCP.** D'après la capture sur `m0` :

- port UDP du serveur : @@{port_server:[0-9]+}@@ ; port UDP du client : @@{port_client:[0-9]+}@@
- `DHCPDISCOVER` : adresse IP source @@{disc_src:[0-9.]+}@@, adresse IP destination
  @@{disc_dst:[0-9.]+}@@, adresse MAC destination @@{disc_mac:[0-9a-fA-F:]+}@@
- ordre des quatre messages de l'obtention d'un bail :
  @@{msg1:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ puis
  @@{msg2:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ puis
  @@{msg3:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ puis
  @@{msg4:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@
- message émis par `dhclient -r` : @@{release:>DHCPDECLINE|DHCPINFORM|DHCPNAK|DHCPRELEASE}@@
- lors d'un renouvellement, le client envoie un
  @@{renew_msg:>DHCPDISCOVER|DHCPINFORM|DHCPREQUEST}@@ qui est
  @@{renew_dst:>diffusé sur le réseau|adressé en unicast au serveur}@@
""")
            + instructor(
                tr("""
**Réponses.**

- ports UDP : `{port_server}` (serveur) et `{port_client}` (client)
- `DHCPDISCOVER` : de `{disc_src}` vers `{disc_dst}`, adresse MAC destination `{disc_mac}`
- ordre des messages : `{msg1}`, `{msg2}`, `{msg3}`, `{msg4}`
- `dhclient -r` émet un `{release}`
- renouvellement : un `{renew_msg}` {renew_dst}
""").format(**q1_answers)
            ),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("client_bail_serveur"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                _same_ip(q1.get("server"), d.ips.srv0.ip)
                and _int(q1.get("lease")) == d.lease0
            ),
            description=tr("identifiant du serveur et durée du bail de m0"),
        )
        self.add_grade_element(
            title=no_tr("client_bail_options"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                _same_ip(q1.get("router"), d.ips.r1_lan0.ip)
                and _same_ip(q1.get("dns"), d.ips.srv0.ip)
                and _norm(q1.get("domain")) == DOMAIN
            ),
            description=tr("routeur, serveur DNS et domaine reçus par m0"),
        )
        self.add_grade_element(
            title=no_tr("client_ports"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                _int(q1.get("port_server")) == 67
                and _int(q1.get("port_client")) == 68
            ),
            description=tr("ports UDP du serveur et du client"),
        )
        self.add_grade_element(
            title=no_tr("client_discover_adresses"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                _norm(q1.get("disc_src")) == "0.0.0.0"
                and _norm(q1.get("disc_dst")) == "255.255.255.255"
                and _norm(q1.get("disc_mac")) == "ff:ff:ff:ff:ff:ff"
            ),
            description=tr("adresses IP et MAC d'un DHCPDISCOVER"),
        )
        self.add_grade_element(
            title=no_tr("client_ordre_messages"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                [_norm(q1.get(f"msg{i}")) for i in range(1, 5)]
                == ["dhcpdiscover", "dhcpoffer", "dhcprequest", "dhcpack"]
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("ordre des quatre messages"),
        )
        self.add_grade_element(
            title=no_tr("client_liberation_renouvellement"),
            max_grade=1,
            grade_part=part1,
            grade=int(
                _norm(q1.get("release")) == "dhcprelease"
                and _norm(q1.get("renew_msg")) == "dhcprequest"
                and "unicast" in _norm(q1.get("renew_dst"))
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("libération et renouvellement d'un bail"),
        )
        self.add_grade_element(
            title=no_tr("client_m0_adresse"),
            max_grade=2,
            grade_part=part1,
            grade=2
            * int(has_address("m0", d.ips.pool0_min, d.ips.pool0_max, d.ips.r1_lan0)),
            description=tr("m0 a obtenu son adresse et sa route par défaut par DHCP"),
        )
        self.add_grade_element(
            title=no_tr("client_m0_persistant"),
            max_grade=1,
            grade_part=part1,
            grade=int(client["m0"]["persistent"]),
            description=tr("configuration persistante de m0"),
        )
        self.add_grade_element(
            title=no_tr("client_m0_dns"),
            max_grade=1,
            grade_part=part1,
            grade=int(resolves("m0", "srv1", d.ips.srv1)),
            description=tr("m0 résout le nom srv1"),
        )

        # =====================================================================
        # Partie 2 — Serveur DHCP sur srv1
        # =====================================================================
        part2 = self.add_grade_part(
            no_tr("partie2"), tr("Partie 2 — Serveur DHCP sur srv1")
        )
        q2_answers = {"state": "active", "asked": str(d.max_lease)}
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Serveur DHCP sur srv1"),
            description=tr("""
Configurez `dhcpd` sur `srv1` pour le réseau `lan1` (`{lan1}`) :

- écoute sur l'interface `eth0` **uniquement** ;
- plage dynamique de `{a_min}` à `{a_max}` ;
- routeur par défaut `{router}`, serveur DNS `{dns}`, nom de domaine `{domain}` ;
- durée de bail par défaut **{default_lease} s**, durée maximale **{max_lease} s** ;
- serveur `authoritative`.

Vérifiez la syntaxe (`dhcpd -t`), lancez le service et contrôlez le journal. Puis sur `m1` :
configuration persistante, `ifup eth0`, et vérifications (`ip a`, `ip route`, `ping srv0`).
Sur `srv1`, suivez l'échange dans le journal et retrouvez le bail de `m1` dans
`/var/lib/dhcp/dhcpd.leases`.
""").format(
                lan1=d.nets.lan1,
                a_min=d.ips.a_min.ip,
                a_max=d.ips.a_max.ip,
                router=d.ips.r1_lan1.ip,
                dns=d.ips.srv0.ip,
                domain=DOMAIN,
                default_lease=d.default_lease,
                max_lease=d.max_lease,
            )
            + instructor(
                tr("""
**Solution.** Sur `srv1`, `/etc/default/isc-dhcp-server` :

```
{defaults}
```

`/etc/dhcp/dhcpd.conf` :

```
{conf}
```

puis :

```
dhcpd -t -cf /etc/dhcp/dhcpd.conf
systemctl restart isc-dhcp-server
journalctl -u isc-dhcp-server -n 20
```

Sur `m1` : `/etc/network/interfaces` comme sur `m0`, puis `ifup eth0`.

- La sonde doit recevoir de `srv1` une offre dans la plage, avec le masque, le routeur, le serveur DNS,
  le domaine et un bail de {default_lease} s. Elle demande ensuite un bail très long, qui doit être
  ramené à {max_lease} s. `authoritative` se vérifie au `DHCPNAK` opposé à la demande d'une adresse
  étrangère au réseau.
- Interface d'écoute : c'est la ligne de commande du processus qui est lue (`ps -C dhcpd -o args` ne
  doit nommer que `eth0`). Avec `INTERFACESv4` vide, le service est en échec mais un `dhcpd` tourne sur
  toutes les interfaces, et `systemctl restart` ne le remplace pas : `pkill dhcpd`, puis relancer.
- `m1` peut tenir son adresse de `srv1` ou, à partir de la partie 5, de `srv2`.
""").format(
                    defaults=DHCPD_DEFAULTS.strip(),
                    conf=self.net_scheme._solution_dhcpd_conf("srv1", part=2).strip(),
                    default_lease=d.default_lease,
                    max_lease=d.max_lease,
                )
            )
            + tr("""
**Baux accordés.**

- état (`binding state`) du bail de `m1` dans `dhcpd.leases` :
  @@{state:>abandoned|active|backup|expired|free}@@
- sur `m1`, ajoutez la ligne `send dhcp-lease-time 86400;` à `/etc/dhcp/dhclient.conf` puis
  redemandez un bail (`ifdown eth0` puis `ifup eth0`). Durée du bail obtenu, en secondes :
  @@{asked:[0-9]+}@@
""")
            + instructor(
                tr("""
**Réponses.** état `{state}` ; bail de `{asked}` s : le serveur ramène les 86400 s demandées à son
`max-lease-time`.
""").format(**q2_answers)
            ),
            cheat_answers={"final": q2_answers},
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_actif"),
            max_grade=2,
            grade_part=part2,
            grade=2 * int(dhcpd_ifaces["srv1"] is not None),
            description=tr("dhcpd tourne sur srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_interface"),
            max_grade=1,
            grade_part=part2,
            grade=int(dhcpd_ifaces["srv1"] == ["eth0"]),
            description=tr("dhcpd de srv1 lancé sur eth0 uniquement"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_offre"),
            max_grade=2,
            grade_part=part2,
            grade=2 * int(srv1["offer"]),
            description=tr("srv1 répond à un DHCPDISCOVER sur lan1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_plage"),
            max_grade=2,
            grade_part=part2,
            grade=2 * int(srv1["range"]),
            description=tr(
                "adresse proposée par srv1 dans la plage {a_min} – {a_max}"
            ).format(a_min=d.ips.a_min.ip, a_max=d.ips.a_max.ip),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_masque_routeur"),
            max_grade=2,
            grade_part=part2,
            grade=2 * int(srv1["mask_router"]),
            description=tr("masque et routeur par défaut proposés par srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_dns"),
            max_grade=1,
            grade_part=part2,
            grade=int(srv1["dns"]),
            description=tr("serveur DNS proposé par srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_domaine"),
            max_grade=1,
            grade_part=part2,
            grade=int(srv1["domain"]),
            description=tr("nom de domaine proposé par srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_bail_defaut"),
            max_grade=1,
            grade_part=part2,
            grade=int(srv1["default_lease"]),
            description=tr("durée de bail par défaut de srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_bail_max"),
            max_grade=1,
            grade_part=part2,
            grade=int(srv1["max_lease"]),
            description=tr("durée de bail maximale de srv1"),
        )
        self.add_grade_element(
            title=no_tr("serveur_srv1_authoritative"),
            max_grade=1,
            grade_part=part2,
            grade=int(srv1["nak"]),
            description=tr("srv1 refuse (DHCPNAK) une adresse étrangère au réseau"),
        )
        # m1 may be served by srv1 (range A) or, from part 5 on, by srv2 (range B).
        m1_ok = has_address(
            "m1", d.ips.a_min, d.ips.a_max, d.ips.r1_lan1
        ) or has_address("m1", d.ips.b_min, d.ips.b_max, d.ips.r1_lan1)
        self.add_grade_element(
            title=no_tr("serveur_m1_adresse"),
            max_grade=2,
            grade_part=part2,
            grade=2 * int(m1_ok),
            description=tr(
                "m1 a obtenu par DHCP une adresse dynamique de lan1 et sa route par défaut"
            ),
        )
        # Register both tests on the first pass: no short-circuit around test() calls.
        m1_reach = all([ping("m1", d.ips.srv0), resolves("m1", "srv0", d.ips.srv0)])
        self.add_grade_element(
            title=no_tr("serveur_m1_acces"),
            max_grade=1,
            grade_part=part2,
            grade=int(m1_reach and client["m1"]["persistent"]),
            description=tr(
                "m1 (configuration persistante) joint srv0 et résout son nom"
            ),
        )
        self.add_grade_element(
            title=no_tr("serveur_bail_etat"),
            max_grade=1,
            grade_part=part2,
            grade=int(_norm(q2.get("state")) == "active"),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("état du bail de m1 dans dhcpd.leases"),
        )
        self.add_grade_element(
            title=no_tr("serveur_bail_demande"),
            max_grade=1,
            grade_part=part2,
            grade=int(_int(q2.get("asked")) == d.max_lease),
            description=tr("durée obtenue quand le client demande un bail d'un jour"),
        )

        # =====================================================================
        # Partie 3 — Adresse fixe
        # =====================================================================
        part3 = self.add_grade_part(
            no_tr("partie3"), tr("Partie 3 — Adresse fixe pour m2")
        )
        q3_answers = {"mac": mac_m2, "in_leases": "non"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Adresse fixe pour m2"),
            description=tr("""
La machine `m2` doit toujours recevoir l'adresse **`{m2}`** (en dehors de la plage dynamique).

1. relevez l'adresse MAC de l'interface `eth0` de `m2` ;
2. sur `srv1`, déclarez la réservation correspondante puis relancez le service ;
3. sur `m2` : configuration persistante, `ifup eth0`, vérifications ;
4. sur `srv1`, comparez les lignes du journal pour `m1` et pour `m2`, et cherchez `m2` dans
   `/var/lib/dhcp/dhcpd.leases`.
""").format(m2=d.ips.m2.ip)
            + instructor(
                tr("""
**Solution.** L'adresse MAC de `m2` (`ip link show eth0` sur `m2`) est `{mac}`. À ajouter à
`/etc/dhcp/dhcpd.conf` sur `srv1` :

```
{host}
```

puis `systemctl restart isc-dhcp-server`. Sur `m2` : `/etc/network/interfaces` comme sur `m0`, puis
`ifup eth0`.

- L'offre faite à `m2` est immédiate ; celle faite à `m1` suit son `DHCPDISCOVER` d'une seconde
  environ, le temps pour `dhcpd` de vérifier par un `ping` que l'adresse dynamique est libre.
- Une adresse fixe n'est jamais inscrite dans `dhcpd.leases`.
- Évaluation : la sonde se présente avec l'adresse MAC de `m2`, et `srv1` doit lui proposer `{m2}`.
""").format(
                    mac=mac_m2,
                    host="\n".join(self.net_scheme._solution_host("m2")),
                    m2=d.ips.m2.ip,
                )
            )
            + tr("""
**Réservation.**

- adresse MAC de `m2` : @@{mac:[0-9a-fA-F:]+}@@
- le bail de `m2` est-il enregistré dans `dhcpd.leases` ? @@{in_leases:>non|oui}@@
""")
            + instructor(
                tr("""
**Réponses.** adresse MAC `{mac}` ; `{in_leases}` : `dhcpd` n'inscrit rien dans `dhcpd.leases` pour une
adresse fixe.
""").format(**q3_answers)
            ),
            cheat_answers={"final": q3_answers},
        )
        self.add_grade_element(
            title=no_tr("fixe_srv1_offre"),
            max_grade=2,
            grade_part=part3,
            grade=2 * int(srv1["fixed"]),
            description=tr("srv1 propose {m2} à l'adresse MAC de m2").format(
                m2=d.ips.m2.ip
            ),
        )
        self.add_grade_element(
            title=no_tr("fixe_m2_adresse"),
            max_grade=2,
            grade_part=part3,
            grade=2 * int(has_address("m2", d.ips.m2, d.ips.m2, d.ips.r1_lan1)),
            description=tr("m2 a obtenu {m2} par DHCP").format(m2=d.ips.m2.ip),
        )
        self.add_grade_element(
            title=no_tr("fixe_m2_persistant"),
            max_grade=1,
            grade_part=part3,
            grade=int(client["m2"]["persistent"]),
            description=tr("configuration persistante de m2"),
        )
        self.add_grade_element(
            title=no_tr("fixe_questions"),
            max_grade=1,
            grade_part=part3,
            grade=int(
                _norm(q3.get("mac")) == mac_m2 and _norm(q3.get("in_leases")) == "non"
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("adresse MAC de m2 et absence de bail enregistré"),
        )

        # =====================================================================
        # Partie 4 — Routes distribuées par DHCP
        # =====================================================================
        part4 = self.add_grade_part(
            no_tr("partie4"), tr("Partie 4 — Routes distribuées par DHCP")
        )
        q4_answers = {
            "option": render_classless_routes(lan1_routes).replace(" ", ""),
            "no_default": "n'a plus de route par défaut",
        }
        q4 = self.question_form(
            section=self.section(0),
            title=tr("Routes distribuées par DHCP"),
            description=tr("""
Le réseau `lan1` a un second routeur, `r2` (`{r2}`), qui mène au réseau `lan3` (`{lan3}`) où se
trouve le serveur `srv3`. Le routeur `r1` ne connaît pas `lan3` : avec leur seule route par
défaut, les machines de `lan1` ne peuvent pas joindre `srv3` (essayez `ping srv3` sur `m1`).

Un serveur DHCP peut distribuer d'autres routes que la route par défaut, par l'option 121
(voir l'onglet Informations, section 7) :

1. sur `srv1`, faites distribuer aux clients de `lan1`, et à eux seuls, la route vers `{lan3}`
   par `{r2}`, **en plus** de la route par défaut par `{r1}`, puis relancez le service ;
2. redemandez un bail sur `m1` et sur `m2` (`ifdown eth0` puis `ifup eth0`) ;
3. vérifiez sur `m1` : `ip route`, `ping srv3`, `ping srv0`, et retrouvez l'option dans le
   fichier de baux ;
4. essai : retirez la route par défaut de l'option 121 (en laissant `option routers`),
   relancez le service, redemandez un bail sur `m1` et regardez `ip route`. **Rétablissez
   ensuite la configuration du point 1** et redemandez un bail sur `m1`.
""").format(r2=d.ips.r2_lan1.ip, lan3=d.nets.lan3, r1=d.ips.r1_lan1.ip)
            + instructor(
                tr("""
**Solution.** Dans `/etc/dhcp/dhcpd.conf` sur `srv1`, déclarer l'option une fois, hors de tout bloc,
puis lui donner sa valeur dans le `subnet` de `lan1` :

```
{declaration}

{subnet}
```

puis `systemctl restart isc-dhcp-server`, et `ifdown eth0` puis `ifup eth0` sur `m1` et `m2`.
`ip route` sur `m1` montre alors, entre autres :

```
default via {r1} dev eth0
{lan3} via {r2} dev eth0
```

- Codage de l'option : pour chaque route, la longueur du préfixe, les octets significatifs du réseau,
  puis les quatre octets du routeur ; `0` suivi d'un routeur est la route par défaut.
- Sans la déclaration, `dhcpd` ne démarre pas (`unknown option dhcp.rfc3442-classless-static-routes`).
  Le nom donné à l'option est libre : c'est le code 121 qui compte.
- Un client qui reçoit l'option 121 ignore l'option `routers` : à l'essai du point 4, `m1` n'a plus de
  route par défaut (`ping srv0` échoue), alors que `routers` est toujours envoyé.
- `dhclient` n'installe ces routes qu'à l'obtention d'un bail, pas à son renouvellement : d'où
  `ifdown` puis `ifup` après chaque changement sur le serveur.
- Écrite hors du `subnet` de `lan1`, l'option serait aussi envoyée aux clients de `lan2` (partie 6), qui
  perdraient leur route par défaut : les routeurs qu'elle cite ne sont pas sur leur réseau.
- Évaluation : la sonde lit l'option 121 dans les offres de `srv1`. Sur `m1` et `m2`, la route doit être
  installée **et** figurer dans le bail : une route ajoutée avec `ip route add` ne compte pas.
""").format(
                    declaration=CLASSLESS_ROUTES_DECLARATION,
                    subnet="\n".join(
                        self.net_scheme._solution_lan1_subnet("srv1", routes=True)
                    ),
                    r1=d.ips.r1_lan1.ip,
                    r2=d.ips.r2_lan1.ip,
                    lan3=d.nets.lan3,
                )
            )
            + tr("""
**Routes reçues.**

- valeur de l'option `rfc3442-classless-static-routes` dans le bail de `m1` (les nombres,
  séparés par des virgules) : @@{option:[0-9, ]+}@@
- à l'essai du point 4, `m1` :
  @@{no_default:>garde sa route par défaut|n'a plus de route par défaut}@@
""")
            + instructor(
                tr("""
**Réponses.** option `{option}` (les deux routes, dans n'importe quel ordre) ; à l'essai, `m1`
{no_default}.
""").format(**q4_answers)
            ),
            cheat_answers={"final": q4_answers},
        )
        self.add_grade_element(
            title=no_tr("routes_srv1_lan3"),
            max_grade=2,
            grade_part=part4,
            grade=2 * int(srv1["route_lan3"]),
            description=tr("srv1 distribue la route vers lan3 par r2 (option 121)"),
        )
        self.add_grade_element(
            title=no_tr("routes_srv1_defaut"),
            max_grade=1,
            grade_part=part4,
            grade=int(srv1["route_default"]),
            description=tr("l'option 121 de srv1 contient aussi la route par défaut"),
        )
        self.add_grade_element(
            title=no_tr("routes_m1_route"),
            max_grade=2,
            grade_part=part4,
            grade=2 * int(has_dhcp_route("m1") and m1_ok),
            description=tr(
                "m1 a reçu par DHCP la route vers lan3 et garde sa route par défaut"
            ),
        )
        self.add_grade_element(
            title=no_tr("routes_m1_acces"),
            max_grade=1,
            grade_part=part4,
            grade=int(ping("m1", d.ips.srv3)),
            description=tr("m1 joint srv3"),
        )
        self.add_grade_element(
            title=no_tr("routes_m2_route"),
            max_grade=1,
            grade_part=part4,
            grade=int(
                has_dhcp_route("m2")
                and has_address("m2", d.ips.m2, d.ips.m2, d.ips.r1_lan1)
            ),
            description=tr("m2 (adresse fixe) a reçu les mêmes routes"),
        )
        self.add_grade_element(
            title=no_tr("routes_option_bail"),
            max_grade=1,
            grade_part=part4,
            grade=int(
                set(parse_classless_routes(q4.get("option"))) == set(lan1_routes)
            ),
            description=tr("valeur de l'option 121 dans le bail de m1"),
        )
        self.add_grade_element(
            title=no_tr("routes_question_defaut"),
            max_grade=1,
            grade_part=part4,
            grade=int("plus de route" in _norm(q4.get("no_default"))),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("effet d'une option 121 sans route par défaut"),
        )

        # =====================================================================
        # Partie 5 — Second serveur
        # =====================================================================
        part5 = self.add_grade_part(
            no_tr("partie5"), tr("Partie 5 — Second serveur DHCP sur lan1")
        )
        q5_answers = {
            "offers": "2",
            "refusal": "en recevant le DHCPREQUEST diffusé",
            "overlap": "deux machines pourraient recevoir la même adresse",
        }
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Second serveur DHCP sur lan1"),
            description=tr("""
Pour que `lan1` reste servi si `srv1` tombe en panne, configurez `srv2` comme second serveur
DHCP **indépendant** du même réseau :

- mêmes paramètres que `srv1` (interface, routeur, routes de l'option 121, DNS, domaine,
  durées de bail, `authoritative`) ;
- plage dynamique de `{b_min}` à `{b_max}` : elle n'a aucune adresse commune avec celle de
  `srv1`, qui reste inchangée ;
- même réservation pour `m2`.

Observations, avec une capture sur `m1` :

1. redemandez un bail sur `m1` (`ifdown eth0` puis `ifup eth0`) et comptez les `DHCPOFFER` ;
   repérez dans le `DHCPREQUEST` l'option qui désigne le serveur retenu ;
2. arrêtez `dhcpd` sur `srv1` (`systemctl stop isc-dhcp-server`), redemandez un bail sur
   `m1` puis sur `m2` : qui répond ? quelles adresses obtiennent-elles ?
3. **relancez `dhcpd` sur `srv1`**.
""").format(b_min=d.ips.b_min.ip, b_max=d.ips.b_max.ip)
            + instructor(
                tr("""
**Solution.** Sur `srv2`, `/etc/default/isc-dhcp-server` comme sur `srv1`, et `/etc/dhcp/dhcpd.conf`,
celui de `srv1` à la plage près :

```
{conf}
```

puis `systemctl restart isc-dhcp-server`.

- Capture sur `m1` : deux `DHCPOFFER`, un par serveur, chacun dans sa plage. Le `DHCPREQUEST`, diffusé,
  désigne le serveur retenu par l'option 54 (`Server-ID` dans `tcpdump`) : l'autre serveur y lit que
  son offre n'est pas retenue.
- `srv1` arrêté, `srv2` répond seul : `m1` reçoit une adresse de `{b_min}` à `{b_max}`, et `m2` garde
  `{m2}` puisque la réservation est déclarée sur les deux serveurs.
- L'évaluation interroge les deux serveurs : un `srv1` resté arrêté perd tous ses points.
- Sans l'option 121 sur `srv2`, une machine qui tient son bail de `srv2` n'a plus la route vers `lan3` :
  les points de `m1` et de `m2` dans la partie 4 dépendent alors du serveur qui leur a répondu.
""").format(
                    conf=self.net_scheme._solution_dhcpd_conf("srv2", part=5).strip(),
                    b_min=d.ips.b_min.ip,
                    b_max=d.ips.b_max.ip,
                    m2=d.ips.m2.ip,
                )
            )
            + tr("""
**Deux serveurs.**

- nombre de `DHCPOFFER` reçus par `m1` quand les deux serveurs tournent (avant la mise en
  place du relais de la partie 6) : @@{offers:[0-9]+}@@
- le serveur dont l'offre n'est pas retenue l'apprend :
  @@{refusal:>en recevant un DHCPDECLINE|en recevant un DHCPNAK|en recevant le DHCPREQUEST diffusé|jamais}@@
- si les deux plages dynamiques avaient des adresses communes :
  @@{overlap:>dhcpd refuserait de démarrer|deux machines pourraient recevoir la même adresse|les serveurs se synchroniseraient}@@
""")
            + instructor(
                tr("""
**Réponses.** `{offers}` offres, une par serveur ; `{refusal}` ; `{overlap}`.

Une fois le relais de la partie 6 à l'écoute sur `eth1`, il relaie aussi les diffusions de `lan1` : `m1`
reçoit alors des offres supplémentaires (`giaddr` = `{giaddr}`), d'où la précision de la question.
""").format(giaddr=d.ips.r1_lan1.ip, **q5_answers)
            ),
            cheat_answers={"final": q5_answers},
        )
        self.add_grade_element(
            title=no_tr("second_srv2_actif"),
            max_grade=1,
            grade_part=part5,
            grade=int(dhcpd_ifaces["srv2"] == ["eth0"]),
            description=tr("dhcpd tourne sur srv2, sur eth0 uniquement"),
        )
        self.add_grade_element(
            title=no_tr("second_srv2_plage"),
            max_grade=3,
            grade_part=part5,
            grade=3 * int(srv2["range"]),
            description=tr(
                "srv2 propose une adresse de la plage {b_min} – {b_max}"
            ).format(b_min=d.ips.b_min.ip, b_max=d.ips.b_max.ip),
        )
        srv2_options = all(
            srv2[k]
            for k in ("mask_router", "dns", "domain", "default_lease", "max_lease")
        )
        self.add_grade_element(
            title=no_tr("second_srv2_options"),
            max_grade=2,
            grade_part=part5,
            grade=2 * int(srv2_options),
            description=tr("srv2 propose les mêmes options et durées de bail que srv1"),
        )
        self.add_grade_element(
            title=no_tr("second_srv2_routes"),
            max_grade=1,
            grade_part=part5,
            grade=int(srv2["route_lan3"] and srv2["route_default"]),
            description=tr("srv2 distribue les mêmes routes que srv1 (option 121)"),
        )
        self.add_grade_element(
            title=no_tr("second_srv2_authoritative"),
            max_grade=1,
            grade_part=part5,
            grade=int(srv2["nak"]),
            description=tr("srv2 refuse (DHCPNAK) une adresse étrangère au réseau"),
        )
        self.add_grade_element(
            title=no_tr("second_srv2_reservation"),
            max_grade=2,
            grade_part=part5,
            grade=2 * int(srv2["fixed"]),
            description=tr("srv2 propose aussi {m2} à l'adresse MAC de m2").format(
                m2=d.ips.m2.ip
            ),
        )
        self.add_grade_element(
            title=no_tr("second_nombre_offres"),
            max_grade=1,
            grade_part=part5,
            grade=int(_int(q5.get("offers")) == 2),
            description=tr("nombre d'offres reçues par m1"),
        )
        self.add_grade_element(
            title=no_tr("second_questions"),
            max_grade=1,
            grade_part=part5,
            grade=int(
                "dhcprequest" in _norm(q5.get("refusal"))
                and "deux machines" in _norm(q5.get("overlap"))
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("offre non retenue et risque des plages communes"),
        )

        # =====================================================================
        # Partie 6 — Relais
        # =====================================================================
        part6 = self.add_grade_part(
            no_tr("partie6"), tr("Partie 6 — Relais DHCP pour lan2")
        )
        q6_answers = {
            "giaddr": str(d.ips.r1_lan2.ip),
            "offer_src": str(d.ips.r1_lan2.ip),
            "server": str(d.ips.srv1.ip),
            "choice": "le champ giaddr",
        }
        q6 = self.question_form(
            section=self.section(0),
            title=tr("Relais DHCP pour lan2"),
            description=tr("""
Le réseau `lan2` (`{lan2}`) n'a pas de serveur DHCP. Essayez `dhclient -v eth0` sur `m3` en
capturant sur `m3` puis sur `m1` : les diffusions de `m3` ne sortent pas de `lan2`
(interrompez `dhclient` avec Ctrl-C puis arrêtez-le complètement avec `dhclient -r eth0`).
C'est `srv1` qui servira `lan2`, à travers un relais installé sur `r1` :

1. sur `srv1`, ajoutez le réseau `lan2` : plage dynamique de `{c_min}` à `{c_max}`, routeur
   par défaut `{router}`, et une réservation donnant toujours **`{m4}`** à `m4` ;
2. sur `r1`, configurez et lancez le relais `isc-dhcp-relay` vers `srv1`
   (`{srv1}`). `r1` ne doit pas devenir serveur DHCP ;
3. sur `m3` et `m4` : configuration persistante, `ifup eth0`, vérifications (`ping srv0`).

Observez l'échange complet : capture sur `m3` (côté client) et capture sur `m1` ou `srv1`
(côté serveur : `lan1` montre les messages échangés entre `r1` et `srv1`). Repérez le
champ `Gateway-IP` et regardez dans le journal de `srv1` comment la demande est notée.
Le journal de `srv2` signale ces mêmes demandes avec `unknown network segment` : à cause du
concentrateur il voit passer les messages destinés à `srv1`, mais il ne connaît pas `lan2`.
""").format(
                lan2=d.nets.lan2,
                c_min=d.ips.c_min.ip,
                c_max=d.ips.c_max.ip,
                router=d.ips.r1_lan2.ip,
                m4=d.ips.m4.ip,
                srv1=d.ips.srv1.ip,
            )
            + instructor(
                tr("""
**Solution.** À ajouter à `/etc/dhcp/dhcpd.conf` sur `srv1` :

```
{conf}
```

puis `systemctl restart isc-dhcp-server`. Sur `r1`, `/etc/default/isc-dhcp-relay` :

```
{relay}
```

puis `systemctl restart isc-dhcp-relay` et `ps -C dhcrelay -o pid,args`. Sur `m3` et `m4` :
`/etc/network/interfaces` comme sur `m0`, puis `ifup eth0`.

- Le relais écoute sur `eth2` (les clients) **et** sur `eth1` (les réponses de `srv1`). Conviennent
  aussi `INTERFACES=""` seul (toutes les interfaces) ou avec `OPTIONS="-id eth2 -iu eth1"` ; avec
  `INTERFACES="eth2"`, les demandes partent mais les réponses sont perdues.
- Évaluation du relais : un processus `dhcrelay` lancé vers l'adresse `{srv1}` (un nom dans `SERVERS`
  n'est pas reconnu), pas de `dhcpd` sur `r1`, et sur `lan2` une offre de `srv1` portant
  `giaddr` = `{giaddr}`.
- Journal de `srv1` : une demande relayée est notée `via {giaddr}` au lieu de `via eth0`.
- `srv1` joint déjà `lan2` par sa route par défaut (`r1`) : aucune route à ajouter.
""").format(
                    conf="\n".join(
                        self.net_scheme._solution_lan2_subnet(failover=False)
                        + [""]
                        + self.net_scheme._solution_host("m4")
                    ),
                    relay=render_dhcp_relay(
                        self.net_scheme._solution_relay(part=6)
                    ).strip(),
                    srv1=d.ips.srv1.ip,
                    giaddr=d.ips.r1_lan2.ip,
                )
            )
            + tr("""
**Messages relayés.**

- valeur du champ `giaddr` (`Gateway-IP`) des messages relayés pour `m3` : @@{giaddr:[0-9.]+}@@
- adresse IP **source** du `DHCPOFFER` tel que `m3` le reçoit : @@{offer_src:[0-9.]+}@@
- adresse du serveur DHCP enregistrée dans le bail de `m3` (`dhcp-server-identifier`) :
  @@{server:[0-9.]+}@@
- `srv1` choisit le réseau (`subnet`) dans lequel prendre l'adresse d'après :
  @@{choice:>l'adresse MAC du client|l'interface de réception|le champ giaddr|le nom du client}@@
""")
            + instructor(
                tr("""
**Réponses.**

- `giaddr` : `{giaddr}`, l'adresse de `r1` sur `lan2`
- adresse source de l'offre : `{offer_src}`, c'est le relais qui la remet à `m3`
- serveur inscrit dans le bail : `{server}` (`srv1` ; l'adresse de `srv2` est acceptée aussi, pour une
  réponse donnée après la partie 7)
- `srv1` choisit le réseau d'après {choice}
""").format(**q6_answers)
            ),
            cheat_answers={"final": q6_answers},
        )
        relay_to_srv1 = relay_running and str(d.ips.srv1.ip) in relay["servers"]
        self.add_grade_element(
            title=no_tr("relais_processus"),
            max_grade=2,
            grade_part=part6,
            grade=2 * int(relay_to_srv1 and dhcpd_ifaces["r1"] is None),
            description=tr(
                "dhcrelay tourne sur r1 vers srv1 (et r1 n'est pas serveur DHCP)"
            ),
        )
        via_relay = every(lan2_dyn["srv1"], lambda r: r.giaddr == d.ips.r1_lan2.ip)
        self.add_grade_element(
            title=no_tr("relais_offre"),
            max_grade=2,
            grade_part=part6,
            grade=2 * int(via_relay),
            description=tr(
                "srv1 répond sur lan2 à travers le relais (giaddr {giaddr})"
            ).format(giaddr=d.ips.r1_lan2.ip),
        )
        self.add_grade_element(
            title=no_tr("relais_plage"),
            max_grade=2,
            grade_part=part6,
            grade=2
            * int(
                every(
                    lan2_dyn["srv1"],
                    lambda r: _in_range(r.yiaddr, d.ips.c_min, d.ips.c_max),
                )
            ),
            description=tr(
                "adresse proposée sur lan2 dans la plage {c_min} – {c_max}"
            ).format(c_min=d.ips.c_min.ip, c_max=d.ips.c_max.ip),
        )
        self.add_grade_element(
            title=no_tr("relais_routeur"),
            max_grade=1,
            grade_part=part6,
            grade=int(
                every(
                    lan2_dyn["srv1"],
                    lambda r: (
                        r.subnet_mask == d.nets.lan2.netmask
                        and r.routers == [d.ips.r1_lan2.ip]
                    ),
                )
            ),
            description=tr("masque et routeur par défaut proposés sur lan2"),
        )
        self.add_grade_element(
            title=no_tr("relais_m3_adresse"),
            max_grade=2,
            grade_part=part6,
            grade=2 * int(has_address("m3", d.ips.c_min, d.ips.c_max, d.ips.r1_lan2)),
            description=tr(
                "m3 a obtenu par DHCP une adresse dynamique de lan2 et sa route par défaut"
            ),
        )
        m3_reach = all([ping("m3", d.ips.srv0), resolves("m3", "srv0", d.ips.srv0)])
        self.add_grade_element(
            title=no_tr("relais_m3_acces"),
            max_grade=1,
            grade_part=part6,
            grade=int(m3_reach),
            description=tr("m3 joint srv0 et résout son nom"),
        )
        self.add_grade_element(
            title=no_tr("relais_m4_reservation"),
            max_grade=1,
            grade_part=part6,
            grade=int(every(lan2_fixed["srv1"], lambda r: r.yiaddr == d.ips.m4.ip)),
            description=tr("srv1 propose {m4} à l'adresse MAC de m4").format(
                m4=d.ips.m4.ip
            ),
        )
        self.add_grade_element(
            title=no_tr("relais_m4_adresse"),
            max_grade=1,
            grade_part=part6,
            grade=int(has_address("m4", d.ips.m4, d.ips.m4, d.ips.r1_lan2)),
            description=tr("m4 a obtenu {m4} par DHCP").format(m4=d.ips.m4.ip),
        )
        self.add_grade_element(
            title=no_tr("relais_persistant"),
            max_grade=1,
            grade_part=part6,
            grade=int(client["m3"]["persistent"] and client["m4"]["persistent"]),
            description=tr("configuration persistante de m3 et m4"),
        )
        self.add_grade_element(
            title=no_tr("relais_giaddr"),
            max_grade=1,
            grade_part=part6,
            grade=int(
                _same_ip(q6.get("giaddr"), d.ips.r1_lan2.ip)
                and _same_ip(q6.get("offer_src"), d.ips.r1_lan2.ip)
            ),
            description=tr("giaddr et adresse source de l'offre reçue par m3"),
        )
        self.add_grade_element(
            title=no_tr("relais_questions"),
            max_grade=1,
            grade_part=part6,
            grade=int(
                _norm(q6.get("server")) in (str(srv_ip["srv1"]), str(srv_ip["srv2"]))
                and "giaddr" in _norm(q6.get("choice"))
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr(
                "identifiant du serveur dans le bail de m3 et choix du réseau par le serveur"
            ),
        )

        # =====================================================================
        # Partie 7 — Failover
        # =====================================================================
        part7 = self.add_grade_part(
            no_tr("partie7"), tr("Partie 7 — Failover pour lan2")
        )
        q7_answers = {"first_lease": str(d.mclt), "responders": "1"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Failover pour lan2"),
            description=tr("""
`lan2` ne dépend encore que de `srv1`. Plutôt que de découper sa plage, faites
partager **la même plage** (`{c_min}` à `{c_max}`) à `srv1` et `srv2` par le protocole
**failover** (voir l'onglet Informations, section 8) :

1. sur `srv1` (**primaire**) et `srv2` (**secondaire**), déclarez la relation
   `failover peer` avec le port 647 des deux côtés, `load balance max seconds 3`, et sur le
   primaire `mclt {mclt}` et `split 128` ;
2. sur les deux serveurs, déclarez le réseau `lan2` avec la plage placée dans un `pool`
   rattaché à cette relation, le routeur `{router}` et la réservation de `m4`. La
   configuration de `lan1` (plages disjointes) ne change pas ;
3. relancez les deux serveurs et attendez `Both servers normal` dans leurs journaux ;
4. sur `r1`, faites suivre les demandes aux **deux** serveurs (dans cette maquette `srv2`
   voit déjà passer les demandes relayées vers `srv1`, à cause du concentrateur ; sur un
   réseau commuté réel il ne les recevrait que grâce à cette configuration).

Essais : redemandez un bail sur `m3` (`ifdown eth0` puis `ifup eth0`) en capturant sur
`m3`, notez la durée du bail, puis celle obtenue au premier renouvellement. Arrêtez `srv1`
et vérifiez que `m3` obtient toujours une adresse ; **relancez `srv1`**.
""").format(
                c_min=d.ips.c_min.ip,
                c_max=d.ips.c_max.ip,
                mclt=d.mclt,
                router=d.ips.r1_lan2.ip,
            )
            + instructor(
                tr("""
**Solution.** `/etc/dhcp/dhcpd.conf` de `srv1` (primaire) :

```
{conf1}
```

et de `srv2` (secondaire) :

```
{conf2}
```

puis `systemctl restart isc-dhcp-server` sur les deux serveurs. Sur `r1`, `/etc/default/isc-dhcp-relay` :

```
{relay}
```

puis `systemctl restart isc-dhcp-relay`.

- Partis de fichiers de baux vides (c'est ce que fait l'état `final`), les deux serveurs sont en état
  `normal` en quelques secondes. L'évaluation lit cet état dans `dhcpd.leases`
  (`failover peer "{failover}" state`) et demande que `dhcpd.conf` contienne au moins deux lignes
  `failover peer` : la déclaration et le `pool`.
- Premier bail de `m3` : {mclt} s, le MCLT ; dès le premier renouvellement, {default_lease} s.
- En état `normal`, un seul serveur répond à un client donné, choisi d'après son adresse MAC. La sonde
  annonce un champ `secs` supérieur à `load balance max seconds` : les deux serveurs lui répondent,
  chacun avec une adresse de sa part de la plage et un bail de {mclt} s.
- La configuration de `lan1` ne change pas : les parties 2 à 6 gardent leurs points.
""").format(
                    conf1=self.net_scheme._solution_dhcpd_conf("srv1").strip(),
                    conf2=self.net_scheme._solution_dhcpd_conf("srv2").strip(),
                    relay=render_dhcp_relay(self.net_scheme._solution_relay()).strip(),
                    failover=FAILOVER_NAME,
                    mclt=d.mclt,
                    default_lease=d.default_lease,
                )
            )
            + tr("""
**Failover.**

- durée en secondes du **premier** bail accordé à `m3` après la mise en place du failover :
  @@{first_lease:[0-9]+}@@
- nombre de serveurs **différents** qui répondent au `DHCPDISCOVER` de `m3` quand les deux
  sont en état `normal` : @@{responders:>0|1|2}@@
""")
            + instructor(
                tr("""
**Réponses.** premier bail de `{first_lease}` s, le MCLT ; `{responders}` seul serveur répond à `m3`.
""").format(**q7_answers)
            ),
            cheat_answers={"final": q7_answers},
        )
        failover_normal = [
            _int(failover_conf[s], 0) >= 2
            and any(
                st.get("my_state") == "normal" and st.get("partner_state") == "normal"
                for st in failover_state[s].values()
            )
            for s in SERVERS
        ]
        self.add_grade_element(
            title=no_tr("failover_etat"),
            max_grade=3,
            grade_part=part7,
            grade=3 * int(all(failover_normal)),
            description=tr(
                "relation failover déclarée et en état normal sur srv1 et srv2"
            ),
        )
        # The probe announces a high `secs`, above `load balance max seconds`: both peers
        # answer, each with an address of its own share of the pool and an MCLT-long lease.
        shared_pool = all(
            every(
                lan2_dyn[s],
                lambda r: (
                    _in_range(r.yiaddr, d.ips.c_min, d.ips.c_max)
                    and r.giaddr == d.ips.r1_lan2.ip
                    and r.lease_time == d.mclt
                ),
            )
            for s in SERVERS
        )
        distinct = not (
            {r.yiaddr for r in lan2_dyn["srv1"]} & {r.yiaddr for r in lan2_dyn["srv2"]}
        )
        self.add_grade_element(
            title=no_tr("failover_offres"),
            max_grade=2,
            grade_part=part7,
            grade=2 * int(shared_pool and distinct),
            description=tr(
                "srv1 et srv2 servent la plage de lan2 en failover (bail limité au MCLT)"
            ),
        )
        self.add_grade_element(
            title=no_tr("failover_relais"),
            max_grade=1,
            grade_part=part7,
            grade=int(
                relay_running
                and all(str(srv_ip[s]) in relay["servers"] for s in SERVERS)
            ),
            description=tr(
                "le relais fait suivre les demandes à srv1 et à srv2"
            ),
        )
        self.add_grade_element(
            title=no_tr("failover_m4_reservation"),
            max_grade=1,
            grade_part=part7,
            grade=int(every(lan2_fixed["srv2"], lambda r: r.yiaddr == d.ips.m4.ip)),
            description=tr(
                "srv2 propose aussi {m4} à l'adresse MAC de m4"
            ).format(m4=d.ips.m4.ip),
        )
        self.add_grade_element(
            title=no_tr("failover_questions"),
            max_grade=1,
            grade_part=part7,
            grade=int(
                _int(q7.get("first_lease")) == d.mclt
                and _norm(q7.get("responders")) == "1"
            ),
            scope=params.EXO_EVAL_SCOPE,
            description=tr(
                "durée du premier bail et nombre de serveurs qui répondent"
            ),
        )
