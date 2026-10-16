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
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
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

title = tr("DHCP (Dynamic Host Configuration Protocol)",
           en="DHCP (Dynamic Host Configuration Protocol)")
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
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Introduction"), tag="why")
            + tr("""

Pour communiquer en IPv4, une machine a besoin de multiples informations : son **adresse IP**,
le **masque** de son réseau, l'adresse du **routeur par défaut** (et éventuellement
les autres routes statiques nécessaires). et celle d'un **serveur DNS**.
Les saisir à la main est fastidieux et de fait impossible dans le cas de portables qui se connectent
à différents réseaux ou dès que le parc de machines considéré atteint une certaine taille.

**DHCP** automatise cette configuration : un serveur DHCP fournit ces informations sur demande aux clients
DHCP et s'assure qu'une adresse IP n'est allouée qu'à une machine à la fois.

Le serveur peut également fournir d'autres informations au client comme par exemple son nom (*hostname*), les adresses des serveurs de synchronisation du temps (NTP).

Un serveur peut attribuer une adresse de deux façons :

- **adresse dynamique** : l'adresse est prise dans une plage et **allouée pour une durée limitée** (durée du *bail*). Rendue ou expirée, 
elle pourra être attribuée à une autre machine.
- **adresse fixe** (*réservation*) : l'administrateur a associé une adresse à une machine
  précise, identifiée par l'adresse MAC de son interface réseau.

DHCP a été créé en 1993. Il prolonge **BOOTP** (1985), conçu pour démarrer des stations sans disque,
dont il garde le format de message et les ports UDP : c'est pourquoi les outils de capture
parlent de `BOOTP/DHCP`. 

Textes de référence actuels (en anglais) : [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) (le protocole, 1997),
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132) (les options, 1997),
[RFC 3046](https://www.rfc-editor.org/rfc/rfc3046) (l'option ajoutée par les relais, 2001).
""")
            + info_subtitle(tr("Obtention d'un bail"), tag="dora")
            + tr("""

Une machine qui démarre sans configuration ne connaît ni son adresse, ni son réseau, ni même
l'adresse d'un serveur : elle ne peut qu'envoyer une demande à l'adresse de broadcast de son réseau local.
L'échange nécessaire à l'attribution d'une adresse IP comporte quatre messages :

```
   client                                            serveur
     |                                                  |
     |--- DHCPDISCOVER (diffusion) -------------------->|   y a-t-il un serveur sur le réseau ?
     |<--- DHCPOFFER -----------------------------------|   proposition d'une adresse et d'une durée de bail par le serveur
     |--- DHCPREQUEST (diffusion) --------------------->|   acceptation d'une offre (pour une certaine durée) par le client
     |<--- DHCPACK -------------------------------------|   le serveur accuse réception de la demande du client, qui peut utiliser l'IP allouée
     |                                                  |
```

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPDISCOVER` | client | recherche des serveurs DHCP sur le réseau |
| `DHCPOFFER` | serveur | propose une adresse, une durée de bail et des paramètres |
| `DHCPREQUEST` | client | accepte **une** offre en nommant le serveur retenu et la durée de bail (ou prolonge un bail) |
| `DHCPACK` | serveur | confirme : le bail est accordé, le client configure son interface |

Sans réponse, le client répète son `DHCPDISCOVER` à intervalles de plus en plus longs. Si
plusieurs serveurs répondent, il reçoit plusieurs offres et en retient une, en général la
première. Une adresse proposée reste mise de côté par le serveur pendant deux minutes environ : si
le client ne la confirme pas, elle redevient disponible.

### @@sec@@ Transport et adresses


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

### @@sec@@ Les autres messages

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPNAK` | serveur | refuse un `DHCPREQUEST` (adresse étrangère au réseau, bail expiré et réattribué…) : le client recommence à zéro par un `DHCPDISCOVER` |
| `DHCPDECLINE` | client | signale que l'adresse reçue est déjà utilisée par une autre machine : le serveur la met à l'écart |
| `DHCPRELEASE` | client | rend son adresse avant la fin du bail (arrêt propre de l'interface) |
| `DHCPINFORM` | client | demande seulement des paramètres (DNS, domaine…) pour une adresse qu'il a déjà, configurée à la main |
""")
            + info_subtitle(tr("Le format des messages et les options"), tag="format")
            + tr("""

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
| 33 | `static-routes` | routes vers des adresses, sans masque (section @@ref:routes@@) | `Static-Route` |
| 42 | `ntp-servers` | serveurs de temps | `NTP` |
| 50 | `dhcp-requested-address` | adresse que le client souhaite obtenir | `Requested-IP` |
| 51 | `dhcp-lease-time` | durée du bail, en secondes | `Lease-Time` |
| 53 | `dhcp-message-type` | type du message (`DHCPDISCOVER`, `DHCPOFFER`…) | `DHCP-Message` |
| 54 | `dhcp-server-identifier` | adresse du serveur qui fait l'offre, ou que le client retient | `Server-ID` |
| 55 | `dhcp-parameter-request-list` | liste des options demandées par le client | `Parameter-Request` |
| 58 | `dhcp-renewal-time` | instant T1 (section @@ref:lease@@) | `RN` |
| 59 | `dhcp-rebinding-time` | instant T2 (section @@ref:lease@@) | `RB` |
| 61 | `dhcp-client-identifier` | identifiant du client, quand il n'utilise pas son adresse MAC | `Client-ID` |
| 82 | (ajoutée par un relais) | informations sur le point de raccordement du client | `Agent-Information` |
| 121 | `rfc3442-classless-static-routes` (à déclarer) | routes vers des réseaux, en plus de la route par défaut (section @@ref:routes@@) | `Classless-Static-Route` |
""")
            + info_subtitle(tr("La vie d'un bail"), tag="lease")
            + tr("""

L'adresse n'est pas donnée mais **allouée temporairement** : le bail a une durée (option 51) au terme de
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

### @@sec@@ Libération, redémarrage, changement de réseau

- **Libération** : un client qui s'arrête proprement envoie un `DHCPRELEASE` et le serveur peut
  réattribuer l'adresse aussitôt. Un client éteint brutalement n'envoie rien : son adresse reste
  immobilisée jusqu'à l'expiration du bail.
- **Redémarrage** : un client qui a gardé la trace d'un bail encore valide ne repart pas du
  `DHCPDISCOVER`, il diffuse directement un `DHCPREQUEST` pour son ancienne adresse. Si elle
  convient toujours, le serveur répond `DHCPACK`.
- **Changement de réseau** : si l'adresse redemandée n'appartient pas au réseau où le client se
  trouve maintenant (cas d'un téléphone ou d'un ordinateur portable déplacé), un serveur répond `DHCPNAK` ; le client abandonne cette adresse et recommence par un
  `DHCPDISCOVER`. Sans ce refus, il attend inutilement avant de s'y résoudre.

### @@sec@@ Éviter les doublons

Pour éviter qu'une adresse de la plage d'allocation du serveur ne soit utilisée par une machine configurée à la main et ensuite attribuée par le serveur
à une deuxième machine, deux garde-fous existent :

- avant de proposer une adresse dynamique, `dhcpd` lui envoie un `ping` et attend une seconde
  (c'est pourquoi une première offre arrive avec une seconde de retard). Si une machine répond,
  l'adresse est mise à l'écart (*abandonnée*) et le client, qui répète sa demande, s'en voit
  proposer une autre ;
- le client peut vérifier de son côté, par une requête ARP, que personne n'utilise l'adresse
  reçue et la refuser par un `DHCPDECLINE`.

### @@sec@@ Durée de bail

On configure la durée du bail proposée par les serveurs DHCP en fonction de l'usage :

- si le bail est court (quelques minutes), les adresses des machines parties sont vite récupérées.
  C'est le cas par exemple des réseaux des lieux publics, où il peut venir plus de machines en une
  journée qu'il n'y a d'adresses disponibles ;
- si le bail est long (plusieurs heures à plusieurs jours), il y a moins de trafic réseau et
  surtout les postes restent fonctionnels malgré une longue panne du serveur.
""")
            + info_subtitle(tr("Le client : dhclient et ifupdown"), tag="client")
            + tr("""

```
dhclient -v eth0       # demande un bail, configure l'interface, puis reste en arrière-plan
dhclient -r -v eth0    # libère le bail et arrête le client
```

Avec `-v`, `dhclient` affiche le dialogue avec le serveur :

```
DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3
DHCPOFFER of 192.0.2.101 from 192.0.2.2
DHCPREQUEST for 192.0.2.101 on eth0 to 255.255.255.255 port 67
DHCPACK of 192.0.2.101 from 192.0.2.2
bound to 192.0.2.101 -- renewal in 1527 seconds.
```

Une fois le bail obtenu, `dhclient` configure l'adresse de l'interface, la route par défaut et
`/etc/resolv.conf` (par le script `/sbin/dhclient-script`), puis reste en arrière-plan pour
renouveler le bail. Dans `ip a`, l'adresse est marquée `dynamic` et sa durée de validité
restante est affichée (`valid_lft`).

| fichier | rôle |
|---------|------|
| `/etc/dhcp/dhclient.conf` | réglages du client |
| `/var/lib/dhcp/dhclient.leases` | baux obtenus par un `dhclient` lancé à la main |
| `/var/lib/dhcp/dhclient.eth0.leases` | baux obtenus par `ifup eth0` |

### @@sec@@ Le fichier de baux du client

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

### @@sec@@ Les réglages du client

| instruction de `dhclient.conf` | effet |
|--------------------------------|-------|
| `request subnet-mask, routers, …;` | options demandées au serveur (option 55) |
| `send dhcp-lease-time 86400;` | valeur envoyée au serveur, ici la durée de bail souhaitée |
| `supersede domain-name "example.org";` | valeur imposée, quelle que soit la réponse du serveur |
| `prepend domain-name-servers 192.0.2.53;` | valeur placée avant celles du serveur |
| `timeout 60;` | secondes de recherche avant d'abandonner (60 par défaut) |

### @@sec@@ Configuration persistante : ifupdown

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
            + info_subtitle(tr("Le serveur : dhcpd"), tag="server")
            + tr("""

| fichier | rôle |
|---------|------|
| `/etc/default/isc-dhcp-server` | interfaces d'écoute : `INTERFACESv4="eth0"` |
| `/etc/dhcp/dhcpd.conf` | configuration |
| `/var/lib/dhcp/dhcpd.leases` | baux accordés (écrit par `dhcpd`, à ne pas modifier) |

### @@sec@@ Structure de dhcpd.conf

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

### @@sec@@ Exemple

```
authoritative;                         # ce serveur fait autorité sur ses réseaux
default-lease-time 3600;               # durée de bail en secondes accordée si le client ne demande rien
max-lease-time 7200;                   # bail maximal accordé si le client demande plus que default-lease-time
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

### @@sec@@ Les durées de bail

| paramètre | rôle | sans réglage |
|-----------|------|--------------|
| `default-lease-time` | durée accordée à un client qui ne demande rien | 43200 s (12 h) |
| `max-lease-time` | plafond appliqué à un client qui demande une durée | 86400 s (24 h) |
| `min-lease-time` | plancher : aucun bail plus court n'est accordé | 300 s |

### @@sec@@ Les adresses fixes

Une réservation (bloc `host`) identifie le client par son **adresse MAC** (`ip link show eth0`
sur le client) et lui donne toujours la même adresse :

- l'adresse fixe se choisit **en dehors** des plages dynamiques, mais dans le réseau défini par le serveur :
la réservation ne s'applique que si le client se présente sur le `subnet` qui
  contient cette adresse ;
- Il est possible d'ajouter des options spécifiquement pour ce client dans le bloc `host`, en plus de celles du 
`subnet` et des options globales ;
- le nom donné au bloc `host` n'est pas utilisé : c'est l'adresse MAC qui désigne la machine.

### @@sec@@ Choisir les clients servis

Par défaut `dhcpd` sert toute machine qui se présente. L'option `deny unknown-clients;` réserve les adresses dynamiques 
aux machines déclarées par un bloc `host`.

### @@sec@@ Le registre des baux : dhcpd.leases

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

### @@sec@@ Lancer et contrôler le serveur

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
            + info_subtitle(tr("Distribuer d'autres routes statiques"), tag="routes")
            + tr("""

L'option `routers` ne donne au client qu'une **route par défaut**. C'est insuffisant lorsque le
réseau comporte plusieurs routeurs et que le routeur par défaut ne connaît pas tous les réseaux. Dans ce cas le serveur
 DHCP peut distribuer d'autres routes.

| option | code | contenu |
|--------|------|---------|
| `static-routes` | 33 | des routes sans masque, vers des adresses : conçue avant les réseaux sans classe, à éviter |
| routes sans classe (*classless static routes*) | 121 | des routes vers des réseaux de préfixe quelconque ([RFC 3442](https://www.rfc-editor.org/rfc/rfc3442), 2002) : c'est elle qu'on utilise |

### @@sec@@ Le codage de l'option 121

L'option est une suite d'octets. Chaque route s'y écrit : la **longueur du préfixe**, puis les
seuls **octets significatifs** de l'adresse du réseau (ceux que couvre le préfixe), puis les
**quatre octets du routeur**.

| route | codage |
|-------|--------|
| `198.51.100.0/24` par `192.0.2.254` | `24, 198,51,100, 192,0,2,254` |
| `172.16.0.0/12` par `192.0.2.254` | `12, 172,16, 192,0,2,254` |
| `10.0.0.0/8` par `192.0.2.254` | `8, 10, 192,0,2,254` |
| route par défaut par `192.0.2.1` | `0, 192,0,2,1` |

### @@sec@@ Configuration du serveur

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

### @@sec@@ Utilisation par le client

`dhclient` installe les routes reçues **à l'obtention d'un bail**, pas lors d'un simple
renouvellement : après une modification sur le serveur, il faut dedemander un bail (`ifdown eth0` puis
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
            + info_subtitle(tr("Plusieurs serveurs sur un même réseau"), tag="servers")
            + tr("""

Pour pallier au risque de défaillance d'un serveur DHCP unique sur un réseau, rien
n'interdit d'avoir plusieurs serveurs DHCP sur un réseau : tous reçoivent le `DHCPDISCOVER`,
tous répondent par un `DHCPOFFER`, et le client choisit (en général la première offre). 

On peut les configurer de deux façons :

- avec des **plages disjointes** (*split scope*) : les deux serveurs sont indépendants et ne se
  connaissent pas. Ils ne partagent pas leurs baux : leurs plages dynamiques ne doivent
  donc avoir **aucune adresse commune**, tandis que les options et les réservations doivent
  être **identiques** sur les deux ;
- **failover** : les deux serveurs partagent **la même plage** et se synchronisent par une
  connexion TCP.

### @@sec@@ Plages disjointes

C'est la solution la plus simple, et elle fonctionne avec n'importe quels serveurs. Ses limites :
chaque serveur ne dispose que de sa part des adresses (si l'un tombe, l'autre doit pouvoir
servir seul toutes les machines), toute modification est à reporter à la main sur les deux, et
une machine peut changer d'adresse en changeant de serveur.

### @@sec@@ Failover

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
            + info_subtitle(tr("Le relais DHCP"), tag="relay")
            + tr("""

Une diffusion n'est jamais routé : un client ne peut pas atteindre un serveur situé
sur un autre réseau. Un **agent relais**, placé sur le routeur, écoute les diffusions des
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
raccordé. 

Le serveur relais de l'ISC se configure dans `/etc/default/isc-dhcp-relay` :

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
            + info_subtitle(tr("Capturer les échanges de trames"), tag="diagnostic")
            + tr("""

### @@sec@@ Utiliser `tcpdump`

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

### @@sec@@ Utiliser `tshark`

`tshark`, la version en ligne de commande de Wireshark, résume chaque
trame en une ligne, avec son type et son identifiant de transaction :

```
tshark -n -i eth0 -f "port 67 or port 68"
```

```
    1   0.000000      0.0.0.0 → 255.255.255.255 DHCP 342 DHCP Discover - Transaction ID 0x6b3f2a1c
    2   1.001234     10.0.0.1 → 10.0.0.23    DHCP 342 DHCP Offer    - Transaction ID 0x6b3f2a1c
```

`-f` prend un *filtre de capture*, dans la syntaxe de `tcpdump` ; `-Y` un *filtre d'affichage*,
qui utilise les noms de champs de Wireshark : `-Y dhcp` (tous les messages DHCP),
`-Y "dhcp.option.dhcp == 2"` (les offres seulement). `-V` affiche le décodage complet de chaque
message, `-O dhcp` seulement sa partie DHCP, chaque champ étant nommé en clair (extrait d'une offre) :

```
Dynamic Host Configuration Protocol (Offer)
    Message type: Boot Reply (2)
    Transaction ID: 0x6b3f2a1c
    Your (client) IP address: 10.0.0.23
    Relay agent IP address: 0.0.0.0
    Client MAC address: 02:53:52:aa:bb:cc
    Option: (53) DHCP Message Type (Offer)
    Option: (54) DHCP Server Identifier (10.0.0.1)
    Option: (51) IP Address Lease Time
        IP Address Lease Time: (600s) 10 minutes
```

Enfin `-T fields -e <champ>` n'affiche que les champs demandés, un message par ligne, séparés
par des tabulations :

```
tshark -n -i eth0 -f "port 67 or port 68" -T fields -e dhcp.option.dhcp -e dhcp.hw.mac_addr \\
       -e dhcp.ip.your -e dhcp.ip.relay -e dhcp.option.dhcp_server_id -e dhcp.option.ip_address_lease_time
```

| ce que l'on cherche | où le lire dans `tcpdump` | champ Wireshark (`tshark -Y`, `-e`) |
|---------------------|---------------------------|-------------------------------------|
| adresses MAC source et destination | début de la première ligne (option `-e`) | `eth.src`, `eth.dst` |
| adresses IP et ports | `0.0.0.0.68 > 255.255.255.255.67` : le dernier nombre de chaque côté est le port UDP | `ip.src`, `ip.dst`, `udp.srcport`, `udp.dstport` |
| sens du message | `Request` (venant d'un client) ou `Reply` (venant d'un serveur) | `dhcp.type` : 1 (requête) ou 2 (réponse) |
| type du message | option `DHCP-Message` | `dhcp.option.dhcp` : 1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK |
| adresse attribuée | `Your-IP` | `dhcp.ip.your` |
| passage par un relais | `Gateway-IP` | `dhcp.ip.relay` |
| serveur qui répond, ou serveur retenu par le client | option `Server-ID` | `dhcp.option.dhcp_server_id` |
| durée du bail | option `Lease-Time` | `dhcp.option.ip_address_lease_time` (en secondes) |
""")
            + info_subtitle(tr("Sécurité"), tag="security")
            + tr("""

DHCP ne comporte **aucune authentification** : le client fait confiance au premier serveur qui
lui répond, et le serveur à l'adresse MAC que le client annonce. Cela permet de multiples attaques :

- **Serveur pirate** (*rogue DHCP server*) : n'importe quelle machine du réseau peut répondre
  aux `DHCPDISCOVER`. Ainsi un attaquant qui s'annonce comme routeur par défaut ou comme serveur DNS
  voit passer ou détourne tout le trafic de ses victimes.
- **Épuisement de la plage** (*DHCP starvation*) : un attaquant demande des baux sous des
  milliers d'adresses MAC inventées, jusqu'à vider la plage : les vraies machines n'obtiennent
  plus rien.
- **Usurpation** : en prenant l'adresse MAC d'une machine, un attaquant obtient l'adresse qui lui est
  réservée.
""")

        #     La parade se trouve dans les commutateurs. Le **DHCP snooping** n'accepte les messages de
        #     serveur (`DHCPOFFER`, `DHCPACK`) que sur les ports déclarés de confiance, limite le débit des
        # demandes sur les autres, et retient quelle adresse a été attribuée à quelle machine sur quel
        # port, ce que d'autres protections réutilisent (contre l'usurpation ARP notamment).


#             + tr("""
# ## 12. Pour aller plus loin
#
# - **DNS dynamique** : le serveur DHCP peut inscrire dans le DNS le nom de chaque machine à
#   laquelle il attribue une adresse (`ddns-update-style`). Ce mécanisme n'est pas utilisé ici.
# - **Démarrage par le réseau** (PXE) : les paramètres `next-server` et `filename` de `dhcpd.conf`
#   indiquent à une machine sans système où télécharger son programme de démarrage.
# - **IPv6** : l'autoconfiguration sans serveur (SLAAC, à partir des annonces des routeurs) suffit
#   souvent. **DHCPv6** ([RFC 8415](https://www.rfc-editor.org/rfc/rfc8415), 2018) est un protocole
#   distinct : ports UDP 546 (client) et 547
#   (serveur), multidiffusion vers `ff02::1:2` au lieu de la diffusion, messages `SOLICIT`,
#   `ADVERTISE`, `REQUEST` et `REPLY`, clients identifiés par un DUID et non par leur adresse MAC.
#   Il ne distribue pas la route par défaut, toujours apprise des annonces des routeurs.
# - **Kea** : ISC DHCP n'est plus développé depuis 2022. Son successeur, Kea, se configure en
#   JSON mais reprend les mêmes notions (réseaux, plages, réservations, relais, haute
#   disponibilité). ISC DHCP reste très répandu et sa configuration illustre directement les
#   mécanismes du protocole.
#
# Documentation : `man dhcpd.conf`, `man dhcp-options`, `man dhcpd.leases`, `man dhclient.conf`,
# `man dhcrelay` ; [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) et
# [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132) (1997, en anglais).
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
            description= tr("""
Ce TP met en œuvre **DHCP** (*Dynamic Host Configuration Protocol*,
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131), 1997) avec les
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
## Particularités du TP

- chaque client doit recevoir une configuration **persistante** (`/etc/network/interfaces`)
          activée par `ifup eth0` ;
- après chaque modification d'un fichier de configuration, **relancez le service** et
          vérifiez dans le journal qu'il a bien démarré ;
- l'évaluation interroge les serveurs tels qu'ils tournent au moment où elle est lancée :
          un serveur arrêté pour un essai doit être relancé.
- Le réseau virtuel se comporte comme un **concentrateur** (*hub*) : une capture sur
  n'importe quelle machine montre **toutes** les trames de son réseau, y compris les
  échanges unicast entre d'autres machines (par exemple entre le relais et un serveur) ;
- À chaque évaluation, une sonde émet sur `lan1` et `lan2` quelques requêtes DHCP de test.
  Elles viennent d'adresses MAC commençant par `02:53:52` avec le nom d'hôte `sonde`, ou
  reprennent l'adresse MAC de `m2` ou de `m4`. Vous les verrez dans les journaux et les
  captures ; elles ne sont jamais suivies d'un `DHCPREQUEST`, donc aucun bail n'est
  enregistré.
- Les parties sont à faire **dans l'ordre**.
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
                _norm(q3.get("mac")) == mac_m2 and _norm(q3.get("in_leases")) in ("non", "no")
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
(voir l'onglet Informations, section @@ref:routes@@) :

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
            grade=int(any(s in _norm(q4.get("no_default")) for s in ("plus de route", "no longer"))),
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
                and any(s in _norm(q5.get("overlap")) for s in ("deux machines", "two machines"))
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
**failover** (voir l'onglet Informations, section @@ref:servers@@) :

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
_TRANSLATIONS = {
    'en': {
        """

### @@sec@@ Utiliser `tcpdump`

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

### @@sec@@ Utiliser `tshark`

`tshark`, la version en ligne de commande de Wireshark, résume chaque
trame en une ligne, avec son type et son identifiant de transaction :

```
tshark -n -i eth0 -f "port 67 or port 68"
```

```
    1   0.000000      0.0.0.0 → 255.255.255.255 DHCP 342 DHCP Discover - Transaction ID 0x6b3f2a1c
    2   1.001234     10.0.0.1 → 10.0.0.23    DHCP 342 DHCP Offer    - Transaction ID 0x6b3f2a1c
```

`-f` prend un *filtre de capture*, dans la syntaxe de `tcpdump` ; `-Y` un *filtre d'affichage*,
qui utilise les noms de champs de Wireshark : `-Y dhcp` (tous les messages DHCP),
`-Y "dhcp.option.dhcp == 2"` (les offres seulement). `-V` affiche le décodage complet de chaque
message, `-O dhcp` seulement sa partie DHCP, chaque champ étant nommé en clair (extrait d'une offre) :

```
Dynamic Host Configuration Protocol (Offer)
    Message type: Boot Reply (2)
    Transaction ID: 0x6b3f2a1c
    Your (client) IP address: 10.0.0.23
    Relay agent IP address: 0.0.0.0
    Client MAC address: 02:53:52:aa:bb:cc
    Option: (53) DHCP Message Type (Offer)
    Option: (54) DHCP Server Identifier (10.0.0.1)
    Option: (51) IP Address Lease Time
        IP Address Lease Time: (600s) 10 minutes
```

Enfin `-T fields -e <champ>` n'affiche que les champs demandés, un message par ligne, séparés
par des tabulations :

```
tshark -n -i eth0 -f "port 67 or port 68" -T fields -e dhcp.option.dhcp -e dhcp.hw.mac_addr \\
       -e dhcp.ip.your -e dhcp.ip.relay -e dhcp.option.dhcp_server_id -e dhcp.option.ip_address_lease_time
```

| ce que l'on cherche | où le lire dans `tcpdump` | champ Wireshark (`tshark -Y`, `-e`) |
|---------------------|---------------------------|-------------------------------------|
| adresses MAC source et destination | début de la première ligne (option `-e`) | `eth.src`, `eth.dst` |
| adresses IP et ports | `0.0.0.0.68 > 255.255.255.255.67` : le dernier nombre de chaque côté est le port UDP | `ip.src`, `ip.dst`, `udp.srcport`, `udp.dstport` |
| sens du message | `Request` (venant d'un client) ou `Reply` (venant d'un serveur) | `dhcp.type` : 1 (requête) ou 2 (réponse) |
| type du message | option `DHCP-Message` | `dhcp.option.dhcp` : 1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK |
| adresse attribuée | `Your-IP` | `dhcp.ip.your` |
| passage par un relais | `Gateway-IP` | `dhcp.ip.relay` |
| serveur qui répond, ou serveur retenu par le client | option `Server-ID` | `dhcp.option.dhcp_server_id` |
| durée du bail | option `Lease-Time` | `dhcp.option.ip_address_lease_time` (en secondes) |
""": """

### @@sec@@ Using `tcpdump`

```
tcpdump -n -e -v -i eth0 port 67 or port 68
```

shows for every message the MAC and IP addresses, then the DHCP content: `Your-IP` (proposed
address), `Gateway-IP` (`giaddr`), `Client-Ethernet-Address`, and the options (`DHCP-Message`
gives the type of the message). Open a second terminal on the machine to let the capture run
during your tests. Beginning of a message (simplified extract):

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

### @@sec@@ Using `tshark`

`tshark`, the command-line version of Wireshark, summarises each frame on one line, with its
type and its transaction identifier:

```
tshark -n -i eth0 -f "port 67 or port 68"
```

```
    1   0.000000      0.0.0.0 → 255.255.255.255 DHCP 342 DHCP Discover - Transaction ID 0x6b3f2a1c
    2   1.001234     10.0.0.1 → 10.0.0.23    DHCP 342 DHCP Offer    - Transaction ID 0x6b3f2a1c
```

`-f` takes a *capture filter*, in the syntax of `tcpdump`; `-Y` a *display filter*, which uses
the field names of Wireshark: `-Y dhcp` (every DHCP message), `-Y "dhcp.option.dhcp == 2"`
(the offers only). `-V` shows the full decoding of each message, `-O dhcp` only its DHCP part,
every field being named in clear (extract of an offer):

```
Dynamic Host Configuration Protocol (Offer)
    Message type: Boot Reply (2)
    Transaction ID: 0x6b3f2a1c
    Your (client) IP address: 10.0.0.23
    Relay agent IP address: 0.0.0.0
    Client MAC address: 02:53:52:aa:bb:cc
    Option: (53) DHCP Message Type (Offer)
    Option: (54) DHCP Server Identifier (10.0.0.1)
    Option: (51) IP Address Lease Time
        IP Address Lease Time: (600s) 10 minutes
```

Finally `-T fields -e <field>` prints only the requested fields, one message per line,
separated by tabs:

```
tshark -n -i eth0 -f "port 67 or port 68" -T fields -e dhcp.option.dhcp -e dhcp.hw.mac_addr \\
       -e dhcp.ip.your -e dhcp.ip.relay -e dhcp.option.dhcp_server_id -e dhcp.option.ip_address_lease_time
```

| what to look for | where to read it in `tcpdump` | Wireshark field (`tshark -Y`, `-e`) |
|------------------|-------------------------------|-------------------------------------|
| source and destination MAC addresses | start of the first line (option `-e`) | `eth.src`, `eth.dst` |
| IP addresses and ports | `0.0.0.0.68 > 255.255.255.255.67`: the last number on each side is the UDP port | `ip.src`, `ip.dst`, `udp.srcport`, `udp.dstport` |
| direction of the message | `Request` (from a client) or `Reply` (from a server) | `dhcp.type`: 1 (request) or 2 (reply) |
| type of the message | option `DHCP-Message` | `dhcp.option.dhcp`: 1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK |
| assigned address | `Your-IP` | `dhcp.ip.your` |
| passage through a relay | `Gateway-IP` | `dhcp.ip.relay` |
| server that answers, or server chosen by the client | option `Server-ID` | `dhcp.option.dhcp_server_id` |
| lease time | option `Lease-Time` | `dhcp.option.ip_address_lease_time` (in seconds) |
""",
        """

DHCP ne comporte **aucune authentification** : le client fait confiance au premier serveur qui
lui répond, et le serveur à l'adresse MAC que le client annonce. Cela permet de multiples attaques :

- **Serveur pirate** (*rogue DHCP server*) : n'importe quelle machine du réseau peut répondre
  aux `DHCPDISCOVER`. Ainsi un attaquant qui s'annonce comme routeur par défaut ou comme serveur DNS
  voit passer ou détourne tout le trafic de ses victimes.
- **Épuisement de la plage** (*DHCP starvation*) : un attaquant demande des baux sous des
  milliers d'adresses MAC inventées, jusqu'à vider la plage : les vraies machines n'obtiennent
  plus rien.
- **Usurpation** : en prenant l'adresse MAC d'une machine, un attaquant obtient l'adresse qui lui est
  réservée.
""": """

DHCP has **no authentication at all**: the client trusts the first server that answers it, and
the server trusts the MAC address the client announces. This allows many attacks:

- **Rogue server** (*rogue DHCP server*): any machine of the network can answer the
  `DHCPDISCOVER`s. An attacker who announces itself as the default router or as the DNS server
  thus watches or hijacks all the traffic of its victims.
- **Pool exhaustion** (*DHCP starvation*): an attacker requests leases under thousands of
  made-up MAC addresses until the range is empty: the real machines get nothing any more.
- **Spoofing**: by taking the MAC address of a machine, an attacker obtains the address
  reserved for it.
""",
        """

L'adresse n'est pas donnée mais **allouée temporairement** : le bail a une durée (option 51) au terme de
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

### @@sec@@ Libération, redémarrage, changement de réseau

- **Libération** : un client qui s'arrête proprement envoie un `DHCPRELEASE` et le serveur peut
  réattribuer l'adresse aussitôt. Un client éteint brutalement n'envoie rien : son adresse reste
  immobilisée jusqu'à l'expiration du bail.
- **Redémarrage** : un client qui a gardé la trace d'un bail encore valide ne repart pas du
  `DHCPDISCOVER`, il diffuse directement un `DHCPREQUEST` pour son ancienne adresse. Si elle
  convient toujours, le serveur répond `DHCPACK`.
- **Changement de réseau** : si l'adresse redemandée n'appartient pas au réseau où le client se
  trouve maintenant (cas d'un téléphone ou d'un ordinateur portable déplacé), un serveur répond `DHCPNAK` ; le client abandonne cette adresse et recommence par un
  `DHCPDISCOVER`. Sans ce refus, il attend inutilement avant de s'y résoudre.

### @@sec@@ Éviter les doublons

Pour éviter qu'une adresse de la plage d'allocation du serveur ne soit utilisée par une machine configurée à la main et ensuite attribuée par le serveur
à une deuxième machine, deux garde-fous existent :

- avant de proposer une adresse dynamique, `dhcpd` lui envoie un `ping` et attend une seconde
  (c'est pourquoi une première offre arrive avec une seconde de retard). Si une machine répond,
  l'adresse est mise à l'écart (*abandonnée*) et le client, qui répète sa demande, s'en voit
  proposer une autre ;
- le client peut vérifier de son côté, par une requête ARP, que personne n'utilise l'adresse
  reçue et la refuser par un `DHCPDECLINE`.

### @@sec@@ Durée de bail

On configure la durée du bail proposée par les serveurs DHCP en fonction de l'usage :

- si le bail est court (quelques minutes), les adresses des machines parties sont vite récupérées.
  C'est le cas par exemple des réseaux des lieux publics, où il peut venir plus de machines en une
  journée qu'il n'y a d'adresses disponibles ;
- si le bail est long (plusieurs heures à plusieurs jours), il y a moins de trafic réseau et
  surtout les postes restent fonctionnels malgré une longue panne du serveur.
""": """

The address is not given away but **allocated temporarily**: the lease has a duration (option 51)
at the end of which the client must stop using the address unless it has obtained an extension.

```
  obtained             T1 = 50 %                 T2 = 87.5 %      expiry
  |------------------------|--------------------------|----------------|
  | lease in progress      | renewing:                | rebinding:     |
  | (nothing is sent)      | unicast DHCPREQUEST      | broadcast      |
  |                        | to the lease's server    | DHCPREQUEST    |
```

- **at T1**, half the lease: the client asks for an extension with a `DHCPREQUEST` sent
  **in unicast to the server that granted the lease**; that server answers with a `DHCPACK`
  and the lease starts again for its full duration. There is neither `DHCPDISCOVER` nor
  `DHCPOFFER`;
- **at T2**, 87.5 % of the lease, if that server has not answered: the client **broadcasts**
  its `DHCPREQUEST`, so that any server of the network can extend the lease;
- **at expiry**: the client removes the address from its interface and starts all over again
  from the `DHCPDISCOVER`.

In normal operation a lease is therefore extended well before its end and the machine keeps the
same address indefinitely: it only loses it if no server answers during the whole second half
of the lease.

### @@sec@@ Release, reboot, change of network

- **Release**: a client that shuts down cleanly sends a `DHCPRELEASE` and the server may
  reassign the address at once. A client switched off abruptly sends nothing: its address stays
  tied up until the lease expires.
- **Reboot**: a client that kept track of a still valid lease does not start from the
  `DHCPDISCOVER`, it directly broadcasts a `DHCPREQUEST` for its old address. If that address
  is still suitable, the server answers `DHCPACK`.
- **Change of network**: if the requested address does not belong to the network where the
  client now is (a phone or a laptop that has moved), a server answers `DHCPNAK`; the client
  gives up that address and starts again with a `DHCPDISCOVER`. Without that refusal, it waits
  needlessly before resigning itself to it.

### @@sec@@ Avoiding duplicates

To prevent an address of the server's allocation range from being used by a hand-configured
machine and then assigned by the server to a second machine, two safeguards exist:

- before proposing a dynamic address, `dhcpd` sends it a `ping` and waits one second (this is
  why a first offer arrives one second late). If a machine answers, the address is set aside
  (*abandoned*) and the client, which repeats its request, is offered another one;
- the client can check on its side, with an ARP request, that nobody uses the address it
  received, and refuse it with a `DHCPDECLINE`.

### @@sec@@ Lease time

The lease time offered by the DHCP servers is set according to the use of the network:

- with a short lease (a few minutes), the addresses of the machines that have left are quickly
  recovered. This is the case, for example, of the networks of public places, where more
  machines may come in a day than there are addresses available;
- with a long lease (several hours to several days), there is less network traffic and, above
  all, the workstations keep working through a long outage of the server.
""",
        """

L'option `routers` ne donne au client qu'une **route par défaut**. C'est insuffisant lorsque le
réseau comporte plusieurs routeurs et que le routeur par défaut ne connaît pas tous les réseaux. Dans ce cas le serveur
 DHCP peut distribuer d'autres routes.

| option | code | contenu |
|--------|------|---------|
| `static-routes` | 33 | des routes sans masque, vers des adresses : conçue avant les réseaux sans classe, à éviter |
| routes sans classe (*classless static routes*) | 121 | des routes vers des réseaux de préfixe quelconque ([RFC 3442](https://www.rfc-editor.org/rfc/rfc3442), 2002) : c'est elle qu'on utilise |

### @@sec@@ Le codage de l'option 121

L'option est une suite d'octets. Chaque route s'y écrit : la **longueur du préfixe**, puis les
seuls **octets significatifs** de l'adresse du réseau (ceux que couvre le préfixe), puis les
**quatre octets du routeur**.

| route | codage |
|-------|--------|
| `198.51.100.0/24` par `192.0.2.254` | `24, 198,51,100, 192,0,2,254` |
| `172.16.0.0/12` par `192.0.2.254` | `12, 172,16, 192,0,2,254` |
| `10.0.0.0/8` par `192.0.2.254` | `8, 10, 192,0,2,254` |
| route par défaut par `192.0.2.1` | `0, 192,0,2,1` |

### @@sec@@ Configuration du serveur

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

### @@sec@@ Utilisation par le client

`dhclient` installe les routes reçues **à l'obtention d'un bail**, pas lors d'un simple
renouvellement : après une modification sur le serveur, il faut dedemander un bail (`ifdown eth0` puis
`ifup eth0`).

```
ip route                                             # les routes installées
grep classless /var/lib/dhcp/dhclient.eth0.leases    # l'option reçue
```

Dans le fichier de baux, l'option apparaît telle que le serveur l'a envoyée :

```
  option rfc3442-classless-static-routes 24,198,51,100,192,0,2,254,0,192,0,2,1;
```
""": """

The `routers` option only gives the client a **default route**. That is not enough when the
network has several routers and the default router does not know every network. The DHCP
server can then distribute other routes.

| option | code | content |
|--------|------|---------|
| `static-routes` | 33 | routes without a mask, to addresses: designed before classless networks, to be avoided |
| classless static routes | 121 | routes to networks of any prefix length ([RFC 3442](https://www.rfc-editor.org/rfc/rfc3442), 2002): the one to use |

### @@sec@@ Encoding of option 121

The option is a sequence of bytes. Each route is written as: the **prefix length**, then only
the **significant bytes** of the network address (those covered by the prefix), then the
**four bytes of the router**.

| route | encoding |
|-------|----------|
| `198.51.100.0/24` via `192.0.2.254` | `24, 198,51,100, 192,0,2,254` |
| `172.16.0.0/12` via `192.0.2.254` | `12, 172,16, 192,0,2,254` |
| `10.0.0.0/8` via `192.0.2.254` | `8, 10, 192,0,2,254` |
| default route via `192.0.2.1` | `0, 192,0,2,1` |

### @@sec@@ Server configuration

`dhcpd` does not know this option by name: it must be **declared**, once and outside any
block, before it is given a value in the `subnet` concerned.

```
option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;

subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.100 192.0.2.150;
    option routers 192.0.2.1;
    option rfc3442-classless-static-routes 24, 198,51,100, 192,0,2,254, 0, 192,0,2,1;
}
```

Three rules:

- **a client that receives option 121 ignores the `routers` option**: the default route must
  therefore **also** appear in option 121. `option routers` is kept for the clients that do not
  know option 121;
- the routers named must be on the client's network: the option goes in the `subnet` of that
  network, not among the global options;
- `dhcpd` only sends the option to the clients that ask for it (option 55), which `dhclient` does.

The name given to the option is free, since only the code 121 travels. The one of the example
is the name `dhclient` uses.

### @@sec@@ Use by the client

`dhclient` installs the routes received **when it obtains a lease**, not on a mere renewal:
after a change on the server, a lease must be requested again (`ifdown eth0` then `ifup eth0`).

```
ip route                                             # the routes installed
grep classless /var/lib/dhcp/dhclient.eth0.leases    # the option received
```

In the lease file, the option appears as the server sent it:

```
  option rfc3442-classless-static-routes 24,198,51,100,192,0,2,254,0,192,0,2,1;
```
""",
        """

Pour communiquer en IPv4, une machine a besoin de multiples informations : son **adresse IP**,
le **masque** de son réseau, l'adresse du **routeur par défaut** (et éventuellement
les autres routes statiques nécessaires). et celle d'un **serveur DNS**.
Les saisir à la main est fastidieux et de fait impossible dans le cas de portables qui se connectent
à différents réseaux ou dès que le parc de machines considéré atteint une certaine taille.

**DHCP** automatise cette configuration : un serveur DHCP fournit ces informations sur demande aux clients
DHCP et s'assure qu'une adresse IP n'est allouée qu'à une machine à la fois.

Le serveur peut également fournir d'autres informations au client comme par exemple son nom (*hostname*), les adresses des serveurs de synchronisation du temps (NTP).

Un serveur peut attribuer une adresse de deux façons :

- **adresse dynamique** : l'adresse est prise dans une plage et **allouée pour une durée limitée** (durée du *bail*). Rendue ou expirée, 
elle pourra être attribuée à une autre machine.
- **adresse fixe** (*réservation*) : l'administrateur a associé une adresse à une machine
  précise, identifiée par l'adresse MAC de son interface réseau.

DHCP a été créé en 1993. Il prolonge **BOOTP** (1985), conçu pour démarrer des stations sans disque,
dont il garde le format de message et les ports UDP : c'est pourquoi les outils de capture
parlent de `BOOTP/DHCP`. 

Textes de référence actuels (en anglais) : [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) (le protocole, 1997),
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132) (les options, 1997),
[RFC 3046](https://www.rfc-editor.org/rfc/rfc3046) (l'option ajoutée par les relais, 2001).
""": """

To communicate over IPv4, a machine needs several pieces of information: its **IP address**,
the **mask** of its network, the address of its **default router** (and possibly the other
static routes it needs) and that of a **DNS server**.
Entering them by hand is tedious, and in practice impossible for laptops that connect to
different networks, or as soon as the number of machines reaches a certain size.

**DHCP** automates this configuration: a DHCP server supplies this information on demand to DHCP
clients and makes sure that an IP address is allocated to only one machine at a time.

The server can also give the client other information, such as its name (*hostname*) or the
addresses of the time synchronisation servers (NTP).

A server can assign an address in two ways:

- **dynamic address**: the address is taken from a range and **allocated for a limited time**
  (the duration of the *lease*). Once returned or expired, it may be assigned to another machine.
- **fixed address** (*reservation*): the administrator has associated an address with one
  particular machine, identified by the MAC address of its network interface.

DHCP was created in 1993. It extends **BOOTP** (1985), designed to boot diskless workstations,
and keeps its message format and UDP ports: this is why capture tools speak of `BOOTP/DHCP`.

Current reference texts: [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) (the protocol, 1997),
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132) (the options, 1997),
[RFC 3046](https://www.rfc-editor.org/rfc/rfc3046) (the option added by relays, 2001).
""",
        """

Pour pallier au risque de défaillance d'un serveur DHCP unique sur un réseau, rien
n'interdit d'avoir plusieurs serveurs DHCP sur un réseau : tous reçoivent le `DHCPDISCOVER`,
tous répondent par un `DHCPOFFER`, et le client choisit (en général la première offre). 

On peut les configurer de deux façons :

- avec des **plages disjointes** (*split scope*) : les deux serveurs sont indépendants et ne se
  connaissent pas. Ils ne partagent pas leurs baux : leurs plages dynamiques ne doivent
  donc avoir **aucune adresse commune**, tandis que les options et les réservations doivent
  être **identiques** sur les deux ;
- **failover** : les deux serveurs partagent **la même plage** et se synchronisent par une
  connexion TCP.

### @@sec@@ Plages disjointes

C'est la solution la plus simple, et elle fonctionne avec n'importe quels serveurs. Ses limites :
chaque serveur ne dispose que de sa part des adresses (si l'un tombe, l'autre doit pouvoir
servir seul toutes les machines), toute modification est à reporter à la main sur les deux, et
une machine peut changer d'adresse en changeant de serveur.

### @@sec@@ Failover

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
""": """

To guard against the failure of a single DHCP server on a network, nothing forbids having
several DHCP servers on it: all of them receive the `DHCPDISCOVER`, all of them answer with a
`DHCPOFFER`, and the client chooses (usually the first offer).

They can be set up in two ways:

- with **disjoint ranges** (*split scope*): the two servers are independent and do not know
  each other. They do not share their leases: their dynamic ranges must therefore have **no
  address in common**, while the options and the reservations must be **identical** on both;
- **failover**: the two servers share **the same range** and synchronise over a TCP connection.

### @@sec@@ Disjoint ranges

This is the simplest solution, and it works with any servers. Its limits: each server only has
its share of the addresses (if one fails, the other must be able to serve every machine on its
own), every change must be copied by hand to both, and a machine may change address when it
changes server.

### @@sec@@ Failover

The range is placed in a `pool` attached to a `failover peer` relationship declared on both
servers (one `primary`, the other `secondary`):

```
failover peer "lan2" {
    primary;                           # "secondary;" on the other server
    address 192.0.2.2;                 # address of this server
    port 647;
    peer address 192.0.2.3;            # address of the other server
    peer port 647;
    max-response-delay 30;
    max-unacked-updates 10;
    load balance max seconds 3;
    mclt 120;                          # on the primary server only
    split 128;                         # on the primary server only
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

| parameter | role |
|-----------|------|
| `address`, `port`, `peer address`, `peer port` | the two ends of the TCP connection between the servers |
| `max-response-delay` | seconds of silence from the partner before the link is considered down |
| `max-unacked-updates` | number of updates that may remain unacknowledged by the partner |
| `split 128` | distribution of the clients between the servers: 128 out of 256, i.e. half and half |
| `load balance max seconds` | beyond this waiting time of the client (`secs` field), both servers answer it |
| `mclt` | *Maximum Client Lead Time*: how far a lease may run ahead of what the partner knows of it |

In normal operation (`Both servers normal` in the journal) the servers share the clients
(`split 128`: half and half) and only one of them answers a given client; if one fails, the
other serves everybody. As long as a lease has not been confirmed by both servers, its duration
is limited to the **MCLT** (*Maximum Client Lead Time*): the first lease of a client is
therefore short, and it is by renewing it that the client gets the normal duration.

The free addresses of the `pool` are shared between the two servers (`free` for the primary,
`backup` for the secondary in `dhcpd.leases`), so that each one can still assign some when it
is alone. The state of the relationship is recorded in the journal and in `dhcpd.leases`:

| state | situation |
|-------|-----------|
| `recover`, `recover-done` | start-up: the servers exchange what they know of the leases |
| `normal` | the two servers see each other and synchronise |
| `communications-interrupted` | the partner no longer answers: each goes on with its own free addresses, the leases being limited to the MCLT |
| `partner-down` | the partner has been declared out of service by the administrator: the remaining server takes over the whole range |

The two servers must declare the same `pool`, and their clocks must show the same time.
""",
        """

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
| 33 | `static-routes` | routes vers des adresses, sans masque (section @@ref:routes@@) | `Static-Route` |
| 42 | `ntp-servers` | serveurs de temps | `NTP` |
| 50 | `dhcp-requested-address` | adresse que le client souhaite obtenir | `Requested-IP` |
| 51 | `dhcp-lease-time` | durée du bail, en secondes | `Lease-Time` |
| 53 | `dhcp-message-type` | type du message (`DHCPDISCOVER`, `DHCPOFFER`…) | `DHCP-Message` |
| 54 | `dhcp-server-identifier` | adresse du serveur qui fait l'offre, ou que le client retient | `Server-ID` |
| 55 | `dhcp-parameter-request-list` | liste des options demandées par le client | `Parameter-Request` |
| 58 | `dhcp-renewal-time` | instant T1 (section @@ref:lease@@) | `RN` |
| 59 | `dhcp-rebinding-time` | instant T2 (section @@ref:lease@@) | `RB` |
| 61 | `dhcp-client-identifier` | identifiant du client, quand il n'utilise pas son adresse MAC | `Client-ID` |
| 82 | (ajoutée par un relais) | informations sur le point de raccordement du client | `Agent-Information` |
| 121 | `rfc3442-classless-static-routes` (à déclarer) | routes vers des réseaux, en plus de la route par défaut (section @@ref:routes@@) | `Classless-Static-Route` |
""": """

Every message has the same format, inherited from BOOTP: fixed fields, then a list of
**options**.

| field | content | in `tcpdump -v` |
|-------|---------|-----------------|
| `op` | direction of the message: request (from the client) or reply (from the server) | `Request` / `Reply` |
| `xid` | transaction identifier, chosen by the client and copied by the server: it ties the replies to the request | `xid` |
| `secs` | seconds elapsed since the client started looking for an address | `secs` |
| `flags` | *broadcast* flag: "answer me by broadcast" | `Flags` |
| `ciaddr` | the client's **current** address, when it already has one (renewal) | `Client-IP` |
| `yiaddr` | *your address*: the address the server assigns to the client | `Your-IP` |
| `siaddr` | server to contact for a network boot | `Server-IP` |
| `giaddr` | address of the relay that forwarded the request (zero without a relay) | `Gateway-IP` |
| `chaddr` | hardware (MAC) address of the client | `Client-Ethernet-Address` |
| `hops` | number of relays crossed | `hops` |

`tcpdump` only shows the non-zero fields: no `Gateway-IP` without a relay, no `Your-IP` in a
message from the client.

Everything else travels in the options, each identified by a **code**. The message type is
itself an option (53); the client lists the parameters it wants (option 55) and the server
returns those it knows.

| code | name in `dhcpd.conf` and in the lease files | content | in `tcpdump -v` |
|------|------|---------|-----------------|
| 1 | `subnet-mask` | network mask | `Subnet-Mask` |
| 3 | `routers` | default router(s) | `Default-Gateway` |
| 6 | `domain-name-servers` | DNS server(s) | `Domain-Name-Server` |
| 12 | `host-name` | name of the machine | `Hostname` |
| 15 | `domain-name` | DNS domain, which completes short names (`ping srv1`) | `Domain-Name` |
| 28 | `broadcast-address` | broadcast address of the network | `BR` |
| 33 | `static-routes` | routes to addresses, without a mask (section @@ref:routes@@) | `Static-Route` |
| 42 | `ntp-servers` | time servers | `NTP` |
| 50 | `dhcp-requested-address` | address the client would like to get | `Requested-IP` |
| 51 | `dhcp-lease-time` | lease time, in seconds | `Lease-Time` |
| 53 | `dhcp-message-type` | type of the message (`DHCPDISCOVER`, `DHCPOFFER`…) | `DHCP-Message` |
| 54 | `dhcp-server-identifier` | address of the server making the offer, or chosen by the client | `Server-ID` |
| 55 | `dhcp-parameter-request-list` | list of the options requested by the client | `Parameter-Request` |
| 58 | `dhcp-renewal-time` | time T1 (section @@ref:lease@@) | `RN` |
| 59 | `dhcp-rebinding-time` | time T2 (section @@ref:lease@@) | `RB` |
| 61 | `dhcp-client-identifier` | identifier of the client, when it does not use its MAC address | `Client-ID` |
| 82 | (added by a relay) | information on the client's point of attachment | `Agent-Information` |
| 121 | `rfc3442-classless-static-routes` (must be declared) | routes to networks, in addition to the default route (section @@ref:routes@@) | `Classless-Static-Route` |
""",
        """

Une diffusion n'est jamais routé : un client ne peut pas atteindre un serveur situé
sur un autre réseau. Un **agent relais**, placé sur le routeur, écoute les diffusions des
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
raccordé. 

Le serveur relais de l'ISC se configure dans `/etc/default/isc-dhcp-relay` :

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
""": """

A broadcast is never routed: a client cannot reach a server located on another network. A
**relay agent**, placed on the router, listens to the clients' broadcasts and forwards them
**in unicast** to the server(s) after writing its own address on the client's network in the
**`giaddr`** field of the message.

```
   client                relay (router)                              server
     |                          |                                        |
     |--- DHCPDISCOVER -------->|                                        |
     |    (broadcast)           |--- DHCPDISCOVER ---------------------->|
     |                          |    unicast, giaddr = relay's address   |
     |                          |<--- DHCPOFFER -------------------------|
     |<--- DHCPOFFER -----------|    sent to the giaddr address          |
     |                          |                                        |
     |   then, along the same path: DHCPREQUEST and DHCPACK              |
```

The server:

- chooses the `subnet` (hence the range) from `giaddr`: it needs a `subnet` declaration for
  the remote network, with a `routers` option **specific to that network**;
- answers the relay, at the `giaddr` address (so it must have a route to that network); the
  relay hands the answer to the client.

A single server can thus serve every network of a site without having an interface on them.
**Renewals**, however, do not go through the relay: the client, which now has an address,
writes directly to the server, which assumes that routing works between the two networks.
A relay may add option 82 to the request, which tells the server where the client is attached.

The ISC relay is configured in `/etc/default/isc-dhcp-relay`:

```
SERVERS="192.0.2.2"          # address(es) of the server(s), separated by spaces
INTERFACES="eth1 eth2"       # listening interfaces
OPTIONS=""
```

`dhcrelay` must listen on the **clients'** interface and on the one through which the
**servers' answers** arrive (otherwise the requests leave but the answers are ignored).
The role of each interface can be stated with `INTERFACES=""` and
`OPTIONS="-id eth2 -iu eth1"` (`-id`: client side, `-iu`: server side).

```
systemctl restart isc-dhcp-relay
ps -C dhcrelay -o pid,args             # the only reliable check that the relay is running
dhcrelay -d -i eth1 -i eth2 192.0.2.2  # in the foreground, with the messages (Ctrl-C to stop)
```

`systemctl` reports the service as active even when `dhcrelay` refused to start.
""",
        """

Une machine qui démarre sans configuration ne connaît ni son adresse, ni son réseau, ni même
l'adresse d'un serveur : elle ne peut qu'envoyer une demande à l'adresse de broadcast de son réseau local.
L'échange nécessaire à l'attribution d'une adresse IP comporte quatre messages :

```
   client                                            serveur
     |                                                  |
     |--- DHCPDISCOVER (diffusion) -------------------->|   y a-t-il un serveur sur le réseau ?
     |<--- DHCPOFFER -----------------------------------|   proposition d'une adresse et d'une durée de bail par le serveur
     |--- DHCPREQUEST (diffusion) --------------------->|   acceptation d'une offre (pour une certaine durée) par le client
     |<--- DHCPACK -------------------------------------|   le serveur accuse réception de la demande du client, qui peut utiliser l'IP allouée
     |                                                  |
```

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPDISCOVER` | client | recherche des serveurs DHCP sur le réseau |
| `DHCPOFFER` | serveur | propose une adresse, une durée de bail et des paramètres |
| `DHCPREQUEST` | client | accepte **une** offre en nommant le serveur retenu et la durée de bail (ou prolonge un bail) |
| `DHCPACK` | serveur | confirme : le bail est accordé, le client configure son interface |

Sans réponse, le client répète son `DHCPDISCOVER` à intervalles de plus en plus longs. Si
plusieurs serveurs répondent, il reçoit plusieurs offres et en retient une, en général la
première. Une adresse proposée reste mise de côté par le serveur pendant deux minutes environ : si
le client ne la confirme pas, elle redevient disponible.

### @@sec@@ Transport et adresses


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

### @@sec@@ Les autres messages

| message | émetteur | rôle |
|---------|----------|------|
| `DHCPNAK` | serveur | refuse un `DHCPREQUEST` (adresse étrangère au réseau, bail expiré et réattribué…) : le client recommence à zéro par un `DHCPDISCOVER` |
| `DHCPDECLINE` | client | signale que l'adresse reçue est déjà utilisée par une autre machine : le serveur la met à l'écart |
| `DHCPRELEASE` | client | rend son adresse avant la fin du bail (arrêt propre de l'interface) |
| `DHCPINFORM` | client | demande seulement des paramètres (DNS, domaine…) pour une adresse qu'il a déjà, configurée à la main |
""": """

A machine that boots without any configuration knows neither its address, nor its network, nor
even the address of a server: all it can do is send a request to the broadcast address of its
local network. Assigning an IP address takes an exchange of four messages:

```
   client                                            server
     |                                                  |
     |--- DHCPDISCOVER (broadcast) -------------------->|   is there a server on the network?
     |<--- DHCPOFFER -----------------------------------|   the server proposes an address and a lease time
     |--- DHCPREQUEST (broadcast) --------------------->|   the client accepts an offer (for a given time)
     |<--- DHCPACK -------------------------------------|   the server acknowledges the request: the client may use the allocated IP
     |                                                  |
```

| message | sender | role |
|---------|--------|------|
| `DHCPDISCOVER` | client | looks for DHCP servers on the network |
| `DHCPOFFER` | server | proposes an address, a lease time and parameters |
| `DHCPREQUEST` | client | accepts **one** offer, naming the chosen server and the lease time (or extends a lease) |
| `DHCPACK` | server | confirms: the lease is granted, the client configures its interface |

Without an answer, the client repeats its `DHCPDISCOVER` at longer and longer intervals. If
several servers answer, it receives several offers and keeps one, usually the first. A proposed
address is set aside by the server for about two minutes: if the client does not confirm it, it
becomes available again.

### @@sec@@ Transport and addresses

DHCP is carried over **UDP**: the server (like the relay) listens on port **67**, the client on
port **68**. As long as the client has no address:

- it sends from the source address `0.0.0.0` ("no address yet") to the broadcast address
  `255.255.255.255`, in an Ethernet frame addressed to `ff:ff:ff:ff:ff:ff`: every machine of the
  local network receives it, no router forwards it;
- the server answers it directly (a frame sent to the client's MAC address, a packet addressed
  to the address it proposes), or by broadcast if the client asked for it with the *broadcast*
  flag of the message;
- the `DHCPREQUEST` is still **broadcast**, although the client knows which server it is
  talking to: this is how the **other** servers learn that their offer was not kept.

### @@sec@@ The other messages

| message | sender | role |
|---------|--------|------|
| `DHCPNAK` | server | refuses a `DHCPREQUEST` (address foreign to the network, lease expired and reassigned…): the client starts over with a `DHCPDISCOVER` |
| `DHCPDECLINE` | client | reports that the address received is already used by another machine: the server sets it aside |
| `DHCPRELEASE` | client | returns its address before the end of the lease (clean shutdown of the interface) |
| `DHCPINFORM` | client | only asks for parameters (DNS, domain…) for an address it already has, configured by hand |
""",
        """

```
dhclient -v eth0       # demande un bail, configure l'interface, puis reste en arrière-plan
dhclient -r -v eth0    # libère le bail et arrête le client
```

Avec `-v`, `dhclient` affiche le dialogue avec le serveur :

```
DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3
DHCPOFFER of 192.0.2.101 from 192.0.2.2
DHCPREQUEST for 192.0.2.101 on eth0 to 255.255.255.255 port 67
DHCPACK of 192.0.2.101 from 192.0.2.2
bound to 192.0.2.101 -- renewal in 1527 seconds.
```

Une fois le bail obtenu, `dhclient` configure l'adresse de l'interface, la route par défaut et
`/etc/resolv.conf` (par le script `/sbin/dhclient-script`), puis reste en arrière-plan pour
renouveler le bail. Dans `ip a`, l'adresse est marquée `dynamic` et sa durée de validité
restante est affichée (`valid_lft`).

| fichier | rôle |
|---------|------|
| `/etc/dhcp/dhclient.conf` | réglages du client |
| `/var/lib/dhcp/dhclient.leases` | baux obtenus par un `dhclient` lancé à la main |
| `/var/lib/dhcp/dhclient.eth0.leases` | baux obtenus par `ifup eth0` |

### @@sec@@ Le fichier de baux du client

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

### @@sec@@ Les réglages du client

| instruction de `dhclient.conf` | effet |
|--------------------------------|-------|
| `request subnet-mask, routers, …;` | options demandées au serveur (option 55) |
| `send dhcp-lease-time 86400;` | valeur envoyée au serveur, ici la durée de bail souhaitée |
| `supersede domain-name "example.org";` | valeur imposée, quelle que soit la réponse du serveur |
| `prepend domain-name-servers 192.0.2.53;` | valeur placée avant celles du serveur |
| `timeout 60;` | secondes de recherche avant d'abandonner (60 par défaut) |

### @@sec@@ Configuration persistante : ifupdown

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
""": """

```
dhclient -v eth0       # requests a lease, configures the interface, then stays in the background
dhclient -r -v eth0    # releases the lease and stops the client
```

With `-v`, `dhclient` shows the dialogue with the server:

```
DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3
DHCPOFFER of 192.0.2.101 from 192.0.2.2
DHCPREQUEST for 192.0.2.101 on eth0 to 255.255.255.255 port 67
DHCPACK of 192.0.2.101 from 192.0.2.2
bound to 192.0.2.101 -- renewal in 1527 seconds.
```

Once the lease is obtained, `dhclient` configures the address of the interface, the default
route and `/etc/resolv.conf` (through the script `/sbin/dhclient-script`), then stays in the
background to renew the lease. In `ip a`, the address is marked `dynamic` and its remaining
validity is shown (`valid_lft`).

| file | role |
|------|------|
| `/etc/dhcp/dhclient.conf` | client settings |
| `/var/lib/dhcp/dhclient.leases` | leases obtained by a `dhclient` started by hand |
| `/var/lib/dhcp/dhclient.eth0.leases` | leases obtained by `ifup eth0` |

### @@sec@@ The client's lease file

`dhclient` writes every lease obtained or extended there; the last block is the current lease.

```
lease {
  interface "eth0";
  fixed-address 192.0.2.101;                  # the address obtained
  option subnet-mask 255.255.255.0;
  option routers 192.0.2.1;
  option dhcp-lease-time 3600;                # lease time
  option dhcp-message-type 5;                 # 5 = DHCPACK
  option domain-name-servers 192.0.2.53;
  option dhcp-server-identifier 192.0.2.2;    # the server that granted the lease
  option domain-name "example.org";
  renew 3 2026/10/07 08:28:11;                # T1
  rebind 3 2026/10/07 08:52:30;               # T2
  expire 3 2026/10/07 09:00:00;               # end of the lease
}
```

The dates are in universal time (UTC), preceded by the number of the day of the week.

### @@sec@@ The client's settings

| `dhclient.conf` statement | effect |
|---------------------------|--------|
| `request subnet-mask, routers, …;` | options requested from the server (option 55) |
| `send dhcp-lease-time 86400;` | value sent to the server, here the desired lease time |
| `supersede domain-name "example.org";` | value imposed, whatever the server answers |
| `prepend domain-name-servers 192.0.2.53;` | value placed before those of the server |
| `timeout 60;` | seconds of searching before giving up (60 by default) |

### @@sec@@ Persistent configuration: ifupdown

For a **persistent** configuration (applied at every boot), the interface is declared in
`/etc/network/interfaces`:

```
auto eth0
iface eth0 inet dhcp
```

then brought up with `ifup eth0` (and brought down with `ifdown eth0`, which releases the
lease). `ifup` starts its own `dhclient`, with its own lease file
(`/var/lib/dhcp/dhclient.eth0.leases`): first release a lease obtained by hand
(`dhclient -r eth0`), then use nothing but `ifup` / `ifdown`.
""",
        """

| fichier | rôle |
|---------|------|
| `/etc/default/isc-dhcp-server` | interfaces d'écoute : `INTERFACESv4="eth0"` |
| `/etc/dhcp/dhcpd.conf` | configuration |
| `/var/lib/dhcp/dhcpd.leases` | baux accordés (écrit par `dhcpd`, à ne pas modifier) |

### @@sec@@ Structure de dhcpd.conf

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

### @@sec@@ Exemple

```
authoritative;                         # ce serveur fait autorité sur ses réseaux
default-lease-time 3600;               # durée de bail en secondes accordée si le client ne demande rien
max-lease-time 7200;                   # bail maximal accordé si le client demande plus que default-lease-time
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

### @@sec@@ Les durées de bail

| paramètre | rôle | sans réglage |
|-----------|------|--------------|
| `default-lease-time` | durée accordée à un client qui ne demande rien | 43200 s (12 h) |
| `max-lease-time` | plafond appliqué à un client qui demande une durée | 86400 s (24 h) |
| `min-lease-time` | plancher : aucun bail plus court n'est accordé | 300 s |

### @@sec@@ Les adresses fixes

Une réservation (bloc `host`) identifie le client par son **adresse MAC** (`ip link show eth0`
sur le client) et lui donne toujours la même adresse :

- l'adresse fixe se choisit **en dehors** des plages dynamiques, mais dans le réseau défini par le serveur :
la réservation ne s'applique que si le client se présente sur le `subnet` qui
  contient cette adresse ;
- Il est possible d'ajouter des options spécifiquement pour ce client dans le bloc `host`, en plus de celles du 
`subnet` et des options globales ;
- le nom donné au bloc `host` n'est pas utilisé : c'est l'adresse MAC qui désigne la machine.

### @@sec@@ Choisir les clients servis

Par défaut `dhcpd` sert toute machine qui se présente. L'option `deny unknown-clients;` réserve les adresses dynamiques 
aux machines déclarées par un bloc `host`.

### @@sec@@ Le registre des baux : dhcpd.leases

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

### @@sec@@ Lancer et contrôler le serveur

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
""": """

| file | role |
|------|------|
| `/etc/default/isc-dhcp-server` | listening interfaces: `INTERFACESv4="eth0"` |
| `/etc/dhcp/dhcpd.conf` | configuration |
| `/var/lib/dhcp/dhcpd.leases` | leases granted (written by `dhcpd`, not to be edited) |

### @@sec@@ Structure of dhcpd.conf

The file holds **parameters** and **declarations**. Every statement ends with `;`, a block is
delimited by braces, a comment starts with `#`.

- a **parameter** sets the behaviour of the server (`default-lease-time 3600;`); preceded by
  the word `option`, it names a DHCP option sent to the clients (`option routers 192.0.2.1;`);
- a **declaration** describes the network and delimits the **scope** of the parameters it
  contains:

| declaration | describes |
|-------------|-----------|
| `subnet … netmask … { }` | an IP network |
| `range first last;` | in a `subnet` or a `pool`: the range of the dynamically assigned addresses |
| `pool { }` | in a `subnet`: a range subject to particular rules (admitted clients, failover) |
| `host name { }` | one particular machine: fixed address, options of its own |
| `group { }` | declarations that share the same parameters |
| `shared-network name { }` | several IP networks carried by the same physical network |
| `class "name" { }` | a category of clients, recognised by what they send |

A parameter written outside any block is **global**. For a given client, the value of the
**most specific** scope wins: `host`, then `class`, `pool`, `subnet`, `shared-network`, and
finally the global parameters. So what applies everywhere (DNS server, domain, lease times) is
written once, globally, and what is specific to each `subnet` (the router) is written in it.

### @@sec@@ Example

```
authoritative;                         # this server is authoritative on its networks
default-lease-time 3600;               # lease time in seconds granted when the client asks for nothing
max-lease-time 7200;                   # maximum lease granted when the client asks for more than default-lease-time
option domain-name "example.org";      # global options: valid for every network
option domain-name-servers 192.0.2.53;

subnet 192.0.2.0 netmask 255.255.255.0 {
    range 192.0.2.100 192.0.2.150;     # range of the dynamically assigned addresses
    option routers 192.0.2.1;          # option specific to this network
}

host printer {                         # fixed address (reservation) for one machine
    hardware ethernet 00:11:22:33:44:55;
    fixed-address 192.0.2.10;          # outside any dynamic range
}
```

`dhcpd` requires a `subnet` declaration for the network of every interface it listens on, and
one is needed for every network it serves. An `authoritative` server answers `DHCPNAK` to a
client that asks again for an address foreign to the network (a machine coming from another
network): without it the client waits needlessly.

### @@sec@@ Lease times

| parameter | role | default |
|-----------|------|---------|
| `default-lease-time` | time granted to a client that asks for nothing | 43200 s (12 h) |
| `max-lease-time` | ceiling applied to a client that asks for a time | 86400 s (24 h) |
| `min-lease-time` | floor: no shorter lease is granted | 300 s |

### @@sec@@ Fixed addresses

A reservation (`host` block) identifies the client by its **MAC address** (`ip link show eth0`
on the client) and always gives it the same address:

- the fixed address is chosen **outside** the dynamic ranges, but inside the network defined by
  the server: the reservation only applies if the client shows up on the `subnet` that
  contains that address;
- options may be added specifically for that client in the `host` block, on top of those of
  the `subnet` and of the global options;
- the name given to the `host` block is not used: the MAC address is what designates the machine.

### @@sec@@ Choosing the clients served

By default `dhcpd` serves every machine that shows up. The statement `deny unknown-clients;`
reserves the dynamic addresses to the machines declared by a `host` block.

### @@sec@@ The lease registry: dhcpd.leases

`dhcpd` records in `/var/lib/dhcp/dhcpd.leases` the leases of the addresses of its dynamic
ranges, to find them again after a restart. It is a journal: every change **appends** a block,
and for a given address the **last** block is the one that counts.

```
lease 192.0.2.101 {
  starts 3 2026/10/07 08:00:00;          # start of the lease (UTC)
  ends 3 2026/10/07 09:00:00;            # end of the lease
  cltt 3 2026/10/07 08:00:00;            # last exchange with the client
  binding state active;                  # state of the lease
  next binding state free;               # state it will take at its end
  hardware ethernet 00:11:22:33:44:55;   # the client
  client-hostname "laptop";
}
```

| state (`binding state`) | meaning |
|-------------------------|---------|
| `active` | lease in progress |
| `free` | address available: lease ended or returned |
| `abandoned` | address set aside: it answered the server's `ping`, or a client refused it |
| `backup` | failover: available address entrusted to the secondary server |
| `expired`, `released` | failover: transient states of an ended or returned lease, before `free` |

An offer is not a lease: nothing is written until the client has confirmed with a
`DHCPREQUEST`. The command `dhcp-lease-list` gives a readable summary of the current leases.

### @@sec@@ Starting and controlling the server

```
dhcpd -t -cf /etc/dhcp/dhcpd.conf      # checks the syntax without starting the server
systemctl restart isc-dhcp-server      # to run again after EVERY change
systemctl status isc-dhcp-server
journalctl -u isc-dhcp-server -f       # live journal: one line per DHCP message
ps -C dhcpd -o pid,args                # the process and its arguments
dhcp-lease-list                        # summary of the current leases
```

The journal shows every message received or sent:

```
DHCPDISCOVER from 00:11:22:33:44:55 via eth0
DHCPOFFER on 192.0.2.101 to 00:11:22:33:44:55 (laptop) via eth0
DHCPREQUEST for 192.0.2.101 (192.0.2.2) from 00:11:22:33:44:55 (laptop) via eth0
DHCPACK on 192.0.2.101 to 00:11:22:33:44:55 (laptop) via eth0
```

`via eth0` names the interface the request came in on; in the `DHCPREQUEST`, the address in
parentheses is that of the server the client has chosen.

If `INTERFACESv4` is empty, the service is reported as failed while a `dhcpd` keeps running on
every interface: fix the file, kill that process (`pkill dhcpd`) then restart the service.
""",
        """
## Particularités du TP

- chaque client doit recevoir une configuration **persistante** (`/etc/network/interfaces`)
          activée par `ifup eth0` ;
- après chaque modification d'un fichier de configuration, **relancez le service** et
          vérifiez dans le journal qu'il a bien démarré ;
- l'évaluation interroge les serveurs tels qu'ils tournent au moment où elle est lancée :
          un serveur arrêté pour un essai doit être relancé.
- Le réseau virtuel se comporte comme un **concentrateur** (*hub*) : une capture sur
  n'importe quelle machine montre **toutes** les trames de son réseau, y compris les
  échanges unicast entre d'autres machines (par exemple entre le relais et un serveur) ;
- À chaque évaluation, une sonde émet sur `lan1` et `lan2` quelques requêtes DHCP de test.
  Elles viennent d'adresses MAC commençant par `02:53:52` avec le nom d'hôte `sonde`, ou
  reprennent l'adresse MAC de `m2` ou de `m4`. Vous les verrez dans les journaux et les
  captures ; elles ne sont jamais suivies d'un `DHCPREQUEST`, donc aucun bail n'est
  enregistré.
- Les parties sont à faire **dans l'ordre**.
""": """
## Specifics of the lab

- every client must end up with a **persistent** configuration (`/etc/network/interfaces`)
  brought up with `ifup eth0`;
- after every change to a configuration file, **restart the service** and check in the
  journal that it did start;
- the evaluation queries the servers as they are running when it is launched: a server stopped
  for a test must be restarted.
- The virtual network behaves like a **hub**: a capture on any machine shows **every** frame
  of its network, including the unicast exchanges between other machines (for example between
  the relay and a server);
- At every evaluation, a probe sends a few test DHCP requests on `lan1` and `lan2`. They come
  from MAC addresses starting with `02:53:52` with the hostname `sonde`, or reuse the MAC
  address of `m2` or of `m4`. You will see them in the journals and in the captures; they are
  never followed by a `DHCPREQUEST`, so no lease is recorded.
- The parts must be done **in order**.
""",
        """
**Baux accordés.**

- état (`binding state`) du bail de `m1` dans `dhcpd.leases` :
  @@{state:>abandoned|active|backup|expired|free}@@
- sur `m1`, ajoutez la ligne `send dhcp-lease-time 86400;` à `/etc/dhcp/dhclient.conf` puis
  redemandez un bail (`ifdown eth0` puis `ifup eth0`). Durée du bail obtenu, en secondes :
  @@{asked:[0-9]+}@@
""": """
**Leases granted.**

- state (`binding state`) of the lease of `m1` in `dhcpd.leases`:
  @@{state:>abandoned|active|backup|expired|free}@@
- on `m1`, add the line `send dhcp-lease-time 86400;` to `/etc/dhcp/dhclient.conf` then
  request a lease again (`ifdown eth0` then `ifup eth0`). Duration of the lease obtained, in
  seconds: @@{asked:[0-9]+}@@
""",
        """
**Deux serveurs.**

- nombre de `DHCPOFFER` reçus par `m1` quand les deux serveurs tournent (avant la mise en
  place du relais de la partie 6) : @@{offers:[0-9]+}@@
- le serveur dont l'offre n'est pas retenue l'apprend :
  @@{refusal:>en recevant un DHCPDECLINE|en recevant un DHCPNAK|en recevant le DHCPREQUEST diffusé|jamais}@@
- si les deux plages dynamiques avaient des adresses communes :
  @@{overlap:>dhcpd refuserait de démarrer|deux machines pourraient recevoir la même adresse|les serveurs se synchroniseraient}@@
""": """
**Two servers.**

- number of `DHCPOFFER`s received by `m1` when both servers are running (before the relay of
  part 6 is set up): @@{offers:[0-9]+}@@
- the server whose offer is not kept learns it:
  @@{refusal:>by receiving a DHCPDECLINE|by receiving a DHCPNAK|by receiving the broadcast DHCPREQUEST|never}@@
- if the two dynamic ranges had addresses in common:
  @@{overlap:>dhcpd would refuse to start|two machines could receive the same address|the servers would synchronise}@@
""",
        """
**Failover.**

- durée en secondes du **premier** bail accordé à `m3` après la mise en place du failover :
  @@{first_lease:[0-9]+}@@
- nombre de serveurs **différents** qui répondent au `DHCPDISCOVER` de `m3` quand les deux
  sont en état `normal` : @@{responders:>0|1|2}@@
""": """
**Failover.**

- duration in seconds of the **first** lease granted to `m3` after the failover was set up:
  @@{first_lease:[0-9]+}@@
- number of **different** servers that answer the `DHCPDISCOVER` of `m3` when both are in the
  `normal` state: @@{responders:>0|1|2}@@
""",
        """
**Le bail obtenu par m0.** D'après le fichier de baux de `m0` :

- adresse IP du serveur DHCP (`dhcp-server-identifier`) : @@{server:[0-9.]+}@@
- durée du bail en secondes : @@{lease:[0-9]+}@@
- routeur par défaut : @@{router:[0-9.]+}@@ ; serveur DNS : @@{dns:[0-9.]+}@@
- nom de domaine : @@{domain:[a-zA-Z0-9.-]+}@@
""": """
**The lease obtained by m0.** According to the lease file of `m0`:

- IP address of the DHCP server (`dhcp-server-identifier`): @@{server:[0-9.]+}@@
- lease time in seconds: @@{lease:[0-9]+}@@
- default router: @@{router:[0-9.]+}@@; DNS server: @@{dns:[0-9.]+}@@
- domain name: @@{domain:[a-zA-Z0-9.-]+}@@
""",
        """
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
""": """
**The DHCP messages.** According to the capture on `m0`:

- UDP port of the server: @@{port_server:[0-9]+}@@; UDP port of the client: @@{port_client:[0-9]+}@@
- `DHCPDISCOVER`: source IP address @@{disc_src:[0-9.]+}@@, destination IP address
  @@{disc_dst:[0-9.]+}@@, destination MAC address @@{disc_mac:[0-9a-fA-F:]+}@@
- order of the four messages when obtaining a lease:
  @@{msg1:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ then
  @@{msg2:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ then
  @@{msg3:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@ then
  @@{msg4:>DHCPACK|DHCPDISCOVER|DHCPOFFER|DHCPREQUEST}@@
- message sent by `dhclient -r`: @@{release:>DHCPDECLINE|DHCPINFORM|DHCPNAK|DHCPRELEASE}@@
- on a renewal, the client sends a
  @@{renew_msg:>DHCPDISCOVER|DHCPINFORM|DHCPREQUEST}@@ which is
  @@{renew_dst:>broadcast on the network|sent in unicast to the server}@@
""",
        """
**Messages relayés.**

- valeur du champ `giaddr` (`Gateway-IP`) des messages relayés pour `m3` : @@{giaddr:[0-9.]+}@@
- adresse IP **source** du `DHCPOFFER` tel que `m3` le reçoit : @@{offer_src:[0-9.]+}@@
- adresse du serveur DHCP enregistrée dans le bail de `m3` (`dhcp-server-identifier`) :
  @@{server:[0-9.]+}@@
- `srv1` choisit le réseau (`subnet`) dans lequel prendre l'adresse d'après :
  @@{choice:>l'adresse MAC du client|l'interface de réception|le champ giaddr|le nom du client}@@
""": """
**Relayed messages.**

- value of the `giaddr` field (`Gateway-IP`) of the messages relayed for `m3`: @@{giaddr:[0-9.]+}@@
- **source** IP address of the `DHCPOFFER` as `m3` receives it: @@{offer_src:[0-9.]+}@@
- address of the DHCP server recorded in the lease of `m3` (`dhcp-server-identifier`):
  @@{server:[0-9.]+}@@
- `srv1` chooses the network (`subnet`) to take the address from according to:
  @@{choice:>the client's MAC address|the receiving interface|the giaddr field|the client's name}@@
""",
        """
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
""": """
**For the instructor.** Each question ends with its solution, computed for the addresses of
this project.

- The `final` state (*Apply Configuration* tab) applies the whole solution and fills in the
  forms. It erases the leases of the servers and requests those of the clients again: wait
  about ten seconds, the time for the failover to reach the `normal` state, before launching an
  evaluation.
- The evaluation bears on the behaviour of the servers: the hidden machine `sonde`, attached
  to `lan1` and `lan2`, sends test requests and what each server answers it is recorded, the
  server being recognised by its `dhcp-server-identifier`. The form of the `dhcpd.conf` files
  is therefore free (only part 7 looks for `failover peer` in them).
- Also read: the command line of the `dhcpd` and `dhcrelay` processes, the failover state in
  `dhcpd.leases`, and on each client the address, the default route, the `dhclient` leases and
  `/etc/network/interfaces`.
- A client only counts if its address comes from DHCP (marked `dynamic` in `ip a` and recorded
  in a `/var/lib/dhcp/dhclient*.leases` file) and if it has a single default route, to the
  router of its network: an address added with `ip addr add` earns nothing.
- Persistent configuration of a client: `iface eth0 inet dhcp` in `/etc/network/interfaces`; a
  file of `/etc/network/interfaces.d/` is only read if `/etc/network/interfaces` contains the
  line `source /etc/network/interfaces.d/*`.
""",
        """
**Routes reçues.**

- valeur de l'option `rfc3442-classless-static-routes` dans le bail de `m1` (les nombres,
  séparés par des virgules) : @@{option:[0-9, ]+}@@
- à l'essai du point 4, `m1` :
  @@{no_default:>garde sa route par défaut|n'a plus de route par défaut}@@
""": """
**Routes received.**

- value of the option `rfc3442-classless-static-routes` in the lease of `m1` (the numbers,
  separated by commas): @@{option:[0-9, ]+}@@
- in the experiment of step 4, `m1`:
  @@{no_default:>keeps its default route|no longer has a default route}@@
""",
        """
**Réponses.**

- `giaddr` : `{giaddr}`, l'adresse de `r1` sur `lan2`
- adresse source de l'offre : `{offer_src}`, c'est le relais qui la remet à `m3`
- serveur inscrit dans le bail : `{server}` (`srv1` ; l'adresse de `srv2` est acceptée aussi, pour une
  réponse donnée après la partie 7)
- `srv1` choisit le réseau d'après {choice}
""": """
**Answers.**

- `giaddr`: `{giaddr}`, the address of `r1` on `lan2`
- source address of the offer: `{offer_src}`, the relay is what hands it to `m3`
- server recorded in the lease: `{server}` (`srv1`; the address of `srv2` is accepted too, for
  an answer given after part 7)
- `srv1` chooses the network according to {choice}
""",
        """
**Réponses.**

- ports UDP : `{port_server}` (serveur) et `{port_client}` (client)
- `DHCPDISCOVER` : de `{disc_src}` vers `{disc_dst}`, adresse MAC destination `{disc_mac}`
- ordre des messages : `{msg1}`, `{msg2}`, `{msg3}`, `{msg4}`
- `dhclient -r` émet un `{release}`
- renouvellement : un `{renew_msg}` {renew_dst}
""": """
**Answers.**

- UDP ports: `{port_server}` (server) and `{port_client}` (client)
- `DHCPDISCOVER`: from `{disc_src}` to `{disc_dst}`, destination MAC address `{disc_mac}`
- order of the messages: `{msg1}`, `{msg2}`, `{msg3}`, `{msg4}`
- `dhclient -r` sends a `{release}`
- renewal: a `{renew_msg}` {renew_dst}
""",
        """
**Réponses.**

- serveur DHCP : `{server}` (`srv0`)
- durée du bail : `{lease}` s
- routeur : `{router}` (`r1`) ; serveur DNS : `{dns}` (`srv0`)
- nom de domaine : `{domain}`
""": """
**Answers.**

- DHCP server: `{server}` (`srv0`)
- lease time: `{lease}` s
- router: `{router}` (`r1`); DNS server: `{dns}` (`srv0`)
- domain name: `{domain}`
""",
        """
**Réponses.** `{offers}` offres, une par serveur ; `{refusal}` ; `{overlap}`.

Une fois le relais de la partie 6 à l'écoute sur `eth1`, il relaie aussi les diffusions de `lan1` : `m1`
reçoit alors des offres supplémentaires (`giaddr` = `{giaddr}`), d'où la précision de la question.
""": """
**Answers.** `{offers}` offers, one per server; `{refusal}`; `{overlap}`.

Once the relay of part 6 listens on `eth1`, it also relays the broadcasts of `lan1`: `m1` then
receives extra offers (`giaddr` = `{giaddr}`), hence the wording of the question.
""",
        """
**Réponses.** adresse MAC `{mac}` ; `{in_leases}` : `dhcpd` n'inscrit rien dans `dhcpd.leases` pour une
adresse fixe.
""": """
**Answers.** MAC address `{mac}`; `{in_leases}`: `dhcpd` writes nothing in `dhcpd.leases` for a
fixed address.
""",
        """
**Réponses.** option `{option}` (les deux routes, dans n'importe quel ordre) ; à l'essai, `m1`
{no_default}.
""": """
**Answers.** option `{option}` (the two routes, in any order); in the experiment, `m1`
{no_default}.
""",
        """
**Réponses.** premier bail de `{first_lease}` s, le MCLT ; `{responders}` seul serveur répond à `m3`.
""": """
**Answers.** first lease of `{first_lease}` s, the MCLT; `{responders}` single server answers `m3`.
""",
        """
**Réponses.** état `{state}` ; bail de `{asked}` s : le serveur ramène les 86400 s demandées à son
`max-lease-time`.
""": """
**Answers.** state `{state}`; lease of `{asked}` s: the server brings the 86400 s requested
down to its `max-lease-time`.
""",
        """
**Réservation.**

- adresse MAC de `m2` : @@{mac:[0-9a-fA-F:]+}@@
- le bail de `m2` est-il enregistré dans `dhcpd.leases` ? @@{in_leases:>non|oui}@@
""": """
**Reservation.**

- MAC address of `m2`: @@{mac:[0-9a-fA-F:]+}@@
- is the lease of `m2` recorded in `dhcpd.leases`? @@{in_leases:>no|yes}@@
""",
        """
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
""": """
**Solution.** In `/etc/dhcp/dhcpd.conf` on `srv1`, declare the option once, outside any block,
then give it its value in the `subnet` of `lan1`:

```
{declaration}

{subnet}
```

then `systemctl restart isc-dhcp-server`, and `ifdown eth0` then `ifup eth0` on `m1` and `m2`.
`ip route` on `m1` then shows, among others:

```
default via {r1} dev eth0
{lan3} via {r2} dev eth0
```

- Encoding of the option: for each route, the prefix length, the significant bytes of the
  network, then the four bytes of the router; `0` followed by a router is the default route.
- Without the declaration, `dhcpd` does not start (`unknown option dhcp.rfc3442-classless-static-routes`).
  The name given to the option is free: the code 121 is what counts.
- A client that receives option 121 ignores the `routers` option: in the experiment of step 4,
  `m1` has no default route any more (`ping srv0` fails), although `routers` is still sent.
- `dhclient` only installs these routes when it obtains a lease, not on its renewal: hence
  `ifdown` then `ifup` after every change on the server.
- Written outside the `subnet` of `lan1`, the option would also be sent to the clients of `lan2`
  (part 6), which would lose their default route: the routers it names are not on their network.
- Evaluation: the probe reads option 121 in the offers of `srv1`. On `m1` and `m2`, the route
  must be installed **and** appear in the lease: a route added with `ip route add` does not count.
""",
        """
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
""": """
**Solution.** The MAC address of `m2` (`ip link show eth0` on `m2`) is `{mac}`. To add to
`/etc/dhcp/dhcpd.conf` on `srv1`:

```
{host}
```

then `systemctl restart isc-dhcp-server`. On `m2`: `/etc/network/interfaces` as on `m0`, then
`ifup eth0`.

- The offer made to `m2` is immediate; the one made to `m1` follows its `DHCPDISCOVER` by about
  one second, the time for `dhcpd` to check with a `ping` that the dynamic address is free.
- A fixed address is never written in `dhcpd.leases`.
- Evaluation: the probe shows up with the MAC address of `m2`, and `srv1` must offer it `{m2}`.
""",
        """
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
""": """
**Solution.** On `m0`:

```
dhclient -v eth0       # DHCPDISCOVER, DHCPOFFER, DHCPREQUEST, DHCPACK
dhclient -r -v eth0    # DHCPRELEASE
```

then, in `/etc/network/interfaces`:

```
{interfaces}
```

and `ifup eth0`.

- `srv0` gives `m0` an address from `{pool_min}` to `{pool_max}`, the default route `{router}`,
  the DNS server `{dns}` and the domain `{domain}`: `ping srv1` then works (name resolved by
  `srv0`, packets routed by `r1`).
- The lease lasts {lease} s: a renewal (`DHCPREQUEST` then `DHCPACK`, both in unicast) can be
  observed at the latest at half the lease, i.e. after {renewal} s.
""",
        """
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
""": """
**Solution.** On `srv1`, `/etc/default/isc-dhcp-server`:

```
{defaults}
```

`/etc/dhcp/dhcpd.conf`:

```
{conf}
```

then:

```
dhcpd -t -cf /etc/dhcp/dhcpd.conf
systemctl restart isc-dhcp-server
journalctl -u isc-dhcp-server -n 20
```

On `m1`: `/etc/network/interfaces` as on `m0`, then `ifup eth0`.

- The probe must receive from `srv1` an offer in the range, with the mask, the router, the DNS
  server, the domain and a lease of {default_lease} s. It then asks for a very long lease,
  which must be brought down to {max_lease} s. `authoritative` is checked by the `DHCPNAK`
  returned to the request of an address foreign to the network.
- Listening interface: the command line of the process is what is read (`ps -C dhcpd -o args`
  must name `eth0` only). With `INTERFACESv4` empty, the service is failed but a `dhcpd` runs
  on every interface, and `systemctl restart` does not replace it: `pkill dhcpd`, then restart.
- `m1` may hold its address from `srv1` or, from part 5 on, from `srv2`.
""",
        """
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
""": """
**Solution.** On `srv2`, `/etc/default/isc-dhcp-server` as on `srv1`, and `/etc/dhcp/dhcpd.conf`,
the one of `srv1` except for the range:

```
{conf}
```

then `systemctl restart isc-dhcp-server`.

- Capture on `m1`: two `DHCPOFFER`s, one per server, each in its own range. The `DHCPREQUEST`,
  broadcast, names the chosen server through option 54 (`Server-ID` in `tcpdump`): the other
  server reads there that its offer was not kept.
- With `srv1` stopped, `srv2` answers alone: `m1` receives an address from `{b_min}` to
  `{b_max}`, and `m2` keeps `{m2}` since the reservation is declared on both servers.
- The evaluation queries both servers: a `srv1` left stopped loses all its points.
- Without option 121 on `srv2`, a machine that holds its lease from `srv2` no longer has the
  route to `lan3`: the points of `m1` and `m2` in part 4 then depend on the server that
  answered them.
""",
        """
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
""": """
**Solution.** `/etc/dhcp/dhcpd.conf` of `srv1` (primary):

```
{conf1}
```

and of `srv2` (secondary):

```
{conf2}
```

then `systemctl restart isc-dhcp-server` on both servers. On `r1`, `/etc/default/isc-dhcp-relay`:

```
{relay}
```

then `systemctl restart isc-dhcp-relay`.

- Starting from empty lease files (which is what the `final` state does), the two servers are
  in the `normal` state within a few seconds. The evaluation reads that state in `dhcpd.leases`
  (`failover peer "{failover}" state`) and requires `dhcpd.conf` to hold at least two
  `failover peer` lines: the declaration and the `pool`.
- First lease of `m3`: {mclt} s, the MCLT; from the first renewal on, {default_lease} s.
- In the `normal` state, a single server answers a given client, chosen from its MAC address.
  The probe announces a `secs` field greater than `load balance max seconds`: both servers
  answer it, each with an address of its share of the range and a lease of {mclt} s.
- The configuration of `lan1` does not change: parts 2 to 6 keep their points.
""",
        """
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
""": """
**Solution.** To add to `/etc/dhcp/dhcpd.conf` on `srv1`:

```
{conf}
```

then `systemctl restart isc-dhcp-server`. On `r1`, `/etc/default/isc-dhcp-relay`:

```
{relay}
```

then `systemctl restart isc-dhcp-relay` and `ps -C dhcrelay -o pid,args`. On `m3` and `m4`:
`/etc/network/interfaces` as on `m0`, then `ifup eth0`.

- The relay listens on `eth2` (the clients) **and** on `eth1` (the answers of `srv1`).
  `INTERFACES=""` alone (every interface) or with `OPTIONS="-id eth2 -iu eth1"` also work;
  with `INTERFACES="eth2"`, the requests leave but the answers are lost.
- Evaluation of the relay: a `dhcrelay` process started towards the address `{srv1}` (a name in
  `SERVERS` is not recognised), no `dhcpd` on `r1`, and on `lan2` an offer of `srv1` carrying
  `giaddr` = `{giaddr}`.
- Journal of `srv1`: a relayed request is recorded `via {giaddr}` instead of `via eth0`.
- `srv1` already reaches `lan2` through its default route (`r1`): no route to add.
""",
        """
Ce TP met en œuvre **DHCP** (*Dynamic Host Configuration Protocol*,
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131), 1997) avec les
logiciels de l'**ISC** fournis par Debian : le client `dhclient`, le serveur `dhcpd` (paquet
`isc-dhcp-server`) et le relais `dhcrelay` (paquet `isc-dhcp-relay`).

Le routeur `r1` relie les réseaux `lan0`, `lan1` et `lan2`. Un second routeur, `r2`, relie
`lan1` à `lan3` ; `r1` ne connaît pas `lan3` :
""": """
This lab uses **DHCP** (*Dynamic Host Configuration Protocol*,
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131), 1997) with the **ISC** software shipped
by Debian: the client `dhclient`, the server `dhcpd` (package `isc-dhcp-server`) and the relay
`dhcrelay` (package `isc-dhcp-relay`).

The router `r1` connects the networks `lan0`, `lan1` and `lan2`. A second router, `r2`,
connects `lan1` to `lan3`; `r1` does not know `lan3`:
""",
        """
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
""": """
Configure `dhcpd` on `srv1` for the network `lan1` (`{lan1}`):

- listening on the interface `eth0` **only**;
- dynamic range from `{a_min}` to `{a_max}`;
- default router `{router}`, DNS server `{dns}`, domain name `{domain}`;
- default lease time **{default_lease} s**, maximum lease time **{max_lease} s**;
- `authoritative` server.
""",
        """
La machine `m2` doit toujours recevoir l'adresse **`{m2}`** (en dehors de la plage dynamique).

1. relevez l'adresse MAC de l'interface `eth0` de `m2` ;
2. sur `srv1`, déclarez la réservation correspondante puis relancez le service ;
3. sur `m2` : configuration persistante, `ifup eth0`, vérifications ;
4. sur `srv1`, comparez les lignes du journal pour `m1` et pour `m2`, et cherchez `m2` dans
   `/var/lib/dhcp/dhcpd.leases`.
""": """
The machine `m2` must always receive the address **`{m2}`** (outside the dynamic range).

1. note the MAC address of the interface `eth0` of `m2`;
2. on `srv1`, declare the corresponding reservation then restart the service;
3. on `m2`: persistent configuration, `ifup eth0`, checks;
4. on `srv1`, compare the journal lines for `m1` and for `m2`, and look for `m2` in
   `/var/lib/dhcp/dhcpd.leases`.
""",
        """
Le réseau `lan1` a un second routeur, `r2` (`{r2}`), qui mène au réseau `lan3` (`{lan3}`) où se
trouve le serveur `srv3`. Le routeur `r1` ne connaît pas `lan3` : avec leur seule route par
défaut, les machines de `lan1` ne peuvent pas joindre `srv3` (essayez `ping srv3` sur `m1`).

Un serveur DHCP peut distribuer d'autres routes que la route par défaut, par l'option 121
(voir l'onglet Informations, section @@ref:routes@@) :

1. sur `srv1`, faites distribuer aux clients de `lan1`, et à eux seuls, la route vers `{lan3}`
   par `{r2}`, **en plus** de la route par défaut par `{r1}`, puis relancez le service ;
2. redemandez un bail sur `m1` et sur `m2` (`ifdown eth0` puis `ifup eth0`) ;
3. vérifiez sur `m1` : `ip route`, `ping srv3`, `ping srv0`, et retrouvez l'option dans le
   fichier de baux ;
4. essai : retirez la route par défaut de l'option 121 (en laissant `option routers`),
   relancez le service, redemandez un bail sur `m1` et regardez `ip route`. **Rétablissez
   ensuite la configuration du point 1** et redemandez un bail sur `m1`.
""": """
The network `lan1` has a second router, `r2` (`{r2}`), which leads to the network `lan3`
(`{lan3}`) where the server `srv3` is. The router `r1` does not know `lan3`: with their default
route alone, the machines of `lan1` cannot reach `srv3` (try `ping srv3` on `m1`).

A DHCP server can distribute other routes than the default route, through option 121 (see the
Informations tab, section @@ref:routes@@):

1. on `srv1`, have the route to `{lan3}` via `{r2}` distributed to the clients of `lan1`, and
   to them only, **in addition to** the default route via `{r1}`, then restart the service;
2. request a lease again on `m1` and on `m2` (`ifdown eth0` then `ifup eth0`);
3. check on `m1`: `ip route`, `ping srv3`, `ping srv0`, and find the option in the lease file;
4. experiment: remove the default route from option 121 (keeping `option routers`), restart
   the service, request a lease again on `m1` and look at `ip route`. **Then restore the
   configuration of step 1** and request a lease again on `m1`.
""",
        """
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
""": """
The network `lan2` (`{lan2}`) has no DHCP server. Try `dhclient -v eth0` on `m3` while
capturing on `m3` then on `m1`: the broadcasts of `m3` do not leave `lan2` (interrupt
`dhclient` with Ctrl-C then stop it completely with `dhclient -r eth0`).
`srv1` will serve `lan2`, through a relay installed on `r1`:

1. on `srv1`, add the network `lan2`: dynamic range from `{c_min}` to `{c_max}`, default
   router `{router}`, and a reservation always giving **`{m4}`** to `m4`;
2. on `r1`, configure and start the relay `isc-dhcp-relay` towards `srv1` (`{srv1}`). `r1`
   must not become a DHCP server;
3. on `m3` and `m4`: persistent configuration, `ifup eth0`, checks (`ping srv0`).

Watch the whole exchange: capture on `m3` (client side) and capture on `m1` or `srv1` (server
side: `lan1` shows the messages exchanged between `r1` and `srv1`). Spot the `Gateway-IP`
field and look in the journal of `srv1` at how the request is recorded.
The journal of `srv2` reports these same requests with `unknown network segment`: because of
the hub it sees the messages meant for `srv1` go by, but it does not know `lan2`.
""",
        """
Le serveur `srv0` est **déjà configuré** : il est serveur DHCP pour `lan0` et serveur DNS du
domaine `tp-dhcp.lan` (vous ne pouvez pas vous y connecter). Le routeur `r2` et le serveur
`srv3` sont eux aussi déjà configurés, et vous ne pouvez pas non plus vous y connecter. Les
serveurs `srv1` et `srv2` et le routeur `r1` ont leur configuration IP statique mais aucun
service DHCP. Les machines `m0` à `m4` n'ont **aucune** configuration réseau : ni adresse, ni
route, ni serveur DNS.

Les noms `srv0` à `srv3`, `r1`, `r2`, `m2` et `m4` ne sont connus que du serveur DNS `srv0` :
un client ne peut donc les utiliser (`ping srv1`) qu'après avoir été configuré par DHCP.
""": """
The server `srv0` is **already configured**: it is the DHCP server of `lan0` and the DNS server
of the domain `tp-dhcp.lan` (you cannot log in to it). The router `r2` and the server `srv3`
are also already configured, and you cannot log in to them either. The servers `srv1` and
`srv2` and the router `r1` have their static IP configuration but no DHCP service. The
machines `m0` to `m4` have **no** network configuration at all: no address, no route, no DNS
server.

The names `srv0` to `srv3`, `r1`, `r2`, `m2` and `m4` are only known to the DNS server `srv0`:
a client can therefore only use them (`ping srv1`) once it has been configured by DHCP.
""",
        """
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
""": """
So that `lan1` stays served if `srv1` fails, configure `srv2` as a second DHCP server,
**independent**, on the same network:

- same parameters as `srv1` (interface, router, routes of option 121, DNS, domain, lease
  times, `authoritative`);
- dynamic range from `{b_min}` to `{b_max}`: it has no address in common with that of `srv1`,
  which stays unchanged;
- same reservation for `m2`.

Observations, with a capture on `m1`:

1. request a lease again on `m1` (`ifdown eth0` then `ifup eth0`) and count the `DHCPOFFER`s;
   spot in the `DHCPREQUEST` the option that names the chosen server;
2. stop `dhcpd` on `srv1` (`systemctl stop isc-dhcp-server`), request a lease again on `m1`
   then on `m2`: who answers? which addresses do they get?
3. **restart `dhcpd` on `srv1`**.
""",
        """
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
""": """
On `m0` (network `lan0`, server `srv0`):

1. check with `ip a`, `ip route` and `cat /etc/resolv.conf` that nothing is configured;
2. in a second terminal on `m0`, start the capture
   `tcpdump -n -e -v -i eth0 port 67 or port 68` and let it run;
3. request a lease with `dhclient -v eth0`. Repeat the checks of step 1, try `ping srv1`, and
   read the lease recorded in `/var/lib/dhcp/dhclient.leases`;
4. release the lease with `dhclient -r -v eth0` and watch the message sent;
5. make the configuration **persistent** (`/etc/network/interfaces`) and bring it up with
   `ifup eth0`;
6. let the capture run for a few minutes to observe a **renewal** of the lease.
""",
        """
`lan2` ne dépend encore que de `srv1`. Plutôt que de découper sa plage, faites
partager **la même plage** (`{c_min}` à `{c_max}`) à `srv1` et `srv2` par le protocole
**failover** (voir l'onglet Informations, section @@ref:servers@@) :

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
""": """
`lan2` still depends on `srv1` alone. Rather than splitting its range, have `srv1` and `srv2`
share **the same range** (`{c_min}` to `{c_max}`) through the **failover** protocol (see the
Informations tab, section @@ref:servers@@):

1. on `srv1` (**primary**) and `srv2` (**secondary**), declare the `failover peer`
   relationship with port 647 on both sides, `load balance max seconds 3`, and on the primary
   `mclt {mclt}` and `split 128`;
2. on both servers, declare the network `lan2` with the range placed in a `pool` attached to
   that relationship, the router `{router}` and the reservation of `m4`. The configuration of
   `lan1` (disjoint ranges) does not change;
3. restart both servers and wait for `Both servers normal` in their journals;
4. on `r1`, forward the requests to **both** servers (in this lab `srv2` already sees the
   requests relayed to `srv1` go by, because of the hub; on a real switched network it would
   only receive them thanks to this configuration).

Experiments: request a lease again on `m3` (`ifdown eth0` then `ifup eth0`) while capturing
on `m3`, note the lease time, then the one obtained at the first renewal. Stop `srv1` and
check that `m3` still obtains an address; **restart `srv1`**.
""",
        """**Sommaire**
""": """**Contents**
""",
        'Adresse fixe pour m2': 'Fixed address for m2',
        'Capturer les échanges de trames': 'Capturing the frames',
        'Client DHCP et observation du protocole': 'DHCP client and protocol observation',
        'DHCP (Dynamic Host Configuration Protocol)': 'DHCP (Dynamic Host Configuration Protocol)',
        "Distribuer d'autres routes statiques": 'Distributing other static routes',
        'Failover pour lan2': 'Failover for lan2',
        'Introduction': 'Introduction',
        "La vie d'un bail": 'The life of a lease',
        'Le client : dhclient et ifupdown': 'The client: dhclient and ifupdown',
        'Le format des messages et les options': 'Message format and options',
        'Le relais DHCP': 'The DHCP relay',
        'Le serveur : dhcpd': 'The server: dhcpd',
        "Obtention d'un bail": 'Obtaining a lease',
        'Organisation du TP': 'Organisation of the lab',
        'Partie 1 — Client DHCP et observation du protocole': 'Part 1 — DHCP client and protocol observation',
        'Partie 2 — Serveur DHCP sur srv1': 'Part 2 — DHCP server on srv1',
        'Partie 3 — Adresse fixe pour m2': 'Part 3 — Fixed address for m2',
        'Partie 4 — Routes distribuées par DHCP': 'Part 4 — Routes distributed by DHCP',
        'Partie 5 — Second serveur DHCP sur lan1': 'Part 5 — Second DHCP server on lan1',
        'Partie 6 — Relais DHCP pour lan2': 'Part 6 — DHCP relay for lan2',
        'Partie 7 — Failover pour lan2': 'Part 7 — Failover for lan2',
        'Plusieurs serveurs sur un même réseau': 'Several servers on the same network',
        'Relais DHCP pour lan2': 'DHCP relay for lan2',
        'Routes distribuées par DHCP': 'Routes distributed by DHCP',
        'Second serveur DHCP sur lan1': 'Second DHCP server on lan1',
        'Serveur DHCP sur srv1': 'DHCP server on srv1',
        'Sécurité': 'Security',
        'adresse MAC de m2 et absence de bail enregistré': 'MAC address of m2 and absence of a recorded lease',
        'adresse proposée par srv1 dans la plage {a_min} – {a_max}': 'address offered by srv1 within the range {a_min} – {a_max}',
        'adresse proposée sur lan2 dans la plage {c_min} – {c_max}': 'address offered on lan2 within the range {c_min} – {c_max}',
        "adresses IP et MAC d'un DHCPDISCOVER": 'IP and MAC addresses of a DHCPDISCOVER',
        'configuration persistante de m0': 'persistent configuration of m0',
        'configuration persistante de m2': 'persistent configuration of m2',
        'configuration persistante de m3 et m4': 'persistent configuration of m3 and m4',
        'dhcpd de srv1 lancé sur eth0 uniquement': 'dhcpd of srv1 started on eth0 only',
        'dhcpd tourne sur srv1': 'dhcpd is running on srv1',
        'dhcpd tourne sur srv2, sur eth0 uniquement': 'dhcpd is running on srv2, on eth0 only',
        "dhcrelay tourne sur r1 vers srv1 (et r1 n'est pas serveur DHCP)": 'dhcrelay is running on r1 towards srv1 (and r1 is not a DHCP server)',
        'durée de bail maximale de srv1': 'maximum lease time of srv1',
        'durée de bail par défaut de srv1': 'default lease time of srv1',
        'durée du premier bail et nombre de serveurs qui répondent': 'duration of the first lease and number of servers that answer',
        "durée obtenue quand le client demande un bail d'un jour": 'duration obtained when the client asks for a one-day lease',
        "effet d'une option 121 sans route par défaut": 'effect of an option 121 without a default route',
        "giaddr et adresse source de l'offre reçue par m3": 'giaddr and source address of the offer received by m3',
        'identifiant du serveur dans le bail de m3 et choix du réseau par le serveur': 'server identifier in the lease of m3 and choice of the network by the server',
        'identifiant du serveur et durée du bail de m0': 'server identifier and lease time of m0',
        "l'option 121 de srv1 contient aussi la route par défaut": 'option 121 of srv1 also holds the default route',
        'le relais fait suivre les demandes à srv1 et à srv2': 'the relay forwards the requests to srv1 and to srv2',
        "libération et renouvellement d'un bail": 'release and renewal of a lease',
        'm0 a obtenu son adresse et sa route par défaut par DHCP': 'm0 obtained its address and its default route by DHCP',
        'm0 résout le nom srv1': 'm0 resolves the name srv1',
        'm1 (configuration persistante) joint srv0 et résout son nom': 'm1 (persistent configuration) reaches srv0 and resolves its name',
        'm1 a obtenu par DHCP une adresse dynamique de lan1 et sa route par défaut': 'm1 obtained by DHCP a dynamic address of lan1 and its default route',
        'm1 a reçu par DHCP la route vers lan3 et garde sa route par défaut': 'm1 received by DHCP the route to lan3 and keeps its default route',
        'm1 joint srv3': 'm1 reaches srv3',
        'm2 (adresse fixe) a reçu les mêmes routes': 'm2 (fixed address) received the same routes',
        'm2 a obtenu {m2} par DHCP': 'm2 obtained {m2} by DHCP',
        'm3 a obtenu par DHCP une adresse dynamique de lan2 et sa route par défaut': 'm3 obtained by DHCP a dynamic address of lan2 and its default route',
        'm3 joint srv0 et résout son nom': 'm3 reaches srv0 and resolves its name',
        'm4 a obtenu {m4} par DHCP': 'm4 obtained {m4} by DHCP',
        'masque et routeur par défaut proposés par srv1': 'mask and default router offered by srv1',
        'masque et routeur par défaut proposés sur lan2': 'mask and default router offered on lan2',
        'nom de domaine proposé par srv1': 'domain name offered by srv1',
        "nombre d'offres reçues par m1": 'number of offers received by m1',
        'offre non retenue et risque des plages communes': 'offer not kept and risk of overlapping ranges',
        'ordre des quatre messages': 'order of the four messages',
        'ports UDP du serveur et du client': 'UDP ports of the server and of the client',
        'relation failover déclarée et en état normal sur srv1 et srv2': 'failover relationship declared and in the normal state on srv1 and srv2',
        'routeur, serveur DNS et domaine reçus par m0': 'router, DNS server and domain received by m0',
        'serveur DNS proposé par srv1': 'DNS server offered by srv1',
        'srv1 distribue la route vers lan3 par r2 (option 121)': 'srv1 distributes the route to lan3 via r2 (option 121)',
        'srv1 et srv2 servent la plage de lan2 en failover (bail limité au MCLT)': 'srv1 and srv2 serve the range of lan2 in failover (lease limited to the MCLT)',
        "srv1 propose {m2} à l'adresse MAC de m2": 'srv1 offers {m2} to the MAC address of m2',
        "srv1 propose {m4} à l'adresse MAC de m4": 'srv1 offers {m4} to the MAC address of m4',
        'srv1 refuse (DHCPNAK) une adresse étrangère au réseau': 'srv1 refuses (DHCPNAK) an address foreign to the network',
        'srv1 répond sur lan2 à travers le relais (giaddr {giaddr})': 'srv1 answers on lan2 through the relay (giaddr {giaddr})',
        'srv1 répond à un DHCPDISCOVER sur lan1': 'srv1 answers a DHCPDISCOVER on lan1',
        'srv2 distribue les mêmes routes que srv1 (option 121)': 'srv2 distributes the same routes as srv1 (option 121)',
        "srv2 propose aussi {m2} à l'adresse MAC de m2": 'srv2 also offers {m2} to the MAC address of m2',
        "srv2 propose aussi {m4} à l'adresse MAC de m4": 'srv2 also offers {m4} to the MAC address of m4',
        'srv2 propose les mêmes options et durées de bail que srv1': 'srv2 offers the same options and lease times as srv1',
        'srv2 propose une adresse de la plage {b_min} – {b_max}': 'srv2 offers an address of the range {b_min} – {b_max}',
        'srv2 refuse (DHCPNAK) une adresse étrangère au réseau': 'srv2 refuses (DHCPNAK) an address foreign to the network',
        "valeur de l'option 121 dans le bail de m1": 'value of option 121 in the lease of m1',
        'état du bail de m1 dans dhcpd.leases': 'state of the lease of m1 in dhcpd.leases',
    },
}
