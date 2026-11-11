"""TP VRRP : redondance de la passerelle avec keepalived.

Two routers (r1, r2) between a LAN (pc1, pc2) and the WAN of a provider router (isp).  The
students build, with keepalived: a virtual gateway on the LAN, a virtual address on the WAN tied
to it by a sync group, a health check and a notify script, authentication and unicast peers, a
second virtual router for load sharing, a virtual MAC and a VRRPv3 / IPv6 virtual gateway.

Grading by "hidden mirror" (``lib/hidden_mirror.py``): the whole topology is cloned (suffix
``_h``, same addresses, same interface numbers).  At each evaluation the content of
``/etc/keepalived`` and ``/etc/radvd.conf`` of r1 and r2 is replayed on r1_h and r2_h, then the
failures (a link down, a dead upstream, forged adverts) are injected on the clones only and
observed from pc1_h, pc2_h and isp_h: the students' routers are never touched.

Texts: the Informations tab is a course, independent of the instance; the addressing, the values
of the instance and the rules of the evaluation are in the question "Organisation du TP"; every
question ends with its solution in an instructor-only block.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, ip_address
from typing import Dict

import hidden_mirror
from SRE import params
from SRE.lib_sre import Data0, Grade0, NetScheme0, info_subtitle, info_toc, instructor, make_tr, no_tr, sre_state
from SRE.params import sre_docker_image
from arp import arp_query_cmd, get_neigh, install_arp_probe, neigh_lladdr, parse_arp_probe
from bridging import get_ip_links, links_by_name, normalize_mac
from ips import random_ipv4networks, random_ipv6networks, random_mac_address
from ipv6 import default_routes6, get_ip6_addrs, get_ip6_routes, install_ipv6_probe, ipv6_probe, ipv6_probe_spec
from net_config import NetConfigEntry, get_routes, set_ip_forward, set_ipv6_forward, set_net_config_entry
from openvpn import get_ip_addresses_json, interface_of_address, parse_ip_addr_json
from ping import eval_ping
from server_echo_helpers import get_http_echo, install_echo_server
from utils import random_password
from vrrp import (
    KEEPALIVED_CONF, KEEPALIVED_DIR, KEEPALIVED_UNIT, RADVD_CONF, RADVD_UNIT, VMAC_PREFIX, VRRP_GROUP6, adverts,
    advert_interval, apply_archive_cmd, archive_mode, archive_text, config_archive_cmd, drop_echo_from_cmd,
    echo_server_is, fault_clear_cmd, find_instance, forged_adverts, holds_address, install_vrrp_probe,
    instance_addresses, instance_group, is_multicast_advert, master_down_interval, notify_paths, notify_states,
    parse_keepalived_conf, parse_notify_log, parse_tcpdump_vrrp, read_archive, stop_cmd, tracked_interfaces,
    tracked_scripts, virtual_mac, vrrp_capture_cmd, wait_cmd,
)
from wireguard import get_unit_state

default_language = 'fr'
tr = make_tr(default_language)

title = tr("VRRP et keepalived : redondance de la passerelle", en="VRRP and keepalived: gateway redundancy")
ipv6 = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the hidden mirror.
export_kathara_project = False
# An evaluation replays the configuration on the mirror and injects failures there: about a minute.
eval_interval_without_exam_mode = 300
eval_before_exit = True
record_sessions = False

DOMAIN = "lab"
MIRROR = "_h"                       # suffix of the hidden clones (hidden_mirror.expand_topology)
ROUTERS = ('r1', 'r2')
CLIENTS = ('pc1', 'pc2')
INIT_MACHINE = {'image': sre_docker_image("init"), 'privileged': True, 'entrypoint': "/sbin/init"}
#: the provider's network: one of the documentation ranges (TEST-NET-1/2/3)
WAN_NETWORKS = [IPv4Network("192.0.2.0/24"), IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24")]
MAC_PREFIX = "02:53:52"             # locally administered addresses
#: host part of every address, IPv4 (decimal) and IPv6 (the same digits read as hexadecimal)
HOST_PARTS = {'pc1': 11, 'pc2': 12, 'r1_lan': 251, 'r2_lan': 252, 'vip_lan': 254, 'vip_lan2': 253,
              'isp': 1, 'r1_wan': 251, 'r2_wan': 252, 'vip_wan': 254}
#: ips.<key> / ips6.<key> -> network
ADDRESSED = {'pc1': 'lan', 'pc2': 'lan', 'r1_lan': 'lan', 'r2_lan': 'lan', 'vip_lan': 'lan', 'vip_lan2': 'lan',
             'isp': 'wan', 'r1_wan': 'wan', 'r2_wan': 'wan', 'vip_wan': 'wan'}
#: keys that have no IPv6 twin (the IPv6 virtual gateway of the LAN is the link-local VIP6_LAN)
IPV4_ONLY = ('vip_lan', 'vip_lan2')
VIP6_LAN = "fe80::1"                # virtual link-local address of the IPv6 gateway
#: (machine, network) -> macs.<key>: fixed MAC addresses of the routers
MAC_KEYS = {('r1', 'lan'): 'r1_lan', ('r2', 'lan'): 'r2_lan', ('r1', 'wan'): 'r1_wan', ('r2', 'wan'): 'r2_wan'}

PRIORITY_MASTER, PRIORITY_BACKUP = 150, 100
ADVERT_INT = 1
ECHO_PORTS = (80,)
#: names imposed by the statement (the grader finds the instances by VRID, not by name)
VI_LAN, VI_WAN, VI_LAN2, VI_LAN6, GROUP = "VI_LAN", "VI_WAN", "VI_LAN2", "VI_LAN6", "G_EDGE"
CHECK_NAME = "chk_upstream"
CHECK_SCRIPT = f"{KEEPALIVED_DIR}/check_upstream.sh"
CHECK_INTERVAL, CHECK_FALL, CHECK_RISE = 2, 2, 2
NOTIFY_SCRIPT = f"{KEEPALIVED_DIR}/notify.sh"
NOTIFY_LOG = "/var/log/vrrp-state.log"
LAST_PART = 7
LAN_SWITCHES = ('lan', 'lan' + MIRROR)
#: console command of the LAN switches: a MAC address seen on a new port moves there at once, as
#: on a real switch (vde_switch holds it 3 s on the old port by default, which blacks a virtual
#: MAC out for 3 to 4 s after a handover: measured live on 2026-11-11).  Run at the first step of
#: every evaluation: at the start of a project the console of the switches cannot be reached once
#: the privileges are dropped (lab with privileged machines), so `initial` cannot do it.
SWITCH_NO_HOLD = "hash/setminper 0"

# -- the evaluation ---------------------------------------------------------------------------
CAPTURE_SECONDS = 4          # live capture of the advertisements (pc1 on the LAN, isp on the WAN)
CONFIG_TEST_CMD = "keepalived -t >/dev/null 2>&1; echo rc=$?"
#: bounded waits of the mirror scenario (seconds), sized on the live measurements of 2026-11-11:
#: start 3.5-3.7 s, link down 3.4-3.6 s, back 4.8-5.2 s, health check 4.6-5.9 s (7.5 s to come back)
WAIT_START, WAIT_FAILOVER, WAIT_BACK, WAIT_TRACK, WAIT_CHECK = 15, 10, 12, 10, 16
SETTLE_SECONDS = 5           # the routers are read at least that long after their restart
FORGE_SECONDS = 8            # forged advertisements of step 7
FORGE_SAMPLES = (4, 3)       # the holders are read 4 s then 7 s after the start of the step
LAST_STEP = 8
CLIENT_RESET_CMD = ("pkill -9 -f 'vrrp_prob[e].py' 2>/dev/null; ip neigh flush all; "
                    "ip -6 route flush proto ra 2>/dev/null; true")

# Creation-time sysctls (Kathara meta).  EUI-64 link-local addresses whatever the host's defaults;
# the routers and the provider ignore router advertisements and keep their IPv6 addresses when a
# link goes down (a failure is simulated with `ip link set ... down`); the clients take their
# default route from the advertisements but no automatic address.
BASE_SYSCTLS = ('net.ipv6.conf.default.addr_gen_mode=0', 'net.ipv6.conf.default.use_tempaddr=0')
PROVIDER_SYSCTLS = BASE_SYSCTLS + ('net.ipv6.conf.default.accept_ra=0', 'net.ipv6.conf.default.autoconf=0')
# arp_announce=2: an ARP request of a router always carries the address of the interface it leaves
# by, never a virtual address.  Without it a router answering from the virtual address of a
# macvlan (use_vmac) asks "who has pc2, tell <virtual address>" from its real MAC address, and
# pc2 replaces the virtual MAC by the real one in its ARP cache (seen live on 2026-11-11).
ROUTER_SYSCTLS = PROVIDER_SYSCTLS + ('net.ipv6.conf.all.keep_addr_on_down=1',
                                     'net.ipv6.conf.default.keep_addr_on_down=1',
                                     'net.ipv4.conf.all.arp_announce=2')
CLIENT_SYSCTLS = BASE_SYSCTLS + ('net.ipv6.conf.default.autoconf=0',)

_TOPOLOGY = {
    'lan': {'pc1': 0, 'pc2': 0, 'r1': 0, 'r2': 0},
    'wan': {'r1': 1, 'r2': 1, 'isp': 0},
}
_SPECS = {
    'pc1': {'color': 'lightyellow', 'sysctls': CLIENT_SYSCTLS},
    'pc2': {'color': 'lightyellow', 'sysctls': CLIENT_SYSCTLS},
    'r1': {**INIT_MACHINE, 'color': 'lightblue', 'sysctls': ROUTER_SYSCTLS},
    'r2': {**INIT_MACHINE, 'color': 'lightblue', 'sysctls': ROUTER_SYSCTLS},
    'isp': {'color': 'lightgrey', 'sysctls': PROVIDER_SYSCTLS},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS)


def H(machine: str) -> str:
    """Name of the hidden clone of *machine*."""
    return machine + MIRROR


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    vrid_lan: int = 0        # VI_LAN: the IPv4 virtual gateway of pc1
    vrid_wan: int = 0        # VI_WAN: the virtual address the provider routes the LAN to
    vrid_lan2: int = 0       # VI_LAN2: the second virtual gateway (pc2), mastered by r2
    vrid_lan6: int = 0       # VI_LAN6: the IPv6 virtual gateway (VRRPv3)
    auth_pass: str = ""      # password of VI_LAN (auth_type PASS: 8 characters)

    @classmethod
    def generate(cls):
        data = cls()
        data.vrid_lan, data.vrid_wan, data.vrid_lan2, data.vrid_lan6 = random.sample(range(10, 250), 4)
        data.auth_pass = random_password(8)
        data.nets.lan = random_ipv4networks(masks=[24], from_private_network=True,
                                            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])[0]
        data.nets.wan = random.choice(WAN_NETWORKS)
        data.nets6.lan, data.nets6.wan = random_ipv6networks(masks=[64, 64], from_private_network=True)
        for key, net in ADDRESSED.items():
            net4 = getattr(data.nets, net)
            setattr(data.ips, key, IPv4Interface(f"{net4.network_address + HOST_PARTS[key]}/{net4.prefixlen}"))
            if key not in IPV4_ONLY:
                net6 = getattr(data.nets6, net)
                setattr(data.ips6, key, IPv6Interface((int(net6.network_address) + int(str(HOST_PARTS[key]), 16),
                                                       net6.prefixlen)))
        keys = sorted(set(MAC_KEYS.values()))
        for key, mac in zip(keys, random_mac_address(prefix=MAC_PREFIX, n=len(keys))):
            setattr(data.macs, key, mac)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = _FULL_SPECS
    # The LAN is a learning switch, as a real one: the frames sent to a virtual MAC address
    # (use_vmac) only reach the port where that address was last seen, the master's.  On a hub
    # they reach every router: the backup keeps its macvlan interface up and, as it forwards
    # too, it duplicates the packets or answers "net unreachable" (seen live on 2026-11-11).
    # The WAN stays a hub, the provider's shared segment: isp sees the unicast adverts.
    _network_specs = {
        'lan': {'mode': 'managed', 'allow_connection': False, 'color': 'lightyellow'},
        'wan': {'color': 'lightgrey'},
        'lan' + MIRROR: {'mode': 'managed', 'allow_connection': False},
    }

    @property
    def _topology(self):
        # the visible routers get the fixed MAC addresses of the data (the clones keep random ones)
        macs = self.data.macs
        topology = {net: dict(machines) for net, machines in _FULL_TOPOLOGY.items()}
        for (machine, net), key in MAC_KEYS.items():
            topology[net][machine] = (topology[net][machine], getattr(macs, key))
        return topology

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        self.net_config: Dict[str, NetConfigEntry] = dict(self._net_config(target=False))
        # the clones of the clients and of the provider already use the virtual addresses
        for m, nc in self._net_config(target=True).items():
            self.net_config[H(m)] = nc

        # The course: one tr() text per section (the lab itself is presented by the first question).
        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi une passerelle redondante ?"), tag="why")
            + tr("""
Un poste ne connaît en général qu'une route : sa **passerelle par défaut**. Si ce routeur tombe,
tout le réseau local est coupé du reste du monde, même s'il existe un second routeur juste à côté :
les postes ne le connaissent pas. La passerelle est un **point de défaillance unique**.

Plutôt que de faire tourner un protocole de routage sur chaque poste, on rend la passerelle
elle-même redondante : plusieurs routeurs se partagent **une adresse IP virtuelle**, que les postes
utilisent comme passerelle. À un instant donné un seul routeur détient cette adresse ; s'il
disparaît, un autre la reprend en quelques secondes, sans que les postes changent quoi que ce soit.

Les protocoles de cette famille (*First Hop Redundancy Protocols*) sont **VRRP** (*Virtual Router
Redundancy Protocol*, standard de l'IETF : RFC 3768 pour la version 2, RFC 5798 pour la version 3),
HSRP et GLBP (Cisco) et CARP (BSD). Sous Linux, VRRP est mis en œuvre par **keepalived**.
""")
            + info_subtitle(tr("Le protocole VRRP"), tag="protocol")
            + tr("""
### @@sec@@ Routeur virtuel, maître et secours

Un **routeur virtuel** est défini, sur un réseau local, par un identifiant, le **VRID** (de 1 à
255), et par une ou plusieurs adresses IP virtuelles. Les routeurs réels qui y participent ont
chacun une **priorité** (de 1 à 254, 100 par défaut). Le plus prioritaire est le **maître**
(*master*) : il détient les adresses virtuelles, répond aux requêtes ARP qui les concernent et
achemine le trafic. Les autres sont **secours** (*backup*) : ils écoutent.

Deux priorités sont réservées : **255** désigne le routeur dont l'adresse virtuelle est la propre
adresse d'interface (le « propriétaire »), et **0** est la valeur que le maître annonce quand il se
retire volontairement.

### @@sec@@ Les annonces

Le maître émet régulièrement une **annonce** (*advertisement*) ; les secours n'émettent rien.

| | VRRP sur IPv4 | VRRP sur IPv6 |
|---|---|---|
| destination | `224.0.0.18` (multidiffusion) | `ff02::12` |
| protocole | IP 112 (ni TCP ni UDP) | en-tête suivant 112 |
| TTL / limite de sauts | 255 | 255 |
| source | l'adresse réelle du maître | son adresse lien-local |
| contenu | version, VRID, priorité, intervalle, adresses virtuelles | idem |

Le TTL de 255 est une protection : une annonce qui aurait traversé un routeur arriverait avec un
TTL plus petit et serait rejetée. VRRP ne sort pas du réseau local.

### @@sec@@ Élection et bascule

Un secours qui ne reçoit plus d'annonce pendant l'**intervalle d'indisponibilité du maître** se
déclare maître :

```
intervalle d'indisponibilité = 3 × intervalle des annonces + décalage
décalage (skew time)         = (256 − priorité) / 256 seconde
```

Avec des annonces toutes les secondes, un secours de priorité 100 attend 3,61 s, un secours de
priorité 150 attend 3,41 s : le plus prioritaire se déclare le premier, et son annonce fait taire
les autres. À priorité égale, le routeur dont l'adresse IP est la plus grande l'emporte.

Quand le maître s'arrête proprement, il émet une annonce de **priorité 0** : les secours n'attendent
alors que le décalage, moins d'une seconde. Quand il disparaît brutalement (panne, câble
débranché), il faut attendre l'intervalle complet.

En devenant maître, un routeur émet des **ARP gratuits** (des requêtes ARP pour sa propre adresse
virtuelle) : les postes et les commutateurs apprennent ainsi où se trouve désormais l'adresse.

### @@sec@@ VRRPv2 et VRRPv3

| | VRRPv2 (RFC 3768) | VRRPv3 (RFC 5798) |
|---|---|---|
| familles d'adresses | IPv4 | IPv4 et IPv6 |
| intervalle des annonces | en secondes | en centisecondes (bascules en moins d'une seconde) |
| authentification | champ présent, usage déconseillé | aucune |
| décalage | (256 − priorité) / 256 s | proportionnel à l'intervalle du maître |
""")
            + info_subtitle(tr("keepalived"), tag="keepalived")
            + tr("""
keepalived est un démon qui met en œuvre VRRP (et, ce qui ne sert pas ici, la surveillance des
serveurs d'un répartiteur de charge LVS). Sa configuration est le fichier
`/etc/keepalived/keepalived.conf` ; tant que ce fichier n'existe pas, le service ne démarre pas.

### @@sec@@ Une instance VRRP

```
global_defs {
    router_id routeur-a          # un nom pour ce routeur, dans les journaux
}

vrrp_instance VI_1 {             # le nom est local au fichier
    interface eth0               # où émettre les annonces et poser les adresses
    virtual_router_id 51         # le VRID : le même sur tous les routeurs du routeur virtuel
    state MASTER                 # état de départ souhaité : MASTER ou BACKUP
    priority 150
    advert_int 1                 # intervalle des annonces, en secondes
    virtual_ipaddress {
        192.0.2.1/24             # sans masque, l'adresse est posée en /32
    }
}
```

Un bloc s'ouvre par `{` en fin de ligne et se ferme par `}` seul sur sa ligne ; `#` et `!`
commencent un commentaire. Le fichier du second routeur est identique, à `router_id`, `state` et
`priority` près.

C'est la **priorité** qui décide de l'élection, pas `state` : avec une priorité inférieure à 255,
une instance `state MASTER` démarre tout de même en secours et ne devient maître qu'après
l'intervalle d'indisponibilité. Le VRID doit être unique sur le réseau local : deux routeurs
virtuels différents qui porteraient le même se perturberaient.

### @@sec@@ Le service

| commande | effet |
|---|---|
| `keepalived -t` | vérifie la configuration (aucun message et code 0 : elle est valide) |
| `systemctl enable --now keepalived` | active le service au démarrage et le lance |
| `systemctl reload keepalived` | relit la configuration sans interrompre les instances inchangées |
| `systemctl restart keepalived` | arrête tout (annonce de priorité 0) et redémarre |
| `journalctl -u keepalived -f` | suit le journal : `Entering BACKUP STATE`, `Entering MASTER STATE`... |
| `kill -USR1 $(cat /run/keepalived.pid)` | écrit l'état complet dans `/tmp/keepalived.data` |

Une instance est dans l'un de trois états : **MASTER**, **BACKUP** ou **FAULT** (elle ne peut pas
être maître : son interface est tombée, ou un élément qu'elle suit est en panne).
""")
            + info_subtitle(tr("La préemption"), tag="preemption")
            + tr("""
Par défaut, VRRP est **préemptif** : un routeur plus prioritaire que le maître en place lui reprend
le rôle dès qu'il revient. C'est prévisible (le maître est toujours le même en temps normal), mais
chaque retour provoque une seconde bascule.

- `nopreempt` : le routeur qui revient reste secours tant que le maître en place fonctionne. Cette
  option exige `state BACKUP` sur tous les routeurs.
- `preempt_delay 30` : il attend 30 s après son démarrage avant de reprendre la main, le temps que
  ses routes et ses autres services soient prêts.
""")
            + info_subtitle(tr("Les groupes de synchronisation"), tag="sync-group")
            + tr("""
Un routeur a plusieurs côtés, donc plusieurs instances VRRP : une par réseau. Elles sont
indépendantes : si une seule interface tombe, une seule instance bascule. Le trafic sort alors par
un routeur et revient par l'autre, qui ne peut plus le remettre à destination. Chaque instance est
dans un état correct, et pourtant plus rien ne passe.

Un **groupe de synchronisation** lie des instances : toutes sont maîtres, ou aucune.

```
vrrp_sync_group G_1 {
    group {
        VI_1
        VI_2
    }
}
```

Dès qu'une instance du groupe passe à l'état FAULT ou BACKUP, les autres la suivent. Les éléments
suivis (section @@ref:tracking@@) et les notifications (section @@ref:notify@@) se déclarent alors
sur le groupe.
""")
            + info_subtitle(tr("Le suivi : interfaces et scripts"), tag="tracking")
            + tr("""
Une instance surveille toujours sa propre interface. On peut lui donner d'autres critères.

### @@sec@@ Suivre une interface

```
track_interface {
    eth1                 # eth1 tombe : l'instance passe à l'état FAULT
    eth2 weight -30      # eth2 tombe : la priorité baisse de 30
}
```

Une interface n'est « tombée » que si le système le voit (lien désactivé, câble débranché). Un
voisin injoignable derrière un lien qui reste actif ne se détecte pas ainsi.

### @@sec@@ Suivre un script

```
vrrp_script chk_service {
    script "/etc/keepalived/check.sh"    # code de retour 0 : tout va bien
    interval 2                           # lancé toutes les 2 s
    fall 2                               # 2 échecs de suite : en panne
    rise 2                               # 2 succès de suite : rétabli
}

vrrp_instance VI_1 {
    ...
    track_script {
        chk_service
    }
}
```

Le **poids** (`weight`, dans `vrrp_script` ou après le nom dans `track_script`) fixe l'effet d'un
échec :

| poids | effet |
|---|---|
| 0 (par défaut) | en cas d'échec, l'instance passe à l'état **FAULT** |
| négatif (`weight -60`) | en cas d'échec, la priorité annoncée baisse d'autant ; l'instance reste secours ou maître selon les autres |
| positif | la priorité augmente d'autant tant que le script réussit |

**Dans un groupe de synchronisation, les poids sont ignorés** (keepalived les ramène à 0) : on y
suit donc les scripts sans poids, et un échec met tout le groupe à l'état FAULT.

### @@sec@@ Sécurité des scripts

keepalived tourne avec les droits de `root`, et ses scripts aussi par défaut (ou avec ceux de
l'utilisateur `keepalived_script` s'il existe). Dans `global_defs` :

- `script_user root` fixe l'utilisateur qui exécute les scripts ;
- `enable_script_security` refuse d'exécuter en tant que `root` un script qu'un autre utilisateur
  pourrait modifier (le fichier, ou l'un des répertoires qui y mènent).

Un script de test doit être rapide et sans effet de bord : il est lancé toutes les quelques
secondes.
""")
            + info_subtitle(tr("Les notifications"), tag="notify")
            + tr("""
keepalived peut lancer un programme à chaque changement d'état, pour journaliser, prévenir, ou
démarrer et arrêter un service qui doit suivre l'adresse virtuelle.

| mot-clé | lancé quand l'instance (ou le groupe) |
|---|---|
| `notify_master` | devient maître |
| `notify_backup` | devient secours |
| `notify_fault` | passe à l'état FAULT |
| `notify_stop` | s'arrête avec keepalived |
| `notify` | change d'état, quel qu'il soit |

Le script de `notify` reçoit quatre arguments : le type (`INSTANCE` ou `GROUP`), le nom, le nouvel
état (`MASTER`, `BACKUP`, `FAULT`, `STOP`) et la priorité.

```
#!/bin/sh
echo "$(date '+%F %T') $1 $2 $3 $4" >> /var/log/vrrp-state.log
```
""")
            + info_subtitle(tr("La sécurité des annonces"), tag="security")
            + tr("""
VRRP fait confiance au réseau local : toute machine capable d'émettre une annonce de priorité 255
pour le bon VRID devient maître et reçoit le trafic des postes. C'est un moyen simple d'interrompre
le service ou de l'intercepter.

### @@sec@@ L'authentification

```
authentication {
    auth_type PASS
    auth_pass secret12       # 8 caractères au plus
}
```

Chaque annonce porte alors le mot de passe, et une annonce qui ne le porte pas est ignorée. Mais il
circule **en clair** : une simple capture le révèle. C'est une protection contre les erreurs (deux
routeurs virtuels configurés par mégarde avec le même VRID), pas contre un attaquant. La RFC 3768 a
retiré l'authentification de VRRPv2 et VRRPv3 n'en prévoit pas ; l'autre type, `AH`, est déconseillé.

### @@sec@@ Les annonces en unicast

```
unicast_src_ip 192.0.2.2
unicast_peer {
    192.0.2.3
}
```

Les annonces sont envoyées directement aux homologues désignés au lieu du groupe de multidiffusion.
C'est indispensable là où la multidiffusion est filtrée (beaucoup de réseaux d'hébergeurs), et cela
évite de diffuser les annonces à tout le réseau.

La vraie protection se fait au niveau du commutateur : n'accepter le protocole 112 que sur les
ports des routeurs.
""")
            + info_subtitle(tr("Le partage de charge"), tag="load-sharing")
            + tr("""
Avec un seul routeur virtuel, le secours ne fait rien en temps normal. On peut en définir **deux**
sur le même réseau, avec deux VRID et deux adresses virtuelles : chaque routeur est maître de l'un
et secours de l'autre. La moitié des postes prend la première adresse pour passerelle, l'autre
moitié la seconde.

Ce partage est **statique** : il dépend de la passerelle donnée à chaque poste (à la main, ou par le
serveur DHCP). Et chaque routeur doit pouvoir acheminer seul tout le trafic, puisqu'il reprend les
deux adresses quand l'autre tombe.
""")
            + info_subtitle(tr("L'adresse MAC virtuelle"), tag="vmac")
            + tr("""
La norme attribue à chaque routeur virtuel une **adresse MAC virtuelle** : `00:00:5e:00:01:XX` en
IPv4, `00:00:5e:00:02:XX` en IPv6, où `XX` est le VRID en hexadécimal. Le maître répond aux requêtes
ARP avec cette adresse : à la bascule, l'adresse IP **et** l'adresse MAC changent de routeur, et les
caches ARP des postes restent valables.

keepalived, par défaut, ne le fait pas : l'adresse virtuelle prend l'adresse MAC de l'interface du
maître, et le nouveau maître prévient les postes par des ARP gratuits. L'option `use_vmac`, dans une
instance, active l'adresse MAC virtuelle :

- keepalived crée une interface `vrrp.VRID` de type **macvlan** au-dessus de l'interface de
  l'instance, avec l'adresse MAC virtuelle ; elle existe sur le maître comme sur les secours ;
- le maître y pose l'adresse virtuelle et émet ses annonces depuis cette adresse MAC : c'est ainsi
  que le commutateur apprend sur quel port elle se trouve désormais.

Deux précautions :

- les routeurs doivent émettre leurs requêtes ARP avec l'adresse de leur interface, jamais avec
  l'adresse virtuelle (`sysctl net.ipv4.conf.all.arp_announce=2`), sans quoi les postes
  réapprennent l'adresse MAC réelle ;
- le réseau doit être commuté : sur un concentrateur, ou si le commutateur diffuse les trames faute
  de connaître l'adresse, le secours reçoit lui aussi les trames destinées à l'adresse MAC
  virtuelle.

Avec des homologues en unicast, `use_vmac` demande en plus `vmac_xmit_base`.
""")
            + info_subtitle(tr("VRRPv3 et IPv6"), tag="vrrpv3-ipv6")
            + tr("""
Une instance dont les adresses virtuelles sont IPv6 est toujours en **VRRPv3**. Ses annonces vont à
`ff02::12` avec une limite de sauts de 255, et la première adresse virtuelle est une adresse
**lien-local**.

```
vrrp_instance VI_6 {
    interface eth0
    version 3
    virtual_router_id 61
    priority 150
    virtual_ipaddress {
        fe80::1/64
    }
}
```

Il n'y a pas d'ARP en IPv6 : en devenant maître, le routeur émet une **annonce de voisin non
sollicitée** (*unsolicited neighbor advertisement*) pour chaque adresse virtuelle.

### @@sec@@ Les annonces de routeur

Un poste IPv6 apprend sa passerelle par les **annonces de routeur** (RA) : la route par défaut
qu'il installe passe par l'adresse lien-local **source** de l'annonce. Si c'est l'adresse réelle
d'un routeur, la route meurt avec lui. Les annonces doivent donc partir de l'adresse virtuelle :

```
interface eth0
{
    AdvSendAdvert on;
    AdvRASrcAddress { fe80::1; };
    prefix 2001:db8:1::/64
    {
    };
};
```

Avec ce fichier sur tous les routeurs, seul celui qui détient l'adresse virtuelle, le maître,
émet des annonces.

### @@sec@@ Deux familles dans une instance

Les adresses de `virtual_ipaddress` sont toutes de la même famille. Pour qu'une instance IPv4
gère aussi une adresse IPv6 (ou l'inverse), on la place dans `virtual_ipaddress_excluded` : elle
n'apparaît pas dans les annonces, mais elle est posée et retirée avec les autres.
""")
            + info_subtitle(tr("Observer et dépanner"), tag="observing")
            + tr("""
| commande | ce qu'elle montre |
|---|---|
| `tcpdump -n -v -i eth0 vrrp` | les annonces IPv4 : source, VRID, priorité, intervalle, authentification |
| `tcpdump -n -v -i eth0 'ip6 proto 112'` | les annonces VRRPv3 en IPv6 |
| `tcpdump -e -n -i eth0 vrrp` | les mêmes avec les adresses MAC |
| `ip -br addr` | quel routeur porte les adresses virtuelles |
| `ip -d link show type macvlan` | les interfaces créées par `use_vmac` |
| `ip neigh` | sur un poste : l'adresse MAC associée à la passerelle |
| `ip -6 route` | sur un poste : la route par défaut reçue par annonce de routeur |
| `journalctl -u keepalived` | les transitions, les scripts, les annonces rejetées |

| symptôme | causes fréquentes |
|---|---|
| les deux routeurs sont maîtres | ils ne s'entendent pas : VRID différents, mot de passe différent, multidiffusion filtrée, homologues unicast mal désignés |
| aucun n'est maître | instances à l'état FAULT : interface tombée, script en échec, script refusé par `enable_script_security` |
| l'adresse virtuelle ne répond pas | masque oublié ou erroné, mauvaise interface, cache ARP périmé sur le poste |
| bascules à répétition | script de test trop sensible (`fall` trop petit), deux instances non groupées |
| keepalived ne démarre pas | fichier absent ou vide, erreur de syntaxe : `keepalived -t` |
""")
        )

    def _net_config(self, target: bool) -> Dict[str, NetConfigEntry]:
        """Addresses and static routes of the five machines: at the start of the lab (*target*
        false: everything goes through r1, no IPv6 route) or in the redundant architecture the
        students build (the virtual addresses as next hops; the IPv6 default route of the
        clients comes from the router advertisements)."""
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        gw1 = d.ips.vip_lan.ip if target else d.ips.r1_lan.ip
        gw2 = d.ips.vip_lan2.ip if target else d.ips.r1_lan.ip
        isp_routes = [(d.nets.lan, d.ips.vip_wan.ip if target else d.ips.r1_wan.ip)]
        if target:
            isp_routes.append((d.nets6.lan, d.ips6.vip_wan.ip))
        return {
            'pc1': [([d.ips.pc1, d.ips6.pc1], [(default, gw1)])],
            'pc2': [([d.ips.pc2, d.ips6.pc2], [(default, gw2)])],
            'r1': [([d.ips.r1_lan, d.ips6.r1_lan], []), ([d.ips.r1_wan, d.ips6.r1_wan], [])],
            'r2': [([d.ips.r2_lan, d.ips6.r2_lan], []), ([d.ips.r2_wan, d.ips6.r2_wan], [])],
            'isp': [([d.ips.isp, d.ips6.isp], isp_routes)],
        }

    def hosts_content(self, machine: str) -> str:
        d = self.data
        entries = [('pc1', d.ips.pc1), ('pc2', d.ips.pc2), ('r1', d.ips.r1_lan), ('r2', d.ips.r2_lan),
                   ('r1-wan', d.ips.r1_wan), ('r2-wan', d.ips.r2_wan), ('isp', d.ips.isp)]
        name = machine.removesuffix(MIRROR)
        lines = ["127.0.0.1\tlocalhost", f"127.0.1.1\t{name}", "::1\t\tlocalhost ip6-localhost ip6-loopback",
                 "ff02::1\t\tip6-allnodes", "ff02::2\t\tip6-allrouters", ""]
        lines += [f"{ip.ip}\t\t{host}.{DOMAIN}\t{host}" for host, ip in entries]
        return "\n".join(lines) + "\n"

    # -- reference solution (state `final` and instructor texts) ---------------------------

    def keepalived_conf(self, router: str, part: int = LAST_PART) -> str:
        """``keepalived.conf`` of *router* once the parts 1..*part* are done.

        r1 is the master of the group (LAN gateway of pc1, WAN address, IPv6 gateway), r2 the
        master of the second LAN gateway (pc2)."""
        d = self.data
        first = router == 'r1'
        peer = 'r2' if first else 'r1'

        def role(master: bool) -> str:
            return (f"    state {'MASTER' if master else 'BACKUP'}\n"
                    f"    priority {PRIORITY_MASTER if master else PRIORITY_BACKUP}\n"
                    f"    advert_int {ADVERT_INT}\n")

        text = f"global_defs {{\n    router_id {router}\n"
        if part >= 3:
            text += "    enable_script_security\n    script_user root\n"
        text += "}\n"
        if part >= 3:
            text += (f"\nvrrp_script {CHECK_NAME} {{\n    script \"{CHECK_SCRIPT}\"\n"
                     f"    interval {CHECK_INTERVAL}\n    fall {CHECK_FALL}\n    rise {CHECK_RISE}\n}}\n")
        if part >= 2:
            members = [VI_LAN, VI_WAN] + ([VI_LAN6] if part >= 7 else [])
            text += (f"\nvrrp_sync_group {GROUP} {{\n    group {{\n"
                     + "".join(f"        {m}\n" for m in members) + "    }\n")
            if part >= 3:
                text += f"    track_script {{\n        {CHECK_NAME}\n    }}\n    notify {NOTIFY_SCRIPT}\n"
            text += "}\n"

        text += f"\nvrrp_instance {VI_LAN} {{\n    interface eth0\n    virtual_router_id {d.vrid_lan}\n" + role(first)
        if part >= 4:
            text += f"    authentication {{\n        auth_type PASS\n        auth_pass {d.auth_pass}\n    }}\n"
        text += f"    virtual_ipaddress {{\n        {d.ips.vip_lan}\n    }}\n}}\n"

        if part >= 2:
            text += (f"\nvrrp_instance {VI_WAN} {{\n    interface eth1\n    virtual_router_id {d.vrid_wan}\n"
                     + role(first))
            if part >= 4:
                text += (f"    unicast_src_ip {getattr(d.ips, router + '_wan').ip}\n"
                         f"    unicast_peer {{\n        {getattr(d.ips, peer + '_wan').ip}\n    }}\n")
            text += f"    virtual_ipaddress {{\n        {d.ips.vip_wan}\n    }}\n"
            if part >= 7:
                text += f"    virtual_ipaddress_excluded {{\n        {d.ips6.vip_wan}\n    }}\n"
            text += "}\n"

        if part >= 5:
            text += (f"\nvrrp_instance {VI_LAN2} {{\n    interface eth0\n    virtual_router_id {d.vrid_lan2}\n"
                     + role(not first))
            if part >= 6:
                text += "    use_vmac\n"
            text += "    track_interface {\n        eth1\n    }\n"
            text += f"    virtual_ipaddress {{\n        {d.ips.vip_lan2}\n    }}\n}}\n"

        if part >= 7:
            text += (f"\nvrrp_instance {VI_LAN6} {{\n    interface eth0\n    version 3\n"
                     f"    virtual_router_id {d.vrid_lan6}\n" + role(first)
                     + f"    virtual_ipaddress {{\n        {VIP6_LAN}/64\n    }}\n}}\n")
        return text

    def check_script(self) -> str:
        """Health check of part 3: succeeds while the provider router answers."""
        return ("#!/bin/sh\n# 0 while the provider router answers\n"
                f"exec ping -c 1 -W 1 {self.data.ips.isp.ip} >/dev/null 2>&1\n")

    @staticmethod
    def notify_script() -> str:
        """Notify script of part 3: one line per transition."""
        return ("#!/bin/sh\n# $1 = GROUP | INSTANCE, $2 = name, $3 = MASTER | BACKUP | FAULT | STOP, $4 = priority\n"
                f"echo \"$(date '+%F %T') $1 $2 $3 $4\" >> {NOTIFY_LOG}\n")

    def radvd_conf(self) -> str:
        """``radvd.conf`` of part 7, the same on both routers: the advertisements leave from
        the virtual link-local address, which only the master holds."""
        return ("interface eth0\n{\n    AdvSendAdvert on;\n    MinRtrAdvInterval 3;\n    MaxRtrAdvInterval 10;\n"
                f"    AdvRASrcAddress {{ {VIP6_LAN}; }};\n"
                f"    prefix {self.data.nets6.lan}\n    {{\n        AdvOnLink on;\n        AdvAutonomous on;\n"
                "    };\n};\n")

    def client_commands(self, machine: str, part: int = LAST_PART) -> list:
        """Routing commands of the reference solution on a client or on the provider router."""
        d = self.data
        if machine == 'pc1':
            return [f"ip route replace default via {d.ips.vip_lan.ip}"]
        if machine == 'pc2':
            return [f"ip route replace default via {(d.ips.vip_lan2 if part >= 5 else d.ips.vip_lan).ip}"]
        commands = [f"ip route replace {d.nets.lan} via {d.ips.vip_wan.ip}"] if part >= 2 else []
        if part >= 7:
            commands.append(f"ip -6 route replace {d.nets6.lan} via {d.ips6.vip_wan.ip}")
        return commands

    # -- states -----------------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of the seven parts (forms are filled through cheat_answers).

        Step 1: clean start on r1 and r2.  Step 2: the files.  Step 3: the services, and the
        routes of the clients and of the provider router.
        """
        for r in ROUTERS:
            self.cmd(r, f"systemctl stop {KEEPALIVED_UNIT} radvd >/dev/null 2>&1; "
                        f"rm -rf {KEEPALIVED_DIR}/* {RADVD_CONF} {NOTIFY_LOG}; mkdir -p {KEEPALIVED_DIR}; true")
            self.file(r, KEEPALIVED_CONF, self.keepalived_conf(r), step=2)
            self.file(r, CHECK_SCRIPT, self.check_script(), permissions=0o755, step=2)
            self.file(r, NOTIFY_SCRIPT, self.notify_script(), permissions=0o755, step=2)
            self.file(r, RADVD_CONF, self.radvd_conf(), step=2)
            self.cmd(r, f"systemctl enable {KEEPALIVED_UNIT} radvd >/dev/null 2>&1; "
                        f"systemctl restart {KEEPALIVED_UNIT} radvd || "
                        f"systemctl status {KEEPALIVED_UNIT} radvd --no-pager",
                     step=3)
        for m in CLIENTS + ('isp',):
            for command in self.client_commands(m):
                self.cmd(m, command, step=3)

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            name = m.removesuffix(MIRROR)
            if name in ROUTERS:
                # privileged: /proc/sys is already writable (set_ip_forward's remount would fail)
                self.cmd(m, "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=False)
                set_ipv6_forward(net_scheme=self, machine_name=m, ipv6_forward=False)
            self.file(m, "/etc/hosts", self.hosts_content(m))
            # no DNS in the lab: an empty resolver fails fast instead of timing out
            self.file(m, "/etc/resolv.conf", "")
            if name in ROUTERS or name == 'isp':
                # `curl http://<virtual address>/` names the router that answers
                install_echo_server(net_scheme=self, machine=m, name=name, ports=ECHO_PORTS)
        # the probes of the evaluation, on the hidden clients
        install_vrrp_probe(self, H('pc1'))
        install_ipv6_probe(net_scheme=self, machine=H('pc1'))
        install_arp_probe(self, H('pc2'))


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower()


def _digits(s) -> str:
    return ''.join(ch for ch in (s or '') if ch.isdigit())


def _same_mac(answer, expected) -> bool:
    return normalize_mac(answer) != '' and normalize_mac(answer) == normalize_mac(expected)


def _same_ip(answer, expected) -> bool:
    try:
        return ip_address(_norm(answer).split('/')[0].split('%')[0]) == ip_address(str(expected).split('/')[0])
    except ValueError:
        return False


def _float_near(answer, expected: float, tolerance: float) -> bool:
    try:
        value = float(_norm(answer).replace(',', '.').rstrip('s').strip())
    except ValueError:
        return False
    return abs(value - expected) <= tolerance


def _holds4(addresses, ip) -> bool:
    """*addresses* (``ip -j -4 addr``, parsed) has the IPv4 address *ip* on some interface."""
    return interface_of_address(addresses or {}, ip) is not None


def _holds6(addresses, ip) -> bool:
    """*addresses* (``ip -j -6 addr``, parsed) has the IPv6 address *ip*."""
    wanted = IPv6Address(str(ip).split('/')[0])
    return any(a['address'] == wanted for a in addresses or [])


def _arp_reply_macs(output: str) -> list:
    """MAC addresses of the ARP replies an ``arp_probe`` query got."""
    replies = parse_arp_probe(output or '')['result'].get('replies') or []
    return [normalize_mac(reply.get('sender_mac', '')) for reply in replies]


def router_reset_cmd(data, router: str) -> str:
    """Shell command putting the clone of *router* back as `initial` left it: services stopped,
    links up, addresses in place, no configuration, no notify log.  The first and the last
    command of the mirror scenario: whatever an interrupted evaluation left behind is undone."""
    commands = [stop_cmd().removesuffix("; true"), "ip link set eth0 up", "ip link set eth1 up"]
    for side, device in (('lan', 'eth0'), ('wan', 'eth1')):
        for container in (data.ips, data.ips6):
            commands.append(f"ip addr replace {getattr(container, f'{router}_{side}')} dev {device}")
    commands += [f"rm -rf {KEEPALIVED_DIR}/* {RADVD_CONF} {NOTIFY_LOG}", "ip neigh flush all", "true"]
    return "; ".join(commands)


ISP_RESET_CMD = fault_clear_cmd().removesuffix("; true") + "; ip neigh flush all; true"


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        vip, vip2, vip_wan, vip6_wan = d.ips.vip_lan.ip, d.ips.vip_lan2.ip, d.ips.vip_wan.ip, d.ips6.vip_wan.ip
        isp4, isp6 = d.ips.isp.ip, d.ips6.isp.ip
        lan_ip = {r: getattr(d.ips, r + '_lan').ip for r in ROUTERS}
        wan_ip = {r: getattr(d.ips, r + '_wan').ip for r in ROUTERS}
        client_ip = {m: getattr(d.ips, m).ip for m in CLIENTS}
        mac = {r: normalize_mac(getattr(d.macs, r + '_lan')) for r in ROUTERS}
        vmac = virtual_mac(d.vrid_lan2)
        vmac_iface = f"{VMAC_PREFIX}{d.vrid_lan2}"
        peer = {'r1': 'r2', 'r2': 'r1'}

        # =====================================================================
        # Step 1 — the real machines: files, live state, advertisements on the wire
        # =====================================================================
        for network in LAN_SWITCHES:
            self.test_switch(network, SWITCH_NO_HOLD, allow_error=True)
        unit, radvd_unit, encoded, files, conf, config_ok, addr4, addr6, links = ({} for _ in range(9))
        for r in ROUTERS:
            unit[r] = get_unit_state(self, r, KEEPALIVED_UNIT)
            radvd_unit[r] = get_unit_state(self, r, RADVD_UNIT)
            encoded[r] = self.test(r, config_archive_cmd(), allow_error=True)[0]
            files[r] = read_archive(encoded[r])
            conf[r] = parse_keepalived_conf(archive_text(files[r], KEEPALIVED_CONF))
            config_ok[r] = self.test(r, CONFIG_TEST_CMD, allow_error=True)[0].strip() == "rc=0"
            addr4[r] = get_ip_addresses_json(self, r)
            addr6[r] = get_ip6_addrs(self, r)
            links[r] = links_by_name(get_ip_links(self, r))
            # kept in the archive for the instructor
            self.test(r, f"journalctl -u {KEEPALIVED_UNIT} --no-pager -n 40 2>/dev/null", allow_error=True)
            if encoded[r].strip() and files[r] is None:
                # say why the hidden copy scores nothing, instead of a silent zero
                self.add_warning(tr("les fichiers de {router} ne sont pas rejoués sur la copie cachée : "
                                    "{dir} et {radvd} ne doivent contenir que des fichiers ordinaires "
                                    "(ni lien ni périphérique), pour moins de 48 Ko en tout")
                                 .format(router=r, dir=KEEPALIVED_DIR, radvd=RADVD_CONF))
        lan_frames = parse_tcpdump_vrrp(self.test('pc1', vrrp_capture_cmd('eth0', CAPTURE_SECONDS),
                                                  timeout=CAPTURE_SECONDS + 10, allow_error=True)[0])
        wan_frames = parse_tcpdump_vrrp(self.test('isp', vrrp_capture_cmd('eth0', CAPTURE_SECONDS),
                                                  timeout=CAPTURE_SECONDS + 10, allow_error=True)[0])
        routes = {m: get_routes(self, m) for m in CLIENTS + ('isp',)}
        routes6 = {m: get_ip6_routes(self, m) for m in ('pc1', 'isp')}
        live_gw = {'pc1': get_http_echo(self, 'pc1', vip, timeout=2),
                   'pc2': get_http_echo(self, 'pc2', vip2, timeout=2)}
        live_isp = {m: get_http_echo(self, m, isp4, timeout=2) for m in CLIENTS}
        live_ping6 = eval_ping(self, 'pc1', isp6, count=1, deadline=2, allow_error=True)
        neigh_pc2 = get_neigh(self, 'pc2')

        # the clones go back to their initial state, whatever an earlier evaluation left
        for r in ROUTERS:
            self.test(H(r), router_reset_cmd(d, r), timeout=30, allow_error=True)
        for m in CLIENTS:
            self.test(H(m), CLIENT_RESET_CMD, allow_error=True)
        self.test(H('isp'), ISP_RESET_CMD, allow_error=True)

        def inst(r, vrid):
            return find_instance(conf[r], vrid=vrid)

        has = {key: any(inst(r, getattr(d, 'vrid_' + key)) is not None for r in ROUTERS)
               for key in ('lan', 'wan', 'lan2', 'lan6')}
        checked = any(tracked_scripts(conf[r], inst(r, d.vrid_lan)) for r in ROUTERS)
        lan2_tracked = any(tracked_interfaces(conf[r], inst(r, d.vrid_lan2))
                           or tracked_scripts(conf[r], inst(r, d.vrid_lan2)) for r in ROUTERS)
        # a router is replayed when its archive is valid and holds a keepalived.conf
        replayed = {r: bool(files[r]) and KEEPALIVED_CONF.lstrip('/') in files[r] for r in ROUTERS}

        # =====================================================================
        # Steps 2 to 8 — the hidden mirror: the files are replayed on r1_h and r2_h, failures
        # are injected there and observed from pc1_h, pc2_h and isp_h.  Registered only once the
        # archives of step 1 are known and valid (their content decides, never the pass number:
        # `sre re-eval` calls grade() once on archived results).  Every wait is a command of its
        # own: retuning it never changes the key of a measurement.
        # =====================================================================
        m_addr4, m_addr6, m_echo, m_arp, m_ping6, m_log = {}, {}, {}, {}, {}, {}
        ras, forged, forge_samples = [], {'sent': 0, 'error': None, 'heard': []}, []

        if any(replayed.values()):
            def run(machine, command, step, timeout=params.default_timeout):
                return self.test(H(machine), command, step=step, timeout=timeout, allow_error=True)[0]

            def when(flag, condition):
                return condition if flag else None

            def settle(machine, step, conditions, cap, head=0):
                condition = ' && '.join(c for c in conditions if c) or 'true'
                run(machine, (f"sleep {head}; " if head else "") + wait_cmd(condition, cap), step,
                    timeout=cap + head + 10)

            def read_routers(step):
                for r in ROUTERS:
                    m_addr4[(step, r)] = get_ip_addresses_json(self, H(r), step=step)
                    m_addr6[(step, r)] = get_ip6_addrs(self, H(r), step=step)

            def read_client(step, client, gateway):
                m_echo[(step, client, 'gw')] = get_http_echo(self, H(client), gateway, step=step, timeout=2)
                m_echo[(step, client, 'isp')] = get_http_echo(self, H(client), isp4, step=step, timeout=2)

            edge = [when(has['lan'], holds_address(vip)), when(has['wan'], holds_address(vip_wan)),
                    when(has['lan6'], holds_address(VIP6_LAN))]

            # step 2: the students' files, then the nominal state
            for r in ROUTERS:
                if replayed[r]:
                    run(r, apply_archive_cmd(encoded[r]), 2)
            settle('r1', 2, edge, WAIT_START, head=SETTLE_SECONDS)
            settle('r2', 2, [when(has['lan2'], holds_address(vip2))], WAIT_START, head=SETTLE_SECONDS)
            read_routers(2)
            settle('pc1', 2, [when(has['lan'], echo_server_is(vip, 'r1'))], WAIT_START)
            read_client(2, 'pc1', vip)
            ras = ipv6_probe(self, H('pc1'), ipv6_probe_spec('eth0', rs=True, wait=3.0), step=2, timeout=15)[0]
            m_ping6[2] = eval_ping(self, H('pc1'), isp6, step=2, count=2, deadline=3, allow_error=True)
            settle('pc2', 2, [when(has['lan2'], echo_server_is(vip2, 'r2'))], WAIT_START)
            read_client(2, 'pc2', vip2)
            m_arp[2] = _arp_reply_macs(run('pc2', arp_query_cmd('eth0', vip2, wait=1.0), 2))

            # step 3: the LAN link of r1 goes down
            run('r1', "ip link set eth0 down", 3)
            settle('r1', 3, [when(has['wan'], "! " + holds_address(vip_wan))], WAIT_FAILOVER)
            settle('r2', 3, edge, WAIT_FAILOVER)
            read_routers(3)
            settle('pc1', 3, [when(has['lan'], echo_server_is(vip, 'r2'))], WAIT_FAILOVER)
            read_client(3, 'pc1', vip)
            m_ping6[3] = eval_ping(self, H('pc1'), isp6, step=3, count=2, deadline=3, allow_error=True)

            # step 4: it comes back (alone in its step: with r2 broken at the same time, r1 would
            # get the addresses back whatever its configuration says about preemption)
            run('r1', "ip link set eth0 up", 4)
            settle('r1', 4, edge, WAIT_BACK)
            settle('r2', 4, [when(has['lan'], "! " + holds_address(vip)), when(has['lan2'], holds_address(vip2))],
                   WAIT_BACK)
            read_routers(4)
            settle('pc1', 4, [when(has['lan'], echo_server_is(vip, 'r1'))], WAIT_BACK)
            m_echo[(4, 'pc1', 'gw')] = get_http_echo(self, H('pc1'), vip, step=4, timeout=2)

            # step 5: the WAN link of r2 goes down (the second gateway must leave r2)
            run('r2', "ip link set eth1 down", 5)
            settle('r1', 5, [when(lan2_tracked, holds_address(vip2))], WAIT_TRACK)
            read_routers(5)
            settle('pc2', 5, [when(lan2_tracked, echo_server_is(vip2, 'r1'))], WAIT_TRACK)
            read_client(5, 'pc2', vip2)
            m_arp[5] = _arp_reply_macs(run('pc2', arp_query_cmd('eth0', vip2, wait=1.0), 5))

            # step 6: r2 is repaired; the provider no longer answers the pings of r1
            run('r2', "ip link set eth1 up", 6)
            run('isp', drop_echo_from_cmd(wan_ip['r1']), 6)
            settle('r2', 6, [when(checked, holds_address(vip))], WAIT_CHECK)
            settle('r1', 6, [when(checked, "! " + holds_address(vip))], WAIT_CHECK)
            read_routers(6)
            for r in ROUTERS:
                m_log[r] = parse_notify_log(run(r, f"cat {NOTIFY_LOG} 2>/dev/null", 6))
            settle('pc1', 6, [when(checked, echo_server_is(vip, 'r2'))], WAIT_CHECK)
            read_client(6, 'pc1', vip)

            # step 7: the provider answers again; forged advertisements (priority 255, no
            # password) are sent from pc1_h while the routers are read twice
            run('isp', fault_clear_cmd(), 7)
            forged = forged_adverts(self, H('pc1'), d.vrid_lan, vip, step=7, seconds=FORGE_SECONDS)
            for delay in FORGE_SAMPLES:
                forge_samples.append({r: parse_ip_addr_json(run(r, f"sleep {delay}; ip -j -4 addr show", 7))
                                      for r in ROUTERS})

            # step 8: the clones are left clean
            for r in ROUTERS:
                run(r, router_reset_cmd(d, r), LAST_STEP, timeout=30)
            for m in CLIENTS:
                run(m, CLIENT_RESET_CMD, LAST_STEP)
            run('isp', ISP_RESET_CMD, LAST_STEP)

        # ---------------- what was observed ------------------------------------------------
        def live_held(r, ip):
            return _holds6(addr6[r], ip) if ':' in str(ip) else _holds4(addr4[r], ip)

        def live_only(r, ip):
            return live_held(r, ip) and not live_held(peer[r], ip)

        def held(step, r, ip):
            if ':' in str(ip):
                return _holds6(m_addr6.get((step, r)), ip)
            return _holds4(m_addr4.get((step, r)), ip)

        def only(step, r, ip):
            return held(step, r, ip) and not held(step, peer[r], ip)

        def moved(ip, holder, before, taker, after):
            """*ip* was on *holder* alone at step *before* and is on *taker* at step *after*: a
            failover, not the fixed position of the only router that was configured."""
            return only(before, holder, ip) and held(after, taker, ip)

        def served(step, client, name):
            return m_echo.get((step, client, 'gw'), {}).get('server') == name

        def through(step, client):
            answer = m_echo.get((step, client, 'isp'), {})
            return answer.get('server') == 'isp' and answer.get('client_ip') == str(client_ip[client])

        def live_through(client):
            answer = live_isp[client]
            return answer.get('server') == 'isp' and answer.get('client_ip') == str(client_ip[client])

        def default_gateway(machine):
            return routes[machine].get(('0.0.0.0', 0), ('', '', 0))[0]

        def instance_on(r, vrid, address, interface='eth0'):
            instance = inst(r, vrid)
            return (bool(instance) and instance['interface'] == interface
                    and str(address) in instance_addresses(instance))

        def priorities(vrid, master):
            first, second = inst(master, vrid), inst(peer[master], vrid)
            return bool(first and second) and (first['priority'], second['priority']) == (PRIORITY_MASTER,
                                                                                         PRIORITY_BACKUP)

        def conf_code(text: str) -> str:
            return text.rstrip("\n")

        # =====================================================================
        # Organisation
        # =====================================================================
        addressing = tr("""
| machine | interface | réseau | IPv4 | IPv6 |
|---------|-----------|--------|------|------|
| `pc1` | eth0 | `lan` | `{pc1}` | `{pc1_6}` |
| `pc2` | eth0 | `lan` | `{pc2}` | `{pc2_6}` |
| `r1` | eth0 | `lan` | `{r1_lan}` | `{r1_lan6}` |
| `r1` | eth1 | `wan` | `{r1_wan}` | `{r1_wan6}` |
| `r2` | eth0 | `lan` | `{r2_lan}` | `{r2_lan6}` |
| `r2` | eth1 | `wan` | `{r2_wan}` | `{r2_wan6}` |
| `isp` | eth0 | `wan` | `{isp}` | `{isp6}` |
""").format(pc1=d.ips.pc1, pc2=d.ips.pc2, r1_lan=d.ips.r1_lan, r2_lan=d.ips.r2_lan, r1_wan=d.ips.r1_wan,
            r2_wan=d.ips.r2_wan, isp=d.ips.isp, pc1_6=d.ips6.pc1, pc2_6=d.ips6.pc2, r1_lan6=d.ips6.r1_lan,
            r2_lan6=d.ips6.r2_lan, r1_wan6=d.ips6.r1_wan, r2_wan6=d.ips6.r2_wan, isp6=d.ips6.isp)
        values = tr("""
| instance VRRP | interface | VRID | maître (150) / secours (100) | adresse virtuelle |
|---------------|-----------|------|------------------------------|-------------------|
| `VI_LAN` | eth0 | **{vrid_lan}** | r1 / r2 | `{vip_lan}` : la passerelle de `pc1` |
| `VI_WAN` | eth1 | **{vrid_wan}** | r1 / r2 | `{vip_wan}` : par où `isp` joint le réseau local (partie 2) |
| `VI_LAN2` | eth0 | **{vrid_lan2}** | r2 / r1 | `{vip_lan2}` : la passerelle de `pc2` (partie 5) |
| `VI_LAN6` | eth0 | **{vrid_lan6}** | r1 / r2 | `{vip6_lan}/64` : la passerelle IPv6 (partie 7) |

- intervalle des annonces : {advert} s partout ;
- mot de passe de `VI_LAN` (partie 4) : `{auth_pass}` ;
- adresse virtuelle IPv6 côté `wan` (partie 7) : `{vip6_wan}` ;
- script de test (partie 3) : `{check}`, toutes les {interval} s, {fall} échecs pour tomber, {rise} succès pour revenir ;
- script de notification (partie 3) : `{notify}`, qui écrit dans `{log}`.
""").format(vrid_lan=d.vrid_lan, vrid_wan=d.vrid_wan, vrid_lan2=d.vrid_lan2, vrid_lan6=d.vrid_lan6,
            vip_lan=d.ips.vip_lan, vip_wan=d.ips.vip_wan, vip_lan2=d.ips.vip_lan2, vip6_lan=VIP6_LAN,
            vip6_wan=d.ips6.vip_wan, advert=ADVERT_INT, auth_pass=d.auth_pass, check=CHECK_SCRIPT,
            interval=CHECK_INTERVAL, fall=CHECK_FALL, rise=CHECK_RISE, notify=NOTIFY_SCRIPT, log=NOTIFY_LOG)

        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez d'abord l'onglet **Informations** : il présente VRRP et keepalived. Cette page décrit la
maquette et les valeurs propres à votre instance.

**La maquette.** Deux routeurs, `r1` et `r2`, relient le réseau local `lan` (les clients `pc1` et
`pc2`, sur un commutateur) au réseau `wan` du fournisseur d'accès, dont le routeur est `isp`. Pour ce
TP vous administrez toutes les machines, `isp` compris.
""")
            + addressing
            + tr("""
**Déjà en place (ne pas modifier).** Les adresses ci-dessus ; le routage IPv4 et IPv6 sur `r1` et
`r2` ; `/etc/hosts` (noms `pc1`, `pc2`, `r1`, `r2`, `r1-wan`, `r2-wan`, `isp`) ; un petit serveur web
sur `r1`, `r2` et `isp` : `curl http://ADRESSE/` affiche `SERVER=` suivi du nom de la machine qui a
répondu (et `CLIENT_IP=`, l'adresse du client telle que le serveur la voit) ; sur les routeurs, le
réglage `arp_announce=2` (cf. section @@ref:vmac@@). keepalived et radvd sont installés sur `r1` et
`r2`, **arrêtés et sans configuration**.

**Au départ, aucune redondance.** `pc1` et `pc2` ont `r1` (`{r1_lan}`) pour passerelle, et `isp`
joint le réseau local par `r1` (`{r1_wan}`). Tout fonctionne tant que `r1` fonctionne.

**Valeurs de votre instance.**
""").format(r1_lan=lan_ip['r1'], r1_wan=wan_ip['r1'])
            + values
            + tr("""
Les noms des instances sont libres (l'évaluation reconnaît une instance à son VRID) ; ceux du
tableau sont ceux des solutions.

**Simuler une panne.** `systemctl stop keepalived` (arrêt propre du service) ; `ip link set eth0 down`
puis `ip link set eth0 up` (câble débranché : les adresses des routeurs sont conservées) ; ou, sur
`isp`, une règle nftables qui ignore les `ping` d'un routeur (partie 3).

**L'évaluation ne touche jamais à vos routeurs.** À chaque évaluation, le contenu de
**`/etc/keepalived/`** (la configuration **et les scripts**) et le fichier **`/etc/radvd.conf`** de
`r1` et de `r2` sont recopiés sur une copie cachée de la maquette (mêmes adresses). keepalived y est
redémarré, puis des pannes y sont provoquées : lien coupé, fournisseur injoignable, fausses annonces.
En conséquence :

- tout ce dont votre solution dépend doit se trouver dans ces deux emplacements (aucun script
  ailleurs) et être enregistré dans les fichiers ;
- peu importe l'état de vos routeurs au moment de l'évaluation (une panne en cours ne fausse rien),
  sauf pour les quelques vérifications faites sur la maquette réelle : service actif, adresses,
  annonces, routes des clients ;
- une évaluation dure d'une demi-minute à une minute.

Les questions à formulaire ne sont notées qu'à l'évaluation de l'enseignant.

**Plan du TP.** 1. une première passerelle virtuelle ; 2. le côté `wan` et le groupe de
synchronisation ; 3. test de santé et notification ; 4. authentification et homologues en unicast ;
5. partage de charge ; 6. adresse MAC virtuelle ; 7. VRRPv3 et IPv6.
""")
            + instructor(tr("""
**Pour l'enseignant.** L'état `final` applique la solution des sept parties sur `r1`, `r2`, les
clients et `isp` ; les formulaires se remplissent avec les réponses de l'état. La maquette cachée
(`pc1_h`, `pc2_h`, `r1_h`, `r2_h`, `isp_h`) rejoue l'archive de `/etc/keepalived` et de
`/etc/radvd.conf` en huit étapes : remise à zéro ; fichiers et état nominal ; lien LAN de `r1_h`
coupé ; lien rétabli (préemption) ; lien WAN de `r2_h` coupé ; `isp_h` ignore les `ping` de `r1_h` ;
fausses annonces de priorité 255 émises par `pc1_h` ; remise à zéro. Le commutateur du réseau local
est un `vde_switch` : la première évaluation lui retire son délai de 3 s avant de déplacer une adresse
MAC (`hash/setminper 0`), sans quoi une adresse MAC virtuelle reste injoignable 3 à 4 s après une
bascule propre.
""")),
        )

        # =====================================================================
        # Part 1 — a first virtual gateway (questions 1 to 3)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"),
                                    tr("Partie 1 — Une première passerelle virtuelle (questions 1 à 3)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Un seul routeur : le point de défaillance unique"),
            description=tr("""
Depuis `pc1`, vérifiez que `isp` répond : `ping {isp}` et `curl http://{isp}/`. Laissez le `ping`
tourner et, sur `r1`, coupez le lien du réseau local : `ip link set eth0 down`. Que devient le
`ping` ? Que faudrait-il changer, et sur quelles machines, pour passer par `r2` ? Rétablissez le
lien (`ip link set eth0 up`) avant de continuer.
""").format(isp=isp4)
            + instructor(tr("""
**Solution.** Le `ping` s'arrête : la passerelle de `pc1` est l'adresse de `r1` (`{r1_lan}`), que plus
personne ne détient. Pour passer par `r2` il faudrait changer la route par défaut de **chaque**
client (`ip route replace default via {r2_lan}`) et, sur `isp`, la route vers le réseau local
(`ip route replace {lan} via {r2_wan}`) : une intervention manuelle sur toutes les machines. VRRP
rend ce changement automatique en faisant porter l'adresse de la passerelle par le routeur
disponible. Rien n'est noté ici.
""").format(r1_lan=lan_ip['r1'], r2_lan=lan_ip['r2'], lan=d.nets.lan, r2_wan=wan_ip['r2'])),
        )

        self.question_dummy(
            section=self.section(0),
            title=tr("L'instance VI_LAN sur r1 et r2"),
            description=tr("""
Sur `r1` et sur `r2`, écrivez `{conf}` avec une instance VRRP sur `eth0` (cf. section
@@ref:keepalived@@ des Informations) : VRID **{vrid}**, adresse virtuelle `{vip}`, annonces
toutes les {advert} s ; `r1` est le maître prévu (`state MASTER`, priorité {master}), `r2` le
secours (`state BACKUP`, priorité {backup}).

1. Vérifiez chaque fichier avec `keepalived -t`, puis activez et démarrez le service :
   `systemctl enable --now keepalived`.
2. Sur `pc1`, remplacez la passerelle par l'adresse virtuelle : `ip route replace default via {vip_ip}`.
3. Vérifiez : `ip -br addr show eth0` sur les deux routeurs (qui porte `{vip_ip}` ?),
   `journalctl -u keepalived` et, depuis `pc1`, `curl http://{vip_ip}/` puis `ping {isp}`.
""").format(conf=KEEPALIVED_CONF, vrid=d.vrid_lan, vip=d.ips.vip_lan, vip_ip=vip, advert=ADVERT_INT,
            master=PRIORITY_MASTER, backup=PRIORITY_BACKUP, isp=isp4)
            + instructor(tr("""
**Solution.** `{conf}` sur `r1` :

```
{r1_conf}
```

Sur `r2` : `router_id r2`, `state BACKUP`, `priority {backup}`. Puis sur les deux routeurs
`keepalived -t && systemctl enable --now keepalived`, et sur `pc1`
`ip route replace default via {vip_ip}`. `r1` démarre en secours et devient maître au bout de 3 à
4 s (`Entering MASTER STATE` dans le journal) : seule une priorité 255 rend `state MASTER`
immédiat. `curl http://{vip_ip}/` affiche `SERVER=r1`.
""").format(conf=KEEPALIVED_CONF, r1_conf=conf_code(self.net_scheme.keepalived_conf('r1', part=1)),
            backup=PRIORITY_BACKUP,
            vip_ip=vip)),
        )

        q3_answers = {"dst": "224.0.0.18", "proto": "112", "ttl": "255", "sender": "r1", "mac_before": mac['r1'],
                      "prio_stop": "0", "mac_after": mac['r2'],
                      "down_time": f"{master_down_interval(ADVERT_INT, PRIORITY_BACKUP):.2f}"}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Les annonces et la bascule"),
            description=tr("""
Sur `pc1`, capturez les annonces : `tcpdump -n -v -i eth0 vrrp`. Notez aussi l'adresse MAC que
`pc1` associe à l'adresse virtuelle (`ip neigh show {vip_ip}`, après un `ping {vip_ip}`).

Laissez la capture et un `ping {isp}` tourner sur `pc1`, puis arrêtez le service sur `r1` :
`systemctl stop keepalived`. Observez la dernière annonce de `r1`, le journal de `r2`, le `ping` et
de nouveau `ip neigh show {vip_ip}`. Redémarrez le service sur `r1` : qui redevient maître ?

Recommencez en coupant le lien au lieu d'arrêter le service (`ip link set eth0 down` sur `r1`, puis
`up`) et comparez la durée de l'interruption (cf. section @@ref:protocol@@).
""").format(vip_ip=vip, isp=isp4)
            + tr("""
- adresse IP de destination des annonces : @@{dst:[0-9.]+}@@ ; numéro de protocole IP : @@{proto:[0-9]+}@@ ; TTL : @@{ttl:[0-9]+}@@
- en fonctionnement normal, qui émet des annonces ? @@{sender:>r1 seulement>>>r1|r2 seulement>>>r2|r1 et r2>>>both}@@
- adresse MAC de l'adresse virtuelle vue par pc1, r1 étant maître : @@{mac_before:[0-9a-fA-F:-]+}@@
- priorité annoncée par r1 dans sa dernière annonce, à l'arrêt du service : @@{prio_stop:[0-9]+}@@
- adresse MAC de l'adresse virtuelle vue par pc1, r2 étant maître : @@{mac_after:[0-9a-fA-F:-]+}@@
- lien coupé (aucune annonce de priorité 0) : délai, en secondes, au bout duquel r2 (priorité 100) se déclare maître : @@{down_time:[0-9.,]+}@@
""")
            + instructor(tr("""
**Solution.** Les annonces partent de l'adresse réelle du maître vers le groupe `224.0.0.18`,
protocole IP 112, TTL 255, une par seconde ; seul le maître en émet. `pc1` associe `{vip_ip}` à
l'adresse MAC de `r1` (`{mac_r1}`).

- Arrêt du service : `r1` émet une annonce de **priorité 0**, `r2` prend le relais en moins d'une
  seconde et envoie des ARP gratuits : l'entrée de `pc1` devient `{mac_r2}`, le `ping` ne perd rien
  ou un paquet. Au redémarrage, `r1` (priorité 150) reprend la main : c'est la préemption.
- Lien coupé : aucune annonce de priorité 0 ne peut partir. `r2` attend l'intervalle
  d'indisponibilité du maître, `3 × 1 + (256 − 100) / 256` = **{down:.2f} s**, pendant lesquelles le
  `ping` est interrompu.
""").format(vip_ip=vip, mac_r1=mac['r1'], mac_r2=mac['r2'],
            down=master_down_interval(ADVERT_INT, PRIORITY_BACKUP))),
            cheat_answers={"final": q3_answers},
        )

        lan_adverts = adverts(lan_frames, vrid=d.vrid_lan, src=lan_ip['r1'])
        lan_interval = advert_interval(lan_adverts)
        self.add_grade_element(
            title=no_tr("lan_service"), max_grade=2, grade_part=part1,
            grade=sum(int(unit[r]['active'] == 'active' and unit[r]['enabled'] == 'enabled' and config_ok[r])
                      for r in ROUTERS),
            description=tr("keepalived actif, activé au démarrage et de configuration valide (r1, r2)"),
        )
        self.add_grade_element(
            title=no_tr("lan_config"), max_grade=3, grade_part=part1,
            grade=sum(int(instance_on(r, d.vrid_lan, vip)) for r in ROUTERS) + int(priorities(d.vrid_lan, 'r1')),
            description=tr("instance de VRID {vrid} sur eth0 avec l'adresse {vip} (r1, r2) ; priorités 150 et 100")
            .format(vrid=d.vrid_lan, vip=vip),
        )
        self.add_grade_element(
            title=no_tr("lan_live"), max_grade=3, grade_part=part1,
            grade=(int(live_only('r1', vip))
                   + int(len(lan_adverts) >= 2 and all(f['priority'] == PRIORITY_MASTER for f in lan_adverts)
                         and lan_interval is not None and abs(lan_interval - ADVERT_INT) < 0.3)
                   + int(default_gateway('pc1') == str(vip) and live_gw['pc1'].get('server') == 'r1')),
            description=tr("sur la maquette : {vip} sur r1 seul ; annonces de r1 (priorité 150, une par seconde) ; "
                           "pc1 passe par {vip} et r1 lui répond").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("lan_mirror_nominal"), max_grade=3, grade_part=part1,
            grade=2 * int(only(2, 'r1', vip)) + int(served(2, 'pc1', 'r1')),
            description=tr("copie cachée, état nominal : {vip} sur r1 seul, qui répond à pc1").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("lan_mirror_failover"), max_grade=4, grade_part=part1,
            grade=2 * int(moved(vip, 'r1', 2, 'r2', 3))
            + 2 * int(moved(vip, 'r1', 2, 'r2', 3) and served(3, 'pc1', 'r2')),
            description=tr("copie cachée, lien LAN de r1 coupé : r2 prend {vip} et répond à pc1").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("lan_mirror_preempt"), max_grade=3, grade_part=part1,
            grade=2 * int(only(4, 'r1', vip)) + int(served(4, 'pc1', 'r1')),
            description=tr("copie cachée, lien rétabli : r1 reprend {vip} (préemption), r2 la rend").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("lan_form"), max_grade=4, grade_part=part1, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_same_ip(q3.get("dst"), "224.0.0.18")) + int(_digits(q3.get("proto")) == "112")
                         + int(_digits(q3.get("ttl")) == "255") + int(_norm(q3.get("sender")) == "r1")
                         + int(_same_mac(q3.get("mac_before"), mac['r1'])) + int(_digits(q3.get("prio_stop")) == "0")
                         + int(_same_mac(q3.get("mac_after"), mac['r2']))
                         + int(_float_near(q3.get("down_time"), master_down_interval(ADVERT_INT, PRIORITY_BACKUP),
                                           0.02))),
            description=tr("annonces (224.0.0.18, protocole 112, TTL 255, maître seul), adresses MAC avant et "
                           "après la bascule, priorité 0, délai de bascule"),
        )

        # =====================================================================
        # Part 2 — the WAN side and the sync group (questions 4 and 5)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Le côté wan et le groupe de synchronisation "
                                                       "(questions 4 et 5)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("L'instance VI_WAN et le groupe de synchronisation"),
            description=tr("""
Une passerelle a deux côtés. Pour l'instant `isp` joint le réseau local par l'adresse de `r1`
(`{r1_wan}`) : si `r1` tombe, les réponses n'ont plus de chemin de retour.

1. Sur `r1` et `r2`, ajoutez une instance sur `eth1` : VRID **{vrid}**, adresse virtuelle
   `{vip}`, mêmes rôles et priorités que `VI_LAN`.
2. Liez les deux instances dans un **groupe de synchronisation** (cf. section @@ref:sync-group@@) :
   elles doivent changer d'état ensemble.
3. Rechargez la configuration (`keepalived -t && systemctl reload keepalived`).
4. Sur `isp`, faites passer le trafic du réseau local par l'adresse virtuelle :
   `ip route replace {lan} via {vip_ip}`.

Vérifiez depuis `pc1` (`curl http://{isp}/`) puis coupez le lien du réseau local de `r1`
(`ip link set eth0 down`) : les **deux** adresses virtuelles doivent passer sur `r2` et `pc1` doit
toujours joindre `isp`. Rétablissez le lien.
""").format(r1_wan=wan_ip['r1'], vrid=d.vrid_wan, vip=d.ips.vip_wan, vip_ip=vip_wan, lan=d.nets.lan, isp=isp4)
            + instructor(tr("""
**Solution.** `{conf}` sur `r1` (sur `r2` : `router_id r2`, `state BACKUP` et `priority {backup}` dans
les deux instances) :

```
{r1_conf}
```

Sur `isp` : `ip route replace {lan} via {vip_ip}`. Lien `eth0` de `r1` coupé : `VI_LAN` passe à
l'état FAULT, le groupe y entraîne `VI_WAN` (`VRRP_Group(G_EDGE) Syncing instances to FAULT state`)
et `r2` prend les deux adresses.
""").format(conf=KEEPALIVED_CONF, backup=PRIORITY_BACKUP,
            r1_conf=conf_code(self.net_scheme.keepalived_conf('r1', part=2)),
            lan=d.nets.lan, vip_ip=vip_wan)),
        )

        q5_answers = {"lan_holder": "r2", "wan_holder": "r1", "result": "blackhole", "group_state": "FAULT"}
        q5 = self.question_form(
            section=self.section(0),
            title=tr("Sans le groupe de synchronisation"),
            description=tr("""
Raisonnez (ou essayez, en retirant provisoirement le groupe) : les instances `VI_LAN` et `VI_WAN`
sont indépendantes, `isp` joint le réseau local par `{vip_wan}`, et le lien `eth0` de `r1` tombe
alors que son lien `eth1` fonctionne.
""").format(vip_wan=vip_wan)
            + tr("""
- qui détient l'adresse virtuelle du réseau local ? @@{lan_holder:>r1>>>r1|r2>>>r2|personne>>>none}@@
- qui détient l'adresse virtuelle côté wan ? @@{wan_holder:>r1>>>r1|r2>>>r2|personne>>>none}@@
- un `ping` de pc1 vers isp : @@{result:>fonctionne>>>ok|échoue : la réponse de isp arrive sur r1, qui n'a plus de lien vers le réseau local>>>blackhole|échoue : pc1 ne trouve plus sa passerelle>>>gateway}@@
- avec le groupe, état de l'instance VI_WAN de r1 quand son lien eth0 tombe : @@{group_state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""")
            + instructor(tr("""
**Solution.** Sans groupe, `VI_LAN` bascule sur `r2` mais `VI_WAN` reste sur `r1`, dont le lien
`eth1` est intact : la requête de `pc1` sort par `r2`, la réponse de `isp` revient à `r1`, qui ne
peut plus la remettre au réseau local. C'est un trou noir, alors que chaque instance, prise seule,
est dans un état correct. Avec le groupe, toutes les instances de `r1` passent à l'état FAULT dès
que l'une d'elles y passe.
""")),
            cheat_answers={"final": q5_answers},
        )

        def grouped(r):
            first, second = inst(r, d.vrid_lan), inst(r, d.vrid_wan)
            group = instance_group(conf[r], first)
            return bool(first and second and group) and second['name'] in group['members']

        self.add_grade_element(
            title=no_tr("wan_config"), max_grade=3, grade_part=part2,
            grade=sum(int(instance_on(r, d.vrid_wan, vip_wan, interface='eth1')) for r in ROUTERS)
            + int(all(grouped(r) for r in ROUTERS)),
            description=tr("instance de VRID {vrid} sur eth1 avec l'adresse {vip} (r1, r2) ; les deux instances "
                           "dans un groupe de synchronisation").format(vrid=d.vrid_wan, vip=vip_wan),
        )
        # the last point only when the path uses both virtual addresses: at the start of the lab
        # pc1 already reaches isp, through r1 alone
        isp_by_vip = routes['isp'].get((str(d.nets.lan.network_address), d.nets.lan.prefixlen),
                                       ('', '', 0))[0] == str(vip_wan)
        self.add_grade_element(
            title=no_tr("wan_live"), max_grade=3, grade_part=part2,
            grade=(int(live_only('r1', vip_wan)) + int(isp_by_vip)
                   + int(isp_by_vip and default_gateway('pc1') == str(vip) and live_through('pc1'))),
            description=tr("sur la maquette : {vip} sur r1 seul ; isp joint le réseau local par {vip} ; "
                           "pc1 et isp se joignent par les adresses virtuelles").format(vip=vip_wan),
        )
        self.add_grade_element(
            title=no_tr("wan_mirror_nominal"), max_grade=2, grade_part=part2,
            grade=int(only(2, 'r1', vip_wan)) + int(through(2, 'pc1')),
            description=tr("copie cachée, état nominal : {vip} sur r1 seul ; pc1 et isp se joignent")
            .format(vip=vip_wan),
        )
        self.add_grade_element(
            title=no_tr("wan_mirror_sync"), max_grade=4, grade_part=part2,
            grade=2 * int(moved(vip_wan, 'r1', 2, 'r2', 3) and not held(3, 'r1', vip_wan))
            + 2 * int(moved(vip, 'r1', 2, 'r2', 3) and through(3, 'pc1')),
            description=tr("copie cachée, lien LAN de r1 coupé : {vip} passe aussi sur r2 (r1 la rend) ; pc1 et "
                           "isp se joignent toujours").format(vip=vip_wan),
        )
        self.add_grade_element(
            title=no_tr("wan_form"), max_grade=2, grade_part=part2, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_norm(q5.get("lan_holder")) == "r2") + int(_norm(q5.get("wan_holder")) == "r1")
                         + int(_norm(q5.get("result")) == "blackhole")
                         + int(_norm(q5.get("group_state")) == "fault")),
            description=tr("sans groupe : les deux adresses sur deux routeurs, trou noir ; état FAULT avec le groupe"),
        )

        # =====================================================================
        # Part 3 — health check and notification (questions 6 and 7)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"),
                                    tr("Partie 3 — Test de santé et notification (questions 6 et 7)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Surveiller le fournisseur, journaliser les transitions"),
            description=tr("""
Un lien peut rester « monté » alors que plus rien ne passe : keepalived ne le voit pas. Un **script
de test** lui donne un critère de plus (cf. section @@ref:tracking@@).

1. Sur `r1` et `r2`, écrivez `{check}` : il se termine avec le code 0 si `isp` (`{isp}`) répond à
   **un** `ping` en moins d'une seconde, avec un autre code sinon. Rendez-le exécutable ; il doit
   appartenir à `root`.
2. Déclarez-le dans keepalived (`vrrp_script`) : lancé toutes les {interval} s, {fall} échecs
   consécutifs pour le déclarer en panne, {rise} succès pour le déclarer rétabli. Faites-le suivre
   par le groupe, **sans poids**. Dans `global_defs`, ajoutez `enable_script_security` et
   `script_user root`.
3. Écrivez `{notify}` : à chaque transition il ajoute à `{log}` une ligne contenant ses quatre
   arguments (type, nom, nouvel état, priorité). Faites-le appeler par le groupe (`notify`).
4. `keepalived -t && systemctl reload keepalived`.

Essai : sur `isp`, ignorez les `ping` de `r1`, observez la bascule (journal, `{log}`,
`curl http://{vip}/` depuis `pc1`), puis retirez la règle.
""").format(check=CHECK_SCRIPT, isp=isp4, interval=CHECK_INTERVAL, fall=CHECK_FALL, rise=CHECK_RISE,
            notify=NOTIFY_SCRIPT, log=NOTIFY_LOG, vip=vip)
            + tr("""
```
nft add table ip essai
nft 'add chain ip essai input { type filter hook input priority 0; }'
nft add rule ip essai input ip saddr ADRESSE_WAN_DE_R1 icmp type echo-request drop
nft delete table ip essai
```
""")
            + instructor(tr("""
**Solution.** `{check}` (mode 755) :

```
{check_text}
```

`{notify}` (mode 755) :

```
{notify_text}
```

`{conf}` sur `r1` (le groupe suit le script et appelle la notification) :

```
{r1_conf}
```

`isp` muet pour `r1` (`{r1_wan}`) : après {fall} échecs (4 à 6 s) le journal de `r1` affiche
`VRRP_Script({name}) failed` puis `Syncing instances to FAULT state`, `r2` devient maître et
`{log}` reçoit `GROUP {group} FAULT 0` sur `r1`, `GROUP {group} MASTER 0` sur `r2` (un groupe n'a
pas de priorité : 0). Règle retirée, `r1` revient après {rise} succès et reprend la main.
""").format(check=CHECK_SCRIPT, check_text=conf_code(self.net_scheme.check_script()), notify=NOTIFY_SCRIPT,
            notify_text=conf_code(self.net_scheme.notify_script()), conf=KEEPALIVED_CONF,
            r1_conf=conf_code(self.net_scheme.keepalived_conf('r1', part=3)), r1_wan=wan_ip['r1'],
            fall=CHECK_FALL,
            rise=CHECK_RISE, name=CHECK_NAME, group=GROUP, log=NOTIFY_LOG)),
        )

        q7_answers = {"effective": str(PRIORITY_MASTER - 60), "master": "r2", "in_group": "ignored", "state": "FAULT"}
        q7 = self.question_form(
            section=self.section(0),
            title=tr("Poids d'un script et groupe de synchronisation"),
            description=tr("""
Un script suivi peut avoir un **poids** (cf. section @@ref:tracking@@). Imaginez `VI_LAN` **hors de
tout groupe**, suivant le script avec `weight -60` : `r1` a la priorité {master}, `r2` la priorité
{backup}, et le script échoue sur `r1` seulement.
""").format(master=PRIORITY_MASTER, backup=PRIORITY_BACKUP)
            + tr("""
- priorité que r1 annonce alors : @@{effective:[0-9]+}@@
- qui est maître ? @@{master:>r1>>>r1|r2>>>r2}@@
- et dans un groupe de synchronisation, le poids d'un script suivi est : @@{in_group:>appliqué comme hors groupe>>>applied|ignoré : keepalived le ramène à 0>>>ignored|refusé : keepalived ne démarre pas>>>refused}@@
- état des instances du groupe sur r1 quand le script, suivi sans poids, échoue : @@{state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""")
            + instructor(tr("""
**Solution.** Hors groupe, un poids négatif est retranché de la priorité tant que le script
échoue : `r1` annonce {master} − 60 = **{effective}**, inférieur à {backup} ; `r2` le préempte
et devient maître, `r1` reste secours (il n'est pas en panne, seulement moins prioritaire). Dans un
groupe, les poids sont ramenés à 0 : un script suivi sans poids met les instances à l'état
**FAULT**. C'est la forme à utiliser dans un groupe.
""").format(master=PRIORITY_MASTER, backup=PRIORITY_BACKUP, effective=PRIORITY_MASTER - 60)),
            cheat_answers={"final": q7_answers},
        )

        def script_file(r, path):
            mode = archive_mode(files[r], path)
            return path.startswith(KEEPALIVED_DIR + '/') and mode is not None and bool(mode & 0o100)

        def check_tracked(r):
            entries = tracked_scripts(conf[r], inst(r, d.vrid_lan))
            return any(e['weight'] == 0 and e['script'] and script_file(r, (e['script']['script'] or '').split()[0])
                       for e in entries if e['script'] and e['script']['script'])

        def check_timers(r):
            entries = [e['script'] for e in tracked_scripts(conf[r], inst(r, d.vrid_lan)) if e['script']]
            return any((s['interval'], s['fall'], s['rise']) == (CHECK_INTERVAL, CHECK_FALL, CHECK_RISE)
                       for s in entries)

        def notified(r):
            return any(script_file(r, path) for path in notify_paths(conf[r], inst(r, d.vrid_lan)))

        self.add_grade_element(
            title=no_tr("check_config"), max_grade=3, grade_part=part3,
            grade=(int(all(script_file(r, CHECK_SCRIPT) for r in ROUTERS))
                   + int(all(check_timers(r) for r in ROUTERS)) + int(all(check_tracked(r) for r in ROUTERS))),
            description=tr("script {check} exécutable (r1, r2) ; vrrp_script toutes les {interval} s, {fall} échecs, "
                           "{rise} succès ; suivi sans poids par le groupe")
            .format(check=CHECK_SCRIPT, interval=CHECK_INTERVAL, fall=CHECK_FALL, rise=CHECK_RISE),
        )
        self.add_grade_element(
            title=no_tr("notify_config"), max_grade=2, grade_part=part3,
            grade=sum(int(notified(r)) for r in ROUTERS),
            description=tr("script de notification exécutable sous {dir}, appelé par le groupe (r1, r2)")
            .format(dir=KEEPALIVED_DIR),
        )
        self.add_grade_element(
            title=no_tr("check_mirror"), max_grade=4, grade_part=part3,
            grade=2 * int(moved(vip, 'r1', 4, 'r2', 6)) + int(moved(vip, 'r1', 4, 'r2', 6) and not held(6, 'r1', vip))
            + int(moved(vip, 'r1', 4, 'r2', 6) and served(6, 'pc1', 'r2')),
            description=tr("copie cachée, isp ne répond plus aux ping de r1 : r2 prend {vip}, r1 la rend, r2 répond "
                           "à pc1").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("notify_mirror"), max_grade=3, grade_part=part3,
            grade=2 * int('MASTER' in notify_states(m_log.get('r2', [])))
            + int('FAULT' in notify_states(m_log.get('r1', []))),
            description=tr("copie cachée : {log} contient la transition MASTER sur r2 et la transition FAULT sur r1")
            .format(log=NOTIFY_LOG),
        )
        self.add_grade_element(
            title=no_tr("check_form"), max_grade=2, grade_part=part3, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_digits(q7.get("effective")) == str(PRIORITY_MASTER - 60))
                         + int(_norm(q7.get("master")) == "r2") + int(_norm(q7.get("in_group")) == "ignored")
                         + int(_norm(q7.get("state")) == "fault")),
            description=tr("poids d'un script : priorité 90 et r2 maître hors groupe ; ignoré dans un groupe ; "
                           "état FAULT sans poids"),
        )

        # =====================================================================
        # Part 4 — authentication and unicast peers (questions 8 and 9)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Authentification et homologues en unicast "
                                                       "(questions 8 et 9)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Protéger les annonces"),
            description=tr("""
N'importe quelle machine du réseau local peut émettre une annonce de priorité 255 et se faire élire
maître (cf. section @@ref:security@@).

1. Dans `VI_LAN`, sur `r1` et `r2`, ajoutez une authentification par mot de passe (`auth_type PASS`)
   avec le mot de passe `{password}`.
2. Dans `VI_WAN`, n'envoyez plus les annonces au groupe de diffusion mais **en unicast** à l'autre
   routeur : adresse source `{r1_wan}` et homologue `{r2_wan}` sur `r1`, l'inverse sur `r2`.
3. `keepalived -t && systemctl reload keepalived` sur les deux routeurs (l'un après l'autre : tant
   qu'un seul des deux a le mot de passe, chacun ignore les annonces de l'autre).

Capturez de nouveau sur `pc1` (`tcpdump -n -v -i eth0 vrrp`) et sur `isp` (même commande).
""").format(password=d.auth_pass, r1_wan=wan_ip['r1'], r2_wan=wan_ip['r2'])
            + instructor(tr("""
**Solution.** Dans `VI_LAN` (les deux routeurs) et dans `VI_WAN` (ici sur `r1`, adresses inversées
sur `r2`) :

```
{snippet}
```

La capture sur `pc1` montre `authtype simple` et le mot de passe **en clair** (`auth "{password}"`) ;
celle de `isp` montre `{r1_wan} > {r2_wan}` au lieu de `224.0.0.18`. Une annonce sans mot de passe
est rejetée (`received a 0 auth, expecting 1!` dans le journal). L'évaluation en émet depuis la
copie cachée de `pc1`, avec la priorité 255 : `r1` doit garder `{vip}`.
""").format(snippet=conf_code(
                f"vrrp_instance {VI_LAN} {{\n    ...\n    authentication {{\n        auth_type PASS\n"
                f"        auth_pass {d.auth_pass}\n    }}\n}}\n\nvrrp_instance {VI_WAN} {{\n    ...\n"
                f"    unicast_src_ip {wan_ip['r1']}\n    unicast_peer {{\n        {wan_ip['r2']}\n    }}\n}}\n"),
            password=d.auth_pass, r1_wan=wan_ip['r1'], r2_wan=wan_ip['r2'], vip=vip)),
        )

        q9_answers = {"auth_seen": "clear", "forged": "ignored", "wan_dst": str(wan_ip['r2']), "v3": "no"}
        q9 = self.question_form(
            section=self.section(0),
            title=tr("Ce que montre une capture"),
            description=tr("""
D'après vos captures et la section @@ref:security@@ :
""")
            + tr("""
- dans une annonce de VI_LAN, la capture montre : @@{auth_seen:>le mot de passe en clair>>>clear|une empreinte du mot de passe>>>hash|rien : l'annonce est chiffrée>>>encrypted}@@
- une annonce de priorité 255 **sans** mot de passe reçue par r1 est : @@{forged:>ignorée : r1 reste maître>>>ignored|acceptée : r1 devient secours>>>accepted}@@
- adresse de destination des annonces de VI_WAN émises par r1 : @@{wan_dst:[0-9.]+}@@
- VRRPv3 prévoit-il une authentification ? @@{v3:>oui>>>yes|non>>>no}@@
""")
            + instructor(tr("""
**Solution.** Le mot de passe circule en clair : il protège d'une erreur de configuration ou d'un
équipement bavard, pas d'un attaquant qui écoute le réseau (la RFC 3768 a d'ailleurs retiré
l'authentification de VRRPv2, et VRRPv3 n'en a pas). Une annonce sans mot de passe est ignorée.
Les annonces de `VI_WAN` vont à `{r2_wan}`.
""").format(r2_wan=wan_ip['r2'])),
            cheat_answers={"final": q9_answers},
        )

        def authenticated(r):
            instance = inst(r, d.vrid_lan)
            return (bool(instance) and (instance['auth_type'] or '').upper() == 'PASS'
                    and instance['auth_pass'] == d.auth_pass)

        def unicast(r):
            instance = inst(r, d.vrid_wan)
            return (bool(instance) and instance['unicast_src_ip'] == str(wan_ip[r])
                    and instance['unicast_peers'] == [str(wan_ip[peer[r]])])

        wan_adverts = adverts(wan_frames, vrid=d.vrid_wan)
        forged_seen = forged['sent'] >= 3 and len(forge_samples) == len(FORGE_SAMPLES)
        self.add_grade_element(
            title=no_tr("auth_config"), max_grade=2, grade_part=part4,
            grade=sum(int(authenticated(r)) for r in ROUTERS),
            description=tr("VI_LAN : auth_type PASS avec le mot de passe de l'instance (r1, r2)"),
        )
        self.add_grade_element(
            title=no_tr("auth_live"), max_grade=2, grade_part=part4,
            grade=2 * int(bool(lan_adverts) and all(f['auth_type'] == 'simple' and f['password'] == d.auth_pass
                                                    for f in lan_adverts)),
            description=tr("sur la maquette : les annonces de VI_LAN portent le mot de passe"),
        )
        self.add_grade_element(
            title=no_tr("auth_mirror"), max_grade=3, grade_part=part4,
            grade=3 * int(forged_seen and all(any(_holds4(sample[r], vip) for r in ROUTERS)
                                              for sample in forge_samples)),
            description=tr("copie cachée : pendant de fausses annonces de priorité 255 sans mot de passe, un "
                           "routeur garde {vip}").format(vip=vip),
        )
        self.add_grade_element(
            title=no_tr("unicast_config"), max_grade=2, grade_part=part4,
            grade=sum(int(unicast(r)) for r in ROUTERS),
            description=tr("VI_WAN : unicast_src_ip et unicast_peer vers l'autre routeur (r1, r2)"),
        )
        self.add_grade_element(
            title=no_tr("unicast_live"), max_grade=1, grade_part=part4,
            grade=int(bool(wan_adverts) and not any(is_multicast_advert(f) for f in wan_adverts)
                      and all({f['src'], f['dst']} == {str(wan_ip['r1']), str(wan_ip['r2'])} for f in wan_adverts)),
            description=tr("sur la maquette : les annonces de VI_WAN vont d'un routeur à l'autre, plus au groupe "
                           "224.0.0.18"),
        )
        self.add_grade_element(
            title=no_tr("secure_form"), max_grade=2, grade_part=part4, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_norm(q9.get("auth_seen")) == "clear") + int(_norm(q9.get("forged")) == "ignored")
                         + int(_same_ip(q9.get("wan_dst"), wan_ip['r2'])) + int(_norm(q9.get("v3")) == "no")),
            description=tr("mot de passe en clair, annonce sans mot de passe ignorée, destination unicast, pas "
                           "d'authentification en VRRPv3"),
        )

        # =====================================================================
        # Part 5 — load sharing (questions 10 and 11)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Partage de charge (questions 10 et 11)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Une deuxième passerelle virtuelle, dont r2 est le maître"),
            description=tr("""
Avec une seule adresse virtuelle, `r2` ne sert à rien tant que `r1` fonctionne. Répartissez la
charge (cf. section @@ref:load-sharing@@) avec une deuxième instance sur `eth0` : VRID **{vrid}**,
adresse virtuelle `{vip}`, dont **`r2` est le maître** (priorité {master}) et `r1` le secours
(priorité {backup}).

1. Ajoutez l'instance sur les deux routeurs ; elle ne fait **pas** partie du groupe.
2. Si le lien `eth1` de `r2` tombe, `r2` ne doit pas garder cette passerelle : faites suivre
   l'interface `eth1` par l'instance (`track_interface`), sur les deux routeurs.
3. `keepalived -t && systemctl reload keepalived`, puis sur `pc2` :
   `ip route replace default via {vip_ip}`.

Vérifiez depuis `pc2` : `curl http://{vip_ip}/` (qui répond ?), `curl http://{isp}/`, puis
`ip link set eth1 down` sur `r2` et de nouveau les deux `curl`. Rétablissez le lien.
""").format(vrid=d.vrid_lan2, vip=d.ips.vip_lan2, vip_ip=vip2, master=PRIORITY_MASTER, backup=PRIORITY_BACKUP,
            isp=isp4)
            + instructor(tr("""
**Solution.** Sur `r2` (sur `r1` : `state BACKUP`, `priority {backup}`) :

```
{snippet}
```

Sur `pc2` : `ip route replace default via {vip_ip}`. En temps normal `r1` achemine le trafic de
`pc1` et `r2` celui de `pc2` ; chacun secourt l'autre. Lien `eth1` de `r2` coupé : l'instance passe
à l'état FAULT (interface suivie sans poids), `r1` prend `{vip_ip}` en moins d'une seconde et `pc2`
joint toujours `isp`.
""").format(backup=PRIORITY_BACKUP, vip_ip=vip2, snippet=conf_code(
                f"vrrp_instance {VI_LAN2} {{\n    interface eth0\n    virtual_router_id {d.vrid_lan2}\n"
                f"    state MASTER\n    priority {PRIORITY_MASTER}\n    advert_int {ADVERT_INT}\n"
                f"    track_interface {{\n        eth1\n    }}\n    virtual_ipaddress {{\n"
                f"        {d.ips.vip_lan2}\n    }}\n}}\n"))),
        )

        q11_answers = {"nominal": "split", "after": "r1"}
        q11 = self.question_form(
            section=self.section(0),
            title=tr("Qui achemine quoi ?"),
            description=tr("""
Avec les deux passerelles virtuelles en place :
""")
            + tr("""
- en fonctionnement normal : @@{nominal:>r1 achemine le trafic de pc1, r2 celui de pc2>>>split|r1 achemine tout>>>r1|r2 achemine tout>>>r2}@@
- keepalived arrêté sur r2 : @@{after:>r1 achemine le trafic des deux clients>>>r1|r1 achemine celui de pc1, pc2 n'a plus de passerelle>>>none|r2 continue d'acheminer celui de pc2>>>r2}@@
""")
            + instructor(tr("""
**Solution.** Chaque routeur est maître d'une passerelle et secours de l'autre : la charge est
répartie entre les clients, par leur route par défaut, et `r1` reprend les deux adresses si `r2`
s'arrête. Le partage est statique : c'est l'administrateur (ou le serveur DHCP) qui répartit les
clients entre les deux passerelles.
""")),
            cheat_answers={"final": q11_answers},
        )

        def tracks_wan(r):
            return any(e['name'] == 'eth1' for e in tracked_interfaces(conf[r], inst(r, d.vrid_lan2)))

        self.add_grade_element(
            title=no_tr("lan2_config"), max_grade=3, grade_part=part5,
            grade=sum(int(instance_on(r, d.vrid_lan2, vip2)) for r in ROUTERS) + int(priorities(d.vrid_lan2, 'r2')),
            description=tr("instance de VRID {vrid} sur eth0 avec l'adresse {vip} (r1, r2) ; r2 prioritaire")
            .format(vrid=d.vrid_lan2, vip=vip2),
        )
        self.add_grade_element(
            title=no_tr("lan2_track"), max_grade=1, grade_part=part5,
            grade=int(all(tracks_wan(r) for r in ROUTERS)),
            description=tr("la deuxième instance suit l'interface eth1 (r1, r2)"),
        )
        self.add_grade_element(
            title=no_tr("lan2_live"), max_grade=2, grade_part=part5,
            grade=int(live_only('r2', vip2))
            + int(default_gateway('pc2') == str(vip2) and live_gw['pc2'].get('server') == 'r2'),
            description=tr("sur la maquette : {vip} sur r2 seul ; pc2 passe par {vip} et r2 lui répond")
            .format(vip=vip2),
        )
        self.add_grade_element(
            title=no_tr("lan2_mirror_nominal"), max_grade=2, grade_part=part5,
            grade=int(only(2, 'r2', vip2)) + int(served(2, 'pc2', 'r2') and through(2, 'pc2')),
            description=tr("copie cachée, état nominal : {vip} sur r2 seul ; pc2 passe par r2 et joint isp")
            .format(vip=vip2),
        )
        self.add_grade_element(
            title=no_tr("lan2_mirror_track"), max_grade=3, grade_part=part5,
            grade=2 * int(moved(vip2, 'r2', 2, 'r1', 5)) + int(moved(vip2, 'r2', 2, 'r1', 5) and through(5, 'pc2')),
            description=tr("copie cachée, lien WAN de r2 coupé : r1 prend {vip} ; pc2 joint toujours isp")
            .format(vip=vip2),
        )
        self.add_grade_element(
            title=no_tr("lan2_form"), max_grade=1, grade_part=part5, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_norm(q11.get("nominal")) == "split") + int(_norm(q11.get("after")) == "r1")),
            description=tr("partage de charge : un routeur par client, r1 reprend tout si r2 s'arrête"),
        )

        # =====================================================================
        # Part 6 — virtual MAC address (questions 12 and 13)
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Adresse MAC virtuelle (questions 12 et 13)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("use_vmac sur la deuxième passerelle"),
            description=tr("""
À chaque bascule, les clients doivent apprendre la nouvelle adresse MAC de leur passerelle : le
nouveau maître la leur annonce par des ARP gratuits. Avec une **adresse MAC virtuelle**, propre au
routeur virtuel, rien ne change pour eux (cf. section @@ref:vmac@@).

1. Dans la deuxième instance (VRID {vrid}), sur `r1` et `r2`, ajoutez `use_vmac`, puis
   **redémarrez** keepalived : `systemctl restart keepalived`.
2. Observez : sur les deux routeurs, `ip -d link show` et `ip -br addr` (quelle interface est
   apparue, où est `{vip_ip}` ?) ; sur `pc2`, `ip neigh flush all`, `ping -c 2 {vip_ip}` puis
   `ip neigh show {vip_ip}` ; sur `pc1`, `tcpdump -e -n -i eth0 vrrp` (adresses MAC sources).
3. Arrêtez keepalived sur `r2`, relisez l'entrée de `pc2`, puis redémarrez-le. Comparez avec
   l'entrée de `pc1` pour `{vip1}` quand le groupe bascule.
""").format(vrid=d.vrid_lan2, vip_ip=vip2, vip1=vip)
            + instructor(tr("""
**Solution.** Une ligne `use_vmac` dans l'instance `{name}` des deux routeurs, et
`systemctl restart keepalived`. keepalived crée sur **chaque** routeur, maître ou secours,
l'interface `{iface}` (un macvlan sur `eth0`) d'adresse MAC `{vmac}` ; l'adresse `{vip_ip}` y est
posée sur le maître, et les annonces de ce routeur virtuel partent avec cette adresse MAC pour
source. `pc2` associe `{vip_ip}` à `{vmac}`, avant comme après la bascule, alors que l'entrée de
`pc1` pour `{vip1}` passe de l'adresse MAC de `r1` à celle de `r2`. Le commutateur, lui, apprend que
`{vmac}` a changé de port à la première annonce du nouveau maître.
""").format(name=VI_LAN2, iface=vmac_iface, vmac=vmac, vip_ip=vip2, vip1=vip)),
        )

        q13_answers = {"vmac": vmac, "iface": vmac_iface, "arp_vip2": "same", "arp_vip1": "r2"}
        q13 = self.question_form(
            section=self.section(0),
            title=tr("Ce qui change, ce qui ne change pas"),
            description=tr("""
D'après vos observations :
""")
            + tr("""
- adresse MAC virtuelle de la deuxième passerelle : @@{vmac:[0-9a-fA-F:-]+}@@
- interface créée par keepalived sur r1 et r2 : @@{iface:[A-Za-z0-9._-]+}@@
- deuxième passerelle : quand elle passe de r2 à r1, l'entrée ARP de pc2 : @@{arp_vip2:>ne change pas>>>same|devient l'adresse MAC de r1>>>r1}@@
- première passerelle (sans use_vmac) : quand elle passe de r1 à r2, l'entrée ARP de pc1 : @@{arp_vip1:>ne change pas>>>same|devient l'adresse MAC de r2>>>r2}@@
""")
            + instructor(tr("""
**Solution.** L'adresse MAC d'un routeur virtuel IPv4 est `00:00:5e:00:01:XX`, où `XX` est le VRID
en hexadécimal : ici `{vmac}` (VRID {vrid}), sur l'interface `{iface}`. Elle suit la passerelle
d'un routeur à l'autre : les caches ARP des clients restent valables. Sans `use_vmac`, l'adresse
virtuelle prend l'adresse MAC du routeur qui la détient, et les clients doivent être prévenus.
""").format(vmac=vmac, vrid=d.vrid_lan2, iface=vmac_iface)),
            cheat_answers={"final": q13_answers},
        )

        def vmac_holder(r):
            interface = interface_of_address(addr4[r], vip2)
            return interface is not None and normalize_mac(links[r].get(interface, {}).get('address', '')) == vmac

        lan2_adverts = adverts(lan_frames, vrid=d.vrid_lan2)
        on_vmac = any(vmac_holder(r) for r in ROUTERS)
        self.add_grade_element(
            title=no_tr("vmac_config"), max_grade=2, grade_part=part6,
            grade=sum(int(bool(inst(r, d.vrid_lan2)) and inst(r, d.vrid_lan2)['use_vmac']) for r in ROUTERS),
            description=tr("use_vmac dans la deuxième instance (r1, r2)"),
        )
        self.add_grade_element(
            title=no_tr("vmac_live"), max_grade=3, grade_part=part6,
            # the cache of pc2 only counts while a router does hold the address on a macvlan (an
            # old entry survives the removal of the configuration)
            grade=(int(on_vmac)
                   + int(bool(lan2_adverts) and all(f['src_mac'] == vmac for f in lan2_adverts))
                   + int(on_vmac and neigh_lladdr(neigh_pc2, vip2) == vmac)),
            description=tr("sur la maquette : {vip} sur une interface d'adresse MAC {vmac} ; annonces émises depuis "
                           "cette adresse ; pc2 l'associe à {vip}").format(vip=vip2, vmac=vmac),
        )
        self.add_grade_element(
            title=no_tr("vmac_mirror"), max_grade=3, grade_part=part6,
            grade=int(bool(m_arp.get(2)) and set(m_arp[2]) == {vmac})
            + 2 * int(bool(m_arp.get(5)) and set(m_arp[5]) == {vmac}),
            description=tr("copie cachée : la requête ARP pour {vip} reçoit {vmac}, avant la bascule et après")
            .format(vip=vip2, vmac=vmac),
        )
        self.add_grade_element(
            title=no_tr("vmac_form"), max_grade=2, grade_part=part6, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_same_mac(q13.get("vmac"), vmac)) + int(_norm(q13.get("iface")) == vmac_iface)
                         + int(_norm(q13.get("arp_vip2")) == "same") + int(_norm(q13.get("arp_vip1")) == "r2")),
            description=tr("adresse MAC virtuelle, interface macvlan, cache ARP inchangé avec use_vmac"),
        )

        # =====================================================================
        # Part 7 — VRRPv3 and IPv6 (questions 14 and 15)
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — VRRPv3 et IPv6 (questions 14 et 15)"))

        self.question_dummy(
            section=self.section(0),
            title=tr("Une passerelle IPv6 : VRRPv3 et annonces de routeur"),
            description=tr("""
Un client IPv6 apprend sa passerelle par les annonces de routeur (RA) : c'est l'adresse
**lien-local** dont part l'annonce. Pour qu'elle survive à une panne, cette adresse doit être
virtuelle (cf. section @@ref:vrrpv3-ipv6@@).

1. Sur `r1` et `r2`, ajoutez une instance sur `eth0` : VRID **{vrid}**, adresse virtuelle
   `{vip6}/64`, `r1` maître (priorité {master}), `r2` secours (priorité {backup}). Une instance IPv6
   est en VRRPv3. Ajoutez-la au groupe.
2. Le retour a lui aussi besoin d'une adresse virtuelle IPv6 côté `wan` : ajoutez `{vip6_wan}` à
   l'instance `VI_WAN`, dans un bloc `virtual_ipaddress_excluded` (une instance n'annonce qu'une
   famille d'adresses).
3. Sur `r1` et `r2`, écrivez `{radvd}` : annonces sur `eth0` du préfixe `{lan6}`, émises **depuis
   l'adresse virtuelle** (`AdvRASrcAddress`). Puis `systemctl enable --now radvd` et
   `keepalived -t && systemctl reload keepalived`.
4. Sur `isp` : `ip -6 route replace {lan6} via {vip6_wan_ip}`.

Vérifiez sur `pc1` : `ip -6 route` (la route par défaut), `ping {isp6}` et
`tcpdump -n -v -i eth0 'ip6 proto 112'` ; puis coupez `eth0` sur `r1` et recommencez le `ping`.
""").format(vrid=d.vrid_lan6, vip6=VIP6_LAN, master=PRIORITY_MASTER, backup=PRIORITY_BACKUP,
            vip6_wan=d.ips6.vip_wan, vip6_wan_ip=vip6_wan, radvd=RADVD_CONF, lan6=d.nets6.lan, isp6=isp6)
            + instructor(tr("""
**Solution.** Dans `{conf}` de `r1` (sur `r2` : `state BACKUP`, `priority {backup}`), l'instance
IPv6, ajoutée à la liste `group` de `{group}`, et le bloc ajouté à `{wan}` :

```
{snippet}
```

`{radvd}`, identique sur les deux routeurs :

```
{radvd_text}
```

Sur `isp` : `ip -6 route replace {lan6} via {vip6_wan_ip}`. `pc1` reçoit
`default via {vip6} dev eth0 proto ra`. Seul le maître détient `{vip6}` : le radvd du secours, qui
ne trouve pas son adresse source, reste silencieux, sans erreur. À la bascule, le nouveau maître
émet une annonce de voisin non sollicitée pour `{vip6}` et `pc1` continue de joindre `isp`.
""").format(conf=KEEPALIVED_CONF, backup=PRIORITY_BACKUP, group=GROUP, wan=VI_WAN, radvd=RADVD_CONF,
            radvd_text=conf_code(self.net_scheme.radvd_conf()), lan6=d.nets6.lan, vip6_wan_ip=vip6_wan,
            vip6=VIP6_LAN,
            snippet=conf_code(
                f"vrrp_instance {VI_LAN6} {{\n    interface eth0\n    version 3\n"
                f"    virtual_router_id {d.vrid_lan6}\n    state MASTER\n    priority {PRIORITY_MASTER}\n"
                f"    advert_int {ADVERT_INT}\n    virtual_ipaddress {{\n        {VIP6_LAN}/64\n    }}\n}}\n\n"
                f"vrrp_instance {VI_WAN} {{\n    ...\n    virtual_ipaddress_excluded {{\n"
                f"        {d.ips6.vip_wan}\n    }}\n}}\n"))),
        )

        q15_answers = {"group6": VRRP_GROUP6, "interval": "cs", "announce": "na", "ra_src": VIP6_LAN}
        q15 = self.question_form(
            section=self.section(0),
            title=tr("VRRPv3 vu dans une capture"),
            description=tr("""
D'après vos captures sur `pc1` (`tcpdump -n -v -i eth0 'ip6 proto 112'`, puis
`tcpdump -n -v -i eth0 icmp6`) :
""")
            + tr("""
- adresse de destination des annonces VRRPv3 en IPv6 : @@{group6:[0-9a-fA-F:]+}@@
- intervalle affiché par tcpdump dans une annonce VRRPv3 : @@{interval:>1s>>>s|100cs>>>cs|1000ms>>>ms}@@
- après une bascule, les voisins IPv6 sont prévenus par : @@{announce:>un ARP gratuit>>>garp|une annonce de voisin (NA) non sollicitée>>>na|une annonce de routeur (RA)>>>ra}@@
- adresse source des annonces de routeur reçues par pc1 : @@{ra_src:[0-9a-fA-F:]+}@@
""")
            + instructor(tr("""
**Solution.** VRRPv3 (RFC 5798) envoie ses annonces à `ff02::12`, avec une limite de sauts de 255,
et exprime l'intervalle en centisecondes (`intvl 100cs`), ce qui permet des bascules en moins d'une
seconde. Il n'y a pas d'ARP en IPv6 : le nouveau maître émet une annonce de voisin non sollicitée.
Les annonces de routeur partent de `{vip6}`, que `pc1` prend pour passerelle.
""").format(vip6=VIP6_LAN)),
            cheat_answers={"final": q15_answers},
        )

        def grouped6(r):
            first, sixth = inst(r, d.vrid_lan), inst(r, d.vrid_lan6)
            group = instance_group(conf[r], first)
            return bool(first and sixth and group) and sixth['name'] in group['members']

        def wan_address6(r):
            instance = inst(r, d.vrid_wan)
            return bool(instance) and str(vip6_wan) in instance_addresses(instance, excluded=True)

        def ra_source(r):
            match = re.search(r'AdvRASrcAddress\s*\{([^}]*)\}', archive_text(files[r], RADVD_CONF))
            return bool(match) and any(_same_ip(word, VIP6_LAN) for word in match[1].replace(';', ' ').split())

        lan6 = d.nets6.lan
        lan6_adverts = adverts(lan_frames, vrid=d.vrid_lan6, version=3)
        defaults6 = default_routes6(routes6['pc1'])
        self.add_grade_element(
            title=no_tr("v6_config"), max_grade=3, grade_part=part7,
            grade=sum(int(instance_on(r, d.vrid_lan6, VIP6_LAN)) for r in ROUTERS)
            + int(all(grouped6(r) for r in ROUTERS)),
            description=tr("instance de VRID {vrid} sur eth0 avec l'adresse {vip6} (r1, r2), membre du groupe")
            .format(vrid=d.vrid_lan6, vip6=VIP6_LAN),
        )
        self.add_grade_element(
            title=no_tr("v6_wan"), max_grade=2, grade_part=part7,
            grade=int(all(wan_address6(r) for r in ROUTERS))
            + int(any(r['dst'] == str(lan6) and r['gateway'] == vip6_wan for r in routes6['isp'])),
            description=tr("{vip6} dans virtual_ipaddress_excluded de VI_WAN (r1, r2) ; route IPv6 de isp vers le "
                           "réseau local par cette adresse").format(vip6=vip6_wan),
        )
        self.add_grade_element(
            title=no_tr("v6_radvd"), max_grade=2, grade_part=part7,
            grade=int(all(ra_source(r) for r in ROUTERS))
            + int(all(radvd_unit[r]['active'] == 'active' for r in ROUTERS)),
            description=tr("radvd.conf avec AdvRASrcAddress {vip6} (r1, r2) ; radvd actif sur les deux")
            .format(vip6=VIP6_LAN),
        )
        self.add_grade_element(
            title=no_tr("v6_live"), max_grade=3, grade_part=part7,
            grade=(int(live_only('r1', VIP6_LAN))
                   + int(bool(lan6_adverts) and all(f['dst'] == VRRP_GROUP6 for f in lan6_adverts))
                   + int(any(r['gateway'] == IPv6Address(VIP6_LAN) and r['protocol'] == 'ra' for r in defaults6)
                         and live_ping6)),
            description=tr("sur la maquette : {vip6} sur r1 seul ; annonces VRRPv3 vers ff02::12 ; pc1 a reçu sa "
                           "route par défaut de {vip6} et joint isp en IPv6").format(vip6=VIP6_LAN),
        )
        self.add_grade_element(
            title=no_tr("v6_mirror_nominal"), max_grade=2, grade_part=part7,
            grade=int(any(ra.src == IPv6Address(VIP6_LAN) and ra.router_lifetime > 0 for ra in ras))
            + int(bool(m_ping6.get(2))),
            description=tr("copie cachée, état nominal : annonce de routeur émise depuis {vip6} ; pc1 joint isp en "
                           "IPv6").format(vip6=VIP6_LAN),
        )
        self.add_grade_element(
            title=no_tr("v6_mirror_failover"), max_grade=2, grade_part=part7,
            grade=int(moved(VIP6_LAN, 'r1', 2, 'r2', 3))
            + int(moved(VIP6_LAN, 'r1', 2, 'r2', 3) and bool(m_ping6.get(3))),
            description=tr("copie cachée, lien LAN de r1 coupé : r2 prend {vip6} ; pc1 joint toujours isp en IPv6")
            .format(vip6=VIP6_LAN),
        )
        self.add_grade_element(
            title=no_tr("v6_form"), max_grade=2, grade_part=part7, scope=params.EXO_EVAL_SCOPE,
            grade=0.5 * (int(_same_ip(q15.get("group6"), VRRP_GROUP6)) + int(_norm(q15.get("interval")) == "cs")
                         + int(_norm(q15.get("announce")) == "na") + int(_same_ip(q15.get("ra_src"), VIP6_LAN))),
            description=tr("VRRPv3 : groupe ff02::12, intervalle en centisecondes, annonce de voisin, RA depuis "
                           "l'adresse virtuelle"),
        )


_TRANSLATIONS = {
    'en': {
        'VRRP et keepalived : redondance de la passerelle': 'VRRP and keepalived: gateway redundancy',
        """**Sommaire**
""": """**Contents**
""",
        'Pourquoi une passerelle redondante ?': 'Why a redundant gateway?',
        """
Un poste ne connaît en général qu'une route : sa **passerelle par défaut**. Si ce routeur tombe,
tout le réseau local est coupé du reste du monde, même s'il existe un second routeur juste à côté :
les postes ne le connaissent pas. La passerelle est un **point de défaillance unique**.

Plutôt que de faire tourner un protocole de routage sur chaque poste, on rend la passerelle
elle-même redondante : plusieurs routeurs se partagent **une adresse IP virtuelle**, que les postes
utilisent comme passerelle. À un instant donné un seul routeur détient cette adresse ; s'il
disparaît, un autre la reprend en quelques secondes, sans que les postes changent quoi que ce soit.

Les protocoles de cette famille (*First Hop Redundancy Protocols*) sont **VRRP** (*Virtual Router
Redundancy Protocol*, standard de l'IETF : RFC 3768 pour la version 2, RFC 5798 pour la version 3),
HSRP et GLBP (Cisco) et CARP (BSD). Sous Linux, VRRP est mis en œuvre par **keepalived**.
""": """
A host usually knows a single route: its **default gateway**. If that router fails, the whole
local network is cut off from the rest of the world, even when a second router sits right next to
it: the hosts do not know about it. The gateway is a **single point of failure**.

Rather than running a routing protocol on every host, the gateway itself is made redundant:
several routers share **one virtual IP address**, which the hosts use as their gateway. At any
time a single router holds that address; if it disappears, another one takes it over within a few
seconds, and the hosts change nothing.

The protocols of this family (*First Hop Redundancy Protocols*) are **VRRP** (*Virtual Router
Redundancy Protocol*, an IETF standard: RFC 3768 for version 2, RFC 5798 for version 3), HSRP and
GLBP (Cisco) and CARP (BSD). On Linux, VRRP is implemented by **keepalived**.
""",
        'Le protocole VRRP': 'The VRRP protocol',
        """
### @@sec@@ Routeur virtuel, maître et secours

Un **routeur virtuel** est défini, sur un réseau local, par un identifiant, le **VRID** (de 1 à
255), et par une ou plusieurs adresses IP virtuelles. Les routeurs réels qui y participent ont
chacun une **priorité** (de 1 à 254, 100 par défaut). Le plus prioritaire est le **maître**
(*master*) : il détient les adresses virtuelles, répond aux requêtes ARP qui les concernent et
achemine le trafic. Les autres sont **secours** (*backup*) : ils écoutent.

Deux priorités sont réservées : **255** désigne le routeur dont l'adresse virtuelle est la propre
adresse d'interface (le « propriétaire »), et **0** est la valeur que le maître annonce quand il se
retire volontairement.

### @@sec@@ Les annonces

Le maître émet régulièrement une **annonce** (*advertisement*) ; les secours n'émettent rien.

| | VRRP sur IPv4 | VRRP sur IPv6 |
|---|---|---|
| destination | `224.0.0.18` (multidiffusion) | `ff02::12` |
| protocole | IP 112 (ni TCP ni UDP) | en-tête suivant 112 |
| TTL / limite de sauts | 255 | 255 |
| source | l'adresse réelle du maître | son adresse lien-local |
| contenu | version, VRID, priorité, intervalle, adresses virtuelles | idem |

Le TTL de 255 est une protection : une annonce qui aurait traversé un routeur arriverait avec un
TTL plus petit et serait rejetée. VRRP ne sort pas du réseau local.

### @@sec@@ Élection et bascule

Un secours qui ne reçoit plus d'annonce pendant l'**intervalle d'indisponibilité du maître** se
déclare maître :

```
intervalle d'indisponibilité = 3 × intervalle des annonces + décalage
décalage (skew time)         = (256 − priorité) / 256 seconde
```

Avec des annonces toutes les secondes, un secours de priorité 100 attend 3,61 s, un secours de
priorité 150 attend 3,41 s : le plus prioritaire se déclare le premier, et son annonce fait taire
les autres. À priorité égale, le routeur dont l'adresse IP est la plus grande l'emporte.

Quand le maître s'arrête proprement, il émet une annonce de **priorité 0** : les secours n'attendent
alors que le décalage, moins d'une seconde. Quand il disparaît brutalement (panne, câble
débranché), il faut attendre l'intervalle complet.

En devenant maître, un routeur émet des **ARP gratuits** (des requêtes ARP pour sa propre adresse
virtuelle) : les postes et les commutateurs apprennent ainsi où se trouve désormais l'adresse.

### @@sec@@ VRRPv2 et VRRPv3

| | VRRPv2 (RFC 3768) | VRRPv3 (RFC 5798) |
|---|---|---|
| familles d'adresses | IPv4 | IPv4 et IPv6 |
| intervalle des annonces | en secondes | en centisecondes (bascules en moins d'une seconde) |
| authentification | champ présent, usage déconseillé | aucune |
| décalage | (256 − priorité) / 256 s | proportionnel à l'intervalle du maître |
""": """
### @@sec@@ Virtual router, master and backup

A **virtual router** is defined, on a local network, by an identifier, the **VRID** (1 to 255),
and by one or more virtual IP addresses. Each real router taking part in it has a **priority**
(1 to 254, 100 by default). The one with the highest priority is the **master**: it holds the
virtual addresses, answers the ARP requests for them and forwards the traffic. The others are
**backups**: they listen.

Two priorities are reserved: **255** is for the router whose own interface address is the virtual
address (the "owner"), and **0** is what the master announces when it steps down on purpose.

### @@sec@@ The advertisements

The master regularly sends an **advertisement**; the backups send nothing.

| | VRRP over IPv4 | VRRP over IPv6 |
|---|---|---|
| destination | `224.0.0.18` (multicast) | `ff02::12` |
| protocol | IP 112 (neither TCP nor UDP) | next header 112 |
| TTL / hop limit | 255 | 255 |
| source | the real address of the master | its link-local address |
| content | version, VRID, priority, interval, virtual addresses | the same |

The TTL of 255 is a protection: an advertisement that crossed a router would arrive with a lower
TTL and would be rejected. VRRP never leaves the local network.

### @@sec@@ Election and failover

A backup that receives no advertisement during the **master-down interval** declares itself
master:

```
master-down interval = 3 × advertisement interval + skew time
skew time            = (256 − priority) / 256 second
```

With one advertisement per second, a backup of priority 100 waits 3.61 s, a backup of priority
150 waits 3.41 s: the one with the highest priority speaks first, and its advertisement silences
the others. With equal priorities, the router with the highest IP address wins.

When the master stops cleanly, it sends an advertisement of **priority 0**: the backups then wait
for the skew time only, less than a second. When it disappears abruptly (failure, unplugged
cable), the whole interval must elapse.

On becoming master, a router sends **gratuitous ARPs** (ARP requests for its own virtual
address): the hosts and the switches learn where the address now is.

### @@sec@@ VRRPv2 and VRRPv3

| | VRRPv2 (RFC 3768) | VRRPv3 (RFC 5798) |
|---|---|---|
| address families | IPv4 | IPv4 and IPv6 |
| advertisement interval | in seconds | in centiseconds (failovers in less than a second) |
| authentication | field present, use discouraged | none |
| skew time | (256 − priority) / 256 s | proportional to the interval of the master |
""",
        'keepalived': 'keepalived',
        """
keepalived est un démon qui met en œuvre VRRP (et, ce qui ne sert pas ici, la surveillance des
serveurs d'un répartiteur de charge LVS). Sa configuration est le fichier
`/etc/keepalived/keepalived.conf` ; tant que ce fichier n'existe pas, le service ne démarre pas.

### @@sec@@ Une instance VRRP

```
global_defs {
    router_id routeur-a          # un nom pour ce routeur, dans les journaux
}

vrrp_instance VI_1 {             # le nom est local au fichier
    interface eth0               # où émettre les annonces et poser les adresses
    virtual_router_id 51         # le VRID : le même sur tous les routeurs du routeur virtuel
    state MASTER                 # état de départ souhaité : MASTER ou BACKUP
    priority 150
    advert_int 1                 # intervalle des annonces, en secondes
    virtual_ipaddress {
        192.0.2.1/24             # sans masque, l'adresse est posée en /32
    }
}
```

Un bloc s'ouvre par `{` en fin de ligne et se ferme par `}` seul sur sa ligne ; `#` et `!`
commencent un commentaire. Le fichier du second routeur est identique, à `router_id`, `state` et
`priority` près.

C'est la **priorité** qui décide de l'élection, pas `state` : avec une priorité inférieure à 255,
une instance `state MASTER` démarre tout de même en secours et ne devient maître qu'après
l'intervalle d'indisponibilité. Le VRID doit être unique sur le réseau local : deux routeurs
virtuels différents qui porteraient le même se perturberaient.

### @@sec@@ Le service

| commande | effet |
|---|---|
| `keepalived -t` | vérifie la configuration (aucun message et code 0 : elle est valide) |
| `systemctl enable --now keepalived` | active le service au démarrage et le lance |
| `systemctl reload keepalived` | relit la configuration sans interrompre les instances inchangées |
| `systemctl restart keepalived` | arrête tout (annonce de priorité 0) et redémarre |
| `journalctl -u keepalived -f` | suit le journal : `Entering BACKUP STATE`, `Entering MASTER STATE`... |
| `kill -USR1 $(cat /run/keepalived.pid)` | écrit l'état complet dans `/tmp/keepalived.data` |

Une instance est dans l'un de trois états : **MASTER**, **BACKUP** ou **FAULT** (elle ne peut pas
être maître : son interface est tombée, ou un élément qu'elle suit est en panne).
""": """
keepalived is a daemon implementing VRRP (and, which is of no use here, the monitoring of the
servers of an LVS load balancer). Its configuration is the file
`/etc/keepalived/keepalived.conf`; as long as that file does not exist, the service does not
start.

### @@sec@@ A VRRP instance

```
global_defs {
    router_id router-a           # a name for this router, in the logs
}

vrrp_instance VI_1 {             # the name is local to the file
    interface eth0               # where to send the advertisements and put the addresses
    virtual_router_id 51         # the VRID: the same on every router of the virtual router
    state MASTER                 # wanted initial state: MASTER or BACKUP
    priority 150
    advert_int 1                 # advertisement interval, in seconds
    virtual_ipaddress {
        192.0.2.1/24             # without a mask, the address is installed as a /32
    }
}
```

A block opens with `{` at the end of a line and closes with `}` alone on its line; `#` and `!`
start a comment. The file of the second router is the same, except for `router_id`, `state` and
`priority`.

The **priority** decides the election, not `state`: with a priority below 255, a `state MASTER`
instance still starts as a backup and only becomes master after the master-down interval. The
VRID must be unique on the local network: two different virtual routers carrying the same one
would disturb each other.

### @@sec@@ The service

| command | effect |
|---|---|
| `keepalived -t` | checks the configuration (no message and status 0: it is valid) |
| `systemctl enable --now keepalived` | enables the service at boot and starts it |
| `systemctl reload keepalived` | reads the configuration again without interrupting the unchanged instances |
| `systemctl restart keepalived` | stops everything (advertisement of priority 0) and starts again |
| `journalctl -u keepalived -f` | follows the journal: `Entering BACKUP STATE`, `Entering MASTER STATE`... |
| `kill -USR1 $(cat /run/keepalived.pid)` | writes the whole state to `/tmp/keepalived.data` |

An instance is in one of three states: **MASTER**, **BACKUP** or **FAULT** (it cannot be master:
its interface is down, or something it tracks has failed).
""",
        'La préemption': 'Preemption',
        """
Par défaut, VRRP est **préemptif** : un routeur plus prioritaire que le maître en place lui reprend
le rôle dès qu'il revient. C'est prévisible (le maître est toujours le même en temps normal), mais
chaque retour provoque une seconde bascule.

- `nopreempt` : le routeur qui revient reste secours tant que le maître en place fonctionne. Cette
  option exige `state BACKUP` sur tous les routeurs.
- `preempt_delay 30` : il attend 30 s après son démarrage avant de reprendre la main, le temps que
  ses routes et ses autres services soient prêts.
""": """
By default, VRRP is **preemptive**: a router with a higher priority than the current master takes
the role back as soon as it returns. This is predictable (the master is always the same in normal
operation), but every return causes a second failover.

- `nopreempt`: the returning router stays a backup as long as the current master works. This
  option requires `state BACKUP` on every router.
- `preempt_delay 30`: it waits 30 s after its start before taking over, the time for its routes
  and its other services to be ready.
""",
        'Les groupes de synchronisation': 'Sync groups',
        """
Un routeur a plusieurs côtés, donc plusieurs instances VRRP : une par réseau. Elles sont
indépendantes : si une seule interface tombe, une seule instance bascule. Le trafic sort alors par
un routeur et revient par l'autre, qui ne peut plus le remettre à destination. Chaque instance est
dans un état correct, et pourtant plus rien ne passe.

Un **groupe de synchronisation** lie des instances : toutes sont maîtres, ou aucune.

```
vrrp_sync_group G_1 {
    group {
        VI_1
        VI_2
    }
}
```

Dès qu'une instance du groupe passe à l'état FAULT ou BACKUP, les autres la suivent. Les éléments
suivis (section @@ref:tracking@@) et les notifications (section @@ref:notify@@) se déclarent alors
sur le groupe.
""": """
A router has several sides, hence several VRRP instances: one per network. They are independent:
if a single interface goes down, a single instance fails over. The traffic then leaves through
one router and comes back through the other, which can no longer deliver it. Each instance is in
a correct state, and yet nothing gets through.

A **sync group** ties instances together: all of them are master, or none.

```
vrrp_sync_group G_1 {
    group {
        VI_1
        VI_2
    }
}
```

As soon as one instance of the group goes to the FAULT or BACKUP state, the others follow. The
tracked items (section @@ref:tracking@@) and the notifications (section @@ref:notify@@) are then
declared on the group.
""",
        'Le suivi : interfaces et scripts': 'Tracking: interfaces and scripts',
        """
Une instance surveille toujours sa propre interface. On peut lui donner d'autres critères.

### @@sec@@ Suivre une interface

```
track_interface {
    eth1                 # eth1 tombe : l'instance passe à l'état FAULT
    eth2 weight -30      # eth2 tombe : la priorité baisse de 30
}
```

Une interface n'est « tombée » que si le système le voit (lien désactivé, câble débranché). Un
voisin injoignable derrière un lien qui reste actif ne se détecte pas ainsi.

### @@sec@@ Suivre un script

```
vrrp_script chk_service {
    script "/etc/keepalived/check.sh"    # code de retour 0 : tout va bien
    interval 2                           # lancé toutes les 2 s
    fall 2                               # 2 échecs de suite : en panne
    rise 2                               # 2 succès de suite : rétabli
}

vrrp_instance VI_1 {
    ...
    track_script {
        chk_service
    }
}
```

Le **poids** (`weight`, dans `vrrp_script` ou après le nom dans `track_script`) fixe l'effet d'un
échec :

| poids | effet |
|---|---|
| 0 (par défaut) | en cas d'échec, l'instance passe à l'état **FAULT** |
| négatif (`weight -60`) | en cas d'échec, la priorité annoncée baisse d'autant ; l'instance reste secours ou maître selon les autres |
| positif | la priorité augmente d'autant tant que le script réussit |

**Dans un groupe de synchronisation, les poids sont ignorés** (keepalived les ramène à 0) : on y
suit donc les scripts sans poids, et un échec met tout le groupe à l'état FAULT.

### @@sec@@ Sécurité des scripts

keepalived tourne avec les droits de `root`, et ses scripts aussi par défaut (ou avec ceux de
l'utilisateur `keepalived_script` s'il existe). Dans `global_defs` :

- `script_user root` fixe l'utilisateur qui exécute les scripts ;
- `enable_script_security` refuse d'exécuter en tant que `root` un script qu'un autre utilisateur
  pourrait modifier (le fichier, ou l'un des répertoires qui y mènent).

Un script de test doit être rapide et sans effet de bord : il est lancé toutes les quelques
secondes.
""": """
An instance always watches its own interface. It can be given other criteria.

### @@sec@@ Tracking an interface

```
track_interface {
    eth1                 # eth1 goes down: the instance goes to the FAULT state
    eth2 weight -30      # eth2 goes down: the priority drops by 30
}
```

An interface is "down" only when the system sees it (link disabled, cable unplugged). An
unreachable neighbour behind a link that stays up is not detected that way.

### @@sec@@ Tracking a script

```
vrrp_script chk_service {
    script "/etc/keepalived/check.sh"    # exit status 0: all is well
    interval 2                           # run every 2 s
    fall 2                               # 2 failures in a row: failed
    rise 2                               # 2 successes in a row: recovered
}

vrrp_instance VI_1 {
    ...
    track_script {
        chk_service
    }
}
```

The **weight** (`weight`, in `vrrp_script` or after the name in `track_script`) sets the effect of
a failure:

| weight | effect |
|---|---|
| 0 (default) | on failure, the instance goes to the **FAULT** state |
| negative (`weight -60`) | on failure, the advertised priority drops by that much; the instance stays backup or master depending on the others |
| positive | the priority rises by that much while the script succeeds |

**In a sync group, weights are ignored** (keepalived sets them to 0): scripts are therefore
tracked without a weight there, and a failure puts the whole group in the FAULT state.

### @@sec@@ Script security

keepalived runs with the rights of `root`, and so do its scripts by default (or with those of the
user `keepalived_script` when it exists). In `global_defs`:

- `script_user root` sets the user running the scripts;
- `enable_script_security` refuses to run as `root` a script another user could modify (the
  file, or one of the directories leading to it).

A check script must be fast and free of side effects: it is run every few seconds.
""",
        'Les notifications': 'Notifications',
        """
keepalived peut lancer un programme à chaque changement d'état, pour journaliser, prévenir, ou
démarrer et arrêter un service qui doit suivre l'adresse virtuelle.

| mot-clé | lancé quand l'instance (ou le groupe) |
|---|---|
| `notify_master` | devient maître |
| `notify_backup` | devient secours |
| `notify_fault` | passe à l'état FAULT |
| `notify_stop` | s'arrête avec keepalived |
| `notify` | change d'état, quel qu'il soit |

Le script de `notify` reçoit quatre arguments : le type (`INSTANCE` ou `GROUP`), le nom, le nouvel
état (`MASTER`, `BACKUP`, `FAULT`, `STOP`) et la priorité.

```
#!/bin/sh
echo "$(date '+%F %T') $1 $2 $3 $4" >> /var/log/vrrp-state.log
```
""": """
keepalived can run a program at every change of state, to log it, to send an alert, or to start
and stop a service that must follow the virtual address.

| keyword | run when the instance (or the group) |
|---|---|
| `notify_master` | becomes master |
| `notify_backup` | becomes backup |
| `notify_fault` | goes to the FAULT state |
| `notify_stop` | stops with keepalived |
| `notify` | changes state, whatever the state |

The `notify` script receives four arguments: the type (`INSTANCE` or `GROUP`), the name, the new
state (`MASTER`, `BACKUP`, `FAULT`, `STOP`) and the priority.

```
#!/bin/sh
echo "$(date '+%F %T') $1 $2 $3 $4" >> /var/log/vrrp-state.log
```
""",
        'La sécurité des annonces': 'Securing the advertisements',
        """
VRRP fait confiance au réseau local : toute machine capable d'émettre une annonce de priorité 255
pour le bon VRID devient maître et reçoit le trafic des postes. C'est un moyen simple d'interrompre
le service ou de l'intercepter.

### @@sec@@ L'authentification

```
authentication {
    auth_type PASS
    auth_pass secret12       # 8 caractères au plus
}
```

Chaque annonce porte alors le mot de passe, et une annonce qui ne le porte pas est ignorée. Mais il
circule **en clair** : une simple capture le révèle. C'est une protection contre les erreurs (deux
routeurs virtuels configurés par mégarde avec le même VRID), pas contre un attaquant. La RFC 3768 a
retiré l'authentification de VRRPv2 et VRRPv3 n'en prévoit pas ; l'autre type, `AH`, est déconseillé.

### @@sec@@ Les annonces en unicast

```
unicast_src_ip 192.0.2.2
unicast_peer {
    192.0.2.3
}
```

Les annonces sont envoyées directement aux homologues désignés au lieu du groupe de multidiffusion.
C'est indispensable là où la multidiffusion est filtrée (beaucoup de réseaux d'hébergeurs), et cela
évite de diffuser les annonces à tout le réseau.

La vraie protection se fait au niveau du commutateur : n'accepter le protocole 112 que sur les
ports des routeurs.
""": """
VRRP trusts the local network: any machine able to send an advertisement of priority 255 for the
right VRID becomes master and receives the traffic of the hosts. It is a simple way to interrupt
the service or to intercept it.

### @@sec@@ Authentication

```
authentication {
    auth_type PASS
    auth_pass secret12       # 8 characters at most
}
```

Each advertisement then carries the password, and an advertisement without it is ignored. But it
travels **in clear**: a simple capture reveals it. It protects against mistakes (two virtual
routers configured with the same VRID by accident), not against an attacker. RFC 3768 removed
authentication from VRRPv2 and VRRPv3 has none; the other type, `AH`, is discouraged.

### @@sec@@ Unicast advertisements

```
unicast_src_ip 192.0.2.2
unicast_peer {
    192.0.2.3
}
```

The advertisements are sent straight to the named peers instead of the multicast group. This is
required where multicast is filtered (many hosting networks), and it avoids broadcasting the
advertisements to the whole network.

The real protection belongs to the switch: accepting protocol 112 on the ports of the routers
only.
""",
        'Le partage de charge': 'Load sharing',
        """
Avec un seul routeur virtuel, le secours ne fait rien en temps normal. On peut en définir **deux**
sur le même réseau, avec deux VRID et deux adresses virtuelles : chaque routeur est maître de l'un
et secours de l'autre. La moitié des postes prend la première adresse pour passerelle, l'autre
moitié la seconde.

Ce partage est **statique** : il dépend de la passerelle donnée à chaque poste (à la main, ou par le
serveur DHCP). Et chaque routeur doit pouvoir acheminer seul tout le trafic, puisqu'il reprend les
deux adresses quand l'autre tombe.
""": """
With a single virtual router, the backup does nothing in normal operation. **Two** of them can be
defined on the same network, with two VRIDs and two virtual addresses: each router is the master
of one and the backup of the other. Half of the hosts take the first address as their gateway,
the other half the second one.

This sharing is **static**: it depends on the gateway given to each host (by hand, or by the DHCP
server). And each router must be able to carry all the traffic alone, since it takes both
addresses over when the other one fails.
""",
        "L'adresse MAC virtuelle": 'The virtual MAC address',
        """
La norme attribue à chaque routeur virtuel une **adresse MAC virtuelle** : `00:00:5e:00:01:XX` en
IPv4, `00:00:5e:00:02:XX` en IPv6, où `XX` est le VRID en hexadécimal. Le maître répond aux requêtes
ARP avec cette adresse : à la bascule, l'adresse IP **et** l'adresse MAC changent de routeur, et les
caches ARP des postes restent valables.

keepalived, par défaut, ne le fait pas : l'adresse virtuelle prend l'adresse MAC de l'interface du
maître, et le nouveau maître prévient les postes par des ARP gratuits. L'option `use_vmac`, dans une
instance, active l'adresse MAC virtuelle :

- keepalived crée une interface `vrrp.VRID` de type **macvlan** au-dessus de l'interface de
  l'instance, avec l'adresse MAC virtuelle ; elle existe sur le maître comme sur les secours ;
- le maître y pose l'adresse virtuelle et émet ses annonces depuis cette adresse MAC : c'est ainsi
  que le commutateur apprend sur quel port elle se trouve désormais.

Deux précautions :

- les routeurs doivent émettre leurs requêtes ARP avec l'adresse de leur interface, jamais avec
  l'adresse virtuelle (`sysctl net.ipv4.conf.all.arp_announce=2`), sans quoi les postes
  réapprennent l'adresse MAC réelle ;
- le réseau doit être commuté : sur un concentrateur, ou si le commutateur diffuse les trames faute
  de connaître l'adresse, le secours reçoit lui aussi les trames destinées à l'adresse MAC
  virtuelle.

Avec des homologues en unicast, `use_vmac` demande en plus `vmac_xmit_base`.
""": """
The standard gives every virtual router a **virtual MAC address**: `00:00:5e:00:01:XX` in IPv4,
`00:00:5e:00:02:XX` in IPv6, where `XX` is the VRID in hexadecimal. The master answers the ARP
requests with that address: at a failover the IP address **and** the MAC address move to the
other router, and the ARP caches of the hosts stay valid.

keepalived does not do so by default: the virtual address takes the MAC address of the interface
of the master, and the new master tells the hosts with gratuitous ARPs. The option `use_vmac`, in
an instance, turns the virtual MAC address on:

- keepalived creates an interface `vrrp.VRID` of the **macvlan** type on top of the interface of
  the instance, with the virtual MAC address; it exists on the master and on the backups alike;
- the master puts the virtual address on it and sends its advertisements from that MAC address:
  this is how the switch learns on which port it now is.

Two precautions:

- the routers must send their ARP requests with the address of their interface, never with the
  virtual address (`sysctl net.ipv4.conf.all.arp_announce=2`), or the hosts learn the real MAC
  address again;
- the network must be switched: on a hub, or when the switch floods the frames because it does
  not know the address, the backup receives the frames sent to the virtual MAC address too.

With unicast peers, `use_vmac` also requires `vmac_xmit_base`.
""",
        'VRRPv3 et IPv6': 'VRRPv3 and IPv6',
        """
Une instance dont les adresses virtuelles sont IPv6 est toujours en **VRRPv3**. Ses annonces vont à
`ff02::12` avec une limite de sauts de 255, et la première adresse virtuelle est une adresse
**lien-local**.

```
vrrp_instance VI_6 {
    interface eth0
    version 3
    virtual_router_id 61
    priority 150
    virtual_ipaddress {
        fe80::1/64
    }
}
```

Il n'y a pas d'ARP en IPv6 : en devenant maître, le routeur émet une **annonce de voisin non
sollicitée** (*unsolicited neighbor advertisement*) pour chaque adresse virtuelle.

### @@sec@@ Les annonces de routeur

Un poste IPv6 apprend sa passerelle par les **annonces de routeur** (RA) : la route par défaut
qu'il installe passe par l'adresse lien-local **source** de l'annonce. Si c'est l'adresse réelle
d'un routeur, la route meurt avec lui. Les annonces doivent donc partir de l'adresse virtuelle :

```
interface eth0
{
    AdvSendAdvert on;
    AdvRASrcAddress { fe80::1; };
    prefix 2001:db8:1::/64
    {
    };
};
```

Avec ce fichier sur tous les routeurs, seul celui qui détient l'adresse virtuelle, le maître,
émet des annonces.

### @@sec@@ Deux familles dans une instance

Les adresses de `virtual_ipaddress` sont toutes de la même famille. Pour qu'une instance IPv4
gère aussi une adresse IPv6 (ou l'inverse), on la place dans `virtual_ipaddress_excluded` : elle
n'apparaît pas dans les annonces, mais elle est posée et retirée avec les autres.
""": """
An instance whose virtual addresses are IPv6 is always in **VRRPv3**. Its advertisements go to
`ff02::12` with a hop limit of 255, and the first virtual address is a **link-local** address.

```
vrrp_instance VI_6 {
    interface eth0
    version 3
    virtual_router_id 61
    priority 150
    virtual_ipaddress {
        fe80::1/64
    }
}
```

There is no ARP in IPv6: on becoming master, the router sends an **unsolicited neighbor
advertisement** for each virtual address.

### @@sec@@ Router advertisements

An IPv6 host learns its gateway from the **router advertisements** (RA): the default route it
installs goes through the link-local **source** address of the advertisement. If that is the real
address of a router, the route dies with it. The advertisements must therefore leave from the
virtual address:

```
interface eth0
{
    AdvSendAdvert on;
    AdvRASrcAddress { fe80::1; };
    prefix 2001:db8:1::/64
    {
    };
};
```

With this file on every router, only the one holding the virtual address, the master, sends
advertisements.

### @@sec@@ Two families in one instance

The addresses of `virtual_ipaddress` all belong to the same family. For an IPv4 instance to
manage an IPv6 address too (or the reverse), it goes into `virtual_ipaddress_excluded`: it does
not appear in the advertisements, but it is installed and removed with the others.
""",
        'Observer et dépanner': 'Observing and troubleshooting',
        """
| commande | ce qu'elle montre |
|---|---|
| `tcpdump -n -v -i eth0 vrrp` | les annonces IPv4 : source, VRID, priorité, intervalle, authentification |
| `tcpdump -n -v -i eth0 'ip6 proto 112'` | les annonces VRRPv3 en IPv6 |
| `tcpdump -e -n -i eth0 vrrp` | les mêmes avec les adresses MAC |
| `ip -br addr` | quel routeur porte les adresses virtuelles |
| `ip -d link show type macvlan` | les interfaces créées par `use_vmac` |
| `ip neigh` | sur un poste : l'adresse MAC associée à la passerelle |
| `ip -6 route` | sur un poste : la route par défaut reçue par annonce de routeur |
| `journalctl -u keepalived` | les transitions, les scripts, les annonces rejetées |

| symptôme | causes fréquentes |
|---|---|
| les deux routeurs sont maîtres | ils ne s'entendent pas : VRID différents, mot de passe différent, multidiffusion filtrée, homologues unicast mal désignés |
| aucun n'est maître | instances à l'état FAULT : interface tombée, script en échec, script refusé par `enable_script_security` |
| l'adresse virtuelle ne répond pas | masque oublié ou erroné, mauvaise interface, cache ARP périmé sur le poste |
| bascules à répétition | script de test trop sensible (`fall` trop petit), deux instances non groupées |
| keepalived ne démarre pas | fichier absent ou vide, erreur de syntaxe : `keepalived -t` |
""": """
| command | what it shows |
|---|---|
| `tcpdump -n -v -i eth0 vrrp` | the IPv4 advertisements: source, VRID, priority, interval, authentication |
| `tcpdump -n -v -i eth0 'ip6 proto 112'` | the VRRPv3 advertisements over IPv6 |
| `tcpdump -e -n -i eth0 vrrp` | the same with the MAC addresses |
| `ip -br addr` | which router holds the virtual addresses |
| `ip -d link show type macvlan` | the interfaces created by `use_vmac` |
| `ip neigh` | on a host: the MAC address associated with the gateway |
| `ip -6 route` | on a host: the default route received from a router advertisement |
| `journalctl -u keepalived` | the transitions, the scripts, the rejected advertisements |

| symptom | frequent causes |
|---|---|
| both routers are master | they do not hear each other: different VRIDs, different password, filtered multicast, wrong unicast peers |
| none is master | instances in the FAULT state: interface down, failing script, script refused by `enable_script_security` |
| the virtual address does not answer | missing or wrong mask, wrong interface, stale ARP cache on the host |
| repeated failovers | check script too sensitive (`fall` too small), two instances not grouped |
| keepalived does not start | missing or empty file, syntax error: `keepalived -t` |
""",
        'les fichiers de {router} ne sont pas rejoués sur la copie cachée : {dir} et {radvd} ne doivent contenir que des fichiers ordinaires (ni lien ni périphérique), pour moins de 48 Ko en tout': 'the files of {router} are not replayed on the hidden copy: {dir} and {radvd} must hold plain files only (no link, no device), for less than 48 KiB in all',
        """
| machine | interface | réseau | IPv4 | IPv6 |
|---------|-----------|--------|------|------|
| `pc1` | eth0 | `lan` | `{pc1}` | `{pc1_6}` |
| `pc2` | eth0 | `lan` | `{pc2}` | `{pc2_6}` |
| `r1` | eth0 | `lan` | `{r1_lan}` | `{r1_lan6}` |
| `r1` | eth1 | `wan` | `{r1_wan}` | `{r1_wan6}` |
| `r2` | eth0 | `lan` | `{r2_lan}` | `{r2_lan6}` |
| `r2` | eth1 | `wan` | `{r2_wan}` | `{r2_wan6}` |
| `isp` | eth0 | `wan` | `{isp}` | `{isp6}` |
""": """
| machine | interface | network | IPv4 | IPv6 |
|---------|-----------|---------|------|------|
| `pc1` | eth0 | `lan` | `{pc1}` | `{pc1_6}` |
| `pc2` | eth0 | `lan` | `{pc2}` | `{pc2_6}` |
| `r1` | eth0 | `lan` | `{r1_lan}` | `{r1_lan6}` |
| `r1` | eth1 | `wan` | `{r1_wan}` | `{r1_wan6}` |
| `r2` | eth0 | `lan` | `{r2_lan}` | `{r2_lan6}` |
| `r2` | eth1 | `wan` | `{r2_wan}` | `{r2_wan6}` |
| `isp` | eth0 | `wan` | `{isp}` | `{isp6}` |
""",
        """
| instance VRRP | interface | VRID | maître (150) / secours (100) | adresse virtuelle |
|---------------|-----------|------|------------------------------|-------------------|
| `VI_LAN` | eth0 | **{vrid_lan}** | r1 / r2 | `{vip_lan}` : la passerelle de `pc1` |
| `VI_WAN` | eth1 | **{vrid_wan}** | r1 / r2 | `{vip_wan}` : par où `isp` joint le réseau local (partie 2) |
| `VI_LAN2` | eth0 | **{vrid_lan2}** | r2 / r1 | `{vip_lan2}` : la passerelle de `pc2` (partie 5) |
| `VI_LAN6` | eth0 | **{vrid_lan6}** | r1 / r2 | `{vip6_lan}/64` : la passerelle IPv6 (partie 7) |

- intervalle des annonces : {advert} s partout ;
- mot de passe de `VI_LAN` (partie 4) : `{auth_pass}` ;
- adresse virtuelle IPv6 côté `wan` (partie 7) : `{vip6_wan}` ;
- script de test (partie 3) : `{check}`, toutes les {interval} s, {fall} échecs pour tomber, {rise} succès pour revenir ;
- script de notification (partie 3) : `{notify}`, qui écrit dans `{log}`.
""": """
| VRRP instance | interface | VRID | master (150) / backup (100) | virtual address |
|---------------|-----------|------|-----------------------------|-----------------|
| `VI_LAN` | eth0 | **{vrid_lan}** | r1 / r2 | `{vip_lan}`: the gateway of `pc1` |
| `VI_WAN` | eth1 | **{vrid_wan}** | r1 / r2 | `{vip_wan}`: how `isp` reaches the local network (part 2) |
| `VI_LAN2` | eth0 | **{vrid_lan2}** | r2 / r1 | `{vip_lan2}`: the gateway of `pc2` (part 5) |
| `VI_LAN6` | eth0 | **{vrid_lan6}** | r1 / r2 | `{vip6_lan}/64`: the IPv6 gateway (part 7) |

- advertisement interval: {advert} s everywhere;
- password of `VI_LAN` (part 4): `{auth_pass}`;
- IPv6 virtual address on the `wan` side (part 7): `{vip6_wan}`;
- check script (part 3): `{check}`, every {interval} s, {fall} failures to fail, {rise} successes to recover;
- notify script (part 3): `{notify}`, which writes to `{log}`.
""",
        'Organisation du TP': 'Organisation of the lab',
        """
Lisez d'abord l'onglet **Informations** : il présente VRRP et keepalived. Cette page décrit la
maquette et les valeurs propres à votre instance.

**La maquette.** Deux routeurs, `r1` et `r2`, relient le réseau local `lan` (les clients `pc1` et
`pc2`, sur un commutateur) au réseau `wan` du fournisseur d'accès, dont le routeur est `isp`. Pour ce
TP vous administrez toutes les machines, `isp` compris.
""": """
First read the **Informations** tab: it presents VRRP and keepalived. This page describes the lab
network and the values of your instance.

**The network.** Two routers, `r1` and `r2`, connect the local network `lan` (the clients `pc1`
and `pc2`, on a switch) to the network `wan` of the access provider, whose router is `isp`. In
this lab you administer every machine, `isp` included.
""",
        """
**Déjà en place (ne pas modifier).** Les adresses ci-dessus ; le routage IPv4 et IPv6 sur `r1` et
`r2` ; `/etc/hosts` (noms `pc1`, `pc2`, `r1`, `r2`, `r1-wan`, `r2-wan`, `isp`) ; un petit serveur web
sur `r1`, `r2` et `isp` : `curl http://ADRESSE/` affiche `SERVER=` suivi du nom de la machine qui a
répondu (et `CLIENT_IP=`, l'adresse du client telle que le serveur la voit) ; sur les routeurs, le
réglage `arp_announce=2` (cf. section @@ref:vmac@@). keepalived et radvd sont installés sur `r1` et
`r2`, **arrêtés et sans configuration**.

**Au départ, aucune redondance.** `pc1` et `pc2` ont `r1` (`{r1_lan}`) pour passerelle, et `isp`
joint le réseau local par `r1` (`{r1_wan}`). Tout fonctionne tant que `r1` fonctionne.

**Valeurs de votre instance.**
""": """
**Already in place (do not change).** The addresses above; IPv4 and IPv6 forwarding on `r1` and
`r2`; `/etc/hosts` (names `pc1`, `pc2`, `r1`, `r2`, `r1-wan`, `r2-wan`, `isp`); a small web server
on `r1`, `r2` and `isp`: `curl http://ADDRESS/` prints `SERVER=` followed by the name of the
machine that answered (and `CLIENT_IP=`, the address of the client as the server sees it); on the
routers, the setting `arp_announce=2` (see section @@ref:vmac@@). keepalived and radvd are
installed on `r1` and `r2`, **stopped and without configuration**.

**At the start, no redundancy.** `pc1` and `pc2` have `r1` (`{r1_lan}`) as their gateway, and
`isp` reaches the local network through `r1` (`{r1_wan}`). Everything works as long as `r1` works.

**Values of your instance.**
""",
        """
Les noms des instances sont libres (l'évaluation reconnaît une instance à son VRID) ; ceux du
tableau sont ceux des solutions.

**Simuler une panne.** `systemctl stop keepalived` (arrêt propre du service) ; `ip link set eth0 down`
puis `ip link set eth0 up` (câble débranché : les adresses des routeurs sont conservées) ; ou, sur
`isp`, une règle nftables qui ignore les `ping` d'un routeur (partie 3).

**L'évaluation ne touche jamais à vos routeurs.** À chaque évaluation, le contenu de
**`/etc/keepalived/`** (la configuration **et les scripts**) et le fichier **`/etc/radvd.conf`** de
`r1` et de `r2` sont recopiés sur une copie cachée de la maquette (mêmes adresses). keepalived y est
redémarré, puis des pannes y sont provoquées : lien coupé, fournisseur injoignable, fausses annonces.
En conséquence :

- tout ce dont votre solution dépend doit se trouver dans ces deux emplacements (aucun script
  ailleurs) et être enregistré dans les fichiers ;
- peu importe l'état de vos routeurs au moment de l'évaluation (une panne en cours ne fausse rien),
  sauf pour les quelques vérifications faites sur la maquette réelle : service actif, adresses,
  annonces, routes des clients ;
- une évaluation dure d'une demi-minute à une minute.

Les questions à formulaire ne sont notées qu'à l'évaluation de l'enseignant.

**Plan du TP.** 1. une première passerelle virtuelle ; 2. le côté `wan` et le groupe de
synchronisation ; 3. test de santé et notification ; 4. authentification et homologues en unicast ;
5. partage de charge ; 6. adresse MAC virtuelle ; 7. VRRPv3 et IPv6.
""": """
The names of the instances are free (the evaluation recognises an instance by its VRID); those of
the table are the ones of the solutions.

**Simulating a failure.** `systemctl stop keepalived` (clean stop of the service);
`ip link set eth0 down` then `ip link set eth0 up` (unplugged cable: the addresses of the routers
are kept); or, on `isp`, an nftables rule ignoring the `ping`s of a router (part 3).

**The evaluation never touches your routers.** At each evaluation, the content of
**`/etc/keepalived/`** (the configuration **and the scripts**) and the file **`/etc/radvd.conf`** of
`r1` and `r2` are copied onto a hidden copy of the network (same addresses). keepalived is
restarted there, then failures are caused there: link down, unreachable provider, forged
advertisements. As a consequence:

- everything your solution depends on must be in those two places (no script elsewhere) and
  saved in the files;
- the state of your routers at the time of the evaluation does not matter (a failure in progress
  distorts nothing), except for the few checks made on the real network: active service,
  addresses, advertisements, routes of the clients;
- an evaluation lasts from half a minute to a minute.

The form questions are graded by the instructor's evaluation only.

**Plan of the lab.** 1. a first virtual gateway; 2. the `wan` side and the sync group; 3. health
check and notification; 4. authentication and unicast peers; 5. load sharing; 6. virtual MAC
address; 7. VRRPv3 and IPv6.
""",
        """
**Pour l'enseignant.** L'état `final` applique la solution des sept parties sur `r1`, `r2`, les
clients et `isp` ; les formulaires se remplissent avec les réponses de l'état. La maquette cachée
(`pc1_h`, `pc2_h`, `r1_h`, `r2_h`, `isp_h`) rejoue l'archive de `/etc/keepalived` et de
`/etc/radvd.conf` en huit étapes : remise à zéro ; fichiers et état nominal ; lien LAN de `r1_h`
coupé ; lien rétabli (préemption) ; lien WAN de `r2_h` coupé ; `isp_h` ignore les `ping` de `r1_h` ;
fausses annonces de priorité 255 émises par `pc1_h` ; remise à zéro. Le commutateur du réseau local
est un `vde_switch` : la première évaluation lui retire son délai de 3 s avant de déplacer une adresse
MAC (`hash/setminper 0`), sans quoi une adresse MAC virtuelle reste injoignable 3 à 4 s après une
bascule propre.
""": """
**For the instructor.** The state `final` applies the solution of the seven parts on `r1`, `r2`,
the clients and `isp`; the forms are filled with the answers of the state. The hidden network
(`pc1_h`, `pc2_h`, `r1_h`, `r2_h`, `isp_h`) replays the archive of `/etc/keepalived` and
`/etc/radvd.conf` in eight steps: reset; files and nominal state; LAN link of `r1_h` down; link
restored (preemption); WAN link of `r2_h` down; `isp_h` ignores the `ping`s of `r1_h`; forged
advertisements of priority 255 sent by `pc1_h`; reset. The switch of the local network is a
`vde_switch`: the first evaluation removes its 3 s delay before moving a MAC address
(`hash/setminper 0`), without which a virtual MAC address stays unreachable for 3 to 4 s after a
clean handover.
""",
        'Partie 1 — Une première passerelle virtuelle (questions 1 à 3)': 'Part 1 — A first virtual gateway (questions 1 to 3)',
        'Un seul routeur : le point de défaillance unique': 'A single router: the single point of failure',
        """
Depuis `pc1`, vérifiez que `isp` répond : `ping {isp}` et `curl http://{isp}/`. Laissez le `ping`
tourner et, sur `r1`, coupez le lien du réseau local : `ip link set eth0 down`. Que devient le
`ping` ? Que faudrait-il changer, et sur quelles machines, pour passer par `r2` ? Rétablissez le
lien (`ip link set eth0 up`) avant de continuer.
""": """
From `pc1`, check that `isp` answers: `ping {isp}` and `curl http://{isp}/`. Leave the `ping`
running and, on `r1`, cut the link of the local network: `ip link set eth0 down`. What happens to
the `ping`? What would have to be changed, and on which machines, to go through `r2`? Restore the
link (`ip link set eth0 up`) before going on.
""",
        """
**Solution.** Le `ping` s'arrête : la passerelle de `pc1` est l'adresse de `r1` (`{r1_lan}`), que plus
personne ne détient. Pour passer par `r2` il faudrait changer la route par défaut de **chaque**
client (`ip route replace default via {r2_lan}`) et, sur `isp`, la route vers le réseau local
(`ip route replace {lan} via {r2_wan}`) : une intervention manuelle sur toutes les machines. VRRP
rend ce changement automatique en faisant porter l'adresse de la passerelle par le routeur
disponible. Rien n'est noté ici.
""": """
**Solution.** The `ping` stops: the gateway of `pc1` is the address of `r1` (`{r1_lan}`), which
nobody holds any more. Going through `r2` would mean changing the default route of **every**
client (`ip route replace default via {r2_lan}`) and, on `isp`, the route to the local network
(`ip route replace {lan} via {r2_wan}`): a manual intervention on every machine. VRRP makes that
change automatic by having the available router carry the address of the gateway. Nothing is
graded here.
""",
        "L'instance VI_LAN sur r1 et r2": 'The VI_LAN instance on r1 and r2',
        """
Sur `r1` et sur `r2`, écrivez `{conf}` avec une instance VRRP sur `eth0` (cf. section
@@ref:keepalived@@ des Informations) : VRID **{vrid}**, adresse virtuelle `{vip}`, annonces
toutes les {advert} s ; `r1` est le maître prévu (`state MASTER`, priorité {master}), `r2` le
secours (`state BACKUP`, priorité {backup}).

1. Vérifiez chaque fichier avec `keepalived -t`, puis activez et démarrez le service :
   `systemctl enable --now keepalived`.
2. Sur `pc1`, remplacez la passerelle par l'adresse virtuelle : `ip route replace default via {vip_ip}`.
3. Vérifiez : `ip -br addr show eth0` sur les deux routeurs (qui porte `{vip_ip}` ?),
   `journalctl -u keepalived` et, depuis `pc1`, `curl http://{vip_ip}/` puis `ping {isp}`.
""": """
On `r1` and on `r2`, write `{conf}` with a VRRP instance on `eth0` (see section
@@ref:keepalived@@ of the Informations): VRID **{vrid}**, virtual address `{vip}`, one
advertisement every {advert} s; `r1` is the intended master (`state MASTER`, priority {master}),
`r2` the backup (`state BACKUP`, priority {backup}).

1. Check each file with `keepalived -t`, then enable and start the service:
   `systemctl enable --now keepalived`.
2. On `pc1`, replace the gateway by the virtual address: `ip route replace default via {vip_ip}`.
3. Check: `ip -br addr show eth0` on both routers (which one holds `{vip_ip}`?),
   `journalctl -u keepalived` and, from `pc1`, `curl http://{vip_ip}/` then `ping {isp}`.
""",
        """
**Solution.** `{conf}` sur `r1` :

```
{r1_conf}
```

Sur `r2` : `router_id r2`, `state BACKUP`, `priority {backup}`. Puis sur les deux routeurs
`keepalived -t && systemctl enable --now keepalived`, et sur `pc1`
`ip route replace default via {vip_ip}`. `r1` démarre en secours et devient maître au bout de 3 à
4 s (`Entering MASTER STATE` dans le journal) : seule une priorité 255 rend `state MASTER`
immédiat. `curl http://{vip_ip}/` affiche `SERVER=r1`.
""": """
**Solution.** `{conf}` on `r1`:

```
{r1_conf}
```

On `r2`: `router_id r2`, `state BACKUP`, `priority {backup}`. Then on both routers
`keepalived -t && systemctl enable --now keepalived`, and on `pc1`
`ip route replace default via {vip_ip}`. `r1` starts as a backup and becomes master after 3 to
4 s (`Entering MASTER STATE` in the journal): only a priority of 255 makes `state MASTER`
immediate. `curl http://{vip_ip}/` prints `SERVER=r1`.
""",
        'Les annonces et la bascule': 'The advertisements and the failover',
        """
Sur `pc1`, capturez les annonces : `tcpdump -n -v -i eth0 vrrp`. Notez aussi l'adresse MAC que
`pc1` associe à l'adresse virtuelle (`ip neigh show {vip_ip}`, après un `ping {vip_ip}`).

Laissez la capture et un `ping {isp}` tourner sur `pc1`, puis arrêtez le service sur `r1` :
`systemctl stop keepalived`. Observez la dernière annonce de `r1`, le journal de `r2`, le `ping` et
de nouveau `ip neigh show {vip_ip}`. Redémarrez le service sur `r1` : qui redevient maître ?

Recommencez en coupant le lien au lieu d'arrêter le service (`ip link set eth0 down` sur `r1`, puis
`up`) et comparez la durée de l'interruption (cf. section @@ref:protocol@@).
""": """
On `pc1`, capture the advertisements: `tcpdump -n -v -i eth0 vrrp`. Also note the MAC address
`pc1` associates with the virtual address (`ip neigh show {vip_ip}`, after a `ping {vip_ip}`).

Leave the capture and a `ping {isp}` running on `pc1`, then stop the service on `r1`:
`systemctl stop keepalived`. Watch the last advertisement of `r1`, the journal of `r2`, the `ping`
and `ip neigh show {vip_ip}` again. Start the service again on `r1`: who becomes master again?

Do it again by cutting the link instead of stopping the service (`ip link set eth0 down` on `r1`,
then `up`) and compare the length of the interruption (see section @@ref:protocol@@).
""",
        """
- adresse IP de destination des annonces : @@{dst:[0-9.]+}@@ ; numéro de protocole IP : @@{proto:[0-9]+}@@ ; TTL : @@{ttl:[0-9]+}@@
- en fonctionnement normal, qui émet des annonces ? @@{sender:>r1 seulement>>>r1|r2 seulement>>>r2|r1 et r2>>>both}@@
- adresse MAC de l'adresse virtuelle vue par pc1, r1 étant maître : @@{mac_before:[0-9a-fA-F:-]+}@@
- priorité annoncée par r1 dans sa dernière annonce, à l'arrêt du service : @@{prio_stop:[0-9]+}@@
- adresse MAC de l'adresse virtuelle vue par pc1, r2 étant maître : @@{mac_after:[0-9a-fA-F:-]+}@@
- lien coupé (aucune annonce de priorité 0) : délai, en secondes, au bout duquel r2 (priorité 100) se déclare maître : @@{down_time:[0-9.,]+}@@
""": """
- destination IP address of the advertisements: @@{dst:[0-9.]+}@@ ; IP protocol number: @@{proto:[0-9]+}@@ ; TTL: @@{ttl:[0-9]+}@@
- in normal operation, who sends advertisements? @@{sender:>r1 only>>>r1|r2 only>>>r2|r1 and r2>>>both}@@
- MAC address of the virtual address as pc1 sees it, r1 being master: @@{mac_before:[0-9a-fA-F:-]+}@@
- priority announced by r1 in its last advertisement, when the service stops: @@{prio_stop:[0-9]+}@@
- MAC address of the virtual address as pc1 sees it, r2 being master: @@{mac_after:[0-9a-fA-F:-]+}@@
- link cut (no advertisement of priority 0): delay, in seconds, after which r2 (priority 100) declares itself master: @@{down_time:[0-9.,]+}@@
""",
        """
**Solution.** Les annonces partent de l'adresse réelle du maître vers le groupe `224.0.0.18`,
protocole IP 112, TTL 255, une par seconde ; seul le maître en émet. `pc1` associe `{vip_ip}` à
l'adresse MAC de `r1` (`{mac_r1}`).

- Arrêt du service : `r1` émet une annonce de **priorité 0**, `r2` prend le relais en moins d'une
  seconde et envoie des ARP gratuits : l'entrée de `pc1` devient `{mac_r2}`, le `ping` ne perd rien
  ou un paquet. Au redémarrage, `r1` (priorité 150) reprend la main : c'est la préemption.
- Lien coupé : aucune annonce de priorité 0 ne peut partir. `r2` attend l'intervalle
  d'indisponibilité du maître, `3 × 1 + (256 − 100) / 256` = **{down:.2f} s**, pendant lesquelles le
  `ping` est interrompu.
""": """
**Solution.** The advertisements leave from the real address of the master to the group
`224.0.0.18`, IP protocol 112, TTL 255, one per second; only the master sends some. `pc1`
associates `{vip_ip}` with the MAC address of `r1` (`{mac_r1}`).

- Service stopped: `r1` sends an advertisement of **priority 0**, `r2` takes over in less than a
  second and sends gratuitous ARPs: the entry of `pc1` becomes `{mac_r2}`, the `ping` loses nothing
  or one packet. At the restart, `r1` (priority 150) takes the role back: that is preemption.
- Link cut: no advertisement of priority 0 can leave. `r2` waits for the master-down interval,
  `3 × 1 + (256 − 100) / 256` = **{down:.2f} s**, during which the `ping` is interrupted.
""",
        'keepalived actif, activé au démarrage et de configuration valide (r1, r2)': 'keepalived active, enabled at boot and with a valid configuration (r1, r2)',
        "instance de VRID {vrid} sur eth0 avec l'adresse {vip} (r1, r2) ; priorités 150 et 100": 'instance of VRID {vrid} on eth0 with the address {vip} (r1, r2); priorities 150 and 100',
        'sur la maquette : {vip} sur r1 seul ; annonces de r1 (priorité 150, une par seconde) ; pc1 passe par {vip} et r1 lui répond': 'on the real network: {vip} on r1 alone; advertisements of r1 (priority 150, one per second); pc1 goes through {vip} and r1 answers it',
        'copie cachée, état nominal : {vip} sur r1 seul, qui répond à pc1': 'hidden copy, nominal state: {vip} on r1 alone, which answers pc1',
        'copie cachée, lien LAN de r1 coupé : r2 prend {vip} et répond à pc1': 'hidden copy, LAN link of r1 down: r2 takes {vip} and answers pc1',
        'copie cachée, lien rétabli : r1 reprend {vip} (préemption), r2 la rend': 'hidden copy, link restored: r1 takes {vip} back (preemption), r2 releases it',
        'annonces (224.0.0.18, protocole 112, TTL 255, maître seul), adresses MAC avant et après la bascule, priorité 0, délai de bascule': 'advertisements (224.0.0.18, protocol 112, TTL 255, master alone), MAC addresses before and after the failover, priority 0, failover delay',
        'Partie 2 — Le côté wan et le groupe de synchronisation (questions 4 et 5)': 'Part 2 — The wan side and the sync group (questions 4 and 5)',
        "L'instance VI_WAN et le groupe de synchronisation": 'The VI_WAN instance and the sync group',
        """
Une passerelle a deux côtés. Pour l'instant `isp` joint le réseau local par l'adresse de `r1`
(`{r1_wan}`) : si `r1` tombe, les réponses n'ont plus de chemin de retour.

1. Sur `r1` et `r2`, ajoutez une instance sur `eth1` : VRID **{vrid}**, adresse virtuelle
   `{vip}`, mêmes rôles et priorités que `VI_LAN`.
2. Liez les deux instances dans un **groupe de synchronisation** (cf. section @@ref:sync-group@@) :
   elles doivent changer d'état ensemble.
3. Rechargez la configuration (`keepalived -t && systemctl reload keepalived`).
4. Sur `isp`, faites passer le trafic du réseau local par l'adresse virtuelle :
   `ip route replace {lan} via {vip_ip}`.

Vérifiez depuis `pc1` (`curl http://{isp}/`) puis coupez le lien du réseau local de `r1`
(`ip link set eth0 down`) : les **deux** adresses virtuelles doivent passer sur `r2` et `pc1` doit
toujours joindre `isp`. Rétablissez le lien.
""": """
A gateway has two sides. For now `isp` reaches the local network through the address of `r1`
(`{r1_wan}`): if `r1` fails, the answers have no way back.

1. On `r1` and `r2`, add an instance on `eth1`: VRID **{vrid}**, virtual address `{vip}`, same
   roles and priorities as `VI_LAN`.
2. Tie the two instances in a **sync group** (see section @@ref:sync-group@@): they must change
   state together.
3. Reload the configuration (`keepalived -t && systemctl reload keepalived`).
4. On `isp`, send the traffic of the local network through the virtual address:
   `ip route replace {lan} via {vip_ip}`.

Check from `pc1` (`curl http://{isp}/`) then cut the link of the local network of `r1`
(`ip link set eth0 down`): **both** virtual addresses must move to `r2` and `pc1` must still reach
`isp`. Restore the link.
""",
        """
**Solution.** `{conf}` sur `r1` (sur `r2` : `router_id r2`, `state BACKUP` et `priority {backup}` dans
les deux instances) :

```
{r1_conf}
```

Sur `isp` : `ip route replace {lan} via {vip_ip}`. Lien `eth0` de `r1` coupé : `VI_LAN` passe à
l'état FAULT, le groupe y entraîne `VI_WAN` (`VRRP_Group(G_EDGE) Syncing instances to FAULT state`)
et `r2` prend les deux adresses.
""": """
**Solution.** `{conf}` on `r1` (on `r2`: `router_id r2`, `state BACKUP` and `priority {backup}` in
both instances):

```
{r1_conf}
```

On `isp`: `ip route replace {lan} via {vip_ip}`. Link `eth0` of `r1` down: `VI_LAN` goes to the
FAULT state, the group takes `VI_WAN` along (`VRRP_Group(G_EDGE) Syncing instances to FAULT state`)
and `r2` takes both addresses.
""",
        'Sans le groupe de synchronisation': 'Without the sync group',
        """
Raisonnez (ou essayez, en retirant provisoirement le groupe) : les instances `VI_LAN` et `VI_WAN`
sont indépendantes, `isp` joint le réseau local par `{vip_wan}`, et le lien `eth0` de `r1` tombe
alors que son lien `eth1` fonctionne.
""": """
Reason it out (or try, by removing the group for a moment): the instances `VI_LAN` and `VI_WAN`
are independent, `isp` reaches the local network through `{vip_wan}`, and the link `eth0` of `r1`
goes down while its link `eth1` works.
""",
        """
- qui détient l'adresse virtuelle du réseau local ? @@{lan_holder:>r1>>>r1|r2>>>r2|personne>>>none}@@
- qui détient l'adresse virtuelle côté wan ? @@{wan_holder:>r1>>>r1|r2>>>r2|personne>>>none}@@
- un `ping` de pc1 vers isp : @@{result:>fonctionne>>>ok|échoue : la réponse de isp arrive sur r1, qui n'a plus de lien vers le réseau local>>>blackhole|échoue : pc1 ne trouve plus sa passerelle>>>gateway}@@
- avec le groupe, état de l'instance VI_WAN de r1 quand son lien eth0 tombe : @@{group_state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""": """
- who holds the virtual address of the local network? @@{lan_holder:>r1>>>r1|r2>>>r2|nobody>>>none}@@
- who holds the virtual address on the wan side? @@{wan_holder:>r1>>>r1|r2>>>r2|nobody>>>none}@@
- a `ping` from pc1 to isp: @@{result:>works>>>ok|fails: the answer of isp arrives on r1, which has no link to the local network any more>>>blackhole|fails: pc1 no longer finds its gateway>>>gateway}@@
- with the group, state of the VI_WAN instance of r1 when its link eth0 goes down: @@{group_state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""",
        """
**Solution.** Sans groupe, `VI_LAN` bascule sur `r2` mais `VI_WAN` reste sur `r1`, dont le lien
`eth1` est intact : la requête de `pc1` sort par `r2`, la réponse de `isp` revient à `r1`, qui ne
peut plus la remettre au réseau local. C'est un trou noir, alors que chaque instance, prise seule,
est dans un état correct. Avec le groupe, toutes les instances de `r1` passent à l'état FAULT dès
que l'une d'elles y passe.
""": """
**Solution.** Without a group, `VI_LAN` fails over to `r2` but `VI_WAN` stays on `r1`, whose link
`eth1` is intact: the request of `pc1` leaves through `r2`, the answer of `isp` comes back to `r1`,
which can no longer deliver it to the local network. It is a black hole, although each instance,
taken alone, is in a correct state. With the group, every instance of `r1` goes to the FAULT
state as soon as one of them does.
""",
        "instance de VRID {vrid} sur eth1 avec l'adresse {vip} (r1, r2) ; les deux instances dans un groupe de synchronisation": 'instance of VRID {vrid} on eth1 with the address {vip} (r1, r2); both instances in a sync group',
        'sur la maquette : {vip} sur r1 seul ; isp joint le réseau local par {vip} ; pc1 et isp se joignent par les adresses virtuelles': 'on the real network: {vip} on r1 alone; isp reaches the local network through {vip}; pc1 and isp reach each other through the virtual addresses',
        'copie cachée, état nominal : {vip} sur r1 seul ; pc1 et isp se joignent': 'hidden copy, nominal state: {vip} on r1 alone; pc1 and isp reach each other',
        'copie cachée, lien LAN de r1 coupé : {vip} passe aussi sur r2 (r1 la rend) ; pc1 et isp se joignent toujours': 'hidden copy, LAN link of r1 down: {vip} moves to r2 as well (r1 releases it); pc1 and isp still reach each other',
        'sans groupe : les deux adresses sur deux routeurs, trou noir ; état FAULT avec le groupe': 'without a group: the two addresses on two routers, black hole; FAULT state with the group',
        'Partie 3 — Test de santé et notification (questions 6 et 7)': 'Part 3 — Health check and notification (questions 6 and 7)',
        'Surveiller le fournisseur, journaliser les transitions': 'Watching the provider, logging the transitions',
        """
Un lien peut rester « monté » alors que plus rien ne passe : keepalived ne le voit pas. Un **script
de test** lui donne un critère de plus (cf. section @@ref:tracking@@).

1. Sur `r1` et `r2`, écrivez `{check}` : il se termine avec le code 0 si `isp` (`{isp}`) répond à
   **un** `ping` en moins d'une seconde, avec un autre code sinon. Rendez-le exécutable ; il doit
   appartenir à `root`.
2. Déclarez-le dans keepalived (`vrrp_script`) : lancé toutes les {interval} s, {fall} échecs
   consécutifs pour le déclarer en panne, {rise} succès pour le déclarer rétabli. Faites-le suivre
   par le groupe, **sans poids**. Dans `global_defs`, ajoutez `enable_script_security` et
   `script_user root`.
3. Écrivez `{notify}` : à chaque transition il ajoute à `{log}` une ligne contenant ses quatre
   arguments (type, nom, nouvel état, priorité). Faites-le appeler par le groupe (`notify`).
4. `keepalived -t && systemctl reload keepalived`.

Essai : sur `isp`, ignorez les `ping` de `r1`, observez la bascule (journal, `{log}`,
`curl http://{vip}/` depuis `pc1`), puis retirez la règle.
""": """
A link can stay "up" while nothing gets through any more: keepalived does not see it. A **check
script** gives it one more criterion (see section @@ref:tracking@@).

1. On `r1` and `r2`, write `{check}`: it exits with status 0 when `isp` (`{isp}`) answers **one**
   `ping` in less than a second, with another status otherwise. Make it executable; it must
   belong to `root`.
2. Declare it in keepalived (`vrrp_script`): run every {interval} s, {fall} failures in a row to
   declare it failed, {rise} successes to declare it recovered. Have the group track it,
   **without a weight**. In `global_defs`, add `enable_script_security` and `script_user root`.
3. Write `{notify}`: at each transition it appends to `{log}` a line holding its four arguments
   (type, name, new state, priority). Have the group call it (`notify`).
4. `keepalived -t && systemctl reload keepalived`.

Trial: on `isp`, ignore the `ping`s of `r1`, watch the failover (journal, `{log}`,
`curl http://{vip}/` from `pc1`), then remove the rule.
""",
        """
```
nft add table ip essai
nft 'add chain ip essai input { type filter hook input priority 0; }'
nft add rule ip essai input ip saddr ADRESSE_WAN_DE_R1 icmp type echo-request drop
nft delete table ip essai
```
""": """
```
nft add table ip trial
nft 'add chain ip trial input { type filter hook input priority 0; }'
nft add rule ip trial input ip saddr WAN_ADDRESS_OF_R1 icmp type echo-request drop
nft delete table ip trial
```
""",
        """
**Solution.** `{check}` (mode 755) :

```
{check_text}
```

`{notify}` (mode 755) :

```
{notify_text}
```

`{conf}` sur `r1` (le groupe suit le script et appelle la notification) :

```
{r1_conf}
```

`isp` muet pour `r1` (`{r1_wan}`) : après {fall} échecs (4 à 6 s) le journal de `r1` affiche
`VRRP_Script({name}) failed` puis `Syncing instances to FAULT state`, `r2` devient maître et
`{log}` reçoit `GROUP {group} FAULT 0` sur `r1`, `GROUP {group} MASTER 0` sur `r2` (un groupe n'a
pas de priorité : 0). Règle retirée, `r1` revient après {rise} succès et reprend la main.
""": """
**Solution.** `{check}` (mode 755):

```
{check_text}
```

`{notify}` (mode 755):

```
{notify_text}
```

`{conf}` on `r1` (the group tracks the script and calls the notification):

```
{r1_conf}
```

`isp` silent for `r1` (`{r1_wan}`): after {fall} failures (4 to 6 s) the journal of `r1` shows
`VRRP_Script({name}) failed` then `Syncing instances to FAULT state`, `r2` becomes master and
`{log}` receives `GROUP {group} FAULT 0` on `r1`, `GROUP {group} MASTER 0` on `r2` (a group has no
priority: 0). Rule removed, `r1` comes back after {rise} successes and takes the role back.
""",
        "Poids d'un script et groupe de synchronisation": 'Weight of a script and sync group',
        """
Un script suivi peut avoir un **poids** (cf. section @@ref:tracking@@). Imaginez `VI_LAN` **hors de
tout groupe**, suivant le script avec `weight -60` : `r1` a la priorité {master}, `r2` la priorité
{backup}, et le script échoue sur `r1` seulement.
""": """
A tracked script may have a **weight** (see section @@ref:tracking@@). Imagine `VI_LAN` **outside
any group**, tracking the script with `weight -60`: `r1` has priority {master}, `r2` priority
{backup}, and the script fails on `r1` only.
""",
        """
- priorité que r1 annonce alors : @@{effective:[0-9]+}@@
- qui est maître ? @@{master:>r1>>>r1|r2>>>r2}@@
- et dans un groupe de synchronisation, le poids d'un script suivi est : @@{in_group:>appliqué comme hors groupe>>>applied|ignoré : keepalived le ramène à 0>>>ignored|refusé : keepalived ne démarre pas>>>refused}@@
- état des instances du groupe sur r1 quand le script, suivi sans poids, échoue : @@{state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""": """
- priority r1 then announces: @@{effective:[0-9]+}@@
- who is master? @@{master:>r1>>>r1|r2>>>r2}@@
- and in a sync group, the weight of a tracked script is: @@{in_group:>applied as outside a group>>>applied|ignored: keepalived sets it to 0>>>ignored|refused: keepalived does not start>>>refused}@@
- state of the instances of the group on r1 when the script, tracked without a weight, fails: @@{state:>MASTER>>>MASTER|BACKUP>>>BACKUP|FAULT>>>FAULT}@@
""",
        """
**Solution.** Hors groupe, un poids négatif est retranché de la priorité tant que le script
échoue : `r1` annonce {master} − 60 = **{effective}**, inférieur à {backup} ; `r2` le préempte
et devient maître, `r1` reste secours (il n'est pas en panne, seulement moins prioritaire). Dans un
groupe, les poids sont ramenés à 0 : un script suivi sans poids met les instances à l'état
**FAULT**. C'est la forme à utiliser dans un groupe.
""": """
**Solution.** Outside a group, a negative weight is subtracted from the priority while the script
fails: `r1` announces {master} − 60 = **{effective}**, lower than {backup}; `r2` preempts it and
becomes master, `r1` stays a backup (it has not failed, it only has a lower priority). In a group,
weights are set to 0: a script tracked without a weight puts the instances in the **FAULT**
state. That is the form to use in a group.
""",
        'script {check} exécutable (r1, r2) ; vrrp_script toutes les {interval} s, {fall} échecs, {rise} succès ; suivi sans poids par le groupe': 'script {check} executable (r1, r2); vrrp_script every {interval} s, {fall} failures, {rise} successes; tracked without a weight by the group',
        'script de notification exécutable sous {dir}, appelé par le groupe (r1, r2)': 'notify script executable under {dir}, called by the group (r1, r2)',
        'copie cachée, isp ne répond plus aux ping de r1 : r2 prend {vip}, r1 la rend, r2 répond à pc1': 'hidden copy, isp no longer answers the pings of r1: r2 takes {vip}, r1 releases it, r2 answers pc1',
        'copie cachée : {log} contient la transition MASTER sur r2 et la transition FAULT sur r1': 'hidden copy: {log} holds the MASTER transition on r2 and the FAULT transition on r1',
        "poids d'un script : priorité 90 et r2 maître hors groupe ; ignoré dans un groupe ; état FAULT sans poids": 'weight of a script: priority 90 and r2 master outside a group; ignored in a group; FAULT state without a weight',
        'Partie 4 — Authentification et homologues en unicast (questions 8 et 9)': 'Part 4 — Authentication and unicast peers (questions 8 and 9)',
        'Protéger les annonces': 'Protecting the advertisements',
        """
N'importe quelle machine du réseau local peut émettre une annonce de priorité 255 et se faire élire
maître (cf. section @@ref:security@@).

1. Dans `VI_LAN`, sur `r1` et `r2`, ajoutez une authentification par mot de passe (`auth_type PASS`)
   avec le mot de passe `{password}`.
2. Dans `VI_WAN`, n'envoyez plus les annonces au groupe de diffusion mais **en unicast** à l'autre
   routeur : adresse source `{r1_wan}` et homologue `{r2_wan}` sur `r1`, l'inverse sur `r2`.
3. `keepalived -t && systemctl reload keepalived` sur les deux routeurs (l'un après l'autre : tant
   qu'un seul des deux a le mot de passe, chacun ignore les annonces de l'autre).

Capturez de nouveau sur `pc1` (`tcpdump -n -v -i eth0 vrrp`) et sur `isp` (même commande).
""": """
Any machine of the local network can send an advertisement of priority 255 and get itself elected
master (see section @@ref:security@@).

1. In `VI_LAN`, on `r1` and `r2`, add a password authentication (`auth_type PASS`) with the
   password `{password}`.
2. In `VI_WAN`, stop sending the advertisements to the multicast group and send them **in
   unicast** to the other router: source address `{r1_wan}` and peer `{r2_wan}` on `r1`, the
   reverse on `r2`.
3. `keepalived -t && systemctl reload keepalived` on both routers (one after the other: as long
   as only one of them has the password, each ignores the advertisements of the other).

Capture again on `pc1` (`tcpdump -n -v -i eth0 vrrp`) and on `isp` (same command).
""",
        """
**Solution.** Dans `VI_LAN` (les deux routeurs) et dans `VI_WAN` (ici sur `r1`, adresses inversées
sur `r2`) :

```
{snippet}
```

La capture sur `pc1` montre `authtype simple` et le mot de passe **en clair** (`auth "{password}"`) ;
celle de `isp` montre `{r1_wan} > {r2_wan}` au lieu de `224.0.0.18`. Une annonce sans mot de passe
est rejetée (`received a 0 auth, expecting 1!` dans le journal). L'évaluation en émet depuis la
copie cachée de `pc1`, avec la priorité 255 : `r1` doit garder `{vip}`.
""": """
**Solution.** In `VI_LAN` (both routers) and in `VI_WAN` (here on `r1`, addresses swapped on
`r2`):

```
{snippet}
```

The capture on `pc1` shows `authtype simple` and the password **in clear** (`auth "{password}"`);
the one of `isp` shows `{r1_wan} > {r2_wan}` instead of `224.0.0.18`. An advertisement without the
password is rejected (`received a 0 auth, expecting 1!` in the journal). The evaluation sends some
from the hidden copy of `pc1`, with priority 255: `r1` must keep `{vip}`.
""",
        'Ce que montre une capture': 'What a capture shows',
        """
D'après vos captures et la section @@ref:security@@ :
""": """
From your captures and section @@ref:security@@:
""",
        """
- dans une annonce de VI_LAN, la capture montre : @@{auth_seen:>le mot de passe en clair>>>clear|une empreinte du mot de passe>>>hash|rien : l'annonce est chiffrée>>>encrypted}@@
- une annonce de priorité 255 **sans** mot de passe reçue par r1 est : @@{forged:>ignorée : r1 reste maître>>>ignored|acceptée : r1 devient secours>>>accepted}@@
- adresse de destination des annonces de VI_WAN émises par r1 : @@{wan_dst:[0-9.]+}@@
- VRRPv3 prévoit-il une authentification ? @@{v3:>oui>>>yes|non>>>no}@@
""": """
- in an advertisement of VI_LAN, the capture shows: @@{auth_seen:>the password in clear>>>clear|a hash of the password>>>hash|nothing: the advertisement is encrypted>>>encrypted}@@
- an advertisement of priority 255 **without** the password received by r1 is: @@{forged:>ignored: r1 stays master>>>ignored|accepted: r1 becomes a backup>>>accepted}@@
- destination address of the advertisements of VI_WAN sent by r1: @@{wan_dst:[0-9.]+}@@
- does VRRPv3 provide an authentication? @@{v3:>yes>>>yes|no>>>no}@@
""",
        """
**Solution.** Le mot de passe circule en clair : il protège d'une erreur de configuration ou d'un
équipement bavard, pas d'un attaquant qui écoute le réseau (la RFC 3768 a d'ailleurs retiré
l'authentification de VRRPv2, et VRRPv3 n'en a pas). Une annonce sans mot de passe est ignorée.
Les annonces de `VI_WAN` vont à `{r2_wan}`.
""": """
**Solution.** The password travels in clear: it protects against a configuration mistake or a
chatty device, not against an attacker listening to the network (RFC 3768 removed authentication
from VRRPv2, and VRRPv3 has none). An advertisement without the password is ignored. The
advertisements of `VI_WAN` go to `{r2_wan}`.
""",
        "VI_LAN : auth_type PASS avec le mot de passe de l'instance (r1, r2)": 'VI_LAN: auth_type PASS with the password of the instance (r1, r2)',
        'sur la maquette : les annonces de VI_LAN portent le mot de passe': 'on the real network: the advertisements of VI_LAN carry the password',
        'copie cachée : pendant de fausses annonces de priorité 255 sans mot de passe, un routeur garde {vip}': 'hidden copy: during forged advertisements of priority 255 without the password, a router keeps {vip}',
        "VI_WAN : unicast_src_ip et unicast_peer vers l'autre routeur (r1, r2)": 'VI_WAN: unicast_src_ip and unicast_peer to the other router (r1, r2)',
        "sur la maquette : les annonces de VI_WAN vont d'un routeur à l'autre, plus au groupe 224.0.0.18": 'on the real network: the advertisements of VI_WAN go from one router to the other, no longer to the group 224.0.0.18',
        "mot de passe en clair, annonce sans mot de passe ignorée, destination unicast, pas d'authentification en VRRPv3": 'password in clear, advertisement without the password ignored, unicast destination, no authentication in VRRPv3',
        'Partie 5 — Partage de charge (questions 10 et 11)': 'Part 5 — Load sharing (questions 10 and 11)',
        'Une deuxième passerelle virtuelle, dont r2 est le maître': 'A second virtual gateway, of which r2 is the master',
        """
Avec une seule adresse virtuelle, `r2` ne sert à rien tant que `r1` fonctionne. Répartissez la
charge (cf. section @@ref:load-sharing@@) avec une deuxième instance sur `eth0` : VRID **{vrid}**,
adresse virtuelle `{vip}`, dont **`r2` est le maître** (priorité {master}) et `r1` le secours
(priorité {backup}).

1. Ajoutez l'instance sur les deux routeurs ; elle ne fait **pas** partie du groupe.
2. Si le lien `eth1` de `r2` tombe, `r2` ne doit pas garder cette passerelle : faites suivre
   l'interface `eth1` par l'instance (`track_interface`), sur les deux routeurs.
3. `keepalived -t && systemctl reload keepalived`, puis sur `pc2` :
   `ip route replace default via {vip_ip}`.

Vérifiez depuis `pc2` : `curl http://{vip_ip}/` (qui répond ?), `curl http://{isp}/`, puis
`ip link set eth1 down` sur `r2` et de nouveau les deux `curl`. Rétablissez le lien.
""": """
With a single virtual address, `r2` is of no use as long as `r1` works. Share the load (see
section @@ref:load-sharing@@) with a second instance on `eth0`: VRID **{vrid}**, virtual address
`{vip}`, of which **`r2` is the master** (priority {master}) and `r1` the backup (priority
{backup}).

1. Add the instance on both routers; it is **not** part of the group.
2. If the link `eth1` of `r2` goes down, `r2` must not keep this gateway: have the instance track
   the interface `eth1` (`track_interface`), on both routers.
3. `keepalived -t && systemctl reload keepalived`, then on `pc2`:
   `ip route replace default via {vip_ip}`.

Check from `pc2`: `curl http://{vip_ip}/` (who answers?), `curl http://{isp}/`, then
`ip link set eth1 down` on `r2` and both `curl`s again. Restore the link.
""",
        """
**Solution.** Sur `r2` (sur `r1` : `state BACKUP`, `priority {backup}`) :

```
{snippet}
```

Sur `pc2` : `ip route replace default via {vip_ip}`. En temps normal `r1` achemine le trafic de
`pc1` et `r2` celui de `pc2` ; chacun secourt l'autre. Lien `eth1` de `r2` coupé : l'instance passe
à l'état FAULT (interface suivie sans poids), `r1` prend `{vip_ip}` en moins d'une seconde et `pc2`
joint toujours `isp`.
""": """
**Solution.** On `r2` (on `r1`: `state BACKUP`, `priority {backup}`):

```
{snippet}
```

On `pc2`: `ip route replace default via {vip_ip}`. In normal operation `r1` forwards the traffic
of `pc1` and `r2` that of `pc2`; each backs the other up. Link `eth1` of `r2` down: the instance
goes to the FAULT state (interface tracked without a weight), `r1` takes `{vip_ip}` in less than a
second and `pc2` still reaches `isp`.
""",
        'Qui achemine quoi ?': 'Who forwards what?',
        """
Avec les deux passerelles virtuelles en place :
""": """
With both virtual gateways in place:
""",
        """
- en fonctionnement normal : @@{nominal:>r1 achemine le trafic de pc1, r2 celui de pc2>>>split|r1 achemine tout>>>r1|r2 achemine tout>>>r2}@@
- keepalived arrêté sur r2 : @@{after:>r1 achemine le trafic des deux clients>>>r1|r1 achemine celui de pc1, pc2 n'a plus de passerelle>>>none|r2 continue d'acheminer celui de pc2>>>r2}@@
""": """
- in normal operation: @@{nominal:>r1 forwards the traffic of pc1, r2 that of pc2>>>split|r1 forwards everything>>>r1|r2 forwards everything>>>r2}@@
- keepalived stopped on r2: @@{after:>r1 forwards the traffic of both clients>>>r1|r1 forwards that of pc1, pc2 has no gateway any more>>>none|r2 goes on forwarding that of pc2>>>r2}@@
""",
        """
**Solution.** Chaque routeur est maître d'une passerelle et secours de l'autre : la charge est
répartie entre les clients, par leur route par défaut, et `r1` reprend les deux adresses si `r2`
s'arrête. Le partage est statique : c'est l'administrateur (ou le serveur DHCP) qui répartit les
clients entre les deux passerelles.
""": """
**Solution.** Each router is the master of one gateway and the backup of the other: the load is
shared between the clients, by their default route, and `r1` takes both addresses over if `r2`
stops. The sharing is static: the administrator (or the DHCP server) splits the clients between
the two gateways.
""",
        "instance de VRID {vrid} sur eth0 avec l'adresse {vip} (r1, r2) ; r2 prioritaire": 'instance of VRID {vrid} on eth0 with the address {vip} (r1, r2); r2 has the higher priority',
        "la deuxième instance suit l'interface eth1 (r1, r2)": 'the second instance tracks the interface eth1 (r1, r2)',
        'sur la maquette : {vip} sur r2 seul ; pc2 passe par {vip} et r2 lui répond': 'on the real network: {vip} on r2 alone; pc2 goes through {vip} and r2 answers it',
        'copie cachée, état nominal : {vip} sur r2 seul ; pc2 passe par r2 et joint isp': 'hidden copy, nominal state: {vip} on r2 alone; pc2 goes through r2 and reaches isp',
        'copie cachée, lien WAN de r2 coupé : r1 prend {vip} ; pc2 joint toujours isp': 'hidden copy, WAN link of r2 down: r1 takes {vip}; pc2 still reaches isp',
        "partage de charge : un routeur par client, r1 reprend tout si r2 s'arrête": 'load sharing: one router per client, r1 takes everything over if r2 stops',
        'Partie 6 — Adresse MAC virtuelle (questions 12 et 13)': 'Part 6 — Virtual MAC address (questions 12 and 13)',
        'use_vmac sur la deuxième passerelle': 'use_vmac on the second gateway',
        """
À chaque bascule, les clients doivent apprendre la nouvelle adresse MAC de leur passerelle : le
nouveau maître la leur annonce par des ARP gratuits. Avec une **adresse MAC virtuelle**, propre au
routeur virtuel, rien ne change pour eux (cf. section @@ref:vmac@@).

1. Dans la deuxième instance (VRID {vrid}), sur `r1` et `r2`, ajoutez `use_vmac`, puis
   **redémarrez** keepalived : `systemctl restart keepalived`.
2. Observez : sur les deux routeurs, `ip -d link show` et `ip -br addr` (quelle interface est
   apparue, où est `{vip_ip}` ?) ; sur `pc2`, `ip neigh flush all`, `ping -c 2 {vip_ip}` puis
   `ip neigh show {vip_ip}` ; sur `pc1`, `tcpdump -e -n -i eth0 vrrp` (adresses MAC sources).
3. Arrêtez keepalived sur `r2`, relisez l'entrée de `pc2`, puis redémarrez-le. Comparez avec
   l'entrée de `pc1` pour `{vip1}` quand le groupe bascule.
""": """
At each failover, the clients must learn the new MAC address of their gateway: the new master
tells them with gratuitous ARPs. With a **virtual MAC address**, belonging to the virtual router,
nothing changes for them (see section @@ref:vmac@@).

1. In the second instance (VRID {vrid}), on `r1` and `r2`, add `use_vmac`, then **restart**
   keepalived: `systemctl restart keepalived`.
2. Observe: on both routers, `ip -d link show` and `ip -br addr` (which interface appeared, where
   is `{vip_ip}`?); on `pc2`, `ip neigh flush all`, `ping -c 2 {vip_ip}` then
   `ip neigh show {vip_ip}`; on `pc1`, `tcpdump -e -n -i eth0 vrrp` (source MAC addresses).
3. Stop keepalived on `r2`, read the entry of `pc2` again, then start it again. Compare with the
   entry of `pc1` for `{vip1}` when the group fails over.
""",
        """
**Solution.** Une ligne `use_vmac` dans l'instance `{name}` des deux routeurs, et
`systemctl restart keepalived`. keepalived crée sur **chaque** routeur, maître ou secours,
l'interface `{iface}` (un macvlan sur `eth0`) d'adresse MAC `{vmac}` ; l'adresse `{vip_ip}` y est
posée sur le maître, et les annonces de ce routeur virtuel partent avec cette adresse MAC pour
source. `pc2` associe `{vip_ip}` à `{vmac}`, avant comme après la bascule, alors que l'entrée de
`pc1` pour `{vip1}` passe de l'adresse MAC de `r1` à celle de `r2`. Le commutateur, lui, apprend que
`{vmac}` a changé de port à la première annonce du nouveau maître.
""": """
**Solution.** One line `use_vmac` in the instance `{name}` of both routers, and
`systemctl restart keepalived`. keepalived creates on **each** router, master or backup, the
interface `{iface}` (a macvlan on `eth0`) with the MAC address `{vmac}`; the address `{vip_ip}` is
put on it on the master, and the advertisements of this virtual router leave with that MAC
address as their source. `pc2` associates `{vip_ip}` with `{vmac}`, before and after the failover
alike, whereas the entry of `pc1` for `{vip1}` goes from the MAC address of `r1` to that of `r2`.
As for the switch, it learns that `{vmac}` changed ports at the first advertisement of the new
master.
""",
        'Ce qui change, ce qui ne change pas': 'What changes, what does not',
        """
D'après vos observations :
""": """
From your observations:
""",
        """
- adresse MAC virtuelle de la deuxième passerelle : @@{vmac:[0-9a-fA-F:-]+}@@
- interface créée par keepalived sur r1 et r2 : @@{iface:[A-Za-z0-9._-]+}@@
- deuxième passerelle : quand elle passe de r2 à r1, l'entrée ARP de pc2 : @@{arp_vip2:>ne change pas>>>same|devient l'adresse MAC de r1>>>r1}@@
- première passerelle (sans use_vmac) : quand elle passe de r1 à r2, l'entrée ARP de pc1 : @@{arp_vip1:>ne change pas>>>same|devient l'adresse MAC de r2>>>r2}@@
""": """
- virtual MAC address of the second gateway: @@{vmac:[0-9a-fA-F:-]+}@@
- interface created by keepalived on r1 and r2: @@{iface:[A-Za-z0-9._-]+}@@
- second gateway: when it moves from r2 to r1, the ARP entry of pc2: @@{arp_vip2:>does not change>>>same|becomes the MAC address of r1>>>r1}@@
- first gateway (without use_vmac): when it moves from r1 to r2, the ARP entry of pc1: @@{arp_vip1:>does not change>>>same|becomes the MAC address of r2>>>r2}@@
""",
        """
**Solution.** L'adresse MAC d'un routeur virtuel IPv4 est `00:00:5e:00:01:XX`, où `XX` est le VRID
en hexadécimal : ici `{vmac}` (VRID {vrid}), sur l'interface `{iface}`. Elle suit la passerelle
d'un routeur à l'autre : les caches ARP des clients restent valables. Sans `use_vmac`, l'adresse
virtuelle prend l'adresse MAC du routeur qui la détient, et les clients doivent être prévenus.
""": """
**Solution.** The MAC address of an IPv4 virtual router is `00:00:5e:00:01:XX`, where `XX` is the
VRID in hexadecimal: here `{vmac}` (VRID {vrid}), on the interface `{iface}`. It follows the
gateway from one router to the other: the ARP caches of the clients stay valid. Without
`use_vmac`, the virtual address takes the MAC address of the router holding it, and the clients
must be told.
""",
        'use_vmac dans la deuxième instance (r1, r2)': 'use_vmac in the second instance (r1, r2)',
        "sur la maquette : {vip} sur une interface d'adresse MAC {vmac} ; annonces émises depuis cette adresse ; pc2 l'associe à {vip}": 'on the real network: {vip} on an interface with the MAC address {vmac}; advertisements sent from that address; pc2 associates it with {vip}',
        'copie cachée : la requête ARP pour {vip} reçoit {vmac}, avant la bascule et après': 'hidden copy: the ARP request for {vip} gets {vmac}, before the failover and after',
        'adresse MAC virtuelle, interface macvlan, cache ARP inchangé avec use_vmac': 'virtual MAC address, macvlan interface, ARP cache unchanged with use_vmac',
        'Partie 7 — VRRPv3 et IPv6 (questions 14 et 15)': 'Part 7 — VRRPv3 and IPv6 (questions 14 and 15)',
        'Une passerelle IPv6 : VRRPv3 et annonces de routeur': 'An IPv6 gateway: VRRPv3 and router advertisements',
        """
Un client IPv6 apprend sa passerelle par les annonces de routeur (RA) : c'est l'adresse
**lien-local** dont part l'annonce. Pour qu'elle survive à une panne, cette adresse doit être
virtuelle (cf. section @@ref:vrrpv3-ipv6@@).

1. Sur `r1` et `r2`, ajoutez une instance sur `eth0` : VRID **{vrid}**, adresse virtuelle
   `{vip6}/64`, `r1` maître (priorité {master}), `r2` secours (priorité {backup}). Une instance IPv6
   est en VRRPv3. Ajoutez-la au groupe.
2. Le retour a lui aussi besoin d'une adresse virtuelle IPv6 côté `wan` : ajoutez `{vip6_wan}` à
   l'instance `VI_WAN`, dans un bloc `virtual_ipaddress_excluded` (une instance n'annonce qu'une
   famille d'adresses).
3. Sur `r1` et `r2`, écrivez `{radvd}` : annonces sur `eth0` du préfixe `{lan6}`, émises **depuis
   l'adresse virtuelle** (`AdvRASrcAddress`). Puis `systemctl enable --now radvd` et
   `keepalived -t && systemctl reload keepalived`.
4. Sur `isp` : `ip -6 route replace {lan6} via {vip6_wan_ip}`.

Vérifiez sur `pc1` : `ip -6 route` (la route par défaut), `ping {isp6}` et
`tcpdump -n -v -i eth0 'ip6 proto 112'` ; puis coupez `eth0` sur `r1` et recommencez le `ping`.
""": """
An IPv6 client learns its gateway from the router advertisements (RA): it is the **link-local**
address the advertisement leaves from. For it to survive a failure, that address must be virtual
(see section @@ref:vrrpv3-ipv6@@).

1. On `r1` and `r2`, add an instance on `eth0`: VRID **{vrid}**, virtual address `{vip6}/64`, `r1`
   master (priority {master}), `r2` backup (priority {backup}). An IPv6 instance is in VRRPv3. Add
   it to the group.
2. The way back also needs an IPv6 virtual address on the `wan` side: add `{vip6_wan}` to the
   instance `VI_WAN`, in a `virtual_ipaddress_excluded` block (an instance advertises a single
   address family).
3. On `r1` and `r2`, write `{radvd}`: advertisements on `eth0` of the prefix `{lan6}`, sent **from
   the virtual address** (`AdvRASrcAddress`). Then `systemctl enable --now radvd` and
   `keepalived -t && systemctl reload keepalived`.
4. On `isp`: `ip -6 route replace {lan6} via {vip6_wan_ip}`.

Check on `pc1`: `ip -6 route` (the default route), `ping {isp6}` and
`tcpdump -n -v -i eth0 'ip6 proto 112'`; then cut `eth0` on `r1` and run the `ping` again.
""",
        """
**Solution.** Dans `{conf}` de `r1` (sur `r2` : `state BACKUP`, `priority {backup}`), l'instance
IPv6, ajoutée à la liste `group` de `{group}`, et le bloc ajouté à `{wan}` :

```
{snippet}
```

`{radvd}`, identique sur les deux routeurs :

```
{radvd_text}
```

Sur `isp` : `ip -6 route replace {lan6} via {vip6_wan_ip}`. `pc1` reçoit
`default via {vip6} dev eth0 proto ra`. Seul le maître détient `{vip6}` : le radvd du secours, qui
ne trouve pas son adresse source, reste silencieux, sans erreur. À la bascule, le nouveau maître
émet une annonce de voisin non sollicitée pour `{vip6}` et `pc1` continue de joindre `isp`.
""": """
**Solution.** In `{conf}` of `r1` (on `r2`: `state BACKUP`, `priority {backup}`), the IPv6
instance, added to the `group` list of `{group}`, and the block added to `{wan}`:

```
{snippet}
```

`{radvd}`, the same on both routers:

```
{radvd_text}
```

On `isp`: `ip -6 route replace {lan6} via {vip6_wan_ip}`. `pc1` gets
`default via {vip6} dev eth0 proto ra`. Only the master holds `{vip6}`: the radvd of the backup,
which does not find its source address, stays silent, without any error. At the failover, the new
master sends an unsolicited neighbor advertisement for `{vip6}` and `pc1` goes on reaching `isp`.
""",
        'VRRPv3 vu dans une capture': 'VRRPv3 seen in a capture',
        """
D'après vos captures sur `pc1` (`tcpdump -n -v -i eth0 'ip6 proto 112'`, puis
`tcpdump -n -v -i eth0 icmp6`) :
""": """
From your captures on `pc1` (`tcpdump -n -v -i eth0 'ip6 proto 112'`, then
`tcpdump -n -v -i eth0 icmp6`):
""",
        """
- adresse de destination des annonces VRRPv3 en IPv6 : @@{group6:[0-9a-fA-F:]+}@@
- intervalle affiché par tcpdump dans une annonce VRRPv3 : @@{interval:>1s>>>s|100cs>>>cs|1000ms>>>ms}@@
- après une bascule, les voisins IPv6 sont prévenus par : @@{announce:>un ARP gratuit>>>garp|une annonce de voisin (NA) non sollicitée>>>na|une annonce de routeur (RA)>>>ra}@@
- adresse source des annonces de routeur reçues par pc1 : @@{ra_src:[0-9a-fA-F:]+}@@
""": """
- destination address of the VRRPv3 advertisements over IPv6: @@{group6:[0-9a-fA-F:]+}@@
- interval tcpdump prints in a VRRPv3 advertisement: @@{interval:>1s>>>s|100cs>>>cs|1000ms>>>ms}@@
- after a failover, the IPv6 neighbours are told by: @@{announce:>a gratuitous ARP>>>garp|an unsolicited neighbor advertisement (NA)>>>na|a router advertisement (RA)>>>ra}@@
- source address of the router advertisements received by pc1: @@{ra_src:[0-9a-fA-F:]+}@@
""",
        """
**Solution.** VRRPv3 (RFC 5798) envoie ses annonces à `ff02::12`, avec une limite de sauts de 255,
et exprime l'intervalle en centisecondes (`intvl 100cs`), ce qui permet des bascules en moins d'une
seconde. Il n'y a pas d'ARP en IPv6 : le nouveau maître émet une annonce de voisin non sollicitée.
Les annonces de routeur partent de `{vip6}`, que `pc1` prend pour passerelle.
""": """
**Solution.** VRRPv3 (RFC 5798) sends its advertisements to `ff02::12`, with a hop limit of 255,
and expresses the interval in centiseconds (`intvl 100cs`), which allows failovers in less than a
second. There is no ARP in IPv6: the new master sends an unsolicited neighbor advertisement. The
router advertisements leave from `{vip6}`, which `pc1` takes as its gateway.
""",
        "instance de VRID {vrid} sur eth0 avec l'adresse {vip6} (r1, r2), membre du groupe": 'instance of VRID {vrid} on eth0 with the address {vip6} (r1, r2), member of the group',
        '{vip6} dans virtual_ipaddress_excluded de VI_WAN (r1, r2) ; route IPv6 de isp vers le réseau local par cette adresse': '{vip6} in virtual_ipaddress_excluded of VI_WAN (r1, r2); IPv6 route of isp to the local network through that address',
        'radvd.conf avec AdvRASrcAddress {vip6} (r1, r2) ; radvd actif sur les deux': 'radvd.conf with AdvRASrcAddress {vip6} (r1, r2); radvd active on both',
        'sur la maquette : {vip6} sur r1 seul ; annonces VRRPv3 vers ff02::12 ; pc1 a reçu sa route par défaut de {vip6} et joint isp en IPv6': 'on the real network: {vip6} on r1 alone; VRRPv3 advertisements to ff02::12; pc1 got its default route from {vip6} and reaches isp over IPv6',
        'copie cachée, état nominal : annonce de routeur émise depuis {vip6} ; pc1 joint isp en IPv6': 'hidden copy, nominal state: router advertisement sent from {vip6}; pc1 reaches isp over IPv6',
        'copie cachée, lien LAN de r1 coupé : r2 prend {vip6} ; pc1 joint toujours isp en IPv6': 'hidden copy, LAN link of r1 down: r2 takes {vip6}; pc1 still reaches isp over IPv6',
        "VRRPv3 : groupe ff02::12, intervalle en centisecondes, annonce de voisin, RA depuis l'adresse virtuelle": 'VRRPv3: group ff02::12, interval in centiseconds, neighbor advertisement, RA from the virtual address',
    },
}
