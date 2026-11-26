"""TP IPv6 : adressage et découverte de voisins, routage statique, SLAAC, DHCPv6, MTU et PMTUD en
double pile, tunnel 6in4.

Maquette double pile : ``m1 — lan1 — r1 — wan1 — wan — wan2 — r2 — lan2 — m2``, plus ``lan3`` sur la
troisième interface de ``r2`` avec le serveur ``srv`` (image init13 : DHCPv6) et deux postes ``pc1``
(SLAAC) et ``pc2`` (DHCPv6).  L'IPv4 est déjà configuré partout (le réseau « historique ») ; les
étudiants déploient IPv6 par-dessus : adresses et routes statiques de ``m1``, ``r1``, ``r2``, ``m2``
et ``srv`` (l'opérateur ``wan`` est pré-configuré et route un /48 par site), annonces de routeur sur
``r2``, DHCPv6 sans état puis avec état sur ``srv``, puis la partie MTU du TP ``mtu6.py`` (Packet Too
Big, trou noir PMTUD des deux familles, tunnel 6in4).

Notation par sondes cachées : ``h1`` (lan1) et ``h2`` (lan2) sont les hôtes double pile que ``wan``
maintient derrière un trou noir PMTUD permanent (table nftables ``sondes``), ``h3`` (lan3) envoie
les sollicitations de routeur et les requêtes DHCPv6 de l'évaluation (``lib/ipv6_probe.py``).
Les adresses MAC de ``m1``, ``r1`` (lan1), ``r2`` (lan3), ``pc1`` et ``pc2`` sont fixées par le TP :
adresses de lien local, adresse SLAAC de ``pc1`` et DUID-LL de ``pc2`` sont donc prévisibles.
L'état ``final`` applique la solution de référence et remplit les formulaires.  Chaque question se
termine par sa solution dans un bloc ``instructor()`` (mode enseignant), calculée pour les valeurs
du projet.  Les fonctions pures sont dans ``lib/ipv6.py`` et ``lib/pmtu.py``.

Debian n'a qu'un service ``isc-dhcp-server`` (script SysV) : il lance ``dhcpd -4`` et/ou ``dhcpd -6``
selon ``INTERFACESv4`` / ``INTERFACESv6`` de ``/etc/default/isc-dhcp-server``.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Interface, IPv6Network
from typing import Dict

import pmtu
import tc
from SRE import params
from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ipv6 import (
    DHCPD6_CONF, DHCPD6_DEFAULTS, DHCPD6_LEASES, DHCPD6_UNIT, MAC_PREFIX,
    advertised, default_routes6, dhcp6_query, duid_ll, get_dhclient6_leases, get_dhcpd6_interfaces,
    get_ip6_addrs, get_ip6_routes, get_resolv_conf, global_addresses, install_ipv6_probe, ipv6_probe,
    ipv6_probe_spec, ipv6_subnet, link_local_addresses, link_local_from_mac, mac_str, multicast_mac,
    normalize_duid, parse_ipv6, radvd_running, render_dhcpd6_conf, same_ipv6, slaac_address, small_ipv6s,
    solicited_node_multicast,
)
from ips import random_ipv4networks, random_ipv6networks, random_ips_from_topology, random_mac_address
from net_config import (
    NetConfigEntry, eval_net_config, get_ipv6_forward, get_net_config_entry, get_persistent_net_config_entry,
    net_config_entry_family, remount_proc_sys, render_persistent_net_config_entry, set_ip_forward,
    set_ipv6_forward, set_net_config_entry, set_persistent_net_config_entry,
)
from ping import eval_ping
from state_helpers import create_hosts_file, render_radvd_conf, set_radvd, set_slaac_client

ipv6 = True   # IPv6 enabled in every container

default_language = 'fr'
tr = make_tr(default_language)

title = tr("IPv6 : adressage, routage statique, SLAAC, DHCPv6, MTU et tunnel 6in4",
           en="IPv6: addressing, static routing, SLAAC, DHCPv6, MTU and 6in4 tunnel")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True
# The Kathara export would reveal the operator's MTU, the probes and the solutions.
export_kathara_project = False
# An evaluation runs ~10 s of probes and transfers between the hidden machines.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp-ipv6.lan"
#: MTU of the operator's link: N-20 (6in4) stays >= 1280, N-48 < 1452
MTU_CHOICES = list(range(1320, 1461, 20))
#: DHCPv6 valid lifetime (default-lease-time of dhcpd6.conf), away from the ISC default (43200)
LEASE6_CHOICES = [600, 900, 1200, 1800]
#: first offset of the DHCPv6 range6 (0x1000 addresses long)
POOL_STARTS = [0x1000, 0x2000, 0x3000, 0x5000, 0x8000, 0xa000, 0xc000]
POOL_SIZE = 0x1000
GRADE_PORT_V4, GRADE_PORT_V6 = 5301, 5302   # iperf3 servers of the probe h2 (one client at a time each)
PROBE_TABLE = "sondes"            # wan: permanent black hole toward the probes h1 / h2 only
PROBE_RULES = "/root/sondes.nft"
TN_TABLE = "trou_noir"            # wan: black hole toward everybody (states trou_noir / icmp_retabli)
TN_RULES = "/root/trou_noir.nft"
CLAMP_TABLE = "mss_clamp"         # r1 / r2: reference solution
CLAMP_RULES = "/root/mss_clamp.nft"
TUN_DEV = "sit1"
TUN_OVERHEAD = pmtu.SIT_OVERHEAD  # 20: IPv6 packet inside a plain IPv4 packet (protocol 41)
MIN_BYTES = 100_000               # a transfer "works" above this (≈ 0 under the black hole, ~5 MB otherwise)
WAN_IFACE = {'r1': 'eth1', 'r2': 'eth0'}   # interfaces of the students' routers toward the operator
PROBE_WAIT = 5.0                  # seconds the probe collects RAs / DHCPv6 replies
INIT_MACHINE = {"image": sre_docker_image("init13"), "privileged": True, "entrypoint": "/sbin/init"}
# the privileged machines: /proc/sys is already writable (remount_proc_sys would fail)
PRIVILEGED = ('srv',)
#: visible machines with a static configuration (IPv4 pre-configured, IPv6 configured by the students)
STATIC_MACHINES = ('m1', 'r1', 'wan', 'r2', 'm2', 'srv')
STUDENT_STATIC = ('m1', 'r1', 'r2', 'm2', 'srv')
PERSISTENT_MACHINES = ('m1', 'r1')     # /etc/network/interfaces asked (inet6 static)
PROBES = ('h1', 'h2', 'h3')
AUTO_HOSTS = ('pc1', 'pc2')            # SLAAC / DHCPv6 hosts of lan3
ROUTERS4 = ('r1', 'wan', 'r2')         # IPv4 forwarding from the start
ROUTERS6 = ('r1', 'r2')                # IPv6 forwarding to be enabled by the students (wan has it)
MTU_MACHINES = ('m1', 'r1', 'r2', 'm2')   # machines of the MTU parts
# Creation-time sysctls (Kathara meta): EUI-64 link-local addresses whatever the host's defaults,
# no temporary addresses; the static machines ignore router advertisements.
HOST_SYSCTLS = ('net.ipv6.conf.default.addr_gen_mode=0', 'net.ipv6.conf.default.use_tempaddr=0',
                'net.ipv6.conf.all.use_tempaddr=0')
STATIC_SYSCTLS = HOST_SYSCTLS + ('net.ipv6.conf.default.accept_ra=0', 'net.ipv6.conf.default.autoconf=0')
DHCLIENT6_CLEANUP = "pkill -x dhclient; rm -f /run/dhclient6*.pid /var/lib/dhcp/dhclient6*.leases"
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

#: interfaces of the multi-homed machines are explicit: r1 0/1, wan 0/1, r2 0/1/2
_TOPOLOGY = {
    'lan1': {'m1': 0, 'r1': 0, 'h1': 0},
    'wan1': {'r1': 1, 'wan': 0},
    'wan2': {'wan': 1, 'r2': 0},
    'lan2': {'r2': 1, 'm2': 0, 'h2': 0},
    'lan3': {'r2': 2, 'srv': 0, 'pc1': 0, 'pc2': 0, 'h3': 0},
}
_SPECS = {
    'm1': {'color': 'lightyellow', 'sysctls': STATIC_SYSCTLS},
    'r1': {'color': 'lightblue', 'sysctls': STATIC_SYSCTLS},
    'wan': {'allow_connection': False, 'color': 'lightgrey', 'sysctls': STATIC_SYSCTLS},   # operator: no terminal
    'r2': {'color': 'lightblue', 'sysctls': STATIC_SYSCTLS},
    'm2': {'color': 'lightyellow', 'sysctls': STATIC_SYSCTLS},
    'srv': {**INIT_MACHINE, 'color': 'lightgreen', 'sysctls': STATIC_SYSCTLS},   # DHCPv6 + DNS server
    'pc1': {'color': 'lightcyan', 'sysctls': HOST_SYSCTLS},    # SLAAC host
    'pc2': {'color': 'lightcyan', 'sysctls': HOST_SYSCTLS},    # DHCPv6 host (autoconf off)
    'h1': {'hidden': True, 'sysctls': STATIC_SYSCTLS},         # grading probes
    'h2': {'hidden': True, 'sysctls': STATIC_SYSCTLS},
    'h3': {'hidden': True, 'sysctls': STATIC_SYSCTLS},
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _addr(network, offset: int) -> IPv6Interface:
    """Address *offset* of *network*, with the prefix of the network."""
    return IPv6Interface((int(network.network_address) + offset, network.prefixlen))


@dataclass(slots=True)
class Data(Data0):
    wan_mtu: int = 0   # MTU of both interfaces of wan (never printed in the student texts)
    lease6: int = 0    # DHCPv6 valid lifetime asked of the students (default-lease-time)

    @classmethod
    def generate(cls):
        data = cls()
        data.wan_mtu = random.choice(MTU_CHOICES)
        data.lease6 = random.choice(LEASE6_CHOICES)

        # IPv4: the legacy network, pre-configured everywhere (pc1 / pc2 keep an unused address)
        (data.nets.lan1, data.nets.wan1, data.nets.wan2, data.nets.lan2, data.nets.lan3) = random_ipv4networks(
            masks=[24] * 5, from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")])
        random_ips_from_topology(data, _TOPOLOGY)   # ips.m1, ips.r1_lan1, ips.r1_wan1, ips.wan_wan1, ...

        # IPv6: one unique local /48 per site (RFC 4193), /64 subnets inside; the operator's links
        # and the inner prefix of the 6in4 tunnel are /64 of their own.
        n6 = data.nets6
        n6.site1, n6.site2 = random_ipv6networks(masks=[48, 48], from_private_network=True)
        n6.wan1, n6.wan2, n6.tun = random_ipv6networks(masks=[64, 64, 64], from_private_network=True,
                                                      exclude=[n6.site1, n6.site2])
        n6.lan1 = ipv6_subnet(n6.site1, 1)
        n6.lan2 = ipv6_subnet(n6.site2, 1)
        n6.lan3 = ipv6_subnet(n6.site2, 2)

        # Routers get ::1 (operator side) / ::2, hosts short random interface identifiers:
        # students type these addresses.
        i6 = data.ips6
        i6.r1_lan1, i6.r2_lan2, i6.r2_lan3 = _addr(n6.lan1, 1), _addr(n6.lan2, 1), _addr(n6.lan3, 1)
        i6.wan_wan1, i6.r1_wan1 = _addr(n6.wan1, 1), _addr(n6.wan1, 2)
        i6.wan_wan2, i6.r2_wan2 = _addr(n6.wan2, 1), _addr(n6.wan2, 2)
        i6.r1_tun, i6.r2_tun = _addr(n6.tun, 1), _addr(n6.tun, 2)
        i6.m1, i6.h1 = small_ipv6s(n6.lan1, 2, low=0x10, exclude=[1])
        i6.m2, i6.h2 = small_ipv6s(n6.lan2, 2, low=0x10, exclude=[1])
        i6.srv, i6.h3, i6.pc2_fixe = small_ipv6s(n6.lan3, 3, low=0x10, exclude=[1])
        pool_start = random.choice(POOL_STARTS)   # DHCPv6 range6: outside the short identifiers
        i6.pool_min, i6.pool_max = _addr(n6.lan3, pool_start), _addr(n6.lan3, pool_start + POOL_SIZE - 1)

        # Fixed MAC addresses: link-local / SLAAC / DUID-LL values become predictable.
        (data.macs.m1, data.macs.r1_lan1, data.macs.r2_lan3, data.macs.pc1, data.macs.pc2,
         data.macs.probe) = random_mac_address(prefix=MAC_PREFIX, n=6)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = _SPECS
    _network_specs = {
        'lan1': {'color': 'lightyellow'},
        'wan1': {'color': 'lightgrey'},
        'wan2': {'color': 'lightgrey'},
        'lan2': {'color': 'lightyellow'},
        'lan3': {'color': 'lightcyan'},
    }

    @property
    def _topology(self):
        macs = self.data.macs
        return {
            'lan1': {'m1': (0, macs.m1), 'r1': (0, macs.r1_lan1), 'h1': 0},
            'wan1': {'r1': 1, 'wan': 0},
            'wan2': {'wan': 1, 'r2': 0},
            'lan2': {'r2': 1, 'm2': 0, 'h2': 0},
            'lan3': {'r2': (2, macs.r2_lan3), 'srv': 0, 'pc1': (0, macs.pc1), 'pc2': (0, macs.pc2), 'h3': 0},
        }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        d4, d6 = d.ips, d.ips6
        default4, default6 = IPv4Network("0.0.0.0/0"), IPv6Network("::/0")
        # Expected dual-stack configuration (IPv4 first): applied in IPv4 at the start, in IPv6
        # by the students (m1, r1, r2, m2, srv) or at the start (wan, probes).  The operator
        # routes one /48 per site.  pc1 / pc2 have no static address.
        self.net_config: Dict[str, NetConfigEntry] = {
            'm1': [([d4.m1, d6.m1], [(default4, d4.r1_lan1), (default6, d6.r1_lan1)])],
            'h1': [([d4.h1, d6.h1], [(default4, d4.r1_lan1), (default6, d6.r1_lan1)])],
            'r1': [([d4.r1_lan1, d6.r1_lan1], []),
                   ([d4.r1_wan1, d6.r1_wan1], [(default4, d4.wan_wan1), (default6, d6.wan_wan1)])],
            'wan': [([d4.wan_wan1, d6.wan_wan1], [(d.nets.lan1, d4.r1_wan1), (d.nets6.site1, d6.r1_wan1)]),
                    ([d4.wan_wan2, d6.wan_wan2], [(d.nets.lan2, d4.r2_wan2), (d.nets.lan3, d4.r2_wan2),
                                                  (d.nets6.site2, d6.r2_wan2)])],
            'r2': [([d4.r2_wan2, d6.r2_wan2], [(default4, d4.wan_wan2), (default6, d6.wan_wan2)]),
                   ([d4.r2_lan2, d6.r2_lan2], []),
                   ([d4.r2_lan3, d6.r2_lan3], [])],
            'm2': [([d4.m2, d6.m2], [(default4, d4.r2_lan2), (default6, d6.r2_lan2)])],
            'h2': [([d4.h2, d6.h2], [(default4, d4.r2_lan2), (default6, d6.r2_lan2)])],
            'srv': [([d4.srv, d6.srv], [(default4, d4.r2_lan3), (default6, d6.r2_lan3)])],
            'h3': [([d4.h3, d6.h3], [(default4, d4.r2_lan3), (default6, d6.r2_lan3)])],
            'pc1': [None],
            'pc2': [None],
        }

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Pourquoi IPv6"), tag="why")
            + tr("""

IPv4 numérote les machines sur **32 bits** : 4 milliards d'adresses, une par machine en théorie,
beaucoup moins en pratique à cause du découpage en réseaux. Les derniers blocs libres ont été
attribués en 2011 (IANA) et entre 2012 et 2019 (registres régionaux). Depuis, les adresses IPv4
se rachètent, se partagent (NAT, *carrier-grade NAT* chez les opérateurs) et se bricolent, au prix
de la règle fondatrice d'Internet : **une machine, une adresse, joignable de bout en bout**.

**IPv6** (RFC 2460 en 1998, RFC 8200 en 2017) reprend le modèle d'IPv4 avec des adresses de
**128 bits** : 3,4 × 10³⁸ adresses, assez pour donner un réseau entier à chaque machine. Le
protocole en profite pour simplifier ce qui gênait IPv4 :

| | IPv4 | IPv6 |
|---|---|---|
| adresse | 32 bits, notation décimale pointée | 128 bits, notation hexadécimale |
| en-tête | 20 octets + options, somme de contrôle | 40 octets fixes, pas de somme de contrôle, extensions en chaîne |
| diffusion | *broadcast* | n'existe plus : multidiffusion (*multicast*) |
| résolution des adresses MAC | ARP | découverte de voisins (ICMPv6) |
| configuration automatique | DHCP seulement | annonces de routeur (SLAAC), DHCPv6 |
| fragmentation | par les routeurs | par la source seulement |
| NAT | omniprésent | inutile : adresses publiques pour tous |
| adresses par interface | une, en général | plusieurs, de portées différentes |

IPv6 n'est pas compatible avec IPv4 : une machine IPv6 pure ne parle pas à une machine IPv4 pure.
D'où la **double pile** (*dual stack*), chaque machine ayant les deux adresses et les deux routages,
pendant une transition commencée il y a vingt ans. En 2026, un peu moins de la moitié des accès à
Google se font en IPv6 ; les opérateurs mobiles et les grands hébergeurs l'utilisent en interne, et
de plus en plus de réseaux sont **IPv6 seulement** avec une traduction (NAT64) vers le vieux monde.
""")
            + info_subtitle(tr("L'écriture des adresses"), tag="notation")
            + tr("""

Une adresse IPv6 s'écrit en **hexadécimal**, en huit groupes de 16 bits séparés par deux-points :

```
2001:0db8:0000:0000:0000:0000:0000:0001
```

Deux règles abrègent l'écriture (RFC 5952 fixe la forme canonique) :

- les **zéros de tête** de chaque groupe sont supprimés : `2001:db8:0:0:0:0:0:1` ;
- **une seule** suite de groupes nuls peut être remplacée par `::` (la plus longue, la première en
  cas d'égalité) : `2001:db8::1`.

`::` seul est l'adresse nulle, `::1` l'adresse de bouclage. Les lettres s'écrivent en minuscules.
Le **préfixe** se note comme en IPv4 : `2001:db8:1::/64` est le réseau, `2001:db8:1::a/64` une
adresse avec la longueur de son préfixe (il n'y a plus de masque écrit en long).

Comme les deux-points servent déjà, une adresse suivie d'un port se met entre **crochets** :
`http://[2001:db8::1]:8080/`, `[2001:db8::1]:22`. Enfin une adresse de lien local (section @@ref:types@@) ne
désigne une machine qu'avec le nom de l'interface par laquelle on la joint, après `%` :
`ping fe80::1%eth0`, `ssh root@fe80::1%eth0`.

Quelques formes rencontrées dans ce TP :

| forme | signification |
|---|---|
| `fd12:3456:789a:1::/64` | un réseau (préfixe de 64 bits) |
| `fd12:3456:789a:1::1/64` | l'adresse `::1` de ce réseau, avec son préfixe |
| `fe80::53:52ff:fe12:3456%eth0` | une adresse de lien local, jointe par `eth0` |
| `ff02::1` | le groupe multicast « tous les nœuds du lien » |
| `::/0` | la route par défaut (`default` dans `ip -6 route`) |
""")
            + info_subtitle(tr("Les types d'adresses"), tag="types")
            + tr("""

Les premiers bits d'une adresse disent à quoi elle sert (RFC 4291) :

| préfixe | type | usage |
|---|---|---|
| `2000::/3` | **unicast global** (de `2000::` à `3fff:…`) | les adresses publiques, attribuées par les opérateurs et les registres |
| `fc00::/7`, en pratique `fd00::/8` | **unicast local unique** (ULA, RFC 4193) | adresses privées d'un site, non routées sur Internet : les 40 bits qui suivent `fd` sont tirés au sort pour que deux sites n'aient pas le même préfixe |
| `fe80::/10` | **lien local** (*link-local*) | une adresse par interface, construite sans aucune configuration, valable sur le lien seulement : jamais routée |
| `::1/128` | bouclage | `localhost` |
| `::/128` | non spécifiée | « pas encore d'adresse » (source des premiers messages d'une machine qui démarre) |
| `ff00::/8` | **multicast** | groupes de machines (section suivante) |
| `::ffff:0:0/96` | IPv4 projetée (*IPv4-mapped*) | `::ffff:192.0.2.1` : une adresse IPv4 vue par une socket IPv6 double pile |
| `2001:db8::/32` | documentation | réservée aux exemples (RFC 3849), comme `192.0.2.0/24` en IPv4 |
| `64:ff9b::/96` | NAT64 | préfixe de traduction vers IPv4 (RFC 6052) |

Une interface a **toujours plusieurs adresses** : son adresse de lien local, une ou plusieurs
adresses globales ou ULA, et les adresses des groupes multicast auxquels elle appartient. Le
TP emploie des adresses **ULA** (`fd00::/8`), ce qui ne change rien aux mécanismes.

### @@sec@@ Multicast

Il n'y a plus de diffusion en IPv6 : tout ce qui s'adresse « à tout le monde » passe par un groupe
multicast, et seules les machines inscrites traitent la trame. Le quatrième chiffre hexadécimal de
l'adresse est sa **portée** : `ff01` (interface), `ff02` (**lien**), `ff05` (site), `ff0e` (global).

| groupe | membres |
|---|---|
| `ff02::1` | tous les nœuds du lien (`ping -6 ff02::1%eth0` fait répondre toutes les machines du lien) |
| `ff02::2` | tous les routeurs du lien (destinataire des sollicitations de routeur) |
| `ff02::1:2` | tous les serveurs et relais DHCPv6 du lien |
| `ff02::1:ffxx:xxxx` | **nœud sollicité** (*solicited-node*) : groupe propre à chaque adresse, formé de `ff02::1:ff` et des 24 derniers bits de l'adresse ; sert à la découverte de voisins |
| `ff02::fb`, `ff02::5`, `ff02::9` | mDNS, OSPFv3, RIPng |

Une adresse multicast se transporte dans une trame Ethernet dont l'adresse MAC de destination est
`33:33` suivi des quatre derniers octets de l'adresse IPv6 (`ff02::1` → `33:33:00:00:00:01`).

### @@sec@@ Anycast

Une même adresse peut être portée par plusieurs machines : un paquet est remis à la plus proche.
Chaque préfixe réserve ainsi son adresse `::0` (*subnet-router anycast*, tous les routeurs du
réseau) : c'est pourquoi la première adresse d'un réseau n'est pas donnée à une machine.
""")
            + info_subtitle(tr("Le plan d'adressage et l'identifiant d'interface"), tag="addressing")
            + tr("""

Une adresse unicast se découpe en un **préfixe de réseau** et un **identifiant d'interface**
(*interface ID*). Sur un réseau où les machines se configurent seules, le préfixe fait **64 bits**
et l'identifiant 64 bits : le `/64` est la taille normale d'un réseau IPv6, même pour deux
machines. Un site reçoit de son opérateur un préfixe plus court, typiquement un **/48** (65 536
réseaux /64) ou un **/56** (256 réseaux) chez les particuliers : il le découpe lui-même, un /64 par
LAN, et l'opérateur ne route que l'**agrégat** (le /48), jamais chaque /64. Les liens entre deux
routeurs peuvent recevoir un `/127` (RFC 6164) ; on leur donne souvent un /64 quand même.

```
fd12:3456:789a:0001:0000:0000:0000:0042
└───────────┬────────┘└─────────┬────────┘
      préfixe /64          identifiant d'interface
└────┬────┘└──┬─┘
 site /48   réseau n° 1 du site
```

### @@sec@@ D'où vient l'identifiant d'interface ?

| méthode | identifiant | où |
|---|---|---|
| **manuel** | choisi par l'administrateur (`::1`, `::53`…) | routeurs, serveurs |
| **EUI-64 modifié** (RFC 4291) | déduit de l'adresse MAC : on insère `ff:fe` au milieu des 6 octets et on inverse le bit *universal/local* (le 2ᵉ bit de poids faible du premier octet) : `02:53:52:aa:bb:cc` → `0053:52ff:feaa:bbcc` | adresses de lien local de Linux, SLAAC par défaut dans un conteneur |
| **stable et opaque** (RFC 7217) | haché à partir du préfixe, de l'interface et d'un secret : stable sur un réseau donné, différent d'un réseau à l'autre, sans révéler l'adresse MAC | SLAAC des systèmes modernes (`addr_gen_mode=2` ou `3` sous Linux) |
| **temporaire** (RFC 8981, *privacy extensions*) | tiré au sort et renouvelé (un jour) : les connexions sortantes ne sont pas traçables | postes clients ; `use_tempaddr` sous Linux |
| **DHCPv6** | choisi par le serveur | section @@ref:dhcpv6@@ |

Dans ce TP, le sysctl `net.ipv6.conf.*.addr_gen_mode` vaut 0 : les identifiants automatiques sont
en **EUI-64**, donc calculables à partir de l'adresse MAC (`ip link show eth0`).
""")
            + info_subtitle(tr("L'en-tête IPv6 et les en-têtes d'extension"), tag="header")
            + tr("""

L'en-tête fait **40 octets, toujours** : pas d'options, pas de somme de contrôle (celles de TCP,
UDP et ICMPv6 couvrent l'adresse), pas de champs de fragmentation.

| champ | bits | rôle |
|---|---|---|
| version | 4 | 6 |
| classe de trafic | 8 | qualité de service (l'équivalent du TOS / DSCP) |
| étiquette de flux | 20 | identifie un flux pour un traitement homogène (peu utilisé) |
| longueur de la charge utile | 16 | ce qui suit l'en-tête, extensions comprises |
| **en-tête suivant** (*next header*) | 8 | protocole de ce qui suit : 6 TCP, 17 UDP, **58 ICMPv6**, ou un en-tête d'extension |
| limite de sauts (*hop limit*) | 8 | le TTL : décrémenté par chaque routeur, le paquet est jeté à 0 |
| adresse source, adresse destination | 128 + 128 | |

Tout ce qui était optionnel en IPv4 passe dans des **en-têtes d'extension**, chaînés par le champ
*next header* entre l'en-tête IPv6 et le transport, et traités seulement par le destinataire (sauf
*hop-by-hop*) :

| extension | *next header* | rôle |
|---|---|---|
| *hop-by-hop options* | 0 | examinée par chaque routeur (alertes, jumbogrammes) |
| *routing* | 43 | routage par la source, segment routing |
| **fragment** | **44** | fragmentation par la source (section @@ref:mtu@@) |
| ESP, AH | 50, 51 | IPsec |
| *destination options* | 60 | options pour le destinataire |

`tcpdump -n -v -i eth0 ip6` montre `flowlabel`, `hlim` et `next-header`. Un routeur IPv6 ne
recalcule aucune somme de contrôle et ne fragmente jamais : il ne fait que décrémenter *hop limit*
et transmettre.
""")
            + info_subtitle(tr("ICMPv6"), tag="icmpv6")
            + tr("""

ICMPv6 (RFC 4443, *next header* 58) fait beaucoup plus que signaler des erreurs : il porte la
**découverte de voisins** (section @@ref:ndp@@), les **annonces de routeur** (section @@ref:slaac@@) et la gestion des
groupes multicast (MLD). Le filtrer en bloc casse IPv6.

| type | nom | rôle |
|---|---|---|
| 1 | *destination unreachable* | code 0 pas de route, 1 interdit, 3 adresse injoignable, 4 port injoignable |
| 2 | **packet too big** | le paquet dépasse le MTU du lien suivant (section @@ref:mtu@@) ; il porte ce MTU |
| 3 | *time exceeded* | *hop limit* tombé à 0 (`traceroute`) |
| 4 | *parameter problem* | en-tête incompréhensible |
| 128, 129 | *echo request*, *echo reply* | `ping` |
| 130, 131, 132, 143 | MLD (*multicast listener*) | inscription aux groupes multicast |
| **133** | **router solicitation** (RS) | « y a-t-il un routeur ? » (vers `ff02::2`) |
| **134** | **router advertisement** (RA) | les routeurs se présentent et annoncent les préfixes (vers `ff02::1` ou en réponse à un RS) |
| **135** | **neighbor solicitation** (NS) | « qui a cette adresse ? » (l'ARP *request*), vers le groupe du nœud sollicité ; détection d'adresse dupliquée |
| **136** | **neighbor advertisement** (NA) | « c'est moi, voici mon adresse MAC » (l'ARP *reply*) |
| 137 | *redirect* | un routeur indique un meilleur premier saut sur le lien |

Les messages de découverte de voisins voyagent avec un *hop limit* de **255** : un message qui
arrive avec moins a traversé un routeur et est ignoré (ils ne quittent jamais le lien).
`tcpdump -n -v -i eth0 icmp6` les affiche tous ; `icmp6 and ip6[40] == 134` ne garde que les RA
(le type est le premier octet après les 40 de l'en-tête).
""")
            + info_subtitle(tr("La découverte de voisins (NDP)"), tag="ndp")
            + tr("""

Le protocole de découverte de voisins (*Neighbor Discovery*, RFC 4861) remplace ARP et une partie
de DHCP. Pour envoyer un paquet à une adresse du lien, une machine doit connaître l'adresse MAC
correspondante :

```
   m1                                                    r1
    |--- NS, de m1 vers ff02::1:ff00:1 (nœud sollicité) --->|   "qui a fd…::1 ?"  option : MAC de m1
    |<-- NA, de fd…::1 vers m1 ------------------------------|   "moi, MAC 02:53:52:…"  drapeau S (sollicité)
```

- le **NS** part vers le groupe du nœud sollicité de l'adresse cherchée (`ff02::1:ff` + ses 24
  derniers bits, trame `33:33:ff:xx:xx:xx`) : seules les machines dont l'adresse se termine ainsi
  le reçoivent, au lieu de toutes comme avec ARP ;
- le **NA** répond en unicast, avec l'adresse MAC dans une option ; le drapeau *override* (O) force
  la mise à jour du cache, le drapeau *router* (R) dit si l'émetteur est un routeur.

### @@sec@@ Le cache de voisins

`ip -6 neigh` montre les correspondances adresse → MAC et leur état (`REACHABLE`, `STALE` : à
reconfirmer au prochain envoi, `DELAY`, `PROBE`, `FAILED`). Une entrée `STALE` est réutilisée tout
de suite et vérifiée en arrière-plan : la découverte de voisins vérifie en permanence que le voisin
répond encore (*Neighbor Unreachability Detection*), ce qu'ARP ne faisait pas.

### @@sec@@ La détection d'adresse dupliquée (DAD)

Avant d'utiliser une adresse (manuelle, automatique ou de lien local), une machine envoie un **NS**
pour sa propre adresse, avec l'adresse source **non spécifiée** `::`. Si un NA revient, l'adresse est
déjà prise : elle est marquée `dadfailed` et n'est pas utilisée. Pendant la vérification (une
seconde), `ip -6 addr` la montre `tentative`. C'est pourquoi une adresse tout juste ajoutée ne
répond pas immédiatement.

### @@sec@@ La redirection

Quand un routeur reçoit un paquet qu'il renvoie sur le lien d'où il vient, il envoie à la source un
*redirect* (type 137) : « pour cette destination, passe plutôt par ce voisin ». Les hôtes mettent à
jour leur cache de destinations (`ip -6 route get`).
""")
            + info_subtitle(tr("Les routeurs et leurs annonces : SLAAC"), tag="slaac")
            + tr("""

En IPv6 ce sont les **routeurs** qui renseignent les machines sur leur réseau, par des **annonces de
routeur** (RA, ICMPv6 type 134) envoyées périodiquement à `ff02::1` (toutes les quelques minutes) et
en réponse aux **sollicitations** (RS, type 133, vers `ff02::2`) d'une machine qui démarre. Une
annonce contient :

| champ ou option | rôle |
|---|---|
| **durée de vie du routeur** (*router lifetime*) | > 0 : l'émetteur est un **routeur par défaut** pour cette durée ; 0 : il annonce des préfixes mais pas de route par défaut |
| drapeau **M** (*managed*) | « obtenez vos adresses par DHCPv6 » |
| drapeau **O** (*other*) | « obtenez les autres paramètres (DNS…) par DHCPv6 » |
| option **préfixe** (*prefix information*) | un préfixe du lien, avec ses durées de vie et deux drapeaux : **L** (*on-link* : les adresses de ce préfixe sont directement joignables sur le lien) et **A** (*autonomous* : les machines peuvent s'en fabriquer une adresse) |
| option **MTU** | le MTU du lien |
| option **RDNSS** (RFC 8106) | adresses de serveurs DNS récursifs |
| option **DNSSL** | domaines de recherche |
| option *source link-layer address* | l'adresse MAC du routeur (entrée du cache de voisins) |
| *cur hop limit*, *reachable time*, *retrans timer* | paramètres de la pile |

### @@sec@@ L'autoconfiguration sans état (SLAAC, RFC 4862)

Une machine qui démarre :

1. se fabrique son adresse de **lien local** (`fe80::` + identifiant d'interface) et la vérifie (DAD) ;
2. envoie un **RS** et reçoit les **RA** ;
3. pour chaque préfixe annoncé avec le drapeau **A**, forme une adresse **préfixe + identifiant
   d'interface** (EUI-64 ou autre, section @@ref:addressing@@), la vérifie (DAD), et l'utilise avec les durées de
   vie annoncées (`valid_lft`, `preferred_lft` dans `ip -6 addr`, qui décroissent entre deux annonces) ;
4. installe une **route par défaut** vers l'adresse **de lien local** du routeur (`default via
   fe80::… dev eth0 proto ra expires …`) pour la durée de vie du routeur ;
5. selon M et O, interroge un serveur DHCPv6 (section @@ref:dhcpv6@@).

Aucun serveur, aucun état : chaque machine se débrouille avec ce que le routeur annonce. Le prix :
le routeur ne sait pas qui a quelle adresse, et la machine n'obtient ses serveurs DNS que si le
routeur les annonce (RDNSS) **et** si son système sait lire cette option (sous Linux : `rdnssd`,
NetworkManager, systemd-networkd ; pas le noyau seul).

### @@sec@@ Côté Linux

| sysctl `net.ipv6.conf.<iface>.` | rôle |
|---|---|
| `forwarding` | 1 : la machine route (et, par défaut, **ignore** les annonces de routeur) |
| `accept_ra` | 0 : ignorer les RA ; 1 : les accepter si `forwarding` = 0 ; **2** : les accepter même en routant |
| `autoconf` | 1 : former une adresse pour chaque préfixe avec A (0 : garder seulement la route par défaut) |
| `addr_gen_mode` | 0 : identifiant EUI-64 ; 2, 3 : identifiant stable (RFC 7217) |
| `use_tempaddr` | 2 : adresses temporaires préférées pour sortir |

`sysctl net.ipv6.conf.all.forwarding=1` propage la valeur à toutes les interfaces ; `all.accept_ra`
ne la propage pas, il faut la régler par interface. Dans ce TP les machines à configuration statique
ont `accept_ra=0` : elles ignorent les annonces ; `pc1` (`accept_ra=2`, `autoconf=1`) et `pc2`
(`accept_ra=2`, `autoconf=0` : route par défaut, pas d'adresse automatique) les écoutent.

### @@sec@@ Le démon radvd

Un routeur Linux annonce ses préfixes avec **radvd** (`/etc/radvd.conf`) :

```
interface eth2
{
    AdvSendAdvert on;                   # émettre des annonces sur cette interface
    MinRtrAdvInterval 3;                # intervalle entre deux annonces (3 à 10 s ici ;
    MaxRtrAdvInterval 10;               #   200 à 600 s par défaut)
    AdvManagedFlag off;                 # drapeau M (adresses par DHCPv6)
    AdvOtherConfigFlag off;             # drapeau O (autres paramètres par DHCPv6)
    prefix 2001:db8:1::/64
    {
        AdvOnLink on;                   # drapeau L
        AdvAutonomous on;               # drapeau A : SLAAC
    };
    RDNSS 2001:db8:1::53 { };           # serveurs DNS
    DNSSL example.org { };              # domaines de recherche
};
```

```
radvd -c                               # vérifie la syntaxe
systemctl restart radvd                # relancer après CHAQUE modification
pidof radvd                            # tourne-t-il ?
```

radvd exige que le routage IPv6 soit actif (`net.ipv6.conf.all.forwarding=1`). Pour vérifier ce
qu'il annonce : `tcpdump -n -v -i eth2 'icmp6 and ip6[40] == 134'` sur le routeur, ou sur un hôte
`ip -6 addr` / `ip -6 route` quelques secondes plus tard.
""")
            + info_subtitle(tr("DHCPv6"), tag="dhcpv6")
            + tr("""

**DHCPv6** (RFC 8415) est un protocole distinct de DHCP, qui ne partage avec lui ni le format ni les
ports. Il complète SLAAC dans deux situations :

- **sans état** (*stateless*, drapeau **O** du RA) : la machine a formé son adresse par SLAAC et
  ne demande que les **autres paramètres** (serveurs DNS, domaines de recherche, NTP…) ;
- **avec état** (*stateful*, drapeau **M**) : le serveur **attribue aussi les adresses**, en garde
  le registre (baux) et permet des réservations, comme DHCP en IPv4.

Dans les deux cas **la route par défaut vient du RA**, jamais de DHCPv6 : un réseau DHCPv6 a besoin
d'un routeur qui s'annonce (avec les drapeaux M ou O, et un préfixe sans le drapeau A si l'on veut
que les adresses viennent du serveur seul).

### @@sec@@ Transport et messages

| | DHCP (IPv4) | DHCPv6 |
|---|---|---|
| port serveur / client | UDP 67 / 68 | UDP **547** / **546** |
| destination des demandes | diffusion `255.255.255.255` | multicast **`ff02::1:2`** (tous les serveurs et relais du lien) |
| identité du client | adresse MAC (`chaddr`) | **DUID** (*DHCP Unique Identifier*) + IAID |
| obtention d'une adresse | DISCOVER, OFFER, REQUEST, ACK | **SOLICIT** (1), **ADVERTISE** (2), **REQUEST** (3), **REPLY** (7) |
| paramètres seuls | DHCPINFORM | **INFORMATION-REQUEST** (11) → REPLY |
| renouvellement | REQUEST unicast | RENEW (5) à T1, REBIND (6) à T2 |
| libération, refus | DHCPRELEASE, DHCPDECLINE | RELEASE (8), DECLINE (9) |
| redémarrage | REQUEST | CONFIRM (4) |
| relais | `giaddr` | RELAY-FORW (12) / RELAY-REPL (13), le message du client encapsulé |

`ADVERTISE` propose, sans engager le serveur ; le client en choisit un (option *preference*) et
confirme par `REQUEST` ; `REPLY` accorde le bail. L'option *rapid commit* réduit l'échange à
SOLICIT / REPLY.

### @@sec@@ Le DUID

Chaque client et chaque serveur a un identifiant **stable**, choisi une fois pour toutes et
indépendant de l'interface :

| type | forme | exemple |
|---|---|---|
| 1, **DUID-LLT** | adresse MAC + date de création | `00:01:00:01:2e:4f:…:02:53:52:aa:bb:cc` (le choix par défaut de `dhclient`) |
| 2, DUID-EN | numéro d'entreprise + identifiant | |
| 3, **DUID-LL** | type de lien (`00:01` Ethernet) + adresse MAC | `00:03:00:01:02:53:52:aa:bb:cc` : prévisible à partir de la MAC |
| 4, DUID-UUID | UUID de la machine | |

Un client peut demander plusieurs adresses, regroupées en **associations d'identité** : IA_NA
(adresses normales, option 3), IA_TA (temporaires), IA_PD (**délégation de préfixe**, option 25 :
le serveur délègue un préfixe entier, par exemple le /56 d'un abonné à sa *box*). Chaque IA a un
IAID choisi par le client. Une réservation se fait donc sur le **DUID** (et éventuellement l'IAID), pas
sur l'adresse MAC.

### @@sec@@ Les options

| code | option (nom ISC) | contenu |
|---|---|---|
| 1, 2 | `dhcp6.client-id`, `dhcp6.server-id` | DUID du client, du serveur |
| 3 | IA_NA | association d'adresses : IAID, T1, T2, et les adresses (option 5 **IA_ADDR** : adresse, durée préférée, durée de validité) |
| 6 | ORO (*option request*) | options demandées par le client |
| 7 | *preference* | préférence du serveur (0 à 255) |
| 8 | *elapsed time* | temps écoulé depuis le début de la recherche |
| 13 | *status code* | 0 succès, 2 `NoAddrsAvail`, 4 `NotOnLink`… |
| 14 | *rapid commit* | échange en deux messages |
| 23 | `dhcp6.name-servers` | serveurs DNS |
| 24 | `dhcp6.domain-search` | domaines de recherche |
| 25, 26 | IA_PD, IA_PREFIX | délégation de préfixe |
| 32 | *information refresh time* | pour les clients sans état |

Les adresses n'ont pas une « durée de bail » mais deux durées, comme en SLAAC : **préférée**
(*preferred lifetime*, après quoi l'adresse n'est plus utilisée pour de nouvelles connexions) et
**valide** (*valid lifetime*, après quoi elle est retirée). T1 et T2 sont les instants des
renouvellements.

### @@sec@@ Le serveur ISC : dhcpd -6

Le même programme que pour IPv4, lancé avec `-6`, avec sa propre configuration et son propre
registre :

| fichier | rôle |
|---|---|
| `/etc/default/isc-dhcp-server` | `INTERFACESv6="eth0"` : interface d'écoute du serveur IPv6 ; `INTERFACESv4=""` pour ne pas lancer le serveur IPv4 (les deux vides : le service lance les deux sur toutes les interfaces) |
| `/etc/dhcp/dhcpd6.conf` | configuration |
| `/var/lib/dhcp/dhcpd6.leases` | baux accordés |

```
default-lease-time 600;                    # durée de validité des adresses (secondes)
preferred-lifetime 375;                    # durée préférée (facultatif)
option dhcp6.name-servers 2001:db8:1::53;  # options globales
option dhcp6.domain-search "example.org";

subnet6 2001:db8:1::/64 {                  # le réseau de l'interface d'écoute (obligatoire,
    range6 2001:db8:1::1000 2001:db8:1::1fff;   #   même sans adresse à distribuer)
}

host portable {                            # réservation, par le DUID du client
    host-identifier option dhcp6.client-id 00:03:00:01:02:53:52:aa:bb:cc;
    fixed-address6 2001:db8:1::42;
}
```

- sans `range6`, le serveur ne distribue aucune adresse : il ne répond qu'aux INFORMATION-REQUEST
  (mode sans état) ;
- `subnet6` doit couvrir une adresse **globale** de l'interface d'écoute : le serveur doit avoir
  son adresse IPv6 avant de démarrer ;
- une adresse réservée se choisit hors de `range6`.

```
dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf     # vérifie la syntaxe
systemctl restart isc-dhcp-server         # un seul service pour les deux familles : il lance dhcpd -4
                                          #   et/ou dhcpd -6 selon INTERFACESv4 / INTERFACESv6
                                          #   ("Launching IPv6 server only." dans le journal)
journalctl -u isc-dhcp-server -f          # journal : "Solicit message from fe80::… port 546",
                                          #   "Advertise NA: address … to client with duid …"
ps -C dhcpd -o pid,args                   # le processus et ses arguments (-6, interface)
```

### @@sec@@ Le client ISC : dhclient -6

```
dhclient -6 -S -v eth0          # sans état : INFORMATION-REQUEST, ne demande pas d'adresse
dhclient -6 -D LL -v eth0       # avec état : demande une adresse, DUID-LL (prévisible)
dhclient -6 -D LL -r eth0       # libère l'adresse (RELEASE) et arrête le client
```

| fichier | rôle |
|---|---|
| `/var/lib/dhcp/dhclient6.leases` | le DUID du client (`default-duid`) et ses baux (`lease6 { … }`) |
| `/etc/resolv.conf` | réécrit par `dhclient-script` avec `dhcp6.name-servers` et `dhcp6.domain-search` |

Le DUID est **conservé** dans le fichier de baux : une fois choisi (LLT par défaut), `-D LL` n'y
change plus rien. Pour changer de type, libérez le bail, arrêtez le client et supprimez le fichier.
L'adresse obtenue est posée avec un préfixe `/128` et les durées du bail (`ip -6 addr` :
`dynamic`, `valid_lft`) ; le préfixe du lien, lui, vient de l'annonce de routeur (drapeau L).

Dans une capture : `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` montre les messages, leur
identifiant de transaction et leurs options.
""")
            + info_subtitle(tr("Le routage statique"), tag="routing")
            + tr("""

Le routage IPv6 est le routage IPv4 avec une table de plus (`ip -6 route`) : une route par
préfixe, la plus longue qui correspond l'emporte, `::/0` est la route par défaut.

```
ip -6 addr add 2001:db8:1::1/64 dev eth0            # une adresse (DAD : une seconde avant usage)
ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254  # une route vers un préfixe
ip -6 route add default via 2001:db8:1::254          # la route par défaut (::/0)
ip -6 route add default via fe80::1 dev eth0         # prochain saut de lien local : dev obligatoire
ip -6 route                                          # la table ; "proto kernel" : les réseaux
                                                     #   des adresses, "proto ra" : appris d'un RA
ip -6 route get 2001:db8:2::7                        # la route choisie pour une destination
sysctl -w net.ipv6.conf.all.forwarding=1             # routage activé (sur un routeur seulement)
```

Particularités :

- le **prochain saut** peut être une adresse **de lien local** (c'est ce que font les RA et les
  protocoles de routage) : il faut alors nommer l'interface (`dev`) puisque toutes les interfaces ont
  des adresses `fe80::` ;
- la route du réseau connecté apparaît quand l'adresse est ajoutée (`proto kernel`), et le lien
  local a toujours sa route `fe80::/64 dev ethN` ;
- un routeur dont le `forwarding` est actif ignore les RA (sauf `accept_ra=2`) et ne forme pas
  d'adresse automatique : sa configuration est **statique** ou vient d'un protocole de routage
  (OSPFv3, BGP) ;
- l'opérateur ne connaît qu'un **agrégat** par site (`/48`) : à l'intérieur du site, ce sont les
  routeurs du site qui connaissent les `/64`.

### @@sec@@ Configuration persistante (ifupdown)

Dans `/etc/network/interfaces`, une interface double pile a deux blocs, `inet` et `inet6` :

```
auto eth0
iface eth0 inet static
    address 192.0.2.10/24
    gateway 192.0.2.1

iface eth0 inet6 static
    address 2001:db8:1::10/64
    gateway 2001:db8:1::1
    post-up ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254
```

(`netmask 64` est accepté à la place du préfixe dans l'adresse ; `accept_ra 0` et `autoconf 0`
existent aussi dans un bloc `inet6`.) `ifup eth0` applique les deux blocs ; `ifdown eth0` les
retire. Les routes supplémentaires passent par `post-up`.
""")
            + info_subtitle(tr("Les noms et la double pile"), tag="names")
            + tr("""

Le DNS associe à un nom une adresse IPv4 par un enregistrement **A** et une adresse IPv6 par un
enregistrement **AAAA** ; la résolution inverse d'IPv6 vit sous `ip6.arpa`. Dans `/etc/hosts`, un
nom peut avoir une ligne par famille :

```
192.0.2.10        srv   srv.example.org
2001:db8:1::10    srv   srv.example.org
```

Sur une machine double pile, `getent ahosts srv` renvoie les deux adresses, **IPv6 en premier**
(RFC 6724 préfère IPv6 quand une adresse globale ou ULA existe) : `ping srv`, `ssh srv` ou `curl`
tentent IPv6 d'abord. Les navigateurs appliquent *happy eyeballs* (RFC 8305) : tentatives IPv6 et
IPv4 presque simultanées, la première qui aboutit l'emporte. Pour forcer une famille :
`ping -4` / `ping -6`, `ssh -6`, `curl -6`, `dig AAAA nom`, `getent ahostsv6 nom`.

Un serveur DNS s'interroge aussi bien en IPv6 : `nameserver 2001:db8:1::53` dans `/etc/resolv.conf`
fonctionne comme son équivalent IPv4, et c'est ce que RDNSS ou `dhcp6.name-servers` y mettent.
""")
            + info_subtitle(tr("MTU, fragmentation et découverte du PMTU"), tag="mtu")
            + tr("""

Le **MTU** d'un lien (1500 sur Ethernet) borne la taille des paquets. En IPv4 un routeur
**fragmente** un paquet trop grand pour le lien suivant, sauf si le bit **DF** est positionné : il le
jette alors et renvoie **ICMP type 3 code 4** (*fragmentation needed*) avec le MTU du lien suivant ;
l'émetteur mémorise ce **PMTU** par destination (`ip route get`, 10 min) et adapte ses paquets
(RFC 1191). `ping -4 -M do -s 1472` (1472 + 20 + 8 = 1500 octets) sonde le chemin.

### @@sec@@ En IPv6, la source seule fragmente

Un routeur IPv6 **ne fragmente jamais**. Un paquet trop grand pour le lien suivant est jeté et le
routeur renvoie à la source un message **ICMPv6 type 2, *Packet Too Big*** qui contient le MTU du
lien (RFC 8201). La source mémorise le PMTU (`ip -6 route get`, `ip -6 route flush cache`) et, si
elle tient vraiment à envoyer de plus gros datagrammes, les **fragmente elle-même** avec un en-tête
d'extension **Fragment** (*next header* **44**, 8 octets : identifiant, décalage, bit M) que seul le
destinataire traite. Deux garanties du protocole : tout lien IPv6 a un MTU d'au moins **1280**
octets (une interface dont le MTU descend en dessous perd ses adresses IPv6), et l'en-tête IPv6 fait
toujours **40** octets. Un écho ICMPv6 ajoute 8 octets : `ping -6 -s 1452` émet des paquets de 1500
octets.

```
ping -6 -c 3 -M do -s 1452 m2       # "Packet too big: mtu=N" venant du routeur, puis
                                    #   "sendmsg: Message too long" (PMTU connu)
ping -6 -c 1 -s 3000 m2             # trop grand pour tout lien : la source fragmente (en-tête 44)
tracepath -6 -n m2                  # PMTU saut par saut
ip -6 route get ADRESSE             # "mtu N" quand un PMTU est mémorisé ; ip -6 route flush cache
```

`tcpdump -n -v -i eth0 icmp6` montre l'erreur `ICMP6, packet too big, mtu N` émise par le routeur,
et `tcpdump -n -v -i eth0 ip6` les fragments : `frag (0x…:0|1448)` (identifiant, décalage, taille)
avec `next-header Fragment (44)`, déjà découpés par la source avant de partir.

| | IPv4 | IPv6 |
|---|---|---|
| en-tête | 20 octets (+ options) | 40 octets fixes (+ extensions) |
| fragmentation en route | par les routeurs si DF = 0 | jamais (RFC 8200) |
| fragmentation par la source | possible (DF = 0) | seule possibilité, en-tête Fragment (44) |
| erreur « trop grand » | ICMP type 3 code 4 | ICMPv6 type 2 *Packet Too Big* |
| MTU minimal | 68 (576 en pratique) | 1280 |
| charge utile max. de `ping -s` sur Ethernet | 1472 | 1452 |
| MSS = MTU − | 40 | 60 |

### @@sec@@ TCP, MSS et trou noir

Le **MSS** annoncé dans le SYN vaut MTU − 40 en IPv4 (1460) et **MTU − 60** en IPv6 (1440 ; `ss -ti`
affiche la valeur effective, 12 octets de moins avec l'option *timestamps*). Comme IPv6 ne fragmente
jamais en route, un pare-feu qui filtre les *Packet Too Big* crée exactement le même **trou noir
PMTUD** qu'en IPv4 : connexion établie, petits échanges normaux, transferts volumineux gelés, `ping`
intact. Remèdes côté routeurs, identiques dans les deux familles :

- **MSS clamping** nftables, table `inet`, hook `forward`, priorité `mangle`. Une règle sans
  `meta nfproto` s'applique **aux deux familles** avec la même valeur ; l'exemple ci-dessous donne
  une valeur à chaque famille (`… size set rt mtu` prend le MTU de la route de sortie du routeur :
  inutile tant que son interface de sortie est à 1500).
- **MTU des interfaces WAN** des routeurs abaissé au MTU de l'opérateur : le routeur émet lui-même
  *fragmentation needed* / *Packet Too Big* vers ses hôtes.
- Côté hôtes seulement : `net.ipv4.tcp_mtu_probing=1` (vaut aussi pour TCP sur IPv6), routes avec
  `mtu` : ne corrigent que la machine réglée.

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1400
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1380
```
""")
            + info_subtitle(tr("Tunnels et transition"), tag="tunnels")
            + tr("""

Tant que les deux familles coexistent, il faut faire passer l'une à travers l'autre :

| mécanisme | principe |
|---|---|
| **double pile** | chaque machine et chaque routeur ont les deux adresses : la solution de référence |
| **6in4** (RFC 4213, Linux `sit`) | paquets IPv6 dans des paquets IPv4 (protocole **41**) entre deux routeurs d'adresses IPv4 fixes : le raccordement historique d'un site IPv6 à travers un réseau IPv4 (*tunnel brokers*) |
| 6rd, 6to4 | 6in4 automatique : le préfixe IPv6 du site est dérivé de son adresse IPv4 |
| GRE, IPsec, WireGuard | tunnels génériques, qui transportent aussi bien IPv6 |
| **NAT64 + DNS64** (RFC 6146, 6147) | un réseau IPv6 seul joint le monde IPv4 : le résolveur fabrique une adresse `64:ff9b::<IPv4>` et un traducteur convertit les paquets |
| 464XLAT, DS-Lite, MAP | variantes pour les opérateurs mobiles et d'accès |

Un tunnel ajoute un en-tête : son **MTU** vaut le MTU du chemin extérieur moins cet en-tête
(**20 octets** pour 6in4, 24 pour GRE), et doit rester ≥ 1280.

```
ip link add sit1 type sit local ADRESSE_IPV4_LOCALE remote ADRESSE_IPV4_DISTANTE ttl 64
ip link set sit1 mtu MTU up
ip -6 addr add ADRESSE_TUN/64 dev sit1
ip -d link show sit1                # "sit remote … local … pmtudisc"
```

Le chargement du module crée aussi `sit0@NONE`, à ignorer. On teste le MTU du tunnel avec
`ping -6 -M do -s` vers l'adresse du routeur distant ; `tcpdump -n -i eth1 'ip proto 41'` montre
les paquets encapsulés.
""")
            + info_subtitle(tr("Pare-feu"), tag="firewall")
            + tr("""

nftables filtre IPv6 dans une table `ip6`, ou les deux familles dans une table `inet`. Trois
différences avec IPv4 :

- **ICMPv6 doit passer** : au minimum les types 1 à 4 (erreurs, dont *Packet Too Big*), 133 à 136
  (RA, RS, NS, NA) et les échos :
  `icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem,
  echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit,
  nd-neighbor-advert } accept` ;
- pas de NAT : les machines ont des adresses publiques ; c'est le pare-feu du routeur qui joue le
  rôle protecteur que le NAT jouait par accident ;
- les adresses de lien local (`fe80::/10`) et le multicast (`ff02::/16`) sont le trafic local
  normal, à ne pas bloquer.

En IPv4 comme en IPv6, les en-têtes d'extension et la fragmentation par la source compliquent
l'inspection : un pare-feu peut rejeter les fragments autres que le premier (`exthdr frag`).
""")
            + info_subtitle(tr("Outils"), tag="tools")
            + tr("""

| outil | usage |
|---|---|
| `ip -6 addr [show dev IFACE]` | adresses, portée (`global`, `link`), drapeaux (`dynamic`, `tentative`, `mngtmpaddr`), durées de vie |
| `ip -6 route`, `ip -6 route get DEST` | table de routage, route choisie ; `proto ra` : apprise d'une annonce |
| `ip -6 neigh` | cache de voisins (le remplaçant de `arp -n`) |
| `ip link show IFACE` | adresse MAC, MTU ; `ip -d link show sit1` pour un tunnel |
| `ping -6 DEST`, `ping -6 ff02::1%eth0` | écho ; tous les nœuds du lien |
| `ping -6 -M do -s TAILLE DEST`, `tracepath -6 -n DEST` | sonder le MTU du chemin |
| `traceroute -6 DEST` | les routeurs traversés |
| `tcpdump -n -v -i IFACE icmp6` | découverte de voisins, annonces de routeur, erreurs ; `'icmp6 and ip6[40] == 134'` : les RA seuls |
| `tcpdump -n -v -i IFACE 'udp port 546 or udp port 547'` | DHCPv6 |
| `tcpdump -n -v -i IFACE ip6` | tout le trafic IPv6 (fragments, *next-header*) |
| `sysctl net.ipv6.conf.IFACE` | `forwarding`, `accept_ra`, `autoconf`, `addr_gen_mode` |
| `ss -6 -tlnp`, `ss -6 -ti` | sockets IPv6, MSS et PMTU des connexions |
| `getent ahosts NOM`, `getent ahostsv6 NOM`, `dig AAAA NOM` | résolution de noms |
| `radvd -c`, `pidof radvd` | le démon d'annonces |
| `dhcpd -t -6 -cf …`, `journalctl -u isc-dhcp-server`, `ps -C dhcpd -o args` | le serveur DHCPv6 |
| `nft list ruleset` | règles nftables du routeur |
| `iperf3 -s` / `iperf3 -6 -c SERVEUR -t 5` | transfert TCP de test (`-R` : sens inverse ; `-4` / `-6`) |
""")
            + info_subtitle(tr("Dépannage"), tag="troubleshooting")
            + tr("""

| symptôme | cause probable | à vérifier |
|---|---|---|
| `ping -6` : `Network is unreachable` | pas de route pour la destination (pas de route par défaut) | `ip -6 route` |
| `ping -6` : `Destination unreachable: Address unreachable` | la destination est sur le lien mais ne répond pas aux NS (adresse fausse, machine éteinte, interface sans adresse) | `ip -6 neigh` (`FAILED`), `ip -6 addr` sur la cible |
| l'adresse ajoutée ne répond pas la première seconde | DAD en cours (`tentative`) | `ip -6 addr` |
| adresse marquée `dadfailed` | une autre machine a déjà cette adresse | `ip -6 neigh`, captures de NA |
| `Invalid argument` à `ip -6 route add default via fe80::…` | prochain saut de lien local sans `dev` | ajouter `dev ethN` |
| `pc1` n'a pas d'adresse automatique | pas d'annonce (radvd arrêté, `forwarding=0` sur le routeur, préfixe sans drapeau A), ou `accept_ra` / `autoconf` à 0 | `pidof radvd`, `tcpdump icmp6` sur le routeur, `sysctl net.ipv6.conf.eth0` |
| `pc1` a une adresse mais pas de route par défaut | durée de vie du routeur nulle (`AdvDefaultLifetime 0`) | capture du RA |
| `pc1` a une adresse mais ne résout aucun nom | aucun système ne lit RDNSS ici ; DNS par DHCPv6 (drapeau O) | `/etc/resolv.conf` |
| `dhcpd -6` ne démarre pas : `No subnet6 declaration for eth0` | l'interface n'a pas d'adresse globale dans un `subnet6` | `ip -6 addr` sur le serveur, `dhcpd6.conf` |
| `dhclient -6` répète ses `XMT: Solicit` | pas de serveur à l'écoute sur le lien, ou mauvaise interface d'écoute | `ps -C dhcpd -o args`, journal du serveur |
| `pc2` obtient une adresse dynamique malgré la réservation | DUID différent de celui déclaré (fichier de baux ancien, `-D LL` oublié) | journal du serveur (`duid …`), `/var/lib/dhcp/dhclient6.leases` |
| le routeur IPv6 ne relaie pas | `net.ipv6.conf.all.forwarding=0` | `sysctl` |
| `sendmsg: Message too long` dès le premier `ping -6 -M do` | un PMTU est déjà mémorisé (`ip -6 route get`, `ip -6 route flush cache`) | |
| `ping -6 -M do -s 1452` n'obtient ni réponse ni erreur | ICMPv6 filtré (`trou_noir`) : le paquet est jeté en silence | |
| `ping` passe mais `iperf3` reste à 0 bit/s | trou noir PMTUD (section @@ref:mtu@@) | |
| `iperf3 -4` passe mais `iperf3 -6` gèle | correction limitée à IPv4 (règle `meta nfproto ipv4`, ou table `ip` au lieu de `inet`) | |
| `ip link set … mtu 1200` : plus d'adresse IPv6 | MTU sous 1280 : IPv6 désactivé sur l'interface | |
| `ping -6` à travers `sit1` muet | `local`/`remote` inversés, ou MTU du tunnel trop grand sous `trou_noir` | |
""")
        )

    # -- reference configuration texts ---------------------------------------------

    def _unbound_conf(self) -> str:
        """unbound on srv: A and AAAA records of the static names of the lab (zone DOMAIN), reachable
        in both families; pc1 gets its predictable SLAAC address."""
        d = self.data
        names = {
            'm1': ([d.ips.m1], [d.ips6.m1]),
            'r1': ([d.ips.r1_lan1, d.ips.r1_wan1], [d.ips6.r1_lan1, d.ips6.r1_wan1]),
            'r1_lan1': ([d.ips.r1_lan1], [d.ips6.r1_lan1]),
            'r1_wan1': ([d.ips.r1_wan1], [d.ips6.r1_wan1]),
            'wan': ([d.ips.wan_wan1, d.ips.wan_wan2], [d.ips6.wan_wan1, d.ips6.wan_wan2]),
            'wan_wan1': ([d.ips.wan_wan1], [d.ips6.wan_wan1]),
            'wan_wan2': ([d.ips.wan_wan2], [d.ips6.wan_wan2]),
            'r2': ([d.ips.r2_wan2, d.ips.r2_lan2, d.ips.r2_lan3], [d.ips6.r2_wan2, d.ips6.r2_lan2, d.ips6.r2_lan3]),
            'r2_wan2': ([d.ips.r2_wan2], [d.ips6.r2_wan2]),
            'r2_lan2': ([d.ips.r2_lan2], [d.ips6.r2_lan2]),
            'r2_lan3': ([d.ips.r2_lan3], [d.ips6.r2_lan3]),
            'm2': ([d.ips.m2], [d.ips6.m2]),
            'srv': ([d.ips.srv], [d.ips6.srv]),
            'pc1': ([], [slaac_address(d.nets6.lan3, d.macs.pc1)]),
            'pc2': ([], [d.ips6.pc2_fixe]),
        }
        lines = [
            "server:",
            "    interface: 0.0.0.0",
            "    interface: ::0",
            "    access-control: 0.0.0.0/0 allow",
            "    access-control: ::/0 allow",
            '    chroot: ""',
            # no DNSSEC validation and no recursion: the lab has no Internet access, any
            # name outside the zone gets an immediate NXDOMAIN instead of a long timeout
            '    module-config: "iterator"',
            '    local-zone: "." static',
            f'    local-zone: "{DOMAIN}." static',
        ]
        for name, (v4, v6) in names.items():
            for ip in v4:
                lines.append(f'    local-data: "{name}.{DOMAIN}. IN A {ip.ip}"')
            for ip in v6:
                lines.append(f'    local-data: "{name}.{DOMAIN}. IN AAAA {ip.ip}"')
        return "\n".join(lines) + "\n"

    def _solution_radvd_conf(self, part: int = 4) -> str:
        """radvd.conf of r2 (eth2): the lan3 prefix and the DNS server (part 3), then the O flag
        (part 4a) and the M flag (part 4b)."""
        d = self.data
        return render_radvd_conf({2: [d.nets6.lan3]}, rdnss=[d.ips6.srv], dnssl=[DOMAIN],
                                 adv_other_config=(part >= 4), adv_managed=(part >= 5))

    def _solution_dhcpd6_conf(self, part: int = 6) -> str:
        """dhcpd6.conf of srv: options only (part 4a), then the range (4b) and the reservation of
        pc2 (4c).  *part* numbers the sub-parts 4, 5, 6 for 4a, 4b, 4c."""
        d = self.data
        return render_dhcpd6_conf(
            d.nets6.lan3,
            range6=(d.ips6.pool_min, d.ips6.pool_max) if part >= 5 else None,
            dns=[d.ips6.srv], domain_search=[DOMAIN], default_lease=d.lease6,
            hosts=[('pc2', duid_ll(d.macs.pc2), d.ips6.pc2_fixe)] if part >= 6 else (),
            comment="dhcpd6.conf de srv (solution de référence)")

    # -- states ------------------------------------------------------------------

    def _sysctl(self, machine: str, settings: dict, allow_error: bool = False):
        """``sysctl -w`` on *machine*; /proc/sys is remounted first on the non-privileged ones."""
        if machine not in PRIVILEGED:
            remount_proc_sys(self, machine)
        for name, value in settings.items():
            self.cmd(machine, f"sysctl -w {name}={value}", allow_error=allow_error)

    def _set_ipv6_forward(self, machine: str, enabled: bool):
        if machine in PRIVILEGED:
            self.cmd(machine, f"sysctl -w net.ipv6.conf.all.forwarding={int(enabled)}")
        else:
            set_ipv6_forward(net_scheme=self, machine_name=machine, ipv6_forward=enabled)

    def _configure_network(self):
        """Runtime configuration applied at start: IPv4 everywhere (but pc1 / pc2), IPv6 on the
        operator and the probes, the kernel settings, the operator's MTU and black holes, the DNS
        and the iperf3 servers.  The students do the IPv6 of m1, r1, r2, m2 and srv."""
        d = self.data
        for m, nc in self.net_config.items():
            if m in AUTO_HOSTS:
                self.cmd(m, "ip link set eth0 up")
                continue
            if m == 'wan' or m in PROBES:
                set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)   # both families
            else:
                set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=net_config_entry_family(nc, 4))
            for i in range(len(nc)):
                self.cmd(m, f"ethtool -K eth{i} gso off tso off gro off", allow_error=True)
        for m in self.get_machine_names():
            # Kathara starts every container with forwarding on in both families.
            if m in PRIVILEGED:
                self.cmd(m, f"sysctl -w net.ipv4.ip_forward={int(m in ROUTERS4)}")
            else:
                set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTERS4))
            self._set_ipv6_forward(m, m == 'wan')
            if m in AUTO_HOSTS:
                continue
            # the static machines ignore router advertisements, whatever their forwarding state
            # (the per-interface accept_ra of a Kathara container is 1)
            settings = {}
            for i in range(len(self.net_config.get(m, []))):
                settings[f"net.ipv6.conf.eth{i}.accept_ra"] = 0
                settings[f"net.ipv6.conf.eth{i}.autoconf"] = 0
            self._sysctl(m, settings)
        # pc1: SLAAC host; pc2: DHCPv6 host (route from the RA, no autoconfigured address);
        # EUI-64 identifiers whatever the host (the Kathara sysctls say so too)
        for m in AUTO_HOSTS:
            self._sysctl(m, {"net.ipv6.conf.eth0.addr_gen_mode": 0, "net.ipv6.conf.eth0.use_tempaddr": 0})
        set_slaac_client(self, 'pc1')
        self._sysctl('pc2', {"net.ipv6.conf.eth0.accept_ra": 2, "net.ipv6.conf.eth0.autoconf": 0})
        # the probes stay silent on ping ff02::1 (kernel >= 5.1)
        for h in PROBES:
            self._sysctl(h, {"net.ipv6.icmp.echo_ignore_multicast": 1}, allow_error=True)
        # The operator's link: reduced MTU on both interfaces of wan (both families).
        self.cmd('wan', f"ip link set dev eth0 mtu {d.wan_mtu}; ip link set dev eth1 mtu {d.wan_mtu}")
        # Permanent black hole toward the grading probes h1 / h2 only (never touched by the states).
        self.file('wan', PROBE_RULES, pmtu.nft_drop_pmtu_errors(
            PROBE_TABLE, daddr4=[d.ips.h1, d.ips.h2], daddr6=[d.ips6.h1, d.ips6.h2]))
        self.cmd('wan', f"nft delete table inet {PROBE_TABLE} 2>/dev/null; nft -f {PROBE_RULES}")
        # Black hole toward everybody, applied by the state trou_noir.
        self.file('wan', TN_RULES, pmtu.nft_drop_pmtu_errors(TN_TABLE))
        # iperf3 servers of the probe h2 (dual stack; one per family so that the flows overlap).
        for port in (GRADE_PORT_V4, GRADE_PORT_V6):
            self.cmd('h2', f"iperf3 -s -D -p {port} >/dev/null 2>&1")
        # DNS of the lab on srv (reachable in IPv4 from the start, in IPv6 once srv is configured);
        # started directly: `systemctl start unbound` would first wait for unbound-anchor.
        self.file('srv', '/etc/unbound/unbound.conf', self._unbound_conf())
        self.cmd('srv', "sh -c 'pkill -x unbound; unbound -c /etc/unbound/unbound.conf >/dev/null 2>&1'")
        install_ipv6_probe(net_scheme=self, machine='h3')

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        self._configure_network()
        # names of the static machines (both families); pc1 / pc2 only know the DNS of srv once
        # an RA or DHCPv6 gives it to them
        static = list(STATIC_MACHINES)
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN, machine_list=static, included=static, ipv6=True)
        for m in static:
            self.file(m, '/etc/resolv.conf', f"search {DOMAIN}\nnameserver {d.ips.srv.ip}\n")
        for m in AUTO_HOSTS:
            self.file(m, '/etc/hosts', f"127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t{m}\n")
            self.file(m, '/etc/resolv.conf', "")
        # the IPv4 part of the persistent configuration: the students add the inet6 stanzas
        for m in PERSISTENT_MACHINES:
            set_persistent_net_config_entry(self, m, net_config_entry_family(self.net_config[m], 4))
            self.cmd(m, "mkdir -p /run/network")   # ifup keeps its state there

    @sre_state(user_allowed=True,
               description=tr("Trou noir PMTUD : le routeur de l'opérateur (wan) n'émet plus les erreurs ICMP "
                              "« fragmentation needed » ni ICMPv6 « packet too big » ; les PMTU déjà appris par "
                              "m1, m2, r1 et r2 sont oubliés",
                              en="PMTUD black hole: the operator's router (wan) no longer sends the ICMP "
                                 "\"fragmentation needed\" errors nor the ICMPv6 \"packet too big\" ones; the PMTUs "
                                 "already learnt by m1, m2, r1 and r2 are forgotten"))
    def trou_noir(self):
        self.cmd('wan', f"nft delete table inet {TN_TABLE} 2>/dev/null; nft -f {TN_RULES}")
        for m in MTU_MACHINES:
            self.cmd(m, "ip route flush cache; ip -6 route flush cache", allow_error=True)

    @sre_state(user_allowed=True,
               description=tr("ICMP rétabli : le routeur de l'opérateur émet de nouveau les erreurs ICMP et ICMPv6",
                              en="ICMP restored: the operator's router sends the ICMP and ICMPv6 errors again"))
    def icmp_retabli(self):
        self.cmd('wan', f"nft delete table inet {TN_TABLE} 2>/dev/null; true")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution (idempotent): IPv6 of the static machines (step 1, with the persistent
        files, the forwarding, radvd, dhcpd6, the MSS clamping and the 6in4 tunnel), then the
        DHCPv6 clients pc1 / pc2 (step 2).  The forms are filled through cheat_answers; the
        probes' black hole and the trou_noir / icmp_retabli state do not depend on it."""
        d = self.data
        n = d.wan_mtu
        for m in STUDENT_STATIC:
            nc6 = net_config_entry_family(self.net_config[m], 6)
            for i, entry in enumerate(nc6):
                if entry:
                    self.cmd(m, f"ip -6 route flush dev eth{i} proto boot; ip -6 addr flush dev eth{i} scope global",
                             allow_error=True)
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc6)
        for r in ROUTERS6:
            self._set_ipv6_forward(r, True)
        for m in PERSISTENT_MACHINES:
            set_persistent_net_config_entry(self, m, self.net_config[m])
        # part 3 / 4: router advertisements of r2 on lan3 (M and O flags for part 4), DHCPv6 on srv
        set_radvd(self, 'r2', {2: [d.nets6.lan3]}, rdnss=[d.ips6.srv], dnssl=[DOMAIN],
                  adv_managed=True, adv_other_config=True)
        self.cmd('srv', f"sh -c 'systemctl stop {DHCPD6_UNIT}; pkill -x dhcpd; "
                        f"rm -f /var/run/dhcpd6.pid {DHCPD6_LEASES}*; true'", allow_error=True)
        self.file('srv', '/etc/default/isc-dhcp-server', DHCPD6_DEFAULTS)
        self.file('srv', DHCPD6_CONF, self._solution_dhcpd6_conf())
        self.cmd('srv', f"systemctl restart {DHCPD6_UNIT}")
        # part 5 / 6: MSS clamping of both families on r1 and r2, 6in4 tunnel at the right MTU
        for r in ROUTERS6:
            self.file(r, CLAMP_RULES, pmtu.nft_mss_clamp(CLAMP_TABLE, mss4=pmtu.mss_for(n), mss6=pmtu.mss_for(n, ipv6=True)))
            self.cmd(r, f"nft delete table inet {CLAMP_TABLE} 2>/dev/null; nft -f {CLAMP_RULES}")
        tunnel = (('r1', d.ips.r1_wan1.ip, d.ips.r2_wan2.ip, d.ips6.r1_tun),
                  ('r2', d.ips.r2_wan2.ip, d.ips.r1_wan1.ip, d.ips6.r2_tun))
        for r, local, remote, inner in tunnel:
            self.cmd(r, f"ip link del {TUN_DEV} 2>/dev/null; "
                        f"ip link add {TUN_DEV} type sit local {local} remote {remote} ttl 64; "
                        f"ip link set {TUN_DEV} mtu {n - TUN_OVERHEAD} up; "
                        f"ip -6 addr add {inner} dev {TUN_DEV} nodad")
        # step 2: the DHCPv6 clients (dhclient daemonizes with its stdio closed; a stored DUID
        # would override -D LL, so the lease files go first); the first RA has arrived meanwhile
        self.cmd('pc1', f"sh -c '{DHCLIENT6_CLEANUP}; sleep 3; "
                        f"timeout 60 dhclient -6 -S -1 -v eth0 >/tmp/dhclient6.log 2>&1'", step=2, allow_error=True)
        self.cmd('pc2', f"sh -c '{DHCLIENT6_CLEANUP}; ip -6 addr flush dev eth0 scope global; sleep 3; "
                        f"timeout 60 dhclient -6 -D LL -1 -v eth0 >/tmp/dhclient6.log 2>&1'", step=2, allow_error=True)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _float(s, default=None):
    try:
        return float(str(s).strip().replace(',', '.'))
    except (TypeError, ValueError):
        return default


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip(".")


def _is(answer, expected) -> bool:
    """A numeric form answer equals *expected*."""
    return _float(answer) == float(expected)


def _entry(nc_entry, index: int) -> list:
    """One-interface net_config entry: the entry *index* of *nc_entry* alone ([] when absent)."""
    return [nc_entry[index]] if nc_entry is not None and index < len(nc_entry) else []


def _ipv6_in(answer, *expected) -> bool:
    """The typed *answer* is one of the *expected* addresses (objects, strings or lists of them)."""
    for item in expected:
        candidates = item if isinstance(item, (list, tuple, set)) else [item]
        if any(same_ipv6(answer, c) for c in candidates):
            return True
    return False


#: The English labels of the French dropdown options that the instructor texts print as answers, the
#: labels of the English forms (`label>>>option`): the stored answer, the grading and the cheat answers
#: keep the French option.
ANSWERS_EN = {
    ":: (l'adresse non spécifiée)": ":: (the unspecified address)",
    "un préfixe /48 par site": "one /48 prefix per site",
    "le nom de l'interface (dev)": "the name of the interface (dev)",
    "le réseau de chaque adresse": "the network of each address",
    "l'annonce de routeur (durée de vie du routeur)": "the router advertisement (router lifetime)",
    "les machines forment une adresse avec ce préfixe (SLAAC)": "the machines form an address from this prefix (SLAAC)",
    "le préfixe est joignable directement sur le lien": "the prefix is reachable directly on the link",
    "non : elle vient toujours de l'annonce de routeur": "no: it always comes from the router advertisement",
    "m1 uniquement": "m1 only",
}


def _with_answers(text: TranslatedText, answers: dict, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values* and the form *answers*, a French option printed with
    its English label (ANSWERS_EN) in the English version."""
    return TranslatedText({lang: version.format(**values, **{k: ANSWERS_EN.get(v, v) if lang == 'en' else v
                                                             for k, v in answers.items()})
                           for lang, version in text.items()})


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        nc = self.net_scheme.net_config
        d4, d6 = d.ips, d.ips6
        n = d.wan_mtu
        mss4, mss6 = pmtu.mss_for(n), pmtu.mss_for(n, ipv6=True)
        tun_mtu = n - TUN_OVERHEAD
        ll_expected = {'m1': link_local_from_mac(d.macs.m1), 'r1': link_local_from_mac(d.macs.r1_lan1),
                       'r2': link_local_from_mac(d.macs.r2_lan3)}
        pc1_slaac = slaac_address(d.nets6.lan3, d.macs.pc1)
        pc2_duid, probe_duid = duid_ll(d.macs.pc2), duid_ll(d.macs.probe)
        sollicite = solicited_node_multicast(d6.r1_lan1)
        h2v4, h2v6 = str(d4.h2.ip), str(d6.h2.ip)
        r2_tun = str(d6.r2_tun.ip)
        wan_addr = {'r1': str(d4.r1_wan1.ip), 'r2': str(d4.r2_wan2.ip)}

        def family6(entry):
            return net_config_entry_family(entry, 6)

        # ---------------- step 1: configuration of the static machines ------------------
        current = {m: get_net_config_entry(self, m, ipv6=True) for m in STUDENT_STATIC}
        ll = {m: link_local_addresses(get_ip6_addrs(self, m, dev='eth0')) for m in ('m1', 'r1')}
        fwd6 = {m: get_ipv6_forward(self, m) for m in STUDENT_STATIC}
        persistent = {m: get_persistent_net_config_entry(self, m, ipv6=True)[0] for m in PERSISTENT_MACHINES}
        for m in STUDENT_STATIC:
            self.test(m, "ip -6 neigh", allow_error=True)   # diagnostics kept in the archive
        radvd = radvd_running(self, 'r2')
        self.test('r2', "grep -Ev '^[[:space:]]*(#|$)' /etc/radvd.conf", allow_error=True)

        # ---------------- step 1: the probe of lan3 (RS, DHCPv6 queries) -------------------
        # The spec only depends on the lab data: the command is the same on every pass.
        ras, replies = ipv6_probe(self, 'h3', ipv6_probe_spec('eth0', rs=True, wait=PROBE_WAIT, queries=[
            dhcp6_query('info', 'information-request', duid=probe_duid),
            dhcp6_query('dyn', 'solicit', duid=probe_duid),
            dhcp6_query('fixe', 'solicit', duid=pc2_duid),
        ]), step=1, timeout=30)
        # the advertisement of r2 (its link-local address, or the first one announcing lan3)
        ra = next((r for r in ras if r.src == ll_expected['r2']), None) or \
            next((r for r in ras if r.prefix(d.nets6.lan3)), None) or \
            (ras[0] if ras else None)
        ra_prefix = ra.prefix(d.nets6.lan3) if ra else None
        info = advertised(replies.get('info', []), 'REPLY')
        dyn = advertised(replies.get('dyn', []))
        fixe = advertised(replies.get('fixe', []))

        # ---------------- step 1: the hosts of lan3 and the DHCPv6 server ------------------
        pc1_addrs = get_ip6_addrs(self, 'pc1', dev='eth0')
        pc1_defaults = default_routes6(get_ip6_routes(self, 'pc1'))
        pc2_addrs = get_ip6_addrs(self, 'pc2', dev='eth0')
        pc2_defaults = default_routes6(get_ip6_routes(self, 'pc2'))
        resolv = {m: get_resolv_conf(self, m) for m in AUTO_HOSTS}
        pc2_duid_seen, pc2_leases = get_dhclient6_leases(self, 'pc2')
        dhcpd6_ifaces = get_dhcpd6_interfaces(self, 'srv')
        for c in (f"grep -Ev '^[[:space:]]*(#|$)' {DHCPD6_CONF}",
                  "grep -Ev '^[[:space:]]*(#|$)' /etc/default/isc-dhcp-server",
                  f"journalctl -u {DHCPD6_UNIT} --no-pager -n 40"):
            self.test('srv', c, allow_error=True)
        for m in AUTO_HOSTS:
            self.test(m, "pgrep -a dhclient", allow_error=True)

        # ---------------- step 1: MTU parts (as mtu6.py) ---------------------------------
        rulesets, links = {}, {}
        for m in MTU_MACHINES:
            rulesets[m], _ = self.test(m, "nft list ruleset", allow_error=True)
            links[m], _ = self.test(m, "ip -j -d link show", allow_error=True)
            self.test(m, "sysctl net.ipv4.tcp_mtu_probing", allow_error=True)
        self.test('m1', f"ip route get {d4.m2.ip}; ip -6 route get {d6.m2.ip}", allow_error=True)
        flush = "ip route flush cache; ip -6 route flush cache; echo flushed"
        self.test('h1', flush, step=1, allow_error=True)
        self.test('r1', flush, step=1, allow_error=True)
        servers = "; ".join(f"pgrep -f 'iperf3 -s -D -p {p}' >/dev/null || iperf3 -s -D -p {p} >/dev/null 2>&1"
                            for p in (GRADE_PORT_V4, GRADE_PORT_V6))
        self.test('h2', f"{flush}; {servers}; echo servers", step=1, allow_error=True)

        # ---------------- step 2: pings, name resolution, transfers, tunnel ---------------
        def ping(src, dest, **kw):
            return eval_ping(self, src, dest, step=2, count=3, deadline=5, allow_error=True, **kw)

        pings = {
            'h1_m1': ping('h1', d6.m1), 'h1_r1': ping('h1', d6.r1_lan1),
            'h1_h2': ping('h1', 'h2', ipv6=True), 'h2_h1': ping('h2', 'h1', ipv6=True),
            'h3_m1': ping('h3', d6.m1), 'm2_srv': ping('m2', d6.srv),
            'h3_pc1': ping('h3', pc1_slaac), 'pc1_m1': ping('pc1', d6.m1),
        }
        getent = {m: self.test(m, "timeout 5 getent ahostsv6 m1", step=2, allow_error=True)[0] for m in AUTO_HOSTS}
        seq4 = (f"{tc.iperf3_cmd(h2v4, GRADE_PORT_V4, seconds=2)} >/tmp/.sre_mtu_4a 2>&1; "
                f"{tc.iperf3_cmd(h2v4, GRADE_PORT_V4, seconds=2, reverse=True)} >/tmp/.sre_mtu_4r 2>&1")
        seq6 = (f"{tc.iperf3_cmd(h2v6, GRADE_PORT_V6, seconds=2)} >/tmp/.sre_mtu_6a 2>&1; "
                f"{tc.iperf3_cmd(h2v6, GRADE_PORT_V6, seconds=2, reverse=True)} >/tmp/.sre_mtu_6r 2>&1")
        transfer_cmd = (f"( {seq4} ) & ( {seq6} ) & wait; "
                        f'echo "===V4A"; cat /tmp/.sre_mtu_4a; echo "===V4R"; cat /tmp/.sre_mtu_4r; '
                        f'echo "===V6A"; cat /tmp/.sre_mtu_6a; echo "===V6R"; cat /tmp/.sre_mtu_6r')
        transfer_out, _ = self.test('h1', transfer_cmd, step=2, timeout=40, allow_error=True)
        flows = {tag: tc.parse_iperf3(tc.section_text(transfer_out, tag)) for tag in ('V4A', 'V4R', 'V6A', 'V6R')}
        connected4 = eval_ping(self, 'h1', 'h2', step=2, count=2, deadline=3, allow_error=True)
        fit = pmtu.max_ping_payload(tun_mtu, ipv6=True)
        tunnel_probe = (f'echo "===T6"; ping -6 -n -c 2 -i 0.3 -w 3 {r2_tun} 2>&1; '
                        f'echo "===FIT"; {pmtu.pmtu_ping_cmd(r2_tun, fit, ipv6=True, count=2, deadline=3, interval=0.3)} 2>&1; '
                        f'echo "===OVER"; {pmtu.pmtu_ping_cmd(r2_tun, fit + 1, ipv6=True, count=1, deadline=2)} 2>&1')
        tunnel_out, _ = self.test('r1', tunnel_probe, step=2, timeout=20, allow_error=True)
        tunnel_pings = pmtu.ping_received(tc.section_text(tunnel_out, 'T6'))
        fit_ok = pmtu.ping_received(tc.section_text(tunnel_out, 'FIT')) >= 1
        over_ok = pmtu.refused_locally(tc.section_text(tunnel_out, 'OVER'), tun_mtu)
        mtus = {r: pmtu.iface_mtus(links[r]) for r in ROUTERS6}
        wan_mtu_reduced = {r: (mtus[r].get(WAN_IFACE[r]) or 1500) <= n for r in ROUTERS6}
        clamp6_ok = any(pmtu.mss_clamped(pmtu.mss_clamp_rules(rulesets[r]), 6, mss6, rt_mtu_ok=wan_mtu_reduced[r])
                        for r in ROUTERS6)
        mtu_fix_ok = all(wan_mtu_reduced.values())
        tun = {}
        for r in ROUTERS6:
            link = next((l for l in pmtu.parse_ip_links_json(links[r]) if l.get('ifname') == TUN_DEV), {})
            tun[r] = pmtu.tunnel_info(link)
        charge6, charge4 = pmtu.max_ping_payload(n, ipv6=True), pmtu.max_ping_payload(n)

        # ---------------- organisation ----------------------------------------------------
        # The texts of a question are not indented: an indented one would be a code block.
        addressing = tr(f"""
| réseau | IPv4 | IPv6 | machines |
|--------|------|------|----------|
| `lan1` (site 1) | `{d.nets.lan1}` | `{d.nets6.lan1}` | `m1` (`{d4.m1.ip}`, `{d6.m1.ip}`), `r1` eth0 (`{d4.r1_lan1.ip}`, `{d6.r1_lan1.ip}`) |
| `wan1` | `{d.nets.wan1}` | `{d.nets6.wan1}` | `r1` eth1 (`{d4.r1_wan1.ip}`, `{d6.r1_wan1.ip}`), `wan` eth0 (`{d4.wan_wan1.ip}`, `{d6.wan_wan1.ip}`) |
| `wan2` | `{d.nets.wan2}` | `{d.nets6.wan2}` | `wan` eth1 (`{d4.wan_wan2.ip}`, `{d6.wan_wan2.ip}`), `r2` eth0 (`{d4.r2_wan2.ip}`, `{d6.r2_wan2.ip}`) |
| `lan2` (site 2) | `{d.nets.lan2}` | `{d.nets6.lan2}` | `r2` eth1 (`{d4.r2_lan2.ip}`, `{d6.r2_lan2.ip}`), `m2` (`{d4.m2.ip}`, `{d6.m2.ip}`) |
| `lan3` (site 2) | `{d.nets.lan3}` | `{d.nets6.lan3}` | `r2` eth2 (`{d4.r2_lan3.ip}`, `{d6.r2_lan3.ip}`), `srv` (`{d4.srv.ip}`, `{d6.srv.ip}`), `pc1` et `pc2` (IPv6 seulement, adresses automatiques) |
| `tun` (partie 6) | — | `{d.nets6.tun}` | extrémités du tunnel 6in4 : `r1` (`{d6.r1_tun.ip}`), `r2` (`{d6.r2_tun.ip}`) |

Préfixes des sites : site 1 `{d.nets6.site1}` (`lan1` en est le sous-réseau n° 1), site 2 `{d.nets6.site2}`
(`lan2` : sous-réseau n° 1, `lan3` : n° 2). L'opérateur route le `/48` de chaque site vers le routeur de
ce site (`r1` pour le site 1, `r2` pour le site 2), rien de plus précis.
""", en=f"""
| network | IPv4 | IPv6 | machines |
|--------|------|------|----------|
| `lan1` (site 1) | `{d.nets.lan1}` | `{d.nets6.lan1}` | `m1` (`{d4.m1.ip}`, `{d6.m1.ip}`), `r1` eth0 (`{d4.r1_lan1.ip}`, `{d6.r1_lan1.ip}`) |
| `wan1` | `{d.nets.wan1}` | `{d.nets6.wan1}` | `r1` eth1 (`{d4.r1_wan1.ip}`, `{d6.r1_wan1.ip}`), `wan` eth0 (`{d4.wan_wan1.ip}`, `{d6.wan_wan1.ip}`) |
| `wan2` | `{d.nets.wan2}` | `{d.nets6.wan2}` | `wan` eth1 (`{d4.wan_wan2.ip}`, `{d6.wan_wan2.ip}`), `r2` eth0 (`{d4.r2_wan2.ip}`, `{d6.r2_wan2.ip}`) |
| `lan2` (site 2) | `{d.nets.lan2}` | `{d.nets6.lan2}` | `r2` eth1 (`{d4.r2_lan2.ip}`, `{d6.r2_lan2.ip}`), `m2` (`{d4.m2.ip}`, `{d6.m2.ip}`) |
| `lan3` (site 2) | `{d.nets.lan3}` | `{d.nets6.lan3}` | `r2` eth2 (`{d4.r2_lan3.ip}`, `{d6.r2_lan3.ip}`), `srv` (`{d4.srv.ip}`, `{d6.srv.ip}`), `pc1` and `pc2` (IPv6 only, automatic addresses) |
| `tun` (part 6) | — | `{d.nets6.tun}` | endpoints of the 6in4 tunnel: `r1` (`{d6.r1_tun.ip}`), `r2` (`{d6.r2_tun.ip}`) |

Prefixes of the sites: site 1 `{d.nets6.site1}` (`lan1` is its subnet no. 1), site 2 `{d.nets6.site2}`
(`lan2`: subnet no. 1, `lan3`: no. 2). The operator routes the `/48` of each site to the router of
that site (`r1` for site 1, `r2` for site 2), nothing more specific.
""")
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="73c724f9fbbb84ce",
            description=tr("""
Lisez l'onglet **Informations** : c'est le cours (adresses, découverte de voisins, annonces de
routeur, DHCPv6, routage, MTU), avec les commandes utiles et un tableau de dépannage.

Deux sites, `lan1` (`m1`) et `lan2` + `lan3` (`m2`, `srv`, `pc1`, `pc2`), sont reliés par leurs
routeurs `r1` et `r2` à travers le réseau d'un **opérateur**, représenté par le routeur `wan`
(pas de terminal : c'est l'équipement de l'opérateur). Le réseau **IPv4** est en place partout
(adresses, routes, routage) : c'est le réseau historique du site. Vous déployez **IPv6** par-dessus,
en suivant le plan d'adressage ci-dessous ; `wan` est déjà configuré dans les deux familles.
""")
            + addressing
            + tr("""
**Plan du TP.** Six parties, à faire dans l'ordre :

1. **Adressage et voisinage** sur `lan1` : adresses de lien local, `ff02::1`, adresses statiques de
   `m1` et `r1`, découverte de voisins (12 points).
2. **Routage statique** : adresses et routes de `r1`, `r2`, `m2`, `srv`, routage activé,
   configuration persistante de `m1` et `r1` (23 points).
3. **SLAAC** : annonces de routeur de `r2` sur `lan3` (radvd), autoconfiguration de `pc1`
   (16 points).
4. **DHCPv6** sur `srv` : sans état (DNS pour `pc1`), avec état (adresse de `pc2`), réservation par
   DUID (24 points).
5. **MTU et trou noir PMTUD en double pile** : *Packet Too Big*, fragmentation par la source,
   correction sur `r1` / `r2` (15 points).
6. **Tunnel 6in4** entre `r1` et `r2` à travers l'IPv4 de l'opérateur (10 points).

Règles valables pour tout le TP :

- les parties sont à faire **dans l'ordre** : chaque partie suppose la précédente en place, et la
  configuration d'une partie terminée reste en place ;
- `wan` ne se configure pas ; ses liens ont un MTU **inférieur à 1500** (partie 5) ;
- les machines à configuration statique (`m1`, `r1`, `r2`, `m2`, `srv`) ignorent les annonces de
  routeur (`accept_ra=0`) ; `pc1` et `pc2` n'ont **ni adresse IPv4 ni configuration IPv6** : elles
  se configurent par les annonces de `r2` et par DHCPv6 (parties 3 et 4) et ne connaissent les
  noms que par le serveur DNS `srv`, une fois son adresse reçue ;
- les noms des machines statiques sont dans `/etc/hosts` avec une ligne par famille (`ping -4 m2`,
  `ping -6 m2`, `ping -6 r1_lan1`… ; **précisez `-4` ou `-6`** : sans option, la résolution de noms
  propose IPv6 en premier) et dans le DNS de `srv` ;
- après chaque modification d'un fichier de configuration, **relancez le service** et vérifiez
  dans le journal qu'il a démarré ;
- les états `trou_noir` et `icmp_retabli` (onglet **Appliquer une configuration**) servent à la
  partie 5 ; l'évaluation ne dépend pas de l'état choisi ;
- l'évaluation (bouton d'évaluation, ≈ 15 s) lit la configuration des machines telle qu'elle est
  au moment où elle est lancée, et fait des mesures depuis **trois postes cachés** : `h1` dans
  `lan1`, `h2` dans `lan2` (transferts et pings, partie 5) et `h3` dans `lan3` (sollicitations de
  routeur et requêtes DHCPv6, parties 3 et 4). Vous verrez leurs adresses dans vos captures ; ils
  n'ont aucune configuration à faire et ne répondent pas à `ping ff02::1`.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (IPv6 des
  machines statiques et fichiers persistants, radvd avec les drapeaux M et O, dhcpd6 avec la plage et
  la réservation, `dhclient -6` sur `pc1` et `pc2`, MSS clamping et tunnel 6in4) et remplit les
  formulaires. Compter une dizaine de secondes avant l'évaluation (clients DHCPv6, DAD).
- Sondes : `h1` (`{h1v4}`, `{h1v6}`) et `h2` (`{h2v4}`, `{h2v6}`) sont derrière le trou noir permanent
  de `wan` (table nftables `sondes`) ; `h3` (`{h3v4}`, `{h3v6}`) a `accept_ra=0` et envoie à chaque
  évaluation une sollicitation de routeur, une INFORMATION-REQUEST et deux SOLICIT (DUID
  `{probe_duid}`, puis le DUID-LL de `pc2`, `{pc2_duid}`) : les serveurs ne font qu'annoncer, aucun
  bail n'est engagé.
- Valeurs cachées ou prévisibles : MTU de l'opérateur **{n}** (charge utile maximale de `ping` :
  {charge6} en IPv6, {charge4} en IPv4 ; MSS : {mss6} / {mss4} ; MTU du tunnel : {tun_mtu}) ;
  adresses de lien local `{ll_m1}` (`m1`), `{ll_r1}` (`r1` eth0), `{ll_r2}` (`r2` eth2) ; adresse
  SLAAC de `pc1` `{pc1_slaac}` ; plage DHCPv6 `{pool_min}` – `{pool_max}`, durée de validité
  {lease6} s, adresse réservée de `pc2` `{pc2_fixe}`.
- Évaluation : lecture de `ip a` / `ip -6 route` / `/etc/network/interfaces` / forwarding des machines
  statiques, `ip -j -6 addr` / `route` / `resolv.conf` / baux de `pc1` et `pc2`, ligne de commande de
  `dhcpd`, sonde `h3` (≈ {wait} s), puis pings depuis `h1`, `h2`, `h3`, `m2` et `pc1`, `getent ahostsv6 m1`
  sur `pc1` / `pc2`, transferts `iperf3` de 2 s entre `h1` et `h2` dans les deux familles et le test du
  tunnel depuis `r1`.
""").format(h1v4=d4.h1.ip, h1v6=d6.h1.ip, h2v4=h2v4, h2v6=h2v6, h3v4=d4.h3.ip, h3v6=d6.h3.ip,
            probe_duid=probe_duid, pc2_duid=pc2_duid, n=n, charge6=charge6, charge4=charge4, mss6=mss6, mss4=mss4,
            tun_mtu=tun_mtu, ll_m1=ll_expected['m1'], ll_r1=ll_expected['r1'], ll_r2=ll_expected['r2'],
            pc1_slaac=pc1_slaac.ip, pool_min=d6.pool_min.ip, pool_max=d6.pool_max.ip, lease6=d.lease6,
            pc2_fixe=d6.pc2_fixe.ip, wait=int(PROBE_WAIT))),
        )

        # =====================================================================
        # Partie 1 — Adressage et voisinage
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Adressage et découverte de voisins (lan1)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Adressage et découverte de voisins sur lan1"),
            hash="6f637d8764625087",
            description=tr("""
Sur `lan1`, `m1` et `r1` (interface `eth0`) n'ont encore qu'IPv4.

1. Sur `m1`, relevez l'adresse MAC de `eth0` (`ip link show eth0`) et son adresse IPv6 de **lien
   local** (`ip -6 addr show eth0`). Retrouvez par le calcul (EUI-64 : `ff:fe` inséré au milieu, bit
   *universal/local* inversé) comment l'une se déduit de l'autre, et faites de même sur `r1`.
2. Sur `m1`, `ping -6 -c 2 ff02::1%eth0` : qui répond ? Regardez ensuite `ip -6 neigh`.
3. Donnez à `m1` et à `r1` (eth0) leurs adresses **globales** du plan d'adressage, en `/64`
   (`ip -6 addr add … dev eth0`). Observez `ip -6 addr` juste après (`tentative`), puis `ip -6 route` :
   quelle route est apparue toute seule ?
4. Dans un second terminal sur `m1`, lancez `tcpdump -n -v -i eth0 icmp6`, puis depuis `m1`
   `ping -6 -c 2 r1_lan1` (ou l'adresse). Relevez les messages de découverte de voisins : types,
   adresse de destination du premier (le groupe du *nœud sollicité* de l'adresse de `r1`), adresse MAC
   de destination de la trame, puis `ip -6 neigh` sur `m1`.
5. Toujours en capturant, retirez puis remettez l'adresse de `m1` (`ip -6 addr del` / `add`) : observez
   la **détection d'adresse dupliquée** (un NS dont l'adresse source est `::`).
""")
            + instructor(tr("""
**Solution.** Adresses de lien local attendues (EUI-64 des adresses MAC fixées par le TP) : `m1`
`{ll_m1}` (MAC `{mac_m1}`), `r1` eth0 `{ll_r1}` (MAC `{mac_r1}`). Sur `m1` :

```
ip -6 addr add {m1}/64 dev eth0
```

Sur `r1` :

```
ip -6 addr add {r1}/64 dev eth0
```

- `ping -6 ff02::1%eth0` fait répondre `m1` elle-même, `r1` et… `h1`, la sonde cachée de `lan1`, qui
  est réglée pour ne pas répondre (`echo_ignore_multicast`) : deux réponses par écho, dont une `(DUP!)`.
- La route `{lan1} dev eth0 proto kernel` apparaît avec l'adresse.
- Capture : `NS, who has {r1}` de `{m1}` vers `{sollicite}` (trame vers `{mac_sollicite}`), puis `NA, tgt is {r1}`
  de `r1` vers `m1` (drapeaux *solicited*, *override*) ; les types sont 135 et 136. DAD : `NS, who has {m1}`
  depuis `::` vers `{sollicite_m1}`.
- Évaluation : adresses de `m1` et de `r1` eth0 (`ip a`), pings de `h1` vers les deux, et les réponses du
  formulaire (adresses de lien local comparées à ce que les machines ont réellement, valeur EUI-64
  attendue en solution).
""").format(ll_m1=ll_expected['m1'], mac_m1=mac_str(d.macs.m1), ll_r1=ll_expected['r1'], mac_r1=mac_str(d.macs.r1_lan1),
            m1=d6.m1.ip, r1=d6.r1_lan1.ip, lan1=d.nets6.lan1, sollicite=sollicite, mac_sollicite=multicast_mac(sollicite),
            sollicite_m1=solicited_node_multicast(d6.m1))),
        )
        q1_answers = {"ll_m1": str(ll_expected['m1']), "ll_r1": str(ll_expected['r1']), "prefixe_ll": "fe80::/10",
                      "ns_type": "135", "na_type": "136", "sollicite": str(sollicite),
                      "mac_sollicite": multicast_mac(sollicite), "dad_src": ":: (l'adresse non spécifiée)"}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Adresses et messages observés"),
            hash="47cc93a8e2afc5a7",
            description=tr("""
- Adresse de lien local de `m1` : @@{ll_m1:[0-9a-fA-F:%/]+}@@ ; de `r1` (eth0) : @@{ll_r1:[0-9a-fA-F:%/]+}@@
- Préfixe de toutes les adresses de lien local : @@{prefixe_ll:[0-9a-fA-F:/]+}@@
- Types ICMPv6 de la sollicitation de voisin : @@{ns_type:[0-9]+}@@ et de l'annonce de voisin : @@{na_type:[0-9]+}@@
- Adresse IPv6 de destination de la sollicitation de voisin pour l'adresse de `r1` : @@{sollicite:[0-9a-fA-F:]+}@@ ;
  adresse MAC de destination de cette trame : @@{mac_sollicite:[0-9a-fA-F:]+}@@
- Adresse source du NS de la détection d'adresse dupliquée : @@{dad_src:>:: (l'adresse non spécifiée)|l'adresse de lien local de m1|l'adresse testée}@@
""")
            + instructor(_with_answers(tr("""
**Réponses.**

- lien local de `m1` : `{ll_m1}` ; de `r1` : `{ll_r1}` (1 point chacune : la valeur relevée sur la machine est
  acceptée, même si l'hôte Docker fabriquait des identifiants non EUI-64)
- préfixe `{prefixe_ll}` (`fe80::/64` accepté)
- NS : `{ns_type}` ; NA : `{na_type}`
- nœud sollicité de `r1` : `{sollicite}`, trame vers `{mac_sollicite}` (`33:33:ff` + les 3 derniers octets de l'adresse)
- DAD : `{dad_src}`
"""), q1_answers)),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("adr_q_lien_local"), max_grade=2, grade_part=part1,
            grade=int(_ipv6_in(q1.get("ll_m1"), ll_expected['m1'], ll['m1']))
            + int(_ipv6_in(q1.get("ll_r1"), ll_expected['r1'], ll['r1'])),
            description=tr("adresses de lien local de m1 et de r1 (relevées ou calculées)"),
        )
        prefixe = _norm(q1.get("prefixe_ll")).replace(" ", "")
        self.add_grade_element(
            title=no_tr("adr_q_prefixe"), max_grade=1, grade_part=part1,
            grade=int(prefixe in ("fe80::/10", "fe80::/64", "fe80:/10", "fe80:/64")),
            description=tr("préfixe des adresses de lien local"),
        )
        self.add_grade_element(
            title=no_tr("adr_q_nd_typed"), max_grade=1, grade_part=part1,
            grade=int(_is(q1.get("ns_type"), 135) and _is(q1.get("na_type"), 136)),
            description=tr("types des messages NS / NA"),
        )
        self.add_grade_element(
            title=no_tr("adr_q_nd"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get("dad_src")).startswith("::")),
            description=tr("source du NS de la détection d'adresse dupliquée"),
        )
        self.add_grade_element(
            title=no_tr("adr_q_sollicite"), max_grade=1, grade_part=part1,
            grade=int(same_ipv6(q1.get("sollicite"), sollicite)
                      and _norm(q1.get("mac_sollicite")).replace("-", ":") == multicast_mac(sollicite)),
            description=tr("groupe du nœud sollicité de r1 et adresse MAC multicast correspondante"),
        )
        r_m1 = eval_net_config(self, family6(nc['m1']), current=family6(current['m1']))
        self.add_grade_element(
            title=no_tr("adr_m1"), max_grade=2, grade_part=part1, grade=2 * r_m1.ips,
            description=tr("adresse IPv6 globale de m1 ({m1}/64)").format(m1=d6.m1.ip),
        )
        r_r1_lan = eval_net_config(self, _entry(family6(nc['r1']), 0), current=_entry(family6(current['r1']), 0))
        self.add_grade_element(
            title=no_tr("adr_r1_lan1"), max_grade=1, grade_part=part1, grade=r_r1_lan.ips,
            description=tr("adresse IPv6 de r1 sur lan1 ({r1}/64)").format(r1=d6.r1_lan1.ip),
        )
        self.add_grade_element(
            title=no_tr("adr_ping_h1_m1"), max_grade=2, grade_part=part1, grade=2 * int(pings['h1_m1']),
            description=tr("ping -6 de la sonde h1 vers m1"),
        )
        self.add_grade_element(
            title=no_tr("adr_ping_h1_r1"), max_grade=1, grade_part=part1, grade=int(pings['h1_r1']),
            description=tr("ping -6 de la sonde h1 vers r1"),
        )
        self.question_text(
            section=self.section(1),
            title=tr("Découverte de voisins"),
            hash="bb5faa5634702a95",
            description=tr("Collez les lignes de `tcpdump` montrant la sollicitation et l'annonce de voisin de "
                           "l'étape 4, puis le NS de la détection d'adresse dupliquée de l'étape 5.")
            + instructor(tr("""

**Attendu.** `{m1} > {sollicite}: ICMP6, neighbor solicitation, who has {r1}, length 32` (option *source
link-address* : MAC de `m1`), `{r1} > {m1}: ICMP6, neighbor advertisement, tgt is {r1}, length 32` (drapeaux
`[solicited, override]`), puis `:: > {sollicite_m1}: ICMP6, neighbor solicitation, who has {m1}`. Question non
notée.
""").format(m1=d6.m1.ip, r1=d6.r1_lan1.ip, sollicite=sollicite, sollicite_m1=solicited_node_multicast(d6.m1))),
            cheat_answers={"final": "NS vers le nœud sollicité, NA en unicast, NS de DAD depuis ::"},
        )

        # =====================================================================
        # Partie 2 — Routage statique
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Routage statique"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Adresses et routes statiques"),
            hash="f56f65d9d1659b5a",
            description=tr("""
Déployez IPv6 sur le reste des machines statiques, d'après le plan d'adressage :

1. `r1` : adresse de `eth1` (vers l'opérateur), route par défaut vers `wan`, **routage IPv6 activé**
   (`net.ipv6.conf.all.forwarding`) ;
2. `r2` : ses trois adresses (`eth0` vers l'opérateur, `eth1` sur `lan2`, `eth2` sur `lan3`), route
   par défaut vers `wan`, routage activé ;
3. `m2` et `srv` : adresse et route par défaut vers `r2` ;
4. `m1` : route par défaut vers `r1`.

L'opérateur route le `/48` de chaque site vers `r1` ou `r2` : aucune route n'est à ajouter sur `wan`
(et vous ne le pourriez pas), ni sur `r1` / `r2` au-delà de leur route par défaut et de leurs réseaux
connectés. Vérifiez de proche en proche : `ping -6 wan_wan1` depuis `r1`, `ping -6 m2` et `ping -6 srv`
depuis `m1`, `traceroute -6 m1` depuis `m2`, `ip -6 route get` ; `tcpdump -n -i eth1 icmp6` sur `r1` montre
les échos et, en cas d'erreur, le type ICMPv6 que renvoie le routeur qui n'a pas de route.

Enfin, rendez la configuration IPv6 de `m1` et de `r1` **persistante** dans `/etc/network/interfaces`
(bloc `iface ethN inet6 static`, voir le cours ; les blocs `inet` IPv4 y sont déjà), et vérifiez
qu'elle s'applique : `ifdown eth0; ifup eth0` sur `m1` (sur `r1`, `ifdown eth1; ifup eth1`), puis
`ip -6 addr` et `ip -6 route`.
""")
            + instructor(tr("""
**Solution.** Sur `r1` :

```
ip -6 addr add {r1_wan1}/64 dev eth1
ip -6 route add default via {wan_wan1}
sysctl -w net.ipv6.conf.all.forwarding=1
```

Sur `r2` :

```
ip -6 addr add {r2_wan2}/64 dev eth0
ip -6 addr add {r2_lan2}/64 dev eth1
ip -6 addr add {r2_lan3}/64 dev eth2
ip -6 route add default via {wan_wan2}
sysctl -w net.ipv6.conf.all.forwarding=1
```

Sur `m2` : `ip -6 addr add {m2}/64 dev eth0; ip -6 route add default via {r2_lan2}` ; sur `srv` :
`ip -6 addr add {srv}/64 dev eth0; ip -6 route add default via {r2_lan3}` ; sur `m1` :
`ip -6 route add default via {r1_lan1}`.

`/etc/network/interfaces` de `m1` :

```
{interfaces_m1}
```

et de `r1` :

```
{interfaces_r1}
```

- Un routeur sans route renvoie `ICMP6, destination unreachable, unreachable route` (type 1, code 0).
- Évaluation : adresses et route par défaut de chaque machine (`ip a`, `ip -6 route`), `forwarding`
  à 1 sur `r1` et `r2` et à 0 sur les hôtes, blocs `inet6 static` de `m1` et `r1` (adresse et `gateway`),
  pings `h1` ↔ `h2`, `h3` → `m1`, `m2` → `srv`.
""").format(r1_wan1=d6.r1_wan1.ip, wan_wan1=d6.wan_wan1.ip, r2_wan2=d6.r2_wan2.ip, r2_lan2=d6.r2_lan2.ip,
            r2_lan3=d6.r2_lan3.ip, wan_wan2=d6.wan_wan2.ip, m2=d6.m2.ip, srv=d6.srv.ip, r1_lan1=d6.r1_lan1.ip,
            interfaces_m1=render_persistent_net_config_entry(nc['m1']).strip(),
            interfaces_r1=render_persistent_net_config_entry(nc['r1']).strip())),
        )
        q2_answers = {"agregat": "un préfixe /48 par site", "unreach_type": "1",
                      "via_ll": "le nom de l'interface (dev)", "kernel_route": "le réseau de chaque adresse"}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Routage"),
            hash="822c0c8c5504b40f",
            description=tr("""
- Ce que l'opérateur route vers chaque site : @@{agregat:>un préfixe /48 par site|un préfixe /64 par réseau|une route par machine}@@
- Type ICMPv6 du message « destination injoignable » renvoyé par un routeur sans route : @@{unreach_type:[0-9]+}@@
- Pour une route dont le prochain saut est une adresse de lien local, `ip -6 route add` exige en plus :
  @@{via_ll:>le nom de l'interface (dev)|une métrique|le préfixe du prochain saut}@@
- Les routes `proto kernel` de la table IPv6 décrivent : @@{kernel_route:>le réseau de chaque adresse|la route par défaut|les routes apprises des annonces}@@
""")
            + instructor(_with_answers(tr("""
**Réponses.** `{agregat}` ; type `{unreach_type}` (code 0, *no route to destination*) ; `{via_ll}` ;
`{kernel_route}`.
"""), q2_answers)),
            cheat_answers={"final": q2_answers},
        )
        results = {m: eval_net_config(self, family6(nc[m]), current=family6(current[m])) for m in STUDENT_STATIC}
        self.add_grade_element(
            title=no_tr("route_r1"), max_grade=3, grade_part=part2,
            grade=min(2, results['r1'].ips) + results['r1'].default_route,
            description=tr("adresses IPv6 de r1 et route par défaut vers l'opérateur"),
        )
        self.add_grade_element(
            title=no_tr("route_r2"), max_grade=4, grade_part=part2,
            grade=min(3, results['r2'].ips) + results['r2'].default_route,
            description=tr("trois adresses IPv6 de r2 et route par défaut vers l'opérateur"),
        )
        for m in ('m2', 'srv'):
            self.add_grade_element(
                title=no_tr(f"route_{m}"), max_grade=2, grade_part=part2,
                grade=min(1, results[m].ips) + results[m].default_route,
                description=tr("adresse IPv6 de {m} et route par défaut vers r2").format(m=m),
            )
        self.add_grade_element(
            title=no_tr("route_m1"), max_grade=1, grade_part=part2, grade=results['m1'].default_route,
            description=tr("route par défaut de m1 vers r1"),
        )
        self.add_grade_element(
            title=no_tr("route_forwarding"), max_grade=2, grade_part=part2,
            grade=int(fwd6['r1']) + int(fwd6['r2']),
            description=tr("routage IPv6 activé sur r1 et r2"),
        )
        self.add_grade_element(
            title=no_tr("route_hotes"), max_grade=1, grade_part=part2,
            grade=int(not fwd6['m1'] and not fwd6['m2'] and not fwd6['srv']),
            description=tr("routage IPv6 désactivé sur m1, m2 et srv"),
        )
        for m, pts in (('m1', 1), ('r1', 2)):
            r = eval_net_config(self, family6(nc[m]), current=family6(persistent[m]))
            self.add_grade_element(
                title=no_tr(f"route_persistant_{m}"), max_grade=pts, grade_part=part2,
                grade=pts * int(r.ips == r.ips_expected and r.default_route == 1),
                description=tr("configuration IPv6 persistante de {m} (/etc/network/interfaces)").format(m=m),
            )
        for key, pts, desc in (('h1_h2', 1, tr("ping -6 de h1 (lan1) vers h2 (lan2) à travers l'opérateur")),
                               ('h2_h1', 1, tr("ping -6 de h2 vers h1")),
                               ('h3_m1', 1, tr("ping -6 de h3 (lan3) vers m1")),
                               ('m2_srv', 1, tr("ping -6 de m2 vers srv"))):
            self.add_grade_element(title=no_tr(f"route_ping_{key}"), max_grade=pts, grade_part=part2,
                                   grade=pts * int(pings[key]), description=desc)
        self.add_grade_element(
            title=no_tr("route_q_typed"), max_grade=0.5, grade_part=part2,
            grade=0.5 * int(_is(q2.get("unreach_type"), 1)),
            description=tr("message d'erreur"),
        )
        self.add_grade_element(
            title=no_tr("route_q"), max_grade=0.5, grade_part=part2, scope=CHOICE_SCOPE,
            grade=0.5 * int("/48" in _norm(q2.get("agregat"))
                            and "dev" in _norm(q2.get("via_ll")) and "chaque adresse" in _norm(q2.get("kernel_route"))),
            description=tr("agrégation, prochain saut de lien local, routes du noyau"),
        )

        # =====================================================================
        # Partie 3 — SLAAC
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Annonces de routeur et SLAAC sur lan3"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Annonces de routeur de r2 et autoconfiguration de pc1"),
            hash="eb27293c57948683",
            description=tr("""
`pc1` et `pc2`, sur `lan3`, n'ont que leur adresse de lien local (`ip -6 addr`, `ip -6 route`) : elles
attendent les **annonces de routeur** de `r2`.

1. Sur `pc1`, lancez `tcpdump -n -v -i eth0 icmp6` dans un second terminal : rien ne vient.
2. Sur `r2`, écrivez `/etc/radvd.conf` pour `eth2` : annonces activées, intervalle court
   (`MinRtrAdvInterval 3`, `MaxRtrAdvInterval 10`, pour ne pas attendre), le préfixe `{lan3}`
   avec les drapeaux *on-link* et *autonomous*, et l'option **RDNSS** avec l'adresse de `srv`
   (`{srv}`). Vérifiez la syntaxe (`radvd -c`), lancez le service (`systemctl restart radvd`) et
   vérifiez qu'il tourne (`pidof radvd`).
3. Sur `pc1`, lisez l'annonce dans la capture (drapeaux, durée de vie du routeur, préfixe, RDNSS),
   puis `ip -6 addr` et `ip -6 route` : d'où viennent l'adresse et la route par défaut ? Comparez
   l'adresse avec l'adresse MAC de `pc1`. Vérifiez `ping -6 {m1}` (l'adresse de `m1`) depuis `pc1`,
   et sur `r2` `ip -6 neigh`.
4. Sur `pc1`, `cat /etc/resolv.conf` : vide. Le noyau ne fait rien de l'option RDNSS (il y faudrait
   `rdnssd` ou NetworkManager) : `ping -6 m1` échoue sur le nom. La partie 4 y remédie.
5. Facultatif : `sysctl net.ipv6.conf.eth0.accept_ra`, `autoconf` sur `pc1` et `pc2`, et comparez
   `ip -6 addr` / `ip -6 route` de `pc2` (`autoconf=0` : la route sans l'adresse).
""").format(lan3=d.nets6.lan3, srv=d6.srv.ip, m1=d6.m1.ip)
            + instructor(tr("""
**Solution.** `/etc/radvd.conf` sur `r2` :

```
{radvd}
```

puis `radvd -c`, `systemctl restart radvd`, `pidof radvd` (le routage IPv6 de la partie 2 doit être
actif : radvd refuse de fonctionner sans).

- `pc1` obtient `{pc1}/64` (EUI-64 de sa MAC `{mac_pc1}` : `ff:fe` au milieu, bit U/L inversé) marquée
  `dynamic mngtmpaddr`, et `default via {ll_r2} dev eth0 proto ra metric 1024 expires …` : le prochain
  saut est l'adresse de lien local de `r2` sur `eth2`, la durée de vie celle du routeur (3 × `MaxRtrAdvInterval`
  par défaut).
- Dans la capture : `ICMP6, router advertisement, length 96 … hop limit 64, Flags [none], pref medium,
  router lifetime 30s …, prefix info option (3) … {lan3}, Flags [onlink, auto] …, rdnss option (25)
  … {srv}, dnssl option (31)`.
- Évaluation : la sonde `h3` envoie un RS et lit le RA (préfixe avec A et L, RDNSS, durée de vie du
  routeur, émetteur en lien local), `ip -j -6 addr` et la route par défaut (`protocol ra`) de `pc1`,
  `pidof radvd` sur `r2`, pings `h3` → `pc1` et `pc1` → `m1`.
""").format(radvd=self.net_scheme._solution_radvd_conf(part=3).strip(), pc1=pc1_slaac.ip,
            mac_pc1=mac_str(d.macs.pc1), ll_r2=ll_expected['r2'], lan3=d.nets6.lan3, srv=d6.srv.ip)),
        )
        q3_answers = {"adresse_pc1": str(pc1_slaac.ip), "next_hop": str(ll_expected['r2']), "rs_type": "133",
                      "ra_type": "134", "route_source": "l'annonce de routeur (durée de vie du routeur)",
                      "flag_a": "les machines forment une adresse avec ce préfixe (SLAAC)",
                      "flag_l": "le préfixe est joignable directement sur le lien"}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Ce que pc1 a reçu"),
            hash="5291b7e685e9e1c0",
            description=tr("""
- Adresse globale obtenue par `pc1` : @@{adresse_pc1:[0-9a-fA-F:/]+}@@
- Prochain saut de sa route par défaut : @@{next_hop:[0-9a-fA-F:%/]+}@@
- Types ICMPv6 de la sollicitation de routeur : @@{rs_type:[0-9]+}@@ et de l'annonce : @@{ra_type:[0-9]+}@@
- La route par défaut de `pc1` vient de : @@{route_source:>l'annonce de routeur (durée de vie du routeur)|l'option préfixe|DHCPv6|une configuration manuelle}@@
- Drapeau **A** (*autonomous*) d'un préfixe annoncé : @@{flag_a:>les machines forment une adresse avec ce préfixe (SLAAC)|le préfixe est joignable directement sur le lien|les adresses viennent de DHCPv6}@@
- Drapeau **L** (*on-link*) : @@{flag_l:>le préfixe est joignable directement sur le lien|les machines forment une adresse avec ce préfixe (SLAAC)|le routeur est la route par défaut}@@
""")
            + instructor(_with_answers(tr("""
**Réponses.** adresse `{adresse_pc1}` ; prochain saut `{next_hop}` (lien local de `r2` eth2 ; la valeur
réellement installée sur `pc1` est acceptée) ; RS `{rs_type}`, RA `{ra_type}` ; {route_source} ;
A : {flag_a} ; L : {flag_l}.
"""), q3_answers)),
            cheat_answers={"final": q3_answers},
        )
        pc1_slaac_addrs = [a for a in global_addresses(pc1_addrs, slaac=True) if a in d.nets6.lan3]
        ra_default = [r for r in pc1_defaults if r['protocol'] == 'ra' and r['gateway'] and r['gateway'].is_link_local]
        self.add_grade_element(
            title=no_tr("slaac_ra_prefixe"), max_grade=2, grade_part=part3,
            grade=2 * int(ra_prefix is not None and ra_prefix.autonomous and ra_prefix.on_link),
            description=tr("r2 annonce le préfixe {lan3} avec les drapeaux A et L").format(lan3=d.nets6.lan3),
        )
        self.add_grade_element(
            title=no_tr("slaac_ra_routeur"), max_grade=1, grade_part=part3,
            grade=int(ra is not None and ra.router_lifetime > 0 and ra.src is not None and ra.src.is_link_local),
            description=tr("l'annonce fait de r2 un routeur par défaut (durée de vie non nulle)"),
        )
        self.add_grade_element(
            title=no_tr("slaac_ra_rdnss"), max_grade=1, grade_part=part3,
            grade=int(ra is not None and d6.srv.ip in ra.rdnss),
            description=tr("option RDNSS de l'annonce : le serveur DNS srv"),
        )
        self.add_grade_element(
            title=no_tr("slaac_radvd"), max_grade=1, grade_part=part3, grade=int(radvd),
            description=tr("radvd tourne sur r2"),
        )
        self.add_grade_element(
            title=no_tr("slaac_pc1_adresse"), max_grade=2, grade_part=part3, grade=2 * int(bool(pc1_slaac_addrs)),
            description=tr("pc1 a une adresse automatique dans {lan3}").format(lan3=d.nets6.lan3),
        )
        self.add_grade_element(
            title=no_tr("slaac_pc1_eui64"), max_grade=1, grade_part=part3, grade=int(pc1_slaac.ip in pc1_slaac_addrs),
            description=tr("l'adresse de pc1 est l'EUI-64 de son adresse MAC ({pc1})").format(pc1=pc1_slaac.ip),
        )
        self.add_grade_element(
            title=no_tr("slaac_pc1_route"), max_grade=2, grade_part=part3, grade=2 * int(bool(ra_default)),
            description=tr("route par défaut de pc1 apprise de l'annonce (prochain saut de lien local, proto ra)"),
        )
        self.add_grade_element(
            title=no_tr("slaac_ping_h3_pc1"), max_grade=1, grade_part=part3, grade=int(pings['h3_pc1']),
            description=tr("ping -6 de h3 vers l'adresse SLAAC de pc1"),
        )
        self.add_grade_element(
            title=no_tr("slaac_ping_pc1_m1"), max_grade=2, grade_part=part3, grade=2 * int(pings['pc1_m1']),
            description=tr("ping -6 de pc1 vers m1 (route par défaut apprise, routage de r2)"),
        )
        self.add_grade_element(
            title=no_tr("slaac_q_pc1"), max_grade=1, grade_part=part3,
            grade=int(_ipv6_in(q3.get("adresse_pc1"), pc1_slaac, pc1_slaac_addrs)
                      and _ipv6_in(q3.get("next_hop"), ll_expected['r2'], [r['gateway'] for r in ra_default])),
            description=tr("adresse et prochain saut relevés sur pc1"),
        )
        self.add_grade_element(
            title=no_tr("slaac_q_ra_typed"), max_grade=0.5, grade_part=part3,
            grade=0.5 * int(_is(q3.get("rs_type"), 133) and _is(q3.get("ra_type"), 134)),
            description=tr("types RS / RA"),
        )
        self.add_grade_element(
            title=no_tr("slaac_q_ra"), max_grade=1.5, grade_part=part3, scope=CHOICE_SCOPE,
            grade=0.5 * int(_norm(q3.get("route_source")).startswith("l'annonce"))
            + int(_norm(q3.get("flag_a")).startswith("les machines forment")
                  and _norm(q3.get("flag_l")).startswith("le préfixe est joignable")),
            description=tr("origine de la route par défaut, drapeaux A et L"),
        )

        # =====================================================================
        # Partie 4 — DHCPv6
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — DHCPv6 sur srv"))
        self.question_dummy(
            section=self.section(0),
            title=tr("DHCPv6 sans état : le DNS pour pc1"),
            hash="f3f8f01ac46861e7",
            description=tr("""
`srv` (image avec systemd) sera le serveur DHCPv6 de `lan3`. Commencez par le mode **sans état** :
`pc1` garde son adresse SLAAC et ne demande que les paramètres DNS.

1. Sur `r2`, ajoutez `AdvOtherConfigFlag on;` (drapeau **O**) à l'interface `eth2` de `radvd.conf`
   et relancez radvd.
2. Sur `srv` : `INTERFACESv6="eth0"` dans `/etc/default/isc-dhcp-server`, puis `/etc/dhcp/dhcpd6.conf`
   avec les options `dhcp6.name-servers` (`{srv}`) et `dhcp6.domain-search` (`{domain}`), la durée
   `default-lease-time {lease6}` (utile dès la question suivante) et une déclaration `subnet6` pour
   `{lan3}` **sans `range6`**. Vérifiez la syntaxe (`dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`), lancez
   `systemctl restart isc-dhcp-server`, contrôlez `journalctl -u isc-dhcp-server` et
   `ps -C dhcpd -o pid,args`.
3. Sur `pc1`, capturez `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` puis lancez
   `dhclient -6 -S -v eth0`. Relevez les messages échangés, l'adresse de destination et les ports,
   puis `cat /etc/resolv.conf` et `ping -6 -c 2 m1` (le nom, cette fois).
""").format(srv=d6.srv.ip, domain=DOMAIN, lease6=d.lease6, lan3=d.nets6.lan3)
            + instructor(tr("""
**Solution.** `radvd.conf` de `r2` avec le drapeau O :

```
{radvd}
```

Sur `srv`, `/etc/default/isc-dhcp-server` :

```
{defaults}
```

`/etc/dhcp/dhcpd6.conf` (sans état) :

```
{conf}
```

puis `dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`, `systemctl restart isc-dhcp-server`. Sur `pc1` :
`dhclient -6 -S -v eth0` affiche `XMT: Info-Request on eth0, interval …` puis `RCV: Reply message on
eth0 from fe80::…` ; `/etc/resolv.conf` contient `search {domain}` et `nameserver {srv}`.

- Capture : `fe80::… .546 > ff02::1:2.547: dhcp6 inf-req` puis `… .547 > … .546: dhcp6 reply` avec les
  options `client-ID`, `server-ID`, `DNS-server`, `DNS-search-list`.
- Le `subnet6` est exigé même sans adresse à distribuer : `dhcpd` doit trouver l'adresse globale de
  `eth0` dedans (`No subnet6 declaration for eth0` sinon) ; la partie 2 doit donc être faite.
- Évaluation : drapeau O lu par la sonde, INFORMATION-REQUEST de la sonde → REPLY avec le serveur DNS
  et le domaine, `dhcpd -6` lancé sur `eth0` seulement (ligne de commande), `resolv.conf` de `pc1` et
  `getent ahostsv6 m1` sur `pc1`.
""").format(radvd=self.net_scheme._solution_radvd_conf(part=4).strip(), defaults=DHCPD6_DEFAULTS.strip(),
            conf=self.net_scheme._solution_dhcpd6_conf(part=4).strip(), domain=DOMAIN, srv=d6.srv.ip)),
        )
        q4a_answers = {"port_client": "546", "port_serveur": "547", "multicast": "ff02::1:2",
                       "msg_req": "INFORMATION-REQUEST", "msg_rep": "REPLY",
                       "route6": "non : elle vient toujours de l'annonce de routeur"}
        q4a = self.question_form(
            section=self.section(1),
            title=tr("Le protocole"),
            hash="d3733e751866316c",
            description=tr("""
- Port UDP du client DHCPv6 : @@{port_client:[0-9]+}@@ ; du serveur : @@{port_serveur:[0-9]+}@@
- Adresse de destination de la requête de `pc1` : @@{multicast:[0-9a-fA-F:]+}@@
- Messages échangés en mode sans état : @@{msg_req:>INFORMATION-REQUEST|SOLICIT|REQUEST|DHCPINFORM}@@ puis
  @@{msg_rep:>REPLY|ADVERTISE|ACK|OFFER}@@
- DHCPv6 peut-il donner la route par défaut ? @@{route6:>non : elle vient toujours de l'annonce de routeur|oui, par une option comme routers en IPv4|oui, c'est le serveur qui la choisit}@@
""")
            + instructor(_with_answers(tr("""
**Réponses.** client `{port_client}`, serveur `{port_serveur}` ; destination `{multicast}` (tous les serveurs et
relais DHCPv6 du lien) ; `{msg_req}` puis `{msg_rep}` ; {route6}.
"""), q4a_answers)),
            cheat_answers={"final": q4a_answers},
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("DHCPv6 avec état : une adresse pour pc2"),
            hash="69d9931d4126850a",
            description=tr("""
`pc2` est réglée pour **ne pas** former d'adresse automatique (`autoconf=0`) tout en acceptant la route
par défaut des annonces : c'est un poste qui attend son adresse d'un serveur.

1. Sur `r2`, ajoutez `AdvManagedFlag on;` (drapeau **M**) et relancez radvd.
2. Sur `srv`, ajoutez au `subnet6` la plage `range6 {pool_min} {pool_max}` et relancez le service.
3. Sur `pc2`, capturez puis lancez `dhclient -6 -D LL -v eth0` (DUID de type **LL**, déduit de
   l'adresse MAC ; sans `-D LL`, le client fabrique un DUID-LLT horodaté). Relevez les quatre messages,
   puis `ip -6 addr` (préfixe et durées de vie de l'adresse reçue), `ip -6 route` (d'où vient la route
   par défaut ?), `/etc/resolv.conf`, `ping -6 -c 2 m1`.
4. Lisez le bail dans `/var/lib/dhcp/dhclient6.leases` sur `pc2` (`default-duid`, `iaaddr`,
   `max-life`) et, sur `srv`, le journal (`Solicit message from … duid …`) et
   `/var/lib/dhcp/dhcpd6.leases`.
""").format(pool_min=d6.pool_min.ip, pool_max=d6.pool_max.ip)
            + instructor(tr("""
**Solution.** `radvd.conf` avec M et O :

```
{radvd}
```

`dhcpd6.conf` avec la plage :

```
{conf}
```

puis `systemctl restart radvd` sur `r2`, `systemctl restart isc-dhcp-server` sur `srv`, et sur `pc2`
`dhclient -6 -D LL -v eth0` : `XMT: Solicit`, `RCV: Advertise`, `XMT: Request`, `RCV: Reply`, `bound to
{pool_min}…` (une adresse de la plage, en `/128`, `valid_lft {lease6}sec`).

- La route par défaut de `pc2` est `via {ll_r2} … proto ra` : DHCPv6 n'en donne jamais.
- DUID-LL de `pc2` : `{pc2_duid}` (`00:03` + `00:01` + MAC `{mac_pc2}`) ; le journal de `srv` l'écrit en
  hexadécimal, le fichier de baux de `pc2` en octal (`default-duid "\\000\\003\\000\\001…"`).
- Évaluation : drapeau M, SOLICIT de la sonde → ADVERTISE avec une adresse de la plage et une durée de
  validité de {lease6} s, adresse `dynamic` de `pc2` dans la plage (ou l'adresse réservée de la question
  suivante) inscrite dans son fichier de baux, route par défaut de `pc2` apprise du RA, `getent ahostsv6 m1`
  sur `pc2`.
""").format(radvd=self.net_scheme._solution_radvd_conf(part=5).strip(),
            conf=self.net_scheme._solution_dhcpd6_conf(part=5).strip(), pool_min=d6.pool_min.ip, lease6=d.lease6,
            ll_r2=ll_expected['r2'], pc2_duid=pc2_duid, mac_pc2=mac_str(d.macs.pc2))),
        )
        q4b_answers = {"duid_pc2": pc2_duid, "prefixlen": "128", "msg1": "SOLICIT", "msg2": "ADVERTISE",
                       "msg3": "REQUEST", "msg4": "REPLY", "valid": str(d.lease6)}
        q4b = self.question_form(
            section=self.section(1),
            title=tr("Le bail de pc2"),
            hash="f74980f51ef14102",
            description=tr("""
- DUID de `pc2` (octets en hexadécimal séparés par `:`) : @@{duid_pc2:[0-9a-fA-F:-]+}@@
- Longueur du préfixe de l'adresse posée par `dhclient` sur `eth0` : @@{prefixlen:[0-9]+}@@
- Les quatre messages de l'obtention d'une adresse : @@{msg1:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis
  @@{msg2:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis @@{msg3:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis
  @@{msg4:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@
- Durée de validité de l'adresse (`max-life` dans le bail), en secondes : @@{valid:[0-9]+}@@
""")
            + instructor(tr("""
**Réponses.** DUID `{duid_pc2}` ; préfixe `/{prefixlen}` (le préfixe du lien vient du RA, drapeau L) ;
`{msg1}`, `{msg2}`, `{msg3}`, `{msg4}` ; validité `{valid}` s (`default-lease-time`).
""").format(**q4b_answers)),
            cheat_answers={"final": q4b_answers},
        )
        self.question_dummy(
            section=self.section(1),
            title=tr("Réservation par DUID"),
            hash="dbae8a4244916493",
            description=tr("""
`pc2` doit toujours recevoir l'adresse **`{pc2_fixe}`** (hors de la plage).

1. Sur `srv`, déclarez un bloc `host` identifié par le DUID de `pc2` (`host-identifier option
   dhcp6.client-id …`) avec `fixed-address6`, et relancez le service.
2. Sur `pc2`, libérez l'adresse (`dhclient -6 -D LL -r eth0`) puis redemandez-en une
   (`dhclient -6 -D LL -v eth0`) : vérifiez `ip -6 addr` et le journal de `srv`.
""").format(pc2_fixe=d6.pc2_fixe.ip)
            + instructor(tr("""
**Solution.** À ajouter à `dhcpd6.conf` sur `srv` (fichier complet) :

```
{conf}
```

puis `systemctl restart isc-dhcp-server` ; sur `pc2`, `dhclient -6 -D LL -r eth0` puis
`dhclient -6 -D LL -v eth0` : `bound to {pc2_fixe}`.

- Piège : le DUID est conservé dans `/var/lib/dhcp/dhclient6.leases` ; un client lancé une première fois
  sans `-D LL` garde son DUID-LLT et la réservation ne s'applique pas (le journal de `srv` montre le DUID
  reçu). Remède : libérer, `pkill dhclient`, supprimer le fichier de baux, relancer avec `-D LL`.
- Évaluation : SOLICIT de la sonde avec le DUID-LL de `pc2` → ADVERTISE de `{pc2_fixe}` ; adresse `dynamic`
  de `pc2` égale à `{pc2_fixe}`.
""").format(conf=self.net_scheme._solution_dhcpd6_conf(part=6).strip(), pc2_fixe=d6.pc2_fixe.ip)),
        )
        pool = (d6.pool_min.ip, d6.pool_max.ip)

        def in_pool(address) -> bool:
            return pool[0] <= address <= pool[1]

        dyn_pool = [r for r in dyn if any(in_pool(a.address) for a in r.addresses)]
        dyn_valid = [r for r in dyn_pool if any(a.valid == d.lease6 for a in r.addresses if in_pool(a.address))]
        pc2_dhcp = [a for a in global_addresses(pc2_addrs, dynamic=True, slaac=False) if a in d.nets6.lan3]
        pc2_leased = {a['address'] for lease in pc2_leases for a in lease['addresses']}
        pc2_ra_default = [r for r in pc2_defaults if r['protocol'] == 'ra' and r['gateway'] and r['gateway'].is_link_local]
        self.add_grade_element(
            title=no_tr("dhcp6_ra_o"), max_grade=1, grade_part=part4, grade=int(ra is not None and ra.other),
            description=tr("drapeau O (other config) dans les annonces de r2"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_serveur"), max_grade=1, grade_part=part4, grade=int(dhcpd6_ifaces == ['eth0']),
            description=tr("dhcpd -6 tourne sur srv, sur eth0 uniquement"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_info"), max_grade=3, grade_part=part4,
            grade=2 * int(bool(info) and all(d6.srv.ip in r.dns_servers for r in info))
            + int(bool(info) and all(DOMAIN in r.domain_search for r in info)),
            description=tr("REPLY à une INFORMATION-REQUEST : serveur DNS srv et domaine {domain}").format(domain=DOMAIN),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_pc1_resolv"), max_grade=1, grade_part=part4,
            grade=int(str(d6.srv.ip) in resolv['pc1']['nameservers'] and DOMAIN in resolv['pc1']['search']),
            description=tr("resolv.conf de pc1 écrit par dhclient -6 -S"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_pc1_dns"), max_grade=2, grade_part=part4,
            grade=2 * int(str(d6.m1.ip) in getent['pc1'].split()),
            description=tr("pc1 résout le nom m1 (serveur DNS reçu par DHCPv6)"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_ra_m"), max_grade=1, grade_part=part4, grade=int(ra is not None and ra.managed),
            description=tr("drapeau M (managed) dans les annonces de r2"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_advertise"), max_grade=3, grade_part=part4,
            grade=2 * int(bool(dyn_pool)) + int(bool(dyn_valid)),
            description=tr("ADVERTISE à un SOLICIT : adresse de la plage {pool_min} – {pool_max}, validité {lease6} s")
            .format(pool_min=pool[0], pool_max=pool[1], lease6=d.lease6),
        )
        pc2_ok = [a for a in pc2_dhcp if in_pool(a) or a == d6.pc2_fixe.ip]
        self.add_grade_element(
            title=no_tr("dhcp6_pc2_adresse"), max_grade=3, grade_part=part4,
            grade=2 * int(bool(pc2_ok)) + int(any(a in pc2_leased for a in pc2_ok)),
            description=tr("pc2 a obtenu par DHCPv6 une adresse de la plage ou l'adresse réservée, inscrite dans son bail"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_pc2_route"), max_grade=1, grade_part=part4, grade=int(bool(pc2_ra_default)),
            description=tr("route par défaut de pc2 apprise de l'annonce de routeur"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_pc2_dns"), max_grade=1, grade_part=part4,
            grade=int(str(d6.m1.ip) in getent['pc2'].split()),
            description=tr("pc2 résout le nom m1"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_reservation"), max_grade=3, grade_part=part4,
            grade=3 * int(bool(fixe) and all(any(a.address == d6.pc2_fixe.ip for a in r.addresses) for r in fixe)),
            description=tr("srv propose {pc2_fixe} au DUID de pc2").format(pc2_fixe=d6.pc2_fixe.ip),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_pc2_fixe"), max_grade=2, grade_part=part4,
            grade=2 * int(d6.pc2_fixe.ip in pc2_dhcp),
            description=tr("pc2 a reçu l'adresse réservée {pc2_fixe}").format(pc2_fixe=d6.pc2_fixe.ip),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_q_protocole_typed"), max_grade=0.5, grade_part=part4,
            grade=0.5 * int(_is(q4a.get("port_client"), 546) and _is(q4a.get("port_serveur"), 547)
                            and same_ipv6(q4a.get("multicast"), "ff02::1:2")),
            description=tr("ports, adresse multicast"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_q_protocole"), max_grade=0.5, grade_part=part4, scope=CHOICE_SCOPE,
            grade=0.5 * int(_norm(q4a.get("msg_req")) == "information-request" and _norm(q4a.get("msg_rep")) == "reply"
                            and _norm(q4a.get("route6")).startswith("non")),
            description=tr("messages sans état, route par défaut"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_q_bail_typed"), max_grade=0.5, grade_part=part4,
            grade=0.5 * int(normalize_duid(q4b.get("duid_pc2")) in (pc2_duid, pc2_duid_seen or "")
                            and _is(q4b.get("prefixlen"), 128) and _is(q4b.get("valid"), d.lease6)),
            description=tr("DUID de pc2, préfixe de l'adresse, durée de validité"),
        )
        self.add_grade_element(
            title=no_tr("dhcp6_q_bail"), max_grade=0.5, grade_part=part4, scope=CHOICE_SCOPE,
            grade=0.5 * int([_norm(q4b.get(f"msg{i}")) for i in range(1, 5)] == ["solicit", "advertise", "request", "reply"]),
            description=tr("ordre des messages"),
        )

        # =====================================================================
        # Partie 5 — PMTUD et trou noir en double pile
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — MTU, Packet Too Big et trou noir en double pile"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Découverte du PMTU en IPv6"),
            hash="d674337761cd40de",
            description=tr("""
Les liens de l'opérateur (`wan`) ont un MTU inférieur à 1500. Dans cette partie et la suivante,
`m1`, `m2`, `r1` et `r2` sont les machines des deux sites (cours, sections @@ref:mtu@@ et @@ref:tunnels@@).

1. Sur `m1`, lancez `tcpdump -n -v -i eth0 icmp6` dans un second terminal, puis
   `ping -6 -c 3 -M do -s 1452 m2`. Relevez le message d'erreur, la machine qui l'émet et le MTU
   annoncé ; comparez avec `ping -4 -c 3 -M do -s 1472 m2` (faites `ip route flush cache` et
   `ip -6 route flush cache` entre deux essais pour repartir d'un cache vide). Consultez
   `ip -6 route get` vers `m2` et `tracepath -6 -n m2`.
2. Par dichotomie avec `ping -6 -M do -s TAILLE m2`, trouvez la plus grande charge utile qui
   traverse l'opérateur sans erreur, et comparez avec la valeur IPv4.
3. Fragmentation : `ping -6 -c 4 -s 3000 m2` (sans `-M do`), caches vidés au préalable. Observez
   avec `tcpdump -n -i eth1 ip6` sur `r1` : qui découpe le paquet, en combien de fragments
   (`frag (décalage|taille)`), et quel en-tête d'extension les porte ? Pourquoi les premiers
   essais échouent-ils avant qu'un essai réussisse (pensez à la réponse de `m2`, aussi grosse que
   la demande) ? Comparez avec `ping -4 -c 2 -s 3000 m2` : en IPv4 `wan` refragmente ce que `m1` a
   déjà découpé en 1500 et le premier essai réussit.
4. Déduisez-en le MSS TCP qu'un hôte devrait annoncer en IPv6 pour que ses segments traversent
   l'opérateur, et vérifiez-le pendant un `iperf3 -6 -c m2` (`iperf3 -s` sur `m2`) avec `ss -ti` sur `m1`.
""")
            + instructor(tr("""
**Solution.** Sur `m1`, caches vidés (`ip route flush cache; ip -6 route flush cache`) :

```
ping -6 -c 3 -M do -s 1452 m2  # From wan_wan1 ({wan1v6}) icmp_seq=1 Packet too big: mtu={n}
# puis, deux fois : ping: sendmsg: Message too long
ping -4 -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1v4}) icmp_seq=1 Frag needed and DF set (mtu = {n})
ip -6 route get {m2v6}  # ... expires ...sec mtu {n}
tracepath -6 -n m2  # Resume: pmtu {n} hops 4 back 4
ping -6 -c 1 -M do -s {charge6} m2  # passe : {charge6} + 48 = {n} (IPv4 : {charge4} + 28 = {n})
ping -6 -c 1 -M do -s {charge61} m2  # refusé
ping -6 -c 4 -s 3000 m2  # deux essais perdus, puis des réponses
ping -4 -c 2 -s 3000 m2  # réussit dès le premier essai
```

- L'erreur est un ICMPv6 type 2 (*Packet Too Big*) émis par `wan` (son adresse côté `wan1`) ; `tcpdump`
  affiche `ICMP6, packet too big, mtu {n}`.
- `ping -6 -s 3000` : `m1` découpe d'abord pour son lien à 1500 (`frag (0|1448)`, `frag (1448|1448)`,
  `frag (2896|112)`, en-tête *Fragment*, *next header* 44). `wan` ne fragmente pas : il répond *Packet Too
  Big*. Au deuxième essai `m1` découpe pour {n} (`frag (0|{frag6})`…) et le paquet arrive, mais la réponse
  de `m2`, aussi grosse, est perdue à son tour : `m2` doit lui aussi apprendre le PMTU. Les essais suivants
  passent.
- En IPv4 `m1` découpe en 1500 puis `wan` refragmente : aucun apprentissage n'est nécessaire.
- MSS IPv6 : {n} − 60 = **{mss6}** ; `ss -ti` affiche 12 octets de moins (option *timestamps*).
""").format(n=n, charge6=charge6, charge61=charge6 + 1, charge4=charge4, mss6=mss6,
            frag6=(n - pmtu.IPV6_HDR - 8) // 8 * 8, m2v6=d6.m2.ip, wan1v6=d6.wan_wan1.ip, wan1v4=d4.wan_wan1.ip)),
        )
        q5_answers = {"charge_v6": str(charge6), "charge_v4": str(charge4), "icmpv6_type": "2", "emetteur": "wan",
                      "qui_v6": "m1 uniquement", "next_header": "44", "mss_v6": str(mss6)}
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Mesures"),
            hash="b7ceb67b65dc5fa7",
            description=tr("""
- Plus grande charge utile de `ping -6 -M do -s` qui traverse l'opérateur sans erreur : @@{charge_v6:[0-9]+}@@ ;
  la même en IPv4 (`ping -4 -M do -s`) : @@{charge_v4:[0-9]+}@@
- Message ICMPv6 reçu par `m1` : type @@{icmpv6_type:[0-9]+}@@, émis par @@{emetteur:>m2|wan|r1|r2}@@
- Pour `ping -6 -s 3000 m2`, la ou les machines qui fragmentent : @@{qui_v6:>m1 uniquement|wan uniquement|m1 puis wan|r1|n'importe quel routeur}@@
- Valeur du champ *next header* qui annonce un en-tête Fragment : @@{next_header:[0-9]+}@@
- MSS TCP (sans option) adapté au lien de l'opérateur en IPv6 : @@{mss_v6:[0-9]+}@@
""")
            + instructor(_with_answers(tr("""
**Réponses.**

- charge utile maximale : `{charge_v6}` en IPv6 ({n} − 40 − 8), `{charge_v4}` en IPv4 ({n} − 20 − 8)
- ICMPv6 type `{icmpv6_type}` (*Packet Too Big*), émis par `{emetteur}`
- fragmentation : `{qui_v6}` (un routeur IPv6 ne fragmente jamais) ; *next header* `{next_header}`
- MSS : `{mss_v6}` ({n} − 60)
"""), q5_answers, n=n)),
            cheat_answers={"final": q5_answers},
        )
        choices = {"pmtu_q_ptb", "pmtu_q_fragmentation"}
        for title_, pts, ok, desc in (
                ("pmtu_q_charge", 1, _is(q5.get("charge_v6"), charge6) and _is(q5.get("charge_v4"), charge4),
                 tr("plus grandes charges utiles de ping -M do qui traversent (IPv6 et IPv4)")),
                ("pmtu_q_ptb_typed", 0.5, _is(q5.get("icmpv6_type"), 2), tr("type du message Packet Too Big")),
                ("pmtu_q_ptb", 0.5, _norm(q5.get("emetteur")) == "wan", tr("émetteur du message Packet Too Big")),
                ("pmtu_q_fragmentation_typed", 0.5, _is(q5.get("next_header"), 44),
                 tr("next header de l'en-tête Fragment")),
                ("pmtu_q_fragmentation", 0.5, _norm(q5.get("qui_v6")) == "m1 uniquement",
                 tr("en IPv6 seule la source fragmente")),
                ("pmtu_q_mss", 1, _is(q5.get("mss_v6"), mss6), tr("MSS TCP IPv6 adapté au lien de l'opérateur")),
        ):
            self.add_grade_element(title=no_tr(title_), max_grade=pts, grade_part=part5,
                                   scope=CHOICE_SCOPE if title_ in choices else params.BOTH_EVAL_SCOPE,
                                   grade=pts * int(ok), description=desc)
        self.question_dummy(
            section=self.section(1),
            title=tr("Trou noir PMTUD en double pile"),
            hash="52c11c7a49b1dea7",
            description=tr("""
1. Lancez `iperf3 -s` sur `m2`, puis sur `m1` `iperf3 -6 -c m2 -t 5` et `iperf3 -4 -c m2 -t 5` :
   les deux transferts passent.
2. Appliquez l'état **`trou_noir`** (onglet *Appliquer une configuration*). Vérifiez que
   `ping -6 m2` et `ping -4 m2` passent toujours, puis relancez `timeout 20 iperf3 -6 -c m2 -t 5`
   et la même chose en `-4` : observez le gel, `ss -ti dst m2` (retransmissions) et
   `tcpdump -n -i eth1 'ip6 or icmp'` sur `r1`.
3. Corrigez le problème **sur `r1` et/ou `r2`, pour les deux familles** : MSS clamping nftables
   (`meta nfproto ipv4` / `ipv6`, ou une règle commune), ou MTU réduit sur les interfaces tournées
   vers l'opérateur. Vérifiez que les deux transferts passent de nouveau et, dans une capture des
   SYN sur `r1`, la nouvelle valeur de l'option `mss` dans chaque famille.
4. Les transferts notés se font entre les postes cachés `h1` et `h2`, qui restent derrière le trou
   noir quoi qu'il arrive : votre correction doit être en place sur les routeurs au moment de
   l'évaluation, IPv6 compris. `trou_noir` peut rester appliqué ou non.
""")
            + instructor(tr("""
**Solution.** Après `trou_noir`, `ping -6 m2` et `ping -4 m2` passent encore, mais `iperf3 -6 -c m2` et
`iperf3 -4 -c m2` affichent `0.00 Bytes` côté *receiver* : les segments de 1500 octets partent vers `wan`
et aucune erreur ne revient.

Correction A, MSS clamping des deux familles, sur `r1`, sur `r2` ou sur les deux (c'est ce qu'applique
l'état `final`) :

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set {mss4}
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set {mss6}
```

ou une seule règle pour les deux familles, avec la plus petite valeur :
`nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss6}`.

Correction B, MTU des interfaces tournées vers l'opérateur, sur les **deux** routeurs (elle vaut pour les
deux familles) :

```
ip link set dev eth1 mtu {n}  # sur r1
ip link set dev eth0 mtu {n}  # sur r2
```

- Vérification : `iperf3 -6 -c m2 -t 5` et `iperf3 -4 -c m2 -t 5` passent de nouveau. Avec A, sur `r1`,
  `tcpdump -n -i eth1 'ip6 proto 6 and ip6[53] & 2 != 0'` montre `mss {mss6}` dans les SYN IPv6, et
  `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'` `mss {mss4}` dans les SYN IPv4.
- Piège : une table `ip`, ou la seule règle `meta nfproto ipv4`, laisse IPv6 dans le trou noir (transferts
  IPv6 des sondes à 0, soit 6 points). A sur un seul routeur suffit ; B sur `r1` seul laisse le sens
  `h2` → `h1` dans le trou noir.
- Évaluation : `tn_v6a` et `tn_v6r` (3 points chacun), `tn_v4a` et `tn_v4r` (1 point chacun),
  `tn_connectivite`, `tn_config` (clamping applicable à IPv6, de valeur ≤ {mss6}, dans un hook routé de
  `r1` ou de `r2`, ou MTU ≤ {n} sur `eth1` de `r1` **et** `eth0` de `r2`).
""").format(n=n, mss4=mss4, mss6=mss6)),
        )
        q5b = self.question_form(
            section=self.section(1),
            title=tr("Correction retenue"),
            hash="3dcf79b569c3f0dc",
            description=tr("""
- Correction que vous avez mise en place : @@{correctif:>MSS clamping nftables sur r1 et/ou r2|MTU des interfaces WAN de r1 et r2 abaissé|net.ipv4.tcp_mtu_probing sur m1 et m2|route avec mtu sur m1 et m2}@@
""")
            + instructor(tr("""
**Réponses.** `MSS clamping nftables sur r1 et/ou r2` ou `MTU des interfaces WAN de r1 et r2 abaissé`,
selon la correction faite (1 point). Les deux autres choix ne corrigent que `m1` et `m2` : 0.
""")),
            cheat_answers={"final": {"correctif": "MSS clamping nftables sur r1 et/ou r2"}},
        )
        for tag, pts, description in (
                ('V6A', 3, tr("transfert TCP IPv6 de h1 vers h2 entre les sondes malgré le trou noir")),
                ('V6R', 3, tr("transfert TCP IPv6 de h2 vers h1 entre les sondes malgré le trou noir")),
                ('V4A', 1, tr("transfert TCP IPv4 de h1 vers h2 entre les sondes malgré le trou noir")),
                ('V4R', 1, tr("transfert TCP IPv4 de h2 vers h1 entre les sondes malgré le trou noir"))):
            self.add_grade_element(
                title=no_tr(f"tn_{tag.lower()}"), max_grade=pts, grade_part=part5,
                grade=pts * int((flows[tag].get('bytes') or 0) >= MIN_BYTES),
                description=description,
            )
        self.add_grade_element(
            title=no_tr("tn_connectivite"), max_grade=1, grade_part=part5,
            grade=int(pings['h1_h2'] and connected4),
            description=tr("connectivité IPv6 et IPv4 conservée entre les deux sites (ping h1 → h2)"),
        )
        self.add_grade_element(
            title=no_tr("tn_config"), max_grade=1, grade_part=part5,
            grade=int(clamp6_ok or mtu_fix_ok),
            description=tr("MSS clamping IPv6 sur r1 ou r2, ou MTU réduit sur les interfaces WAN de r1 et r2"),
        )
        self.add_grade_element(
            title=no_tr("tn_q_correctif"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
            grade=int(_norm(q5b.get("correctif")).startswith(("mss clamping", "mtu des interfaces"))),
            description=tr("correction faite sur les routeurs"),
        )
        if 1400 <= mss6:
            verdict = instructor(tr("1400 convient donc aux deux familles."))
        elif 1400 <= mss4:
            verdict = instructor(tr("1400 convient donc en IPv4 mais reste trop grand en IPv6."))
        else:
            verdict = instructor(tr("1400 est donc trop grand dans les deux familles."))
        self.question_text(
            section=self.section(1),
            title=tr("Une seule règle pour deux familles"),
            hash="8cedfc1ad7ee8ebe",
            description=tr("Dans une table `inet`, une règle `tcp flags syn tcp option maxseg size set 1400` sans "
                           "`meta nfproto` s'applique aussi aux SYN IPv6. Est-elle suffisante pour les deux familles "
                           "avec le MTU de l'opérateur que vous avez mesuré ? Justifiez par le calcul.")
            + instructor(tr("""

**Attendu.** Avec un MTU de {n}, le MSS doit valoir au plus {mss6} en IPv6 ({n} − 60) et {mss4} en IPv4
({n} − 40).""").format(n=n, mss6=mss6, mss4=mss4) + no_tr(" ") + verdict + tr(""" Une règle commune doit porter
la plus petite des deux valeurs, {mss6}, au prix de 20 octets de charge utile par segment IPv4. Question non
notée.
""").format(mss6=mss6)),
            cheat_answers={"final": "Oui si la valeur est au plus MTU - 60 : elle convient alors aussi en IPv4 "
                                    "(MTU - 40), au prix de 20 octets de charge utile par segment IPv4."},
        )

        # =====================================================================
        # Partie 6 — Tunnel 6in4
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Tunnel 6in4 et surcoût d'encapsulation"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Tunnel 6in4 entre r1 et r2"),
            hash="9cb645cac3d3cd2d",
            description=tr("""
Supposons que l'opérateur n'offre pas IPv6 : les deux sites peuvent se relier par un tunnel qui
transporte IPv6 dans l'IPv4 de l'opérateur.

1. Créez un tunnel 6in4 `sit1` entre `r1` et `r2` : les extrémités sont leurs adresses **IPv4** sur
   les réseaux de l'opérateur (`wan1` / `wan2`), les adresses intérieures les adresses **IPv6** du
   réseau `tun` du plan d'adressage (`ip link add … type sit local … remote … ttl 64`,
   `ip link set … up`, `ip -6 addr add …/64 dev sit1`). Vérifiez `ping -6` entre les deux adresses
   `tun`, et observez les paquets encapsulés avec `tcpdump -n -v -i eth1 'ip proto 41'` sur `r1`.
2. Calculez le MTU que doit avoir le tunnel pour qu'aucun paquet encapsulé ne dépasse le MTU de
   l'opérateur, réglez-le des deux côtés (`ip link set sit1 mtu …`) et vérifiez-le avec
   `ip -d link show sit1`. Que se passe-t-il si vous tentez un MTU inférieur à 1280 ?
3. Depuis `r1`, testez avec `ping -6 -M do -s TAILLE ADRESSE_TUN_DE_R2` : la plus grande charge
   utile qui passe doit correspondre au MTU du tunnel (moins 48 octets d'en-têtes IPv6 et ICMPv6),
   et un octet de plus doit être refusé localement (`message too long`).
""")
            + instructor(tr("""
**Solution.** Sur `r1` :

```
ip link add sit1 type sit local {r1_wan} remote {r2_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r1_tun} dev sit1
```

Sur `r2` :

```
ip link add sit1 type sit local {r2_wan} remote {r1_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r2_tun} dev sit1
```

- MTU du tunnel : {n} − 20 (en-tête IPv4 extérieur) = **{tun_mtu}**. Sans réglage, `sit1` reste à 1480. Un
  MTU inférieur à 1280 est refusé (`Error: mtu less than device minimum.`).
- Vérification depuis `r1` : `ping -6 {r2_tun_ip}` passe ; `ping -6 -M do -s {fit} {r2_tun_ip}` passe
  ({fit} + 48 = {tun_mtu}) ; `ping -6 -M do -s {over} {r2_tun_ip}` répond
  `ping: sendmsg: Message too long`. `tcpdump -n -v -i eth1 'ip proto 41'` montre des paquets
  IPv4 d'au plus {n} octets.
- Évaluation : `sit_r1` et `sit_r2` (type `sit` avec `local` / `remote` égaux aux adresses IPv4 `wan1` /
  `wan2`, puis MTU {tun_mtu} : 2 points chacun), `sit_joignable`, `sit_pmtu` (les deux `ping -6 -M do` ci-dessus,
  cache de `r1` vidé : sans MTU réglé sur `sit1`, le paquet trop grand part et n'est pas refusé localement).
- Les corrections de la partie 5 peuvent rester en place, et le tunnel fonctionne avec ou sans `trou_noir`.
""").format(n=n, tun_mtu=tun_mtu, r1_wan=wan_addr['r1'], r2_wan=wan_addr['r2'],
            r1_tun=d6.r1_tun, r2_tun=d6.r2_tun, r2_tun_ip=r2_tun, fit=fit, over=fit + 1)),
        )
        q6_answers = {"surcout": str(TUN_OVERHEAD), "mtu_tunnel": str(tun_mtu)}
        q6 = self.question_form(
            section=self.section(1),
            title=tr("MTU du tunnel"),
            hash="04f92c7c2f148fe8",
            description=tr("""
- Surcoût d'encapsulation d'un tunnel 6in4, en octets : @@{surcout:[0-9]+}@@
- MTU à configurer sur `sit1` : @@{mtu_tunnel:[0-9]+}@@
""")
            + instructor(tr("""
**Réponses.** surcoût `{surcout}` octets (l'en-tête IPv4 extérieur) ; MTU de `sit1` : `{mtu_tunnel}`
({n} − {surcout}).
""").format(n=n, **q6_answers)),
            cheat_answers={"final": q6_answers},
        )
        for r in ROUTERS6:
            other = 'r2' if r == 'r1' else 'r1'
            info_r = tun[r]
            self.add_grade_element(
                title=no_tr(f"sit_{r}"), max_grade=2, grade_part=part6,
                grade=int(info_r['kind'] == 'sit' and info_r['local'] == wan_addr[r] and info_r['remote'] == wan_addr[other])
                + int(info_r['mtu'] == tun_mtu),
                description=tr("tunnel sit1 sur {r} : type sit et extrémités IPv4, puis MTU").format(r=r),
            )
        self.add_grade_element(
            title=no_tr("sit_joignable"), max_grade=2, grade_part=part6, grade=2 * int(tunnel_pings >= 1),
            description=tr("ping -6 de r1 vers r2 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("sit_pmtu"), max_grade=2, grade_part=part6, grade=2 * int(fit_ok and over_ok),
            description=tr("le plus grand paquet passe dans le tunnel, un octet de plus est refusé localement"),
        )
        self.add_grade_element(
            title=no_tr("sit_q"), max_grade=2, grade_part=part6,
            grade=int(_is(q6.get("surcout"), TUN_OVERHEAD)) + int(_is(q6.get("mtu_tunnel"), tun_mtu)),
            description=tr("surcoût d'encapsulation 6in4 et MTU du tunnel"),
        )


_TRANSLATIONS = {'en': {
    "IPv6 : adressage, routage statique, SLAAC, DHCPv6, MTU et tunnel 6in4": "IPv6: addressing, static routing, SLAAC, DHCPv6, MTU and 6in4 tunnel",
    """**Sommaire**
""": """**Contents**
""",
    "Pourquoi IPv6": "Why IPv6",
    """

IPv4 numérote les machines sur **32 bits** : 4 milliards d'adresses, une par machine en théorie,
beaucoup moins en pratique à cause du découpage en réseaux. Les derniers blocs libres ont été
attribués en 2011 (IANA) et entre 2012 et 2019 (registres régionaux). Depuis, les adresses IPv4
se rachètent, se partagent (NAT, *carrier-grade NAT* chez les opérateurs) et se bricolent, au prix
de la règle fondatrice d'Internet : **une machine, une adresse, joignable de bout en bout**.

**IPv6** (RFC 2460 en 1998, RFC 8200 en 2017) reprend le modèle d'IPv4 avec des adresses de
**128 bits** : 3,4 × 10³⁸ adresses, assez pour donner un réseau entier à chaque machine. Le
protocole en profite pour simplifier ce qui gênait IPv4 :

| | IPv4 | IPv6 |
|---|---|---|
| adresse | 32 bits, notation décimale pointée | 128 bits, notation hexadécimale |
| en-tête | 20 octets + options, somme de contrôle | 40 octets fixes, pas de somme de contrôle, extensions en chaîne |
| diffusion | *broadcast* | n'existe plus : multidiffusion (*multicast*) |
| résolution des adresses MAC | ARP | découverte de voisins (ICMPv6) |
| configuration automatique | DHCP seulement | annonces de routeur (SLAAC), DHCPv6 |
| fragmentation | par les routeurs | par la source seulement |
| NAT | omniprésent | inutile : adresses publiques pour tous |
| adresses par interface | une, en général | plusieurs, de portées différentes |

IPv6 n'est pas compatible avec IPv4 : une machine IPv6 pure ne parle pas à une machine IPv4 pure.
D'où la **double pile** (*dual stack*), chaque machine ayant les deux adresses et les deux routages,
pendant une transition commencée il y a vingt ans. En 2026, un peu moins de la moitié des accès à
Google se font en IPv6 ; les opérateurs mobiles et les grands hébergeurs l'utilisent en interne, et
de plus en plus de réseaux sont **IPv6 seulement** avec une traduction (NAT64) vers le vieux monde.
""": """

IPv4 numbers the machines on **32 bits**: 4 billion addresses, one per machine in theory, far
fewer in practice because of the division into networks. The last free blocks were allocated in
2011 (IANA) and between 2012 and 2019 (regional registries). Since then, IPv4 addresses are bought
back, shared (NAT, *carrier-grade NAT* at the operators) and patched together, at the cost of the
founding rule of the Internet: **one machine, one address, reachable end to end**.

**IPv6** (RFC 2460 in 1998, RFC 8200 in 2017) takes up the model of IPv4 with **128-bit**
addresses: 3.4 × 10³⁸ addresses, enough to give a whole network to every machine. The protocol
takes the opportunity to simplify what hampered IPv4:

| | IPv4 | IPv6 |
|---|---|---|
| address | 32 bits, dotted decimal notation | 128 bits, hexadecimal notation |
| header | 20 bytes + options, checksum | 40 fixed bytes, no checksum, chained extensions |
| broadcast | yes (*broadcast* addresses) | no longer exists: *multicast* instead |
| resolution of MAC addresses | ARP | neighbour discovery (ICMPv6) |
| automatic configuration | DHCP only | router advertisements (SLAAC), DHCPv6 |
| fragmentation | by the routers | by the source only |
| NAT | everywhere | needless: public addresses for everyone |
| addresses per interface | one, usually | several, of different scopes |

IPv6 is not compatible with IPv4: a pure IPv6 machine does not talk to a pure IPv4 machine.
Hence the **dual stack**, every machine having both addresses and both routing tables, during a
transition that started twenty years ago. In 2026, a little under half of the connections to
Google are made over IPv6; mobile operators and large hosting providers use it internally, and
more and more networks are **IPv6-only** with a translation (NAT64) to the old world.
""",
    "L'écriture des adresses": "Writing addresses",
    """

Une adresse IPv6 s'écrit en **hexadécimal**, en huit groupes de 16 bits séparés par deux-points :

```
2001:0db8:0000:0000:0000:0000:0000:0001
```

Deux règles abrègent l'écriture (RFC 5952 fixe la forme canonique) :

- les **zéros de tête** de chaque groupe sont supprimés : `2001:db8:0:0:0:0:0:1` ;
- **une seule** suite de groupes nuls peut être remplacée par `::` (la plus longue, la première en
  cas d'égalité) : `2001:db8::1`.

`::` seul est l'adresse nulle, `::1` l'adresse de bouclage. Les lettres s'écrivent en minuscules.
Le **préfixe** se note comme en IPv4 : `2001:db8:1::/64` est le réseau, `2001:db8:1::a/64` une
adresse avec la longueur de son préfixe (il n'y a plus de masque écrit en long).

Comme les deux-points servent déjà, une adresse suivie d'un port se met entre **crochets** :
`http://[2001:db8::1]:8080/`, `[2001:db8::1]:22`. Enfin une adresse de lien local (section @@ref:types@@) ne
désigne une machine qu'avec le nom de l'interface par laquelle on la joint, après `%` :
`ping fe80::1%eth0`, `ssh root@fe80::1%eth0`.

Quelques formes rencontrées dans ce TP :

| forme | signification |
|---|---|
| `fd12:3456:789a:1::/64` | un réseau (préfixe de 64 bits) |
| `fd12:3456:789a:1::1/64` | l'adresse `::1` de ce réseau, avec son préfixe |
| `fe80::53:52ff:fe12:3456%eth0` | une adresse de lien local, jointe par `eth0` |
| `ff02::1` | le groupe multicast « tous les nœuds du lien » |
| `::/0` | la route par défaut (`default` dans `ip -6 route`) |
""": """

An IPv6 address is written in **hexadecimal**, as eight groups of 16 bits separated by colons:

```
2001:0db8:0000:0000:0000:0000:0000:0001
```

Two rules shorten it (RFC 5952 sets the canonical form):

- the **leading zeros** of each group are dropped: `2001:db8:0:0:0:0:0:1`;
- **only one** run of zero groups may be replaced by `::` (the longest, the first one in case of
  a tie): `2001:db8::1`.

`::` alone is the null address, `::1` the loopback address. Letters are written in lower case.
The **prefix** is written as in IPv4: `2001:db8:1::/64` is the network, `2001:db8:1::a/64` an
address with the length of its prefix (there is no longer a mask written out in full).

Since the colons are already taken, an address followed by a port goes between **square brackets**:
`http://[2001:db8::1]:8080/`, `[2001:db8::1]:22`. Finally, a link-local address (section @@ref:types@@)
only designates a machine together with the name of the interface through which it is reached,
after `%`: `ping fe80::1%eth0`, `ssh root@fe80::1%eth0`.

A few forms met in this lab:

| form | meaning |
|---|---|
| `fd12:3456:789a:1::/64` | a network (64-bit prefix) |
| `fd12:3456:789a:1::1/64` | the address `::1` of this network, with its prefix |
| `fe80::53:52ff:fe12:3456%eth0` | a link-local address, reached through `eth0` |
| `ff02::1` | the multicast group "all nodes on the link" |
| `::/0` | the default route (`default` in `ip -6 route`) |
""",
    "Les types d'adresses": "Address types",
    """

Les premiers bits d'une adresse disent à quoi elle sert (RFC 4291) :

| préfixe | type | usage |
|---|---|---|
| `2000::/3` | **unicast global** (de `2000::` à `3fff:…`) | les adresses publiques, attribuées par les opérateurs et les registres |
| `fc00::/7`, en pratique `fd00::/8` | **unicast local unique** (ULA, RFC 4193) | adresses privées d'un site, non routées sur Internet : les 40 bits qui suivent `fd` sont tirés au sort pour que deux sites n'aient pas le même préfixe |
| `fe80::/10` | **lien local** (*link-local*) | une adresse par interface, construite sans aucune configuration, valable sur le lien seulement : jamais routée |
| `::1/128` | bouclage | `localhost` |
| `::/128` | non spécifiée | « pas encore d'adresse » (source des premiers messages d'une machine qui démarre) |
| `ff00::/8` | **multicast** | groupes de machines (section suivante) |
| `::ffff:0:0/96` | IPv4 projetée (*IPv4-mapped*) | `::ffff:192.0.2.1` : une adresse IPv4 vue par une socket IPv6 double pile |
| `2001:db8::/32` | documentation | réservée aux exemples (RFC 3849), comme `192.0.2.0/24` en IPv4 |
| `64:ff9b::/96` | NAT64 | préfixe de traduction vers IPv4 (RFC 6052) |

Une interface a **toujours plusieurs adresses** : son adresse de lien local, une ou plusieurs
adresses globales ou ULA, et les adresses des groupes multicast auxquels elle appartient. Le
TP emploie des adresses **ULA** (`fd00::/8`), ce qui ne change rien aux mécanismes.

### @@sec@@ Multicast

Il n'y a plus de diffusion en IPv6 : tout ce qui s'adresse « à tout le monde » passe par un groupe
multicast, et seules les machines inscrites traitent la trame. Le quatrième chiffre hexadécimal de
l'adresse est sa **portée** : `ff01` (interface), `ff02` (**lien**), `ff05` (site), `ff0e` (global).

| groupe | membres |
|---|---|
| `ff02::1` | tous les nœuds du lien (`ping -6 ff02::1%eth0` fait répondre toutes les machines du lien) |
| `ff02::2` | tous les routeurs du lien (destinataire des sollicitations de routeur) |
| `ff02::1:2` | tous les serveurs et relais DHCPv6 du lien |
| `ff02::1:ffxx:xxxx` | **nœud sollicité** (*solicited-node*) : groupe propre à chaque adresse, formé de `ff02::1:ff` et des 24 derniers bits de l'adresse ; sert à la découverte de voisins |
| `ff02::fb`, `ff02::5`, `ff02::9` | mDNS, OSPFv3, RIPng |

Une adresse multicast se transporte dans une trame Ethernet dont l'adresse MAC de destination est
`33:33` suivi des quatre derniers octets de l'adresse IPv6 (`ff02::1` → `33:33:00:00:00:01`).

### @@sec@@ Anycast

Une même adresse peut être portée par plusieurs machines : un paquet est remis à la plus proche.
Chaque préfixe réserve ainsi son adresse `::0` (*subnet-router anycast*, tous les routeurs du
réseau) : c'est pourquoi la première adresse d'un réseau n'est pas donnée à une machine.
""": """

The first bits of an address say what it is for (RFC 4291):

| prefix | type | use |
|---|---|---|
| `2000::/3` | **global unicast** (from `2000::` to `3fff:…`) | the public addresses, allocated by the operators and the registries |
| `fc00::/7`, in practice `fd00::/8` | **unique local unicast** (ULA, RFC 4193) | private addresses of a site, not routed on the Internet: the 40 bits that follow `fd` are drawn at random so that two sites do not get the same prefix |
| `fe80::/10` | **link-local** | one address per interface, built without any configuration, valid on the link only: never routed |
| `::1/128` | loopback | `localhost` |
| `::/128` | unspecified | "no address yet" (source of the first messages of a machine that boots) |
| `ff00::/8` | **multicast** | groups of machines (next section) |
| `::ffff:0:0/96` | IPv4-mapped | `::ffff:192.0.2.1`: an IPv4 address seen by a dual-stack IPv6 socket |
| `2001:db8::/32` | documentation | reserved for examples (RFC 3849), like `192.0.2.0/24` in IPv4 |
| `64:ff9b::/96` | NAT64 | translation prefix towards IPv4 (RFC 6052) |

An interface **always has several addresses**: its link-local address, one or more global or ULA
addresses, and the addresses of the multicast groups it belongs to. The lab uses **ULA**
addresses (`fd00::/8`), which changes nothing in the mechanisms.

### @@sec@@ Multicast

There is no broadcast any more in IPv6: everything addressed to "everybody" goes through a
multicast group, and only the machines that have joined it process the frame. The fourth
hexadecimal digit of the address is its **scope**: `ff01` (interface), `ff02` (**link**), `ff05`
(site), `ff0e` (global).

| group | members |
|---|---|
| `ff02::1` | all the nodes on the link (`ping -6 ff02::1%eth0` makes every machine of the link answer) |
| `ff02::2` | all the routers on the link (destination of the router solicitations) |
| `ff02::1:2` | all the DHCPv6 servers and relays on the link |
| `ff02::1:ffxx:xxxx` | **solicited-node**: a group specific to each address, made of `ff02::1:ff` and the last 24 bits of the address; used by neighbour discovery |
| `ff02::fb`, `ff02::5`, `ff02::9` | mDNS, OSPFv3, RIPng |

A multicast address is carried in an Ethernet frame whose destination MAC address is `33:33`
followed by the last four bytes of the IPv6 address (`ff02::1` → `33:33:00:00:00:01`).

### @@sec@@ Anycast

The same address can be held by several machines: a packet is delivered to the nearest one. Each
prefix thus reserves its address `::0` (*subnet-router anycast*, all the routers of the
network): this is why the first address of a network is not given to a machine.
""",
    "Le plan d'adressage et l'identifiant d'interface": "The addressing plan and the interface identifier",
    """

Une adresse unicast se découpe en un **préfixe de réseau** et un **identifiant d'interface**
(*interface ID*). Sur un réseau où les machines se configurent seules, le préfixe fait **64 bits**
et l'identifiant 64 bits : le `/64` est la taille normale d'un réseau IPv6, même pour deux
machines. Un site reçoit de son opérateur un préfixe plus court, typiquement un **/48** (65 536
réseaux /64) ou un **/56** (256 réseaux) chez les particuliers : il le découpe lui-même, un /64 par
LAN, et l'opérateur ne route que l'**agrégat** (le /48), jamais chaque /64. Les liens entre deux
routeurs peuvent recevoir un `/127` (RFC 6164) ; on leur donne souvent un /64 quand même.

```
fd12:3456:789a:0001:0000:0000:0000:0042
└───────────┬────────┘└─────────┬────────┘
      préfixe /64          identifiant d'interface
└────┬────┘└──┬─┘
 site /48   réseau n° 1 du site
```

### @@sec@@ D'où vient l'identifiant d'interface ?

| méthode | identifiant | où |
|---|---|---|
| **manuel** | choisi par l'administrateur (`::1`, `::53`…) | routeurs, serveurs |
| **EUI-64 modifié** (RFC 4291) | déduit de l'adresse MAC : on insère `ff:fe` au milieu des 6 octets et on inverse le bit *universal/local* (le 2ᵉ bit de poids faible du premier octet) : `02:53:52:aa:bb:cc` → `0053:52ff:feaa:bbcc` | adresses de lien local de Linux, SLAAC par défaut dans un conteneur |
| **stable et opaque** (RFC 7217) | haché à partir du préfixe, de l'interface et d'un secret : stable sur un réseau donné, différent d'un réseau à l'autre, sans révéler l'adresse MAC | SLAAC des systèmes modernes (`addr_gen_mode=2` ou `3` sous Linux) |
| **temporaire** (RFC 8981, *privacy extensions*) | tiré au sort et renouvelé (un jour) : les connexions sortantes ne sont pas traçables | postes clients ; `use_tempaddr` sous Linux |
| **DHCPv6** | choisi par le serveur | section @@ref:dhcpv6@@ |

Dans ce TP, le sysctl `net.ipv6.conf.*.addr_gen_mode` vaut 0 : les identifiants automatiques sont
en **EUI-64**, donc calculables à partir de l'adresse MAC (`ip link show eth0`).
""": """

A unicast address splits into a **network prefix** and an **interface identifier** (*interface
ID*). On a network where the machines configure themselves, the prefix is **64 bits** long and the
identifier 64 bits: the `/64` is the normal size of an IPv6 network, even for two machines. A site
receives a shorter prefix from its operator, typically a **/48** (65,536 /64 networks) or a **/56**
(256 networks) for home users: it divides it itself, one /64 per LAN, and the operator only routes
the **aggregate** (the /48), never each /64. The links between two routers may get a `/127`
(RFC 6164); they are often given a /64 anyway.

```
fd12:3456:789a:0001:0000:0000:0000:0042
└───────────┬────────┘└─────────┬────────┘
      /64 prefix           interface identifier
└────┬────┘└──┬─┘
 site /48   network no. 1 of the site
```

### @@sec@@ Where does the interface identifier come from?

| method | identifier | where |
|---|---|---|
| **manual** | chosen by the administrator (`::1`, `::53`…) | routers, servers |
| **modified EUI-64** (RFC 4291) | derived from the MAC address: `ff:fe` is inserted in the middle of the 6 bytes and the *universal/local* bit (the 2nd least significant bit of the first byte) is inverted: `02:53:52:aa:bb:cc` → `0053:52ff:feaa:bbcc` | Linux link-local addresses, SLAAC by default in a container |
| **stable and opaque** (RFC 7217) | hashed from the prefix, the interface and a secret: stable on a given network, different from one network to another, without revealing the MAC address | SLAAC of modern systems (`addr_gen_mode=2` or `3` under Linux) |
| **temporary** (RFC 8981, *privacy extensions*) | drawn at random and renewed (one day): outgoing connections cannot be tracked | client hosts; `use_tempaddr` under Linux |
| **DHCPv6** | chosen by the server | section @@ref:dhcpv6@@ |

In this lab, the sysctl `net.ipv6.conf.*.addr_gen_mode` is 0: the automatic identifiers are
**EUI-64**, hence computable from the MAC address (`ip link show eth0`).
""",
    "L'en-tête IPv6 et les en-têtes d'extension": "The IPv6 header and the extension headers",
    """

L'en-tête fait **40 octets, toujours** : pas d'options, pas de somme de contrôle (celles de TCP,
UDP et ICMPv6 couvrent l'adresse), pas de champs de fragmentation.

| champ | bits | rôle |
|---|---|---|
| version | 4 | 6 |
| classe de trafic | 8 | qualité de service (l'équivalent du TOS / DSCP) |
| étiquette de flux | 20 | identifie un flux pour un traitement homogène (peu utilisé) |
| longueur de la charge utile | 16 | ce qui suit l'en-tête, extensions comprises |
| **en-tête suivant** (*next header*) | 8 | protocole de ce qui suit : 6 TCP, 17 UDP, **58 ICMPv6**, ou un en-tête d'extension |
| limite de sauts (*hop limit*) | 8 | le TTL : décrémenté par chaque routeur, le paquet est jeté à 0 |
| adresse source, adresse destination | 128 + 128 | |

Tout ce qui était optionnel en IPv4 passe dans des **en-têtes d'extension**, chaînés par le champ
*next header* entre l'en-tête IPv6 et le transport, et traités seulement par le destinataire (sauf
*hop-by-hop*) :

| extension | *next header* | rôle |
|---|---|---|
| *hop-by-hop options* | 0 | examinée par chaque routeur (alertes, jumbogrammes) |
| *routing* | 43 | routage par la source, segment routing |
| **fragment** | **44** | fragmentation par la source (section @@ref:mtu@@) |
| ESP, AH | 50, 51 | IPsec |
| *destination options* | 60 | options pour le destinataire |

`tcpdump -n -v -i eth0 ip6` montre `flowlabel`, `hlim` et `next-header`. Un routeur IPv6 ne
recalcule aucune somme de contrôle et ne fragmente jamais : il ne fait que décrémenter *hop limit*
et transmettre.
""": """

The header is **40 bytes, always**: no options, no checksum (those of TCP, UDP and ICMPv6 cover
the address), no fragmentation fields.

| field | bits | role |
|---|---|---|
| version | 4 | 6 |
| traffic class | 8 | quality of service (the equivalent of TOS / DSCP) |
| flow label | 20 | identifies a flow for uniform handling (little used) |
| payload length | 16 | what follows the header, extensions included |
| **next header** | 8 | protocol of what follows: 6 TCP, 17 UDP, **58 ICMPv6**, or an extension header |
| hop limit | 8 | the TTL: decremented by each router, the packet is dropped at 0 |
| source address, destination address | 128 + 128 | |

Everything that was optional in IPv4 moves into **extension headers**, chained by the *next
header* field between the IPv6 header and the transport, and processed only by the destination
(except *hop-by-hop*):

| extension | *next header* | role |
|---|---|---|
| *hop-by-hop options* | 0 | examined by every router (alerts, jumbograms) |
| *routing* | 43 | source routing, segment routing |
| **fragment** | **44** | fragmentation by the source (section @@ref:mtu@@) |
| ESP, AH | 50, 51 | IPsec |
| *destination options* | 60 | options for the destination |

`tcpdump -n -v -i eth0 ip6` shows `flowlabel`, `hlim` and `next-header`. An IPv6 router
recomputes no checksum and never fragments: it only decrements *hop limit* and forwards.
""",
    "ICMPv6": "ICMPv6",
    """

ICMPv6 (RFC 4443, *next header* 58) fait beaucoup plus que signaler des erreurs : il porte la
**découverte de voisins** (section @@ref:ndp@@), les **annonces de routeur** (section @@ref:slaac@@) et la gestion des
groupes multicast (MLD). Le filtrer en bloc casse IPv6.

| type | nom | rôle |
|---|---|---|
| 1 | *destination unreachable* | code 0 pas de route, 1 interdit, 3 adresse injoignable, 4 port injoignable |
| 2 | **packet too big** | le paquet dépasse le MTU du lien suivant (section @@ref:mtu@@) ; il porte ce MTU |
| 3 | *time exceeded* | *hop limit* tombé à 0 (`traceroute`) |
| 4 | *parameter problem* | en-tête incompréhensible |
| 128, 129 | *echo request*, *echo reply* | `ping` |
| 130, 131, 132, 143 | MLD (*multicast listener*) | inscription aux groupes multicast |
| **133** | **router solicitation** (RS) | « y a-t-il un routeur ? » (vers `ff02::2`) |
| **134** | **router advertisement** (RA) | les routeurs se présentent et annoncent les préfixes (vers `ff02::1` ou en réponse à un RS) |
| **135** | **neighbor solicitation** (NS) | « qui a cette adresse ? » (l'ARP *request*), vers le groupe du nœud sollicité ; détection d'adresse dupliquée |
| **136** | **neighbor advertisement** (NA) | « c'est moi, voici mon adresse MAC » (l'ARP *reply*) |
| 137 | *redirect* | un routeur indique un meilleur premier saut sur le lien |

Les messages de découverte de voisins voyagent avec un *hop limit* de **255** : un message qui
arrive avec moins a traversé un routeur et est ignoré (ils ne quittent jamais le lien).
`tcpdump -n -v -i eth0 icmp6` les affiche tous ; `icmp6 and ip6[40] == 134` ne garde que les RA
(le type est le premier octet après les 40 de l'en-tête).
""": """

ICMPv6 (RFC 4443, *next header* 58) does much more than report errors: it carries
**neighbour discovery** (section @@ref:ndp@@), **router advertisements** (section @@ref:slaac@@) and the management of
multicast groups (MLD). Filtering it wholesale breaks IPv6.

| type | name | role |
|---|---|---|
| 1 | *destination unreachable* | code 0 no route, 1 prohibited, 3 address unreachable, 4 port unreachable |
| 2 | **packet too big** | the packet exceeds the MTU of the next link (section @@ref:mtu@@); it carries that MTU |
| 3 | *time exceeded* | *hop limit* down to 0 (`traceroute`) |
| 4 | *parameter problem* | header not understood |
| 128, 129 | *echo request*, *echo reply* | `ping` |
| 130, 131, 132, 143 | MLD (*multicast listener*) | joining multicast groups |
| **133** | **router solicitation** (RS) | "is there a router?" (to `ff02::2`) |
| **134** | **router advertisement** (RA) | the routers introduce themselves and advertise the prefixes (to `ff02::1` or in reply to an RS) |
| **135** | **neighbor solicitation** (NS) | "who has this address?" (the ARP *request*), to the solicited-node group; duplicate address detection |
| **136** | **neighbor advertisement** (NA) | "it's me, here is my MAC address" (the ARP *reply*) |
| 137 | *redirect* | a router points out a better first hop on the link |

Neighbour discovery messages travel with a *hop limit* of **255**: a message that arrives with
less has crossed a router and is ignored (they never leave the link).
`tcpdump -n -v -i eth0 icmp6` shows them all; `icmp6 and ip6[40] == 134` keeps only the RAs
(the type is the first byte after the 40 of the header).
""",
    "La découverte de voisins (NDP)": "Neighbour discovery (NDP)",
    """

Le protocole de découverte de voisins (*Neighbor Discovery*, RFC 4861) remplace ARP et une partie
de DHCP. Pour envoyer un paquet à une adresse du lien, une machine doit connaître l'adresse MAC
correspondante :

```
   m1                                                    r1
    |--- NS, de m1 vers ff02::1:ff00:1 (nœud sollicité) --->|   "qui a fd…::1 ?"  option : MAC de m1
    |<-- NA, de fd…::1 vers m1 ------------------------------|   "moi, MAC 02:53:52:…"  drapeau S (sollicité)
```

- le **NS** part vers le groupe du nœud sollicité de l'adresse cherchée (`ff02::1:ff` + ses 24
  derniers bits, trame `33:33:ff:xx:xx:xx`) : seules les machines dont l'adresse se termine ainsi
  le reçoivent, au lieu de toutes comme avec ARP ;
- le **NA** répond en unicast, avec l'adresse MAC dans une option ; le drapeau *override* (O) force
  la mise à jour du cache, le drapeau *router* (R) dit si l'émetteur est un routeur.

### @@sec@@ Le cache de voisins

`ip -6 neigh` montre les correspondances adresse → MAC et leur état (`REACHABLE`, `STALE` : à
reconfirmer au prochain envoi, `DELAY`, `PROBE`, `FAILED`). Une entrée `STALE` est réutilisée tout
de suite et vérifiée en arrière-plan : la découverte de voisins vérifie en permanence que le voisin
répond encore (*Neighbor Unreachability Detection*), ce qu'ARP ne faisait pas.

### @@sec@@ La détection d'adresse dupliquée (DAD)

Avant d'utiliser une adresse (manuelle, automatique ou de lien local), une machine envoie un **NS**
pour sa propre adresse, avec l'adresse source **non spécifiée** `::`. Si un NA revient, l'adresse est
déjà prise : elle est marquée `dadfailed` et n'est pas utilisée. Pendant la vérification (une
seconde), `ip -6 addr` la montre `tentative`. C'est pourquoi une adresse tout juste ajoutée ne
répond pas immédiatement.

### @@sec@@ La redirection

Quand un routeur reçoit un paquet qu'il renvoie sur le lien d'où il vient, il envoie à la source un
*redirect* (type 137) : « pour cette destination, passe plutôt par ce voisin ». Les hôtes mettent à
jour leur cache de destinations (`ip -6 route get`).
""": """

The neighbour discovery protocol (*Neighbor Discovery*, RFC 4861) replaces ARP and part of DHCP.
To send a packet to an address on the link, a machine must know the corresponding MAC address:

```
   m1                                                    r1
    |--- NS, from m1 to ff02::1:ff00:1 (solicited node) --->|   "who has fd…::1?"  option: MAC of m1
    |<-- NA, from fd…::1 to m1 ------------------------------|   "me, MAC 02:53:52:…"  flag S (solicited)
```

- the **NS** goes to the solicited-node group of the address sought (`ff02::1:ff` + its last 24
  bits, frame `33:33:ff:xx:xx:xx`): only the machines whose address ends that way receive it,
  instead of all of them as with ARP;
- the **NA** replies in unicast, with the MAC address in an option; the *override* (O) flag forces
  the update of the cache, the *router* (R) flag says whether the sender is a router.

### @@sec@@ The neighbour cache

`ip -6 neigh` shows the address → MAC mappings and their state (`REACHABLE`, `STALE`: to be
confirmed again at the next sending, `DELAY`, `PROBE`, `FAILED`). A `STALE` entry is reused
straight away and checked in the background: neighbour discovery constantly checks that the
neighbour still answers (*Neighbor Unreachability Detection*), which ARP did not do.

### @@sec@@ Duplicate address detection (DAD)

Before using an address (manual, automatic or link-local), a machine sends an **NS** for its own
address, with the **unspecified** source address `::`. If an NA comes back, the address is already
taken: it is marked `dadfailed` and is not used. During the check (one second), `ip -6 addr` shows
it `tentative`. This is why an address that has just been added does not answer immediately.

### @@sec@@ Redirection

When a router receives a packet that it sends back onto the link it came from, it sends the source a
*redirect* (type 137): "for this destination, go through this neighbour instead". The hosts update
their destination cache (`ip -6 route get`).
""",
    "Les routeurs et leurs annonces : SLAAC": "Routers and their advertisements: SLAAC",
    """

En IPv6 ce sont les **routeurs** qui renseignent les machines sur leur réseau, par des **annonces de
routeur** (RA, ICMPv6 type 134) envoyées périodiquement à `ff02::1` (toutes les quelques minutes) et
en réponse aux **sollicitations** (RS, type 133, vers `ff02::2`) d'une machine qui démarre. Une
annonce contient :

| champ ou option | rôle |
|---|---|
| **durée de vie du routeur** (*router lifetime*) | > 0 : l'émetteur est un **routeur par défaut** pour cette durée ; 0 : il annonce des préfixes mais pas de route par défaut |
| drapeau **M** (*managed*) | « obtenez vos adresses par DHCPv6 » |
| drapeau **O** (*other*) | « obtenez les autres paramètres (DNS…) par DHCPv6 » |
| option **préfixe** (*prefix information*) | un préfixe du lien, avec ses durées de vie et deux drapeaux : **L** (*on-link* : les adresses de ce préfixe sont directement joignables sur le lien) et **A** (*autonomous* : les machines peuvent s'en fabriquer une adresse) |
| option **MTU** | le MTU du lien |
| option **RDNSS** (RFC 8106) | adresses de serveurs DNS récursifs |
| option **DNSSL** | domaines de recherche |
| option *source link-layer address* | l'adresse MAC du routeur (entrée du cache de voisins) |
| *cur hop limit*, *reachable time*, *retrans timer* | paramètres de la pile |

### @@sec@@ L'autoconfiguration sans état (SLAAC, RFC 4862)

Une machine qui démarre :

1. se fabrique son adresse de **lien local** (`fe80::` + identifiant d'interface) et la vérifie (DAD) ;
2. envoie un **RS** et reçoit les **RA** ;
3. pour chaque préfixe annoncé avec le drapeau **A**, forme une adresse **préfixe + identifiant
   d'interface** (EUI-64 ou autre, section @@ref:addressing@@), la vérifie (DAD), et l'utilise avec les durées de
   vie annoncées (`valid_lft`, `preferred_lft` dans `ip -6 addr`, qui décroissent entre deux annonces) ;
4. installe une **route par défaut** vers l'adresse **de lien local** du routeur (`default via
   fe80::… dev eth0 proto ra expires …`) pour la durée de vie du routeur ;
5. selon M et O, interroge un serveur DHCPv6 (section @@ref:dhcpv6@@).

Aucun serveur, aucun état : chaque machine se débrouille avec ce que le routeur annonce. Le prix :
le routeur ne sait pas qui a quelle adresse, et la machine n'obtient ses serveurs DNS que si le
routeur les annonce (RDNSS) **et** si son système sait lire cette option (sous Linux : `rdnssd`,
NetworkManager, systemd-networkd ; pas le noyau seul).

### @@sec@@ Côté Linux

| sysctl `net.ipv6.conf.<iface>.` | rôle |
|---|---|
| `forwarding` | 1 : la machine route (et, par défaut, **ignore** les annonces de routeur) |
| `accept_ra` | 0 : ignorer les RA ; 1 : les accepter si `forwarding` = 0 ; **2** : les accepter même en routant |
| `autoconf` | 1 : former une adresse pour chaque préfixe avec A (0 : garder seulement la route par défaut) |
| `addr_gen_mode` | 0 : identifiant EUI-64 ; 2, 3 : identifiant stable (RFC 7217) |
| `use_tempaddr` | 2 : adresses temporaires préférées pour sortir |

`sysctl net.ipv6.conf.all.forwarding=1` propage la valeur à toutes les interfaces ; `all.accept_ra`
ne la propage pas, il faut la régler par interface. Dans ce TP les machines à configuration statique
ont `accept_ra=0` : elles ignorent les annonces ; `pc1` (`accept_ra=2`, `autoconf=1`) et `pc2`
(`accept_ra=2`, `autoconf=0` : route par défaut, pas d'adresse automatique) les écoutent.

### @@sec@@ Le démon radvd

Un routeur Linux annonce ses préfixes avec **radvd** (`/etc/radvd.conf`) :

```
interface eth2
{
    AdvSendAdvert on;                   # émettre des annonces sur cette interface
    MinRtrAdvInterval 3;                # intervalle entre deux annonces (3 à 10 s ici ;
    MaxRtrAdvInterval 10;               #   200 à 600 s par défaut)
    AdvManagedFlag off;                 # drapeau M (adresses par DHCPv6)
    AdvOtherConfigFlag off;             # drapeau O (autres paramètres par DHCPv6)
    prefix 2001:db8:1::/64
    {
        AdvOnLink on;                   # drapeau L
        AdvAutonomous on;               # drapeau A : SLAAC
    };
    RDNSS 2001:db8:1::53 { };           # serveurs DNS
    DNSSL example.org { };              # domaines de recherche
};
```

```
radvd -c                               # vérifie la syntaxe
systemctl restart radvd                # relancer après CHAQUE modification
pidof radvd                            # tourne-t-il ?
```

radvd exige que le routage IPv6 soit actif (`net.ipv6.conf.all.forwarding=1`). Pour vérifier ce
qu'il annonce : `tcpdump -n -v -i eth2 'icmp6 and ip6[40] == 134'` sur le routeur, ou sur un hôte
`ip -6 addr` / `ip -6 route` quelques secondes plus tard.
""": """

In IPv6 it is the **routers** that tell the machines about their network, through **router
advertisements** (RA, ICMPv6 type 134) sent periodically to `ff02::1` (every few minutes) and in
reply to the **solicitations** (RS, type 133, to `ff02::2`) of a machine that boots. An
advertisement contains:

| field or option | role |
|---|---|
| **router lifetime** | > 0: the sender is a **default router** for this duration; 0: it advertises prefixes but no default route |
| **M** flag (*managed*) | "get your addresses through DHCPv6" |
| **O** flag (*other*) | "get the other parameters (DNS…) through DHCPv6" |
| **prefix** option (*prefix information*) | a prefix of the link, with its lifetimes and two flags: **L** (*on-link*: the addresses of this prefix are directly reachable on the link) and **A** (*autonomous*: the machines may build themselves an address from it) |
| **MTU** option | the MTU of the link |
| **RDNSS** option (RFC 8106) | addresses of recursive DNS servers |
| **DNSSL** option | search domains |
| *source link-layer address* option | the MAC address of the router (neighbour cache entry) |
| *cur hop limit*, *reachable time*, *retrans timer* | parameters of the stack |

### @@sec@@ Stateless address autoconfiguration (SLAAC, RFC 4862)

A machine that boots:

1. builds its **link-local** address (`fe80::` + interface identifier) and checks it (DAD);
2. sends an **RS** and receives the **RAs**;
3. for each prefix advertised with the **A** flag, forms an address **prefix + interface
   identifier** (EUI-64 or other, section @@ref:addressing@@), checks it (DAD), and uses it with the advertised
   lifetimes (`valid_lft`, `preferred_lft` in `ip -6 addr`, which decrease between two advertisements);
4. installs a **default route** to the **link-local** address of the router (`default via
   fe80::… dev eth0 proto ra expires …`) for the router lifetime;
5. depending on M and O, queries a DHCPv6 server (section @@ref:dhcpv6@@).

No server, no state: each machine manages with what the router advertises. The price: the router
does not know who has which address, and the machine only gets its DNS servers if the router
advertises them (RDNSS) **and** if its system can read that option (under Linux: `rdnssd`,
NetworkManager, systemd-networkd; not the kernel alone).

### @@sec@@ On the Linux side

| sysctl `net.ipv6.conf.<iface>.` | role |
|---|---|
| `forwarding` | 1: the machine routes (and, by default, **ignores** router advertisements) |
| `accept_ra` | 0: ignore RAs; 1: accept them if `forwarding` = 0; **2**: accept them even when routing |
| `autoconf` | 1: form an address for each prefix with A (0: keep only the default route) |
| `addr_gen_mode` | 0: EUI-64 identifier; 2, 3: stable identifier (RFC 7217) |
| `use_tempaddr` | 2: temporary addresses preferred for outgoing traffic |

`sysctl net.ipv6.conf.all.forwarding=1` propagates the value to every interface; `all.accept_ra`
does not propagate it, it must be set per interface. In this lab the machines with a static
configuration have `accept_ra=0`: they ignore the advertisements; `pc1` (`accept_ra=2`, `autoconf=1`)
and `pc2` (`accept_ra=2`, `autoconf=0`: default route, no automatic address) listen to them.

### @@sec@@ The radvd daemon

A Linux router advertises its prefixes with **radvd** (`/etc/radvd.conf`):

```
interface eth2
{
    AdvSendAdvert on;                   # send advertisements on this interface
    MinRtrAdvInterval 3;                # interval between two advertisements (3 to 10 s here;
    MaxRtrAdvInterval 10;               #   200 to 600 s by default)
    AdvManagedFlag off;                 # M flag (addresses through DHCPv6)
    AdvOtherConfigFlag off;             # O flag (other parameters through DHCPv6)
    prefix 2001:db8:1::/64
    {
        AdvOnLink on;                   # L flag
        AdvAutonomous on;               # A flag: SLAAC
    };
    RDNSS 2001:db8:1::53 { };           # DNS servers
    DNSSL example.org { };              # search domains
};
```

```
radvd -c                               # checks the syntax
systemctl restart radvd                # restart after EACH change
pidof radvd                            # is it running?
```

radvd requires IPv6 routing to be on (`net.ipv6.conf.all.forwarding=1`). To check what it
advertises: `tcpdump -n -v -i eth2 'icmp6 and ip6[40] == 134'` on the router, or on a host
`ip -6 addr` / `ip -6 route` a few seconds later.
""",
    "DHCPv6": "DHCPv6",
    """

**DHCPv6** (RFC 8415) est un protocole distinct de DHCP, qui ne partage avec lui ni le format ni les
ports. Il complète SLAAC dans deux situations :

- **sans état** (*stateless*, drapeau **O** du RA) : la machine a formé son adresse par SLAAC et
  ne demande que les **autres paramètres** (serveurs DNS, domaines de recherche, NTP…) ;
- **avec état** (*stateful*, drapeau **M**) : le serveur **attribue aussi les adresses**, en garde
  le registre (baux) et permet des réservations, comme DHCP en IPv4.

Dans les deux cas **la route par défaut vient du RA**, jamais de DHCPv6 : un réseau DHCPv6 a besoin
d'un routeur qui s'annonce (avec les drapeaux M ou O, et un préfixe sans le drapeau A si l'on veut
que les adresses viennent du serveur seul).

### @@sec@@ Transport et messages

| | DHCP (IPv4) | DHCPv6 |
|---|---|---|
| port serveur / client | UDP 67 / 68 | UDP **547** / **546** |
| destination des demandes | diffusion `255.255.255.255` | multicast **`ff02::1:2`** (tous les serveurs et relais du lien) |
| identité du client | adresse MAC (`chaddr`) | **DUID** (*DHCP Unique Identifier*) + IAID |
| obtention d'une adresse | DISCOVER, OFFER, REQUEST, ACK | **SOLICIT** (1), **ADVERTISE** (2), **REQUEST** (3), **REPLY** (7) |
| paramètres seuls | DHCPINFORM | **INFORMATION-REQUEST** (11) → REPLY |
| renouvellement | REQUEST unicast | RENEW (5) à T1, REBIND (6) à T2 |
| libération, refus | DHCPRELEASE, DHCPDECLINE | RELEASE (8), DECLINE (9) |
| redémarrage | REQUEST | CONFIRM (4) |
| relais | `giaddr` | RELAY-FORW (12) / RELAY-REPL (13), le message du client encapsulé |

`ADVERTISE` propose, sans engager le serveur ; le client en choisit un (option *preference*) et
confirme par `REQUEST` ; `REPLY` accorde le bail. L'option *rapid commit* réduit l'échange à
SOLICIT / REPLY.

### @@sec@@ Le DUID

Chaque client et chaque serveur a un identifiant **stable**, choisi une fois pour toutes et
indépendant de l'interface :

| type | forme | exemple |
|---|---|---|
| 1, **DUID-LLT** | adresse MAC + date de création | `00:01:00:01:2e:4f:…:02:53:52:aa:bb:cc` (le choix par défaut de `dhclient`) |
| 2, DUID-EN | numéro d'entreprise + identifiant | |
| 3, **DUID-LL** | type de lien (`00:01` Ethernet) + adresse MAC | `00:03:00:01:02:53:52:aa:bb:cc` : prévisible à partir de la MAC |
| 4, DUID-UUID | UUID de la machine | |

Un client peut demander plusieurs adresses, regroupées en **associations d'identité** : IA_NA
(adresses normales, option 3), IA_TA (temporaires), IA_PD (**délégation de préfixe**, option 25 :
le serveur délègue un préfixe entier, par exemple le /56 d'un abonné à sa *box*). Chaque IA a un
IAID choisi par le client. Une réservation se fait donc sur le **DUID** (et éventuellement l'IAID), pas
sur l'adresse MAC.

### @@sec@@ Les options

| code | option (nom ISC) | contenu |
|---|---|---|
| 1, 2 | `dhcp6.client-id`, `dhcp6.server-id` | DUID du client, du serveur |
| 3 | IA_NA | association d'adresses : IAID, T1, T2, et les adresses (option 5 **IA_ADDR** : adresse, durée préférée, durée de validité) |
| 6 | ORO (*option request*) | options demandées par le client |
| 7 | *preference* | préférence du serveur (0 à 255) |
| 8 | *elapsed time* | temps écoulé depuis le début de la recherche |
| 13 | *status code* | 0 succès, 2 `NoAddrsAvail`, 4 `NotOnLink`… |
| 14 | *rapid commit* | échange en deux messages |
| 23 | `dhcp6.name-servers` | serveurs DNS |
| 24 | `dhcp6.domain-search` | domaines de recherche |
| 25, 26 | IA_PD, IA_PREFIX | délégation de préfixe |
| 32 | *information refresh time* | pour les clients sans état |

Les adresses n'ont pas une « durée de bail » mais deux durées, comme en SLAAC : **préférée**
(*preferred lifetime*, après quoi l'adresse n'est plus utilisée pour de nouvelles connexions) et
**valide** (*valid lifetime*, après quoi elle est retirée). T1 et T2 sont les instants des
renouvellements.

### @@sec@@ Le serveur ISC : dhcpd -6

Le même programme que pour IPv4, lancé avec `-6`, avec sa propre configuration et son propre
registre :

| fichier | rôle |
|---|---|
| `/etc/default/isc-dhcp-server` | `INTERFACESv6="eth0"` : interface d'écoute du serveur IPv6 ; `INTERFACESv4=""` pour ne pas lancer le serveur IPv4 (les deux vides : le service lance les deux sur toutes les interfaces) |
| `/etc/dhcp/dhcpd6.conf` | configuration |
| `/var/lib/dhcp/dhcpd6.leases` | baux accordés |

```
default-lease-time 600;                    # durée de validité des adresses (secondes)
preferred-lifetime 375;                    # durée préférée (facultatif)
option dhcp6.name-servers 2001:db8:1::53;  # options globales
option dhcp6.domain-search "example.org";

subnet6 2001:db8:1::/64 {                  # le réseau de l'interface d'écoute (obligatoire,
    range6 2001:db8:1::1000 2001:db8:1::1fff;   #   même sans adresse à distribuer)
}

host portable {                            # réservation, par le DUID du client
    host-identifier option dhcp6.client-id 00:03:00:01:02:53:52:aa:bb:cc;
    fixed-address6 2001:db8:1::42;
}
```

- sans `range6`, le serveur ne distribue aucune adresse : il ne répond qu'aux INFORMATION-REQUEST
  (mode sans état) ;
- `subnet6` doit couvrir une adresse **globale** de l'interface d'écoute : le serveur doit avoir
  son adresse IPv6 avant de démarrer ;
- une adresse réservée se choisit hors de `range6`.

```
dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf     # vérifie la syntaxe
systemctl restart isc-dhcp-server         # un seul service pour les deux familles : il lance dhcpd -4
                                          #   et/ou dhcpd -6 selon INTERFACESv4 / INTERFACESv6
                                          #   ("Launching IPv6 server only." dans le journal)
journalctl -u isc-dhcp-server -f          # journal : "Solicit message from fe80::… port 546",
                                          #   "Advertise NA: address … to client with duid …"
ps -C dhcpd -o pid,args                   # le processus et ses arguments (-6, interface)
```

### @@sec@@ Le client ISC : dhclient -6

```
dhclient -6 -S -v eth0          # sans état : INFORMATION-REQUEST, ne demande pas d'adresse
dhclient -6 -D LL -v eth0       # avec état : demande une adresse, DUID-LL (prévisible)
dhclient -6 -D LL -r eth0       # libère l'adresse (RELEASE) et arrête le client
```

| fichier | rôle |
|---|---|
| `/var/lib/dhcp/dhclient6.leases` | le DUID du client (`default-duid`) et ses baux (`lease6 { … }`) |
| `/etc/resolv.conf` | réécrit par `dhclient-script` avec `dhcp6.name-servers` et `dhcp6.domain-search` |

Le DUID est **conservé** dans le fichier de baux : une fois choisi (LLT par défaut), `-D LL` n'y
change plus rien. Pour changer de type, libérez le bail, arrêtez le client et supprimez le fichier.
L'adresse obtenue est posée avec un préfixe `/128` et les durées du bail (`ip -6 addr` :
`dynamic`, `valid_lft`) ; le préfixe du lien, lui, vient de l'annonce de routeur (drapeau L).

Dans une capture : `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` montre les messages, leur
identifiant de transaction et leurs options.
""": """

**DHCPv6** (RFC 8415) is a protocol distinct from DHCP, which shares neither its format nor its
ports with it. It complements SLAAC in two situations:

- **stateless** (**O** flag of the RA): the machine has formed its address through SLAAC and only
  asks for the **other parameters** (DNS servers, search domains, NTP…);
- **stateful** (**M** flag): the server **also assigns the addresses**, keeps a record of them
  (leases) and allows reservations, like DHCP in IPv4.

In both cases **the default route comes from the RA**, never from DHCPv6: a DHCPv6 network needs a
router that advertises itself (with the M or O flags, and a prefix without the A flag if the
addresses are to come from the server alone).

### @@sec@@ Transport and messages

| | DHCP (IPv4) | DHCPv6 |
|---|---|---|
| server / client port | UDP 67 / 68 | UDP **547** / **546** |
| destination of the requests | broadcast `255.255.255.255` | multicast **`ff02::1:2`** (all the servers and relays on the link) |
| identity of the client | MAC address (`chaddr`) | **DUID** (*DHCP Unique Identifier*) + IAID |
| obtaining an address | DISCOVER, OFFER, REQUEST, ACK | **SOLICIT** (1), **ADVERTISE** (2), **REQUEST** (3), **REPLY** (7) |
| parameters only | DHCPINFORM | **INFORMATION-REQUEST** (11) → REPLY |
| renewal | unicast REQUEST | RENEW (5) at T1, REBIND (6) at T2 |
| release, decline | DHCPRELEASE, DHCPDECLINE | RELEASE (8), DECLINE (9) |
| reboot | REQUEST | CONFIRM (4) |
| relay | `giaddr` | RELAY-FORW (12) / RELAY-REPL (13), the client's message encapsulated |

`ADVERTISE` offers, without committing the server; the client picks one (*preference* option) and
confirms with `REQUEST`; `REPLY` grants the lease. The *rapid commit* option cuts the exchange down
to SOLICIT / REPLY.

### @@sec@@ The DUID

Each client and each server has a **stable** identifier, chosen once and for all and independent
of the interface:

| type | form | example |
|---|---|---|
| 1, **DUID-LLT** | MAC address + creation time | `00:01:00:01:2e:4f:…:02:53:52:aa:bb:cc` (the default choice of `dhclient`) |
| 2, DUID-EN | enterprise number + identifier | |
| 3, **DUID-LL** | link type (`00:01` Ethernet) + MAC address | `00:03:00:01:02:53:52:aa:bb:cc`: predictable from the MAC |
| 4, DUID-UUID | UUID of the machine | |

A client may ask for several addresses, grouped into **identity associations**: IA_NA (normal
addresses, option 3), IA_TA (temporary), IA_PD (**prefix delegation**, option 25: the server
delegates a whole prefix, for example the /56 of a subscriber to their home router). Each IA has
an IAID chosen by the client. A reservation is therefore made on the **DUID** (and possibly the
IAID), not on the MAC address.

### @@sec@@ The options

| code | option (ISC name) | content |
|---|---|---|
| 1, 2 | `dhcp6.client-id`, `dhcp6.server-id` | DUID of the client, of the server |
| 3 | IA_NA | address association: IAID, T1, T2, and the addresses (option 5 **IA_ADDR**: address, preferred lifetime, valid lifetime) |
| 6 | ORO (*option request*) | options requested by the client |
| 7 | *preference* | preference of the server (0 to 255) |
| 8 | *elapsed time* | time elapsed since the start of the search |
| 13 | *status code* | 0 success, 2 `NoAddrsAvail`, 4 `NotOnLink`… |
| 14 | *rapid commit* | two-message exchange |
| 23 | `dhcp6.name-servers` | DNS servers |
| 24 | `dhcp6.domain-search` | search domains |
| 25, 26 | IA_PD, IA_PREFIX | prefix delegation |
| 32 | *information refresh time* | for stateless clients |

The addresses do not have a "lease time" but two lifetimes, as in SLAAC: **preferred** (*preferred
lifetime*, after which the address is no longer used for new connections) and **valid** (*valid
lifetime*, after which it is removed). T1 and T2 are the times of the renewals.

### @@sec@@ The ISC server: dhcpd -6

The same program as for IPv4, started with `-6`, with its own configuration and its own lease
file:

| file | role |
|---|---|
| `/etc/default/isc-dhcp-server` | `INTERFACESv6="eth0"`: listening interface of the IPv6 server; `INTERFACESv4=""` so as not to start the IPv4 server (both empty: the service starts both on every interface) |
| `/etc/dhcp/dhcpd6.conf` | configuration |
| `/var/lib/dhcp/dhcpd6.leases` | leases granted |

```
default-lease-time 600;                    # valid lifetime of the addresses (seconds)
preferred-lifetime 375;                    # preferred lifetime (optional)
option dhcp6.name-servers 2001:db8:1::53;  # global options
option dhcp6.domain-search "example.org";

subnet6 2001:db8:1::/64 {                  # the network of the listening interface (mandatory,
    range6 2001:db8:1::1000 2001:db8:1::1fff;   #   even with no address to hand out)
}

host portable {                            # reservation, by the DUID of the client
    host-identifier option dhcp6.client-id 00:03:00:01:02:53:52:aa:bb:cc;
    fixed-address6 2001:db8:1::42;
}
```

- without `range6`, the server hands out no address: it only answers the INFORMATION-REQUESTs
  (stateless mode);
- `subnet6` must cover a **global** address of the listening interface: the server must have
  its IPv6 address before it starts;
- a reserved address is chosen outside `range6`.

```
dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf     # checks the syntax
systemctl restart isc-dhcp-server         # a single service for both families: it starts dhcpd -4
                                          #   and/or dhcpd -6 according to INTERFACESv4 / INTERFACESv6
                                          #   ("Launching IPv6 server only." in the journal)
journalctl -u isc-dhcp-server -f          # journal: "Solicit message from fe80::… port 546",
                                          #   "Advertise NA: address … to client with duid …"
ps -C dhcpd -o pid,args                   # the process and its arguments (-6, interface)
```

### @@sec@@ The ISC client: dhclient -6

```
dhclient -6 -S -v eth0          # stateless: INFORMATION-REQUEST, does not ask for an address
dhclient -6 -D LL -v eth0       # stateful: asks for an address, DUID-LL (predictable)
dhclient -6 -D LL -r eth0       # releases the address (RELEASE) and stops the client
```

| file | role |
|---|---|
| `/var/lib/dhcp/dhclient6.leases` | the DUID of the client (`default-duid`) and its leases (`lease6 { … }`) |
| `/etc/resolv.conf` | rewritten by `dhclient-script` with `dhcp6.name-servers` and `dhcp6.domain-search` |

The DUID is **kept** in the lease file: once chosen (LLT by default), `-D LL` no longer changes
anything. To change its type, release the lease, stop the client and delete the file. The address
obtained is set with a `/128` prefix and the lifetimes of the lease (`ip -6 addr`: `dynamic`,
`valid_lft`); the prefix of the link, for its part, comes from the router advertisement (L flag).

In a capture: `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` shows the messages, their
transaction identifier and their options.
""",
    "Le routage statique": "Static routing",
    """

Le routage IPv6 est le routage IPv4 avec une table de plus (`ip -6 route`) : une route par
préfixe, la plus longue qui correspond l'emporte, `::/0` est la route par défaut.

```
ip -6 addr add 2001:db8:1::1/64 dev eth0            # une adresse (DAD : une seconde avant usage)
ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254  # une route vers un préfixe
ip -6 route add default via 2001:db8:1::254          # la route par défaut (::/0)
ip -6 route add default via fe80::1 dev eth0         # prochain saut de lien local : dev obligatoire
ip -6 route                                          # la table ; "proto kernel" : les réseaux
                                                     #   des adresses, "proto ra" : appris d'un RA
ip -6 route get 2001:db8:2::7                        # la route choisie pour une destination
sysctl -w net.ipv6.conf.all.forwarding=1             # routage activé (sur un routeur seulement)
```

Particularités :

- le **prochain saut** peut être une adresse **de lien local** (c'est ce que font les RA et les
  protocoles de routage) : il faut alors nommer l'interface (`dev`) puisque toutes les interfaces ont
  des adresses `fe80::` ;
- la route du réseau connecté apparaît quand l'adresse est ajoutée (`proto kernel`), et le lien
  local a toujours sa route `fe80::/64 dev ethN` ;
- un routeur dont le `forwarding` est actif ignore les RA (sauf `accept_ra=2`) et ne forme pas
  d'adresse automatique : sa configuration est **statique** ou vient d'un protocole de routage
  (OSPFv3, BGP) ;
- l'opérateur ne connaît qu'un **agrégat** par site (`/48`) : à l'intérieur du site, ce sont les
  routeurs du site qui connaissent les `/64`.

### @@sec@@ Configuration persistante (ifupdown)

Dans `/etc/network/interfaces`, une interface double pile a deux blocs, `inet` et `inet6` :

```
auto eth0
iface eth0 inet static
    address 192.0.2.10/24
    gateway 192.0.2.1

iface eth0 inet6 static
    address 2001:db8:1::10/64
    gateway 2001:db8:1::1
    post-up ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254
```

(`netmask 64` est accepté à la place du préfixe dans l'adresse ; `accept_ra 0` et `autoconf 0`
existent aussi dans un bloc `inet6`.) `ifup eth0` applique les deux blocs ; `ifdown eth0` les
retire. Les routes supplémentaires passent par `post-up`.
""": """

IPv6 routing is IPv4 routing with one more table (`ip -6 route`): one route per prefix, the
longest one that matches wins, `::/0` is the default route.

```
ip -6 addr add 2001:db8:1::1/64 dev eth0            # an address (DAD: one second before use)
ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254  # a route to a prefix
ip -6 route add default via 2001:db8:1::254          # the default route (::/0)
ip -6 route add default via fe80::1 dev eth0         # link-local next hop: dev mandatory
ip -6 route                                          # the table; "proto kernel": the networks
                                                     #   of the addresses, "proto ra": learnt from an RA
ip -6 route get 2001:db8:2::7                        # the route chosen for a destination
sysctl -w net.ipv6.conf.all.forwarding=1             # routing enabled (on a router only)
```

Particular points:

- the **next hop** may be a **link-local** address (this is what RAs and routing protocols do): the
  interface (`dev`) must then be named, since every interface has `fe80::` addresses;
- the route of the connected network appears when the address is added (`proto kernel`), and the
  link-local always has its route `fe80::/64 dev ethN`;
- a router whose `forwarding` is on ignores RAs (unless `accept_ra=2`) and forms no automatic
  address: its configuration is **static** or comes from a routing protocol (OSPFv3, BGP);
- the operator only knows one **aggregate** per site (`/48`): inside the site, it is the routers of
  the site that know the `/64`s.

### @@sec@@ Persistent configuration (ifupdown)

In `/etc/network/interfaces`, a dual-stack interface has two stanzas, `inet` and `inet6`:

```
auto eth0
iface eth0 inet static
    address 192.0.2.10/24
    gateway 192.0.2.1

iface eth0 inet6 static
    address 2001:db8:1::10/64
    gateway 2001:db8:1::1
    post-up ip -6 route add 2001:db8:2::/64 via 2001:db8:1::254
```

(`netmask 64` is accepted instead of the prefix in the address; `accept_ra 0` and `autoconf 0`
also exist in an `inet6` stanza.) `ifup eth0` applies both stanzas; `ifdown eth0` removes them.
The additional routes go through `post-up`.
""",
    "Les noms et la double pile": "Names and the dual stack",
    """

Le DNS associe à un nom une adresse IPv4 par un enregistrement **A** et une adresse IPv6 par un
enregistrement **AAAA** ; la résolution inverse d'IPv6 vit sous `ip6.arpa`. Dans `/etc/hosts`, un
nom peut avoir une ligne par famille :

```
192.0.2.10        srv   srv.example.org
2001:db8:1::10    srv   srv.example.org
```

Sur une machine double pile, `getent ahosts srv` renvoie les deux adresses, **IPv6 en premier**
(RFC 6724 préfère IPv6 quand une adresse globale ou ULA existe) : `ping srv`, `ssh srv` ou `curl`
tentent IPv6 d'abord. Les navigateurs appliquent *happy eyeballs* (RFC 8305) : tentatives IPv6 et
IPv4 presque simultanées, la première qui aboutit l'emporte. Pour forcer une famille :
`ping -4` / `ping -6`, `ssh -6`, `curl -6`, `dig AAAA nom`, `getent ahostsv6 nom`.

Un serveur DNS s'interroge aussi bien en IPv6 : `nameserver 2001:db8:1::53` dans `/etc/resolv.conf`
fonctionne comme son équivalent IPv4, et c'est ce que RDNSS ou `dhcp6.name-servers` y mettent.
""": """

DNS associates a name with an IPv4 address through an **A** record and with an IPv6 address through
an **AAAA** record; the reverse resolution of IPv6 lives under `ip6.arpa`. In `/etc/hosts`, a name
can have one line per family:

```
192.0.2.10        srv   srv.example.org
2001:db8:1::10    srv   srv.example.org
```

On a dual-stack machine, `getent ahosts srv` returns both addresses, **IPv6 first** (RFC 6724
prefers IPv6 when a global or ULA address exists): `ping srv`, `ssh srv` or `curl` try IPv6 first.
Browsers apply *happy eyeballs* (RFC 8305): IPv6 and IPv4 attempts almost simultaneous, the first
one that succeeds wins. To force a family: `ping -4` / `ping -6`, `ssh -6`, `curl -6`,
`dig AAAA name`, `getent ahostsv6 name`.

A DNS server can be queried over IPv6 just as well: `nameserver 2001:db8:1::53` in
`/etc/resolv.conf` works like its IPv4 equivalent, and that is what RDNSS or `dhcp6.name-servers`
put there.
""",
    "MTU, fragmentation et découverte du PMTU": "MTU, fragmentation and path MTU discovery",
    """

Le **MTU** d'un lien (1500 sur Ethernet) borne la taille des paquets. En IPv4 un routeur
**fragmente** un paquet trop grand pour le lien suivant, sauf si le bit **DF** est positionné : il le
jette alors et renvoie **ICMP type 3 code 4** (*fragmentation needed*) avec le MTU du lien suivant ;
l'émetteur mémorise ce **PMTU** par destination (`ip route get`, 10 min) et adapte ses paquets
(RFC 1191). `ping -4 -M do -s 1472` (1472 + 20 + 8 = 1500 octets) sonde le chemin.

### @@sec@@ En IPv6, la source seule fragmente

Un routeur IPv6 **ne fragmente jamais**. Un paquet trop grand pour le lien suivant est jeté et le
routeur renvoie à la source un message **ICMPv6 type 2, *Packet Too Big*** qui contient le MTU du
lien (RFC 8201). La source mémorise le PMTU (`ip -6 route get`, `ip -6 route flush cache`) et, si
elle tient vraiment à envoyer de plus gros datagrammes, les **fragmente elle-même** avec un en-tête
d'extension **Fragment** (*next header* **44**, 8 octets : identifiant, décalage, bit M) que seul le
destinataire traite. Deux garanties du protocole : tout lien IPv6 a un MTU d'au moins **1280**
octets (une interface dont le MTU descend en dessous perd ses adresses IPv6), et l'en-tête IPv6 fait
toujours **40** octets. Un écho ICMPv6 ajoute 8 octets : `ping -6 -s 1452` émet des paquets de 1500
octets.

```
ping -6 -c 3 -M do -s 1452 m2       # "Packet too big: mtu=N" venant du routeur, puis
                                    #   "sendmsg: Message too long" (PMTU connu)
ping -6 -c 1 -s 3000 m2             # trop grand pour tout lien : la source fragmente (en-tête 44)
tracepath -6 -n m2                  # PMTU saut par saut
ip -6 route get ADRESSE             # "mtu N" quand un PMTU est mémorisé ; ip -6 route flush cache
```

`tcpdump -n -v -i eth0 icmp6` montre l'erreur `ICMP6, packet too big, mtu N` émise par le routeur,
et `tcpdump -n -v -i eth0 ip6` les fragments : `frag (0x…:0|1448)` (identifiant, décalage, taille)
avec `next-header Fragment (44)`, déjà découpés par la source avant de partir.

| | IPv4 | IPv6 |
|---|---|---|
| en-tête | 20 octets (+ options) | 40 octets fixes (+ extensions) |
| fragmentation en route | par les routeurs si DF = 0 | jamais (RFC 8200) |
| fragmentation par la source | possible (DF = 0) | seule possibilité, en-tête Fragment (44) |
| erreur « trop grand » | ICMP type 3 code 4 | ICMPv6 type 2 *Packet Too Big* |
| MTU minimal | 68 (576 en pratique) | 1280 |
| charge utile max. de `ping -s` sur Ethernet | 1472 | 1452 |
| MSS = MTU − | 40 | 60 |

### @@sec@@ TCP, MSS et trou noir

Le **MSS** annoncé dans le SYN vaut MTU − 40 en IPv4 (1460) et **MTU − 60** en IPv6 (1440 ; `ss -ti`
affiche la valeur effective, 12 octets de moins avec l'option *timestamps*). Comme IPv6 ne fragmente
jamais en route, un pare-feu qui filtre les *Packet Too Big* crée exactement le même **trou noir
PMTUD** qu'en IPv4 : connexion établie, petits échanges normaux, transferts volumineux gelés, `ping`
intact. Remèdes côté routeurs, identiques dans les deux familles :

- **MSS clamping** nftables, table `inet`, hook `forward`, priorité `mangle`. Une règle sans
  `meta nfproto` s'applique **aux deux familles** avec la même valeur ; l'exemple ci-dessous donne
  une valeur à chaque famille (`… size set rt mtu` prend le MTU de la route de sortie du routeur :
  inutile tant que son interface de sortie est à 1500).
- **MTU des interfaces WAN** des routeurs abaissé au MTU de l'opérateur : le routeur émet lui-même
  *fragmentation needed* / *Packet Too Big* vers ses hôtes.
- Côté hôtes seulement : `net.ipv4.tcp_mtu_probing=1` (vaut aussi pour TCP sur IPv6), routes avec
  `mtu` : ne corrigent que la machine réglée.

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1400
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1380
```
""": """

The **MTU** of a link (1500 on Ethernet) bounds the size of the packets. In IPv4 a router
**fragments** a packet too big for the next link, unless the **DF** bit is set: it then drops it
and sends back **ICMP type 3 code 4** (*fragmentation needed*) with the MTU of the next link; the
sender remembers this **PMTU** per destination (`ip route get`, 10 min) and adapts its packets
(RFC 1191). `ping -4 -M do -s 1472` (1472 + 20 + 8 = 1500 bytes) probes the path.

### @@sec@@ In IPv6, only the source fragments

An IPv6 router **never fragments**. A packet too big for the next link is dropped and the router
sends the source an **ICMPv6 type 2, *Packet Too Big*** message that contains the MTU of the link
(RFC 8201). The source remembers the PMTU (`ip -6 route get`, `ip -6 route flush cache`) and, if it
really wants to send bigger datagrams, **fragments them itself** with a **Fragment** extension
header (*next header* **44**, 8 bytes: identifier, offset, M bit) that only the destination
processes. Two guarantees of the protocol: every IPv6 link has an MTU of at least **1280** bytes (an
interface whose MTU goes below that loses its IPv6 addresses), and the IPv6 header is always
**40** bytes. An ICMPv6 echo adds 8 bytes: `ping -6 -s 1452` sends 1500-byte packets.

```
ping -6 -c 3 -M do -s 1452 m2       # "Packet too big: mtu=N" from the router, then
                                    #   "sendmsg: Message too long" (PMTU known)
ping -6 -c 1 -s 3000 m2             # too big for any link: the source fragments (header 44)
tracepath -6 -n m2                  # PMTU hop by hop
ip -6 route get ADDRESS             # "mtu N" when a PMTU is remembered; ip -6 route flush cache
```

`tcpdump -n -v -i eth0 icmp6` shows the error `ICMP6, packet too big, mtu N` sent by the router,
and `tcpdump -n -v -i eth0 ip6` the fragments: `frag (0x…:0|1448)` (identifier, offset, size)
with `next-header Fragment (44)`, already cut by the source before leaving.

| | IPv4 | IPv6 |
|---|---|---|
| header | 20 bytes (+ options) | 40 fixed bytes (+ extensions) |
| fragmentation on the way | by the routers if DF = 0 | never (RFC 8200) |
| fragmentation by the source | possible (DF = 0) | the only possibility, Fragment header (44) |
| "too big" error | ICMP type 3 code 4 | ICMPv6 type 2 *Packet Too Big* |
| minimum MTU | 68 (576 in practice) | 1280 |
| max. payload of `ping -s` on Ethernet | 1472 | 1452 |
| MSS = MTU − | 40 | 60 |

### @@sec@@ TCP, MSS and black hole

The **MSS** advertised in the SYN is MTU − 40 in IPv4 (1460) and **MTU − 60** in IPv6 (1440; `ss -ti`
shows the effective value, 12 bytes less with the *timestamps* option). Since IPv6 never fragments
on the way, a firewall that filters the *Packet Too Big* messages creates exactly the same **PMTUD
black hole** as in IPv4: connection established, small exchanges normal, bulk transfers frozen,
`ping` intact. Remedies on the routers, identical in both families:

- nftables **MSS clamping**, `inet` table, `forward` hook, `mangle` priority. A rule without
  `meta nfproto` applies **to both families** with the same value; the example below gives each
  family its own value (`… size set rt mtu` takes the MTU of the router's outgoing route: useless
  as long as its outgoing interface is at 1500).
- **MTU of the WAN interfaces** of the routers lowered to the operator's MTU: the router itself
  sends *fragmentation needed* / *Packet Too Big* to its hosts.
- On the hosts only: `net.ipv4.tcp_mtu_probing=1` (also valid for TCP over IPv6), routes with
  `mtu`: they only fix the machine where they are set.

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set 1400
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set 1380
```
""",
    "Tunnels et transition": "Tunnels and transition",
    """

Tant que les deux familles coexistent, il faut faire passer l'une à travers l'autre :

| mécanisme | principe |
|---|---|
| **double pile** | chaque machine et chaque routeur ont les deux adresses : la solution de référence |
| **6in4** (RFC 4213, Linux `sit`) | paquets IPv6 dans des paquets IPv4 (protocole **41**) entre deux routeurs d'adresses IPv4 fixes : le raccordement historique d'un site IPv6 à travers un réseau IPv4 (*tunnel brokers*) |
| 6rd, 6to4 | 6in4 automatique : le préfixe IPv6 du site est dérivé de son adresse IPv4 |
| GRE, IPsec, WireGuard | tunnels génériques, qui transportent aussi bien IPv6 |
| **NAT64 + DNS64** (RFC 6146, 6147) | un réseau IPv6 seul joint le monde IPv4 : le résolveur fabrique une adresse `64:ff9b::<IPv4>` et un traducteur convertit les paquets |
| 464XLAT, DS-Lite, MAP | variantes pour les opérateurs mobiles et d'accès |

Un tunnel ajoute un en-tête : son **MTU** vaut le MTU du chemin extérieur moins cet en-tête
(**20 octets** pour 6in4, 24 pour GRE), et doit rester ≥ 1280.

```
ip link add sit1 type sit local ADRESSE_IPV4_LOCALE remote ADRESSE_IPV4_DISTANTE ttl 64
ip link set sit1 mtu MTU up
ip -6 addr add ADRESSE_TUN/64 dev sit1
ip -d link show sit1                # "sit remote … local … pmtudisc"
```

Le chargement du module crée aussi `sit0@NONE`, à ignorer. On teste le MTU du tunnel avec
`ping -6 -M do -s` vers l'adresse du routeur distant ; `tcpdump -n -i eth1 'ip proto 41'` montre
les paquets encapsulés.
""": """

As long as both families coexist, one has to be carried through the other:

| mechanism | principle |
|---|---|
| **dual stack** | every machine and every router has both addresses: the reference solution |
| **6in4** (RFC 4213, Linux `sit`) | IPv6 packets inside IPv4 packets (protocol **41**) between two routers with fixed IPv4 addresses: the historical way of connecting an IPv6 site across an IPv4 network (*tunnel brokers*) |
| 6rd, 6to4 | automatic 6in4: the IPv6 prefix of the site is derived from its IPv4 address |
| GRE, IPsec, WireGuard | generic tunnels, which carry IPv6 just as well |
| **NAT64 + DNS64** (RFC 6146, 6147) | an IPv6-only network reaches the IPv4 world: the resolver makes up an address `64:ff9b::<IPv4>` and a translator converts the packets |
| 464XLAT, DS-Lite, MAP | variants for mobile and access operators |

A tunnel adds a header: its **MTU** is the MTU of the outer path minus that header
(**20 bytes** for 6in4, 24 for GRE), and must stay ≥ 1280.

```
ip link add sit1 type sit local LOCAL_IPV4_ADDRESS remote REMOTE_IPV4_ADDRESS ttl 64
ip link set sit1 mtu MTU up
ip -6 addr add TUN_ADDRESS/64 dev sit1
ip -d link show sit1                # "sit remote … local … pmtudisc"
```

Loading the module also creates `sit0@NONE`, to be ignored. The MTU of the tunnel is tested with
`ping -6 -M do -s` towards the address of the remote router; `tcpdump -n -i eth1 'ip proto 41'` shows
the encapsulated packets.
""",
    "Pare-feu": "Firewall",
    """

nftables filtre IPv6 dans une table `ip6`, ou les deux familles dans une table `inet`. Trois
différences avec IPv4 :

- **ICMPv6 doit passer** : au minimum les types 1 à 4 (erreurs, dont *Packet Too Big*), 133 à 136
  (RA, RS, NS, NA) et les échos :
  `icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem,
  echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit,
  nd-neighbor-advert } accept` ;
- pas de NAT : les machines ont des adresses publiques ; c'est le pare-feu du routeur qui joue le
  rôle protecteur que le NAT jouait par accident ;
- les adresses de lien local (`fe80::/10`) et le multicast (`ff02::/16`) sont le trafic local
  normal, à ne pas bloquer.

En IPv4 comme en IPv6, les en-têtes d'extension et la fragmentation par la source compliquent
l'inspection : un pare-feu peut rejeter les fragments autres que le premier (`exthdr frag`).
""": """

nftables filters IPv6 in an `ip6` table, or both families in an `inet` table. Three
differences from IPv4:

- **ICMPv6 must get through**: at least types 1 to 4 (errors, including *Packet Too Big*), 133 to 136
  (RA, RS, NS, NA) and the echoes:
  `icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem,
  echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit,
  nd-neighbor-advert } accept`;
- no NAT: the machines have public addresses; it is the router's firewall that plays the
  protective role that NAT played by accident;
- the link-local addresses (`fe80::/10`) and multicast (`ff02::/16`) are normal local traffic,
  not to be blocked.

In IPv4 as in IPv6, extension headers and fragmentation by the source make inspection harder: a
firewall may reject the fragments other than the first one (`exthdr frag`).
""",
    "Outils": "Tools",
    """

| outil | usage |
|---|---|
| `ip -6 addr [show dev IFACE]` | adresses, portée (`global`, `link`), drapeaux (`dynamic`, `tentative`, `mngtmpaddr`), durées de vie |
| `ip -6 route`, `ip -6 route get DEST` | table de routage, route choisie ; `proto ra` : apprise d'une annonce |
| `ip -6 neigh` | cache de voisins (le remplaçant de `arp -n`) |
| `ip link show IFACE` | adresse MAC, MTU ; `ip -d link show sit1` pour un tunnel |
| `ping -6 DEST`, `ping -6 ff02::1%eth0` | écho ; tous les nœuds du lien |
| `ping -6 -M do -s TAILLE DEST`, `tracepath -6 -n DEST` | sonder le MTU du chemin |
| `traceroute -6 DEST` | les routeurs traversés |
| `tcpdump -n -v -i IFACE icmp6` | découverte de voisins, annonces de routeur, erreurs ; `'icmp6 and ip6[40] == 134'` : les RA seuls |
| `tcpdump -n -v -i IFACE 'udp port 546 or udp port 547'` | DHCPv6 |
| `tcpdump -n -v -i IFACE ip6` | tout le trafic IPv6 (fragments, *next-header*) |
| `sysctl net.ipv6.conf.IFACE` | `forwarding`, `accept_ra`, `autoconf`, `addr_gen_mode` |
| `ss -6 -tlnp`, `ss -6 -ti` | sockets IPv6, MSS et PMTU des connexions |
| `getent ahosts NOM`, `getent ahostsv6 NOM`, `dig AAAA NOM` | résolution de noms |
| `radvd -c`, `pidof radvd` | le démon d'annonces |
| `dhcpd -t -6 -cf …`, `journalctl -u isc-dhcp-server`, `ps -C dhcpd -o args` | le serveur DHCPv6 |
| `nft list ruleset` | règles nftables du routeur |
| `iperf3 -s` / `iperf3 -6 -c SERVEUR -t 5` | transfert TCP de test (`-R` : sens inverse ; `-4` / `-6`) |
""": """

| tool | use |
|---|---|
| `ip -6 addr [show dev IFACE]` | addresses, scope (`global`, `link`), flags (`dynamic`, `tentative`, `mngtmpaddr`), lifetimes |
| `ip -6 route`, `ip -6 route get DEST` | routing table, route chosen; `proto ra`: learnt from an advertisement |
| `ip -6 neigh` | neighbour cache (the replacement of `arp -n`) |
| `ip link show IFACE` | MAC address, MTU; `ip -d link show sit1` for a tunnel |
| `ping -6 DEST`, `ping -6 ff02::1%eth0` | echo; all the nodes on the link |
| `ping -6 -M do -s SIZE DEST`, `tracepath -6 -n DEST` | probe the MTU of the path |
| `traceroute -6 DEST` | the routers crossed |
| `tcpdump -n -v -i IFACE icmp6` | neighbour discovery, router advertisements, errors; `'icmp6 and ip6[40] == 134'`: the RAs only |
| `tcpdump -n -v -i IFACE 'udp port 546 or udp port 547'` | DHCPv6 |
| `tcpdump -n -v -i IFACE ip6` | all the IPv6 traffic (fragments, *next-header*) |
| `sysctl net.ipv6.conf.IFACE` | `forwarding`, `accept_ra`, `autoconf`, `addr_gen_mode` |
| `ss -6 -tlnp`, `ss -6 -ti` | IPv6 sockets, MSS and PMTU of the connections |
| `getent ahosts NAME`, `getent ahostsv6 NAME`, `dig AAAA NAME` | name resolution |
| `radvd -c`, `pidof radvd` | the advertisement daemon |
| `dhcpd -t -6 -cf …`, `journalctl -u isc-dhcp-server`, `ps -C dhcpd -o args` | the DHCPv6 server |
| `nft list ruleset` | nftables rules of the router |
| `iperf3 -s` / `iperf3 -6 -c SERVER -t 5` | test TCP transfer (`-R`: reverse direction; `-4` / `-6`) |
""",
    "Dépannage": "Troubleshooting",
    """

| symptôme | cause probable | à vérifier |
|---|---|---|
| `ping -6` : `Network is unreachable` | pas de route pour la destination (pas de route par défaut) | `ip -6 route` |
| `ping -6` : `Destination unreachable: Address unreachable` | la destination est sur le lien mais ne répond pas aux NS (adresse fausse, machine éteinte, interface sans adresse) | `ip -6 neigh` (`FAILED`), `ip -6 addr` sur la cible |
| l'adresse ajoutée ne répond pas la première seconde | DAD en cours (`tentative`) | `ip -6 addr` |
| adresse marquée `dadfailed` | une autre machine a déjà cette adresse | `ip -6 neigh`, captures de NA |
| `Invalid argument` à `ip -6 route add default via fe80::…` | prochain saut de lien local sans `dev` | ajouter `dev ethN` |
| `pc1` n'a pas d'adresse automatique | pas d'annonce (radvd arrêté, `forwarding=0` sur le routeur, préfixe sans drapeau A), ou `accept_ra` / `autoconf` à 0 | `pidof radvd`, `tcpdump icmp6` sur le routeur, `sysctl net.ipv6.conf.eth0` |
| `pc1` a une adresse mais pas de route par défaut | durée de vie du routeur nulle (`AdvDefaultLifetime 0`) | capture du RA |
| `pc1` a une adresse mais ne résout aucun nom | aucun système ne lit RDNSS ici ; DNS par DHCPv6 (drapeau O) | `/etc/resolv.conf` |
| `dhcpd -6` ne démarre pas : `No subnet6 declaration for eth0` | l'interface n'a pas d'adresse globale dans un `subnet6` | `ip -6 addr` sur le serveur, `dhcpd6.conf` |
| `dhclient -6` répète ses `XMT: Solicit` | pas de serveur à l'écoute sur le lien, ou mauvaise interface d'écoute | `ps -C dhcpd -o args`, journal du serveur |
| `pc2` obtient une adresse dynamique malgré la réservation | DUID différent de celui déclaré (fichier de baux ancien, `-D LL` oublié) | journal du serveur (`duid …`), `/var/lib/dhcp/dhclient6.leases` |
| le routeur IPv6 ne relaie pas | `net.ipv6.conf.all.forwarding=0` | `sysctl` |
| `sendmsg: Message too long` dès le premier `ping -6 -M do` | un PMTU est déjà mémorisé (`ip -6 route get`, `ip -6 route flush cache`) | |
| `ping -6 -M do -s 1452` n'obtient ni réponse ni erreur | ICMPv6 filtré (`trou_noir`) : le paquet est jeté en silence | |
| `ping` passe mais `iperf3` reste à 0 bit/s | trou noir PMTUD (section @@ref:mtu@@) | |
| `iperf3 -4` passe mais `iperf3 -6` gèle | correction limitée à IPv4 (règle `meta nfproto ipv4`, ou table `ip` au lieu de `inet`) | |
| `ip link set … mtu 1200` : plus d'adresse IPv6 | MTU sous 1280 : IPv6 désactivé sur l'interface | |
| `ping -6` à travers `sit1` muet | `local`/`remote` inversés, ou MTU du tunnel trop grand sous `trou_noir` | |
""": """

| symptom | likely cause | to check |
|---|---|---|
| `ping -6`: `Network is unreachable` | no route for the destination (no default route) | `ip -6 route` |
| `ping -6`: `Destination unreachable: Address unreachable` | the destination is on the link but does not answer the NSs (wrong address, machine down, interface without an address) | `ip -6 neigh` (`FAILED`), `ip -6 addr` on the target |
| the added address does not answer during the first second | DAD in progress (`tentative`) | `ip -6 addr` |
| address marked `dadfailed` | another machine already has this address | `ip -6 neigh`, captures of NAs |
| `Invalid argument` on `ip -6 route add default via fe80::…` | link-local next hop without `dev` | add `dev ethN` |
| `pc1` has no automatic address | no advertisement (radvd stopped, `forwarding=0` on the router, prefix without the A flag), or `accept_ra` / `autoconf` at 0 | `pidof radvd`, `tcpdump icmp6` on the router, `sysctl net.ipv6.conf.eth0` |
| `pc1` has an address but no default route | router lifetime zero (`AdvDefaultLifetime 0`) | capture of the RA |
| `pc1` has an address but resolves no name | nothing reads RDNSS here; DNS through DHCPv6 (O flag) | `/etc/resolv.conf` |
| `dhcpd -6` does not start: `No subnet6 declaration for eth0` | the interface has no global address in a `subnet6` | `ip -6 addr` on the server, `dhcpd6.conf` |
| `dhclient -6` keeps repeating its `XMT: Solicit` | no server listening on the link, or wrong listening interface | `ps -C dhcpd -o args`, journal of the server |
| `pc2` gets a dynamic address despite the reservation | DUID different from the one declared (old lease file, `-D LL` forgotten) | journal of the server (`duid …`), `/var/lib/dhcp/dhclient6.leases` |
| the IPv6 router does not forward | `net.ipv6.conf.all.forwarding=0` | `sysctl` |
| `sendmsg: Message too long` from the very first `ping -6 -M do` | a PMTU is already remembered (`ip -6 route get`, `ip -6 route flush cache`) | |
| `ping -6 -M do -s 1452` gets neither a reply nor an error | ICMPv6 filtered (`trou_noir`): the packet is dropped silently | |
| `ping` works but `iperf3` stays at 0 bit/s | PMTUD black hole (section @@ref:mtu@@) | |
| `iperf3 -4` works but `iperf3 -6` freezes | fix limited to IPv4 (`meta nfproto ipv4` rule, or `ip` table instead of `inet`) | |
| `ip link set … mtu 1200`: no IPv6 address any more | MTU below 1280: IPv6 disabled on the interface | |
| `ping -6` through `sit1` silent | `local`/`remote` swapped, or tunnel MTU too big under `trou_noir` | |
""",
    "Trou noir PMTUD : le routeur de l'opérateur (wan) n'émet plus les erreurs ICMP « fragmentation needed » ni ICMPv6 « packet too big » ; les PMTU déjà appris par m1, m2, r1 et r2 sont oubliés": "PMTUD black hole: the operator's router (wan) no longer sends the ICMP \"fragmentation needed\" errors nor the ICMPv6 \"packet too big\" ones; the PMTUs already learnt by m1, m2, r1 and r2 are forgotten",
    "ICMP rétabli : le routeur de l'opérateur émet de nouveau les erreurs ICMP et ICMPv6": "ICMP restored: the operator's router sends the ICMP and ICMPv6 errors again",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : c'est le cours (adresses, découverte de voisins, annonces de
routeur, DHCPv6, routage, MTU), avec les commandes utiles et un tableau de dépannage.

Deux sites, `lan1` (`m1`) et `lan2` + `lan3` (`m2`, `srv`, `pc1`, `pc2`), sont reliés par leurs
routeurs `r1` et `r2` à travers le réseau d'un **opérateur**, représenté par le routeur `wan`
(pas de terminal : c'est l'équipement de l'opérateur). Le réseau **IPv4** est en place partout
(adresses, routes, routage) : c'est le réseau historique du site. Vous déployez **IPv6** par-dessus,
en suivant le plan d'adressage ci-dessous ; `wan` est déjà configuré dans les deux familles.
""": """
Read the **Informations** tab: it is the course (addresses, neighbour discovery, router
advertisements, DHCPv6, routing, MTU), with the useful commands and a troubleshooting table.

Two sites, `lan1` (`m1`) and `lan2` + `lan3` (`m2`, `srv`, `pc1`, `pc2`), are connected by their
routers `r1` and `r2` across the network of an **operator**, represented by the router `wan`
(no terminal: it is the operator's equipment). The **IPv4** network is in place everywhere
(addresses, routes, routing): it is the legacy network of the site. You deploy **IPv6** on top of it,
following the addressing plan below; `wan` is already configured in both families.
""",
    """
**Plan du TP.** Six parties, à faire dans l'ordre :

1. **Adressage et voisinage** sur `lan1` : adresses de lien local, `ff02::1`, adresses statiques de
   `m1` et `r1`, découverte de voisins (12 points).
2. **Routage statique** : adresses et routes de `r1`, `r2`, `m2`, `srv`, routage activé,
   configuration persistante de `m1` et `r1` (23 points).
3. **SLAAC** : annonces de routeur de `r2` sur `lan3` (radvd), autoconfiguration de `pc1`
   (16 points).
4. **DHCPv6** sur `srv` : sans état (DNS pour `pc1`), avec état (adresse de `pc2`), réservation par
   DUID (24 points).
5. **MTU et trou noir PMTUD en double pile** : *Packet Too Big*, fragmentation par la source,
   correction sur `r1` / `r2` (15 points).
6. **Tunnel 6in4** entre `r1` et `r2` à travers l'IPv4 de l'opérateur (10 points).

Règles valables pour tout le TP :

- les parties sont à faire **dans l'ordre** : chaque partie suppose la précédente en place, et la
  configuration d'une partie terminée reste en place ;
- `wan` ne se configure pas ; ses liens ont un MTU **inférieur à 1500** (partie 5) ;
- les machines à configuration statique (`m1`, `r1`, `r2`, `m2`, `srv`) ignorent les annonces de
  routeur (`accept_ra=0`) ; `pc1` et `pc2` n'ont **ni adresse IPv4 ni configuration IPv6** : elles
  se configurent par les annonces de `r2` et par DHCPv6 (parties 3 et 4) et ne connaissent les
  noms que par le serveur DNS `srv`, une fois son adresse reçue ;
- les noms des machines statiques sont dans `/etc/hosts` avec une ligne par famille (`ping -4 m2`,
  `ping -6 m2`, `ping -6 r1_lan1`… ; **précisez `-4` ou `-6`** : sans option, la résolution de noms
  propose IPv6 en premier) et dans le DNS de `srv` ;
- après chaque modification d'un fichier de configuration, **relancez le service** et vérifiez
  dans le journal qu'il a démarré ;
- les états `trou_noir` et `icmp_retabli` (onglet **Appliquer une configuration**) servent à la
  partie 5 ; l'évaluation ne dépend pas de l'état choisi ;
- l'évaluation (bouton d'évaluation, ≈ 15 s) lit la configuration des machines telle qu'elle est
  au moment où elle est lancée, et fait des mesures depuis **trois postes cachés** : `h1` dans
  `lan1`, `h2` dans `lan2` (transferts et pings, partie 5) et `h3` dans `lan3` (sollicitations de
  routeur et requêtes DHCPv6, parties 3 et 4). Vous verrez leurs adresses dans vos captures ; ils
  n'ont aucune configuration à faire et ne répondent pas à `ping ff02::1`.
""": """
**Plan of the lab.** Six parts, to be done in order:

1. **Addressing and neighbours** on `lan1`: link-local addresses, `ff02::1`, static addresses of
   `m1` and `r1`, neighbour discovery (12 points).
2. **Static routing**: addresses and routes of `r1`, `r2`, `m2`, `srv`, routing enabled,
   persistent configuration of `m1` and `r1` (23 points).
3. **SLAAC**: router advertisements of `r2` on `lan3` (radvd), autoconfiguration of `pc1`
   (16 points).
4. **DHCPv6** on `srv`: stateless (DNS for `pc1`), stateful (address of `pc2`), reservation by
   DUID (24 points).
5. **MTU and PMTUD black hole in dual stack**: *Packet Too Big*, fragmentation by the source,
   fix on `r1` / `r2` (15 points).
6. **6in4 tunnel** between `r1` and `r2` across the operator's IPv4 (10 points).

Rules for the whole lab:

- the parts are to be done **in order**: each part assumes the previous one is in place, and the
  configuration of a finished part stays in place;
- `wan` is not yours to configure; its links have an MTU **below 1500** (part 5);
- the machines with a static configuration (`m1`, `r1`, `r2`, `m2`, `srv`) ignore router
  advertisements (`accept_ra=0`); `pc1` and `pc2` have **neither an IPv4 address nor an IPv6
  configuration**: they configure themselves from the advertisements of `r2` and through DHCPv6
  (parts 3 and 4) and only know the names through the DNS server `srv`, once they have received
  its address;
- the names of the static machines are in `/etc/hosts` with one line per family (`ping -4 m2`,
  `ping -6 m2`, `ping -6 r1_lan1`…; **specify `-4` or `-6`**: without an option, name resolution
  offers IPv6 first) and in the DNS of `srv`;
- after each change to a configuration file, **restart the service** and check in the journal
  that it has started;
- the states `trou_noir` and `icmp_retabli` (**Apply Configuration** tab) are for part 5; the
  evaluation does not depend on the state chosen;
- the evaluation (evaluation button, ≈ 15 s) reads the configuration of the machines as it is at
  the moment it is launched, and takes measurements from **three hidden hosts**: `h1` in `lan1`,
  `h2` in `lan2` (transfers and pings, part 5) and `h3` in `lan3` (router solicitations and DHCPv6
  requests, parts 3 and 4). You will see their addresses in your captures; they need no
  configuration and do not answer `ping ff02::1`.
""",
    """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet.

- L'état `final` (onglet *Appliquer une configuration*) applique toute la solution (IPv6 des
  machines statiques et fichiers persistants, radvd avec les drapeaux M et O, dhcpd6 avec la plage et
  la réservation, `dhclient -6` sur `pc1` et `pc2`, MSS clamping et tunnel 6in4) et remplit les
  formulaires. Compter une dizaine de secondes avant l'évaluation (clients DHCPv6, DAD).
- Sondes : `h1` (`{h1v4}`, `{h1v6}`) et `h2` (`{h2v4}`, `{h2v6}`) sont derrière le trou noir permanent
  de `wan` (table nftables `sondes`) ; `h3` (`{h3v4}`, `{h3v6}`) a `accept_ra=0` et envoie à chaque
  évaluation une sollicitation de routeur, une INFORMATION-REQUEST et deux SOLICIT (DUID
  `{probe_duid}`, puis le DUID-LL de `pc2`, `{pc2_duid}`) : les serveurs ne font qu'annoncer, aucun
  bail n'est engagé.
- Valeurs cachées ou prévisibles : MTU de l'opérateur **{n}** (charge utile maximale de `ping` :
  {charge6} en IPv6, {charge4} en IPv4 ; MSS : {mss6} / {mss4} ; MTU du tunnel : {tun_mtu}) ;
  adresses de lien local `{ll_m1}` (`m1`), `{ll_r1}` (`r1` eth0), `{ll_r2}` (`r2` eth2) ; adresse
  SLAAC de `pc1` `{pc1_slaac}` ; plage DHCPv6 `{pool_min}` – `{pool_max}`, durée de validité
  {lease6} s, adresse réservée de `pc2` `{pc2_fixe}`.
- Évaluation : lecture de `ip a` / `ip -6 route` / `/etc/network/interfaces` / forwarding des machines
  statiques, `ip -j -6 addr` / `route` / `resolv.conf` / baux de `pc1` et `pc2`, ligne de commande de
  `dhcpd`, sonde `h3` (≈ {wait} s), puis pings depuis `h1`, `h2`, `h3`, `m2` et `pc1`, `getent ahostsv6 m1`
  sur `pc1` / `pc2`, transferts `iperf3` de 2 s entre `h1` et `h2` dans les deux familles et le test du
  tunnel depuis `r1`.
""": """
**For the instructor.** Each question ends with its solution, computed for this project.

- The state `final` (*Apply Configuration* tab) applies the whole solution (IPv6 of the static
  machines and persistent files, radvd with the M and O flags, dhcpd6 with the range and the
  reservation, `dhclient -6` on `pc1` and `pc2`, MSS clamping and 6in4 tunnel) and fills in the
  forms. Allow about ten seconds before the evaluation (DHCPv6 clients, DAD).
- Probes: `h1` (`{h1v4}`, `{h1v6}`) and `h2` (`{h2v4}`, `{h2v6}`) are behind the permanent black hole
  of `wan` (nftables table `sondes`); `h3` (`{h3v4}`, `{h3v6}`) has `accept_ra=0` and at each
  evaluation sends a router solicitation, an INFORMATION-REQUEST and two SOLICITs (DUID
  `{probe_duid}`, then the DUID-LL of `pc2`, `{pc2_duid}`): the servers only advertise, no
  lease is committed.
- Hidden or predictable values: operator's MTU **{n}** (maximum `ping` payload: {charge6} in IPv6,
  {charge4} in IPv4; MSS: {mss6} / {mss4}; MTU of the tunnel: {tun_mtu}); link-local addresses
  `{ll_m1}` (`m1`), `{ll_r1}` (`r1` eth0), `{ll_r2}` (`r2` eth2); SLAAC address of `pc1`
  `{pc1_slaac}`; DHCPv6 range `{pool_min}` – `{pool_max}`, valid lifetime {lease6} s, reserved
  address of `pc2` `{pc2_fixe}`.
- Evaluation: reading of `ip a` / `ip -6 route` / `/etc/network/interfaces` / forwarding of the
  static machines, `ip -j -6 addr` / `route` / `resolv.conf` / leases of `pc1` and `pc2`, command
  line of `dhcpd`, probe `h3` (≈ {wait} s), then pings from `h1`, `h2`, `h3`, `m2` and `pc1`,
  `getent ahostsv6 m1` on `pc1` / `pc2`, `iperf3` transfers of 2 s between `h1` and `h2` in both
  families and the test of the tunnel from `r1`.
""",
    "Partie 1 — Adressage et découverte de voisins (lan1)": "Part 1 — Addressing and neighbour discovery (lan1)",
    "Adressage et découverte de voisins sur lan1": "Addressing and neighbour discovery on lan1",
    """
Sur `lan1`, `m1` et `r1` (interface `eth0`) n'ont encore qu'IPv4.

1. Sur `m1`, relevez l'adresse MAC de `eth0` (`ip link show eth0`) et son adresse IPv6 de **lien
   local** (`ip -6 addr show eth0`). Retrouvez par le calcul (EUI-64 : `ff:fe` inséré au milieu, bit
   *universal/local* inversé) comment l'une se déduit de l'autre, et faites de même sur `r1`.
2. Sur `m1`, `ping -6 -c 2 ff02::1%eth0` : qui répond ? Regardez ensuite `ip -6 neigh`.
3. Donnez à `m1` et à `r1` (eth0) leurs adresses **globales** du plan d'adressage, en `/64`
   (`ip -6 addr add … dev eth0`). Observez `ip -6 addr` juste après (`tentative`), puis `ip -6 route` :
   quelle route est apparue toute seule ?
4. Dans un second terminal sur `m1`, lancez `tcpdump -n -v -i eth0 icmp6`, puis depuis `m1`
   `ping -6 -c 2 r1_lan1` (ou l'adresse). Relevez les messages de découverte de voisins : types,
   adresse de destination du premier (le groupe du *nœud sollicité* de l'adresse de `r1`), adresse MAC
   de destination de la trame, puis `ip -6 neigh` sur `m1`.
5. Toujours en capturant, retirez puis remettez l'adresse de `m1` (`ip -6 addr del` / `add`) : observez
   la **détection d'adresse dupliquée** (un NS dont l'adresse source est `::`).
""": """
On `lan1`, `m1` and `r1` (interface `eth0`) only have IPv4 so far.

1. On `m1`, note the MAC address of `eth0` (`ip link show eth0`) and its IPv6 **link-local**
   address (`ip -6 addr show eth0`). Work out by calculation (EUI-64: `ff:fe` inserted in the middle,
   *universal/local* bit inverted) how one is derived from the other, and do the same on `r1`.
2. On `m1`, `ping -6 -c 2 ff02::1%eth0`: who answers? Then look at `ip -6 neigh`.
3. Give `m1` and `r1` (eth0) their **global** addresses from the addressing plan, as `/64`
   (`ip -6 addr add … dev eth0`). Look at `ip -6 addr` right after (`tentative`), then `ip -6 route`:
   which route has appeared by itself?
4. In a second terminal on `m1`, start `tcpdump -n -v -i eth0 icmp6`, then from `m1`
   `ping -6 -c 2 r1_lan1` (or the address). Note the neighbour discovery messages: types,
   destination address of the first one (the *solicited-node* group of the address of `r1`),
   destination MAC address of the frame, then `ip -6 neigh` on `m1`.
5. Still capturing, remove then put back the address of `m1` (`ip -6 addr del` / `add`): observe
   **duplicate address detection** (an NS whose source address is `::`).
""",
    """
**Solution.** Adresses de lien local attendues (EUI-64 des adresses MAC fixées par le TP) : `m1`
`{ll_m1}` (MAC `{mac_m1}`), `r1` eth0 `{ll_r1}` (MAC `{mac_r1}`). Sur `m1` :

```
ip -6 addr add {m1}/64 dev eth0
```

Sur `r1` :

```
ip -6 addr add {r1}/64 dev eth0
```

- `ping -6 ff02::1%eth0` fait répondre `m1` elle-même, `r1` et… `h1`, la sonde cachée de `lan1`, qui
  est réglée pour ne pas répondre (`echo_ignore_multicast`) : deux réponses par écho, dont une `(DUP!)`.
- La route `{lan1} dev eth0 proto kernel` apparaît avec l'adresse.
- Capture : `NS, who has {r1}` de `{m1}` vers `{sollicite}` (trame vers `{mac_sollicite}`), puis `NA, tgt is {r1}`
  de `r1` vers `m1` (drapeaux *solicited*, *override*) ; les types sont 135 et 136. DAD : `NS, who has {m1}`
  depuis `::` vers `{sollicite_m1}`.
- Évaluation : adresses de `m1` et de `r1` eth0 (`ip a`), pings de `h1` vers les deux, et les réponses du
  formulaire (adresses de lien local comparées à ce que les machines ont réellement, valeur EUI-64
  attendue en solution).
""": """
**Solution.** Expected link-local addresses (EUI-64 of the MAC addresses set by the lab): `m1`
`{ll_m1}` (MAC `{mac_m1}`), `r1` eth0 `{ll_r1}` (MAC `{mac_r1}`). On `m1`:

```
ip -6 addr add {m1}/64 dev eth0
```

On `r1`:

```
ip -6 addr add {r1}/64 dev eth0
```

- `ping -6 ff02::1%eth0` makes `m1` itself and `r1` answer; `h1`, the hidden probe of `lan1`, is
  set not to answer (`echo_ignore_multicast`): two replies per echo, one of them `(DUP!)`.
- The route `{lan1} dev eth0 proto kernel` appears with the address.
- Capture: `NS, who has {r1}` from `{m1}` to `{sollicite}` (frame to `{mac_sollicite}`), then `NA, tgt is {r1}`
  from `r1` to `m1` (flags *solicited*, *override*); the types are 135 and 136. DAD: `NS, who has {m1}`
  from `::` to `{sollicite_m1}`.
- Evaluation: addresses of `m1` and of `r1` eth0 (`ip a`), pings from `h1` to both, and the answers of the
  form (link-local addresses compared with what the machines really have, EUI-64 value expected in
  the solution).
""",
    "Adresses et messages observés": "Addresses and messages observed",
    """
- Adresse de lien local de `m1` : @@{ll_m1:[0-9a-fA-F:%/]+}@@ ; de `r1` (eth0) : @@{ll_r1:[0-9a-fA-F:%/]+}@@
- Préfixe de toutes les adresses de lien local : @@{prefixe_ll:[0-9a-fA-F:/]+}@@
- Types ICMPv6 de la sollicitation de voisin : @@{ns_type:[0-9]+}@@ et de l'annonce de voisin : @@{na_type:[0-9]+}@@
- Adresse IPv6 de destination de la sollicitation de voisin pour l'adresse de `r1` : @@{sollicite:[0-9a-fA-F:]+}@@ ;
  adresse MAC de destination de cette trame : @@{mac_sollicite:[0-9a-fA-F:]+}@@
- Adresse source du NS de la détection d'adresse dupliquée : @@{dad_src:>:: (l'adresse non spécifiée)|l'adresse de lien local de m1|l'adresse testée}@@
""": """
- Link-local address of `m1`: @@{ll_m1:[0-9a-fA-F:%/]+}@@; of `r1` (eth0): @@{ll_r1:[0-9a-fA-F:%/]+}@@
- Prefix of all the link-local addresses: @@{prefixe_ll:[0-9a-fA-F:/]+}@@
- ICMPv6 types of the neighbour solicitation: @@{ns_type:[0-9]+}@@ and of the neighbour advertisement: @@{na_type:[0-9]+}@@
- Destination IPv6 address of the neighbour solicitation for the address of `r1`: @@{sollicite:[0-9a-fA-F:]+}@@;
  destination MAC address of that frame: @@{mac_sollicite:[0-9a-fA-F:]+}@@
- Source address of the NS of duplicate address detection: @@{dad_src:>:: (the unspecified address)>>>:: (l'adresse non spécifiée)|the link-local address of m1>>>l'adresse de lien local de m1|the address being tested>>>l'adresse testée}@@
""",
    """
**Réponses.**

- lien local de `m1` : `{ll_m1}` ; de `r1` : `{ll_r1}` (1 point chacune : la valeur relevée sur la machine est
  acceptée, même si l'hôte Docker fabriquait des identifiants non EUI-64)
- préfixe `{prefixe_ll}` (`fe80::/64` accepté)
- NS : `{ns_type}` ; NA : `{na_type}`
- nœud sollicité de `r1` : `{sollicite}`, trame vers `{mac_sollicite}` (`33:33:ff` + les 3 derniers octets de l'adresse)
- DAD : `{dad_src}`
""": """
**Answers.**

- link-local of `m1`: `{ll_m1}`; of `r1`: `{ll_r1}` (1 point each: the value read on the machine is
  accepted, even if the Docker host made non-EUI-64 identifiers)
- prefix `{prefixe_ll}` (`fe80::/64` accepted)
- NS: `{ns_type}`; NA: `{na_type}`
- solicited node of `r1`: `{sollicite}`, frame to `{mac_sollicite}` (`33:33:ff` + the last 3 bytes of the address)
- DAD: `{dad_src}`
""",
    "adresses de lien local de m1 et de r1 (relevées ou calculées)": "link-local addresses of m1 and r1 (read or computed)",
    "préfixe des adresses de lien local": "prefix of the link-local addresses",
    "types des messages NS / NA": "types of the NS / NA messages",
    "source du NS de la détection d'adresse dupliquée": "source of the NS of duplicate address detection",
    "groupe du nœud sollicité de r1 et adresse MAC multicast correspondante": "solicited-node group of r1 and the corresponding multicast MAC address",
    "adresse IPv6 globale de m1 ({m1}/64)": "global IPv6 address of m1 ({m1}/64)",
    "adresse IPv6 de r1 sur lan1 ({r1}/64)": "IPv6 address of r1 on lan1 ({r1}/64)",
    "ping -6 de la sonde h1 vers m1": "ping -6 from the probe h1 to m1",
    "ping -6 de la sonde h1 vers r1": "ping -6 from the probe h1 to r1",
    "Découverte de voisins": "Neighbour discovery",
    "Collez les lignes de `tcpdump` montrant la sollicitation et l'annonce de voisin de l'étape 4, puis le NS de la détection d'adresse dupliquée de l'étape 5.": "Paste the `tcpdump` lines showing the neighbour solicitation and advertisement of step 4, then the NS of the duplicate address detection of step 5.",
    """

**Attendu.** `{m1} > {sollicite}: ICMP6, neighbor solicitation, who has {r1}, length 32` (option *source
link-address* : MAC de `m1`), `{r1} > {m1}: ICMP6, neighbor advertisement, tgt is {r1}, length 32` (drapeaux
`[solicited, override]`), puis `:: > {sollicite_m1}: ICMP6, neighbor solicitation, who has {m1}`. Question non
notée.
""": """

**Expected.** `{m1} > {sollicite}: ICMP6, neighbor solicitation, who has {r1}, length 32` (option *source
link-address*: MAC of `m1`), `{r1} > {m1}: ICMP6, neighbor advertisement, tgt is {r1}, length 32` (flags
`[solicited, override]`), then `:: > {sollicite_m1}: ICMP6, neighbor solicitation, who has {m1}`. Question not
graded.
""",
    "Partie 2 — Routage statique": "Part 2 — Static routing",
    "Adresses et routes statiques": "Static addresses and routes",
    """
Déployez IPv6 sur le reste des machines statiques, d'après le plan d'adressage :

1. `r1` : adresse de `eth1` (vers l'opérateur), route par défaut vers `wan`, **routage IPv6 activé**
   (`net.ipv6.conf.all.forwarding`) ;
2. `r2` : ses trois adresses (`eth0` vers l'opérateur, `eth1` sur `lan2`, `eth2` sur `lan3`), route
   par défaut vers `wan`, routage activé ;
3. `m2` et `srv` : adresse et route par défaut vers `r2` ;
4. `m1` : route par défaut vers `r1`.

L'opérateur route le `/48` de chaque site vers `r1` ou `r2` : aucune route n'est à ajouter sur `wan`
(et vous ne le pourriez pas), ni sur `r1` / `r2` au-delà de leur route par défaut et de leurs réseaux
connectés. Vérifiez de proche en proche : `ping -6 wan_wan1` depuis `r1`, `ping -6 m2` et `ping -6 srv`
depuis `m1`, `traceroute -6 m1` depuis `m2`, `ip -6 route get` ; `tcpdump -n -i eth1 icmp6` sur `r1` montre
les échos et, en cas d'erreur, le type ICMPv6 que renvoie le routeur qui n'a pas de route.

Enfin, rendez la configuration IPv6 de `m1` et de `r1` **persistante** dans `/etc/network/interfaces`
(bloc `iface ethN inet6 static`, voir le cours ; les blocs `inet` IPv4 y sont déjà), et vérifiez
qu'elle s'applique : `ifdown eth0; ifup eth0` sur `m1` (sur `r1`, `ifdown eth1; ifup eth1`), puis
`ip -6 addr` et `ip -6 route`.
""": """
Deploy IPv6 on the rest of the static machines, following the addressing plan:

1. `r1`: address of `eth1` (towards the operator), default route to `wan`, **IPv6 routing enabled**
   (`net.ipv6.conf.all.forwarding`);
2. `r2`: its three addresses (`eth0` towards the operator, `eth1` on `lan2`, `eth2` on `lan3`), default
   route to `wan`, routing enabled;
3. `m2` and `srv`: address and default route to `r2`;
4. `m1`: default route to `r1`.

The operator routes the `/48` of each site to `r1` or `r2`: no route is to be added on `wan`
(and you could not), nor on `r1` / `r2` beyond their default route and their connected
networks. Check step by step: `ping -6 wan_wan1` from `r1`, `ping -6 m2` and `ping -6 srv`
from `m1`, `traceroute -6 m1` from `m2`, `ip -6 route get`; `tcpdump -n -i eth1 icmp6` on `r1` shows
the echoes and, in case of error, the ICMPv6 type sent back by the router that has no route.

Finally, make the IPv6 configuration of `m1` and `r1` **persistent** in `/etc/network/interfaces`
(stanza `iface ethN inet6 static`, see the course; the IPv4 `inet` stanzas are already there), and check
that it applies: `ifdown eth0; ifup eth0` on `m1` (on `r1`, `ifdown eth1; ifup eth1`), then
`ip -6 addr` and `ip -6 route`.
""",
    """
**Solution.** Sur `r1` :

```
ip -6 addr add {r1_wan1}/64 dev eth1
ip -6 route add default via {wan_wan1}
sysctl -w net.ipv6.conf.all.forwarding=1
```

Sur `r2` :

```
ip -6 addr add {r2_wan2}/64 dev eth0
ip -6 addr add {r2_lan2}/64 dev eth1
ip -6 addr add {r2_lan3}/64 dev eth2
ip -6 route add default via {wan_wan2}
sysctl -w net.ipv6.conf.all.forwarding=1
```

Sur `m2` : `ip -6 addr add {m2}/64 dev eth0; ip -6 route add default via {r2_lan2}` ; sur `srv` :
`ip -6 addr add {srv}/64 dev eth0; ip -6 route add default via {r2_lan3}` ; sur `m1` :
`ip -6 route add default via {r1_lan1}`.

`/etc/network/interfaces` de `m1` :

```
{interfaces_m1}
```

et de `r1` :

```
{interfaces_r1}
```

- Un routeur sans route renvoie `ICMP6, destination unreachable, unreachable route` (type 1, code 0).
- Évaluation : adresses et route par défaut de chaque machine (`ip a`, `ip -6 route`), `forwarding`
  à 1 sur `r1` et `r2` et à 0 sur les hôtes, blocs `inet6 static` de `m1` et `r1` (adresse et `gateway`),
  pings `h1` ↔ `h2`, `h3` → `m1`, `m2` → `srv`.
""": """
**Solution.** On `r1`:

```
ip -6 addr add {r1_wan1}/64 dev eth1
ip -6 route add default via {wan_wan1}
sysctl -w net.ipv6.conf.all.forwarding=1
```

On `r2`:

```
ip -6 addr add {r2_wan2}/64 dev eth0
ip -6 addr add {r2_lan2}/64 dev eth1
ip -6 addr add {r2_lan3}/64 dev eth2
ip -6 route add default via {wan_wan2}
sysctl -w net.ipv6.conf.all.forwarding=1
```

On `m2`: `ip -6 addr add {m2}/64 dev eth0; ip -6 route add default via {r2_lan2}`; on `srv`:
`ip -6 addr add {srv}/64 dev eth0; ip -6 route add default via {r2_lan3}`; on `m1`:
`ip -6 route add default via {r1_lan1}`.

`/etc/network/interfaces` of `m1`:

```
{interfaces_m1}
```

and of `r1`:

```
{interfaces_r1}
```

- A router without a route sends back `ICMP6, destination unreachable, unreachable route` (type 1, code 0).
- Evaluation: addresses and default route of each machine (`ip a`, `ip -6 route`), `forwarding`
  at 1 on `r1` and `r2` and at 0 on the hosts, `inet6 static` stanzas of `m1` and `r1` (address and `gateway`),
  pings `h1` ↔ `h2`, `h3` → `m1`, `m2` → `srv`.
""",
    "Routage": "Routing",
    """
- Ce que l'opérateur route vers chaque site : @@{agregat:>un préfixe /48 par site|un préfixe /64 par réseau|une route par machine}@@
- Type ICMPv6 du message « destination injoignable » renvoyé par un routeur sans route : @@{unreach_type:[0-9]+}@@
- Pour une route dont le prochain saut est une adresse de lien local, `ip -6 route add` exige en plus :
  @@{via_ll:>le nom de l'interface (dev)|une métrique|le préfixe du prochain saut}@@
- Les routes `proto kernel` de la table IPv6 décrivent : @@{kernel_route:>le réseau de chaque adresse|la route par défaut|les routes apprises des annonces}@@
""": """
- What the operator routes to each site: @@{agregat:>one /48 prefix per site>>>un préfixe /48 par site|one /64 prefix per network>>>un préfixe /64 par réseau|one route per machine>>>une route par machine}@@
- ICMPv6 type of the "destination unreachable" message sent back by a router without a route: @@{unreach_type:[0-9]+}@@
- For a route whose next hop is a link-local address, `ip -6 route add` also requires:
  @@{via_ll:>the name of the interface (dev)>>>le nom de l'interface (dev)|a metric>>>une métrique|the prefix of the next hop>>>le préfixe du prochain saut}@@
- The `proto kernel` routes of the IPv6 table describe: @@{kernel_route:>the network of each address>>>le réseau de chaque adresse|the default route>>>la route par défaut|the routes learnt from the advertisements>>>les routes apprises des annonces}@@
""",
    """
**Réponses.** `{agregat}` ; type `{unreach_type}` (code 0, *no route to destination*) ; `{via_ll}` ;
`{kernel_route}`.
""": """
**Answers.** `{agregat}`; type `{unreach_type}` (code 0, *no route to destination*); `{via_ll}`;
`{kernel_route}`.
""",
    "adresses IPv6 de r1 et route par défaut vers l'opérateur": "IPv6 addresses of r1 and default route to the operator",
    "trois adresses IPv6 de r2 et route par défaut vers l'opérateur": "three IPv6 addresses of r2 and default route to the operator",
    "adresse IPv6 de {m} et route par défaut vers r2": "IPv6 address of {m} and default route to r2",
    "route par défaut de m1 vers r1": "default route of m1 to r1",
    "routage IPv6 activé sur r1 et r2": "IPv6 routing enabled on r1 and r2",
    "routage IPv6 désactivé sur m1, m2 et srv": "IPv6 routing disabled on m1, m2 and srv",
    "configuration IPv6 persistante de {m} (/etc/network/interfaces)": "persistent IPv6 configuration of {m} (/etc/network/interfaces)",
    "ping -6 de h1 (lan1) vers h2 (lan2) à travers l'opérateur": "ping -6 from h1 (lan1) to h2 (lan2) across the operator",
    "ping -6 de h2 vers h1": "ping -6 from h2 to h1",
    "ping -6 de h3 (lan3) vers m1": "ping -6 from h3 (lan3) to m1",
    "ping -6 de m2 vers srv": "ping -6 from m2 to srv",
    "message d'erreur": "error message",
    "agrégation, prochain saut de lien local, routes du noyau": "aggregation, link-local next hop, kernel routes",
    "Partie 3 — Annonces de routeur et SLAAC sur lan3": "Part 3 — Router advertisements and SLAAC on lan3",
    "Annonces de routeur de r2 et autoconfiguration de pc1": "Router advertisements of r2 and autoconfiguration of pc1",
    """
`pc1` et `pc2`, sur `lan3`, n'ont que leur adresse de lien local (`ip -6 addr`, `ip -6 route`) : elles
attendent les **annonces de routeur** de `r2`.

1. Sur `pc1`, lancez `tcpdump -n -v -i eth0 icmp6` dans un second terminal : rien ne vient.
2. Sur `r2`, écrivez `/etc/radvd.conf` pour `eth2` : annonces activées, intervalle court
   (`MinRtrAdvInterval 3`, `MaxRtrAdvInterval 10`, pour ne pas attendre), le préfixe `{lan3}`
   avec les drapeaux *on-link* et *autonomous*, et l'option **RDNSS** avec l'adresse de `srv`
   (`{srv}`). Vérifiez la syntaxe (`radvd -c`), lancez le service (`systemctl restart radvd`) et
   vérifiez qu'il tourne (`pidof radvd`).
3. Sur `pc1`, lisez l'annonce dans la capture (drapeaux, durée de vie du routeur, préfixe, RDNSS),
   puis `ip -6 addr` et `ip -6 route` : d'où viennent l'adresse et la route par défaut ? Comparez
   l'adresse avec l'adresse MAC de `pc1`. Vérifiez `ping -6 {m1}` (l'adresse de `m1`) depuis `pc1`,
   et sur `r2` `ip -6 neigh`.
4. Sur `pc1`, `cat /etc/resolv.conf` : vide. Le noyau ne fait rien de l'option RDNSS (il y faudrait
   `rdnssd` ou NetworkManager) : `ping -6 m1` échoue sur le nom. La partie 4 y remédie.
5. Facultatif : `sysctl net.ipv6.conf.eth0.accept_ra`, `autoconf` sur `pc1` et `pc2`, et comparez
   `ip -6 addr` / `ip -6 route` de `pc2` (`autoconf=0` : la route sans l'adresse).
""": """
`pc1` and `pc2`, on `lan3`, only have their link-local address (`ip -6 addr`, `ip -6 route`): they
are waiting for the **router advertisements** of `r2`.

1. On `pc1`, start `tcpdump -n -v -i eth0 icmp6` in a second terminal: nothing comes.
2. On `r2`, write `/etc/radvd.conf` for `eth2`: advertisements enabled, short interval
   (`MinRtrAdvInterval 3`, `MaxRtrAdvInterval 10`, so as not to wait), the prefix `{lan3}`
   with the *on-link* and *autonomous* flags, and the **RDNSS** option with the address of `srv`
   (`{srv}`). Check the syntax (`radvd -c`), start the service (`systemctl restart radvd`) and
   check that it is running (`pidof radvd`).
3. On `pc1`, read the advertisement in the capture (flags, router lifetime, prefix, RDNSS),
   then `ip -6 addr` and `ip -6 route`: where do the address and the default route come from? Compare
   the address with the MAC address of `pc1`. Check `ping -6 {m1}` (the address of `m1`) from `pc1`,
   and on `r2` `ip -6 neigh`.
4. On `pc1`, `cat /etc/resolv.conf`: empty. The kernel does nothing with the RDNSS option (that
   would take `rdnssd` or NetworkManager): `ping -6 m1` fails on the name. Part 4 remedies this.
5. Optional: `sysctl net.ipv6.conf.eth0.accept_ra`, `autoconf` on `pc1` and `pc2`, and compare
   `ip -6 addr` / `ip -6 route` of `pc2` (`autoconf=0`: the route without the address).
""",
    """
**Solution.** `/etc/radvd.conf` sur `r2` :

```
{radvd}
```

puis `radvd -c`, `systemctl restart radvd`, `pidof radvd` (le routage IPv6 de la partie 2 doit être
actif : radvd refuse de fonctionner sans).

- `pc1` obtient `{pc1}/64` (EUI-64 de sa MAC `{mac_pc1}` : `ff:fe` au milieu, bit U/L inversé) marquée
  `dynamic mngtmpaddr`, et `default via {ll_r2} dev eth0 proto ra metric 1024 expires …` : le prochain
  saut est l'adresse de lien local de `r2` sur `eth2`, la durée de vie celle du routeur (3 × `MaxRtrAdvInterval`
  par défaut).
- Dans la capture : `ICMP6, router advertisement, length 96 … hop limit 64, Flags [none], pref medium,
  router lifetime 30s …, prefix info option (3) … {lan3}, Flags [onlink, auto] …, rdnss option (25)
  … {srv}, dnssl option (31)`.
- Évaluation : la sonde `h3` envoie un RS et lit le RA (préfixe avec A et L, RDNSS, durée de vie du
  routeur, émetteur en lien local), `ip -j -6 addr` et la route par défaut (`protocol ra`) de `pc1`,
  `pidof radvd` sur `r2`, pings `h3` → `pc1` et `pc1` → `m1`.
""": """
**Solution.** `/etc/radvd.conf` on `r2`:

```
{radvd}
```

then `radvd -c`, `systemctl restart radvd`, `pidof radvd` (the IPv6 routing of part 2 must be
on: radvd refuses to work without it).

- `pc1` gets `{pc1}/64` (EUI-64 of its MAC `{mac_pc1}`: `ff:fe` in the middle, U/L bit inverted) marked
  `dynamic mngtmpaddr`, and `default via {ll_r2} dev eth0 proto ra metric 1024 expires …`: the next
  hop is the link-local address of `r2` on `eth2`, the lifetime that of the router (3 × `MaxRtrAdvInterval`
  by default).
- In the capture: `ICMP6, router advertisement, length 96 … hop limit 64, Flags [none], pref medium,
  router lifetime 30s …, prefix info option (3) … {lan3}, Flags [onlink, auto] …, rdnss option (25)
  … {srv}, dnssl option (31)`.
- Evaluation: the probe `h3` sends an RS and reads the RA (prefix with A and L, RDNSS, router
  lifetime, link-local sender), `ip -j -6 addr` and the default route (`protocol ra`) of `pc1`,
  `pidof radvd` on `r2`, pings `h3` → `pc1` and `pc1` → `m1`.
""",
    "Ce que pc1 a reçu": "What pc1 received",
    """
- Adresse globale obtenue par `pc1` : @@{adresse_pc1:[0-9a-fA-F:/]+}@@
- Prochain saut de sa route par défaut : @@{next_hop:[0-9a-fA-F:%/]+}@@
- Types ICMPv6 de la sollicitation de routeur : @@{rs_type:[0-9]+}@@ et de l'annonce : @@{ra_type:[0-9]+}@@
- La route par défaut de `pc1` vient de : @@{route_source:>l'annonce de routeur (durée de vie du routeur)|l'option préfixe|DHCPv6|une configuration manuelle}@@
- Drapeau **A** (*autonomous*) d'un préfixe annoncé : @@{flag_a:>les machines forment une adresse avec ce préfixe (SLAAC)|le préfixe est joignable directement sur le lien|les adresses viennent de DHCPv6}@@
- Drapeau **L** (*on-link*) : @@{flag_l:>le préfixe est joignable directement sur le lien|les machines forment une adresse avec ce préfixe (SLAAC)|le routeur est la route par défaut}@@
""": """
- Global address obtained by `pc1`: @@{adresse_pc1:[0-9a-fA-F:/]+}@@
- Next hop of its default route: @@{next_hop:[0-9a-fA-F:%/]+}@@
- ICMPv6 types of the router solicitation: @@{rs_type:[0-9]+}@@ and of the advertisement: @@{ra_type:[0-9]+}@@
- The default route of `pc1` comes from: @@{route_source:>the router advertisement (router lifetime)>>>l'annonce de routeur (durée de vie du routeur)|the prefix option>>>l'option préfixe|DHCPv6|a manual configuration>>>une configuration manuelle}@@
- Flag **A** (*autonomous*) of an advertised prefix: @@{flag_a:>the machines form an address from this prefix (SLAAC)>>>les machines forment une adresse avec ce préfixe (SLAAC)|the prefix is reachable directly on the link>>>le préfixe est joignable directement sur le lien|the addresses come from DHCPv6>>>les adresses viennent de DHCPv6}@@
- Flag **L** (*on-link*): @@{flag_l:>the prefix is reachable directly on the link>>>le préfixe est joignable directement sur le lien|the machines form an address from this prefix (SLAAC)>>>les machines forment une adresse avec ce préfixe (SLAAC)|the router is the default route>>>le routeur est la route par défaut}@@
""",
    """
**Réponses.** adresse `{adresse_pc1}` ; prochain saut `{next_hop}` (lien local de `r2` eth2 ; la valeur
réellement installée sur `pc1` est acceptée) ; RS `{rs_type}`, RA `{ra_type}` ; {route_source} ;
A : {flag_a} ; L : {flag_l}.
""": """
**Answers.** address `{adresse_pc1}`; next hop `{next_hop}` (link-local of `r2` eth2; the value
really installed on `pc1` is accepted); RS `{rs_type}`, RA `{ra_type}`; {route_source};
A: {flag_a}; L: {flag_l}.
""",
    "r2 annonce le préfixe {lan3} avec les drapeaux A et L": "r2 advertises the prefix {lan3} with the A and L flags",
    "l'annonce fait de r2 un routeur par défaut (durée de vie non nulle)": "the advertisement makes r2 a default router (non-zero lifetime)",
    "option RDNSS de l'annonce : le serveur DNS srv": "RDNSS option of the advertisement: the DNS server srv",
    "radvd tourne sur r2": "radvd runs on r2",
    "pc1 a une adresse automatique dans {lan3}": "pc1 has an automatic address in {lan3}",
    "l'adresse de pc1 est l'EUI-64 de son adresse MAC ({pc1})": "the address of pc1 is the EUI-64 of its MAC address ({pc1})",
    "route par défaut de pc1 apprise de l'annonce (prochain saut de lien local, proto ra)": "default route of pc1 learnt from the advertisement (link-local next hop, proto ra)",
    "ping -6 de h3 vers l'adresse SLAAC de pc1": "ping -6 from h3 to the SLAAC address of pc1",
    "ping -6 de pc1 vers m1 (route par défaut apprise, routage de r2)": "ping -6 from pc1 to m1 (learnt default route, routing by r2)",
    "adresse et prochain saut relevés sur pc1": "address and next hop read on pc1",
    "types RS / RA": "RS / RA types",
    "origine de la route par défaut, drapeaux A et L": "origin of the default route, A and L flags",
    "Partie 4 — DHCPv6 sur srv": "Part 4 — DHCPv6 on srv",
    "DHCPv6 sans état : le DNS pour pc1": "Stateless DHCPv6: the DNS for pc1",
    """
`srv` (image avec systemd) sera le serveur DHCPv6 de `lan3`. Commencez par le mode **sans état** :
`pc1` garde son adresse SLAAC et ne demande que les paramètres DNS.

1. Sur `r2`, ajoutez `AdvOtherConfigFlag on;` (drapeau **O**) à l'interface `eth2` de `radvd.conf`
   et relancez radvd.
2. Sur `srv` : `INTERFACESv6="eth0"` dans `/etc/default/isc-dhcp-server`, puis `/etc/dhcp/dhcpd6.conf`
   avec les options `dhcp6.name-servers` (`{srv}`) et `dhcp6.domain-search` (`{domain}`), la durée
   `default-lease-time {lease6}` (utile dès la question suivante) et une déclaration `subnet6` pour
   `{lan3}` **sans `range6`**. Vérifiez la syntaxe (`dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`), lancez
   `systemctl restart isc-dhcp-server`, contrôlez `journalctl -u isc-dhcp-server` et
   `ps -C dhcpd -o pid,args`.
3. Sur `pc1`, capturez `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` puis lancez
   `dhclient -6 -S -v eth0`. Relevez les messages échangés, l'adresse de destination et les ports,
   puis `cat /etc/resolv.conf` et `ping -6 -c 2 m1` (le nom, cette fois).
""": """
`srv` (image with systemd) will be the DHCPv6 server of `lan3`. Start with the **stateless** mode:
`pc1` keeps its SLAAC address and only asks for the DNS parameters.

1. On `r2`, add `AdvOtherConfigFlag on;` (**O** flag) to the `eth2` interface of `radvd.conf`
   and restart radvd.
2. On `srv`: `INTERFACESv6="eth0"` in `/etc/default/isc-dhcp-server`, then `/etc/dhcp/dhcpd6.conf`
   with the options `dhcp6.name-servers` (`{srv}`) and `dhcp6.domain-search` (`{domain}`), the
   lifetime `default-lease-time {lease6}` (useful from the next question on) and a `subnet6`
   declaration for `{lan3}` **without `range6`**. Check the syntax (`dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`),
   run `systemctl restart isc-dhcp-server`, check `journalctl -u isc-dhcp-server` and
   `ps -C dhcpd -o pid,args`.
3. On `pc1`, capture `tcpdump -n -v -i eth0 'udp port 546 or udp port 547'` then run
   `dhclient -6 -S -v eth0`. Note the messages exchanged, the destination address and the ports,
   then `cat /etc/resolv.conf` and `ping -6 -c 2 m1` (the name, this time).
""",
    """
**Solution.** `radvd.conf` de `r2` avec le drapeau O :

```
{radvd}
```

Sur `srv`, `/etc/default/isc-dhcp-server` :

```
{defaults}
```

`/etc/dhcp/dhcpd6.conf` (sans état) :

```
{conf}
```

puis `dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`, `systemctl restart isc-dhcp-server`. Sur `pc1` :
`dhclient -6 -S -v eth0` affiche `XMT: Info-Request on eth0, interval …` puis `RCV: Reply message on
eth0 from fe80::…` ; `/etc/resolv.conf` contient `search {domain}` et `nameserver {srv}`.

- Capture : `fe80::… .546 > ff02::1:2.547: dhcp6 inf-req` puis `… .547 > … .546: dhcp6 reply` avec les
  options `client-ID`, `server-ID`, `DNS-server`, `DNS-search-list`.
- Le `subnet6` est exigé même sans adresse à distribuer : `dhcpd` doit trouver l'adresse globale de
  `eth0` dedans (`No subnet6 declaration for eth0` sinon) ; la partie 2 doit donc être faite.
- Évaluation : drapeau O lu par la sonde, INFORMATION-REQUEST de la sonde → REPLY avec le serveur DNS
  et le domaine, `dhcpd -6` lancé sur `eth0` seulement (ligne de commande), `resolv.conf` de `pc1` et
  `getent ahostsv6 m1` sur `pc1`.
""": """
**Solution.** `radvd.conf` of `r2` with the O flag:

```
{radvd}
```

On `srv`, `/etc/default/isc-dhcp-server`:

```
{defaults}
```

`/etc/dhcp/dhcpd6.conf` (stateless):

```
{conf}
```

then `dhcpd -t -6 -cf /etc/dhcp/dhcpd6.conf`, `systemctl restart isc-dhcp-server`. On `pc1`:
`dhclient -6 -S -v eth0` prints `XMT: Info-Request on eth0, interval …` then
`RCV: Reply message on eth0 from fe80::…`; `/etc/resolv.conf` contains `search {domain}` and
`nameserver {srv}`.

- Capture: `fe80::… .546 > ff02::1:2.547: dhcp6 inf-req` then `… .547 > … .546: dhcp6 reply` with the
  options `client-ID`, `server-ID`, `DNS-server`, `DNS-search-list`.
- The `subnet6` is required even with no address to hand out: `dhcpd` must find the global address of
  `eth0` in it (`No subnet6 declaration for eth0` otherwise); part 2 must therefore be done.
- Evaluation: O flag read by the probe, INFORMATION-REQUEST of the probe → REPLY with the DNS server
  and the domain, `dhcpd -6` started on `eth0` only (command line), `resolv.conf` of `pc1` and
  `getent ahostsv6 m1` on `pc1`.
""",
    "Le protocole": "The protocol",
    """
- Port UDP du client DHCPv6 : @@{port_client:[0-9]+}@@ ; du serveur : @@{port_serveur:[0-9]+}@@
- Adresse de destination de la requête de `pc1` : @@{multicast:[0-9a-fA-F:]+}@@
- Messages échangés en mode sans état : @@{msg_req:>INFORMATION-REQUEST|SOLICIT|REQUEST|DHCPINFORM}@@ puis
  @@{msg_rep:>REPLY|ADVERTISE|ACK|OFFER}@@
- DHCPv6 peut-il donner la route par défaut ? @@{route6:>non : elle vient toujours de l'annonce de routeur|oui, par une option comme routers en IPv4|oui, c'est le serveur qui la choisit}@@
""": """
- UDP port of the DHCPv6 client: @@{port_client:[0-9]+}@@; of the server: @@{port_serveur:[0-9]+}@@
- Destination address of the request of `pc1`: @@{multicast:[0-9a-fA-F:]+}@@
- Messages exchanged in stateless mode: @@{msg_req:>INFORMATION-REQUEST|SOLICIT|REQUEST|DHCPINFORM}@@ then
  @@{msg_rep:>REPLY|ADVERTISE|ACK|OFFER}@@
- Can DHCPv6 provide the default route? @@{route6:>no: it always comes from the router advertisement>>>non : elle vient toujours de l'annonce de routeur|yes, through an option like routers in IPv4>>>oui, par une option comme routers en IPv4|yes, the server chooses it>>>oui, c'est le serveur qui la choisit}@@
""",
    """
**Réponses.** client `{port_client}`, serveur `{port_serveur}` ; destination `{multicast}` (tous les serveurs et
relais DHCPv6 du lien) ; `{msg_req}` puis `{msg_rep}` ; {route6}.
""": """
**Answers.** client `{port_client}`, server `{port_serveur}`; destination `{multicast}` (all the DHCPv6
servers and relays on the link); `{msg_req}` then `{msg_rep}`; {route6}.
""",
    "DHCPv6 avec état : une adresse pour pc2": "Stateful DHCPv6: an address for pc2",
    """
`pc2` est réglée pour **ne pas** former d'adresse automatique (`autoconf=0`) tout en acceptant la route
par défaut des annonces : c'est un poste qui attend son adresse d'un serveur.

1. Sur `r2`, ajoutez `AdvManagedFlag on;` (drapeau **M**) et relancez radvd.
2. Sur `srv`, ajoutez au `subnet6` la plage `range6 {pool_min} {pool_max}` et relancez le service.
3. Sur `pc2`, capturez puis lancez `dhclient -6 -D LL -v eth0` (DUID de type **LL**, déduit de
   l'adresse MAC ; sans `-D LL`, le client fabrique un DUID-LLT horodaté). Relevez les quatre messages,
   puis `ip -6 addr` (préfixe et durées de vie de l'adresse reçue), `ip -6 route` (d'où vient la route
   par défaut ?), `/etc/resolv.conf`, `ping -6 -c 2 m1`.
4. Lisez le bail dans `/var/lib/dhcp/dhclient6.leases` sur `pc2` (`default-duid`, `iaaddr`,
   `max-life`) et, sur `srv`, le journal (`Solicit message from … duid …`) et
   `/var/lib/dhcp/dhcpd6.leases`.
""": """
`pc2` is set **not** to form an automatic address (`autoconf=0`) while accepting the default route
of the advertisements: it is a host that waits for its address from a server.

1. On `r2`, add `AdvManagedFlag on;` (**M** flag) and restart radvd.
2. On `srv`, add the range `range6 {pool_min} {pool_max}` to the `subnet6` and restart the service.
3. On `pc2`, capture then run `dhclient -6 -D LL -v eth0` (DUID of type **LL**, derived from the
   MAC address; without `-D LL`, the client makes a timestamped DUID-LLT). Note the four messages,
   then `ip -6 addr` (prefix and lifetimes of the address received), `ip -6 route` (where does the
   default route come from?), `/etc/resolv.conf`, `ping -6 -c 2 m1`.
4. Read the lease in `/var/lib/dhcp/dhclient6.leases` on `pc2` (`default-duid`, `iaaddr`,
   `max-life`) and, on `srv`, the journal (`Solicit message from … duid …`) and
   `/var/lib/dhcp/dhcpd6.leases`.
""",
    """
**Solution.** `radvd.conf` avec M et O :

```
{radvd}
```

`dhcpd6.conf` avec la plage :

```
{conf}
```

puis `systemctl restart radvd` sur `r2`, `systemctl restart isc-dhcp-server` sur `srv`, et sur `pc2`
`dhclient -6 -D LL -v eth0` : `XMT: Solicit`, `RCV: Advertise`, `XMT: Request`, `RCV: Reply`, `bound to
{pool_min}…` (une adresse de la plage, en `/128`, `valid_lft {lease6}sec`).

- La route par défaut de `pc2` est `via {ll_r2} … proto ra` : DHCPv6 n'en donne jamais.
- DUID-LL de `pc2` : `{pc2_duid}` (`00:03` + `00:01` + MAC `{mac_pc2}`) ; le journal de `srv` l'écrit en
  hexadécimal, le fichier de baux de `pc2` en octal (`default-duid "\\000\\003\\000\\001…"`).
- Évaluation : drapeau M, SOLICIT de la sonde → ADVERTISE avec une adresse de la plage et une durée de
  validité de {lease6} s, adresse `dynamic` de `pc2` dans la plage (ou l'adresse réservée de la question
  suivante) inscrite dans son fichier de baux, route par défaut de `pc2` apprise du RA, `getent ahostsv6 m1`
  sur `pc2`.
""": """
**Solution.** `radvd.conf` with M and O:

```
{radvd}
```

`dhcpd6.conf` with the range:

```
{conf}
```

then `systemctl restart radvd` on `r2`, `systemctl restart isc-dhcp-server` on `srv`, and on `pc2`
`dhclient -6 -D LL -v eth0`: `XMT: Solicit`, `RCV: Advertise`, `XMT: Request`, `RCV: Reply`, `bound to
{pool_min}…` (an address of the range, as a `/128`, `valid_lft {lease6}sec`).

- The default route of `pc2` is `via {ll_r2} … proto ra`: DHCPv6 never gives one.
- DUID-LL of `pc2`: `{pc2_duid}` (`00:03` + `00:01` + MAC `{mac_pc2}`); the journal of `srv` writes it in
  hexadecimal, the lease file of `pc2` in octal (`default-duid "\\000\\003\\000\\001…"`).
- Evaluation: M flag, SOLICIT of the probe → ADVERTISE with an address of the range and a valid
  lifetime of {lease6} s, `dynamic` address of `pc2` in the range (or the reserved address of the next
  question) recorded in its lease file, default route of `pc2` learnt from the RA, `getent ahostsv6 m1`
  on `pc2`.
""",
    "Le bail de pc2": "The lease of pc2",
    """
- DUID de `pc2` (octets en hexadécimal séparés par `:`) : @@{duid_pc2:[0-9a-fA-F:-]+}@@
- Longueur du préfixe de l'adresse posée par `dhclient` sur `eth0` : @@{prefixlen:[0-9]+}@@
- Les quatre messages de l'obtention d'une adresse : @@{msg1:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis
  @@{msg2:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis @@{msg3:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ puis
  @@{msg4:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@
- Durée de validité de l'adresse (`max-life` dans le bail), en secondes : @@{valid:[0-9]+}@@
""": """
- DUID of `pc2` (bytes in hexadecimal separated by `:`): @@{duid_pc2:[0-9a-fA-F:-]+}@@
- Prefix length of the address set by `dhclient` on `eth0`: @@{prefixlen:[0-9]+}@@
- The four messages for obtaining an address: @@{msg1:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ then
  @@{msg2:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ then @@{msg3:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@ then
  @@{msg4:>SOLICIT|ADVERTISE|REQUEST|REPLY}@@
- Valid lifetime of the address (`max-life` in the lease), in seconds: @@{valid:[0-9]+}@@
""",
    """
**Réponses.** DUID `{duid_pc2}` ; préfixe `/{prefixlen}` (le préfixe du lien vient du RA, drapeau L) ;
`{msg1}`, `{msg2}`, `{msg3}`, `{msg4}` ; validité `{valid}` s (`default-lease-time`).
""": """
**Answers.** DUID `{duid_pc2}`; prefix `/{prefixlen}` (the prefix of the link comes from the RA, L flag);
`{msg1}`, `{msg2}`, `{msg3}`, `{msg4}`; valid lifetime `{valid}` s (`default-lease-time`).
""",
    "Réservation par DUID": "Reservation by DUID",
    """
`pc2` doit toujours recevoir l'adresse **`{pc2_fixe}`** (hors de la plage).

1. Sur `srv`, déclarez un bloc `host` identifié par le DUID de `pc2` (`host-identifier option
   dhcp6.client-id …`) avec `fixed-address6`, et relancez le service.
2. Sur `pc2`, libérez l'adresse (`dhclient -6 -D LL -r eth0`) puis redemandez-en une
   (`dhclient -6 -D LL -v eth0`) : vérifiez `ip -6 addr` et le journal de `srv`.
""": """
`pc2` must always receive the address **`{pc2_fixe}`** (outside the range).

1. On `srv`, declare a `host` block identified by the DUID of `pc2` (`host-identifier option
   dhcp6.client-id …`) with `fixed-address6`, and restart the service.
2. On `pc2`, release the address (`dhclient -6 -D LL -r eth0`) then ask for one again
   (`dhclient -6 -D LL -v eth0`): check `ip -6 addr` and the journal of `srv`.
""",
    """
**Solution.** À ajouter à `dhcpd6.conf` sur `srv` (fichier complet) :

```
{conf}
```

puis `systemctl restart isc-dhcp-server` ; sur `pc2`, `dhclient -6 -D LL -r eth0` puis
`dhclient -6 -D LL -v eth0` : `bound to {pc2_fixe}`.

- Piège : le DUID est conservé dans `/var/lib/dhcp/dhclient6.leases` ; un client lancé une première fois
  sans `-D LL` garde son DUID-LLT et la réservation ne s'applique pas (le journal de `srv` montre le DUID
  reçu). Remède : libérer, `pkill dhclient`, supprimer le fichier de baux, relancer avec `-D LL`.
- Évaluation : SOLICIT de la sonde avec le DUID-LL de `pc2` → ADVERTISE de `{pc2_fixe}` ; adresse `dynamic`
  de `pc2` égale à `{pc2_fixe}`.
""": """
**Solution.** To be added to `dhcpd6.conf` on `srv` (complete file):

```
{conf}
```

then `systemctl restart isc-dhcp-server`; on `pc2`, `dhclient -6 -D LL -r eth0` then
`dhclient -6 -D LL -v eth0`: `bound to {pc2_fixe}`.

- Trap: the DUID is kept in `/var/lib/dhcp/dhclient6.leases`; a client started a first time
  without `-D LL` keeps its DUID-LLT and the reservation does not apply (the journal of `srv` shows the
  DUID received). Remedy: release, `pkill dhclient`, delete the lease file, start again with `-D LL`.
- Evaluation: SOLICIT of the probe with the DUID-LL of `pc2` → ADVERTISE of `{pc2_fixe}`; `dynamic` address
  of `pc2` equal to `{pc2_fixe}`.
""",
    "drapeau O (other config) dans les annonces de r2": "O flag (other config) in the advertisements of r2",
    "dhcpd -6 tourne sur srv, sur eth0 uniquement": "dhcpd -6 runs on srv, on eth0 only",
    "REPLY à une INFORMATION-REQUEST : serveur DNS srv et domaine {domain}": "REPLY to an INFORMATION-REQUEST: DNS server srv and domain {domain}",
    "resolv.conf de pc1 écrit par dhclient -6 -S": "resolv.conf of pc1 written by dhclient -6 -S",
    "pc1 résout le nom m1 (serveur DNS reçu par DHCPv6)": "pc1 resolves the name m1 (DNS server received through DHCPv6)",
    "drapeau M (managed) dans les annonces de r2": "M flag (managed) in the advertisements of r2",
    "ADVERTISE à un SOLICIT : adresse de la plage {pool_min} – {pool_max}, validité {lease6} s": "ADVERTISE to a SOLICIT: address of the range {pool_min} – {pool_max}, valid lifetime {lease6} s",
    "pc2 a obtenu par DHCPv6 une adresse de la plage ou l'adresse réservée, inscrite dans son bail": "pc2 obtained through DHCPv6 an address of the range or the reserved address, recorded in its lease",
    "route par défaut de pc2 apprise de l'annonce de routeur": "default route of pc2 learnt from the router advertisement",
    "pc2 résout le nom m1": "pc2 resolves the name m1",
    "srv propose {pc2_fixe} au DUID de pc2": "srv offers {pc2_fixe} to the DUID of pc2",
    "pc2 a reçu l'adresse réservée {pc2_fixe}": "pc2 received the reserved address {pc2_fixe}",
    "ports, adresse multicast": "ports, multicast address",
    "messages sans état, route par défaut": "stateless messages, default route",
    "DUID de pc2, préfixe de l'adresse, durée de validité": "DUID of pc2, prefix of the address, valid lifetime",
    "ordre des messages": "order of the messages",
    "Partie 5 — MTU, Packet Too Big et trou noir en double pile": "Part 5 — MTU, Packet Too Big and black hole in dual stack",
    "Découverte du PMTU en IPv6": "PMTU discovery in IPv6",
    """
Les liens de l'opérateur (`wan`) ont un MTU inférieur à 1500. Dans cette partie et la suivante,
`m1`, `m2`, `r1` et `r2` sont les machines des deux sites (cours, sections @@ref:mtu@@ et @@ref:tunnels@@).

1. Sur `m1`, lancez `tcpdump -n -v -i eth0 icmp6` dans un second terminal, puis
   `ping -6 -c 3 -M do -s 1452 m2`. Relevez le message d'erreur, la machine qui l'émet et le MTU
   annoncé ; comparez avec `ping -4 -c 3 -M do -s 1472 m2` (faites `ip route flush cache` et
   `ip -6 route flush cache` entre deux essais pour repartir d'un cache vide). Consultez
   `ip -6 route get` vers `m2` et `tracepath -6 -n m2`.
2. Par dichotomie avec `ping -6 -M do -s TAILLE m2`, trouvez la plus grande charge utile qui
   traverse l'opérateur sans erreur, et comparez avec la valeur IPv4.
3. Fragmentation : `ping -6 -c 4 -s 3000 m2` (sans `-M do`), caches vidés au préalable. Observez
   avec `tcpdump -n -i eth1 ip6` sur `r1` : qui découpe le paquet, en combien de fragments
   (`frag (décalage|taille)`), et quel en-tête d'extension les porte ? Pourquoi les premiers
   essais échouent-ils avant qu'un essai réussisse (pensez à la réponse de `m2`, aussi grosse que
   la demande) ? Comparez avec `ping -4 -c 2 -s 3000 m2` : en IPv4 `wan` refragmente ce que `m1` a
   déjà découpé en 1500 et le premier essai réussit.
4. Déduisez-en le MSS TCP qu'un hôte devrait annoncer en IPv6 pour que ses segments traversent
   l'opérateur, et vérifiez-le pendant un `iperf3 -6 -c m2` (`iperf3 -s` sur `m2`) avec `ss -ti` sur `m1`.
""": """
The links of the operator (`wan`) have an MTU below 1500. In this part and the next one,
`m1`, `m2`, `r1` and `r2` are the machines of the two sites (course, sections @@ref:mtu@@ and @@ref:tunnels@@).

1. On `m1`, start `tcpdump -n -v -i eth0 icmp6` in a second terminal, then
   `ping -6 -c 3 -M do -s 1452 m2`. Note the error message, the machine that sends it and the MTU
   announced; compare with `ping -4 -c 3 -M do -s 1472 m2` (run `ip route flush cache` and
   `ip -6 route flush cache` between two attempts to start again from an empty cache). Look at
   `ip -6 route get` towards `m2` and `tracepath -6 -n m2`.
2. By bisection with `ping -6 -M do -s SIZE m2`, find the largest payload that crosses the
   operator without error, and compare with the IPv4 value.
3. Fragmentation: `ping -6 -c 4 -s 3000 m2` (without `-M do`), caches flushed beforehand. Observe
   with `tcpdump -n -i eth1 ip6` on `r1`: who cuts the packet, into how many fragments
   (`frag (offset|size)`), and which extension header carries them? Why do the first attempts
   fail before one succeeds (think of the reply of `m2`, as big as the request)? Compare with
   `ping -4 -c 2 -s 3000 m2`: in IPv4 `wan` re-fragments what `m1` has already cut into 1500 and
   the first attempt succeeds.
4. Deduce from this the TCP MSS that a host should advertise in IPv6 for its segments to cross the
   operator, and check it during an `iperf3 -6 -c m2` (`iperf3 -s` on `m2`) with `ss -ti` on `m1`.
""",
    """
**Solution.** Sur `m1`, caches vidés (`ip route flush cache; ip -6 route flush cache`) :

```
ping -6 -c 3 -M do -s 1452 m2  # From wan_wan1 ({wan1v6}) icmp_seq=1 Packet too big: mtu={n}
# puis, deux fois : ping: sendmsg: Message too long
ping -4 -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1v4}) icmp_seq=1 Frag needed and DF set (mtu = {n})
ip -6 route get {m2v6}  # ... expires ...sec mtu {n}
tracepath -6 -n m2  # Resume: pmtu {n} hops 4 back 4
ping -6 -c 1 -M do -s {charge6} m2  # passe : {charge6} + 48 = {n} (IPv4 : {charge4} + 28 = {n})
ping -6 -c 1 -M do -s {charge61} m2  # refusé
ping -6 -c 4 -s 3000 m2  # deux essais perdus, puis des réponses
ping -4 -c 2 -s 3000 m2  # réussit dès le premier essai
```

- L'erreur est un ICMPv6 type 2 (*Packet Too Big*) émis par `wan` (son adresse côté `wan1`) ; `tcpdump`
  affiche `ICMP6, packet too big, mtu {n}`.
- `ping -6 -s 3000` : `m1` découpe d'abord pour son lien à 1500 (`frag (0|1448)`, `frag (1448|1448)`,
  `frag (2896|112)`, en-tête *Fragment*, *next header* 44). `wan` ne fragmente pas : il répond *Packet Too
  Big*. Au deuxième essai `m1` découpe pour {n} (`frag (0|{frag6})`…) et le paquet arrive, mais la réponse
  de `m2`, aussi grosse, est perdue à son tour : `m2` doit lui aussi apprendre le PMTU. Les essais suivants
  passent.
- En IPv4 `m1` découpe en 1500 puis `wan` refragmente : aucun apprentissage n'est nécessaire.
- MSS IPv6 : {n} − 60 = **{mss6}** ; `ss -ti` affiche 12 octets de moins (option *timestamps*).
""": """
**Solution.** On `m1`, caches flushed (`ip route flush cache; ip -6 route flush cache`):

```
ping -6 -c 3 -M do -s 1452 m2  # From wan_wan1 ({wan1v6}) icmp_seq=1 Packet too big: mtu={n}
# then, twice: ping: sendmsg: Message too long
ping -4 -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1v4}) icmp_seq=1 Frag needed and DF set (mtu = {n})
ip -6 route get {m2v6}  # ... expires ...sec mtu {n}
tracepath -6 -n m2  # Resume: pmtu {n} hops 4 back 4
ping -6 -c 1 -M do -s {charge6} m2  # gets through: {charge6} + 48 = {n} (IPv4: {charge4} + 28 = {n})
ping -6 -c 1 -M do -s {charge61} m2  # refused
ping -6 -c 4 -s 3000 m2  # two attempts lost, then replies
ping -4 -c 2 -s 3000 m2  # succeeds from the first attempt
```

- The error is an ICMPv6 type 2 (*Packet Too Big*) sent by `wan` (its address on the `wan1` side); `tcpdump`
  shows `ICMP6, packet too big, mtu {n}`.
- `ping -6 -s 3000`: `m1` first cuts for its 1500 link (`frag (0|1448)`, `frag (1448|1448)`,
  `frag (2896|112)`, *Fragment* header, *next header* 44). `wan` does not fragment: it answers *Packet Too
  Big*. At the second attempt `m1` cuts for {n} (`frag (0|{frag6})`…) and the packet arrives, but the reply
  of `m2`, just as big, is lost in turn: `m2` too must learn the PMTU. The following attempts
  get through.
- In IPv4 `m1` cuts into 1500 then `wan` re-fragments: no learning is needed.
- IPv6 MSS: {n} − 60 = **{mss6}**; `ss -ti` shows 12 bytes less (*timestamps* option).
""",
    "Mesures": "Measurements",
    """
- Plus grande charge utile de `ping -6 -M do -s` qui traverse l'opérateur sans erreur : @@{charge_v6:[0-9]+}@@ ;
  la même en IPv4 (`ping -4 -M do -s`) : @@{charge_v4:[0-9]+}@@
- Message ICMPv6 reçu par `m1` : type @@{icmpv6_type:[0-9]+}@@, émis par @@{emetteur:>m2|wan|r1|r2}@@
- Pour `ping -6 -s 3000 m2`, la ou les machines qui fragmentent : @@{qui_v6:>m1 uniquement|wan uniquement|m1 puis wan|r1|n'importe quel routeur}@@
- Valeur du champ *next header* qui annonce un en-tête Fragment : @@{next_header:[0-9]+}@@
- MSS TCP (sans option) adapté au lien de l'opérateur en IPv6 : @@{mss_v6:[0-9]+}@@
""": """
- Largest payload of `ping -6 -M do -s` that crosses the operator without error: @@{charge_v6:[0-9]+}@@;
  the same in IPv4 (`ping -4 -M do -s`): @@{charge_v4:[0-9]+}@@
- ICMPv6 message received by `m1`: type @@{icmpv6_type:[0-9]+}@@, sent by @@{emetteur:>m2|wan|r1|r2}@@
- For `ping -6 -s 3000 m2`, the machine or machines that fragment: @@{qui_v6:>m1 only>>>m1 uniquement|wan only>>>wan uniquement|m1 then wan>>>m1 puis wan|r1|any router>>>n'importe quel routeur}@@
- Value of the *next header* field that announces a Fragment header: @@{next_header:[0-9]+}@@
- TCP MSS (without options) suited to the operator's link in IPv6: @@{mss_v6:[0-9]+}@@
""",
    """
**Réponses.**

- charge utile maximale : `{charge_v6}` en IPv6 ({n} − 40 − 8), `{charge_v4}` en IPv4 ({n} − 20 − 8)
- ICMPv6 type `{icmpv6_type}` (*Packet Too Big*), émis par `{emetteur}`
- fragmentation : `{qui_v6}` (un routeur IPv6 ne fragmente jamais) ; *next header* `{next_header}`
- MSS : `{mss_v6}` ({n} − 60)
""": """
**Answers.**

- maximum payload: `{charge_v6}` in IPv6 ({n} − 40 − 8), `{charge_v4}` in IPv4 ({n} − 20 − 8)
- ICMPv6 type `{icmpv6_type}` (*Packet Too Big*), sent by `{emetteur}`
- fragmentation: `{qui_v6}` (an IPv6 router never fragments); *next header* `{next_header}`
- MSS: `{mss_v6}` ({n} − 60)
""",
    "plus grandes charges utiles de ping -M do qui traversent (IPv6 et IPv4)": "largest payloads of ping -M do that get through (IPv6 and IPv4)",
    "type du message Packet Too Big": "type of the Packet Too Big message",
    "émetteur du message Packet Too Big": "sender of the Packet Too Big message",
    "next header de l'en-tête Fragment": "next header of the Fragment header",
    "en IPv6 seule la source fragmente": "in IPv6 only the source fragments",
    "MSS TCP IPv6 adapté au lien de l'opérateur": "IPv6 TCP MSS suited to the operator's link",
    "Trou noir PMTUD en double pile": "PMTUD black hole in dual stack",
    """
1. Lancez `iperf3 -s` sur `m2`, puis sur `m1` `iperf3 -6 -c m2 -t 5` et `iperf3 -4 -c m2 -t 5` :
   les deux transferts passent.
2. Appliquez l'état **`trou_noir`** (onglet *Appliquer une configuration*). Vérifiez que
   `ping -6 m2` et `ping -4 m2` passent toujours, puis relancez `timeout 20 iperf3 -6 -c m2 -t 5`
   et la même chose en `-4` : observez le gel, `ss -ti dst m2` (retransmissions) et
   `tcpdump -n -i eth1 'ip6 or icmp'` sur `r1`.
3. Corrigez le problème **sur `r1` et/ou `r2`, pour les deux familles** : MSS clamping nftables
   (`meta nfproto ipv4` / `ipv6`, ou une règle commune), ou MTU réduit sur les interfaces tournées
   vers l'opérateur. Vérifiez que les deux transferts passent de nouveau et, dans une capture des
   SYN sur `r1`, la nouvelle valeur de l'option `mss` dans chaque famille.
4. Les transferts notés se font entre les postes cachés `h1` et `h2`, qui restent derrière le trou
   noir quoi qu'il arrive : votre correction doit être en place sur les routeurs au moment de
   l'évaluation, IPv6 compris. `trou_noir` peut rester appliqué ou non.
""": """
1. Start `iperf3 -s` on `m2`, then on `m1` `iperf3 -6 -c m2 -t 5` and `iperf3 -4 -c m2 -t 5`:
   both transfers get through.
2. Apply the state **`trou_noir`** (*Apply Configuration* tab). Check that
   `ping -6 m2` and `ping -4 m2` still work, then run `timeout 20 iperf3 -6 -c m2 -t 5` again
   and the same with `-4`: observe the freeze, `ss -ti dst m2` (retransmissions) and
   `tcpdump -n -i eth1 'ip6 or icmp'` on `r1`.
3. Fix the problem **on `r1` and/or `r2`, for both families**: nftables MSS clamping
   (`meta nfproto ipv4` / `ipv6`, or a common rule), or reduced MTU on the interfaces facing
   the operator. Check that both transfers get through again and, in a capture of the
   SYNs on `r1`, the new value of the `mss` option in each family.
4. The graded transfers run between the hidden hosts `h1` and `h2`, which stay behind the black
   hole whatever happens: your fix must be in place on the routers at the time of the
   evaluation, IPv6 included. `trou_noir` may stay applied or not.
""",
    """
**Solution.** Après `trou_noir`, `ping -6 m2` et `ping -4 m2` passent encore, mais `iperf3 -6 -c m2` et
`iperf3 -4 -c m2` affichent `0.00 Bytes` côté *receiver* : les segments de 1500 octets partent vers `wan`
et aucune erreur ne revient.

Correction A, MSS clamping des deux familles, sur `r1`, sur `r2` ou sur les deux (c'est ce qu'applique
l'état `final`) :

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set {mss4}
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set {mss6}
```

ou une seule règle pour les deux familles, avec la plus petite valeur :
`nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss6}`.

Correction B, MTU des interfaces tournées vers l'opérateur, sur les **deux** routeurs (elle vaut pour les
deux familles) :

```
ip link set dev eth1 mtu {n}  # sur r1
ip link set dev eth0 mtu {n}  # sur r2
```

- Vérification : `iperf3 -6 -c m2 -t 5` et `iperf3 -4 -c m2 -t 5` passent de nouveau. Avec A, sur `r1`,
  `tcpdump -n -i eth1 'ip6 proto 6 and ip6[53] & 2 != 0'` montre `mss {mss6}` dans les SYN IPv6, et
  `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'` `mss {mss4}` dans les SYN IPv4.
- Piège : une table `ip`, ou la seule règle `meta nfproto ipv4`, laisse IPv6 dans le trou noir (transferts
  IPv6 des sondes à 0, soit 6 points). A sur un seul routeur suffit ; B sur `r1` seul laisse le sens
  `h2` → `h1` dans le trou noir.
- Évaluation : `tn_v6a` et `tn_v6r` (3 points chacun), `tn_v4a` et `tn_v4r` (1 point chacun),
  `tn_connectivite`, `tn_config` (clamping applicable à IPv6, de valeur ≤ {mss6}, dans un hook routé de
  `r1` ou de `r2`, ou MTU ≤ {n} sur `eth1` de `r1` **et** `eth0` de `r2`).
""": """
**Solution.** After `trou_noir`, `ping -6 m2` and `ping -4 m2` still work, but `iperf3 -6 -c m2` and
`iperf3 -4 -c m2` show `0.00 Bytes` on the *receiver* side: the 1500-byte segments leave towards `wan`
and no error comes back.

Fix A, MSS clamping of both families, on `r1`, on `r2` or on both (this is what the state `final`
applies):

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward meta nfproto ipv4 tcp flags syn tcp option maxseg size set {mss4}
nft add rule inet clamp forward meta nfproto ipv6 tcp flags syn tcp option maxseg size set {mss6}
```

or a single rule for both families, with the smaller value:
`nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss6}`.

Fix B, MTU of the interfaces facing the operator, on **both** routers (it holds for both
families):

```
ip link set dev eth1 mtu {n}  # on r1
ip link set dev eth0 mtu {n}  # on r2
```

- Check: `iperf3 -6 -c m2 -t 5` and `iperf3 -4 -c m2 -t 5` get through again. With A, on `r1`,
  `tcpdump -n -i eth1 'ip6 proto 6 and ip6[53] & 2 != 0'` shows `mss {mss6}` in the IPv6 SYNs, and
  `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'` `mss {mss4}` in the IPv4 SYNs.
- Trap: an `ip` table, or the `meta nfproto ipv4` rule alone, leaves IPv6 in the black hole (IPv6
  transfers of the probes at 0, i.e. 6 points). A on a single router is enough; B on `r1` alone leaves the
  direction `h2` → `h1` in the black hole.
- Evaluation: `tn_v6a` and `tn_v6r` (3 points each), `tn_v4a` and `tn_v4r` (1 point each),
  `tn_connectivite`, `tn_config` (clamping applicable to IPv6, with a value ≤ {mss6}, in a routed hook of
  `r1` or `r2`, or MTU ≤ {n} on `eth1` of `r1` **and** `eth0` of `r2`).
""",
    "Correction retenue": "Fix chosen",
    """
- Correction que vous avez mise en place : @@{correctif:>MSS clamping nftables sur r1 et/ou r2|MTU des interfaces WAN de r1 et r2 abaissé|net.ipv4.tcp_mtu_probing sur m1 et m2|route avec mtu sur m1 et m2}@@
""": """
- Fix you have put in place: @@{correctif:>nftables MSS clamping on r1 and/or r2>>>MSS clamping nftables sur r1 et/ou r2|MTU of the WAN interfaces of r1 and r2 lowered>>>MTU des interfaces WAN de r1 et r2 abaissé|net.ipv4.tcp_mtu_probing on m1 and m2>>>net.ipv4.tcp_mtu_probing sur m1 et m2|route with mtu on m1 and m2>>>route avec mtu sur m1 et m2}@@
""",
    """
**Réponses.** `MSS clamping nftables sur r1 et/ou r2` ou `MTU des interfaces WAN de r1 et r2 abaissé`,
selon la correction faite (1 point). Les deux autres choix ne corrigent que `m1` et `m2` : 0.
""": """
**Answers.** `nftables MSS clamping on r1 and/or r2` or `MTU of the WAN interfaces of r1 and r2 lowered`,
depending on the fix made (1 point). The other two choices only fix `m1` and `m2`: 0.
""",
    "transfert TCP IPv6 de h1 vers h2 entre les sondes malgré le trou noir": "IPv6 TCP transfer from h1 to h2 between the probes despite the black hole",
    "transfert TCP IPv6 de h2 vers h1 entre les sondes malgré le trou noir": "IPv6 TCP transfer from h2 to h1 between the probes despite the black hole",
    "transfert TCP IPv4 de h1 vers h2 entre les sondes malgré le trou noir": "IPv4 TCP transfer from h1 to h2 between the probes despite the black hole",
    "transfert TCP IPv4 de h2 vers h1 entre les sondes malgré le trou noir": "IPv4 TCP transfer from h2 to h1 between the probes despite the black hole",
    "connectivité IPv6 et IPv4 conservée entre les deux sites (ping h1 → h2)": "IPv6 and IPv4 connectivity kept between the two sites (ping h1 → h2)",
    "MSS clamping IPv6 sur r1 ou r2, ou MTU réduit sur les interfaces WAN de r1 et r2": "IPv6 MSS clamping on r1 or r2, or reduced MTU on the WAN interfaces of r1 and r2",
    "correction faite sur les routeurs": "fix made on the routers",
    "1400 convient donc aux deux familles.": "1400 therefore suits both families.",
    "1400 convient donc en IPv4 mais reste trop grand en IPv6.": "1400 therefore suits IPv4 but is still too big in IPv6.",
    "1400 est donc trop grand dans les deux familles.": "1400 is therefore too big in both families.",
    "Une seule règle pour deux familles": "A single rule for two families",
    "Dans une table `inet`, une règle `tcp flags syn tcp option maxseg size set 1400` sans `meta nfproto` s'applique aussi aux SYN IPv6. Est-elle suffisante pour les deux familles avec le MTU de l'opérateur que vous avez mesuré ? Justifiez par le calcul.": "In an `inet` table, a rule `tcp flags syn tcp option maxseg size set 1400` without `meta nfproto` also applies to IPv6 SYNs. Is it enough for both families with the operator's MTU you measured? Justify by calculation.",
    """

**Attendu.** Avec un MTU de {n}, le MSS doit valoir au plus {mss6} en IPv6 ({n} − 60) et {mss4} en IPv4
({n} − 40).""": """

**Expected.** With an MTU of {n}, the MSS must be at most {mss6} in IPv6 ({n} − 60) and {mss4} in IPv4
({n} − 40).""",
    """ Une règle commune doit porter
la plus petite des deux valeurs, {mss6}, au prix de 20 octets de charge utile par segment IPv4. Question non
notée.
""": """ A common rule must carry
the smaller of the two values, {mss6}, at the cost of 20 bytes of payload per IPv4 segment. Question not
graded.
""",
    "Partie 6 — Tunnel 6in4 et surcoût d'encapsulation": "Part 6 — 6in4 tunnel and encapsulation overhead",
    "Tunnel 6in4 entre r1 et r2": "6in4 tunnel between r1 and r2",
    """
Supposons que l'opérateur n'offre pas IPv6 : les deux sites peuvent se relier par un tunnel qui
transporte IPv6 dans l'IPv4 de l'opérateur.

1. Créez un tunnel 6in4 `sit1` entre `r1` et `r2` : les extrémités sont leurs adresses **IPv4** sur
   les réseaux de l'opérateur (`wan1` / `wan2`), les adresses intérieures les adresses **IPv6** du
   réseau `tun` du plan d'adressage (`ip link add … type sit local … remote … ttl 64`,
   `ip link set … up`, `ip -6 addr add …/64 dev sit1`). Vérifiez `ping -6` entre les deux adresses
   `tun`, et observez les paquets encapsulés avec `tcpdump -n -v -i eth1 'ip proto 41'` sur `r1`.
2. Calculez le MTU que doit avoir le tunnel pour qu'aucun paquet encapsulé ne dépasse le MTU de
   l'opérateur, réglez-le des deux côtés (`ip link set sit1 mtu …`) et vérifiez-le avec
   `ip -d link show sit1`. Que se passe-t-il si vous tentez un MTU inférieur à 1280 ?
3. Depuis `r1`, testez avec `ping -6 -M do -s TAILLE ADRESSE_TUN_DE_R2` : la plus grande charge
   utile qui passe doit correspondre au MTU du tunnel (moins 48 octets d'en-têtes IPv6 et ICMPv6),
   et un octet de plus doit être refusé localement (`message too long`).
""": """
Suppose that the operator does not offer IPv6: the two sites can connect through a tunnel that
carries IPv6 inside the operator's IPv4.

1. Create a 6in4 tunnel `sit1` between `r1` and `r2`: the endpoints are their **IPv4** addresses on
   the networks of the operator (`wan1` / `wan2`), the inner addresses the **IPv6** addresses of the
   `tun` network of the addressing plan (`ip link add … type sit local … remote … ttl 64`,
   `ip link set … up`, `ip -6 addr add …/64 dev sit1`). Check `ping -6` between the two `tun`
   addresses, and observe the encapsulated packets with `tcpdump -n -v -i eth1 'ip proto 41'` on `r1`.
2. Calculate the MTU the tunnel must have so that no encapsulated packet exceeds the MTU of the
   operator, set it on both sides (`ip link set sit1 mtu …`) and check it with
   `ip -d link show sit1`. What happens if you try an MTU below 1280?
3. From `r1`, test with `ping -6 -M do -s SIZE TUN_ADDRESS_OF_R2`: the largest payload that gets
   through must match the MTU of the tunnel (minus 48 bytes of IPv6 and ICMPv6 headers), and one
   more byte must be refused locally (`message too long`).
""",
    """
**Solution.** Sur `r1` :

```
ip link add sit1 type sit local {r1_wan} remote {r2_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r1_tun} dev sit1
```

Sur `r2` :

```
ip link add sit1 type sit local {r2_wan} remote {r1_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r2_tun} dev sit1
```

- MTU du tunnel : {n} − 20 (en-tête IPv4 extérieur) = **{tun_mtu}**. Sans réglage, `sit1` reste à 1480. Un
  MTU inférieur à 1280 est refusé (`Error: mtu less than device minimum.`).
- Vérification depuis `r1` : `ping -6 {r2_tun_ip}` passe ; `ping -6 -M do -s {fit} {r2_tun_ip}` passe
  ({fit} + 48 = {tun_mtu}) ; `ping -6 -M do -s {over} {r2_tun_ip}` répond
  `ping: sendmsg: Message too long`. `tcpdump -n -v -i eth1 'ip proto 41'` montre des paquets
  IPv4 d'au plus {n} octets.
- Évaluation : `sit_r1` et `sit_r2` (type `sit` avec `local` / `remote` égaux aux adresses IPv4 `wan1` /
  `wan2`, puis MTU {tun_mtu} : 2 points chacun), `sit_joignable`, `sit_pmtu` (les deux `ping -6 -M do` ci-dessus,
  cache de `r1` vidé : sans MTU réglé sur `sit1`, le paquet trop grand part et n'est pas refusé localement).
- Les corrections de la partie 5 peuvent rester en place, et le tunnel fonctionne avec ou sans `trou_noir`.
""": """
**Solution.** On `r1`:

```
ip link add sit1 type sit local {r1_wan} remote {r2_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r1_tun} dev sit1
```

On `r2`:

```
ip link add sit1 type sit local {r2_wan} remote {r1_wan} ttl 64
ip link set sit1 mtu {tun_mtu} up
ip -6 addr add {r2_tun} dev sit1
```

- MTU of the tunnel: {n} − 20 (outer IPv4 header) = **{tun_mtu}**. Without a setting, `sit1` stays at 1480. An
  MTU below 1280 is refused (`Error: mtu less than device minimum.`).
- Check from `r1`: `ping -6 {r2_tun_ip}` gets through; `ping -6 -M do -s {fit} {r2_tun_ip}` gets through
  ({fit} + 48 = {tun_mtu}); `ping -6 -M do -s {over} {r2_tun_ip}` answers
  `ping: sendmsg: Message too long`. `tcpdump -n -v -i eth1 'ip proto 41'` shows IPv4 packets of
  at most {n} bytes.
- Evaluation: `sit_r1` and `sit_r2` (type `sit` with `local` / `remote` equal to the IPv4 addresses `wan1` /
  `wan2`, then MTU {tun_mtu}: 2 points each), `sit_joignable`, `sit_pmtu` (the two `ping -6 -M do` above,
  cache of `r1` flushed: without an MTU set on `sit1`, the packet that is too big leaves and is not refused locally).
- The fixes of part 5 may stay in place, and the tunnel works with or without `trou_noir`.
""",
    "MTU du tunnel": "Tunnel MTU",
    """
- Surcoût d'encapsulation d'un tunnel 6in4, en octets : @@{surcout:[0-9]+}@@
- MTU à configurer sur `sit1` : @@{mtu_tunnel:[0-9]+}@@
""": """
- Encapsulation overhead of a 6in4 tunnel, in bytes: @@{surcout:[0-9]+}@@
- MTU to configure on `sit1`: @@{mtu_tunnel:[0-9]+}@@
""",
    """
**Réponses.** surcoût `{surcout}` octets (l'en-tête IPv4 extérieur) ; MTU de `sit1` : `{mtu_tunnel}`
({n} − {surcout}).
""": """
**Answers.** overhead `{surcout}` bytes (the outer IPv4 header); MTU of `sit1`: `{mtu_tunnel}`
({n} − {surcout}).
""",
    "tunnel sit1 sur {r} : type sit et extrémités IPv4, puis MTU": "sit1 tunnel on {r}: sit type and IPv4 endpoints, then MTU",
    "ping -6 de r1 vers r2 à travers le tunnel": "ping -6 from r1 to r2 through the tunnel",
    "le plus grand paquet passe dans le tunnel, un octet de plus est refusé localement": "the largest packet gets through the tunnel, one more byte is refused locally",
    "surcoût d'encapsulation 6in4 et MTU du tunnel": "6in4 encapsulation overhead and tunnel MTU",
}}
