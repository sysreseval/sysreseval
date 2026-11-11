"""RIP lab with FRR (FRRouting).

Four FRR routers in a ring (r1-r2-r3-r4) with a slow diagonal backup link (r1-r3), three host
LANs, a virtualisation host whose internal network is reached through a static route, and an ISP
behind r4.  r1 and r2 already speak RIP on their common link; the students extend RIP to the
whole site, then work on convergence (timers, poisoned reverse), passive interfaces, the default
route, redistribution, metrics (offset-list, ECMP), security (MD5 authentication, a rogue RIP
speaker) and, as a bonus, RIPng.

Two hidden machines: ``probe`` listens, without any address and without ever sending a frame, to
the RIP updates of every site network (lib/rip_probe.py, lib/rip.py), which lets the grader
check what each router really announces; ``intruder`` is the rogue speaker of lan3.  The ``final``
state applies the reference solution.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network, IPv6Interface
from typing import Dict

import utils
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s, random_ipv6networks
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward, set_ipv6_forward
from ping import eval_ping
from frr import (
    RIP_ROUTE_PROTOCOLS, get_kernel_routes, kernel_route_gateways, get_rip_routes, get_rip_status,
    is_ripng_protocol, rip_route_metric, rip_route_sources,
)
from ipv6 import get_ip6_routes, ipv6_subnet
from rip import (
    RIP_INFINITY, announced_metric, get_rip_probe, heard, install_rip_probe, md5_authenticated, probe_ready,
    rip_announce_cmd, rip_listen_cmd, rip_window,
)
from tcp import netem_cmd

default_language = 'fr'
tr = make_tr(default_language)

title = tr("Routage dynamique : RIP", en="Dynamic routing: RIP")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
# the export replays `initial` for the hidden machines too: it would give away the probe and
# the rogue speaker
export_kathara_project = False
eval_interval_without_exam_mode = 60
eval_before_exit = True
record_sessions = False
ipv6 = True

# "Internet": an address of TEST-NET-3 held by the ISP.
INTERNET = IPv4Network("203.0.113.0/24")
INTERNET_HOST = IPv4Interface("203.0.113.1/24")

# Router interfaces in ethN order: (network name, data.ips attribute).  Must match _TOPOLOGY.
ROUTER_IFACES = {
    'r1': [('lan1', 'r1_lan1'), ('l12', 'r1_l12'), ('l13', 'r1_l13'), ('l14', 'r1_l14')],
    'r2': [('lan2', 'r2_lan2'), ('l12', 'r2_l12'), ('l23', 'r2_l23')],
    'r3': [('lan3', 'r3_lan3'), ('l13', 'r3_l13'), ('l23', 'r3_l23'), ('l34', 'r3_l34')],
    'r4': [('l14', 'r4_l14'), ('l34', 'r4_l34'), ('wan', 'r4_wan')],
}
# Hosts: (router, data.ips attribute of the router interface on the host LAN)
HOST_ROUTER = {
    'pc1': ('r1', 'r1_lan1'),
    'pc2': ('r2', 'r2_lan2'),
    'hv': ('r3', 'r3_lan3'),
}
LANS = {'lan1': 'r1', 'lan2': 'r2', 'lan3': 'r3'}                      # LAN -> its router
TRANSIT = {'l12': ('r1', 'r2'), 'l13': ('r1', 'r3'), 'l14': ('r1', 'r4'), 'l23': ('r2', 'r3'), 'l34': ('r3', 'r4')}
BACKUP_LINK = 'l13'
POISON_LINK = 'l12'
# Third octet of every site network (and, read as hexadecimal, its IPv6 subnet number).
SITE_OCTETS = {'lan1': 1, 'lan2': 2, 'lan3': 3, 'l12': 12, 'l13': 13, 'l14': 14, 'l23': 23, 'l34': 34}
SITE_NETS = list(SITE_OCTETS)
# The probe has one interface per site network, in this order (ethN = position).
PROBE_IFACES = {net: f"eth{n}" for n, net in enumerate(SITE_NETS)}
HOST_IPV6_ID = 0x100
TIMER_PRESETS = [(5, 15, 10), (6, 18, 12), (8, 24, 16)]              # update, timeout, garbage
KEY_CHAIN = 'RIPKEYS'
OFFSET_ACL = 'BACKUP'
BACKUP_DELAY_MS = 20                                                 # netem delay of each end of the backup link
GHOST_INTERVAL = 2                                                   # seconds between two rogue announcements
ROUTER_COLOR = 'lightblue'
# an `ip link set ethX down` experiment must not lose the IPv6 addresses of the interface
ROUTER_SYSCTLS = ('net.ipv6.conf.all.keep_addr_on_down=1', 'net.ipv6.conf.default.keep_addr_on_down=1')

_TOPOLOGY = {
    'lan1': {'r1': 0, 'pc1': 0, 'probe': 0},
    'lan2': {'r2': 0, 'pc2': 0, 'probe': 1},
    'lan3': {'r3': 0, 'hv': 0, 'intruder': 0, 'probe': 2},
    'l12': {'r1': 1, 'r2': 1, 'probe': 3},
    'l13': {'r1': 2, 'r3': 1, 'probe': 4},
    'l14': {'r1': 3, 'r4': 0, 'probe': 5},
    'l23': {'r2': 2, 'r3': 2, 'probe': 6},
    'l34': {'r3': 3, 'r4': 1, 'probe': 7},
    'wan': {'r4': 2, 'isp': 0},
}

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : ripd et ripngd sont activés
# (zebra, staticd et watchfrr démarrent toujours)
bgpd=no
ospfd=no
ospf6d=no
ripd=yes
ripngd=yes
isisd=no
pimd=no
pim6d=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no

vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
ospfd_options="  -A 127.0.0.1"
ospf6d_options=" -A ::1"
ripd_options="   -A 127.0.0.1"
ripngd_options=" -A ::1"
isisd_options="  -A 127.0.0.1"
pimd_options="   -A 127.0.0.1"
pim6d_options="  -A ::1"
ldpd_options="   -A 127.0.0.1"
nhrpd_options="  -A 127.0.0.1"
eigrpd_options=" -A 127.0.0.1"
babeld_options=" -A 127.0.0.1"
sharpd_options=" -A 127.0.0.1"
pbrd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
fabricd_options="-A 127.0.0.1"
vrrpd_options="  -A 127.0.0.1"
pathd_options="  -A 127.0.0.1"
"""

FRR_VTYSH_CONF = "service integrated-vtysh-config\n"


def iface(router: str, net: str) -> str:
    """Name of the interface of *router* on *net* (``eth2``)."""
    return f"eth{[name for name, _attr in ROUTER_IFACES[router]].index(net)}"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    update_timer: int = 0     # part 3: `timers basic <update> <timeout> <garbage>`
    timeout_timer: int = 0
    garbage_timer: int = 0
    static_metric: int = 0    # part 6: metric of the redistributed static route
    backup_offset: int = 0    # part 7: metric added to what is announced on the backup link
    key_id: int = 0           # part 8: key of the key chain (never 1, the id of `authentication string`)
    key_secret: str = ""      # part 8: its secret (<= 16 characters)

    @classmethod
    def generate(cls):
        data = cls()
        data.update_timer, data.timeout_timer, data.garbage_timer = random.choice(TIMER_PRESETS)
        data.static_metric = random.randint(2, 4)
        data.backup_offset = random.randint(3, 5)
        data.key_id = random.randint(2, 255)
        data.key_secret = utils.random_password(12)

        # The site is one 10.x.0.0/16; the third octet of a network tells which one it is.
        data.nets.site = random_ipv4networks(masks=[16], from_network=IPv4Network("10.0.0.0/8"),
                                             exclude=[IPv4Network("10.0.0.0/16")])[0]
        blocks = list(data.nets.site.subnets(new_prefix=24))
        for net, octet in SITE_OCTETS.items():
            setattr(data.nets, net, blocks[octet] if net in LANS else next(blocks[octet].subnets(new_prefix=30)))
        data.nets.vmnet = blocks[random.randint(40, 99)]
        data.nets.wan, data.nets.ghost = random_ipv4networks(
            masks=[30, 24], from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/8"), IPv4Network("172.17.0.0/16")])

        data.ips.r1_lan1, data.ips.pc1 = random_ipv4s(data.nets.lan1, 2)
        data.ips.r2_lan2, data.ips.pc2 = random_ipv4s(data.nets.lan2, 2)
        data.ips.r3_lan3, data.ips.hv, data.ips.intruder = random_ipv4s(data.nets.lan3, 3)
        for link, (a, b) in TRANSIT.items():
            ip_a, ip_b = random_ipv4s(getattr(data.nets, link), 2)
            setattr(data.ips, f"{a}_{link}", ip_a)
            setattr(data.ips, f"{b}_{link}", ip_b)
        data.ips.r4_wan, data.ips.isp = random_ipv4s(data.nets.wan, 2)
        data.ips.vm = random_ipv4s(data.nets.vmnet, 1)[0]

        # IPv6 (bonus part): one ULA /48, subnet 0x12 for l12..., rN is ::N, a host ::100.
        data.nets6.site = random_ipv6networks(48, from_private_network=True)[0]
        for net, octet in SITE_OCTETS.items():
            setattr(data.nets6, net, ipv6_subnet(data.nets6.site, int(str(octet), 16), 64))
        for router, ifaces in ROUTER_IFACES.items():
            for net, attr in ifaces:
                if net in SITE_OCTETS:
                    setattr(data.ips6, attr, _ipv6(getattr(data.nets6, net), int(router[1:])))
        for host, (_router, router_attr) in HOST_ROUTER.items():
            setattr(data.ips6, host, _ipv6(getattr(data.nets6, router_attr.split('_')[1]), HOST_IPV6_ID))
        return data


def _ipv6(network, identifier: int) -> IPv6Interface:
    return IPv6Interface((int(network.network_address) + identifier, network.prefixlen))


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        **{r: {'image': sre_docker_image("frr"), 'color': ROUTER_COLOR, 'sysctls': ROUTER_SYSCTLS}
           for r in ROUTER_IFACES},
        'pc1': {'color': 'lightyellow'},
        'pc2': {'color': 'lightyellow'},
        'hv': {'color': 'lightgreen'},
        'isp': {'allow_connection': False, 'color': 'lightgrey', 'ipv6': False},     # the operator: no terminal
        'probe': {'hidden': True, 'allow_connection': False, 'ipv6': False},
        'intruder': {'hidden': True, 'allow_connection': False, 'ipv6': False},
    }
    _network_specs = {
        BACKUP_LINK: {'color': 'orange'},
        'wan': {'color': 'lightgrey'},
    }
    # Interface numbers must follow ROUTER_IFACES and PROBE_IFACES (ethN = position in the list).
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        default6 = d.nets6.site.supernet(new_prefix=0)

        # Routers: addresses only (RIP does the routing; r4's default route is an FRR static
        # route written in frr.conf, see _frr_conf()).  The wan link has no IPv6.
        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, ifaces in ROUTER_IFACES.items():
            self.net_config[r] = [
                ([getattr(d.ips, attr)] + ([getattr(d.ips6, attr)] if net in SITE_OCTETS else []), [])
                for net, attr in ifaces]
        for h, (_r, r_attr) in HOST_ROUTER.items():
            self.net_config[h] = [([getattr(d.ips, h), getattr(d.ips6, h)],
                                   [(default, getattr(d.ips, r_attr).ip), (default6, getattr(d.ips6, r_attr).ip)])]
        self.net_config['isp'] = [([d.ips.isp, INTERNET_HOST], [(d.nets.site, d.ips.r4_wan.ip)])]
        self.net_config['intruder'] = [([d.ips.intruder], [])]
        # the probe only listens: its interfaces are up, without any address
        self.net_config['probe'] = [([], []) for _net in SITE_NETS]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX.  Never an
        # address of a hidden machine.
        lines = []
        for r, ifaces in ROUTER_IFACES.items():
            for i, (_net, attr) in enumerate(ifaces):
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{getattr(d.ips, attr).ip}\t{names}")
        for h in HOST_ROUTER:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
            lines.append(f"{getattr(d.ips6, h).ip}\t{h}-v6")
        lines.append(f"{d.ips.vm.ip}\tvm")
        lines.append(f"{d.ips.isp.ip}\tisp")
        lines.append(f"{INTERNET_HOST.ip}\tinternet")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le routage à vecteur de distance"), tag="principle")
            + tr("""
**RIP** (*Routing Information Protocol* ; RFC 1058 pour la version 1, RFC 2453 pour la version 2)
est le plus ancien des protocoles de routage **dynamique** encore en usage. C'est un protocole
**intérieur** (IGP), fait pour un petit domaine administré par une seule équipe, et un protocole à
**vecteur de distance** :

- un routeur ne connaît pas la carte du réseau : il sait seulement, pour chaque destination, **à
  quelle distance** elle se trouve et **par quel voisin** l'atteindre ;
- périodiquement, chaque routeur envoie à ses voisins directs la liste de ses destinations avec
  leur distance : son *vecteur de distances* ;
- à la réception, le routeur **ajoute 1** à chaque distance annoncée (le saut pour atteindre le
  voisin) et garde, pour chaque destination, l'annonce la plus courte ; le voisin qui l'a faite
  devient le **prochain saut** ;
- de proche en proche, tous les routeurs apprennent toutes les destinations : c'est l'algorithme
  de **Bellman-Ford** réparti.

Un protocole à **état de liens** comme OSPF procède autrement : chaque routeur reçoit la
description de tous les liens et calcule lui-même les plus courts chemins. RIP est plus simple
(presque rien à configurer, peu de calcul) mais il converge lentement et ne passe pas à l'échelle.

### @@sec:metric@@ La métrique : le nombre de sauts

La distance de RIP est un **nombre de sauts** (*hop count*) : un réseau directement connecté est
annoncé avec la métrique **1**, et chaque routeur traversé ajoute 1. La métrique ne tient compte
ni du débit ni du délai des liens : un chemin de deux sauts par un lien lent est préféré à un
chemin de trois sauts par des liens rapides.

La valeur **16** signifie « **infini** » : la destination est inaccessible. Un chemin compte donc
au plus 15 sauts, ce qui limite la taille d'un domaine RIP. Cette limite, très basse, est voulue :
elle borne la durée des boucles (section @@ref:loops@@).

Entre deux routes de même métrique vers une destination, RIP garde la première apprise ; il peut
aussi les installer toutes les deux (section @@ref:tuning@@).
""")
            + info_subtitle(tr("Les messages RIP"), tag="messages")
            + tr("""
RIP est transporté par **UDP**, port **520** (source et destination). Il n'a que deux messages :

- la **requête** (*request*, commande 1) : « envoie-moi ta table » ; un routeur en émet une au
  démarrage de RIP sur une interface, pour ne pas attendre la prochaine annonce de ses voisins ;
- la **réponse** (*response*, commande 2) : une liste de routes. C'est la réponse à une requête,
  mais aussi l'**annonce périodique** que chaque routeur envoie spontanément, et la **mise à jour
  déclenchée** (*triggered update*) envoyée dès qu'une route change, sans attendre la période
  (elle ne contient alors que les routes modifiées).

Un message contient au plus 25 routes ; une table plus longue est envoyée en plusieurs messages.
Chaque route occupe 20 octets :

| champ | taille | rôle |
|-------|--------|------|
| famille d'adresses | 2 octets | 2 pour IPv4 |
| étiquette (route tag) | 2 octets | marque libre, RIPv2 seulement |
| adresse | 4 octets | le réseau annoncé |
| masque | 4 octets | RIPv2 seulement |
| prochain saut | 4 octets | RIPv2 seulement ; 0.0.0.0 : l'émetteur lui-même |
| métrique | 4 octets | 1 à 16 |

### @@sec:versions@@ RIPv1 et RIPv2

| | RIPv1 | RIPv2 |
|---|-------|-------|
| destination des annonces | diffusion (255.255.255.255) | multidiffusion 224.0.0.9 |
| masque dans les annonces | non : routage par classes A, B, C | oui : sous-réseaux de taille quelconque |
| authentification | non | oui (mot de passe en clair ou MD5) |

RIPv1 ne transporte pas de masque : il ne sait pas annoncer `10.1.2.0/24` et `10.1.12.0/30` dans
le même domaine. On utilise donc toujours **RIPv2** ; ses annonces, envoyées à l'adresse de
groupe **224.0.0.9** avec un TTL de 1, ne dérangent que les routeurs RIP du lien et ne sont jamais
routées.

Pour observer les messages : `tcpdump -ni eth1 -v udp port 520`. Avec `-v`, `tcpdump` affiche le
type du message et, pour chaque route, le préfixe, la métrique et le prochain saut.
""")
            + info_subtitle(tr("Les temporisateurs"), tag="timers")
            + tr("""
Trois durées règlent la vie d'une route apprise par RIP :

| temporisateur | valeur par défaut | rôle |
|---------------|-------------------|------|
| update | 30 s | période des annonces ; chaque routeur la fait varier un peu pour que les routeurs ne se synchronisent pas |
| timeout | 180 s | durée de validité d'une route : il est réarmé à chaque annonce qui la confirme |
| garbage | 120 s | durée pendant laquelle une route devenue invalide est encore annoncée, avec la métrique 16, avant d'être oubliée |

Une route qui n'est plus confirmée pendant le *timeout* (six annonces manquées) devient
**invalide** : elle quitte la table de routage et sa métrique passe à 16. Le routeur continue à
l'annoncer ainsi pendant le *garbage*, pour que ses voisins apprennent sa disparition, puis il
l'efface.

Deux pannes se comportent donc très différemment :

- une interface qui **tombe** sur le routeur lui-même (câble débranché, `ip link set … down`) est
  vue tout de suite : ses routes sont invalidées et une mise à jour déclenchée part aussitôt ;
- une panne **silencieuse** — le voisin s'arrête, ou le lien est coupé plus loin alors que
  l'interface reste active — n'est détectée que par l'absence d'annonces, au bout du *timeout* :
  trois minutes avec les valeurs par défaut.

Des temporisateurs plus courts accélèrent la détection au prix d'annonces plus fréquentes. Ils
doivent être **identiques sur tous les routeurs** du domaine : un routeur dont le *timeout* est
plus court que la période de ses voisins perd ses routes entre deux annonces.
""")
            + info_subtitle(tr("Boucles et comptage à l'infini"), tag="loops")
            + tr("""
Un routeur à vecteur de distance croit ce que ses voisins lui disent, sans savoir par où passent
leurs routes. Après une panne, cela peut créer une **boucle**. Soit trois routeurs en ligne,
A — B — C, et un réseau N derrière C : C annonce N avec la métrique 1, B l'apprend avec 2, A avec 3.

1. Le lien B — C tombe : B invalide sa route vers N.
2. Mais A annonce toujours « N, métrique 3 » — une route qui passait par B. Si cette annonce
   arrive à B avant que B ait prévenu A, B croit avoir trouvé un autre chemin : il installe « N
   par A, métrique 4 ».
3. B annonce N avec 4 : A, dont le prochain saut est B, passe à 5 ; puis B passe à 6, etc.

Pendant ce temps, les paquets destinés à N rebondissent entre A et B jusqu'à l'expiration de leur
TTL. Les métriques montent d'une unité par échange : c'est le **comptage à l'infini**, qui ne
s'arrête que lorsque la métrique atteint 16. D'où l'intérêt d'un « infini » aussi petit.

RIP combine plusieurs remèdes :

- l'**horizon partagé** (*split horizon*) : un routeur n'annonce jamais une route sur l'interface
  par laquelle il l'a apprise. A n'annonce pas N à B : la boucle à deux routeurs ne peut pas se
  former. C'est le comportement par défaut ;
- l'**empoisonnement inverse** (*poisoned reverse*) : au lieu de se taire, le routeur annonce ces
  routes sur l'interface d'où elles viennent avec la métrique **16**. Le voisin est sûr de ne pas
  les utiliser, sans attendre un *timeout* ; les annonces sont plus longues ;
- l'**empoisonnement de route** (*route poisoning*) : une route perdue est annoncée avec la
  métrique 16 au lieu de simplement disparaître des annonces ;
- les **mises à jour déclenchées**, qui propagent une mauvaise nouvelle sans attendre la période.

Aucun de ces mécanismes n'empêche une boucle entre **trois routeurs ou plus** (A apprend la route
de B, qui la tient de C, qui la tient de A) : le comptage à l'infini y reste possible, et c'est
la limite à 16 qui y met fin.
""")
            + info_subtitle(tr("RIP avec FRR"), tag="frr")
            + tr("""
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` (l'interface avec le
noyau : il y installe les routes choisies), `staticd` (les routes statiques) et un démon par
protocole, ici `ripd` (RIP) et `ripngd` (RIPng). Les démons lancés sont choisis dans
`/etc/frr/daemons` (`systemctl status frr`). On les configure avec le shell **`vtysh`**, dont la
syntaxe est proche de celle des équipements Cisco :

```
vtysh                              # ouvre le shell (prompt : routeur#)
show running-config                # configuration courante
configure terminal                 # passe en mode configuration (prompt : routeur(config)#)
 router rip                        #   processus RIP (prompt : routeur(config-router)#)
  version 2                        #   n'émet et n'accepte que RIPv2
  network 192.0.2.0/24             #   active RIP sur les interfaces dont l'adresse est dans ce préfixe
  network eth1                     #   ... ou sur une interface désignée par son nom
  exit
 interface eth1                    #   réglages RIP d'une interface (prompt : routeur(config-if)#)
  ip rip split-horizon poisoned-reverse
  exit
 end                               # retour au mode privilégié
write                              # sauvegarde dans /etc/frr/frr.conf
```

La commande **`network`** fait deux choses à la fois : RIP **parle** sur les interfaces
concernées (il y envoie ses annonces et y écoute celles des voisins) et il **annonce le réseau**
de ces interfaces. On supprime une ligne de configuration en la préfixant par `no`
(`no network eth1`). Une commande peut aussi être passée depuis le shell Linux :
`vtysh -c "show ip rip"`.

Commandes d'observation :

```
show ip rip                        # la table de RIP : routes, prochain saut, métrique, source, durée restante
show ip rip status                 # temporisateurs, interfaces, réseaux, voisins entendus
show ip route                      # table de routage complète (vue de zebra)
show ip route rip                  # ... limitée aux routes RIP
clear ip rip                       # oublie les routes apprises (mode privilégié)
```

Dans `show ip rip`, chaque ligne commence par un code : `R(n)` une route apprise d'un voisin
(colonne *From* ; la colonne *Time* décompte le *timeout*), `C(i)` le réseau d'une interface où
RIP est activé, `C(r)`, `S(r)` ou `K(r)` une route **redistribuée** (connectée, statique, du
noyau), `R(d)` la route par défaut que le routeur engendre lui-même.

Dans `show ip route`, une route RIP s'écrit `R>* 10.1.2.0/24 [120/2] via …` : **120** est la
**distance administrative** de RIP (la confiance accordée au protocole : 0 pour un réseau
connecté, 1 pour une route statique, 110 pour OSPF ; à destination égale, la plus petite gagne)
et **2** la métrique. Dans la table du noyau (`ip route`), ces routes portent `proto rip` ; la
valeur `metric 20` qu'on y lit est une priorité fixée par FRR, **pas** le nombre de sauts.

### @@sec:passive@@ Interfaces passives

Sur un réseau où il n'y a que des hôtes, les annonces RIP sont inutiles : personne ne les lit,
et elles renseignent quiconque écoute sur la topologie du site. Une interface **passive**
n'émet plus aucune annonce, mais son réseau reste annoncé sur les autres interfaces :

```
router rip
 passive-interface eth0
```

Attention : une interface passive **écoute encore** (section @@ref:security@@).

### @@sec:redistribution@@ Route par défaut et redistribution

RIP n'annonce spontanément que les réseaux des interfaces désignées par `network`. Pour le reste :

```
router rip
 default-information originate     # annonce la route par défaut 0.0.0.0/0 (routeur de sortie)
 redistribute static metric 3      # annonce les routes statiques de FRR, avec la métrique 3
 redistribute connected            # annonce tous les réseaux connectés, même sans `network`
```

**Redistribuer**, c'est injecter dans RIP des routes venues d'une autre source : routes statiques
(`ip route 198.51.100.0/24 192.0.2.7` en mode configuration : c'est une route de FRR, différente
d'une route ajoutée avec la commande Linux `ip route add`), réseaux connectés, autre protocole.
La métrique d'origine n'ayant pas de sens pour RIP, on la fixe avec `metric` ; à défaut, c'est 1.

### @@sec:tuning@@ Agir sur les métriques

Le nombre de sauts ignore la qualité des liens. Pour écarter un lien lent sans le retirer de RIP
— il doit rester un chemin de **secours** —, on alourdit ce qui y est annoncé avec une
**`offset-list`** :

```
access-list SLOW permit any        # les routes concernées : toutes
router rip
 offset-list SLOW out 4 eth2       # ajoute 4 à la métrique des routes annoncées par eth2
```

Avec `in`, le décalage s'applique aux routes reçues par l'interface. Le lien n'est plus choisi
que si les autres chemins disparaissent.

Quand deux chemins ont la **même métrique**, `allow-ecmp` (sous `router rip`) les installe tous
les deux : le trafic est réparti entre les prochains sauts (*Equal Cost Multi-Path*).
""")
            + info_subtitle(tr("Sécurité"), tag="security")
            + tr("""
Par défaut, un routeur RIP **croit n'importe quelle annonce** venant d'une machine d'un réseau
où RIP est activé : aucun voisin n'est déclaré, rien n'est vérifié. Un poste mal configuré — ou
malveillant — qui émet des annonces RIP peut donc injecter des routes dans tout le domaine :
détourner un préfixe vers lui, ou attirer tout le trafic sortant en annonçant une route par
défaut.

Une interface **passive ne protège pas** : elle n'émet plus, mais elle reçoit et accepte
toujours. Sur un réseau d'hôtes, où aucun routeur n'est attendu, on choisit donc l'une de ces
parades :

- ne pas activer RIP sur l'interface (pas de `network` pour elle) et annoncer son réseau avec
  `redistribute connected` ;
- garder `network` mais refuser ce qui arrive : `ip rip receive version none` sous l'interface ;
- filtrer les routes reçues : `distribute-list prefix NOM in eth0` sous `router rip`.

Entre routeurs, où il faut bien s'écouter, on **authentifie** les annonces (RIPv2 seulement).
Le mode `text` place un mot de passe en clair dans chaque message : il protège d'une erreur, pas
d'un attaquant qui écoute le lien. Le mode **MD5** n'envoie pas le secret mais une empreinte du
message calculée avec lui ; le message porte aussi le **numéro de la clé** utilisée, ce qui
permet d'en changer sans coupure. Les clés sont rangées dans un **trousseau** (*key chain*) :

```
key chain SITE                     # mode configuration
 key 5                             #   numéro de la clé : il doit être le même aux deux bouts
  key-string monSecret
  exit
 exit
interface eth1
 ip rip authentication mode md5
 ip rip authentication key-chain SITE
```

Les deux extrémités d'un lien doivent avoir le même mode, le même numéro de clé et le même
secret ; sinon chacun rejette les annonces de l'autre, et les routes expirent au bout du
*timeout*. `show ip rip status` compte les paquets refusés de chaque source (*BadPackets*).
""")
            + info_subtitle(tr("RIPng : RIP pour IPv6"), tag="ripng")
            + tr("""
**RIPng** (RFC 2080) est l'adaptation de RIP à IPv6. Le principe, la métrique, les
temporisateurs et les remèdes aux boucles sont les mêmes ; ce qui change :

| | RIPv2 | RIPng |
|---|-------|-------|
| transport | UDP 520 | UDP 521 |
| destination des annonces | 224.0.0.9 | ff02::9 |
| adresse source et prochain saut | adresse IPv4 de l'interface | adresse lien-local (fe80::…) |
| authentification | dans le protocole | aucune : on s'en remet à IPsec |

Les deux protocoles sont indépendants : un routeur à double pile fait tourner les deux, et les
tables IPv4 et IPv6 se construisent séparément. Avec FRR (démon `ripngd`) :

```
router ripng
 network eth1                      # active RIPng sur l'interface (ou : network 2001:db8:1::/64)
```

Observation : `show ipv6 ripng`, `show ipv6 ripng status`, `show ipv6 route`, et dans le noyau
`ip -6 route` (`proto ripng`). Les prochains sauts sont des adresses lien-local, toujours
accompagnées de l'interface de sortie.
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `ip route` sur un routeur ou un hôte : les routes apprises par RIP portent `proto rip` ;
- `traceroute -n IP` depuis un hôte : chemin réellement suivi ;
- `tcpdump -ni ethX -v udp port 520` : les annonces émises et reçues sur une interface ;
- `show ip rip status` : la liste *Routing Information Sources* donne les voisins entendus et
  l'ancienneté de leur dernière annonce ;
- `/var/log/frr/frr.log` : journal des démons FRR.

| symptôme | causes à vérifier |
|----------|-------------------|
| aucune route RIP | ripd non démarré, pas de router rip, aucune commande network |
| un voisin n'apparaît pas dans les sources | RIP non activé sur l'interface d'un des deux côtés, interface passive chez le voisin, versions différentes, authentification différente |
| le réseau d'une interface n'est pas annoncé | commande network manquante pour ce réseau (ou pas de redistribute connected) |
| une route disparaît puis revient | temporisateurs différents entre voisins, authentification d'un seul côté |
| une route inconnue dans les tables | une machine qui n'est pas un routeur du site émet des annonces : regarder la colonne From |
| la route ne passe pas par le chemin attendu | métriques (offset-list), route apprise en premier à métrique égale |
| une modification tarde à se voir chez les voisins | elle n'est transmise qu'à l'annonce suivante : une période, ou clear ip rip |
""")
        )

    # -- FRR configuration files -------------------------------------------------

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf: RIP already running on r1 and r2 (r1 does not announce
        lan1), nothing on r3, only the static default route on r4."""
        d = self.data
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "log file /var/log/frr/frr.log", "!"]
        if router == 'r1':
            lines += ["router rip", " version 2", f" network {d.nets.l12}", "exit", "!"]
        elif router == 'r2':
            lines += ["router rip", " version 2", f" network {d.nets.l12}", f" network {d.nets.lan2}", "exit", "!"]
        elif router == 'r4':
            lines += [f"ip route 0.0.0.0/0 {d.ips.isp.ip}", "!"]
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step)

    def _reference(self, router: str) -> list:
        """vtysh configuration commands of the reference solution of *router* (every part)."""
        d = self.data
        cmds = ["key chain " + KEY_CHAIN, f"key {d.key_id}", f"key-string {d.key_secret}", "exit", "exit"]
        for net, _attr in ROUTER_IFACES[router]:
            if net in TRANSIT:
                cmds.append(f"interface {iface(router, net)}")
                if net == POISON_LINK:
                    cmds.append("ip rip split-horizon poisoned-reverse")
                cmds += ["ip rip authentication mode md5", f"ip rip authentication key-chain {KEY_CHAIN}", "exit"]
        if router == 'r3':
            # the rogue speaker of lan3 is not listened to any more; the VM network behind hv
            cmds += ["interface eth0", "ip rip receive version none", "exit",
                     f"ip route {d.nets.vmnet} {d.ips.hv.ip}"]
        if router in TRANSIT[BACKUP_LINK]:
            cmds.append(f"access-list {OFFSET_ACL} permit any")
        cmds += ["router rip", "version 2"]
        cmds += [f"network {getattr(d.nets, net)}" for net, _attr in ROUTER_IFACES[router] if net in SITE_OCTETS]
        cmds.append(f"timers basic {d.update_timer} {d.timeout_timer} {d.garbage_timer}")
        if router in LANS.values():
            cmds.append("passive-interface eth0")
        if router == 'r3':
            cmds.append(f"redistribute static metric {d.static_metric}")
        if router == 'r4':
            cmds.append("default-information originate")
        if router in TRANSIT[BACKUP_LINK]:
            cmds += [f"offset-list {OFFSET_ACL} out {d.backup_offset} {iface(router, BACKUP_LINK)}", "allow-ecmp"]
        cmds.append("exit")
        cmds.append("router ripng")
        cmds += [f"network {iface(router, net)}" for net, _attr in ROUTER_IFACES[router] if net in SITE_OCTETS]
        cmds.append("exit")
        return cmds

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
        for h in HOST_ROUTER:
            set_ipv6_forward(net_scheme=self, machine_name=h, ipv6_forward=False)
        for m in list(ROUTER_IFACES) + list(HOST_ROUTER):
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)

        # the VM network lives on hv's loopback: every address of it answers
        self.cmd('hv', f"ip addr add {d.ips.vm} dev lo")
        # the backup link is slow
        for r in TRANSIT[BACKUP_LINK]:
            self.cmd(r, netem_cmd(iface(r, BACKUP_LINK), BACKUP_DELAY_MS))

        # hidden machines: the listener is up before the first RIP update (FRR starts at step 2)
        install_rip_probe(self, 'probe')
        self.cmd('probe', rip_listen_cmd(PROBE_IFACES.values(), keys={d.key_id: d.key_secret}))
        install_rip_probe(self, 'intruder')
        self.cmd('intruder', rip_announce_cmd(d.ips.intruder, [(d.nets.ghost, 1)], interval=GHOST_INTERVAL))

        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", FRR_DAEMONS, permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: every grade element is at its maximum when the state returns.

        Step 1 configures the four routers (see _reference()): r3 stops listening to the rogue
        speaker.  Steps 2 and 3 clear the RIP routes of the four routers, so that a bogus route
        learned under the old 180 s timeout goes at once; all at the same step, and twice: a
        router cleared before its neighbours learns the route again from them (seen live: the
        ring then counts to infinity for some seconds).  Step 4 waits until every router has
        sent an update with its new configuration and the LAN interfaces have been silent for
        a whole window.  Form questions are filled through cheat_answers.
        """
        d = self.data
        for r in ROUTER_IFACES:
            self._vtysh(r, *self._reference(r))
        for step in (2, 3):
            for r in ROUTER_IFACES:
                self.cmd(r, 'vtysh -c "clear ip rip"', step=step)
        self.cmd('r1', f"sleep {rip_window(d.update_timer) + 8}", step=4)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s, default: int = -1) -> int:
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _same_ip(answer: str, expected) -> bool:
    try:
        return IPv4Interface(_norm(answer)).ip == expected
    except ValueError:
        return False


def _same_network(answer: str, expected: IPv4Network) -> bool:
    try:
        return IPv4Network(_norm(answer), strict=False) == expected
    except ValueError:
        return False


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        routers = list(ROUTER_IFACES)

        def addr(router: str, net: str):
            return getattr(d.ips, f"{router}_{net}").ip

        def prefix(net: str) -> IPv4Network:
            return getattr(d.nets, net)

        # ---------------- diagnostics kept in the archive -------------------------
        for r in routers:
            for c in ('vtysh -c "show running-config"', 'vtysh -c "show ip route"'):
                self.test(r, c, allow_error=True)

        # ---------------- live state of every router, and what the probe heard -----
        status = {r: get_rip_status(self, r, allow_error=True) for r in routers}
        table = {r: get_rip_routes(self, r, allow_error=True) for r in routers}
        kroutes = {r: get_kernel_routes(self, r, allow_error=True) for r in routers}
        k6routes = {r: get_ip6_routes(self, r) for r in routers}
        probe = get_rip_probe(self, 'probe')
        # how old an update of a router may be: its own update timer, plus the jitter
        window = {r: rip_window(status[r].get('update')) for r in routers}

        def rip_gateways(r: str, net_prefix) -> set:
            return set(kernel_route_gateways(kroutes[r], net_prefix, protocols=RIP_ROUTE_PROTOCOLS))

        def has_rip_route(r: str, net_prefix) -> bool:
            return bool(rip_gateways(r, net_prefix))

        def heard_from(r: str, net: str) -> bool:
            """r sent an update on net during its last window."""
            return heard(probe, PROBE_IFACES[net], addr(r, net), window[r])

        def announces(r: str, net: str, net_prefix):
            """Metric r announces for net_prefix on net (None: not announced)."""
            return announced_metric(probe, PROBE_IFACES[net], addr(r, net), net_prefix, window[r])

        def offers(r: str, net: str, net_prefix) -> bool:
            metric = announces(r, net, net_prefix)
            return metric is not None and metric < RIP_INFINITY

        def ping(src: str, dest) -> bool:
            return eval_ping(self, src=src, dest=dest, count=2, deadline=3, allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        # addressing plan: one row per network, with the interfaces (and hosts) on it
        members = {net: [] for net in SITE_NETS + ['wan']}
        for r, r_ifaces in ROUTER_IFACES.items():
            for n, (net, attr) in enumerate(r_ifaces):
                members[net].append(f"`{r}` eth{n} (`{getattr(d.ips, attr).ip}`)")
        for h, (_r, r_attr) in HOST_ROUTER.items():
            members[r_attr.split('_', 1)[1]].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        members['wan'].append(f"`isp` (`{d.ips.isp.ip}`)")
        addressing = "\n".join(
            f"| `{net}` | `{prefix(net)}` | " + (f"`{getattr(d.nets6, net)}`" if net in SITE_OCTETS else "—")
            + f" | {', '.join(members[net])} |"
            for net in members)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente RIP (vecteur de distance, messages, temporisateurs,
boucles), sa configuration avec FRR et `vtysh`, la sécurité, RIPng et les commandes de diagnostic.

**Le réseau.** Le site est desservi par quatre routeurs, `r1` à `r4`, sur lesquels la suite
**FRRouting** (FRR) est installée et démarrée, démons `ripd` et `ripngd` compris. Ils forment un
anneau `r1` – `r2` – `r3` – `r4`. Le lien `l13` (en orange sur le schéma) relie directement `r1`
et `r3`, mais c'est un lien **lent**, prévu comme secours.

- `pc1` et `pc2` sont des postes. `hv` est un serveur de virtualisation : ses machines virtuelles
  sont dans un réseau interne, `vmnet` (`{vmnet}`), que seul `hv` sait joindre ; la machine
  virtuelle `vm` a l'adresse `{vm}`.
- `r4` est le routeur de sortie du site. `isp` est le routeur du fournisseur d'accès : vous ne
  l'administrez pas, et il connaît déjà la route de retour vers tout le site (`{site}`).
  L'adresse `{internet}` (nom `internet`) est située « sur Internet », derrière lui.
- Toutes les adresses IPv4 et IPv6 sont déjà configurées, de même que la route par défaut des
  hôtes vers leur routeur. Les fichiers `/etc/hosts` contiennent les noms des interfaces :
  `r3-eth2` désigne l'adresse de l'interface `eth2` de `r3`, `r3` (tout court) celle de `eth0`.
- **Au départ**, `r1` et `r2` échangent déjà des routes RIP sur leur lien `l12`. `r3` et `r4`
  n'ont aucune configuration RIP ; `r4` a seulement une route par défaut statique vers `isp`.

**Plan d'adressage.** Le troisième octet d'un préfixe IPv4 (et le quatrième groupe d'un préfixe
IPv6) rappelle le nom du réseau. En IPv6, `rN` porte l'identifiant `::N` sur chacun de ses liens
et les hôtes `::100` ; le lien `wan` n'a pas d'IPv6.

| réseau | IPv4 | IPv6 | interfaces |
|--------|------|------|------------|
{addressing}

**Valeurs propres à votre instance.**

- temporisateurs (partie 3) : *update* **{update} s**, *timeout* **{timeout} s**, *garbage*
  **{garbage} s** ;
- métrique de la route statique redistribuée (partie 6) : **{static_metric}** ;
- pénalité du lien de secours (partie 7) : **{offset}** ;
- authentification (partie 8) : clé numéro **{key_id}**, secret `{secret}`.

**Consignes.**

- Les parties sont à faire **dans l'ordre** : chaque partie s'appuie sur la configuration
  réalisée dans les précédentes, qui reste en place.
- Sauvegardez régulièrement la configuration des routeurs (`write` dans vtysh) : elle est
  conservée dans `/etc/frr/frr.conf`.
- Votre réseau n'est pas un laboratoire stérile. Si un réseau qui ne figure pas dans le plan
  d'adressage apparaît dans vos tables, notez-le et continuez : la partie 8 y revient.

**Évaluation.** Chaque évaluation lit vos réponses et les tables des routeurs, lance des `ping`
entre les hôtes et **écoute les annonces RIP** émises sur chaque réseau du site. Une modification
n'est donc prise en compte qu'une fois **annoncée** : après un changement, attendez une période
de mise à jour avant de lancer une évaluation (une quarantaine de secondes avec les
temporisateurs par défaut, une dizaine après la partie 3). De même, une route qui n'est plus
annoncée ne quitte les tables qu'à l'expiration de son *timeout* ; `clear ip rip` l'efface tout
de suite.
""").format(vmnet=d.nets.vmnet, vm=d.ips.vm.ip, site=d.nets.site, internet=INTERNET_HOST.ip,
            addressing=addressing, update=d.update_timer, timeout=d.timeout_timer, garbage=d.garbage_timer,
            static_metric=d.static_metric, offset=d.backup_offset, key_id=d.key_id, secret=d.key_secret)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Deux machines sont cachées aux étudiants (elles apparaissent dans le *schéma complet*
d'un projet de débogage) :

- `probe` a une interface, sans adresse, sur chacun des huit réseaux du site. Elle n'émet jamais
  rien et note les annonces RIP qu'elle entend : c'est par elle que l'évaluation sait ce que
  chaque routeur annonce réellement sur un lien (interfaces passives, empoisonnement inverse,
  `offset-list`, authentification MD5 vérifiée avec la clé de l'instance). Une annonce compte
  pendant une période de mise à jour du routeur, plus un quart et 3 s ;
- `intruder` (`{intruder}`, sur `lan3`) annonce toutes les {interval} s le réseau fantôme
  `{ghost}` avec la métrique 1 : il entre dans les tables dès que RIP est activé sur l'interface
  `eth0` de `r3` (partie 2) et n'en sort qu'à la partie 8.

L'état `final` (onglet *Appliquer une configuration*) applique toute la solution sur les quatre
routeurs, efface les routes apprises (`clear ip rip`), attend que les nouvelles annonces aient
été entendues puis remplit les formulaires : une évaluation lancée dès son retour donne tous les
points.
""").format(intruder=d.ips.intruder.ip, interval=GHOST_INTERVAL, ghost=d.nets.ghost)),
        )

        # =====================================================================
        # Part 1 — discovery
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Découverte de RIP sur r1 et r2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Découverte de RIP sur r1 et r2"),
            description=tr("""
`r1` et `r2` sont déjà configurés. Sur chacun, ouvrez `vtysh` et lisez la configuration
(`show running-config`), la table de RIP (`show ip rip`), son état (`show ip rip status`) et la
table de routage (`show ip route`). Observez les annonces échangées sur le lien `l12` :
`tcpdump -ni eth1 -v udp port 520` sur `r1` (sections @@ref:messages@@ et @@ref:frr@@).

Depuis `pc2`, essayez de joindre `pc1` : le `ping` échoue. Trouvez pourquoi en comparant ce que
`r1` et `r2` annoncent, puis corrigez la configuration de `r1` pour que son réseau `lan1`
(`{lan1}`) soit annoncé. Vérifiez que `r2` apprend la route et que `pc1` et `pc2` se joignent.
""").format(lan1=d.nets.lan1)
            + instructor(tr("""
**Solution.** `r1` n'a qu'une commande `network {l12}` : RIP est actif sur son interface `eth1`
mais `lan1` n'est pas annoncé. `r2` n'a donc aucune route vers `lan1` et ne sait pas répondre à
`pc1`, alors que `r1` connaît `lan2`, que `r2` annonce. Dans `vtysh` sur `r1` :

```
configure terminal
 router rip
  network {lan1}
 end
write
```

`r1` envoie aussitôt une mise à jour déclenchée : `show ip rip` sur `r2` affiche
`R(n) {lan1}` par `{r1_l12}`, métrique 2.

Évaluation : `discovery_lan1_announced` (2 points : `r2` a une route RIP vers `lan1` par `r1`),
`discovery_pings` (2 : `pc1` et `pc2` se joignent dans les deux sens).
""").format(l12=d.nets.l12, lan1=d.nets.lan1, r1_l12=addr('r1', 'l12'))),
        )
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations"),
            description=tr("""
À partir de vos observations sur `r1` et `r2` :

- adresse de destination des annonces RIP :
  @@{group:>224.0.0.5|224.0.0.9|224.0.0.10|255.255.255.255}@@ et port UDP : @@{port:[0-9]+}@@
- type des messages émis périodiquement (affiché par `tcpdump -v`) :
  @@{command:>Request|Response|Update|Hello}@@
- métrique de la route vers `lan2` dans la table de `r1` : @@{metric:[0-9]+}@@
- temporisateurs affichés par `show ip rip status`, en secondes — *update* : @@{update:[0-9]+}@@,
  *timeout* : @@{timeout:[0-9]+}@@, *garbage* : @@{garbage:[0-9]+}@@
- distance administrative des routes RIP (le premier nombre entre crochets dans
  `show ip route`) : @@{distance:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.**

- les annonces de RIPv2 sont envoyées à **224.0.0.9**, port UDP **520** (`224.0.0.5` est
  l'adresse d'OSPF, `224.0.0.10` celle d'EIGRP, la diffusion celle de RIPv1) ;
- ce sont des **Response** : RIP n'a pas de message propre aux annonces ;
- `lan2` est à la métrique **2** sur `r1` : `r2` l'annonce avec 1, `r1` ajoute 1 ;
- *update* **30** s, *timeout* **180** s, *garbage* **120** s ;
- distance administrative **120** (`R>* … [120/2]`).

Évaluation, pour l'enseignant seulement : `discovery_destination` (1 point), `discovery_message`
(1), `discovery_metric` (1), `discovery_timers` (1), `discovery_distance` (1).
""")),
            cheat_answers={"final": {
                "group": "224.0.0.9", "port": "520", "command": "Response", "metric": "2",
                "update": "30", "timeout": "180", "garbage": "120", "distance": "120",
            }},
        )
        self.add_grade_element(
            title=no_tr("discovery_lan1_announced"), max_grade=2, grade_part=part1,
            grade=2 * int(str(addr('r1', 'l12')) in rip_gateways('r2', d.nets.lan1)),
            description=tr("r2 apprend lan1 par RIP"),
        )
        # Register every ping on the first pass: no short-circuit `and` around ping()/test() calls.
        pings_pc1_pc2 = all([ping('pc1', d.ips.pc2.ip), ping('pc2', d.ips.pc1.ip)])
        self.add_grade_element(
            title=no_tr("discovery_pings"), max_grade=2, grade_part=part1, grade=2 * int(pings_pc1_pc2),
            description=tr("pc1 et pc2 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("discovery_destination"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("group")) == "224.0.0.9" and _int(q1.get("port")) == 520),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("adresse de groupe et port de RIPv2"),
        )
        self.add_grade_element(
            title=no_tr("discovery_message"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("command")) == "response"), scope=params.EXO_EVAL_SCOPE,
            description=tr("type des annonces périodiques"),
        )
        self.add_grade_element(
            title=no_tr("discovery_metric"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("metric")) == 2), scope=params.EXO_EVAL_SCOPE,
            description=tr("métrique de lan2 sur r1"),
        )
        self.add_grade_element(
            title=no_tr("discovery_timers"), max_grade=1, grade_part=part1,
            grade=int((_int(q1.get("update")), _int(q1.get("timeout")), _int(q1.get("garbage"))) == (30, 180, 120)),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("temporisateurs par défaut"),
        )
        self.add_grade_element(
            title=no_tr("discovery_distance"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("distance")) == 120), scope=params.EXO_EVAL_SCOPE,
            description=tr("distance administrative de RIP"),
        )

        # =====================================================================
        # Part 2 — RIP on the whole site
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — RIP sur r3 et r4"))
        self.question_dummy(
            section=self.section(0),
            title=tr("RIP sur r3 et r4"),
            description=tr("""
Étendez RIP à tout le site :

- sur `r3`, créez le processus RIP, en **version 2**, et activez-le sur ses quatre interfaces :
  `lan3` (`{lan3}`), `l13` (`{l13}`), `l23` (`{l23}`) et `l34` (`{l34}`) ;
- sur `r4`, faites de même sur `l14` (`{l14}`) et `l34` — mais **pas** sur `wan` : on n'échange
  pas de routes RIP avec le fournisseur d'accès ;
- sur `r1` et `r2`, activez RIP sur leurs liens vers `r3` et `r4` : `l13` et `l14` pour `r1`,
  `l23` pour `r2`.

Vérifiez que chaque routeur connaît les huit réseaux du site (`show ip rip`), que ses voisins
figurent dans `show ip rip status`, et que `pc1`, `pc2` et `hv` se joignent (`ping`,
`traceroute`).
""").format(lan3=d.nets.lan3, l13=d.nets.l13, l23=d.nets.l23, l34=d.nets.l34, l14=d.nets.l14)
            + instructor(tr("""
**Solution.** Dans `vtysh`, après `configure terminal` (puis `end` et `write`) :

```
! r3
router rip
 version 2
 network {lan3}
 network {l13}
 network {l23}
 network {l34}
!
! r4
router rip
 version 2
 network {l14}
 network {l34}
!
! r1
router rip
 network {l13}
 network {l14}
!
! r2
router rip
 network {l23}
```

- Une seule commande `network {site}` conviendrait aussi sur `r1`, `r2` et `r3` (toutes leurs
  interfaces sont dans ce préfixe) ; sur `r4` également, puisque `wan` (`{wan}`) n'en fait pas
  partie.
- Sans `version 2`, FRR émet en version 2 mais accepte les deux versions
  (`receive any version` dans `show ip rip status`).
- Dès que RIP est activé sur `eth0` de `r3`, le réseau fantôme `{ghost}`, annoncé par la machine
  cachée `intruder` (`{intruder}`), entre dans toutes les tables : c'est l'objet de la partie 8.

Évaluation : `site_r3` (2 points : RIP version 2 sur `r3`, qui a des routes RIP vers `lan1` et
`lan2`), `site_r4` (2 : de même sur `r4` vers les trois LAN), `site_tables` (4 : 1 par routeur
qui connaît les huit réseaux du site), `site_pings` (4 : `pc1` ↔ `hv` et `pc2` ↔ `hv`).
""").format(lan3=d.nets.lan3, l13=d.nets.l13, l23=d.nets.l23, l34=d.nets.l34, l14=d.nets.l14,
            site=d.nets.site, wan=d.nets.wan, ghost=d.nets.ghost, intruder=d.ips.intruder.ip)),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Métriques"),
            description=tr("""
Une fois les tables complètes :

- métrique de la route de `r4` vers `lan2` : @@{metric_r4_lan2:[0-9]+}@@
- métrique de la route de `r1` vers `lan3` : @@{metric_r1_lan3:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** `lan2` est à **3** de `r4` (par `r1` puis `r2`, ou par `r3` puis `r2` : `r2`
annonce 1, son voisin 2, `r4` 3). `lan3` est à **2** de `r1`, par le lien direct `l13`.

Évaluation, pour l'enseignant seulement : `site_metrics` (2 points : 1 par réponse).
""")),
            cheat_answers={"final": {"metric_r4_lan2": "3", "metric_r1_lan3": "2"}},
        )

        def version_2(r: str) -> bool:
            return status[r].get('send_version') == '2' and status[r].get('receive_version') == '2'

        self.add_grade_element(
            title=no_tr("site_r3"), max_grade=2, grade_part=part2,
            grade=2 * int(version_2('r3') and has_rip_route('r3', d.nets.lan1) and has_rip_route('r3', d.nets.lan2)),
            description=tr("RIP version 2 sur r3, qui apprend lan1 et lan2"),
        )
        self.add_grade_element(
            title=no_tr("site_r4"), max_grade=2, grade_part=part2,
            grade=2 * int(version_2('r4') and all(has_rip_route('r4', prefix(lan)) for lan in LANS)),
            description=tr("RIP version 2 sur r4, qui apprend les trois LAN"),
        )
        self.add_grade_element(
            title=no_tr("site_tables"), max_grade=4, grade_part=part2,
            grade=sum(int(all(str(prefix(net)) in kroutes[r] for net in SITE_NETS)) for r in routers),
            description=tr("chaque routeur connaît les huit réseaux du site"),
        )
        pings_pc1_hv = all([ping('pc1', d.ips.hv.ip), ping('hv', d.ips.pc1.ip)])
        pings_pc2_hv = all([ping('pc2', d.ips.hv.ip), ping('hv', d.ips.pc2.ip)])
        self.add_grade_element(
            title=no_tr("site_pings"), max_grade=4, grade_part=part2,
            grade=2 * int(pings_pc1_hv) + 2 * int(pings_pc2_hv),
            description=tr("pc1 et pc2 joignent hv, et réciproquement"),
        )
        self.add_grade_element(
            title=no_tr("site_metrics"), max_grade=2, grade_part=part2,
            grade=int(_int(q2.get("metric_r4_lan2")) == 3) + int(_int(q2.get("metric_r1_lan3")) == 2),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("métriques de r4 vers lan2 et de r1 vers lan3"),
        )

        # =====================================================================
        # Part 3 — convergence, loops, timers
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Convergence, boucles et temporisateurs"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Convergence, boucles et temporisateurs"),
            description=tr("""
**Une panne.** Sur `r2`, suivez la table de RIP : `watch -n 1 'vtysh -c "show ip rip"'`. Sur
`r1`, lancez une capture sur le lien vers `r4` (`tcpdump -ni eth3 -v udp port 520`) puis, dans un
autre terminal, coupez l'interface du lien `l12` : `ip link set eth1 down`.

- Pour `r1`, la panne est immédiate : que contient l'annonce qu'il envoie aussitôt ?
- Pour `r2`, dont l'interface reste active, la panne est **silencieuse** : suivez la colonne
  *Time* de sa route vers `lan1`, et mesurez pendant combien de temps `pc2` ne joint plus `pc1`.

Rétablissez le lien (`ip link set eth1 up`).

**Temporisateurs.** Sur les **quatre** routeurs, réglez les temporisateurs de RIP à
**{update} s** (*update*), **{timeout} s** (*timeout*) et **{garbage} s** (*garbage*)
(section @@ref:timers@@), puis refaites l'expérience.

**Empoisonnement inverse.** Avec la capture `tcpdump -ni eth1 -v udp port 520` sur `r1`,
vérifiez que `r1` n'annonce pas à `r2` les routes qu'il tient de lui (horizon partagé). Puis
activez l'**empoisonnement inverse** aux deux extrémités du lien `l12` — interface `eth1` de `r1`
et de `r2` — et observez de nouveau les annonces (section @@ref:loops@@).
""").format(update=d.update_timer, timeout=d.timeout_timer, garbage=d.garbage_timer)
            + instructor(tr("""
**Solution.** Sur chacun des quatre routeurs :

```
router rip
 timers basic {update} {timeout} {garbage}
```

et sur `r1` et `r2` :

```
interface eth1
 ip rip split-horizon poisoned-reverse
```

- À la coupure, `r1` invalide les routes apprises par `eth1` et envoie une **mise à jour
  déclenchée** qui les annonce avec la métrique **16** (empoisonnement de route) ; il ne retrouve
  `lan2` par un autre voisin qu'à l'annonce périodique suivante de celui-ci.
- `r2` ne voit rien : sa route vers `lan1` par `r1` reste en place jusqu'à l'expiration du
  *timeout*, **180 s** par défaut, pendant lesquelles `pc2` ne joint plus `pc1`. Ce n'est qu'alors
  qu'il accepte la route, plus longue, annoncée par `r3`. Avec les nouveaux temporisateurs, ce
  délai tombe à **{timeout} s**.
- Avec l'horizon partagé simple, `r1` ne dit rien de `lan2` sur `l12` ; avec l'empoisonnement
  inverse, il l'y annonce avec la métrique 16, ainsi que le réseau de `l12` lui-même.

Évaluation : `convergence_timers` (4 points : 1 par routeur dont `show ip rip status` affiche
{update} / {timeout} / {garbage}), `convergence_poisoned_reverse` (4 : 2 par extrémité de `l12`
dont les annonces entendues sur le lien portent des routes à 16).
""").format(update=d.update_timer, timeout=d.timeout_timer, garbage=d.garbage_timer)),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations"),
            description=tr("""
- Juste après la coupure, métrique avec laquelle `r1` annonce `lan2` à `r4` :
  @@{poison_metric:[0-9]+}@@
- Message par lequel `r1` l'annonce sans attendre :
  @@{trigger:>annonce périodique|mise à jour déclenchée|requête}@@
- Avec les temporisateurs par défaut, temps pendant lequel `r2` garde sa route vers `lan1` par
  `r1` après la coupure : @@{silent_delay:>30 s|120 s|180 s|300 s}@@
- Ce même temps, en secondes, avec vos nouveaux temporisateurs : @@{new_delay:[0-9]+}@@
- Avec l'horizon partagé simple (avant l'empoisonnement inverse), `r1` annonce-t-il `lan2` sur
  `l12` ? @@{split_horizon:>oui|non}@@
""")
            + instructor(tr("""
**Solution.** Métrique **16** ; **mise à jour déclenchée** ; **180 s** (le *timeout*) ;
**{timeout}** s ; **non**.

Évaluation, pour l'enseignant seulement : `convergence_route_poisoning` (1 point),
`convergence_triggered_update` (1), `convergence_silent_failure` (1), `convergence_new_delay`
(1), `convergence_split_horizon` (1).
""").format(timeout=d.timeout_timer)),
            cheat_answers={"final": {
                "poison_metric": "16", "trigger": "mise à jour déclenchée", "silent_delay": "180 s",
                "new_delay": str(d.timeout_timer), "split_horizon": "non",
            }},
        )
        expected_timers = (d.update_timer, d.timeout_timer, d.garbage_timer)
        self.add_grade_element(
            title=no_tr("convergence_timers"), max_grade=4, grade_part=part3,
            grade=sum(int((status[r].get('update'), status[r].get('timeout'), status[r].get('garbage'))
                          == expected_timers) for r in routers),
            description=tr("temporisateurs demandés sur les quatre routeurs"),
        )

        def poisons(r: str, peer: str) -> bool:
            """The updates of r on the poison link carry what split horizon would leave out,
            with metric 16: the prefix of the link itself, or a route learned from the peer."""
            own = announces(r, POISON_LINK, prefix(POISON_LINK)) == RIP_INFINITY
            peer_lan = prefix(next(lan for lan, router in LANS.items() if router == peer))
            learned = (str(addr(peer, POISON_LINK)) in rip_route_sources(table[r], peer_lan)
                       and announces(r, POISON_LINK, peer_lan) == RIP_INFINITY)
            return own or learned

        self.add_grade_element(
            title=no_tr("convergence_poisoned_reverse"), max_grade=4, grade_part=part3,
            grade=2 * int(poisons('r1', 'r2')) + 2 * int(poisons('r2', 'r1')),
            description=tr("empoisonnement inverse aux deux extrémités de l12"),
        )
        self.add_grade_element(
            title=no_tr("convergence_route_poisoning"), max_grade=1, grade_part=part3,
            grade=int(_int(q3.get("poison_metric")) == RIP_INFINITY), scope=params.EXO_EVAL_SCOPE,
            description=tr("métrique d'une route perdue"),
        )
        self.add_grade_element(
            title=no_tr("convergence_triggered_update"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("trigger")) == "mise à jour déclenchée"), scope=params.EXO_EVAL_SCOPE,
            description=tr("message envoyé à la coupure"),
        )
        self.add_grade_element(
            title=no_tr("convergence_silent_failure"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("silent_delay")) == "180 s"), scope=params.EXO_EVAL_SCOPE,
            description=tr("détection d'une panne silencieuse avec les temporisateurs par défaut"),
        )
        self.add_grade_element(
            title=no_tr("convergence_new_delay"), max_grade=1, grade_part=part3,
            grade=int(_int(q3.get("new_delay")) == d.timeout_timer), scope=params.EXO_EVAL_SCOPE,
            description=tr("détection d'une panne silencieuse avec les nouveaux temporisateurs"),
        )
        self.add_grade_element(
            title=no_tr("convergence_split_horizon"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("split_horizon")) == "non"), scope=params.EXO_EVAL_SCOPE,
            description=tr("horizon partagé"),
        )

        # =====================================================================
        # Part 4 — passive interfaces
        # =====================================================================
        part4 = self.add_grade_part(no_tr("part4"), tr("Partie 4 — Interfaces passives"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Interfaces passives"),
            description=tr("""
Sur `pc1`, lancez `tcpdump -ni eth0 udp port 520` : `r1` envoie ses annonces RIP sur le réseau
des postes, où aucun routeur ne les attend.

Faites en sorte que `r1`, `r2` et `r3` n'émettent **plus aucune annonce** sur leur réseau
d'hôtes (`lan1`, `lan2`, `lan3` : leur interface `eth0`), tout en continuant à **annoncer ces
réseaux** aux autres routeurs (section @@ref:passive@@). Vérifiez avec `tcpdump` sur les hôtes,
avec `show ip rip status`, et en contrôlant que `pc1`, `pc2` et `hv` se joignent toujours.
""")
            + instructor(tr("""
**Solution.** Sur `r1`, `r2` et `r3` :

```
router rip
 passive-interface eth0
```

`show ip rip status` liste alors `eth0` sous *Passive Interface(s)* ; le réseau reste `C(i)` dans
`show ip rip` et les autres routeurs le gardent. Retirer la commande `network` du LAN ne
conviendrait pas : le réseau ne serait plus annoncé (sauf à ajouter `redistribute connected`,
autre solution acceptée).

Évaluation : `passive_lan1`, `passive_lan2`, `passive_lan3` (3 points chacun) : l'interface est
passive dans `show ip rip status` (ou RIP n'y est pas activé), aucune annonce du routeur n'a été
entendue sur le LAN pendant une fenêtre complète, le LAN figure toujours dans la table RIP du
routeur, et un autre routeur l'apprend par RIP. Après la commande, il faut donc attendre une
période avant l'évaluation.
""")),
        )
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Passive, mais pas sourde"),
            description=tr("""
Une interface passive accepte-t-elle encore les annonces RIP qu'elle reçoit ?
@@{passive_listens:>oui|non}@@
""")
            + instructor(tr("""
**Solution.** **Oui** : `passive-interface` ne supprime que l'émission. C'est ce qui rend
possible l'intrusion de la partie 8.

Évaluation, pour l'enseignant seulement : `passive_listens` (1 point).
""")),
            cheat_answers={"final": {"passive_listens": "oui"}},
        )
        for lan, r in LANS.items():
            # a silence only counts when the probe listened for a whole window...
            silent = probe_ready(probe, window[r]) and not heard_from(r, lan)
            # ... and when the router says it will stay silent: an interface RIP has just been
            # enabled on sends its first update up to a period later (seen live)
            muted = (iface(r, lan) in status[r].get('passive_interfaces', [])
                     or iface(r, lan) not in status[r].get('interfaces', {}))
            in_rip = any(path['code'] == 'C' for path in table[r].get(str(prefix(lan)), []))
            learned = any(has_rip_route(other, prefix(lan)) for other in routers if other != r)
            self.add_grade_element(
                title=no_tr(f"passive_{lan}"), max_grade=3, grade_part=part4,
                grade=3 * int(silent and muted and in_rip and learned),
                description=tr("aucune annonce RIP sur {lan}, qui reste annoncé aux autres routeurs").format(lan=lan),
            )
        self.add_grade_element(
            title=no_tr("passive_listens"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("passive_listens")) == "oui"), scope=params.EXO_EVAL_SCOPE,
            description=tr("une interface passive écoute encore"),
        )

        # =====================================================================
        # Part 5 — default route
        # =====================================================================
        part5 = self.add_grade_part(no_tr("part5"), tr("Partie 5 — Route par défaut"))
        default_route = IPv4Network("0.0.0.0/0")
        self.question_dummy(
            section=self.section(0),
            title=tr("Route par défaut"),
            description=tr("""
Depuis `pc1`, `ping internet` (`{internet}`) échoue : seul `r4`, qui a une route par défaut
statique vers `isp`, sait sortir du site.

Faites annoncer par `r4` une **route par défaut** dans RIP (section @@ref:redistribution@@),
sans activer RIP sur le lien `wan`. Vérifiez que `r1`, `r2` et `r3` l'apprennent et que `pc1`,
`pc2` et `hv` joignent `internet` (`traceroute -n internet` montre le chemin).
""").format(internet=INTERNET_HOST.ip)
            + instructor(tr("""
**Solution.** Sur `r4` :

```
router rip
 default-information originate
```

`show ip rip` sur `r4` affiche `R(d) 0.0.0.0/0` (route engendrée par le routeur, métrique 1) ;
`r1` et `r3` l'apprennent avec la métrique 2, `r2` avec 3. La route par défaut statique de `r4`
sert à `r4` lui-même : c'est `default-information originate` qui la fait connaître aux autres.

Évaluation : `default_routes` (3 points : 1 par routeur parmi `r1`, `r2`, `r3` qui a une route
par défaut RIP), `default_pings` (6 : 2 par hôte qui joint `{internet}`).
""").format(internet=INTERNET_HOST.ip)),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("La route par défaut dans les tables"),
            description=tr("""
- métrique de la route par défaut sur `r2` : @@{default_metric:[0-9]+}@@
- code de la route `0.0.0.0/0` dans `show ip rip` sur `r4` : @@{default_code:>R(n)|R(d)|S(r)|C(i)}@@
""")
            + instructor(tr("""
**Solution.** **3** sur `r2` (1 sur `r4`, 2 sur ses voisins `r1` et `r3`) ; **R(d)** sur `r4`.

Évaluation, pour l'enseignant seulement : `default_answers` (2 points : 1 par réponse).
""")),
            cheat_answers={"final": {"default_metric": "3", "default_code": "R(d)"}},
        )
        self.add_grade_element(
            title=no_tr("default_routes"), max_grade=3, grade_part=part5,
            grade=sum(int(has_rip_route(r, default_route)) for r in ('r1', 'r2', 'r3')),
            description=tr("r1, r2 et r3 apprennent la route par défaut par RIP"),
        )
        internet_pings = [ping(h, INTERNET_HOST.ip) for h in HOST_ROUTER]
        self.add_grade_element(
            title=no_tr("default_pings"), max_grade=6, grade_part=part5,
            grade=2 * sum(int(ok) for ok in internet_pings),
            description=tr("pc1, pc2 et hv joignent internet"),
        )
        self.add_grade_element(
            title=no_tr("default_answers"), max_grade=2, grade_part=part5,
            grade=int(_int(q5.get("default_metric")) == 3) + int(_norm(q5.get("default_code")) == "r(d)"),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("métrique et code de la route par défaut"),
        )

        # =====================================================================
        # Part 6 — redistribution of a static route
        # =====================================================================
        part6 = self.add_grade_part(no_tr("part6"), tr("Partie 6 — Redistribution d'une route statique"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Redistribution d'une route statique"),
            description=tr("""
Les machines virtuelles de `hv` sont dans le réseau `vmnet` (`{vmnet}`), accessible uniquement
par `hv` (`{hv}`), qui ne parle pas RIP : aucun routeur ne connaît ce réseau.

- Sur `r3`, ajoutez **dans FRR** une route statique vers `vmnet` passant par `hv` (commande
  `ip route` du mode configuration de `vtysh`, et non la commande Linux `ip route add`).
- Faites annoncer cette route par RIP avec la métrique **{metric}**
  (section @@ref:redistribution@@).

Vérifiez que `r1`, `r2` et `r4` apprennent la route et que `pc1` et `pc2` joignent la machine
virtuelle `vm` (`{vm}`).
""").format(vmnet=d.nets.vmnet, hv=d.ips.hv.ip, metric=d.static_metric, vm=d.ips.vm.ip)
            + instructor(tr("""
**Solution.** Sur `r3` :

```
ip route {vmnet} {hv}
router rip
 redistribute static metric {metric}
```

`show ip rip` sur `r3` affiche `S(r) {vmnet}` — avec la métrique 1 dans sa propre table : la
métrique {metric} est celle des **annonces** — et `r2` et `r4` l'apprennent avec
{metric_plus_1}. Une route ajoutée avec `ip route add` sous Linux serait une route du noyau :
`redistribute static` ne l'annoncerait pas (il faudrait `redistribute kernel`).

Évaluation : `static_route_r3` (2 points : `r3` a une route vers `vmnet` par `hv` qui ne vient pas
de RIP), `static_redistributed` (3 : 1 par routeur parmi `r1`, `r2`, `r4` qui l'apprend par RIP),
`static_metric` (1 : métrique {metric_plus_1} dans la table RIP de `r2`), `static_pings` (2 :
`pc1` et `pc2` joignent `vm`).
""").format(vmnet=d.nets.vmnet, hv=d.ips.hv.ip, metric=d.static_metric, metric_plus_1=d.static_metric + 1)),
        )
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Une route redistribuée"),
            description=tr("""
- code de la route vers `vmnet` dans `show ip rip` sur `r3` : @@{static_code:>R(n)|R(s)|S(r)|C(r)}@@
- métrique avec laquelle `r3` l'annoncerait si `metric` n'était pas précisé :
  @@{default_redistribution_metric:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** **S(r)** : une route statique (S) redistribuée (r) ; métrique **1** (*Default
redistribution metric is 1* dans `show ip rip status`, modifiable avec `default-metric`).

Évaluation, pour l'enseignant seulement : `static_answers` (2 points : 1 par réponse).
""")),
            cheat_answers={"final": {"static_code": "S(r)", "default_redistribution_metric": "1"}},
        )
        vmnet_r3 = kroutes['r3'].get(str(d.nets.vmnet)) or {}
        self.add_grade_element(
            title=no_tr("static_route_r3"), max_grade=2, grade_part=part6,
            grade=2 * int(str(d.ips.hv.ip) in [gw for gw, _dev in vmnet_r3.get('nexthops', [])]
                          and vmnet_r3.get('protocol') not in RIP_ROUTE_PROTOCOLS),
            description=tr("route de r3 vers vmnet par hv"),
        )
        self.add_grade_element(
            title=no_tr("static_redistributed"), max_grade=3, grade_part=part6,
            grade=sum(int(has_rip_route(r, d.nets.vmnet)) for r in ('r1', 'r2', 'r4')),
            description=tr("r1, r2 et r4 apprennent vmnet par RIP"),
        )
        self.add_grade_element(
            title=no_tr("static_metric"), max_grade=1, grade_part=part6,
            grade=int(rip_route_metric(table['r2'], d.nets.vmnet, learned=True) == d.static_metric + 1),
            description=tr("métrique demandée pour la route redistribuée"),
        )
        vm_pings = [ping(h, d.ips.vm.ip) for h in ('pc1', 'pc2')]
        self.add_grade_element(
            title=no_tr("static_pings"), max_grade=2, grade_part=part6,
            grade=sum(int(ok) for ok in vm_pings),
            description=tr("pc1 et pc2 joignent vm"),
        )
        self.add_grade_element(
            title=no_tr("static_answers"), max_grade=2, grade_part=part6,
            grade=(int(_norm(q6.get("static_code")) == "s(r)")
                   + int(_int(q6.get("default_redistribution_metric")) == 1)),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("code et métrique par défaut d'une route redistribuée"),
        )

        # =====================================================================
        # Part 7 — metrics: the backup link, ECMP
        # =====================================================================
        part7 = self.add_grade_part(no_tr("part7"), tr("Partie 7 — Métriques et choix des chemins"))
        offset = d.backup_offset
        self.question_dummy(
            section=self.section(0),
            title=tr("Métriques et choix des chemins"),
            description=tr("""
Depuis `r1`, comparez `ping r3-eth1` (par le lien `l13`) et `ping r2-eth1` : `l13` est un lien
lent. Pourtant `traceroute -n hv` depuis `pc1` montre que tout le trafic entre `lan1` et `lan3`
l'emprunte : pourquoi ?

- Sur `r1` et sur `r3`, ajoutez **{offset}** à la métrique de toutes les routes **annoncées sur
  `l13`** (une `offset-list` en sortie, section @@ref:tuning@@). Ne retirez pas `l13` de RIP : il
  doit rester disponible comme chemin de secours.
- Les deux chemins de l'anneau, par `r2` et par `r4`, ont alors la même métrique : sur `r1` et
  sur `r3`, autorisez RIP à installer les deux.

Vérifiez avec `show ip rip` et `ip route` sur `r1` (deux prochains sauts vers `lan3`) et avec
`traceroute` de `pc1` vers `hv`. Pour éprouver le secours, coupez sur `r1` les interfaces de
`l12` et de `l14` : après le *timeout*, le trafic doit passer par `l13`.
""").format(offset=offset)
            + instructor(tr("""
**Solution.** RIP compte les sauts : par `l13`, `lan3` est à 2 sauts de `r1`, contre 3 par
l'anneau. Sur `r1` (interface `{r1_if}`) et sur `r3` (interface `{r3_if}`) :

```
! r1
access-list {acl} permit any
router rip
 offset-list {acl} out {offset} {r1_if}
 allow-ecmp
!
! r3
access-list {acl} permit any
router rip
 offset-list {acl} out {offset} {r3_if}
 allow-ecmp
```

`r3` annonce désormais `lan3` sur `l13` avec la métrique {announced} : pour `r1`, le chemin direct
vaut {backup}, l'anneau 3. `ip route show {lan3}` sur `r1` affiche deux `nexthop`, `{r2_l12}`
(`r2`) et `{r4_l14}` (`r4`). Un décalage en entrée (`in`) aurait le même effet sur les tables,
mais c'est l'annonce qui est demandée et évaluée.

Évaluation : `backup_offset_r1` et `backup_offset_r3` (2 points chacun : sur `l13`, le routeur
annonce son LAN avec la métrique {announced}), `backup_path_r1` et `backup_path_r3` (2 chacun :
la route vers le LAN d'en face ne passe plus par `l13`, qui l'annonce toujours avec une métrique
inférieure à 16), `ecmp_r1` et `ecmp_r3` (2 chacun : les deux prochains sauts de l'anneau).
""").format(offset=offset, acl=OFFSET_ACL, r1_if=iface('r1', BACKUP_LINK), r3_if=iface('r3', BACKUP_LINK),
            announced=1 + offset, backup=2 + offset, lan3=d.nets.lan3, r2_l12=addr('r2', 'l12'),
            r4_l14=addr('r4', 'l14'))),
        )
        q7 = self.question_form(
            section=self.section(1),
            title=tr("Chemins et métriques"),
            description=tr("""
Après ces réglages, sur `r1` :

- métrique de la route vers `lan3` : @@{metric_ring:[0-9]+}@@
- nombre de prochains sauts de cette route : @@{nexthops:[0-9]+}@@
- métrique qu'aurait la route vers `lan3` si elle passait par `l13` : @@{metric_backup:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Métrique **3** par l'anneau, avec **2** prochains sauts ; par `l13`, la route
vaudrait **{backup}** (1 pour `lan3` sur `r3`, plus {offset} en sortie de `r3`, plus 1 à la
réception par `r1`).

Évaluation, pour l'enseignant seulement : `backup_answers` (3 points : 1 par réponse).
""").format(backup=2 + offset, offset=offset)),
            cheat_answers={"final": {"metric_ring": "3", "nexthops": "2", "metric_backup": str(2 + offset)}},
        )
        # each end of the backup link: its LAN, the far LAN, the two next hops of the ring
        backup_ends = {
            'r1': ('lan1', 'lan3', {str(addr('r2', 'l12')), str(addr('r4', 'l14'))}),
            'r3': ('lan3', 'lan1', {str(addr('r2', 'l23')), str(addr('r4', 'l34'))}),
        }
        for r, (own_lan, _far_lan, _ring) in backup_ends.items():
            self.add_grade_element(
                title=no_tr(f"backup_offset_{r}"), max_grade=2, grade_part=part7,
                grade=2 * int(announces(r, BACKUP_LINK, prefix(own_lan)) == 1 + offset),
                description=tr("pénalité des routes annoncées par {r} sur l13").format(r=r),
            )
        for r, (_own_lan, far_lan, ring) in backup_ends.items():
            other = next(o for o in backup_ends if o != r)
            # the backup link must still offer the far LAN: leaving it out of RIP is not the answer
            kept = offers(other, BACKUP_LINK, prefix(far_lan))
            gateways = rip_gateways(r, prefix(far_lan))
            self.add_grade_element(
                title=no_tr(f"backup_path_{r}"), max_grade=2, grade_part=part7,
                grade=2 * int(kept and bool(gateways) and gateways <= ring),
                description=tr("{r} joint {lan} par l'anneau, l13 restant en secours").format(r=r, lan=far_lan),
            )
            self.add_grade_element(
                title=no_tr(f"ecmp_{r}"), max_grade=2, grade_part=part7,
                grade=2 * int(kept and gateways == ring),
                description=tr("{r} répartit le trafic vers {lan} entre r2 et r4").format(r=r, lan=far_lan),
            )
        self.add_grade_element(
            title=no_tr("backup_answers"), max_grade=3, grade_part=part7,
            grade=(int(_int(q7.get("metric_ring")) == 3) + int(_int(q7.get("nexthops")) == 2)
                   + int(_int(q7.get("metric_backup")) == 2 + offset)),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("métriques par l'anneau et par le lien de secours"),
        )

        # =====================================================================
        # Part 8 — security: authentication, the rogue speaker
        # =====================================================================
        part8 = self.add_grade_part(no_tr("part8"), tr("Partie 8 — Sécurité"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Sécurité"),
            description=tr("""
**Authentifier les liens entre routeurs.** Sur les cinq liens entre routeurs (`l12`, `l13`,
`l14`, `l23`, `l34`), authentifiez les annonces RIP en **MD5** avec un trousseau de clés (de nom
quelconque) contenant la clé numéro **{key_id}**, de secret `{secret}`
(section @@ref:security@@). Procédez lien par lien : tant qu'une seule extrémité est configurée,
chacun des deux routeurs rejette les annonces de l'autre. Contrôlez avec `tcpdump -v`, qui
affiche l'en-tête d'authentification, et avec la colonne *BadPackets* de `show ip rip status`.

**Un intrus.** Un réseau qui ne figure pas dans le plan d'adressage est présent dans les tables
de vos routeurs. Trouvez quelle machine l'annonce, et sur quel réseau (colonne *From* de
`show ip rip`, puis `tcpdump`). Faites ensuite en sorte que vos routeurs **ignorent ses
annonces**, tout en continuant à annoncer le réseau où elle se trouve. Les interfaces passives
de la partie 4 suffisaient-elles ?
""").format(key_id=d.key_id, secret=d.key_secret)
            + instructor(tr("""
**Solution.** Sur chaque routeur, le trousseau puis chaque interface vers un autre routeur
(`eth1` à `eth3` pour `r1` et `r3`, `eth1` et `eth2` pour `r2`, `eth0` et `eth1` pour `r4`) :

```
key chain {chain}
 key {key_id}
  key-string {secret}
  exit
 exit
interface eth1
 ip rip authentication mode md5
 ip rip authentication key-chain {chain}
```

Avec `ip rip authentication string {secret}` à la place du trousseau, les annonces portent le
numéro de clé 1 et non {key_id} : un voisin configuré avec le trousseau les rejette, et
l'évaluation ne les compte pas.

L'intrus est `{intruder}`, une machine de `lan3` (cachée sur le schéma) qui annonce `{ghost}` :
`show ip rip` sur `r3` donne `R(n) {ghost}` *From* `{intruder}`, et `tcpdump -ni eth0 udp port 520`
sur `hv` montre ses annonces. L'interface `eth0` de `r3` est passive, mais elle écoute toujours.
Sur `r3` :

```
interface eth0
 ip rip receive version none
```

puis `clear ip rip` (ou attendre le *timeout*). Autres solutions acceptées : ne plus activer RIP
sur `eth0` (`no network {lan3}`) et annoncer le LAN avec `redistribute connected` ; un filtre en
entrée (`distribute-list prefix … in eth0`) ; l'authentification sur `eth0`.

Évaluation : `auth_l12`, `auth_l13`, `auth_l14`, `auth_l23`, `auth_l34` (2 points chacun : 1 par
extrémité dont les annonces entendues sur le lien portent une empreinte MD5 valide pour la clé
{key_id}), `rogue_ignored` (5 : `{ghost}` n'est plus dans la table de routage d'aucun des quatre
routeurs, alors que `r1` et `r2` apprennent toujours `lan3` par RIP).
""").format(chain=KEY_CHAIN, key_id=d.key_id, secret=d.key_secret, intruder=d.ips.intruder.ip,
            ghost=d.nets.ghost, lan3=d.nets.lan3)),
        )
        q8 = self.question_form(
            section=self.section(1),
            title=tr("L'intrus"),
            description=tr("""
- adresse IP de la machine qui annonce le réseau inconnu : @@{rogue_address:[0-9.]+}@@
- préfixe qu'elle annonce (adresse/longueur) : @@{rogue_prefix:[0-9./]+}@@
- une interface passive protège-t-elle de ces annonces ? @@{passive_protects:>oui|non}@@
""")
            + instructor(tr("""
**Solution.** `{intruder}` ; `{ghost}` ; **non**.

Évaluation, pour l'enseignant seulement : `rogue_answers` (3 points : 1 par réponse).
""").format(intruder=d.ips.intruder.ip, ghost=d.nets.ghost)),
            cheat_answers={"final": {
                "rogue_address": str(d.ips.intruder.ip), "rogue_prefix": str(d.nets.ghost), "passive_protects": "non",
            }},
        )
        for link, ends in TRANSIT.items():
            self.add_grade_element(
                title=no_tr(f"auth_{link}"), max_grade=2, grade_part=part8,
                grade=sum(int(md5_authenticated(probe, PROBE_IFACES[link], addr(r, link), window[r],
                                                key_id=d.key_id)) for r in ends),
                description=tr("annonces authentifiées en MD5 sur {link}").format(link=link),
            )
        # an absence only counts on routers that answered, and while lan3 is still announced
        ghost_free = all(kroutes[r] and str(d.nets.ghost) not in kroutes[r] for r in routers)
        lan3_announced = has_rip_route('r1', d.nets.lan3) and has_rip_route('r2', d.nets.lan3)
        self.add_grade_element(
            title=no_tr("rogue_ignored"), max_grade=5, grade_part=part8,
            grade=5 * int(ghost_free and lan3_announced),
            description=tr("le réseau annoncé par l'intrus n'est plus dans les tables"),
        )
        self.add_grade_element(
            title=no_tr("rogue_answers"), max_grade=3, grade_part=part8,
            grade=(int(_same_ip(q8.get("rogue_address"), d.ips.intruder.ip))
                   + int(_same_network(q8.get("rogue_prefix"), d.nets.ghost))
                   + int(_norm(q8.get("passive_protects")) == "non")),
            scope=params.EXO_EVAL_SCOPE,
            description=tr("adresse de l'intrus, préfixe annoncé, limite des interfaces passives"),
        )

        # =====================================================================
        # Part 9 — RIPng (bonus)
        # =====================================================================
        part9 = self.add_grade_part(no_tr("part9"), tr("Partie 9 — RIPng (bonus)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("RIPng (bonus)"),
            description=tr("""
Le site est aussi adressé en IPv6 (voir le plan d'adressage), mais aucune route IPv6 n'est
échangée : depuis `pc1`, `ping hv-v6` (`{hv6}`) échoue.

Activez **RIPng** sur les quatre routeurs, sur toutes leurs interfaces internes au site (pas sur
`wan`, qui n'a pas d'IPv6) (section @@ref:ripng@@). Vérifiez avec `show ipv6 ripng`,
`ip -6 route` et des `ping` entre `pc1`, `pc2` et `hv` (noms `pc1-v6`, `pc2-v6`, `hv-v6`).
""").format(hv6=d.ips6.hv.ip)
            + instructor(tr("""
**Solution.** Sur chaque routeur, avec ses interfaces du site (`eth0` à `eth3` pour `r1` et
`r3`, `eth0` à `eth2` pour `r2`, `eth0` et `eth1` pour `r4`) :

```
router ripng
 network eth0
 network eth1
 network eth2
 network eth3
```

`ip -6 route` montre les préfixes des autres réseaux avec `proto ripng` et un prochain saut
lien-local (`via fe80::… dev ethX`).

Évaluation (points de bonus) : `ripng_routes` (4 : 1 par routeur qui apprend par RIPng les LAN
qui ne lui sont pas connectés), `ripng_pings` (2 : `pc1` ↔ `hv` et `pc2` ↔ `hv` en IPv6).
""")),
        )

        def has_ripng_route(r: str, net: str) -> bool:
            return any(route.get('dst') == str(getattr(d.nets6, net)) and is_ripng_protocol(route.get('protocol'))
                       for route in k6routes[r])

        self.add_grade_element(
            title=no_tr("ripng_routes"), max_grade=4, grade_part=part9, bonus=True,
            grade=sum(int(all(has_ripng_route(r, lan) for lan, owner in LANS.items() if owner != r))
                      for r in routers),
            description=tr("chaque routeur apprend les LAN distants par RIPng"),
        )
        pings6_pc1_hv = all([ping('pc1', d.ips6.hv.ip), ping('hv', d.ips6.pc1.ip)])
        pings6_pc2_hv = all([ping('pc2', d.ips6.hv.ip), ping('hv', d.ips6.pc2.ip)])
        self.add_grade_element(
            title=no_tr("ripng_pings"), max_grade=2, grade_part=part9, bonus=True,
            grade=int(pings6_pc1_hv) + int(pings6_pc2_hv),
            description=tr("pc1 et pc2 joignent hv en IPv6"),
        )


_TRANSLATIONS = {}
