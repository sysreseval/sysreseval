"""BGP at scale with FRR: well-known communities, multipath, confederations, dampening; bonus graceful shutdown.

IPv4 only.  Four independent sites, one per part, and a bonus site (completing a part gives all its
points whatever the others):

- ``ne``: ``ne_r1`` announces two /24 of its block tagged ``no-export`` to its provider ``ne_isp``
  (traffic engineering: ``ne_far``, beyond the provider, sees only the /22) and tags one prefix of
  its customer the same way; the customer's ``no-export`` / ``no-advertise`` prefixes are observed;
- ``mp``: ``mp_r1`` has two parallel sessions with ``mp_isp1`` (ECMP by default in FRR) and one with
  ``mp_isp2``; the students add ``as-path multipath-relax`` and the L4 hash of the kernel; each
  evaluation sends 60 UDP flows from ``mp_h1`` and counts them per outgoing interface;
- ``cf``: a confederation of two member ASes; ``cf_r3`` / ``cf_r4`` are given (``cf_r4`` sets a
  local-preference and tags a prefix ``no-export`` and one ``local-AS``), the students build the BGP
  of ``cf_r1`` / ``cf_r2``; OSPF is given inside;
- ``dmp``: ``dmp_cust`` flaps a prefix every few seconds; ``dmp_r1`` dampens it;
- ``gs`` (bonus): ``gs_r1`` drains its primary link with GRACEFUL_SHUTDOWN without closing it.

Grading reads the json of vtysh (lib/frr.py), the running configuration, the kernel routes,
interface counters and pings.  The states ``solve_<part>`` apply the reference solution of one part,
``final`` all of them.
"""
import random
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Dict, List

from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks
from net_config import set_net_config_entry, set_ip_forward
from frr import (
    bgp_best_path, bgp_paths, get_bgp_dampened_paths, get_bgp_prefix, get_bgp_routes, get_bgp_summary,
    get_frr_running_config, get_kernel_routes, parse_frr_config,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("BGP : communautés, multichemin, confédérations et amortissement",
           en="BGP: communities, multipath, confederations and dampening")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------

# interfaces of every machine in ethN order: the network of each
MACHINE_IFACES = {
    'ne_r1': ['ne_l1', 'ne_l2'],
    'ne_isp': ['ne_l1', 'ne_l3'],
    'ne_far': ['ne_l3'],
    'ne_cust': ['ne_l2'],
    'mp_r1': ['mp_l1a', 'mp_l1b', 'mp_l2', 'mp_lan'],
    'mp_isp1': ['mp_l1a', 'mp_l1b'],
    'mp_isp2': ['mp_l2'],
    'mp_h1': ['mp_lan'],
    'cf_r1': ['cf_le1', 'cf_l12'],
    'cf_r2': ['cf_l12', 'cf_l23'],
    'cf_r3': ['cf_l23', 'cf_l34'],
    'cf_r4': ['cf_l34', 'cf_le2'],
    'cf_ext1': ['cf_le1'],
    'cf_ext2': ['cf_le2'],
    'dmp_r1': ['dmp_l1', 'dmp_l2'],
    'dmp_isp': ['dmp_l1'],
    'dmp_cust': ['dmp_l2'],
    'gs_r1': ['gs_l1', 'gs_l2'],
    'gs_isp1': ['gs_l1', 'gs_l12'],
    'gs_isp2': ['gs_l2', 'gs_l12'],
}
MACHINES = list(MACHINE_IFACES)
HOSTS = ('mp_h1',)
FRR_ROUTERS = [m for m in MACHINES if m not in HOSTS]
STUDENT_ROUTERS = ('ne_r1', 'mp_r1', 'cf_r1', 'cf_r2', 'dmp_r1', 'gs_r1')
# the members of the confederation the lab configures: terminals to look, not graded
CONFED_GIVEN = ('cf_r3', 'cf_r4')
CONFED_ROUTERS = ('cf_r1', 'cf_r2') + CONFED_GIVEN
TERMINALS = STUDENT_ROUTERS + CONFED_GIVEN + HOSTS

# point-to-point links (/30): the first machine gets .1, the second .2
LINKS = {
    'ne_l1': ('ne_r1', 'ne_isp'), 'ne_l2': ('ne_r1', 'ne_cust'), 'ne_l3': ('ne_isp', 'ne_far'),
    'mp_l1a': ('mp_r1', 'mp_isp1'), 'mp_l1b': ('mp_r1', 'mp_isp1'), 'mp_l2': ('mp_r1', 'mp_isp2'),
    'cf_le1': ('cf_r1', 'cf_ext1'), 'cf_l12': ('cf_r1', 'cf_r2'), 'cf_l23': ('cf_r2', 'cf_r3'),
    'cf_l34': ('cf_r3', 'cf_r4'), 'cf_le2': ('cf_r4', 'cf_ext2'),
    'dmp_l1': ('dmp_r1', 'dmp_isp'), 'dmp_l2': ('dmp_r1', 'dmp_cust'),
    'gs_l1': ('gs_r1', 'gs_isp1'), 'gs_l2': ('gs_r1', 'gs_isp2'), 'gs_l12': ('gs_isp1', 'gs_isp2'),
}
CONFED_LINKS = ('cf_l12', 'cf_l23', 'cf_l34')     # inside the confederation: OSPF

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _m, _nets in MACHINE_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_m] = _i

SITE_COLORS = {'ne': 'lightblue', 'mp': 'palegreen', 'cf': 'khaki', 'dmp': 'lightsalmon', 'gs': 'lightgrey'}
SITE_NUMBER = {'ne': 1, 'mp': 2, 'cf': 3, 'dmp': 4, 'gs': 5}
LOOPBACK_OCTET = 15

# AS numbers of the routers the lab configures (the students' AS, Data.our_as, is random; the
# member ASes of the confederation are Data.cf_sub1 / cf_sub2)
EXT_AS = {'ne_isp': 65110, 'ne_far': 65111, 'ne_cust': 65112,
          'mp_isp1': 65120, 'mp_isp2': 65121,
          'cf_ext1': 65131, 'cf_ext2': 65132,
          'dmp_isp': 65140, 'dmp_cust': 65141,
          'gs_isp1': 65150, 'gs_isp2': 65151}

# public prefixes (a random /16 of 172.16.0.0/12 per instance): (third octet, prefix length)
PUB = {
    'ne_own': (16, 22), 'ne_te1': (16, 24), 'ne_te2': (17, 24),      # the students' block, two of its /24
    'ne_c1': (20, 24), 'ne_c2': (21, 24), 'ne_c3': (22, 24),         # ne_cust: plain, no-export, no-advertise
    'ne_far': (24, 24), 'ne_isp': (25, 24),
    'mp_q': (32, 24), 'mp_p': (33, 24),                              # mp_isp1 only; both providers
    'mp_own': (36, 22), 'mp_lan': (36, 24),
    'cf_e1': (52, 24), 'cf_e2': (53, 24),                            # behind cf_ext1 / cf_ext2
    'cf_s2': (56, 24), 'cf_n': (57, 24), 'cf_l': (58, 24),           # cf_r4: plain, no-export, local-AS
    'dmp_own': (64, 22), 'dmp_s': (68, 24), 'dmp_f': (69, 24),       # dmp_cust: stable, flapping
    'gs_own': (80, 22), 'gs_inet': (84, 24),
}
NO_EXPORT_VALUE = "65535:65281"
LOCAL_PREF_EXT2 = 150            # given on cf_r4 for the routes of cf_ext2
FLAP_HALF_PERIOD = 8             # s: dmp_cust withdraws its flapping prefix for this long, then announces it
FLAP_SCRIPT = "/usr/local/sbin/flap.sh"
FLOWS_SCRIPT = "/usr/local/bin/flows.py"
FLOW_COUNT = 60
FLOW_FIRST_PORT = 40000
FLOW_MIN_PER_LINK = 5            # flows each next hop must carry with an L4 hash (about 20 expected)
# dampening parameters asked in part 4: (half-life min, reuse, suppress, max-suppress min), never
# FRR's defaults (a bare `bgp dampening` in the configuration)
DAMPENING_CHOICES = ((10, 800, 2500, 40), (5, 600, 1800, 30), (12, 900, 2800, 45), (8, 700, 2200, 35))
DAMPENING_WAIT = 90              # s: the reference states wait for the flapping prefix to be suppressed
CONNECT_RETRY = 10               # s: `timers connect` of the routers of the lab (FRR's default: 120)
CONVERGE_WAIT = 15
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : bgpd{ospf} activé
bgpd=yes
ospfd={ospfd}
ospf6d=no
ripd=no
ripngd=no
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
staticd_options="-A 127.0.0.1"
"""
FRR_VTYSH_CONF = "service integrated-vtysh-config\n"

FLOWS_PY = """#!/usr/bin/env python3
# flows.py DEST N FIRST_PORT: one UDP datagram from each of N source ports (N flows of one host)
import socket, sys
dest, n, first = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', first + i))
    s.sendto(b'flow', (dest, 9))
    s.close()
"""


def site_of(machine: str) -> str:
    return machine.split('_', 1)[0]


def iface(machine: str, net: str) -> str:
    """Name of the interface of *machine* on *net* (``eth1``)."""
    return f"eth{MACHINE_IFACES[machine].index(net)}"


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    our_as: int = 0            # the students' AS (the identifier of the confederation too)
    cf_sub1: int = 0           # part 3: member AS of cf_r1 and cf_r2
    cf_sub2: int = 0           # part 3: member AS of cf_r3 and cf_r4
    damp_half_life: int = 0    # part 4: bgp dampening (minutes)
    damp_reuse: int = 0
    damp_suppress: int = 0
    damp_max: int = 0          # minutes

    @classmethod
    def generate(cls):
        data = cls()
        data.our_as = random.randint(64600, 64999)
        data.cf_sub1, data.cf_sub2 = random.sample(range(65201, 65300), 2)
        data.damp_half_life, data.damp_reuse, data.damp_suppress, data.damp_max = random.choice(DAMPENING_CHOICES)

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        data.nets.pub = random_ipv4networks(16, from_network=IPv4Network('172.16.0.0/12'))[0]
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            links = [n for n in LINKS if site_of(n) == site]
            for k, net in enumerate(links):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET))
        for name, (third, plen) in PUB.items():
            setattr(data.nets, name, _subnet(data.nets.pub, third, plen))
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        lan = int(data.nets.mp_lan.network_address)
        data.ips.mp_r1_mp_lan = IPv4Interface((lan + 1, 24))
        data.ips.mp_h1 = IPv4Interface((lan + random.randint(10, 250), 24))
        for site in SITE_NUMBER:
            block = getattr(data.nets, f"{site}_lo")
            routers = [m for m in FRR_ROUTERS if site_of(m) == site]
            for k, router in enumerate(routers):
                setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + k + 1, 32)))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in FRR_ROUTERS:
        spec['image'] = sre_docker_image("routing-frr13")
        spec['shape'] = 'box'
    if machine not in TERMINALS:
        spec['allow_connection'] = False
    return spec


class NetScheme(NetScheme0):
    _machine_specs = {m: _machine_spec(m) for m in MACHINES}
    _network_specs = {}
    _topology = _TOPOLOGY

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")

        self.net_config = {}
        for m, nets in MACHINE_IFACES.items():
            if m == 'mp_h1':
                self.net_config[m] = [([d.ips.mp_h1], [(default, self.addr('mp_r1', 'mp_lan'))])]
            else:
                self.net_config[m] = [([getattr(d.ips, f"{m}_{n}")], []) for n in nets]

        # /etc/hosts: every interface gets rX-ethN, the first one also rX; loopbacks rX-lo
        lines = []
        for m, nets in MACHINE_IFACES.items():
            if m in HOSTS:
                lines.append(f"{d.ips.mp_h1.ip}\tmp_h1")
                continue
            for i, n in enumerate(nets):
                names = f"{m}-eth{i}" if i else f"{m}\t{m}-eth{i}"
                lines.append(f"{self.addr(m, n)}\t{names}")
            lines.append(f"{self.lo(m)}\t{m}-lo")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses and names -------------------------------------------------------

    def addr(self, machine: str, net: str) -> IPv4Address:
        """Address (without prefix) of *machine* on *net*."""
        return getattr(self.data.ips, f"{machine}_{net}").ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def host(self, name: str, n: int = 1) -> IPv4Address:
        """Address number *n* of the network *name*."""
        return self.net(name).network_address + n

    def as_of(self, router: str) -> int:
        d = self.data
        if router in ('cf_r1', 'cf_r2'):
            return d.cf_sub1
        if router in CONFED_GIVEN:
            return d.cf_sub2
        return d.our_as if router in STUDENT_ROUTERS else EXT_AS[router]

    def damping(self) -> tuple:
        d = self.data
        return d.damp_half_life, d.damp_reuse, d.damp_suppress, d.damp_max

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Les communautés"), tag="communities")
            + tr("""
Une **communauté** (RFC 1997) est une étiquette de 32 bits attachée à une route, notée `AS:valeur`
(deux nombres de 16 bits ; l'AS est celui qui en définit le sens). Une route peut en porter
plusieurs. Les communautés ne changent rien par elles-mêmes : ce sont les **politiques** des
routeurs (`match community`) qui leur donnent un sens. Usages courants :

- **marquer l'origine** d'une route (client, pair, fournisseur, site) pour la filtrer plus loin ;
- **demander quelque chose à son fournisseur**, qui publie la liste des communautés qu'il
  comprend : allonger l'AS_PATH vers tel pair, baisser la `local-preference`, ne pas annoncer dans
  telle région…

### @@sec:well-known@@ Les communautés bien connues

Quelques valeurs de l'AS 65535 ont un sens fixé par une RFC, appliqué **par tous les routeurs sans
configuration** :

| nom (FRR) | valeur | effet |
|-----------|--------|-------|
| `no-export` | 65535:65281 (0xFFFFFF01) | ne pas annoncer la route hors de l'AS (ni hors de la confédération, section @@ref:confed@@) |
| `no-advertise` | 65535:65282 | ne l'annoncer à **aucun** pair, même interne |
| `local-AS` (NO_EXPORT_SUBCONFED) | 65535:65283 | ne pas l'annoncer hors de l'AS membre d'une confédération |
| `blackhole` | 65535:666 | demande de blackholing de la destination (RFC 7999) |
| `graceful-shutdown` | 65535:0 | lien bientôt en maintenance (RFC 8326, section @@ref:gshut@@) |

**Où s'applique la vérification.** Un routeur décide d'annoncer une route à un pair d'après les
communautés qu'elle porte **dans sa table**, **avant** la route-map de sortie. Une communauté
ajoutée par la route-map de sortie est donc **transmise au pair** et c'est **lui** qui l'appliquera.
C'est l'usage classique de `no-export` en ingénierie de trafic : un AS annonce son bloc à tous et,
à un seul fournisseur, des préfixes plus spécifiques marqués `no-export` ; le fournisseur les utilise
(la plus longue correspondance attire chez lui le trafic de ses clients vers ces préfixes) mais ne les
propage pas : le reste de l'Internet ne voit que le bloc.

### @@sec:communities-frr@@ Avec FRR

```
ip prefix-list TE seq 5 permit 198.51.100.0/24
route-map TO-ISP permit 10
 match ip address prefix-list TE
 set community no-export additive        ! additive : ajoutée aux communautés déjà présentes
exit
route-map TO-ISP permit 20
exit
bgp community-list standard NOEXP seq 5 permit no-export
route-map X permit 10
 match community NOEXP
```

- Sans `additive`, `set community` **remplace** toutes les communautés de la route.
- FRR envoie les communautés à ses pairs par défaut (`neighbor X send-community`, visible avec
  `show running-config all`).
- `show bgp ipv4 unicast P` affiche la ligne `Community:` d'un chemin ; `show bgp ipv4 unicast
  community no-export` liste les routes qui portent une communauté. La vue d'ensemble `show bgp ipv4
  unicast` ne les montre pas.
- Il existe aussi les communautés **étendues** (RFC 4360, 64 bits : cibles de route des VPN, bande
  passante) et les **grandes** communautés (RFC 8092, `AS:valeur1:valeur2` sur 3 × 32 bits, pour les
  numéros d'AS de 32 bits).
""")
            + info_subtitle(tr("Plusieurs chemins : l'ECMP"), tag="multipath")
            + tr("""
BGP choisit **un** meilleur chemin par préfixe (le processus de décision). Avec le **multichemin**,
il installe aussi dans la table de routage les autres chemins **équivalents** : le noyau répartit
alors le trafic entre plusieurs prochains sauts (**ECMP**, *Equal-Cost Multi-Path*).

Deux chemins sont équivalents quand ils sont à égalité jusqu'à la métrique IGP vers le prochain saut :
même `weight`, même `LOCAL_PREF`, même **longueur** d'AS_PATH, même `ORIGIN`, même `MED`, même type
(eBGP ou iBGP) — et, par défaut, **le même AS voisin** (le premier AS de l'AS_PATH).

- FRR active le multichemin **par défaut** (jusqu'à 64 chemins, `maximum-paths` n'apparaît dans la
  configuration que s'il est changé) : deux sessions parallèles avec le même fournisseur donnent deux
  prochains sauts sans rien configurer.
- `bgp bestpath as-path multipath-relax` (mode `router bgp`) lève la condition du même AS voisin : seule
  la longueur de l'AS_PATH compte. C'est ce qui permet de répartir entre **deux fournisseurs** (un
  service présent chez les deux, un réseau de diffusion de contenu…).
- `maximum-paths N` (address-family) limite le nombre de chemins eBGP installés, `maximum-paths ibgp N`
  celui des chemins iBGP.
- `show bgp ipv4 unicast` marque les chemins installés avec le meilleur par `=` (`multipath` dans le
  détail d'un préfixe) ; `ip route` montre une route à plusieurs `nexthop`.

### @@sec:hash@@ La répartition dans le noyau

Le noyau ne répartit pas paquet par paquet (les segments d'une connexion arriveraient dans le
désordre) mais **flux par flux** : il calcule un hachage d'en-têtes du paquet et en déduit le prochain
saut. `net.ipv4.fib_multipath_hash_policy` choisit les champs :

| valeur | champs | effet |
|--------|--------|-------|
| 0 (défaut) | adresses source et destination | tout le trafic entre deux machines suit le même chemin |
| 1 | adresses, protocole et **ports** | les connexions d'une même machine se répartissent |

```
sysctl -w net.ipv4.fib_multipath_hash_policy=1                       # immédiat
echo net.ipv4.fib_multipath_hash_policy=1 > /etc/sysctl.d/90-ecmp.conf  # au démarrage
```
""")
            + info_subtitle(tr("Les confédérations"), tag="confed")
            + tr("""
Les routeurs iBGP d'un AS doivent être maillés (n(n−1)/2 sessions) : une route apprise d'un pair iBGP
n'est pas réannoncée à un autre. Deux solutions existent : le **réflecteur de routes** et la
**confédération** (RFC 5065), qui découpe l'AS en plusieurs **AS membres** (des numéros privés).

- Chaque AS membre est maillé en interne ; entre AS membres, les sessions sont des sessions
  **eBGP de confédération**.
- Vu de l'extérieur, la confédération est **un seul AS**, son **identifiant** : les voisins externes
  déclarent `remote-as IDENTIFIANT`.
- À l'intérieur, l'AS_PATH garde la trace des AS membres traversés dans un segment à part,
  `AS_CONFED_SEQUENCE`, affiché **entre parenthèses** (`(65102) 64500`) ; il ne compte pas dans la
  longueur de l'AS_PATH et sert à détecter les boucles entre membres. Il est **retiré** à la sortie :
  l'extérieur ne voit que l'identifiant.
- Sur une session eBGP de confédération, les attributs se comportent **comme en iBGP** : le
  `NEXT_HOP`, la `LOCAL_PREF` et le `MED` sont **conservés**. L'IGP doit donc couvrir toute la
  confédération (ou `next-hop-self` aux bords).
- `no-export` garde une route dans la confédération entière ; `local-AS` (NO_EXPORT_SUBCONFED) la
  garde dans son AS membre.

```
router bgp 65101                                ! le numéro de l'AS membre
 bgp confederation identifier 64512             ! l'AS vu de l'extérieur
 bgp confederation peers 65102                  ! les autres AS membres (voisins de confédération)
 neighbor 10.0.0.2 remote-as 65101              ! iBGP dans l'AS membre
 neighbor 10.0.0.2 update-source lo
 neighbor 10.1.0.2 remote-as 65102              ! eBGP de confédération
 neighbor 192.0.2.1 remote-as 64500             ! eBGP externe
```

`show bgp neighbors` indique le type de chaque session (`confed-external` dans le détail d'un chemin) ;
`show bgp ipv4 unicast P` montre l'AS_PATH avec ses parenthèses.
""")
            + info_subtitle(tr("Amortir les oscillations"), tag="dampening")
            + tr("""
Une route qui oscille (*flap* : annoncée, retirée, annoncée…) fait recalculer et réannoncer chaque
routeur de l'Internet à chaque changement. L'**amortissement** (*route flap dampening*, RFC 2439)
pénalise ces routes :

- chaque **retrait** ajoute **1000** à la pénalité de la route (une modification de ses attributs,
  500) ; la pénalité **décroît exponentiellement** : elle est divisée par deux à chaque **demi-vie**
  (*half-life*) ;
- quand elle dépasse le seuil de **suppression**, la route est **supprimée** : gardée dans la table
  (`d` : *damped*) mais ni choisie ni annoncée, même si elle est à nouveau présente ;
- elle est réutilisée quand la pénalité redescend sous le seuil de **réutilisation**, et au plus tard
  au bout de la **durée maximale de suppression**.

| paramètre (FRR) | défaut |
|-----------------|--------|
| demi-vie | 15 min |
| seuil de réutilisation | 750 |
| seuil de suppression | 2000 |
| durée maximale de suppression | 60 min |

```
router bgp 64512
 address-family ipv4 unicast
  bgp dampening 10 800 2500 40         ! demi-vie, réutilisation, suppression, durée maximale
```

- FRR n'amortit que les routes reçues en **eBGP** ; une configuration aux valeurs par défaut s'affiche
  `bgp dampening` sans paramètres.
- `show bgp ipv4 unicast dampening parameters`, `… dampening dampened-paths` (les routes supprimées et
  l'heure de leur réutilisation), `… dampening flap-statistics` (le nombre d'oscillations) ; le détail
  d'un préfixe donne sa pénalité.
- L'amortissement est **déconseillé aujourd'hui** sous sa forme d'origine : un seul événement
  (une panne de lien) produit plusieurs mises à jour successives pendant que BGP explore les chemins
  de rechange, et une route stable mais malchanceuse se retrouve supprimée longtemps. La RFC 7196
  recommande, si on l'utilise, un seuil de suppression bien plus haut (6000).
""")
            + info_subtitle(tr("Une maintenance sans coupure : graceful shutdown"), tag="gshut")
            + tr("""
Couper une session BGP pour une maintenance (`neighbor X shutdown`) retire brutalement ses routes :
le temps que les autres routeurs choisissent un autre chemin, du trafic est perdu. La communauté
**GRACEFUL_SHUTDOWN** (65535:0, RFC 8326) permet de **vider** le lien d'abord, sans le couper : les
routes qui passent par lui reçoivent une `LOCAL_PREF` de **0**, les chemins de secours deviennent les
meilleurs, et la session peut ensuite être coupée sans perte.

- Le routeur qui part en maintenance marque les routes qu'il **annonce** sur ce lien avec la
  communauté ; le voisin, qui l'applique (FRR le fait de lui-même), leur donne une `LOCAL_PREF` de 0 :
  le trafic **entrant** se déplace.
- Il baisse lui-même la préférence des routes qu'il **reçoit** sur ce lien : le trafic **sortant** se
  déplace.

Avec FRR, `bgp graceful-shutdown` (mode `router bgp`) le fait pour **toutes** les sessions eBGP du
routeur (dans les deux sens). `neighbor X graceful-shutdown` ne vise qu'une session, mais n'agit que
sur les routes **reçues** de X (communauté et `LOCAL_PREF` 0) : pour le trafic entrant, on ajoute la
communauté aux routes annoncées à X par une route-map de sortie (`set community graceful-shutdown
additive`).
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
Les routeurs font tourner **FRRouting** ; on les configure avec `vtysh` (`configure terminal`,
`write` pour enregistrer dans `/etc/frr/frr.conf`, `no` devant une ligne pour la supprimer). Rappels
utiles :

- une session **eBGP** ne s'ouvre aux routes qu'avec une politique en entrée et en sortie (RFC 8212 :
  mention `(Policy)` dans `show bgp summary`) ou `no bgp ebgp-requires-policy` ;
- `network P` n'annonce `P` que si une route identique existe dans la table de routage ;
- entre loopbacks : `neighbor X update-source lo` ; `neighbor X next-hop-self` en iBGP.

```
show bgp ipv4 unicast summary              # sessions, état, préfixes reçus
show bgp ipv4 unicast                      # table BGP : meilleur chemin (>), multichemin (=), supprimé (d)
show bgp ipv4 unicast P                    # détail : AS_PATH, communautés, local-pref, multipath
show bgp neighbors A.B.C.D                 # détail d'une session
show bgp ipv4 unicast neighbors A.B.C.D advertised-routes
show bgp ipv4 unicast community no-export
show bgp ipv4 unicast dampening dampened-paths | flap-statistics | parameters
clear bgp A.B.C.D [soft in|soft out]
show ip ospf neighbor                      # l'IGP de la confédération
```

Documentation : [FRR — BGP](https://docs.frrouting.org/en/latest/bgp.html) (sections *Communities*,
*Multipath*, *Confederation*, *Route Flap Dampening*, *Graceful Shutdown*).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `ip route` : les routes BGP portent `proto bgp`, une route ECMP a plusieurs `nexthop` ;
- `ip -s link show ethX` : les compteurs de paquets d'une interface (la répartition des flux) ;
- `tcpdump -nvi ethX tcp port 179` : les messages BGP ; `/var/log/frr/frr.log` : le journal.

| symptôme | causes à vérifier |
|----------|-------------------|
| un préfixe marqué `no-export` est quand même propagé | communauté perdue (`set community` sans `additive` ailleurs), route-map pas appliquée (`clear bgp X soft out`) |
| un seul prochain saut malgré deux fournisseurs | AS voisins différents sans `multipath-relax`, AS_PATH de longueurs différentes |
| tout le trafic d'une machine sur le même lien | hachage sur les seules adresses (`fib_multipath_hash_policy`) |
| session de confédération en `Active` / `Idle` | AS membre ou identifiant différent, `confederation peers` oublié, pas de route vers la loopback du pair |
| AS membres visibles hors de la confédération | le routeur de bord n'est pas configuré en confédération |
| route marquée `d` | amortissement : attendre la réutilisation ou `clear bgp ipv4 unicast dampening` |
""")
        )

    # -- configurations --------------------------------------------------------------

    def _bgp_block(self, router: str, neighbors: List[dict], networks=(), router_lines=(), af_lines=()) -> List[str]:
        """frr.conf lines of ``router bgp``: each neighbour is ``{'ip', 'as', 'desc', 'router': [...],
        'in': map, 'out': map, 'af': [...]}`` (the lists hold the words after ``neighbor IP``);
        *networks* are prefixes or ``(prefix, route-map)``."""
        lines = [f"router bgp {self.as_of(router)}", f" bgp router-id {self.lo(router)}"]
        lines += [f" {x}" for x in router_lines]
        for n in neighbors:
            lines.append(f" neighbor {n['ip']} remote-as {n['as']}")
            if n.get('desc'):
                lines.append(f" neighbor {n['ip']} description {n['desc']}")
            lines += [f" neighbor {n['ip']} {x}" for x in n.get('router', [])]
        lines.append(" address-family ipv4 unicast")
        for p in networks:
            lines.append(f"  network {p[0]} route-map {p[1]}" if isinstance(p, tuple) else f"  network {p}")
        lines += [f"  {x}" for x in af_lines]
        for n in neighbors:
            if n.get('in'):
                lines.append(f"  neighbor {n['ip']} route-map {n['in']} in")
            if n.get('out'):
                lines.append(f"  neighbor {n['ip']} route-map {n['out']} out")
            lines += [f"  neighbor {n['ip']} {x}" for x in n.get('af', [])]
        lines += [" exit-address-family", "exit", "!"]
        return lines

    def _peer(self, me: str, peer: str, link: str, desc: str = None, **kw) -> dict:
        """A neighbour entry of *me* for *peer* across *link* (its address on the link)."""
        n = {'ip': self.addr(peer, link), 'as': self.as_of(peer), 'desc': desc, 'in': 'ALL', 'out': 'ALL'}
        n.update(kw)
        return n

    def _ospf_lines(self, r: str) -> List[str]:
        """OSPF of the confederation (given): the internal links in point-to-point, the loopback."""
        lines = []
        for i, n in enumerate(MACHINE_IFACES[r]):
            if n in CONFED_LINKS:
                lines += [f"interface eth{i}", " ip ospf area 0", " ip ospf network point-to-point", "exit", "!"]
        lines += ["interface lo", " ip ospf area 0", " ip ospf passive", "exit", "!",
                  "router ospf", f" ospf router-id {self.lo(r)}", "exit", "!"]
        return lines

    def _given_lines(self, r: str) -> List[str]:
        """frr.conf lines of *r* at start (blackhole routes, filters, OSPF, BGP)."""
        d, net = self.data, self.net
        all_map = ["route-map ALL permit 10", "exit", "!"]
        retry = [f"timers connect {CONNECT_RETRY}"]
        lines: List[str] = []
        if r == 'ne_r1':
            lines += [f"ip route {net(p)} blackhole" for p in ('ne_own', 'ne_te1', 'ne_te2')] + ["!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'ne_isp', 'ne_l1', 'ISP'),
                                         self._peer(r, 'ne_cust', 'ne_l2', 'CUSTOMER')], networks=(net('ne_own'),))
        elif r == 'ne_isp':
            lines += [f"ip route {net('ne_isp')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'ne_r1', 'ne_l1', 'CUSTOMER', router=retry),
                                         self._peer(r, 'ne_far', 'ne_l3', 'PEER', router=retry)],
                                     networks=(net('ne_isp'),))
        elif r == 'ne_far':
            lines += [f"ip route {net('ne_far')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'ne_isp', 'ne_l3', 'PEER', router=retry)],
                                     networks=(net('ne_far'),))
        elif r == 'ne_cust':
            lines += [f"ip route {net(p)} blackhole" for p in ('ne_c1', 'ne_c2', 'ne_c3')] + ["!"]
            lines += ["route-map NO-EXPORT permit 10", " set community no-export", "exit", "!",
                      "route-map NO-ADVERTISE permit 10", " set community no-advertise", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'ne_r1', 'ne_l2', 'PROVIDER', router=retry)],
                                     networks=(net('ne_c1'), (net('ne_c2'), 'NO-EXPORT'),
                                               (net('ne_c3'), 'NO-ADVERTISE')))
        elif r == 'mp_r1':
            lines += [f"ip route {net('mp_own')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'mp_isp1', 'mp_l1a', 'ISP1-A'),
                                         self._peer(r, 'mp_isp1', 'mp_l1b', 'ISP1-B'),
                                         self._peer(r, 'mp_isp2', 'mp_l2', 'ISP2')], networks=(net('mp_own'),))
        elif r == 'mp_isp1':
            lines += [f"ip route {net(p)} blackhole" for p in ('mp_q', 'mp_p')] + ["!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'mp_r1', 'mp_l1a', 'CUSTOMER-A', router=retry),
                                         self._peer(r, 'mp_r1', 'mp_l1b', 'CUSTOMER-B', router=retry)],
                                     networks=(net('mp_q'), net('mp_p')))
        elif r == 'mp_isp2':
            lines += [f"ip route {net('mp_p')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'mp_r1', 'mp_l2', 'CUSTOMER', router=retry)],
                                     networks=(net('mp_p'),))
        elif r in ('cf_r1', 'cf_r2'):
            lines += self._ospf_lines(r)
        elif r == 'cf_r3':
            lines += self._ospf_lines(r) + all_map
            lines += self._bgp_block(r, [
                {'ip': self.addr('cf_r2', 'cf_l23'), 'as': d.cf_sub1, 'desc': 'CONFED-R2', 'router': retry,
                 'in': 'ALL', 'out': 'ALL'},
                {'ip': self.lo('cf_r4'), 'as': d.cf_sub2, 'desc': 'R4', 'router': ['update-source lo']}],
                router_lines=(f"bgp confederation identifier {d.our_as}", f"bgp confederation peers {d.cf_sub1}"))
        elif r == 'cf_r4':
            lines += [f"ip route {net(p)} blackhole" for p in ('cf_s2', 'cf_n', 'cf_l')] + ["!"]
            lines += self._ospf_lines(r)
            lines += ["route-map NO-EXPORT permit 10", " set community no-export", "exit", "!",
                      "route-map LOCAL-AS permit 10", " set community local-AS", "exit", "!",
                      "route-map FROM-EXT2 permit 10", f" set local-preference {LOCAL_PREF_EXT2}", "exit", "!"]
            lines += all_map
            lines += self._bgp_block(r, [
                {'ip': self.lo('cf_r3'), 'as': d.cf_sub2, 'desc': 'R3', 'router': ['update-source lo'],
                 'af': ['next-hop-self']},
                self._peer(r, 'cf_ext2', 'cf_le2', 'EXT2', **{'in': 'FROM-EXT2'})],
                networks=(net('cf_s2'), (net('cf_n'), 'NO-EXPORT'), (net('cf_l'), 'LOCAL-AS')),
                router_lines=(f"bgp confederation identifier {d.our_as}", f"bgp confederation peers {d.cf_sub1}"))
        elif r == 'cf_ext1':
            lines += [f"ip route {net('cf_e1')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [{'ip': self.addr('cf_r1', 'cf_le1'), 'as': d.our_as, 'desc': 'PROVIDER',
                                          'router': retry, 'in': 'ALL', 'out': 'ALL'}], networks=(net('cf_e1'),))
        elif r == 'cf_ext2':
            lines += [f"ip route {net('cf_e2')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [{'ip': self.addr('cf_r4', 'cf_le2'), 'as': d.our_as, 'desc': 'PROVIDER',
                                          'router': retry, 'in': 'ALL', 'out': 'ALL'}], networks=(net('cf_e2'),))
        elif r == 'dmp_r1':
            lines += [f"ip route {net('dmp_own')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'dmp_isp', 'dmp_l1', 'ISP'),
                                         self._peer(r, 'dmp_cust', 'dmp_l2', 'CUSTOMER')], networks=(net('dmp_own'),))
        elif r == 'dmp_isp':
            lines += all_map
            lines += self._bgp_block(r, [self._peer(r, 'dmp_r1', 'dmp_l1', 'CUSTOMER', router=retry)])
        elif r == 'dmp_cust':
            lines += [f"ip route {net(p)} blackhole" for p in ('dmp_s', 'dmp_f')] + ["!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'dmp_r1', 'dmp_l2', 'PROVIDER', router=retry)],
                                     networks=(net('dmp_s'), net('dmp_f')))
        elif r == 'gs_r1':
            lines += [f"ip route {net('gs_own')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'gs_isp1', 'gs_l1', 'ISP1'),
                                         self._peer(r, 'gs_isp2', 'gs_l2', 'ISP2')], networks=(net('gs_own'),))
        elif r == 'gs_isp1':
            lines += [f"ip route {net('gs_inet')} blackhole", "!",
                      "bgp community-list standard GSHUT seq 5 permit graceful-shutdown", "!",
                      "route-map FROM-CUSTOMER permit 10", " match community GSHUT", " set local-preference 0",
                      "exit", "!", "route-map FROM-CUSTOMER permit 20", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'gs_r1', 'gs_l1', 'CUSTOMER', router=retry,
                                                    **{'in': 'FROM-CUSTOMER'}),
                                         self._peer(r, 'gs_isp2', 'gs_l12', 'PEER', router=retry)],
                                     networks=(net('gs_inet'),))
        elif r == 'gs_isp2':
            lines += all_map
            lines += self._bgp_block(r, [self._peer(r, 'gs_r1', 'gs_l2', 'CUSTOMER', router=retry),
                                         self._peer(r, 'gs_isp1', 'gs_l12', 'PEER', router=retry)])
        return lines

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf of *router*."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {router}", "log file /var/log/frr/frr.log", "!"]
        return "\n".join(lines + self._given_lines(router)) + "\n"

    def _daemons(self, router: str) -> str:
        ospf = router in CONFED_ROUTERS
        return FRR_DAEMONS.format(ospf=" et ospfd" if ospf else "", ospfd="yes" if ospf else "no")

    def flap_script(self) -> str:
        """The loop of dmp_cust: withdraw its flapping prefix, wait, announce it, wait."""
        d = self.data
        cmd = (f"vtysh -c 'configure terminal' -c 'router bgp {EXT_AS['dmp_cust']}' "
               f"-c 'address-family ipv4 unicast' -c '{{}}network {self.net('dmp_f')}'")
        return ("#!/bin/sh\n# the unstable prefix of the customer (lab, part 4)\nwhile :; do\n"
                f"  {cmd.format('no ')}\n  sleep {FLAP_HALF_PERIOD}\n  {cmd.format('')}\n  sleep {FLAP_HALF_PERIOD}\n"
                "done\n")

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part (texts shown by the instructor solutions) ------

    def solution_ne(self) -> Dict[str, List[str]]:
        d, net = self.data, self.net
        isp = self.addr('ne_isp', 'ne_l1')
        return {'ne_r1': [
            f"ip prefix-list TE seq 5 permit {net('ne_te1')}", f"ip prefix-list TE seq 10 permit {net('ne_te2')}",
            f"ip prefix-list C1 seq 5 permit {net('ne_c1')}",
            "route-map TO-ISP permit 10", "match ip address prefix-list TE", "set community no-export additive", "exit",
            "route-map TO-ISP permit 20", "match ip address prefix-list C1", "set community no-export additive", "exit",
            "route-map TO-ISP permit 30", "exit",
            f"router bgp {d.our_as}", "address-family ipv4 unicast", f"network {net('ne_te1')}",
            f"network {net('ne_te2')}", f"neighbor {isp} route-map TO-ISP out", "exit-address-family", "exit"]}

    def solution_mp(self) -> Dict[str, List[str]]:
        return {'mp_r1': [f"router bgp {self.data.our_as}", "bgp bestpath as-path multipath-relax", "exit"]}

    MP_SYSCTL = "net.ipv4.fib_multipath_hash_policy"

    def solution_cf(self) -> Dict[str, List[str]]:
        d = self.data
        common = [f"bgp confederation identifier {d.our_as}", f"bgp confederation peers {d.cf_sub2}"]
        r1_lo, r2_lo = self.lo('cf_r1'), self.lo('cf_r2')
        ext1, r3 = self.addr('cf_ext1', 'cf_le1'), self.addr('cf_r3', 'cf_l23')
        return {
            'cf_r1': ["route-map ALL permit 10", "exit",
                      f"router bgp {d.cf_sub1}", f"bgp router-id {r1_lo}"] + common + [
                      f"neighbor {r2_lo} remote-as {d.cf_sub1}", f"neighbor {r2_lo} update-source lo",
                      f"neighbor {ext1} remote-as {EXT_AS['cf_ext1']}",
                      "address-family ipv4 unicast", f"neighbor {r2_lo} next-hop-self",
                      f"neighbor {ext1} route-map ALL in", f"neighbor {ext1} route-map ALL out",
                      "exit-address-family", "exit"],
            'cf_r2': ["route-map ALL permit 10", "exit",
                      f"router bgp {d.cf_sub1}", f"bgp router-id {r2_lo}"] + common + [
                      f"neighbor {r1_lo} remote-as {d.cf_sub1}", f"neighbor {r1_lo} update-source lo",
                      f"neighbor {r3} remote-as {d.cf_sub2}",
                      "address-family ipv4 unicast", f"neighbor {r3} route-map ALL in",
                      f"neighbor {r3} route-map ALL out", "exit-address-family", "exit"],
        }

    def solution_dmp(self) -> Dict[str, List[str]]:
        h, r, s, m = self.damping()
        return {'dmp_r1': [f"router bgp {self.data.our_as}", "address-family ipv4 unicast",
                           f"bgp dampening {h} {r} {s} {m}", "exit-address-family", "exit"]}

    def solution_gs(self) -> Dict[str, List[str]]:
        d = self.data
        isp1 = self.addr('gs_isp1', 'gs_l1')
        return {'gs_r1': ["route-map TO-ISP1 permit 10", "set community graceful-shutdown additive", "exit",
                          f"router bgp {d.our_as}", f"neighbor {isp1} graceful-shutdown",
                          "address-family ipv4 unicast", f"neighbor {isp1} route-map TO-ISP1 out",
                          "exit-address-family", "exit"]}

    # -- applying the solutions ----------------------------------------------------

    def _apply(self, solution: Dict[str, List[str]], step: int = 1):
        for r, cmds in solution.items():
            self._vtysh(r, *cmds, step=step)

    def _apply_mp(self):
        self._apply(self.solution_mp())
        self.cmd('mp_r1', f"sysctl -w {self.MP_SYSCTL}=1 && echo {self.MP_SYSCTL}=1 > /etc/sysctl.d/90-ecmp.conf")

    def _apply_cf(self):
        self._apply(self.solution_cf())
        # the loopback sessions may have tried before OSPF knew the loopbacks: try again now
        for r in ('cf_r1', 'cf_r2'):
            self.cmd(r, "sleep 3; vtysh -c 'clear bgp *'", step=2)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in MACHINES:
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in FRR_ROUTERS))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for r in FRR_ROUTERS:
            self.cmd(r, f"ip addr add {getattr(d.ips, f'{r}_lo')} dev lo")
        # public addresses: the destinations of pings and flows
        for r, name in (('ne_r1', 'ne_te1'), ('ne_far', 'ne_far'), ('mp_isp1', 'mp_q'), ('mp_isp1', 'mp_p'),
                        ('mp_isp2', 'mp_p'), ('cf_ext1', 'cf_e1'), ('cf_ext2', 'cf_e2'), ('gs_r1', 'gs_own'),
                        ('gs_isp1', 'gs_inet')):
            self.cmd(r, f"ip addr add {self.host(name)}/32 dev lo")
        self.file('mp_h1', FLOWS_SCRIPT, FLOWS_PY, permissions=0o755)
        self.file('dmp_cust', FLAP_SCRIPT, self.flap_script(), permissions=0o755)
        for r in FRR_ROUTERS:
            self.file(r, "/etc/frr/daemons", self._daemons(r), permissions=0o640, owner="frr:frr", step=2)
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(r, "systemctl start frr", step=2)
        # the customer's unstable prefix flaps for ever (part 4)
        self.cmd('dmp_cust', f"sleep 5; setsid -f {FLAP_SCRIPT} > /dev/null 2>&1", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (communautés)"))
    def solve_ne(self):
        self._apply(self.solution_ne())
        self.cmd('ne_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (multichemin)"))
    def solve_mp(self):
        self._apply_mp()
        self.cmd('mp_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (confédération)"))
    def solve_cf(self):
        self._apply_cf()
        self.cmd('cf_r1', f"sleep {CONVERGE_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (amortissement)"))
    def solve_dmp(self):
        self._apply(self.solution_dmp())
        self.cmd('dmp_r1', f"sleep {DAMPENING_WAIT}", step=2, timeout=DAMPENING_WAIT + 30)

    @sre_state(user_allowed=False, description=tr("Bonus : solution (graceful shutdown)"))
    def solve_gs(self):
        self._apply(self.solution_gs())
        self.cmd('gs_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns (it waits for the flapping prefix to be suppressed).  Form questions are filled
        through cheat_answers."""
        self._apply(self.solution_dmp())
        self._apply(self.solution_ne())
        self._apply_mp()
        self._apply_cf()
        self._apply(self.solution_gs())
        self.cmd('dmp_r1', f"sleep {DAMPENING_WAIT}", step=3, timeout=DAMPENING_WAIT + 30)


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _norm(s) -> str:
    return (s or "").strip().lower().rstrip('.')


def _int(s):
    try:
        return int(_norm(s).replace(' ', ''))
    except ValueError:
        return None


_OPENERS = ("router ", "interface ", "route-map ", "address-family ")


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    """The reference configuration of a part, as vtysh sessions (one block per router); the lines
    inside a block (``router``, ``route-map``, ``address-family``...) are indented."""
    blocks = []
    for router, cmds in solution.items():
        body, depth = ["configure terminal"], 1
        for c in cmds:
            if c in ("exit", "exit-address-family"):
                depth = max(1, depth - 1)
                body.append(" " * depth + c)
                continue
            body.append(" " * depth + c)
            if c.startswith(_OPENERS):
                depth += 1
        blocks.append(f"`{router}` :\n\n```\n" + "\n".join(body + ["end", "write"]) + "\n```")
    return "\n\n".join(blocks)


def _running_config(grade: Grade0, router: str) -> Dict:
    """The parsed running configuration of *router*; the empty shape before the results (or when
    vtysh fails)."""
    return get_frr_running_config(grade, router, allow_error=True) or parse_frr_config("")


def _counters(output: str) -> List[int]:
    """The transmitted packets of ``cat /sys/class/net/eth{0,1,2}/statistics/tx_packets``."""
    return [int(x) for x in re.findall(r'^\s*(\d+)\s*$', output or '', re.M)]


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def _ping(self, src: str, dest, source=None, step: int = 1) -> bool:
        """Three pings from *src* (``-I source``); True when one answers."""
        option = f" -I {source}" if source else ""
        output, _code = self.test(src, f"ping -c 3 -w 5{option} {dest}", step=step, allow_error=True)
        return 'bytes from' in (output or '')

    def grade(self):
        super().grade()
        d = self.get_data()
        ns = self.net_scheme
        addr, net, lo, host = ns.addr, ns.net, ns.lo, ns.host

        def best_via(routes: Dict, prefix, nexthop) -> bool:
            return str(bgp_best_path(routes, prefix).get('nexthop')) == str(nexthop)

        def gateways(routes: Dict, prefix) -> List[str]:
            return [str(gw) for gw, _dev in (routes.get(str(prefix)) or {}).get('nexthops', []) if gw]

        def neighbor(cfg: Dict, peer) -> Dict:
            return (cfg.get('router_bgp') or {}).get('neighbors', {}).get(str(peer)) or {}

        def peer_up(summary: Dict, peer) -> bool:
            return bool(((summary.get('peers') or {}).get(str(peer)) or {}).get('established'))

        def has_community(prefix_data: Dict, community: str, peer=None) -> bool:
            return any(community in p['communities'] and (peer is None or p['peer'] == str(peer))
                       for p in prefix_data['paths'])

        # ---------------- diagnostics kept in the archive -------------------------
        for r in STUDENT_ROUTERS:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)

        # ---------------- what the elements read ----------------------------------
        ne_isp_te = [get_bgp_prefix(self, 'ne_isp', net(p), allow_error=True) for p in ('ne_te1', 'ne_te2')]
        ne_isp_c1 = get_bgp_prefix(self, 'ne_isp', net('ne_c1'), allow_error=True)
        ne_isp_routes = get_bgp_routes(self, 'ne_isp', allow_error=True)
        ne_far_routes = get_bgp_routes(self, 'ne_far', allow_error=True)
        ne_ping = self._ping('ne_far', host('ne_te1'), source=host('ne_far'))

        mp_cfg = _running_config(self, 'mp_r1')
        mp_routes = get_bgp_routes(self, 'mp_r1', allow_error=True)
        mp_k = get_kernel_routes(self, 'mp_r1', allow_error=True)
        mp_hash_out, _code = self.test('mp_r1', f"sysctl -n {ns.MP_SYSCTL}", allow_error=True)
        counters = "cat " + " ".join(f"/sys/class/net/{iface('mp_r1', n)}/statistics/tx_packets"
                                     for n in ('mp_l1a', 'mp_l1b', 'mp_l2'))
        mp_before, _code = self.test('mp_r1', counters, allow_error=True)
        self.test('mp_h1', f"python3 {FLOWS_SCRIPT} {host('mp_p')} {FLOW_COUNT} {FLOW_FIRST_PORT}", step=2,
                  allow_error=True)
        mp_after, _code = self.test('mp_r1', counters, step=3, allow_error=True)

        cf_cfg = {r: _running_config(self, r) for r in ('cf_r1', 'cf_r2')}
        cf_sum = {r: get_bgp_summary(self, r, allow_error=True) for r in ('cf_r1', 'cf_r2')}
        cf_routes = {r: get_bgp_routes(self, r, allow_error=True) for r in ('cf_r1', 'cf_r2', 'cf_ext1', 'cf_ext2')}
        cf_r1_e2 = get_bgp_prefix(self, 'cf_r1', net('cf_e2'), allow_error=True)
        cf_ping = self._ping('cf_ext1', host('cf_e2'), source=host('cf_e1'))

        dmp_cfg = _running_config(self, 'dmp_r1')
        dmp_damped = get_bgp_dampened_paths(self, 'dmp_r1')
        dmp_f = get_bgp_prefix(self, 'dmp_r1', net('dmp_f'), allow_error=True)
        dmp_isp_routes = get_bgp_routes(self, 'dmp_isp', allow_error=True)

        gs_isp1 = addr('gs_isp1', 'gs_l1')
        gs_cfg = _running_config(self, 'gs_r1')
        gs_sum = get_bgp_summary(self, 'gs_r1', allow_error=True)
        gs_routes = get_bgp_routes(self, 'gs_r1', allow_error=True)
        gs_isp1_own = get_bgp_prefix(self, 'gs_isp1', net('gs_own'), allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('ne', "1 — communautés bien connues", "`ne_r1` ; `ne_isp`, `ne_far`, `ne_cust` sans terminal"),
                 ('mp', "2 — multichemin", "`mp_r1`, l'hôte `mp_h1` ; `mp_isp1`, `mp_isp2` sans terminal"),
                 ('cf', "3 — confédération", "`cf_r1`, `cf_r2` (à configurer), `cf_r3`, `cf_r4` (déjà "
                                            "configurés) ; `cf_ext1`, `cf_ext2` sans terminal"),
                 ('dmp', "4 — amortissement", "`dmp_r1` ; `dmp_isp`, `dmp_cust` sans terminal"),
                 ('gs', "bonus — graceful shutdown", "`gs_r1` ; `gs_isp1`, `gs_isp2` sans terminal")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {}
        for m, nets in MACHINE_IFACES.items():
            for i, n in enumerate(nets):
                if m in HOSTS:
                    members.setdefault(n, []).append(f"`{m}` (`{d.ips.mp_h1.ip}`)")
                else:
                    members.setdefault(n, []).append(f"`{m}` eth{i} (`{addr(m, n)}`)")
        address_rows = [f"| `{n}` | `{net(n)}` | {', '.join(v)} |" for n, v in members.items()]
        address_rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                         + ", ".join(f"`{r}` `{lo(r)}`" for r in FRR_ROUTERS if site_of(r) == site) + " |"
                         for site in SITE_NUMBER]
        addressing = "\n".join(address_rows)
        as_rows = "\n".join(f"| `{r}` | {asn} |" for r, asn in EXT_AS.items())

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Lisez l'onglet **Informations** : il présente les communautés (dont les communautés bien connues),
le multichemin, les confédérations, l'amortissement des oscillations et le *graceful shutdown*, leur
configuration avec FRR et les commandes de diagnostic.

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Vous êtes l'opérateur de l'**AS {our_as}** : ses routeurs sont les `*_r1` de chaque site, et les
  quatre routeurs `cf_r*` (l'AS {our_as} y est une confédération). Les autres routeurs appartiennent à
  d'autres opérateurs : vous n'avez pas de terminal sur eux.
- Les routeurs font tourner **FRRouting** (FRR) avec `bgpd` (et `ospfd` dans la confédération) :
  configurez-les avec `vtysh`. Les sessions BGP de vos routeurs existent déjà, avec leurs politiques
  (route-map `ALL`), sauf sur `cf_r1` et `cf_r2`.
- Toutes les adresses sont en place, y compris les interfaces de bouclage (`lo`). Les fichiers
  `/etc/hosts` contiennent les noms : `ne_isp-eth1` désigne l'adresse de l'interface `eth1` de
  `ne_isp`, `cf_r2-lo` son adresse de bouclage.

**Les AS des autres opérateurs.**

| routeur | AS |
|---------|----|
{as_rows}

**Plan d'adressage.** Les liens entre routeurs sont des /30. Les préfixes annoncés en BGP sont pris
dans `{pub}`.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).
- Une route-map modifiée prend effet au bout de quelques secondes ; `clear bgp A.B.C.D soft in|out`
  la réapplique aussitôt.

**Évaluation.** Chaque évaluation lit vos réponses, l'état de BGP sur les routeurs (sessions, tables,
configuration), les tables de routage, et lance des `ping` et une série de flux depuis `mp_h1`.
""").format(site_rows=site_rows, our_as=d.our_as, as_rows=as_rows, pub=net('pub'), addressing=addressing)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_ne`, `solve_mp`, `solve_cf`, `solve_dmp` et `solve_gs` (onglet *Appliquer
une configuration*) appliquent la solution d'une seule partie et remplissent ses formulaires. L'état
`final` les applique toutes et attend {wait} s (la suppression du préfixe instable) puis remplit tous
les formulaires : une évaluation lancée dès son retour donne tous les points, bonus compris.

`dmp_cust` retire et réannonce son préfixe instable toutes les {half} s (`{script}`, lancé par l'état
initial ; il ne survit pas au redémarrage de la machine).
""").format(wait=DAMPENING_WAIT, half=FLAP_HALF_PERIOD, script=FLAP_SCRIPT)),
        )

        # =====================================================================
        # Part 1 — well-known communities (ne)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("ne"), tr("Partie 1 — communautés bien connues (site ne)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Communautés bien connues"),
            description=tr("""
`ne_r1` a un fournisseur, `ne_isp` (AS {asi}), qui a lui-même pour pair `ne_far` (AS {asf}, « le
reste de l'Internet »), et un client, `ne_cust` (AS {asc}). Il annonce votre bloc `{own}`.

`ne_cust` annonce trois préfixes : `{c1}` sans communauté, `{c2}` marqué **`no-export`** et `{c3}`
marqué **`no-advertise`** (sections @@ref:communities@@ et @@ref:well-known@@).

1. **Observation.** Sur `ne_r1`, quels préfixes de `ne_cust` reçoit-on, avec quelles communautés
   (`show bgp ipv4 unicast P`) ? Lesquels annonce-t-il à `ne_isp` (`show bgp ipv4 unicast neighbors
   {isp} advertised-routes`) ? Pourquoi ?
2. **Ingénierie de trafic.** Annoncez à `ne_isp` (et seulement à lui) les deux /24 `{te1}` et `{te2}`
   de votre bloc, marqués **`no-export`** : `ne_isp` doit les recevoir, `ne_far` ne voir que `{own}`.
   Les routes statiques vers `blackhole` de ces deux /24 existent déjà.
3. **Demande du client.** `ne_cust` veut que `{c1}` ne soit pas propagé au-delà de votre fournisseur :
   marquez-le **`no-export`** vers `ne_isp`.
4. Vérifiez chez `ne_isp` (`advertised-routes`) et chez `ne_far` (`ping {far_addr}` depuis `ne_r1`
   passe toujours).
""").format(asi=EXT_AS['ne_isp'], asf=EXT_AS['ne_far'], asc=EXT_AS['ne_cust'], own=net('ne_own'), c1=net('ne_c1'),
            c2=net('ne_c2'), c3=net('ne_c3'), isp=addr('ne_isp', 'ne_l1'), te1=net('ne_te1'), te2=net('ne_te2'),
            far_addr=host('ne_far'))
            + instructor(tr("""
**Solution.**

{solution}

La route-map de sortie ajoute la communauté **après** la vérification des communautés bien connues
par `ne_r1` : les routes partent chez `ne_isp`, qui les garde pour lui. `{c2}` (`no-export` posé par
le client) n'est pas annoncé à `ne_isp` (session eBGP) ; `{c3}` (`no-advertise`) n'arrive même pas
chez `ne_r1` : `ne_cust` ne l'annonce à personne.

Évaluation : `ne_te_isp` (3 : les deux /24 chez `ne_isp` avec `no-export`), `ne_te_far` (3 : `ne_far`
a `{own}` mais aucun des /24), `ne_c1_isp` (2 : `{c1}` chez `ne_isp` avec `no-export`), `ne_c1_far`
(2 : absent de `ne_far`), `ne_reach` (2 : `ne_far` joint `{te_addr}`).
""").format(solution=_vtysh_text(ns.solution_ne()), c2=net('ne_c2'), c3=net('ne_c3'), own=net('ne_own'),
            c1=net('ne_c1'), te_addr=host('ne_te1'))),
        )
        cheat_ne = {'c2': 'no-export', 'count': '1', 'value': NO_EXPORT_VALUE, 'c3': 'never'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site ne"),
            description=tr("""
- communauté de `{c2}` vue par `ne_r1` : @@{{c2:[a-zA-Z0-9:-]+}}@@
- au départ, nombre de préfixes de `ne_cust` que `ne_r1` annonce à `ne_isp` : @@{{count:[0-9]+}}@@
- valeur de `no-export` (forme `AS:valeur`) : @@{{value:[0-9:]+}}@@
- `{c3}` :
  @@{{c3:>n'arrive jamais chez ne_r1>>>never|arrive chez ne_r1 qui ne le réannonce pas>>>stops|arrive chez ne_isp qui ne le réannonce pas>>>isp|est propagé partout>>>everywhere}}@@
""").format(c2=net('ne_c2'), c3=net('ne_c3'))
            + instructor(tr("""
**Solution.** **no-export** ; **1** (`{c1}` seulement) ; **{value}** (0xFFFFFF01) ; `{c3}`
**n'arrive jamais chez `ne_r1`** (`no-advertise` : `ne_cust` ne l'annonce à aucun pair).

Évaluation : `ne_q_c2`, `ne_q_count`, `ne_q_value` (1 chacun) et, pour l'enseignant seulement,
`ne_q_c3` (1).
""").format(c1=net('ne_c1'), value=NO_EXPORT_VALUE, c3=net('ne_c3'))),
            cheat_answers={"final": cheat_ne, "solve_ne": cheat_ne},
        )
        r1_ne = addr('ne_r1', 'ne_l1')
        te_isp_ok = all(has_community(p, 'noExport', r1_ne) for p in ne_isp_te)
        c1_isp_ok = has_community(ne_isp_c1, 'noExport', r1_ne)
        self.add_grade_element(
            title=no_tr("ne_te_isp"), max_grade=3, grade_part=part1, grade=3 * int(te_isp_ok),
            description=tr("les /24 annoncés au fournisseur avec no-export"),
        )
        self.add_grade_element(
            title=no_tr("ne_te_far"), max_grade=3, grade_part=part1,
            grade=3 * int(te_isp_ok and str(net('ne_own')) in ne_far_routes
                          and not any(str(net(p)) in ne_far_routes for p in ('ne_te1', 'ne_te2'))),
            description=tr("au-delà du fournisseur, seul le bloc est visible"),
        )
        self.add_grade_element(
            title=no_tr("ne_c1_isp"), max_grade=2, grade_part=part1, grade=2 * int(c1_isp_ok),
            description=tr("préfixe du client marqué no-export vers le fournisseur"),
        )
        self.add_grade_element(
            title=no_tr("ne_c1_far"), max_grade=2, grade_part=part1,
            grade=2 * int(c1_isp_ok and bool(ne_far_routes) and str(net('ne_c1')) not in ne_far_routes),
            description=tr("préfixe du client non propagé au-delà"),
        )
        self.add_grade_element(
            title=no_tr("ne_reach"), max_grade=2, grade_part=part1, grade=2 * int(te_isp_ok and ne_ping),
            description=tr("le reste de l'Internet joint toujours le bloc"),
        )
        self.add_grade_element(
            title=no_tr("ne_q_c2"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get('c2')).replace('_', '-') in ('no-export', NO_EXPORT_VALUE)),
            description=tr("communauté posée par le client"),
        )
        self.add_grade_element(
            title=no_tr("ne_q_count"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('count')) == 1),
            description=tr("préfixes du client annoncés au fournisseur"),
        )
        self.add_grade_element(
            title=no_tr("ne_q_value"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get('value')).replace(' ', '') == NO_EXPORT_VALUE), description=tr("valeur de no-export"),
        )
        self.add_grade_element(
            title=no_tr("ne_q_c3"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get('c3')) == cheat_ne['c3']), description=tr("effet de no-advertise"),
        )

        # =====================================================================
        # Part 2 — multipath (mp)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("mp"), tr("Partie 2 — multichemin (site mp)"))
        isp1a, isp1b, isp2 = addr('mp_isp1', 'mp_l1a'), addr('mp_isp1', 'mp_l1b'), addr('mp_isp2', 'mp_l2')
        self.question_dummy(
            section=self.section(0),
            title=tr("Répartir le trafic sur plusieurs chemins"),
            description=tr("""
`mp_r1` a deux liens et deux sessions avec `mp_isp1` (AS {as1}), une session avec `mp_isp2`
(AS {as2}). `mp_isp1` annonce `{q}` ; un service présent chez les deux fournisseurs, `{p}`, est
annoncé par chacun avec un AS_PATH d'un seul AS. L'hôte `mp_h1` (`{h1}`) est derrière `mp_r1`.

1. **Observation.** Sur `mp_r1` : combien de prochains sauts pour `{q}` et pour `{p}` (`ip route`,
   `show bgp ipv4 unicast`, marque `=`) ? Pourquoi `mp_isp2` n'est-il pas utilisé pour `{p}` (section
   @@ref:multipath@@) ?
2. **Multichemin entre fournisseurs.** Faites installer par `mp_r1` les trois chemins de `{p}`.
3. **Répartition.** Depuis `mp_h1`, `python3 {flows} {p_addr} 60 40000` envoie un datagramme UDP depuis
   chacun de 60 ports source. Regardez les compteurs des interfaces de `mp_r1` (`ip -s link`) :
   comment se répartissent ces flux ? Faites en sorte qu'ils se répartissent sur les trois liens, de
   façon durable (section @@ref:hash@@).
""").format(as1=EXT_AS['mp_isp1'], as2=EXT_AS['mp_isp2'], q=net('mp_q'), p=net('mp_p'), h1=d.ips.mp_h1.ip,
            flows=FLOWS_SCRIPT, p_addr=host('mp_p'))
            + instructor(tr("""
**Solution.**

{solution}

et, sur `mp_r1` : `sysctl -w {sysctl}=1` et `echo {sysctl}=1 > /etc/sysctl.d/90-ecmp.conf`.

FRR installe déjà les deux chemins de `mp_isp1` (même AS voisin, multichemin actif par défaut) :
`{q}` a deux prochains sauts. Pour `{p}`, le chemin de `mp_isp2` a un autre AS voisin : il n'entre
dans le multichemin qu'avec `multipath-relax`. Avec le hachage par défaut (adresses seulement), les 60
flux de `mp_h1` vers la même adresse partent tous par le même lien ; avec `{sysctl}=1` (ports
compris), environ 20 par lien.

Évaluation : `mp_relax_conf` (1), `mp_three_paths` (3 : trois prochains sauts dans le noyau pour
`{p}`), `mp_bgp_flags` (1 : les trois chemins installés), `mp_hash` (2), `mp_spread` (3 : chacun des
trois liens porte au moins {min_flows} des {count} flux de l'évaluation).
""").format(solution=_vtysh_text(ns.solution_mp()), sysctl=ns.MP_SYSCTL, q=net('mp_q'), p=net('mp_p'),
            min_flows=FLOW_MIN_PER_LINK, count=FLOW_COUNT)),
        )
        cheat_mp = {'q_paths': '2', 'relax': 'neighbor_as', 'hash': 'addresses', 'default': 'on'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site mp"),
            description=tr("""
- au départ, nombre de prochains sauts de `mp_r1` vers `{q}` : @@{{q_paths:[0-9]+}}@@
- au départ, le chemin de `mp_isp2` vers `{p}` n'est pas installé avec les deux autres car :
  @@{{relax:>son AS voisin n'est pas celui du meilleur chemin>>>neighbor_as|son AS_PATH est plus long>>>longer|sa local-preference est plus basse>>>locpref|maximum-paths vaut 1 par défaut>>>maxpaths}}@@
- par défaut, le noyau choisit le prochain saut d'un paquet d'après :
  @@{{hash:>les adresses source et destination>>>addresses|les adresses et les ports>>>ports|un tirage paquet par paquet>>>packet|le premier prochain saut toujours>>>first}}@@
- avec FRR, le multichemin eBGP :
  @@{{default:>est actif sans configuration>>>on|demande maximum-paths>>>off|n'existe qu'entre deux AS voisins différents>>>relax}}@@
""").format(q=net('mp_q'), p=net('mp_p'))
            + instructor(tr("""
**Solution.** **2** ; **son AS voisin n'est pas celui du meilleur chemin** ; **les adresses source et
destination** (`fib_multipath_hash_policy` 0) ; **actif sans configuration**.

Évaluation : `mp_q_paths` (1) et, pour l'enseignant seulement, `mp_q_relax`, `mp_q_hash`,
`mp_q_default` (1 chacun).
""")),
            cheat_answers={"final": cheat_mp, "solve_mp": cheat_mp},
        )
        three = sorted(gateways(mp_k, net('mp_p'))) == sorted(str(x) for x in (isp1a, isp1b, isp2))
        before, after = _counters(mp_before), _counters(mp_after)
        spread = [b - a for a, b in zip(before, after)] if len(before) == len(after) == 3 else []
        self.add_grade_element(
            title=no_tr("mp_relax_conf"), max_grade=1, grade_part=part2,
            grade=int('as-path multipath-relax' in mp_cfg['router_bgp']['bestpath']),
            description=tr("condition du même AS voisin levée"),
        )
        self.add_grade_element(
            title=no_tr("mp_three_paths"), max_grade=3, grade_part=part2, grade=3 * int(three),
            description=tr("trois prochains sauts vers le service"),
        )
        p_paths = mp_routes.get(str(net('mp_p')), [])
        self.add_grade_element(
            title=no_tr("mp_bgp_flags"), max_grade=1, grade_part=part2,
            grade=int(len(p_paths) == 3 and all(p['multipath'] or p['best'] for p in p_paths)),
            description=tr("trois chemins BGP installés"),
        )
        self.add_grade_element(
            title=no_tr("mp_hash"), max_grade=2, grade_part=part2, grade=2 * int(_int(mp_hash_out) == 1),
            description=tr("hachage sur les ports"),
        )
        self.add_grade_element(
            title=no_tr("mp_spread"), max_grade=3, grade_part=part2,
            grade=3 * int(three and bool(spread) and min(spread) >= FLOW_MIN_PER_LINK),
            description=tr("flux répartis sur les trois liens"),
        )
        self.add_grade_element(
            title=no_tr("mp_q_paths"), max_grade=1, grade_part=part2, grade=int(_int(q2.get('q_paths')) == 2),
            description=tr("prochains sauts par défaut"),
        )
        for key, label in (('relax', tr("condition du même AS voisin")), ('hash', tr("hachage par défaut")),
                           ('default', tr("multichemin par défaut"))):
            self.add_grade_element(
                title=no_tr(f"mp_q_{key}"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                grade=int(_norm(q2.get(key)) == cheat_mp[key]), description=label,
            )

        # =====================================================================
        # Part 3 — confederation (cf)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("cf"), tr("Partie 3 — confédération (site cf)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une confédération"),
            description=tr("""
Dans ce site, l'AS **{our_as}** est une **confédération** de deux AS membres (section
@@ref:confed@@) : **{s1}** (`cf_r1`, `cf_r2`) et **{s2}** (`cf_r3`, `cf_r4`). Les quatre routeurs
sont en ligne ; OSPF tourne déjà entre eux (liens internes et adresses de bouclage). `cf_ext1`
(AS {e1}, `{pe1}`) est relié à `cf_r1`, `cf_ext2` (AS {e2}, `{pe2}`) à `cf_r4` ; tous deux voient
l'AS {our_as}.

`cf_r3` et `cf_r4` sont configurés (regardez leur configuration) : session iBGP entre leurs adresses
de bouclage, session eBGP de confédération de `cf_r3` vers `cf_r2` (`{r2l23}`), session avec
`cf_ext2`. `cf_r4` donne une `local-preference` de {lp} aux routes de `cf_ext2` et annonce `{s2net}`,
`{n}` marqué **`no-export`** et `{l}` marqué **`local-AS`**.

1. **Configuration.** Configurez BGP sur `cf_r1` et `cf_r2` (AS membre {s1}) : identifiant et pairs
   de la confédération, session iBGP entre leurs adresses de bouclage (`next-hop-self` de `cf_r1` vers
   `cf_r2`), session eBGP de confédération de `cf_r2` vers `cf_r3` (`{r3l23}`), session de `cf_r1` avec
   `cf_ext1` (`{ext1}`).
2. **Observation.** Comparez l'AS_PATH de `{pe2}` sur `cf_r1`, `cf_r2` et (d'après ce que reçoit
   `cf_ext1` : `show bgp ipv4 unicast neighbors {ext1} advertised-routes` sur `cf_r1`) chez `cf_ext1`.
   Que devient la `local-preference` posée par `cf_r4` ? Où vont `{n}` et `{l}` ?
3. Vérifiez que `cf_ext1` et `cf_ext2` échangent leurs préfixes (`ping -I {e1addr} {e2addr}` depuis…
   l'évaluation le fait).
""").format(our_as=d.our_as, s1=d.cf_sub1, s2=d.cf_sub2, e1=EXT_AS['cf_ext1'], pe1=net('cf_e1'),
            e2=EXT_AS['cf_ext2'], pe2=net('cf_e2'), r2l23=addr('cf_r2', 'cf_l23'), lp=LOCAL_PREF_EXT2,
            s2net=net('cf_s2'), n=net('cf_n'), l=net('cf_l'), r3l23=addr('cf_r3', 'cf_l23'),
            ext1=addr('cf_ext1', 'cf_le1'), e1addr=host('cf_e1'), e2addr=host('cf_e2'))
            + instructor(tr("""
**Solution.**

{solution}

Vu de `cf_r1`, `{pe2}` a l'AS_PATH `({s2}) {e2}` et la `local-preference` {lp} (conservée entre AS
membres) ; `cf_ext1` reçoit `{our_as} {e2}` : les AS membres disparaissent à la sortie. `{n}`
(`no-export`) va jusqu'à `cf_r1` mais pas chez `cf_ext1` ; `{l}` (`local-AS`) reste dans l'AS membre
{s2} (`cf_r3`, `cf_r4`).

Évaluation : `cf_conf` (2 : un par routeur), `cf_sessions` (3 : iBGP `cf_r1`–`cf_r2`, `cf_r2`–`cf_r3`,
`cf_r1`–`cf_ext1`), `cf_ext1_path` (3), `cf_ext2_path` (2), `cf_inside` (2 : `({s2})` vu de `cf_r1`),
`cf_localpref` (2), `cf_no_export` (3), `cf_local_as` (2), `cf_ping` (2).
""").format(solution=_vtysh_text(ns.solution_cf()), pe2=net('cf_e2'), s2=d.cf_sub2, e2=EXT_AS['cf_ext2'],
            lp=LOCAL_PREF_EXT2, our_as=d.our_as, n=net('cf_n'), l=net('cf_l'))),
        )
        cheat_cf = {'path': f"{d.our_as} {EXT_AS['cf_ext2']}", 'attr': 'localpref', 'nexthop': 'unchanged'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site cf"),
            description=tr("""
- AS_PATH de `{pe2}` reçu par `cf_ext1` : @@{{path:[0-9 ]+}}@@
- l'attribut conservé d'un AS membre à l'autre et jamais transmis à un AS externe :
  @@{{attr:>LOCAL_PREF>>>localpref|ORIGIN>>>origin|AS_PATH>>>aspath|COMMUNITY>>>community}}@@
- le NEXT_HOP d'une route passée par une session eBGP de confédération :
  @@{{nexthop:>est conservé, comme en iBGP>>>unchanged|devient l'adresse du routeur qui l'annonce, comme en eBGP>>>self|est retiré>>>removed}}@@
""").format(pe2=net('cf_e2'))
            + instructor(tr("""
**Solution.** **{path}** ; **LOCAL_PREF** ; **conservé, comme en iBGP**.

Évaluation : `cf_q_path` (1) et, pour l'enseignant seulement, `cf_q_attr`, `cf_q_nexthop` (1 chacun).
""").format(path=cheat_cf['path'])),
            cheat_answers={"final": cheat_cf, "solve_cf": cheat_cf},
        )

        def confed_ok(r: str) -> int:
            rb = cf_cfg[r]['router_bgp']
            return int(rb.get('as') == d.cf_sub1 and rb.get('confederation_identifier') == d.our_as
                       and d.cf_sub2 in rb.get('confederation_peers', []))

        r1, r2 = cf_sum['cf_r1'], cf_sum['cf_r2']
        ext1_e2 = bgp_best_path(cf_routes['cf_ext1'], net('cf_e2'))
        ext2_e1 = bgp_best_path(cf_routes['cf_ext2'], net('cf_e1'))
        inside = next((p for p in cf_r1_e2['paths'] if p['best']), {})
        self.add_grade_element(
            title=no_tr("cf_conf"), max_grade=2, grade_part=part3, grade=confed_ok('cf_r1') + confed_ok('cf_r2'),
            description=tr("cf_r1 et cf_r2 dans la confédération"),
        )
        self.add_grade_element(
            title=no_tr("cf_sessions"), max_grade=3, grade_part=part3,
            grade=int(peer_up(r1, lo('cf_r2'))) + int(peer_up(r2, addr('cf_r3', 'cf_l23')))
            + int(peer_up(r1, addr('cf_ext1', 'cf_le1'))),
            description=tr("sessions de cf_r1 et cf_r2 établies"),
        )
        self.add_grade_element(
            title=no_tr("cf_ext1_path"), max_grade=3, grade_part=part3,
            grade=3 * int(ext1_e2.get('as_list') == [d.our_as, EXT_AS['cf_ext2']]),
            description=tr("cf_ext1 voit l'identifiant de la confédération"),
        )
        self.add_grade_element(
            title=no_tr("cf_ext2_path"), max_grade=2, grade_part=part3,
            grade=2 * int(ext2_e1.get('as_list') == [d.our_as, EXT_AS['cf_ext1']]),
            description=tr("cf_ext2 voit l'identifiant de la confédération"),
        )
        self.add_grade_element(
            title=no_tr("cf_inside"), max_grade=2, grade_part=part3,
            grade=2 * int(inside.get('confed_as_list') == [d.cf_sub2]),
            description=tr("l'AS membre traversé est visible dans la confédération"),
        )
        self.add_grade_element(
            title=no_tr("cf_localpref"), max_grade=2, grade_part=part3,
            grade=2 * int(inside.get('locprf') == LOCAL_PREF_EXT2), description=tr("local-preference conservée"),
        )
        self.add_grade_element(
            title=no_tr("cf_no_export"), max_grade=3, grade_part=part3,
            grade=3 * int(bool(ext1_e2) and str(net('cf_n')) in cf_routes['cf_r1']
                          and str(net('cf_n')) not in cf_routes['cf_ext1']),
            description=tr("no-export : dans la confédération, pas au-delà"),
        )
        self.add_grade_element(
            title=no_tr("cf_local_as"), max_grade=2, grade_part=part3,
            grade=2 * int(str(net('cf_s2')) in cf_routes['cf_r2'] and str(net('cf_l')) not in cf_routes['cf_r2']),
            description=tr("local-AS : dans l'AS membre seulement"),
        )
        self.add_grade_element(
            title=no_tr("cf_ping"), max_grade=2, grade_part=part3, grade=2 * int(cf_ping),
            description=tr("cf_ext1 et cf_ext2 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("cf_q_path"), max_grade=1, grade_part=part3,
            grade=int(" ".join(_norm(q3.get('path')).split()) == cheat_cf['path']),
            description=tr("AS_PATH vu de l'extérieur"),
        )
        for key, label in (('attr', tr("attribut conservé entre AS membres")),
                           ('nexthop', tr("NEXT_HOP en eBGP de confédération"))):
            self.add_grade_element(
                title=no_tr(f"cf_q_{key}"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
                grade=int(_norm(q3.get(key)) == cheat_cf[key]), description=label,
            )

        # =====================================================================
        # Part 4 — dampening (dmp)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("dmp"), tr("Partie 4 — amortissement des oscillations (site dmp)"))
        h, r, s, m = ns.damping()
        self.question_dummy(
            section=self.section(0),
            title=tr("Amortir une route instable"),
            description=tr("""
`dmp_r1` a un fournisseur, `dmp_isp` (AS {asi}), et un client, `dmp_cust` (AS {asc}), qui annonce
`{s}` et `{f}`. La liaison de ce client vers `{f}` est instable : le préfixe apparaît et disparaît
toutes les {half} s, et chaque changement repart vers `dmp_isp` et tout l'Internet.

1. **Observation.** Sur `dmp_r1`, regardez `{f}` apparaître et disparaître (`show bgp ipv4 unicast`,
   `/var/log/frr/frr.log`), et ce que voit `dmp_isp` (`advertised-routes`).
2. **Amortissement.** Activez l'amortissement sur `dmp_r1` avec : demi-vie **{h}** min, seuil de
   réutilisation **{r}**, seuil de suppression **{s_}**, durée maximale de suppression **{m}** min
   (section @@ref:dampening@@).
3. Suivez la pénalité de `{f}` (`show bgp ipv4 unicast {f}`, `show bgp ipv4 unicast dampening
   flap-statistics`) jusqu'à sa suppression (environ une minute), puis vérifiez que `dmp_isp` ne le
   reçoit plus alors que `{s}` reste annoncé.
""").format(asi=EXT_AS['dmp_isp'], asc=EXT_AS['dmp_cust'], s=net('dmp_s'), f=net('dmp_f'),
            half=FLAP_HALF_PERIOD, h=h, r=r, s_=s, m=m)
            + instructor(tr("""
**Solution.**

{solution}

Chaque retrait ajoute 1000 à la pénalité de `{f}` ; au-delà de {s_} (trois ou quatre oscillations, en
une minute environ), la route est supprimée (`d` dans `show bgp ipv4 unicast`, `suppressed due to
dampening`) et n'est plus annoncée à `dmp_isp`. Tant que le préfixe oscille, la pénalité reste haute :
la route ne sera réutilisée qu'après {m} min au plus.

Évaluation : `dmp_conf` (3 : les quatre paramètres), `dmp_suppressed` (4 : `{f}` supprimé sur
`dmp_r1`), `dmp_not_propagated` (3 : `{f}` absent de `dmp_isp`, `{s}` présent).
""").format(solution=_vtysh_text(ns.solution_dmp()), f=net('dmp_f'), s_=s, m=m, s=net('dmp_s'))),
        )
        cheat_dmp = {'penalty': '1000', 'halved': str(h), 'code': 'd', 'why': 'convergence'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site dmp"),
            description=tr("""
- pénalité ajoutée par un retrait de la route : @@{penalty:[0-9]+}@@
- avec vos paramètres, durée (en minutes) au bout de laquelle une pénalité est divisée par deux :
  @@{halved:[0-9]+}@@
- code d'état d'une route supprimée dans `show bgp ipv4 unicast` :
  @@{code:>d>>>d|h>>>h|s>>>s|r>>>r}@@
- l'amortissement est déconseillé aujourd'hui car :
  @@{why:>un seul événement produit plusieurs mises à jour et une route stable peut être supprimée>>>convergence|il demande trop de mémoire>>>memory|il ne marche qu'en iBGP>>>ibgp|il est incompatible avec RPKI>>>rpki}@@
""")
            + instructor(tr("""
**Solution.** **1000** ; **{h}** ; **d** (*damped* ; `h` = historique d'une route retirée) ; **un seul
événement produit plusieurs mises à jour** (exploration des chemins de rechange) **et une route stable
peut être supprimée** (RFC 7196).

Évaluation : `dmp_q_penalty`, `dmp_q_halved` (1 chacun) et, pour l'enseignant seulement, `dmp_q_code`,
`dmp_q_why` (1 chacun).
""").format(h=h)),
            cheat_answers={"final": cheat_dmp, "solve_dmp": cheat_dmp},
        )
        conf_ok = dmp_cfg['router_bgp'].get('dampening') == (h, r, s, m)
        suppressed = (any(e['damped'] for e in dmp_damped.get(str(net('dmp_f')), []))
                      or any(p['damped'] for p in dmp_f['paths']))
        self.add_grade_element(
            title=no_tr("dmp_conf"), max_grade=3, grade_part=part4, grade=3 * int(conf_ok),
            description=tr("paramètres de l'amortissement"),
        )
        self.add_grade_element(
            title=no_tr("dmp_suppressed"), max_grade=4, grade_part=part4, grade=4 * int(suppressed),
            description=tr("route instable supprimée"),
        )
        self.add_grade_element(
            title=no_tr("dmp_not_propagated"), max_grade=3, grade_part=part4,
            grade=3 * int(suppressed and str(net('dmp_s')) in dmp_isp_routes
                          and str(net('dmp_f')) not in dmp_isp_routes),
            description=tr("route supprimée non propagée"),
        )
        self.add_grade_element(
            title=no_tr("dmp_q_penalty"), max_grade=1, grade_part=part4, grade=int(_int(q4.get('penalty')) == 1000),
            description=tr("pénalité d'un retrait"),
        )
        self.add_grade_element(
            title=no_tr("dmp_q_halved"), max_grade=1, grade_part=part4, grade=int(_int(q4.get('halved')) == h),
            description=tr("demi-vie"),
        )
        for key, label in (('code', tr("code d'une route supprimée")), ('why', tr("limites de l'amortissement"))):
            self.add_grade_element(
                title=no_tr(f"dmp_q_{key}"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                grade=int(_norm(q4.get(key)) == cheat_dmp[key]), description=label,
            )

        # =====================================================================
        # Bonus — graceful shutdown (gs)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("gs"), tr("Bonus — graceful shutdown (site gs)"))
        gs_isp2 = addr('gs_isp2', 'gs_l2')
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : vider un lien avant une maintenance"),
            description=tr("""
`gs_r1` a deux fournisseurs, `gs_isp1` (AS {as1}) et `gs_isp2` (AS {as2}), qui sont pairs entre eux.
`gs_isp1` annonce `{inet}` ; `gs_r1` annonce `{own}`. Dans les deux sens, le trafic passe par le lien
direct `gs_r1`–`gs_isp1` (le chemin par `gs_isp2` est plus long d'un AS).

Le lien vers `gs_isp1` doit passer en maintenance. **Sans fermer la session**, faites en sorte que le
trafic **sortant** de `gs_r1` vers `{inet}` **et** le trafic **entrant** de `gs_isp1` vers `{own}`
passent par `gs_isp2` (section @@ref:gshut@@). `gs_isp1` applique la communauté GRACEFUL_SHUTDOWN.
""").format(as1=EXT_AS['gs_isp1'], as2=EXT_AS['gs_isp2'], inet=net('gs_inet'), own=net('gs_own'))
            + instructor(tr("""
**Solution.**

{solution}

`neighbor … graceful-shutdown` donne une `local-preference` de 0 aux routes reçues de `gs_isp1` :
`{inet}` passe par `gs_isp2` ({isp2}). La route-map ajoute la communauté aux routes annoncées à
`gs_isp1`, qui leur donne une `local-preference` de 0 et préfère le chemin par `gs_isp2`. La session
reste établie : elle peut ensuite être coupée sans perte. (`bgp graceful-shutdown` marquerait aussi
les routes envoyées à `gs_isp2` et ne viderait pas le lien.)

Évaluation (bonus) : `gs_conf` (1), `gs_out` (2 : `{inet}` par `gs_isp2`), `gs_in` (2 : `gs_isp1`
préfère `{own}` par `gs_isp2`, sa route directe porte la communauté), `gs_session` (1 : session avec
`gs_isp1` toujours établie).
""").format(solution=_vtysh_text(ns.solution_gs()), inet=net('gs_inet'), isp2=gs_isp2, own=net('gs_own'))),
        )
        out_ok = best_via(gs_routes, net('gs_inet'), gs_isp2)
        best_isp1 = next((p for p in gs_isp1_own['paths'] if p['best']), {})
        in_ok = (best_isp1.get('as_list') == [EXT_AS['gs_isp2'], d.our_as]
                 and has_community(gs_isp1_own, 'gracefulShutdown', addr('gs_r1', 'gs_l1')))
        self.add_grade_element(
            title=no_tr("gs_conf"), max_grade=1, grade_part=part5, bonus=True,
            grade=int(bool(neighbor(gs_cfg, gs_isp1).get('graceful_shutdown'))),
            description=tr("graceful-shutdown vers gs_isp1"),
        )
        self.add_grade_element(
            title=no_tr("gs_out"), max_grade=2, grade_part=part5, bonus=True, grade=2 * int(out_ok),
            description=tr("trafic sortant par gs_isp2"),
        )
        self.add_grade_element(
            title=no_tr("gs_in"), max_grade=2, grade_part=part5, bonus=True, grade=2 * int(in_ok),
            description=tr("trafic entrant par gs_isp2"),
        )
        self.add_grade_element(
            title=no_tr("gs_session"), max_grade=1, grade_part=part5, bonus=True,
            grade=int((out_ok or in_ok) and peer_up(gs_sum, gs_isp1)),
            description=tr("session avec gs_isp1 maintenue"),
        )


_TRANSLATIONS = {}
