"""BGP security with FRR: route origin validation (RPKI), maximum-prefix, GTSM, RTBH; bonus BFD.

IPv4 only.  Four independent sites, one per part, and a bonus site (completing a part gives all its
points whatever the others).  The students' routers (``*_r1``, all in their AS) already have their
BGP sessions; each part adds an operational protection:

- ``rov``: ``rov_r1`` connects to the RPKI cache ``rov_rpki`` (stayrtr serving a local JSON file of
  ROAs) and drops the invalid routes of its two providers (an origin hijack and a sub-prefix hijack
  with a forged origin) while preferring the valid ones; the students also fix the ROA of their own
  prefix so that the validating peer ``rov_peer`` accepts their more-specific /24;
- ``pfx``: ``pfx_r1`` limits the prefixes of its two customers; ``pfx_c2`` leaks a table of 40
  routes and its session must close (``Idle (PfxCt)``) instead of passing the leak to ``pfx_isp``;
- ``gtsm``: ``gtsm_isp`` (direct) and ``gtsm_par`` (two hops, loopbacks) demand GTSM;
- ``bh``: ``bh_cust`` asks for the blackholing of an attacked address (BLACKHOLE community) and of
  an address that is not its own; ``bh_r1`` drops the traffic to the first one through its discard
  interface and refuses the second;
- ``bfd`` (bonus): BFD on the eBGP session of ``bfd_r1`` to its primary provider; each evaluation
  cuts the bridge ``bfd_sw`` for a few seconds and measures the outage.

Grading reads the json of vtysh (lib/frr.py: summary, neighbours, tables, RPKI, BFD), the running
configuration, the kernel routes and real pings.  The states ``solve_<part>`` apply the reference
solution of one part, ``final`` all of them.
"""
import json
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
    bfd_profile_value, bgp_best_path, bgp_paths, get_bfd_peers, get_bgp_routes, get_bgp_summary,
    get_frr_running_config, get_kernel_routes, get_rpki_cache_connection, get_rpki_prefix_table,
    get_bgp_prefix, parse_frr_config,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("BGP : sécuriser les sessions et les annonces (RPKI, maximum-prefix, GTSM, RTBH)",
           en="BGP: securing sessions and announcements (RPKI, maximum-prefix, GTSM, RTBH)")
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

# interfaces of every machine in ethN order: the network (collision domain) of each
MACHINE_IFACES = {
    'rov_r1': ['rov_l1', 'rov_l2', 'rov_l3', 'rov_mgmt'],
    'rov_isp1': ['rov_l1'],
    'rov_isp2': ['rov_l2'],
    'rov_peer': ['rov_l3', 'rov_mgmt'],
    'rov_rpki': ['rov_mgmt'],
    'pfx_r1': ['pfx_l1', 'pfx_l2', 'pfx_l3'],
    'pfx_isp': ['pfx_l1'],
    'pfx_c1': ['pfx_l2'],
    'pfx_c2': ['pfx_l3'],
    'gtsm_r1': ['gtsm_l1', 'gtsm_l2'],
    'gtsm_isp': ['gtsm_l1'],
    'gtsm_mid': ['gtsm_l2', 'gtsm_l3'],
    'gtsm_par': ['gtsm_l3'],
    'bh_r1': ['bh_l1', 'bh_l2'],
    'bh_isp': ['bh_l1'],
    'bh_cust': ['bh_l2', 'bh_lan'],
    'bh_srv': ['bh_lan'],
    'bfd_r1': ['bfd_l1s', 'bfd_l2'],
    'bfd_isp1': ['bfd_ls1'],
    'bfd_isp2': ['bfd_l2'],
    'bfd_sw': ['bfd_l1s', 'bfd_ls1'],
}
MACHINES = list(MACHINE_IFACES)
# machines without FRR: the validator (stayrtr), a plain router, a host, a bridge
NO_FRR = ('rov_rpki', 'gtsm_mid', 'bh_srv', 'bfd_sw')
FRR_ROUTERS = [m for m in MACHINES if m not in NO_FRR]
STUDENT_ROUTERS = ('rov_r1', 'pfx_r1', 'gtsm_r1', 'bh_r1', 'bfd_r1')
# the students have a terminal on their routers and on the validator only
TERMINALS = STUDENT_ROUTERS + ('rov_rpki', 'bfd_isp1')
BRIDGE = 'bfd_sw'

# point-to-point links (/30): the first machine gets .1, the second .2
LINKS = {
    'rov_l1': ('rov_r1', 'rov_isp1'), 'rov_l2': ('rov_r1', 'rov_isp2'), 'rov_l3': ('rov_r1', 'rov_peer'),
    'pfx_l1': ('pfx_r1', 'pfx_isp'), 'pfx_l2': ('pfx_r1', 'pfx_c1'), 'pfx_l3': ('pfx_r1', 'pfx_c2'),
    'gtsm_l1': ('gtsm_r1', 'gtsm_isp'), 'gtsm_l2': ('gtsm_r1', 'gtsm_mid'), 'gtsm_l3': ('gtsm_mid', 'gtsm_par'),
    'bh_l1': ('bh_r1', 'bh_isp'), 'bh_l2': ('bh_r1', 'bh_cust'),
    'bfd_l1': ('bfd_r1', 'bfd_isp1'), 'bfd_l2': ('bfd_r1', 'bfd_isp2'),
}
# the IP link bfd_l1 is made of two collision domains joined by the bridge bfd_sw
COLLISION_DOMAINS = {'bfd_l1s': 'bfd_l1', 'bfd_ls1': 'bfd_l1'}

_TOPOLOGY: Dict[str, Dict[str, int]] = {}
for _m, _nets in MACHINE_IFACES.items():
    for _i, _n in enumerate(_nets):
        _TOPOLOGY.setdefault(_n, {})[_m] = _i

SITE_COLORS = {'rov': 'lightblue', 'pfx': 'palegreen', 'gtsm': 'khaki', 'bh': 'lightsalmon', 'bfd': 'lightgrey'}
SITE_NUMBER = {'rov': 1, 'pfx': 2, 'gtsm': 3, 'bh': 4, 'bfd': 5}
LOOPBACK_OCTET = 15

# AS numbers of the routers the lab configures (the students' AS, Data.our_as, is random)
EXT_AS = {'rov_isp1': 65010, 'rov_isp2': 65020, 'rov_peer': 65030,
          'pfx_isp': 65040, 'pfx_c1': 65041, 'pfx_c2': 65042,
          'gtsm_isp': 65050, 'gtsm_par': 65051,
          'bh_isp': 65060, 'bh_cust': 65061,
          'bfd_isp1': 65070, 'bfd_isp2': 65071}

# public prefixes (a random /16 of 172.16.0.0/12 per instance): (third octet, prefix length)
PUB = {
    'rov_own': (16, 22), 'rov_te': (17, 24),           # the students' block and its /24 (traffic engineering)
    'rov_v1': (20, 24), 'rov_n1': (21, 24),            # rov_isp1: a valid prefix, a prefix without ROA
    'rov_h': (22, 24),                                 # owned by AS 65020, also announced by rov_isp1 (hijack)
    'rov_m': (24, 22), 'rov_m24': (25, 24),            # owned by AS 65020 (ROA /22); rov_isp1 announces the /24
    'rov_v2': (28, 24), 'rov_p': (29, 24),             # rov_isp2's other prefix, rov_peer's prefix
    'pfx_own': (32, 22), 'pfx_c1a': (36, 24), 'pfx_c1b': (37, 24), 'pfx_c1c': (38, 24), 'pfx_c1d': (39, 24),
    'pfx_c2a': (40, 24), 'pfx_c2b': (41, 24), 'pfx_isp': (44, 24),
    'gtsm_own': (48, 22), 'gtsm_isp': (52, 24), 'gtsm_par': (53, 24),
    'bh_own': (64, 22), 'bh_cust': (68, 24), 'bh_isp': (72, 24),
    'bfd_own': (80, 22), 'bfd_svc': (84, 24),
}
PFX_C1 = ('pfx_c1a', 'pfx_c1b', 'pfx_c1c', 'pfx_c1d')
PFX_C2 = ('pfx_c2a', 'pfx_c2b')
LEAK_COUNT = 40          # pfx_c2 leaks these /24 (third octets 128 to 167 of the public /16)
LEAK_FIRST = 128

RTR_PORT = 3323
ROA_FILE = "/etc/stayrtr/roas.json"
STAYRTR_LOG = "/var/log/stayrtr.log"
STAYRTR_REFRESH = 10     # s: how often stayrtr reads the file again
VALID_LOCAL_PREF = 200
DISCARD_IFACE = "discard0"
DISCARD_NET = IPv4Interface("192.0.2.1/30")     # address of bh_r1's discard interface (TEST-NET-1)
DISCARD_NEXT_HOP = IPv4Address("192.0.2.2")     # "behind" discard0: a packet routed there disappears
BLACKHOLE_COMMUNITY = "65535:666"

PFX_LIMITS = (10, 12, 15, 20)
PFX_THRESHOLDS = (80, 85, 90)    # never 75: FRR's default (not shown in the configuration)
BFD_PROFILE = "FAST"
BFD_INTERVALS = (100, 150, 200)
BFD_MULTIPLIERS = (3, 4)
# the failover measure of each evaluation: bfd_r1 pings the service every PING_INTERVAL s while the
# bridge drops everything during CUT_SECONDS; the outage must stay under MAX_OUTAGE s
CUT_SECONDS = 6
PING_INTERVAL = 0.05
PING_COUNT = int((CUT_SECONDS + 2) / PING_INTERVAL)
MAX_OUTAGE = 3.0
CUT_TABLE = "table bridge cut { chain c { type filter hook forward priority 0; policy drop; }; }"
UNCUT_CMD = "nft delete table bridge cut 2>/dev/null; true"
CONNECT_RETRY = 10       # s: `timers connect` of the routers of the lab (FRR's default: 120)
CONVERGE_WAIT = 15
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : bgpd{rpki}{bfd} activé
bgpd=yes
ospfd=no
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
bfdd={bfdd}
fabricd=no
vrrpd=no
pathd=no

vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1{module}"
staticd_options="-A 127.0.0.1"
bfdd_options="   -A 127.0.0.1"
"""
FRR_VTYSH_CONF = "service integrated-vtysh-config\n"
RPKI_ROUTERS = ('rov_r1', 'rov_peer')


def site_of(machine: str) -> str:
    return machine.split('_', 1)[0]


def iface(machine: str, net: str) -> str:
    """Name of the interface of *machine* on *net* (``eth1``)."""
    return f"eth{MACHINE_IFACES[machine].index(net)}"


def _subnet(block: IPv4Network, third: int, prefixlen: int = 24) -> IPv4Network:
    return IPv4Network((int(block.network_address) + (third << 8), prefixlen))


def leaked_prefixes(pub: IPv4Network) -> List[IPv4Network]:
    """The /24 that pfx_c2 leaks."""
    return [_subnet(pub, LEAK_FIRST + i) for i in range(LEAK_COUNT)]


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    our_as: int = 0            # the students' AS (all their routers)
    pfx_limit: int = 0         # part 2: maximum-prefix of each customer
    pfx_threshold: int = 0     # part 2: warning threshold (%)
    bfd_interval: int = 0      # bonus: BFD transmit / receive interval (ms)
    bfd_multiplier: int = 0    # bonus: BFD detect multiplier

    @classmethod
    def generate(cls):
        data = cls()
        data.our_as = random.randint(64600, 64999)
        data.pfx_limit = random.choice(PFX_LIMITS)
        data.pfx_threshold = random.choice(PFX_THRESHOLDS)
        data.bfd_interval = random.choice(BFD_INTERVALS)
        data.bfd_multiplier = random.choice(BFD_MULTIPLIERS)

        data.nets.instance = random_ipv4networks(16, from_network=IPv4Network('10.0.0.0/8'))[0]
        data.nets.pub = random_ipv4networks(16, from_network=IPv4Network('172.16.0.0/12'))[0]
        for site, number in SITE_NUMBER.items():
            base = 16 * number
            links = [n for n in LINKS if site_of(n) == site]
            for k, net in enumerate(links):
                block = _subnet(data.nets.instance, base)
                setattr(data.nets, net, IPv4Network((int(block.network_address) + 4 * k, 30)))
            setattr(data.nets, f"{site}_lo", _subnet(data.nets.instance, base + LOOPBACK_OCTET))
        data.nets.rov_mgmt = _subnet(data.nets.instance, 16 * SITE_NUMBER['rov'] + 1)
        for name, (third, plen) in PUB.items():
            setattr(data.nets, name, _subnet(data.nets.pub, third, plen))
        for net, (first, second) in LINKS.items():
            network = getattr(data.nets, net)
            setattr(data.ips, f"{first}_{net}", IPv4Interface((int(network.network_address) + 1, 30)))
            setattr(data.ips, f"{second}_{net}", IPv4Interface((int(network.network_address) + 2, 30)))
        mgmt = int(data.nets.rov_mgmt.network_address)
        data.ips.rov_r1_rov_mgmt = IPv4Interface((mgmt + 1, 24))
        data.ips.rov_peer_rov_mgmt = IPv4Interface((mgmt + 2, 24))
        data.ips.rov_rpki_rov_mgmt = IPv4Interface((mgmt + 10, 24))
        lan = int(data.nets.bh_cust.network_address)
        data.ips.bh_cust_bh_lan = IPv4Interface((lan + 1, 24))
        data.ips.bh_srv_victim = IPv4Interface((lan + random.randint(20, 99), 24))
        data.ips.bh_srv_control = IPv4Interface((lan + random.randint(150, 250), 24))
        for site in SITE_NUMBER:
            block = getattr(data.nets, f"{site}_lo")
            routers = [m for m in FRR_ROUTERS + ['gtsm_mid'] if site_of(m) == site]
            for k, router in enumerate(routers):
                setattr(data.ips, f"{router}_lo", IPv4Interface((int(block.network_address) + k + 1, 32)))
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


def _machine_spec(machine: str) -> dict:
    spec = {'color': SITE_COLORS[site_of(machine)]}
    if machine in FRR_ROUTERS or machine in ('rov_rpki', 'gtsm_mid'):
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
            if m == 'bh_srv':
                self.net_config[m] = [([d.ips.bh_srv_victim, d.ips.bh_srv_control],
                                       [(default, self.addr('bh_cust', 'bh_lan'))])]
            elif m == BRIDGE:
                self.net_config[m] = [([], []) for _n in nets]
            else:
                self.net_config[m] = [([self.iface_addr(m, n)], []) for n in nets]
        # gtsm_mid (no FRR) routes between the loopbacks of gtsm_r1 and gtsm_par
        self.net_config['gtsm_mid'][0][1].append((IPv4Network(f"{self.lo('gtsm_r1')}/32"),
                                                  self.addr('gtsm_r1', 'gtsm_l2')))
        self.net_config['gtsm_mid'][1][1].append((IPv4Network(f"{self.lo('gtsm_par')}/32"),
                                                  self.addr('gtsm_par', 'gtsm_l3')))

        # /etc/hosts: every interface gets rX-ethN, the first one also rX; loopbacks rX-lo
        lines = []
        for m, nets in MACHINE_IFACES.items():
            if m in (BRIDGE, 'bh_srv'):
                continue
            for i, n in enumerate(nets):
                names = f"{m}-eth{i}" if i else f"{m}\t{m}-eth{i}"
                lines.append(f"{self.addr(m, n)}\t{names}")
            if m in FRR_ROUTERS or m == 'gtsm_mid':
                lines.append(f"{self.lo(m)}\t{m}-lo")
        lines.append(f"{d.ips.bh_srv_victim.ip}\tbh_srv victim")
        lines.append(f"{d.ips.bh_srv_control.ip}\tbh_srv-control")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = self._informations()

    # -- addresses and names -------------------------------------------------------

    def iface_addr(self, machine: str, net: str) -> IPv4Interface:
        """Address with prefix of *machine* on the network (or collision domain) *net*."""
        return getattr(self.data.ips, f"{machine}_{COLLISION_DOMAINS.get(net, net)}")

    def addr(self, machine: str, net: str) -> IPv4Address:
        """Address (without prefix) of *machine* on *net*."""
        return self.iface_addr(machine, net).ip

    def lo(self, router: str) -> IPv4Address:
        return getattr(self.data.ips, f"{router}_lo").ip

    def net(self, name: str) -> IPv4Network:
        return getattr(self.data.nets, name)

    def host(self, name: str, n: int = 1) -> IPv4Address:
        """Address number *n* of the network *name* (``host('bfd_svc')`` = the service address)."""
        return self.net(name).network_address + n

    def as_of(self, router: str) -> int:
        return self.data.our_as if router in STUDENT_ROUTERS else EXT_AS[router]

    def rpki_addr(self) -> IPv4Address:
        return self.addr('rov_rpki', 'rov_mgmt')

    # -- course ------------------------------------------------------------------

    def _informations(self):
        return (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Menaces sur le routage inter-domaine"), tag="threats")
            + tr("""
BGP (RFC 4271) a été conçu à une époque où les opérateurs se faisaient confiance : un routeur
**croit** ce que lui annoncent ses pairs. Rien dans le protocole ne vérifie qu'un AS a le droit
d'annoncer un préfixe, ni que le chemin annoncé existe. Les incidents les plus courants :

| incident | ce qui se passe | exemples |
|----------|-----------------|----------|
| **fuite de routes** (*route leak*, RFC 7908) | un AS réannonce des routes qu'il n'aurait pas dû propager (les routes d'un fournisseur à un autre fournisseur, une table complète vers ses fournisseurs) et attire un trafic qu'il ne peut pas acheminer | AS 7007 (1997), Verizon / Cloudflare (2019) |
| **détournement** (*hijack*) | un AS annonce un préfixe qui ne lui appartient pas, par erreur ou pour capter le trafic | Pakistan Telecom / YouTube (2008) |
| **détournement de sous-préfixe** | l'annonce d'un préfixe **plus spécifique** que celui du propriétaire : la plus longue correspondance l'emporte partout | Amazon Route 53 / MyEtherWallet (2018) |
| **attaque de la session** | segments TCP forgés (RST, SYN) visant le port 179 d'un routeur pour couper ou saturer ses sessions | — |
| **déni de service** | un afflux de trafic vers une adresse qui sature les liens de son réseau et de ses fournisseurs | — |

Les protections de ce TP se complètent ; elles font partie des actions recommandées par
[MANRS](https://www.manrs.org) (*Mutually Agreed Norms for Routing Security*) :

- **filtrer** ce que l'on accepte : listes de préfixes construites à partir des bases de routage
  (IRR), **validation de l'origine par RPKI** (section @@ref:rpki@@), limite du nombre de préfixes
  (section @@ref:maxprefix@@) ;
- **protéger les sessions** : GTSM (section @@ref:gtsm@@), authentification TCP, détection rapide des
  pannes (BFD, section @@ref:bfd@@) ;
- **coopérer** contre les attaques : le *blackholing* à distance (section @@ref:rtbh@@).
""")
            + info_subtitle(tr("RPKI et validation de l'origine"), tag="rpki")
            + tr("""
La **RPKI** (*Resource Public Key Infrastructure*, RFC 6480) est une infrastructure de certificats
qui suit l'attribution des ressources Internet : les cinq **RIR** (RIPE NCC, ARIN, APNIC, LACNIC,
AFRINIC) sont les autorités racines (*trust anchors*) et certifient les blocs d'adresses et les
numéros d'AS qu'ils attribuent. Le titulaire d'un bloc signe des **ROA** (*Route Origin
Authorization*, RFC 6482) :

| champ d'une ROA | rôle |
|-----------------|------|
| préfixe | le bloc concerné, par exemple `198.51.100.0/22` |
| `maxLength` | la longueur maximale des préfixes annonçables (`22` : seul le /22 ; `24` : le /22 et tous ses /23 et /24) |
| AS d'origine | le seul AS autorisé à **originer** ces préfixes |

### @@sec:validator@@ Du dépôt au routeur

Les routeurs ne vérifient pas eux-mêmes les signatures : un **validateur** (*relying party* :
rpki-client, Routinator, FORT…) télécharge les dépôts RPKI, vérifie toute la chaîne de certificats
et en tire la liste des **VRP** (*Validated ROA Payloads* : préfixe, longueur maximale, AS). Un
**cache** la sert aux routeurs par le protocole **RPKI-RTR** (RFC 8210) sur TCP : port **323**
officiellement, souvent **3323** ou **8282** pour ne pas lancer le serveur en root. Le cache prévient
les routeurs (*Serial Notify*) dès que la liste change.

Dans ce TP, `rov_rpki` fait tourner **stayrtr** (un serveur RTR) qui sert directement le fichier
`{roa_file}` : ce fichier tient lieu de la RPKI mondiale (les machines n'ont pas accès à l'Internet).
Une ROA y est un objet `"prefix"` / `"maxLength"` / `"asn"` de la liste `"roas"` ; stayrtr relit le
fichier toutes les {refresh} s et garde l'ancienne liste si le fichier n'est plus du JSON valide
(`{log}` le signale).

### @@sec:rov@@ La validation de l'origine (ROV)

Pour chaque route reçue, le routeur compare le préfixe et l'**AS d'origine** (le dernier AS de
l'AS_PATH) aux VRP (RFC 6811) :

| état | condition |
|------|-----------|
| **valid** | une VRP couvre le préfixe, avec cet AS d'origine et une longueur maximale ≥ la longueur du préfixe |
| **invalid** | une VRP au moins couvre le préfixe, mais aucune ne correspond (mauvais AS, ou préfixe trop long) |
| **notfound** | aucune VRP ne couvre le préfixe (son titulaire n'a pas signé de ROA) |

La politique recommandée (RFC 8893, MANRS) est de **rejeter les routes invalides** et de garder les
autres : une grande partie de l'espace d'adressage n'a pas encore de ROA, rejeter les routes
*notfound* couperait l'Internet. Certains opérateurs préfèrent en plus les routes valides.

- Une ROA trop large (`maxLength` supérieur à ce qui est réellement annoncé) laisse la place à un
  détournement de sous-préfixe avec l'origine légitime ; une ROA trop étroite rend **invalides** les
  préfixes plus spécifiques que l'on annonce (ingénierie de trafic). La RFC 9319 recommande de ne
  signer que les longueurs réellement annoncées.
- La ROV ne vérifie **que l'origine** : un AS qui forge un chemin se terminant par l'AS légitime
  (`… 64500 65020`) passe la validation. ASPA (vérification des relations entre AS) et BGPsec
  (chemins signés) traitent ce point.

### @@sec:rpki-frr@@ RPKI avec FRR

`bgpd` doit être lancé avec le module RPKI (`-M rpki` dans `/etc/frr/daemons`, déjà fait sur les
routeurs concernés). Le module récupère les VRP du cache ; une **route-map** décide de leur usage :

```
rpki
 rpki cache tcp 192.0.2.10 3323 preference 1   ! le cache (plusieurs : la plus petite préférence d'abord)
exit
route-map ROV deny 10
 match rpki invalid
exit
route-map ROV permit 20
 match rpki valid
 set local-preference 200
exit
route-map ROV permit 30
exit
router bgp 64512
 address-family ipv4 unicast
  neighbor 198.51.100.1 soft-reconfiguration inbound
  neighbor 198.51.100.1 route-map ROV in
```

- `show rpki cache-connection`, `show rpki cache-server` : l'état de la connexion au cache ;
  `show rpki prefix-table` : les VRP reçues ; `show rpki prefix P [AS]` : les VRP qui couvrent un
  préfixe.
- `show bgp ipv4 unicast` marque chaque route `V` (valid), `I` (invalid) ou `N` (notfound) ;
  `show bgp ipv4 unicast P` affiche `rpki validation-state` ; `show bgp ipv4 unicast rpki invalid`
  liste les routes invalides.
- Sans connexion au cache, toutes les routes sont `notfound`. Après un échec de connexion, FRR ne
  réessaie qu'au bout de 10 min (`retry_interval`) : `rpki reset` relance la connexion.
- Quand une VRP change, FRR revalide les routes ; pour réappliquer la route-map d'entrée aux routes
  déjà reçues il lui faut leur copie (`soft-reconfiguration inbound`). Une route **déjà rejetée**
  par `match rpki invalid` ne revient pas d'elle-même quand sa ROA est corrigée : le routeur qui
  l'a rejetée doit la redemander à son pair (`clear bgp A.B.C.D soft in`).
""").format(roa_file=ROA_FILE, refresh=STAYRTR_REFRESH, log=STAYRTR_LOG)
            + info_subtitle(tr("Limiter le nombre de préfixes"), tag="maxprefix")
            + tr("""
Le premier filtre d'une session avec un client est une **liste de préfixes** précise (ses blocs,
tirés des bases de routage IRR avec un outil comme `bgpq4`). En complément, **`maximum-prefix`**
fixe le nombre maximal de préfixes acceptés d'un pair : c'est le filet de sécurité contre une fuite
massive (un client qui réannonce une table complète, un pair qui se trompe de filtre). Les valeurs
publiées dans PeeringDB par les opérateurs servent souvent de référence.

```
router bgp 64512
 address-family ipv4 unicast
  neighbor 203.0.113.2 maximum-prefix 100              ! au-delà de 100 : la session est fermée
  neighbor 203.0.113.2 maximum-prefix 100 80           ! alerte dans le journal à 80 % de la limite
  neighbor 203.0.113.2 maximum-prefix 100 warning-only ! alerte seulement, rien n'est coupé
  neighbor 203.0.113.2 maximum-prefix 100 restart 30   ! rétablissement automatique après 30 min
```

- La limite compte les préfixes **acceptés** (après la route-map d'entrée). Le seuil d'alerte vaut
  75 % par défaut.
- Quand la limite est dépassée, le routeur envoie un `NOTIFICATION` (*Cease / Maximum Number of
  Prefixes Reached*) et ferme la session, qui reste fermée : `show bgp summary` affiche
  **`Idle (PfxCt)`**, le journal (`/var/log/frr/frr.log`) un message `%MAXPFXEXCEED` avec le nombre de
  préfixes reçus. Elle ne se rétablit qu'avec `clear bgp A.B.C.D` (une fois le pair corrigé), ou
  automatiquement avec `restart`.
- `neighbor X maximum-prefix-out N` limite dans l'autre sens ce que l'on annonce à un pair.
""")
            + info_subtitle(tr("GTSM : protéger les sessions"), tag="gtsm")
            + tr("""
Une session BGP est une connexion TCP : un attaquant qui connaît les adresses des deux routeurs peut
forger des segments (RST pour la couper, SYN en masse pour saturer le processeur du routeur) depuis
n'importe où dans l'Internet. Le **GTSM** (*Generalized TTL Security Mechanism*, RFC 5082) s'appuie
sur un fait simple : chaque routeur traversé décrémente le TTL, et personne ne peut envoyer un paquet
avec un TTL supérieur à 255.

- Les deux pairs émettent leurs paquets BGP avec un **TTL de 255** (au lieu de 1 en eBGP par
  défaut) ;
- chacun **rejette** les paquets reçus dont le TTL est inférieur à **256 − N**, N étant le nombre de
  sauts configuré : un pair directement connecté (`hops 1`) doit arriver avec un TTL de 255, un pair
  à deux sauts (`hops 2`) avec 254 au moins. Un paquet forgé à plusieurs sauts de là arrive avec un
  TTL trop petit et le noyau le jette avant même TCP (option de socket `IP_MINTTL`).

```
router bgp 64512
 neighbor 198.51.100.1 ttl-security hops 1          ! pair directement connecté
 neighbor 192.0.2.7 ttl-security hops 2             ! pair à deux sauts (entre loopbacks)
```

- `ttl-security` et `ebgp-multihop` sont **incompatibles** (FRR refuse : *ebgp-multihop and
  ttl-security cannot be configured together*) : `ttl-security hops N` remplace `ebgp-multihop`.
- Les **deux côtés** doivent l'activer : le côté qui l'exige rejette les paquets émis avec un TTL de
  1 (ou celui d'`ebgp-multihop`) par l'autre ; la session ne s'établit pas (`Active` ou `Idle`).
- Un routeur qui a échoué réessaie d'ouvrir la session toutes les 120 s par défaut (`neighbor X timers
  connect N`) ; `clear bgp A.B.C.D` relance une tentative aussitôt.
- GTSM se combine avec l'authentification de la session : TCP MD5 (`neighbor X password`, RFC 2385)
  ou, plus récent, TCP-AO (RFC 5925).
""")
            + info_subtitle(tr("RTBH : le blackholing déclenché à distance"), tag="rtbh")
            + tr("""
Face à une attaque par déni de service, un client voit ses liens saturés par un trafic qu'il ne
peut pas filtrer lui-même : il est déjà arrivé. Le **RTBH** (*Remotely Triggered Black Hole*,
RFC 5635) lui permet de demander à son fournisseur de **jeter, à l'entrée de son réseau, tout le
trafic à destination de l'adresse attaquée** : le reste de ses services est sauvé, au prix de
l'adresse attaquée elle-même.

- Le client annonce la route de l'adresse attaquée (un /32) avec la communauté bien connue
  **BLACKHOLE**, **65535:666** (RFC 7999 ; `blackhole` dans FRR).
- Le fournisseur accepte ces /32 **seulement dans l'espace d'adresses du client** (sinon un client
  pourrait faire disparaître l'adresse de n'importe qui) et seulement avec la communauté ; il change
  leur prochain saut pour une adresse « poubelle » et ne les annonce pas plus loin (`no-export`).
- Le noyau Linux jette ce qui est routé vers une interface factice (`dummy`) : une adresse du réseau
  d'une telle interface sert de prochain saut poubelle (l'équivalent de `Null0` des équipements
  dédiés). Avec FRR, le prochain saut doit être dans ce réseau connecté : une route BGP dont le
  prochain saut est résolu par une route `blackhole` statique reste **inactive** (zebra ne
  l'installe pas, le trafic suit alors la route du préfixe plus large).

```
bgp community-list standard BLACKHOLE seq 5 permit blackhole
ip prefix-list CUST-HOSTS seq 5 permit 203.0.113.0/24 ge 32
route-map FROM-CUST permit 5
 match ip address prefix-list CUST-HOSTS
 match community BLACKHOLE
 set ip next-hop 192.0.2.2
 set community no-export additive
exit
```

- Deux clauses `match` dans une même séquence doivent être **toutes deux** vraies.
- FRR ajoute de lui-même `no-export` à une route reçue avec la communauté BLACKHOLE (`show bgp
  ipv4 unicast P` : *inform peer to blackhole prefix*), mais l'installe comme une route ordinaire : le
  rejet du trafic est l'affaire de la politique du routeur.
- Une modification d'une route-map déjà appliquée prend effet au bout de quelques secondes ;
  `clear bgp A.B.C.D soft in` la réapplique aussitôt.
- Variantes : RTBH sur la **source** (avec le contrôle uRPF), et **FlowSpec** (RFC 8955), qui
  diffuse des règles de filtrage plus fines (protocole, ports) au lieu d'une route.
""")
            + info_subtitle(tr("BFD : détecter vite une panne"), tag="bfd")
            + tr("""
BGP ne s'aperçoit d'une **panne silencieuse** (le lien reste actif mais ne transmet plus rien : un
commutateur intermédiaire en panne, un équipement de transmission) qu'à l'expiration du *hold time*,
**180 s** par défaut : pendant tout ce temps, le trafic part dans le vide. **BFD** (*Bidirectional
Forwarding Detection*, RFC 5880 et 5881) échange des paquets UDP très fréquents (port 3784) entre les
deux routeurs et prévient BGP dès que `detect-multiplier` paquets consécutifs manquent : temps de
détection = intervalle × multiplicateur (300 ms × 3 = 900 ms par défaut).

```
bfd
 profile FAST
  transmit-interval 100
  receive-interval 100
  detect-multiplier 3
 exit
exit
router bgp 64512
 neighbor 198.51.100.1 bfd profile FAST
```

`bfdd` doit être lancé (`bfdd=yes` dans `/etc/frr/daemons`). `show bfd peers` affiche les sessions
BFD, leur état et les intervalles négociés ; `show bgp neighbors A.B.C.D` la session BFD du pair. Quand
BFD tombe, BGP ferme la session et retire ses routes : le trafic bascule aussitôt sur un autre chemin.
BFD doit être activé **des deux côtés** : tant que sa session BFD n'est pas établie, FRR garde la
session BGP en `Idle`.
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
Les routeurs font tourner **FRRouting** ; on les configure avec `vtysh` (`configure terminal`,
`write` pour enregistrer dans `/etc/frr/frr.conf`, `no` devant une ligne pour la supprimer).

```
show bgp ipv4 unicast summary              # sessions, état (Established, Active, Idle (PfxCt)…), préfixes reçus
show bgp ipv4 unicast                      # table BGP, états RPKI (V/I/N), meilleur chemin (>)
show bgp ipv4 unicast P                    # détail d'un préfixe : chemins, communautés, état RPKI
show bgp neighbors A.B.C.D                 # détail d'une session : TTL, limites, BFD, dernière fermeture
show bgp ipv4 unicast neighbors A.B.C.D advertised-routes
show bgp ipv4 unicast neighbors A.B.C.D received-routes   # avec soft-reconfiguration inbound
show rpki cache-connection / prefix-table / prefix P
show bfd peers
clear bgp A.B.C.D [soft in|soft out]       # couper / réappliquer les politiques
show ip route                              # table de routage (B = BGP)
```

Documentation : [FRR — BGP](https://docs.frrouting.org/en/latest/bgp.html) (sections *RPKI*,
*Maximum-prefix*, *Communities*, *BFD*).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `ip route` sur un routeur : les routes BGP portent `proto bgp` ; `ip route get A` donne la route
  choisie pour une adresse ;
- `tcpdump -nvi ethX tcp port 179` : les messages BGP et leur **TTL** ; `tcpdump -ni ethX udp port
  3784` : BFD ;
- `/var/log/frr/frr.log` : ouvertures et fermetures des sessions, alertes de `maximum-prefix`.

| symptôme | causes à vérifier |
|----------|-------------------|
| `show rpki cache-connection` : pas de connexion | adresse ou port du cache, cache arrêté, échec ancien (`rpki reset`) |
| route invalide encore présente | route-map pas appliquée à ce pair, `match rpki` absent, revalidation sans `soft-reconfiguration inbound` (`clear bgp X soft in`) |
| route corrigée encore rejetée chez un pair | il doit la redemander (`clear bgp X soft in` de son côté) |
| session `Idle (PfxCt)` | limite `maximum-prefix` dépassée : corriger le pair puis `clear bgp X` |
| session `Active` ou `Idle` avec un pair qui exige GTSM | `ttl-security` absent ou mauvais nombre de sauts, `ebgp-multihop` resté configuré |
| route BGP présente mais trafic non jeté | prochain saut non résolu par un réseau connecté, route-map pas réappliquée |
""")
        )

    # -- configurations --------------------------------------------------------------

    def _bgp_block(self, router: str, neighbors: List[dict], networks=(), router_lines=(), af_lines=()) -> List[str]:
        """frr.conf lines of ``router bgp``: each neighbour is ``{'ip', 'as', 'desc', 'router': [...],
        'in': map, 'out': map, 'af': [...]}`` (the lists hold the words after ``neighbor IP``)."""
        lines = [f"router bgp {self.as_of(router)}", f" bgp router-id {self.lo(router)}"]
        lines += [f" {x}" for x in router_lines]
        for n in neighbors:
            lines.append(f" neighbor {n['ip']} remote-as {n['as']}")
            if n.get('desc'):
                lines.append(f" neighbor {n['ip']} description {n['desc']}")
            lines += [f" neighbor {n['ip']} {x}" for x in n.get('router', [])]
        lines.append(" address-family ipv4 unicast")
        lines += [f"  network {p}" for p in networks]
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

    def _given_lines(self, r: str) -> List[str]:
        """frr.conf lines of *r* at start (blackhole routes, filters, BGP, RPKI, BFD)."""
        d, net, addr = self.data, self.net, self.addr
        all_map = ["route-map ALL permit 10", "exit", "!"]
        retry = [f"timers connect {CONNECT_RETRY}"]
        lines: List[str] = []
        if r == 'rov_r1':
            lines += [f"ip route {net('rov_own')} blackhole", f"ip route {net('rov_te')} blackhole", "!",
                      f"ip prefix-list OWN seq 5 permit {net('rov_own')}",
                      f"ip prefix-list OWN seq 10 permit {net('rov_te')}", "!",
                      "route-map OWN permit 10", " match ip address prefix-list OWN", "exit", "!",
                      "route-map FROM-PROVIDER permit 10", "exit", "!"] + all_map
            lines += self._bgp_block(r, [
                self._peer(r, 'rov_isp1', 'rov_l1', 'ISP1', **{'in': 'FROM-PROVIDER', 'out': 'OWN'}),
                self._peer(r, 'rov_isp2', 'rov_l2', 'ISP2', **{'in': 'FROM-PROVIDER', 'out': 'OWN'}),
                self._peer(r, 'rov_peer', 'rov_l3', 'PEER', out='OWN')],
                networks=(net('rov_own'), net('rov_te')))
        elif r == 'rov_isp1':
            prefixes = [net(p) for p in ('rov_v1', 'rov_n1', 'rov_h', 'rov_m24')]
            lines += [f"ip route {p} blackhole" for p in prefixes] + ["!"]
            lines += [f"ip prefix-list FORGED seq 5 permit {net('rov_m24')}", "!",
                      "route-map OUT permit 10", " match ip address prefix-list FORGED",
                      f" set as-path prepend {EXT_AS['rov_isp2']}", "exit", "!",
                      "route-map OUT permit 20", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'rov_r1', 'rov_l1', 'CUSTOMER', out='OUT')], networks=prefixes)
        elif r == 'rov_isp2':
            prefixes = [net(p) for p in ('rov_h', 'rov_m', 'rov_v2')]
            own = EXT_AS['rov_isp2']
            lines += [f"ip route {p} blackhole" for p in prefixes] + ["!"]
            lines += ["route-map OUT permit 10", f" set as-path prepend {own} {own}", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'rov_r1', 'rov_l2', 'CUSTOMER', out='OUT')], networks=prefixes)
        elif r == 'rov_peer':
            lines += [f"ip route {net('rov_p')} blackhole", "!",
                      "route-map ROV deny 10", " match rpki invalid", "exit", "!",
                      "route-map ROV permit 20", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'rov_r1', 'rov_l3', 'PEER', **{
                'in': 'ROV', 'af': ['soft-reconfiguration inbound']})], networks=(net('rov_p'),))
            lines += ["rpki", f" rpki cache tcp {self.rpki_addr()} {RTR_PORT} preference 1", "exit", "!"]
        elif r == 'pfx_r1':
            lines += [f"ip route {net('pfx_own')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'pfx_isp', 'pfx_l1', 'ISP'),
                                         self._peer(r, 'pfx_c1', 'pfx_l2', 'CUSTOMER1'),
                                         self._peer(r, 'pfx_c2', 'pfx_l3', 'CUSTOMER2')],
                                     networks=(net('pfx_own'),))
        elif r == 'pfx_isp':
            lines += [f"ip route {net('pfx_isp')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'pfx_r1', 'pfx_l1', 'CUSTOMER', router=retry)],
                                     networks=(net('pfx_isp'),))
        elif r == 'pfx_c1':
            prefixes = [net(p) for p in PFX_C1]
            lines += [f"ip route {p} blackhole" for p in prefixes] + ["!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'pfx_r1', 'pfx_l2', 'PROVIDER', router=retry)],
                                     networks=prefixes)
        elif r == 'pfx_c2':
            # its two prefixes, and a table it should never have passed on (redistributed statics)
            prefixes = [net(p) for p in PFX_C2] + leaked_prefixes(net('pub'))
            lines += [f"ip route {p} blackhole" for p in prefixes] + ["!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'pfx_r1', 'pfx_l3', 'PROVIDER', router=retry)],
                                     af_lines=("redistribute static",))
        elif r == 'gtsm_r1':
            lines += [f"ip route {net('gtsm_own')} blackhole",
                      f"ip route {self.lo('gtsm_par')}/32 {addr('gtsm_mid', 'gtsm_l2')}", "!"] + all_map
            lines += self._bgp_block(r, [
                self._peer(r, 'gtsm_isp', 'gtsm_l1', 'ISP'),
                {'ip': self.lo('gtsm_par'), 'as': EXT_AS['gtsm_par'], 'desc': 'PARTNER', 'in': 'ALL', 'out': 'ALL',
                 'router': ['update-source lo', 'ebgp-multihop 2']}], networks=(net('gtsm_own'),))
        elif r == 'gtsm_isp':
            lines += [f"ip route {net('gtsm_isp')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'gtsm_r1', 'gtsm_l1', 'CUSTOMER',
                                                    router=retry + ['ttl-security hops 1'])],
                                     networks=(net('gtsm_isp'),))
        elif r == 'gtsm_par':
            lines += [f"ip route {net('gtsm_par')} blackhole",
                      f"ip route {self.lo('gtsm_r1')}/32 {addr('gtsm_mid', 'gtsm_l3')}", "!"] + all_map
            lines += self._bgp_block(r, [{'ip': self.lo('gtsm_r1'), 'as': d.our_as, 'desc': 'PARTNER', 'in': 'ALL',
                                          'out': 'ALL', 'router': retry + ['update-source lo', 'ttl-security hops 2']}],
                                     networks=(net('gtsm_par'),))
        elif r == 'bh_r1':
            lines += [f"ip route {net('bh_own')} blackhole", "!",
                      f"ip prefix-list CUSTOMER seq 5 permit {net('bh_cust')}", "!",
                      "route-map FROM-CUSTOMER permit 10", " match ip address prefix-list CUSTOMER", "exit", "!"]
            lines += all_map
            lines += self._bgp_block(r, [self._peer(r, 'bh_isp', 'bh_l1', 'ISP'),
                                         self._peer(r, 'bh_cust', 'bh_l2', 'CUSTOMER', **{
                                             'in': 'FROM-CUSTOMER', 'af': ['default-originate']})],
                                     networks=(net('bh_own'),))
        elif r == 'bh_isp':
            lines += [f"ip route {net('bh_isp')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'bh_r1', 'bh_l1', 'CUSTOMER', router=retry)],
                                     networks=(net('bh_isp'),))
        elif r == 'bh_cust':
            victim, bogus = self.data.ips.bh_srv_victim.ip, self.host('bh_isp')
            lines += [f"ip route {victim}/32 {iface('bh_cust', 'bh_lan')}",
                      f"ip route {bogus}/32 {addr('bh_r1', 'bh_l2')}", "!",
                      f"ip prefix-list RTBH seq 5 permit {victim}/32",
                      f"ip prefix-list RTBH seq 10 permit {bogus}/32", "!",
                      "route-map TO-PROVIDER permit 10", " match ip address prefix-list RTBH",
                      " set community blackhole", "exit", "!",
                      "route-map TO-PROVIDER permit 20", "exit", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'bh_r1', 'bh_l2', 'PROVIDER', router=retry, out='TO-PROVIDER')],
                                     networks=(net('bh_cust'), f"{victim}/32", f"{bogus}/32"))
        elif r == 'bfd_r1':
            lines += [f"ip route {net('bfd_own')} blackhole", "!",
                      "route-map FROM-ISP1 permit 10", f" set local-preference {VALID_LOCAL_PREF}", "exit", "!"]
            lines += all_map
            lines += self._bgp_block(r, [self._peer(r, 'bfd_isp1', 'bfd_l1', 'ISP1', router=retry, **{
                                             'in': 'FROM-ISP1'}),
                                         self._peer(r, 'bfd_isp2', 'bfd_l2', 'ISP2')], networks=(net('bfd_own'),))
        elif r == 'bfd_isp1':
            lines += [f"ip route {net('bfd_svc')} blackhole", "!"] + all_map
            lines += ["bfd", f" profile {BFD_PROFILE}", f"  transmit-interval {d.bfd_interval}",
                      f"  receive-interval {d.bfd_interval}", f"  detect-multiplier {d.bfd_multiplier}", " exit",
                      "exit", "!"]
            lines += self._bgp_block(r, [self._peer(r, 'bfd_r1', 'bfd_l1', 'CUSTOMER', router=retry)],
                                     networks=(net('bfd_svc'),))
        elif r == 'bfd_isp2':
            lines += [f"ip route {net('bfd_svc')} blackhole", "!"] + all_map
            lines += self._bgp_block(r, [self._peer(r, 'bfd_r1', 'bfd_l2', 'CUSTOMER', router=retry)],
                                     networks=(net('bfd_svc'),))
        return lines

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf of *router*."""
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "frr defaults traditional", f"hostname {router}", "log file /var/log/frr/frr.log", "!"]
        return "\n".join(lines + self._given_lines(router)) + "\n"

    def _daemons(self, router: str) -> str:
        rpki, bfd = router in RPKI_ROUTERS, site_of(router) == 'bfd'
        return FRR_DAEMONS.format(rpki=" (module RPKI)" if rpki else "", bfd=" et bfdd" if bfd else "",
                                  bfdd="yes" if bfd else "no", module=" -M rpki" if rpki else "")

    def roas(self, fixed: bool = False) -> List[dict]:
        """The ROAs of the validator's file: the students' /22 is signed with maxLength 22 (the
        mistake of part 1) or, *fixed*, 24 (its /24 of traffic engineering becomes valid)."""
        d, net = self.data, self.net
        return [
            {"prefix": str(net('rov_v1')), "maxLength": 24, "asn": EXT_AS['rov_isp1']},
            {"prefix": str(net('rov_h')), "maxLength": 24, "asn": EXT_AS['rov_isp2']},
            {"prefix": str(net('rov_m')), "maxLength": 22, "asn": EXT_AS['rov_isp2']},
            {"prefix": str(net('rov_v2')), "maxLength": 24, "asn": EXT_AS['rov_isp2']},
            {"prefix": str(net('rov_own')), "maxLength": 24 if fixed else 22, "asn": d.our_as},
        ]

    def roa_file(self, fixed: bool = False) -> str:
        roas = ",\n".join("    " + json.dumps(r) for r in self.roas(fixed))
        return "{\n  \"roas\": [\n" + roas + "\n  ]\n}\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1, allow_error: bool = False):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step, allow_error=allow_error)

    # -- reference solutions, one per part (texts shown by the instructor solutions) ------

    def solution_rov(self) -> Dict[str, List[str]]:
        d, addr = self.data, self.addr
        isp1, isp2 = addr('rov_isp1', 'rov_l1'), addr('rov_isp2', 'rov_l2')
        return {'rov_r1': [
            "rpki", f"rpki cache tcp {self.rpki_addr()} {RTR_PORT} preference 1", "exit",
            "route-map RPKI-IN deny 10", "match rpki invalid", "exit",
            "route-map RPKI-IN permit 20", "match rpki valid", f"set local-preference {VALID_LOCAL_PREF}", "exit",
            "route-map RPKI-IN permit 30", "exit",
            f"router bgp {d.our_as}", "address-family ipv4 unicast",
            f"neighbor {isp1} soft-reconfiguration inbound", f"neighbor {isp2} soft-reconfiguration inbound",
            f"neighbor {isp1} route-map RPKI-IN in", f"neighbor {isp2} route-map RPKI-IN in",
            "exit-address-family", "exit"]}

    def solution_pfx(self) -> Dict[str, List[str]]:
        d, addr = self.data, self.addr
        limit = f"maximum-prefix {d.pfx_limit} {d.pfx_threshold}"
        return {'pfx_r1': [f"router bgp {d.our_as}", "address-family ipv4 unicast",
                           f"neighbor {addr('pfx_c1', 'pfx_l2')} {limit}",
                           f"neighbor {addr('pfx_c2', 'pfx_l3')} {limit}", "exit-address-family", "exit"]}

    def solution_gtsm(self) -> Dict[str, List[str]]:
        d = self.data
        isp, par = self.addr('gtsm_isp', 'gtsm_l1'), self.lo('gtsm_par')
        return {'gtsm_r1': [f"router bgp {d.our_as}", f"neighbor {isp} ttl-security hops 1",
                            f"no neighbor {par} ebgp-multihop", f"neighbor {par} ttl-security hops 2", "exit"]}

    def solution_bh(self) -> Dict[str, List[str]]:
        return {'bh_r1': [
            "bgp community-list standard BLACKHOLE seq 5 permit blackhole",
            f"ip prefix-list CUSTOMER-HOSTS seq 5 permit {self.net('bh_cust')} ge 32",
            "route-map FROM-CUSTOMER permit 5", "match ip address prefix-list CUSTOMER-HOSTS",
            "match community BLACKHOLE", f"set ip next-hop {DISCARD_NEXT_HOP}", "set community no-export additive",
            "exit"]}

    def solution_bfd(self) -> Dict[str, List[str]]:
        d = self.data
        return {'bfd_r1': ["bfd", f"profile {BFD_PROFILE}", f"transmit-interval {d.bfd_interval}",
                           f"receive-interval {d.bfd_interval}", f"detect-multiplier {d.bfd_multiplier}", "exit",
                           "exit", f"router bgp {d.our_as}",
                           f"neighbor {self.addr('bfd_isp1', 'bfd_l1')} bfd profile {BFD_PROFILE}", "exit"],
                'bfd_isp1': [f"router bgp {EXT_AS['bfd_isp1']}",
                             f"neighbor {self.addr('bfd_r1', 'bfd_l1')} bfd profile {BFD_PROFILE}", "exit"]}

    # -- applying the solutions ----------------------------------------------------

    def _apply(self, solution: Dict[str, List[str]], step: int = 1):
        for r, cmds in solution.items():
            self._vtysh(r, *cmds, step=step)

    def _apply_rov(self):
        self._apply(self.solution_rov())
        self.file('rov_rpki', ROA_FILE, self.roa_file(fixed=True))
        # once the cache has served the corrected file: rov_peer asks for the routes it had rejected
        self.cmd('rov_r1', f"sleep {STAYRTR_REFRESH + 5}; vtysh -c 'clear bgp * soft in'", step=2,
                 timeout=STAYRTR_REFRESH + 30)
        self.cmd('rov_peer', f"sleep {STAYRTR_REFRESH + 5}; vtysh -c 'clear bgp * soft in'", step=2,
                 timeout=STAYRTR_REFRESH + 30)

    def _apply_gtsm(self):
        self._apply(self.solution_gtsm())
        # the providers wait in OpenSent on their own attempt (the OPEN of gtsm_r1, sent with a TTL of
        # 1, was dropped) and only accept a new connection after up to a minute: start again on both sides
        self.cmd('gtsm_r1', f"vtysh -c 'clear bgp {self.addr('gtsm_isp', 'gtsm_l1')}' "
                            f"-c 'clear bgp {self.lo('gtsm_par')}'", step=2)
        for r in ('gtsm_isp', 'gtsm_par'):
            self.cmd(r, "vtysh -c 'clear bgp *'", step=2)

    def _apply_bh(self):
        self._apply(self.solution_bh())
        self.cmd('bh_r1', f"vtysh -c 'clear bgp {self.addr('bh_cust', 'bh_l2')} soft in'", step=2)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in MACHINES:
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in FRR_ROUTERS or m == 'gtsm_mid'))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)
        for r in FRR_ROUTERS + ['gtsm_mid']:
            self.cmd(r, f"ip addr add {getattr(d.ips, f'{r}_lo')} dev lo")
        # the public addresses: the source of bfd_r1's pings, the service (both providers), the
        # address of bh_isp's network that bh_cust asks to blackhole
        self.cmd('bfd_r1', f"ip addr add {self.host('bfd_own')}/32 dev lo")
        for r in ('bfd_isp1', 'bfd_isp2'):
            self.cmd(r, f"ip addr add {self.host('bfd_svc')}/32 dev lo")
        self.cmd('bh_isp', f"ip addr add {self.host('bh_isp')}/32 dev lo")
        self.cmd('bh_r1', f"ip link add {DISCARD_IFACE} type dummy && ip addr add {DISCARD_NET} dev {DISCARD_IFACE}"
                          f" && ip link set {DISCARD_IFACE} up")
        self.cmd(BRIDGE, "ip link add br0 type bridge && ip link set eth0 master br0 && ip link set eth1 master br0"
                         " && ip link set br0 up")
        self.cmd(BRIDGE, UNCUT_CMD)
        # the validator first (step 1): a router whose first connection fails waits 10 minutes
        self.cmd('rov_rpki', "mkdir -p /etc/stayrtr")
        self.file('rov_rpki', ROA_FILE, self.roa_file())
        self.cmd('rov_rpki', f"cd /tmp && setsid -f stayrtr -bind :{RTR_PORT} -cache {ROA_FILE} -checktime=false "
                             f"-refresh {STAYRTR_REFRESH} -metrics.addr 127.0.0.1:9847 > {STAYRTR_LOG} 2>&1; "
                             f"for i in $(seq 40); do ss -ltn | grep -q ':{RTR_PORT} ' && break; sleep 0.25; done")
        for r in FRR_ROUTERS:
            self.file(r, "/etc/frr/daemons", self._daemons(r), permissions=0o640, owner="frr:frr", step=2)
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty", step=2)
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr", step=2)
            self.cmd(r, "systemctl start frr", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 1 : solution (RPKI)"))
    def solve_rov(self):
        self._apply_rov()

    @sre_state(user_allowed=False, description=tr("Partie 2 : solution (maximum-prefix)"))
    def solve_pfx(self):
        self._apply(self.solution_pfx())
        self.cmd('pfx_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False, description=tr("Partie 3 : solution (GTSM)"))
    def solve_gtsm(self):
        self._apply_gtsm()
        self.cmd('gtsm_r1', f"sleep {CONVERGE_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Partie 4 : solution (RTBH)"))
    def solve_bh(self):
        self._apply_bh()
        self.cmd('bh_r1', f"sleep {CONVERGE_WAIT}", step=3)

    @sre_state(user_allowed=False, description=tr("Bonus : solution (BFD)"))
    def solve_bfd(self):
        self._apply(self.solution_bfd())
        self.cmd('bfd_r1', f"sleep {CONVERGE_WAIT}", step=2)

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution of every part: every grade element is at its maximum when the state
        returns.  Form questions are filled through cheat_answers."""
        self._apply_rov()
        self._apply(self.solution_pfx())
        self._apply_gtsm()
        self._apply_bh()
        self._apply(self.solution_bfd())
        self.cmd('pfx_r1', f"sleep {CONVERGE_WAIT}", step=3)


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


_OPENERS = ("router ", "interface ", "route-map ", "address-family ", "profile ")


def _vtysh_text(solution: Dict[str, List[str]]) -> str:
    """The reference configuration of a part, as vtysh sessions (one block per router); the lines
    inside a block (``router``, ``route-map``, ``address-family``, ``rpki``, ``bfd``...) are indented."""
    blocks = []
    for router, cmds in solution.items():
        body, depth = ["configure terminal"], 1
        for c in cmds:
            if c in ("exit", "exit-address-family"):
                depth = max(1, depth - 1)
                body.append(" " * depth + c)
                continue
            body.append(" " * depth + c)
            if c.startswith(_OPENERS) or c in ("rpki", "bfd"):
                depth += 1
        blocks.append(f"`{router}` :\n\n```\n" + "\n".join(body + ["end", "write"]) + "\n```")
    return "\n\n".join(blocks)


def _running_config(grade: Grade0, router: str) -> Dict:
    """The parsed running configuration of *router*; the empty shape before the results (or when
    vtysh fails)."""
    return get_frr_running_config(grade, router, allow_error=True) or parse_frr_config("")


def _ping_outage(output: str, interval: float = PING_INTERVAL):
    """(replies, longest outage in s) of a ``ping -i`` output: the largest gap of icmp_seq."""
    seqs = sorted({int(n) for n in re.findall(r'icmp_seq=(\d+)', output or '')})
    if not seqs:
        return 0, None
    gaps = [b - a - 1 for a, b in zip(seqs, seqs[1:])]
    return len(seqs), max(gaps or [0]) * interval


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

        def peer_up(summary: Dict, peer) -> Dict:
            p = (summary.get('peers') or {}).get(str(peer)) or {}
            return p if p.get('established') else {}

        # ---------------- diagnostics kept in the archive -------------------------
        for r in STUDENT_ROUTERS:
            self.test(r, 'vtysh -c "show running-config"', allow_error=True)
        self.test('rov_rpki', f"cat {ROA_FILE}; tail -5 {STAYRTR_LOG}", allow_error=True)

        # ---------------- what the elements read ----------------------------------
        isp1, isp2 = addr('rov_isp1', 'rov_l1'), addr('rov_isp2', 'rov_l2')
        rov_cfg = _running_config(self, 'rov_r1')
        rov_conn = get_rpki_cache_connection(self, 'rov_r1')
        rov_vrps = get_rpki_prefix_table(self, 'rov_r1')
        rov_routes = get_bgp_routes(self, 'rov_r1', allow_error=True)
        rov_k = get_kernel_routes(self, 'rov_r1', allow_error=True)
        # rov_peer asks rov_r1 again for its routes (a route rejected as invalid never comes back
        # by itself once its ROA is fixed), then reads them at step 2
        self.test('rov_peer', "vtysh -c 'clear bgp * soft in'; sleep 2", allow_error=True)
        rov_peer_te = get_bgp_prefix(self, 'rov_peer', net('rov_te'), step=2, allow_error=True)
        rov_peer_own = get_bgp_prefix(self, 'rov_peer', net('rov_own'), step=2, allow_error=True)

        c1, c2 = addr('pfx_c1', 'pfx_l2'), addr('pfx_c2', 'pfx_l3')
        pfx_cfg = _running_config(self, 'pfx_r1')
        pfx_sum = get_bgp_summary(self, 'pfx_r1', allow_error=True)
        pfx_isp_routes = get_bgp_routes(self, 'pfx_isp', allow_error=True)

        gisp, gpar = addr('gtsm_isp', 'gtsm_l1'), lo('gtsm_par')
        gtsm_cfg = _running_config(self, 'gtsm_r1')
        gtsm_sum = get_bgp_summary(self, 'gtsm_r1', allow_error=True)
        gtsm_routes = get_bgp_routes(self, 'gtsm_r1', allow_error=True)

        victim, control, bogus = d.ips.bh_srv_victim.ip, d.ips.bh_srv_control.ip, host('bh_isp')
        bh_routes = get_bgp_routes(self, 'bh_r1', allow_error=True)
        # the whole table has no communities: the detail of the /32
        bh_victim = get_bgp_prefix(self, 'bh_r1', f"{victim}/32", allow_error=True)
        bh_k = get_kernel_routes(self, 'bh_r1', allow_error=True)
        bh_isp_routes = get_bgp_routes(self, 'bh_isp', allow_error=True)
        bh_ping_victim = self._ping('bh_isp', victim, source=bogus)
        bh_ping_control = self._ping('bh_isp', control, source=bogus)
        bh_ping_bogus = self._ping('bh_r1', bogus)

        bfd_isp1 = addr('bfd_isp1', 'bfd_l1')
        bfd_cfg = _running_config(self, 'bfd_r1')
        bfd_peers = get_bfd_peers(self, 'bfd_r1')
        # the failover measure: reset any cut left by an interrupted evaluation, then, at step 2,
        # bfd_r1 pings the service while the bridge drops everything for CUT_SECONDS
        self.test(BRIDGE, UNCUT_CMD, allow_error=True)
        self.test(BRIDGE, f"sleep 1; echo '{CUT_TABLE}' | nft -f - && sleep {CUT_SECONDS}; {UNCUT_CMD}",
                  step=2, timeout=CUT_SECONDS + 20, allow_error=True)
        bfd_ping_out, _code = self.test(
            'bfd_r1', f"ping -I {host('bfd_own')} -i {PING_INTERVAL} -c {PING_COUNT} -W 1 {host('bfd_svc')}",
            step=2, timeout=CUT_SECONDS + 20, allow_error=True)

        # ---------------- texts shared by the questions ---------------------------
        sites = [('rov', "1 — validation de l'origine (RPKI)",
                  "`rov_r1`, `rov_rpki` (le validateur) ; `rov_isp1`, `rov_isp2`, `rov_peer` sans terminal"),
                 ('pfx', "2 — limiter les préfixes reçus", "`pfx_r1` ; `pfx_isp`, `pfx_c1`, `pfx_c2` sans terminal"),
                 ('gtsm', "3 — GTSM", "`gtsm_r1` ; `gtsm_isp`, `gtsm_mid`, `gtsm_par` sans terminal"),
                 ('bh', "4 — RTBH", "`bh_r1` ; `bh_isp`, `bh_cust`, `bh_srv` sans terminal"),
                 ('bfd', "bonus — BFD", "`bfd_r1`, `bfd_isp1` ; `bfd_isp2`, le pont `bfd_sw` sans terminal")]
        site_rows = "\n".join(f"| {part} | `{site}_*` | {machines} |" for site, part, machines in sites)
        members: Dict[str, List[str]] = {}
        for m, nets in MACHINE_IFACES.items():
            for i, n in enumerate(nets):
                if m == BRIDGE or m == 'bh_srv':
                    continue
                key = COLLISION_DOMAINS.get(n, n)
                members.setdefault(key, []).append(f"`{m}` eth{i} (`{addr(m, n)}`)")
        members['bh_lan'].append(f"`bh_srv` (`{victim}` et `{control}`)")
        address_rows = [f"| `{n}` | `{net(n) if n != 'bh_lan' else net('bh_cust')}` | {', '.join(v)} |"
                        for n, v in members.items()]
        address_rows += [f"| `{site}_lo` | `{net(site + '_lo')}` | "
                         + ", ".join(f"`{r}` `{lo(r)}`" for r in FRR_ROUTERS + ['gtsm_mid'] if site_of(r) == site)
                         + " |" for site in SITE_NUMBER]
        addressing = "\n".join(address_rows)
        as_rows = "\n".join(f"| `{r}` | {asn} |" for r, asn in EXT_AS.items())

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="4ca6c605f65d06c4",
            description=tr("""
Lisez l'onglet **Informations** : il présente les menaces sur BGP et les protections de ce TP
(RPKI et validation de l'origine, `maximum-prefix`, GTSM, RTBH, BFD), leur configuration avec FRR
et les commandes de diagnostic.

**Le réseau.** Il est fait de **cinq sites indépendants**, un par partie. Chaque site a sa couleur
sur le schéma :

| partie | site | machines |
|--------|------|----------|
{site_rows}

- Vous êtes l'opérateur de l'**AS {our_as}** : ses routeurs sont les `*_r1` de chaque site. Les
  autres routeurs appartiennent à d'autres opérateurs (vos fournisseurs, vos clients, un pair) : vous
  n'avez pas de terminal sur eux.
- Les routeurs font tourner **FRRouting** (FRR) avec `bgpd` : configurez-les avec `vtysh`. Toutes les
  sessions BGP de vos routeurs existent déjà, avec leurs politiques (route-maps `ALL`, `OWN`…) ; chaque
  partie leur ajoute une protection.
- Toutes les adresses sont en place, y compris les interfaces de bouclage (`lo`). Les fichiers
  `/etc/hosts` contiennent les noms : `rov_isp1-eth0` désigne l'adresse de l'interface `eth0` de
  `rov_isp1`, `gtsm_par-lo` son adresse de bouclage.

**Les AS des autres opérateurs.**

| routeur | AS |
|---------|----|
{as_rows}

**Plan d'adressage.** Les liens entre routeurs sont des /30. Les préfixes annoncés en BGP (les
vôtres comme ceux des autres AS) sont pris dans `{pub}`.

| réseau | préfixe | interfaces |
|--------|---------|------------|
{addressing}

**Consignes.**

- Les parties sont **indépendantes** : faites-les dans l'ordre que vous voulez. Une partie terminée
  rapporte tous ses points, quel que soit l'état des autres.
- Enregistrez la configuration de FRR (`write` dans `vtysh`).
- Une route-map modifiée prend effet au bout de quelques secondes ; `clear bgp A.B.C.D soft in`
  la réapplique aussitôt.

**Évaluation.** Chaque évaluation lit vos réponses, l'état de BGP sur les routeurs (sessions, tables,
RPKI, BFD, configuration), les tables de routage, et lance des `ping`. Elle coupe aussi pendant
{cut} s le lien de `bfd_r1` vers `bfd_isp1` (bonus).
""").format(site_rows=site_rows, our_as=d.our_as, as_rows=as_rows, pub=net('pub'), addressing=addressing,
            cut=CUT_SECONDS)
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution pour les valeurs de cette
instance. Les états `solve_rov`, `solve_pfx`, `solve_gtsm`, `solve_bh` et `solve_bfd` (onglet
*Appliquer une configuration*) appliquent la solution d'une seule partie et remplissent ses
formulaires. L'état `final` les applique toutes et attend la convergence (environ 40 s) puis
remplit tous les formulaires : une évaluation lancée dès son retour donne tous les points, bonus
compris.

Le validateur `rov_rpki` fait tourner `stayrtr` sur le fichier `{roa_file}` (relu toutes les
{refresh} s, journal `{log}`). S'il a été arrêté :
`cd /tmp && setsid -f stayrtr -bind :{port} -cache {roa_file} -checktime=false -refresh {refresh}
-metrics.addr 127.0.0.1:9847 > {log} 2>&1`, puis `rpki reset` sur `rov_r1` et `rov_peer`.
""").format(roa_file=ROA_FILE, refresh=STAYRTR_REFRESH, log=STAYRTR_LOG, port=RTR_PORT)),
        )

        # =====================================================================
        # Part 1 — route origin validation (rov)
        # =====================================================================
        part1 = self.add_grade_part(no_tr("rov"), tr("Partie 1 — validation de l'origine par RPKI (site rov)"))
        roa_rows = "\n".join(f"| `{r['prefix']}` | {r['maxLength']} | {r['asn']} |" for r in ns.roas())
        self.question_dummy(
            section=self.section(0),
            title=tr("Validation de l'origine par RPKI"),
            hash="e3f06ecf1dc1122e",
            description=tr("""
`rov_r1` a deux fournisseurs, `rov_isp1` (AS {as1}) et `rov_isp2` (AS {as2}), et un pair,
`rov_peer` (AS {asp}). Il annonce votre bloc `{own}` et, pour l'ingénierie de trafic, le /24 `{te}`.
Le validateur `rov_rpki` (`{rpki}`, réseau d'administration `rov_mgmt`) sert en RTR, sur le port
**{port}**, les ROA du fichier `{roa_file}` (section @@ref:validator@@) :

| préfixe | maxLength | AS d'origine |
|---------|-----------|--------------|
{roa_rows}

`rov_peer` est déjà connecté au validateur et **rejette les routes invalides**.

1. **Observation.** Sur `rov_r1`, regardez les routes reçues (`show bgp ipv4 unicast`) : par où passe
   le trafic vers `{h}` ? vers `{m24}` (`ip route get`) ? Qui annonce ces préfixes, avec quel AS
   d'origine ? Que dit `show rpki cache-connection` ?
2. **Connexion au cache.** Connectez `rov_r1` au validateur (section @@ref:rpki-frr@@) et vérifiez
   qu'il a reçu les VRP (`show rpki prefix-table`). Quel est l'état de validation de chaque route ?
3. **Politique.** Sur les sessions de **vos deux fournisseurs**, appliquez en entrée la politique
   suivante : rejeter les routes **invalid**, donner aux routes **valid** une `local-preference` de
   **{lp}**, garder les routes **notfound** telles quelles. Activez aussi `soft-reconfiguration
   inbound` sur ces deux sessions. Vérifiez la table de `rov_r1` et `ip route get` pour `{h}` et
   `{m24}`.
4. **Votre ROA.** Votre `{te}` est rejeté par `rov_peer` : avec `show rpki prefix {te} {our_as}` sur
   `rov_r1`, trouvez pourquoi. Corrigez la ROA de votre bloc dans `{roa_file}` sur `rov_rpki` (le
   fichier est relu toutes les {refresh} s) pour que votre /22 **et** votre /24 soient valides.
""").format(as1=EXT_AS['rov_isp1'], as2=EXT_AS['rov_isp2'], asp=EXT_AS['rov_peer'], own=net('rov_own'),
            te=net('rov_te'), rpki=ns.rpki_addr(), port=RTR_PORT, roa_file=ROA_FILE, roa_rows=roa_rows,
            h=net('rov_h'), m24=net('rov_m24'), lp=VALID_LOCAL_PREF, our_as=d.our_as, refresh=STAYRTR_REFRESH)
            + instructor(tr("""
**Solution.**

{solution}

Sur `rov_rpki`, la ROA de `{own}` passe à `"maxLength": 24` :

```
{fixed}
```

Au départ, `rov_isp1` annonce `{h}` avec l'origine {as1} (chemin plus court que celui de `rov_isp2`,
qui ajoute deux fois son AS) : le trafic part chez lui, c'est un **détournement d'origine**
(`invalid` : la ROA autorise l'AS {as2}). Il annonce aussi `{m24}` avec l'origine **{as2}** forgée
(`{as1} {as2}`) : la plus longue correspondance l'emporte sur le `{m}` légitime de `rov_isp2`. L'origine
est la bonne, mais la ROA de `{m}` limite la longueur à 22 : `invalid` aussi. Après la politique, `{h}`
passe par `rov_isp2` (`{isp2}`), `{m24}` disparaît et le trafic suit `{m}`. La revalidation par
`rov_peer` demande un `clear bgp * soft in` de son côté : l'évaluation le fait.

Évaluation : `rov_cache_conf` (1), `rov_cache_up` (2), `rov_vrps` (1), `rov_hijack` (3 : plus de
chemin de `rov_isp1` pour `{h}`, meilleur chemin par `rov_isp2`), `rov_subprefix` (3 : `{m24}` rejeté,
`{m}` par `rov_isp2`), `rov_kernel` (2), `rov_notfound` (2 : `{n1}` toujours accepté), `rov_valid_pref`
(2 : local-preference {lp} des routes valides), `rov_roa` (4 : `{te}` et `{own}` valides et acceptés
par `rov_peer`).
""").format(solution=_vtysh_text(ns.solution_rov()), own=net('rov_own'), fixed=json.dumps(ns.roas(True)[-1]),
            h=net('rov_h'), m24=net('rov_m24'), m=net('rov_m'), as1=EXT_AS['rov_isp1'], as2=EXT_AS['rov_isp2'],
            isp2=isp2, n1=net('rov_n1'), lp=VALID_LOCAL_PREF, te=net('rov_te'))),
        )
        cheat_rov = {'port': str(RTR_PORT), 'origin': str(EXT_AS['rov_isp2']), 'state': 'invalid',
                     'why': 'maxlength', 'refresh': 'softin'}
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site rov"),
            hash="7eb9a4c7d5a8bdb2",
            description=tr("""
- port TCP du protocole RPKI-RTR de `rov_rpki` : @@{{port:[0-9]+}}@@
- seul AS autorisé à originer `{h}` : @@{{origin:[0-9]+}}@@
- état de validation du chemin de `{h}` reçu de `rov_isp1` :
  @@{{state:>valid>>>valid|invalid>>>invalid|notfound>>>notfound}}@@
- `{m24}` annoncé par `rov_isp1` est invalide car :
  @@{{why:>son AS d'origine n'est pas celui de la ROA>>>origin|il est plus long que le maxLength de la ROA>>>maxlength|aucune ROA ne le couvre>>>noroa|sa signature est expirée>>>expired}}@@
- après la correction d'une ROA, un routeur qui avait rejeté la route la récupère :
  @@{{refresh:>tout seul, dès la notification du cache>>>auto|avec clear bgp X soft in de son côté>>>softin|seulement après un redémarrage de bgpd>>>restart|jamais : il faut une nouvelle ROA>>>never}}@@
""").format(h=net('rov_h'), m24=net('rov_m24'))
            + instructor(tr("""
**Solution.** **{port}** ; **{as2}** ; **invalid** ; **plus long que le maxLength** (origine {as2}
forgée, mais la ROA de `{m}` dit 22) ; **avec `clear bgp X soft in`** (une route rejetée n'est plus
connue du routeur : il doit la redemander).

Évaluation : `rov_q_port`, `rov_q_origin` (1 chacun) et, pour l'enseignant seulement (choix dans une
liste), `rov_q_state`, `rov_q_why`, `rov_q_refresh` (1 chacun).
""").format(port=RTR_PORT, as2=EXT_AS['rov_isp2'], m=net('rov_m'))),
            cheat_answers={"final": cheat_rov, "solve_rov": cheat_rov},
        )
        h_paths = rov_routes.get(str(net('rov_h')), [])
        hijack_ok = (bool(h_paths) and not bgp_paths(rov_routes, net('rov_h'), peer=isp1)
                     and best_via(rov_routes, net('rov_h'), isp2))
        self.add_grade_element(
            title=no_tr("rov_cache_conf"), max_grade=1, grade_part=part1,
            grade=int(any(s['host'] == str(ns.rpki_addr()) and s['port'] == RTR_PORT
                          for s in rov_cfg['rpki']['cache_servers'])),
            description=tr("rov_r1 configuré avec le cache RPKI"),
        )
        self.add_grade_element(
            title=no_tr("rov_cache_up"), max_grade=2, grade_part=part1, grade=2 * int(rov_conn['connected']),
            description=tr("rov_r1 connecté au cache RPKI"),
        )
        self.add_grade_element(
            title=no_tr("rov_vrps"), max_grade=1, grade_part=part1,
            grade=int(any(v['prefix'] == str(net('rov_h')) and v['asn'] == EXT_AS['rov_isp2'] for v in rov_vrps)),
            description=tr("VRP reçues par rov_r1"),
        )
        self.add_grade_element(
            title=no_tr("rov_hijack"), max_grade=3, grade_part=part1, grade=3 * int(hijack_ok),
            description=tr("détournement d'origine rejeté"),
        )
        self.add_grade_element(
            title=no_tr("rov_subprefix"), max_grade=3, grade_part=part1,
            grade=3 * int(str(net('rov_m24')) not in rov_routes and str(net('rov_m24')) not in rov_k
                          and best_via(rov_routes, net('rov_m'), isp2)),
            description=tr("détournement de sous-préfixe rejeté"),
        )
        self.add_grade_element(
            title=no_tr("rov_kernel"), max_grade=2, grade_part=part1,
            grade=2 * int(gateways(rov_k, net('rov_h')) == [str(isp2)]),
            description=tr("le trafic vers le préfixe détourné suit le chemin légitime"),
        )
        self.add_grade_element(
            title=no_tr("rov_notfound"), max_grade=2, grade_part=part1,
            grade=2 * int(hijack_ok and best_via(rov_routes, net('rov_n1'), isp1)),
            description=tr("les routes notfound restent acceptées"),
        )
        self.add_grade_element(
            title=no_tr("rov_valid_pref"), max_grade=2, grade_part=part1,
            grade=2 * int(hijack_ok and all(bgp_best_path(rov_routes, net(p)).get('locprf') == VALID_LOCAL_PREF
                                            for p in ('rov_v1', 'rov_v2'))
                          and bgp_best_path(rov_routes, net('rov_n1')).get('locprf') in (None, 100)),
            description=tr("routes valides préférées"),
        )
        te_paths, own_paths = rov_peer_te['paths'], rov_peer_own['paths']
        self.add_grade_element(
            title=no_tr("rov_roa"), max_grade=4, grade_part=part1,
            grade=4 * int(any(p['rpki'] == 'valid' for p in te_paths) and any(p['rpki'] == 'valid' for p in own_paths)),
            description=tr("ROA corrigée : votre /24 accepté par rov_peer"),
        )
        self.add_grade_element(
            title=no_tr("rov_q_port"), max_grade=1, grade_part=part1, grade=int(_int(q1.get('port')) == RTR_PORT),
            description=tr("port RPKI-RTR"),
        )
        self.add_grade_element(
            title=no_tr("rov_q_origin"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get('origin')) == EXT_AS['rov_isp2']), description=tr("AS d'origine autorisé"),
        )
        for key, label in (('state', tr("état de validation d'un détournement")),
                           ('why', tr("cause de l'invalidité d'un sous-préfixe")),
                           ('refresh', tr("retour d'une route rejetée"))):
            self.add_grade_element(
                title=no_tr(f"rov_q_{key}"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
                grade=int(_norm(q1.get(key)) == cheat_rov[key]), description=label,
            )

        # =====================================================================
        # Part 2 — maximum-prefix (pfx)
        # =====================================================================
        part2 = self.add_grade_part(no_tr("pfx"), tr("Partie 2 — limiter les préfixes reçus (site pfx)"))
        leak = leaked_prefixes(net('pub'))
        c1_prefixes = [net(p) for p in PFX_C1]
        self.question_dummy(
            section=self.section(0),
            title=tr("Limiter les préfixes reçus"),
            hash="39c9366318bb8bfb",
            description=tr("""
`pfx_r1` a un fournisseur, `pfx_isp` (AS {asi}), et deux clients : `pfx_c1` (AS {as1}), qui annonce
ses quatre /24 (`{c1a}` à `{c1d}`), et `pfx_c2` (AS {as2}), qui devrait n'annoncer que `{c2a}` et
`{c2b}`. Les sessions des clients acceptent tout ce qu'ils annoncent (route-map `ALL`), et `pfx_r1`
réannonce tout à son fournisseur.

1. **Observation.** Combien de préfixes `pfx_r1` reçoit-il de chaque client (`show bgp ipv4 unicast
   summary`) ? Que réannonce-t-il à `pfx_isp` (`show bgp ipv4 unicast neighbors {isp}
   advertised-routes`) ? D'où viennent les routes de `pfx_c2` (`show bgp ipv4 unicast` : AS_PATH,
   origine `?`) ?
2. **Protection.** Le contrat de chaque client fixe une limite de **{limit}** préfixes : configurez-la
   sur les deux sessions avec une **alerte à {threshold} %** de la limite (section @@ref:maxprefix@@).
   Ni `warning-only` ni `restart` : une session qui dépasse la limite reste fermée.
3. Vérifiez l'état des deux sessions, le message du journal (`/var/log/frr/frr.log`) et ce que reçoit
   maintenant `pfx_isp`.
""").format(asi=EXT_AS['pfx_isp'], as1=EXT_AS['pfx_c1'], as2=EXT_AS['pfx_c2'], c1a=c1_prefixes[0],
            c1d=c1_prefixes[-1], c2a=net('pfx_c2a'), c2b=net('pfx_c2b'), isp=addr('pfx_isp', 'pfx_l1'),
            limit=d.pfx_limit, threshold=d.pfx_threshold)
            + instructor(tr("""
**Solution.**

{solution}

`pfx_c2` redistribue {count} routes statiques en plus de ses deux préfixes ({total} au total, origine
`incomplete`) : une fuite. Avec la limite, sa session se ferme aussitôt (`Idle (PfxCt)`, journal
`%MAXPFXEXCEED: No. of IPv4 Unicast prefix received from {c2}(pfx_c2) {total} exceed, limit {limit}`) et
les routes disparaissent de `pfx_isp`. `pfx_c1` reste établi (4 préfixes, sous le seuil d'alerte ou
au-dessus selon {threshold} % de {limit}).

Évaluation : `pfx_conf_c1`, `pfx_conf_c2` (2 chacun : limite {limit}, seuil {threshold}, sans
`warning-only` ni `restart`), `pfx_c2_down` (3), `pfx_c1_up` (2 : établi, 4 préfixes), `pfx_leak` (3 : plus
aucune route de la fuite chez `pfx_isp`, les 4 de `pfx_c1` toujours là).
""").format(solution=_vtysh_text(ns.solution_pfx()), count=LEAK_COUNT, total=LEAK_COUNT + 2, c2=c2,
            limit=d.pfx_limit, threshold=d.pfx_threshold)),
        )
        cheat_pfx = {'state': 'Idle (PfxCt)', 'count': str(LEAK_COUNT + 2), 'restore': 'clear', 'warning': 'leak'}
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site pfx"),
            hash="211d0ecfa7afd201",
            description=tr("""
- état affiché pour `pfx_c2` dans `show bgp ipv4 unicast summary` une fois la limite en place :
  @@{state:.+}@@
- nombre de préfixes que `pfx_c2` a envoyés (journal) : @@{count:[0-9]+}@@
- une fois la fuite corrigée chez `pfx_c2`, la session se rétablit :
  @@{restore:>toute seule au bout de 120 s>>>auto|avec clear bgp sur pfx_r1>>>clear|en retirant maximum-prefix seulement>>>remove|jamais>>>never}@@
- avec `warning-only` à la place, la fuite :
  @@{warning:>serait acceptée et réannoncée à pfx_isp>>>leak|serait refusée, la session restant ouverte>>>filtered|fermerait la session après 30 min>>>delayed}@@
""")
            + instructor(tr("""
**Solution.** **`Idle (PfxCt)`** ; **{total}** ; **avec `clear bgp {c2}`** (la session reste fermée
sans `restart`) ; avec `warning-only`, la fuite **serait acceptée et réannoncée** (une alerte au
journal seulement).

Évaluation : `pfx_q_state`, `pfx_q_count` (1 chacun) et, pour l'enseignant seulement, `pfx_q_restore`,
`pfx_q_warning` (1 chacun).
""").format(total=LEAK_COUNT + 2, c2=c2)),
            cheat_answers={"final": cheat_pfx, "solve_pfx": cheat_pfx},
        )

        def limit_ok(peer) -> bool:
            mp = neighbor(pfx_cfg, peer).get('maximum_prefix') or {}
            return (mp.get('limit') == d.pfx_limit and mp.get('threshold') == d.pfx_threshold
                    and not mp.get('warning_only') and mp.get('restart') is None)

        c2_peer = (pfx_sum.get('peers') or {}).get(str(c2)) or {}
        c1_peer = peer_up(pfx_sum, c1)
        self.add_grade_element(
            title=no_tr("pfx_conf_c1"), max_grade=2, grade_part=part2, grade=2 * int(limit_ok(c1)),
            description=tr("limite de préfixes de pfx_c1"),
        )
        self.add_grade_element(
            title=no_tr("pfx_conf_c2"), max_grade=2, grade_part=part2, grade=2 * int(limit_ok(c2)),
            description=tr("limite de préfixes de pfx_c2"),
        )
        self.add_grade_element(
            title=no_tr("pfx_c2_down"), max_grade=3, grade_part=part2,
            grade=3 * int(bool(c2_peer.get('prefix_limit_exceeded'))),
            description=tr("session de pfx_c2 fermée par la limite"),
        )
        self.add_grade_element(
            title=no_tr("pfx_c1_up"), max_grade=2, grade_part=part2,
            grade=2 * int(limit_ok(c1) and c1_peer.get('pfx_rcd') == len(PFX_C1)),
            description=tr("session de pfx_c1 établie sous la limite"),
        )
        self.add_grade_element(
            title=no_tr("pfx_leak"), max_grade=3, grade_part=part2,
            grade=3 * int(not any(str(p) in pfx_isp_routes for p in leak)
                          and all(str(p) in pfx_isp_routes for p in c1_prefixes)),
            description=tr("la fuite n'atteint plus pfx_isp"),
        )
        self.add_grade_element(
            title=no_tr("pfx_q_state"), max_grade=1, grade_part=part2,
            grade=int('pfxct' in _norm(q2.get('state')).replace(' ', '')), description=tr("état d'une session fermée"),
        )
        self.add_grade_element(
            title=no_tr("pfx_q_count"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get('count')) == LEAK_COUNT + 2), description=tr("taille de la fuite"),
        )
        for key, label in (('restore', tr("rétablissement de la session")), ('warning', tr("effet de warning-only"))):
            self.add_grade_element(
                title=no_tr(f"pfx_q_{key}"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
                grade=int(_norm(q2.get(key)) == cheat_pfx[key]), description=label,
            )

        # =====================================================================
        # Part 3 — GTSM (gtsm)
        # =====================================================================
        part3 = self.add_grade_part(no_tr("gtsm"), tr("Partie 3 — GTSM (site gtsm)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Protéger les sessions avec GTSM"),
            hash="5d90ac011c238c1b",
            description=tr("""
`gtsm_r1` a deux sessions eBGP, qui ne s'établissent pas (`Active` ou `Idle`) :

- avec son fournisseur `gtsm_isp` (AS {asi}, `{isp}`), directement connecté ;
- avec un partenaire, `gtsm_par` (AS {asp}), entre les adresses de bouclage (`{r1lo}` et `{parlo}`) à
  travers le routeur `gtsm_mid` : `gtsm_r1` a pour cela `ebgp-multihop 2` et `update-source lo`.

Les deux opérateurs **exigent GTSM** (section @@ref:gtsm@@), chacun avec le nombre de sauts qui le
sépare de `gtsm_r1`. Ils retentent d'ouvrir la session toutes les {retry} s.

1. **Observation.** Avec `tcpdump -nvi eth0 tcp port 179` puis sur `eth1`, regardez les paquets
   échangés : quels TTL ? Que montrent `show bgp ipv4 unicast summary` et `show bgp neighbors` ?
2. **Configuration.** Activez GTSM sur les deux sessions de `gtsm_r1`, avec le bon nombre de sauts.
3. Vérifiez que les deux sessions s'établissent et que les préfixes `{pisp}` et `{ppar}` sont reçus ;
   observez à nouveau les TTL. Une session peut mettre jusqu'à une minute à s'établir : le routeur
   d'en face attend la fin de sa tentative précédente (`OpenSent`), restée sans réponse.
""").format(asi=EXT_AS['gtsm_isp'], isp=gisp, asp=EXT_AS['gtsm_par'], r1lo=lo('gtsm_r1'), parlo=gpar,
            retry=CONNECT_RETRY, pisp=net('gtsm_isp'), ppar=net('gtsm_par'))
            + instructor(tr("""
**Solution.**

{solution}

Sans GTSM, `gtsm_r1` émet ses paquets eBGP avec un TTL de 1 (2 vers `gtsm_par` avec `ebgp-multihop 2`,
qui arrivent avec 1) : `gtsm_isp` exige 255, `gtsm_par` 254 au moins, et les jettent. `ebgp-multihop`
et `ttl-security` sont incompatibles : il faut retirer le premier. Avec `hops 2`, `gtsm_r1` accepte
les paquets qui arrivent avec un TTL ≥ 254 : ceux de `gtsm_par` (255 − 1 saut).

Évaluation : `gtsm_isp_conf` (2), `gtsm_isp_up` (3 : établie grâce à GTSM, `{pisp}` reçu),
`gtsm_par_conf` (2 : `hops 2`, plus d'`ebgp-multihop`), `gtsm_par_up` (3 : établie grâce à GTSM,
`{ppar}` reçu).
""").format(solution=_vtysh_text(ns.solution_gtsm()), pisp=net('gtsm_isp'), ppar=net('gtsm_par'))),
        )
        cheat_gtsm = {'minttl': '254', 'sent': '255', 'default': '1', 'oneside': 'active'}
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site gtsm"),
            hash="f68c2ecc1f8f3533",
            description=tr("""
- TTL minimal des paquets de `gtsm_par` qu'accepte `gtsm_r1` une fois GTSM en place : @@{minttl:[0-9]+}@@
- TTL des paquets BGP émis par un routeur avec GTSM : @@{sent:[0-9]+}@@
- TTL des paquets d'une session eBGP sans GTSM ni `ebgp-multihop` : @@{default:[0-9]+}@@
- si un seul des deux pairs active GTSM, la session :
  @@{oneside:>ne s'établit pas (les paquets de l'autre sont jetés)>>>active|s'établit sans protection>>>open|s'établit puis se ferme toutes les 180 s>>>flap}@@
""")
            + instructor(tr("""
**Solution.** **254** (256 − 2) ; **255** ; **1** ; elle **ne s'établit pas**.

Évaluation : `gtsm_q_minttl`, `gtsm_q_sent`, `gtsm_q_default` (1 chacun) et, pour l'enseignant
seulement, `gtsm_q_oneside` (1).
""")),
            cheat_answers={"final": cheat_gtsm, "solve_gtsm": cheat_gtsm},
        )
        isp_conf = neighbor(gtsm_cfg, gisp).get('ttl_security') == 1
        par_n = neighbor(gtsm_cfg, gpar)
        par_conf = par_n.get('ttl_security') == 2 and par_n.get('ebgp_multihop') is None
        self.add_grade_element(
            title=no_tr("gtsm_isp_conf"), max_grade=2, grade_part=part3, grade=2 * int(isp_conf),
            description=tr("GTSM vers gtsm_isp"),
        )
        self.add_grade_element(
            title=no_tr("gtsm_isp_up"), max_grade=3, grade_part=part3,
            grade=3 * int(isp_conf and bool(peer_up(gtsm_sum, gisp)) and str(net('gtsm_isp')) in gtsm_routes),
            description=tr("session avec gtsm_isp établie"),
        )
        self.add_grade_element(
            title=no_tr("gtsm_par_conf"), max_grade=2, grade_part=part3, grade=2 * int(par_conf),
            description=tr("GTSM vers gtsm_par (deux sauts)"),
        )
        self.add_grade_element(
            title=no_tr("gtsm_par_up"), max_grade=3, grade_part=part3,
            grade=3 * int(par_conf and bool(peer_up(gtsm_sum, gpar)) and str(net('gtsm_par')) in gtsm_routes),
            description=tr("session avec gtsm_par établie"),
        )
        for key, value in (('minttl', 254), ('sent', 255), ('default', 1)):
            self.add_grade_element(
                title=no_tr(f"gtsm_q_{key}"), max_grade=1, grade_part=part3, grade=int(_int(q3.get(key)) == value),
                description=tr("TTL de GTSM"),
            )
        self.add_grade_element(
            title=no_tr("gtsm_q_oneside"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get('oneside')) == cheat_gtsm['oneside']), description=tr("GTSM d'un seul côté"),
        )

        # =====================================================================
        # Part 4 — RTBH (bh)
        # =====================================================================
        part4 = self.add_grade_part(no_tr("bh"), tr("Partie 4 — RTBH (site bh)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Blackholing déclenché par un client"),
            hash="7f3fbb07727414b8",
            description=tr("""
`bh_r1` est le fournisseur de `bh_cust` (AS {asc}), dont le réseau `{cust}` héberge le serveur
`bh_srv` (`{victim}` et `{control}`), et le client de `bh_isp` (AS {asi}). La session avec `bh_cust`
n'accepte que son /24 (prefix-list `CUSTOMER`, route-map `FROM-CUSTOMER`).

`{victim}` subit une attaque : `bh_cust` demande son **blackholing** en annonçant `{victim}/32` avec
la communauté **BLACKHOLE** (section @@ref:rtbh@@). Il annonce aussi, par erreur, `{bogus}/32` avec
la même communauté : une adresse du réseau de `bh_isp`, qui n'est pas à lui.

`bh_r1` a une interface factice **`{discard}`** (`{dnet}`) : tout ce qui est routé vers
`{nexthop}` y disparaît.

1. **Observation.** Sur `bh_r1`, que reçoit-on de `bh_cust` (`show bgp ipv4 unicast neighbors {cust_ip}
   received-routes` n'est pas disponible : regardez ce que `bh_cust` annonce avec les compteurs de
   `show bgp ipv4 unicast summary` et `show bgp ipv4 unicast neighbors {cust_ip}`) ? `ping {victim}` et
   `ping {control}` depuis `bh_r1` passent-ils ?
2. **Configuration.** Sans toucher au reste de la politique, faites accepter par `bh_r1` les /32 que
   `bh_cust` marque avec BLACKHOLE, **uniquement dans `{cust}`**, avec `{nexthop}` comme prochain saut
   et `no-export`.
3. Vérifiez la table BGP et `ip route` sur `bh_r1`, que `ping {victim}` échoue et `ping {control}`
   passe toujours, que `{bogus}/32` a été refusé et que rien n'est annoncé à `bh_isp`.
""").format(asc=EXT_AS['bh_cust'], cust=net('bh_cust'), victim=victim, control=control, asi=EXT_AS['bh_isp'],
            bogus=bogus, discard=DISCARD_IFACE, dnet=DISCARD_NET, nexthop=DISCARD_NEXT_HOP,
            cust_ip=addr('bh_cust', 'bh_l2'))
            + instructor(tr("""
**Solution.**

{solution}

La séquence 5 passe avant la séquence 10 (le /24 du client) ; ses deux `match` doivent être vrais.
`{victim}/32` est installé `via {nexthop} dev {discard}` : le trafic de l'attaque, qui arrive de
`bh_isp`, est jeté par `bh_r1` ; `{control}` reste joignable (le /24). `{bogus}/32` n'est pas dans
`{cust}` : refusé. FRR ajoute `no-export` de lui-même aux routes BLACKHOLE (le `set community`
l'écrit explicitement).

Évaluation : `bh_accept` (3 : `{victim}/32` accepté avec la communauté), `bh_discard` (3 : route
noyau vers `{discard}`), `bh_drop` (3 : depuis `bh_isp`, `{victim}` ne répond plus, `{control}`
répond), `bh_scope` (3 : `{bogus}/32` refusé, `bh_r1` joint toujours `{bogus}`), `bh_not_exported`
(2 : `bh_isp` ne reçoit pas `{victim}/32`).
""").format(solution=_vtysh_text(ns.solution_bh()), victim=victim, nexthop=DISCARD_NEXT_HOP,
            discard=DISCARD_IFACE, control=control, bogus=bogus, cust=net('bh_cust'))),
        )
        cheat_bh = {'community': BLACKHOLE_COMMUNITY, 'rfc': '7999', 'added': 'noexport', 'scope': 'anyone'}
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le site bh"),
            hash="009be88bb38fc6f2",
            description=tr("""
- valeur de la communauté BLACKHOLE (forme `AS:valeur`) : @@{community:[0-9:]+}@@
- numéro de la RFC qui la définit : @@{rfc:[0-9]+}@@
- communauté que FRR ajoute de lui-même à une route reçue avec BLACKHOLE :
  @@{added:>no-export>>>noexport|no-advertise>>>noadvertise|local-AS>>>localas|graceful-shutdown>>>gshut}@@
- `bh_r1` doit limiter ces /32 à l'espace du client, sinon :
  @@{scope:>n'importe quel client pourrait faire jeter le trafic de n'importe qui>>>anyone|la table de routage déborderait>>>size|les sessions se fermeraient (maximum-prefix)>>>maxpfx}@@
""")
            + instructor(tr("""
**Solution.** **{community}** ; RFC **7999** ; **no-export** ; **n'importe quel client pourrait faire
jeter le trafic de n'importe qui** (ici `{bogus}`).

Évaluation : `bh_q_community`, `bh_q_rfc` (1 chacun) et, pour l'enseignant seulement, `bh_q_added`,
`bh_q_scope` (1 chacun).
""").format(community=BLACKHOLE_COMMUNITY, bogus=bogus)),
            cheat_answers={"final": cheat_bh, "solve_bh": cheat_bh},
        )
        accept_ok = any('blackhole' in [c.lower() for c in p['communities']] for p in bh_victim['paths'])
        victim_k = bh_k.get(f"{victim}/32") or {}
        discard_ok = (any(dev == DISCARD_IFACE for _gw, dev in victim_k.get('nexthops', []))
                      or victim_k.get('type') in ('blackhole', 'unreachable', 'prohibit'))
        self.add_grade_element(
            title=no_tr("bh_accept"), max_grade=3, grade_part=part4, grade=3 * int(accept_ok),
            description=tr("/32 du client accepté avec BLACKHOLE"),
        )
        self.add_grade_element(
            title=no_tr("bh_discard"), max_grade=3, grade_part=part4, grade=3 * int(discard_ok),
            description=tr("route vers l'interface de rejet"),
        )
        self.add_grade_element(
            title=no_tr("bh_drop"), max_grade=3, grade_part=part4,
            grade=3 * int(not bh_ping_victim and bh_ping_control),
            description=tr("trafic vers l'adresse attaquée jeté, le reste passe"),
        )
        self.add_grade_element(
            title=no_tr("bh_scope"), max_grade=3, grade_part=part4,
            grade=3 * int(accept_ok and f"{bogus}/32" not in bh_routes and bh_ping_bogus),
            description=tr("blackholing limité à l'espace du client"),
        )
        self.add_grade_element(
            title=no_tr("bh_not_exported"), max_grade=2, grade_part=part4,
            grade=2 * int(accept_ok and bool(bh_isp_routes) and f"{victim}/32" not in bh_isp_routes),
            description=tr("/32 non annoncé au fournisseur"),
        )
        for key, value in (('community', BLACKHOLE_COMMUNITY), ('rfc', '7999')):
            self.add_grade_element(
                title=no_tr(f"bh_q_{key}"), max_grade=1, grade_part=part4,
                grade=int(_norm(q4.get(key)).replace(' ', '') == value), description=tr("communauté BLACKHOLE"),
            )
        for key, label in (('added', tr("communauté ajoutée par FRR")), ('scope', tr("limite à l'espace du client"))):
            self.add_grade_element(
                title=no_tr(f"bh_q_{key}"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
                grade=int(_norm(q4.get(key)) == cheat_bh[key]), description=label,
            )

        # =====================================================================
        # Bonus — BFD (bfd)
        # =====================================================================
        part5 = self.add_grade_part(no_tr("bfd"), tr("Bonus — BFD (site bfd)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Bonus : détecter une panne avec BFD"),
            hash="b6ecbb9cfdccb3fb",
            description=tr("""
`bfd_r1` joint le service `{svc}` (annoncé par ses deux fournisseurs) par `bfd_isp1` (AS {as1},
préféré : `local-preference {lp}`) ou, en secours, par `bfd_isp2` (AS {as2}). Le lien vers
`bfd_isp1` traverse le pont `bfd_sw` : quand il tombe en panne, les interfaces restent actives mais
plus rien ne passe. Chaque évaluation **coupe `bfd_sw` pendant {cut} s** et mesure, depuis `bfd_r1`,
l'interruption du trafic vers `{svc}` (un ping toutes les {step} s, depuis `{src}`).

1. Lancez `ping -I {src} -i 0.2 {svc}` sur `bfd_r1`, puis une évaluation : combien de temps le trafic
   est-il interrompu ? Que devient la session BGP avec `bfd_isp1` ? Pourquoi (section @@ref:bfd@@) ?
2. L'opérateur de `bfd_isp1` vous ouvre son routeur : il y a défini un profil BFD **`{profile}`**
   (intervalles de **{interval}** ms, multiplicateur **{mult}**). Créez le même profil sur `bfd_r1` et
   activez BFD avec ce profil sur la session BGP entre `bfd_r1` et `bfd_isp1`, **des deux côtés**.
   Vérifiez `show bfd peers` et `show bgp neighbors`.
3. Relancez une évaluation : l'interruption doit durer moins de {max_outage} s.
""").format(svc=host('bfd_svc'), as1=EXT_AS['bfd_isp1'], lp=VALID_LOCAL_PREF, as2=EXT_AS['bfd_isp2'],
            cut=CUT_SECONDS, step=PING_INTERVAL, src=host('bfd_own'), profile=BFD_PROFILE, interval=d.bfd_interval,
            mult=d.bfd_multiplier, max_outage=int(MAX_OUTAGE))
            + instructor(tr("""
**Solution.**

{solution}

Sans BFD, la coupure de {cut} s est plus courte que le *hold time* (180 s) : la session reste
établie et le trafic part dans le vide pendant toute la coupure. Tant qu'un seul côté a BFD, FRR
garde la session BGP en `Idle` : il attend que la session BFD soit établie. Avec BFD, la session tombe au bout de
{detection} ms ({mult} × {interval}), les routes de `bfd_isp1` sont retirées et le trafic passe par
`bfd_isp2`. Après la coupure, la session revient en quelques secondes (`timers connect {retry}`).

Évaluation (bonus) : `bfd_conf` (1 : profil et session), `bfd_up` (2 : session BFD établie avec
`bfd_isp1`), `bfd_failover` (3 : interruption de moins de {max_outage} s pendant la coupure).
""").format(solution=_vtysh_text(ns.solution_bfd()), cut=CUT_SECONDS, detection=d.bfd_interval * d.bfd_multiplier,
            mult=d.bfd_multiplier, interval=d.bfd_interval, retry=CONNECT_RETRY, max_outage=int(MAX_OUTAGE))),
        )
        bfd_n = neighbor(bfd_cfg, bfd_isp1)
        profile = bfd_cfg['bfd']['profiles'].get(bfd_n.get('bfd_profile') or '')
        conf_ok = (bool(bfd_n.get('bfd')) and profile is not None
                   and bfd_profile_value(profile, 'transmit_interval') == d.bfd_interval
                   and bfd_profile_value(profile, 'receive_interval') == d.bfd_interval
                   and bfd_profile_value(profile, 'detect_multiplier') == d.bfd_multiplier)
        bfd_up = bool((bfd_peers.get(str(bfd_isp1)) or {}).get('up'))
        replies, outage = _ping_outage(bfd_ping_out)
        self.add_grade_element(
            title=no_tr("bfd_conf"), max_grade=1, grade_part=part5, bonus=True, grade=int(conf_ok),
            description=tr("profil BFD et session BGP"),
        )
        self.add_grade_element(
            title=no_tr("bfd_up"), max_grade=2, grade_part=part5, bonus=True, grade=2 * int(bfd_up),
            description=tr("session BFD établie avec bfd_isp1"),
        )
        self.add_grade_element(
            title=no_tr("bfd_failover"), max_grade=3, grade_part=part5, bonus=True,
            grade=3 * int(bfd_up and replies > 0 and outage is not None and outage < MAX_OUTAGE),
            description=tr("bascule rapide pendant la coupure"),
        )


_TRANSLATIONS = {}
