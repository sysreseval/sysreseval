"""MTU lab in IPv4: fragmentation, path MTU discovery, PMTUD black hole, GRE tunnel.

Topology: ``m1 — lan1 — r1 — wan1 — wan — wan2 — r2 — lan2 — m2``.  ``wan`` is the operator's router:
visible in the schema, without a terminal, both of its interfaces have a reduced MTU drawn at random
(``Data.wan_mtu``).  The students administer ``m1``, ``m2``, ``r1`` and ``r2``.

Grading by hidden probes: ``h1`` (lan1) and ``h2`` (lan2) are ordinary hosts (MTU 1500,
``tcp_mtu_probing`` at 0) that ``wan`` keeps **permanently** behind a PMTUD black hole (an nftables
table ``probes`` drops the ICMP "fragmentation needed" errors addressed to them).  The graded
transfers (iperf3) run between the probes: only the fixes made on the routers ``r1`` / ``r2`` (MSS
clamping, MTU of the WAN interfaces) let them through, and the evaluation never disturbs what the
students do (the networks are switches: the students' captures do not see these transfers).  The
states ``black_hole`` / ``icmp_restored`` (applied by the students) act on a second table
(``black_hole``) and never touch the probes' table.  The ``final`` state applies the reference
solution (MSS clamping on r1 and r2, GRE tunnel at the right MTU) and fills the answers of the forms.
Every question ends with its solution in an ``instructor()`` block (instructor mode), computed for the
values of the project.

The pure functions (``ping -M do`` commands, output parsers, nftables texts) are in ``lib/pmtu.py``.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

import pmtu
import tc
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from ips import random_ipv4networks, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from ping import eval_ping
from state_helpers import create_hosts_file

default_language = 'fr'
tr = make_tr(default_language)

title = tr("MTU et découverte du PMTU en IPv4 (fragmentation, trou noir, tunnel GRE)",
           en="MTU and path MTU discovery in IPv4 (fragmentation, black hole, GRE tunnel)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
allow_user_states = True
# The Kathara export would reveal the operator's MTU and the probe black hole.
export_kathara_project = False
# An evaluation runs ~20 s of transfers between the hidden probes.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp-mtu.lan"
#: MTU of the operator's link: N-24 (GRE) stays >= 1280 (the same values serve the IPv6 lab), N-28 < 1472
MTU_CHOICES = list(range(1320, 1461, 20))
GRADE_PORT = 5301                 # iperf3 server of the probe h2
PROBE_TABLE = "probes"            # wan: permanent black hole toward the probes only
PROBE_RULES = "/root/probes.nft"
BLACK_HOLE_TABLE = "black_hole"   # wan: black hole toward everybody (states black_hole / icmp_restored)
BLACK_HOLE_RULES = "/root/black_hole.nft"
CLAMP_TABLE = "mss_clamp"         # r1 / r2: reference solution
CLAMP_RULES = "/root/mss_clamp.nft"
TUN_DEV = "gre1"
MIN_BYTES = 100_000               # a transfer "works" above this (≈ 0 under the black hole, ~5 MB otherwise)
ROUTERS = ('r1', 'r2', 'wan')
STUDENT_MACHINES = ('m1', 'r1', 'r2', 'm2')
WAN_IFACE = {'r1': 'eth1', 'r2': 'eth0'}   # interfaces of the students' routers toward the operator
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_TOPOLOGY = {
    'lan1': {'m1': 0, 'r1': 0, 'h1': 0},
    'wan1': {'r1': 1, 'wan': 0},
    'wan2': {'wan': 1, 'r2': 0},
    'lan2': {'r2': 1, 'm2': 0, 'h2': 0},
}
_SPECS = {
    'm1': {'color': 'lightyellow'},
    'r1': {'color': 'lightblue'},
    'wan': {'allow_connection': False, 'color': 'lightgrey'},   # operator's router: visible, no terminal
    'r2': {'color': 'lightblue'},
    'm2': {'color': 'lightyellow'},
    'h1': {'hidden': True},                                     # grading probes
    'h2': {'hidden': True},
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    wan_mtu: int = 0   # MTU of both interfaces of wan (never printed in the texts)

    @classmethod
    def generate(cls):
        data = cls()
        data.wan_mtu = random.choice(MTU_CHOICES)
        lan1, wan1, wan2, lan2, tun = random_ipv4networks(
            masks=[24, 24, 24, 24, 30],
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        data.nets.lan1, data.nets.wan1, data.nets.wan2, data.nets.lan2, data.nets.tun = lan1, wan1, wan2, lan2, tun
        # ips.m1, ips.h1, ips.m2, ips.h2, ips.r1_lan1, ips.r1_wan1, ips.wan_wan1, ips.wan_wan2, ips.r2_wan2, ips.r2_lan2
        random_ips_from_topology(data, _TOPOLOGY)
        first, second = list(tun.hosts())[:2]
        data.ips.r1_tun = IPv4Interface(f"{first}/{tun.prefixlen}")    # inner addresses of the GRE tunnel
        data.ips.r2_tun = IPv4Interface(f"{second}/{tun.prefixlen}")
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _TOPOLOGY
    _machine_specs = _SPECS
    # Learning switches, not hubs: the students' captures do not show the probes' transfers.
    _network_specs = {
        'lan1': {'mode': 'switch', 'color': 'lightyellow'},
        'wan1': {'mode': 'switch', 'color': 'lightgrey'},
        'wan2': {'mode': 'switch', 'color': 'lightgrey'},
        'lan2': {'mode': 'switch', 'color': 'lightyellow'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        self.net_config: Dict[str, NetConfigEntry] = {
            'm1': [([d.ips.m1], [(default, d.ips.r1_lan1)])],
            'h1': [([d.ips.h1], [(default, d.ips.r1_lan1)])],
            'r1': [([d.ips.r1_lan1], []), ([d.ips.r1_wan1], [(default, d.ips.wan_wan1)])],
            'wan': [([d.ips.wan_wan1], [(d.nets.lan1, d.ips.r1_wan1)]),
                    ([d.ips.wan_wan2], [(d.nets.lan2, d.ips.r2_wan2)])],
            'r2': [([d.ips.r2_wan2], [(default, d.ips.wan_wan2)]), ([d.ips.r2_lan2], [])],
            'm2': [([d.ips.m2], [(default, d.ips.r2_lan2)])],
            'h2': [([d.ips.h2], [(default, d.ips.r2_lan2)])],
        }

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("MTU, fragmentation IPv4 et découverte du PMTU"), tag="mtu")
            + tr("""
Le **MTU** (*maximum transmission unit*) d'un lien est le nombre maximal d'octets de données
qu'une trame peut y transporter : 

- **1500** sur Ethernet ; 
- **2304** dans la norme Wi-Fi (802.11),
mais une interface Wi-Fi reste en pratique à 1500 car le point d'accès limite ses trames vers
Ethernet ; 
- **9000** en général pour les *jumbo frames*, trames Ethernet étendues que la norme
IEEE ne définit pas et que chaque équipement du réseau doit accepter.

### @@sec:adjust@@ Ajuster le MTU
 
**Augmenter le MTU** réduit le nombre de paquets pour une même quantité de
données : les en-têtes IPv4 et TCP (40 octets) pèsent 2,7 % d'un paquet de 1500 octets mais
0,4 % d'un paquet de 9000, et chaque paquet en moins économise du temps de traitement
(interruptions, traversée de la pile réseau). 

Les *jumbo frames* servent ainsi sur les réseaux
locaux rapides (centres de données, stockage iSCSI ou NFS, grappes de calcul), à condition que
**toutes** les machines et tous les commutateurs du réseau les acceptent : une trame trop grande
y est jetée en silence, sans message d'erreur. Vers Internet le chemin reste de toute façon à
1500. 

**Diminuer le MTU** s'impose quand un en-tête supplémentaire s'ajoute sur un lien dont le MTU
est fixé : PPPoE (8 octets, MTU 1492 chez de nombreux fournisseurs d'accès), tunnels GRE, IPsec
ou VPN (section @@ref:gre@@). Sur un lien lent ou peu fiable (radio, satellite), des trames plus
courtes limitent aussi le coût d'une erreur de transmission (une trame corrompue est perdue en
entier) et l'attente d'un petit paquet urgent, de voix par exemple, derrière une grande trame en
cours d'émission : 1500 octets occupent un lien à 1 Mbit/s pendant 12 ms.

Un paquet IPv4 contient un en-tête de
**20 octets** (sans option) ; un écho ICMP ajoute un en-tête de **8 octets** : `ping -s 1472` émet
donc des paquets de 1500 octets, le maximum sans fragmentation sur Ethernet (`ping` affiche
`1472(1500) bytes`).

### @@sec:fragmentation@@ Fragmentation

En IPv4 un routeur qui doit émettre un paquet plus grand que le MTU du lien de
sortie le **fragmente** : chaque fragment porte le même identifiant, le bit **MF** (*more
fragments*, sauf le dernier) et un **décalage** (*offset*, en mots de 8 octets). Seul le
destinataire réassemble. La fragmentation coûte cher (un fragment perdu = tout le paquet perdu,
charge CPU, pare-feu qui ne voient le port que dans le premier fragment) ; les systèmes modernes
l'évitent en positionnant le bit **DF** (*don't fragment*) : le routeur jette alors le paquet et
renvoie à l'émetteur un message **ICMP type 3 (*destination unreachable*), code 4 (*fragmentation
needed and DF set*)** qui indique le **MTU du lien suivant** (RFC 1191).

### @@sec:pmtud@@ Découverte du MTU du chemin (PMTUD)

L'émetteur mémorise ce MTU pour la destination (cache des *routes*, 10 min par défaut,
`net.ipv4.route.mtu_expires`) et adapte la taille de ses paquets : c'est la **découverte du MTU du
chemin** (*path MTU discovery*, PMTUD). Linux positionne DF sur tout le trafic TCP. Pour voir le
PMTU appris :

```
ip route get ADRESSE          # affiche "mtu N expires Ns" quand un PMTU est mémorisé
ip route flush cache          # oublie les PMTU appris
```

### @@sec:ping@@ ping et le bit DF

L'option `-M` de `ping` (cf `man ping`) choisit le bit DF des échos émis :

```
ping -c 1 -s 1472 DEST               # défaut (-M want) : DF si le paquet tient dans le PMTU connu
ping -c 1 -M do -s 1472 DEST         # DF toujours : "Frag needed and DF set (mtu = N)" venant du
                                     #   routeur, puis "local error: message too long, mtu=N"
                                     #   quand le PMTU est connu (le paquet n'est plus émis)
ping -c 1 -M dont -s 1472 DEST       # jamais DF : les routeurs fragmentent, la réponse arrive
tracepath -n DEST                    # MTU du chemin saut par saut ("pmtu N")
```

### @@sec:capture@@ Ce que montre une capture

Avec `tcpdump -n -v -i eth0 icmp` sur l'émetteur, l'erreur apparaît sous la forme

`ROUTEUR > ÉMETTEUR: ICMP DEST unreachable - need to frag (mtu N), length 556`

l'adresse
source est celle du routeur fautif et le message cite l'en-tête du paquet refusé. Un paquet
fragmenté donne un premier fragment `flags [+]` (MF) puis des fragments `offset 1440 …
ip-proto-1` : seul le premier contient l'en-tête ICMP. La même capture sur l'interface de sortie
d'un routeur montre ce qui part vers le lien au MTU réduit et ce qui en revient.
""")
            + info_subtitle(tr("TCP, MSS et trou noir PMTUD"), tag="tcp")
            + tr("""

### @@sec:mss@@ Le MSS

Le **MSS** (*maximum segment size*) est la plus grande charge utile TCP qu'un hôte accepte de
recevoir : chacun l'annonce dans l'option `mss` de son SYN. Pour un paquet IPv4 sans option, **MSS = MTU − 40** (20
d'IPv4 + 20 de TCP) : 1460 pour un hôte Ethernet, visible dans l'option `mss` des SYN capturés.
`ss -ti` affiche pour chaque connexion `mss:` (valeur effective, 12 octets de moins quand l'option
*timestamps* est utilisée : 1448), `pmtu:`, `advmss:` et les retransmissions (`retrans`, `lost`).

### @@sec:blackhole@@ Le trou noir

TCP envoie des segments de 1500 octets avec DF ; le routeur placé devant un lien au MTU plus petit
les jette et répond par l'ICMP *fragmentation needed*… que beaucoup de pare-feu **filtrent**.
L'émetteur ne reçoit alors ni acquittement ni erreur : il retransmet le même segment, en vain.
Symptômes typiques : `ping` passe, la connexion TCP s'établit (SYN/ACK petits), les petits
échanges fonctionnent, mais tout transfert volumineux **gèle** (`iperf3` affiche 0 bit/s et des
retransmissions, une page web ne finit jamais de charger).

### @@sec:remedies@@ Les remèdes

Du côté de l'administrateur des routeurs, deux solutions existent pour remédier à ce problème :

**MSS clamping** : réécrire l'option MSS des SYN qui traversent le routeur pour que les deux
hôtes n'émettent que des segments qui passent. Avec nftables (table `inet`, hook `forward`,
priorité `mangle`, `tcp flags syn` couvre SYN et SYN/ACK) :

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set 1400
nft list ruleset
```

`tcp option maxseg size set rt mtu` utilise le MTU de la **route de sortie du routeur** (donc
de son interface de sortie) : ce n'est utile que si cette interface a elle-même le MTU réduit.

**MTU des interfaces** : `ip link set dev IFACE mtu N` sur l'interface de chaque routeur de site
tournée vers le lien au MTU réduit. Le routeur émet alors lui-même l'erreur ICMP vers ses hôtes
(elle n'est pas filtrée) et la PMTUD fonctionne de nouveau dans chaque site.

Du côté des **hôtes** seulement : `sysctl -w net.ipv4.tcp_mtu_probing=1` (RFC 4821, TCP sonde
lui-même le MTU après un trou noir) ou une route avec `mtu N`. Ces réglages ne corrigent que la
machine sur laquelle on les fait, pas les autres postes du site.
""")
            + info_subtitle(tr("Tunnel GRE et surcoût d'encapsulation"), tag="gre")
            + tr("""
Un tunnel **GRE** (*generic routing encapsulation*, RFC 2784) transporte un paquet IP dans un
autre paquet IP : l'en-tête IPv4 extérieur (**20** octets) et l'en-tête GRE (**4** octets sans
clé ni somme de contrôle) ajoutent **24 octets**. Le MTU du tunnel doit donc valoir **MTU du
chemin − 24** : le MTU par défaut d'un tunnel GRE (1476) suppose un chemin à 1500 et devient trop
grand dès que le chemin passe par un lien au MTU plus petit.

```
ip link add gre1 type gre local ADRESSE_WAN_LOCALE remote ADRESSE_WAN_DISTANTE ttl 64
ip link set gre1 mtu MTU up
ip addr add ADRESSE_TUN/30 dev gre1
ip -d link show gre1                 # "gre remote … local … pmtudisc" : DF sur le paquet extérieur
```

`local` et `remote` sont les adresses des deux routeurs sur le réseau qui les relie, `ADRESSE_TUN`
l'adresse intérieure de cette extrémité du tunnel. Le chargement du module crée aussi une
interface `gre0@NONE`, à ignorer. On teste le MTU du tunnel comme celui d'un lien :
`ping -M do -s` vers l'adresse intérieure du routeur distant. Si le MTU du tunnel est trop grand,
le paquet extérieur dépasse le MTU du chemin : erreur ICMP reçue par le routeur (pas par l'hôte
qui a émis le paquet intérieur) ou, si ces erreurs sont filtrées, disparition silencieuse.
""")
            + info_subtitle(tr("Outils"), tag="tools")
            + tr("""
| outil | usage |
|-------|-------|
| `ip -d link show [IFACE]` | MTU et paramètres des interfaces et des tunnels |
| `ip link set dev IFACE mtu N` | changer le MTU d'une interface |
| `ping -M do -s TAILLE DEST` | sonder le MTU du chemin (DF) ; `-M dont` pour laisser fragmenter |
| `tracepath -n DEST` | PMTU saut par saut |
| `ip route get DEST` / `ip route flush cache` | PMTU mémorisé / oublié |
| `tcpdump -n -v -i IFACE icmp` | erreurs ICMP (`need to frag (mtu N)`), fragments (`flags [+]`, `offset`) |
| `tcpdump -n -i IFACE 'tcp[tcpflags] & tcp-syn != 0'` | les SYN et leur option `mss` |
| `ss -ti` | `mss`, `pmtu`, `advmss`, retransmissions des connexions TCP |
| `iperf3 -s` / `iperf3 -c SERVEUR -t 5` | transfert TCP de test (`-R` : sens inverse) |
| `nft list ruleset` | règles nftables du routeur |
""")
            + info_subtitle(tr("Dépannage"), tag="troubleshooting")
            + tr("""
| symptôme | cause probable |
|----------|----------------|
| `local error: message too long, mtu=N` dès le premier `ping -M do` | un PMTU est déjà mémorisé (`ip route get`, `ip route flush cache`) |
| `ping -M do -s 1472` n'obtient ni réponse ni erreur | erreurs ICMP filtrées sur le chemin : le paquet est jeté en silence |
| `ping` passe mais `iperf3` reste à 0 bit/s | trou noir PMTUD : section @@ref:blackhole@@ |
| `iperf3` passe toujours alors que les erreurs ICMP sont filtrées | PMTU encore en cache sur la machine (10 min) ou MSS déjà réduit |
| `nft add rule … maxseg size set rt mtu` ne change rien | l'interface de sortie du routeur est à 1500 : `rt mtu` donne 1500 |
| `ping` à travers `gre1` muet, `ip -d link show gre1` correct | `local`/`remote` inversés, ou MTU du tunnel trop grand derrière un trou noir |
| `RTNETLINK answers: Operation not supported` | module `ip_gre` absent du noyau |
""")
        )

    # -- states ------------------------------------------------------------------

    def _configure_network(self):
        """Runtime configuration, applied at start (and again after a restore: addresses,
        MTU, nft tables and daemons do not survive it)."""
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTERS))
            # MTU-sized frames (no GSO/GRO super-packets): the captures show the real fragments.
            for i in range(len(self.net_config.get(m, []))):
                self.cmd(m, f"ethtool -K eth{i} gso off tso off gro off", allow_error=True)
        # The operator's link: reduced MTU on both interfaces of wan.
        self.cmd('wan', f"ip link set dev eth0 mtu {d.wan_mtu}; ip link set dev eth1 mtu {d.wan_mtu}")
        # Permanent black hole toward the grading probes only (never touched by the states).
        self.file('wan', PROBE_RULES, pmtu.nft_drop_pmtu_errors(PROBE_TABLE, daddr4=[d.ips.h1, d.ips.h2], ipv6=False))
        self.cmd('wan', f"nft delete table inet {PROBE_TABLE} 2>/dev/null; nft -f {PROBE_RULES}")
        # Black hole toward everybody, applied by the state black_hole.
        self.file('wan', BLACK_HOLE_RULES, pmtu.nft_drop_pmtu_errors(BLACK_HOLE_TABLE, ipv6=False))
        # iperf3 server of the probe h2 (the grader restarts it if needed).
        self.cmd('h2', f"iperf3 -s -D -p {GRADE_PORT} >/dev/null 2>&1")

    @sre_state(user_allowed=False)
    def initial(self):
        self._configure_network()
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN)

    @sre_state(user_allowed=False)
    def restore(self):
        self._configure_network()

    # the descriptions of the states are evaluated at import time, before _TRANSLATIONS: inline English too
    @sre_state(user_allowed=True,
               description=tr("Trou noir PMTUD : le routeur de l'opérateur (wan) n'émet plus les erreurs ICMP "
                              "« fragmentation needed » ; les PMTU déjà appris par m1, m2, r1 et r2 sont oubliés",
                              en="PMTUD black hole: the operator's router (wan) no longer emits the ICMP "
                                 "\"fragmentation needed\" errors; the PMTUs already learned by m1, m2, r1 and r2 "
                                 "are forgotten"))
    def black_hole(self):
        self.cmd('wan', f"nft delete table inet {BLACK_HOLE_TABLE} 2>/dev/null; nft -f {BLACK_HOLE_RULES}")
        for m in STUDENT_MACHINES:
            # a PMTU learned in part 1 would hide the black hole for 10 minutes
            self.cmd(m, "ip route flush cache", allow_error=True)

    @sre_state(user_allowed=True,
               description=tr("ICMP rétabli : le routeur de l'opérateur émet de nouveau les erreurs ICMP",
                              en="ICMP restored: the operator's router emits the ICMP errors again"))
    def icmp_restored(self):
        self.cmd('wan', f"nft delete table inet {BLACK_HOLE_TABLE} 2>/dev/null; true")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution (idempotent): MSS clamping on r1 and r2, GRE tunnel at the right MTU.

        The probes' black hole does not depend on the states, so nothing is done on wan."""
        d = self.data
        n = d.wan_mtu
        for r in ('r1', 'r2'):
            self.file(r, CLAMP_RULES, pmtu.nft_mss_clamp(CLAMP_TABLE, mss4=pmtu.mss_for(n)))
            self.cmd(r, f"nft delete table inet {CLAMP_TABLE} 2>/dev/null; nft -f {CLAMP_RULES}")
        tunnel = (('r1', d.ips.r1_wan1.ip, d.ips.r2_wan2.ip, d.ips.r1_tun),
                  ('r2', d.ips.r2_wan2.ip, d.ips.r1_wan1.ip, d.ips.r2_tun))
        for r, local, remote, inner in tunnel:
            self.cmd(r, f"ip link del {TUN_DEV} 2>/dev/null; "
                        f"ip link add {TUN_DEV} type gre local {local} remote {remote} ttl 64; "
                        f"ip link set {TUN_DEV} mtu {n - pmtu.GRE_OVERHEAD} up; "
                        f"ip addr add {inner} dev {TUN_DEV}")


# ---------------------------------------------------------------------------
# Grade
# ---------------------------------------------------------------------------


def _float(s, default=None):
    try:
        return float(str(s).strip().replace(',', '.'))
    except (TypeError, ValueError):
        return default


def _norm(s) -> str:
    return (s or "").strip().lower()


def _is(answer, expected) -> bool:
    """A numeric form answer equals *expected*."""
    return _float(answer) == float(expected)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        n = d.wan_mtu
        mss = pmtu.mss_for(n)
        tun_mtu = n - pmtu.GRE_OVERHEAD
        h2 = str(d.ips.h2.ip)
        r2_tun = str(d.ips.r2_tun.ip)
        wan_addr = {'r1': str(d.ips.r1_wan1.ip), 'r2': str(d.ips.r2_wan2.ip)}

        # ---------------- diagnostics kept in the archive (also used below) -----------
        rulesets, links = {}, {}
        for m in STUDENT_MACHINES:
            rulesets[m], _ = self.test(m, "nft list ruleset", allow_error=True)
            links[m], _ = self.test(m, "ip -j -d link show", allow_error=True)
            for c in ("ip route show", "sysctl net.ipv4.tcp_mtu_probing"):
                self.test(m, c, allow_error=True)
        self.test('m1', f"ip route get {d.ips.m2.ip}", allow_error=True)

        # ---------------- step 1: forget the learned PMTU, make sure the server runs -----
        # A PMTU learned from a fix that has since been removed would mask the black hole for
        # 10 minutes; on r1 a cold cache makes the oversized tunnel ping deterministic.
        flush = "ip route flush cache; echo flushed"
        self.test('h1', flush, step=1, allow_error=True)
        self.test('r1', flush, step=1, allow_error=True)
        self.test('h2', f"{flush}; pgrep -f 'iperf3 -s -D -p {GRADE_PORT}' >/dev/null || "
                        f"iperf3 -s -D -p {GRADE_PORT} >/dev/null 2>&1; echo server", step=1, allow_error=True)

        # ---------------- step 2: transfers between the probes (black hole for them) ------
        forward = tc.iperf3_cmd(h2, GRADE_PORT, seconds=2)
        backward = tc.iperf3_cmd(h2, GRADE_PORT, seconds=2, reverse=True)
        transfer_cmd = (f"{forward} >/tmp/.sre_mtu_a 2>&1; {backward} >/tmp/.sre_mtu_r 2>&1; "
                        f'echo "===A"; cat /tmp/.sre_mtu_a; echo "===R"; cat /tmp/.sre_mtu_r')
        transfer_out, _ = self.test('h1', transfer_cmd, step=2, timeout=30, allow_error=True)
        flow_a = tc.parse_iperf3(tc.section_text(transfer_out, 'A'))
        flow_r = tc.parse_iperf3(tc.section_text(transfer_out, 'R'))
        connected = eval_ping(self, 'h1', 'h2', step=2, count=2, deadline=3,
                              net_config=self.net_scheme.net_config, allow_error=True)

        # ---------------- step 2: the tunnel seen from r1 ---------------------------------
        fit = pmtu.max_ping_payload(tun_mtu)
        gre_probe = (f'echo "===T"; ping -4 -n -c 2 -i 0.3 -w 3 {r2_tun} 2>&1; '
                     f'echo "===FIT"; {pmtu.pmtu_ping_cmd(r2_tun, fit, count=2, deadline=3, interval=0.3)} 2>&1; '
                     f'echo "===OVER"; {pmtu.pmtu_ping_cmd(r2_tun, fit + 1, count=1, deadline=2)} 2>&1')
        gre_out, _ = self.test('r1', gre_probe, step=2, timeout=20, allow_error=True)
        tunnel_pings = pmtu.ping_received(tc.section_text(gre_out, 'T'))
        fit_ok = pmtu.ping_received(tc.section_text(gre_out, 'FIT')) >= 1
        over_ok = pmtu.parse_ping_errors(tc.section_text(gre_out, 'OVER'))['too_long_mtu'] == tun_mtu

        # ---------------- configuration of the students' routers -------------------------
        mtus = {r: pmtu.iface_mtus(links[r]) for r in ('r1', 'r2')}
        wan_mtu_reduced = {r: (mtus[r].get(WAN_IFACE[r]) or 1500) <= n for r in ('r1', 'r2')}
        clamp_ok = any(pmtu.mss_clamped(pmtu.mss_clamp_rules(rulesets[r]), 4, mss, rt_mtu_ok=wan_mtu_reduced[r])
                       for r in ('r1', 'r2'))
        mtu_fix_ok = all(wan_mtu_reduced.values())
        gre = {}
        for r in ('r1', 'r2'):
            link = next((l for l in pmtu.parse_ip_links_json(links[r]) if l.get('ifname') == TUN_DEV), {})
            gre[r] = pmtu.tunnel_info(link)

        payload = pmtu.max_ping_payload(n)   # largest ping payload that crosses the operator

        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `r1` eth0 (`{r1_lan1}`) |
| `wan1` | `{wan1}` | `r1` eth1 (`{r1_wan1}`), `wan` eth0 (`{wan_wan1}`) |
| `wan2` | `{wan2}` | `wan` eth1 (`{wan_wan2}`), `r2` eth0 (`{r2_wan2}`) |
| `lan2` | `{lan2}` | `r2` eth1 (`{r2_lan2}`), `m2` (`{m2}`) |
| `tun` (partie 3) | `{tun}` | extrémités du tunnel GRE : `r1` (`{r1_tun}`), `r2` (`{r2_tun}`) |
""").format(lan1=d.nets.lan1, wan1=d.nets.wan1, wan2=d.nets.wan2, lan2=d.nets.lan2, tun=d.nets.tun,
            m1=d.ips.m1.ip, r1_lan1=d.ips.r1_lan1.ip, r1_wan1=d.ips.r1_wan1.ip, wan_wan1=d.ips.wan_wan1.ip,
            wan_wan2=d.ips.wan_wan2.ip, r2_wan2=d.ips.r2_wan2.ip, r2_lan2=d.ips.r2_lan2.ip, m2=d.ips.m2.ip,
            r1_tun=d.ips.r1_tun.ip, r2_tun=d.ips.r2_tun.ip)

        # ---------------- organisation ----------------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            description=tr("""
Ce TP étudie le **MTU** des liens, la **fragmentation** IPv4, la **découverte du MTU du chemin**
(PMTUD), le **trou noir PMTUD** que provoque le filtrage des erreurs ICMP, ses remèdes (**MSS
clamping**, MTU des interfaces) et le **surcoût d'encapsulation** d'un tunnel **GRE**. Lisez
l'onglet **Informations** : c'est le cours sur ces notions, avec les commandes utiles.

**La maquette.** Deux sites, `lan1` (`m1`) et `lan2` (`m2`), sont reliés par leurs routeurs `r1`
et `r2` à travers le réseau d'un **opérateur**, représenté par le routeur `wan`. Vous administrez
`m1`, `r1`, `r2` et `m2` ; `wan` n'est **pas accessible** (pas de terminal, MTU non modifiable) :
c'est l'équipement de l'opérateur, dont le MTU est **inférieur à 1500** et que vous allez mesurer
en l'observant depuis `r1` et `r2`.
""")
            + addressing
            + tr("""
Déjà en place (ne pas modifier) : adresses IP et routes statiques sur toutes les machines, routage
IPv4 activé sur `r1`, `r2` et `wan`, noms dans `/etc/hosts` (`ping m2`, `ping r2_lan2`,
`ping wan_wan1` fonctionnent), *offloads* GSO/GRO désactivés (les trames observées ont la taille
du MTU). La configuration d'une partie terminée reste en place : le MSS clamping ou le MTU réduit
de la partie 2 n'empêche pas le tunnel de la partie 3.

**Sondes de notation.** Deux hôtes cachés, `h1` dans `lan1` et `h2` dans `lan2`, servent aux
mesures : ce sont des **postes ordinaires** (MTU 1500, PMTUD classique, aucun réglage possible de
votre part) et l'opérateur **filtre en permanence** les erreurs ICMP qui leur sont destinées. Ils
représentent les utilisateurs des deux sites : seule une correction faite sur **vos routeurs**
`r1` et `r2` rend leurs transferts possibles (partie 2), pas une correction faite sur `m1` et
`m2` (`tcp_mtu_probing`, route avec `mtu` : ces réglages d'hôte ne comptent pas, les sondes
n'étant pas administrables). Les réseaux de la maquette sont des commutateurs : vos captures ne
montrent pas les transferts des sondes, seulement leurs requêtes ARP ; leurs adresses apparaissent
aussi dans `ip neigh` sur `r1` et `r2`.

**États.** L'onglet **Appliquer une configuration** propose deux états que vous appliquez
vous-même au moment indiqué dans les questions ; l'évaluation ne dépend pas de l'état choisi :

- `black_hole` : l'opérateur cesse d'émettre les erreurs ICMP « fragmentation needed » vers tout
  le monde (et les PMTU déjà appris par `m1`, `m2`, `r1`, `r2` sont oubliés) ;
- `icmp_restored` : l'opérateur émet de nouveau ces erreurs.

**Plan du TP.** Trois parties, à faire dans l'ordre (entre parenthèses : les points, puis la
section du cours de l'onglet **Informations** à lire) :

1. **Découverte du MTU** de l'opérateur avec `ping -M do`, `tracepath`, `tcpdump` et le cache
   des routes ; fragmentation sans DF (10 points, formulaire ; section @@ref:mtu@@).
2. **Trou noir PMTUD** : appliquer l'état `black_hole`, constater le gel des transferts TCP,
   diagnostiquer, puis corriger sur `r1` / `r2` (16 points : transferts entre les sondes,
   configuration, formulaire ; section @@ref:tcp@@).
3. **Tunnel GRE** entre `r1` et `r2` à travers l'opérateur, au bon MTU (14 points :
   configuration et tests depuis `r1`, formulaire ; section @@ref:gre@@).

Les sections @@ref:tools@@ (outils) et @@ref:troubleshooting@@ (dépannage) servent aux trois
parties.

**Évaluation.** Chaque évaluation (≈ 20 s) lance des transferts `iperf3` entre `h1` et `h2`,
vérifie la configuration de `r1` et `r2`, teste le tunnel GRE depuis `r1` et lit vos réponses aux
formulaires. Elle vide le cache des PMTU de `r1` et des sondes ; elle ne modifie rien d'autre.
""")
            + instructor(tr("""
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet : le MTU de
l'opérateur y vaut **{n}** octets (charge utile maximale de `ping` : {payload} ; MSS : {mss} ; MTU du
tunnel GRE : {tun_mtu}).

- L'état `final` (onglet *Appliquer une configuration*) applique la solution des parties 2 et 3 (MSS
  clamping sur `r1` et `r2`, tunnel `gre1`) et remplit les formulaires. Il ne touche pas à `wan` :
  l'état `black_hole` ou `icmp_restored` en cours reste en place.
- `wan` a le MTU {n} sur ses deux interfaces et deux tables nftables : `probes`, permanente, jette les
  erreurs ICMP *fragmentation needed* destinées aux sondes cachées `h1` (`{h1}`) et `h2` (`{h2}`) ;
  `black_hole`, posée et retirée par les deux états, les jette pour tout le monde.
- Évaluation (une dizaine de secondes) : cache des PMTU vidé sur `h1`, `h2` et `r1` ; transfert `iperf3`
  de 2 s de `h1` vers `h2` puis en sens inverse (réussi au-delà de 100 ko reçus) et `ping` de `h1` vers
  `h2` ; lecture des règles nftables et des MTU de `r1` et `r2` ; pour le tunnel, `ip -j -d link show`
  sur `r1` et `r2` puis, depuis `r1`, un `ping` vers l'adresse `tun` de `r2`, un `ping -M do -s {fit}`
  qui doit passer et un `ping -M do -s {over}` qui doit être refusé localement.
- Une correction faite seulement sur `m1` et `m2` (`tcp_mtu_probing`, route avec `mtu`) fait passer les
  essais de l'étudiant mais pas les transferts des sondes : les 10 points des transferts sont perdus.
""").format(n=n, payload=payload, mss=mss, tun_mtu=tun_mtu, h1=d.ips.h1.ip, h2=d.ips.h2.ip,
            fit=fit, over=fit + 1)),
        )

        # =====================================================================
        # Partie 1 — Découverte du MTU
        # =====================================================================
        part1 = self.add_grade_part(no_tr("part1"), tr("Partie 1 — Découverte du MTU de l'opérateur"))
        q1_answers = {
            "mtu": str(n), "payload": str(payload), "icmp_type": "3", "icmp_code": "4", "fragmenter": "wan",
            "mss": str(mss), "command": "ip route get",
            "capture": f"{d.ips.wan_wan1.ip} > {d.ips.m1.ip}: ICMP {d.ips.m2.ip} unreachable - need to frag (mtu {n}), length 556",
            "explanation": "L'adresse source est celle de wan côté wan1, le routeur qui n'a pas pu émettre le paquet ; "
                           "le MTU annoncé est celui de son lien de sortie, que m1 adopte comme PMTU vers m2.",
        }
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Découverte du MTU de l'opérateur"),
            description=tr("""
1. Sur `m1`, relevez le MTU de `eth0` (`ip link`), puis vérifiez que `ping -c 1 -M do -s 1472 r1_lan1`
   passe : 1472 octets de charge utile font un paquet de 1500 octets.
2. Lancez `tcpdump -n -v -i eth0 icmp` dans un second terminal de `m1`, puis
   `ping -c 3 -M do -s 1472 m2`. Observez le message d'erreur de `ping`, l'adresse qui l'émet
   et le MTU qu'il annonce ; retrouvez-le dans la capture (`need to frag`). Pourquoi le deuxième
   `ping` échoue-t-il différemment du premier (`local error`) ? Consultez `ip route get` vers
   `m2`, puis `ip route flush cache`.
3. Par dichotomie avec `ping -M do -s TAILLE m2`, trouvez la plus grande charge utile qui traverse
   l'opérateur sans erreur, et comparez avec `tracepath -n m2`.
4. Sans DF : `ping -c 1 -M dont -s 1472 m2`. La réponse arrive ; dans la capture sur `m1` (et sur
   `r1`, `tcpdump -n -v -i eth1 icmp`), repérez les fragments (`flags [+]`, `offset`) et
   déterminez quelle machine a fragmenté le paquet aller, et laquelle la réponse.
5. Déduisez-en le MSS TCP qu'un hôte devrait annoncer pour que ses segments traversent
   l'opérateur sans fragmentation.
""")
            + instructor(tr("""
**Solution.** Sur `m1` (MTU de `eth0` : 1500) :

```
ping -c 1 -M do -s 1472 r1_lan1  # passe : 1472 + 28 = 1500
ping -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1}) icmp_seq=1 Frag needed and DF set (mtu = {n})
# puis, deux fois : ping: local error: message too long, mtu={n}
ip route get {m2}  # ... cache expires ...sec mtu {n}
ip route flush cache
ping -c 1 -M do -s {payload} m2  # passe : {payload} + 28 = {n}
ping -c 1 -M do -s {payload1} m2  # refusé
tracepath -n m2  # Resume: pmtu {n} hops 4 back 4
ping -c 1 -M dont -s 1472 m2  # passe : wan fragmente
```

- L'erreur est un ICMP type 3 code 4 émis par `wan` (son adresse côté `wan1`, `{wan1}`). `tcpdump`
  affiche `{wan1} > {m1}: ICMP {m2} unreachable - need to frag (mtu {n})`.
- Le premier `ping` reçoit l'erreur du routeur ; `m1` mémorise alors le PMTU vers `m2` (10 min) et
  refuse lui-même les suivants (`local error`), sans rien émettre.
- Sans DF, `wan` fragmente le paquet aller : un fragment de {first} octets marqué `flags [+]`, puis le
  reste à l'`offset {offset}`. La réponse de `m2`, de 1500 octets elle aussi, est fragmentée par `wan`
  dans l'autre sens.
- MSS : {n} − 40 = **{mss}**.
""").format(n=n, payload=payload, payload1=payload + 1, mss=mss, m1=d.ips.m1.ip, m2=d.ips.m2.ip,
            wan1=d.ips.wan_wan1.ip, first=(n - pmtu.IPV4_HDR) // 8 * 8 + pmtu.IPV4_HDR,
            offset=(n - pmtu.IPV4_HDR) // 8 * 8))
            + tr("""
**Mesures.**

- MTU du lien de l'opérateur, en octets : @@{mtu:[0-9]+}@@
- Plus grande charge utile de `ping -M do -s` qui traverse l'opérateur sans erreur : @@{payload:[0-9]+}@@
- Message ICMP reçu par `m1` : type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Pour un paquet de 1500 octets émis **sans** DF par `m1` vers `m2`, la machine qui le fragmente
  est : @@{fragmenter:>m1|r1|wan|r2|personne>>>nobody}@@
- MSS TCP (sans option IP ni TCP) adapté au lien de l'opérateur : @@{mss:[0-9]+}@@
- Commande qui affiche, sur `m1`, le PMTU mémorisé vers `m2` : @@{command:>ip route get|ip link|arp -a|ss -s}@@
- Ligne de `tcpdump` qui montre l'erreur ICMP reçue par `m1` (étape 2) : @@{capture:.*}@@
- Ce qu'indiquent l'adresse source et le MTU annoncé par cette erreur : @@{explanation:.*}@@
""")
            + instructor(tr("""
**Réponses.**

- MTU de l'opérateur : `{mtu}` ; charge utile maximale : `{payload}` ({mtu} − 20 − 8)
- ICMP type `{icmp_type}` (*destination unreachable*), code `{icmp_code}` (*fragmentation needed and DF set*)
- sans DF c'est `{fragmenter}` qui fragmente : le routeur dont le lien de sortie est trop petit
- MSS : `{mss}` ({mtu} − 40) ; PMTU mémorisé : `{command}`
- ligne attendue : `{capture}` ; l'adresse source est celle de `wan` côté `wan1` (le routeur qui n'a pas pu
  émettre le paquet sur son lien de sortie) et le MTU annoncé celui de ce lien, que `m1` adopte comme PMTU
  vers `m2`. Ces deux derniers champs ne sont pas notés.
""").format(**q1_answers)),
            cheat_answers={"final": q1_answers},
        )
        self.add_grade_element(
            title=no_tr("mtu_wan"), max_grade=3, grade_part=part1,
            grade=3 * int(_is(q1.get("mtu"), n)),
            description=tr("MTU du lien de l'opérateur"),
        )
        self.add_grade_element(
            title=no_tr("max_payload"), max_grade=2, grade_part=part1,
            grade=2 * int(_is(q1.get("payload"), payload)),
            description=tr("plus grande charge utile de ping -M do qui traverse"),
        )
        self.add_grade_element(
            title=no_tr("icmp_frag_needed"), max_grade=1, grade_part=part1,
            grade=int(_is(q1.get("icmp_type"), 3) and _is(q1.get("icmp_code"), 4)),
            description=tr("type et code du message ICMP fragmentation needed"),
        )
        self.add_grade_element(
            title=no_tr("fragmenting_machine"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get("fragmenter")) == "wan"),
            description=tr("machine qui fragmente un paquet sans DF"),
        )
        self.add_grade_element(
            title=no_tr("mss_v4"), max_grade=2, grade_part=part1,
            grade=2 * int(_is(q1.get("mss"), mss)),
            description=tr("MSS TCP adapté au lien de l'opérateur"),
        )
        self.add_grade_element(
            title=no_tr("pmtu_command"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get("command")) == "ip route get"),
            description=tr("commande qui affiche le PMTU mémorisé"),
        )

        # =====================================================================
        # Partie 2 — Trou noir PMTUD
        # =====================================================================
        part2 = self.add_grade_part(no_tr("part2"), tr("Partie 2 — Trou noir PMTUD et correction"))
        q2_answers = {
            "fix": "mss_clamping",
            "rt_mtu": "rt mtu prend le MTU de la route de sortie, donc de eth1 (1500) : le MSS reste 1460. "
                      "Il faut abaisser le MTU de eth1 au MTU de l'opérateur, ou fixer la valeur.",
        }
        q2 = self.question_form(
            section=self.section(0),
            title=tr("Trou noir PMTUD et correction"),
            description=tr("""
1. Lancez `iperf3 -s` sur `m2`, puis `iperf3 -c m2 -t 5` sur `m1` : le transfert passe (notez
   le débit). Dans un autre terminal de `m1`, `ss -ti dst m2` pendant le transfert montre `mss`
   et `pmtu`.
2. Appliquez l'état **`black_hole`** (onglet *Appliquer une configuration*) : l'opérateur
   n'émet plus d'erreur ICMP et les PMTU appris sont oubliés. Vérifiez que `ping m2` passe
   toujours, puis relancez `timeout 20 iperf3 -c m2 -t 5` : que se passe-t-il ? Observez avec
   `ss -ti dst m2` (retransmissions, `mss`) et `tcpdump -n -i eth1 'tcp or icmp'` sur `r1`
   (segments de 1500 octets qui partent, rien ne revient).
3. Corrigez le problème **sur `r1` et/ou `r2`** (onglet *Informations*, section @@ref:remedies@@) : MSS clamping
   avec nftables, ou MTU réduit sur les interfaces tournées vers l'opérateur. Vérifiez que le
   transfert `iperf3` passe de nouveau et, dans une capture des SYN sur `r1`, la nouvelle valeur
   de l'option `mss`.
4. Les transferts notés se font entre deux postes cachés de `lan1` et `lan2` qui restent
   derrière le trou noir quoi qu'il arrive : votre correction doit être en place sur les
   routeurs au moment de l'évaluation. `black_hole` peut rester appliqué ou non, au choix.
""")
            + instructor(tr("""
**Solution.** Avant `black_hole`, `iperf3 -c m2 -t 5` donne plusieurs dizaines de Mbit/s. Après, `ping m2`
passe encore mais `iperf3` affiche `0.00 Bytes` côté *receiver* : `ss -ti dst {m2}` montre
`mss:1448 pmtu:1500` et des retransmissions, et sur `r1` les segments de 1500 octets partent vers `wan`
sans qu'aucune erreur ICMP ne revienne.

Correction A, MSS clamping, sur `r1`, sur `r2` ou sur les deux (c'est ce qu'applique l'état `final`, sur
les deux routeurs, avec une table équivalente nommée `{clamp_table}` chargée depuis `{clamp_rules}`) :

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss}
```

Correction B, MTU des interfaces tournées vers l'opérateur, sur les **deux** routeurs :

```
ip link set dev eth1 mtu {n}  # sur r1
ip link set dev eth0 mtu {n}  # sur r2
```

- Vérification : `iperf3 -c m2 -t 5` passe de nouveau. Avec A, `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'`
  sur `r1` montre `mss {mss}` dans le SYN et le SYN/ACK. Avec B, c'est `r1` (ou `r2`) qui répond à l'hôte par
  *fragmentation needed* (`mtu {n}`) : la PMTUD fonctionne de nouveau dans chaque site.
- A sur un seul routeur suffit : SYN et SYN/ACK le traversent tous les deux. B sur `r1` seul laisse le sens
  `h2` → `h1` dans le trou noir.
- Toute valeur de MSS ≤ {mss} convient. `… size set rt mtu` ne compte que si l'interface WAN du routeur
  est déjà à {n} (correction B).
- Évaluation : `bh_forward` et `bh_backward` (transferts entre les sondes, 5 points chacun), `bh_connectivity`,
  `bh_config` (règle de clamping ≤ {mss} dans un hook routé de `r1` ou de `r2`, ou MTU ≤ {n} sur `eth1` de
  `r1` **et** `eth0` de `r2`).
""").format(n=n, mss=mss, m2=d.ips.m2.ip, clamp_table=CLAMP_TABLE, clamp_rules=CLAMP_RULES))
            + tr("""
**Questions.**

- Correction que vous avez mise en place : @@{fix:>MSS clamping nftables sur r1 et/ou r2>>>mss_clamping|MTU des interfaces WAN de r1 et r2 abaissé>>>wan_mtu|net.ipv4.tcp_mtu_probing sur m1 et m2>>>host_probing|route avec mtu sur m1 et m2>>>host_route}@@
- Un collègue propose `tcp option maxseg size set rt mtu` sur `r1`, sans rien changer d'autre. Pourquoi
  cela ne corrige-t-il pas le trou noir tant que `eth1` de `r1` garde un MTU de 1500, et que faudrait-il
  faire pour que cette règle fonctionne ? @@{rt_mtu:.*}@@
""")
            + instructor(tr("""
**Réponses.** `MSS clamping nftables sur r1 et/ou r2` ou `MTU des interfaces WAN de r1 et r2 abaissé`,
selon la correction faite (2 points) ; les deux autres choix ne corrigent que `m1` et `m2` : 0. Sur
`rt mtu` (non noté) : il vaut le MTU de la route de sortie du paquet sur `r1`, donc celui de `eth1` : 1500,
soit un MSS de 1460, inchangé. `r1` ignore le MTU de l'opérateur : l'erreur ICMP de `wan` est destinée à la
source du paquet, pas à `r1`, et elle est filtrée. Il faut `ip link set dev eth1 mtu {n}` sur `r1` (et
`eth0` sur `r2`), ou fixer la valeur (`size set {mss}`).
""").format(n=n, mss=mss)),
            cheat_answers={"final": q2_answers},
        )
        for tag, flow, description in (
                ('forward', flow_a, tr("transfert TCP de h1 vers h2 entre les sondes malgré le trou noir")),
                ('backward', flow_r, tr("transfert TCP de h2 vers h1 entre les sondes malgré le trou noir"))):
            self.add_grade_element(
                title=no_tr(f"bh_{tag}"), max_grade=5, grade_part=part2,
                grade=5 * int((flow.get('bytes') or 0) >= MIN_BYTES),
                description=description,
            )
        # the ping passes on a fresh project too: it only counts once a fix is in place on the routers
        self.add_grade_element(
            title=no_tr("bh_connectivity"), max_grade=2, grade_part=part2,
            grade=2 * int(connected and (clamp_ok or mtu_fix_ok)),
            description=tr("connectivité IP conservée entre les deux sites par la correction (ping h1 → h2)"),
        )
        self.add_grade_element(
            title=no_tr("bh_config"), max_grade=2, grade_part=part2,
            grade=2 * int(clamp_ok or mtu_fix_ok),
            description=tr("MSS clamping sur r1 ou r2, ou MTU réduit sur les interfaces WAN de r1 et r2"),
        )
        self.add_grade_element(
            title=no_tr("bh_q_fix"), max_grade=2, grade_part=part2, scope=CHOICE_SCOPE,
            grade=2 * int(_norm(q2.get("fix")) in ("mss_clamping", "wan_mtu")),
            description=tr("correction faite sur les routeurs"),
        )

        # =====================================================================
        # Partie 3 — Tunnel GRE
        # =====================================================================
        part3 = self.add_grade_part(no_tr("part3"), tr("Partie 3 — Tunnel GRE et surcoût d'encapsulation"))
        q3_answers = {"overhead": str(pmtu.GRE_OVERHEAD), "mtu_tunnel": str(tun_mtu)}
        q3 = self.question_form(
            section=self.section(0),
            title=tr("Tunnel GRE entre r1 et r2"),
            description=tr("""
1. Créez un tunnel GRE `gre1` entre `r1` et `r2`, dont les extrémités sont leurs adresses sur
   les réseaux de l'opérateur (`wan1` / `wan2`) et les adresses intérieures celles du réseau
   `tun` du plan d'adressage de la question « Organisation du TP » (`ip link add … type gre local … remote … ttl 64`, `ip addr add`,
   `ip link set … up`). Vérifiez `ping` entre les deux adresses `tun`.
2. Calculez le MTU que doit avoir le tunnel pour qu'aucun paquet encapsulé ne dépasse le MTU de
   l'opérateur (surcoût GRE : en-tête IPv4 + en-tête GRE). Réglez-le des deux côtés
   (`ip link set gre1 mtu …`) et vérifiez-le avec `ip -d link show gre1`.
3. Depuis `r1`, testez avec `ping -M do -s TAILLE ADRESSE_TUN_DE_R2` : la plus grande charge
   utile qui passe doit correspondre au MTU du tunnel, et un octet de plus doit être refusé
   localement (`message too long`). Capturez sur `eth1` de `r1` (`tcpdump -n -v -i eth1 proto gre`)
   pour voir les paquets encapsulés et leur taille.
""")
            + instructor(tr("""
**Solution.** Sur `r1` :

```
ip link add gre1 type gre local {r1_wan} remote {r2_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r1_tun} dev gre1
```

Sur `r2` :

```
ip link add gre1 type gre local {r2_wan} remote {r1_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r2_tun} dev gre1
```

- MTU du tunnel : {n} − 24 (20 d'IPv4 + 4 de GRE) = **{tun_mtu}**. Sans réglage, `gre1` reste à 1476.
- Vérification depuis `r1` : `ping {r2_tun_ip}` passe ; `ping -M do -s {fit} {r2_tun_ip}` passe
  ({fit} + 28 = {tun_mtu}) ; `ping -M do -s {over} {r2_tun_ip}` répond
  `local error: message too long, mtu={tun_mtu}`. `tcpdump -n -v -i eth1 proto gre` montre des paquets
  extérieurs d'au plus {n} octets, avec DF (`pmtudisc`).
- Évaluation : `gre_r1` et `gre_r2` (type `gre`, `local` / `remote` égaux aux adresses `wan1` / `wan2`,
  MTU {tun_mtu} : 1 point chacun), `gre_reachable`, `gre_pmtu` (les deux `ping -M do` ci-dessus, cache de
  `r1` vidé : sans MTU réglé sur `gre1`, le paquet trop grand part et n'est pas refusé localement).
- Les corrections de la partie 2 peuvent rester en place, et le tunnel fonctionne avec ou sans `black_hole`.
""").format(n=n, tun_mtu=tun_mtu, r1_wan=wan_addr['r1'], r2_wan=wan_addr['r2'],
            r1_tun=d.ips.r1_tun, r2_tun=d.ips.r2_tun,
            r2_tun_ip=r2_tun, fit=fit, over=fit + 1))
            + tr("""
**MTU du tunnel.**

- Surcoût d'encapsulation d'un tunnel GRE sur IPv4 (sans clé ni somme de contrôle), en octets : @@{overhead:[0-9]+}@@
- MTU à configurer sur `gre1` : @@{mtu_tunnel:[0-9]+}@@
""")
            + instructor(tr("""
**Réponses.** surcoût `{overhead}` octets (20 d'IPv4 + 4 de GRE) ; MTU de `gre1` : `{mtu_tunnel}`
({n} − {overhead}).
""").format(n=n, **q3_answers)),
            cheat_answers={"final": q3_answers},
        )
        for r in ('r1', 'r2'):
            other = 'r2' if r == 'r1' else 'r1'
            info = gre[r]
            self.add_grade_element(
                title=no_tr(f"gre_{r}"), max_grade=3, grade_part=part3,
                grade=int(info['kind'] == 'gre')
                + int(info['local'] == wan_addr[r] and info['remote'] == wan_addr[other])
                + int(info['mtu'] == tun_mtu),
                description=tr("tunnel gre1 sur {r} : type GRE, extrémités, MTU").format(r=r),
            )
        self.add_grade_element(
            title=no_tr("gre_reachable"), max_grade=2, grade_part=part3,
            grade=2 * int(tunnel_pings >= 1),
            description=tr("ping de r1 vers r2 à travers le tunnel"),
        )
        self.add_grade_element(
            title=no_tr("gre_pmtu"), max_grade=3, grade_part=part3,
            grade=3 * int(fit_ok and over_ok),
            description=tr("le plus grand paquet passe dans le tunnel, un octet de plus est refusé localement"),
        )
        self.add_grade_element(
            title=no_tr("gre_q_overhead"), max_grade=1, grade_part=part3,
            grade=int(_is(q3.get("overhead"), pmtu.GRE_OVERHEAD)),
            description=tr("surcoût d'encapsulation GRE"),
        )
        self.add_grade_element(
            title=no_tr("gre_q_mtu"), max_grade=2, grade_part=part3,
            grade=2 * int(_is(q3.get("mtu_tunnel"), tun_mtu)),
            description=tr("MTU du tunnel"),
        )

_TRANSLATIONS = {
    'en': {
        """

### @@sec:mss@@ Le MSS

Le **MSS** (*maximum segment size*) est la plus grande charge utile TCP qu'un hôte accepte de
recevoir : chacun l'annonce dans l'option `mss` de son SYN. Pour un paquet IPv4 sans option, **MSS = MTU − 40** (20
d'IPv4 + 20 de TCP) : 1460 pour un hôte Ethernet, visible dans l'option `mss` des SYN capturés.
`ss -ti` affiche pour chaque connexion `mss:` (valeur effective, 12 octets de moins quand l'option
*timestamps* est utilisée : 1448), `pmtu:`, `advmss:` et les retransmissions (`retrans`, `lost`).

### @@sec:blackhole@@ Le trou noir

TCP envoie des segments de 1500 octets avec DF ; le routeur placé devant un lien au MTU plus petit
les jette et répond par l'ICMP *fragmentation needed*… que beaucoup de pare-feu **filtrent**.
L'émetteur ne reçoit alors ni acquittement ni erreur : il retransmet le même segment, en vain.
Symptômes typiques : `ping` passe, la connexion TCP s'établit (SYN/ACK petits), les petits
échanges fonctionnent, mais tout transfert volumineux **gèle** (`iperf3` affiche 0 bit/s et des
retransmissions, une page web ne finit jamais de charger).

### @@sec:remedies@@ Les remèdes

Du côté de l'administrateur des routeurs, deux solutions existent pour remédier à ce problème :

**MSS clamping** : réécrire l'option MSS des SYN qui traversent le routeur pour que les deux
hôtes n'émettent que des segments qui passent. Avec nftables (table `inet`, hook `forward`,
priorité `mangle`, `tcp flags syn` couvre SYN et SYN/ACK) :

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set 1400
nft list ruleset
```

`tcp option maxseg size set rt mtu` utilise le MTU de la **route de sortie du routeur** (donc
de son interface de sortie) : ce n'est utile que si cette interface a elle-même le MTU réduit.

**MTU des interfaces** : `ip link set dev IFACE mtu N` sur l'interface de chaque routeur de site
tournée vers le lien au MTU réduit. Le routeur émet alors lui-même l'erreur ICMP vers ses hôtes
(elle n'est pas filtrée) et la PMTUD fonctionne de nouveau dans chaque site.

Du côté des **hôtes** seulement : `sysctl -w net.ipv4.tcp_mtu_probing=1` (RFC 4821, TCP sonde
lui-même le MTU après un trou noir) ou une route avec `mtu N`. Ces réglages ne corrigent que la
machine sur laquelle on les fait, pas les autres postes du site.
""": """

### @@sec:mss@@ The MSS

The **MSS** (*maximum segment size*) is the largest TCP payload a host accepts to receive: each host
announces it in the `mss` option of its SYN. For an IPv4 packet without options, **MSS = MTU − 40**
(20 for IPv4 + 20 for TCP): 1460 for an Ethernet host, visible in the `mss` option of the captured
SYNs. `ss -ti` prints for each connection `mss:` (the effective value, 12 bytes less when the
*timestamps* option is used: 1448), `pmtu:`, `advmss:` and the retransmissions (`retrans`, `lost`).

### @@sec:blackhole@@ The black hole

TCP sends 1500-byte segments with DF; the router in front of a link with a smaller MTU drops them and
answers with the ICMP *fragmentation needed*… which many firewalls **filter**. The sender then
receives neither an acknowledgement nor an error: it retransmits the same segment, in vain. Typical
symptoms: `ping` works, the TCP connection is established (small SYN/ACK), small exchanges work, but
any large transfer **freezes** (`iperf3` shows 0 bit/s and retransmissions, a web page never finishes
loading).

### @@sec:remedies@@ The remedies

On the side of the administrator of the routers, two solutions exist to fix this problem:

**MSS clamping**: rewriting the MSS option of the SYNs that cross the router so that both hosts only
send segments that get through. With nftables (`inet` table, `forward` hook, `mangle` priority,
`tcp flags syn` covers SYN and SYN/ACK):

```
nft add table inet clamp
nft add chain inet clamp forward '{ type filter hook forward priority mangle; }'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set 1400
nft list ruleset
```

`tcp option maxseg size set rt mtu` uses the MTU of the **outgoing route of the router** (hence of
its outgoing interface): it is useful only if that interface itself has the reduced MTU.

**MTU of the interfaces**: `ip link set dev IFACE mtu N` on the interface of each site router that
faces the link with the reduced MTU. The router then emits the ICMP error itself towards its hosts
(it is not filtered) and PMTUD works again in each site.

On the side of the **hosts** only: `sysctl -w net.ipv4.tcp_mtu_probing=1` (RFC 4821, TCP probes the
MTU itself after a black hole) or a route with `mtu N`. These settings only fix the machine they are
made on, not the other workstations of the site.
""",
        """
**MTU du tunnel.**

- Surcoût d'encapsulation d'un tunnel GRE sur IPv4 (sans clé ni somme de contrôle), en octets : @@{overhead:[0-9]+}@@
- MTU à configurer sur `gre1` : @@{mtu_tunnel:[0-9]+}@@
""": """
**MTU of the tunnel.**

- Encapsulation overhead of a GRE tunnel over IPv4 (without key or checksum), in bytes: @@{overhead:[0-9]+}@@
- MTU to configure on `gre1`: @@{mtu_tunnel:[0-9]+}@@
""",
        """
**Mesures.**

- MTU du lien de l'opérateur, en octets : @@{mtu:[0-9]+}@@
- Plus grande charge utile de `ping -M do -s` qui traverse l'opérateur sans erreur : @@{payload:[0-9]+}@@
- Message ICMP reçu par `m1` : type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- Pour un paquet de 1500 octets émis **sans** DF par `m1` vers `m2`, la machine qui le fragmente
  est : @@{fragmenter:>m1|r1|wan|r2|personne>>>nobody}@@
- MSS TCP (sans option IP ni TCP) adapté au lien de l'opérateur : @@{mss:[0-9]+}@@
- Commande qui affiche, sur `m1`, le PMTU mémorisé vers `m2` : @@{command:>ip route get|ip link|arp -a|ss -s}@@
- Ligne de `tcpdump` qui montre l'erreur ICMP reçue par `m1` (étape 2) : @@{capture:.*}@@
- Ce qu'indiquent l'adresse source et le MTU annoncé par cette erreur : @@{explanation:.*}@@
""": """
**Measurements.**

- MTU of the operator's link, in bytes: @@{mtu:[0-9]+}@@
- Largest payload of `ping -M do -s` that crosses the operator without error: @@{payload:[0-9]+}@@
- ICMP message received by `m1`: type @@{icmp_type~4:[0-9]+}@@, code @@{icmp_code~4:[0-9]+}@@
- For a 1500-byte packet sent **without** DF by `m1` to `m2`, the machine that fragments it
  is: @@{fragmenter:>m1|r1|wan|r2|nobody}@@
- TCP MSS (without IP or TCP options) suited to the operator's link: @@{mss:[0-9]+}@@
- Command that shows, on `m1`, the PMTU remembered towards `m2`: @@{command:>ip route get|ip link|arp -a|ss -s}@@
- `tcpdump` line that shows the ICMP error received by `m1` (step 2): @@{capture:.*}@@
- What the source address and the MTU announced by this error indicate: @@{explanation:.*}@@
""",
        """
**Pour l'enseignant.** Chaque question se termine par sa solution, calculée pour ce projet : le MTU de
l'opérateur y vaut **{n}** octets (charge utile maximale de `ping` : {payload} ; MSS : {mss} ; MTU du
tunnel GRE : {tun_mtu}).

- L'état `final` (onglet *Appliquer une configuration*) applique la solution des parties 2 et 3 (MSS
  clamping sur `r1` et `r2`, tunnel `gre1`) et remplit les formulaires. Il ne touche pas à `wan` :
  l'état `black_hole` ou `icmp_restored` en cours reste en place.
- `wan` a le MTU {n} sur ses deux interfaces et deux tables nftables : `probes`, permanente, jette les
  erreurs ICMP *fragmentation needed* destinées aux sondes cachées `h1` (`{h1}`) et `h2` (`{h2}`) ;
  `black_hole`, posée et retirée par les deux états, les jette pour tout le monde.
- Évaluation (une dizaine de secondes) : cache des PMTU vidé sur `h1`, `h2` et `r1` ; transfert `iperf3`
  de 2 s de `h1` vers `h2` puis en sens inverse (réussi au-delà de 100 ko reçus) et `ping` de `h1` vers
  `h2` ; lecture des règles nftables et des MTU de `r1` et `r2` ; pour le tunnel, `ip -j -d link show`
  sur `r1` et `r2` puis, depuis `r1`, un `ping` vers l'adresse `tun` de `r2`, un `ping -M do -s {fit}`
  qui doit passer et un `ping -M do -s {over}` qui doit être refusé localement.
- Une correction faite seulement sur `m1` et `m2` (`tcp_mtu_probing`, route avec `mtu`) fait passer les
  essais de l'étudiant mais pas les transferts des sondes : les 10 points des transferts sont perdus.
""": """
**For the instructor.** Each question ends with its solution, computed for this project: the MTU of
the operator is **{n}** bytes here (largest `ping` payload: {payload}; MSS: {mss}; MTU of the GRE
tunnel: {tun_mtu}).

- The `final` state (*Apply Configuration* tab) applies the solution of parts 2 and 3 (MSS clamping
  on `r1` and `r2`, tunnel `gre1`) and fills the forms. It does not touch `wan`: the current
  `black_hole` or `icmp_restored` state stays in place.
- `wan` has the MTU {n} on both of its interfaces and two nftables tables: `probes`, permanent, drops
  the ICMP *fragmentation needed* errors addressed to the hidden probes `h1` (`{h1}`) and `h2`
  (`{h2}`); `black_hole`, set and removed by the two states, drops them for everybody.
- Evaluation (about ten seconds): PMTU cache emptied on `h1`, `h2` and `r1`; an `iperf3` transfer of
  2 s from `h1` to `h2` then in the reverse direction (successful above 100 kB received) and a `ping`
  from `h1` to `h2`; reading of the nftables rules and of the MTUs of `r1` and `r2`; for the tunnel,
  `ip -j -d link show` on `r1` and `r2` then, from `r1`, a `ping` towards the `tun` address of `r2`,
  a `ping -M do -s {fit}` that must pass and a `ping -M do -s {over}` that must be refused locally.
- A fix made only on `m1` and `m2` (`tcp_mtu_probing`, route with `mtu`) makes the student's tests
  pass but not the transfers of the probes: the 10 points of the transfers are lost.
""",
        """
**Questions.**

- Correction que vous avez mise en place : @@{fix:>MSS clamping nftables sur r1 et/ou r2>>>mss_clamping|MTU des interfaces WAN de r1 et r2 abaissé>>>wan_mtu|net.ipv4.tcp_mtu_probing sur m1 et m2>>>host_probing|route avec mtu sur m1 et m2>>>host_route}@@
- Un collègue propose `tcp option maxseg size set rt mtu` sur `r1`, sans rien changer d'autre. Pourquoi
  cela ne corrige-t-il pas le trou noir tant que `eth1` de `r1` garde un MTU de 1500, et que faudrait-il
  faire pour que cette règle fonctionne ? @@{rt_mtu:.*}@@
""": """
**Questions.**

- Fix you put in place: @@{fix:>MSS clamping with nftables on r1 and/or r2>>>mss_clamping|MTU of the WAN interfaces of r1 and r2 lowered>>>wan_mtu|net.ipv4.tcp_mtu_probing on m1 and m2>>>host_probing|route with mtu on m1 and m2>>>host_route}@@
- A colleague suggests `tcp option maxseg size set rt mtu` on `r1`, without changing anything else.
  Why does it not fix the black hole as long as `eth1` of `r1` keeps an MTU of 1500, and what would
  have to be done for this rule to work? @@{rt_mtu:.*}@@
""",
        """
**Réponses.**

- MTU de l'opérateur : `{mtu}` ; charge utile maximale : `{payload}` ({mtu} − 20 − 8)
- ICMP type `{icmp_type}` (*destination unreachable*), code `{icmp_code}` (*fragmentation needed and DF set*)
- sans DF c'est `{fragmenter}` qui fragmente : le routeur dont le lien de sortie est trop petit
- MSS : `{mss}` ({mtu} − 40) ; PMTU mémorisé : `{command}`
- ligne attendue : `{capture}` ; l'adresse source est celle de `wan` côté `wan1` (le routeur qui n'a pas pu
  émettre le paquet sur son lien de sortie) et le MTU annoncé celui de ce lien, que `m1` adopte comme PMTU
  vers `m2`. Ces deux derniers champs ne sont pas notés.
""": """
**Answers.**

- MTU of the operator: `{mtu}`; largest payload: `{payload}` ({mtu} − 20 − 8)
- ICMP type `{icmp_type}` (*destination unreachable*), code `{icmp_code}` (*fragmentation needed and DF set*)
- without DF it is `{fragmenter}` that fragments: the router whose outgoing link is too small
- MSS: `{mss}` ({mtu} − 40); remembered PMTU: `{command}`
- expected line: `{capture}`; the source address is that of `wan` on the `wan1` side (the router that
  could not send the packet on its outgoing link) and the MTU announced is that of this link, which
  `m1` adopts as its PMTU towards `m2`. These last two fields are not graded.
""",
        """
**Réponses.** `MSS clamping nftables sur r1 et/ou r2` ou `MTU des interfaces WAN de r1 et r2 abaissé`,
selon la correction faite (2 points) ; les deux autres choix ne corrigent que `m1` et `m2` : 0. Sur
`rt mtu` (non noté) : il vaut le MTU de la route de sortie du paquet sur `r1`, donc celui de `eth1` : 1500,
soit un MSS de 1460, inchangé. `r1` ignore le MTU de l'opérateur : l'erreur ICMP de `wan` est destinée à la
source du paquet, pas à `r1`, et elle est filtrée. Il faut `ip link set dev eth1 mtu {n}` sur `r1` (et
`eth0` sur `r2`), ou fixer la valeur (`size set {mss}`).
""": """
**Answers.** `MSS clamping with nftables on r1 and/or r2` or
`MTU of the WAN interfaces of r1 and r2 lowered`, depending on the fix made (2 points); the other two
choices only fix `m1` and `m2`: 0. On `rt mtu` (not graded): it is the MTU of the outgoing route of
the packet on `r1`, hence that of `eth1`: 1500, i.e. an MSS of 1460, unchanged. `r1` does not know
the operator's MTU: the ICMP error of `wan` is addressed to the source of the packet, not to `r1`,
and it is filtered. One needs `ip link set dev eth1 mtu {n}` on `r1` (and `eth0` on `r2`), or a fixed
value (`size set {mss}`).
""",
        """
**Réponses.** surcoût `{overhead}` octets (20 d'IPv4 + 4 de GRE) ; MTU de `gre1` : `{mtu_tunnel}`
({n} − {overhead}).
""": """
**Answers.** overhead `{overhead}` bytes (20 for IPv4 + 4 for GRE); MTU of `gre1`: `{mtu_tunnel}`
({n} − {overhead}).
""",
        """
**Solution.** Avant `black_hole`, `iperf3 -c m2 -t 5` donne plusieurs dizaines de Mbit/s. Après, `ping m2`
passe encore mais `iperf3` affiche `0.00 Bytes` côté *receiver* : `ss -ti dst {m2}` montre
`mss:1448 pmtu:1500` et des retransmissions, et sur `r1` les segments de 1500 octets partent vers `wan`
sans qu'aucune erreur ICMP ne revienne.

Correction A, MSS clamping, sur `r1`, sur `r2` ou sur les deux (c'est ce qu'applique l'état `final`, sur
les deux routeurs, avec une table équivalente nommée `{clamp_table}` chargée depuis `{clamp_rules}`) :

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss}
```

Correction B, MTU des interfaces tournées vers l'opérateur, sur les **deux** routeurs :

```
ip link set dev eth1 mtu {n}  # sur r1
ip link set dev eth0 mtu {n}  # sur r2
```

- Vérification : `iperf3 -c m2 -t 5` passe de nouveau. Avec A, `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'`
  sur `r1` montre `mss {mss}` dans le SYN et le SYN/ACK. Avec B, c'est `r1` (ou `r2`) qui répond à l'hôte par
  *fragmentation needed* (`mtu {n}`) : la PMTUD fonctionne de nouveau dans chaque site.
- A sur un seul routeur suffit : SYN et SYN/ACK le traversent tous les deux. B sur `r1` seul laisse le sens
  `h2` → `h1` dans le trou noir.
- Toute valeur de MSS ≤ {mss} convient. `… size set rt mtu` ne compte que si l'interface WAN du routeur
  est déjà à {n} (correction B).
- Évaluation : `bh_forward` et `bh_backward` (transferts entre les sondes, 5 points chacun), `bh_connectivity`,
  `bh_config` (règle de clamping ≤ {mss} dans un hook routé de `r1` ou de `r2`, ou MTU ≤ {n} sur `eth1` de
  `r1` **et** `eth0` de `r2`).
""": """
**Solution.** Before `black_hole`, `iperf3 -c m2 -t 5` gives several tens of Mbit/s. After it,
`ping m2` still works but `iperf3` shows `0.00 Bytes` on the *receiver* side: `ss -ti dst {m2}` shows
`mss:1448 pmtu:1500` and retransmissions, and on `r1` the 1500-byte segments leave towards `wan`
without any ICMP error coming back.

Fix A, MSS clamping, on `r1`, on `r2` or on both (this is what the `final` state applies, on both
routers, with an equivalent table named `{clamp_table}` loaded from `{clamp_rules}`):

```
nft add table inet clamp
nft add chain inet clamp forward '{{ type filter hook forward priority mangle; }}'
nft add rule inet clamp forward tcp flags syn tcp option maxseg size set {mss}
```

Fix B, MTU of the interfaces facing the operator, on **both** routers:

```
ip link set dev eth1 mtu {n}  # on r1
ip link set dev eth0 mtu {n}  # on r2
```

- Check: `iperf3 -c m2 -t 5` works again. With A, `tcpdump -n -i eth1 'tcp[tcpflags] & tcp-syn != 0'`
  on `r1` shows `mss {mss}` in the SYN and the SYN/ACK. With B, it is `r1` (or `r2`) that answers the
  host with *fragmentation needed* (`mtu {n}`): PMTUD works again in each site.
- A on a single router is enough: SYN and SYN/ACK both cross it. B on `r1` alone leaves the direction
  `h2` → `h1` in the black hole.
- Any MSS value ≤ {mss} will do. `… size set rt mtu` only counts if the WAN interface of the router is
  already at {n} (fix B).
- Evaluation: `bh_forward` and `bh_backward` (transfers between the probes, 5 points each),
  `bh_connectivity`, `bh_config` (clamping rule ≤ {mss} in a forwarding hook of `r1` or `r2`, or
  MTU ≤ {n} on `eth1` of `r1` **and** `eth0` of `r2`).
""",
        """
**Solution.** Sur `m1` (MTU de `eth0` : 1500) :

```
ping -c 1 -M do -s 1472 r1_lan1  # passe : 1472 + 28 = 1500
ping -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1}) icmp_seq=1 Frag needed and DF set (mtu = {n})
# puis, deux fois : ping: local error: message too long, mtu={n}
ip route get {m2}  # ... cache expires ...sec mtu {n}
ip route flush cache
ping -c 1 -M do -s {payload} m2  # passe : {payload} + 28 = {n}
ping -c 1 -M do -s {payload1} m2  # refusé
tracepath -n m2  # Resume: pmtu {n} hops 4 back 4
ping -c 1 -M dont -s 1472 m2  # passe : wan fragmente
```

- L'erreur est un ICMP type 3 code 4 émis par `wan` (son adresse côté `wan1`, `{wan1}`). `tcpdump`
  affiche `{wan1} > {m1}: ICMP {m2} unreachable - need to frag (mtu {n})`.
- Le premier `ping` reçoit l'erreur du routeur ; `m1` mémorise alors le PMTU vers `m2` (10 min) et
  refuse lui-même les suivants (`local error`), sans rien émettre.
- Sans DF, `wan` fragmente le paquet aller : un fragment de {first} octets marqué `flags [+]`, puis le
  reste à l'`offset {offset}`. La réponse de `m2`, de 1500 octets elle aussi, est fragmentée par `wan`
  dans l'autre sens.
- MSS : {n} − 40 = **{mss}**.
""": """
**Solution.** On `m1` (MTU of `eth0`: 1500):

```
ping -c 1 -M do -s 1472 r1_lan1  # passes: 1472 + 28 = 1500
ping -c 3 -M do -s 1472 m2  # From wan_wan1 ({wan1}) icmp_seq=1 Frag needed and DF set (mtu = {n})
# then, twice: ping: local error: message too long, mtu={n}
ip route get {m2}  # ... cache expires ...sec mtu {n}
ip route flush cache
ping -c 1 -M do -s {payload} m2  # passes: {payload} + 28 = {n}
ping -c 1 -M do -s {payload1} m2  # refused
tracepath -n m2  # Resume: pmtu {n} hops 4 back 4
ping -c 1 -M dont -s 1472 m2  # passes: wan fragments
```

- The error is an ICMP type 3 code 4 sent by `wan` (its address on the `wan1` side, `{wan1}`).
  `tcpdump` prints `{wan1} > {m1}: ICMP {m2} unreachable - need to frag (mtu {n})`.
- The first `ping` receives the error of the router; `m1` then remembers the PMTU towards `m2`
  (10 min) and refuses the following ones itself (`local error`), without sending anything.
- Without DF, `wan` fragments the outgoing packet: a fragment of {first} bytes marked `flags [+]`,
  then the rest at `offset {offset}`. The reply of `m2`, also 1500 bytes long, is fragmented by `wan`
  in the other direction.
- MSS: {n} − 40 = **{mss}**.
""",
        """
**Solution.** Sur `r1` :

```
ip link add gre1 type gre local {r1_wan} remote {r2_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r1_tun} dev gre1
```

Sur `r2` :

```
ip link add gre1 type gre local {r2_wan} remote {r1_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r2_tun} dev gre1
```

- MTU du tunnel : {n} − 24 (20 d'IPv4 + 4 de GRE) = **{tun_mtu}**. Sans réglage, `gre1` reste à 1476.
- Vérification depuis `r1` : `ping {r2_tun_ip}` passe ; `ping -M do -s {fit} {r2_tun_ip}` passe
  ({fit} + 28 = {tun_mtu}) ; `ping -M do -s {over} {r2_tun_ip}` répond
  `local error: message too long, mtu={tun_mtu}`. `tcpdump -n -v -i eth1 proto gre` montre des paquets
  extérieurs d'au plus {n} octets, avec DF (`pmtudisc`).
- Évaluation : `gre_r1` et `gre_r2` (type `gre`, `local` / `remote` égaux aux adresses `wan1` / `wan2`,
  MTU {tun_mtu} : 1 point chacun), `gre_reachable`, `gre_pmtu` (les deux `ping -M do` ci-dessus, cache de
  `r1` vidé : sans MTU réglé sur `gre1`, le paquet trop grand part et n'est pas refusé localement).
- Les corrections de la partie 2 peuvent rester en place, et le tunnel fonctionne avec ou sans `black_hole`.
""": """
**Solution.** On `r1`:

```
ip link add gre1 type gre local {r1_wan} remote {r2_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r1_tun} dev gre1
```

On `r2`:

```
ip link add gre1 type gre local {r2_wan} remote {r1_wan} ttl 64
ip link set gre1 mtu {tun_mtu} up
ip addr add {r2_tun} dev gre1
```

- MTU of the tunnel: {n} − 24 (20 for IPv4 + 4 for GRE) = **{tun_mtu}**. Without this setting, `gre1`
  stays at 1476.
- Check from `r1`: `ping {r2_tun_ip}` passes; `ping -M do -s {fit} {r2_tun_ip}` passes
  ({fit} + 28 = {tun_mtu}); `ping -M do -s {over} {r2_tun_ip}` answers
  `local error: message too long, mtu={tun_mtu}`. `tcpdump -n -v -i eth1 proto gre` shows outer
  packets of at most {n} bytes, with DF (`pmtudisc`).
- Evaluation: `gre_r1` and `gre_r2` (type `gre`, `local` / `remote` equal to the `wan1` / `wan2`
  addresses, MTU {tun_mtu}: 1 point each), `gre_reachable`, `gre_pmtu` (the two `ping -M do` above,
  cache of `r1` emptied: without an MTU set on `gre1`, the oversized packet leaves and is not refused
  locally).
- The fixes of part 2 may stay in place, and the tunnel works with or without `black_hole`.
""",
        """
**Sommaire**
""": """
**Contents**
""",
        """
1. Créez un tunnel GRE `gre1` entre `r1` et `r2`, dont les extrémités sont leurs adresses sur
   les réseaux de l'opérateur (`wan1` / `wan2`) et les adresses intérieures celles du réseau
   `tun` du plan d'adressage de la question « Organisation du TP » (`ip link add … type gre local … remote … ttl 64`, `ip addr add`,
   `ip link set … up`). Vérifiez `ping` entre les deux adresses `tun`.
2. Calculez le MTU que doit avoir le tunnel pour qu'aucun paquet encapsulé ne dépasse le MTU de
   l'opérateur (surcoût GRE : en-tête IPv4 + en-tête GRE). Réglez-le des deux côtés
   (`ip link set gre1 mtu …`) et vérifiez-le avec `ip -d link show gre1`.
3. Depuis `r1`, testez avec `ping -M do -s TAILLE ADRESSE_TUN_DE_R2` : la plus grande charge
   utile qui passe doit correspondre au MTU du tunnel, et un octet de plus doit être refusé
   localement (`message too long`). Capturez sur `eth1` de `r1` (`tcpdump -n -v -i eth1 proto gre`)
   pour voir les paquets encapsulés et leur taille.
""": """
1. Create a GRE tunnel `gre1` between `r1` and `r2`, whose endpoints are their addresses on the
   operator's networks (`wan1` / `wan2`) and whose inner addresses are those of the `tun` network of
   the addressing plan of the question "Organisation of the lab" (`ip link add … type gre local … remote … ttl 64`,
   `ip addr add`, `ip link set … up`). Check `ping` between the two `tun` addresses.
2. Compute the MTU the tunnel must have so that no encapsulated packet exceeds the MTU of the
   operator (GRE overhead: IPv4 header + GRE header). Set it on both sides (`ip link set gre1 mtu …`)
   and check it with `ip -d link show gre1`.
3. From `r1`, test with `ping -M do -s SIZE TUN_ADDRESS_OF_R2`: the largest payload that passes must
   match the MTU of the tunnel, and one more byte must be refused locally (`message too long`).
   Capture on `eth1` of `r1` (`tcpdump -n -v -i eth1 proto gre`) to see the encapsulated packets and
   their size.
""",
        """
1. Lancez `iperf3 -s` sur `m2`, puis `iperf3 -c m2 -t 5` sur `m1` : le transfert passe (notez
   le débit). Dans un autre terminal de `m1`, `ss -ti dst m2` pendant le transfert montre `mss`
   et `pmtu`.
2. Appliquez l'état **`black_hole`** (onglet *Appliquer une configuration*) : l'opérateur
   n'émet plus d'erreur ICMP et les PMTU appris sont oubliés. Vérifiez que `ping m2` passe
   toujours, puis relancez `timeout 20 iperf3 -c m2 -t 5` : que se passe-t-il ? Observez avec
   `ss -ti dst m2` (retransmissions, `mss`) et `tcpdump -n -i eth1 'tcp or icmp'` sur `r1`
   (segments de 1500 octets qui partent, rien ne revient).
3. Corrigez le problème **sur `r1` et/ou `r2`** (onglet *Informations*, section @@ref:remedies@@) : MSS clamping
   avec nftables, ou MTU réduit sur les interfaces tournées vers l'opérateur. Vérifiez que le
   transfert `iperf3` passe de nouveau et, dans une capture des SYN sur `r1`, la nouvelle valeur
   de l'option `mss`.
4. Les transferts notés se font entre deux postes cachés de `lan1` et `lan2` qui restent
   derrière le trou noir quoi qu'il arrive : votre correction doit être en place sur les
   routeurs au moment de l'évaluation. `black_hole` peut rester appliqué ou non, au choix.
""": """
1. Run `iperf3 -s` on `m2`, then `iperf3 -c m2 -t 5` on `m1`: the transfer works (note the
   throughput). In another terminal of `m1`, `ss -ti dst m2` during the transfer shows `mss` and
   `pmtu`.
2. Apply the **`black_hole`** state (*Apply Configuration* tab): the operator no longer emits any
   ICMP error and the learned PMTUs are forgotten. Check that `ping m2` still works, then run
   `timeout 20 iperf3 -c m2 -t 5` again: what happens? Observe with `ss -ti dst m2` (retransmissions,
   `mss`) and `tcpdump -n -i eth1 'tcp or icmp'` on `r1` (1500-byte segments leave, nothing comes
   back).
3. Fix the problem **on `r1` and/or `r2`** (*Informations* tab, section @@ref:remedies@@): MSS
   clamping with nftables, or a reduced MTU on the interfaces facing the operator. Check that the
   `iperf3` transfer works again and, in a capture of the SYNs on `r1`, the new value of the `mss`
   option.
4. The graded transfers run between two hidden workstations of `lan1` and `lan2` that stay behind the
   black hole whatever happens: your fix must be in place on the routers at the time of the
   evaluation. `black_hole` may stay applied or not, as you like.
""",
        """
1. Sur `m1`, relevez le MTU de `eth0` (`ip link`), puis vérifiez que `ping -c 1 -M do -s 1472 r1_lan1`
   passe : 1472 octets de charge utile font un paquet de 1500 octets.
2. Lancez `tcpdump -n -v -i eth0 icmp` dans un second terminal de `m1`, puis
   `ping -c 3 -M do -s 1472 m2`. Observez le message d'erreur de `ping`, l'adresse qui l'émet
   et le MTU qu'il annonce ; retrouvez-le dans la capture (`need to frag`). Pourquoi le deuxième
   `ping` échoue-t-il différemment du premier (`local error`) ? Consultez `ip route get` vers
   `m2`, puis `ip route flush cache`.
3. Par dichotomie avec `ping -M do -s TAILLE m2`, trouvez la plus grande charge utile qui traverse
   l'opérateur sans erreur, et comparez avec `tracepath -n m2`.
4. Sans DF : `ping -c 1 -M dont -s 1472 m2`. La réponse arrive ; dans la capture sur `m1` (et sur
   `r1`, `tcpdump -n -v -i eth1 icmp`), repérez les fragments (`flags [+]`, `offset`) et
   déterminez quelle machine a fragmenté le paquet aller, et laquelle la réponse.
5. Déduisez-en le MSS TCP qu'un hôte devrait annoncer pour que ses segments traversent
   l'opérateur sans fragmentation.
""": """
1. On `m1`, note the MTU of `eth0` (`ip link`), then check that `ping -c 1 -M do -s 1472 r1_lan1`
   passes: 1472 bytes of payload make a packet of 1500 bytes.
2. Run `tcpdump -n -v -i eth0 icmp` in a second terminal of `m1`, then
   `ping -c 3 -M do -s 1472 m2`. Look at the error message of `ping`, the address that sends it and
   the MTU it announces; find it again in the capture (`need to frag`). Why does the second `ping`
   fail differently from the first one (`local error`)? Look at `ip route get` towards `m2`, then
   run `ip route flush cache`.
3. By bisection with `ping -M do -s SIZE m2`, find the largest payload that crosses the operator
   without error, and compare with `tracepath -n m2`.
4. Without DF: `ping -c 1 -M dont -s 1472 m2`. The reply arrives; in the capture on `m1` (and on
   `r1`, `tcpdump -n -v -i eth1 icmp`), spot the fragments (`flags [+]`, `offset`) and determine
   which machine fragmented the outgoing packet, and which one fragmented the reply.
5. Deduce from this the TCP MSS a host should announce so that its segments cross the operator
   without fragmentation.
""",
        """
Ce TP étudie le **MTU** des liens, la **fragmentation** IPv4, la **découverte du MTU du chemin**
(PMTUD), le **trou noir PMTUD** que provoque le filtrage des erreurs ICMP, ses remèdes (**MSS
clamping**, MTU des interfaces) et le **surcoût d'encapsulation** d'un tunnel **GRE**. Lisez
l'onglet **Informations** : c'est le cours sur ces notions, avec les commandes utiles.

**La maquette.** Deux sites, `lan1` (`m1`) et `lan2` (`m2`), sont reliés par leurs routeurs `r1`
et `r2` à travers le réseau d'un **opérateur**, représenté par le routeur `wan`. Vous administrez
`m1`, `r1`, `r2` et `m2` ; `wan` n'est **pas accessible** (pas de terminal, MTU non modifiable) :
c'est l'équipement de l'opérateur, dont le MTU est **inférieur à 1500** et que vous allez mesurer
en l'observant depuis `r1` et `r2`.
""": """
This lab studies the **MTU** of links, IPv4 **fragmentation**, **path MTU discovery** (PMTUD), the
**PMTUD black hole** caused by the filtering of ICMP errors, its remedies (**MSS clamping**, MTU of
the interfaces) and the **encapsulation overhead** of a **GRE** tunnel. Read the **Informations**
tab: it is the course on these notions, with the useful commands.

**The setup.** Two sites, `lan1` (`m1`) and `lan2` (`m2`), are linked by their routers `r1` and
`r2` through the network of an **operator**, represented by the router `wan`. You administer `m1`,
`r1`, `r2` and `m2`; `wan` is **not accessible** (no terminal, its MTU cannot be changed): it is the
operator's equipment, whose MTU is **below 1500** and which you are going to measure by observing it
from `r1` and `r2`.
""",
        """
Déjà en place (ne pas modifier) : adresses IP et routes statiques sur toutes les machines, routage
IPv4 activé sur `r1`, `r2` et `wan`, noms dans `/etc/hosts` (`ping m2`, `ping r2_lan2`,
`ping wan_wan1` fonctionnent), *offloads* GSO/GRO désactivés (les trames observées ont la taille
du MTU). La configuration d'une partie terminée reste en place : le MSS clamping ou le MTU réduit
de la partie 2 n'empêche pas le tunnel de la partie 3.

**Sondes de notation.** Deux hôtes cachés, `h1` dans `lan1` et `h2` dans `lan2`, servent aux
mesures : ce sont des **postes ordinaires** (MTU 1500, PMTUD classique, aucun réglage possible de
votre part) et l'opérateur **filtre en permanence** les erreurs ICMP qui leur sont destinées. Ils
représentent les utilisateurs des deux sites : seule une correction faite sur **vos routeurs**
`r1` et `r2` rend leurs transferts possibles (partie 2), pas une correction faite sur `m1` et
`m2` (`tcp_mtu_probing`, route avec `mtu` : ces réglages d'hôte ne comptent pas, les sondes
n'étant pas administrables). Les réseaux de la maquette sont des commutateurs : vos captures ne
montrent pas les transferts des sondes, seulement leurs requêtes ARP ; leurs adresses apparaissent
aussi dans `ip neigh` sur `r1` et `r2`.

**États.** L'onglet **Appliquer une configuration** propose deux états que vous appliquez
vous-même au moment indiqué dans les questions ; l'évaluation ne dépend pas de l'état choisi :

- `black_hole` : l'opérateur cesse d'émettre les erreurs ICMP « fragmentation needed » vers tout
  le monde (et les PMTU déjà appris par `m1`, `m2`, `r1`, `r2` sont oubliés) ;
- `icmp_restored` : l'opérateur émet de nouveau ces erreurs.

**Plan du TP.** Trois parties, à faire dans l'ordre (entre parenthèses : les points, puis la
section du cours de l'onglet **Informations** à lire) :

1. **Découverte du MTU** de l'opérateur avec `ping -M do`, `tracepath`, `tcpdump` et le cache
   des routes ; fragmentation sans DF (10 points, formulaire ; section @@ref:mtu@@).
2. **Trou noir PMTUD** : appliquer l'état `black_hole`, constater le gel des transferts TCP,
   diagnostiquer, puis corriger sur `r1` / `r2` (16 points : transferts entre les sondes,
   configuration, formulaire ; section @@ref:tcp@@).
3. **Tunnel GRE** entre `r1` et `r2` à travers l'opérateur, au bon MTU (14 points :
   configuration et tests depuis `r1`, formulaire ; section @@ref:gre@@).

Les sections @@ref:tools@@ (outils) et @@ref:troubleshooting@@ (dépannage) servent aux trois
parties.

**Évaluation.** Chaque évaluation (≈ 20 s) lance des transferts `iperf3` entre `h1` et `h2`,
vérifie la configuration de `r1` et `r2`, teste le tunnel GRE depuis `r1` et lit vos réponses aux
formulaires. Elle vide le cache des PMTU de `r1` et des sondes ; elle ne modifie rien d'autre.
""": """
Already in place (do not modify): IP addresses and static routes on every machine, IPv4 forwarding
enabled on `r1`, `r2` and `wan`, names in `/etc/hosts` (`ping m2`, `ping r2_lan2`, `ping wan_wan1`
work), GSO/GRO *offloads* disabled (the frames you observe have the size of the MTU). The
configuration of a finished part stays in place: the MSS clamping or the reduced MTU of part 2 does
not prevent the tunnel of part 3.

**Grading probes.** Two hidden hosts, `h1` in `lan1` and `h2` in `lan2`, are used for the
measurements: they are **ordinary workstations** (MTU 1500, classic PMTUD, no setting possible on your
side) and the operator **permanently filters** the ICMP errors addressed to them. They represent the
users of the two sites: only a fix made on **your routers** `r1` and `r2` makes their transfers
possible (part 2), not a fix made on `m1` and `m2` (`tcp_mtu_probing`, route with `mtu`: these host
settings do not count, since the probes cannot be administered). The networks of the setup are
switches: your captures do not show the transfers of the probes, only their ARP requests; their
addresses also appear in `ip neigh` on `r1` and `r2`.

**States.** The **Apply Configuration** tab offers two states that you apply yourself at the time
given in the questions; the evaluation does not depend on the state chosen:

- `black_hole`: the operator stops emitting the ICMP "fragmentation needed" errors towards everybody
  (and the PMTUs already learned by `m1`, `m2`, `r1`, `r2` are forgotten);
- `icmp_restored`: the operator emits these errors again.

**Plan of the lab.** Three parts, to be done in order (in brackets: the points, then the section of
the course of the **Informations** tab to read):

1. **Discovery of the MTU** of the operator with `ping -M do`, `tracepath`, `tcpdump` and the route
   cache; fragmentation without DF (10 points, form; section @@ref:mtu@@).
2. **PMTUD black hole**: apply the `black_hole` state, observe the freeze of the TCP transfers,
   diagnose, then fix it on `r1` / `r2` (16 points: transfers between the probes, configuration,
   form; section @@ref:tcp@@).
3. **GRE tunnel** between `r1` and `r2` through the operator, at the right MTU (14 points:
   configuration and tests from `r1`, form; section @@ref:gre@@).

Sections @@ref:tools@@ (tools) and @@ref:troubleshooting@@ (troubleshooting) serve all three
parts.

**Evaluation.** Each evaluation (≈ 20 s) runs `iperf3` transfers between `h1` and `h2`, checks the
configuration of `r1` and `r2`, tests the GRE tunnel from `r1` and reads your answers to the forms. It
empties the PMTU cache of `r1` and of the probes; it changes nothing else.
""",
        """
Le **MTU** (*maximum transmission unit*) d'un lien est le nombre maximal d'octets de données
qu'une trame peut y transporter : 

- **1500** sur Ethernet ; 
- **2304** dans la norme Wi-Fi (802.11),
mais une interface Wi-Fi reste en pratique à 1500 car le point d'accès limite ses trames vers
Ethernet ; 
- **9000** en général pour les *jumbo frames*, trames Ethernet étendues que la norme
IEEE ne définit pas et que chaque équipement du réseau doit accepter.

### @@sec:adjust@@ Ajuster le MTU
 
**Augmenter le MTU** réduit le nombre de paquets pour une même quantité de
données : les en-têtes IPv4 et TCP (40 octets) pèsent 2,7 % d'un paquet de 1500 octets mais
0,4 % d'un paquet de 9000, et chaque paquet en moins économise du temps de traitement
(interruptions, traversée de la pile réseau). 

Les *jumbo frames* servent ainsi sur les réseaux
locaux rapides (centres de données, stockage iSCSI ou NFS, grappes de calcul), à condition que
**toutes** les machines et tous les commutateurs du réseau les acceptent : une trame trop grande
y est jetée en silence, sans message d'erreur. Vers Internet le chemin reste de toute façon à
1500. 

**Diminuer le MTU** s'impose quand un en-tête supplémentaire s'ajoute sur un lien dont le MTU
est fixé : PPPoE (8 octets, MTU 1492 chez de nombreux fournisseurs d'accès), tunnels GRE, IPsec
ou VPN (section @@ref:gre@@). Sur un lien lent ou peu fiable (radio, satellite), des trames plus
courtes limitent aussi le coût d'une erreur de transmission (une trame corrompue est perdue en
entier) et l'attente d'un petit paquet urgent, de voix par exemple, derrière une grande trame en
cours d'émission : 1500 octets occupent un lien à 1 Mbit/s pendant 12 ms.

Un paquet IPv4 contient un en-tête de
**20 octets** (sans option) ; un écho ICMP ajoute un en-tête de **8 octets** : `ping -s 1472` émet
donc des paquets de 1500 octets, le maximum sans fragmentation sur Ethernet (`ping` affiche
`1472(1500) bytes`).

### @@sec:fragmentation@@ Fragmentation

En IPv4 un routeur qui doit émettre un paquet plus grand que le MTU du lien de
sortie le **fragmente** : chaque fragment porte le même identifiant, le bit **MF** (*more
fragments*, sauf le dernier) et un **décalage** (*offset*, en mots de 8 octets). Seul le
destinataire réassemble. La fragmentation coûte cher (un fragment perdu = tout le paquet perdu,
charge CPU, pare-feu qui ne voient le port que dans le premier fragment) ; les systèmes modernes
l'évitent en positionnant le bit **DF** (*don't fragment*) : le routeur jette alors le paquet et
renvoie à l'émetteur un message **ICMP type 3 (*destination unreachable*), code 4 (*fragmentation
needed and DF set*)** qui indique le **MTU du lien suivant** (RFC 1191).

### @@sec:pmtud@@ Découverte du MTU du chemin (PMTUD)

L'émetteur mémorise ce MTU pour la destination (cache des *routes*, 10 min par défaut,
`net.ipv4.route.mtu_expires`) et adapte la taille de ses paquets : c'est la **découverte du MTU du
chemin** (*path MTU discovery*, PMTUD). Linux positionne DF sur tout le trafic TCP. Pour voir le
PMTU appris :

```
ip route get ADRESSE          # affiche "mtu N expires Ns" quand un PMTU est mémorisé
ip route flush cache          # oublie les PMTU appris
```

### @@sec:ping@@ ping et le bit DF

L'option `-M` de `ping` (cf `man ping`) choisit le bit DF des échos émis :

```
ping -c 1 -s 1472 DEST               # défaut (-M want) : DF si le paquet tient dans le PMTU connu
ping -c 1 -M do -s 1472 DEST         # DF toujours : "Frag needed and DF set (mtu = N)" venant du
                                     #   routeur, puis "local error: message too long, mtu=N"
                                     #   quand le PMTU est connu (le paquet n'est plus émis)
ping -c 1 -M dont -s 1472 DEST       # jamais DF : les routeurs fragmentent, la réponse arrive
tracepath -n DEST                    # MTU du chemin saut par saut ("pmtu N")
```

### @@sec:capture@@ Ce que montre une capture

Avec `tcpdump -n -v -i eth0 icmp` sur l'émetteur, l'erreur apparaît sous la forme

`ROUTEUR > ÉMETTEUR: ICMP DEST unreachable - need to frag (mtu N), length 556`

l'adresse
source est celle du routeur fautif et le message cite l'en-tête du paquet refusé. Un paquet
fragmenté donne un premier fragment `flags [+]` (MF) puis des fragments `offset 1440 …
ip-proto-1` : seul le premier contient l'en-tête ICMP. La même capture sur l'interface de sortie
d'un routeur montre ce qui part vers le lien au MTU réduit et ce qui en revient.
""": """
The **MTU** (*maximum transmission unit*) of a link is the maximum number of data bytes a frame can
carry on it:

- **1500** on Ethernet;
- **2304** in the Wi-Fi standard (802.11),
but in practice a Wi-Fi interface stays at 1500 because the access point limits its frames towards
Ethernet;
- **9000** in general for *jumbo frames*, extended Ethernet frames that the IEEE standard does not
define and that every device of the network must accept.

### @@sec:adjust@@ Adjusting the MTU

**Raising the MTU** reduces the number of packets for the same amount of data: the IPv4 and TCP
headers (40 bytes) weigh 2.7 % of a 1500-byte packet but 0.4 % of a 9000-byte one, and every packet
less saves processing time (interrupts, traversal of the network stack).

*Jumbo frames* are therefore used on fast local networks (data centres, iSCSI or NFS storage,
computing clusters), provided that **all** the machines and all the switches of the network accept
them: a frame that is too large is silently dropped there, without any error message. Towards the
Internet the path stays at 1500 anyway.

**Lowering the MTU** is necessary when an extra header is added on a link whose MTU is fixed: PPPoE
(8 bytes, MTU 1492 at many Internet service providers), GRE, IPsec or VPN tunnels (section
@@ref:gre@@). On a slow or unreliable link (radio, satellite), shorter frames also limit the cost of
a transmission error (a corrupted frame is lost entirely) and the wait of a small urgent packet, of
voice for example, behind a large frame being transmitted: 1500 bytes occupy a 1 Mbit/s link for
12 ms.

An IPv4 packet contains a header of **20 bytes** (without options); an ICMP echo adds a header of
**8 bytes**: `ping -s 1472` therefore sends packets of 1500 bytes, the maximum without fragmentation
on Ethernet (`ping` prints `1472(1500) bytes`).

### @@sec:fragmentation@@ Fragmentation

In IPv4 a router that must send a packet larger than the MTU of the outgoing link **fragments** it:
every fragment carries the same identifier, the **MF** bit (*more fragments*, except on the last one)
and an **offset** (in 8-byte words). Only the destination reassembles the packet. Fragmentation is
costly (one fragment lost = the whole packet lost, CPU load, firewalls that see the port in the first
fragment only); modern systems avoid it by setting the **DF** bit (*don't fragment*): the router then
drops the packet and sends back to the sender an **ICMP type 3 (*destination unreachable*), code 4
(*fragmentation needed and DF set*)** message that gives the **MTU of the next link** (RFC 1191).

### @@sec:pmtud@@ Path MTU discovery (PMTUD)

The sender remembers this MTU for the destination (cache of the *routes*, 10 min by default,
`net.ipv4.route.mtu_expires`) and adapts the size of its packets: this is **path MTU discovery**
(PMTUD). Linux sets DF on all TCP traffic. To see the learned PMTU:

```
ip route get ADDRESS          # prints "mtu N expires Ns" when a PMTU is remembered
ip route flush cache          # forgets the learned PMTUs
```

### @@sec:ping@@ ping and the DF bit

The `-M` option of `ping` (see `man ping`) chooses the DF bit of the echoes it sends:

```
ping -c 1 -s 1472 DEST               # default (-M want): DF if the packet fits in the known PMTU
ping -c 1 -M do -s 1472 DEST         # DF always: "Frag needed and DF set (mtu = N)" from the
                                     #   router, then "local error: message too long, mtu=N"
                                     #   once the PMTU is known (the packet is no longer sent)
ping -c 1 -M dont -s 1472 DEST       # DF never: the routers fragment, the reply arrives
tracepath -n DEST                    # path MTU hop by hop ("pmtu N")
```

### @@sec:capture@@ What a capture shows

With `tcpdump -n -v -i eth0 icmp` on the sender, the error appears as

`ROUTER > SENDER: ICMP DEST unreachable - need to frag (mtu N), length 556`

The source address is that of the faulty router and the message quotes the header of the refused
packet. A fragmented packet gives a first fragment `flags [+]` (MF) then fragments `offset 1440 …
ip-proto-1`: only the first one contains the ICMP header. The same capture on the outgoing interface
of a router shows what leaves towards the link with the reduced MTU and what comes back from it.
""",
        """
Un tunnel **GRE** (*generic routing encapsulation*, RFC 2784) transporte un paquet IP dans un
autre paquet IP : l'en-tête IPv4 extérieur (**20** octets) et l'en-tête GRE (**4** octets sans
clé ni somme de contrôle) ajoutent **24 octets**. Le MTU du tunnel doit donc valoir **MTU du
chemin − 24** : le MTU par défaut d'un tunnel GRE (1476) suppose un chemin à 1500 et devient trop
grand dès que le chemin passe par un lien au MTU plus petit.

```
ip link add gre1 type gre local ADRESSE_WAN_LOCALE remote ADRESSE_WAN_DISTANTE ttl 64
ip link set gre1 mtu MTU up
ip addr add ADRESSE_TUN/30 dev gre1
ip -d link show gre1                 # "gre remote … local … pmtudisc" : DF sur le paquet extérieur
```

`local` et `remote` sont les adresses des deux routeurs sur le réseau qui les relie, `ADRESSE_TUN`
l'adresse intérieure de cette extrémité du tunnel. Le chargement du module crée aussi une
interface `gre0@NONE`, à ignorer. On teste le MTU du tunnel comme celui d'un lien :
`ping -M do -s` vers l'adresse intérieure du routeur distant. Si le MTU du tunnel est trop grand,
le paquet extérieur dépasse le MTU du chemin : erreur ICMP reçue par le routeur (pas par l'hôte
qui a émis le paquet intérieur) ou, si ces erreurs sont filtrées, disparition silencieuse.
""": """
A **GRE** tunnel (*generic routing encapsulation*, RFC 2784) carries an IP packet inside another IP
packet: the outer IPv4 header (**20** bytes) and the GRE header (**4** bytes without key or
checksum) add **24 bytes**. The MTU of the tunnel must therefore be **path MTU − 24**: the default
MTU of a GRE tunnel (1476) assumes a 1500 path and becomes too large as soon as the path goes through
a link with a smaller MTU.

```
ip link add gre1 type gre local LOCAL_WAN_ADDRESS remote REMOTE_WAN_ADDRESS ttl 64
ip link set gre1 mtu MTU up
ip addr add TUN_ADDRESS/30 dev gre1
ip -d link show gre1                 # "gre remote … local … pmtudisc": DF on the outer packet
```

`local` and `remote` are the addresses of the two routers on the network that links them,
`TUN_ADDRESS` the inner address of this end of the tunnel. Loading the module also creates an
interface `gre0@NONE`, to be ignored. The MTU of the tunnel is tested like that of a link:
`ping -M do -s` towards the inner address of the remote router. If the MTU of the tunnel is too
large, the outer packet exceeds the path MTU: an ICMP error received by the router (not by the host
that sent the inner packet) or, if these errors are filtered, a silent disappearance.
""",
        """
| outil | usage |
|-------|-------|
| `ip -d link show [IFACE]` | MTU et paramètres des interfaces et des tunnels |
| `ip link set dev IFACE mtu N` | changer le MTU d'une interface |
| `ping -M do -s TAILLE DEST` | sonder le MTU du chemin (DF) ; `-M dont` pour laisser fragmenter |
| `tracepath -n DEST` | PMTU saut par saut |
| `ip route get DEST` / `ip route flush cache` | PMTU mémorisé / oublié |
| `tcpdump -n -v -i IFACE icmp` | erreurs ICMP (`need to frag (mtu N)`), fragments (`flags [+]`, `offset`) |
| `tcpdump -n -i IFACE 'tcp[tcpflags] & tcp-syn != 0'` | les SYN et leur option `mss` |
| `ss -ti` | `mss`, `pmtu`, `advmss`, retransmissions des connexions TCP |
| `iperf3 -s` / `iperf3 -c SERVEUR -t 5` | transfert TCP de test (`-R` : sens inverse) |
| `nft list ruleset` | règles nftables du routeur |
""": """
| tool | use |
|-------|-------|
| `ip -d link show [IFACE]` | MTU and parameters of the interfaces and tunnels |
| `ip link set dev IFACE mtu N` | change the MTU of an interface |
| `ping -M do -s SIZE DEST` | probe the path MTU (DF); `-M dont` to let it fragment |
| `tracepath -n DEST` | PMTU hop by hop |
| `ip route get DEST` / `ip route flush cache` | PMTU remembered / forgotten |
| `tcpdump -n -v -i IFACE icmp` | ICMP errors (`need to frag (mtu N)`), fragments (`flags [+]`, `offset`) |
| `tcpdump -n -i IFACE 'tcp[tcpflags] & tcp-syn != 0'` | the SYNs and their `mss` option |
| `ss -ti` | `mss`, `pmtu`, `advmss`, retransmissions of the TCP connections |
| `iperf3 -s` / `iperf3 -c SERVER -t 5` | test TCP transfer (`-R`: reverse direction) |
| `nft list ruleset` | nftables rules of the router |
""",
        """
| réseau | préfixe | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `r1` eth0 (`{r1_lan1}`) |
| `wan1` | `{wan1}` | `r1` eth1 (`{r1_wan1}`), `wan` eth0 (`{wan_wan1}`) |
| `wan2` | `{wan2}` | `wan` eth1 (`{wan_wan2}`), `r2` eth0 (`{r2_wan2}`) |
| `lan2` | `{lan2}` | `r2` eth1 (`{r2_lan2}`), `m2` (`{m2}`) |
| `tun` (partie 3) | `{tun}` | extrémités du tunnel GRE : `r1` (`{r1_tun}`), `r2` (`{r2_tun}`) |
""": """
| network | prefix | machines |
|--------|---------|----------|
| `lan1` | `{lan1}` | `m1` (`{m1}`), `r1` eth0 (`{r1_lan1}`) |
| `wan1` | `{wan1}` | `r1` eth1 (`{r1_wan1}`), `wan` eth0 (`{wan_wan1}`) |
| `wan2` | `{wan2}` | `wan` eth1 (`{wan_wan2}`), `r2` eth0 (`{r2_wan2}`) |
| `lan2` | `{lan2}` | `r2` eth1 (`{r2_lan2}`), `m2` (`{m2}`) |
| `tun` (part 3) | `{tun}` | endpoints of the GRE tunnel: `r1` (`{r1_tun}`), `r2` (`{r2_tun}`) |
""",
        """
| symptôme | cause probable |
|----------|----------------|
| `local error: message too long, mtu=N` dès le premier `ping -M do` | un PMTU est déjà mémorisé (`ip route get`, `ip route flush cache`) |
| `ping -M do -s 1472` n'obtient ni réponse ni erreur | erreurs ICMP filtrées sur le chemin : le paquet est jeté en silence |
| `ping` passe mais `iperf3` reste à 0 bit/s | trou noir PMTUD : section @@ref:blackhole@@ |
| `iperf3` passe toujours alors que les erreurs ICMP sont filtrées | PMTU encore en cache sur la machine (10 min) ou MSS déjà réduit |
| `nft add rule … maxseg size set rt mtu` ne change rien | l'interface de sortie du routeur est à 1500 : `rt mtu` donne 1500 |
| `ping` à travers `gre1` muet, `ip -d link show gre1` correct | `local`/`remote` inversés, ou MTU du tunnel trop grand derrière un trou noir |
| `RTNETLINK answers: Operation not supported` | module `ip_gre` absent du noyau |
""": """
| symptom | probable cause |
|----------|----------------|
| `local error: message too long, mtu=N` from the very first `ping -M do` | a PMTU is already remembered (`ip route get`, `ip route flush cache`) |
| `ping -M do -s 1472` gets neither a reply nor an error | ICMP errors filtered on the path: the packet is silently dropped |
| `ping` works but `iperf3` stays at 0 bit/s | PMTUD black hole: section @@ref:blackhole@@ |
| `iperf3` still works although the ICMP errors are filtered | PMTU still cached on the machine (10 min) or MSS already reduced |
| `nft add rule … maxseg size set rt mtu` changes nothing | the outgoing interface of the router is at 1500: `rt mtu` gives 1500 |
| `ping` through `gre1` silent, `ip -d link show gre1` correct | `local`/`remote` swapped, or MTU of the tunnel too large behind a black hole |
| `RTNETLINK answers: Operation not supported` | module `ip_gre` missing from the kernel |
""",
        "Découverte du MTU de l'opérateur": "Discovery of the operator's MTU",
        'Dépannage': 'Troubleshooting',
        "ICMP rétabli : le routeur de l'opérateur émet de nouveau les erreurs ICMP": "ICMP restored: the operator's router emits the ICMP errors again",
        "MSS TCP adapté au lien de l'opérateur": "TCP MSS suited to the operator's link",
        'MSS clamping sur r1 ou r2, ou MTU réduit sur les interfaces WAN de r1 et r2': 'MSS clamping on r1 or r2, or reduced MTU on the WAN interfaces of r1 and r2',
        "MTU du lien de l'opérateur": "MTU of the operator's link",
        'MTU du tunnel': 'MTU of the tunnel',
        'MTU et découverte du PMTU en IPv4 (fragmentation, trou noir, tunnel GRE)': 'MTU and path MTU discovery in IPv4 (fragmentation, black hole, GRE tunnel)',
        'MTU, fragmentation IPv4 et découverte du PMTU': 'MTU, IPv4 fragmentation and path MTU discovery',
        'Organisation du TP': 'Organisation of the lab',
        'Outils': 'Tools',
        "Partie 1 — Découverte du MTU de l'opérateur": "Part 1 — Discovery of the operator's MTU",
        'Partie 2 — Trou noir PMTUD et correction': 'Part 2 — PMTUD black hole and fix',
        "Partie 3 — Tunnel GRE et surcoût d'encapsulation": 'Part 3 — GRE tunnel and encapsulation overhead',
        'TCP, MSS et trou noir PMTUD': 'TCP, MSS and PMTUD black hole',
        "Trou noir PMTUD : le routeur de l'opérateur (wan) n'émet plus les erreurs ICMP « fragmentation needed » ; les PMTU déjà appris par m1, m2, r1 et r2 sont oubliés": 'PMTUD black hole: the operator\'s router (wan) no longer emits the ICMP "fragmentation needed" errors; the PMTUs already learned by m1, m2, r1 and r2 are forgotten',
        'Trou noir PMTUD et correction': 'PMTUD black hole and fix',
        'Tunnel GRE entre r1 et r2': 'GRE tunnel between r1 and r2',
        "Tunnel GRE et surcoût d'encapsulation": 'GRE tunnel and encapsulation overhead',
        'commande qui affiche le PMTU mémorisé': 'command that shows the remembered PMTU',
        'connectivité IP conservée entre les deux sites par la correction (ping h1 → h2)': 'IP connectivity between the two sites kept by the fix (ping h1 → h2)',
        'correction faite sur les routeurs': 'fix made on the routers',
        'le plus grand paquet passe dans le tunnel, un octet de plus est refusé localement': 'the largest packet passes through the tunnel, one more byte is refused locally',
        'machine qui fragmente un paquet sans DF': 'machine that fragments a packet without DF',
        'ping de r1 vers r2 à travers le tunnel': 'ping from r1 to r2 through the tunnel',
        'plus grande charge utile de ping -M do qui traverse': 'largest payload of ping -M do that crosses',
        "surcoût d'encapsulation GRE": 'GRE encapsulation overhead',
        'transfert TCP de h1 vers h2 entre les sondes malgré le trou noir': 'TCP transfer from h1 to h2 between the probes despite the black hole',
        'transfert TCP de h2 vers h1 entre les sondes malgré le trou noir': 'TCP transfer from h2 to h1 between the probes despite the black hole',
        'tunnel gre1 sur {r} : type GRE, extrémités, MTU': 'tunnel gre1 on {r}: GRE type, endpoints, MTU',
        'type et code du message ICMP fragmentation needed': 'type and code of the ICMP fragmentation needed message',
    },
}
