"""TP Contrôle de trafic : tc (netem, tbf, htb, fq_codel, cake), filtres u32 / fw, marquage nftables, ifb.

Topologie du sujet R4B11 « TP1 TC » : le LAN A relie m1, r1 et r2 ; r1 dessert serveur1 et
serveur2 (ce dernier derrière un pont transparent caché ``wan`` qui ajoute un délai inconnu) ;
m2 est derrière r2.  Chaque partie du TP configure une interface distincte (r1 eth2, serveur2
eth0, r2 eth1, r1 eth1 + ifb) : la configuration complète coexiste et est notée à chaque
évaluation.

Évaluation par « miroir caché » (cf. ``lib/hidden_mirror.py``) : toute la topologie est clonée
(suffixe ``_h``, mêmes adresses, mêmes numéros d'interface).  À chaque évaluation la
configuration tc (``lib/tc.py``) et nft de r1, r2 et serveur2 est relue puis reconstruite sur
r1_h, r2_h et serveur2_h ; les mesures (ping, iperf3) se font uniquement entre clones, hors
de portée du trafic et des manipulations des étudiants.  L'état ``final`` applique la
solution de référence sur les machines réelles.

Textes : l'onglet Informations est un cours, indépendant de l'instance ; la maquette, le plan
d'adressage, les valeurs de l'instance, le plan du TP et les règles de l'évaluation sont dans la
question « Organisation du TP » ; chaque question se termine par sa solution dans un bloc
``instructor()`` (mode enseignant), avec les commandes de l'état ``final``.
"""
import random
import statistics
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

import firewall
import hidden_mirror
import tc
from SRE import params
from SRE.common import TranslatedText
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from ips import random_ipv4networks, random_ipv4s, random_ips_from_topology
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from state_helpers import create_hosts_file

default_language = 'fr'
tr = make_tr(default_language)

# evaluated at import time, before _TRANSLATIONS (end of the file): the English inline too
title = tr("tc : contrôle de trafic (netem, tbf, htb, cake)", en="tc: traffic control (netem, tbf, htb, cake)")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 60
# The Kathara export would reveal the mirror network and the hidden WAN delay.
export_kathara_project = False
# An evaluation runs ~30 s of measurements on the mirror network.
eval_interval_without_exam_mode = 120
eval_before_exit = True
record_sessions = False

DOMAIN = "tp-tc.lan"
MIRROR = "_h"                 # suffix of the hidden clones (hidden_mirror.expand_topology)
PORT_A, PORT_B = 5201, 5202   # iperf3 ports of the exercises (students' own servers)
GRADE_PORT_DEFAULT = 5302     # part 2: flow of the default class on the mirror
GRADE_PORT_DOWNLOAD = 5301    # part 4: download flow on the mirror
TBF_BURST, TBF_LATENCY = "30kbit", "400ms"
#: (machine, interface) configured by each part; shared by final(), grade() and the texts.
IFACE = {
    'netem': ('r1', 'eth2'),        # part 1: toward serveur2
    'reverse': ('serveur2', 'eth0'),  # part 1: loss toward r1
    'shape': ('r2', 'eth1'),        # part 2: toward m2
    'prio': ('r1', 'eth1'),         # part 3: toward serveur1
    'ingress': ('r1', 'eth1'),      # part 4: from serveur1
}
#: interfaces whose tc configuration is copied onto the mirror
MIRRORED = {'r1': ['eth0', 'eth1', 'eth2'], 'r2': ['eth0', 'eth1'], 'serveur2': ['eth0']}
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE

_TOPOLOGY = {
    'netA': {'m1': 0, 'r1': 0, 'r2': 0},
    'netS1': {'r1': 1, 'serveur1': 0},
    'netS2a': {'r1': 2, 'wan': 0},        # wan: hidden transparent bridge (netem delay each way)
    'netS2b': {'wan': 1, 'serveur2': 0},  # same IPv4 subnet as netS2a
    'netB': {'r2': 1, 'm2': 0},
}
_SPECS = {
    'm1': {'bridged': True, 'x11_host': True, 'color': 'lightyellow'},
    'r1': {'color': 'lightblue'},
    'r2': {'color': 'lightblue'},
    'serveur1': {'color': 'lightgreen'},
    'serveur2': {'color': 'lightgreen'},
    'm2': {'color': 'lightyellow'},
    'wan': {'hidden': True, 'allow_connection': False},
}
_FULL_TOPOLOGY, _FULL_SPECS = hidden_mirror.expand_topology(_TOPOLOGY, _SPECS, extra_specs={'m1': {'x11_host': False}})
#: addressing topology: the bridge has no IP address
_IP_TOPOLOGY = {net: {m: i for m, i in ms.items() if m != 'wan'} for net, ms in _TOPOLOGY.items()}


def H(machine: str) -> str:
    """Name of the hidden clone of *machine*."""
    return machine + MIRROR


def mbit(value: int) -> float:
    return value * 1_000_000.0


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    wan_delay_ms: int = 0        # part 1: one-way delay of the hidden bridge toward serveur2
    netem_delay_ms: int = 0      # part 1: netem on r1 eth2
    netem_jitter_ms: int = 0
    netem_loss_pct: int = 0
    reverse_loss_pct: int = 0    # part 1: netem loss on serveur2 eth0
    tbf_rate_mbit: int = 0       # part 2: intermediate tbf step (question only)
    htb_rate_mbit: int = 0       # part 2: total rate toward m2 (80 % / 20 % split by port)
    prio_rate_mbit: int = 0      # part 3: total rate toward serveur1 (80 % / 20 % by mark), < VDE capacity
    mark: int = 0                # part 3: packet mark of the netA traffic
    cake_mbit: int = 0           # part 4: ingress bandwidth from serveur1

    @classmethod
    def generate(cls):
        data = cls()
        data.wan_delay_ms = random.choice([10, 15, 20, 25, 30, 35, 40])
        data.netem_delay_ms = random.choice([80, 100, 120, 150])
        data.netem_jitter_ms = random.choice([20, 30, 40, 50])
        data.netem_loss_pct = random.choice([5, 8, 10, 12, 15])
        data.reverse_loss_pct = random.choice([5, 8, 10, 12, 15])
        data.tbf_rate_mbit = random.choice([1, 2, 3, 4])
        data.htb_rate_mbit = random.choice([10, 20])
        # The Kathara links are userspace VDE switches: ~45-50 Mbit/s of TCP at most, so every
        # shaped rate stays well below that (an unshaped flow must visibly exceed the limit).
        data.prio_rate_mbit = random.choice([20, 25, 30])
        data.mark = random.randint(11, 99)   # never 10, the value of the handout
        data.cake_mbit = random.choice([10, 15, 20, 25])

        net_a, net_s1, net_s2, net_b = random_ipv4networks(
            masks=[24, 24, 24, 24],
            from_private_network=True,
            exclude=[IPv4Network("172.17.0.0/16"), IPv4Network("10.0.0.0/16")],
        )
        data.nets.netA, data.nets.netS1, data.nets.netB = net_a, net_s1, net_b
        data.nets.netS2a = data.nets.netS2b = net_s2   # one subnet on both sides of the bridge
        random_ips_from_topology(data, _IP_TOPOLOGY)
        # netS2a / netS2b are drawn independently: r1 must not take serveur2's address
        data.ips.r1_netS2a = random_ipv4s(net_s2, 1, exclude_ips=[data.ips.serveur2])[0]
        hidden_mirror.copy_addressing(data, _IP_TOPOLOGY)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _topology = _FULL_TOPOLOGY
    _machine_specs = _FULL_SPECS
    _network_specs = {
        'netA': {'color': 'lightyellow'},
        'netS1': {'color': 'lightgreen'},
        'netS2a': {'color': 'lightgreen'},
        'netS2b': {'color': 'lightgreen'},
        'netB': {'color': 'lightyellow'},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")
        r1_a, r2_a = d.ips.r1_netA.ip, d.ips.r2_netA.ip

        base: Dict[str, NetConfigEntry] = {
            # m1 is also linked to the workstation (last interface), where Docker already
            # installs the default route: specific routes only.
            'm1': [([d.ips.m1], [(d.nets.netS1, r1_a), (d.nets.netS2a, r1_a), (d.nets.netB, r2_a)])],
            'r1': [([d.ips.r1_netA], [(d.nets.netB, r2_a)]), ([d.ips.r1_netS1], []), ([d.ips.r1_netS2a], [])],
            'r2': [([d.ips.r2_netA], [(default, r1_a)]), ([d.ips.r2_netB], [])],
            'serveur1': [([d.ips.serveur1], [(default, d.ips.r1_netS1.ip)])],
            'serveur2': [([d.ips.serveur2], [(default, d.ips.r1_netS2a.ip)])],
            'm2': [([d.ips.m2], [(default, d.ips.r2_netB.ip)])],
            'wan': [None, None],
        }
        # the mirror uses the very same addresses and routes
        self.net_config: Dict[str, NetConfigEntry] = dict(base)
        for m, nc in base.items():
            self.net_config[H(m)] = nc
        self.routers = ['r1', 'r2', H('r1'), H('r2')]

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Le contrôle de trafic : qdisc, classes et filtres"), tag="qdisc")
            + tr("""
Le **contrôle de trafic** du noyau Linux se règle avec la commande `tc` (paquet `iproute2`). Il
permet d'émuler un réseau dégradé (**netem**), de limiter un débit (**tbf**), de partager la
bande passante entre des classes (**htb**), d'utiliser des files d'attente modernes
(**fq_codel**, **cake**), de classer les paquets (filtres **u32**, **fw**, marquage
**nftables**) et de réguler le trafic *entrant* (**ifb**).

Chaque interface réseau possède en sortie (*egress*) une **discipline de file d'attente**
(*queueing discipline*, **qdisc**) qui décide dans quel ordre, et à quel rythme, les paquets
sont émis. Par défaut : `noqueue` (interfaces virtuelles) ou `pfifo_fast` / `fq_codel`.

- Les qdisc **sans classes** (*classless*) traitent tout le trafic de la même façon : `pfifo`,
  `netem`, `tbf`, `sfq`, `fq_codel`, `cake`.
- Les qdisc **à classes** (*classful*) ont des **classes** (`htb`, `prio`, …) : un **filtre**
  (`u32`, `fw`, `flower`) range chaque paquet dans une classe, et chaque classe a sa propre
  qdisc feuille (par défaut `pfifo`).

### @@sec:commands@@ Identifiants et commandes

Les objets sont désignés par des identifiants `majeur:mineur` **en hexadécimal** : la qdisc
racine `1:` (ou `1:0`), ses classes `1:1`, `1:10`, `1:20`. `root` désigne la racine,
`parent 1:10` l'attache sous la classe `1:10`. Les commandes :

```
tc qdisc  add | replace | change | del  dev eth1 root ...
tc class  add | change | del            dev eth1 parent 1: classid 1:10 htb ...
tc filter add | del                     dev eth1 parent 1: protocol ip prio 1 u32 ...
tc qdisc show dev eth1          tc class show dev eth1          tc filter show dev eth1
tc -s qdisc show dev eth1       tc -s class show dev eth1       # avec les compteurs
tc qdisc del dev eth1 root      # tout supprimer sur eth1
```

`tc qdisc add` échoue quand une qdisc est déjà configurée à cet endroit : `replace` la remplace
(ou la crée), `del` la supprime. La configuration vit dans le noyau : rien n'en est conservé au
redémarrage de la machine.

`tc -s class show` affiche par classe les octets et paquets envoyés, les rejets (`dropped`)
et les dépassements (`overlimits`) : indispensable pour vérifier qu'un filtre dirige bien le
trafic vers la classe prévue (`watch -n 1 tc -s class show dev eth1`).
""")
            + info_subtitle(tr("netem : émuler un réseau"), tag="netem")
            + tr("""
`netem` (*network emulator*, `man tc-netem`) retarde, perd, duplique ou réordonne les
paquets qui **sortent** par l'interface :

```
tc qdisc add     dev eth2 root netem delay 100ms            # délai fixe
tc qdisc replace dev eth2 root netem delay 100ms 50ms       # ± 50 ms de gigue (uniforme)
tc qdisc replace dev eth2 root netem delay 100ms 50ms loss 10%
tc qdisc del     dev eth2 root
```

Le délai s'ajoute dans **un seul sens** (celui de l'interface de sortie) : un `ping` qui
traverse `eth2` à l'aller et revient par le même routeur voit son RTT augmenter du délai
une seule fois. De même, une perte configurée sur `eth2` ne touche que les paquets qui sortent
par `eth2` : ceux qui reviennent en sens inverse (les acquittements d'un transfert, par
exemple) ne sont pas affectés.
""")
            + info_subtitle(tr("tbf : limiter un débit"), tag="tbf")
            + tr("""
`tbf` (*token bucket filter*, `man tc-tbf`) laisse passer les paquets au rythme de jetons
produits à `rate` ; `burst` est la taille du seau (la rafale maximale, au moins un MTU) et
`latency` (ou `limit`) la durée maximale qu'un paquet peut attendre dans la file avant d'être
jeté :

```
tc qdisc add dev eth1 root tbf rate 1mbit burst 30kbit latency 400ms
```

### @@sec:bufferbloat@@ Bufferbloat et fq_codel

Une file de 400 ms de paquets en attente signifie qu'**un `ping` qui traverse le lien chargé
voit son RTT augmenter de 400 ms** : c'est le *bufferbloat*. Remplacer la file `pfifo`
par **`fq_codel`** (file équitable par flux + contrôleur de délai CoDel, cible 5 ms) rend la
latence quasi indépendante de la charge : `tc qdisc add dev eth1 parent 1:10 fq_codel` (ici
sous une classe `htb`, section @@ref:htb@@).
""")
            + info_subtitle(tr("htb : partager la bande passante"), tag="htb")
            + tr("""
`htb` (*hierarchy token bucket*, `man tc-htb`) répartit un débit entre des classes
hiérarchiques. Chaque classe a un débit **garanti** `rate` et un plafond `ceil` ; une classe
peut *emprunter* à ses sœurs la bande passante qu'elles n'utilisent pas, jusqu'à `ceil`.
L'emprunt passe par la **classe parente**, qui porte le débit total (`1:1` ci-dessous) : une
classe attachée directement à la racine `1:` n'a personne à qui emprunter et reste limitée à
son `rate`, quel que soit son `ceil`. `prio` (0 = la plus prioritaire) décide qui emprunte en
premier. `default` (en **hexa**) désigne la classe des paquets qu'aucun filtre ne classe :

```
tc qdisc add dev eth1 root handle 1: htb default 20
tc class add dev eth1 parent 1: classid 1:1  htb rate 10mbit
tc class add dev eth1 parent 1:1 classid 1:10 htb rate 8mbit ceil 10mbit
tc class add dev eth1 parent 1:1 classid 1:20 htb rate 2mbit ceil 10mbit
tc qdisc add dev eth1 parent 1:10 fq_codel
tc qdisc add dev eth1 parent 1:20 fq_codel
# le trafic vers le port TCP 5201 va dans 1:10 ; le reste dans 1:20 (default)
tc filter add dev eth1 protocol ip parent 1: prio 1 u32 match ip dport 5201 0xffff flowid 1:10
```

### @@sec:u32@@ Le filtre u32

Le filtre **u32** compare des mots de l'en-tête (`match ip dport PORT 0xffff`,
`match ip src 192.0.2.0/24`, `match ip protocol 6 0xff`). `tc filter show` affiche la
comparaison brute (`match 00001451/0000ffff at 20` : 0x1451 = 5201, à l'offset 20 de
l'en-tête IP).
""")
            + info_subtitle(tr("Marquage nftables et filtre fw"), tag="mark")
            + tr("""
Plutôt que décrire les paquets dans `tc`, on peut les **marquer** avec le pare-feu et classer
sur la marque. En nftables la marque est `meta mark` ; on la pose dans une chaîne de type
`filter` accrochée à un *hook* traversé par le trafic **routé** (`prerouting` ou `forward` :
le hook `output` ne voit que les paquets émis par le routeur lui-même) :

```
nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule  ip mangle prerouting ip saddr 192.0.2.0/24 meta l4proto tcp meta mark set 10
nft list ruleset
```

Côté `tc`, le filtre **fw** classe selon la marque (`handle` = valeur de la marque) :

```
tc filter add dev eth1 parent 1: protocol ip handle 10 fw flowid 1:10
```

La marque n'existe que dans le noyau du routeur qui la pose : elle n'est pas transportée dans
le paquet. Les deux outils l'affichent en hexadécimal : `meta mark set 0x0000000a` dans
`nft list ruleset`, `handle 0xa` dans `tc filter show`.

`iptables -t mangle … -j MARK --set-mark 10` fait la même chose avec l'ancien outil.
""")
            + info_subtitle(tr("Trafic entrant : ifb et cake"), tag="ingress")
            + tr("""
Une qdisc ne retient les paquets qu'en **sortie**. En entrée (*ingress*) le noyau ne peut
que *policer*, c'est-à-dire jeter l'excédent, sans file d'attente. Pour **régler** le débit
reçu, on redirige le trafic entrant vers une interface virtuelle **ifb** (*intermediate
functional block*), dont la sortie, elle, peut être régulée :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev eth1 handle ffff: ingress
tc filter add dev eth1 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth 50mbit
```

La qdisc `ingress` (identifiant `ffff:`) ne retient aucun paquet : elle ne sert qu'à accrocher
des filtres en entrée, et cohabite avec la qdisc racine de la même interface
(`tc qdisc del dev eth1 ingress` la supprime avec ses filtres). `match u32 0 0` est vrai pour
tout paquet ; l'interface `ifb0` doit être active (`up`), sinon les paquets redirigés sont
perdus.

### @@sec:cake@@ cake

**cake** (*common applications kept enhanced*, `man tc-cake`) combine en une seule qdisc
régulation de débit, file équitable par flux, AQM et priorisation : c'est la solution
moderne pour un lien d'accès. `tc -s qdisc show dev ifb0` montre son activité.
""")
            + info_subtitle(tr("Mesurer"), tag="measure")
            + tr("""
- `ping -c 20 -i 0.2 DEST` : RTT min/avg/max et **mdev** (écart-type, image de la gigue),
  pertes.
- `iperf3 -s [-p PORT]` sur le serveur ; `iperf3 -c SERVEUR [-p PORT] -t 10` sur le client ;
  `-R` (*reverse*) fait envoyer le serveur vers le client (mesure du débit *descendant*) ;
  `-J` produit du JSON. Un serveur iperf3 ne sert qu'un client à la fois : lancez-en un par
  port.
- `ss -ti dst SERVEUR` pendant un transfert : `rtt:<moyenne>/<variation>`, `cwnd`, `retrans`,
  `bytes_acked`… (`watch -n 0.5 "ss -ti dst SERVEUR"`).
- Wireshark, ou `dumpcap -i eth0 -w FICHIER.pcap` sur une machine sans écran puis ouverture du
  fichier dans Wireshark : *Statistiques → Graphique des flux TCP → Temps d'aller-retour* ;
  filtre `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
  tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
  tcp.analysis.lost_segment` puis *Statistiques → Conversations → TCP* pour la proportion.
""")
        )

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        d = self.data
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in self.routers))
            # MTU-sized frames (no GSO/GRO super-packets): realistic losses, rates and captures.
            for i in range(len(self.net_config.get(m, []))):
                self.cmd(m, f"ethtool -K eth{i} gso off tso off gro off", allow_error=True)
        create_hosts_file(net_scheme=self, domain_extension=DOMAIN)

        # Transparent bridge toward serveur2 with a fixed one-way delay in each direction:
        # invisible at layer 3 (no hop), discovered by measurement in part 1.
        for wan in ('wan', H('wan')):
            self.cmd(wan, "ip link set eth0 up; ip link set eth1 up; ip link add br0 type bridge; "
                          "ip link set eth0 master br0; ip link set eth1 master br0; ip link set br0 up")
            for iface in ('eth0', 'eth1'):
                self.cmd(wan, f"tc qdisc add dev {iface} root netem delay {d.wan_delay_ms}ms")

        # iperf3 servers of the mirror (students start their own on the real machines).
        for m, ports in {H('serveur1'): (PORT_A, GRADE_PORT_DOWNLOAD),
                         H('m2'): (PORT_A, GRADE_PORT_DEFAULT),
                         H('m1'): (PORT_A,)}.items():
            for port in ports:
                self.cmd(m, f"iperf3 -s -D -p {port} >/dev/null 2>&1")

        firewall.flush_ruleset(self, 'r1')
        firewall.flush_ruleset(self, H('r1'))

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution on the real machines (the mirror is fed by the evaluation).

        Idempotent: every tree is deleted before being rebuilt."""
        d = self.data
        R, T, C, M = d.htb_rate_mbit, d.prio_rate_mbit, d.cake_mbit, d.mark
        r1, dev_netem = IFACE['netem']
        s2, dev_rev = IFACE['reverse']
        r2, dev_shape = IFACE['shape']
        _, dev_prio = IFACE['prio']

        # part 1
        self.cmd(r1, f"tc qdisc replace dev {dev_netem} root netem delay {d.netem_delay_ms}ms "
                     f"{d.netem_jitter_ms}ms loss {d.netem_loss_pct}%")
        self.cmd(s2, f"tc qdisc replace dev {dev_rev} root netem loss {d.reverse_loss_pct}%")

        # part 2: htb by destination port toward m2
        self.cmd(r2, f"tc qdisc del dev {dev_shape} root 2>/dev/null; true")
        self.cmd(r2, f"tc qdisc add dev {dev_shape} root handle 1: htb default 20")
        self.cmd(r2, f"tc class add dev {dev_shape} parent 1: classid 1:1 htb rate {R}mbit ceil {R}mbit")
        self.cmd(r2, f"tc class add dev {dev_shape} parent 1:1 classid 1:10 htb rate {int(R * 0.8)}mbit ceil {R}mbit")
        self.cmd(r2, f"tc class add dev {dev_shape} parent 1:1 classid 1:20 htb rate {int(R * 0.2)}mbit ceil {R}mbit")
        self.cmd(r2, f"tc qdisc add dev {dev_shape} parent 1:10 fq_codel")
        self.cmd(r2, f"tc qdisc add dev {dev_shape} parent 1:20 fq_codel")
        self.cmd(r2, f"tc filter add dev {dev_shape} protocol ip parent 1: prio 1 u32 "
                     f"match ip dport {PORT_A} 0xffff flowid 1:10")

        # part 3: nft mark + htb by mark toward serveur1
        self.cmd(r1, "nft delete table ip mangle 2>/dev/null; true")
        self.cmd(r1, "nft add table ip mangle")
        self.cmd(r1, "nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'")
        self.cmd(r1, f"nft add rule ip mangle prerouting ip saddr {d.nets.netA} meta l4proto tcp meta mark set {M}")
        self.cmd(r1, f"tc qdisc del dev {dev_prio} root 2>/dev/null; true")
        self.cmd(r1, f"tc qdisc add dev {dev_prio} root handle 1: htb default 20")
        self.cmd(r1, f"tc class add dev {dev_prio} parent 1: classid 1:10 htb rate {int(T * 0.8)}mbit ceil {T}mbit prio 0")
        self.cmd(r1, f"tc class add dev {dev_prio} parent 1: classid 1:20 htb rate {int(T * 0.2)}mbit ceil {T}mbit prio 1")
        self.cmd(r1, f"tc qdisc add dev {dev_prio} parent 1:10 fq_codel")
        self.cmd(r1, f"tc qdisc add dev {dev_prio} parent 1:20 fq_codel")
        self.cmd(r1, f"tc filter add dev {dev_prio} parent 1: protocol ip handle {M} fw flowid 1:10")

        # part 4: ingress of eth1 redirected to ifb0, shaped by cake
        self.cmd(r1, "ip link add ifb0 type ifb 2>/dev/null; ip link set ifb0 up")
        self.cmd(r1, f"tc qdisc del dev {dev_prio} ingress 2>/dev/null; true")
        self.cmd(r1, f"tc qdisc add dev {dev_prio} handle ffff: ingress")
        self.cmd(r1, f"tc filter add dev {dev_prio} parent ffff: protocol ip u32 match u32 0 0 "
                     f"action mirred egress redirect dev ifb0")
        self.cmd(r1, f"tc qdisc replace dev ifb0 root cake bandwidth {C}mbit")


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


def _close_ms(value_s, expected_ms, tol_ms=2.0) -> bool:
    """A netem time (seconds) equals the expected number of milliseconds."""
    return value_s is not None and abs(value_s * 1000 - expected_ms) <= tol_ms


def _approx(value, expected, rel=0.25, abs_margin=0.0) -> bool:
    return value is not None and abs(value - expected) <= rel * expected + abs_margin


def _by_language(text: TranslatedText, **values) -> TranslatedText:
    """*text* (a tr() text) formatted with *values*; a dict value gives one value per language (a decimal
    comma in French, a point in English)."""
    return TranslatedText({lang: version.format(**{k: v[lang] if isinstance(v, dict) else v
                                                  for k, v in values.items()})
                           for lang, version in text.items()})


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        R, T, C, M = d.htb_rate_mbit, d.prio_rate_mbit, d.cake_mbit, d.mark
        base_rtt_ms = 2 * d.wan_delay_ms
        r1, dev_netem = IFACE['netem']
        s2, dev_rev = IFACE['reverse']
        r2, dev_shape = IFACE['shape']
        _, dev_prio = IFACE['prio']
        ip = {m: str(getattr(d.ips, H(m)).ip) for m in ('m1', 'm2', 'serveur1', 'serveur2')}

        # ---------------- diagnostics kept in the archive ---------------------------
        for m in (r1, r2, s2):
            for c in ("tc -s qdisc show", "tc -j qdisc show", "ip -o link show type ifb"):
                self.test(m, c, allow_error=True)
        for c in ("nft list ruleset", "iptables-save -t mangle"):
            self.test(r1, c, allow_error=True)

        # ---------------- step 1: read the real routers; step 2: rebuild on the mirror -----
        mirror = {m: tc.transplant_tc(self, m, H(m), devices=MIRRORED[m]) for m in MIRRORED}
        firewall.transplant_ruleset(self, src=r1, dst=H(r1))
        nft_rules = tc.nft_mark_rules(tc.get_nft_rules(self, r1))
        m_r1, m_r2, m_s2 = mirror[r1].model, mirror[r2].model, mirror[s2].model
        for m, t in mirror.items():
            for item in t.render.skipped:
                self.add_warning(tr("configuration tc non reproduite sur le miroir de {m} : {item}")
                                 .format(m=m, item=item), step=2)
        if any(rule['xt'] for rule in nft_rules):
            self.add_warning(tr("marquage iptables détecté sur r1 : seul nftables est reproduit sur le miroir"),
                             step=2)

        # ---------------- step 3: measurements from m1_h ----------------------------
        # part 1: RTT toward serveur2_h through r1_h eth2 (netem) and the hidden bridge
        ping_s2_out = self.test(H('m1'), tc.ping_cmd(ip['serveur2'], count=20, interval=0.2),
                                step=3, timeout=14, allow_error=True)[0]
        ping_s2 = tc.parse_ping(ping_s2_out)
        # the median of the echoes, not the average of the summary: the losses of part 2 (netem on r1
        # and on serveur2) also drop ARP frames, and with a cold cache (the first evaluation) the lost
        # request or reply is retried a second later; the echoes queued behind it come back up to
        # 1.4 s late and the average is 250 to 410 ms for a 150 ms path (8 evaluations of 40 on s14,
        # about what 5 % + 12 % of losses give)
        times_s2 = tc.ping_times(ping_s2_out)
        rtt_s2 = statistics.median(times_s2) if times_s2 else None
        # part 2: two concurrent flows toward m2_h (port 5201 → priority class, 5302 → default)
        # and a ping under load; one shell so that the flows really overlap
        flow_a = tc.iperf3_cmd(ip['m2'], PORT_A, seconds=5)
        flow_b = tc.iperf3_cmd(ip['m2'], GRADE_PORT_DEFAULT, seconds=5)
        ping_load = tc.ping_cmd(ip['m2'], count=8, interval=0.3, deadline=5)
        part2_cmd = (f"( {flow_a} >/tmp/.sre_tc_a 2>&1 & {flow_b} >/tmp/.sre_tc_b 2>&1 & sleep 1.5; "
                     f"{ping_load} >/tmp/.sre_tc_p 2>&1; wait ); "
                     f'echo "===A"; cat /tmp/.sre_tc_a; echo "===B"; cat /tmp/.sre_tc_b; echo "===P"; cat /tmp/.sre_tc_p')
        part2_out, _ = self.test(H('m1'), part2_cmd, step=3, timeout=20, allow_error=True)
        shape_hi = tc.parse_iperf3(tc.section_text(part2_out, 'A'))
        shape_lo = tc.parse_iperf3(tc.section_text(part2_out, 'B'))
        ping_shape = tc.parse_ping(tc.section_text(part2_out, 'P'))
        # part 4: download from serveur1_h through r1_h eth1 ingress → ifb → cake
        download = tc.parse_iperf3(self.test(H('m1'), tc.iperf3_cmd(ip['serveur1'], GRADE_PORT_DOWNLOAD, seconds=4, reverse=True),
                                             step=3, timeout=16, allow_error=True)[0])

        # ---------------- step 4: measurements from serveur1_h ----------------------
        # part 3: reverse mode makes m1_h (marked, netA) and m2_h (netB) send toward serveur1_h
        # at the same time through r1_h eth1
        flow_hi = tc.iperf3_cmd(ip['m1'], PORT_A, seconds=5, reverse=True)
        flow_lo = tc.iperf3_cmd(ip['m2'], PORT_A, seconds=5, reverse=True)
        part3_cmd = (f"( {flow_hi} >/tmp/.sre_tc_a 2>&1 & {flow_lo} >/tmp/.sre_tc_b 2>&1; wait ); "
                     f'echo "===A"; cat /tmp/.sre_tc_a; echo "===B"; cat /tmp/.sre_tc_b')
        part3_out, _ = self.test(H('serveur1'), part3_cmd, step=4, timeout=20, allow_error=True)
        prio_hi = tc.parse_iperf3(tc.section_text(part3_out, 'A'))
        prio_lo = tc.parse_iperf3(tc.section_text(part3_out, 'B'))

        def mbps(result) -> float:
            return (result.get('bps') or 0.0) / 1e6

        # ---------------- organisation ----------------------------------------------
        addressing = tr("""
| réseau | préfixe | machines |
|--------|---------|----------|
| `netA` | `{netA}` | `m1` (`{m1}`), `r1` eth0 (`{r1_a}`), `r2` eth0 (`{r2_a}`) |
| `netS1` | `{netS1}` | `r1` eth1 (`{r1_s1}`), `serveur1` (`{serveur1}`) |
| `netS2` | `{netS2}` | `r1` eth2 (`{r1_s2}`), `serveur2` (`{serveur2}`) |
| `netB` | `{netB}` | `r2` eth1 (`{r2_b}`), `m2` (`{m2}`) |
""").format(netA=d.nets.netA, netS1=d.nets.netS1, netS2=d.nets.netS2a, netB=d.nets.netB,
            m1=d.ips.m1.ip, r1_a=d.ips.r1_netA.ip, r2_a=d.ips.r2_netA.ip, r1_s1=d.ips.r1_netS1.ip,
            serveur1=d.ips.serveur1.ip, r1_s2=d.ips.r1_netS2a.ip, serveur2=d.ips.serveur2.ip,
            r2_b=d.ips.r2_netB.ip, m2=d.ips.m2.ip)
        values = tr("""
| partie | machine / interface | paramètres de **votre** instance |
|--------|---------------------|----------------------------------|
| 2 — netem | `r1` `{dev_netem}` (vers `serveur2`) puis `serveur2` `{dev_rev}` | délai **{delay} ms**, gigue **{jitter} ms**, pertes **{loss} %** ; pertes retour **{rloss} %** |
| 3 — shaping | `r2` `{dev_shape}` (vers `m2`) | tbf **{tbf} Mbit/s** puis htb **{R} Mbit/s** ({hi} / {lo}) |
| 4 — priorité | `r1` `{dev_prio}` (vers `serveur1`) | marque **{mark}**, htb **{T} Mbit/s** ({thi} / {tlo}) |
| 5 — ingress | `r1` `{dev_prio}` → `ifb0` | cake **{C} Mbit/s** |
""").format(dev_netem=dev_netem, dev_rev=dev_rev, dev_shape=dev_shape, dev_prio=dev_prio,
            delay=d.netem_delay_ms, jitter=d.netem_jitter_ms, loss=d.netem_loss_pct, rloss=d.reverse_loss_pct,
            tbf=d.tbf_rate_mbit, R=R, hi=int(R * 0.8), lo=int(R * 0.2),
            mark=M, T=T, thi=int(T * 0.8), tlo=int(T * 0.2), C=C)
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="989e6e8af734d92f",
            description=tr("""
Lisez l'onglet **Informations** : il présente `tc`, les qdisc utilisées, les filtres, le marquage
des paquets, la régulation du trafic entrant et les outils de mesure.

**La maquette.** Le LAN `netA` relie `m1`, `r1` et `r2`. Le routeur `r1` dessert `serveur1`
(`eth1`) et `serveur2` (`eth2`) ; `m2` est derrière `r2`. Le lien de `r1` vers `serveur2` traverse
un « WAN » qui ajoute un délai inconnu : vous l'estimerez dans la partie 1.
""")
            + addressing
            + tr("""
**Déjà en place** (ne pas modifier) : adresses IP, routes et routage IPv4 sur `r1` et `r2`, noms
dans `/etc/hosts` (`ping serveur1` fonctionne), *offloads* GSO/GRO désactivés (les trames ont
la taille du MTU : pertes et débits réalistes). `m1` dispose aussi d'une interface vers votre
poste de travail (`172.17.0.1`) : `wireshark` lancé sur `m1` s'affiche sur votre écran.

Les liens de la maquette sont des commutateurs **VDE** en espace utilisateur : leur capacité
plafonne vers **45 à 50 Mbit/s** (vous la mesurerez dans la partie 1). Les débits demandés sont
donc tous inférieurs à 30 Mbit/s, sinon la limitation ne se verrait pas.

**Les valeurs de votre instance** (délais, débits, marque) :
""")
            + values
            + tr("""
**Plan du TP.** Les énoncés détaillés sont dans les questions suivantes, numérotées comme les
parties.

- **Partie 1 — Diagnostic** : mesurer le RTT de `m1` vers `serveur1` et vers `serveur2` (le lien
  vers `serveur2` traverse le « WAN » dont vous estimerez le délai) et la capacité brute d'un
  lien. Cours : section @@ref:measure@@.
- **Partie 2 — netem** sur `r1 {dev_netem}` (vers `serveur2`) : délai, gigue, pertes ; pertes dans
  le sens retour sur `serveur2 {dev_rev}`. La configuration finale (délai + gigue + pertes) reste
  en place. Cours : section @@ref:netem@@.
- **Partie 3 — Shaping vers m2** sur `r2 {dev_shape}` : tbf (mesures, puis supprimé), puis htb
  80 % / 20 % selon le port avec files `fq_codel`. Cours : sections @@ref:tbf@@ et @@ref:htb@@.
- **Partie 4 — Priorité par marquage** sur `r1 {dev_prio}` (vers `serveur1`) : marque nftables du
  trafic de `netA`, htb à deux classes de priorités différentes, filtre `fw`. Cours : section
  @@ref:mark@@.
- **Partie 5 — Ingress** sur `r1 {dev_prio}` : redirection vers `ifb0` et `cake`. Cours : section
  @@ref:ingress@@.

**Règles valables pour tout le TP.**

- Chaque partie configure une interface différente (les parties 4 et 5 : la sortie puis
  l'entrée de la même interface) : **laissez en place** la configuration d'une partie terminée
  en passant à la suivante (seul le `tbf` de la partie 3 est remplacé par le `htb`). `tc` ne
  conserve rien au redémarrage d'une machine.
- Les serveurs `iperf3` sont à lancer vous-même sur `serveur1`, `serveur2` ou `m2` selon
  l'exercice (`iperf3 -s`, `iperf3 -s -p {pb}`, …), un par port : aucun ne tourne au départ.
- Le marquage de la partie 4 se fait avec **nftables** : une règle `iptables` ne serait pas
  reproduite sur la copie du réseau où l'évaluation fait ses mesures.
- Captures : Wireshark se lance sur `m1` ; sur une autre machine,
  `dumpcap -i eth0 -w /shared/capture.pcap` puis ouverture du fichier sur votre poste, avec lequel
  le répertoire `/shared` est partagé (`chmod a+r` sur le fichier s'il n'y est pas lisible).

**Évaluation.** À chaque évaluation la configuration `tc` (et `nft`) de **`r1`, `r2` et
`serveur2`** est relue, telle qu'elle est à ce moment, et reproduite sur une copie cachée du
réseau où sont faites toutes les mesures (ping, iperf3) : vos propres tests ne perturbent donc
pas la notation, mais **la configuration doit être en place au moment de l'évaluation**. Une
évaluation dure une trentaine de secondes. L'auto-évaluation ne note pas les réponses à choix
des formulaires (listes déroulantes) : seule l'évaluation de l'enseignant les prend en compte.
""").format(dev_netem=dev_netem, dev_rev=dev_rev, dev_shape=dev_shape, dev_prio=dev_prio, pb=PORT_B)
            + instructor(tr("""
**Pour l'enseignant.** Le « WAN » est un pont transparent caché, `wan`, entre `r1` et
`serveur2` : un `netem delay {wan}ms` sur chacune de ses deux interfaces, soit **{wan} ms par
sens**, sans saut visible dans un `traceroute`. RTT attendus de `m1` vers `serveur2` : **{base} ms**
au départ (réponse de la partie 1), **{rtt} ms** avec le délai netem de la partie 2. Les autres
valeurs de l'instance sont dans le tableau ci-dessus.

Toute la maquette est doublée par des clones cachés (`m1_h`, `r1_h`, … : mêmes adresses, mêmes
interfaces). Chaque évaluation relit la configuration `tc` de `r1`, `r2` et `serveur2` et les
règles nftables de `r1`, les reconstruit sur les clones, puis mesure entre clones (`ping`,
`iperf3`) : 40 points (3 + 9 + 10 + 10 + 8). Un avertissement signale une construction `tc`
qui n'a pas pu être reproduite sur le miroir, ou un marquage fait avec `iptables`. Les cinq
réponses à choix (`diag_ss_rtt`, `netem_q_asym`, `shape_q_bufferbloat`, `prio_q_hook`,
`ingress_q_ifb`) ne comptent que dans l'évaluation de l'enseignant ; les trois questions à réponse
libre ne sont pas notées. L'export Kathara est désactivé : il révélerait le miroir et le délai
du WAN.

Chaque question se termine par sa solution pour ces valeurs ; l'état `final` (onglet *Appliquer
une configuration*) applique toute la solution et remplit les formulaires.
""").format(wan=d.wan_delay_ms, base=base_rtt_ms, rtt=base_rtt_ms + d.netem_delay_ms)),
        )

        # =====================================================================
        # Partie 1 — Diagnostic du lien
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Diagnostic du lien vers serveur2"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Diagnostic du lien vers serveur2"),
            hash="525fa95867937dd3",
            description=tr("""
1. Depuis `m1`, mesurez le RTT vers `serveur1` puis vers `serveur2` (`ping -c 20 -i 0.2`).
   Le lien `r1` ↔ `serveur2` traverse un « WAN » qui ajoute un délai inconnu : vous le
   retrouverez dans la différence entre les deux mesures.
2. Lancez `iperf3 -s` sur `serveur1`, puis `iperf3 -c serveur1 -t 10` sur `m1` : c'est la
   capacité brute d'un lien de la maquette (commutateurs VDE), à garder en tête pour la suite.
3. Lancez `iperf3 -s` sur `serveur2`, puis `iperf3 -c serveur2 -t 30` sur `m1`. Pendant le
   transfert, dans un second terminal de `m1`, observez `watch -n 0.5 "ss -ti dst serveur2"` :
   retrouvez le RTT estimé par TCP (`rtt:`), la fenêtre de congestion (`cwnd`) et les
   retransmissions.
4. Capturez ce transfert avec Wireshark (sur `m1`, ou `dumpcap -i eth0 -w /shared/capture.pcap`
   puis ouverture sur le poste) et tracez *Statistiques → Graphique des flux TCP → Temps
   d'aller-retour*.
""")
            + instructor(tr("""
**Solution.** Rien à configurer dans cette partie, seulement des mesures depuis `m1`.

- `ping -c 20 -i 0.2 serveur1` : un RTT de l'ordre de la milliseconde ou moins, aucun délai
  n'existant sur ce chemin. `ping -c 20 -i 0.2 serveur2` : environ **{base} ms**, soit {wan} ms
  ajoutés par le « WAN » dans chaque sens. Le premier écho vers `serveur2` dure à peu près le
  double : la résolution ARP traverse elle aussi le WAN.
- `iperf3 -c serveur1 -t 10` : environ 45 à 50 Mbit/s, la capacité des commutateurs VDE.
- `ss -ti dst serveur2` pendant le transfert : `rtt:<moyenne>/<variation>` en millisecondes,
  `cwnd:<segments>` et, dès qu'il y a eu des pertes, `retrans:<en cours>/<total>`.
- Graphique du RTT : capturer sur `m1`, l'émetteur des données, et sélectionner un segment du
  sens `m1` → `serveur2` avant d'ouvrir le graphique. Un fichier écrit par `dumpcap` dans `/shared`
  n'est lisible que par `root` : `chmod a+r /shared/capture.pcap` avant de l'ouvrir sur le poste.

Évaluation : cet énoncé ne porte aucun point ; les éléments de la partie 1 (`diag_rtt`,
`diag_ss_rtt`) notent le formulaire suivant.
""").format(base=base_rtt_ms, wan=d.wan_delay_ms)),
        )
        q0 = self.question_form(
            section=self.section(1),
            title=tr("RTT de base"),
            hash="e1f70ffb0564415f",
            description=tr("""
- RTT moyen mesuré par `ping` de `m1` vers `serveur2`, en ms : @@{rtt:[0-9]+([.,][0-9]+)?}@@
- Dans la sortie de `ss -ti`, le champ qui donne le RTT estimé par TCP et sa variation est :
  @@{ss_field:>cwnd|rtt|rto|bytes_acked}@@
""")
            + instructor(tr("""
**Solution.** RTT : **{base}** ms, soit 2 × {wan} ms, le délai du WAN dans chaque sens (le reste
du chemin n'ajoute presque rien). Champ **`rtt`** : `rtt:<moyenne>/<variation>`, en
millisecondes ; `rto` est la temporisation de retransmission que TCP en déduit, `cwnd` la
fenêtre de congestion, `bytes_acked` le nombre d'octets acquittés.

Évaluation : `diag_rtt` (2 points : réponse égale à {base} ms à 25 % + 2 ms près) et
`diag_ss_rtt` (1 point, évaluation de l'enseignant seulement : `rtt`).
""").format(base=base_rtt_ms, wan=d.wan_delay_ms)),
            cheat_answers={"final": {"rtt": str(base_rtt_ms), "ss_field": "rtt"}},
        )
        self.add_grade_element(
            title=no_tr("diag_rtt"), max_grade=2, grade_part=part1,
            grade=2 * int(_approx(_float(q0.get("rtt")), base_rtt_ms, rel=0.25, abs_margin=2)),
            description=tr("RTT mesuré de m1 vers serveur2 (délai du WAN)"),
        )
        self.add_grade_element(
            title=no_tr("diag_ss_rtt"), max_grade=1, grade_part=part1, scope=CHOICE_SCOPE,
            grade=int(_norm(q0.get("ss_field")) == "rtt"),
            description=tr("champ rtt de ss -ti"),
        )
        self.question_text(
            section=self.section(1),
            title=tr("Observations sur le graphique du RTT"),
            hash="9196eb6d697ce1b7",
            description=tr("Décrivez l'allure du graphique *Temps d'aller-retour* du transfert iperf3 "
                           "(valeur typique, variations) et comparez-la au `ping`.")
            + instructor(tr("""

**Solution.** Réponse libre, non notée. Attendu : le RTT vu par TCP ne descend pas sous celui du
`ping` au repos (environ {base} ms, le délai du WAN) et se tient nettement au-dessus pendant le
transfert : `iperf3` remplit les files d'attente du chemin, et chaque segment attend derrière
ceux qui le précèdent. La courbe est en dents de scie : elle suit la fenêtre de congestion, qui
grandit jusqu'à une perte puis se réduit. Le `ping` au repos ne mesure, lui, que le délai du
chemin vide.
""").format(base=base_rtt_ms)),
        )
        self.question_text(
            section=self.section(1),
            title=tr("Capacité brute d'un lien"),
            hash="b5daca9d2fd7fee2",
            description=tr("Débit obtenu par `iperf3` de `m1` vers `serveur1` sans aucune régulation (Mbit/s), "
                           "et ce que cela implique pour les débits à configurer dans ce TP.")
            + instructor(tr("""

**Solution.** Réponse libre, non notée. Attendu : environ **45 à 50 Mbit/s** (les liens sont des
commutateurs VDE en espace utilisateur ; la valeur dépend de la charge du poste). Conséquence :
une limitation ne se voit que si elle est nettement inférieure à cette capacité, d'où des débits
demandés tous inférieurs à 30 Mbit/s ; un débit configuré au-dessus ne limiterait rien.
""")),
        )

        # =====================================================================
        # Partie 2 — netem
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Émulation de latence et de pertes (netem)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("netem sur r1 vers serveur2"),
            hash="d5dfaf2122aa1000",
            description=tr("""
Sur `r1`, l'interface **`{dev}`** mène à `serveur2`. Toutes les mesures se font de `m1`
vers `serveur2` (`ping`, `iperf3 -c serveur2`).

1. Ajoutez un délai de **{delay} ms** : `tc qdisc add dev {dev} root netem delay {delay}ms`.
   Refaites la mesure du RTT par `ping` vers `serveur2` (et, pour comparer, vers `serveur1`).
2. Ajoutez une gigue de **{jitter} ms** : `tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms`.
   Refaites les mesures : observez `mdev` dans le résumé de `ping`.
3. Supprimez la configuration (`tc qdisc del dev {dev} root`) puis configurez **{loss} %** de
   pertes : `tc qdisc add dev {dev} root netem loss {loss}%`. Relancez `iperf3` : que
   constatez-vous ? Capturez le transfert et estimez la proportion de segments retransmis avec
   le filtre d'affichage `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
   tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
   tcp.analysis.lost_segment` puis *Statistiques → Conversations → TCP*.
4. Pertes dans le sens **retour** : sur **`serveur2`**, `tc qdisc add dev eth0 root netem loss {rloss}%`
   (les paquets de `serveur2` vers `m1`, donc les acquittements du transfert). Refaites le test
   `iperf3` de `m1` vers `serveur2` : que se passe-t-il ?
5. **Configuration finale à laisser en place** : sur `r1 {dev}`, délai **{delay} ms**, gigue
   **{jitter} ms** et pertes **{loss} %** ensemble
   (`tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%`) ; sur
   `serveur2 eth0`, pertes **{rloss} %**.
""").format(dev=dev_netem, delay=d.netem_delay_ms, jitter=d.netem_jitter_ms,
            loss=d.netem_loss_pct, rloss=d.reverse_loss_pct)
            + instructor(tr("""
**Solution.** Configuration finale, celle qu'applique l'état `final`. Sur `r1` :

```
tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%
```

Sur `serveur2` :

```
tc qdisc replace dev {rdev} root netem loss {rloss}%
```

- Étape 1 : le RTT vers `serveur2` passe de {base} à environ **{rtt} ms** ({base} + {delay}). Le
  délai ne retarde que les paquets qui sortent de `r1` par `{dev}`, donc l'aller seulement ; le
  RTT vers `serveur1` ne change pas.
- Étape 2 : la moyenne reste voisine de {rtt} ms, les RTT s'étalent de {low} à {high} ms et
  `mdev` monte à environ {mdev} ms (écart-type d'une loi uniforme sur ± {jitter} ms :
  {jitter} / √3).
- Étape 3 : le débit s'effondre et la proportion de segments retransmis est voisine de
  {loss} % (voir les deux questions suivantes).
- Étape 4 : ces pertes ne touchent que les acquittements du transfert ; le débit baisse peu.
- `tc qdisc add` échoue quand une qdisc racine est déjà en place : `replace`, ou `del` d'abord.

Évaluation : `netem_delai`, `netem_gigue`, `netem_pertes` (1 point chacun : la qdisc racine de
`r1` `{dev}` est un netem de délai {delay} ms et de gigue {jitter} ms à 2 ms près, de pertes
{loss} % à 0,6 point près), `netem_pertes_retour` (1 : netem de pertes {rloss} % à la racine de
`serveur2` `{rdev}`) et `netem_rtt_mesure` (2 : sur le miroir, 20 échos de `m1` vers `serveur2`,
au moins 8 réponses et un RTT médian de {rtt} ms à 25 % + 10 ms près).
""").format(dev=dev_netem, rdev=dev_rev, delay=d.netem_delay_ms, jitter=d.netem_jitter_ms,
            loss=d.netem_loss_pct, rloss=d.reverse_loss_pct, base=base_rtt_ms,
            rtt=base_rtt_ms + d.netem_delay_ms,
            low=base_rtt_ms + d.netem_delay_ms - d.netem_jitter_ms,
            high=base_rtt_ms + d.netem_delay_ms + d.netem_jitter_ms,
            mdev=round(d.netem_jitter_ms / 3 ** 0.5))),
        )
        q1 = self.question_form(
            section=self.section(1),
            title=tr("Mesures avec netem"),
            hash="46f9eb464e77841b",
            description=tr("""
- RTT moyen (ms) de `m1` vers `serveur2` après l'ajout du délai de {delay} ms (étape 1) :
  @@{{rtt_delay:[0-9]+([.,][0-9]+)?}}@@
- Proportion (%) de segments retransmis observée dans Wireshark avec {loss} % de pertes (étape 3) :
  @@{{retrans:[0-9]+([.,][0-9]+)?}}@@
- Avec les pertes dans le sens retour (étape 4), le débit du transfert de `m1` vers `serveur2` :
  @@{{asym:>devient nul|s'effondre autant qu'avec des pertes de données|baisse peu : les acquittements sont cumulatifs}}@@
""").format(delay=d.netem_delay_ms, loss=d.netem_loss_pct)
            + instructor(tr("""
**Solution.** RTT après l'ajout du délai : **{rtt}** ms ({base} + {delay}). Proportion de
segments retransmis : environ **{loss}** %, chaque segment perdu étant retransmis. Avec les
pertes dans le sens retour, le débit **baisse peu : les acquittements sont cumulatifs** —
l'acquittement suivant confirme aussi les octets de celui qui s'est perdu, sans retransmission
de données.

Évaluation : `netem_q_rtt` (1 point : {rtt} ms à 25 % + 5 ms près), `netem_q_retrans` (1 : une
valeur comprise entre la moitié et le double de {loss} %) et `netem_q_asym` (1, évaluation de
l'enseignant seulement).
""").format(rtt=base_rtt_ms + d.netem_delay_ms, base=base_rtt_ms, delay=d.netem_delay_ms,
            loss=d.netem_loss_pct)),
            cheat_answers={"final": {
                "rtt_delay": str(base_rtt_ms + d.netem_delay_ms),
                "retrans": str(d.netem_loss_pct),
                "asym": "baisse peu : les acquittements sont cumulatifs",
            }},
        )
        mathis = str(round(1.22 * 1448 * 8 / (base_rtt_ms / 1000) / (d.netem_loss_pct / 100) ** 0.5 / 1e6, 1))
        self.question_text(
            section=self.section(1),
            title=tr("Observations avec des pertes"),
            hash="b6545ec90580eedd",
            description=tr("Que constatez-vous sur le débit `iperf3` avec {loss} % de pertes ? Qu'indique `ss -ti` "
                           "(`cwnd`, `retrans`) ?").format(loss=d.netem_loss_pct)
            + instructor(_by_language(tr("""

**Solution.** Réponse libre, non notée. Attendu : le débit s'effondre, de 45 à 50 Mbit/s à
quelques Mbit/s au plus : TCP prend chaque perte pour un signe de congestion et réduit sa
fenêtre. Ordre de grandeur donné par la formule de Mathis, débit ≈ 1,22 × MSS / (RTT × √p) :
avec un RTT de {base} ms et p = {loss} %, au plus {mathis} Mbit/s environ, et souvent
nettement moins car à ce taux de pertes les expirations de temporisation s'ajoutent aux
retransmissions rapides. `ss -ti` montre un `cwnd` qui reste à quelques segments et un champ
`retrans:<en cours>/<total>` dont le total augmente sans cesse.
"""), base=base_rtt_ms, loss=d.netem_loss_pct,
                mathis={'fr': mathis.replace('.', ','), 'en': mathis})),
        )
        netem = tc.root_qdisc(m_r1, dev_netem)
        netem_ok = netem is not None and netem['kind'] == 'netem'
        reverse = tc.root_qdisc(m_s2, dev_rev)
        self.add_grade_element(
            title=no_tr("netem_delai"), max_grade=1, grade_part=part2,
            grade=int(netem_ok and _close_ms(netem.get('delay'), d.netem_delay_ms)),
            description=tr("netem sur r1 {dev} : délai de {delay} ms").format(dev=dev_netem, delay=d.netem_delay_ms),
        )
        self.add_grade_element(
            title=no_tr("netem_gigue"), max_grade=1, grade_part=part2,
            grade=int(netem_ok and _close_ms(netem.get('jitter'), d.netem_jitter_ms)),
            description=tr("netem sur r1 {dev} : gigue de {jitter} ms").format(dev=dev_netem, jitter=d.netem_jitter_ms),
        )
        self.add_grade_element(
            title=no_tr("netem_pertes"), max_grade=1, grade_part=part2,
            grade=int(netem_ok and netem.get('loss') is not None and abs(netem['loss'] - d.netem_loss_pct) < 0.6),
            description=tr("netem sur r1 {dev} : pertes de {loss} %").format(dev=dev_netem, loss=d.netem_loss_pct),
        )
        self.add_grade_element(
            title=no_tr("netem_pertes_retour"), max_grade=1, grade_part=part2,
            grade=int(reverse is not None and reverse['kind'] == 'netem' and reverse.get('loss') is not None
                      and abs(reverse['loss'] - d.reverse_loss_pct) < 0.6),
            description=tr("netem sur serveur2 eth0 : pertes de {loss} % vers r1").format(loss=d.reverse_loss_pct),
        )
        expected_rtt = base_rtt_ms + d.netem_delay_ms
        self.add_grade_element(
            title=no_tr("netem_rtt_mesure"), max_grade=2, grade_part=part2,
            grade=2 * int((ping_s2.get('received') or 0) >= 8
                          and _approx(rtt_s2, expected_rtt, rel=0.25, abs_margin=10)),
            description=tr("RTT mesuré sur le miroir de m1 vers serveur2 ≈ {rtt} ms").format(rtt=expected_rtt),
        )
        self.add_grade_element(
            title=no_tr("netem_q_rtt"), max_grade=1, grade_part=part2,
            grade=int(_approx(_float(q1.get("rtt_delay")), expected_rtt, rel=0.25, abs_margin=5)),
            description=tr("RTT déclaré après ajout du délai"),
        )
        retrans = _float(q1.get("retrans"))
        self.add_grade_element(
            title=no_tr("netem_q_retrans"), max_grade=1, grade_part=part2,
            grade=int(retrans is not None and d.netem_loss_pct / 2 <= retrans <= 2 * d.netem_loss_pct),
            description=tr("proportion de retransmissions cohérente avec les pertes"),
        )
        self.add_grade_element(
            title=no_tr("netem_q_asym"), max_grade=1, grade_part=part2, scope=CHOICE_SCOPE,
            grade=int(_norm(q1.get("asym")).startswith("baisse peu")),
            description=tr("effet des pertes dans le sens retour"),
        )

        # =====================================================================
        # Partie 3 — shaping vers m2
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Régulation de débit vers m2 (tbf, htb, fq_codel)"))
        R_hi, R_lo = int(R * 0.8), int(R * 0.2)
        self.question_dummy(
            section=self.section(0),
            title=tr("Shaping sur r2 vers m2"),
            hash="d87e66eea7d083df",
            description=tr("""
Sur `r2`, l'interface **`{dev}`** mène à `m2`. Lancez sur `m2` deux serveurs :
`iperf3 -s -p {pa}` et `iperf3 -s -p {pb}` ; les clients tournent sur `m1`.

1. **tbf** : limitez le débit vers `m2` à **{tbf} Mbit/s** avec un seau de {burst} et une
   latence de {latency} : `tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}`.
   Mesurez le débit avec `iperf3 -c m2 -p {pa} -t 15` et, **pendant** ce transfert, le RTT de
   `m1` vers `m2` avec `ping` : c'est le *bufferbloat*.
2. Supprimez le `tbf`. Avec **htb**, limitez le trafic total vers `m2` à **{R} Mbit/s** en
   garantissant **{hi} Mbit/s** au port TCP **{pa}** (classe `1:10`) et **{lo} Mbit/s** au
   reste (classe `1:20`, classe par défaut), chaque classe pouvant emprunter jusqu'à {R} Mbit/s
   (`ceil`). Le filtre `u32` dirige le port {pa} vers `1:10`.
3. Remplacez la file `pfifo` de chaque classe par **`fq_codel`**
   (`tc qdisc add dev {dev} parent 1:10 fq_codel`, idem `1:20`).
4. Testez avec deux clients simultanés sur `m1` (`iperf3 -c m2 -p {pa} -t 15` et
   `iperf3 -c m2 -p {pb} -t 15`) et observez `watch -n 1 tc -s class show dev {dev}` sur `r2`.
   Refaites un `ping` de `m1` vers `m2` pendant les transferts et comparez avec l'étape 1.
""").format(dev=dev_shape, pa=PORT_A, pb=PORT_B, tbf=d.tbf_rate_mbit, burst=TBF_BURST, latency=TBF_LATENCY,
            R=R, hi=R_hi, lo=R_lo)
            + instructor(tr("""
**Solution.** Étape 1, sur `r2` :

```
tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}
```

`iperf3` mesure environ {tbf} Mbit/s et le RTT de `m1` vers `m2` monte à environ 400 ms pendant
le transfert : la file du `tbf` (`latency {latency}`) reste pleine et chaque paquet, écho
compris, y attend son tour.

Étapes 2 et 3, sur `r2` (ce qu'applique l'état `final`) :

```
tc qdisc del dev {dev} root
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:1 htb rate {R}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:10 htb rate {hi}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:20 htb rate {lo}mbit ceil {R}mbit
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} protocol ip parent 1: prio 1 u32 match ip dport {pa} 0xffff flowid 1:10
```

- Étape 4 : avec les deux clients, le port {pa} obtient environ {hi} Mbit/s et le port {pb}
  environ {lo} Mbit/s, {R} au total ; un client seul emprunte jusqu'à {R} Mbit/s (`ceil`). Dans
  `tc -s class show dev {dev}`, les compteurs de `1:10` et de `1:20` avancent chacun avec son
  flux. Le RTT du `ping` reste faible, loin des 400 ms de l'étape 1 : `fq_codel` ne fait pas
  attendre les échos derrière les transferts.
- La classe parente `1:1` porte le débit total : sans elle, `1:10` et `1:20` ne pourraient
  rien s'emprunter.
- `default 20` est lu en hexadécimal, comme les identifiants de classes : il désigne bien `1:20`.
- Le « reste » doit passer par la classe par défaut, et non par un second filtre sur le port
  {pb} : l'évaluation mesure le flux non classé sur un autre port ({gp}).

Évaluation : `shape_htb_racine` (1 point : htb à la racine de `r2` `{dev}`, avec une classe
feuille par défaut), `shape_classe_port` (1 : la classe visée par le filtre du port {pa} a
`rate {hi}mbit` et `ceil {R}mbit`, à 3 % près), `shape_classe_defaut` (1 : la classe par défaut,
distincte de la précédente, a `rate {lo}mbit` et `ceil {R}mbit`), `shape_fq_codel` (1 : une
`fq_codel` sous chaque classe feuille), `shape_filtre_u32` (1 : un filtre sur le port
destination {pa} vise une classe feuille autre que la classe par défaut), puis, sur le miroir,
deux flux simultanés de `m1` vers `m2` (ports {pa} et {gp}) et un `ping` : `shape_mesure_total`
(1 : total entre 60 % et 110 % de {R} Mbit/s), `shape_mesure_partage` (1 : le flux du port {pa}
atteint 60 % de {R} Mbit/s, l'autre ne dépasse pas 30 %) et `shape_mesure_latence` (1 : avec le
htb à la racine, RTT moyen sous charge inférieur à 50 ms).
""").format(dev=dev_shape, pa=PORT_A, pb=PORT_B, gp=GRADE_PORT_DEFAULT, tbf=d.tbf_rate_mbit,
            burst=TBF_BURST, latency=TBF_LATENCY, R=R, hi=R_hi, lo=R_lo)),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Mesures de shaping"),
            hash="21f1c62021dced0b",
            description=tr("""
- Débit (Mbit/s) mesuré par `iperf3` avec le `tbf` à {tbf} Mbit/s (étape 1) : @@{{tbf_mbps:[0-9]+([.,][0-9]+)?}}@@
- RTT de `m1` vers `m2` pendant le transfert avec le `tbf` (étape 1) :
  @@{{bloat:>environ 1 ms|environ 40 ms|environ 400 ms|plus de 4 s}}@@
""").format(tbf=d.tbf_rate_mbit)
            + instructor(tr("""
**Solution.** Débit avec le `tbf` : environ **{tbf}** Mbit/s, le `rate` configuré. RTT pendant
le transfert : **environ 400 ms** — le transfert maintient la file du `tbf` pleine, et tout
paquet qui la traverse y attend jusqu'à la durée fixée par `latency {latency}` : c'est le
*bufferbloat*.

Évaluation : `shape_q_tbf` (1 point : {tbf} Mbit/s à 30 % près) et `shape_q_bufferbloat` (1,
évaluation de l'enseignant seulement).
""").format(tbf=d.tbf_rate_mbit, latency=TBF_LATENCY)),
            cheat_answers={"final": {"tbf_mbps": str(d.tbf_rate_mbit), "bloat": "environ 400 ms"}},
        )
        shape_root = tc.root_qdisc(m_r2, dev_shape)
        shape_htb = shape_root is not None and shape_root['kind'] == 'htb'
        shape_leaves = tc.leaf_classes(m_r2, dev_shape)
        default_minor = shape_root.get('default') if shape_htb else None
        shape_default = next((c for c in shape_leaves if tc.classid_minor(c['classid']) == default_minor), None)
        shape_port_filters = [f for f in tc.filters_of(m_r2, dev_shape, ingress=False)
                              if tc.u32_match_dport(f) == PORT_A and tc.filter_target(f)]
        shape_hi_class = next((c for c in shape_leaves
                               if shape_port_filters and c['classid'] == tc.filter_target(shape_port_filters[0])), None)
        self.add_grade_element(
            title=no_tr("shape_htb_racine"), max_grade=1, grade_part=part3,
            grade=int(shape_htb and shape_default is not None),
            description=tr("htb à la racine de r2 {dev} avec une classe par défaut").format(dev=dev_shape),
        )
        self.add_grade_element(
            title=no_tr("shape_classe_port"), max_grade=1, grade_part=part3,
            grade=int(shape_hi_class is not None and tc.rate_close(shape_hi_class.get('rate'), mbit(R_hi))
                      and tc.rate_close(shape_hi_class.get('ceil'), mbit(R))),
            description=tr("classe du port {pa} : rate {hi} Mbit/s, ceil {R} Mbit/s").format(pa=PORT_A, hi=R_hi, R=R),
        )
        self.add_grade_element(
            title=no_tr("shape_classe_defaut"), max_grade=1, grade_part=part3,
            grade=int(shape_default is not None and shape_default is not shape_hi_class
                      and tc.rate_close(shape_default.get('rate'), mbit(R_lo))
                      and tc.rate_close(shape_default.get('ceil'), mbit(R))),
            description=tr("classe par défaut : rate {lo} Mbit/s, ceil {R} Mbit/s").format(lo=R_lo, R=R),
        )
        self.add_grade_element(
            title=no_tr("shape_fq_codel"), max_grade=1, grade_part=part3,
            grade=int(bool(shape_leaves) and all(
                (tc.leaf_qdisc(m_r2, dev_shape, c['classid']) or {}).get('kind') == 'fq_codel' for c in shape_leaves)),
            description=tr("fq_codel sous chaque classe feuille"),
        )
        self.add_grade_element(
            title=no_tr("shape_filtre_u32"), max_grade=1, grade_part=part3,
            grade=int(shape_hi_class is not None and shape_hi_class is not shape_default),
            description=tr("filtre u32 : port {pa} vers la classe garantie").format(pa=PORT_A),
        )
        total = mbps(shape_hi) + mbps(shape_lo)
        self.add_grade_element(
            title=no_tr("shape_mesure_total"), max_grade=1, grade_part=part3,
            grade=int(bool(shape_hi.get('bps')) and bool(shape_lo.get('bps')) and 0.6 * R <= total <= 1.1 * R),
            description=tr("miroir : débit total vers m2 limité à {R} Mbit/s").format(R=R),
        )
        self.add_grade_element(
            title=no_tr("shape_mesure_partage"), max_grade=1, grade_part=part3,
            grade=int(mbps(shape_hi) >= 0.6 * R and 0 < mbps(shape_lo) <= 0.3 * R),
            description=tr("miroir : port {pa} ≈ {hi} Mbit/s, autre flux ≈ {lo} Mbit/s").format(pa=PORT_A, hi=R_hi, lo=R_lo),
        )
        self.add_grade_element(
            title=no_tr("shape_mesure_latence"), max_grade=1, grade_part=part3,
            # with the htb in place: on an unshaped link the RTT under load depends on the speed of
            # the link alone (low on a fast one, whatever the student did)
            grade=int(shape_htb and bool(shape_hi.get('bps')) and (ping_shape.get('received') or 0) >= 4
                      and ping_shape.get('avg') is not None and ping_shape['avg'] < 50),
            description=tr("miroir : RTT vers m2 sous charge < 50 ms (fq_codel)"),
        )
        self.add_grade_element(
            title=no_tr("shape_q_tbf"), max_grade=1, grade_part=part3,
            grade=int(_approx(_float(q2.get("tbf_mbps")), d.tbf_rate_mbit, rel=0.3)),
            description=tr("débit déclaré avec le tbf"),
        )
        self.add_grade_element(
            title=no_tr("shape_q_bufferbloat"), max_grade=1, grade_part=part3, scope=CHOICE_SCOPE,
            grade=int(_norm(q2.get("bloat")) == "environ 400 ms"),
            description=tr("RTT sous charge avec le tbf (bufferbloat)"),
        )

        # =====================================================================
        # Partie 4 — priorité par marquage
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Priorité par marquage nftables (fw, htb)"))
        T_hi, T_lo = int(T * 0.8), int(T * 0.2)
        self.question_dummy(
            section=self.section(0),
            title=tr("Marquage et priorité sur r1 vers serveur1"),
            hash="dd9063abb982ce91",
            description=tr("""
Sur `r1`, l'interface **`{dev}`** mène à `serveur1`. La bande passante totale vers `serveur1`
sera limitée à **{T} Mbit/s** ; le trafic provenant du réseau de `m1` (`{netA}`) est
prioritaire et garanti **{hi} Mbit/s**, le reste (par exemple `m2`) **{lo} Mbit/s**.

1. Avec **nftables**, marquez les paquets TCP venant de `{netA}` avec la marque **{mark}**
   (table `mangle`, chaîne de type `filter` sur le hook `prerouting`, règle
   `ip saddr {netA} meta l4proto tcp meta mark set {mark}`). Vérifiez avec `nft list ruleset`.
2. Avec **htb** sur `{dev}` : classe `1:10` (`rate {hi}mbit ceil {T}mbit prio 0`) pour le trafic
   marqué, classe `1:20` (`rate {lo}mbit ceil {T}mbit prio 1`) par défaut, une `fq_codel` sous
   chaque classe, et le filtre `fw` qui envoie la marque {mark} dans `1:10` :
   `tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10`.
3. Testez avec deux serveurs `iperf3` sur `serveur1` (ports {pa} et {pb}) et deux clients
   simultanés, l'un sur `m1`, l'autre sur `m2`. Observez `tc -s class show dev {dev}` sur `r1`.
""").format(dev=dev_prio, T=T, hi=T_hi, lo=T_lo, netA=d.nets.netA, mark=M, pa=PORT_A, pb=PORT_B)
            + instructor(tr("""
**Solution.** Sur `r1` (ce qu'applique l'état `final`, qui supprime d'abord la table `mangle` et
la qdisc racine déjà présentes pour pouvoir être rejoué) :

```
nft add table ip mangle
nft add chain ip mangle prerouting '{{ type filter hook prerouting priority mangle; }}'
nft add rule ip mangle prerouting ip saddr {netA} meta l4proto tcp meta mark set {mark}
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:10 htb rate {hi}mbit ceil {T}mbit prio 0
tc class add dev {dev} parent 1: classid 1:20 htb rate {lo}mbit ceil {T}mbit prio 1
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10
```

- La marque s'affiche en hexadécimal : `meta mark set 0x{mark:08x}` dans `nft list ruleset`,
  `handle 0x{mark:x} classid 1:10` dans `tc filter show dev {dev}`.
- Étape 3 : le flux de `m1`, marqué, obtient environ {hi} Mbit/s et celui de `m2` environ
  {lo} Mbit/s ; `tc -s class show dev {dev}` montre le premier dans `1:10`, le second dans
  `1:20`. Les deux classes sont attachées directement à la racine : elles ne s'empruntent rien
  et chacune reste limitée à son `rate`, d'où un total d'au plus {T} Mbit/s (un flux de `m1`
  seul plafonne à {hi} Mbit/s, malgré le `ceil`).
- La marque doit être posée avant la file de sortie de `{dev}`, sur un hook que traverse le
  trafic routé : une chaîne `output` ne marque que les paquets émis par `r1` lui-même.
- Un marquage fait avec `iptables` n'est pas reproduit sur le miroir : l'évaluation affiche un
  avertissement, `prio_nft_marque` et `prio_mesure_marque` valent 0.
- Le `htb` (sortie de `{dev}`) et la qdisc `ingress` de la partie 5 (entrée de `{dev}`)
  cohabitent sur la même interface.

Évaluation : `prio_nft_marque` (2 points : une règle nftables pose la marque {mark} sur le
trafic de source `{netA}`, TCP ou tout protocole, dans une chaîne `prerouting`, `forward` ou
`postrouting` ; 1 point seulement sur un autre hook), `prio_htb_classes` (1 : la classe visée
par le filtre `fw` et la classe par défaut, distinctes, ont `rate {hi}mbit` et `rate {lo}mbit`,
`ceil {T}mbit`, à 3 % près), `prio_htb_priorites` (1 : `prio` de la classe du trafic marqué
inférieur à celui de la classe par défaut), `prio_fq_codel` (1 : une `fq_codel` sous chaque
classe feuille), `prio_filtre_fw` (1 : un filtre `fw` de `handle {mark}` vise une classe
feuille), puis, sur le miroir, `m1` et `m2` émettant ensemble vers `serveur1` :
`prio_mesure_marque` (2 : le flux de `m1` obtient entre 60 % et 110 % de {T} Mbit/s, le filtre
`fw` étant en place : sans aucune configuration, les deux flux se partagent le lien et celui de
`m1` tomberait par hasard dans cette fourchette) et
`prio_mesure_defaut` (1 : le flux de `m2` passe, sans dépasser 35 % de {T} Mbit/s, et le total
reste sous 115 %).
""").format(dev=dev_prio, T=T, hi=T_hi, lo=T_lo, netA=d.nets.netA, mark=M)),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Marquage"),
            hash="872c7b56dd29e001",
            description=tr("""
- Pour marquer les paquets **routés** par `r1`, la chaîne nftables doit être accrochée au hook :
  @@{hook:>output|input|prerouting ou forward|postrouting uniquement}@@
""")
            + instructor(tr("""
**Solution.** **prerouting ou forward** : ce sont les hooks que traverse un paquet routé avant
d'atteindre la file de sortie. `input` ne voit que les paquets destinés au routeur et `output`
que ceux qu'il émet lui-même. `postrouting` voit aussi le trafic routé, et l'évaluation de la
configuration l'accepte, mais il n'est pas le seul hook possible : « postrouting uniquement »
est faux.

Évaluation : `prio_q_hook` (1 point, évaluation de l'enseignant seulement).
""")),
            cheat_answers={"final": {"hook": "prerouting ou forward"}},
        )
        good_rules = [rule for rule in nft_rules
                      if rule['mark'] == M and tc.addresses_cover(rule['saddr'], d.nets.netA)
                      and rule['l4proto'] in (None, 'tcp')]
        hooked_rules = [rule for rule in good_rules if rule['hook'] in ('prerouting', 'forward', 'postrouting')]
        self.add_grade_element(
            title=no_tr("prio_nft_marque"), max_grade=2, grade_part=part4,
            grade=2 * int(bool(hooked_rules)) if hooked_rules else int(bool(good_rules)),
            description=tr("règle nftables : marque {mark} sur le trafic TCP de {netA} (hook du trafic routé)")
            .format(mark=M, netA=d.nets.netA),
        )
        prio_root = tc.root_qdisc(m_r1, dev_prio)
        prio_htb = prio_root is not None and prio_root['kind'] == 'htb'
        prio_leaves = tc.leaf_classes(m_r1, dev_prio)
        prio_default = next((c for c in prio_leaves
                             if prio_htb and tc.classid_minor(c['classid']) == prio_root.get('default')), None)
        fw_filters = [f for f in tc.filters_of(m_r1, dev_prio, kind='fw', ingress=False)
                      if tc.fw_mark(f) == M and tc.filter_target(f)]
        prio_hi_class = next((c for c in prio_leaves
                              if fw_filters and c['classid'] == tc.filter_target(fw_filters[0])), None)
        self.add_grade_element(
            title=no_tr("prio_htb_classes"), max_grade=1, grade_part=part4,
            grade=int(prio_hi_class is not None and prio_default is not None and prio_hi_class is not prio_default
                      and tc.rate_close(prio_hi_class.get('rate'), mbit(T_hi)) and tc.rate_close(prio_hi_class.get('ceil'), mbit(T))
                      and tc.rate_close(prio_default.get('rate'), mbit(T_lo)) and tc.rate_close(prio_default.get('ceil'), mbit(T))),
            description=tr("htb sur r1 {dev} : classes {hi} / {lo} Mbit/s, ceil {T} Mbit/s").format(dev=dev_prio, hi=T_hi, lo=T_lo, T=T),
        )
        self.add_grade_element(
            title=no_tr("prio_htb_priorites"), max_grade=1, grade_part=part4,
            grade=int(prio_hi_class is not None and prio_default is not None
                      and prio_hi_class.get('prio', 0) < prio_default.get('prio', 0)),
            description=tr("la classe du trafic marqué est plus prioritaire (prio) que la classe par défaut"),
        )
        self.add_grade_element(
            title=no_tr("prio_fq_codel"), max_grade=1, grade_part=part4,
            grade=int(bool(prio_leaves) and all(
                (tc.leaf_qdisc(m_r1, dev_prio, c['classid']) or {}).get('kind') == 'fq_codel' for c in prio_leaves)),
            description=tr("fq_codel sous chaque classe feuille"),
        )
        self.add_grade_element(
            title=no_tr("prio_filtre_fw"), max_grade=1, grade_part=part4,
            grade=int(prio_hi_class is not None),
            description=tr("filtre fw : marque {mark} vers la classe prioritaire").format(mark=M),
        )
        self.add_grade_element(
            title=no_tr("prio_mesure_marque"), max_grade=2, grade_part=part4,
            # without any configuration the two flows share the link (about 24 Mbit/s each, seen
            # live): the rate alone would fall in the window, so the fw filter must be there
            grade=2 * int(prio_hi_class is not None and mbps(prio_hi) >= 0.6 * T and mbps(prio_hi) <= 1.1 * T),
            description=tr("miroir : le flux de m1 (marqué) obtient ≈ {hi} Mbit/s").format(hi=T_hi),
        )
        self.add_grade_element(
            title=no_tr("prio_mesure_defaut"), max_grade=1, grade_part=part4,
            grade=int(bool(prio_lo.get('bps')) and mbps(prio_lo) <= 0.35 * T and mbps(prio_hi) + mbps(prio_lo) <= 1.15 * T),
            description=tr("miroir : le flux de m2 est limité ≈ {lo} Mbit/s, total ≤ {T} Mbit/s").format(lo=T_lo, T=T),
        )
        self.add_grade_element(
            title=no_tr("prio_q_hook"), max_grade=1, grade_part=part4, scope=CHOICE_SCOPE,
            grade=int(_norm(q3.get("hook")) == "prerouting ou forward"),
            description=tr("hook nftables du trafic routé"),
        )

        # =====================================================================
        # Partie 5 — ingress
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Régulation du trafic entrant (ifb, cake)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Ingress sur r1 depuis serveur1"),
            hash="26a28cc6d177baed",
            description=tr("""
Le trafic **reçu** par `r1` sur **`{dev}`** (envoyé par `serveur1`) doit être limité à
**{C} Mbit/s**. Une qdisc ne régule qu'en sortie : redirigez le trafic entrant de `{dev}` vers
une interface **ifb** et régulez la sortie de celle-ci avec **cake** :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth {C}mbit
```

Testez depuis `m1` en sens *descendant* : `iperf3 -c serveur1 -R -t 15` (le serveur envoie).
Observez `tc -s qdisc show dev ifb0` sur `r1`.
""").format(dev=dev_prio, C=C)
            + instructor(tr("""
**Solution.** Sur `r1` : les commandes de l'énoncé. L'état `final` applique les mêmes, en
supprimant d'abord la qdisc `ingress` déjà présente et en posant `cake` avec `replace`, pour
pouvoir être rejoué :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc replace dev ifb0 root cake bandwidth {C}mbit
```

- `iperf3 -c serveur1 -R -t 15` depuis `m1` : environ **{C} Mbit/s** au lieu de 45 à 50, et
  les compteurs de `tc -s qdisc show dev ifb0` avancent pendant le transfert. Sans `-R`, les
  données vont de `m1` vers `serveur1` : c'est le `htb` de la partie 4 qui agit, pas `cake`.
- `match u32 0 0` est vrai pour tout paquet : tout le trafic IPv4 reçu sur `{dev}` est redirigé.
- `ifb0` doit être active (`ip link set ifb0 up`) : un paquet redirigé vers une interface
  arrêtée est jeté, et plus rien n'arrive de `serveur1`.
- La qdisc `ingress` et le `htb` racine de la partie 4 cohabitent sur `{dev}` :
  `tc qdisc del dev {dev} root` ne retire que le `htb`, `tc qdisc del dev {dev} ingress` que la
  redirection.

Évaluation : `ingress_ifb` (1 point : une interface ifb existe et est active sur `r1`),
`ingress_qdisc` (1 : qdisc `ingress` ou `clsact` sur `{dev}`), `ingress_redirect` (1 : un filtre
d'entrée redirige, par `mirred`, vers une interface ifb), `ingress_cake` (1 : `cake` à la racine
de cette interface), `ingress_cake_debit` (1 : `bandwidth {C}mbit` à 3 % près) et
`ingress_mesure` (2 : sur le miroir, un `iperf3 -R` de `m1` vers `serveur1` donne entre 70 % et
110 % de {C} Mbit/s).
""").format(dev=dev_prio, C=C)),
        )
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Pourquoi ifb ?"),
            hash="d41157f2cd055874",
            description=tr("""
- Pourquoi faut-il passer par une interface ifb pour réguler le trafic entrant ?
  @@{ifb:>ifb accélère le traitement des paquets|en entrée le noyau ne peut que jeter (policing) : les files d'attente n'existent qu'en sortie|le noyau interdit tc sur une interface physique|cake exige une interface virtuelle}@@
""")
            + instructor(tr("""
**Solution.** « en entrée le noyau ne peut que jeter (policing) : les files d'attente
n'existent qu'en sortie ». Rediriger le trafic reçu vers `ifb0` le fait passer par la **sortie**
d'une interface, où une qdisc (`cake`) peut le retarder et le lisser. Les autres réponses sont
fausses : `tc` s'emploie sur une interface physique, `cake` n'exige pas d'interface virtuelle
et ifb n'accélère rien.

Évaluation : `ingress_q_ifb` (1 point, évaluation de l'enseignant seulement).
""")),
            cheat_answers={"final": {"ifb": "en entrée le noyau ne peut que jeter (policing) : les files d'attente n'existent qu'en sortie"}},
        )
        ifb_links = {link['name']: link for link in mirror[r1].ifb_links}
        ingress_hooks = tc.qdiscs_of(m_r1, dev_prio, parent='ingress')
        redirects = [dev for dev in tc.ingress_redirect_devices(m_r1, dev_prio) if dev in ifb_links]
        cake = tc.root_qdisc(m_r1, redirects[0]) if redirects else None
        self.add_grade_element(
            title=no_tr("ingress_ifb"), max_grade=1, grade_part=part5,
            grade=int(any(link['up'] for link in ifb_links.values())),
            description=tr("une interface ifb existe et est active sur r1"),
        )
        self.add_grade_element(
            title=no_tr("ingress_qdisc"), max_grade=1, grade_part=part5,
            grade=int(bool(ingress_hooks)),
            description=tr("qdisc ingress (ou clsact) sur r1 {dev}").format(dev=dev_prio),
        )
        self.add_grade_element(
            title=no_tr("ingress_redirect"), max_grade=1, grade_part=part5,
            grade=int(bool(redirects)),
            description=tr("filtre ingress : redirection (mirred) vers l'interface ifb"),
        )
        self.add_grade_element(
            title=no_tr("ingress_cake"), max_grade=1, grade_part=part5,
            grade=int(cake is not None and cake['kind'] == 'cake'),
            description=tr("cake à la racine de l'interface ifb"),
        )
        self.add_grade_element(
            title=no_tr("ingress_cake_debit"), max_grade=1, grade_part=part5,
            grade=int(cake is not None and cake['kind'] == 'cake' and tc.rate_close(cake.get('bandwidth'), mbit(C))),
            description=tr("cake : bandwidth {C} Mbit/s").format(C=C),
        )
        self.add_grade_element(
            title=no_tr("ingress_mesure"), max_grade=2, grade_part=part5,
            grade=2 * int(0.7 * C <= mbps(download) <= 1.1 * C),
            description=tr("miroir : débit descendant depuis serveur1 ≈ {C} Mbit/s").format(C=C),
        )
        self.add_grade_element(
            title=no_tr("ingress_q_ifb"), max_grade=1, grade_part=part5, scope=CHOICE_SCOPE,
            grade=int(_norm(q4.get("ifb")).startswith("en entrée le noyau ne peut que jeter")),
            description=tr("rôle de l'interface ifb"),
        )
_TRANSLATIONS = {'en': {
    "tc : contrôle de trafic (netem, tbf, htb, cake)": "tc: traffic control (netem, tbf, htb, cake)",
    """
**Sommaire**
""": """
**Contents**
""",
    "Le contrôle de trafic : qdisc, classes et filtres": "Traffic control: qdiscs, classes and filters",
    """
Le **contrôle de trafic** du noyau Linux se règle avec la commande `tc` (paquet `iproute2`). Il
permet d'émuler un réseau dégradé (**netem**), de limiter un débit (**tbf**), de partager la
bande passante entre des classes (**htb**), d'utiliser des files d'attente modernes
(**fq_codel**, **cake**), de classer les paquets (filtres **u32**, **fw**, marquage
**nftables**) et de réguler le trafic *entrant* (**ifb**).

Chaque interface réseau possède en sortie (*egress*) une **discipline de file d'attente**
(*queueing discipline*, **qdisc**) qui décide dans quel ordre, et à quel rythme, les paquets
sont émis. Par défaut : `noqueue` (interfaces virtuelles) ou `pfifo_fast` / `fq_codel`.

- Les qdisc **sans classes** (*classless*) traitent tout le trafic de la même façon : `pfifo`,
  `netem`, `tbf`, `sfq`, `fq_codel`, `cake`.
- Les qdisc **à classes** (*classful*) ont des **classes** (`htb`, `prio`, …) : un **filtre**
  (`u32`, `fw`, `flower`) range chaque paquet dans une classe, et chaque classe a sa propre
  qdisc feuille (par défaut `pfifo`).

### @@sec:commands@@ Identifiants et commandes

Les objets sont désignés par des identifiants `majeur:mineur` **en hexadécimal** : la qdisc
racine `1:` (ou `1:0`), ses classes `1:1`, `1:10`, `1:20`. `root` désigne la racine,
`parent 1:10` l'attache sous la classe `1:10`. Les commandes :

```
tc qdisc  add | replace | change | del  dev eth1 root ...
tc class  add | change | del            dev eth1 parent 1: classid 1:10 htb ...
tc filter add | del                     dev eth1 parent 1: protocol ip prio 1 u32 ...
tc qdisc show dev eth1          tc class show dev eth1          tc filter show dev eth1
tc -s qdisc show dev eth1       tc -s class show dev eth1       # avec les compteurs
tc qdisc del dev eth1 root      # tout supprimer sur eth1
```

`tc qdisc add` échoue quand une qdisc est déjà configurée à cet endroit : `replace` la remplace
(ou la crée), `del` la supprime. La configuration vit dans le noyau : rien n'en est conservé au
redémarrage de la machine.

`tc -s class show` affiche par classe les octets et paquets envoyés, les rejets (`dropped`)
et les dépassements (`overlimits`) : indispensable pour vérifier qu'un filtre dirige bien le
trafic vers la classe prévue (`watch -n 1 tc -s class show dev eth1`).
""": """
The Linux kernel's **traffic control** is configured with the `tc` command (package `iproute2`). It
can emulate a degraded network (**netem**), limit a rate (**tbf**), share the bandwidth between
classes (**htb**), use modern queues (**fq_codel**, **cake**), classify packets (**u32** and
**fw** filters, **nftables** marking) and regulate *incoming* traffic (**ifb**).

On egress, every network interface has a **queueing discipline** (**qdisc**) that decides in
which order, and at what pace, the packets are sent. By default: `noqueue` (virtual interfaces)
or `pfifo_fast` / `fq_codel`.

- **Classless** qdiscs treat all the traffic the same way: `pfifo`, `netem`, `tbf`, `sfq`,
  `fq_codel`, `cake`.
- **Classful** qdiscs have **classes** (`htb`, `prio`, …): a **filter** (`u32`, `fw`, `flower`)
  puts each packet into a class, and each class has its own leaf qdisc (`pfifo` by default).

### @@sec:commands@@ Identifiers and commands

Objects are named by `major:minor` identifiers **in hexadecimal**: the root qdisc `1:` (or
`1:0`), its classes `1:1`, `1:10`, `1:20`. `root` designates the root, `parent 1:10` attaches
the object under class `1:10`. The commands:

```
tc qdisc  add | replace | change | del  dev eth1 root ...
tc class  add | change | del            dev eth1 parent 1: classid 1:10 htb ...
tc filter add | del                     dev eth1 parent 1: protocol ip prio 1 u32 ...
tc qdisc show dev eth1          tc class show dev eth1          tc filter show dev eth1
tc -s qdisc show dev eth1       tc -s class show dev eth1       # with the counters
tc qdisc del dev eth1 root      # delete everything on eth1
```

`tc qdisc add` fails when a qdisc is already configured at that place: `replace` replaces it
(or creates it), `del` deletes it. The configuration lives in the kernel: nothing of it is kept
when the machine restarts.

`tc -s class show` displays, per class, the bytes and packets sent, the drops (`dropped`) and
the overruns (`overlimits`): essential to check that a filter really directs the traffic to
the intended class (`watch -n 1 tc -s class show dev eth1`).
""",
    "netem : émuler un réseau": "netem: emulating a network",
    """
`netem` (*network emulator*, `man tc-netem`) retarde, perd, duplique ou réordonne les
paquets qui **sortent** par l'interface :

```
tc qdisc add     dev eth2 root netem delay 100ms            # délai fixe
tc qdisc replace dev eth2 root netem delay 100ms 50ms       # ± 50 ms de gigue (uniforme)
tc qdisc replace dev eth2 root netem delay 100ms 50ms loss 10%
tc qdisc del     dev eth2 root
```

Le délai s'ajoute dans **un seul sens** (celui de l'interface de sortie) : un `ping` qui
traverse `eth2` à l'aller et revient par le même routeur voit son RTT augmenter du délai
une seule fois. De même, une perte configurée sur `eth2` ne touche que les paquets qui sortent
par `eth2` : ceux qui reviennent en sens inverse (les acquittements d'un transfert, par
exemple) ne sont pas affectés.
""": """
`netem` (*network emulator*, `man tc-netem`) delays, drops, duplicates or reorders the packets
that **leave** through the interface:

```
tc qdisc add     dev eth2 root netem delay 100ms            # fixed delay
tc qdisc replace dev eth2 root netem delay 100ms 50ms       # ± 50 ms of jitter (uniform)
tc qdisc replace dev eth2 root netem delay 100ms 50ms loss 10%
tc qdisc del     dev eth2 root
```

The delay is added in **one direction only** (that of the egress interface): a `ping` that
crosses `eth2` on the way out and comes back through the same router sees its RTT grow by the
delay only once. Likewise, a loss configured on `eth2` only affects the packets leaving through
`eth2`: those coming back the other way (the acknowledgements of a transfer, for example) are
not affected.
""",
    "tbf : limiter un débit": "tbf: limiting a rate",
    """
`tbf` (*token bucket filter*, `man tc-tbf`) laisse passer les paquets au rythme de jetons
produits à `rate` ; `burst` est la taille du seau (la rafale maximale, au moins un MTU) et
`latency` (ou `limit`) la durée maximale qu'un paquet peut attendre dans la file avant d'être
jeté :

```
tc qdisc add dev eth1 root tbf rate 1mbit burst 30kbit latency 400ms
```

### @@sec:bufferbloat@@ Bufferbloat et fq_codel

Une file de 400 ms de paquets en attente signifie qu'**un `ping` qui traverse le lien chargé
voit son RTT augmenter de 400 ms** : c'est le *bufferbloat*. Remplacer la file `pfifo`
par **`fq_codel`** (file équitable par flux + contrôleur de délai CoDel, cible 5 ms) rend la
latence quasi indépendante de la charge : `tc qdisc add dev eth1 parent 1:10 fq_codel` (ici
sous une classe `htb`, section @@ref:htb@@).
""": """
`tbf` (*token bucket filter*, `man tc-tbf`) lets the packets through at the pace of tokens
produced at `rate`; `burst` is the size of the bucket (the maximum burst, at least one MTU) and
`latency` (or `limit`) the maximum time a packet may wait in the queue before being dropped:

```
tc qdisc add dev eth1 root tbf rate 1mbit burst 30kbit latency 400ms
```

### @@sec:bufferbloat@@ Bufferbloat and fq_codel

A queue holding 400 ms of waiting packets means that **a `ping` crossing the loaded link sees
its RTT grow by 400 ms**: this is *bufferbloat*. Replacing the `pfifo` queue with **`fq_codel`**
(per-flow fair queueing + CoDel delay controller, 5 ms target) makes the latency almost
independent of the load: `tc qdisc add dev eth1 parent 1:10 fq_codel` (here under an `htb`
class, section @@ref:htb@@).
""",
    "htb : partager la bande passante": "htb: sharing the bandwidth",
    """
`htb` (*hierarchy token bucket*, `man tc-htb`) répartit un débit entre des classes
hiérarchiques. Chaque classe a un débit **garanti** `rate` et un plafond `ceil` ; une classe
peut *emprunter* à ses sœurs la bande passante qu'elles n'utilisent pas, jusqu'à `ceil`.
L'emprunt passe par la **classe parente**, qui porte le débit total (`1:1` ci-dessous) : une
classe attachée directement à la racine `1:` n'a personne à qui emprunter et reste limitée à
son `rate`, quel que soit son `ceil`. `prio` (0 = la plus prioritaire) décide qui emprunte en
premier. `default` (en **hexa**) désigne la classe des paquets qu'aucun filtre ne classe :

```
tc qdisc add dev eth1 root handle 1: htb default 20
tc class add dev eth1 parent 1: classid 1:1  htb rate 10mbit
tc class add dev eth1 parent 1:1 classid 1:10 htb rate 8mbit ceil 10mbit
tc class add dev eth1 parent 1:1 classid 1:20 htb rate 2mbit ceil 10mbit
tc qdisc add dev eth1 parent 1:10 fq_codel
tc qdisc add dev eth1 parent 1:20 fq_codel
# le trafic vers le port TCP 5201 va dans 1:10 ; le reste dans 1:20 (default)
tc filter add dev eth1 protocol ip parent 1: prio 1 u32 match ip dport 5201 0xffff flowid 1:10
```

### @@sec:u32@@ Le filtre u32

Le filtre **u32** compare des mots de l'en-tête (`match ip dport PORT 0xffff`,
`match ip src 192.0.2.0/24`, `match ip protocol 6 0xff`). `tc filter show` affiche la
comparaison brute (`match 00001451/0000ffff at 20` : 0x1451 = 5201, à l'offset 20 de
l'en-tête IP).
""": """
`htb` (*hierarchy token bucket*, `man tc-htb`) shares a rate between hierarchical classes. Each
class has a **guaranteed** rate `rate` and a ceiling `ceil`; a class can *borrow* from its
siblings the bandwidth they do not use, up to `ceil`. Borrowing goes through the **parent
class**, which carries the total rate (`1:1` below): a class attached directly to the root `1:`
has nobody to borrow from and stays limited to its `rate`, whatever its `ceil`. `prio` (0 = the
highest priority) decides who borrows first. `default` (in **hex**) designates the class of the
packets that no filter classifies:

```
tc qdisc add dev eth1 root handle 1: htb default 20
tc class add dev eth1 parent 1: classid 1:1  htb rate 10mbit
tc class add dev eth1 parent 1:1 classid 1:10 htb rate 8mbit ceil 10mbit
tc class add dev eth1 parent 1:1 classid 1:20 htb rate 2mbit ceil 10mbit
tc qdisc add dev eth1 parent 1:10 fq_codel
tc qdisc add dev eth1 parent 1:20 fq_codel
# traffic to TCP port 5201 goes into 1:10; the rest into 1:20 (default)
tc filter add dev eth1 protocol ip parent 1: prio 1 u32 match ip dport 5201 0xffff flowid 1:10
```

### @@sec:u32@@ The u32 filter

The **u32** filter compares words of the header (`match ip dport PORT 0xffff`,
`match ip src 192.0.2.0/24`, `match ip protocol 6 0xff`). `tc filter show` displays the raw
comparison (`match 00001451/0000ffff at 20`: 0x1451 = 5201, at offset 20 of the IP header).
""",
    "Marquage nftables et filtre fw": "nftables marking and the fw filter",
    """
Plutôt que décrire les paquets dans `tc`, on peut les **marquer** avec le pare-feu et classer
sur la marque. En nftables la marque est `meta mark` ; on la pose dans une chaîne de type
`filter` accrochée à un *hook* traversé par le trafic **routé** (`prerouting` ou `forward` :
le hook `output` ne voit que les paquets émis par le routeur lui-même) :

```
nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule  ip mangle prerouting ip saddr 192.0.2.0/24 meta l4proto tcp meta mark set 10
nft list ruleset
```

Côté `tc`, le filtre **fw** classe selon la marque (`handle` = valeur de la marque) :

```
tc filter add dev eth1 parent 1: protocol ip handle 10 fw flowid 1:10
```

La marque n'existe que dans le noyau du routeur qui la pose : elle n'est pas transportée dans
le paquet. Les deux outils l'affichent en hexadécimal : `meta mark set 0x0000000a` dans
`nft list ruleset`, `handle 0xa` dans `tc filter show`.

`iptables -t mangle … -j MARK --set-mark 10` fait la même chose avec l'ancien outil.
""": """
Rather than describing the packets in `tc`, you can **mark** them with the firewall and classify
on the mark. In nftables the mark is `meta mark`; it is set in a chain of type `filter` attached
to a *hook* that **routed** traffic goes through (`prerouting` or `forward`: the `output` hook
only sees the packets sent by the router itself):

```
nft add table ip mangle
nft add chain ip mangle prerouting '{ type filter hook prerouting priority mangle; }'
nft add rule  ip mangle prerouting ip saddr 192.0.2.0/24 meta l4proto tcp meta mark set 10
nft list ruleset
```

On the `tc` side, the **fw** filter classifies by mark (`handle` = value of the mark):

```
tc filter add dev eth1 parent 1: protocol ip handle 10 fw flowid 1:10
```

The mark only exists in the kernel of the router that sets it: it is not carried in the packet.
Both tools display it in hexadecimal: `meta mark set 0x0000000a` in `nft list ruleset`,
`handle 0xa` in `tc filter show`.

`iptables -t mangle … -j MARK --set-mark 10` does the same with the older tool.
""",
    "Trafic entrant : ifb et cake": "Incoming traffic: ifb and cake",
    """
Une qdisc ne retient les paquets qu'en **sortie**. En entrée (*ingress*) le noyau ne peut
que *policer*, c'est-à-dire jeter l'excédent, sans file d'attente. Pour **régler** le débit
reçu, on redirige le trafic entrant vers une interface virtuelle **ifb** (*intermediate
functional block*), dont la sortie, elle, peut être régulée :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev eth1 handle ffff: ingress
tc filter add dev eth1 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth 50mbit
```

La qdisc `ingress` (identifiant `ffff:`) ne retient aucun paquet : elle ne sert qu'à accrocher
des filtres en entrée, et cohabite avec la qdisc racine de la même interface
(`tc qdisc del dev eth1 ingress` la supprime avec ses filtres). `match u32 0 0` est vrai pour
tout paquet ; l'interface `ifb0` doit être active (`up`), sinon les paquets redirigés sont
perdus.

### @@sec:cake@@ cake

**cake** (*common applications kept enhanced*, `man tc-cake`) combine en une seule qdisc
régulation de débit, file équitable par flux, AQM et priorisation : c'est la solution
moderne pour un lien d'accès. `tc -s qdisc show dev ifb0` montre son activité.
""": """
A qdisc holds packets back only on **egress**. On ingress the kernel can only *police*, that is
drop the excess, without any queue. To **regulate** the received rate, the incoming traffic is
redirected to a virtual **ifb** interface (*intermediate functional block*), whose egress, for
its part, can be shaped:

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev eth1 handle ffff: ingress
tc filter add dev eth1 parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth 50mbit
```

The `ingress` qdisc (identifier `ffff:`) holds no packet back: it only serves to attach filters
on ingress, and it coexists with the root qdisc of the same interface
(`tc qdisc del dev eth1 ingress` deletes it together with its filters). `match u32 0 0` is true
for every packet; the `ifb0` interface must be active (`up`), otherwise the redirected packets
are lost.

### @@sec:cake@@ cake

**cake** (*common applications kept enhanced*, `man tc-cake`) combines in a single qdisc rate
shaping, per-flow fair queueing, AQM and prioritisation: it is the modern solution for an access
link. `tc -s qdisc show dev ifb0` shows its activity.
""",
    "Mesurer": "Measuring",
    """
- `ping -c 20 -i 0.2 DEST` : RTT min/avg/max et **mdev** (écart-type, image de la gigue),
  pertes.
- `iperf3 -s [-p PORT]` sur le serveur ; `iperf3 -c SERVEUR [-p PORT] -t 10` sur le client ;
  `-R` (*reverse*) fait envoyer le serveur vers le client (mesure du débit *descendant*) ;
  `-J` produit du JSON. Un serveur iperf3 ne sert qu'un client à la fois : lancez-en un par
  port.
- `ss -ti dst SERVEUR` pendant un transfert : `rtt:<moyenne>/<variation>`, `cwnd`, `retrans`,
  `bytes_acked`… (`watch -n 0.5 "ss -ti dst SERVEUR"`).
- Wireshark, ou `dumpcap -i eth0 -w FICHIER.pcap` sur une machine sans écran puis ouverture du
  fichier dans Wireshark : *Statistiques → Graphique des flux TCP → Temps d'aller-retour* ;
  filtre `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
  tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
  tcp.analysis.lost_segment` puis *Statistiques → Conversations → TCP* pour la proportion.
""": """
- `ping -c 20 -i 0.2 DEST`: min/avg/max RTT and **mdev** (standard deviation, a picture of the
  jitter), losses.
- `iperf3 -s [-p PORT]` on the server; `iperf3 -c SERVER [-p PORT] -t 10` on the client;
  `-R` (*reverse*) makes the server send to the client (measurement of the *download* rate);
  `-J` produces JSON. An iperf3 server serves only one client at a time: start one per
  port.
- `ss -ti dst SERVER` during a transfer: `rtt:<average>/<variation>`, `cwnd`, `retrans`,
  `bytes_acked`… (`watch -n 0.5 "ss -ti dst SERVER"`).
- Wireshark, or `dumpcap -i eth0 -w FILE.pcap` on a machine without a display, then open the
  file in Wireshark: *Statistics → TCP Stream Graphs → Round Trip Time*;
  filter `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
  tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
  tcp.analysis.lost_segment` then *Statistics → Conversations → TCP* for the proportion.
""",
    "configuration tc non reproduite sur le miroir de {m} : {item}": "tc configuration not reproduced on the mirror of {m}: {item}",
    "marquage iptables détecté sur r1 : seul nftables est reproduit sur le miroir": "iptables marking detected on r1: only nftables is reproduced on the mirror",
    """
| réseau | préfixe | machines |
|--------|---------|----------|
| `netA` | `{netA}` | `m1` (`{m1}`), `r1` eth0 (`{r1_a}`), `r2` eth0 (`{r2_a}`) |
| `netS1` | `{netS1}` | `r1` eth1 (`{r1_s1}`), `serveur1` (`{serveur1}`) |
| `netS2` | `{netS2}` | `r1` eth2 (`{r1_s2}`), `serveur2` (`{serveur2}`) |
| `netB` | `{netB}` | `r2` eth1 (`{r2_b}`), `m2` (`{m2}`) |
""": """
| network | prefix | machines |
|---------|--------|----------|
| `netA` | `{netA}` | `m1` (`{m1}`), `r1` eth0 (`{r1_a}`), `r2` eth0 (`{r2_a}`) |
| `netS1` | `{netS1}` | `r1` eth1 (`{r1_s1}`), `serveur1` (`{serveur1}`) |
| `netS2` | `{netS2}` | `r1` eth2 (`{r1_s2}`), `serveur2` (`{serveur2}`) |
| `netB` | `{netB}` | `r2` eth1 (`{r2_b}`), `m2` (`{m2}`) |
""",
    """
| partie | machine / interface | paramètres de **votre** instance |
|--------|---------------------|----------------------------------|
| 2 — netem | `r1` `{dev_netem}` (vers `serveur2`) puis `serveur2` `{dev_rev}` | délai **{delay} ms**, gigue **{jitter} ms**, pertes **{loss} %** ; pertes retour **{rloss} %** |
| 3 — shaping | `r2` `{dev_shape}` (vers `m2`) | tbf **{tbf} Mbit/s** puis htb **{R} Mbit/s** ({hi} / {lo}) |
| 4 — priorité | `r1` `{dev_prio}` (vers `serveur1`) | marque **{mark}**, htb **{T} Mbit/s** ({thi} / {tlo}) |
| 5 — ingress | `r1` `{dev_prio}` → `ifb0` | cake **{C} Mbit/s** |
""": """
| part | machine / interface | parameters of **your** instance |
|------|---------------------|---------------------------------|
| 2 — netem | `r1` `{dev_netem}` (towards `serveur2`) then `serveur2` `{dev_rev}` | delay **{delay} ms**, jitter **{jitter} ms**, loss **{loss}%**; return loss **{rloss}%** |
| 3 — shaping | `r2` `{dev_shape}` (towards `m2`) | tbf **{tbf} Mbit/s** then htb **{R} Mbit/s** ({hi} / {lo}) |
| 4 — priority | `r1` `{dev_prio}` (towards `serveur1`) | mark **{mark}**, htb **{T} Mbit/s** ({thi} / {tlo}) |
| 5 — ingress | `r1` `{dev_prio}` → `ifb0` | cake **{C} Mbit/s** |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente `tc`, les qdisc utilisées, les filtres, le marquage
des paquets, la régulation du trafic entrant et les outils de mesure.

**La maquette.** Le LAN `netA` relie `m1`, `r1` et `r2`. Le routeur `r1` dessert `serveur1`
(`eth1`) et `serveur2` (`eth2`) ; `m2` est derrière `r2`. Le lien de `r1` vers `serveur2` traverse
un « WAN » qui ajoute un délai inconnu : vous l'estimerez dans la partie 1.
""": """
Read the **Informations** tab: it presents `tc`, the qdiscs used, the filters, packet marking,
the shaping of incoming traffic and the measurement tools.

**The topology.** The LAN `netA` links `m1`, `r1` and `r2`. The router `r1` serves `serveur1`
(`eth1`) and `serveur2` (`eth2`); `m2` is behind `r2`. The link from `r1` to `serveur2` crosses
a "WAN" that adds an unknown delay: you will estimate it in part 1.
""",
    """
**Déjà en place** (ne pas modifier) : adresses IP, routes et routage IPv4 sur `r1` et `r2`, noms
dans `/etc/hosts` (`ping serveur1` fonctionne), *offloads* GSO/GRO désactivés (les trames ont
la taille du MTU : pertes et débits réalistes). `m1` dispose aussi d'une interface vers votre
poste de travail (`172.17.0.1`) : `wireshark` lancé sur `m1` s'affiche sur votre écran.

Les liens de la maquette sont des commutateurs **VDE** en espace utilisateur : leur capacité
plafonne vers **45 à 50 Mbit/s** (vous la mesurerez dans la partie 1). Les débits demandés sont
donc tous inférieurs à 30 Mbit/s, sinon la limitation ne se verrait pas.

**Les valeurs de votre instance** (délais, débits, marque) :
""": """
**Already in place** (do not modify): IP addresses, routes and IPv4 routing on `r1` and `r2`,
names in `/etc/hosts` (`ping serveur1` works), GSO/GRO *offloads* disabled (the frames have the
size of the MTU: realistic losses and rates). `m1` also has an interface to your workstation
(`172.17.0.1`): `wireshark` started on `m1` is displayed on your screen.

The links of the topology are userspace **VDE** switches: their capacity tops out at around
**45 to 50 Mbit/s** (you will measure it in part 1). The rates asked for are therefore all below
30 Mbit/s, otherwise the limitation would not be visible.

**The values of your instance** (delays, rates, mark):
""",
    """
**Plan du TP.** Les énoncés détaillés sont dans les questions suivantes, numérotées comme les
parties.

- **Partie 1 — Diagnostic** : mesurer le RTT de `m1` vers `serveur1` et vers `serveur2` (le lien
  vers `serveur2` traverse le « WAN » dont vous estimerez le délai) et la capacité brute d'un
  lien. Cours : section @@ref:measure@@.
- **Partie 2 — netem** sur `r1 {dev_netem}` (vers `serveur2`) : délai, gigue, pertes ; pertes dans
  le sens retour sur `serveur2 {dev_rev}`. La configuration finale (délai + gigue + pertes) reste
  en place. Cours : section @@ref:netem@@.
- **Partie 3 — Shaping vers m2** sur `r2 {dev_shape}` : tbf (mesures, puis supprimé), puis htb
  80 % / 20 % selon le port avec files `fq_codel`. Cours : sections @@ref:tbf@@ et @@ref:htb@@.
- **Partie 4 — Priorité par marquage** sur `r1 {dev_prio}` (vers `serveur1`) : marque nftables du
  trafic de `netA`, htb à deux classes de priorités différentes, filtre `fw`. Cours : section
  @@ref:mark@@.
- **Partie 5 — Ingress** sur `r1 {dev_prio}` : redirection vers `ifb0` et `cake`. Cours : section
  @@ref:ingress@@.

**Règles valables pour tout le TP.**

- Chaque partie configure une interface différente (les parties 4 et 5 : la sortie puis
  l'entrée de la même interface) : **laissez en place** la configuration d'une partie terminée
  en passant à la suivante (seul le `tbf` de la partie 3 est remplacé par le `htb`). `tc` ne
  conserve rien au redémarrage d'une machine.
- Les serveurs `iperf3` sont à lancer vous-même sur `serveur1`, `serveur2` ou `m2` selon
  l'exercice (`iperf3 -s`, `iperf3 -s -p {pb}`, …), un par port : aucun ne tourne au départ.
- Le marquage de la partie 4 se fait avec **nftables** : une règle `iptables` ne serait pas
  reproduite sur la copie du réseau où l'évaluation fait ses mesures.
- Captures : Wireshark se lance sur `m1` ; sur une autre machine,
  `dumpcap -i eth0 -w /shared/capture.pcap` puis ouverture du fichier sur votre poste, avec lequel
  le répertoire `/shared` est partagé (`chmod a+r` sur le fichier s'il n'y est pas lisible).

**Évaluation.** À chaque évaluation la configuration `tc` (et `nft`) de **`r1`, `r2` et
`serveur2`** est relue, telle qu'elle est à ce moment, et reproduite sur une copie cachée du
réseau où sont faites toutes les mesures (ping, iperf3) : vos propres tests ne perturbent donc
pas la notation, mais **la configuration doit être en place au moment de l'évaluation**. Une
évaluation dure une trentaine de secondes. L'auto-évaluation ne note pas les réponses à choix
des formulaires (listes déroulantes) : seule l'évaluation de l'enseignant les prend en compte.
""": """
**Lab plan.** The detailed instructions are in the following questions, numbered like the
parts.

- **Part 1 — Diagnostics**: measure the RTT from `m1` to `serveur1` and to `serveur2` (the link
  to `serveur2` crosses the "WAN" whose delay you will estimate) and the raw capacity of a
  link. Course: section @@ref:measure@@.
- **Part 2 — netem** on `r1 {dev_netem}` (towards `serveur2`): delay, jitter, loss; loss in
  the return direction on `serveur2 {dev_rev}`. The final configuration (delay + jitter + loss)
  stays in place. Course: section @@ref:netem@@.
- **Part 3 — Shaping towards m2** on `r2 {dev_shape}`: tbf (measurements, then removed), then htb
  80% / 20% by port with `fq_codel` queues. Course: sections @@ref:tbf@@ and @@ref:htb@@.
- **Part 4 — Priority by marking** on `r1 {dev_prio}` (towards `serveur1`): nftables mark of the
  traffic of `netA`, htb with two classes of different priorities, `fw` filter. Course: section
  @@ref:mark@@.
- **Part 5 — Ingress** on `r1 {dev_prio}`: redirection to `ifb0` and `cake`. Course: section
  @@ref:ingress@@.

**Rules for the whole lab.**

- Each part configures a different interface (parts 4 and 5: the egress then the ingress of the
  same interface): **leave in place** the configuration of a finished part when moving on to the
  next one (only the `tbf` of part 3 is replaced by the `htb`). `tc` keeps nothing when a machine
  restarts.
- You start the `iperf3` servers yourself on `serveur1`, `serveur2` or `m2` depending on the
  exercise (`iperf3 -s`, `iperf3 -s -p {pb}`, …), one per port: none is running at the start.
- The marking of part 4 is done with **nftables**: an `iptables` rule would not be reproduced on
  the copy of the network where the evaluation takes its measurements.
- Captures: Wireshark runs on `m1`; on another machine,
  `dumpcap -i eth0 -w /shared/capture.pcap`, then open the file on your workstation, with which
  the `/shared` directory is shared (`chmod a+r` on the file if it is not readable there).

**Evaluation.** At each evaluation the `tc` (and `nft`) configuration of **`r1`, `r2` and
`serveur2`** is read, as it is at that moment, and reproduced on a hidden copy of the network
where all the measurements (ping, iperf3) are made: your own tests therefore do not disturb the
grading, but **the configuration must be in place at the time of the evaluation**. An evaluation
lasts about thirty seconds. The self-evaluation does not grade the multiple-choice answers of the
forms (drop-down lists): only the instructor's evaluation takes them into account.
""",
    """
**Pour l'enseignant.** Le « WAN » est un pont transparent caché, `wan`, entre `r1` et
`serveur2` : un `netem delay {wan}ms` sur chacune de ses deux interfaces, soit **{wan} ms par
sens**, sans saut visible dans un `traceroute`. RTT attendus de `m1` vers `serveur2` : **{base} ms**
au départ (réponse de la partie 1), **{rtt} ms** avec le délai netem de la partie 2. Les autres
valeurs de l'instance sont dans le tableau ci-dessus.

Toute la maquette est doublée par des clones cachés (`m1_h`, `r1_h`, … : mêmes adresses, mêmes
interfaces). Chaque évaluation relit la configuration `tc` de `r1`, `r2` et `serveur2` et les
règles nftables de `r1`, les reconstruit sur les clones, puis mesure entre clones (`ping`,
`iperf3`) : 40 points (3 + 9 + 10 + 10 + 8). Un avertissement signale une construction `tc`
qui n'a pas pu être reproduite sur le miroir, ou un marquage fait avec `iptables`. Les cinq
réponses à choix (`diag_ss_rtt`, `netem_q_asym`, `shape_q_bufferbloat`, `prio_q_hook`,
`ingress_q_ifb`) ne comptent que dans l'évaluation de l'enseignant ; les trois questions à réponse
libre ne sont pas notées. L'export Kathara est désactivé : il révélerait le miroir et le délai
du WAN.

Chaque question se termine par sa solution pour ces valeurs ; l'état `final` (onglet *Appliquer
une configuration*) applique toute la solution et remplit les formulaires.
""": """
**For the instructor.** The "WAN" is a hidden transparent bridge, `wan`, between `r1` and
`serveur2`: a `netem delay {wan}ms` on each of its two interfaces, i.e. **{wan} ms in each
direction**, with no visible hop in a `traceroute`. Expected RTTs from `m1` to `serveur2`:
**{base} ms** at the start (answer of part 1), **{rtt} ms** with the netem delay of part 2. The
other values of the instance are in the table above.

The whole topology is duplicated by hidden clones (`m1_h`, `r1_h`, …: same addresses, same
interfaces). Each evaluation reads the `tc` configuration of `r1`, `r2` and `serveur2` and the
nftables rules of `r1`, rebuilds them on the clones, then measures between clones (`ping`,
`iperf3`): 40 points (3 + 9 + 10 + 10 + 8). A warning reports a `tc` construction that could not
be reproduced on the mirror, or a marking done with `iptables`. The five multiple-choice answers
(`diag_ss_rtt`, `netem_q_asym`, `shape_q_bufferbloat`, `prio_q_hook`, `ingress_q_ifb`) only count
in the instructor's evaluation; the three free-text questions are not graded. The Kathara export
is disabled: it would reveal the mirror and the delay of the WAN.

Each question ends with its solution for these values; the `final` state (*Apply Configuration*
tab) applies the whole solution and fills in the forms.
""",
    "Partie 1 — Diagnostic du lien vers serveur2": "Part 1 — Diagnosing the link to serveur2",
    "Diagnostic du lien vers serveur2": "Diagnosing the link to serveur2",
    """
1. Depuis `m1`, mesurez le RTT vers `serveur1` puis vers `serveur2` (`ping -c 20 -i 0.2`).
   Le lien `r1` ↔ `serveur2` traverse un « WAN » qui ajoute un délai inconnu : vous le
   retrouverez dans la différence entre les deux mesures.
2. Lancez `iperf3 -s` sur `serveur1`, puis `iperf3 -c serveur1 -t 10` sur `m1` : c'est la
   capacité brute d'un lien de la maquette (commutateurs VDE), à garder en tête pour la suite.
3. Lancez `iperf3 -s` sur `serveur2`, puis `iperf3 -c serveur2 -t 30` sur `m1`. Pendant le
   transfert, dans un second terminal de `m1`, observez `watch -n 0.5 "ss -ti dst serveur2"` :
   retrouvez le RTT estimé par TCP (`rtt:`), la fenêtre de congestion (`cwnd`) et les
   retransmissions.
4. Capturez ce transfert avec Wireshark (sur `m1`, ou `dumpcap -i eth0 -w /shared/capture.pcap`
   puis ouverture sur le poste) et tracez *Statistiques → Graphique des flux TCP → Temps
   d'aller-retour*.
""": """
1. From `m1`, measure the RTT to `serveur1` then to `serveur2` (`ping -c 20 -i 0.2`).
   The link `r1` ↔ `serveur2` crosses a "WAN" that adds an unknown delay: you will find it in
   the difference between the two measurements.
2. Start `iperf3 -s` on `serveur1`, then `iperf3 -c serveur1 -t 10` on `m1`: this is the raw
   capacity of a link of the topology (VDE switches), to keep in mind for what follows.
3. Start `iperf3 -s` on `serveur2`, then `iperf3 -c serveur2 -t 30` on `m1`. During the
   transfer, in a second terminal of `m1`, watch `watch -n 0.5 "ss -ti dst serveur2"`:
   find the RTT estimated by TCP (`rtt:`), the congestion window (`cwnd`) and the
   retransmissions.
4. Capture this transfer with Wireshark (on `m1`, or `dumpcap -i eth0 -w /shared/capture.pcap`
   then open it on your workstation) and plot *Statistics → TCP Stream Graphs → Round Trip
   Time*.
""",
    """
**Solution.** Rien à configurer dans cette partie, seulement des mesures depuis `m1`.

- `ping -c 20 -i 0.2 serveur1` : un RTT de l'ordre de la milliseconde ou moins, aucun délai
  n'existant sur ce chemin. `ping -c 20 -i 0.2 serveur2` : environ **{base} ms**, soit {wan} ms
  ajoutés par le « WAN » dans chaque sens. Le premier écho vers `serveur2` dure à peu près le
  double : la résolution ARP traverse elle aussi le WAN.
- `iperf3 -c serveur1 -t 10` : environ 45 à 50 Mbit/s, la capacité des commutateurs VDE.
- `ss -ti dst serveur2` pendant le transfert : `rtt:<moyenne>/<variation>` en millisecondes,
  `cwnd:<segments>` et, dès qu'il y a eu des pertes, `retrans:<en cours>/<total>`.
- Graphique du RTT : capturer sur `m1`, l'émetteur des données, et sélectionner un segment du
  sens `m1` → `serveur2` avant d'ouvrir le graphique. Un fichier écrit par `dumpcap` dans `/shared`
  n'est lisible que par `root` : `chmod a+r /shared/capture.pcap` avant de l'ouvrir sur le poste.

Évaluation : cet énoncé ne porte aucun point ; les éléments de la partie 1 (`diag_rtt`,
`diag_ss_rtt`) notent le formulaire suivant.
""": """
**Solution.** Nothing to configure in this part, only measurements from `m1`.

- `ping -c 20 -i 0.2 serveur1`: an RTT of the order of a millisecond or less, since there is no
  delay on this path. `ping -c 20 -i 0.2 serveur2`: about **{base} ms**, i.e. {wan} ms added by
  the "WAN" in each direction. The first echo to `serveur2` takes roughly twice as long: the ARP
  resolution also crosses the WAN.
- `iperf3 -c serveur1 -t 10`: about 45 to 50 Mbit/s, the capacity of the VDE switches.
- `ss -ti dst serveur2` during the transfer: `rtt:<average>/<variation>` in milliseconds,
  `cwnd:<segments>` and, as soon as there have been losses, `retrans:<current>/<total>`.
- RTT graph: capture on `m1`, the sender of the data, and select a segment of the
  `m1` → `serveur2` direction before opening the graph. A file written by `dumpcap` in `/shared`
  is only readable by `root`: `chmod a+r /shared/capture.pcap` before opening it on the
  workstation.

Grading: this statement carries no points; the elements of part 1 (`diag_rtt`,
`diag_ss_rtt`) grade the next form.
""",
    "RTT de base": "Base RTT",
    """
- RTT moyen mesuré par `ping` de `m1` vers `serveur2`, en ms : @@{rtt:[0-9]+([.,][0-9]+)?}@@
- Dans la sortie de `ss -ti`, le champ qui donne le RTT estimé par TCP et sa variation est :
  @@{ss_field:>cwnd|rtt|rto|bytes_acked}@@
""": """
- Average RTT measured by `ping` from `m1` to `serveur2`, in ms: @@{rtt:[0-9]+([.,][0-9]+)?}@@
- In the output of `ss -ti`, the field giving the RTT estimated by TCP and its variation is:
  @@{ss_field:>cwnd|rtt|rto|bytes_acked}@@
""",
    """
**Solution.** RTT : **{base}** ms, soit 2 × {wan} ms, le délai du WAN dans chaque sens (le reste
du chemin n'ajoute presque rien). Champ **`rtt`** : `rtt:<moyenne>/<variation>`, en
millisecondes ; `rto` est la temporisation de retransmission que TCP en déduit, `cwnd` la
fenêtre de congestion, `bytes_acked` le nombre d'octets acquittés.

Évaluation : `diag_rtt` (2 points : réponse égale à {base} ms à 25 % + 2 ms près) et
`diag_ss_rtt` (1 point, évaluation de l'enseignant seulement : `rtt`).
""": """
**Solution.** RTT: **{base}** ms, i.e. 2 × {wan} ms, the delay of the WAN in each direction (the
rest of the path adds almost nothing). Field **`rtt`**: `rtt:<average>/<variation>`, in
milliseconds; `rto` is the retransmission timeout TCP derives from it, `cwnd` the congestion
window, `bytes_acked` the number of bytes acknowledged.

Grading: `diag_rtt` (2 points: an answer equal to {base} ms within 25% + 2 ms) and
`diag_ss_rtt` (1 point, instructor's evaluation only: `rtt`).
""",
    "RTT mesuré de m1 vers serveur2 (délai du WAN)": "RTT measured from m1 to serveur2 (WAN delay)",
    "champ rtt de ss -ti": "rtt field of ss -ti",
    "Observations sur le graphique du RTT": "Observations on the RTT graph",
    "Décrivez l'allure du graphique *Temps d'aller-retour* du transfert iperf3 (valeur typique, variations) et comparez-la au `ping`.": "Describe the shape of the *Round Trip Time* graph of the iperf3 transfer (typical value, variations) and compare it with the `ping`.",
    """

**Solution.** Réponse libre, non notée. Attendu : le RTT vu par TCP ne descend pas sous celui du
`ping` au repos (environ {base} ms, le délai du WAN) et se tient nettement au-dessus pendant le
transfert : `iperf3` remplit les files d'attente du chemin, et chaque segment attend derrière
ceux qui le précèdent. La courbe est en dents de scie : elle suit la fenêtre de congestion, qui
grandit jusqu'à une perte puis se réduit. Le `ping` au repos ne mesure, lui, que le délai du
chemin vide.
""": """

**Solution.** Free answer, not graded. Expected: the RTT seen by TCP does not go below that of
the idle `ping` (about {base} ms, the delay of the WAN) and stays clearly above it during the
transfer: `iperf3` fills the queues of the path, and each segment waits behind those ahead of
it. The curve is saw-toothed: it follows the congestion window, which grows until a loss and
then shrinks. The idle `ping`, for its part, only measures the delay of the empty path.
""",
    "Capacité brute d'un lien": "Raw capacity of a link",
    "Débit obtenu par `iperf3` de `m1` vers `serveur1` sans aucune régulation (Mbit/s), et ce que cela implique pour les débits à configurer dans ce TP.": "Rate obtained by `iperf3` from `m1` to `serveur1` without any shaping (Mbit/s), and what this implies for the rates to configure in this lab.",
    """

**Solution.** Réponse libre, non notée. Attendu : environ **45 à 50 Mbit/s** (les liens sont des
commutateurs VDE en espace utilisateur ; la valeur dépend de la charge du poste). Conséquence :
une limitation ne se voit que si elle est nettement inférieure à cette capacité, d'où des débits
demandés tous inférieurs à 30 Mbit/s ; un débit configuré au-dessus ne limiterait rien.
""": """

**Solution.** Free answer, not graded. Expected: about **45 to 50 Mbit/s** (the links are
userspace VDE switches; the value depends on the load of the workstation). Consequence: a
limitation is only visible if it is clearly below this capacity, hence the rates asked for are
all below 30 Mbit/s; a rate configured above it would limit nothing.
""",
    "Partie 2 — Émulation de latence et de pertes (netem)": "Part 2 — Emulating latency and losses (netem)",
    "netem sur r1 vers serveur2": "netem on r1 towards serveur2",
    """
Sur `r1`, l'interface **`{dev}`** mène à `serveur2`. Toutes les mesures se font de `m1`
vers `serveur2` (`ping`, `iperf3 -c serveur2`).

1. Ajoutez un délai de **{delay} ms** : `tc qdisc add dev {dev} root netem delay {delay}ms`.
   Refaites la mesure du RTT par `ping` vers `serveur2` (et, pour comparer, vers `serveur1`).
2. Ajoutez une gigue de **{jitter} ms** : `tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms`.
   Refaites les mesures : observez `mdev` dans le résumé de `ping`.
3. Supprimez la configuration (`tc qdisc del dev {dev} root`) puis configurez **{loss} %** de
   pertes : `tc qdisc add dev {dev} root netem loss {loss}%`. Relancez `iperf3` : que
   constatez-vous ? Capturez le transfert et estimez la proportion de segments retransmis avec
   le filtre d'affichage `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
   tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
   tcp.analysis.lost_segment` puis *Statistiques → Conversations → TCP*.
4. Pertes dans le sens **retour** : sur **`serveur2`**, `tc qdisc add dev eth0 root netem loss {rloss}%`
   (les paquets de `serveur2` vers `m1`, donc les acquittements du transfert). Refaites le test
   `iperf3` de `m1` vers `serveur2` : que se passe-t-il ?
5. **Configuration finale à laisser en place** : sur `r1 {dev}`, délai **{delay} ms**, gigue
   **{jitter} ms** et pertes **{loss} %** ensemble
   (`tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%`) ; sur
   `serveur2 eth0`, pertes **{rloss} %**.
""": """
On `r1`, interface **`{dev}`** leads to `serveur2`. All the measurements are made from `m1`
to `serveur2` (`ping`, `iperf3 -c serveur2`).

1. Add a delay of **{delay} ms**: `tc qdisc add dev {dev} root netem delay {delay}ms`.
   Measure the RTT again with `ping` to `serveur2` (and, for comparison, to `serveur1`).
2. Add a jitter of **{jitter} ms**: `tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms`.
   Repeat the measurements: look at `mdev` in the summary of `ping`.
3. Delete the configuration (`tc qdisc del dev {dev} root`), then configure **{loss}%**
   loss: `tc qdisc add dev {dev} root netem loss {loss}%`. Run `iperf3` again: what do you
   notice? Capture the transfer and estimate the proportion of retransmitted segments with
   the display filter `tcp.analysis.retransmission || tcp.analysis.fast_retransmission ||
   tcp.analysis.spurious_retransmission || tcp.analysis.out_of_order ||
   tcp.analysis.lost_segment` then *Statistics → Conversations → TCP*.
4. Loss in the **return** direction: on **`serveur2`**, `tc qdisc add dev eth0 root netem loss {rloss}%`
   (the packets from `serveur2` to `m1`, hence the acknowledgements of the transfer). Repeat the
   `iperf3` test from `m1` to `serveur2`: what happens?
5. **Final configuration to leave in place**: on `r1 {dev}`, delay **{delay} ms**, jitter
   **{jitter} ms** and loss **{loss}%** together
   (`tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%`); on
   `serveur2 eth0`, loss **{rloss}%**.
""",
    """
**Solution.** Configuration finale, celle qu'applique l'état `final`. Sur `r1` :

```
tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%
```

Sur `serveur2` :

```
tc qdisc replace dev {rdev} root netem loss {rloss}%
```

- Étape 1 : le RTT vers `serveur2` passe de {base} à environ **{rtt} ms** ({base} + {delay}). Le
  délai ne retarde que les paquets qui sortent de `r1` par `{dev}`, donc l'aller seulement ; le
  RTT vers `serveur1` ne change pas.
- Étape 2 : la moyenne reste voisine de {rtt} ms, les RTT s'étalent de {low} à {high} ms et
  `mdev` monte à environ {mdev} ms (écart-type d'une loi uniforme sur ± {jitter} ms :
  {jitter} / √3).
- Étape 3 : le débit s'effondre et la proportion de segments retransmis est voisine de
  {loss} % (voir les deux questions suivantes).
- Étape 4 : ces pertes ne touchent que les acquittements du transfert ; le débit baisse peu.
- `tc qdisc add` échoue quand une qdisc racine est déjà en place : `replace`, ou `del` d'abord.

Évaluation : `netem_delai`, `netem_gigue`, `netem_pertes` (1 point chacun : la qdisc racine de
`r1` `{dev}` est un netem de délai {delay} ms et de gigue {jitter} ms à 2 ms près, de pertes
{loss} % à 0,6 point près), `netem_pertes_retour` (1 : netem de pertes {rloss} % à la racine de
`serveur2` `{rdev}`) et `netem_rtt_mesure` (2 : sur le miroir, 20 échos de `m1` vers `serveur2`,
au moins 8 réponses et un RTT médian de {rtt} ms à 25 % + 10 ms près).
""": """
**Solution.** The final configuration, the one the `final` state applies. On `r1`:

```
tc qdisc replace dev {dev} root netem delay {delay}ms {jitter}ms loss {loss}%
```

On `serveur2`:

```
tc qdisc replace dev {rdev} root netem loss {rloss}%
```

- Step 1: the RTT to `serveur2` goes from {base} to about **{rtt} ms** ({base} + {delay}). The
  delay only holds back the packets leaving `r1` through `{dev}`, hence the outbound direction
  only; the RTT to `serveur1` does not change.
- Step 2: the average stays close to {rtt} ms, the RTTs spread from {low} to {high} ms and
  `mdev` rises to about {mdev} ms (standard deviation of a uniform distribution over ± {jitter} ms:
  {jitter} / √3).
- Step 3: the rate collapses and the proportion of retransmitted segments is close to
  {loss}% (see the next two questions).
- Step 4: these losses only affect the acknowledgements of the transfer; the rate drops only
  slightly.
- `tc qdisc add` fails when a root qdisc is already in place: `replace`, or `del` first.

Grading: `netem_delai`, `netem_gigue`, `netem_pertes` (1 point each: the root qdisc of `r1`
`{dev}` is a netem with a delay of {delay} ms and a jitter of {jitter} ms within 2 ms, and a
loss of {loss}% within 0.6 percentage points), `netem_pertes_retour` (1: a netem with a loss of
{rloss}% at the root of `serveur2` `{rdev}`) and `netem_rtt_mesure` (2: on the mirror, 20 echoes
from `m1` to `serveur2`, at least 8 replies and a median RTT of {rtt} ms within 25% + 10 ms).
""",
    "Mesures avec netem": "Measurements with netem",
    """
- RTT moyen (ms) de `m1` vers `serveur2` après l'ajout du délai de {delay} ms (étape 1) :
  @@{{rtt_delay:[0-9]+([.,][0-9]+)?}}@@
- Proportion (%) de segments retransmis observée dans Wireshark avec {loss} % de pertes (étape 3) :
  @@{{retrans:[0-9]+([.,][0-9]+)?}}@@
- Avec les pertes dans le sens retour (étape 4), le débit du transfert de `m1` vers `serveur2` :
  @@{{asym:>devient nul|s'effondre autant qu'avec des pertes de données|baisse peu : les acquittements sont cumulatifs}}@@
""": """
- Average RTT (ms) from `m1` to `serveur2` after adding the delay of {delay} ms (step 1):
  @@{{rtt_delay:[0-9]+([.,][0-9]+)?}}@@
- Proportion (%) of retransmitted segments observed in Wireshark with {loss}% loss (step 3):
  @@{{retrans:[0-9]+([.,][0-9]+)?}}@@
- With the loss in the return direction (step 4), the rate of the transfer from `m1` to `serveur2`:
  @@{{asym:>becomes zero>>>devient nul|collapses as much as with a loss of data>>>s'effondre autant qu'avec des pertes de données|drops only slightly: acknowledgements are cumulative>>>baisse peu : les acquittements sont cumulatifs}}@@
""",
    """
**Solution.** RTT après l'ajout du délai : **{rtt}** ms ({base} + {delay}). Proportion de
segments retransmis : environ **{loss}** %, chaque segment perdu étant retransmis. Avec les
pertes dans le sens retour, le débit **baisse peu : les acquittements sont cumulatifs** —
l'acquittement suivant confirme aussi les octets de celui qui s'est perdu, sans retransmission
de données.

Évaluation : `netem_q_rtt` (1 point : {rtt} ms à 25 % + 5 ms près), `netem_q_retrans` (1 : une
valeur comprise entre la moitié et le double de {loss} %) et `netem_q_asym` (1, évaluation de
l'enseignant seulement).
""": """
**Solution.** RTT after adding the delay: **{rtt}** ms ({base} + {delay}). Proportion of
retransmitted segments: about **{loss}**%, each lost segment being retransmitted. With the
loss in the return direction, the rate **drops only slightly: acknowledgements are cumulative**
— the next acknowledgement also confirms the bytes of the one that was lost, without any
retransmission of data.

Grading: `netem_q_rtt` (1 point: {rtt} ms within 25% + 5 ms), `netem_q_retrans` (1: a
value between half and twice {loss}%) and `netem_q_asym` (1, instructor's evaluation
only).
""",
    "Observations avec des pertes": "Observations with losses",
    "Que constatez-vous sur le débit `iperf3` avec {loss} % de pertes ? Qu'indique `ss -ti` (`cwnd`, `retrans`) ?": "What do you notice about the `iperf3` rate with {loss}% loss? What does `ss -ti` show (`cwnd`, `retrans`)?",
    """

**Solution.** Réponse libre, non notée. Attendu : le débit s'effondre, de 45 à 50 Mbit/s à
quelques Mbit/s au plus : TCP prend chaque perte pour un signe de congestion et réduit sa
fenêtre. Ordre de grandeur donné par la formule de Mathis, débit ≈ 1,22 × MSS / (RTT × √p) :
avec un RTT de {base} ms et p = {loss} %, au plus {mathis} Mbit/s environ, et souvent
nettement moins car à ce taux de pertes les expirations de temporisation s'ajoutent aux
retransmissions rapides. `ss -ti` montre un `cwnd` qui reste à quelques segments et un champ
`retrans:<en cours>/<total>` dont le total augmente sans cesse.
""": """

**Solution.** Free answer, not graded. Expected: the rate collapses, from 45 to 50 Mbit/s down to
a few Mbit/s at most: TCP takes each loss as a sign of congestion and reduces its window. The
Mathis formula gives the order of magnitude, rate ≈ 1.22 × MSS / (RTT × √p): with an RTT of
{base} ms and p = {loss}%, about {mathis} Mbit/s at most, and often clearly less, because at
this loss rate retransmission timeouts add to the fast retransmissions. `ss -ti` shows a `cwnd`
that stays at a few segments and a `retrans:<current>/<total>` field whose total keeps
growing.
""",
    "netem sur r1 {dev} : délai de {delay} ms": "netem on r1 {dev}: delay of {delay} ms",
    "netem sur r1 {dev} : gigue de {jitter} ms": "netem on r1 {dev}: jitter of {jitter} ms",
    "netem sur r1 {dev} : pertes de {loss} %": "netem on r1 {dev}: loss of {loss}%",
    "netem sur serveur2 eth0 : pertes de {loss} % vers r1": "netem on serveur2 eth0: loss of {loss}% towards r1",
    "RTT mesuré sur le miroir de m1 vers serveur2 ≈ {rtt} ms": "RTT measured on the mirror from m1 to serveur2 ≈ {rtt} ms",
    "RTT déclaré après ajout du délai": "RTT stated after adding the delay",
    "proportion de retransmissions cohérente avec les pertes": "proportion of retransmissions consistent with the loss",
    "effet des pertes dans le sens retour": "effect of the loss in the return direction",
    "Partie 3 — Régulation de débit vers m2 (tbf, htb, fq_codel)": "Part 3 — Rate shaping towards m2 (tbf, htb, fq_codel)",
    "Shaping sur r2 vers m2": "Shaping on r2 towards m2",
    """
Sur `r2`, l'interface **`{dev}`** mène à `m2`. Lancez sur `m2` deux serveurs :
`iperf3 -s -p {pa}` et `iperf3 -s -p {pb}` ; les clients tournent sur `m1`.

1. **tbf** : limitez le débit vers `m2` à **{tbf} Mbit/s** avec un seau de {burst} et une
   latence de {latency} : `tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}`.
   Mesurez le débit avec `iperf3 -c m2 -p {pa} -t 15` et, **pendant** ce transfert, le RTT de
   `m1` vers `m2` avec `ping` : c'est le *bufferbloat*.
2. Supprimez le `tbf`. Avec **htb**, limitez le trafic total vers `m2` à **{R} Mbit/s** en
   garantissant **{hi} Mbit/s** au port TCP **{pa}** (classe `1:10`) et **{lo} Mbit/s** au
   reste (classe `1:20`, classe par défaut), chaque classe pouvant emprunter jusqu'à {R} Mbit/s
   (`ceil`). Le filtre `u32` dirige le port {pa} vers `1:10`.
3. Remplacez la file `pfifo` de chaque classe par **`fq_codel`**
   (`tc qdisc add dev {dev} parent 1:10 fq_codel`, idem `1:20`).
4. Testez avec deux clients simultanés sur `m1` (`iperf3 -c m2 -p {pa} -t 15` et
   `iperf3 -c m2 -p {pb} -t 15`) et observez `watch -n 1 tc -s class show dev {dev}` sur `r2`.
   Refaites un `ping` de `m1` vers `m2` pendant les transferts et comparez avec l'étape 1.
""": """
On `r2`, interface **`{dev}`** leads to `m2`. Start two servers on `m2`:
`iperf3 -s -p {pa}` and `iperf3 -s -p {pb}`; the clients run on `m1`.

1. **tbf**: limit the rate towards `m2` to **{tbf} Mbit/s** with a bucket of {burst} and a
   latency of {latency}: `tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}`.
   Measure the rate with `iperf3 -c m2 -p {pa} -t 15` and, **during** this transfer, the RTT from
   `m1` to `m2` with `ping`: this is *bufferbloat*.
2. Delete the `tbf`. With **htb**, limit the total traffic towards `m2` to **{R} Mbit/s** while
   guaranteeing **{hi} Mbit/s** to TCP port **{pa}** (class `1:10`) and **{lo} Mbit/s** to the
   rest (class `1:20`, the default class), each class being able to borrow up to {R} Mbit/s
   (`ceil`). The `u32` filter directs port {pa} to `1:10`.
3. Replace the `pfifo` queue of each class with **`fq_codel`**
   (`tc qdisc add dev {dev} parent 1:10 fq_codel`, likewise for `1:20`).
4. Test with two simultaneous clients on `m1` (`iperf3 -c m2 -p {pa} -t 15` and
   `iperf3 -c m2 -p {pb} -t 15`) and watch `watch -n 1 tc -s class show dev {dev}` on `r2`.
   Run a `ping` from `m1` to `m2` again during the transfers and compare with step 1.
""",
    """
**Solution.** Étape 1, sur `r2` :

```
tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}
```

`iperf3` mesure environ {tbf} Mbit/s et le RTT de `m1` vers `m2` monte à environ 400 ms pendant
le transfert : la file du `tbf` (`latency {latency}`) reste pleine et chaque paquet, écho
compris, y attend son tour.

Étapes 2 et 3, sur `r2` (ce qu'applique l'état `final`) :

```
tc qdisc del dev {dev} root
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:1 htb rate {R}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:10 htb rate {hi}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:20 htb rate {lo}mbit ceil {R}mbit
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} protocol ip parent 1: prio 1 u32 match ip dport {pa} 0xffff flowid 1:10
```

- Étape 4 : avec les deux clients, le port {pa} obtient environ {hi} Mbit/s et le port {pb}
  environ {lo} Mbit/s, {R} au total ; un client seul emprunte jusqu'à {R} Mbit/s (`ceil`). Dans
  `tc -s class show dev {dev}`, les compteurs de `1:10` et de `1:20` avancent chacun avec son
  flux. Le RTT du `ping` reste faible, loin des 400 ms de l'étape 1 : `fq_codel` ne fait pas
  attendre les échos derrière les transferts.
- La classe parente `1:1` porte le débit total : sans elle, `1:10` et `1:20` ne pourraient
  rien s'emprunter.
- `default 20` est lu en hexadécimal, comme les identifiants de classes : il désigne bien `1:20`.
- Le « reste » doit passer par la classe par défaut, et non par un second filtre sur le port
  {pb} : l'évaluation mesure le flux non classé sur un autre port ({gp}).

Évaluation : `shape_htb_racine` (1 point : htb à la racine de `r2` `{dev}`, avec une classe
feuille par défaut), `shape_classe_port` (1 : la classe visée par le filtre du port {pa} a
`rate {hi}mbit` et `ceil {R}mbit`, à 3 % près), `shape_classe_defaut` (1 : la classe par défaut,
distincte de la précédente, a `rate {lo}mbit` et `ceil {R}mbit`), `shape_fq_codel` (1 : une
`fq_codel` sous chaque classe feuille), `shape_filtre_u32` (1 : un filtre sur le port
destination {pa} vise une classe feuille autre que la classe par défaut), puis, sur le miroir,
deux flux simultanés de `m1` vers `m2` (ports {pa} et {gp}) et un `ping` : `shape_mesure_total`
(1 : total entre 60 % et 110 % de {R} Mbit/s), `shape_mesure_partage` (1 : le flux du port {pa}
atteint 60 % de {R} Mbit/s, l'autre ne dépasse pas 30 %) et `shape_mesure_latence` (1 : avec le
htb à la racine, RTT moyen sous charge inférieur à 50 ms).
""": """
**Solution.** Step 1, on `r2`:

```
tc qdisc add dev {dev} root tbf rate {tbf}mbit burst {burst} latency {latency}
```

`iperf3` measures about {tbf} Mbit/s and the RTT from `m1` to `m2` rises to about 400 ms during
the transfer: the queue of the `tbf` (`latency {latency}`) stays full and every packet, echoes
included, waits its turn in it.

Steps 2 and 3, on `r2` (what the `final` state applies):

```
tc qdisc del dev {dev} root
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:1 htb rate {R}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:10 htb rate {hi}mbit ceil {R}mbit
tc class add dev {dev} parent 1:1 classid 1:20 htb rate {lo}mbit ceil {R}mbit
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} protocol ip parent 1: prio 1 u32 match ip dport {pa} 0xffff flowid 1:10
```

- Step 4: with the two clients, port {pa} gets about {hi} Mbit/s and port {pb} about
  {lo} Mbit/s, {R} in total; a single client borrows up to {R} Mbit/s (`ceil`). In
  `tc -s class show dev {dev}`, the counters of `1:10` and of `1:20` each advance with their own
  flow. The RTT of the `ping` stays low, far from the 400 ms of step 1: `fq_codel` does not make
  the echoes wait behind the transfers.
- The parent class `1:1` carries the total rate: without it, `1:10` and `1:20` could not borrow
  anything from each other.
- `default 20` is read in hexadecimal, like the class identifiers: it does designate `1:20`.
- The "rest" must go through the default class, not through a second filter on port
  {pb}: the evaluation measures the unclassified flow on another port ({gp}).

Grading: `shape_htb_racine` (1 point: htb at the root of `r2` `{dev}`, with a default leaf
class), `shape_classe_port` (1: the class targeted by the filter of port {pa} has
`rate {hi}mbit` and `ceil {R}mbit`, within 3%), `shape_classe_defaut` (1: the default class,
distinct from the previous one, has `rate {lo}mbit` and `ceil {R}mbit`), `shape_fq_codel` (1: an
`fq_codel` under each leaf class), `shape_filtre_u32` (1: a filter on destination port
{pa} targets a leaf class other than the default class), then, on the mirror, two simultaneous
flows from `m1` to `m2` (ports {pa} and {gp}) and a `ping`: `shape_mesure_total`
(1: a total between 60% and 110% of {R} Mbit/s), `shape_mesure_partage` (1: the flow of port {pa}
reaches 60% of {R} Mbit/s, the other one does not exceed 30%) and `shape_mesure_latence` (1: with
the htb at the root, an average RTT under load below 50 ms).
""",
    "Mesures de shaping": "Shaping measurements",
    """
- Débit (Mbit/s) mesuré par `iperf3` avec le `tbf` à {tbf} Mbit/s (étape 1) : @@{{tbf_mbps:[0-9]+([.,][0-9]+)?}}@@
- RTT de `m1` vers `m2` pendant le transfert avec le `tbf` (étape 1) :
  @@{{bloat:>environ 1 ms|environ 40 ms|environ 400 ms|plus de 4 s}}@@
""": """
- Rate (Mbit/s) measured by `iperf3` with the `tbf` at {tbf} Mbit/s (step 1): @@{{tbf_mbps:[0-9]+([.,][0-9]+)?}}@@
- RTT from `m1` to `m2` during the transfer with the `tbf` (step 1):
  @@{{bloat:>about 1 ms>>>environ 1 ms|about 40 ms>>>environ 40 ms|about 400 ms>>>environ 400 ms|more than 4 s>>>plus de 4 s}}@@
""",
    """
**Solution.** Débit avec le `tbf` : environ **{tbf}** Mbit/s, le `rate` configuré. RTT pendant
le transfert : **environ 400 ms** — le transfert maintient la file du `tbf` pleine, et tout
paquet qui la traverse y attend jusqu'à la durée fixée par `latency {latency}` : c'est le
*bufferbloat*.

Évaluation : `shape_q_tbf` (1 point : {tbf} Mbit/s à 30 % près) et `shape_q_bufferbloat` (1,
évaluation de l'enseignant seulement).
""": """
**Solution.** Rate with the `tbf`: about **{tbf}** Mbit/s, the configured `rate`. RTT during
the transfer: **about 400 ms** — the transfer keeps the queue of the `tbf` full, and any packet
crossing it waits there for up to the time set by `latency {latency}`: this is
*bufferbloat*.

Grading: `shape_q_tbf` (1 point: {tbf} Mbit/s within 30%) and `shape_q_bufferbloat` (1,
instructor's evaluation only).
""",
    "htb à la racine de r2 {dev} avec une classe par défaut": "htb at the root of r2 {dev} with a default class",
    "classe du port {pa} : rate {hi} Mbit/s, ceil {R} Mbit/s": "class of port {pa}: rate {hi} Mbit/s, ceil {R} Mbit/s",
    "classe par défaut : rate {lo} Mbit/s, ceil {R} Mbit/s": "default class: rate {lo} Mbit/s, ceil {R} Mbit/s",
    "fq_codel sous chaque classe feuille": "fq_codel under each leaf class",
    "filtre u32 : port {pa} vers la classe garantie": "u32 filter: port {pa} to the guaranteed class",
    "miroir : débit total vers m2 limité à {R} Mbit/s": "mirror: total rate towards m2 limited to {R} Mbit/s",
    "miroir : port {pa} ≈ {hi} Mbit/s, autre flux ≈ {lo} Mbit/s": "mirror: port {pa} ≈ {hi} Mbit/s, other flow ≈ {lo} Mbit/s",
    "miroir : RTT vers m2 sous charge < 50 ms (fq_codel)": "mirror: RTT to m2 under load < 50 ms (fq_codel)",
    "débit déclaré avec le tbf": "rate stated with the tbf",
    "RTT sous charge avec le tbf (bufferbloat)": "RTT under load with the tbf (bufferbloat)",
    "Partie 4 — Priorité par marquage nftables (fw, htb)": "Part 4 — Priority by nftables marking (fw, htb)",
    "Marquage et priorité sur r1 vers serveur1": "Marking and priority on r1 towards serveur1",
    """
Sur `r1`, l'interface **`{dev}`** mène à `serveur1`. La bande passante totale vers `serveur1`
sera limitée à **{T} Mbit/s** ; le trafic provenant du réseau de `m1` (`{netA}`) est
prioritaire et garanti **{hi} Mbit/s**, le reste (par exemple `m2`) **{lo} Mbit/s**.

1. Avec **nftables**, marquez les paquets TCP venant de `{netA}` avec la marque **{mark}**
   (table `mangle`, chaîne de type `filter` sur le hook `prerouting`, règle
   `ip saddr {netA} meta l4proto tcp meta mark set {mark}`). Vérifiez avec `nft list ruleset`.
2. Avec **htb** sur `{dev}` : classe `1:10` (`rate {hi}mbit ceil {T}mbit prio 0`) pour le trafic
   marqué, classe `1:20` (`rate {lo}mbit ceil {T}mbit prio 1`) par défaut, une `fq_codel` sous
   chaque classe, et le filtre `fw` qui envoie la marque {mark} dans `1:10` :
   `tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10`.
3. Testez avec deux serveurs `iperf3` sur `serveur1` (ports {pa} et {pb}) et deux clients
   simultanés, l'un sur `m1`, l'autre sur `m2`. Observez `tc -s class show dev {dev}` sur `r1`.
""": """
On `r1`, interface **`{dev}`** leads to `serveur1`. The total bandwidth towards `serveur1`
will be limited to **{T} Mbit/s**; the traffic coming from the network of `m1` (`{netA}`) has
priority and is guaranteed **{hi} Mbit/s**, the rest (for example `m2`) **{lo} Mbit/s**.

1. With **nftables**, mark the TCP packets coming from `{netA}` with the mark **{mark}**
   (table `mangle`, chain of type `filter` on the `prerouting` hook, rule
   `ip saddr {netA} meta l4proto tcp meta mark set {mark}`). Check with `nft list ruleset`.
2. With **htb** on `{dev}`: class `1:10` (`rate {hi}mbit ceil {T}mbit prio 0`) for the marked
   traffic, class `1:20` (`rate {lo}mbit ceil {T}mbit prio 1`) by default, an `fq_codel` under
   each class, and the `fw` filter that sends mark {mark} into `1:10`:
   `tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10`.
3. Test with two `iperf3` servers on `serveur1` (ports {pa} and {pb}) and two simultaneous
   clients, one on `m1`, the other on `m2`. Watch `tc -s class show dev {dev}` on `r1`.
""",
    """
**Solution.** Sur `r1` (ce qu'applique l'état `final`, qui supprime d'abord la table `mangle` et
la qdisc racine déjà présentes pour pouvoir être rejoué) :

```
nft add table ip mangle
nft add chain ip mangle prerouting '{{ type filter hook prerouting priority mangle; }}'
nft add rule ip mangle prerouting ip saddr {netA} meta l4proto tcp meta mark set {mark}
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:10 htb rate {hi}mbit ceil {T}mbit prio 0
tc class add dev {dev} parent 1: classid 1:20 htb rate {lo}mbit ceil {T}mbit prio 1
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10
```

- La marque s'affiche en hexadécimal : `meta mark set 0x{mark:08x}` dans `nft list ruleset`,
  `handle 0x{mark:x} classid 1:10` dans `tc filter show dev {dev}`.
- Étape 3 : le flux de `m1`, marqué, obtient environ {hi} Mbit/s et celui de `m2` environ
  {lo} Mbit/s ; `tc -s class show dev {dev}` montre le premier dans `1:10`, le second dans
  `1:20`. Les deux classes sont attachées directement à la racine : elles ne s'empruntent rien
  et chacune reste limitée à son `rate`, d'où un total d'au plus {T} Mbit/s (un flux de `m1`
  seul plafonne à {hi} Mbit/s, malgré le `ceil`).
- La marque doit être posée avant la file de sortie de `{dev}`, sur un hook que traverse le
  trafic routé : une chaîne `output` ne marque que les paquets émis par `r1` lui-même.
- Un marquage fait avec `iptables` n'est pas reproduit sur le miroir : l'évaluation affiche un
  avertissement, `prio_nft_marque` et `prio_mesure_marque` valent 0.
- Le `htb` (sortie de `{dev}`) et la qdisc `ingress` de la partie 5 (entrée de `{dev}`)
  cohabitent sur la même interface.

Évaluation : `prio_nft_marque` (2 points : une règle nftables pose la marque {mark} sur le
trafic de source `{netA}`, TCP ou tout protocole, dans une chaîne `prerouting`, `forward` ou
`postrouting` ; 1 point seulement sur un autre hook), `prio_htb_classes` (1 : la classe visée
par le filtre `fw` et la classe par défaut, distinctes, ont `rate {hi}mbit` et `rate {lo}mbit`,
`ceil {T}mbit`, à 3 % près), `prio_htb_priorites` (1 : `prio` de la classe du trafic marqué
inférieur à celui de la classe par défaut), `prio_fq_codel` (1 : une `fq_codel` sous chaque
classe feuille), `prio_filtre_fw` (1 : un filtre `fw` de `handle {mark}` vise une classe
feuille), puis, sur le miroir, `m1` et `m2` émettant ensemble vers `serveur1` :
`prio_mesure_marque` (2 : le flux de `m1` obtient entre 60 % et 110 % de {T} Mbit/s, le filtre
`fw` étant en place : sans aucune configuration, les deux flux se partagent le lien et celui de
`m1` tomberait par hasard dans cette fourchette) et
`prio_mesure_defaut` (1 : le flux de `m2` passe, sans dépasser 35 % de {T} Mbit/s, et le total
reste sous 115 %).
""": """
**Solution.** On `r1` (what the `final` state applies; it first deletes the `mangle` table and
the root qdisc already present, so that it can be replayed):

```
nft add table ip mangle
nft add chain ip mangle prerouting '{{ type filter hook prerouting priority mangle; }}'
nft add rule ip mangle prerouting ip saddr {netA} meta l4proto tcp meta mark set {mark}
tc qdisc add dev {dev} root handle 1: htb default 20
tc class add dev {dev} parent 1: classid 1:10 htb rate {hi}mbit ceil {T}mbit prio 0
tc class add dev {dev} parent 1: classid 1:20 htb rate {lo}mbit ceil {T}mbit prio 1
tc qdisc add dev {dev} parent 1:10 fq_codel
tc qdisc add dev {dev} parent 1:20 fq_codel
tc filter add dev {dev} parent 1: protocol ip handle {mark} fw flowid 1:10
```

- The mark is displayed in hexadecimal: `meta mark set 0x{mark:08x}` in `nft list ruleset`,
  `handle 0x{mark:x} classid 1:10` in `tc filter show dev {dev}`.
- Step 3: the flow of `m1`, marked, gets about {hi} Mbit/s and that of `m2` about
  {lo} Mbit/s; `tc -s class show dev {dev}` shows the first in `1:10`, the second in
  `1:20`. The two classes are attached directly to the root: they borrow nothing from each other
  and each stays limited to its `rate`, hence a total of at most {T} Mbit/s (a flow from `m1`
  alone tops out at {hi} Mbit/s, despite the `ceil`).
- The mark must be set before the egress queue of `{dev}`, on a hook that routed traffic goes
  through: an `output` chain only marks the packets sent by `r1` itself.
- A marking done with `iptables` is not reproduced on the mirror: the evaluation shows a
  warning, and `prio_nft_marque` and `prio_mesure_marque` are worth 0.
- The `htb` (egress of `{dev}`) and the `ingress` qdisc of part 5 (ingress of `{dev}`)
  coexist on the same interface.

Grading: `prio_nft_marque` (2 points: an nftables rule sets the mark {mark} on the traffic with
source `{netA}`, TCP or any protocol, in a `prerouting`, `forward` or `postrouting` chain; only
1 point on another hook), `prio_htb_classes` (1: the class targeted by the `fw` filter and the
default class, distinct, have `rate {hi}mbit` and `rate {lo}mbit`, `ceil {T}mbit`, within 3%),
`prio_htb_priorites` (1: the `prio` of the class of the marked traffic is lower than that of the
default class), `prio_fq_codel` (1: an `fq_codel` under each leaf class), `prio_filtre_fw` (1:
an `fw` filter with `handle {mark}` targets a leaf class), then, on the mirror, `m1` and `m2`
sending together to `serveur1`:
`prio_mesure_marque` (2: the flow of `m1` gets between 60% and 110% of {T} Mbit/s, the filter
`fw` being in place: without any configuration, the two flows share the link and that of
`m1` would fall into this range by chance) and
`prio_mesure_defaut` (1: the flow of `m2` gets through, without exceeding 35% of {T} Mbit/s, and
the total stays below 115%).
""",
    "Marquage": "Marking",
    """
- Pour marquer les paquets **routés** par `r1`, la chaîne nftables doit être accrochée au hook :
  @@{hook:>output|input|prerouting ou forward|postrouting uniquement}@@
""": """
- To mark the packets **routed** by `r1`, the nftables chain must be attached to the hook:
  @@{hook:>output|input|prerouting or forward>>>prerouting ou forward|postrouting only>>>postrouting uniquement}@@
""",
    """
**Solution.** **prerouting ou forward** : ce sont les hooks que traverse un paquet routé avant
d'atteindre la file de sortie. `input` ne voit que les paquets destinés au routeur et `output`
que ceux qu'il émet lui-même. `postrouting` voit aussi le trafic routé, et l'évaluation de la
configuration l'accepte, mais il n'est pas le seul hook possible : « postrouting uniquement »
est faux.

Évaluation : `prio_q_hook` (1 point, évaluation de l'enseignant seulement).
""": """
**Solution.** **prerouting or forward**: these are the hooks a routed packet goes through before
reaching the egress queue. `input` only sees the packets addressed to the router and `output`
only those it sends itself. `postrouting` also sees routed traffic, and the evaluation of the
configuration accepts it, but it is not the only possible hook: "postrouting only" is
wrong.

Grading: `prio_q_hook` (1 point, instructor's evaluation only).
""",
    "règle nftables : marque {mark} sur le trafic TCP de {netA} (hook du trafic routé)": "nftables rule: mark {mark} on the TCP traffic of {netA} (hook of routed traffic)",
    "htb sur r1 {dev} : classes {hi} / {lo} Mbit/s, ceil {T} Mbit/s": "htb on r1 {dev}: classes {hi} / {lo} Mbit/s, ceil {T} Mbit/s",
    "la classe du trafic marqué est plus prioritaire (prio) que la classe par défaut": "the class of the marked traffic has a higher priority (prio) than the default class",
    "filtre fw : marque {mark} vers la classe prioritaire": "fw filter: mark {mark} to the priority class",
    "miroir : le flux de m1 (marqué) obtient ≈ {hi} Mbit/s": "mirror: the flow of m1 (marked) gets ≈ {hi} Mbit/s",
    "miroir : le flux de m2 est limité ≈ {lo} Mbit/s, total ≤ {T} Mbit/s": "mirror: the flow of m2 is limited to ≈ {lo} Mbit/s, total ≤ {T} Mbit/s",
    "hook nftables du trafic routé": "nftables hook of routed traffic",
    "Partie 5 — Régulation du trafic entrant (ifb, cake)": "Part 5 — Shaping incoming traffic (ifb, cake)",
    "Ingress sur r1 depuis serveur1": "Ingress on r1 from serveur1",
    """
Le trafic **reçu** par `r1` sur **`{dev}`** (envoyé par `serveur1`) doit être limité à
**{C} Mbit/s**. Une qdisc ne régule qu'en sortie : redirigez le trafic entrant de `{dev}` vers
une interface **ifb** et régulez la sortie de celle-ci avec **cake** :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth {C}mbit
```

Testez depuis `m1` en sens *descendant* : `iperf3 -c serveur1 -R -t 15` (le serveur envoie).
Observez `tc -s qdisc show dev ifb0` sur `r1`.
""": """
The traffic **received** by `r1` on **`{dev}`** (sent by `serveur1`) must be limited to
**{C} Mbit/s**. A qdisc only shapes on egress: redirect the incoming traffic of `{dev}` to
an **ifb** interface and shape the egress of the latter with **cake**:

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc add dev ifb0 root cake bandwidth {C}mbit
```

Test from `m1` in the *download* direction: `iperf3 -c serveur1 -R -t 15` (the server sends).
Watch `tc -s qdisc show dev ifb0` on `r1`.
""",
    """
**Solution.** Sur `r1` : les commandes de l'énoncé. L'état `final` applique les mêmes, en
supprimant d'abord la qdisc `ingress` déjà présente et en posant `cake` avec `replace`, pour
pouvoir être rejoué :

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc replace dev ifb0 root cake bandwidth {C}mbit
```

- `iperf3 -c serveur1 -R -t 15` depuis `m1` : environ **{C} Mbit/s** au lieu de 45 à 50, et
  les compteurs de `tc -s qdisc show dev ifb0` avancent pendant le transfert. Sans `-R`, les
  données vont de `m1` vers `serveur1` : c'est le `htb` de la partie 4 qui agit, pas `cake`.
- `match u32 0 0` est vrai pour tout paquet : tout le trafic IPv4 reçu sur `{dev}` est redirigé.
- `ifb0` doit être active (`ip link set ifb0 up`) : un paquet redirigé vers une interface
  arrêtée est jeté, et plus rien n'arrive de `serveur1`.
- La qdisc `ingress` et le `htb` racine de la partie 4 cohabitent sur `{dev}` :
  `tc qdisc del dev {dev} root` ne retire que le `htb`, `tc qdisc del dev {dev} ingress` que la
  redirection.

Évaluation : `ingress_ifb` (1 point : une interface ifb existe et est active sur `r1`),
`ingress_qdisc` (1 : qdisc `ingress` ou `clsact` sur `{dev}`), `ingress_redirect` (1 : un filtre
d'entrée redirige, par `mirred`, vers une interface ifb), `ingress_cake` (1 : `cake` à la racine
de cette interface), `ingress_cake_debit` (1 : `bandwidth {C}mbit` à 3 % près) et
`ingress_mesure` (2 : sur le miroir, un `iperf3 -R` de `m1` vers `serveur1` donne entre 70 % et
110 % de {C} Mbit/s).
""": """
**Solution.** On `r1`: the commands of the statement. The `final` state applies the same ones,
first deleting the `ingress` qdisc already present and setting `cake` with `replace`, so that it
can be replayed:

```
ip link add ifb0 type ifb
ip link set ifb0 up
tc qdisc add dev {dev} handle ffff: ingress
tc filter add dev {dev} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
tc qdisc replace dev ifb0 root cake bandwidth {C}mbit
```

- `iperf3 -c serveur1 -R -t 15` from `m1`: about **{C} Mbit/s** instead of 45 to 50, and
  the counters of `tc -s qdisc show dev ifb0` advance during the transfer. Without `-R`, the
  data go from `m1` to `serveur1`: it is the `htb` of part 4 that acts, not `cake`.
- `match u32 0 0` is true for every packet: all the IPv4 traffic received on `{dev}` is redirected.
- `ifb0` must be active (`ip link set ifb0 up`): a packet redirected to an interface that is
  down is dropped, and nothing arrives from `serveur1` any more.
- The `ingress` qdisc and the root `htb` of part 4 coexist on `{dev}`:
  `tc qdisc del dev {dev} root` only removes the `htb`, `tc qdisc del dev {dev} ingress` only the
  redirection.

Grading: `ingress_ifb` (1 point: an ifb interface exists and is active on `r1`),
`ingress_qdisc` (1: an `ingress` or `clsact` qdisc on `{dev}`), `ingress_redirect` (1: an
ingress filter redirects, with `mirred`, to an ifb interface), `ingress_cake` (1: `cake` at the
root of that interface), `ingress_cake_debit` (1: `bandwidth {C}mbit` within 3%) and
`ingress_mesure` (2: on the mirror, an `iperf3 -R` from `m1` to `serveur1` gives between 70% and
110% of {C} Mbit/s).
""",
    "Pourquoi ifb ?": "Why ifb?",
    """
- Pourquoi faut-il passer par une interface ifb pour réguler le trafic entrant ?
  @@{ifb:>ifb accélère le traitement des paquets|en entrée le noyau ne peut que jeter (policing) : les files d'attente n'existent qu'en sortie|le noyau interdit tc sur une interface physique|cake exige une interface virtuelle}@@
""": """
- Why do you have to go through an ifb interface to shape incoming traffic?
  @@{ifb:>ifb speeds up packet processing>>>ifb accélère le traitement des paquets|on ingress the kernel can only drop (policing): queues exist only on egress>>>en entrée le noyau ne peut que jeter (policing) : les files d'attente n'existent qu'en sortie|the kernel forbids tc on a physical interface>>>le noyau interdit tc sur une interface physique|cake requires a virtual interface>>>cake exige une interface virtuelle}@@
""",
    """
**Solution.** « en entrée le noyau ne peut que jeter (policing) : les files d'attente
n'existent qu'en sortie ». Rediriger le trafic reçu vers `ifb0` le fait passer par la **sortie**
d'une interface, où une qdisc (`cake`) peut le retarder et le lisser. Les autres réponses sont
fausses : `tc` s'emploie sur une interface physique, `cake` n'exige pas d'interface virtuelle
et ifb n'accélère rien.

Évaluation : `ingress_q_ifb` (1 point, évaluation de l'enseignant seulement).
""": """
**Solution.** "on ingress the kernel can only drop (policing): queues exist only on
egress". Redirecting the received traffic to `ifb0` makes it go through the **egress**
of an interface, where a qdisc (`cake`) can delay and smooth it. The other answers are
wrong: `tc` can be used on a physical interface, `cake` does not require a virtual interface
and ifb speeds nothing up.

Grading: `ingress_q_ifb` (1 point, instructor's evaluation only).
""",
    "une interface ifb existe et est active sur r1": "an ifb interface exists and is active on r1",
    "qdisc ingress (ou clsact) sur r1 {dev}": "ingress (or clsact) qdisc on r1 {dev}",
    "filtre ingress : redirection (mirred) vers l'interface ifb": "ingress filter: redirection (mirred) to the ifb interface",
    "cake à la racine de l'interface ifb": "cake at the root of the ifb interface",
    "cake : bandwidth {C} Mbit/s": "cake: bandwidth {C} Mbit/s",
    "miroir : débit descendant depuis serveur1 ≈ {C} Mbit/s": "mirror: download rate from serveur1 ≈ {C} Mbit/s",
    "rôle de l'interface ifb": "role of the ifb interface",
}}
