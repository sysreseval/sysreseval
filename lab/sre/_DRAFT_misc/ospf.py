"""TP OSPF avec FRR (FRRouting).

Sept routeurs FRR, trois aires (0, 1 stub, 2), un préfixe externe redistribué.
r1 et r2 sont pré-configurés ; les étudiants configurent r3 à r7 puis modifient
coûts, priorités DR/BDR, aires, agrégation, redistribution, authentification et
temporisateurs.  L'état ``final`` applique la solution de référence.
"""
import random
from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
from typing import Dict

import utils
from SRE import params
from SRE.lib_sre import Data0, NetScheme0, Grade0, sre_state, make_tr, no_tr, instructor, info_subtitle, info_toc
from SRE.params import sre_docker_image
from ips import random_ipv4networks, random_ipv4s
from net_config import NetConfigEntry, set_net_config_entry, set_ip_forward
from ping import eval_ping
from frr import (
    get_ospf_interfaces, get_ospf_neighbors, neighbor_is_full, find_neighbor, get_ospf_info,
    get_ospf_routes, get_kernel_routes, kernel_route_gateways, get_frr_running_config,
    expected_auto_cost, is_ospf_protocol,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("OSPF : routage dynamique", en="OSPF: dynamic routing")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60
eval_before_exit = True
record_sessions = False

# Fixed "external" prefix announced by r1 (TEST-NET-3, never routed on the Internet).
EXT_PUBLIC = IPv4Network("203.0.113.0/24")
EXT_PUBLIC_HOST = IPv4Interface("203.0.113.1/24")

# Router ids the students must configure (r2 keeps the automatic one, see part 1).
ROUTER_IDS = {'r1': '1.1.1.1', 'r3': '3.3.3.3', 'r4': '4.4.4.4', 'r5': '5.5.5.5', 'r6': '6.6.6.6', 'r7': '7.7.7.7'}

# Router interfaces in ethN order: (network name, data.ips attribute).  Must match _topology.
ROUTER_IFACES = {
    'r1': [('net1', 'r1_net1'), ('core', 'r1_core'), ('l14', 'r1_l14'), ('ext', 'r1_ext')],
    'r2': [('core', 'r2_core'), ('l24', 'r2_l24')],
    'r3': [('core', 'r3_core'), ('l35', 'r3_l35')],
    'r4': [('net4', 'r4_net4'), ('l14', 'r4_l14'), ('l24', 'r4_l24'), ('l46', 'r4_l46')],
    'r5': [('net5', 'r5_net5'), ('l35', 'r5_l35')],
    'r6': [('net6', 'r6_net6'), ('l46', 'r6_l46'), ('l67', 'r6_l67')],
    'r7': [('net7', 'r7_net7'), ('l67', 'r7_l67')],
}
# Hosts: (router, data.ips attribute of the router interface on the host LAN)
HOST_ROUTER = {
    'm1': ('r1', 'r1_net1'),
    'm4': ('r4', 'r4_net4'),
    'm5': ('r5', 'r5_net5'),
    'm6': ('r6', 'r6_net6'),
    'm7': ('r7', 'r7_net7'),
}
AREA0_ROUTERS = ['r1', 'r2', 'r3', 'r4']
AREA_COLORS = {0: 'lightblue', 1: 'lightgreen', 2: 'lightyellow'}
NET_AREAS = {'net1': 0, 'core': 0, 'l14': 0, 'l24': 0, 'net4': 0, 'l35': 1, 'net5': 1,
             'l46': 2, 'l67': 2, 'net6': 2, 'net7': 2}
DEFAULT_REF_BANDWIDTH = 100000  # FRR default (Mbit/s): a 10 Gbit/s veth gets cost 10

FRR_DAEMONS = """# /etc/frr/daemons -- généré par le TP : seul ospfd est activé
# (zebra, staticd et watchfrr démarrent toujours)
bgpd=no
ospfd=yes
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
# A form answer picked from a short list is graded for the instructor only: shown in a
# self-evaluation, its grade would let a student try every choice. Typed answers count in both.
CHOICE_SCOPE = params.EXO_EVAL_SCOPE


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Data(Data0):
    cost_l14: int = 0        # part 3: cost imposed on both ends of l14 (> 2 * auto-cost of a veth)
    ref_bandwidth: int = 0   # part 3: auto-cost reference-bandwidth (Mbit/s)
    md5_key: str = ""        # part 8: MD5 key (<= 16 characters)
    hello_l24: int = 0       # part 9: hello interval on l24; dead = 4 * hello

    @classmethod
    def generate(cls):
        data = cls()
        data.cost_l14 = random.randint(250, 800)
        data.ref_bandwidth = random.choice([200000, 500000, 1000000])
        data.md5_key = utils.random_password(12)
        data.hello_l24 = random.randint(2, 5)

        (data.nets.net1, data.nets.core, data.nets.l14, data.nets.l24, data.nets.net4,
         data.nets.l35, data.nets.net5, data.nets.ext, area2_block) = random_ipv4networks(
            masks=[24, 24, 30, 30, 24, 30, 24, 30, 16],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16"), EXT_PUBLIC],
        )
        # Area 2 lives inside one /22 so that it can be summarised with `area 2 range`.
        data.nets.area2_block = area2_block
        data.nets.area2_range = random.choice(list(area2_block.subnets(new_prefix=22)))
        sub24 = list(data.nets.area2_range.subnets(new_prefix=24))
        data.nets.net6, data.nets.net7 = sub24[0], sub24[1]
        sub30 = list(sub24[2].subnets(new_prefix=30))
        data.nets.l46, data.nets.l67 = sub30[0], sub30[1]

        data.ips.r1_net1, data.ips.m1 = random_ipv4s(data.nets.net1, 2)
        data.ips.r1_core, data.ips.r2_core, data.ips.r3_core = random_ipv4s(data.nets.core, 3)
        data.ips.r1_l14, data.ips.r4_l14 = random_ipv4s(data.nets.l14, 2)
        data.ips.r2_l24, data.ips.r4_l24 = random_ipv4s(data.nets.l24, 2)
        data.ips.r4_net4, data.ips.m4 = random_ipv4s(data.nets.net4, 2)
        data.ips.r3_l35, data.ips.r5_l35 = random_ipv4s(data.nets.l35, 2)
        data.ips.r5_net5, data.ips.m5 = random_ipv4s(data.nets.net5, 2)
        data.ips.r4_l46, data.ips.r6_l46 = random_ipv4s(data.nets.l46, 2)
        data.ips.r6_l67, data.ips.r7_l67 = random_ipv4s(data.nets.l67, 2)
        data.ips.r6_net6, data.ips.m6 = random_ipv4s(data.nets.net6, 2)
        data.ips.r7_net7, data.ips.m7 = random_ipv4s(data.nets.net7, 2)
        data.ips.r1_ext, data.ips.isp_ext = random_ipv4s(data.nets.ext, 2)
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        'r1': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[0]},
        'r2': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[0]},
        'r3': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[0]},
        'r4': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[0]},
        'r5': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[1]},
        'r6': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[2]},
        'r7': {'image': sre_docker_image("netdev13"), 'color': AREA_COLORS[2]},
        'm1': {}, 'm4': {}, 'm5': {}, 'm6': {}, 'm7': {},
        'isp': {'hidden': True},
    }
    _network_specs = {
        **{net: {'color': AREA_COLORS[area]} for net, area in NET_AREAS.items()},
        'ext': {'color': 'lightgrey'},
    }
    # Interface numbers must follow ROUTER_IFACES (ethN = position in the list).
    _topology = {
        'net1': {'r1': 0, 'm1': 0},
        'core': {'r1': 1, 'r2': 0, 'r3': 0},
        'l14': {'r1': 2, 'r4': 1},
        'l24': {'r2': 1, 'r4': 2},
        'net4': {'r4': 0, 'm4': 0},
        'l35': {'r3': 1, 'r5': 1},
        'net5': {'r5': 0, 'm5': 0},
        'l46': {'r4': 3, 'r6': 1},
        'l67': {'r6': 2, 'r7': 1},
        'net6': {'r6': 0, 'm6': 0},
        'net7': {'r7': 0, 'm7': 0},
        'ext': {'r1': 3, 'isp': 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network("0.0.0.0/0")

        # Routers: addresses only, no static route (OSPF does the job; r1's external
        # routes are FRR static routes written in frr.conf, see _frr_conf()).
        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, ifaces in ROUTER_IFACES.items():
            self.net_config[r] = [([getattr(d.ips, attr)], []) for _net, attr in ifaces]
        for h, (_r, r_attr) in HOST_ROUTER.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(default, getattr(d.ips, r_attr).ip)])]
        self.net_config['isp'] = [([d.ips.isp_ext, EXT_PUBLIC_HOST], [(default, d.ips.r1_ext.ip)])]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX.
        lines = []
        for r, ifaces in ROUTER_IFACES.items():
            for i, (_net, attr) in enumerate(ifaces):
                ip = getattr(d.ips, attr).ip
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{ip}\t{names}")
        for h in HOST_ROUTER:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
        lines.append(f"{EXT_PUBLIC_HOST.ip}\tinternet")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Principe d'OSPF"), tag="principle")
            + tr("""
**OSPF** (*Open Shortest Path First* ; RFC 2328 pour la version 2, celle d'IPv4) est un protocole
de routage **dynamique** : les routeurs s'échangent la description du réseau, calculent eux-mêmes
leurs tables de routage et les recalculent quand un lien apparaît ou disparaît. C'est un protocole
**intérieur** (IGP), utilisé au sein d'un même domaine administratif, et un protocole à **état de
liens** (*link state*) :

- chaque routeur découvre ses **voisins** grâce à des paquets **Hello** envoyés périodiquement
  en multicast (`224.0.0.5`) ; OSPF est transporté directement dans IP (protocole numéro 89),
  sans TCP ni UDP ;
- chaque routeur décrit ses liens dans des **LSA** (*Link State Advertisements*) qui sont
  **inondés** (*flooding*) à tous les routeurs de l'aire ;
- tous les routeurs d'une aire possèdent donc la même **base de données** (LSDB) et calculent
  chacun, avec l'algorithme de **Dijkstra** (SPF), l'arbre des plus courts chemins vers toutes
  les destinations ;
- les meilleures routes sont installées dans la table de routage du noyau (`ip route`, où
  elles apparaissent avec `proto ospf` ; leur distance administrative est 110).

### @@sec:cost@@ Le coût des chemins

Le **coût** d'un chemin est la somme des coûts des interfaces *de sortie* traversées : il se
règle donc séparément dans chaque sens. Par défaut FRR calcule le coût d'une interface par
`coût = bande_passante_de_référence / bande_passante_de_l'interface` (arrondi, minimum 1). La
référence vaut 100 000 Mbit/s et une interface virtuelle d'un conteneur annonce 10 000 Mbit/s : le
coût par défaut y est donc **10**. On peut :

- fixer le coût d'une interface : `ip ospf cost N` (mode `interface ethX`) ; il l'emporte sur
  le coût calculé ;
- changer la référence : `auto-cost reference-bandwidth N` (mode `router ospf`, N en Mbit/s),
  à faire sur **tous** les routeurs du domaine pour que les coûts restent comparables ;
- déclarer la bande passante d'une interface : `bandwidth N` (mode `interface`, N en Mbit/s).

Lorsque plusieurs chemins ont le même coût, OSPF installe **tous** les prochains sauts
(*ECMP*, *Equal-Cost Multi-Path*) : la route apparaît avec plusieurs `nexthop` dans `ip route`.
""")
            + info_subtitle(tr("Voisinage et adjacences"), tag="neighbors")
            + tr("""
Deux routeurs deviennent voisins si leurs Hello sont compatibles : même **aire**, même
**intervalle Hello**, même **intervalle Dead**, même type de réseau, même type d'aire (stub ou
non), même authentification, même préfixe sur le lien. La relation passe par les états `Down`,
`Init` (j'entends le voisin), `2-Way` (il m'entend aussi), `ExStart`, `Exchange`, `Loading`
(échange des bases) et enfin **`Full`** (bases synchronisées).

### @@sec:dr@@ DR et BDR

Sur un réseau à diffusion (Ethernet) les routeurs élisent un **DR** (*Designated Router*)
et un **BDR** (*Backup DR*) ; les autres routeurs (`DROther`) ne forment une adjacence
complète qu'avec le DR et le BDR (ils restent en `2-Way` entre eux), ce qui limite le nombre
d'adjacences et le trafic d'inondation. Le DR décrit le réseau dans un LSA de type 2 ; les
`DROther` lui écrivent à l'adresse `224.0.0.6`. L'élection se fait sur la **priorité**
(`ip ospf priority N` en mode interface, 1 par défaut, 0 = jamais DR ni BDR) puis, à priorité
égale, sur le **router-id** le plus grand. Elle **n'est pas préemptive** : un routeur qui arrive
avec une meilleure priorité ne détrône pas le DR en place ; il faut relancer le processus
(`clear ip ospf process`) sur les routeurs qui tiennent les rôles pour provoquer une nouvelle
élection. Un routeur qui démarre attend la durée de l'intervalle Dead (*Wait timer*) avant de
se déclarer DR ou BDR.

### @@sec:router-id@@ Le router-id

Le **router-id** identifie le routeur dans la base de données ; il s'écrit comme une adresse
IPv4 mais n'en est pas une. S'il n'est pas configuré (`ospf router-id A.B.C.D`, mode
`router ospf`), FRR prend la plus grande adresse IP des interfaces du routeur au démarrage. Si
des adjacences sont déjà établies, un changement de router-id n'est appliqué qu'après
`clear ip ospf process` : mieux vaut le fixer avant les commandes `network`.

### @@sec:timers@@ Temporisateurs et convergence

Un routeur envoie un Hello sur chaque interface toutes les **10 s** (*intervalle Hello*) et
déclare un voisin mort s'il n'en a rien reçu pendant **40 s** (*intervalle Dead*, quatre Hello
par défaut). Ils se règlent par interface (`ip ospf hello-interval N`, `ip ospf dead-interval N`)
et doivent être **identiques aux deux extrémités** : sinon les Hello du voisin sont ignorés et
l'adjacence tombe à l'expiration de l'intervalle Dead.

Le temps de **convergence** après une panne dépend de la façon dont elle est détectée :

- **coupure franche** (l'interface passe à l'état *down*) : le routeur le sait immédiatement,
  inonde un nouveau LSA et tous recalculent leurs routes — une à deux secondes ;
- **panne silencieuse** (l'interface reste *up* mais le voisin ne répond plus : switch
  intermédiaire, filtre, processus bloqué) : seule l'absence de Hello la révèle, au bout de
  l'intervalle Dead.

Réduire les temporisateurs accélère la détection au prix de plus de trafic et de fausses
alertes sur un lien chargé ; les réseaux qui visent une détection en moins d'une seconde
utilisent BFD (*Bidirectional Forwarding Detection*).

### @@sec:auth@@ Authentification

Sans authentification, n'importe quelle machine branchée sur un lien peut se faire passer pour
un routeur et injecter des LSA. OSPFv2 prévoit trois modes : aucun (par défaut), mot de passe
en clair, et **MD5** : chaque paquet porte un condensat calculé avec une clé partagée (les
paquets sont signés, pas chiffrés). En mode interface :

```
ip ospf authentication message-digest          # mode MD5 sur cette interface
ip ospf message-digest-key 1 md5 SECRET        # clé numéro 1 (16 caractères au plus)
```

Le numéro de clé et la clé doivent être les mêmes aux deux extrémités ; `area N authentication
message-digest` (mode `router ospf`) active le mode MD5 sur toutes les interfaces d'une aire,
les clés restant à définir par interface. Un paquet mal authentifié est ignoré : l'adjacence
tombe à l'expiration de l'intervalle Dead et le journal de FRR signale l'erreur. MD5 est
aujourd'hui considéré comme faible ; la RFC 5709 le remplace par HMAC-SHA.
""")
            + info_subtitle(tr("Aires et types de routes"), tag="areas")
            + tr("""
Pour limiter la taille des bases de données et le nombre de calculs SPF, un domaine OSPF
est découpé en **aires**. L'aire **0** (`0.0.0.0`) est le **backbone** ; toute autre aire
doit lui être directement rattachée par au moins un **ABR** (*Area Border Router*), qui
possède des interfaces dans les deux aires et **résume** les réseaux d'une aire vers l'autre.
Une interface appartient à une seule aire (`network PREFIXE area N` en mode `router ospf`, ou
`ip ospf area N` en mode interface) ; les deux extrémités d'un lien sont dans la même aire.

| LSA | nom | émis par | portée |
|-----|-----|----------|--------|
| type 1 | *Router* | chaque routeur : ses liens et leurs coûts | son aire |
| type 2 | *Network* | le DR d'un réseau à diffusion : les routeurs du réseau | son aire |
| type 3 | *Summary* | un ABR : un préfixe d'une autre aire | une aire |
| type 4 | *ASBR Summary* | un ABR : où se trouve un ASBR d'une autre aire | une aire |
| type 5 | *AS External* | un ASBR : un préfixe extérieur au domaine | tout le domaine, hors aires stub |

Les routes calculées se classent en quatre types, par ordre de préférence :

| type | `show ip ospf route` (FRR) | notation usuelle | signification |
|------|----------------------------|------------------|---------------|
| intra-aire | `N` | `O` | réseau de l'une des aires du routeur |
| inter-aire | `N IA` | `O IA` | réseau d'une autre aire, résumé par un ABR |
| externe de type 1 | `N E1` | `O E1` | métrique = coût externe + coût interne jusqu'à l'ASBR |
| externe de type 2 | `N E2` | `O E2` | métrique = coût externe seul, quel que soit l'éloignement de l'ASBR |

`show ip route` (la table de zebra) marque toutes ces routes d'un simple `O`, suivi de
`[110/métrique]`.

### @@sec:range@@ Agrégation

Un ABR peut **agréger** les préfixes d'une aire : `area N range PREFIXE` (mode `router ospf`)
remplace, dans ce qu'il annonce aux autres aires, tous les réseaux de l'aire N contenus dans
PREFIXE par ce seul préfixe. Les tables des autres aires sont plus courtes et une instabilité
à l'intérieur de l'aire N ne s'y propage plus. Le plan d'adressage doit s'y prêter : des
réseaux contigus, contenus dans un préfixe qui ne couvre rien d'autre.

### @@sec:external@@ Routes externes

Un **ASBR** (*AS Boundary Router*) injecte dans OSPF des routes venues d'ailleurs (routes
statiques, réseaux connectés hors OSPF, autre protocole) sous forme de LSA de type 5 :

```
router ospf
 redistribute static                 # les routes statiques de FRR (« ip route … » dans vtysh)
 redistribute connected              # les réseaux connectés qui ne sont pas dans OSPF
 default-information originate       # annonce la route par défaut que possède le routeur
```

Les routes redistribuées sont de type **E2** avec une métrique de 20 par défaut
(`redistribute static metric N metric-type 1` pour les changer). `redistribute static` ne
concerne que les routes statiques déclarées dans FRR : une route ajoutée par `ip route add`
est une route du noyau (`redistribute kernel`).

### @@sec:stub@@ Aires stub

Une aire **stub** (`area N stub` sur **tous** ses routeurs : c'est un champ des Hello, deux
voisins en désaccord ne forment pas d'adjacence) ne reçoit pas les routes externes : l'ABR y
injecte à la place une route par défaut inter-aire. Une aire ***totally stubby***
(`area N stub no-summary`, sur l'ABR seulement) ne reçoit même plus les routes inter-aires :
ses routeurs ne connaissent que leur aire et la route par défaut. Une aire stub ne peut pas
contenir d'ASBR ni être le backbone.
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` (l'interface avec
le noyau : il y installe les routes choisies), `staticd` (les routes statiques) et un démon par
protocole, ici `ospfd` (`systemctl status frr` ; les démons lancés sont choisis dans
`/etc/frr/daemons`). On les configure avec le shell **`vtysh`**, dont la syntaxe est proche de
celle des équipements Cisco :

```
vtysh                              # ouvre le shell (prompt : routeur#)
show running-config                # configuration courante
configure terminal                 # passe en mode configuration (prompt : routeur(config)#)
 router ospf                       #   processus OSPF (prompt : routeur(config-router)#)
  ospf router-id 192.0.2.1
  network 198.51.100.0/24 area 0   #   active OSPF sur les interfaces de ce réseau, dans l'aire 0
  passive-interface eth0           #   n'envoie pas de Hello sur eth0 (mais annonce son réseau)
  exit
 interface eth1                    #   paramètres d'une interface (prompt : routeur(config-if)#)
  ip ospf cost 50
  exit
 end                               # retour au mode privilégié
write                              # sauvegarde dans /etc/frr/frr.conf
```

On supprime une ligne de configuration en la préfixant par `no` (`no network … area 0`).
Une commande peut aussi être passée directement depuis le shell Linux :
`vtysh -c "show ip ospf neighbor"`. Une interface **passive** est annoncée dans OSPF mais
n'émet aucun Hello : c'est le réglage d'un réseau d'hôtes, où aucun routeur n'est attendu
(`show running-config` l'écrit `ip ospf passive` sous l'interface).

Commandes d'observation utiles :

```
show ip ospf                       # router-id, aires, rôle ABR/ASBR
show ip ospf interface [ethX]      # aire, coût, état DR/BDR/DROther, temporisateurs, voisins
show ip ospf neighbor              # voisins et état de la relation
show ip ospf database              # base de données des LSA
show ip ospf route                 # table de routage calculée par OSPF (N, N IA, N E1, N E2)
show ip route                      # table de routage complète (vue de zebra)
clear ip ospf process              # redémarre le processus OSPF (mode privilégié)
```

Documentation : [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html) et
[vtysh](https://docs.frrouting.org/en/latest/vtysh.html).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `ip route` sur un routeur ou un hôte : les routes apprises par OSPF portent `proto ospf` ;
- `traceroute -n IP` depuis un hôte : chemin réellement suivi ;
- `tcpdump -ni ethX ip proto 89` : observation des paquets OSPF (un Hello par intervalle) ;
- `/var/log/frr/frr.log` : journal des démons FRR.

| symptôme | causes à vérifier |
|----------|-------------------|
| aucun voisin sur un lien | OSPF pas activé sur l'interface (`network`), interface passive, aires différentes, temporisateurs ou authentification différents, aire stub d'un seul côté |
| voisin bloqué en `Init` | il ne reçoit pas nos Hello (filtre, authentification) |
| voisin en `2-Way` | normal entre deux `DROther` d'un réseau à diffusion |
| voisin bloqué en `ExStart` / `Exchange` | MTU différentes aux deux extrémités |
| voisins `Full` mais route absente | réseau non annoncé (`network`), agrégation, aire stub, route non redistribuée |
| le DR n'est pas celui attendu | élection non préemptive : `clear ip ospf process` sur le DR et le BDR en place |
""")
        )

    # -- FRR configuration files -------------------------------------------------

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf: OSPF already running on r1 and r2, empty elsewhere."""
        d = self.data
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "log file /var/log/frr/frr.log", "!"]
        if router == 'r1':
            lines += [
                f"ip route {EXT_PUBLIC} {d.ips.isp_ext.ip}",
                f"ip route 0.0.0.0/0 {d.ips.isp_ext.ip}",
                "!",
                "router ospf",
                f" ospf router-id {ROUTER_IDS['r1']}",
                f" network {d.nets.net1} area 0",
                f" network {d.nets.core} area 0",
                f" network {d.nets.l14} area 0",
                " passive-interface eth0",
                "exit",
                "!",
            ]
        elif router == 'r2':
            lines += [
                "router ospf",
                f" network {d.nets.core} area 0",
                f" network {d.nets.l24} area 0",
                "exit",
                "!",
            ]
        return "\n".join(lines) + "\n"

    def _vtysh(self, machine: str, *cmds: str, step: int = 1):
        """Register a vtysh configuration session: configure terminal, cmds..., end, write."""
        args = " ".join(f'-c "{c}"' for c in ("configure terminal", *cmds, "end", "write"))
        self.cmd(machine, f"vtysh {args}", step=step)

    # -- states ------------------------------------------------------------------

    @sre_state(user_allowed=False)
    def initial(self):
        for m, nc in self.net_config.items():
            set_net_config_entry(net_scheme=self, machine_name=m, nc_entry=nc)
        for m in self.get_machine_names():
            # Kathara starts every container with ip_forward=1: routers only.
            set_ip_forward(net_scheme=self, machine_name=m, ip_forward=(m in ROUTER_IFACES))
            self.file(m, "/etc/hosts", f"127.0.0.1\tlocalhost\n127.0.1.1\t{m}\n" + self.hosts_content)

        for r in ROUTER_IFACES:
            self.file(r, "/etc/frr/daemons", FRR_DAEMONS, permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution: every grade element reaches its maximum once adjacencies
        are up (allow ~90 s after applying the state before running an evaluation).

        Step 1 configures r3..r7 and modifies r1/r2 (costs, auto-cost, priorities, MD5,
        timers, redistribution, stub, range); step 2 restarts the OSPF process on r1 and
        r2 so that r3 (priority 100) becomes DR and r1 (priority 50) BDR of `core`.
        Form questions are filled through cheat_answers.
        """
        d = self.data
        ref = d.ref_bandwidth
        hello, dead = d.hello_l24, 4 * d.hello_l24

        # r1: cost + MD5 on l14 (eth2), priority 50 on core (eth1), auto-cost, ASBR
        self._vtysh('r1',
                    "interface eth2",
                    f"ip ospf cost {d.cost_l14}",
                    "ip ospf authentication message-digest",
                    f"ip ospf message-digest-key 1 md5 {d.md5_key}",
                    "exit",
                    "interface eth1",
                    "ip ospf priority 50",
                    "exit",
                    "router ospf",
                    f"auto-cost reference-bandwidth {ref}",
                    "redistribute static",
                    "default-information originate",
                    "exit")
        # r2: priority 0 on core (eth0), timers on l24 (eth1), auto-cost
        self._vtysh('r2',
                    "interface eth0",
                    "ip ospf priority 0",
                    "exit",
                    "interface eth1",
                    f"ip ospf hello-interval {hello}",
                    f"ip ospf dead-interval {dead}",
                    "exit",
                    "router ospf",
                    f"auto-cost reference-bandwidth {ref}",
                    "exit")
        # r3: core in area 0 (priority 100, bandwidth 1000), l35 in area 1 (totally stubby ABR)
        self._vtysh('r3',
                    "interface eth0",
                    "ip ospf priority 100",
                    "bandwidth 1000",
                    "exit",
                    "router ospf",
                    f"ospf router-id {ROUTER_IDS['r3']}",
                    f"auto-cost reference-bandwidth {ref}",
                    f"network {d.nets.core} area 0",
                    f"network {d.nets.l35} area 1",
                    "area 1 stub no-summary",
                    "exit")
        # r4: area 0 (net4 passive, l14 with cost + MD5, l24 with timers), l46 in area 2, range
        self._vtysh('r4',
                    "interface eth1",
                    f"ip ospf cost {d.cost_l14}",
                    "ip ospf authentication message-digest",
                    f"ip ospf message-digest-key 1 md5 {d.md5_key}",
                    "exit",
                    "interface eth2",
                    f"ip ospf hello-interval {hello}",
                    f"ip ospf dead-interval {dead}",
                    "exit",
                    "router ospf",
                    f"ospf router-id {ROUTER_IDS['r4']}",
                    f"auto-cost reference-bandwidth {ref}",
                    "passive-interface eth0",
                    f"network {d.nets.net4} area 0",
                    f"network {d.nets.l14} area 0",
                    f"network {d.nets.l24} area 0",
                    f"network {d.nets.l46} area 2",
                    f"area 2 range {d.nets.area2_range}",
                    "exit")
        # r5: stub area 1
        self._vtysh('r5',
                    "router ospf",
                    f"ospf router-id {ROUTER_IDS['r5']}",
                    f"auto-cost reference-bandwidth {ref}",
                    "passive-interface eth0",
                    f"network {d.nets.net5} area 1",
                    f"network {d.nets.l35} area 1",
                    "area 1 stub",
                    "exit")
        # r6, r7: area 2
        self._vtysh('r6',
                    "router ospf",
                    f"ospf router-id {ROUTER_IDS['r6']}",
                    f"auto-cost reference-bandwidth {ref}",
                    "passive-interface eth0",
                    f"network {d.nets.net6} area 2",
                    f"network {d.nets.l46} area 2",
                    f"network {d.nets.l67} area 2",
                    "exit")
        self._vtysh('r7',
                    "router ospf",
                    f"ospf router-id {ROUTER_IDS['r7']}",
                    f"auto-cost reference-bandwidth {ref}",
                    "passive-interface eth0",
                    f"network {d.nets.net7} area 2",
                    f"network {d.nets.l67} area 2",
                    "exit")
        # DR/BDR re-election on core: the current DR/BDR (r1, r2) must restart.
        for r in ('r1', 'r2'):
            self.cmd(r, 'vtysh -c "clear ip ospf process"', step=2)


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
        ip = {attr: getattr(d.ips, attr).ip for ifaces in ROUTER_IFACES.values() for _n, attr in ifaces}

        # ---------------- diagnostics kept in the archive -------------------------
        for r in routers:
            for c in ('vtysh -c "show ip ospf database"', 'vtysh -c "show ip route"'):
                self.test(r, c, allow_error=True)

        # ---------------- live state of every router ------------------------------
        info = {r: get_ospf_info(self, r, allow_error=True) for r in routers}
        ifaces = {r: get_ospf_interfaces(self, r, allow_error=True) for r in routers}
        neigh = {r: get_ospf_neighbors(self, r, allow_error=True) for r in routers}
        conf = {r: get_frr_running_config(self, r, allow_error=True) for r in routers}
        kroutes = {r: get_kernel_routes(self, r, allow_error=True) for r in routers}
        oroutes = {r: get_ospf_routes(self, r, allow_error=True) for r in routers}
        rid = {r: info[r].get('router_id') for r in routers}

        def iface(r: str, n: int) -> dict:
            return ifaces[r].get(f'eth{n}') or {}

        def full_with(r: str, other: str, interface: str = None) -> bool:
            """True when r sees `other` (by its live router-id) in state Full."""
            if not rid.get(other):
                return False
            return neighbor_is_full(neigh[r], neighbor_id=rid[other], interface=interface)

        def ping(src: str, dest) -> bool:
            return eval_ping(self, src=src, dest=dest, count=3, deadline=5, allow_error=True)

        def ospf_conf(r: str) -> dict:
            return conf[r].get('router_ospf') or {}

        def if_conf(r: str, n: int) -> dict:
            return (conf[r].get('interfaces') or {}).get(f'eth{n}') or {}

        def has_ospf_route(r: str, prefix) -> bool:
            entry = kroutes[r].get(str(prefix))
            return entry is not None and is_ospf_protocol(entry['protocol'])

        # ---------------- texts shared by the questions ---------------------------
        # addressing plan: one row per network, with the interfaces (and hosts) on it
        members = {net: [] for net in list(NET_AREAS) + ['ext']}
        for r, r_ifaces in ROUTER_IFACES.items():
            for n, (net, attr) in enumerate(r_ifaces):
                members[net].append(f"`{r}` eth{n} (`{getattr(d.ips, attr).ip}`)")
        for h, (_r, r_attr) in HOST_ROUTER.items():
            members[r_attr.split('_', 1)[1]].append(f"`{h}` (`{getattr(d.ips, h).ip}`)")
        addressing = "\n".join(
            f"| `{net}` | `{getattr(d.nets, net)}` | {NET_AREAS.get(net, '—')} | {', '.join(members[net])} |"
            for net in members)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="f5dc919e16f348fa",
            description=tr("""
Lisez l'onglet **Informations** : il présente OSPF (état de liens, coûts, voisinage, DR et BDR,
aires, routes externes, authentification, temporisateurs), la configuration de FRR avec `vtysh`
et les commandes de diagnostic.

**Le réseau.** Ce TP met en œuvre OSPF avec la suite logicielle **FRRouting** (FRR), installée
et démarrée sur les sept routeurs `r1` à `r7`. Les machines `m1`, `m4`, `m5`, `m6` et `m7` sont
de simples hôtes dont la route par défaut pointe vers leur routeur. Le domaine sera découpé en
trois aires, repérées par les couleurs du schéma : l'aire 0 en bleu (`r1` à `r4`), l'aire 1 en
vert (`r5`) et l'aire 2 en jaune (`r6` et `r7`) ; `r3` et `r4` seront à cheval sur deux aires.

- **Au départ**, `r1` et `r2` sont déjà configurés (aire 0). Les routeurs `r3` à `r7` ont FRR
  démarré mais **aucune configuration OSPF** : c'est vous qui les configurez.
- Les fichiers `/etc/hosts` contiennent les noms de toutes les interfaces : `r4-eth2` désigne
  l'adresse de l'interface `eth2` de `r4`, `r4` (tout court) celle de `eth0` ; `traceroute`
  (sans `-n`) affiche ces noms.
- L'adresse `{ext_host}` (nom `internet`) est un serveur situé « à l'extérieur », derrière `r1`
  (réseau `ext`, qui ne fait pas partie du domaine OSPF).

**Plan d'adressage.**

| réseau | préfixe | aire | interfaces |
|--------|---------|------|------------|
{addressing}

**Consignes.**

- Les parties sont à faire **dans l'ordre** : chaque partie s'appuie sur la configuration
  réalisée dans les précédentes, qui reste en place.
- Pour chaque routeur que vous configurez, utilisez le router-id **`X.X.X.X`** pour `rX` (par
  exemple `3.3.3.3` pour `r3`), à définir **avant** les commandes `network`.
- Sauvegardez régulièrement la configuration des routeurs (`write` dans vtysh) : elle est
  conservée dans `/etc/frr/frr.conf`.

**Plan du TP.**

1. **Découverte** d'OSPF sur `r1` et `r2`, déjà configurés ;
2. **Aire 0** : configuration de `r3` et `r4`, chemins de coût égal ;
3. **Coûts** : coût d'une interface, bande passante de référence, choix des chemins ;
4. **DR et BDR** : élection sur le réseau `core` ;
5. **Aire 2** (`r6`, `r7`) et **agrégation** de ses préfixes ;
6. **Routes externes** : `r1` devient ASBR ;
7. **Aire stub** : l'aire 1 (`r5`) ;
8. **Authentification** MD5 d'un lien ;
9. **Temporisateurs** et temps de convergence.

**Évaluation.** Chaque évaluation lit vos réponses et l'état des routeurs (voisinages, tables
de routage, configuration) et lance des `ping` entre les hôtes. Les valeurs numériques demandées
(coûts, clé, temporisateurs) sont propres à votre instance du TP. Une adjacence met jusqu'à une
minute à s'établir, l'élection d'un DR une minute et demie : attendez que les voisins soient
`Full` avant de lancer une évaluation.
""").format(ext_host=EXT_PUBLIC_HOST.ip, addressing=addressing)
            + instructor(tr("""
**Pour l'enseignant.** Valeurs de cette instance : coût imposé sur `l14` **{cost}** ; bande
passante de référence **{ref} Mbit/s** (coût d'une interface à 10 Gbit/s : {auto_cost}) ; clé MD5
`{key}` ; Hello / Dead sur `l24` : **{hello} s / {dead} s** ; préfixe agrégé de l'aire 2 :
`{range}` ; router-id automatique de `r2` : `{rid_r2}`. Chaque question se termine par sa solution
pour ces valeurs.

L'état `final` (onglet *Appliquer une configuration*) applique toute la solution — configuration
de `r3` à `r7`, modifications de `r1` et `r2`, puis `clear ip ospf process` sur `r1` et `r2` pour
l'élection du DR — et remplit les formulaires. Attendez environ 90 s après l'avoir appliqué avant
de lancer une évaluation : le temps que les adjacences soient de nouveau `Full`.
""").format(cost=d.cost_l14, ref=d.ref_bandwidth, auto_cost=expected_auto_cost(d.ref_bandwidth, 10000),
            key=d.md5_key, hello=d.hello_l24, dead=4 * d.hello_l24, range=d.nets.area2_range,
            rid_r2=max(d.ips.r2_core.ip, d.ips.r2_l24.ip))),
        )

        # =====================================================================
        # Partie 1 — Découverte
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Découverte d'OSPF sur r1 et r2"))
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Découverte d'OSPF sur r1 et r2"),
            hash="a6aeee4720f0c58d",
            description=tr("""
Sur `r1` et `r2`, ouvrez `vtysh` et explorez la configuration en place (`show running-config`)
ainsi que les commandes `show ip ospf`, `show ip ospf interface`, `show ip ospf neighbor` et
`show ip ospf database`. Vérifiez depuis `m1` que vous ne joignez aucune autre machine `mX`
pour l'instant.

- router-id de `r2` (aucun n'est configuré : d'où vient cette valeur ?) : @@{rid_r2:[0-9.]+}@@
- coût OSPF de l'interface `eth1` de `r1` : @@{cost:[0-9]+}@@
- intervalle **Hello** en secondes : @@{hello:[0-9]+}@@  et intervalle **Dead** : @@{dead:[0-9]+}@@
- état de la relation entre `r1` et `r2` : @@{state:>Down|Init|2-Way|ExStart|Exchange|Loading|Full}@@
- adresse multicast de destination des paquets Hello (à observer avec `tcpdump`) :
  @@{mcast:>224.0.0.5|224.0.0.6|224.0.0.9|255.255.255.255}@@
  et numéro de protocole IP utilisé par OSPF : @@{proto:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer : `vtysh -c "show ip ospf neighbor"` et
`vtysh -c "show ip ospf interface eth1"` sur `r1`, `tcpdump -ni eth1 ip proto 89` pour les Hello.

- router-id de `r2` : **`{rid_r2}`**, la plus grande adresse IP de ses interfaces au démarrage
  de FRR (aucun `ospf router-id` dans sa configuration ; `r1` a `1.1.1.1`, configuré) ;
- coût de `eth1` de `r1` : **10** (référence 100 000 Mbit/s ÷ 10 000 Mbit/s annoncés par
  l'interface) ;
- Hello **10** s, Dead **40** s ;
- état **Full** : sur `core`, `r2` est DR (plus grand router-id) et `r1` BDR ;
- Hello envoyés à **224.0.0.5** (tous les routeurs OSPF ; `224.0.0.6` est l'adresse du DR et du
  BDR), protocole IP **89**.

`m1` ne joint aucune autre machine `mX` : leurs routeurs n'annoncent encore rien, `r1` ne connaît
que `net1`, `core`, `l14` et `l24`.

Évaluation : `decouverte_router_id_r2` (1 point : la réponse est comparée au router-id lu sur
`r2`), `decouverte_cout_defaut` (1), `decouverte_timers` (1), `decouverte_multicast_proto_typed`
(0,5 : protocole 89), et, pour l'évaluation de l'enseignant seulement (choix dans une liste),
`decouverte_etat_voisin` (1) et `decouverte_multicast_proto` (0,5 : adresse 224.0.0.5).
""").format(rid_r2=max(d.ips.r2_core.ip, d.ips.r2_l24.ip))),
            cheat_answers={"final": {
                "rid_r2": str(max(d.ips.r2_core.ip, d.ips.r2_l24.ip)),
                "cost": "10", "hello": "10", "dead": "40", "state": "Full",
                "mcast": "224.0.0.5", "proto": "89",
            }},
        )
        self.add_grade_element(
            title=no_tr("decouverte_router_id_r2"), max_grade=1, grade_part=part1,
            grade=int(bool(rid['r2']) and _norm(q1.get("rid_r2")) == rid['r2']),
            description=tr("router-id de r2"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_cout_defaut"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("cost")) == 10),
            description=tr("coût par défaut d'une interface"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_timers"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("hello")) == 10 and _int(q1.get("dead")) == 40),
            description=tr("intervalles Hello et Dead par défaut"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_etat_voisin"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("state")) == "full"), scope=CHOICE_SCOPE,
            description=tr("état de la relation r1–r2"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_multicast_proto_typed"), max_grade=0.5, grade_part=part1,
            grade=0.5 * int(_int(q1.get("proto")) == 89),
            description=tr("numéro de protocole d'OSPF"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_multicast_proto"), max_grade=0.5, grade_part=part1,
            grade=0.5 * int(_norm(q1.get("mcast")) == "224.0.0.5"),
            scope=CHOICE_SCOPE,
            description=tr("adresse multicast d'OSPF"),
        )

        # =====================================================================
        # Partie 2 — Aire 0 : r3 et r4
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — Aire 0 : configuration de r3 et r4"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Aire 0 : configuration de r3 et r4"),
            hash="2a2d6cc852a156d9",
            description=tr("""
Configurez OSPF dans l'aire 0 sur les routeurs `r3` et `r4` :

- `r3` : router-id `3.3.3.3`, interface `eth0` (réseau `core` `{core}`) ;
- `r4` : router-id `4.4.4.4`, interfaces `eth0` (réseau `net4` `{net4}`), `eth1` (lien vers
  `r1`, `{l14}`) et `eth2` (lien vers `r2`, `{l24}`). L'interface `eth0` mène à un réseau
  d'hôtes sans routeur : déclarez-la **passive** (le réseau est annoncé mais aucun Hello n'y
  est envoyé). Ne touchez pas encore à `eth3`.

Vérifiez que `r3` et `r4` ont bien des voisins en état `Full`, que `m1` et `m4` se joignent
(`ping`, `traceroute`) et observez la table de routage de `r3` (`ip route`, `show ip ospf route`).
""").format(core=d.nets.core, net4=d.nets.net4, l14=d.nets.l14, l24=d.nets.l24)
            + instructor(tr("""
**Solution.** Dans `vtysh`, après `configure terminal` (puis `end` et `write`) :

```
! r3
router ospf
 ospf router-id {rid_r3}
 network {core} area 0
!
! r4
router ospf
 ospf router-id {rid_r4}
 passive-interface eth0
 network {net4} area 0
 network {l14} area 0
 network {l24} area 0
```

- `show ip ospf neighbor` sur `r3` : `r1` et `r2` en `Full` (le DR et le BDR de `core` ; `r3`,
  arrivé après l'élection, est `DROther`) ; sur `r4` : `r1` par `eth1` et `r2` par `eth2`.
- `show running-config` réécrit `passive-interface eth0` en `ip ospf passive` sous
  `interface eth0` ; `show ip ospf interface eth0` affiche *No Hellos (Passive interface)*.
- Le router-id est donné avant les `network` : défini après, il ne serait pris en compte
  qu'après `clear ip ospf process`.

Évaluation : `aire0_r3_voisins` (2 points : `r3` voit `r1` et `r2` en `Full`), `aire0_r4_voisins`
(2 : `r4` voit `r1` par `eth1` et `r2` par `eth2`), `aire0_router_ids` (1), `aire0_r4_eth0_passive`
(1 : `eth0` de `r4` est dans OSPF et passive), `aire0_pings_m1_m4` (2 : `ping` dans les deux sens).
""").format(core=d.nets.core, net4=d.nets.net4, l14=d.nets.l14, l24=d.nets.l24,
            rid_r3=ROUTER_IDS['r3'], rid_r4=ROUTER_IDS['r4'])),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Chemins de coût égal"),
            hash="4135f90aa442f3dc",
            description=tr("""
Sur `r3`, combien la route vers le réseau `net4` (`{net4}`) possède-t-elle de prochains sauts
(*nexthop*) ? Expliquez-le à partir des coûts des chemins possibles : @@{{nexthops:[0-9]+}}@@
""").format(net4=d.nets.net4)
            + instructor(tr("""
**Solution.** **2** prochains sauts : `ip route show {net4}` sur `r3` affiche deux `nexthop`,
`{r1_core}` (`r1`) et `{r2_core}` (`r2`). Les deux chemins ont le même coût, 30 : sortie de `r3`
par `core` (10), puis `r1` → `l14` (10) ou `r2` → `l24` (10), puis `r4` → `net4` (10). À coût
égal, OSPF installe tous les prochains sauts (ECMP).

Évaluation : `aire0_ecmp_r3` (1 point).
""").format(net4=d.nets.net4, r1_core=ip['r1_core'], r2_core=ip['r2_core'])),
            cheat_answers={"final": {"nexthops": "2"}},
        )
        r3_full = full_with('r3', 'r1') and full_with('r3', 'r2')
        r4_full = full_with('r4', 'r1', interface='eth1') and full_with('r4', 'r2', interface='eth2')
        self.add_grade_element(
            title=no_tr("aire0_r3_voisins"), max_grade=2, grade_part=part2, grade=2 * int(r3_full),
            description=tr("r3 est en état Full avec r1 et r2"),
        )
        self.add_grade_element(
            title=no_tr("aire0_r4_voisins"), max_grade=2, grade_part=part2, grade=2 * int(r4_full),
            description=tr("r4 est en état Full avec r1 (eth1) et r2 (eth2)"),
        )
        self.add_grade_element(
            title=no_tr("aire0_router_ids"), max_grade=1, grade_part=part2,
            grade=int(rid['r3'] == ROUTER_IDS['r3'] and rid['r4'] == ROUTER_IDS['r4']),
            description=tr("router-id 3.3.3.3 et 4.4.4.4"),
        )
        self.add_grade_element(
            title=no_tr("aire0_r4_eth0_passive"), max_grade=1, grade_part=part2,
            grade=int(bool(iface('r4', 0).get('passive')) and iface('r4', 0).get('area') is not None),
            description=tr("eth0 de r4 est annoncée dans OSPF et passive"),
        )
        # Register every ping on the first pass: no short-circuit `and` around ping()/test() calls.
        pings_m1_m4 = all([ping('m1', 'm4'), ping('m4', 'm1')])
        self.add_grade_element(
            title=no_tr("aire0_pings_m1_m4"), max_grade=2, grade_part=part2, grade=2 * int(pings_m1_m4),
            description=tr("m1 et m4 se joignent"),
        )
        self.add_grade_element(
            title=no_tr("aire0_ecmp_r3"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get("nexthops")) == 2),
            description=tr("nombre de prochains sauts de r3 vers net4"),
        )

        # =====================================================================
        # Partie 3 — Coûts
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — Coûts et choix des chemins"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Coûts et choix des chemins"),
            hash="1a0bdac8d7c60df2",
            description=tr("""
Depuis `m4`, faites un `traceroute` vers `m1` : le trafic passe par le lien direct `r4`–`r1`.

1. Fixez à **{cost}** le coût du lien `l14` **aux deux extrémités** (`ip ospf cost` sur `eth2`
   de `r1` et sur `eth1` de `r4`) de façon que le trafic entre `m1` et `m4` passe par `r2`
   **dans les deux sens**. Vérifiez avec `traceroute` et `ip route` sur `r1` et `r4`.
2. Sur **tous** les routeurs OSPF de l'aire 0 (`r1` à `r4` ; pensez à le refaire sur ceux
   que vous configurerez ensuite), fixez la bande passante de référence à **{ref} Mbit/s**
   (`auto-cost reference-bandwidth`). Observez le nouveau coût des interfaces
   (`show ip ospf interface`) et vérifiez que le trafic `m1`–`m4` passe toujours par `r2`.
3. Sur `r3`, déclarez que l'interface `eth0` est un lien à **1000 Mbit/s** (commande
   `bandwidth`, mode interface) et observez le coût calculé.
""").format(cost=d.cost_l14, ref=d.ref_bandwidth)
            + instructor(tr("""
**Solution.** Au départ `r4` joint `net1` par le lien direct `l14` : coût 20 (10 + 10), contre 30
par `r2`.

```
! étape 1 — r1
interface eth2
 ip ospf cost {cost}
! étape 1 — r4
interface eth1
 ip ospf cost {cost}
!
! étape 2 — r1, r2, r3 et r4
router ospf
 auto-cost reference-bandwidth {ref}
!
! étape 3 — r3
interface eth0
 bandwidth 1000
```

1. Le coût est celui de l'interface de **sortie** : celui de `eth1` de `r4` détourne le sens
   `m4` → `m1`, celui de `eth2` de `r1` le sens retour. Le chemin direct coûte alors {cost} + 10,
   contre 30 par `r2` : `ip route` montre `net1` par `{r2_l24}` sur `r4` et `net4` par
   `{r2_core}` sur `r1`.
2. Une interface à 10 Gbit/s passe du coût 10 au coût **{auto_cost}** ({ref} ÷ 10 000) ; `l14`
   garde {cost} (un coût fixé l'emporte). Le trafic passe toujours par `r2` : 3 × {auto_cost}
   contre {cost} + {auto_cost}. FRR rappelle que la référence doit être la même partout.
3. `eth0` de `r3` prend le coût **{bw_cost}** ({ref} ÷ 1000) : `show ip ospf interface eth0`.

Évaluation : `couts_l14_valeur` (1 point : coût {cost} lu aux deux extrémités),
`couts_chemin_r4_vers_net1` et `couts_chemin_r1_vers_net4` (1 chacun : la route du noyau n'a que
`r2` pour prochain saut), `couts_auto_cost_config` (2 : la référence dans la configuration des
quatre routeurs ; 1 point si deux ou trois l'ont), `couts_auto_cost_effet` (1 : le coût de `eth0`
de `r2` suit la nouvelle référence), `couts_bandwidth_r3` (1 : `bandwidth 1000` dans la
configuration de `r3` et coût correspondant).
""").format(cost=d.cost_l14, ref=d.ref_bandwidth, r2_l24=ip['r2_l24'], r2_core=ip['r2_core'],
            auto_cost=expected_auto_cost(d.ref_bandwidth, 10000), bw_cost=expected_auto_cost(d.ref_bandwidth, 1000))),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Vérification du chemin"),
            hash="87c5cb75805974a0",
            description=tr("""
Après l'étape 1, par quel routeur passe le trafic de `m4` vers `m1` ? @@{via:>r1|r2|r3|r4}@@
""")
            + instructor(tr("""
**Solution.** Par **`r2`** : `traceroute m1` depuis `m4` affiche `r4`, `r2-eth1`, `r1-eth1` puis
`m1` (chaque routeur répond avec l'adresse de l'interface par laquelle sa réponse repart vers `m4`).

Évaluation : `couts_via_r2` (1 point, évaluation de l'enseignant seulement).
""")),
            cheat_answers={"final": {"via": "r2"}},
        )
        cost_ok = (iface('r1', 2).get('cost') == d.cost_l14 and iface('r4', 1).get('cost') == d.cost_l14)
        self.add_grade_element(
            title=no_tr("couts_l14_valeur"), max_grade=1, grade_part=part3, grade=int(cost_ok),
            description=tr("coût {cost} sur les deux extrémités de l14").format(cost=d.cost_l14),
        )
        via_r2_from_r4 = kernel_route_gateways(kroutes['r4'], d.nets.net1) == [str(ip['r2_l24'])]
        via_r2_from_r1 = kernel_route_gateways(kroutes['r1'], d.nets.net4) == [str(ip['r2_core'])]
        self.add_grade_element(
            title=no_tr("couts_chemin_r4_vers_net1"), max_grade=1, grade_part=part3, grade=int(via_r2_from_r4),
            description=tr("r4 route net1 uniquement via r2"),
        )
        self.add_grade_element(
            title=no_tr("couts_chemin_r1_vers_net4"), max_grade=1, grade_part=part3, grade=int(via_r2_from_r1),
            description=tr("r1 route net4 uniquement via r2"),
        )
        self.add_grade_element(
            title=no_tr("couts_via_r2"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("via")) == "r2"), scope=CHOICE_SCOPE,
            description=tr("routeur traversé après modification des coûts"),
        )
        nb_autocost = sum(ospf_conf(r).get('auto_cost_reference_bandwidth') == d.ref_bandwidth for r in AREA0_ROUTERS)
        self.add_grade_element(
            title=no_tr("couts_auto_cost_config"), max_grade=2, grade_part=part3,
            grade=2 if nb_autocost == len(AREA0_ROUTERS) else int(nb_autocost >= 2),
            description=tr("auto-cost reference-bandwidth {ref} sur r1, r2, r3 et r4").format(ref=d.ref_bandwidth),
        )
        r2_eth0 = iface('r2', 0)
        autocost_effect = (r2_eth0.get('bandwidth') is not None and r2_eth0.get('cost') is not None
                           and r2_eth0['cost'] == expected_auto_cost(d.ref_bandwidth, r2_eth0['bandwidth'])
                           and r2_eth0['cost'] != 10)
        self.add_grade_element(
            title=no_tr("couts_auto_cost_effet"), max_grade=1, grade_part=part3, grade=int(autocost_effect),
            description=tr("le coût des interfaces suit la nouvelle référence (eth0 de r2)"),
        )
        r3_eth0 = iface('r3', 0)
        ref_r3 = ospf_conf('r3').get('auto_cost_reference_bandwidth') or DEFAULT_REF_BANDWIDTH
        bandwidth_ok = (r3_eth0.get('bandwidth') == 1000 and if_conf('r3', 0).get('bandwidth') == 1000
                        and r3_eth0.get('cost') == expected_auto_cost(ref_r3, 1000))
        self.add_grade_element(
            title=no_tr("couts_bandwidth_r3"), max_grade=1, grade_part=part3, grade=int(bandwidth_ok),
            description=tr("bandwidth 1000 sur eth0 de r3 et coût correspondant"),
        )

        # =====================================================================
        # Partie 4 — DR / BDR
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Élection du DR et du BDR"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Élection du DR et du BDR sur le réseau core"),
            hash="1d8762d766ff488d",
            description=tr("""
Sur le réseau `core` ({core}), notez quel routeur est **DR** et lequel est **BDR**
(`show ip ospf interface` ou `show ip ospf neighbor`) et expliquez ce résultat.

Faites en sorte que **`r3` soit le DR** et **`r1` le BDR**, et que `r2` ne puisse **jamais**
être élu (priorités 100, 50 et 0). L'élection n'étant pas préemptive, il faudra relancer
le processus OSPF (`clear ip ospf process`) sur les routeurs qui détiennent actuellement
les rôles DR et BDR, puis patienter jusqu'à une minute et demie.
""").format(core=d.nets.core)
            + instructor(tr("""
**Solution.** Au départ `r2` est DR et `r1` BDR : à priorité égale (1), le plus grand router-id
l'emporte, et celui de `r2` (`{rid_r2}`, sa plus grande adresse) dépasse `1.1.1.1`. `r3`
(`3.3.3.3`), arrivé après l'élection, reste `DROther` : l'élection n'est pas préemptive.

```
! r3
interface eth0
 ip ospf priority 100
! r1
interface eth1
 ip ospf priority 50
! r2
interface eth0
 ip ospf priority 0
```

puis, sur `r1` et sur `r2` (mode privilégié de `vtysh`) : `clear ip ospf process`. Leurs
adjacences tombent, `r3` se retrouve seul et devient DR ; `r1` revient avec la priorité 50 et
devient BDR ; `r2` (priorité 0) ne peut plus être élu. Vérification sur `r2` :
`show ip ospf neighbor` affiche `r3` en `Full/DR` et `r1` en `Full/Backup`, et
`show ip ospf interface eth0` l'état `DROther`.

Évaluation : `dr_r3` (2 points : le DR de `core`, vu de `r2`, est le router-id de `r3`), `bdr_r1`
(1 : le BDR est `r1`, compté seulement si `r3` est DR — `r1` est déjà BDR au départ), `dr_priorites`
(1 : priorités 100 / 50 / 0 et `r2` en `DROther`).
""").format(rid_r2=max(d.ips.r2_core.ip, d.ips.r2_l24.ip))),
        )
        core_view = iface('r2', 0)  # r2 stays up during the re-election of r1/r3
        dr_ok = bool(rid['r3']) and core_view.get('dr_id') == rid['r3']
        # r1 is already BDR in the initial state (r2 DR by router-id): only meaningful once r3 is DR
        bdr_ok = dr_ok and bool(rid['r1']) and core_view.get('bdr_id') == rid['r1']
        prio_ok = (iface('r3', 0).get('priority') == 100 and iface('r1', 1).get('priority') == 50
                   and iface('r2', 0).get('priority') == 0 and iface('r2', 0).get('ospf_state') == 'DROther')
        self.add_grade_element(
            title=no_tr("dr_r3"), max_grade=2, grade_part=part4, grade=2 * int(dr_ok),
            description=tr("r3 est le DR du réseau core"),
        )
        self.add_grade_element(
            title=no_tr("bdr_r1"), max_grade=1, grade_part=part4, grade=int(bdr_ok),
            description=tr("r1 est le BDR du réseau core"),
        )
        self.add_grade_element(
            title=no_tr("dr_priorites"), max_grade=1, grade_part=part4, grade=int(prio_ok),
            description=tr("priorités 100 / 50 / 0 et r2 en DROther"),
        )

        # =====================================================================
        # Partie 5 — Aire 2 et agrégation
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Aire 2 et agrégation de routes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une seconde aire : l'aire 2"),
            hash="739775415387bdcd",
            description=tr("""
Les routeurs `r6` et `r7` et l'interface `eth3` de `r4` forment l'**aire 2** :

- `r6` : router-id `6.6.6.6`, interfaces `eth0` (`{net6}`, passive), `eth1` (`{l46}`) et
  `eth2` (`{l67}`), toutes dans l'aire 2 ;
- `r7` : router-id `7.7.7.7`, interfaces `eth0` (`{net7}`, passive) et `eth1` (`{l67}`)
  dans l'aire 2 ;
- `r4` : ajoutez `eth3` (`{l46}`) dans l'aire 2 (`network … area 2`, ou `ip ospf area 2`
  en mode interface). `r4` devient un **ABR** (`show ip ospf`).

N'oubliez pas la bande passante de référence ({ref}) sur les nouveaux routeurs.
Vérifiez que `m6` et `m7` joignent `m1` et `m4`, puis comparez `show ip ospf route` sur `r1`
et sur `r7` (routes `IA`).

**Agrégation** : les quatre réseaux de l'aire 2 sont contigus. Déterminez le plus petit
préfixe qui les contient tous et configurez sur l'ABR (`area 2 range PREFIXE`) l'agrégation
de l'aire 2 vers le backbone. Vérifiez sur `r1` que les quatre routes ont été remplacées par
une seule.
""").format(net6=d.nets.net6, net7=d.nets.net7, l46=d.nets.l46, l67=d.nets.l67, ref=d.ref_bandwidth)
            + instructor(tr("""
**Solution.**

```
! r6
router ospf
 ospf router-id {rid_r6}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net6} area 2
 network {l46} area 2
 network {l67} area 2
!
! r7
router ospf
 ospf router-id {rid_r7}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net7} area 2
 network {l67} area 2
!
! r4
router ospf
 network {l46} area 2
 area 2 range {range}
```

- `show ip ospf` sur `r4` : *This router is an ABR* ; `show ip ospf route` montre sur `r1` les
  réseaux de l'aire 2 en `N IA` et sur `r7` ceux de l'aire 0 en `N IA`.
- Agrégation : `{net6}`, `{net7}`, `{l46}` et `{l67}` tiennent tous dans **`{range}`**, le plus
  petit préfixe qui les contient (voir la question suivante). Après `area 2 range`, `r1` n'a plus
  qu'une route `{range}` au lieu de quatre (`ip route`, `show ip ospf route`).

Évaluation : `aire2_abr_r4` (1 point : `eth3` de `r4` dans l'aire 2 et `r4` ABR), `aire2_voisins`
(1 : `r6` voit `r4` par `eth1` et `r7` par `eth2` en `Full`), `aire2_router_ids` (1), `aire2_pings`
(1 : `m1` → `m6`, `m4` → `m7`, `m7` → `m1`), `aire2_range_r1` (1 : `r1` a une route OSPF vers
`{range}`), `aire2_range_pas_de_detail` (1 : et plus aucune des quatre routes détaillées).
""").format(net6=d.nets.net6, net7=d.nets.net7, l46=d.nets.l46, l67=d.nets.l67, ref=d.ref_bandwidth,
            range=d.nets.area2_range, rid_r6=ROUTER_IDS['r6'], rid_r7=ROUTER_IDS['r7'])),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Préfixe agrégé de l'aire 2"),
            hash="e7f52f073f5f1d37",
            description=tr("Préfixe utilisé dans `area 2 range` : @@{range:[0-9./]+}@@")
            + instructor(tr("""

**Solution.** **`{range}`**. Les deux réseaux d'hôtes `{net6}` et `{net7}` sont deux /24
consécutifs et les deux liens `{l46}` et `{l67}` sont des /30 du /24 suivant : il faut un /22
pour les couvrir tous (un /23 ne contient que les deux premiers /24).

Évaluation : `aire2_prefixe_agrege` (1 point : la réponse désigne le réseau `{range}`).
""").format(range=d.nets.area2_range, net6=d.nets.net6, net7=d.nets.net7, l46=d.nets.l46, l67=d.nets.l67)),
            cheat_answers={"final": {"range": str(d.nets.area2_range)}},
        )
        abr_r4 = bool(info['r4'].get('abr')) and iface('r4', 3).get('area') == '0.0.0.2'
        self.add_grade_element(
            title=no_tr("aire2_abr_r4"), max_grade=1, grade_part=part5, grade=int(abr_r4),
            description=tr("eth3 de r4 est dans l'aire 2 et r4 est ABR"),
        )
        aire2_full = full_with('r6', 'r4', interface='eth1') and full_with('r6', 'r7', interface='eth2')
        self.add_grade_element(
            title=no_tr("aire2_voisins"), max_grade=1, grade_part=part5, grade=int(aire2_full),
            description=tr("r6 est en état Full avec r4 et r7"),
        )
        self.add_grade_element(
            title=no_tr("aire2_router_ids"), max_grade=1, grade_part=part5,
            grade=int(rid['r6'] == ROUTER_IDS['r6'] and rid['r7'] == ROUTER_IDS['r7']),
            description=tr("router-id 6.6.6.6 et 7.7.7.7"),
        )
        pings_aire2 = all([ping('m1', 'm6'), ping('m4', 'm7'), ping('m7', 'm1')])
        self.add_grade_element(
            title=no_tr("aire2_pings"), max_grade=1, grade_part=part5, grade=int(pings_aire2),
            description=tr("m6 et m7 joignent m1 et m4"),
        )
        self.add_grade_element(
            title=no_tr("aire2_prefixe_agrege"), max_grade=1, grade_part=part5,
            grade=int(_same_network(q5.get("range"), d.nets.area2_range)),
            description=tr("préfixe agrégé de l'aire 2"),
        )
        range_r1 = has_ospf_route('r1', d.nets.area2_range)
        self.add_grade_element(
            title=no_tr("aire2_range_r1"), max_grade=1, grade_part=part5, grade=int(range_r1),
            description=tr("r1 possède la route agrégée {range}").format(range=d.nets.area2_range),
        )
        no_24_on_r1 = range_r1 and not any(
            str(n) in kroutes['r1'] for n in (d.nets.net6, d.nets.net7, d.nets.l46, d.nets.l67))
        self.add_grade_element(
            title=no_tr("aire2_range_pas_de_detail"), max_grade=1, grade_part=part5, grade=int(no_24_on_r1),
            description=tr("r1 ne voit plus les préfixes détaillés de l'aire 2 (suppose la route agrégée)"),
        )

        # =====================================================================
        # Partie 6 — Routes externes
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Routes externes (ASBR)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Routes externes : r1 devient ASBR"),
            hash="b917c1541768dcce",
            description=tr("""
`r1` possède deux routes **statiques** configurées dans FRR (`show running-config`,
`show ip route`) : une vers le réseau `{ext}` (le serveur `internet`, `{ext_host}`) et une
route par défaut, toutes deux via un routeur extérieur au domaine OSPF. Aucun autre routeur
ne connaît ces destinations (essayez `ping internet` depuis `m7`).

Sur `r1` (mode `router ospf`) :

1. redistribuez les routes statiques dans OSPF (`redistribute static`) ;
2. annoncez la route par défaut (`default-information originate`).

Observez sur `r7` la table `show ip ospf route` et `show ip route`, puis vérifiez que
`m7` joint `internet`.
""").format(ext=EXT_PUBLIC, ext_host=EXT_PUBLIC_HOST.ip)
            + instructor(tr("""
**Solution.**

```
! r1
router ospf
 redistribute static
 default-information originate
```

- `show ip ospf` sur `r1` : *This router is an ASBR*. Les deux routes statiques de `r1`
  (`ip route {ext} {isp}` et `ip route 0.0.0.0/0 {isp}` dans sa configuration) deviennent des
  LSA de type 5, inondés dans tout le domaine.
- Sur `r7`, `show ip ospf route` les range dans la table *external* : `N E2 {ext}` et
  `N E2 0.0.0.0/0` ; `show ip route` les marque `O` et `ip route` `proto ospf`.
- `ping internet` depuis `m7` passe : `r1` route `{ext}` vers l'extérieur, qui a une route
  retour par `r1`.

Évaluation : `externe_asbr_r1` (1 point), `externe_routes_r7` (2 : `r7` a `{ext}` et la route par
défaut en E2, installées dans le noyau par OSPF), `externe_ping_internet` (1 : `m7` joint
`{ext_host}`).
""").format(ext=EXT_PUBLIC, ext_host=EXT_PUBLIC_HOST.ip, isp=d.ips.isp_ext.ip)),
        )
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Type des routes externes"),
            hash="1ed2cf33f77784ba",
            description=tr("""
Sur `r7`, de quel type est la route vers `{ext}` (`show ip ospf route` ; le tableau des types de
routes est dans l'onglet **Informations**, section @@ref:areas@@) ?
@@{{type:>O|O IA|O E1|O E2}}@@  et quelle est sa métrique ? @@{{metric:[0-9]+}}@@
""").format(ext=EXT_PUBLIC)
            + instructor(tr("""
**Solution.** **O E2**, métrique **20** : `show ip ospf route` sur `r7` affiche
`N E2 {ext} [coût/20]` (le coût jusqu'à l'ASBR, puis la métrique externe) et `show ip route`
`O>* {ext} [110/20]`. Une route redistribuée est de type 2 avec la métrique 20 par défaut : seule
la métrique externe compte, elle est donc la même sur tous les routeurs du domaine, quel que soit
leur éloignement de `r1`.

Évaluation : `externe_type_route_typed` (0,5 point : métrique 20) et, pour l'évaluation de
l'enseignant seulement (choix dans une liste), `externe_type_route` (0,5 : type O E2).
""").format(ext=EXT_PUBLIC)),
            cheat_answers={"final": {"type": "O E2", "metric": "20"}},
        )
        self.add_grade_element(
            title=no_tr("externe_asbr_r1"), max_grade=1, grade_part=part6, grade=int(bool(info['r1'].get('asbr'))),
            description=tr("r1 est ASBR"),
        )
        ext_r7 = oroutes['r7'].get(str(EXT_PUBLIC)) or {}
        def_r7 = oroutes['r7'].get('0.0.0.0/0') or {}
        ext_routes_r7 = (ext_r7.get('type') == 'E2' and has_ospf_route('r7', EXT_PUBLIC)
                         and def_r7.get('type') == 'E2' and has_ospf_route('r7', '0.0.0.0/0'))
        self.add_grade_element(
            title=no_tr("externe_routes_r7"), max_grade=2, grade_part=part6, grade=2 * int(ext_routes_r7),
            description=tr("r7 reçoit {ext} et la route par défaut en routes E2").format(ext=EXT_PUBLIC),
        )
        m7_pings_internet = ping('m7', EXT_PUBLIC_HOST.ip)
        self.add_grade_element(
            title=no_tr("externe_ping_internet"), max_grade=1, grade_part=part6,
            grade=int(m7_pings_internet),
            description=tr("m7 joint internet ({ext_host})").format(ext_host=EXT_PUBLIC_HOST.ip),
        )
        self.add_grade_element(
            title=no_tr("externe_type_route_typed"), max_grade=0.5, grade_part=part6,
            grade=0.5 * int(_int(q6.get("metric")) == 20),
            description=tr("métrique de la route externe"),
        )
        self.add_grade_element(
            title=no_tr("externe_type_route"), max_grade=0.5, grade_part=part6,
            grade=0.5 * int(_norm(q6.get("type")) == "o e2"),
            scope=CHOICE_SCOPE,
            description=tr("type de la route externe"),
        )

        # =====================================================================
        # Partie 7 — Aire stub
        # =====================================================================
        part7 = self.add_grade_part(no_tr("partie7"), tr("Partie 7 — Aire stub (aire 1)"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Une aire stub : l'aire 1"),
            hash="3b28e96f0b34499f",
            description=tr("""
Le routeur `r5` (router-id `5.5.5.5`, `eth0` = `{net5}` passive, `eth1` = `{l35}`) et
l'interface `eth1` de `r3` forment l'**aire 1**. Configurez-les (référence {ref} comprise)
et vérifiez que `m5` joint `m1` et `internet`, puis comparez `show ip ospf route` sur `r5`
avec celle de `r7`.

1. Transformez l'aire 1 en aire **stub** (`area 1 stub` sur `r3` **et** sur `r5` : que se
   passe-t-il si un seul des deux est configuré ?). Observez sur `r5` la disparition des
   routes externes, l'apparition d'une route par défaut inter-aire et l'absence de LSA de
   type 5 dans `show ip ospf database`. `m5` doit toujours joindre `internet`.
2. *(bonus)* Transformez l'aire 1 en aire ***totally stubby*** (`area 1 stub no-summary` sur
   l'ABR uniquement) et observez la table de routage de `r5`.
""").format(net5=d.nets.net5, l35=d.nets.l35, ref=d.ref_bandwidth)
            + instructor(tr("""
**Solution.**

```
! r5
router ospf
 ospf router-id {rid_r5}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net5} area 1
 network {l35} area 1
 area 1 stub
!
! r3
router ospf
 network {l35} area 1
 area 1 stub no-summary
```

(`area 1 stub` sur `r3` pour l'étape 1, `area 1 stub no-summary` pour le bonus.)

- Avant `stub`, `r5` voit comme `r7` les réseaux des autres aires en `N IA` et les deux routes
  externes en `N E2`.
- `area 1 stub` d'un seul côté : le drapeau *stub* des Hello diffère, chaque routeur ignore les
  Hello de l'autre et l'adjacence tombe (au plus tard à l'expiration de l'intervalle Dead,
  40 s) ; elle revient quand les deux sont configurés.
- Aire stub : les `N E2` disparaissent de `r5`, remplacées par une route par défaut inter-aire
  (`N IA 0.0.0.0/0`, par `{r3_l35}`) ; `show ip ospf database` n'a plus de section *AS External
  Link States*. `m5` joint toujours `internet`, par cette route par défaut.
- *Totally stubby* : il ne reste sur `r5` que ses deux réseaux et la route par défaut.

Évaluation : `stub_r5_voisin` (1 point : `r5`, router-id `{rid_r5}`, voit `r3` en `Full` et `r3`
est ABR), `stub_ping_m5` (1 : `m5` joint `m1`), `stub_configuration` (1 : aire 1 stub sur `r3` et
`r5`), `stub_route_par_defaut` (1 : route par défaut inter-aire de `r5` par `r3`),
`stub_pas_de_route_externe` (1 : `{ext}` connu de `r3` mais absent de `r5`, aucun LSA de type 5
sur `r5` ; suppose la partie 6), `stub_no_summary` (1, le bonus : `no-summary` sur `r3`, plus de
route vers `net1` sur `r5`, `m5` joint `internet`).
""").format(net5=d.nets.net5, l35=d.nets.l35, ref=d.ref_bandwidth, rid_r5=ROUTER_IDS['r5'],
            r3_l35=ip['r3_l35'], ext=EXT_PUBLIC)),
        )
        stub_r5_ok = full_with('r5', 'r3', interface='eth1') and rid['r5'] == ROUTER_IDS['r5'] \
                     and bool(info['r3'].get('abr'))
        self.add_grade_element(
            title=no_tr("stub_r5_voisin"), max_grade=1, grade_part=part7, grade=int(stub_r5_ok),
            description=tr("r5 (5.5.5.5) est en état Full avec r3, qui est ABR"),
        )
        m5_pings_m1 = ping('m5', 'm1')
        self.add_grade_element(
            title=no_tr("stub_ping_m5"), max_grade=1, grade_part=part7, grade=int(m5_pings_m1),
            description=tr("m5 joint m1"),
        )
        area1_r3 = (info['r3'].get('areas') or {}).get('0.0.0.1') or {}
        area1_r5 = (info['r5'].get('areas') or {}).get('0.0.0.1') or {}
        stub_conf = area1_r3.get('type') == 'stub' and area1_r5.get('type') == 'stub'
        self.add_grade_element(
            title=no_tr("stub_configuration"), max_grade=1, grade_part=part7, grade=int(stub_conf),
            description=tr("l'aire 1 est stub sur r3 et sur r5"),
        )
        def_r5 = oroutes['r5'].get('0.0.0.0/0') or {}
        default_ia = def_r5.get('type') == 'IA' and str(ip['r3_l35']) in [gw for gw, _i in def_r5.get('nexthops', [])]
        self.add_grade_element(
            title=no_tr("stub_route_par_defaut"), max_grade=1, grade_part=part7, grade=int(default_ia),
            description=tr("r5 reçoit une route par défaut inter-aire de r3"),
        )
        db_r5, _ = self.test('r5', 'vtysh -c "show ip ospf database"', allow_error=True)
        ext_seen_by_r3 = str(EXT_PUBLIC) in oroutes['r3']
        no_ext_r5 = (ext_seen_by_r3 and str(EXT_PUBLIC) not in kroutes['r5']
                     and 'AS External Link States' not in (db_r5 or ''))
        self.add_grade_element(
            title=no_tr("stub_pas_de_route_externe"), max_grade=1, grade_part=part7, grade=int(no_ext_r5),
            description=tr("r5 ne reçoit ni la route externe ni les LSA de type 5 (suppose la partie 6)"),
        )
        m5_pings_internet = ping('m5', EXT_PUBLIC_HOST.ip)
        totally_stubby = (stub_conf and bool(area1_r3.get('no_summary')) and default_ia
                          and str(d.nets.net1) not in oroutes['r5'] and m5_pings_internet)
        self.add_grade_element(
            title=no_tr("stub_no_summary"), max_grade=1, grade_part=part7, grade=int(totally_stubby),
            description=tr("bonus : aire 1 totally stubby (plus de routes inter-aires sur r5, internet joignable)"),
        )

        # =====================================================================
        # Partie 8 — Authentification
        # =====================================================================
        part8 = self.add_grade_part(no_tr("partie8"), tr("Partie 8 — Authentification MD5"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Authentification des échanges OSPF"),
            hash="f39c181ca09b8416",
            description=tr("""
Sans authentification, n'importe quelle machine branchée sur un lien peut injecter des LSA.
Protégez le lien `l14` (`eth2` de `r1`, `eth1` de `r4`) par une authentification **MD5**
(mode interface) :

```
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 {key}
```

Configurez d'abord une seule extrémité et observez `show ip ospf neighbor` (et le journal
`/var/log/frr/frr.log`) pendant une minute, puis configurez l'autre extrémité et vérifiez
que l'adjacence est de nouveau `Full`.
""").format(key=d.md5_key)
            + instructor(tr("""
**Solution.**

```
! r1
interface eth2
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
! r4
interface eth1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
```

- Une seule extrémité configurée : chaque routeur rejette les paquets de l'autre (type
  d'authentification différent, signalé dans `/var/log/frr/frr.log`) ; le voisin disparaît de
  `show ip ospf neighbor` à l'expiration de l'intervalle Dead (40 s). Le trafic `m1`–`m4` n'est
  pas touché : il passe par `r2` depuis la partie 3.
- Les deux extrémités configurées : l'adjacence remonte jusqu'à `Full` ;
  `show ip ospf interface eth1` sur `r4` affiche *Cryptographic authentication enabled* et
  *Algorithm:MD5*.

Évaluation : `auth_configuration` (2 points, 1 par extrémité : mode `message-digest` sur
l'interface, ou sur toute l'aire 0, et clé numéro 1 égale à `{key}`), `auth_adjacence` (1 :
l'adjacence `r1`–`r4` est `Full` et l'une des extrémités au moins est configurée).
""").format(key=d.md5_key)),
        )

        def md5_ok(r: str, n: int) -> bool:
            ic = if_conf(r, n)
            area0 = (ospf_conf(r).get('areas') or {}).get('0.0.0.0') or {}
            auth = ic.get('authentication') == 'message-digest' or area0.get('authentication') == 'message-digest'
            return auth and (ic.get('message_digest_keys') or {}).get(1) == d.md5_key

        auth_r1, auth_r4 = md5_ok('r1', 2), md5_ok('r4', 1)
        self.add_grade_element(
            title=no_tr("auth_configuration"), max_grade=2, grade_part=part8, grade=int(auth_r1) + int(auth_r4),
            description=tr("authentification MD5 (clé 1) sur eth2 de r1 et eth1 de r4"),
        )
        auth_adj = (auth_r1 or auth_r4) and full_with('r4', 'r1', interface='eth1')
        self.add_grade_element(
            title=no_tr("auth_adjacence"), max_grade=1, grade_part=part8, grade=int(auth_adj),
            description=tr("l'adjacence r1–r4 sur l14 est Full avec l'authentification"),
        )

        # =====================================================================
        # Partie 9 — Temporisateurs et convergence
        # =====================================================================
        part9 = self.add_grade_part(no_tr("partie9"), tr("Partie 9 — Temporisateurs et convergence"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Temporisateurs et temps de convergence"),
            hash="311d80c9d7e76578",
            description=tr("""
Sur le lien `l24` (`eth1` de `r2`, `eth2` de `r4`), réglez l'intervalle **Hello** à
**{hello} s** et l'intervalle **Dead** à **{dead} s** (`ip ospf hello-interval`,
`ip ospf dead-interval`, mode interface). Configurez d'abord une seule extrémité : que
devient l'adjacence ? Terminez la configuration et vérifiez qu'elle est de nouveau `Full`.

Mesurez ensuite le temps de convergence en lançant `ping m1` depuis `m4` (le trafic passe
par `r2`) et en provoquant deux pannes différentes du lien `l24` sur `r4` :

- coupure franche : `ip link set eth2 down` (puis `ip link set eth2 up` pour rétablir) ;
- panne silencieuse : l'interface reste active mais plus rien ne sort de `r4` par `eth2` :
  `tc qdisc add dev eth2 root netem loss 100%` (puis `tc qdisc del dev eth2 root` pour
  rétablir). Observez `show ip ospf neighbor` sur `r2` et sur `r4` pendant la panne.
""").format(hello=d.hello_l24, dead=4 * d.hello_l24)
            + instructor(tr("""
**Solution.**

```
! r2
interface eth1
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
! r4
interface eth2
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
```

- Une seule extrémité configurée : les intervalles annoncés dans les Hello diffèrent, chaque
  routeur ignore ceux de l'autre et l'adjacence tombe à l'expiration de l'intervalle Dead ; le
  trafic `m1`–`m4` repasse alors par `l14` malgré son coût. Les deux extrémités configurées :
  adjacence `Full`, `show ip ospf interface eth2` sur `r4` affiche `Hello {hello}s, Dead {dead}s`.
- Coupure franche (`ip link set eth2 down` sur `r4`) : `r4` le sait aussitôt, inonde un nouveau
  LSA par `l14` et tous les routeurs recalculent : le `ping` ne perd rien, ou un écho tout au
  plus, et passe désormais par `l14`.
- Panne silencieuse (`netem loss 100%` sur `eth2` de `r4`) : l'interface reste active et `r4`
  continue d'envoyer par `eth2` le trafic de `m4`, qui est perdu. Rien ne signale la panne : `r2`,
  qui ne reçoit plus les Hello de `r4`, ne le déclare mort qu'à l'expiration de l'intervalle Dead
  (`show ip ospf neighbor` sur `r2` : le *Dead Time* de `r4` descend jusqu'à zéro). Ses propres
  Hello, qui arrivent toujours à `r4`, ne citent alors plus `r4`, qui abandonne l'adjacence à son
  tour et recalcule ses routes : le `ping` reprend par `l14` au bout d'environ {dead} s. Une fois
  le `netem` retiré, l'adjacence se reforme en quelques secondes.

Évaluation : `timers_valeurs` (1 point : Hello {hello} s et Dead {dead} s lus aux deux
extrémités de `l24`), `timers_adjacence` (1 : l'adjacence `r2`–`r4` est `Full` et l'une des
extrémités au moins a les nouveaux temporisateurs).
""").format(hello=d.hello_l24, dead=4 * d.hello_l24)),
        )
        q9 = self.question_form(
            section=self.section(1),
            title=tr("Temps de convergence observés"),
            hash="dcc4543b2b921412",
            description=tr("""
Temps avant que `m4` ne joigne de nouveau `m1` après la coupure franche :
@@{link_down:>moins de 5 s|environ l'intervalle Hello|environ l'intervalle Dead|jamais}@@

et après la panne silencieuse :
@@{filtre:>moins de 5 s|environ l'intervalle Hello|environ l'intervalle Dead|jamais}@@
""")
            + instructor(tr("""
**Solution.** Coupure franche : **moins de 5 s** (la panne est connue immédiatement). Panne
silencieuse : **environ l'intervalle Dead** ({dead} s ici) : rien ne signale la panne, il faut que
`r2` reste {dead} s sans Hello de `r4` pour que l'adjacence tombe et que les routes changent.

Évaluation : `convergence_coupure` et `convergence_panne_silencieuse` (1 point chacune,
évaluation de l'enseignant seulement).
""").format(dead=4 * d.hello_l24)),
            cheat_answers={"final": {"link_down": "moins de 5 s", "filtre": "environ l'intervalle Dead"}},
        )
        h, dd = d.hello_l24, 4 * d.hello_l24
        timers_r2 = iface('r2', 1).get('hello_interval') == h and iface('r2', 1).get('dead_interval') == dd
        timers_r4 = iface('r4', 2).get('hello_interval') == h and iface('r4', 2).get('dead_interval') == dd
        self.add_grade_element(
            title=no_tr("timers_valeurs"), max_grade=1, grade_part=part9, grade=int(timers_r2 and timers_r4),
            description=tr("Hello {hello} s / Dead {dead} s sur les deux extrémités de l24").format(hello=h, dead=dd),
        )
        timers_adj = (timers_r2 or timers_r4) and full_with('r4', 'r2', interface='eth2')
        self.add_grade_element(
            title=no_tr("timers_adjacence"), max_grade=1, grade_part=part9, grade=int(timers_adj),
            description=tr("l'adjacence r2–r4 sur l24 est Full avec les nouveaux temporisateurs"),
        )
        self.add_grade_element(
            title=no_tr("convergence_coupure"), max_grade=1, grade_part=part9,
            grade=int(_norm(q9.get("link_down")) == "moins de 5 s"), scope=CHOICE_SCOPE,
            description=tr("convergence après une coupure franche"),
        )
        self.add_grade_element(
            title=no_tr("convergence_panne_silencieuse"), max_grade=1, grade_part=part9,
            grade=int(_norm(q9.get("filtre")) == "environ l'intervalle dead"), scope=CHOICE_SCOPE,
            description=tr("convergence après une panne silencieuse"),
        )


_TRANSLATIONS = {'en': {
    "OSPF : routage dynamique": "OSPF: dynamic routing",
    """
**Sommaire**
""": """
**Contents**
""",
    "Principe d'OSPF": "OSPF principles",
    """
**OSPF** (*Open Shortest Path First* ; RFC 2328 pour la version 2, celle d'IPv4) est un protocole
de routage **dynamique** : les routeurs s'échangent la description du réseau, calculent eux-mêmes
leurs tables de routage et les recalculent quand un lien apparaît ou disparaît. C'est un protocole
**intérieur** (IGP), utilisé au sein d'un même domaine administratif, et un protocole à **état de
liens** (*link state*) :

- chaque routeur découvre ses **voisins** grâce à des paquets **Hello** envoyés périodiquement
  en multicast (`224.0.0.5`) ; OSPF est transporté directement dans IP (protocole numéro 89),
  sans TCP ni UDP ;
- chaque routeur décrit ses liens dans des **LSA** (*Link State Advertisements*) qui sont
  **inondés** (*flooding*) à tous les routeurs de l'aire ;
- tous les routeurs d'une aire possèdent donc la même **base de données** (LSDB) et calculent
  chacun, avec l'algorithme de **Dijkstra** (SPF), l'arbre des plus courts chemins vers toutes
  les destinations ;
- les meilleures routes sont installées dans la table de routage du noyau (`ip route`, où
  elles apparaissent avec `proto ospf` ; leur distance administrative est 110).

### @@sec:cost@@ Le coût des chemins

Le **coût** d'un chemin est la somme des coûts des interfaces *de sortie* traversées : il se
règle donc séparément dans chaque sens. Par défaut FRR calcule le coût d'une interface par
`coût = bande_passante_de_référence / bande_passante_de_l'interface` (arrondi, minimum 1). La
référence vaut 100 000 Mbit/s et une interface virtuelle d'un conteneur annonce 10 000 Mbit/s : le
coût par défaut y est donc **10**. On peut :

- fixer le coût d'une interface : `ip ospf cost N` (mode `interface ethX`) ; il l'emporte sur
  le coût calculé ;
- changer la référence : `auto-cost reference-bandwidth N` (mode `router ospf`, N en Mbit/s),
  à faire sur **tous** les routeurs du domaine pour que les coûts restent comparables ;
- déclarer la bande passante d'une interface : `bandwidth N` (mode `interface`, N en Mbit/s).

Lorsque plusieurs chemins ont le même coût, OSPF installe **tous** les prochains sauts
(*ECMP*, *Equal-Cost Multi-Path*) : la route apparaît avec plusieurs `nexthop` dans `ip route`.
""": """
**OSPF** (*Open Shortest Path First*; RFC 2328 for version 2, the IPv4 one) is a **dynamic**
routing protocol: the routers exchange the description of the network, compute their routing
tables themselves and recompute them when a link appears or disappears. It is an **interior**
protocol (IGP), used within a single administrative domain, and a **link state** protocol:

- each router discovers its **neighbours** thanks to **Hello** packets sent periodically by
  multicast (`224.0.0.5`); OSPF is carried directly in IP (protocol number 89), without TCP or
  UDP;
- each router describes its links in **LSAs** (*Link State Advertisements*), which are
  **flooded** to all the routers of the area;
- all the routers of an area therefore hold the same **database** (LSDB), and each of them
  computes, with **Dijkstra**'s algorithm (SPF), the tree of the shortest paths to all the
  destinations;
- the best routes are installed in the kernel routing table (`ip route`, where they appear with
  `proto ospf`; their administrative distance is 110).

### @@sec:cost@@ The cost of a path

The **cost** of a path is the sum of the costs of the *outgoing* interfaces crossed: it is
therefore set separately in each direction. By default FRR computes the cost of an interface as
`cost = reference_bandwidth / interface_bandwidth` (rounded, minimum 1). The reference is
100,000 Mbit/s and a virtual interface of a container announces 10,000 Mbit/s: the default cost
there is therefore **10**. You can:

- set the cost of an interface: `ip ospf cost N` (`interface ethX` mode); it overrides the
  computed cost;
- change the reference: `auto-cost reference-bandwidth N` (`router ospf` mode, N in Mbit/s),
  to be done on **all** the routers of the domain so that the costs remain comparable;
- declare the bandwidth of an interface: `bandwidth N` (`interface` mode, N in Mbit/s).

When several paths have the same cost, OSPF installs **all** the next hops
(*ECMP*, *Equal-Cost Multi-Path*): the route appears with several `nexthop` in `ip route`.
""",
    "Voisinage et adjacences": "Neighbours and adjacencies",
    """
Deux routeurs deviennent voisins si leurs Hello sont compatibles : même **aire**, même
**intervalle Hello**, même **intervalle Dead**, même type de réseau, même type d'aire (stub ou
non), même authentification, même préfixe sur le lien. La relation passe par les états `Down`,
`Init` (j'entends le voisin), `2-Way` (il m'entend aussi), `ExStart`, `Exchange`, `Loading`
(échange des bases) et enfin **`Full`** (bases synchronisées).

### @@sec:dr@@ DR et BDR

Sur un réseau à diffusion (Ethernet) les routeurs élisent un **DR** (*Designated Router*)
et un **BDR** (*Backup DR*) ; les autres routeurs (`DROther`) ne forment une adjacence
complète qu'avec le DR et le BDR (ils restent en `2-Way` entre eux), ce qui limite le nombre
d'adjacences et le trafic d'inondation. Le DR décrit le réseau dans un LSA de type 2 ; les
`DROther` lui écrivent à l'adresse `224.0.0.6`. L'élection se fait sur la **priorité**
(`ip ospf priority N` en mode interface, 1 par défaut, 0 = jamais DR ni BDR) puis, à priorité
égale, sur le **router-id** le plus grand. Elle **n'est pas préemptive** : un routeur qui arrive
avec une meilleure priorité ne détrône pas le DR en place ; il faut relancer le processus
(`clear ip ospf process`) sur les routeurs qui tiennent les rôles pour provoquer une nouvelle
élection. Un routeur qui démarre attend la durée de l'intervalle Dead (*Wait timer*) avant de
se déclarer DR ou BDR.

### @@sec:router-id@@ Le router-id

Le **router-id** identifie le routeur dans la base de données ; il s'écrit comme une adresse
IPv4 mais n'en est pas une. S'il n'est pas configuré (`ospf router-id A.B.C.D`, mode
`router ospf`), FRR prend la plus grande adresse IP des interfaces du routeur au démarrage. Si
des adjacences sont déjà établies, un changement de router-id n'est appliqué qu'après
`clear ip ospf process` : mieux vaut le fixer avant les commandes `network`.

### @@sec:timers@@ Temporisateurs et convergence

Un routeur envoie un Hello sur chaque interface toutes les **10 s** (*intervalle Hello*) et
déclare un voisin mort s'il n'en a rien reçu pendant **40 s** (*intervalle Dead*, quatre Hello
par défaut). Ils se règlent par interface (`ip ospf hello-interval N`, `ip ospf dead-interval N`)
et doivent être **identiques aux deux extrémités** : sinon les Hello du voisin sont ignorés et
l'adjacence tombe à l'expiration de l'intervalle Dead.

Le temps de **convergence** après une panne dépend de la façon dont elle est détectée :

- **coupure franche** (l'interface passe à l'état *down*) : le routeur le sait immédiatement,
  inonde un nouveau LSA et tous recalculent leurs routes — une à deux secondes ;
- **panne silencieuse** (l'interface reste *up* mais le voisin ne répond plus : switch
  intermédiaire, filtre, processus bloqué) : seule l'absence de Hello la révèle, au bout de
  l'intervalle Dead.

Réduire les temporisateurs accélère la détection au prix de plus de trafic et de fausses
alertes sur un lien chargé ; les réseaux qui visent une détection en moins d'une seconde
utilisent BFD (*Bidirectional Forwarding Detection*).

### @@sec:auth@@ Authentification

Sans authentification, n'importe quelle machine branchée sur un lien peut se faire passer pour
un routeur et injecter des LSA. OSPFv2 prévoit trois modes : aucun (par défaut), mot de passe
en clair, et **MD5** : chaque paquet porte un condensat calculé avec une clé partagée (les
paquets sont signés, pas chiffrés). En mode interface :

```
ip ospf authentication message-digest          # mode MD5 sur cette interface
ip ospf message-digest-key 1 md5 SECRET        # clé numéro 1 (16 caractères au plus)
```

Le numéro de clé et la clé doivent être les mêmes aux deux extrémités ; `area N authentication
message-digest` (mode `router ospf`) active le mode MD5 sur toutes les interfaces d'une aire,
les clés restant à définir par interface. Un paquet mal authentifié est ignoré : l'adjacence
tombe à l'expiration de l'intervalle Dead et le journal de FRR signale l'erreur. MD5 est
aujourd'hui considéré comme faible ; la RFC 5709 le remplace par HMAC-SHA.
""": """
Two routers become neighbours if their Hellos are compatible: same **area**, same **Hello
interval**, same **Dead interval**, same network type, same area type (stub or not), same
authentication, same prefix on the link. The relationship goes through the states `Down`,
`Init` (I hear the neighbour), `2-Way` (it hears me too), `ExStart`, `Exchange`, `Loading`
(exchange of the databases) and finally **`Full`** (databases synchronised).

### @@sec:dr@@ DR and BDR

On a broadcast network (Ethernet) the routers elect a **DR** (*Designated Router*) and a **BDR**
(*Backup DR*); the other routers (`DROther`) form a full adjacency only with the DR and the BDR
(they stay in `2-Way` with each other), which limits the number of adjacencies and the flooding
traffic. The DR describes the network in a type 2 LSA; the `DROther` routers write to it at the
address `224.0.0.6`. The election is based on the **priority** (`ip ospf priority N` in
interface mode, 1 by default, 0 = never DR nor BDR) then, at equal priority, on the highest
**router-id**. It is **not preemptive**: a router that arrives with a better priority does not
dethrone the DR in place; the process must be restarted (`clear ip ospf process`) on the routers
that hold the roles to trigger a new election. A router that starts waits for the length of the
Dead interval (*Wait timer*) before declaring itself DR or BDR.

### @@sec:router-id@@ The router-id

The **router-id** identifies the router in the database; it is written like an IPv4 address but
is not one. If it is not configured (`ospf router-id A.B.C.D`, `router ospf` mode), FRR takes
the highest IP address of the router's interfaces at start-up. If adjacencies are already
established, a change of router-id is only applied after `clear ip ospf process`: it is better
to set it before the `network` commands.

### @@sec:timers@@ Timers and convergence

A router sends a Hello on each interface every **10 s** (*Hello interval*) and declares a
neighbour dead if it has received nothing from it for **40 s** (*Dead interval*, four Hellos by
default). They are set per interface (`ip ospf hello-interval N`, `ip ospf dead-interval N`)
and must be **identical at both ends**: otherwise the neighbour's Hellos are ignored and the
adjacency drops when the Dead interval expires.

The **convergence** time after a failure depends on how it is detected:

- **clean cut** (the interface goes *down*): the router knows it immediately, floods a new LSA
  and all the routers recompute their routes — one to two seconds;
- **silent failure** (the interface stays *up* but the neighbour no longer answers: switch in
  between, filter, blocked process): only the absence of Hellos reveals it, after the Dead
  interval.

Lowering the timers speeds up detection at the cost of more traffic and of false alarms on a
loaded link; networks that aim at a detection in less than a second use BFD (*Bidirectional
Forwarding Detection*).

### @@sec:auth@@ Authentication

Without authentication, any machine plugged into a link can pose as a router and inject LSAs.
OSPFv2 provides three modes: none (the default), clear-text password, and **MD5**: each packet
carries a digest computed with a shared key (the packets are signed, not encrypted). In
interface mode:

```
ip ospf authentication message-digest          # MD5 mode on this interface
ip ospf message-digest-key 1 md5 SECRET        # key number 1 (16 characters at most)
```

The key number and the key must be the same at both ends; `area N authentication
message-digest` (`router ospf` mode) enables MD5 mode on all the interfaces of an area, the keys
still having to be defined per interface. A badly authenticated packet is ignored: the adjacency
drops when the Dead interval expires and the FRR log reports the error. MD5 is now considered
weak; RFC 5709 replaces it with HMAC-SHA.
""",
    "Aires et types de routes": "Areas and route types",
    """
Pour limiter la taille des bases de données et le nombre de calculs SPF, un domaine OSPF
est découpé en **aires**. L'aire **0** (`0.0.0.0`) est le **backbone** ; toute autre aire
doit lui être directement rattachée par au moins un **ABR** (*Area Border Router*), qui
possède des interfaces dans les deux aires et **résume** les réseaux d'une aire vers l'autre.
Une interface appartient à une seule aire (`network PREFIXE area N` en mode `router ospf`, ou
`ip ospf area N` en mode interface) ; les deux extrémités d'un lien sont dans la même aire.

| LSA | nom | émis par | portée |
|-----|-----|----------|--------|
| type 1 | *Router* | chaque routeur : ses liens et leurs coûts | son aire |
| type 2 | *Network* | le DR d'un réseau à diffusion : les routeurs du réseau | son aire |
| type 3 | *Summary* | un ABR : un préfixe d'une autre aire | une aire |
| type 4 | *ASBR Summary* | un ABR : où se trouve un ASBR d'une autre aire | une aire |
| type 5 | *AS External* | un ASBR : un préfixe extérieur au domaine | tout le domaine, hors aires stub |

Les routes calculées se classent en quatre types, par ordre de préférence :

| type | `show ip ospf route` (FRR) | notation usuelle | signification |
|------|----------------------------|------------------|---------------|
| intra-aire | `N` | `O` | réseau de l'une des aires du routeur |
| inter-aire | `N IA` | `O IA` | réseau d'une autre aire, résumé par un ABR |
| externe de type 1 | `N E1` | `O E1` | métrique = coût externe + coût interne jusqu'à l'ASBR |
| externe de type 2 | `N E2` | `O E2` | métrique = coût externe seul, quel que soit l'éloignement de l'ASBR |

`show ip route` (la table de zebra) marque toutes ces routes d'un simple `O`, suivi de
`[110/métrique]`.

### @@sec:range@@ Agrégation

Un ABR peut **agréger** les préfixes d'une aire : `area N range PREFIXE` (mode `router ospf`)
remplace, dans ce qu'il annonce aux autres aires, tous les réseaux de l'aire N contenus dans
PREFIXE par ce seul préfixe. Les tables des autres aires sont plus courtes et une instabilité
à l'intérieur de l'aire N ne s'y propage plus. Le plan d'adressage doit s'y prêter : des
réseaux contigus, contenus dans un préfixe qui ne couvre rien d'autre.

### @@sec:external@@ Routes externes

Un **ASBR** (*AS Boundary Router*) injecte dans OSPF des routes venues d'ailleurs (routes
statiques, réseaux connectés hors OSPF, autre protocole) sous forme de LSA de type 5 :

```
router ospf
 redistribute static                 # les routes statiques de FRR (« ip route … » dans vtysh)
 redistribute connected              # les réseaux connectés qui ne sont pas dans OSPF
 default-information originate       # annonce la route par défaut que possède le routeur
```

Les routes redistribuées sont de type **E2** avec une métrique de 20 par défaut
(`redistribute static metric N metric-type 1` pour les changer). `redistribute static` ne
concerne que les routes statiques déclarées dans FRR : une route ajoutée par `ip route add`
est une route du noyau (`redistribute kernel`).

### @@sec:stub@@ Aires stub

Une aire **stub** (`area N stub` sur **tous** ses routeurs : c'est un champ des Hello, deux
voisins en désaccord ne forment pas d'adjacence) ne reçoit pas les routes externes : l'ABR y
injecte à la place une route par défaut inter-aire. Une aire ***totally stubby***
(`area N stub no-summary`, sur l'ABR seulement) ne reçoit même plus les routes inter-aires :
ses routeurs ne connaissent que leur aire et la route par défaut. Une aire stub ne peut pas
contenir d'ASBR ni être le backbone.
""": """
To limit the size of the databases and the number of SPF computations, an OSPF domain is divided
into **areas**. Area **0** (`0.0.0.0`) is the **backbone**; every other area must be directly
attached to it by at least one **ABR** (*Area Border Router*), which has interfaces in both areas
and **summarises** the networks of one area towards the other. An interface belongs to a single
area (`network PREFIX area N` in `router ospf` mode, or `ip ospf area N` in interface mode); both
ends of a link are in the same area.

| LSA | name | originated by | scope |
|-----|-----|----------|--------|
| type 1 | *Router* | every router: its links and their costs | its area |
| type 2 | *Network* | the DR of a broadcast network: the routers of the network | its area |
| type 3 | *Summary* | an ABR: a prefix of another area | one area |
| type 4 | *ASBR Summary* | an ABR: where an ASBR of another area is | one area |
| type 5 | *AS External* | an ASBR: a prefix outside the domain | the whole domain, except stub areas |

The computed routes fall into four types, in order of preference:

| type | `show ip ospf route` (FRR) | usual notation | meaning |
|------|----------------------------|------------------|---------------|
| intra-area | `N` | `O` | network of one of the router's areas |
| inter-area | `N IA` | `O IA` | network of another area, summarised by an ABR |
| external type 1 | `N E1` | `O E1` | metric = external cost + internal cost to the ASBR |
| external type 2 | `N E2` | `O E2` | metric = external cost only, however far away the ASBR is |

`show ip route` (zebra's table) marks all these routes with a plain `O`, followed by
`[110/metric]`.

### @@sec:range@@ Summarisation

An ABR can **summarise** the prefixes of an area: `area N range PREFIX` (`router ospf` mode)
replaces, in what it announces to the other areas, all the networks of area N contained in
PREFIX with this single prefix. The tables of the other areas are shorter and an instability
inside area N no longer spreads to them. The addressing plan must lend itself to it: contiguous
networks, contained in a prefix that covers nothing else.

### @@sec:external@@ External routes

An **ASBR** (*AS Boundary Router*) injects into OSPF routes that come from elsewhere (static
routes, connected networks outside OSPF, another protocol) as type 5 LSAs:

```
router ospf
 redistribute static                 # FRR's static routes ("ip route …" in vtysh)
 redistribute connected              # the connected networks that are not in OSPF
 default-information originate       # announces the default route the router has
```

Redistributed routes are of type **E2** with a metric of 20 by default
(`redistribute static metric N metric-type 1` to change them). `redistribute static` only
concerns the static routes declared in FRR: a route added with `ip route add` is a kernel route
(`redistribute kernel`).

### @@sec:stub@@ Stub areas

A **stub** area (`area N stub` on **all** its routers: it is a field of the Hellos, two
neighbours that disagree do not form an adjacency) does not receive the external routes: the ABR
injects an inter-area default route into it instead. A ***totally stubby*** area
(`area N stub no-summary`, on the ABR only) does not even receive the inter-area routes any
more: its routers only know their own area and the default route. A stub area can neither
contain an ASBR nor be the backbone.
""",
    "FRR et vtysh": "FRR and vtysh",
    """
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` (l'interface avec
le noyau : il y installe les routes choisies), `staticd` (les routes statiques) et un démon par
protocole, ici `ospfd` (`systemctl status frr` ; les démons lancés sont choisis dans
`/etc/frr/daemons`). On les configure avec le shell **`vtysh`**, dont la syntaxe est proche de
celle des équipements Cisco :

```
vtysh                              # ouvre le shell (prompt : routeur#)
show running-config                # configuration courante
configure terminal                 # passe en mode configuration (prompt : routeur(config)#)
 router ospf                       #   processus OSPF (prompt : routeur(config-router)#)
  ospf router-id 192.0.2.1
  network 198.51.100.0/24 area 0   #   active OSPF sur les interfaces de ce réseau, dans l'aire 0
  passive-interface eth0           #   n'envoie pas de Hello sur eth0 (mais annonce son réseau)
  exit
 interface eth1                    #   paramètres d'une interface (prompt : routeur(config-if)#)
  ip ospf cost 50
  exit
 end                               # retour au mode privilégié
write                              # sauvegarde dans /etc/frr/frr.conf
```

On supprime une ligne de configuration en la préfixant par `no` (`no network … area 0`).
Une commande peut aussi être passée directement depuis le shell Linux :
`vtysh -c "show ip ospf neighbor"`. Une interface **passive** est annoncée dans OSPF mais
n'émet aucun Hello : c'est le réglage d'un réseau d'hôtes, où aucun routeur n'est attendu
(`show running-config` l'écrit `ip ospf passive` sous l'interface).

Commandes d'observation utiles :

```
show ip ospf                       # router-id, aires, rôle ABR/ASBR
show ip ospf interface [ethX]      # aire, coût, état DR/BDR/DROther, temporisateurs, voisins
show ip ospf neighbor              # voisins et état de la relation
show ip ospf database              # base de données des LSA
show ip ospf route                 # table de routage calculée par OSPF (N, N IA, N E1, N E2)
show ip route                      # table de routage complète (vue de zebra)
clear ip ospf process              # redémarre le processus OSPF (mode privilégié)
```

Documentation : [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html) et
[vtysh](https://docs.frrouting.org/en/latest/vtysh.html).
""": """
**FRRouting** (FRR) is a suite of routing daemons for Linux: `zebra` (the interface with the
kernel: it installs the chosen routes there), `staticd` (the static routes) and one daemon per
protocol, here `ospfd` (`systemctl status frr`; the daemons started are chosen in
`/etc/frr/daemons`). They are configured with the **`vtysh`** shell, whose syntax is close to
that of Cisco equipment:

```
vtysh                              # opens the shell (prompt: router#)
show running-config                # current configuration
configure terminal                 # enters configuration mode (prompt: router(config)#)
 router ospf                       #   OSPF process (prompt: router(config-router)#)
  ospf router-id 192.0.2.1
  network 198.51.100.0/24 area 0   #   enables OSPF on the interfaces of this network, in area 0
  passive-interface eth0           #   sends no Hello on eth0 (but announces its network)
  exit
 interface eth1                    #   settings of an interface (prompt: router(config-if)#)
  ip ospf cost 50
  exit
 end                               # back to privileged mode
write                              # saves to /etc/frr/frr.conf
```

A configuration line is removed by prefixing it with `no` (`no network … area 0`). A command can
also be passed directly from the Linux shell: `vtysh -c "show ip ospf neighbor"`. A **passive**
interface is announced in OSPF but sends no Hello: it is the setting for a host network, where no
router is expected (`show running-config` writes it `ip ospf passive` under the interface).

Useful observation commands:

```
show ip ospf                       # router-id, areas, ABR/ASBR role
show ip ospf interface [ethX]      # area, cost, DR/BDR/DROther state, timers, neighbours
show ip ospf neighbor              # neighbours and state of the relationship
show ip ospf database              # LSA database
show ip ospf route                 # routing table computed by OSPF (N, N IA, N E1, N E2)
show ip route                      # complete routing table (zebra's view)
clear ip ospf process              # restarts the OSPF process (privileged mode)
```

Documentation: [FRR — OSPFv2](https://docs.frrouting.org/en/latest/ospfd.html) and
[vtysh](https://docs.frrouting.org/en/latest/vtysh.html).
""",
    "Diagnostic": "Troubleshooting",
    """
- `ip route` sur un routeur ou un hôte : les routes apprises par OSPF portent `proto ospf` ;
- `traceroute -n IP` depuis un hôte : chemin réellement suivi ;
- `tcpdump -ni ethX ip proto 89` : observation des paquets OSPF (un Hello par intervalle) ;
- `/var/log/frr/frr.log` : journal des démons FRR.

| symptôme | causes à vérifier |
|----------|-------------------|
| aucun voisin sur un lien | OSPF pas activé sur l'interface (`network`), interface passive, aires différentes, temporisateurs ou authentification différents, aire stub d'un seul côté |
| voisin bloqué en `Init` | il ne reçoit pas nos Hello (filtre, authentification) |
| voisin en `2-Way` | normal entre deux `DROther` d'un réseau à diffusion |
| voisin bloqué en `ExStart` / `Exchange` | MTU différentes aux deux extrémités |
| voisins `Full` mais route absente | réseau non annoncé (`network`), agrégation, aire stub, route non redistribuée |
| le DR n'est pas celui attendu | élection non préemptive : `clear ip ospf process` sur le DR et le BDR en place |
""": """
- `ip route` on a router or a host: the routes learnt through OSPF carry `proto ospf`;
- `traceroute -n IP` from a host: the path actually followed;
- `tcpdump -ni ethX ip proto 89`: observing the OSPF packets (one Hello per interval);
- `/var/log/frr/frr.log`: log of the FRR daemons.

| symptom | causes to check |
|----------|-------------------|
| no neighbour on a link | OSPF not enabled on the interface (`network`), passive interface, different areas, different timers or authentication, stub area on one side only |
| neighbour stuck in `Init` | it does not receive our Hellos (filter, authentication) |
| neighbour in `2-Way` | normal between two `DROther` routers of a broadcast network |
| neighbour stuck in `ExStart` / `Exchange` | different MTUs at the two ends |
| neighbours `Full` but route missing | network not announced (`network`), summarisation, stub area, route not redistributed |
| the DR is not the expected one | non-preemptive election: `clear ip ospf process` on the DR and the BDR in place |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente OSPF (état de liens, coûts, voisinage, DR et BDR,
aires, routes externes, authentification, temporisateurs), la configuration de FRR avec `vtysh`
et les commandes de diagnostic.

**Le réseau.** Ce TP met en œuvre OSPF avec la suite logicielle **FRRouting** (FRR), installée
et démarrée sur les sept routeurs `r1` à `r7`. Les machines `m1`, `m4`, `m5`, `m6` et `m7` sont
de simples hôtes dont la route par défaut pointe vers leur routeur. Le domaine sera découpé en
trois aires, repérées par les couleurs du schéma : l'aire 0 en bleu (`r1` à `r4`), l'aire 1 en
vert (`r5`) et l'aire 2 en jaune (`r6` et `r7`) ; `r3` et `r4` seront à cheval sur deux aires.

- **Au départ**, `r1` et `r2` sont déjà configurés (aire 0). Les routeurs `r3` à `r7` ont FRR
  démarré mais **aucune configuration OSPF** : c'est vous qui les configurez.
- Les fichiers `/etc/hosts` contiennent les noms de toutes les interfaces : `r4-eth2` désigne
  l'adresse de l'interface `eth2` de `r4`, `r4` (tout court) celle de `eth0` ; `traceroute`
  (sans `-n`) affiche ces noms.
- L'adresse `{ext_host}` (nom `internet`) est un serveur situé « à l'extérieur », derrière `r1`
  (réseau `ext`, qui ne fait pas partie du domaine OSPF).

**Plan d'adressage.**

| réseau | préfixe | aire | interfaces |
|--------|---------|------|------------|
{addressing}

**Consignes.**

- Les parties sont à faire **dans l'ordre** : chaque partie s'appuie sur la configuration
  réalisée dans les précédentes, qui reste en place.
- Pour chaque routeur que vous configurez, utilisez le router-id **`X.X.X.X`** pour `rX` (par
  exemple `3.3.3.3` pour `r3`), à définir **avant** les commandes `network`.
- Sauvegardez régulièrement la configuration des routeurs (`write` dans vtysh) : elle est
  conservée dans `/etc/frr/frr.conf`.

**Plan du TP.**

1. **Découverte** d'OSPF sur `r1` et `r2`, déjà configurés ;
2. **Aire 0** : configuration de `r3` et `r4`, chemins de coût égal ;
3. **Coûts** : coût d'une interface, bande passante de référence, choix des chemins ;
4. **DR et BDR** : élection sur le réseau `core` ;
5. **Aire 2** (`r6`, `r7`) et **agrégation** de ses préfixes ;
6. **Routes externes** : `r1` devient ASBR ;
7. **Aire stub** : l'aire 1 (`r5`) ;
8. **Authentification** MD5 d'un lien ;
9. **Temporisateurs** et temps de convergence.

**Évaluation.** Chaque évaluation lit vos réponses et l'état des routeurs (voisinages, tables
de routage, configuration) et lance des `ping` entre les hôtes. Les valeurs numériques demandées
(coûts, clé, temporisateurs) sont propres à votre instance du TP. Une adjacence met jusqu'à une
minute à s'établir, l'élection d'un DR une minute et demie : attendez que les voisins soient
`Full` avant de lancer une évaluation.
""": """
Read the **Informations** tab: it presents OSPF (link state, costs, neighbours, DR and BDR,
areas, external routes, authentication, timers), the configuration of FRR with `vtysh` and the
troubleshooting commands.

**The network.** This lab puts OSPF into practice with the **FRRouting** (FRR) software suite,
installed and started on the seven routers `r1` to `r7`. The machines `m1`, `m4`, `m5`, `m6` and
`m7` are plain hosts whose default route points to their router. The domain will be divided into
three areas, shown by the colours of the diagram: area 0 in blue (`r1` to `r4`), area 1 in green
(`r5`) and area 2 in yellow (`r6` and `r7`); `r3` and `r4` will straddle two areas.

- **At the start**, `r1` and `r2` are already configured (area 0). The routers `r3` to `r7` have
  FRR started but **no OSPF configuration**: you are the one who configures them.
- The `/etc/hosts` files contain the names of all the interfaces: `r4-eth2` is the address of
  the `eth2` interface of `r4`, `r4` (on its own) that of `eth0`; `traceroute` (without `-n`)
  displays these names.
- The address `{ext_host}` (name `internet`) is a server located "outside", behind `r1`
  (network `ext`, which is not part of the OSPF domain).

**Addressing plan.**

| network | prefix | area | interfaces |
|--------|---------|------|------------|
{addressing}

**Instructions.**

- The parts must be done **in order**: each part builds on the configuration made in the
  previous ones, which stays in place.
- For each router you configure, use the router-id **`X.X.X.X`** for `rX` (for example
  `3.3.3.3` for `r3`), to be set **before** the `network` commands.
- Save the configuration of the routers regularly (`write` in vtysh): it is kept in
  `/etc/frr/frr.conf`.

**Outline of the lab.**

1. **Discovery** of OSPF on `r1` and `r2`, already configured;
2. **Area 0**: configuration of `r3` and `r4`, equal-cost paths;
3. **Costs**: cost of an interface, reference bandwidth, choice of the paths;
4. **DR and BDR**: election on the `core` network;
5. **Area 2** (`r6`, `r7`) and **summarisation** of its prefixes;
6. **External routes**: `r1` becomes an ASBR;
7. **Stub area**: area 1 (`r5`);
8. MD5 **authentication** of a link;
9. **Timers** and convergence time.

**Evaluation.** Each evaluation reads your answers and the state of the routers (neighbours,
routing tables, configuration) and runs `ping`s between the hosts. The numeric values asked for
(costs, key, timers) are specific to your instance of the lab. An adjacency takes up to a minute
to come up, the election of a DR a minute and a half: wait until the neighbours are `Full`
before running an evaluation.
""",
    """
**Pour l'enseignant.** Valeurs de cette instance : coût imposé sur `l14` **{cost}** ; bande
passante de référence **{ref} Mbit/s** (coût d'une interface à 10 Gbit/s : {auto_cost}) ; clé MD5
`{key}` ; Hello / Dead sur `l24` : **{hello} s / {dead} s** ; préfixe agrégé de l'aire 2 :
`{range}` ; router-id automatique de `r2` : `{rid_r2}`. Chaque question se termine par sa solution
pour ces valeurs.

L'état `final` (onglet *Appliquer une configuration*) applique toute la solution — configuration
de `r3` à `r7`, modifications de `r1` et `r2`, puis `clear ip ospf process` sur `r1` et `r2` pour
l'élection du DR — et remplit les formulaires. Attendez environ 90 s après l'avoir appliqué avant
de lancer une évaluation : le temps que les adjacences soient de nouveau `Full`.
""": """
**For the instructor.** Values of this instance: cost imposed on `l14` **{cost}**; reference
bandwidth **{ref} Mbit/s** (cost of a 10 Gbit/s interface: {auto_cost}); MD5 key `{key}`;
Hello / Dead on `l24`: **{hello} s / {dead} s**; summary prefix of area 2: `{range}`; automatic
router-id of `r2`: `{rid_r2}`. Each question ends with its solution for these values.

The `final` state (*Apply Configuration* tab) applies the whole solution — configuration of `r3`
to `r7`, changes to `r1` and `r2`, then `clear ip ospf process` on `r1` and `r2` for the DR
election — and fills in the forms. Wait about 90 s after applying it before running an
evaluation: the time it takes for the adjacencies to be `Full` again.
""",
    "Partie 1 — Découverte d'OSPF sur r1 et r2": "Part 1 — Discovering OSPF on r1 and r2",
    "Découverte d'OSPF sur r1 et r2": "Discovering OSPF on r1 and r2",
    """
Sur `r1` et `r2`, ouvrez `vtysh` et explorez la configuration en place (`show running-config`)
ainsi que les commandes `show ip ospf`, `show ip ospf interface`, `show ip ospf neighbor` et
`show ip ospf database`. Vérifiez depuis `m1` que vous ne joignez aucune autre machine `mX`
pour l'instant.

- router-id de `r2` (aucun n'est configuré : d'où vient cette valeur ?) : @@{rid_r2:[0-9.]+}@@
- coût OSPF de l'interface `eth1` de `r1` : @@{cost:[0-9]+}@@
- intervalle **Hello** en secondes : @@{hello:[0-9]+}@@  et intervalle **Dead** : @@{dead:[0-9]+}@@
- état de la relation entre `r1` et `r2` : @@{state:>Down|Init|2-Way|ExStart|Exchange|Loading|Full}@@
- adresse multicast de destination des paquets Hello (à observer avec `tcpdump`) :
  @@{mcast:>224.0.0.5|224.0.0.6|224.0.0.9|255.255.255.255}@@
  et numéro de protocole IP utilisé par OSPF : @@{proto:[0-9]+}@@
""": """
On `r1` and `r2`, open `vtysh` and explore the configuration in place (`show running-config`)
as well as the commands `show ip ospf`, `show ip ospf interface`, `show ip ospf neighbor` and
`show ip ospf database`. Check from `m1` that you cannot reach any other `mX` machine for the
time being.

- router-id of `r2` (none is configured: where does this value come from?): @@{rid_r2:[0-9.]+}@@
- OSPF cost of the `eth1` interface of `r1`: @@{cost:[0-9]+}@@
- **Hello** interval in seconds: @@{hello:[0-9]+}@@  and **Dead** interval: @@{dead:[0-9]+}@@
- state of the relationship between `r1` and `r2`: @@{state:>Down|Init|2-Way|ExStart|Exchange|Loading|Full}@@
- multicast destination address of the Hello packets (to be observed with `tcpdump`):
  @@{mcast:>224.0.0.5|224.0.0.6|224.0.0.9|255.255.255.255}@@
  and IP protocol number used by OSPF: @@{proto:[0-9]+}@@
""",
    """
**Solution.** Rien à configurer : `vtysh -c "show ip ospf neighbor"` et
`vtysh -c "show ip ospf interface eth1"` sur `r1`, `tcpdump -ni eth1 ip proto 89` pour les Hello.

- router-id de `r2` : **`{rid_r2}`**, la plus grande adresse IP de ses interfaces au démarrage
  de FRR (aucun `ospf router-id` dans sa configuration ; `r1` a `1.1.1.1`, configuré) ;
- coût de `eth1` de `r1` : **10** (référence 100 000 Mbit/s ÷ 10 000 Mbit/s annoncés par
  l'interface) ;
- Hello **10** s, Dead **40** s ;
- état **Full** : sur `core`, `r2` est DR (plus grand router-id) et `r1` BDR ;
- Hello envoyés à **224.0.0.5** (tous les routeurs OSPF ; `224.0.0.6` est l'adresse du DR et du
  BDR), protocole IP **89**.

`m1` ne joint aucune autre machine `mX` : leurs routeurs n'annoncent encore rien, `r1` ne connaît
que `net1`, `core`, `l14` et `l24`.

Évaluation : `decouverte_router_id_r2` (1 point : la réponse est comparée au router-id lu sur
`r2`), `decouverte_cout_defaut` (1), `decouverte_timers` (1), `decouverte_multicast_proto_typed`
(0,5 : protocole 89), et, pour l'évaluation de l'enseignant seulement (choix dans une liste),
`decouverte_etat_voisin` (1) et `decouverte_multicast_proto` (0,5 : adresse 224.0.0.5).
""": """
**Solution.** Nothing to configure: `vtysh -c "show ip ospf neighbor"` and
`vtysh -c "show ip ospf interface eth1"` on `r1`, `tcpdump -ni eth1 ip proto 89` for the Hellos.

- router-id of `r2`: **`{rid_r2}`**, the highest IP address of its interfaces when FRR started
  (no `ospf router-id` in its configuration; `r1` has `1.1.1.1`, configured);
- cost of `eth1` of `r1`: **10** (reference 100,000 Mbit/s ÷ 10,000 Mbit/s announced by the
  interface);
- Hello **10** s, Dead **40** s;
- state **Full**: on `core`, `r2` is DR (highest router-id) and `r1` BDR;
- Hellos sent to **224.0.0.5** (all OSPF routers; `224.0.0.6` is the address of the DR and the
  BDR), IP protocol **89**.

`m1` reaches no other `mX` machine: their routers do not announce anything yet, `r1` only knows
`net1`, `core`, `l14` and `l24`.

Evaluation: `decouverte_router_id_r2` (1 point: the answer is compared with the router-id read on
`r2`), `decouverte_cout_defaut` (1), `decouverte_timers` (1), `decouverte_multicast_proto_typed`
(0.5: protocol 89), and, for the instructor's evaluation only (choice from a list),
`decouverte_etat_voisin` (1) and `decouverte_multicast_proto` (0.5: address 224.0.0.5).
""",
    "router-id de r2": "router-id of r2",
    "coût par défaut d'une interface": "default cost of an interface",
    "intervalles Hello et Dead par défaut": "default Hello and Dead intervals",
    "état de la relation r1–r2": "state of the r1–r2 relationship",
    "numéro de protocole d'OSPF": "OSPF protocol number",
    "adresse multicast d'OSPF": "OSPF multicast address",
    "Partie 2 — Aire 0 : configuration de r3 et r4": "Part 2 — Area 0: configuring r3 and r4",
    "Aire 0 : configuration de r3 et r4": "Area 0: configuring r3 and r4",
    """
Configurez OSPF dans l'aire 0 sur les routeurs `r3` et `r4` :

- `r3` : router-id `3.3.3.3`, interface `eth0` (réseau `core` `{core}`) ;
- `r4` : router-id `4.4.4.4`, interfaces `eth0` (réseau `net4` `{net4}`), `eth1` (lien vers
  `r1`, `{l14}`) et `eth2` (lien vers `r2`, `{l24}`). L'interface `eth0` mène à un réseau
  d'hôtes sans routeur : déclarez-la **passive** (le réseau est annoncé mais aucun Hello n'y
  est envoyé). Ne touchez pas encore à `eth3`.

Vérifiez que `r3` et `r4` ont bien des voisins en état `Full`, que `m1` et `m4` se joignent
(`ping`, `traceroute`) et observez la table de routage de `r3` (`ip route`, `show ip ospf route`).
""": """
Configure OSPF in area 0 on the routers `r3` and `r4`:

- `r3`: router-id `3.3.3.3`, interface `eth0` (network `core` `{core}`);
- `r4`: router-id `4.4.4.4`, interfaces `eth0` (network `net4` `{net4}`), `eth1` (link to
  `r1`, `{l14}`) and `eth2` (link to `r2`, `{l24}`). The `eth0` interface leads to a host network
  without a router: declare it **passive** (the network is announced but no Hello is sent on
  it). Do not touch `eth3` yet.

Check that `r3` and `r4` do have neighbours in the `Full` state, that `m1` and `m4` reach each
other (`ping`, `traceroute`) and look at the routing table of `r3` (`ip route`,
`show ip ospf route`).
""",
    """
**Solution.** Dans `vtysh`, après `configure terminal` (puis `end` et `write`) :

```
! r3
router ospf
 ospf router-id {rid_r3}
 network {core} area 0
!
! r4
router ospf
 ospf router-id {rid_r4}
 passive-interface eth0
 network {net4} area 0
 network {l14} area 0
 network {l24} area 0
```

- `show ip ospf neighbor` sur `r3` : `r1` et `r2` en `Full` (le DR et le BDR de `core` ; `r3`,
  arrivé après l'élection, est `DROther`) ; sur `r4` : `r1` par `eth1` et `r2` par `eth2`.
- `show running-config` réécrit `passive-interface eth0` en `ip ospf passive` sous
  `interface eth0` ; `show ip ospf interface eth0` affiche *No Hellos (Passive interface)*.
- Le router-id est donné avant les `network` : défini après, il ne serait pris en compte
  qu'après `clear ip ospf process`.

Évaluation : `aire0_r3_voisins` (2 points : `r3` voit `r1` et `r2` en `Full`), `aire0_r4_voisins`
(2 : `r4` voit `r1` par `eth1` et `r2` par `eth2`), `aire0_router_ids` (1), `aire0_r4_eth0_passive`
(1 : `eth0` de `r4` est dans OSPF et passive), `aire0_pings_m1_m4` (2 : `ping` dans les deux sens).
""": """
**Solution.** In `vtysh`, after `configure terminal` (then `end` and `write`):

```
! r3
router ospf
 ospf router-id {rid_r3}
 network {core} area 0
!
! r4
router ospf
 ospf router-id {rid_r4}
 passive-interface eth0
 network {net4} area 0
 network {l14} area 0
 network {l24} area 0
```

- `show ip ospf neighbor` on `r3`: `r1` and `r2` in `Full` (the DR and the BDR of `core`; `r3`,
  which arrived after the election, is `DROther`); on `r4`: `r1` through `eth1` and `r2` through
  `eth2`.
- `show running-config` rewrites `passive-interface eth0` as `ip ospf passive` under
  `interface eth0`; `show ip ospf interface eth0` displays *No Hellos (Passive interface)*.
- The router-id is given before the `network` commands: set afterwards, it would only be taken
  into account after `clear ip ospf process`.

Evaluation: `aire0_r3_voisins` (2 points: `r3` sees `r1` and `r2` in `Full`), `aire0_r4_voisins`
(2: `r4` sees `r1` through `eth1` and `r2` through `eth2`), `aire0_router_ids` (1),
`aire0_r4_eth0_passive` (1: `eth0` of `r4` is in OSPF and passive), `aire0_pings_m1_m4` (2: `ping`
in both directions).
""",
    "Chemins de coût égal": "Equal-cost paths",
    """
Sur `r3`, combien la route vers le réseau `net4` (`{net4}`) possède-t-elle de prochains sauts
(*nexthop*) ? Expliquez-le à partir des coûts des chemins possibles : @@{{nexthops:[0-9]+}}@@
""": """
On `r3`, how many next hops (*nexthop*) does the route to the network `net4` (`{net4}`) have?
Explain it from the costs of the possible paths: @@{{nexthops:[0-9]+}}@@
""",
    """
**Solution.** **2** prochains sauts : `ip route show {net4}` sur `r3` affiche deux `nexthop`,
`{r1_core}` (`r1`) et `{r2_core}` (`r2`). Les deux chemins ont le même coût, 30 : sortie de `r3`
par `core` (10), puis `r1` → `l14` (10) ou `r2` → `l24` (10), puis `r4` → `net4` (10). À coût
égal, OSPF installe tous les prochains sauts (ECMP).

Évaluation : `aire0_ecmp_r3` (1 point).
""": """
**Solution.** **2** next hops: `ip route show {net4}` on `r3` displays two `nexthop`,
`{r1_core}` (`r1`) and `{r2_core}` (`r2`). Both paths have the same cost, 30: out of `r3` through
`core` (10), then `r1` → `l14` (10) or `r2` → `l24` (10), then `r4` → `net4` (10). At equal cost,
OSPF installs all the next hops (ECMP).

Evaluation: `aire0_ecmp_r3` (1 point).
""",
    "r3 est en état Full avec r1 et r2": "r3 is in the Full state with r1 and r2",
    "r4 est en état Full avec r1 (eth1) et r2 (eth2)": "r4 is in the Full state with r1 (eth1) and r2 (eth2)",
    "router-id 3.3.3.3 et 4.4.4.4": "router-id 3.3.3.3 and 4.4.4.4",
    "eth0 de r4 est annoncée dans OSPF et passive": "eth0 of r4 is announced in OSPF and passive",
    "m1 et m4 se joignent": "m1 and m4 reach each other",
    "nombre de prochains sauts de r3 vers net4": "number of next hops from r3 to net4",
    "Partie 3 — Coûts et choix des chemins": "Part 3 — Costs and choice of the paths",
    "Coûts et choix des chemins": "Costs and choice of the paths",
    """
Depuis `m4`, faites un `traceroute` vers `m1` : le trafic passe par le lien direct `r4`–`r1`.

1. Fixez à **{cost}** le coût du lien `l14` **aux deux extrémités** (`ip ospf cost` sur `eth2`
   de `r1` et sur `eth1` de `r4`) de façon que le trafic entre `m1` et `m4` passe par `r2`
   **dans les deux sens**. Vérifiez avec `traceroute` et `ip route` sur `r1` et `r4`.
2. Sur **tous** les routeurs OSPF de l'aire 0 (`r1` à `r4` ; pensez à le refaire sur ceux
   que vous configurerez ensuite), fixez la bande passante de référence à **{ref} Mbit/s**
   (`auto-cost reference-bandwidth`). Observez le nouveau coût des interfaces
   (`show ip ospf interface`) et vérifiez que le trafic `m1`–`m4` passe toujours par `r2`.
3. Sur `r3`, déclarez que l'interface `eth0` est un lien à **1000 Mbit/s** (commande
   `bandwidth`, mode interface) et observez le coût calculé.
""": """
From `m4`, run a `traceroute` to `m1`: the traffic goes through the direct link `r4`–`r1`.

1. Set the cost of the link `l14` to **{cost}** **at both ends** (`ip ospf cost` on `eth2` of
   `r1` and on `eth1` of `r4`) so that the traffic between `m1` and `m4` goes through `r2`
   **in both directions**. Check with `traceroute` and `ip route` on `r1` and `r4`.
2. On **all** the OSPF routers of area 0 (`r1` to `r4`; remember to do it again on those you
   configure later), set the reference bandwidth to **{ref} Mbit/s**
   (`auto-cost reference-bandwidth`). Look at the new cost of the interfaces
   (`show ip ospf interface`) and check that the `m1`–`m4` traffic still goes through `r2`.
3. On `r3`, declare that the `eth0` interface is a **1000 Mbit/s** link (`bandwidth` command,
   interface mode) and look at the computed cost.
""",
    """
**Solution.** Au départ `r4` joint `net1` par le lien direct `l14` : coût 20 (10 + 10), contre 30
par `r2`.

```
! étape 1 — r1
interface eth2
 ip ospf cost {cost}
! étape 1 — r4
interface eth1
 ip ospf cost {cost}
!
! étape 2 — r1, r2, r3 et r4
router ospf
 auto-cost reference-bandwidth {ref}
!
! étape 3 — r3
interface eth0
 bandwidth 1000
```

1. Le coût est celui de l'interface de **sortie** : celui de `eth1` de `r4` détourne le sens
   `m4` → `m1`, celui de `eth2` de `r1` le sens retour. Le chemin direct coûte alors {cost} + 10,
   contre 30 par `r2` : `ip route` montre `net1` par `{r2_l24}` sur `r4` et `net4` par
   `{r2_core}` sur `r1`.
2. Une interface à 10 Gbit/s passe du coût 10 au coût **{auto_cost}** ({ref} ÷ 10 000) ; `l14`
   garde {cost} (un coût fixé l'emporte). Le trafic passe toujours par `r2` : 3 × {auto_cost}
   contre {cost} + {auto_cost}. FRR rappelle que la référence doit être la même partout.
3. `eth0` de `r3` prend le coût **{bw_cost}** ({ref} ÷ 1000) : `show ip ospf interface eth0`.

Évaluation : `couts_l14_valeur` (1 point : coût {cost} lu aux deux extrémités),
`couts_chemin_r4_vers_net1` et `couts_chemin_r1_vers_net4` (1 chacun : la route du noyau n'a que
`r2` pour prochain saut), `couts_auto_cost_config` (2 : la référence dans la configuration des
quatre routeurs ; 1 point si deux ou trois l'ont), `couts_auto_cost_effet` (1 : le coût de `eth0`
de `r2` suit la nouvelle référence), `couts_bandwidth_r3` (1 : `bandwidth 1000` dans la
configuration de `r3` et coût correspondant).
""": """
**Solution.** At the start `r4` reaches `net1` through the direct link `l14`: cost 20 (10 + 10),
against 30 through `r2`.

```
! step 1 — r1
interface eth2
 ip ospf cost {cost}
! step 1 — r4
interface eth1
 ip ospf cost {cost}
!
! step 2 — r1, r2, r3 and r4
router ospf
 auto-cost reference-bandwidth {ref}
!
! step 3 — r3
interface eth0
 bandwidth 1000
```

1. The cost is that of the **outgoing** interface: the cost of `eth1` of `r4` diverts the
   `m4` → `m1` direction, that of `eth2` of `r1` the return direction. The direct path then costs
   {cost} + 10, against 30 through `r2`: `ip route` shows `net1` via `{r2_l24}` on `r4` and `net4`
   via `{r2_core}` on `r1`.
2. A 10 Gbit/s interface goes from cost 10 to cost **{auto_cost}** ({ref} ÷ 10,000); `l14` keeps
   {cost} (a fixed cost takes precedence). The traffic still goes through `r2`: 3 × {auto_cost}
   against {cost} + {auto_cost}. FRR reminds you that the reference must be the same everywhere.
3. `eth0` of `r3` gets the cost **{bw_cost}** ({ref} ÷ 1000): `show ip ospf interface eth0`.

Evaluation: `couts_l14_valeur` (1 point: cost {cost} read at both ends),
`couts_chemin_r4_vers_net1` and `couts_chemin_r1_vers_net4` (1 each: the kernel route has only
`r2` as next hop), `couts_auto_cost_config` (2: the reference in the configuration of the four
routers; 1 point if two or three have it), `couts_auto_cost_effet` (1: the cost of `eth0` of `r2`
follows the new reference), `couts_bandwidth_r3` (1: `bandwidth 1000` in the configuration of
`r3` and the matching cost).
""",
    "Vérification du chemin": "Checking the path",
    """
Après l'étape 1, par quel routeur passe le trafic de `m4` vers `m1` ? @@{via:>r1|r2|r3|r4}@@
""": """
After step 1, which router does the traffic from `m4` to `m1` go through? @@{via:>r1|r2|r3|r4}@@
""",
    """
**Solution.** Par **`r2`** : `traceroute m1` depuis `m4` affiche `r4`, `r2-eth1`, `r1-eth1` puis
`m1` (chaque routeur répond avec l'adresse de l'interface par laquelle sa réponse repart vers `m4`).

Évaluation : `couts_via_r2` (1 point, évaluation de l'enseignant seulement).
""": """
**Solution.** Through **`r2`**: `traceroute m1` from `m4` displays `r4`, `r2-eth1`, `r1-eth1` then
`m1` (each router answers with the address of the interface through which its reply goes back to
`m4`).

Evaluation: `couts_via_r2` (1 point, instructor's evaluation only).
""",
    "coût {cost} sur les deux extrémités de l14": "cost {cost} at both ends of l14",
    "r4 route net1 uniquement via r2": "r4 routes net1 via r2 only",
    "r1 route net4 uniquement via r2": "r1 routes net4 via r2 only",
    "routeur traversé après modification des coûts": "router crossed after changing the costs",
    "auto-cost reference-bandwidth {ref} sur r1, r2, r3 et r4": "auto-cost reference-bandwidth {ref} on r1, r2, r3 and r4",
    "le coût des interfaces suit la nouvelle référence (eth0 de r2)": "the cost of the interfaces follows the new reference (eth0 of r2)",
    "bandwidth 1000 sur eth0 de r3 et coût correspondant": "bandwidth 1000 on eth0 of r3 and matching cost",
    "Partie 4 — Élection du DR et du BDR": "Part 4 — Election of the DR and the BDR",
    "Élection du DR et du BDR sur le réseau core": "Election of the DR and the BDR on the core network",
    """
Sur le réseau `core` ({core}), notez quel routeur est **DR** et lequel est **BDR**
(`show ip ospf interface` ou `show ip ospf neighbor`) et expliquez ce résultat.

Faites en sorte que **`r3` soit le DR** et **`r1` le BDR**, et que `r2` ne puisse **jamais**
être élu (priorités 100, 50 et 0). L'élection n'étant pas préemptive, il faudra relancer
le processus OSPF (`clear ip ospf process`) sur les routeurs qui détiennent actuellement
les rôles DR et BDR, puis patienter jusqu'à une minute et demie.
""": """
On the `core` network ({core}), note which router is the **DR** and which is the **BDR**
(`show ip ospf interface` or `show ip ospf neighbor`) and explain this result.

Make **`r3` the DR** and **`r1` the BDR**, and make sure that `r2` can **never** be elected
(priorities 100, 50 and 0). Since the election is not preemptive, you will have to restart the
OSPF process (`clear ip ospf process`) on the routers that currently hold the DR and BDR roles,
then wait for up to a minute and a half.
""",
    """
**Solution.** Au départ `r2` est DR et `r1` BDR : à priorité égale (1), le plus grand router-id
l'emporte, et celui de `r2` (`{rid_r2}`, sa plus grande adresse) dépasse `1.1.1.1`. `r3`
(`3.3.3.3`), arrivé après l'élection, reste `DROther` : l'élection n'est pas préemptive.

```
! r3
interface eth0
 ip ospf priority 100
! r1
interface eth1
 ip ospf priority 50
! r2
interface eth0
 ip ospf priority 0
```

puis, sur `r1` et sur `r2` (mode privilégié de `vtysh`) : `clear ip ospf process`. Leurs
adjacences tombent, `r3` se retrouve seul et devient DR ; `r1` revient avec la priorité 50 et
devient BDR ; `r2` (priorité 0) ne peut plus être élu. Vérification sur `r2` :
`show ip ospf neighbor` affiche `r3` en `Full/DR` et `r1` en `Full/Backup`, et
`show ip ospf interface eth0` l'état `DROther`.

Évaluation : `dr_r3` (2 points : le DR de `core`, vu de `r2`, est le router-id de `r3`), `bdr_r1`
(1 : le BDR est `r1`, compté seulement si `r3` est DR — `r1` est déjà BDR au départ), `dr_priorites`
(1 : priorités 100 / 50 / 0 et `r2` en `DROther`).
""": """
**Solution.** At the start `r2` is DR and `r1` BDR: at equal priority (1), the highest router-id
wins, and that of `r2` (`{rid_r2}`, its highest address) is above `1.1.1.1`. `r3` (`3.3.3.3`),
which arrived after the election, stays `DROther`: the election is not preemptive.

```
! r3
interface eth0
 ip ospf priority 100
! r1
interface eth1
 ip ospf priority 50
! r2
interface eth0
 ip ospf priority 0
```

then, on `r1` and on `r2` (privileged mode of `vtysh`): `clear ip ospf process`. Their
adjacencies drop, `r3` is left alone and becomes DR; `r1` comes back with priority 50 and becomes
BDR; `r2` (priority 0) can no longer be elected. Check on `r2`: `show ip ospf neighbor` displays
`r3` in `Full/DR` and `r1` in `Full/Backup`, and `show ip ospf interface eth0` the state
`DROther`.

Evaluation: `dr_r3` (2 points: the DR of `core`, seen from `r2`, is the router-id of `r3`),
`bdr_r1` (1: the BDR is `r1`, counted only if `r3` is DR — `r1` is already BDR at the start),
`dr_priorites` (1: priorities 100 / 50 / 0 and `r2` in `DROther`).
""",
    "r3 est le DR du réseau core": "r3 is the DR of the core network",
    "r1 est le BDR du réseau core": "r1 is the BDR of the core network",
    "priorités 100 / 50 / 0 et r2 en DROther": "priorities 100 / 50 / 0 and r2 in DROther",
    "Partie 5 — Aire 2 et agrégation de routes": "Part 5 — Area 2 and route summarisation",
    "Une seconde aire : l'aire 2": "A second area: area 2",
    """
Les routeurs `r6` et `r7` et l'interface `eth3` de `r4` forment l'**aire 2** :

- `r6` : router-id `6.6.6.6`, interfaces `eth0` (`{net6}`, passive), `eth1` (`{l46}`) et
  `eth2` (`{l67}`), toutes dans l'aire 2 ;
- `r7` : router-id `7.7.7.7`, interfaces `eth0` (`{net7}`, passive) et `eth1` (`{l67}`)
  dans l'aire 2 ;
- `r4` : ajoutez `eth3` (`{l46}`) dans l'aire 2 (`network … area 2`, ou `ip ospf area 2`
  en mode interface). `r4` devient un **ABR** (`show ip ospf`).

N'oubliez pas la bande passante de référence ({ref}) sur les nouveaux routeurs.
Vérifiez que `m6` et `m7` joignent `m1` et `m4`, puis comparez `show ip ospf route` sur `r1`
et sur `r7` (routes `IA`).

**Agrégation** : les quatre réseaux de l'aire 2 sont contigus. Déterminez le plus petit
préfixe qui les contient tous et configurez sur l'ABR (`area 2 range PREFIXE`) l'agrégation
de l'aire 2 vers le backbone. Vérifiez sur `r1` que les quatre routes ont été remplacées par
une seule.
""": """
The routers `r6` and `r7` and the `eth3` interface of `r4` form **area 2**:

- `r6`: router-id `6.6.6.6`, interfaces `eth0` (`{net6}`, passive), `eth1` (`{l46}`) and
  `eth2` (`{l67}`), all in area 2;
- `r7`: router-id `7.7.7.7`, interfaces `eth0` (`{net7}`, passive) and `eth1` (`{l67}`) in
  area 2;
- `r4`: add `eth3` (`{l46}`) to area 2 (`network … area 2`, or `ip ospf area 2` in interface
  mode). `r4` becomes an **ABR** (`show ip ospf`).

Do not forget the reference bandwidth ({ref}) on the new routers. Check that `m6` and `m7` reach
`m1` and `m4`, then compare `show ip ospf route` on `r1` and on `r7` (`IA` routes).

**Summarisation**: the four networks of area 2 are contiguous. Work out the smallest prefix that
contains them all and configure on the ABR (`area 2 range PREFIX`) the summarisation of area 2
towards the backbone. Check on `r1` that the four routes have been replaced by a single one.
""",
    """
**Solution.**

```
! r6
router ospf
 ospf router-id {rid_r6}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net6} area 2
 network {l46} area 2
 network {l67} area 2
!
! r7
router ospf
 ospf router-id {rid_r7}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net7} area 2
 network {l67} area 2
!
! r4
router ospf
 network {l46} area 2
 area 2 range {range}
```

- `show ip ospf` sur `r4` : *This router is an ABR* ; `show ip ospf route` montre sur `r1` les
  réseaux de l'aire 2 en `N IA` et sur `r7` ceux de l'aire 0 en `N IA`.
- Agrégation : `{net6}`, `{net7}`, `{l46}` et `{l67}` tiennent tous dans **`{range}`**, le plus
  petit préfixe qui les contient (voir la question suivante). Après `area 2 range`, `r1` n'a plus
  qu'une route `{range}` au lieu de quatre (`ip route`, `show ip ospf route`).

Évaluation : `aire2_abr_r4` (1 point : `eth3` de `r4` dans l'aire 2 et `r4` ABR), `aire2_voisins`
(1 : `r6` voit `r4` par `eth1` et `r7` par `eth2` en `Full`), `aire2_router_ids` (1), `aire2_pings`
(1 : `m1` → `m6`, `m4` → `m7`, `m7` → `m1`), `aire2_range_r1` (1 : `r1` a une route OSPF vers
`{range}`), `aire2_range_pas_de_detail` (1 : et plus aucune des quatre routes détaillées).
""": """
**Solution.**

```
! r6
router ospf
 ospf router-id {rid_r6}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net6} area 2
 network {l46} area 2
 network {l67} area 2
!
! r7
router ospf
 ospf router-id {rid_r7}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net7} area 2
 network {l67} area 2
!
! r4
router ospf
 network {l46} area 2
 area 2 range {range}
```

- `show ip ospf` on `r4`: *This router is an ABR*; `show ip ospf route` shows on `r1` the
  networks of area 2 as `N IA` and on `r7` those of area 0 as `N IA`.
- Summarisation: `{net6}`, `{net7}`, `{l46}` and `{l67}` all fit in **`{range}`**, the smallest
  prefix that contains them (see the next question). After `area 2 range`, `r1` has only one
  route `{range}` instead of four (`ip route`, `show ip ospf route`).

Evaluation: `aire2_abr_r4` (1 point: `eth3` of `r4` in area 2 and `r4` ABR), `aire2_voisins`
(1: `r6` sees `r4` through `eth1` and `r7` through `eth2` in `Full`), `aire2_router_ids` (1),
`aire2_pings` (1: `m1` → `m6`, `m4` → `m7`, `m7` → `m1`), `aire2_range_r1` (1: `r1` has an OSPF
route to `{range}`), `aire2_range_pas_de_detail` (1: and none of the four detailed routes any
more).
""",
    "Préfixe agrégé de l'aire 2": "Summary prefix of area 2",
    "Préfixe utilisé dans `area 2 range` : @@{range:[0-9./]+}@@": "Prefix used in `area 2 range`: @@{range:[0-9./]+}@@",
    """

**Solution.** **`{range}`**. Les deux réseaux d'hôtes `{net6}` et `{net7}` sont deux /24
consécutifs et les deux liens `{l46}` et `{l67}` sont des /30 du /24 suivant : il faut un /22
pour les couvrir tous (un /23 ne contient que les deux premiers /24).

Évaluation : `aire2_prefixe_agrege` (1 point : la réponse désigne le réseau `{range}`).
""": """

**Solution.** **`{range}`**. The two host networks `{net6}` and `{net7}` are two consecutive
/24s and the two links `{l46}` and `{l67}` are /30s of the next /24: a /22 is needed to cover
them all (a /23 only contains the first two /24s).

Evaluation: `aire2_prefixe_agrege` (1 point: the answer designates the network `{range}`).
""",
    "eth3 de r4 est dans l'aire 2 et r4 est ABR": "eth3 of r4 is in area 2 and r4 is an ABR",
    "r6 est en état Full avec r4 et r7": "r6 is in the Full state with r4 and r7",
    "router-id 6.6.6.6 et 7.7.7.7": "router-id 6.6.6.6 and 7.7.7.7",
    "m6 et m7 joignent m1 et m4": "m6 and m7 reach m1 and m4",
    "préfixe agrégé de l'aire 2": "summary prefix of area 2",
    "r1 possède la route agrégée {range}": "r1 has the summary route {range}",
    "r1 ne voit plus les préfixes détaillés de l'aire 2 (suppose la route agrégée)": "r1 no longer sees the detailed prefixes of area 2 (requires the summary route)",
    "Partie 6 — Routes externes (ASBR)": "Part 6 — External routes (ASBR)",
    "Routes externes : r1 devient ASBR": "External routes: r1 becomes an ASBR",
    """
`r1` possède deux routes **statiques** configurées dans FRR (`show running-config`,
`show ip route`) : une vers le réseau `{ext}` (le serveur `internet`, `{ext_host}`) et une
route par défaut, toutes deux via un routeur extérieur au domaine OSPF. Aucun autre routeur
ne connaît ces destinations (essayez `ping internet` depuis `m7`).

Sur `r1` (mode `router ospf`) :

1. redistribuez les routes statiques dans OSPF (`redistribute static`) ;
2. annoncez la route par défaut (`default-information originate`).

Observez sur `r7` la table `show ip ospf route` et `show ip route`, puis vérifiez que
`m7` joint `internet`.
""": """
`r1` has two **static** routes configured in FRR (`show running-config`, `show ip route`): one
to the network `{ext}` (the `internet` server, `{ext_host}`) and a default route, both via a
router outside the OSPF domain. No other router knows these destinations (try `ping internet`
from `m7`).

On `r1` (`router ospf` mode):

1. redistribute the static routes into OSPF (`redistribute static`);
2. announce the default route (`default-information originate`).

Look at the `show ip ospf route` table and at `show ip route` on `r7`, then check that `m7`
reaches `internet`.
""",
    """
**Solution.**

```
! r1
router ospf
 redistribute static
 default-information originate
```

- `show ip ospf` sur `r1` : *This router is an ASBR*. Les deux routes statiques de `r1`
  (`ip route {ext} {isp}` et `ip route 0.0.0.0/0 {isp}` dans sa configuration) deviennent des
  LSA de type 5, inondés dans tout le domaine.
- Sur `r7`, `show ip ospf route` les range dans la table *external* : `N E2 {ext}` et
  `N E2 0.0.0.0/0` ; `show ip route` les marque `O` et `ip route` `proto ospf`.
- `ping internet` depuis `m7` passe : `r1` route `{ext}` vers l'extérieur, qui a une route
  retour par `r1`.

Évaluation : `externe_asbr_r1` (1 point), `externe_routes_r7` (2 : `r7` a `{ext}` et la route par
défaut en E2, installées dans le noyau par OSPF), `externe_ping_internet` (1 : `m7` joint
`{ext_host}`).
""": """
**Solution.**

```
! r1
router ospf
 redistribute static
 default-information originate
```

- `show ip ospf` on `r1`: *This router is an ASBR*. The two static routes of `r1`
  (`ip route {ext} {isp}` and `ip route 0.0.0.0/0 {isp}` in its configuration) become type 5
  LSAs, flooded throughout the domain.
- On `r7`, `show ip ospf route` lists them in the *external* table: `N E2 {ext}` and
  `N E2 0.0.0.0/0`; `show ip route` marks them `O` and `ip route` `proto ospf`.
- `ping internet` from `m7` works: `r1` routes `{ext}` to the outside, which has a return route
  through `r1`.

Evaluation: `externe_asbr_r1` (1 point), `externe_routes_r7` (2: `r7` has `{ext}` and the default
route as E2, installed in the kernel by OSPF), `externe_ping_internet` (1: `m7` reaches
`{ext_host}`).
""",
    "Type des routes externes": "Type of the external routes",
    """
Sur `r7`, de quel type est la route vers `{ext}` (`show ip ospf route` ; le tableau des types de
routes est dans l'onglet **Informations**, section @@ref:areas@@) ?
@@{{type:>O|O IA|O E1|O E2}}@@  et quelle est sa métrique ? @@{{metric:[0-9]+}}@@
""": """
On `r7`, what type is the route to `{ext}` (`show ip ospf route`; the table of the route types
is in the **Informations** tab, section @@ref:areas@@)?
@@{{type:>O|O IA|O E1|O E2}}@@  and what is its metric? @@{{metric:[0-9]+}}@@
""",
    """
**Solution.** **O E2**, métrique **20** : `show ip ospf route` sur `r7` affiche
`N E2 {ext} [coût/20]` (le coût jusqu'à l'ASBR, puis la métrique externe) et `show ip route`
`O>* {ext} [110/20]`. Une route redistribuée est de type 2 avec la métrique 20 par défaut : seule
la métrique externe compte, elle est donc la même sur tous les routeurs du domaine, quel que soit
leur éloignement de `r1`.

Évaluation : `externe_type_route_typed` (0,5 point : métrique 20) et, pour l'évaluation de
l'enseignant seulement (choix dans une liste), `externe_type_route` (0,5 : type O E2).
""": """
**Solution.** **O E2**, metric **20**: `show ip ospf route` on `r7` displays
`N E2 {ext} [cost/20]` (the cost to the ASBR, then the external metric) and `show ip route`
`O>* {ext} [110/20]`. A redistributed route is of type 2 with metric 20 by default: only the
external metric counts, so it is the same on all the routers of the domain, however far they are
from `r1`.

Evaluation: `externe_type_route_typed` (0.5 point: metric 20) and, for the instructor's
evaluation only (choice from a list), `externe_type_route` (0.5: type O E2).
""",
    "r1 est ASBR": "r1 is an ASBR",
    "r7 reçoit {ext} et la route par défaut en routes E2": "r7 receives {ext} and the default route as E2 routes",
    "m7 joint internet ({ext_host})": "m7 reaches internet ({ext_host})",
    "métrique de la route externe": "metric of the external route",
    "type de la route externe": "type of the external route",
    "Partie 7 — Aire stub (aire 1)": "Part 7 — Stub area (area 1)",
    "Une aire stub : l'aire 1": "A stub area: area 1",
    """
Le routeur `r5` (router-id `5.5.5.5`, `eth0` = `{net5}` passive, `eth1` = `{l35}`) et
l'interface `eth1` de `r3` forment l'**aire 1**. Configurez-les (référence {ref} comprise)
et vérifiez que `m5` joint `m1` et `internet`, puis comparez `show ip ospf route` sur `r5`
avec celle de `r7`.

1. Transformez l'aire 1 en aire **stub** (`area 1 stub` sur `r3` **et** sur `r5` : que se
   passe-t-il si un seul des deux est configuré ?). Observez sur `r5` la disparition des
   routes externes, l'apparition d'une route par défaut inter-aire et l'absence de LSA de
   type 5 dans `show ip ospf database`. `m5` doit toujours joindre `internet`.
2. *(bonus)* Transformez l'aire 1 en aire ***totally stubby*** (`area 1 stub no-summary` sur
   l'ABR uniquement) et observez la table de routage de `r5`.
""": """
The router `r5` (router-id `5.5.5.5`, `eth0` = `{net5}` passive, `eth1` = `{l35}`) and the `eth1`
interface of `r3` form **area 1**. Configure them (reference {ref} included) and check that `m5`
reaches `m1` and `internet`, then compare `show ip ospf route` on `r5` with that of `r7`.

1. Turn area 1 into a **stub** area (`area 1 stub` on `r3` **and** on `r5`: what happens if only
   one of the two is configured?). Observe on `r5` the disappearance of the external routes, the
   appearance of an inter-area default route and the absence of type 5 LSAs in
   `show ip ospf database`. `m5` must still reach `internet`.
2. *(bonus)* Turn area 1 into a ***totally stubby*** area (`area 1 stub no-summary` on the ABR
   only) and look at the routing table of `r5`.
""",
    """
**Solution.**

```
! r5
router ospf
 ospf router-id {rid_r5}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net5} area 1
 network {l35} area 1
 area 1 stub
!
! r3
router ospf
 network {l35} area 1
 area 1 stub no-summary
```

(`area 1 stub` sur `r3` pour l'étape 1, `area 1 stub no-summary` pour le bonus.)

- Avant `stub`, `r5` voit comme `r7` les réseaux des autres aires en `N IA` et les deux routes
  externes en `N E2`.
- `area 1 stub` d'un seul côté : le drapeau *stub* des Hello diffère, chaque routeur ignore les
  Hello de l'autre et l'adjacence tombe (au plus tard à l'expiration de l'intervalle Dead,
  40 s) ; elle revient quand les deux sont configurés.
- Aire stub : les `N E2` disparaissent de `r5`, remplacées par une route par défaut inter-aire
  (`N IA 0.0.0.0/0`, par `{r3_l35}`) ; `show ip ospf database` n'a plus de section *AS External
  Link States*. `m5` joint toujours `internet`, par cette route par défaut.
- *Totally stubby* : il ne reste sur `r5` que ses deux réseaux et la route par défaut.

Évaluation : `stub_r5_voisin` (1 point : `r5`, router-id `{rid_r5}`, voit `r3` en `Full` et `r3`
est ABR), `stub_ping_m5` (1 : `m5` joint `m1`), `stub_configuration` (1 : aire 1 stub sur `r3` et
`r5`), `stub_route_par_defaut` (1 : route par défaut inter-aire de `r5` par `r3`),
`stub_pas_de_route_externe` (1 : `{ext}` connu de `r3` mais absent de `r5`, aucun LSA de type 5
sur `r5` ; suppose la partie 6), `stub_no_summary` (1, le bonus : `no-summary` sur `r3`, plus de
route vers `net1` sur `r5`, `m5` joint `internet`).
""": """
**Solution.**

```
! r5
router ospf
 ospf router-id {rid_r5}
 auto-cost reference-bandwidth {ref}
 passive-interface eth0
 network {net5} area 1
 network {l35} area 1
 area 1 stub
!
! r3
router ospf
 network {l35} area 1
 area 1 stub no-summary
```

(`area 1 stub` on `r3` for step 1, `area 1 stub no-summary` for the bonus.)

- Before `stub`, `r5` sees, like `r7`, the networks of the other areas as `N IA` and the two
  external routes as `N E2`.
- `area 1 stub` on one side only: the *stub* flag of the Hellos differs, each router ignores the
  other's Hellos and the adjacency drops (at the latest when the Dead interval expires, 40 s); it
  comes back when both are configured.
- Stub area: the `N E2` routes disappear from `r5`, replaced by an inter-area default route
  (`N IA 0.0.0.0/0`, via `{r3_l35}`); `show ip ospf database` no longer has an *AS External Link
  States* section. `m5` still reaches `internet`, through this default route.
- *Totally stubby*: only its two networks and the default route are left on `r5`.

Evaluation: `stub_r5_voisin` (1 point: `r5`, router-id `{rid_r5}`, sees `r3` in `Full` and `r3`
is an ABR), `stub_ping_m5` (1: `m5` reaches `m1`), `stub_configuration` (1: area 1 stub on `r3`
and `r5`), `stub_route_par_defaut` (1: inter-area default route of `r5` via `r3`),
`stub_pas_de_route_externe` (1: `{ext}` known to `r3` but absent from `r5`, no type 5 LSA on
`r5`; requires part 6), `stub_no_summary` (1, the bonus: `no-summary` on `r3`, no route to
`net1` any more on `r5`, `m5` reaches `internet`).
""",
    "r5 (5.5.5.5) est en état Full avec r3, qui est ABR": "r5 (5.5.5.5) is in the Full state with r3, which is an ABR",
    "m5 joint m1": "m5 reaches m1",
    "l'aire 1 est stub sur r3 et sur r5": "area 1 is stub on r3 and on r5",
    "r5 reçoit une route par défaut inter-aire de r3": "r5 receives an inter-area default route from r3",
    "r5 ne reçoit ni la route externe ni les LSA de type 5 (suppose la partie 6)": "r5 receives neither the external route nor the type 5 LSAs (requires part 6)",
    "bonus : aire 1 totally stubby (plus de routes inter-aires sur r5, internet joignable)": "bonus: area 1 totally stubby (no inter-area routes left on r5, internet reachable)",
    "Partie 8 — Authentification MD5": "Part 8 — MD5 authentication",
    "Authentification des échanges OSPF": "Authentication of the OSPF exchanges",
    """
Sans authentification, n'importe quelle machine branchée sur un lien peut injecter des LSA.
Protégez le lien `l14` (`eth2` de `r1`, `eth1` de `r4`) par une authentification **MD5**
(mode interface) :

```
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 {key}
```

Configurez d'abord une seule extrémité et observez `show ip ospf neighbor` (et le journal
`/var/log/frr/frr.log`) pendant une minute, puis configurez l'autre extrémité et vérifiez
que l'adjacence est de nouveau `Full`.
""": """
Without authentication, any machine plugged into a link can inject LSAs. Protect the link `l14`
(`eth2` of `r1`, `eth1` of `r4`) with **MD5** authentication (interface mode):

```
ip ospf authentication message-digest
ip ospf message-digest-key 1 md5 {key}
```

Configure only one end first and watch `show ip ospf neighbor` (and the log
`/var/log/frr/frr.log`) for a minute, then configure the other end and check that the adjacency
is `Full` again.
""",
    """
**Solution.**

```
! r1
interface eth2
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
! r4
interface eth1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
```

- Une seule extrémité configurée : chaque routeur rejette les paquets de l'autre (type
  d'authentification différent, signalé dans `/var/log/frr/frr.log`) ; le voisin disparaît de
  `show ip ospf neighbor` à l'expiration de l'intervalle Dead (40 s). Le trafic `m1`–`m4` n'est
  pas touché : il passe par `r2` depuis la partie 3.
- Les deux extrémités configurées : l'adjacence remonte jusqu'à `Full` ;
  `show ip ospf interface eth1` sur `r4` affiche *Cryptographic authentication enabled* et
  *Algorithm:MD5*.

Évaluation : `auth_configuration` (2 points, 1 par extrémité : mode `message-digest` sur
l'interface, ou sur toute l'aire 0, et clé numéro 1 égale à `{key}`), `auth_adjacence` (1 :
l'adjacence `r1`–`r4` est `Full` et l'une des extrémités au moins est configurée).
""": """
**Solution.**

```
! r1
interface eth2
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
! r4
interface eth1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 {key}
```

- Only one end configured: each router rejects the packets of the other (different
  authentication type, reported in `/var/log/frr/frr.log`); the neighbour disappears from
  `show ip ospf neighbor` when the Dead interval expires (40 s). The `m1`–`m4` traffic is not
  affected: it has gone through `r2` since part 3.
- Both ends configured: the adjacency comes back up to `Full`; `show ip ospf interface eth1` on
  `r4` displays *Cryptographic authentication enabled* and *Algorithm:MD5*.

Evaluation: `auth_configuration` (2 points, 1 per end: `message-digest` mode on the interface,
or on the whole of area 0, and key number 1 equal to `{key}`), `auth_adjacence` (1: the
`r1`–`r4` adjacency is `Full` and at least one of the ends is configured).
""",
    "authentification MD5 (clé 1) sur eth2 de r1 et eth1 de r4": "MD5 authentication (key 1) on eth2 of r1 and eth1 of r4",
    "l'adjacence r1–r4 sur l14 est Full avec l'authentification": "the r1–r4 adjacency on l14 is Full with authentication",
    "Partie 9 — Temporisateurs et convergence": "Part 9 — Timers and convergence",
    "Temporisateurs et temps de convergence": "Timers and convergence time",
    """
Sur le lien `l24` (`eth1` de `r2`, `eth2` de `r4`), réglez l'intervalle **Hello** à
**{hello} s** et l'intervalle **Dead** à **{dead} s** (`ip ospf hello-interval`,
`ip ospf dead-interval`, mode interface). Configurez d'abord une seule extrémité : que
devient l'adjacence ? Terminez la configuration et vérifiez qu'elle est de nouveau `Full`.

Mesurez ensuite le temps de convergence en lançant `ping m1` depuis `m4` (le trafic passe
par `r2`) et en provoquant deux pannes différentes du lien `l24` sur `r4` :

- coupure franche : `ip link set eth2 down` (puis `ip link set eth2 up` pour rétablir) ;
- panne silencieuse : l'interface reste active mais plus rien ne sort de `r4` par `eth2` :
  `tc qdisc add dev eth2 root netem loss 100%` (puis `tc qdisc del dev eth2 root` pour
  rétablir). Observez `show ip ospf neighbor` sur `r2` et sur `r4` pendant la panne.
""": """
On the link `l24` (`eth1` of `r2`, `eth2` of `r4`), set the **Hello** interval to **{hello} s**
and the **Dead** interval to **{dead} s** (`ip ospf hello-interval`, `ip ospf dead-interval`,
interface mode). Configure only one end first: what happens to the adjacency? Finish the
configuration and check that it is `Full` again.

Then measure the convergence time by running `ping m1` from `m4` (the traffic goes through `r2`)
and causing two different failures of the link `l24` on `r4`:

- clean cut: `ip link set eth2 down` (then `ip link set eth2 up` to restore it);
- silent failure: the interface stays up but nothing leaves `r4` through `eth2` any more:
  `tc qdisc add dev eth2 root netem loss 100%` (then `tc qdisc del dev eth2 root` to restore
  it). Watch `show ip ospf neighbor` on `r2` and on `r4` during the failure.
""",
    """
**Solution.**

```
! r2
interface eth1
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
! r4
interface eth2
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
```

- Une seule extrémité configurée : les intervalles annoncés dans les Hello diffèrent, chaque
  routeur ignore ceux de l'autre et l'adjacence tombe à l'expiration de l'intervalle Dead ; le
  trafic `m1`–`m4` repasse alors par `l14` malgré son coût. Les deux extrémités configurées :
  adjacence `Full`, `show ip ospf interface eth2` sur `r4` affiche `Hello {hello}s, Dead {dead}s`.
- Coupure franche (`ip link set eth2 down` sur `r4`) : `r4` le sait aussitôt, inonde un nouveau
  LSA par `l14` et tous les routeurs recalculent : le `ping` ne perd rien, ou un écho tout au
  plus, et passe désormais par `l14`.
- Panne silencieuse (`netem loss 100%` sur `eth2` de `r4`) : l'interface reste active et `r4`
  continue d'envoyer par `eth2` le trafic de `m4`, qui est perdu. Rien ne signale la panne : `r2`,
  qui ne reçoit plus les Hello de `r4`, ne le déclare mort qu'à l'expiration de l'intervalle Dead
  (`show ip ospf neighbor` sur `r2` : le *Dead Time* de `r4` descend jusqu'à zéro). Ses propres
  Hello, qui arrivent toujours à `r4`, ne citent alors plus `r4`, qui abandonne l'adjacence à son
  tour et recalcule ses routes : le `ping` reprend par `l14` au bout d'environ {dead} s. Une fois
  le `netem` retiré, l'adjacence se reforme en quelques secondes.

Évaluation : `timers_valeurs` (1 point : Hello {hello} s et Dead {dead} s lus aux deux
extrémités de `l24`), `timers_adjacence` (1 : l'adjacence `r2`–`r4` est `Full` et l'une des
extrémités au moins a les nouveaux temporisateurs).
""": """
**Solution.**

```
! r2
interface eth1
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
! r4
interface eth2
 ip ospf hello-interval {hello}
 ip ospf dead-interval {dead}
```

- Only one end configured: the intervals announced in the Hellos differ, each router ignores
  those of the other and the adjacency drops when the Dead interval expires; the `m1`–`m4`
  traffic then goes back through `l14` despite its cost. Both ends configured: adjacency `Full`,
  `show ip ospf interface eth2` on `r4` displays `Hello {hello}s, Dead {dead}s`.
- Clean cut (`ip link set eth2 down` on `r4`): `r4` knows it at once, floods a new LSA through
  `l14` and all the routers recompute: the `ping` loses nothing, or one echo at most, and now
  goes through `l14`.
- Silent failure (`netem loss 100%` on `eth2` of `r4`): the interface stays up and `r4` keeps
  sending the traffic of `m4` through `eth2`, where it is lost. Nothing reports the failure: `r2`,
  which no longer receives the Hellos of `r4`, only declares it dead when the Dead interval
  expires (`show ip ospf neighbor` on `r2`: the *Dead Time* of `r4` counts down to zero). Its own
  Hellos, which still reach `r4`, then no longer list `r4`, which in turn drops the adjacency and
  recomputes its routes: the `ping` resumes through `l14` after about {dead} s. Once the `netem`
  is removed, the adjacency comes back in a few seconds.

Evaluation: `timers_valeurs` (1 point: Hello {hello} s and Dead {dead} s read at both ends of
`l24`), `timers_adjacence` (1: the `r2`–`r4` adjacency is `Full` and at least one of the ends has
the new timers).
""",
    "Temps de convergence observés": "Observed convergence times",
    """
Temps avant que `m4` ne joigne de nouveau `m1` après la coupure franche :
@@{link_down:>moins de 5 s|environ l'intervalle Hello|environ l'intervalle Dead|jamais}@@

et après la panne silencieuse :
@@{filtre:>moins de 5 s|environ l'intervalle Hello|environ l'intervalle Dead|jamais}@@
""": """
Time before `m4` reaches `m1` again after the clean cut:
@@{link_down:>less than 5 s>>>moins de 5 s|about the Hello interval>>>environ l'intervalle Hello|about the Dead interval>>>environ l'intervalle Dead|never>>>jamais}@@

and after the silent failure:
@@{filtre:>less than 5 s>>>moins de 5 s|about the Hello interval>>>environ l'intervalle Hello|about the Dead interval>>>environ l'intervalle Dead|never>>>jamais}@@
""",
    """
**Solution.** Coupure franche : **moins de 5 s** (la panne est connue immédiatement). Panne
silencieuse : **environ l'intervalle Dead** ({dead} s ici) : rien ne signale la panne, il faut que
`r2` reste {dead} s sans Hello de `r4` pour que l'adjacence tombe et que les routes changent.

Évaluation : `convergence_coupure` et `convergence_panne_silencieuse` (1 point chacune,
évaluation de l'enseignant seulement).
""": """
**Solution.** Clean cut: **less than 5 s** (the failure is known immediately). Silent failure:
**about the Dead interval** ({dead} s here): nothing reports the failure, `r2` has to go {dead} s
without a Hello from `r4` for the adjacency to drop and the routes to change.

Evaluation: `convergence_coupure` and `convergence_panne_silencieuse` (1 point each,
instructor's evaluation only).
""",
    "Hello {hello} s / Dead {dead} s sur les deux extrémités de l24": "Hello {hello} s / Dead {dead} s at both ends of l24",
    "l'adjacence r2–r4 sur l24 est Full avec les nouveaux temporisateurs": "the r2–r4 adjacency on l24 is Full with the new timers",
    "convergence après une coupure franche": "convergence after a clean cut",
    "convergence après une panne silencieuse": "convergence after a silent failure",
}}
