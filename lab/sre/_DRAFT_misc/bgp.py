"""TP BGP avec FRR (FRRouting) : eBGP et iBGP.

Sept routeurs FRR répartis dans cinq systèmes autonomes : l'AS 65001 des étudiants
(r1, r2, r3, IGP OSPF pré-configuré), deux fournisseurs (ispa = AS 65100, ispb = AS 65200),
« le reste de l'Internet » (inet = AS 65000, qui héberge le serveur web 203.0.113.1) et un
client (r4 = AS 65300).  r1 est déjà en eBGP avec ispa ; les étudiants configurent l'eBGP
de r3, l'iBGP (loopbacks, next-hop-self), les politiques (local-preference, AS-path prepend,
filtrage), le client (default-originate) et un réflecteur de routes.  L'état ``final``
applique la solution de référence (il suppose l'état initial : les sessions ajoutées par
un étudiant ne sont pas retirées).
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
    get_bgp_summary, get_bgp_neighbor, get_bgp_routes, get_bgp_prefix, get_bgp_advertised_routes,
    bgp_best_path, bgp_paths, get_kernel_routes, kernel_route_gateways, get_frr_running_config,
    is_bgp_protocol, BGP_ROUTE_PROTOCOLS,
)

default_language = 'fr'
tr = make_tr(default_language)

title = tr("BGP : routage inter-domaine", en="BGP: inter-domain routing")
shared_path = True
allow_self_grade = True
no_mark_on_self_grade = True
delay_between_self_grade = 30
export_kathara_project = True
eval_interval_without_exam_mode = 60
eval_before_exit = True
record_sessions = False

# "The Internet": a fixed prefix (TEST-NET-3) behind inet, with the web server.
EXT_PUBLIC = IPv4Network("203.0.113.0/24")
WEB_HOST = IPv4Interface("203.0.113.1/24")
INET_WEB = IPv4Interface("203.0.113.254/24")
DEFAULT_ROUTE = "0.0.0.0/0"

AS1, AS_CUST, AS_ISPA, AS_ISPB, AS_INET = 65001, 65300, 65100, 65200, 65000
AS_OF = {'r1': AS1, 'r2': AS1, 'r3': AS1, 'r4': AS_CUST, 'ispa': AS_ISPA, 'ispb': AS_ISPB, 'inet': AS_INET}
# Fixed router-ids of the pre-configured routers and of the customer router; r1, r2 and r3
# use their loopback address (OSPF and BGP).
ROUTER_IDS = {'ispa': '100.100.100.100', 'ispb': '200.200.200.200', 'inet': '250.250.250.250', 'r4': '4.4.4.4'}

# Router interfaces in ethN order: (network name, data.ips attribute).  Must match _topology.
ROUTER_IFACES = {
    'r1': [('net1', 'r1_net1'), ('l12', 'r1_l12'), ('la', 'r1_la')],
    'r2': [('l12', 'r2_l12'), ('l23', 'r2_l23')],
    'r3': [('net3', 'r3_net3'), ('l23', 'r3_l23'), ('lb', 'r3_lb'), ('l34', 'r3_l34')],
    'r4': [('net4', 'r4_net4'), ('l34', 'r4_l34')],
    'ispa': [('neta', 'ispa_neta'), ('la', 'ispa_la'), ('lab', 'ispa_lab'), ('lai', 'ispa_lai')],
    'ispb': [('netb', 'ispb_netb'), ('lb', 'ispb_lb'), ('lab', 'ispb_lab'), ('lbi', 'ispb_lbi')],
    'inet': [('netweb', 'inet_netweb'), ('lai', 'inet_lai'), ('lbi', 'inet_lbi')],
}
LOOPBACKS = {'r1': 'lo1', 'r2': 'lo2', 'r3': 'lo3'}  # data.ips attributes (/32)
# Hosts: (router, data.ips attribute of the router interface on the host LAN)
HOST_ROUTER = {
    'm1': ('r1', 'r1_net1'),
    'm3': ('r3', 'r3_net3'),
    'm4': ('r4', 'r4_net4'),
    'web': ('inet', 'inet_netweb'),
}
AS1_ROUTERS = ['r1', 'r2', 'r3']
AS_COLORS = {AS1: 'lightblue', AS_ISPA: 'lightgreen', AS_ISPB: 'lightyellow', AS_INET: 'lightgrey',
             AS_CUST: 'mistyrose'}
NET_AS = {'net1': AS1, 'net3': AS1, 'l12': AS1, 'l23': AS1,
          'la': AS_ISPA, 'neta': AS_ISPA, 'lab': AS_ISPA, 'lai': AS_INET,
          'lb': AS_ISPB, 'netb': AS_ISPB, 'lbi': AS_INET, 'netweb': AS_INET,
          'l34': AS_CUST, 'net4': AS_CUST}
BGP_STATES = "Idle|Connect|Active|OpenSent|OpenConfirm|Established"

FRR_DAEMONS_TEMPLATE = """# /etc/frr/daemons -- généré par le TP : bgpd{ospf_comment}
# (zebra, staticd et watchfrr démarrent toujours)
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
    local_pref: int = 0   # part 4: local-preference of the Internet prefix learnt from ISP B
    prepend: int = 0      # part 5: number of times 65001 is prepended towards ISP A
    keepalive: int = 0    # part 4: keepalive on the r3-ispb session; hold = 3 * keepalive
    cust_tag: int = 0     # part 7: community 65001:<cust_tag> on the customer's routes
    md5_key: str = ""     # part 2 (bonus): TCP MD5 password of the r3-ispb session

    @classmethod
    def generate(cls):
        data = cls()
        data.local_pref = random.choice([150, 200, 250, 300])
        data.prepend = random.choice([2, 3])
        data.keepalive = random.randint(5, 20)
        data.cust_tag = random.randint(100, 999)
        data.md5_key = utils.random_password(12)

        (block, data.nets.neta, data.nets.netb, data.nets.net4, data.nets.la, data.nets.lb,
         data.nets.lab, data.nets.lai, data.nets.lbi, data.nets.l34) = random_ipv4networks(
            masks=[22, 24, 24, 24, 30, 30, 30, 30, 30, 30],
            from_private_network=True,
            exclude=[IPv4Network("10.0.0.0/16"), IPv4Network("172.17.0.0/16"), EXT_PUBLIC],
        )
        # AS 65001 owns one /22: two LANs, one /24 of point-to-point links, one /24 of loopbacks.
        data.nets.as1_block = block
        data.nets.net1, data.nets.net3, links, data.nets.loops = block.subnets(new_prefix=24)
        sub30 = list(links.subnets(new_prefix=30))
        data.nets.l12, data.nets.l23 = sub30[0], sub30[1]
        data.nets.netweb = EXT_PUBLIC

        data.ips.r1_net1, data.ips.m1 = random_ipv4s(data.nets.net1, 2)
        data.ips.r3_net3, data.ips.m3 = random_ipv4s(data.nets.net3, 2)
        data.ips.r1_l12, data.ips.r2_l12 = random_ipv4s(data.nets.l12, 2)
        data.ips.r2_l23, data.ips.r3_l23 = random_ipv4s(data.nets.l23, 2)
        data.ips.r1_la, data.ips.ispa_la = random_ipv4s(data.nets.la, 2)
        data.ips.r3_lb, data.ips.ispb_lb = random_ipv4s(data.nets.lb, 2)
        data.ips.r3_l34, data.ips.r4_l34 = random_ipv4s(data.nets.l34, 2)
        data.ips.r4_net4, data.ips.m4 = random_ipv4s(data.nets.net4, 2)
        data.ips.ispa_neta = random_ipv4s(data.nets.neta, 1)[0]
        data.ips.ispb_netb = random_ipv4s(data.nets.netb, 1)[0]
        data.ips.ispa_lab, data.ips.ispb_lab = random_ipv4s(data.nets.lab, 2)
        data.ips.ispa_lai, data.ips.inet_lai = random_ipv4s(data.nets.lai, 2)
        data.ips.ispb_lbi, data.ips.inet_lbi = random_ipv4s(data.nets.lbi, 2)
        data.ips.inet_netweb = INET_WEB
        data.ips.web = WEB_HOST
        # Loopbacks in increasing order (lo1 < lo2 < lo3): the router-id tie-break is deterministic.
        hosts = list(data.nets.loops.hosts())
        data.ips.lo1 = IPv4Interface(f"{hosts[0]}/32")
        data.ips.lo2 = IPv4Interface(f"{hosts[1]}/32")
        data.ips.lo3 = IPv4Interface(f"{hosts[2]}/32")
        return data


# ---------------------------------------------------------------------------
# NetScheme
# ---------------------------------------------------------------------------


class NetScheme(NetScheme0):
    _machine_specs = {
        **{r: {'image': sre_docker_image("netdev13"), 'color': AS_COLORS[AS_OF[r]]} for r in ROUTER_IFACES},
        'm1': {'color': AS_COLORS[AS1]}, 'm3': {'color': AS_COLORS[AS1]},
        'm4': {'color': AS_COLORS[AS_CUST]}, 'web': {'color': AS_COLORS[AS_INET]},
    }
    _network_specs = {net: {'color': AS_COLORS[as_]} for net, as_ in NET_AS.items()}
    # Interface numbers must follow ROUTER_IFACES (ethN = position in the list).
    _topology = {
        'net1': {'r1': 0, 'm1': 0},
        'l12': {'r1': 1, 'r2': 0},
        'la': {'r1': 2, 'ispa': 1},
        'l23': {'r2': 1, 'r3': 1},
        'net3': {'r3': 0, 'm3': 0},
        'lb': {'r3': 2, 'ispb': 1},
        'l34': {'r3': 3, 'r4': 1},
        'net4': {'r4': 0, 'm4': 0},
        'neta': {'ispa': 0},
        'lab': {'ispa': 2, 'ispb': 2},
        'lai': {'ispa': 3, 'inet': 1},
        'netb': {'ispb': 0},
        'lbi': {'ispb': 3, 'inet': 2},
        'netweb': {'inet': 0, 'web': 0},
    }

    def __init__(self, data, running_lab_name):
        super().__init__(data=data, running_lab_name=running_lab_name)
        d = self.data
        default = IPv4Network(DEFAULT_ROUTE)

        # Routers: addresses only (BGP/OSPF do the routing); hosts: address + default route.
        self.net_config: Dict[str, NetConfigEntry] = {}
        for r, ifaces in ROUTER_IFACES.items():
            self.net_config[r] = [([getattr(d.ips, attr)], []) for _net, attr in ifaces]
        for h, (_r, r_attr) in HOST_ROUTER.items():
            self.net_config[h] = [([getattr(d.ips, h)], [(default, getattr(d.ips, r_attr).ip)])]

        # /etc/hosts: every router interface gets rX-ethN, the first one also rX; loopbacks rX-lo.
        lines = []
        for r, ifaces in ROUTER_IFACES.items():
            for i, (_net, attr) in enumerate(ifaces):
                ip = getattr(d.ips, attr).ip
                names = f"{r}-eth{i}" if i else f"{r}\t{r}-eth{i}"
                lines.append(f"{ip}\t{names}")
            if r in LOOPBACKS:
                lines.append(f"{getattr(d.ips, LOOPBACKS[r]).ip}\t{r}-lo")
        for h in HOST_ROUTER:
            lines.append(f"{getattr(d.ips, h).ip}\t{h}")
        lines.append(f"{WEB_HOST.ip}\tinternet")
        self.hosts_content = "\n".join(lines) + "\n"

        self.informations = (
            no_tr("## ") + title + no_tr("\n")
            + tr("\n**Sommaire**\n") + info_toc()
            + info_subtitle(tr("Principe de BGP"), tag="principle")
            + tr("""
L'Internet est un ensemble de **systèmes autonomes** (AS, *Autonomous System*), chacun identifié
par un numéro (ASN ; les numéros 64512 à 65534 sont **privés**, comme les adresses de la
RFC 1918) et administré par une organisation. À l'intérieur d'un AS, un **IGP** (OSPF, IS-IS)
calcule les plus courts chemins ; **entre** les AS, **BGP** (*Border Gateway Protocol*, version 4,
RFC 4271) échange des **préfixes** accompagnés d'**attributs** et chaque AS choisit ses routes
selon sa **politique** (coûts, contrats, sécurité), pas seulement selon la distance.

BGP est un protocole à **vecteur de chemins** : chaque route porte la liste des AS traversés
(**AS_PATH**). Un routeur **rejette** toute route dont l'AS_PATH contient son propre numéro
d'AS : c'est la protection contre les boucles.

Dans la table de routage (`show ip route`, `ip route`), les routes BGP sont marquées `B` (`proto
bgp` pour le noyau) avec une **distance administrative** de **20** (eBGP) ou **200** (iBGP).

### @@sec:sessions@@ Sessions et messages

- Deux routeurs BGP (**pairs**, *peers* ou *neighbors*) établissent une **session** sur une
  connexion **TCP** (port **179**) configurée explicitement des deux côtés (`neighbor A.B.C.D
  remote-as N`) : il n'y a pas de découverte automatique des voisins.
- Une session est **eBGP** (*external*) entre deux AS différents, **iBGP** (*internal*) entre
  deux routeurs du même AS. Par défaut les paquets eBGP sont émis avec un **TTL de 1** : les pairs
  eBGP sont directement connectés (sinon `neighbor X ebgp-multihop`).
- Messages : `OPEN` (numéro d'AS, router-id, *hold time*, capacités), `UPDATE` (préfixes annoncés
  avec leurs attributs, préfixes retirés), `KEEPALIVE` et `NOTIFICATION` (erreur, fermeture de la
  session).
- Automate d'une session : `Idle` → `Connect` / `Active` (tentatives TCP) → `OpenSent` →
  `OpenConfirm` → **`Established`** (routes échangées). Un pair déclaré d'un seul côté reste en
  `Active` ou `Connect` : il tente périodiquement d'ouvrir la connexion.
- `neighbor X password MOT` authentifie la session (option TCP MD5, RFC 2385) ; le mot de passe
  doit être le même des deux côtés.

### @@sec:timers@@ Temporisateurs et convergence

Chaque pair envoie un `KEEPALIVE` toutes les **60 s** par défaut. Si aucun message n'est reçu
pendant le **hold time** (**180 s** par défaut), la session est fermée et toutes les routes
apprises du pair sont retirées. Le hold time est **négocié** à l'ouverture de la session (la plus
petite des deux valeurs) : `neighbor X timers KEEPALIVE HOLD` ne prend donc effet qu'après
`clear bgp X`. Le temps de convergence après une panne dépend de la façon dont elle est détectée :

- fermeture **administrative** (`neighbor X shutdown`) : le pair est prévenu par un
  `NOTIFICATION`, les routes sont retirées aussitôt des deux côtés ;
- **coupure franche** (l'interface passe *down*) : le routeur ferme aussitôt ses sessions eBGP
  sur ce lien ; le pair, si sa propre interface reste active, n'apprend la panne qu'à
  l'expiration du hold time ;
- **panne silencieuse** (le lien reste *up* mais ne transmet plus rien) : rien ne la signale,
  chaque côté attend l'expiration du hold time.

Les réseaux qui visent une détection plus rapide réduisent ces temporisateurs ou utilisent BFD.
""")
            + info_subtitle(tr("Attributs et choix du meilleur chemin"), tag="attributes")
            + tr("""
| attribut | type | rôle |
|----------|------|------|
| `AS_PATH` | obligatoire | liste des AS traversés (chaque AS ajoute son numéro en tête à la sortie) |
| `NEXT_HOP` | obligatoire | adresse du prochain saut ; modifiée sur une session eBGP, **conservée** sur une session iBGP |
| `ORIGIN` | obligatoire | origine de la route : `i` (IGP, commande `network`), `e` (EGP), `?` (incomplète, redistribution) |
| `LOCAL_PREF` | discrétionnaire | préférence **locale à l'AS** (100 par défaut), transmise en iBGP, **jamais** en eBGP |
| `MED` | optionnel non transitif | *Multi-Exit Discriminator* : suggère au voisin le point d'entrée à préférer ; comparé uniquement entre routes venant du **même AS voisin** |
| `COMMUNITY` | optionnel transitif | étiquettes `AS:valeur` pour marquer des routes et leur appliquer des politiques ; communautés connues : `no-export`, `no-advertise` |
| `ORIGINATOR_ID`, `CLUSTER_LIST` | optionnels | ajoutés par un réflecteur de routes (section @@ref:rr@@) |

### @@sec:decision@@ Le processus de décision

Pour chaque préfixe, si plusieurs chemins sont connus, BGP n'en installe et n'en annonce qu'**un
seul**, choisi dans l'ordre suivant :

1. `weight` le plus grand (FRR/Cisco, local au routeur ; 32768 pour les routes locales) ;
2. **`LOCAL_PREF`** le plus grand ;
3. route originée localement (`network`, agrégat) ;
4. **`AS_PATH`** le plus court ;
5. `ORIGIN` le plus bas (`i` < `e` < `?`) ;
6. **`MED`** le plus petit (entre routes du même AS voisin) ;
7. route **eBGP** préférée à route iBGP ;
8. métrique IGP la plus faible vers le `NEXT_HOP` ;
9. chemin le plus ancien (eBGP) ou **router-id** du pair le plus petit.

`show ip bgp` (ou `show bgp ipv4 unicast`) affiche tous les chemins connus : `*` = chemin valide
(prochain saut joignable), `>` = meilleur chemin, `i` en tête = appris en iBGP. `show ip bgp
PREFIXE` détaille un préfixe et indique entre parenthèses, après `best`, la raison du choix
(`AS Path`, `Local Pref`, `Router ID`, `Peer Type`…).
""")
            + info_subtitle(tr("iBGP"), tag="ibgp")
            + tr("""
Une route apprise d'un pair **iBGP** n'est **jamais réannoncée à un autre pair iBGP** (règle de
*split horizon* : les routeurs d'un AS ne portent pas leur AS dans l'AS_PATH, une boucle interne
serait indétectable). Conséquences :

- tous les routeurs BGP d'un AS doivent être **maillés** (*full mesh* : n(n−1)/2 sessions), ou
  utiliser un réflecteur de routes (section @@ref:rr@@) ;
- les sessions iBGP sont établies entre **loopbacks** (`neighbor X update-source lo`) : elles
  survivent à la panne d'un lien tant que l'IGP trouve un autre chemin ;
- le `NEXT_HOP` reçu en eBGP (adresse du routeur du fournisseur) est transmis tel quel en iBGP :
  s'il n'est pas dans l'IGP, la route est **invalide** sur les autres routeurs. Solution :
  `neighbor X next-hop-self` sur le routeur de bordure ;
- un routeur de l'AS qui relaie le trafic sans parler BGP ne connaît pas les destinations
  externes et forme un **trou noir** : dans un AS de transit, tous les routeurs du chemin doivent
  connaître les routes BGP.

### @@sec:rr@@ Réflecteur de routes

Le maillage complet ne passe pas à l'échelle. Un **réflecteur de routes** (*route reflector*, RR,
RFC 4456) est un routeur autorisé à réannoncer en iBGP les routes de ses **clients**
(`neighbor X route-reflector-client`, sur le réflecteur seulement) : chaque client n'a plus
besoin que d'une session, vers le réflecteur. Pour remplacer la protection perdue, le réflecteur
ajoute à la route `ORIGINATOR_ID` (le router-id du routeur qui l'a introduite dans l'AS) et
`CLUSTER_LIST` (les réflecteurs traversés) ; un routeur rejette une route qui porte son propre
identifiant dans l'un des deux. Le réflecteur ne modifie ni le `NEXT_HOP` ni les autres attributs.
""")
            + info_subtitle(tr("Politiques de routage"), tag="policies")
            + tr("""
### @@sec:traffic@@ Trafic sortant, trafic entrant

- Sortie de l'AS (trafic **sortant**) : on décide soi-même, avec `LOCAL_PREF` (préférer un
  fournisseur pour tout l'AS) ou `weight` (pour un seul routeur).
- Entrée dans l'AS (trafic **entrant**) : on ne décide pas pour les autres, on les **influence** :
  **`AS_PATH prepend`** (allonger artificiellement le chemin annoncé à un fournisseur), `MED`
  (entre plusieurs liens vers le même voisin), communautés interprétées par le fournisseur.

### @@sec:filtering@@ Filtres et route-maps

- `ip prefix-list NOM seq N permit|deny PREFIXE` : une liste de préfixes ;
  `bgp as-path access-list` : expressions régulières sur l'AS_PATH ; `bgp community-list`.
- Une **`route-map`** est une suite de séquences numérotées `permit` / `deny`, chacune avec des
  clauses `match` (les routes concernées) et `set` (les attributs modifiés). Une route est
  traitée par la première séquence qui lui correspond ; une séquence sans `match` correspond à
  tout ; une route qui ne correspond à aucune séquence est **refusée**.
- `neighbor X route-map NOM in|out` (address-family) applique la route-map aux routes reçues du
  pair ou annoncées au pair. Après une modification de politique, `clear bgp X soft in|out`
  la réapplique sans couper la session.
- Un AS **non-transit** (client de deux fournisseurs) ne doit annoncer que **ses propres
  préfixes** (et ceux de ses clients), jamais ceux appris d'un fournisseur à l'autre : sinon il
  se propose comme chemin entre ses fournisseurs.
- `neighbor X maximum-prefix N` protège contre une fuite massive de routes.

### @@sec:rfc8212@@ RFC 8212 : pas de session eBGP sans politique

FRR refuse d'accepter et d'annoncer des routes sur une session **eBGP** tant qu'aucune politique
(`route-map` ou `prefix-list`, en entrée et en sortie) n'est définie : la session s'établit mais
le pair apparaît avec la mention `(Policy)` dans `show ip bgp summary`. Cette règle évite les
fuites de routes involontaires d'un routeur mal configuré. On définit des politiques explicites,
ou on désactive la protection : `no bgp ebgp-requires-policy` (mode `router bgp`).

### @@sec:announce@@ Annoncer un préfixe

- `network PREFIXE` (address-family) n'annonce un préfixe que si une route **exactement
  identique** existe dans la table de routage (`bgp network import-check`). Pour annoncer un bloc
  qui regroupe plusieurs réseaux, on ajoute une route statique vers `blackhole`
  (`ip route PREFIXE blackhole`, l'équivalent de `Null0`) : les routes plus précises de l'IGP
  restent prioritaires.
- `aggregate-address PREFIXE` construit un agrégat à partir des routes plus spécifiques présentes
  dans BGP ; avec `summary-only`, seul l'agrégat est annoncé, les préfixes plus spécifiques sont
  supprimés des annonces.
- `neighbor X default-originate` annonce une route par défaut à un pair (typiquement un client,
  qui n'a pas besoin de la table complète).
- `set community AS:VALEUR` dans une route-map marque des routes ; les communautés sont
  transmises aux pairs et visibles dans `show ip bgp PREFIXE`.
""")
            + info_subtitle(tr("FRR et vtysh"), tag="frr")
            + tr("""
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` (l'interface avec le
noyau), `staticd` (les routes statiques), `bgpd`, `ospfd`… (les démons lancés sont choisis dans
`/etc/frr/daemons`). On les configure avec le shell **`vtysh`**, dont la syntaxe est proche de
celle des équipements Cisco :

```
vtysh                                    # ouvre le shell (prompt : routeur#)
show running-config                      # configuration courante
configure terminal
 router bgp 64512                        # processus BGP de l'AS 64512 (prompt : routeur(config-router)#)
  bgp router-id 198.51.100.253
  neighbor 192.0.2.1 remote-as 64513     # pair eBGP
  neighbor 192.0.2.1 description ISP-B
  neighbor 198.51.100.254 remote-as 64512     # pair iBGP
  neighbor 198.51.100.254 update-source lo
  address-family ipv4 unicast
   network 198.51.100.0/24               # préfixe annoncé
   neighbor 198.51.100.254 next-hop-self
   neighbor 192.0.2.1 route-map TO-B out
  exit-address-family
 exit
 ip prefix-list MINE seq 5 permit 198.51.100.0/24
 route-map TO-B permit 10
  match ip address prefix-list MINE
  set as-path prepend 64512 64512
 exit
 end
write                                    # sauvegarde dans /etc/frr/frr.conf
```

On supprime une ligne en la préfixant par `no`. Une commande peut être passée depuis le shell
Linux : `vtysh -c "show ip bgp summary"`. `clear bgp * soft` (ou `clear bgp A.B.C.D soft in|out`)
réapplique les politiques sans couper les sessions ; `clear bgp A.B.C.D` coupe et rétablit une
session (nécessaire pour changer ses temporisateurs).

Commandes d'observation utiles :

```
show ip bgp summary                        # sessions, état, préfixes reçus (State/PfxRcd)
show ip bgp                                # table BGP : tous les chemins, meilleur chemin (>)
show ip bgp PREFIXE                        # détail d'un préfixe : attributs, raison du choix
show ip bgp neighbors A.B.C.D              # détail d'une session : timers, politiques, compteurs
show ip bgp neighbors A.B.C.D advertised-routes   # ce que l'on annonce à ce pair (après politiques)
show ip bgp neighbors A.B.C.D received-routes     # ce que l'on reçoit (avec soft-reconfiguration inbound)
show ip route                              # table de routage (B = BGP, O = OSPF)
```

Documentation : [FRR — BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html) et
[filtrage](https://docs.frrouting.org/en/latest/filter.html).
""")
            + info_subtitle(tr("Diagnostic"), tag="diagnostic")
            + tr("""
- `ip route` sur un routeur : les routes apprises par BGP portent `proto bgp` ;
- `traceroute -n IP` (ou `traceroute IP` pour les noms) depuis un hôte : chemin réellement suivi,
  d'un AS à l'autre ;
- `tcpdump -ni ethX tcp port 179` : observation des messages BGP (`-v` montre le TTL des paquets) ;
- `/var/log/frr/frr.log` : journal des démons FRR (établissement et fermeture des sessions).

| symptôme | causes à vérifier |
|----------|-------------------|
| session en `Active` / `Connect` | pair non déclaré de l'autre côté, mauvaise adresse ou mauvais numéro d'AS, pas de route vers le pair, `update-source` oublié entre loopbacks, mots de passe différents |
| session `Established`, mention `(Policy)` | RFC 8212 : aucune politique sur la session eBGP |
| préfixe déclaré par `network` mais pas annoncé | pas de route exactement identique dans la table de routage |
| route reçue en iBGP mais non valide (pas de `*`) | `NEXT_HOP` injoignable : `next-hop-self` sur le routeur de bordure |
| route BGP installée mais trafic perdu en chemin | un routeur du chemin ne connaît pas la destination (trou noir), ou pas de route retour |
| politique modifiée sans effet | `clear bgp X soft in` / `soft out` ; `clear bgp X` pour les temporisateurs |
""")
        )

    # -- FRR configuration files -------------------------------------------------

    def _daemons(self, router: str) -> str:
        ospf = router in AS1_ROUTERS
        return FRR_DAEMONS_TEMPLATE.format(ospfd="yes" if ospf else "no",
                                           ospf_comment=" et ospfd sont activés" if ospf else " est activé")

    def _bgp_neighbor_lines(self, peer_ip, remote_as: int, description: str):
        return [f" neighbor {peer_ip} remote-as {remote_as}",
                f" neighbor {peer_ip} description {description}"]

    def _frr_conf(self, router: str) -> str:
        """Initial /etc/frr/frr.conf.

        r1, r2, r3: loopback + OSPF (the IGP of AS 65001; the external links are not in
        OSPF).  r1 also runs eBGP with ispa and announces the /22.  ispa, ispb and inet are
        fully configured (``bgp bestpath compare-routerid`` makes tie-breaks deterministic;
        ispb already declares r3 as a neighbour).  r4 is empty.
        """
        d = self.data
        lines = ["!", "! FRRouting configuration file (initial state generated by the lab)", "!",
                 "log file /var/log/frr/frr.log", "!"]
        if router in AS1_ROUTERS:
            lo = getattr(d.ips, LOOPBACKS[router])
            nets = [getattr(d.nets, net) for net, _attr in ROUTER_IFACES[router] if NET_AS[net] == AS1]
            lines += ["interface lo", f" ip address {lo}", "exit", "!", "router ospf", f" ospf router-id {lo.ip}"]
            lines += [f" network {n} area 0" for n in nets] + [f" network {lo} area 0"]
            if router != 'r2':
                lines.append(" passive-interface eth0")
            lines += [" passive-interface lo", "exit", "!"]
        if router == 'r1':
            lines += [
                f"ip route {d.nets.as1_block} blackhole",
                "!",
                f"router bgp {AS1}",
                f" bgp router-id {d.ips.lo1.ip}",
                " no bgp ebgp-requires-policy",
                *self._bgp_neighbor_lines(d.ips.ispa_la.ip, AS_ISPA, "ISP-A"),
                " address-family ipv4 unicast",
                f"  network {d.nets.as1_block}",
                " exit-address-family",
                "exit",
                "!",
            ]
        elif router in ('ispa', 'ispb', 'inet'):
            if router == 'ispa':
                neighbors = [(d.ips.r1_la.ip, AS1, "CLIENT-AS65001"), (d.ips.ispb_lab.ip, AS_ISPB, "PEER-ISPB"),
                             (d.ips.inet_lai.ip, AS_INET, "TRANSIT-INET")]
                network = d.nets.neta
            elif router == 'ispb':
                neighbors = [(d.ips.r3_lb.ip, AS1, "CLIENT-AS65001"), (d.ips.ispa_lab.ip, AS_ISPA, "PEER-ISPA"),
                             (d.ips.inet_lbi.ip, AS_INET, "TRANSIT-INET")]
                network = d.nets.netb
            else:
                neighbors = [(d.ips.ispa_lai.ip, AS_ISPA, "ISP-A"), (d.ips.ispb_lbi.ip, AS_ISPB, "ISP-B")]
                network = EXT_PUBLIC
            lines += [f"router bgp {AS_OF[router]}", f" bgp router-id {ROUTER_IDS[router]}",
                      " no bgp ebgp-requires-policy", " bgp bestpath compare-routerid"]
            for peer_ip, remote_as, desc in neighbors:
                lines += self._bgp_neighbor_lines(peer_ip, remote_as, desc)
            lines += [" address-family ipv4 unicast", f"  network {network}", " exit-address-family", "exit", "!"]
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
            self.file(r, "/etc/frr/daemons", self._daemons(r), permissions=0o640, owner="frr:frr")
            self.file(r, "/etc/frr/vtysh.conf", FRR_VTYSH_CONF, permissions=0o640, owner="frr:frrvty")
            self.file(r, "/etc/frr/frr.conf", self._frr_conf(r), permissions=0o640, owner="frr:frr")
            self.cmd(r, "systemctl start frr")

    @sre_state(user_allowed=False)
    def final(self):
        """Reference solution (assumes the initial state; allow ~60 s before an evaluation).

        r3 and r4 run eBGP, the iBGP of AS 65001 is built directly in its route-reflector
        form (r2 reflects between r1 and r3, next-hop-self on the border routers), the
        Internet prefix is preferred through ISP B (local-preference on r3), inbound
        traffic is steered to ISP B (AS-path prepend towards ispa), both borders announce
        only the /22 and the customer's prefix, r4 receives only a default route, its
        routes are tagged with a community, the r3-ispb session has custom timers and a
        MD5 password.  Form questions are filled through cheat_answers.
        """
        d = self.data
        lo1, lo2, lo3 = d.ips.lo1.ip, d.ips.lo2.ip, d.ips.lo3.ip
        k, hold = d.keepalive, 3 * d.keepalive
        prepend = " ".join([str(AS1)] * d.prepend)

        # r2: route reflector between r1 and r3 (sessions between loopbacks)
        self._vtysh('r2',
                    f"router bgp {AS1}",
                    f"bgp router-id {lo2}",
                    f"neighbor {lo1} remote-as {AS1}",
                    f"neighbor {lo1} update-source lo",
                    f"neighbor {lo1} description r1",
                    f"neighbor {lo3} remote-as {AS1}",
                    f"neighbor {lo3} update-source lo",
                    f"neighbor {lo3} description r3",
                    "address-family ipv4 unicast",
                    f"neighbor {lo1} route-reflector-client",
                    f"neighbor {lo3} route-reflector-client",
                    "exit-address-family",
                    "exit")
        # r1: iBGP with r2 (next-hop-self), outbound filter + prepend towards ISP A
        self._vtysh('r1',
                    f"ip prefix-list TO-ISPA seq 5 permit {d.nets.as1_block}",
                    f"ip prefix-list TO-ISPA seq 10 permit {d.nets.net4}",
                    "route-map TO-ISPA permit 10",
                    "match ip address prefix-list TO-ISPA",
                    f"set as-path prepend {prepend}",
                    "exit",
                    f"router bgp {AS1}",
                    f"neighbor {lo2} remote-as {AS1}",
                    f"neighbor {lo2} update-source lo",
                    f"neighbor {lo2} description r2",
                    "address-family ipv4 unicast",
                    f"neighbor {lo2} next-hop-self",
                    f"neighbor {d.ips.ispa_la.ip} route-map TO-ISPA out",
                    "exit-address-family",
                    "exit")
        # r3: eBGP with ISP B (timers, MD5, local-preference on the Internet prefix, outbound
        # filter), iBGP with r2 (next-hop-self), customer r4 (default only, community)
        self._vtysh('r3',
                    f"ip route {d.nets.as1_block} blackhole",
                    f"ip prefix-list TO-ISPB seq 5 permit {d.nets.as1_block}",
                    f"ip prefix-list TO-ISPB seq 10 permit {d.nets.net4}",
                    f"ip prefix-list WEB seq 5 permit {EXT_PUBLIC}",
                    f"ip prefix-list DEFAULT-ONLY seq 5 permit {DEFAULT_ROUTE}",
                    "route-map LP-IN permit 10",
                    "match ip address prefix-list WEB",
                    f"set local-preference {d.local_pref}",
                    "exit",
                    "route-map LP-IN permit 20",
                    "exit",
                    "route-map TO-ISPB permit 10",
                    "match ip address prefix-list TO-ISPB",
                    "exit",
                    "route-map FROM-R4 permit 10",
                    f"set community {AS1}:{d.cust_tag}",
                    "exit",
                    "route-map TO-R4 permit 10",
                    "match ip address prefix-list DEFAULT-ONLY",
                    "exit",
                    f"router bgp {AS1}",
                    f"bgp router-id {lo3}",
                    "no bgp ebgp-requires-policy",
                    f"neighbor {d.ips.ispb_lb.ip} remote-as {AS_ISPB}",
                    f"neighbor {d.ips.ispb_lb.ip} description ISP-B",
                    f"neighbor {d.ips.ispb_lb.ip} timers {k} {hold}",
                    f"neighbor {d.ips.ispb_lb.ip} password {d.md5_key}",
                    f"neighbor {lo2} remote-as {AS1}",
                    f"neighbor {lo2} update-source lo",
                    f"neighbor {lo2} description r2",
                    f"neighbor {d.ips.r4_l34.ip} remote-as {AS_CUST}",
                    f"neighbor {d.ips.r4_l34.ip} description CLIENT-AS65300",
                    "address-family ipv4 unicast",
                    f"network {d.nets.as1_block}",
                    f"neighbor {d.ips.ispb_lb.ip} route-map LP-IN in",
                    f"neighbor {d.ips.ispb_lb.ip} route-map TO-ISPB out",
                    f"neighbor {lo2} next-hop-self",
                    f"neighbor {d.ips.r4_l34.ip} default-originate",
                    f"neighbor {d.ips.r4_l34.ip} route-map TO-R4 out",
                    f"neighbor {d.ips.r4_l34.ip} route-map FROM-R4 in",
                    "exit-address-family",
                    "exit")
        # ispb: MD5 counterpart of the bonus of part 2
        self._vtysh('ispb',
                    f"router bgp {AS_ISPB}",
                    f"neighbor {d.ips.r3_lb.ip} password {d.md5_key}",
                    "exit")
        # r4: the customer
        self._vtysh('r4',
                    f"router bgp {AS_CUST}",
                    f"bgp router-id {ROUTER_IDS['r4']}",
                    "no bgp ebgp-requires-policy",
                    f"neighbor {d.ips.r3_l34.ip} remote-as {AS1}",
                    f"neighbor {d.ips.r3_l34.ip} description FAI-AS65001",
                    "address-family ipv4 unicast",
                    f"network {d.nets.net4}",
                    "exit-address-family",
                    "exit")


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


def _as_path(s) -> str:
    """Normalise an AS-path typed by a student: '65100  65000' -> '65100 65000'."""
    return " ".join(str(s or "").replace(',', ' ').split())


def _same_ip(answer, expected) -> bool:
    return _norm(answer) == str(expected)


class Grade(Grade0):
    def __init__(self, net_scheme):
        super().__init__(net_scheme)
        self.section_fmt = [("N", 1), ("N", 2), ("l", 3), ("N", 4)]

    def grade(self):
        super().grade()
        d = self.get_data()
        routers = list(ROUTER_IFACES)
        ip = {attr: str(getattr(d.ips, attr).ip) for ifaces in ROUTER_IFACES.values() for _n, attr in ifaces}
        lo = {r: str(getattr(d.ips, attr).ip) for r, attr in LOOPBACKS.items()}
        block, net4, web = str(d.nets.as1_block), str(d.nets.net4), str(EXT_PUBLIC)
        neta, netb = str(d.nets.neta), str(d.nets.netb)
        k, hold = d.keepalive, 3 * d.keepalive
        community = f"{AS1}:{d.cust_tag}"

        # ---------------- diagnostics kept in the archive -------------------------
        for r in routers:
            for c in ('vtysh -c "show ip bgp"', 'vtysh -c "show ip bgp summary"', 'vtysh -c "show ip route"'):
                self.test(r, c, allow_error=True)

        # ---------------- live state (every call unconditional: two-pass contract) --
        summ = {r: get_bgp_summary(self, r, allow_error=True) for r in routers}
        routes = {r: get_bgp_routes(self, r, allow_error=True) for r in routers}
        conf = {r: get_frr_running_config(self, r, allow_error=True) for r in routers}
        kroutes = {r: get_kernel_routes(self, r, allow_error=True) for r in ('r1', 'r2', 'r3', 'r4')}
        nb_r3_ispb = get_bgp_neighbor(self, 'r3', ip['ispb_lb'], allow_error=True)
        nb_r2_lo1 = get_bgp_neighbor(self, 'r2', lo['r1'], allow_error=True)
        nb_r2_lo3 = get_bgp_neighbor(self, 'r2', lo['r3'], allow_error=True)
        pfx_r3_neta = get_bgp_prefix(self, 'r3', neta, allow_error=True)
        pfx_ispa_net4 = get_bgp_prefix(self, 'ispa', net4, allow_error=True)
        pfx_inet_net4 = get_bgp_prefix(self, 'inet', net4, allow_error=True)
        adv_r1_ispa = get_bgp_advertised_routes(self, 'r1', ip['ispa_la'], allow_error=True)
        adv_r3_ispb = get_bgp_advertised_routes(self, 'r3', ip['ispb_lb'], allow_error=True)
        get_bgp_advertised_routes(self, 'r3', ip['r4_l34'], allow_error=True)  # diagnostic
        tr_web_m1, _ = self.test('web', f'traceroute -n -q 1 -w 1 -m 8 {d.ips.m1.ip}', timeout=40, allow_error=True)

        def peer(r: str, addr) -> dict:
            return (summ[r].get('peers') or {}).get(str(addr)) or {}

        def established(r: str, addr, remote_as: int = None) -> bool:
            p = peer(r, addr)
            return bool(p.get('established')) and (remote_as is None or p.get('remote_as') == remote_as)

        def best(r: str, prefix) -> dict:
            return bgp_best_path(routes[r], prefix)

        def bgp_kroute(r: str, prefix) -> bool:
            entry = kroutes[r].get(str(prefix))
            return entry is not None and is_bgp_protocol(entry['protocol'])

        def neighbor_conf(r: str, addr) -> dict:
            return ((conf[r].get('router_bgp') or {}).get('neighbors') or {}).get(str(addr)) or {}

        def ping(src: str, dest) -> bool:
            return eval_ping(self, src=src, dest=dest, count=3, deadline=5, allow_error=True)

        # ---------------- organisation ---------------------------------------------
        self.question_dummy(
            title=tr("Organisation du TP"),
            hash="0f2f9ce69ea0fa34",
            description=tr("""
Lisez l'onglet **Informations** : il présente BGP (sessions, attributs, choix du meilleur chemin,
iBGP et réflecteur de routes, politiques de routage), la configuration de FRR avec `vtysh` et les
commandes de diagnostic.

**Le réseau.** Ce TP met en œuvre BGP avec la suite logicielle **FRRouting** (FRR). Vous
administrez l'**AS 65001** (routeurs `r1`, `r2`, `r3`, hôtes `m1` et `m3`), raccordé à deux
fournisseurs d'accès : **ISP A** (`ispa`, AS 65100) et **ISP B** (`ispb`, AS 65200), eux-mêmes
reliés entre eux et au « reste de l'Internet » (`inet`, AS 65000) où se trouve le serveur `web`
(`{web_host}`, nom `internet`). L'AS 65001 héberge en outre un **client** (`r4`, AS 65300, hôte
`m4`). Chaque AS a sa couleur dans le schéma.

- **Au départ**, `r1` est déjà en session eBGP avec `ispa` et annonce le bloc `{block}` de
  l'AS 65001. `r2`, `r3` et `r4` ont FRR démarré (`bgpd` actif) mais **aucune configuration
  BGP** ; l'IGP de l'AS 65001 (OSPF sur `r1`, `r2` et `r3`, loopbacks comprises) est en place.
- Les routeurs des fournisseurs et `inet` sont déjà entièrement configurés : vous pouvez vous y
  connecter pour observer ce qu'ils reçoivent (`vtysh`), mais leur configuration ne doit pas être
  modifiée (sauf indication contraire). Comme `r1`, ils ont désactivé la protection de la
  RFC 8212 (`no bgp ebgp-requires-policy`).
- Les fichiers `/etc/hosts` contiennent les noms de toutes les interfaces : `r3-eth2` désigne
  l'adresse de `eth2` de `r3`, `r3` (tout court) celle de `eth0`, `r3-lo` sa loopback, `ispa`
  l'adresse de `ispa` sur son réseau de clients `neta`.

**Plan d'adressage.**

| AS | routeur | interfaces | loopback |
|----|---------|------------|----------|
| 65001 | `r1` | eth0 `{net1}` (`net1`, hôte `m1`), eth1 `{l12}` (`l12`, vers `r2`), eth2 `{la}` (`la`, vers `ispa`) | `{lo1}` |
| 65001 | `r2` | eth0 `{l12}` (`l12`), eth1 `{l23}` (`l23`, vers `r3`) | `{lo2}` |
| 65001 | `r3` | eth0 `{net3}` (`net3`, hôte `m3`), eth1 `{l23}` (`l23`), eth2 `{lb}` (`lb`, vers `ispb`), eth3 `{l34}` (`l34`, vers `r4`) | `{lo3}` |
| 65300 | `r4` | eth0 `{net4}` (`net4`, hôte `m4`), eth1 `{l34}` (`l34`, vers `r3`) | – |
| 65100 | `ispa` | eth0 `{neta}` (`neta`, clients de l'ISP A), eth1 `{la}`, eth2 `{lab}` (`lab`, vers `ispb`), eth3 `{lai}` (`lai`, vers `inet`) | – |
| 65200 | `ispb` | eth0 `{netb}` (`netb`, clients de l'ISP B), eth1 `{lb}`, eth2 `{lab}`, eth3 `{lbi}` (`lbi`, vers `inet`) | – |
| 65000 | `inet` | eth0 `{web}` (`netweb`, serveur `web` = `{web_host}`), eth1 `{lai}`, eth2 `{lbi}` | – |

L'AS 65001 possède le bloc **`{block}`** (`net1`, `net3`, les liens internes et les loopbacks
`{loops}`).

**Consignes.**

- Les parties sont à faire **dans l'ordre** : chaque partie s'appuie sur la configuration
  réalisée dans les précédentes (les politiques des parties 4 à 7 se cumulent).
- Dans l'AS 65001, le router-id BGP de chaque routeur est l'adresse de sa **loopback**
  (`bgp router-id`, à définir en premier dans `router bgp 65001`).
- Sauvegardez régulièrement la configuration des routeurs (`write` dans vtysh).

**Plan du TP.**

1. **Découverte** de BGP sur `r1` et `ispa`, déjà configurés ;
2. **eBGP** : session entre `r3` et ISP B, annonce du bloc de l'AS ;
3. **iBGP** dans l'AS 65001 : sessions entre loopbacks, `next-hop-self`, trou noir ;
4. **Trafic sortant** : `local-preference`, temporisateurs et convergence ;
5. **Trafic entrant** : *AS-path prepend* ;
6. **Filtrage** : ne pas devenir un AS de transit ;
7. **Un client** : l'AS 65300 (`r4`), route par défaut, communauté ;
8. **Réflecteur de routes** à la place du maillage iBGP.

**Évaluation.** Chaque évaluation lit vos réponses et l'état des routeurs, les vôtres et ceux des
fournisseurs (sessions, tables BGP, routes annoncées, configuration), et lance des `ping` et un
`traceroute` entre les hôtes. Les valeurs demandées (local-preference, nombre de *prepend*,
temporisateurs, communauté, mot de passe) sont propres à votre instance du TP. Attendez que les
sessions soient `Established` et les routes propagées avant de lancer une évaluation.
""").format(block=block, web=web, web_host=WEB_HOST.ip, net1=d.nets.net1, net3=d.nets.net3, net4=net4,
            neta=neta, netb=netb, l12=d.nets.l12, l23=d.nets.l23, l34=d.nets.l34, la=d.nets.la, lb=d.nets.lb,
            lab=d.nets.lab, lai=d.nets.lai, lbi=d.nets.lbi, lo1=lo['r1'], lo2=lo['r2'], lo3=lo['r3'],
            loops=d.nets.loops)
            + instructor(tr("""
**Pour l'enseignant.** Valeurs de cette instance : local-preference **{lp}** ; *prepend*
**{prepend} fois** 65001 vers ISP A ; keepalive / hold time de la session `r3`–`ispb` :
**{k} s / {hold} s** ; communauté du client **`{community}`** ; mot de passe MD5 `{key}`. Chaque
question se termine par sa solution pour ces valeurs.

L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
formulaires. Il suppose l'état initial (il ne retire pas les sessions ajoutées à la main) et
construit l'iBGP directement dans sa forme finale, celle de la partie 8 : `r2` réflecteur de
routes, pas de session directe `r1`–`r3`. Attendez environ 60 s après l'avoir appliqué avant de
lancer une évaluation.
""").format(lp=d.local_pref, prepend=d.prepend, k=k, hold=hold, community=community, key=d.md5_key)),
        )

        # =====================================================================
        # Partie 1 — Découverte
        # =====================================================================
        part1 = self.add_grade_part(no_tr("partie1"), tr("Partie 1 — Découverte de BGP sur r1 et ispa"))
        q1 = self.question_form(
            section=self.section(0),
            title=tr("Découverte de BGP sur r1 et ispa"),
            hash="a79715b4b7db4a5e",
            description=tr("""
Sur `r1`, ouvrez `vtysh` et explorez la configuration en place (`show running-config`) ainsi que
les commandes `show ip bgp summary`, `show ip bgp`, `show ip bgp neighbors` et `show ip route`.
Observez les paquets BGP avec `tcpdump -ni eth2 -v tcp port 179` (patientez jusqu'à un
KEEPALIVE). Vérifiez depuis `m1` que vous joignez `internet` (`ping`, `traceroute`) et depuis
`m3` que ce n'est pas le cas.

- numéro d'AS du pair de `r1` : @@{as_ispa:[0-9]+}@@ ; port TCP utilisé par BGP : @@{port:[0-9]+}@@
- état de la session : @@{state:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@ ;
  nombre de préfixes reçus de `ispa` (colonne `State/PfxRcd`) : @@{nb_prefixes:[0-9]+}@@
- `AS_PATH` de la route vers `203.0.113.0/24` sur `r1` (dans l'ordre affiché) : @@{aspath_web:[0-9 ]+}@@
- distance administrative d'une route eBGP dans `show ip route` (entre crochets) : @@{ad:[0-9]+}@@
- hold time négocié : @@{hold:[0-9]+}@@ s et intervalle des KEEPALIVE : @@{keepalive:[0-9]+}@@ s
  (`show ip bgp neighbors`)
- pourquoi `m3` ne joint-il pas `internet` ?
  @@{why_m3:>r3 n'a aucune route vers ce réseau|ispa filtre le trafic de m3|r1 refuse de router le trafic de net3|le serveur web est en panne}@@
""")
            + instructor(tr("""
**Solution.** Rien à configurer : `vtysh -c "show ip bgp summary"`, `vtysh -c "show ip bgp"` et
`vtysh -c "show ip bgp neighbors {ispa_la}"` sur `r1`.

- AS du pair : **65100** ; port TCP **179** ;
- session **Established** ; **3** préfixes reçus : `{neta}` (ISP A), `{netb}` (ISP B, à travers
  ISP A) et `{web}` ;
- `AS_PATH` vers `{web}` : **65100 65000** ;
- distance administrative d'une route eBGP : **20** (`[20/0]` dans `show ip route`) ;
- hold time **180** s, keepalive **60** s : les valeurs par défaut ;
- `m3` : **`r3` n'a aucune route vers ce réseau**. `r3` ne parle pas encore BGP et OSPF ne
  transporte que les réseaux internes de l'AS 65001.

Évaluation : `decouverte_as_port`, `decouverte_aspath`, `decouverte_ad_timers` (1 point chacun),
`decouverte_etat_prefixes_typed` (0,5 : nombre de préfixes) ; pour l'enseignant seulement (choix
dans une liste) : `decouverte_etat_prefixes` (0,5 : état de la session), `decouverte_m3` (1).
""").format(ispa_la=ip['ispa_la'], neta=neta, netb=netb, web=web)),
            cheat_answers={"final": {
                "as_ispa": str(AS_ISPA), "port": "179", "state": "Established", "nb_prefixes": "3",
                "aspath_web": f"{AS_ISPA} {AS_INET}", "ad": "20", "hold": "180", "keepalive": "60",
                "why_m3": "r3 n'a aucune route vers ce réseau",
            }},
        )
        self.add_grade_element(
            title=no_tr("decouverte_as_port"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("as_ispa")) == AS_ISPA and _int(q1.get("port")) == 179),
            description=tr("numéro d'AS de ispa et port TCP de BGP"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_etat_prefixes_typed"), max_grade=0.5, grade_part=part1,
            grade=0.5 * int(_int(q1.get("nb_prefixes")) == 3),
            description=tr("nombre de préfixes reçus"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_etat_prefixes"), max_grade=0.5, grade_part=part1,
            grade=0.5 * int(_norm(q1.get("state")) == "established"),
            scope=CHOICE_SCOPE, description=tr("état de la session"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_aspath"), max_grade=1, grade_part=part1,
            grade=int(_as_path(q1.get("aspath_web")) == f"{AS_ISPA} {AS_INET}"),
            description=tr("AS_PATH de la route vers 203.0.113.0/24"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_ad_timers"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("ad")) == 20 and _int(q1.get("hold")) == 180 and _int(q1.get("keepalive")) == 60),
            description=tr("distance administrative eBGP, hold time et keepalive par défaut"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_m3"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("why_m3")).startswith("r3 n'a aucune route")),
            scope=CHOICE_SCOPE, description=tr("pourquoi m3 ne joint pas internet"),
        )

        # =====================================================================
        # Partie 2 — eBGP : r3 et ISP B
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — eBGP : r3 et ISP B"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Session eBGP entre r3 et ispb"),
            hash="b540af939825784a",
            description=tr("""
Sur `ispb`, observez `show ip bgp summary` : la session avec `r3` (`{r3_lb}`) est déjà déclarée
côté fournisseur mais n'est pas établie. Configurez BGP sur `r3` :

1. `router bgp 65001`, router-id `{lo3}` (sa loopback), pair `{ispb_lb}` dans l'AS 65200 ;
2. observez `show ip bgp summary` : la session s'établit, mais aucun préfixe n'est échangé
   (mention `(Policy)`, voir la RFC 8212 dans l'onglet **Informations**, section
   @@ref:rfc8212@@). Levez cette protection comme sur `r1` (ou définissez des politiques
   explicites) ;
3. annoncez le bloc **`{block}`** de l'AS 65001 (`network`, address-family `ipv4 unicast`).
   Vérifiez sur `ispb` (`show ip bgp {block}`) : tant que `r3` n'a pas de route vers ce
   préfixe exact, il ne l'annonce pas (`bgp network import-check`). Ajoutez la route statique
   `ip route {block} blackhole` comme sur `r1` et vérifiez que `ispb` reçoit désormais le bloc
   directement de `r3` (AS_PATH `65001`) et non plus seulement via `ispa`.

Vérifiez que `m3` joint `internet` et `ispb` (adresse `{ispb_netb}`, réseau des clients de
l'ISP B) et observez `show ip bgp` et `ip route` sur `r3`.

*Bonus* : protégez la session `r3`–`ispb` par un mot de passe MD5 (`neighbor X password
{key}`, à configurer sur `r3` **et** sur `ispb`, la seule modification autorisée sur un
fournisseur) et vérifiez qu'elle est de nouveau `Established`.
""").format(r3_lb=ip['r3_lb'], lo3=lo['r3'], ispb_lb=ip['ispb_lb'], block=block, ispb_netb=ip['ispb_netb'],
            key=d.md5_key)
            + instructor(tr("""
**Solution.** Dans `vtysh`, après `configure terminal` (puis `end` et `write`) :

```
! r3
ip route {block} blackhole
router bgp 65001
 bgp router-id {lo3}
 no bgp ebgp-requires-policy
 neighbor {ispb_lb} remote-as 65200
 neighbor {ispb_lb} description ISP-B
 address-family ipv4 unicast
  network {block}
 exit-address-family
```

1. Dès que le pair est déclaré, `r3` ouvre la connexion et la session passe `Established`.
2. Sans politique, les colonnes `State/PfxRcd` et `PfxSnt` de `show ip bgp summary` affichent
   `(Policy)` : rien n'est accepté ni annoncé. `no bgp ebgp-requires-policy` lève la protection,
   comme dans la configuration de `r1`.
3. Sans la route `blackhole`, `show ip bgp` sur `r3` liste le bloc sans `*>` et `ispb` ne le
   connaît que par ISP A (AS_PATH `65100 65001`). Avec elle, `show ip bgp {block}` sur `ispb`
   montre le chemin direct, AS_PATH `65001`, meilleur chemin. OSPF garde les routes plus précises
   vers `net1`, `net3` et les liens.

`r3` installe alors `neta`, `netb` et `203.0.113.0/24` (`ip route` : `proto bgp`) et `m3` joint
`internet` et `{ispb_netb}`.

Bonus : `neighbor {ispb_lb} password {key}` sur `r3` (mode `router bgp 65001`) et
`neighbor {r3_lb} password {key}` sur `ispb` (mode `router bgp 65200`). Tant qu'un seul côté
est configuré, la session retombe et ne se rétablit pas.

Évaluation : `ebgp_session_r3` (2 points : session `Established` avec l'AS 65200),
`ebgp_router_id_r3` (1), `ebgp_politique_rfc8212` (1 : pas de mention `(Policy)` et au moins trois
préfixes reçus), `ebgp_annonce_bloc` (2 : le meilleur chemin de `ispb` vers `{block}` vient de
`r3`, AS_PATH `65001`), `ebgp_routes_noyau_r3` (1 : routes `proto bgp` vers `neta`, `netb` et
`203.0.113.0/24`), `ebgp_pings_m3` (1), `ebgp_md5_bonus` (1 : le mot de passe dans la configuration
des deux routeurs et la session `Established`).
""").format(r3_lb=ip['r3_lb'], lo3=lo['r3'], ispb_lb=ip['ispb_lb'], block=block, ispb_netb=ip['ispb_netb'],
            key=d.md5_key)),
        )
        q2 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur la session eBGP"),
            hash="9fe8237741a5327e",
            description=tr("""
- état de la session vu de `ispb` **avant** la configuration de `r3` : @@{state_before:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@
- `AS_PATH` de la route vers `203.0.113.0/24` sur `r3` : @@{aspath_web:[0-9 ]+}@@ ;
  `NEXT_HOP` des routes reçues de `ispb` : @@{nexthop:[0-9.]+}@@
- TTL des paquets BGP émis par `r3` vers `ispb` (`tcpdump -v`) : @@{ttl:[0-9]+}@@
""")
            + instructor(tr("""
**Solution.**

- avant : **Active** (`ispb` tente périodiquement d'ouvrir la connexion TCP, que `r3` refuse ;
  `Connect` est accepté aussi) ;
- AS_PATH vers `203.0.113.0/24` sur `r3` : **65200 65000** ; NEXT_HOP : **`{ispb_lb}`**,
  l'adresse de `ispb` sur le lien `lb` ;
- TTL : **1** (`tcpdump -ni eth2 -v tcp port 179` sur `r3` : `ttl 1`) : deux pairs eBGP sont
  directement connectés.

Évaluation (1 point chacun) : `ebgp_q_aspath_nexthop`, `ebgp_q_ttl` ; pour l'enseignant
seulement (choix dans une liste) : `ebgp_q_etat_avant`.
""").format(ispb_lb=ip['ispb_lb'])),
            cheat_answers={"final": {"state_before": "Active", "aspath_web": f"{AS_ISPB} {AS_INET}",
                                     "nexthop": ip['ispb_lb'], "ttl": "1"}},
        )
        r3_session = established('r3', ip['ispb_lb'], AS_ISPB)
        self.add_grade_element(
            title=no_tr("ebgp_session_r3"), max_grade=2, grade_part=part2, grade=2 * int(r3_session),
            description=tr("session r3–ispb Established (AS 65200)"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_router_id_r3"), max_grade=1, grade_part=part2,
            grade=int(summ['r3'].get('router_id') == lo['r3']),
            description=tr("router-id de r3 = {lo3}").format(lo3=lo['r3']),
        )
        p_r3 = peer('r3', ip['ispb_lb'])
        policy_ok = r3_session and not p_r3.get('policy_blocked') and p_r3.get('pfx_rcd', 0) >= 3
        self.add_grade_element(
            title=no_tr("ebgp_politique_rfc8212"), max_grade=1, grade_part=part2, grade=int(policy_ok),
            description=tr("la session échange des préfixes (RFC 8212 : politique définie ou désactivée)"),
        )
        b_ispb_block = best('ispb', block)
        announce_ok = b_ispb_block.get('peer') == ip['r3_lb'] and b_ispb_block.get('as_list') == [AS1]
        self.add_grade_element(
            title=no_tr("ebgp_annonce_bloc"), max_grade=2, grade_part=part2, grade=2 * int(announce_ok),
            description=tr("ispb reçoit {block} directement de r3 (AS_PATH 65001)").format(block=block),
        )
        r3_kroutes = all([bgp_kroute('r3', neta), bgp_kroute('r3', netb), bgp_kroute('r3', web)])
        self.add_grade_element(
            title=no_tr("ebgp_routes_noyau_r3"), max_grade=1, grade_part=part2, grade=int(r3_kroutes),
            description=tr("r3 a des routes BGP (proto bgp) vers neta, netb et 203.0.113.0/24"),
        )
        pings_m3 = all([ping('m3', WEB_HOST.ip), ping('m3', d.ips.ispb_netb.ip)])
        self.add_grade_element(
            title=no_tr("ebgp_pings_m3"), max_grade=1, grade_part=part2, grade=int(pings_m3),
            description=tr("m3 joint internet et ispb"),
        )
        md5_ok = (r3_session and neighbor_conf('r3', ip['ispb_lb']).get('password') == d.md5_key
                  and neighbor_conf('ispb', ip['r3_lb']).get('password') == d.md5_key)
        self.add_grade_element(
            title=no_tr("ebgp_md5_bonus"), max_grade=1, grade_part=part2, grade=int(md5_ok),
            description=tr("bonus : session r3–ispb authentifiée par MD5 des deux côtés"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_q_etat_avant"), max_grade=1, grade_part=part2,
            grade=int(_norm(q2.get("state_before")) in ("active", "connect")), scope=CHOICE_SCOPE,
            description=tr("état de la session côté ispb avant la configuration de r3"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_q_aspath_nexthop"), max_grade=1, grade_part=part2,
            grade=int(_as_path(q2.get("aspath_web")) == f"{AS_ISPB} {AS_INET}" and _same_ip(q2.get("nexthop"), ip['ispb_lb'])),
            description=tr("AS_PATH et NEXT_HOP des routes reçues de ispb"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_q_ttl"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get("ttl")) == 1),
            description=tr("TTL des paquets eBGP"),
        )

        # =====================================================================
        # Partie 3 — iBGP
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — iBGP dans l'AS 65001"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Sessions iBGP, next-hop-self et trou noir"),
            hash="b41681b24724ee7b",
            description=tr("""
`r1` ne connaît que ce que lui annonce `ispa`, `r3` que ce que lui annonce `ispb` : si le lien
d'un fournisseur tombe, la moitié de l'AS perd l'Internet alors que l'autre fournisseur est
disponible. Les routeurs de l'AS doivent partager leurs routes externes en **iBGP**.

1. Établissez une session iBGP entre `r1` et `r3` **entre leurs loopbacks** (`neighbor {lo3}
   remote-as 65001` + `neighbor {lo3} update-source lo` sur `r1`, et symétriquement sur `r3`).
   Observez sur `r1` la route vers `netb` (`{netb}`, `show ip bgp {netb}`) : quel est son
   `NEXT_HOP` ? Pourquoi n'est-elle pas valide (`*`) ?
2. Sur `r1` et `r3`, activez `next-hop-self` vers les pairs iBGP (address-family). Vérifiez que
   les routes apprises en iBGP sont désormais valides et installées (`ip route`, distance 200).
3. Coupez la session avec ISP A (`neighbor {ispa_la} shutdown` sur `r1`) et lancez `ping
   internet` depuis `m1` : `r1` envoie le trafic vers `r3` via `r2`… qui ne connaît pas
   `203.0.113.0/24` (**trou noir**, `traceroute`). Rétablissez la session (`no neighbor … shutdown`).
4. Ajoutez `r2` au maillage iBGP (router-id `{lo2}`, sessions avec `r1` et `r3` entre
   loopbacks) et refaites l'expérience du point 3 : le trafic passe maintenant par ISP B.

Vérifiez pour finir que `m3` joint `ispa` (`{ispa_neta}`) et `m1` joint `ispb` (`{ispb_netb}`).
""").format(lo3=lo['r3'], lo2=lo['r2'], netb=netb, ispa_la=ip['ispa_la'], ispa_neta=ip['ispa_neta'],
            ispb_netb=ip['ispb_netb'])
            + instructor(tr("""
**Solution.**

```
! étapes 1 et 2 — r1
router bgp 65001
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
 address-family ipv4 unicast
  neighbor {lo3} next-hop-self
 exit-address-family
! étapes 1 et 2 — r3
router bgp 65001
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 address-family ipv4 unicast
  neighbor {lo1} next-hop-self
 exit-address-family
!
! étape 4 — r2
router bgp 65001
 bgp router-id {lo2}
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
! étape 4 — r1 (et r3 de même)
router bgp 65001
 neighbor {lo2} remote-as 65001
 neighbor {lo2} update-source lo
 address-family ipv4 unicast
  neighbor {lo2} next-hop-self
 exit-address-family
```

1. Sur `r1`, le chemin iBGP vers `{netb}` a pour `NEXT_HOP` `{ispb_lb}`, l'adresse de `ispb` sur
   le lien `lb` : en iBGP le `NEXT_HOP` n'est pas modifié. Ce lien n'est pas dans OSPF, `r1` n'a
   aucune route vers cette adresse : le chemin est inaccessible, sans `*`, et `r1` garde son
   chemin par ISP A.
2. Avec `next-hop-self`, `r3` annonce ses routes externes avec sa loopback `{lo3}`, connue par
   OSPF : le chemin devient valide et, plus court (`65200` contre `65100 65200`), il est choisi
   et installé (`[200/0]` dans `show ip route`).
3. Session ISP A coupée : `r1` envoie le trafic vers `{lo3}`, donc à `r2`, qui n'a aucune route
   vers `203.0.113.0/24` et le jette (`traceroute` s'arrête à `r2`).
4. Avec BGP sur `r2`, toute la chaîne connaît les routes externes et `m1` joint `internet` par
   ISP B. Ne pas oublier `no neighbor {ispa_la} shutdown` sur `r1`.

L'état `final` ne crée pas la session directe `r1`–`r3` : il construit directement la forme de
la partie 8.

Évaluation : `ibgp_sessions_r2` (2 points : `r2` en session `Established` avec `{lo1}` et
`{lo3}`), `ibgp_next_hop_self` (2 : sur `r2`, `neta` a pour prochain saut `{lo1}` et `netb`
`{lo3}`, routes iBGP installées dans le noyau), `ibgp_routes_bordure` (1 : `r1` connaît `netb`
par `r3` et `r3` connaît `neta` par `r1`), `ibgp_pings` (2 : `m3` joint `{ispa_neta}` et `m1`
joint `{ispb_netb}`).
""").format(lo1=lo['r1'], lo2=lo['r2'], lo3=lo['r3'], netb=netb, ispa_la=ip['ispa_la'], ispb_lb=ip['ispb_lb'],
            ispa_neta=ip['ispa_neta'], ispb_netb=ip['ispb_netb'])),
        )
        q3 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur iBGP"),
            hash="1251d6a4a9eb0d05",
            description=tr("""
- distance administrative d'une route iBGP : @@{ad_ibgp:[0-9]+}@@ ; nombre de sessions iBGP
  nécessaires pour mailler complètement un AS de 10 routeurs : @@{sessions10:[0-9]+}@@
- avant `next-hop-self`, le `NEXT_HOP` de la route vers `netb` sur `r1` est :
  @@{nh_before:>l'adresse de ispb sur le lien lb|la loopback de r3|l'adresse de r3 sur l23|l'adresse de r2}@@
- pourquoi `r2` doit-il parler BGP ?
  @@{why_r2:>r2 relaie le trafic entre r1 et r3 et doit connaître les destinations externes|r2 doit élire un DR|OSPF ne fonctionne pas sans BGP|pour que r1 et r3 puissent établir leur session}@@
""")
            + instructor(tr("""
**Solution.**

- distance administrative iBGP : **200** ; maillage de 10 routeurs : 10 × 9 ÷ 2 = **45** sessions ;
- `NEXT_HOP` avant `next-hop-self` : **l'adresse de ispb sur le lien lb** (`{ispb_lb}`),
  transmise telle quelle en iBGP ;
- **`r2` relaie le trafic entre `r1` et `r3` et doit connaître les destinations externes** :
  la session `r1`–`r3` s'établit très bien sans lui (OSPF suffit à joindre les loopbacks), mais
  les paquets, eux, traversent `r2`.

Évaluation (1 point chacun) : `ibgp_q_ad_sessions` ; pour l'enseignant seulement (choix dans
une liste) : `ibgp_q_nexthop`, `ibgp_q_r2`.
""").format(ispb_lb=ip['ispb_lb'])),
            cheat_answers={"final": {"ad_ibgp": "200", "sessions10": "45",
                                     "nh_before": "l'adresse de ispb sur le lien lb",
                                     "why_r2": "r2 relaie le trafic entre r1 et r3 et doit connaître les destinations externes"}},
        )
        r2_sessions = established('r2', lo['r1'], AS1) and established('r2', lo['r3'], AS1)
        self.add_grade_element(
            title=no_tr("ibgp_sessions_r2"), max_grade=2, grade_part=part3, grade=2 * int(r2_sessions),
            description=tr("r2 est en session iBGP (Established) avec les loopbacks de r1 et r3"),
        )
        b_r2_neta, b_r2_netb = best('r2', neta), best('r2', netb)
        nhs_ok = (b_r2_neta.get('nexthop') == lo['r1'] and b_r2_neta.get('path_from') == 'internal'
                  and b_r2_netb.get('nexthop') == lo['r3'] and b_r2_netb.get('path_from') == 'internal'
                  and bgp_kroute('r2', neta) and bgp_kroute('r2', netb))
        self.add_grade_element(
            title=no_tr("ibgp_next_hop_self"), max_grade=2, grade_part=part3, grade=2 * int(nhs_ok),
            description=tr("sur r2, neta a pour prochain saut la loopback de r1 et netb celle de r3 (next-hop-self), routes installées"),
        )
        border_ok = (best('r1', netb).get('nexthop') in (lo['r3'], lo['r2'])
                     and best('r3', neta).get('nexthop') in (lo['r1'], lo['r2']))
        self.add_grade_element(
            title=no_tr("ibgp_routes_bordure"), max_grade=1, grade_part=part3, grade=int(border_ok),
            description=tr("r1 connaît netb par r3 et r3 connaît neta par r1"),
        )
        pings_ibgp = all([ping('m3', d.ips.ispa_neta.ip), ping('m1', d.ips.ispb_netb.ip)])
        self.add_grade_element(
            title=no_tr("ibgp_pings"), max_grade=2, grade_part=part3, grade=2 * int(pings_ibgp),
            description=tr("m3 joint ispa et m1 joint ispb"),
        )
        self.add_grade_element(
            title=no_tr("ibgp_q_ad_sessions"), max_grade=1, grade_part=part3,
            grade=int(_int(q3.get("ad_ibgp")) == 200 and _int(q3.get("sessions10")) == 45),
            description=tr("distance administrative iBGP et nombre de sessions d'un maillage"),
        )
        self.add_grade_element(
            title=no_tr("ibgp_q_nexthop"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("nh_before")).startswith("l'adresse de ispb")), scope=CHOICE_SCOPE,
            description=tr("NEXT_HOP transmis tel quel en iBGP"),
        )
        self.add_grade_element(
            title=no_tr("ibgp_q_r2"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("why_r2")).startswith("r2 relaie")), scope=CHOICE_SCOPE,
            description=tr("rôle de BGP sur le routeur de transit r2"),
        )

        # =====================================================================
        # Partie 4 — Meilleur chemin et local-preference
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Choix du meilleur chemin : local-preference"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Trafic sortant : préférer ISP B pour l'Internet"),
            hash="b4e3235263b64de0",
            description=tr("""
Le préfixe `203.0.113.0/24` est connu par deux chemins d'AS de même longueur (via ISP A et via
ISP B). Observez sur `r1`, `r2` et `r3` quel chemin est retenu et pourquoi (`show ip bgp
203.0.113.0/24`, dernière ligne de chaque chemin ; `traceroute internet` depuis `m1` et `m3`).

ISP B offre un meilleur débit vers l'Internet : faites en sorte que **tout** le trafic de l'AS
65001 vers `203.0.113.0/24` sorte par `r3` et ISP B, **sans changer** le chemin vers les autres
réseaux (`neta` reste joint directement par `r1`). Sur `r3`, appliquez en entrée de la session
avec `ispb` une `route-map` qui affecte la **local-preference {lp}** aux routes vers
`203.0.113.0/24` seulement (`ip prefix-list` + `route-map … permit 10 / match ip address
prefix-list … / set local-preference {lp}`, suivie d'une séquence `permit 20` vide pour laisser
passer les autres routes), puis `clear bgp {ispb_lb} soft in`. Vérifiez sur `r1` : la route
via `r3` est maintenant préférée à sa propre route eBGP.

Réglez ensuite les temporisateurs de la session `r3`–`ispb` : keepalive **{k} s**, hold time
**{hold} s** (`neighbor {ispb_lb} timers {k} {hold}`, puis `clear bgp {ispb_lb}` : les
temporisateurs sont négociés à l'ouverture de la session). Vérifiez avec `show ip bgp neighbors`.

Mesurez enfin le temps de convergence en lançant `ping internet` depuis `m3` et en provoquant
trois pannes différentes sur `r3` :

- coupure administrative : `neighbor {ispb_lb} shutdown` (puis `no neighbor {ispb_lb} shutdown`) ;
- coupure franche : `ip link set eth2 down` (puis `ip link set eth2 up`) ;
- panne silencieuse : le lien reste « up » mais plus rien ne sort de `r3` par `eth2` :
  `tc qdisc add dev eth2 root netem loss 100%` (puis `tc qdisc del dev eth2 root` pour
  rétablir). Observez `show ip bgp summary` sur `r3` et sur `ispb` pendant la panne : les
  KEEPALIVE de `r3` n'arrivent plus, `ispb` ferme la session à l'expiration de son hold time.
""").format(lp=d.local_pref, ispb_lb=ip['ispb_lb'], k=k, hold=hold)
            + instructor(tr("""
**Solution.** Avant : les deux chemins vers `203.0.113.0/24` ont un AS_PATH de deux AS. `r1` et
`r3` gardent chacun leur chemin eBGP (préféré à l'iBGP) ; `r2`, qui n'a que deux chemins iBGP
équivalents, retient celui du pair au plus petit router-id, `r1` : `m1` sort par ISP A, `m3` par
ISP B.

```
! r3
ip prefix-list WEB seq 5 permit {web}
route-map LP-IN permit 10
 match ip address prefix-list WEB
 set local-preference {lp}
route-map LP-IN permit 20
router bgp 65001
 neighbor {ispb_lb} timers {k} {hold}
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map LP-IN in
 exit-address-family
```

puis `clear bgp {ispb_lb} soft in` (la politique) et `clear bgp {ispb_lb}` (les temporisateurs).

- `show ip bgp {web}` sur `r1` : le chemin iBGP par `{lo3}` porte `localpref {lp}` et devient le
  meilleur (`Local Pref`), devant le chemin eBGP de `r1` (100) ; `ip route` sur `r1` : `{web}`
  par `{r2_l12}`. `traceroute internet` depuis `m1` : `r1`, `r2`, `r3`, `ispb`, `inet`. Sans la
  séquence `permit 20`, les autres routes reçues de `ispb` seraient refusées.
- `neta` n'est pas dans la liste `WEB` : `r1` le joint toujours directement par `ispa`.
- `show ip bgp neighbors {ispb_lb}` sur `r3` : hold time {hold} s, keepalive {k} s. `ispb` garde
  180 s dans sa configuration : la plus petite des deux valeurs est retenue.
- Convergence, à ce stade du TP : `shutdown` et `ip link set eth2 down` ne font perdre aucun
  `ping` (`r3` ferme la session aussitôt et sort par `r1` ; les réponses reviennent par ISP A,
  que `inet` préfère tant que la partie 5 n'est pas faite). Avec `netem loss 100%`, la session
  reste `Established` environ {hold} s, jusqu'à ce que `ispb` la ferme : autant de `ping`
  perdus, puis le trafic repart par `r1`. Une fois la partie 5 faite, le trafic entrant arrive
  par ISP B et la coupure franche coûte elle aussi un hold time : `ispb`, dont l'interface reste
  active, continue d'envoyer vers `r3`.

Évaluation : `lp_valeur_r3` (1 point : sur `r3`, le chemin reçu de `ispb` a la local-preference
{lp}), `lp_effet_r1` (2 : le meilleur chemin de `r1` vers `{web}` est le chemin iBGP par `r3`),
`lp_route_noyau_r1` (1 : route du noyau de `r1` par `{r2_l12}`), `lp_effet_r2` (1 : prochain saut
`{lo3}` sur `r2`), `lp_neta_inchange` (1 : `r1` garde son chemin eBGP vers `neta`), `lp_timers`
(1 : keepalive {k} s et hold time {hold} s négociés).
""").format(lp=d.local_pref, ispb_lb=ip['ispb_lb'], k=k, hold=hold, web=web, lo3=lo['r3'],
            r2_l12=ip['r2_l12'])),
        )
        q4 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le choix du meilleur chemin"),
            hash="0e246706b01cbc12",
            description=tr("""
- **avant** la modification, critère qui départage les deux chemins sur `r2` :
  @@{crit_r2:>local-preference|longueur de l'AS_PATH|métrique IGP vers le NEXT_HOP|router-id du pair le plus petit|MED}@@
  et sur `r1` : @@{crit_r1:>local-preference|route eBGP préférée à la route iBGP|longueur de l'AS_PATH|router-id du pair le plus petit}@@
- **après** la modification, routeurs traversés par le trafic de `m1` vers `internet` :
  @@{via:>r1, ispa, inet|r1, r2, r3, ispb, inet|r1, r2, r3, ispa, inet|r1, ispa, ispb, inet}@@
- attribut qui n'est jamais transmis sur une session eBGP : @@{not_sent:>LOCAL_PREF|AS_PATH|NEXT_HOP|MED|ORIGIN}@@
- temps avant que `m3` ne joigne de nouveau `internet` après la coupure administrative :
  @@{shutdown:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@,
  après la coupure franche : @@{linkdown:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@,
  après la panne silencieuse : @@{silent:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@
""")
            + instructor(tr("""
**Solution.**

- avant, sur `r2` : **router-id du pair le plus petit** (deux chemins iBGP de même
  local-preference, même longueur d'AS_PATH, même origine, même métrique IGP : `{lo1}` <
  `{lo3}`) ; sur `r1` : **route eBGP préférée à la route iBGP** ;
- après : **r1, r2, r3, ispb, inet** ;
- jamais transmis en eBGP : **LOCAL_PREF** (il n'a de sens qu'à l'intérieur de l'AS) ;
- coupure administrative : **immédiatement** ; coupure franche : **immédiatement** ; panne
  silencieuse : **environ le hold time** ({hold} s).

Évaluation (enseignant seulement, 1 point chacun) : `lp_q_criteres`, `lp_q_chemin`,
`lp_q_attribut`, `lp_q_convergence`.
""").format(lo1=lo['r1'], lo3=lo['r3'], hold=hold)),
            cheat_answers={"final": {"crit_r2": "router-id du pair le plus petit",
                                     "crit_r1": "route eBGP préférée à la route iBGP",
                                     "via": "r1, r2, r3, ispb, inet", "not_sent": "LOCAL_PREF",
                                     "shutdown": "immédiatement (moins de 5 s)",
                                     "linkdown": "immédiatement (moins de 5 s)",
                                     "silent": "environ le hold time"}},
        )
        lp_r3 = bool(bgp_paths(routes['r3'], web, peer=ip['ispb_lb']))
        lp_r3 = lp_r3 and any(p.get('locprf') == d.local_pref for p in bgp_paths(routes['r3'], web, peer=ip['ispb_lb']))
        self.add_grade_element(
            title=no_tr("lp_valeur_r3"), max_grade=1, grade_part=part4, grade=int(lp_r3),
            description=tr("sur r3, la route vers 203.0.113.0/24 reçue de ispb a la local-preference {lp}").format(lp=d.local_pref),
        )
        b_r1_web = best('r1', web)
        lp_r1 = (b_r1_web.get('nexthop') in (lo['r3'], lo['r2']) and b_r1_web.get('path_from') == 'internal'
                 and (b_r1_web.get('locprf') == d.local_pref or 'local pref' in str(b_r1_web.get('reason') or '').lower()))
        self.add_grade_element(
            title=no_tr("lp_effet_r1"), max_grade=2, grade_part=part4, grade=2 * int(lp_r1),
            description=tr("r1 préfère le chemin iBGP via r3 pour 203.0.113.0/24 (local-preference)"),
        )
        r1_web_gw = kernel_route_gateways(kroutes['r1'], web, protocols=BGP_ROUTE_PROTOCOLS)
        self.add_grade_element(
            title=no_tr("lp_route_noyau_r1"), max_grade=1, grade_part=part4,
            grade=int(r1_web_gw == [ip['r2_l12']]),
            description=tr("la route du noyau de r1 vers 203.0.113.0/24 passe par r2"),
        )
        self.add_grade_element(
            title=no_tr("lp_effet_r2"), max_grade=1, grade_part=part4,
            grade=int(best('r2', web).get('nexthop') == lo['r3']),
            description=tr("r2 route 203.0.113.0/24 vers la loopback de r3"),
        )
        neta_direct = lp_r1 and best('r1', neta).get('path_from') == 'external'
        self.add_grade_element(
            title=no_tr("lp_neta_inchange"), max_grade=1, grade_part=part4, grade=int(neta_direct),
            description=tr("r1 joint toujours neta directement par ispa (local-preference limitée à 203.0.113.0/24)"),
        )
        timers_ok = (nb_r3_ispb.get('established') and nb_r3_ispb.get('hold_time') == hold
                     and nb_r3_ispb.get('keepalive') == k)
        self.add_grade_element(
            title=no_tr("lp_timers"), max_grade=1, grade_part=part4, grade=int(bool(timers_ok)),
            description=tr("keepalive {k} s / hold time {hold} s négociés sur la session r3–ispb").format(k=k, hold=hold),
        )
        self.add_grade_element(
            title=no_tr("lp_q_criteres"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("crit_r2")).startswith("router-id") and _norm(q4.get("crit_r1")).startswith("route ebgp")),
            scope=CHOICE_SCOPE, description=tr("critères de choix avant la modification (r2 et r1)"),
        )
        self.add_grade_element(
            title=no_tr("lp_q_chemin"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("via")) == "r1, r2, r3, ispb, inet"), scope=CHOICE_SCOPE,
            description=tr("chemin de m1 vers internet après la modification"),
        )
        self.add_grade_element(
            title=no_tr("lp_q_attribut"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("not_sent")) == "local_pref"), scope=CHOICE_SCOPE,
            description=tr("attribut jamais transmis en eBGP"),
        )
        conv_ok = (_norm(q4.get("shutdown")).startswith("immédiatement") and _norm(q4.get("linkdown")).startswith("immédiatement")
                   and _norm(q4.get("silent")).startswith("environ le hold"))
        self.add_grade_element(
            title=no_tr("lp_q_convergence"), max_grade=1, grade_part=part4, grade=int(conv_ok),
            scope=CHOICE_SCOPE, description=tr("temps de convergence observés"),
        )

        # =====================================================================
        # Partie 5 — Trafic entrant : AS-path prepend
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Trafic entrant : AS-path prepend et MED"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Influencer le trafic entrant"),
            hash="978649f689074080",
            description=tr("""
Le trafic **entrant** (de `internet` vers `m1`) est décidé par les autres AS. Observez sur
`inet` (`show ip bgp {block}`) les deux chemins vers le bloc de l'AS 65001 et lequel est
retenu (les fournisseurs et `inet` utilisent `bgp bestpath compare-routerid`, sans quoi le
chemin le plus ancien l'emporterait). Vérifiez avec `traceroute m1` depuis `web`.

Faites entrer le trafic par **ISP B** sans toucher aux fournisseurs : sur `r1`, appliquez en
sortie de la session avec `ispa` une `route-map` qui **allonge l'AS_PATH** de vos annonces en y
ajoutant **{prepend} fois** votre numéro d'AS (`set as-path prepend 65001 …`), puis `clear bgp
{ispa_la} soft out`. Observez le résultat sur `ispa` (`show ip bgp {block}`), sur `inet` et
avec `traceroute` depuis `web`.

Le **MED** ne peut pas servir ici : il n'est comparé qu'entre chemins reçus du *même* AS voisin
(il servirait si l'AS 65001 avait deux liens vers ISP B).
""").format(block=block, prepend=d.prepend, ispa_la=ip['ispa_la'])
            + instructor(tr("""
**Solution.** Avant : `show ip bgp {block}` sur `inet` montre deux chemins de même longueur,
`65100 65001` et `65200 65001` ; le meilleur est celui d'ISP A, départagé par le router-id du
pair (`100.100.100.100` < `200.200.200.200`). `traceroute m1` depuis `web` passe par `ispa`.

```
! r1
route-map TO-ISPA permit 10
 set as-path prepend {prepend_list}
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispa_la} route-map TO-ISPA out
 exit-address-family
```

puis `clear bgp {ispa_la} soft out`.

- Sur `ispa`, le chemin direct a maintenant l'AS_PATH `{aspath}` ({n} fois 65001) : `ispa`
  lui-même préfère passer par ISP B (`65200 65001`).
- Sur `inet`, le chemin par ISP A devient `65100 65200 65001` (`ispa` annonce son nouveau
  meilleur chemin) : `65200 65001`, plus court, l'emporte.
- `traceroute -n m1` depuis `web` : `inet`, `ispb`, `r3` (`{r3_lb}`), `r2`, `r1`, `m1`.

Évaluation : `prepend_annonce` (1 point : `ispa` reçoit `{block}` de `r1` avec {n} fois 65001),
`prepend_effet_inet` (2 : le meilleur chemin de `inet` est `65200 65001`), `prepend_traceroute`
(1 : le `traceroute` de `web` vers `m1` lancé par l'évaluation contient `{r3_lb}`).
""").format(block=block, ispa_la=ip['ispa_la'], r3_lb=ip['r3_lb'], n=d.prepend + 1,
            prepend_list=" ".join([str(AS1)] * d.prepend), aspath=" ".join([str(AS1)] * (d.prepend + 1)))),
        )
        q5 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le trafic entrant"),
            hash="f3f1965860aeb4ff",
            description=tr("""
- **avant** la modification, `inet` atteint l'AS 65001 par : @@{{before_via:>ISP A (65100)|ISP B (65200)}}@@,
  critère de choix : @@{{before_crit:>longueur de l'AS_PATH|MED|local-preference|router-id du pair le plus petit}}@@
- **après** la modification, quel chemin `ispa` préfère-t-il vers `{block}` ?
  @@{{ispa_now:>directement par r1|par ISP B (65200)}}@@
- le MED n'est comparé qu'entre chemins issus du même AS voisin : @@{{med:>vrai|faux}}@@
- leviers sur le trafic **entrant** : @@{{inbound:>AS-path prepend, MED|local-preference, weight}}@@ ;
  sur le trafic **sortant** : @@{{outbound:>AS-path prepend, MED|local-preference, weight}}@@
""").format(block=block)
            + instructor(tr("""
**Solution.**

- avant : **ISP A (65100)**, critère **router-id du pair le plus petit** (`inet` utilise
  `bgp bestpath compare-routerid`) ;
- après, `ispa` préfère passer **par ISP B (65200)** ;
- MED comparé seulement entre chemins du même AS voisin : **vrai** ;
- trafic entrant : **AS-path prepend, MED** ; trafic sortant : **local-preference, weight**.

Évaluation (enseignant seulement, 1 point chacun) : `prepend_q_avant`, `prepend_q_ispa`,
`prepend_q_med_leviers`.
""")),
            cheat_answers={"final": {"before_via": "ISP A (65100)", "before_crit": "router-id du pair le plus petit",
                                     "ispa_now": "par ISP B (65200)", "med": "vrai",
                                     "inbound": "AS-path prepend, MED", "outbound": "local-preference, weight"}},
        )
        prepended = [AS1] * (d.prepend + 1)
        prepend_ok = any(p.get('as_list') == prepended for p in bgp_paths(routes['ispa'], block, peer=ip['r1_la']))
        self.add_grade_element(
            title=no_tr("prepend_annonce"), max_grade=1, grade_part=part5, grade=int(prepend_ok),
            description=tr("ispa reçoit {block} de r1 avec l'AS_PATH allongé ({n} fois 65001)").format(block=block, n=d.prepend + 1),
        )
        self.add_grade_element(
            title=no_tr("prepend_effet_inet"), max_grade=2, grade_part=part5,
            grade=2 * int(best('inet', block).get('as_list') == [AS_ISPB, AS1]),
            description=tr("inet préfère le chemin par ISP B vers {block}").format(block=block),
        )
        self.add_grade_element(
            title=no_tr("prepend_traceroute"), max_grade=1, grade_part=part5,
            grade=int(ip['r3_lb'] in (tr_web_m1 or '')),
            description=tr("le traceroute de web vers m1 traverse r3 (lien lb)"),
        )
        self.add_grade_element(
            title=no_tr("prepend_q_avant"), max_grade=1, grade_part=part5,
            grade=int(_norm(q5.get("before_via")).startswith("isp a") and _norm(q5.get("before_crit")).startswith("router-id")),
            scope=CHOICE_SCOPE, description=tr("chemin et critère de choix de inet avant la modification"),
        )
        self.add_grade_element(
            title=no_tr("prepend_q_ispa"), max_grade=1, grade_part=part5,
            grade=int(_norm(q5.get("ispa_now")).startswith("par isp b")), scope=CHOICE_SCOPE,
            description=tr("chemin préféré par ispa après la modification"),
        )
        self.add_grade_element(
            title=no_tr("prepend_q_med_leviers"), max_grade=1, grade_part=part5,
            grade=int(_norm(q5.get("med")) == "vrai" and _norm(q5.get("inbound")).startswith("as-path")
                      and _norm(q5.get("outbound")).startswith("local-preference")),
            scope=CHOICE_SCOPE, description=tr("MED et leviers sur le trafic entrant / sortant"),
        )

        # =====================================================================
        # Partie 6 — Filtrage et non-transit
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Filtrage : ne pas devenir un AS de transit"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrer les annonces vers les fournisseurs"),
            hash="b00e8497ecac8516",
            description=tr("""
Par défaut, un routeur annonce à ses pairs eBGP **tous** ses meilleurs chemins : `r1` annonce à
`ispa` les routes apprises d'ISP B (`show ip bgp neighbors {ispa_la} advertised-routes` sur
`r1`, `show ip bgp {netb}` sur `ispa`) et `r3` annonce à `ispb` celles apprises d'ISP A. L'AS
65001 se propose ainsi comme **transit** entre ses deux fournisseurs : si le lien `lab` tombait,
du trafic entre les clients d'ISP A et ceux d'ISP B passerait par vos routeurs.

Sur `r1` (vers `ispa`) et sur `r3` (vers `ispb`), n'annoncez que le bloc **`{block}`** : une
`ip prefix-list` et une `route-map … out` (sur `r1`, complétez la route-map de la partie 5),
puis `clear bgp … soft out`. Vérifiez avec `advertised-routes` et sur les fournisseurs.
""").format(ispa_la=ip['ispa_la'], netb=netb, block=block)
            + instructor(tr("""
**Solution.**

```
! r1 : la route-map de la partie 5 reçoit une clause match
ip prefix-list TO-ISPA seq 5 permit {block}
route-map TO-ISPA permit 10
 match ip address prefix-list TO-ISPA
!
! r3
ip prefix-list TO-ISPB seq 5 permit {block}
route-map TO-ISPB permit 10
 match ip address prefix-list TO-ISPB
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map TO-ISPB out
 exit-address-family
```

puis `clear bgp {ispa_la} soft out` sur `r1` et `clear bgp {ispb_lb} soft out` sur `r3`.

- Une route qui ne correspond à aucune séquence d'une route-map est refusée : seul `{block}`
  sort. `show ip bgp neighbors {ispa_la} advertised-routes` sur `r1` ne liste plus que lui (avec
  son AS_PATH allongé).
- Sur `ispa`, `show ip bgp {netb}` n'a plus de chemin commençant par 65001 ; de même sur `ispb`
  pour `{neta}` et `203.0.113.0/24`.

Évaluation : `filtre_annonces_r1` et `filtre_annonces_r3` (1 point chacun : les routes annoncées
au fournisseur contiennent `{block}` et rien d'autre que lui et le préfixe du client),
`filtre_pas_de_fuite_ispa` et `filtre_pas_de_fuite_ispb` (1 chacun : le fournisseur reçoit le bloc
et n'a plus aucun chemin par l'AS 65001 vers le réseau de l'autre fournisseur ni vers
`203.0.113.0/24`), `filtre_bloc_toujours_annonce` (1). Les quatre premiers ne comptent que si
l'iBGP de la partie 3 est en place : sans lui il n'y a rien à filtrer.
""").format(block=block, ispa_la=ip['ispa_la'], ispb_lb=ip['ispb_lb'], neta=neta, netb=netb)),
        )
        q6 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le filtrage"),
            hash="40a930d8aeb88607",
            description=tr("""
- sans filtre, si le lien `lab` tombe, par où passe le trafic de `netb` vers `neta` ?
  @@{lab_down:>par l'AS 65001 (transit involontaire)|par inet (AS 65000) uniquement|nulle part, neta devient injoignable}@@
  (indice : sur `ispb`, comparez les AS_PATH des chemins restants vers `neta` et le critère de
  départage)
- que fait `ispa` d'une route reçue de `r1` dont l'AS_PATH contient déjà 65100 ?
  @@{loop:>il la rejette (détection de boucle)|il l'accepte avec une préférence plus faible|il la préfère}@@
- ce que protège la RFC 8212 (politique obligatoire en eBGP) :
  @@{rfc8212:>les fuites de routes involontaires|la confidentialité des sessions|le temps de convergence}@@
""")
            + instructor(tr("""
**Solution.**

- lien `lab` coupé, sans filtre : **par l'AS 65001 (transit involontaire)**. Il reste à `ispb`
  deux chemins de même longueur vers `neta`, `65000 65100` par `inet` et `65001 65100` par `r3`,
  départagés par le router-id du pair : celui de `r3` (sa loopback, une adresse privée) est plus
  petit que `250.250.250.250`. Dans l'autre sens, de `neta` vers `netb`, `ispa` choisit `inet` :
  le *prepend* de la partie 5 allonge tout ce que `r1` lui annonce.
- route dont l'AS_PATH contient déjà 65100 : **il la rejette (détection de boucle)** ;
- RFC 8212 : **les fuites de routes involontaires**.

Évaluation (enseignant seulement, 1 point chacun) : `filtre_q_transit`,
`filtre_q_boucle_rfc8212`.
""")),
            cheat_answers={"final": {"lab_down": "par l'AS 65001 (transit involontaire)",
                                     "loop": "il la rejette (détection de boucle)",
                                     "rfc8212": "les fuites de routes involontaires"}},
        )
        # The transit leak only exists once the borders learn the other ISP's routes in iBGP
        # (before that, r1 has nothing but the /22 to announce): the checks require it.
        r1_ibgp = best('r1', netb).get('path_from') == 'internal'
        r3_ibgp = best('r3', neta).get('path_from') == 'internal'
        allowed = {block, net4}
        adv_r1_ok = r1_ibgp and bool(adv_r1_ispa) and block in adv_r1_ispa and set(adv_r1_ispa) <= allowed
        adv_r3_ok = r3_ibgp and bool(adv_r3_ispb) and block in adv_r3_ispb and set(adv_r3_ispb) <= allowed
        self.add_grade_element(
            title=no_tr("filtre_annonces_r1"), max_grade=1, grade_part=part6, grade=int(adv_r1_ok),
            description=tr("r1 n'annonce à ispa que {block} (et le préfixe du client)").format(block=block),
        )
        self.add_grade_element(
            title=no_tr("filtre_annonces_r3"), max_grade=1, grade_part=part6, grade=int(adv_r3_ok),
            description=tr("r3 n'annonce à ispb que {block} (et le préfixe du client)").format(block=block),
        )
        ispa_has_block = bool(bgp_paths(routes['ispa'], block, peer=ip['r1_la']))
        ispb_has_block = bool(bgp_paths(routes['ispb'], block, peer=ip['r3_lb']))
        leak_ispa = bgp_paths(routes['ispa'], netb, first_as=AS1) + bgp_paths(routes['ispa'], web, first_as=AS1)
        leak_ispb = bgp_paths(routes['ispb'], neta, first_as=AS1) + bgp_paths(routes['ispb'], web, first_as=AS1)
        self.add_grade_element(
            title=no_tr("filtre_pas_de_fuite_ispa"), max_grade=1, grade_part=part6,
            grade=int(r1_ibgp and ispa_has_block and not leak_ispa),
            description=tr("ispa ne voit plus netb ni 203.0.113.0/24 par l'AS 65001"),
        )
        self.add_grade_element(
            title=no_tr("filtre_pas_de_fuite_ispb"), max_grade=1, grade_part=part6,
            grade=int(r3_ibgp and ispb_has_block and not leak_ispb),
            description=tr("ispb ne voit plus neta ni 203.0.113.0/24 par l'AS 65001"),
        )
        self.add_grade_element(
            title=no_tr("filtre_bloc_toujours_annonce"), max_grade=1, grade_part=part6,
            grade=int(ispa_has_block and ispb_has_block),
            description=tr("les deux fournisseurs reçoivent toujours {block}").format(block=block),
        )
        self.add_grade_element(
            title=no_tr("filtre_q_transit"), max_grade=1, grade_part=part6,
            grade=int(_norm(q6.get("lab_down")).startswith("par l'as 65001")), scope=CHOICE_SCOPE,
            description=tr("conséquence d'une absence de filtre"),
        )
        self.add_grade_element(
            title=no_tr("filtre_q_boucle_rfc8212"), max_grade=1, grade_part=part6,
            grade=int(_norm(q6.get("loop")).startswith("il la rejette") and _norm(q6.get("rfc8212")).startswith("les fuites")),
            scope=CHOICE_SCOPE, description=tr("détection de boucle et RFC 8212"),
        )

        # =====================================================================
        # Partie 7 — Client AS 65300
        # =====================================================================
        part7 = self.add_grade_part(no_tr("partie7"), tr("Partie 7 — Un client : l'AS 65300"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Raccorder le client r4 (AS 65300)"),
            hash="74b2fe03daa8bde9",
            description=tr("""
L'AS 65001 fournit l'accès à l'Internet au client `r4` (AS 65300, réseau `{net4}`, hôte `m4`),
raccordé à `r3` par le lien `l34` (`{l34}`).

1. Sur `r4` : `router bgp 65300`, router-id `4.4.4.4`, pair `{r3_l34}` (AS 65001), annonce de
   `{net4}` (n'oubliez pas la RFC 8212).
2. Sur `r3` : pair `{r4_l34}` (AS 65300). Un client n'a pas besoin de la table complète :
   annoncez-lui **uniquement une route par défaut** (`neighbor {r4_l34} default-originate` et
   une `route-map … out` qui ne laisse passer que `0.0.0.0/0`). Vérifiez sur `r4` (`show ip
   bgp`, `ip route`) et depuis `m4` (`ping internet`, `ping m1`).
3. Le préfixe du client doit être annoncé aux **deux** fournisseurs : complétez les filtres de
   la partie 6 sur `r1` et `r3` (`show ip bgp {net4}` sur `ispa`, `ispb` et `inet`).

*Bonus* : sur `r3`, marquez les routes reçues de `r4` avec la communauté **`65001:{tag}`**
(`route-map … in` avec `set community`) et vérifiez qu'elle est visible sur `ispa` ou `inet`
(`show ip bgp {net4}`).
""").format(net4=net4, l34=str(d.nets.l34), r3_l34=ip['r3_l34'], r4_l34=ip['r4_l34'], tag=d.cust_tag)
            + instructor(tr("""
**Solution.**

```
! r4
router bgp 65300
 bgp router-id 4.4.4.4
 no bgp ebgp-requires-policy
 neighbor {r3_l34} remote-as 65001
 neighbor {r3_l34} description FAI-AS65001
 address-family ipv4 unicast
  network {net4}
 exit-address-family
!
! r3
ip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0
ip prefix-list TO-ISPB seq 10 permit {net4}
route-map TO-R4 permit 10
 match ip address prefix-list DEFAULT-ONLY
route-map FROM-R4 permit 10
 set community {community}
router bgp 65001
 neighbor {r4_l34} remote-as 65300
 neighbor {r4_l34} description CLIENT-AS65300
 address-family ipv4 unicast
  neighbor {r4_l34} default-originate
  neighbor {r4_l34} route-map TO-R4 out
  neighbor {r4_l34} route-map FROM-R4 in
 exit-address-family
!
! r1
ip prefix-list TO-ISPA seq 10 permit {net4}
```

puis `clear bgp * soft` sur `r1` et `r3`. La route-map `FROM-R4` est le bonus.

- `{net4}` est un réseau connecté de `r4` : `network` l'annonce sans route `blackhole`.
- Sur `r4`, `show ip bgp` ne contient que `0.0.0.0/0` (prochain saut `{r3_l34}`) et son propre
  réseau ; `ip route` : `default … proto bgp`.
- `show ip bgp {net4}` sur `ispa`, `ispb` et `inet` : AS_PATH terminé par `65001 65300`, et la
  communauté `{community}` (`Community:`) avec le bonus.

Évaluation : `client_session` (2 points : session `Established` vue des deux côtés, `r4` dans
l'AS 65300 avec le router-id `4.4.4.4`), `client_defaut_seul` (2 : la table BGP de `r4` ne
contient, hors son réseau, que la route par défaut reçue de `{r3_l34}`, installée),
`client_prefixe_propage` (2 : `ispa`, `ispb` et `inet` ont un chemin vers `{net4}` terminé par
`65001 65300`), `client_pings` (1 : `m4` joint `internet` et `m1`, `web` joint `m4`),
`client_communaute_bonus` (1 : la communauté `{community}` vue sur `ispa` ou sur `inet`).
""").format(net4=net4, r3_l34=ip['r3_l34'], r4_l34=ip['r4_l34'], community=community)),
        )
        q7 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le client"),
            hash="b52ea24b27d4083b",
            description=tr("""
- `r1` apprend `{net4}` : @@{{learn:>par iBGP depuis r3|par eBGP depuis ispa|par OSPF}}@@ ;
  `NEXT_HOP` de cette route sur `r1` : @@{{nexthop:[0-9.]+}}@@
- effet de `aggregate-address PREFIXE summary-only` :
  @@{{summary_only:>seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés|l'agrégat et les préfixes plus spécifiques sont annoncés|seuls les préfixes plus spécifiques sont annoncés}}@@
""").format(net4=net4)
            + instructor(tr("""
**Solution.**

- `r1` apprend `{net4}` **par iBGP depuis r3** (à travers `r2`) ; `NEXT_HOP` : **`{lo3}`**, la
  loopback de `r3` (`next-hop-self`) ;
- `summary-only` : **seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés**.

Évaluation : `client_q_apprentissage_typed` (0,5 point : le `NEXT_HOP`) ; pour l'enseignant
seulement (choix dans une liste) : `client_q_apprentissage` (0,5 : par iBGP depuis `r3`),
`client_q_agregat` (1).
""").format(net4=net4, lo3=lo['r3'])),
            cheat_answers={"final": {"learn": "par iBGP depuis r3", "nexthop": lo['r3'],
                                     "summary_only": "seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés"}},
        )
        cust_session = (established('r3', ip['r4_l34'], AS_CUST) and established('r4', ip['r3_l34'], AS1)
                        and summ['r4'].get('router_id') == ROUTER_IDS['r4'] and summ['r4'].get('as') == AS_CUST)
        self.add_grade_element(
            title=no_tr("client_session"), max_grade=2, grade_part=part7, grade=2 * int(cust_session),
            description=tr("session r3–r4 Established, r4 dans l'AS 65300 avec le router-id 4.4.4.4"),
        )
        b_r4_def = best('r4', DEFAULT_ROUTE)
        default_only = (b_r4_def.get('nexthop') == ip['r3_l34'] and bool(b_r4_def.get('valid'))
                        and set(routes['r4']) - {net4} == {DEFAULT_ROUTE} and bgp_kroute('r4', DEFAULT_ROUTE))
        self.add_grade_element(
            title=no_tr("client_defaut_seul"), max_grade=2, grade_part=part7, grade=2 * int(default_only),
            description=tr("r4 ne reçoit de r3 qu'une route par défaut (installée)"),
        )
        propagated = all([bool(bgp_paths(routes[x], net4, ends_with=[AS1, AS_CUST])) for x in ('ispa', 'ispb', 'inet')])
        self.add_grade_element(
            title=no_tr("client_prefixe_propage"), max_grade=2, grade_part=part7, grade=2 * int(propagated),
            description=tr("ispa, ispb et inet connaissent {net4} par l'AS 65001 (AS_PATH … 65001 65300)").format(net4=net4),
        )
        pings_cust = all([ping('m4', WEB_HOST.ip), ping('m4', 'm1'), ping('web', 'm4')])
        self.add_grade_element(
            title=no_tr("client_pings"), max_grade=1, grade_part=part7, grade=int(pings_cust),
            description=tr("m4 joint internet et m1, web joint m4"),
        )
        community_ok = any(community in (p.get('communities') or [])
                           for p in pfx_ispa_net4.get('paths', []) + pfx_inet_net4.get('paths', []))
        self.add_grade_element(
            title=no_tr("client_communaute_bonus"), max_grade=1, grade_part=part7, grade=int(community_ok),
            description=tr("bonus : {net4} porte la communauté {community} chez ispa ou inet").format(net4=net4, community=community),
        )
        self.add_grade_element(
            title=no_tr("client_q_apprentissage_typed"), max_grade=0.5, grade_part=part7,
            grade=0.5 * int(_same_ip(q7.get("nexthop"), lo['r3'])),
            description=tr("NEXT_HOP du préfixe du client sur r1"),
        )
        self.add_grade_element(
            title=no_tr("client_q_apprentissage"), max_grade=0.5, grade_part=part7,
            grade=0.5 * int(_norm(q7.get("learn")).startswith("par ibgp")),
            scope=CHOICE_SCOPE, description=tr("protocole par lequel r1 apprend le préfixe du client"),
        )
        self.add_grade_element(
            title=no_tr("client_q_agregat"), max_grade=1, grade_part=part7,
            grade=int(_norm(q7.get("summary_only")).startswith("seul l'agrégat")), scope=CHOICE_SCOPE,
            description=tr("effet de summary-only"),
        )

        # =====================================================================
        # Partie 8 — Réflecteur de routes
        # =====================================================================
        part8 = self.add_grade_part(no_tr("partie8"), tr("Partie 8 — Réflecteur de routes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Remplacer le maillage iBGP par un réflecteur de routes"),
            hash="4133cb2b3770dd70",
            description=tr("""
Le maillage complet ne passe pas à l'échelle. Faites de `r2` un **réflecteur de routes** :

1. sur `r2`, déclarez `r1` et `r3` comme clients (`neighbor {lo1} route-reflector-client` et
   `neighbor {lo3} route-reflector-client`, address-family) ;
2. supprimez la session directe entre `r1` et `r3` (`no neighbor {lo3} remote-as 65001` sur `r1`
   et symétriquement sur `r3`).

Vérifiez que `r1` connaît toujours `netb` et `r3` toujours `neta` (`show ip bgp {neta}` sur `r3` :
observez les attributs `Originator` et `Cluster list`), que le `NEXT_HOP` n'a pas été modifié
par le réflecteur et que `m1` joint `ispb`, `m3` joint `ispa`.
""").format(lo1=lo['r1'], lo3=lo['r3'], neta=neta)
            + instructor(tr("""
**Solution.**

```
! r2
router bgp 65001
 address-family ipv4 unicast
  neighbor {lo1} route-reflector-client
  neighbor {lo3} route-reflector-client
 exit-address-family
! r1
router bgp 65001
 no neighbor {lo3} remote-as 65001
! r3
router bgp 65001
 no neighbor {lo1} remote-as 65001
```

`show ip bgp {neta}` sur `r3` : le chemin iBGP est reçu de `{lo2}` avec
`Originator: {lo1}, Cluster list: {lo2}` et son `NEXT_HOP` reste `{lo1}` : le réflecteur ne
modifie pas les attributs. Sans `route-reflector-client`, `r2` ne réannoncerait pas à `r3` les
routes apprises de `r1` et les deux routeurs de bordure perdraient les routes de l'autre.

Évaluation : `rr_clients_r2` (2 points : `r1` et `r3` clients du réflecteur dans la
configuration ou l'état de `r2`), `rr_plus_de_maillage` (1 : plus de session `r1`–`r3`, `r2`
toujours en session avec les deux), `rr_attributs` (2 : sur `r3`, un chemin vers `neta` porte
`ORIGINATOR_ID` = `{lo1}` et `{lo2}` dans sa `CLUSTER_LIST`), `rr_pings` (1 : les `ping` de la
partie 3).
""").format(lo1=lo['r1'], lo2=lo['r2'], lo3=lo['r3'], neta=neta)),
        )
        q8 = self.question_form(
            section=self.section(1),
            title=tr("Observations sur le réflecteur de routes"),
            hash="1a0fdd685ae8b3f3",
            description=tr("""
- nombre de sessions iBGP pour 8 routeurs en maillage complet : @@{mesh8:[0-9]+}@@ ;
  avec un seul réflecteur de routes : @@{rr8:[0-9]+}@@
- attributs ajoutés par le réflecteur pour éviter les boucles :
  @@{attrs:>ORIGINATOR_ID et CLUSTER_LIST|AS_PATH et NEXT_HOP|LOCAL_PREF et MED}@@
""")
            + instructor(tr("""
**Solution.** Maillage complet de 8 routeurs : 8 × 7 ÷ 2 = **28** sessions ; avec un réflecteur :
**7** (une par client). Attributs ajoutés : **ORIGINATOR_ID et CLUSTER_LIST**.

Évaluation (1 point chacun) : `rr_q_sessions` ; pour l'enseignant seulement (choix dans une
liste) : `rr_q_attributs`.
""")),
            cheat_answers={"final": {"mesh8": "28", "rr8": "7", "attrs": "ORIGINATOR_ID et CLUSTER_LIST"}},
        )
        rr_conf = (neighbor_conf('r2', lo['r1']).get('route_reflector_client') or nb_r2_lo1.get('route_reflector_client')) \
            and (neighbor_conf('r2', lo['r3']).get('route_reflector_client') or nb_r2_lo3.get('route_reflector_client'))
        self.add_grade_element(
            title=no_tr("rr_clients_r2"), max_grade=2, grade_part=part8, grade=2 * int(bool(rr_conf)),
            description=tr("r1 et r3 sont clients du réflecteur r2"),
        )
        no_mesh = r2_sessions and not established('r1', lo['r3']) and not established('r3', lo['r1'])
        self.add_grade_element(
            title=no_tr("rr_plus_de_maillage"), max_grade=1, grade_part=part8, grade=int(no_mesh),
            description=tr("plus de session directe r1–r3 (r2 reste en session avec les deux)"),
        )
        reflected = any(p.get('originator_id') == lo['r1'] and lo['r2'] in (p.get('cluster_list') or [])
                        for p in pfx_r3_neta.get('paths', []))
        self.add_grade_element(
            title=no_tr("rr_attributs"), max_grade=2, grade_part=part8, grade=2 * int(reflected),
            description=tr("sur r3, neta est reçu de r2 avec ORIGINATOR_ID = r1 et CLUSTER_LIST contenant r2"),
        )
        self.add_grade_element(
            title=no_tr("rr_pings"), max_grade=1, grade_part=part8, grade=int(pings_ibgp),
            description=tr("m1 joint ispb et m3 joint ispa à travers le réflecteur"),
        )
        self.add_grade_element(
            title=no_tr("rr_q_sessions"), max_grade=1, grade_part=part8,
            grade=int(_int(q8.get("mesh8")) == 28 and _int(q8.get("rr8")) == 7),
            description=tr("nombre de sessions avec et sans réflecteur"),
        )
        self.add_grade_element(
            title=no_tr("rr_q_attributs"), max_grade=1, grade_part=part8,
            grade=int(_norm(q8.get("attrs")).startswith("originator_id")), scope=CHOICE_SCOPE,
            description=tr("attributs ajoutés par un réflecteur"),
        )


_TRANSLATIONS = {'en': {
    "BGP : routage inter-domaine": "BGP: inter-domain routing",
    """
**Sommaire**
""": """
**Contents**
""",
    "Principe de BGP": "Principles of BGP",
    """
L'Internet est un ensemble de **systèmes autonomes** (AS, *Autonomous System*), chacun identifié
par un numéro (ASN ; les numéros 64512 à 65534 sont **privés**, comme les adresses de la
RFC 1918) et administré par une organisation. À l'intérieur d'un AS, un **IGP** (OSPF, IS-IS)
calcule les plus courts chemins ; **entre** les AS, **BGP** (*Border Gateway Protocol*, version 4,
RFC 4271) échange des **préfixes** accompagnés d'**attributs** et chaque AS choisit ses routes
selon sa **politique** (coûts, contrats, sécurité), pas seulement selon la distance.

BGP est un protocole à **vecteur de chemins** : chaque route porte la liste des AS traversés
(**AS_PATH**). Un routeur **rejette** toute route dont l'AS_PATH contient son propre numéro
d'AS : c'est la protection contre les boucles.

Dans la table de routage (`show ip route`, `ip route`), les routes BGP sont marquées `B` (`proto
bgp` pour le noyau) avec une **distance administrative** de **20** (eBGP) ou **200** (iBGP).

### @@sec:sessions@@ Sessions et messages

- Deux routeurs BGP (**pairs**, *peers* ou *neighbors*) établissent une **session** sur une
  connexion **TCP** (port **179**) configurée explicitement des deux côtés (`neighbor A.B.C.D
  remote-as N`) : il n'y a pas de découverte automatique des voisins.
- Une session est **eBGP** (*external*) entre deux AS différents, **iBGP** (*internal*) entre
  deux routeurs du même AS. Par défaut les paquets eBGP sont émis avec un **TTL de 1** : les pairs
  eBGP sont directement connectés (sinon `neighbor X ebgp-multihop`).
- Messages : `OPEN` (numéro d'AS, router-id, *hold time*, capacités), `UPDATE` (préfixes annoncés
  avec leurs attributs, préfixes retirés), `KEEPALIVE` et `NOTIFICATION` (erreur, fermeture de la
  session).
- Automate d'une session : `Idle` → `Connect` / `Active` (tentatives TCP) → `OpenSent` →
  `OpenConfirm` → **`Established`** (routes échangées). Un pair déclaré d'un seul côté reste en
  `Active` ou `Connect` : il tente périodiquement d'ouvrir la connexion.
- `neighbor X password MOT` authentifie la session (option TCP MD5, RFC 2385) ; le mot de passe
  doit être le même des deux côtés.

### @@sec:timers@@ Temporisateurs et convergence

Chaque pair envoie un `KEEPALIVE` toutes les **60 s** par défaut. Si aucun message n'est reçu
pendant le **hold time** (**180 s** par défaut), la session est fermée et toutes les routes
apprises du pair sont retirées. Le hold time est **négocié** à l'ouverture de la session (la plus
petite des deux valeurs) : `neighbor X timers KEEPALIVE HOLD` ne prend donc effet qu'après
`clear bgp X`. Le temps de convergence après une panne dépend de la façon dont elle est détectée :

- fermeture **administrative** (`neighbor X shutdown`) : le pair est prévenu par un
  `NOTIFICATION`, les routes sont retirées aussitôt des deux côtés ;
- **coupure franche** (l'interface passe *down*) : le routeur ferme aussitôt ses sessions eBGP
  sur ce lien ; le pair, si sa propre interface reste active, n'apprend la panne qu'à
  l'expiration du hold time ;
- **panne silencieuse** (le lien reste *up* mais ne transmet plus rien) : rien ne la signale,
  chaque côté attend l'expiration du hold time.

Les réseaux qui visent une détection plus rapide réduisent ces temporisateurs ou utilisent BFD.
""": """
The Internet is a set of **autonomous systems** (AS), each identified by a number (ASN; the
numbers 64512 to 65534 are **private**, like the addresses of RFC 1918) and administered by one
organisation. Inside an AS, an **IGP** (OSPF, IS-IS) computes the shortest paths; **between** the
ASes, **BGP** (*Border Gateway Protocol*, version 4, RFC 4271) exchanges **prefixes** together with
**attributes**, and each AS chooses its routes according to its **policy** (costs, contracts,
security), not only according to distance.

BGP is a **path-vector** protocol: each route carries the list of the ASes it went through
(**AS_PATH**). A router **rejects** any route whose AS_PATH contains its own AS number: this is
the protection against loops.

In the routing table (`show ip route`, `ip route`), BGP routes are marked `B` (`proto bgp` in
the kernel) with an **administrative distance** of **20** (eBGP) or **200** (iBGP).

### @@sec:sessions@@ Sessions and messages

- Two BGP routers (**peers**, also called *neighbors*) establish a **session** over a **TCP**
  connection (port **179**) configured explicitly on both sides (`neighbor A.B.C.D remote-as N`):
  there is no automatic discovery of the neighbours.
- A session is **eBGP** (*external*) between two different ASes, **iBGP** (*internal*) between
  two routers of the same AS. By default eBGP packets are sent with a **TTL of 1**: eBGP peers
  are directly connected (otherwise `neighbor X ebgp-multihop`).
- Messages: `OPEN` (AS number, router-id, *hold time*, capabilities), `UPDATE` (announced prefixes
  with their attributes, withdrawn prefixes), `KEEPALIVE` and `NOTIFICATION` (error, closing of
  the session).
- State machine of a session: `Idle` → `Connect` / `Active` (TCP attempts) → `OpenSent` →
  `OpenConfirm` → **`Established`** (routes exchanged). A peer declared on one side only stays in
  `Active` or `Connect`: it periodically tries to open the connection.
- `neighbor X password PASSWORD` authenticates the session (TCP MD5 option, RFC 2385); the
  password must be the same on both sides.

### @@sec:timers@@ Timers and convergence

Each peer sends a `KEEPALIVE` every **60 s** by default. If no message is received during the
**hold time** (**180 s** by default), the session is closed and all the routes learnt from the
peer are withdrawn. The hold time is **negotiated** when the session opens (the smaller of the
two values): `neighbor X timers KEEPALIVE HOLD` therefore takes effect only after `clear bgp X`.
The convergence time after a failure depends on how the failure is detected:

- **administrative** shutdown (`neighbor X shutdown`): the peer is warned by a `NOTIFICATION`,
  the routes are withdrawn at once on both sides;
- **clean link failure** (the interface goes *down*): the router closes its eBGP sessions on that
  link at once; the peer, if its own interface stays up, learns of the failure only when the hold
  time expires;
- **silent failure** (the link stays *up* but no longer carries anything): nothing reports it,
  each side waits for the hold time to expire.

Networks that aim at a faster detection lower these timers or use BFD.
""",
    "Attributs et choix du meilleur chemin": "Attributes and best path selection",
    """
| attribut | type | rôle |
|----------|------|------|
| `AS_PATH` | obligatoire | liste des AS traversés (chaque AS ajoute son numéro en tête à la sortie) |
| `NEXT_HOP` | obligatoire | adresse du prochain saut ; modifiée sur une session eBGP, **conservée** sur une session iBGP |
| `ORIGIN` | obligatoire | origine de la route : `i` (IGP, commande `network`), `e` (EGP), `?` (incomplète, redistribution) |
| `LOCAL_PREF` | discrétionnaire | préférence **locale à l'AS** (100 par défaut), transmise en iBGP, **jamais** en eBGP |
| `MED` | optionnel non transitif | *Multi-Exit Discriminator* : suggère au voisin le point d'entrée à préférer ; comparé uniquement entre routes venant du **même AS voisin** |
| `COMMUNITY` | optionnel transitif | étiquettes `AS:valeur` pour marquer des routes et leur appliquer des politiques ; communautés connues : `no-export`, `no-advertise` |
| `ORIGINATOR_ID`, `CLUSTER_LIST` | optionnels | ajoutés par un réflecteur de routes (section @@ref:rr@@) |

### @@sec:decision@@ Le processus de décision

Pour chaque préfixe, si plusieurs chemins sont connus, BGP n'en installe et n'en annonce qu'**un
seul**, choisi dans l'ordre suivant :

1. `weight` le plus grand (FRR/Cisco, local au routeur ; 32768 pour les routes locales) ;
2. **`LOCAL_PREF`** le plus grand ;
3. route originée localement (`network`, agrégat) ;
4. **`AS_PATH`** le plus court ;
5. `ORIGIN` le plus bas (`i` < `e` < `?`) ;
6. **`MED`** le plus petit (entre routes du même AS voisin) ;
7. route **eBGP** préférée à route iBGP ;
8. métrique IGP la plus faible vers le `NEXT_HOP` ;
9. chemin le plus ancien (eBGP) ou **router-id** du pair le plus petit.

`show ip bgp` (ou `show bgp ipv4 unicast`) affiche tous les chemins connus : `*` = chemin valide
(prochain saut joignable), `>` = meilleur chemin, `i` en tête = appris en iBGP. `show ip bgp
PREFIXE` détaille un préfixe et indique entre parenthèses, après `best`, la raison du choix
(`AS Path`, `Local Pref`, `Router ID`, `Peer Type`…).
""": """
| attribute | type | role |
|----------|------|------|
| `AS_PATH` | mandatory | list of the ASes traversed (each AS adds its number at the front when the route leaves it) |
| `NEXT_HOP` | mandatory | address of the next hop; changed on an eBGP session, **kept** on an iBGP session |
| `ORIGIN` | mandatory | origin of the route: `i` (IGP, `network` command), `e` (EGP), `?` (incomplete, redistribution) |
| `LOCAL_PREF` | discretionary | preference **local to the AS** (100 by default), passed on in iBGP, **never** in eBGP |
| `MED` | optional non-transitive | *Multi-Exit Discriminator*: suggests to the neighbour the entry point to prefer; compared only between routes coming from the **same neighbouring AS** |
| `COMMUNITY` | optional transitive | `AS:value` tags used to mark routes and apply policies to them; well-known communities: `no-export`, `no-advertise` |
| `ORIGINATOR_ID`, `CLUSTER_LIST` | optional | added by a route reflector (section @@ref:rr@@) |

### @@sec:decision@@ The decision process

For each prefix, when several paths are known, BGP installs and announces **only one** of them,
chosen in the following order:

1. highest `weight` (FRR/Cisco, local to the router; 32768 for local routes);
2. highest **`LOCAL_PREF`**;
3. locally originated route (`network`, aggregate);
4. shortest **`AS_PATH`**;
5. lowest `ORIGIN` (`i` < `e` < `?`);
6. lowest **`MED`** (between routes from the same neighbouring AS);
7. **eBGP** route preferred over iBGP route;
8. lowest IGP metric to the `NEXT_HOP`;
9. oldest path (eBGP) or lowest peer **router-id**.

`show ip bgp` (or `show bgp ipv4 unicast`) displays every known path: `*` = valid path (next hop
reachable), `>` = best path, `i` at the start of the line = learnt over iBGP. `show ip bgp
PREFIX` details one prefix and gives in parentheses, after `best`, the reason for the choice
(`AS Path`, `Local Pref`, `Router ID`, `Peer Type`…).
""",
    "iBGP": "iBGP",
    """
Une route apprise d'un pair **iBGP** n'est **jamais réannoncée à un autre pair iBGP** (règle de
*split horizon* : les routeurs d'un AS ne portent pas leur AS dans l'AS_PATH, une boucle interne
serait indétectable). Conséquences :

- tous les routeurs BGP d'un AS doivent être **maillés** (*full mesh* : n(n−1)/2 sessions), ou
  utiliser un réflecteur de routes (section @@ref:rr@@) ;
- les sessions iBGP sont établies entre **loopbacks** (`neighbor X update-source lo`) : elles
  survivent à la panne d'un lien tant que l'IGP trouve un autre chemin ;
- le `NEXT_HOP` reçu en eBGP (adresse du routeur du fournisseur) est transmis tel quel en iBGP :
  s'il n'est pas dans l'IGP, la route est **invalide** sur les autres routeurs. Solution :
  `neighbor X next-hop-self` sur le routeur de bordure ;
- un routeur de l'AS qui relaie le trafic sans parler BGP ne connaît pas les destinations
  externes et forme un **trou noir** : dans un AS de transit, tous les routeurs du chemin doivent
  connaître les routes BGP.

### @@sec:rr@@ Réflecteur de routes

Le maillage complet ne passe pas à l'échelle. Un **réflecteur de routes** (*route reflector*, RR,
RFC 4456) est un routeur autorisé à réannoncer en iBGP les routes de ses **clients**
(`neighbor X route-reflector-client`, sur le réflecteur seulement) : chaque client n'a plus
besoin que d'une session, vers le réflecteur. Pour remplacer la protection perdue, le réflecteur
ajoute à la route `ORIGINATOR_ID` (le router-id du routeur qui l'a introduite dans l'AS) et
`CLUSTER_LIST` (les réflecteurs traversés) ; un routeur rejette une route qui porte son propre
identifiant dans l'un des deux. Le réflecteur ne modifie ni le `NEXT_HOP` ni les autres attributs.
""": """
A route learnt from an **iBGP** peer is **never re-announced to another iBGP peer** (*split
horizon* rule: the routers of an AS do not put their own AS in the AS_PATH, so an internal loop
could not be detected). Consequences:

- all the BGP routers of an AS must be **meshed** (*full mesh*: n(n−1)/2 sessions), or use a
  route reflector (section @@ref:rr@@);
- iBGP sessions are established between **loopbacks** (`neighbor X update-source lo`): they
  survive the failure of a link as long as the IGP finds another path;
- the `NEXT_HOP` received over eBGP (the address of the provider's router) is passed on unchanged
  in iBGP: if it is not in the IGP, the route is **invalid** on the other routers. Solution:
  `neighbor X next-hop-self` on the border router;
- a router of the AS that forwards the traffic without speaking BGP does not know the external
  destinations and becomes a **black hole**: in a transit AS, every router on the path must
  know the BGP routes.

### @@sec:rr@@ Route reflector

The full mesh does not scale. A **route reflector** (RR, RFC 4456) is a router allowed to
re-announce in iBGP the routes of its **clients** (`neighbor X route-reflector-client`, on the
reflector only): each client then needs a single session, to the reflector. To make up for the
lost protection, the reflector adds to the route `ORIGINATOR_ID` (the router-id of the router that
introduced it into the AS) and `CLUSTER_LIST` (the reflectors traversed); a router rejects a route
that carries its own identifier in either of them. The reflector changes neither the `NEXT_HOP`
nor the other attributes.
""",
    "Politiques de routage": "Routing policies",
    """
### @@sec:traffic@@ Trafic sortant, trafic entrant

- Sortie de l'AS (trafic **sortant**) : on décide soi-même, avec `LOCAL_PREF` (préférer un
  fournisseur pour tout l'AS) ou `weight` (pour un seul routeur).
- Entrée dans l'AS (trafic **entrant**) : on ne décide pas pour les autres, on les **influence** :
  **`AS_PATH prepend`** (allonger artificiellement le chemin annoncé à un fournisseur), `MED`
  (entre plusieurs liens vers le même voisin), communautés interprétées par le fournisseur.

### @@sec:filtering@@ Filtres et route-maps

- `ip prefix-list NOM seq N permit|deny PREFIXE` : une liste de préfixes ;
  `bgp as-path access-list` : expressions régulières sur l'AS_PATH ; `bgp community-list`.
- Une **`route-map`** est une suite de séquences numérotées `permit` / `deny`, chacune avec des
  clauses `match` (les routes concernées) et `set` (les attributs modifiés). Une route est
  traitée par la première séquence qui lui correspond ; une séquence sans `match` correspond à
  tout ; une route qui ne correspond à aucune séquence est **refusée**.
- `neighbor X route-map NOM in|out` (address-family) applique la route-map aux routes reçues du
  pair ou annoncées au pair. Après une modification de politique, `clear bgp X soft in|out`
  la réapplique sans couper la session.
- Un AS **non-transit** (client de deux fournisseurs) ne doit annoncer que **ses propres
  préfixes** (et ceux de ses clients), jamais ceux appris d'un fournisseur à l'autre : sinon il
  se propose comme chemin entre ses fournisseurs.
- `neighbor X maximum-prefix N` protège contre une fuite massive de routes.

### @@sec:rfc8212@@ RFC 8212 : pas de session eBGP sans politique

FRR refuse d'accepter et d'annoncer des routes sur une session **eBGP** tant qu'aucune politique
(`route-map` ou `prefix-list`, en entrée et en sortie) n'est définie : la session s'établit mais
le pair apparaît avec la mention `(Policy)` dans `show ip bgp summary`. Cette règle évite les
fuites de routes involontaires d'un routeur mal configuré. On définit des politiques explicites,
ou on désactive la protection : `no bgp ebgp-requires-policy` (mode `router bgp`).

### @@sec:announce@@ Annoncer un préfixe

- `network PREFIXE` (address-family) n'annonce un préfixe que si une route **exactement
  identique** existe dans la table de routage (`bgp network import-check`). Pour annoncer un bloc
  qui regroupe plusieurs réseaux, on ajoute une route statique vers `blackhole`
  (`ip route PREFIXE blackhole`, l'équivalent de `Null0`) : les routes plus précises de l'IGP
  restent prioritaires.
- `aggregate-address PREFIXE` construit un agrégat à partir des routes plus spécifiques présentes
  dans BGP ; avec `summary-only`, seul l'agrégat est annoncé, les préfixes plus spécifiques sont
  supprimés des annonces.
- `neighbor X default-originate` annonce une route par défaut à un pair (typiquement un client,
  qui n'a pas besoin de la table complète).
- `set community AS:VALEUR` dans une route-map marque des routes ; les communautés sont
  transmises aux pairs et visibles dans `show ip bgp PREFIXE`.
""": """
### @@sec:traffic@@ Outbound traffic, inbound traffic

- Leaving the AS (**outbound** traffic): you decide yourself, with `LOCAL_PREF` (prefer one
  provider for the whole AS) or `weight` (for a single router).
- Entering the AS (**inbound** traffic): you do not decide for the others, you **influence**
  them: **`AS_PATH prepend`** (artificially lengthen the path announced to a provider), `MED`
  (between several links to the same neighbour), communities interpreted by the provider.

### @@sec:filtering@@ Filters and route-maps

- `ip prefix-list NAME seq N permit|deny PREFIX`: a list of prefixes;
  `bgp as-path access-list`: regular expressions on the AS_PATH; `bgp community-list`.
- A **`route-map`** is a series of numbered `permit` / `deny` sequences, each with `match`
  clauses (the routes concerned) and `set` clauses (the attributes changed). A route is handled
  by the first sequence that matches it; a sequence without `match` matches everything; a route
  that matches no sequence is **denied**.
- `neighbor X route-map NAME in|out` (address-family) applies the route-map to the routes received
  from the peer or announced to the peer. After a policy change, `clear bgp X soft in|out`
  applies it again without resetting the session.
- A **non-transit** AS (a customer of two providers) must announce only **its own prefixes** (and
  those of its customers), never those learnt from one provider to the other: otherwise it offers
  itself as a path between its providers.
- `neighbor X maximum-prefix N` protects against a massive route leak.

### @@sec:rfc8212@@ RFC 8212: no eBGP session without a policy

FRR refuses to accept and announce routes on an **eBGP** session as long as no policy
(`route-map` or `prefix-list`, inbound and outbound) is defined: the session comes up but the
peer is shown with `(Policy)` in `show ip bgp summary`. This rule prevents unintended route leaks
from a misconfigured router. Either define explicit policies or disable the protection:
`no bgp ebgp-requires-policy` (`router bgp` mode).

### @@sec:announce@@ Announcing a prefix

- `network PREFIX` (address-family) announces a prefix only if an **exactly identical** route
  exists in the routing table (`bgp network import-check`). To announce a block that groups
  several networks, add a static route to `blackhole` (`ip route PREFIX blackhole`, the
  equivalent of `Null0`): the more specific routes of the IGP keep priority.
- `aggregate-address PREFIX` builds an aggregate from the more specific routes present in BGP;
  with `summary-only`, only the aggregate is announced, the more specific prefixes are suppressed
  from the announcements.
- `neighbor X default-originate` announces a default route to a peer (typically a customer,
  which does not need the full table).
- `set community AS:VALUE` in a route-map tags routes; the communities are passed on to the peers
  and visible in `show ip bgp PREFIX`.
""",
    "FRR et vtysh": "FRR and vtysh",
    """
**FRRouting** (FRR) est une suite de démons de routage pour Linux : `zebra` (l'interface avec le
noyau), `staticd` (les routes statiques), `bgpd`, `ospfd`… (les démons lancés sont choisis dans
`/etc/frr/daemons`). On les configure avec le shell **`vtysh`**, dont la syntaxe est proche de
celle des équipements Cisco :

```
vtysh                                    # ouvre le shell (prompt : routeur#)
show running-config                      # configuration courante
configure terminal
 router bgp 64512                        # processus BGP de l'AS 64512 (prompt : routeur(config-router)#)
  bgp router-id 198.51.100.253
  neighbor 192.0.2.1 remote-as 64513     # pair eBGP
  neighbor 192.0.2.1 description ISP-B
  neighbor 198.51.100.254 remote-as 64512     # pair iBGP
  neighbor 198.51.100.254 update-source lo
  address-family ipv4 unicast
   network 198.51.100.0/24               # préfixe annoncé
   neighbor 198.51.100.254 next-hop-self
   neighbor 192.0.2.1 route-map TO-B out
  exit-address-family
 exit
 ip prefix-list MINE seq 5 permit 198.51.100.0/24
 route-map TO-B permit 10
  match ip address prefix-list MINE
  set as-path prepend 64512 64512
 exit
 end
write                                    # sauvegarde dans /etc/frr/frr.conf
```

On supprime une ligne en la préfixant par `no`. Une commande peut être passée depuis le shell
Linux : `vtysh -c "show ip bgp summary"`. `clear bgp * soft` (ou `clear bgp A.B.C.D soft in|out`)
réapplique les politiques sans couper les sessions ; `clear bgp A.B.C.D` coupe et rétablit une
session (nécessaire pour changer ses temporisateurs).

Commandes d'observation utiles :

```
show ip bgp summary                        # sessions, état, préfixes reçus (State/PfxRcd)
show ip bgp                                # table BGP : tous les chemins, meilleur chemin (>)
show ip bgp PREFIXE                        # détail d'un préfixe : attributs, raison du choix
show ip bgp neighbors A.B.C.D              # détail d'une session : timers, politiques, compteurs
show ip bgp neighbors A.B.C.D advertised-routes   # ce que l'on annonce à ce pair (après politiques)
show ip bgp neighbors A.B.C.D received-routes     # ce que l'on reçoit (avec soft-reconfiguration inbound)
show ip route                              # table de routage (B = BGP, O = OSPF)
```

Documentation : [FRR — BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html) et
[filtrage](https://docs.frrouting.org/en/latest/filter.html).
""": """
**FRRouting** (FRR) is a suite of routing daemons for Linux: `zebra` (the interface with the
kernel), `staticd` (static routes), `bgpd`, `ospfd`… (the daemons started are chosen in
`/etc/frr/daemons`). They are configured with the **`vtysh`** shell, whose syntax is close to
that of Cisco equipment:

```
vtysh                                    # opens the shell (prompt: router#)
show running-config                      # current configuration
configure terminal
 router bgp 64512                        # BGP process of AS 64512 (prompt: router(config-router)#)
  bgp router-id 198.51.100.253
  neighbor 192.0.2.1 remote-as 64513     # eBGP peer
  neighbor 192.0.2.1 description ISP-B
  neighbor 198.51.100.254 remote-as 64512     # iBGP peer
  neighbor 198.51.100.254 update-source lo
  address-family ipv4 unicast
   network 198.51.100.0/24               # announced prefix
   neighbor 198.51.100.254 next-hop-self
   neighbor 192.0.2.1 route-map TO-B out
  exit-address-family
 exit
 ip prefix-list MINE seq 5 permit 198.51.100.0/24
 route-map TO-B permit 10
  match ip address prefix-list MINE
  set as-path prepend 64512 64512
 exit
 end
write                                    # saves to /etc/frr/frr.conf
```

A line is removed by prefixing it with `no`. A command can be run from the Linux shell:
`vtysh -c "show ip bgp summary"`. `clear bgp * soft` (or `clear bgp A.B.C.D soft in|out`)
applies the policies again without resetting the sessions; `clear bgp A.B.C.D` resets a session
and brings it up again (needed to change its timers).

Useful observation commands:

```
show ip bgp summary                        # sessions, state, prefixes received (State/PfxRcd)
show ip bgp                                # BGP table: all paths, best path (>)
show ip bgp PREFIX                         # details of a prefix: attributes, reason for the choice
show ip bgp neighbors A.B.C.D              # details of a session: timers, policies, counters
show ip bgp neighbors A.B.C.D advertised-routes   # what we announce to this peer (after policies)
show ip bgp neighbors A.B.C.D received-routes     # what we receive (with soft-reconfiguration inbound)
show ip route                              # routing table (B = BGP, O = OSPF)
```

Documentation: [FRR — BGP](https://docs.frrouting.org/en/latest/bgp.html),
[route-maps](https://docs.frrouting.org/en/latest/routemap.html) and
[filtering](https://docs.frrouting.org/en/latest/filter.html).
""",
    "Diagnostic": "Diagnostics",
    """
- `ip route` sur un routeur : les routes apprises par BGP portent `proto bgp` ;
- `traceroute -n IP` (ou `traceroute IP` pour les noms) depuis un hôte : chemin réellement suivi,
  d'un AS à l'autre ;
- `tcpdump -ni ethX tcp port 179` : observation des messages BGP (`-v` montre le TTL des paquets) ;
- `/var/log/frr/frr.log` : journal des démons FRR (établissement et fermeture des sessions).

| symptôme | causes à vérifier |
|----------|-------------------|
| session en `Active` / `Connect` | pair non déclaré de l'autre côté, mauvaise adresse ou mauvais numéro d'AS, pas de route vers le pair, `update-source` oublié entre loopbacks, mots de passe différents |
| session `Established`, mention `(Policy)` | RFC 8212 : aucune politique sur la session eBGP |
| préfixe déclaré par `network` mais pas annoncé | pas de route exactement identique dans la table de routage |
| route reçue en iBGP mais non valide (pas de `*`) | `NEXT_HOP` injoignable : `next-hop-self` sur le routeur de bordure |
| route BGP installée mais trafic perdu en chemin | un routeur du chemin ne connaît pas la destination (trou noir), ou pas de route retour |
| politique modifiée sans effet | `clear bgp X soft in` / `soft out` ; `clear bgp X` pour les temporisateurs |
""": """
- `ip route` on a router: the routes learnt by BGP carry `proto bgp`;
- `traceroute -n IP` (or `traceroute IP` for the names) from a host: the path actually followed,
  from one AS to the next;
- `tcpdump -ni ethX tcp port 179`: observing the BGP messages (`-v` shows the TTL of the packets);
- `/var/log/frr/frr.log`: log of the FRR daemons (sessions established and closed).

| symptom | causes to check |
|----------|-------------------|
| session in `Active` / `Connect` | peer not declared on the other side, wrong address or wrong AS number, no route to the peer, `update-source` forgotten between loopbacks, different passwords |
| session `Established`, shown with `(Policy)` | RFC 8212: no policy on the eBGP session |
| prefix declared with `network` but not announced | no exactly identical route in the routing table |
| route received over iBGP but not valid (no `*`) | unreachable `NEXT_HOP`: `next-hop-self` on the border router |
| BGP route installed but traffic lost on the way | a router on the path does not know the destination (black hole), or no return route |
| policy changed with no effect | `clear bgp X soft in` / `soft out`; `clear bgp X` for the timers |
""",
    "Organisation du TP": "Organisation of the lab",
    """
Lisez l'onglet **Informations** : il présente BGP (sessions, attributs, choix du meilleur chemin,
iBGP et réflecteur de routes, politiques de routage), la configuration de FRR avec `vtysh` et les
commandes de diagnostic.

**Le réseau.** Ce TP met en œuvre BGP avec la suite logicielle **FRRouting** (FRR). Vous
administrez l'**AS 65001** (routeurs `r1`, `r2`, `r3`, hôtes `m1` et `m3`), raccordé à deux
fournisseurs d'accès : **ISP A** (`ispa`, AS 65100) et **ISP B** (`ispb`, AS 65200), eux-mêmes
reliés entre eux et au « reste de l'Internet » (`inet`, AS 65000) où se trouve le serveur `web`
(`{web_host}`, nom `internet`). L'AS 65001 héberge en outre un **client** (`r4`, AS 65300, hôte
`m4`). Chaque AS a sa couleur dans le schéma.

- **Au départ**, `r1` est déjà en session eBGP avec `ispa` et annonce le bloc `{block}` de
  l'AS 65001. `r2`, `r3` et `r4` ont FRR démarré (`bgpd` actif) mais **aucune configuration
  BGP** ; l'IGP de l'AS 65001 (OSPF sur `r1`, `r2` et `r3`, loopbacks comprises) est en place.
- Les routeurs des fournisseurs et `inet` sont déjà entièrement configurés : vous pouvez vous y
  connecter pour observer ce qu'ils reçoivent (`vtysh`), mais leur configuration ne doit pas être
  modifiée (sauf indication contraire). Comme `r1`, ils ont désactivé la protection de la
  RFC 8212 (`no bgp ebgp-requires-policy`).
- Les fichiers `/etc/hosts` contiennent les noms de toutes les interfaces : `r3-eth2` désigne
  l'adresse de `eth2` de `r3`, `r3` (tout court) celle de `eth0`, `r3-lo` sa loopback, `ispa`
  l'adresse de `ispa` sur son réseau de clients `neta`.

**Plan d'adressage.**

| AS | routeur | interfaces | loopback |
|----|---------|------------|----------|
| 65001 | `r1` | eth0 `{net1}` (`net1`, hôte `m1`), eth1 `{l12}` (`l12`, vers `r2`), eth2 `{la}` (`la`, vers `ispa`) | `{lo1}` |
| 65001 | `r2` | eth0 `{l12}` (`l12`), eth1 `{l23}` (`l23`, vers `r3`) | `{lo2}` |
| 65001 | `r3` | eth0 `{net3}` (`net3`, hôte `m3`), eth1 `{l23}` (`l23`), eth2 `{lb}` (`lb`, vers `ispb`), eth3 `{l34}` (`l34`, vers `r4`) | `{lo3}` |
| 65300 | `r4` | eth0 `{net4}` (`net4`, hôte `m4`), eth1 `{l34}` (`l34`, vers `r3`) | – |
| 65100 | `ispa` | eth0 `{neta}` (`neta`, clients de l'ISP A), eth1 `{la}`, eth2 `{lab}` (`lab`, vers `ispb`), eth3 `{lai}` (`lai`, vers `inet`) | – |
| 65200 | `ispb` | eth0 `{netb}` (`netb`, clients de l'ISP B), eth1 `{lb}`, eth2 `{lab}`, eth3 `{lbi}` (`lbi`, vers `inet`) | – |
| 65000 | `inet` | eth0 `{web}` (`netweb`, serveur `web` = `{web_host}`), eth1 `{lai}`, eth2 `{lbi}` | – |

L'AS 65001 possède le bloc **`{block}`** (`net1`, `net3`, les liens internes et les loopbacks
`{loops}`).

**Consignes.**

- Les parties sont à faire **dans l'ordre** : chaque partie s'appuie sur la configuration
  réalisée dans les précédentes (les politiques des parties 4 à 7 se cumulent).
- Dans l'AS 65001, le router-id BGP de chaque routeur est l'adresse de sa **loopback**
  (`bgp router-id`, à définir en premier dans `router bgp 65001`).
- Sauvegardez régulièrement la configuration des routeurs (`write` dans vtysh).

**Plan du TP.**

1. **Découverte** de BGP sur `r1` et `ispa`, déjà configurés ;
2. **eBGP** : session entre `r3` et ISP B, annonce du bloc de l'AS ;
3. **iBGP** dans l'AS 65001 : sessions entre loopbacks, `next-hop-self`, trou noir ;
4. **Trafic sortant** : `local-preference`, temporisateurs et convergence ;
5. **Trafic entrant** : *AS-path prepend* ;
6. **Filtrage** : ne pas devenir un AS de transit ;
7. **Un client** : l'AS 65300 (`r4`), route par défaut, communauté ;
8. **Réflecteur de routes** à la place du maillage iBGP.

**Évaluation.** Chaque évaluation lit vos réponses et l'état des routeurs, les vôtres et ceux des
fournisseurs (sessions, tables BGP, routes annoncées, configuration), et lance des `ping` et un
`traceroute` entre les hôtes. Les valeurs demandées (local-preference, nombre de *prepend*,
temporisateurs, communauté, mot de passe) sont propres à votre instance du TP. Attendez que les
sessions soient `Established` et les routes propagées avant de lancer une évaluation.
""": """
Read the **Informations** tab: it presents BGP (sessions, attributes, best path selection, iBGP
and route reflectors, routing policies), the configuration of FRR with `vtysh` and the diagnostic
commands.

**The network.** This lab puts BGP into practice with the **FRRouting** (FRR) software suite. You
administer **AS 65001** (routers `r1`, `r2`, `r3`, hosts `m1` and `m3`), connected to two Internet
service providers: **ISP A** (`ispa`, AS 65100) and **ISP B** (`ispb`, AS 65200), themselves
connected to each other and to "the rest of the Internet" (`inet`, AS 65000), where the `web`
server lives (`{web_host}`, name `internet`). AS 65001 also hosts a **customer** (`r4`, AS 65300,
host `m4`). Each AS has its own colour in the *Schema* tab.

- **At the start**, `r1` already has an eBGP session with `ispa` and announces the block `{block}`
  of AS 65001. `r2`, `r3` and `r4` have FRR started (`bgpd` running) but **no BGP
  configuration**; the IGP of AS 65001 (OSPF on `r1`, `r2` and `r3`, loopbacks included) is in place.
- The routers of the providers and `inet` are already fully configured: you may connect to them
  to observe what they receive (`vtysh`), but their configuration must not be changed (unless
  stated otherwise). Like `r1`, they have disabled the protection of RFC 8212
  (`no bgp ebgp-requires-policy`).
- The `/etc/hosts` files contain the names of all the interfaces: `r3-eth2` stands for the
  address of `eth2` of `r3`, `r3` (on its own) for that of `eth0`, `r3-lo` for its loopback, `ispa`
  for the address of `ispa` on its customer network `neta`.

**Addressing plan.**

| AS | router | interfaces | loopback |
|----|---------|------------|----------|
| 65001 | `r1` | eth0 `{net1}` (`net1`, host `m1`), eth1 `{l12}` (`l12`, to `r2`), eth2 `{la}` (`la`, to `ispa`) | `{lo1}` |
| 65001 | `r2` | eth0 `{l12}` (`l12`), eth1 `{l23}` (`l23`, to `r3`) | `{lo2}` |
| 65001 | `r3` | eth0 `{net3}` (`net3`, host `m3`), eth1 `{l23}` (`l23`), eth2 `{lb}` (`lb`, to `ispb`), eth3 `{l34}` (`l34`, to `r4`) | `{lo3}` |
| 65300 | `r4` | eth0 `{net4}` (`net4`, host `m4`), eth1 `{l34}` (`l34`, to `r3`) | – |
| 65100 | `ispa` | eth0 `{neta}` (`neta`, customers of ISP A), eth1 `{la}`, eth2 `{lab}` (`lab`, to `ispb`), eth3 `{lai}` (`lai`, to `inet`) | – |
| 65200 | `ispb` | eth0 `{netb}` (`netb`, customers of ISP B), eth1 `{lb}`, eth2 `{lab}`, eth3 `{lbi}` (`lbi`, to `inet`) | – |
| 65000 | `inet` | eth0 `{web}` (`netweb`, server `web` = `{web_host}`), eth1 `{lai}`, eth2 `{lbi}` | – |

AS 65001 owns the block **`{block}`** (`net1`, `net3`, the internal links and the loopbacks
`{loops}`).

**Instructions.**

- The parts must be done **in order**: each part builds on the configuration made in the
  previous ones (the policies of parts 4 to 7 add up).
- In AS 65001, the BGP router-id of each router is the address of its **loopback**
  (`bgp router-id`, to be set first in `router bgp 65001`).
- Save the configuration of the routers regularly (`write` in vtysh).

**Outline of the lab.**

1. **Discovery** of BGP on `r1` and `ispa`, already configured;
2. **eBGP**: session between `r3` and ISP B, announcement of the block of the AS;
3. **iBGP** in AS 65001: sessions between loopbacks, `next-hop-self`, black hole;
4. **Outbound traffic**: `local-preference`, timers and convergence;
5. **Inbound traffic**: *AS-path prepend*;
6. **Filtering**: not becoming a transit AS;
7. **A customer**: AS 65300 (`r4`), default route, community;
8. **Route reflector** instead of the iBGP mesh.

**Evaluation.** Each evaluation reads your answers and the state of the routers, yours and those
of the providers (sessions, BGP tables, announced routes, configuration), and runs `ping`s and a
`traceroute` between the hosts. The values asked for (local-preference, number of *prepends*,
timers, community, password) are specific to your instance of the lab. Wait until the sessions
are `Established` and the routes propagated before running an evaluation.
""",
    """
**Pour l'enseignant.** Valeurs de cette instance : local-preference **{lp}** ; *prepend*
**{prepend} fois** 65001 vers ISP A ; keepalive / hold time de la session `r3`–`ispb` :
**{k} s / {hold} s** ; communauté du client **`{community}`** ; mot de passe MD5 `{key}`. Chaque
question se termine par sa solution pour ces valeurs.

L'état `final` (onglet *Appliquer une configuration*) applique toute la solution et remplit les
formulaires. Il suppose l'état initial (il ne retire pas les sessions ajoutées à la main) et
construit l'iBGP directement dans sa forme finale, celle de la partie 8 : `r2` réflecteur de
routes, pas de session directe `r1`–`r3`. Attendez environ 60 s après l'avoir appliqué avant de
lancer une évaluation.
""": """
**For the instructor.** Values of this instance: local-preference **{lp}**; *prepend* of 65001
**{prepend} times** towards ISP A; keepalive / hold time of the `r3`–`ispb` session:
**{k} s / {hold} s**; customer community **`{community}`**; MD5 password `{key}`. Each
question ends with its solution for these values.

The `final` state (*Apply Configuration* tab) applies the whole solution and fills in the
forms. It assumes the initial state (it does not remove the sessions added by hand) and
builds the iBGP directly in its final form, that of part 8: `r2` route reflector, no direct
`r1`–`r3` session. Wait about 60 s after applying it before running an evaluation.
""",
    "Partie 1 — Découverte de BGP sur r1 et ispa": "Part 1 — Discovering BGP on r1 and ispa",
    "Découverte de BGP sur r1 et ispa": "Discovering BGP on r1 and ispa",
    """
Sur `r1`, ouvrez `vtysh` et explorez la configuration en place (`show running-config`) ainsi que
les commandes `show ip bgp summary`, `show ip bgp`, `show ip bgp neighbors` et `show ip route`.
Observez les paquets BGP avec `tcpdump -ni eth2 -v tcp port 179` (patientez jusqu'à un
KEEPALIVE). Vérifiez depuis `m1` que vous joignez `internet` (`ping`, `traceroute`) et depuis
`m3` que ce n'est pas le cas.

- numéro d'AS du pair de `r1` : @@{as_ispa:[0-9]+}@@ ; port TCP utilisé par BGP : @@{port:[0-9]+}@@
- état de la session : @@{state:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@ ;
  nombre de préfixes reçus de `ispa` (colonne `State/PfxRcd`) : @@{nb_prefixes:[0-9]+}@@
- `AS_PATH` de la route vers `203.0.113.0/24` sur `r1` (dans l'ordre affiché) : @@{aspath_web:[0-9 ]+}@@
- distance administrative d'une route eBGP dans `show ip route` (entre crochets) : @@{ad:[0-9]+}@@
- hold time négocié : @@{hold:[0-9]+}@@ s et intervalle des KEEPALIVE : @@{keepalive:[0-9]+}@@ s
  (`show ip bgp neighbors`)
- pourquoi `m3` ne joint-il pas `internet` ?
  @@{why_m3:>r3 n'a aucune route vers ce réseau|ispa filtre le trafic de m3|r1 refuse de router le trafic de net3|le serveur web est en panne}@@
""": """
On `r1`, open `vtysh` and explore the configuration in place (`show running-config`) as well as
the commands `show ip bgp summary`, `show ip bgp`, `show ip bgp neighbors` and `show ip route`.
Observe the BGP packets with `tcpdump -ni eth2 -v tcp port 179` (wait for a KEEPALIVE). Check
from `m1` that you reach `internet` (`ping`, `traceroute`) and from `m3` that you do not.

- AS number of the peer of `r1`: @@{as_ispa:[0-9]+}@@; TCP port used by BGP: @@{port:[0-9]+}@@
- state of the session: @@{state:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@;
  number of prefixes received from `ispa` (column `State/PfxRcd`): @@{nb_prefixes:[0-9]+}@@
- `AS_PATH` of the route to `203.0.113.0/24` on `r1` (in the order displayed): @@{aspath_web:[0-9 ]+}@@
- administrative distance of an eBGP route in `show ip route` (in square brackets): @@{ad:[0-9]+}@@
- negotiated hold time: @@{hold:[0-9]+}@@ s and KEEPALIVE interval: @@{keepalive:[0-9]+}@@ s
  (`show ip bgp neighbors`)
- why does `m3` not reach `internet`?
  @@{why_m3:>r3 has no route to this network>>>r3 n'a aucune route vers ce réseau|ispa filters the traffic of m3>>>ispa filtre le trafic de m3|r1 refuses to route the traffic of net3>>>r1 refuse de router le trafic de net3|the web server is down>>>le serveur web est en panne}@@
""",
    """
**Solution.** Rien à configurer : `vtysh -c "show ip bgp summary"`, `vtysh -c "show ip bgp"` et
`vtysh -c "show ip bgp neighbors {ispa_la}"` sur `r1`.

- AS du pair : **65100** ; port TCP **179** ;
- session **Established** ; **3** préfixes reçus : `{neta}` (ISP A), `{netb}` (ISP B, à travers
  ISP A) et `{web}` ;
- `AS_PATH` vers `{web}` : **65100 65000** ;
- distance administrative d'une route eBGP : **20** (`[20/0]` dans `show ip route`) ;
- hold time **180** s, keepalive **60** s : les valeurs par défaut ;
- `m3` : **`r3` n'a aucune route vers ce réseau**. `r3` ne parle pas encore BGP et OSPF ne
  transporte que les réseaux internes de l'AS 65001.

Évaluation : `decouverte_as_port`, `decouverte_aspath`, `decouverte_ad_timers` (1 point chacun),
`decouverte_etat_prefixes_typed` (0,5 : nombre de préfixes) ; pour l'enseignant seulement (choix
dans une liste) : `decouverte_etat_prefixes` (0,5 : état de la session), `decouverte_m3` (1).
""": """
**Solution.** Nothing to configure: `vtysh -c "show ip bgp summary"`, `vtysh -c "show ip bgp"` and
`vtysh -c "show ip bgp neighbors {ispa_la}"` on `r1`.

- AS of the peer: **65100**; TCP port **179**;
- session **Established**; **3** prefixes received: `{neta}` (ISP A), `{netb}` (ISP B, through
  ISP A) and `{web}`;
- `AS_PATH` to `{web}`: **65100 65000**;
- administrative distance of an eBGP route: **20** (`[20/0]` in `show ip route`);
- hold time **180** s, keepalive **60** s: the default values;
- `m3`: **`r3` has no route to this network**. `r3` does not speak BGP yet and OSPF only carries
  the internal networks of AS 65001.

Evaluation: `decouverte_as_port`, `decouverte_aspath`, `decouverte_ad_timers` (1 point each),
`decouverte_etat_prefixes_typed` (0.5: number of prefixes); for the instructor only (choice
from a list): `decouverte_etat_prefixes` (0.5: state of the session), `decouverte_m3` (1).
""",
    "numéro d'AS de ispa et port TCP de BGP": "AS number of ispa and TCP port of BGP",
    "nombre de préfixes reçus": "number of prefixes received",
    "état de la session": "state of the session",
    "AS_PATH de la route vers 203.0.113.0/24": "AS_PATH of the route to 203.0.113.0/24",
    "distance administrative eBGP, hold time et keepalive par défaut": "eBGP administrative distance, default hold time and keepalive",
    "pourquoi m3 ne joint pas internet": "why m3 does not reach internet",
    "Partie 2 — eBGP : r3 et ISP B": "Part 2 — eBGP: r3 and ISP B",
    "Session eBGP entre r3 et ispb": "eBGP session between r3 and ispb",
    """
Sur `ispb`, observez `show ip bgp summary` : la session avec `r3` (`{r3_lb}`) est déjà déclarée
côté fournisseur mais n'est pas établie. Configurez BGP sur `r3` :

1. `router bgp 65001`, router-id `{lo3}` (sa loopback), pair `{ispb_lb}` dans l'AS 65200 ;
2. observez `show ip bgp summary` : la session s'établit, mais aucun préfixe n'est échangé
   (mention `(Policy)`, voir la RFC 8212 dans l'onglet **Informations**, section
   @@ref:rfc8212@@). Levez cette protection comme sur `r1` (ou définissez des politiques
   explicites) ;
3. annoncez le bloc **`{block}`** de l'AS 65001 (`network`, address-family `ipv4 unicast`).
   Vérifiez sur `ispb` (`show ip bgp {block}`) : tant que `r3` n'a pas de route vers ce
   préfixe exact, il ne l'annonce pas (`bgp network import-check`). Ajoutez la route statique
   `ip route {block} blackhole` comme sur `r1` et vérifiez que `ispb` reçoit désormais le bloc
   directement de `r3` (AS_PATH `65001`) et non plus seulement via `ispa`.

Vérifiez que `m3` joint `internet` et `ispb` (adresse `{ispb_netb}`, réseau des clients de
l'ISP B) et observez `show ip bgp` et `ip route` sur `r3`.

*Bonus* : protégez la session `r3`–`ispb` par un mot de passe MD5 (`neighbor X password
{key}`, à configurer sur `r3` **et** sur `ispb`, la seule modification autorisée sur un
fournisseur) et vérifiez qu'elle est de nouveau `Established`.
""": """
On `ispb`, look at `show ip bgp summary`: the session with `r3` (`{r3_lb}`) is already declared
on the provider's side but is not established. Configure BGP on `r3`:

1. `router bgp 65001`, router-id `{lo3}` (its loopback), peer `{ispb_lb}` in AS 65200;
2. look at `show ip bgp summary`: the session comes up, but no prefix is exchanged
   (shown as `(Policy)`, see RFC 8212 in the **Informations** tab, section
   @@ref:rfc8212@@). Lift this protection as on `r1` (or define explicit
   policies);
3. announce the block **`{block}`** of AS 65001 (`network`, address-family `ipv4 unicast`).
   Check on `ispb` (`show ip bgp {block}`): as long as `r3` has no route to this exact
   prefix, it does not announce it (`bgp network import-check`). Add the static route
   `ip route {block} blackhole` as on `r1` and check that `ispb` now receives the block
   directly from `r3` (AS_PATH `65001`) and no longer only through `ispa`.

Check that `m3` reaches `internet` and `ispb` (address `{ispb_netb}`, the network of the customers
of ISP B) and look at `show ip bgp` and `ip route` on `r3`.

*Bonus*: protect the `r3`–`ispb` session with an MD5 password (`neighbor X password
{key}`, to be configured on `r3` **and** on `ispb`, the only change allowed on a
provider) and check that it is `Established` again.
""",
    """
**Solution.** Dans `vtysh`, après `configure terminal` (puis `end` et `write`) :

```
! r3
ip route {block} blackhole
router bgp 65001
 bgp router-id {lo3}
 no bgp ebgp-requires-policy
 neighbor {ispb_lb} remote-as 65200
 neighbor {ispb_lb} description ISP-B
 address-family ipv4 unicast
  network {block}
 exit-address-family
```

1. Dès que le pair est déclaré, `r3` ouvre la connexion et la session passe `Established`.
2. Sans politique, les colonnes `State/PfxRcd` et `PfxSnt` de `show ip bgp summary` affichent
   `(Policy)` : rien n'est accepté ni annoncé. `no bgp ebgp-requires-policy` lève la protection,
   comme dans la configuration de `r1`.
3. Sans la route `blackhole`, `show ip bgp` sur `r3` liste le bloc sans `*>` et `ispb` ne le
   connaît que par ISP A (AS_PATH `65100 65001`). Avec elle, `show ip bgp {block}` sur `ispb`
   montre le chemin direct, AS_PATH `65001`, meilleur chemin. OSPF garde les routes plus précises
   vers `net1`, `net3` et les liens.

`r3` installe alors `neta`, `netb` et `203.0.113.0/24` (`ip route` : `proto bgp`) et `m3` joint
`internet` et `{ispb_netb}`.

Bonus : `neighbor {ispb_lb} password {key}` sur `r3` (mode `router bgp 65001`) et
`neighbor {r3_lb} password {key}` sur `ispb` (mode `router bgp 65200`). Tant qu'un seul côté
est configuré, la session retombe et ne se rétablit pas.

Évaluation : `ebgp_session_r3` (2 points : session `Established` avec l'AS 65200),
`ebgp_router_id_r3` (1), `ebgp_politique_rfc8212` (1 : pas de mention `(Policy)` et au moins trois
préfixes reçus), `ebgp_annonce_bloc` (2 : le meilleur chemin de `ispb` vers `{block}` vient de
`r3`, AS_PATH `65001`), `ebgp_routes_noyau_r3` (1 : routes `proto bgp` vers `neta`, `netb` et
`203.0.113.0/24`), `ebgp_pings_m3` (1), `ebgp_md5_bonus` (1 : le mot de passe dans la configuration
des deux routeurs et la session `Established`).
""": """
**Solution.** In `vtysh`, after `configure terminal` (then `end` and `write`):

```
! r3
ip route {block} blackhole
router bgp 65001
 bgp router-id {lo3}
 no bgp ebgp-requires-policy
 neighbor {ispb_lb} remote-as 65200
 neighbor {ispb_lb} description ISP-B
 address-family ipv4 unicast
  network {block}
 exit-address-family
```

1. As soon as the peer is declared, `r3` opens the connection and the session goes `Established`.
2. Without a policy, the columns `State/PfxRcd` and `PfxSnt` of `show ip bgp summary` show
   `(Policy)`: nothing is accepted or announced. `no bgp ebgp-requires-policy` lifts the protection,
   as in the configuration of `r1`.
3. Without the `blackhole` route, `show ip bgp` on `r3` lists the block without `*>` and `ispb`
   knows it only through ISP A (AS_PATH `65100 65001`). With it, `show ip bgp {block}` on `ispb`
   shows the direct path, AS_PATH `65001`, as the best path. OSPF keeps the more specific routes
   to `net1`, `net3` and the links.

`r3` then installs `neta`, `netb` and `203.0.113.0/24` (`ip route`: `proto bgp`) and `m3` reaches
`internet` and `{ispb_netb}`.

Bonus: `neighbor {ispb_lb} password {key}` on `r3` (`router bgp 65001` mode) and
`neighbor {r3_lb} password {key}` on `ispb` (`router bgp 65200` mode). As long as only one side
is configured, the session drops and does not come back up.

Evaluation: `ebgp_session_r3` (2 points: session `Established` with AS 65200),
`ebgp_router_id_r3` (1), `ebgp_politique_rfc8212` (1: no `(Policy)` and at least three
prefixes received), `ebgp_annonce_bloc` (2: the best path of `ispb` to `{block}` comes from
`r3`, AS_PATH `65001`), `ebgp_routes_noyau_r3` (1: `proto bgp` routes to `neta`, `netb` and
`203.0.113.0/24`), `ebgp_pings_m3` (1), `ebgp_md5_bonus` (1: the password in the configuration
of both routers and the session `Established`).
""",
    "Observations sur la session eBGP": "Observations on the eBGP session",
    """
- état de la session vu de `ispb` **avant** la configuration de `r3` : @@{state_before:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@
- `AS_PATH` de la route vers `203.0.113.0/24` sur `r3` : @@{aspath_web:[0-9 ]+}@@ ;
  `NEXT_HOP` des routes reçues de `ispb` : @@{nexthop:[0-9.]+}@@
- TTL des paquets BGP émis par `r3` vers `ispb` (`tcpdump -v`) : @@{ttl:[0-9]+}@@
""": """
- state of the session seen from `ispb` **before** `r3` is configured: @@{state_before:>Idle|Connect|Active|OpenSent|OpenConfirm|Established}@@
- `AS_PATH` of the route to `203.0.113.0/24` on `r3`: @@{aspath_web:[0-9 ]+}@@;
  `NEXT_HOP` of the routes received from `ispb`: @@{nexthop:[0-9.]+}@@
- TTL of the BGP packets sent by `r3` to `ispb` (`tcpdump -v`): @@{ttl:[0-9]+}@@
""",
    """
**Solution.**

- avant : **Active** (`ispb` tente périodiquement d'ouvrir la connexion TCP, que `r3` refuse ;
  `Connect` est accepté aussi) ;
- AS_PATH vers `203.0.113.0/24` sur `r3` : **65200 65000** ; NEXT_HOP : **`{ispb_lb}`**,
  l'adresse de `ispb` sur le lien `lb` ;
- TTL : **1** (`tcpdump -ni eth2 -v tcp port 179` sur `r3` : `ttl 1`) : deux pairs eBGP sont
  directement connectés.

Évaluation (1 point chacun) : `ebgp_q_aspath_nexthop`, `ebgp_q_ttl` ; pour l'enseignant
seulement (choix dans une liste) : `ebgp_q_etat_avant`.
""": """
**Solution.**

- before: **Active** (`ispb` periodically tries to open the TCP connection, which `r3` refuses;
  `Connect` is accepted too);
- AS_PATH to `203.0.113.0/24` on `r3`: **65200 65000**; NEXT_HOP: **`{ispb_lb}`**,
  the address of `ispb` on the `lb` link;
- TTL: **1** (`tcpdump -ni eth2 -v tcp port 179` on `r3`: `ttl 1`): two eBGP peers are
  directly connected.

Evaluation (1 point each): `ebgp_q_aspath_nexthop`, `ebgp_q_ttl`; for the instructor
only (choice from a list): `ebgp_q_etat_avant`.
""",
    "session r3–ispb Established (AS 65200)": "r3–ispb session Established (AS 65200)",
    "router-id de r3 = {lo3}": "router-id of r3 = {lo3}",
    "la session échange des préfixes (RFC 8212 : politique définie ou désactivée)": "the session exchanges prefixes (RFC 8212: policy defined or disabled)",
    "ispb reçoit {block} directement de r3 (AS_PATH 65001)": "ispb receives {block} directly from r3 (AS_PATH 65001)",
    "r3 a des routes BGP (proto bgp) vers neta, netb et 203.0.113.0/24": "r3 has BGP routes (proto bgp) to neta, netb and 203.0.113.0/24",
    "m3 joint internet et ispb": "m3 reaches internet and ispb",
    "bonus : session r3–ispb authentifiée par MD5 des deux côtés": "bonus: r3–ispb session authenticated by MD5 on both sides",
    "état de la session côté ispb avant la configuration de r3": "state of the session on the ispb side before r3 is configured",
    "AS_PATH et NEXT_HOP des routes reçues de ispb": "AS_PATH and NEXT_HOP of the routes received from ispb",
    "TTL des paquets eBGP": "TTL of the eBGP packets",
    "Partie 3 — iBGP dans l'AS 65001": "Part 3 — iBGP in AS 65001",
    "Sessions iBGP, next-hop-self et trou noir": "iBGP sessions, next-hop-self and black hole",
    """
`r1` ne connaît que ce que lui annonce `ispa`, `r3` que ce que lui annonce `ispb` : si le lien
d'un fournisseur tombe, la moitié de l'AS perd l'Internet alors que l'autre fournisseur est
disponible. Les routeurs de l'AS doivent partager leurs routes externes en **iBGP**.

1. Établissez une session iBGP entre `r1` et `r3` **entre leurs loopbacks** (`neighbor {lo3}
   remote-as 65001` + `neighbor {lo3} update-source lo` sur `r1`, et symétriquement sur `r3`).
   Observez sur `r1` la route vers `netb` (`{netb}`, `show ip bgp {netb}`) : quel est son
   `NEXT_HOP` ? Pourquoi n'est-elle pas valide (`*`) ?
2. Sur `r1` et `r3`, activez `next-hop-self` vers les pairs iBGP (address-family). Vérifiez que
   les routes apprises en iBGP sont désormais valides et installées (`ip route`, distance 200).
3. Coupez la session avec ISP A (`neighbor {ispa_la} shutdown` sur `r1`) et lancez `ping
   internet` depuis `m1` : `r1` envoie le trafic vers `r3` via `r2`… qui ne connaît pas
   `203.0.113.0/24` (**trou noir**, `traceroute`). Rétablissez la session (`no neighbor … shutdown`).
4. Ajoutez `r2` au maillage iBGP (router-id `{lo2}`, sessions avec `r1` et `r3` entre
   loopbacks) et refaites l'expérience du point 3 : le trafic passe maintenant par ISP B.

Vérifiez pour finir que `m3` joint `ispa` (`{ispa_neta}`) et `m1` joint `ispb` (`{ispb_netb}`).
""": """
`r1` knows only what `ispa` announces to it, `r3` only what `ispb` announces to it: if the link
to one provider fails, half of the AS loses the Internet although the other provider is
available. The routers of the AS must share their external routes over **iBGP**.

1. Establish an iBGP session between `r1` and `r3` **between their loopbacks** (`neighbor {lo3}
   remote-as 65001` + `neighbor {lo3} update-source lo` on `r1`, and symmetrically on `r3`).
   On `r1`, look at the route to `netb` (`{netb}`, `show ip bgp {netb}`): what is its
   `NEXT_HOP`? Why is it not valid (`*`)?
2. On `r1` and `r3`, enable `next-hop-self` towards the iBGP peers (address-family). Check that
   the routes learnt over iBGP are now valid and installed (`ip route`, distance 200).
3. Shut down the session with ISP A (`neighbor {ispa_la} shutdown` on `r1`) and run `ping
   internet` from `m1`: `r1` sends the traffic to `r3` through `r2`… which does not know
   `203.0.113.0/24` (**black hole**, `traceroute`). Bring the session back (`no neighbor … shutdown`).
4. Add `r2` to the iBGP mesh (router-id `{lo2}`, sessions with `r1` and `r3` between
   loopbacks) and repeat the experiment of step 3: the traffic now goes through ISP B.

Finally, check that `m3` reaches `ispa` (`{ispa_neta}`) and `m1` reaches `ispb` (`{ispb_netb}`).
""",
    """
**Solution.**

```
! étapes 1 et 2 — r1
router bgp 65001
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
 address-family ipv4 unicast
  neighbor {lo3} next-hop-self
 exit-address-family
! étapes 1 et 2 — r3
router bgp 65001
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 address-family ipv4 unicast
  neighbor {lo1} next-hop-self
 exit-address-family
!
! étape 4 — r2
router bgp 65001
 bgp router-id {lo2}
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
! étape 4 — r1 (et r3 de même)
router bgp 65001
 neighbor {lo2} remote-as 65001
 neighbor {lo2} update-source lo
 address-family ipv4 unicast
  neighbor {lo2} next-hop-self
 exit-address-family
```

1. Sur `r1`, le chemin iBGP vers `{netb}` a pour `NEXT_HOP` `{ispb_lb}`, l'adresse de `ispb` sur
   le lien `lb` : en iBGP le `NEXT_HOP` n'est pas modifié. Ce lien n'est pas dans OSPF, `r1` n'a
   aucune route vers cette adresse : le chemin est inaccessible, sans `*`, et `r1` garde son
   chemin par ISP A.
2. Avec `next-hop-self`, `r3` annonce ses routes externes avec sa loopback `{lo3}`, connue par
   OSPF : le chemin devient valide et, plus court (`65200` contre `65100 65200`), il est choisi
   et installé (`[200/0]` dans `show ip route`).
3. Session ISP A coupée : `r1` envoie le trafic vers `{lo3}`, donc à `r2`, qui n'a aucune route
   vers `203.0.113.0/24` et le jette (`traceroute` s'arrête à `r2`).
4. Avec BGP sur `r2`, toute la chaîne connaît les routes externes et `m1` joint `internet` par
   ISP B. Ne pas oublier `no neighbor {ispa_la} shutdown` sur `r1`.

L'état `final` ne crée pas la session directe `r1`–`r3` : il construit directement la forme de
la partie 8.

Évaluation : `ibgp_sessions_r2` (2 points : `r2` en session `Established` avec `{lo1}` et
`{lo3}`), `ibgp_next_hop_self` (2 : sur `r2`, `neta` a pour prochain saut `{lo1}` et `netb`
`{lo3}`, routes iBGP installées dans le noyau), `ibgp_routes_bordure` (1 : `r1` connaît `netb`
par `r3` et `r3` connaît `neta` par `r1`), `ibgp_pings` (2 : `m3` joint `{ispa_neta}` et `m1`
joint `{ispb_netb}`).
""": """
**Solution.**

```
! steps 1 and 2 — r1
router bgp 65001
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
 address-family ipv4 unicast
  neighbor {lo3} next-hop-self
 exit-address-family
! steps 1 and 2 — r3
router bgp 65001
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 address-family ipv4 unicast
  neighbor {lo1} next-hop-self
 exit-address-family
!
! step 4 — r2
router bgp 65001
 bgp router-id {lo2}
 neighbor {lo1} remote-as 65001
 neighbor {lo1} update-source lo
 neighbor {lo3} remote-as 65001
 neighbor {lo3} update-source lo
! step 4 — r1 (and r3 likewise)
router bgp 65001
 neighbor {lo2} remote-as 65001
 neighbor {lo2} update-source lo
 address-family ipv4 unicast
  neighbor {lo2} next-hop-self
 exit-address-family
```

1. On `r1`, the iBGP path to `{netb}` has `{ispb_lb}` as its `NEXT_HOP`, the address of `ispb` on
   the `lb` link: in iBGP the `NEXT_HOP` is not changed. This link is not in OSPF, so `r1` has
   no route to this address: the path is inaccessible, without `*`, and `r1` keeps its
   path through ISP A.
2. With `next-hop-self`, `r3` announces its external routes with its loopback `{lo3}`, known
   through OSPF: the path becomes valid and, being shorter (`65200` against `65100 65200`), it is
   chosen and installed (`[200/0]` in `show ip route`).
3. ISP A session shut down: `r1` sends the traffic to `{lo3}`, hence to `r2`, which has no route
   to `203.0.113.0/24` and drops it (`traceroute` stops at `r2`).
4. With BGP on `r2`, the whole chain knows the external routes and `m1` reaches `internet` through
   ISP B. Do not forget `no neighbor {ispa_la} shutdown` on `r1`.

The `final` state does not create the direct `r1`–`r3` session: it builds the form of part 8
directly.

Evaluation: `ibgp_sessions_r2` (2 points: `r2` in an `Established` session with `{lo1}` and
`{lo3}`), `ibgp_next_hop_self` (2: on `r2`, `neta` has `{lo1}` as next hop and `netb`
`{lo3}`, iBGP routes installed in the kernel), `ibgp_routes_bordure` (1: `r1` knows `netb`
through `r3` and `r3` knows `neta` through `r1`), `ibgp_pings` (2: `m3` reaches `{ispa_neta}` and
`m1` reaches `{ispb_netb}`).
""",
    "Observations sur iBGP": "Observations on iBGP",
    """
- distance administrative d'une route iBGP : @@{ad_ibgp:[0-9]+}@@ ; nombre de sessions iBGP
  nécessaires pour mailler complètement un AS de 10 routeurs : @@{sessions10:[0-9]+}@@
- avant `next-hop-self`, le `NEXT_HOP` de la route vers `netb` sur `r1` est :
  @@{nh_before:>l'adresse de ispb sur le lien lb|la loopback de r3|l'adresse de r3 sur l23|l'adresse de r2}@@
- pourquoi `r2` doit-il parler BGP ?
  @@{why_r2:>r2 relaie le trafic entre r1 et r3 et doit connaître les destinations externes|r2 doit élire un DR|OSPF ne fonctionne pas sans BGP|pour que r1 et r3 puissent établir leur session}@@
""": """
- administrative distance of an iBGP route: @@{ad_ibgp:[0-9]+}@@; number of iBGP sessions
  needed to fully mesh an AS of 10 routers: @@{sessions10:[0-9]+}@@
- before `next-hop-self`, the `NEXT_HOP` of the route to `netb` on `r1` is:
  @@{nh_before:>the address of ispb on the lb link>>>l'adresse de ispb sur le lien lb|the loopback of r3>>>la loopback de r3|the address of r3 on l23>>>l'adresse de r3 sur l23|the address of r2>>>l'adresse de r2}@@
- why must `r2` speak BGP?
  @@{why_r2:>r2 forwards the traffic between r1 and r3 and must know the external destinations>>>r2 relaie le trafic entre r1 et r3 et doit connaître les destinations externes|r2 must elect a DR>>>r2 doit élire un DR|OSPF does not work without BGP>>>OSPF ne fonctionne pas sans BGP|so that r1 and r3 can establish their session>>>pour que r1 et r3 puissent établir leur session}@@
""",
    """
**Solution.**

- distance administrative iBGP : **200** ; maillage de 10 routeurs : 10 × 9 ÷ 2 = **45** sessions ;
- `NEXT_HOP` avant `next-hop-self` : **l'adresse de ispb sur le lien lb** (`{ispb_lb}`),
  transmise telle quelle en iBGP ;
- **`r2` relaie le trafic entre `r1` et `r3` et doit connaître les destinations externes** :
  la session `r1`–`r3` s'établit très bien sans lui (OSPF suffit à joindre les loopbacks), mais
  les paquets, eux, traversent `r2`.

Évaluation (1 point chacun) : `ibgp_q_ad_sessions` ; pour l'enseignant seulement (choix dans
une liste) : `ibgp_q_nexthop`, `ibgp_q_r2`.
""": """
**Solution.**

- iBGP administrative distance: **200**; mesh of 10 routers: 10 × 9 ÷ 2 = **45** sessions;
- `NEXT_HOP` before `next-hop-self`: **the address of ispb on the lb link** (`{ispb_lb}`),
  passed on unchanged in iBGP;
- **`r2` forwards the traffic between `r1` and `r3` and must know the external destinations**:
  the `r1`–`r3` session comes up perfectly well without it (OSPF is enough to reach the
  loopbacks), but the packets themselves go through `r2`.

Evaluation (1 point each): `ibgp_q_ad_sessions`; for the instructor only (choice from
a list): `ibgp_q_nexthop`, `ibgp_q_r2`.
""",
    "r2 est en session iBGP (Established) avec les loopbacks de r1 et r3": "r2 has iBGP sessions (Established) with the loopbacks of r1 and r3",
    "sur r2, neta a pour prochain saut la loopback de r1 et netb celle de r3 (next-hop-self), routes installées": "on r2, neta has the loopback of r1 as next hop and netb that of r3 (next-hop-self), routes installed",
    "r1 connaît netb par r3 et r3 connaît neta par r1": "r1 knows netb through r3 and r3 knows neta through r1",
    "m3 joint ispa et m1 joint ispb": "m3 reaches ispa and m1 reaches ispb",
    "distance administrative iBGP et nombre de sessions d'un maillage": "iBGP administrative distance and number of sessions of a full mesh",
    "NEXT_HOP transmis tel quel en iBGP": "NEXT_HOP passed on unchanged in iBGP",
    "rôle de BGP sur le routeur de transit r2": "role of BGP on the transit router r2",
    "Partie 4 — Choix du meilleur chemin : local-preference": "Part 4 — Best path selection: local-preference",
    "Trafic sortant : préférer ISP B pour l'Internet": "Outbound traffic: preferring ISP B for the Internet",
    """
Le préfixe `203.0.113.0/24` est connu par deux chemins d'AS de même longueur (via ISP A et via
ISP B). Observez sur `r1`, `r2` et `r3` quel chemin est retenu et pourquoi (`show ip bgp
203.0.113.0/24`, dernière ligne de chaque chemin ; `traceroute internet` depuis `m1` et `m3`).

ISP B offre un meilleur débit vers l'Internet : faites en sorte que **tout** le trafic de l'AS
65001 vers `203.0.113.0/24` sorte par `r3` et ISP B, **sans changer** le chemin vers les autres
réseaux (`neta` reste joint directement par `r1`). Sur `r3`, appliquez en entrée de la session
avec `ispb` une `route-map` qui affecte la **local-preference {lp}** aux routes vers
`203.0.113.0/24` seulement (`ip prefix-list` + `route-map … permit 10 / match ip address
prefix-list … / set local-preference {lp}`, suivie d'une séquence `permit 20` vide pour laisser
passer les autres routes), puis `clear bgp {ispb_lb} soft in`. Vérifiez sur `r1` : la route
via `r3` est maintenant préférée à sa propre route eBGP.

Réglez ensuite les temporisateurs de la session `r3`–`ispb` : keepalive **{k} s**, hold time
**{hold} s** (`neighbor {ispb_lb} timers {k} {hold}`, puis `clear bgp {ispb_lb}` : les
temporisateurs sont négociés à l'ouverture de la session). Vérifiez avec `show ip bgp neighbors`.

Mesurez enfin le temps de convergence en lançant `ping internet` depuis `m3` et en provoquant
trois pannes différentes sur `r3` :

- coupure administrative : `neighbor {ispb_lb} shutdown` (puis `no neighbor {ispb_lb} shutdown`) ;
- coupure franche : `ip link set eth2 down` (puis `ip link set eth2 up`) ;
- panne silencieuse : le lien reste « up » mais plus rien ne sort de `r3` par `eth2` :
  `tc qdisc add dev eth2 root netem loss 100%` (puis `tc qdisc del dev eth2 root` pour
  rétablir). Observez `show ip bgp summary` sur `r3` et sur `ispb` pendant la panne : les
  KEEPALIVE de `r3` n'arrivent plus, `ispb` ferme la session à l'expiration de son hold time.
""": """
The prefix `203.0.113.0/24` is known through two AS paths of the same length (through ISP A and
through ISP B). On `r1`, `r2` and `r3`, observe which path is selected and why (`show ip bgp
203.0.113.0/24`, last line of each path; `traceroute internet` from `m1` and `m3`).

ISP B offers a better throughput to the Internet: make **all** the traffic of AS 65001 to
`203.0.113.0/24` leave through `r3` and ISP B, **without changing** the path to the other
networks (`neta` is still reached directly by `r1`). On `r3`, apply a `route-map` inbound on
the session with `ispb`, which sets the **local-preference {lp}** on the routes to
`203.0.113.0/24` only (`ip prefix-list` + `route-map … permit 10 / match ip address
prefix-list … / set local-preference {lp}`, followed by an empty `permit 20` sequence to let
the other routes through), then `clear bgp {ispb_lb} soft in`. Check on `r1`: the route
through `r3` is now preferred over its own eBGP route.

Then set the timers of the `r3`–`ispb` session: keepalive **{k} s**, hold time
**{hold} s** (`neighbor {ispb_lb} timers {k} {hold}`, then `clear bgp {ispb_lb}`: the
timers are negotiated when the session opens). Check with `show ip bgp neighbors`.

Finally, measure the convergence time by running `ping internet` from `m3` and causing
three different failures on `r3`:

- administrative shutdown: `neighbor {ispb_lb} shutdown` (then `no neighbor {ispb_lb} shutdown`);
- clean link failure: `ip link set eth2 down` (then `ip link set eth2 up`);
- silent failure: the link stays "up" but nothing leaves `r3` through `eth2` any more:
  `tc qdisc add dev eth2 root netem loss 100%` (then `tc qdisc del dev eth2 root` to
  restore it). Look at `show ip bgp summary` on `r3` and on `ispb` during the failure: the
  KEEPALIVEs of `r3` no longer arrive, `ispb` closes the session when its hold time expires.
""",
    """
**Solution.** Avant : les deux chemins vers `203.0.113.0/24` ont un AS_PATH de deux AS. `r1` et
`r3` gardent chacun leur chemin eBGP (préféré à l'iBGP) ; `r2`, qui n'a que deux chemins iBGP
équivalents, retient celui du pair au plus petit router-id, `r1` : `m1` sort par ISP A, `m3` par
ISP B.

```
! r3
ip prefix-list WEB seq 5 permit {web}
route-map LP-IN permit 10
 match ip address prefix-list WEB
 set local-preference {lp}
route-map LP-IN permit 20
router bgp 65001
 neighbor {ispb_lb} timers {k} {hold}
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map LP-IN in
 exit-address-family
```

puis `clear bgp {ispb_lb} soft in` (la politique) et `clear bgp {ispb_lb}` (les temporisateurs).

- `show ip bgp {web}` sur `r1` : le chemin iBGP par `{lo3}` porte `localpref {lp}` et devient le
  meilleur (`Local Pref`), devant le chemin eBGP de `r1` (100) ; `ip route` sur `r1` : `{web}`
  par `{r2_l12}`. `traceroute internet` depuis `m1` : `r1`, `r2`, `r3`, `ispb`, `inet`. Sans la
  séquence `permit 20`, les autres routes reçues de `ispb` seraient refusées.
- `neta` n'est pas dans la liste `WEB` : `r1` le joint toujours directement par `ispa`.
- `show ip bgp neighbors {ispb_lb}` sur `r3` : hold time {hold} s, keepalive {k} s. `ispb` garde
  180 s dans sa configuration : la plus petite des deux valeurs est retenue.
- Convergence, à ce stade du TP : `shutdown` et `ip link set eth2 down` ne font perdre aucun
  `ping` (`r3` ferme la session aussitôt et sort par `r1` ; les réponses reviennent par ISP A,
  que `inet` préfère tant que la partie 5 n'est pas faite). Avec `netem loss 100%`, la session
  reste `Established` environ {hold} s, jusqu'à ce que `ispb` la ferme : autant de `ping`
  perdus, puis le trafic repart par `r1`. Une fois la partie 5 faite, le trafic entrant arrive
  par ISP B et la coupure franche coûte elle aussi un hold time : `ispb`, dont l'interface reste
  active, continue d'envoyer vers `r3`.

Évaluation : `lp_valeur_r3` (1 point : sur `r3`, le chemin reçu de `ispb` a la local-preference
{lp}), `lp_effet_r1` (2 : le meilleur chemin de `r1` vers `{web}` est le chemin iBGP par `r3`),
`lp_route_noyau_r1` (1 : route du noyau de `r1` par `{r2_l12}`), `lp_effet_r2` (1 : prochain saut
`{lo3}` sur `r2`), `lp_neta_inchange` (1 : `r1` garde son chemin eBGP vers `neta`), `lp_timers`
(1 : keepalive {k} s et hold time {hold} s négociés).
""": """
**Solution.** Before: both paths to `203.0.113.0/24` have an AS_PATH of two ASes. `r1` and
`r3` each keep their eBGP path (preferred over iBGP); `r2`, which only has two equivalent iBGP
paths, selects the one of the peer with the lowest router-id, `r1`: `m1` leaves through ISP A,
`m3` through ISP B.

```
! r3
ip prefix-list WEB seq 5 permit {web}
route-map LP-IN permit 10
 match ip address prefix-list WEB
 set local-preference {lp}
route-map LP-IN permit 20
router bgp 65001
 neighbor {ispb_lb} timers {k} {hold}
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map LP-IN in
 exit-address-family
```

then `clear bgp {ispb_lb} soft in` (the policy) and `clear bgp {ispb_lb}` (the timers).

- `show ip bgp {web}` on `r1`: the iBGP path through `{lo3}` carries `localpref {lp}` and becomes
  the best one (`Local Pref`), ahead of the eBGP path of `r1` (100); `ip route` on `r1`: `{web}`
  via `{r2_l12}`. `traceroute internet` from `m1`: `r1`, `r2`, `r3`, `ispb`, `inet`. Without the
  `permit 20` sequence, the other routes received from `ispb` would be denied.
- `neta` is not in the `WEB` list: `r1` still reaches it directly through `ispa`.
- `show ip bgp neighbors {ispb_lb}` on `r3`: hold time {hold} s, keepalive {k} s. `ispb` keeps
  180 s in its configuration: the smaller of the two values is used.
- Convergence, at this stage of the lab: `shutdown` and `ip link set eth2 down` lose no
  `ping` (`r3` closes the session at once and leaves through `r1`; the replies come back through
  ISP A, which `inet` prefers as long as part 5 is not done). With `netem loss 100%`, the session
  stays `Established` for about {hold} s, until `ispb` closes it: as many `ping`s are
  lost, then the traffic leaves through `r1` again. Once part 5 is done, the inbound traffic
  arrives through ISP B and the clean link failure costs a hold time too: `ispb`, whose interface
  stays up, keeps sending to `r3`.

Evaluation: `lp_valeur_r3` (1 point: on `r3`, the path received from `ispb` has the local-preference
{lp}), `lp_effet_r1` (2: the best path of `r1` to `{web}` is the iBGP path through `r3`),
`lp_route_noyau_r1` (1: kernel route of `r1` via `{r2_l12}`), `lp_effet_r2` (1: next hop
`{lo3}` on `r2`), `lp_neta_inchange` (1: `r1` keeps its eBGP path to `neta`), `lp_timers`
(1: keepalive {k} s and hold time {hold} s negotiated).
""",
    "Observations sur le choix du meilleur chemin": "Observations on best path selection",
    """
- **avant** la modification, critère qui départage les deux chemins sur `r2` :
  @@{crit_r2:>local-preference|longueur de l'AS_PATH|métrique IGP vers le NEXT_HOP|router-id du pair le plus petit|MED}@@
  et sur `r1` : @@{crit_r1:>local-preference|route eBGP préférée à la route iBGP|longueur de l'AS_PATH|router-id du pair le plus petit}@@
- **après** la modification, routeurs traversés par le trafic de `m1` vers `internet` :
  @@{via:>r1, ispa, inet|r1, r2, r3, ispb, inet|r1, r2, r3, ispa, inet|r1, ispa, ispb, inet}@@
- attribut qui n'est jamais transmis sur une session eBGP : @@{not_sent:>LOCAL_PREF|AS_PATH|NEXT_HOP|MED|ORIGIN}@@
- temps avant que `m3` ne joigne de nouveau `internet` après la coupure administrative :
  @@{shutdown:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@,
  après la coupure franche : @@{linkdown:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@,
  après la panne silencieuse : @@{silent:>immédiatement (moins de 5 s)|environ le keepalive|environ le hold time|jamais}@@
""": """
- **before** the change, the criterion that breaks the tie between the two paths on `r2`:
  @@{crit_r2:>local-preference|AS_PATH length>>>longueur de l'AS_PATH|IGP metric to the NEXT_HOP>>>métrique IGP vers le NEXT_HOP|lowest peer router-id>>>router-id du pair le plus petit|MED}@@
  and on `r1`: @@{crit_r1:>local-preference|eBGP route preferred over iBGP route>>>route eBGP préférée à la route iBGP|AS_PATH length>>>longueur de l'AS_PATH|lowest peer router-id>>>router-id du pair le plus petit}@@
- **after** the change, routers crossed by the traffic from `m1` to `internet`:
  @@{via:>r1, ispa, inet|r1, r2, r3, ispb, inet|r1, r2, r3, ispa, inet|r1, ispa, ispb, inet}@@
- attribute that is never sent on an eBGP session: @@{not_sent:>LOCAL_PREF|AS_PATH|NEXT_HOP|MED|ORIGIN}@@
- time before `m3` reaches `internet` again after the administrative shutdown:
  @@{shutdown:>immediately (less than 5 s)>>>immédiatement (moins de 5 s)|about the keepalive interval>>>environ le keepalive|about the hold time>>>environ le hold time|never>>>jamais}@@,
  after the clean link failure: @@{linkdown:>immediately (less than 5 s)>>>immédiatement (moins de 5 s)|about the keepalive interval>>>environ le keepalive|about the hold time>>>environ le hold time|never>>>jamais}@@,
  after the silent failure: @@{silent:>immediately (less than 5 s)>>>immédiatement (moins de 5 s)|about the keepalive interval>>>environ le keepalive|about the hold time>>>environ le hold time|never>>>jamais}@@
""",
    """
**Solution.**

- avant, sur `r2` : **router-id du pair le plus petit** (deux chemins iBGP de même
  local-preference, même longueur d'AS_PATH, même origine, même métrique IGP : `{lo1}` <
  `{lo3}`) ; sur `r1` : **route eBGP préférée à la route iBGP** ;
- après : **r1, r2, r3, ispb, inet** ;
- jamais transmis en eBGP : **LOCAL_PREF** (il n'a de sens qu'à l'intérieur de l'AS) ;
- coupure administrative : **immédiatement** ; coupure franche : **immédiatement** ; panne
  silencieuse : **environ le hold time** ({hold} s).

Évaluation (enseignant seulement, 1 point chacun) : `lp_q_criteres`, `lp_q_chemin`,
`lp_q_attribut`, `lp_q_convergence`.
""": """
**Solution.**

- before, on `r2`: **lowest peer router-id** (two iBGP paths with the same
  local-preference, the same AS_PATH length, the same origin, the same IGP metric: `{lo1}` <
  `{lo3}`); on `r1`: **eBGP route preferred over iBGP route**;
- after: **r1, r2, r3, ispb, inet**;
- never sent over eBGP: **LOCAL_PREF** (it only makes sense inside the AS);
- administrative shutdown: **immediately**; clean link failure: **immediately**; silent
  failure: **about the hold time** ({hold} s).

Evaluation (instructor only, 1 point each): `lp_q_criteres`, `lp_q_chemin`,
`lp_q_attribut`, `lp_q_convergence`.
""",
    "sur r3, la route vers 203.0.113.0/24 reçue de ispb a la local-preference {lp}": "on r3, the route to 203.0.113.0/24 received from ispb has the local-preference {lp}",
    "r1 préfère le chemin iBGP via r3 pour 203.0.113.0/24 (local-preference)": "r1 prefers the iBGP path through r3 for 203.0.113.0/24 (local-preference)",
    "la route du noyau de r1 vers 203.0.113.0/24 passe par r2": "the kernel route of r1 to 203.0.113.0/24 goes through r2",
    "r2 route 203.0.113.0/24 vers la loopback de r3": "r2 routes 203.0.113.0/24 to the loopback of r3",
    "r1 joint toujours neta directement par ispa (local-preference limitée à 203.0.113.0/24)": "r1 still reaches neta directly through ispa (local-preference limited to 203.0.113.0/24)",
    "keepalive {k} s / hold time {hold} s négociés sur la session r3–ispb": "keepalive {k} s / hold time {hold} s negotiated on the r3–ispb session",
    "critères de choix avant la modification (r2 et r1)": "selection criteria before the change (r2 and r1)",
    "chemin de m1 vers internet après la modification": "path from m1 to internet after the change",
    "attribut jamais transmis en eBGP": "attribute never sent over eBGP",
    "temps de convergence observés": "convergence times observed",
    "Partie 5 — Trafic entrant : AS-path prepend et MED": "Part 5 — Inbound traffic: AS-path prepend and MED",
    "Influencer le trafic entrant": "Influencing inbound traffic",
    """
Le trafic **entrant** (de `internet` vers `m1`) est décidé par les autres AS. Observez sur
`inet` (`show ip bgp {block}`) les deux chemins vers le bloc de l'AS 65001 et lequel est
retenu (les fournisseurs et `inet` utilisent `bgp bestpath compare-routerid`, sans quoi le
chemin le plus ancien l'emporterait). Vérifiez avec `traceroute m1` depuis `web`.

Faites entrer le trafic par **ISP B** sans toucher aux fournisseurs : sur `r1`, appliquez en
sortie de la session avec `ispa` une `route-map` qui **allonge l'AS_PATH** de vos annonces en y
ajoutant **{prepend} fois** votre numéro d'AS (`set as-path prepend 65001 …`), puis `clear bgp
{ispa_la} soft out`. Observez le résultat sur `ispa` (`show ip bgp {block}`), sur `inet` et
avec `traceroute` depuis `web`.

Le **MED** ne peut pas servir ici : il n'est comparé qu'entre chemins reçus du *même* AS voisin
(il servirait si l'AS 65001 avait deux liens vers ISP B).
""": """
**Inbound** traffic (from `internet` to `m1`) is decided by the other ASes. On `inet`
(`show ip bgp {block}`), observe the two paths to the block of AS 65001 and which one is
selected (the providers and `inet` use `bgp bestpath compare-routerid`, otherwise the
oldest path would win). Check with `traceroute m1` from `web`.

Make the traffic come in through **ISP B** without touching the providers: on `r1`, apply a
`route-map` outbound on the session with `ispa`, which **lengthens the AS_PATH** of your
announcements by adding your AS number to it **{prepend} times** (`set as-path prepend 65001 …`),
then `clear bgp {ispa_la} soft out`. Observe the result on `ispa` (`show ip bgp {block}`), on
`inet` and with `traceroute` from `web`.

The **MED** cannot help here: it is only compared between paths received from the *same*
neighbouring AS (it would help if AS 65001 had two links to ISP B).
""",
    """
**Solution.** Avant : `show ip bgp {block}` sur `inet` montre deux chemins de même longueur,
`65100 65001` et `65200 65001` ; le meilleur est celui d'ISP A, départagé par le router-id du
pair (`100.100.100.100` < `200.200.200.200`). `traceroute m1` depuis `web` passe par `ispa`.

```
! r1
route-map TO-ISPA permit 10
 set as-path prepend {prepend_list}
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispa_la} route-map TO-ISPA out
 exit-address-family
```

puis `clear bgp {ispa_la} soft out`.

- Sur `ispa`, le chemin direct a maintenant l'AS_PATH `{aspath}` ({n} fois 65001) : `ispa`
  lui-même préfère passer par ISP B (`65200 65001`).
- Sur `inet`, le chemin par ISP A devient `65100 65200 65001` (`ispa` annonce son nouveau
  meilleur chemin) : `65200 65001`, plus court, l'emporte.
- `traceroute -n m1` depuis `web` : `inet`, `ispb`, `r3` (`{r3_lb}`), `r2`, `r1`, `m1`.

Évaluation : `prepend_annonce` (1 point : `ispa` reçoit `{block}` de `r1` avec {n} fois 65001),
`prepend_effet_inet` (2 : le meilleur chemin de `inet` est `65200 65001`), `prepend_traceroute`
(1 : le `traceroute` de `web` vers `m1` lancé par l'évaluation contient `{r3_lb}`).
""": """
**Solution.** Before: `show ip bgp {block}` on `inet` shows two paths of the same length,
`65100 65001` and `65200 65001`; the best one is that of ISP A, chosen by the router-id of the
peer (`100.100.100.100` < `200.200.200.200`). `traceroute m1` from `web` goes through `ispa`.

```
! r1
route-map TO-ISPA permit 10
 set as-path prepend {prepend_list}
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispa_la} route-map TO-ISPA out
 exit-address-family
```

then `clear bgp {ispa_la} soft out`.

- On `ispa`, the direct path now has the AS_PATH `{aspath}` (65001 {n} times): `ispa`
  itself prefers to go through ISP B (`65200 65001`).
- On `inet`, the path through ISP A becomes `65100 65200 65001` (`ispa` announces its new
  best path): `65200 65001`, shorter, wins.
- `traceroute -n m1` from `web`: `inet`, `ispb`, `r3` (`{r3_lb}`), `r2`, `r1`, `m1`.

Evaluation: `prepend_annonce` (1 point: `ispa` receives `{block}` from `r1` with 65001 {n} times),
`prepend_effet_inet` (2: the best path of `inet` is `65200 65001`), `prepend_traceroute`
(1: the `traceroute` from `web` to `m1` run by the evaluation contains `{r3_lb}`).
""",
    "Observations sur le trafic entrant": "Observations on inbound traffic",
    """
- **avant** la modification, `inet` atteint l'AS 65001 par : @@{{before_via:>ISP A (65100)|ISP B (65200)}}@@,
  critère de choix : @@{{before_crit:>longueur de l'AS_PATH|MED|local-preference|router-id du pair le plus petit}}@@
- **après** la modification, quel chemin `ispa` préfère-t-il vers `{block}` ?
  @@{{ispa_now:>directement par r1|par ISP B (65200)}}@@
- le MED n'est comparé qu'entre chemins issus du même AS voisin : @@{{med:>vrai|faux}}@@
- leviers sur le trafic **entrant** : @@{{inbound:>AS-path prepend, MED|local-preference, weight}}@@ ;
  sur le trafic **sortant** : @@{{outbound:>AS-path prepend, MED|local-preference, weight}}@@
""": """
- **before** the change, `inet` reaches AS 65001 through: @@{{before_via:>ISP A (65100)|ISP B (65200)}}@@,
  selection criterion: @@{{before_crit:>AS_PATH length>>>longueur de l'AS_PATH|MED|local-preference|lowest peer router-id>>>router-id du pair le plus petit}}@@
- **after** the change, which path does `ispa` prefer to `{block}`?
  @@{{ispa_now:>directly through r1>>>directement par r1|through ISP B (65200)>>>par ISP B (65200)}}@@
- the MED is only compared between paths coming from the same neighbouring AS: @@{{med:>true>>>vrai|false>>>faux}}@@
- levers on **inbound** traffic: @@{{inbound:>AS-path prepend, MED|local-preference, weight}}@@;
  on **outbound** traffic: @@{{outbound:>AS-path prepend, MED|local-preference, weight}}@@
""",
    """
**Solution.**

- avant : **ISP A (65100)**, critère **router-id du pair le plus petit** (`inet` utilise
  `bgp bestpath compare-routerid`) ;
- après, `ispa` préfère passer **par ISP B (65200)** ;
- MED comparé seulement entre chemins du même AS voisin : **vrai** ;
- trafic entrant : **AS-path prepend, MED** ; trafic sortant : **local-preference, weight**.

Évaluation (enseignant seulement, 1 point chacun) : `prepend_q_avant`, `prepend_q_ispa`,
`prepend_q_med_leviers`.
""": """
**Solution.**

- before: **ISP A (65100)**, criterion **lowest peer router-id** (`inet` uses
  `bgp bestpath compare-routerid`);
- after, `ispa` prefers to go **through ISP B (65200)**;
- MED compared only between paths from the same neighbouring AS: **true**;
- inbound traffic: **AS-path prepend, MED**; outbound traffic: **local-preference, weight**.

Evaluation (instructor only, 1 point each): `prepend_q_avant`, `prepend_q_ispa`,
`prepend_q_med_leviers`.
""",
    "ispa reçoit {block} de r1 avec l'AS_PATH allongé ({n} fois 65001)": "ispa receives {block} from r1 with the lengthened AS_PATH (65001 {n} times)",
    "inet préfère le chemin par ISP B vers {block}": "inet prefers the path through ISP B to {block}",
    "le traceroute de web vers m1 traverse r3 (lien lb)": "the traceroute from web to m1 goes through r3 (lb link)",
    "chemin et critère de choix de inet avant la modification": "path and selection criterion of inet before the change",
    "chemin préféré par ispa après la modification": "path preferred by ispa after the change",
    "MED et leviers sur le trafic entrant / sortant": "MED and levers on inbound / outbound traffic",
    "Partie 6 — Filtrage : ne pas devenir un AS de transit": "Part 6 — Filtering: not becoming a transit AS",
    "Filtrer les annonces vers les fournisseurs": "Filtering the announcements to the providers",
    """
Par défaut, un routeur annonce à ses pairs eBGP **tous** ses meilleurs chemins : `r1` annonce à
`ispa` les routes apprises d'ISP B (`show ip bgp neighbors {ispa_la} advertised-routes` sur
`r1`, `show ip bgp {netb}` sur `ispa`) et `r3` annonce à `ispb` celles apprises d'ISP A. L'AS
65001 se propose ainsi comme **transit** entre ses deux fournisseurs : si le lien `lab` tombait,
du trafic entre les clients d'ISP A et ceux d'ISP B passerait par vos routeurs.

Sur `r1` (vers `ispa`) et sur `r3` (vers `ispb`), n'annoncez que le bloc **`{block}`** : une
`ip prefix-list` et une `route-map … out` (sur `r1`, complétez la route-map de la partie 5),
puis `clear bgp … soft out`. Vérifiez avec `advertised-routes` et sur les fournisseurs.
""": """
By default, a router announces **all** its best paths to its eBGP peers: `r1` announces to
`ispa` the routes learnt from ISP B (`show ip bgp neighbors {ispa_la} advertised-routes` on
`r1`, `show ip bgp {netb}` on `ispa`) and `r3` announces to `ispb` those learnt from ISP A. AS
65001 thus offers itself as a **transit** between its two providers: if the `lab` link failed,
traffic between the customers of ISP A and those of ISP B would go through your routers.

On `r1` (towards `ispa`) and on `r3` (towards `ispb`), announce only the block **`{block}`**: an
`ip prefix-list` and a `route-map … out` (on `r1`, extend the route-map of part 5),
then `clear bgp … soft out`. Check with `advertised-routes` and on the providers.
""",
    """
**Solution.**

```
! r1 : la route-map de la partie 5 reçoit une clause match
ip prefix-list TO-ISPA seq 5 permit {block}
route-map TO-ISPA permit 10
 match ip address prefix-list TO-ISPA
!
! r3
ip prefix-list TO-ISPB seq 5 permit {block}
route-map TO-ISPB permit 10
 match ip address prefix-list TO-ISPB
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map TO-ISPB out
 exit-address-family
```

puis `clear bgp {ispa_la} soft out` sur `r1` et `clear bgp {ispb_lb} soft out` sur `r3`.

- Une route qui ne correspond à aucune séquence d'une route-map est refusée : seul `{block}`
  sort. `show ip bgp neighbors {ispa_la} advertised-routes` sur `r1` ne liste plus que lui (avec
  son AS_PATH allongé).
- Sur `ispa`, `show ip bgp {netb}` n'a plus de chemin commençant par 65001 ; de même sur `ispb`
  pour `{neta}` et `203.0.113.0/24`.

Évaluation : `filtre_annonces_r1` et `filtre_annonces_r3` (1 point chacun : les routes annoncées
au fournisseur contiennent `{block}` et rien d'autre que lui et le préfixe du client),
`filtre_pas_de_fuite_ispa` et `filtre_pas_de_fuite_ispb` (1 chacun : le fournisseur reçoit le bloc
et n'a plus aucun chemin par l'AS 65001 vers le réseau de l'autre fournisseur ni vers
`203.0.113.0/24`), `filtre_bloc_toujours_annonce` (1). Les quatre premiers ne comptent que si
l'iBGP de la partie 3 est en place : sans lui il n'y a rien à filtrer.
""": """
**Solution.**

```
! r1: the route-map of part 5 gets a match clause
ip prefix-list TO-ISPA seq 5 permit {block}
route-map TO-ISPA permit 10
 match ip address prefix-list TO-ISPA
!
! r3
ip prefix-list TO-ISPB seq 5 permit {block}
route-map TO-ISPB permit 10
 match ip address prefix-list TO-ISPB
router bgp 65001
 address-family ipv4 unicast
  neighbor {ispb_lb} route-map TO-ISPB out
 exit-address-family
```

then `clear bgp {ispa_la} soft out` on `r1` and `clear bgp {ispb_lb} soft out` on `r3`.

- A route that matches no sequence of a route-map is denied: only `{block}` goes
  out. `show ip bgp neighbors {ispa_la} advertised-routes` on `r1` lists nothing else (with
  its lengthened AS_PATH).
- On `ispa`, `show ip bgp {netb}` no longer has any path starting with 65001; likewise on `ispb`
  for `{neta}` and `203.0.113.0/24`.

Evaluation: `filtre_annonces_r1` and `filtre_annonces_r3` (1 point each: the routes announced
to the provider contain `{block}` and nothing other than it and the customer's prefix),
`filtre_pas_de_fuite_ispa` and `filtre_pas_de_fuite_ispb` (1 each: the provider receives the block
and no longer has any path through AS 65001 to the network of the other provider or to
`203.0.113.0/24`), `filtre_bloc_toujours_annonce` (1). The first four count only if
the iBGP of part 3 is in place: without it there is nothing to filter.
""",
    "Observations sur le filtrage": "Observations on filtering",
    """
- sans filtre, si le lien `lab` tombe, par où passe le trafic de `netb` vers `neta` ?
  @@{lab_down:>par l'AS 65001 (transit involontaire)|par inet (AS 65000) uniquement|nulle part, neta devient injoignable}@@
  (indice : sur `ispb`, comparez les AS_PATH des chemins restants vers `neta` et le critère de
  départage)
- que fait `ispa` d'une route reçue de `r1` dont l'AS_PATH contient déjà 65100 ?
  @@{loop:>il la rejette (détection de boucle)|il l'accepte avec une préférence plus faible|il la préfère}@@
- ce que protège la RFC 8212 (politique obligatoire en eBGP) :
  @@{rfc8212:>les fuites de routes involontaires|la confidentialité des sessions|le temps de convergence}@@
""": """
- without a filter, if the `lab` link fails, which way does the traffic from `netb` to `neta` go?
  @@{lab_down:>through AS 65001 (unintended transit)>>>par l'AS 65001 (transit involontaire)|through inet (AS 65000) only>>>par inet (AS 65000) uniquement|nowhere, neta becomes unreachable>>>nulle part, neta devient injoignable}@@
  (hint: on `ispb`, compare the AS_PATHs of the remaining paths to `neta` and the tie-break
  criterion)
- what does `ispa` do with a route received from `r1` whose AS_PATH already contains 65100?
  @@{loop:>it rejects it (loop detection)>>>il la rejette (détection de boucle)|it accepts it with a lower preference>>>il l'accepte avec une préférence plus faible|it prefers it>>>il la préfère}@@
- what RFC 8212 (mandatory policy on eBGP) protects against:
  @@{rfc8212:>unintended route leaks>>>les fuites de routes involontaires|the confidentiality of the sessions>>>la confidentialité des sessions|the convergence time>>>le temps de convergence}@@
""",
    """
**Solution.**

- lien `lab` coupé, sans filtre : **par l'AS 65001 (transit involontaire)**. Il reste à `ispb`
  deux chemins de même longueur vers `neta`, `65000 65100` par `inet` et `65001 65100` par `r3`,
  départagés par le router-id du pair : celui de `r3` (sa loopback, une adresse privée) est plus
  petit que `250.250.250.250`. Dans l'autre sens, de `neta` vers `netb`, `ispa` choisit `inet` :
  le *prepend* de la partie 5 allonge tout ce que `r1` lui annonce.
- route dont l'AS_PATH contient déjà 65100 : **il la rejette (détection de boucle)** ;
- RFC 8212 : **les fuites de routes involontaires**.

Évaluation (enseignant seulement, 1 point chacun) : `filtre_q_transit`,
`filtre_q_boucle_rfc8212`.
""": """
**Solution.**

- `lab` link cut, without a filter: **through AS 65001 (unintended transit)**. `ispb` is left
  with two paths of the same length to `neta`, `65000 65100` through `inet` and `65001 65100`
  through `r3`, separated by the router-id of the peer: that of `r3` (its loopback, a private
  address) is lower than `250.250.250.250`. In the other direction, from `neta` to `netb`, `ispa`
  chooses `inet`: the *prepend* of part 5 lengthens everything `r1` announces to it.
- route whose AS_PATH already contains 65100: **it rejects it (loop detection)**;
- RFC 8212: **unintended route leaks**.

Evaluation (instructor only, 1 point each): `filtre_q_transit`,
`filtre_q_boucle_rfc8212`.
""",
    "r1 n'annonce à ispa que {block} (et le préfixe du client)": "r1 announces only {block} to ispa (and the customer's prefix)",
    "r3 n'annonce à ispb que {block} (et le préfixe du client)": "r3 announces only {block} to ispb (and the customer's prefix)",
    "ispa ne voit plus netb ni 203.0.113.0/24 par l'AS 65001": "ispa no longer sees netb or 203.0.113.0/24 through AS 65001",
    "ispb ne voit plus neta ni 203.0.113.0/24 par l'AS 65001": "ispb no longer sees neta or 203.0.113.0/24 through AS 65001",
    "les deux fournisseurs reçoivent toujours {block}": "both providers still receive {block}",
    "conséquence d'une absence de filtre": "consequence of having no filter",
    "détection de boucle et RFC 8212": "loop detection and RFC 8212",
    "Partie 7 — Un client : l'AS 65300": "Part 7 — A customer: AS 65300",
    "Raccorder le client r4 (AS 65300)": "Connecting the customer r4 (AS 65300)",
    """
L'AS 65001 fournit l'accès à l'Internet au client `r4` (AS 65300, réseau `{net4}`, hôte `m4`),
raccordé à `r3` par le lien `l34` (`{l34}`).

1. Sur `r4` : `router bgp 65300`, router-id `4.4.4.4`, pair `{r3_l34}` (AS 65001), annonce de
   `{net4}` (n'oubliez pas la RFC 8212).
2. Sur `r3` : pair `{r4_l34}` (AS 65300). Un client n'a pas besoin de la table complète :
   annoncez-lui **uniquement une route par défaut** (`neighbor {r4_l34} default-originate` et
   une `route-map … out` qui ne laisse passer que `0.0.0.0/0`). Vérifiez sur `r4` (`show ip
   bgp`, `ip route`) et depuis `m4` (`ping internet`, `ping m1`).
3. Le préfixe du client doit être annoncé aux **deux** fournisseurs : complétez les filtres de
   la partie 6 sur `r1` et `r3` (`show ip bgp {net4}` sur `ispa`, `ispb` et `inet`).

*Bonus* : sur `r3`, marquez les routes reçues de `r4` avec la communauté **`65001:{tag}`**
(`route-map … in` avec `set community`) et vérifiez qu'elle est visible sur `ispa` ou `inet`
(`show ip bgp {net4}`).
""": """
AS 65001 provides Internet access to the customer `r4` (AS 65300, network `{net4}`, host `m4`),
connected to `r3` by the `l34` link (`{l34}`).

1. On `r4`: `router bgp 65300`, router-id `4.4.4.4`, peer `{r3_l34}` (AS 65001), announcement of
   `{net4}` (do not forget RFC 8212).
2. On `r3`: peer `{r4_l34}` (AS 65300). A customer does not need the full table:
   announce **only a default route** to it (`neighbor {r4_l34} default-originate` and
   a `route-map … out` that lets only `0.0.0.0/0` through). Check on `r4` (`show ip
   bgp`, `ip route`) and from `m4` (`ping internet`, `ping m1`).
3. The customer's prefix must be announced to **both** providers: extend the filters of
   part 6 on `r1` and `r3` (`show ip bgp {net4}` on `ispa`, `ispb` and `inet`).

*Bonus*: on `r3`, tag the routes received from `r4` with the community **`65001:{tag}`**
(`route-map … in` with `set community`) and check that it is visible on `ispa` or `inet`
(`show ip bgp {net4}`).
""",
    """
**Solution.**

```
! r4
router bgp 65300
 bgp router-id 4.4.4.4
 no bgp ebgp-requires-policy
 neighbor {r3_l34} remote-as 65001
 neighbor {r3_l34} description FAI-AS65001
 address-family ipv4 unicast
  network {net4}
 exit-address-family
!
! r3
ip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0
ip prefix-list TO-ISPB seq 10 permit {net4}
route-map TO-R4 permit 10
 match ip address prefix-list DEFAULT-ONLY
route-map FROM-R4 permit 10
 set community {community}
router bgp 65001
 neighbor {r4_l34} remote-as 65300
 neighbor {r4_l34} description CLIENT-AS65300
 address-family ipv4 unicast
  neighbor {r4_l34} default-originate
  neighbor {r4_l34} route-map TO-R4 out
  neighbor {r4_l34} route-map FROM-R4 in
 exit-address-family
!
! r1
ip prefix-list TO-ISPA seq 10 permit {net4}
```

puis `clear bgp * soft` sur `r1` et `r3`. La route-map `FROM-R4` est le bonus.

- `{net4}` est un réseau connecté de `r4` : `network` l'annonce sans route `blackhole`.
- Sur `r4`, `show ip bgp` ne contient que `0.0.0.0/0` (prochain saut `{r3_l34}`) et son propre
  réseau ; `ip route` : `default … proto bgp`.
- `show ip bgp {net4}` sur `ispa`, `ispb` et `inet` : AS_PATH terminé par `65001 65300`, et la
  communauté `{community}` (`Community:`) avec le bonus.

Évaluation : `client_session` (2 points : session `Established` vue des deux côtés, `r4` dans
l'AS 65300 avec le router-id `4.4.4.4`), `client_defaut_seul` (2 : la table BGP de `r4` ne
contient, hors son réseau, que la route par défaut reçue de `{r3_l34}`, installée),
`client_prefixe_propage` (2 : `ispa`, `ispb` et `inet` ont un chemin vers `{net4}` terminé par
`65001 65300`), `client_pings` (1 : `m4` joint `internet` et `m1`, `web` joint `m4`),
`client_communaute_bonus` (1 : la communauté `{community}` vue sur `ispa` ou sur `inet`).
""": """
**Solution.**

```
! r4
router bgp 65300
 bgp router-id 4.4.4.4
 no bgp ebgp-requires-policy
 neighbor {r3_l34} remote-as 65001
 neighbor {r3_l34} description FAI-AS65001
 address-family ipv4 unicast
  network {net4}
 exit-address-family
!
! r3
ip prefix-list DEFAULT-ONLY seq 5 permit 0.0.0.0/0
ip prefix-list TO-ISPB seq 10 permit {net4}
route-map TO-R4 permit 10
 match ip address prefix-list DEFAULT-ONLY
route-map FROM-R4 permit 10
 set community {community}
router bgp 65001
 neighbor {r4_l34} remote-as 65300
 neighbor {r4_l34} description CLIENT-AS65300
 address-family ipv4 unicast
  neighbor {r4_l34} default-originate
  neighbor {r4_l34} route-map TO-R4 out
  neighbor {r4_l34} route-map FROM-R4 in
 exit-address-family
!
! r1
ip prefix-list TO-ISPA seq 10 permit {net4}
```

then `clear bgp * soft` on `r1` and `r3`. The `FROM-R4` route-map is the bonus.

- `{net4}` is a connected network of `r4`: `network` announces it without a `blackhole` route.
- On `r4`, `show ip bgp` contains only `0.0.0.0/0` (next hop `{r3_l34}`) and its own
  network; `ip route`: `default … proto bgp`.
- `show ip bgp {net4}` on `ispa`, `ispb` and `inet`: AS_PATH ending with `65001 65300`, and the
  community `{community}` (`Community:`) with the bonus.

Evaluation: `client_session` (2 points: session `Established` seen from both sides, `r4` in
AS 65300 with the router-id `4.4.4.4`), `client_defaut_seul` (2: apart from its own network,
the BGP table of `r4` contains only the default route received from `{r3_l34}`, installed),
`client_prefixe_propage` (2: `ispa`, `ispb` and `inet` have a path to `{net4}` ending with
`65001 65300`), `client_pings` (1: `m4` reaches `internet` and `m1`, `web` reaches `m4`),
`client_communaute_bonus` (1: the community `{community}` seen on `ispa` or on `inet`).
""",
    "Observations sur le client": "Observations on the customer",
    """
- `r1` apprend `{net4}` : @@{{learn:>par iBGP depuis r3|par eBGP depuis ispa|par OSPF}}@@ ;
  `NEXT_HOP` de cette route sur `r1` : @@{{nexthop:[0-9.]+}}@@
- effet de `aggregate-address PREFIXE summary-only` :
  @@{{summary_only:>seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés|l'agrégat et les préfixes plus spécifiques sont annoncés|seuls les préfixes plus spécifiques sont annoncés}}@@
""": """
- `r1` learns `{net4}`: @@{{learn:>via iBGP from r3>>>par iBGP depuis r3|via eBGP from ispa>>>par eBGP depuis ispa|via OSPF>>>par OSPF}}@@;
  `NEXT_HOP` of this route on `r1`: @@{{nexthop:[0-9.]+}}@@
- effect of `aggregate-address PREFIX summary-only`:
  @@{{summary_only:>only the aggregate is announced, the more specific prefixes are suppressed>>>seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés|the aggregate and the more specific prefixes are announced>>>l'agrégat et les préfixes plus spécifiques sont annoncés|only the more specific prefixes are announced>>>seuls les préfixes plus spécifiques sont annoncés}}@@
""",
    """
**Solution.**

- `r1` apprend `{net4}` **par iBGP depuis r3** (à travers `r2`) ; `NEXT_HOP` : **`{lo3}`**, la
  loopback de `r3` (`next-hop-self`) ;
- `summary-only` : **seul l'agrégat est annoncé, les préfixes plus spécifiques sont supprimés**.

Évaluation : `client_q_apprentissage_typed` (0,5 point : le `NEXT_HOP`) ; pour l'enseignant
seulement (choix dans une liste) : `client_q_apprentissage` (0,5 : par iBGP depuis `r3`),
`client_q_agregat` (1).
""": """
**Solution.**

- `r1` learns `{net4}` **via iBGP from r3** (through `r2`); `NEXT_HOP`: **`{lo3}`**, the
  loopback of `r3` (`next-hop-self`);
- `summary-only`: **only the aggregate is announced, the more specific prefixes are suppressed**.

Evaluation: `client_q_apprentissage_typed` (0.5 point: the `NEXT_HOP`); for the instructor
only (choice from a list): `client_q_apprentissage` (0.5: via iBGP from `r3`),
`client_q_agregat` (1).
""",
    "session r3–r4 Established, r4 dans l'AS 65300 avec le router-id 4.4.4.4": "r3–r4 session Established, r4 in AS 65300 with the router-id 4.4.4.4",
    "r4 ne reçoit de r3 qu'une route par défaut (installée)": "r4 receives only a default route from r3 (installed)",
    "ispa, ispb et inet connaissent {net4} par l'AS 65001 (AS_PATH … 65001 65300)": "ispa, ispb and inet know {net4} through AS 65001 (AS_PATH … 65001 65300)",
    "m4 joint internet et m1, web joint m4": "m4 reaches internet and m1, web reaches m4",
    "bonus : {net4} porte la communauté {community} chez ispa ou inet": "bonus: {net4} carries the community {community} at ispa or inet",
    "NEXT_HOP du préfixe du client sur r1": "NEXT_HOP of the customer's prefix on r1",
    "protocole par lequel r1 apprend le préfixe du client": "protocol through which r1 learns the customer's prefix",
    "effet de summary-only": "effect of summary-only",
    "Partie 8 — Réflecteur de routes": "Part 8 — Route reflector",
    "Remplacer le maillage iBGP par un réflecteur de routes": "Replacing the iBGP mesh with a route reflector",
    """
Le maillage complet ne passe pas à l'échelle. Faites de `r2` un **réflecteur de routes** :

1. sur `r2`, déclarez `r1` et `r3` comme clients (`neighbor {lo1} route-reflector-client` et
   `neighbor {lo3} route-reflector-client`, address-family) ;
2. supprimez la session directe entre `r1` et `r3` (`no neighbor {lo3} remote-as 65001` sur `r1`
   et symétriquement sur `r3`).

Vérifiez que `r1` connaît toujours `netb` et `r3` toujours `neta` (`show ip bgp {neta}` sur `r3` :
observez les attributs `Originator` et `Cluster list`), que le `NEXT_HOP` n'a pas été modifié
par le réflecteur et que `m1` joint `ispb`, `m3` joint `ispa`.
""": """
The full mesh does not scale. Make `r2` a **route reflector**:

1. on `r2`, declare `r1` and `r3` as clients (`neighbor {lo1} route-reflector-client` and
   `neighbor {lo3} route-reflector-client`, address-family);
2. remove the direct session between `r1` and `r3` (`no neighbor {lo3} remote-as 65001` on `r1`
   and symmetrically on `r3`).

Check that `r1` still knows `netb` and `r3` still knows `neta` (`show ip bgp {neta}` on `r3`:
observe the `Originator` and `Cluster list` attributes), that the `NEXT_HOP` has not been changed
by the reflector and that `m1` reaches `ispb` and `m3` reaches `ispa`.
""",
    """
**Solution.**

```
! r2
router bgp 65001
 address-family ipv4 unicast
  neighbor {lo1} route-reflector-client
  neighbor {lo3} route-reflector-client
 exit-address-family
! r1
router bgp 65001
 no neighbor {lo3} remote-as 65001
! r3
router bgp 65001
 no neighbor {lo1} remote-as 65001
```

`show ip bgp {neta}` sur `r3` : le chemin iBGP est reçu de `{lo2}` avec
`Originator: {lo1}, Cluster list: {lo2}` et son `NEXT_HOP` reste `{lo1}` : le réflecteur ne
modifie pas les attributs. Sans `route-reflector-client`, `r2` ne réannoncerait pas à `r3` les
routes apprises de `r1` et les deux routeurs de bordure perdraient les routes de l'autre.

Évaluation : `rr_clients_r2` (2 points : `r1` et `r3` clients du réflecteur dans la
configuration ou l'état de `r2`), `rr_plus_de_maillage` (1 : plus de session `r1`–`r3`, `r2`
toujours en session avec les deux), `rr_attributs` (2 : sur `r3`, un chemin vers `neta` porte
`ORIGINATOR_ID` = `{lo1}` et `{lo2}` dans sa `CLUSTER_LIST`), `rr_pings` (1 : les `ping` de la
partie 3).
""": """
**Solution.**

```
! r2
router bgp 65001
 address-family ipv4 unicast
  neighbor {lo1} route-reflector-client
  neighbor {lo3} route-reflector-client
 exit-address-family
! r1
router bgp 65001
 no neighbor {lo3} remote-as 65001
! r3
router bgp 65001
 no neighbor {lo1} remote-as 65001
```

`show ip bgp {neta}` on `r3`: the iBGP path is received from `{lo2}` with
`Originator: {lo1}, Cluster list: {lo2}` and its `NEXT_HOP` stays `{lo1}`: the reflector does
not change the attributes. Without `route-reflector-client`, `r2` would not re-announce to `r3`
the routes learnt from `r1`, and the two border routers would lose each other's routes.

Evaluation: `rr_clients_r2` (2 points: `r1` and `r3` clients of the reflector in the
configuration or the state of `r2`), `rr_plus_de_maillage` (1: no more `r1`–`r3` session, `r2`
still in session with both), `rr_attributs` (2: on `r3`, a path to `neta` carries
`ORIGINATOR_ID` = `{lo1}` and `{lo2}` in its `CLUSTER_LIST`), `rr_pings` (1: the `ping`s of
part 3).
""",
    "Observations sur le réflecteur de routes": "Observations on the route reflector",
    """
- nombre de sessions iBGP pour 8 routeurs en maillage complet : @@{mesh8:[0-9]+}@@ ;
  avec un seul réflecteur de routes : @@{rr8:[0-9]+}@@
- attributs ajoutés par le réflecteur pour éviter les boucles :
  @@{attrs:>ORIGINATOR_ID et CLUSTER_LIST|AS_PATH et NEXT_HOP|LOCAL_PREF et MED}@@
""": """
- number of iBGP sessions for 8 routers in a full mesh: @@{mesh8:[0-9]+}@@;
  with a single route reflector: @@{rr8:[0-9]+}@@
- attributes added by the reflector to avoid loops:
  @@{attrs:>ORIGINATOR_ID and CLUSTER_LIST>>>ORIGINATOR_ID et CLUSTER_LIST|AS_PATH and NEXT_HOP>>>AS_PATH et NEXT_HOP|LOCAL_PREF and MED>>>LOCAL_PREF et MED}@@
""",
    """
**Solution.** Maillage complet de 8 routeurs : 8 × 7 ÷ 2 = **28** sessions ; avec un réflecteur :
**7** (une par client). Attributs ajoutés : **ORIGINATOR_ID et CLUSTER_LIST**.

Évaluation (1 point chacun) : `rr_q_sessions` ; pour l'enseignant seulement (choix dans une
liste) : `rr_q_attributs`.
""": """
**Solution.** Full mesh of 8 routers: 8 × 7 ÷ 2 = **28** sessions; with a reflector:
**7** (one per client). Attributes added: **ORIGINATOR_ID and CLUSTER_LIST**.

Evaluation (1 point each): `rr_q_sessions`; for the instructor only (choice from a
list): `rr_q_attributs`.
""",
    "r1 et r3 sont clients du réflecteur r2": "r1 and r3 are clients of the reflector r2",
    "plus de session directe r1–r3 (r2 reste en session avec les deux)": "no more direct r1–r3 session (r2 stays in session with both)",
    "sur r3, neta est reçu de r2 avec ORIGINATOR_ID = r1 et CLUSTER_LIST contenant r2": "on r3, neta is received from r2 with ORIGINATOR_ID = r1 and CLUSTER_LIST containing r2",
    "m1 joint ispb et m3 joint ispa à travers le réflecteur": "m1 reaches ispb and m3 reaches ispa through the reflector",
    "nombre de sessions avec et sans réflecteur": "number of sessions with and without a reflector",
    "attributs ajoutés par un réflecteur": "attributes added by a reflector",
}}
