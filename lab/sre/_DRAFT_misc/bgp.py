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

title = tr("Routage inter-domaine : BGP", en="Inter-domain routing: BGP")
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
        **{r: {'image': sre_docker_image("frr"), 'color': AS_COLORS[AS_OF[r]]} for r in ROUTER_IFACES},
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

Évaluation (enseignant seulement, 1 point chacun) : `decouverte_as_port`,
`decouverte_etat_prefixes`, `decouverte_aspath`, `decouverte_ad_timers`, `decouverte_m3`.
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
            scope=params.EXO_EVAL_SCOPE, description=tr("numéro d'AS de ispa et port TCP de BGP"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_etat_prefixes"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("state")) == "established" and _int(q1.get("nb_prefixes")) == 3),
            scope=params.EXO_EVAL_SCOPE, description=tr("état de la session et nombre de préfixes reçus"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_aspath"), max_grade=1, grade_part=part1,
            grade=int(_as_path(q1.get("aspath_web")) == f"{AS_ISPA} {AS_INET}"),
            scope=params.EXO_EVAL_SCOPE, description=tr("AS_PATH de la route vers 203.0.113.0/24"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_ad_timers"), max_grade=1, grade_part=part1,
            grade=int(_int(q1.get("ad")) == 20 and _int(q1.get("hold")) == 180 and _int(q1.get("keepalive")) == 60),
            scope=params.EXO_EVAL_SCOPE, description=tr("distance administrative eBGP, hold time et keepalive par défaut"),
        )
        self.add_grade_element(
            title=no_tr("decouverte_m3"), max_grade=1, grade_part=part1,
            grade=int(_norm(q1.get("why_m3")).startswith("r3 n'a aucune route")),
            scope=params.EXO_EVAL_SCOPE, description=tr("pourquoi m3 ne joint pas internet"),
        )

        # =====================================================================
        # Partie 2 — eBGP : r3 et ISP B
        # =====================================================================
        part2 = self.add_grade_part(no_tr("partie2"), tr("Partie 2 — eBGP : r3 et ISP B"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Session eBGP entre r3 et ispb"),
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

Évaluation (enseignant seulement, 1 point chacun) : `ebgp_q_etat_avant`,
`ebgp_q_aspath_nexthop`, `ebgp_q_ttl`.
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
            grade=int(_norm(q2.get("state_before")) in ("active", "connect")), scope=params.EXO_EVAL_SCOPE,
            description=tr("état de la session côté ispb avant la configuration de r3"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_q_aspath_nexthop"), max_grade=1, grade_part=part2,
            grade=int(_as_path(q2.get("aspath_web")) == f"{AS_ISPB} {AS_INET}" and _same_ip(q2.get("nexthop"), ip['ispb_lb'])),
            scope=params.EXO_EVAL_SCOPE, description=tr("AS_PATH et NEXT_HOP des routes reçues de ispb"),
        )
        self.add_grade_element(
            title=no_tr("ebgp_q_ttl"), max_grade=1, grade_part=part2,
            grade=int(_int(q2.get("ttl")) == 1), scope=params.EXO_EVAL_SCOPE,
            description=tr("TTL des paquets eBGP"),
        )

        # =====================================================================
        # Partie 3 — iBGP
        # =====================================================================
        part3 = self.add_grade_part(no_tr("partie3"), tr("Partie 3 — iBGP dans l'AS 65001"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Sessions iBGP, next-hop-self et trou noir"),
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

Évaluation (enseignant seulement, 1 point chacun) : `ibgp_q_ad_sessions`, `ibgp_q_nexthop`,
`ibgp_q_r2`.
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
            scope=params.EXO_EVAL_SCOPE, description=tr("distance administrative iBGP et nombre de sessions d'un maillage"),
        )
        self.add_grade_element(
            title=no_tr("ibgp_q_nexthop"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("nh_before")).startswith("l'adresse de ispb")), scope=params.EXO_EVAL_SCOPE,
            description=tr("NEXT_HOP transmis tel quel en iBGP"),
        )
        self.add_grade_element(
            title=no_tr("ibgp_q_r2"), max_grade=1, grade_part=part3,
            grade=int(_norm(q3.get("why_r2")).startswith("r2 relaie")), scope=params.EXO_EVAL_SCOPE,
            description=tr("rôle de BGP sur le routeur de transit r2"),
        )

        # =====================================================================
        # Partie 4 — Meilleur chemin et local-preference
        # =====================================================================
        part4 = self.add_grade_part(no_tr("partie4"), tr("Partie 4 — Choix du meilleur chemin : local-preference"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Trafic sortant : préférer ISP B pour l'Internet"),
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
            scope=params.EXO_EVAL_SCOPE, description=tr("critères de choix avant la modification (r2 et r1)"),
        )
        self.add_grade_element(
            title=no_tr("lp_q_chemin"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("via")) == "r1, r2, r3, ispb, inet"), scope=params.EXO_EVAL_SCOPE,
            description=tr("chemin de m1 vers internet après la modification"),
        )
        self.add_grade_element(
            title=no_tr("lp_q_attribut"), max_grade=1, grade_part=part4,
            grade=int(_norm(q4.get("not_sent")) == "local_pref"), scope=params.EXO_EVAL_SCOPE,
            description=tr("attribut jamais transmis en eBGP"),
        )
        conv_ok = (_norm(q4.get("shutdown")).startswith("immédiatement") and _norm(q4.get("linkdown")).startswith("immédiatement")
                   and _norm(q4.get("silent")).startswith("environ le hold"))
        self.add_grade_element(
            title=no_tr("lp_q_convergence"), max_grade=1, grade_part=part4, grade=int(conv_ok),
            scope=params.EXO_EVAL_SCOPE, description=tr("temps de convergence observés"),
        )

        # =====================================================================
        # Partie 5 — Trafic entrant : AS-path prepend
        # =====================================================================
        part5 = self.add_grade_part(no_tr("partie5"), tr("Partie 5 — Trafic entrant : AS-path prepend et MED"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Influencer le trafic entrant"),
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
            scope=params.EXO_EVAL_SCOPE, description=tr("chemin et critère de choix de inet avant la modification"),
        )
        self.add_grade_element(
            title=no_tr("prepend_q_ispa"), max_grade=1, grade_part=part5,
            grade=int(_norm(q5.get("ispa_now")).startswith("par isp b")), scope=params.EXO_EVAL_SCOPE,
            description=tr("chemin préféré par ispa après la modification"),
        )
        self.add_grade_element(
            title=no_tr("prepend_q_med_leviers"), max_grade=1, grade_part=part5,
            grade=int(_norm(q5.get("med")) == "vrai" and _norm(q5.get("inbound")).startswith("as-path")
                      and _norm(q5.get("outbound")).startswith("local-preference")),
            scope=params.EXO_EVAL_SCOPE, description=tr("MED et leviers sur le trafic entrant / sortant"),
        )

        # =====================================================================
        # Partie 6 — Filtrage et non-transit
        # =====================================================================
        part6 = self.add_grade_part(no_tr("partie6"), tr("Partie 6 — Filtrage : ne pas devenir un AS de transit"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Filtrer les annonces vers les fournisseurs"),
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
            grade=int(_norm(q6.get("lab_down")).startswith("par l'as 65001")), scope=params.EXO_EVAL_SCOPE,
            description=tr("conséquence d'une absence de filtre"),
        )
        self.add_grade_element(
            title=no_tr("filtre_q_boucle_rfc8212"), max_grade=1, grade_part=part6,
            grade=int(_norm(q6.get("loop")).startswith("il la rejette") and _norm(q6.get("rfc8212")).startswith("les fuites")),
            scope=params.EXO_EVAL_SCOPE, description=tr("détection de boucle et RFC 8212"),
        )

        # =====================================================================
        # Partie 7 — Client AS 65300
        # =====================================================================
        part7 = self.add_grade_part(no_tr("partie7"), tr("Partie 7 — Un client : l'AS 65300"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Raccorder le client r4 (AS 65300)"),
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

Évaluation (enseignant seulement, 1 point chacun) : `client_q_apprentissage`,
`client_q_agregat`.
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
            title=no_tr("client_q_apprentissage"), max_grade=1, grade_part=part7,
            grade=int(_norm(q7.get("learn")).startswith("par ibgp") and _same_ip(q7.get("nexthop"), lo['r3'])),
            scope=params.EXO_EVAL_SCOPE, description=tr("comment r1 apprend le préfixe du client"),
        )
        self.add_grade_element(
            title=no_tr("client_q_agregat"), max_grade=1, grade_part=part7,
            grade=int(_norm(q7.get("summary_only")).startswith("seul l'agrégat")), scope=params.EXO_EVAL_SCOPE,
            description=tr("effet de summary-only"),
        )

        # =====================================================================
        # Partie 8 — Réflecteur de routes
        # =====================================================================
        part8 = self.add_grade_part(no_tr("partie8"), tr("Partie 8 — Réflecteur de routes"))
        self.question_dummy(
            section=self.section(0),
            title=tr("Remplacer le maillage iBGP par un réflecteur de routes"),
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
            description=tr("""
- nombre de sessions iBGP pour 8 routeurs en maillage complet : @@{mesh8:[0-9]+}@@ ;
  avec un seul réflecteur de routes : @@{rr8:[0-9]+}@@
- attributs ajoutés par le réflecteur pour éviter les boucles :
  @@{attrs:>ORIGINATOR_ID et CLUSTER_LIST|AS_PATH et NEXT_HOP|LOCAL_PREF et MED}@@
""")
            + instructor(tr("""
**Solution.** Maillage complet de 8 routeurs : 8 × 7 ÷ 2 = **28** sessions ; avec un réflecteur :
**7** (une par client). Attributs ajoutés : **ORIGINATOR_ID et CLUSTER_LIST**.

Évaluation (enseignant seulement, 1 point chacun) : `rr_q_sessions`, `rr_q_attributs`.
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
            grade=int(_int(q8.get("mesh8")) == 28 and _int(q8.get("rr8")) == 7), scope=params.EXO_EVAL_SCOPE,
            description=tr("nombre de sessions avec et sans réflecteur"),
        )
        self.add_grade_element(
            title=no_tr("rr_q_attributs"), max_grade=1, grade_part=part8,
            grade=int(_norm(q8.get("attrs")).startswith("originator_id")), scope=params.EXO_EVAL_SCOPE,
            description=tr("attributs ajoutés par un réflecteur"),
        )


_TRANSLATIONS = {}
